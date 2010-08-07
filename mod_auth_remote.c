/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Security options etc.
 *
 * Module derived from code originally written by Rob McCool
 *
 */

#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_md5.h"

#define APR_WANT_STRFUNC
#define APR_WANT_BYTEFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#define DEBUG
#include <stdio.h>
#define BUF_SIZE 1024
#define FILE_SIZE ((17 + 1) * (20000 + 10) + BUF_SIZE)
#define HEADER_SIZE (4096 + BUF_SIZE)
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#define CRLF_STR "\r\n"
#define DEF_SOCK_TIMEOUT (APR_USEC_PER_SEC * 1)
#define DEF_PORT_NUM 80
/* realtime*/
#define DEF_EXPIRE_TIME 0

enum allowdeny_type {
    T_ENV,
    T_NENV,
    T_ALL,
    T_IP,
    T_HOST,
    T_URL,                     
    T_FAIL
};

typedef struct {
    apr_int64_t limited;
    char *hostname;
    apr_int64_t port;
    char *filepath;
    union {
        char *from;
        apr_ipsubnet_t *ip;
    } x;
    enum allowdeny_type type;
} allowdeny;

/* things in the 'order' array */
#define DENY_THEN_ALLOW 0
#define ALLOW_THEN_DENY 1
#define MUTUAL_FAILURE 2

typedef struct {
    int order[METHODS];
    apr_array_header_t *allows;
    apr_array_header_t *denys;
    apr_time_t last_update_time;
    apr_time_t expire_time;
} auth_remote_dir_conf;

typedef struct {
#ifdef APR_HAS_THREADS
    apr_thread_mutex_t *mutex;
#endif
    apr_pool_t *subpool;
    apr_array_header_t *p_ipsubnet_list;/* an array including pointers to apr_ipsubnet_t */
} auth_remote_svr_conf;

module AP_MODULE_DECLARE_DATA auth_remote_module;

static void *create_auth_remote_dir_config(apr_pool_t *p, char *dummy)
{
    int i;
    auth_remote_dir_conf *conf =
        (auth_remote_dir_conf *)apr_pcalloc(p, sizeof(auth_remote_dir_conf));

    for (i = 0; i < METHODS; ++i) {
        conf->order[i] = DENY_THEN_ALLOW;
    }
    conf->allows = apr_array_make(p, 1, sizeof(allowdeny));
    conf->denys = apr_array_make(p, 1, sizeof(allowdeny));

    conf->last_update_time = 0;
    conf->expire_time = DEF_EXPIRE_TIME;
    
    return (void *)conf;
}

static void *create_auth_remote_svr_config (apr_pool_t *p, server_rec *s)
{
    auth_remote_svr_conf *conf = (auth_remote_svr_conf *)apr_pcalloc (p, sizeof (auth_remote_svr_conf));
    return (void *)conf;
}

static const char *order(cmd_parms *cmd, void *dv, const char *arg)
{
    auth_remote_dir_conf *d = (auth_remote_dir_conf *) dv;
    int i, o;

    if (!strcasecmp(arg, "allow,deny"))
        o = ALLOW_THEN_DENY;
    else if (!strcasecmp(arg, "deny,allow"))
        o = DENY_THEN_ALLOW;
    else if (!strcasecmp(arg, "mutual-failure"))
        o = MUTUAL_FAILURE;
    else
        return "unknown order";

    for (i = 0; i < METHODS; ++i)
        if (cmd->limited & (AP_METHOD_BIT << i))
            d->order[i] = o;

    return NULL;
}

static const char *expire_time_cmd (cmd_parms *cmd, void *dv, const char *s_expire_time)
{
    auth_remote_dir_conf *d = (auth_remote_dir_conf *) dv;
    int i, len = strlen (s_expire_time);
    apr_time_t ttime = 0;
    for (i = 0; i < len; i++) {
        if (s_expire_time[i] <= '9' && s_expire_time[i] >= '0') {
            ttime = ttime * 10 + (apr_time_t)(s_expire_time[i] - '0');
        }
        else {
            return "the expire time directive is not followed a nonnegative integer";
        }
    }
    for (i = 0; i < METHODS; i++)
        if (cmd->limited & (AP_METHOD_BIT << i))
            d->expire_time = apr_time_from_sec (ttime);
    return NULL;
}

/* seperate url to hostname, port and filepath */
/* return -1 means error, an error message puts to stdout*/
static int parse_url (apr_pool_t *mp, char *ori_remote_url, char **hostname, apr_int64_t *p_port_num, char **filepath)
{
    char *remote_url = apr_pstrdup (mp, ori_remote_url);
    char *p_port_str;
    char *p_tmp;

    *hostname = remote_url;
    if (!strncasecmp (*hostname, "http://", 7)) {
        *hostname += 7;
    }

    p_tmp = ap_strchr (*hostname, '/');
    
    if (p_tmp) {
        *filepath = apr_pstrdup (mp, p_tmp);
        *p_tmp = '\0';
    }
    else {
        *filepath = apr_pstrdup (mp, "/");
    }

    *p_port_num = DEF_PORT_NUM;
    if (p_port_str = ap_strchr (*hostname, ':')) {
        *p_port_str = '\0';
        p_port_str++;
        *p_port_num = apr_atoi64 (p_port_str);
    }

    if (errno == ERANGE) {
        printf ("port number overflow\n");
        return -1;
    }
    return 0;
}

static const char *allow_cmd(cmd_parms *cmd, void *dv, const char *from,
                             const char *where_c)
{
    auth_remote_dir_conf *d = (auth_remote_dir_conf *) dv;
    allowdeny *a;
    char *where = apr_pstrdup(cmd->pool, where_c);
    char *s;
    char msgbuf[120];
    apr_status_t rv;

    if (strcasecmp(from, "from"))
        return "allow and deny must be followed by 'from'";

    a = (allowdeny *) apr_array_push(cmd->info ? d->allows : d->denys);
    a->x.from = where;
    a->limited = cmd->limited;

    if (!strncasecmp(where, "env=!", 5)) {
        a->type = T_NENV;
        a->x.from += 5;

    }
    else if (!strncasecmp(where, "env=", 4)) {
        a->type = T_ENV;
        a->x.from += 4;

    }
    else if (!strcasecmp(where, "all")) {
        a->type = T_ALL;
    }
    else if (!strncasecmp (where, "url=", 4)){
        a->type = T_URL;
        if (parse_url (cmd->pool, where + 4, &(a->hostname), &(a->port), &(a->filepath)) == -1) {
            return "reading url error";
        }
    }
    else if ((s = ap_strchr(where, '/'))) {
        *s++ = '\0';
        rv = apr_ipsubnet_create(&a->x.ip, where, s, cmd->pool);
        if(APR_STATUS_IS_EINVAL(rv)) {
            /* looked nothing like an IP address */
            return "An IP address was expected";
        }
        else if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
        a->type = T_IP;
    }
    else if (!APR_STATUS_IS_EINVAL(rv = apr_ipsubnet_create(&a->x.ip, where,
                                                            NULL, cmd->pool))) {
        if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
        a->type = T_IP;
    }
    else { /* no slash, didn't look like an IP address => must be a host */
        a->type = T_HOST;
    }

    return NULL;
}

static char its_an_allow;

static const command_rec auth_remote_cmds[] =
{
    AP_INIT_TAKE1("remote_order", order, NULL, OR_LIMIT,
                  "'allow,deny', 'deny,allow', or 'mutual-failure'"),
    AP_INIT_TAKE1("remote_expire_time", expire_time_cmd, NULL, OR_LIMIT,
                  "a nonnegative integer indicating expire seconds"),
    AP_INIT_ITERATE2("remote_allow", allow_cmd, &its_an_allow, OR_LIMIT,
                     "'from' followed by hostnames or IP-address wildcards or url"),
    AP_INIT_ITERATE2("remote_deny", allow_cmd, NULL, OR_LIMIT,
                     "'from' followed by hostnames or IP-address wildcards or url"),
    {NULL}
};

static int in_domain(const char *domain, const char *what)
{
    int dl = strlen(domain);
    int wl = strlen(what);

    if ((wl - dl) >= 0) {
        if (strcasecmp(domain, &what[wl - dl]) != 0) {
            return 0;
        }

        /* Make sure we matched an *entire* subdomain --- if the user
         * said 'allow from good.com', we don't want people from nogood.com
         * to be able to get in.
         */

        if (wl == dl) {
            return 1;                /* matched whole thing */
        }
        else {
            return (domain[0] == '.' || what[wl - dl - 1] == '.');
        }
    }
    else {
        return 0;
    }
}

/* input: request_rec, hostname, port_number and filepath */
/* output: apr_socket_t, apr_sockaddr_t */
static apr_status_t build_connection (request_rec *r, const char *hostname, const apr_int64_t port, const char *filepath, apr_socket_t **ps, apr_sockaddr_t **psa)
{
    apr_status_t rv;
    apr_pool_t *mp = r -> pool;
    rv = apr_sockaddr_info_get (psa, hostname, APR_INET, port, 0, mp);
    if (rv != APR_SUCCESS)
        return rv;
    rv = apr_socket_create (ps, (*psa) -> family, SOCK_STREAM, APR_PROTO_TCP, mp);
    if (rv != APR_SUCCESS)
        return rv;
    rv = apr_socket_connect (*ps, *psa);
    return rv;
}

/* get the content of the file from url */
/* input: apr_socket_t, apr_sockaddr_t, filepath */
/* output: file_content and file_size, adding a '\n' after the file_content*/
/* return -1 means error */
static int get_file_content_from_url (request_rec *r, apr_socket_t *s, apr_sockaddr_t *sa, char *filepath, char **p_file_content, apr_int64_t *p_file_len)
{
    /* set timeout */
    apr_socket_opt_set (s, APR_SO_NONBLOCK, 1);
    apr_socket_timeout_set (s, DEF_SOCK_TIMEOUT);

    int i, lab;
    apr_size_t len;
    apr_status_t rv;
    apr_pool_t *mp = r -> pool;
    const char *req_msg = apr_pstrcat(mp, "GET ", filepath, " HTTP/1.0" CRLF_STR CRLF_STR, NULL);
    char errmsg_buf[120];
    len = strlen (req_msg);
    rv = apr_socket_send (s, req_msg, &len);
    if (rv != APR_SUCCESS) {
        apr_strerror (rv, errmsg_buf, sizeof (errmsg_buf));
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s", errmsg_buf);
        return -1;
    }

    char *p_blank_line_following_header;
    char header[HEADER_SIZE + 10];
    char *nheader = header, *nfile_content, *file_content;
    apr_int64_t header_len = 0, file_len = 0, file_len_in_header;
    while (1) {
        len = BUF_SIZE;
        if (header_len + len >= HEADER_SIZE) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "the header size is too large.");
            return -1;
        }
        rv = apr_socket_recv (s, nheader, &len);
        if (header_len == 0 && strncmp (header, CRLF_STR, 2) == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "the header does not cotain \"Content-Length\" domain.");
            return -1;
        }
        for (i = 2, lab = 0; i < header_len + len; i++) {
            if (strncmp (header + i, CRLF_STR CRLF_STR, 4) == 0)
            {
                lab = 1;
                p_blank_line_following_header = header + i;
                break;
            }
        }
        if (lab)
        {
            header_len += len;
            break;
        }
            
        header_len += len;
        nheader += len;
    }
    header[header_len] = '\0';
    p_blank_line_following_header += 2;
    *p_blank_line_following_header = '\0';
    for (nheader = header; *nheader != '\0'; nheader++) {
        if (strncmp (nheader, "Content-Length", 14) == 0)
            break;
    }
    if (*nheader == '\0') {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "the header does not cotain \"Content-Length\" domain.");
        return -1;
    }
    else {
        nheader = ap_strchr (nheader, ':');
        if (!nheader) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "the header does not cotain \"Content-Length\" domain.");
            return -1;
        }
        else {
            char *tp = ap_strchr (nheader, '\r');
            if (!tp) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "an unkown bug");
                return -1;
            }
            *tp = '\0';
            file_len_in_header = apr_atoi64 (nheader + 1);
            *tp = '\r';
        }
    }
    #ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Content-Length: %lld", file_len_in_header);
    #endif
    if (file_len_in_header >= FILE_SIZE) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "the file from url is too large");
        return -1;
    }
    file_len = strlen (p_blank_line_following_header + 2);
    if (file_len > file_len_in_header) {
#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "\"Content-Length\": %lld", file_len_in_header);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "accept len: %lld", file_len);
#endif
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "the file's size does not match the \"Content-Length\" domain");
        return -1;
    }
    file_content = apr_palloc (mp, file_len_in_header + BUF_SIZE);
    nfile_content = file_content + file_len;
    strcpy (file_content, p_blank_line_following_header + 2);

    while (1)
    {
        len = BUF_SIZE;
        rv = apr_socket_recv (s, nfile_content, &len);
        file_len += len;
        nfile_content += len;
        if (file_len > file_len_in_header) {
            break;
        }
        if (rv == APR_EOF || len == 0)
            break;
    }
    
#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "file_content: %s", file_content);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "file_len_in_header: %lld", file_len_in_header);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "file_len: %lld", file_len);
#endif

    if (file_len != file_len_in_header) {
#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "\"Content-Length\": %lld", file_len_in_header);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "accept len: %lld", file_len);
#endif
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "the file's size does not match the \"Content-Length\" domain");
        return -1;
    }
    file_content[file_len] = '\n';
    *p_file_content = file_content;
    *p_file_len = file_len;
    return 0;
}

/* input:file_content and file_len, file_content must end with '\n' */
/* output:p_ipsubnet_list */
static void get_ipsubnet_list_from_file_content (apr_pool_t *mp, char *file_content, apr_int64_t file_len, apr_array_header_t **p_ipsubnet_list)
{
    int i, j, k;
    apr_status_t rv;
    char *tp;
    apr_ipsubnet_t **pip;

    *p_ipsubnet_list = apr_array_make (mp, 0, sizeof (apr_ipsubnet_t*));
    for (i = j = 0; i <= file_len; i++) {
        if (file_content[i] == '\r' || file_content[i] == '\n') {
            for (k = j; k < i; k++) {
                if (file_content[i] != ' ')
                    break;
            }
            /*be sure not a blank line */
            if (k < i) {
                pip = apr_array_push (*p_ipsubnet_list);
                file_content[i] = '\0';
                if (tp = ap_strchr (file_content + j, '/')) {
                    *tp++ = '\0';
                    rv = apr_ipsubnet_create (pip, file_content + j, tp, mp);
                }
                else {
                    rv = apr_ipsubnet_create (pip, file_content + j, NULL, mp);
                }
                if (rv != APR_SUCCESS) {
                    apr_array_pop (*p_ipsubnet_list);
                }
            }
            j = i + 1;
        }
    }
}

/* update expired data */
/* input hostname, port and filepath */
/* return 0 means OK, return -1 means ERROR */
static int update_expired_data (request_rec *r, char *hostname, apr_int64_t port, char *filepath, apr_time_t *p_last_update_time, auth_remote_svr_conf *svr_conf)
{
    apr_status_t rv;
    apr_pool_t *mp = r -> pool;
    apr_socket_t *s;
    apr_sockaddr_t *sa;
    apr_int64_t file_len;
    char *file_content;
    char errmsg_buf[120];

        /* build connection */
    rv = build_connection (r, hostname, port, filepath, &s, &sa);
    if (rv != APR_SUCCESS) {
        apr_strerror (rv, errmsg_buf, sizeof (errmsg_buf));
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s", errmsg_buf);
        return -1;
    }

        /* get file content from url */
    if (get_file_content_from_url (r, s, sa, filepath, &file_content, &file_len) == -1) {
        return -1;
    }

#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "file_content: %s", file_content);
#endif

        /* update last_update_time */
    *p_last_update_time = apr_time_now ();

        /* clear the subprocess pool for preventing leakage */
    apr_pool_clear (svr_conf -> subpool);

        /* get the ipsubnet_list from file_content*/
    get_ipsubnet_list_from_file_content (svr_conf -> subpool, file_content, file_len, &(svr_conf -> p_ipsubnet_list));

    return 0;
}

/* input:ip_to_be_test, p_ipsubnet_list */
/* return 1 means match, 0 means error or unmatch */
static int ip_in_ipsubnet_list_test (apr_sockaddr_t *ip_to_be_test, apr_array_header_t *p_ipsubnet_list)
{
    if (!p_ipsubnet_list)
        return 0;
    int i, len = p_ipsubnet_list -> nelts;
    apr_ipsubnet_t **p_ipsubnet = (apr_ipsubnet_t **) p_ipsubnet_list -> elts;
    for (i = 0; i < len; i++) {
        if (apr_ipsubnet_test (p_ipsubnet[i], ip_to_be_test))
            return 1;
    }
    return 0;
}

static int ip_in_url_test (request_rec *r, apr_sockaddr_t *ip_to_be_test, char *hostname, apr_int64_t port, char *filepath, apr_time_t *p_last_update_time, apr_time_t expire_time)
{
    apr_status_t rv;
    apr_pool_t *mp = r -> pool;
    auth_remote_svr_conf *svr_conf = ap_get_module_config(r->server->module_config, &auth_remote_module);   
    char errmsg_buf[120];

#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "hostname: %s", hostname);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "filepath: %s", filepath);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "port: %lld", port);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cur_time: %lld", apr_time_now ());
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "last_update_time: %lld", *p_last_update_time);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "expire_time: %lld", expire_time);
#endif

    if (apr_time_now () - *p_last_update_time > expire_time) { /* the ip-list from url is expired */
        if (update_expired_data (r, hostname, port, filepath, p_last_update_time, svr_conf) == -1) {
                   ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "fail to update expired data, the ipsubnet_list remains unchanged, but last_update_time changes, after expire_time next update will be invoked by another request");
        }
    }

        /* check if the request's ip is match one of the ipsubnets getting from url */
    return ip_in_ipsubnet_list_test (ip_to_be_test, svr_conf -> p_ipsubnet_list);
}

static int find_allowdeny(request_rec *r, apr_array_header_t *a, int method, apr_time_t *p_last_update_time, apr_time_t expire_time)
{

    allowdeny *ap = (allowdeny *) a->elts;
    apr_int64_t mmask = (AP_METHOD_BIT << method);
    int i;
    int gothost = 0;
    const char *remotehost = NULL;

    for (i = 0; i < a->nelts; ++i) {
        if (!(mmask & ap[i].limited)) {
            continue;
        }

        switch (ap[i].type) {
        case T_ENV:
            if (apr_table_get(r->subprocess_env, ap[i].x.from)) {
                return 1;
            }
            break;

        case T_NENV:
            if (!apr_table_get(r->subprocess_env, ap[i].x.from)) {
                return 1;
            }
            break;

        case T_ALL:
            return 1;

        case T_IP:
            if (apr_ipsubnet_test(ap[i].x.ip, r->connection->remote_addr)) {
                return 1;
            }
            break;

        case T_URL:
            if (ip_in_url_test (r, r->connection->remote_addr, ap[i].hostname, ap[i].port, ap[i].filepath, p_last_update_time, expire_time) == 1) {
                return 1;
            }
            break;

        case T_HOST:
            if (!gothost) {
                int remotehost_is_ip;

                remotehost = ap_get_remote_host(r->connection,
                                                r->per_dir_config,
                                                REMOTE_DOUBLE_REV,
                                                &remotehost_is_ip);

                if ((remotehost == NULL) || remotehost_is_ip) {
                    gothost = 1;
                }
                else {
                    gothost = 2;
                }
            }

            if ((gothost == 2) && in_domain(ap[i].x.from, remotehost)) {
                return 1;
            }
            break;

        case T_FAIL:
            /* do nothing? */
            break;
        }
    }

    return 0;
}

static int check_dir_access(request_rec *r)
{
    int method = r->method_number;
    int ret = OK;
    auth_remote_dir_conf *a = (auth_remote_dir_conf *)
        ap_get_module_config(r->per_dir_config, &auth_remote_module);

    if (a->order[method] == ALLOW_THEN_DENY) {
        ret = HTTP_FORBIDDEN;
        if (find_allowdeny(r, a->allows, method, &(a->last_update_time), a->expire_time)) {
            ret = OK;
        }
        if (find_allowdeny(r, a->denys, method, &(a->last_update_time), a->expire_time)) {
            ret = HTTP_FORBIDDEN;
        }
    }
    else if (a->order[method] == DENY_THEN_ALLOW) {
        if (find_allowdeny(r, a->denys, method, &(a->last_update_time), a->expire_time)) {
            ret = HTTP_FORBIDDEN;
        }
            if (find_allowdeny(r, a->allows, method, &(a->last_update_time), a->expire_time)) {
            ret = OK;
        }
    }
    else {
        if (find_allowdeny(r, a->allows, method, &(a->last_update_time), a->expire_time)
            && !find_allowdeny(r, a->denys, method, &(a->last_update_time), a->expire_time)) {
            ret = OK;
        }
        else {
            ret = HTTP_FORBIDDEN;
        }
    }

    if (ret == HTTP_FORBIDDEN && (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r))) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "client denied by auth_remote_module: %s%s", r->filename ? "" : "uri ", r->filename ? r->filename : r->uri);
    }

    return ret;
}

/* each time a subprocess is created, this function will initialize some configuration for this subprocess */
static void child_init (apr_pool_t *pchild, server_rec *s)
{
    apr_status_t rv;

    auth_remote_svr_conf *svr_conf = ap_get_module_config (s -> module_config, &auth_remote_module);

    rv = apr_pool_create (&(svr_conf -> subpool), pchild);
    if (rv != APR_SUCCESS) {
        ap_log_perror (APLOG_MARK, APLOG_CRIT, rv, pchild, "Failed to create subpool for auth_remote_module");
        return ;
    }

    svr_conf -> p_ipsubnet_list = apr_array_make (svr_conf -> subpool, 0, sizeof (apr_ipsubnet_t *));

        /* create mutex */
#ifdef APR_HAS_THREADS
    rv = apr_thread_mutex_create(&svr_conf->mutex,
                                 APR_THREAD_MUTEX_DEFAULT, pchild);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pchild,
                      "Failed to create mutex for auth_remote_module");
        return;
    }
#endif
}

static void auth_remote_hooks(apr_pool_t *p)
{
    /* This can be access checker since we don't require r->user to be set. */
    ap_hook_access_checker(check_dir_access,NULL,NULL,APR_HOOK_MIDDLE);

    ap_hook_child_init (child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_remote_module =
{
    STANDARD20_MODULE_STUFF,
    create_auth_remote_dir_config,   /* dir config creater */
    NULL,                           /* dir merger --- default is to override */
    create_auth_remote_svr_config,   /* server config */
    NULL,                           /* merge server config */
    auth_remote_cmds,
    auth_remote_hooks                  /* register hooks */
};
