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
#include <apr_version.h>
#define FILE_SIZE ((17 + 1) * (20000 + 10))
#define HEADER_SIZE (4096)
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#define CRLF_STR "\r\n"
#define DEF_SOCK_TIMEOUT (APR_USEC_PER_SEC * 1)
#define DEF_PORT_NUM 80
#define DEF_EXPIRE_TIME 0 /* realtime*/
#define MAX_REDIRECT_TIME 50

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
    apr_time_t last_contact_time;
    char *last_update_time;
    char *last_update_url;
    char *remote_url;
    apr_array_header_t *p_ipsubnet_list;/* an array including pointers to apr_ipsubnet_t */
    apr_pool_t *subpool;
} REMOTE_INFO;

typedef struct {
    apr_int64_t limited;
    union {
        char *from;
        apr_ipsubnet_t *ip;
        REMOTE_INFO remote_info;
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
    apr_time_t expire_time;
} auth_remote_dir_conf;

typedef struct {
    apr_pool_t *subpool;
#if APR_HAS_THREADS
    apr_thread_mutex_t *mutex;
#endif
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
            if (ttime > (1000000000 - (apr_time_t)(s_expire_time[i] - '0')) / 10) {
                return "the expire time is too large (maximum: 1000000000)";
            }
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
/* return -1 means error */
static int parse_url (request_rec *r, const char *remote_url, char **hostname, apr_int64_t *p_port_num, char **filepath)
{
    apr_pool_t *rp = r -> pool;
    char *p_port_str;
    char *p_tmp;

    *hostname = apr_pstrdup (rp, remote_url);
    if (!strncasecmp (*hostname, "http://", 7)) {
        *hostname += 7;
    }

    p_tmp = ap_strchr (*hostname, '/');
    
    if (p_tmp) {
        *filepath = apr_pstrdup (rp, p_tmp);
        *p_tmp = '\0';
    }
    else {
        *filepath = apr_pstrdup (rp, "/");
    }

    *p_port_num = DEF_PORT_NUM;
    if (p_port_str = ap_strchr (*hostname, ':')) {
        *p_port_str = '\0';
        p_port_str++;
        *p_port_num = apr_atoi64 (p_port_str);
    }

    if (errno == ERANGE) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "port number overflow");
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
        return "remote_allow and remote_deny must be followed by 'from'";

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
        a->x.remote_info.last_contact_time = 0;
        a->x.remote_info.last_update_time = NULL;
        a->x.remote_info.last_update_url = NULL;
        a->x.remote_info.remote_url = where + 4;
        a->x.remote_info.subpool = NULL;
        a->x.remote_info.p_ipsubnet_list = NULL;
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

/* input: request_rec, hostname, port_number */
/* output: apr_socket_t, apr_sockaddr_t */
static apr_status_t build_connection (request_rec *r, const char *hostname, const apr_int64_t port, apr_socket_t **ps, apr_sockaddr_t **psa)
{
    apr_status_t rv;
    apr_pool_t *rp = r -> pool;
    rv = apr_sockaddr_info_get (psa, hostname, APR_INET, port, 0, rp);
    if (rv != APR_SUCCESS)
        return rv;
#if APR_MAJOR_VERSION != 0
    rv = apr_socket_create (ps, (*psa) -> family, SOCK_STREAM, APR_PROTO_TCP, rp);
#else
    rv = apr_socket_create_ex (ps, (*psa) -> family, SOCK_STREAM, APR_PROTO_TCP, rp);
#endif
    if (rv != APR_SUCCESS)
        return rv;
    rv = apr_socket_connect (*ps, *psa);
    return rv;
}

/* the http-header will be stored in the area that header point to */
/* redundant stores part of the body of the response (content following the blank line)*/
/* p_hlen indicate the max size of header as input, and indicate the receive size of header as output */
/* p_rlen indicate the receive size of redundant as output */
/* return -1 means error */
/* redundant buffer size should be larger than hlen */
static int get_header_from_response (request_rec *r, apr_socket_t *s, char *header, apr_size_t *p_hlen, char *redundant, apr_size_t *p_rlen)
{
    int i, crlf_loc;
    apr_status_t rv;
    apr_size_t len, hlen = 0;
    char *nheader = header;
    while (1) {
        len = *p_hlen - hlen;
        if (len == 0) {
            char buf[1];
            len = 1;
            rv = apr_socket_recv (s, buf, &len);
            if (rv == APR_EOF || len == 0) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "fail to get compelte http head (maybe the server is too busy)");
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "the http header's size is too large");
            }
            return -1;
        }
        rv = apr_socket_recv (s, nheader, &len);
        if (strncmp (header, CRLF_STR, 2) == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
            return -1;
        }
        for (i = 2; i < hlen + len; i++)
            if (strncmp (header + i, CRLF_STR CRLF_STR, 4) == 0) {
                crlf_loc = i + 2;
                break;
            }
        if (i < hlen + len)
            break;
        if (rv == APR_EOF || len == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "fail to get compelete http head (maybe the server is too busy)");
            return -1;
        }
        hlen += len;
        nheader += len;
    }
    if (hlen + len - crlf_loc - 2 > *p_rlen) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "the bufsize of redundant is too small");
#endif
        return -1;
    }
    for (i = crlf_loc + 2, *p_rlen = 0; i < hlen + len; i++)
        redundant[(*p_rlen)++] = header[i];
    *p_hlen = crlf_loc;
    return 0;
}

/* get status code from http header, return from p_sc */
static int get_status_code_from_header (request_rec *r, char *header, apr_size_t hlen, char **p_sc)
{
    int i, j;
    apr_pool_t *rp = r -> pool;
    for (i = 0; i < hlen; i++)
        if (header[i] == ' ')
            break;
    if (i >= hlen) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
        return -1;
    }
    for (j = i + 1; j < hlen; j++)
        if (header[j] == ' ')
            break;
    if (j >= hlen) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
        return -1;
    }
    *p_sc = apr_pstrmemdup (rp, header + i + 1, j - (i + 1));
    return 0;
}

/* get content-length from http header, return from p_cl */
static int get_content_length_from_header (request_rec *r, char *header, apr_size_t hlen, apr_size_t maxlen, apr_size_t *p_cl)
{
    int i, j;
    *p_cl = 0;
    for (i = 0; i + 15 <= hlen; i++)
        if (strncmp (header + i, "Content-Length:", 15) == 0) {
            for (j = i + 15; j < hlen && header[j] == ' '; j++){}
            for (; j < hlen; j++) {
                if (header[j] <= '9' && header[j] >= '0') {
                    if (*p_cl > (maxlen - (header[j] - '0')) / 10) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "content-length too large");
                        return -1;
                    }
                    *p_cl = *p_cl * 10 + header[j] - '0';
                }
                else if (header[j] == '\r' || header[j] == ' ')
                    return 0;
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
#ifdef DEBUG
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "content-length invalid");
#endif
                    return -1;
                }
            }
            if (j >= hlen) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
#ifdef DEBUG
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "content-length invalid");
#endif
                return -1;
            }
        }
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
    return -1;    
}

/* the http-body will be store in the area file_content that point to */
/* redundant is starting string of file_content */
/* expect_len is the expect len */
static int get_body_from_response (request_rec *r, apr_socket_t *s, apr_size_t expect_len, char *redundant, apr_size_t rlen, char *body, apr_size_t *p_blen)
{
    int i;
    apr_size_t len;
    apr_status_t rv;
    if (rlen > expect_len) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "fail to get expect size file content");
        return -1;
    }
    *p_blen = rlen;
    for (i = 0; i < rlen; i++)
        body[i] = redundant[i];
    body += rlen;
    while (1) {
        len = expect_len - *p_blen;
        if (len == 0) {
            char buf[1];
            len = 1;
            rv = apr_socket_recv (s, buf, &len);
            if (rv != APR_EOF) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "fail to get expect size file content");
                return -1;
            }
            break;
        }
        rv = apr_socket_recv (s, body, &len);
        *p_blen += len;
        body += len;
        if (rv == APR_EOF || len == 0)
            break;
    }
    if (*p_blen != expect_len) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "fail to get expect size file content");
        return -1;
    }
    return 0;
}

/* get location value from header, store in what *p_url points to */
static int get_location_from_header (request_rec *r, char *header, apr_size_t hlen, char **p_url)
{
    apr_pool_t *rp = r -> pool;
    int i, j;
    for (i = 0; i + 9 <= hlen; i++)
        if (strncmp (header + i, "Location:", 9) == 0)
            break;
    if (i + 9 > hlen) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "location unfound");
#endif
        return -1;
    }
    i += 9;
    for (j = i; j < hlen; j++)
        if (header[j] == '\r')
            break;
    if (j >= hlen)
        return -1;
    *p_url = apr_pstrmemdup (rp, header + i + 1, j - (i + 1));
    return 0;
}

/* get the date value from http header, store in date */
/* return -1 means error */
static int get_date_from_header (request_rec *r, char *header, apr_size_t hlen, char **date)
{
    int i, j;
    apr_pool_t *rp = r -> pool;
    for (i = 0; i + 5 <= hlen; i++)
        if (strncmp (header + i, "Date:", 5) == 0)
            break;
    if (i + 5 > hlen)  {
#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "date unfound");
#endif
        return -1;
    }
    i += 5;
    for (j = i; j < hlen; j++)
        if (header[j] == '\r')
            break;
    if (j >= hlen) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
        return -1;
    }
    *date = apr_pstrmemdup (rp, header + i + 1, j - (i + 1));
    return 0;
}

static int get_content_type_from_header (request_rec *r, char *header, apr_size_t hlen, char **content_type)
{
    int i, j;
    apr_pool_t *rp = r -> pool;
    for (i = 0; i + 13 <= hlen; i++)
        if (strncmp (header + i, "Content-Type:", 13) == 0)
            break;
    if (i + 13 > hlen)  {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Content-Type unfound");
#endif
        return -1;
    }
    i += 13;
    for (j = i; j < hlen; j++)
        if (header[j] == '\r')
            break;
    if (j >= hlen) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
        return -1;
    }
    *content_type = apr_pstrmemdup (rp, header + i + 1, j - (i + 1));
    return 0;
}

/* input:file_content and file_len, file_content must end with '\n' */
/* output:p_ipsubnet_list */
static void get_ipsubnet_list_from_file_content (request_rec *r, apr_pool_t *mp, char *file_content, apr_int64_t file_len, apr_array_header_t **p_ipsubnet_list)
{
    int i, j, k;
    int cr = 0, cn = 0;
    apr_status_t rv;
    char *tp;
    apr_ipsubnet_t **pip;
    char errmsg_buf[120];

    *p_ipsubnet_list = apr_array_make (mp, 0, sizeof (apr_ipsubnet_t*));
    for (i = j = 0; i <= file_len; i++) {
        if (file_content[i] == '\r' || file_content[i] == '\n') {
            file_content[i] == '\r' ? cr++ : cn++;
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
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "invalid ipsubnet address at line %d", MAX (cr, cn));
#ifdef DEBUG
                    apr_strerror (rv, errmsg_buf, sizeof (errmsg_buf));
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s", errmsg_buf);
#endif
                }
            }
            j = i + 1;
        }
    }
}

/* update expired data from infomation linked to the url*/
/* return 0 means OK, return -1 means ERROR */
static int update_expired_data_from_remote_info (request_rec *r, REMOTE_INFO *p_remote_info)
{
    apr_size_t len;
    char errmsg_buf[120];
    apr_pool_t *rp = r -> pool;
    apr_time_t cur_time = apr_time_now ();
    int redirect_cnt;

    char *now_url = apr_pstrdup (rp, p_remote_info -> remote_url);
    char *hostname;
    apr_int64_t port;
    char *filepath;
    
    apr_status_t rv;
    apr_socket_t *s;
    apr_sockaddr_t *sa;

    char *req_msg;
    char header[HEADER_SIZE + 10], redundant[HEADER_SIZE + 10];
    apr_size_t hlen, rlen;
    char *status_code;
    apr_size_t expect_len;
    char *content_type;
    char *file_content;
    apr_size_t flen;
    char *ts;

#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "before loop");
#endif

    if (!(p_remote_info -> subpool)) { /* create subpool */
        auth_remote_svr_conf *svr_conf = ap_get_module_config(r->server->module_config, &auth_remote_module);
        apr_status_t rv = apr_pool_create (&(p_remote_info -> subpool), svr_conf -> subpool);
        if (rv != APR_SUCCESS) {
            apr_strerror (rv, errmsg_buf, sizeof (errmsg_buf));
            ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "fail to create subpool for url: %s", errmsg_buf);
            return -1;
        }
    }
    if (!(p_remote_info -> last_update_time)) { /* init last_update_time */
        if (!(p_remote_info -> subpool)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
#ifdef DEBUG
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "fail to initial last_update_time as the pool is NULL");
#endif
            return -1;
        }
        p_remote_info -> last_update_time = apr_palloc (p_remote_info -> subpool, APR_RFC822_DATE_LEN);
        rv = apr_rfc822_date (p_remote_info -> last_update_time, 0);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "internal error");
#ifdef DEBUG
            apr_strerror (rv, errmsg_buf, sizeof (errmsg_buf));
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "fail to initialize last_update_time: %s", errmsg_buf);
#endif
            return -1;
        }
#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "init_last_update_time: %s", p_remote_info -> last_update_time);
#endif
    }

    for (redirect_cnt = 0; redirect_cnt <= MAX_REDIRECT_TIME; redirect_cnt++) {

        if (parse_url (r, now_url, &hostname, &port, &filepath) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "the module fail to get info from remote url, remote url in configuration file may be invalid.");
#ifdef DEBUG
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "fail to parse %s", now_url);
#endif
            return -1;
        }


#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "before build connection");
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "hostname: %s | filepath: %s | port: %lld", hostname, filepath, port);
#endif
            /* build connection */
        rv = build_connection (r, hostname, port, &s, &sa);
        if (rv != APR_SUCCESS) {
            apr_strerror (rv, errmsg_buf, sizeof (errmsg_buf));
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "connection error: %s", errmsg_buf);
            return -1;
        }

            /* set timeout */
        apr_socket_opt_set (s, APR_SO_NONBLOCK, 1);
        apr_socket_timeout_set (s, DEF_SOCK_TIMEOUT);

            /* send request */
        req_msg = apr_pstrcat(rp, "GET ", filepath, " HTTP/1.0", CRLF_STR, "If-Modified-Since: ", p_remote_info -> last_update_time, CRLF_STR, CRLF_STR, NULL);
        len = strlen (req_msg);
        rv = apr_socket_send (s, req_msg, &len);
        if (rv != APR_SUCCESS) {
            apr_strerror (rv, errmsg_buf, sizeof (errmsg_buf));
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "fail to send the request to url: %s", errmsg_buf);
            return -1;
        }

#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "before get header");
#endif
            /* get response header */
        hlen = rlen = HEADER_SIZE;
        if (get_header_from_response (r, s, header, &hlen, redundant, &rlen) == -1)
            return -1;

#ifdef DEBUG
        header[hlen] = '\0';
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "header: %s", header);
#endif

            /* get status code */
        if (get_status_code_from_header (r, header, hlen, &status_code) == -1)
            return -1;

#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "status code: %s", status_code);
#endif
        
            /* deal with different status_code */
        if (strcmp (status_code, "200") == 0 || (strcmp (status_code, "304") == 0 && strcmp (now_url, p_remote_info -> last_update_url) != 0)) {/* need to update */
            if (get_content_length_from_header (r, header, hlen, FILE_SIZE, &expect_len) == -1)
                return -1;

            if (get_content_type_from_header (r, header, hlen, &content_type) == -1)
                return -1;
#ifdef DEBUG
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Content-Type: %s", content_type);
#endif
            if (strncasecmp (content_type, "text", 4) != 0) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "the module fail to get info from remote url, remote url in configuration file may be invalid.");
                return -1;
            }
            
            file_content = apr_palloc (rp, expect_len + 2);
            if (get_body_from_response (r, s, expect_len, redundant, rlen, file_content, &flen) == -1)
                return -1;

/* #ifdef DEBUG */
/*             file_content[flen] = '\0'; */
/*             ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "file_content: %s", file_content); */
/* #endif */

                /* update last_update_time */
            if (get_date_from_header (r, header, hlen, &ts) == -1) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "date unfound");
                p_remote_info -> last_update_time = NULL;
            }
            else {
                p_remote_info -> last_update_time = apr_pstrdup (p_remote_info -> subpool, ts);
            }
                /* update last_update_url */
            p_remote_info -> last_update_url = apr_pstrdup (p_remote_info -> subpool, now_url);

                /* clear the pool, preventing leakage */
            apr_pool_clear (p_remote_info -> subpool);
            
                /* get the ipsubnet_list from file_content*/
            file_content[flen] = '\n';
            get_ipsubnet_list_from_file_content (r, p_remote_info -> subpool, file_content, flen, &(p_remote_info -> p_ipsubnet_list));

            return 0;
        }
        else if (strcmp (status_code, "304") == 0) {/* not modified */
            return 0;
        }
        else if (strcmp (status_code, "300") == 0 || strcmp (status_code, "301") == 0 || strcmp (status_code, "302") == 0 || strcmp (status_code, "307") == 0) {/* redirect */
            if (get_location_from_header (r, header, hlen, &now_url) == -1) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "the module fail to get info from remote url, remote url in configuration file may be invalid.");
                return -1;
            }
            continue;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "the module fail to get info from remote url, remote url in configuration file may be invalid.");
            return -1;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "the remote url redirects too many times, auth_remote_module stop updating data from url to prevent infinite redirection loop");
    return -1;
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

static int ip_in_url_test (request_rec *r, apr_sockaddr_t *ip_to_be_test,REMOTE_INFO *p_remote_info, apr_time_t expire_time)
{
    apr_status_t rv;
    char errmsg_buf[120];

#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cur_time: %lld | last_contact_time: %lld | last_update_time: %s | expire_time: %lld", apr_time_now (), p_remote_info -> last_contact_time, p_remote_info -> last_update_time, expire_time);
#endif

    if (apr_time_now () - p_remote_info -> last_contact_time > expire_time) { /* the ip-list from url is expired */
        p_remote_info -> last_contact_time = apr_time_now ();
        if (update_expired_data_from_remote_info (r, p_remote_info) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "fail to update expired data, the ipsubnet-list remains unchanged, after remote_expire_time next update will be invoked by another request");
        }
    }

        /* check if the request's ip is match one of the ipsubnets getting from url */
    return ip_in_ipsubnet_list_test (ip_to_be_test, p_remote_info -> p_ipsubnet_list);
}

static int find_allowdeny(request_rec *r, apr_array_header_t *a, int method, apr_time_t expire_time)
{

    allowdeny *ap = (allowdeny *) a->elts;
    apr_int64_t mmask = (AP_METHOD_BIT << method);
    int i;
    int gothost = 0;
    const char *remotehost = NULL;
    char errmsg_buf[120];

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
            if (ip_in_url_test (r, r->connection->remote_addr, &ap[i].x.remote_info, expire_time) == 1) {
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
        if (find_allowdeny(r, a->allows, method, a->expire_time)) {
            ret = OK;
        }
        if (find_allowdeny(r, a->denys, method, a->expire_time)) {
            ret = HTTP_FORBIDDEN;
        }
    }
    else if (a->order[method] == DENY_THEN_ALLOW) {
        if (find_allowdeny(r, a->denys, method, a->expire_time)) {
            ret = HTTP_FORBIDDEN;
        }
        if (find_allowdeny(r, a->allows, method, a->expire_time)) {
            ret = OK;
        }
    }
    else {
        if (find_allowdeny(r, a->allows, method, a->expire_time)
            && !find_allowdeny(r, a->denys, method, a->expire_time)) {
            ret = OK;
        }
        else {
            ret = HTTP_FORBIDDEN;
        }
    }

    if (ret == HTTP_FORBIDDEN && (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "client denied by auth_remote_module: %s%s", r->filename ? "" : "uri ", r->filename ? r->filename : r->uri);
    }

    return ret;
}

/* each time a subprocess is created, this function will initialize some configuration for this subprocess */
static void child_init (apr_pool_t *pchild, server_rec *s)
{
    apr_status_t rv;

    auth_remote_svr_conf *svr_conf = ap_get_module_config (s -> module_config, &auth_remote_module);
    rv = apr_pool_create(&(svr_conf->subpool), pchild);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pchild, "Failed to create subpool for my_module");
        return;
    }

        /* create mutex */
#if APR_HAS_THREADS
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
