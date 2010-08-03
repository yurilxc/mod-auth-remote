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

/* modified */
#define DEBUG
#include <stdio.h>
#define BUFSIZE 255
#define FILE_BUFSIZE ((16 + 1) * (20000 + 10))
//#define FILE_BUFSIZE (10)
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#define CRLF_STR "\r\n"
#define DEF_SOCK_TIMEOUT (APR_USEC_PER_SEC * 4)
/* realtime*/
#define DEF_EXPIRE_TIME 0

enum allowdeny_type {
    T_ENV,
    T_NENV,
    T_ALL,
    T_IP,
    T_HOST,
    T_URL,                      /* modified */
    T_FAIL
};

typedef struct {
    apr_int64_t limited;
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
    apr_time_t last_update_time;/* modified */
    apr_time_t expire_time;/* modified */
    apr_array_header_t *allows;
    apr_array_header_t *denys;
} auth_remote_dir_conf;

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

    /* modified */
    conf->last_update_time = 0;
    conf->expire_time = DEF_EXPIRE_TIME;
    
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

/* modified */
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
            d->expire_time = apr_time_from_msec (ttime);
    return NULL;
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
    else if (!strncasecmp (where, "url=", 4))   /* modified */ {
        a->type = T_URL;
        a->x.from += 4;
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
    /* modified */
    AP_INIT_TAKE1("remote_expire_time", expire_time_cmd, NULL, OR_LIMIT,
                  "a nonnegative integer indicating expire milliseconds"),
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

/* seperate url to hostname port and filepath */
static int seperate_url (char *remote_url, char **hostname, apr_int64_t *p_port_num, char **filepath, request_rec *r)
{
    /* else if ((s = ap_strchr(where, '/'))) { */
    /* *s++ = '\0'; */
    printf ("get in seperate_url\n");
    char * p_port_str;
    char * p_tmp;
    apr_pool_t *mp = r -> pool;
    server_rec *sr = r -> server;  
   
    *hostname = remote_url;
    if (!strncasecmp (*hostname, "http://", 7)) {
        *hostname += 7;
    }
    
    p_tmp = ap_strchr (*hostname, '/');
    if (!p_tmp) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "%s", *hostname);
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, sr, "no filepath in url");
        return 0;
    }
    *filepath = apr_pstrdup (mp, p_tmp);
    *p_tmp = '\0';

    if (p_port_str = ap_strchr (*hostname, ':')) {
        *p_port_str = 0;
        p_port_str++;
        *p_port_num = apr_atoi64 (p_port_str);
    }
    else {
        *p_port_num = 80;       /* default port number*/
    }
    
    #ifdef DEBUG
    printf ("get out seperate_url\n");
    if (*hostname)
        printf ("hostname: %s\n", *hostname);
    else
        printf ("no hostname\n");
    printf ("port: %d\n", (int)(*p_port_num));
    if (*filepath)
        printf ("filepath: %s\n", *filepath);
    else
        printf ("no filepath\n");
    printf ("\n");
    #endif DEBUG
    
    return 1;
}

/* modified */
/* the first arg should not be of complex forms */
static int ip_match (apr_sockaddr_t *ip, char *mode, request_rec *r)
{
    apr_status_t rv;
    char *s;
    apr_ipsubnet_t *url_ip;
    apr_pool_t *mp = r -> pool;
    server_rec *sr = r -> server;
    char errmsg_buf[120];

        /* blank line is invalid in allow(deny) directive, but if it appears in the ip-list from url, it will incorectly match all ip in my module */
    {
        int i, len = strlen (mode);
        for (i = 0; i < len; i++) /* it also exclude the situation when (strlen(mode) == 0) */
            if (mode[i] != ' ') {
                break;
            }
        if (i >= len) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, sr, "url is a blank line.");
            return 0;
        }
    }
    
    if (s = ap_strchr (mode, '/')) {
        *s++ = '\0';
        rv = apr_ipsubnet_create (&url_ip, mode, s, mp);
        if (APR_STATUS_IS_EINVAL(rv)) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, sr, "a directive in url is not a valid ip address.");
            return 0;
        }
        else if (rv != APR_SUCCESS) {
            apr_strerror (rv, errmsg_buf, sizeof (errmsg_buf));
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, sr, "%s", errmsg_buf);
            return 0;
        }
     }
    else {
        rv = apr_ipsubnet_create (&url_ip, mode, NULL, mp);
        if (rv != APR_SUCCESS) {
            apr_strerror (rv, errmsg_buf, sizeof (errmsg_buf));
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, sr, "%s", errmsg_buf);
            return 0;
        }
    }
    #ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "mode: %s", mode);
    #endif DEBUG

    if (apr_ipsubnet_test (url_ip, ip)) {
        return 1;
    }
    #ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "ip match failed!");
    #endif DEBUG
    return 0;
}

/* modified */
static apr_status_t my_connection (apr_sockaddr_t **psa, apr_socket_t **ps, char *hostname, apr_int64_t port, request_rec *r)
{
    apr_status_t rv;
    apr_pool_t *mp = r -> pool;
    rv = apr_sockaddr_info_get (psa, hostname, APR_INET, port, 0, mp);
    if (rv != APR_SUCCESS)
        return rv;
    rv = apr_socket_create (ps, (*psa)->family, SOCK_STREAM, APR_PROTO_TCP, mp);
    if (rv != APR_SUCCESS)
        return rv;
    rv = apr_socket_connect (*ps, *psa);
    return rv;
}

static int get_ip_list (apr_socket_t *s, char filepath[], char filebuf[], int filebuf_len, request_rec *r)
{
    #ifdef BLOCKFOREVER
    #else
    apr_socket_opt_set(s, APR_SO_NONBLOCK, 1);
    apr_socket_timeout_set(s, DEF_SOCK_TIMEOUT);
    #endif BLOCKFOREVER

    apr_size_t len;
    apr_status_t rv;
    apr_pool_t *mp = r -> pool;
    server_rec *sr = r -> server;
    const char *req_msg = apr_pstrcat(mp, "GET ", filepath, " HTTP/1.0" CRLF_STR CRLF_STR, NULL);
    char errmsg_buf[120];
    len = strlen (req_msg);
    rv = apr_socket_send (s, req_msg, &len);
    if (rv != APR_SUCCESS) {
        apr_strerror (rv, errmsg_buf, sizeof (errmsg_buf));
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, sr, "%s", errmsg_buf);
        return 0;
    }
    
    char *nfilebuf = filebuf;
    int filebuf_cnt = 0;
    memset (filebuf, 0, sizeof (char) * filebuf_len); /* for the loop to be terminated normally */
    while(1) {
        apr_size_t len = BUFSIZE;
        if (filebuf_cnt + len > filebuf_len) {/* file too large */
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, sr, "the file from url is too large");
            return 0;
        }
        rv = apr_socket_recv (s, nfilebuf, &len);
        filebuf_cnt += len;
        nfilebuf += len;
        if (rv == APR_EOF || len == 0) {
            break;
        }
    }
    filebuf[filebuf_cnt] = '\n';
    
    #ifdef BLOCKFOREVER
    #else
    apr_socket_opt_set(s, APR_SO_NONBLOCK, 0);
    apr_socket_timeout_set(s, DEF_SOCK_TIMEOUT);
    #endif BLOCKFOREVER

    return 1;
}

static int ip_in_url_test (char *ori_remote_url, apr_sockaddr_t *ip_to_be_test, apr_time_t *p_last_update_time, apr_time_t expire_time, request_rec *r) /* modified */
{
    apr_status_t rv;
    apr_pool_t *mp = r -> pool;
    server_rec *sr = r -> server;
    
    apr_socket_t *s;
    apr_sockaddr_t *sa;

    char *hostname;
    char *filepath;
    apr_int64_t port;

    char errmsg_buf[120];

    char *remote_url;
    remote_url = apr_pstrdup (mp, ori_remote_url); /* remote_url will be changed, so make a copy*/

    #ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "remote_url: %s", remote_url);
    #endif DEBUG

    /* seperate url to hostname port and filepath */
    if (!seperate_url (remote_url, &hostname, &port, &filepath, r)) { /* error */
        return 0;
    }
    else {                      /* normal */
        ;
    }

    #ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "filepath: %s", filepath);
    #endif DEBUG

    apr_time_t cur_time; /* current time */
    cur_time = apr_time_now ();
    static char filebuf[FILE_BUFSIZE + 10];
  
    if (cur_time - *p_last_update_time > expire_time) { /* the ip-list from url is expired */

        #ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "cur_time: %lld", cur_time);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "last_update_time: %lld", *p_last_update_time);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "expire_time: %lld", expire_time);
        #endif DEBUG
        
        /* update last_update_time */
        *p_last_update_time = cur_time;
        
            /* connection */
        rv = my_connection (&sa, &s, hostname, port, r);
        if (rv != APR_SUCCESS) {
            apr_strerror (rv, errmsg_buf, sizeof (errmsg_buf));
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, sr, "%s", errmsg_buf);
            return 0;
        }

            /* get ip-list from url */
        if (!get_ip_list (s, filepath, filebuf, FILE_BUFSIZE, r))
            return 0;

        #ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "expire_update_filebuf: %s", filebuf);
        #endif DEBUG
    }

    /* process the request whth the data recv from url */
    //char *nfilebuf = filebuf;
    char *nfilebuf = apr_pstrdup (mp, filebuf);
    while (1) {
        char *t1 = ap_strchr (nfilebuf, '\r');
        char *t2 = ap_strchr (nfilebuf, '\n');
        if (t1)
            *t1 = '\0';
        if (t2)
            *t2 = '\0';
        if (!t1 && !t2) {       /* an unkonwn bug */
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, sr, "an unknown bug");
            return 0;
        }
        if (strlen (nfilebuf) == 0) { /* blank line */
            nfilebuf = MAX(t1,t2) + 1;
            break;
        }
        nfilebuf = MAX(t1,t2) + 1;
    }
    #ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "nfilebuf: %s", nfilebuf);
    #endif DEBUG
    while (1) {
        char *t1 = ap_strchr (nfilebuf, '\r');
        char *t2 = ap_strchr (nfilebuf, '\n');
        #ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "nfilebuf_len: %d", strlen (nfilebuf));
        #endif DEBUG
        if (t1)
            *t1 = '\0';
        if (t2)
            *t2 = '\0';
        if (!t1 && !t2) {
            break;
        }
        #ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr, "nfilebuf %s", nfilebuf);
        #endif DEBUG

        if (ip_match (ip_to_be_test, nfilebuf, r))  {
            return 1;
        }
        if (t1 && t2) {
            nfilebuf = MAX(t1,t2) + 1;
        }
        else if (t1) {
            nfilebuf = t1 + 1;
        }
        else if (t2) {
            nfilebuf = t2 + 1;
        }
        else  {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, sr, "an unknown bug");
            return 0;
        }
    }
    return 0;
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

        case T_URL:             /* modified */
            if (ip_in_url_test (ap[i].x.from, r->connection->remote_addr, p_last_update_time, expire_time, r) == 1) {
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

    /* modified */
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

    if (ret == HTTP_FORBIDDEN
        && (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "client denied by server configuration: %s%s",
            r->filename ? "" : "uri ",
            r->filename ? r->filename : r->uri);
    }

    return ret;
}

static void auth_remote_hooks(apr_pool_t *p)
{
    /* This can be access checker since we don't require r->user to be set. */
    ap_hook_access_checker(check_dir_access,NULL,NULL,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_remote_module =
{
    STANDARD20_MODULE_STUFF,
    create_auth_remote_dir_config,   /* dir config creater */
    NULL,                           /* dir merger --- default is to override */
    NULL,                           /* server config */
    NULL,                           /* merge server config */
    auth_remote_cmds,
    auth_remote_hooks                  /* register hooks */
};
