/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the LICENSE file distributed with
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
#include <apr_thread_rwlock.h>
#include <apr_file_io.h>
#define FILE_SIZE ((17 + 1) * (20000 + 10))
#define HEADER_SIZE (4096)
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#define CRLF_STR "\r\n"
#define DEF_SOCK_TIMEOUT (APR_USEC_PER_SEC * 5)
#define DEF_PORT_NUM 80
#define DEF_EXPIRE_TIME 0 /* realtime*/
#define MAX_REDIRECT_TIME 50
#define MAX_EXPIRE_TIME 1000000000
#define MAX_EXPIRE_TIME_STR "1000000000"

enum allowdeny_type {
    T_ENV,
    T_NENV,
    T_ALL,
    T_IP,
    T_HOST,
    T_URL,
    T_FILE,
    T_FAIL
};

typedef struct {
    apr_time_t last_contact_time;
    char *last_update_time;
    char *last_update_url;
    char *remote_url;
    apr_array_header_t *p_ipsubnet_list;/* an array including pointers to apr_ipsubnet_t */
    apr_pool_t *subpool;
#if APR_HAS_THREADS
    apr_thread_rwlock_t *rwlock;
#endif
} REMOTE_INFO;

typedef struct 
{
    apr_time_t last_update_time;
    char *last_update_file;
    char *local_file;
    apr_array_header_t *p_ipsubnet_list;/* an array including pointers to apr_ipsubnet_t */
    apr_pool_t *subpool;
#if APR_HAS_THREADS
    apr_thread_rwlock_t *rwlock;
#endif    
} LOCAL_FILE_INFO;

typedef struct {
    apr_int64_t limited;
    union {
        char *from;
        apr_ipsubnet_t *ip;
        REMOTE_INFO remote_info;
        LOCAL_FILE_INFO local_file_info;
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
