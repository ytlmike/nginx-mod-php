#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "sapi/helper.h"

extern ngx_http_request_t *ngx_php_request;
extern ngx_module_t ngx_http_php_module;

#ifndef NGX_PHP_MODULE_DEF
#define NGX_PHP_MODULE_DEF
typedef struct {
    ngx_str_t filename;
} ngx_http_php_loc_conf_t;

typedef struct nginx_php_script_s {
    ngx_str_t full;
    ngx_str_t dir;
    ngx_str_t file;
    ngx_str_t ext;
    ngx_str_t uri;
} nginx_php_script_t;

typedef struct ngx_http_php_ctx_s {
    ngx_chain_t *out_head;
    ngx_chain_t **out_tail;
    nginx_php_script_t *php_file;
    ngx_fd_t body_tmp_fd;
    ngx_file_info_t body_tmp_fi;
    int has_content_type;
} ngx_http_php_ctx_t;
#endif