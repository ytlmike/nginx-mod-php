//
// Created by ytlmike on 2021/4/20.
//

#include <ngx_http.h>

#ifndef HELPER_DEF
#define HELPER_DEF
typedef struct nginx_php_file_info {
    ngx_str_t full;
    ngx_str_t dir;
    ngx_str_t file;
    ngx_str_t ext;
    ngx_str_t uri;
} nginx_php_file_info;
#endif

char *
nginx_str_to_char(ngx_pool_t *pool, ngx_str_t *str);

void
printf_ngx_str(const char *format, ngx_str_t *str);

char *
nginx_header_name_to_php_server_key(ngx_pool_t *pool, ngx_table_elt_t *header_elt);

nginx_php_file_info *
nginx_file_path_to_dir(ngx_pool_t *pool, ngx_str_t * filename);
