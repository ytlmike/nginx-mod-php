//
// Created by ytlmike on 2021/4/20.
//

#include <ngx_http.h>

char *
nginx_str_to_char(ngx_pool_t *pool, ngx_str_t *str);

void
printf_ngx_str(const char *format, ngx_str_t *str);

char *
nginx_header_name_to_php_server_key(ngx_pool_t *pool, ngx_table_elt_t *header_elt);