#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <php_embed.h>

#include "defined.h"

char * ngx_http_php_handle_post(ngx_conf_t *cf, void *data, void *filed);

char * ngx_http_php_handle_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_php_init(ngx_conf_t *cf);

static void *ngx_http_php_create_loc_conf(ngx_conf_t *cf);

static int nginx_http_run_php_file(char *filename);

static size_t ngx_http_php_ub_write(const char *str, size_t str_length TSRMLS_DC);

static ngx_buf_t *ngx_http_php_build_buffer(ngx_pool_t *pool, const char *str, unsigned int len);