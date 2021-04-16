#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <php_embed.h>

ngx_http_request_t *ngx_php_request;

extern ngx_module_t ngx_http_php_module;

typedef struct {
    ngx_str_t filename;
} ngx_http_php_loc_conf_t;

typedef struct ngx_http_php_ctx_s {
    ngx_chain_t *out_head;
    ngx_chain_t **out_tail;
} ngx_http_php_ctx_t;