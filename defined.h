typedef struct {
    ngx_str_t filename;
} ngx_http_php_loc_conf_t;

typedef struct ngx_http_php_ctx {
    ngx_chain_t *out_head;
    ngx_chain_t **out_tail;
} ngx_http_php_ctx_t;