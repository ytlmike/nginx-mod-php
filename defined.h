typedef struct {
    ngx_str_t filename;
} ngx_http_php_loc_conf_t;

typedef struct ngx_http_php_ctx_s {
    ngx_chain_t *out_head;
    ngx_chain_t **out_tail;
} ngx_http_php_ctx_t;

typedef struct ngx_http_php_conf_ctx_s {
    zend_op_array *op_array;
} ngx_http_php_conf_ctx_t;