#include "ngx_http_php_module.h"
#include "sapi/ngx_handler.h"

ngx_http_request_t *ngx_php_request;
nginx_php_file_info *php_file;

static void * ngx_http_php_create_loc_conf(ngx_conf_t *cf);

static char * ngx_http_php_handle_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

ngx_int_t ngx_http_php_run(ngx_http_request_t *r);

void ngx_http_php_read_request_body_callback(ngx_http_request_t *r);

ngx_int_t ngx_http_php_init_ctx(ngx_http_request_t *r) ;

static ngx_command_t ngx_http_php_commands[] = {
        {
                ngx_string("load_php"),
                NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1,
                ngx_http_php_handle_conf,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_php_loc_conf_t, filename),
                NULL
        },
        ngx_null_command
};

static ngx_http_module_t ngx_http_php_module_ctx = {
        NULL,                           //pre_configuration
        NULL,                          //post_configuration
        NULL,                           //create main configuration
        NULL,                           //init main configuration
        NULL,                           //create server configuration
        NULL,                           //merge server configuration
        ngx_http_php_create_loc_conf,   //create location configuration
        NULL                            //merge location configuration
};

ngx_module_t ngx_http_php_module = {
        NGX_MODULE_V1,
        &ngx_http_php_module_ctx,   /* module context */
        ngx_http_php_commands,      /* module directives */
        NGX_HTTP_MODULE,            /* module type */
        NULL,                       /* init master */
        NULL,                       /* init module */
        NULL,                       /* init process */
        NULL,                       /* init thread */
        NULL,                       /* exit thread */
        NULL,                       /* exit process */
        NULL,                       /* exit master */
        NGX_MODULE_V1_PADDING
};

static void *
ngx_http_php_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_php_loc_conf_t *local_conf = NULL;
    local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_php_loc_conf_t));
    if (local_conf == NULL) {
        return NULL;
    }

    ngx_str_null(&local_conf->filename);
    ngx_php_request = NULL;

    return local_conf;
}

static ngx_int_t
ngx_http_php_handler(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_php_request = r;

    if (ngx_http_php_init_ctx(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if ((r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT || r->method == NGX_HTTP_DELETE || r->method == NGX_HTTP_PATCH)) {
        // read body
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
//        r->request_body_in_file_only = 1;
        rc = ngx_http_read_client_request_body(r, ngx_http_php_read_request_body_callback);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
    } else {
        ngx_http_php_run(r);
    }

    return NGX_DONE;
}

static char *
ngx_http_php_handle_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    printf("--------- READ_CONF ---------\n");

    ngx_http_php_loc_conf_t *php_conf;
    ngx_http_core_loc_conf_t *loc_conf;

    if (php_nginx_handler_startup(0, NULL) == FAILURE) {
        return NGX_CONF_ERROR;
    }

    loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    loc_conf->handler = ngx_http_php_handler;

    char *rv = ngx_conf_set_str_slot(cf, cmd, conf);
    php_conf = conf;
    php_file = nginx_file_path_to_dir(cf->pool, &php_conf->filename);
    if (php_file == NULL || php_conf->filename.len == 0) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "empty php script file");
        return NGX_CONF_ERROR;
    }

    return rv;
}

ngx_int_t
ngx_http_php_init_ctx(ngx_http_request_t *r) {
    ngx_http_php_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "cannot alloc ctx");
        return NGX_ERROR;
    }
    ctx->php_file = php_file;
    ngx_http_set_ctx(r, ctx, ngx_http_php_module);

    return NGX_OK;
}

void
ngx_http_php_read_request_body_callback(ngx_http_request_t *r) {
    ngx_int_t rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (r->request_body != NULL) {
        rc = ngx_http_php_run(r);
    }
    ngx_http_finalize_request(r, rc);
}

ngx_int_t
ngx_http_php_run(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_http_php_ctx_t *ctx;

    php_nginx_execute_script(r, php_file);

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    (*ctx->out_tail)->buf->last_buf = 1;
    (*ctx->out_tail)->buf->last_in_chain = 1;

    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
    r->headers_out.status = NGX_HTTP_OK;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || (int)r->header_only) {
        return rc;
    }

    rc = ngx_http_output_filter(r, ctx->out_head);
    ngx_http_set_ctx(r, NULL, ngx_http_php_module);

    return rc;
}