#include "ngx_http_php_module.h"

ngx_http_request_t *ngx_php_request;

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

static void *ngx_http_php_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_php_loc_conf_t *local_conf = NULL;
    local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_php_loc_conf_t));
    if (local_conf == NULL) {
        return NULL;
    }

    ngx_str_null(&local_conf->filename);
    ngx_php_request = NULL;

    return local_conf;
}

static ngx_int_t ngx_http_php_handler(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_http_php_loc_conf_t *my_conf;
    char *filename;
    ngx_http_php_ctx_t *ctx;

    ngx_php_request = r;
    my_conf = ngx_http_get_module_loc_conf(r, ngx_http_php_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_php_module);

    filename = ngx_pcalloc(r->pool, 1);
    ngx_cpystrn((u_char *) filename, my_conf->filename.data, my_conf->filename.len + 1);

    if (strlen(filename) == 0) {
        return NGX_OK;
    }

    nginx_http_run_php_file(filename);

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    (*ctx->out_tail)->buf->last_buf = 1;

    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
    r->headers_out.status = NGX_HTTP_OK;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    ngx_http_output_filter(r, ctx->out_head);
    ngx_http_set_ctx(r, NULL, ngx_http_php_module);

    return NGX_OK;
}

static char * ngx_http_php_handle_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    printf("--------- READ_CONF ---------\n");

    php_embed_module.ub_write = *ngx_http_php_ub_write;
    if (ngx_php_init(0, NULL) == FAILURE) {
        return NGX_CONF_ERROR;
    }

    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_php_handler;

    return ngx_conf_set_str_slot(cf, cmd, conf);
}

static int nginx_http_run_php_file(char *filename) {
    if (php_request_startup() == FAILURE) {
        return FAILURE;
    }
    zend_file_handle script;
    script.type = ZEND_HANDLE_FP;
    script.filename = filename;
    script.opened_path = NULL;
    script.free_filename = 0;
    if (!(script.handle.fp = fopen(script.filename, "rb"))) {
        fprintf(stderr, "Unable to open: %s\n", script.filename);
        return -1;
    }

    zend_first_try
    {
        php_execute_script(&script);
    }
    zend_catch
    {}
    zend_end_try();
    php_request_shutdown((void *) 0);

    return 0;
}

static size_t ngx_http_php_ub_write(const char *str, size_t str_length TSRMLS_DC) {
    ngx_http_php_ctx_t *ctx;
    ngx_http_request_t *r;

    r = ngx_php_request;
    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    if (ctx->out_head == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_php_ctx_t));
        ctx->out_head = ngx_alloc_chain_link(r->pool);
        ctx->out_tail = &ctx->out_head;
    } else {
        (*ctx->out_tail)->next = ngx_alloc_chain_link(r->pool);
        ctx->out_tail = &(*ctx->out_tail)->next;
    }

    (*ctx->out_tail)->buf = ngx_http_php_build_buffer(ngx_php_request->pool, (const char *) str,
                                                      (unsigned int) str_length);
    (*ctx->out_tail)->next = NULL;

    ngx_http_set_ctx(r, ctx, ngx_http_php_module);

    if (r->headers_out.content_length_n == -1) {
        r->headers_out.content_length_n += str_length + 1;
    } else {
        r->headers_out.content_length_n += str_length;
    }

    return r->headers_out.content_length_n;
}

int ngx_php_init(int argc, char **argv) {
    zend_llist global_vars;

#if defined(SIGPIPE) && defined(SIG_IGN)
    signal(SIGPIPE, SIG_IGN);
#endif

#ifdef ZTS
    php_tsrm_startup();
# ifdef PHP_WIN32
  ZEND_TSRMLS_CACHE_UPDATE();
# endif
#endif

    zend_signal_startup();

    sapi_startup(&php_embed_module);

    if (php_embed_module.startup(&php_embed_module) == FAILURE) {
        return FAILURE;
    }

    zend_llist_init(&global_vars, sizeof(char *), NULL, 0);

    /* Set some Embedded PHP defaults */
    SG(options) |= SAPI_OPTION_NO_CHDIR;

    SG(headers_sent) = 1;
    SG(request_info).no_headers = 1;
    php_register_variable("PHP_SELF", "-", NULL);

    return SUCCESS;
}

/**
 * build a buffer pointer as ngx_buf_t
 * @param pool
 * @param str
 * @return
 */
static ngx_buf_t *ngx_http_php_build_buffer(ngx_pool_t *pool, const char *str, unsigned int len) {
    ngx_buf_t *b;
    ngx_str_t ns;
    u_char *u_str;

    ns.data = (u_char *) str;
    ns.len = len;

    u_str = ngx_pstrdup(pool, &ns);
    u_str[ns.len] = '\0';

    b = ngx_pcalloc(pool, sizeof(ngx_buf_t));
    b->pos = u_str;
    b->last = u_str + ns.len;
    b->memory = 1;

    return b;
}

//static ngx_int_t ngx_http_php_init(ngx_conf_t *cf) {
//    printf("--------- INIT ---------\n");
//    ngx_http_handler_pt *h;
//    ngx_http_core_main_conf_t *cmcf;
//
//    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
//    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
//    if (h == NULL) {
//        return NGX_ERROR;
//    }
//
//    *h = ngx_http_php_handler;
//    return NGX_OK;
//}