#include "ngx_handler.h"
#include "helper.h"

static int
php_nginx_startup(sapi_module_struct *module) {

    printf("------------- SAPI_STARTUP ---------------\n");

    if (php_module_startup(module, NULL, 0) == FAILURE) {
        return FAILURE;
    }
    return SUCCESS;
}

static int
php_nginx_sapi_deactivate(void) {

    printf("------------- SAPI_DEACTIVATE ---------------\n");

    fflush(stdout);
    return SUCCESS;
}

static size_t
php_nginx_sapi_ub_write(const char *str, size_t str_length) {
    printf("------------- SAPI_UB_WRITE ---------------\n");

    ngx_http_php_ctx_t *ctx;
    ngx_http_request_t *r;

    r = ngx_php_request;
    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    if (ctx->out_head == NULL) {
        ctx->out_head = ngx_alloc_chain_link(r->pool);
        ctx->out_tail = &ctx->out_head;
    } else {
        (*ctx->out_tail)->next = ngx_alloc_chain_link(r->pool);
        ctx->out_tail = &(*ctx->out_tail)->next;
    }

    (*ctx->out_tail)->buf = php_nginx_build_buffer(r->pool, (const char *) str, (unsigned int) str_length);
    (*ctx->out_tail)->next = NULL;

    ngx_http_set_ctx(r, ctx, ngx_http_php_module);

    if (r->headers_out.content_length_n == -1) {
        r->headers_out.content_length_n += (long) str_length + 1;
    } else {
        r->headers_out.content_length_n += (long) str_length;
    }

    return r->headers_out.content_length_n;
}

static void
php_nginx_sapi_flush(void *server_context) {
    printf("------------- SAPI_FLUSH ---------------\n");

    nginx_php_ctx_t *ctx = server_context;
    sapi_send_headers();

    ctx->r->headers_out.status = SG(sapi_headers).http_response_code;
    SG(headers_sent) = 1;

    if (fflush(stdout) == EOF) {
        php_handle_aborted_connection();
    }
}

static int
php_nginx_sapi_header_handler(sapi_header_struct *sapi_header, sapi_header_op_enum op, sapi_headers_struct *sapi_headers) {
    ngx_http_request_t *r;
    ngx_table_elt_t *header;
    char *pos;

    if ((pos = ngx_strstr(sapi_header->header, ": ")) == NULL){
        return NGX_ERROR;
    }
    r = ngx_php_request;
    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL){
        return NGX_ERROR;
    }

    header->hash = 1;
    header->key.len = pos - sapi_header->header;
    header->key.data = ngx_pcalloc(r->pool, header->key.len);
    ngx_cpystrn((u_char *)header->key.data, (u_char *) sapi_header->header, header->key.len + 1);

    header->value.len = sapi_header->header_len - header->key.len - 2;
    header->value.data = ngx_pcalloc(r->pool, header->value.len);
    ngx_cpystrn((u_char *) header->value.data, (u_char *)(pos + 2), header->value.len + 1);

    return 0;
}

static int
php_nginx_sapi_send_headers(sapi_headers_struct *sapi_headers) {
    //TODO
    return SAPI_HEADER_SENT_SUCCESSFULLY;
}

static size_t
php_nginx_sapi_read_post(char *buffer, size_t count_bytes) {
    printf("------------- SAPI_READ_POST ---------------\n");
    nginx_php_ctx_t *php_ctx;
    ngx_chain_t *head;
    size_t read_len = 0;
    size_t remaining = SG(request_info).content_length - SG(read_post_bytes);

    if (remaining < count_bytes) {
        count_bytes = remaining;
    }

    php_ctx = SG(server_context);
    if (php_ctx->r->request_body == NULL || php_ctx->r->request_body->bufs == NULL) {
        return 0;
    }

    head = php_ctx->r->request_body->bufs;
    while(read_len < count_bytes) {
        memcpy(buffer+read_len, head->buf->pos + SG(read_post_bytes), count_bytes - read_len);
        read_len += count_bytes - read_len;
    }

    printf("------------- COUNT_BYTES: %zu ---------------\n", count_bytes);
    printf("------------- BODY_DATA: %s ---------------\n", buffer);

    return read_len;
}

static char *
php_nginx_sapi_read_cookies(void) {
    printf("------------- SAPI_READ_COOKIE ---------------\n");
    return SG(request_info).cookie_data;
}

char *
nginx_php_get_port(ngx_pool_t *pool, struct sockaddr_in *sin) {
    ngx_uint_t port;
    char *port_str;
    port_str = ngx_pcalloc(pool, sizeof("65535") - 1);
    port = ntohs(sin->sin_port);
    sprintf(port_str, "%lu", port);
    return port_str;
}

static void
php_nginx_sapi_register_variables(zval *track_vars_array) {

    printf("------------- SAPI_REGISTER_VAR ---------------\n");

    nginx_php_ctx_t *ctx;
    ngx_http_request_t *r;
    ngx_http_core_srv_conf_t *serve_conf;
    ngx_http_php_loc_conf_t *my_conf;
    ngx_list_part_t *part;
    ngx_table_elt_t *header;

    ngx_uint_t i;
    char *schema;

    php_import_environment_variables(track_vars_array);

    ctx = SG(server_context);
    r = ctx->r;
    serve_conf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    my_conf = ngx_http_get_module_loc_conf(r, ngx_http_php_module);

    schema = "http";
#if (NGX_HTTP_SSL)
    if (r->connection->ssl) {
        schema = "https";
    }
#endif
    php_register_variable("REQUEST_SCHEME", schema, track_vars_array);
    php_register_variable("REQUEST_METHOD", (char *)SG(request_info).request_method, track_vars_array);
    php_register_variable("QUERY_STRING", SG(request_info).query_string, track_vars_array);
    php_register_variable("REQUEST_URI", SG(request_info).request_uri, track_vars_array);
    php_register_variable("CONTENT_TYPE", (char *)SG(request_info).content_type, track_vars_array);

    php_register_variable_safe("PHP_SELF", (char *) ctx->script->uri.data, ctx->script->uri.len, track_vars_array);
    php_register_variable_safe("DOCUMENT_ROOT", (char *) ctx->script->dir.data, ctx->script->dir.len, track_vars_array);
    php_register_variable_safe("DOCUMENT_URI", (char *) ctx->script->uri.data, ctx->script->uri.len, track_vars_array);
    php_register_variable_safe("SCRIPT_FILENAME", (char *) my_conf->filename.data, my_conf->filename.len, track_vars_array);
    php_register_variable_safe("SCRIPT_NAME", (char *) ctx->script->uri.data, ctx->script->uri.len, track_vars_array);
    php_register_variable_safe("REMOTE_ADDR", (char *) r->connection->addr_text.data, r->connection->addr_text.len, track_vars_array);
    php_register_variable("REMOTE_PORT", nginx_php_get_port(r->pool, (struct sockaddr_in *) r->connection->sockaddr), track_vars_array);

    ngx_str_t addr;
    u_char     addr_str[NGX_SOCKADDR_STRLEN];
    addr.len = NGX_SOCKADDR_STRLEN;
    addr.data = addr_str;
    ngx_connection_local_sockaddr(r->connection, &addr, 0);
    php_register_variable_safe("SERVER_ADDR", (char *)addr.data, addr.len, track_vars_array);
    php_register_variable("SERVER_PORT", nginx_php_get_port(r->pool, (struct sockaddr_in *) r->connection->local_sockaddr), track_vars_array);
    php_register_variable_safe("SERVER_NAME", (char *) serve_conf->server_name.data, serve_conf->server_name.len, track_vars_array);
    php_register_variable_safe("SERVER_PROTOCOL", (char *) r->http_protocol.data, r->http_protocol.len, track_vars_array);
    php_register_variable("SERVER_SOFTWARE", NGINX_VER, track_vars_array);

    part = &r->headers_in.headers.part;
    header = part->elts;
    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }
        if (ngx_strncasecmp(header[i].lowcase_key, (u_char *) "content-length", header[i].key.len) == 0) {
            php_register_variable_safe((char *)"CONTENT_LENGTH", (char *) header[i].value.data, header[i].value.len, track_vars_array);
        }
        php_register_variable_safe(nginx_header_name_to_php_server_key(r->pool, &header[i]), (char *) header[i].value.data, header[i].value.len, track_vars_array);
    }
}

static void
php_nginx_sapi_log_message(char *msg, int syslog_type_int) {
    printf("------------- SAPI_LOG_MSG ---------------\n");

    fprintf(stderr, "%s\n", msg);
}

sapi_module_struct nginx_sapi_module = {
        "nginx_handler",                /* name */
        "PHP Nginx Handler",            /* pretty name */

        php_nginx_startup,              /* startup */
        php_module_shutdown_wrapper,    /* shutdown */

        NULL,                           /* activate */
        php_nginx_sapi_deactivate,      /* deactivate */

        php_nginx_sapi_ub_write,        /* unbuffered write */
        php_nginx_sapi_flush,           /* flush */
        NULL,                           /* get uid */
        NULL,                           /* getenv */

        php_error,                      /* error handler */

        php_nginx_sapi_header_handler,  /* header handler */
        php_nginx_sapi_send_headers,    /* send headers handler */
        NULL,                           /* send header handler */

        php_nginx_sapi_read_post,       /* read POST data */
        php_nginx_sapi_read_cookies,    /* read Cookies */

        php_nginx_sapi_register_variables,  /* register server variables */
        php_nginx_sapi_log_message,         /* Log message */
        NULL,    /* Get request time */
        NULL,                                /* Child terminate */

        STANDARD_SAPI_MODULE_PROPERTIES
};

int
php_nginx_handler_startup(int argc, char **argv) {
    printf("------------- SAPI_HANDLER_START_UP---------------\n");

#ifdef ZTS
    tsrm_startup(1, 1, 0, NULL);
    (void)ts_resource(0);
    ZEND_TSRMLS_CACHE_UPDATE();
#endif

    zend_signal_startup();

    sapi_startup(&nginx_sapi_module);
    if (nginx_sapi_module.startup(&nginx_sapi_module) == FAILURE) {
        return FAILURE;
    }

    return SUCCESS;
}

int
php_nginx_request_init(ngx_http_request_t *r, nginx_php_file_info *php_file) {
    nginx_php_ctx_t *ctx;

    ctx = SG(server_context);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        ctx->r = r;
        ctx->script = php_file;
        SG(server_context) = ctx;
    }

    SG(request_info).content_type = "";
    SG(request_info).path_translated = NULL;
    SG(request_info).proto_num = 1000;
    SG(sapi_headers).http_response_code = 200;
    SG(request_info).content_length = 0;
    SG(request_info).query_string = r->args.len > 0 ? nginx_str_to_char(r->pool, &r->args) : "";

    char *method;
    switch (r->method) {
        case NGX_HTTP_GET:
            method = (char *) "GET";
            break;
        case NGX_HTTP_POST:
            method = (char *) "POST";
            break;
        case NGX_HTTP_HEAD:
            method = (char *) "HEAD";
            break;
        case NGX_HTTP_PUT:
            method = (char *) "PUT";
            break;
        case NGX_HTTP_DELETE:
            method = (char *) "DELETE";
            break;
        case NGX_HTTP_OPTIONS:
            method = (char *) "OPTIONS";
            break;
        case NGX_HTTP_PATCH:
            method = (char *) "PATCH";
            break;
        case NGX_HTTP_TRACE:
            method = (char *) "TRACE";
            break;
        default:
            method = (char *) "";
    }
    SG(request_info).request_method = method;

    ngx_uint_t uri_len = r->uri_end - r->uri_start + 1;
    if (uri_len == 0) {
        SG(request_info).request_uri = "";
    } else {
        char *uri = ngx_pcalloc(r->pool, uri_len);
        ngx_cpystrn((u_char *)uri, r->uri_start, uri_len);
        SG(request_info).request_uri = uri;
    }

    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    part = &(r->headers_in.headers.part);
    header = part->elts;
    for (ngx_uint_t i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }
        if (ngx_strncasecmp(header[i].lowcase_key, (u_char *) "content-type", header[i].key.len) == 0) {
            SG(request_info).content_type = nginx_str_to_char(r->pool, &header[i].value);
        }
        if (ngx_strncasecmp(header[i].lowcase_key, (u_char *) "content-length", header[i].key.len) == 0) {
            SG(request_info).content_length = atoi(nginx_str_to_char(r->pool, &header[i].value));
        }
        if (ngx_strncasecmp(header[i].lowcase_key, (u_char *) "cookie", header[i].key.len) == 0) {
            SG(request_info).cookie_data = nginx_str_to_char(r->pool, &header[i].value);
        }
    }

    if (php_request_startup() == FAILURE) {
        return FAILURE;
    }

    return SUCCESS;
}

int
php_nginx_execute_script(ngx_http_request_t *r, nginx_php_file_info *php_file) {
    printf("------------- SAPI_EXEC_SCRIPT ---------------\n");

    if (php_nginx_request_init(r, php_file) == FAILURE) {
        return FAILURE;
    }

    zend_file_handle script;
    script.type = ZEND_HANDLE_FP;
    script.filename = nginx_str_to_char(r->pool, &php_file->full);
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

    SG(server_context) = NULL;
    php_request_shutdown((void *) 0);

    return 0;
}

ngx_buf_t *
php_nginx_build_buffer(ngx_pool_t *pool, const char *str, unsigned int len) {
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