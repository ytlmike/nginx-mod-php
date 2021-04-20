#include "ngx_handler.h"

#include "../ngx_http_php_module.h"

static int
php_nginx_startup(sapi_module_struct *module) {
    if (php_module_startup(module, NULL, 0) == FAILURE) {
        return FAILURE;
    }
    return SUCCESS;
}

static int
php_nginx_sapi_deactivate(void) {
    fflush(stdout);
    return SUCCESS;
}

static size_t
php_nginx_sapi_ub_write(const char *str, size_t str_length) {
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

    (*ctx->out_tail)->buf = php_nginx__build_buffer(ngx_php_request->pool, (const char *) str,
                                                    (unsigned int) str_length);
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
    if (fflush(stdout) == EOF) {
        php_handle_aborted_connection();
    }
    //TODO
}

static zend_stat_t *
php_nginx_sapi_get_stat(void) {
    //TODO
    return NULL;
}

static char *
php_nginx_sapi_getenv(char *name, size_t name_len) {
    //TODO
    return NULL;
}

static int
php_nginx_sapi_header_handler(sapi_header_struct *sapi_header, sapi_header_op_enum op,
                              sapi_headers_struct *sapi_headers) {
    //TODO
    return 0;
}

static int
php_nginx_sapi_send_headers(sapi_headers_struct *sapi_headers) {
    //TODO
    return SAPI_HEADER_SENT_SUCCESSFULLY;
}

static size_t php_nginx_sapi_read_post(char *buffer, size_t count_bytes) /* {{{ */
{
    //TODO
    return 0;
}

static char *
php_nginx_sapi_read_cookies(void) {
    //TODO
    return NULL;
}

void
nginx_php_set_header_variable(ngx_table_elt_t elt, zval *track_vars_array){
    char *upper, *dest;
    char *from = "-";
    char *to = "_";
    u_char *name = elt.key.data;
    size_t n = elt.key.len + 1;
    if (n == 0) {
        return;
    }
    upper = emalloc(n);
    dest = emalloc(n+5);
    char *upper_ptr = upper;
    while(--n) {
        if ((char)*name == *from) {
            *upper_ptr = *to;
        } else {
            *upper_ptr = (*name >= 'a' && *name <= 'z') ? (*name & ~0x20) : *name;
        }
        if (*name == '\0') {
            break;
        }
        name++;
        upper_ptr++;
    }
    *upper_ptr = '\0';
    sprintf(dest, "HTTP_%s", upper);
    php_register_variable_safe(dest, (char *) elt.value.data, elt.value.len, track_vars_array);
    efree(upper);
}

void
nginx_php_set_header_variable_name(ngx_table_elt_t elt, const char *name, const char *dest, void *default_val, zval *track_vars_array) {
    if (ngx_strncasecmp(elt.lowcase_key, (u_char *) name, elt.key.len) == 0) {
        php_register_variable_safe((char *)dest, (char *) elt.value.data, elt.value.len, track_vars_array);
    } else {
        if (default_val != NULL) {
            php_register_variable_safe((char *)dest, (char *)default_val, 0, track_vars_array);
        }
    }
}

char *
nginx_php_get_port(struct sockaddr_in *sin) {
    ngx_uint_t port;
    char *port_str;
    port_str = emalloc(sizeof("65535") - 1);
    port = ntohs(sin->sin_port);
    sprintf(port_str, "%lu", port);
    return port_str;
}

static void
php_nginx_sapi_register_variables(zval *track_vars_array) {
    ngx_http_request_t *r;
    ngx_http_core_srv_conf_t *serve_conf;
    ngx_http_php_loc_conf_t *my_conf;
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_uint_t i;
    char *method;

    php_import_environment_variables(track_vars_array);

    r = ngx_php_request;
    serve_conf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    my_conf = ngx_http_get_module_loc_conf(r, ngx_http_php_module);

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

    /*
SERVER_SOFTWARE: nginx/1.19.0 TODO
REQUEST_SCHEME: http TODO
DOCUMENT_ROOT: /home/ytlmike/code/blog/public
DOCUMENT_URI: /index.php
SCRIPT_NAME: /index.php
PHP_SELF: /index.php TODO
                  */

    php_register_variable("REQUEST_METHOD", method, track_vars_array);
    if (r->args.len > 0) {
        php_register_variable_safe("QUERY_STRING", (char *) r->args.data, r->args.len, track_vars_array);
    } else {
        php_register_variable_safe("QUERY_STRING", (char *) "", 0, track_vars_array);
    }
    php_register_variable_safe("DOCUMENT_ROOT", (char *) my_conf->filename.data, my_conf->filename.len, track_vars_array); //TODO
    php_register_variable_safe("DOCUMENT_URI", (char *) r->uri.data, r->uri.len, track_vars_array); //TODO
    php_register_variable_safe("SCRIPT_FILENAME", (char *) my_conf->filename.data, my_conf->filename.len, track_vars_array);
    php_register_variable_safe("SCRIPT_NAME", (char *) r->uri.data, r->uri.len, track_vars_array); //TODO
    php_register_variable_safe("REQUEST_URI", (char *) r->uri_start,strlen((char *) r->uri_start) - strlen((char *) r->uri_end), track_vars_array);
    php_register_variable_safe("REMOTE_ADDR", (char *) r->connection->addr_text.data, r->connection->addr_text.len, track_vars_array);
    php_register_variable("REMOTE_PORT", nginx_php_get_port((struct sockaddr_in *) r->connection->sockaddr), track_vars_array);

    ngx_str_t addr;
    u_char     addr_str[NGX_SOCKADDR_STRLEN];
    addr.len = NGX_SOCKADDR_STRLEN;
    addr.data = addr_str;
    ngx_connection_local_sockaddr(r->connection, &addr, 0);
    php_register_variable_safe("SERVER_ADDR", (char *)addr.data, addr.len, track_vars_array);
    php_register_variable("SERVER_PORT", nginx_php_get_port((struct sockaddr_in *) r->connection->local_sockaddr), track_vars_array);
    php_register_variable_safe("SERVER_NAME", (char *) serve_conf->server_name.data, serve_conf->server_name.len, track_vars_array);
    php_register_variable_safe("SERVER_PROTOCOL", (char *) r->http_protocol.data, r->http_protocol.len, track_vars_array);

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
        nginx_php_set_header_variable_name(header[i], "content-type", "CONTENT_TYPE", "", track_vars_array);
        nginx_php_set_header_variable_name(header[i], "content-length", "CONTENT_LENGTH", "", track_vars_array);
        nginx_php_set_header_variable(header[i], track_vars_array);
    }
}

static void
php_nginx_sapi_log_message(char *msg, int syslog_type_int) {
    fprintf(stderr, "%s\n", msg);
    //TODO
}

static double php_nginx_sapi_get_request_time(void) {
    return (double) 0;
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
        php_nginx_sapi_get_stat,        /* get uid */
        php_nginx_sapi_getenv,      /* getenv */

        php_error,                      /* error handler */

        php_nginx_sapi_header_handler,  /* header handler */
        php_nginx_sapi_send_headers,    /* send headers handler */
        NULL,                           /* send header handler */

        php_nginx_sapi_read_post,       /* read POST data */
        php_nginx_sapi_read_cookies,    /* read Cookies */

        php_nginx_sapi_register_variables,  /* register server variables */
        php_nginx_sapi_log_message,         /* Log message */
        php_nginx_sapi_get_request_time,    /* Get request time */
        NULL,                                /* Child terminate */

        STANDARD_SAPI_MODULE_PROPERTIES
};

int
php_nginx_handler_startup(int argc, char **argv) {
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
php_nginx_execute_script(const char *filename) {
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

ngx_buf_t *
php_nginx__build_buffer(ngx_pool_t *pool, const char *str, unsigned int len) {
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