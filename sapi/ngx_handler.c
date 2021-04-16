#include "ngx_handler.h"

#include "../ngx_http_php_module.h"

static int
php_nginx_startup(sapi_module_struct *module)
{
    if (php_module_startup(module, NULL, 0) == FAILURE) {
        return FAILURE;
    }
    return SUCCESS;
}

static int
php_nginx_sapi_deactivate(void)
{
    fflush(stdout);
    return SUCCESS;
}

static size_t
php_nginx_sapi_ub_write(const char *str, size_t str_length)
{
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
        r->headers_out.content_length_n += (long)str_length + 1;
    } else {
        r->headers_out.content_length_n += (long)str_length;
    }

    return r->headers_out.content_length_n;
}

static void
php_nginx_sapi_flush(void *server_context)
{
    if (fflush(stdout)==EOF) {
        php_handle_aborted_connection();
    }
    //TODO
}

static zend_stat_t*
php_nginx_sapi_get_stat(void)
{
    //TODO
    return NULL;
}

static char *
php_nginx_sapi_getenv(char *name, size_t name_len)
{
    //TODO
    return NULL;
}

static int
php_nginx_sapi_header_handler(sapi_header_struct *sapi_header, sapi_header_op_enum op, sapi_headers_struct *sapi_headers)
{
    //TODO
    return 0;
}

static int
php_nginx_sapi_send_headers(sapi_headers_struct *sapi_headers)
{
    //TODO
    return SAPI_HEADER_SENT_SUCCESSFULLY;
}

static size_t php_nginx_sapi_read_post(char *buffer, size_t count_bytes) /* {{{ */
{
    //TODO
    return 0;
}

static char *
php_nginx_sapi_read_cookies(void)
{
    //TODO
    return NULL;
}

static void
php_nginx_sapi_register_variables(zval *track_vars_array)
{
    php_import_environment_variables(track_vars_array);
    //TODO
}

static void
php_nginx_sapi_log_message(char *msg, int syslog_type_int)
{
    fprintf (stderr, "%s\n", msg);
    //TODO
}

static double php_nginx_sapi_get_request_time(void)
{
    return (double)0;
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
    php_nginx_sapi_get_request_time,	/* Get request time */
	NULL,							    /* Child terminate */

	STANDARD_SAPI_MODULE_PROPERTIES
};

int php_nginx_handler_startup(int argc, char **argv) {
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

int php_nginx_execute_script(const char *filename) {
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

ngx_buf_t
*ngx_http_php_build_buffer(ngx_pool_t *pool, const char *str, unsigned int len) {
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