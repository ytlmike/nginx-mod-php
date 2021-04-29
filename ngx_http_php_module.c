#include "ngx_http_php_module.h"
#include "sapi/ngx_handler.h"

ngx_http_request_t *ngx_php_request;

static void * ngx_http_php_create_loc_conf(ngx_conf_t *cf);

static char * ngx_http_php_handle_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

ngx_int_t ngx_http_php_run(ngx_http_request_t *r);

void ngx_http_php_read_request_body_callback(ngx_http_request_t *r);

ngx_int_t ngx_http_php_init_ctx(ngx_http_request_t *r);

nginx_php_script_t *
nginx_file_path_to_dir(ngx_pool_t *pool, ngx_str_t *filename);

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

    ngx_http_core_loc_conf_t *loc_conf;

    if (php_nginx_handler_startup() == FAILURE) {
        return NGX_CONF_ERROR;
    }

    loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    loc_conf->handler = ngx_http_php_handler;

    return ngx_conf_set_str_slot(cf, cmd, conf);
}

ngx_int_t
ngx_http_php_init_ctx(ngx_http_request_t *r) {
    ngx_http_php_ctx_t *ctx;
    ngx_http_php_loc_conf_t *conf;
    nginx_php_script_t *php_script;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_php_module);
    if (conf->filename.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "empty php script file");
        return NGX_ERROR;
    }
    php_script = nginx_file_path_to_dir(r->pool, &conf->filename);
    if (php_script == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "alloc php_script failed");
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "cannot alloc ctx");
        return NGX_ERROR;
    }
    ctx->php_file = php_script;
    ngx_http_set_ctx(r, ctx, ngx_http_php_module);

    return NGX_OK;
}

void
ngx_http_php_read_request_body_callback(ngx_http_request_t *r) {
    ngx_http_php_ctx_t *ctx;
    ngx_int_t rc = NGX_HTTP_INTERNAL_SERVER_ERROR;

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    ctx->body_tmp_fd = 0;
    if (r->request_body->temp_file != NULL) {
        ctx->body_tmp_fd = ngx_open_file(r->request_body->temp_file->file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
        if (ctx->body_tmp_fd == NGX_INVALID_FILE) {
            fprintf(stderr, "Unable to open body tmp file: %s\n", r->request_body->temp_file->file.name.data);
            ngx_http_finalize_request(r, rc);
            return;
        }
        if (ngx_fd_info(ctx->body_tmp_fd, &ctx->body_tmp_fi) == NGX_FILE_ERROR) {
            fprintf(stderr, "Unable to get body tmp file info: %s\n",  r->request_body->temp_file->file.name.data);
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

    if (r->request_body != NULL) {
        rc = ngx_http_php_run(r);
        if (ctx->body_tmp_fd != 0) {
            ngx_close_file(ctx->body_tmp_fd);
            ngx_delete_file( r->request_body->temp_file->file.name.data);
        }
    }

    ngx_http_finalize_request(r, rc);
}

ngx_int_t
ngx_http_php_run(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_http_php_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    php_nginx_execute_script(r, ctx->php_file);

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    (*ctx->out_tail)->buf->last_buf = 1;
    (*ctx->out_tail)->buf->last_in_chain = 1;

    if (ctx->has_content_type == 0) {
        r->headers_out.content_type.len = sizeof("text/html") - 1;
        r->headers_out.content_type.data = (u_char *) "text/html";
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || (int)r->header_only) {
        return rc;
    }

    rc = ngx_http_output_filter(r, ctx->out_head);
    ngx_http_set_ctx(r, NULL, ngx_http_php_module);

    return rc;
}

/**
 * resolve a filepath to a nginx_php_script_t struct
 * @param pool
 * @param filename
 * @return
 */
nginx_php_script_t *
nginx_file_path_to_dir(ngx_pool_t *pool, ngx_str_t *filename) {
    size_t i;
    size_t dir_end_pos = 0;
    size_t ext_start_pos = 0;
    nginx_php_script_t *info;
    u_char *str, *dir, *ext, *file, *uri;
    u_char *dir_ptr, *ext_ptr, *file_ptr;

    u_char dir_mark[1] = "/";
    u_char ext_mark[1] = ".";
    str = filename->data;
    info = ngx_pcalloc(pool, sizeof(nginx_php_script_t));
    if (info == NULL) {
        return NULL;
    }

    for (i = 0; i < filename->len; i++) {
        if (*str == dir_mark[0]) {
            dir_end_pos = i;
        }
        if (*str == ext_mark[0]) {
            ext_start_pos = i + 1;
        }
        str++;
    }

    if (dir_end_pos == filename->len - 1 || ext_start_pos == filename->len - 1) {
        return NULL;
    }

    info->full = *filename;
    info->dir.len = dir_end_pos + 1;
    info->file.len = filename->len - dir_end_pos - 1;
    info->uri.len = filename->len - dir_end_pos;
    info->ext.len = filename->len - ext_start_pos;

    dir = ngx_pcalloc(pool, info->dir.len + 1);
    file = ngx_pcalloc(pool, info->file.len + 1);
    uri = ngx_pcalloc(pool, info->uri.len + 1);
    ext = ngx_pcalloc(pool, info->ext.len + 1);

    dir_ptr = dir;
    file_ptr = file;
    ext_ptr = ext;
    str = filename->data;
    for (i = 0; i < filename->len; i++) {
        if (i <= dir_end_pos) {
            *dir_ptr = *str;
            dir_ptr++;
        } else {
            *file_ptr = *str;
            file_ptr++;
        }
        if (i >= ext_start_pos) {
            *ext_ptr = *str;
            ext_ptr++;
        }
        str++;
    }
    *dir_ptr = '\0';
    *file_ptr = '\0';
    *ext_ptr = '\0';
    sprintf((char *)uri, "/%s", file);

    info->dir.data = dir;
    info->file.data = file;
    info->ext.data = ext;
    info->uri.data = uri;

    printf_ngx_str("------ URI: %s ----- \n", &info->uri);

    return info;
}