//
// Created by ytlmike on 2021/4/20.
//
#include "helper.h"

/**
 * convert ngx_str_t to char *
 * @param pool
 * @param str
 * @return
 */
char *
nginx_str_to_char(ngx_pool_t *pool, ngx_str_t *str) {
    char *c;
    c = ngx_pcalloc(pool, str->len +1);
    if (c != NULL) {
        ngx_cpystrn((u_char *)c, str->data, str->len + 1);
    }
    return c;
}

/**
 * print ngx_str_t data
 * @param format
 * @param str
 */
void
printf_ngx_str(const char *format, ngx_str_t *str) {
    if (str == NULL) {
        printf(format, NULL);
        return;
    }
    u_char *s = malloc(str->len + 1);
    if (s != NULL) {
        ngx_cpystrn(s, str->data, str->len + 1);
        printf(format, s);
        free(s);
    }
}

/**
 * convert header name to php $_SERVER key name,
 * @exp "cache-control" => "HTTP_CACHE_CONTROL"
 * @param pool
 * @param header_elt
 * @return
 */
char *
nginx_header_name_to_php_server_key(ngx_pool_t *pool, ngx_table_elt_t *header_elt) {
    char *upper, *dest, *from, *to;
    u_char *name;
    size_t n;

    n = header_elt->key.len + 1;
    if (n == 0) {
        return NULL;
    }
    name = header_elt->key.data;
    from = "-";
    to = "_";
    upper = malloc(n);
    dest = ngx_pcalloc(pool, n + 5);
    char *upper_ptr = upper;
    while (--n) {
        if ((char) *name == *from) {
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
    free(upper);

    return dest;
}

/**
 * resolve a filepath to a nginx_php_file_info struct
 * @param pool
 * @param filename
 * @return
 */
nginx_php_file_info *
nginx_file_path_to_dir(ngx_pool_t *pool, ngx_str_t *filename) {
    size_t i;
    size_t dir_end_pos = 0;
    size_t ext_start_pos = 0;
    nginx_php_file_info *info;
    u_char *str, *dir, *ext, *file, *uri;
    u_char *dir_ptr, *ext_ptr, *file_ptr;

    u_char dir_mark[1] = "/";
    u_char ext_mark[1] = ".";
    str = filename->data;
    info = ngx_pcalloc(pool, sizeof(nginx_php_file_info));

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

