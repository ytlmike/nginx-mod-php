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
