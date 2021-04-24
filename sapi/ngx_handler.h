#include "php.h"
#include "SAPI.h"
#include "php_main.h"
#include "php_variables.h"
#include "php_ini.h"
#include <zend_ini.h>

#include <ngx_http.h>
#include "../ngx_http_php_module.h"

extern sapi_module_struct nginx_sapi_module;

int php_nginx_handler_startup();

int php_nginx_execute_script(ngx_http_request_t *r, nginx_php_script_t *php_file);

ngx_buf_t *php_nginx_build_buffer(ngx_pool_t *pool, const char *str, unsigned int len);
