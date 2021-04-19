#include "php.h"
#include "SAPI.h"
#include "php_main.h"
#include "php_variables.h"
#include "php_ini.h"
#include <zend_ini.h>

#include <ngx_http.h>

extern sapi_module_struct nginx_sapi_module;

int php_nginx_handler_startup(int argc, char **argv);

int php_nginx_execute_script(const char *filename);

ngx_buf_t *php_nginx__build_buffer(ngx_pool_t *pool, const char *str, unsigned int len);
