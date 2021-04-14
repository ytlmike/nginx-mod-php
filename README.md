# nginx-mod-php
A ngx-module to run php script

## Install

linux only yet.

- prepare php
    - install php
    - exec:
    ```shell
    cp path_to_php/lib/libphp7.so lib/php
    export PHP_INC=path_to_php/include
    ```
    
- get nginx source code
    ```shell
    wget 'http://nginx.org/download/nginx-1.19.0.tar.gz'
    tar -zxvf nginx-1.19.0.tar.gz
    cd nginx-1.19.0
    ./configure --user=www --group=www \
                --prefix=/usr/local/nginx_php \
                --add-module=/path_to_nginx_mod_php
    ```

## Config

```
location /demo {
    load_php path_to_your_php_file;
}
```

## Opcache
the opcache extension is not support embed sapi by default, to enable it, you should change your php source code and rebuild php.
the code is in `php-src/ext/opcache/ZendAccelerator.c`, find `accel_find_sapi` function and add "embed" to `upported_sapis[]`