From:liushenzeng@hotmail.com

Title:ncache make error, thanks

Content:
```
[root@f7 ncache]# 
[root@f7 ncache]# 
[root@f7 ncache]# ./configure
checking for OS
 + Linux 2.6.20.3 i686
checking for C compiler ... found
 + using GNU C compiler
 + gcc version: 4.1.2 20070502 (Red Hat 4.1.2-12)
checking for gcc -pipe switch ... found
checking for gcc variadic macros ... found
checking for C99 variadic macros ... found
checking for unistd.h ... found
checking for inttypes.h ... found
checking for limits.h ... found
checking for sys/filio.h ... not found
checking for crypt.h ... found
checking for malloc.h ... found
checking for Linux specific features
 + rt signals found
checking for epoll ... found
checking for sendfile() ... found
checking for sendfile64() ... found
checking for sys/prctl.h ... found
checking for prctl(PR_SET_DUMPABLE) ... found
checking for sched_setaffinity() ... found
checking for nobody group ... found
checking for poll() ... found
checking f Configuration summary
  + threads are not used
  + using system PCRE library
  + OpenSSL library is not used
  + md5: using system crypto library
  + sha1 library is not used
  + using system zlib library
  nginx path prefix: "/usr/local/ncache"
  nginx binary file: "/usr/local/ncache/sbin/ncache"
  nginx configuration file: "/usr/local/ncache/conf/ncache.conf"
  nginx pid file: "/usr/local/ncache/logs/ncache.pid"
  nginx error log file: "/usr/local/ncache/logs/error.log"
  nginx http access log file: "/usr/local/ncache/logs/access.log"
  nginx http client request body temporary files: "/usr/local/ncache/client_body_temp"
  nginx http proxy temporary files: "/usr/local/ncache/proxy_temp"
  nginx http fastcgi temporary files: "/usr/local/ncache/fastcgi_temp"
[root@f7 ncache]# make 
make -f objs/Makefile
make[1]: Entering directory `/root/work/nginx/ncache'
gcc -c -O -pipe  -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Wno-unused-function -Wunused-variable -Wunused-value -Werror -g  -I src/core -I src/event -I src/event/modules -I src/os/unix -I objs \
                -o objs/src/core/nginx.o \
                src/core/nginx.c
In file included from src/os/unix/ngx_atomic.h:15,
                 from src/core/ngx_core.h:38,
                 from src/core/nginx.c:8:
src/os/unix/atomic.h:9:26: error: linux/config.h: No such file or directory
src/os/unix/atomic.h:10:28: error: linux/compiler.h: 
```

reply:
```
没有找到内核头文件 这个是src/os/unix/atomic.h头文件引起的，你可以用编辑器打开该文件，修改引用的头文件路径config.h 和 complier.h ，将他们对应到你操作系统的相应路径上就可以了

Ubuntu下安装内核头文件： 
                                apt-get   install   build-essential 


 
谢谢你告诉我们这个问题，我会去看看能不能尽量在安装文件里把这个路径问题解决，谢谢
```