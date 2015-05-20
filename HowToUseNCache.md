# How to use ncache #


  * delete the old ncache files and folders

  * install the ncache
```
    ./configure

    make 

    make install
```

> edit your config file at
```
      {install_prefix}/conf/ncache.conf
```

> run the "mkdir\_ngx\_cache.sh" to make cache dir:
```
      {install_prefix}/bin/mkdir_ngx_cache.sh {install_prefix}/conf/ncache.conf
```

  * example to make cache directories  :
```
      /usr/local/ncache/bin/mkdir_ngx_cache.sh /usr/local/ncache/conf/ncache.conf
```

> note:only support linux

  * example to config the ncache

```

  user  www www;

  worker_processes 4;
  
  #ulimit -n 20480
  worker_rlimit_nofile 20480;

  events
  {
    worker_connections  10240;
  }


  http
  {
    sendfile        on;

    keepalive_timeout  65;

    #here to set the free list max size 2 Power 24 about 30,000,000
    #in 1.2 or 1.1 it is 25
    cache_max_size 24;
    
    #the new config in v1.3 to set proxy big file buffer null
    proxy_buffering off;



    upstream backend
    {
      server 10.1.1.1;
      server 10.1.1.2;

      #just support 256,128,and 64
      #you must end path with '/' 
      cachedir /data0/ 128 128;
      cachedir /data1/ 64 64;
    }


    server
    {
      listen       80;

      set $purge_uri $request_uri;

      location /
      {
        if ($request_method ~ "PURGE")
        {
          rewrite (.*) /PURGE$1 last;
        }                                                                                         
        proxy_pass http://backend;
        
        #here you can ignore any client use "Cache-Control:no-cache" headers refresh the cache

        proxy_ignore_client_no_cache on;
      }                
      
      #allow some one who can use http PURGE method delete the caches
      location /PURGE/ 
      {   
        internal;        
        allow   10.1.1.0/24;           
        deny    all;
        purge;  
      }
      
      #use "http://{serverip}/status_infos" watch nginx services status
      location /status_infos
      {
        access_log      off;
        stub_status     on;
      }     
    }  
  }

```

  * backend set

> you must add the http header <sup>Cache-Control: max-age=***</sup> to the backend server which you want to be cached, ortherwise, ncache will not cache it forever.

> if you set max-age < 1 minute ncache will set it to 1 minute, and ncache will exact all max-age to minute, so please align it to 60.


  * run and kill

> run: {install\_prefix}/sbin/ncache

> kill: kill -9 `ps auwx|grep ncache|awk '{print $2}'`