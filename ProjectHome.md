## NCache is now in nginx core ,  you can use it as nginx proxy cache. see [here](http://wiki.nginx.org/NginxHttpProxyModule#proxy_cache) ##

NCache is out of maintaince from 2009.1.1


# What is ncache? #

a web cache system base on nginx web server.
faster and more efficient than squid.

we have published [a release version 2.3](http://ncache.googlecode.com/files/ncache-2.3_release.tar.gz) on 32-bit linux and [a release version 3.1\_64](http://ncache.googlecode.com/files/ncache-3.1_64_linux.tar.gz) on 64-bit linux now, you can see the change log [here](http://code.google.com/p/ncache/wiki/NCacheChangeLog)

if you want to improve your ncache performance (32-bit) please see this wiki paper: [AdviceIOPerfomance](http://code.google.com/p/ncache/wiki/AdviceIOPerfomance)

and we will maintain it be fresh.

you can also visit here by http://www.ncache.org or http://ncache.googlecode.com

and left your message [here](http://groups.google.com/group/ncache-group)

there is also have some BUGS, so if you find it please tell us, thanks alot.

shinepf@gmail.com   shineyear@msn.com

shuiyang@gmail.com  shuiyang@live.cn

fgxlzh@gmail.com

# Features #

  * The large storage can save over 30,000,000 caches

  * The self sort share memory hash index

  * Base on the fastest web server framework : nginx

  * The high throughput and high concurrent volume of the cache request

  * Without http headers cache

  * Low cpu cost and low iowait

  * Memory cache the hottest data by MMAP like "varnish"

  * Texturixer storage system

  * Auto delete cache file when it is cold




# How to use? #

You can see it on the wiki paper [HowToNcacheV2](http://code.google.com/p/ncache/wiki/HowToNcacheV2) and  [HowToNcacheV3](http://code.google.com/p/ncache/wiki/HowToNcacheV3).

# Problem yet~ #


  * only support on linux 2.6 up (64-bit can support freebsd).

  * do not have enough information about the Run-time statistics




# The ncache [Subversion](http://subversion.tigris.org/) repository is available #
  * http://ncache.googlecode.com/svn/



