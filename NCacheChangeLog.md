= Changes with ncache 3.1 for 64 =                                        4 Mar 2009

  * Change: use little meta data

  * Change: use pthread\_mutex

  * Change: use sendfile

  * Bugfix: state print

  * Bugfix: realloc page

= Changes with ncache 3 for 64 =                                        12 Jan 2009

  * Change: use new storage methed to store file

  * Change: purge is faster

  * Change: no thread

  * I/O is better

= Changes with ncache 2.3 =                                               21 Nov 2008
  * bugfix: make error in gcc 4.

  * Bugfix: the cached file may use other file's index info.
= Changes with ncache 2.2 =                                               17 Nov 2008
  * Change: del type field in hash idex.

  * Bugfix: once timeout,it never cached.

  * Change: file clock range.

  * Bugfix: close file error.

  * Feature: deal with file collision.
= Changes with ncache 2.1 =                                               3 Nov 2008
  * Change: use mempool in process.

  * Bugfix: POST method.

  * Change: use list chain instead of msg.

  * Bugfix: unlink in purge,the file name is wrong.

  * Feature: use less memory.

  * Change: md5,use 8 chars.

  * Change: delete some members,check and del.

  * Bugfix: the count of stored files,it is not accurate as it does nothing when the file is timeout

  * Bugfix: lock in purge,lock one index but unlock the other.


= Changes with ncache 2.0 =                                               23 july 2008
  * Change: be a nginx module, you can use it with standard nginx.

  * Bugfix: http 208 head handle.

  * Change: more error log.

  * Bugfix: if an error occur on upstream to backend server ncache will not update the cache index.

  * Feature: multi upstream support, thanks for Arden.Emily.

  * Change: more ncache state check.

  * Change: command in conf file.

  * Feature: will keep all cache when you restart ncache

= Changes with ncache 1.3 =                                               17 Mar 2008
  * Bugfix: can not complete on gcc 4.

= Changes with ncache 1.3-beta =                                          28 Feb 2008
  * Bugfix: if proxy file is too big, then ncache will not cache all file content.

  * Bugfix: ncache worker process deadlock.

  * Change: process lock change to record lock, when malloc new index or free old.

  * Feature: aio write list improve disk io performance.

  * Feature: compress md5 key's first 3 byte, the index file is 700MB right now.

  * Bugfix: reopen or rewrite the same cache file.

  * Change: merge 3 index file to 1.

  * Change: use free index list to solve the hash conflict.

  * Feature: HAC memory cache elimination algorithm (beta yet).

  * Bugfix: can not make install when linux do not have some kernel head files.


= Changes with ncache 1.2 =						   16 Jan 2008
  * Bugfix:if the max-age time < time\_out\_max then the timeout value in the index will be set to 0.

  * Feature: user custom set of the storage max size

  * Change: exact timeout time to minute, set the max timeout time to 65535 minute = about 45 days.

  * Feature: support HTTP 304.

  * Change: > 1MB cache file size.

= Changes with ncache 1.2 beta =                                            11 Jan 2008

  * Bugfix: add some function return check. when any function call is fault, ncache will log it

  * Feature: compress the index file about 800MB.

  * Change: the purge function do not response any body content to http purge request.

  * Bugfix: the mkdir\_ngx\_cache.sh code, fix empty args bug, and a bug when not set user

  * Change: Unified the ncache config file name, command name and dir name ...

= Changes with ncache 1.1 =                                                   9 Jan 2008

  * Bugfix: if use purge to delete cache, will cause a segmentation fault

= Changes with ncache 1.0 =                                                   8 Jan 2008

  * Change: add shoot Percentage to the ngx\_http\_stub\_status\_module
