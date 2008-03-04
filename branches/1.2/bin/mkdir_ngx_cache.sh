#!/bin/sh

####################################################################
#
# Copyright (C) simon
#
#	Run:
#		./mkdir_ngx_cache.sh /usr/local/nginx/conf/nginx.conf
#
###################################################################


if [ "-$1" = "-" ]; then
	 echo "Please Run the shell Like :"
     echo "./mkdir_ngx_cache.sh /usr/local/nginx/conf/nginx.conf"
     exit   0   
fi;

ngx_conf=$1

if [ ! -e $ngx_conf ];then

	echo "Nginx Conf: "  $ngx_conf " not a file"
	echo "Please Run the shell Like :"
	echo "./mkdir_ngx_cache.sh /usr/local/nginx/conf/nginx.conf"
	exit   0   
	
fi

cache_paths=`cat $ngx_conf|grep cachedir|awk '{print $2}'`

cache_owner=`cat $ngx_conf|egrep "^user"|sed 's/;//g'|awk '{print $2":"$3}'`

cache_owner_count=`cat $ngx_conf|egrep "^user"|sed 's/;//g'|wc -l`

if [ $cache_owner_count -lt 1 ];then

	echo "Warning: Please  add nginx worker running user to your config file! Default set to nobody:nobody"
	cache_owner="nobody:nobody"	
fi

for base_cache_path in $cache_paths;do

	max_p0=`cat $ngx_conf|grep $base_cache_path|sed 's/;//g'|awk '{print $3}'`	
	max_p1=`cat $ngx_conf|grep $base_cache_path|sed 's/;//g'|awk '{print $4}'`	

	echo ""
	echo "-----------------Build dir "$base_cache_path"-------------------------------"
	echo ""
	
	i=0
	while [ $i -lt $max_p0 ];do
		
			j=0
			while [ $j -lt $max_p1 ];do
					
				make_dir=`printf %s/%02x/%02x $base_cache_path $i $j`
					
				/bin/mkdir -p $make_dir
				
				j=$[$j+1]
				
			done
		
		i=$[$i+1]
	done

	/bin/chown -R $cache_owner $base_cache_path

done
