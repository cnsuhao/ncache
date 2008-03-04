/* 
 * Copyright (C) Igor shineyear
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <aio.h>
#include <openssl/md5.h>
#include <sys/mman.h>


#define MY_SIGNO (SIGRTMIN+11)

//aio transfer data
typedef struct vila
{
	int fd;
	int hash_index;
	int type;
	int charset;
	int zip;
	char filename[33];
	char path[255];
	unsigned char md5[16];
	struct aiocb *req;
	int time;
}VILA;

static ngx_int_t ngx_http_upstream_cache_init(ngx_conf_t *cf);


extern int ngx_http_shm_hash_find(int hash_index, u_char *key, int *hash_stat);
extern ngx_int_t ngx_http_shm_is_timeout(char *filepath, int hash_index);

extern void ngx_http_shm_hash_update(int new_index, u_char *key, int time, int type, int zip, int charset);


static ngx_http_module_t  ngx_http_upstream_cache_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_upstream_cache_init, 				 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,         												 /* create location configuration */
    NULL          												 /* merge location configuration */
};

ngx_module_t  ngx_http_upstream_cache_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_cache_module_ctx,   /* module context */
    NULL,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,				   /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


extern ngx_http_upstream_cache_hash_t *nhucht;
extern ngx_shmtx_t	ngx_upstream_mutex;


static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


//when aio write is complete, this function will be call
void aio_completion_handler( union sigval foo )
{

	VILA *v = (VILA *)foo.sival_ptr;
	if(v == NULL)return ;
	if (aio_error( v->req ) == 0)
	{
		int ret = aio_return( v->req );
		if(ret < 0)
		{
			return ;
		}
     
	}

	//close cache file
	close(v->req->aio_fildes);

	//update index
	ngx_http_shm_hash_update(v->hash_index, v->md5, v->time, v->type, v->zip, v->charset);


	//free resources
	if(v)
	{
		if(v->req)
		{
			if(v->req->aio_buf)free((void *)v->req->aio_buf);
			free(v->req);
		}
		free(v);
	}
}


//set content type to index base on response headers from backend server
void ngx_http_upstream_cache_set_content_type(ngx_http_request_t *r, VILA *v)
{
	if(r->headers_out.content_type.data)
	{
		u_char *tmp = strchr(r->headers_out.content_type.data, ';');
		int len = 0;
		if(tmp)
		{
			len = tmp - r->headers_out.content_type.data;
		}
		else
		{
			len = r->headers_out.content_type.len;
		}

		//set charset
		if(r->headers_out.charset.len > 0)
		{
			if(!strncmp(r->headers_out.charset.data, "utf-8", r->headers_out.charset.len))
			{
				v->charset = 1;
			}
		}
	
		if(!strncmp(r->headers_out.content_type.data, "text/html", len))
		{
			v->type = 0;
			return ;
		}
		if(!strncmp(r->headers_out.content_type.data, "text/xml", len))
		{
			v->type = 1;
			return ;
		}
		if(!strncmp(r->headers_out.content_type.data, "text/css", len))
		{
			v->type = 2;
			return ;
		}
		if(!strncmp(r->headers_out.content_type.data, "image/gif", len))
		{
			v->type = 3;
			return ;
		}
		if(!strncmp(r->headers_out.content_type.data, "image/jpeg", len))
		{
			v->type = 4;
			return ;
		}
		if(!strncmp(r->headers_out.content_type.data, "image/png", len))
		{
			v->type = 5;
			return ;
		}
		if(!strncmp(r->headers_out.content_type.data, "text/plain", len))
		{
			v->type = 6;
			return ;
		}
		if(!strncmp(r->headers_out.content_type.data, "application/x-javascript", len))
		{
			v->type = 7;
			return ;
		}
		if(!strncmp(r->headers_out.content_type.data, "application/x-shockwave-flash", len))
		{
			v->type = 8;
			return ;
		}
		if(!strncmp(r->headers_out.content_type.data, "image/x-icon", len))
		{
			v->type = 9;
			return ;
		}
		if(!strncmp(r->headers_out.content_type.data, "application/xml", len))
		{
			v->type = 10;
			return ;
		}
	}
	else
	{
		if(r->headers_out.charset.len > 0)
		{
			if(!strncmp(r->headers_out.charset.data, "utf-8", r->headers_out.charset.len))
			{
				v->charset = 1;
			}
		}
		v->type = 0;		
		return ;
	}
}

//get content from backend server, before it be send to the client
static ngx_int_t
ngx_http_upstream_cache_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	
	

	if (in == NULL || r->header_only || r->headers_out.status != 200 || r->upstream == NULL || r->cache_hash_index == -1) {
		return ngx_http_next_body_filter(r, in);
	}
  


	//copy the backend data to this request cache
	if(r->upstream->out_bufs == NULL)
	{
		r->upstream->out_bufs = ngx_alloc_chain_link(r->pool);
		if(r->upstream->out_bufs == NULL)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_alloc_chain_link error");
			return NGX_ERROR;
		}
		r->upstream->busy_bufs = r->upstream->out_bufs;
	}
	
	ngx_chain_t *tmp = in;
	int len = 0;
	
	while(tmp)
	{
		len = tmp->buf->last - tmp->buf->pos;
		r->cache_file_size += len;
		
		ngx_buf_t *b = ngx_create_temp_buf(r->pool, len);
		if(b == NULL)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_create_temp_buf error");
			return NGX_ERROR;
		}

		if(r->upstream->busy_bufs == NULL)
		{
			r->upstream->busy_bufs = ngx_alloc_chain_link(r->pool);	
			if(r->upstream->busy_bufs == NULL)
			{
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_alloc_chain_link error");
				return NGX_ERROR;
			}
		}
		r->upstream->busy_bufs->buf = b;

		b->last = ngx_copy(b->last, tmp->buf->pos, len);
		b->last_buf = tmp->buf->last_buf;

		r->upstream->busy_bufs->next = ngx_alloc_chain_link(r->pool);
		
		if(r->upstream->busy_bufs->next == NULL)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_alloc_chain_link error");
			return NGX_ERROR;
		}
		
		r->upstream->busy_bufs = r->upstream->busy_bufs->next;
		

		tmp = tmp->next;			
	}
	

	//if it is the last chunk of the data
 	if(in->buf->last_buf) 
	{
	
	
		int index = nhucht[r->cache_hash_index].cache.index;

		
		
		unsigned char *md5 = r->cache_md5;
		char filename[33];
		filename[32] = 0;
		
		int i;
		for(i=0;i<16;i++)
		{
			sprintf (filename + (i*2), "%02X", md5[i]);
		}
		
		ngx_http_upstream_cache_conf_t	*cache = r->upstream->conf->upstream->caches->elts;
		if(cache == NULL)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "cache dir info error");
			return NGX_ERROR;
		}
		unsigned char x1;
		unsigned char x2;
		
		switch (cache[index].size1)
		{
			case 64:
				x1 = md5[6] >> 2;
				break;
			case 128:
				x1 = md5[6] >> 1;
				break;
			case 256:
			default:
				x1 = md5[6];
		}
	
		switch (cache[index].size2)
		{
			case 64:
				x2 = md5[8] >> 2;
				break;
			case 128:
				x2 = md5[8] >> 1;
				break;
			case 256:
			default:
				x2 = md5[8];
		}
		
	
		
	
		int real_path_len = cache[index].path.len + 4 + 2 + 1 + 33;
	
		char real_path[real_path_len];
	
		real_path[real_path_len - 1] = 0;
	
		sprintf(real_path, "%s%02x/%02x/%s", cache[index].path.data, x1, x2, filename);
	


		ngx_uint_t j;
		int time = 0;
		ngx_table_elt_t  **ccp = r->headers_out.cache_control.elts;
		for(j=0;j<r->headers_out.cache_control.nelts;j++)
		{
			if(!ngx_strncasecmp(ccp[j]->value.data, "max-age=", 8))
			{
				time = atoi(ccp[j]->value.data + 8);
				break;
			}
		}
	
		//if without "max-age" header, do not cache anything
		if(time == 0)
		{
			return ngx_http_next_body_filter(r, in);
			//time = 259000;
		}


		

		int fd = open( real_path, O_EXCL | O_CREAT | O_RDWR , 0644);

		if(fd < 0)
		{
			//time out?
			if(errno == 17 && nhucht[r->cache_hash_index].cache.timeout)
			{
				fd = open( real_path, O_RDWR | O_TRUNC , 0644);
				goto cachenext;

			}
		}
		else
		{
			
cachenext:
		{
			//max size of cache file 1MB limit
			//char str[1024000];
			
			//copy the request cache to the aio buf
			char *buf = malloc(r->cache_file_size + 2);
			if(buf == NULL)
			{
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "malloc aio buf error");
				return NGX_ERROR;
			}
			
			
			ngx_chain_t *tmp = r->upstream->out_bufs;
			
			int allen = 0;
			while(tmp && tmp->buf && tmp->buf->pos)
			{
				
				len = tmp->buf->last - tmp->buf->pos;

				//append the request cache to aio buf
				memcpy(buf + allen, tmp->buf->pos, len);
				allen += len;
				if(tmp->buf->last_buf)break;
				tmp = tmp->next;
			}

			buf[allen + 1] = 0;

			//malloc the aio struct
			struct aiocb *cb = malloc(sizeof(struct aiocb));
			if(cb == NULL)
			{
				free(buf);
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "malloc struct aiocb error");
				return NGX_ERROR;
			}
			bzero( cb, sizeof(struct aiocb) );
		
			



			
			//memcpy(buf, str, allen + 1);
			
		
	
			cb->aio_fildes = fd;                                                                                                                                                                         
	    	cb->aio_buf = buf;                                                                                
	    	cb->aio_nbytes = allen;
	    	cb->aio_offset = 0;  
			//set aio use kernel thread to handle the io complete signal
	    	cb->aio_sigevent.sigev_notify = SIGEV_THREAD;                                                                       
			cb->aio_sigevent.sigev_notify_attributes = NULL;
			cb->aio_sigevent.sigev_signo = MY_SIGNO;  
			//set the handler
			cb->aio_sigevent.sigev_notify_function = aio_completion_handler;

	   		//malloc handle struct
	    	VILA *v = malloc(sizeof(VILA));
			if(v == NULL)
			{
				free(buf);
				free(cb);
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "malloc v struct error");
				return NGX_ERROR;

			}
	    	bzero(v, sizeof(VILA));
	    
	    	//set content type
			ngx_http_upstream_cache_set_content_type(r, v);

			//set gzip
			if(r->headers_out.content_encoding)
			{
				if(!strcmp(r->headers_out.content_encoding->value.data, "gzip"))
				{
					v->zip = 1;
				}
			}
			
			v->time = time;
	    	v->fd = fd;
	    	v->hash_index = r->cache_hash_index;
	    	ngx_cpymem(v->filename, filename, 33);   
	    	ngx_cpymem(v->md5, md5, 16);    
	    	ngx_cpymem(v->path, real_path, real_path_len);    
	    	v->req = cb;      

			//set handle struct
	    	cb->aio_sigevent.sigev_value.sival_ptr = v;

			//write
	    	if(aio_write(cb) !=0)
	    	{
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "aio_write struct error");
				return NGX_ERROR;
			}
		}
			
		}
	}
	return ngx_http_next_body_filter(r, in);
}

//set body filter module
static ngx_int_t
ngx_http_upstream_cache_init(ngx_conf_t *cf)
{
	
	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_upstream_cache_body_filter;
  

  
	return NGX_OK;
}





