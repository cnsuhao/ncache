
/*
 * Copyright (C) Igor Sysoev, shineyear
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <openssl/md5.h>
#include <math.h>

//the record loc acers
#define read_lock(fd, offset, whence, len) \
        lock_reg(fd, F_SETLK, F_RDLCK, offset, whence, len)

#define readw_lock(fd, offset, whence, len) \
        lock_reg(fd, F_SETLKW, F_RDLCK, offset, whence, len)

#define write_lock(fd, offset, whence, len) \
        lock_reg(fd, F_SETLK, F_WRLCK, offset, whence, len)

#define writew_lock(fd, offset, whence, len) \
        lock_reg(fd, F_SETLKW, F_WRLCK, offset, whence, len)

#define un_lock(fd, offset, whence, len) \
        lock_reg(fd, F_SETLK, F_UNLCK, offset, whence, len)

#define is_read_lockable(fd, offset, whence, len) \
        lock_test(fd, F_RDLCK, offset, whence, len)

#define is_write_lockable(fd, offset, whence, len) \
        lock_test(fd, F_WRLCK, offset, whence, len)




typedef struct ngx_http_proxy_redirect_s  ngx_http_proxy_redirect_t;

typedef ngx_int_t (*ngx_http_proxy_redirect_pt)(ngx_http_request_t *r,
    ngx_table_elt_t *h, size_t prefix, ngx_http_proxy_redirect_t *pr);

struct ngx_http_proxy_redirect_s {
    ngx_http_proxy_redirect_pt     handler;
    ngx_str_t                      redirect;

    union {
        ngx_str_t                  text;

        struct {
            void                  *lengths;
            void                  *values;
        } vars;

        void                      *regex;
    } replacement;
};


typedef struct {
    ngx_http_upstream_conf_t       upstream;

    ngx_array_t                   *flushes;
    ngx_array_t                   *body_set_len;
    ngx_array_t                   *body_set;
    ngx_array_t                   *headers_set_len;
    ngx_array_t                   *headers_set;
    ngx_hash_t                     headers_set_hash;

    ngx_array_t                   *headers_source;
    ngx_array_t                   *headers_names;

    ngx_array_t                   *redirects;

    ngx_str_t                      body_source;

    ngx_str_t                      method;
    ngx_str_t                      host_header;
    ngx_str_t                      port;

    ngx_flag_t                     redirect;

    ngx_uint_t                     headers_hash_max_size;
    ngx_uint_t                     headers_hash_bucket_size;

	ngx_flag_t					   proxy_no_cache; //proxy_ignore_client_no_cache 
} ngx_http_proxy_loc_conf_t;


typedef struct {
    ngx_uint_t                     status;
    ngx_uint_t                     status_count;
    u_char                        *status_start;
    u_char                        *status_end;

    size_t                         internal_body_length;
} ngx_http_proxy_ctx_t;


#define NGX_HTTP_PROXY_PARSE_NO_HEADER  20


static ngx_int_t ngx_http_proxy_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_parse_status_line(ngx_http_request_t *r,
    ngx_http_proxy_ctx_t *p);
static ngx_int_t ngx_http_proxy_process_header(ngx_http_request_t *r);
static void ngx_http_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http_proxy_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_proxy_host_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_proxy_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
    ngx_http_proxy_add_x_forwarded_for_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
    ngx_http_proxy_internal_body_length_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_proxy_rewrite_redirect(ngx_http_request_t *r,
    ngx_table_elt_t *h, size_t prefix);

static ngx_int_t ngx_http_proxy_add_variables(ngx_conf_t *cf);
static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_proxy_store(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data);

static char *ngx_http_proxy_upstream_max_fails_unsupported(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_proxy_upstream_fail_timeout_unsupported(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static char *ngx_http_cache_max_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);



static ngx_int_t ngx_http_shm_hash_init();
ngx_int_t ngx_http_shm_is_timeout(ngx_file_info_t *fi, int hash_index);
ngx_int_t ngx_http_shm_hash_add(int hash_index, u_char *key, int dir_index);
int ngx_http_shm_hash_find(int hash_index, u_char *key, int *hash_stat);
int ngx_http_shm_hash_malloc();
void ngx_http_shm_set_timeout(int hash_index);
void ngx_http_upstream_cached_set_content_type(ngx_http_request_t *r, int hash_index);
static char *ngx_http_upstream_purge(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len);
void ngx_http_hash_check_count(int hash_index);
int ngx_http_shm_hash_getindex(ngx_http_proxy_loc_conf_t  *plcf);


// ncache hash index first floor size
static ngx_uint_t MAX_CACHE_NUM = 16777216; /* 2^24 */

// ncache hash index max size
static ngx_uint_t ALL_CACHE_NUM = 33554432; /* 2^25 */

static int TIME_OUT_MAX = 65534; /* 2^16 */


//the global share memory hash index point
ngx_http_upstream_cache_hash_t *nhucht;

//hash index sync file fd
static int hash_fd;

//hash malloc counter sync file fd
static int count_fd;

//the global share memory hash malloc counter point
ngx_http_upstream_cache_hash_count_t *nhuchct;

//cache dir distribute counter
static u_char cache_dir_index = 0;

//multi process lock, when hash malloc
ngx_shmtx_t	ngx_upstream_mutex;

//the global temporary verable, save the upstream info, used by purge request
ngx_http_upstream_srv_conf_t *myupstream;

//ngx_http_upstream_cache_hash_t struct size, when hash init it will be fill, to save the cpu cost
static int cache_size = 0;

//atomic counters
atomic_t request_count = ATOMIC_INIT(0); //all request
atomic_t shoot_count = ATOMIC_INIT(0); //shoot percentage  
atomic_t time_count = ATOMIC_INIT(0); // shoot percentage count time interval  



static ngx_conf_post_t  ngx_http_proxy_lowat_post =
    { ngx_http_proxy_lowat_check };

static ngx_conf_deprecated_t  ngx_conf_deprecated_proxy_header_buffer_size = {
    ngx_conf_deprecated, "proxy_header_buffer_size", "proxy_buffer_size"
};

static ngx_conf_deprecated_t  ngx_conf_deprecated_proxy_redirect_errors = {
    ngx_conf_deprecated, "proxy_redirect_errors", "proxy_intercept_errors"
};


static ngx_conf_bitmask_t  ngx_http_proxy_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_proxy_commands[] = {

	//to skip the client cache contral: no cache request
	{ ngx_string("proxy_ignore_client_no_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, proxy_no_cache),
      NULL },

    { ngx_string("proxy_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      
	{ ngx_string("cache_max_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_max_size,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },
	

    { ngx_string("proxy_redirect"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_proxy_redirect,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_store"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_store,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_store_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.store_access),
      NULL },

    { ngx_string("proxy_buffering"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.buffering),
      NULL },

    { ngx_string("proxy_ignore_client_abort"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { ngx_string("proxy_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("proxy_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("proxy_send_lowat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.send_lowat),
      &ngx_http_proxy_lowat_post },

    { ngx_string("proxy_intercept_errors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.intercept_errors),
      NULL },

    { ngx_string("proxy_redirect_errors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.intercept_errors),
      &ngx_conf_deprecated_proxy_redirect_errors },

    { ngx_string("proxy_set_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, headers_source),
      NULL },

    { ngx_string("proxy_headers_hash_max_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, headers_hash_max_size),
      NULL },

    { ngx_string("proxy_headers_hash_bucket_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, headers_hash_bucket_size),
      NULL },

    { ngx_string("proxy_set_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, body_source),
      NULL },

    { ngx_string("proxy_method"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, method),
      NULL },

    { ngx_string("proxy_pass_request_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { ngx_string("proxy_pass_request_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_request_body),
      NULL },

    { ngx_string("proxy_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("proxy_header_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.buffer_size),
      &ngx_conf_deprecated_proxy_header_buffer_size },

    { ngx_string("proxy_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("proxy_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.bufs),
      NULL },

    { ngx_string("proxy_busy_buffers_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { ngx_string("proxy_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.temp_path),
      (void *) ngx_garbage_collector_temp_handler },

    { ngx_string("proxy_max_temp_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { ngx_string("proxy_temp_file_write_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { ngx_string("proxy_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.next_upstream),
      &ngx_http_proxy_next_upstream_masks },

    { ngx_string("proxy_upstream_max_fails"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_upstream_max_fails_unsupported,
      0,
      0,
      NULL },

    { ngx_string("proxy_upstream_fail_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_upstream_fail_timeout_unsupported,
      0,
      0,
      NULL },

    { ngx_string("proxy_pass_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_headers),
      NULL },

    { ngx_string("proxy_hide_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.hide_headers),
      NULL },

	//delete memory hash index and file cache
	{ ngx_string("purge"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_purge,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_proxy_module_ctx = {
    ngx_http_proxy_add_variables,          /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_proxy_create_loc_conf,        /* create location configration */
    ngx_http_proxy_merge_loc_conf          /* merge location configration */
};


ngx_module_t  ngx_http_proxy_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_module_ctx,            /* module context */
    ngx_http_proxy_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char  ngx_http_proxy_version[] = " HTTP/1.0" CRLF;


static ngx_keyval_t  ngx_http_proxy_headers[] = {
    { ngx_string("Host"), ngx_string("$proxy_host") },
    { ngx_string("Connection"), ngx_string("close") },
    { ngx_string("Keep-Alive"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};


static ngx_str_t  ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffer"),
    ngx_null_string
};


static ngx_http_variable_t  ngx_http_proxy_vars[] = {

    { ngx_string("proxy_host"), NULL, ngx_http_proxy_host_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("proxy_port"), NULL, ngx_http_proxy_port_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("proxy_add_x_forwarded_for"), NULL,
      ngx_http_proxy_add_x_forwarded_for_variable, 0, NGX_HTTP_VAR_NOHASH, 0 },

#if 0
    { ngx_string("proxy_add_via"), NULL, NULL, 0, NGX_HTTP_VAR_NOHASH, 0 },
#endif

    { ngx_string("proxy_internal_body_length"), NULL,
      ngx_http_proxy_internal_body_length_variable, 0, NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_proxy_handler(ngx_http_request_t *r)
{

    //nonstandard  http request
	if(r->headers_in.host == NULL)return NGX_HTTP_INTERNAL_SERVER_ERROR;

	//calculate the shoot percentage
	int tmp_time = time(NULL);
	if(tmp_time - atomic_read(&time_count) > 1200)
	{
		atomic_set(&request_count, 0);
		atomic_set(&shoot_count, 0);
		atomic_set(&time_count, tmp_time);
	}
	atomic_inc(&request_count);


		

    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

	//calculate the full request uri
	int request_path_len = r->headers_in.host->value.len + r->unparsed_uri.len + 1;

	char request_path[request_path_len];

	snprintf(request_path, request_path_len, "%s%s", r->headers_in.host->value.data, r->unparsed_uri.data);
	request_path[request_path_len - 1] = 0;

	//hash the uri
	ngx_uint_t hash_key = ngx_hash_key(request_path, request_path_len);

	//save the hash value to this  request
	r->cache_hash_key = hash_key;

	//calculate the location of the hash index first floor
	int hash_index = hash_key % MAX_CACHE_NUM;

	//calculate the md5 value
	unsigned char md5[16];

	MD5_CTX x;

	MD5_Init(&x);

	MD5_Update (&x, request_path, request_path_len);

	MD5_Final(md5, &x);

	memcpy(r->cache_md5, md5, 16);

	int hash_stat = 0;

	//find the empty location where can add new index or the cached index
	hash_index = ngx_http_shm_hash_find(hash_index, md5, &hash_stat);

	//save it to this request
	r->cache_hash_index = hash_index;

	//empty or can be reused or malloc new
	if(hash_stat == -1 || hash_stat == -2 || hash_stat == -3)
	{
		//lock record and add new
		writew_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size);
		if(!nhucht[hash_index].cache.cached || nhucht[hash_index].cache.del)
		{
			ngx_http_shm_hash_add(hash_index, md5, ngx_http_shm_hash_getindex(plcf));	
		}
		un_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size); 
	}
	//found cache
	else if(hash_stat == 1)
	{
		//check proxy_ignore_client_no_cache config, if it is "off" then work
		if(!plcf->proxy_no_cache)
		{
			ngx_list_part_t 			 *part;    
			ngx_table_elt_t				*header;
						
			part = &r->headers_in.headers.part; 	   
			header = part->elts;

			ngx_uint_t ti;
			for (ti = 0; /* void */; ti++) 
			{

				if (ti >= part->nelts)
				{                
																					if (part->next == NULL)	
				    {                   
					break;                
				    }                
					part = part->next;
					header = part->elts;
					ti = 0;
				}
				//find the no_cache request from client request
				if(!strncmp(header[ti].key.data, "Cache-Control", 13) && !strncmp(header[ti].value.data, "no-cache", 8))
				{
					ngx_http_shm_set_timeout(hash_index);
					goto next;
				}
																											
			}

		}
/*
		rc = ngx_http_discard_body(r);

    	if (rc != NGX_OK && rc != NGX_AGAIN) {
       		return rc;
    	}

*/		
		//read from hash index and get the cache dir info
		int index = nhucht[hash_index].cache.index;

		//cache dir info from config fle
		ngx_http_upstream_cache_conf_t	*cache = plcf->upstream.upstream->caches->elts;

		if(cache == NULL)
		{
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http cache dir config error");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		char filename[33];

		filename[32] = 0;

		unsigned char x1;

		unsigned char x2;
		
		//swich diffrent size of the cache dir
		//first floor
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

		//second floor
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

		//get the filename
		int i;
		for(i=0;i<16;i++)
		{
			sprintf (filename + (i*2), "%02X", md5[i]);
		}

		//get the real path of the file
		int real_path_len = cache[index].path.len + 4 + 2 + 1 + 33;

		char real_path[real_path_len];

		real_path[real_path_len - 1] = 0;

		sprintf(real_path, "%s%02x/%02x/%s", cache[index].path.data, x1, x2, filename);
		

		//open and send it
		ngx_fd_t	fd = ngx_open_file(real_path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

		//open fault
		if(fd < 0)
		{
			ngx_http_shm_set_timeout(hash_index);
			goto next;
		}
		
		ngx_file_info_t            fi;
		
		ngx_fd_info(fd, &fi);

		//file size = 0
		if(ngx_file_size(&fi) == 0)
		{
			ngx_http_shm_set_timeout(hash_index);
			close(fd);
			goto next;
		}

		//cache time out check
		if(ngx_http_shm_is_timeout(&fi, hash_index))
		{
			close(fd);
			goto next;
		}
		
		r->headers_out.status = NGX_HTTP_OK;
		r->headers_out.content_length_n = ngx_file_size(&fi);
    	r->headers_out.last_modified_time = ngx_file_mtime(&fi);
    
    
    	ngx_table_elt_t	*cc = ngx_list_push(&r->headers_out.headers);
		if (cc == NULL) {
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_list_push error");
		    close(fd);
		    return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		//add the "age" header, this header save the cache file time
		cc->hash = 1;
		cc->key.len = sizeof("Age") - 1;
		cc->key.data = (u_char *) "Age";
		
		long t = time(NULL) - fi.st_mtime;
		
		char age[10];
		bzero(age, 10);
		sprintf(age, "%ld", t);
		
		cc->value.len = strlen(age);
		cc->value.data = (u_char *) age;

		//set content type header
		ngx_http_upstream_cached_set_content_type(r, hash_index);

		//check if need gzip header
		if(nhucht[hash_index].cache.zip)
		{
			r->headers_out.content_encoding = ngx_list_push(&r->headers_out.headers);

    		if (r->headers_out.content_encoding == NULL)
			{
				ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "gzip ngx_list_push error");
				close(fd);
        		return NGX_HTTP_INTERNAL_SERVER_ERROR;
    		}

 		   	r->headers_out.content_encoding->hash = 1;
		    r->headers_out.content_encoding->key.len = sizeof("Content-Encoding") - 1;
    		r->headers_out.content_encoding->key.data = (u_char *) "Content-Encoding";
   		 	r->headers_out.content_encoding->value.len = sizeof("gzip") - 1;
   		 	r->headers_out.content_encoding->value.data = (u_char *) "gzip";
		}
		
		
		

		
		ngx_buf_t                 *b;
		ngx_chain_t                out;
		ngx_log_t                 *log = r->connection->log;
	
	
		ngx_pool_cleanup_t        *cln;
		ngx_pool_cleanup_file_t   *clnf;
		
		
		cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
		
		r->allow_ranges = 1;
		
		
		
		log->action = "sending response to client";
		cln->handler = ngx_pool_cleanup_file;
		clnf = cln->data;
	
		clnf->fd = fd;
		clnf->name = filename;
		clnf->log = r->pool->log;
	
	
		
		b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

		if (b == NULL) {
        	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    	}
		
		b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));

		if (b->file == NULL) {
        	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    	}
		
		rc = ngx_http_send_header(r);

		if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        	return rc;
    	}
		
		
		b->file_pos = 0;
		b->file_last = ngx_file_size(&fi);
		
		b->in_file = b->file_last ? 1: 0;
		b->last_buf = (r == r->main) ? 1: 0;
		b->last_in_chain = 1;
		
		b->file->fd = fd;
		b->file->name.data = filename;
		b->file->name.len = strlen(filename);
		b->file->log = log;
		out.buf = b;
		out.next = NULL;

		//add index count
		ngx_http_hash_check_count(hash_index);

		//add shoot percentage
		atomic_inc(&shoot_count);

		//sendfile
		return ngx_http_output_filter(r, &out);
	}

	
	
next: 
	
	//do not found index or some error of index then 
	//make a new upstream to the proxy and 
	//get the cache file content from backend

    u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
    if (u == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;
#if (NGX_THREADS)
    u->peer.lock = &r->connection->lock;
#endif

    u->output.tag = (ngx_buf_tag_t) &ngx_http_proxy_module;

    u->conf = &plcf->upstream;

    u->create_request = ngx_http_proxy_create_request;
    u->reinit_request = ngx_http_proxy_reinit_request;
    u->process_header = ngx_http_proxy_process_status_line;
    u->abort_request = ngx_http_proxy_abort_request;
    u->finalize_request = ngx_http_proxy_finalize_request;

    if (plcf->redirects) {
        u->rewrite_redirect = ngx_http_proxy_rewrite_redirect;
    }

    u->buffering = plcf->upstream.buffering;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_event_pipe_copy_input_filter;

    u->accel = 1;

    r->upstream = u;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_proxy_create_request(ngx_http_request_t *r)
{
    size_t                        len, loc_len, body_len;
    uintptr_t                     escape;
    ngx_buf_t                    *b;
    ngx_str_t                     method;
    ngx_uint_t                    i, unparsed_uri;
    ngx_chain_t                  *cl, *body;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_ctx_t         *p;
    ngx_http_script_code_pt       code;
    ngx_http_script_engine_t      e, le;
    ngx_http_proxy_loc_conf_t    *plcf;
    ngx_http_script_len_code_pt   lcode;

    u = r->upstream;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    p = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_ctx_t));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, p, ngx_http_proxy_module);

    len = sizeof(ngx_http_proxy_version) - 1 + sizeof(CRLF) - 1;

    if (u->method.len) {
        /* HEAD was changed to GET to cache response */
        method = u->method;
        method.len++;

    } else if (plcf->method.len) {
        method = plcf->method;

    } else {
        method = r->method_name;
        method.len++;
    }

    len += method.len + u->conf->uri.len;

    escape = 0;

    loc_len = (r->valid_location && u->conf->uri.len) ? u->conf->location.len:
                                                        0;

    if (u->conf->uri.len == 0 && r->valid_unparsed_uri && r == r->main) {
        unparsed_uri = 1;
        len += r->unparsed_uri.len;

    } else {
        unparsed_uri = 0;
        if (r->quoted_uri || r->internal) {
            escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
                                        r->uri.len - loc_len, NGX_ESCAPE_URI);
        }

        len += r->uri.len - loc_len + escape + sizeof("?") - 1 + r->args.len;
    }

    ngx_http_script_flush_no_cacheable_variables(r, plcf->flushes);

    if (plcf->body_set_len) {
        le.ip = plcf->body_set_len->elts;
        le.request = r;
        le.flushed = 1;
        body_len = 0;

        while (*(uintptr_t *) le.ip) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            body_len += lcode(&le);
        }

        p->internal_body_length = body_len;
        len += body_len;
    }

    le.ip = plcf->headers_set_len->elts;
    le.request = r;
    le.flushed = 1;

    while (*(uintptr_t *) le.ip) {
        while (*(uintptr_t *) le.ip) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            len += lcode(&le);
        }
        le.ip += sizeof(uintptr_t);
    }


    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&plcf->headers_set_hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            len += header[i].key.len + sizeof(": ") - 1
                + header[i].value.len + sizeof(CRLF) - 1;
        }
    }


    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;


    /* the request line */

    b->last = ngx_copy(b->last, method.data, method.len);

    u->uri.data = b->last;

    if (unparsed_uri) {
        b->last = ngx_copy(b->last, r->unparsed_uri.data, r->unparsed_uri.len);

    } else {
        if (r->valid_location) {
            b->last = ngx_copy(b->last, u->conf->uri.data, u->conf->uri.len);
        }

        if (escape) {
            ngx_escape_uri(b->last, r->uri.data + loc_len,
                           r->uri.len - loc_len, NGX_ESCAPE_URI);
            b->last += r->uri.len - loc_len + escape;

        } else {
            b->last = ngx_copy(b->last, r->uri.data + loc_len,
                               r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *b->last++ = '?';
            b->last = ngx_copy(b->last, r->args.data, r->args.len);
        }
    }

    u->uri.len = b->last - u->uri.data;

    b->last = ngx_cpymem(b->last, ngx_http_proxy_version,
                         sizeof(ngx_http_proxy_version) - 1);

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    e.ip = plcf->headers_set->elts;
    e.pos = b->last;
    e.request = r;
    e.flushed = 1;

    le.ip = plcf->headers_set_len->elts;

    while (*(uintptr_t *) le.ip) {
        lcode = *(ngx_http_script_len_code_pt *) le.ip;

        /* skip the header line name length */
        (void) lcode(&le);

        if (*(ngx_http_script_len_code_pt *) le.ip) {

            for (len = 0; *(uintptr_t *) le.ip; len += lcode(&le)) {
                lcode = *(ngx_http_script_len_code_pt *) le.ip;
            }

            e.skip = (len == sizeof(CRLF) - 1) ? 1 : 0;

        } else {
            e.skip = 0;
        }

        le.ip += sizeof(uintptr_t);

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);
    }

    b->last = e.pos;


    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&plcf->headers_set_hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);

            *b->last++ = ':'; *b->last++ = ' ';

            b->last = ngx_copy(b->last, header[i].value.data,
                               header[i].value.len);

            *b->last++ = CR; *b->last++ = LF;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
    }


    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

    if (plcf->body_set) {
        e.ip = plcf->body_set->elts;
        e.pos = b->last;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }

        b->last = e.pos;
    }

#if (NGX_DEBUG)
    {
    ngx_str_t  s;

    s.len = b->last - b->pos;
    s.data = b->pos;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header:\n\"%V\"", &s);
    }
#endif

    if (plcf->body_set == NULL && plcf->upstream.pass_request_body) {

        body = u->request_bufs;
        u->request_bufs = cl;

        while (body) {
            b = ngx_alloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

            cl->next = ngx_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

        b->flush = 1;

    } else {
        u->request_bufs = cl;
    }

    cl->next = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_reinit_request(ngx_http_request_t *r)
{
    ngx_http_proxy_ctx_t  *p;

    p = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (p == NULL) {
        return NGX_OK;
    }

    p->status = 0;
    p->status_count = 0;
    p->status_start = NULL;
    p->status_end = NULL;

    r->upstream->process_header = ngx_http_proxy_process_status_line;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_process_status_line(ngx_http_request_t *r)
{
    ngx_int_t              rc;
    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *p;

    p = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_proxy_parse_status_line(r, p);

    if (rc == NGX_AGAIN) {
        return rc;
    }

    u = r->upstream;

    if (rc == NGX_HTTP_PROXY_PARSE_NO_HEADER) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent no valid HTTP/1.0 header");

#if 0
        if (u->accel) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }
#endif

        r->http_version = NGX_HTTP_VERSION_9;
        p->status = NGX_HTTP_OK;

        return NGX_OK;
    }

    u->headers_in.status_n = p->status;
    u->state->status = p->status;

    u->headers_in.status_line.len = p->status_end - p->status_start;
    u->headers_in.status_line.data = ngx_palloc(r->pool,
                                                u->headers_in.status_line.len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, p->status_start,
               u->headers_in.status_line.len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    u->process_header = ngx_http_proxy_process_header;

    return ngx_http_proxy_process_header(r);
}


static ngx_int_t
ngx_http_proxy_parse_status_line(ngx_http_request_t *r, ngx_http_proxy_ctx_t *p)
{
    u_char                ch;
    u_char               *pos;
    ngx_http_upstream_t  *u;
    enum  {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    u = r->upstream;

    state = r->state;

    for (pos = u->buffer.pos; pos < u->buffer.last; pos++) {
        ch = *pos;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            p->status = p->status * 10 + ch - '0';

            if (++p->status_count == 3) {
                state = sw_space_after_status;
                p->status_start = pos - 2;
            }

            break;

         /* space or end of line */
         case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            p->status_end = pos - 1;
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
        }
    }

    u->buffer.pos = pos;
    r->state = state;

    return NGX_AGAIN;

done:

    u->buffer.pos = pos + 1;

    if (p->status_end == NULL) {
        p->status_end = pos;
    }

    r->state = sw_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_process_header(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_uint_t                      i;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for ( ;;  ) {

        rc = ngx_http_parse_header_line(r, &r->upstream->buffer);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_palloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);
            ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                for (i = 0; i < h->key.len; i++) {
                    h->lowcase_key[i] = ngx_tolower(h->key.data[i]);
                }
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header done");

            /*
             * if no "Server" and "Date" in header line,
             * then add the special empty headers
             */

            if (r->upstream->headers_in.server == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                h->key.len = sizeof("Server") - 1;
                h->key.data = (u_char *) "Server";
                h->value.len = 0;
                h->value.data = NULL;
                h->lowcase_key = (u_char *) "server";
            }

            if (r->upstream->headers_in.date == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

                h->key.len = sizeof("Date") - 1;
                h->key.data = (u_char *) "Date";
                h->value.len = 0;
                h->value.data = NULL;
                h->lowcase_key = (u_char *) "date";
            }

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* there was error while a header line parsing */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}


static void
ngx_http_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http proxy request");

    return;
}


static void
ngx_http_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http proxy request");

    return;
}


static ngx_int_t
ngx_http_proxy_host_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    v->len = plcf->host_header.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = plcf->host_header.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    v->len = plcf->port.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = plcf->port.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_add_x_forwarded_for_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->headers_in.x_forwarded_for == NULL) {
        v->len = r->connection->addr_text.len;
        v->data = r->connection->addr_text.data;
        return NGX_OK;
    }

    v->len = r->headers_in.x_forwarded_for->value.len
             + sizeof(", ") - 1 + r->connection->addr_text.len;

    p = ngx_palloc(r->pool, v->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    p = ngx_copy(p, r->headers_in.x_forwarded_for->value.data,
                 r->headers_in.x_forwarded_for->value.len);

    *p++ = ','; *p++ = ' ';

    ngx_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_internal_body_length_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_ctx_t  *p;

    p = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (p == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_palloc(r->connection->pool, NGX_SIZE_T_LEN);

    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%uz", p->internal_body_length) - v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_rewrite_redirect(ngx_http_request_t *r, ngx_table_elt_t *h,
    size_t prefix)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_http_proxy_loc_conf_t  *plcf;
    ngx_http_proxy_redirect_t  *pr;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    pr = plcf->redirects->elts;

    if (pr == NULL) {
        return NGX_DECLINED;
    }

    for (i = 0; i < plcf->redirects->nelts; i++) {
        rc = pr[i].handler(r, h, prefix, &pr[i]);

        if (rc != NGX_DECLINED) {
            return rc;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_proxy_rewrite_redirect_text(ngx_http_request_t *r, ngx_table_elt_t *h,
    size_t prefix, ngx_http_proxy_redirect_t *pr)
{
    size_t   len;
    u_char  *data, *p;

    if (pr->redirect.len > h->value.len - prefix
        || ngx_rstrncmp(h->value.data + prefix, pr->redirect.data,
                        pr->redirect.len) != 0)
    {
        return NGX_DECLINED;
    }

    len = prefix + pr->replacement.text.len + h->value.len - pr->redirect.len;

    data = ngx_palloc(r->pool, len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;

    p = ngx_copy(p, h->value.data, prefix);

    if (pr->replacement.text.len) {
        p = ngx_copy(p, pr->replacement.text.data, pr->replacement.text.len);
    }

    ngx_memcpy(p, h->value.data + prefix + pr->redirect.len,
               h->value.len - pr->redirect.len - prefix);

    h->value.len = len;
    h->value.data = data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_rewrite_redirect_vars(ngx_http_request_t *r, ngx_table_elt_t *h,
    size_t prefix, ngx_http_proxy_redirect_t *pr)
{
    size_t                        len;
    u_char                       *data, *p;
    ngx_http_script_code_pt       code;
    ngx_http_script_engine_t      e;
    ngx_http_script_len_code_pt   lcode;

    if (pr->redirect.len > h->value.len - prefix
        || ngx_rstrncmp(h->value.data + prefix, pr->redirect.data,
                        pr->redirect.len) != 0)
    {
        return NGX_DECLINED;
    }

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    e.ip = pr->replacement.vars.lengths;
    e.request = r;

    len = prefix + h->value.len - pr->redirect.len;

    while (*(uintptr_t *) e.ip) {
        lcode = *(ngx_http_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }

    data = ngx_palloc(r->pool, len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;

    p = ngx_copy(p, h->value.data, prefix);

    e.ip = pr->replacement.vars.values;
    e.pos = p;

    while (*(uintptr_t *) e.ip) {
        code = *(ngx_http_script_code_pt *) e.ip;
        code(&e);
    }

    ngx_memcpy(e.pos, h->value.data + prefix + pr->redirect.len,
               h->value.len - pr->redirect.len - prefix);

    h->value.len = len;
    h->value.data = data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_proxy_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_proxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.hide_headers = NULL;
     *     conf->upstream.pass_headers = NULL;
     *     conf->upstream.schema = { 0, NULL };
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *
     *     conf->method = NULL;
     *     conf->headers_source = NULL;
     *     conf->headers_set_len = NULL;
     *     conf->headers_set = NULL;
     *     conf->headers_set_hash = NULL;
     *     conf->body_set_len = NULL;
     *     conf->body_set = NULL;
     *     conf->body_source = { 0, NULL };
     *     conf->rewrite_locations = NULL;
     */

    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;

    conf->upstream.intercept_errors = NGX_CONF_UNSET;

    /* "proxy_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->redirect = NGX_CONF_UNSET;
    conf->upstream.change_buffering = 1;

    conf->headers_hash_max_size = NGX_CONF_UNSET_UINT;
    conf->headers_hash_bucket_size = NGX_CONF_UNSET_UINT;

	conf->proxy_no_cache = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_proxy_loc_conf_t *prev = parent;
    ngx_http_proxy_loc_conf_t *conf = child;

    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    ngx_str_t                    *header;
    ngx_uint_t                    i, j;
    ngx_array_t                   hide_headers;
    ngx_keyval_t                 *src, *s, *h;
    ngx_hash_key_t               *hk;
    ngx_hash_init_t               hash;
    ngx_http_proxy_redirect_t    *pr;
    ngx_http_script_compile_t     sc;
    ngx_http_script_copy_code_t  *copy;

    if (conf->upstream.store != 0) {
        ngx_conf_merge_value(conf->upstream.store,
                                  prev->upstream.store, 0);

        if (conf->upstream.store_lengths == NULL) {
            conf->upstream.store_lengths = prev->upstream.store_lengths;
            conf->upstream.store_values = prev->upstream.store_values;
        }
    }

    ngx_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    ngx_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"proxy_buffers\"");
        return NGX_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
                                         conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be equal or bigger than "
             "maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be less than "
             "the size of all \"proxy_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
                                      conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_temp_file_write_size\" must be equal or bigger than "
             "maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
                                        conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_max_temp_file_size\" must be equal to zero to disable "
             "the temporary files usage or must be equal or bigger than "
             "maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    ngx_conf_merge_path_value(conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              NGX_HTTP_PROXY_TEMP_PATH, 1, 2, 0,
                              ngx_garbage_collector_temp_handler, cf);

    if (conf->method.len == 0) {
        conf->method = prev->method;

    } else {
        conf->method.data[conf->method.len] = ' ';
        conf->method.len++;
    }

    ngx_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    ngx_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

    ngx_conf_merge_value(conf->redirect, prev->redirect, 1);

    if (conf->redirect) {

        if (conf->redirects == NULL) {
            conf->redirects = prev->redirects;
        }

        if (conf->redirects == NULL && conf->upstream.url.data) {

            conf->redirects = ngx_array_create(cf->pool, 1,
                                            sizeof(ngx_http_proxy_redirect_t));
            if (conf->redirects == NULL) {
                return NGX_CONF_ERROR;
            }

            pr = ngx_array_push(conf->redirects);
            if (pr == NULL) {
                return NGX_CONF_ERROR;
            }

            pr->handler = ngx_http_proxy_rewrite_redirect_text;
            pr->redirect = conf->upstream.url;

            if (conf->upstream.uri.len) {
                pr->replacement.text = conf->upstream.location;

            } else {
                pr->replacement.text.len = 0;
                pr->replacement.text.data = NULL;
            }
        }
    }

    ngx_conf_merge_uint_value(conf->headers_hash_max_size,
                              prev->headers_hash_max_size, 512);

    ngx_conf_merge_uint_value(conf->headers_hash_bucket_size,
                              prev->headers_hash_bucket_size, 64);

	ngx_conf_merge_value(conf->proxy_no_cache, prev->proxy_no_cache, 1);

    conf->headers_hash_bucket_size = ngx_align(conf->headers_hash_bucket_size,
                                               ngx_cacheline_size);

    if (conf->upstream.hide_headers == NULL
        && conf->upstream.pass_headers == NULL)
    {
        conf->upstream.hide_headers = prev->upstream.hide_headers;
        conf->upstream.pass_headers = prev->upstream.pass_headers;
        conf->upstream.hide_headers_hash = prev->upstream.hide_headers_hash;

        if (conf->upstream.hide_headers_hash.buckets) {
            goto peers;
        }

    } else {
        if (conf->upstream.hide_headers == NULL) {
            conf->upstream.hide_headers = prev->upstream.hide_headers;
        }

        if (conf->upstream.pass_headers == NULL) {
            conf->upstream.pass_headers = prev->upstream.pass_headers;
        }
    }

    if (ngx_array_init(&hide_headers, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (header = ngx_http_proxy_hide_headers; header->len; header++) {
        hk = ngx_array_push(&hide_headers);
        if (hk == NULL) {
            return NGX_CONF_ERROR;
        }

        hk->key = *header;
        hk->key_hash = ngx_hash_key_lc(header->data, header->len);
        hk->value = (void *) 1;
    }

    if (conf->upstream.hide_headers) {

        header = conf->upstream.hide_headers->elts;

        for (i = 0; i < conf->upstream.hide_headers->nelts; i++) {

            hk = hide_headers.elts;

            for (j = 0; j < hide_headers.nelts; j++) {
                if (ngx_strcasecmp(header[i].data, hk[j].key.data) == 0) {
                    goto exist;
                }
            }

            hk = ngx_array_push(&hide_headers);
            if (hk == NULL) {
                return NGX_CONF_ERROR;
            }

            hk->key = header[i];
            hk->key_hash = ngx_hash_key_lc(header[i].data, header[i].len);
            hk->value = (void *) 1;

        exist:

            continue;
        }
    }

    if (conf->upstream.pass_headers) {

        hk = hide_headers.elts;
        header = conf->upstream.pass_headers->elts;

        for (i = 0; i < conf->upstream.pass_headers->nelts; i++) {
            for (j = 0; j < hide_headers.nelts; j++) {

                if (hk[j].key.data == NULL) {
                    continue;
                }

                if (ngx_strcasecmp(header[i].data, hk[j].key.data) == 0) {
                    hk[j].key.data = NULL;
                    break;
                }
            }
        }
    }

    hash.hash = &conf->upstream.hide_headers_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, hide_headers.elts, hide_headers.nelts) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

peers:

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;

        conf->host_header = prev->host_header;
        conf->port = prev->port;
        conf->upstream.schema = prev->upstream.schema;
    }


    if (conf->body_source.data == NULL) {
        conf->body_source = prev->body_source;
        conf->body_set_len = prev->body_set_len;
        conf->body_set = prev->body_set;
    }

    if (conf->body_source.data && conf->body_set_len == NULL) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &conf->body_source;
        sc.flushes = &conf->flushes;
        sc.lengths = &conf->body_set_len;
        sc.values = &conf->body_set;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (conf->headers_source == NULL) {
            conf->headers_source = ngx_array_create(cf->pool, 4,
                                                    sizeof(ngx_keyval_t));
            if (conf->headers_source == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        s = ngx_array_push(conf->headers_source);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }

        s->key.len = sizeof("Content-Length") - 1;
        s->key.data = (u_char *) "Content-Length";
        s->value.len = sizeof("$proxy_internal_body_length") - 1;
        s->value.data = (u_char *) "$proxy_internal_body_length";
    }


    if (conf->headers_source == NULL) {
        conf->flushes = prev->flushes;
        conf->headers_set_len = prev->headers_set_len;
        conf->headers_set = prev->headers_set;
        conf->headers_set_hash = prev->headers_set_hash;
        conf->headers_source = prev->headers_source;
    }

    if (conf->headers_set_hash.buckets) {
        return NGX_CONF_OK;
    }


    conf->headers_names = ngx_array_create(cf->pool, 4, sizeof(ngx_hash_key_t));
    if (conf->headers_names == NULL) {
        return NGX_CONF_ERROR;
    }

    if (conf->headers_source == NULL) {
        conf->headers_source = ngx_array_create(cf->pool, 4,
                                                sizeof(ngx_keyval_t));
        if (conf->headers_source == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    conf->headers_set_len = ngx_array_create(cf->pool, 64, 1);
    if (conf->headers_set_len == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->headers_set = ngx_array_create(cf->pool, 512, 1);
    if (conf->headers_set == NULL) {
        return NGX_CONF_ERROR;
    }


    src = conf->headers_source->elts;

    for (h = ngx_http_proxy_headers; h->key.len; h++) {

        for (i = 0; i < conf->headers_source->nelts; i++) {
            if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
                goto next;
            }
        }

        s = ngx_array_push(conf->headers_source);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }

        *s = *h;

        src = conf->headers_source->elts;

    next:

        continue;
    }


    src = conf->headers_source->elts;
    for (i = 0; i < conf->headers_source->nelts; i++) {

        hk = ngx_array_push(conf->headers_names);
        if (hk == NULL) {
            return NGX_CONF_ERROR;
        }

        hk->key = src[i].key;
        hk->key_hash = ngx_hash_key_lc(src[i].key.data, src[i].key.len);
        hk->value = (void *) 1;

        if (src[i].value.len == 0) {
            continue;
        }

        if (ngx_http_script_variables_count(&src[i].value) == 0) {
            copy = ngx_array_push_n(conf->headers_set_len,
                                    sizeof(ngx_http_script_copy_code_t));
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = (ngx_http_script_code_pt)
                                                 ngx_http_script_copy_len_code;
            copy->len = src[i].key.len + sizeof(": ") - 1
                        + src[i].value.len + sizeof(CRLF) - 1;


            size = (sizeof(ngx_http_script_copy_code_t)
                       + src[i].key.len + sizeof(": ") - 1
                       + src[i].value.len + sizeof(CRLF) - 1
                       + sizeof(uintptr_t) - 1)
                    & ~(sizeof(uintptr_t) - 1);

            copy = ngx_array_push_n(conf->headers_set, size);
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = ngx_http_script_copy_code;
            copy->len = src[i].key.len + sizeof(": ") - 1
                        + src[i].value.len + sizeof(CRLF) - 1;

            p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);

            p = ngx_cpymem(p, src[i].key.data, src[i].key.len);
            *p++ = ':'; *p++ = ' ';
            p = ngx_cpymem(p, src[i].value.data, src[i].value.len);
            *p++ = CR; *p = LF;

        } else {
            copy = ngx_array_push_n(conf->headers_set_len,
                                    sizeof(ngx_http_script_copy_code_t));
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = (ngx_http_script_code_pt)
                                                 ngx_http_script_copy_len_code;
            copy->len = src[i].key.len + sizeof(": ") - 1;


            size = (sizeof(ngx_http_script_copy_code_t)
                    + src[i].key.len + sizeof(": ") - 1 + sizeof(uintptr_t) - 1)
                    & ~(sizeof(uintptr_t) - 1);

            copy = ngx_array_push_n(conf->headers_set, size);
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = ngx_http_script_copy_code;
            copy->len = src[i].key.len + sizeof(": ") - 1;

            p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
            p = ngx_cpymem(p, src[i].key.data, src[i].key.len);
            *p++ = ':'; *p = ' ';


            ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

            sc.cf = cf;
            sc.source = &src[i].value;
            sc.flushes = &conf->flushes;
            sc.lengths = &conf->headers_set_len;
            sc.values = &conf->headers_set;

            if (ngx_http_script_compile(&sc) != NGX_OK) {
                return NGX_CONF_ERROR;
            }


            copy = ngx_array_push_n(conf->headers_set_len,
                                    sizeof(ngx_http_script_copy_code_t));
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = (ngx_http_script_code_pt)
                                                 ngx_http_script_copy_len_code;
            copy->len = sizeof(CRLF) - 1;


            size = (sizeof(ngx_http_script_copy_code_t)
                    + sizeof(CRLF) - 1 + sizeof(uintptr_t) - 1)
                    & ~(sizeof(uintptr_t) - 1);

            copy = ngx_array_push_n(conf->headers_set, size);
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = ngx_http_script_copy_code;
            copy->len = sizeof(CRLF) - 1;

            p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
            *p++ = CR; *p = LF;
        }

        code = ngx_array_push_n(conf->headers_set_len, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_CONF_ERROR;
        }

        *code = (uintptr_t) NULL;

        code = ngx_array_push_n(conf->headers_set, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_CONF_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = ngx_array_push_n(conf->headers_set_len, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_CONF_ERROR;
    }

    *code = (uintptr_t) NULL;


    hash.hash = &conf->headers_set_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, conf->headers_names->elts,
                      conf->headers_names->nelts)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{



	//init the share memory hash index
	if(ngx_http_shm_hash_init() != NGX_OK)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_http_shm_hash_init error");
		return NGX_CONF_ERROR;
	}
		
	ngx_shm_t	shm;
	shm.size = 128;
	shm.log = cf->log;
	  
	if(ngx_shm_alloc(&shm) != NGX_OK)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_shm_alloc error");
		return NGX_CONF_ERROR;
	}	
	
	if(ngx_shmtx_create(&ngx_upstream_mutex, shm.addr, NGX_PREFIX"/logs/nginx.upstream.lock")!= NGX_OK)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_shmtx_create error");
		return NGX_CONF_ERROR;
	}

    ngx_http_proxy_loc_conf_t *plcf = conf;

    u_char                    *p;
    size_t                     add;
    u_short                    port;
    ngx_str_t                 *value, *url;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;
#if (NGX_HTTP_SSL)
    ngx_pool_cleanup_t        *cln;
#endif

    if (plcf->upstream.schema.len) {
        return "is duplicate";
    }

    value = cf->args->elts;

    url = &value[1];

    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
        port = 80;

    } else if (ngx_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {

#if (NGX_HTTP_SSL)

        add = 8;
        port = 443;

        plcf->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (plcf->upstream.ssl == NULL) {
            return NGX_CONF_ERROR;
        }

        plcf->upstream.ssl->log = cf->log;

        if (ngx_ssl_create(plcf->upstream.ssl,
                           NGX_SSL_SSLv2|NGX_SSL_SSLv3|NGX_SSL_TLSv1, NULL)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return NGX_CONF_ERROR;
        }

        cln->handler = ngx_ssl_cleanup_ctx;
        cln->data = plcf->upstream.ssl;

#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "https protocol requires SSL support");
        return NGX_CONF_ERROR;
#endif

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL prefix");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    plcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (plcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

	//save the upstream point to a global varible
	myupstream = plcf->upstream.upstream;

    if (!u.unix_socket) {
        if (u.no_port || u.port == port) {
            plcf->host_header = u.host;

            if (port == 80) {
                plcf->port.len = sizeof("80") - 1;
                plcf->port.data = (u_char *) "80";

            } else {
                plcf->port.len = sizeof("443") - 1;
                plcf->port.data = (u_char *) "443";
            }

        } else {
            p = ngx_palloc(cf->pool, u.host.len + sizeof(":65536") - 1);
            if (p == NULL) {
                return NGX_CONF_ERROR;
            }

            plcf->host_header.len = ngx_sprintf(p, "%V:%d", &u.host, u.port)
                                        - p;
            plcf->host_header.data = p;

            plcf->port.len = plcf->host_header.len -  u.host.len - 1;
            plcf->port.data = p + u.host.len + 1;
        }


    } else {
        plcf->host_header.len = sizeof("localhost") - 1;
        plcf->host_header.data = (u_char *) "localhost";
        plcf->port.len = 0;
        plcf->port.data = (u_char *) "";
    }

    plcf->upstream.uri = u.uri;

    plcf->upstream.schema.len = add;
    plcf->upstream.schema.data = url->data;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_proxy_handler;

    plcf->upstream.location = clcf->name;

    if (clcf->named
#if (NGX_PCRE)
        || clcf->regex
#endif
        || clcf->noname)
    {
        if (plcf->upstream.uri.len) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"proxy_pass\" may not have URI part in "
                               "location given by regular expression, "
                               "or inside named location, "
                               "or inside the \"if\" statement, "
                               "or inside the \"limit_except\" block");
            return NGX_CONF_ERROR;
        }

        plcf->upstream.location.len = 0;
    }

    plcf->upstream.url = *url;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_str_t                  *value;
    ngx_array_t                *vars_lengths, *vars_values;
    ngx_http_script_compile_t   sc;
    ngx_http_proxy_redirect_t  *pr;

    if (plcf->redirect == 0) {
        return NGX_CONF_OK;
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        plcf->redirect = 0;
        plcf->redirects = NULL;
        return NGX_CONF_OK;
    }

    if (plcf->redirects == NULL) {
        plcf->redirects = ngx_array_create(cf->pool, 1,
                                           sizeof(ngx_http_proxy_redirect_t));
        if (plcf->redirects == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pr = ngx_array_push(plcf->redirects);
    if (pr == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "default") == 0) {
        if (plcf->upstream.url.data == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"proxy_rewrite_location default\" must go "
                               "after the \"proxy_pass\" directive");
            return NGX_CONF_ERROR;
        }

        pr->handler = ngx_http_proxy_rewrite_redirect_text;
        pr->redirect = plcf->upstream.url;

        if (plcf->upstream.uri.len) {
            pr->replacement.text = plcf->upstream.location;

        } else {
            pr->replacement.text.len = 0;
            pr->replacement.text.data = NULL;
        }

        return NGX_CONF_OK;
    }

    if (ngx_http_script_variables_count(&value[2]) == 0) {
        pr->handler = ngx_http_proxy_rewrite_redirect_text;
        pr->redirect = value[1];
        pr->replacement.text = value[2];

        return NGX_CONF_OK;
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    vars_lengths = NULL;
    vars_values = NULL;

    sc.cf = cf;
    sc.source = &value[2];
    sc.lengths = &vars_lengths;
    sc.values = &vars_values;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    pr->handler = ngx_http_proxy_rewrite_redirect_vars;
    pr->redirect = value[1];
    pr->replacement.vars.lengths = vars_lengths->elts;
    pr->replacement.vars.values = vars_values->elts;

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_str_t                  *value;
    ngx_http_script_compile_t   sc;

    if (plcf->upstream.store != NGX_CONF_UNSET || plcf->upstream.store_lengths)
    {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "on") == 0) {
        plcf->upstream.store = 1;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        plcf->upstream.store = 0;
        return NGX_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &plcf->upstream.store_lengths;
    sc.values = &plcf->upstream.store_values;
    sc.variables = ngx_http_script_variables_count(&value[1]);
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"proxy_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"proxy_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_upstream_max_fails_unsupported(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
         "\"proxy_upstream_max_fails\" is not supported, "
         "use the \"max_fails\" parameter of the \"server\" directive ",
         "inside the \"upstream\" block");

    return NGX_CONF_ERROR;
}


static char *
ngx_http_proxy_upstream_fail_timeout_unsupported(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
         "\"proxy_upstream_fail_timeout\" is not supported, "
         "use the \"fail_timeout\" parameter of the \"server\" directive ",
         "inside the \"upstream\" block");

    return NGX_CONF_ERROR;
}

//set record lock
int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
        struct flock lock;

        lock.l_type = type;
        lock.l_start = offset;
        lock.l_whence = whence;
        lock.l_len = len;

        return (fcntl(fd, cmd, &lock));
}

//record lock test                                                                                                                 
pid_t lock_test(int fd, int type, off_t offset, int whence, off_t len)                                            
{                                                                                                                 
        struct flock lock;                                                                                        
                                                                                                                  
        lock.l_type = type;                                                                                       
        lock.l_start = offset;                                                                                    
        lock.l_whence = whence;                                                                                   
        lock.l_len = len;                                                                                         
                                                                                                                  
        if(fcntl(fd, F_GETLK, &lock) == -1)                                                                       
                return (-1);                                                                                      
                                                                                                                  
        if(lock.l_type == F_UNLCK)                                                                                
                return (0);                                                                                       
                                                                                                                  
        return (lock.l_pid);                                                                                      
}   



//set content type function base on indexed info
void ngx_http_upstream_cached_set_content_type(ngx_http_request_t *r, int hash_index)
{
	if(nhucht[hash_index].cache.charset)
	{
		r->headers_out.charset.len = sizeof("utf-8") - 1;
		r->headers_out.charset.data = (u_char *) "utf-8";
	}
	
	switch (nhucht[hash_index].cache.type)
	{	
		
		case 1:
			if(nhucht[hash_index].cache.charset)
			{
				r->headers_out.content_type.len = sizeof("text/xml;charset=utf-8") - 1;
				r->headers_out.content_type.data = (u_char *) "text/xml;charset=utf-8";
			}
			else
			{
				r->headers_out.content_type.len = sizeof("text/xml") - 1;
				r->headers_out.content_type.data = (u_char *) "text/xml";
			}
			break;
		case 2:
			if(nhucht[hash_index].cache.charset)
			{
				r->headers_out.content_type.len = sizeof("text/css;charset=utf-8") - 1;
				r->headers_out.content_type.data = (u_char *) "text/css;charset=utf-8";
			}
			else
			{
				r->headers_out.content_type.len = sizeof("text/css") - 1;
				r->headers_out.content_type.data = (u_char *) "text/css";
			}
			break;
		case 3:
			if(nhucht[hash_index].cache.charset)
			{
				r->headers_out.content_type.len = sizeof("image/gif;charset=utf-8") - 1;
				r->headers_out.content_type.data = (u_char *) "image/gif;charset=utf-8";
			}
			else
			{
				r->headers_out.content_type.len = sizeof("image/gif") - 1;
				r->headers_out.content_type.data = (u_char *) "image/gif";
			}
			break;
		case 4:
			if(nhucht[hash_index].cache.charset)
			{
				r->headers_out.content_type.len = sizeof("image/jpeg;charset=utf-8") - 1;
				r->headers_out.content_type.data = (u_char *) "image/jpeg;charset=utf-8";
			}
			else
			{
				r->headers_out.content_type.len = sizeof("image/jpeg") - 1;
				r->headers_out.content_type.data = (u_char *) "image/jpeg";
			}
			break;
		case 5:
			if(nhucht[hash_index].cache.charset)
			{
				r->headers_out.content_type.len = sizeof("image/png;charset=utf-8") - 1;
				r->headers_out.content_type.data = (u_char *) "image/png;charset=utf-8";
			}
			else
			{
				r->headers_out.content_type.len = sizeof("image/png") - 1;
				r->headers_out.content_type.data = (u_char *) "image/png";
			}
			break;
		case 6:
			if(nhucht[hash_index].cache.charset)
			{
				r->headers_out.content_type.len = sizeof("text/plain;charset=utf-8") - 1;
				r->headers_out.content_type.data = (u_char *) "text/plain;charset=utf-8";
			}
			else
			{
				r->headers_out.content_type.len = sizeof("text/plain") - 1;
				r->headers_out.content_type.data = (u_char *) "text/plain";
			}
			break;
		case 7:	
			if(nhucht[hash_index].cache.charset)
			{
				r->headers_out.content_type.len = sizeof("application/x-javascript;charset=utf-8") - 1;
				r->headers_out.content_type.data = (u_char *) "application/x-javascript;charset=utf-8";
			}
			else
			{
				r->headers_out.content_type.len = sizeof("application/x-javascript") - 1;
				r->headers_out.content_type.data = (u_char *) "application/x-javascript";
			}
			break;
		case 8:	
			if(nhucht[hash_index].cache.charset)
			{
				r->headers_out.content_type.len = sizeof("application/x-shockwave-flash;charset=utf-8") - 1;
				r->headers_out.content_type.data = (u_char *) "application/x-shockwave-flash;charset=utf-8";
			}
			else
			{
				r->headers_out.content_type.len = sizeof("application/x-shockwave-flash") - 1;
				r->headers_out.content_type.data = (u_char *) "application/x-shockwave-flash";
			}
			break;
		case 9:	
			if(nhucht[hash_index].cache.charset)
			{
				r->headers_out.content_type.len = sizeof("image/x-icon;charset=utf-8") - 1;
				r->headers_out.content_type.data = (u_char *) "image/x-icon;charset=utf-8";
			}
			else
			{
				r->headers_out.content_type.len = sizeof("image/x-icon") - 1;
				r->headers_out.content_type.data = (u_char *) "image/x-icon";
			}
			break;
		case 10:
			if(nhucht[hash_index].cache.charset)
			{
				r->headers_out.content_type.len = sizeof("application/xml;charset=utf-8") - 1;
				r->headers_out.content_type.data = (u_char *) "application/xml;charset=utf-8";
			}
			else
			{
				r->headers_out.content_type.len = sizeof("application/xml") - 1;
				r->headers_out.content_type.data = (u_char *) "application/xml";
			}
			break;
		case 0:
		default:
			if(nhucht[hash_index].cache.charset)
			{
				r->headers_out.content_type.len = sizeof("text/html;charset=utf-8") - 1;
				r->headers_out.content_type.data = (u_char *) "text/html;charset=utf-8";
			}
			else
			{
				r->headers_out.content_type.len = sizeof("text/html") - 1;
				r->headers_out.content_type.data = (u_char *) "text/html";
			}
	}
}


//share memory hash index init function
static ngx_int_t ngx_http_shm_hash_init()
{

	int file_exist = 1;
	int count_exist = 1;

	cache_size = sizeof(ngx_http_upstream_cache_hash_t);
	

	hash_fd = open( NGX_PREFIX"/logs/hash",O_RDWR);

	if(hash_fd < 0)
	{
		

		hash_fd = open(NGX_PREFIX"/logs/hash", O_CREAT|O_RDWR, 0777);

		if(hash_fd < 0)return NGX_ERROR;
		if(lseek(hash_fd, sizeof(ngx_http_upstream_cache_hash_t)*ALL_CACHE_NUM-1, SEEK_SET) < 0)return NGX_ERROR;	
		if(write(hash_fd ,"", 1) < 0)return NGX_ERROR;

		file_exist = 0;
	}

	count_fd = open( NGX_PREFIX"/logs/count",O_RDWR);

	if(count_fd < 0)
	{
		count_fd = open(NGX_PREFIX"/logs/count", O_CREAT|O_RDWR, 0777);
		if(count_fd < 0)return NGX_ERROR;
		if(lseek(count_fd, sizeof(ngx_http_upstream_cache_hash_count_t), SEEK_SET) < 0)return NGX_ERROR;
		if(write(count_fd ,"", 1) < 0)return NGX_ERROR;

		count_exist = 0;
	}

	//hash malloc counter
	nhuchct = (ngx_http_upstream_cache_hash_count_t*)mmap(NULL,sizeof(ngx_http_upstream_cache_hash_count_t), PROT_READ|PROT_WRITE, MAP_SHARED, count_fd, 0);

	if(nhuchct == MAP_FAILED)return NGX_ERROR;


	//hash index
	nhucht = (ngx_http_upstream_cache_hash_t*)mmap(NULL,sizeof(ngx_http_upstream_cache_hash_t)*ALL_CACHE_NUM, PROT_READ|PROT_WRITE, MAP_SHARED, hash_fd, 0);
	if(nhucht == MAP_FAILED)return NGX_ERROR;

	//Initialization the share memory and the sync files
	if(!file_exist)
	{
		memset(nhucht, 0, sizeof(ngx_http_upstream_cache_hash_t)*ALL_CACHE_NUM);
		if(msync(nhucht, sizeof(ngx_http_upstream_cache_hash_t)*ALL_CACHE_NUM, MS_ASYNC) < 0)return NGX_ERROR;
	}
	
	if(!count_exist)
	{
		memset(nhuchct, 0, sizeof(ngx_http_upstream_cache_hash_count_t));
		if(msync(nhuchct, sizeof(ngx_http_upstream_cache_hash_count_t), MS_ASYNC) < 0)return NGX_ERROR;

	}



	return NGX_OK;
}

//set hash index time out
void ngx_http_shm_set_timeout(int hash_index)
{
	writew_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size);
	nhucht[hash_index].cache.timeout |= 0x01;
	un_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size); 
}

//check index cache time, if cache file is time out then set it to hash index
ngx_int_t ngx_http_shm_is_timeout(ngx_file_info_t *fi, int hash_index)
{
	
	
	if(nhucht[hash_index].cache.timeout)return 1;

	if(time(NULL) - ngx_file_mtime(fi) > nhucht[hash_index].cache.time * 60)
	{
		writew_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size);
		nhucht[hash_index].cache.timeout |= 0x01;
		un_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size); 
		return -1;
	}
	return 0;
}

//increase the designated  index count
void ngx_http_hash_check_count(int hash_index)
{
	writew_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size);
	nhucht[hash_index].count++;
	int next = nhucht[hash_index].next;
	if(next != 0)
	{
		if(nhucht[hash_index].count < nhucht[next].count)
		{
			ngx_http_upstream_cache_t tmp_cache;
			int size = sizeof(ngx_http_upstream_cache_t);

			ngx_cpymem(&tmp_cache, &nhucht[hash_index].cache, size);
			u_int  tmp_count = nhucht[hash_index].count;

			ngx_cpymem(&nhucht[hash_index].cache, &nhucht[next].cache, size);

			writew_lock(hash_fd, next * cache_size, SEEK_SET, cache_size);
			ngx_cpymem(&nhucht[next].cache, &tmp_cache, size);
			nhucht[next].count = tmp_count;
			un_lock(hash_fd, next * cache_size, SEEK_SET, cache_size);
		}

	}
	un_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size);
}


//delete hash index
void ngx_http_shm_hash_del(int hash_index, u_char *key, char *filepath)
{
	writew_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size);
	nhucht[hash_index].cache.del |= 0x01;
	un_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size);
	unlink(filepath);
	
}

//update the designated  hash index
void ngx_http_shm_hash_update(int hash_index, u_char *key, int time, int type, int zip, int charset)
{
	if(!strncmp(nhucht[hash_index].cache.key, key, 16))
	{
		writew_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size);

		//exact time in a minute
		if(time < 60)
		{
			time = 60;
		}
		else
		{
			time = time / 60;
		}
		//prevent too large time data
		if(time >= TIME_OUT_MAX)time = TIME_OUT_MAX;
		
		nhucht[hash_index].cache.time = time;
		nhucht[hash_index].cache.type = type;
		nhucht[hash_index].cache.timeout &= 0x00;
		if(nhucht[hash_index].cache.del)
		{
			nhucht[hash_index].count = 0;	
			nhucht[hash_index].cache.del &= 0x00;
		}
		nhucht[hash_index].cache.cached |= 0x01;
		if(zip)
		{
			nhucht[hash_index].cache.zip |= 0x01;
		}
		else
		{
			nhucht[hash_index].cache.zip &= 0x00;
		}
		nhucht[hash_index].cache.charset = charset;
		nhucht[hash_index].cache.check &= 0x00;

		un_lock(hash_fd, hash_index * cache_size, SEEK_SET, cache_size); 
	}
}

//get the cache dir
int ngx_http_shm_hash_getindex(ngx_http_proxy_loc_conf_t  *plcf)
{
	cache_dir_index++;
	if(cache_dir_index >= plcf->upstream.upstream->caches->nelts)
	{
		cache_dir_index = 0;
		return 0;
	}
	return cache_dir_index;
}

//add new hash index, fill it 
ngx_int_t ngx_http_shm_hash_add(int hash_index, u_char *key, int dir_index)
{

	nhucht[hash_index].cache.index = dir_index;
	nhucht[hash_index].cache.time = 0;
	nhucht[hash_index].cache.type = 0;
	ngx_cpymem(nhucht[hash_index].cache.key, key, 16);
	nhucht[hash_index].cache.cached |= 0x01;
	nhucht[hash_index].cache.zip = 0;
	nhucht[hash_index].cache.charset = 0;
	nhucht[hash_index].cache.del = 0;
	nhucht[hash_index].cache.check |= 0x01;
	nhucht[hash_index].cache.timeout &= 0x00;

	return NGX_OK;
}

//find the hash index with md5 key
int ngx_http_shm_hash_find(int hash_index, u_char *key, int *hash_stat)
{
	int old_index = 0;	
	if(nhucht[hash_index].cache.cached == 0)
	{
		*hash_stat = -1;
		return hash_index;
	}

	if(!strncmp(nhucht[hash_index].cache.key, key, 16))
	{
		if(nhucht[hash_index].cache.del)
		{
			*hash_stat = -2;
			return hash_index;
		}
		*hash_stat = 1;
		return hash_index;
	}
	else
	{
		old_index = hash_index;
		hash_index = nhucht[hash_index].next;
		while(hash_index != 0 && nhucht[hash_index].cache.cached != 0)
		{
			if(!strncmp(nhucht[hash_index].cache.key, key, 16))
			{
				if(nhucht[hash_index].cache.del)
				{
					*hash_stat = -2;
					return hash_index;
				}
				*hash_stat = 1;
				return hash_index;
			}
			old_index = hash_index;	
			hash_index = nhucht[hash_index].next;
		}
		if(*hash_stat == 1)
		{
			*hash_stat = -4;
			return -1;
		}
		*hash_stat = -3;
		nhucht[old_index].next = ngx_http_shm_hash_malloc();
		return nhucht[old_index].next;

	}
	*hash_stat = -5;
	return -2;
}

//malloc new index
int ngx_http_shm_hash_malloc()
{
	//process lock
	ngx_shmtx_lock(&ngx_upstream_mutex);
	while(MAX_CACHE_NUM + nhuchct->count < ALL_CACHE_NUM)
	{
		nhuchct->count++;

		//if be delete then reuse it
		if(!nhucht[MAX_CACHE_NUM + nhuchct->count].cache.cached || nhucht[MAX_CACHE_NUM + nhuchct->count].cache.del)
		{
			ngx_shmtx_unlock(&ngx_upstream_mutex);
			return MAX_CACHE_NUM + nhuchct->count;
		}
	}

	//if arrive at the bottom
	if(MAX_CACHE_NUM + nhuchct->count >= ALL_CACHE_NUM)
	{
		nhuchct->count = 0;
		ngx_shmtx_unlock(&ngx_upstream_mutex);
		return ngx_http_shm_hash_malloc();
	}

	ngx_shmtx_unlock(&ngx_upstream_mutex);	
	return -1;
}


//ncache purge handler, operate the purge request
static ngx_int_t
ngx_http_upstream_purge_handler(ngx_http_request_t *r)
{


	int request_path_len = 0;
	char *doman = NULL;
	int doman_len = 0;

	//if you use the squidclient to purge, the request will not have the "host" header
	if(r->headers_in.host == NULL)
	{
		doman = strstr(r->request_line.data, "http://") + 7;
		doman_len = strchr(doman, '/') - doman;
		if(doman_len <= 0)doman_len = strchr(doman, ' ') - doman;
		request_path_len = doman_len + r->unparsed_uri.len + 1;
	}
	else
	{
		request_path_len = r->headers_in.host->value.len + r->unparsed_uri.len + 1;
	}

	
	char request_path[request_path_len];
	
	if(r->headers_in.host == NULL)
	{
		snprintf(request_path, request_path_len, "%s%s", doman, r->unparsed_uri.data);
	}
	else
	{
		snprintf(request_path, request_path_len, "%s%s", r->headers_in.host->value.data, r->unparsed_uri.data);
	}

	request_path[request_path_len - 1] = 0;

	ngx_uint_t hash_key = ngx_hash_key(request_path, request_path_len);
	int hash_index = hash_key % MAX_CACHE_NUM;
	
	unsigned char md5[16];
	char filename[33];
	filename[32] = 0;
	
	MD5_CTX x;
	
	MD5_Init(&x);
	
	MD5_Update (&x, request_path, request_path_len);
	
	MD5_Final(md5, &x);

	//set stat code = 1 hash find function will not malloc new index
	int hash_stat = 1;
	int new_index = ngx_http_shm_hash_find(hash_index, md5, &hash_stat);

	if(hash_stat == 1)
	{
	
	
		int i;
		for(i=0;i<16;i++)
		{
			sprintf (filename + (i*2), "%02X", md5[i]);
		}
		
		
		ngx_http_upstream_cache_conf_t	*cache = myupstream->caches->elts;
		int index = nhucht[new_index].cache.index; 
		
		
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
		
	
		//delete index from memory and cache file from file system
		ngx_http_shm_hash_del(hash_index, md5, real_path);

		r->headers_out.status = NGX_HTTP_OK;

	}
	else
	{
			//do not found
			r->headers_out.status = NGX_HTTP_NOT_FOUND;
	}
	

	//construct the response content
	char content[2];
	content[0] = 0;
	content[1] = 0;
	
	ngx_buf_t    *b;
	ngx_chain_t   out;
	r->headers_out.content_type.len = sizeof("text/html") - 1;
	r->headers_out.content_type.data = (u_char *) "text/html";
	r->headers_out.content_length_n = 1;
	
	
	
	ngx_http_send_header(r);
	
	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_pcalloc error");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	b->pos = content;
	b->last = content + 1;
	b->memory = 1;
	b->last_buf = 1;
  
	out.buf = b;
	out.next = NULL;

	

	return ngx_http_output_filter(r, &out);
}

//when nginx init set the ncache purge handler
static char *
ngx_http_upstream_purge(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    
    ngx_http_core_loc_conf_t  *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_upstream_purge_handler;

    return NGX_CONF_OK;
}

static char *
ngx_http_cache_max_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t *value = cf->args->elts;
	char size[16];
	bzero(size, 16);
	memcpy(size, value[1].data, value[1].len);
	int max_size = atoi(size);
	
	ALL_CACHE_NUM = exp2(max_size);
	MAX_CACHE_NUM = exp2(max_size - 1);

	return NGX_CONF_OK;
}




