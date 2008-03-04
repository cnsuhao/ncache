
/*
 * Copyright (C) Igor Sysoev, shineyear
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

extern atomic_t request_count;
extern atomic_t shoot_count;



static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);

static ngx_command_t  ngx_http_status_commands[] = {

    { ngx_string("stub_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_set_status,
      0,
      0,
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_stub_status_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_stub_status_module = {
    NGX_MODULE_V1,
    &ngx_http_stub_status_module_ctx,      /* module context */
    ngx_http_status_commands,              /* module directives */
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


static ngx_int_t ngx_http_status_handler(ngx_http_request_t *r)
{
    size_t             size;
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;
    ngx_atomic_int_t   ap, hn, ac, rq, rd, wr;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_body(r);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    size = sizeof("Uptime: ,, \n") + 12 
		   + sizeof("Active connections:  \n") + NGX_ATOMIC_T_LEN
           + sizeof("server accepts handled requests\n") - 1
           + 6 + 3 * NGX_ATOMIC_T_LEN
           + sizeof("Reading:  Writing:  Waiting:  \n") + 3 * NGX_ATOMIC_T_LEN
           + sizeof("Shoot: \n") + 3;

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;

	//nginx stat time check
    /////////////////////////////////////////////
    struct stat st;
    bzero(&st, sizeof(struct stat));
    
    if(stat(NGX_PREFIX"logs/nginx.pid", &st) != -1)
    {
			time_t now = time(NULL);
			time_t t = now - st.st_mtime;
			
			int day = t/60/60/24;
			int hour = t/60/60 - day*24;
			int min = t/60 - hour*60 - day*60*24;
			b->last = ngx_sprintf(b->last, "Uptime: %d,%d,%d \n", day, hour, min);
    }
    ///////////////////////////////////////////////

    b->last = ngx_sprintf(b->last, "Active connections: %uA \n", ac);

    b->last = ngx_cpymem(b->last, "server accepts handled requests\n",
                         sizeof("server accepts handled requests\n") - 1);

    b->last = ngx_sprintf(b->last, " %uA %uA %uA \n", ap, hn, rq);

    b->last = ngx_sprintf(b->last, "Reading: %uA Writing: %uA Waiting: %uA \n",
                          rd, wr, ac - (rd + wr));

	//cache shoot Percentage check
	b->last = b->last + sprintf(b->last, "Shoot:%.2f\n", ((float)shoot_count.counter / (float)request_count.counter) * 100);
	/////////////////////////////
	

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_status_handler;

    return NGX_CONF_OK;
}
