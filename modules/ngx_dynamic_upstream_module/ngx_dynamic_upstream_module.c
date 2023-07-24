

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_dynamic_upstream_module.h"
#include "ngx_dynamic_upstream_op.h"

static ngx_str_t                flag = ngx_string("mysql");
static ngx_str_t                host = ngx_string("127.0.0.1");
static ngx_int_t                port = 3306;
static ngx_str_t                user = ngx_string("user");
static ngx_str_t                password = ngx_string("password");
//flag : mysql or conf
static u_char                   sz_flag[10] = {0};
static u_char                   sz_host[20] = {0};
static u_char                   sz_port[10] = {0};
static u_char                   sz_user[50] = {0};
static u_char                   sz_password[50] = {0};

static ngx_int_t
ngx_dynamic_upstream_preconfiguration(ngx_conf_t* cf);

/*
static char*
ngx_dynamic_upstream_init_main(ngx_conf_t* cf, void* conf);
*/
/*
static void *
ngx_dynamic_upstream_create_server_conf(ngx_conf_t *cf);
*/

static ngx_int_t
ngx_dynamic_upstream_create_response_buf(
    ngx_http_upstream_srv_conf_t* uscf,
    ngx_buf_t* b,
    size_t size,
    ngx_int_t verbose);

static ngx_int_t
ngx_dynamic_upstream_handler(ngx_http_request_t* r);

static char*
ngx_dynamic_upstream(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
/*
static char*
ngx_mysql_config(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
*/
static ngx_command_t ngx_dynamic_upstream_commands[] = {
    {
        ngx_string("dynamic_upstream"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_dynamic_upstream,
        0,
        0,
        NULL
    },
    /*
    {
        ngx_string("sg_mysql"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE4,
        ngx_mysql_config,
        0,
        0,
        NULL
    },*/
    
    ngx_null_command
};


static ngx_http_module_t
ngx_dynamic_upstream_module_ctx = {
    ngx_dynamic_upstream_preconfiguration,                              /* preconfiguration */
    NULL,                                                               /* postconfiguration */
    NULL,                                                               /* create main configuration */
   /* ngx_dynamic_upstream_init_main*/NULL,                                     /* init main configuration */
    NULL,                                     /* create server configuration */
    NULL,                                                               /* merge server configuration */
    NULL,                                                               /* create location configuration */
    NULL                                                                /* merge location configuration */
};


ngx_module_t
ngx_dynamic_upstream_module = {
    NGX_MODULE_V1,
    &ngx_dynamic_upstream_module_ctx,                                   /* module context */
    ngx_dynamic_upstream_commands,                                      /* module directives */
    NGX_HTTP_MODULE,                                                    /* module type */
    NULL,                                                               /* init master */
    NULL,                                                               /* init module */
    NULL,                                                               /* init process */
    NULL,                                                               /* init thread */
    NULL,                                                               /* exit thread */
    NULL,                                                               /* exit process */
    NULL,                                                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
replace(ngx_conf_t* cf, u_char* base, size_t base_len,
        char* src, size_t src_len,
        u_char* dst, size_t dst_len)
{
    /*
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
    "replace : [%s:%d][%s:%d][%s:%d]  ",
    base, base_len, src, src_len, dst, dst_len);
    */
    u_char* offset = ngx_strnstr(base, src, base_len);
    
    if(offset == NULL) {
        return NGX_OK;
    }
    
    //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "replace offset: %s", offset);
    int diff = dst_len - src_len;
    //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "diff: %d", diff);
    
    if(diff < 0) {
        if(dst_len)
            ngx_memcpy(offset, dst, dst_len);
            
        /*
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "replace : [%s:%d][%s:%d][%s:%d]  ",
        base, base_len, src, src_len, dst, dst_len);
        */
        ngx_memset(offset + dst_len, 0, src_len - dst_len);
        /*
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "replace : [%s:%d][%s:%d][%s:%d]  ",
        base, base_len, src, src_len, dst, dst_len);
        */
    } else if(diff == 0) {
        if(dst_len)
            ngx_memcpy(offset, dst, dst_len);
    } else {
        return NGX_ERROR;
    }
    
    return NGX_OK;
}

static ngx_int_t
read_mysql_config(ngx_conf_t* cf, u_char* filename)
{
    ngx_fd_t            fd;
    ngx_file_t          file;
    ssize_t             n;
    u_char              buf[1024] = {0};
    size_t              size = sizeof(buf);
    
    if(filename == NULL) {
        return NGX_ERROR;
    }
    
    fd = ngx_open_file(filename, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    
    if(fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%s\" failed",
                           filename);
        return NGX_ERROR;
    }
    
    file.fd = fd;
    file.name.data = filename;
    file.name.len = ngx_strlen(filename);
    file.offset = 0;
    file.log = cf->log;
    n = ngx_read_file(&file, buf, size, file.offset);
    
    if(n == NGX_ERROR) {
        return NGX_ERROR;
    }
    
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, ngx_errno,
                       "mysql config info: %s",
                       buf);
                       
    if(ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                      ngx_close_file_n " %s failed",
                      filename);
        return NGX_ERROR;
    }
    
    char* token = strtok((char*)buf, " ");
    int index = 0;
    
    while(token) {
        switch(index) {
        case 0: {
                memcpy(sz_flag, token, strlen(token));
                flag.data = sz_flag;
                flag.len = strlen(token);
                break;
            }
        case 1: {
                memcpy(sz_host, token, strlen(token));
                host.data = sz_host;
                host.len = strlen(token);
                break;
            }
            
        case 2: {
                memcpy(sz_port, token, strlen(token));
                port = atoi((const char*)sz_port);
                break;
            }
            
        case 3: {
                memcpy(sz_user, token, strlen(token));
                user.data = sz_user;
                user.len = strlen(token);
                break;
            }
            
        case 4: {
                memcpy(sz_password, token, strlen(token) - 1);
                password.data = sz_password;
                password.len = strlen(token) - 1;
                break;
            }
            
        default: {
                break;
            }
        }
        
        index++;
        token = strtok(NULL, " ");
    }
    
    ngx_log_error(NGX_LOG_DEBUG, cf->log, ngx_errno,
                  "mysql info:  %V %d %V %V",
                  &host, port, &user, &password);
    return NGX_OK;
}

static ngx_int_t
ngx_dynamic_upstream_preconfiguration(ngx_conf_t* cf)
{
    if (ngx_strcmp(flag.data, "conf") == 0) {
        return NGX_OK;
    }
    //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "ngx_dynamic_upstream_preconfiguration %V", &cf->conf_file->file.name);
    u_char conf_path[1024] = {0};
    ngx_memcpy(conf_path, cf->conf_file->file.name.data, cf->conf_file->file.name.len - 10);
    u_char cmd[2048] = {0};
    ngx_snprintf(cmd, sizeof(cmd), "rm -rf %svhost/*.conf", conf_path);
    //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "ngx_dynamic_upstream_preconfiguration %s", cmd);
    system((const char*)cmd);
    ngx_snprintf(cmd, sizeof(cmd), "rm -rf %svhost/upstream_ip/*", conf_path);
    //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "ngx_dynamic_upstream_preconfiguration %s", cmd);
    system((const char*)cmd);
    memset(cmd, 0, sizeof(cmd));
    ngx_snprintf(cmd, sizeof(cmd), "%ssg_mysql.conf", conf_path);
    //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "ngx_dynamic_upstream_preconfiguration %s", cmd);
    
    if(read_mysql_config(cf, cmd) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "read mysql configure failed.");
        return NGX_ERROR;
    }
    
    //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "ngx_dynamic_upstream_preconfiguration1 %s", cmd);
    MYSQL                   my;
    MYSQL*                  conn = NULL;
    MYSQL_RES*              res = NULL;
    MYSQL_ROW               row;
    ngx_str_t               database = ngx_string("biznginx");
    ngx_str_t               charset = ngx_string("utf8");
    ngx_str_t               sql_vhost = ngx_string("select a.service_instance_id,a.service_name,a.domain,a.route_expr,a.vhost_attribute,b.ip,b.port,b.attribute,b.route_group,b.is_del, a.server_attr, a.upstream_attr, a.location_attr, a.listen_port from vhost as a left join upstream_ip as b on a.domain=b.domain and a.service_instance_id=b.service_instance_id and a.service_name=b.service_name");
    mysql_init(&my);
    
    int timeout = 10; 
    
    int ret = 0;
    ret = mysql_options(&my, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
    if(ret != 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "mysql set connect timeout failed. error: %s", 
        mysql_error(&my));
        goto error;
    }
    
    ret = mysql_options(&my, MYSQL_OPT_READ_TIMEOUT, &timeout);
    if(ret != 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "mysql set connect timeout failed. error: %s", 
        mysql_error(&my));
        goto error;
    }
    
    conn = mysql_real_connect(&my,
                              (const char*)host.data,
                              (const char*)user.data,
                              (const char*)password.data,
                              (const char*)database.data,
                              port,
                              NULL,
                              0);
                              
    if(conn == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "connect mysql failed. error: %s, host:%V port:%d user:%V password:%V", 
        mysql_error(&my), &host, port, &user, &password);
        goto error;
    }
    
    if(mysql_set_character_set(conn, (const char*)charset.data)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "set charset failed. charset: %V error: %s", 
        &charset, mysql_error(conn));
        goto error;
    }
    
    if(mysql_real_query(conn, (const char*)sql_vhost.data, sql_vhost.len)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "mysql query failed.sql: %V error: %s", 
        &sql_vhost, mysql_error(conn));
        goto error;
    }
    
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "mysql query.sql: %V ", &sql_vhost);
    
    u_char tmp[2048] = {0};
    res = mysql_store_result(conn);
    
    if(res == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "mysql store result failed.");
        goto error;
    }
    
    while((row = mysql_fetch_row(res))) {
        if(row[0] == NULL || row[1] == NULL || row[2] == NULL 
        || row[3] == NULL || row[4] == NULL || row[12] == NULL
        || row[13] == NULL) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
            "service_instance_id,service_name,domain,route_expr,vhost_attribute, listen_port is null." );
            goto error;
        }

        u_char sz_domain[100] = {0};
        size_t len = ngx_strlen((u_char*)row[2]);
        if(ngx_strncmp((u_char*)row[2], "http://", 7) == 0) {
            ngx_memcpy(sz_domain, (u_char*)row[2] + 7, len-7);
        } else {
            ngx_memcpy(sz_domain, (u_char*)row[2], len);
        }

	u_char sz_location_attr[2048] = {0};
	ngx_snprintf(sz_location_attr, sizeof(sz_location_attr), row[12], sz_domain);
	u_char sz_vhost_attr[2048] = {0};
	ngx_snprintf(sz_vhost_attr, sizeof(sz_vhost_attr), row[4], row[1], sz_domain, row[1], sz_domain);
	 
        ngx_snprintf(tmp, sizeof(tmp), "echo \"upstream %s {\nzone zone_%s 32k;\nreverse_proxy %s;\ninclude %svhost/upstream_ip/%s.ip;\n}\nserver {\nlisten %s;\nserver_name %s;\n%s\n%s\n}\" > %s/vhost/%s.conf", sz_domain, sz_domain, row[3], conf_path, sz_domain, row[13], sz_domain, sz_vhost_attr, sz_location_attr, conf_path, sz_domain);
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "tmp value: %s", tmp);
        system((const char*)tmp);

        ngx_str_t ip = ngx_string("127.0.0.1");
        ngx_str_t port = ngx_string("49999");
        ngx_str_t attribute = ngx_string("weight=1 max_fails=1 fail_timeout=10000 down");
        ngx_str_t route_group = ngx_string("0");
        //ngx_str_t is_del = ngx_string("0");
        
        ngx_memzero(tmp, 2048);
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "base value: %V", &base);
        ngx_snprintf(tmp, sizeof(tmp), 
        "echo \"server %s:%s %s group=%s;\" > %s/vhost/upstream_ip/%s.ip", 
        ip.data, port.data, attribute.data, route_group.data, conf_path, sz_domain);
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "tmp value: %s", tmp);
        system((const char*)tmp);
        
        /*if(row[5] != NULL) {
            ip.data = (u_char*)row[5];
            ip.len = ngx_strlen(row[5]);
        }
        
        if(row[6] != NULL) {
            port.data = (u_char*)row[6];
            port.len = ngx_strlen(row[6]);
        }
        if(row[7] != NULL) {
            attribute.data = (u_char*)row[7];
            attribute.len = ngx_strlen(row[7]);
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "base value: %V", &attribute);
        ngx_str_t src1 = ngx_string("status=up");
        ngx_str_t src2 = ngx_string("status=down");
        ngx_str_t dst1 = ngx_string("");
        ngx_str_t dst2 = ngx_string("down");
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "base value: %V", &base);
        
        if(replace(cf, attribute.data, attribute.len, (char*)src1.data, 
        src1.len, dst1.data, dst1.len) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
            "replace string too long. attribute: %V, src: %V, dst: %V", 
            &attribute, &src1, &dst1);
            goto error;
        }
        
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, " base value: %V    %d", &base, cf->log->log_level);
        
        if(replace(cf, attribute.data, attribute.len, (char*)src2.data, 
        src2.len, dst2.data, dst2.len) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
            "replace string too long. attribute: %V, src: %V, dst: %V", 
            &attribute, &src2, &dst2);
            goto error;
        }
        } else {
        
        }
        
        if(row[8] != NULL) {
            route_group.data = (u_char*)row[8];
            route_group.len = ngx_strlen(row[8]);
        }
        if(row[9] != NULL) {
            is_del.data = (u_char*)row[9];
            is_del.len = ngx_strlen(row[9]);
        }

        if(ngx_strcmp(is_del.data, "1") == 0) {
            continue;
        }
        
        ngx_memzero(tmp, 2048);
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "base value: %V", &base);
        ngx_snprintf(tmp, sizeof(tmp), 
        "echo \"server %s:%s %s group=%s;\" >> %s/vhost/upstream_ip/%s_%s_%s.ip", 
        ip.data, port.data, attribute.data, route_group.data, conf_path, row[1], row[0], sz_domain);
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "tmp value: %s", tmp);
        system((const char*)tmp);*/
    }
    
    mysql_free_result(res);
    
    if(mysql_real_query(conn, (const char*)sql_vhost.data, sql_vhost.len)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "mysql query failed.sql: %V error: %s", 
        &sql_vhost, mysql_error(conn));
        goto error;
    }
    
    res = mysql_store_result(conn);
    
    if(res == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "mysql store result failed.");
        goto error;
    }
    
    while((row = mysql_fetch_row(res))) {
        if(row[0] == NULL || row[1] == NULL || row[2] == NULL 
        || row[3] == NULL || row[4] == NULL || row[5] == NULL
        || row[6] == NULL || row[7] == NULL || row[8] == NULL
        || row[9] == NULL) {
            //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
            //"service_instance_id,service_name,domain,route_expr,vhost_attribute has null." );
            continue;
        }
        
        u_char sz_domain[100] = {0};
        size_t len = ngx_strlen((u_char*)row[2]);
        if(ngx_strncmp((u_char*)row[2], "http://", 7) == 0) {
            ngx_memcpy(sz_domain, (u_char*)row[2] + 7, len-7);
        } else {
            ngx_memcpy(sz_domain, (u_char*)row[2], len);
        }

        ngx_str_t ip = ngx_string("127.0.0.1");
        ngx_str_t port = ngx_string("49999");
        ngx_str_t attribute = ngx_string("weight=1 max_fails=1 fail_timeout=10000 down");
        ngx_str_t route_group = ngx_string("0");
        ngx_str_t is_del = ngx_string("0");
        
        if(row[5] != NULL) {
            ip.data = (u_char*)row[5];
            ip.len = ngx_strlen(row[5]);
        }
        
        if(row[6] != NULL) {
            port.data = (u_char*)row[6];
            port.len = ngx_strlen(row[6]);
        }
        if(row[7] != NULL) {
            attribute.data = (u_char*)row[7];
            attribute.len = ngx_strlen(row[7]);
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "base value: %V", &attribute);
        ngx_str_t src1 = ngx_string("status=up");
        ngx_str_t src2 = ngx_string("status=down");
        ngx_str_t dst1 = ngx_string("");
        ngx_str_t dst2 = ngx_string("down");
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "base value: %V", &base);
        
        if(replace(cf, attribute.data, attribute.len, (char*)src1.data, 
        src1.len, dst1.data, dst1.len) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
            "replace string too long. attribute: %V, src: %V, dst: %V", 
            &attribute, &src1, &dst1);
            goto error;
        }
        
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, " base value: %V    %d", &base, cf->log->log_level);
        
        if(replace(cf, attribute.data, attribute.len, (char*)src2.data, 
        src2.len, dst2.data, dst2.len) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
            "replace string too long. attribute: %V, src: %V, dst: %V", 
            &attribute, &src2, &dst2);
            goto error;
        }
        }

        if(row[8] != NULL) {
            route_group.data = (u_char*)row[8];
            route_group.len = ngx_strlen(row[8]);
        }
        if(row[9] != NULL) {
            is_del.data = (u_char*)row[9];
            is_del.len = ngx_strlen(row[9]);
        }

        if(ngx_strcmp(is_del.data, "1") == 0) {
            continue;
        }
        
        ngx_memzero(tmp, 2048);
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "base value: %V", &base);
        ngx_snprintf(tmp, sizeof(tmp), 
        "echo \"server %s:%s %s group=%s;\" >> %s/vhost/upstream_ip/%s.ip", 
        ip.data, port.data, attribute.data, route_group.data, conf_path, sz_domain);
        //ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "tmp value: %s", tmp);
        system((const char*)tmp);
    }
    
    mysql_free_result(res);
    
    if(conn != NULL) {
        mysql_close(conn);
        conn = NULL;
    }
    
    return NGX_OK;
error:

    if(conn != NULL) {
        mysql_close(conn);
        conn = NULL;
    }
    
    return NGX_ERROR;
}

static ngx_int_t
ngx_dynamic_upstream_create_response_buf(ngx_http_upstream_srv_conf_t* uscf,
        ngx_buf_t* b, size_t size, ngx_int_t verbose)
{
    ngx_http_upstream_rr_peers_t *peers = (ngx_http_upstream_rr_peers_t*)uscf->peer.data;
    ngx_http_upstream_rr_peer_t *peer;
    ngx_http_upstream_reverse_proxy_t *rpcf;
    u_char namebuf[512], typebuf[10], valuebuf[1024], *last;
    
    last = b->last + size;
    rpcf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_reverse_proxy_module);
    
    ngx_http_upstream_reverse_proxy_ctx_t *ctx;
    ngx_slab_pool_t *pool;
    
    pool = (ngx_slab_pool_t*)rpcf->shm_zone->shm.addr;
    
    ngx_shmtx_lock(&pool->mutex);
    ctx = (ngx_http_upstream_reverse_proxy_ctx_t*)pool->data;
    ngx_cpystrn(typebuf, ctx->reverse_proxy_type.data, ctx->reverse_proxy_type.len + 1);
    ngx_cpystrn(valuebuf, ctx->reverse_proxy_value.data, ctx->reverse_proxy_value.len + 1);
    ngx_shmtx_unlock(&pool->mutex);
    b->last = ngx_snprintf(b->last, last - b->last,
                           "reverse_proxy %s %s;\n",
                           typebuf,
                           valuebuf);
                           
    for(peer = peers->peer; peer; peer = peer->next) {
        if(peer->name.len > 511) {
            return NGX_ERROR;
        }
        
        ngx_cpystrn(namebuf, peer->name.data, peer->name.len + 1);
        
        if(verbose) {
            b->last = ngx_snprintf(b->last, last - b->last, 
            "server %s weight=%d max_fails=%d fail_timeout=%d group=%d",
            namebuf, peer->weight, peer->max_fails, peer->fail_timeout, peer->group);
        } else {
            b->last = ngx_snprintf(b->last, last - b->last, "server %s", namebuf);
        }
        
        b->last = peer->down ? ngx_snprintf(b->last, last - b->last, " down;\n") : ngx_snprintf(b->last, last - b->last, ";\n");
    }
    
    return NGX_OK;
}


static ngx_int_t
ngx_dynamic_upstream_handler(ngx_http_request_t* r)
{
    size_t                                          size;
    ngx_int_t                                       rc;
    ngx_dynamic_upstream_op_t                       op;
    ngx_buf_t*                                      b;
    ngx_http_upstream_srv_conf_t*                   uscf;
    ngx_slab_pool_t*                                shpool;
    
    if(r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    
    rc = ngx_http_discard_request_body(r);
    
    if(rc != NGX_OK) {
        return rc;
    }
    
    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;
    
    if(r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;
        rc = ngx_http_send_header(r);
        
        if(rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }
    
    rc = ngx_dynamic_upstream_build_op(r, &op);
    
    if(rc != NGX_OK) {
        if(op.status == NGX_HTTP_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        return op.status;
    }
    
    ngx_chain_t*                            head = NULL;
    ngx_chain_t*                            out = NULL;
    ngx_chain_t*                            tail = NULL;
    ngx_uint_t                              i;
    ngx_http_upstream_srv_conf_t**          uscfp;
    ngx_http_upstream_main_conf_t*          umcf;
    ngx_int_t                               found = 0;
    ngx_chain_t                             tmp;
    
    if(!(op.op & NGX_DYNAMIC_UPSTEAM_OP_RELOAD)) {
        umcf  = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
        uscfp = umcf->upstreams.elts;
        
        for(i = 0; i < umcf->upstreams.nelts; i++) {
            uscf = uscfp[i];
            
            /**
            ngx_http_upstream_reverse_proxy_t*              rpcf;
            rpcf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_reverse_proxy_module);
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                          "reverse proxy type: %V value: %V", &rpcf->reverse_proxy_type, &rpcf->reverse_proxy_value);
            **/
            if(uscf->shm_zone != NULL) {
                ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "shm name: %V", &uscf->shm_zone->shm.name);
            }
            
            if(uscf->shm_zone != NULL &&
                    uscf->shm_zone->shm.name.len == op.upstream.len &&
                    ngx_strncmp(uscf->shm_zone->shm.name.data, op.upstream.data, op.upstream.len) == 0) {
                found = 1;
                shpool = (ngx_slab_pool_t*) uscf->shm_zone->shm.addr;
                ngx_shmtx_lock(&shpool->mutex);
                rc = ngx_dynamic_upstream_op(r, &op, shpool, uscf);
                
                if(rc != NGX_OK) {
                    ngx_shmtx_unlock(&shpool->mutex);
                    
                    if(op.status == NGX_HTTP_OK) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "failed to upstream op. %s:%d",
                                      __FUNCTION__,
                                      __LINE__);
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }
                    
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "failed to upstream op. [op: %ud] %s:%d", op.status,
                                  __FUNCTION__,
                                  __LINE__);
                    return op.status;
                }
                
                ngx_shmtx_unlock(&shpool->mutex);
                size = uscf->shm_zone->shm.size;
                b = ngx_create_temp_buf(r->pool, size);
                
                if(b == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                
                out = ngx_alloc_chain_link(r->pool);
                
                if(out == NULL) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "ngx alloc chain link failed. %s:%d", op.status,
                                  __FUNCTION__,
                                  __LINE__);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                
                out->buf = b;
                out->next = NULL;
                
                if(head == NULL) {
                    head = out;
                }
                
                if(tail == NULL) {
                    tail = out;
                } else {
                    tail->next = out;
                    tail = tail->next;
                }
                
                rc = ngx_dynamic_upstream_create_response_buf(uscf, b, size, op.verbose);
                
                if(rc == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "failed to create a response. %s:%d",
                                  __FUNCTION__,
                                  __LINE__);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                
                r->headers_out.status = NGX_HTTP_OK;
                r->headers_out.content_length_n = b->last - b->pos;
                b->last_buf = (r == r->main) ? 1 : 0;
                b->last_in_chain = 1;
            }
        }
        
        if(found == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream is not found. %s:%d",
                          __FUNCTION__,
                          __LINE__);
            return NGX_HTTP_NOT_FOUND;
        }
    } else {
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_type_len = sizeof("text/plain") - 1;
        ngx_str_set(&r->headers_out.content_type, "text/plain");
        r->headers_out.content_type_lowcase = NULL;
        size_t             size;
        size = sizeof("reload nginx successful!\n") - 1;
        b = ngx_create_temp_buf(r->pool, size);
        
        if(b == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ngx_create_temp_buf error. %s:%d",
                          __FUNCTION__,
                          __LINE__);
            return NGX_ERROR;
        }
        
        b->last = ngx_cpymem(b->last, "reload nginx successful!\n",
                             sizeof("reload nginx successful!\n") - 1);
        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;
        tmp.buf = b;
        tmp.next = NULL;
        head = &tmp;
    }
    
    rc = ngx_http_send_header(r);
    
    if(rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx http send header failed. %s:%d",
                      __FUNCTION__,
                      __LINE__);
        return rc;
    }
    
    return ngx_http_output_filter(r, head);
}

static char*
ngx_dynamic_upstream(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
    ngx_http_core_loc_conf_t*  clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_dynamic_upstream_handler;
    return NGX_CONF_OK;
}

/*
static char*
ngx_mysql_config(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
    ngx_str_t*                                      value;
    value = cf->args->elts;
    
    if(cf->args->nelts > 1) {
        host = value[1];
    }
    
    if(cf->args->nelts > 2) {
        port = atoi((char*)value[2].data);
    }
    
    if(cf->args->nelts > 3) {
        user = value[3];
    }
    
    if(cf->args->nelts > 4) {
        password = value[4];
    }
    
    return NGX_CONF_OK;
}*/
