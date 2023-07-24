

       #include <sys/types.h>
              #include <unistd.h>
#include "ngx_http_reverse_proxy_module.h"

typedef struct {
    ngx_str_t header_uid;
    ngx_str_t header_uname;
    ngx_str_t cookie_uid;
    ngx_str_t cookie_uname;
} ngx_http_upstream_reverse_proxy_header_data_t;

static ngx_int_t
ngx_http_upstream_reverse_proxy_init_zone(ngx_shm_zone_t* shm_zone, void* data);
static void*
ngx_http_upstream_reverse_proxy_create_conf(ngx_conf_t* cf);
static char*
ngx_http_upstream_reverse_proxy(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

static ngx_command_t
ngx_http_upstream_reverse_proxy_commands[] = {
    {
        ngx_string("reverse_proxy"),
        NGX_HTTP_UPS_CONF | NGX_CONF_TAKE12,
        ngx_http_upstream_reverse_proxy,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t
ngx_http_upstream_reverse_proxy_module_ctx = {
    NULL,                                           /* preconfiguration */
    NULL,                                           /* postconfiguration */
    NULL,                                           /* create main configuration */
    NULL,                                           /* init main configuration */
    ngx_http_upstream_reverse_proxy_create_conf,    /* create server configuration */
    NULL,                                           /* merge server configuration */
    NULL,                                           /* create location configuration */
    NULL                                            /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_reverse_proxy_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_reverse_proxy_module_ctx,    /* module context */
    ngx_http_upstream_reverse_proxy_commands,       /* module directives */
    NGX_HTTP_MODULE,                                /* module type */
    NULL,                                           /* init master */
    NULL,                                           /* init module */
    NULL,                                           /* init process */
    NULL,                                           /* init thread */
    NULL,                                           /* exit thread */
    NULL,                                           /* exit process */
    NULL,                                           /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_upstream_reverse_proxy_header_data_t header_data;
static u_char ngx_http_upstream_reverse_proxy_pseudo_addr[3];

static ngx_int_t
ngx_http_upstream_init_reverse_proxy_peer(ngx_http_request_t* r, ngx_http_upstream_srv_conf_t* us);
static ngx_int_t
ngx_http_upstream_get_reverse_proxy_peer(ngx_peer_connection_t* pc, void* data);


static ngx_int_t
ngx_http_upstream_reverse_proxy_init_zone(ngx_shm_zone_t* shm_zone, void* data)
{
    ngx_slab_pool_t*                             shpool;
    ngx_http_upstream_reverse_proxy_t*           urpt;
    ngx_http_upstream_reverse_proxy_ctx_t*       dst;
    shpool = (ngx_slab_pool_t*) shm_zone->shm.addr;
    urpt = shm_zone->data;
    
    if(shm_zone->shm.exists) {
        dst = shpool->data;
    }
    
    dst = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_reverse_proxy_ctx_t));
    
    if(dst == NULL) {
        return NGX_ERROR;
    }
    
    if(urpt) {
        dst->reverse_proxy_type.data = NULL;
        dst->reverse_proxy_type.len = urpt->reverse_proxy_type.len;
        dst->reverse_proxy_value.data = NULL;
        dst->reverse_proxy_value.len = urpt->reverse_proxy_value.len;
        dst->name.data = NULL;
        dst->name.len = urpt->name.len;
    }
    
    dst->name.data = ngx_slab_alloc(shpool, 1024);
    
    if(dst->name.data == NULL) {
        goto end;
    }
    
    dst->reverse_proxy_type.data = ngx_slab_alloc(shpool, 1024);
    
    if(dst->reverse_proxy_type.data == NULL) {
        goto end;
    }
    
    dst->reverse_proxy_value.data = ngx_slab_alloc(shpool, 1024);
    
    if(dst->reverse_proxy_value.data == NULL) {
        goto end;
    }
    
    if(urpt) {
        ngx_memcpy(dst->name.data, urpt->name.data, urpt->name.len);
        ngx_memcpy(dst->reverse_proxy_type.data, urpt->reverse_proxy_type.data, urpt->reverse_proxy_type.len);
        ngx_memcpy(dst->reverse_proxy_value.data, urpt->reverse_proxy_value.data, urpt->reverse_proxy_value.len);
    }
    
    urpt->ctx = dst;
    shpool->data = dst;
    return NGX_OK;
end:

    if(dst->reverse_proxy_value.data) {
        ngx_slab_free(shpool, dst->reverse_proxy_value.data);
    }
    
    if(dst->reverse_proxy_type.data) {
        ngx_slab_free(shpool, dst->reverse_proxy_type.data);
    }
    
    if(dst->name.data) {
        ngx_slab_free(shpool, dst->name.data);
    }
    
    if(dst) {
        ngx_slab_free(shpool, dst);
    }
    
    return NGX_ERROR;
}

static ngx_int_t
ngx_http_upstream_init_reverse_proxy(ngx_conf_t* cf, ngx_http_upstream_srv_conf_t* us)
{
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "ngx_http_upstream_init_reverse_proxy");
    
    if(ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }
    
    us->peer.init = ngx_http_upstream_init_reverse_proxy_peer;
    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_init_reverse_proxy_peer(ngx_http_request_t* r,
        ngx_http_upstream_srv_conf_t* us)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "ngx http upstream init reverse proxy peer. %s:%d",
                  __FUNCTION__,
                  __LINE__);
    struct sockaddr_in*                             sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6*                            sin6;
#endif
    ngx_http_upstream_reverse_proxy_peer_data_t*    iphp;
    ngx_http_upstream_reverse_proxy_t*     rpcf;
    ngx_list_part_t*                                part;
    ngx_table_elt_t*                                header;
    ngx_uint_t                                      i;
    ngx_table_elt_t**                               cookies;
    ngx_memzero(&header_data, sizeof(ngx_http_upstream_reverse_proxy_header_data_t));
    part = &r->headers_in.headers.part;
    header = part->elts;
    cookies = r->headers_in.cookies.elts;
    
    for(i = 0; /* void */; i++) {
        if(i >= part->nelts) {
            if(part->next == NULL) {
                break;
            }
            
            part = part->next;
            header = part->elts;
            i = 0;
        }
        
        if(ngx_strcmp(header[i].key.data, "uid") == 0) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "key: %V, value: %V",
                          &header[i].key,
                          &header[i].value);
            header_data.header_uid = header[i].value;
        }
        
        if(ngx_strcmp(header[i].key.data, "uname") == 0) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "key: %V, value: %V",
                          &header[i].key,
                          &header[i].value);
            header_data.header_uname = header[i].value;
        }
    }
    
    for(i = 0; /* void */; i++) {
        if(i >= r->headers_in.cookies.nelts) {
            break;
        }
        ngx_str_t keyid = ngx_string("uid");
        ngx_str_t keyname = ngx_string("uname");
        ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &keyid, &header_data.cookie_uid); 
        ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &keyname, &header_data.cookie_uname); 

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "cookie value: %d: %V",
                      r->headers_in.cookies.nelts,
                      &cookies[i]->value);
    }
    
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "header_uid: %V header_uname:%V cookie_uid:%V cookie_uname:%V",
                  &header_data.header_uid, &header_data.header_uname,
                  &header_data.cookie_uid, &header_data.cookie_uname);
    rpcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_reverse_proxy_module);
    iphp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_reverse_proxy_peer_data_t));
    
    if(iphp == NULL) {
        return NGX_ERROR;
    }
    
    iphp->conf = rpcf;
    r->upstream->peer.data = &iphp->rrp;
    
    if(ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }
    
    r->upstream->peer.get = ngx_http_upstream_get_reverse_proxy_peer;
    
    switch(r->connection->sockaddr->sa_family) {
    case AF_INET:
        sin = (struct sockaddr_in*) r->connection->sockaddr;
        iphp->addr = (u_char*) &sin->sin_addr.s_addr;
        iphp->addrlen = 3;
        break;
#if (NGX_HAVE_INET6)
        
    case AF_INET6:
        sin6 = (struct sockaddr_in6*) r->connection->sockaddr;
        iphp->addr = (u_char*) &sin6->sin6_addr.s6_addr;
        iphp->addrlen = 16;
        break;
#endif
        
    default:
        iphp->addr = ngx_http_upstream_reverse_proxy_pseudo_addr;
        iphp->addrlen = 3;
    }
    
    iphp->hash = 89;
    iphp->tries = 0;
    iphp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;
    iphp->us = us;
    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_get_reverse_proxy_peer(ngx_peer_connection_t* pc, void* data)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_http_upstream_get_reverse_proxy_peer");
    ngx_http_upstream_reverse_proxy_peer_data_t*    iphp = data;
    ngx_http_upstream_reverse_proxy_t*              conf = iphp->conf;
    time_t                                          now;
    ngx_int_t                                       w;
    uintptr_t                                       m;
    ngx_uint_t                                      i, n, p, hash;
    ngx_http_upstream_rr_peer_t*                    peer;
    ngx_uint_t                                      target_group = 0;
    ngx_http_upstream_reverse_proxy_ctx_t*          ctx;
    ngx_slab_pool_t*                                pool;
    pool = (ngx_slab_pool_t*)conf->shm_zone->shm.addr;
    ngx_shmtx_lock(&pool->mutex);
    ctx = (ngx_http_upstream_reverse_proxy_ctx_t*)pool->data;
    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get ip hash peer, try: %ui name: %V, reverse_proxy: %s[%V]",
                   pc->tries, &ctx->name, ctx->reverse_proxy_type.data, &ctx->reverse_proxy_value);
    ngx_http_upstream_rr_peers_wlock(iphp->rrp.peers);
    
    if(ngx_strcmp(ctx->reverse_proxy_type.data, "auto") == 0) {
        ngx_str_t id;
        ngx_uint_t key = 0;
        
        if(ngx_strstr(ctx->reverse_proxy_value.data, "uid") != NULL) {
            id = header_data.header_uid;
            
            if(id.len == 0) {
                id = header_data.cookie_uid;
            }
            
            key = ngx_atoi(id.data, id.len);
        }
        
        if(ngx_strstr(ctx->reverse_proxy_value.data, "uname") != NULL) {
            id = header_data.header_uname;
            
            if(id.len == 0) {
                id = header_data.cookie_uname;
            }
            
            key = ngx_crc32_long(id.data, id.len);
        }
        
        /*
        if(ngx_strstr("uip", ctx->reverse_proxy_value.data) != NULL) {
            id = pc->sockaddr;
            key = ngx_crc32_long(id.data, id.len);
        }*/
        
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "key: %d", key);
        ngx_uint_t v = key % 10;
        u_char value;
        ngx_memcpy(&value, ctx->reverse_proxy_value.data + ctx->reverse_proxy_value.len - 1, 1);
        ngx_uint_t target_value = ngx_atoi(&value, 1);
        target_group = (v < target_value) ? 1 : 0;
    } else if(ngx_strcmp(ctx->reverse_proxy_type.data, "close") == 0) {
        target_group = 0;
    } else if(ngx_strcmp(ctx->reverse_proxy_type.data, "gray") == 0) {
        u_char id[100] = {0};
        u_char name[200] = {0};
        u_char cookie_id[100] = {0};
        u_char cookie_name[100] = {0};
        memcpy(id, header_data.header_uid.data, header_data.header_uid.len);
        memcpy(name, header_data.header_uname.data, header_data.header_uname.len);
        memcpy(cookie_id, header_data.cookie_uid.data, header_data.cookie_uid.len);
        memcpy(cookie_name, header_data.cookie_uname.data, header_data.cookie_uname.len);
       
        if((header_data.header_uid.len != 0 && ngx_strstr(ctx->reverse_proxy_value.data, id) != NULL) ||
            (header_data.header_uname.len != 0 && ngx_strstr(ctx->reverse_proxy_value.data, name) != NULL) ||
            (header_data.cookie_uid.len != 0 && ngx_strstr(ctx->reverse_proxy_value.data, cookie_id) != NULL) ||
            (header_data.cookie_uname.len != 0 && ngx_strstr(ctx->reverse_proxy_value.data, cookie_name) != NULL)) 
            {
                target_group = 1;
            }

    } else if(ngx_strcmp(ctx->reverse_proxy_type.data, "target") == 0) {
        ngx_str_t id = header_data.header_uid;
        target_group = ngx_atoi(id.data, id.len) % 10;
    }
    
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "reverse_proxy: %V[%V] group: %d",
                   &ctx->reverse_proxy_type,
                   &ctx->reverse_proxy_value,
                   target_group);
    ngx_shmtx_unlock(&pool->mutex);
    
    if(iphp->tries > 20 || iphp->rrp.peers->single) {
        ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
        return iphp->get_rr_peer(pc, &iphp->rrp);
    }
    
    now = ngx_time();
    pc->cached = 0;
    pc->connection = NULL;
    hash = iphp->hash;
    
    for(;;) {
        for(i = 0; i < (ngx_uint_t) iphp->addrlen; i++) {
            hash = (hash * 113 + iphp->addr[i]) % 6271;
        }
        
        w = hash % iphp->rrp.peers->total_weight;
        peer = iphp->rrp.peers->peer;
        p = 0;
        
        while(w >= peer->weight) {
            w -= peer->weight;
            peer = peer->next;
            p++;
        }
        
        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
        
        if(iphp->rrp.tried[n] & m) {
            goto next;
        }
        
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get ip hash peer, hash: %ui %04XL", p, (uint64_t) m);
                       
        if(peer->down) {
            goto next;
        }
        
        if(peer->group != target_group) {
            goto next;
        }
        
        if(peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout) {
            goto next;
        }
        
        if(peer->max_conns && peer->conns >= peer->max_conns) {
            goto next;
        }
        
        break;
next:

        if(++iphp->tries > 20) {
            ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
            return iphp->get_rr_peer(pc, &iphp->rrp);
        }
    }
    
    iphp->rrp.current = peer;
    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                  "get ip hash peer, max_fails: %ui server: %s",
                  peer->max_fails, peer->server.data);
    peer->conns++;
    
    if(now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }
    
    ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
    iphp->rrp.tried[n] |= m;
    iphp->hash = hash;
    return NGX_OK;
}

static void*
ngx_http_upstream_reverse_proxy_create_conf(ngx_conf_t* cf)
{
    ngx_http_upstream_reverse_proxy_t*  conf;
    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_reverse_proxy_t));
                       
    if(conf == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "ngx_http_upstream_reverse_proxy_create_conf faild.");
        return NULL;
    }
    
    return conf;
}

static char*
ngx_http_upstream_reverse_proxy(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
    ngx_http_upstream_srv_conf_t*                   uscf;
    ngx_http_upstream_reverse_proxy_t*              rpcf = conf;
    ngx_str_t*                                      value;
    ssize_t                                         size = 1024*32;
    value = cf->args->elts;
    
    if(cf->args->nelts > 1) {
        rpcf->reverse_proxy_type = value[1];
    }
    
    if(cf->args->nelts > 2) {
        rpcf->reverse_proxy_value = value[2];
    }
    
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    
    if(uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "load balancing method redefined.");
    }
    
    
    rpcf->name = uscf->host;
    rpcf->shm_zone = ngx_shared_memory_add(cf, &uscf->host, size,
                                           &ngx_http_upstream_reverse_proxy_module);
                                           
    if(rpcf->shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx shared memory add failed.");
        return NGX_CONF_ERROR;
    }
    
    if(rpcf->shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "shm_zone already has %V",
                           &uscf->host);
        return NGX_CONF_ERROR;
    }
    
    rpcf->shm_zone->init = ngx_http_upstream_reverse_proxy_init_zone;
    rpcf->shm_zone->data = rpcf;
    rpcf->shm_zone->noreuse = 1;
    uscf->peer.init_upstream = ngx_http_upstream_init_reverse_proxy;
    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  | NGX_HTTP_UPSTREAM_WEIGHT
                  | NGX_HTTP_UPSTREAM_MAX_CONNS
                  | NGX_HTTP_UPSTREAM_MAX_FAILS
                  | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  | NGX_HTTP_UPSTREAM_DOWN
                  | NGX_HTTP_UPSTREAM_GROUP;
    return NGX_CONF_OK;
}
