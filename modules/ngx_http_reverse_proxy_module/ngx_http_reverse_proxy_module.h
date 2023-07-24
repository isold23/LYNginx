

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t                           reverse_proxy_type;
    ngx_str_t                           reverse_proxy_value;
    ngx_str_t                           name;
} ngx_http_upstream_reverse_proxy_ctx_t;

typedef struct {
    ngx_str_t                           reverse_proxy_type;
    ngx_str_t                           reverse_proxy_value;
    ngx_str_t                           name;
    ngx_shm_zone_t*            shm_zone;
    ngx_http_upstream_reverse_proxy_ctx_t* ctx;
} ngx_http_upstream_reverse_proxy_t;


typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t                rrp;
    ngx_uint_t                                      hash;
    u_char                                          addrlen;
    u_char*                                         addr;
    u_char                                          tries;
    ngx_event_get_peer_pt                           get_rr_peer;
    ngx_http_upstream_reverse_proxy_t*              conf;
    ngx_http_upstream_srv_conf_t*                   us;
} ngx_http_upstream_reverse_proxy_peer_data_t;

extern ngx_module_t ngx_http_upstream_reverse_proxy_module;



