


#ifndef NGX_DYNAMIC_UPSTREAM_H
#define NGX_DYNAMIC_UPSTREAM_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_DYNAMIC_UPSTEAM_OP_LIST                             0
#define NGX_DYNAMIC_UPSTEAM_OP_ADD                              1
#define NGX_DYNAMIC_UPSTEAM_OP_REMOVE                           2
#define NGX_DYNAMIC_UPSTEAM_OP_BACKUP                           4
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM                            8
#define NGX_DYNAMIC_UPSTEAM_OP_UPDATE                           16
#define NGX_DYNAMIC_UPSTEAM_OP_RELOAD                           32
#define NGX_DYNAMIC_UPSTEAM_OP_REPLACE                          64

#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT                     1
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS                  2
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT               4
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP                         8
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN                       16
#define NGX_DYNAMIC_UPSTREAM_OP_PARAM_REVERSE_PROXY_TYPE        32
#define NGX_DYNAMIC_UPSTREAM_OP_PARAM_REVERSE_PROXY_VALUE       64
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_GROUP                      128

#endif /* NGX_DYNAMIC_UPSTEAM_H */
