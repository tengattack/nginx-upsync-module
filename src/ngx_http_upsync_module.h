#ifndef _NGX_HTTP_UPSYNC_MODELE_H_INCLUDED_
#define _NGX_HTTP_UPSYNC_MODELE_H_INCLUDED_


#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

#include "ngx_http_json.h"
#include "ngx_http_parser.h"

#if !(NGX_WIN32)
#define ngx_ftruncate(fd, offset)       ftruncate(fd, offset)
#define ngx_lseek(fd, offset, whence)   lseek(fd, offset, whence)
#define ngx_fgets(fp, offset, whence)   fgets(fp, offset, whence)
#define ngx_fopen(path, mode)           fopen(path, mode)
#define ngx_fclose(fp)                  fclose(fp)
#else
extern int ngx_ftruncate(ngx_fd_t fd, off_t length);
extern off_t ngx_lseek(ngx_fd_t fd, off_t offset, int whence);
#endif

#define ngx_strrchr(s1, c)              strrchr((const char *) s1, (int) c)

#define ngx_strtoull(nptr, endptr, base) strtoull((const char *) nptr, \
                                                  (char **) endptr, (int) base)

#define NGX_INDEX_HEADER "X-Consul-Index"
#define NGX_INDEX_HEADER_LEN 14

#define NGX_INDEX_ETCD_HEADER "X-Etcd-Index"
#define NGX_INDEX_ETCD_HEADER_LEN 12

#define NGX_MAX_HEADERS 20
#define NGX_MAX_ELEMENT_SIZE 512

#define NGX_DELAY_DELETE 30 * 60 * 1000   //75 * 1000

#define NGX_ADD 0
#define NGX_DEL 1

#define NGX_PAGE_SIZE 4 * 1024
#define NGX_PAGE_NUMBER 1024

#define NGX_HTTP_RETRY_TIMES 3
#define NGX_HTTP_SOCKET_TIMEOUT 1

#define NGX_HTTP_LB_DEFAULT        0
#define NGX_HTTP_LB_ROUNDROBIN     1
#define NGX_HTTP_LB_IP_HASH        2
#define NGX_HTTP_LB_LEAST_CONN     4
#define NGX_HTTP_LB_HASH_MODULA    8
#define NGX_HTTP_LB_HASH_KETAMA    16

#if (NGX_HTTP_UPSTREAM_CHECK) 

extern ngx_uint_t ngx_http_upstream_check_add_dynamic_peer(ngx_pool_t *pool,
    ngx_http_upstream_srv_conf_t *uscf, ngx_addr_t *peer_addr);
extern void ngx_http_upstream_check_delete_dynamic_peer(ngx_str_t *name,
    ngx_addr_t *peer_addr);

#endif


/******************************hash*********************************/

extern  ngx_module_t ngx_http_upstream_hash_module;


typedef struct {
    uint32_t                            hash;
    ngx_str_t                          *server;
} ngx_http_upstream_chash_point_t;


typedef struct {
    ngx_uint_t                          number;
    ngx_http_upstream_chash_point_t     point[1];
} ngx_http_upstream_chash_points_t;


typedef struct {
    ngx_http_complex_value_t            key;
    ngx_http_upstream_chash_points_t   *points;
} ngx_http_upstream_hash_srv_conf_t;

/****************************hash_end*******************************/


static int ngx_libc_cdecl ngx_http_upsync_chash_cmp_points(const void *one, 
    const void *two);
static ngx_int_t ngx_http_upsync_chash_init(ngx_http_upstream_srv_conf_t *uscf,
    ngx_http_upstream_rr_peers_t *tmp_peers);
static ngx_int_t ngx_http_upsync_del_chash_peer(
    ngx_http_upstream_srv_conf_t *uscf);


#endif //_NGX_HTTP_UPSYNC_MODELE_H_INCLUDED_
