#ifndef	_SYS_CLUSTER_TARGET_SOCKET_H
#define	_SYS_CLUSTER_TARGET_SOCKET_H
#include <linux/in.h>  
#include <linux/inet.h>  
#include <linux/socket.h>  
#include <net/sock.h>
#include <asm/atomic.h>

typedef struct cluster_target_port_socket {
    char ipaddr[16];
    int port;
    /* socket param */
    struct socket *srv_socket;
    taskq_t *accept_tq;
    atomic_t accept_thread_stop;
    kmutex_t    stop_lock;
    kmutex_t css_lock;
    kcondvar_t  css_cv;
} cluster_target_port_socket_t;

typedef struct cluster_target_socket_param {
   char hostname[256];
   char ipaddr[16];
   int port;
   int hostid;
   int priority;
} cluster_target_socket_param_t;

typedef struct cluster_target_session_socket {
	cluster_target_socket_param_t *param;
    struct sockaddr_in s_addr;
    struct socket *s_socket;
    struct socket *r_socket;
    kmutex_t s_lock;
    kmutex_t r_lock;
    kcondvar_t  socket_cv;
	int socket_link_state;
    taskq_t *rcv_tq;
    atomic_t rcv_thread_stop;
} cluster_target_session_socket_t;

int cluster_target_socket_port_init(
	cluster_target_port_t *ctp, char *link_name, nvlist_t *nvl_conf);
void cts_socket_hb_init(cluster_target_session_t *cts);
void cluster_target_socket_port_fini(cluster_target_port_t *ctp);
#endif

