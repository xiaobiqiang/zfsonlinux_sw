#ifndef	_SYS_CLUSTER_SAN_H
#define	_SYS_CLUSTER_SAN_H

#include <sys/nvpair.h>
#include <sys/avl.h>
#include <sys/modhash.h>
#include <sys/modhash_impl.h>
#include <sys/fs/zfs.h>
#define	CLUSTER_SAN_MEMFREE_DEALAY				0

#define	TARGET_PROTOCOL_MIRROR					0x1
#define	TARGET_PROTOCOL_CLUSTER					0x2

#define	CTS_LINK_DOWN							0x00
#define	CTS_LINK_UP								0x01

#define	CLUSTER_TARGET_MAC						0x01
#define	CLUSTER_TARGET_NTB						0x02
#define	CLUSTER_TARGET_RPC_RDMA					0x03
#define CLUSTER_TARGET_SOCKET                   0x04

#define	CLUSTER_TARGET_PRI_RPC_RDMA				0x01
#define	CLUSTER_TARGET_PRI_NTB					0x02
#define	CLUSTER_TARGET_PRI_MAC					0x03
#define CLUSTER_TARGET_PRI_SOCKET               0x04

#define	CLUSTER_MAC_MTU							9000
#define	CLUSTER_MAC_FRAGMENT_LEN				8192

#define	CLUSTER_NTB_MTU							(128 * 1024)
#define	CLUSTER_NTB_FRAGMENT_LEN				(127 * 1024)

#define	CLUSTER_RPC_RDMA_FRAGMENT_LEN			(1000 * 1024)

#define	CTS_REPLY_HASH_SIZE				(1024)

#define	CLUSTER_TARGET_SESS_FLAG_MIRROR			0x01
#define	CLUSTER_TARGET_SESS_FLAG_SAN			0x02
#define	CLUSTER_TARGET_SESS_FLAG_UINIT			0x04

#define	CLUSTER_TARGET_TH_STATE_ACTIVE			0x01
#define	CLUSTER_TARGET_TH_STATE_STOP			0x02
#define	CLUSTER_TARGET_TH_STATE_SUSPEND			0x04

/* msg_type */
#define	CLUSTER_SAN_MSGTYPE_IMPTSAS				0x01
#define	CLUSTER_SAN_MSGTYPE_PPPT				0x02
#define	CLUSTER_SAN_MSGTYPE_ZFS_MIRROR			0x70
#define	CLUSTER_SAN_MSGTYPE_ZFS_HBX				0x71
#define CLUSTER_SAN_MSGTYPE_CLUSTERFS			0x72
#define	CLUSTER_SAN_MSGTYPE_JOIN				0x80
#define	CLUSTER_SAN_MSGTYPE_HB					0x81
#define	CLUSTER_SAN_MSGTYPE_REPLY				0x82
#define	CLUSTER_SAN_MSGTYPE_CLUSTER				0x83
#define CLUSTER_SAN_MSGTYPE_TEST				0x90
#define	CLUSTER_SAN_MSGTYPE_COMMSOCK			0xA0
#define	CLUSTER_SAN_MSGTYPE_NOP					0xff


#define	CLUSTER_EVT_SYNC_CMD					0x01
#define	CLUSTER_EVT_SYNC_CMD_RET				0x02
#define	CLUSTER_EVT_SYNC_MSG_RET				0x03
#define	CLUSTER_EVT_UPDATA_REMOTE_SPA_CONFIG	0x04
#define	CLUSTER_EVT_CLEAR_REMOTE_SPA_CONFIG		0x05
#define	CLUSTER_EVT_GET_REMOTE_SPA_CONFIG		0x06
#define	CLUSTER_EVT_SEL_FAILOVER_HOST			0x07
#define	CLUSTER_EVT_CLR_FAILOVER_HOST			0x08
#define	CLUSTER_EVT_CHANGE_POOL_OWNER			0x09
#define	CLUSTER_EVT_RX_IMPI_IPADDR				0x10

/* err code */
#define	CSENODATA								0x01
#define CSELINKDOWN								0x02

#define	CS_WALK_CONTINUE						0
#define	CS_WALK_TERMINATE						1

#define	CLUSTER_SAN_BROADCAST_SESS				((void *)(0-1))

#define	CLUSTER_SAN_ASYN_TX_LPORT_REG			0x01
#define	CLUSTER_SAN_ASYN_TX_LU_REG				0x02
#define	CLUSTER_SAN_ASYN_TX_GETSASPATH			0x03
#define	CLUSTER_SAN_ASYN_TX_PUTSASPATH			0x04
#define	CLUSTER_SAN_ASYN_TX_SYNC_CMD			0x05
#define	CLUSTER_SAN_ASYN_TX_AVS_STATE			0x06

typedef enum cts_link_evt {
	LINK_EVT_UP_TO_DOWN,
	LINK_EVT_DOWN_TO_UP
} cts_link_evt_t;

typedef struct cluster_target_msg_header {
	uint8_t msg_type;
	uint8_t	need_reply;
	uint8_t pad[4];
	uint16_t ex_len;
	uint64_t index;
	uint64_t len;
	uint64_t total_len;
	uint64_t offset;
	uint32_t fc_tx_len;
	uint32_t fc_rx_len;
	uint8_t reserved[8];
} cluster_target_msg_header_t;

typedef struct cluster_evt_header {
	uint32_t msg_type;
	uint8_t pad[4];
	uint64_t msg_id;
} cluster_evt_header_t;

typedef struct cluster_target_tran_data {
	void *fragmentation;
} cluster_target_tran_data_t;

typedef struct cs_rx_data {
	list_node_t		node;
	uint64_t		data_index;
	uint64_t		data_len;
	uint8_t			msg_type;
	uint8_t			need_reply;
	uint8_t			pad[6];
	uint64_t		ex_len;
	void			*ex_head;
	char			*data;
	void			*cs_cache_private;
	void 			*cs_private;
} cs_rx_data_t;

typedef struct cluster_target_tran_node{
	list_node_t node;
	void *fragmentation;
	int wait;
	kcondvar_t *cv;
	kmutex_t *mtx;
	int ret;
} cluster_target_tran_node_t;

typedef struct cluster_tran_data_origin {
	uint8_t msg_type;
	uint8_t	need_reply;
	uint8_t pad[2];
	int retry_times;
	uint64_t index;
	void *data;
	uint64_t data_len;
	void *header;
	uint64_t header_len;
} cluster_tran_data_origin_t;

typedef struct cluster_target_tran_worker {
	kthread_t *th;
	kmutex_t mtx;
	kcondvar_t cv;
	list_t *queue_r;
	list_t *queue_w;
	kmutex_t lock_pri;
	list_t *queue_pri;
	list_t queue1;
	list_t queue2;
	list_t queue3;
	uint32_t state;
	uint32_t node_numbers;
	void *tran_target_private;
} cluster_target_tran_worker_t;

typedef struct cts_rx_worker {
	kmutex_t		fragment_lock;
	avl_tree_t		fragment_avl;
	list_t			fragment_list; /* time sort */
	/* wait for handle */
	list_t			*worker_list_r;
	list_t			*worker_list_w;
	list_t			worker_list1;
	list_t			worker_list2;
	kmutex_t		worker_mtx;
	kcondvar_t		worker_cv;
	uint32_t		worker_flags;
	uint32_t		worker_ntasks;
	void			*worker_private;
	uint32_t		worker_index;
} cts_rx_worker_t;

typedef struct cluster_san_hostinfo {
	list_node_t node;
	kmutex_t lock;
	uint32_t hostid;
	uint32_t link_state;
	char *hostname;
	list_t sesslist;
	void *cur_sess;
	nvlist_t *spa_config;
	char ipmi_ipaddr[16];
	char host_ipaddr[16];
	uint64_t ref_count;
	uint32_t need_failover;

	uint64_t host_tx_index;
	mod_hash_t *host_reply_hash;

	/* rx worker */
	uint32_t host_rx_worker_n;
	taskq_t *host_rx_worker_tq;
	cts_rx_worker_t *host_rx_worker;

	/* FIXME: add by wml, to replace them in workers */
	kmutex_t 	host_fragment_lock;
	avl_tree_t	host_fragment_avl;
	list_t		host_fragment_list; /* time sort */

	/* async send */
	kmutex_t host_asyn_tx_mtx;
	kcondvar_t host_asyn_tx_cv;
	list_t host_asyn_tx_tasks;
	taskq_t *host_asyn_tx_tq;
	uint32_t host_asyn_tx_state;

	/* sync send */
	kmutex_t host_sync_tx_msg_mtx;
	list_t host_sync_tx_msgs;
} cluster_san_hostinfo_t;

typedef struct cs_sync_cmd_host_node {
	list_node_t node;
	cluster_san_hostinfo_t *host;
	int ret;
	int is_synced;
} cs_sync_cmd_host_node_t;

typedef struct cs_sync_cmd_node {
	list_node_t node;
	kmutex_t lock;
	kcondvar_t cv;
	list_t cmd_host_list;
	uint64_t cmd_id;
	char *cmd;
	int host_cnt;
	int ret_cnt;
	uint32_t refcount;
} cs_sync_cmd_node_t;

typedef struct cs_sync_cmd_list {
	kmutex_t sync_cmd_lock;
	list_t sync_cmd_list;
} cs_sync_cmd_list_t;

typedef struct cts_list_pri {
	list_node_t node;
	uint32_t pri;
	list_t sess_list;
} cts_list_pri_t;

typedef struct cluster_target_session {
	list_node_t target_node;
	list_node_t host_node;
	cts_list_pri_t *host_list;
	kmutex_t sess_lock;
	kcondvar_t sess_cv;
	void *sess_port_private;
	void *sess_host_private;
	uint32_t sess_flags;
	uint32_t sess_id;
	uint32_t sess_linkstate;
	uint32_t sess_pri;

	void *sess_target_private;

	/* tran worker */
	uint64_t sess_tran_work_index;
	uint32_t sess_tran_worker_n;
	uint32_t sess_tran_running_n;
	cluster_target_tran_worker_t *sess_tran_worker;
	
	/* rx worker */
	uint32_t sess_rx_worker_n;
	taskq_t *sess_rx_worker_tq;
	cts_rx_worker_t *sess_rx_worker;
	uint64_t sess_tx_index;

	/* heartbeat */
	taskq_t *sess_hb_tq;
	uint32_t sess_hb_state;
	uint32_t sess_hb_timeout_cnt;

	uint64_t sess_refcount;
} cluster_target_session_t;

typedef void (*csh_asyn_tx_compl_cb_func_t)(void *private, uint32_t hostid, int ret);
typedef void (*csh_asyn_tx_clean_cb_func_t)(void *data, uint64_t len,
	void *header, uint64_t header_len, void *private);
typedef int (*csh_asyn_tx_node_comp_func_t)(void *arg1, void *arg2);

typedef struct csh_asyn_tx_msg {
	void *data;
	uint64_t len;
	void *header;
	uint64_t header_len;
	uint8_t msg_type;
	uint32_t asyn_type;
	void *private;
	csh_asyn_tx_compl_cb_func_t compl_cb;
	csh_asyn_tx_clean_cb_func_t clean_cb;
	csh_asyn_tx_node_comp_func_t comp;
	uint64_t ref_count;
} csh_asyn_tx_msg_t;

typedef struct csh_asyn_tx_task_node {
	list_node_t node;
	csh_asyn_tx_msg_t *msg;
	int64_t active_time;
	boolean_t is_clean;
} csh_asyn_tx_task_node_t;

typedef struct csh_sync_tx_msg_ret {
	uint64_t msg_id;
	uint8_t msg_type;
	uint8_t pad[7];
	uint64_t ret;
} csh_sync_tx_msg_ret_t;

typedef struct csh_sync_tx_msg_node {
	list_node_t node;
	uint64_t msg_id;
	uint8_t msg_type;
	void *host_private;
	void *data;
	uint64_t len;
	void *header;
	uint64_t header_len;
	kmutex_t mtx;
	kcondvar_t cv;
	uint64_t ret;
	int responsed;
	int timeout;
	int *taskq_ret;
} csh_sync_tx_msg_node_t;

typedef struct cts_fragment_data {
	list_node_t node;
	void *target_port;
	void *rx_msg;

	uint64_t len;
	uint64_t offset;
	char *data;

	void *phy_head;
	cluster_target_msg_header_t *ct_head;

	void *ex_head;
	uint16_t ex_len;
	uint8_t pad[6];
}cts_fragment_data_t;

typedef int (*cluster_target_send_msg_t)(void *, void *);
typedef void (*cluster_target_tran_data_free_t)(void *);
typedef int (*cluster_target_tran_data_fragment_t)(
	void *, void *, cluster_tran_data_origin_t *,
	cluster_target_tran_data_t**, int *);
typedef int (*cts_tran_start_t)(cluster_target_session_t *, void *);
typedef void (*cluster_target_session_init_t)(cluster_target_session_t *, void *);
typedef void (*cluster_target_session_fini_t)(cluster_target_session_t *);
typedef cts_fragment_data_t *(*cts_rxmsg_to_fragment_t)(void *, void *);
typedef void (*cts_fragment_free_t)(cts_fragment_data_t *);
typedef void (*cluster_target_rxmsg_free_t)(void *);
typedef int (*cts_compare_t)(cluster_target_session_t *, void *);
typedef void (*ctp_get_info_t)(void *, nvlist_t *);
typedef void (*cts_get_info_t)(cluster_target_session_t *, nvlist_t *);

typedef struct cluster_target_port {
	list_node_t node;
	uint32_t target_type;
	char link_name[MAXNAMELEN];
	uint64_t ref_count;
	uint32_t protocol;
	uint32_t pri;

	kmutex_t ctp_lock;
	void *target_private;
	list_t ctp_sesslist;

	/* func */
	/* tx */
	cluster_target_send_msg_t f_send_msg;
	/* free rx data */

	/* tran data */
	cluster_target_tran_data_free_t f_tran_free;
	cluster_target_tran_data_fragment_t f_tran_fragment;
	cluster_target_tran_data_fragment_t f_tran_fragment_sgl;
	cts_tran_start_t f_session_tran_start;
	cluster_target_session_init_t f_session_init;
	cluster_target_session_fini_t f_session_fini;
	cts_rxmsg_to_fragment_t f_rxmsg_to_fragment;
	cts_fragment_free_t f_fragment_free;
	cluster_target_rxmsg_free_t f_rxmsg_free;
	cts_compare_t f_cts_compare;
	ctp_get_info_t f_ctp_get_info;
	cts_get_info_t f_cts_get_info;

	uint64_t tran_work_index;
	uint32_t tran_worker_n;
	uint32_t tran_running_n;
	cluster_target_tran_worker_t *tran_worker;

	kmutex_t brosan_mtx;
	kcondvar_t brosan_cv;
	taskq_t *brosan_tq;
	uint32_t brosan_state;

	uint64_t ref_tx_count;
	uint32_t ctp_state;
} cluster_target_port_t;

typedef struct cts_worker_para{
	list_node_t node;
	uint8_t msg_type;
	uint64_t index;
	cts_rx_worker_t *worker;
	cts_fragment_data_t *fragment;
	void *sess;
} cts_worker_para_t;

#define	CLUSTER_SAN_STATE_DISABLE			0x00
#define	CLUSTER_SAN_STATE_ENABLE			0x01
#define	CLUSTER_SAN_STATE_TARGET_DISABLE	0x02
typedef struct cluster_san {
	char cs_name[MAXNAMELEN];
	list_t cs_target_list;
	list_t cs_hostlist;
	uint32_t cs_hostcnt;
	cluster_san_hostinfo_t cs_host;

	kmutex_t cs_failover_host_lock;
	cluster_san_hostinfo_t *cs_failover_host;

	kmutex_t cs_wd_mtx;
	kcondvar_t cs_wd_cv;
	taskq_t *cs_wd_tq;
	uint32_t cs_wd_flags;

	taskq_t *cs_async_taskq;

	cs_sync_cmd_list_t cs_sync_cmd;

	uint32_t cs_state;
	uint64_t refcount;
} cluster_san_t;

extern cluster_san_t *clustersan;

typedef void (*cs_vsas_rx_cb_t)(int, int);
typedef void (*cs_rx_cb_t)(cs_rx_data_t *cs_data, void *arg);
typedef void (*cs_link_evt_cb_t)(void *private,
	cts_link_evt_t link_evt, void *arg);

int cluster_san_init(void);
void cluster_san_fini(void);
void *cs_kmem_alloc(size_t size);
void cs_kmem_free(void *buf, size_t size);
cluster_target_port_t *
cluster_target_port_init(char *name, nvlist_t *nvl_conf, uint32_t protocol);
int cluster_target_port_hold(cluster_target_port_t *ctp);
void cluster_target_port_rele(cluster_target_port_t *ctp);
int ctp_tx_hold(cluster_target_port_t *ctp);
void ctp_tx_rele(cluster_target_port_t *ctp);
void cluster_target_port_remove(
	cluster_target_port_t *ctp, uint32_t protocol);
int cluster_target_send_wait(cluster_target_port_t *ctp,
	cluster_target_tran_data_t *data_array, int cnt, int pri);
int cluster_target_session_send(cluster_target_session_t *cts,
	cluster_tran_data_origin_t *origin_data, int pri);
int cluster_target_session_send_sgl(cluster_target_session_t *cts,
	cluster_tran_data_origin_t *origin_data, int pri);

#ifdef COMM_TEST
int cluster_comm_test(int hostid, int datalen, int headlen);
#endif
int cluster_san_enable(char *clustername, char *linkname, nvlist_t *nvl_conf);
int cluster_san_disable(void);
int cluster_san_disable_target(char *link_name);
nvlist_t *cluster_san_get_hostlist(uint32_t flags);
nvlist_t *cluster_san_get_hostinfo(uint32_t hostid, uint32_t flags);
nvlist_t *cluster_san_get_targetlist(void);
nvlist_t *cluster_san_get_targetinfo(char *name, uint32_t flags);
nvlist_t *cluster_san_get_state(void);
int cluster_san_set_prop(const char *prop, const char *value);
nvlist_t *cluster_san_sync_cmd(uint64_t cmd_id, char *cmd_str, int timeout, int remote_hostid);
void cluster_san_hostinfo_hold(cluster_san_hostinfo_t *cshi);
void cluster_san_hostinfo_rele(cluster_san_hostinfo_t *cshi);
int clustersan_vsas_set_levent_callback(cs_vsas_rx_cb_t rx_cb, void *arg);
cluster_san_hostinfo_t *cluster_remote_hostinfo_hold(uint32_t hostid);
int cluster_target_session_hold(cluster_target_session_t *cts, void *tag);
void cluster_target_session_rele(cluster_target_session_t *cts, void *tag);
cluster_target_session_t * cluster_target_session_add(
	cluster_target_port_t *ctp, char *hostname, uint32_t hostid,
	void *phy_head, boolean_t *new_cts);
void cluster_san_host_walk(
	uint_t (*callback)(cluster_san_hostinfo_t *, void *), void *arg);
int csh_link_evt_hook_add(cs_link_evt_cb_t link_evt_cb, void *arg);
int csh_link_evt_hook_remove(cs_link_evt_cb_t link_evt_cb);
int cts_rx_hook_add(uint32_t msg_type, cs_rx_cb_t rx_cb, void *arg);
int cts_rx_hook_remove(uint32_t msg_type);
int csh_rx_hook_add(uint32_t msg_type, cs_rx_cb_t rx_cb, void *arg);
int csh_rx_hook_remove(uint32_t msg_type);
void csh_rx_data_free(cs_rx_data_t *cs_data, boolean_t csh_hold);
int cluster_san_host_send(cluster_san_hostinfo_t *cshi,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type, int pri, boolean_t need_reply, int retry_times);
int cluster_san_host_send_sgl(cluster_san_hostinfo_t *cshi,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type, int pri, boolean_t need_reply, int retry_times);

void cluster_san_host_asyn_send(cluster_san_hostinfo_t *cshi,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type, uint32_t type, void *private,
	csh_asyn_tx_compl_cb_func_t compl_cb, csh_asyn_tx_clean_cb_func_t clean_cb,
	csh_asyn_tx_node_comp_func_t comp);
int cluster_san_host_sync_send_msg(cluster_san_hostinfo_t *cshi,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint64_t msg_id, uint8_t msg_type, int timeout);
void cluster_san_host_sync_msg_ret(cluster_san_hostinfo_t *cshi,
	uint64_t msg_id, uint8_t msg_type, uint64_t ret);
void cluster_san_host_asyn_send_clean(uint32_t type, void *private, int wait);
void cluster_san_remote_cmd_return(char *buf, uint64_t len);

void cluster_update_spa_config(nvlist_t *nvl, boolean_t sync_remote);
int cluster_get_remote_spa_config(uint32_t hostid, nvlist_t **ppnvl);
void cluster_sync_spa_config_to_remote(uint32_t remote_hostid);
void cluster_remove_remote_spa_config(uint32_t hostid, char *spa_name);
int cluster_remote_import_pool(uint32_t remote_hostid, char *spa_name);
void cts_reply_notify(cluster_san_hostinfo_t *cshi, uint64_t index);

void cts_link_down_to_up_handle(void *arg);
void cts_link_up_to_down_handle(void *arg);

void cts_rx_worker_wakeup(cts_rx_worker_t *w, cts_worker_para_t *para);
void cs_join_msg_handle(void *arg);

int cluster_change_failover_host(cluster_san_hostinfo_t *cshi);
uint32_t cluster_get_failover_hostid(void);
void cluster_host_cancle_failover(uint32_t hostid);
boolean_t cluster_host_need_failover(uint32_t hostid);
void cluster_san_broadcast_send(
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type, int pri);

void cluster_set_host_ipmi_ip(uint32_t hostid, char *ipmi_ipaddr);
void cluster_send_ipmi_ip(uint32_t hostid, char *ipmi_ipaddr);
int cluster_get_host_ipmi_ip(uint32_t hostid, char *ipmi_ipaddr);

void zfs_mirror_cancel_check_spa_txg(uint32_t hostid);
void csh_rx_data_free_ext(cs_rx_data_t *cs_data);

#endif/* #ifndef	_SYS_CLUSTER_SAN_H */

