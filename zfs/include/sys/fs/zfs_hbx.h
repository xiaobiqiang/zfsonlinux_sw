/*
 * Copyright 2011 Ceresdata, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef	_SYS_ZFS_HBX_H
#define	_SYS_ZFS_HBX_H

#include <sys/nvpair.h>
#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	CLUSTERD			"svc:/system/cluster:default"
#define	CLUSTERD_DOOR			"/var/run/clusterd_door"
#define	CLUSTERD_DOORCALL_MAX_RETRY	4

#define	HBX_DOOR_FAIL_MAX_TIMES		3
#define	HBX_ALLCO_BUF_FAIL_MAX_TIMES	10

#define	HBX_MONITOR_MAX_DEVS	8
#define	MAXDEVNAMELEN	32
#define	MAXDEVPARA		64
#define	HBX_DATA_FRAGMENT_LEN	8192
#define	ZFS_HBX_HASH_SIZE	1*1024*1024

#define	ZFS_HBX_FRAGMENT_HASH_SIZE	128*1024

#define	ZFS_HBX_TX_FLAG_REPLY		0x01
#define	ZFS_HBX_TX_FLAG_RETRY		0x02

typedef struct dev_event {
	char dev_names[MAXDEVNAMELEN];
	char dev_para[MAXDEVPARA];
}dev_event_t;

enum hbx_event_type {
	EVT_REMOTE_HOST_DOWN = 0x1,
	EVT_REMOTE_HOST_UP,
	EVT_REMOTE_HOST_NORMAL,
	EVT_SPA_REMOTE_HUNG,
	EVT_SPA_REMOTE_NORESPONSE,
	EVT_SPA_REMOTE_RESPONSE,
	EVT_SPA_REMOTE_TXG,
	EVT_IPMI_REMOTE_IP,
	EVT_IPMI_EXCHANGE_IP,
	EVT_IPMI_ADD_ROUTE,
	EVT_HBX_CLOSED,

	EVT_UPDATE_REMOTE_POOL_CONFIG = 0x10,
	EVT_CLEAR_REMOTE_POOL_CONFIG,
	EVT_UPDATE_PARTNER_NIC_CONFIG,
	EVT_UPDATE_KEYFILE,
	EVT_UPDATE_KEYPATH,
	EVT_UPDATE_RCMD,
	EVT_CHANGE_POOL_OWNER,
	EVT_REQ_RELEASE_PARTNER_POOL,
	EVT_RELEASE_PARTNER_POOL,
	EVT_RELEASE_PARTNER_POOL_END,
	EVT_REMOTE_MPTSAS_FAULT,
	EVT_REMOTE_LOOP_FAILED,
	EVT_SYNCKEY_RESULT,
	EVT_IMPORT_REMOTE_POOL,

	EVT_LOCAL_REBOOT_BY_FC_DISK = 0x20,
	EVT_LOCAL_REBOOT_BY_NIC,
	EVT_LOCAL_REBOOT_BY_MEMORY,
	EVT_LOCAL_REBOOT_BY_HB,
	EVT_LOCAL_REBOOT_BY_EXCEPTION,
	EVT_LOCAL_REBOOT_BY_FC_TARGET,
	EVT_LOCAL_REBOOT_BY_FC_INITIATOR,
	EVT_LOCAL_REBOOT_BY_MPTSAS,
	EVT_LOCAL_REBOOT_BY_FC_LOOP_FAILED,
	EVT_LOCAL_REBOOT_BY_ENCLOSURE,
	EVT_LOCAL_REBOOT_BY_RAID_OS_DISK,

	EVT_IMPTSAS_REMOTE_REQ = 0x30,
	EVT_PPPT_HBX_TRANSMIT,

	EVT_MAC_STATE,
	EVT_MAC_OFFLINE,
	EVT_RELEASE_POOLS,
	EVT_CLUSTER_IMPORT,
	EVT_POOL_EXPORT,
	EVT_POWEROFF_REMOTEHOST,
	EVT_POWERON_REMOTEHOST,

	EVT_CLUSTERSAN_SYNC_CMD = 0x40,
	EVT_CLUSTER_CLOSE_RDMA_RPC,

	EVT_CLUSTERNAS_FAILOVER_CTL,

	EVT_END = 0x50
};

typedef enum hbx_node_state_s {
	INACTIVE = 0,
	ACTIVE
} hbx_node_state_t;

typedef enum hbx_link_state_s {
	LINK_DOWN = 0,
	LINK_UP
} hbx_link_state_t;

typedef struct clustered_door_res {
	int	res_status;
	int	res_len;
	char	res_data[1];
} clusterd_door_res_t;

typedef struct {
	hbx_link_state_t  	link_state;
	hbx_node_state_t	major;
	hbx_node_state_t 	minor;
} hbx_state_t;

typedef struct hbx_door_para {
	uint32_t host_id;
	int event;
	hbx_link_state_t    link_state;
	hbx_node_state_t major;
	hbx_node_state_t minor;
	boolean_t b_data;
	uint64_t data_len;
}hbx_door_para_t;

#ifdef _KERNEL

typedef enum hbx_tx_reply {
	NEED_REPLY = 1,
	NEED_NO_REPLY
} hbx_tx_reply_type;

typedef struct hbx_spa_config {
	nvlist_t *config_own;
	nvlist_t *config_partner;
} hbx_spa_config_t;

typedef struct hbx_event_s {
	list_node_t event_node;
	enum hbx_event_type type;
	hbx_link_state_t	link_state;
	hbx_node_state_t	major;
	hbx_node_state_t	minor;
	dev_event_t  devs[HBX_MONITOR_MAX_DEVS];
	uint32_t 	dev_num;
	boolean_t  event_request;
	uint64_t	event_id;
	boolean_t b_data;
	char *data;
	uint64_t data_len;
} hbx_event_t;

typedef struct hb_event_list_s {
	list_t event_list;
	kmutex_t event_mutex;
} hb_event_list_t;

typedef struct zfs_hbx_s {
	boolean_t		hb_initialized;
	uint32_t		hb_host_id;
	uint64_t		hb_event_id;

	kmem_cache_t	*hb_wait_hdr;

	kmutex_t 		hb_mutex;
	kcondvar_t 	hb_conv;

	/*door_handle_t	hb_door_hdl;*/

	hbx_link_state_t    link_state;
	hbx_node_state_t major;
	hbx_node_state_t minor;

	kthread_t		*hb_thread;
	kmutex_t		hb_thr_lock;
	kcondvar_t	hb_thr_cv;
	boolean_t		hb_thr_running;
	boolean_t		hb_thr_exit;

	kthread_t		*hb_tx_thread;
	kmutex_t		hb_tx_thr_lock;
	kcondvar_t	hb_tx_thr_cv;
	boolean_t		hb_tx_thr_running;
	boolean_t		hb_tx_thr_exit;

	mod_hash_t 		*hb_modhash;

	taskq_t			*tq_hb_rx_ctrl;
	taskq_t			*tq_hb_rx_reply;
	taskq_t			*tq_hb_rx_data;
	taskq_t			*tq_hb_rx_worker;

	taskq_t			*tq_hb_ck_spa_hung;
	taskq_t			*tq_hb_tx_spa_txg;

	uint64_t		data_index;

	/*zfs_mirror_hb_data_list_t *hb_data_list;*/
} zfs_hbx_t;

typedef enum zfs_hbx_link_evt {
	LINK_UP_TO_DOWN,
	LINK_DOWN_TO_UP
}zfs_hbx_link_evt_t;

typedef void (*zfs_hbx_rx_cb_t)(void *data, uint64_t len);
typedef void (*zfs_hbx_link_evt_cb_t)(zfs_hbx_link_evt_t link_evt);

int zfs_hbx_init(void);
int zfs_hbx_fini(void);

extern void hbx_mac_offline_notify(void *data, uint64_t len);
extern void zfs_notify_clusterd(enum hbx_event_type type, char *data, uint64_t data_len);

#endif /* #ifdef _KERNEL */
#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZFS_HBX_H */
