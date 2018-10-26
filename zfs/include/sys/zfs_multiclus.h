/*
 * Copyright 2011 Ceresdata, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ZFS_MULTICLUS_H
#define	_SYS_ZFS_MULTICLUS_H

#include <sys/cluster_san.h>
#include <sys/callb.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Use default system priority.
 */
#define	TASKQ_DEFAULTPRI -1

/* MultiCluster Msg Type */
typedef enum zfs_multiclus_data_type {
	ZFS_MULTICLUS_GROUP_MSG = 0x1,
	ZFS_MULTICLUS_GROUP_REPLY,
	ZFS_MULTICLUS_GROUP_CHANGE,
	ZFS_MULTICLUS_OPERATE_MSG,
	ZFS_MULTICLUS_OPERATE_REPLY	,
	ZFS_MULTICLUS_SCAN,
	ZFS_MULTICLUS_STATUS,
	ZFS_MULTICLUS_IOSTAT,
	ZFS_MULTICLUS_SET
} zfs_multiclus_data_type_t;

#ifdef _KERNEL

struct dmu_buf_impl;

/* base microseconds  */
#define	ZFS_MULTICLUS_SECOND	1*1000*1000 /* 1s, base micro sec */
#define	ZFS_MULTICLUS_CVWAIT_TIME	(5*ZFS_MULTICLUS_SECOND)	 /* 5s */
#define	ZFS_MULTICLUS_WAITCOUNT	 (12) /*(60*1000*1000)/ZFS_MULTICLUS_CVWAIT_TIME*/
#define	ZFS_MULTICLUS_OPERATE_TIMEOUT	50*ZFS_MULTICLUS_SECOND /* 60s */
#define	ZFS_MULTICLUS_RX_TIMEOUT		ZFS_MULTICLUS_SECOND /* 1s */
#define	ZFS_MULTICLUS_RX_HASH_CHECK		2*ZFS_MULTICLUS_SECOND /* 2s */

#define	ZFS_MULTICLUS_HOLD_FRAME_HASH_SIZE	64*1024
#define	ZFS_MULTICLUS_TIME_MAGNITUDE	1000

#define	ZFS_MULTICLUS_GROUP_NODE_NUM	32
#define	ZFS_MULTICLUS_GROUP_TABLE_SIZE	64

#define	ZFS_MULTICLUS_RPC_ADDR_SIZE	16

#define ZFS_MULTICLUS_MAX_OS_NUMS \
    (ZFS_MULTICLUS_GROUP_NODE_NUM * ZFS_MULTICLUS_GROUP_TABLE_SIZE)

#define ZFS_MULTICLUS_NVLIST_MAXSIZE 256*1024

typedef enum zfs_multiclus_node_type {
	ZFS_MULTICLUS_SLAVE,
	ZFS_MULTICLUS_MASTER,
	ZFS_MULTICLUS_MASTER2,
	ZFS_MULTICLUS_MASTER3,
	ZFS_MULTICLUS_MASTER4,
	ZFS_MULTICLUS_NODE_TYPE_NUM
}zfs_multiclus_node_type_t;

typedef struct zfs_group_header {
	int64_t	magic;		/* Magic for Shared file system */
	uint64_t	data_index;
	uint64_t	orig_type;
	uint64_t	msg_type;
	uint64_t	op_type;
	uint64_t	wait_flag;	/* Wait/no wait/no thread */
	uint64_t	originator;	/* Server or Client */
	uint64_t	command;	/* Command */
	uint64_t	operation;	/* Command operation */
	uint64_t	length;	/* Length of call message */
	uint64_t	out_length;	/* Length of returned call message */
	uint64_t	seqno;		/* Seqno - identifies client message */
	uint64_t	ack;		/* Message ack - identifies outgoing message */
	uint64_t	error;		/* Error - returned */
	uint64_t	client_spa;	/* Ordinal for shared client */
	uint64_t	client_os;
	uint64_t	client_object;
	uint64_t	server_spa;	/* Ordinal for shared server */
	uint64_t	server_os;
	uint64_t	server_object;
	uint64_t	data_spa;
	uint64_t	data_os;
	uint64_t	data_object;
	uint64_t	master_spa;
	uint64_t	master_os;
	uint64_t	master_object;
	uint64_t	hostid;		/* Client host unique id */
	uint64_t	fsgen;		/* Generation number for this file system */
	uint64_t	reset_seqno;	/* Flag set by clnt for srvr to reset seqno */
	uint64_t	nmsg_data;
	uint64_t	nmsg_len;
	uint64_t	nmsg_header;
	uint64_t	master_gen;
	uint64_t	data2_spa;
	uint64_t	data2_os;
	uint64_t	data2_object;
	uint64_t	master2_spa;
	uint64_t	master2_os;
	uint64_t	master2_object;
	uint64_t	master2_gen;
	uint64_t	master3_spa;
	uint64_t	master3_os;
	uint64_t	master3_object;
	uint64_t	master3_gen;
	uint64_t	master4_spa;
	uint64_t	master4_os;
	uint64_t	master4_object;
	uint64_t	master4_gen;
	zfs_multiclus_node_type_t			m_node_type;
	uint8_t		group_name[MAXNAMELEN];
	uint64_t	group_name_len;
	void *work_para;
	cs_rx_data_t *cs_data;
} zfs_group_header_t;

typedef enum status_type {
	ZFS_MULTICLUS_NODE_OFFLINE,
	ZFS_MULTICLUS_NODE_CHECKING,
	ZFS_MULTICLUS_NODE_ONLINE,
	ZFS_MULTICLUS_NODE_STATUS_MAX
}status_type_t;

typedef struct node_status{
	status_type_t status;
	uint64_t last_update_time;
}node_status_t;

typedef enum start_reg_types {
	EXCEPT_SOMEONE = 1,
	WAKEUP_SOMEONE,
	START_REG_TYPES
}start_reg_types_t;

typedef struct zfs_multiclus_group_record {
	uint8_t	resv[4];
	uint64_t spa_id;
	uint64_t os_id;
	uint64_t hostid;
	zfs_multiclus_node_type_t node_type;
	boolean_t used;
	uint64_t avail_size;
	uint64_t used_size;
	uint64_t load_ios;
	uint64_t root;
	uint64_t txg;
	uint8_t	rpc_addr[ZFS_MULTICLUS_RPC_ADDR_SIZE];
	uint8_t fsname[MAX_FSNAME_LEN];
	node_status_t node_status;
} zfs_multiclus_group_record_t;

typedef struct zfs_multiclus_register {
	kcondvar_t reg_timer_cv;
	kmutex_t reg_timer_lock;
	boolean_t used;
	uint64_t spa_id;
	uint64_t os_id;
} zfs_multiclus_register_t;

typedef struct zfs_multiclus_group {
	zfs_multiclus_group_record_t	multiclus_group[ZFS_MULTICLUS_GROUP_NODE_NUM];
	kmutex_t	multiclus_group_mutex;
	kcondvar_t	multiclus_group_cv;
	uint64_t	group_name_len;
	char	group_name[MAXNAMELEN];
	boolean_t	used;
	zfs_multiclus_register_t	multiclus_reg[ZFS_MULTICLUS_GROUP_NODE_NUM];
	taskq_t *group_reg_timer_tq;
} zfs_multiclus_group_t;

typedef struct zfs_multiclus_worker {
	avl_tree_t	worker_avl;
	list_t	worker_para_list;
	kmutex_t	worker_lock;
	kmutex_t	worker_avl_lock;
	kcondvar_t	worker_cv;
	uint32_t	worker_flags;
	uint32_t	worker_ntasks;
	taskq_t	*worker_taskq;
} zfs_multiclus_worker_t;

typedef struct zfs_multiclus_rx_workers{
	zfs_multiclus_worker_t	*zfs_multiclus_rx_worker_nodes;
	taskq_t	*zfs_multiclus_rx_worker_taskq;
	uint32_t	zfs_multiclus_rx_running_workers;
}zfs_multiclus_rx_workers_t;

typedef struct zfs_multiclus_action_workers{
	zfs_multiclus_worker_t	*zfs_multiclus_action_worker_nodes;
	taskq_t	*zfs_multiclus_action_worker_taskq;
	uint32_t	zfs_multiclus_action_running_workers;
}zfs_multiclus_action_workers_t;

typedef struct zfs_multiclus_workers {
	zfs_multiclus_rx_workers_t	zfs_multiclus_rx_workers;
	zfs_multiclus_action_workers_t	zfs_multiclus_action_workers;
	taskq_t	*zfs_multiclus_rx_post_tq;
	taskq_t	*zfs_multiclus_action_post_tq;
	kmutex_t	mm_mutex;
	uint64_t	mm_log_index;
	boolean_t	b_initialized;
}zfs_multiclus_workers_t;


typedef void	*timeout_id_t;	/* opaque handle from timeout(9F) */

typedef struct zfs_multiclus_hash_header{
	mod_hash_t	*zfs_multiclus_modhash;
	timeout_id_t	zfs_multiclus_timeout;
	krwlock_t	zfs_multiclus_timeout_lock;
	kthread_t	*hash_tmchk_thread;
	kmutex_t	hash_tmchk_thr_lock;
	kcondvar_t	hash_tmchk_thr_cv;
	boolean_t	hash_tmchk_thr_running;
	boolean_t	hash_tmchk_thr_exit;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint8_t	used;
}zfs_multiclus_hash_header_t;

typedef struct zfs_multiclus_hash{
	list_node_t	hash_list_node;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	hash_key;
	uint32_t	tx_msg;
	uint32_t	tx_no_rx;
	uint32_t	rx_done;
	uint32_t	rx_timeout;
	krwlock_t	rx_timeout_lock;
	boolean_t	rx_flag;
	uint64_t	multiclus_segments;
	kcondvar_t	multiclus_hash_cv;
	kmutex_t	multiclus_hash_mutex;
	uint64_t	cache_num;
	uint64_t	data_len;
	uint64_t	start_time;
	uint64_t	post_time;
	uint64_t	despatch_time;
	uint64_t	server_action_time;
	char	*omsg_header;
	char	*datap;
}zfs_multiclus_hash_t;

typedef enum zfs_migrate_type {
	ZFS_MIGRATE_START,
	ZFS_MIGRATE_STOP,
	ZFS_MIGRATE_INSERT,
	ZFS_MIGRATE_TRAVESE_FINISHED,
	ZFS_MIGRATE_MIXED
} zfs_migrate_type;

typedef struct migrate_obj {
	uint64_t object;
	uint64_t file_length;
	uint64_t block_size;
} migrate_obj_t;

typedef struct zfs_migrate_cmd {
	uint8_t fsname[MAX_FSNAME_LEN];
	zfs_migrate_type cmd_type;
	uint64_t data_spa;
	uint64_t data_os;
	uint64_t obj_count;
	migrate_obj_t mobj[50];
} zfs_migrate_cmd_t;

#define	ZFS_MULTICLUS_WORKER_TERMINATE	0x01
#define	ZFS_MULTICLUS_WORKER_STARTED	0x02
#define	ZFS_MULTICLUS_WORKER_ACTIVE	0x04

extern int zfs_multiclus_init(void);
extern void zfs_multiclus_fini(void);
extern boolean_t zfs_multiclus_enable(void);
extern boolean_t zfs_multiclus_done(void);
int zfs_get_group_state(nvlist_t **config, uint64_t *num_group, 
	uint64_t * breakmark, boolean_t *onceflag);
int zfs_get_group_znode_info(char *path, nvlist_t **config);
int zfs_get_group_name(char *poolname, nvlist_t **rmconfig);
int zfs_get_group_ip(nvlist_t **config);
int zfs_get_master_ip(char *fsname, nvlist_t **config);
int zfs_multiclus_update_record(char *group_name, objset_t *os);
int zfs_multiclus_create_group(char *group_name, char *fs_name);
int zfs_multiclus_add_group(char *group_name, char *fs_name);
int zfs_multiclus_set_slave(char* group_name, char* fs_name);
int zfs_multiclus_set_master(char* group_name, char* fs_name, 
	zfs_multiclus_node_type_t node_type);
void zfs_multiclus_group_record_init(char *group_name,  char *fs_name, uint64_t spa_id,
	uint64_t os_id, uint64_t root_id, zfs_multiclus_node_type_t node_type, uint64_t avail_size, 
	uint64_t used_size, uint64_t load_ios);
int zfs_multiclus_write_operate_msg(objset_t *os, zfs_group_header_t *msg_header, void *msg_data, uint64_t data_len);
int zfs_multiclus_write_group_record(void *reg_msg, zfs_multiclus_data_type_t data_type, 
	zfs_multiclus_node_type_t node_type);
int zfs_multiclus_get_group(char *group_name, zfs_multiclus_group_t **group);
zfs_multiclus_group_t * 
zfs_multiclus_get_current_group( uint64_t spaid );
int zfs_multiclus_get_fsname(uint64_t spa_guid, uint64_t objset, char *fsname);
zfs_multiclus_group_record_t * zfs_multiclus_get_record(uint64_t spa_id, uint64_t os_id);
void zfs_multiclus_destroy_reg_record(char *group_name, uint64_t spa_id, uint64_t os_id);
zfs_multiclus_group_record_t *zfs_multiclus_get_group_master(char *group_name, zfs_multiclus_node_type_t type);
zfs_multiclus_node_type_t zmc_get_node_type(objset_t* os);
int zfs_multiclus_get_group_record_num(char *group_name, uint64_t group_name_len);
int zfs_multiclus_get_info_from_group(zfs_migrate_cmd_t *zmc, char *gname, int num_zmc);
#endif
#ifdef	__cplusplus
}
#endif
#endif
