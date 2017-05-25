/*
 * Copyright 2011 Ceresdata, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ZFS_MIRROR_H
#define	_SYS_ZFS_MIRROR_H
//#include <sys/ethernet.h>
//#include <sys/mac_client.h>
#include <sys/arc.h>
#include <sys/zfs_znode.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum zfs_mirror_data_type {
	MIRROR_DATA_ALIGNED,
	MIRROR_DATA_UNALIGNED,
	MIRROR_DATA_META_ALIGNED
} zfs_mirror_data_type_t;

#ifdef _KERNEL
#include <sys/cluster_san.h>

struct dmu_buf_impl;
struct dbuf_mirror_io;

#define	ZFS_MIRROR_DATA							0x01
#define	ZFS_MIRROR_DATA_UNALIGNED				0x02
#define	ZFS_MIRROR_CLEAR_ALIGNED				0x03
#define	ZFS_MIRROR_CLEAR_NONALIGNED				0x04
#define	ZFS_MIRROR_META_DATA					0x05

#define	ZFS_MIRROR_GET_LAST_SYNCED_TXG			0x07
#define	ZFS_MIRROR_REPLY_LAST_SYNCED_TXG		0x08

#define	ZFS_MIRROR_IS_NONALIGNED_ACTIVE			0x09
#define ZFS_MIRROR_REPLY_NONALIGNED_ACTIVE		0x0a

#define	ZFS_MIRROR_SPA_TXG						0x0b
#define	ZFS_MIRROR_SPEED_TEST				0x0c

#define	ZFS_MIRROR_NONALI_DATA_HASH_SIZE	16*1024

#define	ZFS_MIRROR_TIME_MAGNITUDE	1000

typedef struct mirror_cksum {
	uint64_t mc_cksum[2];
} mirror_cksum_t;

typedef struct zfs_mirror_cache_data {
	list_node_t node;
	cs_rx_data_t *cs_data;
}zfs_mirror_cache_data_t;

typedef struct zfs_mirror_msg_header {
	uint32_t msg_type;
	uint8_t pad[4];
}zfs_mirror_msg_header_t;

typedef struct zfs_mirror_msg_mirrordata_header {
	zfs_mirror_msg_header_t msg_head;
	uint64_t spa_id;
	uint64_t os_id;
	uint64_t object_id;
	uint64_t blk_id;
	uint64_t blk_offset;
	uint64_t len;
	uint64_t txg;
	uint64_t index;
	uint64_t tx_time;
}zfs_mirror_msg_mirrordata_header_t;

typedef struct zfs_mirror_msg_clean_header {
	zfs_mirror_msg_header_t msg_head;
	uint64_t spa_id;
	uint64_t os_id;
	uint64_t object_id;
	uint64_t txg;
}zfs_mirror_msg_clean_header_t;

typedef struct mirror_cache_txg_list {
	list_node_t cache_txg_list_node;
	list_node_t cache_time_list_node;
	kmutex_t cache_txg_list_mtx;
	
	uint64_t cache_txg_list_txg;
	uint64_t spa_id;
	uint64_t os_id;
	list_t  cache_txg_list;
	uint64_t active_time;
}mirror_cache_txg_list_t;

typedef struct mirror_cache_spa_list {
	uint64_t spa_id;
	list_t cache_list_txg;/* txg sort */
	list_t cache_list_time;/* time sort */
	list_node_t spa_node;
	kmutex_t mtx;
	uint64_t ref_cnt;
}mirror_cache_spa_list_t;

typedef struct mirror_aligned_cache {
	kmutex_t lock;
	refcount_t refcount;
	list_t aligned_list_txg; /* txg sort */
	list_t aligned_list_time; /* time sort */
}mirror_aligned_cache_t;

typedef struct mirror_unaligned_cache {
	kmutex_t lock;
	refcount_t refcount;
	mod_hash_t *unaligned_modhash;
	list_t unaligned_list_time; /* time sort */
}mirror_unaligned_cache_t;

typedef struct mirror_spa_os {
	list_node_t node;
	uint64_t spa_id;
	uint64_t os_id;
	uint32_t remote_hostid;
	uint32_t pad;
	uint64_t active_time;
	void *parent;
	mirror_aligned_cache_t *aligned_cache;
	mirror_unaligned_cache_t *unaligned_cache;
}mirror_spa_os_t;

typedef struct zfs_mirror_stat {
	kstat_named_t mirror_hostid;

	/* reserved mirror cache stats */
	kstat_named_t	rs_ali_cache_size;
	kstat_named_t rs_nonali_cache_size;
	kstat_named_t rs_nonali_modhash_num;
	
	/* mirror stats */
	kstat_named_t	tx_ali_data_frames;
	kstat_named_t tx_nonali_data_frames;
	
	kstat_named_t tx_ali_clr_frames;
	kstat_named_t tx_nonali_clr_frames;

	kstat_named_t tx_ali_timeout_frames;
	kstat_named_t tx_nonali_timeout_frames;

	kstat_named_t tx_ali_reply_frame;
	kstat_named_t tx_nonali_reply_frame;

	kstat_named_t rx_ali_reply_frames;
	kstat_named_t rx_nonali_reply_frames;

	kstat_named_t rx_ali_data_frames;
	kstat_named_t rx_nonali_data_frames;

	kstat_named_t rx_ali_data_dec_frames;
	kstat_named_t rx_nonali_data_dec_frames;

	kstat_named_t rx_obsolete_frames;

	kstat_named_t rx_add_blk_list;
	kstat_named_t rx_dec_blk_list;
	
	kstat_named_t rx_ali_clr_frames;
	kstat_named_t rx_nonali_clr_frames;

	/* hbx stats */
	kstat_named_t tx_hbx_frames;
	kstat_named_t rx_hbx_frames;
} zfs_mirror_stat_t;

typedef struct zfs_mirror_host_node {
	list_node_t node;
	uint32_t hostid;
	int have_mirror;
	cluster_san_hostinfo_t *cshi;
	nvlist_t *spa_txg_state;
} zfs_mirror_host_node_t;

typedef struct zfs_mirror_mac {
	krwlock_t mirror_host_rwlock;
	list_t mirror_host_lists;
	zfs_mirror_host_node_t *mirror_local_host;
	zfs_mirror_host_node_t *mirror_cur_host;
	zfs_mirror_host_node_t *mirror_failover_host;
	uint32_t mirror_permanent_hostid;

	kmutex_t		spa_os_lock;
	mod_hash_t		*spa_os_modhash;

	kmutex_t mirror_io_list_mtx;
	mod_hash_t		*mirror_io_modhash;
	uint64_t		mirror_io_cnt;
	
	taskq_t *tq_mirror_aligned_handle;
	taskq_t *tq_mirror_nonaligned_handle;
	taskq_t *tq_mirror_reply_frame;

	taskq_t *mirror_log_clean;

	taskq_t *mirror_watch_tq;

	taskq_t *tq_tx_spa_txg;
	taskq_t *tq_check_spa_hung;

	kmem_cache_t *mm_io_hdr;

	uint64_t mm_log_index;

	uint64_t 	rs_nonali_modhash_frames;

	/* reserved in mirror cache list */
	uint64_t	rs_ali_cache_size;
	uint64_t	rs_nonali_cache_size;
	
	/* mirror stats */
	uint64_t	tx_ali_data_frames;
	uint64_t tx_nonali_data_frames;
	
	uint64_t tx_ali_clr_frames;
	uint64_t tx_nonali_clr_frames;

	uint64_t tx_ali_timeout_frames;
	uint64_t tx_nonali_timeout_frames;

	uint64_t tx_ali_reply_frame;
	uint64_t tx_nonali_reply_frame;

	uint64_t rx_ali_reply_frames;
	uint64_t rx_nonali_reply_frames;
	
	uint64_t rx_ali_data_frames;
	uint64_t rx_nonali_data_frames;

	uint64_t rx_ali_data_dec_frames;
	uint64_t rx_nonali_data_dec_frames;

	uint64_t rx_obsolete_frames;

	uint64_t rx_add_blk_list;
	uint64_t rx_dec_blk_list;
	
	uint64_t rx_ali_clr_frames;
	uint64_t rx_nonali_clr_frames;

	/* hbx stats */
	uint64_t tx_hbx_frames;
	uint64_t rx_hbx_frames;

	kstat_t	*mirror_ks;
}zfs_mirror_mac_t;

typedef struct zfs_mirror_nonali_hash{
	uint64_t		spa_id;
	uint64_t		os_id;
	uint64_t		object_id;
	uint64_t		blk_id;
	uint64_t		blk_offset;
	uint64_t		hash_key;

	list_node_t		hash_list_node;
	list_node_t		hash_sort_node;

	list_t			hash_nonali_blk_list;
	uint64_t		active_time;
	int				check_times;
}zfs_mirror_nonali_hash_t;

typedef struct log_clear_para{
	uint64_t spa_id;
	uint64_t os_id;
	uint64_t object_id;
	uint64_t blk_id;
	uint64_t blk_offset;
	uint64_t txg;
	void *para_data;
	zfs_mirror_data_type_t data_type;
} log_clear_para_t;

typedef struct data_replay_para {
	objset_t *os;
	char *data;
	uint64_t object;
	uint64_t offset;
	uint64_t len;
}data_replay_para_t;

typedef struct meta_data_replay_para {
	void	*usr_data;
	char	*data;
	objset_t	*os;
	uint64_t	len;
}meta_data_replay_para_t;

#define	ZFS_MIRROR_NONALI_STATE_NONE		0
#define	ZFS_MIRROR_NONALI_STATE_ACTIVE	1
typedef struct zfs_mirror_unali_state {
	uint64_t spa_id;
	uint64_t os_id;
	uint64_t object_id;
	uint64_t blk_id;
	uint64_t offset;
	uint64_t state;
} zfs_mirror_unali_state_t;

typedef enum zfs_mirror_watchdog_state {
	ZFS_MIRROR_WD_NONE = 0,
	ZFS_MIRROR_WD_ACTIVE,
	ZFS_MIRROR_WD_DEACTIVATE
}zfs_mirror_watchdog_state_t;

typedef struct zfs_mirror_watchdog {
	kthread_t *wd_th;
	kmutex_t wd_mxt;
	kcondvar_t wd_cv;
	zfs_mirror_watchdog_state_t wd_state;
}zfs_mirror_watchdog_t;

typedef struct zfs_mirror_reply_synced_txg {
	uint64_t	spa_guid;
	uint64_t	txg;
}zfs_mirror_reply_synced_txg_t;

typedef enum zfs_mirror_thread_state {
	ZFS_MIRROR_TH_NONE = 0,
	ZFS_MIRROR_TH_ACTIVE,
	ZFS_MIRROR_TH_DEACTIVATE
}zfs_mirror_thread_state_t;

int zfs_mirror_write_data_msg(uint64_t spa_id, uint64_t os_id, uint64_t object_id, 
    uint64_t blk_id, char *data,  uint64_t offset, uint64_t len, uint64_t txg,
    zfs_mirror_data_type_t data_type, struct dbuf_mirror_io *mirror_io);
int zfs_mirror_meta(znode_t *zp, itx_t *itx, dmu_tx_t *tx);
int zfs_mirror_init(uint32_t mirror_hostid);
int zfs_mirror_fini(void);
boolean_t zfs_mirror_enable(void);
boolean_t zfs_mirror_get_state(void);
int zfs_mirror_hold(void);
void zfs_mirror_rele(void);
int zfs_mirror_hold_to_tx(void);
void zfs_mirror_log_clean(objset_t *os, 
    uint64_t spa_id, uint64_t os_id, uint64_t txg,
    uint64_t blk_id, zfs_mirror_data_type_t data_type);
void zfs_mirror_get_all_buf(objset_t *os) ;
struct dbuf_mirror_io  *zfs_mirror_create(void);
void zfs_replay_cache_data(objset_t *os, zfs_mirror_cache_data_t *cache_data);
void zfs_mirror_destroy(struct dbuf_mirror_io  *mirror_io);
uint64_t zfs_mirror_located_keygen(
	uint64_t object_id, uint64_t blk_id, uint64_t offset);

void zfs_mirror_data_expired_switch(boolean_t on_off);

int zfs_mirror_get_updated_spa(uint32_t hostid, nvlist_t **nv_ptr);

#endif
#ifdef	__cplusplus
}
#endif
#endif
