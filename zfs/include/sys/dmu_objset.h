/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Saso Kiselkov. All rights reserved.
 * Copyright (c) 2012, 2014 by Delphix. All rights reserved.
 * Copyright (c) 2014 Spectra Logic Corporation, All rights reserved.
 */

/* Portions Copyright 2010 Robert Milkowski */

#ifndef	_SYS_DMU_OBJSET_H
#define	_SYS_DMU_OBJSET_H

#include <sys/spa.h>
#include <sys/arc.h>
#include <sys/txg.h>
#include <sys/zfs_context.h>
#include <sys/dnode.h>
#include <sys/zio.h>
#include <sys/zil.h>
#include <sys/sa.h>
#include <sys/zfs_rlock.h>
#include <sys/dbuf.h>
#ifdef _KERNEL
#include <sys/zfs_group_dtl.h>
#endif
#include <sys/lun_migrate.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern krwlock_t os_lock;

struct dsl_pool;
struct dsl_dataset;
struct dmu_tx;
struct dbuf_mirror_io;
struct dmu_buf_impl;

#define	OBJSET_PHYS_SIZE 2048
#define	OBJSET_OLD_PHYS_SIZE 1024

#define	OBJSET_BUF_HAS_USERUSED(buf) \
	(arc_buf_size(buf) > OBJSET_OLD_PHYS_SIZE)

#define	OBJSET_FLAG_USERACCOUNTING_COMPLETE	(1ULL<<0)

#define	OS_WORKER_RUNNING	0x1
#define	OS_WORKER_TERMINATE	0x2

#define	OS_CLEAR_SEGMENTS_GAP	4
#define	OS_WORKER_CACHE_LIST_MAX_LEN	((longlong_t)1 << 30)
#define	OS_WORKER_CACHE_MAX_LEN	((longlong_t)1 << 32)
#define	OS_WORKER_CACHE_LIST_INSERT 0x1
#define	OS_WORKER_CACHE_LIST_NOINSERT 0x1

#define OS_NODE_TYPE_SLAVE		0
#define OS_NODE_TYPE_MASTER		1   /* not used */
#define OS_NODE_TYPE_MASTER2	2
#define OS_NODE_TYPE_MASTER3	3
#define OS_NODE_TYPE_MASTER4	4

typedef struct objset_phys {
	dnode_phys_t os_meta_dnode;
	zil_header_t os_zil_header;
	uint64_t os_type;
	uint64_t os_flags;
	char os_pad[OBJSET_PHYS_SIZE - sizeof (dnode_phys_t)*3 -
	    sizeof (zil_header_t) - sizeof (uint64_t)*2];
	dnode_phys_t os_userused_dnode;
	dnode_phys_t os_groupused_dnode;
	dnode_phys_t os_userobjused_dnode ;
	dnode_phys_t os_groupobjused_dnode ;
} objset_phys_t;

typedef struct os_mirror_blkptr_node {
    uint64_t spa_id;
    uint64_t os_id;
    uint64_t object_id;
    uint64_t blk_id;
    uint64_t offset;
    uint64_t mirror_io_index;
}os_mirror_blkptr_node_t;

typedef struct os_mirror_blkptr_list {
    uint64_t blkptr_num;
    os_mirror_blkptr_node_t *blkptr_array;
}os_mirror_blkptr_list_t;

typedef struct os_seg_worker {
    list_t  worker_list;
    kmutex_t worker_mtx;
    kcondvar_t worker_cv;
    uint64_t worker_data;
    boolean_t clean_all;
    boolean_t seg_clean_all;
    uint64_t clean_size;
    objset_t *worker_os;
    taskq_t *worker_taskq;
    task_func_t *worker_clean;
    void *worker_executor;
}os_seg_worker_t;

#ifdef _KERNEL
typedef int os_replay_data_func(struct objset  *os, char *data,
    uint64_t object, uint64_t offset, uint64_t len);

typedef rl_t *os_seg_data_lock_func(struct objset *os,
    uint64_t object_id, uint64_t offset, uint64_t len, uint8_t type);

typedef void os_seg_data_unlock_func(rl_t *rl);
#endif

typedef struct wrc_blkhdr {
	/*
	 * MAXNAMELEN + strlen(MOS_DIR_NAME) + 1
	 */
	char			ds_name[MAXNAMELEN + 5];
	/*
	 * This count determines the life of the header. Header
	 * is removed from the list when th num_blks reaches
	 * zero.
	 */
	int			num_blks;

	/*
	 * The header is valid if the flag is TRUE. This flag can
	 * help in the delayed freeing of the header.
	 */
	boolean_t		hdr_isvalid;

	/*
	 * All the headers are structured as a linked list and
	 * blocks point to this. This avoids the duplication of
	 * details in each blocks.
	 */
	struct wrc_blkhdr	*prev;
	struct wrc_blkhdr	*next;
} wrc_blkhdr_t;

typedef struct wrc_block {
	wrc_blkhdr_t	*hdr;

	uint64_t		spa_guid;
	uint64_t		objset;	
	uint64_t		object;
	uint64_t		offset;
	uint64_t		size;
	uint64_t		block_size;	/* in bytes. */

	list_node_t		node;
} wrc_block_t;

typedef struct wrc_data {
	kthread_t		*wrc_thread;
	boolean_t		wrc_thr_exit;
	kthread_t		*traverse_thread;
	boolean_t		trav_thr_exit;
	kmutex_t		wrc_lock;
	kcondvar_t		wrc_cv;
	wrc_blkhdr_t	*wrc_blkhdr_head;
	list_t			wrc_blocks;
	uint64_t		wrc_block_count;
	uint64_t		wrc_total_to_migrate; /* bytes */
	uint64_t		wrc_total_migrated;	/* bytes */
	uint64_t		wrc_max_task_queue_depth;
	boolean_t		traverse_finished;
	timestruc_t 	migrate_time;
} wrc_data_t;

struct objset {
	/* Immutable: */
	struct dsl_dataset *os_dsl_dataset;
	spa_t *os_spa;
	arc_buf_t *os_phys_buf;
	objset_phys_t *os_phys;
	/*
	 * The following "special" dnodes have no parent, are exempt
	 * from dnode_move(), and are not recorded in os_dnodes, but they
	 * root their descendents in this objset using handles anyway, so
	 * that all access to dnodes from dbufs consistently uses handles.
	 */
	dnode_handle_t os_meta_dnode;
	dnode_handle_t os_userused_dnode;
	dnode_handle_t os_groupused_dnode;
	dnode_handle_t os_userobjused_dnode ;
	dnode_handle_t os_groupobjused_dnode ;
	zilog_t *os_zil;

	list_node_t os_evicting_node;

	/* can change, under dsl_dir's locks: */
	enum zio_checksum os_checksum;
	enum zio_compress os_compress;
	uint8_t os_copies;
	enum zio_checksum os_dedup_checksum;
	boolean_t os_dedup_verify;
	zfs_logbias_op_t os_logbias;
	zfs_cache_type_t os_primary_cache;
	zfs_cache_type_t os_secondary_cache;
	zfs_sync_type_t os_sync;
	zfs_redundant_metadata_type_t os_redundant_metadata;
	int os_recordsize;
    uint8_t os_woptimize;
    uint8_t os_appmeta;

	/* Lun Migrate */
	uint8_t os_lun_migrate;
	lun_copy_t *os_lun_copy;

	/* no lock needed: */
	struct dmu_tx *os_synctx; /* XXX sketchy */
	blkptr_t *os_rootbp;
	zil_header_t os_zil_header;
	list_t os_synced_dnodes;
	uint64_t os_flags;

	/* Protected by os_obj_lock */
	kmutex_t os_obj_lock;
	uint64_t os_obj_next;

	/* Protected by os_lock */
	kmutex_t os_lock;
	list_t os_dirty_dnodes[TXG_SIZE];
	list_t os_free_dnodes[TXG_SIZE];
	list_t os_dnodes;
	list_t os_downgraded_dbufs;

	/* stuff we store for the user */
	kmutex_t os_user_ptr_lock;
	void *os_user_ptr;
	sa_os_t *os_sa;

	/* destroying when crypto keys aren't present */
	boolean_t os_destroy_nokey;	
	uint64_t	z_aclswitch_obj;
	uint64_t	z_accesslist_obj;
    uint64_t    os_group_obj;

    uint64_t   os_is_group;
    uint64_t   os_is_master;
	/*
	 * os_is_master == 0: os_node_type indicates the node type in the cluster group
	 * os_is_master == 1: os_node_type is ignored
	 */
	uint64_t	os_node_type;	/* OS_NODE_TYPE_XXX */
    uint64_t    os_master_os;
    uint64_t    os_master_spa;
    uint64_t    os_master_root;
    uint64_t    os_self_root;
    uint64_t    os_group_tx_seq;
    char        os_group_name[MAXNAMELEN];

#ifdef _KERNEL
    zil_replay_func_t *os_replay;
    os_replay_data_func *os_replay_data;
    list_t os_zil_list;
    boolean_t os_breplaying;
    os_cache_t *os_cache_all;
    os_seg_worker_t *os_seg_record_worker;
    os_seg_worker_t *os_seg_data_worker;
    os_seg_data_lock_func *os_seg_data_lock;
    os_seg_data_unlock_func *os_seg_data_unlock;

    kmutex_t os_mirror_io_mutex[TXG_SIZE];
    uint64_t os_mirror_io_num[TXG_SIZE];
    list_t os_mirror_io_list[TXG_SIZE];
	zfs_group_dtl_thread_t os_group_dtl_th;
	zfs_group_dtl_thread_t os_group_dtl3_th;
	zfs_group_dtl_thread_t os_group_dtl4_th;
	uint64_t	os_last_master_os;
	uint64_t	os_last_master_spa;
	boolean_t	os_will_be_master;
	wrc_data_t	os_wrc;
#endif
};




#define	DMU_META_OBJSET		0
#define	DMU_META_DNODE_OBJECT	0
#define	DMU_OBJECT_IS_SPECIAL(obj) ((int64_t)(obj) <= 0)
#define	DMU_META_DNODE(os)	((os)->os_meta_dnode.dnh_dnode)
#define	DMU_USERUSED_DNODE(os)	((os)->os_userused_dnode.dnh_dnode)
#define	DMU_USEROBJUSED_DNODE(os) ( (os)->os_userobjused_dnode.dnh_dnode )
#define	DMU_GROUPUSED_DNODE(os)	((os)->os_groupused_dnode.dnh_dnode)
#define	DMU_GROUPOBJUSED_DNODE(os)	((os)->os_groupobjused_dnode.dnh_dnode)

#define	DMU_OS_IS_L2CACHEABLE(os)				\
	((os)->os_secondary_cache == ZFS_CACHE_ALL ||		\
	(os)->os_secondary_cache == ZFS_CACHE_METADATA)

#define	DMU_OS_IS_L2COMPRESSIBLE(os)	(zfs_mdcomp_disable == B_FALSE)

/* called from zpl */
int dmu_objset_hold(const char *name, void *tag, objset_t **osp);
int dmu_objset_own(const char *name, dmu_objset_type_t type,
    boolean_t readonly, void *tag, objset_t **osp);
int dmu_objset_own_obj(struct dsl_pool *dp, uint64_t obj,
    dmu_objset_type_t type, boolean_t readonly, void *tag, objset_t **osp);
void dmu_objset_refresh_ownership(objset_t *os, void *tag);
void dmu_objset_rele(objset_t *os, void *tag);
void dmu_objset_disown(objset_t *os, void *tag);
int dmu_objset_from_ds(struct dsl_dataset *ds, objset_t **osp);

void dmu_objset_stats(objset_t *os, nvlist_t *nv);
void dmu_objset_fast_stat(objset_t *os, dmu_objset_stats_t *stat);
void dmu_objset_space(objset_t *os, uint64_t *refdbytesp, uint64_t *availbytesp,
    uint64_t *usedobjsp, uint64_t *availobjsp);
uint64_t dmu_objset_fsid_guid(objset_t *os);
int dmu_objset_find_dp(struct dsl_pool *dp, uint64_t ddobj,
    int func(struct dsl_pool *, struct dsl_dataset *, void *),
    void *arg, int flags);
void dmu_objset_evict_dbufs(objset_t *os);
timestruc_t dmu_objset_snap_cmtime(objset_t *os);

/* called from dsl */
void dmu_objset_sync(objset_t *os, zio_t *zio, dmu_tx_t *tx);
boolean_t dmu_objset_is_dirty(objset_t *os, uint64_t txg);
objset_t *dmu_objset_create_impl(spa_t *spa, struct dsl_dataset *ds,
    blkptr_t *bp, dmu_objset_type_t type, dmu_tx_t *tx);
int dmu_objset_open_impl(spa_t *spa, struct dsl_dataset *ds, blkptr_t *bp,
    objset_t **osp);
void dmu_objset_evict(objset_t *os);
void dmu_objset_do_userquota_updates(objset_t *os, dmu_tx_t *tx);
void dmu_objset_userquota_get_ids(dnode_t *dn, boolean_t before, dmu_tx_t *tx);
boolean_t dmu_objset_userused_enabled(objset_t *os);
int dmu_objset_userspace_upgrade(objset_t *os);
boolean_t dmu_objset_userspace_present(objset_t *os);
int dmu_fsname(const char *snapname, char *buf);

void dmu_objset_evict_done(objset_t *os);

#ifdef _KERNEL
int objset_notify_system_space(objset_t *os);

void dmu_objset_replay_all_cache(objset_t *os);
void dmu_objset_insert_data(objset_t *os, dmu_buf_impl_t *db,
    struct dbuf_segs_data *seg_data);
void dmu_objset_insert_record(objset_t *os, dmu_buf_impl_t *db);
int dmu_objset_remove_record(objset_t *os, dmu_buf_impl_t *db);
void dmu_objset_wait_clean_all_cache(objset_t *os);
uint64_t dmu_objset_cache_clean_size(objset_t *os, longlong_t size,
    boolean_t clean_all);
uint64_t dmu_objset_get_cache_size(objset_t *os);
uint64_t dmu_objset_woptimizeprop(objset_t *os);
uint64_t dmu_objset_appmetaprop(objset_t *os);
rl_t *dmu_objset_lock_seg_data(objset_t *os, uint64_t object,
    uint64_t offset, uint64_t len, rl_type_t type);
void dmu_objset_unlock_seg_data(objset_t *os, rl_t *rl);
#endif

boolean_t dmu_objset_sync_check(objset_t *os);
void dmu_objset_insert_mirror_io(objset_t *os,
    struct dbuf_mirror_io *mirror_io, uint64_t txg);
os_mirror_blkptr_list_t *dmu_objset_clear_mirror_io(objset_t *os, uint64_t txg);
void dmu_objset_remove_seg_cache(objset_t *os, dmu_buf_impl_t *db);

void dmu_objset_init(void);
void dmu_objset_fini(void);
void dmu_objset_set_group(objset_t *os, uint64_t master_spa, uint64_t master_os, uint64_t root);
uint64_t objset_sec_reftime(objset_t *os);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DMU_OBJSET_H */
