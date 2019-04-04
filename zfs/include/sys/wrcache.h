/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_SYS_WRCACHE_H
#define	_SYS_WRCACHE_H

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/fs/zfs.h>
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_dataset.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_group.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * write cache special class.
 */

#define	WRCIO_PERC_MIN	(25)
#define	WRCIO_PERC_MAX	(75)


/*
 * This is the header for each wrc_block_t structure.
 * This stores only the dataset name for now, but can
 * store more details needed for blocks in future.
 * This is in place for avoiding the duplication of
 * dataset details like name in all the block structures.
 */
//typedef struct wrc_blkhdr {
	/*
	 * MAXNAMELEN + strlen(MOS_DIR_NAME) + 1
	 */
	//char			ds_name[MAXNAMELEN + 5];
	/*
	 * This count determines the life of the header. Header
	 * is removed from the list when th num_blks reaches
	 * zero.
	 */
	//int			num_blks;

	/*
	 * The header is valid if the flag is TRUE. This flag can
	 * help in the delayed freeing of the header.
	 */
	//boolean_t		hdr_isvalid;

	/*
	 * All the headers are structured as a linked list and
	 * blocks point to this. This avoids the duplication of
	 * details in each blocks.
	 */
	//struct wrc_blkhdr	*prev;
	//struct wrc_blkhdr	*next;
//} wrc_blkhdr_t;

//typedef struct wrc_block {
	//wrc_blkhdr_t	*hdr;

	//uint64_t		spa_guid;
	//uint64_t		objset;	
	//uint64_t		object;
	//uint64_t		offset;
	//uint64_t		size;
	//uint64_t		block_size;	/* in bytes. */

	//list_node_t		node;
//} wrc_block_t;

//typedef struct wrc_data {
	//kthread_t		*wrc_thread;
	//boolean_t		wrc_thr_exit;
	//kthread_t		*traverse_thread;
	//boolean_t		trav_thr_exit;
	//kmutex_t		wrc_lock;
	//kcondvar_t		wrc_cv;
	//wrc_blkhdr_t	*wrc_blkhdr_head;
	//list_t			wrc_blocks;
	//uint64_t		wrc_block_count;
	//uint64_t		wrc_total_to_migrate; /* bytes */
	//uint64_t		wrc_total_migrated;	/* bytes */
	//uint64_t		wrc_max_task_queue_depth;
	//boolean_t		traverse_finished;
//} wrc_data_t;

typedef struct wrc_status {
	kmutex_t	status_lock;
	uint64_t		spa_total_to_migrate; /* bytes */
	uint64_t		spa_total_migrated;	/* bytes */
} wrc_status_t;

typedef struct wrc_migrate_param {
	objset_t *os;
	uint64_t flags;
	uint64_t obj;
} wrc_migrate_param_t;

//#define	WRC_START_MIGRATE  0x1
//#define	WRC_STOP_MIGRATE  0x2
//#define	WRC_STATUS_MIGRATE  0x4
//#define	WRC_START_ALL  0x8

#define	WRC_BLK_DSNAME(block)	(block->hdr->ds_name)
#define	WRC_BLK_ADDCOUNT(block)	(block->hdr->num_blks++)
#define	WRC_BLK_DECCOUNT(block)	(block->hdr->num_blks--)

/*
 * write cache thread.
 */
void start_wrc_thread(objset_t *os, uint64_t flags, uint64_t obj);
boolean_t stop_wrc_thread(objset_t *os);
void wrc_insert_block(objset_t *os, uint64_t objset, uint64_t object, uint64_t file_length, uint64_t block_size);
void travese_migrate_dir(objset_t *os, uint64_t dir_obj);
void start_travese_migrate_thread(char *fsname, uint64_t flags, uint64_t start_obj, msg_orig_type_t cmd_type);
void stop_travese_migrate_thread(char *fsname, msg_orig_type_t cmd_type);
int migrate_insert_block(zfs_migrate_cmd_t *migrate_cmd);
void status_travese_migrate_thread(char *fsname, char *state, uint64_t *total_to_migrate, uint64_t *total_migrated);
void travese_finished(char *fsname, msg_orig_type_t cmd_type);
#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_WRCACHE_H */
