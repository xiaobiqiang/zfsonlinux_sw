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
 * Copyright 2016, Ceres Data, Inc.  All rights reserved.
 */

#ifndef	_SYS_ZFS_GROUP_SYNC_H
#define	_SYS_ZFS_GROUP_SYNC_H

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/vnode.h>

#include <sys/zfs_multiclus.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Callback function for zfs_foreach_dir_entry.
 *
 * IN:
 *   pvp	-	vnode of parent directory
 *   vp		-	the current child directory entry to be processed
 *   args	-	user-passed args for the callback function
 *
 * OUT:
 *   None
 *
 * RETURN:
 *   0 if success and will continue the iteration, error code if
 * failure and will stop the iteration
 */
typedef int (*zfs_dir_entry_func_t)(struct inode * pip, struct inode * ip, void* args);

typedef struct zfs_multiclus_dir_entry
{
	uint64_t obj_id;
//	enum vtype obj_type;
	umode_t mode;
} zfs_multiclus_dirent_t;

int zfs_read_local_dir(struct inode * ip, uint64_t* offset, uint64_t count,
	zfs_multiclus_dirent_t* entry, uint64_t* entry_cnt);

int zfs_remote_lookup(struct inode * pip, char* name, struct inode ** ipp,
	zfs_multiclus_node_type_t node_type);

int zfs_foreach_dir_entry(struct inode * ip, zfs_dir_entry_func_t func, void* args);

int zfs_multiclus_kfcreate(char* file_name, vnode_t** vpp);
int zfs_multiclus_kfwrite(vnode_t* vp, offset_t offset, char* buf, ssize_t buf_size, ssize_t* written);
int zfs_multiclus_kfclose(vnode_t* vp);

extern void* zfs_multiclus_create_group_sync_obj(void);
void zfs_multiclus_destroy_group_sync_obj(void* sync_obj);

int zfs_multiclus_sync_group(char* group_name, char* fs_name, char* output_file, char* dir_path, boolean_t check_only);
int zfs_multiclus_stop_sync(char* group_name, char* fs_name);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ZFS_GROUP_SYNC_H */

