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

#ifndef	_SYS_ZFS_GROUP_SYNC_DATA_H
#define	_SYS_ZFS_GROUP_SYNC_DATA_H

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
extern int zfs_read_local_dir(struct inode * ip, uint64_t* offset, uint64_t count,
	zfs_multiclus_dirent_t* entry, uint64_t* entry_cnt);

extern int zfs_foreach_dir_entry(struct inode * ip, zfs_dir_entry_func_t func, void* args);

extern int zfs_multiclus_kfcreate(char* file_name, vnode_t** vpp);
extern int zfs_multiclus_kfwrite(vnode_t* vp, offset_t offset, char* buf, ssize_t buf_size, ssize_t* written);
extern int zfs_multiclus_kfclose(vnode_t* vp);
extern int	zfs_group_proc_znode(znode_t *zp, znode_operation_t op, void *ptr,	
	cred_t *credp, boolean_t waitting);
int zfs_multiclus_sync_group_data(char* group_name, char* fs_name, char* output_file, char* dir_path, boolean_t check_only, boolean_t all_member_online);


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ZFS_GROUP_SYNC_H */

