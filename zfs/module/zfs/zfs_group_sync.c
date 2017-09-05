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

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/varargs.h>
#include <sys/cmn_err.h>

#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/zfs_ctldir.h>
#include <sys/zap.h>
#include <sys/zfs_vnops.h>
#include <sys/cred.h>
#include <sys/fcntl.h>
#include <linux/cred.h>

#include <sys/zfs_group.h>
#include <sys/zfs_group_sync.h>

#define ZMC_SYNC_MAX_ENTRY								(256)

#define ZMC_SYNC_LOG_BUF_SIZE							(1024)

#define ZMC_SYNC_SYNC_MASTER							(0x00000001)
#define ZMC_SYNC_SYNC_MASTER2							(0x00000002)
#define ZMC_SYNC_SYNC_MASTER3							(0x00000004)
#define ZMC_SYNC_SYNC_MASTER4							(0x00000008)

#define ZMC_SYNC_DIFF_NONE								0
#define ZMC_SYNC_DIFF_TYPE								1
#define ZMC_SYNC_DIFF_SIZE								2
#define ZMC_SYNC_DIFF_DATA_OBJ							3
#define ZMC_SYNC_DIFF_MASTER_OBJ						4

kmutex_t tod_lock;	/* protects time-of-day stuff */
todinfo_t saved_tod;
int saved_utc = -60;

typedef struct zmc_sync_object
{
	kmutex_t lock;
	kthread_t* thread;
	boolean_t thread_exit;

	vnode_t* kf_vp;
	offset_t kf_fpos;
	char buf[ZMC_SYNC_LOG_BUF_SIZE];
} zmc_sync_obj_t;

typedef struct zmc_sync_thread_arg
{
	char group_name[MAXNAMELEN];
	char fs_name[MAXNAMELEN];
	char output_file[MAXNAMELEN];
	char dir_path[MAXNAMELEN];
	boolean_t check_only;
} zmc_sync_thread_arg_t;

void zmc_sync_worker_thread(zmc_sync_thread_arg_t* arg);

void zmc_sync_log(zmc_sync_obj_t* sync_obj, const char* fmt, ...);

int zmc_check_group(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path);
int zmc_check_group_master(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path);

int zmc_sync_group(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path);
int zmc_sync_group_master(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path);

int zmc_check_master_dir_entry(struct inode * pip, struct inode * ip, void* args);
int zmc_check_master_dir(struct inode * pip, struct inode * ip);
int zmc_check_master_file(struct inode * pip, struct inode * ip);
int zmc_check_master_symlink(struct inode * pip, struct inode * ip);
int zmc_do_check_master_dir(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);
int zmc_do_check_master_file(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);
int zmc_do_check_master_symlink(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);

int zmc_sync_master_dir_entry(struct inode * pip, struct inode * ip, void* args);
int zmc_sync_master_dir(struct inode * pip, struct inode * ip, int flag);
int zmc_sync_master_file(struct inode * pip, struct inode * ip, int flag);
int zmc_sync_master_symlink(struct inode * pip, struct inode * ip, int flag);
int zmc_do_sync_master_dir(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);
int zmc_do_sync_master_file(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);
int zmc_do_sync_master_symlink(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);

int zmc_remote_create_entry(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);
int zmc_remote_remove_entry(struct inode * pip, struct inode * rip, zfs_multiclus_node_type_t node_type);
int zmc_remote_create_dir(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);
int zmc_remote_remove_dir(struct inode * pip, struct inode * rip, zfs_multiclus_node_type_t node_type);
int zmc_remote_create_file(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);
int zmc_remote_remove_file(struct inode * pip, struct inode * rip, zfs_multiclus_node_type_t node_type);
int zmc_remote_create_symlink(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);
int zmc_remote_remove_symlink(struct inode * pip, struct inode * rip, zfs_multiclus_node_type_t node_type);

/*
 * Read directory entries into the provided buffer from the given
 * directory cursor position.
 *
 * IN:
 *   vp			-	vnode of directory to read.
 *   offset		-	start position in the directory to read
 *   count		-	how many directory entries to read
 *
 * OUT:
 *   offset		-	end position in the directory after reading
 *   entry		-	buffer to hold returned entries, must be enough to
 *                  hold as many as count entries
 *   entry_cnt	-	the actual entry count in entry
 *
 * RETURN:
 *   0 if success, error code if failure
 */
int zfs_read_local_dir(struct inode * ip, uint64_t* offset, uint64_t count,
	zfs_multiclus_dirent_t* entry, uint64_t* entry_cnt)
{
	zap_cursor_t zc = { 0 };
	zap_attribute_t zap = { 0 };
	znode_t* zp = NULL;
	znode_t* obj = NULL;
	uint64_t index = 0;
	int error = 0;

	if (ip == NULL || offset == NULL || entry == NULL || entry_cnt == NULL) {
		return EINVAL;
	}

//	if (vp->v_type != VDIR) {
	if ((ip->i_mode & S_IFMT) != S_IFDIR) {
		return EINVAL;
	}

	zp = ITOZ(ip);
	*entry_cnt = 0;

	ZFS_ENTER(zp->z_zsb);
	ZFS_VERIFY_ZP(zp);

	if (zp->z_unlinked != 0) {
		ZFS_EXIT(zp->z_zsb);
		return 0;
	}

	zap_cursor_init_serialized(&zc, zp->z_zsb->z_os, zp->z_id, *offset);

	while (index < count) {
		error = zap_cursor_retrieve(&zc, &zap);
		if (error != 0) {
			if (error == ENOENT) {
				error = 0;
			}

			break;
		}

		if (zap.za_integer_length != 8 || zap.za_num_integers != 1) {
			error = ENXIO;
			break;
		}

		entry[index].obj_id = ZFS_DIRENT_OBJ(zap.za_first_integer);
/*
		if (zfs_zget(zp->z_zfsvfs, entry[index].obj_id, &obj) == 0) {
			entry[index].obj_type = ZTOV(obj)-> v_type;
			VN_RELE(ZTOV(obj));
		} else {
			entry[index].obj_type = VNON;
		}
*/
		if (zfs_zget(zp->z_zsb, entry[index].obj_id, &obj) == 0) {
			entry[index].mode = (ZTOI(obj)->i_mode) & S_IFMT;
			iput(ZTOI(obj));
		} else {
//			entry[index].obj_type = VNON;
			entry[index].mode = 0;
		}
		++index;

		zap_cursor_advance(&zc);
	}

	*offset = zap_cursor_serialize(&zc);

	zap_cursor_fini(&zc);

	ZFS_EXIT(zp->z_zsb);

	*entry_cnt = index;

	return error;
}

static void zmc_build_msg_header(objset_t *os, zfs_group_header_t *hdr,
	uint64_t cmd, share_flag_t wait_flag, uint64_t op, uint64_t length,
	uint64_t out_length, uint64_t server_spa, uint64_t server_os,
	uint64_t server_object, uint64_t master_object, uint64_t data_spa,
	uint64_t data_os, uint64_t data_object, msg_op_type_t op_type,
	msg_orig_type_t orig_type)
{
	hdr->magic = ZFS_GROUP_MAGIC;
	hdr->msg_type = op_type;
	hdr->orig_type = orig_type;
	hdr->wait_flag = (ushort_t)wait_flag;
	hdr->command = cmd;
	hdr->operation = op;
	hdr->length = length;
	hdr->out_length = out_length;
	hdr->error = 0;

	hdr->master_object = master_object;

	hdr->client_os = dmu_objset_id(os);
	hdr->client_spa = spa_guid(dmu_objset_spa(os));
	hdr->client_object = master_object;

	hdr->server_spa = server_spa;
	hdr->server_os = server_os;
	hdr->server_object = server_object;

	hdr->data_spa = data_spa;
	hdr->data_os = data_os;
	hdr->data_object = data_object;
	hdr->reset_seqno = 0;

	return;
}

int zmc_do_remote_lookup(struct inode * pip, char* name, struct inode ** ipp,
	uint64_t dst_spa, uint64_t dst_os, uint64_t dst_obj)
{
	znode_t* pzp = ITOZ(pip);
	znode_t* zp = NULL;
	zfs_group_name_msg_t *msg = NULL;
	zfs_group_header_t *msg_header = NULL;
	zfs_group_name_t *send_info = NULL;
	zfs_group_name2_t *reply_info = NULL;
	unsigned int buf_len = 0;
	int error = 0;

	msg = kmem_zalloc(sizeof(zfs_group_name_msg_t), KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	send_info = &(msg->call.name);

	send_info->parent_object = pzp->z_group_id;

	/*
	 * in server, it will extract the znode via
	 * this 'parent_object.master_object' field
	 */
	send_info->parent_object.master_object = dst_obj;

	bzero(&(send_info->arg), sizeof(zfs_group_name_arg_t));
	send_info->flags = 0;
	zfs_group_set_cred(kcred, &(send_info->cred));
	buf_len = ZFS_GROUP_MAX_NAME_LEN - offsetof(zfs_group_name_t, component);
	strncpy(send_info->component, name, buf_len);
	send_info->component[buf_len - 1] = 0;

	zmc_build_msg_header(pzp->z_zsb->z_os, msg_header, ZFS_GROUP_CMD_NAME,
		SHARE_WAIT, NAME_LOOKUP, sizeof(zfs_group_name_msg_t), sizeof(zfs_group_name2_t),
		dst_spa, dst_os, dst_obj, 0, 0, 0, 0, MSG_REQUEST, APP_USER);

	error = zfs_client_send_to_server(pzp->z_zsb->z_os, msg_header, (zfs_msg_t*)msg, B_TRUE);
	if (error == 0) {
		reply_info = &(msg->call.name2);

		zp = zfs_znode_alloc_by_group(pzp->z_zsb, reply_info->nrec.object_blksz,
				&(reply_info->nrec.object_id), &(reply_info->nrec.object_phy));
		strncpy(zp->z_filename, name, MAXNAMELEN);
		zp->z_filename[MAXNAMELEN - 1] = 0;

		*ipp = ZTOI(zp);
	}

	kmem_free(msg, sizeof(zfs_group_name_msg_t));
	kmem_free(msg_header, sizeof(zfs_group_header_t));

	return error;
}

/*
 * Lookup an entry in a directory, on remote server.
 * If it exists, return a held vnode reference for it.
 *
 * IN:
 *   pvp		-	vnode of parent directory to search.
 *   name		-	name of entry to lookup.
 *   node_type	-	target remote server
 *
 * OUT:
 *   vpp		-	vnode of located entry, NULL if not found.
 *
 * RETURN:
 *   0 if success (*vpp == NULL, if the target entry is not
 * existed), error code if failure
 */
int zfs_remote_lookup(struct inode * pip, char* name, struct inode ** ipp, zfs_multiclus_node_type_t node_type)
{
	znode_t* pzp = NULL;
	zfs_multiclus_group_record_t* record = NULL;
	uint64_t dst_spa = (uint64_t)-1;
	uint64_t dst_os = (uint64_t)-1;
	uint64_t dst_obj = (uint64_t)-1;
	int error = 0;

	if (pip == NULL || name == NULL || ipp == NULL) {
		return EINVAL;
	}

	if ((pip->i_mode & S_IFMT) == S_IFDIR){
		return EINVAL;
	}

	if (name[0] == 0 || strcmp(name, ".") == 0 || strcmp(name, "..") == 0
		|| strcmp(name, ZFS_CTLDIR_NAME) == 0) {
		return ENOTSUP;
	}

	pzp = ITOZ(pip);

	switch (node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			dst_spa = pzp->z_group_id.master2_spa;
			dst_os = pzp->z_group_id.master2_objset;
			dst_obj = pzp->z_group_id.master2_object;
			break;

		case ZFS_MULTICLUS_MASTER3:
			dst_spa = pzp->z_group_id.master3_spa;
			dst_os = pzp->z_group_id.master3_objset;
			dst_obj = pzp->z_group_id.master3_object;
			break;

		case ZFS_MULTICLUS_MASTER4:
			dst_spa = pzp->z_group_id.master4_spa;
			dst_os = pzp->z_group_id.master4_objset;
			dst_obj = pzp->z_group_id.master4_object;
			break;

		case ZFS_MULTICLUS_MASTER:
		case ZFS_MULTICLUS_SLAVE:
		default:
			/* not support yet */
			dst_spa = -1;
			dst_os = -1;
			dst_obj = -1;
			break;
	}

	if (dst_spa == 0 || dst_os == 0 || dst_obj == 0) {
		/*
		 * root node
		 */
		record = zfs_multiclus_get_group_master(pzp->z_zsb->z_os->os_group_name, node_type);
		if (record != NULL) {
			dst_spa = record->spa_id;
			dst_os = record->os_id;
			dst_obj = record->root;
		}
	}

	if (dst_spa == 0 || dst_os == 0 || dst_obj == 0
		|| dst_spa == -1 || dst_os == -1 || dst_obj == -1) {
		/* TODO: find a better return value */
		return ENXIO;
	}

	record = zfs_multiclus_get_record(dst_spa, dst_os);
	if (record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
		return ENOENT;
	}

	error = zmc_do_remote_lookup(pip, name, ipp, dst_spa, dst_os, dst_obj);
	if (error != 0) {
		*ipp = NULL;
	}

	if (error == ENOENT) {
		/*
		 * error = 0, *vpp = NULL:
		 * the target file/dir is not existed
		 */
		error = 0;
	}

	return error;
}

/*
 * Iterate each entry in a directory, and process it with the
 * specified callback function.
 *
 * IN:
 *   vp		-	vnode of directory to iterate
 *   func	-	callback function to process each entry,
 *				return 0 to continue the iteration, others
 *				to stop the iteration and will be returned
 *				as the error code
 *   args	-	args for callback function
 *
 * OUT:
 *   None
 *
 * RETURN:
 *   0 if success, error code if failure
 */
//int zfs_foreach_dir_entry(vnode_t* vp, zfs_dir_entry_func_t func, void* args)
int zfs_foreach_dir_entry(struct inode * ip, zfs_dir_entry_func_t func, void* args)
{
	znode_t* zp = NULL;
	znode_t* czp = NULL; /* children znode */
	zfs_multiclus_dirent_t* entry = NULL;
	uint64_t offset = 0;
	uint64_t count = 0;
	uint64_t index = 0;
	int error = 0;

	if (ip == NULL || (ip->i_mode & S_IFMT) != S_IFDIR || func == NULL) {
		return EINVAL;
	}

	zp = ITOZ(ip);

	entry = kmem_zalloc(sizeof(zfs_multiclus_dirent_t) * ZMC_SYNC_MAX_ENTRY, KM_SLEEP);

	offset = 0;
	while (TRUE) {
		error = zfs_read_local_dir(ip, &offset, ZMC_SYNC_MAX_ENTRY, entry, &count);
		if (error != 0) {
			break;
		}

		for (index = 0; index < count; ++index) {
			if (zfs_zget(zp->z_zsb, entry[index].obj_id, &czp) != 0) {
				continue;
			}

			/* process the entry */
			error = (*func)(ip, ZTOI(czp), args);
			iput(ZTOI(czp));

			if (error != 0) {
				break;
			}
		}
		if (index != count) {
			/* failed to process the entry */
			break;
		}

		if (count < ZMC_SYNC_MAX_ENTRY) {
			break; /* done */
		}
	}

	kmem_free(entry, sizeof(zfs_multiclus_dirent_t) * ZMC_SYNC_MAX_ENTRY);

	return error;
}

/*
 * Create or open a file.
 *
 * IN:
 *	 file_name	-	file name
 *
 * OUT:
 *	 vpp		-	vnode pointer for created/opened file
 *
 * RETURN:
 *	 0 if success, error code if failure
 */
int zfs_multiclus_kfcreate(char* file_name, vnode_t** vpp)
{
	if (file_name == NULL || file_name[0] == 0 || vpp == NULL) {
		return EINVAL;
	}

	/* 0666: read/write permission for everyone */
	return vn_open(file_name, UIO_SYSSPACE, FCREAT | FWRITE | FTRUNC, 0666, vpp, CRCREAT, 0);
}

/*
 * Write file.
 *
 * IN:
 *	 vp			-	vnode returned by zfs_multiclus_kfcreate
 *   offset		-	file offset to start write
 *   buf		-	buffer to write
 *   buf_size	-	buffer size
 *
 * OUT:
 *	 writen		-	how many data has been written, in bytes
 *
 * RETURN:
 *	 0 if success, error code if failure
 */
int zfs_multiclus_kfwrite(vnode_t* vp, offset_t offset, char* buf, ssize_t buf_size, ssize_t* written)
{
	int err = 0;
	ssize_t len = 0;
	ssize_t resid = 0;
	ssize_t wrt_cnt = 0;

	if (vp == NULL || written == NULL) {
		return EINVAL;
	}

	*written = 0;

	if (buf == NULL || buf_size == 0) {
		return 0;
	}

	len = buf_size;
	for (; ;) {
		err = vn_rdwr(UIO_WRITE, vp, buf, len, offset, UIO_SYSSPACE, FSYNC, RLIM64_INFINITY, CRED(), &resid);
		if (err != 0) {
			break;
		}

		wrt_cnt += (len - resid);

		if (resid == 0) {
			break; /* done */
		}

		if (resid == len) {
			err = ENOSPC;
			break;
		}

		buf += (len - resid);
		offset += (len - resid);

		len = resid;
	}

	*written = wrt_cnt;

	return err;
}

/*
 * Close file.
 *
 * IN:
 *	 vp		-	vnode returned by zfs_multiclus_kfcreate
 *
 * OUT:
 *   None
 *
 * RETURN:
 *	 0 if success, error code if failure
 */
int zfs_multiclus_kfclose(vnode_t* vp)
{
	int rval = 0;

	if (vp == NULL) {  
		return 0;
	}

	rval = VOP_FSYNC(vp, FSYNC, CRED(), NULL);
	if (rval != 0) {
		cmn_err(CE_WARN, "%s %d: fsync fail, error = %d.", __func__, __LINE__, rval);
	}

	rval = VOP_CLOSE(vp, FCREAT | FWRITE | FTRUNC, 1, (offset_t)0, CRED(), NULL);
//	VN_RELE(vp);
	return rval;
}

void* zfs_multiclus_create_group_sync_obj(void)
{
	zmc_sync_obj_t* obj = NULL;

	obj = kmem_zalloc(sizeof(zmc_sync_obj_t), KM_SLEEP);

	obj->thread = NULL;
	obj->thread_exit = B_FALSE;
	mutex_init(&(obj->lock), NULL, MUTEX_DEFAULT, NULL);

	obj->kf_vp = NULL;
	obj->kf_fpos = 0;

	return (void*)obj;
}

void zfs_multiclus_destroy_group_sync_obj(void* sync_obj)
{
	zmc_sync_obj_t* obj = (zmc_sync_obj_t*)sync_obj;
//	kt_did_t thread_id = 0;
	kthread_t *sync_thread = NULL;

	if (obj == NULL) {
		return;
	}

	mutex_enter(&(obj->lock));
	if (obj->thread != NULL) {

//		thread_id = obj->thread->t_did;
		sync_thread = obj->thread;
		/* inform worker thread to exit */
		obj->thread_exit = B_TRUE;
	}
	mutex_exit(&(obj->lock));

//	if (thread_id != 0) {
//		thread_join(thread_id);
//	}
	kthread_stop(sync_thread);

	mutex_destroy(&(obj->lock));
	kmem_free(obj, sizeof(zmc_sync_obj_t));
	return;
}

int zfs_multiclus_sync_group(char* group_name, char* fs_name, char* output_file, 
	char* dir_path, boolean_t check_only)
{
	zfs_multiclus_group_t* group = NULL;
	objset_t* os = NULL;
	zfs_sb_t * zsb = NULL;
	zmc_sync_obj_t* sync_obj = NULL;
	zmc_sync_thread_arg_t* arg = NULL;

	if (group_name == NULL || fs_name == NULL || output_file == NULL) {
		return EINVAL;
	}

	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "multicluster is disabled.");
		return -1;
	}

	zfs_multiclus_get_group(group_name, &group);
	if (group == NULL) {
		cmn_err(CE_WARN, "failed to get group %s.", group_name);
		return EINVAL;
	}

	if (dmu_objset_hold(fs_name, FTAG, &os) != 0) {
		cmn_err(CE_WARN, "failed to get fs %s.", fs_name);
		return EINVAL;
	}

	if (os->os_phys->os_type != DMU_OST_ZFS || os->os_is_group == 0) {
		cmn_err(CE_WARN, "fs %s is invalid.", fs_name);
		dmu_objset_rele(os, FTAG);

		return EINVAL;
	}

	mutex_enter(&os->os_user_ptr_lock);
	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	mutex_exit(&os->os_user_ptr_lock);

	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);
	if (sync_obj == NULL) {
		dmu_objset_rele(os, FTAG);
		return EINVAL;
	}

	arg = kmem_zalloc(sizeof(zmc_sync_thread_arg_t), KM_SLEEP);

	strncpy(arg->group_name, group_name, MAXNAMELEN);
	arg->group_name[MAXNAMELEN - 1] = 0;
	strncpy(arg->fs_name, fs_name, MAXNAMELEN);
	arg->fs_name[MAXNAMELEN - 1] = 0;
	strncpy(arg->output_file, output_file, MAXNAMELEN);
	arg->output_file[MAXNAMELEN - 1] = 0;
	strncpy(arg->dir_path, dir_path, MAXNAMELEN);
	arg->dir_path[MAXNAMELEN - 1] = 0;
	arg->check_only = check_only;

	mutex_enter(&(sync_obj->lock));

	if (sync_obj->thread != NULL) {
		cmn_err(CE_WARN, "group %s, fs %s is in syncing.", group_name, fs_name);

		mutex_exit(&(sync_obj->lock));
		kmem_free(arg, sizeof(zmc_sync_thread_arg_t));
		dmu_objset_rele(os, FTAG);

		return EBUSY;
	}

	sync_obj->thread_exit = B_FALSE;
	sync_obj->thread = thread_create(NULL, 0, zmc_sync_worker_thread, arg, 0, &p0, TS_RUN, maxclsyspri);

	mutex_exit(&(sync_obj->lock));

	dmu_objset_rele(os, FTAG);

	return 0;
}

int zfs_multiclus_stop_sync(char* group_name, char* fs_name)
{
	zfs_multiclus_group_t* group = NULL;
	objset_t* os = NULL;
	zfs_sb_t *zsb = NULL;
	zmc_sync_obj_t* sync_obj = NULL;
//	kt_did_t thread_id = 0;
	kthread_t *sync_thread = NULL;

	if (group_name == NULL || fs_name == NULL) {
		return EINVAL;
	}

	zfs_multiclus_get_group(group_name, &group);
	if (group == NULL) {
		cmn_err(CE_WARN, "failed to get group %s.", group_name);
		return EINVAL;
	}

	if (dmu_objset_hold(fs_name, FTAG, &os) != 0) {
		cmn_err(CE_WARN, "failed to get fs %s.", fs_name);
		return EINVAL;
	}

	mutex_enter(&os->os_user_ptr_lock);
	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	mutex_exit(&os->os_user_ptr_lock);

	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);
	if (sync_obj == NULL) {
		dmu_objset_rele(os, FTAG);
		return EINVAL;
	}

	mutex_enter(&(sync_obj->lock));

	if (sync_obj->thread == NULL) {
		cmn_err(CE_NOTE, "group %s, fs %s is not in syncing.", group_name, fs_name);

		mutex_exit(&(sync_obj->lock));
		dmu_objset_rele(os, FTAG);

		return 0;
	}

//	thread_id = sync_obj->thread->t_did;
	sync_thread = sync_obj->thread;

	/* inform worker thread to exit */
	sync_obj->thread_exit = B_TRUE;

	mutex_exit(&(sync_obj->lock));

//	thread_join(thread_id);  
	kthread_stop(sync_thread);

	dmu_objset_rele(os, FTAG);

	return 0;
}

void zmc_sync_worker_thread(zmc_sync_thread_arg_t* arg)
{
	zfs_multiclus_group_t* group = NULL;
	objset_t* os = NULL;
	zfs_sb_t *zsb = NULL;
	zmc_sync_obj_t* sync_obj = NULL;
	int ret = 0;

	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "multicluster is disabled.");
		goto out;
	}

	zfs_multiclus_get_group(arg->group_name, &group);
	if (group == NULL) {
		cmn_err(CE_WARN, "failed to get group %s.", arg->group_name);
		goto out;
	}

	if (dmu_objset_hold(arg->fs_name, FTAG, &os)) {
		cmn_err(CE_WARN, "failed to get fs %s.", arg->fs_name);
		goto out;
	}

	if (os->os_phys->os_type != DMU_OST_ZFS || os->os_is_group == 0) {
		cmn_err(CE_WARN, "fs %s is invalid.", arg->fs_name);
		goto out;
	}

	mutex_enter(&os->os_user_ptr_lock);
	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	mutex_exit(&os->os_user_ptr_lock);

	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);
	if (sync_obj == NULL) {
		goto out;
	}

	ret = zfs_multiclus_kfcreate(arg->output_file, &(sync_obj->kf_vp));
	if (ret != 0) {
		cmn_err(CE_WARN, "failed to create log file, file = %s, error = %d.",
			arg->output_file, ret);
		goto out;
	}
	sync_obj->kf_fpos = 0;

	if (arg->check_only) {
		cmn_err(CE_WARN, "group check is started, group = %s, fs = %s, dir_path = '%s'.",
			arg->group_name, arg->fs_name, arg->dir_path);
		zmc_sync_log(sync_obj, "group check is started, group = %s, fs = %s, dir_path = '%s'.",
			arg->group_name, arg->fs_name, arg->dir_path);

		ret = zmc_check_group(group, zsb, arg->dir_path);
		if (ret == EINTR) {
			cmn_err(CE_WARN, "group check is stopped, group = %s, fs = %s, dir_path = '%s'.",
				arg->group_name, arg->fs_name, arg->dir_path);
			zmc_sync_log(sync_obj, "group check is stopped, group = %s, fs = %s, dir_path = '%s'.",
				arg->group_name, arg->fs_name, arg->dir_path);
		} else if (ret != 0) {
			cmn_err(CE_WARN, "group check is completed, sync is needed, group = %s, fs = %s, dir_path = '%s'.",
				arg->group_name, arg->fs_name, arg->dir_path);
			zmc_sync_log(sync_obj, "group check is completed, sync is needed, group = %s, fs = %s, dir_path = '%s'.",
				arg->group_name, arg->fs_name, arg->dir_path);
		} else {
			cmn_err(CE_WARN, "group check is completed, sync is unneeded, group = %s, fs = %s, dir_path = '%s'.",
				arg->group_name, arg->fs_name, arg->dir_path);
			zmc_sync_log(sync_obj, "group check is completed, sync is unneeded, group = %s, fs = %s, dir_path = '%s'.",
				arg->group_name, arg->fs_name, arg->dir_path);
		}
	} else {
		cmn_err(CE_WARN, "group sync is started, group = %s, fs = %s, dir_path = '%s'.",
			arg->group_name, arg->fs_name, arg->dir_path);
		zmc_sync_log(sync_obj, "group sync is started, group = %s, fs = %s, dir_path = '%s'.",
			arg->group_name, arg->fs_name, arg->dir_path);

		ret = zmc_sync_group(group, zsb, arg->dir_path);
		if (ret == EINTR) {
			cmn_err(CE_WARN, "group sync is stopped, group = %s, fs = %s, dir_path = '%s'.",
				arg->group_name, arg->fs_name, arg->dir_path);
			zmc_sync_log(sync_obj, "group sync is stopped, group = %s, fs = %s, dir_path = '%s'.",
				arg->group_name, arg->fs_name, arg->dir_path);
		} else if (ret != 0) {
			cmn_err(CE_WARN, "group sync is failed, group = %s, fs = %s, dir_path = '%s', error = %d.",
				arg->group_name, arg->fs_name, arg->dir_path, ret);
			zmc_sync_log(sync_obj, "group sync is failed, group = %s, fs = %s, dir_path = '%s', error = %d.",
				arg->group_name, arg->fs_name, arg->dir_path, ret);
		} else {
			cmn_err(CE_WARN, "group sync is completed, group = %s, fs = %s, dir_path = '%s'.",
				arg->group_name, arg->fs_name, arg->dir_path);
			zmc_sync_log(sync_obj, "group sync is completed, group = %s, fs = %s, dir_path = '%s'.",
				arg->group_name, arg->fs_name, arg->dir_path);
		}
	}

out:
	if (sync_obj != NULL) {
		if (sync_obj->kf_vp != NULL) {
			zfs_multiclus_kfclose(sync_obj->kf_vp);
		}
		sync_obj->kf_vp = NULL;

		mutex_enter(&(sync_obj->lock));
		sync_obj->thread = NULL;
		mutex_exit(&(sync_obj->lock));
	}

	if (os != NULL) {
		dmu_objset_rele(os, FTAG);
	}

	/* allocated in zfs_multiclus_sync_group */
	kmem_free(arg, sizeof(zmc_sync_thread_arg_t));

	thread_exit();

	/* never reach here */
	return;
}


/*
 * Routines to convert standard UNIX time (seconds since Jan 1, 1970)
 * into year/month/day/hour/minute/second format, and back again.
 * Note: these routines require tod_lock held to protect cached state.
 */
static int days_thru_month[64] = {
	0, 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366, 0, 0,
	0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365, 0, 0,
	0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365, 0, 0,
	0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365, 0, 0,
};

todinfo_t
utc_to_tod(time_t utc)
{
	long dse, day, month, year;
	todinfo_t tod;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (utc < 0)			/* should never happen */
		utc = 0;

	saved_tod.tod_sec += utc - saved_utc;
	saved_utc = utc;
	if (saved_tod.tod_sec >= 0 && saved_tod.tod_sec < 60)
		return (saved_tod);	/* only the seconds changed */

	dse = utc / 86400;		/* days since epoch */

	tod.tod_sec = utc % 60;
	tod.tod_min = (utc % 3600) / 60;
	tod.tod_hour = (utc % 86400) / 3600;
	tod.tod_dow = (dse + 4) % 7 + 1;	/* epoch was a Thursday */

	year = dse / 365 + 72;	/* first guess -- always a bit too large */
	do {
		year--;
		day = dse - 365 * (year - 70) - ((year - 69) >> 2);
	} while (day < 0);

	month = ((year & 3) << 4) + 1;
	while (day >= days_thru_month[month + 1])
		month++;

	tod.tod_day = day - days_thru_month[month] + 1;
	tod.tod_month = month & 15;
	tod.tod_year = year;

	saved_tod = tod;
	return (tod);
}


void zmc_sync_log(zmc_sync_obj_t* sync_obj, const char* fmt, ...)
{
 	todinfo_t todinfo = { 0 };
	va_list ap;
	size_t len = 0;
	ssize_t written = 0;
	int ret = 0;

	todinfo = utc_to_tod(ddi_get_time());
	len = snprintf(sync_obj->buf, ZMC_SYNC_LOG_BUF_SIZE - 2, "[%04d-%02d-%02d %02d:%02d:%02d] ",
    	todinfo.tod_year + 1970 - 70, todinfo.tod_month, todinfo.tod_day,
		todinfo.tod_hour, todinfo.tod_min, todinfo.tod_sec);

	va_start(ap, fmt);
	len += vsnprintf(sync_obj->buf + len, ZMC_SYNC_LOG_BUF_SIZE - 2 - len, fmt, ap);
	va_end(ap);

	sync_obj->buf[len++] = '\n';
	sync_obj->buf[len] = 0; /* for safety (if we want to print the msg) */

	ret = zfs_multiclus_kfwrite(sync_obj->kf_vp, sync_obj->kf_fpos, sync_obj->buf, (ssize_t)len, &written);
	if (ret != 0) {
		cmn_err(CE_WARN, "%s %d: failed to log message, error = %d.", __func__, __LINE__, ret);
	}

	sync_obj->kf_fpos += written;

	return;
}


int zmc_check_group(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path)
{
	zfs_multiclus_node_type_t node_type = ZFS_MULTICLUS_SLAVE;
	int ret = 0;

	node_type = zmc_get_node_type(zsb->z_os);
	switch (node_type)
	{
		case ZFS_MULTICLUS_MASTER:
			ret = zmc_check_group_master(group, zsb, dir_path);
			break;

		case ZFS_MULTICLUS_MASTER2:
		case ZFS_MULTICLUS_MASTER3:
		case ZFS_MULTICLUS_MASTER4:
		case ZFS_MULTICLUS_SLAVE:
		default:
			/* not support yet */
			ret = 0;
			break;
	}

//OUT:
	return ret;
}


int zmc_check_group_master(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path)
{
	zmc_sync_obj_t* sync_obj = NULL;
	znode_t* root = NULL;
//	vnode_t* pvp = NULL;
//	vnode_t* vp = NULL;
	struct inode *pip = NULL;
	struct inode *ip = NULL;
	uint64_t root_id = 0;
	int error = 0;
	struct file	*filp = NULL, *dirfilp = NULL;
	char dir_path_tmp[MAXNAMELEN] = {'\0'};
	char *p = NULL;

	group = group;

	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);

	error = zfs_zget(zsb, zsb->z_root, &root);
	if (error != 0) {
		zmc_sync_log(sync_obj, "failed to get root directory, error = %d.", error);
		return 0;
	}

	if (dir_path == NULL || dir_path[0] == 0) {
//		VN_HOLD(ZTOV(root));
//		vp = ZTOV(root);
		igrab(ZTOI(root));
		ip = ZTOI(root);
	} else {
//		error = lookupnameat(dir_path, UIO_SYSSPACE, (enum symfollow)(FOLLOW | FNOREMOTE), &pvp, &vp, ZTOV(root));
/*
		if (error != 0) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path, error);
			VN_RELE(ZTOV(root));
			return 0;
		}
*/
		
		filp = filp_open(dir_path, O_RDONLY, 0);
		if (IS_ERR(filp)) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path, error);
			iput(ZTOI(root));
			goto RETURNOK;
		}
		ip = file_inode(filp);
		if (ip == NULL) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path, error);
			iput(ZTOI(root));
			goto RETURNOK0;
		}
		igrab(ip);
		
		bcopy(dir_path, dir_path_tmp, strlen(dir_path));
		p = dir_path_tmp + strlen(dir_path) - 1;
		while (*p != '/')
			p--;
		*p = '\0';
		dirfilp = filp_open(dir_path_tmp, O_RDONLY, 0);
		if (IS_ERR(dirfilp)) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path_tmp, error);
			iput(ZTOI(root));
			goto RETURNOK0;
		}
		pip = file_inode(dirfilp);
		if (pip == NULL) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path_tmp, error);
			iput(ZTOI(root));
			iput(ip);
			goto RETURNOK1;
		}
		igrab(pip);	

//		if (vp->v_type != VDIR) {
		if ((ip->i_mode & S_IFMT) != S_IFDIR) {
			zmc_sync_log(sync_obj, "target path is not a directory, dir_path = '%s'.", dir_path);
			iput(ZTOI(root));
			iput(pip);
			iput(ip);
			goto RETURNOK1;
		}

//		if (memcmp(&(vp->v_vfsp->vfs_fsid), &(zfsvfs->z_vfs->vfs_fsid), sizeof(fsid_t)) != 0) {
		if (dmu_objset_fsid_guid(ITOZ(ip)->z_zsb->z_os) == dmu_objset_fsid_guid(zsb->z_os)) {
			zmc_sync_log(sync_obj, "target path is not in group and fs, dir_path = '%s'.", dir_path);
			iput(ZTOI(root));
			iput(pip);
			iput(ip);
			goto RETURNOK1;
		}
	}

	root_id = root->z_id;
//	VN_RELE(ZTOV(root));
	iput(ZTOI(root));

	if (ITOZ(ip)->z_id == root_id) {
		/*
		 * start checking from root dir:
		 * no need to check root dir itself, just check each dir entry within root dir
		 */
		error = zfs_foreach_dir_entry(ip, zmc_check_master_dir_entry, NULL);
	} else {
		/*
		 * start checking from specified dir:
		 * check the target dir first, and then check each dir entry within it
		 */
		error = zmc_check_master_dir(pip, ip);
	}
	
	if (pip != NULL) {
		iput(pip);
	}

	iput(ip);
	return error;

RETURNOK1:
	fput(dirfilp);
RETURNOK0:
	fput(filp);
RETURNOK:
	return 0;
}


int zmc_sync_group(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path)
{
	zfs_multiclus_node_type_t node_type = ZFS_MULTICLUS_SLAVE;
	int ret = 0;

	node_type = zmc_get_node_type(zsb->z_os);
	switch (node_type)
	{
		case ZFS_MULTICLUS_MASTER:
			ret = zmc_sync_group_master(group, zsb, dir_path);
			break;

		case ZFS_MULTICLUS_MASTER2:
		case ZFS_MULTICLUS_MASTER3:
		case ZFS_MULTICLUS_MASTER4:
		case ZFS_MULTICLUS_SLAVE:
		default:
			/* not support yet */
			ret = ENOTSUP;
			break;
	}

//OUT:
	return ret;
}


int zmc_sync_group_master(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path)
{
	zmc_sync_obj_t* sync_obj = NULL;
	znode_t* root = NULL;
//	vnode_t* pvp = NULL;
//	vnode_t* vp = NULL;
	struct inode *pip = NULL;
	struct inode *ip = NULL;
	uint64_t root_id = 0;
	int flag = ZMC_SYNC_SYNC_MASTER2 | ZMC_SYNC_SYNC_MASTER3 | ZMC_SYNC_SYNC_MASTER4;
	int error = 0;
	struct file	*filp = NULL, *dirfilp = NULL;
	char dir_path_tmp[MAXNAMELEN] = {'\0'};
	char *p = NULL;
	

	group = group;


	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);

	error = zfs_zget(zsb, zsb->z_root, &root);
	if (error != 0) {
		zmc_sync_log(sync_obj, "failed to get root directory, error = %d.", error);
		return -1;
	}

	if (dir_path == NULL || dir_path[0] == 0) {
		igrab(ZTOI(root));
		ip = ZTOI(root);
	} else {
/*
		error = lookupnameat(dir_path, UIO_SYSSPACE, (enum symfollow)(FOLLOW | FNOREMOTE), &pvp, &vp, ZTOV(root));
		if (error != 0) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path, error);
			VN_RELE(ZTOV(root));
			iput(ZTOI(root));
			return -1;
		}
*/
		filp = filp_open(dir_path, O_RDONLY, 0);
		if (IS_ERR(filp)) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path, error);
			iput(ZTOI(root));
			return -1;
		}
		ip = file_inode(filp);
		if (ip == NULL) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path, error);
			iput(ZTOI(root));
			fput(filp);
			return -1;
		}
		igrab(ip);

		bcopy(dir_path, dir_path_tmp, strlen(dir_path));
		p = dir_path_tmp + strlen(dir_path) - 1;
		while (*p != '/')
			p--;
		*p = '\0';
		dirfilp = filp_open(dir_path_tmp, O_RDONLY, 0);
		if (IS_ERR(dirfilp)) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path_tmp, error);
			iput(ZTOI(root));
			iput(ip);
			fput(filp);
			return -1;
		}
		pip = file_inode(dirfilp);
		if (pip == NULL) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path_tmp, error);
			iput(ZTOI(root));
			iput(ip);
			fput(filp);
			fput(dirfilp);
			return -1;
		}
		igrab(pip);

//		if (vp->v_type != VDIR) {
		if ((ip->i_mode & S_IFMT) != S_IFDIR) {
			zmc_sync_log(sync_obj, "target path is not a directory, dir_path = '%s'.", dir_path);
			iput(ZTOI(root));
			iput(pip);
			iput(ip);
			fput(filp);
			fput(dirfilp);
			return -1;
		}

//		if (memcmp(&(vp->v_vfsp->vfs_fsid), &(zfsvfs->z_vfs->vfs_fsid), sizeof(fsid_t)) != 0) {
		if (dmu_objset_fsid_guid(ITOZ(ip)->z_zsb->z_os) == dmu_objset_fsid_guid(zsb->z_os)) {
			zmc_sync_log(sync_obj, "target path is not in group and fs, dir_path = '%s'.", dir_path);
			iput(ZTOI(root));
			iput(pip);
			iput(ip);
			fput(filp);
			fput(dirfilp);
			return -1;
		}
	}

	root_id = root->z_id;
	iput(ZTOI(root));

	if (ITOZ(ip)->z_id == root_id) {
		/*
		 * start syncing from root dir:
		 * no need to sync root dir itself, just sync each dir entry within root dir
		 */
		error = zfs_foreach_dir_entry(ip, zmc_sync_master_dir_entry, (void*)((intptr_t)flag));
	} else {
		/*
		 * start syncing from specified dir:
		 * sync the target dir first, and then sync each dir entry within it
		 */
		error = zmc_sync_master_dir(pip, ip, flag);
	}

	if (pip != NULL) {
		iput(pip);
	}

	iput(ip);
	fput(filp);
	fput(dirfilp);
	return error;
}

int zmc_compare_data_object(zfs_group_object_t* obj, zfs_group_object_t* robj)
{
	if (obj->data_spa != robj->data_spa || obj->data_objset != robj->data_objset
		|| obj->data_object != robj->data_object || obj->data_status != robj->data_status) {
		return -1;
	}

	if (obj->data2_spa != robj->data2_spa || obj->data2_objset != robj->data2_objset
		|| obj->data2_object != robj->data2_object || obj->data2_status != robj->data2_status) {
		return -1;
	}

	return 0;
}

#define zmc_is_master_obj(spa_id, os_id, obj_id, gen, grp_obj) \
	(((spa_id) == (grp_obj)->master_spa && (os_id) == (grp_obj)->master_objset \
	&& (obj_id) == (grp_obj)->master_object && (gen) == (grp_obj)->master_gen) \
	|| ((spa_id) == (grp_obj)->master2_spa && (os_id) == (grp_obj)->master2_objset \
	&& (obj_id) == (grp_obj)->master2_object && (gen) == (grp_obj)->master2_gen) \
	|| ((spa_id) == (grp_obj)->master3_spa && (os_id) == (grp_obj)->master3_objset \
	&& (obj_id) == (grp_obj)->master3_object && (gen) == (grp_obj)->master3_gen) \
	|| ((spa_id) == (grp_obj)->master4_spa && (os_id) == (grp_obj)->master4_objset \
	&& (obj_id) == (grp_obj)->master4_object && (gen) == (grp_obj)->master4_gen))

int zmc_compare_master_object(zfs_group_object_t* obj, zfs_group_object_t* robj)
{
	if (!zmc_is_master_obj(obj->master_spa, obj->master_objset,
			obj->master_object, obj->master_gen, robj)) {
		return -1;
	}

	if (!zmc_is_master_obj(obj->master2_spa, obj->master2_objset,
			obj->master2_object, obj->master2_gen, robj)) {
		return -1;
	}

	if (!zmc_is_master_obj(obj->master3_spa, obj->master3_objset,
			obj->master3_object, obj->master3_gen, robj)) {
		return -1;
	}

	if (!zmc_is_master_obj(obj->master4_spa, obj->master4_objset,
			obj->master4_object, obj->master4_gen, robj)) {
		return -1;
	}

	return 0;
}


int zmc_compare_dir_entry(struct inode * ip, struct inode * rip)
{
	znode_t* zp = ITOZ(ip);
	znode_t* rzp = ITOZ(rip);

	if ((ip->i_mode & S_IFMT) != (rip->i_mode & S_IFMT)){
		return ZMC_SYNC_DIFF_TYPE;
	}

	if (zmc_compare_master_object(&(zp->z_group_id), &(rzp->z_group_id)) != 0) {
		return ZMC_SYNC_DIFF_MASTER_OBJ;
	}

	return ZMC_SYNC_DIFF_NONE;
}


int zmc_compare_file_entry(struct inode * ip, struct inode * rip)
{
	znode_t* zp = ITOZ(ip);
	znode_t* rzp = ITOZ(rip);

	if ((ip->i_mode & S_IFMT) != (rip->i_mode & S_IFMT)){
		return ZMC_SYNC_DIFF_TYPE;
	}

	if (zp->z_size != rzp->z_size) {
		return ZMC_SYNC_DIFF_SIZE;
	}

	if (zmc_compare_data_object(&(zp->z_group_id), &(rzp->z_group_id)) != 0) {
		return ZMC_SYNC_DIFF_DATA_OBJ;
	}

	if (zmc_compare_master_object(&(zp->z_group_id), &(rzp->z_group_id)) != 0) {
		return ZMC_SYNC_DIFF_MASTER_OBJ;
	}

	return ZMC_SYNC_DIFF_NONE;
}


int zmc_compare_symlink_entry(struct inode * ip, struct inode * rip)
{
	znode_t* zp = ITOZ(ip);
	znode_t* rzp = ITOZ(rip);

	if ((ip->i_mode & S_IFMT) != (rip->i_mode & S_IFMT)){
		return ZMC_SYNC_DIFF_TYPE;
	}

	if (zp->z_size != rzp->z_size) {
		return ZMC_SYNC_DIFF_SIZE;
	}

	/* TODO: compare the target name of this symlink */

	if (zmc_compare_master_object(&(zp->z_group_id), &(rzp->z_group_id)) != 0) {
		return ZMC_SYNC_DIFF_MASTER_OBJ;
	}

	return ZMC_SYNC_DIFF_NONE;
}


int zmc_check_master_dir_entry(struct inode * pip, struct inode * ip, void* args)
{
	znode_t *zp = ITOZ(ip);
	zmc_sync_obj_t* sync_obj = (zmc_sync_obj_t*)(zp->z_zsb->z_group_sync_obj);
	int ret = 0;

	args = args;

	/*
	 * the check operation is stopped
	 */
	if (sync_obj->thread_exit) {
		return EINTR;
	}

	switch (ip->i_mode & S_IFMT)
	{
		case S_IFDIR:
			ret = zmc_check_master_dir(pip, ip);
			break;
		case S_IFREG:
			ret = zmc_check_master_file(pip, ip);
			break;
		case S_IFLNK:
			ret = zmc_check_master_symlink(pip, ip);
			break;

		default:
			/* not support yet */
			ret = 0;
			break;
	}

	return ret;
}


int zmc_check_master_dir(struct inode * pip, struct inode * ip)
{
	int ret = 0;

	if (zmc_do_check_master_dir(pip, ip, ZFS_MULTICLUS_MASTER2) != 0) {
		ret = -1;
	}

	if (zmc_do_check_master_dir(pip, ip, ZFS_MULTICLUS_MASTER3) != 0) {
		ret = -1;
	}

	if (zmc_do_check_master_dir(pip, ip, ZFS_MULTICLUS_MASTER4) != 0) {
		ret = -1;
	}

	if (ret == 0) {
		ret = zfs_foreach_dir_entry(ip, zmc_check_master_dir_entry, NULL);
	}

	return ret;
}

int zmc_check_master_file(struct inode * pip, struct inode * ip)
{
	int ret = 0;

	if (strstr(ITOZ(ip)->z_filename, SMB_STREAM_PREFIX) != NULL) {
		/* samba private file, ignore */
		return 0;
	}

	if (zmc_do_check_master_file(pip, ip, ZFS_MULTICLUS_MASTER2) != 0) {
		ret = -1;
	}

	if (zmc_do_check_master_file(pip, ip, ZFS_MULTICLUS_MASTER3) != 0) {
		ret = -1;
	}

	if (zmc_do_check_master_file(pip, ip, ZFS_MULTICLUS_MASTER4) != 0) {
		ret = -1;
	}

	return ret;
}

int zmc_check_master_symlink(struct inode * pip, struct inode * ip)
{
	int ret = 0;

	if (zmc_do_check_master_symlink(pip, ip, ZFS_MULTICLUS_MASTER2) != 0) {
		ret = -1;
	}

	if (zmc_do_check_master_symlink(pip, ip, ZFS_MULTICLUS_MASTER3) != 0) {
		ret = -1;
	}

	if (zmc_do_check_master_symlink(pip, ip, ZFS_MULTICLUS_MASTER4) != 0) {
		ret = -1;
	}

	return ret;
}

int zmc_do_check_master_dir(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type)
{
	znode_t* zp = ITOZ(ip);
	struct inode * rip = NULL;
	zmc_sync_obj_t* sync_obj = (zmc_sync_obj_t*)(zp->z_zsb->z_group_sync_obj);
	int error = 0;

	error = zfs_remote_lookup(pip, zp->z_filename, &rip, node_type);
	if (error != 0) {
		zmc_sync_log(sync_obj, "failed to get dir %s on Master %d, error = %d",
			zp->z_filename, node_type, error);
		return error;
	}

	if (rip == NULL) {
		zmc_sync_log(sync_obj, "dir %s is not existed on Master %d",
			zp->z_filename, node_type);
		return ENOENT;
	}

	error = zmc_compare_dir_entry(ip, rip);
	switch (error)
	{
		case ZMC_SYNC_DIFF_NONE:
			error = 0; /* no difference */
			break;

		case ZMC_SYNC_DIFF_TYPE:
			zmc_sync_log(sync_obj, "dir %s is not matched (type) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;

		case ZMC_SYNC_DIFF_MASTER_OBJ:
			zmc_sync_log(sync_obj, "dir %s is not matched (master obj) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;

		default:
			zmc_sync_log(sync_obj, "dir %s is not matched (unknown) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;
	}

	iput(rip);

	return error;
}

int zmc_do_check_master_file(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type)
{
	znode_t* zp = ITOZ(ip);
	struct inode * rip = NULL;
	zmc_sync_obj_t* sync_obj = (zmc_sync_obj_t*)(zp->z_zsb->z_group_sync_obj);
	int error = 0;

	error = zfs_remote_lookup(pip, zp->z_filename, &rip, node_type);
	if (error != 0) {
		zmc_sync_log(sync_obj, "failed to get file %s on Master %d, error = %d",
			zp->z_filename, node_type, error);
		return error;
	}

	if (rip == NULL) {
		zmc_sync_log(sync_obj, "file %s is not existed on Master %d",
			zp->z_filename, node_type);
		return ENOENT;
	}

	error = zmc_compare_file_entry(ip, rip);
	switch (error)
	{
		case ZMC_SYNC_DIFF_NONE:
			error = 0; /* no difference */
			break;

		case ZMC_SYNC_DIFF_TYPE:
			zmc_sync_log(sync_obj, "file %s is not matched (type) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;

		case ZMC_SYNC_DIFF_SIZE:
			zmc_sync_log(sync_obj, "file %s is not matched (size) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;

		case ZMC_SYNC_DIFF_DATA_OBJ:
			zmc_sync_log(sync_obj, "file %s is not matched (data obj) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;

		case ZMC_SYNC_DIFF_MASTER_OBJ:
			zmc_sync_log(sync_obj, "file %s is not matched (master obj) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;

		default:
			zmc_sync_log(sync_obj, "file %s is not matched (unknown) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;
	}

	iput(rip);

	return error;
}

int zmc_do_check_master_symlink(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type)
{
	znode_t* zp = ITOZ(ip);
	struct inode * rip = NULL;
	zmc_sync_obj_t* sync_obj = (zmc_sync_obj_t*)(zp->z_zsb->z_group_sync_obj);
	int error = 0;

	error = zfs_remote_lookup(pip, zp->z_filename, &rip, node_type);
	if (error != 0) {
		zmc_sync_log(sync_obj, "failed to get symlink %s on Master %d, error = %d",
			zp->z_filename, node_type, error);
		return error;
	}

	if (rip == NULL) {
		zmc_sync_log(sync_obj, "symlink %s is not existed on Master %d",
			zp->z_filename, node_type);
		return ENOENT;
	}

	error = zmc_compare_symlink_entry(ip, rip);
	switch (error)
	{
		case ZMC_SYNC_DIFF_NONE:
			error = 0; /* no difference */
			break;

		case ZMC_SYNC_DIFF_TYPE:
			zmc_sync_log(sync_obj, "symlink %s is not matched (type) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;

		case ZMC_SYNC_DIFF_SIZE:
			zmc_sync_log(sync_obj, "symlink %s is not matched (size) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;

		case ZMC_SYNC_DIFF_MASTER_OBJ:
			zmc_sync_log(sync_obj, "symlink %s is not matched (master obj) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;

		default:
			zmc_sync_log(sync_obj, "symlink %s is not matched (unknown) on Master %d",
				zp->z_filename, node_type);
			error = -1;
			break;
	}

	iput(rip);

	return error;
}

int zmc_sync_master_dir_entry(struct inode * pip, struct inode * ip, void* args)
{
	znode_t* zp = ITOZ(ip);
	zmc_sync_obj_t* sync_obj = (zmc_sync_obj_t*)(zp->z_zsb->z_group_sync_obj);
	int flag = (int)((intptr_t)args);
	int ret = 0;

	/*
	 * the sync operation is stopped
	 */
	if (sync_obj->thread_exit) {
		return EINTR;
	}

	switch (ip->i_mode & S_IFMT)
	{
		case S_IFDIR:
			ret = zmc_sync_master_dir(pip, ip, flag);
			break;
		case S_IFREG:
			ret = zmc_sync_master_file(pip, ip, flag);
			break;
		case S_IFLNK:
			ret = zmc_sync_master_symlink(pip, ip, flag);
			break;

		default:
			/* not support yet */
			ret = 0;
			break;
	}

	return ret;
}
int zmc_sync_master_dir(struct inode * pip, struct inode * ip, int flag)
{
	int ret = 0;

	/*
	 * if it failed to sync some directory on MasterX,
	 * it would also cancel the sync of the subsequent
	 * directory entries under that directory on MasterX
	 */
	if ((flag & ZMC_SYNC_SYNC_MASTER2) != 0) {
		if (zmc_do_sync_master_dir(pip, ip, ZFS_MULTICLUS_MASTER2) != 0) {
			flag &= ~ZMC_SYNC_SYNC_MASTER2;
		}
	}

	if ((flag & ZMC_SYNC_SYNC_MASTER3) != 0) {
		if (zmc_do_sync_master_dir(pip, ip, ZFS_MULTICLUS_MASTER3) != 0) {
			flag &= ~ZMC_SYNC_SYNC_MASTER3;
		}
	}

	if ((flag & ZMC_SYNC_SYNC_MASTER4) != 0) {
		if (zmc_do_sync_master_dir(pip, ip, ZFS_MULTICLUS_MASTER4) != 0) {
			flag &= ~ZMC_SYNC_SYNC_MASTER4;
		}
	}

	if (flag != 0) {
		ret = zfs_foreach_dir_entry(ip, zmc_sync_master_dir_entry, (void*)((intptr_t)flag));
	}

	return ret;
}

int zmc_sync_master_file(struct inode * pip, struct inode * ip, int flag)
{
	if (strstr(ITOZ(ip)->z_filename, SMB_STREAM_PREFIX) != NULL) {
		/* samba private file, ignore */
		return 0;
	}

	if ((flag & ZMC_SYNC_SYNC_MASTER2) != 0) {
		zmc_do_sync_master_file(pip, ip, ZFS_MULTICLUS_MASTER2);
	}

	if ((flag & ZMC_SYNC_SYNC_MASTER3) != 0) {
		zmc_do_sync_master_file(pip, ip, ZFS_MULTICLUS_MASTER3);
	}

	if ((flag & ZMC_SYNC_SYNC_MASTER4) != 0) {
		zmc_do_sync_master_file(pip, ip, ZFS_MULTICLUS_MASTER4);
	}

	return 0;
}


int zmc_sync_master_symlink(struct inode * pip, struct inode * ip, int flag)
{
	if ((flag & ZMC_SYNC_SYNC_MASTER2) != 0) {
		zmc_do_sync_master_symlink(pip, ip, ZFS_MULTICLUS_MASTER2);
	}

	if ((flag & ZMC_SYNC_SYNC_MASTER3) != 0) {
		zmc_do_sync_master_symlink(pip, ip, ZFS_MULTICLUS_MASTER3);
	}

	if ((flag & ZMC_SYNC_SYNC_MASTER4) != 0) {
		zmc_do_sync_master_symlink(pip, ip, ZFS_MULTICLUS_MASTER4);
	}

	return 0;
}


int zmc_do_sync_master_dir(struct inode *pip, struct inode *ip, zfs_multiclus_node_type_t node_type)
{
	znode_t *zp = ITOZ(ip);
	struct inode *rip = NULL;
	zmc_sync_obj_t* sync_obj = (zmc_sync_obj_t*)(zp->z_zsb->z_group_sync_obj);
	int error = 0;

	error = zfs_remote_lookup(pip, zp->z_filename, &rip, node_type);
	if (error != 0) {
		zmc_sync_log(sync_obj, "failed to get dir %s %lu on Master %d, error = %d",
			zp->z_filename, zp->z_id, node_type, error);
		return error;
	}

	if (rip == NULL) {
		error = zmc_remote_create_entry(pip, ip, node_type);

		zmc_sync_log(sync_obj, "syncing dir %s %lu on Master %d, error = %d",
			zp->z_filename, zp->z_id, node_type, error);

		return error;
	}

	error = zmc_compare_dir_entry(ip, rip);
	
	if (error == ZMC_SYNC_DIFF_NONE) {
		iput(rip);
		return 0;
	}

	zmc_sync_log(sync_obj, "syncing dir %s %lu on Master %d, error = %d",
		zp->z_filename, zp->z_id, node_type, ENOTSUP);

#if 0
	if (zmc_compare_dir_entry(vp, rvp) != 0) {
		error = zmc_remote_remove_entry(pvp, rvp, node_type);
		if (error == 0) {
			error = zmc_remote_create_entry(pvp, vp, node_type);
		}

		zmc_sync_log(sync_obj, "syncing dir %s on Master %d, error = %d",
			(vp->v_path == NULL) ? zp->z_filename : vp->v_path, node_type, error);
	}
#endif
	iput(rip);
	return error;
}


int zmc_do_sync_master_file(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type)
{
	znode_t* zp = ITOZ(ip);
	struct inode *rip = NULL;
	zmc_sync_obj_t* sync_obj = (zmc_sync_obj_t*)(zp->z_zsb->z_group_sync_obj);
	int error = 0;

	error = zfs_remote_lookup(pip, zp->z_filename, &rip, node_type);
	if (error != 0) {
		zmc_sync_log(sync_obj, "failed to get file %s %lu on Master %d, error = %d",
			zp->z_filename, zp->z_id, node_type, error);
		return error;
	}

	if (rip == NULL) {
		error = zmc_remote_create_entry(pip, ip, node_type);	
	
		zmc_sync_log(sync_obj, "syncing file %s %lu on Master %d, error = %d",
			zp->z_filename, zp->z_id, node_type, error);

		return error;

	}


	error = zmc_compare_file_entry(ip, rip);
	if (error == ZMC_SYNC_DIFF_NONE) {
		iput(rip);
		return 0;
	}

	zmc_sync_log(sync_obj, "syncing file %s %lu on Master %d, error = %d",
		zp->z_filename, zp->z_id, node_type, ENOTSUP);

#if 0
	if (zmc_compare_file_entry(vp, rvp) != 0) {
		error = zmc_remote_remove_entry(pvp, rvp, node_type);
		if (error == 0) {
			error = zmc_remote_create_entry(pvp, vp, node_type);
		}

		zmc_sync_log(sync_obj, "syncing file %s on Master %d, error = %d",
			(vp->v_path == NULL) ? zp->z_filename : vp->v_path, node_type, error);
	}
#endif
	iput(rip);
	
	return error;
}


int zmc_do_sync_master_symlink(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type)
{
	znode_t *zp = ITOZ(ip);
	struct inode *rip = NULL;
	zmc_sync_obj_t* sync_obj = (zmc_sync_obj_t*)(zp->z_zsb->z_group_sync_obj);
	int error = 0;

	error = zfs_remote_lookup(pip, zp->z_filename, &rip, node_type);
	if (error != 0) {
		zmc_sync_log(sync_obj, "failed to get symlink %s %lu on Master %d, error = %d",
			zp->z_filename, zp->z_id, node_type, error);
		return error;
	}

	if (rip == NULL) {
		error = zmc_remote_create_entry(pip, ip, node_type);

		zmc_sync_log(sync_obj, "syncing symlink %s %lu on Master %d, error = %d",
			zp->z_filename, zp->z_id, node_type, error);

		return error;
	}


	error = zmc_compare_symlink_entry(ip, rip);
	if (error == ZMC_SYNC_DIFF_NONE) {
		iput(rip);
		return 0;
	}

	zmc_sync_log(sync_obj, "syncing symlink %s %lu on Master %d, error = %d",
		zp->z_filename, zp->z_id, node_type, ENOTSUP);

#if 0
	if (zmc_compare_symlink_entry(vp, rvp) != 0) {
		error = zmc_remote_remove_entry(pvp, rvp, node_type);
		if (error == 0) {
			error = zmc_remote_create_entry(pvp, vp, node_type);
		}

		zmc_sync_log(sync_obj, "syncing symlink %s on Master %d, error = %d",
			(vp->v_path == NULL) ? zp->z_filename : vp->v_path, node_type, error);
	}
#endif

	iput(rip);

	return error;
}


int zmc_remote_create_entry(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type)
{
	int ret = 0;

	switch (ip->i_mode & S_IFMT)
	{
		case S_IFDIR:
			ret = zmc_remote_create_dir(pip, ip, node_type);
			break;

		case S_IFREG:
			ret = zmc_remote_create_file(pip, ip, node_type);
			break;

		case S_IFLNK:
			ret = zmc_remote_create_symlink(pip, ip, node_type);
			break;

		default:
			ret = -1;
			break;
	}

	return ret;
}


int zmc_remote_remove_entry(struct inode * pip, struct inode * rip, zfs_multiclus_node_type_t node_type)
{
	int ret = 0;

	switch (rip->i_mode & S_IFMT)
	{
		case S_IFDIR:
			ret = zmc_remote_remove_dir(pip, rip, node_type);
			break;

		case S_IFREG:
			ret = zmc_remote_remove_file(pip, rip, node_type);
			break;

		case S_IFLNK:
			ret = zmc_remote_remove_symlink(pip, rip, node_type);
			break;

		default:
			ret = -1;
			break;
	}

	return ret;
}


int zmc_remote_create_dir(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type)
{
	vattr_t va = { 0 };
	vsecattr_t vsa = { 0 };
	znode_t *pzp = ITOZ(pip);
	znode_t *zp = ITOZ(ip);
	cred_t* credp = NULL;
	dmu_tx_t* tx = NULL;
	int ret = 0;

	va.va_mask = ATTR_IATTR_MASK;
//	ret = vp->v_op->vop_getattr(vp, &va, FCLUSTER, kcred, NULL);
	ret = zfs_getattr(ip, &va, FCLUSTER, kcred); 
	if (ret != 0) {
		goto out;
	}

	vsa.vsa_mask = VSA_ACE | VSA_ACECNT | VSA_ACE_ACLFLAGS | VSA_ACE_ALLTYPES;
//	ret = vp->v_op->vop_getsecattr(vp, &vsa, FCLUSTER, kcred, NULL);
	ret = zfs_getsecattr(ip, &vsa, FCLUSTER, kcred);
	if (ret != 0) {
		goto out;
	}

//	credp = cred_alloc_blank();
	credp = prepare_creds();
	crsetugid(credp, va.va_uid, va.va_gid);

	ret = zfs_client_mkdir_backup(pzp, zp->z_filename, &va, zp, credp, NULL, 0, &vsa, node_type);
	if (ret != 0) {
		goto out;
	}

	tx = dmu_tx_create(zp->z_zsb->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	ret = dmu_tx_assign(tx, TXG_WAIT);
	if (ret != 0) {
		dmu_tx_abort(tx);
		goto out;
	}

	mutex_enter(&(zp->z_lock));
	VERIFY(0 == sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zp->z_zsb), 
		&(zp->z_group_id), sizeof(zfs_group_object_t), tx));
	mutex_exit(&(zp->z_lock));

	dmu_tx_commit(tx);

out:
	if (credp != NULL) {
//		crfree(credp);
		abort_creds(credp);
	}

	if (vsa.vsa_aclentp != NULL && vsa.vsa_aclentsz != 0) {
		kmem_free(vsa.vsa_aclentp, vsa.vsa_aclentsz);
	}

	return ret;
}


int zmc_remote_remove_dir(struct inode * pip, struct inode * rip, zfs_multiclus_node_type_t node_type)
{
	return zfs_client_rmdir_backup(ITOZ(pip), ITOZ(rip)->z_filename, NULL, kcred, NULL, 0, node_type);
}


int zmc_remote_create_file(struct inode* pip, struct inode * ip, zfs_multiclus_node_type_t node_type)
{
	vattr_t va = { 0 };
	vsecattr_t vsa = { 0 };
	znode_t *pzp = ITOZ(pip);
	znode_t *zp = ITOZ(ip);
	cred_t* credp = NULL;
	dmu_tx_t* tx = NULL;
	int ret = 0;

	va.va_mask = ATTR_IATTR_MASK;
//	ret = vp->v_op->vop_getattr(vp, &va, FCLUSTER, kcred, NULL);
	ret = zfs_getattr(ip,  &va, FCLUSTER, kcred);
	if (ret != 0) {
		goto out;
	}

	vsa.vsa_mask = VSA_ACE | VSA_ACECNT | VSA_ACE_ACLFLAGS | VSA_ACE_ALLTYPES;
//	ret = vp->v_op->vop_getsecattr(vp, &vsa, FCLUSTER, kcred, NULL);
	ret = zfs_getsecattr(ip, &vsa, FCLUSTER, kcred);
	if (ret != 0) {
		goto out;
	}

//	credp = crget();
	credp = prepare_creds();
	crsetugid(credp, va.va_uid, va.va_gid);

	ret = zfs_client_create_backup(pzp, zp->z_filename, &va, EXCL, 0, zp, credp, 0, NULL, &vsa, node_type);
	if (ret != 0) {
		goto out;
	}

	tx = dmu_tx_create(zp->z_zsb->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	ret = dmu_tx_assign(tx, TXG_WAIT);
	if (ret != 0) {
		dmu_tx_abort(tx);
		goto out;
	}

	mutex_enter(&(zp->z_lock)); 
	VERIFY(0 == sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zp->z_zsb), 
		&(zp->z_group_id), sizeof(zfs_group_object_t), tx));
	mutex_exit(&(zp->z_lock));

	dmu_tx_commit(tx);

out:
	if (credp != NULL) {
//		crfree(credp);
		abort_creds(credp);
	}

	if (vsa.vsa_aclentp != NULL && vsa.vsa_aclentsz != 0) {
		kmem_free(vsa.vsa_aclentp, vsa.vsa_aclentsz);
	}

	return ret;
}


int zmc_remote_remove_file(struct inode * pip, struct inode * rip, zfs_multiclus_node_type_t node_type)
{
	return zfs_client_remove_backup(ITOZ(pip), ITOZ(rip)->z_filename, kcred, NULL, 0, node_type);
}

int zmc_readlink(znode_t* zp, char* buf, unsigned int buf_len)
{
	int ret = 0;

	mutex_enter(&(zp->z_lock));

	if (zp->z_is_sa) {
		ret = sa_lookup(zp->z_sa_hdl, SA_ZPL_SYMLINK(zp->z_zsb), buf, buf_len);
	} else {
		dmu_buf_t* db = sa_get_db(zp->z_sa_hdl);
		size_t bufsz = zp->z_size;

		if (bufsz + ZFS_OLD_ZNODE_PHYS_SIZE <= db->db_size) {
			bcopy((char*)(db->db_data) + ZFS_OLD_ZNODE_PHYS_SIZE, buf, MIN((size_t)bufsz, buf_len));
		} else {
			dmu_buf_t* dbp = NULL;
			ret = dmu_buf_hold(zp->z_zsb->z_os, zp->z_id, 0, FTAG, &dbp, DMU_READ_NO_PREFETCH);
			if (ret == 0) {
				bcopy(dbp->db_data, buf, MIN((size_t)bufsz, buf_len));
				dmu_buf_rele(dbp, FTAG);
			}
		}
	}

	mutex_exit(&(zp->z_lock));

	buf[buf_len - 1] = 0;

	return ret;
}


int zmc_remote_create_symlink(struct inode *pip, struct inode *ip, zfs_multiclus_node_type_t node_type)
{
	vattr_t va = { 0 };
	char link[MAXNAMELEN] = { 0 };
	znode_t *pzp = ITOZ(pip);
	znode_t *zp = ITOZ(ip);
	cred_t* credp = NULL;
	dmu_tx_t* tx = NULL;
	int ret = 0;

	ret = zmc_readlink(zp, link, MAXNAMELEN);
	if (ret != 0) {
		goto out;
	}

	va.va_mask = ATTR_IATTR_MASK;
//	ret = vp->v_op->vop_getattr(vp, &va, FCLUSTER, kcred, NULL);
	ret = zfs_getattr(ip, &va, FCLUSTER, kcred); 
	if (ret != 0) {
		goto out;
	}

//	credp = crget();
	credp = prepare_creds();
	crsetugid(credp, va.va_uid, va.va_gid);

	ret = zfs_client_symlink_backup(pzp, zp->z_filename, &va, zp, link, credp, NULL, 0, node_type);
	if (ret != 0) {
		goto out;
	}

	tx = dmu_tx_create(zp->z_zsb->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	ret = dmu_tx_assign(tx, TXG_WAIT);
	if (ret != 0) {
		dmu_tx_abort(tx);
		goto out;
	}

	mutex_enter(&(zp->z_lock));
	VERIFY(0 == sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zp->z_zsb), &(zp->z_group_id), sizeof(zfs_group_object_t), tx));
	mutex_exit(&(zp->z_lock));

	dmu_tx_commit(tx);

out:
	if (credp != NULL) {
//		crfree(credp);
		abort_creds(credp);
	}

	return ret;
}


int zmc_remote_remove_symlink(struct inode * pip, struct inode * rip, zfs_multiclus_node_type_t node_type)
{
	return zmc_remote_remove_file(pip, rip, node_type);
}

