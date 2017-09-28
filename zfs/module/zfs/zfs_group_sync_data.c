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
#include <sys/fcntl.h>
#include <linux/cred.h>

#include <sys/zfs_group.h>
#include <sys/zfs_group_sync.h>
#include <sys/zfs_group_sync_data.h>


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
#define ZMC_SYNC_DIFF_DATA_STATUS						5


#define ZMC_SYNC_SYNC_DATA1								(0x00000001)
#define ZMC_SYNC_SYNC_DATA2								(0x00000002)

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
	boolean_t all_member_online;
} zmc_sync_thread_arg_t;

void zmc_sync_data_worker_thread(zmc_sync_thread_arg_t* arg);

extern void zmc_sync_log(zmc_sync_obj_t* sync_obj, const char* fmt, ...);

int zmc_sync_group_data(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path, zmc_sync_thread_arg_t* arg);
int zmc_sync_group_master_data(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path, zmc_sync_thread_arg_t* args);


int zmc_sync_master_dir_entry_data(struct inode * pip, struct inode * ip, void* args);
int zmc_sync_master_dir(struct inode * pip, struct inode * ip, int flag);
int zmc_sync_master_file(struct inode * pip, struct inode * ip, int flag);
int zmc_do_sync_master_dir(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);
int zmc_do_sync_master_file(struct inode * pip, struct inode * ip, zfs_multiclus_node_type_t node_type);

int zfs_remote_get_node(struct inode * ip, struct inode ** ipp, uint64_t dst_spa, uint64_t dst_objset, uint64_t dst_object);
int zmc_remote_get_data_node(struct inode * ip, struct inode ** ipp,int type);
int zmc_sync_master_dir_data(struct inode * pip, struct inode * ip, void* args);
int zmc_sync_data1_data2(struct inode * ip,struct inode  *ip_data1, struct inode *ip_data2);
int zmc_sync_data_to_data(struct inode * src_ip, struct inode * dst_ip);
int zmc_compare_data1_data2_info(struct inode * ip,zfs_group_object_t* robj1, zfs_group_object_t* robj2);
int zmc_compare_data1_data2_node(uint64_t dst1_spa,uint64_t dst1_objset,uint64_t dst1_object,uint64_t dst1_gen,
 				uint64_t dst2_spa,uint64_t dst2_objset,uint64_t dst2_object,uint64_t dst2_gen);
int zmc_get_data_recently_time(znode_t** newtime_zp,znode_t *dst1, znode_t *dst2);
void zmc_adjust_data2_is_masterfile(znode_t* zp);
int zmc_do_sync_file_data(struct inode * pip, struct inode * ip, void *args);
int zmc_check_group_data(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path);
int zmc_check_master_dir_data(struct inode * pip, struct inode * ip);
int zmc_sync_master_file_data(struct inode * pip, struct inode * ip, void *args);
int zmc_check_group_master_data(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path);
int zmc_sync_master_data(struct inode * ip,struct inode *ip_data1, struct inode *ip_data2);
int zfs_sync_master_data(struct inode * ip, struct inode * data_ip);
int zmc_compare_master_data_object_data(zfs_group_object_t* obj, zfs_group_object_t* robj);
int zmc_compare_master_data_object_master(zfs_group_object_t* obj, zfs_group_object_t* robj);
int zfs_client_notify_master_data_info(znode_t* zp, zfs_multiclus_node_type_t m_node_type);
// int zfs_client_do_notify_sync_file_data_info(znode_t* zp, uint64_t dst_spa, uint64_t dst_objset, uint64_t dst_object);
// int zfs_client_notify_master_data12_info(znode_t* zp, zfs_multiclus_node_type_t m_node_type);



static void zmc_build_data_msg_header(objset_t *os, zfs_group_header_t *hdr,
 	uint64_t cmd, share_flag_t wait_flag, uint64_t op, uint64_t length,
 	uint64_t out_length, uint64_t server_spa, uint64_t server_os,
 	uint64_t server_object, uint64_t master_object, uint64_t data2_spa,
 	uint64_t data2_os, uint64_t data2_object, msg_op_type_t op_type,
 	msg_orig_type_t orig_type);

extern void zfs_group_route_data2(zfs_sb_t *zsb, uint64_t orig_spa, uint64_t orig_os,
 	uint64_t *dst_spa, uint64_t *dst_os, uint64_t *root_object, uint64_t* host_id,
 	uint64_t exclude_spa, uint64_t exclude_os);


/*
 * Function: get data1 and data2 node
 */

int zmc_remote_get_data_node(struct inode * ip, struct inode ** ipp,int type)
{
	int error = 0;
	znode_t *zp;
	zfs_multiclus_group_record_t* record = NULL;
	uint64_t dst_spa = 0;
	uint64_t dst_objset = 0;
	uint64_t dst_object = 0;

	zp = ITOZ(ip);
	if (type == ZMC_SYNC_SYNC_DATA1) {
		dst_spa = zp->z_group_id.data_spa;
		dst_objset = zp->z_group_id.data_objset;
		dst_object = zp->z_group_id.data_object;
	} else if (type == ZMC_SYNC_SYNC_DATA2) {
		dst_spa = zp->z_group_id.data2_spa;
		dst_objset = zp->z_group_id.data2_objset;
		dst_object = zp->z_group_id.data2_object;
	} else {
		return ENOENT;
	}

	/* judge the os online or not */
	record = zfs_multiclus_get_record(dst_spa, dst_objset);
	if (record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
		return ENOENT;
	}

	/* get node from remote */
	error = zfs_remote_get_node(ip, ipp, dst_spa, dst_objset, dst_object);
	
	return error;

}

/*
 * Function:
 *	get file data node, the node save in vpp
 * Parameter: 
 *	*vp: the current vnode;
 *	**vpp: the remote vnode;
 * 
 */
int zfs_remote_get_node(struct inode * ip, struct inode ** ipp, uint64_t dst_spa, uint64_t dst_objset, uint64_t dst_object)
{
	int error;
	zfs_group_object_t group_object;
	zfs_group_phys_t tmp_phy;
	znode_t *tmp_zp;
	znode_t *zp;
	zfs_sb_t *zsb;
	znode_t *zpp;

	zp = ITOZ(ip);
	zsb = ZTOZSB(zp);

	group_object.master_spa = dst_spa;
	group_object.master_objset = dst_objset;
	group_object.master_object = dst_object;
	
	group_object.master2_spa = 0;
	group_object.master2_objset = 0;
	group_object.master2_object = 0;

	group_object.data_spa = 0;
	group_object.data_objset = 0;
	group_object.data_object = 0;

	bzero(&tmp_phy, sizeof(zfs_group_phys_t));

	tmp_zp = zfs_znode_alloc_by_group(zsb, 0, &group_object, &tmp_phy);
	/* get the file's object */
	tmp_zp->z_id = zp->z_id;

	/* get remote vnode */
	error = zfs_group_proc_znode(tmp_zp, ZNODE_GET, NULL, kcred, B_TRUE);
	if (error == 0){
		zfs_group_znode_copy_phys(tmp_zp, &tmp_phy, B_TRUE);
		zpp = zfs_znode_alloc_by_group(zsb, 0, &tmp_zp->z_group_id, &tmp_phy);
		*ipp = ZTOI(zpp);
	}
	iput(ZTOI(tmp_zp));
	return (error);
}

int zfs_multiclus_sync_group_data(char* group_name, char* fs_name, char* output_file, char* dir_path, 
	boolean_t check_only, boolean_t all_member_online)
{
	zfs_multiclus_group_t* group = NULL;
	objset_t* os = NULL;
	zfs_sb_t *zsb = NULL;
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
	arg->all_member_online = all_member_online;

	mutex_enter(&(sync_obj->lock));

	if (sync_obj->thread != NULL) {
		cmn_err(CE_WARN, "group %s, fs %s is in syncing.", group_name, fs_name);

		mutex_exit(&(sync_obj->lock));
		kmem_free(arg, sizeof(zmc_sync_thread_arg_t));
		dmu_objset_rele(os, FTAG);

		return EBUSY;
	}

	sync_obj->thread_exit = B_FALSE;
	sync_obj->thread = thread_create(NULL, 0, zmc_sync_data_worker_thread, arg, 0, &p0, TS_RUN, maxclsyspri);

	mutex_exit(&(sync_obj->lock));

	dmu_objset_rele(os, FTAG);

	return 0;
}


void zmc_sync_data_worker_thread(zmc_sync_thread_arg_t* arg)
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

		ret = zmc_check_group_data(group, zsb, arg->dir_path);
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

		ret = zmc_sync_group_data(group, zsb, arg->dir_path,arg);
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


int zmc_check_data1_data2(struct inode * ip, struct inode *ip_data1, struct inode *ip_data2)
{
	zmc_sync_obj_t* sync_obj = NULL;
	zfs_sb_t *zsb = NULL;
	znode_t* zp = NULL;
	znode_t* zp_data1 = NULL;
	znode_t* zp_data2 = NULL;
//	znode_t* newtime_zp = NULL;
//	zfs_group_object_t* newtime_obj = NULL;
	zfs_group_object_t* obj_data1 = NULL;
	zfs_group_object_t* obj_data2 = NULL;
	int error = 0;

	if (ip == NULL)
		return EINVAL;
	
	if (ip_data1== NULL && ip_data2 == NULL)
		return ENOENT;

	if (ip_data1 == NULL || ip_data2 == NULL)
		return 0;
		
	zp = ITOZ(ip);
	zsb = ZTOZSB(zp);
	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);

	zp_data1 = ITOZ(ip_data1);
	obj_data1 = &(zp_data1->z_group_id);
	
	zp_data2 = ITOZ(ip_data2);
	obj_data2 = &(zp_data2->z_group_id);
	
	/* compare file name & type */
	if ((ip_data1->i_mode & S_IFMT) != S_IFREG || (ip_data1->i_mode & S_IFMT) != (ip_data2->i_mode & S_IFMT)
		||strcmp(zp_data1->z_filename,zp_data1->z_filename) != 0) {
		zmc_sync_log(sync_obj, "file %s %lu not matched data1 and data2 (type or filename)",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_TYPE;
	}
	/* compare data1 data2*/
	error = zmc_compare_data1_data2_info(ip,obj_data1,obj_data2);
	if (error != 0) {	
		zmc_sync_log(sync_obj, "file %s %lu not matched data1 and data2 (masters)",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_MASTER_OBJ;
	}

	if (zp_data1->z_group_id.data_status == zp_data2->z_group_id.data_status 
		&& zp_data1->z_group_id.data_status == DATA_NODE_DIRTY) {
		zmc_sync_log(sync_obj, "file %s %lu not data1 and data2 is dirty",
			zp->z_filename, zp->z_id);
		return ENOTSUP;
	}
	
	if(zp_data1->z_group_id.data_status != zp_data2->z_group_id.data_status) { 
		zmc_sync_log(sync_obj, "file %s %lu not matched data1 and data2 (data_status)",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_DATA_STATUS;
	}

	if(zp_data1->z_size != zp_data2->z_size) {
		zmc_sync_log(sync_obj, "file %s %lu not matched data1 and data2 (size)",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_SIZE;
	}
	
	return error;
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

/*
 * compare master's master and data's master info
 */
int zmc_compare_master_data_object_master(zfs_group_object_t* obj, zfs_group_object_t* robj)
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


int zmc_check_master_data(struct inode * ip, struct inode * data_ip)
{
	znode_t* zp = ITOZ(ip);
	znode_t* dzp = ITOZ(data_ip);
	zmc_sync_obj_t* sync_obj = NULL;
	zfs_sb_t *zsb = NULL;

	zsb = ZTOZSB(zp);
	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);

	if ((ip->i_mode & S_IFMT) != (data_ip->i_mode & S_IFMT)) {	
		zmc_sync_log(sync_obj, "file %s %lu not matched data and master (type)",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_TYPE;
	}

	if (zp->z_size != dzp->z_size) {	
		zmc_sync_log(sync_obj, "file %s %lu not matched data and master (size)",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_SIZE;
	}

	if (zp->z_group_id.data_status != dzp->z_group_id.data_status){	
		zmc_sync_log(sync_obj, "file %s %lu not matcheddata and master (data_status))",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_DATA_STATUS;
	}
	
	if(zmc_compare_master_data_object_data(&(zp->z_group_id),&(dzp->z_group_id)) != 0) {
		zmc_sync_log(sync_obj, "file %s %lu not matched(data and master's datainfo diff)",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_DATA_OBJ;
	}

	if(zmc_compare_master_data_object_master(&(zp->z_group_id),&(dzp->z_group_id)) != 0) {
		zmc_sync_log(sync_obj, "file %s %lu not matched(data and master's masterinfo diff)",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_MASTER_OBJ;
	}
	return 0;
}

/*
 * Function : checkout data file(include data1 and data2,data and master)
 *
 */
int zmc_do_check_file_data(struct inode * pip, struct inode * ip)
{
	struct inode *tmp_ipp_data1 = NULL;
	struct inode *tmp_ipp_data2 = NULL;
	znode_t* zp = NULL;
	int error = 0;
	zmc_sync_obj_t* sync_obj = NULL;
	zfs_sb_t *zsb;
//	zfs_multiclus_group_record_t* record = NULL;

	if (ip == NULL)
		return EINVAL;
	
	if (strstr(ITOZ(ip)->z_filename, SMB_STREAM_PREFIX) != NULL) {
		/* samba private file, ignore */
		return 0;
	}

	zp = ITOZ(ip);
	zsb = ZTOZSB(zp);
	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);

	/* get data1 */
	error = zmc_remote_get_data_node(ip, &tmp_ipp_data1, ZMC_SYNC_SYNC_DATA1);
	if (error != 0) {
		zmc_sync_log(sync_obj, "failed to get %s %lu data1 on  error = %d",
			zp->z_filename, zp->z_id, error);	
	}

	/* get data2 */
	error = zmc_remote_get_data_node(ip, &tmp_ipp_data2, ZMC_SYNC_SYNC_DATA2);
	if (error != 0) {		
		zmc_sync_log(sync_obj, "failed to get %s %lu data2 on  error = %d",
			zp->z_filename, zp->z_id, error);	
	}

	/* sync data1 data2 vnode */
	error = zmc_check_data1_data2(ip, tmp_ipp_data1, tmp_ipp_data2);
	if (error != 0) {
		error = -1;
		goto out;
	}

	if (tmp_ipp_data1 != NULL) {
		/* get and compare master and data */
		if (zmc_check_master_data(ip,tmp_ipp_data1) != 0) {
			error = -1;
			goto out;
		}
	} else if (tmp_ipp_data2 != NULL) {
		zmc_adjust_data2_is_masterfile(ITOZ(tmp_ipp_data2));
		/* get and compare master and data */
		if (zmc_check_master_data(ip,tmp_ipp_data2) != 0) {
			error = -1;
			goto out;
		}
	} else {
		/* tmp_data1 ==tmp_data2==NULL */
		zmc_sync_log(sync_obj,"failed to get %s %lu node data1 data2",
			zp->z_filename, zp->z_id);
		goto out;
	}
	
out:
	if (tmp_ipp_data1 != NULL) {
		iput(tmp_ipp_data1);
		tmp_ipp_data1 = NULL;
	}
	if (tmp_ipp_data2 != NULL) {
		iput(tmp_ipp_data2);
		tmp_ipp_data2 = NULL;
	}
	
	return (error);
}


int zmc_check_master_file_data(struct inode * pip, struct inode * ip)
{
	int ret = 0;

	if (strstr(ITOZ(ip)->z_filename, SMB_STREAM_PREFIX) != NULL) {
		/* samba private file, ignore */
		return 0;
	}

	if (zmc_do_check_file_data(pip, ip) != 0) {
		ret = -1;
	}

	return ret;
}


int zmc_check_master_dir_entry_data(struct inode * pip, struct inode * ip, void* args)
{
	znode_t* zp = ITOZ(ip);
	zmc_sync_obj_t* sync_obj = (zmc_sync_obj_t*)(ZTOZSB(zp)->z_group_sync_obj);
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
			ret = zmc_check_master_dir_data(pip, ip);
			break;

		case S_IFREG:
			ret = zmc_check_master_file_data(pip, ip);
			break;

		case S_IFLNK:
			zmc_sync_log(sync_obj,"can't support symlink file %s %lu",
				zp->z_filename, zp->z_id);
			break;

		default:
			/* not support yet */
			ret = 0;
			break;
	}

	return ret;
}


int zmc_check_master_dir_data(struct inode * pip, struct inode * ip)
{
	int ret = 0;
	
	ret = zfs_foreach_dir_entry(ip, zmc_check_master_dir_entry_data, NULL);
	
	return ret;
}

int zmc_check_group_master_data(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path)
{
	zmc_sync_obj_t* sync_obj = NULL;
	znode_t* root = NULL;
//	vnode_t* pvp = NULL;
//	vnode_t* vp = NULL;
	struct inode * pip = NULL;
	struct inode * ip = NULL;
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
/*
		error = lookupnameat(dir_path, UIO_SYSSPACE, (enum symfollow)(FOLLOW | FNOREMOTE), &pvp, &vp, ZTOV(root));
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
			return 0;
		}
		ip = file_inode(filp);	
//		if (vp == NULL) {
		if (ip == NULL) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path, error);
//			VN_RELE(ZTOV(root));
//			VN_RELE(pvp);
			iput(ZTOI(root));
			fput(filp);
			return 0;
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
			return 0;
		}
		pip = file_inode(dirfilp);
		if (pip == NULL) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path_tmp, error);
			iput(ZTOI(root));
			iput(ip);
			fput(filp);
			fput(dirfilp);
		}
		igrab(pip);


//		if (vp->v_type != VDIR) {
		if ((ip->i_mode & S_IFMT) != S_IFDIR){
			zmc_sync_log(sync_obj, "target path is not a directory, dir_path = '%s'.", dir_path);
			iput(ZTOI(root));
			iput(ip);
			iput(pip);
			fput(filp);
			fput(dirfilp);
			return 0;
		}

//		if (memcmp(&(vp->v_vfsp->vfs_fsid), &(zfsvfs->z_vfs->vfs_fsid), sizeof(fsid_t)) != 0) {
		if (dmu_objset_fsid_guid(ITOZSB(ip)->z_os) == dmu_objset_fsid_guid(zsb->z_os)) {
			zmc_sync_log(sync_obj, "target path is not in group and fs, dir_path = '%s'.", dir_path);
			iput(ZTOI(root));
			iput(ip);
			iput(pip);
			fput(filp);
			fput(dirfilp);
			return 0;
		}
	}

	root_id = root->z_id;
	iput(ZTOI(root));

	if (ITOZ(ip)->z_id == root_id) {
		/*
		 * start checking from root dir:
		 * no need to check root dir itself, just check each dir entry within root dir
		 */
		error = zfs_foreach_dir_entry(ip, zmc_check_master_dir_entry_data, NULL);
	} else {
		/*
		 * start checking from specified dir:
		 * check the target dir first, and then check each dir entry within it
		 */
		error = zmc_check_master_dir_data(pip, ip);
	}

	if (pip != NULL) {
		iput(pip);
	}

	iput(ip);

	fput(filp);
	fput(dirfilp);
	return error;
}

int zmc_check_group_data(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path)
{
	zfs_multiclus_node_type_t node_type = ZFS_MULTICLUS_SLAVE;
	int ret = 0;

	node_type = zmc_get_node_type(zsb->z_os);
	switch (node_type)
	{
		case ZFS_MULTICLUS_MASTER:
			ret = zmc_check_group_master_data(group, zsb, dir_path);
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

	return ret;
}


int zmc_sync_group_data(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path, zmc_sync_thread_arg_t* arg)
{
	zfs_multiclus_node_type_t node_type = ZFS_MULTICLUS_SLAVE;
	int ret = 0;

	node_type = zmc_get_node_type(zsb->z_os);
	switch (node_type)
	{
		case ZFS_MULTICLUS_MASTER:
			ret = zmc_sync_group_master_data(group, zsb, dir_path, arg);
			break;

		case ZFS_MULTICLUS_MASTER2:
		case ZFS_MULTICLUS_MASTER3:
		case ZFS_MULTICLUS_MASTER4:
		case ZFS_MULTICLUS_SLAVE:
		default:
			ret = ENOTSUP;
			break;
	}

	return ret;
}

int zmc_sync_group_master_data(zfs_multiclus_group_t* group, zfs_sb_t * zsb, char* dir_path, zmc_sync_thread_arg_t* args)
{
	zmc_sync_obj_t* sync_obj = NULL;
	znode_t* root = NULL;
	struct inode *pip = NULL;
	struct inode *ip = NULL;
	uint64_t root_id = 0;
	int error = 0;

	struct file	*filp = NULL, *dirfilp = NULL;
	char dir_path_tmp[MAXNAMELEN] = {'\0'};
	char *p = NULL;
	
	group = group;
	
	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);
//	sync_obj = (zmc_sync_obj_t*)(zfsvfs->z_group_sync_obj);

	error = zfs_zget(zsb, zsb->z_root, &root);
//	error = zfs_zget(zfsvfs, zfsvfs->z_root, &root);
	if (error != 0) {
		zmc_sync_log(sync_obj, "failed to get root directory, error = %d.", error);
		return -1;
	}

	if (dir_path == NULL || dir_path[0] == 0) {
//		VN_HOLD(ZTOV(root));
//		vp = ZTOV(root);
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
//		if (vp == NULL) {
		if (ip == NULL) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path, error);
//			VN_RELE(ZTOV(root));
//			VN_RELE(pvp);
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
		}
		pip = file_inode(dirfilp);
		if (pip == NULL) {
			zmc_sync_log(sync_obj, "failed to get target directory, dir_path = '%s', error = %d.", dir_path_tmp, error);
			iput(ZTOI(root));
			iput(ip);
			fput(filp);
			fput(dirfilp);
		}
		igrab(pip);

//		if (vp->v_type != VDIR) {
		if ((ip->i_mode & S_IFMT) != S_IFDIR) {
			zmc_sync_log(sync_obj, "target path is not a directory, dir_path = '%s'.", dir_path);
//			VN_RELE(ZTOV(root));
//			VN_RELE(pvp);
//			VN_RELE(vp);
			iput(ZTOI(root));
			iput(pip);
			iput(ip);
			fput(filp);
			fput(dirfilp);
			return -1;
		}

//		if (memcmp(&(vp->v_vfsp->vfs_fsid), &(zfsvfs->z_vfs->vfs_fsid), sizeof(fsid_t)) != 0) {
		if (dmu_objset_fsid_guid(ITOZSB(ip)->z_os) == dmu_objset_fsid_guid(zsb->z_os)) {
			zmc_sync_log(sync_obj, "target path is not in group and fs, dir_path = '%s'.", dir_path);
//			VN_RELE(ZTOV(root));
//			VN_RELE(pvp);
//			VN_RELE(vp);
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
		error = zfs_foreach_dir_entry(ip, zmc_sync_master_dir_entry_data,args);
	} else {
		/*
		 * start syncing from specified dir:
		 * sync the target dir first, and then sync each dir entry within it
		 */
		error = zmc_sync_master_dir_data(pip, ip, args);
	}

	if (pip != NULL) {
		iput(pip);
	}

	iput(ip);
	fput(filp);
	fput(dirfilp);
	return error;
}


int zmc_sync_master_dir_entry_data(struct inode * pip, struct inode * ip, void* args)
{
	znode_t *zp = ITOZ(ip);
	zmc_sync_obj_t* sync_obj = (zmc_sync_obj_t*)(ZTOZSB(zp)->z_group_sync_obj);

	int ret = 0;

	/*
	 * the sync operation is stopped
	 */
	if (sync_obj->thread_exit) {
		return EINTR;
	}

	switch (ip->i_mode & S_IFMT)
	{
		/* if current id dir go in */
		case S_IFDIR:
			ret = zmc_sync_master_dir_data(pip, ip, args);
			break;

		/* compare data1 data2 & master */
		case S_IFREG:
			ret = zmc_sync_master_file_data(pip, ip, args);
			break;

		/* the case will be delte */
		case S_IFLNK:
			zmc_sync_log(sync_obj,"can't support symlink file %s %lu",
				zp->z_filename, zp->z_id);
			break;

		default:
			/* not support yet */
			ret = 0;
			break;
	}

	return ret;
}


int zmc_sync_master_dir_data(struct inode * pip, struct inode * ip, void* args)
{
	int ret = 0;

		ret = zfs_foreach_dir_entry(ip, zmc_sync_master_dir_entry_data, args);

	return ret;
}


int zmc_sync_master_file_data(struct inode * pip, struct inode * ip,void *args)
{
	if (strstr(ITOZ(ip)->z_filename, SMB_STREAM_PREFIX) != NULL) {
		/* samba private file, ignore */
		return 0;
	}
	zmc_do_sync_file_data(pip, ip, args);

	return 0;
}

static void zfs_group_build_header_data_backup(objset_t *os,
    zfs_group_header_t *hdr, uint64_t cmd, share_flag_t wait_flag, 
    uint64_t op, uint64_t length, uint64_t out_length, uint64_t server_spa, 
    uint64_t server_os, uint64_t server_object, uint64_t master_object,
    uint64_t data_spa, uint64_t data_os, uint64_t data_object,
    msg_op_type_t op_type, msg_orig_type_t orig_type, zfs_group_object_t* z_group_id)
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

/* Below is Parent znodes's master2 object. */
	hdr->master_object = master_object;

/* Below are child znode's mater (spa, os, obj) */
	hdr->client_os = z_group_id->master_objset;
	hdr->client_spa = z_group_id->master_spa;
	hdr->client_object = z_group_id->master_object;

/* Below is Parent znodes's masterx (spa, os, obj). */

	hdr->server_spa = server_spa;
	hdr->server_os = server_os;
	hdr->server_object = server_object;

/* Set it master x */
	hdr->master_gen = z_group_id->master_gen;

	hdr->master_spa = z_group_id->master_spa;
	hdr->master_os = z_group_id->master_objset;
	hdr->master_object = z_group_id->master_object;
	hdr->master_gen = z_group_id->master_gen;
	
	hdr->master2_spa = z_group_id->master2_spa;
	hdr->master2_os = z_group_id->master2_objset;
	hdr->master2_object = z_group_id->master2_object;
	hdr->master2_gen = z_group_id->master2_gen;

	hdr->master3_spa = z_group_id->master3_spa;
	hdr->master3_os = z_group_id->master3_objset;
	hdr->master3_object = z_group_id->master3_object;
	hdr->master3_gen = z_group_id->master3_gen;

	hdr->master4_spa = z_group_id->master4_spa;
	hdr->master4_os = z_group_id->master4_objset;
	hdr->master4_object = z_group_id->master4_object;
	hdr->master4_gen = z_group_id->master4_gen;

	hdr->reset_seqno = 0;
}


int zfs_group_create_data_file_node(znode_t *zp, char *name, boolean_t bregual,
	vsecattr_t *vsecp, vattr_t *vap, vcexcl_t ex, int mode, int flag,
	uint64_t orig_spa, uint64_t orig_os, uint64_t* dirlowdata, uint64_t* host_id,zfs_group_object_t *z_group_id, int type)

{
	int err = 0;
	size_t request_length = 0;
	size_t reply_length = 0;
	char new_name[MAXNAMELEN];
	size_t namesize = 0;
	size_t aclsize = 0;
	size_t xvatsize = 0;
	size_t dirlowdatasize = 0;
	zfs_group_create_extra_t *create_extra = NULL;

	zfs_sb_t *zsb;

	uint64_t master_spa;
	uint64_t master_os;
	uint64_t master_object;

	uint64_t dst_spa = 0;
	uint64_t dst_os = 0;
	uint64_t dst_root_object = 0;

	zfs_group_name_create_t *createp;
	zfs_group_name_t *np;
	zfs_group_name2_t *n2p;

	zfs_group_header_t *msg_header = NULL;
	zfs_group_name_msg_t *data_msg;

	zfs_group_object_t group_object = { 0 };

	dmu_tx_t *tx;

	/* only support regular file */
	if (!bregual)
	{
		return 0;
	}

	zsb = ZTOZSB(zp);
	master_object = zp->z_id;
	master_spa = spa_guid(dmu_objset_spa(zsb->z_os));
	master_os = dmu_objset_id(zsb->z_os);

	/*
	 * get original info from zp, but must reset master_spa, master_objset
	 * and master_object, as these 3 fields may be 0 if it failed to create
	 * the data1 file
	 */
	group_object = zp->z_group_id;
	group_object.master_gen = zp->z_gen;
	
	if(type == ZMC_SYNC_SYNC_DATA2){
		zfs_group_route_data2(zsb, orig_spa, orig_os, &dst_spa, &dst_os, &dst_root_object,
			host_id, zp->z_group_id.data_spa, zp->z_group_id.data_objset);
	} else {
		zfs_group_route_data2(zsb, orig_spa, orig_os, &dst_spa, &dst_os, &dst_root_object,
			host_id, zp->z_group_id.data2_spa, zp->z_group_id.data2_objset);

	}
	
	if (dst_spa == 0 && dst_os == 0) {
		/*
		 * there is only one file system in the cluster,
		 * just save one copy of the data file
		 */
		cmn_err(CE_WARN, "[Error] failed to get data2 host for file %s", name);
		return 0;
	}


	data_msg = kmem_zalloc(sizeof(zfs_group_name_msg_t), KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	createp = &data_msg->call.name.arg.p.create;

	sprintf(new_name, DATA_OBJECT_NAME, (longlong_t)master_object, name);
	create_extra = zfs_group_get_create_extra(new_name, vap, vsecp,
					    &namesize, &xvatsize, &aclsize, dirlowdata, &dirlowdatasize);

	createp->name_len = namesize;
	createp->xattr_len = xvatsize;
	createp->acl_len = aclsize;
	createp->dirlowdata_len = dirlowdatasize;
	createp->master_object = master_object;
	createp->master_gen = zp->z_gen;
	createp->ex = (int32_t)ex;
	createp->mode = mode;
	createp->flag = flag;
	if ((err = zfs_group_v_to_v32(vap, &createp->vattr)) != 0) {			
		kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
		kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
		kmem_free(data_msg, sizeof(zfs_group_name_msg_t));
		return (err);
	}
	createp->vattr.va_mask &= ~AT_SIZE;

	np = (zfs_group_name_t *)&data_msg->call.name;
	np->parent_object.data_spa = dst_spa;
	np->parent_object.data_objset = dst_os;
	np->parent_object.data_object = dst_root_object;

	bcopy((void *)create_extra->extra_createp,
	    np->component, create_extra->extra_create_plen);

	request_length = offsetof(zfs_group_name_t, component) +
	    create_extra->extra_create_plen + 1;
	reply_length = sizeof(zfs_group_name2_t);

	zfs_group_build_header_data_backup(zsb->z_os, msg_header, ZFS_GROUP_CMD_NAME_BACKUP,
	    SHARE_WAIT, NAME_CREATE_DATA, request_length, reply_length,
	    dst_spa, dst_os, 0, master_object,
	    dst_spa, dst_os, 0, MSG_REQUEST, APP_GROUP, z_group_id);

	err = zfs_client_send_to_server(zsb->z_os, msg_header, (zfs_msg_t *)data_msg, B_TRUE);

	if (err == 0) {
		n2p = (zfs_group_name2_t *)&data_msg->call.name2;
		if(n2p->nrec.object_id.master_spa == 0 && n2p->nrec.object_id.master_objset == 0
			&& n2p->nrec.object_id.master_object == 0 && n2p->nrec.object_id.data_spa == 0
			&& n2p->nrec.object_id.data_objset == 0 && n2p->nrec.object_id.data_object == 0){
				cmn_err(CE_WARN, "[corrupt group object] %s %s %d", __FILE__, __func__, __LINE__);
		}

		/*
		 * genereate info for data2 node
		 */
		 if (type == ZMC_SYNC_SYNC_DATA2) {
			group_object.data2_spa = n2p->nrec.object_id.data_spa;
			group_object.data2_objset = n2p->nrec.object_id.data_objset;
			group_object.data2_object = n2p->nrec.object_id.data_object;
		 } else {
		 	group_object.data_spa = n2p->nrec.object_id.data_spa;
			group_object.data_objset = n2p->nrec.object_id.data_objset;
			group_object.data_object = n2p->nrec.object_id.data_object;
		 }
		}

	kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
	kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
	kmem_free(msg_header, sizeof(zfs_group_header_t));
	kmem_free(data_msg, sizeof(zfs_group_name_msg_t));

	if (err == 0) {
		tx = dmu_tx_create(zsb->z_os);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if (err){
			dmu_tx_abort(tx);
			return err;
		}

		mutex_enter(&zp->z_lock);
		zfs_sa_set_remote_object(zp, &group_object, tx);
		mutex_exit(&zp->z_lock);

		if (type == ZMC_SYNC_SYNC_DATA2) {
			if (zp->z_group_id.master_spa == 0 && zp->z_group_id.master_objset == 0
				&& zp->z_group_id.master_object == 0 && zp->z_group_id.data2_spa == 0
				&& zp->z_group_id.data2_objset == 0 && zp->z_group_id.data2_object == 0){
				cmn_err(CE_WARN, "[corrupt group object] %s %s %d", __FILE__, __func__, __LINE__);
			}
		} else {
			if(zp->z_group_id.master_spa == 0 && zp->z_group_id.master_objset == 0
				&& zp->z_group_id.master_object == 0 && zp->z_group_id.data_spa == 0
				&& zp->z_group_id.data_objset == 0 && zp->z_group_id.data_object == 0){
				cmn_err(CE_WARN, "[corrupt group object] %s %s %d", __FILE__, __func__, __LINE__);
			}
		
		}
		dmu_tx_commit(tx);
	}

	return (err);
}


int zmc_create_data1_or_data2_file(struct inode * pip, struct inode * ip,
	struct inode **tmp_ipp_data1, struct inode **tmp_ipp_data2, int type)
{
	boolean_t bregual = B_FALSE;
	uint64_t host_id = 0;
	uint64_t flag = 0;
	uint64_t orig_spa = 0;
	uint64_t orig_os = 0;
	znode_t *pzp = ITOZ(pip);
	znode_t *d1zp = ITOZ(*tmp_ipp_data1);
	znode_t *d2zp = NULL;
	zfs_multiclus_group_record_t* target = NULL;
	znode_t *zp = ITOZ(ip);
	zfs_sb_t *zsb;
	
	vattr_t va = { 0 };
	vsecattr_t vsa = { 0 };
	cred_t* credp = NULL;
	caller_context_t ct;
	int error;

	zsb = ZTOZSB(zp);
	 
	va.va_mask = ATTR_IATTR_MASK;
//	error = vp->v_op->vop_getattr(vp, &va, FCLUSTER, kcred, NULL);
	error = zfs_getattr(ip, &va, FCLUSTER, kcred);
	if (error != 0) {
		goto out;
	}
	
	vsa.vsa_mask = VSA_ACE | VSA_ACECNT | VSA_ACE_ACLFLAGS | VSA_ACE_ALLTYPES;
//	error = vp->v_op->vop_getsecattr(vp, &vsa, FCLUSTER, kcred, NULL);
	error = zfs_getsecattr(ip, &vsa, FCLUSTER, kcred);
	if (error != 0) {
		goto out;
	}
		
//	credp = crget();
	credp = prepare_creds();
	crsetugid(credp, va.va_uid, va.va_gid);

	if (zsb->z_os->os_is_master) {
		ct.cc_sysid = BF64_GET(spa_guid(dmu_objset_spa(zsb->z_os)), 32, 32);
		ct.cc_pid = BF64_GET(spa_guid(dmu_objset_spa(zsb->z_os)), 0, 32);
		ct.cc_caller_id = dmu_objset_id(zsb->z_os);
		
		if (flag & FCLUSTER) {
			BF64_SET(orig_spa, 32,32, ct.cc_sysid);
			BF64_SET(orig_spa, 0, 32, ct.cc_pid);
			orig_os = ct.cc_caller_id;
		} else {
			orig_spa = spa_guid(dmu_objset_spa(zsb->z_os));
			orig_os = dmu_objset_id(zsb->z_os);
		}
	}
			
	if((pzp->z_pflags & ZFS_XATTR) == 0
		&& va.va_type == 1) {
		bregual = B_TRUE;
	}
			
			/* get data1 hostid */
	target = zfs_multiclus_get_record(d1zp->z_group_id.data_spa, d1zp->z_group_id.data_objset);
	host_id = target->hostid;
	
	zfs_group_create_data_file_node(zp, zp->z_filename, bregual, &vsa, &va, EXCL,
		0, flag, orig_spa, orig_os, &pzp->z_dirlowdata, &host_id,&d1zp->z_group_id,type);
	
	error = zmc_remote_get_data_node(ip, tmp_ipp_data2, type);
	if (error != 0) {
		error = ENOENT;
		goto out;
	}

	d2zp = ITOZ(*tmp_ipp_data2);
	d2zp->z_ctime[0] = d1zp->z_ctime[0]-1;
	d2zp->z_ctime[1] = d1zp->z_ctime[1]-1;

out:
	if (credp != NULL) {
//		crfree(credp);
		abort_creds(credp);
	}
	
	if (vsa.vsa_aclentp != NULL && vsa.vsa_aclentsz != 0) {
		kmem_free(vsa.vsa_aclentp, vsa.vsa_aclentsz);
	}
	return 0;	

}

/*
 * Function : sync data file(include data1 and data2,data and master)
 *
 */
int zmc_do_sync_file_data(struct inode * pip, struct inode * ip,void *args)
{
	struct inode *tmp_ipp_data1= NULL;
	struct inode *tmp_ipp_data2= NULL;
	znode_t* zp = NULL;
	int error = 0;
	zmc_sync_obj_t* sync_obj = NULL;
	zfs_sb_t *zsb;
//	zfs_multiclus_group_record_t* record = NULL;
	zmc_sync_thread_arg_t* usr_param = (zmc_sync_thread_arg_t*)args;

	if (strstr(ITOZ(ip)->z_filename, SMB_STREAM_PREFIX) != NULL) {
		/* samba private file, ignore */
		return 0;
	}
	
	zp = ITOZ(ip);
	zsb = ZTOZSB(zp);
	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);

	/* get data1 */
	error = zmc_remote_get_data_node(ip, &tmp_ipp_data1, ZMC_SYNC_SYNC_DATA1);
	if (error != 0 && usr_param->all_member_online == B_FALSE) {
		zmc_sync_log(sync_obj, "failed to get %s %lu data1 on error = %d",
			zp->z_filename, zp->z_id, error);
	}

	/* get data2 */
	error = zmc_remote_get_data_node(ip, &tmp_ipp_data2, ZMC_SYNC_SYNC_DATA2);
	if (error != 0 && usr_param->all_member_online == B_FALSE) {		
		zmc_sync_log(sync_obj, "failed to get %s %lu data2 on error = %d",
			zp->z_filename, zp->z_id, error);	
	}
	
	if(usr_param->all_member_online == B_TRUE) {	
		if (tmp_ipp_data1 != NULL && tmp_ipp_data2 == NULL) {
			zmc_create_data1_or_data2_file(pip,ip,&tmp_ipp_data1,&tmp_ipp_data2, ZMC_SYNC_SYNC_DATA2);
		} else if (tmp_ipp_data1 == NULL && tmp_ipp_data2 != NULL) {		
			zmc_create_data1_or_data2_file(pip,ip,&tmp_ipp_data2,&tmp_ipp_data1, ZMC_SYNC_SYNC_DATA1);
			
		}
	}
	/* sync data1 data2 vnode if tmp vpp = NULL go on */
	error = zmc_sync_data1_data2(ip, tmp_ipp_data1, tmp_ipp_data2);
	if (error != 0) {	
		zmc_sync_log(sync_obj, "syncing file %s %lu on error = %d",
			zp->z_filename, zp->z_id, error);
		goto out;
	}
	
	/* sync data and master node info */
	error = zmc_sync_master_data(ip, tmp_ipp_data1, tmp_ipp_data2);
	if (error != 0) {
		zmc_sync_log(sync_obj, "syncing file %s %lu on error = %d",
			zp->z_filename, zp->z_id, error);
		goto out;
	}

	/* send masterX info to data node and other Master node */
	if (zfs_client_notify_master_data_info(zp, ZFS_MULTICLUS_SLAVE) != 0) {
		
		zmc_sync_log(sync_obj, "Failed to update master file node info, file is %s %lu",
			zp->z_filename, zp->z_id);
		goto out;
	}

out:
	if (tmp_ipp_data1 != NULL) {
		iput(tmp_ipp_data1);
		tmp_ipp_data1 = NULL;
	}
	if (tmp_ipp_data2 != NULL) {
		iput(tmp_ipp_data2);
		tmp_ipp_data2 = NULL;
	}
	return (error);
}

int zfs_client_notify_master_data_info(znode_t* zp, zfs_multiclus_node_type_t m_node_type)
{
	zmc_sync_obj_t* sync_obj = NULL;
	struct inode *ip = NULL;
	zfs_sb_t *zsb;

	ip = ZTOI(zp);
	zsb = ZTOZSB(zp);
	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);

	if (zfs_client_notify_file_info(zp, m_node_type, ZFS_UPDATE_FILE_NODE_DATA1) != 0) {
		return -1;
	}
	
	if (zfs_client_notify_file_info(zp, m_node_type, ZFS_UPDATE_FILE_NODE_DATA2) != 0) {	
		return -1;
	}
	
	return 0;
}

/*
 * compare master's data and data's data info
 */
int zmc_compare_master_data_object_data(zfs_group_object_t* obj, zfs_group_object_t* robj)
{
	int ret = 0;
	
	if((obj->data_spa == robj->data_spa && obj->data_objset == robj->data_objset&&
		obj->data_object == robj->data_object)||
		(obj->data2_spa == robj->data_spa && obj->data2_objset == robj->data_objset&&
		obj->data2_object == robj->data_object)) {
		ret = 0;
	} else {
		ret = -1;
	}

	return ret;
}


int zmc_sync_master_data(struct inode * ip,struct inode *ip_data1, struct inode *ip_data2)
{
	int error = 0;
	znode_t *tmp_zp1 = NULL;
	znode_t *tmp_zp2 = NULL;
	znode_t *newtime_zp = NULL;
	znode_t *zp = NULL;
	zmc_sync_obj_t* sync_obj = NULL;
	zfs_sb_t *zsb;
	
	if ((ip_data1 == NULL && ip_data2 == NULL) || ip == NULL)
		return ENOENT;

	zp = ITOZ(ip);
	zsb = ZTOZSB(zp);
	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);

	if (ip_data1 != NULL)
		tmp_zp1 = ITOZ(ip_data1);
	if (ip_data2 != NULL)
		tmp_zp2 = ITOZ(ip_data2);
	error = zmc_get_data_recently_time(&newtime_zp, tmp_zp1, tmp_zp2);
	if (error != 0) {
		zmc_sync_log(sync_obj,"fail to get file=%s data1 data2 new time vnode",zp->z_filename);
		return (error);
	}

	if (newtime_zp == tmp_zp2)
		zmc_adjust_data2_is_masterfile(tmp_zp2);

	error = zfs_sync_master_data(ip, ZTOI(newtime_zp));
	
	return error;
}

static void
zfs_tstamp_update_setup2(znode_t *zp, uint_t flag, boolean_t have_tx)
{
	zfs_sb_t *zsb = ZTOZSB(zp);
	timestruc_t	now;

	gethrestime(&now);

	if (have_tx) {	/* will sa_bulk_update happen really soon? */
		zp->z_atime_dirty = 0;
		zp->z_seq++;
	} else {
		zp->z_atime_dirty = 1;
	}

	if (flag & AT_ATIME){
		if (zsb->z_isworm) {
			if ((zp->z_pflags & (ZFS_WORM | ZFS_IMMUTABLE)) == 0){
				ZFS_TIME_ENCODE(&now, zp->z_atime);
			}
		} else {
			ZFS_TIME_ENCODE(&now, zp->z_atime);
		}
		
	}
	zfs_tstamp_update_setup(zp, flag, zp->z_mtime, zp->z_ctime);
}

int zfs_sync_master_data(struct inode * ip, struct inode * data_ip)
{
	znode_t* zp = NULL; 
	znode_t* dzp = NULL; 
	zmc_sync_obj_t* sync_obj = NULL;
	zfs_sb_t *zsb = NULL;
	dmu_tx_t* tx = NULL;
	sa_bulk_attr_t bulk[4]; // = {'\0'};;
	int count = 0;
	int error = 0;

	if (ip == NULL || data_ip == NULL)
		return EINVAL;

	zp = ITOZ(ip);
	dzp = ITOZ(data_ip);
	
	zsb = ZTOZSB(zp);
	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);
	
	if ((ip->i_mode & S_IFMT) != (data_ip->i_mode & S_IFMT)) {	
		zmc_sync_log(sync_obj, "file %s %lu not matched data and master (type)",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_TYPE;
	}

	if (zmc_compare_master_data_object_data(&(zp->z_group_id),&(dzp->z_group_id)) != 0) {	
		zmc_sync_log(sync_obj, "file %s %lu not matched(data and master's datainfo diff)",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_DATA_OBJ;
	}

	if(zmc_compare_master_data_object_master(&(zp->z_group_id),&(dzp->z_group_id)) != 0) {
		zmc_sync_log(sync_obj, "file %s %lu not matched(data and master's masterinfo diff)",
			zp->z_filename, zp->z_id);
		return ZMC_SYNC_DIFF_MASTER_OBJ;
	}

	if (zp->z_size != dzp->z_size) {
		zp->z_size = dzp->z_size;

		log:
		tx = dmu_tx_create(zsb->z_os);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
		zfs_sa_upgrade_txholds(tx, zp);
		error = dmu_tx_assign(tx, TXG_NOWAIT);
		if (error) {
			if (error == ERESTART) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto log;
			}
			dmu_tx_abort(tx);
			
			zmc_sync_log(sync_obj, "syncing master-data file %s %lu (size diff) error = %d",
				zp->z_filename, zp->z_id, error);
			return (error);
		}

		SA_ADD_BULK_AMCTIME(bulk, count, zsb, zp);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zsb),
		    NULL, &zp->z_pflags, 8);
		zfs_tstamp_update_setup2(zp, CONTENT_MODIFIED, B_TRUE);
		error = sa_bulk_update(zp->z_sa_hdl, bulk, count, tx);
		ASSERT(error == 0);

		dmu_tx_commit(tx);

		zmc_sync_log(sync_obj, "syncing master-data file %s %lu (size diff) error = %d",
			zp->z_filename, zp->z_id, error);
	}
	
	if (dzp->z_group_id.data_status != DATA_NODE_DIRTY && (zp->z_group_id.data_status != dzp->z_group_id.data_status
		|| zp->z_group_id.data2_status != dzp->z_group_id.data_status)){
		zp->z_group_id.data_status = dzp->z_group_id.data_status;
		zp->z_group_id.data2_status = dzp->z_group_id.data_status;
		
		tx = dmu_tx_create(zsb->z_os);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error != 0) {
			dmu_tx_abort(tx);
			iput(ZTOI(zp));
			zmc_sync_log(sync_obj, "syncing master-data file %s %lu (status diff) error = %d",
				zp->z_filename, zp->z_id, error);
			return error;
		}

		mutex_enter(&(zp->z_lock));
		error = sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zsb),
			&(zp->z_group_id), sizeof(zfs_group_object_t), tx);
		mutex_exit(&(zp->z_lock));

		dmu_tx_commit(tx);


		zmc_sync_log(sync_obj, "syncing master-data file %s %lu (status diff) error = %d",
			zp->z_filename, zp->z_id, error);
	}
	
	return 0;
}


/*
 * Function:
 *	sync data1 and data2, get health && closer current time node sync old data.
 * Parameter:
 *	vp :master file vnode
 *	vp_data1: get data1 node from remote;
 *	vp_data2: get data2 node from remote;
 * Return: 0-->success; other fail
 */
int zmc_sync_data1_data2(struct inode * ip,struct inode *ip_data1, struct inode *ip_data2)
{
	zmc_sync_obj_t* sync_obj = NULL;
//	zfsvfs_t *zfsvfs = NULL;
	zfs_sb_t *zsb = NULL;
	znode_t* zp = NULL;
	znode_t* zp_data1 = NULL;
	znode_t* zp_data2 = NULL;
	znode_t* newtime_zp = NULL;
	zfs_group_object_t* newtime_obj = NULL;
	zfs_group_object_t* obj_data1 = NULL;
	zfs_group_object_t* obj_data2 = NULL;
	int error = 0;

	if (ip == NULL)
		return EINVAL;
	if (ip_data1 == NULL && ip_data2 == NULL)
		return ENOENT;
	if (ip_data1 == NULL || ip_data2 == NULL)
		return 0;
		
	zp = ITOZ(ip);
	zsb = ZTOZSB(zp);
	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);

	zp_data1 = ITOZ(ip_data1);
	obj_data1 = &(zp_data1->z_group_id);
	
	zp_data2 = ITOZ(ip_data2);
	obj_data2 = &(zp_data2->z_group_id);
	
	/* compare file name & type */
	if ((ip_data1->i_mode & S_IFMT) != S_IFREG || (ip_data1->i_mode & S_IFMT) != (ip_data2->i_mode & S_IFMT)
		||strcmp(zp_data1->z_filename,zp_data1->z_filename) != 0) {
		zmc_sync_log(sync_obj,"data1 filename=%s,type=%d; data2 filename=%s,type2=%d,",
			zp_data1->z_filename,ip_data1->i_mode & S_IFMT,
			zp_data2->z_filename,ip_data2->i_mode & S_IFMT);
		return ENOTSUP;
	}
	/* compare data1 data2*/
	error = zmc_compare_data1_data2_info(ip,obj_data1,obj_data2);
	if (error != 0) {
		return ENOTSUP;
	}

	/* get Close to the current time vnode, save in newtime_zp */
	error = zmc_get_data_recently_time(&newtime_zp,zp_data1,zp_data2);
	if (error != 0) {
		zmc_sync_log(sync_obj,"fail to get file=%s data1 data2 new time vnode error=%d",zp->z_filename,error);
		return (error);
	}

	/* if new data is dirty ,return  ENOTSUP*/
	newtime_obj = &(newtime_zp->z_group_id);
	if (newtime_obj->data_status == DATA_NODE_DIRTY) {
		zmc_sync_log(sync_obj,"fail file=%s, get newtime data is dirty data_status=%llu",zp->z_filename,(long long unsigned)newtime_obj->data_status);
		return ENOTSUP;
	}

	/* if data2 == master, copy data2_spa ==>data_spa */
	zmc_adjust_data2_is_masterfile(zp_data2);

	/* newtime_zp == zp_data1 or newtime_zp == zp_data2 not other situation */
	if (newtime_zp == zp_data1) {
		if(zp_data1->z_size != zp_data2->z_size || obj_data2->data_status == DATA_NODE_DIRTY) {
			/* sync zp_data1 to zp_data2 */
			error = zmc_sync_data_to_data(ip_data1,ip_data2);	
			
			zmc_sync_log(sync_obj, "syncing data-data file %s %lu (size or status diff) on error = %d",
				zp->z_filename, zp->z_id, error);
			
		}
	} else if (newtime_zp == zp_data2) {
		if(zp_data1->z_size != zp_data2->z_size || obj_data1->data_status == DATA_NODE_DIRTY) {
			/* sync data zp_data2 to zp_data1 */
			error = zmc_sync_data_to_data(ip_data2,ip_data1);
			zmc_sync_log(sync_obj, "syncing data-data file %s %lu(size or status diff) on error = %d",
				zp->z_filename, zp->z_id, error);
		}
	}

	return error;
}


int zmc_sync_data_to_data(struct inode * src_ip, struct inode * dst_ip)
{
	int error;	
	znode_t *src_zp = NULL;
	znode_t *dst_zp = NULL;
	zfs_sb_t *zsb =NULL;
//	uint64_t off;
	uint64_t io_flags;
	zfs_group_data_t *data = NULL;
	uint64_t msg_len = 0;
	zfs_group_data_msg_t *data_msg = NULL;
	zfs_group_header_t *msg_header = NULL;
	int request_length;
	int reply_lenth;
	zfs_group_data_read_t *read;
	
	read = kmem_zalloc(sizeof(zfs_group_data_read_t), KM_SLEEP);

	src_zp = ITOZ(src_ip);
	zsb = ZTOZSB(src_zp);

	dst_zp = ITOZ(dst_ip);
	zfs_group_set_cred(kcred, &read->cred);

	io_flags = FCLUSTER;

	msg_len = sizeof (zfs_group_data_msg_t);
	data_msg = kmem_zalloc(msg_len, KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	data = &data_msg->call.data;
	data->io_flags = io_flags;
	data->arg.p.read = *read;
	request_length = sizeof(zfs_group_data_msg_t);
	reply_lenth = data->arg.p.read.len + sizeof(zfs_group_data_msg_t) - 8;

	zmc_build_data_msg_header(zsb->z_os, msg_header, ZFS_GROUP_CMD_DATA, SHARE_WAIT, MIGRATE_DATA,
		request_length, reply_lenth, src_zp->z_group_id.data_spa, src_zp->z_group_id.data_objset, src_zp->z_group_id.data_object,
		src_zp->z_group_id.master_object,
		dst_zp->z_group_id.data_spa,
		dst_zp->z_group_id.data_objset,
		dst_zp->z_group_id.data_object,
		MSG_REQUEST, APP_USER);

		src_zp->z_group_id.data2_spa = dst_zp->z_group_id.data_spa;
		src_zp->z_group_id.data2_objset = dst_zp->z_group_id.data_objset;
		src_zp->z_group_id.data2_object = dst_zp->z_group_id.data_object;
		data->id = src_zp->z_group_id;
	error = zfs_client_send_to_server(zsb->z_os, msg_header, (zfs_msg_t *)data_msg, B_TRUE);

	if (data_msg != NULL) {
		kmem_free(data_msg, msg_len);
	}
	if (msg_header != NULL) {
		kmem_free(msg_header, sizeof(zfs_group_header_t));
	}
	if (read != NULL) {
		kmem_free(read, sizeof(zfs_group_data_read_t));
	}

	return (error);
}

static void zmc_build_data_msg_header(objset_t *os, zfs_group_header_t *hdr,
	uint64_t cmd, share_flag_t wait_flag, uint64_t op, uint64_t length,
	uint64_t out_length, uint64_t server_spa, uint64_t server_os,
	uint64_t server_object, uint64_t master_object, uint64_t data2_spa,
	uint64_t data2_os, uint64_t data2_object, msg_op_type_t op_type,
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

	/*hdr->data_spa = data_spa;
	hdr->data_os = data_os;
	hdr->data_object = data_object;*/
	hdr->reset_seqno = 0;

	/* save will be MIGRATE data node*/
	hdr->data2_spa = data2_spa;
	hdr->data2_os = data2_os;
	hdr->data2_object = data2_object;

	return;
}


/*
 * Funstion: 
 *	the function compare dst1 and dst2, get the znode which time is close the current time.
 * Parameters:
 *	newtime_zp: when compare the dst1\dst2 and save in the parameter
 *	dst1:	the dst1 will be compare with dst2 znode
 *	dst2: the dst2 will be compare with dst1 zonde
 * Rturn:
 *	0-->success;other-->fail
 */
int zmc_get_data_recently_time(znode_t** newtime_zp,znode_t *dst1, znode_t *dst2)
{
	char dst1mtime[129] = {"\0"};
	char dst2mtime[129] = {"\0"};
	char dst1ctime[129] = {"\0"};
	char dst2ctime[129] = {"\0"};
	
	if (newtime_zp == NULL)
		return EINVAL;
	
	if (dst1 == NULL && dst2 != NULL) {
		*newtime_zp = dst2;
		return 0;
	} else if (dst1 != NULL && dst2 == NULL) {
		*newtime_zp = dst1;
		return 0;
	} else if (dst1 == NULL && dst2 == NULL) {
		*newtime_zp = NULL;
		return EINVAL;
	}

	sprintf(dst1mtime,"%llu%llu",(unsigned long long)dst1->z_mtime[0],(unsigned long long)dst1->z_mtime[1]);
	sprintf(dst1ctime,"%llu%llu",(unsigned long long)dst1->z_ctime[0],(unsigned long long)dst1->z_ctime[1]);

	sprintf(dst2mtime,"%llu%llu",(unsigned long long)dst2->z_mtime[0],(unsigned long long)dst2->z_mtime[1]);
	sprintf(dst2ctime,"%llu%llu",(unsigned long long)dst2->z_ctime[0],(unsigned long long)dst2->z_ctime[1]);

	
	/* if changed mtime, ctime must changed .but ctime changed,not sure mtime change or not */
	if (strcmp(dst1ctime, dst2ctime) >= 0) {
		*newtime_zp = dst1;
	} else if (strcmp(dst2ctime, dst1ctime) >= 0) {
		*newtime_zp = dst2;
	} else {
		*newtime_zp = NULL;
		return ENOTSUP;
	}

	return (0);
}

/*
 * Function : if master2 node is master too, change data_spa = data2_spa
 */
void zmc_adjust_data2_is_masterfile(znode_t* zp)
{
	if ((zp->z_group_id.data2_spa == zp->z_group_id.master_spa
			&& zp->z_group_id.data2_objset == zp->z_group_id.master_objset
			&& zp->z_group_id.data2_object == zp->z_group_id.master_object)
			|| (zp->z_group_id.data2_spa == zp->z_group_id.master2_spa
			&& zp->z_group_id.data2_objset == zp->z_group_id.master2_objset
			&& zp->z_group_id.data2_object == zp->z_group_id.master2_object)
			|| (zp->z_group_id.data2_spa == zp->z_group_id.master3_spa
			&& zp->z_group_id.data2_objset == zp->z_group_id.master3_objset
			&& zp->z_group_id.data2_object == zp->z_group_id.master3_object)
			|| (zp->z_group_id.data2_spa == zp->z_group_id.master4_spa
			&& zp->z_group_id.data2_objset == zp->z_group_id.master4_objset
			&& zp->z_group_id.data2_object == zp->z_group_id.master4_object)) {
			/*
			 * this znode is both a master file and a data2 file
			 *
			 * replace data1 fields with data2 fields, and so we can treat
			 * every data file as data1 file
			 */
			zp->z_group_id.data_spa = zp->z_group_id.data2_spa;
			zp->z_group_id.data_objset = zp->z_group_id.data2_objset;
			zp->z_group_id.data_object = zp->z_group_id.data2_object;
			zp->z_group_id.data_status = zp->z_group_id.data2_status;
		}
	
}


/*
 * Function : compare data1/data2 (inlcude master node info,type judge they are the same file)
 *
 */
int zmc_compare_data1_data2_info(struct inode * ip,zfs_group_object_t* robj1, zfs_group_object_t* robj2)
{
	int error = 0;
	zmc_sync_obj_t* sync_obj = NULL;
	znode_t* zp = NULL;
	zfs_sb_t *zsb = NULL;
	
	zp = ITOZ(ip);
	zsb = ZTOZSB(zp);
	sync_obj = (zmc_sync_obj_t*)(zsb->z_group_sync_obj);
	
	error = zmc_compare_data1_data2_node(robj1->master_spa, robj1->master_objset, robj1->master_object, robj1->master_gen,
							robj2->master_spa, robj2->master_objset, robj2->master_object, robj2->master_gen);
	if (error != 0) {	
		zmc_sync_log(sync_obj,"file data1 group_object master1  != data2 group_object master1");
		return (error);
	}
	
	error = zmc_compare_data1_data2_node(robj1->master2_spa, robj1->master2_objset, robj1->master2_object, robj1->master2_gen,
							robj2->master2_spa, robj2->master2_objset, robj2->master2_object, robj2->master2_gen);
	if (error != 0) {
		zmc_sync_log(sync_obj,"file data1 group_object master2  != data2 group_object master2");
		return (error);
	}
	
	error = zmc_compare_data1_data2_node(robj1->master3_spa, robj1->master3_objset, robj1->master3_object, robj1->master3_gen,
							robj2->master3_spa, robj2->master3_objset, robj2->master3_object, robj2->master3_gen);
	if (error != 0) {
		zmc_sync_log(sync_obj,"file data1 group_object master3  != data2 group_object master3");
		return (error);
	}
	
	error = zmc_compare_data1_data2_node(robj1->master4_spa, robj1->master4_objset, robj1->master4_object, robj1->master4_gen,
							robj2->master4_spa, robj2->master4_objset, robj2->master4_object, robj2->master4_gen);
	if (error != 0) {
		zmc_sync_log(sync_obj,"file data1 group_object master4  != data2 group_object master4");
		return (error);
	}

	return (error);
}

/*
 * Function : judge two node info
 */
int zmc_compare_data1_data2_node(uint64_t dst1_spa,uint64_t dst1_objset,uint64_t dst1_object,uint64_t dst1_gen,
											uint64_t dst2_spa,uint64_t dst2_objset,uint64_t dst2_object,uint64_t dst2_gen)
{
	int ret = 0;
	
	if (dst1_spa != dst2_spa || dst1_objset != dst2_objset
		|| dst1_object != dst2_object || dst1_gen != dst2_gen)
		ret = -1;
	
	return (ret);
}



