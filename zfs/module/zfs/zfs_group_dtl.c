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
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/dmu.h>
#include <sys/zio.h>
#include <sys/vdev_impl.h>
#include <sys/dmu_objset.h>
#include <sys/cmn_err.h>
#include <sys/zap.h>
#ifdef _KERNEL
#include <sys/zfs_multiclus.h>
#include <sys/zfs_group_dtl.h>
#include <sys/ddi.h>
#endif

#define	ZFS_GROUP_DTL_SECOND	1*1000*1000 /* 1s, base micro sec */
#define	ZFS_GROUP_DTL_SECOND_CVWAIT_TIME	(5*ZFS_GROUP_DTL_SECOND)	 /* 5s */
#define ZFS_GROUP_DTL_MICRO_SECOND	1*1000
#define ZFS_GROUP_DTL_ASSIGN_RETRY_MAX	100

int debug_zgroup_dtl = 0;
int debug_zgroup_dtl2 = 0;
int debug_nas_group_dtl = 0;
int ZFS_GROUP_DTL_ENABLE = 1;


int avl_num = 20;
#ifdef _KERNEL
int avl_num_max = ZFS_GROUP_DTL_AVL_NODE_MAX;
#endif
int avl_num_load_max = 0x5000;

const char *zfs_group_dtl_prefix = "zfs_group_dtl@";

static void zfs_group_dtl_thread_worker(void* arg);


/*
 * Data map routines.
 * NOTE: caller is responsible for all locking.
 */
static int
zfs_group_dtl_compare(const void *x1, const void *x2)
{
#ifdef _KERNEL
	zfs_group_dtl_node_t *s1 = (zfs_group_dtl_node_t *)x1;
	zfs_group_dtl_node_t *s2 = (zfs_group_dtl_node_t *)x2;

	if (s1->data.obj == s2->data.obj && 
		s1->data.gentime.tv_sec == s2->data.gentime.tv_sec &&
		s1->data.gentime.tv_nsec == s2->data.gentime.tv_nsec) {
		return (0);
	}

	if(s1->data.gentime.tv_sec > s2->data.gentime.tv_sec){
		return (1);
	}

	if(s1->data.gentime.tv_sec < s2->data.gentime.tv_sec){
		return (-1);
	}

	if(s1->data.gentime.tv_nsec > s2->data.gentime.tv_nsec){
		return (1);
	}

	if(s1->data.gentime.tv_nsec < s2->data.gentime.tv_nsec){
		return (-1);
	}

	if (s1->data.obj > s2->data.obj)
		return (1);

	else
		return (-1);
#else
	return 0;
#endif

}

void zfs_group_dtl_create(avl_tree_t* ptree)
{
#ifdef _KERNEL
	avl_create(ptree, zfs_group_dtl_compare, sizeof(zfs_group_dtl_node_t), offsetof(zfs_group_dtl_node_t, link));
#endif
}

void zfs_group_dtl_destroy(avl_tree_t* ptree)
{
#ifdef _KERNEL
	void *cookie = NULL;
 	zfs_group_dtl_node_t *node;
 
 	while ((node = avl_destroy_nodes(ptree, &cookie)) != NULL){
 		kmem_free(node, sizeof(zfs_group_dtl_node_t));
 	}
#endif
}

void
zfs_group_dtl_add(avl_tree_t *ptree, void* value, size_t size)
{
#ifdef _KERNEL
	avl_index_t where;
	zfs_group_dtl_node_t *ssearch, *ss;
	zfs_group_dtl_data_t *ssdata = value;

	if(avl_numnodes(ptree) > avl_num_max){
		cmn_err(CE_WARN, "[ERROR] %s %d dtl tree is full.", __func__, __LINE__);
		return;
	}
	
	ssearch = kmem_zalloc(sizeof(zfs_group_dtl_node_t), KM_SLEEP);

	ssearch->data.obj = ssdata->obj;
	ssearch->data.gentime = ssdata->gentime;
	ss = avl_find(ptree, ssearch, &where);

	if (ss != NULL) {
		cmn_err(CE_WARN, "[%s %d] ss is not NULL", __func__, __LINE__);
		kmem_free(ssearch, sizeof(zfs_group_dtl_node_t));
		return;
	}

	/* Make sure we don't overlap with either of our neighbors */
	VERIFY(ss == NULL);
	
	ss = kmem_zalloc(sizeof(zfs_group_dtl_node_t), KM_SLEEP);
	bcopy(value, &ss->data, size);
	avl_insert(ptree, ss, where);
	kmem_free(ssearch, sizeof(zfs_group_dtl_node_t));
#endif
}

#ifdef _KERNEL
void zfs_group_dtl_output(zfs_group_dtl_node_t* pnode)
{
	cmn_err(CE_WARN, "Current note obj[%llu], data u64 %s", 
		(unsigned long long)pnode->data.obj, pnode->data.data);
}

void zfs_group_dtl_output2(zfs_group_dtl_node_t* pnode)
{
	cmn_err(CE_WARN, "node time sec %ld, nsec %ld node obj[%llu]", 
		pnode->data.gentime.tv_sec, pnode->data.gentime.tv_nsec,(unsigned long long)pnode->data.obj);
}


void
zfs_group_dtl_walk(avl_tree_t *ptree, zfs_group_dtl_output_t func)
{
	zfs_group_dtl_node_t *dn;

	for (dn = avl_first(ptree); dn; dn = AVL_NEXT(ptree, dn))
	{
		func(dn);
	}
}

#endif

#ifdef _KERNEL
/*
* zfs_group_dtl_sync_treeX can sync NAS dtl from memory to disk obj's A segment or B segment.
* where : 0 - write to A segment.
*          : 1 - write to B segment.
*          A segment :  keep remained dtl entries since last dtl sync loop.
*          B segment :  keep dtl entries which has never been processed.
*/

void
zfs_group_dtl_sync_treeX(objset_t *os, zfs_multiclus_node_type_t master_type, int where)
{

	int err, assign_retry_cnt = 0;
	dmu_tx_t *tx = NULL;
	void *cookie = NULL;
	zfs_group_dtl_node_t *ss;
	dmu_buf_t *db = NULL;
	uint64_t bufsize;
	uint8_t *entry, *entry_map;
	uint64_t nodedatasize = 0, avail_size = 0, remain_size = 0, write_size = 0;
	uint64_t obj_size = 0;
	uint64_t dtl_obj;
	zfs_group_dtl_obj_t dtl_header = {0};
	zfs_sb_t * zsb = NULL;
	avl_tree_t* ptree;
	kmutex_t* ptree_mutex = NULL;
	kmutex_t* dtl_obj_mutex = NULL;
	uint8_t *data_buf = NULL;
	uint64_t* pdtl_obj_num = NULL;
	uint64_t  count = 0;

	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	if (zsb == NULL)
		return;

	rrm_enter(&zsb->z_teardown_lock, RW_READER, FTAG);

	switch(master_type){
		case ZFS_MULTICLUS_MASTER2:
			dtl_obj = zsb->z_group_dtl_obj;
			dtl_obj_mutex = &zsb->z_group_dtl_obj_mutex;
			ptree = &zsb->z_group_dtl_tree;
			ptree_mutex = &zsb->z_group_dtl_tree_mutex;
			pdtl_obj_num = &zsb->z_group_dtl_obj_num;
			break;
		case ZFS_MULTICLUS_MASTER3:
			dtl_obj = zsb->z_group_dtl_obj3;
			dtl_obj_mutex = &zsb->z_group_dtl_obj3_mutex;
			ptree = &zsb->z_group_dtl_tree3;
			ptree_mutex = &zsb->z_group_dtl_tree3_mutex;
			pdtl_obj_num = &zsb->z_group_dtl_obj3_num;
			break;
		case ZFS_MULTICLUS_MASTER4:
			dtl_obj = zsb->z_group_dtl_obj4;
			dtl_obj_mutex = &zsb->z_group_dtl_obj4_mutex;
			ptree = &zsb->z_group_dtl_tree4;
			ptree_mutex = &zsb->z_group_dtl_tree4_mutex;
			pdtl_obj_num = &zsb->z_group_dtl_obj4_num;
			break;
		default:
			rrm_exit(&zsb->z_teardown_lock, FTAG);
			return;
	}

	if(ptree == NULL || dtl_obj == 0){
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		return;
	}
		
	nodedatasize = sizeof(zfs_group_dtl_data_t);
	mutex_enter(ptree_mutex);
	count = avl_numnodes(ptree);
	mutex_exit(ptree_mutex);
	mutex_enter(dtl_obj_mutex);
	err = dmu_bonus_hold(os, dtl_obj, FTAG, &db);

	if(err != 0){
		mutex_exit(dtl_obj_mutex);
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		return;
	}
	
	bcopy(db->db_data, &dtl_header, sizeof (zfs_group_dtl_obj_t));
	dmu_buf_rele(db, FTAG);
	mutex_exit(dtl_obj_mutex);

	switch(where)
	{
		case 0:
			obj_size = dtl_header.last_rewrite;
			break;
		case 1:
			if(dtl_header.start_pos < nodedatasize * count){
					cmn_err(CE_WARN, "[Error] %s %d dtl_header.start_pos 0x%llx, nodedatasize * count 0x%llx",
						__func__, __LINE__, (unsigned long long)dtl_header.start_pos, (unsigned long long)(nodedatasize * count));
					rrm_exit(&zsb->z_teardown_lock, FTAG);
					return;
			}else{
				dtl_header.start_pos -= nodedatasize * count;
				obj_size = dtl_header.start_pos;
			}
			
			break;
		default:
			cmn_err(CE_WARN, "[Error] %s %d where is %d.", __func__, __LINE__, where);
			rrm_exit(&zsb->z_teardown_lock, FTAG);
			return;
	}

	if(count == 0) goto out;
	
	bufsize = count * nodedatasize;
	bufsize = MIN(bufsize, 1ULL << ZFS_GROUP_DTL_BLOCKSHIFT);
	entry_map = zio_buf_alloc(bufsize);
	
	entry = entry_map;
	avail_size = bufsize;
	remain_size = 0;
	
	if(entry_map != NULL){
		mutex_enter(ptree_mutex);
		while ((ss = avl_destroy_nodes(ptree, &cookie)) != NULL && count > 0) {
			count--;
			mutex_exit(ptree_mutex);
			remain_size = nodedatasize;
			while(remain_size > 0){
				write_size = MIN(avail_size, remain_size);
				data_buf = (uint8_t *)&ss->data;
				data_buf = data_buf + nodedatasize - remain_size;
				bcopy(data_buf, entry, write_size);
				if(avail_size > remain_size){
					avail_size = avail_size - write_size;
					remain_size -= write_size;
					entry += write_size;
				}else{
					remain_size -= write_size;
txg_retry:
					tx = dmu_tx_create(os);
					err = dmu_tx_assign(tx, TXG_WAIT);
					if (err != 0) {
						if (assign_retry_cnt < ZFS_GROUP_DTL_ASSIGN_RETRY_MAX) {
							assign_retry_cnt++;
							dmu_tx_abort(tx);
							zfs_group_wait(ZFS_GROUP_DTL_MICRO_SECOND * 100);
							goto txg_retry;
						}
						cmn_err(CE_WARN, "[Error] %s %d, dmu_tx_assign failed", __func__, __LINE__);
						avail_size = bufsize;
						obj_size += bufsize;
						entry = entry_map;
						dmu_tx_abort(tx);
						continue;
					}
				
					dmu_write(os, dtl_obj, obj_size,
						bufsize, entry_map, tx, B_FALSE);
					
					dmu_tx_commit(tx);
										
					avail_size = bufsize;
					obj_size += bufsize;
					entry = entry_map;
				}
			}
	
			kmem_free(ss, sizeof (zfs_group_dtl_node_t));
			mutex_enter(ptree_mutex);
		}
		mutex_exit(ptree_mutex);
		if (entry != entry_map) {
			tx = dmu_tx_create(os);
			err = dmu_tx_assign(tx, TXG_WAIT);
			if (err != 0) {
				dmu_tx_abort(tx);
			}
					
			if(err == 0){
				dmu_write(os, dtl_obj, obj_size,
				    entry - entry_map, entry_map, tx, B_FALSE);
				dmu_tx_commit(tx);
						
				obj_size += entry - entry_map; 
			}
		}

		zio_buf_free(entry_map, bufsize);
	}

out:
	mutex_enter(dtl_obj_mutex);
	tx = dmu_tx_create(os);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err != 0) {
		cmn_err(CE_WARN, "[Error] %s %d, dmu_tx_assign failed", __func__, __LINE__);
		dmu_tx_abort(tx);
		mutex_exit(dtl_obj_mutex);
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		return;
	}
		
	err = dmu_bonus_hold(os, dtl_obj, FTAG, &db);

	if(err != 0){
		mutex_exit(dtl_obj_mutex);
		dmu_tx_commit(tx);
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		return;
	}
	
	dmu_buf_will_dirty(db, tx);

	if(where == 1){
		((zfs_group_dtl_obj_t*)db->db_data)->start_pos = dtl_header.start_pos;
		*pdtl_obj_num = (dtl_header.end_pos - dtl_header.start_pos)/sizeof(zfs_group_dtl_data_t);
		if(1 == debug_nas_group_dtl){
			cmn_err(CE_WARN, "[yzy] %s %d, master_type %d, dtl_obj_num %llu", 
		    	__func__, __LINE__, master_type, (unsigned long long)*pdtl_obj_num);
		}
	}

	if(where == 0){
		((zfs_group_dtl_obj_t*)db->db_data)->last_rewrite = obj_size;
	}
		
	dmu_buf_rele(db, FTAG);
	dmu_tx_commit(tx);

	
	if(where == 1){
		if(dtl_header.start_pos > ZFS_GROUP_DTL_B_SEGMENT_START){
			dmu_free_long_range(zsb->z_os, dtl_obj, ZFS_GROUP_DTL_B_SEGMENT_START, 
				dtl_header.start_pos - ZFS_GROUP_DTL_B_SEGMENT_START);
		}
	}
				
	mutex_exit(dtl_obj_mutex);
	txg_wait_synced(dmu_objset_pool(os),0);

	mutex_enter(dtl_obj_mutex);
	tx = dmu_tx_create(os);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err != 0) {
		cmn_err(CE_WARN, "[Error] %s %d, dmu_tx_assign failed", __func__, __LINE__);
		dmu_tx_abort(tx);
		mutex_exit(dtl_obj_mutex);
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		return;
	}
	
	err = dmu_bonus_hold(os, dtl_obj, FTAG, &db);

	if(err != 0){
		mutex_exit(dtl_obj_mutex);
		dmu_tx_commit(tx);
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		return;
	}


	switch(where){
		case 0:
			/* Segment A is already written, clean  Segment B's old dtl data.*/
			((zfs_group_dtl_obj_t*)db->db_data)->start_pos = ((zfs_group_dtl_obj_t*)db->db_data)->last_read;
			break;
		case 1:
			/* Segment B is already written, clean  Segment A's old dtl data.*/
			((zfs_group_dtl_obj_t*)db->db_data)->last_rewrite = 0;
		default:
			break;
	}
		
	dmu_buf_rele(db, FTAG);
	dmu_tx_commit(tx);
	mutex_exit(dtl_obj_mutex);
		
	rrm_exit(&zsb->z_teardown_lock, FTAG);
}
#endif

/*
*        On Disk, zfs_group_dtl_obj layout is below.
*       ----------------------------------------
*       |      dtl 1     | xxxxx      ... ... xxxxx    | dtl 2  |                  
*       ----------------------------------------
*                         ^                                    ^
*                          |                                    |
*                        start                                end
*        When dtl1 is synced from memory to disk, it is write to disk from start to 0 offset, then update start_pos.
*        When dtl2 is synced from memory to disk, it is appended to the end of zfs_group_dtl_obj, then update end_pos.
*/

void
zfs_group_dtl_sync_tree134(objset_t *os)
{
#ifdef _KERNEL
	zfs_group_dtl_sync_treeX(os, ZFS_MULTICLUS_MASTER2, 0);
	zfs_group_dtl_sync_treeX(os, ZFS_MULTICLUS_MASTER3, 0);
	zfs_group_dtl_sync_treeX(os, ZFS_MULTICLUS_MASTER4, 0);
#endif
}


#ifdef _KERNEL
void zfs_group_dtl_init_obj(objset_t *os, zfs_sb_t *zsb, uint64_t *pobj, int idx)
{
	int err = 0;
	dmu_tx_t *tx = NULL;
	char *buf = NULL;
	dmu_buf_t *db = NULL;
	zfs_group_dtl_obj_t dtl_header = {0};

	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	
	tx = dmu_tx_create(os);			
	err = dmu_tx_assign(tx, TXG_WAIT);
	if(err != 0){
		dmu_tx_abort(tx);
		kmem_free(buf, MAXPATHLEN);
		cmn_err(CE_WARN, "[%s %d] dmu_tx_assign failed", __func__, __LINE__);
		return;
	}
	
	*pobj = dmu_object_alloc(os, DMU_OT_GROUP_DTL, 1 << ZFS_GROUP_DTL_BLOCKSHIFT,	
				DMU_OT_GROUP_DTL_HEADER, sizeof (zfs_group_dtl_obj_t), tx);
	if(*pobj == 0){
			cmn_err(CE_WARN, "[%s %d] failed in allocating zfs_group_dtl_obj!", __func__, __LINE__);
			dmu_tx_commit(tx);
			kmem_free(buf, MAXPATHLEN);
			cmn_err(CE_WARN, "[%s %d] dmu_tx_assign failed", __func__, __LINE__);
			return;
	}
	
	bzero(buf, MAXPATHLEN);
	sprintf(buf, "%s%d", zfs_group_dtl_prefix, idx);
	err = zap_add(os, MASTER_NODE_OBJ, buf, 8, 1, pobj, tx);
	if(err != 0){
		dmu_tx_commit(tx);
		kmem_free(buf, MAXPATHLEN);
		cmn_err(CE_WARN, "[%s %d] Failed in calling zap_add for zfs_group_dtl_prefix %s",
			__func__, __LINE__, buf);
		return;
	}

	err = dmu_bonus_hold(os, *pobj, FTAG, &db);
	if(err == 0){
		bcopy(db->db_data, &dtl_header, sizeof (zfs_group_dtl_obj_t));
		
		/* Reset A segment write pointer. */
		dtl_header.last_rewrite = 0;

		/* Reset B Segment read&write pointer */
		dtl_header.start_pos = ZFS_GROUP_DTL_B_SEGMENT_START;
		dtl_header.end_pos = dtl_header.start_pos;
		dtl_header.last_read = dtl_header.start_pos;
		bcopy(&dtl_header, db->db_data, sizeof (zfs_group_dtl_obj_t));
		dmu_buf_will_dirty(db, tx);
		dmu_buf_rele(db, FTAG);
	}else{
		cmn_err(CE_WARN, "[%s %d] error code %d", __func__, __LINE__, err);
	}

	dmu_tx_commit(tx);
	kmem_free(buf, MAXPATHLEN);
}
#endif

#ifdef _KERNEL
void
zfs_group_dtl_sync_tree2_nolock(objset_t *os, dmu_tx_t *ptx, zfs_sb_t *zsb)
{
	int err;
	dmu_tx_t *tx = ptx;
	void *cookie = NULL;
	zfs_group_dtl_node_t *ss;
	dmu_buf_t *db = NULL, *db3 = NULL, *db4 = NULL;
	uint64_t bufsize;
	uint8_t *entry, *entry_map;
	uint64_t nodedatasize = 0, avail_size = 0, remain_size = 0, write_size = 0;
	uint64_t obj_size = 0, obj3_size = 0, obj4_size = 0;
	uint64_t dtl_obj, dtl_obj3, dtl_obj4;
	zfs_group_dtl_obj_t dtl_header = {0};
	zfs_group_dtl_obj_t dtl_header3 = {0};
	zfs_group_dtl_obj_t dtl_header4 = {0};
	avl_tree_t* ptree;
	kmutex_t* ptree_mutex = NULL;
	uint8_t *data_buf = NULL;
	
	ptree = &zsb->z_group_dtl_tree2;
	ptree_mutex = &zsb->z_group_dtl_tree2_mutex;
	
	if(ptree == NULL || zsb->z_group_dtl_obj == 0
		|| zsb->z_group_dtl_obj3 == 0 || zsb->z_group_dtl_obj4 == 0) {
		cmn_err(CE_WARN, "[%s %d] dtl tree may not be initialized.", __func__, __LINE__);
		return;
	}
		
	dtl_obj = zsb->z_group_dtl_obj;
	dtl_obj3 = zsb->z_group_dtl_obj3;
	dtl_obj4 = zsb->z_group_dtl_obj4;

	nodedatasize = sizeof(zfs_group_dtl_data_t);
	mutex_enter(ptree_mutex);
	
	if(avl_numnodes(ptree) == 0){
		mutex_exit(ptree_mutex);
		return;
	} 

	mutex_enter(&zsb->z_group_dtl_obj_mutex);
	mutex_enter(&zsb->z_group_dtl_obj3_mutex);
	mutex_enter(&zsb->z_group_dtl_obj4_mutex);
	
	err = dmu_bonus_hold(os, dtl_obj, FTAG, &db);
	if(err != 0){
		mutex_exit(&zsb->z_group_dtl_obj4_mutex);
		mutex_exit(&zsb->z_group_dtl_obj3_mutex);
		mutex_exit(&zsb->z_group_dtl_obj_mutex);
		mutex_exit(ptree_mutex);
		cmn_err(CE_WARN, "[%s %d] dmu_bonus_hold dtl_obj=%"PRIu64" failed, err=%d", __func__, __LINE__, dtl_obj, err);
		return;
	}
	bcopy(db->db_data, &dtl_header, sizeof (zfs_group_dtl_obj_t));
	obj_size = dtl_header.end_pos;

	err = dmu_bonus_hold(os, dtl_obj3, FTAG, &db3);
	if(err != 0){
		dmu_buf_rele(db, FTAG);
		mutex_exit(&zsb->z_group_dtl_obj4_mutex);
		mutex_exit(&zsb->z_group_dtl_obj3_mutex);
		mutex_exit(&zsb->z_group_dtl_obj_mutex);
		mutex_exit(ptree_mutex);
		cmn_err(CE_WARN, "[%s %d] dmu_bonus_hold dtl_obj3=%"PRIu64" failed, err=%d", __func__, __LINE__, dtl_obj3, err);
		return;
	}
	bcopy(db3->db_data, &dtl_header3, sizeof (zfs_group_dtl_obj_t));
	obj3_size = dtl_header3.end_pos;

	err = dmu_bonus_hold(os, dtl_obj4, FTAG, &db4);
	if(err != 0){
		dmu_buf_rele(db, FTAG);
		dmu_buf_rele(db3, FTAG);
		mutex_exit(&zsb->z_group_dtl_obj4_mutex);
		mutex_exit(&zsb->z_group_dtl_obj3_mutex);
		mutex_exit(&zsb->z_group_dtl_obj_mutex);
		mutex_exit(ptree_mutex);
		cmn_err(CE_WARN, "[%s %d] dmu_bonus_hold dtl_obj4=%"PRIu64" failed, err=%d", __func__, __LINE__, dtl_obj4, err);
		return;
	}
	bcopy(db4->db_data, &dtl_header4, sizeof (zfs_group_dtl_obj_t));
	obj4_size = dtl_header4.end_pos;
	
	bufsize = (avl_numnodes(ptree)) * nodedatasize;
	bufsize = MIN(bufsize, 1ULL << ZFS_GROUP_DTL_BLOCKSHIFT);
	entry_map = zio_buf_alloc(bufsize);
	entry = entry_map;
	avail_size = bufsize;
	remain_size = 0;
		
	while ((ss = avl_destroy_nodes(ptree, &cookie)) != NULL) {
		remain_size = nodedatasize;
		while(remain_size > 0){
			write_size = MIN(avail_size, remain_size);
			data_buf = (uint8_t *)&ss->data;
			data_buf = data_buf + nodedatasize - remain_size;
			bcopy(data_buf, entry, write_size);
			if(avail_size > remain_size){
				avail_size = avail_size - write_size;
				remain_size -= write_size;
				entry += write_size;
			}else{
				remain_size -= write_size;
				if(tx == NULL){
					tx = dmu_tx_create(os);
					err = dmu_tx_assign(tx, TXG_WAIT);
					if (err != 0) {
						cmn_err(CE_WARN, "[Error] %s %d, dmu_tx_assign failed", __func__, __LINE__);
						zio_buf_free(entry_map, bufsize);
						dmu_buf_rele(db, FTAG);
						dmu_buf_rele(db3, FTAG);
						dmu_buf_rele(db4, FTAG);
						dmu_tx_abort(tx);
						mutex_exit(&zsb->z_group_dtl_obj4_mutex);
						mutex_exit(&zsb->z_group_dtl_obj3_mutex);
						mutex_exit(&zsb->z_group_dtl_obj_mutex);
						mutex_exit(ptree_mutex);
						return;
					}
				}
				dmu_write(os, dtl_obj, obj_size,
					bufsize, entry_map, tx, B_FALSE);
				dmu_write(os, dtl_obj3, obj3_size,
					bufsize, entry_map, tx, B_FALSE);
				dmu_write(os, dtl_obj4, obj4_size,
					bufsize, entry_map, tx, B_FALSE);
				if(ptx == NULL){
					dmu_tx_commit(tx);
					tx = NULL;
				}
				avail_size = bufsize;
				obj_size  += bufsize;
				obj3_size += bufsize;
				obj4_size += bufsize;
				entry = entry_map;
			}
		}
	
		kmem_free(ss, sizeof (zfs_group_dtl_node_t));
	}
	if (entry != entry_map) {
		if(tx == NULL){
			tx = dmu_tx_create(os);
			err = dmu_tx_assign(tx, TXG_WAIT);
			if (err != 0) {
				dmu_tx_abort(tx);
				tx = NULL;
			}
		}
		if(err == 0){
			dmu_write(os, dtl_obj, obj_size,
				entry - entry_map, entry_map, tx, B_FALSE);
			dmu_write(os, dtl_obj3, obj3_size,
				entry - entry_map, entry_map, tx, B_FALSE);
			dmu_write(os, dtl_obj4, obj4_size,
				entry - entry_map, entry_map, tx, B_FALSE);
			if(ptx == NULL){
				dmu_tx_commit(tx);
				tx = NULL;
			}
			obj_size  += entry - entry_map;
			obj3_size += entry - entry_map;
			obj4_size += entry - entry_map;
		}
	}
	zio_buf_free(entry_map, bufsize);
	if(tx == NULL){
		tx = dmu_tx_create(os);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if (err != 0) {
			cmn_err(CE_WARN, "[Error] %s %d, dmu_tx_assign failed", __func__, __LINE__);
			dmu_buf_rele(db, FTAG);
			dmu_buf_rele(db3, FTAG);
			dmu_buf_rele(db4, FTAG);
			dmu_tx_abort(tx);
			mutex_exit(&zsb->z_group_dtl_obj4_mutex);
			mutex_exit(&zsb->z_group_dtl_obj3_mutex);
			mutex_exit(&zsb->z_group_dtl_obj_mutex);
			mutex_exit(ptree_mutex);
			return;
		}
	}

	dmu_buf_will_dirty(db, tx);
	dmu_buf_will_dirty(db3, tx);
	dmu_buf_will_dirty(db4, tx);
	dtl_header.end_pos = obj_size;
	dtl_header3.end_pos = obj3_size;
	dtl_header4.end_pos = obj4_size;
	bcopy(&dtl_header, db->db_data, sizeof (zfs_group_dtl_obj_t));
	dmu_buf_rele(db, FTAG);
	bcopy(&dtl_header3, db3->db_data, sizeof (zfs_group_dtl_obj_t));
	dmu_buf_rele(db3, FTAG);
	bcopy(&dtl_header4, db4->db_data, sizeof (zfs_group_dtl_obj_t));
	dmu_buf_rele(db4, FTAG);
	if(ptx == NULL){
		dmu_tx_commit(tx);
	}
	mutex_exit(&zsb->z_group_dtl_obj4_mutex);
	mutex_exit(&zsb->z_group_dtl_obj3_mutex);
	mutex_exit(&zsb->z_group_dtl_obj_mutex);
	mutex_exit(ptree_mutex);
}
#endif

void
zfs_group_dtl_sync_tree2(objset_t *os, dmu_tx_t *ptx, int zfsvfs_holden)
{
#ifdef _KERNEL
	zfs_sb_t *zsb = NULL;

	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	if (zsb == NULL) {
		cmn_err(CE_WARN, "[%s %d] get zsb failed.", __func__, __LINE__);
		return;
	}

	if (zfsvfs_holden == 0) {
		atomic_inc_not_zero(&zsb->z_sb->s_active);
		rrm_enter(&zsb->z_teardown_lock, RW_READER, FTAG);
	}

	zfs_group_dtl_sync_tree2_nolock(os, ptx, zsb);

	if (zfsvfs_holden == 0) {
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		deactivate_super(zsb->z_sb);
	}
#endif
}

#ifdef _KERNEL
/*
* zfs_group_dtl_loadX can load NAS dtl from disk obj's A segment or B segment.
* from : 0 - load from A segment.
*         : 1 - load from B segment.
*         A segment :  keep remained dtl entries since last dtl sync loop.
*         B segment :  keep dtl entries which has never been processed.
*/
void
zfs_group_dtl_loadX(objset_t *os, zfs_multiclus_node_type_t master_type, int from)
{

	uint8_t *entry, *entry_map;
	uint64_t bufsize, offset, offset_tmp, end;
	dmu_tx_t *tx = NULL;
	int error = 0;
	dmu_buf_t *db = NULL;
	uint64_t dtl_obj;
	zfs_sb_t *zsb = NULL;
	zfs_group_dtl_obj_t dtl_header;
	uint64_t nodedatasize = 0, avail_size = 0, read_size = 0, copied_size = 0, copy_size = 0;
	zfs_group_dtl_node_t* pss;
	avl_tree_t* ptree = NULL;
	uint8_t *dtl_node_data = NULL;
	kmutex_t* ptree_mutex = NULL;
	kmutex_t* pdtl_obj_mutex = NULL;
	int avl_tree_num = 0;
	uint64_t* pdtl_obj_num = NULL;

	nodedatasize = sizeof(zfs_group_dtl_data_t);
	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	if (zsb == NULL)
		return;

	rrm_enter(&zsb->z_teardown_lock, RW_READER, FTAG);

	pss=kmem_alloc(sizeof(zfs_group_dtl_node_t), KM_SLEEP);
	bzero(pss, sizeof(zfs_group_dtl_node_t));
	dtl_node_data = (uint8_t*)&pss->data;


	switch(master_type){
		case ZFS_MULTICLUS_MASTER2:
			dtl_obj = zsb->z_group_dtl_obj;
			ptree = &zsb->z_group_dtl_tree;
			ptree_mutex = &zsb->z_group_dtl_tree_mutex;
			pdtl_obj_num = &zsb->z_group_dtl_obj_num;
			pdtl_obj_mutex = &zsb->z_group_dtl_obj_mutex;
			break;
		case ZFS_MULTICLUS_MASTER3:
			dtl_obj = zsb->z_group_dtl_obj3;
			ptree = &zsb->z_group_dtl_tree3;
			ptree_mutex = &zsb->z_group_dtl_tree3_mutex;
			pdtl_obj_num = &zsb->z_group_dtl_obj3_num;
			pdtl_obj_mutex = &zsb->z_group_dtl_obj3_mutex;
			break;
		case ZFS_MULTICLUS_MASTER4:
			dtl_obj = zsb->z_group_dtl_obj4;
			ptree = &zsb->z_group_dtl_tree4;
			ptree_mutex = &zsb->z_group_dtl_tree4_mutex;
			pdtl_obj_num = &zsb->z_group_dtl_obj4_num;
			pdtl_obj_mutex = &zsb->z_group_dtl_obj4_mutex;
			break;
		default:
			kmem_free(pss, sizeof(zfs_group_dtl_node_t));
			rrm_exit(&zsb->z_teardown_lock, FTAG);
			return;
	}

	mutex_enter(pdtl_obj_mutex);
	if ((error = dmu_bonus_hold(os, dtl_obj, FTAG, &db)) != 0){
		mutex_exit(pdtl_obj_mutex);
		kmem_free(pss, sizeof(zfs_group_dtl_node_t));
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		return;
	}
		
	bcopy(db->db_data, &dtl_header, sizeof(zfs_group_dtl_obj_t));
	dmu_buf_rele(db, FTAG);
	mutex_exit(pdtl_obj_mutex);
	*pdtl_obj_num = (dtl_header.end_pos - dtl_header.start_pos)/nodedatasize;

	switch(from){
		case 0:
			offset_tmp = 0;
			end = dtl_header.last_rewrite;
			break;
		case 1:
			offset_tmp = dtl_header.start_pos;
			end = dtl_header.end_pos;
			break;
		default:
			kmem_free(pss, sizeof(zfs_group_dtl_node_t));
			rrm_exit(&zsb->z_teardown_lock, FTAG);
			return;
	}

	bufsize = 1ULL << ZFS_GROUP_DTL_BLOCKSHIFT;
	entry_map = zio_buf_alloc(bufsize);
	entry = entry_map;
	copied_size = 0;
	mutex_enter(ptree_mutex);
	avl_tree_num = avl_numnodes(ptree);
	mutex_exit(ptree_mutex);
	
	for (offset = offset_tmp; offset < end && avl_tree_num < avl_num_load_max; offset += read_size) {
		read_size = MIN(end - offset, bufsize);
	
		error = dmu_read(os, dtl_obj, offset, read_size, entry_map,
			DMU_READ_PREFETCH);
		if (error != 0){
			cmn_err(CE_WARN, "[Error] zfs group dtl obj read error %d.", error);
			break;
		}
		
		entry = entry_map;
		avail_size = read_size;
		while(entry < entry_map + read_size){
			copy_size = MIN(nodedatasize - copied_size, avail_size);
			bcopy(entry, dtl_node_data + copied_size, copy_size);
			avail_size -= copy_size;
			entry += copy_size;
			copied_size += copy_size;
			if(copied_size == nodedatasize){
				mutex_enter(ptree_mutex);
				zfs_group_dtl_add(ptree, &pss->data, nodedatasize);
				mutex_exit(ptree_mutex);
				avl_tree_num = avl_numnodes(ptree);
				copied_size = 0;
			}
		}
	}
	offset -= avail_size;
	offset -= copied_size;

	mutex_enter(pdtl_obj_mutex);
	if ((error = dmu_bonus_hold(os, dtl_obj, FTAG, &db)) != 0){
		mutex_exit(pdtl_obj_mutex);
		zio_buf_free(entry_map, bufsize);
		kmem_free(pss, sizeof(zfs_group_dtl_node_t));
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		return;
	}

	switch(from){
		case 0:
			break;
		case 1:
			((zfs_group_dtl_obj_t*)db->db_data)->last_read = offset;
			break;
		default:
			break;
	}
	
	tx = dmu_tx_create(os);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error != 0) {
		cmn_err(CE_WARN, "[Error] %s %d, dmu_tx_assign failed", __func__, __LINE__);
		dmu_buf_rele(db, FTAG);
		dmu_tx_abort(tx);
	}else{
		dmu_buf_will_dirty(db, tx);
		dmu_buf_rele(db, FTAG);
		dmu_tx_commit(tx);
	}
	mutex_exit(pdtl_obj_mutex);
	txg_wait_synced(dmu_objset_pool(os),0);
	zio_buf_free(entry_map, bufsize);
	kmem_free(pss, sizeof(zfs_group_dtl_node_t));
	rrm_exit(&zsb->z_teardown_lock, FTAG);
	return;
}
#endif


void
zfs_group_dtl_load(objset_t *os)
{
#ifdef _KERNEL
	zfs_group_dtl_loadX(os, ZFS_MULTICLUS_MASTER2, 0);
	zfs_group_dtl_sync_treeX(os, ZFS_MULTICLUS_MASTER2, 1);
	zfs_group_dtl_loadX(os, ZFS_MULTICLUS_MASTER2, 1);

	zfs_group_dtl_loadX(os, ZFS_MULTICLUS_MASTER3, 0);
	zfs_group_dtl_sync_treeX(os, ZFS_MULTICLUS_MASTER3, 1);
	zfs_group_dtl_loadX(os, ZFS_MULTICLUS_MASTER3, 1);

	zfs_group_dtl_loadX(os, ZFS_MULTICLUS_MASTER4, 0);
	zfs_group_dtl_sync_treeX(os, ZFS_MULTICLUS_MASTER4, 1);
	zfs_group_dtl_loadX(os, ZFS_MULTICLUS_MASTER4, 1);

#endif
	return;
}


int zfs_get_dtltree_status(uint64_t *numarray, char* fs_name)
{
#ifdef _KERNEL
	int error = 0;
	zfs_sb_t *zsb = NULL;
	objset_t *os = NULL;
	
	if (zfs_multiclus_enable() == B_FALSE)
		return (-1);

	if (!ZFS_GROUP_DTL_ENABLE)
		return (-1);
	if ((error = dmu_objset_hold(fs_name, FTAG, &os))){
		return (error);
	}

	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	if (zsb == NULL){
		dmu_objset_rele(os, FTAG);
		return -1;
	}

	atomic_inc_not_zero(&zsb->z_sb->s_active);

	rrm_enter(&zsb->z_teardown_lock, RW_READER, FTAG);
	mutex_enter(&zsb->z_group_dtl_tree_mutex);
	numarray[0] = avl_numnodes(&zsb->z_group_dtl_tree);
	mutex_exit(&zsb->z_group_dtl_tree_mutex);

	mutex_enter(&zsb->z_group_dtl_tree3_mutex);
	numarray[1] = avl_numnodes(&zsb->z_group_dtl_tree3);
	mutex_exit(&zsb->z_group_dtl_tree3_mutex);
	mutex_enter(&zsb->z_group_dtl_tree4_mutex);
	numarray[2] = avl_numnodes(&zsb->z_group_dtl_tree4);
	mutex_exit(&zsb->z_group_dtl_tree4_mutex);
	numarray[3] = zsb->z_group_dtl_obj_num;
	numarray[4] = zsb->z_group_dtl_obj3_num;
	numarray[5] = zsb->z_group_dtl_obj4_num;
	
	rrm_exit(&zsb->z_teardown_lock, FTAG);
	deactivate_super(zsb->z_sb);
	dmu_objset_rele(os, FTAG);

	if(1 == debug_nas_group_dtl){
		cmn_err(CE_WARN, "[lrc] %s %d count %llu", __func__, __LINE__, 
			(unsigned long long)numarray[0]);
		cmn_err(CE_WARN, "[lrc] %s %d count3 %llu", __func__, __LINE__, 
			(unsigned long long)numarray[1]);
		cmn_err(CE_WARN, "[lrc] %s %d count4 %llu", __func__, __LINE__, 
			(unsigned long long)numarray[2]);
	}

#endif
	return 0;
}

void
zfs_group_dtl_reset(objset_t *os, dmu_tx_t *ptx)
{
#ifdef _KERNEL
	int err;
	dmu_tx_t *tx = ptx;
	dmu_buf_t *db = NULL;
	uint64_t dtl_obj = 0;
	zfs_group_dtl_obj_t dtl_header = {0};
	zfs_sb_t * zsb = NULL;
	char *buf = NULL;
	avl_tree_t* ptree = NULL;
	kmutex_t* ptree_mutex = NULL;
	kmutex_t* ptree2_mutex = NULL;
	kmutex_t* ptree3_mutex = NULL;
	kmutex_t* ptree4_mutex = NULL;
	int i;
	
	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	
	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	if (zsb == NULL){
		kmem_free(buf, MAXPATHLEN);
		return;
	}

	atomic_inc_not_zero(&zsb->z_sb->s_active);
	rrm_enter(&zsb->z_teardown_lock, RW_READER, FTAG);

	ptree_mutex = &zsb->z_group_dtl_tree_mutex;
	ptree2_mutex = &zsb->z_group_dtl_tree2_mutex;
	ptree3_mutex = &zsb->z_group_dtl_tree3_mutex;
	ptree4_mutex = &zsb->z_group_dtl_tree4_mutex;
	mutex_enter(ptree_mutex);
	mutex_enter(ptree2_mutex);
	mutex_enter(ptree3_mutex);
	mutex_enter(ptree4_mutex);
	mutex_enter(&zsb->z_group_dtl_obj_mutex);
	mutex_enter(&zsb->z_group_dtl_obj3_mutex);
	mutex_enter(&zsb->z_group_dtl_obj4_mutex);

	for(i=0;i<3;i++)
	{
		if(i==0)
			dtl_obj = zsb->z_group_dtl_obj;
		if(i==1)
			dtl_obj = zsb->z_group_dtl_obj3;
		if(i==2)
			dtl_obj = zsb->z_group_dtl_obj4;

		if(dtl_obj == 0){
			continue;
		}

		err = dmu_bonus_hold(os, dtl_obj, FTAG, &db);

		if(err != 0){
			continue;
		}
	
		bcopy(db->db_data, &dtl_header, sizeof (zfs_group_dtl_obj_t));
	
		dmu_free_long_range(zsb->z_os, dtl_obj, 0, dtl_header.end_pos);

		/* Reset A segment write pointer. */
		dtl_header.last_rewrite = 0;

		/* Reset B Segment read&write pointer */
		dtl_header.start_pos = ZFS_GROUP_DTL_B_SEGMENT_START;
		dtl_header.end_pos = dtl_header.start_pos;
		dtl_header.last_read = dtl_header.start_pos;

		bcopy(&dtl_header, db->db_data, sizeof (zfs_group_dtl_obj_t));
		if(tx == NULL){
			tx = dmu_tx_create(os);
			err = dmu_tx_assign(tx, TXG_WAIT);
			if (err != 0) {
				cmn_err(CE_WARN, "[Error] %s %d, dmu_tx_assign failed", __func__, __LINE__);
				
				dmu_buf_rele(db, FTAG);
				dmu_tx_abort(tx);
				mutex_exit(&zsb->z_group_dtl_obj4_mutex);
				mutex_exit(&zsb->z_group_dtl_obj3_mutex);
				mutex_exit(&zsb->z_group_dtl_obj_mutex);
				mutex_exit(ptree4_mutex);
				mutex_exit(ptree3_mutex);
				mutex_exit(ptree2_mutex);
				
				mutex_exit(ptree_mutex);
				rrm_exit(&zsb->z_teardown_lock, FTAG);
				deactivate_super(zsb->z_sb);
				kmem_free(buf, MAXPATHLEN);
				return;
			}
		}
		dmu_buf_will_dirty(db, tx);
		dmu_buf_rele(db, FTAG);
		if(ptx == NULL){
			dmu_tx_commit(tx);
			tx = ptx;
		}
	}
	
	ptree = &zsb->z_group_dtl_tree;
	zfs_group_dtl_destroy(ptree);

	ptree = &zsb->z_group_dtl_tree2;
	zfs_group_dtl_destroy(ptree);

	ptree = &zsb->z_group_dtl_tree3;
	zfs_group_dtl_destroy(ptree);

	ptree = &zsb->z_group_dtl_tree4;
	zfs_group_dtl_destroy(ptree);
	mutex_exit(&zsb->z_group_dtl_obj4_mutex);
	mutex_exit(&zsb->z_group_dtl_obj3_mutex);
	mutex_exit(&zsb->z_group_dtl_obj_mutex);

	mutex_exit(ptree4_mutex);
	mutex_exit(ptree3_mutex);
	mutex_exit(ptree2_mutex);
	mutex_exit(ptree_mutex);
	

	rrm_exit(&zsb->z_teardown_lock, FTAG);
	deactivate_super(zsb->z_sb);
	kmem_free(buf, MAXPATHLEN);
	
#endif
}


void zfs_group_dtl_test(char *fsname)
{
#ifdef _KERNEL
	int err = 0, i;
	objset_t *os = NULL;
	zfs_group_dtl_data_t* ssdata;
	zfs_sb_t *zsb = NULL;
	avl_tree_t* ptree = NULL;
	kmutex_t *ptree_mutex = NULL;
	
	if ((err = dmu_objset_hold(fsname, FTAG, &os))){
		cmn_err(CE_WARN, "%s: dmu_objset_hold FAIL !!!", __func__);
		return;
	}

	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	if (zsb == NULL) {
		dmu_objset_rele(os, FTAG);
		return;
	}

	atomic_inc_not_zero(&zsb->z_sb->s_active);
	rrm_enter(&zsb->z_teardown_lock, RW_READER, FTAG);
	ptree = &zsb->z_group_dtl_tree2;
	ptree_mutex = &zsb->z_group_dtl_tree2_mutex;
	
	if(debug_zgroup_dtl){
		ssdata = kmem_alloc(sizeof(zfs_group_dtl_data_t), KM_SLEEP);
		for(i = avl_num; i > 1;i --)
		{
			ssdata->obj = i;
			sprintf((char*)ssdata->data, "test string %d", i);
			ssdata->data_size = strlen((char*)ssdata->data);
			gethrestime(&ssdata->gentime);
			mutex_enter(ptree_mutex);
			zfs_group_dtl_add(ptree, ssdata, sizeof(zfs_group_dtl_data_t));
			mutex_exit(ptree_mutex);
		}
		rrm_exit(&zsb->z_teardown_lock, FTAG);

		deactivate_super(zsb->z_sb);
		kmem_free(ssdata, sizeof(zfs_group_dtl_data_t));
		cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
		zfs_group_dtl_walk(ptree, zfs_group_dtl_output2);
		cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
		zfs_group_dtl_walk(ptree, zfs_group_dtl_output);
		cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
		zfs_group_dtl_sync_tree2(os, NULL, 1);
		
		cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
	}else{
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		deactivate_super(zsb->z_sb);
	}

	if(debug_zgroup_dtl2){
		zfs_group_dtl_load(os);
		ptree = &zsb->z_group_dtl_tree;
		cmn_err(CE_WARN, "[yzy] %s %d avl_numnodes(ptree) %lu", 
			__func__, __LINE__, avl_numnodes(ptree));
		zfs_group_dtl_walk(ptree, zfs_group_dtl_output2);
		cmn_err(CE_WARN, "[yzy] %s %d avl_numnodes(ptree) %lu", 
			__func__, __LINE__, avl_numnodes(ptree));
		zfs_group_dtl_walk(ptree, zfs_group_dtl_output);
		zfs_group_dtl_sync_tree134(os);
	}

	atomic_inc_not_zero(&zsb->z_sb->s_active);

	rrm_enter(&zsb->z_teardown_lock, RW_READER, FTAG);
	ptree = &zsb->z_group_dtl_tree2;
	ptree_mutex = &zsb->z_group_dtl_tree2_mutex;
	if(debug_zgroup_dtl){
		ssdata = kmem_alloc(sizeof(zfs_group_dtl_data_t), KM_SLEEP);
		for(i = avl_num; i > 1;i --)
		{
			ssdata->obj = i;
			sprintf((char*)ssdata->data, "test string %d", i);
			ssdata->data_size = strlen((char*)ssdata->data);
			gethrestime(&ssdata->gentime);
			mutex_enter(ptree_mutex);
			zfs_group_dtl_add(ptree, ssdata, sizeof(zfs_group_dtl_data_t));
			mutex_exit(ptree_mutex);
		}
		rrm_exit(&zsb->z_teardown_lock, FTAG);

		deactivate_super(zsb->z_sb);
		kmem_free(ssdata, sizeof(zfs_group_dtl_data_t));
		cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
		zfs_group_dtl_walk(ptree, zfs_group_dtl_output2);
		cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
		zfs_group_dtl_walk(ptree, zfs_group_dtl_output);
		cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
		zfs_group_dtl_sync_tree2(os, NULL, 1);
		cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
	}else{
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		deactivate_super(zsb->z_sb);
	}
	
	if(debug_zgroup_dtl2){
		zfs_group_dtl_load(os);
		ptree = &zsb->z_group_dtl_tree;
		cmn_err(CE_WARN, "[yzy] %s %d avl_numnodes(ptree) %lu", 
			__func__, __LINE__, avl_numnodes(ptree));
		zfs_group_dtl_walk(ptree, zfs_group_dtl_output2);
		cmn_err(CE_WARN, "[yzy] %s %d avl_numnodes(ptree) %lu", 
			__func__, __LINE__, avl_numnodes(ptree));
		zfs_group_dtl_walk(ptree, zfs_group_dtl_output);
		zfs_group_dtl_sync_tree134(os);
	}
	dmu_objset_rele(os, FTAG);
#endif
}

#ifdef _KERNEL
static zfs_group_dtl_carrier_t *
zfs_group_dtl_carry_create(name_operation_t z_op, znode_t *pzp,	char *name,
vattr_t *vap, int ex, int mode, znode_t *zp, cred_t *credp, int flag, vsecattr_t *vsap)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;
	int namesize = 0;
	vattr_t *vattr = NULL;
	
	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	if(NULL == z_carrier) {
		cmn_err(CE_WARN, "[%s %d] alloc z_carrier failed.", __func__, __LINE__);
		return (z_carrier);
	}
	
	z_carrier->z_op = z_op;
	z_carrier->z_dtl.create.dir_zid = pzp->z_id;
	z_carrier->z_dtl.create.dir_os_id = dmu_objset_id(ZTOZSB(pzp)->z_os);
	z_carrier->z_dtl.create.dir_spa_id = spa_guid(dmu_objset_spa(ZTOZSB(pzp)->z_os));
	z_carrier->z_dtl.create.dir_gen = pzp->z_gen;
	z_carrier->z_dtl.create.zid = zp->z_id;
	z_carrier->z_dtl.create.os_id = dmu_objset_id(ZTOZSB(pzp)->z_os);
	z_carrier->z_dtl.create.spa_id = spa_guid(dmu_objset_spa(ZTOZSB(pzp)->z_os));
	z_carrier->z_dtl.create.gen = zp->z_gen;

	if (name != NULL)
		namesize = MIN(strlen(name), MAXNAMELEN-1);
	if (namesize > 0) {
		bcopy(name, z_carrier->z_dtl.create.name, namesize);
		z_carrier->z_dtl.create.name[namesize] = '\0';
	}

	if(vap != NULL)
		z_carrier->z_dtl.create.xvap = *((xvattr_t*)vap);
	else
		bzero(&z_carrier->z_dtl.create.xvap, sizeof(xvattr_t));

	vattr = &z_carrier->z_dtl.create.xvap.xva_vattr;
	if (!(vattr->va_mask & AT_MTIME)) {
		ZFS_TIME_DECODE(&vattr->va_mtime, zp->z_mtime);
		vattr->va_mask |= AT_MTIME;
	}
	z_carrier->z_dtl.create.isvapcarry = B_TRUE;

	if(vsap != NULL) {
		if(vsap->vsa_aclcnt > ZFS_GROUP_DTL_ACL_ENTRY_MAX){
			cmn_err(CE_WARN, "[ERROR] %s vsap->vsa_aclcnt %d, vsap->vsa_aclentsz %lu", 
				__func__, vsap->vsa_aclcnt, vsap->vsa_aclentsz);
		}
		z_carrier->z_dtl.create.vsap.vsa_aclcnt = MIN(vsap->vsa_aclcnt, ZFS_GROUP_DTL_ACL_ENTRY_MAX);
		z_carrier->z_dtl.create.vsap.vsa_dfaclcnt = 
			vsap->vsa_dfaclcnt < ZFS_GROUP_DTL_ACL_ENTRY_MAX ? vsap->vsa_dfaclcnt : 0;
		z_carrier->z_dtl.create.vsap.vsa_aclflags = vsap->vsa_aclflags;
		z_carrier->z_dtl.create.vsap.vsa_mask = vsap->vsa_mask;
		z_carrier->z_dtl.create.vsap.vsa_aclentsz = MIN(vsap->vsa_aclentsz, 0xc * ZFS_GROUP_DTL_ACL_ENTRY_MAX);
		bcopy(vsap->vsa_aclentp, z_carrier->z_dtl.create.vsap.vsa_aclentp, 
		   z_carrier->z_dtl.create.vsap.vsa_aclentsz);
		z_carrier->z_dtl.create.isvsapcarry = B_TRUE;
	}else{
		bzero(&z_carrier->z_dtl.create.vsap, sizeof(zfs_group_dtl_vsecattr_t));
		z_carrier->z_dtl.create.isvsapcarry = B_FALSE;
	}
	
	z_carrier->z_dtl.create.ex = ex;
	z_carrier->z_dtl.create.mode = mode;
	z_carrier->z_dtl.create.flag = flag;
	
	zfs_group_set_cred(credp, &z_carrier->z_dtl.create.cred);

	return(z_carrier);
}

static zfs_group_dtl_carrier_t *
zfs_group_dtl_carry_remove(name_operation_t z_op, znode_t *pzp, char *name,
 cred_t *credp, int flag)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;
	int namesize = 0;

	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	if(NULL == z_carrier) {
		cmn_err(CE_WARN, "[%s %d] alloc z_carrier failed.", __func__, __LINE__);
		return (z_carrier);
	}
	
	z_carrier->z_op = z_op;
	z_carrier->z_dtl.remove.group_id = pzp->z_group_id;
	z_carrier->z_dtl.remove.os_id = dmu_objset_id(ZTOZSB(pzp)->z_os);
	z_carrier->z_dtl.remove.spa_id = spa_guid(dmu_objset_spa(ZTOZSB(pzp)->z_os));
	z_carrier->z_dtl.remove.dirid = pzp->z_id;
	z_carrier->z_dtl.remove.dirlowdata = pzp->z_dirlowdata;
	z_carrier->z_dtl.remove.dirquota = pzp->z_dirquota;
	bcopy(pzp->z_filename, z_carrier->z_dtl.remove.dirname, MAXNAMELEN);
	
	if (name != NULL)
		namesize = MIN(strlen(name), MAXNAMELEN-1);
	if (namesize > 0) {
		bcopy(name, z_carrier->z_dtl.remove.name, namesize);
		z_carrier->z_dtl.remove.name[namesize] = '\0';
	}

	z_carrier->z_dtl.remove.flag = flag;
	
	zfs_group_set_cred(credp, &z_carrier->z_dtl.remove.cred);

	return(z_carrier);
}

static zfs_group_dtl_carrier_t *
zfs_group_dtl_carry_mkdir(name_operation_t z_op, znode_t *pzp, char *name, 
vattr_t *vap, znode_t *zp,	cred_t *credp, int flag, vsecattr_t *vsap)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;
	int namesize = 0;

	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	if(NULL == z_carrier) {
		cmn_err(CE_WARN, "[%s %d] alloc z_carrier failed.", __func__, __LINE__);
		return (z_carrier);
	}
	
	z_carrier->z_op = z_op;
	z_carrier->z_dtl.mkdir.dir_zid = pzp->z_id;
	z_carrier->z_dtl.mkdir.dir_os_id = dmu_objset_id(ZTOZSB(pzp)->z_os);
	z_carrier->z_dtl.mkdir.dir_spa_id = spa_guid(dmu_objset_spa(ZTOZSB(pzp)->z_os));
	z_carrier->z_dtl.mkdir.dir_gen = pzp->z_gen;
	z_carrier->z_dtl.mkdir.zid = zp->z_id;
	z_carrier->z_dtl.mkdir.os_id = dmu_objset_id(ZTOZSB(zp)->z_os);
	z_carrier->z_dtl.mkdir.spa_id = spa_guid(dmu_objset_spa(ZTOZSB(zp)->z_os));
	z_carrier->z_dtl.mkdir.gen = zp->z_gen;

	if (name != NULL)
		namesize = MIN(strlen(name), MAXNAMELEN-1);
	if (namesize > 0) {
		bcopy(name, z_carrier->z_dtl.mkdir.name, namesize);
		z_carrier->z_dtl.mkdir.name[namesize] = '\0';
	}

	if(vap != NULL){
		z_carrier->z_dtl.mkdir.xvap = *((xvattr_t *)vap);
		z_carrier->z_dtl.mkdir.isvapcarry = B_TRUE;
	}else{
		bzero(&z_carrier->z_dtl.mkdir.xvap, sizeof(xvattr_t));
		z_carrier->z_dtl.mkdir.isvapcarry = B_FALSE;
	}
	if(vsap != NULL){
		if(vsap->vsa_aclcnt > ZFS_GROUP_DTL_ACL_ENTRY_MAX){
			cmn_err(CE_WARN, "[ERROR] %s vsap->vsa_aclcnt %d, vsap->vsa_aclentsz %lu", 
				__func__, vsap->vsa_aclcnt, vsap->vsa_aclentsz);
		}
		z_carrier->z_dtl.mkdir.vsap.vsa_aclcnt = MIN(vsap->vsa_aclcnt, ZFS_GROUP_DTL_ACL_ENTRY_MAX);
		z_carrier->z_dtl.mkdir.vsap.vsa_dfaclcnt = vsap->vsa_dfaclcnt < ZFS_GROUP_DTL_ACL_ENTRY_MAX ? vsap->vsa_dfaclcnt : 0;
		z_carrier->z_dtl.mkdir.vsap.vsa_aclflags = vsap->vsa_aclflags;
		z_carrier->z_dtl.mkdir.vsap.vsa_mask = vsap->vsa_mask;
		z_carrier->z_dtl.mkdir.vsap.vsa_aclentsz = MIN(vsap->vsa_aclentsz, 0xc * ZFS_GROUP_DTL_ACL_ENTRY_MAX);
		bcopy(vsap->vsa_aclentp, z_carrier->z_dtl.mkdir.vsap.vsa_aclentp, z_carrier->z_dtl.mkdir.vsap.vsa_aclentsz);
		z_carrier->z_dtl.mkdir.isvsapcarry = B_TRUE;
	}else{
		bzero(&z_carrier->z_dtl.mkdir.vsap, sizeof(zfs_group_dtl_vsecattr_t));
		z_carrier->z_dtl.mkdir.isvsapcarry = B_FALSE;
	}

	z_carrier->z_dtl.mkdir.flag = flag;
	
	zfs_group_set_cred(credp, &z_carrier->z_dtl.mkdir.cred);

	return(z_carrier);
}

static zfs_group_dtl_carrier_t *
zfs_group_dtl_carry_rmdir(name_operation_t z_op, znode_t *pzp, char *name,
 struct inode *cdir, cred_t *credp, int flag)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;
	int namesize = 0;

	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	if(NULL == z_carrier) {
		cmn_err(CE_WARN, "[%s %d] alloc z_carrier failed.", __func__, __LINE__);
		return (z_carrier);
	}
	
	z_carrier->z_op = z_op;
	z_carrier->z_dtl.rmdir.group_id = pzp->z_group_id;
	z_carrier->z_dtl.rmdir.os_id = dmu_objset_id(ZTOZSB(pzp)->z_os);
	z_carrier->z_dtl.rmdir.spa_id = spa_guid(dmu_objset_spa(ZTOZSB(pzp)->z_os));
	z_carrier->z_dtl.rmdir.dirid = pzp->z_id;
	z_carrier->z_dtl.rmdir.dirlowdata = pzp->z_dirlowdata;
	z_carrier->z_dtl.rmdir.dirquota = pzp->z_dirquota;
	bcopy(pzp->z_filename, z_carrier->z_dtl.rmdir.dirname, MAXNAMELEN);

	if (name != NULL)
		namesize = MIN(strlen(name), MAXNAMELEN-1);
	if (namesize > 0) {
		bcopy(name, z_carrier->z_dtl.rmdir.name, namesize);
		z_carrier->z_dtl.rmdir.name[namesize] = '\0';
	}

	z_carrier->z_dtl.rmdir.flag = flag;
	
	zfs_group_set_cred(credp, &z_carrier->z_dtl.rmdir.cred);

	return(z_carrier);
}

static zfs_group_dtl_carrier_t *
zfs_group_dtl_carry_link(name_operation_t z_op, znode_t *dzp,	char *name,
 znode_t *szp, cred_t *credp, int flag)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;
	int namesize = 0;

	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	if(NULL == z_carrier) {
		cmn_err(CE_WARN, "[%s %d] alloc z_carrier failed.", __func__, __LINE__);
		return (z_carrier);
	}
	
	z_carrier->z_op = z_op;
	z_carrier->z_dtl.link.zid = dzp->z_id;
	z_carrier->z_dtl.link.os_id = dmu_objset_id(ZTOZSB(dzp)->z_os);
	z_carrier->z_dtl.link.spa_id = spa_guid(dmu_objset_spa(ZTOZSB(dzp)->z_os));
	z_carrier->z_dtl.link.gen = dzp->z_gen;
	
	z_carrier->z_dtl.link.szid= szp->z_id;
	z_carrier->z_dtl.link.sos_id= dmu_objset_id(ZTOZSB(szp)->z_os);
	z_carrier->z_dtl.link.sspa_id= spa_guid(dmu_objset_spa(ZTOZSB(szp)->z_os));
	z_carrier->z_dtl.link.sgen = szp->z_gen;
	if (name != NULL)
		namesize = MIN(strlen(name), MAXNAMELEN-1);
	if (namesize > 0) {
		bcopy(name, z_carrier->z_dtl.link.name, namesize);
		z_carrier->z_dtl.link.name[namesize] = '\0';
	}

	z_carrier->z_dtl.link.flag = flag;
	
	zfs_group_set_cred(credp, &z_carrier->z_dtl.link.cred);

	return(z_carrier);
}

static zfs_group_dtl_carrier_t *
zfs_group_dtl_carry_rename(name_operation_t z_op, znode_t *ozp, char *name,
znode_t *nzp, cred_t *credp, int flag, char* newname)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;
	int namesize = 0;

	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	if(NULL == z_carrier) {
		cmn_err(CE_WARN, "[%s %d] alloc z_carrier failed.", __func__, __LINE__);
		return (z_carrier);
	}
	
	z_carrier->z_op = z_op;
	z_carrier->z_dtl.rename.zid= ozp->z_id;
	z_carrier->z_dtl.rename.os_id = dmu_objset_id(ZTOZSB(ozp)->z_os);
	z_carrier->z_dtl.rename.spa_id = spa_guid(dmu_objset_spa(ZTOZSB(ozp)->z_os));
	z_carrier->z_dtl.rename.gen = ozp->z_gen;
	
	z_carrier->z_dtl.rename.nzid = nzp->z_id;
	z_carrier->z_dtl.rename.nos_id = dmu_objset_id(ZTOZSB(nzp)->z_os);
	z_carrier->z_dtl.rename.nspa_id = spa_guid(dmu_objset_spa(ZTOZSB(nzp)->z_os));
	z_carrier->z_dtl.rename.ngen = nzp->z_gen;
	z_carrier->z_dtl.rename.old_group_id = ozp->z_group_id;
	z_carrier->z_dtl.rename.new_group_id = nzp->z_group_id;
	if (name != NULL)
		namesize = MIN(strlen(name), MAXNAMELEN-1);
	if (namesize > 0) {
		bcopy(name, z_carrier->z_dtl.rename.name, namesize);
		z_carrier->z_dtl.rename.name[namesize] = '\0';
	}
	if (newname != NULL)
		namesize = MIN(strlen(newname), MAXNAMELEN-1);
	if (namesize > 0) {
		bcopy(newname, z_carrier->z_dtl.rename.newname, namesize);
		z_carrier->z_dtl.rename.newname[namesize] = '\0';
	}
	z_carrier->z_dtl.rename.flag = flag;
	
	zfs_group_set_cred(credp, &z_carrier->z_dtl.rename.cred);

	return(z_carrier);
}

static zfs_group_dtl_carrier_t *
zfs_group_dtl_carry_symlink(name_operation_t z_op, znode_t *dzp, char *name,
vattr_t *vap, znode_t *zp, cred_t *credp, int flag, char *target)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;
	int namesize = 0;
	int targetsize = 0;
	vattr_t *vattr = NULL;

	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	if(NULL == z_carrier) {
		cmn_err(CE_WARN, "[%s %d] alloc z_carrier failed.", __func__, __LINE__);
		return (z_carrier);
	}
	
	z_carrier->z_op = z_op;
	z_carrier->z_dtl.symlink.dir_zid= dzp->z_id;
	z_carrier->z_dtl.symlink.dir_os_id = dmu_objset_id(ZTOZSB(dzp)->z_os);
	z_carrier->z_dtl.symlink.dir_spa_id = spa_guid(dmu_objset_spa(ZTOZSB(dzp)->z_os));
	z_carrier->z_dtl.symlink.dir_gen = dzp->z_gen;
	
	z_carrier->z_dtl.symlink.zid = zp->z_id;
	z_carrier->z_dtl.symlink.os_id = dmu_objset_id(ZTOZSB(zp)->z_os);
	z_carrier->z_dtl.symlink.spa_id = spa_guid(dmu_objset_spa(ZTOZSB(zp)->z_os));
	z_carrier->z_dtl.symlink.gen = zp->z_gen;

	if (name != NULL)
		namesize = MIN(strlen(name), MAXNAMELEN-1);
	if (namesize > 0) {
		bcopy(name, z_carrier->z_dtl.symlink.name, namesize);
		z_carrier->z_dtl.symlink.name[namesize] = '\0';
	}

	if (target != NULL)
		targetsize = MIN(strlen(target), MAXNAMELEN-1);
	if (targetsize > 0) {
		bcopy(target, z_carrier->z_dtl.symlink.target, targetsize);
		z_carrier->z_dtl.symlink.target[targetsize] = '\0';
	}

	if(vap != NULL)
		z_carrier->z_dtl.symlink.xvap = *((xvattr_t*)vap);
	else
		bzero(&z_carrier->z_dtl.symlink.xvap, sizeof(xvattr_t));

	vattr = &z_carrier->z_dtl.symlink.xvap.xva_vattr;
	if (!(vattr->va_mask & AT_MTIME)) {
		ZFS_TIME_DECODE(&vattr->va_mtime, zp->z_mtime);
		vattr->va_mask |= AT_MTIME;
	}
	z_carrier->z_dtl.symlink.isvapcarry = B_TRUE;
	
	z_carrier->z_dtl.symlink.flag = flag;
	
	zfs_group_set_cred(credp, &z_carrier->z_dtl.symlink.cred);

	return(z_carrier);
}

static zfs_group_dtl_carrier_t *
zfs_group_dtl_carry_acl(name_operation_t z_op, znode_t *zp, cred_t *credp,
int flag, vsecattr_t *vsap)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;

	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	if(NULL == z_carrier) {
		cmn_err(CE_WARN, "[%s %d] alloc z_carrier failed.", __func__, __LINE__);
		return (z_carrier);
	}
	
	z_carrier->z_op = z_op;
	z_carrier->z_dtl.setsecattr.zid= zp->z_id;
	z_carrier->z_dtl.setsecattr.os_id = dmu_objset_id(ZTOZSB(zp)->z_os);
	z_carrier->z_dtl.setsecattr.spa_id = spa_guid(dmu_objset_spa(ZTOZSB(zp)->z_os));
	z_carrier->z_dtl.setsecattr.gen = zp->z_gen;

	if(vsap != NULL){
		if(vsap->vsa_aclcnt > ZFS_GROUP_DTL_ACL_ENTRY_MAX){
			cmn_err(CE_WARN, "[ERROR] %s vsap->vsa_aclcnt %d, vsap->vsa_aclentsz %lu", 
				__func__, vsap->vsa_aclcnt, vsap->vsa_aclentsz);
		}
		z_carrier->z_dtl.setsecattr.vsap.vsa_aclcnt = MIN(vsap->vsa_aclcnt, ZFS_GROUP_DTL_ACL_ENTRY_MAX);
		z_carrier->z_dtl.setsecattr.vsap.vsa_dfaclcnt = 
			vsap->vsa_dfaclcnt < ZFS_GROUP_DTL_ACL_ENTRY_MAX ? vsap->vsa_dfaclcnt : 0;
		z_carrier->z_dtl.setsecattr.vsap.vsa_aclflags = vsap->vsa_aclflags;
		z_carrier->z_dtl.setsecattr.vsap.vsa_mask = vsap->vsa_mask;
		z_carrier->z_dtl.setsecattr.vsap.vsa_aclentsz = MIN(vsap->vsa_aclentsz, 0xc * ZFS_GROUP_DTL_ACL_ENTRY_MAX);
		bcopy(vsap->vsa_aclentp, z_carrier->z_dtl.setsecattr.vsap.vsa_aclentp, z_carrier->z_dtl.setsecattr.vsap.vsa_aclentsz);
		z_carrier->z_dtl.setsecattr.isvsapcarry = B_TRUE;
	}else{
		bzero(&z_carrier->z_dtl.setsecattr.vsap, sizeof(zfs_group_dtl_vsecattr_t));
		z_carrier->z_dtl.setsecattr.isvsapcarry = B_FALSE;
	}

	z_carrier->z_dtl.setsecattr.flag = flag;
	
	zfs_group_set_cred(credp, &z_carrier->z_dtl.setsecattr.cred);

	return(z_carrier);
}

static zfs_group_dtl_carrier_t *
zfs_group_dtl_carry_acl2(name_operation_t z_op, znode_t *zp,
vattr_t *vap, cred_t *credp, int flag)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;

	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	if(NULL == z_carrier) {
		cmn_err(CE_WARN, "[%s %d] alloc z_carrier failed.", __func__, __LINE__);
		return (z_carrier);
	}
	
	z_carrier->z_op = z_op;
	z_carrier->z_dtl.setattr.zid = zp->z_id;
	z_carrier->z_dtl.setattr.os_id = dmu_objset_id(ZTOZSB(zp)->z_os);
	z_carrier->z_dtl.setattr.spa_id = spa_guid(dmu_objset_spa(ZTOZSB(zp)->z_os));
	z_carrier->z_dtl.setattr.gen = zp->z_gen;

	if(vap != NULL){
		if (vap->va_mask & AT_XVATTR) {
			z_carrier->z_dtl.setattr.xvap = *((xvattr_t*)vap);
		} else {
			z_carrier->z_dtl.setattr.xvap.xva_vattr = *vap;
		}
		z_carrier->z_dtl.setattr.isvapcarry = B_TRUE;
	}else{
		bzero(&z_carrier->z_dtl.setattr.xvap, sizeof(vattr_t));
		z_carrier->z_dtl.setattr.isvapcarry = B_FALSE;
	}
	
	z_carrier->z_dtl.setattr.flag = flag;
	
	zfs_group_set_cred(credp, &z_carrier->z_dtl.setattr.cred);

	return(z_carrier);
}

static zfs_group_dtl_carrier_t *
zfs_group_dtl_carry_dirquota(name_operation_t z_op, znode_t *zp, 
	uint64_t dir_obj, uint64_t quota, int flag, char *path)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;
	int namesize = 0;

	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	if(NULL == z_carrier) {
		cmn_err(CE_WARN, "[%s %d] alloc z_carrier failed.", __func__, __LINE__);
		return (z_carrier);
	}
	
	z_carrier->z_op = z_op;
	z_carrier->z_dtl.dirquota.zid = zp->z_id;
	z_carrier->z_dtl.dirquota.spa_id = spa_guid(dmu_objset_spa(ZTOZSB(zp)->z_os));
	z_carrier->z_dtl.dirquota.os_id = dmu_objset_id(ZTOZSB(zp)->z_os);

	z_carrier->z_dtl.dirquota.obj_id = dir_obj;
	z_carrier->z_dtl.dirquota.dir_gen = zp->z_gen;
	z_carrier->z_dtl.dirquota.quota = quota;
	if (path != NULL) {
		namesize = MIN(strlen(path), MAXPATHLEN-1);
	}
	if (namesize > 0) {
		bcopy(path+strlen(path)-namesize, z_carrier->z_dtl.dirquota.path, namesize);
		z_carrier->z_dtl.dirquota.path[namesize] = '\0';
	}

	z_carrier->z_dtl.dirquota.flag = flag;
	
	return(z_carrier);
}

static zfs_group_dtl_carrier_t *
zfs_group_dtl_carry_dirlowdata(name_operation_t z_op, znode_t *zp,
	int flag, zfs_group_dirlow_t *z_dirlow)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;

	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	if(NULL == z_carrier) {
		cmn_err(CE_WARN, "[%s %d] alloc z_carrier failed.", __func__, __LINE__);
		return (z_carrier);
	}
	if(NULL == z_dirlow){
		kmem_free(z_carrier, sizeof(zfs_group_dtl_carrier_t));
		return (NULL);
	}
	
	z_carrier->z_op = z_op;
	z_carrier->z_dtl.dirlowdata.zid = zp->z_id;
	z_carrier->z_dtl.dirlowdata.spa_id = spa_guid(dmu_objset_spa(ZTOZSB(zp)->z_os));
	z_carrier->z_dtl.dirlowdata.os_id = dmu_objset_id(ZTOZSB(zp)->z_os);

	z_carrier->z_dtl.dirlowdata.obj_id = z_dirlow->dir_obj;
	z_carrier->z_dtl.dirlowdata.dir_gen = zp->z_gen;
	z_carrier->z_dtl.dirlowdata.value = z_dirlow->value;
	bcopy(z_dirlow->path, z_carrier->z_dtl.dirlowdata.path, 
		sizeof(z_dirlow->path));
	bcopy(z_dirlow->propname, z_carrier->z_dtl.dirlowdata.propname, 
		sizeof(z_dirlow->propname));
	
	z_carrier->z_dtl.dirlowdata.flag = flag;

	return(z_carrier);
}

zfs_group_dtl_carrier_t*	
zfs_group_dtl_carry(name_operation_t z_op, znode_t *pzp,	char *name,
vattr_t *vap, int ex, int mode, void* multiplex1, cred_t *credp, int flag, void* multiplex2)
{
	zfs_group_dtl_carrier_t *z_carrier = NULL;
	
	switch(z_op){
		
		case NAME_CREATE:
		{
			znode_t *zp = (znode_t *)multiplex1;
			vsecattr_t *vsap = (vsecattr_t *)multiplex2;
			z_carrier = zfs_group_dtl_carry_create(z_op, pzp, name, vap, ex, mode, 
				zp, credp, flag, vsap);
			break;
		}
		case NAME_REMOVE:
		{
			z_carrier = zfs_group_dtl_carry_remove(z_op, pzp, name, credp, flag);
			break;
		}
		case NAME_MKDIR:
		{
			znode_t *zp = (znode_t *)multiplex1;
			vsecattr_t *vsap = (vsecattr_t *)multiplex2;
			z_carrier = zfs_group_dtl_carry_mkdir(z_op, pzp,name,vap, 
				zp, credp, flag, vsap);
			break;	
		}
		case NAME_RMDIR:
		{
			struct inode *cdir = (struct inode *)multiplex1;
			z_carrier = zfs_group_dtl_carry_rmdir(z_op, pzp, name, cdir, credp, flag);
			break;
		}
		case NAME_LINK:
		{
			znode_t *szp = (znode_t *)multiplex1;
			z_carrier = zfs_group_dtl_carry_link(z_op, pzp, name, szp, credp, flag);
			break;
		}
		case NAME_RENAME:
		{
			znode_t *nzp = (znode_t *)multiplex1;
			char *newname = (char *)multiplex2;
			z_carrier = zfs_group_dtl_carry_rename(z_op, pzp, name, nzp, credp, 
				flag, newname);
			break;
		}
		case NAME_SYMLINK:
		{
			znode_t *zp = (znode_t *)multiplex1;
			char *target = (char *)multiplex2;
			z_carrier = zfs_group_dtl_carry_symlink(z_op, pzp, name, vap, zp, credp, 
				flag, target);
			break;
		}
		case NAME_ACL:
		{
			vsecattr_t *vsap = (vsecattr_t *)multiplex2;
			z_carrier = zfs_group_dtl_carry_acl(z_op, pzp, credp, flag, vsap);
			break;
		}
		case NAME_ZNODE_SETATTR:
		{
			z_carrier = zfs_group_dtl_carry_acl2(z_op, pzp, vap, credp, flag);
			break;
		}
		case NAME_DIRQUOTA:
		{
			if(multiplex1 && multiplex2){
				uint64_t dir_obj = *(uint64_t *)multiplex1;
				uint64_t quota = *(uint64_t *)multiplex2;
				z_carrier = zfs_group_dtl_carry_dirquota(z_op, pzp, dir_obj, quota, flag, name);
			}
			break;
		}
		case NAME_DIRLOWDATA:
		{
			zfs_group_dirlow_t *z_dirlow = (zfs_group_dirlow_t *)multiplex1;
			z_carrier = zfs_group_dtl_carry_dirlowdata(z_op, pzp, flag, z_dirlow);
			break;
		}
		default:
			return (NULL);
	}
	if(z_carrier != NULL)
		z_carrier->z_magic = ZFS_GROUP_DTL_MAGIC;
	return (z_carrier);
}

static int
zfs_group_dtl_resolve_create(zfs_group_dtl_carrier_t *z_carrier, zfs_multiclus_node_type_t m_node_type)
{
	int err = 0;
	znode_t *pzp = NULL;
	znode_t *zp = NULL;
	cred_t *credp = NULL;
	zfs_sb_t *zsb = NULL;
	dmu_tx_t	 *tx = NULL;
	vattr_t *vap = NULL;
	vsecattr_t *vsap = NULL;
	vsecattr_t vsa = {0};
	
	if(z_carrier->z_dtl.create.isvapcarry)
		vap = (vattr_t*)(&z_carrier->z_dtl.create.xvap);
	if(z_carrier->z_dtl.create.isvsapcarry){
		vsa.vsa_aclcnt = z_carrier->z_dtl.create.vsap.vsa_aclcnt;
		vsa.vsa_dfaclcnt = z_carrier->z_dtl.create.vsap.vsa_dfaclcnt;
		vsa.vsa_aclflags = z_carrier->z_dtl.create.vsap.vsa_aclflags;
		vsa.vsa_mask = z_carrier->z_dtl.create.vsap.vsa_mask;
		vsa.vsa_aclentsz = z_carrier->z_dtl.create.vsap.vsa_aclentsz;
		vsa.vsa_aclentp = &z_carrier->z_dtl.create.vsap.vsa_aclentp[0];
		vsa.vsa_dfaclentp = NULL;
		vsap = &vsa;
	}
	zsb = zfs_sb_group_hold(z_carrier->z_dtl.create.dir_spa_id, 
		z_carrier->z_dtl.create.dir_os_id, FTAG, B_FALSE);
	
	if(zsb){
		err = zfs_zget(zsb, z_carrier->z_dtl.create.dir_zid, &pzp);
		if (err) {
			cmn_err(CE_WARN, "%s:get directory znode_t pointer fail!", __func__);
			zfs_sb_group_rele(zsb, FTAG);
			/* Because parent dir could be removed by subsequent operation, so return success,
			* although zfs_zget() returns error.
			*/
			return 0;
		}else if(pzp->z_gen != z_carrier->z_dtl.create.dir_gen){
			if(1 == debug_nas_group_dtl){
				cmn_err(CE_WARN, "%s: %d!, dir_gen is different.", __func__, __LINE__);
			}
			iput(ZTOI(pzp));
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}
	}else{
		cmn_err(CE_WARN, "%s:get directory zfsvfs_t pointer fail!", __func__);
		return (EINVAL);
	}

	if((z_carrier->z_dtl.create.dir_spa_id == z_carrier->z_dtl.create.spa_id)
		&& (z_carrier->z_dtl.create.dir_os_id == z_carrier->z_dtl.create.os_id)){
		err = zfs_zget(zsb, z_carrier->z_dtl.create.zid, &zp);
		if (err) {
			cmn_err(CE_WARN, "%s:get plain file znode_t pointer fail!", __func__);
			iput(ZTOI(pzp));
			zfs_sb_group_rele(zsb, FTAG);
			/* Because the file could be removed by subsequent operation, so return success,
			* although zfs_zget() returns error.
			*/
			return 0;
		}else if(zp->z_gen != z_carrier->z_dtl.create.gen){
			if(1 == debug_nas_group_dtl){
				cmn_err(CE_WARN, "%s: %d!, file_gen is different.", __func__, __LINE__);
			}
			iput(ZTOI(zp));
			iput(ZTOI(pzp));
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}
	}else{
		cmn_err(CE_WARN, "%s:dir_spa_id != spa_id, dir_os_id != os_id", __func__);
		iput(ZTOI(pzp));	
		zfs_sb_group_rele(zsb, FTAG);		
		return (EINVAL);
	}
	if (vap == NULL) {
		cmn_err(CE_WARN, "%s, %d, vap is NULL, so this carrier data maybe corrupted!", __func__, __LINE__);
		iput(ZTOI(pzp));
		iput(ZTOI(zp));
		zfs_sb_group_rele(zsb, FTAG);
		return 0;
	}
	credp = zfs_group_getcred(&z_carrier->z_dtl.create.cred);
	err = zfs_client_create_backup(pzp, z_carrier->z_dtl.create.name, vap, 
		z_carrier->z_dtl.create.ex, z_carrier->z_dtl.create.mode, zp, credp, 
		z_carrier->z_dtl.create.flag, vsap, m_node_type);
	if(err == 0){
		tx = dmu_tx_create(zsb->z_os);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if(err){
			dmu_tx_abort(tx);
			goto out;
		}
		mutex_enter(&zp->z_lock);
		VERIFY(0 == sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zsb),
		    		&zp->z_group_id, sizeof(zp->z_group_id), tx));
		mutex_exit(&zp->z_lock);
		dmu_tx_commit(tx);
	}
	
out:
	abort_creds(credp);
	iput(ZTOI(pzp));
	iput(ZTOI(zp));
	zfs_sb_group_rele(zsb, FTAG);
	return (err);
}

static int
zfs_group_dtl_resolve_remove(zfs_group_dtl_carrier_t *z_carrier, zfs_multiclus_node_type_t m_node_type)
{
	znode_t pzp = { 0 };
	znode_t *dzp = NULL;
	int zget_err = 0;
	int err = 0;
	cred_t *credp = NULL;
	zfs_sb_t *zsb = NULL;

	zsb = zfs_sb_group_hold(z_carrier->z_dtl.remove.spa_id, 
		z_carrier->z_dtl.remove.os_id, FTAG, B_FALSE);
	
	if(zsb){
		zget_err = zfs_zget(zsb, z_carrier->z_dtl.rmdir.dirid, &dzp);
		if (zget_err) {
			/*
			 * reconstruct the parent znode
			 *
			 * Note:
			 * we may need to reconstruct more fields in the faked znode later;
			 * currently, it is enough to reconstruct z_zfsvfs and z_group_id,
			 * based on the usage in zfs_group_proc_name_backup
			 */
			pzp.z_zsb= zsb;
			pzp.z_group_id = z_carrier->z_dtl.remove.group_id;
			pzp.z_id = z_carrier->z_dtl.remove.dirid;
			pzp.z_dirlowdata = z_carrier->z_dtl.remove.dirlowdata;
			pzp.z_dirquota = z_carrier->z_dtl.remove.dirquota;
			bcopy(z_carrier->z_dtl.remove.dirname, pzp.z_filename, MAXNAMELEN);
			dzp = &pzp;
		}
	}else{
		cmn_err(CE_WARN, "%s:get directory zfsvfs_t pointer fail!", __func__);
		return (EINVAL);
	}

	credp = zfs_group_getcred(&z_carrier->z_dtl.remove.cred);
	err = zfs_client_remove_backup(dzp, z_carrier->z_dtl.remove.name,
		credp, z_carrier->z_dtl.remove.flag, m_node_type);

	abort_creds(credp);
	if (zget_err == 0)
		iput(ZTOI(dzp));
	zfs_sb_group_rele(zsb, FTAG);
	return (err);
}

static int
zfs_group_dtl_resolve_mkdir(zfs_group_dtl_carrier_t *z_carrier, zfs_multiclus_node_type_t m_node_type)
{
	int err = 0;
	znode_t *pzp = NULL;
	znode_t *zp = NULL;
	cred_t *credp = NULL;
	zfs_sb_t *zsb = NULL;
	dmu_tx_t	 *tx = NULL;
	vattr_t *vap = NULL;
	vsecattr_t *vsap = NULL;
	vsecattr_t vsa = {0};
	
	if(z_carrier->z_dtl.mkdir.isvapcarry)
		vap = (vattr_t*)(&z_carrier->z_dtl.mkdir.xvap);
	if(z_carrier->z_dtl.mkdir.isvsapcarry){
		vsa.vsa_aclcnt = z_carrier->z_dtl.mkdir.vsap.vsa_aclcnt;
		vsa.vsa_dfaclcnt = z_carrier->z_dtl.mkdir.vsap.vsa_dfaclcnt;
		vsa.vsa_aclflags = z_carrier->z_dtl.mkdir.vsap.vsa_aclflags;
		vsa.vsa_mask = z_carrier->z_dtl.mkdir.vsap.vsa_mask;
		vsa.vsa_aclentsz = z_carrier->z_dtl.mkdir.vsap.vsa_aclentsz;
		vsa.vsa_aclentp = &z_carrier->z_dtl.mkdir.vsap.vsa_aclentp[0];
		vsa.vsa_dfaclentp = NULL;
		vsap = &vsa;
	}
	zsb = zfs_sb_group_hold(z_carrier->z_dtl.mkdir.dir_spa_id, 
		z_carrier->z_dtl.mkdir.dir_os_id, FTAG, B_FALSE);
	
	if(zsb){
		err = zfs_zget(zsb, z_carrier->z_dtl.mkdir.dir_zid, &pzp);
		if (err) {
			cmn_err(CE_WARN, "%s:get directory znode_t pointer fail!", __func__);
			zfs_sb_group_rele(zsb, FTAG);
			/* Because parent dir could be removed by subsequent operation, so return success,
			* although zfs_zget() returns error.
			*/
			return 0;
		}else if(pzp->z_gen != z_carrier->z_dtl.mkdir.dir_gen){
			if(1 == debug_nas_group_dtl){
				cmn_err(CE_WARN, "%s: %d!, dir_gen is different.", __func__, __LINE__);
			}
			iput(ZTOI(pzp));
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}
	}else{
		cmn_err(CE_WARN, "%s:get directory zfsvfs_t pointer fail!", __func__);
		return (EINVAL);
	}

	if((z_carrier->z_dtl.mkdir.dir_spa_id == z_carrier->z_dtl.mkdir.spa_id)
		&& (z_carrier->z_dtl.mkdir.dir_os_id == z_carrier->z_dtl.mkdir.os_id)){
		err = zfs_zget(zsb, z_carrier->z_dtl.mkdir.zid, &zp);
		if (err) {
			cmn_err(CE_WARN, "%s:get target dir znode_t pointer fail!", __func__);
			iput(ZTOI(pzp));
			zfs_sb_group_rele(zsb, FTAG);
			/* Because the dir could be removed by subsequent operation, so return success,
			* although zfs_zget() returns error.
			*/
			return 0;
		}else if(zp->z_gen != z_carrier->z_dtl.mkdir.gen){
			iput(ZTOI(zp));
			iput(ZTOI(pzp));
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}
	}else{
		cmn_err(CE_WARN, "%s:dir_spa_id != spa_id, dir_os_id != os_id", __func__);
		iput(ZTOI(pzp));
		zfs_sb_group_rele(zsb, FTAG);		
		return (EINVAL);
	}
	if (vap == NULL) {
		cmn_err(CE_WARN, "%s, %d, vap is NULL, so this carrier data maybe corrupted!", __func__, __LINE__);
		iput(ZTOI(pzp));
		iput(ZTOI(zp));
		zfs_sb_group_rele(zsb, FTAG);
		return 0;
	}
	credp = zfs_group_getcred(&z_carrier->z_dtl.mkdir.cred);
	err = zfs_client_mkdir_backup(pzp, z_carrier->z_dtl.mkdir.name, vap, 
		zp, credp, z_carrier->z_dtl.mkdir.flag, vsap, m_node_type);
	
	if(err == 0){
		tx = dmu_tx_create(zsb->z_os);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if(err){
			dmu_tx_abort(tx);
			cmn_err(CE_WARN, "[%s %d] dmu_tx_assign error=%d, tx=%p", __func__, __LINE__, err, (void*)tx);
			goto out;
		}
		mutex_enter(&zp->z_lock);
		VERIFY(0 == sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zsb),
		    		&zp->z_group_id, sizeof(zp->z_group_id), tx));
		mutex_exit(&zp->z_lock);
		dmu_tx_commit(tx);
	}
	
out:
	abort_creds(credp);
	iput(ZTOI(pzp));
	iput(ZTOI(zp));
	zfs_sb_group_rele(zsb, FTAG);
	return (err);
}


static int
zfs_group_dtl_resolve_rmdir(zfs_group_dtl_carrier_t *z_carrier, zfs_multiclus_node_type_t m_node_type)
{
	znode_t pzp = { 0 };
	znode_t *dzp = NULL;
	int err = 0;
	int zget_err = 0;
	cred_t *credp = NULL;
	zfs_sb_t *zsb = NULL;
 
	zsb = zfs_sb_group_hold(z_carrier->z_dtl.rmdir.spa_id, 
		z_carrier->z_dtl.rmdir.os_id, FTAG, B_FALSE);

	if(zsb){
		zget_err = zfs_zget(zsb, z_carrier->z_dtl.rmdir.dirid, &dzp);
		if (zget_err) {
			/*
			 * reconstruct the parent znode
			 *
			 * Note:
			 * we may need to reconstruct more fields in the faked znode later;
			 * currently, it is enough to reconstruct z_zfsvfs and z_group_id,
			 * based on the usage in zfs_group_proc_name_backup
			 */
			pzp.z_zsb= zsb;
			pzp.z_group_id = z_carrier->z_dtl.rmdir.group_id;
			pzp.z_id = z_carrier->z_dtl.rmdir.dirid;
			pzp.z_dirlowdata = z_carrier->z_dtl.rmdir.dirlowdata;
			pzp.z_dirquota = z_carrier->z_dtl.rmdir.dirquota;
			bcopy(z_carrier->z_dtl.rmdir.dirname, pzp.z_filename, MAXNAMELEN);
			dzp = &pzp;
		}
	}else{
		cmn_err(CE_WARN, "%s:get directory zfsvfs_t pointer fail!", __func__);
		return (EINVAL);
	}

	credp = zfs_group_getcred(&z_carrier->z_dtl.rmdir.cred);
	err = zfs_client_rmdir_backup(dzp, z_carrier->z_dtl.rmdir.name, NULL, 
		credp, z_carrier->z_dtl.rmdir.flag, m_node_type);

	abort_creds(credp);
	if (zget_err == 0)
		iput(ZTOI(dzp));
	zfs_sb_group_rele(zsb, FTAG);
	return (err);
}


static int
zfs_group_dtl_resolve_link(zfs_group_dtl_carrier_t *z_carrier, zfs_multiclus_node_type_t m_node_type)
{
	int err = 0;
	znode_t *dzp = NULL;
	znode_t *szp = NULL;
	cred_t *credp = NULL;
	zfs_sb_t *zsb = NULL;
	
	zsb = zfs_sb_group_hold(z_carrier->z_dtl.link.spa_id, 
		z_carrier->z_dtl.link.os_id, FTAG, B_FALSE);

	if(zsb){
		err = zfs_zget(zsb, z_carrier->z_dtl.link.zid, &dzp);
		if (err) {
			cmn_err(CE_WARN, "%s:get target znode_t pointer fail!", __func__);
			zfs_sb_group_rele(zsb, FTAG);
			return (EINVAL);
		}else if(dzp->z_gen != z_carrier->z_dtl.link.gen){
			if(1 == debug_nas_group_dtl){
				cmn_err(CE_WARN, "%s: %d!, target dir_gen is different.", __func__, __LINE__);
			}
			iput(ZTOI(dzp));
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}
	}else{
		cmn_err(CE_WARN, "%s:get target zfsvfs_t pointer fail!", __func__);
		return (EINVAL);
	}

	if((z_carrier->z_dtl.link.spa_id == z_carrier->z_dtl.link.sspa_id)
		&& (z_carrier->z_dtl.link.os_id == z_carrier->z_dtl.link.sos_id)){
		err = zfs_zget(zsb, z_carrier->z_dtl.link.szid, &szp);
		if (err) {
			cmn_err(CE_WARN, "%s:get source znode_t pointer fail!", __func__);
			iput(ZTOI(dzp));
			zfs_sb_group_rele(zsb, FTAG);
			return (EINVAL);
		}else if(szp->z_gen != z_carrier->z_dtl.link.sgen){
			if(1 == debug_nas_group_dtl){
				cmn_err(CE_WARN, "%s: %d!, source file_gen is different.", __func__, __LINE__);
			}
			iput(ZTOI(szp));
			iput(ZTOI(dzp));
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}
	}else{
		cmn_err(CE_WARN, "%s:spa_id != sspa_id, os_id != sos_id", __func__);
		iput(ZTOI(dzp));
		zfs_sb_group_rele(zsb, FTAG);	
		return (EINVAL);
	}
	credp = zfs_group_getcred(&z_carrier->z_dtl.link.cred);
	err = zfs_client_link_backup(dzp, szp, z_carrier->z_dtl.link.name,
		credp, z_carrier->z_dtl.link.flag, m_node_type);

	abort_creds(credp);
	iput(ZTOI(dzp));
	iput(ZTOI(szp));
	zfs_sb_group_rele(zsb, FTAG);
	return (err);
}


static int
zfs_group_dtl_resolve_rename(zfs_group_dtl_carrier_t *z_carrier, zfs_multiclus_node_type_t m_node_type)
{
	int err = 0;
	znode_t *ozp = NULL;
	znode_t *nzp = NULL;
	cred_t *credp = NULL;
	zfs_sb_t *zsb = NULL;

	ozp = kmem_alloc(sizeof(znode_t), KM_NOSLEEP);
	nzp = kmem_alloc(sizeof(znode_t), KM_NOSLEEP);
	
	zsb = zfs_sb_group_hold(z_carrier->z_dtl.rename.spa_id, 
		z_carrier->z_dtl.rename.os_id, FTAG, B_FALSE);

	if(!zsb){
		cmn_err(CE_WARN, "%s:get old zfsvfs_t pointer fail!", __func__);
		return (EINVAL);
	}

	ozp->z_zsb = zsb;
	ozp->z_group_id = z_carrier->z_dtl.rename.old_group_id;
	nzp->z_zsb = zsb;
	nzp->z_group_id = z_carrier->z_dtl.rename.new_group_id;
	credp = zfs_group_getcred(&z_carrier->z_dtl.rename.cred);
	err = zfs_client_rename_backup(ozp, z_carrier->z_dtl.rename.name, nzp, 
		z_carrier->z_dtl.rename.newname, credp, z_carrier->z_dtl.rename.flag, m_node_type);

	abort_creds(credp);
	zfs_sb_group_rele(zsb, FTAG);
	kmem_free(ozp, sizeof(znode_t));
	kmem_free(nzp, sizeof(znode_t));
	return (err);
}


static int
zfs_group_dtl_resolve_symlink(zfs_group_dtl_carrier_t *z_carrier, zfs_multiclus_node_type_t m_node_type)
{
	int err = 0;
	znode_t *pzp = NULL;
	znode_t *zp = NULL;
	cred_t *credp = NULL;
	zfs_sb_t *zsb = NULL;
	vattr_t *vap = NULL;
	dmu_tx_t *tx = NULL;
	
	
	if(z_carrier->z_dtl.symlink.isvapcarry)
		vap = (vattr_t*)(&z_carrier->z_dtl.symlink.xvap);
	 
	zsb = zfs_sb_group_hold(z_carrier->z_dtl.symlink.spa_id, 
		z_carrier->z_dtl.symlink.os_id, FTAG, B_FALSE);
	
	if(zsb){
		err = zfs_zget(zsb, z_carrier->z_dtl.symlink.dir_zid, &pzp);
		if (err) {
			cmn_err(CE_WARN, "%s:get target znode_t pointer fail!", __func__);
			zfs_sb_group_rele(zsb, FTAG);
			return (0);
		}else if(pzp->z_gen !=  z_carrier->z_dtl.symlink.dir_gen){
			if(1 == debug_nas_group_dtl){
				cmn_err(CE_WARN, "%s: %d!, target dir gen is different.", __func__, __LINE__);
			}
			iput(ZTOI(pzp));
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}
	}else{
		cmn_err(CE_WARN, "%s:get target zfsvfs_t pointer fail!", __func__);
		return (EINVAL);
	}
	
	if((z_carrier->z_dtl.symlink.dir_spa_id == z_carrier->z_dtl.symlink.spa_id)
		&& (z_carrier->z_dtl.symlink.dir_os_id == z_carrier->z_dtl.symlink.os_id)){
		err = zfs_zget(zsb, z_carrier->z_dtl.symlink.zid, &zp);
		if (err) {
			cmn_err(CE_WARN, "%s:get symbol znode_t pointer fail!", __func__);
			iput(ZTOI(pzp));
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}else if(zp->z_gen != z_carrier->z_dtl.symlink.gen){
			if(1 == debug_nas_group_dtl){
				cmn_err(CE_WARN, "%s: %d!, target link gen is different.", __func__, __LINE__);
			}
			iput(ZTOI(zp));
			iput(ZTOI(pzp));
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}
	}else{
		cmn_err(CE_WARN, "%s:target_spa_id != spa_id, target_os_id != os_id", __func__);
		iput(ZTOI(pzp));
		zfs_sb_group_rele(zsb, FTAG);		
		return (EINVAL);
	}
	if (vap == NULL) {
		cmn_err(CE_WARN, "%s, %d, xvap is NULL, so this carrier data maybe corrupted!", __func__, __LINE__);
		iput(ZTOI(pzp));
		iput(ZTOI(zp));
		zfs_sb_group_rele(zsb, FTAG);
		return 0;
	}

	credp = zfs_group_getcred(&z_carrier->z_dtl.symlink.cred);
	err = zfs_client_symlink_backup(pzp, z_carrier->z_dtl.symlink.name, vap, zp,
		z_carrier->z_dtl.symlink.target, credp, z_carrier->z_dtl.symlink.flag, m_node_type);
	if(err == 0){
		tx = dmu_tx_create(zsb->z_os);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if(err){
			dmu_tx_abort(tx);
			goto out;
		}
		mutex_enter(&zp->z_lock);
		VERIFY(0 == sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zsb),
		    		&zp->z_group_id, sizeof(zp->z_group_id), tx));
		mutex_exit(&zp->z_lock);
		dmu_tx_commit(tx);
	}
	
out:
	abort_creds(credp);
	iput(ZTOI(pzp));
	iput(ZTOI(zp));
	zfs_sb_group_rele(zsb, FTAG);
	return (err);
}

static int
zfs_group_dtl_resolve_acl(zfs_group_dtl_carrier_t *z_carrier, zfs_multiclus_node_type_t m_node_type)
{
	int err = 0;
	znode_t *pzp = NULL;
	cred_t *credp = NULL;
	zfs_sb_t *zsb = NULL;
	vsecattr_t *vsap = NULL;
	vsecattr_t vsa = {0};
	

	if(z_carrier->z_dtl.setsecattr.isvsapcarry){
		vsa.vsa_aclcnt = z_carrier->z_dtl.setsecattr.vsap.vsa_aclcnt;
		vsa.vsa_dfaclcnt = z_carrier->z_dtl.setsecattr.vsap.vsa_dfaclcnt;
		vsa.vsa_aclflags = z_carrier->z_dtl.setsecattr.vsap.vsa_aclflags;
		vsa.vsa_mask = z_carrier->z_dtl.setsecattr.vsap.vsa_mask;
		vsa.vsa_aclentsz = z_carrier->z_dtl.setsecattr.vsap.vsa_aclentsz;
		vsa.vsa_aclentp = &z_carrier->z_dtl.setsecattr.vsap.vsa_aclentp[0];
		vsa.vsa_dfaclentp = NULL;
		vsap = &vsa;
	} 
	zsb = zfs_sb_group_hold(z_carrier->z_dtl.setsecattr.spa_id, 
		z_carrier->z_dtl.setsecattr.os_id, FTAG, B_FALSE);
	if(zsb){
		err = zfs_zget(zsb, z_carrier->z_dtl.setsecattr.zid, &pzp);
		if (err) {
			cmn_err(CE_WARN, "%s:get target znode_t pointer fail!", __func__);
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}else if(pzp->z_gen != z_carrier->z_dtl.setsecattr.gen){
			if(1 == debug_nas_group_dtl){
				cmn_err(CE_WARN, "%s: %d!, target node gen is different.", __func__, __LINE__);
			}
			iput(ZTOI(pzp));
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}
	}else{
		cmn_err(CE_WARN, "%s:get target zfsvfs_t pointer fail!", __func__);
		return (EINVAL);
	}

	
	credp = zfs_group_getcred(&z_carrier->z_dtl.setsecattr.cred);
	err = zfs_client_setsecattr_backup(pzp, vsap, 
		z_carrier->z_dtl.setsecattr.flag, credp, m_node_type);

	abort_creds(credp);
	iput(ZTOI(pzp));
	zfs_sb_group_rele(zsb, FTAG);
	return (err);
}


static int
zfs_group_dtl_resolve_znode_setattr(zfs_group_dtl_carrier_t *z_carrier, zfs_multiclus_node_type_t m_node_type)
{
	int err = 0;
	znode_t *pzp = NULL;
	cred_t *credp = NULL;
	zfs_sb_t *zsb = NULL;
	xvattr_t *xvap = NULL;
	
	
	if(z_carrier->z_dtl.setattr.isvapcarry)
		xvap = &z_carrier->z_dtl.setattr.xvap;
	
	zsb = zfs_sb_group_hold(z_carrier->z_dtl.setattr.spa_id, 
		z_carrier->z_dtl.setattr.os_id, FTAG, B_FALSE);

	if(zsb){
		err = zfs_zget(zsb, z_carrier->z_dtl.setattr.zid, &pzp);
		if (err) {
			cmn_err(CE_WARN, "%s:get target znode_t pointer fail!", __func__);
			zfs_sb_group_rele(zsb, FTAG);
			/* Because the file or dir could be removed by subsequent operation, so return success,
			* although zfs_zget() returns error.
			*/
			return 0;
		}else if(pzp->z_gen != z_carrier->z_dtl.setattr.gen){
			if(1 == debug_nas_group_dtl){
				cmn_err(CE_WARN, "%s: %d!, target_gen is different.", __func__, __LINE__);
			}
			iput(ZTOI(pzp));
			zfs_sb_group_rele(zsb, FTAG);
			return 0;
		}
	}else{
		cmn_err(CE_WARN, "%s:get target zfsvfs_t pointer fail!", __func__);
		return (EINVAL);
	}
	if (xvap == NULL) {
		cmn_err(CE_WARN, "%s, %d, xvap is NULL, so this carrier data maybe corrupted!", __func__, __LINE__);
		iput(ZTOI(pzp));
		zfs_sb_group_rele(zsb, FTAG);
		return 0;
	}
	credp = zfs_group_getcred(&z_carrier->z_dtl.setattr.cred);
	err = zfs_client_setattr_backup(pzp, (vattr_t*)xvap, z_carrier->z_dtl.setattr.flag,
		credp, m_node_type);

	abort_creds(credp);
	iput(ZTOI(pzp));
	zfs_sb_group_rele(zsb, FTAG);
	return (err);
}

static int
zfs_group_dtl_resolve_dirquota(zfs_group_dtl_carrier_t *z_carrier, 
	zfs_multiclus_node_type_t m_node_type)
{
	int err = 0;
	zfs_sb_t *zsb = NULL;
	znode_t *zp = NULL;
	
	if(NULL == z_carrier){
		cmn_err(CE_WARN, "%s: z_carrier is NULL!", __func__);
		return (EINVAL);
	}
	
	zsb = zfs_sb_group_hold(z_carrier->z_dtl.dirquota.spa_id, 
		z_carrier->z_dtl.dirquota.os_id, FTAG, B_FALSE);

	if(NULL == zsb){
		cmn_err(CE_WARN, "%s:get directory zfsvfs_t pointer fail!", __func__);
		return (EINVAL);
	}
	
	err = zfs_zget(zsb, z_carrier->z_dtl.dirquota.obj_id, &zp);
	if (err) {
		cmn_err(CE_WARN, "%s, %d, zget failed! err: %d", __func__, __LINE__, err);
		zfs_sb_group_rele(zsb, FTAG);
		return err;
	}else if(zp->z_gen != z_carrier->z_dtl.dirquota.dir_gen){
		if(1 == debug_nas_group_dtl){
			cmn_err(CE_WARN, "%s: %d!, dir_gen is different.", __func__, __LINE__);
		}
		iput(ZTOI(zp));
		zfs_sb_group_rele(zsb, FTAG);
		return 0;
	}
	
	err = zfs_client_set_dirquota_backup(zp, z_carrier->z_dtl.dirquota.obj_id,
		z_carrier->z_dtl.dirquota.path, z_carrier->z_dtl.dirquota.quota, m_node_type);

	iput(ZTOI(zp));
	zfs_sb_group_rele(zsb, FTAG);
	return (err);
}

static int
zfs_group_dtl_resolve_dirlowdata(zfs_group_dtl_carrier_t *z_carrier, 
	zfs_multiclus_node_type_t m_node_type)
{
	int err = 0;
	zfs_sb_t *zsb = NULL;
	znode_t *zp = NULL;
	nvpairvalue_t *pairvalue = NULL;
	
	zsb = zfs_sb_group_hold(z_carrier->z_dtl.dirlowdata.spa_id, 
		z_carrier->z_dtl.dirlowdata.os_id, FTAG, B_FALSE);

	if(NULL == zsb){
		cmn_err(CE_WARN, "%s:get directory zfsvfs_t pointer fail!", __func__);
		return (EINVAL);
	}

	err = zfs_zget(zsb, z_carrier->z_dtl.dirlowdata.obj_id, &zp);
	if (err) {
		cmn_err(CE_WARN, "%s, %d, zget failed! err: %d", __func__, __LINE__, err);
		zfs_sb_group_rele(zsb, FTAG);
		return err;
	}else if(zp->z_gen != z_carrier->z_dtl.dirlowdata.dir_gen){
		if(1 == debug_nas_group_dtl){
			cmn_err(CE_WARN, "%s: %d!, dir_gen is different.", __func__, __LINE__);
		}
		iput(ZTOI(zp));
		zfs_sb_group_rele(zsb, FTAG);
		return 0;
	}

	pairvalue = kmem_zalloc(sizeof(nvpairvalue_t), KM_SLEEP);
	pairvalue->value = z_carrier->z_dtl.dirlowdata.value;
	strncpy(pairvalue->path, z_carrier->z_dtl.dirlowdata.path, 
		sizeof(z_carrier->z_dtl.dirlowdata.path));
	pairvalue->path[sizeof(pairvalue->path)-1] = '\0';
	strncpy(pairvalue->propname, z_carrier->z_dtl.dirlowdata.propname, 
		sizeof(z_carrier->z_dtl.dirlowdata.propname));
	pairvalue->propname[sizeof(pairvalue->propname)-1] = '\0';
	
	err = zfs_client_set_dirlow_backup(zp, pairvalue, m_node_type);
	
	if (NULL != pairvalue)
		kmem_free(pairvalue, sizeof(nvpairvalue_t));
	iput(ZTOI(zp));
	zfs_sb_group_rele(zsb, FTAG);
	return (err);
}


int
zfs_group_dtl_resolve(zfs_group_dtl_carrier_t *z_carrier, zfs_multiclus_node_type_t m_node_type)
{
	int error = 0;
	name_operation_t	z_op = z_carrier->z_op;

	if(z_carrier->z_magic != ZFS_GROUP_DTL_MAGIC){
		error = 0;
		cmn_err(CE_WARN, "[%s %d] ZFS_GROUP_DTL_MAGIC is corrupt!", __func__, __LINE__);
		return (error);
	}

	switch(z_op)
	{
		case NAME_CREATE:
		{
			error = zfs_group_dtl_resolve_create(z_carrier, m_node_type);
			if(error == EEXIST){
				error = 0;
			}
			break;
		}
		case NAME_REMOVE:
		{
			error = zfs_group_dtl_resolve_remove(z_carrier, m_node_type);
			if(error == ENOENT){
				error = 0;
			}
			break;
		}
		case NAME_MKDIR:
		{
			error = zfs_group_dtl_resolve_mkdir(z_carrier, m_node_type);
			if(error == EEXIST){
				error = 0;
			}
			break;
		}
		case NAME_RMDIR:
		{
			error = zfs_group_dtl_resolve_rmdir(z_carrier, m_node_type);
			if(error == ENOENT){
				error = 0;
			}
			break;
		}
		case NAME_LINK:
		{
			error = zfs_group_dtl_resolve_link(z_carrier, m_node_type);
			break;
		}
		case NAME_RENAME:
		{
			error = zfs_group_dtl_resolve_rename(z_carrier, m_node_type);
			break;
		}
		case NAME_SYMLINK:
		{
			error = zfs_group_dtl_resolve_symlink(z_carrier, m_node_type);
			break;
		}
		case NAME_ACL:
		{
			error = zfs_group_dtl_resolve_acl(z_carrier, m_node_type);
			break;
		}
		case NAME_ZNODE_SETATTR:
		{
			error = zfs_group_dtl_resolve_znode_setattr(z_carrier, m_node_type);
			break;
		}
		case NAME_DIRQUOTA:
		{
			error = zfs_group_dtl_resolve_dirquota(z_carrier, m_node_type);
			break;
		}
		case NAME_DIRLOWDATA:
		{
			error = zfs_group_dtl_resolve_dirlowdata(z_carrier, m_node_type);
			break;
		}
		default:
			return (EINVAL);

	}
	return (error);
}
#endif

#ifdef _KERNEL
typedef struct zfs_group_dtl_thread_para{
	objset_t *os;
	zfs_multiclus_node_type_t master_type; 
}zfs_group_dtl_thread_para_t;
#endif

static void
zfs_group_dtl_thread_worker(void* arg)
{
#ifdef _KERNEL
	zfs_sb_t *zsb = NULL;
	avl_tree_t* ptree = NULL;
	avl_index_t where;
	kmutex_t *ptree_mutex = NULL;
	zfs_group_dtl_node_t *dtlnode = NULL;
	zfs_group_dtl_node_t *dn = NULL;
	zfs_group_dtl_node_t *old_dn = NULL;
	uint64_t count = 0;
	zfs_group_dtl_carrier_t *z_carrier = NULL;
	int dtlerror = 0;
	clock_t time = 0;
	zfs_multiclus_group_record_t *record = NULL;
	objset_t *os = NULL;
	zfs_group_dtl_thread_t *pdtlthread = NULL;
	zfs_multiclus_node_type_t master_type;
	zfs_group_dtl_thread_para_t *thread_para = (zfs_group_dtl_thread_para_t *)arg;
	os = thread_para->os;
	master_type = thread_para->master_type;
	kmem_free(arg, sizeof(zfs_group_dtl_thread_para_t));
	
	time = drv_usectohz(ZFS_GROUP_DTL_SECOND_CVWAIT_TIME);
	
	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	if (zsb == NULL) {
		cmn_err(CE_WARN, "[%s %d] get zsb failed.", __func__, __LINE__);
		return;
	}

	rrm_enter(&zsb->z_teardown_lock, RW_READER, FTAG);

	switch(master_type){
		case ZFS_MULTICLUS_MASTER2:
			ptree = &zsb->z_group_dtl_tree;
			ptree_mutex = &zsb->z_group_dtl_tree_mutex;
			pdtlthread = &os->os_group_dtl_th;
			break;
		case ZFS_MULTICLUS_MASTER3:
			ptree = &zsb->z_group_dtl_tree3;
			ptree_mutex = &zsb->z_group_dtl_tree3_mutex;
			pdtlthread = &os->os_group_dtl3_th;
			break;
		case ZFS_MULTICLUS_MASTER4:
			ptree = &zsb->z_group_dtl_tree4;
			ptree_mutex = &zsb->z_group_dtl_tree4_mutex;
			pdtlthread = &os->os_group_dtl4_th;
			break;
		default:
			rrm_exit(&zsb->z_teardown_lock, FTAG);
			cmn_err(CE_WARN, "[%s %d] master_type=%d", __func__, __LINE__, master_type);
			return;
	}
	
	dtlnode = kmem_zalloc(sizeof(zfs_group_dtl_node_t), KM_SLEEP);
	z_carrier = kmem_zalloc(sizeof(zfs_group_dtl_carrier_t), KM_SLEEP);
	
	rrm_exit(&zsb->z_teardown_lock, FTAG);
	mutex_enter(&pdtlthread->z_group_dtl_lock);
	
	while (1) {
		
		do {
			if (pdtlthread->z_group_dtl_thr_exit){
				cmn_err(CE_WARN, "[%s %d] thread exit", __func__, __LINE__);
				goto out;
			}

			if(os->os_is_group == B_TRUE && os->os_is_master == B_TRUE){
				/* Load dtl tree from Segment A. */
				zfs_group_dtl_loadX(os, master_type, 0);
				/* Write dtl tree to Segement B. */
				zfs_group_dtl_sync_treeX(os, master_type, 1);
				/* Load dtl tree from Segment B. */
				zfs_group_dtl_loadX(os, master_type, 1);
				mutex_enter(ptree_mutex);
				count = avl_numnodes(ptree);
				mutex_exit(ptree_mutex);
				if(count > 0)
					break;
			}
			cv_timedwait(&pdtlthread->z_group_dtl_cv, &pdtlthread->z_group_dtl_lock, ddi_get_lbolt() + time);
			
			if(os->os_is_group == B_TRUE && os->os_is_master == B_TRUE){
				zfs_group_dtl_sync_tree2(os, NULL, 1);
			}
		} while (count <= 0);
		
		if (zfs_multiclus_enable()) {
			record = zfs_multiclus_get_group_master(zsb->z_os->os_group_name, master_type);
		}else{
			record = NULL;
		}

		if(record != NULL && record->node_status.status != ZFS_MULTICLUS_NODE_OFFLINE){
			mutex_enter(ptree_mutex);
			dn = avl_first(ptree);
			while (count > 0 && dn && avl_numnodes(ptree)) {
				if(pdtlthread->z_group_dtl_thr_exit){
					if(1 == debug_nas_group_dtl){
						cmn_err(CE_WARN, "[yzy] %s %d count %llx, master_type %d", 
						    __func__, __LINE__, (unsigned long long)count, master_type);
					}
					mutex_exit(ptree_mutex);
					cmn_err(CE_WARN, "[%s %d] thread exit", __func__, __LINE__);
					goto out;
				}

				/* save current dn into dtlnode, later, noce take dlt tree again, check if this node is still
				  * in the dtl tree. If no, it means that the dtl tree has been dirtied by an other thread, 
				  * break current while loop.
				  */
				bcopy(dn, dtlnode, sizeof(zfs_group_dtl_node_t));
				bcopy(&dn->data.data[0], z_carrier, sizeof(zfs_group_dtl_carrier_t));
				mutex_exit(ptree_mutex);
				dtlerror = zfs_group_dtl_resolve(z_carrier, master_type);
				mutex_enter(ptree_mutex);
				dn = avl_find(ptree, dtlnode, &where);
				if(dn == NULL){
					/* If dn can't be find back, the dtl tree must be dirty. Break the while loop. */
					cmn_err(CE_WARN, "[%s %d] avl_find error.", __func__, __LINE__);
					break;			
				}
				old_dn = dn;
				dn = AVL_NEXT(ptree, old_dn);
				if(dtlerror == 0){
					avl_remove(ptree, old_dn);
					kmem_free(old_dn, sizeof(zfs_group_dtl_node_t));
				}
				
				if(1 == debug_nas_group_dtl){
					cmn_err(CE_WARN, "[yzy] %s %d count %llu, mater_type %d", 
						__func__, __LINE__, (unsigned long long)count, master_type);
				}
				count --;
			}
			mutex_exit(ptree_mutex);
		}
		/* Write dtl tree into segment A on disk at first */
		zfs_group_dtl_sync_treeX(os, master_type, 0);
		delay(drv_usectohz(3000000));
	}

out:
	if(os->os_is_group == B_TRUE && os->os_is_master == B_TRUE){
		zfs_group_dtl_sync_tree2(os, NULL, 0);
		zfs_group_dtl_sync_treeX(os, master_type, 0);
	}
	pdtlthread->z_group_dtl_thread = NULL;
	mutex_exit(&pdtlthread->z_group_dtl_lock);
	if (NULL != z_carrier)
		kmem_free(z_carrier, sizeof(zfs_group_dtl_carrier_t));
	if (NULL != dtlnode)
		kmem_free(dtlnode, sizeof(zfs_group_dtl_node_t));
	cv_signal(&pdtlthread->z_group_dtl_cv);
	thread_exit();
#endif
}

void
start_zfs_group_dtl_thread(objset_t *os)
{
#ifdef _KERNEL
	zfs_group_dtl_thread_para_t *thread_para = NULL;
	
	mutex_enter(&os->os_group_dtl_th.z_group_dtl_lock);
	if (os->os_group_dtl_th.z_group_dtl_thread == NULL) {
		thread_para = kmem_zalloc(sizeof(zfs_group_dtl_thread_para_t), KM_SLEEP);			
		thread_para->os = os;			
		thread_para->master_type = ZFS_MULTICLUS_MASTER2;
		os->os_group_dtl_th.z_group_dtl_thr_exit = B_FALSE;
		os->os_group_dtl_th.z_group_dtl_thread = kthread_run(zfs_group_dtl_thread_worker, 
			(void *) thread_para, "%s", "zfs_group_dtl_1");
	}
	mutex_exit(&os->os_group_dtl_th.z_group_dtl_lock);

	mutex_enter(&os->os_group_dtl3_th.z_group_dtl_lock);
	if (os->os_group_dtl3_th.z_group_dtl_thread == NULL) {
		thread_para = kmem_zalloc(sizeof(zfs_group_dtl_thread_para_t), KM_SLEEP);			
		thread_para->os = os;			
		thread_para->master_type = ZFS_MULTICLUS_MASTER3;
		os->os_group_dtl3_th.z_group_dtl_thr_exit = B_FALSE;
		os->os_group_dtl3_th.z_group_dtl_thread = kthread_run(zfs_group_dtl_thread_worker, 
			(void *) thread_para, "%s", "zfs_group_dtl_3");
	}
	mutex_exit(&os->os_group_dtl3_th.z_group_dtl_lock);

	mutex_enter(&os->os_group_dtl4_th.z_group_dtl_lock);
	if (os->os_group_dtl4_th.z_group_dtl_thread == NULL) {
		thread_para = kmem_zalloc(sizeof(zfs_group_dtl_thread_para_t), KM_SLEEP);			
		thread_para->os = os;			
		thread_para->master_type = ZFS_MULTICLUS_MASTER4;
		os->os_group_dtl4_th.z_group_dtl_thr_exit = B_FALSE;
		os->os_group_dtl4_th.z_group_dtl_thread = kthread_run(zfs_group_dtl_thread_worker, 
			(void *) thread_para, "%s", "zfs_group_dtl_4");
	}
	mutex_exit(&os->os_group_dtl4_th.z_group_dtl_lock);
	
#endif
}

boolean_t
stop_zfs_group_dtl_thread(objset_t *os)
{
#ifdef _KERNEL
	clock_t time = 0;

	time = drv_usectohz(ZFS_GROUP_DTL_SECOND_CVWAIT_TIME);
	
	if (os->os_group_dtl_th.z_group_dtl_thread != NULL) {
		os->os_group_dtl_th.z_group_dtl_thr_exit = B_TRUE;
		cv_signal(&os->os_group_dtl_th.z_group_dtl_cv);
		cv_timedwait(&os->os_group_dtl_th.z_group_dtl_cv,
			&os->os_group_dtl_th.z_group_dtl_lock, ddi_get_lbolt() + time);
		os->os_group_dtl_th.z_group_dtl_thread = NULL;
	}

	if (os->os_group_dtl3_th.z_group_dtl_thread != NULL) {
		os->os_group_dtl3_th.z_group_dtl_thr_exit = B_TRUE;
		cv_signal(&os->os_group_dtl3_th.z_group_dtl_cv);
		cv_timedwait(&os->os_group_dtl3_th.z_group_dtl_cv, 
			&os->os_group_dtl3_th.z_group_dtl_lock, ddi_get_lbolt() + time);
		os->os_group_dtl3_th.z_group_dtl_thread = NULL;
	}

	if (os->os_group_dtl4_th.z_group_dtl_thread != NULL) {
		os->os_group_dtl4_th.z_group_dtl_thr_exit = B_TRUE;
		cv_signal(&os->os_group_dtl4_th.z_group_dtl_cv);
		cv_timedwait(&os->os_group_dtl4_th.z_group_dtl_cv, 
			&os->os_group_dtl4_th.z_group_dtl_lock, ddi_get_lbolt() + time);
		os->os_group_dtl4_th.z_group_dtl_thread = NULL;
	}
	
#endif
	return (B_TRUE);
}

