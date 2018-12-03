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

/*
 * On the wrcache code: this is a reasonably solid piece of
 * code that we choose not to enable just yet (it is disabled in the
 * user-level code, such that it is not possible to set specialclass to
 * wrcache). We fully intend to turn this on in the next release, but we
 * feel that performance needs to be optimized, and other things adjusted.
 */
#include <sys/zfs_context.h>
#include <sys/fm/fs/zfs.h>
#include <sys/spa_impl.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/zap.h>
#include <sys/zil.h>
#include <sys/ddt.h>
#include <sys/dmu_traverse.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_scan.h>
#include <sys/dsl_prop.h>
#include <sys/arc.h>
#include <sys/vdev_impl.h>
#include <sys/mutex.h>
#include <sys/time.h>
#include <sys/zfs_znode.h>

#ifdef _KERNEL
#include <sys/zfs_group.h>
#include <sys/ddi.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_multiclus.h>
#endif
#include <sys/wrcache.h>
#define	TRYIMPORT_NAME	"$import"

uint64_t zfs_wrc_data_max = 48 << 20; /* Max data to migrate in a pass */
int debug_migrate = 1;

void migrate_insert_wait(clock_t mtime);
static boolean_t dsl_wrc_move_block(wrc_data_t *wrc_data, wrc_block_t *block);

extern int dmu_buf_hold_array(objset_t *os, uint64_t object, uint64_t offset,
    uint64_t length, int read, void *tag, int *numbufsp, dmu_buf_t ***dbpp);

#ifdef _KERNEL
static boolean_t dsl_pool_wrcio_limit(dsl_pool_t *dp, uint64_t txg, uint64_t wrcio_towrite);
static boolean_t wrc_check_cluster_lowdata_migrate(uint64_t spa_guid, uint64_t objsetid, uint64_t objid, 
		objset_t *os, znode_t *zp, zfs_lowdata_type_t lw_type);
#endif
void travese_migrate_thread(wrc_migrate_param_t *param);


/*
 * Thread to manage the data movement from
 * special devices to normal devices.
 * This thread runs as long as the spa is active.
 */
static void
spa_wrc_thread(objset_t *os)
{
#ifdef _KERNEL

	wrc_data_t *wrc_data = &os->os_wrc;
	wrc_block_t	*block = 0;
	wrc_blkhdr_t	*blkhdr;
	uint64_t	done_count = 0;
	uint64_t	migrated_file_len = 0;
	mutex_enter(&wrc_data->wrc_lock);
	/* CONSTCOND */
	while (1) {
		uint64_t count;

		wrc_data->wrc_block_count -= done_count;
		done_count = 0;
		do {
			if (os->os_spa->spa_state == POOL_STATE_UNINITIALIZED ||
			    wrc_data->wrc_thr_exit)
				goto out;

			/* wrc_block_count means pending file nodes to be migrated to low vdev. */
			count = wrc_data->wrc_block_count;

			if(count > 0) break;
			
			cv_wait(&wrc_data->wrc_cv, &wrc_data->wrc_lock);
			
		} while (count <= 0);

		while (count > 0) {
			/* Check if this scan thread is stopped by user command 'zpool scrub -s <pool name>'. */
			if (wrc_data->wrc_thr_exit)
				break;
			/* Take the first file node to migrate. */
			block = list_head(&wrc_data->wrc_blocks);
			if (block) {
				boolean_t bmigrated = B_FALSE;
				list_remove(&wrc_data->wrc_blocks, block);
				mutex_exit(&wrc_data->wrc_lock);
				bmigrated = dsl_wrc_move_block(wrc_data, block);
				migrated_file_len = block->size;
				kmem_free(block, sizeof (*block));
				mutex_enter(&wrc_data->wrc_lock);
				/* If bmigrated is TRUE, it means that dsl_wrc_move_block() already updated wrc_data->wrc_total_migrated progressively. */
				if(B_FALSE == bmigrated){
					wrc_data->wrc_total_migrated = wrc_data->wrc_total_migrated + migrated_file_len;
					//mutex_enter(&os->os_spa->spa_wrc_status.status_lock);
					//os->os_spa->spa_wrc_status.spa_total_migrated += migrated_file_len;
					//mutex_exit(&os->os_spa->spa_wrc_status.status_lock);
				}
			} else {
				break;
			}
			count--;
			done_count++;
		}
	}

out:
	/*
	 * Clean up the list.
	 */
	while (block = list_head(&wrc_data->wrc_blocks)) {
		list_remove(&wrc_data->wrc_blocks, block);
		kmem_free(block, sizeof (*block));
	}
	wrc_data->wrc_block_count = 0;

	//mutex_enter(&os->os_spa->spa_wrc_status.status_lock);
	//os->os_spa->spa_wrc_status.spa_total_migrated -= wrc_data->wrc_total_migrated;
	//os->os_spa->spa_wrc_status.spa_total_to_migrate -= wrc_data->wrc_total_to_migrate;
	//mutex_exit(&os->os_spa->spa_wrc_status.status_lock);

	blkhdr = wrc_data->wrc_blkhdr_head;
	while (blkhdr) {
		boolean_t last = (blkhdr == blkhdr->next);
		wrc_data->wrc_blkhdr_head = blkhdr->next;
		wrc_data->wrc_blkhdr_head->prev = blkhdr->prev;
		blkhdr->prev->next = wrc_data->wrc_blkhdr_head;
		DTRACE_PROBE1(wrc_blkhdr, char *, blkhdr->ds_name);
		kmem_free(blkhdr, sizeof (*blkhdr));

		if (!last)
			blkhdr = wrc_data->wrc_blkhdr_head;
		else
			blkhdr = NULL;
	}
	wrc_data->wrc_blkhdr_head = NULL;
	wrc_data->wrc_thread = NULL;
	wrc_data->wrc_thr_exit = B_FALSE;
	mutex_exit(&wrc_data->wrc_lock);
	thread_exit();
#endif
}

void
start_wrc_thread(objset_t *os, uint64_t flags, uint64_t obj)
{
#ifdef _KERNEL
	int err = 0;
	wrc_data_t *wrc = NULL;
	wrc_migrate_param_t *param = NULL;

	if (os == NULL) {
		cmn_err(CE_WARN, "%s, %d, Invalid os, os is NULL", __func__, __LINE__);
		return;
	}

	wrc = &os->os_wrc;
	
	mutex_enter(&wrc->wrc_lock);
	if (wrc->wrc_thread == NULL) {
		wrc->wrc_thread = thread_create(NULL, 0,
		    spa_wrc_thread, os, 0, &p0, TS_RUN, maxclsyspri);
		wrc->wrc_thr_exit = B_FALSE;
		/* To ensure wrc task queue not overflow 512M memory. */
		wrc->wrc_max_task_queue_depth = (512 << 20)/sizeof(wrc_block_t);
		migrate_insert_wait(500);
	}

	param = kmem_zalloc(sizeof(wrc_migrate_param_t), KM_SLEEP);
	param->os = os;
	param->flags = flags;
	param->obj = obj;
	if (os->os_is_group == B_FALSE || (os->os_is_group == B_TRUE && os->os_is_master == B_TRUE)) {
		if (wrc->traverse_thread == NULL) {
			wrc->traverse_thread = thread_create(NULL, 0,
				travese_migrate_thread, param, 0, &p0, TS_RUN, maxclsyspri);
			wrc->trav_thr_exit = B_FALSE;
		}
	}
	
	mutex_exit(&wrc->wrc_lock);
#endif
}

boolean_t
stop_wrc_thread(objset_t *os)
{
#ifdef _KERNEL
	int err = 0;
	wrc_data_t *wrc = NULL;

	if (os == NULL) {
		cmn_err(CE_WARN, "%s, %d, Invalid os, os is NULL", __func__, __LINE__);
		return(B_FALSE);
	}

	wrc = &os->os_wrc;

	mutex_enter(&wrc->wrc_lock);

	if (wrc->traverse_thread != NULL) {
		wrc->trav_thr_exit = B_TRUE;
		mutex_exit(&wrc->wrc_lock);
		while (wrc->traverse_finished == B_FALSE) {
			migrate_insert_wait(1000);
		}
		mutex_enter(&wrc->wrc_lock);
		wrc->traverse_thread = NULL;
	}

	if (wrc->wrc_thread != NULL) {
		wrc->wrc_thr_exit = B_TRUE;
		//kt_did_t tdid = wrc->wrc_thread->t_did;
		cv_signal(&wrc->wrc_cv);
		mutex_exit(&wrc->wrc_lock);
		//thread_join(tdid);
		return (B_TRUE);
	}

	mutex_exit(&wrc->wrc_lock);
#endif
	return (B_FALSE);
}

#ifdef _KERNEL

static int wrc_client_get_atime(zfs_sb_t *zsb, uint64_t master_object, uint64_t *atime)
{
	int err = 0;
	znode_t *zp = NULL;

	err = zfs_group_zget(zsb, master_object, &zp, 0, 0, 0, B_FALSE);
	if (err == 0) {
		atime[0] = ZTOI(zp)->i_atime.tv_sec;
		atime[1] = ZTOI(zp)->i_atime.tv_nsec;
		iput(ZTOI(zp));
	}
	return err;
}

static int wrc_get_dirlowdata_obj(zfs_sb_t *zsb, znode_t *zp_loc, uint64_t *dirlowdata)
{
	int err = 0;
	znode_t *zp = NULL;

	if (zsb->z_os->os_is_group && !zsb->z_os->os_is_master) {
		err = zfs_group_zget(zsb, zp_loc->z_group_id.master_object, &zp, 0, 0, 0, B_FALSE);
		if (err == 0) {
			*dirlowdata = zp->z_dirlowdata;
			iput(ZTOI(zp));
		}
	} else {
		*dirlowdata = zp_loc->z_dirlowdata;
	}

	return err;
}

/*
 * Moves blocks from a special device to other devices in a pool.
 * TODO: For now the function ignores any errors and it's not
 * correct enough. Ideally there should be a way to report
 * to sync context not to update starting transaction group id.
 */
int tx_again_times = 0x1000;
int debug_wrcache = 1;
static boolean_t dsl_wrc_move_block(wrc_data_t *wrc_data, wrc_block_t *block)
{

	objset_t *os = NULL;
	dmu_tx_t *tx;
	dmu_buf_t *db;
	int err = 0;
	boolean_t stop_wrc_thr = B_FALSE;
	boolean_t bmigrated = B_FALSE;
	boolean_t low_delete = B_FALSE;
	boolean_t send_notify = B_FALSE;

	zfs_sb_t* zfsp = NULL;
	znode_t* zpp = NULL;
	znode_t		*dzp = NULL;
	uint64_t	parent;
	struct	vattr	va;

	dmu_buf_t **dbp;
	dmu_buf_impl_t *db_impl;
	int numbufs, i;

	uint64_t file_length = 0;
	uint64_t file_offset = 0;
	uint64_t wrcio_towrite = 0;
	uint64_t file_done = 0;
	uint64_t dirlowdata_obj = 0;
	rl_t		*rl;
	
	timestruc_t now;
	timestruc_t lowdatatime;
	time_t diff_seconds;
	time_t period;

	char	fname[MAXNAMELEN];

	uint64_t metadata_size = 0;

	zfs_dirlowdata_t dirlowdata = {"",0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,
		0xffffffffffffffff,0xffffffffffffffff};

	sa_bulk_attr_t bulk[5];
	int count = 0;
	int tx_try_again = 0;

	zfs_lowdata_type_t lowdata = ZFS_LOWDATA_OFF;
	zfs_lowdata_criteria_t lowdata_criteria = ZFS_LOWDATA_CRITERIA_ATIME;
	zfs_lowdata_period_unit_t lowdata_period_unit = ZFS_LOWDATA_PERIOD_DAY;

	/* By default, after 7days, if no access, set the file as lowdata, if it is more than 10 days, delete it. */
	uint64_t lowdata_period = 7, lowdata_delete_period = 10;

	zfsp = zfs_sb_group_hold(block->spa_guid, block->objset, FTAG, B_FALSE);
	if(zfsp){
		err = zfs_zget(zfsp, block->object, &zpp);
		if (err) {
			cmn_err(CE_WARN, "dsl_wrc_move_block failed in get plain file's attributes!");
			if (debug_wrcache)
				cmn_err(CE_WARN, "[debug_wrcache] %s, %d, zget failed, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
			goto skip;
		}
		os = zfsp->z_os;
		if(os == NULL){
			cmn_err(CE_WARN, "dsl_wrc_move_block failed in get zfsvfs_t->z_os pointer !");
			if (debug_wrcache)
				cmn_err(CE_WARN, "[debug_wrcache] %s, %d, os is NULL, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
			iput(ZTOI(zpp));
			goto skip;
		}
		
	}else{
		cmn_err(CE_WARN, "dsl_wrc_move_block failed in get zfsvfs_t pointer !");
		if (debug_wrcache)
			cmn_err(CE_WARN, "[debug_wrcache] %s, %d, zfsvfs is NULL, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
		return B_FALSE;
	}

	if( zpp->z_size == 0 || (strlen(zpp->z_filename) == 0 && (os->os_is_group != B_TRUE)) ||
		(strlen(zpp->z_filename) == 0 && os->os_is_group == B_TRUE && os->os_is_master == B_TRUE)){
		if (debug_wrcache)
			cmn_err(CE_WARN, "[debug_wrcache] %s, %d, size or name is 0, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
		iput(ZTOI(zpp));
		goto skip;
	}

	if (wrc_get_dirlowdata_obj(zfsp, zpp, &dirlowdata_obj)) {
		if (debug_wrcache)
			cmn_err(CE_WARN, "[debug_wrcache] %s, %d, get dirlowdata obj failed, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
		iput(ZTOI(zpp));
		goto skip;
	}

	if (dirlowdata_obj != 0) {
		if (os->os_is_group && os->os_is_master == 0) {
			err = zfs_client_get_dirlowdata(zfsp, zpp, &dirlowdata);
		} else {
			err = zfs_get_dir_low(zfsp, zpp->z_dirlowdata, &dirlowdata);
		}
		if (err) {
			if (debug_wrcache)
				cmn_err(CE_WARN, "[debug_wrcache] %s, %d, get struct dirlowdata failed, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
			iput(ZTOI(zpp));
			goto skip;
		}
		if (dirlowdata.lowdata >= ZFS_LOWDATA_OFF && dirlowdata.lowdata <= ZFS_LOWDATA_END ){
			lowdata = dirlowdata.lowdata;
			lowdata_criteria = dirlowdata.lowdata_criteria;
			lowdata_period = dirlowdata.lowdata_period;
			lowdata_delete_period = dirlowdata.lowdata_delete_period;
			lowdata_period_unit = dirlowdata.lowdata_period_unit;
		}
	} else {
		lowdata = zfsp->z_lowdata;
		lowdata_criteria = zfsp->z_lowdata_criteria;
		lowdata_period = zfsp->z_lowdata_period;
		lowdata_delete_period = zfsp->z_lowdata_delete_period;
		lowdata_period_unit = zfsp->z_lowdata_period_unit;
	}

	if (lowdata == ZFS_LOWDATA_OFF) {
		if (debug_wrcache)
			cmn_err(CE_WARN, "[debug_wrcache] %s, %d, lowdata is off, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
		iput(ZTOI(zpp));
		goto skip;
	}

	gethrestime(&now);

	if(lowdata_criteria == ZFS_LOWDATA_CRITERIA_CTIME){
		/*uint64_t crtime[2];
		sa_lookup(zpp->z_sa_hdl, SA_ZPL_CRTIME(zfsp),
			crtime, sizeof (crtime));
		ZFS_TIME_DECODE(&lowdatatime, crtime);
		*/
		diff_seconds = now.tv_sec - ZTOI(zpp)->i_ctime.tv_sec;
	}else{
		uint64_t atime[2];
		if (os->os_is_group == B_TRUE && os->os_is_master == B_FALSE) {
			err = wrc_client_get_atime(zfsp, zpp->z_group_id.master_object, atime);
			if (err != 0) {
				if (debug_wrcache)
					cmn_err(CE_WARN, "[debug_wrcache] %s, %d, get atime failed, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
				iput(ZTOI(zpp));
				goto skip;
			}
			//ZFS_TIME_DECODE(&lowdatatime, atime);
			diff_seconds = now.tv_sec - atime[0];
		} else {
			//ZFS_TIME_DECODE(&lowdatatime, zpp->z_atime);
			diff_seconds = now.tv_sec - ZTOI(zpp)->i_atime.tv_sec;
		}
	}
	
	diff_seconds = now.tv_sec - lowdatatime.tv_sec;
	if(diff_seconds > 0){
		switch(lowdata_period_unit){
			
			case ZFS_LOWDATA_PERIOD_SEC:
				period = diff_seconds;
				break;
			case ZFS_LOWDATA_PERIOD_MIN:
				period = diff_seconds/60;
				break;
			case ZFS_LOWDATA_PERIOD_HR:
				period = diff_seconds/3600;
				break;
			case ZFS_LOWDATA_PERIOD_DAY:
			default:
				period = diff_seconds/3600/24;
				break;
		}
		if(period < lowdata_period ){
			if (debug_wrcache)
				cmn_err(CE_WARN, "[debug_wrcache] %s, %d, period not reach, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
			iput(ZTOI(zpp));
			goto skip;
		}
	}else{
		/* This is negative case, where current system time is later than file's access time. */
		if (debug_wrcache)
			cmn_err(CE_WARN, "[debug_wrcache] %s, %d, system time is laster(diff_second: %ld), skip file obj: %llx", 
			__func__, __LINE__, (unsigned long long)block->object, diff_seconds);
		iput(ZTOI(zpp));
		goto skip;
	}
	if (lowdata == ZFS_LOWDATA_MIGRATE) {
		if ((lowdata_delete_period > lowdata_period) && 
			(lowdata_delete_period > 0) && 
			(period > lowdata_delete_period)) {
			low_delete = B_TRUE;
		} else if (zpp->z_low == 1) {
			if (debug_wrcache)
				cmn_err(CE_WARN, "[debug_wrcache] %s, %d, file is migarated, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
			iput(ZTOI(zpp));
			goto skip;
		}
	}

	if(os->os_is_group == B_TRUE){
		/* Here block->spa_guid is local spa zpool id. */
		if( wrc_check_cluster_lowdata_migrate(block->spa_guid, block->objset, block->object,os,	zpp,  low_delete ? ZFS_LOWDATA_DELETE:lowdata) 
				== B_FALSE){
			if (debug_wrcache)
				cmn_err(CE_WARN, "[debug_wrcache] %s, %d, check lowdata migrate failed, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
			iput(ZTOI(zpp));
			goto skip;
		}
	}
	if(lowdata == ZFS_LOWDATA_MIGRATE && low_delete == B_FALSE){
		file_offset = 0;
		file_length = zpp->z_size;
		metadata_size = block->size > file_length ? block->size - file_length : 0;
		wrcio_towrite = min(file_length - file_done, block->block_size);
		bmigrated = B_TRUE;
		while(wrcio_towrite > 0 && (!wrc_data->wrc_thr_exit)) {
			
			rl = zfs_range_lock(&zpp->z_range_lock, file_offset, wrcio_towrite, RL_WRITER);
			
tx_again:
			tx = dmu_tx_create(os);
			dmu_tx_hold_write(tx, block->object, file_offset, wrcio_towrite);
			dmu_tx_hold_low(tx, B_TRUE);
			err = dmu_tx_assign(tx, TXG_NOWAIT);
			if (err != 0) {
				dmu_tx_abort(tx);
				if (err == ERESTART && tx_try_again < tx_again_times) {
					delay(5 * drv_usectohz(1000));
					tx_try_again++;
					goto tx_again;
				}				
				zfs_range_unlock(rl);				
				if (debug_wrcache)
					cmn_err(CE_WARN, "[debug_wrcache] %s, %d, txg assign failed, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
				iput(ZTOI(zpp));
				goto skip;
			}
			stop_wrc_thr = dsl_pool_wrcio_limit(tx->tx_pool, dmu_tx_get_txg(tx), wrcio_towrite);
		
			err = dmu_buf_hold_array(os, block->object, file_offset, wrcio_towrite,
			    FALSE, FTAG, &numbufs, &dbp);
			if (err != 0) {
				dmu_tx_commit(tx);
				zfs_range_unlock(rl);
				if (debug_wrcache)
					cmn_err(CE_WARN, "[debug_wrcache] %s, %d, dbuf hole filed, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
				iput(ZTOI(zpp));
				goto skip;
			}
	
			for (i = 0; i < numbufs; i++) {
				db = dbp[i];
				db_impl = (dmu_buf_impl_t *)db;
				if(!db_impl->db_low_data[tx->tx_txg & TXG_MASK] && db_impl->db_blkptr != NULL &&
                                   !BP_IS_HOLE(db_impl->db_blkptr)) {
				    if (BP_IS_APPLOW(db_impl->db_blkptr)) {
					    if (debug_wrcache)
					        cmn_err(CE_WARN, "[debug_wrcache] %s, %d, The blk is migrated, skip it and continue!", __func__, __LINE__);
					    continue;
                    }
				}

				db_impl->db_low_data[tx->tx_txg & TXG_MASK] = B_TRUE;
				dmu_buf_will_dirty(db, tx);
			}

			if((file_length - file_done) <= block->block_size){
				/* This last migration of the low file, so upate SA_ZPL_LOW. */
				/* Set plain file's attribute z_low to 1. */
	
				dmu_tx_hold_sa(tx, zpp->z_sa_hdl, B_FALSE);
				mutex_enter(&zpp->z_lock);
				zpp->z_low = 1;
				sa_update(zpp->z_sa_hdl, SA_ZPL_LOW(zpp->z_zsb),
				    &zpp->z_low, sizeof (zpp->z_low), tx);
				mutex_exit(&zpp->z_lock);
				if (os->os_is_group && !os->os_is_master) {
					send_notify = B_TRUE;
				}

				/* This is last file data transfer. Add the file's meta size to wrc_data->wrc_total_migrated. */
				wrc_data->wrc_total_migrated = wrc_data->wrc_total_migrated + metadata_size;
				//mutex_enter(&os->os_spa->spa_wrc_status.status_lock);
				//os->os_spa->spa_wrc_status.spa_total_migrated += metadata_size;
				//mutex_exit(&os->os_spa->spa_wrc_status.status_lock);
				
			}

			/* Release plain data dmu buffer arrays. */	
			dmu_buf_rele_array(dbp, numbufs, FTAG);

			dmu_tx_commit(tx);

			if (send_notify == B_TRUE) {
				sa_object_size(zpp->z_sa_hdl, (uint32_t *)&zpp->z_blksz, (u_longlong_t *)&zpp->z_nblks);
				zpp->z_nblks = ((unsigned long long)((zpp->z_size + SPA_MINBLOCKSIZE/2) >>
	        SPA_MINBLOCKSHIFT) + 1);
				zfs_client_notify_file_space(zpp, 0, EXPAND_SPACE, B_FALSE, block->spa_guid, block->objset);
				send_notify = B_FALSE;
			}

			wrc_data->wrc_total_migrated = wrc_data->wrc_total_migrated + wrcio_towrite;
			//mutex_enter(&os->os_spa->spa_wrc_status.status_lock);
			//os->os_spa->spa_wrc_status.spa_total_migrated += wrcio_towrite;
			//mutex_exit(&os->os_spa->spa_wrc_status.status_lock);
			file_offset = file_offset + wrcio_towrite;
			file_done = file_done + wrcio_towrite;
			wrcio_towrite = min(file_length - file_done, block->block_size);
		
			zfs_range_unlock(rl);
			
			if(stop_wrc_thr == B_TRUE){
				delay(drv_usectohz(1000000));
			}
		}		
		iput(ZTOI(zpp));
		
	}else if ( lowdata == ZFS_LOWDATA_DELETE || low_delete == B_TRUE) {

		if (zpp->z_pflags & (ZFS_IMMUTABLE | ZFS_READONLY)){
			/* Don't delete read only file. */
			if (debug_wrcache)
				cmn_err(CE_WARN, "[debug_wrcache] %s, %d, read only file, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
			iput(ZTOI(zpp));
			goto skip;
		}

		if(!S_ISREG(ZTOI(zpp)->i_mode) && !S_ISLNK(ZTOI(zpp)->i_mode)){
			/* Only delete regular files. */
			if (debug_wrcache)
				cmn_err(CE_WARN, "[debug_wrcache] %s, %d, is not a regular file, skip file obj: %llx, mode: %llx", 
				__func__, __LINE__, (unsigned long long)block->object, (unsigned long long)ZTOI(zpp)->i_mode);
			iput(ZTOI(zpp));
			goto skip;
		}

		va.va_mask = AT_MODE;
		if (zfs_getattr(ZTOI(zpp), &va, 0, CRED()) == 0) {
			if(va.va_mode == (S_IRUSR|S_IRGRP|S_IROTH) ||
				va.va_mode == (S_IRUSR|S_IRGRP)	||
				va.va_mode == (S_IRUSR|S_IROTH)	||
				va.va_mode == (S_IRGRP|S_IROTH)	||
				va.va_mode == S_IRUSR	|| va.va_mode == S_IRUSR || 
				va.va_mode == S_IROTH	|| va.va_mode == 0){
				/* This file has only read permisssion, don't delete it. */
				if (debug_wrcache)
					cmn_err(CE_WARN, "[debug_wrcache] %s, %d, has only read permission, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
				iput(ZTOI(zpp));
				goto skip;
			}
			
		}
		else{
			/* If failed in checking file's permission, skip this file. */
			if (debug_wrcache)
				cmn_err(CE_WARN, "[debug_wrcache] %s, %d, checking file's permission failed, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
			iput(ZTOI(zpp));
			goto skip;
		}
		
		do{
			if ((err = sa_lookup(zpp->z_sa_hdl,	SA_ZPL_PARENT(zpp->z_zsb), &parent,
						sizeof (parent))) != 0){
				cmn_err(CE_WARN, "sa_lookup() failed in getting SA_ZPL_PARENT.");
				if (debug_wrcache)
					cmn_err(CE_WARN, "[debug_wrcache] %s, %d, getting parent, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
				iput(ZTOI(zpp));
				goto skip;
			}

			if(parent == zpp->z_zsb->z_shares_dir){
				if (debug_wrcache)
					cmn_err(CE_WARN, "[debug_wrcache] %s, %d, parent is shares dir, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
				iput(ZTOI(zpp));
				goto skip;
			}

			err = zfs_zget(zfsp, parent, &dzp);
			if (err || dzp == NULL) {
				cmn_err(CE_WARN, "zfs_zget() failed in getting parent znode_t.");
				if (debug_wrcache)
					cmn_err(CE_WARN, "[debug_wrcache] %s, %d, getting parent's znode failed, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
				iput(ZTOI(zpp));
				goto skip;
			}

			switch (ZTOI(zpp)->i_mode & S_IFMT)
			{
				case S_IFREG:
					bcopy(zpp->z_filename, fname, strlen(zpp->z_filename)+1);
					d_prune_aliases(ZTOI(zpp));
					iput(ZTOI(zpp));
					if((err = zfs_remove(ZTOI(dzp), fname, CRED(), 0)) != 0){
						cmn_err(CE_WARN, "%s - delete file %s, errno:%d", __func__, fname, err);
					}
					break;
				case S_IFDIR:
					bcopy(zpp->z_filename, fname, strlen(zpp->z_filename)+1);
					d_prune_aliases(ZTOI(zpp));
					iput(ZTOI(zpp));
					if((err = zfs_rmdir(ZTOI(dzp), fname, ZTOI(dzp), CRED(), 0)) != 0){
						cmn_err(CE_WARN, "%s - remove directory %s, errno:%d", __func__, fname, err);
					}
					break;
				default:
					if (debug_wrcache)
						cmn_err(CE_WARN, "[debug_wrcache] %s, %d, vtype is not VREG and VDIR, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
					iput(ZTOI(zpp));
					goto skip;
			}
			
			zpp = dzp;
		}		while(zfs_dirempty(dzp) == B_TRUE && parent != dzp->z_zsb->z_root && dzp->z_dirlowdata != dzp->z_id);
		iput(ZTOI(zpp));
		
	}else {
		iput(ZTOI(zpp));
		if (debug_wrcache)
			cmn_err(CE_WARN, "[debug_wrcache] %s, %d, lowdata is not migrate and delete, skip file obj: %llx", __func__, __LINE__, (unsigned long long)block->object);
		goto skip;
	}

skip:
	zfs_sb_group_rele(zfsp,	FTAG);
	return bmigrated;
}


void wrc_insert_block(objset_t *os, uint64_t objset, uint64_t object, uint64_t file_length, uint64_t block_size)
{
	wrc_data_t *wrc_data = &os->os_wrc;
	wrc_block_t *block;
	int retry_times = 0;
	int max_retry = 1000;

insert:
	if(wrc_data->wrc_block_count < 
		os->os_wrc.wrc_max_task_queue_depth){

		block = kmem_alloc(sizeof (*block), KM_NOSLEEP);
		block->hdr = NULL;
		block->spa_guid = spa_guid(os->os_spa);
		block->objset = objset;
		block->object = object;

		block->size = file_length;
		block->block_size = block_size;
	
		mutex_enter(&wrc_data->wrc_lock);
		list_insert_tail(&wrc_data->wrc_blocks, block);
		wrc_data->wrc_block_count++;
		wrc_data->wrc_total_to_migrate = wrc_data->wrc_total_to_migrate + block->size;
		//mutex_enter(&os->os_spa->spa_wrc_status.status_lock);
		//os->os_spa->spa_wrc_status.spa_total_to_migrate += block->size;
		//mutex_exit(&os->os_spa->spa_wrc_status.status_lock);
		cv_signal(&wrc_data->wrc_cv);
		mutex_exit(&wrc_data->wrc_lock);
	} else {
		while (wrc_data->wrc_block_count < 
		os->os_wrc.wrc_max_task_queue_depth && retry_times < max_retry) {
			migrate_insert_wait(1);
			retry_times++;
			if (retry_times >= max_retry) {
				cmn_err(CE_WARN, "%s, %d, migrate used mem over 512m for a long time(1 second), insert failed!", __func__, __LINE__);
				return;
			}
		}
		goto insert;
	}
	
}

/*
 * This function checks if write cache migration i/o is
 * affecting the normal user i/o traffic. We determine this
 * by checking if total data in current txg > zfs_wrc_data_max
 * and migration i/o is more than zfs_wrc_io_perc_max % of total
 * data in this txg. If total data in this txg < zfs_dirty_data_sync/4,
 * we assume not much of user traffic is happening..
 */
static boolean_t
dsl_pool_wrcio_limit(dsl_pool_t *dp, uint64_t txg, uint64_t wrcio_towrite)
{
	boolean_t ret = B_FALSE;
	if (mutex_tryenter(&dp->dp_lock)) {
		if (dp->dp_dirty_pertxg[txg & TXG_MASK] != wrcio_towrite &&
		    dp->dp_dirty_pertxg[txg & TXG_MASK] > zfs_wrc_data_max &&
		    wrcio_towrite > ((WRCIO_PERC_MIN *
		    dp->dp_dirty_pertxg[txg & TXG_MASK]) / 100) &&
		    wrcio_towrite <
		    ((WRCIO_PERC_MAX * dp->dp_dirty_pertxg[txg & TXG_MASK]) /
		    100))
			ret = B_TRUE;
		mutex_exit(&dp->dp_lock);
	}
	return (ret);

}

static boolean_t wrc_check_cluster_lowdata_migrate(uint64_t spa_guid,	 uint64_t objsetid, uint64_t objid, 
		objset_t *os, znode_t *zp, zfs_lowdata_type_t lw_type)
{
	boolean_t ret =B_FALSE;
	switch(lw_type)
	{
		case ZFS_LOWDATA_MIGRATE:
			if(spa_guid == zp->z_group_id.data_spa && 
				objsetid == zp->z_group_id.data_objset&&
				objid == zp->z_group_id.data_object){
				ret = B_TRUE;
			}else{
				ret = B_FALSE;
			}
			break;
			
		case ZFS_LOWDATA_DELETE:
			if(os->os_is_master == FALSE){
				ret = B_FALSE;
			}else if(spa_guid == zp->z_group_id.master_spa && 
				objsetid == zp->z_group_id.master_objset&&
				objid == zp->z_group_id.master_object){
				ret = B_TRUE;
			}else {
				ret = B_FALSE;
			}
			break;
			
		default:
			ret = B_FALSE;
	}
	return ret;
}

void migrate_insert_wait(clock_t mtime)
{
	clock_t time = 0;
	kcondvar_t	send_cv;
	kmutex_t	send_lock;

	cv_init(&send_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&send_lock, NULL, MUTEX_DRIVER, NULL);

	time = drv_usectohz(mtime * 1000);
	mutex_enter(&send_lock);
	cv_timedwait(&send_cv, &send_lock, ddi_get_lbolt() + time);
	mutex_exit(&send_lock);

	mutex_destroy(&send_lock);
	cv_destroy(&send_cv);
}

void migrate_insert_block_to_cmd(zfs_migrate_cmd_t *migrate_cmd, int record_num, znode_t * zp, uint64_t block_size)
{
	int i, j = 0;

	for (i = 0; i < record_num; i++) {
		if (migrate_cmd[i].data_spa == zp->z_group_id.data_spa && migrate_cmd[i].data_os == zp->z_group_id.data_objset) {
			j = migrate_cmd[j].obj_count;
			migrate_cmd[i].mobj[j].object = zp->z_group_id.data_object;
			migrate_cmd[i].mobj[j].file_length = zp->z_size;
			migrate_cmd[i].mobj[j].block_size = block_size;
			migrate_cmd[i].obj_count++;
			break;
		}
	}
	return;
}

void migrate_send_cmd_to_remote(objset_t *os, zfs_migrate_cmd_t *migrate_cmd, int record_count, boolean_t send_all)
{
	int i = 0;
	int err = 0;

	for (i = 0; i < record_count; i++) {
		if ((send_all && migrate_cmd[i].obj_count > 0) || (migrate_cmd[i].obj_count >= 50)) {
			err = zfs_client_migrate_insert_block(os, &migrate_cmd[i]);
			if (err == 0) {
				bzero(migrate_cmd[i].mobj, sizeof(migrate_obj_t) * 50);
				migrate_cmd[i].obj_count = 0;
			} else {
				cmn_err(CE_WARN, "%s, %d, Send migrate insert cmd to %s failed, obj count %llu", __func__, __LINE__, migrate_cmd[i].fsname, (unsigned long long)migrate_cmd[i].obj_count);
			}
		}
	}
	return;
}

typedef struct object_list_node {
	uint64_t		object_ID;
	list_node_t 	node;
} object_list_node_t;

int obj_count_limit = 10000;

void travese_migrate_dir(objset_t *os, uint64_t dir_obj)
{
	int err = 0;
	int ret = 0;
	int record_count = 0;
	int obj_count = 0;
	uint64_t spa_id = 0;
	uint64_t objset = 0;
	uint64_t object = 0;
	uint64_t tmp_dir_obj = 0;
	uint64_t file_length = 0;
	uint64_t block_size = 0;
	zap_attribute_t attr = {0};
	zap_cursor_t zc = {0};
	zfs_sb_t *zsb = NULL;
	znode_t *zp = NULL;
	dnode_t *dnp = NULL;
	zfs_multiclus_group_t *current_group = NULL;
	zfs_migrate_cmd_t *migrate_cmd = NULL;
	spa_id = spa_guid(dmu_objset_spa(os));
	objset = dmu_objset_id(os);
	mutex_enter(&os->os_user_ptr_lock);
	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	mutex_exit(&os->os_user_ptr_lock);
	list_t object_list;
	object_list_node_t *tmp_node = NULL;
	
	list_create(&object_list, sizeof (object_list_node_t),
				offsetof(object_list_node_t, node));

	if (os->os_is_group) {
		record_count = zfs_multiclus_get_group_record_num(os->os_group_name, strlen(os->os_group_name));
		if (record_count <= 0) {
			cmn_err(CE_WARN, "%s, %d, Get group record number failed for %s failed", __func__, __LINE__, os->os_group_name);
			return;
		}

		migrate_cmd = vmem_zalloc(sizeof(zfs_migrate_cmd_t) * (record_count - 1), KM_SLEEP);
		ret = zfs_multiclus_get_info_from_group(migrate_cmd, os->os_group_name, record_count - 1);
		if (ret != record_count - 1) {
			cmn_err(CE_WARN, "%s, %d, Get record info from group %s failed, there are %d records, but only get %d records", 
				__func__, __LINE__, os->os_group_name, record_count - 1, ret);
			vmem_free(migrate_cmd, sizeof(zfs_migrate_cmd_t) * (record_count - 1));
			return;
		}
	}

	tmp_dir_obj = dir_obj;

	do {
		for (zap_cursor_init(&zc, os, tmp_dir_obj);
					zap_cursor_retrieve(&zc, &attr) == 0;
					(void) zap_cursor_advance(&zc)) {
			object = ZFS_DIRENT_OBJ(attr.za_first_integer);
			obj_count++;
			err = dnode_hold(os, object, FTAG, &dnp);
			if (err == 0) {
				if (dnp->dn_phys->dn_type == DMU_OT_PLAIN_FILE_CONTENTS) {
					block_size = (uint64_t)dnp->dn_phys->dn_datablkszsec;
					block_size = block_size << 9;
					file_length = DN_USED_BYTES(dnp->dn_phys);
				} else if (dnp->dn_phys->dn_type == DMU_OT_DIRECTORY_CONTENTS) {
					tmp_node = kmem_zalloc(sizeof(object_list_node_t), KM_SLEEP);
					tmp_node->object_ID = object;
					list_insert_tail(&object_list, tmp_node);
				}
				dnode_rele(dnp, FTAG);
				
				err = zfs_zget(zsb, object, &zp);
				if (err == 0) {
					if (S_ISDIR(ZTOI(zp)->i_mode)) {
						if (debug_migrate)
							cmn_err(CE_WARN, "[debug_migrate]%s, %d, Dir name: %s", __func__, __LINE__, zp->z_filename);
					} else if (S_ISREG(ZTOI(zp)->i_mode)) {
						wrc_insert_block(os, objset, object, zp->z_size, block_size);
						if (debug_migrate)
							cmn_err(CE_WARN, "[debug_migrate]%s, %d, File name: %s", __func__, __LINE__, zp->z_filename);
						if (os->os_is_group && 
							(zp->z_group_id.data_spa != zp->z_group_id.master_spa || zp->z_group_id.data_objset != zp->z_group_id.master_objset)) {
							migrate_insert_block_to_cmd(migrate_cmd, record_count - 1, zp, block_size);
							migrate_send_cmd_to_remote(os, migrate_cmd, record_count - 1, B_FALSE);
							if (debug_migrate)
								cmn_err(CE_WARN, "[debug_migrate]%s, %d, zfs_client_migrate_insert_block!", __func__, __LINE__);
						}
					} else {
						if (debug_migrate)
							cmn_err(CE_WARN, "[debug_migrate]%s, %d, type is not dir or regfile, object: %lld, mode: %lld!", 
							__func__, __LINE__, (unsigned long long)object, (unsigned long long)ZTOI(zp)->i_mode);
					}
					iput(ZTOI(zp));
				} else {
					if (debug_migrate)
						cmn_err(CE_WARN, "[debug_migrate]%s, %d, zget for object: %lld failed!Go on!", __func__, __LINE__, (unsigned long long)object);
				}
			} else {
				if (debug_migrate)
					cmn_err(CE_WARN, "[debug_migrate]%s, %d, dnode hold for object: %lld failed!Go on!", __func__, __LINE__, (unsigned long long)object);
			}
		
			bzero(&attr, sizeof(attr));
			dnp = NULL;
			zp = NULL;
			mutex_enter(&os->os_wrc.wrc_lock);
			if (os->os_wrc.trav_thr_exit == B_TRUE) {
				mutex_exit(&os->os_wrc.wrc_lock);
				break;
			}
			mutex_exit(&os->os_wrc.wrc_lock);
		}
		zap_cursor_fini(&zc);
		if (os->os_is_group)
			migrate_send_cmd_to_remote(os, migrate_cmd, record_count - 1, B_TRUE);
		tmp_node = list_head(&object_list);
		if (tmp_node) {
			list_remove(&object_list, tmp_node);
			tmp_dir_obj = tmp_node->object_ID;
			kmem_free(tmp_node, sizeof(object_list_node_t));
		} else {
			break;
		}
		if (obj_count >= obj_count_limit) {
			obj_count = 0;
			migrate_insert_wait(100);
		}
	} while (1);
	if (migrate_cmd)
		vmem_free(migrate_cmd, sizeof(zfs_migrate_cmd_t) * (record_count - 1));
}

void travese_migrate_thread(wrc_migrate_param_t *param)
{
	int err = 0;
	int i = 0;
	uint64_t start_obj = 0;
	uint64_t flags = param->flags;
	objset_t *os = param->os;


	if (flags & START_ALL) {
		err = zap_lookup(os, MASTER_NODE_OBJ, zfs_dirlowdata_prefixex, 8, 1, &start_obj);
		if (err) {
			cmn_err(CE_WARN, "%s, %d, lookup dirlowdata obj failed(err: %d)!", __func__, __LINE__, err);
			return;
		}
	} else {
		start_obj = param->obj;
	}

	travese_migrate_dir(os, start_obj);
	
	cmn_err(CE_WARN, "travese migrate thread finished!");
	os->os_wrc.traverse_thread = NULL;
	os->os_wrc.traverse_finished = B_TRUE;
	if (os->os_is_group) {
		err = zfs_client_migrate_cmd(os, ZFS_MIGRATE_TRAVESE_FINISHED, 0, 0);
	}

	kmem_free(param,sizeof(wrc_migrate_param_t));
}

void travese_finished(char *fsname, msg_orig_type_t cmd_type)
{
	int i = 0;
	int err = 0;
	objset_t *os = NULL;


	err = dmu_objset_hold(fsname, FTAG, &os);
	if (err != 0) {
		cmn_err(CE_WARN, "%s, %d, hold fs: %s failed ,err: %d", __func__, __LINE__, fsname, err);
		return;
	}

	if (os->os_is_group && cmd_type == APP_GROUP) {
		mutex_enter(&os->os_wrc.wrc_lock);
		os->os_wrc.traverse_finished = B_TRUE;
		mutex_exit(&os->os_wrc.wrc_lock);
	} else {
		cmn_err(CE_WARN,"%s, %d, is not group or and cmd type is not APP_USR!", __func__, __LINE__);
	}

	dmu_objset_rele(os, FTAG);
}

void stop_travese_migrate_thread(char *fsname, msg_orig_type_t cmd_type)
{
	int i = 0;
	int err = 0;
	objset_t *os = NULL;


	err = dmu_objset_hold(fsname, FTAG, &os);
	if (err != 0) {
		cmn_err(CE_WARN, "%s, %d, hold fs: %s failed ,err: %d", __func__, __LINE__, fsname, err);
		return;
	}

	/*master or local fs should stop wrc thread and set zero first*/
	if (!os->os_is_group || os->os_is_master) {
		stop_wrc_thread(os);
		os->os_wrc.wrc_total_migrated = 0;
		os->os_wrc.wrc_total_to_migrate = 0;
	}

	if (os->os_is_group && cmd_type == APP_USER) {
		err = zfs_client_migrate_cmd(os, ZFS_MIGRATE_STOP, 0, 0);
	}
	
	if (os->os_is_group && (os->os_is_master == B_FALSE)) {
		os->os_wrc.traverse_finished = B_TRUE;
	}

	/*slave should stop wrc thread and set zero after master*/
	if (os->os_is_group && !os->os_is_master) {
		stop_wrc_thread(os);
		os->os_wrc.wrc_total_migrated = 0;
		os->os_wrc.wrc_total_to_migrate = 0;
	}

	dmu_objset_rele(os, FTAG);
}

void start_travese_migrate_thread(char *fsname, uint64_t flags, uint64_t start_obj, msg_orig_type_t cmd_type)
{
	int err = 0;
	int i = 0;
	int retry_times = 0;
	zfs_sb_t *zsb = NULL;
	uint64_t root_obj = 0;
	uint64_t object = 0;
	objset_t *os = NULL;

	err = dmu_objset_hold(fsname, FTAG, &os);
	if (err != 0) {
		cmn_err(CE_WARN, "%s, %d, hold fs: %s failed ,err: %d", __func__, __LINE__, fsname, err);
		return;
	}

	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	if (zsb == NULL){
		cmn_err(CE_WARN, "%s, %d, get root object failed: %s failed.", __func__, __LINE__, fsname);
		return;
	}

	object = flags & START_OS ?  zsb->z_root : start_obj;

	if (os->os_wrc.traverse_finished && os->os_wrc.wrc_total_migrated == os->os_wrc.wrc_total_to_migrate) {
		os->os_wrc.wrc_total_migrated = 0;
		os->os_wrc.wrc_total_to_migrate = 0;
		if (os->os_is_group && cmd_type == APP_USER)
			err = zfs_client_migrate_cmd(os, ZFS_MIGRATE_START, flags, object);
	} else {
		return;
	}
	os->os_wrc.traverse_finished = B_FALSE;
	start_wrc_thread(os, flags, object);

	dmu_objset_rele(os, FTAG);
}

int migrate_insert_block(zfs_migrate_cmd_t *migrate_cmd)
{
	int err = 0;
	int i = 0;
	objset_t *os = NULL;

	err = dmu_objset_hold((char *)migrate_cmd->fsname, FTAG, &os);
	if (err) {
		cmn_err(CE_WARN, "%s, %d, Hold fs failed for fs: %s", __func__, __LINE__, migrate_cmd->fsname);
		return err;
	}

	for (i = 0; i < migrate_cmd->obj_count; i++) {
		wrc_insert_block(os, dmu_objset_id(os), migrate_cmd->mobj[i].object, migrate_cmd->mobj[i].file_length, migrate_cmd->mobj[i].block_size);
	}

	dmu_objset_rele(os, FTAG);

	return err;
}

void status_travese_migrate_thread(char *fsname, char *state, uint64_t *total_to_migrate, uint64_t *total_migrated)
{
	int err = 0;
	objset_t *os = NULL;

	err = dmu_objset_hold(fsname, FTAG, &os);
	if (err) {
		cmn_err(CE_WARN, "%s, %d, Hold fs failed for fs: %s", __func__, __LINE__, fsname);
		return;
	}

	if (os->os_wrc.traverse_finished == B_TRUE) {
		sprintf(state, "traverse finished or stopped! migrate %s!", os->os_wrc.wrc_total_to_migrate == os->os_wrc.wrc_total_migrated ? "finished" : "on going");
	} else {
		sprintf(state, "traverse and migrate on going!");
	}

	*total_to_migrate = os->os_wrc.wrc_total_to_migrate;
	*total_migrated = os->os_wrc.wrc_total_migrated;

	dmu_objset_rele(os, FTAG);

	return;
}

#endif

