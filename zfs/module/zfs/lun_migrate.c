
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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <sys/zfs_rlock.h>
#include <sys/zfs_znode.h>
#include <sys/vnode.h>
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/fs/zfs.h>
#include <sys/spa_impl.h>
#include <sys/vdev_impl.h>
#include <sys/dmu_objset.h>
#include <sys/zvol.h>
#include <sys/zap.h>
#include <sys/dsl_prop.h>
#include <sys/lun_migrate.h>

#include "zfs_prop.h"

static lun_migrate_t lun_migrate_manager;

/*
 * *************************************************************************
 * lun migrate common route
 * *************************************************************************
 */
int lun_migrate_is_work(objset_t *os)
{
	int ret = 0;
	lun_copy_t *lct = NULL;

	if (os->os_lun_copy == NULL)
		return (0);

	lct = os->os_lun_copy;
	mutex_enter(&lct->lun_copy_lock);
	if (os->os_lun_migrate == 1)
		ret = 1;
	else
		ret = 0;

	mutex_exit(&lct->lun_copy_lock);
	return (ret);
}

void
lun_migrate_destroy(lun_copy_t *lct)
{
	mutex_enter(&lct->lun_copy_lock);
	lct->lun_copy_state = LUN_COPY_DEACTIVE;
	cv_broadcast(&lct->lun_copy_cv);
	mutex_exit(&lct->lun_copy_lock);
}

lun_copy_t *lun_migrate_find_by_name(char *name)
{
	int i = 0;
	lun_copy_t *lct = NULL;

	if (lun_migrate_manager.lum_state == LUN_MIGRATE_NOINIT)
		return (NULL);

	for (i = 0; i < LUN_COPY_NUM; i++) {
		lct = &lun_migrate_manager.lum_copy_array[i];
		if (lct->lun_copy_state != LUN_COPY_NONE &&
				strcmp(name, lct->lun_host_dev) == 0) {
			return (lct);
		}
	}

	return (NULL);
}

#ifdef _KERNEL
void lun_migrate_find_recovery(const char *name)
{
	int err = 0;
	uint64_t position = 0;
	char *fs = NULL;
	objset_t *os = NULL;
	lun_copy_t *lct = NULL;

	if ((fs = strstr(name, "zvol")) == NULL)
		fs = name; 
	else
		fs = fs + 5;

	err = dmu_objset_hold(fs, FTAG, &os);
	if (err) {
		printk("Fail to hold objset.\n");
		return;
	}

	err = zap_lookup(os, ZVOL_ZAP_OBJ, "copy_position", 8, 1, &position);
	if (err == 0) {
		(void) lun_migrate_recovery(fs);
	}

	dmu_objset_rele(os, FTAG);
	return;
}

uint64_t lun_migrate_get_offset(char *name)
{
	lun_copy_t *lct = lun_migrate_find_by_name(name);
	if (lct != NULL) {
		return (lct->lun_cursor_off);
	} else {
		return (0);
	}
}

lun_copy_t *lun_migrate_find_by_fs(const char *fs)
{
	int i = 0;
	lun_copy_t *lct = NULL;

	if (lun_migrate_manager.lum_state == LUN_MIGRATE_NOINIT)
		return (NULL);

	for (i = 0; i < LUN_COPY_NUM; i++) {
		lct = &lun_migrate_manager.lum_copy_array[i];
		if (lct->lun_copy_state != LUN_COPY_NONE &&
				strcmp(fs, lct->lun_zfs) == 0) {
			return (lct);
		}
	}

	return (NULL);
}

lun_copy_t *lun_migrate_find_copy()
{
	int i = 0;
	lun_copy_t *lct = NULL;
	if (lun_migrate_manager.lum_state == LUN_MIGRATE_NOINIT)
		return (NULL);

	for (i = 0; i < LUN_COPY_NUM; i++) {
		lct = &lun_migrate_manager.lum_copy_array[i];	
		if (lct->lun_copy_state == LUN_COPY_NONE) {
			return (lct);
		}
	}

	return (NULL);
}

static boolean_t
lun_migrate_copy_has_start(lun_copy_t *lct)
{
	int i = 0;
	lun_copy_t *search = NULL;
	if (lun_migrate_manager.lum_state == LUN_MIGRATE_NOINIT)
		return (B_FALSE);

	for (i = 0; i < LUN_COPY_NUM; i++) {
		search = &lun_migrate_manager.lum_copy_array[i];
		if ( search->lun_copy_state != LUN_COPY_NONE &&
			strcmp(lct->lun_zfs, search->lun_zfs) == 0) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * ***************************************************************************
 * lun copy read/write route
 * ***************************************************************************
 */

int lun_migrate_remote_read(char *dev_path, uio_t *uio)
{
	size_t offset = 0;
	uint64_t len = 0;
	char *buf = NULL;
	struct file *fp;
	mm_segment_t oldfs = get_fs();

	buf = uio->uio_iov->iov_base;
	len = uio->uio_resid;
	offset = uio->uio_loffset;

	fp = filp_open(dev_path, O_RDONLY, 0);
	if (IS_ERR(fp))
		return (-PTR_ERR(fp));

	set_fs(KERNEL_DS);
	fp->f_pos = offset;

	if (vfs_read(fp, buf, len, &fp->f_pos) != len) {
		set_fs(oldfs);
		filp_close(fp, NULL);
		printk("Failed to read [%s].\n",dev_path);
		return (-1);
	} else {
		set_fs(oldfs);
		filp_close(fp, NULL);
		return (0);
	}
}

int lun_migrate_remote_write(char *dev_path, uio_t *uio)
{
	loff_t offset = 0;
	uint64_t len = 0;
	char *buf = NULL;
	struct file *fp = NULL; 
	mm_segment_t oldfs = get_fs();

	buf = uio->uio_iov->iov_base;
	len = uio->uio_resid;
	offset = uio->uio_loffset;

	fp = filp_open(dev_path, O_RDWR, 0);
	if (IS_ERR(fp))
		return (-PTR_ERR(fp));

	set_fs(KERNEL_DS);
	fp->f_pos = offset;
	
	if (vfs_write(fp, buf, len, &fp->f_pos) != len) {
		set_fs(oldfs);
		filp_close(fp, NULL);
		printk("Failed to write [%s].\n",dev_path);
		return (-1);
	} else {
		set_fs(oldfs);
		filp_close(fp, NULL);
		return (0);
	}
}

int lun_migrate_zvol_sgl_read(char *name, uint64_t off, int size, void *data)
{
	lun_copy_t *lct = NULL;
	struct file *fp = NULL;
	mm_segment_t oldfs = get_fs();

	lct = lun_migrate_find_by_name(name);
	if (lct == NULL)
		return (-1);

	fp = filp_open(lct->lun_remote_dev, O_RDONLY, 0);
	if (IS_ERR(fp))
		return (-PTR_ERR(fp));
	
	set_fs(KERNEL_DS);
	fp->f_pos = off;

	if (vfs_read(fp, data, size, &fp->f_pos) != size) {
		printk("Failed to read [%s].\n",name);
		set_fs(oldfs);
		filp_close(fp, NULL);
		return (-1);
	} else {
		set_fs(oldfs);
		filp_close(fp, NULL);
		return (0);
	}
}

int lun_migrate_zvol_sgl_write(char *name, uint64_t off, int size, void *data)
{
	lun_copy_t *lct = NULL;
	struct file *fp = NULL;
	mm_segment_t oldfs = get_fs();

	lct = lun_migrate_find_by_name(name);
	if (lct == NULL)
		return (-1);

	fp = filp_open(lct->lun_remote_dev, O_RDWR, 0);
	if (IS_ERR(fp))
		return (-PTR_ERR(fp));

	set_fs(KERNEL_DS);
	fp->f_pos = off;
	
	if (vfs_write(fp, data, size, &fp->f_pos) != size) {
		printk("Failed to write [%s].\n",name);
		set_fs(oldfs);
		filp_close(fp, NULL);
		return (-1);
	}

	set_fs(oldfs);
	filp_close(fp, NULL);

	if (off > lct->lun_cursor_off)
		return (0);
	else
		return (1);
}

int lun_migrate_zvol_read(char *name, uio_t *uio)
{
	int ret = 0;
	lun_copy_t *lct = NULL;

	lct = lun_migrate_find_by_name(name);
	if (lct == NULL)
		return (-1);

	ret = lun_migrate_remote_read(lct->lun_remote_dev, uio);
	if (ret != 0)
		return (-1);
	else
		return (0);
}

/*
 * we dirty map when:
 * 1. uio blocks are copying
 * 2. dmu write fail
 * 3. we will copy dirty blocks from remote after copy thread done
 */
int lun_migrate_zvol_write(char *name, uio_t *uio)
{
	int ret = 0;
	lun_copy_t *lct = NULL;

	lct = lun_migrate_find_by_name(name);
	if (lct == NULL)
		return (1);

	ret = lun_migrate_remote_write(lct->lun_remote_dev, uio);
	if (ret != 0)
		return (EIO);

	if (uio->uio_loffset > lct->lun_cursor_off) {
		return (0);
	} else {
		return (1);
	}
}

static void
lun_copy_out_cv_wakeup(lun_copy_t *lct)
{
	mutex_enter(&lct->lun_copy_out_lock);
	cv_broadcast(&lct->lun_copy_out_cv);
	mutex_exit(&lct->lun_copy_out_lock);
}

static void
lun_copy_cv_wait(lun_copy_t *lct)
{
	mutex_enter(&lct->lun_copy_lock);
	cv_wait(&lct->lun_copy_cv, &lct->lun_copy_lock);
	mutex_exit(&lct->lun_copy_lock);
}

static void
lun_copy_cv_timewait(lun_copy_t *lct)
{
	mutex_enter(&lct->lun_copy_lock);
	cv_timedwait(&lct->lun_copy_cv, &lct->lun_copy_lock, ddi_get_lbolt() + drv_usectohz(500000));
	mutex_exit(&lct->lun_copy_lock);
}

static void
lun_copy_ready(lun_copy_t *lct)
{
	int read = -1;
	struct file *rfp = NULL;
	int write = -1;
	struct file *wfp = NULL;

	while (read != 0 || write != 0) {
		if (read != 0) {
			rfp = filp_open(lct->lun_remote_dev, O_RDONLY, 0);
			if (IS_ERR(rfp)) {
				read = -1;
			} else {
				read = 0;
				lct->lun_read_fp = rfp;
				lct->lun_read_fp->f_pos = lct->lun_cursor_off;
			}
		}

		if (write != 0) {
			wfp = filp_open(lct->lun_host_dev, O_RDWR, 0);
			if (IS_ERR(wfp)) {
				write = -1;
			} else {
				write = 0;
				lct->lun_write_fp = wfp;
				lct->lun_write_fp->f_pos = lct->lun_cursor_off;
			}
		}

		if (read == 0 && write == 0) {
			break;
		}

		(void) lun_copy_cv_timewait(lct);

		if (lct->lun_copy_state == LUN_COPY_STOP ||
				lct->lun_copy_state == LUN_COPY_DEACTIVE)
			break;
	}
}

static void
lun_copy_close_readvp(lun_copy_t *lct)
{
	if (lct->lun_read_fp != NULL) {
		mutex_enter(&lct->lun_copy_lock);
		filp_close(lct->lun_read_fp, NULL);
		lct->lun_read_fp = NULL;
		mutex_exit(&lct->lun_copy_lock);
	}

	if (lct->lun_write_fp != NULL) {
		mutex_enter(&lct->lun_copy_lock);
		filp_close(lct->lun_write_fp, NULL);
		lct->lun_write_fp = NULL;
		mutex_exit(&lct->lun_copy_lock);
	}
}

static int 
lun_copy_impl(lun_copy_t *lct, char *buf, offset_t laddr, size_t len)
{
	int error = 0;
	dmu_tx_t *tx = NULL;
	uint64_t end = laddr + len;
	mm_segment_t oldfs = get_fs();
	struct file *rfile = lct->lun_read_fp;
	struct file *wfile = lct->lun_write_fp;

	if (rfile == NULL) {
		printk("lun_read_fp is NULL.\n");
		return (LUN_COPY_READ_FAIL);
	}

	set_fs(KERNEL_DS);

	if (vfs_read(rfile, buf, len, &rfile->f_pos) != len) {
		set_fs(oldfs);
		printk("Failed to read fp\n");
		return (LUN_COPY_READ_FAIL);
	} else {
#if 0
		if (zvol_write_lun_copy(lct, buf, laddr, len) == 0) {
			mutex_enter(&lct->lun_copy_lock);
			lct->lun_cursor_off = laddr + len;
			mutex_exit(&lct->lun_copy_lock);
			return (LUN_COPY_SUCCESS);
		} else {
			printk("Failed to write dmu.\n");
			return (LUN_COPY_ERR);
		}
#endif
		if (vfs_write(wfile, buf, len, &wfile->f_pos) != len) {
			set_fs(oldfs);
			printk("Failed to write fp\n");
			return (LUN_COPY_READ_FAIL);
		} else {
			tx = dmu_tx_create(lct->lun_os);
			dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
			error = dmu_tx_assign(tx, TXG_WAIT);
			if (error) {
				dmu_tx_abort(tx);
			} else {
				zap_update(lct->lun_os, ZVOL_ZAP_OBJ, "copy_position", 8, 1, &end, tx);
				if (laddr == 0)
					zap_update(lct->lun_os, ZVOL_ZAP_OBJ, "copy_totalsize", 8, 1, &lct->lun_total_size, tx);

				dmu_tx_commit(tx);
			}

			mutex_enter(&lct->lun_copy_lock);
			lct->lun_cursor_off = laddr + len;
			mutex_exit(&lct->lun_copy_lock);
			return (LUN_COPY_SUCCESS);
		}
	}
}

void
lun_copy_clear(lun_copy_t *lct, char *buf)
{
	int err = 0;
	objset_t *os = NULL;
	dmu_tx_t *tx = NULL;

	err = dmu_objset_hold(lct->lun_zfs, FTAG, &os);
	if (err) {
		printk("Fail tp hold objset.\n");
		return;
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err) {
		dmu_tx_abort(tx);
	} else {
		if (lct->lun_cursor_off >= lct->lun_total_size) {
			zap_remove(os, ZVOL_ZAP_OBJ, "copy_position", tx);
			zap_remove(os, ZVOL_ZAP_OBJ, "copy_totalsize", tx);
		}
		dmu_tx_commit(tx);
	}

	dmu_objset_rele(os, FTAG);

	mutex_enter(&lct->lun_copy_lock);

	bzero(&lct->lun_remote_dev, LUN_DEV_LEN);
	bzero(&lct->lun_host_dev, LUN_DEV_LEN);
	bzero(&lct->lun_guid, LUN_DEV_LEN);
	bzero(&lct->lun_zfs, 64);

	lct->lun_copy_state = LUN_COPY_NONE;

	cv_broadcast(&lct->lun_copy_cv);

	lct->lun_cursor_off = 0;
	lct->lun_total_size = 0;
	lct->lun_copy_thread = NULL;
	lct->lun_os->os_lun_migrate = 0;
	lct->lun_os->os_lun_copy = NULL;
	lct->lun_os = NULL;

	mutex_exit(&lct->lun_copy_lock);

	if (buf != NULL)
		kfree(buf);

	if (lun_migrate_manager.lum_members > 0) {
		mutex_enter(&lun_migrate_manager.lum_lock);
		lun_migrate_manager.lum_members--;
		mutex_exit(&lun_migrate_manager.lum_lock);
	}
}

/*
 * *************************************************************************
 * lun migrate prop route
 * *************************************************************************
 */
void lun_migrate_prop_set(lun_copy_t *lct)
{
	dsl_prop_set_string(lct->lun_zfs, zfs_prop_to_name(ZFS_PROP_LUN_REMOTE),
			ZPROP_SRC_LOCAL, lct->lun_remote_dev);
	dsl_prop_set_string(lct->lun_zfs, zfs_prop_to_name(ZFS_PROP_LUN_HOST),
			ZPROP_SRC_LOCAL, lct->lun_host_dev);
	dsl_prop_set_string(lct->lun_zfs, zfs_prop_to_name(ZFS_PROP_LUN_GUID),
			ZPROP_SRC_LOCAL, lct->lun_guid);
}

void lun_migrate_prop_get(lun_copy_t *lct)
{
	dsl_prop_get(lct->lun_zfs, zfs_prop_to_name(ZFS_PROP_LUN_REMOTE), 1,
			sizeof(lct->lun_remote_dev), &lct->lun_remote_dev, NULL);
	dsl_prop_get(lct->lun_zfs, zfs_prop_to_name(ZFS_PROP_LUN_HOST), 1,
			sizeof(lct->lun_host_dev), &lct->lun_host_dev, NULL);
	dsl_prop_get(lct->lun_zfs, zfs_prop_to_name(ZFS_PROP_LUN_GUID), 1,
			sizeof(lct->lun_guid), &lct->lun_guid, NULL);
}

void lun_migrate_recovery(const char *fsname)
{
	lun_copy_t *lct = NULL;

	lct = lun_migrate_find_copy();
	if (lct != NULL) {
		bcopy(fsname, lct->lun_zfs, strlen(fsname));
		(void) lun_migrate_start(lct, B_FALSE);
	}
}

/*
 * *************************************************************************
 * lun migrate working route
 * *************************************************************************
 */

/*
 * this is lun copy thread, it work as :
 * 1. copy 32k one times
 * 2. can stop when get stop cmd
 * 3. should clear lun_copy_t after copy done
 * 4. try again when disk or lun have problem
 */
static void lun_copy_thread(lun_copy_t *lct)
{
	int ret = 0;
	offset_t off = 0;
	uint64_t total = 0;
	uint64_t step = 0;
	char *buf = NULL;

	step = LUN_COPY_SIZE;
	off = lct->lun_cursor_off;
	total = lct->lun_total_size;

	(void) lun_copy_ready(lct);
	buf = (char*)kmalloc(LUN_COPY_SIZE, GFP_KERNEL);
	printk(" lun copy begin: off = %lld ,size = %" PRIu64 "\n",off,total);

	while (1) {
		if (lct->lun_copy_state == LUN_COPY_DEACTIVE ||
				lct->lun_copy_state == LUN_COPY_DONE ||
				lun_migrate_manager.lum_state == LUN_MIGRATE_NOINIT) {
			(void) lun_copy_close_readvp(lct);
			(void) lun_copy_clear(lct, buf);
			(void) lun_copy_out_cv_wakeup(lct);
			thread_exit();
		} else if (lct->lun_copy_state == LUN_COPY_STOP) {
			(void) lun_copy_close_readvp(lct);
			(void) lun_copy_cv_wait(lct);

			if (lct->lun_copy_state == LUN_COPY_DEACTIVE)
				continue;

			(void) lun_copy_ready(lct);
		} else {
			if (off >= total) {
				mutex_enter(&lct->lun_copy_lock);
				lct->lun_copy_state = LUN_COPY_DONE;
				mutex_exit(&lct->lun_copy_lock);
				continue;
			}

			if (off > total - LUN_COPY_SIZE && off < total) {
				step = total - off;
			} 

			bzero(buf, LUN_COPY_SIZE);
			ret = lun_copy_impl(lct, buf, off, step);
			if (ret == LUN_COPY_SUCCESS) {
				off += step;
			} else if (ret == LUN_COPY_READ_FAIL) {
				(void) lun_copy_close_readvp(lct);
				(void) lun_copy_ready(lct);
			} else {
				/* TODO */
			}
		}
	}
}

void lun_migrate_start(lun_copy_t *lct, boolean_t b_new)
{
	int error = 0;
	uint64_t off = 0;
	uint64_t total = 0;
	objset_t *os = NULL;

	/* we do nothing if this lun has start */
	if (lun_migrate_copy_has_start(lct)) {
		printk("lun migrate have begin.\n");
		return;
	} else {
		mutex_enter(&lun_migrate_manager.lum_lock);
		lun_migrate_manager.lum_members++;
		mutex_exit(&lun_migrate_manager.lum_lock);
	}

	mutex_enter(&lct->lun_copy_lock);

	/* 1. get lun os by lun name */
	error = dmu_objset_hold(lct->lun_zfs, FTAG, &os);
	if (error) {
		cmn_err(CE_WARN, "%s line(%d)  error(%d)", __func__, __LINE__, error);
		mutex_exit(&lct->lun_copy_lock);
		return; 
	} else {
		lct->lun_os = os;
		os->os_lun_copy = lct;
		os->os_lun_migrate = 1;
	}

	/* 2. config prop of lun copy */
	if (!b_new) {
		(void) zap_lookup(os, ZVOL_ZAP_OBJ, "copy_position", 8, 1, &off);
		(void) zap_lookup(os, ZVOL_ZAP_OBJ, "copy_totalsize", 8, 1, &total);
		if (off >= total) {
			dmu_objset_rele(os, FTAG);
			(void) lun_copy_clear(lct, NULL);
			mutex_exit(&lct->lun_copy_lock);
			return;
		} else {
			dmu_objset_rele(os, FTAG);
			lun_migrate_prop_get(lct);
		}
	} else {
		dmu_objset_rele(os, FTAG);
		lun_migrate_prop_set(lct);
	}

	/* 3. create lun copy thread here */
	lct->lun_cursor_off = off;
	lct->lun_copy_state = LUN_COPY_ACTIVE;
	lct->lun_total_size = ( total == 0 ? lct->lun_total_size : total);
	lct->lun_copy_thread = thread_create(NULL, 0, lun_copy_thread, lct,
			0, &p0, TS_RUN, minclsyspri);

	mutex_exit(&lct->lun_copy_lock);
}

void lun_migrate_stop(lun_copy_t *lct)
{
	if (lct->lun_copy_state == LUN_COPY_NONE)
		return;

	mutex_enter(&lct->lun_copy_lock);
	if (lct->lun_copy_state != LUN_COPY_STOP) {
		lct->lun_copy_state = LUN_COPY_STOP;
	}

	mutex_exit(&lct->lun_copy_lock);
}

void lun_migrate_restart(lun_copy_t *lct)
{
	if (lct->lun_copy_state == LUN_COPY_NONE)
		return;

	if (lct->lun_copy_state == LUN_COPY_STOP) {
		mutex_enter(&lct->lun_copy_lock);
		lct->lun_copy_state = LUN_COPY_ACTIVE;
		cv_broadcast(&lct->lun_copy_cv);
		mutex_exit(&lct->lun_copy_lock);
	}
}

/* init lun migrate when zfs init */
void lun_migrate_init()
{
	int i = 0;
	bzero(&lun_migrate_manager, sizeof(lun_migrate_t));
	mutex_init(&lun_migrate_manager.lum_lock, NULL, MUTEX_DEFAULT, NULL);

	lun_migrate_manager.lum_members = 0;
	lun_migrate_manager.lum_state = LUN_MIGRATE_INIT;

	for (i = 0; i < LUN_COPY_NUM; i++) {
		lun_copy_t *lct = &(lun_migrate_manager.lum_copy_array[i]);
		bzero(lct, sizeof(lun_copy_t));
		mutex_init(&lct->lun_copy_lock, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&lct->lun_copy_out_lock, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&lct->lun_copy_cv, NULL, CV_DEFAULT, NULL);
		cv_init(&lct->lun_copy_out_cv, NULL, CV_DEFAULT, NULL);
		lct->lun_copy_thread = NULL;
		lct->lun_copy_state = LUN_COPY_NONE;
	}
}

void lun_migrate_fini()
{
	int i = 0;
	for (i = 0; i < LUN_COPY_NUM; i++) {
		lun_copy_t *lct = &(lun_migrate_manager.lum_copy_array[i]);
		if (lct->lun_copy_state == LUN_COPY_STOP) {
			mutex_enter(&lct->lun_copy_lock);
			lct->lun_copy_state = LUN_COPY_DEACTIVE;
			cv_broadcast(&lct->lun_copy_cv);
			mutex_exit(&lct->lun_copy_lock);

			mutex_enter(&lct->lun_copy_out_lock);
			cv_wait(&lct->lun_copy_out_cv, &lct->lun_copy_out_lock);
			mutex_exit(&lct->lun_copy_out_lock);
		}

		mutex_destroy(&lct->lun_copy_lock);
		mutex_destroy(&lct->lun_copy_out_lock);
		cv_destroy(&lct->lun_copy_cv);
		cv_destroy(&lct->lun_copy_out_cv);
	}

	mutex_destroy(&lun_migrate_manager.lum_lock);
	lun_migrate_manager.lum_state = LUN_MIGRATE_NOINIT;
}

EXPORT_SYMBOL(lun_migrate_is_work);
EXPORT_SYMBOL(lun_migrate_destroy);
EXPORT_SYMBOL(lun_migrate_zvol_write);
EXPORT_SYMBOL(lun_migrate_zvol_read);
EXPORT_SYMBOL(lun_migrate_get_offset);
EXPORT_SYMBOL(lun_migrate_find_by_name);
EXPORT_SYMBOL(lun_migrate_find_recovery);
EXPORT_SYMBOL(lun_migrate_zvol_sgl_read);
EXPORT_SYMBOL(lun_migrate_zvol_sgl_write);
#endif
