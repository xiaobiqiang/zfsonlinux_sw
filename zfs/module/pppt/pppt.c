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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/nvpair.h>
/* #include <sys/door.h> */
#include <sys/sdt.h>
#include <linux/miscdevice.h>
#include <sys/cmn_err.h>
#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/pppt_ioctl.h>
#include <sys/portif.h>
#include <sys/lpif.h>
#include <sys/systeminfo.h>

/* #include <sys/scsi/scsi.h> */

#include "pppt.h"

#define	PPPT_VERSION		BUILD_DATE "-1.18dev"
#define	PPPT_NAME_VERSION	"COMSTAR PPPT v" PPPT_VERSION

#define	PRIx64				"llx"

/*
 * DDI entry points.
 */
static int pppt_drv_attach(void);
static int pppt_drv_detach(void);
static int pppt_drv_open(struct inode *inode, struct file *file);
static int pppt_drv_close(struct inode *inode, struct file *file);
static boolean_t pppt_drv_busy(void);
static long pppt_drv_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
extern pppt_status_t pppt_ic_so_enable(boolean_t);
extern void pppt_ic_so_disable(void);
extern void stmf_ic_rx_msg(char *, size_t, void *sess_private);

extern void stmf_ic_ksocket_wakeup(void);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
extern void stmf_ic_so_disconnect();
#endif
extern void stmf_ic_tx_thread(void *arg);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
extern void stmf_ic_rx_thread(void *arg);
extern void stmf_ic_handle_msg_thread(void * arg);
#endif

#define	PPPT_MODULE_NAME	"pppt"

static const struct file_operations ppptdev_fops = {
	.open		= pppt_drv_open,
	.release	= pppt_drv_close,
	.unlocked_ioctl	= pppt_drv_ioctl,
	.owner		= THIS_MODULE,
};

static struct miscdevice pppt_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= PPPT_MODULE_NAME,
	.fops		= &ppptdev_fops,
};

pppt_global_t pppt_global;
pppt_conn_t	pppt_conn;

int pppt_logging = 0;
volatile int pppt_session_clear_time = 120;

static int pppt_enable_svc(void);

static void pppt_disable_svc(void);

int pppt_ctrl_svc(int);

static int pppt_task_avl_compare(const void *tgt1, const void *tgt2);

static stmf_data_buf_t *pppt_dbuf_alloc(scsi_task_t *task,
    uint32_t size, uint32_t *pminsize, uint32_t flags);

static void pppt_dbuf_free(stmf_dbuf_store_t *ds, stmf_data_buf_t *dbuf);

static void pppt_sess_destroy_task(void *ps_void);

static void pppt_register_callbacks(void);

extern stmf_ic_msg_status_t stmf_ic_asyn_tx_msg(stmf_ic_msg_t *msg,
	uint32_t type, void *private, void(*compl_cb)(void *, uint32_t, int),
	void (*clean_cb)(void *),
	int (*comp)(void *, void *));
extern void stmf_ic_asyn_tx_clean(uint32_t type, void *private);
extern stmf_ic_msg_status_t stmf_ic_sync_tx_msg(stmf_ic_msg_t *msg);
extern void stmf_ic_sync_tx_msg_ret(void *sess, uint64_t msg_id, uint64_t ret);
extern void stmf_ic_csh_hold(void *csh, void *tag);
extern void stmf_ic_csh_rele(void *csh, void *tag);
extern void *stmf_ic_kmem_alloc(size_t size, int kmflag);
extern void *stmf_ic_kmem_zalloc(size_t size, int kmflag);
extern void stmf_ic_kmem_free(void *ptr, size_t size);

/*
 * Lock order:  global --> target --> session --> task
 */

static int __init
pppt_init(void)
{
	int rc;

	/* initialize */
	bzero(&pppt_conn, sizeof(pppt_conn));
	mutex_init(&pppt_global.global_lock, NULL, MUTEX_DEFAULT, NULL);
	/* mutex_init(&pppt_global.global_door_lock, NULL, MUTEX_DEFAULT, NULL); */
#if (PPPT_TRAN_WAY != PPPT_TRAN_USE_CLUSTERSAN)
	mutex_init(&pppt_conn.ic_tx_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&pppt_conn.ic_tx_cv, NULL, CV_DEFAULT, NULL);
#endif
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
	mutex_init(&pppt_conn.ic_global_lock, NULL, MUTEX_DEFAULT, NULL);
#endif
	mutex_init(&pppt_conn.ic_tx_thr_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&pppt_conn.ic_rx_thr_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&pppt_conn.ic_tx_thr_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&pppt_conn.ic_rx_thr_cv, NULL, CV_DEFAULT, NULL);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
	mutex_init(&pppt_conn.ic_conn_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&pppt_conn.ic_conn_cv, NULL, CV_DEFAULT, NULL);
#endif
	pppt_global.global_svc_state = PSS_DETACHED;
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
	pppt_conn.ic_msg_queue = (stmf_ic_msg_queue_t *)kmem_zalloc(sizeof(stmf_ic_msg_queue_t), KM_SLEEP);
	mutex_init(&pppt_conn.task_msg_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&pppt_conn.ic_msg_queue->queue_cv, NULL, CV_DEFAULT, NULL);
#endif
	pppt_register_callbacks();

	if ((rc = pppt_drv_attach()) != 0) {
		/* mutex_destroy(&pppt_global.global_door_lock); */
		mutex_destroy(&pppt_global.global_lock);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
		mutex_destroy(&pppt_conn.ic_global_lock);
#endif
#if (PPPT_TRAN_WAY != PPPT_TRAN_USE_CLUSTERSAN)
		mutex_destroy(&pppt_conn.ic_tx_mutex);
		cv_destroy(&pppt_conn.ic_tx_cv);
#endif
		mutex_destroy(&pppt_conn.ic_tx_thr_lock);
		mutex_destroy(&pppt_conn.ic_rx_thr_lock);
		cv_destroy(&pppt_conn.ic_tx_thr_cv);
		cv_destroy(&pppt_conn.ic_rx_thr_cv);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
		mutex_destroy(&pppt_conn.ic_conn_lock);
		cv_destroy(&pppt_conn.ic_conn_cv);
#endif
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
		mutex_destroy(&pppt_conn.task_msg_lock);
		cv_destroy(&pppt_conn.ic_msg_queue->queue_cv);
		kmem_free(pppt_conn.ic_msg_queue, sizeof(stmf_ic_msg_queue_t));
#endif
		return (rc);
	}

	return (rc);
}

static void __exit
pppt_fini(void)
{
	/* disable pppt svc */
	pppt_ctrl_svc(PPPT_DISABLE_SVC);

	if (pppt_drv_detach())
		cmn_err(CE_WARN, "pppt detach failed");
	
	mutex_destroy(&pppt_global.global_lock);
	/* mutex_destroy(&pppt_global.global_door_lock); */
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
	mutex_destroy(&pppt_conn.ic_global_lock);
#endif
#if (PPPT_TRAN_WAY != PPPT_TRAN_USE_CLUSTERSAN)
	mutex_destroy(&pppt_conn.ic_tx_mutex);
	cv_destroy(&pppt_conn.ic_tx_cv);
#endif
	mutex_destroy(&pppt_conn.ic_tx_thr_lock);
	mutex_destroy(&pppt_conn.ic_rx_thr_lock);
	cv_destroy(&pppt_conn.ic_tx_thr_cv);
	cv_destroy(&pppt_conn.ic_rx_thr_cv);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
	mutex_destroy(&pppt_conn.ic_conn_lock);
	cv_destroy(&pppt_conn.ic_conn_cv);
#endif
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
	mutex_destroy(&pppt_conn.task_msg_lock);
	cv_destroy(&pppt_conn.ic_msg_queue->queue_cv);
	kmem_free(pppt_conn.ic_msg_queue, sizeof(stmf_ic_msg_queue_t));
#endif

}

static void
pppt_register_callbacks(void)
{
	pppt_callback_t cb;
	cb.ic_reg_port_msg_alloc = stmf_ic_reg_port_msg_alloc;
	cb.ic_dereg_port_msg_alloc = stmf_ic_dereg_port_msg_alloc;
	cb.ic_reg_lun_msg_alloc = stmf_ic_reg_lun_msg_alloc;
	cb.ic_lun_active_msg_alloc = stmf_ic_lun_active_msg_alloc;
	cb.ic_lun_deactive_msg_alloc = stmf_ic_lun_deactive_msg_alloc;
	cb.ic_dereg_lun_msg_alloc = stmf_ic_dereg_lun_msg_alloc;
	cb.ic_scsi_cmd_msg_alloc = stmf_ic_scsi_cmd_msg_alloc;
	cb.ic_scsi_data_xfer_done_msg_alloc = stmf_ic_scsi_data_xfer_done_msg_alloc;
	cb.ic_scsi_data_req_msg_alloc = stmf_ic_scsi_data_req_msg_alloc;
	cb.ic_scsi_data_res_msg_alloc = stmf_ic_scsi_data_res_msg_alloc;
	cb.ic_session_reg_msg_alloc = stmf_ic_session_create_msg_alloc;
	cb.ic_session_dereg_msg_alloc = stmf_ic_session_destroy_msg_alloc;
	cb.ic_tx_msg = stmf_ic_tx_msg;
	cb.ic_msg_free = stmf_ic_msg_free;
	cb.ic_notify_avs_master_state_alloc = stmf_ic_notify_avs_master_state_msg_alloc;
	cb.ic_set_remote_sync_flag_alloc = stmf_ic_set_remote_sync_flag_msg_alloc;
	
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	cb.ic_asyn_tx_msg = stmf_ic_asyn_tx_msg;
	cb.ic_asyn_tx_clean = stmf_ic_asyn_tx_clean;
	cb.ic_sync_tx_msg = stmf_ic_sync_tx_msg;
	cb.ic_sync_tx_msg_ret = stmf_ic_sync_tx_msg_ret;
	cb.ic_csh_hold = stmf_ic_csh_hold;
	cb.ic_csh_rele = stmf_ic_csh_rele;
	cb.ic_kmem_alloc = stmf_ic_kmem_alloc;
	cb.ic_kmem_zalloc = stmf_ic_kmem_zalloc;
	cb.ic_kmem_free = stmf_ic_kmem_free;
#endif

	stmf_register_pppt_cb(cb);
}

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
extern int stmf_hbx_modload(void);
extern void stmf_hbx_modunload(void);

static int
pppt_enable_zfs_hbx()
{
	cluster_status_t cls_state = CLUSTER_DISABLE;
	int ret;

	cls_state = get_host_cluster_enable();
	if (cls_state == CLUSTER_ENABLE) {
		ret = stmf_hbx_modload();
		if (ret != 0) {
			return (-1);
		}
		
		pppt_conn.ic_set_alua_state_complete = B_FALSE;
		
		if (!pppt_conn.ic_tx_thread_running) {
			pppt_conn.ic_tx_thread = thread_create(NULL, 0,
				stmf_ic_tx_thread,
				NULL, 0, &p0, TS_RUN, MINCLSYSPRI);
			if(NULL == pppt_conn.ic_tx_thread)
				panic("pppt create message send thread fail.\n");
		}
		while (!pppt_conn.ic_tx_thread_running) {
			drv_usecwait(10);
		}
	}

	return (0);
}

static void
pppt_disable_zfs_hbx()
{
	stmf_hbx_modunload();

	if (pppt_conn.ic_tx_thread_running) {
		pppt_conn.ic_tx_thread_exit = B_TRUE;
		stmf_ic_ksocket_wakeup();
		thread_join(pppt_conn.ic_tx_thread_did);
	}
}
#endif /* #if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX) */

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
/*
 * pppt ksocket entry points.
 */
static void
pppt_enable_ksocket()
{
	cluster_status_t cls_state = CLUSTER_DISABLE;

	cls_state = get_host_cluster_enable();
	if (cls_state == CLUSTER_ENABLE) {
		if (!pppt_conn.ic_tx_thread_running) {
			pppt_conn.ic_tx_thread = thread_create(NULL, 0,
				stmf_ic_tx_thread,
				NULL, 0, &p0, TS_RUN, MINCLSYSPRI);
			if(NULL == pppt_conn.ic_tx_thread)
				panic("pppt create message send thread fail.\n");
		}
		while (!pppt_conn.ic_tx_thread_running) {
			drv_usecwait(10);
		}
		if (!pppt_conn.ic_rx_thread_running) {
			pppt_conn.ic_rx_thread = thread_create(NULL, 0,
				stmf_ic_rx_thread,
				NULL, 0, &p0, TS_RUN, MINCLSYSPRI);
			if(NULL == pppt_conn.ic_rx_thread)
				panic("pppt create message receive thread fail.\n");
		}
		while (!pppt_conn.ic_rx_thread_running) {
			drv_usecwait(10);
		}
		if (!pppt_conn.ic_handle_msg_thread_running) {
			kthread_t *tmp_thread;

			tmp_thread = thread_create(NULL, 0,
				stmf_ic_handle_msg_thread, (void *)pppt_conn.ic_msg_queue,
				0, &p0, TS_RUN, MINCLSYSPRI);
			if(NULL == tmp_thread)
				panic("pppt create message handle thread fail.\n");
		}

		while (!pppt_conn.ic_handle_msg_thread_running) {
			drv_usecwait(10);
		}
	}
}

static void
pppt_disable_ksocket()
{
	if (pppt_conn.ic_tx_thread_running) {
		pppt_conn.ic_tx_thread_exit = B_TRUE;
		stmf_ic_ksocket_wakeup();
		thread_join(pppt_conn.ic_tx_thread_did);
	}

	if (pppt_conn.ic_rx_thread_running) {
		pppt_conn.ic_rx_thread_exit = B_TRUE;
		stmf_ic_ksocket_wakeup();
		thread_join(pppt_conn.ic_rx_thread_did);
	}

	if (pppt_conn.ic_handle_msg_thread_running) {
		pppt_conn.ic_handle_msg_thread_exit = B_TRUE;
		if(!(pppt_conn.ic_msg_queue->queue_flags & QUEUE_ACTIVE))
			cv_signal(&pppt_conn.ic_msg_queue->queue_cv);
		stmf_ic_ksocket_wakeup();
		thread_join(pppt_conn.ic_handle_msg_thread_did);
	}
}
#endif /* #if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET) */

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
extern int stmf_clustersan_modload(void);
extern void stmf_clustersan_modunload(void);
extern void stmf_clustersan_alua_state_sync(void *arg);
extern int stmf_modload(void);

cluster_status_t get_host_cluster_enable(void)
{
	return (CLUSTER_ENABLE);
}


static int
pppt_enable_clustersan(void)
{
	cluster_status_t cls_state = CLUSTER_DISABLE;
	int ret;
	uint32_t	hostid;
	stmf_alua_state_desc_t *alua_state;

	cls_state = get_host_cluster_enable();
	if (cls_state == CLUSTER_ENABLE) {
		ret = stmf_clustersan_modload();
		if (ret != 0) {
			return (-1);
		}

		ret = stmf_modload();
		if (ret != 0) {
			cmn_err(CE_WARN, "pppt stmf mod load failed");
			return (-1);
		}
		
		if (pppt_conn.ic_cs_asyn_taskq == NULL) {
			pppt_conn.ic_cs_asyn_taskq = taskq_create(
				"pppt_ic_cts_asyn_taskq",
				8, minclsyspri, 8, INT_MAX, TASKQ_PREPOPULATE);
		}

		alua_state = kmem_zalloc(sizeof(stmf_alua_state_desc_t), KM_SLEEP);
		hostid = zone_get_hostid(NULL);
		alua_state->alua_node = (hostid + 1) % 2;
		alua_state->alua_state = 1;
		alua_state->alua_psess = (uint64_t)((uintptr_t)PPPT_BROADCAST_SESS);

		/* set alua state */
		taskq_dispatch(pppt_conn.ic_cs_asyn_taskq,
			stmf_clustersan_alua_state_sync,
			(void *)alua_state, TQ_SLEEP);
		/* get other's alua state */
	}

	return (0);
}

static void
pppt_disable_clustersan(void)
{
	stmf_clustersan_modunload();
	taskq_destroy(pppt_conn.ic_cs_asyn_taskq);
	pppt_conn.ic_cs_asyn_taskq = NULL;
}
#endif /* #if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN) */

static int
pppt_drv_attach()
{
	int ret;

	/* create the minor node */
	ret = misc_register(&pppt_misc);
	if (ret != 0) {
		cmn_err(CE_WARN, "PPPT: misc_register() failed %d", ret);
		return (ret);
	}
	
	pppt_global.global_svc_state = PSS_DISABLED;

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
	pppt_enable_ksocket();
#elif (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
	ret = pppt_enable_zfs_hbx();
	if (ret != 0) {
		misc_deregister(&pppt_misc);		
		pppt_global.global_svc_state = PSS_DETACHED;
		return (DDI_FAILURE);
	}
#elif (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	ret = pppt_enable_clustersan();
	if (ret != 0) {
		misc_deregister(&pppt_misc);
		pppt_global.global_svc_state = PSS_DETACHED;
		return (DDI_FAILURE);
	}
#endif

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pppt_drv_detach()
{
	PPPT_GLOBAL_LOCK();
	if (pppt_drv_busy()) {
		PPPT_GLOBAL_UNLOCK();
		return (EBUSY);
	}

	misc_deregister(&pppt_misc);
	pppt_global.global_svc_state = PSS_DETACHED;

	PPPT_GLOBAL_UNLOCK();
	
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
	pppt_disable_ksocket();
#elif (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
	pppt_disable_zfs_hbx();
#elif (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	pppt_disable_clustersan();
#endif
	
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pppt_drv_open(struct inode *inode, struct file *file)
{
	int	rc = 0;

#if 0
	PPPT_GLOBAL_LOCK();

	switch (pppt_global.global_svc_state) {
	case PSS_DISABLED:
		pppt_global.global_svc_state = PSS_ENABLING;
		PPPT_GLOBAL_UNLOCK();
		rc = pppt_enable_svc();
		PPPT_GLOBAL_LOCK();
		if (rc == 0) {
			pppt_global.global_svc_state = PSS_ENABLED;
		} else {
			pppt_global.global_svc_state = PSS_DISABLED;
		}
		break;
	case PSS_DISABLING:
	case PSS_ENABLING:
	case PSS_ENABLED:
		rc = EBUSY;
		break;
	default:
		rc = EFAULT;
		break;
	}

	PPPT_GLOBAL_UNLOCK();

#endif

	return (rc);
}

/* ARGSUSED */
static int
pppt_drv_close(struct inode *inode, struct file *file)
{
	int rc = 0;
	
#if 0
	PPPT_GLOBAL_LOCK();

	switch (pppt_global.global_svc_state) {
	case PSS_ENABLED:
		pppt_global.global_svc_state = PSS_DISABLING;
		PPPT_GLOBAL_UNLOCK();
		pppt_disable_svc();
		PPPT_GLOBAL_LOCK();
		pppt_global.global_svc_state = PSS_DISABLED;
		/*
		 * release the door to the daemon
		 */
		mutex_enter(&pppt_global.global_door_lock);
		if (pppt_global.global_door != NULL) {
			door_ki_rele(pppt_global.global_door);
			pppt_global.global_door = NULL;
		}
		mutex_exit(&pppt_global.global_door_lock);
		break;
	default:
		rc = EFAULT;
		break;
	}

	PPPT_GLOBAL_UNLOCK();
#endif
	return (rc);
}

static boolean_t
pppt_drv_busy(void)
{
	switch (pppt_global.global_svc_state) {
	case PSS_DISABLED:
	case PSS_DETACHED:
		return (B_FALSE);
	default:
		return (B_TRUE);
	}
	/* NOTREACHED */
}

/* ARGSUSED */
static long
pppt_drv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int		rc;
	void	*buf;
	size_t	buf_size;
	pppt_iocdata_t	iocd;

	rc = ddi_copyin((void *)arg, &iocd, sizeof (iocd), 0);
	if (rc)
		return (EFAULT);

	if (iocd.pppt_version != PPPT_VERSION_1)
		return (EINVAL);

	switch (cmd) {
	case PPPT_MESSAGE:

		/* XXX limit buf_size ? */
		buf_size = (size_t)iocd.pppt_buf_size;
		buf = kmem_alloc(buf_size, KM_SLEEP);
		if (buf == NULL)
			return (ENOMEM);

		rc = ddi_copyin((void *)(unsigned long)iocd.pppt_buf,
		    buf, buf_size, 0);
		if (rc) {
			kmem_free(buf, buf_size);
			return (EFAULT);
		}

		stmf_ic_rx_msg(buf, buf_size, NULL);

		kmem_free(buf, buf_size);
		break;
	case PPPT_INSTALL_DOOR:
#if 0
		new_handle = door_ki_lookup((int)iocd.pppt_door_fd);
		if (new_handle == NULL)
			return (EINVAL);

		mutex_enter(&pppt_global.global_door_lock);
		ASSERT(pppt_global.global_svc_state == PSS_ENABLED);
		if (pppt_global.global_door != NULL) {
			/*
			 * There can only be one door installed
			 */
			mutex_exit(&pppt_global.global_door_lock);
			door_ki_rele(new_handle);
			return (EBUSY);
		}
		pppt_global.global_door = new_handle;
		mutex_exit(&pppt_global.global_door_lock);
#endif
		break;
	case PPPT_ENABLE_SVC:
	case PPPT_DISABLE_SVC:
		pppt_ctrl_svc(cmd);
		break;
	case PPPT_KSOCKET_WAKEUP:
		if (pppt_global.global_svc_state == PSS_ENABLED) {
			stmf_ic_ksocket_wakeup();
		}
		break;
	case PPPT_KSOCKET_ENABLE:
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
		pppt_enable_ksocket();
#elif (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
		pppt_enable_zfs_hbx();
#endif
		break;
	case PPPT_KSOCKET_DISABLE:
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
		pppt_disable_ksocket();
#elif (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
		pppt_disable_zfs_hbx();
#endif
		break;
	case PPPT_KSOCKET_DISCONNECT:
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
		stmf_ic_so_disconnect();
#endif
		break;
	}

	return (rc);
}

/*
 * pppt_enable_svc
 *
 * registers all the configured targets and target portals with STMF
 */
static int
pppt_enable_svc(void)
{
	stmf_port_provider_t	*pp;
	stmf_dbuf_store_t	*dbuf_store;
	int			rc = 0;

	ASSERT(pppt_global.global_svc_state == PSS_ENABLING);
	/*
	 * Make sure that can tell if we have partially allocated
	 * in case we need to exit and tear down anything allocated.
	 */
	pppt_global.global_dbuf_store = NULL;
	pp = NULL;
	pppt_global.global_pp = NULL;
	pppt_global.global_dispatch_taskq = NULL;
	pppt_global.global_sess_taskq = NULL;

	avl_create(&pppt_global.global_target_list,
	    pppt_tgt_avl_compare, sizeof (pppt_tgt_t),
	    offsetof(pppt_tgt_t, target_global_ln));

	avl_create(&pppt_global.global_sess_list,
	    pppt_sess_avl_compare_by_id, sizeof (pppt_sess_t),
	    offsetof(pppt_sess_t, ps_global_ln));

	/*
	 * Setup STMF dbuf store.  Tf buffers are associated with a particular
	 * lport (FC, SRP) then the dbuf_store should stored in the lport
	 * context, otherwise (iSCSI) the dbuf_store should be global.
	 */
	dbuf_store = stmf_alloc(STMF_STRUCT_DBUF_STORE, 0, 0);
	if (dbuf_store == NULL) {
		rc = ENOMEM;
		goto tear_down_and_return;
	}
	dbuf_store->ds_alloc_data_buf = pppt_dbuf_alloc;
	dbuf_store->ds_free_data_buf = pppt_dbuf_free;
	dbuf_store->ds_port_private = NULL;
	pppt_global.global_dbuf_store = dbuf_store;

	/* Register port provider */
	pp = stmf_alloc(STMF_STRUCT_PORT_PROVIDER, 0, 0);
	if (pp == NULL) {
		rc = ENOMEM;
		goto tear_down_and_return;
	}

	pp->pp_portif_rev = PORTIF_REV_1;
	pp->pp_instance = 0;
	pp->pp_name = PPPT_MODNAME;
	pp->pp_cb = NULL;

	pppt_global.global_pp = pp;

	if (stmf_register_port_provider(pp) != STMF_SUCCESS) {
		rc = EIO;
		goto tear_down_and_return;
	}

	pppt_global.global_dispatch_taskq = taskq_create("pppt_dispatch",
	    1, minclsyspri, 1, INT_MAX, TASKQ_PREPOPULATE);

	pppt_global.global_sess_taskq = taskq_create("pppt_session",
	    1, minclsyspri, 1, INT_MAX, TASKQ_PREPOPULATE);


	return (0);

tear_down_and_return:

	if (pppt_global.global_sess_taskq) {
		taskq_destroy(pppt_global.global_sess_taskq);
		pppt_global.global_sess_taskq = NULL;
	}

	if (pppt_global.global_dispatch_taskq) {
		taskq_destroy(pppt_global.global_dispatch_taskq);
		pppt_global.global_dispatch_taskq = NULL;
	}

	if (pppt_global.global_pp)
		pppt_global.global_pp = NULL;

	if (pp)
		stmf_free(pp);

	if (pppt_global.global_dbuf_store) {
		stmf_free(pppt_global.global_dbuf_store);
		pppt_global.global_dbuf_store = NULL;
	}

	avl_destroy(&pppt_global.global_sess_list);
	avl_destroy(&pppt_global.global_target_list);

	return (rc);
}

/*
 * pppt_disable_svc
 *
 * clean up all existing sessions and deregister targets from STMF
 */
static void
pppt_disable_svc(void)
{
	pppt_tgt_t	*tgt, *next_tgt;
	avl_tree_t	delete_target_list;

	ASSERT(pppt_global.global_svc_state == PSS_DISABLING);

	avl_create(&delete_target_list,
	    pppt_tgt_avl_compare, sizeof (pppt_tgt_t),
	    offsetof(pppt_tgt_t, target_global_ln));

	PPPT_GLOBAL_LOCK();
	for (tgt = avl_first(&pppt_global.global_target_list);
	    tgt != NULL;
	    tgt = next_tgt) {
		next_tgt = AVL_NEXT(&pppt_global.global_target_list, tgt);
		avl_remove(&pppt_global.global_target_list, tgt);
		avl_add(&delete_target_list, tgt);
		pppt_tgt_async_delete(tgt);
	}
	PPPT_GLOBAL_UNLOCK();

	for (tgt = avl_first(&delete_target_list);
	    tgt != NULL;
	    tgt = next_tgt) {
		next_tgt = AVL_NEXT(&delete_target_list, tgt);
		mutex_enter(&tgt->target_mutex);
		while ((tgt->target_refcount > 0) ||
		    (tgt->target_state != TS_DELETING)) {
			cv_wait(&tgt->target_cv, &tgt->target_mutex);
		}
		mutex_exit(&tgt->target_mutex);

		avl_remove(&delete_target_list, tgt);
		pppt_tgt_destroy(tgt);
	}

	taskq_destroy(pppt_global.global_sess_taskq);

	taskq_destroy(pppt_global.global_dispatch_taskq);

	avl_destroy(&pppt_global.global_sess_list);
	avl_destroy(&pppt_global.global_target_list);

	(void) stmf_deregister_port_provider(pppt_global.global_pp);

	stmf_free(pppt_global.global_dbuf_store);
	pppt_global.global_dbuf_store = NULL;

	stmf_free(pppt_global.global_pp);
	pppt_global.global_pp = NULL;
}

int
pppt_ctrl_svc(int cmd)
{
	int rc = 0;

	PPPT_GLOBAL_LOCK();
		
	switch (pppt_global.global_svc_state) {
	case PSS_DISABLED:
		if (cmd == PPPT_ENABLE_SVC) {
			pppt_global.global_svc_state = PSS_ENABLING;
			PPPT_GLOBAL_UNLOCK();
			rc = pppt_enable_svc();
			PPPT_GLOBAL_LOCK();
			if (rc == 0) {
				pppt_global.global_svc_state = PSS_ENABLED;
			} else {
				pppt_global.global_svc_state = PSS_DISABLED;
			}
		}
		break;
	case PSS_ENABLED:
		if (cmd == PPPT_DISABLE_SVC) {
			pppt_global.global_svc_state = PSS_DISABLING;
			PPPT_GLOBAL_UNLOCK();
			pppt_disable_svc();
			PPPT_GLOBAL_LOCK();
			pppt_global.global_svc_state = PSS_DISABLED;
		}
		break;
	case PSS_DISABLING:
	case PSS_ENABLING:
		rc = EBUSY;
		break;
	default:
		rc = EFAULT;
		break;
		
	}

	PPPT_GLOBAL_UNLOCK();

	return (rc);
}

/*
 * STMF callbacks
 */

/*ARGSUSED*/
static stmf_data_buf_t *
pppt_dbuf_alloc(scsi_task_t *task, uint32_t size, uint32_t *pminsize,
    uint32_t flags)
{
	stmf_data_buf_t	*result;
	pppt_buf_t	*pbuf;
	uint8_t		*buf;

	/* Get buffer */
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	buf = stmf_ic_kmem_alloc(size, KM_SLEEP);
#else
	buf = kmem_alloc(size, KM_SLEEP);
#endif
	/*
	 *  Allocate stmf buf with private port provider section
	 * (pppt_buf_t)
	 */
	result = stmf_alloc(STMF_STRUCT_DATA_BUF, sizeof (pppt_buf_t), 0);
	if (result != NULL) {
		/* Fill in pppt_buf_t */
		pbuf = result->db_port_private;
		pbuf->pbuf_stmf_buf = result;
		pbuf->pbuf_is_immed = B_FALSE;

		/*
		 * Fill in stmf_data_buf_t.  DB_DONT CACHE tells
		 * stmf not to cache buffers but STMF doesn't do
		 * that yet so it's a no-op.  Port providers like
		 * FC and SRP that have buffers associated with the
		 * target port would want to let STMF cache
		 * the buffers.  Port providers like iSCSI would
		 * not want STMF to cache because the buffers are
		 * really associated with a connection, not an
		 * STMF target port so there is no way for STMF
		 * to cache the buffers effectively.  These port
		 * providers should cache buffers internally if
		 * there is significant buffer setup overhead.
		 *
		 * And of course, since STMF doesn't do any internal
		 * caching right now anyway, all port providers should
		 * do what they can to minimize buffer setup overhead.
		 */
		result->db_flags = DB_DONT_CACHE|DB_TYPE_PPPT;
		result->db_buf_size = size;
		result->db_data_size = size;
		result->db_sglist_length = 1;
		result->db_sglist[0].seg_addr = buf;
		result->db_sglist[0].seg_length = size;
		return (result);
	} else {
		/*
		 * Couldn't get the stmf_data_buf_t so free the
		 * buffer
		 */
		cmn_err(CE_WARN, "pppt_dbuf_alloc failed alloc size %d",(int)sizeof(pppt_buf_t)); 
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		stmf_ic_kmem_free(buf, size);
#else
		kmem_free(buf, size);
#endif
	}

	return (NULL);
}

/*ARGSUSED*/
static void
pppt_dbuf_free(stmf_dbuf_store_t *ds, stmf_data_buf_t *dbuf)
{
	pppt_buf_t *pbuf = dbuf->db_port_private;

	if (pbuf->pbuf_is_immed) {
		stmf_ic_msg_free(pbuf->pbuf_immed_msg);
		
		pbuf->pbuf_is_immed = B_FALSE;		/*is here want to reusing ??*/

		/*
		if ((dbuf->db_flags & DB_WRITE_FROM_PPPT) && !(dbuf->db_flags &
		    DB_WRITE_FROM_PPPT_INIT)) {
			kmem_free(dbuf->db_sglist[0].seg_addr,
		    	    dbuf->db_sglist[0].seg_length);
			stmf_free(dbuf);
		}*/
	} else {
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		stmf_ic_kmem_free(dbuf->db_sglist[0].seg_addr,
		    dbuf->db_sglist[0].seg_length);
#else
		kmem_free(dbuf->db_sglist[0].seg_addr,
		    dbuf->db_sglist[0].seg_length);
#endif
		stmf_free(dbuf);
	}
}

/*ARGSUSED*/
stmf_status_t
pppt_lport_xfer_data(scsi_task_t *task, stmf_data_buf_t *dbuf,
    uint32_t ioflags)
{
	pppt_task_t		*pppt_task = task->task_port_private;
	pppt_tgt_t		*ptgt = pppt_task->pt_sess->ps_target;
	pppt_buf_t		*pbuf = dbuf->db_port_private;
	stmf_ic_msg_t		*msg;
	stmf_ic_msg_status_t	ic_msg_status;

	/*
	 * If it's not immediate data then start the transfer
	 */
	ASSERT(pbuf->pbuf_is_immed == B_FALSE);
	if (dbuf->db_flags & DB_DIRECTION_TO_RPORT) {

		/* Send read data */
		msg = stmf_ic_scsi_data_msg_alloc(
		    pppt_task->pt_task_id,
		    pppt_task->pt_sess->ps_session_id,
		    pppt_task->pt_lun_id,
		    dbuf->db_data_size, 
		    dbuf->db_sglist[0].seg_addr, 0);

		pppt_task->pt_read_buf = pbuf;
		pppt_task->pt_read_xfer_msgid = msg->icm_msgid;
		msg->icm_sess = ptgt->target_psess;

		ic_msg_status = stmf_ic_tx_msg(msg);
		if (ic_msg_status != STMF_IC_MSG_SUCCESS) {
			cmn_err(CE_WARN, "pppt_lport_xfer_data failed. db_flags = 0x%x", dbuf->db_flags);
			return (STMF_FAILURE);
		} else {
			return (STMF_SUCCESS);
		}
	} else if (dbuf->db_flags & DB_DIRECTION_FROM_RPORT) {
		/* Send request for write data */
		msg = stmf_ic_scsi_data_req_msg_alloc(
		    pppt_task->pt_task_id,
		    pppt_task->pt_sess->ps_session_id,
		    pppt_task->pt_lun_id,
		    dbuf->db_relative_offset,
		    dbuf->db_data_size, 0);

		pppt_task->pt_write_buf = pbuf;
		pppt_task->pt_write_xfer_msgid = msg->icm_msgid;
		msg->icm_sess = ptgt->target_psess;

		ic_msg_status = stmf_ic_tx_msg(msg);
		if (ic_msg_status != STMF_IC_MSG_SUCCESS) {
			cmn_err(CE_WARN, "pppt_lport_xfer_data failed. db_flags = 0x%x", dbuf->db_flags);
			return (STMF_FAILURE);
		} else {
			return (STMF_SUCCESS);
		}
	}

	cmn_err(CE_WARN, "pppt_lport_xfer_data failed, STMF_INVALID_ARG. db_flags = 0x%x", dbuf->db_flags);
	return (STMF_INVALID_ARG);
}

void
pppt_xfer_read_complete(pppt_task_t *pppt_task, stmf_status_t status)
{
	pppt_buf_t		*pppt_buf;
	stmf_data_buf_t		*dbuf;

	/*
	 * Caller should have taken a task hold (likely via pppt_task_lookup)
	 *
	 * Get pppt_buf_t and stmf_data_buf_t pointers
	 */
	pppt_buf = pppt_task->pt_read_buf;
	dbuf = pppt_buf->pbuf_stmf_buf;
	dbuf->db_xfer_status = (status == STMF_SUCCESS) ?
	    STMF_SUCCESS : STMF_FAILURE;
	#if 1
		
		stmf_data_xfer_done(pppt_task->pt_stmf_task, dbuf, 0);
	#else
	/*
	 * COMSTAR currently requires port providers to support
	 * the DB_SEND_STATUS_GOOD flag even if phase collapse is
	 * not supported.  So we will roll our own... pretend we are
	 * COMSTAR and ask for a status message.
	 */
	if ((dbuf->db_flags & DB_SEND_STATUS_GOOD) &&
	    (status == STMF_SUCCESS)) {
		/*
		 * It's possible the task has been aborted since the time we
		 * looked it up.  We need to release the hold before calling
		 * pppt_lport_send_status and as soon as we release the hold
		 * the task may disappear.  Calling pppt_task_done allows us
		 * to determine whether the task has been aborted (in which
		 * case we will stop processing and return) and mark the task
		 * "done" which will prevent the task from being aborted while
		 * we are trying to send the status.
		 */
		
		if (pppt_task_done(pppt_task) != PPPT_STATUS_SUCCESS) {
			/* STMF will free task and buffer(s) */
			cmn_err(CE_WARN,   "%s pppt_task_done failed, task = %p",__func__, (void *)pppt_task);
			return;
		}
		
		
		if (pppt_lport_send_status(pppt_task->pt_stmf_task, 0)
		    != STMF_SUCCESS) {
			/* Failed to send status */
			cmn_err(CE_WARN,   "%s pppt_lport_send_status failed, task = %p",__func__, (void *)pppt_task);
			dbuf->db_xfer_status = STMF_FAILURE;
			stmf_data_xfer_done(pppt_task->pt_stmf_task, dbuf,
			    STMF_IOF_LPORT_DONE);
		}
		
 		
	} else {
		stmf_data_xfer_done(pppt_task->pt_stmf_task, dbuf, 0);
	}
	#endif
}

/*ARGSUSED*/
stmf_status_t
pppt_lport_send_status(scsi_task_t *task, uint32_t ioflags)
{
	pppt_task_t *ptask =		task->task_port_private;
	stmf_ic_msg_t			*msg;
	stmf_ic_msg_status_t		ic_msg_status = STMF_SUCCESS;

	/*
	 * Send status.
	 */

	msg = stmf_ic_scsi_status_msg_alloc(
	    ptask->pt_task_id,
	    ptask->pt_sess->ps_session_id,
	    ptask->pt_lun_id,
	    0,
	    task->task_scsi_status,
	    task->task_status_ctrl, task->task_resid,
	    task->task_sense_length, task->task_sense_data, 0);
	msg->icm_sess = ptask->pt_sess->ps_target->target_psess;

	ic_msg_status = stmf_ic_tx_msg(msg);

	if (ic_msg_status != STMF_IC_MSG_SUCCESS) {
		stmf_send_status_done(ptask->pt_stmf_task,
		    STMF_FAILURE, STMF_IOF_LPORT_DONE);
		return (STMF_FAILURE);
	} else {
		stmf_send_status_done(ptask->pt_stmf_task,
		    STMF_SUCCESS, STMF_IOF_LPORT_DONE);
		return (STMF_SUCCESS);
	}
}

void
pppt_lport_task_free(scsi_task_t *task)
{
	pppt_task_t *ptask = task->task_port_private;
	pppt_sess_t *ps = ptask->pt_sess;

    pppt_task_free(ptask);
	pppt_sess_rele(ps);
}

/*ARGSUSED*/
stmf_status_t
pppt_lport_abort(stmf_local_port_t *lport, int abort_cmd, void *arg,
    uint32_t flags)
{
	
	return (STMF_ABORT_SUCCESS);
	
	/*NOTREACHED*/
}

/*ARGSUSED*/
void
pppt_lport_ctl(stmf_local_port_t *lport, int cmd, void *arg)
{
	switch (cmd) {
	case STMF_CMD_LPORT_ONLINE:
	case STMF_CMD_LPORT_OFFLINE:
	case STMF_ACK_LPORT_ONLINE_COMPLETE:
	case STMF_ACK_LPORT_OFFLINE_COMPLETE:
		pppt_tgt_sm_ctl(lport, cmd, arg);
		break;

	default:
		ASSERT(0);
		break;
	}
}

pppt_sess_t *
pppt_sess_lookup_locked(uint64_t session_id,
    scsi_devid_desc_t *lport_devid, stmf_remote_port_t *rport)
{
	pppt_tgt_t				*tgt;
	pppt_sess_t				*ps;
	int					lport_cmp;

	ASSERT(mutex_owned(&pppt_global.global_lock));

	/*
	 * Look for existing session for this ID
	 */
	ps = pppt_sess_lookup_by_id_locked(session_id);
	if (ps == NULL) {
		PPPT_INC_STAT(es_sess_lookup_no_session);
		return (NULL);
	}

	tgt = ps->ps_target;

	mutex_enter(&tgt->target_mutex);

	/* Validate local/remote port names */
	if ((lport_devid->ident_length !=
	    tgt->target_stmf_lport->lport_id->ident_length) ||
	    (rport->rport_tptid_sz !=
	    ps->ps_stmf_sess->ss_rport->rport_tptid_sz)) {
		mutex_exit(&tgt->target_mutex);
		PPPT_INC_STAT(es_sess_lookup_ident_mismatch);
		
		pppt_sess_rele(ps);
		cmn_err(CE_WARN,   "%s  pppt_session idlen is mismatch",__func__);
		return (NULL);
	} else {
		lport_cmp = bcmp(lport_devid->ident,
		    tgt->target_stmf_lport->lport_id->ident,
		    lport_devid->ident_length);
		if (lport_cmp != 0 ||
		    (stmf_scsilib_tptid_compare(rport->rport_tptid,
		    ps->ps_stmf_sess->ss_rport->rport_tptid) != B_TRUE)) {
			mutex_exit(&tgt->target_mutex);
			PPPT_INC_STAT(es_sess_lookup_ident_mismatch);
			pppt_sess_rele(ps);
			cmn_err(CE_WARN,   "%s  pppt_session id is mismatch",__func__);
			return (NULL);
		}

		if (tgt->target_state != TS_STMF_ONLINE) {
			mutex_exit(&tgt->target_mutex);
			PPPT_INC_STAT(es_sess_lookup_bad_tgt_state);
			pppt_sess_rele(ps);
			cmn_err(CE_WARN,   "%s  pppt_session state %d is mismatch",__func__,tgt->target_state);
			return (NULL);
		}
	}
	mutex_exit(&tgt->target_mutex);

	return (ps);
}

pppt_sess_t *
pppt_sess_lookup_by_id_locked(uint64_t session_id)
{
	pppt_sess_t		tmp_ps;
	pppt_sess_t		*ps;

	ASSERT(mutex_owned(&pppt_global.global_lock));
	tmp_ps.ps_session_id = session_id;
	tmp_ps.ps_closed = 0;
	ps = avl_find(&pppt_global.global_sess_list, &tmp_ps, NULL);
	if (ps != NULL) {
		mutex_enter(&ps->ps_mutex);
		if (!ps->ps_closed) {
			ps->ps_refcnt++;
			mutex_exit(&ps->ps_mutex);
			return (ps);
		}
		mutex_exit(&ps->ps_mutex);
	}

	return (NULL);
}

/* New session */
pppt_sess_t *
pppt_sess_lookup_create(scsi_devid_desc_t *lport_devid,
    scsi_devid_desc_t *rport_devid, stmf_remote_port_t *rport,
    uint64_t session_id, stmf_status_t *statusp)
{
	pppt_tgt_t		*tgt;
	pppt_sess_t		*ps;
	stmf_scsi_session_t	*ss;
	pppt_sess_t		tmp_ps;
	stmf_scsi_session_t	tmp_ss;
	*statusp = STMF_SUCCESS;

	PPPT_GLOBAL_LOCK();

	/*
	 * Look for existing session for this ID
	 */
	ps = pppt_sess_lookup_locked(session_id, lport_devid, rport);

	if (ps != NULL) {
		PPPT_GLOBAL_UNLOCK();
		return (ps);
	}

	cmn_err(CE_WARN,   "%s  session_id = %"PRIx64"",__func__, session_id);
	
	/*
	 * No session with that ID, look for another session corresponding
	 * to the same IT nexus.
	 */
	tgt = pppt_tgt_lookup_locked(lport_devid);
	if (tgt == NULL) {
		*statusp = STMF_NOT_FOUND;
		PPPT_GLOBAL_UNLOCK();
		return (NULL);
	}

	mutex_enter(&tgt->target_mutex);
	if (tgt->target_state != TS_STMF_ONLINE) {
		*statusp = STMF_NOT_FOUND;
		mutex_exit(&tgt->target_mutex);
		PPPT_GLOBAL_UNLOCK();
		/* Can't create session to offline target */
		return (NULL);
	}

	bzero(&tmp_ps, sizeof (tmp_ps));
	bzero(&tmp_ss, sizeof (tmp_ss));
	tmp_ps.ps_stmf_sess = &tmp_ss;
	tmp_ss.ss_rport = rport;

	/*
	 * Look for an existing session on this IT nexus
	 */
	ps = avl_find(&tgt->target_sess_list, &tmp_ps, NULL);

	if (ps != NULL) {
		/*
		 * Now check the session ID.  It should not match because if
		 * it did we would have found it on the global session list.
		 * If the session ID in the command is higher than the existing
		 * session ID then we need to tear down the existing session.
		 */
		//mutex_enter(&ps->ps_mutex);
		ASSERT(ps->ps_session_id != session_id);
		if (ps->ps_session_id > session_id) {
			/* Invalid session ID */
			//mutex_exit(&ps->ps_mutex);
			mutex_exit(&tgt->target_mutex);
			PPPT_GLOBAL_UNLOCK();
			*statusp = STMF_INVALID_ARG;
			return (NULL);
		} else {
			/* Existing session needs to be invalidated */
			if (!ps->ps_closed) {
				pppt_sess_close_locked(ps);
			}
		}
		//mutex_exit(&ps->ps_mutex);

		/* Fallthrough and create new session */
	}
	cmn_err(CE_WARN,   "%s  allocate new session session_id = %"PRIx64"",__func__, session_id);
	/*
	 * Allocate and fill in pppt_session_t with the appropriate data
	 * for the protocol.
	 */
	ps = kmem_zalloc(sizeof (*ps), KM_SLEEP);

	/* Fill in session fields */
	ps->ps_target = tgt;
	ps->ps_session_id = session_id;

	ss = stmf_alloc(STMF_STRUCT_SCSI_SESSION, 0,
	    0);
	if (ss == NULL) {
		mutex_exit(&tgt->target_mutex);
		PPPT_GLOBAL_UNLOCK();
		kmem_free(ps, sizeof (*ps));
		*statusp = STMF_ALLOC_FAILURE;
		return (NULL);
	}

	ss->ss_rport_id = kmem_zalloc(sizeof (scsi_devid_desc_t) +
	    rport_devid->ident_length + 1, KM_SLEEP);
	bcopy(rport_devid, ss->ss_rport_id,
	    sizeof (scsi_devid_desc_t) + rport_devid->ident_length + 1);

	ss->ss_lport = tgt->target_stmf_lport;

	ss->ss_rport = stmf_remote_port_alloc(rport->rport_tptid_sz);
	bcopy(rport->rport_tptid, ss->ss_rport->rport_tptid,
	    rport->rport_tptid_sz);

	cmn_err(CE_NOTE, "%s invoke register_scsi_session", __func__);
	if (stmf_register_scsi_session(tgt->target_stmf_lport, ss) !=
	    STMF_SUCCESS) {
		mutex_exit(&tgt->target_mutex);
		PPPT_GLOBAL_UNLOCK();
		kmem_free(ss->ss_rport_id,
		    sizeof (scsi_devid_desc_t) + rport_devid->ident_length + 1);
		stmf_remote_port_free(ss->ss_rport);
		stmf_free(ss);
		kmem_free(ps, sizeof (*ps));
		*statusp = STMF_TARGET_FAILURE;
		return (NULL);
	}

	ss->ss_port_private = ps;
	mutex_init(&ps->ps_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ps->ps_cv, NULL, CV_DEFAULT, NULL);
	avl_create(&ps->ps_task_list, pppt_task_avl_compare,
	    sizeof (pppt_task_t), offsetof(pppt_task_t, pt_sess_ln));
	ps->ps_refcnt = 1;
	ps->ps_stmf_sess = ss;
	avl_add(&tgt->target_sess_list, ps);
	avl_add(&pppt_global.global_sess_list, ps);
	mutex_exit(&tgt->target_mutex);
	PPPT_GLOBAL_UNLOCK();
	stmf_trace("pppt", "New session %p", (void *)ps);

	return (ps);
}

void
pppt_sess_rele(pppt_sess_t *ps)
{
	mutex_enter(&ps->ps_mutex);
	pppt_sess_rele_locked(ps);
	mutex_exit(&ps->ps_mutex);
}

void
pppt_sess_rele_locked(pppt_sess_t *ps)
{
	ASSERT(mutex_owned(&ps->ps_mutex));
	ps->ps_refcnt--;
	if (ps->ps_refcnt == 0) {
		cv_signal(&ps->ps_cv);
	}
}

static void pppt_sess_destroy_task(void *ps_void)
{
	pppt_sess_t *ps = ps_void;
	stmf_scsi_session_t	*ss;

	stmf_trace("pppt", "Session destroy task %p", (void *)ps);

	ss = ps->ps_stmf_sess;
	//mutex_enter(&ps->ps_mutex);
	cmn_err(CE_NOTE, "%s invoke deregister_scsi_session", __func__);
	stmf_deregister_scsi_session(ss->ss_lport, ss);
	kmem_free(ss->ss_rport_id,
	    sizeof (scsi_devid_desc_t) + ss->ss_rport_id->ident_length + 1);
	stmf_remote_port_free(ss->ss_rport);
	avl_destroy(&ps->ps_task_list);
	//mutex_exit(&ps->ps_mutex);
	cv_destroy(&ps->ps_cv);
	mutex_destroy(&ps->ps_mutex);
	stmf_free(ps->ps_stmf_sess);
	kmem_free(ps, sizeof (*ps));
	
	stmf_trace("pppt", "Session destroy task complete %p", (void *)ps);
}

int
pppt_sess_avl_compare_by_id(const void *void_sess1, const void *void_sess2)
{
	const	pppt_sess_t	*psess1 = void_sess1;
	const	pppt_sess_t	*psess2 = void_sess2;

	if (psess1->ps_session_id < psess2->ps_session_id)
		return (-1);
	else if (psess1->ps_session_id > psess2->ps_session_id)
		return (1);

	/* Allow multiple duplicate sessions if one is closed */
	ASSERT(!(psess1->ps_closed && psess2->ps_closed));
	if (psess1->ps_closed)
		return (-1);
	else if (psess2->ps_closed)
		return (1);

	return (0);
}

int
pppt_sess_avl_compare_by_name(const void *void_sess1, const void *void_sess2)
{
	const	pppt_sess_t	*psess1 = void_sess1;
	const	pppt_sess_t	*psess2 = void_sess2;
	int			result;

	/* Compare by tptid size */
	if (psess1->ps_stmf_sess->ss_rport->rport_tptid_sz <
	    psess2->ps_stmf_sess->ss_rport->rport_tptid_sz) {
		return (-1);
	} else if (psess1->ps_stmf_sess->ss_rport->rport_tptid_sz >
	    psess2->ps_stmf_sess->ss_rport->rport_tptid_sz) {
		return (1);
	}

	/* Now compare tptid */
	result = memcmp(psess1->ps_stmf_sess->ss_rport->rport_tptid,
	    psess2->ps_stmf_sess->ss_rport->rport_tptid,
	    psess1->ps_stmf_sess->ss_rport->rport_tptid_sz);

	if (result < 0) {
		return (-1);
	} else if (result > 0) {
		return (1);
	}

	return (0);
}

void
pppt_sess_close_locked(pppt_sess_t *ps)
{
	pppt_tgt_t	*tgt = ps->ps_target;
	int num;
	int i;
	
	stmf_trace("pppt", "Session close %p", (void *)ps);

	ASSERT(mutex_owned(&pppt_global.global_lock));
	ASSERT(mutex_owned(&tgt->target_mutex));
	//ASSERT(mutex_owned(&ps->ps_mutex));
	ASSERT(!ps->ps_closed); /* Caller should ensure session is not closed */
	ps->ps_closed = B_TRUE;
	num = stmf_find_and_abort_task(ps->ps_stmf_sess);
	
	/*
	 * Now that all the tasks are aborting the session refcnt should
	 * go to 0.
	 */
	
	/*
	while (ps->ps_refcnt != 0) {
		cv_wait(&ps->ps_cv, &ps->ps_mutex);
    }
    */
      
    for (i = 0; i < pppt_session_clear_time; i++){
		num = stmf_find_session_tasks(ps->ps_stmf_sess);
		if (num != 0) {
			cmn_err(CE_WARN, "%s  ps = %p not released tasks=%d refcnt=%d",
				__func__, ps, num, ps->ps_refcnt);
			stmf_find_and_abort_task(ps->ps_stmf_sess);
		}
		else if (ps->ps_refcnt == 0)
			break;
		
		delay(100);
    }

	if (num != 0)
		cmn_err(CE_PANIC, " session %p tasks %d refcnt=%d not released timeout",
			ps, num, ps->ps_refcnt);

	avl_remove(&tgt->target_sess_list, ps);
	avl_remove(&pppt_global.global_sess_list, ps);
	(void) taskq_dispatch(pppt_global.global_sess_taskq,
	    &pppt_sess_destroy_task, ps, KM_SLEEP);

	stmf_trace("pppt", "Session close complete %p", (void *)ps);
}

pppt_buf_t *
pppt_pbuf_alloc(void)
{
	pppt_buf_t *pbuf = NULL;
	stmf_data_buf_t *sbuf;

	pbuf = kmem_alloc(sizeof(pppt_buf_t), KM_SLEEP);
	if (pbuf != NULL) {
		sbuf = kmem_alloc(sizeof(stmf_data_buf_t), KM_SLEEP);
		if (sbuf == NULL) {
			kmem_free(pbuf, sizeof(pppt_buf_t));
			goto FINISH;
		}
	
		bzero(pbuf, sizeof(pppt_buf_t));
		bzero(sbuf, sizeof(stmf_data_buf_t));
		pbuf->pbuf_is_immed = B_FALSE;
		pbuf->pbuf_immed_msg = NULL;
		pbuf->pbuf_stmf_buf = sbuf;
		pbuf->pbuf_stmf_buf->db_port_private = pbuf;
		pbuf->pbuf_stmf_buf->db_flags = DB_DIRECTION_FROM_RPORT |
		    DB_DONT_CACHE;			/*?????*/
		pbuf->pbuf_stmf_buf->db_sglist_length = 1;
	} else {
		cmn_err(CE_WARN, "%s: mem alloc failed", __func__);
	}

FINISH:
	return (pbuf);
}

pppt_task_t *
pppt_task_alloc(void)
{
	pppt_task_t	*ptask;

	ptask = kmem_alloc(sizeof (pppt_task_t), KM_NOSLEEP);
	if (ptask != NULL) {
		ptask->pt_state = PTS_INIT;
		ptask->pt_read_buf = NULL;
		ptask->pt_read_xfer_msgid = 0;
		ptask->pt_refcnt = 0;
		
		mutex_init(&ptask->pt_mutex, NULL, MUTEX_DRIVER, NULL);
	}
	return (ptask);

}

void
pppt_task_free(pppt_task_t *ptask)
{
	mutex_enter(&ptask->pt_mutex);
	//ptask->pt_refcnt--;
	
	mutex_exit(&ptask->pt_mutex);

	mutex_enter(&ptask->pt_mutex);
	/* make sure pppt task is freed */
	if(ptask->pt_refcnt != 0){
		cmn_err(CE_WARN,   "%s  ptask = %p refcnt=%d ",__func__, (void *)ptask,ptask->pt_refcnt);
	}
	
	mutex_destroy(&ptask->pt_mutex);
	kmem_free(ptask->pt_pbufs->pbuf_stmf_buf, sizeof(stmf_data_buf_t));
	kmem_free(ptask->pt_pbufs, sizeof(pppt_buf_t));
	kmem_free(ptask, sizeof (pppt_task_t));
}

static int
pppt_task_avl_compare(const void *void_task1, const void *void_task2)
{
	const pppt_task_t	*ptask1 = void_task1;
	const pppt_task_t	*ptask2 = void_task2;

	if (ptask1->pt_task_id < ptask2->pt_task_id)
		return (-1);
	else if (ptask1->pt_task_id > ptask2->pt_task_id)
		return (1);

	return (0);
}

module_init(pppt_init);
module_exit(pppt_fini);

MODULE_DESCRIPTION("STMF implementation");
MODULE_AUTHOR(ZFS_META_AUTHOR);
MODULE_LICENSE(ZFS_META_LICENSE);
MODULE_VERSION(ZFS_META_VERSION "-" ZFS_META_RELEASE);
