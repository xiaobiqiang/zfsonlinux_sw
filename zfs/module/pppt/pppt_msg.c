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
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>

/* #include <sys/socket.h> */
/* #include <sys/strsubr.h> */
/* #include <sys/door.h> */

#include <sys/cmn_err.h>
#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/lpif.h>

/* #include <sys/scsi/scsi.h> */

#include "pppt.h"
#include "alua_ic_xdr.h"

static void pppt_msg_tgt_register(stmf_ic_msg_t *reg_port);

static void pppt_msg_tgt_deregister(stmf_ic_msg_t *msg);

static void pppt_msg_session_destroy(stmf_ic_msg_t *msg);

static void pppt_msg_scsi_cmd(stmf_ic_msg_t *msg);

static void pppt_msg_data_xfer_done(stmf_ic_msg_t *msg);

static void pppt_msg_handle_status(stmf_ic_msg_t *msg);

static void pppt_msg_data_res(stmf_ic_msg_t *msg);

void
pppt_msg_rx(stmf_ic_msg_t *msg)
{
	void *sess = msg->icm_sess;

	switch (msg->icm_msg_type) {
	case STMF_ICM_REGISTER_PROXY_PORT:
		pppt_msg_tgt_register(msg);
		break;
	case STMF_ICM_DEREGISTER_PROXY_PORT:
		pppt_msg_tgt_deregister(msg);
		break;
	case STMF_ICM_SESSION_CREATE:
		pppt_msg_tx_status(msg, STMF_NOT_SUPPORTED);
		stmf_ic_msg_free(msg);
		break;
	case STMF_ICM_SESSION_DESTROY:
		pppt_msg_session_destroy(msg);
		break;
	case STMF_ICM_SCSI_CMD:
		pppt_msg_scsi_cmd(msg);
		break;
	case STMF_ICM_SCSI_DATA_XFER_DONE:
		pppt_msg_data_xfer_done(msg);
		break;
	case STMF_ICM_SCSI_DATA_RES:
		pppt_msg_data_res(msg);
		break;
#if 0
	case STMF_ICM_SCSI_DATA:
		/* Ignore, all proxy data will be immediate for now */
		pppt_msg_tx_status(msg, STMF_NOT_SUPPORTED);
		stmf_ic_msg_free(msg);
		break;
	case STMF_ICM_STATUS:
		pppt_msg_handle_status(msg);
		break;
#endif
	default:
		/* Other message types are not allowed */
		ASSERT(0);
		break;
	}

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	if ((sess != NULL) && (sess != PPPT_BROADCAST_SESS)) {
		stmf_ic_csh_rele(sess, "ic_rx_msg");
	}
#endif
}

void
pppt_msg_tx_status(stmf_ic_msg_t *orig_msg, stmf_status_t status)
{
	stmf_ic_msg_t	*msg;

	/*
	 * If TX of status fails it should be treated the same as a loss of
	 * connection.  We expect the remote node to handle it.
	 */
	msg = stmf_ic_status_msg_alloc(status, orig_msg->icm_msg_type,
	    orig_msg->icm_msgid);

	if (msg != NULL) {
		msg->icm_sess = orig_msg->icm_sess;
		(void) stmf_ic_tx_msg(msg);
	}
}

static void
pppt_msg_tgt_register(stmf_ic_msg_t *msg)
{
	stmf_ic_reg_port_msg_t	*reg_port;
	pppt_tgt_t		*result;
	stmf_status_t		stmf_status;
	void *new, *old;

	reg_port = msg->icm_msg;

	PPPT_GLOBAL_LOCK();
	if (pppt_global.global_svc_state != PSS_ENABLED) {
		stmf_status = STMF_FAILURE;
		PPPT_INC_STAT(es_tgt_reg_svc_disabled);
		goto pppt_register_tgt_done;
	}

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	if (msg->icm_sess != NULL)
		stmf_ic_csh_hold(msg->icm_sess, "tgt_reg");
#endif
	/*
	 * For now we assume that the marshall/unmarshall code is responsible
	 * for validating the message length and ensuring the resulting
	 * request structure is self consistent.  Make sure this
	 * target doesn't already exist.
	 */
	if ((result = pppt_tgt_lookup_locked(reg_port->icrp_port_id)) != NULL) {
#if 0
		stmf_status = STMF_ALREADY;
#else
		stmf_status = STMF_SUCCESS;
#endif
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		do {
			old = result->target_psess;
			new = msg->icm_sess;
		} while(atomic_cas_ptr(&result->target_psess, old, new) != old);
		stmf_ic_csh_rele(old, "tgt_reg");
#endif
		cmn_err(CE_WARN,   "%s  icrp_port_id is lookuped",__func__);

		PPPT_INC_STAT(es_tgt_reg_duplicate);
		goto pppt_register_tgt_done;
	}

	result = pppt_tgt_create(reg_port, &stmf_status);

	if (result == NULL) {
		stmf_status = STMF_TARGET_FAILURE;
		PPPT_INC_STAT(es_tgt_reg_create_fail);
		goto pppt_register_tgt_done;
	}
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	do {
		old = result->target_psess;
		new = msg->icm_sess;
	} while(atomic_cas_ptr(&result->target_psess, old, new) != old);
	stmf_ic_csh_rele(old, "tgt_reg");
#endif
	avl_add(&pppt_global.global_target_list, result);

	stmf_status = STMF_SUCCESS;

pppt_register_tgt_done:
	PPPT_GLOBAL_UNLOCK();
	pppt_msg_tx_status(msg, stmf_status);
	stmf_ic_msg_free(msg);
}

static void
pppt_msg_tgt_deregister(stmf_ic_msg_t *msg)
{
	stmf_ic_dereg_port_msg_t	*dereg_port;
	stmf_status_t			stmf_status;
	pppt_tgt_t			*tgt;

	PPPT_GLOBAL_LOCK();
	if (pppt_global.global_svc_state != PSS_ENABLED) {
		PPPT_GLOBAL_UNLOCK();
		stmf_status = STMF_FAILURE;
		PPPT_INC_STAT(es_tgt_dereg_svc_disabled);
		goto pppt_deregister_tgt_done;
	}

	dereg_port = msg->icm_msg;

	/* Lookup target */
	if ((tgt = pppt_tgt_lookup_locked(dereg_port->icdp_port_id)) == NULL) {
		PPPT_GLOBAL_UNLOCK();
		stmf_status = STMF_NOT_FOUND;
		PPPT_INC_STAT(es_tgt_dereg_not_found);
		goto pppt_deregister_tgt_done;
	}
	avl_remove(&pppt_global.global_target_list, tgt);
	pppt_tgt_async_delete(tgt);

	PPPT_GLOBAL_UNLOCK();

	/* Wait for delete to complete */
	mutex_enter(&tgt->target_mutex);
	while ((tgt->target_refcount > 0) ||
	    (tgt->target_state != TS_DELETING)) {
		cv_wait(&tgt->target_cv, &tgt->target_mutex);
	}
	mutex_exit(&tgt->target_mutex);

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	if ((tgt->target_psess != NULL) &&
		(tgt->target_psess != PPPT_BROADCAST_SESS)) {
		stmf_ic_csh_rele(tgt->target_psess, "tgt_reg");
	}
#endif

	pppt_tgt_destroy(tgt);
	stmf_status = STMF_SUCCESS;

pppt_deregister_tgt_done:
	pppt_msg_tx_status(msg, stmf_status);
	stmf_ic_msg_free(msg);
}

static void
pppt_msg_session_destroy(stmf_ic_msg_t *msg)
{
	stmf_ic_session_create_destroy_msg_t	*sess_destroy;
	pppt_tgt_t				*tgt;
	pppt_sess_t				*ps;

	sess_destroy = msg->icm_msg;

	PPPT_GLOBAL_LOCK();

	/*
	 * Look for existing session for this ID
	 */
	ps = pppt_sess_lookup_locked(sess_destroy->icscd_session_id,
	    sess_destroy->icscd_tgt_devid, sess_destroy->icscd_rport);

	if (ps == NULL) {
		PPPT_GLOBAL_UNLOCK();
		stmf_ic_msg_free(msg);
		PPPT_INC_STAT(es_sess_destroy_no_session);
		return;
	}

	tgt = ps->ps_target;

	mutex_enter(&tgt->target_mutex);
	mutex_enter(&ps->ps_mutex);

	/* Release the reference from the lookup */
	pppt_sess_rele_locked(ps);
	mutex_exit(&ps->ps_mutex);
	
	/* Make sure another thread is not already closing the session */
	if (!ps->ps_closed) {
		/* Found matching open session, quiesce... */
		pppt_sess_close_locked(ps);
	}
	
	mutex_exit(&tgt->target_mutex);
	PPPT_GLOBAL_UNLOCK();

	stmf_ic_msg_free(msg);
}

static void
pppt_msg_scsi_cmd(stmf_ic_msg_t *msg)
{
	pppt_sess_t			*pppt_sess;
	pppt_buf_t			*pbuf;
	stmf_ic_scsi_cmd_msg_t		*scmd;
	pppt_task_t			*ptask;
	scsi_task_t			*task;
	stmf_local_port_t		*lport;
	stmf_scsi_session_t		*stmf_sess;
	stmf_status_t			stmf_status;
	int err;
	int lun_no;

	scmd = msg->icm_msg;

	/*
	 * Get a task context
	 */
	ptask = pppt_task_alloc();
	if (ptask == NULL) {
		/*
		 * We must be very low on memory.  Just free the message
		 * and let the command timeout.
		 */
		stmf_ic_msg_free(msg);
		PPPT_INC_STAT(es_scmd_ptask_alloc_fail);
		return;
	} else {
		pbuf = pppt_pbuf_alloc();
		if (pbuf == NULL) {
			cmn_err(CE_WARN, "%s: pbuf alloc failed, free ptask and msg", __func__);
			pppt_task_free(ptask);
			stmf_ic_msg_free(msg);
			return;
		}

		ptask->pt_pbufs = pbuf;
	}

	/*
	 * Session are created implicitly on the first use of an
	 * IT nexus
	 */
	pppt_sess = pppt_sess_lookup_create(scmd->icsc_tgt_devid,
	    scmd->icsc_ini_devid, scmd->icsc_rport,
	    scmd->icsc_session_id, &stmf_status);
	if (pppt_sess == NULL) {
		pppt_task_free(ptask);
		pppt_msg_tx_status(msg, stmf_status);
		stmf_ic_msg_free(msg);
		PPPT_INC_STAT(es_scmd_sess_create_fail);
		return;
	}

	ptask->pt_sess = pppt_sess;
	ptask->pt_task_id = scmd->icsc_task_msgid;
	ptask->pt_task_proxy_seq_no = 0;
	stmf_sess = pppt_sess->ps_stmf_sess;
	lport = stmf_sess->ss_lport;

	/*
	 * Allocate STMF task context
	 */
	err = stmf_get_lun_id(stmf_sess, scmd->icsc_lun_id, &lun_no);
	if (err == 0) {
		scmd->icsc_task_lun_no[1] = (uint8_t) lun_no;
	}

	ptask->pt_stmf_task = stmf_task_alloc(lport, stmf_sess,
	    scmd->icsc_task_lun_no,
	    scmd->icsc_task_cdb_length, (uint64_t)scmd->icsc_task_msgid);
	if (ptask->pt_stmf_task == NULL) {
		/* MATIS-2776 */
        	pppt_task_free(ptask);
		pppt_sess_rele(pppt_sess);
		pppt_msg_tx_status(msg, STMF_ALLOC_FAILURE);
		stmf_ic_msg_free(msg);
		PPPT_INC_STAT(es_scmd_stask_alloc_fail);
		return;
	}

	task = ptask->pt_stmf_task;
	
        /* task_port_private reference is a real reference. */
	task->task_port_private = ptask;
	task->task_flags = scmd->icsc_task_flags;
	task->task_additional_flags = TASK_PPPT_LU_DBUF;
	task->task_priority = 0;

	/*
	 * Set task->task_mgmt_function to TM_NONE for a normal SCSI task
	 * or one of these values for a task management command:
	 *
	 * TM_ABORT_TASK ***
	 * TM_ABORT_TASK_SET
	 * TM_CLEAR_ACA
	 * TM_CLEAR_TASK_SET
	 * TM_LUN_RESET
	 * TM_TARGET_WARM_RESET
	 * TM_TARGET_COLD_RESET
	 *
	 * *** Note that STMF does not currently support TM_ABORT_TASK so
	 * port providers must implement this command on their own
	 * (e.g. lookup the desired task and call stmf_abort).
	 */
	task->task_mgmt_function = scmd->icsc_task_mgmt_function;

	task->task_max_nbufs = 1; /* Don't allow parallel xfers */
	task->task_cmd_seq_no = msg->icm_msgid;
	task->task_expected_xfer_length = scmd->icsc_task_expected_xfer_length;

	if (scmd->icsc_task_cdb_length) {
		bcopy(scmd->icsc_task_cdb, task->task_cdb,
		    scmd->icsc_task_cdb_length);
	}
	bcopy(scmd->icsc_lun_id, ptask->pt_lun_id, 16);

	if (scmd->icsc_immed_data_len) {
		pbuf->pbuf_is_immed = B_TRUE;
		pbuf->pbuf_immed_msg = msg;
		pbuf->pbuf_stmf_buf->db_data_size = scmd->icsc_immed_data_len;
		pbuf->pbuf_stmf_buf->db_buf_size = scmd->icsc_immed_data_len;
		pbuf->pbuf_stmf_buf->db_relative_offset = scmd->icsc_db_relative_offset;
		pbuf->pbuf_stmf_buf->db_sglist[0].seg_length =
		    scmd->icsc_immed_data_len;
		pbuf->pbuf_stmf_buf->db_sglist[0].seg_addr =
		    scmd->icsc_immed_data;

		task->task_flags |= TF_INITIAL_BURST;
		stmf_post_task(task, pbuf->pbuf_stmf_buf);
	} else {
		stmf_post_task(task, NULL);
		stmf_ic_msg_free(msg);
	}
}

static void
pppt_msg_data_xfer_done(stmf_ic_msg_t *msg)
{
	pppt_task_t				*pppt_task;
	stmf_ic_scsi_data_xfer_done_msg_t	*data_xfer_done;
	scsi_task_t *task;

	data_xfer_done = msg->icm_msg;

	/* pppt_task_lookup(data_xfer_done->icsx_task_msgid); */
	task = stmf_find_and_hold_task(msg->icm_guid, msg->icm_msgid);	
	if (!task) {
		cmn_err(CE_WARN, "%s: task is not found,msgid=%ld",	__func__,(long)msg->icm_msgid);
	}
	else{	
		pppt_task = task->task_port_private;
		/* If we found one, complete the transfer */
		if (pppt_task != NULL) {
			pppt_task->pt_task_proxy_seq_no = data_xfer_done->icsx_proxy_seq_no;
			pppt_xfer_read_complete(pppt_task, data_xfer_done->icsx_status);
		}
	}
	stmf_ic_msg_free(msg);
}

static void
pppt_msg_data_res(stmf_ic_msg_t *msg)
{
	pppt_task_t *ptask;
	stmf_ic_scsi_data_res_msg_t *data_res;
	pppt_buf_t *pbuf;
	stmf_data_buf_t *dbuf;
	scsi_task_t *task;

	data_res = msg->icm_msg;

	/* task = find_task_from_msgid(msg->icsq_lun_id, msg->icsq_task_msgid); */
	task = stmf_find_and_hold_task(msg->icm_guid, msg->icm_msgid);	
	if (!task) {
		cmn_err(CE_WARN, "%s: task is not found,msgid=%ld", __func__,(long)msg->icm_msgid);
		goto out;
	}
	
	ptask = task->task_port_private;
	ptask->pt_task_proxy_seq_no = data_res->icds_proxy_seq_no;
	pbuf = ptask->pt_write_buf;
	if(pbuf==NULL){
		cmn_err(CE_WARN, "%s: Wrong data from peer. pbuf is null", 	__func__);
		goto out;
	}
	
	dbuf = pbuf->pbuf_stmf_buf;
	/* Rest pt_write_buf after we pass current pbuf to stmf */
	ptask->pt_write_buf = NULL;

	if ((dbuf->db_data_size != data_res->icds_data_len) ||
		(dbuf->db_relative_offset != data_res->icds_data_offset)) {
		cmn_err(CE_WARN, "%s: Wrong data from peer. expected: offset=%u, size=%u, received: offset=%u, size=%u",
		       	__func__, dbuf->db_relative_offset, dbuf->db_data_size,
			data_res->icds_data_offset, data_res->icds_data_len);
		dbuf->db_xfer_status = STMF_FAILURE;
	} else {
		bcopy(data_res->icds_data, dbuf->db_sglist[0].seg_addr,
			data_res->icds_data_len);

		dbuf->db_data_size = data_res->icds_data_len;
		dbuf->db_buf_size = data_res->icds_data_len;
		
		//dbuf->db_sglist[0].seg_length = data_res->icds_data_len;
		//dbuf->db_flags |= (DB_LPORT_XFER_ACTIVE | DB_WRITE_FROM_PPPT);
	
	}

	stmf_data_xfer_done(ptask->pt_stmf_task, dbuf, 0);
out:
	stmf_ic_msg_free(msg);
}

static void
pppt_msg_handle_status(stmf_ic_msg_t *msg)
{
	/* Don't care for now */
	stmf_ic_msg_free(msg);
}
