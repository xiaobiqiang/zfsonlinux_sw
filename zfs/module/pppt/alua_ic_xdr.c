/*
 * Copyright 2012 Ceresdata, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
 #include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
/* #include <sys/scsi/scsi.h> */
#include <sys/scsi/generic/persist.h>
#include <sys/byteorder.h>
#include <sys/nvpair.h>
#include <sys/cmn_err.h>
/* #include <sys/door.h> */

#include <sys/stmf.h>
#include <sys/lpif.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/pppt_ic_if.h>
#include <sys/modctl.h>
#include <sys/disp.h>
#include <sys/systeminfo.h>
/* #include <sys/filio.h> */
#include <sys/callb.h>
/* #include <inet/tcp.h> */
#include "pppt.h"
#include "alua_ic_xdr.h"

#define aluanametoolong	((char *)-1)

bool_t
xdr_string_alua(XDR *xdrs, char **cpp, uint_t maxsize)
{
	char *sp;
	uint_t size;
	uint_t nodesize;
	bool_t mem_alloced = FALSE;

	/*
	 * first deal with the length since xdr strings are counted-strings
	 */
	sp = *cpp;
	switch (xdrs->x_op) {
	case XDR_FREE:
		if (sp == NULL || sp == aluanametoolong)
			return (TRUE);	/* already free */
		/* FALLTHROUGH */

	case XDR_ENCODE:
		size = (uint_t)strlen(sp);
		break;

	case XDR_DECODE:
		break;
	}

	if (!xdr_u_int(xdrs, &size))
		return (FALSE);

	/*
	 * now deal with the actual bytes
	 */
	switch (xdrs->x_op) {
	case XDR_DECODE:
		if (size >= maxsize) {
			*cpp = aluanametoolong;
			if (!xdr_control(xdrs, XDR_SKIPBYTES, &size))
				return (FALSE);
			return (TRUE);
		}
		nodesize = size + 1;
		if (nodesize == 0)
			return (TRUE);
		if (sp == NULL) {
			sp = kmem_alloc(nodesize, KM_NOSLEEP);
			*cpp = sp;
			if (sp == NULL)
				return (FALSE);
			mem_alloced = TRUE;
		}
		sp[size] = 0;

		if (xdr_opaque(xdrs, sp, size)) {
			if (strlen(sp) != size) {
				if (mem_alloced)
					kmem_free(sp, nodesize);
				*cpp = NULL;
				return (FALSE);
			}
		} else {
			if (mem_alloced)
				kmem_free(sp, nodesize);
			*cpp = NULL;
			return (FALSE);
		}
		return (TRUE);

	case XDR_ENCODE:
		return (xdr_opaque(xdrs, sp, size));

	case XDR_FREE:
		nodesize = size + 1;
		kmem_free(sp, nodesize);
		*cpp = NULL;
		return (TRUE);
	}

	return (FALSE);
}

scsi_devid_desc_t *
xdr_ic_scsi_devid_unmarshal(XDR *xdrs)
{
	scsi_devid_desc_t *sdid = NULL;
	uchar_t value = 0;
	size_t sdid_size;

	if (!xdr_u_char(xdrs, &value))
		return (NULL);

	sdid_size = sizeof_scsi_devid_desc(value);

	sdid = kmem_zalloc(sdid_size, KM_SLEEP);

	sdid->ident_length = value;
	
	if (!xdr_u_char(xdrs, &value))
		return (B_FALSE);
	sdid->protocol_id = value;

	if (!xdr_u_char(xdrs, &value))
		return (B_FALSE);
	sdid->code_set = value;

	if (!xdr_u_char(xdrs, &value))
		return (B_FALSE);
	sdid->piv = value;
		
	if (!xdr_u_char(xdrs, &value))
		return (B_FALSE);
	sdid->association = value;
		
	if (!xdr_u_char(xdrs, &value))
		return (B_FALSE);
	sdid->ident_type = value;

	if (!xdr_opaque(xdrs, (char *)sdid->ident,  sdid->ident_length))
		return (B_FALSE);

	return (sdid);
}

boolean_t
xdr_ic_scsi_devid_marshal(XDR *xdrs, scsi_devid_desc_t *devid)
{
	uchar_t	value = 0;
	
	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);

	if (!xdr_u_char(xdrs, (uchar_t *)&devid->ident_length))
		return (B_FALSE);
	
	value = devid->protocol_id;
	if (!xdr_u_char(xdrs, &value))
		return (B_FALSE);

	value = devid->code_set;
	if (!xdr_u_char(xdrs, &value))
		return (B_FALSE);

	value = devid->piv;
	if (!xdr_u_char(xdrs, &value))
		return (B_FALSE);

	value = devid->association;
	if (!xdr_u_char(xdrs, &value))
		return (B_FALSE);

	value = devid->ident_type;
	if (!xdr_u_char(xdrs, &value))
		return (B_FALSE);

	if (!xdr_opaque(xdrs, (char *)devid->ident,  devid->ident_length))
		return (B_FALSE);
	
	return (B_TRUE);
}

stmf_remote_port_t *
xdr_ic_remote_port_unmarshal(XDR *xdrs)
{
	ushort_t value = 0;
	stmf_remote_port_t *rport = NULL;

	if (!xdr_u_short(xdrs, &value)) {
		cmn_err(CE_WARN, "%s: test1 value = %u\n", __func__, value);
		return (NULL);
	}

	if (value < sizeof(scsi_transport_id_t)) {
		cmn_err(CE_WARN, "%s: test2, sz:%u\n", __func__, value);	
		return (NULL);
	}

	rport = stmf_remote_port_alloc(value);
	rport->rport_tptid_sz = value;

#if 0
	cmn_err(CE_WARN, "%s:r sz:%u, value:%u", __func__,
	    rport->rport_tptid_sz, value);
#endif

	if (!xdr_opaque(xdrs, (char *)rport->rport_tptid, rport->rport_tptid_sz)) {
		cmn_err(CE_WARN, "%s: rport failed, sz:%d", __func__, (int) rport->rport_tptid_sz);
		stmf_remote_port_free(rport);
		return (NULL);
	}

	return (rport);
}

boolean_t
xdr_ic_remote_port_marshal(XDR *xdrs, stmf_remote_port_t *rport)
{
	boolean_t rc = B_TRUE;

	if (!xdr_u_short(xdrs, &rport->rport_tptid_sz))
		return (B_FALSE);

	rc = xdr_opaque(xdrs, (char *)rport->rport_tptid, rport->rport_tptid_sz);

	return (rc);
}

boolean_t
xdr_ic_reg_port_msg(XDR *xdrs,  void *msg)
{
	boolean_t rc = B_TRUE;
	stmf_ic_reg_port_msg_t *m = (stmf_ic_reg_port_msg_t *)msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);

	if (xdrs->x_op == XDR_ENCODE) {
		if (!xdr_ic_scsi_devid_marshal(xdrs, m->icrp_port_id))
			return (B_FALSE);
	} else {
		m->icrp_port_id = xdr_ic_scsi_devid_unmarshal(xdrs);
		if (m->icrp_port_id == NULL) {
			return (B_FALSE);
		}
	}

	if (!xdr_u_int(xdrs, &m->icrp_local_hostid))
		return (B_FALSE);

	if (!xdr_u_short(xdrs, &m->icrp_relative_port_id))
		return (B_FALSE);

	if (!xdr_u_short(xdrs, &m->icrp_cb_arg_len))
		return (B_FALSE);

	if (m->icrp_cb_arg_len) {
		if (xdrs->x_op == XDR_DECODE)
			m->icrp_cb_arg = kmem_zalloc(m->icrp_cb_arg_len, KM_SLEEP);
		rc = xdr_opaque(xdrs, (char *)m->icrp_cb_arg, m->icrp_cb_arg_len);
	}

	return (rc);
}

boolean_t
xdr_ic_dereg_port_msg(XDR *xdrs, void *msg)
{
	boolean_t rc = B_TRUE;
	stmf_ic_dereg_port_msg_t *m = (stmf_ic_dereg_port_msg_t *)msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);

	if (xdrs->x_op == XDR_ENCODE) {
		if (!xdr_ic_scsi_devid_marshal(xdrs, m->icdp_port_id)) {
			return (B_FALSE);
		} 
	} else {
		m->icdp_port_id = xdr_ic_scsi_devid_unmarshal(xdrs);
		if (m->icdp_port_id == NULL) {
			cmn_err(CE_WARN, "%s: port id failed", __func__);
			return (B_FALSE);
		}
	}
		
	if (!xdr_u_short(xdrs, &m->icdp_cb_arg_len))
		return (B_FALSE);

	if (m->icdp_cb_arg_len) {
		if (xdrs->x_op == XDR_DECODE)
			m->icdp_cb_arg = kmem_zalloc(m->icdp_cb_arg_len, KM_SLEEP);
		rc = xdr_opaque(xdrs, (char *)m->icdp_cb_arg, m->icdp_cb_arg_len);
	}

	return (rc);
}

boolean_t
xdr_ic_reg_dereg_lun_msg(XDR *xdrs, void *msg)
{
	boolean_t rc = B_TRUE;
	stmf_ic_reg_dereg_lun_msg_t *m = (stmf_ic_reg_dereg_lun_msg_t *)msg;

	if (!xdr_opaque(xdrs, (char *)m->icrl_lun_id, 16))
		return (B_FALSE);

	if (!xdr_opaque(xdrs, (char *)m->icrl_serial_no, 32))
		return (B_FALSE);
	
	if (!xdr_string_alua(xdrs, &m->icrl_lu_provider_name, MAXNAMELEN))
		return (B_FALSE);

	if (!xdr_u_short(xdrs, &m->icrl_cb_arg_len))
		return (B_FALSE);

	if (m->icrl_cb_arg_len) {
		if (xdrs->x_op == XDR_DECODE)
			m->icrl_cb_arg = kmem_zalloc(m->icrl_cb_arg_len, KM_SLEEP);
		rc = xdr_opaque(xdrs, (char *)m->icrl_cb_arg, m->icrl_cb_arg_len);
	}

	return (rc);
}

boolean_t
xdr_ic_scsi_cmd_msg(XDR *xdrs, void *msg)
{
	boolean_t rc = B_TRUE;
	stmf_ic_scsi_cmd_msg_t *m = (stmf_ic_scsi_cmd_msg_t *)msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);

	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icsc_task_msgid))
		return (B_FALSE);

	if (xdrs->x_op == XDR_ENCODE) {
		if (!xdr_ic_scsi_devid_marshal(xdrs, m->icsc_ini_devid))
			return (B_FALSE);

		if (!xdr_ic_scsi_devid_marshal(xdrs, m->icsc_tgt_devid))
		    	return (B_FALSE);
	} else {
		m->icsc_ini_devid = xdr_ic_scsi_devid_unmarshal(xdrs);
		if (m->icsc_ini_devid == NULL) {
			cmn_err(CE_WARN, "%s: ini devid failed", __func__);
			return (B_FALSE);
		}

		m->icsc_tgt_devid = xdr_ic_scsi_devid_unmarshal(xdrs);
		if (m->icsc_tgt_devid == NULL) {
			cmn_err(CE_WARN, "%s: tgt devid failed", __func__);
			return (B_FALSE);
		}
	}

	if (xdrs->x_op == XDR_DECODE) {
		m->icsc_rport = xdr_ic_remote_port_unmarshal(xdrs);
		if (m->icsc_rport == NULL) {
			cmn_err(CE_WARN, "%s: rpot failed", __func__);
			return (B_FALSE);
		}
	} else {
		if (!xdr_ic_remote_port_marshal(xdrs, m->icsc_rport) )
			return (B_FALSE);
	}

	if (!xdr_opaque(xdrs, (char *)m->icsc_lun_id, 16))
		return (B_FALSE);
	
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icsc_session_id) ||
	    !xdr_opaque(xdrs, (char *)m->icsc_task_lun_no, 8) ||
	    !xdr_u_int(xdrs, &m->icsc_task_expected_xfer_length))
	    	return (B_FALSE);
	
	if (!xdr_u_short(xdrs, &m->icsc_task_cdb_length))
		return (B_FALSE);

	if (xdrs->x_op == XDR_DECODE)
		m->icsc_task_cdb = kmem_zalloc(m->icsc_task_cdb_length, KM_SLEEP);

	if (!xdr_opaque(xdrs, (char *)m->icsc_task_cdb, m->icsc_task_cdb_length))
		return (B_FALSE);
			
	if (!xdr_u_char(xdrs, &m->icsc_task_flags) ||
	    !xdr_u_char(xdrs, &m->icsc_task_priority) ||
	    !xdr_u_char(xdrs, &m->icsc_task_mgmt_function) ||
	    !xdr_u_int(xdrs, &m->icsc_db_relative_offset) ||
	    !xdr_u_int(xdrs, (uint_t *)&m->icsc_immed_data_len))
		return (B_FALSE);

	if (m->icsc_immed_data_len) {
		if (xdrs->x_op == XDR_DECODE)
			m->icsc_immed_data = kmem_zalloc(m->icsc_immed_data_len, KM_SLEEP);
		rc = xdr_opaque(xdrs, (char *)m->icsc_immed_data, m->icsc_immed_data_len);
	}

	return (rc);
}

boolean_t
xdr_ic_scsi_data_msg(XDR *xdrs, void *msg)
{
	stmf_ic_scsi_data_msg_t *m = (stmf_ic_scsi_data_msg_t *)msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);
		
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icsd_task_msgid) ||
	    !xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icsd_session_id) ||
	    !xdr_opaque(xdrs, (char *)m->icsd_lun_id, 16) ||
	    !xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icsd_data_len) ||
	    !xdr_u_char(xdrs, (uchar_t *)&m->final_xfer))
	    	return (B_FALSE);

	if (xdrs->x_op == XDR_DECODE) {
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		m->icsd_data = stmf_ic_kmem_zalloc(m->icsd_data_len, KM_SLEEP);
#else
		m->icsd_data = kmem_zalloc(m->icsd_data_len, KM_SLEEP);
#endif
	}
	
	if (!xdr_opaque(xdrs, (char *)m->icsd_data, m->icsd_data_len))
	    	return (B_FALSE);

	return (B_TRUE);
}

boolean_t
xdr_ic_scsi_data_req_msg(XDR *xdrs, void *msg)
{
	stmf_ic_scsi_data_req_msg_t *m =
		(stmf_ic_scsi_data_req_msg_t *)msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);

	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icsq_task_msgid) ||
	    !xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icsq_session_id) ||
	    !xdr_opaque(xdrs, (char *)m->icsq_lun_id, 16) ||
	    !xdr_u_int(xdrs, &m->icsq_offset) ||
	    !xdr_u_int(xdrs, &m->icsq_len))
		return (B_FALSE);

	return (B_TRUE);
}

boolean_t
xdr_ic_scsi_data_res_msg(XDR *xdrs, void *msg)
{
	stmf_ic_scsi_data_res_msg_t *m = (stmf_ic_scsi_data_res_msg_t *)msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);

	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icds_task_msgid) ||
	    !xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icds_session_id) ||
	    !xdr_u_int(xdrs, &m->icds_data_offset) ||
	    !xdr_u_int(xdrs, &m->icds_data_len))
		return (B_FALSE);

	if (xdrs->x_op == XDR_DECODE) {
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		m->icds_data = stmf_ic_kmem_zalloc(m->icds_data_len, KM_SLEEP);
#else
		m->icds_data = kmem_zalloc(m->icds_data_len, KM_SLEEP);
#endif
	}
	
	if (!xdr_opaque(xdrs, (char *)m->icds_data, m->icds_data_len))
		return (B_FALSE);

	return (B_TRUE);
}

boolean_t
xdr_ic_scsi_data_xfer_done_msg(XDR *xdrs, void *msg)
{
	stmf_ic_scsi_data_xfer_done_msg_t *m =
	    (stmf_ic_scsi_data_xfer_done_msg_t *)msg;

	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icsx_task_msgid) ||
	    !xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icsx_session_id) ||
	    !xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icsx_status))
	    	return (B_FALSE);
	
	return (B_TRUE);
}

boolean_t
xdr_ic_scsi_status_msg(XDR *xdrs, void *msg)
{
	boolean_t rc = B_TRUE;
	stmf_ic_scsi_status_msg_t *m = (stmf_ic_scsi_status_msg_t *)msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);

	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icss_task_msgid) ||
	    !xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icss_session_id) ||
	    !xdr_opaque(xdrs, (char *)m->icss_lun_id, 16) ||
	    !xdr_u_char(xdrs, &m->icss_response) ||
	    !xdr_u_char(xdrs, &m->icss_status) ||
	    !xdr_u_char(xdrs, &m->icss_flags) ||
	    !xdr_u_int(xdrs, (uint_t *)&m->icss_resid) ||
	    !xdr_u_char(xdrs, &m->icss_sense_len))
	    	return (B_FALSE);

	if (m->icss_sense_len)
		if (xdrs->x_op == XDR_DECODE)
			m->icss_sense = kmem_zalloc(m->icss_sense_len, KM_SLEEP);
		rc = xdr_opaque(xdrs, (char *)m->icss_sense, m->icss_sense_len);

	return (rc);
}

boolean_t
xdr_ic_r2t_msg(XDR *xdrs, void *msg)
{
	stmf_ic_r2t_msg_t *m = (stmf_ic_r2t_msg_t *)msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);
		
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icrt_task_msgid) ||
	    !xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icrt_session_id) ||
	    !xdr_u_int(xdrs, (uint_t *)&m->icrt_offset) ||
	    !xdr_u_int(xdrs, (uint_t *)&m->icrt_length))
	   	return (B_FALSE);
	
	return (B_TRUE);
}

boolean_t
xdr_ic_status_msg(XDR *xdrs, void *msg)
{
	stmf_ic_status_msg_t *m = (stmf_ic_status_msg_t *)msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);
		
	if (!xdr_int(xdrs, (int *)&m->ics_msg_type))
		return (B_FALSE);
	
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->ics_msgid) ||
	    !xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->ics_status))
	    	return (B_FALSE);
	
	return (B_TRUE);
}

boolean_t
xdr_ic_session_create_destroy_msg(XDR *xdrs, void *msg)
{
	stmf_ic_session_create_destroy_msg_t *m =
	    (stmf_ic_session_create_destroy_msg_t *)msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);

	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&m->icscd_session_id))
		return (B_FALSE);

	if (xdrs->x_op == XDR_ENCODE) {
		if (!xdr_ic_scsi_devid_marshal(xdrs, m->icscd_ini_devid))
			return (B_FALSE);

		if (!xdr_ic_scsi_devid_marshal(xdrs, m->icscd_tgt_devid)) {
		    	return (B_FALSE);
		}

		if (!xdr_ic_remote_port_marshal(xdrs, m->icscd_rport) )
			return (B_FALSE);
	} else {
		m->icscd_ini_devid = xdr_ic_scsi_devid_unmarshal(xdrs);
		if (m->icscd_ini_devid == NULL) {
			cmn_err(CE_WARN, "%s: ini devid failed", __func__);
			return (B_FALSE);
		}
		
		m->icscd_tgt_devid = xdr_ic_scsi_devid_unmarshal(xdrs);
		if (m->icscd_tgt_devid == NULL) {
			cmn_err(CE_WARN, "%s: tgt devid failed", __func__);
			return (B_FALSE);
		}
		
		m->icscd_rport = xdr_ic_remote_port_unmarshal(xdrs);
		if (m->icscd_rport == NULL) {
			cmn_err(CE_WARN, "%s: rpot failed", __func__);
			return (B_FALSE);
		} 
	}
	
	return (B_TRUE);
}

boolean_t
xdr_ic_echo_request_reply_msg(XDR *xdrs, void *msg)
{
	boolean_t rc = B_TRUE;
	stmf_ic_echo_request_reply_msg_t *m = msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);

	if (!xdr_u_int(xdrs, (uint_t *)&m->icerr_datalen))
		return (B_FALSE);

	if (m->icerr_datalen) {
		if (xdrs->x_op == XDR_DECODE)
			m->icerr_data = kmem_zalloc(m->icerr_datalen, KM_SLEEP);
		rc = xdr_opaque(xdrs, (char *)m->icerr_data, m->icerr_datalen);
	}
	return (rc);
}

boolean_t
xdr_ic_notify_avs_master_state_msg(XDR *xdrs, void *msg)
{
	boolean_t rc = B_TRUE;
	stmf_ic_notify_avs_master_state_msg_t *m = msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);

	if (!xdr_opaque(xdrs, (char *)m->icnams_lun_id, 16))
		return (B_FALSE);
	if (!xdr_string_alua(xdrs, &m->icnams_lu_provider_name, MAXNAMELEN))
		return (B_FALSE);
	if (!xdr_u_int(xdrs, &m->icnams_avs_master_state))
		return (B_FALSE);

	return (rc);
}

boolean_t
xdr_ic_set_remote_sync_flag_msg(XDR *xdrs, void *msg)
{
	boolean_t rc = B_TRUE;
	stmf_ic_set_remote_sync_flag_msg_t *m = msg;

	if (xdrs->x_op == XDR_FREE)
		return (B_TRUE);

	if (!xdr_opaque(xdrs, (char *)m->ic_lun_id, 16))
		return (B_FALSE);
	if (!xdr_string_alua(xdrs, &m->ic_lu_provider_name, MAXNAMELEN))
		return (B_FALSE);
	if (!xdr_u_int(xdrs, &m->ic_need_synced))
		return (B_FALSE);

	return (rc);
}

boolean_t
xdr_alua_ic_msg(XDR *xdrs, stmf_ic_msg_t *msg)
{
	boolean_t rc = B_FALSE;

	if (!xdr_int(xdrs, (int *)&msg->icm_msg_type))
		return (B_FALSE);
	/* add guid in pppt msg head */
	xdr_opaque(xdrs, (char *)msg->icm_guid,  16);
		
	xdr_u_longlong_t(xdrs, (unsigned long long *)&msg->icm_msgid);

	switch (msg->icm_msg_type) {
	case STMF_ICM_REGISTER_PROXY_PORT:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof (stmf_ic_reg_port_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_reg_port_msg(xdrs, msg->icm_msg);
		break;
		
	case STMF_ICM_DEREGISTER_PROXY_PORT:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof(stmf_ic_dereg_port_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_dereg_port_msg(xdrs, msg->icm_msg);
		break;
		
	case STMF_ICM_LUN_ACTIVE:
	case STMF_ICM_LUN_DEACTIVE:
	case STMF_ICM_REGISTER_LUN:
	case STMF_ICM_DEREGISTER_LUN:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof(stmf_ic_reg_dereg_lun_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_reg_dereg_lun_msg(xdrs, msg->icm_msg);
		break;
		
	case STMF_ICM_SCSI_CMD:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof(stmf_ic_scsi_cmd_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_scsi_cmd_msg(xdrs, msg->icm_msg);
		break;
		
	case STMF_ICM_SCSI_DATA:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof(stmf_ic_scsi_data_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_scsi_data_msg(xdrs, msg->icm_msg);
		break;
		
	case STMF_ICM_SCSI_DATA_XFER_DONE:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof(stmf_ic_scsi_data_xfer_done_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_scsi_data_xfer_done_msg(xdrs, msg->icm_msg);
		break;
		
	case STMF_ICM_SCSI_STATUS:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof(stmf_ic_scsi_status_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_scsi_status_msg(xdrs, msg->icm_msg);
		break;
	case STMF_ICM_SCSI_DATA_REQ:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof(stmf_ic_scsi_data_req_msg_t),
				KM_SLEEP);
		}
		rc = xdr_ic_scsi_data_req_msg(xdrs, msg->icm_msg);
		break;

	case STMF_ICM_SCSI_DATA_RES:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg =
				kmem_zalloc(sizeof(stmf_ic_scsi_data_res_msg_t),
					    KM_SLEEP);
		}
		rc = xdr_ic_scsi_data_res_msg(xdrs, msg->icm_msg);
		break;

	case STMF_ICM_R2T:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof(stmf_ic_r2t_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_r2t_msg(xdrs, msg->icm_msg);
		break;

	case STMF_ICM_STATUS:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof(stmf_ic_dereg_port_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_status_msg(xdrs, msg->icm_msg);
		break;

	case STMF_ICM_SESSION_CREATE:
	case STMF_ICM_SESSION_DESTROY:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof(stmf_ic_session_create_destroy_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_session_create_destroy_msg(xdrs,
		    msg->icm_msg);
		break;

	case STMF_ICM_ECHO_REQUEST:
	case STMF_ICM_ECHO_REPLY:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(sizeof(stmf_ic_echo_request_reply_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_echo_request_reply_msg(xdrs,
		    msg->icm_msg);
		break;

	case STMF_ICM_ALUA_STATE_SYNC:
		/* do nothing */
		rc = B_TRUE;
		break;

	case STMF_ICM_NOTIFY_AVS_MASTER_STATE:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(
				sizeof(stmf_ic_notify_avs_master_state_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_notify_avs_master_state_msg(xdrs,
		    msg->icm_msg);
		break;

	case STMF_ICM_SET_REMOTE_SYNC_FLAG:
		if (xdrs->x_op == XDR_DECODE) {
			msg->icm_msg = kmem_zalloc(
				sizeof(stmf_ic_set_remote_sync_flag_msg_t),
			    KM_SLEEP);
		}
		rc = xdr_ic_set_remote_sync_flag_msg(xdrs,
		    msg->icm_msg);
		break;

	case STMF_ICM_MAX_MSG_TYPE:
		ASSERT(0);
		break;

	default:
		ASSERT(0);
	}

	return (rc);
}

static void
debug_alua_xdr(void)
{
}

char *
alua_ic_encode_common(void *data, size_t *len)
{
	XDR xdrs;
	char *buf = NULL;
	
	if (data == NULL) {
		cmn_err(CE_WARN, "%s: invalid arg", __func__);
		return (NULL);
	}

	*len = xdr_sizeof((xdrproc_t)xdr_alua_ic_msg, data);
	*len = (*len + 7 ) & (~7);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	buf = stmf_ic_kmem_alloc(*len, KM_SLEEP);
#else
	buf = kmem_alloc(*len, KM_SLEEP);
#endif
	xdrmem_create(&xdrs, buf, *len, XDR_ENCODE);
	if (!xdr_alua_ic_msg(&xdrs, data)) {
		cmn_err(CE_WARN, "%s:encode failed", __func__);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		stmf_ic_kmem_free(buf, *len);
#else
		kmem_free(buf, *len);
#endif
		buf = NULL;
		*len = 0;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

stmf_ic_msg_t *
alua_ic_decode_common(char *buf, size_t len)
{
	stmf_ic_msg_t *m = kmem_zalloc(sizeof(*m), KM_SLEEP);
	XDR xdrs;

	if (buf == NULL) {
		cmn_err(CE_WARN, "%s: invalid arg", __func__);
		kmem_free(m, sizeof(*m));
		return (NULL);
	}

	xdrmem_create(&xdrs, buf, len, XDR_DECODE);
	m->icm_msg_flags = STMF_ICM_MSG_XDR;
	if (!xdr_alua_ic_msg(&xdrs, m)) {
		cmn_err(CE_WARN, "%s: decode failed", __func__);
		stmf_ic_msg_free(m);
		m = NULL;
	}
	
	xdr_destroy(&xdrs);
	return (m);
}

