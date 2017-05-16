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

/*
 * XXX TODO
 * #includes cribbed from stmf.c -- undoubtedly only a small subset of these
 * are actually needed.
 */
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
/* #include <sys/scsi/scsi.h> */
/* #include <sys/scsi/generic/persist.h> */
#include <sys/byteorder.h>
#include <sys/nvpair.h>
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
#include <rpc/types.h>
#include <rpc/xdr.h>
#include "alua_ic_xdr.h"
#include "pppt.h"

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
#include <sys/fs/zfs_hbx.h>
#endif
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
#include <sys/cluster_san.h>
#include <sys/stmf_sbd_ioctl.h>
#endif

/*
 * Macros
 */
#define	PRIx64		"llx"

#define aluanametoolong	((char *)-1)
/* ksocket connect retry times */
#define PPPT_KSOCKET_RETRY_TIMES 		10
/* ksocket rx error again max times */
#define PPPT_KSOCKET_EAGAIN_TIMES		10

/* Free a struct if it was allocated */
#define	FREE_IF_ALLOC(m)					\
	do {							\
		if ((m)) kmem_free((m), sizeof (*(m)));		\
		_NOTE(CONSTCOND)				\
	} while (0)

/*
 * Macros to simplify the addition of struct fields to an nvlist.
 * The name of the fields in the nvlist is the same as the name
 * of the struct field.
 *
 * These macros require an int rc and a "done:" return retval label;
 * they assume that the nvlist is named "nvl".
 */
#define	NVLIST_ADD_FIELD(type, structure, field)			\
	do {								\
		rc = nvlist_add_##type(nvl, #field, structure->field);  \
		if (rc) goto done;					\
		_NOTE(CONSTCOND)					\
	} while (0)

/* use this macro when the array is defined as part of the struct */
#define	NVLIST_ADD_ARRAY(type, structure, field)			\
	do {								\
		rc = nvlist_add_##type##_array(nvl, #field,		\
		    structure->field, sizeof (structure->field));	\
		if (rc) goto done;					\
		_NOTE(CONSTCOND)					\
	} while (0)

/*
 * use this macro when the array field is a ptr or you need to explictly
 * call out the size.
 */
#define	NVLIST_ADD_ARRAY_LEN(type, structure, field, len)		\
	do {								\
		rc = nvlist_add_##type##_array(nvl, #field,		\
		    structure->field, len);				\
		if (rc) goto done;					\
		_NOTE(CONSTCOND)					\
	} while (0)

#define	NVLIST_ADD_DEVID(structure, field)				\
	do {								\
		rc = stmf_ic_scsi_devid_desc_marshal(nvl, #field,	\
		    structure->field);					\
		if (rc) goto done;					\
		_NOTE(CONSTCOND)					\
	} while (0)

#define	NVLIST_ADD_RPORT(structure, field)				\
	do {								\
		rc = stmf_ic_remote_port_marshal(nvl, #field,		\
		    structure->field);					\
		if (rc) goto done;					\
		_NOTE(CONSTCOND)					\
	} while (0)

#define	NVLIST_ADD_FIELD_UINT8(structure, field)			\
	NVLIST_ADD_FIELD(structure, field, uint8)

/*
 * Macros to simplify the extraction of struct fields from an nvlist.
 * The name of the fields in the nvlist is the same as the name
 * of the struct field.
 *
 * Requires an int rc and a "done:" return retval label.
 * Assumes that the nvlist is named "nvl".
 *
 * Sample usage: NVLIST_LOOKUP_FIELD(uint8, structname, fieldname);
 */
#define	NVLIST_LOOKUP_FIELD(type, structure, field)			\
	do {								\
		rc = nvlist_lookup_##type(nvl, #field,			\
		    &(structure->field));				\
		if (rc) { 						\
			stmf_ic_nvlookup_warn(__func__, #field);	\
			goto done;					\
		}							\
		_NOTE(CONSTCOND)					\
	} while (0)

/*
 * Look up a field which gets stored into a structure bit field.
 * The type passed is a uint type which can hold the largest value
 * in the bit field.
 *
 * Requires an int rc and a "done:" return retval label.
 * Assumes that the nvlist is named "nvl".
 *
 * Sample usage: NVLIST_LOOKUP_BIT_FIELD(uint8, structname, fieldname);
 */
#define	NVLIST_LOOKUP_BIT_FIELD(type, structure, field)			\
	do {								\
		type##_t tmp;						\
		rc = nvlist_lookup_##type(nvl, #field, &tmp);		\
		if (rc) { 						\
			stmf_ic_nvlookup_warn(__func__, #field);	\
			goto done;					\
		}							\
		structure->field = tmp;					\
		_NOTE(CONSTCOND)					\
	} while (0)

/*
 * Look up a boolean field which gets stored into a structure bit field.
 *
 * Requires an int rc and a "done:" return retval label.
 * Assumes that the nvlist is named "nvl".
 */
#define	NVLIST_LOOKUP_BIT_FIELD_BOOLEAN(structure, field)		\
	do {								\
		boolean_t tmp;						\
		rc = nvlist_lookup_boolean_value(nvl, #field, &tmp);	\
		if (rc) { 						\
			stmf_ic_nvlookup_warn(__func__, #field);	\
			goto done;					\
		}							\
		structure->field = (tmp ?  1 : 0);			\
		_NOTE(CONSTCOND)					\
	} while (0)

/* shorthand  for nvlist_lookup_pairs() args */
#define	NV_PAIR(type, strct, field) #field, DATA_TYPE_##type, &(strct->field)

/* number of times to retry the upcall to transmit */
#define	STMF_MSG_TRANSMIT_RETRY	    3

#define	ISDIGIT(_c) \
	((_c) >= '0' && (_c) <= '9')

#define	ISXDIGIT(_c) \
	(ISDIGIT(_c) || \
	((_c) >= 'a' && (_c) <= 'f') || \
	((_c) >= 'A' && (_c) <= 'F'))

#define	ISLOWER(_c) \
	((_c) >= 'a' && (_c) <= 'z')

#define	ISUPPER(_c) \
	((_c) >= 'A' && (_c) <= 'Z')

#define	ISALPHA(_c) \
	(ISUPPER(_c) || \
	ISLOWER(_c))

#define	ISALNUM(_c) \
	(ISALPHA(_c) || \
	ISDIGIT(_c))

#define	ISSPACE(_c) \
	((_c) == ' ' || \
	(_c) == '\t' || \
	(_c) == '\r' || \
	(_c) == '\n')

#define	ISASCII(c)	(!((c) & ~0177))

#define 	TX_MAGIC	0x84914432
#define 	RX_MAGIC	0x34124215

/* stmf modhandle */
/* ddi_modhandle_t stmf_mod; */

typedef
int (*stmf_reg_set_alua_state)(stmf_alua_state_desc_t *alua_state);
typedef
int (*stmf_reg_set_lu_state)(stmf_lu_state_desc_t *lu_state);
typedef
int (*stmf_reg_reset_lport)(stmf_local_port_t *lport);

stmf_reg_set_alua_state set_alua_state = NULL;
stmf_reg_set_lu_state set_lu_state = NULL;
stmf_reg_reset_lport reset_lport = NULL;

/*
 * How was the message constructed?
 *
 * We need to know this when we free the message in order to
 * determine what to do with pointers in the message:
 *
 * - messages which were unmarshaled from an nvlist may point to
 *   memory within that nvlist; this memory should not be freed since
 *   it will be deallocated when we free the nvlist.
 *
 * - messages which built using a constructor (alloc) function may
 *   point to memory which was explicitly allocated by the constructor;
 *   it should be freed when the message is freed.
 *
 */
typedef enum {
	STMF_CONSTRUCTOR = 0,
	STMF_UNMARSHAL
} stmf_ic_msg_construction_method_t;

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
/* zfs modhandle */
ddi_modhandle_t drvzfs_mod = NULL;
typedef int (*zfs_hbx_link_state_get_t)(void);
typedef int (*zfs_hbx_tran_data_t)(void *data, uint64_t len,
	enum hbx_event_type event, uint32_t flags);
typedef int (*zfs_hbx_rx_hook_add_t)(enum hbx_event_type evt_type,
	zfs_hbx_rx_cb_t rx_cb);
typedef int (*zfs_hbx_rx_hook_remove_t)(enum hbx_event_type evt_type,
	zfs_hbx_rx_cb_t *rx_cb);
typedef int (*zfs_hbx_link_evt_hook_add_t)(zfs_hbx_link_evt_cb_t link_evt_cb);
typedef int (*zfs_hbx_link_evt_hook_remove_t)(zfs_hbx_link_evt_cb_t link_evt_cb);

static zfs_hbx_link_state_get_t zfs_hbx_link_state_get = NULL;
static zfs_hbx_tran_data_t zfs_hbx_tran_data = NULL;
static zfs_hbx_rx_hook_add_t zfs_hbx_rx_hook_add = NULL;
static zfs_hbx_rx_hook_remove_t zfs_hbx_rx_hook_remove = NULL;
static zfs_hbx_link_evt_hook_add_t zfs_hbx_link_evt_hook_add = NULL;
static zfs_hbx_link_evt_hook_remove_t zfs_hbx_link_evt_hook_remove = NULL;
#endif

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
/* ddi_modhandle_t drvzfs_mod = NULL; */
typedef int (*cluster_san_host_send_t)(cluster_san_hostinfo_t *cshi,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type, int pri, boolean_t need_reply, int retry_times);
typedef void (*cluster_san_broadcast_send_t)(
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type, int pri);
typedef int (*csh_rx_hook_add_t)(uint32_t msg_type, cs_rx_cb_t rx_cb, void *arg);
typedef int (*csh_rx_hook_remove_t)(uint32_t msg_type);
typedef int (*csh_link_evt_hook_add_t)(cs_link_evt_cb_t link_evt_cb, void *arg);
typedef int (*csh_link_evt_hook_remove_t)(cs_link_evt_cb_t link_evt_cb);
typedef void (*csh_rx_data_free_t)(cs_rx_data_t *cs_data);
typedef uint64_t (*cluster_san_hostinfo_hold_t)(cluster_san_hostinfo_t *cshi);
typedef uint64_t (*cluster_san_hostinfo_rele_t)(cluster_san_hostinfo_t *cshi);
typedef void (*cluster_san_host_asyn_send_t)(cluster_san_hostinfo_t *cshi,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type, uint32_t type, void *private,
	csh_asyn_tx_compl_cb_func_t compl_cb, csh_asyn_tx_clean_cb_func_t clean_cb,
	csh_asyn_tx_node_comp_func_t comp);
typedef void (*cluster_san_host_asyn_send_clean_t)(uint32_t type, void *private);
typedef int (*cluster_san_host_sync_send_msg_t)(cluster_san_hostinfo_t *cshi,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint64_t msg_id, uint8_t msg_type, int timeout);
typedef void (*cluster_san_host_sync_msg_ret_t)(cluster_san_hostinfo_t *cshi,
	uint64_t msg_id, uint8_t msg_type, uint64_t ret);
typedef void *(*cs_kmem_alloc_t)(size_t size);
typedef void (*cs_kmem_free_t)(void *buf, size_t size);
static cs_kmem_alloc_t ic_cs_kmem_alloc = NULL;
static cs_kmem_free_t ic_cs_kmem_free = NULL;

static cluster_san_host_send_t ic_csh_send = NULL;
static cluster_san_broadcast_send_t ic_cs_broadcast_send = NULL;
static csh_rx_hook_add_t ic_csh_rx_hook_add = NULL;
static csh_rx_hook_remove_t ic_csh_rx_hook_remove = NULL;
static csh_link_evt_hook_add_t ic_csh_link_evt_hook_add = NULL;
static csh_link_evt_hook_remove_t ic_csh_link_evt_hook_remove = NULL;
static csh_rx_data_free_t ic_csh_rx_data_free = NULL;
cluster_san_hostinfo_hold_t ic_csh_hold = NULL;
cluster_san_hostinfo_rele_t ic_csh_rele = NULL;
cluster_san_host_asyn_send_t ic_csh_asyn_send = NULL;
cluster_san_host_asyn_send_clean_t ic_csh_asyn_send_clean = NULL;
cluster_san_host_sync_send_msg_t ic_csh_sync_send_msg = NULL;
cluster_san_host_sync_msg_ret_t ic_csh_sync_send_msg_ret = NULL;
#endif /* PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN */

/*
 * Function prototypes.
 */

/*
 * Helpers for msg_alloc routines, used when the msg payload is
 * the same for multiple types of messages.
 */
static stmf_ic_msg_t *stmf_ic_reg_dereg_lun_msg_alloc(
    stmf_ic_msg_type_t msg_type, uint8_t *lun_id,
    char *lu_provider_name, uint16_t cb_arg_len,
    uint8_t *cb_arg, stmf_ic_msgid_t msgid);

static stmf_ic_msg_t *stmf_ic_session_create_destroy_msg_alloc(
    stmf_ic_msg_type_t msg_type,
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid);

static stmf_ic_msg_t *stmf_ic_echo_request_reply_msg_alloc(
    stmf_ic_msg_type_t msg_type,
    uint32_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid);
static stmf_ic_msg_t *stmf_ic_alua_state_sync_msg_alloc(
    stmf_ic_msgid_t msgid);

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
static stmf_ic_msg_status_t stmf_ic_so_transmit(char *buf, size_t size,
	boolean_t can_retry);
#else
static stmf_ic_msg_status_t stmf_ic_so_transmit(char *buf, size_t size);
#endif
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
static void stmf_ic_tx_complete(pppt_conn_msg_t *msg);
#endif /* #if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET) */
static void stmf_ic_rx_complete(pppt_conn_msg_t *msg);

/*
 * Msg free routines.
 */
static void stmf_ic_reg_port_msg_free(stmf_ic_reg_port_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_dereg_port_msg_free(stmf_ic_dereg_port_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_reg_dereg_lun_msg_free(stmf_ic_reg_dereg_lun_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_scsi_cmd_msg_free(stmf_ic_scsi_cmd_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_scsi_data_msg_free(stmf_ic_scsi_data_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_scsi_data_xfer_done_msg_free(
    stmf_ic_scsi_data_xfer_done_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_scsi_status_msg_free(stmf_ic_scsi_status_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_scsi_data_req_msg_free(stmf_ic_scsi_data_req_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_scsi_data_res_msg_free(stmf_ic_scsi_data_res_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_r2t_msg_free(stmf_ic_r2t_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_status_msg_free(stmf_ic_status_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_session_create_destroy_msg_free(
    stmf_ic_session_create_destroy_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void stmf_ic_echo_request_reply_msg_free(
    stmf_ic_echo_request_reply_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void
stmf_ic_notify_avs_master_state_msg_free(
	stmf_ic_notify_avs_master_state_msg_t *m,
    stmf_ic_msg_flag_t cmethod);
static void
stmf_ic_set_remote_sync_flag_msg_free(
	stmf_ic_set_remote_sync_flag_msg_t *m,
    stmf_ic_msg_flag_t cmethod);

#if 0
/*
 * Marshaling routines.
 */
static nvlist_t *stmf_ic_msg_marshal(stmf_ic_msg_t *msg);
static int stmf_ic_reg_port_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_dereg_port_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_reg_dereg_lun_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_scsi_cmd_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_scsi_data_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_scsi_data_xfer_done_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_scsi_status_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_r2t_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_status_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_session_create_destroy_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_echo_request_reply_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_scsi_devid_desc_marshal(nvlist_t *parent_nvl,
	char *sdid_name, scsi_devid_desc_t *sdid);
static int stmf_ic_remote_port_marshal(nvlist_t *parent_nvl,
	char *rport_name, stmf_remote_port_t *rport);

/*
 * Unmarshaling routines.
 */
static stmf_ic_msg_t *stmf_ic_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_reg_port_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_dereg_port_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_reg_dereg_lun_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_scsi_cmd_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_scsi_data_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_scsi_data_xfer_done_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_scsi_status_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_r2t_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_status_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_session_create_destroy_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_echo_request_reply_msg_unmarshal(nvlist_t *nvl);
static scsi_devid_desc_t *stmf_ic_lookup_scsi_devid_desc_and_unmarshal(
    nvlist_t *nvl, char *field_name);
static scsi_devid_desc_t *stmf_ic_scsi_devid_desc_unmarshal(
    nvlist_t *nvl_devid);
static uint8_t *stmf_ic_uint8_array_unmarshal(nvlist_t *nvl, char *field_name,
	uint64_t len, uint8_t *buf);
static char *stmf_ic_string_unmarshal(nvlist_t *nvl, char *field_name);
static stmf_remote_port_t *stmf_ic_lookup_remote_port_and_unmarshal(
	nvlist_t *nvl, char *field_name);
static stmf_remote_port_t *stmf_ic_remote_port_unmarshal(nvlist_t *nvl);
#endif

/*
 * Transmit and recieve routines.
 */
stmf_ic_msg_status_t stmf_ic_transmit(char *buf, size_t size);

/*
 * Utilities.
 */
static stmf_ic_msg_t *stmf_ic_alloc_msg_header(stmf_ic_msg_type_t msg_type,
	stmf_ic_msgid_t msgid);
size_t sizeof_scsi_devid_desc(int ident_length);
static char *stmf_ic_strdup(char *str);
static scsi_devid_desc_t *scsi_devid_desc_dup(scsi_devid_desc_t *did);
static stmf_remote_port_t *remote_port_dup(stmf_remote_port_t *rport);
static void scsi_devid_desc_free(scsi_devid_desc_t *did);
static inline void stmf_ic_nvlookup_warn(const char *func, char *field);

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
static void stmf_ic_rx_thr_wait();
static void stmf_ic_conn_wakeup();

static void stmf_hbx_rx_task(void *arg)
{
	pppt_conn_msg_t *rx_msg = (pppt_conn_msg_t *)arg;

	if (pppt_conn.ic_rx_tq_exit) {
		stmf_ic_rx_complete(rx_msg);
		return;
	}

	if (!pppt_conn.ic_set_alua_state_complete)  {
		stmf_ic_rx_thr_wait();
	}

	if (pppt_conn.ic_rx_tq_exit) {
		stmf_ic_rx_complete(rx_msg);
		return;
	}

	stmf_ic_rx_msg(rx_msg->msgbuf, rx_msg->size, NULL);
	stmf_ic_rx_complete(rx_msg);
}

static void stmf_hbx_rx_cb(void *data, uint64_t len)
{
	pppt_conn_msg_t *rx_msg = NULL;

	rx_msg = kmem_zalloc(sizeof(pppt_conn_msg_t), KM_SLEEP);
	rx_msg->msgbuf = data;
	rx_msg->size = len;
	rx_msg->msg_queue_next = NULL;

	taskq_dispatch(pppt_conn.ic_rx_tq, stmf_hbx_rx_task,
		(void *)rx_msg, TQ_SLEEP);
}

static void stmf_hbx_link_evt_cb(zfs_hbx_link_evt_t link_evt)
{
	switch (link_evt) {
		case LINK_UP_TO_DOWN:
			cmn_err(CE_WARN, "%s: hbx link to down", __func__);
			mutex_enter(&pppt_conn.ic_tx_mutex);
			cv_signal(&pppt_conn.ic_tx_cv);
			mutex_exit(&pppt_conn.ic_tx_mutex);
			break;
		case LINK_DOWN_TO_UP:
			cmn_err(CE_NOTE, "%s: hbx link to up", __func__);
			mutex_enter(&pppt_conn.ic_conn_lock);
			cv_signal(&pppt_conn.ic_conn_cv);
			mutex_exit(&pppt_conn.ic_conn_lock);
			break;
		default:
			break;
	}
}

int
stmf_hbx_modload(void)
{
	int error;

	if (drvzfs_mod == NULL && ((drvzfs_mod =
	    ddi_modopen("drv/zfs", KRTLD_MODE_FIRST, &error)) == NULL)) {
		cmn_err(CE_WARN, "Unable to load zfs");
		return (-1);
	}

	if (zfs_hbx_link_state_get == NULL && ((zfs_hbx_link_state_get =
	    (zfs_hbx_link_state_get_t)
	    ddi_modsym(drvzfs_mod, "zfs_hbx_link_state_get",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - zfs_hbx_link_state_get");
		return (-1);
	}

	if (zfs_hbx_tran_data == NULL && ((zfs_hbx_tran_data =
	    (zfs_hbx_tran_data_t)
	    ddi_modsym(drvzfs_mod, "zfs_hbx_tran_data",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - zfs_hbx_tran_data");
		return (-1);
	}

	if (zfs_hbx_rx_hook_add == NULL && ((zfs_hbx_rx_hook_add =
	    (zfs_hbx_rx_hook_add_t)
	    ddi_modsym(drvzfs_mod, "zfs_hbx_rx_hook_add",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - zfs_hbx_rx_hook_add");
		return (-1);
	}

	if (zfs_hbx_rx_hook_remove == NULL && ((zfs_hbx_rx_hook_remove =
	    (zfs_hbx_rx_hook_remove_t)
	    ddi_modsym(drvzfs_mod, "zfs_hbx_rx_hook_remove",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - zfs_hbx_rx_hook_remove");
		return (-1);
	}

	if (zfs_hbx_link_evt_hook_add == NULL && ((zfs_hbx_link_evt_hook_add =
	    (zfs_hbx_link_evt_hook_add_t)
	    ddi_modsym(drvzfs_mod, "zfs_hbx_link_evt_hook_add",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - zfs_hbx_link_evt_hook_add");
		return (-1);
	}

	if (zfs_hbx_link_evt_hook_remove == NULL && ((zfs_hbx_link_evt_hook_remove =
	    (zfs_hbx_link_evt_hook_remove_t)
	    ddi_modsym(drvzfs_mod, "zfs_hbx_link_evt_hook_remove",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - zfs_hbx_link_evt_hook_remove");
		return (-1);
	}

	pppt_conn.ic_rx_tq = taskq_create("pppt_ic_rx_tq", 8, minclsyspri,
    	8, INT_MAX, TASKQ_PREPOPULATE);
	pppt_conn.ic_rx_tq_exit = B_FALSE;
	zfs_hbx_rx_hook_add(EVT_PPPT_HBX_TRANSMIT, stmf_hbx_rx_cb);
	zfs_hbx_link_evt_hook_add(stmf_hbx_link_evt_cb);

	return 0;
}

void
stmf_hbx_modunload(void)
{
	zfs_hbx_rx_hook_remove(EVT_PPPT_HBX_TRANSMIT, NULL);
	zfs_hbx_link_evt_hook_remove(stmf_hbx_link_evt_cb);
	pppt_conn.ic_rx_tq_exit = B_TRUE;
	stmf_ic_conn_wakeup();
	taskq_destroy(pppt_conn.ic_rx_tq);
}
#endif /* #if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX) */

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
void stmf_clustersan_alua_state_sync(void *arg)
{
	stmf_alua_state_desc_t *alua_state = arg;
	stmf_ic_msg_t		*msg;
	int ret;

	/* set alua state */
	ret = set_alua_state(alua_state);
	if (ret != 0) {
		cmn_err(CE_WARN, " set alua state failed, node:%d, state:%d, sess:%"PRIx64"",
		    alua_state->alua_node, alua_state->alua_state,
		    alua_state->alua_psess);
	}
	/* get alua state */
	msg = stmf_ic_alua_state_sync_msg_alloc(0);
	if (msg != NULL) {
		msg->icm_sess = (void *)((uintptr_t)alua_state->alua_psess);
		stmf_ic_tx_msg(msg);
	}
	
	kmem_free(alua_state, sizeof(stmf_alua_state_desc_t));
}

void stmf_clustersan_set_lu_state(void *arg)
{
	stmf_lu_state_desc_t *lu_state = arg;
	set_lu_state(lu_state);
	kmem_free(lu_state, sizeof(stmf_lu_state_desc_t));
}

void stmf_clustersan_reset_pppt_lport(void *arg)
{
	cluster_san_hostinfo_t *cshi = (cluster_san_hostinfo_t *)arg;
	pppt_tgt_t *tmp_avl;
	cmn_err(CE_NOTE, "%s", __func__);

	for (tmp_avl = avl_first(&pppt_global.global_target_list); tmp_avl != NULL; 
		tmp_avl = avl_walk(&pppt_global.global_target_list, tmp_avl, AVL_AFTER)) {
		if (tmp_avl->target_psess == cshi) {
			cmn_err(CE_NOTE, "%s find lport", __func__);
			reset_lport(tmp_avl->target_stmf_lport);
		}
	}
}

static void stmf_cs_rx_task(void *arg)
{
	cs_rx_data_t *cs_data = (cs_rx_data_t *)arg;

	if (pppt_conn.ic_cs_rx_tq_exit) {
		ic_csh_rx_data_free(cs_data);
		return;
	}

	stmf_ic_rx_msg(cs_data->data, cs_data->data_len, cs_data->cs_private);
	ic_csh_rx_data_free(cs_data);
}

void stmf_cs_rx_cb(cs_rx_data_t *cs_data, void *arg)
{
	taskq_dispatch(pppt_conn.ic_cs_rx_tq, stmf_cs_rx_task,
		(void *)cs_data, TQ_SLEEP);
}

void stmf_cs_link_evt_cb(void *private,
	cts_link_evt_t link_evt, void *arg)
{
	uint32_t	hostid;
	cluster_san_hostinfo_t *cshi = private;
	stmf_alua_state_desc_t *alua_state;
	stmf_lu_state_desc_t *lu_state;

	switch(link_evt) {
		case LINK_EVT_DOWN_TO_UP:
			cmn_err(CE_NOTE, "alua ic link up ,host: %s-%d",
				cshi->hostname, cshi->hostid);
			/* set and get alua state */
			alua_state = kmem_zalloc(sizeof(stmf_alua_state_desc_t), KM_SLEEP);
			hostid = zone_get_hostid(NULL);
			alua_state->alua_node = (hostid + 1) % 2;
			alua_state->alua_state = 1;
			alua_state->alua_psess = (uint64_t)((uintptr_t)cshi);
			taskq_dispatch(pppt_conn.ic_cs_asyn_taskq,
				stmf_clustersan_alua_state_sync,
				(void *)alua_state, TQ_SLEEP);
			break;
		case LINK_EVT_UP_TO_DOWN:
			cmn_err(CE_NOTE, "alua ic link down ,host: %s-%d",
				cshi->hostname, cshi->hostid);
			/* set state of standby lu and target */
			lu_state = kmem_zalloc(sizeof(stmf_lu_state_desc_t), KM_SLEEP);
			lu_state->lu_access_state = SBD_LU_TRANSITION_TO_ACTIVE;
			lu_state->lu_sess = (void *)cshi;
			taskq_dispatch(pppt_conn.ic_cs_asyn_taskq,
				stmf_clustersan_set_lu_state,
				(void *)lu_state, TQ_SLEEP);
			taskq_dispatch(pppt_conn.ic_cs_asyn_taskq,
				stmf_clustersan_reset_pppt_lport,
				(void *)cshi, TQ_SLEEP);
			break;
		default:
			break;
	}
}

int
stmf_clustersan_modload(void)
{
	ic_csh_send = cluster_san_host_send;
	ic_csh_rx_hook_add = csh_rx_hook_add;
	ic_csh_rx_hook_remove = csh_rx_hook_remove;
	ic_csh_link_evt_hook_add = csh_link_evt_hook_add;
	ic_csh_link_evt_hook_remove = csh_link_evt_hook_remove;
	ic_csh_rx_data_free = csh_rx_data_free_ext;
	ic_cs_broadcast_send = cluster_san_broadcast_send;
	ic_csh_hold = cluster_san_hostinfo_hold;
	ic_csh_rele = cluster_san_hostinfo_rele;
	ic_csh_asyn_send = cluster_san_host_asyn_send;
	ic_csh_asyn_send_clean = cluster_san_host_asyn_send_clean;
	ic_csh_sync_send_msg = cluster_san_host_sync_send_msg;
	ic_csh_sync_send_msg_ret = cluster_san_host_sync_msg_ret;
	ic_cs_kmem_alloc = cs_kmem_alloc;
	ic_cs_kmem_free = cs_kmem_free;
	
	pppt_conn.ic_cs_rx_tq = taskq_create("pppt_ic_rx_tq", 8, minclsyspri,
    	8, INT_MAX, TASKQ_PREPOPULATE);
	pppt_conn.ic_cs_rx_tq_exit = B_FALSE;
	ic_csh_rx_hook_add(CLUSTER_SAN_MSGTYPE_PPPT, stmf_cs_rx_cb, NULL);
	ic_csh_link_evt_hook_add(stmf_cs_link_evt_cb, NULL);
	return (0);
}

void
stmf_clustersan_modunload(void)
{
	ic_csh_rx_hook_remove(CLUSTER_SAN_MSGTYPE_PPPT);
	ic_csh_link_evt_hook_remove(stmf_cs_link_evt_cb);
	pppt_conn.ic_cs_rx_tq_exit = B_TRUE;
	taskq_destroy(pppt_conn.ic_cs_rx_tq);
}

typedef struct stmf_ic_asyn_tx_private {
	void *parent_private;
	void(*compl_cb)(void *, uint32_t, int);
	void (*clean_cb)(void *);
	int (*comp)(void *, void *);
}stmf_ic_asyn_tx_private_t;

static void stmf_ic_asyn_tx_msg_compl(void *private, uint32_t hostid, int ret)
{
	stmf_ic_asyn_tx_private_t *ic_private = private;
	if (ic_private->compl_cb != NULL) {
		ic_private->compl_cb(ic_private->parent_private, hostid, ret);
	}
}

static void stmf_ic_asyn_tx_msg_clean(void *buf, uint64_t len,
	void *header, uint64_t header_len, void *private)
{
	stmf_ic_asyn_tx_private_t *ic_private = private;
	if (buf != NULL) {
		stmf_ic_kmem_free(buf, len);
	}
	ic_private->clean_cb(ic_private->parent_private);
	kmem_free(ic_private, sizeof(stmf_ic_asyn_tx_private_t));
}

static int stmf_ic_asyn_tx_msg_comp(void *arg1, void *arg2)
{
	stmf_ic_asyn_tx_private_t *ic_private = arg2;
	return (ic_private->comp(arg1, ic_private->parent_private));
}

stmf_ic_msg_status_t stmf_ic_asyn_tx_msg(stmf_ic_msg_t *msg,
	uint32_t type, void *private, void(*compl_cb)(void *, uint32_t, int),
	void (*clean_cb)(void *),
	int (*comp)(void *, void *))
{
	size_t size = 0;
	char *buf = NULL;
	stmf_ic_asyn_tx_private_t *ic_private;
	stmf_ic_msg_status_t status = STMF_IC_MSG_SUCCESS;

	buf = alua_ic_encode_common(msg, &size);
	if (buf == NULL) {
		status = STMF_IC_MSG_INTERNAL_ERROR;
		cmn_err(CE_WARN, "%s  msg encode failed", __func__);
		stmf_ic_msg_free(msg);
		return (status);
	}
	
	if (ic_csh_asyn_send != NULL) {
		ic_private = kmem_alloc(sizeof(stmf_ic_asyn_tx_private_t), KM_SLEEP);
		ic_private->parent_private = private;
		ic_private->compl_cb = compl_cb;
		ic_private->clean_cb = clean_cb;
		ic_private->comp = comp;
		ic_csh_asyn_send(msg->icm_sess, buf, size, NULL, 0,
			CLUSTER_SAN_MSGTYPE_PPPT, type, ic_private,
			stmf_ic_asyn_tx_msg_compl, stmf_ic_asyn_tx_msg_clean,
			stmf_ic_asyn_tx_msg_comp);
	} else {
		status = STMF_IC_MSG_INTERNAL_ERROR;
		cmn_err(CE_WARN, "%s: csh_asyn_send is NULL", __func__);
		stmf_ic_kmem_free(buf, size);
	}
	stmf_ic_msg_free(msg);

	return (status);
}

void stmf_ic_asyn_tx_clean(uint32_t type, void *private)
{
	if (ic_csh_asyn_send_clean == NULL) {
		ic_csh_asyn_send_clean(type, private);
	}
}

stmf_ic_msg_status_t stmf_ic_sync_tx_msg(stmf_ic_msg_t *msg)
{
	size_t size = 0;
	char *buf = NULL;
	stmf_ic_msg_status_t status = STMF_IC_MSG_SUCCESS;
	int ret;

	buf = alua_ic_encode_common(msg, &size);

	if (buf == NULL) {
		status = STMF_IC_MSG_INTERNAL_ERROR;
		cmn_err(CE_WARN, "%s  msg encode failed", __func__);
		stmf_ic_msg_free(msg);
		return (status);
	}

	if (ic_csh_sync_send_msg != NULL) {
		ret = ic_csh_sync_send_msg(msg->icm_sess, buf, size,
			NULL, 0, msg->icm_msgid, CLUSTER_SAN_MSGTYPE_PPPT, 0);
		if (ret != 0) {
			status = STMF_IC_MSG_INTERNAL_ERROR;
		}
	} else {
		status = STMF_IC_MSG_INTERNAL_ERROR;
		cmn_err(CE_WARN, "%s: ic_csh_sync_send_msg is NULL", __func__);
	}

	stmf_ic_kmem_free(buf, size);

	stmf_ic_msg_free(msg);
	return (status);
}

void stmf_ic_sync_tx_msg_ret(void *sess, uint64_t msg_id, uint64_t ret)
{
	if (ic_csh_sync_send_msg_ret != NULL) {
		ic_csh_sync_send_msg_ret(sess, msg_id, CLUSTER_SAN_MSGTYPE_PPPT, ret);
	}
}

int stmf_ic_csh_hold(void *csh, void *tag)
{
	int ret = 0;
	if (ic_csh_hold != NULL) {
		ret = ic_csh_hold(csh);
	}
	return (0);
}
void stmf_ic_csh_rele(void *csh, void *tag)
{
	if (ic_csh_rele != NULL) {
		ic_csh_rele(csh);
	}
}

void *stmf_ic_kmem_alloc(size_t size, int kmflag)
{
	void *buf;
	buf = ic_cs_kmem_alloc(size);
	return (buf);
}

void *stmf_ic_kmem_zalloc(size_t size, int kmflag)
{
	void *buf;
	buf = ic_cs_kmem_alloc(size);
	bzero(buf, size);
	return (buf);
}

void stmf_ic_kmem_free(void *ptr, size_t size)
{
	ic_cs_kmem_free(ptr, size);
}
#endif /* PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN */

void stmf_msg_alua_state_sync (stmf_ic_msg_t *msg)
{
	int ret;
	uint32_t	hostid;
	stmf_alua_state_desc_t alua_state;

	hostid = zone_get_hostid(NULL);
	alua_state.alua_node = (hostid + 1) % 2;
	alua_state.alua_state = 1;
	alua_state.alua_psess = (uint64_t)((uintptr_t)msg->icm_sess);
	ret = set_alua_state(&alua_state);
	if (ret != 0) {
		cmn_err(CE_WARN, " set alua state failed, node:%d, state:%d, sess:%"PRIx64"",
		    alua_state.alua_node, alua_state.alua_state,
		    alua_state.alua_psess);
	}
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	if ((msg->icm_sess != NULL) && (msg->icm_sess != PPPT_BROADCAST_SESS)) {
		ic_csh_rele(msg->icm_sess); /* hold: "ic_rx_msg" */
	}
#endif
	stmf_ic_msg_free(msg);
}

/*
 * Send a message out over the interconnect, in the process marshalling
 * the arguments.
 *
 * After being sent, the message is freed.
 */
stmf_ic_msg_status_t
stmf_ic_tx_msg(stmf_ic_msg_t *msg)
{
	size_t size = 0;
	char *buf = NULL;
	int ret = 0;
	int retry_times = 0;
	stmf_ic_msg_status_t status = STMF_IC_MSG_IC_DOWN;
	
	buf = alua_ic_encode_common(msg, &size);
	if (buf == NULL) {
		status = STMF_IC_MSG_INTERNAL_ERROR;
		cmn_err(CE_WARN, "%s  msg encode failed", __func__);
		stmf_ic_msg_free(msg);
		return (STMF_IC_MSG_INTERNAL_ERROR);
	}

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	switch (msg->icm_msg_type) {
		case STMF_ICM_REGISTER_PROXY_PORT:
		case STMF_ICM_SESSION_CREATE:
		case STMF_ICM_SESSION_DESTROY:
		case STMF_ICM_REGISTER_LUN:
		case STMF_ICM_LUN_ACTIVE:
		case STMF_ICM_LUN_DEACTIVE:
		case STMF_ICM_DEREGISTER_LUN:
		case STMF_ICM_STATUS:
		case STMF_ICM_ALUA_STATE_SYNC:
		case STMF_ICM_NOTIFY_AVS_MASTER_STATE:
		case STMF_ICM_SET_REMOTE_SYNC_FLAG:
			retry_times = 3;
			break;
		default:
			retry_times = 0;
			break;
	}

	if (msg->icm_sess == PPPT_BROADCAST_SESS) {
		ic_cs_broadcast_send(buf, size, NULL, 0, CLUSTER_SAN_MSGTYPE_PPPT, 0);
		ret = 0;
	} else {
		ret = ic_csh_send(msg->icm_sess, buf, size, NULL, 0,
			CLUSTER_SAN_MSGTYPE_PPPT, 0, 1, retry_times);
	}
	if (ret == 0) {
		status = STMF_IC_MSG_SUCCESS;
	} else if (ret == -2) {
		status = STMF_IC_MSG_TIMED_OUT;
	} else {
		status = STMF_IC_MSG_IC_DOWN;
	}
#else
	if (pppt_conn.ic_conn_success) {
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
		boolean_t can_retry;
		switch (msg->icm_msg_type) {
			case STMF_ICM_REGISTER_PROXY_PORT:
			case STMF_ICM_SESSION_CREATE:
			case STMF_ICM_SESSION_DESTROY:
			case STMF_ICM_REGISTER_LUN:
			case STMF_ICM_LUN_ACTIVE:
			case STMF_ICM_LUN_DEACTIVE:
			case STMF_ICM_DEREGISTER_LUN:
			case STMF_ICM_STATUS:
			case STMF_ICM_ALUA_STATE_SYNC:
				can_retry = B_TRUE;
				break;
			default:
				can_retry = B_FALSE;
				break;
		}
		status = stmf_ic_so_transmit(buf, size, can_retry);
#else
		status = stmf_ic_so_transmit(buf, size);
#endif
	}else{
		status = STMF_IC_MSG_IC_DOWN;
		cmn_err(CE_WARN, "%s  pppt conn is down", __func__);
	}
#endif
	if (buf) {
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		stmf_ic_kmem_free(buf, size);
#else
		kmem_free(buf, size);
#endif
	}

	stmf_ic_msg_free(msg);


	return (status);
}

#if 0
/*
 * Pass the command to the daemon for transmission to the other node.
 */
stmf_ic_msg_status_t
stmf_ic_transmit(char *buf, size_t size)
{
	int i;
	int rc;
	door_arg_t arg;
	door_handle_t door;
	uint32_t result;

	mutex_enter(&pppt_global.global_door_lock);
	if (pppt_global.global_door == NULL) {
		/* daemon not listening */
		mutex_exit(&pppt_global.global_door_lock);
		return (STMF_IC_MSG_INTERNAL_ERROR);
	}
	door = pppt_global.global_door;
	door_ki_hold(door);
	mutex_exit(&pppt_global.global_door_lock);

	arg.data_ptr = buf;
	arg.data_size = size;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = (char *)&result;
	arg.rsize = sizeof (result);
	/*
	 * Retry a few times if there is a shortage of threads to
	 * service the upcall. This shouldn't happen unless a large
	 * number of initiators issue commands at once.
	 */
	for (i = 0; i < STMF_MSG_TRANSMIT_RETRY; i++) {
		rc = door_ki_upcall(door, &arg);
		if (rc != EAGAIN)
			break;
		delay(hz);
	}
	door_ki_rele(door);
	if (rc != 0) {
		cmn_err(CE_WARN,
		    "stmf_ic_transmit door_ki_upcall failed %d", rc);
		return (STMF_IC_MSG_INTERNAL_ERROR);
	}
	if (result != 0) {
		/* XXX Just warn for now */
		cmn_err(CE_WARN,
		    "stmf_ic_transmit bad result from daemon %d", result);
	}

	return (STMF_IC_MSG_SUCCESS);
}
#endif

/*
 * This is a low-level upcall which is called when a message has
 * been received on the interconnect.
 *
 * The caller is responsible for freeing the buffer which is passed in.
 */
/*ARGSUSED*/
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
void
stmf_ic_rx_msg(char *buf, size_t len, void *sess_private)
#else
void
stmf_ic_rx_msg(char *buf, size_t len)
#endif
{
	stmf_ic_msg_t *m = NULL;
	stmf_ic_echo_request_reply_msg_t *icerr;
	stmf_ic_msg_t *echo_msg;

	if (!stmf_alua_state_enable()) {
		cmn_err(CE_WARN, "stmf alua isn't enabled");
		return;
	}
	
	m = alua_ic_decode_common(buf, len);
	if (m == NULL) {
		cmn_err(CE_WARN, "%s:msg decode failed", __func__);
		return;
	}
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	if (sess_private != NULL) {
		if ((ic_csh_hold(sess_private)) != 0) { /* hold: "ic_rx_msg" */
			stmf_ic_msg_free(m);
			return;
		}
	}
#endif
	m->icm_sess = sess_private;

	switch (m->icm_msg_type) {

	case STMF_ICM_REGISTER_PROXY_PORT:
	case STMF_ICM_DEREGISTER_PROXY_PORT:
	case STMF_ICM_SESSION_CREATE:
	case STMF_ICM_SESSION_DESTROY:
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		taskq_dispatch(pppt_conn.ic_cs_asyn_taskq,
			(void (*)(void *))pppt_msg_rx, (void *)m, TQ_SLEEP);
		break;
#endif
	case STMF_ICM_SCSI_CMD:
	case STMF_ICM_SCSI_DATA_XFER_DONE:
	case STMF_ICM_SCSI_DATA_RES:
		/*
		 * These messages are all received by pppt.
		 * Currently, pppt will parse the message for type
		 */
		(void) pppt_msg_rx(m);
		break;
	case STMF_ICM_ALUA_STATE_SYNC:
		taskq_dispatch(pppt_conn.ic_cs_asyn_taskq,
			(void (*)(void *))stmf_msg_alua_state_sync, (void *)m, TQ_SLEEP);
		break;
	case STMF_ICM_LUN_ACTIVE:
	case STMF_ICM_LUN_DEACTIVE:	
	case STMF_ICM_REGISTER_LUN:
	case STMF_ICM_DEREGISTER_LUN:
	case STMF_ICM_NOTIFY_AVS_MASTER_STATE:
	case STMF_ICM_SET_REMOTE_SYNC_FLAG:
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		taskq_dispatch(pppt_conn.ic_cs_asyn_taskq,
			(void (*)(void *))stmf_msg_rx, (void *)m, TQ_SLEEP);
		break;
#endif
	case STMF_ICM_SCSI_DATA:
	case STMF_ICM_SCSI_STATUS:
	case STMF_ICM_SCSI_DATA_REQ:
		/*
		 * These messages are all received by stmf.
		 * Currently, stmf will parse the message for type
		 */
		(void) stmf_msg_rx(m);
		break;

	case STMF_ICM_ECHO_REQUEST:
		icerr = m->icm_msg;
		echo_msg = stmf_ic_echo_reply_msg_alloc(icerr->icerr_datalen,
		    icerr->icerr_data, 0);
		if (echo_msg != NULL) {
			echo_msg->icm_sess = sess_private;
			(void) stmf_ic_tx_msg(echo_msg);
		}
		stmf_ic_msg_free(m);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		if ((sess_private != NULL) && (sess_private != PPPT_BROADCAST_SESS)) {
			ic_csh_rele(sess_private); /* hold: "ic_rx_msg" */
		}
#endif
		break;

	case STMF_ICM_ECHO_REPLY:
		stmf_ic_msg_free(m);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		if ((sess_private != NULL) && (sess_private != PPPT_BROADCAST_SESS)) {
			ic_csh_rele(sess_private); /* hold: "ic_rx_msg" */
		}
#endif
		break;

	case STMF_ICM_R2T:
		/*
		 * XXX currently not supported
		 */
		stmf_ic_msg_free(m);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		if ((sess_private != NULL) && (sess_private != PPPT_BROADCAST_SESS)) {
			ic_csh_rele(sess_private); /* hold: "ic_rx_msg" */
		}
#endif
		break;

	case STMF_ICM_STATUS:
		(void) stmf_msg_rx(m);
		break;

	default:
		ASSERT(0);
	}
}

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
static stmf_ic_msg_status_t
stmf_ic_tx_so(pppt_conn_msg_t *msg)
{
	int ret;
	size_t sent;
#if 0
	cmn_err(CE_WARN, "tx begin");
#endif
	if (pppt_conn.ic_conn_server) {
 		ret = ksocket_send(pppt_conn.ic_srv_socket, msg->msgbuf, msg->size,
			0, &sent, CRED());
	} else {
		ret = ksocket_send(pppt_conn.ic_cli_socket, msg->msgbuf, msg->size,
			0, &sent, CRED());
	}
	if ((ret != 0) || (sent != msg->size)) {
		cmn_err(CE_WARN, "stmf ic tx so send failed, ret:%d, sent:%d",
			ret, (int)sent);
#if 1
		/* ksocket connet error, to reconnect ksocket */
		pppt_conn.ic_conn_success = B_FALSE;
		if (!pppt_conn.ic_conn_server) {
			mutex_enter(&pppt_conn.ic_tx_mutex);
			cv_signal(&pppt_conn.ic_tx_cv);
			mutex_exit(&pppt_conn.ic_tx_mutex);
		}
		return STMF_IC_MSG_IC_DOWN;
#endif
	}
#if 0
	cmn_err(CE_WARN, "tx end");
#endif
	return STMF_IC_MSG_SUCCESS;
}
#endif

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
static stmf_ic_msg_status_t
stmf_ic_so_transmit(char *buf, size_t size, boolean_t can_retry)
#else
static stmf_ic_msg_status_t
stmf_ic_so_transmit(char *buf, size_t size)
#endif
{
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
	pppt_conn_msg_t *msg = NULL;
	char *buffer = NULL;
	uint32_t	buflen = 0;
	
	msg = kmem_alloc(sizeof(pppt_conn_msg_t), KM_SLEEP);
	buffer = kmem_alloc(size + sizeof(buflen), KM_SLEEP);

	buflen = htonl(size);
	bcopy(&buflen, buffer, sizeof(buflen));
	bcopy(buf, buffer + sizeof(buflen), size);
	msg->msgbuf = buffer;
	msg->size = size + sizeof(buflen);

	mutex_enter(&pppt_conn.ic_global_lock);
	stmf_ic_tx_so(msg);
	mutex_exit(&pppt_conn.ic_global_lock);

	stmf_ic_tx_complete(msg);

#elif (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
	int ret;
	int flags = ZFS_HBX_TX_FLAG_REPLY;
	if (can_retry) {
		flags |= ZFS_HBX_TX_FLAG_RETRY;
	}
	ret = zfs_hbx_tran_data(buf, size, EVT_PPPT_HBX_TRANSMIT, flags);
	if (ret != 0) {
		cmn_err(CE_WARN, "stmf ic so transmit failed, ret:%d", ret);

		if (zfs_hbx_link_state_get() == LINK_DOWN) {
			pppt_conn.ic_conn_success = B_FALSE;
			mutex_enter(&pppt_conn.ic_tx_mutex);
			cv_signal(&pppt_conn.ic_tx_cv);
			mutex_exit(&pppt_conn.ic_tx_mutex);
			return (STMF_IC_MSG_IC_DOWN);
		} else {
			return (STMF_IC_MSG_TIMED_OUT);
		}
	}
#endif	
	return (STMF_IC_MSG_SUCCESS);
}

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
static pppt_conn_msg_t *
stmf_ic_rx_so(int *error)
{
	int ret;
	uint32_t buflen = 0;
	size_t recv;
	pppt_conn_msg_t *rx_msg = NULL;

#if 0
	cmn_err(CE_WARN, "rx begin");
#endif
	*error = 0;	
	if (pppt_conn.ic_conn_server) {
		ret = ksocket_recv(pppt_conn.ic_srv_socket, &buflen, sizeof(buflen),
			MSG_WAITALL, &recv, CRED());
	} else {
		ret = ksocket_recv(pppt_conn.ic_cli_socket, &buflen, sizeof(buflen),
			MSG_WAITALL, &recv, CRED());
	}
	
	if ((ret != 0) || (recv != sizeof(buflen))) {
		if (ret == EAGAIN) {
			*error = ret;
			return (NULL);
		}

		cmn_err(CE_WARN, "stmf ic rx so recv buf len failed,ret:%d, recv:%u",
			ret, (uint32_t)recv);
		*error = (-1);
		return (NULL);
	}
	buflen = ntohl(buflen);

	if (buflen == 0) {
		cmn_err(CE_WARN, "stmf ic rx so recv buf len is 0");
		return (NULL);
	}

	rx_msg = kmem_zalloc(sizeof(pppt_conn_msg_t), KM_SLEEP);
	rx_msg->msgbuf = kmem_alloc(buflen, KM_SLEEP);

	if (pppt_conn.ic_conn_server) {
		ret = ksocket_recv(pppt_conn.ic_srv_socket, rx_msg->msgbuf, buflen,
			MSG_WAITALL, &recv, CRED());
	} else {
		ret = ksocket_recv(pppt_conn.ic_cli_socket, rx_msg->msgbuf, buflen,
			MSG_WAITALL, &recv, CRED());
	}
	if ((ret != 0) || (recv != buflen)) {
		kmem_free(rx_msg->msgbuf, buflen);
		kmem_free(rx_msg, sizeof(pppt_conn_msg_t));

		cmn_err(CE_WARN, "stmf ic rx recv buffer failed, ret:%d, recv:%u, buflen:%u",
			ret, (uint32_t)recv, buflen);
		if (ret == EAGAIN) {
			*error = ret;
			return (NULL);
		} else {
			*error = (-1);
			return (NULL);
		}
	}
#if 0
	cmn_err(CE_WARN, "rx end");
#endif
	rx_msg->size = buflen;
DONE:
	return (rx_msg);
}

/* to make sure the connection is reliable */
static int
stmf_ic_so_magic(uint32_t hostid)
{
	int ret = 0;
	uint32_t	value;
	size_t sent, recv;

	if (hostid % 2) {
		value = TX_MAGIC;
		
		ret = ksocket_send(pppt_conn.ic_srv_socket, &value, sizeof(value),
			0, &sent, CRED());
		if ((ret != 0) || (sent != sizeof(value))) {
			cmn_err(CE_WARN, "server send value failed");
			return (-1);
		}
		cmn_err(CE_WARN, "server have sent magic");
		ret = ksocket_recv(pppt_conn.ic_srv_socket, &value, sizeof(value),
			MSG_WAITALL, &recv, CRED());
		if ((ret != 0) || (recv != sizeof(value))) {
			cmn_err(CE_WARN, "server receive failed");
			return (-1);
		}
		cmn_err(CE_WARN, "server receive value is 0x%x", value);
	}  else {
		
		ret = ksocket_recv(pppt_conn.ic_cli_socket, &value, sizeof(value),
			MSG_WAITALL, &recv, CRED());
		if ((ret != 0) || (recv != sizeof(value))) {
			cmn_err(CE_WARN, "magic client recv failed ret:%d, recv:%d, value:%u",
				ret, (int)recv, value);
			return (-1);
		}
		cmn_err(CE_WARN, "client receive value is 0x%x", value);

		value = RX_MAGIC;
		ret = ksocket_send(pppt_conn.ic_cli_socket, &value, sizeof(value),
			0, &sent, CRED());
		if ((ret != 0) || (sent != sizeof(value))) {
			cmn_err(CE_WARN, "client sent failed");
			return (-1);
		}
	}

	return 0;
}

static void
stmf_ic_tx_complete(pppt_conn_msg_t *msg)
{
	if (msg) {
		if (msg->msgbuf)
			kmem_free(msg->msgbuf, msg->size);

		kmem_free(msg, sizeof(pppt_conn_msg_t));
	}
}
#endif /* #if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET) */

static void
stmf_ic_rx_complete(pppt_conn_msg_t *msg)
{
	if (msg) {
		if (msg->msgbuf)
			kmem_free(msg->msgbuf, msg->size);
		kmem_free(msg, sizeof(pppt_conn_msg_t));
	}
}

static u_long
inet_addr(register char *cp)
{
	register u_long val, base, n;
	register char c;
	u_long parts[4], *pp = parts;

again:
	/*
	 * Collect number up to ``.''.
	 * Values are specified as for C:
	 * 0x=hex, 0=octal, other=decimal.
	 */
	val = 0; base = 10;
	if (*cp == '0') {
		if (*++cp == 'x' || *cp == 'X')
			base = 16, cp++;
		else
			base = 8;
	}
	while (c = *cp) {
		if (ISXDIGIT(c)) {
			if ((c - '0') >= base)
			    break;
			val = (val * base) + (c - '0');
			cp++;
			continue;
		}
		if (base == 16 && ISXDIGIT(c)) {
			val = (val << 4) + (c + 10 - (ISLOWER(c) ? 'a' : 'A'));
			cp++;
			continue;
		}
		break;
	}
	if (*cp == '.') {
		/*
		 * Internet format:
		 *	a.b.c.d
		 *	a.b.c	(with c treated as 16-bits)
		 *	a.b	(with b treated as 24 bits)
		 */
		if (pp >= parts + 4)
			return (-1);
		*pp++ = val, cp++;
		goto again;
	}
	/*
	 * Check for trailing characters.
	 */
	if (*cp && !ISSPACE(*cp))
		return (-1);
	*pp++ = val;
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts;
	switch (n) {

	case 1:				/* a -- 32 bits */
		val = parts[0];
		break;

	case 2:				/* a.b -- 8.24 bits */
		val = (parts[0] << 24) | (parts[1] & 0xffffff);
		break;

	case 3:				/* a.b.c -- 8.8.16 bits */
		val = (parts[0] << 24) | ((parts[1] & 0xff) << 16) |
			(parts[2] & 0xffff);
		break;

	case 4:				/* a.b.c.d -- 8.8.8.8 bits */
		val = (parts[0] << 24) | ((parts[1] & 0xff) << 16) |
		      ((parts[2] & 0xff) << 8) | (parts[3] & 0xff);
		break;

	default:
		return (-1);
	}
	val = htonl(val);
	return (val);
}

int
stmf_modload(void)
{
	set_alua_state = stmf_set_alua_state;

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
	set_lu_state = stmf_set_lu_state;
	reset_lport = stmf_reset_lport;
#endif
	return (0);
}

static void
stmf_ic_conn_wakeup(void)
{
	if (pppt_conn.ic_tx_thr_wait) {
		cmn_err(CE_WARN, "stmf tx thr signal");
		mutex_enter(&pppt_conn.ic_tx_thr_lock);
		cv_signal(&pppt_conn.ic_tx_thr_cv);
		mutex_exit(&pppt_conn.ic_tx_thr_lock);
	}

	if (pppt_conn.ic_rx_thr_wait) {
		cmn_err(CE_WARN, "stmf rx thr signal");
		mutex_enter(&pppt_conn.ic_rx_thr_lock);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
		cv_broadcast(&pppt_conn.ic_rx_thr_cv);
#else
		cv_signal(&pppt_conn.ic_rx_thr_cv);
#endif
		mutex_exit(&pppt_conn.ic_rx_thr_lock);
	}
	return;
}

static void
stmf_ic_tx_thr_wait(void)
{
	mutex_enter(&pppt_conn.ic_tx_thr_lock);
	pppt_conn.ic_tx_thr_wait = B_TRUE;
	cv_wait(&pppt_conn.ic_tx_thr_cv, &pppt_conn.ic_tx_thr_lock);
	pppt_conn.ic_tx_thr_wait = B_FALSE;
	mutex_exit(&pppt_conn.ic_tx_thr_lock);
}

static void
stmf_ic_rx_thr_wait(void)
{
	mutex_enter(&pppt_conn.ic_rx_thr_lock);
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
	if (!pppt_conn.ic_set_alua_state_complete) {
#endif
	pppt_conn.ic_rx_thr_wait = B_TRUE;
	cv_wait(&pppt_conn.ic_rx_thr_cv, &pppt_conn.ic_rx_thr_lock);
	pppt_conn.ic_rx_thr_wait = B_FALSE;
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
	}
#endif
	mutex_exit(&pppt_conn.ic_rx_thr_lock);
}

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
void
stmf_ic_so_disconnect(void)
{
	uint32_t hostid;

	mutex_enter(&pppt_conn.ic_global_lock);
	cmn_err(CE_WARN, "stmf ksocket disconnect");
	hostid = zone_get_hostid(NULL);
	if (hostid % 2) {
		if (pppt_conn.ic_srv_socket != NULL) {
			(void) ksocket_shutdown(pppt_conn.ic_srv_socket, SHUT_RDWR, CRED());
			(void) ksocket_close(pppt_conn.ic_srv_socket, CRED());
			pppt_conn.ic_srv_socket = NULL;
		}
	} else {
		if (pppt_conn.ic_cli_socket != NULL) {
			(void) ksocket_shutdown(pppt_conn.ic_cli_socket, SHUT_RDWR, CRED());
			(void) ksocket_close(pppt_conn.ic_cli_socket, CRED());
			pppt_conn.ic_cli_socket = NULL;
		}
	}
	mutex_exit(&pppt_conn.ic_global_lock);
}

static int
stmf_ic_init_srv_ksocket(void)
{
	int ret;
	const uint32_t on = 1, off = 0;
	struct sockaddr_in	sin;
	uint32_t hostid;
/*
	int32_t rcvbuf = 256*1024;
	int32_t sndbuf = 256*1024;
*/
	int32_t rcvbuf = 2*1024*1024;
	int32_t sndbuf = 2*1024*1024;

	hostid = zone_get_hostid(NULL);

	if (hostid % 2) {
		/* be socket server */
		pppt_conn.ic_conn_server = 1;
		
		if (0 != ksocket_socket(&pppt_conn.ic_socket, AF_INET,
			SOCK_STREAM, 0, KSOCKET_NOSLEEP, CRED())) {
			cmn_err(CE_WARN, "create ksocket failed");
			return (-1);
		}

		bzero(&sin, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(6543);
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		
		(void) ksocket_setsockopt(pppt_conn.ic_socket, SOL_SOCKET,
			SO_REUSEADDR, &on, sizeof (on), CRED());
		(void) ksocket_setsockopt(pppt_conn.ic_socket, SOL_SOCKET,
		    	SO_MAC_EXEMPT, (char *)&off, sizeof (off), CRED());

		ret = ksocket_bind(pppt_conn.ic_socket, (struct sockaddr *)&sin,
			sizeof(sin), CRED());
		if (ret == 0) {
			(void) ksocket_setsockopt(pppt_conn.ic_socket, SOL_SOCKET, SO_RCVBUF,
		    		(char *)&rcvbuf, sizeof (int), CRED());
			(void) ksocket_setsockopt(pppt_conn.ic_socket, SOL_SOCKET, SO_SNDBUF,
		    		(char *)&sndbuf, sizeof (int), CRED());
			(void) ksocket_setsockopt(pppt_conn.ic_socket, IPPROTO_TCP, TCP_NODELAY,
		    		(char *)&on, sizeof (on), CRED());
			ret = ksocket_listen(pppt_conn.ic_socket, 5, CRED());
			if (ret < 0) {
				cmn_err(CE_WARN, "socket listen failed");
				ksocket_shutdown(pppt_conn.ic_socket, SHUT_RDWR, CRED());
				ksocket_close(pppt_conn.ic_socket, CRED());
				return (-1);
			}
		} else {
			cmn_err(CE_WARN, "socket bind failed");
			ksocket_shutdown(pppt_conn.ic_socket, SHUT_RDWR, CRED());
			ksocket_close(pppt_conn.ic_socket, CRED());
			return (-1);
		}
	}
	
	return (0);
}

static void
stmf_ic_con_delay(int level)
{
	switch(level) {
	case 0:
		delay(5 * drv_usectohz(1000000));		/* wait 5 s*/
		break;
	case 1:
		delay(15 * drv_usectohz(1000000));		/* wait 15 s*/
		break;
	default:
		delay(30 * drv_usectohz(1000000));		/* wait 60 s*/
		break;
	}
}

static int
stmf_ic_so_watch(int hostid)
{
	int i, ret, retry = 0;
	int dontroute = 1, retry_level = 0;
	int nonblocking = 1, rval;
	const uint32_t on = 1, off = 0;
	struct sockaddr_in	sin;
	struct timeval tl = {5, 0};
	ksocket_t new_so;
	struct linger linger= {1, 5};
	uint32_t bufsize = 1048576*4;
	cluster_state_t cls_state = CLUSTER_INIT;
	
	if (hostid %2) {
		/*
		 * ksocket server
		 */
		cmn_err(CE_WARN, "to do accept");

		ret = ksocket_accept(pppt_conn.ic_socket, NULL, NULL,
			&new_so, CRED());
		if (ret == 0) {
			(void) ksocket_setsockopt(new_so, SOL_SOCKET, SO_MAC_EXEMPT,
		    		(char *)&off, sizeof (off), CRED());
			ksocket_setsockopt(new_so, SOL_SOCKET, SO_SNDBUF, (const void *)&bufsize,
				sizeof(uint32_t), CRED());
			ksocket_setsockopt(new_so, SOL_SOCKET, SO_RCVBUF, (const void *)&bufsize,
				sizeof(uint32_t), CRED());

			stmf_ic_so_disconnect();
			
			pppt_conn.ic_srv_socket = new_so;
			pppt_conn.ic_conn_success = B_TRUE;
			
			cmn_err(CE_WARN, "major socket accept success");
		} else {
			cmn_err(CE_WARN, "socket accept failed");
			return (-1);
		}
		
	} else {
		/*
		 * ksocket client
		 */
		sin.sin_family = AF_INET;
		sin.sin_port = htons(6543);
		sin.sin_addr.s_addr = inet_addr("10.10.2.1");

		cmn_err(CE_WARN, "minor ksocket connecting");
		/* secondly, connect ksocket server, retry several times */
		do {
			if (pppt_conn.ic_tx_thread_exit)
				return (-1);
			
			retry++;
			if (0 != ksocket_socket(&new_so, AF_INET,
				SOCK_STREAM, 0, KSOCKET_NOSLEEP, CRED())) {
				cmn_err(CE_WARN, "create ksocket failed");
				return (-1);
			}

			(void) ksocket_setsockopt(new_so, SOL_SOCKET,
		    		SO_REUSEADDR, &on, sizeof (on), CRED());
			(void) ksocket_setsockopt(new_so, SOL_SOCKET,
		    		SO_MAC_EXEMPT, (char *)&off, sizeof (off), CRED());
			
			nonblocking = 1;
			ret = ksocket_ioctl(new_so, FIONBIO, (intptr_t)&nonblocking, &rval,
	    		    CRED());
			if (ret != 0) {
				cmn_err(CE_WARN, "ksocket connect non block set failed,ret:%d", ret);
			}
			
			/* socket connect */
			for (i = 0; i < PPPT_KSOCKET_RETRY_TIMES; i++) {
				ret= ksocket_connect(new_so, (struct sockaddr *)&sin,
				    sizeof(sin), CRED());
				if (retry %10 == 0 && i == 0)
					cmn_err(CE_WARN, "ksocket reconnect ret value:%d, retry:%d, time:%d",
				    	    ret, i, retry);

				if (ret == 0 || ret == EISCONN) {
					/* socket success or already success */
					ret = 0;
					break;
				}

				if (ret == EINPROGRESS || ret == EALREADY) {
					/* TCP connect still in progress */
					delay(drv_usectohz(10000));		/* delay 10ms */
				} else {
					break;
				}
			}
			
			if (ret != 0 && new_so != NULL) {
				(void) ksocket_close(new_so, CRED());
			}
			
			delay(drv_usectohz(1000000));		/* delay 1s */
		}while(ret != 0);

		nonblocking = 0;
		ret = ksocket_ioctl(new_so, FIONBIO, (intptr_t)&nonblocking, &rval,
	    		    CRED());

		ksocket_setsockopt(new_so, SOL_SOCKET, SO_SNDBUF,
			(const void *)&bufsize, sizeof(uint32_t), CRED());
		ksocket_setsockopt(new_so, SOL_SOCKET, SO_RCVBUF,
			(const void *)&bufsize, sizeof(uint32_t), CRED());
		
		pppt_conn.ic_cli_socket = new_so;
		pppt_conn.ic_conn_success = B_TRUE;
		
	}

	return (0);
}
#endif /* #if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET) */

#if (PPPT_TRAN_WAY != PPPT_TRAN_USE_CLUSTERSAN)
/*
 * IC message send thread
 */
void
stmf_ic_tx_thread(void *arg)
{
	int ret, count = 0;
	pppt_conn_msg_t *tx_msg = NULL, *next;
	uint32_t	hostid;
	stmf_alua_state_desc_t alua_state = {0, 0};
	callb_cpr_t	cpr;

	CALLB_CPR_INIT(&cpr, &pppt_conn.ic_tx_thr_lock, callb_generic_cpr,
		"stmf_ic_tx_thread");
	pppt_conn.ic_tx_thread_running = B_TRUE;
	pppt_conn.ic_tx_thread_did = pppt_conn.ic_tx_thread->t_did;

	stmf_ic_tx_thr_wait();
	if (!pppt_conn.ic_tx_thread_exit) {
		hostid = zone_get_hostid(NULL);
		alua_state.alua_node = (hostid + 1) % 2;
		alua_state.alua_state = B_TRUE;
		alua_state.alua_psess = (uint64_t)((uintptr_t)PPPT_BROADCAST_SESS);

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
		ret = stmf_ic_init_srv_ksocket();
		if (ret) {
			cmn_err(CE_WARN, "init ksocket failed");
			goto DONE;
		}
#endif
		ret = stmf_modload();
		if (ret != 0) {
			cmn_err(CE_WARN, "pppt stmf mod load failed");
			goto DONE;
		}

	}
	while (!pppt_conn.ic_tx_thread_exit) {
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
		/* do connect of ksocket */
		ret = stmf_ic_so_watch(hostid);
		if (ret != 0) {
			cmn_err(CE_WARN, "pppt ksocket connect failed");
			if (pppt_conn.ic_tx_thread_exit)
				continue;
			/* wait from stmf service */
			stmf_ic_tx_thr_wait();
		} else {
			ret = set_alua_state(&alua_state);
			if (ret != 0) {
				cmn_err(CE_WARN, " set alua state failed, node:%d, state:%d",
				    alua_state.alua_node, alua_state.alua_state);
			}
			stmf_ic_conn_wakeup();

			if ((hostid % 2) == 0) {
				/* client, wait cv from transmit failed */
				mutex_enter(&pppt_conn.ic_tx_mutex);
				cv_wait(&pppt_conn.ic_tx_cv, &pppt_conn.ic_tx_mutex);
				mutex_exit(&pppt_conn.ic_tx_mutex);
			}
		}
#elif (PPPT_TRAN_WAY == PPPT_TRAN_USE_ZFS_HBX)
		/* wait zfs hbx link_state to up */
		mutex_enter(&pppt_conn.ic_conn_lock);
		if (zfs_hbx_link_state_get() == LINK_DOWN) {
			pppt_conn.ic_conn_success = B_FALSE;
			pppt_conn.ic_set_alua_state_complete = B_FALSE;
			cmn_err(CE_WARN, "pppt zfs_hbx connect failed");
			if (pppt_conn.ic_tx_thread_exit) {
				mutex_exit(&pppt_conn.ic_tx_thr_lock);
				continue;
			}
			cv_wait(&pppt_conn.ic_conn_cv, &pppt_conn.ic_conn_lock);
			mutex_exit(&pppt_conn.ic_conn_lock);
		} else {
			mutex_exit(&pppt_conn.ic_conn_lock);
			
			cmn_err(CE_NOTE, "pppt zfs_hbx connect success");
			pppt_conn.ic_conn_success = B_TRUE;
			ret = set_alua_state(&alua_state);
			pppt_conn.ic_set_alua_state_complete = B_TRUE;
			if (ret != 0) {
				cmn_err(CE_WARN, " set alua state failed, node:%d, state:%d",
				    alua_state.alua_node, alua_state.alua_state);
			}
			stmf_ic_conn_wakeup();

			/* wait cv from transmit failed */
			mutex_enter(&pppt_conn.ic_tx_mutex);
			cv_wait(&pppt_conn.ic_tx_cv, &pppt_conn.ic_tx_mutex);
			mutex_exit(&pppt_conn.ic_tx_mutex);
		}
#else
		goto DONE;
#endif
	}

DONE:
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
	if (pppt_conn.ic_socket != NULL) {
		(void) ksocket_shutdown(pppt_conn.ic_socket, SHUT_RDWR, CRED());
		(void) ksocket_close(pppt_conn.ic_socket, CRED());
		pppt_conn.ic_socket = NULL;
	}
	stmf_ic_so_disconnect();
#endif /* #if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET) */

	mutex_enter(&pppt_conn.ic_tx_thr_lock);
	CALLB_CPR_EXIT(&cpr);
	pppt_conn.ic_tx_thread_running = B_FALSE;
	thread_exit();
	/* NOTREACHED */
}
#endif /* #if (PPPT_TRAN_WAY != PPPT_TRAN_USE_CLUSTERSAN) */

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
/*
 * IC message recv thread
 */
void
stmf_ic_rx_thread(void *arg)
{
	int ret, error;
	int rx_eagain_times = 0;
	pppt_conn_msg_t *rx_msg = NULL;
	callb_cpr_t	cpr;
	stmf_ic_msg_queue_t *msg_queue = pppt_conn.ic_msg_queue;

	CALLB_CPR_INIT(&cpr, &pppt_conn.ic_rx_thr_lock, callb_generic_cpr,
		"stmf_ic_rx_thread");
	pppt_conn.ic_rx_thread_running = B_TRUE;
	pppt_conn.ic_rx_thread_did = pppt_conn.ic_rx_thread->t_did;

	while (!pppt_conn.ic_rx_thread_exit) {
		if (!pppt_conn.ic_conn_success)  {
			stmf_ic_rx_thr_wait();
			continue;
		}
		rx_msg = NULL;
		rx_msg = stmf_ic_rx_so(&error);
		if (error == EAGAIN && rx_eagain_times < PPPT_KSOCKET_EAGAIN_TIMES) {
			rx_eagain_times++;
			cmn_err(CE_WARN, "stmf ic rx eagain times:%d", rx_eagain_times);
			continue;
		} else if (error != 0) {
			rx_eagain_times = 0;
			stmf_ic_so_disconnect();
			/* ksocket connet error, to reconnect ksocket */
			pppt_conn.ic_conn_success = B_FALSE;
			if (!pppt_conn.ic_conn_server) {
				cmn_err(CE_WARN, "rx error, signal reconnect");
				mutex_enter(&pppt_conn.ic_tx_mutex);
				cv_signal(&pppt_conn.ic_tx_cv);
				mutex_exit(&pppt_conn.ic_tx_mutex);
			}
			continue;
		}

		rx_eagain_times = 0;
		if (rx_msg != NULL) {
			rx_msg->msg_queue_next = NULL;
			mutex_enter(&pppt_conn.task_msg_lock);
			if (msg_queue->queue_tail) {
				msg_queue->queue_tail->msg_queue_next= rx_msg;
			} else {
				msg_queue->queue_head = rx_msg;
			}
			msg_queue->queue_tail = rx_msg;
			if (++(msg_queue->queue_depth) > msg_queue->queue_max_depth) {
				msg_queue->queue_max_depth = msg_queue->queue_depth;
			}
			if ((msg_queue->queue_flags & QUEUE_ACTIVE) == 0) {
				cv_signal(&msg_queue->queue_cv);
			}
			mutex_exit(&pppt_conn.task_msg_lock);
		} else {
			cmn_err(CE_WARN, "rx msg is null");
		}
	}
	mutex_enter(&pppt_conn.ic_rx_thr_lock);
	CALLB_CPR_EXIT(&cpr);
	pppt_conn.ic_rx_thread_running = B_FALSE;
	/* should not be reached, thread to exit */
	thread_exit();
	
}

void
stmf_ic_handle_msg_thread(void *arg)
{
	stmf_ic_msg_queue_t *msg_queue = (stmf_ic_msg_queue_t*)arg;
	pppt_conn_msg_t	*msg;
	callb_cpr_t cpr;
	kmutex_t cpr_lock;
	
	mutex_init(&cpr_lock, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cpr, &cpr_lock,
		callb_generic_cpr, "stmf_ic_msg_handle");

	mutex_enter(&pppt_conn.task_msg_lock);
	pppt_conn.ic_handle_msg_thread_running = B_TRUE;
	pppt_conn.ic_handle_msg_thread_did = curthread->t_did;
	msg_queue->queue_flags |= QUEUE_ACTIVE;

	while(1) {
		if (pppt_conn.ic_handle_msg_thread_exit) {
			msg_queue->queue_flags &= ~QUEUE_ACTIVE;
			mutex_exit(&pppt_conn.task_msg_lock);
			
			mutex_enter(&cpr_lock);
			CALLB_CPR_EXIT(&cpr);
			mutex_destroy(&cpr_lock);

#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET)
			pppt_conn.ic_rx_thread_running = B_FALSE;
#endif
			thread_exit();
			return;
		}

		while (1) {
			if ((msg = msg_queue->queue_head) == NULL ||
					pppt_conn.ic_handle_msg_thread_exit)
				break;

			msg_queue->queue_head = msg->msg_queue_next;
			if (msg_queue->queue_head == NULL)
				msg_queue->queue_tail = NULL;
			mutex_exit(&pppt_conn.task_msg_lock);

			stmf_ic_rx_msg(msg->msgbuf, msg->size, NULL);
			stmf_ic_rx_complete(msg);

			mutex_enter(&pppt_conn.task_msg_lock);
			msg_queue->queue_depth--;
		}

		if(!pppt_conn.ic_handle_msg_thread_exit) {
			msg_queue->queue_flags &= ~QUEUE_ACTIVE;
			cv_wait(&msg_queue->queue_cv, &pppt_conn.task_msg_lock);
			msg_queue->queue_flags |= QUEUE_ACTIVE;
		}
	}
}
#endif /* #if (PPPT_TRAN_WAY == PPPT_TRAN_USE_KSOCKET) */

void
stmf_ic_ksocket_wakeup(void)
{
	stmf_ic_conn_wakeup();
}

/*
 * IC message allocation routines.
 */

stmf_ic_msg_t *
stmf_ic_reg_port_msg_alloc(
    scsi_devid_desc_t *port_id,
    uint16_t relative_port_id,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_reg_port_msg_t *icrp = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_REGISTER_PROXY_PORT, msgid);
	icrp = (stmf_ic_reg_port_msg_t *)kmem_zalloc(sizeof (*icrp), KM_SLEEP);
	icm->icm_msg = (void *)icrp;

	icrp->icrp_port_id = scsi_devid_desc_dup(port_id);
	icrp->icrp_local_hostid = zone_get_hostid(NULL);
	icrp->icrp_relative_port_id = relative_port_id;

	if (cb_arg_len) {
		icrp->icrp_cb_arg_len = cb_arg_len;
		icrp->icrp_cb_arg = cb_arg;
	}

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_dereg_port_msg_alloc(
    scsi_devid_desc_t *port_id,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_dereg_port_msg_t *icdp = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_DEREGISTER_PROXY_PORT, msgid);
	icdp = (stmf_ic_dereg_port_msg_t *)kmem_zalloc(sizeof (*icdp),
	    KM_SLEEP);
	icm->icm_msg = (void *)icdp;

	icdp->icdp_port_id = scsi_devid_desc_dup(port_id);

	if (cb_arg_len) {
		icdp->icdp_cb_arg_len = cb_arg_len;
		icdp->icdp_cb_arg = cb_arg;
	}

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_reg_lun_msg_alloc(
    uint8_t *lun_id,
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_reg_dereg_lun_msg_alloc(STMF_ICM_REGISTER_LUN, lun_id,
	    lu_provider_name, cb_arg_len, cb_arg, msgid));
}

stmf_ic_msg_t *
stmf_ic_lun_active_msg_alloc(
    uint8_t *lun_id,
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_reg_dereg_lun_msg_alloc(STMF_ICM_LUN_ACTIVE, lun_id,
	    lu_provider_name, cb_arg_len, cb_arg, msgid));
}

stmf_ic_msg_t *
stmf_ic_lun_deactive_msg_alloc(
    uint8_t *lun_id,
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_reg_dereg_lun_msg_alloc(STMF_ICM_LUN_DEACTIVE, lun_id,
	    lu_provider_name, cb_arg_len, cb_arg, msgid));
}

stmf_ic_msg_t *
stmf_ic_dereg_lun_msg_alloc(
    uint8_t *lun_id,
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_reg_dereg_lun_msg_alloc(STMF_ICM_DEREGISTER_LUN, lun_id,
	    lu_provider_name, cb_arg_len, cb_arg, msgid));
}

/*
 * Guts of lun register/deregister/active alloc routines.
 */
static stmf_ic_msg_t *
stmf_ic_reg_dereg_lun_msg_alloc(
    stmf_ic_msg_type_t msg_type,
    uint8_t *lun_id,
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_reg_dereg_lun_msg_t *icrl = NULL;

	icm = stmf_ic_alloc_msg_header(msg_type, msgid);
	icrl = (stmf_ic_reg_dereg_lun_msg_t *)
	    kmem_zalloc(sizeof (*icrl), KM_SLEEP);
	icm->icm_msg = (void *)icrl;

	icrl->icrl_lu_provider_name = stmf_ic_strdup(lu_provider_name);

	bcopy(lun_id, icrl->icrl_lun_id, sizeof (icrl->icrl_lun_id));

	if (cb_arg_len) {
		icrl->icrl_cb_arg_len = cb_arg_len;
		icrl->icrl_cb_arg = cb_arg;
	}

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_scsi_cmd_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    scsi_task_t *task,
    uint32_t db_relative_offset,
    uint32_t immed_data_len,
    uint8_t *immed_data,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_scsi_cmd_msg_t *icsc = NULL;
	scsi_devid_desc_t *ini_devid = task->task_session->ss_rport_id;
	scsi_devid_desc_t *tgt_devid = task->task_lport->lport_id;
	stmf_remote_port_t *rport = task->task_session->ss_rport;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_SCSI_CMD, msgid);
	icsc = (stmf_ic_scsi_cmd_msg_t *)kmem_zalloc(sizeof (*icsc), KM_SLEEP);
	icm->icm_msg = (void *)icsc;

	icsc->icsc_task_msgid = task_msgid;
	icsc->icsc_ini_devid = scsi_devid_desc_dup(ini_devid);
	icsc->icsc_tgt_devid = scsi_devid_desc_dup(tgt_devid);
	icsc->icsc_rport = remote_port_dup(rport);
	icsc->icsc_session_id = task->task_session->ss_session_id;

	if (!task->task_mgmt_function && task->task_lu->lu_id) {
		bcopy(task->task_lu->lu_id->ident,
		    icsc->icsc_lun_id, sizeof (icsc->icsc_lun_id));
	}

	bcopy(task->task_lun_no, icsc->icsc_task_lun_no,
	    sizeof (icsc->icsc_task_lun_no));

	icsc->icsc_task_expected_xfer_length = task->task_expected_xfer_length;
	if (task->task_cdb_length) {
		ASSERT(task->task_mgmt_function == TM_NONE);
		icsc->icsc_task_cdb_length = task->task_cdb_length;
		icsc->icsc_task_cdb =
		    (uint8_t *)kmem_zalloc(task->task_cdb_length, KM_SLEEP);
		bcopy(task->task_cdb, icsc->icsc_task_cdb,
		    task->task_cdb_length);
	}

	icsc->icsc_task_flags = task->task_flags;
	icsc->icsc_task_priority = task->task_priority;
	icsc->icsc_task_mgmt_function = task->task_mgmt_function;
	icsc->icsc_db_relative_offset = db_relative_offset;
	icsc->icsc_immed_data_len = immed_data_len;
	icsc->icsc_immed_data = immed_data;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_scsi_data_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    uint64_t session_id,
    uint8_t *lun_id,
    uint64_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_scsi_data_msg_t *icsd = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_SCSI_DATA, msgid);
	icsd = (stmf_ic_scsi_data_msg_t *)kmem_zalloc(sizeof (*icsd), KM_SLEEP);
	icm->icm_msg = (void *)icsd;
#if 0
	cmn_err(CE_WARN, "send data = %lld", (longlong_t)data_len);
#endif
	icsd->icsd_task_msgid = task_msgid;
	icsd->icsd_session_id = session_id;
	bcopy(lun_id, icsd->icsd_lun_id, sizeof (icsd->icsd_lun_id));
	icsd->icsd_data_len = data_len;
	icsd->icsd_data = data;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_scsi_data_xfer_done_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    uint64_t session_id,
    stmf_status_t status,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_scsi_data_xfer_done_msg_t *icsx = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_SCSI_DATA_XFER_DONE, msgid);
	icsx = (stmf_ic_scsi_data_xfer_done_msg_t *)kmem_zalloc(
	    sizeof (*icsx), KM_SLEEP);
	icm->icm_msg = (void *)icsx;

	icsx->icsx_task_msgid = task_msgid;
	icsx->icsx_session_id = session_id;
	icsx->icsx_status = status;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_scsi_data_req_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    uint64_t session_id,
    uint8_t *lun_id,
    uint32_t offset,
    uint32_t len,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_scsi_data_req_msg_t *icsq = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_SCSI_DATA_REQ, msgid);
	icsq = (stmf_ic_scsi_data_req_msg_t *)kmem_zalloc(sizeof(*icsq),
							  KM_SLEEP);
	icm->icm_msg = (void *)icsq;

	icsq->icsq_task_msgid = task_msgid;
	icsq->icsq_session_id = session_id;
	bcopy(lun_id, icsq->icsq_lun_id, sizeof(icsq->icsq_lun_id));
	icsq->icsq_offset = offset;
	icsq->icsq_len = len;

	return icm;
}

stmf_ic_msg_t *
stmf_ic_scsi_data_res_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    uint8_t *data,
    uint32_t offset,
    uint32_t len,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_scsi_data_res_msg_t *icds = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_SCSI_DATA_RES, msgid);
	icds = (stmf_ic_scsi_data_res_msg_t *)kmem_zalloc(sizeof(*icds),
							  KM_SLEEP);
	icm->icm_msg = icds;

	icds->icds_task_msgid = task_msgid;
	icds->icds_data_offset = offset;
	icds->icds_data_len = len;
	icds->icds_data = data;

	return icm;
}

stmf_ic_msg_t *
stmf_ic_scsi_status_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    uint64_t session_id,
    uint8_t *lun_id,
    uint8_t response,
    uint8_t status,
    uint8_t flags,
    uint32_t resid,
    uint8_t sense_len,
    uint8_t *sense,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_scsi_status_msg_t *icss = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_SCSI_STATUS, msgid);
	icss = (stmf_ic_scsi_status_msg_t *)kmem_zalloc(sizeof (*icss),
	    KM_SLEEP);
	icm->icm_msg = (void *)icss;

	icss->icss_task_msgid = task_msgid;
	icss->icss_session_id = session_id;
	bcopy(lun_id, icss->icss_lun_id, sizeof (icss->icss_lun_id));
	icss->icss_response = response;
	icss->icss_status = status;
	icss->icss_flags = flags;
	icss->icss_resid = resid;
	icss->icss_sense_len = sense_len;
	icss->icss_sense = sense;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_r2t_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    uint64_t session_id,
    uint32_t offset,
    uint32_t length,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_r2t_msg_t *icrt = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_R2T, msgid);
	icrt = (stmf_ic_r2t_msg_t *)kmem_zalloc(sizeof (*icrt), KM_SLEEP);
	icm->icm_msg = (void *)icrt;

	icrt->icrt_task_msgid = task_msgid;
	icrt->icrt_session_id = session_id;
	icrt->icrt_offset = offset;
	icrt->icrt_length = length;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_status_msg_alloc(
    stmf_status_t status,
    stmf_ic_msg_type_t msg_type,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_status_msg_t *ics = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_STATUS, msgid);
	ics = (stmf_ic_status_msg_t *)kmem_zalloc(sizeof (*ics), KM_SLEEP);
	icm->icm_msg = (void *)ics;

	ics->ics_status = status;
	ics->ics_msg_type = msg_type;
	ics->ics_msgid = msgid;		/* XXX same as msgid in header */

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_session_create_msg_alloc(
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_session_create_destroy_msg_alloc(
	    STMF_ICM_SESSION_CREATE, session, msgid));
}

stmf_ic_msg_t *
stmf_ic_session_destroy_msg_alloc(
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_session_create_destroy_msg_alloc(
	    STMF_ICM_SESSION_DESTROY, session, msgid));
}

/*
 * Guts of session create/destroy routines.
 */
static stmf_ic_msg_t *
stmf_ic_session_create_destroy_msg_alloc(
    stmf_ic_msg_type_t msg_type,
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_session_create_destroy_msg_t *icscd = NULL;
	scsi_devid_desc_t *ini_devid = session->ss_rport_id;
	scsi_devid_desc_t *tgt_devid = session->ss_lport->lport_id;

	icm = stmf_ic_alloc_msg_header(msg_type, msgid);
	icscd = (stmf_ic_session_create_destroy_msg_t *)
	    kmem_zalloc(sizeof (*icscd), KM_SLEEP);
	icm->icm_msg = (void *)icscd;

	icscd->icscd_session_id = session->ss_session_id;
	icscd->icscd_ini_devid = scsi_devid_desc_dup(ini_devid);
	icscd->icscd_tgt_devid = scsi_devid_desc_dup(tgt_devid);
	icscd->icscd_rport = remote_port_dup(session->ss_rport);

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_echo_request_msg_alloc(
    uint32_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_echo_request_reply_msg_alloc(
	    STMF_ICM_ECHO_REQUEST, data_len, data, msgid));
}

stmf_ic_msg_t *
stmf_ic_echo_reply_msg_alloc(
    uint32_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_echo_request_reply_msg_alloc(
	    STMF_ICM_ECHO_REPLY, data_len, data, msgid));
}

static stmf_ic_msg_t *
stmf_ic_echo_request_reply_msg_alloc(
    stmf_ic_msg_type_t msg_type,
    uint32_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_echo_request_reply_msg_t *icerr = NULL;

	icm = stmf_ic_alloc_msg_header(msg_type, msgid);
	icerr = kmem_zalloc(sizeof (*icerr), KM_SLEEP);
	icm->icm_msg = (void *)icerr;

	icerr->icerr_data = data;
	icerr->icerr_datalen = data_len;

	return (icm);
}

static stmf_ic_msg_t *
stmf_ic_alua_state_sync_msg_alloc(
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_ALUA_STATE_SYNC, msgid);
	icm->icm_msg = (void *)NULL;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_notify_avs_master_state_msg_alloc(
	uint8_t *lun_id,
    char *lu_provider_name,
    uint32_t master_state,
	stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_notify_avs_master_state_msg_t *icnams = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_NOTIFY_AVS_MASTER_STATE,
		msgid);
	icnams = kmem_zalloc(sizeof(*icnams), KM_SLEEP);
	icm->icm_msg = icnams;
	icnams->icnams_lu_provider_name = stmf_ic_strdup(lu_provider_name);
	bcopy(lun_id, icnams->icnams_lun_id, sizeof (icnams->icnams_lun_id));
	icnams->icnams_avs_master_state = master_state;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_set_remote_sync_flag_msg_alloc(
	uint8_t *lun_id,
    char *lu_provider_name,
    uint32_t need_synced,
	stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_set_remote_sync_flag_msg_t *icrrsd = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_SET_REMOTE_SYNC_FLAG,
		msgid);
	icrrsd = kmem_zalloc(sizeof(*icrrsd), KM_SLEEP);
	icm->icm_msg = icrrsd;
	icrrsd->ic_lu_provider_name = stmf_ic_strdup(lu_provider_name);
	bcopy(lun_id, icrrsd->ic_lun_id, sizeof (icrrsd->ic_lun_id));
	icrrsd->ic_need_synced = need_synced;

	return (icm);
}


/*
 * msg free routines.
 */
void
stmf_ic_msg_free(stmf_ic_msg_t *msg)
{

	stmf_ic_msg_flag_t cmethod = msg->icm_msg_flags;

	switch (msg->icm_msg_type) {
	case STMF_ICM_REGISTER_PROXY_PORT:
		stmf_ic_reg_port_msg_free(
		    (stmf_ic_reg_port_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_DEREGISTER_PROXY_PORT:
		stmf_ic_dereg_port_msg_free(
		    (stmf_ic_dereg_port_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_LUN_ACTIVE:
	case STMF_ICM_LUN_DEACTIVE:	
	case STMF_ICM_REGISTER_LUN:
	case STMF_ICM_DEREGISTER_LUN:
		stmf_ic_reg_dereg_lun_msg_free(
		    (stmf_ic_reg_dereg_lun_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_SCSI_CMD:
		stmf_ic_scsi_cmd_msg_free(
		    (stmf_ic_scsi_cmd_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_SCSI_DATA:
		stmf_ic_scsi_data_msg_free(
		    (stmf_ic_scsi_data_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_SCSI_DATA_XFER_DONE:
		stmf_ic_scsi_data_xfer_done_msg_free(
		    (stmf_ic_scsi_data_xfer_done_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_SCSI_STATUS:
		stmf_ic_scsi_status_msg_free(
		    (stmf_ic_scsi_status_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_SCSI_DATA_REQ:
		stmf_ic_scsi_data_req_msg_free(
		    (stmf_ic_scsi_data_req_msg_t *)msg->icm_msg, cmethod);
		break;
	case STMF_ICM_SCSI_DATA_RES:
		stmf_ic_scsi_data_res_msg_free(
		    (stmf_ic_scsi_data_res_msg_t *)msg->icm_msg, cmethod);
		break;
			
	case STMF_ICM_R2T:
		stmf_ic_r2t_msg_free(
		    (stmf_ic_r2t_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_STATUS:
		stmf_ic_status_msg_free(
		    (stmf_ic_status_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_SESSION_CREATE:
	case STMF_ICM_SESSION_DESTROY:
		stmf_ic_session_create_destroy_msg_free(
		    (stmf_ic_session_create_destroy_msg_t *)msg->icm_msg,
		    cmethod);
		break;

	case STMF_ICM_ECHO_REQUEST:
	case STMF_ICM_ECHO_REPLY:
		stmf_ic_echo_request_reply_msg_free(
		    (stmf_ic_echo_request_reply_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_ALUA_STATE_SYNC:
		/* do nothing */
		break;

	case STMF_ICM_NOTIFY_AVS_MASTER_STATE:
		stmf_ic_notify_avs_master_state_msg_free(
			(stmf_ic_notify_avs_master_state_msg_t *)msg->icm_msg,
			cmethod);
		break;

	case STMF_ICM_SET_REMOTE_SYNC_FLAG:
		stmf_ic_set_remote_sync_flag_msg_free(
			(stmf_ic_set_remote_sync_flag_msg_t *)msg->icm_msg,
			cmethod);
		break;

	case STMF_ICM_MAX_MSG_TYPE:
		ASSERT(0);
		break;

	default:
		ASSERT(0);
	}
#if 0
	if (msg->icm_nvlist)
		nvlist_free(msg->icm_nvlist);
#endif
	kmem_free(msg, sizeof (*msg));
}

/*ARGSUSED*/
static void
stmf_ic_reg_port_msg_free(stmf_ic_reg_port_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	if(!m){
		cmn_err(CE_WARN, "%s the input is null ",__func__);
		return;
	}		
	scsi_devid_desc_free(m->icrp_port_id);

	kmem_free(m, sizeof (*m));
}


/*ARGSUSED*/
static void
stmf_ic_dereg_port_msg_free(stmf_ic_dereg_port_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	scsi_devid_desc_free(m->icdp_port_id);

	if (m->icdp_cb_arg_len && cmethod == STMF_ICM_MSG_XDR)
		kmem_free(m->icdp_cb_arg, m->icdp_cb_arg_len);
	kmem_free(m, sizeof (*m));
}


/*
 * Works for both reg_lun_msg and dereg_lun_msg, since the message
 * payload is the same.
 */
static void
stmf_ic_reg_dereg_lun_msg_free(stmf_ic_reg_dereg_lun_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	if (m->icrl_lu_provider_name != NULL) {
		kmem_free(m->icrl_lu_provider_name,
		    strlen(m->icrl_lu_provider_name) + 1);
	}

	if (m->icrl_cb_arg_len && cmethod == STMF_ICM_MSG_XDR) {
		kmem_free(m->icrl_cb_arg, m->icrl_cb_arg_len);
	}
	kmem_free(m, sizeof (*m));
}

static void
stmf_ic_scsi_cmd_msg_free(stmf_ic_scsi_cmd_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	scsi_devid_desc_free(m->icsc_ini_devid);
	scsi_devid_desc_free(m->icsc_tgt_devid);
	stmf_remote_port_free(m->icsc_rport);
	if (m->icsc_task_cdb) {
		kmem_free(m->icsc_task_cdb, m->icsc_task_cdb_length);
	}

	if (m->icsc_immed_data_len && cmethod == STMF_ICM_MSG_XDR)
		kmem_free(m->icsc_immed_data, m->icsc_immed_data_len);

	kmem_free(m, sizeof (*m));

}

/*ARGSUSED*/
static void
stmf_ic_scsi_data_msg_free(stmf_ic_scsi_data_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	if (m->icsd_data_len && cmethod == STMF_ICM_MSG_XDR) {
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		stmf_ic_kmem_free(m->icsd_data, m->icsd_data_len);
#else
		kmem_free(m->icsd_data, m->icsd_data_len);
#endif
	}
	kmem_free(m, sizeof (*m));
}

/*ARGSUSED*/
static void
stmf_ic_scsi_data_xfer_done_msg_free(stmf_ic_scsi_data_xfer_done_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	kmem_free(m, sizeof (*m));
}

/*ARGSUSED*/
static void
stmf_ic_scsi_status_msg_free(stmf_ic_scsi_status_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	if (m->icss_sense_len && cmethod == STMF_ICM_MSG_XDR)
		kmem_free(m->icss_sense, m->icss_sense_len);
	kmem_free(m, sizeof (*m));
}

/*ARGSUSED*/
static void
stmf_ic_scsi_data_req_msg_free(stmf_ic_scsi_data_req_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
    	kmem_free(m, sizeof(*m));
}

static void
stmf_ic_scsi_data_res_msg_free(stmf_ic_scsi_data_res_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
    if (m->icds_data_len && cmethod == STMF_ICM_MSG_XDR) {
#if (PPPT_TRAN_WAY == PPPT_TRAN_USE_CLUSTERSAN)
		stmf_ic_kmem_free(m->icds_data, m->icds_data_len);
#else
		kmem_free(m->icds_data, m->icds_data_len);
#endif
    }
	kmem_free(m, sizeof(*m));
}


/*ARGSUSED*/
static void
stmf_ic_r2t_msg_free(stmf_ic_r2t_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	kmem_free(m, sizeof (*m));
}

/*ARGSUSED*/
static void
stmf_ic_status_msg_free(stmf_ic_status_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	kmem_free(m, sizeof (*m));
}

/*
 * Works for both session_create and session_destroy msgs, since the message
 * payload is the same.
 */
/*ARGSUSED*/
static void
stmf_ic_session_create_destroy_msg_free(stmf_ic_session_create_destroy_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	scsi_devid_desc_free(m->icscd_ini_devid);
	scsi_devid_desc_free(m->icscd_tgt_devid);
	stmf_remote_port_free(m->icscd_rport);

	kmem_free(m, sizeof (*m));
}

/*ARGSUSED*/
static void
stmf_ic_echo_request_reply_msg_free(stmf_ic_echo_request_reply_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	if (m->icerr_datalen && cmethod == STMF_ICM_MSG_XDR)
		kmem_free(m->icerr_data, m->icerr_datalen);
	kmem_free(m, sizeof (*m));
}

static void
stmf_ic_notify_avs_master_state_msg_free(
	stmf_ic_notify_avs_master_state_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	if (m->icnams_lu_provider_name != NULL) {
		kmem_free(m->icnams_lu_provider_name,
		    strlen(m->icnams_lu_provider_name) + 1);
	}
	kmem_free(m, sizeof (*m));
}

static void
stmf_ic_set_remote_sync_flag_msg_free(
	stmf_ic_set_remote_sync_flag_msg_t *m,
    stmf_ic_msg_flag_t cmethod)
{
	if (m->ic_lu_provider_name != NULL) {
		kmem_free(m->ic_lu_provider_name,
		    strlen(m->ic_lu_provider_name) + 1);
	}
	kmem_free(m, sizeof (*m));
}


/*
 * Utility routines.
 */

static stmf_ic_msg_t *
stmf_ic_alloc_msg_header(
    stmf_ic_msg_type_t msg_type,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm;

	icm = (stmf_ic_msg_t *)kmem_zalloc(sizeof (*icm), KM_SLEEP);
	icm->icm_msg_type = msg_type;
	icm->icm_msgid = msgid;
	icm->icm_msg_flags = STMF_ICM_MSG_ALLOC;
	
	return (icm);
}


size_t
sizeof_scsi_devid_desc(int ident_length)
{
	int num_ident_elems;
	size_t size;

	ASSERT(ident_length > 0);

	/*
	 * Need to account for the fact that there's
	 * already a single element in scsi_devid_desc_t.
	 *
	 * XXX would really like to have a way to determine the
	 * sizeof (struct scsi_devid_desc.ident[0]), but
	 * it's not clear that can be done.
	 * Thus, this code relies on the knowledge of the type of
	 * that field.
	 */
	num_ident_elems = ident_length - 1;
	size = sizeof (scsi_devid_desc_t) +
	    (num_ident_elems * sizeof (uint8_t));

	return (size);
}

/*
 * Duplicate the scsi_devid_desc_t.
 */
static scsi_devid_desc_t *
scsi_devid_desc_dup(scsi_devid_desc_t *did)
{
	scsi_devid_desc_t *dup;
	size_t dup_size;

	ASSERT(did->ident_length > 0);

	dup_size = sizeof_scsi_devid_desc(did->ident_length);
	dup = (scsi_devid_desc_t *)kmem_zalloc(dup_size, KM_SLEEP);
	bcopy(did, dup, dup_size);
	return (dup);
}

/*
 * May be called with a null pointer.
 */
static void
scsi_devid_desc_free(scsi_devid_desc_t *did)
{
	if (!did)
		return;

	kmem_free(did, sizeof_scsi_devid_desc(did->ident_length));
}

/*
 * Duplicate the stmf_remote_port_t.
 */
static stmf_remote_port_t *
remote_port_dup(stmf_remote_port_t *rport)
{
	stmf_remote_port_t *dup = NULL;
	if (rport) {
		dup = stmf_remote_port_alloc(rport->rport_tptid_sz);
		bcopy(rport->rport_tptid, dup->rport_tptid,
		    rport->rport_tptid_sz);
	}
	return (dup);
}

/*
 * Helper functions, returns NULL if no memory.
 */
static char *
stmf_ic_strdup(char *str)
{
	char *copy;

	ASSERT(str);

	copy = kmem_zalloc(strlen(str) + 1, KM_SLEEP);
	(void) strcpy(copy, str);
	return (copy);
}

static inline void
stmf_ic_nvlookup_warn(const char *func, char *field)
{
	cmn_err(CE_WARN, "%s: nvlist lookup of %s failed", func, field);
}
