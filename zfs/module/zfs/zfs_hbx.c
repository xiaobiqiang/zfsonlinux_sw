/*
 * Copyright 2011 Ceresdata, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifdef _KERNEL
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/crc32.h>
#include <sys/dmu.h>
#include <sys/dmu_impl.h>
#include <sys/dmu_tx.h>
#include <sys/dbuf.h>
#include <sys/dnode.h>
#include <sys/zfs_context.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_synctask.h>
#include <sys/dsl_prop.h>
#include <sys/dmu_zfetch.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/zio_checksum.h>
#include <sys/sa.h>
#include <sys/arc.h>
#include <sys/callb.h>
#include <sys/zfs_mirror.h>
#include <sys/fs/zfs_hbx.h>
#include <sys/spa_impl.h>
#include <sys/cluster_san.h>

extern int cn_hbx_msg_send(const char *buf, size_t len);

static zfs_hbx_t zfs_hbx = {B_FALSE, };
static hb_event_list_t hb_para;

int zfs_hbx_timeout = 3000;					/* ms */
int zfs_hbx_timeout_cnt = 0;	
int zfs_hbx_mirror_tx_interval = 30;		/* ms */

int zfs_hbx_send_retry_times = 3;

static uint64_t zfs_hbx_sync_msg_id = 0;

extern zfs_mirror_mac_t *zfs_mirror_mac_port;

typedef struct zfs_hbx_prop_s {
	const char *name;
	const char *odd_value;
	const char *even_value;
} zfs_hbx_prop_t;

static zfs_hbx_prop_t hbx_prop_table[] = {
	{"timeout", 	NULL,	NULL		},
	{"link_state", 	"up",		"down"},
	{"major",		"locked",	"unlocked"},
	{"minor",		"locked",	"unlocked"}
};

#define	N_HBX_PROP		(sizeof(hbx_prop_table) / sizeof(hbx_prop_table[0]))

int zfs_hbx_link_state_get(void);
static int zfs_hbx_send(int hostid, void *data, uint64_t len, enum hbx_event_type event,
	boolean_t need_reply, int retry);
static void zfs_hbx_broadcast(void *data, uint64_t len, enum hbx_event_type event);
static int
zfs_hbx_sync_broadcase(void *data, uint64_t len, enum hbx_event_type event);

typedef void (*remote_pool_export_handle_t)(char *);

remote_pool_export_handle_t remote_pool_export_handler = NULL;

void
zfs_hbx_reg_pool_export_handler(remote_pool_export_handle_t handler)
{
	remote_pool_export_handler = handler;
}

static void zfs_hbx_list_para(char *string)
{
		char buffer[256] = {"\0"};
		
		strcpy(string, hbx_prop_table[0].name);
		string += strlen(hbx_prop_table[0].name);
		sprintf(buffer, "\t\t\t%dms\n", zfs_hbx_timeout);
		strcpy(string, buffer);
		string += strlen(buffer);

		strcpy(string, hbx_prop_table[1].name);
		string += strlen(hbx_prop_table[1].name);
		strcpy(string, "\t\t");
		string += 2;
		if (zfs_hbx.link_state == LINK_UP) {
			strcpy(string, hbx_prop_table[1].odd_value);
			string += strlen(hbx_prop_table[1].odd_value);
		} else {
			strcpy(string, hbx_prop_table[1].even_value);
			string += strlen(hbx_prop_table[1].even_value);
		}
		strcpy(string, "\n");
		string += 1;
		
		strcpy(string, hbx_prop_table[2].name);
		string += strlen(hbx_prop_table[2].name);
		strcpy(string, "\t\t\t");
		string += 3;
		if (zfs_hbx.major == INACTIVE) {
			strcpy(string, hbx_prop_table[2].even_value);
			string += strlen(hbx_prop_table[2].even_value);
		} else {
			strcpy(string, hbx_prop_table[2].odd_value);
			string += strlen(hbx_prop_table[2].odd_value);
		}
		strcpy(string, "\n");
		string += 1;

		strcpy(string, hbx_prop_table[3].name);
		string += strlen(hbx_prop_table[3].name);
		strcpy(string, "\t\t\t");
		string += 3;
		if (zfs_hbx.minor == INACTIVE) {
			strcpy(string, hbx_prop_table[3].even_value);
			string += strlen(hbx_prop_table[3].even_value);
		} else {
			strcpy(string, hbx_prop_table[3].odd_value);
			string += strlen(hbx_prop_table[3].odd_value);
		}
		strcpy(string, "\n");
		string += 1;
}

static void zfs_hbx_set_para(char *string, int value) {
	int i;
	for (i = 0;i < N_HBX_PROP; i++) {
		if (strstr(string, hbx_prop_table[i].name)) {
			switch (i) {
			case 0:
				/* set timeout value */
				if (value != 0)
					zfs_hbx_timeout = value;
				break;
			case 1:
				string = strchr(string, '=');
				if (string) {
					string += 1;
					if (strcmp(string, hbx_prop_table[i].odd_value) == 0) {
						zfs_hbx.link_state = LINK_UP;
					} else if (strcmp(string, hbx_prop_table[i].even_value) == 0) {
						zfs_hbx.link_state = LINK_DOWN;
					}
				}
				break;
			case 2:
				string = strchr(string, '=');
				if (string) {
					string += 1;
					if (strcmp(string, hbx_prop_table[i].odd_value) == 0 &&
						    (zfs_hbx.hb_host_id % 2)) {
						cmn_err(CE_WARN, "set major lock");
						zfs_hbx.major = ACTIVE;
					} else if (strcmp(string, hbx_prop_table[i].even_value) == 0 &&
					    (zfs_hbx.hb_host_id % 2)) {
						cmn_err(CE_WARN, "set major unlock");
						zfs_hbx.major = INACTIVE;
						}
				}
				break;
			case 3:
				string = strchr(string, '=');
				if (string) {
					string += 1;
					if (strcmp(string, hbx_prop_table[i].odd_value) == 0 &&
					    (!(zfs_hbx.hb_host_id % 2))) {
						cmn_err(CE_WARN, "set minor lock");
						zfs_hbx.minor = ACTIVE;
					} else if (strcmp(string, hbx_prop_table[i].even_value) == 0 &&
					    (!(zfs_hbx.hb_host_id % 2))) {
						cmn_err(CE_WARN, "set minor unlock");
						zfs_hbx.minor = INACTIVE;
					}
				}
				break;
			default:
				break;
			}
		}
	}
}

static void zfs_hbx_do_sync_spa_config(zfs_cmd_t *zc)
{
	uint64_t size;
	char *buffer;
	uint32_t remote_hostid;
	int ret;

	size = zc->zc_nvlist_conf_size;
	if (size != 0) {
		buffer = kmem_alloc(size, KM_SLEEP);
		if ((ret = ddi_copyin((void *)(uintptr_t)zc->zc_nvlist_conf, 
			buffer, size, 0)) != 0) {
			cmn_err(CE_NOTE, "%s: ddi copyin failed, size=0x%llx",
				__func__, size);
		} else {
			remote_hostid = *((uint32_t *)buffer);
			cluster_sync_spa_config_to_remote(remote_hostid);
		}
		kmem_free(buffer, size);
	}
}

static int zfs_hbx_do_get_updated_pools(zfs_cmd_t *zc, nvlist_t **nv_ptr)
{
	int ret;
	ret = zfs_mirror_get_updated_spa(zc->zc_perm_action, nv_ptr);
	return (ret);
}

static void zfs_hbx_do_remove_partner_spa_config(zfs_cmd_t *zc)
{
	char *spa_name = zc->zc_name;
	uint32_t remote_hostid = zc->zc_perm_action;
	nvlist_t *nvl;
	char *buf;
	size_t buflen;
	int ret;

	cluster_remove_remote_spa_config(remote_hostid, spa_name);
	/* notify other host */
	VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) == 0);
	VERIFY(nvlist_add_uint32(nvl, "remote_hostid", remote_hostid) == 0);
	VERIFY(nvlist_add_string(nvl, "spa_name", spa_name) == 0);

	VERIFY(nvlist_size(nvl, &buflen, NV_ENCODE_XDR) == 0);
	buf = kmem_alloc(buflen, KM_SLEEP);
	VERIFY(nvlist_pack(nvl, &buf, &buflen, NV_ENCODE_XDR,
	    KM_SLEEP) == 0);
	nvlist_free(nvl);
	ret = zfs_hbx_sync_broadcase(buf, buflen, EVT_IMPORT_REMOTE_POOL);
	kmem_free(buf, buflen);
	cmn_err(CE_NOTE, "%s: notify other host, remote hostid=%d, spa name: %s,"
		" ret:%d", __func__, remote_hostid, spa_name, ret);
}

static int zfs_hbx_do_change_pool_owner(zfs_cmd_t *zc)
{
	int ret;
	ret = cluster_remote_import_pool(zc->zc_perm_action, zc->zc_name);
	return (ret);
}

static int zfs_hbx_do_mac_state(zfs_cmd_t *zc)
{
	char *buffer;
	uint64_t size;
	int ret = -1;
	int hostid = zc->zc_perm_action;

	size = zc->zc_nvlist_conf_size;
	cmn_err(CE_NOTE, "send mac state event to host %d, len=0x%llx", hostid, size);
	if (size != 0) {
		buffer = kmem_alloc(size, KM_SLEEP);
		if ((ret = ddi_copyin((void *)(uintptr_t)zc->zc_nvlist_conf, 
			buffer, size, 0)) != 0) {
			cmn_err(CE_WARN, "%s: ddi copyin failed", __func__);
			kmem_free(buffer, size);
		} else {
			ret = zfs_hbx_send(hostid, buffer, size, EVT_MAC_STATE,
				B_TRUE, zfs_hbx_send_retry_times);
			kmem_free(buffer, size);
		}
	}
	return (ret);
}

static void zfs_hbx_do_send_ipmi_ip(zfs_cmd_t *zc)
{
	/* record local's ipmi ip addr */
	cluster_set_host_ipmi_ip(0, zc->zc_value);
	/* send ipmi ip addr to remote */
	cluster_send_ipmi_ip(zc->zc_perm_action, zc->zc_value);
}

static int zfs_hbx_do_get_ipmi_id(zfs_cmd_t *zc)
{
	int ret;
	ret = cluster_get_host_ipmi_ip(zc->zc_perm_action, zc->zc_value);
	return (ret);
}

static void zfs_hbx_do_mirror_timeout_switch(zfs_cmd_t *zc)
{
	uint64_t size;
	char *buffer;
	int ret;

	size = zc->zc_nvlist_conf_size;
	if (size != 0) {
		buffer = kmem_alloc(size, KM_SLEEP);
		if ((ret = ddi_copyin((void *)(uintptr_t)zc->zc_nvlist_conf, 
			buffer, size, 0)) != 0) {
			cmn_err(CE_NOTE, "ddi copyin failed");
			kmem_free(buffer, size);
		} else {
			cmn_err(CE_NOTE, "hbx ioc: set mirror timeout switch(%s)",
				buffer);
			if (strncmp("on", buffer, 2) == 0) {
				zfs_mirror_data_expired_switch(B_TRUE);
			} else if(strncmp("off", buffer, 3) == 0) {
				zfs_mirror_data_expired_switch(B_FALSE);
			}
			kmem_free(buffer, size);
		}
	}
}

static int zfs_hbx_do_release_pools(zfs_cmd_t *zc)
{
	char *buffer;
	uint64_t size;
	uint32_t hostid = zc->zc_perm_action;
	int ret = -1;

	size = zc->zc_nvlist_conf_size;
	cmn_err(CE_WARN, "send release pools event to host(%d), len=0x%llx",
		hostid, size);
	if (size != 0) {
		buffer = kmem_alloc(size, KM_SLEEP);
		if ((ret = ddi_copyin((void *)(uintptr_t)zc->zc_nvlist_conf, 
			buffer, size, 0)) != 0) {
			cmn_err(CE_NOTE, "%s: ddi copyin failed", __func__);
			kmem_free(buffer, size);
		} else {
			ret = zfs_hbx_send(hostid, buffer, size, EVT_RELEASE_POOLS,
				B_TRUE, zfs_hbx_send_retry_times);
			kmem_free(buffer, size);
		}
	}
	return (ret);
}

static int
zfs_hbx_do_cluster_import(zfs_cmd_t *zc)
{
	char *buffer;
	uint64_t size;
	uint32_t hostid = zc->zc_perm_action;
	int ret = -1;

	size = zc->zc_nvlist_conf_size;
	cmn_err(CE_WARN, "send cluster import event to host %u, len=0x%llx",
		hostid, size);
	if (size != 0) {
		buffer = kmem_alloc(size, KM_SLEEP);
		if ((ret = ddi_copyin((void *)(uintptr_t)zc->zc_nvlist_conf, 
			buffer, size, 0)) != 0) {
			cmn_err(CE_NOTE, "%s: ddi copyin failed", __func__);
			kmem_free(buffer, size);
		} else {
			if (hostid == 0)
				zfs_hbx_broadcast(buffer, size, EVT_CLUSTER_IMPORT);
			else
				ret = zfs_hbx_send(hostid, buffer, size, EVT_CLUSTER_IMPORT,
					B_TRUE, zfs_hbx_send_retry_times);
			kmem_free(buffer, size);
		}
	}
	return (ret);
}

static void
zfs_hbx_do_notify_pool_export(zfs_cmd_t *zc)
{
	zfs_hbx_broadcast(zc->zc_name, strlen(zc->zc_name) + 1, 
		EVT_POOL_EXPORT);
}

static void zfs_hbx_do_cluster_sync_cmd(zfs_cmd_t *zc)
{
	uint64_t size;
	char *buffer;
	int ret;

	size = zc->zc_nvlist_conf_size;
	if (size != 0) {
		buffer = kmem_alloc(size, KM_SLEEP);
		if ((ret = ddi_copyin((void *)(uintptr_t)zc->zc_nvlist_conf, 
			buffer, size, 0)) != 0) {
			cmn_err(CE_NOTE, "%s: ddi copyin failed, size=0x%llx",
				__func__, size);
			kmem_free(buffer, size);
		} else {
			cluster_san_remote_cmd_return(buffer, size);
		}
	}
}

static void zfs_hbx_do_host_is_need_faillover(zfs_cmd_t *zc)
{
	boolean_t need_failover;

	need_failover = cluster_host_need_failover(zc->zc_perm_action);
	if (need_failover) {
		zc->zc_guid = 1;
	} else {
		zc->zc_guid = 0;
	}
}

static void zfs_hbx_do_host_clr_need_faillover(zfs_cmd_t *zc)
{
	cluster_host_cancle_failover(zc->zc_perm_action);
	zfs_mirror_cancel_check_spa_txg(zc->zc_perm_action);
}

static void zfs_hbx_do_get_failover_host(zfs_cmd_t *zc)
{
	zc->zc_guid = cluster_get_failover_hostid();
}

int
zfs_hbx_do_ioc(zfs_cmd_t *zc, nvlist_t **nv_ptr)
{
	uint64_t cmd;
	int value, err = 0;
	char *string;

	cmd = zc->zc_cookie;
	string = zc->zc_string;
	value = zc->zc_perm_action;

	switch (cmd) {
	case ZFS_HBX_LIST:
		zfs_hbx_list_para(string);
		break;
	case ZFS_HBX_SET:
		zfs_hbx_set_para(string, value);
		break;
	case ZFS_HBX_SYNC_POOL:
		zfs_hbx_do_sync_spa_config(zc);
		break;
	case ZFS_HBX_GET_PARTNER_POOL:
		err = cluster_get_remote_spa_config(zc->zc_guid, nv_ptr);
		break;
	case ZFS_HBX_GET_PARTNER_UPDATED_POOL:
		err = zfs_hbx_do_get_updated_pools(zc, nv_ptr);
		break;
	case ZFS_HBX_REMOVE_PARTNER_POOL:
		zfs_hbx_do_remove_partner_spa_config(zc);
		break;
	case ZFS_HBX_CHANGE_POOL:
		err = zfs_hbx_do_change_pool_owner(zc);
		break;
	case ZFS_HBX_REQ_RELEASE_POOL:
		break;
	case ZFS_HBX_RELEASE_POOL_END:
		break;
	case ZFS_HBX_NIC_UPDATE:
		break;
	case ZFS_HBX_MPTSAS_DOWN:
		break;
	case ZFS_HBX_FC_DOWN:
		break;
	case ZFS_HBX_KEYFILE_UPDATE:
		break;
	case ZFS_HBX_KEYPATH_UPDATE:
		break;
	case ZFS_HBX_SYNCKEY_RESULT:
		break;
	case ZFS_HBX_RCMD_UPDATE:
		break;
	case ZFS_HBX_MAC_STAT:
		zfs_hbx_do_mac_state(zc);
		break;
	case ZFS_HBX_SEND_IPMI_IP:
		zfs_hbx_do_send_ipmi_ip(zc);
		break;
	case ZFS_HBX_REMOTE_IPMI_IP:
		break;
	case ZFS_HBX_GET_IMPI_IP:
		zfs_hbx_do_get_ipmi_id(zc);
		break;
	case ZFS_HBX_MIRROR_TIMEOUT_SWITCH:
		zfs_hbx_do_mirror_timeout_switch(zc);
		break;
	case ZFS_HBX_RELEASE_POOLS:
		zfs_hbx_do_release_pools(zc);
		break;
	case ZFS_HBX_CLUSTERSAN_SYNC_CMD:
		zfs_hbx_do_cluster_sync_cmd(zc);
		break;
	case ZFS_HBX_IS_NEED_FAILOVER:
		zfs_hbx_do_host_is_need_faillover(zc);
		break;
	case ZFS_HBX_CLR_NEED_FAILOVER:
		zfs_hbx_do_host_clr_need_faillover(zc);
		break;
	case ZFS_HBX_GET_FAILOVER_HOST:
		zfs_hbx_do_get_failover_host(zc);
		break;
	case ZFS_HBX_CLUSTER_IMPORT:
		zfs_hbx_do_cluster_import(zc);
		break;
	case ZFS_HBX_POOL_EXPORT:
		zfs_hbx_do_notify_pool_export(zc);
		break;
	default:
		cmn_err(CE_WARN, "hbx ioc cmd not found, %d", (int)cmd);
	}

	return (err);
}

static void
zfs_clear_hb_para(hbx_event_t *event)
{
	if (event){
		if ((event->b_data)&&(event->data) && (event->data_len != 0)) {
			kmem_free(event->data, event->data_len);
		}
		kmem_free(event, sizeof(hbx_event_t));
	}
}

static void
zfs_hbx_thr_wakeup(void)
{	
	cv_broadcast(&zfs_hbx.hb_thr_cv);
}

static void
zfs_set_hb_para(enum hbx_event_type type, char *data, uint64_t data_len)
{
	hbx_event_t *event;

	event = kmem_zalloc(sizeof(hbx_event_t), KM_SLEEP);
	event->link_state = zfs_hbx.link_state;
	event->major = zfs_hbx.major;
	event->minor = zfs_hbx.minor;
	event->type = type;
	if (data != NULL && data_len != 0) {
		event->data = data;
		event->data_len = data_len;
		event->b_data = B_TRUE;
	} else {
		event->data = NULL;
		event->data_len = 0;
		event->b_data = B_FALSE;
	}

	mutex_enter(&hb_para.event_mutex);
	list_insert_tail(&hb_para.event_list, event);
	mutex_exit(&hb_para.event_mutex);

	zfs_hbx_thr_wakeup();
}

void
zfs_hbx_reboot(char *str, int reboot_event, dev_event_t *devs,
	uint32_t dev_num)
{
	char *event_data;
	uint64_t data_len;
	
	cmn_err(CE_WARN, "%s\n", str);

	if (zfs_hbx.hb_initialized) {
		data_len = sizeof(dev_event_t) * dev_num;
		event_data = kmem_zalloc(data_len, KM_SLEEP);

		if (devs != NULL)
			bcopy(devs, event_data, data_len);
		zfs_set_hb_para(reboot_event, event_data, data_len);
	} else {
		cmn_err(CE_WARN, "hbx is not initialized");
	}
}

typedef struct zfs_hbx_msg_header {
	uint32_t hbx_msg_type;
	uint8_t pad[4];
	uint64_t msg_id;
} zfs_hbx_msg_header_t;

static int
zfs_hbx_send(int hostid, void *data, uint64_t len, enum hbx_event_type event,
	boolean_t need_reply, int retry)
{
	cluster_san_hostinfo_t *cshi;
	zfs_hbx_msg_header_t msg_header;
	int ret = 0;

	if (hostid == 0)
		hostid = cluster_get_failover_hostid();
	cshi = cluster_remote_hostinfo_hold(hostid);
	if (cshi == NULL || cshi == CLUSTER_SAN_BROADCAST_SESS) {
		cmn_err(CE_WARN, "%s: Can't find host %d in cluster",
			__func__, hostid);
		return (-1);
	}
	cmn_err(CE_WARN, "%s: send hbx event %d to remote %d",
		__func__, event, cshi->hostid);

	msg_header.hbx_msg_type = (uint32_t)event;
	ret = cluster_san_host_send(cshi, data, len, &msg_header,
		sizeof(zfs_hbx_msg_header_t), CLUSTER_SAN_MSGTYPE_ZFS_HBX,
		0, need_reply, retry);

	if (ret != 0) {
		cmn_err(CE_WARN, "%s: send hbx evt(%d) to host(%d) failed, ret=%d",
			__func__, event, hostid, ret);
	}

	return (ret);
}

static void
zfs_hbx_broadcast(void *data, uint64_t len, enum hbx_event_type event)
{
	zfs_hbx_msg_header_t msg_header;

	msg_header.hbx_msg_type = (uint32_t)event;
	cluster_san_broadcast_send(data, len, &msg_header,
		sizeof (zfs_hbx_msg_header_t), CLUSTER_SAN_MSGTYPE_ZFS_HBX, 0);
}

static int
zfs_hbx_sync_broadcase(void *data, uint64_t len, enum hbx_event_type event)
{
	zfs_hbx_msg_header_t msg_header;
	uint64_t sync_msg_id;
	int ret;

	msg_header.hbx_msg_type = (uint32_t)event;
	sync_msg_id = atomic_inc_64_nv(&zfs_hbx_sync_msg_id);
	msg_header.msg_id = sync_msg_id;
	ret = cluster_san_host_sync_send_msg(CLUSTER_SAN_BROADCAST_SESS,
		data, len, &msg_header, sizeof(zfs_hbx_msg_header_t),
		sync_msg_id, CLUSTER_SAN_MSGTYPE_ZFS_HBX, 30);
	return (ret);
}

static void zfs_hbx_rx_evt_mac_state_handle(cs_rx_data_t *cs_data)
{
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	char *buf;

	cmn_err(CE_WARN, "%s: from host(%d)", __func__,
		cshi->hostid);
	buf = kmem_zalloc(cs_data->data_len, KM_SLEEP);
	bcopy(cs_data->data, buf, cs_data->data_len);
	zfs_set_hb_para(EVT_MAC_STATE, buf, cs_data->data_len);
	csh_rx_data_free(cs_data, B_TRUE);
}

static void zfs_hbx_rx_evt_release_pools_handle(cs_rx_data_t *cs_data)
{
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	char *buf;

	cmn_err(CE_WARN, "%s: from host(%d)", __func__,
		cshi->hostid);
	buf = kmem_zalloc(cs_data->data_len, KM_SLEEP);
	bcopy(cs_data->data, buf, cs_data->data_len);
	zfs_set_hb_para(EVT_RELEASE_POOLS, buf, cs_data->data_len);
	csh_rx_data_free(cs_data, B_TRUE);
}

static void
zfs_hbx_rx_evt_cluster_import_handle(cs_rx_data_t *cs_data)
{
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	char *buf;

	cmn_err(CE_WARN, "%s: from host(%d)", __func__,
		cshi->hostid);
	buf = kmem_zalloc(cs_data->data_len, KM_SLEEP);
	bcopy(cs_data->data, buf, cs_data->data_len);
	zfs_set_hb_para(EVT_CLUSTER_IMPORT, buf, cs_data->data_len);
	csh_rx_data_free(cs_data, B_TRUE);
}

static void
zfs_hbx_rx_evt_import_remote_pool_handle(cs_rx_data_t *cs_data)
{
	zfs_hbx_msg_header_t *msg_header = cs_data->ex_head;
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	nvlist_t *nvl = NULL;
	char *spa_name = NULL;
	uint32_t remote_hostid = 0;
	int ret;

	ret = nvlist_unpack(cs_data->data, cs_data->data_len, &nvl, KM_SLEEP);
	if (ret == 0) {
		VERIFY(nvlist_lookup_uint32(nvl, "remote_hostid", &remote_hostid) == 0);
		VERIFY(nvlist_lookup_string(nvl, "spa_name", &spa_name) == 0);
		cmn_err(CE_NOTE, "%s: import hostid=%d, remote hostid=%d, spa name=%s",
			__func__, cshi->hostid, remote_hostid, spa_name);
		cluster_remove_remote_spa_config(remote_hostid, spa_name);
		nvlist_free(nvl);
	}
	cluster_san_host_sync_msg_ret(cshi, msg_header->msg_id,
		CLUSTER_SAN_MSGTYPE_ZFS_HBX, (uint64_t)ret);
	csh_rx_data_free(cs_data, B_TRUE);
}

static void
zfs_hbx_rx_evt_pool_export_handle(cs_rx_data_t *cs_data)
{
	cmn_err(CE_NOTE, "%s pool %s", __func__, cs_data->data);
	if (remote_pool_export_handler)
		remote_pool_export_handler(cs_data->data);
	csh_rx_data_free(cs_data, B_TRUE);
}

static void zfs_hbx_rx_cb(cs_rx_data_t *cs_data, void *arg)
{
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	zfs_hbx_msg_header_t *msg_header = cs_data->ex_head;
	enum hbx_event_type evt_type =
		(enum hbx_event_type)msg_header->hbx_msg_type;

	switch(evt_type) {
		case EVT_MAC_STATE:
			zfs_hbx_rx_evt_mac_state_handle(cs_data);
			break;
		case EVT_RELEASE_POOLS:
			zfs_hbx_rx_evt_release_pools_handle(cs_data);
			break;
		case EVT_CLUSTER_IMPORT:
			zfs_hbx_rx_evt_cluster_import_handle(cs_data);
			break;
		case EVT_IMPORT_REMOTE_POOL:
			zfs_hbx_rx_evt_import_remote_pool_handle(cs_data);
			break;
		case EVT_POOL_EXPORT:
			zfs_hbx_rx_evt_pool_export_handle(cs_data);
			break;
		default:
			cmn_err(CE_NOTE, "%s: invalid hbx event %d from host(%d)",
				__func__, evt_type, cshi->hostid);
			csh_rx_data_free(cs_data, B_TRUE);
			break;
	}
}

static void
zfs_hbx_thr_wait(callb_cpr_t *cpr, kcondvar_t *cv, uint64_t time)
{
	CALLB_CPR_SAFE_BEGIN(cpr);
	if (time)
		(void) cv_timedwait(cv, &zfs_hbx.hb_thr_lock,
		    ddi_get_lbolt() + time);
	else
		cv_wait(cv, &zfs_hbx.hb_thr_lock);
	CALLB_CPR_SAFE_END(cpr, &zfs_hbx.hb_thr_lock);
}

void
zfs_hbx_thr_work(void *arg)
{
	int err/*, index, time, i*/;
	callb_cpr_t cpr;
	char *buf = NULL;
	size_t bufsize;
	hbx_event_t *event = NULL;
	hb_event_list_t *event_list;
	hbx_door_para_t *door_para, door_pa;

	bufsize = 0;
	event_list = arg;
	door_para = &door_pa;
	bzero(door_para, sizeof(hbx_door_para_t));
	
	CALLB_CPR_INIT(&cpr, &zfs_hbx.hb_thr_lock, callb_generic_cpr, (char *)__func__);
	mutex_enter(&zfs_hbx.hb_thr_lock);
	zfs_hbx.hb_thr_running = B_TRUE;
	
	while (!zfs_hbx.hb_thr_exit) {
		if (list_head(&event_list->event_list) == NULL) {
			zfs_hbx_thr_wait(&cpr, &zfs_hbx.hb_thr_cv, 0);
		}
		
		if (zfs_hbx.hb_thr_exit) {
			break;
		} 
		
		mutex_enter(&event_list->event_mutex);
		event = list_head(&event_list->event_list);
		
		if (event == NULL/* || door_hdl == NULL*/) {
			mutex_exit(&event_list->event_mutex);
			delay(drv_usectohz((clock_t)500000));
			continue;
		} else {
			list_remove(&event_list->event_list, event);
		}
		
		mutex_exit(&event_list->event_mutex);


		/* initialize door paras */
		bzero(door_para, sizeof(hbx_door_para_t));
		buf = NULL;
		bufsize = 0;
		door_para->link_state = event->link_state;
		door_para->major = event->major;
		door_para->minor = event->minor;
		door_para->event = event->type;
		door_para->host_id = zfs_hbx.hb_host_id;
		door_para->b_data = event->b_data;
		door_para->data_len = event->data_len;
		
		bufsize = event->data_len + sizeof(hbx_door_para_t);			
		buf = kmem_zalloc(bufsize, KM_SLEEP);
		if (buf == NULL) {
			cmn_err(CE_WARN,"hbx cluster deref zalloc failed");
			zfs_clear_hb_para(event);
			continue;
		}
		bcopy(door_para, buf, sizeof(hbx_door_para_t));
		if (door_para->b_data && event->data != NULL &&
			event->data_len != 0) {
			bcopy(event->data, buf + sizeof(hbx_door_para_t), event->data_len);
		}

		err = cn_hbx_msg_send(buf, bufsize);
		if (err < 0) {
			cmn_err(CE_WARN, "cn_hbx_msg_send() error %d, event %d",
				err, door_para->event);
		}
		if (buf) {
			kmem_free(buf, bufsize);
		}

		zfs_clear_hb_para(event);
	}

	zfs_hbx.hb_thr_running = B_FALSE;
	CALLB_CPR_EXIT(&cpr);
	thread_exit();
	/* NOTREACHED */
}

static void
zfs_hbx_thr_stop(void)
{
	if (zfs_hbx.hb_thr_running) {
		zfs_hbx.hb_thr_exit = B_TRUE;
		cv_broadcast(&zfs_hbx.hb_thr_cv);
		thread_join(zfs_hbx.hb_thread->t_did);
	}
}

static int
zfs_hbx_thr_start(void)
{
	int ret = 0;
	
	mutex_enter(&zfs_hbx.hb_mutex);
	
	zfs_hbx.hb_thread = thread_create(NULL, 12<<10, zfs_hbx_thr_work,
		(void *)&hb_para, 0, &p0, TS_RUN, minclsyspri);
	if (zfs_hbx.hb_thread == NULL) {
		cmn_err(CE_WARN, "create hbx thr failed");
		ret = 1;
		goto FINISH;
	}

FINISH:
	mutex_exit(&zfs_hbx.hb_mutex);

	return (ret);
}

static void
zfs_hbx_event_list_init(void)
{
	list_create(&hb_para.event_list, sizeof(hbx_event_t),
	     offsetof(hbx_event_t, event_node));
	mutex_init(&hb_para.event_mutex, NULL, MUTEX_DEFAULT, NULL);	
}

static void
zfs_hbx_event_list_fini(void)
{
	hbx_event_t *event_node = NULL;
	
	mutex_enter(&hb_para.event_mutex);
	while((event_node = list_head(&hb_para.event_list)) != NULL) {
		list_remove(&hb_para.event_list, event_node);
		if (event_node->b_data && event_node->data_len != 0 &&
			event_node->data != NULL) {
			kmem_free(event_node->data, event_node->data_len);
		}
		kmem_free(event_node, sizeof(hbx_event_t));
	}
	mutex_exit(&hb_para.event_mutex);

	list_destroy(&hb_para.event_list);
	mutex_destroy(&hb_para.event_mutex);
}

int
zfs_hbx_init(void)
{
	int ret = 0;

	if (zfs_hbx.hb_initialized)
		return (0);
	
	bzero(&zfs_hbx, sizeof(zfs_hbx_t));

	zfs_hbx_event_list_init();
	mutex_init(&zfs_hbx.hb_mutex, NULL, MUTEX_DEFAULT, NULL);	
	mutex_init(&zfs_hbx.hb_thr_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&zfs_hbx.hb_thr_cv, NULL, CV_DEFAULT, NULL);
	ret = zfs_hbx_thr_start();
	if (ret) {
		zfs_hbx_thr_stop();
		mutex_destroy(&zfs_hbx.hb_mutex);
		mutex_destroy(&zfs_hbx.hb_thr_lock);
		cv_destroy(&zfs_hbx.hb_thr_cv);
		return (-1);
	}
	zfs_hbx.hb_host_id = zone_get_hostid(NULL);
	zfs_hbx.hb_initialized = B_TRUE;
	csh_rx_hook_add(CLUSTER_SAN_MSGTYPE_ZFS_HBX, zfs_hbx_rx_cb, NULL);

	return (0);
}

int
zfs_hbx_fini(void)
{
	if (!zfs_hbx.hb_initialized)
		return (0);
	csh_rx_hook_remove(CLUSTER_SAN_MSGTYPE_ZFS_HBX);
	zfs_set_hb_para(EVT_HBX_CLOSED, NULL, 0);

	zfs_hbx_thr_stop();
	zfs_hbx_event_list_fini();
	mutex_destroy(&zfs_hbx.hb_mutex);
	mutex_destroy(&zfs_hbx.hb_thr_lock);
	cv_destroy(&zfs_hbx.hb_thr_cv);

	zfs_hbx.link_state = LINK_DOWN;
	zfs_hbx.hb_initialized = B_FALSE;

	return (0);
}

void
hbx_mac_offline_notify(void *data, uint64_t len)
{
	char *event_data;

	event_data = kmem_zalloc(len, KM_SLEEP);
	if (event_data) {
		bcopy(data, event_data, len);
		zfs_set_hb_para(EVT_MAC_OFFLINE, event_data, len);
	}
}

int zfs_hbx_link_state_get(void)
{
	return (int)(zfs_hbx.link_state);
}

void
zfs_notify_clusterd(enum hbx_event_type type, char *data, uint64_t data_len)
{
	if (!zfs_hbx.hb_initialized) {
		return;
	}
	zfs_set_hb_para(type, data, data_len);
}

void
zfs_hbx_poweroff_host(uint32_t hostid)
{
	uint32_t *event_data = kmem_zalloc(sizeof(uint32_t), KM_SLEEP);
	*event_data = hostid;
	zfs_notify_clusterd(EVT_POWEROFF_REMOTEHOST, (char *)event_data, sizeof(uint32_t));
}

void
zfs_hbx_poweron_host(uint32_t hostid)
{
	uint32_t *event_data = kmem_zalloc(sizeof(uint32_t), KM_SLEEP);
	*event_data = hostid;
	zfs_notify_clusterd(EVT_POWERON_REMOTEHOST, (char *)event_data, sizeof(uint32_t));
}

#endif/* #ifdef _KERNEL */
