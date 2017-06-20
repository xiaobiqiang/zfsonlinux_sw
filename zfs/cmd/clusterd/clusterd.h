/*
 * Copyright (c) 2010, by Ceresdata, Inc.
 * All Rights Reserved
 */
#ifndef _CLUSTERD_H_
#define _CLUSTERD_H_

#ifdef __cplusplus
extern "C" {
#endif

#if	0
#define	DOOR_RESULT_BUFSZ	(sizeof (hbx_event_t))
#define	SAFETY_BUFFER		8*1024

#define	SCAN_ALL_DISK	"/usr/sbin/devfsadm"

#define	CLS_NIC_PATH	"/etc/hb/values"
#define	CLS_PAR_NIC_PATH	"/etc/hb/partner_values"
#define	CLS_PAR_NIC_PATH_TMP	"/etc/hb/hb.tmp"
#define	CLS_PAR_NIC_BAK_CMD	"/usr/bin/cp /etc/hb/partner_values /etc/hb/partner_values.bak"
#define	CLS_PAR_NIC_MV_CMD	"/usr/bin/mv /etc/hb/hb.tmp /etc/hb/partner_values"
#define CLS_PAR_AVS_BACKUP_CONF "/etc/hb/cluster_remote_avs.conf"
#endif
#define 	CLS_PAR_KEYFILE_PATH_TMP	"/tmp/keyfile.tmp"
#define	CLS_PAR_KEYFILE_MV_CMD	"/usr/bin/mv /tmp/keyfile.tmp %s"

#define  	MAX_MONITOR_NIC			16
#define 	MONITOR_NIC_PROP			"head.servers.%d.network.interface.monitor.%d.name"

#define 	ZPOOL_CMD_TRAVEL		"/usr/sbin/zpool scan"
#define	ZPOOL_CMD_SCAN		"/usr/sbin/zpool scan -s"
#define	ZPOOL_CMD_SCAN_SWITCH		"/usr/sbin/zpool scan -S"
#define	ZPOOL_CMD_RELEASE		"/usr/sbin/zpool release "

#if	0
#define	ZPOOL_CMD_CHANGE_POOL_OWNER		"/usr/sbin/zpool import -ifs %d %s"
#define	ZPOOL_CMD_CHANGE_POOL_OWNER_LOCAL		"/usr/sbin/zpool import -if %s"
#else
#define	ZPOOL_CMD_CHANGE_POOL_OWNER		"/usr/local/sbin/zpool import -bfs %d %s"
#define	ZPOOL_CMD_CHANGE_POOL_OWNER_LOCAL		"/usr/local/sbin/zpool import -bf %s"
#endif

#if	0
#define	ALUA_CMD_RESTART_PPPT			"/usr/sbin/aluaadm pppt disconnect"

#define	SHARE_ETC_CMD		"share -o ,anon=0,root=* /etc"
#define	HB_PARTNER_ETC_PATH	"/etc.partner"
#define	MOUNT_ETC_CMD	"mount -o vers=3,soft,timeo=20,retry=0 %s:/etc /etc.partner &"
#define	FAILOVER_NIC_IP	"/usr/sbin/hanet -f "
#define	RELEASE_NIC_IP	"/usr/sbin/hanet -r "
#define	RECONFIG_NIC_IP	"/usr/sbin/hanet -b "

#define	CLUSTER_SMF_ENABLE		"/usr/sbin/cluster_smf_init.sh"
#define	CLUSTER_SMF_FAILOVER	"/usr/sbin/cluster_smf_failover.sh"
#define	CLUSTER_SMF_RESTART	"/usr/sbin/cluster_smf_restart.sh"

#define	CLUSTER_OS_RAID	"/usr/sbin/cluster_os_raid.sh"

#define CLS_PARNTER_AVS_CONF 		"/etc/hb/avs/cluster_remote_avs.conf"
#define CLS_LOCAL_AVS_CONF 			"/etc/hb/avs/cluster_local_avs.conf"
#define CLUSTER_AVS_CONF_PATH  		"/etc/hb/avs/avs_host.conf"
#define	CLUSTER_AVS_FAILOVER		"/usr/sbin/cluster_avs_failover.sh"
#define	CLUSTER_AVS_RECONFIG		"/usr/sbin/cluster_avs_reconfig.sh"
#define	CLUSTER_AVS_ENABLE_CMD		"/usr/bin/echo 'stmf_avs_enable_flag/w 0x1' | /usr/bin/mdb -kw"
#define	CLUSTER_AVS_SYNC_U_CMD		"/usr/bin/echo Y | /usr/sbin/sndradm -u"
#endif

#define	CLUSTER_SMF_INIT		"/usr/sbin/cluster_init.sh"
#define	CLUSTER_SMF_INIT_POST	"/usr/sbin/cluster_init_post.sh"

#define	IPMI_GET_LAN_IP_CMD		"/usr/sbin/ipmitool lan print | "\
			"/usr/bin/grep \"IP Address              :\" | /usr/bin/awk '{print $NF}'"
#define	IPMI_REMOTE_POWER_ON		"/usr/sbin/ipmitool -I %s -H \"%s\" -U \"%s\" -f \"%s\" power on"
#define	IPMI_REMOTE_POWER_OFF		"/usr/sbin/ipmitool -I %s -H \"%s\" -U \"%s\" -f \"%s\" power off"
#define	IPMI_REMOTE_POWER_STATUS	"/usr/sbin/ipmitool -I %s -H \"%s\" -U \"%s\" -f \"%s\" power status | "\
			"/usr/bin/awk '{print $NF}'"

#define	CLUSTER_GET_ETH_IP		"/usr/sbin/ifconfig %s | /usr/bin/grep \"inet\" | /usr/bin/awk '{print $2}'"
#define	CLUSTER_ROUTE_ADD		"/usr/sbin/route add %s %s -interface"

#ifdef __cplusplus
}
#endif

#endif	/* _CLUSTERD_H_ */
