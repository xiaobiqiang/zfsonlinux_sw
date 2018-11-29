#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <wait.h>
#include <mqueue.h>
#include <locale.h>
#include <libzfs.h>
#include <sys/types.h>
#include <sys/int_types.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <libcluster.h>
#include <sys/fs/zfs.h>
#include <sys/fs/zfs_hbx.h>
#include <sys/zfs_ioctl.h>
#include <time.h>
#include <stropts.h>
#include <libnvpair.h>
#include <sys/list.h>
#include <sys/spa_impl.h>
#include <disklist.h>
#include "deflt.h"
#include "cn_cluster.h"
#include "systemd_util.h"
#include "if_util/if_util.h"
#include "clusterd.h"

#define	CLUSTERD_CONF	"/etc/default/clusterd"
#define	PID_FILE	RUNSTATEDIR "/clusterd.pid"

int clusterd_log_lvl = 0;

#define	c_log(lvl, fmt, ...)	if (lvl <= clusterd_log_lvl) {	\
	syslog(lvl, fmt, __VA_ARGS__);		\
}

#ifndef	strlcpy
#define	strlcpy	strncpy
#endif

#define	DIR_PERMS	(S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)

#define	MAX_ID_BYTE	8

static char *MyName;
static int verbose = 0;
/*static boolean_t load_fail_devs = B_FALSE;*/
static int host_id;
hbx_state_t cls_hbx_state = {LINK_DOWN, INACTIVE, INACTIVE};
char	sync_keyfile_path[512] = {"\0"};

#define	IPMI_USER_NAME	"ADMIN"
#define	IPMI_PASSWORD	"ADMIN"
#define	IPMI_PASSWORD_FILE	"/etc/.impi_password.tmp~"
/* will get from parter automatically */
char ipmi_local_ip[16] = "255.255.255.255";
char igb0_local_ip[16] = "255.255.255.255";

char sbindir[MAXPATHLEN] = "/usr/local/sbin";
char zpool_cmd[MAXPATHLEN] = "/usr/local/sbin/zpool";
char zpool_import_cmd[MAXPATHLEN] = "/usr/local/sbin/zpool import -bfi";
char zpool_export_cmd[MAXPATHLEN] = "/usr/local/sbin/zpool export -f";
char clusterd_cmd[MAXPATHLEN] = "/usr/local/sbin/clusterd";

char ip_cmd[MAXPATHLEN] = "/usr/sbin/ip";

#define	FAILOVER_TIME_TAG "clusterd failover time:"

typedef enum{
	IPMI_POWER_NONE,
	IPMI_POWER_OFF,
	IPMI_POWER_ON
}ipmi_power_status_t;

int ipmi_use_lanplus = 1;
char ipmi_user[16];
char ipmi_passwd[16];

#define	MAXDEVNAMELEN	32
#define	MAXDEVPARA		64
#define	DLADM_STRSIZE	256

#define	ETH_MAXNAMELEN	32
#define MAXLINKNAMELEN	ETH_MAXNAMELEN

#define	IP_CMD	ip_cmd
#define	ZPOOL_CMD		zpool_cmd
#define	ZPOOL_IMPORT	zpool_import_cmd
#define	ZPOOL_EXPORT	zpool_export_cmd

typedef struct cluster_event_s {
	int event;
	char *data;
	int size;
	struct cluster_event_s *next;
} cluster_event_t;

typedef struct cluster_thread_s {
	pthread_t 			cls_tid;
	pthread_mutex_t  	cls_mutex;
	pthread_mutex_t	cls_stat_mutex;
	pthread_mutex_t	cls_event_mutex;
	pthread_cond_t  	cls_cond;
	cluster_event_t		cls_event_head;
	int				running;
	int				waiting;
	int				state_change;
} cluster_thread_t;

static cluster_thread_t cls_thread;
#if	0
typedef struct monitor_dev {
	dev_event_t dev;
	boolean_t dev_use;
}monitor_dev_t;
monitor_dev_t monitor_fail_devs[MAX_MONITOR_DEVS];
#endif

int fail_event_id = EVT_END;

typedef struct failover_conf {
	char zpool_name[ZFS_MAXNAMELEN];
	int af;
	int mtu;
	int prefixlen;
	char eth[ETH_MAXNAMELEN];
	char ip_addr[INET6_ADDRSTRLEN];
	char prop_id[ZFS_MAXPROPLEN];
} failover_conf_t;

struct link_list {
	void *ptr;
	struct link_list *next;
};

typedef struct service_if {
	char ip_addr[INET6_ADDRSTRLEN];
	int prefixlen;
	int refs;
	list_node_t list;

	char eth[MAXLINKNAMELEN];
	char alias[IFALIASZ];
	struct link_list *zpool_list;
	int zpool_refs;
	failover_conf_t *failover_config;

	int flag;
} service_if_t;

list_t failover_ip_list;

typedef struct service_zpool {
	char zpool_name[ZPOOL_MAXNAMELEN];
	list_node_t list;

	struct link_list *if_list;

	int flag;
} service_zpool_t;

list_t failover_zpool_list;

/* protect failover_ip_list & failover_zpool_list */
pthread_mutex_t failover_list_lock;


struct cluster_failover_conf {
	pthread_mutex_t lock;
	int remote_down;
	int wait_resp;
	struct link_list *todo_mac_offline_event;
	struct link_list *todo_release_zpool;
};

struct cluster_failover_conf cf_conf;

#define	FLAG_CF_MAC_OFFLINE	1
#define	FLAG_CF_RESPONSE	2
#define	FLAG_CF_REMOTE_DOWN	3
#define	FLAG_CF_REMOTE_UP	4
#define	FLAG_CF_RESPTIMEOUT	5

#ifndef	offsetof
#define	offsetof(s, m)  ((size_t)(&((s *)0)->m))
#endif

#define	UPDATE_STAMP_INTERVAL	50000
#define	CONFLICT_DURATION		40

typedef struct failover_pool_import_state {
	nvlist_t	*pool_config;
	boolean_t	imported;
	pthread_mutex_t	mtx;
	pthread_cond_t	cond;
} failover_pool_import_state_t;

typedef struct compete_pool_param {
	void 	*arg;
	failover_pool_import_state_t	*import_state;
} compete_pool_param_t;

typedef struct thr_list_node {
	pthread_t thrid;
	list_node_t list;
	compete_pool_param_t param;
} thr_list_node_t;

typedef struct todo_import_pool_node {
	char poolname[ZPOOL_MAXNAMELEN];
	uint64_t guid;
	int imported;
	list_node_t list;
} todo_import_pool_node_t;

struct cluster_import_pools_thr_conf {
	pthread_mutex_t mtx;
	pthread_cond_t cond;

	pthread_mutex_t list_mtx;
	list_t todo_import_pools;
	list_t imported_pools;

	int exit_flag;
	int reverse_flag;/* to indicate release pool, but no import */

	/* protect cluster_import_pools() */
	pthread_mutex_t import_pools_handler_mtx;
};

struct cluster_import_pools_thr_conf import_thr_conf;

/* ready import host boradcast to other hosts this msgtype */
#define	CLUSTER_IMPORT_MSGTYPE_NOTIFY	0
/* if want stop remote host import, send this msgtype */
#define	CLUSTER_IMPORT_MSGTYPE_RESPONSE	1

typedef struct cluster_import_msg {
	int		msgtype;
	uint64_t	hostid;	/* hostid of the message come from */
	/* char	poolname[ZPOOL_MAXNAMELEN]; */
	uint64_t	pool_guid;
} cluster_import_msg_t;

#define	CLUSTER_IMPORT_INIT	0
#define	CLUSTER_IMPORT_READY	1
#define	CLUSTER_IMPORT_RUN	2
#define	CLUSTER_IMPORT_IMPORTED	3
#define	CLUSTER_IMPORT_FAILED	4
#define	CLUSTER_IMPORT_CANCEL	5

typedef struct cluster_import_pool {
	list_node_t	node;
	int		import_state;
	int		ref;

	pthread_mutex_t	import_lock;
	pthread_cond_t	import_cv;

	uint64_t	guid;
	char	name[ZPOOL_MAXNAMELEN];
} cluster_import_pool_t;

pthread_mutex_t	cluster_import_poollist_lock;
list_t	cluster_import_poollist_ready;
list_t	cluster_import_poollist_run;

/* used for compete thread wait pool satisfy replicas */
pthread_mutex_t	cluster_import_replicas_lock;
pthread_cond_t	cluster_import_replicas_cv;

#define	ARP_MOD_NAME	"arp"

#define	FLAG_MAC_STATE_GET_REMOTE	1 
#define	FLAG_MAC_STATE_REMOTE_STATE	2 
/*
 * Used for old ip failover solution: local released all IPs,
 * remote can do ip failover now
 */
#define	FLAG_MAC_STATE_IP_RELEASED	3

#define	MAX_MAC_STATE_REQ_NUM		10

typedef struct mac_state_param {
	int hostid;
	int flag;
	int mac_num;
	char mac_list[MAX_MAC_STATE_REQ_NUM][MAXLINKNAMELEN];
	unsigned linkstate[MAX_MAC_STATE_REQ_NUM];
} mac_state_param_t;

int clusterd_old_ip_failover_enable = 0;

#define	MAX_RELEASE_POOLS_MSGSIZE	8192

typedef struct release_pool_param {
	char pool_name[ZPOOL_MAXNAMELEN];
	int failover_num;
	char *failover[ZFS_MAXNAMELEN+ZFS_MAXPROPLEN];
} release_pool_param_t;

pthread_mutex_t handle_release_lock;

struct shielding_failover_pools {
	pthread_mutex_t	lock;
	struct link_list *head;	/* point a struct release_pool_param list */
};

/*
 * These pools are ready to import/export by release message handler or
 * mac offline event handler, do_ip_failover()/do_ip_restore() shuold
 * skip them.
 */
static struct shielding_failover_pools shielding_failover_pools;

static int excute_cmd_common(const char *cmd, boolean_t dup2log);
static int excute_cmd(const char *cmd);
static int do_ip_failover(failover_conf_t * conf, int flag);
static int do_ip_restore(failover_conf_t * conf);
static int parse_failover_conf(const char *msg, failover_conf_t *conf);
static int cluster_failover_conf_handler(int flag, const void *data);
/*static int ifplumb(const char *linkname, const char *ifname, int af);*/
static void *cluster_compete_pool(void *arg);
static int cluster_import_pools(int is_boot, int *failover_remote);
static int handle_release_pools_event(const void *buffer, int bufsiz);
static int handle_release_message_common(release_pools_message_t *r_msg);
static int cluster_import_event_handler(const void *buffer, int bufsize);
static struct link_list * cluster_get_local_pools(void);
static uint32_t cluster_get_host_state(uint32_t hostid);
static int hbx_do_cluster_cmd(char *buffer, int size, zfs_hbx_ioc_t iocmd);
static int cluster_poweroff_remote_event_handler(const void *buffer,
	int bufsize);
static int cluster_poweron_remote_event_handler(const void *buffer,
	int bufsize);

static int cluster_get_eth_ip(char *eth_name, char *ip_buf)
{
	char buf[256];
	FILE *f_ip;
	char *ip;
	size_t len = 0;

	if ((eth_name == NULL) || (ip_buf == NULL)) {
		syslog(LOG_WARNING, "%s: arg err", __func__);
		return (-1);
	}
	if (eth_name[0] == '\0') {
		syslog(LOG_WARNING, "%s: eth_name is err", __func__);
		return (-1);
	}
	snprintf(buf, 256, CLUSTER_GET_ETH_IP, eth_name);
	f_ip = popen(buf, "r");
	if (f_ip != NULL) {
		ip = fgets(ip_buf, 16, f_ip);
		fclose(f_ip);
		if (ip == NULL) {
			syslog(LOG_WARNING, "%s: get %s ip failed", __func__, eth_name);
			return (-1);
		}
		len = strlen(ip);
		if (ip[len - 1] == '\n') {
			ip[len - 1] = '\0';
		}
		syslog(LOG_NOTICE, "%s: get %s ip=%s", __func__, eth_name, ip);

		return (0);
	}

	return (-1);
}

static int ipmi_get_local_ip(char *ip)
{
	FILE *f_ip;
	size_t r_size = 0;
	int ret = -1;
	f_ip = popen(IPMI_GET_LAN_IP_CMD, "r");
	if (f_ip != NULL) {
		r_size = fread(ip, sizeof(char), 15, f_ip);
		if (r_size != 0) {
			if (ip[r_size - 1] == '\n') {
				ip[r_size - 1] = '\0';
			}
		}
		ip[r_size] = '\0';
		if (r_size >= 7) {
			ret = (0);
		}
		
		pclose(f_ip);
	}

	return (ret);
}

static void ipmi_send_local_ip(uint32_t remote_hostid)
{
	libzfs_handle_t *zfs_handle = NULL;
	zfs_cmd_t zc = {"\0"};
	int ret;

	if ((zfs_handle = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "%s: host(%d), get zfs handle failed",
			__func__, remote_hostid);
		return;
	}

	ret = ipmi_get_local_ip(ipmi_local_ip);
	if (ret == 0) {
		syslog(LOG_NOTICE, "get local ipmi ip:%s", ipmi_local_ip);
		cluster_get_eth_ip("igb0", igb0_local_ip);
		igb0_local_ip[15] = '\0';

		zc.zc_cookie = ZFS_HBX_SEND_IPMI_IP;
		strncpy(zc.zc_value, ipmi_local_ip, 16);
		strncpy(&zc.zc_value[16], igb0_local_ip, 16);
		zc.zc_perm_action = remote_hostid;
		ret = zfs_ioctl(zfs_handle, ZFS_IOC_HBX, &zc);
		if (ret != 0) {
			syslog(LOG_WARNING, "%s: to host(%d) failed",
				__func__, remote_hostid);
		}
	} else {
		syslog(LOG_WARNING, "%s: get local ipmi ip failed",
			__func__);
	}

	libzfs_fini(zfs_handle);
}

static void ipmi_exchange_ip(uint32_t remote_hostid)
{
	ipmi_send_local_ip(remote_hostid);
	hbx_do_cluster_cmd(NULL, 0, ZFS_HBX_REMOTE_IPMI_IP);
}

static void ipmi_route_add(char *ipmi_addr)
{
	FILE *f_route;
	size_t len = 0;
	char buf[256];
	char ip_buf[16];
	int ret;

	syslog(LOG_NOTICE, "add route to ipmi addr:%s", ipmi_addr);
	ret = cluster_get_eth_ip("igb0", ip_buf);
	if (ret == 0) {
		len = strlen(ip_buf);
		if (ip_buf[len - 1] == '\n') {
			ip_buf[len - 1] = '\0';
		}
		syslog(LOG_NOTICE, "get igbo ip=%s", ip_buf);
		snprintf(buf, 256, CLUSTER_ROUTE_ADD, ipmi_addr, ip_buf);
		syslog(LOG_NOTICE, "exec cmd:%s", buf);
		f_route = popen(buf, "r");
		if (f_route != NULL) {
			while (fgets(buf, 256, f_route) != NULL) {
				syslog(LOG_NOTICE, "%s", buf);
			}
			fclose(f_route);
		}
	}
}

static ipmi_power_status_t ipmi_remote_power_status(char *ipmi_ipaddr)
{
	ipmi_power_status_t power_status = IPMI_POWER_NONE;
	FILE *f_ip;
	char buf[256];
	int ret;

	if ((ipmi_ipaddr == NULL) || (ipmi_ipaddr[0] == '\0')) {
		syslog(LOG_WARNING, "get remote power status failed because "
			"hasn't been get the remote ip");
		return (IPMI_POWER_NONE);
	}

	/* generate the ipmi password file */
	snprintf(buf, 256, "/usr/bin/echo %s > %s", ipmi_passwd, IPMI_PASSWORD_FILE);
	ret = excute_cmd(buf);
	if (ret != 0) {
		syslog(LOG_WARNING, "get remote power status failed because "
			"create ipmi password file failed");
		return (IPMI_POWER_NONE);
	}
	/* create and exec get power status cmd */
	snprintf(buf, 256, IPMI_REMOTE_POWER_STATUS,
		ipmi_use_lanplus ? "lanplus" : "lan", ipmi_ipaddr,
		ipmi_user, IPMI_PASSWORD_FILE);
	c_log(LOG_WARNING, "%s", buf);
	f_ip = popen(buf, "r");

	if (f_ip != NULL) {
		if (fgets(buf, sizeof(buf), f_ip) == NULL) {
			syslog(LOG_WARNING, "read remote power status failed");
		} else {
			syslog(LOG_NOTICE, "get remote power status:%s", buf);
			if (strncmp(buf, "on", 2) == 0) {
				power_status = IPMI_POWER_ON;
			} else {
				power_status = IPMI_POWER_OFF;
			}
		}
		
		pclose(f_ip);
	} else {
		syslog(LOG_WARNING, "get remote power status failed");
	}

	/* delete the ipmi password file */
	snprintf(buf, 256, "/usr/bin/rm %s", IPMI_PASSWORD_FILE);
	system(buf);
	
	return (power_status);
}

static int ipmi_remote_power_on(char *ipmi_ipaddr)
{
	char buf[256];
	int ret;

	syslog(LOG_WARNING, "will power on the remote");
	if ((ipmi_ipaddr == NULL) || (ipmi_ipaddr[0] == '\0')) {
		syslog(LOG_WARNING, "can't power on the remote: "
			"hasn't been get the remote ip");
		return (-1);
	}
	/* generate the ipmi password file */
	snprintf(buf, 256, "/usr/bin/echo %s > %s", ipmi_passwd, IPMI_PASSWORD_FILE);
	ret = excute_cmd(buf);
	if (ret != 0) {
		syslog(LOG_WARNING, "power on remote: create ipmi password failed");
		return (-1);
	}
	
	snprintf(buf, 256, IPMI_REMOTE_POWER_ON,
		ipmi_use_lanplus ? "lanplus" : "lan", ipmi_ipaddr, ipmi_user,
		IPMI_PASSWORD_FILE);

	ret = excute_cmd(buf);

	if (ret != 0) {
		syslog(LOG_WARNING, "power on the remote failed, exited(0x%x)"
			" exit status(0x%x)", WIFEXITED(ret), WEXITSTATUS(ret));
	}

	snprintf(buf, 256, "/usr/bin/rm %s", IPMI_PASSWORD_FILE);
	system(buf);

	return (ret);
}

static int ipmi_remote_power_off(char *ipmi_ipaddr)
{
	char buf[256];
	int ret;

	syslog(LOG_WARNING, "will power off the remote");
	if ((ipmi_ipaddr == NULL) || (ipmi_ipaddr[0] == '\0')) {
		syslog(LOG_WARNING, "can't power off the remote: "
			"hasn't been get the remote ip");
		return (-1);
	}
	/* generate the ipmi password file */
	snprintf(buf, 256, "/usr/bin/echo %s > %s", ipmi_passwd, IPMI_PASSWORD_FILE);
	ret = excute_cmd(buf);
	if (ret != 0) {
		syslog(LOG_WARNING, "power off remote: create ipmi password failed");
		return (-1);
	}

	snprintf(buf, 256, IPMI_REMOTE_POWER_OFF,
		ipmi_use_lanplus ? "lanplus" : "lan", ipmi_ipaddr, ipmi_user,
		IPMI_PASSWORD_FILE);

	ret = excute_cmd(buf);

	if (ret != 0) {
		syslog(LOG_WARNING, "power off the remote failed, exited(0x%x)"
			" exit status(0x%x)", WIFEXITED(ret), WEXITSTATUS(ret));
	}

	snprintf(buf, 256, "/usr/bin/rm %s", IPMI_PASSWORD_FILE);
	system(buf);

	return (ret);
}

static int
pool_in_cluster(nvlist_t *pool_config)
{
	char *poolname;

	verify(nvlist_lookup_string(pool_config, ZPOOL_CONFIG_POOL_NAME, 
			&poolname) == 0);
	if (strncmp(poolname, "syspool", 7) != 0)
		return (1);
	return (0);
}

typedef struct cluster_pool_thread {
	list_node_t node;
	pthread_t pid;
	nvlist_t *pool_config;
	boolean_t is_updated;
	boolean_t uncontrolled;
	void *failover_private;
}cluster_pool_thread_t;

typedef enum cluster_failover_type {
	FAILOVER_NORMAL,
	HBX_TIMEOUT,
	REMOTE_SPA_HUNG,
	REMOTE_SPA_NORESPONSE
}cluster_failover_type_t;

typedef struct cluster_failover_handle_state {
	list_node_t node;
	pthread_t pid;
	uint32_t nthreads;
	pthread_mutex_t mtx;
	pthread_cond_t cond;
	pthread_mutex_t th_mtx;
	pthread_cond_t th_cond;
	list_t pool_list;
	uint32_t hostid;
	int need_failover;
	int can_import_pools;
	int thread_exit;
	int failover_running;
	cluster_failover_type_t failover_type;
	struct timeval	failover_start_time;
	uint64_t refcount;
}cluster_failover_handle_state_t;

pthread_mutex_t cluster_failover_mtx;
static list_t cluster_failover_host_list;

static int clusterd_host_is_need_failover(
	uint32_t hostid, boolean_t *need_failover)
{
	libzfs_handle_t *zfs_handle = NULL;
	zfs_cmd_t zc = {"\0"};
	int err;

	if ((zfs_handle = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "%s: host(%d), get zfs handle failed",
			__func__, hostid);
		return (-1);
	}

	/* determine failover */
	zc.zc_cookie = ZFS_HBX_IS_NEED_FAILOVER;
	zc.zc_perm_action = hostid;
	zc.zc_guid = 0;
	err = zfs_ioctl(zfs_handle, ZFS_IOC_HBX, &zc);
	if (err != 0) {
		syslog(LOG_WARNING, "%s: get the host(%d) is or not need failover failed",
			__func__, hostid);
	} else {
		if (zc.zc_guid == 0) {
			*need_failover = B_FALSE;
		} else {
			*need_failover = B_TRUE;
		}
	}
	libzfs_fini(zfs_handle);

	return (err);
}

static void clusterd_host_clr_need_failover(uint32_t hostid)
{
	libzfs_handle_t *zfs_handle = NULL;
	zfs_cmd_t zc = {"\0"};
	int err;

	/* if remote re-up, don't clear this */
	if (cluster_get_host_state(hostid) == 1)
		return;

	if ((zfs_handle = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "%s: host(%d), get zfs handle failed",
			__func__, hostid);
		return;
	}

	/* determine failover */
	zc.zc_cookie = ZFS_HBX_CLR_NEED_FAILOVER;
	zc.zc_perm_action = hostid;
	err = zfs_ioctl(zfs_handle, ZFS_IOC_HBX, &zc);
	if (err != 0) {
		syslog(LOG_WARNING, "%s: clear host(%d)'s need failover label failed",
			__func__, hostid);
	}
	libzfs_fini(zfs_handle);
}

static void cluster_hbx_closed(void)
{
}

static cluster_failover_handle_state_t *
cluster_failover_host_create(uint32_t hostid)
{
	cluster_failover_handle_state_t *cluster_failover_state;

	cluster_failover_state = malloc(sizeof(cluster_failover_handle_state_t));
	if (cluster_failover_state != NULL) {
		cluster_failover_state->hostid = hostid;
		pthread_mutex_init(&cluster_failover_state->mtx, NULL);
		pthread_cond_init(&cluster_failover_state->cond, NULL);
		pthread_mutex_init(&cluster_failover_state->th_mtx, NULL);
		pthread_cond_init(&cluster_failover_state->th_cond, NULL);
		list_create(&cluster_failover_state->pool_list,
			sizeof(cluster_pool_thread_t),
			offsetof(cluster_pool_thread_t, node));
		cluster_failover_state->failover_running = 0;
		cluster_failover_state->need_failover = 0;
		cluster_failover_state->can_import_pools = 0;
		cluster_failover_state->thread_exit = 0;
		cluster_failover_state->nthreads = 0;
		cluster_failover_state->failover_type = FAILOVER_NORMAL;
		cluster_failover_state->refcount = 0;
	}
	return (cluster_failover_state);
}

static void
cluster_failover_host_destroy(
	cluster_failover_handle_state_t *cluster_failover_state)
{
	while (cluster_failover_state->failover_running == 1) {
		pthread_mutex_lock(&cluster_failover_state->mtx);
		cluster_failover_state->failover_type = FAILOVER_NORMAL;
		pthread_cond_signal(&cluster_failover_state->cond);
		pthread_mutex_unlock(&cluster_failover_state->mtx);

		sleep(1);
	}

	pthread_mutex_destroy(&cluster_failover_state->mtx);
	pthread_cond_destroy(&cluster_failover_state->cond);
	pthread_mutex_destroy(&cluster_failover_state->th_mtx);
	pthread_cond_destroy(&cluster_failover_state->th_cond);
	list_destroy(&cluster_failover_state->pool_list);
}

static cluster_failover_handle_state_t *
cluster_failover_host_find_hold(uint32_t hostid)
{
	cluster_failover_handle_state_t *cluster_failover_state;
	pthread_mutex_lock(&cluster_failover_mtx);
	cluster_failover_state = list_head(&cluster_failover_host_list);
	while (cluster_failover_state != NULL) {
		if (cluster_failover_state->hostid == hostid) {
			break;
		}
		cluster_failover_state = list_next(&cluster_failover_host_list,
			cluster_failover_state);
	}
	if (cluster_failover_state == NULL) {
		cluster_failover_state = cluster_failover_host_create(hostid);
		if (cluster_failover_state != NULL) {
			list_insert_tail(&cluster_failover_host_list,
				cluster_failover_state);
		}
	}
	if (cluster_failover_state != NULL) {
		cluster_failover_state->refcount++;
	}
	pthread_mutex_unlock(&cluster_failover_mtx);

	return (cluster_failover_state);
}

static void cluster_failover_host_rele(
	cluster_failover_handle_state_t *cluster_failover_state)
{
	boolean_t to_destroy = B_FALSE;
	pthread_mutex_lock(&cluster_failover_mtx);
	cluster_failover_state->refcount--;
	if (cluster_failover_state->refcount == 0) {
		list_remove(&cluster_failover_host_list,
			cluster_failover_state);
		to_destroy = B_TRUE;
	}
	pthread_mutex_unlock(&cluster_failover_mtx);
	if (to_destroy) {
		cluster_failover_host_destroy(cluster_failover_state);
	}
}

static void cluster_failover_handle_init(void)
{
	pthread_mutex_init(&cluster_failover_mtx, NULL);
	list_create(&cluster_failover_host_list,
		sizeof(cluster_failover_handle_state_t),
		offsetof(cluster_failover_handle_state_t, node));
}

static void cluster_failover_handle_fini(void)
{
	cluster_failover_handle_state_t *cluster_failover_state;
	pthread_mutex_lock(&cluster_failover_mtx);
	cluster_failover_state = list_head(&cluster_failover_host_list);
	while (cluster_failover_state != NULL) {
		pthread_mutex_lock(&cluster_failover_state->mtx);
		cluster_failover_state->failover_type = FAILOVER_NORMAL;
		pthread_cond_signal(&cluster_failover_state->cond);
		pthread_mutex_unlock(&cluster_failover_state->mtx);
		cluster_failover_state = list_next(&cluster_failover_host_list,
			cluster_failover_state);
	}

	while (list_is_empty(&cluster_failover_host_list) == 0) {
		pthread_mutex_unlock(&cluster_failover_mtx);
		sleep(1);
		pthread_mutex_unlock(&cluster_failover_mtx);
	}
	pthread_mutex_unlock(&cluster_failover_mtx);

	pthread_mutex_destroy(&cluster_failover_mtx);
	list_destroy(&cluster_failover_host_list);

}

static void cluster_failover_time_diff(
	struct timeval *start, struct timeval *end, struct timeval *diff)
{
	diff->tv_sec = end->tv_sec - start->tv_sec;
	diff->tv_usec = end->tv_usec = start->tv_usec;
	if (end->tv_usec < start->tv_usec) {
		diff->tv_sec -= 1;
		diff->tv_usec += 1000000;
	}
}

static int cluster_import_pool_thread(cluster_pool_thread_t *pool_node)
{
	cluster_failover_handle_state_t *cluster_failover_state =
		pool_node->failover_private;
	nvlist_t *config = pool_node->pool_config;
	nvlist_t *nvroot;
	char *poolname;
	uint64_t pool_guid;
	int ret;
	int error = 0;
	libzfs_handle_t *hdl;
	struct timeval elapsed_time1;
	struct timeval elapsed_time2;
	struct timeval diff_time1;
	struct timeval diff_time2;

	pthread_detach(pthread_self());
	verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		&nvroot) == 0);
	verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, 
		&poolname) == 0);
	verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, 
		&pool_guid) == 0);

	syslog(LOG_WARNING, "%s: pool(%s) will import", __func__, poolname);

	while (((cluster_failover_state->failover_type == HBX_TIMEOUT) || 
		(cluster_failover_state->failover_type == REMOTE_SPA_NORESPONSE))
		 && (cluster_failover_state->thread_exit == 0)
		 && (cluster_failover_state->can_import_pools == 0)) {
		spa_quantum_index_t used_index1[SPA_NUM_OF_QUANTUM];
		spa_quantum_index_t used_index2[SPA_NUM_OF_QUANTUM];
		uint64_t real_nquantum1 = 0;
		uint64_t real_nquantum2 = 0;
		timestruc_t	to;
		struct timeval	tp;
		int try_cnt;
		
		if (pool_node->is_updated != B_TRUE) {
			syslog(LOG_NOTICE, "%s: pool(%s) maybe export or readonly in "
				"partner, we don't check the quantum",
				__func__, poolname);
			pthread_mutex_lock(&cluster_failover_state->mtx);
			pthread_cond_signal(&cluster_failover_state->cond);
			pthread_mutex_unlock(&cluster_failover_state->mtx);
			break;
		}
		
		/* check quantum disk is updating or not */
		bzero(used_index1, sizeof(spa_quantum_index_t) * SPA_NUM_OF_QUANTUM);
		bzero(used_index2, sizeof(spa_quantum_index_t) * SPA_NUM_OF_QUANTUM);

		real_nquantum1 = zpool_read_used(nvroot, used_index1, SPA_NUM_OF_QUANTUM);

		try_cnt = 0;
		while ((try_cnt < 3) && (cluster_failover_state->thread_exit == 0)) {
			/* wait a moment, then check index of quantum disk */
			pthread_mutex_lock(&cluster_failover_state->th_mtx);
			(void) gettimeofday(&tp, NULL);
			to.tv_sec = tp.tv_sec + 2;
			to.tv_nsec = tp.tv_usec * 1000;
			pthread_cond_timedwait(&cluster_failover_state->th_cond,
				&cluster_failover_state->th_mtx, &to);
			pthread_mutex_unlock(&cluster_failover_state->th_mtx);

			if ((cluster_failover_state->can_import_pools == 1)
				|| (cluster_failover_state->thread_exit == 1)) {
				break;
			}

			if (B_TRUE == zpool_used_index_changed(used_index1, real_nquantum1,
				used_index2, &real_nquantum2)) {
				syslog(LOG_WARNING, "pool(%s) in use, wait a moment, check again", poolname);
				pthread_mutex_lock(&cluster_failover_state->th_mtx);
				(void) gettimeofday(&tp, NULL);
				to.tv_sec = tp.tv_sec + 5;
				to.tv_nsec = tp.tv_usec * 1000;
				pthread_cond_timedwait(&cluster_failover_state->th_cond,
					&cluster_failover_state->th_mtx, &to);
				pthread_mutex_unlock(&cluster_failover_state->th_mtx);

				break;
			}
			try_cnt++;
		}

		if (try_cnt == 3) {
			/* the pool is stoped, need import to local */
			pthread_mutex_lock(&cluster_failover_state->mtx);
			pool_node->uncontrolled = B_TRUE;
			pthread_cond_signal(&cluster_failover_state->cond);
			pthread_mutex_unlock(&cluster_failover_state->mtx);
			syslog(LOG_WARNING, "pool(%s)'s quantum wasn't updated for a long time", poolname);
			break;
		}
	}

	pthread_mutex_lock(&cluster_failover_state->th_mtx);
	if (cluster_failover_state->thread_exit != 0) {
		pthread_mutex_unlock(&cluster_failover_state->th_mtx);
		goto EXIT;
	}
	if (cluster_failover_state->can_import_pools == 0) {
		pthread_cond_wait(&cluster_failover_state->th_cond,
			&cluster_failover_state->th_mtx);
	}
	pthread_mutex_unlock(&cluster_failover_state->th_mtx);

	(void) gettimeofday(&elapsed_time1, NULL);
	if (cluster_failover_state->can_import_pools != 0) {
		char buf[256];
		pthread_t tid;
		failover_pool_import_state_t import_state;
		compete_pool_param_t	param;

		pthread_mutex_init(&import_state.mtx, NULL);
		pthread_cond_init(&import_state.cond, NULL);
		import_state.imported = B_FALSE;
		import_state.pool_config = config;

		param.arg = import_state.pool_config;
		param.import_state = &import_state;

		error = pthread_create(&tid, NULL, cluster_compete_pool, &param);
		if (error != 0) {
			syslog(LOG_ERR, "pthread_create error: %d, %s", error, strerror(error));
			goto exit_import;
		}
		pthread_mutex_lock(&import_state.mtx);
		pthread_cond_wait(&import_state.cond, &import_state.mtx);
		if (import_state.imported) {
			syslog(LOG_WARNING, "compete lost or error");
			pthread_mutex_unlock(&import_state.mtx);
			goto wait_compete_thread;
		}
		pthread_mutex_unlock(&import_state.mtx);

		snprintf(buf, 256, "%s %llu", ZPOOL_IMPORT,
			(unsigned long long)pool_guid);
		ret = excute_cmd_common(buf, B_TRUE);
		if (ret != 0) {
			syslog(LOG_WARNING, "import pool: %s failed - %d", poolname, ret);
		} else {
			syslog(LOG_NOTICE, "import pool: %s successed", poolname);
			/* remove the pool from host info */
			hdl = libzfs_init();
			if (hdl != NULL) {
				zpool_remove_partner(hdl, poolname, cluster_failover_state->hostid);
				libzfs_fini(hdl);
			}
		}

		import_state.imported = B_TRUE;

wait_compete_thread:
		pthread_join(tid, NULL);

exit_import:
		pthread_mutex_destroy(&import_state.mtx);
		pthread_cond_destroy(&import_state.cond);
	}
	(void) gettimeofday(&elapsed_time2, NULL);
	cluster_failover_time_diff(&elapsed_time1, &elapsed_time2, &diff_time1);
	cluster_failover_time_diff(&cluster_failover_state->failover_start_time,
		&elapsed_time2, &diff_time2);
	syslog(LOG_NOTICE, "%s import pool: %s(spend time:%lds %ldus, "
		"from the start failover:%lds %ldus)",
		FAILOVER_TIME_TAG, poolname,
		diff_time1.tv_sec, diff_time1.tv_usec,
		diff_time2.tv_sec, diff_time2.tv_usec);
EXIT:
	syslog(LOG_WARNING, "%s: exit, pool(%s)", __func__, poolname);

	/* notify cluster_remote_abnormal_handle() thread exit */
	pthread_mutex_lock(&cluster_failover_state->mtx);
	atomic_dec_32(&cluster_failover_state->nthreads);
	pthread_cond_signal(&cluster_failover_state->cond);
	pthread_mutex_unlock(&cluster_failover_state->mtx);

	return (error);
}

static int cluster_if_need_failover_check(
	cluster_failover_handle_state_t *cluster_failover_state, int *all_no_update)
{
	cluster_pool_thread_t *pool_node;
	int need_failover = 1;
	int all_no_updated = 1;

	pool_node = list_head(&cluster_failover_state->pool_list);
	while (pool_node != NULL) {
		if (pool_node->is_updated) {
			all_no_updated = 0;
			if (!pool_node->uncontrolled) {
				/* have active pool, we don't failover */
				need_failover = 0;
				break;
			}
		}
		pool_node = list_next(&cluster_failover_state->pool_list, pool_node);
	}

	/* all pool is exported or readonly, we don't failover */
	if (all_no_updated == 1) {
		need_failover = 0;
	}
	*all_no_update = all_no_updated;

	return (need_failover);
}

static int cluster_remote_abnormal_handle(void *arg)
{
	cluster_failover_handle_state_t *cluster_failover_state = arg;
	nvlist_t *pools;
	nvlist_t *config;
	nvpair_t *elem = NULL;
	nvlist_t *updated_pools = NULL;
	uint64_t temp64;
	libzfs_handle_t *hdl;
	cluster_pool_thread_t *pool_node;
	int ret;
	int try_cnt;
	zfs_cmd_t zc = {"\0"};
	char *ipmi_ipaddr;
	ipmi_power_status_t powerstat;
	int power_off_by_me = 0;
	int do_failover = 0;
	int error = 0;
	int poweroff_success = 0;
	nvlist_t *nvl_clusterstate = NULL;
	uint32_t ipmi_switch = 0;
	importargs_t idata;
	int all_no_update;
	int i;

	struct timeval elapsed_time1;
	struct timeval elapsed_time2;
	struct timeval elapsed_time3;
	struct timeval elapsed_time4;
	struct timeval diff_time;

	(void) gettimeofday(&cluster_failover_state->failover_start_time, NULL);

	pthread_detach(pthread_self());
	/* secondly, check partner is online or not */
	syslog(LOG_ERR, "remote host(%d) abnormal: 0x%x, to do failover",
		cluster_failover_state->hostid, cluster_failover_state->failover_type);

	hdl = libzfs_init();
	if (!hdl) {
		syslog(LOG_ERR, "Failed to get libzfs handle");
		pthread_mutex_lock(&cluster_failover_state->mtx);
		cluster_failover_state->failover_running = 0;
		pthread_mutex_unlock(&cluster_failover_state->mtx);
		if (cluster_failover_state->failover_type == HBX_TIMEOUT) {
			clusterd_host_clr_need_failover(cluster_failover_state->hostid);
		}
		cluster_failover_host_rele(cluster_failover_state);

		return (-1);
	}

	/* notify mirror can't timeout */
	hbx_do_cluster_cmd("off", 4, ZFS_HBX_MIRROR_TIMEOUT_SWITCH);

	bzero(&idata, sizeof(importargs_t));
	idata.cluster_switch = 1;
	idata.cluster_ignore = 1;
	idata.remote_hostid = cluster_failover_state->hostid;
	pools = zpool_search_import(hdl, &idata);
	elem = nvlist_next_nvpair(pools, NULL);

	if ((pools == NULL) || (elem == NULL)) {
#if 0
		/* 
		 * there is no pool in partner, but we still need to do smf failover for
		 *  some service, eg pppt.
		 */
		system(CLUSTER_SMF_FAILOVER);
#endif
		syslog(LOG_ERR, "remote abnormal, partner have no pool, do nothing");
		goto EXIT;
	}
	if ((ret = zfs_do_hbx_get_nvlist(hdl, ZFS_HBX_GET_PARTNER_UPDATED_POOL,
		cluster_failover_state->hostid, &updated_pools)) != 0) {
		syslog(LOG_ERR, "zfs_do_hbx_get_nvlist error %d", ret);
	}

	syslog(LOG_NOTICE, "remote abnormal: create the watch pool threads");
	/* every pool use a thread */
	while (elem != NULL) {
		verify(nvpair_value_nvlist(elem, &config) == 0);
		/* filter the pool not in cluster */
		if (!pool_in_cluster(config)) {
			elem = nvlist_next_nvpair(pools, elem);
			continue;
		}
		atomic_inc_32(&cluster_failover_state->nthreads);

		pool_node = malloc(sizeof(cluster_pool_thread_t));
		pool_node->failover_private = cluster_failover_state;
		pool_node->pool_config = config;
		pool_node->uncontrolled = B_FALSE;

		if ((nvlist_lookup_uint64(updated_pools, nvpair_name(elem), &temp64))
			== 0) {
			pool_node->is_updated = B_TRUE;
		} else {
			pool_node->is_updated = B_FALSE;
		}
		list_insert_tail(&cluster_failover_state->pool_list, pool_node);
		ret = pthread_create(&pool_node->pid, NULL,
			(void *(*)(void *))cluster_import_pool_thread, (void *)pool_node);
		if (ret != 0) {
			atomic_dec_32(&cluster_failover_state->nthreads);
			syslog(LOG_WARNING, "remote abnormal: create import pool thread failed");
			error = -1;
			goto FAILED;
		}
		elem = nvlist_next_nvpair(pools, elem);
	}
	(void) gettimeofday(&elapsed_time1, NULL);
	pthread_mutex_lock(&cluster_failover_state->mtx);
	while (((cluster_failover_state->failover_type == HBX_TIMEOUT) ||
		(cluster_failover_state->failover_type == REMOTE_SPA_NORESPONSE))
		&& (cluster_failover_state->need_failover == 0)) {
		syslog(LOG_NOTICE, "remote host(%d) abnormal: "
			"wait until all pools is dead or stop failover",
			cluster_failover_state->hostid);
		pthread_cond_wait(&cluster_failover_state->cond,
			&cluster_failover_state->mtx);
		cluster_failover_state->need_failover =
			cluster_if_need_failover_check(cluster_failover_state, &all_no_update);
		if (all_no_update == 1)
			break;
	}
	pthread_mutex_unlock(&cluster_failover_state->mtx);
	
	if (cluster_failover_state->need_failover != 0) {
		(void) gettimeofday(&elapsed_time2, NULL);
		cluster_failover_time_diff(&elapsed_time1, &elapsed_time2, &diff_time);
		syslog(LOG_NOTICE, "%s wait all pools dead(spend time:%lds %ldus"
			", host:%d)",
 			FAILOVER_TIME_TAG, diff_time.tv_sec, diff_time.tv_usec,
 			cluster_failover_state->hostid);

		try_cnt = 0;
		poweroff_success = 0;

		/* check ipmi switch */
		nvl_clusterstate = zfs_clustersan_get_nvlist(hdl,
			ZFS_CLUSTERSAN_STATE, NULL, 0);
		if (nvl_clusterstate != NULL) {
			if (nvlist_lookup_uint32(nvl_clusterstate, CS_NVL_IPMI_SWITCH,
				&ipmi_switch) != 0) {
				ipmi_switch = 0;
			}
		} else {
			ipmi_switch = 0;
		}

		if (ipmi_switch == 0) {
			syslog(LOG_NOTICE, "%s: ipmi is off", __func__);
			if (cluster_failover_state->failover_type == HBX_TIMEOUT) {
				syslog(LOG_NOTICE, "%s: host(%d) maybe down, so we do failover now",
					__func__, cluster_failover_state->hostid);
				goto DO_FAILOVER;
			} else {
				error = -1;
				goto FAILED;
			}
		}

		/* get remote host ipmi ip addr */
		zc.zc_cookie = ZFS_HBX_GET_IMPI_IP;
		zc.zc_perm_action = cluster_failover_state->hostid;
		zc.zc_value[0] = '\0';
		ret = zfs_ioctl(hdl, ZFS_IOC_HBX, &zc);
		if ((ret != 0) || (zc.zc_value[0] == '\0')) {
			syslog(LOG_ERR, "%s: get ipmi ip addr failed", __func__);
			if (cluster_failover_state->failover_type == HBX_TIMEOUT) {
				try_cnt = 3;
			} else {
				error = -1;
				goto FAILED;
			}
		} else {
			ipmi_ipaddr = zc.zc_value;
			syslog(LOG_NOTICE, "%s: get host(%d)'s ipmi ip=%s",
				__func__, cluster_failover_state->hostid, ipmi_ipaddr);
		}

		syslog(LOG_WARNING, "remote host(%d) abnormal: ready for failover, "
			"we will poweroff parter and import the pools",
			cluster_failover_state->hostid);
		/* power off the partner avoid manage the same pool both */
		while ((try_cnt < 3) &&
			((powerstat = ipmi_remote_power_status(ipmi_ipaddr)) != IPMI_POWER_OFF)) {
			if (powerstat == IPMI_POWER_NONE) {
				sleep(1);
				try_cnt++;
				continue;
			}
			if (ipmi_remote_power_off(ipmi_ipaddr) == 0) {
				power_off_by_me = 1;
			}
			for (i = 0; i < 10; i++) {
				sleep(1);
				if (ipmi_remote_power_status(ipmi_ipaddr) == IPMI_POWER_OFF) {
					poweroff_success = 1;
					break;
				}
			}
			if (poweroff_success == 0) {
				try_cnt++;
			} else {
				break;
			}
		}
		if (try_cnt == 3) {
			syslog(LOG_WARNING, "power off host(%d) failed, please check the net config",
				cluster_failover_state->hostid);
			if (cluster_failover_state->failover_type == HBX_TIMEOUT) {
				syslog(LOG_WARNING, "may be not config the ipmi ip, "
					"we still do failover when host(%d) timeout",
					cluster_failover_state->hostid);
			} else {
				error = -1;
				goto FAILED;
			}
		} else {
			syslog(LOG_NOTICE, "remote host(%d) abnormal: power off partner success, do failover",
				cluster_failover_state->hostid);
		}
		(void) gettimeofday(&elapsed_time3, NULL);
		cluster_failover_time_diff(&elapsed_time2, &elapsed_time3, &diff_time);
		syslog(LOG_NOTICE, "%s ipmi power off host(%d) (spend time:%lds %ldus)",
			FAILOVER_TIME_TAG, cluster_failover_state->hostid,
			diff_time.tv_sec, diff_time.tv_usec);
DO_FAILOVER:
		do_failover = 1;
		/* notify the thread can import the pool */
		pthread_mutex_lock(&cluster_failover_state->th_mtx);
		cluster_failover_state->can_import_pools = 1;
		pthread_cond_broadcast(&cluster_failover_state->th_cond);
		pthread_mutex_unlock(&cluster_failover_state->th_mtx);
	}

FAILED:
	/* wait all thread exit */
	syslog(LOG_DEBUG, "wait all import spa thread exit");
	pthread_mutex_lock(&cluster_failover_state->th_mtx);
	if (do_failover == 0) {
		cluster_failover_state->thread_exit = 1;
	}
	pthread_cond_broadcast(&cluster_failover_state->th_cond);
	pthread_mutex_unlock(&cluster_failover_state->th_mtx);

	pthread_mutex_lock(&cluster_failover_state->mtx);
	while (cluster_failover_state->nthreads != 0) {
		pthread_cond_wait(&cluster_failover_state->cond,
			&cluster_failover_state->mtx);
	}
	pthread_mutex_unlock(&cluster_failover_state->mtx);

	if (do_failover == 1) {
		(void) gettimeofday(&elapsed_time1, NULL);
#if	0
		cluster_nthread_pool_scan();
		cluster_task_app_failover();
#endif
		(void) gettimeofday(&elapsed_time2, NULL);
		cluster_failover_time_diff(&elapsed_time1, &elapsed_time2, &diff_time);
		syslog(LOG_NOTICE, "%s other failover(task app etc.)(spend time:%lds %ldus)",
			FAILOVER_TIME_TAG, diff_time.tv_sec, diff_time.tv_usec);
	}
	
	if (power_off_by_me == 1) {
		/* we must power on the partner if power off by us*/
		(void) gettimeofday(&elapsed_time1, NULL);
		try_cnt = 0;
		while ((try_cnt < 3) && (ipmi_remote_power_status(ipmi_ipaddr) != IPMI_POWER_ON)) {
			ipmi_remote_power_on(ipmi_ipaddr);
			for (i = 0; i < 10; i++) {
				if (ipmi_remote_power_status(ipmi_ipaddr) == IPMI_POWER_ON) {
					break;
				}
				sleep(1);
			}
			try_cnt++;
		}
		if (try_cnt == 3) {
			syslog(LOG_WARNING, "power on host(%d) failed, please manually power on",
				cluster_failover_state->hostid);
		}
		(void) gettimeofday(&elapsed_time2, NULL);
		cluster_failover_time_diff(&elapsed_time1, &elapsed_time2, &diff_time);
		syslog(LOG_NOTICE, "%s ipmi power on host(%d) (spend time:%lds %ldus)",
			FAILOVER_TIME_TAG, cluster_failover_state->hostid,
			diff_time.tv_sec, diff_time.tv_usec);
	}

	cluster_failover_state->failover_type = FAILOVER_NORMAL;
	cluster_failover_state->need_failover = 0;
	cluster_failover_state->can_import_pools = 0;
	cluster_failover_state->thread_exit = 0;

	while ((pool_node = list_head(&cluster_failover_state->pool_list)) != NULL) {
		list_remove(&cluster_failover_state->pool_list, pool_node);
		free(pool_node);
	}
	
EXIT:
	/* notify mirror can timeout */
	hbx_do_cluster_cmd("on", 3, ZFS_HBX_MIRROR_TIMEOUT_SWITCH);

	(void) gettimeofday(&elapsed_time4, NULL);
	cluster_failover_time_diff(&cluster_failover_state->failover_start_time,
		&elapsed_time4, &diff_time);
	syslog(LOG_NOTICE, "%s host(%d) whole failover(spend time:%lds %ldus)",
		FAILOVER_TIME_TAG, cluster_failover_state->hostid,
		diff_time.tv_sec, diff_time.tv_usec);

	libzfs_fini(hdl);
	if (pools != NULL) {
		nvlist_free(pools);
	}
	if (updated_pools != NULL) {
		nvlist_free(updated_pools);
	}
	if ((cluster_failover_state->failover_type == HBX_TIMEOUT)
		|| (do_failover == 1)) {
		clusterd_host_clr_need_failover(cluster_failover_state->hostid);
	}
	cluster_failover_state->failover_running = 0;

	cluster_failover_host_rele(cluster_failover_state);

	return (error);
}

static void cluster_remote_hbx_recover(uint32_t hostid)
{
	cluster_failover_handle_state_t *cluster_failover_state;

	pthread_mutex_lock(&cluster_failover_mtx);
	cluster_failover_state = list_head(&cluster_failover_host_list);
	while (cluster_failover_state != NULL) {
		if (cluster_failover_state->hostid == hostid) {
			pthread_mutex_lock(&cluster_failover_state->mtx);
			if (cluster_failover_state->failover_type == HBX_TIMEOUT) {
				cluster_failover_state->failover_type = FAILOVER_NORMAL;
				pthread_cond_signal(&cluster_failover_state->cond);
			}
			pthread_mutex_unlock(&cluster_failover_state->mtx);
			break;
		}
		cluster_failover_state = list_next(&cluster_failover_host_list,
			cluster_failover_state);
	}
	pthread_mutex_unlock(&cluster_failover_mtx);
	ipmi_exchange_ip(hostid);
}

static void cluster_remote_spa_response(void)
{
}

static void cluster_remote_hbx_timeout(uint32_t hostid)
{
	cluster_failover_handle_state_t *cluster_failover_state;
	boolean_t need_failover = B_FALSE;
	int ret = -1;

	/* determine failover */
	clusterd_host_is_need_failover(hostid, &need_failover);
	if (!need_failover) {
		syslog(LOG_WARNING, "%s: host(%d), don't need failover",
			__func__, hostid);
		return;
	}

	cluster_failover_state = cluster_failover_host_find_hold(hostid);
	if (cluster_failover_state == NULL) {
		return;
	}
	pthread_mutex_lock(&cluster_failover_state->mtx);
	if (cluster_failover_state->failover_running == 0) {
		cluster_failover_state->failover_running = 1;
		cluster_failover_state->failover_type = HBX_TIMEOUT;
		ret = pthread_create(&cluster_failover_state->pid, NULL,
			(void *(*)(void *))cluster_remote_abnormal_handle,
			(void *)cluster_failover_state);
		if (ret != 0) {
			cluster_failover_state->failover_running = 0;
			syslog(LOG_WARNING, "host(%d) down: create the handle thread failed",
				hostid);
			clusterd_host_clr_need_failover(cluster_failover_state->hostid);
		}
	} else {		
		syslog(LOG_WARNING, "host(%d) down: the failover handle(%d) was running",
			hostid, cluster_failover_state->failover_type);
	}
	pthread_mutex_unlock(&cluster_failover_state->mtx);

	if (ret != 0) {
		cluster_failover_host_rele(cluster_failover_state);
	}
}

static void cluster_remote_spa_hung(uint32_t hostid)
{
	cluster_failover_handle_state_t *cluster_failover_state;
	boolean_t need_failover = B_FALSE;
	int ret = -1;

	clusterd_host_is_need_failover(hostid, &need_failover);
	if (!need_failover) {
		syslog(LOG_WARNING, "%s: host(%d), don't need failover",
			__func__, hostid);
		return;
	}
	cluster_failover_state = cluster_failover_host_find_hold(hostid);
	if (cluster_failover_state == NULL) {
		return;
	}

	pthread_mutex_lock(&cluster_failover_state->mtx);
	if (cluster_failover_state->failover_running == 0) {
		cluster_failover_state->failover_running = 1;
		cluster_failover_state->failover_type = REMOTE_SPA_HUNG;
		cluster_failover_state->need_failover = 1;
		ret = pthread_create(&cluster_failover_state->pid, NULL,
			(void *(*)(void *))cluster_remote_abnormal_handle,
			(void *)cluster_failover_state);
		if (ret != 0) {
			cluster_failover_state->failover_running = 0;
			syslog(LOG_WARNING, "host(%d)'s spa hung: create the handle thread failed",
				hostid);
		}
	} else {		
		syslog(LOG_WARNING, "host(%d)'s spa hung: the failover handle(%d) was running",
			hostid, cluster_failover_state->failover_type);
	}
	pthread_mutex_unlock(&cluster_failover_state->mtx);

	if (ret != 0) {
		cluster_failover_host_rele(cluster_failover_state);
	}
}

static void cluster_remote_spa_noresponse(void)
{
}

static uint32_t
cluster_get_host_state(uint32_t hostid)
{
	uint32_t local_hostid;
	uint32_t flags;
	libzfs_handle_t *zfs_handle = NULL;
	nvlist_t *nvl_hostinfo;
	uint32_t state = 0;

	/*local_hostid = get_host_id();*/
	local_hostid = gethostid();
	if (hostid == local_hostid) {
		return (1);
	}

	if ((zfs_handle = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "%s: host(%d), get zfs handle failed",
			__func__, hostid);
		return (0);
	}

	flags = ZFS_CLUSTER_SESSION_LIST_FLAG;
	nvl_hostinfo = zfs_clustersan_get_nvlist(zfs_handle,
		ZFS_CLUSTERSAN_GET_HOSTINFO, (void *)(uintptr_t)hostid, flags);
	if (nvl_hostinfo != NULL) {
		nvlist_lookup_uint32(nvl_hostinfo, "state", &state);
		nvlist_free(nvl_hostinfo);
	} else {
		state = 0;
	}
	libzfs_fini(zfs_handle);

	return (state);
}

static int
hbx_do_cluster_cmd(char *buffer, int size, zfs_hbx_ioc_t iocmd)
{
	libzfs_handle_t *zfs_handle = NULL;

	if ((zfs_handle = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "hbx do cluster cmd get zfs handle failed");
		return (-1);
	}

	zfs_do_hbx_process(zfs_handle, buffer, size, iocmd);

	libzfs_fini(zfs_handle);

	return (0);
}

static int
hbx_do_cluster_cmd_ex(char *buffer, int size, zfs_hbx_ioc_t iocmd, int remote_id)
{
	libzfs_handle_t *zfs_handle = NULL;

	if ((zfs_handle = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "hbx do cluster cmd get zfs handle failed");
		return (-1);
	}

	zfs_do_hbx_process_ex(zfs_handle, buffer, size, iocmd, remote_id);

	libzfs_fini(zfs_handle);

	return (0);
}

#if	0
static int
cluster_update_partner_nic(char *buffer, int size)
{
	int fd, actual_size = 0;

	if (size == 0) {
		syslog(LOG_ERR, "cluster update partner size is 0");
		return (-1);
	}

	/* back up nic info of last */
	system(CLS_PAR_NIC_BAK_CMD);

	fd = open(CLS_PAR_NIC_PATH_TMP, O_WRONLY | O_CREAT |O_TRUNC);
	if (fd < 0) {
		syslog(LOG_ERR, "cluster update partner open file failed");
		return (-1);
	}

	actual_size = write(fd, buffer, size);
	if (actual_size != size) {
		syslog(LOG_ERR, "cluster update nic write size not equal,"
			"%d:%d", actual_size, size);
		close(fd);
		return (-1);
	}

	close(fd);
	system(CLS_PAR_NIC_MV_CMD);
	return (0);
		
}
#endif

static void cluster_update_mkdirs(const char *dir)
{
        char tmp[1024] = {"\0"};
        char *p;
        if (strlen(dir) == 0 || dir == NULL) {
                printf("strlen(dir) is 0 or dir is NULL.\n");
                return;
        }
        memset(tmp, '\0', sizeof(tmp));
        strncpy(tmp, dir, strlen(dir));
        if (tmp[0] == '/') 
                p = strchr(tmp + 1, '/');
        else 
                p = strchr(tmp, '/');
        if (p) {
                *p = '\0';
                mkdir(tmp, DIR_PERMS);
                chdir(tmp);
        } else {
                mkdir(tmp, DIR_PERMS);
                chdir(tmp);
                return;
        }
        cluster_update_mkdirs(p + 1);
}

static int
cluster_update_keyfile_path(char *filename, int size)
{	
	char file_path[1024] = {"\0"};
	int filename_len;
	filename_len = size;
	char tmp;

	strncpy(file_path, filename, filename_len);
	file_path[filename_len] = 0;
	filename_len  -= 1;
	tmp = file_path[filename_len];
	
	while(filename_len > 0) {
		tmp = file_path[filename_len--];
		if(tmp == '/')
			break;
	}
	
	file_path[filename_len + 1] = 0;
	cluster_update_mkdirs(file_path);
	strncpy(sync_keyfile_path, filename, size);
	sync_keyfile_path[size] = 0;
	return 0;
}

struct event_data_arg {
	char	*buf;
	int		size;
};

static struct event_data_arg *
dup_event_data(char *buffer, int size)
{
	struct event_data_arg *arg;

	arg = (struct event_data_arg *) malloc(sizeof(struct event_data_arg));
	if (arg) {
		arg->size = size;
		arg->buf = (char *) malloc(size);
		if (arg->buf != NULL) {
			memcpy(arg->buf, buffer, size);
		} else {
			free(arg);
			arg = NULL;
		}
	}

	return (arg);
}

static void *
cluster_update_keyfile_thread(void *arg)
{
#if	0
	int fd, actual_size = 0;
	char update_cmd[512]= {"\0"};
	/*char get_opposite_id[9];*/
	int judge = -1;
	char tx_result[512];
	struct event_data_arg *argp = arg;
	char *buffer;
	int size;

	pthread_detach(pthread_self());
	buffer = argp->buf;
	size = argp->size;

	bzero(tx_result, 512);
	strncpy(tx_result, buffer, MAX_ID_BYTE);

	/* skip the ID & get text */
	buffer = buffer + MAX_ID_BYTE;
	size = size - MAX_ID_BYTE;
	
	if (size == 0) {
		syslog(LOG_ERR, "cluster update keyfile size is 0");
		goto exit_thread;
	}

	fd = open(CLS_PAR_KEYFILE_PATH_TMP, O_WRONLY | O_CREAT |O_TRUNC);
	if (fd < 0) {
		syslog(LOG_ERR, "cluster update keyfile open file failed");
		goto exit_thread;
	}
	actual_size = write(fd, buffer, size);
	if (actual_size != size) {
		syslog(LOG_ERR, "cluster update keyfile write size not equal,"
			"%d:%d", actual_size, size);
		close(fd);
		goto exit_thread;
	}
	sprintf(update_cmd, CLS_PAR_KEYFILE_MV_CMD, sync_keyfile_path);
	update_cmd[strlen(CLS_PAR_KEYFILE_MV_CMD)+ strlen(sync_keyfile_path)-2] = 0;
	judge = excute_cmd(update_cmd);
	close(fd);
	
	/* send id & result */
	sprintf(tx_result + MAX_ID_BYTE, "%d", judge);	
	hbx_do_cluster_cmd(tx_result,
		(strlen(tx_result + MAX_ID_BYTE) + MAX_ID_BYTE + 1), ZFS_HBX_SYNCKEY_RESULT);

exit_thread:
	free(argp->buf);
	free(argp);
#endif
	return (NULL);
}

static int
cluster_update_keyfile(char *buffer, int size)
{
	struct event_data_arg *arg;
	pthread_t tid;

	arg = dup_event_data(buffer, size);
	if (arg == NULL) {
		syslog(LOG_ERR, "out of memory");
		return (-1);
	}

	if (pthread_create(&tid, NULL, cluster_update_keyfile_thread,
		(void *) arg) != 0) {
		syslog(LOG_ERR, "pthread_create error.");
		free(arg->buf);
		free(arg);
		return (-1);
	}
	return (0);
}

static void * 
cluster_update_remote_cmd_thread(void *arg)
{
#if	0
	int judge = -1;
	char tx_result[512];
	struct event_data_arg *argp = arg;
	char *cmd_name;
	int size;

	pthread_detach(pthread_self());
	cmd_name = argp->buf;
	size = argp->size;

	/* skip the ID &get text */
	bzero(tx_result, 512);
	strncpy(tx_result, cmd_name, MAX_ID_BYTE);
	size = size - MAX_ID_BYTE;
	cmd_name = cmd_name + MAX_ID_BYTE;

	if (size >= 0) {
		judge = excute_cmd(cmd_name);	

		/* send id & result */
		sprintf(tx_result + MAX_ID_BYTE, "%d", judge);
		hbx_do_cluster_cmd(tx_result, (strlen(tx_result + MAX_ID_BYTE) + MAX_ID_BYTE + 1),
			ZFS_HBX_SYNCKEY_RESULT);
	}

	free(argp->buf);
	free(argp);
#endif
	return (NULL);
}

static int 
cluster_update_remote_cmd(char *cmd_name, int size)
{
	struct event_data_arg *arg;
	pthread_t tid;

	arg = dup_event_data(cmd_name, size);
	if (arg == NULL) {
		syslog(LOG_ERR, "out of memory");
		return (-1);
	}

	if (pthread_create(&tid, NULL, cluster_update_remote_cmd_thread,
		(void *) arg) != 0) {
		syslog(LOG_ERR, "pthread_create error.");
		free(arg->buf);
		free(arg);
		return (-1);
	}
	return (0);
}

static void
cluster_change_pool_owner(char *buf, size_t buflen)
{
	nvlist_t *ripool = NULL;
	uint32_t hostid;
	char *spa_name;
	char cmd[256] = {"\0"};
	int ret;

	ret = nvlist_unpack(buf, buflen, &ripool, KM_SLEEP);
	if (ret != 0) {
		syslog(LOG_WARNING, "%s: nvlist_unpack failed (buflen:%u, ret:%d)",
			__func__, (unsigned int)buflen, ret);
		return;
	}
	ret = nvlist_lookup_uint32(ripool, "hostid", &hostid);
	if (ret != 0) {
		syslog(LOG_WARNING, "%s: get hostid failed, ret:%d",
			__func__, ret);
		nvlist_free(ripool);
		return;
	}
	ret = nvlist_lookup_string(ripool, "spa_name", &spa_name);
	if (ret != 0) {
		syslog(LOG_WARNING, "%s: get spa_name failed, ret:%d",
			__func__, ret);
		nvlist_free(ripool);
		return;
	}

#if	0
	sprintf(cmd, ZPOOL_CMD_CHANGE_POOL_OWNER, hostid, spa_name);
	syslog(LOG_NOTICE, "%s: %s", __func__, cmd);
	ret = system(cmd);
	if ((!WIFEXITED(ret)) || (WEXITSTATUS(ret) != 0)) {
		syslog(LOG_ERR,"%s: import pool(%s) failed, "
			"try again, use 'import -if' instead of 'import -ifs'!",
			__func__, spa_name);
		sprintf(cmd, ZPOOL_CMD_CHANGE_POOL_OWNER_LOCAL, spa_name);
		ret = system(cmd);
		if ((!WIFEXITED(ret)) || (WEXITSTATUS(ret) != 0)) {
			syslog(LOG_ERR,"%s: failed use import -if %s",
				__func__, spa_name);
		} else {
			hdl = libzfs_init();
			if (hdl != NULL) {
				zpool_remove_partner(hdl, spa_name, hostid);
				libzfs_fini(hdl);
			}
		}
	}
#else
	sprintf(cmd, "%s %s", ZPOOL_IMPORT, spa_name);
	if ((ret = excute_cmd_common(cmd, B_TRUE)) != 0) {
		syslog(LOG_ERR, "%s: import '%s' failed, exit_code=%d",
			__func__, spa_name, ret);
	}
#endif
	nvlist_free(ripool);
}

static void
cluster_clear_hbx_event(cluster_event_t *event)
{
	if (event == NULL)
		return;

	if (event->size != 0 && event->data != NULL)
		free(event->data);

	free(event);
}

static void
cluster_clear_all_hbx_event(void)
{
	cluster_event_t *event, *free_event;

	event = cls_thread.cls_event_head.next;
	while (event != NULL) {
		free_event = event;
		event = event->next;
		if (free_event->size != 0 && free_event->data != NULL)
			free(free_event->data);
		free(free_event);
	}
}

static cluster_event_t *
cluster_get_hbx_event(void)
{
	cluster_event_t *event = NULL;

	pthread_mutex_lock(&cls_thread.cls_event_mutex);
	event = cls_thread.cls_event_head.next;
	if (event != NULL) {
		cls_thread.cls_event_head.next = event->next;
	}
	pthread_mutex_unlock(&cls_thread.cls_event_mutex);

	return event;
}

static void
cluster_set_hbx_event(hbx_door_para_t *para, char *data, int len)
{
	int size  = 0;
	cluster_event_t *event, *pevent;
	char *buffer = NULL;
	
	event = malloc(sizeof(cluster_event_t));
	if (event == NULL) {
		syslog(LOG_ERR, "set hbx event malloc failed");
		return;
	}

	if (data != NULL && len != 0) {
		buffer = malloc(len);
		if (buffer == NULL) {
			syslog(LOG_ERR, "set hbx event, malloc data failed");
			return;
		}
		size = len;
		bcopy(data, buffer, size);
	}
	event->event = para->event;
	event->data = buffer;
	event->size = size;
	event->next = NULL;

	pthread_mutex_lock(&cls_thread.cls_event_mutex);
	pevent = &cls_thread.cls_event_head;
	while (pevent->next != NULL) {
		pevent = pevent->next;
	}
	pevent->next = event;
	pthread_mutex_unlock(&cls_thread.cls_event_mutex);
}

static int
excute_cmd_result(const char *cmd, char **result)
{
	int ret, fd;
	char *buf = NULL;
	size_t cmdlen;
	pid_t pid;
	pthread_t tid;
	struct stat sb;
	ssize_t nread;

	cmdlen = strlen(cmd);
	pid = getpid();
	tid = pthread_self();
	buf = (char *) malloc(cmdlen + 64);
	if (buf) {
		snprintf(buf, cmdlen + 64,
			"%s > /tmp/clusterd.%d.%d.stderr 2>&1",
			cmd, (int) pid, (int) tid);
	} else {
		syslog(LOG_ERR, "out of memory");
	}

	c_log(LOG_WARNING, "system('%s')", buf);
	ret = system(buf);

	if (ret == -1) {
		syslog(LOG_ERR,
			"system(): create child failed or cannot receive status of child");
	} else if (!WIFEXITED(ret)) {
		syslog(LOG_ERR,
			"system(): shell could not be executed in the child process");
	} else {
		ret = WEXITSTATUS(ret);
	}

	snprintf(buf, cmdlen+64, "/tmp/clusterd.%d.%d.stderr",
		(int) pid, (int) tid);

	fd = open(buf, O_RDONLY);
	if (fd == -1) {
		syslog(LOG_ERR, "open %s error %d", buf, errno);
		*result = NULL;
		goto out;
	}

	if (fstat(fd, &sb) == -1) {
		syslog(LOG_ERR, "stat %s error %d", buf, errno);
		*result = NULL;
		goto out;
	}

	*result = malloc(sb.st_size + 1);
	if (*result) {
		nread = read(fd, *result, sb.st_size);
		if (nread == -1) {
			syslog(LOG_ERR, "read %s error %d", buf, errno);
			free(*result);
			*result = NULL;
		} else {
			if (nread > 0 && (*result)[nread-1] == '\n')
				(*result)[nread-1] = '\0';
			else
				(*result)[nread] = '\0';
			c_log(LOG_WARNING, "%s", *result);
		}
	}

out:
	if (fd > 0)
		close(fd);
	if (unlink(buf) == -1)
		syslog(LOG_ERR, "unlink %s error %d", buf, errno);

	return (ret);
}

static int
excute_cmd_common(const char *cmd, boolean_t dup2log)
{
	int ret;
	char *buf = NULL;
	size_t cmdlen;
	pid_t pid;
	pthread_t tid;

	if (dup2log) {
		cmdlen = strlen(cmd);
		pid = getpid();
		tid = pthread_self();
		buf = (char *) malloc(cmdlen + 64);
		if (buf) {
			snprintf(buf, cmdlen + 64,
				"%s > /tmp/clusterd.%d.%d.stderr 2>&1",
				cmd, (int) pid, (int) tid);
		} else {
			syslog(LOG_ERR, "out of memory");
		}
	}

	c_log(LOG_WARNING, "system('%s')", cmd);
	if (buf) {
		ret = system(buf);
	} else {
		ret = system(cmd);
	}
	if (ret == -1) {
		syslog(LOG_ERR,
			"system(): create child failed or cannot receive status of child");
	} else if (!WIFEXITED(ret)) {
		syslog(LOG_ERR,
			"system(): shell could not be executed in the child process");
	} else {
		ret = WEXITSTATUS(ret);
	}

	if (buf) {
		snprintf(buf, cmdlen + 64,
			"cat /tmp/clusterd.%d.%d.stderr | logger -p daemon.notice -t clusterd",
			(int) pid, (int) tid);
		(void) system(buf);
		snprintf(buf, cmdlen + 64,
			"unlink /tmp/clusterd.%d.%d.stderr",
			(int) pid, (int) tid);
		(void) system(buf);
		free(buf);
	}

	return (ret);
}


static int
excute_cmd(const char *cmd)
{
	return (excute_cmd_common(cmd, B_FALSE));
}

static int
excute_ifconfig(const char *cmd)
{
	return (excute_cmd_common(cmd, B_TRUE));
}

static inline struct link_list *
create_link(void *data)
{
	struct link_list *node;
	node = (struct link_list *) malloc(sizeof(struct link_list));
	if (node) {
		node->ptr = data;
		node->next = NULL;
	}
	return node;
}

static inline void
free_link_list(struct link_list *list, int free_data)
{
	struct link_list *p = list, *q;
	while (p) {
		q = p;
		p = p->next;
		if (free_data && q->ptr)
			free(q->ptr);
		free(q);
	}
}

static void *
sig_handler_thr(void *data)
{
	pthread_detach(pthread_self());
	cluster_failover_conf_handler(FLAG_CF_RESPTIMEOUT, NULL);
	return (NULL);
}

static void
response_timeout_handler(int sig)
{
	pthread_t tid;
	pthread_create(&tid, NULL, sig_handler_thr, NULL);
}

static int
set_remote_mac_state_response_timer(void)
{
	struct sigaction sa;
	struct itimerval itv;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = response_timeout_handler;
	sa.sa_flags = SA_RESETHAND;
	if (sigaction(SIGALRM, &sa, NULL) == -1) {
		syslog(LOG_ERR, "sigaction() error: signo=SIGALRM, err=%d", errno);
		return (-1);
	}

	itv.it_interval.tv_sec = 0;
	itv.it_interval.tv_usec = 0;
	itv.it_value.tv_sec = 10;
	itv.it_value.tv_usec = 0;
	if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
		syslog(LOG_ERR, "setitimer() error: %d", errno);
		return (-1);
	}
	return (0);
}

static int
clear_remote_mac_state_response_timer(void)
{
	struct itimerval itv;

	itv.it_interval.tv_sec = 0;
	itv.it_interval.tv_usec = 0;
	itv.it_value.tv_sec = 0;
	itv.it_value.tv_usec = 0;
	if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
		syslog(LOG_ERR, "setitimer() error: %d", errno);
		return (-1);
	}
	return (0);
}

static unsigned
cluster_link_state(const char *link)
{
	unsigned linkstate = ils_unknown;
	struct ifs_chain *ifs;
	struct ifs_node *ifn;

	if ((ifs = get_all_ifs()) == NULL)
		return (linkstate);

	for (ifn = ifs->head; ifn; ifn = ifn->next) {
		if (strncmp(ifn->link, link, IFNAMSIZ) == 0) {
			linkstate = ifn->state;
			break;
		}
	}

	free_ifs_chain(ifs);
	return (linkstate);
}

static int __pre_release_zpool(service_zpool_t *zp, 
	struct link_list **eth_list, struct link_list **zpool_list);

static int
__pre_release_ip(service_if_t *ifp, struct link_list **eth_list,
	struct link_list **zpool_list)
{
	struct link_list *p, **pp, *node;
	int cmp = 0;
	char *eth;

	if (!ifp->flag) {
		for (pp = eth_list; *pp && (*pp)->ptr; ) {
			p = *pp;
			cmp = strcmp(ifp->eth, (char *)p->ptr);
			if (cmp >= 0)
				break;
			pp = &p->next;
		}
		if (cmp > 0 || !(*pp)) {
			eth = (char *) malloc(MAXLINKNAMELEN);
			if (!eth)
				return (-1);
			strlcpy(eth, ifp->eth, MAXLINKNAMELEN);
			node = create_link(eth);
			if (!node)
				return (-1);
			node->next = *pp;
			*pp = node;
		}

		ifp->flag = 1;
		for (p = ifp->zpool_list; p && p->ptr; p = p->next) {
			if (__pre_release_zpool((service_zpool_t *)p->ptr, 
				eth_list, zpool_list) != 0)
				return (-1);
		}
	}
	return (0);
}

static int
__pre_release_zpool(service_zpool_t *zp, struct link_list **eth_list,
	struct link_list **zpool_list)
{
	struct link_list *p, *node;
	char *zpool_name;

	if (!zp->flag) {
		zpool_name = (char *) malloc(strlen(zp->zpool_name) + 1);
		if (!zpool_name)
			return (-1);
		strcpy(zpool_name, zp->zpool_name);
		node = create_link(zpool_name);
		if (!node)
			return (-1);
		node->next = *zpool_list;
		*zpool_list = node;

		zp->flag = 1;
		for (p = zp->if_list; p && p->ptr; p = p->next) {
			if (__pre_release_ip((service_if_t *)p->ptr, 
				eth_list, zpool_list) != 0)
				return (-1);
		}
	}
	return (0);
}

static int
pre_release_ip(service_if_t *ifp, struct link_list **eth_list,
	struct link_list **zpool_list, int *reenter)
{
	service_if_t *ip;
	service_zpool_t *zp;

	if (!reenter || *reenter == 0) {
		for (ip = list_head(&failover_ip_list); 
				ip; 
				ip = list_next(&failover_ip_list, ip))
			ip->flag = 0;
		for (zp = list_head(&failover_zpool_list); 
				zp; 
				zp = list_next(&failover_zpool_list, zp))
			zp->flag = 0;
		if (reenter)
			*reenter = 1;
	}

	return __pre_release_ip(ifp, eth_list, zpool_list);
}

static void
init_cluster_failover_conf(void)
{
	cf_conf.remote_down = 0;
	cf_conf.wait_resp = 0;
	cf_conf.todo_mac_offline_event = NULL;
	cf_conf.todo_release_zpool = NULL;
	pthread_mutex_init(&cf_conf.lock, NULL);
}

static void
clear_cluster_failover_conf(void)
{
	cf_conf.wait_resp = 0;
	free_link_list(cf_conf.todo_mac_offline_event, 1);
	free_link_list(cf_conf.todo_release_zpool, 1);
}

typedef struct zpool_iter_data {
	char	poolname[ZPOOL_MAXNAMELEN];
	uint64_t	guid;
} zpool_iter_data_t;

static int
zpool_iter_cb(zpool_handle_t *zhp, void *data)
{
	struct link_list **list = (struct link_list **) data;
	struct link_list *node;
	nvlist_t *config;
	uint64_t guid;
	zpool_iter_data_t *pool;

	config = zpool_get_config(zhp, NULL);
	if (!config) {
		zpool_close(zhp);
		return (-1);
	}
	if (!pool_in_cluster(config)) {
		zpool_close(zhp);
		return (0);
	}
	verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &guid) == 0);

	pool = malloc(sizeof (zpool_iter_data_t));
	if (pool == NULL) {
		zpool_close(zhp);
		return (-1);
	}
	strlcpy(pool->poolname, zpool_get_name(zhp), ZPOOL_MAXNAMELEN);
	pool->guid = guid;

	node = create_link(pool);
	if (!node) {
		free(pool);
		zpool_close(zhp);
		return (-1);
	}
	node->next = *list;
	*list = node;
	zpool_close(zhp);
	return (0);
}

static void
req_remote_mac_state(const char *mac_name)
{
	service_if_t *ifp;
	struct link_list *eth_list = NULL, *zpool_list = NULL;
	struct link_list *p;
	mac_state_param_t request;
	int i, reenter = 0;

	pthread_mutex_lock(&failover_list_lock);
	for (ifp = list_head(&failover_ip_list); 
		ifp; 
		ifp = list_next(&failover_ip_list, ifp)) {
		if (strcmp(ifp->eth, mac_name) == 0 &&
			pre_release_ip(ifp, &eth_list, &zpool_list, &reenter) != 0)
			break;
	}
	pthread_mutex_unlock(&failover_list_lock);

	if (!ifp && eth_list) {
		request.hostid = get_system_hostid();
		request.flag = FLAG_MAC_STATE_GET_REMOTE;
		for (p = eth_list, i = 0; 
			p && i < MAX_MAC_STATE_REQ_NUM; 
			p = p->next, i++) {
			strlcpy(request.mac_list[i], p->ptr, MAXLINKNAMELEN);
		}
		request.mac_num = i;
		hbx_do_cluster_cmd((char *)&request, 
				sizeof(mac_state_param_t), ZFS_HBX_MAC_STAT);
		free_link_list(eth_list, 1);
		cf_conf.todo_release_zpool = zpool_list;
		cf_conf.wait_resp = 1;

		set_remote_mac_state_response_timer();
		return;
	}

	if (eth_list)
		free_link_list(eth_list, 1);
	if (zpool_list)
		free_link_list(zpool_list, 1);
}

static int
cluster_failover_conf_handler(int flag, const void *data)
{
	pthread_mutex_lock(&cf_conf.lock);
	switch (flag) {
	case FLAG_CF_MAC_OFFLINE:
	{
		char *mac_name;
		struct link_list **pp, *node;

		if (cf_conf.remote_down) {
			syslog(LOG_WARNING, "handle mac offline, but remote down");
			clear_cluster_failover_conf();
			pthread_mutex_unlock(&cf_conf.lock);
			return (0);
		}

		if (cf_conf.wait_resp) {
			mac_name = (char *) malloc(MAXLINKNAMELEN);
			if (!mac_name) {
				pthread_mutex_unlock(&cf_conf.lock);
				return (-1);
			}
			strlcpy(mac_name, data, MAXLINKNAMELEN);
			node = create_link(mac_name);
			if (!node) {
				pthread_mutex_unlock(&cf_conf.lock);
				return (-1);
			}
			for (pp = &cf_conf.todo_mac_offline_event; *pp; )
				pp = &(*pp)->next;
			*pp = node;
			pthread_mutex_unlock(&cf_conf.lock);
			return (0);
		}

		req_remote_mac_state(data);
		break;
	}
	case FLAG_CF_RESPONSE:
	{
		struct link_list *p;
		mac_state_param_t *msp;
		int i;
		release_pools_message_t rmsg;
		char *buf;

		clear_remote_mac_state_response_timer();

		if (cf_conf.wait_resp && cf_conf.todo_release_zpool) {
			msp = (mac_state_param_t *) data;

			for (i = 0; i < msp->mac_num; i++) {
				if (msp->linkstate[i] != ils_up) {
					syslog(LOG_WARNING, "remote link %s state: %d",
						msp->mac_list[i], msp->linkstate[i]);
					break;
				}
			}
			if (i > 0 && i == msp->mac_num) {
				rmsg.remote_id = 0;
				rmsg.pools_num = 0;
				for (p = cf_conf.todo_release_zpool; p; p = p->next) {
					buf = (char *) malloc(ZPOOL_MAXNAMELEN);
					if (!buf)
						break;
					strlcpy(buf, p->ptr, ZPOOL_MAXNAMELEN);
					rmsg.pools_list[rmsg.pools_num++] = buf;
				}
				if (p != NULL)
					syslog(LOG_ERR, "%s: out of memory", __func__);
				else
					handle_release_message_common(&rmsg);
				for (i = 0; i < rmsg.pools_num; i++)
					free(rmsg.pools_list[i]);
			}

			free_link_list(cf_conf.todo_release_zpool, 1);
			cf_conf.todo_release_zpool = NULL;
		}
		cf_conf.wait_resp = 0;

		if (cf_conf.todo_mac_offline_event) {
			p = cf_conf.todo_mac_offline_event;
			req_remote_mac_state(p->ptr);
			cf_conf.todo_mac_offline_event = p->next;
			free(p->ptr);
			free(p);
		}
		break;
	}
	case FLAG_CF_RESPTIMEOUT:
	{
		struct link_list *p;

		syslog(LOG_WARNING, "wait response timeout");
		if (cf_conf.todo_release_zpool) {
			free_link_list(cf_conf.todo_release_zpool, 1);
			cf_conf.todo_release_zpool = NULL;
		}
		cf_conf.wait_resp = 0;

		if (cf_conf.todo_mac_offline_event) {
			p = cf_conf.todo_mac_offline_event;
			req_remote_mac_state(p->ptr);
			cf_conf.todo_mac_offline_event = p->next;
			free(p->ptr);
			free(p);
		}
		break;
	}
	case FLAG_CF_REMOTE_DOWN:
		clear_cluster_failover_conf();
		cf_conf.remote_down = 1;
		break;
	case FLAG_CF_REMOTE_UP:
		cf_conf.remote_down = 0;
		break;
	}
	pthread_mutex_unlock(&cf_conf.lock);
	return (0);
}

static int
cluster_import_broadcast(uint64_t pool_guid, uint64_t hostid)
{
	cluster_import_msg_t msg;

	msg.hostid = hostid;
	msg.pool_guid = pool_guid;
	msg.msgtype = CLUSTER_IMPORT_MSGTYPE_NOTIFY;

	return (hbx_do_cluster_cmd_ex((char *) &msg, sizeof (msg),
		ZFS_HBX_CLUSTER_IMPORT, 0));
}

static int
cluster_import_response(uint64_t pool_guid, uint64_t hostid, uint64_t remoteid)
{
	cluster_import_msg_t msg;

	msg.hostid = hostid;
	msg.pool_guid = pool_guid;
	msg.msgtype = CLUSTER_IMPORT_MSGTYPE_RESPONSE;

	return (hbx_do_cluster_cmd_ex((char *) &msg, sizeof (msg),
		ZFS_HBX_CLUSTER_IMPORT, (int) remoteid));
}

static int
zfs_iter_cb(zfs_handle_t *zhp, void *data)
{
	int err = 0;
	nvlist_t *user_props = zfs_get_user_props(zhp);
	nvpair_t *elem = NULL;
	nvlist_t *propval;
	char *strval, *sourceval;
	const char *zfsname; 
	char buf[ZFS_MAXNAMELEN+ZFS_MAXPROPLEN];
	service_zpool_t *zp;
	service_if_t *ifp;
	failover_conf_t conf;
	struct link_list *p;
	int exists = 0;

	zfsname = zfs_get_name(zhp);

	while ((elem = nvlist_next_nvpair(user_props, elem)) != NULL) {
		if (!zfs_is_failover_prop(nvpair_name(elem)))
			continue;
		err = nvlist_lookup_nvlist(user_props, nvpair_name(elem), &propval);
		if (err != 0) {
			syslog(LOG_ERR, "get property error: %d", err);
			zfs_close(zhp);
			return (err);
		}
		verify(nvlist_lookup_string(propval, ZPROP_VALUE, &strval) == 0);
		verify(nvlist_lookup_string(propval, ZPROP_SOURCE, &sourceval) == 0);
		if (strcmp(sourceval, zfsname) == 0) {
			snprintf(buf, sizeof(buf), "%s,%s,%s",
				zfsname, nvpair_name(elem), strval);
			
			if (parse_failover_conf(buf, &conf)) {
				syslog(LOG_ERR, 
					"parse_failover_conf(): failed to parse msg: %s", buf);
				zfs_close(zhp);
				return (-1);
			}

			exists = 0;
			pthread_mutex_lock(&failover_list_lock);
			for (zp = list_head(&failover_zpool_list); 
				zp; 
				zp = list_next(&failover_zpool_list, zp)) {
				if (strcmp(zp->zpool_name, conf.zpool_name) == 0) {
					for (p = zp->if_list; p; p = p->next) {
						ifp = (service_if_t *) p->ptr;
						if (strcmp(ifp->ip_addr, conf.ip_addr) == 0) {
							exists = 1;
							syslog(LOG_WARNING, "zfs_iter_cb: %s:%s exists", 
								zfsname, conf.ip_addr);
							break;
						}
					}
					break;
				}
			}
			pthread_mutex_unlock(&failover_list_lock);

			if (!exists)
				do_ip_failover(&conf, 1);
		}
	}

	if (zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM)
		err = zfs_iter_filesystems(zhp, zfs_iter_cb, NULL);

	zfs_close(zhp);
	return (err);
}

/* 
 * Used for add that failover conf of zpools 
 * which imported before clusterd boot,
 * and used for restore the failover conf when
 * reboot clusterd
 */
static int
init_zpool_failover_conf(void)
{
	libzfs_handle_t *hdl;
	int err;

	if ((hdl = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "get zfs handle failed");
		return (-1);
	}
	err = zfs_iter_root(hdl, zfs_iter_cb, NULL);
	if (err) {
		syslog(LOG_ERR, "zfs_iter_root() error: %d", err);
	}
	libzfs_fini(hdl);
	return (err);
}

static int 
cluster_do_remote_cmd_impl(void *arg)
{
	cluster_event_t *cmd_buf = arg;
	char *cmd_data = cmd_buf->data;
	int size = cmd_buf->size;
	FILE *fptr;
	char pcmd[512];
	nvlist_t *nvl_cmd;
	nvlist_t *nvl_ret;
	uint32_t hostid;
	uint64_t cmd_id;
	char *cmd_str;
	char *buf;
	size_t buflen;
	int ret = 0;

	pthread_detach(pthread_self());

	ret = nvlist_unpack(cmd_data, size, &nvl_cmd, 0);
	if (ret != 0) {
		cluster_clear_hbx_event(cmd_buf);
		return (-1);
	}

	if (nvlist_lookup_uint64(nvl_cmd, "cmd_id", &cmd_id) != 0) {
		goto out;
	}
	if (nvlist_lookup_string(nvl_cmd, "cmd_str", &cmd_str) != 0) {
		goto out;
	}
	if (nvlist_lookup_uint32(nvl_cmd, "hostid", &hostid) != 0) {
		goto out;
	}
	syslog(LOG_INFO, "clustersan: do host(%d)'s cmd(%"PRIx64": %s)",
		hostid, cmd_id, cmd_str);
	snprintf(pcmd, 512, "%s 2>&1", cmd_str);
	fptr = popen(pcmd, "r");
	if (fptr != NULL) {
		while (fgets(pcmd, 512, fptr) != NULL) {
			syslog(LOG_INFO, "clustersan: cmd(%"PRIx64") %s", cmd_id,
				pcmd);
		}
		ret = pclose(fptr);
	} else {
		syslog(LOG_INFO, "clustersan: use system()");
		ret = system(cmd_str);
	}

	if (nvlist_alloc(&nvl_ret, NV_UNIQUE_NAME, 0) != 0) {
		goto out;
	}
	nvlist_add_uint32(nvl_ret, "hostid", hostid);
	nvlist_add_uint64(nvl_ret, "cmd_id", cmd_id);
	nvlist_add_int32(nvl_ret, "return", ret);
	verify(nvlist_size(nvl_ret, &buflen, NV_ENCODE_NATIVE) == 0);
	buf = calloc(1, buflen);
	if (buf == NULL) {
		nvlist_free(nvl_ret);
		goto out;
	}
	verify(nvlist_pack(nvl_ret, &buf, &buflen, NV_ENCODE_NATIVE, 0) == 0);
	nvlist_free(nvl_ret);
	hbx_do_cluster_cmd(buf, buflen, ZFS_HBX_CLUSTERSAN_SYNC_CMD);
	free(buf);
out:
	nvlist_free(nvl_cmd);
	cluster_clear_hbx_event(cmd_buf);

	return (ret);
}

static int 
cluster_do_remote_cmd(char *cmd_data, int size)
{
	pthread_t pid;
	cluster_event_t *cmd_buf;
	char *buf;
	int ret;

	cmd_buf = malloc(sizeof(cluster_event_t));
	buf = malloc(size);
	bcopy(cmd_data, buf, size);
	cmd_buf->data = buf;
	cmd_buf->size = size;
	ret = pthread_create(&pid, NULL,
		(void *(*)(void *))cluster_do_remote_cmd_impl, (void *)cmd_buf);

	if (ret != 0) {
		cluster_clear_hbx_event(cmd_buf);
	}
	return (ret);
}

#if	0
static void
clusternas_failover_ctl_worker(void* arg)
{
	service_zpool_t *zp;
	struct link_list *p;
	service_if_t *ifp;
	char *buffer = (char *)arg;
	char *zpool_name;
	char *time;
	int pool_name_len;
	char cmd[512];

	zpool_name = strtok((char*)buffer, ":");
	time = strtok(NULL, ":");
	
	//pthread_mutex_lock(&failover_list_lock);
	for (zp = list_head(&failover_zpool_list); 
		zp; 
		zp = list_next(&failover_zpool_list, zp)) {
		if (strcmp(zp->zpool_name, zpool_name) == 0) {
			for (p = zp->if_list; p; p = p->next) {
				ifp = (service_if_t *) p->ptr;
				//if (*time == '0') {
					//sprintf(cmd, "%s %s addif %s", IFCONFIG_CMD, ifp->eth, ifp->ip_addr);
				//} else {
				syslog(LOG_ERR, "Cluster nas removeif %s:%s %s's for %s;", ifp->eth, ifp->ip_addr, time, zpool_name);
					sprintf(cmd, "%s %s removeif %s && sleep %s && %s %s addif %s up", 
						IFCONFIG_CMD, ifp->eth, ifp->ip_addr, time, IFCONFIG_CMD, ifp->eth, ifp->ip_addr);
				syslog(LOG_ERR, "Cluster nas addif %s:%s %s's for %s;", ifp->eth, ifp->ip_addr, time, zpool_name);
				//}
				system(cmd);
			}
			break;
		}
	}
	//pthread_mutex_unlock(&failover_list_lock);
	free(arg);
}


static void
clusternas_failover_ctl(const void *buffer, int bufsize)
{
	int ret;
	pthread_t pid;
	char *buff;

	buff = malloc(bufsize);
	bcopy(buffer, buff, bufsize);

	ret = pthread_create(&pid, NULL, (void *(*)(void *))clusternas_failover_ctl_worker, (void *)buff);
}
#endif

static void
cluster_task_wait_event(void)
{
	/*int ret;*/
	boolean_t wait = B_TRUE;
	/*cluster_state_t cls_state = CLUSTER_INIT;*/
	cluster_event_t *event = NULL;
	uint32_t hostid;

	syslog(LOG_ERR, "cluster task wait event");
	/*
	 * do process according to the change of hbx state, should never exit
	 */
	while (wait) {
		pthread_mutex_lock(&cls_thread.cls_mutex);
		while ((event = cluster_get_hbx_event()) == NULL) {
			pthread_cond_wait(&cls_thread.cls_cond, &cls_thread.cls_mutex);
		}
		pthread_mutex_unlock(&cls_thread.cls_mutex);

		syslog(LOG_INFO, "cluster event is %d", event->event);
		/*cls_state = cluster_get_sys_state();*/
		switch (event->event) {
		case EVT_CHANGE_POOL_OWNER:
			cluster_change_pool_owner(event->data, event->size);
			break;
		case EVT_UPDATE_PARTNER_NIC_CONFIG:
			syslog(LOG_ERR, "cluster update nic, size:%d", event->size);
			/*cluster_update_partner_nic(event->data, event->size);*/
			break;
		case EVT_UPDATE_KEYFILE:
			cluster_update_keyfile(event->data, event->size);
			break;
		case EVT_UPDATE_KEYPATH:
			cluster_update_keyfile_path(event->data, event->size);
			break;
		case EVT_UPDATE_RCMD:
			cluster_update_remote_cmd(event->data, event->size);
			break;
		case EVT_REMOTE_HOST_UP:
			hostid = *((uint32_t *)event->data);
			syslog(LOG_ERR, "cluster event remote host:%d up", hostid);
			hbx_do_cluster_cmd(event->data, event->size, ZFS_HBX_SYNC_POOL);
			cluster_remote_hbx_recover(hostid);
			pthread_cond_broadcast(&cluster_import_replicas_cv);
			break;
		case EVT_REMOTE_HOST_DOWN:
			hostid = *((uint32_t *)event->data);
			syslog(LOG_ERR, "cluster event remote host:%d down", hostid);
			cluster_remote_hbx_timeout(hostid);
			break;

		case EVT_SYNCKEY_RESULT: {
			int fifo_fd;
			char recv_ID[16];		/* recv the synckey pid */
			char fifo_name[512];
			char fifo_buffer[16];	/* save fail or success infor */

			bzero(recv_ID, 16);
			bzero(fifo_buffer, 16);

			strncpy(recv_ID, event->data, MAX_ID_BYTE);

			/* send the synckey result to synckey-process */
			bzero(fifo_name, 512);
			sprintf(fifo_name, "/tmp/synckeyrebak%s", recv_ID);
			fifo_fd = open(fifo_name, O_WRONLY);
				if (fifo_fd != -1) {
					strcpy(fifo_buffer, event->data + MAX_ID_BYTE);
					write(fifo_fd, fifo_buffer, sizeof(fifo_buffer));
					close(fifo_fd);				
				} else {
					syslog(LOG_ERR, "open FIFO fail");
				}
			}
			break;
		case EVT_MAC_STATE: {
			mac_state_param_t mac_state, *msp;
			int i;
			
			if (event->size != sizeof(mac_state_param_t)) {
				syslog(LOG_ERR, "EVT_MAC_STATE: invalid data");
			} else {
				msp = (mac_state_param_t *)event->data;
				if (msp->flag == FLAG_MAC_STATE_REMOTE_STATE)
					cluster_failover_conf_handler(FLAG_CF_RESPONSE, event->data);
				else if (msp->flag == FLAG_MAC_STATE_GET_REMOTE) {
					mac_state.flag = FLAG_MAC_STATE_REMOTE_STATE;
					mac_state.mac_num = msp->mac_num;
					for (i = 0; i < msp->mac_num; i++) {
						if (cluster_link_state(msp->mac_list[i]) != ils_up) {
							syslog(LOG_WARNING, "link %s dwon", msp->mac_list[i]);
							mac_state.mac_num = 0;
							break;
						}
						strlcpy(mac_state.mac_list[i], msp->mac_list[i], MAXLINKNAMELEN);
						mac_state.linkstate[i] = ils_up;
					}
					hbx_do_cluster_cmd_ex((char *)&mac_state, 
						sizeof(mac_state_param_t), ZFS_HBX_MAC_STAT, msp->hostid);
				} else if (msp->flag == FLAG_MAC_STATE_IP_RELEASED) {
					/* remote released the IPs, we do ip failover now */
					/* old ip failover */
				}
			}
			break;
		}
		case EVT_MAC_OFFLINE:
#if	0
			if (event->size != MAXLINKNAMELEN)
				syslog(LOG_ERR, "EVT_MAC_OFFLINE: invalid data");
			else
				ret = cluster_failover_conf_handler(FLAG_CF_MAC_OFFLINE, event->data);
#endif
			break;
		case EVT_SPA_REMOTE_HUNG:
			hostid = *((uint32_t *)event->data);
			cluster_remote_spa_hung(hostid);
			break;
		case EVT_SPA_REMOTE_NORESPONSE:
			cluster_remote_spa_noresponse();
			break;
		case EVT_SPA_REMOTE_RESPONSE:
			cluster_remote_spa_response();
			break;
		case EVT_IPMI_EXCHANGE_IP:
			ipmi_send_local_ip(0);
			break;
		case EVT_IPMI_ADD_ROUTE:
			ipmi_route_add(event->data);
			break;
		case EVT_HBX_CLOSED:
			cluster_hbx_closed();
			break;
		case EVT_RELEASE_POOLS:
			handle_release_pools_event(event->data, event->size);
			break;
		case EVT_CLUSTERSAN_SYNC_CMD:
			cluster_do_remote_cmd(event->data, event->size);
			break;
		case EVT_CLUSTER_IMPORT:
			cluster_import_event_handler(event->data, event->size);
			break;
		case EVT_POWEROFF_REMOTEHOST:
			cluster_poweroff_remote_event_handler(event->data, event->size);
			break;
		case EVT_POWERON_REMOTEHOST:
			cluster_poweron_remote_event_handler(event->data, event->size);
			break;
		case EVT_CLUSTERNAS_FAILOVER_CTL:
			/*clusternas_failover_ctl(event->data, event->size);*/
			break;
		case EVT_CLUSTER_CLOSE_RDMA_RPC: {
#if	0
				int rpc_upid = *((int *)event->data);
				syslog(LOG_ERR, "cluster event close rpc process, pid:%d",
					rpc_upid);
				if (rpc_upid != 0) {
					kill(rpc_upid, SIGKILL);
				}
				break;
#endif
			}
		default:
			break;
		}

		cluster_clear_hbx_event(event);
	}
}

static void *
cluster_import_pools_thr(void *arg)
{
	todo_import_pool_node_t *pool;
	char cmd[256];
	
	while (!import_thr_conf.exit_flag ||
		!list_is_empty(&import_thr_conf.todo_import_pools)) {
		pool = list_head(&import_thr_conf.todo_import_pools);
		if (pool) {
			snprintf(cmd, 256, "%s %llu", ZPOOL_IMPORT, 
				(unsigned long long)pool->guid);
			if (excute_cmd_common(cmd, B_TRUE) != 0)
				syslog(LOG_ERR, "%s: import pool '%s' failed", __func__,
					pool->poolname);
			else
				syslog(LOG_WARNING, "%s: import pool '%s' success",
					__func__, pool->poolname);
			pool->imported = 1;
			pthread_mutex_lock(&import_thr_conf.list_mtx);
			list_remove(&import_thr_conf.todo_import_pools, pool);
			pthread_mutex_unlock(&import_thr_conf.list_mtx);
			list_insert_tail(&import_thr_conf.imported_pools, pool);
		} else {
			pthread_mutex_lock(&import_thr_conf.mtx);
			pthread_cond_wait(&import_thr_conf.cond, &import_thr_conf.mtx);
			pthread_mutex_unlock(&import_thr_conf.mtx);
		}
	}
	return (NULL);
}

static todo_import_pool_node_t *
add_todo_import_pool(const char *name, uint64_t guid)
{
	todo_import_pool_node_t *pool;

	pool = (todo_import_pool_node_t *) malloc(sizeof(todo_import_pool_node_t));
	if (!pool) {
		syslog(LOG_ERR, "alloc todo_import_pool_node_t failed");
		return (NULL);
	}
	strlcpy(pool->poolname, name, ZPOOL_MAXNAMELEN);
	pool->guid = guid;
	pool->imported = 0;
	pthread_mutex_lock(&import_thr_conf.list_mtx);
	list_insert_tail(&import_thr_conf.todo_import_pools, pool);
	pthread_mutex_unlock(&import_thr_conf.list_mtx);

	pthread_cond_signal(&import_thr_conf.cond);
	return (pool);
}

#if	0
static int
get_disk_owners(char **disks, int diskcount, int *owners)
{
	dmg_lun_t *luns, *lun;
	int lun_count, i;

	if (dmg_get_disk(&luns, &lun_count) != 1) {
		syslog(LOG_ERR, "dmg_get_disk error");
		return (-1);
	}

	for (i = 0; i < diskcount; i++) {
		for (lun = luns; lun != NULL; lun = lun->lun_next) {
			if (strncmp(lun->name + 10, disks[i], strlen(disks[i]) - 2) == 0)
				break;
		}
		if (lun != NULL) {
			/*
			 * owner indicate node id in cluster, the host ids
			 * is (nodeid*2-1) and (nodeid*2); if owner is 0, indicate
			 * it's local disk.
			 */
			owners[i] = lun->en_no / 1000;
		}
	}

	dmg_free_lunlink(luns);
	return (0);
}

static int
get_smallest_owner(int *owners, int count)
{
	int smallest = 0, i;

	for (i = 0; i < count; i++) {
		if (owners[i] > 0) {
			smallest = owners[i];
			break;
		}
	}
	for (; i < count; i++) {
		if (owners[i] > 0 && owners[i] < smallest)
			smallest = owners[i];
	}
	return (smallest);
}

static char *
choose_critical_disk(char **disks, int diskcount)
{
	dmg_lun_t *luns, *lun;
	int lun_count, i;

	if (dmg_get_disk(&luns, &lun_count) != 1) {
		syslog(LOG_ERR, "dmg_get_disk error");
		return (NULL);
	}

	/* 
	 * choose smaller enid, if enid is equal, choose smaller slot id;
	 * luns is sorted by enid and slot id.
	 */
	for (lun = luns; lun != NULL; lun = lun->lun_next) {
		for (i = 0; i < diskcount; i++) {
			if (strncmp(lun->name + 10, disks[i], strlen(disks[i]) - 2) == 0)
				break;
		}
		if (i < diskcount)
			break;
	}

	dmg_free_lunlink(luns);
	return (i < diskcount ? disks[i]: NULL);
}

uint_t cluster_hostlist_add(uint_t *hostlist, uint_t hostid)
{
	uint_t c;

	for (c = 0; c < hostlist[0]; c++) {
		if (hostlist[1 + c] == hostid)
			break;
	}
	if (c == hostlist[0])
		hostlist[++hostlist[0]] = hostid;

	return hostlist[0];
}

boolean_t cluster_hostlist_exist(uint_t *hostlist, uint_t hostid)
{
	uint_t c;
	
	for (c = 0; c < hostlist[0]; c++) {
		if (hostlist[1 + c] == hostid)
			return TRUE;
	}

	return FALSE;
}

uint_t cluster_hostlist_smallest(uint_t *hostlist, uint_t hostid)
{
	uint_t c;
	uint_t temp = 255;
	
	for (c = 0; c < hostlist[0]; c++) {
		if ((hostlist[1 + c] > hostid) && (hostlist[1 + c] < temp)) {
			temp = hostlist[1 + c];
		}
	}

	if (temp == 0xffffffff)
		return 0;
	else
		return temp;
}

void cluster_check_pool_disk(nvlist_t *pool_root,
	uint_t *disk_total,	uint_t *disk_active,
	uint_t *host_total, uint_t *host_active, char **disks)
{
	char *path;
	int fd, ret = 0;
	nvlist_t **child;
	uint_t i,  c;
	uint_t children = 0;
	char tmp_path[1024];
	uint64_t enid;
	uint_t hostid = 0;

	if ((disk_active == NULL) || (disk_total == NULL) || (pool_root == NULL))
		return;

	*disk_total = *disk_active = 0;
	verify(nvlist_lookup_nvlist_array(pool_root, ZPOOL_CONFIG_CHILDREN,
		&child, &children) == 0);
	for (i = 0; i < children; i ++) {
		nvlist_t **tmp_child;
		uint_t tmp_children = 0;
		
		if (nvlist_lookup_nvlist_array(child[i], ZPOOL_CONFIG_CHILDREN,
			&tmp_child, &tmp_children) == 0) {
			cluster_check_pool_disk(child[i], disk_total, disk_active,
				host_total, host_active, disks);
		} else {
			ret = nvlist_lookup_string(child[i], ZPOOL_CONFIG_PATH, &path);
			if (ret != 0) {
				syslog(LOG_ERR, "pool get config path failed");
				continue;
			}
			(*disk_total)++;

			if (host_total != NULL) {
				ret = nvlist_lookup_uint64(child[i], ZPOOL_CONFIG_DEV_ENCLOSURE_ID, &enid);
				if (ret == 0) {
					if (enid > 1000) {
						hostid = enid/1000 + 1;
						/* cluster_hostlist_add(host_total, hostid); */
					}
				}
				cluster_hostlist_add(host_total, hostid);
			}
			
			if (strncmp(path, "/dev/dsk/", 9) == 0)
				path += 9;
			sprintf(tmp_path, "/dev/rdsk/%s", path);
			fd = open(tmp_path, O_RDONLY|O_NDELAY);
			if (fd > 0) {
				close(fd);
				disks[*disk_active] = strdup(path);
				(*disk_active)++;
				if ((hostid > 0) && (host_active != NULL))
					cluster_hostlist_add(host_active, hostid);
					
			}
		}
	}
}
#endif

static nvlist_t *
cluster_get_remote_pools(uint64_t remoteid)
{
	libzfs_handle_t *libzfs;
	nvlist_t *state, *hostlist, *remote_hostlist, *nvl_host, *hostinfo,
		*poollist, *nvl_pool, *remote_pools = NULL;
	nvpair_t *host, *nvp_pool;
	uint32_t cs_state, host_state;
	uint32_t hostid;
	char *poolname;

	if ((libzfs = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "libzfs_init error");
		return (NULL);
	}

	state = zfs_clustersan_get_nvlist(libzfs, ZFS_CLUSTERSAN_STATE, NULL, 0);
	if (state == NULL) {
		syslog(LOG_ERR, "get clustersan state failed");
		libzfs_fini(libzfs);
		return (NULL);
	}

	verify(nvlist_lookup_uint32(state, CS_NVL_STATE, &cs_state) == 0);
	if (cs_state == 0) {
		syslog(LOG_WARNING, "clustersan disabled");
		libzfs_fini(libzfs);
		return (NULL);
	}

	if (nvlist_alloc(&remote_pools, 0, 0) != 0)
		goto nomem;

	hostlist = zfs_clustersan_get_nvlist(libzfs, ZFS_CLUSTERSAN_LIST_HOST,
		NULL, ZFS_CLUSTER_POOL_LIST_FLAG);
	if (hostlist && nvlist_lookup_nvlist(hostlist, CS_NVL_REMOTE_HOST, 
		&remote_hostlist) == 0) {
		host = NULL;
		while ((host = nvlist_next_nvpair(remote_hostlist, host)) != NULL) {
			verify(0 == nvpair_value_nvlist(host, &nvl_host));
			verify(0 == nvlist_lookup_uint32(nvl_host, CS_NVL_HOST_ID, 
				&hostid));

			if (remoteid > 0 && hostid != remoteid)
				continue;

			hostinfo = zfs_clustersan_get_nvlist(libzfs, 
				ZFS_CLUSTERSAN_GET_HOSTINFO, (void *)(uintptr_t)hostid, 
				ZFS_CLUSTER_POOL_LIST_FLAG | ZFS_CLUSTER_SESSION_LIST_FLAG);
			if (hostinfo && nvlist_lookup_uint32(hostinfo, CS_NVL_STATE,
				&host_state) == 0) {
				if (host_state != 0 && nvlist_lookup_nvlist(hostinfo, CS_NVL_POOL_LIST,
					&poollist) == 0) {
					nvp_pool = NULL;
					while ((nvp_pool = nvlist_next_nvpair(poollist,
						nvp_pool)) != NULL) {
						verify(0 == nvpair_value_nvlist(nvp_pool, &nvl_pool));
						verify(nvlist_lookup_string(nvl_pool, ZPOOL_CONFIG_POOL_NAME,
			    			&poolname) == 0);
						if (nvlist_add_nvlist(remote_pools, poolname, nvl_pool) != 0)
							goto nomem;
					}
				}
			} else
				syslog(LOG_ERR, "%s: get host state failed, hostinfo=%p",
					__func__, hostinfo);
		}
	}

	libzfs_fini(libzfs);
	return (remote_pools);
nomem:
	syslog(LOG_ERR, "out of memory");
	if (remote_pools)
		nvlist_free(remote_pools);
	libzfs_fini(libzfs);
	return (NULL);
}

static boolean_t
cluster_pool_in_remote(uint64_t remoteid, const char *poolname, uint64_t pool_guid)
{
	nvlist_t *remote_pools, *nvl_pool;
	nvpair_t *nvp = NULL;
	char *name;
	uint64_t guid;

	remote_pools = cluster_get_remote_pools(remoteid);
	if (remote_pools == NULL)
		return (B_FALSE);

	while ((nvp = nvlist_next_nvpair(remote_pools, nvp)) != NULL) {
		verify(nvpair_value_nvlist(nvp, &nvl_pool) == 0);
		verify(nvlist_lookup_string(nvl_pool, ZPOOL_CONFIG_POOL_NAME, 
			&name) == 0);
		verify(nvlist_lookup_uint64(nvl_pool, ZPOOL_CONFIG_POOL_GUID, 
			&guid) == 0);
		if ((poolname == NULL && guid == pool_guid) ||
			(poolname != NULL && (strcmp(name, poolname) == 0)))
			break;
	}

	nvlist_free(remote_pools);
	return (nvp != NULL);
}

static struct link_list *
cluster_get_local_pools(void)
{
	struct link_list	*poollist = NULL;
	libzfs_handle_t	*hdl;

	if ((hdl = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "%s: libzfs_init() error", __func__);
		return (NULL);
	}

	if (zpool_iter(hdl, zpool_iter_cb, &poollist) != 0) {
		syslog(LOG_ERR, "%s: zpool_iter() error", __func__);
		if (poollist != NULL) {
			free_link_list(poollist, 1);
			poollist = NULL;
		}
	}

	libzfs_fini(hdl);
	return (poollist);
}

static boolean_t
cluster_pool_in_local(const char *poolname, uint64_t pool_guid)
{
	struct link_list *poollist, *p;
	zpool_iter_data_t *pool;
	boolean_t ret = B_FALSE;

	poollist = cluster_get_local_pools();
	for (p = poollist; p; p = p->next) {
		pool = (zpool_iter_data_t *) p->ptr;
		if ((poolname == NULL && pool->guid == pool_guid) ||
			(poolname != NULL && (strcmp(pool->poolname, poolname) == 0))) {
			ret = B_TRUE;
			break;
		}
	}

	if (poollist != NULL)
		free_link_list(poollist, 1);
	return (ret);
}

static void
cluster_import_poollist_init(void)
{
	pthread_mutex_init(&cluster_import_poollist_lock, NULL);
	list_create(&cluster_import_poollist_ready, sizeof (cluster_import_pool_t),
		offsetof(cluster_import_pool_t, node));
	list_create(&cluster_import_poollist_run, sizeof (cluster_import_pool_t),
		offsetof(cluster_import_pool_t, node));
}

static void
cluster_import_pool_destroy(cluster_import_pool_t *pool)
{
	pthread_mutex_lock(&cluster_import_poollist_lock);
	verify(!list_link_active(&pool->node));
	pthread_mutex_destroy(&pool->import_lock);
	pthread_cond_destroy(&pool->import_cv);
	free(pool);
	pthread_mutex_unlock(&cluster_import_poollist_lock);
}

static cluster_import_pool_t *
cluster_search_import(list_t *poollist, const char *poolname, uint64_t pool_guid,
	boolean_t have_lock)
{
	cluster_import_pool_t *pool = NULL;
	list_t *list = poollist;

	if (!have_lock)
		pthread_mutex_lock(&cluster_import_poollist_lock);
	if (list == NULL)
		list = &cluster_import_poollist_ready;
search:
	for (pool = list_head(list); pool; pool = list_next(list, pool)) {
		if ((poolname == NULL && pool->guid == pool_guid) ||
			(poolname != NULL && (strcmp(pool->name, poolname) == 0)))
			break;
	}
	if (pool == NULL && poollist == NULL &&
		(list == &cluster_import_poollist_ready)) {
		list = &cluster_import_poollist_run;
		goto search;
	}
	if (!have_lock)
		pthread_mutex_unlock(&cluster_import_poollist_lock);
	return (pool);
}

static cluster_import_pool_t *
cluster_ready_import(const char *poolname, uint64_t pool_guid)
{
	cluster_import_pool_t *pool;

	pthread_mutex_lock(&cluster_import_poollist_lock);

	/* a same name pool already on list, check guid */
	pool = cluster_search_import(NULL, poolname, 0, B_TRUE);
	if (pool != NULL)
		goto exit_func;

	pool = malloc(sizeof (cluster_import_pool_t));
	if (pool == NULL)
		goto exit_func;
	strlcpy(pool->name, poolname, ZPOOL_MAXNAMELEN);
	pool->guid = pool_guid;
	pthread_mutex_init(&pool->import_lock, NULL);
	pthread_cond_init(&pool->import_cv, NULL);
	pool->import_state = CLUSTER_IMPORT_READY;
	pool->ref = 1;
	list_insert_head(&cluster_import_poollist_ready, pool);

exit_func:
	pthread_mutex_unlock(&cluster_import_poollist_lock);
	return (pool);
}

static void
cluster_run_import(cluster_import_pool_t *pool)
{
	pthread_mutex_lock(&cluster_import_poollist_lock);
	verify(pool->import_state == CLUSTER_IMPORT_READY);
	list_remove(&cluster_import_poollist_ready, pool);
	list_insert_head(&cluster_import_poollist_run, pool);
	pool->import_state = CLUSTER_IMPORT_RUN;
	pthread_mutex_unlock(&cluster_import_poollist_lock);
}

static void
cluster_import_imported(cluster_import_pool_t *pool, int state)
{
	verify(state > CLUSTER_IMPORT_RUN);
	pthread_mutex_lock(&cluster_import_poollist_lock);
	if (pool->import_state == CLUSTER_IMPORT_READY)
		list_remove(&cluster_import_poollist_ready, pool);
	else if(pool->import_state == CLUSTER_IMPORT_RUN)
		list_remove(&cluster_import_poollist_run, pool);
	else
		verify(0);
	pool->import_state = state;
	pthread_mutex_unlock(&cluster_import_poollist_lock);
}

static int
cluster_import_event_handler(const void *buffer, int bufsize)
{
	cluster_import_msg_t *msg = (cluster_import_msg_t *) buffer;
	cluster_import_pool_t *pool;
	uint64_t hostid;

	if (bufsize != sizeof(cluster_import_msg_t)) {
		syslog(LOG_ERR, "invalid message: size=%d", bufsize);
		return (-1);
	}

	switch (msg->msgtype) {
	case CLUSTER_IMPORT_MSGTYPE_NOTIFY:
		pool = cluster_search_import(NULL, NULL, msg->pool_guid, B_FALSE);
		if (pool != NULL) {
			hostid = gethostid();
			if (hostid > 0 && (pool->import_state == CLUSTER_IMPORT_RUN
				|| hostid < msg->hostid)) {
				syslog(LOG_WARNING, "%s pool '%s', stop other host %llu",
					pool->import_state == CLUSTER_IMPORT_RUN ?
					"importing" : "ready import",
					pool->name, (unsigned long long)msg->hostid);
				cluster_import_response(msg->pool_guid, hostid, msg->hostid);
			}
		} else if (cluster_pool_in_local(NULL, msg->pool_guid)) {
			syslog(LOG_ERR, "NOTICE: pool %llu imported, stop other host %llu",
				(unsigned long long)msg->pool_guid, (unsigned long long)msg->hostid);
			hostid = gethostid();
			cluster_import_response(msg->pool_guid, hostid, msg->hostid);
		}
		break;
	case CLUSTER_IMPORT_MSGTYPE_RESPONSE:
		pool = cluster_search_import(NULL, NULL, msg->pool_guid, B_FALSE);
		if (pool == NULL) {
			syslog(LOG_ERR, "NOTICE: invalid response or too late!");
		} else if (pool->import_state != CLUSTER_IMPORT_READY) {
			syslog(LOG_ERR, "NOTICE: response too late or a bug here!");
		} else {
			syslog(LOG_WARNING, "host %llu ready import '%s' too, cancel import",
				(unsigned long long)msg->hostid, pool->name);
			pthread_mutex_lock(&pool->import_lock);
			cluster_import_imported(pool, CLUSTER_IMPORT_CANCEL);
			pthread_cond_broadcast(&pool->import_cv);
			pthread_mutex_unlock(&pool->import_lock);
		}
		break;
	default:
		syslog(LOG_ERR, "invalid message: msgtype=%d", msg->msgtype);
		return (-1);
	}

	return (0);
}

static int
cluster_get_ipmi_addr(libzfs_handle_t *hdl, uint32_t hostid, 
	char *ipmi_ipaddr)
{
	zfs_cmd_t zc = {"\0"};
	int ret;
	
	zc.zc_cookie = ZFS_HBX_GET_IMPI_IP;
	zc.zc_perm_action = hostid;
	zc.zc_value[0] = '\0';
	ret = zfs_ioctl(hdl, ZFS_IOC_HBX, &zc);

	if ((ret != 0) || (zc.zc_value[0] == '\0')) {
		syslog(LOG_ERR, "%s: get host(%d) ipmi ip addr failed", 
			__func__, hostid);
		return (-1);
	} 

	strncpy(ipmi_ipaddr, zc.zc_value, sizeof(zc.zc_value));
	syslog(LOG_NOTICE, "%s: get host(%d)'s ipmi ip = %s",
		__func__, hostid, ipmi_ipaddr);
	return (0);
}

static int
cluster_poweroff_remote_event_handler(const void *buffer, int bufsize)
{
	uint32_t hostid = *((uint32_t *)buffer);
	libzfs_handle_t *hdl;
	int ret, poweroff_success = 0;
	int try_cnt = 0, poweroff_byme = 0;
	char ipmi_ipaddr[MAXPATHLEN * 2] = {0};
	ipmi_power_status_t powerstat;
	int i;

	hdl = libzfs_init();
	if (!hdl) {
		syslog(LOG_ERR, "%s Failed to get libzfs handle", __func__);
		return (-1);
	}	

	cluster_get_ipmi_addr(hdl, hostid, ipmi_ipaddr);

	while ((try_cnt < 3) &&
		((powerstat = ipmi_remote_power_status(ipmi_ipaddr)) != IPMI_POWER_OFF)) {
		if (powerstat == IPMI_POWER_NONE) {
			sleep(1);
			try_cnt++;
			continue;
		}

		if (ipmi_remote_power_off(ipmi_ipaddr) == 0) {
			poweroff_byme = 1;
			syslog(LOG_NOTICE, "%s host(%d) is poweroff by me", __func__, hostid);
		}
		
		for (i = 0; i < 10; i++) {
			sleep(1);
			if (ipmi_remote_power_status(ipmi_ipaddr) == IPMI_POWER_OFF) {
				poweroff_success = 1;
				break;
			}
		}
		
		if (poweroff_success == 0)
			try_cnt++;
		else
			break;
	}

	if (try_cnt == 3) {
		syslog(LOG_WARNING, "%s power off host(%d) failed, please check the net config",
			__func__, hostid);
	} else {
		poweroff_success = 1;
		syslog(LOG_NOTICE, "%s host(%d) is power off success", __func__, hostid);
	}

	/*ret = zfs_notify_avs_poweronoff_result(hdl, hostid, 0, poweroff_byme, 
		poweroff_success);*/
	libzfs_fini(hdl);
	return (ret);
}

static int
cluster_poweron_remote_event_handler(const void *buffer, int bufsize)
{
	uint32_t hostid = *((uint32_t *)buffer);
	libzfs_handle_t *hdl;
	int ret, poweron_success = 0;
	int try_cnt = 0, poweron_byme = 0;
	char ipmi_ipaddr[MAXPATHLEN * 2] = {0};
	int i;

	hdl = libzfs_init();
	if (!hdl) {
		syslog(LOG_ERR, "%s Failed to get libzfs handle", __func__);
		return (-1);
	}	

	cluster_get_ipmi_addr(hdl, hostid, ipmi_ipaddr);

	while ((try_cnt < 3) &&
		(ipmi_remote_power_status(ipmi_ipaddr) != IPMI_POWER_ON)) {

		if (ipmi_remote_power_on(ipmi_ipaddr) == 0) {
			poweron_byme = 1;
			syslog(LOG_NOTICE, "%s host(%d) is poweron by me", __func__, hostid);
		}
		
		for (i = 0; i < 10; i++) {
			sleep(1);
			if (ipmi_remote_power_status(ipmi_ipaddr) == IPMI_POWER_ON) {
				poweron_success = 1;
				break;
			}
		}
		
		if (poweron_success == 0)
			try_cnt++;
		else
			break;
	}

	if (try_cnt == 3) {
		syslog(LOG_WARNING, "%s power on host(%d) failed, please check the net config",
			__func__, hostid);
	} else {
		poweron_success = 1;
		syslog(LOG_NOTICE, "%s host(%d) is power on success", __func__, hostid);
	}

	/*ret = zfs_notify_avs_poweronoff_result(hdl, hostid, 1, poweron_byme,
		poweron_success);*/
	libzfs_fini(hdl);
	return (ret);
}

static int
cluster_read_stamp(zpool_stamp_t *stamp, nvlist_t *pool_root, char *path)
{
        int error;
        int retry = 0;

        while (retry < 3) {
                if (pool_root != NULL)
                        error = zpool_read_stamp(pool_root, stamp);
                else
                        error = zpool_read_stmp_by_path(path, stamp);
                if (error == 0)
                        break;
                else
                        syslog(LOG_ERR, "%s: error=%d", __func__, error);

                retry++;
                sleep(1);
        }

        return (error);
}

static int
cluster_write_stamp(zpool_stamp_t *stamp, nvlist_t *pool_root, char *path)
{
        int error;
        int retry = 0;

        while (retry < 3) {
                if (pool_root != NULL)
                        error = zpool_write_stamp(pool_root, stamp, SPA_NUM_OF_QUANTUM);
                else
                        error = zpool_write_dev_stamp_mark(path, stamp) == 0 ? 1 : 0;
                if (error > 0)
                        break;
                else
                        syslog(LOG_ERR, "%s: error=%d", __func__, error);

                retry++;
                sleep(1);
        }

        return (error);
}

static nvlist_t *
zpool_get_all_pools(libzfs_handle_t *hdl, int cluster_switch)
{
	importargs_t args;

	memset(&args, 0, sizeof(args));
	args.no_blkid = 1;
	args.cluster_ignore = 1;
	return (zpool_search_import(hdl, &args));
}

/*
 * return 1 the pool can be import, return 0 the pool can't be import,
 * otherwise indicate error or the pool not exists.
 */
static int
cluster_check_pool_replicas(uint64_t pool_guid)
{
	nvlist_t	*pools, *config, *nvroot;
	nvpair_t	*elem = NULL;
	libzfs_handle_t	*hdl;
	uint64_t	guid;
	vdev_stat_t	*vs;
	uint_t	vsc;
	int	ret = -1;
	int 	err;

	hdl = libzfs_init();
	if (hdl == NULL) {
		syslog(LOG_ERR, "libzfs_init() error");
		return (-1);
	}

	pools = zpool_get_all_pools(hdl, 0);
	while ((elem = nvlist_next_nvpair(pools, elem)) != NULL) {
		verify(nvpair_value_nvlist(elem, &config) == 0);
		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
			&guid) == 0);
		if (guid == pool_guid) {
			verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
			    &nvroot) == 0);
			err = nvlist_lookup_uint64_array(nvroot, ZPOOL_CONFIG_VDEV_STATS,
			    (uint64_t **)&vs, &vsc);
			if (err != 0) {
				syslog(LOG_ERR, "nvlist_lookup(ZPOOL_CONFIG_VDEV_STATS) = %d", err);
				continue;
			}
			syslog(LOG_WARNING, "pool %llu state=%llu",
				(unsigned long long)pool_guid, (unsigned long long)vs->vs_state);
			if (vs->vs_state > VDEV_STATE_CANT_OPEN)
				ret = 1;
			else
				ret = 0;
			break;
		}
	}

	nvlist_free(pools);
	libzfs_fini(hdl);
	return (ret);
}

static char *
choose_critical_disk(nvlist_t *pool_root)
{
	uint_t i, nchild, nchild2;
	nvlist_t **children, **children2;
	char *path;
	int fd;

	verify(nvlist_lookup_nvlist_array(pool_root, ZPOOL_CONFIG_CHILDREN,
		&children, &nchild) == 0);

	for (i = 0; i < nchild; i++) {
		if (nvlist_lookup_nvlist_array(children[i], ZPOOL_CONFIG_CHILDREN,
			&children2, &nchild2) == 0) {
			return choose_critical_disk(children[i]);
		}

		if (nvlist_lookup_string(children[i], ZPOOL_CONFIG_PATH, &path) == 0) {
			if ((fd = open(path, O_RDWR)) > 0) {
				close(fd);
				return path;
			}
		}
	}

	return (NULL);
}

#if	defined(__sw_64)

static const char *
path2filename(const char *path)
{
	char *p;
	p = strrchr(path, '/');
	return (p ? ++p : path);
}

static char *
find_sd(const char *scsi_disk, char *sd_path, size_t sd_path_len)
{
	struct stat sb;
	ssize_t n;

	if (lstat(scsi_disk, &sb) != 0)
		return (NULL);
	if ((sb.st_mode & S_IFMT) != S_IFLNK)
		return (NULL);
	if ((n = readlink(scsi_disk, sd_path, sd_path_len-1)) < 0)
		return (NULL);
	sd_path[n] = '\0';
	return (sd_path);
}

static char *
find_dev_tree_path(const char *sd_path, char *path, size_t path_len)
{
	char buf[128];
	const char *filename;
	FILE *fp;
	int found = 0;

	filename = path2filename(sd_path);
	snprintf(buf, 128, "/usr/bin/find /sys/devices -name %s", filename);
	if ((fp = popen(buf, "r")) == NULL)
		return (NULL);
	while (fgets(buf, 128, fp) != NULL) {
		if ((strstr(buf, "/sys/devices") != NULL) && (strstr(buf, filename) != NULL)) {
			strncpy(path, buf, path_len);
			found = 1;
			break;
		}
	}
	pclose(fp);
	return (found ? path : NULL);
}

static int
dev_tree_path_is_vdev(const char *dev_tree_path)
{
	char vmpt2sas_path_prefix[] = "/sys/devices/platform/";

	if (strncmp(dev_tree_path, vmpt2sas_path_prefix, strlen(vmpt2sas_path_prefix)) == 0)
		return (1);
	return (0);
}

static int
disk_is_vdev(const char *scsi_disk)
{
	char *sd_path, *dev_tree_path;
	size_t pathlen = 128;
	int ret = 0;

	sd_path = malloc(pathlen);
	if (sd_path == NULL)
		return (0);

	if (find_sd(scsi_disk, sd_path, pathlen) != NULL) {
		dev_tree_path = malloc(pathlen);
		if (dev_tree_path) {
			if (find_dev_tree_path(sd_path, dev_tree_path, pathlen) != NULL)
				ret = dev_tree_path_is_vdev(dev_tree_path);
			free(dev_tree_path);
		}
	}
	free(sd_path);

	return (ret);
}

static void
cluster_check_pool_disks_common(nvlist_t *root, disk_table_t *table,
	int *total, int *active, int *local)
{
	nvlist_t **child;
	uint_t children, i;

	verify(nvlist_lookup_nvlist_array(root, ZPOOL_CONFIG_CHILDREN,
		&child, &children) == 0);
	for (i = 0; i < children; i ++) {
		nvlist_t **tmp_child;
		uint_t tmp_children = 0;

		if (nvlist_lookup_nvlist_array(child[i], ZPOOL_CONFIG_CHILDREN,
			&tmp_child, &tmp_children) == 0) {
			cluster_check_pool_disks_common(child[i], table, total, active, local);
		} else {
			disk_info_t *cursor;
			const char *filename, *name;
			char *path;

			if (nvlist_lookup_string(child[i], ZPOOL_CONFIG_PATH, &path) != 0) {
				syslog(LOG_ERR, "pool get config path failed");
				continue;
			}
			(*total)++;

			filename = path2filename(path);
			for (cursor = table->next; cursor != NULL; cursor = cursor->next) {
				name = path2filename(cursor->dk_scsid);
				if (strncmp(name, filename, strlen(name)) == 0)
					break;
			}
			if (cursor != 0) {
				(*active)++;
				if (disk_is_vdev(cursor->dk_scsid) == 0)
					(*local)++;
			}
		}
	}
}

static boolean_t
cluster_check_pool_disks(nvlist_t *pool_root)
{
	disk_table_t table = {0, NULL};
	int total, active, local;

	if (disk_get_info(&table) != 0) {
		syslog(LOG_WARNING, "disk_get_info failed");
		return (B_FALSE);
	}

	total = active = local = 0;
	cluster_check_pool_disks_common(pool_root, &table, &total, &active, &local);

	if (local == 0 || active < total / 2) {
		syslog(LOG_WARNING, "disks not satisfied: total=%d, active=%d, local=%d",
			total, active, local);
		return (B_FALSE);
	}

	return (B_TRUE);
}

#endif

static void *
cluster_compete_pool(void *arg)
{
	compete_pool_param_t *param = (compete_pool_param_t *) arg;
	nvlist_t *config = param->arg;
	nvlist_t *nvroot, *pool_root;
	char *poolname;
	uint64_t guid;
	/*nvlist_t **child;*/
	uint_t /*children, disk_total = 0,*/ disk_active = 0;
	spa_quantum_index_t used_index1[SPA_NUM_OF_QUANTUM];
	spa_quantum_index_t used_index2[SPA_NUM_OF_QUANTUM];
	uint64_t real_nquantum1 = 0;
	uint64_t real_nquantum2 = 0;
	uint64_t usec;
	zpool_stamp_t *stamp = NULL;
	uint64_t hostid/*, poolhostid = 0, ownerhostid = 0*/;
	int counter, conflict_cnt;
	todo_import_pool_node_t *todo_import_pool = NULL;
	void *ret = NULL;
	/*uint_t host_total[256 + 1], host_active[256 + 1];*/
	char buf[512], *disks[256], *path;
	int i, err, *owners= NULL/*, chosen*/;
	cluster_import_pool_t *cip = NULL;
	timespec_t ts;

	if (!config) {
		syslog(LOG_WARNING, "NULL config");
		goto exit_thr;
	}
	verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
			&nvroot) == 0);
	verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, 
		&poolname) == 0);
	verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, 
		&guid) == 0);

	hostid = get_system_hostid();
#if 0
	if (hostid > 255) {
		syslog(LOG_ERR, "Invalid host id: %"PRId64"", hostid);
		return (NULL);
	}

	host_total[0] = host_active[0] = 0;
	cluster_check_pool_disk(nvroot, &disk_total, &disk_active,
		host_total, host_active, disks);
	syslog(LOG_WARNING, "%s: pool %s disk total=%u, active=%u", __func__,
		poolname, disk_total, disk_active);

	if (param->import_state == NULL) {/* Initial boot import */
		/* The cluster has remote hosts, beyond double control. */
		while (disk_active <= disk_total/2) {
			/* Wait until most of the pool disk became active */
			syslog(LOG_WARNING, "cluster check pool '%s': wait for disk up", poolname);
			sleep(5);
			for (i = 0; i < disk_active; i++)
				free(disks[i]);
			disk_total = disk_active = 0;
			host_total[0] = host_active[0] = 0;
			cluster_check_pool_disk(nvroot, &disk_total, &disk_active,
				host_total, host_active, disks);
			syslog(LOG_WARNING, "%s: pool %s disk total=%u, active=%u", __func__,
				poolname, disk_total, disk_active);
		}

		owners = malloc(disk_active * sizeof(int));
		if (owners == NULL) {
			syslog(LOG_ERR, "out of memory");
			goto exit_thr;
		}

		if (get_disk_owners(disks, disk_active, owners) < 0) {
			syslog(LOG_ERR, "get disk owners failed");
			goto exit_thr;
		}
		for (i = 0; i < disk_active; i++) {
			if (owners[i] == 0)
				break;
		}
		if (i == disk_active) {
			syslog(LOG_WARNING, "haven't local disk in pool '%s', exit", poolname);
			goto exit_thr;
		}

		if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_HOSTID, &poolhostid) == 0) {
			syslog(LOG_WARNING, "pool '%s' last accessed by hostid %llu",
				poolname, poolhostid);
			if (hostid != poolhostid) {
				if (cluster_get_host_state(poolhostid) == 1) {
					/* 
					 * if remote already imported a same name pool,
					 * we still can compete the pool
					 */
					if (!cluster_pool_in_remote(poolhostid, poolname, 0)) {
						syslog(LOG_WARNING, "other host %d is chosen to import pool '%s'",
							poolhostid, poolname);
						goto exit_thr;
					}
				}
			} else
				goto check_remote;
		}

		chosen = get_smallest_owner(owners, disk_active);
		if (chosen > 0 && chosen < (hostid + 1) / 2) {
			syslog(LOG_WARNING, "other node %d is chosen to import pool '%s'",
				chosen, poolname);
			goto exit_thr;
		}
	}
#endif

#if	defined(__sw_64)
	if (!cluster_check_pool_disks(nvroot)) {
		syslog(LOG_WARNING, "disks of pool '%s' not satisfied", poolname);
		goto exit_thr;
	}
#endif

check_remote:
	if (cluster_pool_in_remote(0, NULL, guid)) {
		syslog(LOG_WARNING, "pool '%s' in remote, exit", poolname);
		goto exit_thr;
	}

	if (cluster_pool_in_local(poolname, 0)) {
		syslog(LOG_WARNING, "a same name pool '%s' already imported", poolname);
		goto exit_thr;
	}

ready_import:
	if ((cip = cluster_ready_import(poolname, guid)) == NULL) {
		syslog(LOG_ERR, "cluster_ready_import: out of memory");
		goto exit_thr;
	}
	if (cip->guid != guid) {
		int ref, import_state;
		syslog(LOG_WARNING, "a same name pool '%s' is ready or importing",
			poolname);

		pthread_mutex_lock(&cip->import_lock);
		cip->ref++;
		while (cip->import_state < CLUSTER_IMPORT_IMPORTED){
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += 5;
			pthread_cond_timedwait(&cip->import_cv, &cip->import_lock, &ts);
		}
		cip->ref--;

		ref = cip->ref;
		import_state = cip->import_state;
		pthread_mutex_unlock(&cip->import_lock);
		if (ref == 0)
			cluster_import_pool_destroy(cip);
		cip = NULL;
		/*
		 * If the same name pool import failed, we need import
		 * current pool, otherwise exit.
		 */
		if (import_state != CLUSTER_IMPORT_IMPORTED)
			goto ready_import;
		goto exit_thr;
	}

	if (cluster_import_broadcast(guid, hostid) < 0) {
		syslog(LOG_ERR, "cluster_import_broadcast failed");
		goto exit_thr;
	}

	pthread_mutex_lock(&cip->import_lock);
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 5;
	while (cip->import_state == CLUSTER_IMPORT_READY) {
		err = pthread_cond_timedwait(&cip->import_cv, &cip->import_lock, &ts);
		if (err == ETIMEDOUT)
			break;
	}

	if (cip->import_state != CLUSTER_IMPORT_READY) {
		cip->ref--;
		if (cip->ref == 0) {
			pthread_mutex_unlock(&cip->import_lock);
			cluster_import_pool_destroy(cip);
			cip = NULL;
		} else {
			/* other same name pool import thread wait on this */
			verify(cip->import_state == CLUSTER_IMPORT_CANCEL);
			pthread_cond_broadcast(&cip->import_cv);
			pthread_mutex_unlock(&cip->import_lock);
		}
		syslog(LOG_WARNING, "other host ready import '%s', exit", poolname);
		goto exit_thr;
	}

	cluster_run_import(cip);
	pthread_mutex_unlock(&cip->import_lock);

	err = cluster_check_pool_replicas(guid);
	if (err == 0) {
		syslog(LOG_WARNING, "pool '%s' not satisfy replicas", poolname);
		/*
		 * If replicas not satisfied, we wait new node join cluster
		 * or timeout; then we will re-compete.
		 */
		pthread_mutex_lock(&cluster_import_replicas_lock);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 60;
		pthread_cond_timedwait(&cluster_import_replicas_cv,
			&cluster_import_replicas_lock, &ts);
		pthread_mutex_unlock(&cluster_import_replicas_lock);

		pthread_mutex_lock(&cip->import_lock);
		pthread_mutex_lock(&cluster_import_poollist_lock);
		list_remove(&cluster_import_poollist_run, cip);
		list_insert_head(&cluster_import_poollist_ready, cip);
		cip->import_state = CLUSTER_IMPORT_READY;
		pthread_mutex_unlock(&cluster_import_poollist_lock);
		pthread_mutex_unlock(&cip->import_lock);

		goto check_remote;
	} else if (err < 0) {
		syslog(LOG_WARNING, "pool '%s' not exists or error", poolname);
		goto exit_thr;
	}

	bzero(used_index1, sizeof(spa_quantum_index_t) * SPA_NUM_OF_QUANTUM) ;
	bzero(used_index2, sizeof(spa_quantum_index_t) * SPA_NUM_OF_QUANTUM) ;
	
	real_nquantum1 = zpool_read_used(nvroot, used_index1, SPA_NUM_OF_QUANTUM);
	if (real_nquantum1 == 0) {
		syslog(LOG_WARNING, "Can't find quantum disk in pool \"%s\"", poolname);
		path = choose_critical_disk(nvroot);
		if (path == NULL)
			goto exit_thr;

		snprintf(buf, 512, "%s", path);
		path = buf;
		stamp = (zpool_stamp_t *) malloc(sizeof(zpool_stamp_t));
		if (stamp == NULL) {
			syslog(LOG_ERR, "alloc zpool_stamp_t failed");
			goto exit_thr;
		}

		bzero(stamp, sizeof (zpool_stamp_t));
		stamp->para.pool_magic = ZPOOL_MAGIC;
		stamp->para.pool_real_owener = hostid;
		stamp->para.pool_current_owener = hostid;
		stamp->para.pool_progress[0] = ZPOOL_NO_PROGRESS;
		stamp->para.pool_progress[1] = ZPOOL_NO_PROGRESS;
		stamp->para.company_name = COMPANY_NAME;

		if (cluster_write_stamp(stamp, NULL, path) <= 0) {
			syslog(LOG_ERR, "write stamp failed");
			goto exit_thr;
		}

		pool_root = NULL;
	} else {
		pool_root = nvroot;
		path = NULL;

		/* wait a moment, then check index of quantum disk */
		usec = ZFS_QUANTUM_INTERVAL_TICK * 20 * 1000;
		while (usleep(usec) != 0) {
			if (errno != EINTR)
				goto exit_thr;
		}

		if (B_TRUE == zpool_used_index_changed(used_index1, real_nquantum1,
			used_index2, &real_nquantum2)) {
			syslog(LOG_WARNING, "pool \"%s\" in use, exit", poolname);
			goto exit_thr;
		}
	}

	if (stamp == NULL) {
		stamp = (zpool_stamp_t *) malloc(sizeof(zpool_stamp_t));
		if (!stamp) {
			syslog(LOG_ERR, "alloc zpool_stamp_t failed");
			goto exit_thr;
		}
		if (cluster_read_stamp(stamp, pool_root, path) != 0) {
			syslog(LOG_ERR, "read stamp failed");
			goto exit_thr;
		}
		stamp->para.pool_current_owener = hostid;
		stamp->para.pool_progress[0] = ZPOOL_NO_PROGRESS;
		stamp->para.pool_progress[1] = ZPOOL_NO_PROGRESS;
		if (cluster_write_stamp(stamp, pool_root, path) <= 0) {
			syslog(LOG_ERR, "write stamp failed");
			goto exit_thr;
		}
	}

	counter = CONFLICT_DURATION;
	conflict_cnt = 0;
	while (counter--) {
		usleep(UPDATE_STAMP_INTERVAL);

		if (cluster_read_stamp(stamp, pool_root, path) != 0) {
			syslog(LOG_ERR, "read stamp failed");
			goto exit_thr;
		}
		if (stamp->para.pool_current_owener != hostid) {
			conflict_cnt++;
			if (conflict_cnt >= 3) {
				syslog(LOG_ERR, "maybe there is a bug!!");
				goto exit_thr;
			}
			
			if (stamp->para.pool_progress[0] == ZPOOL_ON_PROGRESS) {
				syslog(LOG_WARNING, "remote already start import the pool");
				goto exit_thr;
			}
			if (stamp->para.pool_real_owener == hostid) {
				/* you won */
				stamp->para.pool_current_owener = hostid;
				stamp->para.pool_progress[0] = ZPOOL_ON_PROGRESS;
				stamp->para.pool_progress[1] = ZPOOL_ON_PROGRESS;
				if (cluster_write_stamp(stamp, pool_root, path) <= 0) {
					syslog(LOG_ERR, "write stamp failed");
					goto exit_thr;
				}
				continue;
			}
			syslog(LOG_WARNING, "remote won, exit");
			goto exit_thr;
		}
	}

	if (stamp->para.pool_progress[0] == ZPOOL_NO_PROGRESS) {
		stamp->para.pool_current_owener = hostid;
		stamp->para.pool_progress[0] = ZPOOL_ON_PROGRESS;
		stamp->para.pool_progress[1] = ZPOOL_ON_PROGRESS;
		if (cluster_write_stamp(stamp, pool_root, path) <= 0) {
			syslog(LOG_ERR, "write stamp failed");
			goto exit_thr;
		}
	}

	if (param->import_state == NULL) {
		todo_import_pool = add_todo_import_pool(poolname, guid);
		if (!todo_import_pool)
			goto exit_thr;
	} else {
		failover_pool_import_state_t *import_state = param->import_state;

		pthread_cond_signal(&import_state->cond);
		syslog(LOG_WARNING, "compete won.");
	}

	for (counter = 0; counter < CONFLICT_DURATION;) {
		usleep(UPDATE_STAMP_INTERVAL);

		if (cluster_write_stamp(stamp, pool_root, path) <= 0) {
			syslog(LOG_ERR, "write stamp failed");
			goto exit_thr;
		}

		if (param->import_state == NULL) {
			if (todo_import_pool->imported)
				counter++;
		} else {
			if (param->import_state->imported)
				counter++;
		}
	}

	stamp->para.pool_current_owener = hostid;
	stamp->para.pool_progress[0] = ZPOOL_NO_PROGRESS;
	stamp->para.pool_progress[1] = ZPOOL_NO_PROGRESS;
	if (cluster_write_stamp(stamp, pool_root, path) <= 0) {
		syslog(LOG_ERR, "write stamp failed");
		goto exit_thr;
	}

	ret = stamp->para.pool_real_owener == hostid ? (void *)1 : (void *)2;

exit_thr:
	if (param->import_state != NULL) {
		if (!param->import_state->imported) {
			pthread_mutex_lock(&param->import_state->mtx);
			param->import_state->imported = B_TRUE;
			pthread_cond_signal(&param->import_state->cond);
			pthread_mutex_unlock(&param->import_state->mtx);
		}
	}
	if (stamp)
		free(stamp);
	if (owners != NULL)
		free(owners);
	for (i = 0; i < disk_active; i++)
		free(disks[i]);
	if (cip != NULL) {
		pthread_mutex_lock(&cip->import_lock);
		cluster_import_imported(cip, 
			ret == NULL ? CLUSTER_IMPORT_FAILED : CLUSTER_IMPORT_IMPORTED);
		cip->ref--;
		if (cip->ref == 0) {
			pthread_mutex_unlock(&cip->import_lock);
			cluster_import_pool_destroy(cip);
		} else {
			/* other same name pool import thread wait on this */
			verify(cip->import_state == CLUSTER_IMPORT_IMPORTED);
			pthread_cond_broadcast(&cip->import_cv);
			pthread_mutex_unlock(&cip->import_lock);
		}
	}
	return (ret);
}

/*
 * @is_boot: if @is_boot==1, do boot import; @is_boot==0, do failover import
 * @failover_remote: if any pool of remote(the real owner is remote id) imported, 
 * then @failover_remote=1, otherwise @failover_remote=0
 */
static int
cluster_import_pools(int is_boot, int *failover_remote)
{
	libzfs_handle_t *hdl;
	nvlist_t *pools, *config;
	nvpair_t *elem = NULL;
	todo_import_pool_node_t *todo_node, *tmp_todo_node;
	pthread_t import_thr_id;
	list_t thr_list;
	thr_list_node_t *thr_node, *tmp_thr_node;
	int err = 0;
	void *thr_status = NULL;
	char *poolname;
	uint64_t pool_guid, pool_state;

	pthread_mutex_lock(&import_thr_conf.import_pools_handler_mtx);

	/*cluster_task_pool_scan();*/

	hdl = libzfs_init();
	if (!hdl) {
		syslog(LOG_ERR, "Failed to get libzfs handle");
		pthread_mutex_unlock(&import_thr_conf.import_pools_handler_mtx);
		return (-1);
	}

	*failover_remote = 0;
	if (is_boot) {
		pools = zpool_get_all_pools(hdl, 0);
	} else /* failover */
		pools = zpool_get_all_pools(hdl, 1);
	if (!pools) {
		syslog(LOG_WARNING, "Maybe there is no pools");
		libzfs_fini(hdl);
		pthread_mutex_unlock(&import_thr_conf.import_pools_handler_mtx);
		return (-2);
	}

	import_thr_conf.exit_flag = 0;
	pthread_mutex_init(&import_thr_conf.mtx, NULL);
	pthread_cond_init(&import_thr_conf.cond, NULL);
	pthread_mutex_init(&import_thr_conf.list_mtx, NULL);
	list_create(&import_thr_conf.todo_import_pools, 
		sizeof(todo_import_pool_node_t),
		offsetof(todo_import_pool_node_t, list));
	list_create(&import_thr_conf.imported_pools, 
		sizeof(todo_import_pool_node_t),
		offsetof(todo_import_pool_node_t, list));
	list_create(&thr_list, sizeof(thr_list_node_t),
		offsetof(thr_list_node_t, list));

	err = pthread_create(&import_thr_id, NULL, 
		&cluster_import_pools_thr, NULL);
	if (err != 0) {
		syslog(LOG_ERR, "pthread_create error: %d, %s", err, strerror(err));
		goto exit_func;
	}

	while ((elem = nvlist_next_nvpair(pools, elem)) != NULL) {
		verify(nvpair_value_nvlist(elem, &config) == 0);
		verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, 
			&poolname) == 0);
		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, 
			&pool_guid) == 0);
		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
		    &pool_state) == 0);
		if (pool_state == POOL_STATE_DESTROYED) {
			c_log(LOG_WARNING, "pool '%s' state is destroyed\n", poolname);
			continue;
		}

		/* filter the pool not in cluster */
		if (!pool_in_cluster(config))
			continue;
		thr_node = (thr_list_node_t *) malloc(sizeof(thr_list_node_t));
		if (!thr_node) {
			syslog(LOG_ERR, "alloc thr_list_node_t failed");
			err = ENOMEM;
			goto exit_func;
		}
		thr_node->param.arg = config;
		thr_node->param.import_state = NULL;
		
		err = pthread_create(&thr_node->thrid, NULL,
			&cluster_compete_pool, &thr_node->param);
		if (err != 0) {
			syslog(LOG_ERR, "pthread_create error: %d, %s", err, strerror(err));
			free(thr_node);
			goto exit_func;
		}

		list_insert_tail(&thr_list, thr_node);
	}

exit_func:
	if (!list_is_empty(&thr_list)) {
		for (thr_node = list_head(&thr_list); thr_node;) {
			pthread_join(thr_node->thrid, &thr_status);
			if (thr_status == (void *)2)
				*failover_remote = 1;

			tmp_thr_node = thr_node;
			thr_node = list_next(&thr_list, thr_node);
			list_remove(&thr_list, tmp_thr_node);
			free(tmp_thr_node);
		}
	}

	import_thr_conf.exit_flag = 1;
	pthread_mutex_lock(&import_thr_conf.mtx);
	pthread_cond_signal(&import_thr_conf.cond);
	pthread_mutex_unlock(&import_thr_conf.mtx);
	pthread_join(import_thr_id, NULL);

	nvlist_free(pools);
	libzfs_fini(hdl);

	if (!list_is_empty(&import_thr_conf.todo_import_pools)) {
		syslog(LOG_WARNING, "WARN: todo_import_pools not empty!!");
		for (todo_node = list_head(&import_thr_conf.todo_import_pools);
			todo_node;) {
			tmp_todo_node= todo_node;
			todo_node = list_next(&import_thr_conf.todo_import_pools, todo_node);
			list_remove(&import_thr_conf.todo_import_pools, tmp_todo_node);
			free(tmp_todo_node);
		}
	}
	if (!list_is_empty(&import_thr_conf.imported_pools)) {
		for (todo_node = list_head(&import_thr_conf.imported_pools);
			todo_node;) {
			tmp_todo_node= todo_node;
			todo_node = list_next(&import_thr_conf.imported_pools, todo_node);
			list_remove(&import_thr_conf.imported_pools, tmp_todo_node);
			free(tmp_todo_node);
		}
	}

	pthread_mutex_destroy(&import_thr_conf.mtx);
	pthread_cond_destroy(&import_thr_conf.cond);
	pthread_mutex_destroy(&import_thr_conf.list_mtx);

	pthread_mutex_unlock(&import_thr_conf.import_pools_handler_mtx);
	return (err);
}

static void
cluster_check_sessions(void)
{
	libzfs_handle_t *libzfs;
	nvlist_t *state, *targets, *sessions, *nvl_target, *nvl_session;
	nvpair_t *target, *session;
	uint32_t cs_state, link_state;
	char *sessname;
	int check_min_sessions = 1;
	int check_try_times = 60;
	int session_count, trys = 0;

	if ((libzfs = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "libzfs_init error");
		return;
	}

	while (trys < check_try_times) {
		state = zfs_clustersan_get_nvlist(libzfs, ZFS_CLUSTERSAN_STATE, NULL, 0);
		if (state == NULL) {
			syslog(LOG_ERR, "get clustersan state failed");
			break;
		}

		verify(nvlist_lookup_uint32(state, CS_NVL_STATE, &cs_state) == 0);
		if (cs_state == 0) {
			syslog(LOG_WARNING, "clustersan disabled");
			break;
		}

		session_count = 0;
		targets = zfs_clustersan_get_nvlist(libzfs,
			ZFS_CLUSTERSAN_LIST_TARGET, NULL, 0);
		if (targets != NULL) {
			target = NULL;
			while ((target = nvlist_next_nvpair(targets, target)) != NULL) {
				verify(nvpair_value_nvlist(target, &nvl_target) == 0);
				if (nvlist_lookup_nvlist(nvl_target, CS_NVL_SESS_LIST,
					&sessions) == 0) {
					while ((session = 
						nvlist_next_nvpair(sessions, session)) != NULL) {
						sessname = nvpair_name(session);
						verify(nvpair_value_nvlist(session, &nvl_session) == 0);
						verify(nvlist_lookup_uint32(nvl_session,
							CS_NVL_SESS_LINK_STATE, &link_state) == 0);
						syslog(LOG_WARNING, "%s %s", sessname,
							link_state == 0 ? "down" : "up");
						if (link_state != 0)
							session_count++;
					}
				}
			}
		}

		if (session_count >= check_min_sessions) {
			syslog(LOG_WARNING, "%d sessions connected", session_count);
			break;
		}
		trys++;
		sleep(1);
	}

	libzfs_fini(libzfs);
}

void *
cluster_task_setup(void *arg)
{
	int failover_remote;
	int ret;

	pthread_detach(pthread_self());

	/* wait 2 sessions up at least */
	cluster_check_sessions();

	ret = cluster_import_pools(1, &failover_remote);
	if (ret != 0 && ret != -2) {
		syslog(LOG_ERR, "cluster_import_pools error: %d", ret);
 	} else
		init_zpool_failover_conf();

	return (NULL);
}

void *
cluster_thread_process(void *arg)
{
	/*int ret, err;*/
	/*cluster_state_t cls_state = CLUSTER_INIT;*/

	cls_thread.running = 1;
	
	/* thread initialize */
	(void) pthread_mutex_init(&cls_thread.cls_mutex, NULL);
	(void) pthread_mutex_init(&cls_thread.cls_stat_mutex, NULL);
	(void) pthread_mutex_init(&cls_thread.cls_event_mutex, NULL);
	(void) pthread_cond_init(&cls_thread.cls_cond, NULL);
	cls_thread.cls_event_head.next = NULL;

#if	0
	/* check self */
	do {
		ret = check_self(host_id);
		if (!ret) {
			/* system in unhealthy */
			sleep(2);
		}
	} while (!ret);
	
	do {
		ret = cefs_crypto_mkfile_check();
		if (ret) {
			sleep(2);
		}
		
	} while (ret);
	
	/*
	 *  initialize cluster state
	 */
	cluster_task_pool_scan();
#endif
	/*
	 * Finally, to process the change of hbx state, should never exit
	 */
	cluster_task_wait_event();

	/* exit thread */
	cluster_clear_all_hbx_event();
	pthread_cond_destroy(&cls_thread.cls_cond);
	pthread_mutex_destroy(&cls_thread.cls_event_mutex);
	pthread_mutex_destroy(&cls_thread.cls_stat_mutex);
	pthread_mutex_destroy(&cls_thread.cls_mutex);
	cls_thread.running = 0;
	return NULL;
}


static void
cluster_do_hbx_event(hbx_door_para_t *para, char *data, int size)
{
	cls_hbx_state.link_state = para->link_state;
	if (host_id %2) {
		/* host is major, minor node state is from partner, need to update */
		cls_hbx_state.minor = para->minor;
	} else {
		/* host is minor, major node state is from partner, need to update */
		cls_hbx_state.major = para->major;
	}

	if (para->event == EVT_REMOTE_HOST_NORMAL)
		return;

	cluster_set_hbx_event(para, data, size);
	/*
	 * secondly,  signal cluster thread to process
	 */
	(void)pthread_mutex_lock(&cls_thread.cls_mutex);
	(void)pthread_cond_signal(&cls_thread.cls_cond);
	(void)pthread_mutex_unlock(&cls_thread.cls_mutex);
}

static int
cluster_deref(hbx_door_para_t *para)
{
	/*int ret;*/
	char *data = NULL;
	uint64_t data_len = 0;
#if	0
	dev_event_t *devs;
	uint64_t dev_num;
#endif

	if (para->b_data) {
		data = (char *)para + sizeof(hbx_door_para_t);
		data_len = para->data_len;
	}

#if	0
	switch (para->event) {
	case EVT_LOCAL_REBOOT_BY_FC_DISK:
	case EVT_LOCAL_REBOOT_BY_NIC:
	case EVT_LOCAL_REBOOT_BY_FC_TARGET:
	case EVT_LOCAL_REBOOT_BY_FC_INITIATOR:
		if (cluster_state != CLUSTER_QUIET) {
			devs = (dev_event_t *)data;
			dev_num = data_len / sizeof(dev_event_t);
			reboot_self(host_id, para->event, devs, dev_num);
		}
		break;
	case EVT_LOCAL_REBOOT_BY_MPTSAS:
		syslog(LOG_ERR, "mptsas failed   ZFS_HBX_MPTSAS_DOWN");
	/*	cmn_err(CE_NOTE, "mptsas failed   ZFS_HBX_MPTSAS_DOWN ");*/
		hbx_do_cluster_cmd(NULL, 0, ZFS_HBX_MPTSAS_DOWN);
		reboot_self(host_id, para->event, devs, dev_num);
		break;
	case EVT_LOCAL_REBOOT_BY_FC_LOOP_FAILED:
		if(para->link_state == LINK_DOWN){
			syslog(LOG_ERR, "the event EVT_LOCAL_REBOOT_BY_FC_LOOP_FAILED happend,but partner down, ignore it");
			syslog(LOG_ERR, "major : %d     link_state:  %d",para->major,para->link_state);
		 	break;
		}
		syslog(LOG_ERR, "fc Loop failed ZFS_HBX_FC_DOWN  ");
	/*	cmn_err(CE_NOTE, "fc Loop failed ZFS_HBX_FC_DOWN ");*/
		hbx_do_cluster_cmd(NULL, 0, ZFS_HBX_FC_DOWN);
		syslog(LOG_ERR, "fc Loop failed : before  reboot_self ");
		reboot_self(host_id, para->event, devs, dev_num);
		syslog(LOG_ERR, "fc Loop failed : after reboot_self ");
		break;
	case EVT_LOCAL_REBOOT_BY_MEMORY:
	case EVT_LOCAL_REBOOT_BY_HB:
	case EVT_LOCAL_REBOOT_BY_EXCEPTION:
		reboot_self(host_id, para->event, NULL, 0);
		break;
	case EVT_LOCAL_REBOOT_BY_RAID_OS_DISK:
		syslog(LOG_ERR, "os raid broken, do something!");
		system(CLUSTER_OS_RAID);
		break;
	default:
		cluster_do_hbx_event(para, data, data_len);
		break;	
	}
#else
	cluster_do_hbx_event(para, data, data_len);
#endif
	return (0);
}

static void
clusterd_cn_rcv(void *data, int len)
{
	hbx_door_para_t *para;

	if (data == NULL || len < sizeof(hbx_door_para_t)) {
		syslog(LOG_ERR, "clusterd_cn_rcv(): invalid args, data=%p, len=%d",
			data, len);
		return;
	}

	para = (hbx_door_para_t *)data;
	cluster_deref(para);
}

#if	0
/*
 *  reparsed_doorfunc
 *
 *  argp:  "service_type:service_data" string
 *  dp & n_desc: not used.
 */
static void
clusterd_doorfunc(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc)
{
	int err;
	hbx_door_para_t *para;
	clusterd_door_res_t door_res = {0, 0, '\0'};

	if ((argp == NULL) || (arg_size == 0)) {
		syslog(LOG_ERR, "cluster door func error");
		door_return(NULL, 0, NULL, 0);
		/* NOTREACHED */
	}
	para = (hbx_door_para_t *)argp;
	err = cluster_deref(para);

	(void) door_return(NULL, 0, NULL, 0);
	/* NOTREACHED */	
}

static int
start_clusterd_svcs()
{
	int doorfd;
	int dfd;

	if ((doorfd = door_create(clusterd_doorfunc, NULL,
	    DOOR_REFUSE_DESC|DOOR_NO_CANCEL)) == -1) {
		syslog(LOG_ERR, "Unable to create door");
		return (1);
	}

	/*
	 * Create a file system path for the door
	 */

	if ((dfd = open(CLUSTERD_DOOR, O_RDWR|O_CREAT|O_TRUNC,
	    S_IRWXU|S_IWUSR|S_IRWXG|S_IRWXO)) == -1) {
		syslog(LOG_ERR, "unable to open %s", CLUSTERD_DOOR);
		(void) close(doorfd);
		return (1);
	}



	/*
	 * Clean up any stale associations
	 */
	(void) fdetach(CLUSTERD_DOOR);

	/*
	 * Register in the kernel namespace for door_ki_open().
	 */
	if (fattach(doorfd, CLUSTERD_DOOR) == -1) {
		syslog(LOG_ERR, "Unable to fattach door %s", CLUSTERD_DOOR);
		(void) close(doorfd);
		(void) close(dfd);
		return (1);
	}
	(void) close(dfd);

	return (0);
}

static int
ifplumb(const char *linkname, const char *ifname, int af)
{
	int	arp_muxid = -1, ip_muxid;
	int	mux_fd, ip_fd, arp_fd;
	int 	retval;
	char	*udp_dev_name;
	uint64_t flags;
	uint_t	dlpi_flags;
	dlpi_handle_t	dh_arp, dh_ip;
	struct lifreq lifr;
	ifspec_t ifsp;
	struct strioctl ioc;

	/*
	 * Always dlpi_open() with DLPI_NOATTACH because the IP and ARP module
	 * will do the attach themselves for DLPI style-2 links.
	 */
	dlpi_flags = DLPI_NOATTACH;

	retval = dlpi_open(linkname, &dh_ip, dlpi_flags);
	if (retval != DLPI_SUCCESS) {
		syslog(LOG_ERR, "cannot open link %s, error: %d", linkname, retval);
		return (-1);
	}

	ip_fd = dlpi_fd(dh_ip);
	if (ioctl(ip_fd, I_PUSH, IP_MOD_NAME) == -1) {
		syslog(LOG_ERR, "%s I_PUSH, error: %d", IP_MOD_NAME, errno);
		return (-1);
	}

	/*
	 * Prepare to set IFF_IPV4/IFF_IPV6 flags as part of SIOCSLIFNAME.
	 * (At this point in time the kernel also allows an override of the
	 * IFF_CANTCHANGE flags.)
	 */
	lifr.lifr_name[0] = '\0';
	if (ioctl(ip_fd, SIOCGLIFFLAGS, (char *)&lifr) == -1) {
		syslog(LOG_ERR, "ifplumb: SIOCGLIFFLAGS, error %d", errno);
		return (-1);
	}

	if (af == AF_INET6) {
		flags = lifr.lifr_flags | IFF_IPV6;
		flags &= ~(IFF_BROADCAST | IFF_IPV4);
	} else {
		flags = lifr.lifr_flags | IFF_IPV4;
		flags &= ~IFF_IPV6;
	}

	if (!ifparse_ifspec(ifname, &ifsp) || ifsp.ifsp_lunvalid) {
		syslog(LOG_ERR, "invalid IP interface name %s", ifname);
		return (-1);
	}

	lifr.lifr_ppa = ifsp.ifsp_ppa;
	lifr.lifr_flags = flags;
	(void) strlcpy(lifr.lifr_name, ifname, LIFNAMSIZ);
	retval = ioctl(ip_fd, SIOCSLIFNAME, &lifr);

	if (retval == -1) {
		syslog(LOG_ERR, "SIOCSLIFNAME for ip, error %d", errno);
		return (-1);
	}

	/* Get the full set of existing flags for this stream */
	if (ioctl(ip_fd, SIOCGLIFFLAGS, (char *)&lifr) == -1) {
		syslog(LOG_ERR, "ifplumb: SIOCGLIFFLAGS, error %d", errno);
		return (-1);
	}

	/*
	 * Open "/dev/udp" for use as a multiplexor to PLINK the
	 * interface stream under. We use "/dev/udp" instead of "/dev/ip"
	 * since STREAMS will not let you PLINK a driver under itself,
	 * and "/dev/ip" is typically the driver at the bottom of
	 * the stream for tunneling interfaces.
	 */
	if (af == AF_INET6)
		udp_dev_name = UDP6_DEV_NAME;
	else
		udp_dev_name = UDP_DEV_NAME;

	/* open arp on udp */
	if ((mux_fd = open(udp_dev_name, O_RDWR)) == -1) {
		syslog(LOG_ERR, "open %s error %d", udp_dev_name, errno);
		return (-1);
	}
	errno = 0;
	while (ioctl(mux_fd, I_POP, 0) != -1)
		;
	if (errno != EINVAL) {
		syslog(LOG_ERR, "pop %s, error %d", udp_dev_name, errno);
		close(mux_fd);
		return (-1);
	} else if (ioctl(mux_fd, I_PUSH, ARP_MOD_NAME) == -1) {
		syslog(LOG_ERR, "arp PUSH, error %d", udp_dev_name, errno);
		close(mux_fd);
		return (-1);
	}

	/* Check if arp is not needed */
	if (lifr.lifr_flags & (IFF_NOARP|IFF_IPV6)) {
		/*
		 * PLINK the interface stream so that ifconfig can exit
		 * without tearing down the stream.
		 */
		if ((ip_muxid = ioctl(mux_fd, I_PLINK, ip_fd)) == -1) {
			syslog(LOG_ERR, "I_PLINK for ip, error %d", errno);
			return (-1);
		}
		(void) close(mux_fd);
		return (lifr.lifr_ppa);
	}

	/*
	 * This interface does use ARP, so set up a separate stream
	 * from the interface to ARP.
	 */
	retval = dlpi_open(linkname, &dh_arp, dlpi_flags);
	if (retval != DLPI_SUCCESS) {
		syslog(LOG_ERR, "cannot open link %s, error %d", linkname, retval);
		return (-1);
	}

	arp_fd = dlpi_fd(dh_arp);
	if (ioctl(arp_fd, I_PUSH, ARP_MOD_NAME) == -1) {
		syslog(LOG_ERR, "%s I_PUSH, error %d", ARP_MOD_NAME, errno);
		return (-1);
	}

	/*
	 * Tell ARP the name and unit number for this interface.
	 * Note that arp has no support for transparent ioctls.
	 */
	(void) memset(&ioc, 0, sizeof (ioc));
	ioc.ic_cmd = SIOCSLIFNAME;
	ioc.ic_timout = 0;
	ioc.ic_len = sizeof(lifr);
	ioc.ic_dp = (char *)&lifr;
	if (ioctl(arp_fd, I_STR, (char *)&ioc) == -1) {
		if (errno != EEXIST) {
			syslog(LOG_ERR, "SIOCSLIFNAME for arp, error %d", errno);
			return (-1);
		}
		syslog(LOG_ERR, "SIOCSLIFNAME for arp, error %d", errno);
		goto out;
	}

	/*
	 * PLINK the IP and ARP streams so that ifconfig can exit
	 * without tearing down the stream.
	 */
	if ((ip_muxid = ioctl(mux_fd, I_PLINK, ip_fd)) == -1) {
		syslog(LOG_ERR, "I_PLINK for ip, error %d", errno);
		return (-1);
	}
	if ((arp_muxid = ioctl(mux_fd, I_PLINK, arp_fd)) == -1) {
		(void) ioctl(mux_fd, I_PUNLINK, ip_muxid);
		syslog(LOG_ERR, "I_PLINK for arp, error %d", errno);
		return (-1);
	}

out:
	dlpi_close(dh_ip);
	dlpi_close(dh_arp);
	(void) close(mux_fd);
	return (lifr.lifr_ppa);
}

static int
get_all_ifs(char **ifs_req, unsigned *ifs_req_len)
{
	int s;
	struct lifnum lifn;
	struct lifconf lifc;
	struct lifreq *lifrp;
	char *buf;
	unsigned bufsize;
	int numifs = 0, n;
	char ipaddr[INET6_ADDRSTRLEN];
	struct sockaddr_storage *ss;
	const char *p;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		syslog(LOG_ERR, "socket error: %d", s);
		return (-1);
	}

	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = LIFC_NOXMIT|LIFC_TEMPORARY|LIFC_ALLZONES|LIFC_UNDER_IPMP;
	if (ioctl(s, SIOCGLIFNUM, (char *)&lifn) < 0) {
		syslog(LOG_ERR, "Could not determine number"
		    " of interfaces: %d", errno);
		close(s);
		return (-1);
	}
	numifs = lifn.lifn_count;

	bufsize = numifs * sizeof (struct lifreq);
	if ((buf = malloc(bufsize)) == NULL) {
		syslog(LOG_ERR, "out of memory: %d", errno);
		close(s);
		return (-1);
	}

	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = LIFC_NOXMIT|LIFC_TEMPORARY|LIFC_ALLZONES|LIFC_UNDER_IPMP;
	lifc.lifc_len = bufsize;
	lifc.lifc_buf = buf;

	if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) < 0) {
		syslog(LOG_ERR, "SIOCGLIFCONF: %d", errno);
		close(s);
		free(buf);
		return (-1);
	}

	close(s);
	*ifs_req_len = lifc.lifc_len;
	*ifs_req = buf;
	numifs = lifc.lifc_len / sizeof(struct lifreq);
	
	return (numifs);
}

static int
get_if_flags(struct lifreq *lifrp)
{
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		syslog(LOG_ERR, "socket error: %d", s);
		return (-1);
	}

	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t) lifrp) < 0) {
		syslog(LOG_ERR, "status: SIOCGLIFFLAGS");
		close(s);
		return (-1);
	}

	close(s);
	return (0);
}
#endif

static int
check_ip_addr(const char *addrstr, char *dst)
{
	struct in_addr addr;
	struct in6_addr addr6;
	
	if (inet_aton(addrstr, &addr)) {
		if (dst) {
			if (inet_ntop(AF_INET, &addr, dst, INET_ADDRSTRLEN) == NULL) {
				syslog(LOG_ERR, "inet_ntop error: %d", errno);
				return (-1);
			}
		}
		return (AF_INET);
	}
	if (inet_pton(AF_INET6, addrstr, (void *)&addr6) == 1) {
		if (dst) {
			if (inet_ntop(AF_INET6, &addr, dst, INET6_ADDRSTRLEN) == NULL) {
				syslog(LOG_ERR, "inet_ntop error: %d", errno);
				return (-1);
			}
		}
		return (AF_INET6);
	}
	return (-1);
}

static int
parse_failover_conf(const char *msg, failover_conf_t *conf)
{
	char buf[ZFS_MAXNAMELEN + ZFS_MAXPROPLEN];
	char *token, *subtok;
	char *prop_name, *prop_val;
	long val;

	printf("parse_failover_conf: %s\n", msg);
	/*
	 * msg format: zfs_name,prop_name,prop_val
	 * prop_name format: failover:eth_name[:id]
	 * propval format: ipaddr[/prefixlen]
	 */
	memset(conf, 0, sizeof(failover_conf_t));
	strlcpy(buf, msg, sizeof(buf));
	token = strtok(buf, ",");
	if (!token)
		return (-1);
	strlcpy(conf->zpool_name, token, ZFS_MAXNAMELEN);
	subtok = strchr(conf->zpool_name, '/');
	if (subtok)
		*subtok = '\0';
	token = strtok(NULL, ",");
	if (!token)
		return (-1);
	prop_name = token;

	token = strtok(NULL, ",");
	if (!token)
		return (-1);
	prop_val = token;
	token = strchr(prop_val, '/');
	if (token) {
		*token++ = '\0';
		val = strtol(token, NULL, 10);
		if (val > 0 && val <= 32)
			conf->prefixlen = val;
	}
	if ((conf->af = check_ip_addr(prop_val, conf->ip_addr)) == -1)
		return (-1);

	subtok = strtok(prop_name, ":");
	if (!subtok)
		return (-1);
	subtok = strtok(NULL, ":");
	if (!subtok)
		return -1;
	if (strlen(subtok) > ETH_MAXNAMELEN)
		return -1;
	strlcpy(conf->eth, subtok, ETH_MAXNAMELEN);
	subtok = strtok(NULL, ":");
	if (subtok)
		strlcpy(conf->prop_id, subtok, ZFS_MAXPROPLEN);
	
	return (0);
}

static int
handle_failover_set(cluster_mq_message_t *msg)
{
	failover_conf_t conf;
	struct shielding_failover_pools *p = &shielding_failover_pools;
	struct link_list *l;
	release_pool_param_t *r;

	msg->msg[msg->msglen] = 0;
	if (parse_failover_conf(msg->msg, &conf) == 0) {
		pthread_mutex_lock(&p->lock);
		for (l = p->head; l != NULL; l = l->next) {
			r = l->ptr;
			if (strncmp(r->pool_name, conf.zpool_name, ZPOOL_MAXNAMELEN) == 0) {
				syslog(LOG_WARNING, "handle_failover_set: skip pool failover,"
					" poolname=%s, ip=%s, msgtype=%d",
					conf.zpool_name, conf.ip_addr, msg->msgtype);
				pthread_mutex_unlock(&p->lock);
				return (0);
			}
		}
		pthread_mutex_unlock(&p->lock);

		switch (msg->msgtype) {
		case cluster_msgtype_set_failover:
		case cluster_msgtype_mount:
			do_ip_failover(&conf, 0);
			break;
		case cluster_msgtype_remove_failover:
		case cluster_msgtype_umount:
			do_ip_restore(&conf);
			break;
		default:
			syslog(LOG_ERR, "Invalid msgtype: %d", msg->msgtype);
			return (-1);
		}
	}
	
	return (0);
}

static int
check_ip_exist(int af, const char *eth, const char *ip)
{
	struct ifs_chain *ifs;
	struct ifs_node *ifn;
	struct ifs_addr *addr;
	char ipaddr[INET6_ADDRSTRLEN];
	const char *p;

	if ((ifs = get_all_ifs()) == NULL)
		return (0);

	for (ifn = ifs->head; ifn != NULL; ifn = ifn->next) {
		if (strncmp(ifn->link, eth, IFNAMSIZ) != 0)
			continue;

		for (addr = ifn->addrs; addr != NULL; addr = addr->next) {
			if (addr->af != af)
				continue;

			p = inet_ntop(addr->af, addr->addr, ipaddr, INET6_ADDRSTRLEN);
			if (p) {
				if (strncmp(ip, ipaddr, INET6_ADDRSTRLEN) == 0) {
					free_ifs_chain(ifs);
					return (1);
				}
			}
		}
	}

	free_ifs_chain(ifs);
	return (0);
}

/*
 * return 1 if ip up, return 0 if ip down, otherwise return -1
 */
static int
ifconfig_up(const char *cmd, int af, const char *ifname, const char *ipaddr,
	int trycnt)
{
	/*char r_ifname[MAXLINKNAMELEN];*/
	/*char upcmd[128];*/
	int ret = 0;

	ret = excute_ifconfig(cmd);
	if (ret != 0) {
		syslog(LOG_ERR, "excute_ifconfig return %d", ret);
		return -1;
	}
#if	0
	sleep(1);

	r_ifname[0] = '\0';
	ret = check_ip_enable(af, ifname, ipaddr, r_ifname, MAXLINKNAMELEN);
	if (ret != 0)
		return (ret);
	if (strncmp(ifname, r_ifname, strlen(ifname)) != 0) {
		syslog(LOG_ERR, "ifconfig failed: ifname=%s, r_ifname=%s",
			ifname, r_ifname);
		return (-1);
	}

	snprintf(upcmd, sizeof(upcmd), "%s %s %s up", IFCONFIG_CMD, r_ifname,
		af == AF_INET6 ? "inet6" : "");

	while (trycnt-- > 0) {
		sleep(10);

		ret = excute_ifconfig(upcmd);
		if (ret != 0) {
			syslog(LOG_ERR, "excute_ifconfig return %d", ret);
			return (0);
		}
		sleep(1);

		ret = check_ip_enable(af, ifname, ipaddr, NULL, 0);
		if (ret != 0) {
			return (ret == 1 ? 1 : 0);
		}
	}
#endif
	return (1);
}

static failover_conf_t *
dup_failover_config(failover_conf_t *config)
{
	failover_conf_t *f;

	f = malloc(sizeof(failover_conf_t));
	if (f)
		memcpy(f, config, sizeof(failover_conf_t));
	return (f);
}

#define	IFLABELMAXLEN	15

/*
 * @flag: =0 normal ip failover
 *        =1 restore ip failover from clusterd crash
 *        =2 restore ip failover from link down
 */
static int 
do_ip_failover(failover_conf_t *conf, int flag)
{
	char cmd[BUFSIZ];
	char alias[IFLABELMAXLEN];
	service_if_t *ifp;
	int ip_on_link = 0;
	service_zpool_t *zp;
	struct link_list *node;
	int err = 0;

	syslog(LOG_WARNING, "%s: conf=(pool=%s, eth=%s, ip=%s), flag=%d",
		__func__, conf->zpool_name, conf->eth, conf->ip_addr, flag);
	if (!conf || strlen(conf->eth) == 0 || strlen(conf->ip_addr) == 0)
		return (EINVAL);

	pthread_mutex_lock(&failover_list_lock);
	for (ifp = list_head(&failover_ip_list); 
			ifp; 
			ifp = list_next(&failover_ip_list, ifp)) {
		if (strcmp(ifp->ip_addr, conf->ip_addr) == 0) {
			syslog(LOG_WARNING, "ip %s is exist on host", ifp->ip_addr);
			if (flag == 2)
				break;
			ifp->refs++;
			goto add_zpool;
		}
	}

	if (flag == 2 && ifp == NULL) {
		err = ENOENT;
		goto exit_func;
	}

	if (check_ip_exist(conf->af, conf->eth, conf->ip_addr)) {
		syslog(LOG_WARNING, "ip %s is exist on if %s", conf->ip_addr, conf->eth);
		ip_on_link = 1;
		if (flag == 2)
			goto exit_func;
	}

	if (!ip_on_link) {
		snprintf(alias, IFLABELMAXLEN, "%s:%s:%s",
			conf->eth, conf->prop_id, conf->zpool_name);
		snprintf(cmd, BUFSIZ, "%s addr add %s/%d brd + label %s dev %s",
			IP_CMD, conf->ip_addr,
			conf->prefixlen > 0 ? conf->prefixlen : 24,
			alias, conf->eth);
		if ((err = ifconfig_up(cmd, conf->af, conf->eth, conf->ip_addr,
				3)) < 0) {
			syslog(LOG_ERR, "%s: excute ifconfig addif error: %d",
				__func__, err);
			err = -1;
			goto exit_func;
		} else if (err == 0) {
			syslog(LOG_WARNING, "%s: excute ifconfig addif failed, ip down",
				__func__);
		}
	}

	if (flag == 2)
		goto exit_func;

	if ((err = add_monitor_ifs(conf->eth)) != 0) {
		syslog(LOG_WARNING, "add_monitor_ifs() failed: %s",
			strerror(-err));
	}

	ifp = (service_if_t *) malloc(sizeof(service_if_t));
	if (ifp == NULL) {
		syslog(LOG_ERR, "alloc service_if_t failed");
		err = ENOMEM;
		goto exit_func;
	}
	strlcpy(ifp->eth, conf->eth, MAXLINKNAMELEN);
	strlcpy(ifp->alias, alias, IFALIASZ);
	strlcpy(ifp->ip_addr, conf->ip_addr, INET6_ADDRSTRLEN);
	ifp->prefixlen = conf->prefixlen;
	/* 
	 * if restore_flag is set and ip_on_link == 1,
	 * so the ip may set by clusterd
	 */
	ifp->refs = (ip_on_link && flag == 0) ? 2 : 1;
	ifp->zpool_list = NULL;
	ifp->zpool_refs = 0;
	ifp->flag = 0;
	ifp->failover_config = dup_failover_config(conf);

	list_insert_head(&failover_ip_list, ifp);

add_zpool:
	for (zp = list_head(&failover_zpool_list);
			zp;
 			zp = list_next(&failover_zpool_list, zp)) {
		if (strcmp(zp->zpool_name, conf->zpool_name) == 0)
			break;
	}

	if (!zp) {
		zp = (service_zpool_t *) malloc(sizeof(service_zpool_t));
		if (!zp) {
			syslog(LOG_ERR, "alloc service_zpool_t failed");
			err = ENOMEM;
			goto exit_func;
		}
		strlcpy(zp->zpool_name, conf->zpool_name, ZPOOL_MAXNAMELEN);
		zp->if_list = NULL;
		zp->flag = 0;
		list_insert_head(&failover_zpool_list, zp);
	}

	if ((node = create_link(zp)) == NULL) {
		syslog(LOG_ERR, "alloc ifp->zpool_list node failed");
		err = ENOMEM;
		goto exit_func;
	}
	node->next = ifp->zpool_list;
	ifp->zpool_list = node;

	if ((node = create_link(ifp)) == NULL) {
		syslog(LOG_ERR, "alloc zp->if_list node failed");
		err = ENOMEM;
		goto exit_func;
	}
	ifp->zpool_refs++;
	node->next = zp->if_list;
	zp->if_list = node;

exit_func:
	pthread_mutex_unlock(&failover_list_lock);
	return (err);
}

static void
remove_monitor_dev(const char *dev)
{
	service_if_t *ifp;

	for (ifp = list_head(&failover_ip_list); 
			ifp; 
			ifp = list_next(&failover_ip_list, ifp)) {
		if (strncmp(ifp->eth, dev, MAXLINKNAMELEN) == 0)
			return;
	}
	remove_monitor_ifs(dev);
}

static int 
do_ip_restore(failover_conf_t *conf)
{
	char cmd[128];
	service_if_t *ifp, *tmp;
	service_zpool_t *zp;
	struct link_list *p, **pp;
	int err = 0;

	if (!conf || strlen(conf->eth) == 0 || strlen(conf->ip_addr) == 0)
		return (EINVAL);
	pthread_mutex_lock(&failover_list_lock);
	for (ifp = list_head(&failover_ip_list); 
			ifp; 
			ifp = list_next(&failover_ip_list, ifp)) {
		if (strcmp(ifp->ip_addr, conf->ip_addr) == 0) {
			for (pp = &ifp->zpool_list; *pp; ) {
				p = *pp;
				zp = (service_zpool_t *) p->ptr;
				if (zp && strcmp(zp->zpool_name, conf->zpool_name) == 0) {
					*pp = p->next;
					free(p);
					break;
				}
				pp = &p->next;
			}

			ifp->refs--;
			if (ifp->refs == 0) {
				snprintf(cmd, 128, "%s addr del %s/%d dev %s",
					IP_CMD, conf->ip_addr,
					conf->prefixlen > 0 ? conf->prefixlen : 24,
					conf->eth);
				if ((err = excute_ifconfig(cmd)) != 0) {
					syslog(LOG_ERR, "removeif error - %d", err);
#if	0
					ifp->refs++;
					pthread_mutex_unlock(&failover_list_lock);
					return (-1);
#endif
				}
			}
			if (ifp->zpool_list == NULL) {
				tmp = list_prev(&failover_ip_list, ifp);
				list_remove(&failover_ip_list, ifp);
				if (ifp->failover_config)
					free(ifp->failover_config);
				/*free(ifp);*/
				assert(ifp->zpool_refs > 0);
				ifp = tmp;

				remove_monitor_dev(conf->eth);
			}
			goto update_zpool;
		}
	}
	syslog(LOG_WARNING, "ip %s not exist", conf->ip_addr);
	pthread_mutex_unlock(&failover_list_lock);
	return (-1);

update_zpool:
	for (zp = list_head(&failover_zpool_list);
			zp;
			zp = list_next(&failover_zpool_list, zp)) {
		if (strcmp(zp->zpool_name, conf->zpool_name) == 0) {
			for (pp = &zp->if_list; *pp; ) {
				p = *pp;
				ifp = (service_if_t *) p->ptr;
				if (ifp && strcmp(ifp->ip_addr, conf->ip_addr) == 0) {
					assert(ifp->zpool_refs > 0);
					if (--ifp->zpool_refs == 0) {
						assert(!list_link_active(&ifp->list));
						free(ifp);
					}
					*pp = p->next;
					free(p);
					break;
				}
				pp = &p->next;
			}

			if (zp->if_list == NULL) {
				list_remove(&failover_zpool_list, zp);
				free(zp);
			}
			break;
		}
	}

	pthread_mutex_unlock(&failover_list_lock);
	return (0);
}

struct cluster_link_down_timer {
	struct cluster_link_down_timer *next;
	char linkname[IFNAMSIZ];
	int expired;
	int cancel;

	pthread_t tid;
	pthread_mutex_t lock;
	pthread_cond_t cv;
};

static struct cluster_link_down_timer *cluster_link_down_timers = NULL;
static pthread_mutex_t cluster_link_down_timers_lock;
static int cluster_link_down_timeout = 60;	/* seconds */

static void
cluster_link_down_timer_free(pthread_t tid)
{
	struct cluster_link_down_timer *p, **pp;

	pthread_mutex_lock(&cluster_link_down_timers_lock);
	for (pp = &cluster_link_down_timers; *pp; pp = &(*pp)->next) {
		p = *pp;
 		if (p->tid == tid) {
			pthread_cond_destroy(&p->cv);
			pthread_mutex_destroy(&p->lock);
			*pp = p->next;
			free(p);
			break;
		}
	}
	pthread_mutex_unlock(&cluster_link_down_timers_lock);
}

static void *
cluster_link_down_timer_thread(void *arg)
{
	struct cluster_link_down_timer *p;
	pthread_t tid;
	timespec_t ts;
	int err;

	tid = pthread_self();
	pthread_detach(tid);

	pthread_mutex_lock(&cluster_link_down_timers_lock);
	for (p = cluster_link_down_timers; p; p = p->next) {
		if (p->tid == tid)
			break;
	}
	pthread_mutex_unlock(&cluster_link_down_timers_lock);
 	if (!p) return (NULL);

	pthread_mutex_lock(&p->lock);
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += cluster_link_down_timeout;
	while (p->cancel == 0) {
		err = pthread_cond_timedwait(&p->cv, &p->lock, &ts);
		if (err == ETIMEDOUT)
			break;
	}
	if (p->cancel == 0)
		cluster_failover_conf_handler(FLAG_CF_MAC_OFFLINE, p->linkname);
	p->expired = 1;
	pthread_mutex_unlock(&p->lock);

	cluster_link_down_timer_free(tid);

	return (NULL);
}

static int
cluster_link_down_timer_add(const char *linkname)
{
	struct cluster_link_down_timer *p;

	pthread_mutex_lock(&cluster_link_down_timers_lock);

	for (p = cluster_link_down_timers; p; p = p->next) {
		if (strncmp(p->linkname, linkname, IFNAMSIZ) == 0) {
			syslog(LOG_ERR, "%s: link %s is exists", __func__, linkname);
			pthread_mutex_unlock(&cluster_link_down_timers_lock);
			return (-1);
		}
	}

	p = malloc(sizeof(struct cluster_link_down_timer));
	if (!p) {
		syslog(LOG_ERR, "%s: out of memory", __func__);
		pthread_mutex_unlock(&cluster_link_down_timers_lock);
		return (-1);
	}

	memset(p, 0, sizeof(struct cluster_link_down_timer));
	strncpy(p->linkname, linkname, IFNAMSIZ);

	pthread_mutex_init(&p->lock, NULL);
	pthread_cond_init(&p->cv, NULL);
	if (pthread_create(&p->tid, NULL,
		&cluster_link_down_timer_thread, NULL) != 0) {
		syslog(LOG_ERR, "%s: create thread failed - %d", __func__, errno);
		free(p);
		pthread_mutex_unlock(&cluster_link_down_timers_lock);
		return (-1);
	}

	p->next = cluster_link_down_timers;
	cluster_link_down_timers = p;

	pthread_mutex_unlock(&cluster_link_down_timers_lock);
	return (0);
}

static int
cluster_link_down_timer_del(const char *linkname)
{
	struct cluster_link_down_timer *p;

	pthread_mutex_lock(&cluster_link_down_timers_lock);
	for (p = cluster_link_down_timers; p; p = p->next) {
		if (strncmp(p->linkname, linkname, IFNAMSIZ) == 0) {
			pthread_mutex_lock(&p->lock);
			p->cancel = 1;
			pthread_cond_signal(&p->cv);
			pthread_mutex_unlock(&p->lock);

			pthread_mutex_unlock(&cluster_link_down_timers_lock);
			return (0);
		}
	}
	pthread_mutex_unlock(&cluster_link_down_timers_lock);

	return (-1);
}

static void
cluster_link_down_failover_restore(const char *linkname)
{
	service_if_t *ifp;

	syslog(LOG_WARNING, "%s: linkname=%s", __func__, linkname);
	pthread_mutex_lock(&failover_list_lock);
	for (ifp = list_head(&failover_ip_list); 
			ifp; 
			ifp = list_next(&failover_ip_list, ifp)) {
		if (strcmp(ifp->eth, linkname) == 0) {
			pthread_mutex_unlock(&failover_list_lock);
			(void) do_ip_failover(ifp->failover_config, 2);
			pthread_mutex_lock(&failover_list_lock);
		}
	}
	pthread_mutex_unlock(&failover_list_lock);
}

static void
cluster_monitor_dev_state_change(const char *dev,
	unsigned state, unsigned oldstate)
{
	syslog(LOG_WARNING, "%s: dev=%s, state=%d, oldstate=%d",
		__func__, dev, state, oldstate);
	if (state == ils_down && oldstate != ils_down)
		cluster_link_down_timer_add(dev);
	else if (state == ils_up && oldstate != ils_up) {
		cluster_link_down_timer_del(dev);
		cluster_link_down_failover_restore(dev);
	}
}

static void
init_cluster_link_down_timer(void)
{
	pthread_mutex_init(&cluster_link_down_timers_lock, NULL);
	init_monitor_ifs(&cluster_monitor_dev_state_change);
}

#if	0
static int
pack_mq_release_pools_message(release_pools_message_t *r_msg,
	cluster_mq_message_t *mq_msg)
{
	char *p = mq_msg->msg;
	int msglen = 0, i;
	size_t len;

	memcpy(p + msglen, &r_msg->remote_id, sizeof(int));
	msglen += sizeof(int);
	memcpy(p + msglen, &r_msg->pools_num, sizeof(int));
	msglen += sizeof(int);
	for (i = 0; i < r_msg->pools_num; i++) {
		len = strlen(r_msg->pools_list[i]);
		if (msglen + len + sizeof(size_t) > CLUSTER_MQ_MSGSIZ)
			return (-1);
		memcpy(p + msglen, &len, sizeof(size_t));
		msglen += sizeof(size_t);
		memcpy(p + msglen, r_msg->pools_list[i], len);
		msglen += len;
	}
	mq_msg->msglen = msglen;
	mq_msg->msgtype = cluster_msgtype_release;
	return (0);
}
#endif

static int
unpack_mq_release_pools_message(cluster_mq_message_t *mq_msg,
	release_pools_message_t *r_msg)
{
	char *p = mq_msg->msg;
	char *buf;
	size_t len;
	int i, msglen = 0;

	if (mq_msg->msgtype != cluster_msgtype_release ||
			mq_msg->msglen <= 0 || mq_msg->msglen > CLUSTER_MQ_MSGSIZ)
		return (-1);
	r_msg->remote_id = *((int *) p);
	p += sizeof(int);
	msglen += sizeof(int);
	r_msg->pools_num = *((int *) p);
	p += sizeof(int);
	msglen += sizeof(int);
	for (i = 0; msglen < mq_msg->msglen; i++) {
		len = *((size_t *) p);
		if (len >= ZPOOL_MAXNAMELEN)
			goto unpack_fail;
		buf = malloc(ZPOOL_MAXNAMELEN);
		if (!buf)
			goto unpack_fail;
		p += sizeof(size_t);
		memcpy(buf, p, len);
		buf[len] = '\0';
		r_msg->pools_list[i] = buf;
		p += len;
		msglen += len + sizeof(size_t);
	}
	if (i != r_msg->pools_num)
		goto unpack_fail;
	return (0);

unpack_fail:
	for (--i; i >= 0; i--) {
		free(r_msg->pools_list[i]);
	}
	return (-1);
}

static int
pack_release_pool_param(release_pool_param_t *param, void *buffer, int *bufsiz)
{
	char *p = buffer;
	int msglen = 0, i;
	size_t len;

	len = strlen(param->pool_name);
	memcpy(p + msglen, &len, sizeof(len));
	msglen += sizeof(len);
	memcpy(p + msglen, param->pool_name, len);
	msglen += len;
	memcpy(p + msglen, &param->failover_num, sizeof(int));
	msglen += sizeof(int);
	if (msglen > *bufsiz)
		return (-1);
	for (i = 0; i < param->failover_num; i++) {
		len = strlen(param->failover[i]);
		memcpy(p + msglen, &len, sizeof(len));
		msglen += sizeof(len);
		memcpy(p + msglen, param->failover[i], len);
		msglen += len;
		if (msglen > *bufsiz)
			return (-1);
	}
	*bufsiz = msglen;
	return (0);
}

static int
unpack_release_pool_param(const void *buffer, int bufsiz,
	release_pool_param_t *param)
{
	const char *p = buffer;
	char *buf;
	size_t len;
	int i, msglen = 0;

	len = *((size_t *) p);
	if (len >= ZPOOL_MAXNAMELEN)
		return (-1);
	p += sizeof(len);
	memcpy(param->pool_name, p, len);
	param->pool_name[len] = 0;
	p += len;
	msglen += len + sizeof(len);
	param->failover_num = *((int *) p);
	p += sizeof(int);
	msglen += sizeof(int);
	for (i = 0; msglen < bufsiz; i++) {
		len = *((size_t *) p);
		if (len >= ZFS_MAXNAMELEN + ZFS_MAXPROPLEN)
			goto unpack_fail;
		buf = malloc(ZFS_MAXNAMELEN + ZFS_MAXPROPLEN);
		if (!buf)
			goto unpack_fail;
		p += sizeof(len);
		memcpy(buf, p, len);
		buf[len] = '\0';
		param->failover[i] = buf;
		p += len;
		msglen += len + sizeof(len);
	}
	if (i != param->failover_num)
		goto unpack_fail;
	return (0);

unpack_fail:
	for (--i; i >= 0; i--)
		free(param->failover[i]);
	return (-1);
}

static int
pack_release_pool_param_list(struct link_list *param_list,
	void *buffer, int *bufsiz)
{
	struct link_list *p;
	int msglen = 0, len;

	for (p = param_list; (p != NULL) && (p->ptr != NULL); p = p->next) {
		len = *bufsiz - msglen;
		if (pack_release_pool_param((release_pool_param_t *) p->ptr,
				(char *)buffer + msglen + sizeof(int), &len) != 0)
			break;
		*((int *) ((char *)buffer + msglen)) = len;
		msglen += len + sizeof(int);
		if (msglen > *bufsiz)
			return (-1);
	}
	if (p != NULL)
		return (-1);
	*bufsiz = msglen;
	return (0);
}

static void free_release_pool_param(release_pool_param_t *param);

static int
unpack_release_pool_param_list(const void *buffer, int bufsiz,
	struct link_list **param_list)
{
	struct link_list *p;
	release_pool_param_t *param;
	int len, msglen = 0, pool_num = 0;

	if (bufsiz < sizeof(int))
		return (-1);
	while (msglen < bufsiz) {
		len = *((int *) ((char *)buffer + msglen));
		msglen += sizeof(int);
		if (len > bufsiz - msglen)
			goto unpack_fail;
		param = malloc(sizeof(release_pool_param_t));
		if (!param)
			goto unpack_fail;
		if (unpack_release_pool_param((char *)buffer + msglen, len, param) != 0) {
			free(param);
			goto unpack_fail;
		}
		p = create_link(param);
		if (!p) {
			free_release_pool_param(param);
			goto unpack_fail;
		}
		p->next = *param_list;
		*param_list = p;
		msglen += len;
		pool_num++;
	}
	return (0);

unpack_fail:
	while (pool_num--) {
		p = *param_list;
		*param_list = p->next;
		if (p) {
			if (p->ptr)
				free_release_pool_param((release_pool_param_t *) p->ptr);
			free(p);
		}
	}
	return (-1);
}

struct release_zfs_iter_cbdata {
	char root_zfsname[ZFS_MAXNAMELEN];
	struct link_list *failoverprops_list;
};

static int
release_zfs_iter_cb(zfs_handle_t *zhp, void *data)
{
	struct release_zfs_iter_cbdata *cbdata = (struct release_zfs_iter_cbdata *) data;
	const char *zfsname = zfs_get_name(zhp);
	nvlist_t *user_props = zfs_get_user_props(zhp);
	nvpair_t *elem = NULL;
	nvlist_t *propval;
	char *strval, *sourceval;
	char buf[ZFS_MAXNAMELEN+ZFS_MAXPROPLEN];
	char *failoverpropstr;
	struct link_list *node;
	int err = 0;

	if (strncmp(zfsname, cbdata->root_zfsname, strlen(cbdata->root_zfsname)) != 0)
		return (0);

	while ((elem = nvlist_next_nvpair(user_props, elem)) != NULL) {
		if (!zfs_is_failover_prop(nvpair_name(elem)))
			continue;
		err = nvlist_lookup_nvlist(user_props, nvpair_name(elem), &propval);
		if (err != 0) {
			syslog(LOG_ERR, "get property error: %d", err);
			zfs_close(zhp);
			return (err);
		}
		verify(nvlist_lookup_string(propval, ZPROP_VALUE, &strval) == 0);
		verify(nvlist_lookup_string(propval, ZPROP_SOURCE, &sourceval) == 0);
		if (strcmp(sourceval, zfsname) == 0) {
			snprintf(buf, sizeof(buf), "%s,%s,%s",
				zfsname, nvpair_name(elem), strval);
			failoverpropstr = strdup(buf);
			if (failoverpropstr) {
				node = create_link(failoverpropstr);
				if (!node)
					free(failoverpropstr);
				else {
					node->next = cbdata->failoverprops_list;
					cbdata->failoverprops_list = node;
				}
			}
		}
	}

	if (zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM)
		err = zfs_iter_filesystems(zhp, release_zfs_iter_cb, data);

	zfs_close(zhp);
	return (err);
}

static int
get_release_pool_param(release_pool_param_t *pool_param)
{
	libzfs_handle_t *hdl;
	struct release_zfs_iter_cbdata cbdata;
	struct link_list *p;
	int ret = 0, i;

	if (!pool_param || !pool_param->pool_name)
		return (-1);

	hdl = libzfs_init();
	if (!hdl) {
		syslog(LOG_ERR, "%s: failed to get libzfs handle", __func__);
		return (-1);
	}
	strlcpy(cbdata.root_zfsname, pool_param->pool_name, ZFS_MAXNAMELEN);
	cbdata.failoverprops_list = NULL;
	if (zfs_iter_root(hdl, release_zfs_iter_cb, &cbdata) != 0) {
		syslog(LOG_ERR, "%s: iter zfs error", __func__);
		if (cbdata.failoverprops_list != NULL) {
			free_link_list(cbdata.failoverprops_list, 1);
		}
		ret = -1;
	}
	libzfs_fini(hdl);

	if (cbdata.failoverprops_list) {
		for (i = 0, p = cbdata.failoverprops_list; p != NULL; p = p->next, i++) {
			pool_param->failover[i] = malloc(ZFS_MAXNAMELEN + ZFS_MAXPROPLEN);
			if (!pool_param->failover[i]) {
				ret = -1;
				break;
			}
			strlcpy(pool_param->failover[i], (const char *) p->ptr,
				ZFS_MAXNAMELEN + ZFS_MAXPROPLEN);
		}
		if (ret != 0) {
			for (--i; i >= 0; i--)
				free(pool_param->failover[i]);
		} else
			pool_param->failover_num = i;
		free_link_list(cbdata.failoverprops_list, 1);
	}

	return (ret);
}

static void
free_release_pool_param(release_pool_param_t *param)
{
	int i;

	if (param) {
		for (i = 0; i < param->failover_num; i++)
			free(param->failover[i]);
		free(param);
	}
}

static void
init_shielding_failover_poollist(void)
{
	struct shielding_failover_pools *p = &shielding_failover_pools;

	pthread_mutex_init(&p->lock, NULL);
	p->head = NULL;
}

static boolean_t
shielding_failover_poollist(struct link_list *list)
{
	struct shielding_failover_pools *p = &shielding_failover_pools;
	boolean_t success = B_FALSE;

	pthread_mutex_lock(&p->lock);
	if (p->head == NULL) {
		p->head = list;
		success = B_TRUE;
	}
	pthread_mutex_unlock(&p->lock);

	return (success);
}

static boolean_t
unshielding_failover_poollist(struct link_list *list)
{
	struct shielding_failover_pools *p = &shielding_failover_pools;
	boolean_t success = B_FALSE;

	pthread_mutex_lock(&p->lock);
	if (p->head == list) {
		p->head = NULL;
		success = B_TRUE;
	}
	pthread_mutex_unlock(&p->lock);

	return (success);
}

/*
 * Recv release pools event from remote, 
 * import the pools
 */
static int
handle_release_pools_event(const void *buffer, int bufsiz)
{
	struct link_list *pool_list = NULL;
	release_pool_param_t *param;
	failover_conf_t fconf;
	struct link_list *p;
	int i, err = 0;
	char cmdstr[128];

	/* get the todo import pools */
	if (unpack_release_pool_param_list(buffer, bufsiz, &pool_list) != 0) {
		syslog(LOG_ERR, "%s: unpack event message failed", __func__);
		return (-1);
	}

	/*
	 * Shielding the pools let do_ip_failover() skip them, we will
	 * do ip failover in this function.
	 */
	if (!shielding_failover_poollist(pool_list)) {
		syslog(LOG_ERR, "%s: shielding failover pools failed,"
			" ensure no concurrent release process.", __func__);
		err = -1;
		goto exit_func;
	}

	/* step 2: import the pools */
	for (p = pool_list; p != NULL; p = p->next) {
		param = (release_pool_param_t *) p->ptr;
		sprintf(cmdstr, "%s %s", ZPOOL_IMPORT, param->pool_name);
		if ((err = excute_cmd(cmdstr)) != 0) {
			syslog(LOG_ERR, "%s: import pool error - %d",
				__func__, err);
			err = -1;
			unshielding_failover_poollist(pool_list);
			goto exit_func;
		}
	}

	for (p = pool_list; (p != NULL) && (p->ptr != NULL); p = p->next) {
		param = (release_pool_param_t *) p->ptr;
		for (i = 0; i < param->failover_num; i++) {
			if (parse_failover_conf(param->failover[i], &fconf) != 0) {
				syslog(LOG_WARNING, "%s: invalid failover prop '%s'",
					__func__, param->failover[i]);
				continue;
			}

			do_ip_failover(&fconf, 0);
		}
	}

	unshielding_failover_poollist(pool_list);
exit_func:
	for (p = pool_list; p != NULL; p = p->next)
		free_release_pool_param((release_pool_param_t *) p->ptr);
	free_link_list(pool_list, 0);
	return (err);
}

/*
 * Recv the MSGs from mqueue or mac state change handler in clusterd, 
 * release the pools to remote.
 */
static int
handle_release_message_common(release_pools_message_t *r_msg)
{
	release_pool_param_t *param;
	struct link_list * pool_list = NULL, *node, **pp;
	failover_conf_t fconf;
	int err = 0, i, j;
	char cmdstr[128];
	char *buffer;
	int bufsize;

	for (i = 0; i < r_msg->pools_num; i++) {
		param = malloc(sizeof(release_pool_param_t));
		if (!param) {
			err = -1;
			break;
		}
		/* get pool failover props */
		strlcpy(param->pool_name, r_msg->pools_list[i], ZPOOL_MAXNAMELEN);
		param->failover_num = 0;
		if (get_release_pool_param(param) != 0) {
			err = -1;
			free(param);
			break;
		}

		for (j = 0; j < param->failover_num; j++) {
			if (parse_failover_conf(param->failover[j], &fconf) != 0) {
				free_release_pool_param(param);
				err = -1;
				break;
			}

			do_ip_restore(&fconf);
		}
		if (err != 0)
			break;

		node = create_link(param);
		if (!node) {
			free_release_pool_param(param);
			err = -1;
			break;
		}
		node->next = pool_list;
		pool_list = node;
	}

	if (err != 0) {
		syslog(LOG_ERR, "%s: handle release message failed", __func__);
	} else {
		/*
		 * We have released the failover ips, now shielding the pools,
		 * then we export them later and do_ip_restore() will skip them.
		 */
		if (!shielding_failover_poollist(pool_list)) {
			syslog(LOG_ERR, "%s: shielding failover pools failed,"
				" ensure no concurrent release process.", __func__);
			err = -1;
			goto exit_release;
		}

		/* step 2: export the pools */
		if (err == 0) {
			uint32_t	hostid = 0;

#if	0
			/* zfs_narrow_dirty_mem(), copy from zpool release code */
			zfs_narrow_dirty_mem();
			sleep(10);
#endif
			for (node = pool_list; node != NULL; node = node->next) {
				param = (release_pool_param_t *) node->ptr;
				sprintf(cmdstr, "%s %s", ZPOOL_EXPORT, param->pool_name);
				if ((err = excute_cmd_common(cmdstr, B_TRUE)) != 0) {
					syslog(LOG_ERR, "%s: excute export pool error - %d",
						__func__, err);
					err = -1;
					break;
				}
			}
			/*zfs_restore_dirty_mem();*/

			/* sync pools to cluster */
			hbx_do_cluster_cmd((char *) &hostid, sizeof (hostid),
				ZFS_HBX_SYNC_POOL);
		}

		/* step 3: send the todo release pools to remote */
		if (err == 0) {
			buffer = malloc(MAX_RELEASE_POOLS_MSGSIZE);
			if (!buffer)
				err = -1;
			else {
				bufsize = MAX_RELEASE_POOLS_MSGSIZE;
				if (pack_release_pool_param_list(pool_list, 
					buffer, &bufsize) != 0) {
					syslog(LOG_ERR, "%s: pack pool_list failed", __func__);
					err = -1;
				} else
					err = hbx_do_cluster_cmd_ex(buffer, bufsize,
						ZFS_HBX_RELEASE_POOLS, r_msg->remote_id);
				free(buffer);
			}
		}
	}

	unshielding_failover_poollist(pool_list);
exit_release:
	if (pool_list != NULL) {
		for (pp = &pool_list; *pp; ) {
			node = *pp;
			if (node->ptr)
				free_release_pool_param((release_pool_param_t *) node->ptr);
			*pp = node->next;
			free(node);
		}
	}
	return (err);
}

static int
handle_release_message(cluster_mq_message_t *mq_message)
{
	release_pools_message_t r_msg;
	int i, ret;

	if (unpack_mq_release_pools_message(mq_message, &r_msg) != 0) {
		syslog(LOG_ERR, "%s: invalid message", __func__);
		return (-1);
	}
	ret = handle_release_message_common(&r_msg);
	for (i = 0; i < r_msg.pools_num; i++)
		free(r_msg.pools_list[i]);
	return (ret);
}

struct mq_message_args {
	void *buf;
	ssize_t nr;
};

static void *
handle_mq_message_thread(void *arg)
{
	struct mq_message_args *argp = (struct mq_message_args *) arg;
	cluster_mq_message_t msg;

	pthread_detach(pthread_self());
	if (argp->nr < 0 || argp->nr > sizeof(cluster_mq_message_t)) {
		free(argp->buf);
		free(argp);
		return (NULL);
	}

	memcpy(&msg, argp->buf, argp->nr);
	free(argp->buf);
	free(argp);
	if (msg.msglen < 0 || msg.msglen >= CLUSTER_MQ_MSGSIZ) {
		syslog(LOG_ERR, "Invalid message: msglen=%d", msg.msglen);
		return (NULL);
	}

	if (msg.msgtype == cluster_msgtype_release) {
		pthread_mutex_lock(&handle_release_lock);
		handle_release_message(&msg);
		pthread_mutex_unlock(&handle_release_lock);
	} else
		handle_failover_set(&msg);
	return (NULL);
}

static void
handle_mq_notify(union sigval sv)
{
	struct mq_attr attr;
	ssize_t nr;
	void *buf;
	mqd_t mqdes = *((mqd_t *) sv.sival_ptr);
	pthread_t tid;
	struct mq_message_args *arg;

	while (1) {
	 	if (mq_getattr(mqdes, &attr) == -1) {
			syslog(LOG_ERR, "mq_getattr error: %d", errno);
			break;
		}
		if (attr.mq_msgsize <= 0) {
			syslog(LOG_WARNING, "mqueue is empty now");
			break;
		}

		buf = malloc(attr.mq_msgsize);
		if (buf == NULL) {
			syslog(LOG_ERR, "alloc buf failed");
			break;
		}
	 	nr = mq_receive(mqdes, buf, attr.mq_msgsize, NULL);
		if (nr == -1) {
			syslog(LOG_ERR, "mq_receive error: %d", errno);
			free(buf);
			break;
		}

		arg = malloc(sizeof(struct mq_message_args));
		if (!arg) {
			syslog(LOG_ERR, "%s: out of memory", __func__);
			free(buf);
			break;
		}
		arg->buf = buf;
		arg->nr = nr;
		if (pthread_create(&tid, NULL, handle_mq_message_thread, arg) != 0) {
			syslog(LOG_ERR, "%s: create thread failed", __func__);
			free(buf);
			break;
		}
	}
}

static mqd_t mqd;

static int 
initialize_cluster_mqueue(void)
{
	struct mq_attr attr;
	struct sigevent sev;

	list_create(&failover_ip_list, sizeof(service_if_t),
		offsetof(service_if_t, list));
	list_create(&failover_zpool_list, sizeof(service_zpool_t),
		offsetof(service_zpool_t, list));
	pthread_mutex_init(&failover_list_lock, NULL);
	pthread_mutex_init(&handle_release_lock, NULL);
	mq_unlink(CLUSTER_MQ_NAME);
	attr.mq_flags = 0;	
	attr.mq_maxmsg = 10;    	
	attr.mq_msgsize = 1024;    	
	attr.mq_curmsgs = 0;
	mqd = mq_open(CLUSTER_MQ_NAME, O_RDONLY|O_CREAT|O_EXCL, 0644, &attr);
	if (mqd == (mqd_t) -1) {
		syslog(LOG_ERR, "mq_open %s error: %d", CLUSTER_MQ_NAME, errno);
		return (errno);
	}
	
	sev.sigev_notify = SIGEV_THREAD;
   	sev.sigev_notify_function = handle_mq_notify;
   	sev.sigev_notify_attributes = NULL;
   	sev.sigev_value.sival_ptr = &mqd;	 /* Arg. to thread func. */
   	if (mq_notify(mqd, &sev) == -1) {
		syslog(LOG_ERR, "mq_notify error: %d", errno);
		return (errno);
	}
	return (0);
}

static void
cluster_thread_exit(void)
{
	int ret;

	ret = pthread_join(cls_thread.cls_tid, NULL);
	if (ret != 0) {
		syslog(LOG_ERR, "cluster thread join failed");
	}

	if (cls_thread.running) {
		pthread_mutex_destroy(&cls_thread.cls_mutex);
		pthread_mutex_destroy(&cls_thread.cls_stat_mutex);
		pthread_cond_destroy(&cls_thread.cls_cond);
	}

	return;
}

static int
cluster_thread_create(void)
{
	int err;

	err = pthread_create(&cls_thread.cls_tid, NULL,
			cluster_thread_process, NULL);
	
	return (err);
}

static void
usage(void)
{
	syslog(LOG_ERR, "Usage: %s", MyName);
	syslog(LOG_ERR, "\t[-v]\t\tverbose error messages");
	syslog(LOG_ERR, "\t[-d]\t\tdisable daemonize");
	syslog(LOG_ERR, "\t[-S]\t\tStart clusterd daemon in systemd");
	exit(1);
}

static void
warn_hup(int i)
{
	syslog(LOG_ERR, "SIGHUP received: ignored");
	(void) signal(SIGHUP, warn_hup);
}

static int daemon_disable = 0;

static void
fix_command_path(void)
{
	char cmd[32];
	char which[] = "/usr/bin/which";
	struct stat sb;
	char *result;

	if (stat(which, &sb) == -1) {
		if (stat("/bin/which", &sb) == -1) {
			syslog(LOG_ERR, "No 'which' command");
			return;
		} else
			sprintf(which, "/bin/which");
	}

	if (stat(ip_cmd, &sb) == -1) {
		sprintf(cmd, "%s ip", which);
		if (excute_cmd_result(cmd, &result) == 0 && result != NULL) {
			if (stat(result, &sb) == 0) {
				strcpy(ip_cmd, result);
				c_log(LOG_WARNING, "ip_cmd=%s", ip_cmd);
			}
		}
		if (result)
			free(result);
	}

	if (stat(zpool_cmd, &sb) == -1) {
		sprintf(cmd, "%s zpool", which);
		if (excute_cmd_result(cmd, &result) == 0 && result != NULL) {
			if (stat(result, &sb) == 0) {
				strcpy(zpool_cmd, result);
				sprintf(zpool_import_cmd, "%s import -bfi", zpool_cmd);
				sprintf(zpool_export_cmd, "%s export -f", zpool_cmd);
				c_log(LOG_WARNING, "zpool_cmd=%s", zpool_cmd);
			}
		}
		if (result)
			free(result);
	}

	if (stat(clusterd_cmd, &sb) == -1) {
		sprintf(cmd, "%s clusterd", which);
		if (excute_cmd_result(cmd, &result) == 0 && result != NULL) {
			if (stat(result, &sb) == 0) {
				strcpy(clusterd_cmd, result);
				c_log(LOG_WARNING, "clusterd_cmd=%s", clusterd_cmd);
			}
		}
		if (result)
			free(result);
	}
}

int
main(int argc, char *argv[])
{
	int c, error;
	char *defval;
	pthread_t tid;

	/*
	 * There is no check for non-global zone and Trusted Extensions.
	 * Reparsed works in both of these environments as long as the
	 * services that use reparsed are supported.
	 */

	MyName = argv[0];
	if (geteuid() != 0) {
		syslog(LOG_ERR, "%s must be run as root", MyName);
		exit(1);
	}

	ipmi_user[0] = '\0';
	ipmi_passwd[0] = '\0';
	if ((defopen(CLUSTERD_CONF)) == 0) {
		if ((defval = defread("IPMI_LAN_INTERFACE=")) != NULL) {
			if (strncasecmp("LANPLUS", defval, 7) == 0)
				ipmi_use_lanplus = 1;
			else if (strncasecmp("LAN", defval, 3) == 0)
				ipmi_use_lanplus = 0;
		}
		if ((defval = defread("IPMI_USER=")) != NULL) {
			strlcpy(ipmi_user, defval, 16);
		}
		if ((defval = defread("IPMI_PASSWD=")) != NULL) {
			strlcpy(ipmi_passwd, defval, 16);
		}
		if ((defval = defread("LOG_LEVEL=")) != NULL) {
			errno = 0;
			clusterd_log_lvl = strtol(defval, (char **)NULL, 10);
			if (errno != 0)
				clusterd_log_lvl = 0;
		}
		if ((defval = defread("HOSTID=")) != NULL) {
			long hostid;
			errno = 0;
			hostid = strtol(defval, (char **)NULL, 10);
			if (errno != 0)
				syslog(LOG_ERR, "Invalid HOSTID=");
			else {
				if (sethostid(hostid) != 0) {
					syslog(LOG_ERR, "sethostid() failed: %s, error=%d",
						strerror(errno), errno);
				}
			}
		}
		if ((defval = defread("LINK_DOWN_TIMEOUT=")) != NULL) {
			errno = 0;
			cluster_link_down_timeout = strtol(defval, (char **)NULL, 10);
			if (errno != 0)
				syslog(LOG_ERR, "Invalid LINK_DOWN_TIMEOUT=");
		}
		if ((defval = defread("SBINDIR=")) != NULL) {
			strlcpy(sbindir, defval, MAXPATHLEN);
			sprintf(zpool_cmd, "%s/zpool", sbindir);
			sprintf(zpool_import_cmd, "%s/zpool import -bfi", sbindir);
			sprintf(zpool_export_cmd, "%s/zpool export -f", sbindir);
			sprintf(clusterd_cmd, "%s/clusterd", sbindir);
		}

		defopen(NULL);
	}

	if (ipmi_user[0] == '\0')
		strlcpy(ipmi_user, IPMI_USER_NAME, 16);
	if (ipmi_passwd[0] == '\0')
		strlcpy(ipmi_passwd, ipmi_user, 16);
	c_log(LOG_ERR, "ipmi_use_lanplus=%d, ipmi_user=%s, ipmi_passwd=%s",
		ipmi_use_lanplus, ipmi_user, ipmi_passwd);

	fix_command_path();

	while ((c = getopt(argc, argv, "dv")) != EOF) {
		switch (c) {
		case 'd':
			daemon_disable = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

	if (!daemon_disable)
		systemd_daemonize(PID_FILE);
	else
		write_pid(PID_FILE);

	host_id = get_system_hostid();

	openlog(MyName, LOG_PID | LOG_NDELAY, LOG_DAEMON);
	(void) signal(SIGHUP, warn_hup);

	init_cluster_failover_conf();
	pthread_mutex_init(&import_thr_conf.import_pools_handler_mtx, NULL);

	cluster_import_poollist_init();

	pthread_mutex_init(&cluster_import_replicas_lock, NULL);
	pthread_cond_init(&cluster_import_replicas_cv, NULL);

	init_cluster_link_down_timer();
	init_shielding_failover_poollist();

	error = initialize_cluster_mqueue();
	if (error != 0) {
		syslog(LOG_ERR, "initialize mqueue failed: %d", error);
		exit(1);
	}

	/* initialize failover handle */
	cluster_failover_handle_init();

	/* create cluster thread to process event */
	error= cluster_thread_create();
	if (error != 0){
		syslog(LOG_ERR, "clusterd create thread failed, exit");
		exit(1);
	}

	if ((error = cn_cluster_init(clusterd_cn_rcv)) != 0) {
		syslog(LOG_ERR, "cn_cluster_init() failed: error=%d", error);
		exit(1);
	}

	/* initialize mirror port */
	system(CLUSTER_SMF_INIT);

	if (pthread_create(&tid, NULL, cluster_task_setup, NULL) != 0) {
		syslog(LOG_ERR, "pthread_create(): create cluster_task_setup failed");
		exit(1);
	}

	syslog(LOG_ERR, "cluster svc start ...");
	/*
	 * Wait for incoming calls
	 */
	/*CONSTCOND*/
	while (1)
		(void) pause();

	cn_cluster_init(NULL);
	cluster_thread_exit();
	cluster_failover_handle_fini();
	return (error);
}
