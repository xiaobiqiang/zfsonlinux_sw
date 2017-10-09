#ifndef __HOST_WIRE_MONITOR_H_
#define __HOST_WIRE_MONITOR_H_

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <libdevinfo.h>
#include <libtopo.h>
#include <topo_mod.h>
#include <sys/fm/protocol.h>
#include <sys/nvpair.h>

/* #include "mptsas_method.h" */

/* #define ENABLE_LOG */

#define STRING(x) #x
#define STRINGSTRING(x) STRING(x)
#define location __FILE__ " :"STRINGSTRING(__LINE__)

#if defined(DMESG)
    #undef DMESG
#endif

#define DMESG(...) syslog(LOG_ERR | LOG_DAEMON, __VA_ARGS__)

#define HBA_MAX_RETRIES 20
#define ntohll(x) ((((unsigned long long)ntohl(x)) << 32) + (unsigned int)ntohl(x >> 32))
#define htonll(x) ((((unsigned long long)htonl(x)) << 32) + (unsigned int)htonl(x >> 32))

#define log_record(handle, ...) \
	do{ \
		if(handle){ \
			fprintf(log_file, "%s  ", location); \
			fprintf(log_file, __VA_ARGS__); \
			fflush(log_file); \
		} \
	}while(0)

#ifdef ENABLE_LOG
	#define LOG(...) log_record(log_file, __VA_ARGS__)
#else
	#define LOG(...) log_null(log_file, __VA_ARGS__)
#endif

/* conn_t's losted member value */
#define DEV_IS_EXISTED 0x00000001
#define DEV_IS_INSERTED 0x00000011
#define DEV_IS_REMOVED 0x00000100

/* all fc link status I known */
#define FC_STATE_ONLINE 0x2
#define FC_STATE_OFFLINE 0x3

/* all heart link status I known */
#define HT_STATE_UP 0x1
#define HT_STATE_DOWN 0x0
#define HT_STATE_UNKNOWN 0x2

/* all ethernet link status I known */
#define ETH_STATE_UP 0x1
#define ETH_STATE_DOWN 0x0
#define ETH_STATE_UNKNOWN 0xffffffff

/* all fc link status I known */
#define SAS_STATE_ONLINE 0x2
#define SAS_STATE_OFFLINE 0x3

#define FC_LINK "fc_link"
#define HEART_LINK "heart_link"
#define ETHERNET_LINK "ethernet_link"
#define SAS_LINK "sas_link"

#define TOPO_PGROUP_LINK_STATUS "link_status"
#define TOPO_PGROUP_ATTACHED_SMPS "attached_smps"
#define TOPO_PGROUP_ATTACHED_IPORTS "attached_iports"
#define TOPO_LINK_NAME "name"
#define TOPO_LINK_PATH "path"
#define TOPO_LINK_PHYS_PATH "phys_path"
#define TOPO_LINK_SERIALNUMBER "serialnumber"
#define TOPO_LINK_MODELNAME "modelname"
#define TOPO_LINK_MANUFACTURER "manufacturer"
#define TOPO_LINK_BASE_WWID "base_wwid"
#define TOPO_LINK_INITIATOR_PORT "initiator_port"
#define TOPO_LINK_ATTACHED_PORT "attached_port"
#define TOPO_LINK_TARGET_PORT "target_port"
#define TOPO_LINK_SMP_MAX "smp_max"
#define TOPO_LINK_IPORT_MAX "iport_max"
#define TOPO_LINK_TYPE "type"
#define TOPO_LINK_STATE "state"
#define TOPO_LINK_STATE_DESC "state_desc"
#define TOPO_LINK_LASTED_STATE "lasted_state"
#define TOPO_LINK_PRESENT "present"

#define TOPO_METH_LINK_STATUS_CHANGED "topo_link_status_changed"
#define TOPO_METH_LINK_STATUS_CHANGED_DESC "link status is changed"
#define TOPO_METH_LINK_UPDATE_STATUS "topo_link_update_status"
#define TOPO_METH_LINK_STATUS_UPDATE_DESC "link status update"
#define TOPO_METH_LINK_VERSION 0

/* for mpt_sas node register method's out_nvl parameter field. */
#define DEV_ACTION_ARRAY "devact_array"
#define DEV_PATH "devpath"
#define DEV_STATE "devstate"
#define DEV_STATE_ATTACHED 0x1
#define DEV_STATE_DETACHED 0x0
#define DEV_PATH_KEY "devpathkey"

#define XML_PATH "/usr/lib/fm/fmd/mptsas_tree.xml"
#define XML_BACKUP_PATH "/usr/lib/fm/fmd/mptsas_tree_back.xml"


#define CMDLEN 128

enum{
	FC_CONNLIST_INDEX = 0,
	ENET_CONNLIST_INDEX,
	SAS_CONNLIST_INDEX,
	HEART_CONNLIST_INDEX,
	CONNLIST_INDEX_MAX
};

struct node_ops{
	void *(*get_node_info)(di_node_t node, void *arg);
	void (*free_node_info)(void *arg);
};

typedef struct drvnode_list{

	struct drvnode_list *next;
	struct node_ops ops;
	void *data;
}drvnode_list_t;

typedef struct connection_info{

/*	struct connection_info *next; */
	topo_list_t cilist;

	char *name;
	unsigned int lasted_state;
	unsigned int state;
	int losted;		/* inserted|removed not use now */
}conn_t;

typedef struct conn_node_list{

	topo_list_t node_list;
	char *name;
	int node_n;
}conn_node_list_t;

typedef struct conn_handle{

	topo_mod_t *ch_mod;
#if 0
    kstat_ctl_t *kcp;
	di_node_t devtree;
#endif
	int ret_status;
	conn_node_list_t conn_table[CONNLIST_INDEX_MAX];

#define DN_TABLE_MPTSAS_CARD 0 /* index for mptsas_card in dn_table */
#define DN_TABLE_MPTSAS_IPORT 1 /* index for mptsas_iport in dn_table */
#define DN_TABLE_SMP 2 /* index for smp in dn_table */
#define DN_TABLE_INDEX_MAX 3 /* max member for dn_table */
	drvnode_list_t *dn_table[DN_TABLE_INDEX_MAX];
}conn_handle_t;

/* return value is not use now */
typedef int conn_list_ops(conn_node_list_t *, void *);
typedef int conn_node_ops(conn_t *, void *);

typedef struct conn_walk_ops{

	conn_list_ops *for_each_list;
	conn_node_ops *for_each_node;
	void *priv;
}conn_walk_ops_t;


typedef struct link_enum_data{

	topo_mod_t *ed_mod;
	tnode_t *ed_pnode;
	tnode_t *ed_cnode;	/* current tnode just use in mptsas_iport_node_creat */
	const char *ed_name;
	char *ed_label;
	int ed_index;
	topo_instance_t ed_instance;
}link_enum_data_t;

void log_null(FILE *file, ...);

#if 0
void conn_node_append(conn_node_list_t *list, conn_t *node);
void conn_node_insert_head(conn_node_list_t *list, conn_t *node);
void conn_node_unlink(conn_node_list_t *list, conn_t *node);
#endif

int conn_node_creat(conn_handle_t *chp, const char *type, const char *name, unsigned int state);

/* return value is not use now */
int conn_node_list_walk(conn_node_list_t *list, conn_walk_ops_t *walk);
int conn_node_table_walk(conn_node_list_t *table, conn_walk_ops_t *walk);


void link_node_free(topo_mod_t *mod, conn_t *cp);
void link_table_free(topo_mod_t *mod, conn_node_list_t *table);
int heartbeat_status(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *, nvlist_t **);
int is_linkstate_changed(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *, nvlist_t **);
int update_linknode_state(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *, nvlist_t **);
/* for log message */
FILE *log_file;

#ifdef  __cplusplus
}
#endif

#endif
