#ifndef _FANPSU_
#define _FANPSU_

/* fanpsu_t's losted member value */
#define DEV_IS_EXISTED	0x00000001
#define DEV_IS_INSERTED	0x00000011
#define DEV_IS_REMOVED	0x00000100

#define DEV_ACTION_ARRAY "devact_array"

#define FAN_NAME "fan"
#define PSU_NAME "psu"

#define TOPO_PROP_STATUS	"status"
#define TOPO_PROP_STATE		"state"

#define TOPO_METH_FANPSU_UPDATE_STATE "topo_fanpsu_update_status"

#define TOPO_METH_FANPUS_STATUS_UPDATE_DESC "fanpsu status update"
#define TOPO_METH_FAN_STATUS_UPDATE_DESC "fan status update"
#define TOPO_METH_PSU_STATUS_UPDATE_DESC "psu status update"

#define TOPO_METH_FANPSU_VERSION 0

#define TOPO_PGROUP_FANPSU_STATUS "fanpsu_status"
#define TOPO_PGROUP_ATTACHED_SMPS "attached_smps"
#define TOPO_PGROUP_ATTACHED_IPORTS "attached_iports"
#define TOPO_FANPSU_NAME "name"
#define TOPO_FANPSU_PATH "path"
#define TOPO_FANPSU_MODELNAME "modelname"
#define TOPO_FANPSU_TYPE "type"
#define TOPO_FANPSU_STATE "state"
#define TOPO_FANPSU_PRESENT	"present"
#define TOPO_FANPSU_STATE_DESC "state_desc"
#define TOPO_FANPSU_LASTED_STATE "lasted_state"

#define FANPSU_STATE_OK 0x1 /*value refered from 'ses_element_status_string' in topo_2xml.c.*/
#define FANPSU_STATE_CR 0x2

#define FANPSU_GET_NODE 0
#define FANPSU_ITER_NODE 1

#define	FM_FMRI_SCHEME_HC		"hc"

#undef FM_HC_SCHEME_VERSION
#define FM_HC_SCHEME_VERSION	0

typedef struct fanpsu{
	topo_list_t cilist;
	char *name;
	unsigned int lasted_state;
	char state[16];
	int losted;		/* inserted|removed not use now */
}fanpsu_t;

typedef struct fanpsu_node_list{
	topo_list_t node_list;
	char *name;
	int node_n;
}fanpsu_node_list_t;

typedef struct fanpsu_handle{

	topo_mod_t *ch_mod;
	di_node_t ttree;//maybe delete
	int ret_status;
	fanpsu_node_list_t fanpsu_table[2];//fan and psu
}fanpsu_handle_t;

typedef struct fanpsu_nodeinfo{
	char name[17];
	char value[16];
}fanpsu_nodeinfo_t;


typedef struct fanpsu_enum_data{

	topo_mod_t *ed_mod;
	tnode_t *ed_pnode;
	tnode_t *ed_cnode;	/* current tnode just use in mptsas_iport_node_creat */
	const char *ed_name;
	char *ed_label;
	int ed_index;
	topo_instance_t ed_instance;
}fanpsu_enum_data_t;

typedef int fanpsu_list_ops(fanpsu_node_list_t *, void *);
typedef int fanpsu_node_ops(fanpsu_t *, void *);

typedef struct fanpsu_walk_ops{

	fanpsu_list_ops *for_each_list;
	fanpsu_node_ops *for_each_node;
	void *priv;
}fanpsu_walk_ops_t;


enum{
	FAN_LIST_INDEX = 0,
	PSU_LIST_INDEX,
};

#endif

