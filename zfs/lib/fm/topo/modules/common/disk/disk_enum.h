#ifndef _DISK_
#define _DISK_


#define SES_DISK "disk"


#define TOPO_PROP_STATUS	"status"
#define TOPO_PROP_STATE		"state"

#define TOPO_METH_DISK_UPDATE_STATE "topo_disk_update_status"

#define TOPO_METH_FANPUS_STATUS_UPDATE_DESC "disk status update"
#define TOPO_METH_FAN_STATUS_UPDATE_DESC "fan status update"
#define TOPO_METH_PSU_STATUS_UPDATE_DESC "psu status update"

#define TOPO_METH_DISK_VERSION 0

#define TOPO_PGROUP_DISK_STATUS "disk_status"
#define TOPO_PGROUP_ATTACHED_SMPS "attached_smps"
#define TOPO_PGROUP_ATTACHED_IPORTS "attached_iports"
#define TOPO_DISK_NAME "name"
#define TOPO_DISK_PATH "path"
#define TOPO_DISK_MODELNAME "modelname"
#define TOPO_DISK_TYPE "type"
#define TOPO_DISK_STATE "state"
#define TOPO_DISK_PRESENT	"present"
#define TOPO_DISK_STATE_DESC "state_desc"
#define TOPO_DISK_LASTED_STATE "lasted_state"


#define	FM_FMRI_SCHEME_HC		"hc"

#undef FM_HC_SCHEME_VERSION
#define FM_HC_SCHEME_VERSION	0

/* Properties added to the "storage" pgroup: */
#define	TOPO_PGROUP_STORAGE		"storage"
#define	TOPO_PGROUP_SES			"ses"
#define	TOPO_STORAGE_LOGICAL_DISK_NAME	"logical-disk"
#define	TOPO_STORAGE_MODEL		"model"
#define	TOPO_STORAGE_MANUFACTURER	"manufacturer"
#define	TOPO_STORAGE_SERIAL_NUM		"serial-number"
#define	TOPO_STORAGE_FIRMWARE_REV	"firmware-revision"
#define	TOPO_STORAGE_CAPACITY		"capacity-in-bytes"

#define TOPO_PROP_STATUS	"status"
#define TOPO_PROP_PRESENT	"present"
#define	TOPO_PROP_NODE_ID	"node-id"
#define TOPO_PROP_NODE_NUM	"node-num"
#define	TOPO_PROP_TARGET_PATH	"target-path"
#define	TOPO_PROP_SAS_ADDR	"sas-address"
#define	TOPO_PROP_PATHS		"paths"



typedef struct disk_enum_data {
	disk_table_t ded_disk;
	int			ded_errno;
	char		*ded_name;
	topo_mod_t	*ded_mod;
	topo_instance_t	ded_instance;
} disk_enum_data_t;

#endif

