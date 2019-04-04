#ifndef __MPTSAS_METHOD_H_
#define __MPTSAS_METHOD_H_

#include <libdevinfo.h>
#include "link_enum.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define SAS_DRIVER "mpt_sas"	/* mpt_sas driver name */
#define SMP_DRIVER "smp"		/* smp driver name */
#define MPTSAS_PROP_SERIALNUMBER "SerialNumber"
#define MPTSAS_PROP_MODELNAME "ModelName"
#define MPTSAS_PROP_MANUFACTURER "Manufacturer"
#define MPTSAS_PROP_BASE_WWID "base-wwid"
#define MPTSAS_PROP_INITIATOR_PORT "initiator-port"
#define MPTSAS_PROP_ATTACHED_PORT "attached-port"
#define SMP_PROP_TARGET_PORT "target-port"
#define SMP_PROP_ATTACHED_PORT "attached-port"

#define MPTSAS_CARD_IPORTS_MAX 24
#define MPTSAS_IPORT_SMPS_MAX 24

typedef struct phy_mptsas_cardinfo{

	int instance;
	char *phys_path;
	char *serialnumber;
	char *modelname;
	char *manufacturer;
	char *base_wwid;
	void *private;
}phy_mptsas_cardinfo_t;

typedef struct phy_mptsas_portinfo{

	int instance;
	char *phys_path;
	char *initiator_port;
	char *attached_port;
	void *private;
}phy_mptsas_portinfo_t;

typedef struct smp_info{

	int instance;
	char *phys_path;
	char *attached_port;
	char *target_port;
	void *private;
}smp_info_t;

void free_phy_mptsas_cardinfo(void *arg);
void *get_phy_mptsas_cardinfo(di_node_t node, void *arg);
void free_phy_mptsas_portinfo(void *arg);
void *get_phy_mptsas_portinfo(di_node_t node, void *arg);
void free_smp_info(void *arg);
void *get_smp_info(di_node_t node, void *arg);
void free_drvname_nodes(drvnode_list_t *list);
int walk_drvname_nodes(di_node_t root_node, const char *drvname,
	struct node_ops *ops, void *arg, drvnode_list_t **out);
int mptsas_iport_smp_match(const char *iport_path, const char *smp_path);
int mptsas_card_iport_match(const char *card_path, const char *iport_path);
int mptsas_smp_table_init(conn_handle_t *chp);
void mptsas_smp_table_destroy(conn_handle_t *chp);
int mptsas_iport_monitor(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl);
int mptsas_iport_smp_attach(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl);
int mptsas_iport_node_creat(phy_mptsas_portinfo_t *msip, void *arg);

int dump_mptsas_tree_xml(conn_handle_t *chp, char *xml_path);
int update_mptsas_tree_xml(conn_handle_t *chp);

#if 0
int mptsas_card_monitor(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl);
int mptsas_card_iport_attach(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl);
#endif

#ifdef __cplusplus
}
#endif

#endif
