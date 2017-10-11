#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <fcntl.h>

#include "link_enum.h"
//#include "mptsas_method.h"

/* #define ADD_SAS_LINK */

int HBA_LoadLibrary_flag;
FILE *log_file;
#define	ETH_MAXNAMELEN	32
#define MAXLINKNAMELEN	ETH_MAXNAMELEN

extern int is_linkstate_changed(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *, nvlist_t **);
extern int heartbeat_status(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *, nvlist_t **);
extern int update_linknode_state(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *, nvlist_t **);
extern int mptsas_iport_monitor(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *, nvlist_t **);
extern int mptsas_iport_smp_attach(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *, nvlist_t **);
/*
extern int mptsas_card_monitor(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *, nvlist_t **);
extern int mptsas_card_iport_attach(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *, nvlist_t **);
*/
const topo_method_t link_methods[] = {
	{TOPO_METH_LINK_STATUS_CHANGED, TOPO_METH_LINK_STATUS_CHANGED_DESC,
		TOPO_METH_LINK_VERSION, TOPO_STABILITY_INTERNAL,
		is_linkstate_changed},
	{TOPO_METH_LINK_UPDATE_STATUS, TOPO_METH_LINK_STATUS_UPDATE_DESC,
		TOPO_METH_LINK_VERSION, TOPO_STABILITY_INTERNAL,
		update_linknode_state},
	{TOPO_METH_STATUS, TOPO_METH_LINK_STATUS_UPDATE_DESC,
		TOPO_METH_LINK_VERSION, TOPO_STABILITY_INTERNAL,
		heartbeat_status},
	{NULL}
};
#if 0
const topo_method_t mptsas_iport_methods[] = {
	{TOPO_METH_LINK_STATUS_CHANGED, TOPO_METH_LINK_STATUS_CHANGED_DESC,
		TOPO_METH_LINK_VERSION, TOPO_STABILITY_INTERNAL,
		mptsas_iport_monitor},
	{TOPO_METH_LINK_UPDATE_STATUS, TOPO_METH_LINK_STATUS_UPDATE_DESC,
		TOPO_METH_LINK_VERSION, TOPO_STABILITY_INTERNAL,
		mptsas_iport_smp_attach},
	{NULL}
};

/*
const topo_method_t mptsas_card_methods[] = {
	{TOPO_METH_LINK_STATUS_CHANGED, TOPO_METH_LINK_STATUS_CHANGED_DESC,
		TOPO_METH_LINK_VERSION, TOPO_STABILITY_INTERNAL,
		mptsas_card_monitor},
	{TOPO_METH_LINK_UPDATE_STATUS, TOPO_METH_LINK_STATUS_UPDATE_DESC,
		TOPO_METH_LINK_VERSION, TOPO_STABILITY_INTERNAL,
		mptsas_card_iport_attach},
	{NULL}
};
*/
const topo_method_t mptsas_card_methods[1];

/* for debug *//*{{{*/
#ifdef LHL_DBG
struct conn_walk_ops conn_walk;

int get_node_state(conn_t *cp, void *file){

	FILE *dump_file = file ? file : stderr;

	if(cp->losted == DEV_IS_INSERTED)
		fprintf(dump_file, "\tDev_Inserted ==> Name ## %-10s ## State ## %u\n", cp->name, cp->state);
	else if(cp->losted == DEV_IS_REMOVED)
		fprintf(dump_file, "\tDev_Removed ==> Name ## %-10s ##\n", cp->name);
	else{
		if(cp->state != cp->lasted_state)
			fprintf(dump_file, "\tDev_State Changed ==> Name ## %-10s ## State ## %u\n", cp->name, cp->state);
	}

	cp->lasted_state = cp->state;
	cp->losted = DEV_IS_REMOVED;

	return 0;
}
#endif/*}}}*/
#endif
static int add_facility_group(topo_mod_t *mod, tnode_t *tn, int type, int status){

	topo_pgroup_info_t pgi;
	int err;
	nvlist_t *nvl;

    pgi.tpi_name = "facility";
    pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_version = TOPO_VERSION;
    if(topo_pgroup_create(tn, &pgi, &err) != 0){
        if(err != ETOPO_PROP_DEFD){
            topo_mod_dprintf(mod, "failed to create propgroup %s: %s\n", "facility", topo_strerror(err));
            return -1;
        }
    }

	
	nvl = NULL;
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ) {
		topo_mod_dprintf(mod, "nvalloc failed\n");
		return (topo_mod_seterrno(mod, ETOPO_PROP_NOMEM));
	}

	if(type == HEART_CONNLIST_INDEX) {
		if (topo_prop_method_register(tn, TOPO_PGROUP_FACILITY,
			"status", TOPO_TYPE_UINT64, TOPO_METH_STATUS,
			nvl, &err) != 0 ||
			topo_prop_set_uint32(tn, TOPO_PGROUP_LINK_STATUS,
			"present", TOPO_PROP_MUTABLE, 1, &err)) {
				topo_mod_dprintf(mod, "failed to register state method: %s\n",
					topo_strerror(err));
				nvlist_free(nvl);
				return (topo_mod_seterrno(mod, err));
		}

	} else {
		if(topo_prop_set_uint32(tn, TOPO_PGROUP_LINK_STATUS, "status", TOPO_PROP_MUTABLE, status, &err) ||
			topo_prop_set_uint32(tn, TOPO_PGROUP_LINK_STATUS, "present", TOPO_PROP_MUTABLE, 1, &err)){
			topo_mod_dprintf(mod, "add_facility_group: set link name error %s\n", topo_strerror(err));
			nvlist_free(nvl);
			return (topo_mod_seterrno(mod, err));

		}
	}
	nvlist_free(nvl);
	return 0;
}

static int link_node_creat(conn_t *cp, void *arg){/*{{{*/

	link_enum_data_t *data = arg;
	nvlist_t *auth, *fmri;
	tnode_t *pnode = data->ed_pnode;
	topo_mod_t *mod = data->ed_mod;
	tnode_t *tn;
	int err, len;
	topo_pgroup_info_t pgi;
	char label[64], *labelname = NULL;
	int status = 0;

	if((auth = topo_mod_auth(mod, pnode)) == NULL){
		topo_mod_dprintf(mod, "topo_mod_auth() failed: %s", topo_mod_errmsg(mod));
		return -1;
	}
	if((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION, data->ed_name,
					data->ed_instance, NULL, auth, NULL, NULL, NULL)) == NULL){
		nvlist_free(auth);
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s", topo_mod_errmsg(mod));
		LOG("topo_mod_hcfmri() failed: %s", topo_mod_errmsg(mod));
		return -1;
	}
	nvlist_free(auth);

	if((tn = topo_node_bind(mod, pnode, data->ed_name, data->ed_instance, fmri)) == NULL){
		nvlist_free(fmri);
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s", topo_mod_errmsg(mod));
		return -1;
	}

    if(data->ed_label != NULL)
        snprintf(label, sizeof (label), "%s ", data->ed_label);
    else
        label[0] = '\0';

    switch(data->ed_index){
		case FC_CONNLIST_INDEX:
			labelname = "FC";
			status = cp->state == FC_STATE_ONLINE ? SXML_ONLINE : SXML_OFFLINE;
			break;

		case ENET_CONNLIST_INDEX:
			labelname = "ETHERNET";
			status = cp->state == ETH_STATE_UP ? SXML_UP : SXML_DOWN;
			break;

		case SAS_CONNLIST_INDEX:		/* not use now */
			labelname = "SAS";
			break;
		case HEART_CONNLIST_INDEX:
			labelname = "HEART";
			break;
	}

    len = strlen(label);
    snprintf(label + len, sizeof (label) - len, "%s %d", labelname, data->ed_instance);
    if(topo_node_label_set(tn, label, &err) != 0){
        topo_mod_dprintf(mod, "failed to set label: %s\n", topo_strerror(err));
        return -1;
    }

	data->ed_instance++;
	nvlist_free(fmri);

    pgi.tpi_name = TOPO_PGROUP_LINK_STATUS;
    pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_version = TOPO_VERSION;
    if(topo_pgroup_create(tn, &pgi, &err) != 0){
        if(err != ETOPO_PROP_DEFD){
            topo_mod_dprintf(mod, "failed to create propgroup " "%s: %s\n", TOPO_PGROUP_LINK_STATUS, topo_strerror(err));
            return -1;
        }
    }

	if(topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_NAME, TOPO_PROP_MUTABLE, cp->name, &err) ||
		topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_TYPE, TOPO_PROP_MUTABLE, data->ed_name, &err) ||
		topo_prop_set_uint32(tn, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_STATE, TOPO_PROP_MUTABLE, cp->state, &err) ||
		topo_prop_set_uint32(tn, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_PRESENT, TOPO_PROP_MUTABLE, 1, &err)){

		topo_mod_dprintf(mod, "link_set_props: " "set link name error %s\n", topo_strerror(err));
		return -1;
	}
    if(topo_method_register(mod, tn, link_methods) != 0){
        topo_mod_dprintf(mod, "topo_method_register() failed: %s", topo_mod_errmsg(mod));
        return -1;
    }

	add_facility_group(mod, tn, data->ed_index, status);

	return 0;
}/*}}}*/
#if 0
#if 0
/*
 * we reserve all smps which attached iport. use it to determine
 * whether the sas_iport is filled. if sas_iport is filled we
 * must compare if it is changed(remove and insert a new one).
 */
int mptsas_iport_set_smps(phy_mptsas_portinfo_t *msip, void *arg, tnode_t *tn){/*{{{*/

	link_enum_data_t *data = arg;
	topo_mod_t *mod = data->ed_mod;
	conn_handle_t *chp = topo_mod_getspecific(mod);
	topo_pgroup_info_t pgi;
	drvnode_list_t *dlp;
	smp_info_t *sip;
	int count = 0, max = 0;
	int err;
	int status;
	char ch[24];

    pgi.tpi_name = TOPO_PGROUP_ATTACHED_SMPS;
    pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_version = TOPO_VERSION;
    if(topo_pgroup_create(tn, &pgi, &err) != 0){
        if(err != ETOPO_PROP_DEFD){
            topo_mod_dprintf(mod, "failed to create propgroup " "%s: %s\n", TOPO_PGROUP_IPMI, topo_strerror(err));
            return -1;
        }
    }

	for(dlp = chp->dn_table[DN_TABLE_SMP]; dlp; dlp = dlp->next){
		sip = (smp_info_t *)dlp->data;
		if(mptsas_iport_smp_match(msip->phys_path, sip->phys_path)){
			sprintf(ch, "%s%d", TOPO_LINK_PHYS_PATH, count);
			if((sip->phys_path && topo_prop_set_string(tn, TOPO_PGROUP_ATTACHED_SMPS,
					ch, TOPO_PROP_MUTABLE, sip->phys_path, &err))){
				topo_mod_dprintf(mod, "link_set_props: set link name error %s\n", topo_strerror(err));
				return -1;
			}
			count++;
		}
	}
	if(count > max)
		max = count;
	if(topo_prop_set_uint32(tn, TOPO_PGROUP_ATTACHED_SMPS, TOPO_LINK_SMP_MAX, TOPO_PROP_MUTABLE, max, &err)){
		topo_mod_dprintf(mod, "link_set_props: set link name error %s\n", topo_strerror(err));
		return -1;
	}

	if(count)
		status = SXML_ONLINE;
	else
		status = SXML_OFFLINE;
	add_facility_group(mod, tn, 1, status);

	return 0;
}/*}}}*/

int mptsas_iport_node_creat(phy_mptsas_portinfo_t *msip, void *arg){/*{{{*/

	link_enum_data_t *data = arg;
	nvlist_t *auth, *fmri;
	tnode_t *cnode = data->ed_cnode;
	topo_mod_t *mod = data->ed_mod;
	conn_handle_t *chp = topo_mod_getspecific(mod);
	tnode_t *tn;
	int err, len;
	topo_pgroup_info_t pgi;
	char label[64], *labelname;
	char name[24];

	if((auth = topo_mod_auth(mod, cnode)) == NULL){
		topo_mod_dprintf(mod, "topo_mod_auth() failed: %s", topo_mod_errmsg(mod));
		return -1;
	}
	if((fmri = topo_mod_hcfmri(mod, cnode, FM_HC_SCHEME_VERSION, "sas_iport",
					msip->instance, NULL, auth, NULL, NULL, NULL)) == NULL){
		nvlist_free(auth);
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s", topo_mod_errmsg(mod));
		return -1;
	}
	nvlist_free(auth);
	if((tn = topo_node_bind(mod, cnode, "sas_iport", msip->instance, fmri)) == NULL){
		nvlist_free(fmri);
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s", topo_mod_errmsg(mod));
		return -1;
	}

    if(data->ed_label != NULL)
        snprintf(label, sizeof (label), "%s ", data->ed_label);
    else
        label[0] = '\0';

    switch(data->ed_index){
		case FC_CONNLIST_INDEX:
			labelname = "FC";
			break;

		case ENET_CONNLIST_INDEX:
			labelname = "ETHERNET";
			break;

		case SAS_CONNLIST_INDEX:		/* not use now */
			labelname = "SAS HBA";
			break;
	}

    len = strlen(label);
    snprintf(label + len, sizeof (label) - len, "%s %d", labelname, msip->instance);
    if(topo_node_label_set(tn, label, &err) != 0){
        topo_mod_dprintf(mod, "failed to set label: %s\n", topo_strerror(err));
        return -1;
    }

	nvlist_free(fmri);

    pgi.tpi_name = TOPO_PGROUP_LINK_STATUS;
    pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_version = TOPO_VERSION;
    if(topo_pgroup_create(tn, &pgi, &err) != 0){
        if(err != ETOPO_PROP_DEFD){
            topo_mod_dprintf(mod, "failed to create propgroup " "%s: %s\n", TOPO_PGROUP_IPMI, topo_strerror(err));
            return -1;
        }
    }

	sprintf(name, "%s%d", "mpt_sas",  msip->instance);
	if(topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_NAME, TOPO_PROP_MUTABLE, name, &err) ||
		topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_TYPE, TOPO_PROP_MUTABLE, data->ed_name, &err) ||
		(msip->phys_path && topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS,
			TOPO_LINK_PHYS_PATH, TOPO_PROP_MUTABLE, msip->phys_path, &err)) ||
		(msip->initiator_port && topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS,
			TOPO_LINK_INITIATOR_PORT, TOPO_PROP_MUTABLE, msip->initiator_port, &err)) ||
		(msip->attached_port && topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS,
			TOPO_LINK_ATTACHED_PORT, TOPO_PROP_MUTABLE, msip->attached_port, &err))){

		topo_mod_dprintf(mod, "link_set_props: " "set link name error %s\n", topo_strerror(err));
		return -1;
	}

#if 1
    if(topo_method_register(mod, tn, mptsas_iport_methods) != 0) {
        topo_mod_dprintf(mod, "topo_method_register() failed: %s", topo_mod_errmsg(mod));
        return -1;
    }
#endif
	if(mptsas_iport_set_smps(msip, arg, tn)){
		LOG("failed to run mptsas_iport_set_smps.\n");
		return -1;
	}

	return 0;
}/*}}}*/
#endif

int mptsas_card_enumerate_iport(phy_mptsas_cardinfo_t *mscp, void *arg){/*{{{*/

	link_enum_data_t *data = arg;
	topo_mod_t *mod = data->ed_mod;
	conn_handle_t *chp = topo_mod_getspecific(mod);
	topo_pgroup_info_t pgi;
	tnode_t *tn = data->ed_cnode;
	drvnode_list_t *dlp;
	phy_mptsas_portinfo_t *msip;
	int count = 0, max = 0;
	int err;
	char ch[24];

	if(topo_node_range_create(mod, tn, "sas_iport", 0, 24) < 0){
		topo_mod_dprintf(mod, "mptsas_card_node_creat enumeration failed to create iport range [0-4].\n");
		return -1; /* mod_errno set */
	}

    pgi.tpi_name = TOPO_PGROUP_ATTACHED_IPORTS;
    pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_version = TOPO_VERSION;
    if(topo_pgroup_create(tn, &pgi, &err) != 0){
        if(err != ETOPO_PROP_DEFD){
            topo_mod_dprintf(mod, "failed to create propgroup " "%s: %s\n", TOPO_PGROUP_IPMI, topo_strerror(err));
            return -1;
        }
    }

	for(dlp = chp->dn_table[DN_TABLE_MPTSAS_IPORT]; dlp; dlp = dlp->next){
		msip = (phy_mptsas_portinfo_t *)dlp->data;
		if(mptsas_card_iport_match(mscp->phys_path, msip->phys_path)){
			sprintf(ch, "%s%d", TOPO_LINK_PHYS_PATH, count);
			if((msip->phys_path && topo_prop_set_string(tn, TOPO_PGROUP_ATTACHED_IPORTS,
					ch, TOPO_PROP_MUTABLE, msip->phys_path, &err))){
				topo_mod_dprintf(mod, "link_set_props: set link name error %s\n", topo_strerror(err));
				return -1;
			}
			count++;

			mptsas_iport_node_creat(msip, arg);
		}
	}

	if(count > max)
		max = count;
	if(topo_prop_set_uint32(tn, TOPO_PGROUP_ATTACHED_IPORTS, TOPO_LINK_IPORT_MAX, TOPO_PROP_MUTABLE, max, &err)){
		topo_mod_dprintf(mod, "link_set_props: set link name error %s\n", topo_strerror(err));
		return -1;
	}

	return 0;
}/*}}}*/

int mptsas_card_node_creat(phy_mptsas_cardinfo_t *mscp, void *arg){/*{{{*/

	link_enum_data_t *data = arg;
	nvlist_t *auth, *fmri;
	tnode_t *pnode = data->ed_pnode;
	topo_mod_t *mod = data->ed_mod;
//	conn_handle_t *chp = topo_mod_getspecific(mod);
	tnode_t *tn;
	int err, len;
	topo_pgroup_info_t pgi;
	char label[64], *labelname = NULL;
	char name[24];

	if((auth = topo_mod_auth(mod, pnode)) == NULL){
		topo_mod_dprintf(mod, "topo_mod_auth() failed: %s", topo_mod_errmsg(mod));
		return -1;
	}
	if((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION, data->ed_name,
					mscp->instance, NULL, auth, NULL, NULL, NULL)) == NULL){
		nvlist_free(auth);
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s", topo_mod_errmsg(mod));
		return -1;
	}
	nvlist_free(auth);
	if((tn = topo_node_bind(mod, pnode, data->ed_name, mscp->instance, fmri)) == NULL){
		nvlist_free(fmri);
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s", topo_mod_errmsg(mod));
		return -1;
	}

	/* init value data->ed_cnode for make child iport node for mptsas card(sas_link) */
	data->ed_cnode = tn;

    if(data->ed_label != NULL)
        snprintf(label, sizeof (label), "%s ", data->ed_label);
    else
        label[0] = '\0';

    switch(data->ed_index){
		case FC_CONNLIST_INDEX:
			labelname = "FC";
			break;

		case ENET_CONNLIST_INDEX:
			labelname = "ETHERNET";
			break;

		case SAS_CONNLIST_INDEX:		/* not use now */
			labelname = "SAS HBA";
			break;
	}

    len = strlen(label);
    snprintf(label + len, sizeof (label) - len, "%s %d", labelname, mscp->instance);
    if(topo_node_label_set(tn, label, &err) != 0){
        topo_mod_dprintf(mod, "failed to set label: %s\n", topo_strerror(err));
        return -1;
    }

	nvlist_free(fmri);

    pgi.tpi_name = TOPO_PGROUP_LINK_STATUS;
    pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
    pgi.tpi_version = TOPO_VERSION;
    if(topo_pgroup_create(tn, &pgi, &err) != 0){
        if(err != ETOPO_PROP_DEFD){
            topo_mod_dprintf(mod, "failed to create propgroup " "%s: %s\n", TOPO_PGROUP_IPMI, topo_strerror(err));
            return -1;
        }
    }

	sprintf(name, "%s%d", "mpt_sas",  mscp->instance);
	if(topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_NAME, TOPO_PROP_MUTABLE, name, &err) ||
		topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_TYPE, TOPO_PROP_MUTABLE, data->ed_name, &err) ||
		(mscp->phys_path && topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS,
			TOPO_LINK_PHYS_PATH, TOPO_PROP_MUTABLE, mscp->phys_path, &err)) ||
		(mscp->serialnumber && topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS,
			TOPO_LINK_SERIALNUMBER, TOPO_PROP_MUTABLE, mscp->serialnumber, &err)) ||
		(mscp->modelname && topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS,
			TOPO_LINK_MODELNAME, TOPO_PROP_MUTABLE, mscp->modelname, &err)) ||
		(mscp->manufacturer && topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS,
			TOPO_LINK_MANUFACTURER, TOPO_PROP_MUTABLE, mscp->manufacturer, &err)) ||
		(mscp->base_wwid && topo_prop_set_string(tn, TOPO_PGROUP_LINK_STATUS,
			TOPO_LINK_BASE_WWID, TOPO_PROP_MUTABLE, mscp->base_wwid, &err))){

		topo_mod_dprintf(mod, "link_set_props: " "set link name error %s\n", topo_strerror(err));
		return -1;
	}
#if 1
    if(topo_method_register(mod, tn, mptsas_card_methods) != 0){
        topo_mod_dprintf(mod, "topo_method_register() failed: %s", topo_mod_errmsg(mod));
        return -1;
    }
#endif
	if(mptsas_card_enumerate_iport(mscp, arg)){
		LOG("failed run mptsas_card_enumerate_iport\n");
		return -1;
	}

	return 0;
}/*}}}*/
#endif

void log_null(FILE *file, ...){}

static int link_enum(topo_mod_t *mod, tnode_t *conn_node, const char *name,
		topo_instance_t min, topo_instance_t max, void *arg, void *unused){/*{{{*/
	int index;
	conn_handle_t *chp = topo_mod_getspecific(mod);
	struct conn_walk_ops conn_walk;
	link_enum_data_t data;
	if(!strcmp(name, FC_LINK))
		index = FC_CONNLIST_INDEX;
	else if(!strcmp(name, ETHERNET_LINK))
		index = ENET_CONNLIST_INDEX;
	else if(!strcmp(name, SAS_LINK))      /* not use now */
		index = SAS_CONNLIST_INDEX;
	else if(!strcmp(name, HEART_LINK))
		index = HEART_CONNLIST_INDEX;
	else{
		LOG("conn_node_creat error type.\n");
		return -1;
	}

	/* init enum structure that useful in creat tnode */
	data.ed_mod = mod;
	data.ed_pnode = conn_node;
	data.ed_name = name;
	data.ed_index = index;
	data.ed_label = NULL;
	data.ed_instance = 0;

	/* for FC_LINK ETHERNET_LINK and HEART_LINK topo_node create */
	if(index != SAS_CONNLIST_INDEX){

		bzero(&conn_walk, sizeof(struct conn_walk_ops));
		conn_walk.for_each_node = link_node_creat;
		conn_walk.priv = &data;

		conn_node_list_walk((chp->conn_table + index), &conn_walk);
	}
#ifdef ADD_SAS_LINK
	else{
		/* for SAS_LINK topo_node create */
		DMESG("LHL ADD ++ Should update SAS topo XML File.\n");
		drvnode_list_t *dlp;
		phy_mptsas_cardinfo_t *mscp;

		update_mptsas_tree_xml(chp);
		for(dlp = chp->dn_table[DN_TABLE_MPTSAS_CARD]; dlp; dlp = dlp->next){
			mscp = (phy_mptsas_cardinfo_t *)dlp->data;
			mptsas_card_node_creat(mscp, &data);
		}
	}
#endif

	return 0;
}/*}}}*/
const topo_modops_t link_ops = {link_enum, NULL};

const topo_modinfo_t link_info =
{"ceresdata add hostwire monitor module", FM_FMRI_SCHEME_HC, TOPO_VERSION, &link_ops};

#if 0
int hbaport_node_creat(conn_handle_t *chp, HBA_PORTATTRIBUTES *port_p){/*{{{*/

	uint64_t kk;
	char WWN[32];

	memcpy(&kk, port_p->PortWWN.wwn, sizeof(uint64_t));

	sprintf(WWN, "%016llx", ntohll(kk));

	if(conn_node_creat(chp, "fc_link", WWN, port_p->PortState) == -1){
		LOG("hbaport_node_creat conn_node_creat error.\n");
		return -1;
	}

	return 0;
}/*}}}*/

int hbaport_walk(conn_handle_t *chp){/*{{{*/

	int numAdapters = 0, numTgtAdapters = 0, i;
	HBA_STATUS status;
	char adapterName[256];
	HBA_HANDLE handle;
	uint64_t hbaWWN;
	HBA_WWN myWWN;
	HBA_PORTATTRIBUTES port;
	HBA_ADAPTERATTRIBUTES attrs;
	int portIndex = 0, times;

	numAdapters = HBA_GetNumberOfAdapters();

	for(i = 0; i < numAdapters; i++){

		times = 0;
		if(HBA_GetAdapterName(i, adapterName) != HBA_STATUS_OK){
			LOG("failed to get adapter %d.\n", i);
			continue;
		}
		if((handle = HBA_OpenAdapter(adapterName)) == 0){
			LOG("failed to open adapter %s.\n", adapterName);
			continue;
		}

		memset(&attrs, 0, sizeof (attrs));
		status = Sun_HBA_NPIVGetAdapterAttributes(handle, &attrs);
		while((status == HBA_STATUS_ERROR_TRY_AGAIN ||
					status == HBA_STATUS_ERROR_BUSY) && times++ < HBA_MAX_RETRIES){

			(void) sleep(1);
			if((status = Sun_HBA_NPIVGetAdapterAttributes(handle, &attrs)) == HBA_STATUS_OK)
				break;
		}
		if(status != HBA_STATUS_OK){
			LOG("failed to get adapter attributes handle %d.\n", handle);
			HBA_CloseAdapter(handle);
			continue;
		}

		for(portIndex = 0; portIndex < attrs.NumberOfPorts; portIndex++){
			memset(&port, 0, sizeof (port));
			if(HBA_GetAdapterPortAttributes(handle, portIndex, &port) != HBA_STATUS_OK){
				LOG("failed to get port %d attributes.\n", portIndex);
				continue;
			}

			chp->ret_status |= hbaport_node_creat(chp, &port);
		}
		HBA_CloseAdapter(handle);
	}

	numTgtAdapters = Sun_HBA_GetNumberOfTgtAdapters();
	for(i = 0; i < numTgtAdapters; i++){

		if(Sun_HBA_GetTgtAdapterName(i, adapterName) != HBA_STATUS_OK){
			LOG("failed to get adapter %d.\n", i);
			continue;
		}
		if((handle = Sun_HBA_OpenTgtAdapter(adapterName)) == 0){
			LOG("failed to open adapter %s.\n", adapterName);
			continue;
		}
		memset(&attrs, 0, sizeof (attrs));
		if(HBA_GetAdapterAttributes(handle, &attrs) != HBA_STATUS_OK){
			LOG("failed to get target mode adapter attributes handle %d.\n", handle);
			continue;
		}

		for(portIndex = 0; portIndex < attrs.NumberOfPorts; portIndex++){
			memset(&port, 0, sizeof (port));
			if(HBA_GetAdapterPortAttributes(handle, portIndex, &port) != HBA_STATUS_OK){
				LOG("failed to get port %d attributes.\n", portIndex);
				continue;
			}
			chp->ret_status |= hbaport_node_creat(chp, &port);
		}
		HBA_CloseAdapter(handle);
	}

	return (0);
}/*}}}*/
#endif

int heartbeat_walk(conn_handle_t *chp){
	if(conn_node_creat(chp, "heart_link", "heart", HT_STATE_UP) == -1){
		LOG("heartbeat_walk conn_node_creat error.\n");
		chp->ret_status =  -1;
	}
	return 0;
}
int ethernet_link_walk(conn_handle_t *chp){/*{{{*/
	FILE *fp1, *fp2;
	char linkname[CMDLEN];
	char state[CMDLEN];
	char cmd[CMDLEN];
	unsigned int status;
	
	fp1 = popen("ip link show | grep state|cut -d ':' -f 2|sed 's/[[:space:]]//g'", "r");
	while(fgets(linkname, CMDLEN, fp1)){
		linkname[strlen(linkname)-1] = 0;
		sprintf(cmd, "ethtool %s|grep Link|cut -d ':' -f 2|sed 's/[[:space:]]//g'", linkname);
		fp2 = popen(cmd, "r");
		fgets(state, CMDLEN, fp2);
		state[strlen(state)-1] = 0;
		#if 0
		printf("%s: %s\n", linkname, state);
		#endif
		pclose(fp2);

		if(!strncmp("yes", state, 3)){
			status = ETH_STATE_UP;
		}else if(!strncmp("no", state, 2)){
			status = ETH_STATE_DOWN;
		}else{
			status = ETH_STATE_UNKNOWN;
		}

		chp->ret_status |= conn_node_creat(chp, "ethernet_link", linkname, status);
	}

	pclose(fp1);

	return (0);
}

#if 0
int get_link(dladm_handle_t dh, datalink_id_t linkid, void *arg){/*{{{*/
	char link[MAXLINKNAMELEN];
	kstat_named_t *knp;
	kstat_t *ksp;
	conn_handle_t *chp = arg;
	kstat_ctl_t *kcp = chp->kcp;

	if(dladm_datalink_id2info(chp->dh, linkid, NULL, NULL, NULL, link, sizeof(link)) != DLADM_STATUS_OK){
		LOG("dladm_datalink_id2info failed.\n");
		return -1;
	}

	if((ksp = kstat_lookup(kcp, "link", 0, link)) == NULL ||
			kstat_read(kcp, ksp, NULL) == -1 ||
			(knp = kstat_data_lookup(ksp, "link_state")) == NULL){
		LOG("kstat_lookup failed.\n");
		return -1;
	}

	if(conn_node_creat(chp, "ethernet_link", link, knp->value.ui32) == -1){
		LOG("get_link conn_node_creat error.\n");
		return -1;
	}
	return 0;
}/*}}}*/

static int show_link(dladm_handle_t dh, datalink_id_t linkid, void *arg){/*{{{*/
	conn_handle_t *chp = arg;

	chp->ret_status |= get_link(dh, linkid, chp);

	return DLADM_WALK_CONTINUE;
}/*}}}*/
#endif

int
heartbeat_list_gather(conn_handle_t *chp) {

	heartbeat_walk(chp);

	return chp->ret_status;
}

int fcport_list_gather(conn_handle_t *chp){/*{{{*/

	//hbaport_walk(chp);

	return chp->ret_status;
}/*}}}*/

int ethernet_list_gather(conn_handle_t *chp){/*{{{*/

	ethernet_link_walk(chp);

	return chp->ret_status;
}/*}}}*/

int _topo_init(topo_mod_t *mod, topo_version_t version){/*{{{*/
	conn_handle_t *conn_hdl;

	if(topo_mod_register(mod, &link_info, TOPO_VERSION) != 0){

		topo_mod_dprintf(mod, "%s registration failed: %s\n",
				"link", topo_mod_errmsg(mod));
		return -1;
	}

	if(!(log_file = fopen("/var/log/wire_monitor.log", "w"))){
		DMESG("open log file /var/log/wire_monitor.log Error\n");
		goto Err;
	}

	if(!(conn_hdl = topo_mod_zalloc(mod, sizeof(conn_handle_t)))){
		LOG("calloc handle failed.\n");
		goto Err;
	}

	/* just for alloc memory */
	conn_hdl->ch_mod = mod;
#ifdef ADD_SAS_LINK
	conn_hdl->devtree = topo_mod_devinfo(mod);
	DMESG("LHL ADD ++ link_topo_init %p   %p \n", mod, conn_hdl->devtree);
#endif
#if ADD_FC_LINK
	fcport_list_gather(conn_hdl);
#endif

	heartbeat_list_gather(conn_hdl);
	ethernet_list_gather(conn_hdl);

#ifdef ADD_SAS_LINK
	if(mptsas_smp_table_init(conn_hdl)){
		LOG("mptsas_smp_table_init get mptsas info failed.\n");
		kstat_close(conn_hdl->kcp);
		goto Err;
	}
#endif

	topo_mod_setspecific(mod, conn_hdl);
	topo_mod_dprintf(mod, "LINK enumerator initialized\n");

	return 0;

	Err:
		if(conn_hdl)
			free(conn_hdl);
		topo_mod_unregister(mod);

		fclose(log_file);
		return -1;

}/*}}}*/

void _topo_fini(topo_mod_t *mod){/*{{{*/

	conn_handle_t *chp = topo_mod_getspecific(mod);

	DMESG("LHL ADD ++ link_topo_fini %p   \n", mod);
#ifdef ADD_SAS_LINK
	mptsas_smp_table_destroy(chp);
#endif
	link_table_free(mod, chp->conn_table);
//	kstat_close(chp->kcp);
	fclose(log_file);
	topo_mod_free(mod, chp, sizeof(conn_handle_t));

	topo_mod_dprintf(mod, "LINK enumerator initialized\n");
	topo_mod_unregister(mod);
}/*}}}*/
