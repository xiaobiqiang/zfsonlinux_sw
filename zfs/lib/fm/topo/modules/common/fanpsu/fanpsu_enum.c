#include <stdio.h>
#include <syslog.h>
#include <ipmitool/ipmi.h>
#include <ipmitool/ipmi_sel.h>
#include <libipmi.h>
#include <topo_module.h>
#include <topo_mod.h>

#include "fanpsu_enum.h"


extern  struct ipmi_intf ipmi_open_intf;

static int fanpsu_enum(topo_mod_t *mod, tnode_t *t_node, const char *name,
		topo_instance_t min, topo_instance_t max, void *arg, void *unused);
static int fanpsu_status(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers,
	nvlist_t *in, nvlist_t **out);
static int get_fanpsu_status_by_name(fanpsu_handle_t *chp, const char *name, char *state);

const topo_modops_t fanpsu_ops = {fanpsu_enum, NULL};
const topo_modinfo_t fanpsu_info =
		{"ceresdata add fan and psu state monitor module", FM_FMRI_SCHEME_HC, TOPO_VERSION, &fanpsu_ops};

const topo_method_t fanpsu_methods[] = {
		{TOPO_METH_STATUS, TOPO_METH_FANPSU_UPDATE_STATE,
		TOPO_METH_FANPSU_VERSION, TOPO_STABILITY_INTERNAL,
		fanpsu_status},
		{NULL}
};

static int
add_facility_group(topo_mod_t *mod, tnode_t *tn, int type, int status){
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

	if(topo_prop_set_uint32(tn, TOPO_PGROUP_FANPSU_STATUS, "status", TOPO_PROP_MUTABLE, status, &err) ||
	topo_prop_set_uint32(tn, TOPO_PGROUP_FANPSU_STATUS, "present", TOPO_PROP_MUTABLE, 1, &err)){
		topo_mod_dprintf(mod, "add_facility_group: set link name error %s\n", topo_strerror(err));
		nvlist_free(nvl);

		return (topo_mod_seterrno(mod, err));
	}
	nvlist_free(nvl);

	return 0;
	}


static int
fanpsu_node_create(fanpsu_t *cp, void *arg){
	fanpsu_enum_data_t *data = arg;
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
		case FAN_LIST_INDEX:
			labelname = "FAN";
			break;

		case PSU_LIST_INDEX:
			labelname = "PSU";
			break;
	}

	status = strcmp(cp->state, "ok") ? FANPSU_STATE_OK : FANPSU_STATE_NO;

    len = strlen(label);
    snprintf(label + len, sizeof (label) - len, "%s %d", labelname, data->ed_instance);
    if(topo_node_label_set(tn, label, &err) != 0){
        topo_mod_dprintf(mod, "failed to set label: %s\n", topo_strerror(err));
        return -1;
    }

	data->ed_instance++;
	nvlist_free(fmri);

	pgi.tpi_name = TOPO_PGROUP_FANPSU_STATUS;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = TOPO_VERSION;
	if(topo_pgroup_create(tn, &pgi, &err) != 0){
		if(err != ETOPO_PROP_DEFD){
			topo_mod_dprintf(mod, "failed to create propgroup " "%s: %s\n", TOPO_PGROUP_FANPSU_STATUS, topo_strerror(err));
			return -1;
		}
	}

	if(topo_prop_set_string(tn, TOPO_PGROUP_FANPSU_STATUS, TOPO_FANPSU_NAME, TOPO_PROP_MUTABLE, cp->name, &err)
		||topo_prop_set_string(tn, TOPO_PGROUP_FANPSU_STATUS, TOPO_FANPSU_TYPE, TOPO_PROP_MUTABLE, data->ed_name, &err)
		||topo_prop_set_string(tn, TOPO_PGROUP_FANPSU_STATUS, TOPO_FANPSU_STATE, TOPO_PROP_MUTABLE, cp->state, &err)
		||topo_prop_set_uint32(tn, TOPO_PGROUP_FANPSU_STATUS, TOPO_FANPSU_PRESENT, TOPO_PROP_MUTABLE, 1, &err)){

		topo_mod_dprintf(mod, "link_set_props: " "set link name error %s\n", topo_strerror(err));
		return -1;
	}
	if(topo_method_register(mod, tn, fanpsu_methods) != 0){
		topo_mod_dprintf(mod, "topo_method_register() failed: %s", topo_mod_errmsg(mod));
		return -1;
	}

	add_facility_group(mod, tn, data->ed_index, status);

	return 0;
}
static int
fanpsu_node_list_walk(fanpsu_node_list_t *list, fanpsu_walk_ops_t *walk){
	fanpsu_t *cp;

	if(!(list && walk)){
		printf("conn_node_list_dump the list or walk have been fucked\n");
		return -1;
	}

	if(walk->for_each_list)
		walk->for_each_list(list, walk->priv);
	if(walk->for_each_node)
		for(cp = topo_list_next(&list->node_list); cp; cp = topo_list_next(cp))
			walk->for_each_node(cp, walk->priv);

	return 0;
}

static int fanpsu_status(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers,
	nvlist_t *in, nvlist_t **out){
	nvlist_t *nvl;
	fanpsu_handle_t * chp;
	char state[2];
	char *nodename = NULL;
	int err;

	if(topo_prop_get_string(nodep, "fanpsu_status", "name", &nodename, &err) != 0){
		syslog(LOG_ERR, "update_linknode_state nodep no state prop entry.\n");
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));
	}
	get_fanpsu_status_by_name(chp, nodename, state);
#if 0
	printf("###invoked by fanpsu-transport ###node: %s, state: %s.\n", nodename, state);
#endif
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (nvlist_add_string(nvl, TOPO_PROP_VAL_NAME,
		TOPO_PROP_STATE) != 0 ||
		nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_STRING) != 0 ||
		nvlist_add_string(nvl, TOPO_PROP_VAL_VAL, state) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*out = nvl;

	return (0);
}

static int 
fanpsu_enum(topo_mod_t *mod, tnode_t *t_node, const char *name,
		topo_instance_t min, topo_instance_t max, void *arg, void *unused){/*{{{*/
	int index = 0;
	struct fanpsu_walk_ops fp_walk;
	fanpsu_enum_data_t data;
	fanpsu_handle_t *chp = topo_mod_getspecific(mod);

	if(!strcmp(name, FAN_NAME))
		index = FAN_LIST_INDEX;
	else if(!strcmp(name, PSU_NAME))
		index = PSU_LIST_INDEX;
	else{
		syslog(LOG_ERR, "fanpsu_enum error type.\n");
		return -1;
	}

	/* init enum structure that useful in creat tnode */
	data.ed_mod = mod;
	data.ed_pnode = t_node;
	data.ed_name = name;
	data.ed_index = index;
	data.ed_label = NULL;
	data.ed_instance = 0;

	bzero(&fp_walk, sizeof(struct fanpsu_walk_ops));
	fp_walk.for_each_node = fanpsu_node_create;
	fp_walk.priv = &data;

	fanpsu_node_list_walk(chp->fanpsu_table + index, &fp_walk);

	return 0;
}

static void
fanpsu_get_discrete_state_mini(char *header, char *separator,
								uint8_t sensor_type, uint8_t event_type,
								uint8_t state1, uint8_t state2)
{
	uint8_t typ;
	struct ipmi_event_sensor_types *evt;
	int pre = 0, c = 0;

	if (state1 == 0 && (state2 & 0x7f) == 0)
		return;

	evt = generic_event_types;
	typ = event_type;

	if (header)
		printf("%s", header);

	for (; evt->type != NULL; evt++) {
		if ((evt->code != typ) ||
		(evt->data != 0xFF))
			continue;

		if (evt->offset > 7) {
			if ((1 << (evt->offset - 8)) & (state2 & 0x7f)) {
				if (pre++ != 0)
					printf("%s", separator);
				if (evt->desc)
					printf("%s", evt->desc);
			}
		} else {
		if ((1 << evt->offset) & state1) {
			if (pre++ != 0)
				printf("%s", separator);
			if (evt->desc)
				printf("%s", evt->desc);
		}
		}
		c++;
	}
}

static int
fanpsu_topo_node_create(fanpsu_handle_t *fp_hdl, fanpsu_nodeinfo_t *nodeinfo){
	fanpsu_t *fp;
	topo_mod_t *mod = fp_hdl->ch_mod;
	int index;
	fanpsu_node_list_t *table = fp_hdl->fanpsu_table;
	char type[3];
	if(!(fp_hdl && nodeinfo->name)){
		syslog(LOG_ERR, "fanpsu_topo_node_creat invalid parameter.\n");
		return -1;
	}

	if(!strncmp(nodeinfo->name, "Fan", strlen("Fan"))){
		index = FAN_LIST_INDEX;
		strcpy(type, "fan");
	}else if(!strncmp(nodeinfo->name, "PS", strlen("PS"))){
		index = PSU_LIST_INDEX;
		strcpy(type, "psu");
	}else{
		syslog(LOG_ERR, "fanpsu_topo_node_creat error type\n");
		return -1;
	}

	if(!table[index].name)
		if(!(table[index].name = topo_mod_strdup(mod, type))){
			syslog(LOG_ERR, "no memary in fanpsu_topo_node_alloc list.name\n");
			return -1;
		}

	for(fp = topo_list_next(&table[index].node_list); fp; fp = topo_list_next(fp)){
		/*
		 * if we already have a node with name $name just update state
		 * and change node.losted to macro DEV_IS_EXISTED.
		 */
		if(!strcmp(fp->name, nodeinfo->name)){
			strcpy(fp->state, nodeinfo->value);
			fp->losted = DEV_IS_EXISTED;
			return 0;
		}
	}

	/*
	 * if we do not have a node who's name is $name create it and
	 * init the name & state & losted = DEV_IS_INSERTED.
	 */
	if(!fp)
		if(!(fp = (fanpsu_t *)topo_mod_zalloc(mod, sizeof(fanpsu_t)))){
			topo_mod_dprintf(mod, "no memary in conn_node_creat conn_t\n");
			return -1;
		}

	if(!(fp->name = topo_mod_strdup(mod, nodeinfo->name))){
		topo_mod_dprintf(mod, "no memary in conn_node_creat conn_t.name\n");
		topo_mod_free(mod, fp, sizeof(fanpsu_t));
		return -1;
	}

	strcpy(fp->state, nodeinfo->value);
	fp->losted = DEV_IS_INSERTED;
	topo_list_append((topo_list_t *)&table[index].node_list, fp);
	table[index].node_n++;
	topo_mod_dprintf(mod, "INIT TABLE:%s\n", nodeinfo->name);

	return 0;
}

static int
ipmi_sdr_get_sensor_fc(struct ipmi_intf *intf,
							struct sdr_record_common_sensor    *sensor,
							uint8_t sdr_record_type, 
							fanpsu_handle_t *fp_hdl, 
							fanpsu_nodeinfo_t *nodeinfo, 
							int flag)
{
	char sval[16];
	struct sensor_reading *sr;

	sr = ipmi_sdr_read_sensor_value(intf, sensor, sdr_record_type, 2);

	if (sr == NULL){
		return -1;
	}
	/*
	* print sensor name, number, state, entity, reading
	*/
	if( 0 == strncmp(sr->s_id, "Fan", strlen("Fan")) ||
		0 == strncmp(sr->s_id, "PS", strlen("PS"))){
		syslog(LOG_ERR, "%-16s | ", sr->s_id);

		memset(sval, 0, sizeof (sval));

		if (sr->s_reading_valid) {
			if (IS_THRESHOLD_SENSOR(sensor) &&
			sr->s_has_analog_value ) {
				/* Threshold Analog */
				snprintf(sval, sizeof (sval), "%s",
				ipmi_sdr_get_thresh_status(sr, "ns")
			);
		} else {
		/* Analog & Discrete & Threshold/Discrete */
		char *header = NULL;
		snprintf(sval, sizeof("ok"), "%s", sr->s_reading_valid ? "ok" : "ns");

		fanpsu_get_discrete_state_mini(header, ", ",
										sensor->sensor.type,
										sensor->event_type,
										sr->s_data2,
										sr->s_data3);

		}
		}
		else if (sr->s_scanning_disabled)
			snprintf(sval, sizeof (sval), "Disabled");
		else
			snprintf(sval, sizeof (sval), "No Reading");

		syslog(LOG_ERR, "%s\n", sval);

		memset(nodeinfo, 0, sizeof(fanpsu_nodeinfo_t));
		strcpy(nodeinfo->name, sr->s_id);
		strcpy(nodeinfo->value, sval);

		if(flag == FANPSU_ITER_NODE){
			return fp_hdl->ret_status = fanpsu_topo_node_create(fp_hdl, nodeinfo);
		}

		return 0;
	}

	return -1;
}


static int
get_fanpsu_status_by_name(fanpsu_handle_t *chp, const char *name, char *state)
{
	struct sdr_get_rs *header;
	struct ipmi_intf *intf = &ipmi_open_intf;
	struct ipmi_sdr_iterator *sdr_list_itr = NULL;
	struct sdr_record_list *sdr_list_head = NULL;
	struct sdr_record_list *sdr_list_tail = NULL;
	fanpsu_nodeinfo_t nodeinfo;
	int rc = 0;

	uint8_t type = 0xfe;
	if(NULL == name){
		syslog(LOG_ERR, "[fanpsu enum] name is NULL.\n");
		return -1;
	}

	if (sdr_list_itr == NULL) {
		sdr_list_itr = ipmi_sdr_start(intf, 0);
		if (sdr_list_itr == NULL) {
			syslog(LOG_ERR, "Unable to open SDR for reading");
			return -1;
		}
	}

	while ((header = ipmi_sdr_get_next_header(intf, sdr_list_itr)) != NULL) {
		uint8_t *rec;
		struct sdr_record_list *sdrr;

		rec = ipmi_sdr_get_record(intf, header, sdr_list_itr);
		if (rec == NULL) {
			syslog(LOG_ERR, "ipmitool: ipmi_sdr_get_record() failed\n");
			rc = -1;
			continue;
		}

		sdrr = malloc(sizeof (struct sdr_record_list));
		if (sdrr == NULL) {
			syslog(LOG_ERR, "get fan and psu status : malloc failure\n");
			if (rec != NULL) {
				free(rec);
				rec = NULL;
			}
			break;
		}
		memset(sdrr, 0, sizeof (struct sdr_record_list));
		sdrr->id = header->id;
		sdrr->type = header->type;

		switch (header->type) {
			case SDR_RECORD_TYPE_FULL_SENSOR:
			case SDR_RECORD_TYPE_COMPACT_SENSOR:
				sdrr->record.common =
				(struct sdr_record_common_sensor *) rec;
				break;
			case SDR_RECORD_TYPE_EVENTONLY_SENSOR:
				sdrr->record.eventonly =
				(struct sdr_record_eventonly_sensor *) rec;
				break;
			case SDR_RECORD_TYPE_GENERIC_DEVICE_LOCATOR:
				sdrr->record.genloc =
				(struct sdr_record_generic_locator *) rec;
				break;
			case SDR_RECORD_TYPE_FRU_DEVICE_LOCATOR:
				sdrr->record.fruloc =
				(struct sdr_record_fru_locator *) rec;
				break;
			case SDR_RECORD_TYPE_MC_DEVICE_LOCATOR:
				sdrr->record.mcloc =
				(struct sdr_record_mc_locator *) rec;
				break;
			case SDR_RECORD_TYPE_ENTITY_ASSOC:
				sdrr->record.entassoc =
				(struct sdr_record_entity_assoc *) rec;
				break;
			default:
				free(rec);
				rec = NULL;
				if (sdrr != NULL) {
					free(sdrr);
					sdrr = NULL;
				}
				continue;
		}

		if (type == header->type ||
		(type == 0xfe &&
		(header->type == SDR_RECORD_TYPE_FULL_SENSOR ||
		header->type == SDR_RECORD_TYPE_COMPACT_SENSOR))) {
		memset(&nodeinfo, 0, sizeof(fanpsu_nodeinfo_t));
		if (ipmi_sdr_get_sensor_fc(intf,
		                       (struct sdr_record_common_sensor *)rec,
				   			   header->type,
		                       NULL,
		                       &nodeinfo,
		                       FANPSU_GET_NODE)< 0)
			continue;
		else{
		if(NULL != name && !strncmp(name, nodeinfo.name, strlen(name))){
			strcpy(state, nodeinfo.value);
			break;
		}else{
			continue;
		}
		return rc = 0;
		}
		}

		/* add to global record liset */
		if (sdr_list_head == NULL)
		sdr_list_head = sdrr;
		else
		sdr_list_tail->next = sdrr;

		sdr_list_tail = sdrr;
	}

	return rc;
}


static int
fanpsu_node_iter_byipmi(struct ipmi_intf *intf, uint8_t type,
                        uint8_t * raw, int len, fanpsu_handle_t *fp_hdl)
{
		int rc = 0;
		fanpsu_nodeinfo_t node;

		rc = ipmi_sdr_get_sensor_fc(intf,
						(struct sdr_record_common_sensor *) raw,
						type,
						fp_hdl,
						&node,
						FANPSU_ITER_NODE);
		return rc;
}

static int
fanpsu_get_node_by_ipmi(topo_mod_t *mod, fanpsu_handle_t *fp_hdl)
{
	struct sdr_get_rs *header;
	struct ipmi_intf *intf = &ipmi_open_intf;
	struct ipmi_sdr_iterator *sdr_list_itr = NULL;
	struct sdr_record_list *sdr_list_head = NULL;
	struct sdr_record_list *sdr_list_tail = NULL;
	uint8_t type = 0xfe;

	if (sdr_list_itr == NULL) {
		sdr_list_itr = ipmi_sdr_start(intf, 0);
		if (sdr_list_itr == NULL) {
			syslog(LOG_ERR, "Unable to open SDR for reading");
			return -1;
		}
	}

	while ((header = ipmi_sdr_get_next_header(intf, sdr_list_itr)) != NULL) {
		uint8_t *rec;
		struct sdr_record_list *sdrr;

		rec = ipmi_sdr_get_record(intf, header, sdr_list_itr);
		if (rec == NULL) {
			syslog(LOG_ERR, "fanpsu: ipmi_sdr_get_record() failed");
			continue;
		}

		sdrr = malloc(sizeof (struct sdr_record_list));
		if (sdrr == NULL) {
			syslog(LOG_ERR, "fanpsu: malloc failure");
			if (rec != NULL) {
				free(rec);
				rec = NULL;
			}
			break;
		}
		memset(sdrr, 0, sizeof (struct sdr_record_list));
		sdrr->id = header->id;
		sdrr->type = header->type;

		switch (header->type) {
			case SDR_RECORD_TYPE_FULL_SENSOR:
			case SDR_RECORD_TYPE_COMPACT_SENSOR:
				sdrr->record.common =
				(struct sdr_record_common_sensor *) rec;
				break;
			case SDR_RECORD_TYPE_EVENTONLY_SENSOR:
				sdrr->record.eventonly =
				(struct sdr_record_eventonly_sensor *) rec;
				break;
			case SDR_RECORD_TYPE_GENERIC_DEVICE_LOCATOR:
				sdrr->record.genloc =
				(struct sdr_record_generic_locator *) rec;
				break;
			case SDR_RECORD_TYPE_FRU_DEVICE_LOCATOR:
				sdrr->record.fruloc =
				(struct sdr_record_fru_locator *) rec;
				break;
			case SDR_RECORD_TYPE_MC_DEVICE_LOCATOR:
				sdrr->record.mcloc =
				(struct sdr_record_mc_locator *) rec;
				break;
			case SDR_RECORD_TYPE_ENTITY_ASSOC:
				sdrr->record.entassoc =
				(struct sdr_record_entity_assoc *) rec;
				break;
			default:
				free(rec);
				rec = NULL;
				if (sdrr != NULL) {
					free(sdrr);
					sdrr = NULL;
				}
				continue;
		}

		if (type == header->type ||
		(header->type == SDR_RECORD_TYPE_FULL_SENSOR ||
		header->type == SDR_RECORD_TYPE_COMPACT_SENSOR)) {
			if (fanpsu_node_iter_byipmi(intf, header->type,
			                rec, header->length, fp_hdl) < 0){
				continue;
		}
		}

		/* add to global record liset */
		if (sdr_list_head == NULL)
			sdr_list_head = sdrr;
		else
			sdr_list_tail->next = sdrr;

		sdr_list_tail = sdrr;
	}

	return 0;
}

static int
gather_fanpsu_status(topo_mod_t *mod, fanpsu_handle_t *fp_hdl){
	fp_hdl->ch_mod = mod;
	fp_hdl->ttree = topo_mod_devinfo(mod);

	/*
	 *start walk sdr list.
	 */
	return fanpsu_get_node_by_ipmi(mod, fp_hdl);
}

int 
_topo_init(topo_mod_t *mod, topo_version_t version){
	fanpsu_handle_t *fp_hdl;

	topo_mod_dprintf(mod, "fanpsu module started.\n");
	if(topo_mod_register(mod, &fanpsu_info, TOPO_VERSION)){
		topo_mod_dprintf(mod, "%s registration failed: %s\n", "fanpsu", topo_mod_errmsg(mod));
		return -1;
	}

	if(NULL == (fp_hdl = topo_mod_zalloc(mod, sizeof(fanpsu_handle_t)))){
		topo_mod_dprintf(mod, "%s handle zalloc failed: %s\n", "fanpsu", topo_mod_errmsg(mod));
		goto error;
	}
	
	if(gather_fanpsu_status(mod, fp_hdl)){
		topo_mod_dprintf(mod, "cannot get fan and psu status\n");
		goto error;
	}

	topo_mod_setspecific(mod, fp_hdl);

	return 0;
	
error:
	if(fp_hdl){
		topo_mod_free(mod, fp_hdl, sizeof(fanpsu_handle_t));
	}
	topo_mod_unregister(mod);
	
	return -1;
}

void
_topo_fini(topo_mod_t *mod){
	fanpsu_handle_t *fp_hdl = topo_mod_getspecific(mod);
	if(fp_hdl){
		topo_mod_free(mod, fp_hdl, sizeof(fanpsu_handle_t));
	}
	topo_mod_dprintf(mod, "fan and psu enumerator initialized\n");
	topo_mod_unregister(mod);
}
