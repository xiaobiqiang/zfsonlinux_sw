#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <topo_mod.h>
#include <topo_fruhash.h>

#include "link_enum.h"
#include <syslog.h>

static int 
heartbert_status_ok(topo_mod_t *mod)
{
	char cmd[CMDLEN] = "zfs mirror -v|cut -d \':\' -f 2";	

	if (!strncmp(cmd, "up", strlen("up")))
		return HT_STATE_UP;
	else
		return HT_STATE_DOWN;
}

int heartbeat_status(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers,
	nvlist_t *in, nvlist_t **out)
{

    nvlist_t *nvl;
	uint64_t status;

    if(vers != TOPO_METH_LINK_VERSION)
        return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	(void)heartbert_status_ok(mod);
	sleep(1);
	status = heartbert_status_ok(mod);

	if(status == HT_STATE_DOWN)
		status = SXML_DOWN;
	else if(status == HT_STATE_UP)
		status = SXML_UP;
	else
		status = SXML_UNKNOWN;

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (nvlist_add_string(nvl, TOPO_PROP_VAL_NAME,
	    "status") != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT64) != 0 ||
	    nvlist_add_uint64(nvl, TOPO_PROP_VAL_VAL, status) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*out = nvl;
	return (0);

}

/* update link state in it's node */
int update_linknode_state(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl){/*{{{*/

	unsigned int state, old_state;
	int err;

    if(vers != TOPO_METH_LINK_VERSION)
        return (topo_mod_seterrno(mod, EMOD_VER_NEW));

    if(!in_nvl){
		LOG("update_linknode_state get a NULL in_nvl\n");
		return -1;
    }

	if(topo_prop_get_uint32(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_STATE, &old_state, &err) != 0){
		LOG("update_linknode_state nodep no state prop entry.\n");
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));
	}

	if(nvlist_lookup_uint32(in_nvl, TOPO_LINK_STATE, &state)){
		LOG("update_linknode_state nvl no state entry.\n");
		return -1;
	}
	if(old_state == state){
		LOG("update_linknode_state old_state == state \n");
		return -1;
	}

	if(topo_prop_set_uint32(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_STATE, TOPO_PROP_MUTABLE, state, &err)){
		LOG("update_linknode_state update state err.\n");
		return -1;
	}

	return 0;
}/*}}}*/

static int link_status2nvl(const char *type, const char *name, unsigned int state, nvlist_t **nvlp){/*{{{*/

	nvlist_t *nvl;
	char *k;

	if(nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0))
		return -1;

	if(!strcmp(type, FC_LINK)){
		switch(state){
			case FC_STATE_ONLINE:
				k = "online";
				break;
			case FC_STATE_OFFLINE:
				k = "offline";
				break;
			default:
				LOG("link_status2nvl type %s name %s state %d has never seen.\n", type, name, state);
				return -1;
		}
	}else if(!strcmp(type, ETHERNET_LINK)){
		switch(state){
			case ETH_STATE_UP:
				k = "up";
				break;
			case ETH_STATE_DOWN:
				k = "down";
				break;
			case ETH_STATE_UNKNOWN:
				k = "unknown";
				break;
			default:
				LOG("link_status2nvl type %s name %s state %d has never seen.\n", type, name, state);
				return -1;
		}
	}else if(!strcmp(type, SAS_LINK)){      /* not use now */
		switch(state){
			case SAS_STATE_ONLINE:
				k = "online";
				break;
			case SAS_STATE_OFFLINE:
				k = "offline";
				break;
			default:
				LOG("link_status2nvl type %s name %s state %d has never seen.\n", type, name, state);
				return -1;
		}
	}else if(!strcmp(type, HEART_LINK)){
		switch(state){
			case HT_STATE_UP:
				k = "UP";
				break;
			case HT_STATE_DOWN:
				k = "DOWN";
				break;
			case HT_STATE_UNKNOWN:
				k = "UNKNOWN";
				break;
			default:
				LOG("link_status2nvl type %s name %s state %d has never seen.\n", type, name, state);
				return -1;
		}
	}else{
		LOG("link_status2nvl error type.\n");
		return -1;
	}

	if(nvlist_add_string(nvl, TOPO_LINK_TYPE, type) ||
		nvlist_add_string(nvl, TOPO_LINK_NAME, name) ||
		nvlist_add_uint32(nvl, TOPO_LINK_STATE, state) ||
		nvlist_add_string(nvl, TOPO_LINK_STATE_DESC, k)){
		nvlist_free(nvl);
		return -1;
	}

	*nvlp = nvl;
	return 0;
}/*}}}*/

static int get_fcstate_by_name(conn_handle_t *chp /* not used */, const char *link, unsigned int *uip){/*{{{*/
#if 0
	unsigned long long hbaWWN;
	HBA_HANDLE handle;
	HBA_WWN myWWN;
	HBA_STATUS status;
	HBA_ADAPTERATTRIBUTES attrs;
	HBA_PORTATTRIBUTES port;
	int times, portCtr;

	if(!(link && uip)){
		LOG("invalid argument in func get_fcstate_by_name.\n");
		return -1;
	}

	sscanf(link, "%016llx", &hbaWWN);
	hbaWWN = htonll(hbaWWN);
	memcpy(myWWN.wwn, &hbaWWN, sizeof(hbaWWN));

	status = HBA_OpenAdapterByWWN(&handle, myWWN);
	times = 0;
	while((status == HBA_STATUS_ERROR_TRY_AGAIN || status == HBA_STATUS_ERROR_BUSY) && times++ < HBA_MAX_RETRIES){
		sleep(1);
		status = HBA_OpenAdapterByWWN(&handle, myWWN);
	}

	if(status != HBA_STATUS_OK){
		if(Sun_HBA_OpenTgtAdapterByWWN(&handle, myWWN) != HBA_STATUS_OK){
			LOG("failed HBA port %s: not found.\n", link);
			return -1;
		}
	}
	memset(&attrs, 0, sizeof (attrs));
	memset(&port, 0, sizeof (port));

#if 1
	status = HBA_GetAdapterAttributes(handle, &attrs);
	times = 0;
	while((status == HBA_STATUS_ERROR_TRY_AGAIN || status == HBA_STATUS_ERROR_BUSY) && times++ < HBA_MAX_RETRIES){
		sleep(1);
		if((status = HBA_GetAdapterAttributes(handle, &attrs)) == HBA_STATUS_OK) break;
	}
	if(status != HBA_STATUS_OK){
		LOG("failed to get adapter attributes handle %d.\n", handle);
		return -1;
	}

	for(portCtr = 0; portCtr < attrs.NumberOfPorts; portCtr++){
		if((status = HBA_GetAdapterPortAttributes(handle, portCtr, &port)) != HBA_STATUS_OK){
			LOG("failed to get port %d attributes.\n", portCtr);
			return -1;
		}
		if(memcmp(myWWN.wwn, port.PortWWN.wwn, sizeof(port.PortWWN.wwn)) == 0){
			*uip = port.PortState;
			break;
		}
	}
	if(portCtr >= attrs.NumberOfPorts){
		LOG("failed to get port %d attributes.\n", portCtr);
		HBA_CloseAdapter(handle);
		return -1;
	}
#endif
	HBA_CloseAdapter(handle);
#endif
	return 0;
}/*}}}*/


/* we get ethernet card link state from kstat */
static int get_ethstate_by_name(conn_handle_t *chp , const char *link, unsigned int *uip){/*{{{*/
	char cmd[CMDLEN];
	char tmp[CMDLEN];
	FILE *fp;
	
	memset(cmd, 0, CMDLEN);
	memset(tmp, 0, CMDLEN);
	snprintf(cmd, CMDLEN, "ethtool %s|grep Link|cut -d ':' -f 2", link);
	fp = popen(cmd, "r");
	if(fgets(tmp, CMDLEN, fp) == NULL){
		*uip = ETH_STATE_UNKNOWN; /*unknown*/
	}else{
		if(strstr(tmp, "yes") != NULL){
			*uip = ETH_STATE_UP; /*up*/
		}else if(strstr(tmp, "no") != NULL){
			*uip = ETH_STATE_DOWN; /*down*/
		}else{
			*uip = ETH_STATE_UNKNOWN; /*unknown*/
		}
	}	
		
	pclose(fp);

	return 0;
}/*}}}*/

int is_linkstate_changed(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl){/*{{{*/

    char *type, *name;
    int err, ret = 0;
    unsigned int state = 0, status = 0;
    unsigned int old_state;
    nvlist_t *nvl, *fmri;
	char *fmristr;
    conn_handle_t *chp = topo_mod_getspecific(mod);
	
    if(vers != TOPO_METH_LINK_VERSION)
        return (topo_mod_seterrno(mod, EMOD_VER_NEW));

    if(!out_nvl){
		LOG("is_linkstate_changed get a NULL out_nvl\n");
		return -1;
    }
	
	if(topo_node_resource(nodep, &fmri, &err) != 0 ||
		topo_mod_nvl2str(mod, fmri, &fmristr) != 0) {
		nvlist_free(fmri);
		return -1;
	}

	/*
	 * get link device type from topo node, because we need different
	 * methods to capture all kinds of link devices state.
	 */

	if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_TYPE, &type, &err) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));

    /*
     * If the caller specifies the "name" parameter, then this indicates
     * that we should use this instead of deriving it from the topo node
     * itself.
     */

    name = NULL;
    if(nvlist_lookup_string(in_nvl, "name", &name)){

		/* get link device name from topo node. */
		if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_NAME, &name, &err) != 0){
			topo_mod_strfree(mod, type);
			return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));
		}
    }

	if(!strcmp(type, FC_LINK)){
		if(get_fcstate_by_name(chp, name, &state)){
			LOG("failed get_fcstate_by_name type :%s name :%s.\n", type, name);
			ret = -1;
			goto done;
		}
		if (state == FC_STATE_ONLINE)
			status = SXML_ONLINE;
		else
			status = SXML_OFFLINE;
	}else if(!strcmp(type, ETHERNET_LINK)){
		if(get_ethstate_by_name(chp, name, &state)){
			LOG("failed get_ethstate_by_name type :%s name :%s.\n", type, name);
			ret = -1;
			goto done;
		}
		if (state == ETH_STATE_UP)
			status = SXML_UP;
		else if (state == ETH_STATE_DOWN)
			status = SXML_DOWN;
		else
			status = SXML_UNKNOWN;
	}else if(!strcmp(type, SAS_LINK)){      /* not use now */
		LOG("SAS_LINK pass\n");
		ret = -1;
		goto done;
	}else if(!strcmp(type, HEART_LINK)){
		state = heartbert_status_ok(mod);
		if (state == HT_STATE_UP)
			status = SXML_UP;
		else if (state == HT_STATE_DOWN)
			status = SXML_DOWN;
		else
			status = SXML_UNKNOWN;
	}else{
		LOG("is_linkstate_changed error type.\n");
		ret = -1;
		goto done;
	}

	if(topo_prop_get_uint32(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_STATE, &old_state, &err) != 0){
		topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP);
		ret = -1;
		goto done;
	}

	if (status == SXML_OK || status == SXML_ONLINE || status == SXML_UP)
		topo_fru_cleartime(fmristr, 0xffffffff);
	else
		(void) topo_fru_setime(fmristr, status, NULL, NULL, NULL, NULL);
	nvlist_free(fmri);
	topo_mod_strfree(mod, fmristr);
	
	if(old_state != state){
		if(topo_prop_set_uint32(nodep, TOPO_PGROUP_LINK_STATUS,
			"status", TOPO_PROP_MUTABLE, status, &err)){
			LOG("update_linknode_state update state err.\n");
			return -1;
		}
		if(link_status2nvl(type, name, state, &nvl)){
			ret = -1;
			goto done;
		}

		*out_nvl = nvl;
		ret = 1;
	}else
		*out_nvl = NULL;

/*	LOG("type ## %s ##    name ## %s ##    state # %d # %d #\n", type, name, old_state, state); */

done:
	topo_mod_strfree(mod, type);
	topo_mod_strfree(mod, name);
    return ret;
}/*}}}*/

