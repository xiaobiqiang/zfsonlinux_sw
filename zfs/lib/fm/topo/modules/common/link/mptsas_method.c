
#ifdef _MPTSAS_METHOD_
/*empty file.*/
#include <stdio.h>
#include <alloca.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <libnvpair.h>
#include <topo_list.h>
#include <topo_mod.h>
#include <topo_fruhash.h>
#include <libdevinfo.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "mptsas_method.h"

/* test free dn_table memory */
/* #define haha */

static int is_mptsas_phycard(di_node_t node){/*{{{*/

	char *phys_name;
	char *bus_addr;
	int ret = 0;

	phys_name = di_node_name(node);
	bus_addr = di_bus_addr(node);

	/*
	 * There is no basis to determine whether it is a physical sas_card
	 * like this, but it always works good, Thank God.
	 */
	LOG("name:%s, busaddr:%s\n", phys_name, bus_addr);
	if(strcmp(phys_name, "iport") && !strcmp(bus_addr, "0"))
		ret++;

	return ret;
}/*}}}*/

static int is_mptsas_phyport(di_node_t node){/*{{{*/

	char *phys_name;
	char *bus_addr;
	int ret = 0;

	phys_name = di_node_name(node);
	bus_addr = di_bus_addr(node);

	/*
	 * There is no basis to determine whether it is a physical sas_port
	 * like this, but it always works good, Thank God.
	 */

	if(!strcmp(phys_name, "iport") && strcmp(bus_addr, "v0"))
		ret++;

	return ret;
}/*}}}*/

void free_phy_mptsas_cardinfo(void *arg){/*{{{*/

	phy_mptsas_cardinfo_t *mscp = (phy_mptsas_cardinfo_t *)arg;

	if(mscp->phys_path){
#ifdef haha
		printf("free_phy_mptsas_cardinfo Path :%s free.\n", mscp->phys_path);
#endif
		free(mscp->phys_path);
	}
	if(mscp->serialnumber)
		free(mscp->serialnumber);
	if(mscp->modelname)
		free(mscp->modelname);
	if(mscp->manufacturer)
		free(mscp->manufacturer);
	if(mscp->base_wwid)
		free(mscp->base_wwid);
	if(mscp)
		free(mscp);
}/*}}}*/

void *get_phy_mptsas_cardinfo(di_node_t node, void *arg){/*{{{*/

	int instance;
	char *phys_path;
	int64_t *base_wwid = NULL;
	char *serialnumber = NULL, *modelname = NULL;
	char *manufacturer= NULL;
	phy_mptsas_cardinfo_t *mscp;

	if(!is_mptsas_phycard(node))
		return NULL;

	if((mscp = calloc(1, sizeof(*mscp))) == NULL)
		return NULL;

	instance = di_instance(node);
	phys_path = di_devfs_path(node);

	if((mscp->phys_path = strdup(phys_path)) == NULL)
		goto Err;

	di_prop_lookup_strings(DDI_DEV_T_ANY, node, MPTSAS_PROP_SERIALNUMBER, &serialnumber);
	di_prop_lookup_strings(DDI_DEV_T_ANY, node, MPTSAS_PROP_MODELNAME, &modelname);
	di_prop_lookup_strings(DDI_DEV_T_ANY, node, MPTSAS_PROP_MANUFACTURER, &manufacturer);
	di_prop_lookup_int64(DDI_DEV_T_ANY, node, MPTSAS_PROP_BASE_WWID, &base_wwid);

	if(serialnumber && serialnumber[0] != 0)
		if((mscp->serialnumber = strdup(serialnumber)) == NULL)
			goto Err;
	if(modelname && modelname[0] != 0)
		if((mscp->modelname = strdup(modelname)) == NULL)
			goto Err;
	if(manufacturer && manufacturer[0] != 0)
		if((mscp->manufacturer = strdup(manufacturer)) == NULL)
			goto Err;
	if(base_wwid){
		asprintf(&mscp->base_wwid, "%016llx", *base_wwid);
		if(!mscp->base_wwid && mscp->base_wwid[0] == 0)
			goto Err;
	}
	mscp->instance = instance;
	LOG("get mptsas info success\n inst:%d,path:%s\n serialnumber:%s,modelname:%s,manufac:%s,wwid:%s\n",
		instance,phys_path,mscp->serialnumber,modelname,manufacturer,mscp->base_wwid);
	di_devfs_path_free(phys_path);
	return mscp;
Err:
	di_devfs_path_free(phys_path);
	free_phy_mptsas_cardinfo(mscp);
	return NULL;
}/*}}}*/

void free_phy_mptsas_portinfo(void *arg){/*{{{*/

	phy_mptsas_portinfo_t *msip = (phy_mptsas_portinfo_t *)arg;

	if(msip->phys_path){
#ifdef haha
		printf("free_phy_mptsas_portinfo Path :%s free.\n", msip->phys_path);
#endif
		free(msip->phys_path);
	}
	if(msip->initiator_port)
		free(msip->initiator_port);
	if(msip->attached_port)
		free(msip->attached_port);
	if(msip)
		free(msip);
}/*}}}*/

void *get_phy_mptsas_portinfo(di_node_t node, void *arg){/*{{{*/

	int instance;
	char *phys_path;
	char *initiator_port = NULL, *attached_port = NULL;
	phy_mptsas_portinfo_t *msip;

	if(!is_mptsas_phyport(node))
		return NULL;

	if((msip = calloc(1, sizeof(*msip))) == NULL)
		return NULL;

	instance = di_instance(node);
	phys_path = di_devfs_path(node);

	if((msip->phys_path = strdup(phys_path)) == NULL)
		goto Err;

	di_prop_lookup_strings(DDI_DEV_T_ANY, node, MPTSAS_PROP_INITIATOR_PORT, &initiator_port);
	di_prop_lookup_strings(DDI_DEV_T_ANY, node, MPTSAS_PROP_ATTACHED_PORT, &attached_port);

	if(initiator_port && initiator_port[0] != 0)
		if((msip->initiator_port = strdup(initiator_port)) == NULL)
			goto Err;
	if(attached_port && attached_port[0] != 0)
		if((msip->attached_port = strdup(attached_port)) == NULL)
			goto Err;
	msip->instance = instance;

	di_devfs_path_free(phys_path);
	return msip;
Err:
	di_devfs_path_free(phys_path);
	free_phy_mptsas_portinfo(msip);
	return NULL;
}/*}}}*/

void free_smp_info(void *arg){/*{{{*/

	smp_info_t *sip = (smp_info_t *)arg;

	if(sip->phys_path){
#ifdef haha
		printf("free_smp_info Path :%s free.\n", sip->phys_path);
#endif
		free(sip->phys_path);
	}
	if(sip->attached_port)
		free(sip->attached_port);
	if(sip->target_port)
		free(sip->target_port);
	if(sip)
		free(sip);
}/*}}}*/

void *get_smp_info(di_node_t node, void *arg){/*{{{*/

	int instance;
	char *phys_path;
	char *attached_port = NULL, *target_port = NULL;
	smp_info_t *sip;

	if((sip = calloc(1, sizeof(*sip))) == NULL)
		return NULL;

	instance = di_instance(node);
	phys_path = di_devfs_path(node);

	if((sip->phys_path = strdup(phys_path)) == NULL)
		goto Err;

	/* we can get same target_port value from follow two choices */
	target_port = di_bus_addr(node);
	/*	di_prop_lookup_strings(DDI_DEV_T_ANY, node, MPTSAS_PROP_INITIATOR_PORT, &target_port); */
	if((sip->target_port = strdup(target_port)) == NULL)
		goto Err;

	di_prop_lookup_strings(DDI_DEV_T_ANY, node, SMP_PROP_ATTACHED_PORT, &attached_port);

	if(attached_port && attached_port[0] != 0)
		if((sip->attached_port = strdup(attached_port)) == NULL)
			goto Err;
	sip->instance = instance;

	di_devfs_path_free(phys_path);
	return sip;
Err:
	di_devfs_path_free(phys_path);
	free_smp_info(sip);
	return NULL;
}/*}}}*/

int walk_drvname_nodes(di_node_t root_node, const char *drvname,
		struct node_ops *ops, void *arg, drvnode_list_t **out){/*{{{*/

	di_node_t node;
	drvnode_list_t *list = NULL;
	drvnode_list_t *dlp;
	drvnode_list_t *last;
	int count = 0;

	if(root_node == DI_NODE_NIL || !drvname || !ops)
		return -1;

	node = di_drv_first_node(drvname, root_node);

	while(node != DI_NODE_NIL){

		if((dlp = calloc(1, sizeof(*dlp))) == NULL){
			goto Err;
		}
		LOG("enum node %s %d.\n", drvname, di_instance(node));
		if(!(dlp->data = ops->get_node_info(node, arg))){
			LOG("failed to enum node %s %d.\n", drvname, di_instance(node));
			free(dlp);
			node = di_drv_next_node(node);
			continue;
		}
		if(!list)
			list = last = dlp;
		else{
			last->next = dlp;
			last = dlp;
		}
		dlp->ops.get_node_info = ops->get_node_info;
		dlp->ops.free_node_info = ops->free_node_info;
		count++;
		node = di_drv_next_node(node);
	}

	if(out)
		*out = list;
	return count;

Err:
	if(list){
		drvnode_list_t *dlp_tmp;
		for(dlp = list; dlp; dlp = dlp_tmp){
			dlp_tmp = dlp->next;
			if(dlp->data)
				ops->free_node_info(dlp->data);
			free(dlp);
		}
	}
	return -1;
}/*}}}*/

void free_drvname_nodes(drvnode_list_t *list){/*{{{*/

	drvnode_list_t *dlp;
	drvnode_list_t *dlp_tmp;

	if(list){
		for(dlp = list; dlp; dlp = dlp_tmp){
			dlp_tmp = dlp->next;
			if(dlp->data)
				list->ops.free_node_info(dlp->data);
			free(dlp);
		}
	}
}/*}}}*/

static int path_match(const char *path1, const char *path2){/*{{{*/

	char *p = strrchr(path2, '/');
	int len;

	len = p - path2;
	if(len == strlen(path1))
		return (!strncmp(path1, path2, len));
	else
		return 0;
}/*}}}*/

int mptsas_iport_smp_match(const char *iport_path, const char *smp_path){/*{{{*/

	return (path_match(iport_path, smp_path));
}/*}}}*/

int mptsas_card_iport_match(const char *card_path, const char *iport_path){/*{{{*/

	return (path_match(card_path, iport_path));
}/*}}}*/

void mptsas_smp_table_destroy(conn_handle_t *chp){/*{{{*/

	int i;

	for(i = 0; i < DN_TABLE_INDEX_MAX; i++){
		free_drvname_nodes(chp->dn_table[i]);
		chp->dn_table[i] = NULL;
	}
}/*}}}*/

int mptsas_smp_table_init(conn_handle_t *chp){/*{{{*/

	struct node_ops ops;
	drvnode_list_t *dlp;
	drvnode_list_t *list;
	phy_mptsas_cardinfo_t *mscp;
	phy_mptsas_portinfo_t *msip;
	smp_info_t *sip;
	int count;

	ops.get_node_info = get_phy_mptsas_cardinfo; /*{{{*/
	ops.free_node_info = free_phy_mptsas_cardinfo;
	if((count = walk_drvname_nodes(chp->devtree, SAS_DRIVER, &ops, NULL, &list)) != -1){
		LOG("walk_drvname_nodes get mptsas_cardinfo ## %d elements\n", count);

		for(dlp = list; dlp; dlp = dlp->next){
			mscp = (phy_mptsas_cardinfo_t *)dlp->data;
			LOG("%s\n", mscp->phys_path);
		}
		chp->dn_table[DN_TABLE_MPTSAS_CARD] = list;
	}else{
		LOG("failed run walk_drvname_nodes mptsas_cardinfo\n");
		goto Err;
	}/*}}}*/

	ops.get_node_info = get_phy_mptsas_portinfo; /*{{{*/
	ops.free_node_info = free_phy_mptsas_portinfo;
	if((count = walk_drvname_nodes(chp->devtree, SAS_DRIVER, &ops, NULL, &list)) != -1){
		LOG("walk_drvname_nodes get mptsas_portinfo ## %d elements\n", count);

		for(dlp = list; dlp; dlp = dlp->next){
			msip = (phy_mptsas_portinfo_t *)dlp->data;
			LOG("%s\n", mscp->phys_path);
		}
		chp->dn_table[DN_TABLE_MPTSAS_IPORT] = list;
	}else{
		LOG("failed run walk_drvname_nodes mptsas_portinfo\n");
		goto Err;
	}/*}}}*/

	ops.get_node_info = get_smp_info; /*{{{*/
	ops.free_node_info = free_smp_info;
	if((count = walk_drvname_nodes(chp->devtree, SMP_DRIVER, &ops, NULL, &list)) != -1){
		LOG("walk_drvname_nodes get smp_info ## %d elements\n", count);

		for(dlp = list; dlp; dlp = dlp->next){
			mscp = (phy_mptsas_cardinfo_t *)dlp->data;
			LOG("%s\n", mscp->phys_path);
		}
		chp->dn_table[DN_TABLE_SMP] = list;
	}else{
		LOG("failed run walk_drvname_nodes smp_info\n");
		goto Err;
	}/*}}}*/

	return 0;

Err:
	mptsas_smp_table_destroy(chp);
	return -1;
}/*}}}*/

int dump_mptsas_tree_xml(conn_handle_t *chp, char *xml_path){/*{{{*/

	xmlDocPtr doc;
	xmlNodePtr root_node, card_node, iport_node, smp_node;
	char ch[2] = {0};
	drvnode_list_t *dlp;
	drvnode_list_t *dlp1;
	drvnode_list_t *dlp2;
	phy_mptsas_cardinfo_t *mscp;
	phy_mptsas_portinfo_t *msip;
	smp_info_t *sip;

	doc = xmlNewDoc(BAD_CAST "1.0");
	root_node = xmlNewNode(NULL, BAD_CAST "mptsas_tree");
	xmlDocSetRootElement(doc, root_node);

	for(dlp = chp->dn_table[DN_TABLE_MPTSAS_CARD]; dlp; dlp = dlp->next){

		mscp = (phy_mptsas_cardinfo_t *)dlp->data;

		card_node = xmlNewChild(root_node, NULL, BAD_CAST "sas_card", NULL);
		ch[0] = mscp->instance + '0';
		xmlNewProp(card_node, BAD_CAST "instance", BAD_CAST ch);
		if(mscp->phys_path)
			xmlNewProp(card_node, BAD_CAST "phys_path", BAD_CAST mscp->phys_path);
		if(mscp->serialnumber)
			xmlNewProp(card_node, BAD_CAST "serialnumber", BAD_CAST mscp->serialnumber);
		if(mscp->modelname)
			xmlNewProp(card_node, BAD_CAST "modelname", BAD_CAST mscp->modelname);
		if(mscp->manufacturer)
			xmlNewProp(card_node, BAD_CAST "manufacturer", BAD_CAST mscp->manufacturer);
		if(mscp->base_wwid)
			xmlNewProp(card_node, BAD_CAST "base_wwid", BAD_CAST mscp->base_wwid);

		for(dlp1 = chp->dn_table[DN_TABLE_MPTSAS_IPORT]; dlp1; dlp1 = dlp1->next){
			msip = (phy_mptsas_portinfo_t *)dlp1->data;

			if(mptsas_card_iport_match(mscp->phys_path, msip->phys_path)){
				iport_node = xmlNewChild(card_node, NULL, BAD_CAST "sas_iport", NULL);
				ch[0] = msip->instance + '0';
				xmlNewProp(iport_node, BAD_CAST "instance", BAD_CAST ch);
				if(msip->phys_path)
					xmlNewProp(iport_node, BAD_CAST "phys_path", BAD_CAST msip->phys_path);
				if(msip->initiator_port)
					xmlNewProp(iport_node, BAD_CAST "initiator_port", BAD_CAST msip->initiator_port);
				if(msip->attached_port)
					xmlNewProp(iport_node, BAD_CAST "attached_port", BAD_CAST msip->attached_port);

				for(dlp2 = chp->dn_table[DN_TABLE_SMP]; dlp2; dlp2 = dlp2->next){
					sip = (smp_info_t *)dlp2->data;

					if(mptsas_iport_smp_match(msip->phys_path, sip->phys_path)){
						smp_node = xmlNewChild(iport_node, NULL, BAD_CAST "smp", NULL);

						ch[0] = sip->instance + '0';
						xmlNewProp(smp_node, BAD_CAST "instance", BAD_CAST ch);
						if(sip->phys_path)
							xmlNewProp(smp_node, BAD_CAST "phys_path", BAD_CAST sip->phys_path);
						if(sip->attached_port)
							xmlNewProp(smp_node, BAD_CAST "attached_port", BAD_CAST sip->attached_port);
						if(sip->target_port)
							xmlNewProp(smp_node, BAD_CAST "target_port", BAD_CAST sip->target_port);
					}
				}
			}
		}
	}

	xmlSaveFormatFileEnc(xml_path, doc, "UTF-8", 1);

	xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlMemoryDump();

	return 0;
}/*}}}*/

int update_mptsas_tree_xml(conn_handle_t *chp){/*{{{*/

	struct stat st;
	off_t size, size1;
	char *tmp = "/var/log/mptsas_tree_tmp.xml";

	size = size1 = 0;
	if(access(XML_PATH, F_OK))
		dump_mptsas_tree_xml(chp, XML_PATH);
	else{
		dump_mptsas_tree_xml(chp, tmp);
		if(!stat(XML_PATH, &st))
			size = st.st_size;
		if(!stat(tmp, &st))
			size1 = st.st_size;
		if(size != size1){
			rename(XML_PATH, XML_BACKUP_PATH);
			rename(tmp, XML_PATH);
		}
	}

	return 0;
}/*}}}*/

void free_smp_info_array(smp_info_t *array, int array_len){/*{{{*/

	int i;

	for(i = 0; i < array_len; i++){
		if(array[i].phys_path)
			free(array[i].phys_path);
		if(array[i].attached_port)
			free(array[i].attached_port);
		if(array[i].target_port)
			free(array[i].target_port);
	}
}/*}}}*/

int get_allxml_iport_smp(const char *xml_path, const char *phys_path, smp_info_t *buf, int buf_len){/*{{{*/

	xmlDocPtr doc;
	xmlNodePtr rootNode, cardNode, iportNode, smpNode;
	xmlAttrPtr attrPtr;
	xmlChar *tmp = NULL;
	xmlChar *iport_path= NULL;
	xmlChar *smp_path= NULL;
	int count = 0, i;

	if(!buf || buf_len <= 0)
		return -1;

	if(access(xml_path, F_OK))
		return -1;

	bzero(buf, sizeof(smp_info_t) * buf_len);

	doc = xmlParseFile(xml_path);
	rootNode = xmlDocGetRootElement(doc);

	cardNode = rootNode->xmlChildrenNode;
	while(cardNode){

		if(!strcmp((char *)cardNode->name, "text")){
			cardNode = cardNode->next;
			continue;
		}

		iportNode = cardNode->xmlChildrenNode;
		while(iportNode){

			if(!strcmp((char *)iportNode->name, "text")){
				iportNode = iportNode->next;
				continue;
			}

			if(!strcmp((char *)xmlGetProp(iportNode, BAD_CAST "phys_path"), phys_path)){
				smpNode = iportNode->xmlChildrenNode;
				while(smpNode){
					if(!strcmp((char *)smpNode->name, "text")){
						smpNode = smpNode->next;
						continue;
					}
					if(xmlHasProp(smpNode, BAD_CAST "instance")){
						buf[count].instance = atoi((char *)xmlGetProp(smpNode, BAD_CAST "instance"));
					}
					if(xmlHasProp(smpNode, BAD_CAST "phys_path")){
						/*
						 * I don't know whether xmlGetProp interface can return a NULL. if NULL is
						 * returned we will get a segmentfault. thank god :).
						 */
						tmp = xmlGetProp(smpNode, BAD_CAST "phys_path");
						buf[count].phys_path = strdup((char *)tmp);
						xmlFree(tmp);
						if(buf[count].phys_path == NULL)
							goto Err;
					}
					if(xmlHasProp(smpNode, BAD_CAST "attached_port")){
						tmp = xmlGetProp(smpNode, BAD_CAST "attached_port");
						buf[count].attached_port = strdup((char *)tmp);
						xmlFree(tmp);
						if(buf[count].attached_port == NULL){
							free(buf[count].phys_path);
							goto Err;
						}
					}
					if(xmlHasProp(smpNode, BAD_CAST "target_port")){
						tmp = xmlGetProp(smpNode, BAD_CAST "target_port");
						buf[count].target_port = strdup((char *)tmp);
						xmlFree(tmp);
						if(buf[count].target_port == NULL){
							free(buf[count].phys_path);
							free(buf[count].attached_port);
							goto Err;
						}
					}
					smpNode = smpNode->next;
					if(++count >= buf_len)
						goto Done;
				}
			}
			iportNode = iportNode->next;
		}
		cardNode = cardNode->next;
	}
	goto Done;

Err:
	free_smp_info_array(buf, count);
	count = -1;
Done:
	xmlFreeDoc(doc);
	return count;
}/*}}}*/

int get_all_iport_smp(topo_mod_t *mod, const char *mptsas_iport, drvnode_list_t **buf, int buf_len){/*{{{*/

	int count = 0;
	conn_handle_t *chp = topo_mod_getspecific(mod);
	drvnode_list_t *dlp;
	smp_info_t *sip;

	if(!buf && buf_len == 0)
		return -1;

	for(dlp = chp->dn_table[DN_TABLE_SMP]; dlp; dlp = dlp->next){
		sip = (smp_info_t *)dlp->data;
		if(mptsas_iport_smp_match(mptsas_iport, sip->phys_path)){
			buf[count++] = dlp;
			if(count >= buf_len)
				break;
		}
	}

	return count;
}/*}}}*/

int mptsas_iport_monitor(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl){/*{{{*/

	char *type, *phys_path;
	int err, ret = 0;
	int i, j;
	uint32_t count = 0, status = SXML_OFFLINE;
	int realcount, xmlcount;
	char ch[24];
	char **array;
	smp_info_t *sip;
	smp_info_t si_array[MPTSAS_IPORT_SMPS_MAX];
	int state[MPTSAS_IPORT_SMPS_MAX] = {0};
	drvnode_list_t *dl_array[MPTSAS_IPORT_SMPS_MAX] = {0};
	drvnode_list_t *dlp;
	conn_handle_t *chp = topo_mod_getspecific(mod);
	char *fmristr;
	nvlist_t *fmri;

	if(topo_node_resource(nodep, &fmri, &err) != 0 ||
		topo_mod_nvl2str(mod, fmri, &fmristr) != 0) {
		nvlist_free(fmri);
		return -1;
	}
	if(topo_prop_get_uint32(nodep, TOPO_PGROUP_LINK_STATUS,
		"status", &status, &err) != 0){
		topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP);
		nvlist_free(fmri);
		topo_mod_strfree(mod, fmristr);
		ret = -1;
	}

	if (status == SXML_ONLINE)
		topo_fru_cleartime(fmristr);
	else
		(void) topo_fru_setime(fmristr);
	nvlist_free(fmri);
	topo_mod_strfree(mod, fmristr);
	/*
	 * we assume It's impossable happen 24 insert/remove action in 5/10 secs.
	 */
#define nvlist_array_len 24
	nvlist_t *nvl_array[nvlist_array_len] = {0};
	nvlist_t *nvl;
	uint_t nvl_i = 0;

#if 1/*{{{*/
	if(vers != TOPO_METH_DISK_STATUS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if(out_nvl == NULL){
		LOG("mptsas_card_monitor parameter out_nvl mast not NULL.\n");
		return -1;
	}
	/*
	 * get link device type from topo node, because we need different
	 * methods to capture all kinds of link devices state.
	 */
	if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_TYPE, &type, &err) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));

	/* get link device phys_path from topo node. */
	phys_path = NULL;
	if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_PHYS_PATH, &phys_path, &err) != 0){
		topo_mod_strfree(mod, type);
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));
	}

	if(strcmp(type, SAS_LINK)){
		LOG("mptsas_card_monitor type error.\n");
		ret = -1;
		goto Done;
	}
#endif/*}}}*/

#if 1
	if((xmlcount = get_allxml_iport_smp(XML_BACKUP_PATH, phys_path, si_array, MPTSAS_IPORT_SMPS_MAX)) == -1){
		*out_nvl = NULL;
		goto Done;
	}
	realcount = get_all_iport_smp(mod, phys_path, dl_array, MPTSAS_IPORT_SMPS_MAX);

#if 0/*{{{*/
	if(topo_prop_get_uint32(nodep, TOPO_PGROUP_ATTACHED_SMPS, TOPO_LINK_SMP_MAX, &count, &err) != 0){
		LOG("can't get TOPO_LINK_SMP_MAX in mptsas_card_monitor.\n");
		ret = -1;
		goto Done;
	}

	array = alloca(sizeof(char *) * (count + 1));
	bzero(array, sizeof(char *) * (count + 1));
	for(i = 0; i < count; i++){
		sprintf(ch, "%s%d", TOPO_LINK_PHYS_PATH, i);
		if(topo_prop_get_string(nodep, TOPO_PGROUP_ATTACHED_SMPS, ch, array + i, &err) != 0){
			LOG("can't get %s in mptsas_iport_monitor.\n", ch);
			ret = -1;
			goto Done;
		}
	}

	/* Just for debug */
	for(i = 0; array[i]; i++){
		printf("LHL ADD ++ arraypath %s\n", array[i]);
	}
	for(j = 0; j < realcount; j++){
		sip = (smp_info_t *)dl_array[j]->data;
		printf("\tLHL ADD ++ realpath %s\n", sip->phys_path);
	}
#endif /*}}}*/

	/* decide if mat_sas iport's smp is detached */
	for(i = 0; i < xmlcount; i++){
		for(j = 0; j < realcount; j++){
			sip = (smp_info_t *)dl_array[j]->data;
			if(!strcmp(sip->phys_path, si_array[i].phys_path)){
				/*
				 * set flag that indicate the smp_dev is in iport's property
				 * then we traversal the array determine which is a NEW smp attached
				 * whth flag = 0;
				 */
				state[j] = 1;
				break;
			}
		}
		/* smp miss */
		if(j == realcount){
			/* @1: we can export instance##attached_port##target_port info, but I don't want to */
			nvlist_alloc(nvl_array + nvl_i, NV_UNIQUE_NAME, 0);
			nvlist_add_string(nvl_array[nvl_i], TOPO_LINK_TYPE, type);
			nvlist_add_string(nvl_array[nvl_i], TOPO_LINK_NAME, si_array[i].phys_path);
			nvlist_add_uint32(nvl_array[nvl_i], TOPO_LINK_STATE, DEV_STATE_DETACHED);
			nvlist_add_string(nvl_array[nvl_i], TOPO_LINK_STATE_DESC, "offline");
			nvl_i++;
			/* printf("smp %s missed.\n", array[i]); */
		}
	}

	for(i = 0; i < realcount; i++){
		/* smp added */
		LOG("state[%d] == %d\n", i, state[i]);
		if(!state[i]){
			sip = (smp_info_t *)dl_array[i]->data;
			/* @2: like @1 */
			nvlist_alloc(nvl_array + nvl_i, NV_UNIQUE_NAME, 0);
			nvlist_add_string(nvl_array[nvl_i], TOPO_LINK_TYPE, type);
			nvlist_add_string(nvl_array[nvl_i], TOPO_LINK_NAME, sip->phys_path);
			nvlist_add_uint32(nvl_array[nvl_i], TOPO_LINK_STATE, DEV_STATE_ATTACHED);
			nvlist_add_string(nvl_array[nvl_i], TOPO_LINK_STATE_DESC, "online");
			nvl_i++;
			/* printf("smp %s attached.\n", sip->phys_path); */
		}
	}
#endif
	if(nvl_i){
		nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
		nvlist_add_nvlist_array(nvl, DEV_ACTION_ARRAY, nvl_array, nvl_i);
		*out_nvl = nvl;
	}else
		*out_nvl = NULL;
#undef nvlist_array_len
Done:
	topo_mod_strfree(mod, type);
	topo_mod_strfree(mod, phys_path);
	for(i = 0; nvl_array[i]; i++)
		nvlist_free(nvl_array[i]);
	free_smp_info_array(si_array, xmlcount);

	return ret;
}/*}}}*/

int mptsas_iport_smp_attach(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl){/*{{{*/

	int ret = 0, err;
	char *type, *iport_phys_path, *smp_phys_path;
	uint32_t count = 0, max;
	uint32_t path_n, dev_state;
	char ch[24];
	uint_t nvl_len = 0;
	nvlist_t *nvl;
	nvlist_t **nvl_array = NULL;
	int i, j, flag;
	xmlDocPtr doc;
	xmlNodePtr rootNode, cardNode, iportNode, smpNode;
	xmlNodePtr propNodePtr = NULL;

	if(vers != TOPO_METH_DISK_STATUS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if(in_nvl == NULL)
		return 0;

	if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_TYPE, &type, &err) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));

	if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_PHYS_PATH, &iport_phys_path, &err) != 0){
		topo_mod_strfree(mod, type);
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));
	}

	if(strcmp(type, SAS_LINK)){
		LOG("mptsas_iport_smp_attach type error.\n");
		ret = -1;
		goto Done;
	}

	doc = xmlParseFile(XML_BACKUP_PATH);
	rootNode = xmlDocGetRootElement(doc);

	cardNode = rootNode->xmlChildrenNode;
	while(cardNode){

		if(!strcmp((char *)cardNode->name, "text")){
			cardNode = cardNode->next;
			continue;
		}

		iportNode = cardNode->xmlChildrenNode;
		while(iportNode){

			if(!strcmp((char *)iportNode->name, "text")){
				iportNode = iportNode->next;
				continue;
			}
			if(xmlHasProp(iportNode, BAD_CAST "phys_path")){
				if(!strcmp((char *)xmlGetProp(iportNode, BAD_CAST "phys_path"), iport_phys_path)){
					propNodePtr = iportNode;
					break;
				}
			}

			iportNode = iportNode->next;
		}

		if(propNodePtr)
			break;
		cardNode = cardNode->next;
	}

	if(!propNodePtr){
		LOG("failed to get iportNode in mptsas state dictionary.\n");
		ret = -1;
		goto xmlDone;
	}

	nvlist_lookup_nvlist_array(in_nvl, DEV_ACTION_ARRAY, &nvl_array, &nvl_len);
	for(i = 0; i < nvl_len; i++){

		nvl = nvl_array[i];
		nvlist_lookup_uint32(nvl, TOPO_LINK_STATE, &dev_state);
		nvlist_lookup_string(nvl, TOPO_LINK_NAME, &smp_phys_path);
		switch(dev_state){
			case DEV_STATE_DETACHED:

				smpNode = propNodePtr->xmlChildrenNode;
				while(smpNode){

					if(!strcmp((char *)smpNode->name, "text")){
						smpNode = smpNode->next;
						continue;
					}

					if(xmlHasProp(smpNode, BAD_CAST "phys_path")){
						if(!strcmp((char *)xmlGetProp(smpNode, BAD_CAST "phys_path"), smp_phys_path)){
							xmlUnlinkNode(smpNode);
							xmlFreeNode(smpNode);
							break;
						}
					}
					smpNode = smpNode->next;
				}
				break;
			case DEV_STATE_ATTACHED:
				smpNode = xmlNewChild(propNodePtr, NULL, BAD_CAST "smp", NULL);
				xmlNewProp(smpNode, BAD_CAST "phys_path", BAD_CAST smp_phys_path);
				break;
			default:
				LOG("mptsas_iport_smp_attach get a wrong DEV_STATE.");
				ret = -1;
				goto xmlDone;
		}
	}

	xmlSaveFormatFileEnc(XML_BACKUP_PATH, doc, "UTF-8", 1);
xmlDone:
	xmlFreeDoc(doc);
Done:
	topo_mod_strfree(mod, type);
	topo_mod_strfree(mod, iport_phys_path);
	if(nvl_array)
		for(i = 0; nvl_array[i]; i++)
			nvlist_free(nvl_array[i]);
	return ret;
}/*}}}*/

#if 0/*{{{*/
int get_all_card_iport(topo_mod_t *mod, const char *mptsas_card, drvnode_list_t **buf, int buf_len){

	int count = 0;
	conn_handle_t *chp = topo_mod_getspecific(mod);
	drvnode_list_t *dlp;
	phy_mptsas_portinfo_t *msip;

	if(!buf && buf_len == 0)
		return -1;

	for(dlp = chp->dn_table[DN_TABLE_MPTSAS_IPORT]; dlp; dlp = dlp->next){
		msip = (phy_mptsas_portinfo_t *)dlp->data;
		if(mptsas_card_iport_match(mptsas_card, msip->phys_path)){
			buf[count++] = dlp;
			if(count >= buf_len)
				break;
		}
	}

	return count;
}

int mptsas_card_monitor(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl){

	char *type, *phys_path;
	int err, ret = 0;
	int i, j;
	uint32_t count = 0;
	int realcount;
	char ch[24];
	char **array;
	phy_mptsas_portinfo_t *msip;
	int state[MPTSAS_CARD_IPORTS_MAX] = {0};
	drvnode_list_t *dl_array[MPTSAS_CARD_IPORTS_MAX];
	drvnode_list_t *dlp;
	conn_handle_t *chp = topo_mod_getspecific(mod);

#define nvlist_array_len 24
	nvlist_t *nvl_array[nvlist_array_len] = {0};
	nvlist_t *nvl;
	uint_t nvl_i = 0;

#if 1/*{{{*/
	if(vers != TOPO_METH_DISK_STATUS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if(out_nvl == NULL){
		LOG("mptsas_card_monitor parameter out_nvl mast not NULL.\n");
		return -1;
	}

	/*
	 * get link device type from topo node, because we need different
	 * methods to capture all kinds of link devices state.
	 */

	if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_TYPE, &type, &err) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));

	/* get link device phys_path from topo node. */
	phys_path = NULL;
	if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_PHYS_PATH, &phys_path, &err) != 0){
		topo_mod_strfree(mod, type);
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));
	}

	if(strcmp(type, SAS_LINK)){
		LOG("mptsas_card_monitor type error.\n");
		ret = -1;
		goto Done;
	}
#if 1
	/*
	 * free and fill the dn_table point by chp because we must run di_init to
	 * get lastest device snapshot
	 */
	if((chp->devtree = di_init("/", DINFOCPYALL)) == DI_NODE_NIL){
		LOG("failed to run di_init in mptsas_card_monitor.\n");
		return -1;
	}

	mptsas_smp_table_destroy(chp);
	if(mptsas_smp_table_init(chp)){
		LOG("failed to run mptsas_smp_table_init in mptsas_card_monitor.\n");
		return -1;
	}
	di_fini(chp->devtree);
#endif
#endif/*}}}*/

	LOG("\tmptsas_card_monitor I'm comming.\n");

#if 1
	if(topo_prop_get_uint32(nodep, TOPO_PGROUP_ATTACHED_IPORTS, TOPO_LINK_IPORT_MAX, &count, &err) != 0){
		LOG("can't get TOPO_LINK_IPORT_MAX in mptsas_card_monitor.\n");
		ret = -1;
		goto Done;
	}

	array = alloca(sizeof(char *) * (count + 1));
	bzero(array, sizeof(char *) * (count + 1));
	for(i = 0; i < count; i++){
		sprintf(ch, "%s%d", TOPO_LINK_PHYS_PATH, i);
		if(topo_prop_get_string(nodep, TOPO_PGROUP_ATTACHED_IPORTS, ch, array + i, &err) != 0){
			LOG("can't get %s in mptsas_card_monitor.\n", ch);
			ret = -1;
			goto Done;
		}
	}

	realcount = get_all_card_iport(mod, phys_path, dl_array, MPTSAS_CARD_IPORTS_MAX);

	/* decide if mat_sas card's iport is detached */
	for(i = 0; array[i]; i++){
		for(j = 0; j < realcount; j++){
			msip = (phy_mptsas_portinfo_t *)dl_array[j]->data;
			if(!strcmp(msip->phys_path, array[i])){
				/*
				 * set flag that indicate the phys_iport is in card's iport property
				 * then we traversal the array determine which is a NEW iport attached
				 * whth flag = 0;
				 */
				state[j] = 1;
				break;
			}
		}
		/* iport miss */
		if(j == realcount){
			/* I think it will never be run */
			nvlist_alloc(nvl_array + nvl_i, NV_UNIQUE_NAME, 0);
			nvlist_add_uint32(nvl_array[nvl_i], DEV_STATE, DEV_STATE_DETACHED);
			nvlist_add_uint32(nvl_array[nvl_i], DEV_PATH_KEY, i);
			nvlist_add_string(nvl_array[nvl_i], DEV_PATH, array[i]);
			nvl_i++;
			/* printf("iport %s missed.\n", array[i]); */
		}
	}

	for(i = 0; i < realcount; i++){
		if(!state[i]){
			/*
			 * @1: we must export instance##attached_port##initiator_port info,
			 * because a create a iport node need thess properties
			 */
			msip = (phy_mptsas_portinfo_t *)dl_array[i]->data;
			nvlist_alloc(nvl_array + nvl_i, NV_UNIQUE_NAME, 0);
			nvlist_add_uint32(nvl_array[nvl_i], DEV_STATE, DEV_STATE_ATTACHED);
			nvlist_add_uint32(nvl_array[nvl_i], "instance", msip->instance);
			nvlist_add_string(nvl_array[nvl_i], DEV_PATH, msip->phys_path);
			nvlist_add_string(nvl_array[nvl_i], "initiator_port", msip->initiator_port);
			nvlist_add_string(nvl_array[nvl_i], "attached_port", msip->attached_port);
			nvl_i++;
			/* printf("iport %s attached.\n", msip->phys_path);	*/
		}
	}
#endif
	if(nvl_i){
		nvlist_add_nvlist_array(nvl, DEV_ACTION_ARRAY, nvl_array, nvl_i);
		*out_nvl = nvl;
	}else
		*out_nvl = NULL;
#undef nvlist_array_len

Done:
	topo_mod_strfree(mod, type);
	topo_mod_strfree(mod, phys_path);
	for(i = 0; array[i]; i++)
		topo_mod_strfree(mod, array[i]);
	for(i = 0; nvl_array[i]; i++)
		nvlist_free(nvl_array[i]);
	return ret;
}

int mptsas_card_iport_attach(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl){

	int ret = 0, err;
	char *type, *phys_path;
	uint32_t count = 0, max;
	uint32_t path_n, dev_state;
	char ch[24];
	uint_t nvl_len = 0;
	nvlist_t *nvl;
	nvlist_t **nvl_array;
	int i, j, flag;

	phy_mptsas_portinfo_t pmspi;
	link_enum_data_t data;

	if(vers != TOPO_METH_DISK_STATUS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if(in_nvl == NULL)
		return 0;

	if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_TYPE, &type, &err) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));

	if(strcmp(type, SAS_LINK)){
		LOG("mptsas_iport_smp_attach type error.\n");
		ret = -1;
		goto Done;
	}

	/*
	 * init struct phy_mptsas_portinfo_t link_enum_data_t for run
	 * mptsas_iport_node_creat() in link_enum.c, make a iport tnode_t
	 * when a NEW iport is attached on card.
	 */
	bzero(&data, sizeof(data));
	data.ed_mod = mod;
	data.ed_label = NULL;
	data.ed_index = SAS_CONNLIST_INDEX;
	data.ed_name = type;
	data.ed_cnode = nodep;

	if(topo_prop_get_uint32(nodep, TOPO_PGROUP_ATTACHED_SMPS, TOPO_LINK_SMP_MAX, &max, &err) != 0){
		LOG("can't get TOPO_LINK_SMP_MAX in mptsas_iport_smp_attach.\n");
		ret = -1;
		goto Done;
	}

	nvlist_lookup_nvlist_array(in_nvl, DEV_ACTION_ARRAY, &nvl_array, &nvl_len);
	for(i = 0; i < nvl_len; i++){
		nvl = nvl_array[i];
		nvlist_lookup_uint32(nvl, DEV_STATE, &dev_state);
		switch(dev_state){
			case DEV_STATE_DETACHED:
				/* never be run */
				nvlist_lookup_uint32(nvl, DEV_PATH_KEY, &path_n);
				sprintf(ch, "%s%d", TOPO_LINK_PHYS_PATH, path_n);
				topo_prop_set_string(nodep, TOPO_PGROUP_ATTACHED_SMPS, ch, TOPO_PROP_MUTABLE, "nodev", &err);
				break;
			case DEV_STATE_ATTACHED:
				bzero(&pmspi, sizeof(pmspi));
				nvlist_lookup_uint32(nvl, "instance", (uint32_t *)&pmspi.instance);
				nvlist_lookup_string(nvl, DEV_PATH, &pmspi.phys_path);
				nvlist_lookup_string(nvl, "initiator_port", &pmspi.initiator_port);
				nvlist_lookup_string(nvl, "attached_port", &pmspi.attached_port);
				/* make a new iport node for card */
				mptsas_iport_node_creat(&pmspi, &data);
				break;
			default:
				LOG("mptsas_iport_smp_attach get a wrong DEV_STATE.");
				ret = -1;
				goto Done;
		}
	}
Done:
	topo_mod_strfree(mod, type);
	topo_mod_strfree(mod, phys_path);
	for(i = 0; nvl_array[i]; i++)
		nvlist_free(nvl_array[i]);
	return ret;
}

int get_all_iport_smp(topo_mod_t *mod, const char *mptsas_iport, drvnode_list_t **buf, int buf_len){/*{{{*/

	int count = 0;
	conn_handle_t *chp = topo_mod_getspecific(mod);
	drvnode_list_t *dlp;
	smp_info_t *sip;

	if(!buf && buf_len == 0)
		return -1;

	for(dlp = chp->dn_table[DN_TABLE_SMP]; dlp; dlp = dlp->next){
		sip = (smp_info_t *)dlp->data;
		if(mptsas_iport_smp_match(mptsas_iport, sip->phys_path)){
			buf[count++] = dlp;
			if(count >= buf_len)
				break;
		}
	}

	return count;
}/*}}}*/

int mptsas_iport_monitor(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl){/*{{{*/

	char *type, *phys_path;
	int err, ret = 0;
	int i, j;
	uint32_t count = 0;
	int realcount;
	char ch[24];
	char **array;
	smp_info_t *sip;
	int state[MPTSAS_IPORT_SMPS_MAX] = {0};
	drvnode_list_t *dl_array[MPTSAS_IPORT_SMPS_MAX];
	drvnode_list_t *dlp;
	conn_handle_t *chp = topo_mod_getspecific(mod);
	/*
	 * we assume It's impossable happen 24 insert/remove action in 5/10 secs.
	 */
#define nvlist_array_len 24
	nvlist_t *nvl_array[nvlist_array_len] = {0};
	nvlist_t *nvl;
	uint_t nvl_i = 0;

#if 1/*{{{*/
	if(vers != TOPO_METH_DISK_STATUS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if(out_nvl == NULL){
		LOG("mptsas_card_monitor parameter out_nvl mast not NULL.\n");
		return -1;
	}

	/*
	 * get link device type from topo node, because we need different
	 * methods to capture all kinds of link devices state.
	 */
	if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_TYPE, &type, &err) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));

	/* get link device phys_path from topo node. */
	phys_path = NULL;
	if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_PHYS_PATH, &phys_path, &err) != 0){
		topo_mod_strfree(mod, type);
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));
	}

	if(strcmp(type, SAS_LINK)){
		LOG("mptsas_card_monitor type error.\n");
		ret = -1;
		goto Done;
	}
#endif/*}}}*/

#if 1
	if(topo_prop_get_uint32(nodep, TOPO_PGROUP_ATTACHED_SMPS, TOPO_LINK_SMP_MAX, &count, &err) != 0){
		LOG("can't get TOPO_LINK_SMP_MAX in mptsas_card_monitor.\n");
		ret = -1;
		goto Done;
	}

	array = alloca(sizeof(char *) * (count + 1));
	bzero(array, sizeof(char *) * (count + 1));
	for(i = 0; i < count; i++){
		sprintf(ch, "%s%d", TOPO_LINK_PHYS_PATH, i);
		if(topo_prop_get_string(nodep, TOPO_PGROUP_ATTACHED_SMPS, ch, array + i, &err) != 0){
			LOG("can't get %s in mptsas_iport_monitor.\n", ch);
			ret = -1;
			goto Done;
		}
	}

	realcount = get_all_iport_smp(mod, phys_path, dl_array, MPTSAS_IPORT_SMPS_MAX);

#if 0/*{{{*/
	/* Just for debug */
	for(i = 0; array[i]; i++){
		printf("LHL ADD ++ arraypath %s\n", array[i]);
	}
	for(j = 0; j < realcount; j++){
		sip = (smp_info_t *)dl_array[j]->data;
		printf("\tLHL ADD ++ realpath %s\n", sip->phys_path);
	}
#endif /*}}}*/

	/* decide if mat_sas iport's smp is detached */
	for(i = 0; array[i]; i++){
		for(j = 0; j < realcount; j++){
			sip = (smp_info_t *)dl_array[j]->data;
			if(!strcmp(sip->phys_path, array[i])){
				/*
				 * set flag that indicate the smp_dev is in iport's property
				 * then we traversal the array determine which is a NEW smp attached
				 * whth flag = 0;
				 */
				state[j] = 1;
				break;
			}
		}
		/* smp miss */
		if(j == realcount){
			/* @1: we can export instance##attached_port##target_port info, but I don't want to */
			nvlist_alloc(nvl_array + nvl_i, NV_UNIQUE_NAME, 0);
			nvlist_add_uint32(nvl_array[nvl_i], DEV_STATE, DEV_STATE_DETACHED);
			nvlist_add_uint32(nvl_array[nvl_i], DEV_PATH_KEY, i);
			nvlist_add_string(nvl_array[nvl_i], DEV_PATH, array[i]);
			nvl_i++;
			/* printf("smp %s missed.\n", array[i]); */
		}
	}

	for(i = 0; i < realcount; i++){
		/* smp added */
		if(!state[i]){
			sip = (smp_info_t *)dl_array[i]->data;
			/* @2: like @1 */
			nvlist_alloc(nvl_array + nvl_i, NV_UNIQUE_NAME, 0);
			nvlist_add_uint32(nvl_array[nvl_i], DEV_STATE, DEV_STATE_ATTACHED);
			nvlist_add_string(nvl_array[nvl_i], DEV_PATH, sip->phys_path);
			nvl_i++;
			/* printf("smp %s attached.\n", sip->phys_path); */
		}
	}
#endif
	if(nvl_i){
		nvlist_add_nvlist_array(nvl, DEV_ACTION_ARRAY, nvl_array, nvl_i);
		*out_nvl = nvl;
	}else
		*out_nvl = NULL;
#undef nvlist_array_len
Done:
	topo_mod_strfree(mod, type);
	topo_mod_strfree(mod, phys_path);
	for(i = 0; array[i]; i++)
		topo_mod_strfree(mod, array[i]);
	for(i = 0; nvl_array[i]; i++)
		nvlist_free(nvl_array[i]);
	return ret;
}/*}}}*/

int mptsas_iport_smp_attach(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers, nvlist_t *in_nvl, nvlist_t **out_nvl){/*{{{*/

	int ret = 0, err;
	char *type, *phys_path;
	uint32_t count = 0, max;
	uint32_t path_n, dev_state;
	char ch[24];
	uint_t nvl_len = 0;
	nvlist_t *nvl;
	nvlist_t **nvl_array;
	int i, j, flag;

	if(vers != TOPO_METH_DISK_STATUS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if(in_nvl == NULL)
		return 0;

	if(topo_prop_get_string(nodep, TOPO_PGROUP_LINK_STATUS, TOPO_LINK_TYPE, &type, &err) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));

	if(strcmp(type, SAS_LINK)){
		LOG("mptsas_iport_smp_attach type error.\n");
		ret = -1;
		goto Done;
	}

	if(topo_prop_get_uint32(nodep, TOPO_PGROUP_ATTACHED_SMPS, TOPO_LINK_SMP_MAX, &max, &err) != 0){
		LOG("can't get TOPO_LINK_SMP_MAX in mptsas_iport_smp_attach.\n");
		ret = -1;
		goto Done;
	}

	nvlist_lookup_nvlist_array(in_nvl, DEV_ACTION_ARRAY, &nvl_array, &nvl_len);
	for(i = 0; i < nvl_len; i++){
		nvl = nvl_array[i];
		nvlist_lookup_uint32(nvl, DEV_STATE, &dev_state);
		switch(dev_state){
			case DEV_STATE_DETACHED:
				nvlist_lookup_uint32(nvl, DEV_PATH_KEY, &path_n);
				sprintf(ch, "%s%d", TOPO_LINK_PHYS_PATH, path_n);
				topo_prop_set_string(nodep, TOPO_PGROUP_ATTACHED_SMPS, ch, TOPO_PROP_MUTABLE, "nodev", &err);
				break;
			case DEV_STATE_ATTACHED:
				for(j = count; j < max; j++){
					sprintf(ch, "%s%d", TOPO_LINK_PHYS_PATH, j);
					if(topo_prop_get_string(nodep, TOPO_PGROUP_ATTACHED_SMPS, ch, &phys_path, &err) != 0){
						topo_mod_strfree(mod, type);
						return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));
					}
					if(!strcmp(phys_path, "nodev")){
						topo_mod_strfree(mod, phys_path);
						break;
					}
					topo_mod_strfree(mod, phys_path);
					count++;
				}
				nvlist_lookup_string(nvl, DEV_PATH, &phys_path);
				sprintf(ch, "%s%d", TOPO_LINK_PHYS_PATH, count);
				topo_prop_set_string(nodep, TOPO_PGROUP_ATTACHED_SMPS, ch, TOPO_PROP_MUTABLE, phys_path, &err);
				if(count >= max){
					max = ++count;
					if(topo_prop_set_uint32(nodep, TOPO_PGROUP_ATTACHED_SMPS, TOPO_LINK_SMP_MAX, TOPO_PROP_MUTABLE, max, &err)){
						topo_mod_dprintf(mod, "link_set_props: set link name error %s\n", topo_strerror(err));
						return -1;
					}
				}
				break;
			default:
				LOG("mptsas_iport_smp_attach get a wrong DEV_STATE.");
				ret = -1;
				goto Done;
		}
	}
Done:
	topo_mod_strfree(mod, type);
	topo_mod_strfree(mod, phys_path);
	for(i = 0; nvl_array[i]; i++)
		nvlist_free(nvl_array[i]);
	return ret;
}/*}}}*/
#endif/*}}}*/
#endif
