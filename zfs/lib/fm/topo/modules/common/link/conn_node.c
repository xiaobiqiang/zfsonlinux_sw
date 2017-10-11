#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include <topo_list.h>
#include <topo_mod.h>

#include "link_enum.h"

/* fma topo module has provide list operate interface */
#if 0
void conn_node_append(conn_node_list_t *list, conn_t *node){/*{{{*/

	conn_t *cp, *pre_cp;

	if(!(list && node))
		return ;

	pre_cp = cp = list->node_list;
	node->next = NULL;

	if(list->node_list){
		while(cp = cp->next)
			pre_cp = cp;
		pre_cp->next = node;
	}else
		list->node_list = node;
}/*}}}*/

void conn_node_insert_head(conn_node_list_t *list, conn_t *node){/*{{{*/

	if(!(list && node))
		return ;

	node->next = list->node_list;
	list->node_list = node;
}/*}}}*/

void conn_node_unlink(conn_node_list_t *list, conn_t *node){/*{{{*/

	conn_t *cp, *pre_cp;

	if(!(list && node))
		return ;

	pre_cp = cp = list->node_list;

	if(list->node_list){
		while(cp = cp->next){
			if(cp == node)
				break;
			pre_cp = cp;
		}
		pre_cp->next = node->next;
	}else
		return ;
}/*}}}*/
#endif

int conn_node_creat(conn_handle_t *chp, const char *type, const char *name, unsigned int state){/*{{{*/
	int index;
	conn_t *cp;
	topo_mod_t *mod = chp->ch_mod;
	conn_node_list_t *table = chp->conn_table;

	if(!(chp && type && name)){
		LOG("conn_node_creat invalid parameter.\n");
		return -1;
	}
	if(!strcmp(type, "fc_link"))
		index = FC_CONNLIST_INDEX;
	else if(!strcmp(type, "ethernet_link"))
		index = ENET_CONNLIST_INDEX;
	else if(!strcmp(type, "sas_link"))	/* not use now */
		index = SAS_CONNLIST_INDEX;
	else if(!strcmp(type, "heart_link"))
		index = HEART_CONNLIST_INDEX;
	else{
		LOG("conn_node_creat error type\n");
		return -1;
	}

	if(!table[index].name)
		if(!(table[index].name = topo_mod_strdup(mod, type))){
			LOG("no memary in conn_node_alloc list.name\n");
			return -1;
		}

	for(cp = topo_list_next(&table[index].node_list); cp; cp = topo_list_next(cp)){
		/*
		 * if we already have a node with name $name just update state
		 * and change node.losted to macro DEV_IS_EXISTED.
		 */
		if(!strcmp(cp->name, name)){
			cp->state = state;
			cp->losted = DEV_IS_EXISTED;
			return 0;
		}
	}

	/*
	 * if we do not have a node who's name is $name create it and
	 * init the name & state & losted = DEV_IS_INSERTED.
	 */
	if(!cp)
		if(!(cp = (conn_t *)topo_mod_zalloc(mod, sizeof(conn_t)))){
			LOG("no memary in conn_node_creat conn_t\n");
			return -1;
		}

	if(!(cp->name = topo_mod_strdup(mod, name))){
		LOG("no memary in conn_node_creat conn_t.name\n");
		topo_mod_free(mod, cp, sizeof(conn_t));
		return -1;
	}

	cp->state = state;
	cp->losted = DEV_IS_INSERTED;
	#if 0
	printf("%s, %d, name: %s, type: %s.\n", cp->name, cp->state, table[index].name, type);
	#endif
	topo_list_append((topo_list_t *)&table[index].node_list, cp);
	table[index].node_n++;
	LOG("INIT TABLE:%s ,%s\n", type, name);

	return 0;
}/*}}}*/

int conn_node_list_walk(conn_node_list_t *list, conn_walk_ops_t *walk){/*{{{*/

	conn_t *cp;

	if(!(list && walk)){
		LOG("conn_node_list_dump the list or walk have been fucked\n");
		return -1;
	}

	if(walk->for_each_list)
		walk->for_each_list(list, walk->priv);
	if(walk->for_each_node)
		for(cp = topo_list_next(&list->node_list); cp; cp = topo_list_next(cp))
			walk->for_each_node(cp, walk->priv);

	return 0;
}/*}}}*/

int conn_node_table_walk(conn_node_list_t *table, conn_walk_ops_t *walk){/*{{{*/

	int i;

	if(!table)
		return -1;

	for(i = 0; i < CONNLIST_INDEX_MAX; i++){
		if((table + i)->node_n)
			conn_node_list_walk(table + i, walk);
	}

	return 0;
}/*}}}*/

/* free the table *//*{{{*/
void link_node_free(topo_mod_t *mod, conn_t *cp){

	topo_mod_strfree(mod, cp->name);
	topo_mod_free(mod, cp, sizeof *cp);
}

void link_table_free(topo_mod_t *mod, conn_node_list_t *table){
	conn_node_list_t *list;
	conn_t *cp;
	int i;

	for(i = 0; i < CONNLIST_INDEX_MAX; i++){
		list = table + i;
		if(list->node_n){
			while((cp = (conn_t *)topo_list_next(list)) != NULL){

				topo_list_delete((topo_list_t *)list, cp);
				link_node_free(mod, cp);
			}
			topo_mod_strfree(mod, list->name);
		}
	}
}/*}}}*/
