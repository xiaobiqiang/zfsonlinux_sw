/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <stddef.h>
#include <pthread.h>
#include <syslog.h>
#include <assert.h>
#include <libstmf.h>
#include <libcomm.h>
#include <stmf_msg.h>
#include "store.h"

extern boolean_t s_store_init;

void
stmf_add_group_member(char *arg, int len, char **rval, int *rlen)
{
	cmd_add_group_member_t *cmd = (cmd_add_group_member_t *)arg;
	ack_common_t *ack = malloc(sizeof(ack_common_t));

	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	if (cmd->type == HOST_GROUP)
		ack->st = psAddHostGroupMember(cmd->group, cmd->member);
	else
		ack->st = psAddTargetGroupMember(cmd->group, cmd->member);
	
	*rval = (char *)ack;
	*rlen = sizeof(ack_common_t);
}

void
stmf_add_view_entry(char *arg, int len, char **rval, int *rlen)
{
	cmd_add_view_entry_t *cmd = (cmd_add_view_entry_t *)arg;
	ack_common_t *ack = malloc(sizeof(ack_common_t));

	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);
	
	ack->st = psAddViewEntry(&cmd->lu, &cmd->viewEntry);
	*rval = (char *)ack;
	*rlen = sizeof(ack_common_t);
}

void
stmf_create_group(char *arg, int len, char **rval, int *rlen)
{
	cmd_create_group_t *cmd = (cmd_create_group_t *)arg;
	ack_common_t *ack = malloc(sizeof(ack_common_t));

	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);
	
	if (cmd->type == HOST_GROUP)
		ack->st = psCreateHostGroup(cmd->group);
	else
		ack->st = psCreateTargetGroup(cmd->group);
	
	*rval = (char *)ack;
	*rlen = sizeof(ack_common_t);
}

void
stmf_delete_group(char *arg, int len, char **rval, int *rlen)
{
	cmd_delete_group_t *cmd = (cmd_delete_group_t *)arg;
	ack_common_t *ack = malloc(sizeof(ack_common_t));

	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	if (cmd->type == HOST_GROUP)
		ack->st = psDeleteHostGroup(cmd->group);
	else
		ack->st = psDeleteTargetGroup(cmd->group);
	
	*rval = (char *)ack;
	*rlen = sizeof(ack_common_t);
}

void
stmf_get_view_entry(char *arg, int len, char **rval, int *rlen)
{
	cmd_get_view_entry_t *cmd = (cmd_get_view_entry_t *)arg;
	ack_get_view_entry_t *ack = malloc(sizeof(ack_get_view_entry_t));
	
	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);
	
	ack->st = psGetViewEntry(&cmd->lu, cmd->ve_index, &ack->ve);
	*rval = (char *)ack;
	*rlen = sizeof(ack_get_view_entry_t);
}

void
stmf_get_logcial_unit_list(char *arg, int len, char **rval, int *rlen)
{
	char *buf;
	int ack_len;
	stmfGuidList *guidList = NULL;
	ack_get_lu_list_t *ack;
	int ret;

	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);
	
	ret = psGetLogicalUnitList(&guidList);
	if (ret == STMF_PS_SUCCESS) {
		ack_len = sizeof (ack_get_lu_list_t) + guidList->cnt * sizeof (stmfGuid);
		buf = malloc(ack_len);
		if (!buf)
			ret = STMF_PS_ERROR_NOMEM;
	}

	if (ret != STMF_PS_SUCCESS) {
		ack_len = sizeof (ack_get_lu_list_t);
		buf = malloc(ack_len);
		memset(buf, 0, ack_len);
	}

	ack = (ack_get_lu_list_t *)buf;
	ack->st = ret;
	if (ret == STMF_PS_SUCCESS) {
		int i;
		ack->lu_list.cnt = guidList->cnt;
		for (i = 0; i < guidList->cnt; i++) {
			memcpy(&(ack->lu_list.guid[i]), &(guidList->guid[i]),
				sizeof(stmfGuid));
		}
	}
	
	*rval = (char *)ack;
	*rlen = ack_len;
}

void
stmf_remove_group_member(char *arg, int len, char **rval, int *rlen)
{
	cmd_remove_group_member_t *cmd = (cmd_remove_group_member_t *)arg;
	ack_common_t *ack = malloc(sizeof(ack_common_t));
	
	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	if (cmd->type == HOST_GROUP)
		ack->st = psRemoveHostGroupMember(cmd->group, cmd->member);
	else
		ack->st = psRemoveTargetGroupMember(cmd->group, cmd->member);
	
	*rval = (char *)ack;
	*rlen = sizeof(ack_common_t);
}

void
stmf_remove_view_entry(char *arg, int len, char **rval, int *rlen)
{
	cmd_remove_view_entry_t *cmd = (cmd_remove_view_entry_t *)arg;
	ack_common_t *ack = malloc(sizeof(ack_common_t));
	
	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	ack->st = psRemoveViewEntry(&cmd->lu, cmd->ve_index);
	*rval = (char *)ack;
	*rlen = sizeof(ack_common_t);
}

void
stmf_get_group_list(char *arg, int len, char **rval, int *rlen)
{
	char *buf;
	int ack_len;
	stmfGroupList *groupList = NULL;
	cmd_get_group_list_t *cmd = (cmd_get_group_list_t *)arg;
	ack_get_group_list_t *ack;
	int ret;

	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	if (cmd->type == HOST_GROUP)
		ret = psGetHostGroupList(&groupList);
	else
		ret = psGetTargetGroupList(&groupList);

	if (ret == STMF_PS_SUCCESS) {
		ack_len = sizeof (ack_get_group_list_t) + 
			groupList->cnt * sizeof (stmfGroupName);
		buf = malloc(ack_len);
		if (!buf)
			ret = STMF_PS_ERROR_NOMEM;
	}

	if (ret != STMF_PS_SUCCESS) {
		ack_len = sizeof (ack_get_group_list_t);
		buf = malloc(ack_len);
		memset(buf, 0, ack_len);
	}

	ack = (ack_get_group_list_t *)buf;
	ack->st = ret;
	if (ret == STMF_PS_SUCCESS) {
		int i;
		ack->group_list.cnt = groupList->cnt;
		for (i = 0; i < groupList->cnt; i++) {
			memcpy(ack->group_list.name[i], groupList->name[i],
				sizeof(stmfGroupName));
		}
	}
	
	*rval = (char *)ack;
	*rlen = ack_len;
}

void
stmf_get_group_member_list(char *arg, int len, char **rval, int *rlen)
{
	char *buf;
	int ack_len;
	stmfGroupProperties *groupMemberList = NULL;
	cmd_get_group_member_list_t *cmd = (cmd_get_group_member_list_t *)arg;
	ack_get_group_member_list_t *ack;
	int ret;

	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	if (cmd->type == HOST_GROUP)
		ret = psGetHostGroupMemberList(cmd->group, &groupMemberList);
	else
		ret = psGetTargetGroupMemberList(cmd->group, &groupMemberList);

	if (ret == STMF_PS_SUCCESS) {
		ack_len = sizeof (ack_get_group_member_list_t) + 
			groupMemberList->cnt * sizeof (stmfDevid);
		buf = malloc(ack_len);
		if (!buf)
			ret = STMF_PS_ERROR_NOMEM;
	}

	if (ret != STMF_PS_SUCCESS) {
		ack_len = sizeof (ack_get_group_member_list_t);
		buf = malloc(ack_len);
		memset(buf, 0, ack_len);
	}

	ack = (ack_get_group_member_list_t *)buf;
	ack->st = ret;
	if (ret == STMF_PS_SUCCESS) {
		int i;
		ack->prop_list.cnt = groupMemberList->cnt;
		for (i = 0; i < groupMemberList->cnt; i++) {
			memcpy(&(ack->prop_list.name[i]), 
				&(groupMemberList->name[i]),
				sizeof(stmfDevid));
		}
	}
	
	*rval = (char *)ack;
	*rlen = ack_len;
}

void
stmf_get_view_entry_list(char *arg, int len, char **rval, int *rlen)
{
	char *buf;
	int ack_len;
	stmfViewEntryList *viewEntryList = NULL;
	cmd_get_view_entry_list_t *cmd = (cmd_get_view_entry_list_t *)arg;
	ack_get_view_entry_list_t *ack;
	int ret;

	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	ret = psGetViewEntryList(&cmd->lu, &viewEntryList);
	if (ret == STMF_PS_SUCCESS) {
		ack_len = sizeof (ack_get_view_entry_list_t) + 
			viewEntryList->cnt * sizeof (stmfViewEntry);
		buf = malloc(ack_len);
		if (!buf)
			ret = STMF_PS_ERROR_NOMEM;
	}

	if (ret != STMF_PS_SUCCESS) {
		ack_len = sizeof (ack_get_view_entry_list_t);
		buf = malloc(ack_len);
		memset(buf, 0, ack_len);
	}

	ack = (ack_get_view_entry_list_t *)buf;
	ack->st = ret;
	if (ret == STMF_PS_SUCCESS) {
		int i;
		ack->ve_list.cnt = viewEntryList->cnt;
		for (i = 0; i < viewEntryList->cnt; i++) {
			memcpy(&(ack->ve_list.ve[i]), 
				&(viewEntryList->ve[i]),
				sizeof(stmfViewEntry));
		}
	}
	
	*rval = (char *)ack;
	*rlen = ack_len;
}

void
stmf_check_service(char *arg, int len, char **rval, int *rlen)
{
	ack_common_t *ack = malloc(sizeof(ack_common_t));
		
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	if (s_store_init)
		ack->st = STMF_PS_SUCCESS;
	else
		ack->st = STMF_PS_ERROR_DB_NOT_LOAD;
	*rval = (char *)ack;
	*rlen = sizeof(ack_common_t);
}

void
stmf_set_provider_data(char *arg, int len, char **rval, int *rlen)
{
	cmd_set_provider_data_t *cmd = (cmd_set_provider_data_t *)arg;
	ack_common_t *ack = malloc(sizeof(ack_common_t));
	nvlist_t *nvl = NULL;
	
	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	if (nvlist_unpack(cmd->data, cmd->data_len, &nvl, 0) != 0) {
		syslog(LOG_ERR, "unable to unpack nvlist");
		ack->st = STMF_PS_ERROR;
		goto out;
	}

	ack->st = psSetProviderData(cmd->provider, nvl, cmd->type, &cmd->set_cnt);
	nvlist_free(nvl);

out:
	*rval = (char *)ack;
	*rlen = sizeof(ack_common_t);
}

void
stmf_get_provider_data(char *arg, int len, char **rval, int *rlen)
{
	cmd_get_provider_data_t *cmd = (cmd_get_provider_data_t *)arg;
	ack_get_provider_data_t	*ack;
	nvlist_t *nvl = NULL;
	char *nvlistEncoded = NULL;
	size_t nvlistEncodedSize;
	int setToken = 0;
	int ack_len;
	int ret;
	
	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	ret = psGetProviderData(cmd->provider, &nvl, cmd->type, &setToken);

	ack_len = sizeof(ack_get_provider_data_t);
	ack = malloc(ack_len);
	memset(ack, 0, ack_len);
	ack->st = ret;
	strncpy(ack->provider, cmd->provider, sizeof(ack->provider));
	ack->type = cmd->type;
	ack->set_cnt = setToken;
	ack->data_len = 0;

	if (nvl) {
		if (nvlist_pack(nvl, &nvlistEncoded, &nvlistEncodedSize,
	    	NV_ENCODE_XDR, 0) != 0) {
			syslog(LOG_ERR, "nvlist_pack failed");
			ack->st = STMF_PS_ERROR_NOMEM;
			goto out;
		}

		ack->data_len = nvlistEncodedSize;
		ack_len = sizeof(ack_get_provider_data_t) + nvlistEncodedSize - 1;
		ack = realloc(ack, ack_len);
		memcpy(ack->data, nvlistEncoded, nvlistEncodedSize);
		nvlist_free(nvl);
		free(nvlistEncoded);	
	}
	
out:
	*rval = (char *)ack;
	*rlen = ack_len;
}

void
stmf_get_provider_data_list(char *arg, int len, char **rval, int *rlen)
{
	char *buf;
	int ack_len;
	stmfProviderList *providerList = NULL;
	ack_get_provider_data_list_t *ack;
	int ret;

	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);
	
	ret = psGetProviderDataList(&providerList);
	if (ret == STMF_PS_SUCCESS) {
		ack_len = sizeof (ack_get_provider_data_list_t) + 
			providerList->cnt * sizeof (stmfProvider);
		buf = malloc(ack_len);
		if (!buf)
			ret = STMF_PS_ERROR_NOMEM;
	}

	if (ret != STMF_PS_SUCCESS) {
		ack_len = sizeof (ack_get_provider_data_list_t);
		buf = malloc(ack_len);
		memset(buf, 0, ack_len);
	}

	ack = (ack_get_provider_data_list_t *)buf;
	ack->st = ret;
	if (ret == STMF_PS_SUCCESS) {
		int i;
		ack->provider_list.cnt = providerList->cnt;
		for (i = 0; i < providerList->cnt; i++) {
			memcpy(&(ack->provider_list.provider[i]), 
				&(providerList->provider[i]),
				sizeof(stmfProvider));
		}
	}
	
	*rval = (char *)ack;
	*rlen = ack_len;
}

void
stmf_clear_provider_data(char *arg, int len, char **rval, int *rlen)
{
	cmd_clear_provider_data_t *cmd = (cmd_clear_provider_data_t *)arg;
	ack_common_t *ack = malloc(sizeof(ack_common_t));
	
	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	ack->st = psClearProviderData(cmd->provider, cmd->type);
	*rval = (char *)ack;
	*rlen = sizeof(ack_common_t);	
}

void
stmf_set_service_persist(char *arg, int len, char **rval, int *rlen)
{
	cmd_set_service_persist_t *cmd = (cmd_set_service_persist_t *)arg;
	ack_common_t *ack = malloc(sizeof(ack_common_t));
	
	ASSERT(arg != NULL);
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	ack->st = psSetServicePersist(cmd->type);
	*rval = (char *)ack;
	*rlen = sizeof(ack_common_t);
}

void
stmf_get_service_persist(char *arg, int len, char **rval, int *rlen)
{
	ack_get_service_persist_t *ack = malloc(sizeof(ack_get_service_persist_t));
	
	ASSERT(rval != NULL);
	ASSERT(rlen != NULL);

	ack->st = psGetServicePersist(&ack->persist_type);
	*rval = (char *)ack;
	*rlen = sizeof(ack_get_service_persist_t);
}

msg_handler_t stmf_msg_handler_table[] = {
	{STMF_MSG_ADD_GROUP_MEMBER,		&stmf_add_group_member},
	{STMF_MSG_ADD_VIEW_ENTRY,		&stmf_add_view_entry},
	{STMF_MSG_CREATE_GROUP,			&stmf_create_group},
	{STMF_MSG_DELETE_GROUP,			&stmf_delete_group},
	{STMF_MSG_GET_VIEW_ENTRY,		&stmf_get_view_entry},
	{STMF_MSG_GET_LOGICAL_UNIT_LIST,	&stmf_get_logcial_unit_list},
	{STMF_MSG_REMOVE_GROUP_MEMBER,	&stmf_remove_group_member},
	{STMF_MSG_REMOVE_VIEW_ENTRY,	&stmf_remove_view_entry},
	{STMF_MSG_GET_GROUP_LIST,		&stmf_get_group_list},
	{STMF_MSG_GET_GROUP_MEMBER_LIST,	&stmf_get_group_member_list},
	{STMF_MSG_GET_VIEW_ENTRY_LIST,	&stmf_get_view_entry_list},
	{STMF_MSG_CHECK_SERVICE,		&stmf_check_service},
	{STMF_MSG_SET_PROVIDER_DATA,	&stmf_set_provider_data},
	{STMF_MSG_GET_PROVIDER_DATA,	&stmf_get_provider_data},
	{STMF_MSG_GET_PROVIDER_DATA_LIST,	&stmf_get_provider_data_list},
	{STMF_MSG_CLEAR_PROVIDER_DATA,	&stmf_clear_provider_data},
	{STMF_MSG_SET_SERVICE_PERSIST,	&stmf_set_service_persist},
	{STMF_MSG_GET_SERVICE_PERSIST,	&stmf_get_service_persist},
	{-1, NULL}
};


