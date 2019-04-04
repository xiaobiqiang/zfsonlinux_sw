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
#include <libstmf.h>
#include <libnvpair.h>
#include <libcomm.h>
#include <stmf_msg.h>
#include "stmf_comm.h"

#define	CONFIGD_MSG_QUEUE	"/configd_msgq"
#define	COMM_SERVICE		"configd"

int 
stmfCommInit(void)
{
	return comm_init(COMM_TYPE_CLIENT, CONFIGD_MSG_QUEUE);
}

void 
stmfCommFini(void)
{
	return comm_fini();
}

int
stmfCommState(void)
{
	return comm_state();
}


static int
stmfCommAddGroupMember(char *groupName, char *memberName, int type)
{
	ack_common_t *ack = NULL;
	cmd_add_group_member_t cmd;
	int ret;

	memset(&cmd, 0, sizeof(cmd_add_group_member_t));
	strncpy(cmd.group, groupName, sizeof(cmd.group));
	strncpy(cmd.member, memberName, sizeof(cmd.member));
	cmd.type = type;

	ret = comm_send_msg(STMF_MSG_ADD_GROUP_MEMBER, (char *)&cmd, 
		sizeof(cmd_add_group_member_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS)
		ret = ack->st;
	else
		ret = STMF_PS_ERROR_COMM;

	if (ack)
		free(ack);
	
	return (ret);
}

int 
stmfCommAddHostGroupMember(char *groupName, char *memberName)
{
	return stmfCommAddGroupMember(groupName, memberName, HOST_GROUP);
}

int 
stmfCommAddTargetGroupMember(char *groupName, char *memberName)
{
	return stmfCommAddGroupMember(groupName, memberName, TARGET_GROUP);
}

int 
stmfCommAddViewEntry(stmfGuid *lu, stmfViewEntry *viewEntry)
{
	ack_common_t *ack = NULL;
	cmd_add_view_entry_t cmd;
	int ret;

	memset(&cmd, 0, sizeof(cmd_add_view_entry_t));
	memcpy(&cmd.lu, lu, sizeof(stmfGuid));
	memcpy(&cmd.viewEntry, viewEntry, sizeof(stmfViewEntry));

	ret = comm_send_msg(STMF_MSG_ADD_VIEW_ENTRY, (char *)&cmd, 
		sizeof(cmd_add_view_entry_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS)
		ret = ack->st;
	else
		ret = STMF_PS_ERROR_COMM;

	if (ack)
		free(ack);
	
	return (ret);
}

static int
stmfCommCreateGroup(char *groupName, int type)
{
	ack_common_t *ack = NULL;
	cmd_create_group_t cmd;
	int ret;

	memset(&cmd, 0, sizeof(cmd_create_group_t));
	strncpy(cmd.group, groupName, sizeof(cmd.group));
	cmd.type = type;

	ret = comm_send_msg(STMF_MSG_CREATE_GROUP, (char *)&cmd, 
		sizeof(cmd_create_group_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS)
		ret = ack->st;
	else
		ret = STMF_PS_ERROR_COMM;

	if (ack)
		free(ack);
	
	return (ret);
}

static int
stmfCommDeleteGroup(char *groupName, int type)
{
	ack_common_t *ack = NULL;
	cmd_delete_group_t cmd;
	int ret;

	memset(&cmd, 0, sizeof(cmd_delete_group_t));
	strncpy(cmd.group, groupName, sizeof(cmd.group));
	cmd.type = type;

	ret = comm_send_msg(STMF_MSG_DELETE_GROUP, (char *)&cmd, 
		sizeof(cmd_delete_group_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS)
		ret = ack->st;
	else
		ret = STMF_PS_ERROR_COMM;

	if (ack)
		free(ack);
	
	return (ret);

}

int 
stmfCommCreateHostGroup(char *groupName)
{
	return stmfCommCreateGroup(groupName, HOST_GROUP);
}

int 
stmfCommDeleteHostGroup(char *groupName)
{
	return stmfCommDeleteGroup(groupName, HOST_GROUP);
}

int 
stmfCommCreateTargetGroup(char *groupName)
{
	return stmfCommCreateGroup(groupName, TARGET_GROUP);
}

int 
stmfCommDeleteTargetGroup(char *groupName)
{
	return stmfCommDeleteGroup(groupName, TARGET_GROUP);
}

int 
stmfCommGetViewEntry(stmfGuid *lu, uint32_t viewEntryIndex, stmfViewEntry *ve)
{
	cmd_get_view_entry_t cmd;
	ack_get_view_entry_t *ack = NULL;
	int ret;

	if (!ve)
		return (STMF_PS_ERROR_INVALID_ARG);

	memset(ve, 0, sizeof(stmfViewEntry));
	memset(&cmd, 0, sizeof(cmd_get_view_entry_t));
	memcpy(&cmd.lu, lu, sizeof(stmfGuid));
	cmd.ve_index = viewEntryIndex;

	ret = comm_send_msg(STMF_MSG_GET_VIEW_ENTRY, (char *)&cmd, 
		sizeof(cmd_get_view_entry_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS) {
		ret = ack->st;
		if (ret == STMF_PS_SUCCESS)
			memcpy(ve, &ack->ve, sizeof(stmfViewEntry));
	} else {
		ret = STMF_PS_ERROR_COMM;
	}

	if (ack)
		free(ack);
	
	return (ret);
}

int 
stmfCommGetLogicalUnitList(stmfGuidList **guidList)
{
	ack_get_lu_list_t *ack = NULL;
	int ret;

	if (!guidList)
		return (STMF_PS_ERROR_INVALID_ARG);

	ret = comm_send_msg(STMF_MSG_GET_LOGICAL_UNIT_LIST, NULL, 
		0, (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS) {
		ret = ack->st;
		if (ret == STMF_PS_SUCCESS) {
			int i;
			int cnt = ack->lu_list.cnt;
			*guidList = (stmfGuidList *)calloc(1, sizeof (stmfGuidList) + 
				cnt * sizeof (stmfGuid));
			if (*guidList == NULL) {
				ret = STMF_PS_ERROR_NOMEM;
				goto out;
			}

			(*guidList)->cnt = cnt;
			for (i = 0; i < cnt; i++) {
				memcpy(&((*guidList)->guid[i]), &(ack->lu_list.guid[i]), 
					sizeof(stmfGuid));
			}
		}
	} else {
		ret = STMF_PS_ERROR_COMM;
	}

out:
	if (ack)
		free(ack);
	
	return (ret);
}

static int
stmfCommRemoveGroupMember(char *groupName, char *memberName, int type)
{
	ack_common_t *ack = NULL;
	cmd_remove_group_member_t cmd;
	int ret;

	memset(&cmd, 0, sizeof(cmd_remove_group_member_t));
	strncpy(cmd.group, groupName, sizeof(cmd.group));
	strncpy(cmd.member, memberName, sizeof(cmd.member));
	cmd.type = type;

	ret = comm_send_msg(STMF_MSG_REMOVE_GROUP_MEMBER, (char *)&cmd, 
		sizeof(cmd_remove_group_member_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS)
		ret = ack->st;
	else
		ret = STMF_PS_ERROR_COMM;

	if (ack)
		free(ack);
	
	return (ret);
}

int 
stmfCommRemoveHostGroupMember(char *groupName, char *memberName)
{
	return stmfCommRemoveGroupMember(groupName, memberName, HOST_GROUP);
}

int 
stmfCommRemoveTargetGroupMember(char *groupName, char *memberName)
{
	return stmfCommRemoveGroupMember(groupName, memberName, TARGET_GROUP);
}

int 
stmfCommRemoveViewEntry(stmfGuid *lu, uint32_t viewEntryIndex)
{
	ack_common_t *ack = NULL;
	cmd_remove_view_entry_t cmd;
	int ret;

	memset(&cmd, 0, sizeof(cmd_remove_view_entry_t));
	memcpy(&cmd.lu, lu, sizeof(stmfGuid));
	cmd.ve_index = viewEntryIndex;

	ret = comm_send_msg(STMF_MSG_REMOVE_VIEW_ENTRY, (char *)&cmd, 
		sizeof(cmd_remove_view_entry_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS)
		ret = ack->st;
	else
		ret = STMF_PS_ERROR_COMM;

	if (ack)
		free(ack);
	
	return (ret);
}

static int
stmfCommGetGroupList(int type, stmfGroupList **groupList)
{
	cmd_get_group_list_t cmd;
	ack_get_group_list_t *ack = NULL;
	int ret;

	if (!groupList)
		return (STMF_PS_ERROR_INVALID_ARG);

	cmd.type = type;
	ret = comm_send_msg(STMF_MSG_GET_GROUP_LIST, (char *)&cmd, 
		sizeof(cmd_get_group_list_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS) {
		ret = ack->st;
		if (ret == STMF_PS_SUCCESS) {
			int i;
			int cnt = ack->group_list.cnt;			
			*groupList = (stmfGroupList *)calloc(1, sizeof (stmfGroupList) +
				cnt * sizeof (stmfGroupName));
			if (*groupList == NULL) {
				ret = STMF_PS_ERROR_NOMEM;
				goto out;
			}

			(*groupList)->cnt = cnt;
			for (i = 0; i < cnt; i++) {
				memcpy(&((*groupList)->name[i]), &(ack->group_list.name[i]),
					sizeof(stmfGroupName));
			}
		}
	} else {
		ret = STMF_PS_ERROR_COMM;
	}

out:
	if (ack)
		free(ack);
	
	return (ret);
}

int 
stmfCommGetHostGroupList(stmfGroupList **groupList)
{
	return stmfCommGetGroupList(HOST_GROUP, groupList);
}

int 
stmfCommGetTargetGroupList(stmfGroupList **groupList)
{
	return stmfCommGetGroupList(TARGET_GROUP, groupList);
}

static int
stmfCommGetGroupMemberList(char *groupName, int type, 
	stmfGroupProperties **groupMemberList)
{
	cmd_get_group_member_list_t cmd;
	ack_get_group_member_list_t *ack = NULL;
	int ret;

	if (!groupMemberList)
		return (STMF_PS_ERROR_INVALID_ARG);

	memset(&cmd, 0, sizeof(cmd_get_group_member_list_t));
	strncpy(cmd.group, groupName, sizeof(cmd.group));
	cmd.type = type;
	ret = comm_send_msg(STMF_MSG_GET_GROUP_MEMBER_LIST, (char *)&cmd, 
		sizeof(cmd_get_group_member_list_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS) {
		ret = ack->st;
		if (ret == STMF_PS_SUCCESS) {
			int i;
			int cnt = ack->prop_list.cnt;
			*groupMemberList = (stmfGroupProperties *)calloc(1,
				sizeof (stmfGroupProperties) + cnt * sizeof (stmfDevid));
			if (*groupMemberList == NULL) {
				ret = STMF_PS_ERROR_NOMEM;
				goto out;
			}

			(*groupMemberList)->cnt = cnt;
			for (i = 0; i < cnt; i++) {
				memcpy(&((*groupMemberList)->name[i]), 
					&(ack->prop_list.name[i]),
					sizeof(stmfDevid));
			}
		}
	} else {
		ret = STMF_PS_ERROR_COMM;
	}

out:
	if (ack)
		free(ack);
	
	return (ret);
}


int 
stmfCommGetHostGroupMemberList(char *groupName, 
	stmfGroupProperties **groupMemberList)
{
	return stmfCommGetGroupMemberList(groupName, HOST_GROUP, groupMemberList);
}

int 
stmfCommGetTargetGroupMemberList(char *groupName,
    stmfGroupProperties **groupMemberList)
{
	return stmfCommGetGroupMemberList(groupName, TARGET_GROUP, groupMemberList);
}

int 
stmfCommGetViewEntryList(stmfGuid *lu, stmfViewEntryList **viewEntryList)
{
	cmd_get_view_entry_list_t cmd;
	ack_get_view_entry_list_t *ack = NULL;
	int ret;

	if (!viewEntryList)
		return (STMF_PS_ERROR_INVALID_ARG);

	memset(&cmd, 0, sizeof(cmd_get_view_entry_list_t));
	memcpy(&cmd.lu, lu, sizeof(stmfGuid));
	ret = comm_send_msg(STMF_MSG_GET_VIEW_ENTRY_LIST, (char *)&cmd, 
		sizeof(cmd_get_view_entry_list_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS) {
		ret = ack->st;
		if (ret == STMF_PS_SUCCESS) {
			int i;
			int cnt = ack->ve_list.cnt;
			*viewEntryList = (stmfViewEntryList *)calloc(1,
				sizeof (stmfViewEntryList) + cnt * sizeof (stmfViewEntry));
			if (*viewEntryList == NULL) {
				ret = STMF_PS_ERROR_NOMEM;
				goto out;
			}

			(*viewEntryList)->cnt = cnt;
			for (i = 0; i < cnt; i++) {
				memcpy(&((*viewEntryList)->ve[i]), &(ack->ve_list.ve[i]),
					sizeof(stmfViewEntry));
			}
		}
	} else {
		ret = STMF_PS_ERROR_COMM;
	}

out:
	if (ack)
		free(ack);
	
	return (ret);
}

int 
stmfCommCheckService(void)
{
	FILE *fp;
	char command[256] = {0};
	char buf[256] = {0};
	ack_common_t *ack = NULL;
	int ret;

	/* lookup configd is start up */
	snprintf(command, sizeof(command), 
		"ps -C %s | wc -l", COMM_SERVICE);
	fp = popen(command, "r");
	if (!fp) {
		printf("%s popen %s failed\n", __func__,
			command);
		syslog(LOG_ERR, "%s popen %s failed", __func__,
			command);
		return (STMF_PS_ERROR_COMM);
	}

	if (fgets(buf, sizeof(buf), fp) != NULL) {
		int count = atoi(buf);
		if ((count - 1) == 0) {
			printf("%s comm service not exist\n", __func__);
			syslog(LOG_ERR, "%s comm service not exist", 
				__func__);
			return (STMF_PS_ERROR_COMM);
		}
	} else {
		printf("%s fgets failed\n", __func__);
		syslog(LOG_ERR, "%s fgets failed", __func__);
		return (STMF_PS_ERROR_COMM);
	}

	pclose(fp);

	if (stmfCommState() != COMM_STATE_RUNNING) {
		if (stmfCommInit() != 0) {
			syslog(LOG_ERR, "%s comm init failed", __func__);
			printf("%s comm init failed\n", __func__);
			return (STMF_PS_ERROR_COMM);
		}
	}
	
	ret = comm_send_msg(STMF_MSG_CHECK_SERVICE, NULL, 
		0, (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS)
		ret = ack->st;
	else
		ret = STMF_PS_ERROR_COMM;

	if (ack)
		free(ack);
	
	return (ret);
}

int 
stmfCommSetProviderData(char *providerName, nvlist_t *nvl, int providerType,
    uint64_t *setToken)
{
	char *buf = NULL;
	int len = 0;
	cmd_set_provider_data_t *cmd;
	ack_common_t *ack = NULL;
	char *nvlistEncoded = NULL;
	size_t nvlistEncodedSize;
	int ret;

	if (nvlist_pack(nvl, &nvlistEncoded, &nvlistEncodedSize,
	    NV_ENCODE_XDR, 0) != 0) {
	    printf("nvlist_pack failed\n");
		syslog(LOG_ERR, "nvlist_pack failed");
		return (STMF_PS_ERROR_NOMEM);
	}

	len = sizeof(cmd_set_provider_data_t) + nvlistEncodedSize - 1;
	buf = malloc(len);
	if (!buf) {
		printf("%s alloc buf failed, len = %d\n",
			__func__, len);
		syslog(LOG_ERR, "%s alloc buf failed, len = %d",
			__func__, len);
		return (STMF_PS_ERROR_NOMEM);
	}

	memset(buf, 0, len);
	cmd = (cmd_set_provider_data_t *)buf;
	strncpy(cmd->provider, providerName, sizeof(cmd->provider));
	cmd->type = providerType;
	if (setToken)
		cmd->set_cnt = (int)(*setToken);
	cmd->data_len = nvlistEncodedSize;
	memcpy(cmd->data, nvlistEncoded, nvlistEncodedSize);
	
	ret = comm_send_msg(STMF_MSG_SET_PROVIDER_DATA, buf, 
		len, (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS)
		ret = ack->st;
	else
		ret = STMF_PS_ERROR_COMM;

	if (nvlistEncoded)
		free(nvlistEncoded);
	
	if (buf)
		free(buf);

	if (ack)
		free(ack);
	
	return (ret);
}

int 
stmfCommGetProviderData(char *providerName, nvlist_t **nvl, int providerType,
    uint64_t *setToken)
{
	cmd_get_provider_data_t cmd;
	ack_get_provider_data_t *ack = NULL;
	int ret;

	memset(&cmd, 0, sizeof(cmd_get_provider_data_t));
	strncpy(cmd.provider, providerName, sizeof(cmd.provider));
	cmd.type = providerType;
	ret = comm_send_msg(STMF_MSG_GET_PROVIDER_DATA, (char *)&cmd, 
		sizeof(cmd_get_provider_data_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS) {
		ret = ack->st;
		if (setToken)
			*setToken = 0;

		if (ret == STMF_PS_SUCCESS) {
			if (nvlist_unpack(ack->data, ack->data_len, nvl, 0) != 0) {
				printf("unable to unpack nvlist\n");
				syslog(LOG_ERR, "unable to unpack nvlist");
				ret = STMF_PS_ERROR;
				goto out;
			}

			if (setToken)
				*setToken = ack->set_cnt;
		}
	} else {
		ret = STMF_PS_ERROR_COMM;
	}

out:
	if (ack)
		free(ack);
	
	return (ret);
}

int 
stmfCommGetProviderDataList(stmfProviderList **providerList)
{
	ack_get_provider_data_list_t *ack = NULL;
	int ret;

	if (!providerList)
		return (STMF_PS_ERROR_INVALID_ARG);

	ret = comm_send_msg(STMF_MSG_GET_PROVIDER_DATA_LIST, NULL, 
		0, (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS) {
		ret = ack->st;
		if (ret == STMF_PS_SUCCESS) {
			int i;
			int cnt = ack->provider_list.cnt;
			*providerList = (stmfProviderList *)calloc(1, 
				sizeof (stmfProviderList) + cnt * sizeof (stmfProvider));
			if (*providerList == NULL) {
				ret = STMF_PS_ERROR_NOMEM;
				goto out;
			}

			(*providerList)->cnt = cnt;
			for (i = 0; i < cnt; i++) {
				memcpy(&((*providerList)->provider[i]), 
					&(ack->provider_list.provider[i]),
					sizeof(stmfProvider));
			}
		}
	} else {
		ret = STMF_PS_ERROR_COMM;
	}

out:
	if (ack)
		free(ack);
	
	return (ret);
}

int 
stmfCommClearProviderData(char *providerName, int providerType)
{
	cmd_clear_provider_data_t cmd;
	ack_common_t *ack = NULL;
	int ret;

	memset(&cmd, 0, sizeof(cmd_clear_provider_data_t));
	strncpy(cmd.provider, providerName, sizeof(cmd.provider));
	cmd.type = providerType;
	ret = comm_send_msg(STMF_MSG_CLEAR_PROVIDER_DATA, (char *)&cmd, 
		sizeof(cmd_clear_provider_data_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS)
		ret = ack->st;
	else
		ret = STMF_PS_ERROR_COMM;

	if (ack)
		free(ack);
	
	return (ret);
}

int 
stmfCommSetServicePersist(uint8_t persistType)
{
	cmd_set_service_persist_t cmd;
	ack_common_t *ack = NULL;
	int ret;

	memset(&cmd, 0, sizeof(cmd_set_service_persist_t));
	cmd.type = persistType;
	ret = comm_send_msg(STMF_MSG_SET_SERVICE_PERSIST, (char *)&cmd, 
		sizeof(cmd_set_service_persist_t), (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS)
		ret = ack->st;
	else
		ret = STMF_PS_ERROR_COMM;

	if (ack)
		free(ack);
	
	return (ret);

}

int 
stmfCommGetServicePersist(uint8_t *persistType)
{
	ack_get_service_persist_t *ack = NULL;
	int ret;

	if (!persistType)
		return (STMF_PS_ERROR_INVALID_ARG);

	ret = comm_send_msg(STMF_MSG_GET_SERVICE_PERSIST, NULL, 
		0, (char **)&ack, 0);
	
	if (ret == COMM_SUCCESS) {
		ret = ack->st;
		if (ret == STMF_PS_SUCCESS) {
			*persistType = ack->persist_type;
		}	
	} else {
		ret = STMF_PS_ERROR_COMM;
	}

	if (ack)
		free(ack);
	
	return (ret);
}

