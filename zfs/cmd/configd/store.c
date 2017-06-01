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
#include <stmf_msg.h>
#include "store.h"

stmf_global_cfg_t s_config = { STMF_PS_PERSIST_SMF };
list_t s_provider_list;
list_t s_group_list;
list_t s_luns_list;
pthread_rwlock_t s_rwlock;
cfg_store_t *s_ops = NULL;

boolean_t s_store_init = B_FALSE;

int
psInit(cfg_store_t *ops)
{
	stmf_store_info_t storeInfo;
	int ret;

	pthread_rwlock_init(&s_rwlock, NULL);
	storeInfo.cfg = &s_config;
	storeInfo.providers = &s_provider_list;
	storeInfo.groups = &s_group_list;
	storeInfo.luns= &s_luns_list;
	s_ops = ops;
	ret = s_ops->init(&storeInfo);
	
	if (ret != STMF_PS_SUCCESS) {
		syslog(LOG_ERR, "%s failed", __func__);
		return (ret);
	}
	
	s_store_init = B_TRUE;
	return (ret);
}

int 
ipsAddGroupMember(char *groupName, char *memberName, int type)
{
	stmf_group_t *group = NULL;
	stmf_group_elem_t *member = NULL;
	int ret = STMF_PS_SUCCESS;
	int elemID = 0;
	
	pthread_rwlock_wrlock(&s_rwlock);
	group = list_head(&s_group_list);
	while (group) {
		if ((strncmp(group->name, groupName, sizeof(group->name)) == 0) &&
			(group->type == type))
			break;
		group = list_next(&s_group_list, group);
	}

	if (!group) {
		ret = STMF_PS_ERROR_GROUP_NOT_FOUND;
		goto done;
	}

	member = list_head(&group->elem_list);
	while (member) {
		if (strncmp(member->name, memberName, sizeof(member->name))
			== 0)
			break;
		member = list_next(&group->elem_list, member);
	}

	if (member) {
		ret = STMF_PS_ERROR_EXISTS;
		goto done;
	}

	ret = s_ops->addGroupMember(group->group_id, memberName, &elemID);

	if (ret != STMF_PS_SUCCESS)
		goto done;

	member = malloc(sizeof(stmf_group_elem_t));
	memset(member, 0, sizeof(stmf_group_elem_t));
	member->elem_id = elemID;
	member->group_id = group->group_id;
	strncpy(member->name, memberName, sizeof(member->name));
	list_insert_tail(&group->elem_list, member);
	
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}


int 
psAddHostGroupMember(char *groupName, char *memberName)
{
	return ipsAddGroupMember(groupName, memberName, HOST_GROUP);
}

int 
psAddTargetGroupMember(char *groupName, char *memberName)
{
	return ipsAddGroupMember(groupName, memberName, TARGET_GROUP);
}

int 
psAddViewEntry(stmfGuid *lu, stmfViewEntry *viewEntry)
{
	stmf_group_t *hg = NULL;
	stmf_group_t *tg = NULL;
	stmf_group_t *tmp = NULL;
	stmf_lun_t	 *lun = NULL;
	stmf_view_t	 *view = NULL;
	char guidAsciiBuf[33] = {0};
	int ret = STMF_PS_SUCCESS;
	pthread_rwlock_wrlock(&s_rwlock);

	if (viewEntry->allHosts)
		strncpy(viewEntry->hostGroup, STMF_PS_DEFAULT_HG, 
			strlen(STMF_PS_DEFAULT_HG));

	if (viewEntry->allTargets)
		strncpy(viewEntry->targetGroup, STMF_PS_DEFAULT_TG,
			strlen(STMF_PS_DEFAULT_TG));

	tmp = list_head(&s_group_list);
	while (tmp) {
		if (!hg &&
			(tmp->type == HOST_GROUP) &&
			(strncmp(tmp->name, viewEntry->hostGroup, sizeof(tmp->name)) == 0)) {
			hg = tmp;
		}

		if (!tg &&
			(tmp->type == TARGET_GROUP) &&
			(strncmp(tmp->name, viewEntry->targetGroup, sizeof(tmp->name)) == 0)) {
			tg = tmp;
		}

		if (hg && tg)
			break;

		tmp = list_next(&s_group_list, tmp);
	}

	if (!hg || !tg) {
		ret = STMF_PS_ERROR_GROUP_NOT_FOUND;
		goto done;
	}

	/* Convert to ASCII uppercase hexadecimal string */
	(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
	    "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
	    lu->guid[0], lu->guid[1], lu->guid[2], lu->guid[3], lu->guid[4],
	    lu->guid[5], lu->guid[6], lu->guid[7], lu->guid[8], lu->guid[9],
	    lu->guid[10], lu->guid[11], lu->guid[12], lu->guid[13],
	    lu->guid[14], lu->guid[15]);

	lun = list_head(&s_luns_list);
	while (lun) {
		if (memcmp(lun->lu_guid, guidAsciiBuf, sizeof(lun->lu_guid)) == 0)
			break;
		lun = list_next(&s_luns_list, lun);
	}

	if (lun) {
		view = list_head(&lun->view_list);
		while (view) {
			if ((view->hg_id == hg->group_id) &&
				(view->tg_id == tg->group_id)) {
				ret = STMF_PS_ERROR_EXISTS;
				break;
			}

			if (viewEntry->veIndexValid &&
				view->ve_index == viewEntry->veIndex) {
				ret = STMF_PS_ERROR_EXISTS;
				break;
			}
			
			view = list_next(&lun->view_list, view);
		}
	}

	if (ret != STMF_PS_SUCCESS)
		goto done;

	ret = s_ops->addViewEntry(hg->group_id, tg->group_id, viewEntry->veIndex,
		(uchar_t *)guidAsciiBuf, viewEntry->luNbr);

	if (ret != STMF_PS_SUCCESS)
		goto done;

	if (!lun) {
		lun = malloc(sizeof(stmf_lun_t));
		memset(lun, 0, sizeof(stmf_lun_t));
		memcpy(lun->lu_guid, guidAsciiBuf, sizeof(guidAsciiBuf));
		memcpy(lun->lu_nbr, viewEntry->luNbr, sizeof(viewEntry->luNbr));
		list_create(&lun->view_list, sizeof(stmf_view_t),
			offsetof(stmf_view_t, node));
		list_insert_tail(&s_luns_list, lun);
	}

	view = malloc(sizeof(stmf_view_t));
	memset(view, 0, sizeof(stmf_view_t));
	view->hg_id = hg->group_id;
	view->tg_id = tg->group_id;
	view->ve_index = viewEntry->veIndex;
	list_insert_tail(&lun->view_list, view);
	
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int 
ipsCreateGroup(char *groupName, int type)
{
	stmf_group_t *group = NULL;
	int ret = STMF_PS_SUCCESS;
	int groupID = 0;
	pthread_rwlock_wrlock(&s_rwlock);
	group = list_head(&s_group_list);
	while (group) {
		if ((group->type == type) &&
			(strncmp(group->name, groupName, sizeof(group->name)) == 0))
			break;
		group = list_next(&s_group_list, group);
	}

	if (group) {
		ret = STMF_PS_ERROR_EXISTS;
		goto done;
	}

	ret = s_ops->createGroup(groupName, type, &groupID);

	if (ret)
		goto done;

	group = malloc(sizeof(stmf_group_t));
	memset(group, 0, sizeof(stmf_group_t));
	group->group_id = groupID;
	strncpy(group->name, groupName, sizeof(group->name));
	group->type = type;
	list_create(&group->elem_list, sizeof(stmf_group_elem_t),
		offsetof(stmf_group_elem_t, node));
	list_insert_tail(&s_group_list, group);
	
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int 
psCreateHostGroup(char *groupName)
{
	return ipsCreateGroup(groupName, HOST_GROUP);
}

int 
ipsDeleteGroup(char *groupName, int type)
{
	stmf_group_t *group = NULL;
	stmf_group_elem_t *elem = NULL;
	int ret = STMF_PS_SUCCESS;

	pthread_rwlock_wrlock(&s_rwlock);
	group = list_head(&s_group_list);
	while (group) {
		if ((group->type == type) &&
			(strncmp(group->name, groupName, sizeof(group->name)) == 0))
			break;
		group = list_next(&s_group_list, group);
	}

	if (!group) {
		ret = STMF_PS_ERROR_NOT_FOUND;
		goto done;
	}

	ret = s_ops->deleteGroup(group->group_id);

	if (ret != STMF_PS_SUCCESS)
		goto done;

	while (!list_is_empty(&group->elem_list)) {
		elem = list_remove_head(&group->elem_list);
		free(elem);
	}

	list_remove(&s_group_list, group);
	free(group);
	
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int 
psDeleteHostGroup(char *groupName)
{
	return ipsDeleteGroup(groupName, HOST_GROUP);
}

int 
psCreateTargetGroup(char *groupName)
{
	return ipsCreateGroup(groupName, TARGET_GROUP);
}

int 
psDeleteTargetGroup(char *groupName)
{
	return ipsDeleteGroup(groupName, TARGET_GROUP);
}

int
ipsGetGroupName(int groupID, int type, char *name)
{
	stmf_group_t *group = NULL;

	group = list_head(&s_group_list);
	while (group) {
		if ((group->group_id == groupID) &&
			(group->type == type))
			break;
		group = list_next(&s_group_list, group);
	}

	if (!group)
		return (STMF_PS_ERROR_GROUP_NOT_FOUND);

	strncpy(name, group->name, sizeof(group->name));
	return (STMF_PS_SUCCESS);
}

int
ipsGetViewEntry(int hostGroupID, int targetGroupID, int viewEntryIndex,
	uchar_t *luNBR, stmfViewEntry *ve)
{
	int ret = STMF_PS_SUCCESS;
	memset(ve, 0, sizeof(stmfViewEntry));

	ret = ipsGetGroupName(hostGroupID, HOST_GROUP, ve->hostGroup);
	if (ret != STMF_PS_SUCCESS)
		goto done;

	ret = ipsGetGroupName(targetGroupID, TARGET_GROUP, ve->targetGroup);
	if (ret != STMF_PS_SUCCESS)
		goto done;

	if (strncmp(ve->hostGroup, STMF_PS_DEFAULT_HG, sizeof(ve->hostGroup)) == 0)
		ve->allHosts = B_TRUE;
	
	if (strncmp(ve->targetGroup, STMF_PS_DEFAULT_TG, sizeof(ve->targetGroup)) == 0)
		ve->allTargets= B_TRUE;

	ve->veIndexValid = B_TRUE;
	ve->veIndex = viewEntryIndex;
	ve->luNbrValid = B_TRUE;
	memcpy(ve->luNbr, luNBR, sizeof(ve->luNbr));

done:
	return (ret);
}

int 
psGetViewEntry(stmfGuid *lu, uint32_t viewEntryIndex, stmfViewEntry *ve)
{
	stmf_lun_t *lun = NULL;
	stmf_view_t *view = NULL;
	char guidAsciiBuf[33] = {0};
	int ret = STMF_PS_SUCCESS;

	/* Convert to ASCII uppercase hexadecimal string */
	(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
	    "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
	    lu->guid[0], lu->guid[1], lu->guid[2], lu->guid[3], lu->guid[4],
	    lu->guid[5], lu->guid[6], lu->guid[7], lu->guid[8], lu->guid[9],
	    lu->guid[10], lu->guid[11], lu->guid[12], lu->guid[13],
	    lu->guid[14], lu->guid[15]);

	pthread_rwlock_rdlock(&s_rwlock);
	lun = list_head(&s_luns_list);
	while (lun) {
		if (memcmp(lun->lu_guid, guidAsciiBuf, sizeof(guidAsciiBuf)) == 0)
			break;
		lun = list_next(&s_luns_list, lun);
	}

	if (!lun) {
		ret = STMF_PS_ERROR_NOT_FOUND;
		goto done;
	}

	view = list_head(&lun->view_list);
	while (view) {
		if (view->ve_index == viewEntryIndex)
			break;
		view = list_next(&lun->view_list, view);
	}

	if (!view) {
		ret = STMF_PS_ERROR_NOT_FOUND;
		goto done;
	}

	ret = ipsGetViewEntry(view->hg_id, view->tg_id, viewEntryIndex, 
		lun->lu_nbr, ve);
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int 
psGetLogicalUnitList(stmfGuidList **guidList)
{
	stmf_lun_t *lun = NULL;
	int guidCnt = 0, i = 0, j = 0;
	unsigned int guid[sizeof (stmfGuid)];
	stmfGuid outGuid;
	int ret = STMF_PS_SUCCESS;

	pthread_rwlock_rdlock(&s_rwlock);
	lun = list_head(&s_luns_list);
	while (lun) {
		guidCnt++;
		lun = list_next(&s_luns_list, lun);
	}
	
	*guidList = (stmfGuidList *)calloc(1, sizeof (stmfGuidList) +
		guidCnt * sizeof (stmfGuid));
	if (*guidList == NULL) {
		ret = STMF_PS_ERROR_NOMEM;
		goto done;
	}

	(*guidList)->cnt = guidCnt;
	lun = list_head(&s_luns_list);
	while (lun) {
		(void) sscanf((char *)lun->lu_guid,
		    "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
		    &guid[0], &guid[1], &guid[2], &guid[3], &guid[4], &guid[5],
		    &guid[6], &guid[7], &guid[8], &guid[9], &guid[10],
		    &guid[11], &guid[12], &guid[13], &guid[14], &guid[15]);

		for (j = 0; j < sizeof (stmfGuid); j++) {
			outGuid.guid[j] = guid[j];
		}
		memcpy((*guidList)->guid[i++].guid, &outGuid, sizeof (stmfGuid));
		lun = list_next(&s_luns_list, lun);
	}
	
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);	
}

int 
ipsRemoveGroupMember(char *groupName, char *memberName, int type)
{
	stmf_group_t *group = NULL;
	stmf_group_elem_t *elem = NULL;
	int ret = STMF_PS_SUCCESS;
	
	pthread_rwlock_wrlock(&s_rwlock);
	group = list_head(&s_group_list);
	while (group) {
		if ((group->type == type) &&
			(strncmp(group->name, groupName, sizeof(group->name)) == 0))
			break;

		group = list_next(&s_group_list, group);
	}

	if (!group) {
		ret = STMF_PS_ERROR_GROUP_NOT_FOUND;
		goto done;
	}

	elem = list_head(&group->elem_list);
	while (elem) {
		if (strncmp(elem->name, memberName, sizeof(elem->name)) == 0)
			break;
		elem = list_next(&group->elem_list, elem);
	}

	if (!elem) {
		ret = STMF_PS_ERROR_MEMBER_NOT_FOUND;
		goto done;
	}

	ret = s_ops->removeGroupMember(elem->elem_id);
	if (ret != STMF_PS_SUCCESS)
		goto done;

	list_remove(&group->elem_list, elem);
	free(elem);
	
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int 
psRemoveHostGroupMember(char *groupName, char *memberName)
{
	return ipsRemoveGroupMember(groupName, memberName, HOST_GROUP);
}

int 
psRemoveTargetGroupMember(char *groupName, char *memberName)
{
	return ipsRemoveGroupMember(groupName, memberName, TARGET_GROUP);
}

int 
psRemoveViewEntry(stmfGuid *lu, uint32_t viewEntryIndex)
{
	stmf_lun_t *lun = NULL;
	stmf_view_t *view = NULL;
	char guidAsciiBuf[33] = {0};
	int ret = STMF_PS_SUCCESS;

	/* Convert to ASCII uppercase hexadecimal string */
	(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
	    "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
	    lu->guid[0], lu->guid[1], lu->guid[2], lu->guid[3], lu->guid[4],
	    lu->guid[5], lu->guid[6], lu->guid[7], lu->guid[8], lu->guid[9],
	    lu->guid[10], lu->guid[11], lu->guid[12], lu->guid[13],
	    lu->guid[14], lu->guid[15]);
	
	pthread_rwlock_wrlock(&s_rwlock);
	lun = list_head(&s_luns_list);
	while (lun) {
		if (memcmp(lun->lu_guid, guidAsciiBuf, sizeof(guidAsciiBuf)) == 0)
			break;
		lun = list_next(&s_luns_list, lun);
	}

	if (!lun) {
		ret = STMF_PS_ERROR_NOT_FOUND;
		goto done;
	}

	view = list_head(&lun->view_list);
	while (view) {
		if (view->ve_index == viewEntryIndex)
			break;
		view = list_next(&lun->view_list, view);
	}

	if (!view) {
		ret = STMF_PS_ERROR_NOT_FOUND;
		goto done;
	}
	
	ret = s_ops->removeViewEntry(view->hg_id, view->tg_id);
	if (ret != STMF_PS_SUCCESS)
		goto done;

	list_remove(&lun->view_list, view);
	free(view);

	if (list_is_empty(&lun->view_list)) {
		list_remove(&s_luns_list, lun);
		free(lun);
	}
	
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int
ipsGetGroupList(int type, stmfGroupList **groupList)
{
	stmf_group_t *group = NULL;
	int memberCnt = 0;
	int i = 0;
	int ret = STMF_PS_SUCCESS;

	pthread_rwlock_rdlock(&s_rwlock);
	group = list_head(&s_group_list);
	while (group) {
		if (group->type == type)
			memberCnt++;
		group = list_next(&s_group_list, group);
	}

	*groupList = (stmfGroupList *)calloc(1, sizeof (stmfGroupList) +
	    memberCnt * sizeof (stmfGroupName));

	if (*groupList == NULL) {
		ret = STMF_PS_ERROR_NOMEM;
		goto done;
	}

	(*groupList)->cnt = memberCnt;
	group = list_head(&s_group_list);
	while (group) {
		if (group->type == type) {
			strncpy((*groupList)->name[i++], group->name, sizeof(group->name));
		}
		group = list_next(&s_group_list, group);
	}

done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int 
psGetHostGroupList(stmfGroupList **groupList)
{
	return ipsGetGroupList(HOST_GROUP, groupList);
}

int 
psGetTargetGroupList(stmfGroupList **groupList)
{
	return ipsGetGroupList(TARGET_GROUP, groupList);
}

int
ipsGetMemberList(char *groupName, int type, stmfGroupProperties **groupMemberList)
{
	stmf_group_t *group = NULL;
	stmf_group_elem_t *elem = NULL;
	int memberCnt = 0;
	int i = 0;
	int ret = STMF_PS_SUCCESS;

	pthread_rwlock_rdlock(&s_rwlock);
	group = list_head(&s_group_list);
	while (group) {
		if ((group->type == type) &&
			((strncmp(group->name, groupName, sizeof(group->name))) == 0))
			break;
		group = list_next(&s_group_list, group);
	}

	if (!group) {
		ret = STMF_PS_ERROR_GROUP_NOT_FOUND;
		goto done;
	}

	elem = list_head(&group->elem_list);
	while (elem) {
		memberCnt++;
		elem = list_next(&group->elem_list, elem);
				
	}

	*groupMemberList = (stmfGroupProperties *)calloc(1,
		sizeof (stmfGroupProperties) + memberCnt * sizeof (stmfDevid));
	if (*groupMemberList == NULL) {
		ret = STMF_PS_ERROR_NOMEM;
		goto done;
	}
	
	elem = list_head(&group->elem_list);
	while (elem) {
		(*groupMemberList)->name[i].identLength = strlen(elem->name);
		strncpy((char *)((*groupMemberList)->name[i++].ident), elem->name, 
			strlen(elem->name));
		elem = list_next(&group->elem_list, elem);
	}

done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int 
psGetHostGroupMemberList(char *groupName, 
	stmfGroupProperties **groupMemberList)
{
	return ipsGetMemberList(groupName, HOST_GROUP, groupMemberList);
}

int 
psGetTargetGroupMemberList(char *groupName,
    stmfGroupProperties **groupMemberList)
{
	return ipsGetMemberList(groupName, TARGET_GROUP, groupMemberList);
}

int
psGetViewEntryList(stmfGuid *lu, stmfViewEntryList **viewEntryList)
{
	stmf_lun_t *lun = NULL;
	stmf_view_t *view = NULL;
	char guidAsciiBuf[33] = {0};
	int veCnt = 0;
	int i = 0;
	int ret = STMF_PS_SUCCESS;

	/* Convert to ASCII uppercase hexadecimal string */
	(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
	    "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
	    lu->guid[0], lu->guid[1], lu->guid[2], lu->guid[3], lu->guid[4],
	    lu->guid[5], lu->guid[6], lu->guid[7], lu->guid[8], lu->guid[9],
	    lu->guid[10], lu->guid[11], lu->guid[12], lu->guid[13],
	    lu->guid[14], lu->guid[15]);

	pthread_rwlock_rdlock(&s_rwlock);
	lun = list_head(&s_luns_list);
	while (lun) {
		if (memcmp(lun->lu_guid, guidAsciiBuf, sizeof(guidAsciiBuf)) == 0)
			break;
		lun = list_next(&s_luns_list, lun);
	}

	if (!lun) {
		ret = STMF_PS_ERROR_NOT_FOUND;
		goto done;
	}

	view = list_head(&lun->view_list);
	while (view) {
		veCnt++;
		view = list_next(&lun->view_list, view);
	}

	if (veCnt == 0) {
		ret = STMF_PS_ERROR_NOT_FOUND;
		goto done;
	}
	
	/*
	 * alloc the list based on the view entry count
	 */
	*viewEntryList = (stmfViewEntryList *)calloc(1,
	    sizeof (stmfViewEntryList) + veCnt * sizeof (stmfViewEntry));
	if (*viewEntryList == NULL) {
		ret = STMF_PS_ERROR_NOMEM;
		goto done;
	}

	(*viewEntryList)->cnt = 0;
	view = list_head(&lun->view_list);
	while (view) {
		ret = ipsGetViewEntry(view->hg_id, view->tg_id, view->ve_index,
			lun->lu_nbr, &((*viewEntryList)->ve[i]));
		if (ret != STMF_PS_SUCCESS)
			break;

		i++;
		(*viewEntryList)->cnt++;
		view = list_next(&lun->view_list, view);
	}

done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int 
psCheckService()
{
	if (s_store_init) {
		if (STMF_PS_SUCCESS == s_ops->checkService())
			return (STMF_STATUS_SUCCESS);
	}

	return (STMF_STATUS_ERROR);
}

int 
psSetProviderData(char *providerName, nvlist_t *nvl, int providerType,
    int *setToken)
{
	stmf_provider_t *provider = NULL;
	int providerID = -1;
	int retProviderID = -1;
	int setCnt = 0;
	int ret = STMF_PS_SUCCESS;

	pthread_rwlock_wrlock(&s_rwlock);
	provider = list_head(&s_provider_list);
	while (provider) {
		if ((provider->type == providerType) &&
			(strncmp(provider->name, providerName, sizeof(provider->name)) == 0))
			break;
		provider = list_next(&s_provider_list, provider);
	}

	if (provider) {
		if ((*setToken != 0) && 
			(*setToken != provider->setcnt)) {
			ret = STMF_PS_ERROR_PROV_DATA_STALE;
			goto done;
		}

		setCnt = provider->setcnt;
	}

	if (provider)
		providerID = provider->provider_id;

	setCnt++;
	ret = s_ops->setProviderData(providerID, providerName, nvl, providerType, 
		setCnt, &retProviderID);

	if (ret != STMF_PS_SUCCESS)
		goto done;

	if (!provider) {
		provider = malloc(sizeof(stmf_provider_t));
		memset(provider, 0, sizeof(stmf_provider_t));
		provider->provider_id = retProviderID;
		strncpy(provider->name, providerName, sizeof(provider->name));
		provider->type = providerType;
		provider->setcnt = setCnt;
		nvlist_dup(nvl, &provider->nvl, 0);
		list_insert_tail(&s_provider_list, provider);
	} else {
		provider->setcnt = setCnt;
		nvlist_free(provider->nvl);
		nvlist_dup(nvl, &provider->nvl, 0);
	}

	*setToken = setCnt;
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int 
psGetProviderData(char *providerName, nvlist_t **nvl, int providerType,
    int *setToken)
{
	stmf_provider_t *provider = NULL;
	int ret = STMF_PS_SUCCESS;

	pthread_rwlock_rdlock(&s_rwlock);
	provider = list_head(&s_provider_list);
	while (provider) {
		if ((provider->type == providerType) &&
			(strncmp(provider->name, providerName, sizeof(provider->name)) == 0))
			break;
		provider = list_next(&s_provider_list, provider);
	}

	if (!provider) {
		ret = STMF_PS_ERROR_NOT_FOUND;
		goto done;
	}

	nvlist_dup(provider->nvl, nvl, 0);
	*setToken = provider->setcnt;

done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int 
psGetProviderDataList(stmfProviderList **providerList)
{
	stmf_provider_t *provider = NULL;
	int providerCnt = 0;
	int i = 0;
	int ret = STMF_PS_SUCCESS;
	
	pthread_rwlock_rdlock(&s_rwlock);
	provider = list_head(&s_provider_list);
	while (provider) {
		providerCnt++;
		provider = list_next(&s_provider_list, provider);
	}

	*providerList = (stmfProviderList *)calloc(1,
		sizeof (stmfProviderList) + providerCnt * sizeof (stmfProvider));
	if (*providerList == NULL) {
		ret = STMF_PS_ERROR_NOMEM;
		goto done;
	}

	(*providerList)->cnt = providerCnt;
	provider = list_head(&s_provider_list);
	while (provider) {
		(*providerList)->provider[i].providerType = provider->type;
		strncpy((*providerList)->provider[i++].name,
			provider->name, sizeof(provider->name));
		provider = list_next(&s_provider_list, provider);
	}
	
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

int 
psClearProviderData(char *providerName, int providerType)
{
	stmf_provider_t *provider = NULL;
	int ret = STMF_PS_SUCCESS;

	pthread_rwlock_wrlock(&s_rwlock);
	provider = list_head(&s_provider_list);
	while (provider) {
		if ((provider->type == providerType) &&
			(strncmp(provider->name, providerName, sizeof(provider->name))) == 0)
			break;
		provider = list_next(&s_provider_list, provider);
	}

	if (!provider) {
		ret = STMF_PS_ERROR_NOT_FOUND;
		goto done;
	}

	ret = s_ops->clearProviderData(provider->provider_id);

	if (ret != STMF_PS_SUCCESS)
		goto done;

	list_remove(&s_provider_list, provider);
	nvlist_free(provider->nvl);
	free(provider);
	
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);	
}

int 
psSetServicePersist(int persistType)
{
	char *iPersistType;
	int ret = STMF_PS_SUCCESS;
	
	pthread_rwlock_wrlock(&s_rwlock);
	if (persistType == STMF_PERSIST_SMF) {
		iPersistType = STMF_PS_PERSIST_SMF;
	} else if (persistType == STMF_PERSIST_NONE) {
		iPersistType = STMF_PS_PERSIST_NONE;
	} else {
		ret = STMF_PS_ERROR;
		goto done;
	}

	ret = s_ops->setServicePersist(iPersistType);
	if (ret != STMF_PS_SUCCESS)
		goto done;

	strncpy(s_config.persist_type, iPersistType, 
		sizeof(s_config.persist_type));
done:
	pthread_rwlock_unlock(&s_rwlock);
	return (ret);		
}

int 
psGetServicePersist(int *persistType)
{
	int ret = STMF_PS_SUCCESS;
	
	pthread_rwlock_rdlock(&s_rwlock);
	if (strncmp(s_config.persist_type, STMF_PS_PERSIST_SMF, 
		sizeof(s_config.persist_type)) == 0) {
		*persistType = STMF_PERSIST_SMF;
	} else if (strncmp(s_config.persist_type, STMF_PS_PERSIST_NONE, 
		sizeof(s_config.persist_type)) == 0) {
		*persistType = STMF_PERSIST_NONE;
	} else {
		*persistType = STMF_PERSIST_SMF;
	}

	pthread_rwlock_unlock(&s_rwlock);
	return (ret);
}

