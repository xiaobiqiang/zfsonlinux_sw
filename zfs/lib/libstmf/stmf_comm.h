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
#ifndef	_STMF_COMM_H
#define	_STMF_COMM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <libstmf.h>

int stmfCommAddHostGroupMember(char *groupName, char *memberName);
int stmfCommAddTargetGroupMember(char *groupName, char *memberName);
int stmfCommAddViewEntry(stmfGuid *lu, stmfViewEntry *viewEntry);
int stmfCommCreateHostGroup(char *groupName);
int stmfCommDeleteHostGroup(char *groupName);
int stmfCommCreateTargetGroup(char *groupName);
int stmfCommDeleteTargetGroup(char *groupName);
int stmfCommGetViewEntry(stmfGuid *lu, uint32_t viewEntryIndex, stmfViewEntry *ve);
int stmfCommGetLogicalUnitList(stmfGuidList **guidList);
int stmfCommRemoveHostGroupMember(char *groupName, char *memberName);
int stmfCommRemoveTargetGroupMember(char *groupName, char *memberName);
int stmfCommRemoveViewEntry(stmfGuid *lu, uint32_t viewEntryIndex);
int stmfCommGetHostGroupList(stmfGroupList **groupList);
int stmfCommGetTargetGroupList(stmfGroupList **groupList);
int stmfCommGetHostGroupMemberList(char *groupName, 
	stmfGroupProperties **groupMemberList);
int stmfCommGetTargetGroupMemberList(char *groupName,
    stmfGroupProperties **groupMemberList);
int stmfCommGetViewEntryList(stmfGuid *lu, stmfViewEntryList **viewEntryList);
int stmfCommCheckService(void);
int stmfCommSetProviderData(char *providerName, nvlist_t *nvl, int providerType,
    uint64_t *setToken);
int stmfCommGetProviderData(char *providerName, nvlist_t **nvl, int providerType,
    uint64_t *setToken);
int stmfCommGetProviderDataList(stmfProviderList **providerList);
int stmfCommClearProviderData(char *providerName, int providerType);
int stmfCommSetServicePersist(uint8_t persistType);
int stmfCommGetServicePersist(uint8_t *persistType);

#ifdef	__cplusplus
}
#endif

#endif	/* _STMF_COMM_H */
