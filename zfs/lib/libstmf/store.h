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
#ifndef	_STORE_H
#define	_STORE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <libnvpair.h>
#include <sys/list.h>

/*
 * Error defines
 */
#define	STMF_PS_SUCCESS			0
#define	STMF_PS_ERROR			1
#define	STMF_PS_ERROR_MEMBER_NOT_FOUND	2
#define	STMF_PS_ERROR_GROUP_NOT_FOUND	3
#define	STMF_PS_ERROR_NOT_FOUND		4
#define	STMF_PS_ERROR_EXISTS		5
#define	STMF_PS_ERROR_NOMEM		6
#define	STMF_PS_ERROR_RETRY		7
#define	STMF_PS_ERROR_BUSY		8
#define	STMF_PS_ERROR_SERVICE_NOT_FOUND 9
#define	STMF_PS_ERROR_INVALID_ARG	10
#define	STMF_PS_ERROR_VERSION_MISMATCH	11
#define	STMF_PS_ERROR_PROV_DATA_STALE	12
#define	STMF_PS_ERROR_CFG_OPERATION		13

#define	STMF_PS_PERSIST_NONE			"none"
#define	STMF_PS_PERSIST_SMF				"smf"
#define	STMF_PROVIDER_DATA_PROP_SIZE	4000

#define	STMF_PS_DEFAULT_HG				"all"
#define	STMF_PS_DEFAULT_TG				"all"

#define	DB_HOST_GROUP					0
#define	DB_TARGET_GROUP					1

typedef struct stmf_global_cfg {
	char	persist_type[32];
} stmf_global_cfg_t;

typedef struct stmf_provider {
	list_node_t	node;
	int			provider_id;
	char		name[256];
	int			type;
	int			setcnt;
	nvlist_t	*nvl;
} stmf_provider_t;

typedef struct stmf_group_elem {
	list_node_t	node;
	int			elem_id;
	int			group_id;
	char		name[256];
} stmf_group_elem_t;

typedef struct stmf_group {
	list_node_t	node;
	int			group_id;
	char		name[256];
	int			type;
	list_t		elem_list;
} stmf_group_t;

typedef struct stmf_lun_view {
	list_node_t	node;
	int			hg_id;
	int 		tg_id;
	int 		ve_index;
	uchar_t		lu_guid[33];
	uchar_t		lu_nbr[8];
} stmf_lun_view_t;

typedef struct stmf_lun {
	list_node_t	node;
	uchar_t		lu_guid[33];
	uchar_t		lu_nbr[8];
	list_t		view_list;
} stmf_lun_t;

typedef struct stmf_view {
	list_node_t	node;
	int			hg_id;
	int			tg_id;
	int			ve_index;
} stmf_view_t;

typedef struct stmf_store_info {
	stmf_global_cfg_t	*cfg;
	list_t				*providers;
	list_t				*groups;
	list_t				*luns;
} stmf_store_info_t;

typedef int (*cfgInit)(stmf_store_info_t *);
typedef int	(*cfgCheckService)(void);
typedef int (*cfgSetServicePersist)(char *);
typedef int (*cfgSetProviderData)(int, char *, nvlist_t *, int, int, int *);
typedef int (*cfgClearProviderData)(int);
typedef int (*cfgCreateGroup)(char *, int, int *);
typedef int (*cfgDeleteGroup)(int);
typedef int (*cfgAddGroupMember)(int, char *, int *);
typedef int (*cfgRemoveGroupMember)(int);
typedef int (*cfgAddViewEntry)(int, int, int, uchar_t *, uchar_t *);
typedef int (*cfgRemoveViewEntry)(int, int);

typedef struct cfg_store {
	cfgInit					init;
	cfgCheckService			checkService;
	cfgSetServicePersist	setServicePersist;
	cfgSetProviderData		setProviderData;
	cfgClearProviderData	clearProviderData;
	cfgCreateGroup			createGroup;
	cfgDeleteGroup			deleteGroup;
	cfgAddGroupMember		addGroupMember;
	cfgRemoveGroupMember	removeGroupMember;
	cfgAddViewEntry			addViewEntry;
	cfgRemoveViewEntry		removeViewEntry;
} cfg_store_t;

void psInit(cfg_store_t *ops);
int psAddHostGroupMember(char *groupName, char *memberName);
int psAddTargetGroupMember(char *groupName, char *memberName);
int psAddViewEntry(stmfGuid *lu, stmfViewEntry *viewEntry);
int psCreateHostGroup(char *groupName);
int psDeleteHostGroup(char *groupName);
int psCreateTargetGroup(char *groupName);
int psDeleteTargetGroup(char *groupName);
int psGetViewEntry(stmfGuid *lu, uint32_t viewEntryIndex, stmfViewEntry *ve);
int psGetLogicalUnitList(stmfGuidList **guidList);
int psRemoveHostGroupMember(char *groupName, char *memberName);
int psRemoveTargetGroupMember(char *groupName, char *memberName);
int psRemoveViewEntry(stmfGuid *lu, uint32_t viewEntryIndex);
int psGetHostGroupList(stmfGroupList **groupList);
int psGetTargetGroupList(stmfGroupList **groupList);
int psGetHostGroupMemberList(char *groupName, stmfGroupProperties **groupList);
int psGetTargetGroupMemberList(char *groupName,
    stmfGroupProperties **groupList);
int psGetViewEntryList(stmfGuid *lu, stmfViewEntryList **viewEntryList);
int psCheckService(void);
int psSetProviderData(char *providerName, nvlist_t *nvl, int providerType,
    uint64_t *setHandle);
int psGetProviderData(char *providerName, nvlist_t **nvl, int providerType,
    uint64_t *setHandle);
int psGetProviderDataList(stmfProviderList **providerList);
int psClearProviderData(char *providerName, int providerType);
int psSetServicePersist(uint8_t persistType);
int psGetServicePersist(uint8_t *persistType);


#ifdef	__cplusplus
}
#endif

#endif	/* _STORE_H */
