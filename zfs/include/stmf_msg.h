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
#ifndef	_STMF_MSG_H
#define	_STMF_MSG_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <libstmf.h>

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
#define	STMF_PS_ERROR_COMM				14
#define	STMF_PS_ERROR_DB_NOT_LOAD		15

enum stmf_msg_id {
	STMF_MSG_ADD_GROUP_MEMBER = 0x100,
	STMF_MSG_ADD_VIEW_ENTRY,
	STMF_MSG_CREATE_GROUP,
	STMF_MSG_DELETE_GROUP,
	STMF_MSG_GET_VIEW_ENTRY,
	STMF_MSG_GET_LOGICAL_UNIT_LIST,
	STMF_MSG_REMOVE_GROUP_MEMBER,
	STMF_MSG_REMOVE_VIEW_ENTRY,
	STMF_MSG_GET_GROUP_LIST,
	STMF_MSG_GET_GROUP_MEMBER_LIST,
	STMF_MSG_GET_VIEW_ENTRY_LIST,
	STMF_MSG_CHECK_SERVICE,
	STMF_MSG_SET_PROVIDER_DATA,
	STMF_MSG_GET_PROVIDER_DATA,
	STMF_MSG_GET_PROVIDER_DATA_LIST,
	STMF_MSG_CLEAR_PROVIDER_DATA,
	STMF_MSG_SET_SERVICE_PERSIST,
	STMF_MSG_GET_SERVICE_PERSIST
};

typedef struct cmd_add_group_member {
	char	group[256];
	char	member[256];
	int		type;
} cmd_add_group_member_t;

typedef struct cmd_add_view_entry {
	stmfGuid		lu;
	stmfViewEntry	viewEntry;
} cmd_add_view_entry_t;

typedef struct cmd_create_group {
	char	group[256];
	int		type;
} cmd_create_group_t;

typedef struct cmd_delete_group {
	char	group[256];
	int		type;
} cmd_delete_group_t;

typedef struct cmd_get_view_entry {
	stmfGuid	lu;
	int			ve_index;
} cmd_get_view_entry_t;

typedef struct cmd_remove_group_member {
	char		group[256];
	char		member[256];
	int 		type;
} cmd_remove_group_member_t;

typedef struct cmd_remove_view_entry {
	stmfGuid	lu;
	int			ve_index;
} cmd_remove_view_entry_t;

typedef struct cmd_get_group_list {
	int			type;
} cmd_get_group_list_t;

typedef struct cmd_get_group_member_list {
	char		group[256];
	int			type;
} cmd_get_group_member_list_t;

typedef struct cmd_get_view_entry_list {
	stmfGuid	lu;
} cmd_get_view_entry_list_t;

typedef struct cmd_set_provider_data {
	char		provider[256];
	int			type;
	int			set_cnt;
	int			data_len;
	char		data[1];
} cmd_set_provider_data_t;

typedef struct cmd_get_provider_data {
	char		provider[256];
	int			type;
} cmd_get_provider_data_t;

typedef struct cmd_clear_provider_data {
	char		provider[256];
	int			type;
} cmd_clear_provider_data_t;

typedef struct cmd_set_service_persist {
	int			type;
} cmd_set_service_persist_t;

typedef struct ack_common {
	int st;
} ack_common_t;

typedef struct ack_get_view_entry {
	int				st;
	stmfViewEntry	ve;
} ack_get_view_entry_t;

typedef struct ack_get_lu_list {
	int				st;
	stmfGuidList	lu_list;
} ack_get_lu_list_t;

typedef struct ack_get_group_list {
	int				st;
	stmfGroupList	group_list;
} ack_get_group_list_t;

typedef struct ack_get_group_member_list {
	int					st;
	stmfGroupProperties	prop_list;
} ack_get_group_member_list_t;

typedef struct ack_get_view_entry_list {
	int					st;
	stmfViewEntryList	ve_list;
} ack_get_view_entry_list_t;

typedef struct ack_get_provider_data {
	int			st;
	char		provider[256];
	int			type;
	int			set_cnt;
	int			data_len;
	char		data[1];
} ack_get_provider_data_t;

typedef struct ack_get_provider_data_list {
	int					st;
	stmfProviderList	provider_list;
} ack_get_provider_data_list_t;

typedef struct ack_get_service_persist {
	int		st;
	int		persist_type;
} ack_get_service_persist_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _STMF_MSG_H */
