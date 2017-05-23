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
#include <unistd.h>
#include <assert.h>
#include <stddef.h>
#include <strings.h>
#include <sqlite3.h>
#include <libstmf.h>
#include <syslog.h>
#include <libnvpair.h>
#include "store.h"

int dbInit(stmf_store_info_t *storeInfo);
int dbCheckService(void);
int dbSetServicePersist(char *iPersistType);
int dbSetProviderData(int providerID, char *providerName, nvlist_t *nvl, 
	int providerType, int setToken, int *retProviderID);
int dbClearProviderData(int providerID);
int dbCreateGroup(char *groupName, int groupType, int *retGroupID);
int dbDeleteGroup(int groupID);
int dbAddGroupMember(int groupID, char *memberName, int *retElemID);
int dbRemoveGroupMember(int elemID);
int dbAddViewEntry(int hostGroupID, int targetGroupID, int veIndex, 
	uchar_t * luGuid, uchar_t *luNbr);
int dbRemoveViewEntry(int hostGroupID, int targetGroupID);

cfg_store_t db_store = {
	dbInit,
	dbCheckService,
	dbSetServicePersist,
	dbSetProviderData,
	dbClearProviderData,
	dbCreateGroup,
	dbDeleteGroup,
	dbAddGroupMember,
	dbRemoveGroupMember,
	dbAddViewEntry,
	dbRemoveViewEntry
};

static sqlite3 *db = NULL;
#define	DB_DIR			"/etc/svc/"
#define	DB_NAME			"repository.db"

/* GLOBAL CFG TABLE */
#define	GLOBAL_CFG_TABLE				"res_global_cfg"

#define	CFG_PERSIST_TYPE_COL_NAME		"persist_type"
#define	CFG_PERSIST_TYPE_COL_INDEX		0

#define	CFG_CFG_TABLE_COL_COUNT			1

/* PROVIDER TABLE */
#define	PROVIDER_TABLE					"res_provider"

#define	PROVIDER_ID_COL_NAME			"provider_id"
#define	PROVIDER_NAME_COL_NAME			"name"
#define	PROVIDER_TYPE_COL_NAME			"type"
#define	PROVIDER_SETCNT_COL_NAME		"setcnt"
#define	PROVIDER_ID_COL_INDEX			0
#define	PROVIDER_NAME_COL_INDEX			1
#define	PROVIDER_TYPE_COL_INDEX			2
#define	PROVIDER_SETCNT_COL_INDEX		3

#define	PROVIDER_TABLE_COL_COUNT		4

/* PROVIDER ELEM TABLE */
#define	PROVIDER_ELEM_TABLE				"res_provider_elem"

#define	PELEM_ID_COL_NAME				"elem_id"
#define	PELEM_PROVIDER_ID_COL_NAME		"provider_id"
#define	PELEM_VALUE_COL_NAME			"value"

#define	PELEM_ID_COL_INDEX				0
#define	PELEM_PROVIDER_ID_COL_INDEX		1
#define	PELEM_VALUE_COL_INDEX			2

#define	PROVIDER_ELEM_TABLE_COL_COUNT	3

/* GROUP TABLE */
#define	GROUP_TABLE						"res_group"

#define	GROUP_ID_COL_NAME				"group_id"
#define	GROUP_NAME_COL_NAME				"name"
#define	GROUP_TYPE_COL_NAME				"type"

#define	GROUP_ID_COL_INDEX				0
#define	GROUP_NAME_COL_INDEX			1
#define	GROUP_TYPE_COL_INDEX			2

#define	GROUP_TABLE_COL_COUNT			3

/* GROUP ELEM TABLE */
#define	GROUP_ELEM_TABLE				"res_group_elem"

#define	GELEM_ID_COL_NAME				"elem_id"
#define	GELEM_GROUP_ID_COL_NAME			"group_id"
#define	GELEM_MEMBER_COL_NAME			"member"

#define	GELEM_ID_COL_INDEX				0
#define	GELEM_GROUP_ID_COL_INDEX		1
#define	GELEM_MEMBER_COL_INDEX			2

#define	GROUP_ELEM_TABLE_COL_COUNT		3

/* VIEW TABLE */
#define	VIEW_TABLE						"res_view"

#define	VIEW_HG_ID_COL_NAME				"hg_id"
#define	VIEW_TG_ID_COL_NAME				"tg_id"
#define	VIEW_INDEX_COL_NAME				"ve_index"
#define	VIEW_LU_GUID_COL_NAME			"lu_guid"
#define	VIEW_LU_NBR_COL_NAME			"lu_nbr"

#define	VIEW_HG_ID_COL_INDEX			0
#define	VIEW_TG_ID_COL_INDEX			1
#define	VIEW_INDEX_COL_INDEX			2
#define	VIEW_LU_GUILD_COL_INDEX			3
#define	VIEW_LU_NBR_COL_INDEX			4

#define	VIEW_TABLE_COL_COUNT			5

#define	SQL_LEN							512

int
dbExecuteSql(sqlite3 *db, const char *sql)
{
	char *errMsg = NULL;
	
	if (SQLITE_OK != sqlite3_exec(db, sql, 0, 0, &errMsg)) {
		syslog(LOG_ERR, "execute %s failed: %s", sql, errMsg);
		return (STMF_PS_ERROR_CFG_OPERATION);
	}

	return (STMF_PS_SUCCESS);
}

int
dbExecuteQuery(sqlite3 *db, const char *sql, char ***result,
	int *pRow, int *pCol)
{
	char *errMsg = NULL;

	if (SQLITE_OK != sqlite3_get_table(db, sql, result, pRow, 
		pCol, &errMsg)) {
		syslog(LOG_ERR, "execute query %s failed: %s", sql, errMsg);
		return (-1);
	}

	if (*pRow == 0) {
		sqlite3_free_table(*result);
		return (-2);
	}

	return (0);
}

int
dbTableExist(char *tableName)
{
	char sql[SQL_LEN] = {0};
	char **result = NULL;
	int row, col, ret;
	
	snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM sqlite_master "
		"WHERE TYPE = \"table\" AND NAME = \"%s\";",
		tableName);

	if (dbExecuteQuery(db, sql, &result, &row, &col) < 0)
		return (-1);
	
	ret = (strncmp(result[1], "1", 1) == 0) ? 1 : 0;
	sqlite3_free_table(result);
	return (ret);
}

int
dbCreateGlobalCfgTable(void)
{
	char sql[SQL_LEN] = {0};
	int ret;
	
	snprintf(sql, sizeof(sql), "CREATE TABLE %s("
		"%s VARCHAR(32)"
		");", 
		GLOBAL_CFG_TABLE,
		PELEM_PROVIDER_ID_COL_NAME);

	ret = dbExecuteSql(db, sql);
	if (ret != STMF_PS_SUCCESS)
		return (ret);

	snprintf(sql, sizeof(sql), "INSERT INTO %s VALUES(\"%s\");",
		GLOBAL_CFG_TABLE,
		STMF_PS_PERSIST_SMF);
	
	return dbExecuteSql(db, sql);
}

int
dbCreateProviderTable(void)
{
	char sql[SQL_LEN] = {0};

	snprintf(sql, sizeof(sql), "CREATE TABLE %s("
		"%s INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
		"%s VARCHAR(256), "
		"%s INTEGER, "
		"%s INTEGER"
		");", 
		PROVIDER_TABLE,
		PROVIDER_ID_COL_NAME,
		PROVIDER_NAME_COL_NAME,
		PROVIDER_TYPE_COL_NAME,
		PROVIDER_SETCNT_COL_NAME);

	return dbExecuteSql(db, sql);
}

int
dbCreateProviderElemTable(void)
{
	char sql[SQL_LEN] = {0};
	
	snprintf(sql, sizeof(sql), "CREATE TABLE %s("
		"%s INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
		"%s INTEGER, "
		"%s BLOB, "
		"FOREIGN KEY(%s) REFERENCES %s(%s)"
		");", 
		PROVIDER_ELEM_TABLE,
		PELEM_ID_COL_NAME,
		PELEM_PROVIDER_ID_COL_NAME,
		PELEM_VALUE_COL_NAME,
		PELEM_PROVIDER_ID_COL_NAME,
		PROVIDER_TABLE,
		PROVIDER_ID_COL_NAME);

	return dbExecuteSql(db, sql);
}

int
dbCreateGroupTable(void)
{
	char sql[SQL_LEN] = {0};
	int ret;

	snprintf(sql, sizeof(sql), "CREATE TABLE %s("
		"%s INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
		"%s VARCHAR(256), "
		"%s INTEGER"
		");", 
		GROUP_TABLE,
		GROUP_ID_COL_NAME,
		GROUP_NAME_COL_NAME,
		GROUP_TYPE_COL_NAME);

	ret = dbExecuteSql(db, sql);
	if (ret != STMF_PS_SUCCESS)
		return (ret);

	/* add default host/target group */
	snprintf(sql, sizeof(sql), "INSERT INTO %s (%s, %s) "
		"VALUES(\"%s\", %d);",
		GROUP_TABLE,
		GROUP_NAME_COL_NAME,
		GROUP_TYPE_COL_NAME,
		STMF_PS_DEFAULT_HG,
		DB_HOST_GROUP);

	ret = dbExecuteSql(db, sql);
	if (ret != STMF_PS_SUCCESS)
		return (ret);

	snprintf(sql, sizeof(sql), "INSERT INTO %s (%s, %s) "
		"VALUES(\"%s\", %d);",
		GROUP_TABLE,
		GROUP_NAME_COL_NAME,
		GROUP_TYPE_COL_NAME,
		STMF_PS_DEFAULT_TG,
		DB_TARGET_GROUP);

	return dbExecuteSql(db, sql);
}

int
dbCreateGroupElemTable(void)
{
	char sql[SQL_LEN] = {0};

	snprintf(sql, sizeof(sql), "CREATE TABLE %s("
		"%s INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
		"%s INTEGER, "
		"%s VARCHAR(256), "
		"FOREIGN KEY(%s) REFERENCES %s(%s)"
		");", 
		GROUP_ELEM_TABLE,
		GELEM_ID_COL_NAME,
		GELEM_GROUP_ID_COL_NAME,
		GELEM_MEMBER_COL_NAME,
		GELEM_GROUP_ID_COL_NAME,
		GROUP_TABLE,
		GROUP_ID_COL_NAME);

	return dbExecuteSql(db, sql);
}

int
dbCreateViewTable(void)
{
	char sql[SQL_LEN] = {0};

	snprintf(sql, sizeof(sql), "CREATE TABLE %s("
		"%s INTEGER, "
		"%s INTEGER, "
		"%s INTEGER, "
		"%s CHAR(33), "
		"%s CHAR(8), "
		"PRIMARY KEY(%s, %s), "
		"FOREIGN KEY(%s) REFERENCES %s(%s), "
		"FOREIGN KEY(%s) REFERENCES %s(%s)"
		");", 
		VIEW_TABLE,
		VIEW_HG_ID_COL_NAME,
		VIEW_TG_ID_COL_NAME,
		VIEW_INDEX_COL_NAME,
		VIEW_LU_GUID_COL_NAME,
		VIEW_LU_NBR_COL_NAME,
		VIEW_HG_ID_COL_NAME,
		VIEW_TG_ID_COL_NAME,
		VIEW_HG_ID_COL_NAME,
		GROUP_TABLE,
		GROUP_ID_COL_NAME,
		VIEW_TG_ID_COL_NAME,
		GROUP_TABLE,
		GROUP_ID_COL_NAME);

	return dbExecuteSql(db, sql);
}

int
dbLoadGlobalCfg(stmf_global_cfg_t *cfg)
{
	char sql[SQL_LEN] = {0};
	sqlite3_stmt *stmt;
	char *value;
	int len, ret;

	if (!cfg)
		return (STMF_PS_ERROR_INVALID_ARG);

	snprintf(sql, sizeof(sql), "SELECT * FROM %s;", GLOBAL_CFG_TABLE);

	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (STMF_PS_ERROR_CFG_OPERATION);
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		syslog(LOG_ERR, "%s sqlite3_step(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (STMF_PS_ERROR_CFG_OPERATION);
	}

	value = (char *)sqlite3_column_text(stmt, CFG_PERSIST_TYPE_COL_INDEX);
	len = sqlite3_column_bytes(stmt, CFG_PERSIST_TYPE_COL_INDEX);
	strncpy(cfg->persist_type, value, len);	
	sqlite3_finalize(stmt);
	return (STMF_PS_SUCCESS);
}

int
dbLoadProviderNVList(int providerID, nvlist_t **nvl)
{
	char sql[SQL_LEN] = {0};
	sqlite3_stmt *stmt;
	char *nvlistEncoded = NULL;
	int nvlistEncodedSize = 0;
	int blockCnt = 0;
	void *value;
	int len, ret;

	snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s WHERE "
		"%s = %d",
		PROVIDER_ELEM_TABLE,
		PELEM_PROVIDER_ID_COL_NAME,
		providerID);
	
	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (ret);
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		syslog(LOG_ERR, "%s sqlite3_step(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (STMF_PS_ERROR);
	}

	blockCnt = sqlite3_column_int(stmt, 0);
	nvlistEncoded = (char *)calloc(1, 
		blockCnt * STMF_PROVIDER_DATA_PROP_SIZE);
	if (nvlistEncoded == NULL) {
		syslog(LOG_ERR, "nvlistEncoded alloc failed");
		return (STMF_PS_ERROR_NOMEM);
	}

	sqlite3_finalize(stmt);

	snprintf(sql, sizeof(sql), "SELECT * FROM %s WHERE "
		"%s = %d",
		PROVIDER_ELEM_TABLE,
		PELEM_PROVIDER_ID_COL_NAME,
		providerID);

	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (ret);
	}
	
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		len = sqlite3_column_bytes(stmt, PELEM_VALUE_COL_INDEX);
		value = (void *)sqlite3_column_blob(stmt, PELEM_VALUE_COL_INDEX);
		memcpy(&nvlistEncoded[nvlistEncodedSize], (char *)value, len);
		nvlistEncodedSize += len;
	}

	sqlite3_finalize(stmt);

	if (nvlist_unpack(nvlistEncoded, nvlistEncodedSize, nvl, 0) != 0) {
		syslog(LOG_ERR, "unable to unpack nvlist");
		return (STMF_PS_ERROR);
	}
	
	return (STMF_PS_SUCCESS);
}

int
dbLoadProviderList(list_t *providers)
{
	char sql[SQL_LEN] = {0};
	sqlite3_stmt *stmt;
	stmf_provider_t *provider;
	char *value;
	int len;
	int ret;

	if (!providers)
		return (STMF_PS_ERROR_INVALID_ARG);

	list_create(providers, sizeof(stmf_provider_t), 
		offsetof(stmf_provider_t, node));

	snprintf(sql, sizeof(sql), "SELECT * FROM %s;",
		PROVIDER_ELEM_TABLE);

	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (STMF_PS_ERROR_CFG_OPERATION);
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		provider = malloc(sizeof(stmf_provider_t));
		memset(provider, 0, sizeof(stmf_provider_t));
		provider->provider_id = sqlite3_column_int(stmt, PROVIDER_ID_COL_INDEX);
		value = (char *)sqlite3_column_text(stmt, PROVIDER_NAME_COL_INDEX);
		len = sqlite3_column_bytes(stmt, PROVIDER_NAME_COL_INDEX);
		strncpy(provider->name, value, len);
		provider->type = sqlite3_column_int(stmt, PROVIDER_TYPE_COL_INDEX);
		provider->setcnt = sqlite3_column_int(stmt, PROVIDER_SETCNT_COL_INDEX);
		if (STMF_PS_SUCCESS != 
			dbLoadProviderNVList(provider->provider_id, &provider->nvl))
			syslog(LOG_ERR, "%s %s load nvlist failed", __func__,
				provider->name);
		list_insert_tail(providers, provider);
	}

	sqlite3_finalize(stmt);
	return (STMF_PS_SUCCESS);
}

int
dbLoadGroupElems(int groupID, list_t *elems)
{
	char sql[SQL_LEN] = {0};
	sqlite3_stmt *stmt;
	stmf_group_elem_t *elem;
	char *value;
	int len, ret;

	if (!elems)
		return (STMF_PS_ERROR_INVALID_ARG);

	list_create(elems, sizeof(stmf_group_elem_t),
		offsetof(stmf_group_elem_t, node));

	snprintf(sql, sizeof(sql), "SELECT * FROM %s WHERE "
		"%s = %d",
		GROUP_ELEM_TABLE,
		GELEM_GROUP_ID_COL_NAME,
		groupID);
	
	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (ret);
	}
	
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		elem = malloc(sizeof(stmf_group_elem_t));
		memset(elem, 0, sizeof(stmf_group_elem_t));
		elem->elem_id = sqlite3_column_int(stmt, GELEM_ID_COL_INDEX);
		elem->group_id = sqlite3_column_int(stmt, GELEM_GROUP_ID_COL_INDEX);
		len = sqlite3_column_bytes(stmt, GELEM_MEMBER_COL_INDEX);
		value = (char *)sqlite3_column_text(stmt, GELEM_MEMBER_COL_INDEX);
		strncpy(elem->name, value, len);
		list_insert_tail(elems, elem);
	}

	sqlite3_finalize(stmt);
	return (STMF_PS_SUCCESS);
}

int
dbLoadGroupList(list_t *groups)
{
	char sql[SQL_LEN] = {0};
	sqlite3_stmt *stmt;
	stmf_group_t *group;
	char *value;
	int len, ret;

	if (!groups)
		return (STMF_PS_ERROR_INVALID_ARG);

	list_create(groups, sizeof(stmf_group_t),
		offsetof(stmf_group_t, node));

	snprintf(sql, sizeof(sql), "SELECT * FROM %s;",
		GROUP_TABLE);
	
	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (STMF_PS_ERROR_CFG_OPERATION);
	}
	
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		group = malloc(sizeof(stmf_group_t));
		memset(group, 0, sizeof(stmf_group_t));
		group->group_id = sqlite3_column_int(stmt, GROUP_ID_COL_INDEX);
		len = sqlite3_column_bytes(stmt, GROUP_NAME_COL_INDEX);
		value = (char *)sqlite3_column_text(stmt, GROUP_NAME_COL_INDEX);
		strncpy(group->name, value, len);
		group->type = sqlite3_column_int(stmt, GROUP_TYPE_COL_INDEX);
		dbLoadGroupElems(group->group_id, &group->elem_list);
		list_insert_tail(groups, group);
	}

	sqlite3_finalize(stmt);
	return (STMF_PS_SUCCESS);

}

int
dbLoadLunViews(list_t *lun_views)
{
	char sql[SQL_LEN] = {0};
	sqlite3_stmt *stmt;
	stmf_lun_view_t *lun_view;
	char *value;
	int len, ret;

	if (!lun_views)
		return (STMF_PS_ERROR_INVALID_ARG);

	list_create(lun_views, sizeof(stmf_lun_view_t),
		offsetof(stmf_lun_view_t, node));

	snprintf(sql, sizeof(sql), "SELECT * FROM %s;",
		VIEW_TABLE);
	
	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (STMF_PS_ERROR_CFG_OPERATION);
	}
	
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		lun_view = malloc(sizeof(stmf_lun_view_t));
		memset(lun_view, 0, sizeof(stmf_lun_view_t));
		lun_view->hg_id = sqlite3_column_int(stmt, VIEW_HG_ID_COL_INDEX);
		lun_view->tg_id = sqlite3_column_int(stmt, VIEW_TG_ID_COL_INDEX);
		lun_view->ve_index = sqlite3_column_int(stmt, VIEW_INDEX_COL_INDEX);

		len = sqlite3_column_bytes(stmt, VIEW_LU_GUILD_COL_INDEX);
		value = (char *)sqlite3_column_text(stmt, VIEW_LU_GUILD_COL_INDEX);
		strncpy((char *)lun_view->lu_guid, value, len);
		
		len = sqlite3_column_bytes(stmt, VIEW_LU_NBR_COL_INDEX);
		value = (char *)sqlite3_column_text(stmt, VIEW_LU_NBR_COL_INDEX);
		memcpy(lun_view->lu_nbr, value, len);
		
		list_insert_tail(lun_views, lun_view);
	}

	sqlite3_finalize(stmt);
	return (STMF_PS_SUCCESS);
}

int
dbLoadLuns(list_t *luns)
{
	list_t lun_views;
	stmf_lun_view_t *lun_view = NULL;
	stmf_lun_t *lun = NULL;
	stmf_view_t *view = NULL;
	int ret;

	if (!luns)
		return (STMF_PS_ERROR_INVALID_ARG);

	list_create(luns, sizeof(stmf_lun_t), 
		offsetof(stmf_lun_t, node));
	ret = dbLoadLunViews(&lun_views);
	if (ret != STMF_PS_SUCCESS)
		return (ret);
	
	lun_view = list_head(&lun_views);
	while (lun_view) {
		for (lun = list_head(luns);
			lun;
			lun = list_next(luns, lun)) {
			if (memcmp(lun->lu_guid, lun_view->lu_guid, 
				sizeof(lun->lu_guid)) == 0)
				break;
		}

		if (!lun) {
			lun = malloc(sizeof(stmf_lun_t));
			memset(lun, 0, sizeof(stmf_lun_t));
			memcpy(lun->lu_guid, lun_view->lu_guid, sizeof(lun_view->lu_guid));
			memcpy(lun->lu_nbr, lun_view->lu_nbr, sizeof(lun_view->lu_nbr));
			list_create(&lun->view_list, sizeof(stmf_view_t),
				offsetof(stmf_view_t, node));
			list_insert_tail(luns, lun);
		}

		view = malloc(sizeof(stmf_view_t));
		memset(view, 0, sizeof(stmf_view_t));
		view->hg_id = lun_view->hg_id;
		view->tg_id = lun_view->tg_id;
		view->ve_index = lun_view->ve_index;
		list_insert_tail(&lun->view_list, view);
		
		lun_view = list_next(&lun_views, lun_view);
	}

	return (STMF_PS_SUCCESS);
}

int
dbLoad(stmf_store_info_t *storeInfo)
{
	int ret;

	ret = dbLoadGlobalCfg(storeInfo->cfg);
	if (ret != STMF_PS_SUCCESS) {
		syslog(LOG_ERR, "%s load global cfg failed", __func__);
		return (ret);
	}
	
	ret = dbLoadProviderList(storeInfo->providers);	
	if (ret != STMF_PS_SUCCESS) {
		syslog(LOG_ERR, "%s load provider failed", __func__);
		return (ret);
	}
	
	ret = dbLoadGroupList(storeInfo->groups);
	if (ret != STMF_PS_SUCCESS) {
		syslog(LOG_ERR, "%s load group failed", __func__);
		return (ret);
	}

	ret = dbLoadLuns(storeInfo->luns);	
	if (ret != STMF_PS_SUCCESS) {
		syslog(LOG_ERR, "%s load luns failed", __func__);
		return (ret);
	}

	return (STMF_PS_SUCCESS);
}

int
dbInit(stmf_store_info_t *storeInfo)
{
	char *errMsg = NULL;
	char cmd[256] = {0};
	char dbPath[256] = {0};

	if (access(DB_DIR, R_OK | W_OK)) {
		if (mkdir(DB_DIR, 0644))
			syslog(LOG_ERR, "%s mkdir %s failed", __func__);
	}
	
	snprintf(dbPath, sizeof(dbPath), "%s%s", DB_DIR, DB_NAME);
	
	if (SQLITE_OK != 
		sqlite3_open(dbPath, &db)) {
		syslog(LOG_ERR, "%s can't open database: %s", __func__, dbPath);
		return (STMF_PS_ERROR);
	}

	if (SQLITE_OK != 
		sqlite3_exec(db, "PRAGMA foreign_keys = ON", 0, 0, &errMsg)) {
		syslog(LOG_ERR, "%s foreign_keys ON failed %s", __func__, errMsg);
	}

	if (SQLITE_OK != 
		sqlite3_exec(db, "begin transaction", 0, 0, &errMsg)) {
		syslog(LOG_ERR, "%s begin transaction failed: %s", __func__, errMsg);
		goto init_failed;
	}

	if (dbTableExist(GLOBAL_CFG_TABLE) == 0) {
		if (dbCreateGlobalCfgTable() < 0)
			goto init_failed;
	}

	if (dbTableExist(PROVIDER_TABLE) == 0) {
		if (dbCreateProviderTable() < 0)
			goto init_failed;
	}

	if (dbTableExist(PROVIDER_ELEM_TABLE) == 0) {
		if (dbCreateProviderElemTable() < 0)
			goto init_failed;
	}

	if (dbTableExist(GROUP_TABLE) == 0) {
		if (dbCreateGroupTable() < 0)
			goto init_failed;
	}

	if (dbTableExist(GROUP_ELEM_TABLE) == 0) {
		if (dbCreateGroupElemTable() < 0)
			goto init_failed;
	}

	if (dbTableExist(VIEW_TABLE) == 0) {
		if (dbCreateViewTable() < 0)
			goto init_failed;
	}
	
	if (SQLITE_OK != 
		sqlite3_exec(db, "commit transaction", 0, 0, &errMsg)) {
		syslog(LOG_ERR, "%s commit failed: %s", __func__, errMsg);
		goto init_failed;
	}

	return dbLoad(storeInfo);

init_failed:
	syslog(LOG_ERR, "%s init failed, rollback", __func__);
	
	if (SQLITE_OK != 
		sqlite3_exec(db, "rollback transaction", 0, 0, &errMsg))
		syslog(LOG_ERR, "%s rollback failed: %s", __func__, errMsg);

	return (STMF_PS_ERROR);
}

int
dbFini(void)
{
	int rc = 0;
	if (db) {
		rc = sqlite3_close(db);

		if (rc != SQLITE_OK)
			syslog(LOG_ERR, "%s failed to close database", __func__);
	}

	return (rc);
}

int
dbCheckService()
{
	return (db ?  STMF_PS_SUCCESS : STMF_PS_ERROR);
}

int 
dbSetServicePersist(char *iPersistType)
{
	char sql[SQL_LEN] = {0};

	snprintf(sql, sizeof(sql), "UPDATE %s SET "
		"%s = \"%s\";",
		GLOBAL_CFG_TABLE,
		CFG_PERSIST_TYPE_COL_NAME,
		iPersistType);

	return dbExecuteSql(db, sql);
}

int
dbClearProviderElem(int providerID)
{
	char sql[SQL_LEN] = {0};

	snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE "
		"%s = %d;",
		PROVIDER_ELEM_TABLE,
		PELEM_PROVIDER_ID_COL_NAME,
		providerID);

	return dbExecuteSql(db, sql);
}

int
dbSetProviderElem(int providerID, nvlist_t *nvl)
{
	char sql[SQL_LEN] = {0};
	char *nvlistEncoded = NULL;
	size_t nvlistEncodedSize;
	int blockCnt, blockSize, blockOffset;
	int i, ret;
	sqlite3_stmt *stmt;

	if (!nvl)
		return (STMF_PS_ERROR_INVALID_ARG);

	if (nvlist_pack(nvl, &nvlistEncoded, &nvlistEncodedSize,
	    NV_ENCODE_XDR, 0) != 0) {
		syslog(LOG_ERR, "nvlist_pack failed");
		return (STMF_PS_ERROR_NOMEM);
	}

	blockCnt = nvlistEncodedSize / STMF_PROVIDER_DATA_PROP_SIZE;
	if (nvlistEncodedSize % STMF_PROVIDER_DATA_PROP_SIZE)
		blockCnt++;
	
	for (i = 0; i < blockCnt; i++) {
		snprintf(sql, sizeof(sql), "INSERT INTO %s (%s, %s) "
			"VALUES(?, ?);",
			PROVIDER_ELEM_TABLE,
			PELEM_PROVIDER_ID_COL_NAME,
			PELEM_VALUE_COL_NAME);

		ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
		if (ret != SQLITE_OK) {
			syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
				ret, sqlite3_errmsg(db));
			break;
		}
		
		if ((STMF_PROVIDER_DATA_PROP_SIZE * (i + 1))
	    	> nvlistEncodedSize) {
			blockSize = nvlistEncodedSize
		    	- STMF_PROVIDER_DATA_PROP_SIZE * i;
		} else {
			blockSize = STMF_PROVIDER_DATA_PROP_SIZE;
		}

		blockOffset = STMF_PROVIDER_DATA_PROP_SIZE * i;

		ret = sqlite3_bind_int(stmt, 1, providerID);
		if (ret != SQLITE_OK) {
			syslog(LOG_ERR, "%s sqlite3_bind_int(%d): %s", __func__,
				ret, sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			break;
		}
		
		ret = sqlite3_bind_blob(stmt, 2, &nvlistEncoded[blockOffset],
			blockSize, NULL);
		if (ret != SQLITE_OK) {
			syslog(LOG_ERR, "%s sqlite3_bind_blob(%d): %s", __func__,
				ret, sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			break;
		}
		
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_DONE) {
			syslog(LOG_ERR, "%s sqlite3_step(%d): %s", __func__,
				ret, sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			ret = STMF_PS_ERROR_CFG_OPERATION;
			break;
		}

		ret = STMF_PS_SUCCESS;
		sqlite3_finalize(stmt);
	}

	return (ret);
}

int
dbAddProvider(char *providerName, int providerType, int setToken, int *providerID)
{
	char sql[SQL_LEN] = {0};
	sqlite3_stmt *stmt;
	int ret;

	if (!providerID)
		return (STMF_PS_ERROR_INVALID_ARG);

	snprintf(sql, sizeof(sql), "INSERT INTO %s (%s, %s, %s) "
		"VALUES(?, ?, ?);",
		PROVIDER_TABLE,
		PROVIDER_NAME_COL_NAME,
		PROVIDER_TYPE_COL_NAME,
		PROVIDER_SETCNT_COL_NAME);

	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (ret);
	}
	
	ret = sqlite3_bind_text(stmt, 1, providerName, strlen(providerName),
		SQLITE_STATIC);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_bind_text(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (ret);	
	}
	
	ret = sqlite3_bind_int(stmt, 2, providerType);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_bind_int(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (ret);
	}

	ret = sqlite3_bind_int(stmt, 3, setToken);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_bind_int(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (ret);
	}
	
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		syslog(LOG_ERR, "%s sqlite3_step(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (STMF_PS_ERROR_CFG_OPERATION);
	}
	
	sqlite3_finalize(stmt);

	/* query providerID */
	snprintf(sql, sizeof(sql), "SELECT * FROM %s WHERE "
		"%s = \"%s\" AND "
		"%s = %d;",
		PROVIDER_TABLE,
		PROVIDER_NAME_COL_NAME,
		providerName,
		PROVIDER_TYPE_COL_NAME,
		providerType);

	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (ret);
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		syslog(LOG_ERR, "%s sqlite3_step(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (STMF_PS_ERROR_CFG_OPERATION);
	}
	
	*providerID = sqlite3_column_int(stmt, PROVIDER_ID_COL_INDEX);
	
	return (STMF_PS_SUCCESS);
}

int
dbUpdateProvider(int providerID, int setToken)
{
	char sql[SQL_LEN] = {0};

	snprintf(sql, sizeof(sql), "UPDATE %s SET %s = %d "
		"WHERE %s = %d;",
		PROVIDER_TABLE,
		PROVIDER_SETCNT_COL_NAME,
		setToken,
		PROVIDER_ID_COL_NAME,
		providerID);

	return dbExecuteSql(db, sql);
}

int
dbClearProvider(int providerID)
{
	char sql[SQL_LEN] = {0};

	snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE "
		"%s = %d;",
		PROVIDER_TABLE,
		PROVIDER_ID_COL_NAME,
		providerID);

	return dbExecuteSql(db, sql);
}

int
dbSetProviderData(int providerID, char *providerName, nvlist_t *nvl,
	int providerType, int setToken, int *retProviderID)
{
	char *errMsg = NULL;
	int ret = STMF_PS_SUCCESS;

	if (!retProviderID)
		return (STMF_PS_ERROR_INVALID_ARG);

	ret = sqlite3_exec(db, "begin transaction", 0, 0, &errMsg);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s begin transaction failed(%d): %s", 
			__func__, ret, errMsg);
		goto rollback;
	}
	
	if (providerID == -1) {
		/* new provider */
		ret = dbAddProvider(providerName, providerType, setToken, retProviderID);
		if (ret != STMF_PS_SUCCESS)
			goto rollback;

		ret = dbSetProviderElem(*retProviderID, nvl);
		if (ret != STMF_PS_SUCCESS)
			goto rollback;
	} else {
		ret = dbUpdateProvider(providerID, setToken);
		if (ret != STMF_PS_SUCCESS)
			goto rollback;

		ret = dbClearProviderElem(providerID);
		if (ret != STMF_PS_SUCCESS)
			goto rollback;

		ret = dbSetProviderElem(providerID, nvl);
		if (ret != STMF_PS_SUCCESS)
			goto rollback;
	}

	ret = sqlite3_exec(db, "commit transaction", 0, 0, &errMsg);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s commit failed(%d): %s", __func__, 
			ret, errMsg);
		goto rollback;
	}
	
	return (STMF_PS_SUCCESS);

rollback:
	ret = sqlite3_exec(db, "rollback transaction", 0, 0, &errMsg);
	if (ret != SQLITE_OK)
		syslog(LOG_ERR, "%s rollback failed(%d): %s", __func__,
			ret, errMsg);

	return (STMF_PS_ERROR_CFG_OPERATION);
}

int 
dbClearProviderData(int providerID)
{
	char *errMsg = NULL;
	int ret = STMF_PS_SUCCESS;

	ret = sqlite3_exec(db, "begin transaction", 0, 0, &errMsg);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s begin transaction failed(%d): %s", 
			__func__, ret, errMsg);
		goto rollback;
	}

	ret = dbClearProviderElem(providerID);
	if (ret != STMF_PS_SUCCESS)
		goto rollback;

	ret = dbClearProvider(providerID);
	if (ret != STMF_PS_SUCCESS)
		goto rollback;

	ret = sqlite3_exec(db, "commit transaction", 0, 0, &errMsg);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s commit failed(%d): %s", __func__, 
			ret, errMsg);
		goto rollback;
	}

	return (STMF_PS_SUCCESS);

rollback:
	ret = sqlite3_exec(db, "rollback transaction", 0, 0, &errMsg);
	if (ret != SQLITE_OK)
		syslog(LOG_ERR, "%s rollback failed(%d): %s", __func__,
			ret, errMsg);

	return (STMF_PS_ERROR_CFG_OPERATION);
}

int 
dbCreateGroup(char *groupName, int groupType, int *retGroupID)
{
	char sql[SQL_LEN] = {0};
	sqlite3_stmt *stmt;
	int ret;

	if (!retGroupID)
		return (STMF_PS_ERROR_INVALID_ARG);

	snprintf(sql, sizeof(sql), "INSERT INTO %s (%s, %s) "
		"VALUES(\"%s\", %d)",
		GROUP_TABLE,
		GROUP_NAME_COL_NAME,
		GROUP_TYPE_COL_NAME,
		groupName,
		groupType);

	ret = dbExecuteSql(db, sql);
	if (ret != STMF_PS_SUCCESS)
		return (STMF_PS_ERROR_CFG_OPERATION);

	snprintf(sql, sizeof(sql), "SELECT * FROM %s "
		"WHERE %s = \"%s\" AND "
		"%s = %d;",
		GROUP_TABLE,
		GROUP_NAME_COL_NAME,
		groupName,
		GROUP_TYPE_COL_NAME,
		groupType);

	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (ret);
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		syslog(LOG_ERR, "%s sqlite3_step(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (STMF_PS_ERROR_CFG_OPERATION);
	}
	
	*retGroupID = sqlite3_column_int(stmt, GROUP_ID_COL_INDEX);
	return (STMF_PS_SUCCESS);
}

int 
dbDeleteGroup(int groupID)
{
	char sql[SQL_LEN] = {0};

	snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE "
		"%s = %d;",
		GROUP_TABLE,
		GROUP_ID_COL_NAME,
		groupID);

	return dbExecuteSql(db, sql);
}

int 
dbAddGroupMember(int groupID, char *memberName, int *retElemID)
{
	char sql[SQL_LEN] = {0};
	sqlite3_stmt *stmt;
	int ret;

	if (!retElemID)
		return (STMF_PS_ERROR_INVALID_ARG);

	snprintf(sql, sizeof(sql), "INSERT INTO %s (%s, %s) "
		"VALUES(%d, \"%s\");",
		GROUP_ELEM_TABLE,
		GELEM_GROUP_ID_COL_NAME,
		GELEM_MEMBER_COL_NAME,
		groupID,
		memberName);

	ret = dbExecuteSql(db, sql);
	if (ret != STMF_PS_SUCCESS)
		return (STMF_PS_ERROR_CFG_OPERATION);

	snprintf(sql, sizeof(sql), "SELECT * FROM %s "
		"WHERE %s = %d AND "
		"%s = \"%s\";",
		GROUP_ELEM_TABLE,
		GELEM_GROUP_ID_COL_NAME,
		groupID,
		GELEM_MEMBER_COL_NAME,
		memberName);

	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (ret);
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		syslog(LOG_ERR, "%s sqlite3_step(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (STMF_PS_ERROR_CFG_OPERATION);
	}
	
	*retElemID = sqlite3_column_int(stmt, GELEM_ID_COL_INDEX);
	return (STMF_PS_SUCCESS);	
}

int 
dbRemoveGroupMember(int elemID)
{
	char sql[SQL_LEN] = {0};

	snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE "
		"%s = %d;",
		GROUP_ELEM_TABLE,
		GELEM_ID_COL_NAME,
		elemID);

	return dbExecuteSql(db, sql);
}

int 
dbAddViewEntry(int hostGroupID, int targetGroupID, int veIndex, 
	uchar_t * luGuid, uchar_t *luNbr)
{
	char sql[SQL_LEN] = {0};
	sqlite3_stmt *stmt;
	int ret;

	snprintf(sql, sizeof(sql), "INSERT INTO %s "
		"VALUES(?, ?, ?, ?, ?);",
		VIEW_TABLE);

	ret = sqlite3_prepare(db, sql, -1, &stmt, 0);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s sqlite3_prepare(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		return (ret);
	}

	ret = sqlite3_bind_int(stmt, 1, hostGroupID);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s 1 sqlite3_bind_int(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (ret);
	}

	ret = sqlite3_bind_int(stmt, 2, targetGroupID);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s 2 sqlite3_bind_int(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (ret);
	}

	ret = sqlite3_bind_int(stmt, 3, veIndex);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s 3 sqlite3_bind_int(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (ret);
	}

	ret = sqlite3_bind_text(stmt, 4, (char *)luGuid, 33, SQLITE_STATIC);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s 4 sqlite3_bind_text(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (ret);	
	}

	ret = sqlite3_bind_text(stmt, 5, (char *)luNbr, 8, SQLITE_STATIC);
	if (ret != SQLITE_OK) {
		syslog(LOG_ERR, "%s 5 sqlite3_bind_text(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (ret);	
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		syslog(LOG_ERR, "%s sqlite3_step(%d): %s", __func__,
			ret, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return (STMF_PS_ERROR_CFG_OPERATION);
	}

	sqlite3_finalize(stmt);
	return (STMF_PS_SUCCESS);
}

int 
dbRemoveViewEntry(int hostGroupID, int targetGroupID)
{
	char sql[SQL_LEN] = {0};

	snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE "
		"%s = %d AND "
		"%s = %d;",
		VIEW_TABLE,
		VIEW_HG_ID_COL_NAME,
		hostGroupID,
		VIEW_TG_ID_COL_NAME,
		targetGroupID);

	return dbExecuteSql(db, sql);
}

