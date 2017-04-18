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
 *
 * Copyright 2009 CeresData Co., Ltd.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _CLUMGT_IMPL_H
#define	_CLUMGT_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <dlfcn.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/file.h>
#include <locale.h>
#include <libintl.h>
#include <ctype.h>
#include <signal.h>
#include <ftw.h>
#include <sys/types.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/int_types.h>
#include <limits.h>
#include <strings.h>
#include "clu_sync.h"
#include <libgen.h>
#include <syslog.h>
#include <thread.h>
#include <libclumgt.h>
#include "message.h"
#include "clumgt.h"





#define	DAEMON_LOCK_FILE ".clumgt_daemon.lock"


#define	VARRUN "/var/run"



#define	CLUMGT "clumgt"
#define	CLUMGTD "clumgtd"
#define	DEFAULT_USER	"root"
#define	DEFAULT_GROUP	"bin"

/* add new debug level and meanings here */
#define	DEVLINK_MID		"clumgt:devlink"
#define	MODLOAD_MID		"clumgt:modload"
#define	INITFINI_MID		"clumgt:initfini"
#define	EVENT_MID		"clumgt:event"
#define	REMOVE_MID		"clumgt:remove"
#define	LOCK_MID		"clumgt:lock"
#define	PATH2INST_MID		"devfsadm:path2inst"
#define	CACHE_MID		"clumgt:cache"
#define	BUILDCACHE_MID		"clumgt:buildcache"
#define	RECURSEDEV_MID		"clumgt:recursedev"
#define	INSTSYNC_MID		"clumgt:instsync"
#define	FILES_MID		"clumgt:files"
#define	ENUM_MID		"clumgt:enum"
#define	RSRV_MID		"clumgt:rsrv"	/* enum interface reserve  */
#define	RSBY_MID		"clumgt:rsby"	/* enum reserve bypass */
#define	LINKCACHE_MID		"clumgt:linkcache"
#define	ADDREMCACHE_MID		"clumgt:addremcache"
#define	MALLOC_MID		"clumgt:malloc"
#define	READDIR_MID		"clumgt:readdir"
#define	READDIR_ALL_MID		"clumgt:readdir_all"
#define	DEVNAME_MID		"clumgt:devname"
#define	ALL_MID			"all"


#define	CLUMGT_DEBUG_ON	FALSE

#define BUF_CMD 				256
#define BUF_MAX 				128
#define BUF_SHORT 				32

typedef enum cmd_type {
	SHELL_COMMON = 0,
	SHELL_CD,
	SHELL_FORK,
	SHELL_EMPTY,
	SHELL_STATUS,
	SHELL_FCINFO,
	SHELL_DF,
	SHELL_SHOW,
	REQ_STMFMGT,
	REQ_ZPOOLSTATUS_X,
	REQ_FMADMGENXML,
	REQ_GETMASTER,
	REQ_CHECK_SYNC_LOCATE,
	REQ_FULL_SCALE_SYNC_REQ,
	SYNC_REQ,
	SYNC_MSG	
} cmd_type_t;

typedef struct clu_fc_stat {
	char wwn[BUF_SHORT];
	char mode[BUF_SHORT];
	char driver[BUF_SHORT];
	char stat[BUF_SHORT];
	char speed[BUF_SHORT];
	char current[BUF_SHORT];
} clu_fc_stat_t;

typedef struct clu_fc_status {
	uint32_t fc_num;
	char name[BUF_MAX];
	char fc_stat[1];
}clu_fc_status_t;

typedef struct clu_status {
	char name[BUF_MAX];
	char ip[BUF_MAX];
	char version[BUF_MAX];
	char uptime[BUF_MAX];
	char stat[BUF_MAX];
	char hostid[BUF_MAX];
	char systime[BUF_MAX];
	char mem[BUF_MAX];
	char gui_ver[BUF_MAX];
} clu_status_t;

typedef struct clu_df_stat {
	char name[BUF_MAX];
	char avail[BUF_MAX];
	char capacity[BUF_MAX];
	char max[BUF_MAX];
} clu_df_stat_t;

typedef struct clu_df_status {
	uint32_t df_num;
	char name[BUF_MAX];
	char df_stat[1];
}clu_df_status_t;












#ifndef TRUE
#define	TRUE	1
#endif
#ifndef FALSE
#define	FALSE	0
#endif


#ifdef	__cplusplus
}
#endif

#endif /* _CLUMGT_IMPL_H */
