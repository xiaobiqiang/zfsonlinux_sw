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

#ifndef _LUN_MIGRATE_H
#define _LUN_MIGRATE_H

#include <sys/spa_impl.h>
#include <sys/stmf_defines.h>

#define LUN_COPY_ERR	(-1)
#define LUN_COPY_SUCCESS 0
#define LUN_COPY_READ_FAIL 1

#define LUN_COPY_TRY	5
#define LUN_COPY_NUM	6
#define LUN_COPY_SHIFT	15
#define LUN_DEV_LEN		128
#define LUN_COPY_SIZE	(1ULL << LUN_COPY_SHIFT)

typedef enum lun_migrate_cmd {
	LUN_MIGRATE_NONE,
	LUN_MIGRATE_START,
	LUN_MIGRATE_STOP,
	LUN_MIGRATE_RESTART,
	LUN_MIGRATE_CHECK,
	LUN_MIGRATE_RESUME
} lun_migrate_cmd_t;

typedef enum lun_migrate_state {
	LUN_MIGRATE_NOINIT,
	LUN_MIGRATE_INIT,
	LUN_MIGRATE_DEFAULT
} lun_migrate_state_t;

typedef enum lun_copy_state {
	LUN_COPY_NONE,
	LUN_COPY_ACTIVE,
	LUN_COPY_STOP,
	LUN_COPY_DEACTIVE,
	LUN_COPY_DONE,
	LUN_COPY_DEFAULT
} lun_copy_state_t;

typedef struct lun_copy {
	objset_t		*lun_os;
	kthread_t		*lun_copy_thread;
	struct file		*lun_read_fp;
	struct file		*lun_write_fp;
	lun_copy_state_t lun_copy_state;
	kmutex_t		lun_copy_lock;
	kmutex_t		lun_copy_out_lock;
	kcondvar_t		lun_copy_cv;
	kcondvar_t		lun_copy_out_cv;
	uint64_t 		lun_cursor_off;
	uint64_t		lun_total_size;
	char			lun_zfs[64];
	char			lun_guid[LUN_DEV_LEN];
	char			lun_remote_dev[LUN_DEV_LEN];
	char			lun_host_dev[LUN_DEV_LEN];
} lun_copy_t;

typedef struct lun_migrate {
	int					lum_members;
	kmutex_t			lum_lock;
	lun_migrate_state_t lum_state;
	lun_copy_t			lum_copy_array[LUN_COPY_NUM];
} lun_migrate_t;

extern void lun_migrate_init(void);
extern void	lun_migrate_fini(void);
extern void lun_migrate_recovery(const char *fsname);
extern void lun_migrate_start(lun_copy_t *lct, boolean_t b_new);
extern void lun_migrate_stop(lun_copy_t *lct);
extern void lun_migrate_restart(lun_copy_t *lct);
extern void lun_migrate_destroy(lun_copy_t *lct);
extern void lun_copy_clear(lun_copy_t *lct, char *buf);
extern int lun_migrate_is_work(objset_t *os);
extern lun_copy_t *lun_migrate_find_copy(void);
extern lun_copy_t *lun_migrate_find_by_name(char *name);
extern lun_copy_t *lun_migrate_find_by_fs(const char *fs);
extern int lun_migrate_zvol_write(char *name, uio_t *uio);
extern int lun_migrate_zvol_read(char *name, uio_t *uio);
extern int lun_migrate_zvol_sgl_write(char *name, uint64_t off, int size, void *data);
extern int lun_migrate_zvol_sgl_read(char *name, uint64_t off, int size, void *data);
extern uint64_t lun_migrate_get_offset(char *name);

#endif /* lun_migrate.h */
