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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 Actifio, Inc. All rights reserved.
 */

#ifndef	_SYS_ZVOL_H
#define	_SYS_ZVOL_H

#include <sys/zfs_context.h>
#include <sys/spa.h>

struct dbuf_segs_data;

#define	ZVOL_OBJ		1ULL
#define	ZVOL_ZAP_OBJ		2ULL

extern void zvol_create_minors(spa_t *spa, const char *name, boolean_t async);
extern void zvol_remove_minors(spa_t *spa, const char *name, boolean_t async);
extern void zvol_rename_minors(spa_t *spa, const char *oldname,
    const char *newname, boolean_t async);

#ifdef _KERNEL
extern int zvol_create_minor(const char *name);
extern int zvol_check_volsize(uint64_t volsize, uint64_t blocksize);
extern int zvol_check_volblocksize(const char *name, uint64_t volblocksize);
extern int zvol_get_stats(objset_t *os, nvlist_t *nv);
extern boolean_t zvol_is_zvol(const char *);
extern void zvol_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx);
extern int zvol_set_volsize(const char *, uint64_t);
extern int zvol_get_volsize(const char *name, uint64_t *volsize);
extern int zvol_set_volblocksize(const char *, uint64_t);
extern int zvol_get_volblocksize(const char *name, uint64_t *volblocksize);
extern int zvol_set_snapdev(const char *, zprop_source_t, uint64_t);

extern int zvol_get_volume_params(minor_t minor, uint64_t *blksize,
	uint64_t *max_xfer_len, void **minor_hdl, void **objset_hdl, void **zil_hdl,
    void **rl_hdl, void **bonus_hdl);
extern uint64_t zvol_get_volume_size(void *minor_hdl);
extern int zvol_get_volume_wce(void *minor_hdl);
extern void zvol_mirror_replay_wait(void *minor_hdl);

extern int zvol_get_disk_name(const char *name, char *disk_name, int len);
extern int zvol_flush_write_cache(const char *name, void *arg);
extern int zvol_get_wce(const char *name, int *wce);
extern int zvol_set_wce(const char *name, int wce);
extern int zvol_dkio_free(const char *name, void *arg);

extern int zvol_obj_rewrite(objset_t *os, uint64_t object, uint64_t offset,
    uint64_t len, struct dbuf_segs_data *seg_node);

extern int zvol_init(void);
extern void zvol_fini(void);
#endif /* _KERNEL */
#endif /* _SYS_ZVOL_H */
