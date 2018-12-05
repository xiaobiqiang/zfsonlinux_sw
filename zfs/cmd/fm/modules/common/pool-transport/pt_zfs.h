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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	ST_ZFS_H
#define	ST_ZFS_H

#include <libzfs.h>
#include <libstmf.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef int (*st_zfs_iter_cb)(zfs_handle_t *, int, void *, stmfGuidList *);

typedef struct st_zfs_sort_column {
	struct st_zfs_sort_column	*sc_next;
	struct st_zfs_sort_column	*sc_last;
	zfs_prop_t		sc_prop;
	char			*sc_user_prop;
	boolean_t		sc_reverse;
} st_zfs_sort_column_t;

extern libzfs_handle_t *g_zfs;

//#define	offsetof(s, m)  (size_t)(&(((s *)0)->m))

#define	ST_ZFS_ITER_RECURSE	   (1 << 0)
#define	ST_ZFS_ITER_ARGS_CAN_BE_PATHS (1 << 1)
#define	ST_ZFS_ITER_PROP_LISTSNAPS    (1 << 2)
#define	ST_ZFS_ITER_DEPTH_LIMIT	   (1 << 3)
#define	ST_ZFS_ITER_RECVD_PROPS	   (1 << 4)

int pt_zfs_for_each(int options, zfs_type_t,st_zfs_sort_column_t *, 
	zprop_list_t **, int, st_zfs_iter_cb, void *, libzfs_handle_t *zhdl, stmfGuidList *lulist);

#ifdef	__cplusplus
}
#endif

#endif	/* ST_ZFS_H */

