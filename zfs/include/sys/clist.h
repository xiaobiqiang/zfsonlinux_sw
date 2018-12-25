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

#ifndef	_SYS_CLIST_H
#define	_SYS_CLIST_H

#include <sys/zfs_context.h>
#include <sys/spa.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct clist_entry {
	list_node_t node;
	void *data;
} clist_entry_t;

typedef struct c_list {
	kmutex_t	cl_lock;
	list_t		cl_list;
} clist_t;

typedef int clist_itor_t(void *arg, void *data, dmu_tx_t *tx);

void clist_create(clist_t *clst);
void clist_destroy(clist_t *clst);
void clist_append(clist_t *clst, void *data);
void clist_iterate(clist_t *clst, clist_itor_t *func, void *arg, dmu_tx_t *tx);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CLIST_H */
