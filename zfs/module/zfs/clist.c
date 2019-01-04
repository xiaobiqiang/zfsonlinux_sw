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

#include <sys/clist.h>
#include <sys/zfs_context.h>


void
clist_create(clist_t *clst)
{
	mutex_init(&clst->cl_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&clst->cl_list, sizeof (clist_entry_t),
	    offsetof(clist_entry_t, node));
}

void
clist_destroy(clist_t *clst)
{
	list_destroy(&clst->cl_list);
	mutex_destroy(&clst->cl_lock);
}

void
clist_append(clist_t *clst, void *data)
{
	clist_entry_t *entry = kmem_zalloc(sizeof (clist_entry_t), KM_SLEEP);

	mutex_enter(&clst->cl_lock);
	entry->data = data;
	list_insert_tail(&clst->cl_list, entry);
	mutex_exit(&clst->cl_lock);
}

void 
clist_iterate(clist_t *clst, clist_itor_t *func, void *arg, dmu_tx_t *tx)
{
	clist_entry_t *entry;

	mutex_enter(&clst->cl_lock);
	while (entry = list_head(&clst->cl_list)) {
		list_remove(&clst->cl_list, entry);
		mutex_exit(&clst->cl_lock);
		func(arg, entry->data, tx);
		kmem_free(entry, sizeof (*entry));
		mutex_enter(&clst->cl_lock);
	}
	mutex_exit(&clst->cl_lock);
}
