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

#include <libintl.h>
#include <libuutil.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>

#include <sys/zio.h>
//#include <libzfs_zfs.h>
#include <libzfs.h>
#include <zfs_iter.h>
#include "pt_zfs.h"

/*
 * This is a private interface used to gather up all the datasets specified on
 * the command line so that we can iterate over them in order.
 *
 * First, we iterate over all filesystems, gathering them together into an
 * AVL tree.  We report errors for any explicitly specified datasets
 * that we couldn't open.
 *
 * When finished, we have an AVL tree of ZFS handles.  We go through and execute
 * the provided callback for each one, passing whatever data the user supplied.
 */


typedef struct st_zfs_node {
	zfs_handle_t	*zn_handle;
	uu_avl_node_t	zn_avlnode;
	/*
	 * Depth is zero for all specified (top level) datasets and N for
	 * descendant datasets (visited when the ZFS_ITER_RECURSE flag is set),
	 * where N is the number of parent datasets traversed to reach the top
	 * level dataset.
	 */
	int		zn_depth;
}st_zfs_node_t;

typedef struct callback_data {
	uu_avl_t		*cb_avl;
	int			cb_flags;
	zfs_type_t		cb_types;
	st_zfs_sort_column_t	*cb_sortcol;
	zprop_list_t		**cb_proplist;
	int			cb_depth_limit;
	int			cb_depth;
	uint8_t			cb_props_table[ZFS_NUM_PROPS];
} callback_data_t;

uu_avl_pool_t *avl_pool;


/*
 * Include snaps if they were requested or if this a zfs list where types
 * were not specified and the "listsnapshots" property is set on this pool.
 */
void
nomem(void)
{
	syslog(LOG_ERR, "internal error: out of memory");
	exit(1);
}

void *
safe_malloc(size_t size)
{
	void *data;

	if ((data = calloc(1, size)) == NULL)
		nomem();

	return (data);
}


static int
st_zfs_include_snapshots(zfs_handle_t *zhp, callback_data_t *cb)
{
	zpool_handle_t *zph;

	if ((cb->cb_flags & ST_ZFS_ITER_PROP_LISTSNAPS) == 0)
		return (cb->cb_types & ZFS_TYPE_SNAPSHOT);

	zph = zfs_get_pool_handle(zhp);
	return (zpool_get_prop_int(zph, ZPOOL_PROP_LISTSNAPS, NULL));
}

static int
st_zfs_compare(const void *larg, const void *rarg, void *unused)
{
	zfs_handle_t *l = ((st_zfs_node_t *)larg)->zn_handle;
	zfs_handle_t *r = ((st_zfs_node_t *)rarg)->zn_handle;
	const char *lname = zfs_get_name(l);
	const char *rname = zfs_get_name(r);
	char *lat, *rat;
	uint64_t lcreate, rcreate;
	int ret;

	lat = (char *)strchr(lname, '@');
	rat = (char *)strchr(rname, '@');

	if (lat != NULL)
		*lat = '\0';
	if (rat != NULL)
		*rat = '\0';

	ret = strcmp(lname, rname);
	if (ret == 0) {
		/*
		 * If we're comparing a dataset to one of its snapshots, we
		 * always make the full dataset first.
		 */
		if (lat == NULL) {
			ret = -1;
		} else if (rat == NULL) {
			ret = 1;
		} else {
			/*
			 * If we have two snapshots from the same dataset, then
			 * we want to sort them according to creation time.  We
			 * use the hidden CREATETXG property to get an absolute
			 * ordering of snapshots.
			 */
			lcreate = zfs_prop_get_int(l, ZFS_PROP_CREATETXG);
			rcreate = zfs_prop_get_int(r, ZFS_PROP_CREATETXG);

			if (lcreate < rcreate)
				ret = -1;
			else if (lcreate > rcreate)
				ret = 1;
		}
	}

	if (lat != NULL)
		*lat = '@';
	if (rat != NULL)
		*rat = '@';

	return (ret);
}

static int
st_zfs_sort(const void *larg, const void *rarg, void *data)
{
	zfs_handle_t *l = ((st_zfs_node_t *)larg)->zn_handle;
	zfs_handle_t *r = ((st_zfs_node_t *)rarg)->zn_handle;
	st_zfs_sort_column_t *sc = (st_zfs_sort_column_t *)data;
	st_zfs_sort_column_t *psc;

	for (psc = sc; psc != NULL; psc = psc->sc_next) {
		char lbuf[ZFS_MAXPROPLEN], rbuf[ZFS_MAXPROPLEN];
		char *lstr, *rstr;
		uint64_t lnum, rnum;
		boolean_t lvalid, rvalid;
		int ret = 0;

		/*
		 * We group the checks below the generic code.  If 'lstr' and
		 * 'rstr' are non-NULL, then we do a string based comparison.
		 * Otherwise, we compare 'lnum' and 'rnum'.
		 */
		lstr = rstr = NULL;
		if (psc->sc_prop == ZPROP_INVAL) {
			nvlist_t *luser, *ruser;
			nvlist_t *lval, *rval;

			luser = zfs_get_user_props(l);
			ruser = zfs_get_user_props(r);

			lvalid = (nvlist_lookup_nvlist(luser,
			    psc->sc_user_prop, &lval) == 0);
			rvalid = (nvlist_lookup_nvlist(ruser,
			    psc->sc_user_prop, &rval) == 0);

			if (lvalid)
				verify(nvlist_lookup_string(lval,
				    ZPROP_VALUE, &lstr) == 0);
			if (rvalid)
				verify(nvlist_lookup_string(rval,
				    ZPROP_VALUE, &rstr) == 0);

		} else if (zfs_prop_is_string(psc->sc_prop)) {
			lvalid = (zfs_prop_get(l, psc->sc_prop, lbuf,
			    sizeof (lbuf), NULL, NULL, 0, B_TRUE) == 0);
			rvalid = (zfs_prop_get(r, psc->sc_prop, rbuf,
			    sizeof (rbuf), NULL, NULL, 0, B_TRUE) == 0);

			lstr = lbuf;
			rstr = rbuf;
		} else {
			lvalid = zfs_prop_valid_for_type(psc->sc_prop,
			    zfs_get_type(l), B_FALSE);
			rvalid = zfs_prop_valid_for_type(psc->sc_prop,
			    zfs_get_type(r), B_FALSE);

			if (lvalid)
				(void) zfs_prop_get_numeric(l, psc->sc_prop,
				    &lnum, NULL, NULL, 0);
			if (rvalid)
				(void) zfs_prop_get_numeric(r, psc->sc_prop,
				    &rnum, NULL, NULL, 0);
		}

		if (!lvalid && !rvalid)
			continue;
		else if (!lvalid)
			return (1);
		else if (!rvalid)
			return (-1);

		if (lstr)
			ret = strcmp(lstr, rstr);
		else if (lnum < rnum)
			ret = -1;
		else if (lnum > rnum)
			ret = 1;

		if (ret != 0) {
			if (psc->sc_reverse == B_TRUE)
				ret = (ret < 0) ? 1 : -1;
			return (ret);
		}
	}

	return (st_zfs_compare(larg, rarg, NULL));
}

static int
st_zfs_callback(zfs_handle_t *zhp, void *data)
{
	callback_data_t *cb = data;
	int dontclose = 0;
	int include_snaps = st_zfs_include_snapshots(zhp, cb);

	if ((zfs_get_type(zhp) & cb->cb_types) ||
	    ((zfs_get_type(zhp) == ZFS_TYPE_SNAPSHOT) && include_snaps)) {
		uu_avl_index_t idx;
		st_zfs_node_t *node = safe_malloc(sizeof (st_zfs_node_t));
		st_zfs_node_t *found;

		node->zn_handle = zhp;
		uu_avl_node_init(node, &node->zn_avlnode, avl_pool);
		if ((found = uu_avl_find(cb->cb_avl, node, cb->cb_sortcol,
		    &idx)) == NULL) {
			if (cb->cb_proplist) {
				if ((*cb->cb_proplist) &&
				    !(*cb->cb_proplist)->pl_all)
					zfs_prune_proplist(zhp,
					    cb->cb_props_table);

				if (zfs_expand_proplist(zhp, cb->cb_proplist,
				    (cb->cb_flags & ST_ZFS_ITER_RECVD_PROPS), 
                                    (cb->cb_flags & ZFS_ITER_LITERAL_PROPS))
				    != 0) {
					free(node);
					return (-1);
				}
			}
			node->zn_depth = cb->cb_depth;
			uu_avl_insert(cb->cb_avl, node, idx);
			dontclose = 1;
		} else {
			free(node);

			if (cb->cb_depth < found->zn_depth)
				found->zn_depth = cb->cb_depth;
		}
	}

	/*
	 * Recurse if necessary.
	 */
	if (cb->cb_flags & ST_ZFS_ITER_RECURSE &&
	    ((cb->cb_flags & ST_ZFS_ITER_DEPTH_LIMIT) == 0 ||
	    cb->cb_depth < cb->cb_depth_limit)) {
		cb->cb_depth++;
		if (zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM)
			(void) zfs_iter_filesystems(zhp, st_zfs_callback, data);
		if ((zfs_get_type(zhp) != ZFS_TYPE_SNAPSHOT) && include_snaps)
			(void) zfs_iter_snapshots(zhp, 
                               (cb->cb_flags & ZFS_ITER_SIMPLE) != 0, 
                               st_zfs_callback, data);
		cb->cb_depth--;
	}

	if (!dontclose)
		zfs_close(zhp);

	return (0);
}
int
pt_zfs_for_each(int flags, zfs_type_t types,
    st_zfs_sort_column_t *sortcol, zprop_list_t **proplist, int limit,
    st_zfs_iter_cb callback,void *data, libzfs_handle_t *zhdl, stmfGuidList *luList)
{
	callback_data_t cbp = {0};
	int ret = 0;
	st_zfs_node_t *node;
	uu_avl_walk_t *walk;

	avl_pool = uu_avl_pool_create("fm_zfs_pool", sizeof (st_zfs_node_t),
	    offsetof(st_zfs_node_t, zn_avlnode), st_zfs_sort, UU_DEFAULT);

	if (avl_pool == NULL)
		nomem();

	cbp.cb_sortcol = sortcol;
	cbp.cb_flags = flags;
	cbp.cb_proplist = proplist;
	cbp.cb_types = types;
	cbp.cb_depth_limit = limit;
	/*
	 * If cb_proplist is provided then in the zfs_handles created we
	 * retain only those properties listed in cb_proplist and sortcol.
	 * The rest are pruned. So, the caller should make sure that no other
	 * properties other than those listed in cb_proplist/sortcol are
	 * accessed.
	 *
	 * If cb_proplist is NULL then we retain all the properties.  We
	 * always retain the zoned property, which some other properties
	 * need (userquota & friends), and the createtxg property, which
	 * we need to sort snapshots.
	 */
	if (cbp.cb_proplist && *cbp.cb_proplist) {
		zprop_list_t *p = *cbp.cb_proplist;
		
		while (p) {
			if (p->pl_prop >= ZFS_PROP_TYPE &&
			    p->pl_prop < ZFS_NUM_PROPS) {
				cbp.cb_props_table[p->pl_prop] = B_TRUE;
			}
			p = p->pl_next;
		}

		while (sortcol) {
			if (sortcol->sc_prop >= ZFS_PROP_TYPE &&
			    sortcol->sc_prop < ZFS_NUM_PROPS) {
				cbp.cb_props_table[sortcol->sc_prop] = B_TRUE;
			}
			sortcol = sortcol->sc_next;
		}

		cbp.cb_props_table[ZFS_PROP_ZONED] = B_TRUE;
		cbp.cb_props_table[ZFS_PROP_CREATETXG] = B_TRUE;
	} else {
		(void) memset(cbp.cb_props_table, B_TRUE,
		    sizeof (cbp.cb_props_table));
	}

	if ((cbp.cb_avl = uu_avl_create(avl_pool, NULL, UU_DEFAULT)) == NULL)
		nomem();

	cbp.cb_flags |= ST_ZFS_ITER_RECURSE;
	ret = zfs_iter_root(zhdl, st_zfs_callback, &cbp);

	/*
	 * At this point we've got our AVL tree full of zfs handles, so iterate
	 * over each one and execute the real user callback.
	 */
	for (node = uu_avl_first(cbp.cb_avl); node != NULL;
	    node = uu_avl_next(cbp.cb_avl, node))
		ret |= callback(node->zn_handle, node->zn_depth, data, luList);
	    	

	/*
	 * Finally, clean up the AVL tree.
	 */
	if ((walk = uu_avl_walk_start(cbp.cb_avl, UU_WALK_ROBUST)) == NULL)
		nomem();

	while ((node = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_remove(cbp.cb_avl, node);
		zfs_close(node->zn_handle);
		free(node);
	}
	
	uu_avl_walk_end(walk);
	uu_avl_destroy(cbp.cb_avl);
	uu_avl_pool_destroy(avl_pool);

	return (ret);
}
