#include <libgen.h>
#include <libintl.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h> 
#include <libuutil.h> 
#include <sys/fs/zfs.h>
#include <sys/stat.h>
#include <syslog.h>
#include <sys/zfs_ioctl.h>
#include <pthread.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include "libzfs_impl.h"
#include "libzfs_zfs.h"
#include "libzfs_rpc.h"
#include "libzfs.h"


uu_avl_pool_t *avl_pool;
libzfs_handle_t *g_zfs;

/*
 * Functions for printing zfs or zpool properties
 */
typedef struct zfs_get_cbdata {
	boolean_t cb_literal;
	boolean_t cb_first;
	zprop_list_t *cb_proplist;
	char cb_prop_value[256][ZFS_MAXPROPLEN];
} zfs_get_cbdata_t;



void
nomem(void)
{
	(void) fprintf(stderr, gettext("internal error: out of memory\n"));
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

/* ARGSUSED */
static int
zfs_compare(const void *larg, const void *rarg, void *unused)
{
	zfs_handle_t *l = ((zfs_node_t *)larg)->zn_handle;
	zfs_handle_t *r = ((zfs_node_t *)rarg)->zn_handle;
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
zfs_sort(const void *larg, const void *rarg, void *data)
{
	zfs_handle_t *l = ((zfs_node_t *)larg)->zn_handle;
	zfs_handle_t *r = ((zfs_node_t *)rarg)->zn_handle;
	zfs_sort_column_t *sc = (zfs_sort_column_t *)data;
	zfs_sort_column_t *psc;

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

	return (zfs_compare(larg, rarg, NULL));
}

static int
zfs_include_snapshots(zfs_handle_t *zhp, callback_data_t *cb)
{
	zpool_handle_t *zph;

	if ((cb->cb_flags & ZFS_RPC_PROP_LISTSNAPS) == 0)
		return (cb->cb_types & ZFS_TYPE_SNAPSHOT);

	zph = zfs_get_pool_handle(zhp);
	return (zpool_get_prop_int(zph, ZPOOL_PROP_LISTSNAPS, NULL));
}

static int
zfs_callback(zfs_handle_t *zhp, void *data)
{
	callback_data_t *cb = data;
	int dontclose = 0;
	int include_snaps = zfs_include_snapshots(zhp, cb);

	if ((zfs_get_type(zhp) & cb->cb_types) ||
	    ((zfs_get_type(zhp) == ZFS_TYPE_SNAPSHOT) && include_snaps)) {
		uu_avl_index_t idx;
		zfs_node_t *node = safe_malloc(sizeof (zfs_node_t));
		zfs_node_t *found;

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
				    (cb->cb_flags & ZFS_RPC_RECVD_PROPS),
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
	if (cb->cb_flags & ZFS_RPC_RECURSE &&
	    ((cb->cb_flags & ZFS_RPC_DEPTH_LIMIT) == 0 ||
	    cb->cb_depth < cb->cb_depth_limit)) {
		cb->cb_depth++;
		if (zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM)
			(void) zfs_iter_filesystems(zhp, zfs_callback, data);
		if ((zfs_get_type(zhp) != ZFS_TYPE_SNAPSHOT) && include_snaps)
			(void) zfs_iter_snapshots(zhp, B_FALSE, zfs_callback, data);
		cb->cb_depth--;
	}

	if (!dontclose)
		zfs_close(zhp);

	return (0);
}

static int
zfs_for_each(int argc, char **argv, int flags, zfs_type_t types,
    zfs_sort_column_t *sortcol, zprop_list_t **proplist, int limit,
    zfs_iter_cb callback, void *data)
{
	callback_data_t cb = {0};
	int ret = 0;
	zfs_node_t *node;
	uu_avl_walk_t *walk;

	avl_pool = uu_avl_pool_create("zfs_pool", sizeof (zfs_node_t),
	    offsetof(zfs_node_t, zn_avlnode), zfs_sort, UU_DEFAULT);

	if (avl_pool == NULL)
		nomem();

	cb.cb_sortcol = sortcol;
	cb.cb_flags = flags;
	cb.cb_proplist = proplist;
	cb.cb_types = types;
	cb.cb_depth_limit = limit;
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
	if (cb.cb_proplist && *cb.cb_proplist) {
		zprop_list_t *p = *cb.cb_proplist;

		while (p) {
			if (p->pl_prop >= ZFS_PROP_TYPE &&
			    p->pl_prop < ZFS_NUM_PROPS) {
				cb.cb_props_table[p->pl_prop] = B_TRUE;
			}
			p = p->pl_next;
		}

		while (sortcol) {
			if (sortcol->sc_prop >= ZFS_PROP_TYPE &&
			    sortcol->sc_prop < ZFS_NUM_PROPS) {
				cb.cb_props_table[sortcol->sc_prop] = B_TRUE;
			}
			sortcol = sortcol->sc_next;
		}

		cb.cb_props_table[ZFS_PROP_ZONED] = B_TRUE;
		cb.cb_props_table[ZFS_PROP_CREATETXG] = B_TRUE;
	} else {
		(void) memset(cb.cb_props_table, B_TRUE,
		    sizeof (cb.cb_props_table));
	}

	if ((cb.cb_avl = uu_avl_create(avl_pool, NULL, UU_DEFAULT)) == NULL)
		nomem();

	if (argc == 0) {
		/*
		 * If given no arguments, iterate over all datasets.
		 */
		cb.cb_flags |= ZFS_RPC_RECURSE;
		ret = zfs_iter_root(g_zfs, zfs_callback, &cb);
	} else {
		int i;
		zfs_handle_t *zhp;
		zfs_type_t argtype;

		/*
		 * If we're recursive, then we always allow filesystems as
		 * arguments.  If we also are interested in snapshots, then we
		 * can take volumes as well.
		 */
		argtype = types;
		if (flags & ZFS_RPC_RECURSE) {
			argtype |= ZFS_TYPE_FILESYSTEM;
			if (types & ZFS_TYPE_SNAPSHOT)
				argtype |= ZFS_TYPE_VOLUME;
		}

		for (i = 0; i < argc; i++) {
			if (flags & ZFS_RPC_ARGS_CAN_BE_PATHS) {
				zhp = zfs_path_to_zhandle(g_zfs, argv[i],
				    argtype);
			} else {
				zhp = zfs_open(g_zfs, argv[i], argtype);
			}
			if (zhp != NULL)
				ret |= zfs_callback(zhp, &cb);
			else
				ret = 1;
		}
	}

	/*
	 * At this point we've got our AVL tree full of zfs handles, so iterate
	 * over each one and execute the real user callback.
	 */
	for (node = uu_avl_first(cb.cb_avl); node != NULL;
	    node = uu_avl_next(cb.cb_avl, node))
		ret |= callback(node->zn_handle, node->zn_depth, data);

	/*
	 * Finally, clean up the AVL tree.
	 */
	if ((walk = uu_avl_walk_start(cb.cb_avl, UU_WALK_ROBUST)) == NULL)
		nomem();

	while ((node = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_remove(cb.cb_avl, node);
		zfs_close(node->zn_handle);
		free(node);
	}

	uu_avl_walk_end(walk);
	uu_avl_destroy(cb.cb_avl);
	uu_avl_pool_destroy(avl_pool);

	return (ret);
}

static int
set_cb(zfs_handle_t *zhp, int depth, void *data)
{
	set_cbdata_t *cbp = data;
	zprop_setflags_t flags;

	flags = (depth > 0 ? ZPROP_SET_DESCENDANT : 0);

	if (zfs_prop_set_extended(zhp, cbp->cb_propname, cbp->cb_value,
	    flags) != 0) {
		switch (libzfs_errno(g_zfs)) {
		case EZFS_MOUNTFAILED:
			syslog(LOG_ERR, "Fail to mount filesystem ");
			break;
		case EZFS_SHARENFSFAILED:
			syslog(LOG_ERR, "Fail to share filesystem ");
			break;
		}
		return (1);
	}
	return (0);
}

static int
set_recurse_cb(zfs_handle_t *zhp, int depth, void *data)
{
	set_cbdata_t *cbp = data;
	zfs_prop_t prop = zfs_name_to_prop(cbp->cb_propname);

	/*
	 * If we're doing it recursively, then ignore properties that
	 * are not valid for this type of dataset.
	 */
	if (prop != ZPROP_INVAL &&
	    !zfs_prop_valid_for_type(prop, zfs_get_type(zhp), B_FALSE))
		return (0);

	return (set_cb(zhp, depth, data));
}


/*
 * zfs set [-r] userquota@username=value { fs | snap | vol } ...
 *
 * Sets the given property for all datasets specified on the command line.
 * For rpc remote call
 */
int
zfs_remote_set(zfs_rpc_arg_t *arg)
{
	zfs_iter_cb iter_cb;
	set_cbdata_t cb;
	int ret = 0;

	if ((g_zfs = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "Fail to libzfs_init ");
		return (1);
	}
	#if 0
	syslog(LOG_ERR, "propname:<%s> ", arg->propname);
	syslog(LOG_ERR, "value:<%s> ", arg->value);
	syslog(LOG_ERR, "fsname[0]:<%s> ", arg->buf[0]);
	syslog(LOG_ERR, "flag:<%d> ", arg->flag);
	syslog(LOG_ERR, "bufcnt:<%d> ", arg->bufcnt);
	#endif
	cb.cb_propname = arg->propname;
	cb.cb_value = arg->value;
	iter_cb = ((arg->flag & ZFS_RPC_RECURSE) ? set_recurse_cb : set_cb);
	ret = zfs_for_each(arg->bufcnt, arg->buf, arg->flag, ZFS_TYPE_DATASET, NULL, NULL, 0,
	    iter_cb, &cb);
	
	libzfs_fini(g_zfs);

	return (ret);
}

/*
 * Invoked to display the properties for a single dataset.
 */
/* ARGSUSED */
static int
get_callback(zfs_handle_t *zhp, int depth, void *data)
{
	char buf[ZFS_MAXPROPLEN];
	zprop_source_t sourcetype;
	zfs_get_cbdata_t *cbp = data;
	zprop_list_t *pl = cbp->cb_proplist;
	int ii = 0;
	
	for (; pl != NULL; pl = pl->pl_next) {
		/*
		 * Skip the special fake placeholder.  This will also skip over
		 * the name property when 'all' is specified.
		 */
		if (pl->pl_prop == ZFS_PROP_NAME &&
		    pl == cbp->cb_proplist)
			continue;

		if (zfs_prop_userquota(pl->pl_user_prop)) {
			sourcetype = ZPROP_SRC_LOCAL;
			if (zfs_prop_get_userquota(zhp, pl->pl_user_prop,
			    buf, sizeof (buf), cbp->cb_literal) != 0) {
				sourcetype = ZPROP_SRC_NONE;
				(void) strlcpy(buf, "-", sizeof (buf));
			}
			strcpy(cbp->cb_prop_value[ii], buf);
			ii++;
		} else {
		}
	}

	return (0);
}


/*
 * zfs get [-r] userquota@username { fs | snap | vol } ...
 *
 * Get the given property for all datasets specified on the command line.
 * For rpc remote call
 */
int
zfs_remote_get(zfs_rpc_arg_t *arg, char **backbuf)
{
	zfs_get_cbdata_t cb;
	int ret = 0;
	int ii = 0;
	int limit = 0;
	zprop_list_t fake_name = { 0 };
	char *bufptr=NULL;

	if ((g_zfs = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "Fail to libzfs_init ");
		return (1);
	}
	#if 0
	syslog(LOG_ERR, "propname:<%s> ", arg->cb_first);
	syslog(LOG_ERR, "value:<%s> ", arg->value);
	syslog(LOG_ERR, "fsname[0]:<%s> ", arg->buf[0]);
	syslog(LOG_ERR, "flag:<%d> ", arg->flag);
	syslog(LOG_ERR, "bufcnt:<%d> ", arg->bufcnt);
	#endif
	if (zprop_get_list(g_zfs, arg->propname, &cb.cb_proplist, ZFS_TYPE_DATASET)
	    != 0){
		libzfs_fini(g_zfs);
		return (1);
	}
	if (cb.cb_proplist != NULL) {
		fake_name.pl_prop = ZFS_PROP_NAME;
		fake_name.pl_width = strlen(gettext("NAME"));
		fake_name.pl_next = cb.cb_proplist;
		cb.cb_proplist = &fake_name;
	}

	cb.cb_first = B_TRUE;
	ret = zfs_for_each(arg->bufcnt, arg->buf, arg->flag, ZFS_TYPE_DATASET, 
		NULL, &cb.cb_proplist, limit, get_callback, &cb);

	*backbuf = (char*)malloc(arg->bufcnt*ZFS_MAXPROPLEN);
	bufptr = *backbuf;
	for(ii=0; ii<arg->bufcnt; ii++)
	{
		strcpy(bufptr, cb.cb_prop_value[ii]);
		bufptr += ZFS_MAXPROPLEN;
	}
	
	if (cb.cb_proplist == &fake_name)
		zprop_free_list(fake_name.pl_next);
	else
		zprop_free_list(cb.cb_proplist);
	
	libzfs_fini(g_zfs); 

	return (ret);
}


static int
remote_userspace_cb(void *arg, const char *domain, uid_t rid, uint64_t space, char 
	**back)
{
	zfs_userquota_prop_t *typep = arg;
	zfs_userquota_prop_t p = *typep;
	char *name = NULL;
	char *ug, *propname;
	char namebuf[32];
	char sizebuf[32];

	if (domain == NULL || domain[0] == '\0') {
		if (p == ZFS_PROP_GROUPUSED || p == ZFS_PROP_GROUPQUOTA) {
			struct group *g = getgrgid(rid);
			if (g)
				name = g->gr_name;
		} else {
			struct passwd *p = getpwuid(rid);
			if (p)
				name = p->pw_name;
		}
	}

	if (p == ZFS_PROP_GROUPUSED || p == ZFS_PROP_GROUPQUOTA)
		ug = "group";
	else
		ug = "user";

	if (p == ZFS_PROP_USERUSED || p == ZFS_PROP_GROUPUSED)
		propname = "used";
	else
		propname = "quota";

	if (name == NULL) {
		(void) snprintf(namebuf, sizeof (namebuf),
		    "%llu", (longlong_t)rid);
		name = namebuf;
	}
	zfs_nicenum(space, sizebuf, sizeof (sizebuf));

  /*	(void) printf("%s %s %s%c%s %s\n", propname, ug, domain,
	    domain[0] ? '-' : ' ', name, sizebuf);*/

	sprintf(*back,"%-6s %-6s %s%c%-8s %-6s", propname, ug, domain,
	    domain[0] ? '-' : ' ', name, sizebuf);

	*back += ENTRY_USERSAPCE-1;
	*(*back) = '\0';
	(*back)++;
	
	return (0);
}

int 
get_userspace(zfs_handle_t *zhp, zfs_userquota_prop_t type,
	zfs_remote_userspace_cb_t func, void *arg, char **back)
{
	zfs_cmd_t zc;
	int error;
	zfs_useracct_t buf[100];
	
	memset(&zc, '\0', sizeof(zfs_cmd_t));
	(void) strncpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));

	zc.zc_objset_type = type;
	zc.zc_nvlist_dst = (uintptr_t)buf;

	/* CONSTCOND */
	while (1) {
		zfs_useracct_t *zua = buf;

		zc.zc_nvlist_dst_size = sizeof (buf);
		error = ioctl(zhp->zfs_hdl->libzfs_fd,
		    ZFS_IOC_USERSPACE_MANY, &zc);
		if (error || zc.zc_nvlist_dst_size == 0)
			break;

		while (zc.zc_nvlist_dst_size > 0) {
			error = func(arg, zua->zu_domain, zua->zu_rid,
			    zua->zu_space, back);
			
			if (error != 0)
				return (error);
			zua++;
			zc.zc_nvlist_dst_size -= sizeof (zfs_useracct_t);
		}
	}

	return (error);
}


uint_t
zfs_remote_userspace(zfs_rpc_arg_t * arg, char **backbuf)
{
	zfs_handle_t *zhp;
	zfs_userquota_prop_t p;
	int error;
	char *backbuf_index = NULL;

	*backbuf = (char*)malloc(RPC_SEND_RECV_SIZE);
	backbuf_index = *backbuf;
	
	if ((g_zfs = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "%s:Fail to libzfs_init ",__func__);
		return (1);
	}
	

	syslog(LOG_ERR, "%s:remote userspace start",arg->buf[0]);
	if ((zhp = zfs_open(g_zfs, arg->buf[0], ZFS_TYPE_DATASET)) == NULL) {
		syslog(LOG_ERR,"%s:open fail",__func__);
		libzfs_fini(g_zfs); 
		return (1);
	}

	for (p = 0; p < ZFS_NUM_USERQUOTA_PROPS; p++) {
		error = get_userspace(zhp, p, remote_userspace_cb,
			&p, &backbuf_index);
		if (error){
			syslog(LOG_ERR, "get_userspace return fail !!!");
			break;
		}
			
		if(backbuf_index - *backbuf >= RPC_USERSPACE_SIZE){
			syslog(LOG_ERR, "too many entries"
				"(> RPC_USERSPACE_SIZE/ENTRY_USERSAPCE) "
				"in remote userspace  !!!");
			break;
		}
	}
	syslog(LOG_ERR, "%s:remote userspace end",arg->buf[0]);
	
	libzfs_fini(g_zfs);
	return (backbuf_index-*backbuf);

}

/*
 * Basic routines to read and write from a vdev label.
 * Used throughout the rest of this file.
 */
uint64_t
vdev_label_offset(uint64_t psize, int l, uint64_t offset)
{
	ASSERT(offset < sizeof (vdev_label_t));
	ASSERT(P2PHASE_TYPED(psize, sizeof (vdev_label_t), uint64_t) == 0);

	return (offset + l * sizeof (vdev_label_t) + (l < VDEV_LABELS / 2 ?
	    0 : psize - VDEV_LABELS * sizeof (vdev_label_t)));
}

/*
 * Function	: use the function get the disk nvlist infor and label ,state.
 * Parameters:
 * 	config	: get the nvlist infor
 * 	vs_aux	: get enum vdev_aux number
 *	state		: get the state
 * Return	: return the state
 */
 
static char *
get_disk_state(nvlist_t *nv, nvlist_t **config, uint64_t *vs_aux, char **state)
{

	uint64_t psize = 0;
	int fd;
	int len;
	int loop;
	vdev_label_t label;
	uint64_t tmp_pool_state = 0;
	struct stat64 statbuf;
	char *label_buf = label.vl_vdev_phys.vp_nvlist;
	size_t label_buflen = sizeof (label.vl_vdev_phys.vp_nvlist);
	char spare_path[MAXPATHLEN];
	char *spare_name;
	int spare_name_len;

	/* when other control use the disk */
	nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &spare_name);
	len = strlen(spare_name) + 1;

	if (strncmp(spare_name, "/dev/dsk/", 9) == 0) {
		(void) snprintf(spare_path, len+1, "%s%s", "/dev/rdsk/", spare_name + 9);
	} else {
		printf("%s error\n", spare_name);
	}

	spare_name_len = strlen(spare_name);
	if (*(spare_name + spare_name_len -2) != 's')
		(void) snprintf(spare_path, MAXPATHLEN, "%ss0", spare_path);
	else
		(void) snprintf(spare_path, MAXPATHLEN, "%s", spare_path);

	/* read disk label & state */
	if ((fd = open64(spare_path, O_RDONLY)) >= 0) {
			if (fstat64(fd, &statbuf) != 0) {
				syslog(LOG_ERR, "failed to fstate %s", spare_path);
				goto FAIL;
			}

			if (S_ISBLK(statbuf.st_mode)) {
				syslog(LOG_ERR, "failed to S_ISBLK %s", spare_path);
				goto FAIL;
			}

		for (loop = 0; loop < VDEV_LABELS; loop++) {
			if (pread64(fd, &label, sizeof (label),
				vdev_label_offset(psize, loop, 0)) != sizeof (label)) {
				syslog(LOG_ERR, "read fail %s", spare_path);
				if (VDEV_LABELS - 1 <= loop)
					continue;
				else
					goto FAIL;
			}

			if (nvlist_unpack(label_buf, label_buflen, config, 0) != 0) {
				syslog(LOG_ERR, "failed to unpack label");
				if (VDEV_LABELS -1 <= loop)
					continue;
				else
					goto FAIL;
			} else {
				if (nvlist_lookup_uint64(*config,
					ZPOOL_CONFIG_POOL_STATE, &tmp_pool_state) != 0)
					nvlist_free(*config);
			}

			if (POOL_STATE_ACTIVE == tmp_pool_state || POOL_STATE_EXPORTED 
				== tmp_pool_state) {
				*state = "INUSE";
				*vs_aux = VDEV_AUX_SPARED;
				break;
			} else {
				*state = "AVAIL";
				break;
			}
		}
		(void) close(fd);
	} else {
		/* fail to get disk infor */
		FAIL:
			*vs_aux = VDEV_AUX_OPEN_FAILED;
			*state = "UNAVAIL";
	}
	return (gettext(*state));
}

static boolean_t
find_vdev(nvlist_t *nv, uint64_t search)
{
	uint64_t guid;
	nvlist_t **child;
	uint_t c, children;

	if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid) == 0 &&
	    search == guid)
		return (B_TRUE);

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++)
			if (find_vdev(child[c], search))
				return (B_TRUE);
	}

	return (B_FALSE);
}

static int
find_spare(zpool_handle_t *zhp, void *data)
{
	spare_cbdata_t *cbp = data;
	nvlist_t *config, *nvroot;

	config = zpool_get_config(zhp, NULL);
	verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) == 0);

	if (find_vdev(nvroot, cbp->cb_guid)) {
		cbp->cb_zhp = zhp;
		return (1);
	}

	zpool_close(zhp);
	return (0);
}

/*
 * Print out configuration state as requested by status_callback.
 */
void
get_status_config(zpool_handle_t *zhp, nvlist_t **nv)
{
	nvlist_t **child;
	uint_t c, children;
	pool_scan_stat_t *ps = NULL;
	vdev_stat_t *vs;
	char *vname;
	uint64_t notpresent;
	spare_cbdata_t cb;
	char *state;
	nvlist_t  *config;
	char *pool_name;
	char statusinfo[256] = {0};

	/* syslog(LOG_ERR, "get_status_config-------start"); */
	if (nvlist_lookup_nvlist_array(*nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0)
		children = 0;

	/* nvlist_print(stdout, nv); */
	verify(nvlist_lookup_uint64_array(*nv, ZPOOL_CONFIG_VDEV_STATS,
	    (uint64_t **)&vs, &c) == 0);

	state = zpool_state_to_name(vs->vs_state, vs->vs_aux);

	/* syslog(LOG_ERR, "get_status_config-------1"); */
	/*
	 * For hot spares, we use the terms 'INUSE' and 'AVAILABLE' for
	 * online drives.
	 */
	if (vs->vs_aux == VDEV_AUX_SPARED)
		state = "INUSE";
	else if (vs->vs_state == VDEV_STATE_HEALTHY) {
		/* get the disk state 'INUSE' 'AVAILABLE' or 'UNAVAIL' */
		state = get_disk_state(*nv, &config, &vs->vs_aux, &state);
	}


	/* syslog(LOG_ERR, "get_status_config-------2"); */
	if (nvlist_lookup_uint64(*nv, ZPOOL_CONFIG_NOT_PRESENT,
	    &notpresent) == 0) {
		char *path;
		verify(nvlist_lookup_string(*nv, ZPOOL_CONFIG_PATH, &path) == 0);
		/* (void) printf("  was %s", path); */
		sprintf(statusinfo, "  was %s", path);
	} else if (vs->vs_aux != 0) {

		switch (vs->vs_aux) {
		case VDEV_AUX_OPEN_FAILED:
			/* (void) printf(gettext("cannot open")); */
			strcpy(statusinfo, "cannot open");
			break;

		case VDEV_AUX_BAD_GUID_SUM:
			/* (void) printf(gettext("missing device")); */
			strcpy(statusinfo, "missing device");
			break;

		case VDEV_AUX_NO_REPLICAS:
			/* (void) printf(gettext("insufficient replicas")); */
			strcpy(statusinfo, "insufficient replicas");
			break;

		case VDEV_AUX_VERSION_NEWER:
			/* (void) printf(gettext("newer version")); */
			strcpy(statusinfo, "newer version");
			break;

		case VDEV_AUX_SPARED:
			verify(nvlist_lookup_uint64(*nv, ZPOOL_CONFIG_GUID,
			    &cb.cb_guid) == 0);
			if (zpool_iter(g_zfs, find_spare, &cb) == 1) {
				if (strcmp(zpool_get_name(cb.cb_zhp),
				    zpool_get_name(zhp)) == 0){
					/* (void) printf(gettext("currently in use")); */
					strcpy(statusinfo, "currently in use");
				}
				else{
					/* (void) printf(gettext("in use by pool '%s'"),
					    zpool_get_name(cb.cb_zhp)); */
					sprintf(statusinfo, "in use by pool '%s'", 
						zpool_get_name(cb.cb_zhp));
				}
				zpool_close(cb.cb_zhp);
			} else {
					if (nvlist_lookup_string(config,
					ZPOOL_CONFIG_POOL_NAME, &pool_name) == 0) {
						if (strcmp(zpool_get_name(zhp), pool_name) == 0) {
							/* (void) printf(gettext("currently in use")); */
							strcpy(statusinfo, "currently in use");
						} else {
							/* (void) printf(gettext("in use by "
								"pool '%s'"), pool_name); */
							sprintf(statusinfo, "in use by pool '%s'", 
								pool_name);
						}
					}
					nvlist_free(config);
			}
			break;

		case VDEV_AUX_ERR_EXCEEDED:
			/* (void) printf(gettext("too many errors")); */
			strcpy(statusinfo, "too many errors");
			break;

		case VDEV_AUX_IO_FAILURE:
			/* (void) printf(gettext("experienced I/O failures")); */
			strcpy(statusinfo, "experienced I/O failures");
			break;

		case VDEV_AUX_BAD_LOG:
			/* (void) printf(gettext("bad intent log")); */
			strcpy(statusinfo, "bad intent log");
			break;

		case VDEV_AUX_EXTERNAL:
			/* (void) printf(gettext("external device fault")); */
			strcpy(statusinfo, "external device fault");
			break;

		case VDEV_AUX_SPLIT_POOL:
			/* (void) printf(gettext("split into new pool")); */
			strcpy(statusinfo, "split into new pool");
			break;

		default:
			/* (void) printf(gettext("corrupted data")); */
			strcpy(statusinfo, "corrupted data");
			break;
		}
	}

	/* syslog(LOG_ERR, "get_status_config-------3"); */
	(void) nvlist_lookup_uint64_array(*nv, ZPOOL_CONFIG_SCAN_STATS,
	    (uint64_t **)&ps, &c);

	if (ps && ps->pss_state == DSS_SCANNING &&
	    vs->vs_scan_processed != 0 && children == 0) {
		/* (void) printf(gettext("  (%s)"),
		    (ps->pss_func == POOL_SCAN_RESILVER) ?
		    "resilvering" : ((ps->pss_func == POOL_SCAN_SCRUB) ?
		    "repairing" : "migrating low data"));*/
		sprintf(statusinfo, "  (%s)", (ps->pss_func == POOL_SCAN_RESILVER) ?
		    "resilvering" : ((ps->pss_func == POOL_SCAN_SCRUB) ?
		    "repairing" : "migrating low data"));
	}

	/* syslog(LOG_ERR, "get_status_config-------4"); */
	for (c = 0; c < children; c++) {
		uint64_t islog = B_FALSE, ishole = B_FALSE,  is_meta=B_FALSE, is_low=B_FALSE;

		/* Don't print logs or holes here */
		(void) nvlist_lookup_uint64(child[c], ZPOOL_CONFIG_IS_LOG,
		    &islog);
		(void) nvlist_lookup_uint64(child[c], ZPOOL_CONFIG_IS_HOLE,
		    &ishole);
		(void) nvlist_lookup_uint64(child[c], ZPOOL_CONFIG_IS_META,
		    &is_meta);
		(void) nvlist_lookup_uint64(child[c], ZPOOL_CONFIG_IS_LOW,
		    &is_low);
		if (islog || ishole || is_meta || is_low)
			continue;
		if ((vname = zpool_vdev_name(g_zfs, zhp, child[c], B_TRUE)) != NULL ) {
			get_status_config(zhp, &child[c]);
			free(vname);
		}
	}
	/* syslog(LOG_ERR, "get_status_config-------5"); */
 	verify(nvlist_add_string(*nv, ZPOOL_CONFIG_SPARES_STATUS, state) == 0);
	verify(nvlist_add_uint64(*nv, ZPOOL_CONFIG_SPARES_AUX, vs->vs_aux) == 0);
	/* syslog(LOG_ERR, "get_status_config-------end"); */

	
}


static void
get_vstat(zpool_handle_t *zhp, nvlist_t **spares, uint_t nspares,
    int namewidth)
{
	uint_t i;
	char *name;

	/* syslog(LOG_ERR, "get_vstat-------start:%d", nspares); */
	if (nspares == 0){
		syslog(LOG_ERR, "nspares == 0");
		return;
	}

	for (i = 0; i < nspares; i++) {
		if ((name = zpool_vdev_name(g_zfs, zhp, spares[i], B_FALSE)) != NULL ) {
			get_status_config(zhp, &spares[i]);
			free(name);
		}
	}
	/* syslog(LOG_ERR, "get_vstat-------end"); */
}

int get_vdev_status(zpool_handle_t *zhp, nvlist_t **config)
{
	nvlist_t *nvroot;
	int namewidth;
	nvlist_t **spares, **lowspares, **metaspares, **mirrorspare;
	uint_t nspares, nlowspares, nmetaspares, nmirrorspare;

	verify(nvlist_lookup_nvlist(*config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) == 0);
	if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_SPARES,
	    &spares, &nspares) == 0)
		get_vstat(zhp, spares, nspares, namewidth);
	if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_METASPARES,
	    &metaspares, &nmetaspares) == 0)
		get_vstat(zhp, metaspares, nmetaspares, namewidth);
	if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_LOWSPARES,
	    &lowspares, &nlowspares) == 0)
		get_vstat(zhp, lowspares, nlowspares, namewidth);
	if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_MIRRORSPARES,
	    &mirrorspare, &nmirrorspare) == 0)
		get_vstat(zhp, mirrorspare, nmirrorspare, namewidth);
	
	return (0);
}

uint_t
zpool_remote_status(zfs_rpc_arg_t *arg, char **nvstring)
{
	zpool_handle_t *zhp;
	boolean_t missing;
	nvlist_t *config;
	uint_t size = 0;

	if ((g_zfs = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "Fail to libzfs_init ");
		return (1);
	}

	if ((zhp = zfs_alloc(g_zfs, sizeof (zpool_handle_t))) == NULL){
		libzfs_fini(g_zfs); 
		return (-1);
	}

	zhp->zpool_hdl = g_zfs;
	(void) strlcpy(zhp->zpool_name, arg->propname, sizeof (zhp->zpool_name));

	if (zpool_refresh_stats(zhp, &missing) != 0) {
		zpool_close(zhp);
		libzfs_fini(g_zfs); 
		syslog(LOG_ERR, "Fail to call zpool_refresh_stats");
		return (-1);
	}

	config = zpool_get_config(zhp, NULL);
	get_vdev_status(zhp, &config);
	verify(nvlist_size(config, (size_t*)&size, NV_ENCODE_NATIVE) == 0);
	if(0 == size)
	{
		zpool_close(zhp);
		libzfs_fini(g_zfs);
		syslog(LOG_ERR, "Fail to get nvlist size");
		return (size);
	}
	
	*nvstring = (char*)malloc(size);
	verify(nvlist_pack(config, nvstring, (size_t*)&size, NV_ENCODE_NATIVE, 0) == 0);
	syslog(LOG_ERR, "Get nvlist size:%"PRIu64"", (uint64_t)size);
	
	zpool_close(zhp);
	
	libzfs_fini(g_zfs); 
	return (size);
}

static void* cmd_exec(void* arg)
{
	
	if(!strcmp("poweroff", arg)){
		system("poweroff");
	}else if(!strcmp("reboot", arg)){
		system("reboot");
	}else if(!strcmp("test", arg)){
		syslog(LOG_ERR, "Cmd TEST------!!!");
	}else{
		syslog(LOG_ERR, "Cmd:<%s>------!!!", (char*)arg);
	}
	
	return ((void*)0);
}

int
zfs_rpc_cmd(zfs_rpc_arg_t *arg)
{
	int ret = 0;
	int fd = 0;
	int ii = 0;
	char remotecmd[1024] = {0};
	char cmdstr[64] = {0};
	pthread_t tid;
	off_t size = 0;

	if(REMOTE_CMD == arg->flag){
		/* syslog(LOG_ERR, "flag:<%d> ", arg->flag); */
		if((1 == arg->bufcnt) && ((!strcmp("poweroff", arg->buf[0])) ||
			(!strcmp("reboot", arg->buf[0]))))
		{
			if (pthread_create(&tid, NULL, cmd_exec, arg->buf[0])) {
				syslog(LOG_ERR, "Create Pthread Fail!!!");
				ret = -1;
			}
 		} else if(1 == arg->bufcnt){
 			system(arg->buf[0]);
 		} else {
			for(ii = 0; ii< arg->bufcnt; ii++){
				memset(cmdstr, 0, 64);
				sprintf(cmdstr, "%s ", arg->buf[ii]);
				strcat(remotecmd, cmdstr);
			}
 			system(remotecmd);
 		}
	}else if(REMOTE_FILE == arg->flag){
		fd = open(arg->propname, O_CREAT | O_RDWR | O_TRUNC);
		if (fd < 0) {
			syslog(LOG_ERR, "Open local file failed");
			return (-1);
		}
		
		size = write(fd, arg->filebuf, arg->filelen);
		if(size != arg->filelen)
		{
			syslog(LOG_ERR, "Fail to write file!!!");
			ret = -1;
		}
		close(fd);
	} else {
		syslog(LOG_ERR, "Invalid Remote process Type!!!");
		ret = -1;
	}
	
	return (ret);
}

int zfs_rpc_back_proc(uint_t rtype, char **backbuf, zfs_rpc_arg_t *recvarg, 
	zfs_rpc_ret_t *backarg)
{
	int ret = 0;
	char send_buf[ZFS_NAME_LEN] = {0};
	static uint_t total_msg_cnt = 0;
	
	switch(rtype){
		case ZFS_RPC_SET_USERQUOTA:
			ret = zfs_remote_set(recvarg);
			sprintf(send_buf, "%d", ret);
			backarg->backbuf = send_buf;
			backarg->backlen = strlen(send_buf);
			break;
		case ZFS_RPC_GET_USERQUOTA:
			if(!recvarg->flag){
				ret = zfs_remote_get(recvarg, backbuf);
				if(ret){
					strcpy(send_buf, "RPC remote Fail to get userquota!!!");
					backarg->backbuf = send_buf;
					backarg->backlen = strlen(send_buf);
					backarg->flag = 0;
				}else{
					total_msg_cnt = recvarg->bufcnt*ZFS_MAXPROPLEN;
					if(total_msg_cnt > RPC_BUF_SIZE_MAX){
						backarg->backbuf = *backbuf;
						backarg->backlen = RPC_BUF_SIZE_MAX;
						backarg->flag = total_msg_cnt;
					}else{
						backarg->backbuf = *backbuf;
						backarg->backlen = total_msg_cnt;
						backarg->flag = 0;
						total_msg_cnt = 0;
					}
				}
			}else{
				if(total_msg_cnt-recvarg->backoffset > RPC_BUF_SIZE_MAX){
					backarg->backbuf = 
						*backbuf+recvarg->backoffset;
					backarg->backlen = RPC_BUF_SIZE_MAX;
					backarg->flag = 1;
				}else{
					backarg->backbuf = 
						*backbuf+recvarg->backoffset;
					backarg->backlen = 
						(total_msg_cnt-recvarg->backoffset);
					backarg->flag = 0;
					total_msg_cnt = 0;
				}
			}
			break;
		case ZFS_RPC_USERSPACE:
			if(!recvarg->flag){
				total_msg_cnt = zfs_remote_userspace(recvarg, backbuf);
				if(0 == total_msg_cnt){
					strcpy(send_buf, "RPC remote Fail to get userquota!!!");
					backarg->backbuf = send_buf;
					backarg->backlen = strlen(send_buf);
					backarg->flag = 0;
				}else{
					if(total_msg_cnt > RPC_BUF_SIZE_MAX){
						backarg->backbuf = *backbuf;
						backarg->backlen = RPC_BUF_SIZE_MAX;
						backarg->flag = 1;
					}else{
						backarg->backbuf = *backbuf;
						backarg->backlen = total_msg_cnt;
						backarg->flag = 0;
						total_msg_cnt = 0;
					}
				}
			}else{
				if(total_msg_cnt-recvarg->backoffset > RPC_BUF_SIZE_MAX){
					backarg->backbuf = 
						*backbuf+recvarg->backoffset;
					backarg->backlen = RPC_BUF_SIZE_MAX;
					backarg->flag = 1;
				}else{
					backarg->backbuf = 
						*backbuf+recvarg->backoffset;
					backarg->backlen = 
						(total_msg_cnt-recvarg->backoffset);
					backarg->flag = 0;
					total_msg_cnt = 0;
				}
			}
			break;
		case ZFS_RPC_ZPOOL_STATUS:
			if(!recvarg->flag){
				total_msg_cnt = zpool_remote_status(recvarg, 
					backbuf);
				if(0 == total_msg_cnt){
					strcpy(send_buf, "RPC remote Fail to get zpool status!!!");
					backarg->backbuf = send_buf;
					backarg->backlen = strlen(send_buf);
					backarg->flag = 0;
				}else{
					if(total_msg_cnt > RPC_BUF_SIZE_MAX){
						backarg->backbuf = *backbuf;
						backarg->backlen = RPC_BUF_SIZE_MAX;
						backarg->flag = total_msg_cnt;
					}else{
						backarg->backbuf = *backbuf;
						backarg->backlen = total_msg_cnt;
						backarg->flag = 0;
						total_msg_cnt = 0;
					}
				}
			}else{
				if(total_msg_cnt-recvarg->backoffset > RPC_BUF_SIZE_MAX){
					backarg->backbuf = 
						*backbuf+recvarg->backoffset;
					backarg->backlen = RPC_BUF_SIZE_MAX;
					backarg->flag = 1;
				}else{
					backarg->backbuf = 
						*backbuf+recvarg->backoffset;
					backarg->backlen = 
						(total_msg_cnt-recvarg->backoffset);
					backarg->flag = 0;
					total_msg_cnt = 0;
				}
			}
			break;
		case ZFS_RPC_REMOTE_CMD:
			ret = zfs_rpc_cmd(recvarg);
			sprintf(send_buf, "%d", ret);
			backarg->backbuf = send_buf;
			backarg->backlen = strlen(send_buf);
			break;
		case ZFS_RPC_DISK_TEST:
			sprintf(send_buf, "0x%x", RPC_USERSPACE_SIZE);
			if(!recvarg->flag){
				total_msg_cnt = RPC_USERSPACE_SIZE;
				*backbuf = (char*)malloc(total_msg_cnt);
				if(NULL == *backbuf)
				{
					strcpy(send_buf, "RPC Server Fail to malloc!!!");
					backarg->backbuf = send_buf;
					backarg->backlen = strlen(send_buf);
				}else{
					memset(*backbuf, 0, total_msg_cnt);
					memcpy(*backbuf, send_buf, strlen(send_buf));
					if(total_msg_cnt > RPC_USERSPACE_SIZE){
						backarg->backbuf = *backbuf;
						backarg->backlen = RPC_USERSPACE_SIZE;
						backarg->flag = 1;
					}else{
						backarg->backbuf = *backbuf;
						backarg->backlen = total_msg_cnt;
						backarg->flag = 0;
						total_msg_cnt = 0;
					}
				}
			}else{
				if(total_msg_cnt-recvarg->backoffset > RPC_USERSPACE_SIZE){
					backarg->backbuf = 
						*backbuf+recvarg->backoffset;
					backarg->backlen = RPC_USERSPACE_SIZE;
					backarg->flag = 1;
				}else{
					backarg->backbuf = 
						*backbuf+recvarg->backoffset;
					backarg->backlen = 
						(total_msg_cnt-recvarg->backoffset);
					backarg->flag = 0;
					total_msg_cnt = 0;
				}
			}
			break;
		default:
			syslog(LOG_ERR, "%s:The type is invalid: %d", __func__, rtype);
	}
	
	return ret;
}

