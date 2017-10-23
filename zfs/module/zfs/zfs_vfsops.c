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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

/* Portions Copyright 2010 Robert Milkowski */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/mntent.h>
#include <sys/mount.h>
#include <sys/cmn_err.h>
#include "fs/fs_subr.h"
#include <sys/zfs_znode.h>
#include <sys/zfs_vnops.h>
#include <sys/zfs_dir.h>
#include <sys/zil.h>
#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_deleg.h>
#include <sys/spa.h>
#include <sys/zap.h>
#include <sys/sa.h>
#include <sys/sa_impl.h>
#include <sys/varargs.h>
#include <sys/policy.h>
#include <sys/atomic.h>
#include <sys/mkdev.h>
#include <sys/modctl.h>
#include <sys/refstr.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_ctldir.h>
#include <sys/zfs_fuid.h>
#include <sys/bootconf.h>
#include <sys/sunddi.h>
#include <sys/dnlc.h>
#include <sys/dmu_objset.h>
#include <sys/spa_boot.h>
#include <sys/zpl.h>
#include "zfs_comutil.h"
#include <sys/zfs_mirror.h>
#include <sys/zfs_group.h>
#include <sys/zfs_group_dtl.h>
#include <sys/zfs_group_sync.h>
#include <linux/spinlock.h>
#include <linux/percpu_counter.h>
#include <linux/security.h>


int vget_repeat_times = 1000;
int vget_failover_time = 210;
int vget_slow_retry_time = 10;
int group_get_fsstat = 0;

extern int ZFS_GROUP_DTL_ENABLE;

const char *zfs_group_map_key_name_prefix_format = "mspa%llu_mobjset%llu_mobj%llu_mgen%llu";
const char *zfs_group_fid_map_key_spa_prefix_format = "object%llu_gen%llu_spa";
const char *zfs_group_fid_map_key_os_prefix_format = "object%llu_gen%llu_objset";
const char *zfs_group_map_zap_obj = "zfs_group_map_obj";
const char *zfs_overquota_prefixex = "overquota@";

const char *zfs_accesslist_prop_prefixes ="accesslist@";
const char *zfs_dirquota_prefixex = "dirquota@";
const char *zfs_dirused_prefixex = "quotaused@";
const char *zfs_dirpath_name_prefixex = "quotapath@";

const char *zfs_dirlowdata_prefixex = "dirlowdata@";
const char *zfs_dirlowdata_period_prefixex = "dirlowdata_period@";
const char *zfs_dirlowdata_delete_period_prefixex = "dirlowdata_delete_period@";
const char *zfs_dirlowdata_period_unit_prefixex = "dirlowdata_period_unit@";
const char *zfs_dirlowdata_criteria_prefixex = "dirlowdata_criteria@";
const char *zfs_dirlowdata_path_prefixex = "dirlowdata_path@";


/*
 * We need to keep a count of active fs's.
 * This is necessary to prevent our module
 * from being unloaded after a umount -f
 */
static uint32_t	zfs_active_fs_count = 0;

/*ARGSUSED*/
int
zfs_sync(struct super_block *sb, int wait, cred_t *cr)
{
	zfs_sb_t *zsb = sb->s_fs_info;

	/*
	 * Data integrity is job one.  We don't want a compromised kernel
	 * writing to the storage pool, so we never sync during panic.
	 */
	if (unlikely(oops_in_progress))
		return (0);

	/*
	 * Semantically, the only requirement is that the sync be initiated.
	 * The DMU syncs out txgs frequently, so there's nothing to do.
	 */
	if (!wait)
		return (0);

	if (zsb != NULL) {
		/*
		 * Sync a specific filesystem.
		 */
		dsl_pool_t *dp;

		ZFS_ENTER(zsb);
		dp = dmu_objset_pool(zsb->z_os);

		/*
		 * If the system is shutting down, then skip any
		 * filesystems which may exist on a suspended pool.
		 */
		if (spa_suspended(dp->dp_spa)) {
			ZFS_EXIT(zsb);
			return (0);
		}

		if (zsb->z_log != NULL)
			zil_commit(zsb->z_log, 0);

		ZFS_EXIT(zsb);
	} else {
		/*
		 * Sync all ZFS filesystems.  This is what happens when you
		 * run sync(1M).  Unlike other filesystems, ZFS honors the
		 * request by waiting for all pools to commit all dirty data.
		 */
		spa_sync_allpools();
	}

	return (0);
}
EXPORT_SYMBOL(zfs_sync);

boolean_t
zfs_is_readonly(zfs_sb_t *zsb)
{
	return (!!(zsb->z_sb->s_flags & MS_RDONLY));
}
EXPORT_SYMBOL(zfs_is_readonly);

static void
atime_changed_cb(void *arg, uint64_t newval)
{
	((zfs_sb_t *)arg)->z_atime = newval;
}

static void
relatime_changed_cb(void *arg, uint64_t newval)
{
	((zfs_sb_t *)arg)->z_relatime = newval;
}

static void
xattr_changed_cb(void *arg, uint64_t newval)
{
	zfs_sb_t *zsb = arg;

	if (newval == ZFS_XATTR_OFF) {
		zsb->z_flags &= ~ZSB_XATTR;
	} else {
		zsb->z_flags |= ZSB_XATTR;

		if (newval == ZFS_XATTR_SA)
			zsb->z_xattr_sa = B_TRUE;
		else
			zsb->z_xattr_sa = B_FALSE;
	}
}

static void
acltype_changed_cb(void *arg, uint64_t newval)
{
	zfs_sb_t *zsb = arg;

	switch (newval) {
	case ZFS_ACLTYPE_OFF:
		zsb->z_acl_type = ZFS_ACLTYPE_OFF;
		zsb->z_sb->s_flags &= ~MS_POSIXACL;
		break;
	case ZFS_ACLTYPE_POSIXACL:
#ifdef CONFIG_FS_POSIX_ACL
		zsb->z_acl_type = ZFS_ACLTYPE_POSIXACL;
		zsb->z_sb->s_flags |= MS_POSIXACL;
#else
		zsb->z_acl_type = ZFS_ACLTYPE_OFF;
		zsb->z_sb->s_flags &= ~MS_POSIXACL;
#endif /* CONFIG_FS_POSIX_ACL */
		break;
	default:
		break;
	}
}

static void
blksz_changed_cb(void *arg, uint64_t newval)
{
	zfs_sb_t *zsb = arg;
	ASSERT3U(newval, <=, spa_maxblocksize(dmu_objset_spa(zsb->z_os)));
	ASSERT3U(newval, >=, SPA_MINBLOCKSIZE);
	ASSERT(ISP2(newval));

	zsb->z_max_blksz = newval;
}

static void
readonly_changed_cb(void *arg, uint64_t newval)
{
	zfs_sb_t *zsb = arg;
	struct super_block *sb = zsb->z_sb;

	if (sb == NULL)
		return;

	if (newval)
		sb->s_flags |= MS_RDONLY;
	else
		sb->s_flags &= ~MS_RDONLY;
}

static void
devices_changed_cb(void *arg, uint64_t newval)
{
}

static void
setuid_changed_cb(void *arg, uint64_t newval)
{
}

static void
exec_changed_cb(void *arg, uint64_t newval)
{
}

static void
nbmand_changed_cb(void *arg, uint64_t newval)
{
	zfs_sb_t *zsb = arg;
	struct super_block *sb = zsb->z_sb;

	if (sb == NULL)
		return;

	if (newval == TRUE)
		sb->s_flags |= MS_MANDLOCK;
	else
		sb->s_flags &= ~MS_MANDLOCK;
}

static void
snapdir_changed_cb(void *arg, uint64_t newval)
{
	((zfs_sb_t *)arg)->z_show_ctldir = newval;
}

static void
vscan_changed_cb(void *arg, uint64_t newval)
{
	((zfs_sb_t *)arg)->z_vscan = newval;
}

static void
acl_inherit_changed_cb(void *arg, uint64_t newval)
{
	((zfs_sb_t *)arg)->z_acl_inherit = newval;
}

int
zfs_register_callbacks(zfs_sb_t *zsb)
{
	struct dsl_dataset *ds = NULL;
	objset_t *os = zsb->z_os;
	zfs_mntopts_t *zmo = zsb->z_mntopts;
	int error = 0;

	ASSERT(zsb);
	ASSERT(zmo);

	/*
	 * The act of registering our callbacks will destroy any mount
	 * options we may have.  In order to enable temporary overrides
	 * of mount options, we stash away the current values and
	 * restore them after we register the callbacks.
	 */
	if (zfs_is_readonly(zsb) || !spa_writeable(dmu_objset_spa(os))) {
		zmo->z_do_readonly = B_TRUE;
		zmo->z_readonly = B_TRUE;
	}

	/*
	 * Register property callbacks.
	 *
	 * It would probably be fine to just check for i/o error from
	 * the first prop_register(), but I guess I like to go
	 * overboard...
	 */
	ds = dmu_objset_ds(os);
	dsl_pool_config_enter(dmu_objset_pool(os), FTAG);
	error = dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_ATIME), atime_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_RELATIME), relatime_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_XATTR), xattr_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_RECORDSIZE), blksz_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_READONLY), readonly_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_DEVICES), devices_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_SETUID), setuid_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_EXEC), exec_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_SNAPDIR), snapdir_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_ACLTYPE), acltype_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_ACLINHERIT), acl_inherit_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_VSCAN), vscan_changed_cb, zsb);
	error = error ? error : dsl_prop_register(ds,
	    zfs_prop_to_name(ZFS_PROP_NBMAND), nbmand_changed_cb, zsb);
	dsl_pool_config_exit(dmu_objset_pool(os), FTAG);
	if (error)
		goto unregister;

	/*
	 * Invoke our callbacks to restore temporary mount options.
	 */
	if (zmo->z_do_readonly)
		readonly_changed_cb(zsb, zmo->z_readonly);
	if (zmo->z_do_setuid)
		setuid_changed_cb(zsb, zmo->z_setuid);
	if (zmo->z_do_exec)
		exec_changed_cb(zsb, zmo->z_exec);
	if (zmo->z_do_devices)
		devices_changed_cb(zsb, zmo->z_devices);
	if (zmo->z_do_xattr)
		xattr_changed_cb(zsb, zmo->z_xattr);
	if (zmo->z_do_atime)
		atime_changed_cb(zsb, zmo->z_atime);
	if (zmo->z_do_relatime)
		relatime_changed_cb(zsb, zmo->z_relatime);
	if (zmo->z_do_nbmand)
		nbmand_changed_cb(zsb, zmo->z_nbmand);

	return (0);

unregister:
	/*
	 * We may attempt to unregister some callbacks that are not
	 * registered, but this is OK; it will simply return ENOMSG,
	 * which we will ignore.
	 */
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_ATIME),
	    atime_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_RELATIME),
	    relatime_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_XATTR),
	    xattr_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_RECORDSIZE),
	    blksz_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_READONLY),
	    readonly_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_DEVICES),
	    devices_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_SETUID),
	    setuid_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_EXEC),
	    exec_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_SNAPDIR),
	    snapdir_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_ACLTYPE),
	    acltype_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_ACLINHERIT),
	    acl_inherit_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_VSCAN),
	    vscan_changed_cb, zsb);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_NBMAND),
	    nbmand_changed_cb, zsb);

	return (error);
}
EXPORT_SYMBOL(zfs_register_callbacks);

static int
zfs_space_delta_cb(dmu_object_type_t bonustype, void *data,
    uint64_t *userp, uint64_t *groupp)
{
	/*
	 * Is it a valid type of object to track?
	 */
	if (bonustype != DMU_OT_ZNODE && bonustype != DMU_OT_SA)
		return (SET_ERROR(ENOENT));

	/*
	 * If we have a NULL data pointer
	 * then assume the id's aren't changing and
	 * return EEXIST to the dmu to let it know to
	 * use the same ids
	 */
	if (data == NULL)
		return (SET_ERROR(EEXIST));

	if (bonustype == DMU_OT_ZNODE) {
		znode_phys_t *znp = data;
		*userp = znp->zp_uid;
		*groupp = znp->zp_gid;
	} else {
		int hdrsize;
		sa_hdr_phys_t *sap = data;
		sa_hdr_phys_t sa = *sap;
		boolean_t swap = B_FALSE;

		ASSERT(bonustype == DMU_OT_SA);

		if (sa.sa_magic == 0) {
			/*
			 * This should only happen for newly created
			 * files that haven't had the znode data filled
			 * in yet.
			 */
			*userp = 0;
			*groupp = 0;
			return (0);
		}
		if (sa.sa_magic == BSWAP_32(SA_MAGIC)) {
			sa.sa_magic = SA_MAGIC;
			sa.sa_layout_info = BSWAP_16(sa.sa_layout_info);
			swap = B_TRUE;
		} else {
			VERIFY3U(sa.sa_magic, ==, SA_MAGIC);
		}

		hdrsize = sa_hdrsize(&sa);
		VERIFY3U(hdrsize, >=, sizeof (sa_hdr_phys_t));
		*userp = *((uint64_t *)((uintptr_t)data + hdrsize +
		    SA_UID_OFFSET));
		*groupp = *((uint64_t *)((uintptr_t)data + hdrsize +
		    SA_GID_OFFSET));
		if (swap) {
			*userp = BSWAP_64(*userp);
			*groupp = BSWAP_64(*groupp);
		}
	}
	return (0);
}

static void
fuidstr_to_sid(zfs_sb_t *zsb, const char *fuidstr,
    char *domainbuf, int buflen, uid_t *ridp)
{
	uint64_t fuid;
	const char *domain;

	fuid = strtonum(fuidstr, NULL);

	domain = zfs_fuid_find_by_idx(zsb, FUID_INDEX(fuid));
	if (domain)
		(void) strlcpy(domainbuf, domain, buflen);
	else
		domainbuf[0] = '\0';
	*ridp = FUID_RID(fuid);
}

static uint64_t
zfs_userquota_prop_to_obj(zfs_sb_t *zsb, zfs_userquota_prop_t type)
{
	switch (type) {
	case ZFS_PROP_USERUSED:
		return (DMU_USERUSED_OBJECT);
	case ZFS_PROP_GROUPUSED:
		return (DMU_GROUPUSED_OBJECT);
	case ZFS_PROP_USEROBJUSED:
		return (DMU_USEROBJUSED_OBJECT ) ;
	case ZFS_PROP_GROUPOBJUSED:
		return (DMU_GROUPOBJUSED_OBJECT ) ;
	case ZFS_PROP_USERQUOTA:
		return (zsb->z_userquota_obj);
	case ZFS_PROP_USEROBJQUOTA:
		return (zsb->z_userobjquota_obj);
	case ZFS_PROP_GROUPQUOTA:
		return (zsb->z_groupquota_obj);
	case ZFS_PROP_GROUPOBJQUOTA:
		return (zsb->z_groupobjquota_obj);
	case ZFS_PROP_SOFTUSERQUOTA:
		return (zsb->z_softuserquota_obj);
	case ZFS_PROP_SOFTGROUPQUOTA:
		return (zsb->z_softgroupquota_obj);
	default:
		return (SET_ERROR(ENOTSUP));
	}
	return (0);
}

int
zfs_userspace_many(zfs_sb_t *zsb, zfs_userquota_prop_t type,
    uint64_t *cookiep, void *vbuf, uint64_t *bufsizep)
{
	int error;
	zap_cursor_t zc;
	zap_attribute_t za;
	zfs_useracct_t *buf = vbuf;
	uint64_t obj;

	if (!dmu_objset_userspace_present(zsb->z_os))
		return (SET_ERROR(ENOTSUP));

	obj = zfs_userquota_prop_to_obj(zsb, type);
	if (obj == 0) {
		*bufsizep = 0;
		return (0);
	}

	for (zap_cursor_init_serialized(&zc, zsb->z_os, obj, *cookiep);
	    (error = zap_cursor_retrieve(&zc, &za)) == 0;
	    zap_cursor_advance(&zc)) {
		if ((uintptr_t)buf - (uintptr_t)vbuf + sizeof (zfs_useracct_t) >
		    *bufsizep)
			break;

		fuidstr_to_sid(zsb, za.za_name,
		    buf->zu_domain, sizeof (buf->zu_domain), &buf->zu_rid);

		buf->zu_space = za.za_first_integer;
		buf++;
	}
	if (error == ENOENT)
		error = 0;

	ASSERT3U((uintptr_t)buf - (uintptr_t)vbuf, <=, *bufsizep);
	*bufsizep = (uintptr_t)buf - (uintptr_t)vbuf;
	*cookiep = zap_cursor_serialize(&zc);
	zap_cursor_fini(&zc);
	return (error);
}
EXPORT_SYMBOL(zfs_userspace_many);

/*
 * buf must be big enough (eg, 32 bytes)
 */
static int
id_to_fuidstr(zfs_sb_t *zsb, const char *domain, uid_t rid,
    char *buf, boolean_t addok)
{
	uint64_t fuid;
	int domainid = 0;

	if (domain && domain[0]) {
		domainid = zfs_fuid_find_by_domain(zsb, domain, NULL, addok);
		if (domainid == -1)
			return (SET_ERROR(ENOENT));
	}
	fuid = FUID_ENCODE(domainid, rid);
	(void) sprintf(buf, "%llx", (longlong_t)fuid);
	return (0);
}

int
zfs_userspace_one(zfs_sb_t *zsb, zfs_userquota_prop_t type,
    const char *domain, uint64_t rid, uint64_t *valp)
{
	char buf[32];
	int err;
	uint64_t obj;

	*valp = 0;

	if (zsb->z_os->os_is_group && zsb->z_os->os_is_master == 0)
		return (ENOENT);
#if 0	
	if (!dmu_objset_userspace_present(zsb->z_os))
		return (SET_ERROR(ENOTSUP));
#endif

	obj = zfs_userquota_prop_to_obj(zsb, type);
	if (obj == 0)
		return (0);

	err = id_to_fuidstr(zsb, domain, rid, buf, B_FALSE);
	if (err)
		return (err);

	err = zap_lookup(zsb->z_os, obj, buf, 8, 1, valp);
	if (err == ENOENT)
		err = 0;
	return (err);
}
EXPORT_SYMBOL(zfs_userspace_one);

int
zfs_set_userquota(zfs_sb_t *zsb, zfs_userquota_prop_t type,
    const char *domain, uint64_t rid, uint64_t quota)
{
	char buf[32];
	int err;
	dmu_tx_t *tx;
	uint64_t *objp;
	uint64_t used_obj ;
	boolean_t fuid_dirtied;

	if (zsb->z_os->os_is_group &&
		zsb->z_os->os_is_master == 0 &&
		zsb->z_os->os_node_type == OS_NODE_TYPE_SLAVE)
		return (EINVAL);

	if (type != ZFS_PROP_USERQUOTA &&
		type != ZFS_PROP_USEROBJQUOTA &&
		type != ZFS_PROP_GROUPQUOTA &&
		type != ZFS_PROP_GROUPOBJQUOTA &&
		type != ZFS_PROP_SOFTUSERQUOTA &&
		type != ZFS_PROP_SOFTGROUPQUOTA)
		return (EINVAL);

	if (zsb->z_version < ZPL_VERSION_USERSPACE)
		return (SET_ERROR(ENOTSUP));

	switch(type) {
		case ZFS_PROP_USERQUOTA:
			objp = &zsb->z_userquota_obj;
			used_obj = DMU_USERUSED_OBJECT ;
			break;
		case ZFS_PROP_USEROBJQUOTA:
			objp = &zsb->z_userobjquota_obj ;
			used_obj = DMU_USEROBJUSED_OBJECT ;
			break ;
		case ZFS_PROP_GROUPQUOTA:
			objp = &zsb->z_groupquota_obj;
			used_obj = DMU_GROUPUSED_OBJECT ;
			break;
		case ZFS_PROP_GROUPOBJQUOTA:
			objp = &zsb->z_groupobjquota_obj ;
			used_obj = DMU_GROUPOBJUSED_OBJECT ;
			break ;
		case ZFS_PROP_SOFTUSERQUOTA:
			objp = &zsb->z_softuserquota_obj;
			used_obj = DMU_USERUSED_OBJECT ;
			break;
		case ZFS_PROP_SOFTGROUPQUOTA:
			objp = &zsb->z_softgroupquota_obj;
			used_obj = DMU_GROUPUSED_OBJECT ;
			break;
	}

	err = id_to_fuidstr(zsb, domain, rid, buf, B_TRUE);
	if (err)
		return (err);
	fuid_dirtied = zsb->z_fuid_dirty;

	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_zap(tx, *objp ? *objp : DMU_NEW_OBJECT, B_TRUE, NULL);
	if (*objp == 0) {
		dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, B_TRUE,
		    zfs_userquota_prop_prefixes[type]);
	}
	if (fuid_dirtied)
		zfs_fuid_txhold(zsb, tx);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err) {
		dmu_tx_abort(tx);
		return (err);
	}

	mutex_enter(&zsb->z_lock);
	if (*objp == 0) {
		*objp = zap_create(zsb->z_os, DMU_OT_USERGROUP_QUOTA,
		    DMU_OT_NONE, 0, tx);
		VERIFY(0 == zap_add(zsb->z_os, MASTER_NODE_OBJ,
		    zfs_userquota_prop_prefixes[type], 8, 1, objp, tx));
	}
	if (DMU_USERUSED_DNODE(zsb->z_os)->dn_type == DMU_OT_NONE) {
		VERIFY(0 == zap_create_claim(zsb->z_os,
		    DMU_USERUSED_OBJECT,
		    DMU_OT_USERGROUP_USED, DMU_OT_NONE, 0, tx));
		VERIFY(0 == zap_create_claim(zsb->z_os,
		    DMU_GROUPUSED_OBJECT,
		    DMU_OT_USERGROUP_USED, DMU_OT_NONE, 0, tx));
		VERIFY(0 == zap_create_claim(zsb->z_os,
		    DMU_USEROBJUSED_OBJECT,
		    DMU_OT_USERGROUP_USED, DMU_OT_NONE, 0, tx));
		VERIFY(0 == zap_create_claim(zsb->z_os,
		    DMU_GROUPOBJUSED_OBJECT,
		    DMU_OT_USERGROUP_USED, DMU_OT_NONE, 0, tx));
	}
	mutex_exit(&zsb->z_lock);

	if (quota == 0) {
		err = zap_remove(zsb->z_os, *objp, buf, tx);
		if (err == 0 || err == ENOENT)
			err = zap_remove(zsb->z_os, used_obj, buf, tx);

		if (err == ENOENT)
			err = 0;
	} else {
		uint64_t used=0;
		err = zap_lookup(zsb->z_os, used_obj, buf, 8, 1, &used);
		if (quota < used) {
			err = EINVAL;
		} else {
			if (err == ENOENT) {
				used = 0;
				err = zap_update(zsb->z_os, used_obj, buf, 8, 1, &used, tx);
			}
			if (err == 0 ) {
				err = zap_update(zsb->z_os, *objp, buf, 8, 1, &quota, tx);
			}
		}
	}
	ASSERT(err == 0);
	if (fuid_dirtied)
		zfs_fuid_sync(zsb, tx);
	dmu_tx_commit(tx);
	txg_wait_synced( dmu_objset_pool( zsb->z_os ), dmu_tx_get_txg( tx ) ) ;
	return (err);
}
EXPORT_SYMBOL(zfs_set_userquota);

static boolean_t
__zfs_fuid_overspacequota( zfs_sb_t *zsb, boolean_t isgroup, uint64_t fuid ) {
	char buf[32];
	uint64_t used, quota, usedobj, quotaobj;
	int err;

	usedobj = isgroup ? DMU_GROUPUSED_OBJECT : DMU_USERUSED_OBJECT;
	quotaobj = isgroup ? zsb->z_groupquota_obj : zsb->z_userquota_obj;

	if (quotaobj == 0 || zsb->z_replay)
		return (B_FALSE);

	(void) sprintf(buf, "%llx", (longlong_t)fuid);
	err = zap_lookup(zsb->z_os, quotaobj, buf, 8, 1, &quota);
	if (err != 0)
		return (B_FALSE);

	err = zap_lookup(zsb->z_os, usedobj, buf, 8, 1, &used);
	if (err != 0)
		return (B_FALSE);

	return ( used > quota ) ;
}

static boolean_t
__zfs_fuid_overobjquota( zfs_sb_t *zsb, boolean_t isgroup, uint64_t fuid ) {
	char buf[32];
	uint64_t used, quota, usedobj, quotaobj;
	int err;

	usedobj = isgroup ? DMU_GROUPOBJUSED_OBJECT : DMU_USEROBJUSED_OBJECT;
	quotaobj = isgroup ? zsb->z_groupobjquota_obj : zsb->z_userobjquota_obj;

	if (quotaobj == 0 || zsb->z_replay)
		return (B_FALSE);

	(void) sprintf(buf, "%llx", (longlong_t)fuid);
	err = zap_lookup(zsb->z_os, quotaobj, buf, 8, 1, &quota);
	if (err != 0)
		return (B_FALSE);

	err = zap_lookup(zsb->z_os, usedobj, buf, 8, 1, &used);
	if (err != 0)
		return (B_FALSE);

	return ( used>=quota ) ;

}

boolean_t
zfs_fuid_overquota(zfs_sb_t *zsb, boolean_t isgroup, uint64_t fuid, int flag)
{
	boolean_t res = 0 ;

	if( flag & QUOTA_SPACE )
		res |= __zfs_fuid_overspacequota( zsb, isgroup, fuid ) ;
	if( flag & QUOTA_OBJ )
		res |= __zfs_fuid_overobjquota( zsb, isgroup, fuid ) ;

	return res ;
}
EXPORT_SYMBOL(zfs_fuid_overquota);

static int
__zfs_fuid_inspacequota( zfs_sb_t *zsb, boolean_t isgroup, uint64_t fuid ) {
	char buf[32];
	uint64_t quota, usedobj, quotaobj;
	int err;

	quotaobj = isgroup ? zsb->z_groupquota_obj : zsb->z_userquota_obj;
	if (quotaobj == 0 || zsb->z_replay)
		return (ENOENT);

	(void) sprintf(buf, "%llx", (longlong_t)fuid);
	err = zap_lookup(zsb->z_os, quotaobj, buf, 8, 1, &quota);

	return (err);
}

static int
__zfs_fuid_inobjquota( zfs_sb_t *zsb, boolean_t isgroup, uint64_t fuid ) {
	char buf[32];
	uint64_t quota, usedobj, quotaobj;
	int err;

	quotaobj = isgroup ? zsb->z_groupobjquota_obj : zsb->z_userobjquota_obj;
	if (quotaobj == 0 || zsb->z_replay)
		return (ENOENT);

	(void) sprintf(buf, "%llx", (longlong_t)fuid);
	err = zap_lookup(zsb->z_os, quotaobj, buf, 8, 1, &quota);

	return (err);
}

int
zfs_fuid_inquota(zfs_sb_t *zsb, boolean_t isgroup, uint64_t fuid)
{
	if( __zfs_fuid_inspacequota(zsb, isgroup, fuid) == 0 ) return 0 ;
	return __zfs_fuid_inobjquota( zsb, isgroup, fuid ) ;
}

boolean_t
zfs_owner_overquota(zfs_sb_t *zsb, znode_t *zp, boolean_t isgroup, int flag)
{
	uint64_t fuid;

	fuid = isgroup ? zp->z_gid : zp->z_uid;

	if ( zsb->z_replay)
		return (B_FALSE);

	return (zfs_fuid_overquota(zsb, isgroup, fuid, flag ));
}
EXPORT_SYMBOL(zfs_owner_overquota);

zfs_mntopts_t *
zfs_mntopts_alloc(void)
{
	return (kmem_zalloc(sizeof (zfs_mntopts_t), KM_SLEEP));
}

void
zfs_mntopts_free(zfs_mntopts_t *zmo)
{
	if (zmo->z_osname)
		strfree(zmo->z_osname);

	if (zmo->z_mntpoint)
		strfree(zmo->z_mntpoint);

	kmem_free(zmo, sizeof (zfs_mntopts_t));
}

int
zfs_sb_create(const char *osname, zfs_mntopts_t *zmo, zfs_sb_t **zsbp)
{
	objset_t *os;
	zfs_sb_t *zsb;
	uint64_t zval;
	int i, size, error;
	uint64_t sa_obj;
	dmu_tx_t *tx = NULL;
	char *buf = NULL;

	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	zsb = vmem_zalloc(sizeof (zfs_sb_t), KM_SLEEP);
	zsb->z_group_map_objs = vmem_zalloc(sizeof(uint64_t)*NASGROUP_MAP_NUM, KM_SLEEP);

	/*
	 * Optional temporary mount options, free'd in zfs_sb_free().
	 */
	zsb->z_mntopts = (zmo ? zmo : zfs_mntopts_alloc());

	/*
	 * We claim to always be readonly so we can open snapshots;
	 * other ZPL code will prevent us from writing to snapshots.
	 */
	error = dmu_objset_own(osname, DMU_OST_ZFS, B_TRUE, zsb, &os);
	if (error)
		goto out_zmo;

	/*
	 * Initialize the zfs-specific filesystem structure.
	 * Should probably make this a kmem cache, shuffle fields.
	 */
	zsb->z_sb = NULL;
	zsb->z_parent = zsb;
	zsb->z_max_blksz = SPA_OLD_MAXBLOCKSIZE;
	zsb->z_show_ctldir = ZFS_SNAPDIR_VISIBLE;
	zsb->z_os = os;
    os->os_replay = zfs_replay_vector;
    os->os_replay_data = zfs_replay_rawdata;
    os->os_seg_data_lock = zfs_seg_data_lock;
    os->os_seg_data_unlock = zfs_seg_data_unlock;

	error = zfs_get_zplprop(os, ZFS_PROP_VERSION, &zsb->z_version);
	if (error) {
		goto out;
	} else if (zsb->z_version > ZPL_VERSION) {
		error = SET_ERROR(ENOTSUP);
		goto out;
	}
	if ((error = zfs_get_zplprop(os, ZFS_PROP_NORMALIZE, &zval)) != 0)
		goto out;
	zsb->z_norm = (int)zval;

	if ((error = zfs_get_zplprop(os, ZFS_PROP_UTF8ONLY, &zval)) != 0)
		goto out;
	zsb->z_utf8 = (zval != 0);

	if ((error = zfs_get_zplprop(os, ZFS_PROP_CASE, &zval)) != 0)
		goto out;
	zsb->z_case = (uint_t)zval;

	if ((error = zfs_get_zplprop(os, ZFS_PROP_ACLTYPE, &zval)) != 0)
		goto out;
	zsb->z_acl_type = (uint_t)zval;

	/*
	 * Fold case on file systems that are always or sometimes case
	 * insensitive.
	 */
	if (zsb->z_case == ZFS_CASE_INSENSITIVE ||
	    zsb->z_case == ZFS_CASE_MIXED)
		zsb->z_norm |= U8_TEXTPREP_TOUPPER;

	zsb->z_use_fuids = USE_FUIDS(zsb->z_version, zsb->z_os);
	zsb->z_use_sa = USE_SA(zsb->z_version, zsb->z_os);

	if (zsb->z_use_sa) {
		/* should either have both of these objects or none */
		error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_SA_ATTRS, 8, 1,
		    &sa_obj);
		if (error)
			goto out;

		error = zfs_get_zplprop(os, ZFS_PROP_XATTR, &zval);
		if ((error == 0) && (zval == ZFS_XATTR_SA))
			zsb->z_xattr_sa = B_TRUE;
	} else {
		/*
		 * Pre SA versions file systems should never touch
		 * either the attribute registration or layout objects.
		 */
		sa_obj = 0;
	}

	error = sa_setup(os, sa_obj, zfs_attr_table, ZPL_END,
	    &zsb->z_attr_table);
	if (error)
		goto out;

	if (zsb->z_version >= ZPL_VERSION_SA)
		sa_register_update_callback(os, zfs_sa_upgrade);

	error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ, 8, 1,
	    &zsb->z_root);
	if (error)
		goto out;
	ASSERT(zsb->z_root != 0);

	error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_UNLINKED_SET, 8, 1,
	    &zsb->z_unlinkedobj);
	if (error)
		goto out;

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_accesslist_prop_prefixes,
	    8, 1, &zsb->z_os->z_accesslist_obj);
	if (error && error != ENOENT)
		goto out;

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    "aclswitch",
	    8, 1, &zsb->z_os->z_aclswitch_obj);
	if (error && error != ENOENT)
		goto out;

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_USERQUOTA],
	    8, 1, &zsb->z_userquota_obj);
	if (error && error != ENOENT)
		goto out;

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_USEROBJQUOTA],
	    8, 1, &zsb->z_userobjquota_obj);
	if (error && error != ENOENT)
		goto out;

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_SOFTUSERQUOTA],
	    8, 1, &zsb->z_softuserquota_obj);
	if (error && error != ENOENT)
		goto out;

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_GROUPQUOTA],
	    8, 1, &zsb->z_groupquota_obj);
	if (error && error != ENOENT)
		goto out;

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_GROUPOBJQUOTA],
	    8, 1, &zsb->z_groupobjquota_obj);
	if (error && error != ENOENT)
		goto out;

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_userquota_prop_prefixes[ZFS_PROP_SOFTGROUPQUOTA],
	    8, 1, &zsb->z_softgroupquota_obj);
	if (error && error != ENOENT)
		goto out;
	zsb->z_overquota = 0;


	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_dirquota_prefixex,
	    8, 1, &zsb->z_dirquota_obj);
	if (error && error != ENOENT)
		goto out;

	error = zap_lookup(os, MASTER_NODE_OBJ,
	    zfs_dirlowdata_prefixex,
	    8, 1, &zsb->z_dirlowdata_obj);
	if (error && error != ENOENT)
		goto out;
	
	error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_FUID_TABLES, 8, 1,
	    &zsb->z_fuid_obj);
	if (error && error != ENOENT)
		goto out;

	error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_SHARES_DIR, 8, 1,
	    &zsb->z_shares_dir);
	if (error && error != ENOENT)
		goto out;

	error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_NAS_GROUP, 8, 1, 
		&zsb->z_nas_group_obj);
	if (error){
		goto out;
	}
/*
	for(i=0;i<NASGROUP_MAP_NUM;i++){
		bzero(buf, MAXPATHLEN);
		sprintf(buf, "%s%d", zfs_group_map_zap_obj, i);
		error = zap_lookup(os, zsb->z_nas_group_obj, buf,
	    	8, 1, &zsb->z_group_map_objs[i]);
		if (error && error != ENOENT){
			cmn_err(CE_WARN, "[%s %d] error=%d", __func__, __LINE__, error);
			goto out;
		}

		if(zsb->z_group_map_objs[i] == 0){
			tx = dmu_tx_create(zsb->z_os);
			error = dmu_tx_assign(tx, TXG_WAIT);
			if (error) {
				dmu_tx_abort(tx);
				cmn_err(CE_WARN, "[Error] %s %d failed in creating %s!", __func__, __LINE__, buf);
				goto out;
			}
			zsb->z_group_map_objs[i] = zap_create(zsb->z_os, DMU_OT_GROUP_MAP,
				DMU_OT_NONE, 0, tx);
			error = zap_add(zsb->z_os, zsb->z_nas_group_obj, buf, 8, 1, &zsb->z_group_map_objs[i], tx);
			dmu_tx_commit(tx);
			if (error != 0){
				cmn_err(CE_WARN, "[Error] %s %d failed in creating %s!", __func__, __LINE__, buf);
				goto out;
			}

			if(debug_nas_group_dtl == 1){
				cmn_err(CE_WARN, "[INFO] %s %llu", buf, (unsigned long long)zsb->z_group_map_objs[i]);
			}
			
		}

		if(debug_nas_group_dtl == 2){
			cmn_err(CE_WARN, "[INFO] %s %d %s %llu", __func__, __LINE__, buf, (unsigned long long)zsb->z_group_map_objs[i]);
		}
	}

	bzero(buf, MAXPATHLEN);
	sprintf(buf, "%s%d", zfs_group_dtl_prefix, 0);
	error = zap_lookup(os, MASTER_NODE_OBJ,
	    buf,
	    8, 1, &zsb->z_group_dtl_obj);
	if (error && error != ENOENT)
		goto out;

#ifdef _KERNEL
	if(zsb->z_group_dtl_obj == 0 && ZFS_GROUP_DTL_ENABLE){
		zfs_group_dtl_init_obj(os, zsb, &zsb->z_group_dtl_obj, 0);
	}
#endif	

	cmn_err(CE_WARN, "[Info] %s %d, zsb->z_group_dtl_obj %llu", 
		__func__, __LINE__, (unsigned long long)zsb->z_group_dtl_obj);

	bzero(buf, MAXPATHLEN);
	sprintf(buf, "%s%d", zfs_group_dtl_prefix, 1);
	error = zap_lookup(os, MASTER_NODE_OBJ,
	    buf, 8, 1, &zsb->z_group_dtl_obj3);
	if (error && error != ENOENT)
		goto out;

#ifdef _KERNEL
	if(zsb->z_group_dtl_obj3 == 0 && ZFS_GROUP_DTL_ENABLE){
		zfs_group_dtl_init_obj(os, zsb, &zsb->z_group_dtl_obj3, 1);
	}
#endif	

	cmn_err(CE_WARN, "[Info] %s %d, zsb->z_group_dtl_obj3 %llu", 
		__func__, __LINE__, (unsigned long long)zsb->z_group_dtl_obj3);

	bzero(buf, MAXPATHLEN);
	sprintf(buf, "%s%d", zfs_group_dtl_prefix, 2);
	error = zap_lookup(os, MASTER_NODE_OBJ,
	    buf,
	    8, 1, &zsb->z_group_dtl_obj4);
	if (error && error != ENOENT)
		goto out;

#ifdef _KERNEL
	if(zsb->z_group_dtl_obj4 == 0 && ZFS_GROUP_DTL_ENABLE){
		zfs_group_dtl_init_obj(os, zsb, &zsb->z_group_dtl_obj4, 2);
	}
#endif

	cmn_err(CE_WARN, "[Info] %s %d, zsb->z_group_dtl_obj4 %llu", 
		__func__, __LINE__, (unsigned long long)zsb->z_group_dtl_obj4);
*/
	
	mutex_init(&zsb->z_znodes_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&zsb->z_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&zsb->z_all_znodes, sizeof (znode_t),
	    offsetof(znode_t, z_link_node));
	rrm_init(&zsb->z_teardown_lock, B_FALSE);
	rw_init(&zsb->z_teardown_inactive_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&zsb->z_fuid_lock, NULL, RW_DEFAULT, NULL);
	for (i = 0; i != 1024; i++)
		mutex_init(&zsb->z_hold_mtx[i], NULL, MUTEX_DEFAULT, NULL);
		
	
	size = MIN(1 << (highbit64(zfs_object_mutex_size)-1), ZFS_OBJ_MTX_MAX);
	zsb->z_hold_size = size;
	zsb->z_hold_trees = vmem_zalloc(sizeof (avl_tree_t) * size, KM_SLEEP);
	zsb->z_hold_locks = vmem_zalloc(sizeof (kmutex_t) * size, KM_SLEEP);
	for (i = 0; i != size; i++) {
		avl_create(&zsb->z_hold_trees[i], zfs_znode_hold_compare,
		    sizeof (znode_hold_t), offsetof(znode_hold_t, zh_node));
		mutex_init(&zsb->z_hold_locks[i], NULL, MUTEX_DEFAULT, NULL);
	}

//	zsb->notify_taskq = taskq_create("ZFS_NOTIFY_TASQ", 512, TASKQ_DEFAULTPRI, 1, 512, 0);
//	zsb->overquota_taskq = taskq_create("ZFS_OVERQUOTA_TASKQ", 512, TASKQ_DEFAULTPRI, 1, 512, 0);
	if (ZFS_GROUP_DTL_ENABLE) {
		zfs_group_dtl_create(&zsb->z_group_dtl_tree);
		zfs_group_dtl_create(&zsb->z_group_dtl_tree2);
		zfs_group_dtl_create(&zsb->z_group_dtl_tree3);
		zfs_group_dtl_create(&zsb->z_group_dtl_tree4);
		mutex_init(&zsb->z_group_dtl_obj_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&zsb->z_group_dtl_tree_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&zsb->z_group_dtl_tree2_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&os->os_group_dtl_th.z_group_dtl_lock, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&os->os_group_dtl3_th.z_group_dtl_lock, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&os->os_group_dtl4_th.z_group_dtl_lock, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&os->os_group_dtl_th.z_group_dtl_cv, NULL, CV_DEFAULT, NULL);
		cv_init(&os->os_group_dtl3_th.z_group_dtl_cv, NULL, CV_DEFAULT, NULL);
		cv_init(&os->os_group_dtl4_th.z_group_dtl_cv, NULL, CV_DEFAULT, NULL);
		mutex_init(&zsb->z_group_dtl_obj3_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&zsb->z_group_dtl_tree3_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&zsb->z_group_dtl_obj4_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&zsb->z_group_dtl_tree4_mutex, NULL, MUTEX_DEFAULT, NULL);
		zsb->z_group_dtl_obj_num = 0;
		zsb->z_group_dtl_obj3_num = 0;
		zsb->z_group_dtl_obj4_num = 0;
	}
	zsb->z_group_sync_obj = zfs_multiclus_create_group_sync_obj();
	
	*zsbp = zsb;
	kmem_free(buf, MAXPATHLEN);
	return (0);

out:
	dmu_objset_disown(os, zsb);
out_zmo:
	*zsbp = NULL;
	zfs_mntopts_free(zsb->z_mntopts);
	vmem_free(zsb->z_group_map_objs, sizeof(uint64_t)*NASGROUP_MAP_NUM);
	vmem_free(zsb, sizeof (zfs_sb_t));
	kmem_free(buf, MAXPATHLEN);
	return (error);
}
EXPORT_SYMBOL(zfs_sb_create);

int
zfs_sb_setup(zfs_sb_t *zsb, boolean_t mounting)
{
	int error;

	error = zfs_register_callbacks(zsb);
	if (error)
		return (error);

	/*
	 * Set the objset user_ptr to track its zsb.
	 */
	mutex_enter(&zsb->z_os->os_user_ptr_lock);
	dmu_objset_set_user(zsb->z_os, zsb);
	mutex_exit(&zsb->z_os->os_user_ptr_lock);

	zsb->z_log = zil_open(zsb->z_os, zfs_get_data);

	/*
	 * If we are not mounting (ie: online recv), then we don't
	 * have to worry about replaying the log as we blocked all
	 * operations out since we closed the ZIL.
	 */
	if (mounting) {
		boolean_t readonly;

		/*
		 * During replay we remove the read only flag to
		 * allow replays to succeed.
		 */
		readonly = zfs_is_readonly(zsb);
		if (readonly != 0)
			readonly_changed_cb(zsb, B_FALSE);
		else
			zfs_unlinked_drain(zsb);

		/*
		 * Parse and replay the intent log.
		 *
		 * Because of ziltest, this must be done after
		 * zfs_unlinked_drain().  (Further note: ziltest
		 * doesn't use readonly mounts, where
		 * zfs_unlinked_drain() isn't called.)  This is because
		 * ziltest causes spa_sync() to think it's committed,
		 * but actually it is not, so the intent log contains
		 * many txg's worth of changes.
		 *
		 * In particular, if object N is in the unlinked set in
		 * the last txg to actually sync, then it could be
		 * actually freed in a later txg and then reallocated
		 * in a yet later txg.  This would write a "create
		 * object N" record to the intent log.  Normally, this
		 * would be fine because the spa_sync() would have
		 * written out the fact that object N is free, before
		 * we could write the "create object N" intent log
		 * record.
		 *
		 * But when we are in ziltest mode, we advance the "open
		 * txg" without actually spa_sync()-ing the changes to
		 * disk.  So we would see that object N is still
		 * allocated and in the unlinked set, and there is an
		 * intent log record saying to allocate it.
		 */
		if (spa_writeable(dmu_objset_spa(zsb->z_os))) {
			if (zil_replay_disable) {
				zil_destroy(zsb->z_log, B_FALSE);
			} else {
				zsb->z_replay = B_TRUE;
                zil_replay(zsb->z_os, zsb,
                    zfs_replay_vector);
				zsb->z_replay = B_FALSE;
			}

            /* check mirror status in dmu_objset_replay_all_cache */
            zsb->z_replay = B_TRUE;
            dmu_objset_replay_all_cache(zsb->z_os);
            zsb->z_replay = B_FALSE;
		}

		/* restore readonly bit */
		if (readonly != 0)
			readonly_changed_cb(zsb, B_TRUE);
	}

	return (0);
}
EXPORT_SYMBOL(zfs_sb_setup);

void
zfs_sb_free(zfs_sb_t *zsb)
{
	int i, size = zsb->z_hold_size;

//	taskq_destroy(zsb->notify_taskq);
//	taskq_destroy(zsb->overquota_taskq);
	zfs_fuid_destroy(zsb);

	mutex_destroy(&zsb->z_znodes_lock);
	mutex_destroy(&zsb->z_lock);
	list_destroy(&zsb->z_all_znodes);
	rrm_destroy(&zsb->z_teardown_lock);
	rw_destroy(&zsb->z_teardown_inactive_lock);
	rw_destroy(&zsb->z_fuid_lock);
	for (i = 0; i != size; i++) {
		avl_destroy(&zsb->z_hold_trees[i]);
		mutex_destroy(&zsb->z_hold_locks[i]);
	}

	for (i = 0; i != 1024; i++)
		mutex_destroy(&zsb->z_hold_mtx[i]);

	vmem_free(zsb->z_hold_trees, sizeof (avl_tree_t) * size);
	vmem_free(zsb->z_hold_locks, sizeof (kmutex_t) * size);
	zfs_mntopts_free(zsb->z_mntopts);

	if (ZFS_GROUP_DTL_ENABLE) {
		mutex_destroy(&zsb->z_group_dtl_obj_mutex);
		mutex_destroy(&zsb->z_group_dtl_tree_mutex);
		mutex_destroy(&zsb->z_group_dtl_tree2_mutex);
		mutex_destroy(&zsb->z_group_dtl_obj3_mutex);
		mutex_destroy(&zsb->z_group_dtl_tree3_mutex);
		mutex_destroy(&zsb->z_group_dtl_obj4_mutex);
		mutex_destroy(&zsb->z_group_dtl_tree4_mutex);
	}
//	zfs_multiclus_destroy_group_sync_obj(zsb->z_group_sync_obj);
//	zsb->z_group_sync_obj = NULL;
	kmem_free(zsb->z_group_map_objs, sizeof(uint64_t)*NASGROUP_MAP_NUM);
	kmem_free(zsb, sizeof (zfs_sb_t));
}
EXPORT_SYMBOL(zfs_sb_free);

static void
zfs_set_fuid_feature(zfs_sb_t *zsb)
{
	zsb->z_use_fuids = USE_FUIDS(zsb->z_version, zsb->z_os);
	zsb->z_use_sa = USE_SA(zsb->z_version, zsb->z_os);
}

void
zfs_unregister_callbacks(zfs_sb_t *zsb)
{
	objset_t *os = zsb->z_os;
	struct dsl_dataset *ds;

	/*
	 * Unregister properties.
	 */
	if (!dmu_objset_is_snapshot(os)) {
		ds = dmu_objset_ds(os);
		VERIFY(dsl_prop_unregister(ds, "atime", atime_changed_cb,
		    zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "relatime", relatime_changed_cb,
		    zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "xattr", xattr_changed_cb,
		    zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "recordsize", blksz_changed_cb,
		    zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "readonly", readonly_changed_cb,
		    zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "devices", devices_changed_cb,
		    zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "setuid", setuid_changed_cb,
		    zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "exec", exec_changed_cb,
		    zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "snapdir", snapdir_changed_cb,
		    zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "acltype", acltype_changed_cb,
		    zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "aclinherit",
		    acl_inherit_changed_cb, zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "vscan",
		    vscan_changed_cb, zsb) == 0);

		VERIFY(dsl_prop_unregister(ds, "nbmand",
		    nbmand_changed_cb, zsb) == 0);
	}
}
EXPORT_SYMBOL(zfs_unregister_callbacks);

#ifdef HAVE_MLSLABEL
/*
 * Check that the hex label string is appropriate for the dataset being
 * mounted into the global_zone proper.
 *
 * Return an error if the hex label string is not default or
 * admin_low/admin_high.  For admin_low labels, the corresponding
 * dataset must be readonly.
 */
int
zfs_check_global_label(const char *dsname, const char *hexsl)
{
	if (strcasecmp(hexsl, ZFS_MLSLABEL_DEFAULT) == 0)
		return (0);
	if (strcasecmp(hexsl, ADMIN_HIGH) == 0)
		return (0);
	if (strcasecmp(hexsl, ADMIN_LOW) == 0) {
		/* must be readonly */
		uint64_t rdonly;

		if (dsl_prop_get_integer(dsname,
		    zfs_prop_to_name(ZFS_PROP_READONLY), &rdonly, NULL))
			return (SET_ERROR(EACCES));
		return (rdonly ? 0 : EACCES);
	}
	return (SET_ERROR(EACCES));
}
EXPORT_SYMBOL(zfs_check_global_label);
#endif /* HAVE_MLSLABEL */

int
zfs_statvfs(struct dentry *dentry, struct kstatfs *statp)
{
	zfs_sb_t *zsb = dentry->d_sb->s_fs_info;
	uint64_t refdbytes, availbytes, usedobjs, availobjs;
	uint64_t fsid;
	uint32_t bshift;

	ZFS_ENTER(zsb);

	if (zsb->z_os->os_is_group){
		if (group_get_fsstat) {
			zfs_client_master_get_group_fsstat(zsb,
			    &refdbytes, &availbytes, &usedobjs, &availobjs);
		} else {
			zfs_client_get_fictitious_group_fsstat(zsb,
			    &refdbytes, &availbytes, &usedobjs, &availobjs);
		}
	} else {
		dmu_objset_space(zsb->z_os,
		    &refdbytes, &availbytes, &usedobjs, &availobjs);
	}

	fsid = dmu_objset_fsid_guid(zsb->z_os);
	/*
	 * The underlying storage pool actually uses multiple block
	 * size.  Under Solaris frsize (fragment size) is reported as
	 * the smallest block size we support, and bsize (block size)
	 * as the filesystem's maximum block size.  Unfortunately,
	 * under Linux the fragment size and block size are often used
	 * interchangeably.  Thus we are forced to report both of them
	 * as the filesystem's maximum block size.
	 */
	statp->f_frsize = zsb->z_max_blksz;
	statp->f_bsize = zsb->z_max_blksz;
	bshift = fls(statp->f_bsize) - 1;

	/*
	 * The following report "total" blocks of various kinds in
	 * the file system, but reported in terms of f_bsize - the
	 * "preferred" size.
	 */

	statp->f_blocks = (refdbytes + availbytes) >> bshift;
	statp->f_bfree = availbytes >> bshift;
	statp->f_bavail = statp->f_bfree; /* no root reservation */

	/*
	 * statvfs() should really be called statufs(), because it assumes
	 * static metadata.  ZFS doesn't preallocate files, so the best
	 * we can do is report the max that could possibly fit in f_files,
	 * and that minus the number actually used in f_ffree.
	 * For f_ffree, report the smaller of the number of object available
	 * and the number of blocks (each object will take at least a block).
	 */
	statp->f_ffree = MIN(availobjs, availbytes >> DNODE_SHIFT);
	statp->f_files = statp->f_ffree + usedobjs;
	statp->f_fsid.val[0] = (uint32_t)fsid;
	statp->f_fsid.val[1] = (uint32_t)(fsid >> 32);
	statp->f_type = ZFS_SUPER_MAGIC;
	statp->f_namelen = ZFS_MAXNAMELEN;

	/*
	 * We have all of 40 characters to stuff a string here.
	 * Is there anything useful we could/should provide?
	 */
	bzero(statp->f_spare, sizeof (statp->f_spare));

	ZFS_EXIT(zsb);
	return (0);
}
EXPORT_SYMBOL(zfs_statvfs);

int
zfs_root(zfs_sb_t *zsb, struct inode **ipp)
{
	znode_t *rootzp;
	int error;

	ZFS_ENTER(zsb);

	error = zfs_zget(zsb, zsb->z_root, &rootzp);
	if (error == 0)
		*ipp = ZTOI(rootzp);

	ZFS_EXIT(zsb);
	return (error);
}
EXPORT_SYMBOL(zfs_root);

#ifdef HAVE_D_PRUNE_ALIASES
/*
 * Linux kernels older than 3.1 do not support a per-filesystem shrinker.
 * To accommodate this we must improvise and manually walk the list of znodes
 * attempting to prune dentries in order to be able to drop the inodes.
 *
 * To avoid scanning the same znodes multiple times they are always rotated
 * to the end of the z_all_znodes list.  New znodes are inserted at the
 * end of the list so we're always scanning the oldest znodes first.
 */
static int
zfs_sb_prune_aliases(zfs_sb_t *zsb, unsigned long nr_to_scan)
{
	znode_t **zp_array, *zp;
	int max_array = MIN(nr_to_scan, PAGE_SIZE * 8 / sizeof (znode_t *));
	int objects = 0;
	int i = 0, j = 0;

	zp_array = kmem_zalloc(max_array * sizeof (znode_t *), KM_SLEEP);

	mutex_enter(&zsb->z_znodes_lock);
	while ((zp = list_head(&zsb->z_all_znodes)) != NULL) {

		if ((i++ > nr_to_scan) || (j >= max_array))
			break;

		ASSERT(list_link_active(&zp->z_link_node));
		list_remove(&zsb->z_all_znodes, zp);
		list_insert_tail(&zsb->z_all_znodes, zp);

		/* Skip active znodes and .zfs entries */
		if (MUTEX_HELD(&zp->z_lock) || zp->z_is_ctldir)
			continue;

		if (igrab(ZTOI(zp)) == NULL)
			continue;

		zp_array[j] = zp;
		j++;
	}
	mutex_exit(&zsb->z_znodes_lock);

	for (i = 0; i < j; i++) {
		zp = zp_array[i];

		ASSERT3P(zp, !=, NULL);
		d_prune_aliases(ZTOI(zp));

		if (atomic_read(&ZTOI(zp)->i_count) == 1)
			objects++;

		iput(ZTOI(zp));
	}

	kmem_free(zp_array, max_array * sizeof (znode_t *));

	return (objects);
}
#endif /* HAVE_D_PRUNE_ALIASES */

/*
 * The ARC has requested that the filesystem drop entries from the dentry
 * and inode caches.  This can occur when the ARC needs to free meta data
 * blocks but can't because they are all pinned by entries in these caches.
 */
int
zfs_sb_prune(struct super_block *sb, unsigned long nr_to_scan, int *objects)
{
	zfs_sb_t *zsb = sb->s_fs_info;
	int error = 0;
#if defined(HAVE_SHRINK) || defined(HAVE_SPLIT_SHRINKER_CALLBACK)
	struct shrinker *shrinker = &sb->s_shrink;
	struct shrink_control sc = {
		.nr_to_scan = nr_to_scan,
		.gfp_mask = GFP_KERNEL,
	};
#endif

	ZFS_ENTER(zsb);

#if defined(HAVE_SPLIT_SHRINKER_CALLBACK) && \
	defined(SHRINK_CONTROL_HAS_NID) && \
	defined(SHRINKER_NUMA_AWARE)
	if (sb->s_shrink.flags & SHRINKER_NUMA_AWARE) {
		*objects = 0;
		for_each_online_node(sc.nid)
			*objects += (*shrinker->scan_objects)(shrinker, &sc);
	} else {
			*objects = (*shrinker->scan_objects)(shrinker, &sc);
	}

#elif defined(HAVE_SPLIT_SHRINKER_CALLBACK)
	*objects = (*shrinker->scan_objects)(shrinker, &sc);
#elif defined(HAVE_SHRINK)
	*objects = (*shrinker->shrink)(shrinker, &sc);
#elif defined(HAVE_D_PRUNE_ALIASES)
#define	D_PRUNE_ALIASES_IS_DEFAULT
	*objects = zfs_sb_prune_aliases(zsb, nr_to_scan);
#else
#error "No available dentry and inode cache pruning mechanism."
#endif

#if defined(HAVE_D_PRUNE_ALIASES) && !defined(D_PRUNE_ALIASES_IS_DEFAULT)
#undef	D_PRUNE_ALIASES_IS_DEFAULT
	/*
	 * Fall back to zfs_sb_prune_aliases if the kernel's per-superblock
	 * shrinker couldn't free anything, possibly due to the inodes being
	 * allocated in a different memcg.
	 */
	if (*objects == 0)
		*objects = zfs_sb_prune_aliases(zsb, nr_to_scan);
#endif

	ZFS_EXIT(zsb);

	dprintf_ds(zsb->z_os->os_dsl_dataset,
	    "pruning, nr_to_scan=%lu objects=%d error=%d\n",
	    nr_to_scan, *objects, error);

	return (error);
}
EXPORT_SYMBOL(zfs_sb_prune);

/*
 * Teardown the zfs_sb_t.
 *
 * Note, if 'unmounting' if FALSE, we return with the 'z_teardown_lock'
 * and 'z_teardown_inactive_lock' held.
 */
int
zfs_sb_teardown(zfs_sb_t *zsb, boolean_t unmounting)
{
	znode_t	*zp;

	/*
	 * If someone has not already unmounted this file system,
	 * drain the iput_taskq to ensure all active references to the
	 * zfs_sb_t have been handled only then can it be safely destroyed.
	 */
	if (zsb->z_os) {
		/*
		 * If we're unmounting we have to wait for the list to
		 * drain completely.
		 *
		 * If we're not unmounting there's no guarantee the list
		 * will drain completely, but iputs run from the taskq
		 * may add the parents of dir-based xattrs to the taskq
		 * so we want to wait for these.
		 *
		 * We can safely read z_nr_znodes without locking because the
		 * VFS has already blocked operations which add to the
		 * z_all_znodes list and thus increment z_nr_znodes.
		 */
		int round = 0;
		while (zsb->z_nr_znodes > 0) {
			taskq_wait_outstanding(dsl_pool_iput_taskq(
			    dmu_objset_pool(zsb->z_os)), 0);
			if (++round > 1 && !unmounting)
				break;
		}
	}

	rrm_enter(&zsb->z_teardown_lock, RW_WRITER, FTAG);

	if (!unmounting) {
		/*
		 * We purge the parent filesystem's super block as the
		 * parent filesystem and all of its snapshots have their
		 * inode's super block set to the parent's filesystem's
		 * super block.  Note,  'z_parent' is self referential
		 * for non-snapshots.
		 */
		shrink_dcache_sb(zsb->z_parent->z_sb);
	}

	/*
	 * Close the zil. NB: Can't close the zil while zfs_inactive
	 * threads are blocked as zil_close can call zfs_inactive.
	 */
	if (zsb->z_log) {
		zil_close(zsb->z_log);
		zsb->z_log = NULL;
	}

	rw_enter(&zsb->z_teardown_inactive_lock, RW_WRITER);

	/*
	 * If we are not unmounting (ie: online recv) and someone already
	 * unmounted this file system while we were doing the switcheroo,
	 * or a reopen of z_os failed then just bail out now.
	 */
	if (!unmounting && (zsb->z_unmounted || zsb->z_os == NULL)) {
		rw_exit(&zsb->z_teardown_inactive_lock);
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		return (SET_ERROR(EIO));
	}

	/*
	 * At this point there are no VFS ops active, and any new VFS ops
	 * will fail with EIO since we have z_teardown_lock for writer (only
	 * relevant for forced unmount).
	 *
	 * Release all holds on dbufs.
	 */
	if (!unmounting) {
		mutex_enter(&zsb->z_znodes_lock);
		for (zp = list_head(&zsb->z_all_znodes); zp != NULL;
		zp = list_next(&zsb->z_all_znodes, zp)) {
			if (zp->z_sa_hdl)
				zfs_znode_dmu_fini(zp);
		}
		mutex_exit(&zsb->z_znodes_lock);
	}

	/*
	 * If we are unmounting, set the unmounted flag and let new VFS ops
	 * unblock.  zfs_inactive will have the unmounted behavior, and all
	 * other VFS ops will fail with EIO.
	 */
	if (unmounting) {
		zsb->z_unmounted = B_TRUE;
		rrm_exit(&zsb->z_teardown_lock, FTAG);
		rw_exit(&zsb->z_teardown_inactive_lock);
	}

	/*
	 * z_os will be NULL if there was an error in attempting to reopen
	 * zsb, so just return as the properties had already been
	 *
	 * unregistered and cached data had been evicted before.
	 */
	if (zsb->z_os == NULL)
		return (0);

	/*
	 * Unregister properties.
	 */
	zfs_unregister_callbacks(zsb);

    dmu_objset_cache_clean_size(zsb->z_os, -1, B_TRUE);

	/*
	 * Evict cached data
	 */
	if (dsl_dataset_is_dirty(dmu_objset_ds(zsb->z_os)) &&
	    !zfs_is_readonly(zsb))
		txg_wait_synced(dmu_objset_pool(zsb->z_os), 0);
	dmu_objset_evict_dbufs(zsb->z_os);

	return (0);
}
EXPORT_SYMBOL(zfs_sb_teardown);

#if !defined(HAVE_2ARGS_BDI_SETUP_AND_REGISTER) && \
	!defined(HAVE_3ARGS_BDI_SETUP_AND_REGISTER)
atomic_long_t zfs_bdi_seq = ATOMIC_LONG_INIT(0);
#endif


int debug_zgroup_dtl_test = 0;

int
zfs_domount(struct super_block *sb, zfs_mntopts_t *zmo, int silent)
{
	const char *osname = zmo->z_osname;
	zfs_sb_t *zsb;
	struct inode *root_inode;
	uint64_t recordsize;
	int error;

	error = zfs_sb_create(osname, zmo, &zsb);
	if (error)
		return (error);

	if ((error = dsl_prop_get_integer(osname, "recordsize",
	    &recordsize, NULL)))
		goto out;

	zsb->z_sb = sb;
	sb->s_fs_info = zsb;
	sb->s_magic = ZFS_SUPER_MAGIC;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;
	sb->s_blocksize = recordsize;
	sb->s_blocksize_bits = ilog2(recordsize);
	zsb->z_bdi.ra_pages = 0;
	sb->s_bdi = &zsb->z_bdi;

	error = -zpl_bdi_setup_and_register(&zsb->z_bdi, "zfs");
	if (error)
		goto out;

	/* Set callback operations for the file system. */
	sb->s_op = &zpl_super_operations;
	sb->s_xattr = zpl_xattr_handlers;
	sb->s_export_op = &zpl_export_operations;
#ifdef HAVE_S_D_OP
	sb->s_d_op = &zpl_dentry_operations;
#endif /* HAVE_S_D_OP */

	/* Set features for file system. */
	zfs_set_fuid_feature(zsb);

	if (dmu_objset_is_snapshot(zsb->z_os)) {
		uint64_t pval;

		atime_changed_cb(zsb, B_FALSE);
		readonly_changed_cb(zsb, B_TRUE);
		if ((error = dsl_prop_get_integer(osname,
		    "xattr", &pval, NULL)))
			goto out;
		xattr_changed_cb(zsb, pval);
		if ((error = dsl_prop_get_integer(osname,
		    "acltype", &pval, NULL)))
			goto out;
		acltype_changed_cb(zsb, pval);
		zsb->z_issnap = B_TRUE;
        /*zsb->z_os->os_sync = ZFS_SYNC_DISABLED;*/
        zsb->z_os->os_sync = ZFS_SYNC_MIRROR;
		zsb->z_snap_defer_time = jiffies;

		mutex_enter(&zsb->z_os->os_user_ptr_lock);
		dmu_objset_set_user(zsb->z_os, zsb);
		mutex_exit(&zsb->z_os->os_user_ptr_lock);
	} else {
#ifdef _KERNEL
		zsb->z_is_setting_up = B_TRUE;
		if (zsb->z_os->os_phys->os_type == DMU_OST_ZFS && zsb->z_os->os_is_group) {
			if (zfs_multiclus_update_record(zsb->z_os->os_group_name, zsb->z_os) == -1)
				cmn_err(CE_WARN, "zfs_multiclus mod is not ready");
		}
#endif
		error = zfs_sb_setup(zsb, B_TRUE);
#ifdef _KERNEL
		zsb->z_is_setting_up = B_FALSE;
#endif
	}

	/* Allocate a root inode for the filesystem. */
	error = zfs_root(zsb, &root_inode);
	if (error) {
		(void) zfs_umount(sb);
		goto out;
	}

	/* Allocate a root dentry for the filesystem */
	sb->s_root = d_make_root(root_inode);
	if (sb->s_root == NULL) {
		(void) zfs_umount(sb);
		error = SET_ERROR(ENOMEM);
		goto out;
	}

	if (!zsb->z_issnap)
		zfsctl_create(zsb);

	zsb->z_arc_prune = arc_add_prune_callback(zpl_prune_sb, sb);
out:
	if (error) {
		dmu_objset_disown(zsb->z_os, zsb);
		zfs_sb_free(zsb);
	}else{
		atomic_add_32(&zfs_active_fs_count, 1);
	}

	if(debug_zgroup_dtl_test){
		zfs_group_dtl_test(osname);
	}else{
		if(error == 0 && ZFS_GROUP_DTL_ENABLE){
			start_zfs_group_dtl_thread(zsb->z_os);
		}
	}
	
	return (error);
}
EXPORT_SYMBOL(zfs_domount);

/*
 * Called when an unmount is requested and certain sanity checks have
 * already passed.  At this point no dentries or inodes have been reclaimed
 * from their respective caches.  We drop the extra reference on the .zfs
 * control directory to allow everything to be reclaimed.  All snapshots
 * must already have been unmounted to reach this point.
 */
void
zfs_preumount(struct super_block *sb)
{
	zfs_sb_t *zsb = sb->s_fs_info;

	if (zsb)
		zfsctl_destroy(sb->s_fs_info);
}
EXPORT_SYMBOL(zfs_preumount);

/*
 * Called once all other unmount released tear down has occurred.
 * It is our responsibility to release any remaining infrastructure.
 */
/*ARGSUSED*/
int
zfs_umount(struct super_block *sb)
{
	zfs_sb_t *zsb = sb->s_fs_info;
	objset_t *os;
	char fsname[MAX_FSNAME_LEN] = {0};
	os = zsb->z_os;

	if (ZFS_GROUP_DTL_ENABLE)
		stop_zfs_group_dtl_thread(os);
	if (zfs_multiclus_enable()) {
		dmu_objset_name(os, fsname);
		zfs_multiclus_stop_sync((char *)os->os_group_name, (char *)fsname);
	}
	
	if (os != NULL && os->os_is_group && zfs_multiclus_enable() && ZFS_GROUP_DTL_ENABLE) {
		zfs_group_dtl_sync_tree134(os);
		zfs_group_dtl_sync_tree2(os, NULL);
	}

	arc_remove_prune_callback(zsb->z_arc_prune);
	VERIFY(zfs_sb_teardown(zsb, B_TRUE) == 0);
	bdi_destroy(sb->s_bdi);

	/*
	 * z_os will be NULL if there was an error in
	 * attempting to reopen zsb.
	 */
	if (os != NULL) {
		if (os->os_is_group && zfs_multiclus_enable()) {
			zfs_multiclus_destroy_reg_record(os->os_group_name,
			    spa_guid(dmu_objset_spa(os)), dmu_objset_id(os));
		}

		/*
		 * Unset the objset user_ptr.
		 */
		mutex_enter(&os->os_user_ptr_lock);
		dmu_objset_set_user(os, NULL);
		mutex_exit(&os->os_user_ptr_lock);

		/*
		 * Finally release the objset
		 */
		dmu_objset_disown(os, zsb);
	}
	zfs_sb_free(zsb);
	return (0);
}
EXPORT_SYMBOL(zfs_umount);

int
zfs_remount(struct super_block *sb, int *flags, zfs_mntopts_t *zmo)
{
	zfs_sb_t *zsb = sb->s_fs_info;
	int error;

	zfs_unregister_callbacks(zsb);
	error = zfs_register_callbacks(zsb);

	return (error);
}
EXPORT_SYMBOL(zfs_remount);


static int zfs_fid_get_master_info(zfs_sb_t	*zsb, uint64_t object, uint64_t gen, uint64_t *master_spa, uint64_t *master_os)
{
	int i = 0;
	int err = 0;
	uint64_t map_obj = 0;
	char buf[MAXNAMELEN];


	map_obj = zsb->z_group_map_objs[object%NASGROUP_MAP_NUM];
	if (map_obj == 0) {
		return -1;
	}
	
	bzero(buf, MAXNAMELEN);
	sprintf(buf, zfs_group_fid_map_key_spa_prefix_format, object, gen);
	err = zap_lookup(zsb->z_os, map_obj, buf, 8, 1, master_spa);
	if (err) {
		return -1;
	}
	bzero(buf, MAXNAMELEN);
	sprintf(buf, zfs_group_fid_map_key_os_prefix_format, object, gen);
	err = zap_lookup(zsb->z_os, map_obj, buf, 8, 1, master_os);
	if (err) {
		return -1;
	}

	return 0;
}

int
zfs_vget(struct super_block *sb, struct inode **ipp, fid_t *fidp)
{
	zfs_sb_t	*zsb = sb->s_fs_info;
	znode_t		*zp;
	int			i, err;
	int 		retry = 0;
	int			record_num = 0;
	uint64_t	object = 0;
	uint64_t	fid_gen = 0;
	uint64_t	old_gen = 0;
	uint64_t	gen_mask;
	uint64_t	zp_gen;
	uint64_t	dirquota = 0;
	uint64_t	dirlowdata = 0;
	uint64_t	master_spa = 0;
	uint64_t	master_os = 0;
	uint64_t	m_spa = 0;
	uint64_t	m_objset = 0;
	uint64_t	m_object = 0;
	boolean_t	failover_down = B_FALSE;
	boolean_t	local_regeted = B_FALSE;
	char		buf[MAXNAMELEN];

	*ipp = NULL;

	ZFS_ENTER(zsb);

	if (fidp->fid_len == LONG_FID_LEN) {
		zfid_long_t	*zlfid = (zfid_long_t *)fidp;
		uint64_t	objsetid = 0;

		for (i = 0; i < sizeof (zlfid->zf_setid); i++)
			objsetid |= ((uint64_t)zlfid->zf_setid[i]) << (8 * i);
		for (i = 0; i < sizeof (zlfid->zf_dirquota); i++)
			dirquota |= ((uint64_t)zlfid->zf_dirquota[i]) << (8 * i);
		for (i = 0; i < sizeof (zlfid->zf_dirlowdata); i++)
			dirlowdata |= ((uint64_t)zlfid->zf_dirlowdata[i] << (8 * i));

		ZFS_EXIT(zsb);
		if (objsetid != dmu_objset_id(zsb->z_os)) {
			err = zfsctl_lookup_objset(sb, objsetid, &zsb);
			if (err){
				cmn_err(CE_WARN, "[%s %d] long fid return", __func__, __LINE__);
				return (SET_ERROR(EINVAL));
			}
		}
		ZFS_ENTER(zsb);
	}

	if (fidp->fid_len == SHORT_FID_LEN || fidp->fid_len == LONG_FID_LEN) {
		zfid_short_t	*zfid = (zfid_short_t *)fidp;

		for (i = 0; i < sizeof (zfid->zf_object); i++)
			object |= ((uint64_t)zfid->zf_object[i]) << (8 * i);

		for (i = 0; i < sizeof (zfid->zf_gen); i++)
			fid_gen |= ((uint64_t)zfid->zf_gen[i]) << (8 * i);
	} else {
		cmn_err(CE_WARN, "[%s %d] long fid return", __func__, __LINE__);
		ZFS_EXIT(zsb);
		return (SET_ERROR(EINVAL));
	}

	/* A zero fid_gen means we are in the .zfs control directories */
	if (fid_gen == 0 &&
	    (object == ZFSCTL_INO_ROOT || object == ZFSCTL_INO_SNAPDIR)) {
		*ipp = zsb->z_ctldir;
		ASSERT(*ipp != NULL);
		if (object == ZFSCTL_INO_SNAPDIR) {
			VERIFY(zfsctl_root_lookup(*ipp, "snapshot", ipp,
			    0, kcred, NULL, NULL) == 0);
		} else {
			igrab(*ipp);
		}
		cmn_err(CE_WARN, "[%s %d] long fid return", __func__, __LINE__);
		ZFS_EXIT(zsb);
		return (0);
	}

	gen_mask = ZFS_GROUP_GEN_MASK;
	dprintf("getting %llu [%llu mask %llx]\n", object, fid_gen, gen_mask);

	if (zsb->z_os->os_is_group && object != zsb->z_root) {
		(void)zfs_fid_get_master_info(zsb, object, fid_gen, &master_spa, &master_os);
	}

reget:

	if (master_spa && master_os && (master_spa != zsb->z_os->os_master_spa || master_os != zsb->z_os->os_master_os)) {
		m_spa = master_spa;
		m_objset = master_os;
	}

	if ((object <= zsb->z_shares_dir) || !zsb->z_os->os_is_group || (zsb->z_os->os_is_group && zsb->z_os->os_is_master)) {

		if(zsb->z_group_map_objs[object%NASGROUP_MAP_NUM] != 0 && m_spa !=0 && m_objset !=0){
			bzero(buf, MAXNAMELEN);
			sprintf(buf, zfs_group_map_key_name_prefix_format, m_spa, m_objset, object, fid_gen);
			err = zap_lookup(zsb->z_os, zsb->z_group_map_objs[object%NASGROUP_MAP_NUM], buf, 8, 1, &m_object);
			if(err == 0){
				object = m_object;
			}
		}
		if (err = zfs_zget(zsb, object, &zp)) {
			if (err && local_regeted == B_FALSE) {
				local_regeted = B_TRUE;
				goto reget;
			}
			ZFS_EXIT(zsb);
			cmn_err(CE_WARN, "long fid return error3 object=%lld, err: %d", (longlong_t)object, err);
			return (err);
		}
		(void) sa_lookup(zp->z_sa_hdl, SA_ZPL_GEN(zsb), &zp_gen, sizeof (uint64_t));
	} else {
		err = zfs_group_zget(zsb, object, &zp, m_spa, m_objset, fid_gen, B_FALSE);
		if (err) {
			if (retry < vget_repeat_times){
				if (retry > vget_failover_time && !failover_down) {
					zfs_failover_ctl(zsb->z_os, 80);
					failover_down = B_TRUE;
				}
				if (retry > vget_slow_retry_time) {
					zfs_group_wait(ZFS_MULTICLUS_SECOND/10);
				}
				retry++;
				goto reget;
			}
			cmn_err(CE_WARN, "long fid return error4, object=%lld, err: %d", (longlong_t)object, err);
			ZFS_EXIT(zsb);
			return (err);
 		}
		/* if zp is dir, need to get inode with dentry*/
		if (object != zsb->z_root && S_ISDIR(ZTOI(zp)->i_mode)){
			char *fullpath = NULL;
			struct file *filp = NULL;

			fullpath = vmem_zalloc(MAXPATHLEN, KM_SLEEP);
			/*root dir*/
			sprintf(fullpath, "%s/%s", zsb->z_mntopts->z_mntpoint, zp->z_filename);
			//cmn_err(CE_WARN, "[%s %d] full path=%s", __func__, __LINE__, fullpath);
			iput(ZTOI(zp));
			zp = NULL;

			/*get inode linked dentry*/
			if (fullpath == NULL) {
				vmem_free(fullpath, MAXPATHLEN);
				return EINVAL;
			}
			ZFS_EXIT(zsb);
			filp = filp_open(fullpath, O_DIRECTORY, 0);
			if (IS_ERR(filp)){
				filp = filp_open(fullpath, O_RDONLY, 0444);
				if (IS_ERR(filp)){
					cmn_err(CE_WARN, "[%s %d], the fullpath %s is error", __func__, __LINE__, fullpath);
					vmem_free(fullpath, MAXPATHLEN);
					return (EINVAL);
				}
			}
			zp = ITOZ(filp->f_path.dentry->d_inode);
			dget(filp->f_path.dentry);
			igrab(ZTOI(zp));
			filp_close(filp, NULL);
			vmem_free(fullpath, MAXPATHLEN);
			ZFS_ENTER(zsb);
		}
		zp_gen = zp->z_gen;
	}
	zp_gen = zp_gen & gen_mask;
	old_gen = zp->z_old_gen & gen_mask;
	if (zp_gen == 0) {
		zp_gen = 1;
	}

	if (zp->z_unlinked || (zp_gen != fid_gen && fid_gen != old_gen && (zsb->z_os->os_is_group == 0))) {
		cmn_err(CE_WARN, "[ERROR] zp->z_unlinked %d, z_id 0x%llx, zp_gen 0x%llx, fid_gen 0x%llx, file name %s, zp->z_gen 0x%llx, gen_mask 0x%llx, z_old_gen: %llx", 
			zp->z_unlinked, (unsigned long long)zp->z_id,(unsigned long long)zp_gen, 
			(unsigned long long)fid_gen, zp->z_filename, (unsigned long long)zp->z_gen, (unsigned long long)gen_mask, 
			(unsigned long long)zp->z_old_gen);
		dprintf("znode gen (%u) != fid gen (%u)\n", zp_gen, fid_gen);
		iput(ZTOI(zp));
		ZFS_EXIT(zsb);
		cmn_err(CE_WARN, "long fid return error5");
		return (EINVAL);
	}
	if (zp->z_dirquota == 0) {
		zp->z_dirquota = dirquota;
	}
	if (zp->z_dirlowdata == 0) {
		zp->z_dirlowdata = dirlowdata;
	}
	if (zp->z_dirquota != 0 && (zsb->z_os->os_is_group && !zsb->z_os->os_is_master)) {
		zp->z_overquota = zfs_client_overquota(zsb, zp, QUOTA_ALL );
	}
	if (failover_down && retry < vget_repeat_times) {
		zfs_failover_ctl(zsb->z_os, 0);
	}

	zfs_inquota(zsb, zp);
	*ipp = ZTOI(zp);
	ZFS_EXIT(zsb);
	return (0);
}
EXPORT_SYMBOL(zfs_vget);

/*
 * Block out VFS ops and close zfs_sb_t
 *
 * Note, if successful, then we return with the 'z_teardown_lock' and
 * 'z_teardown_inactive_lock' write held.  We leave ownership of the underlying
 * dataset and objset intact so that they can be atomically handed off during
 * a subsequent rollback or recv operation and the resume thereafter.
 */
int
zfs_suspend_fs(zfs_sb_t *zsb)
{
	int error;

	if ((error = zfs_sb_teardown(zsb, B_FALSE)) != 0)
		return (error);

	return (0);
}
EXPORT_SYMBOL(zfs_suspend_fs);

/*
 * Reopen zfs_sb_t and release VFS ops.
 */
int
zfs_resume_fs(zfs_sb_t *zsb, const char *osname)
{
	int err, err2;
	znode_t *zp;
	uint64_t sa_obj = 0;

	ASSERT(RRM_WRITE_HELD(&zsb->z_teardown_lock));
	ASSERT(RW_WRITE_HELD(&zsb->z_teardown_inactive_lock));

	/*
	 * We already own this, so just hold and rele it to update the
	 * objset_t, as the one we had before may have been evicted.
	 */
	VERIFY0(dmu_objset_hold(osname, zsb, &zsb->z_os));
	VERIFY3P(zsb->z_os->os_dsl_dataset->ds_owner, ==, zsb);
	VERIFY(dsl_dataset_long_held(zsb->z_os->os_dsl_dataset));
	dmu_objset_rele(zsb->z_os, zsb);

	/*
	 * Make sure version hasn't changed
	 */

	err = zfs_get_zplprop(zsb->z_os, ZFS_PROP_VERSION,
	    &zsb->z_version);

	if (err)
		goto bail;

	err = zap_lookup(zsb->z_os, MASTER_NODE_OBJ,
	    ZFS_SA_ATTRS, 8, 1, &sa_obj);

	if (err && zsb->z_version >= ZPL_VERSION_SA)
		goto bail;

	if ((err = sa_setup(zsb->z_os, sa_obj,
	    zfs_attr_table,  ZPL_END, &zsb->z_attr_table)) != 0)
		goto bail;

	if (zsb->z_version >= ZPL_VERSION_SA)
		sa_register_update_callback(zsb->z_os,
		    zfs_sa_upgrade);

	VERIFY(zfs_sb_setup(zsb, B_FALSE) == 0);

	zfs_set_fuid_feature(zsb);
	zsb->z_rollback_time = jiffies;

	/*
	 * Attempt to re-establish all the active inodes with their
	 * dbufs.  If a zfs_rezget() fails, then we unhash the inode
	 * and mark it stale.  This prevents a collision if a new
	 * inode/object is created which must use the same inode
	 * number.  The stale inode will be be released when the
	 * VFS prunes the dentry holding the remaining references
	 * on the stale inode.
	 */
	mutex_enter(&zsb->z_znodes_lock);
	for (zp = list_head(&zsb->z_all_znodes); zp;
	    zp = list_next(&zsb->z_all_znodes, zp)) {
		err2 = zfs_rezget(zp);
		if (err2) {
			remove_inode_hash(ZTOI(zp));
			zp->z_is_stale = B_TRUE;
		}
	}
	mutex_exit(&zsb->z_znodes_lock);

bail:
	/* release the VFS ops */
	rw_exit(&zsb->z_teardown_inactive_lock);
	rrm_exit(&zsb->z_teardown_lock, FTAG);

	if (err) {
		/*
		 * Since we couldn't setup the sa framework, try to force
		 * unmount this file system.
		 */
		if (zsb->z_os)
			(void) zfs_umount(zsb->z_sb);
	}
	return (err);
}
EXPORT_SYMBOL(zfs_resume_fs);

int
zfs_set_version(zfs_sb_t *zsb, uint64_t newvers)
{
	int error;
	objset_t *os = zsb->z_os;
	dmu_tx_t *tx;

	if (newvers < ZPL_VERSION_INITIAL || newvers > ZPL_VERSION)
		return (SET_ERROR(EINVAL));

	if (newvers < zsb->z_version)
		return (SET_ERROR(EINVAL));

	if (zfs_spa_version_map(newvers) >
	    spa_version(dmu_objset_spa(zsb->z_os)))
		return (SET_ERROR(ENOTSUP));

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, B_FALSE, ZPL_VERSION_STR);
	if (newvers >= ZPL_VERSION_SA && !zsb->z_use_sa) {
		dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, B_TRUE,
		    ZFS_SA_ATTRS);
		dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, FALSE, NULL);
	}
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}

	error = zap_update(os, MASTER_NODE_OBJ, ZPL_VERSION_STR,
	    8, 1, &newvers, tx);

	if (error) {
		dmu_tx_commit(tx);
		return (error);
	}

	if (newvers >= ZPL_VERSION_SA && !zsb->z_use_sa) {
		uint64_t sa_obj;

		ASSERT3U(spa_version(dmu_objset_spa(zsb->z_os)), >=,
		    SPA_VERSION_SA);
		sa_obj = zap_create(os, DMU_OT_SA_MASTER_NODE,
		    DMU_OT_NONE, 0, tx);

		error = zap_add(os, MASTER_NODE_OBJ,
		    ZFS_SA_ATTRS, 8, 1, &sa_obj, tx);
		ASSERT0(error);

		VERIFY(0 == sa_set_sa_object(os, sa_obj));
		sa_register_update_callback(os, zfs_sa_upgrade);
	}

	spa_history_log_internal_ds(dmu_objset_ds(os), "upgrade", tx,
	    "from %llu to %llu", zsb->z_version, newvers);

	dmu_tx_commit(tx);

	zsb->z_version = newvers;

	zfs_set_fuid_feature(zsb);

	return (0);
}
EXPORT_SYMBOL(zfs_set_version);

/*
 * Read a property stored within the master node.
 */
int
zfs_get_zplprop(objset_t *os, zfs_prop_t prop, uint64_t *value)
{
	const char *pname;
	int error = SET_ERROR(ENOENT);

	/*
	 * Look up the file system's value for the property.  For the
	 * version property, we look up a slightly different string.
	 */
	if (prop == ZFS_PROP_VERSION)
		pname = ZPL_VERSION_STR;
	else
		pname = zfs_prop_to_name(prop);

	if (os != NULL)
		error = zap_lookup(os, MASTER_NODE_OBJ, pname, 8, 1, value);

	if (error == ENOENT) {
		/* No value set, use the default value */
		switch (prop) {
		case ZFS_PROP_VERSION:
			*value = ZPL_VERSION;
			break;
		case ZFS_PROP_NORMALIZE:
		case ZFS_PROP_UTF8ONLY:
			*value = 0;
			break;
		case ZFS_PROP_CASE:
			*value = ZFS_CASE_SENSITIVE;
			break;
		case ZFS_PROP_ACLTYPE:
			*value = ZFS_ACLTYPE_OFF;
			break;
		default:
			return (error);
		}
		error = 0;
	}
	return (error);
}
EXPORT_SYMBOL(zfs_get_zplprop);

void
zfs_init(void)
{
	zfsctl_init();
	zfs_znode_init();
	dmu_objset_register_type(DMU_OST_ZFS, zfs_space_delta_cb);
	register_filesystem(&zpl_fs_type);
}

void
zfs_fini(void)
{
	/*
	 * we don't use outstanding because zpl_posix_acl_free might add more.
	 */
	taskq_wait(system_taskq);
	unregister_filesystem(&zpl_fs_type);
	zfs_znode_fini();
	zfsctl_fini();
}

zfs_sb_t * 
zfs_sb_group_hold(uint64_t spa_guid, uint64_t objset, void *tag, boolean_t b_check_setting_up)
{
	int err, wait_sec;
//	boolean_t b_hold = B_FALSE;
	spa_t *spa = NULL;
	dsl_pool_t *dp = NULL;
	dsl_dataset_t *dsl_dataset = NULL;
	objset_t *os = NULL;
	zfs_sb_t *zsb = NULL;
	
	mutex_enter(&spa_namespace_lock);
	spa = spa_by_guid(spa_guid, 0);
	if (spa == NULL) {
		mutex_exit(&spa_namespace_lock);
		return (NULL);
	}
		
	dp = spa_get_dsl(spa);
	rrw_enter(&dp->dp_config_rwlock, RW_READER, FTAG);
	err = dsl_dataset_hold_obj(dp, objset, FTAG, &dsl_dataset);
	rrw_exit(&dp->dp_config_rwlock, FTAG);
	if (err != 0)
		cmn_err(CE_WARN, "dsl_dataset_hold_obj errno:%d", err);
	mutex_exit(&spa_namespace_lock);
	if (dsl_dataset == NULL)
		return (NULL);

	err = dmu_objset_from_ds(dsl_dataset, &os);
	if (err != 0)
		cmn_err(CE_WARN, "dmu_objset_from_ds errno:%d", err);	

	if (os == NULL ) {
		cmn_err(CE_WARN, "zfsvfs_group_hold: os == NULL");
		dsl_dataset_rele(dsl_dataset, FTAG);
		return (NULL);
	}

	mutex_enter(&os->os_user_ptr_lock);
	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
	if (zsb == NULL) {
		cmn_err(CE_WARN, "zfsvfs_group_hold: zfsvfs->z_mounted = false!");
		mutex_exit(&os->os_user_ptr_lock);
		dsl_dataset_rele(dsl_dataset, FTAG);
		return (NULL);
	}
//	VFS_HOLD(zfsvfs->z_vfs);
	atomic_inc_not_zero(&zsb->z_sb->s_active);
	mutex_exit(&os->os_user_ptr_lock);
	wait_sec = 0;
	/*while (b_check_setting_up && zfsvfs->z_is_setting_up) {*/

	if(b_check_setting_up && zsb->z_is_setting_up){
		/*delay(USEC_TO_TICK_ROUNDUP(1000000));
		wait_sec++;
		cmn_err(CE_WARN, "%s, %d, zfsvfs is replaying, wait for %d second!", 
			__func__, __LINE__, wait_sec);*/
		cmn_err(CE_WARN, "zfsvfs_group_hold: zfsvfs->z_is_setting_up");
//		VFS_RELE(zfsvfs->z_vfs);
		deactivate_super(zsb->z_sb);
		dsl_dataset_rele(dsl_dataset, FTAG);
		return (NULL);
	}

	rrm_enter(&zsb->z_teardown_lock, RW_READER, tag);
	if (zsb->z_unmounted) {
		cmn_err(CE_WARN, "zfsvfs_group_hold: zfsvfs->z_unmounted");
		rrm_exit(&zsb->z_teardown_lock, tag);
//		VFS_RELE(zfsvfs->z_vfs);
		deactivate_super(zsb->z_sb);
		dsl_dataset_rele(dsl_dataset, FTAG);
		return (NULL);
	}
	dsl_dataset_rele(dsl_dataset, FTAG);
	return (zsb);
}


void 
zfs_sb_group_rele(zfs_sb_t *zsb,  void *tag)
{
	rrm_exit(&zsb->z_teardown_lock, tag);
//	VFS_RELE(zfsvfs->z_vfs);
	deactivate_super(zsb->z_sb);
}

int zfs_get_dirquota(zfs_sb_t *zsb, uint64_t dir_obj, zfs_dirquota_t *dirquota)
{

	char *buf;
	int error;

	if (zsb->z_os->os_is_group && zsb->z_os->os_is_master == 0)
		return (ENOENT);
	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	sprintf(buf, DIR_QUOTA_FORMAT, zfs_dirquota_prefixex, 
	    (longlong_t)dir_obj);

	error = zap_lookup(zsb->z_os, zsb->z_dirquota_obj, buf, 8, 1, 
	    &dirquota->zq_value);
	if (error != 0) {
		kmem_free(buf, MAXPATHLEN);
		return (error);
	}

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_QUOTA_USED, zfs_dirused_prefixex, 
	    (longlong_t)dir_obj);
	error = zap_lookup(zsb->z_os, zsb->z_dirquota_obj, buf, 8, 1, &dirquota->zq_used);

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_QUOTA_PATH, zfs_dirpath_name_prefixex, 
	    (longlong_t)dir_obj);
	error = zap_lookup(zsb->z_os, zsb->z_dirquota_obj, buf, 1, MAXPATHLEN, 
	    &dirquota->zq_path);

	kmem_free(buf, MAXPATHLEN);
	return (error);

}

int
zfs_fuid_oversoftquota(zfs_sb_t *zsb, boolean_t isgroup, uint64_t fuid)
{
	char buf[32];
	uint64_t used, quota, usedobj, quotaobj;
	int err;
	uint64_t	currenttime;
	uint64_t 	delta;

	usedobj = isgroup ? DMU_GROUPUSED_OBJECT : DMU_USERUSED_OBJECT;
	quotaobj = isgroup ? zsb->z_softgroupquota_obj : zsb->z_softuserquota_obj;

	if (quotaobj == 0 || zsb->z_replay)
		return (SOFTQUOTA_NO);

	(void) sprintf(buf, "%llx", (longlong_t)fuid);
	err = zap_lookup(zsb->z_os, quotaobj, buf, 8, 1, &quota);
	if (err != 0)
		return (SOFTQUOTA_NO);

	err = zap_lookup(zsb->z_os, usedobj, buf, 8, 1, &used);
	if (err != 0)
		return (SOFTQUOTA_NO);

	currenttime = gethrestime_sec();
	delta = currenttime - zsb->z_overquota;
	if (used > quota && zsb->z_overquota == 0) {
		zsb->z_overquota = gethrestime_sec();
		return SOFTQUOTA_OVER;
	} else if (used > quota && delta > SOFTQUOTA_OVER_TIME)
		return SOFTQUOTA_OVER_HARD;

	return (SOFTQUOTA_NO);
}

int
zfs_owner_oversoftquota(zfs_sb_t *zsb, znode_t *zp, boolean_t isgroup)
{
	uint64_t fuid;
	uint64_t quotaobj;

	quotaobj = isgroup ? zsb->z_softgroupquota_obj : zsb->z_softuserquota_obj;

	fuid = isgroup ? zp->z_gid : zp->z_uid;
	if (quotaobj == 0 || zsb->z_replay)
		return (B_FALSE);
	return (zfs_fuid_oversoftquota(zsb, isgroup, fuid));
}

boolean_t zfs_dir_overquota(zfs_sb_t *zsb, znode_t *zp, uint64_t dirquota_index)
{
	boolean_t over_quota = B_FALSE;
	zfs_dirquota_t *dir_quota;
	int err;

	dir_quota = kmem_zalloc(sizeof(zfs_dirquota_t), KM_SLEEP);
	err = zfs_get_dirquota(zsb, dirquota_index, dir_quota);

	if (err != 0 || dir_quota->zq_value > dir_quota->zq_used)
		over_quota = B_FALSE;
	else
		over_quota = B_TRUE;

	kmem_free(dir_quota, sizeof(zfs_dirquota_t));

	return (over_quota);

}

boolean_t zfs_overquota(zfs_sb_t *zsb, znode_t *zp, uint64_t dirquota_index, int flag)
{
	boolean_t bover;

	bover = B_FALSE;
	if (dirquota_index != 0)
		bover = zfs_dir_overquota(zsb, zp, dirquota_index);

	if (!bover) {
		bover = zfs_owner_overquota(zsb, zp, B_TRUE, flag);
	}

	if (!bover) {
		bover = zfs_owner_overquota(zsb, zp, B_FALSE, flag );
	}

	return (bover);
}

int zfs_set_overquota(zfs_sb_t *zsb, uint64_t dir_obj, boolean_t overquota, boolean_t remove, dmu_tx_t *tx_para)
{
	char *buf;
	int err;
	uint64_t *objp;
	dmu_tx_t *tx;
	boolean_t waited = B_FALSE;

	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	objp = &zsb->z_dirquota_obj;

if (!tx_para) {
	top:
		tx = dmu_tx_create(zsb->z_os);
		err = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
		if (err != 0) {
			if (err == ERESTART) {
				waited = B_TRUE;
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto top;
			}
			dmu_tx_abort(tx);
			kmem_free(buf, MAXPATHLEN);
			return (err);
		}
} else {
	tx = tx_para;
}

	dmu_tx_hold_zap(tx, *objp ? *objp : DMU_NEW_OBJECT, B_TRUE, NULL);
	if (*objp == 0) {
		dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, B_TRUE, zfs_dirquota_prefixex);
	}

	mutex_enter(&zsb->z_lock);
	if (*objp == 0) {
		*objp = zap_create(zsb->z_os, DMU_OT_DIRQUOTA,
		    DMU_OT_NONE, 0, tx);
		VERIFY(0 == zap_add(zsb->z_os, MASTER_NODE_OBJ,
		    zfs_dirquota_prefixex, 8, 1, objp, tx));
	}
	mutex_exit(&zsb->z_lock);

	if (dir_obj) {
		sprintf(buf, DIR_OVERQUOTQ_FORMAT, zfs_overquota_prefixex, (longlong_t)dir_obj);
		if (remove) {
			err = zap_remove(zsb->z_os, *objp, buf, tx);	
		} else {
			err = zap_update(zsb->z_os, *objp, buf, sizeof(boolean_t), 1, &overquota, tx);
		}
	}
	if (!tx_para)
		dmu_tx_commit(tx);
	kmem_free(buf, MAXPATHLEN);
	return err;
}

boolean_t zfs_get_overquota(zfs_sb_t *zsb, uint64_t dir_obj)
{
	char *buf;
	int err;
	boolean_t overquota = B_FALSE;

	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	sprintf(buf, DIR_OVERQUOTQ_FORMAT, zfs_overquota_prefixex, (longlong_t)dir_obj);
	err = zap_lookup(zsb->z_os, zsb->z_dirquota_obj, buf, sizeof(boolean_t), 1, &overquota);

	kmem_free(buf, MAXPATHLEN);
	return overquota;
}

void zfs_dir_updatequota(zfs_sb_t *zsb, znode_t *zp, uint64_t update_size,
    uint64_t update_op, dmu_tx_t *tx)
{
	int err;
	uint64_t used;
	uint64_t quota;
	char *buf;

	if (zp->z_dirquota == 0)
		return;

	buf = kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	sprintf(buf, DIR_QUOTA_FORMAT, zfs_dirquota_prefixex, (longlong_t)zp->z_dirquota);
	err = zap_lookup(zsb->z_os, zsb->z_dirquota_obj, buf, 8, 1, &quota);
	if (err != 0) {
		kmem_free(buf, MAXNAMELEN);
		return;
	}
	
	bzero(buf, MAXNAMELEN);
	sprintf(buf, DIR_QUOTA_USED, zfs_dirused_prefixex, 
	    (longlong_t)zp->z_dirquota);
	err = zap_lookup(zsb->z_os, zsb->z_dirquota_obj, buf, 8, 1, &used);
	if (err != 0 && err != ENOENT){
		kmem_free(buf, MAXNAMELEN);
		return;
	}
	if (update_op == EXPAND_SPACE)
		used += update_size;
	else {
	if (used > update_size)
		used -= update_size;
	else
		used = 0;
	}

	zap_update(zsb->z_os, zsb->z_dirquota_obj, buf, 
	    sizeof(uint64_t), 1, &used, tx);
	kmem_free(buf, MAXNAMELEN);
}


void
zfs_fuid_updatequota(zfs_sb_t *zsb, boolean_t isgroup, uint64_t fuid, 
    uint64_t update_size, uint64_t update_op, dmu_tx_t *tx)
{
	char buf[32];
	uint64_t used=0, quota=0, usedobj, quotaobj;
	int err;

	if( update_op == EXPAND_SPACE || update_op == REDUCE_SPACE ) {
		usedobj = isgroup ? DMU_GROUPUSED_OBJECT : DMU_USERUSED_OBJECT;
		quotaobj = isgroup ? zsb->z_groupquota_obj : zsb->z_userquota_obj;
	}else {
		usedobj = isgroup ? DMU_GROUPOBJUSED_OBJECT : DMU_USEROBJUSED_OBJECT;
		quotaobj = isgroup ? zsb->z_groupobjquota_obj : zsb->z_userobjquota_obj;
	}

	if (quotaobj == 0 || zsb->z_replay)
		return ;

	(void) sprintf(buf, "%llx", (longlong_t)fuid);
	err = zap_lookup(zsb->z_os, quotaobj, buf, 8, 1, &quota);
	if (err )
		return;

	err = zap_lookup(zsb->z_os, usedobj, buf, 8, 1, &used);
	if (err && err != ENOENT )
		return ;
	if (update_op == EXPAND_SPACE || update_op == ADD_FILE ) {
		used += update_size;
	} else {
		if (used > update_size)
			used -= update_size;
		else
			used = 0;
	}
	zap_update(zsb->z_os, usedobj, buf, 8, 1, &used, tx);
	
}


int
zfs_del_dirquota(zfs_sb_t *zsb, uint64_t dir_obj)
{
	char *buf;
	int err;
	uint64_t *objp;
	dmu_tx_t *tx;
//	znode_t *zp;
	boolean_t waited = B_FALSE;

	

	if ((zsb->z_os->os_is_group 
		&& zsb->z_os->os_is_master == 0 
		&& zsb->z_os->os_node_type == OS_NODE_TYPE_SLAVE)
		|| zsb->z_dirquota_obj == 0)
		return (EINVAL);

	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	objp = &zsb->z_dirquota_obj;

top:
	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_zap(tx, *objp, B_TRUE, NULL);
	
	err = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (err != 0) {
		if (err == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		kmem_free(buf, MAXPATHLEN);
		return (err);
	}

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_QUOTA_FORMAT, zfs_dirquota_prefixex, (longlong_t)dir_obj);
	zap_remove(zsb->z_os, *objp, buf, tx);
	
	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_QUOTA_USED, zfs_dirused_prefixex, (longlong_t)dir_obj);
	zap_remove(zsb->z_os, *objp, buf, tx);
		
	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_QUOTA_PATH, zfs_dirpath_name_prefixex, (longlong_t)dir_obj);
	zap_remove(zsb->z_os, *objp, buf, tx);
	
	dmu_tx_commit(tx);
	kmem_free(buf, MAXPATHLEN);
	return (err);
}


int
zfs_set_dir_low(zfs_sb_t *zsb, uint64_t dir_obj, char *path, 
    const char *propname, uint64_t new_value, zfs_dirlowdata_t *dir_lowdata)
{
	char *buf;
	int err;
	uint64_t used;
	znode_t *zp;
	dmu_tx_t *tx;
	uint64_t *objp;
	boolean_t fuid_dirtied;
	boolean_t waited = B_FALSE;
	int namesize = 0;
	zfs_group_dtl_carrier_t*	z_carrier = NULL;
	zfs_group_dtl_data_t*	ss_data = NULL;
	zfs_group_dirlow_t *z_dirlow = NULL;

	tx = NULL;
	objp = NULL;
	fuid_dirtied = B_FALSE;
	err = 0;
	used = 0;

	if (zsb->z_os->os_is_group && 
		zsb->z_os->os_is_master == 0 && 
		zsb->z_os->os_node_type == OS_NODE_TYPE_SLAVE){ 
		return (EINVAL); 
	} 


	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	objp = &zsb->z_dirlowdata_obj;

	err = zfs_zget(zsb, dir_obj, &zp);
	if (err) {
		kmem_free(buf, MAXPATHLEN);
		return err;
	}

	if (!zfs_dirempty(zp) && (zp->z_dirlowdata !=  dir_obj)) {
		kmem_free(buf, MAXPATHLEN);
		iput(ZTOI(zp));
		return (EINVAL);
	}
top:
	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_zap(tx, *objp ? *objp : DMU_NEW_OBJECT, B_TRUE, NULL);
	if (*objp == 0) {
		dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, B_TRUE,
		    zfs_dirlowdata_prefixex);
	}
	err = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (err != 0) {
		if (err == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		kmem_free(buf, MAXPATHLEN);
		iput(ZTOI(zp));
		dmu_tx_abort(tx);
		return (err);
	}

	mutex_enter(&zsb->z_lock);
	if (*objp == 0) {
		*objp = zap_create(zsb->z_os, DMU_OT_DIRLOWDATA,
		    DMU_OT_NONE, 0, tx);
		err = zap_add(zsb->z_os, MASTER_NODE_OBJ,zfs_dirlowdata_prefixex, 8, 1, objp, tx);
		if (err != 0){
			mutex_exit(&zsb->z_lock);
			goto end;
		}
	}
	mutex_exit(&zsb->z_lock);

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_FORMAT, zfs_dirlowdata_prefixex, (longlong_t)dir_obj);
	err = zap_update(zsb->z_os, *objp, buf, 8, 1, &dir_lowdata->lowdata, tx);
	if (err != 0) {
		goto end;
	}
			
	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_PERIOD_FORMAT, zfs_dirlowdata_period_prefixex, (longlong_t)dir_obj);
	err = zap_update(zsb->z_os, *objp, buf, 8, 1, &dir_lowdata->lowdata_period, tx);
	if (err != 0) {
		goto end;
	}

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_DELETE_PERIOD_FORMAT, zfs_dirlowdata_delete_period_prefixex, (longlong_t)dir_obj);
	err = zap_update(zsb->z_os, *objp, buf, 8, 1, &dir_lowdata->lowdata_delete_period, tx);
	if (err != 0) {
		goto end;
	}

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_PERIOD_UNIT_FORMAT, zfs_dirlowdata_period_unit_prefixex, (longlong_t)dir_obj);
	err = zap_update(zsb->z_os, *objp, buf, 8, 1, &dir_lowdata->lowdata_period_unit, tx);
	if (err != 0) {
		goto end;
	}

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_CRITERIA_FORMAT, zfs_dirlowdata_criteria_prefixex, (longlong_t)dir_obj);
	err = zap_update(zsb->z_os, *objp, buf, 8, 1, &dir_lowdata->lowdata_criteria, tx);
	if (err != 0) {
		goto end;
	}

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_PATH_FORMAT, zfs_dirlowdata_path_prefixex, (longlong_t)dir_obj);
	err = zap_update(zsb->z_os, *objp, buf, 1, strlen(path), path, tx);
	if (err != 0) {
		goto end;
	}
	mutex_enter(&zp->z_lock);
	zfs_sa_set_dirlowdata(zp, dir_obj, tx);
	mutex_exit(&zp->z_lock);
	
end:	
	dmu_tx_commit(tx);
	kmem_free(buf, MAXPATHLEN);
	if(0 == err && zsb->z_os->os_is_group && zsb->z_os->os_is_master){
		z_dirlow = kmem_zalloc(sizeof(zfs_group_dirlow_t), KM_SLEEP);
		z_dirlow->dir_obj = dir_obj;
		z_dirlow->value = new_value;
		namesize = MIN(strlen(path), MAXPATHLEN-1);
		if (namesize > 0) {
			bcopy(path+strlen(path)	- namesize, z_dirlow->path, namesize);
			z_dirlow->path[namesize] = '\0';
		}
		namesize = 0;
		if(propname != NULL){
			namesize = MIN(strlen(propname), MAXNAMELEN-1);
		}
		if (namesize > 0) {
			bcopy(propname+strlen(propname)-namesize, z_dirlow->propname, namesize);
			z_dirlow->propname[namesize] = '\0';
		}
		z_carrier = zfs_group_dtl_carry(NAME_DIRLOWDATA, zp, NULL, NULL, 0,
			0, z_dirlow, NULL, 0, NULL, NULL);
		kmem_free(z_dirlow, sizeof(zfs_group_dirlow_t));
		if(z_carrier){
			ss_data = kmem_alloc(sizeof(zfs_group_dtl_data_t), KM_SLEEP);
			ss_data->obj = zp->z_id;
			ss_data->data_size = sizeof(zfs_group_dtl_carrier_t);
			bcopy(z_carrier, ss_data->data, sizeof(zfs_group_dtl_carrier_t));
			mutex_enter(&zsb->z_group_dtl_tree2_mutex);
			gethrestime(&ss_data->gentime);
			zfs_group_dtl_add(&zsb->z_group_dtl_tree2, ss_data, sizeof(zfs_group_dtl_data_t));
			mutex_exit(&zsb->z_group_dtl_tree2_mutex);
			kmem_free(z_carrier, sizeof(zfs_group_dtl_carrier_t));
			kmem_free(ss_data, sizeof(zfs_group_dtl_data_t));
		}
	}
	iput(ZTOI(zp));
	return (err);
}


int zfs_get_dir_low(zfs_sb_t *zsb, uint64_t dir_obj, zfs_dirlowdata_t *dir_lowdata)
{
	
	char *buf;
	int error;
	
	if (zsb->z_os->os_is_group && 
		zsb->z_os->os_is_master == 0 && 
		zsb->z_os->os_node_type == OS_NODE_TYPE_SLAVE){ 
		return (EINVAL); 
	} 

	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	sprintf(buf, DIR_LOWDATA_FORMAT, zfs_dirlowdata_prefixex, (longlong_t)dir_obj);
		
	error = zap_lookup(zsb->z_os, zsb->z_dirlowdata_obj, buf, 8, 1, 
	    &dir_lowdata->lowdata);
	if (error != 0) {
		goto end;
	}
	
	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_PERIOD_FORMAT, zfs_dirlowdata_period_prefixex, (longlong_t)dir_obj);
	error = zap_lookup(zsb->z_os, zsb->z_dirlowdata_obj, buf, 8, 1, 
			    &dir_lowdata->lowdata_period);
	if (error != 0) {
		goto end;
	}

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_DELETE_PERIOD_FORMAT, zfs_dirlowdata_delete_period_prefixex, (longlong_t)dir_obj);
	error = zap_lookup(zsb->z_os, zsb->z_dirlowdata_obj, buf, 8, 1, 
			    &dir_lowdata->lowdata_delete_period);
	if (error != 0) {
		goto end;
	}

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_PERIOD_UNIT_FORMAT, zfs_dirlowdata_period_unit_prefixex, (longlong_t)dir_obj);
	error = zap_lookup(zsb->z_os, zsb->z_dirlowdata_obj, buf, 8, 1, 
			    &dir_lowdata->lowdata_period_unit);
	if (error != 0) {
		goto end;
	}

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_CRITERIA_FORMAT, zfs_dirlowdata_criteria_prefixex, (longlong_t)dir_obj);
	error = zap_lookup(zsb->z_os, zsb->z_dirlowdata_obj, buf, 8, 1, 
			    &dir_lowdata->lowdata_criteria);
	if (error != 0) {
		goto end;
	}
	
	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_PATH_FORMAT, zfs_dirlowdata_path_prefixex, (longlong_t)dir_obj);
	error = zap_lookup(zsb->z_os, zsb->z_dirlowdata_obj, buf, 1, MAXPATHLEN, 
			    &dir_lowdata->lowdata_path);

end:
	kmem_free(buf, MAXPATHLEN);
	return (error);
}


int zfs_get_dir_lowdata_many(zfs_sb_t *zsb,  uint64_t *cookiep,
    void *vbuf, uint64_t *bufsizep)
{
	int error;
	uint64_t object;
	char *object_char;
	char *endp;
	objset_t *os;
	zap_cursor_t zc;
	char *key;
	zap_attribute_t za;
//	uint64_t used;
	zfs_dirlowdata_t *buf = vbuf;
	uint64_t obj;
	void *prop;


	key = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	obj = zsb->z_dirlowdata_obj;
	os = zsb->z_os;

	for (zap_cursor_init_serialized(&zc, os, obj, *cookiep);
		(error = zap_cursor_retrieve(&zc, &za)) == 0;
		zap_cursor_advance(&zc)) {


		if ((uintptr_t)buf - (uintptr_t)vbuf >=
		    *bufsizep)
			break;

		prop = kmem_zalloc(za.za_num_integers *
				za.za_integer_length, KM_NOSLEEP);

		(void) zap_lookup(os, obj, za.za_name,
				za.za_integer_length, za.za_num_integers, prop);


		if (strncmp(za.za_name, zfs_dirlowdata_prefixex, 
		    strlen(zfs_dirlowdata_prefixex)) == 0){
		    
			object_char = strchr(za.za_name, '@') + 1;
			object = strtonum(object_char, &endp);
			
			if (zsb->z_os->os_is_group && zsb->z_os->os_is_master == 0) {
				znode_t *zp = NULL;
				error = zfs_zget(zsb, object, &zp);
				if (error != 0) {
					kmem_free(prop, za.za_num_integers * za.za_integer_length);
					continue;
				}
				error = zfs_client_get_dirlowdata(zsb, zp, buf);
				iput(ZTOI(zp));
			} else {
				error = zfs_get_dir_low(zsb, object, buf);			
			}

			if (error != 0) {
				bzero(buf, sizeof(zfs_dirlowdata_t));
			}
			buf ++;
		}

		kmem_free(prop, za.za_num_integers * za.za_integer_length);
	}
	if (error == ENOENT)
		error = 0;

	kmem_free(key, MAXPATHLEN);
	ASSERT3U((uintptr_t)buf - (uintptr_t)vbuf, <=, *bufsizep);
	*bufsizep = (uintptr_t)buf - (uintptr_t)vbuf;
	*cookiep = zap_cursor_serialize(&zc);
	zap_cursor_fini(&zc);
	return (error);
}


int
zfs_set_dir_quota(zfs_sb_t *zsb, uint64_t dir_obj, char *path, 
    uint64_t quota)
{
	char *buf;
	int err;
	uint64_t used;
	znode_t *zp;
	dmu_tx_t *tx;
	uint64_t *objp;
	boolean_t fuid_dirtied;
	boolean_t waited = B_FALSE;
	zfs_group_dtl_carrier_t*	z_carrier = NULL;
	zfs_group_dtl_data_t*	ss_data = NULL;
	boolean_t bover = B_FALSE;
	uint64_t old_dirquota_id = 0;

	tx = NULL;
	objp = NULL;
	fuid_dirtied = B_FALSE;
	err = 0;
	used = 0;

	if (zsb->z_os->os_is_group && 
		zsb->z_os->os_is_master == 0 && 
		zsb->z_os->os_node_type == OS_NODE_TYPE_SLAVE)
		return (EINVAL);

	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	objp = &zsb->z_dirquota_obj;
top:
	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_zap(tx, *objp ? *objp : DMU_NEW_OBJECT, B_TRUE, NULL);
	if (*objp == 0) {
		dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, B_TRUE,
		    zfs_dirquota_prefixex);
	}
	err = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (err != 0) {
		if (err == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		kmem_free(buf, MAXPATHLEN);
		return (err);
	}

	mutex_enter(&zsb->z_lock);
	if (*objp == 0) {
		*objp = zap_create(zsb->z_os, DMU_OT_DIRQUOTA,
		    DMU_OT_NONE, 0, tx);
		VERIFY(0 == zap_add(zsb->z_os, MASTER_NODE_OBJ,
		    zfs_dirquota_prefixex, 8, 1, objp, tx));
	}
	mutex_exit(&zsb->z_lock);

	if (quota == 0) {
		sprintf(buf, DIR_QUOTA_FORMAT, zfs_dirquota_prefixex, (longlong_t)dir_obj);
		err = zap_remove(zsb->z_os, *objp, buf, tx);
		if (err != 0) {
			err = (err == ENOENT) ? 0 : err;

			goto end;
		}
		bzero(buf, MAXPATHLEN);
		sprintf(buf, DIR_QUOTA_USED, zfs_dirused_prefixex, (longlong_t)dir_obj);
		err = zap_remove(zsb->z_os, *objp, buf, tx);
		if (err != 0) {
			err = (err == ENOENT) ? 0 : err;
			goto end;
		}

		bzero(buf, MAXPATHLEN);
		sprintf(buf, DIR_QUOTA_PATH, zfs_dirpath_name_prefixex, (longlong_t)dir_obj);
		err = zap_remove(zsb->z_os, *objp, buf, tx);

		err = zfs_zget(zsb, dir_obj, &zp);
		if (err) {
			goto end;
		}
		old_dirquota_id = zp->z_dirquota;
		mutex_enter(&zp->z_lock);
		zfs_sa_set_dirquota(zp, 0, tx);
		mutex_exit(&zp->z_lock);
	} else {
		used = 0;

		err = zfs_zget(zsb, dir_obj, &zp);
		if (err) {
			goto end;
		}

		sprintf(buf, DIR_QUOTA_FORMAT, zfs_dirquota_prefixex, (longlong_t)dir_obj);
		err = zap_update(zsb->z_os, *objp, buf, 8, 1, &quota, tx);
		if (err != 0) {
			iput(ZTOI(zp));
			goto end;
		}
		bzero(buf, MAXPATHLEN);
		sprintf(buf, DIR_QUOTA_PATH, zfs_dirpath_name_prefixex, (longlong_t)dir_obj);
		err = zap_update(zsb->z_os, *objp, buf, 1, strlen(path), path, tx);


		bzero(buf, MAXPATHLEN);
		sprintf(buf, DIR_QUOTA_USED, zfs_dirused_prefixex, (longlong_t)dir_obj);

		err = zap_lookup(zsb->z_os, *objp,
		    buf, 8, 1, &used);
		if (err == ENOENT) {
			used = 0;
			err = zap_update(zsb->z_os, *objp, buf, 8, 1, &used, tx);
		}

		old_dirquota_id = zp->z_dirquota;
		mutex_enter(&zp->z_lock);
		zfs_sa_set_dirquota(zp, dir_obj, tx);
		mutex_exit(&zp->z_lock);
		
		bover = zfs_write_overquota(zsb, zp);
		zfs_set_overquota(zsb, zp->z_dirquota, bover, B_FALSE, NULL);
	}
	zfs_group_broadcast_unflag_overquota(zp, old_dirquota_id);
end:
	dmu_tx_commit(tx);
	kmem_free(buf, MAXPATHLEN);
	if(0 == err && zsb->z_os->os_is_group && zsb->z_os->os_is_master){
		z_carrier = zfs_group_dtl_carry(NAME_DIRQUOTA, zp, path, NULL, 0,
			0, &dir_obj, NULL, 0, NULL, &quota);
		if(z_carrier){
			ss_data = kmem_alloc(sizeof(zfs_group_dtl_data_t), KM_SLEEP);
			ss_data->obj = zp->z_id;
			ss_data->data_size = sizeof(zfs_group_dtl_carrier_t);
			bcopy(z_carrier, ss_data->data, sizeof(zfs_group_dtl_carrier_t));
			mutex_enter(&zsb->z_group_dtl_tree2_mutex);
			gethrestime(&ss_data->gentime);
			zfs_group_dtl_add(&zsb->z_group_dtl_tree2, ss_data, sizeof(zfs_group_dtl_data_t));
			mutex_exit(&zsb->z_group_dtl_tree2_mutex);
			kmem_free(z_carrier, sizeof(zfs_group_dtl_carrier_t));
			kmem_free(ss_data, sizeof(zfs_group_dtl_data_t));
		}
		iput(ZTOI(zp));
	}else if(0 == err){
		iput(ZTOI(zp));
	}
	return (err);
}

int
zfs_get_dir_qutoa_many(zfs_sb_t *zsb,  uint64_t *cookiep, 
    void *vbuf, uint64_t *bufsizep)
{
	int error;
	uint64_t object;
	char *object_char;
	char *endp;
	objset_t *os;
	zap_cursor_t zc;
	char *key;
	zap_attribute_t za;
//	uint64_t used;
	zfs_dirquota_t *buf = vbuf;
	uint64_t obj;
	void *prop;


	if (zsb->z_os->os_is_group && zsb->z_os->os_is_master == 0)
		return (ENOENT);

	key = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	obj = zsb->z_dirquota_obj;
	os = zsb->z_os;

	for (zap_cursor_init_serialized(&zc, os, obj, *cookiep);
		(error = zap_cursor_retrieve(&zc, &za)) == 0;
		zap_cursor_advance(&zc)) {

		if ((uintptr_t)buf - (uintptr_t)vbuf >=
		    *bufsizep)
			break;

		prop = kmem_zalloc(za.za_num_integers *
				za.za_integer_length, KM_NOSLEEP);

		(void) zap_lookup(os, obj, za.za_name,
				za.za_integer_length, za.za_num_integers, prop);


		if (strncmp(za.za_name, zfs_dirquota_prefixex, 
		    strlen(zfs_dirquota_prefixex)) == 0){

			object_char = strchr(za.za_name, '@') + 1;
			object = strtonum(object_char, &endp);

			bzero(key, MAXPATHLEN);
			sprintf(key, DIR_QUOTA_USED, zfs_dirused_prefixex, (longlong_t)object);
			zap_lookup(os, obj,key, 8, 1, &buf->zq_used); 

			bzero(key, MAXPATHLEN);
			sprintf(key, DIR_QUOTA_PATH, zfs_dirpath_name_prefixex, (longlong_t)object);
			error = zap_lookup(os, obj, key, 1, MAXPATHLEN, buf->zq_path);
			if (error != 0) {
				bzero(buf->zq_path, MAXPATHLEN);
			}

			buf->zq_value = (uint64_t)(*(uint64_t *)prop);
			buf ++;
		}

		kmem_free(prop, za.za_num_integers * za.za_integer_length);
	}
	if (error == ENOENT)
		error = 0;

	kmem_free(key, MAXPATHLEN);
	ASSERT3U((uintptr_t)buf - (uintptr_t)vbuf, <=, *bufsizep);
	*bufsizep = (uintptr_t)buf - (uintptr_t)vbuf;
	*cookiep = zap_cursor_serialize(&zc);
	zap_cursor_fini(&zc);
	return (error);
}


int
zfs_del_dirlowdata(zfs_sb_t *zsb, uint64_t dir_obj)
{
	char *buf;
	int err;
	uint64_t *objp;
	dmu_tx_t *tx;
//	znode_t *zp;
	boolean_t waited = B_FALSE;

	

	if ((zsb->z_os->os_is_group 
		&& zsb->z_os->os_is_master == 0 
		&& zsb->z_os->os_node_type == OS_NODE_TYPE_SLAVE)
		|| zsb->z_dirlowdata_obj == 0)
		return (EINVAL);

	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	objp = &zsb->z_dirlowdata_obj;

top:
	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_zap(tx, *objp, B_TRUE, NULL);

	err = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (err != 0) {
		if (err == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		kmem_free(buf, MAXPATHLEN);
		return (err);
	}

	sprintf(buf, DIR_LOWDATA_FORMAT, zfs_dirlowdata_prefixex, (longlong_t)dir_obj);
	err = zap_remove(zsb->z_os, *objp, buf, tx);
	if (err != 0) {
		goto end;
	}
	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_PERIOD_FORMAT, zfs_dirlowdata_period_prefixex, (longlong_t)dir_obj);
	err = zap_remove(zsb->z_os, *objp, buf, tx);
	if (err != 0) {
		goto end;
	}
	
	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_PERIOD_UNIT_FORMAT, zfs_dirlowdata_period_unit_prefixex, (longlong_t)dir_obj);
	err = zap_remove(zsb->z_os, *objp, buf, tx);
	if (err != 0) {
		goto end;
	}

	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_DELETE_PERIOD_FORMAT, zfs_dirlowdata_delete_period_prefixex, (longlong_t)dir_obj);
	err = zap_remove(zsb->z_os, *objp, buf, tx);
	if (err != 0) {
		goto end;
	}
	
	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_CRITERIA_FORMAT, zfs_dirlowdata_criteria_prefixex, (longlong_t)dir_obj);
	err = zap_remove(zsb->z_os, *objp, buf, tx);
	if (err != 0) {
		goto end;
	}
	
	bzero(buf, MAXPATHLEN);
	sprintf(buf, DIR_LOWDATA_PATH_FORMAT, zfs_dirlowdata_path_prefixex, (longlong_t)dir_obj);
	err = zap_remove(zsb->z_os, *objp, buf, tx);
	if (err != 0) {
		goto end;
	}
	
end:
	dmu_tx_commit(tx);
	kmem_free(buf, MAXPATHLEN);
	return (err);
}

