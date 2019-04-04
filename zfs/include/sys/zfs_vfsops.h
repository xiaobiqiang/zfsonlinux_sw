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

#ifndef	_SYS_FS_ZFS_VFSOPS_H
#define	_SYS_FS_ZFS_VFSOPS_H

#include <sys/isa_defs.h>
#include <sys/types32.h>
#include <sys/list.h>
#include <sys/vfs.h>
#include <sys/zil.h>
#include <sys/sa.h>
#include <sys/rrwlock.h>
#include <sys/zfs_ioctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct zfs_sb;
struct znode;

#define DIR_OVERQUOTQ_FORMAT "%s%llx"

#define DIR_QUOTA_FORMAT	"%s%llx"
#define DIR_QUOTA_USED		"%s%llx" 
#define DIR_QUOTA_PATH		"%s%llx" 

#define DIR_LOWDATA_FORMAT	"%s%llx"
#define DIR_LOWDATA_PERIOD_FORMAT	"%s%llx"
#define DIR_LOWDATA_DELETE_PERIOD_FORMAT	"%s%llx"
#define DIR_LOWDATA_PERIOD_UNIT_FORMAT	"%s%llx"
#define DIR_LOWDATA_CRITERIA_FORMAT	"%s%llx"
#define DIR_LOWDATA_PATH_FORMAT				"%s%llx"

#define NASGROUP_MAP_NUM	10240

extern const char *zfs_group_fid_map_key_spa_prefix_format;
extern const char *zfs_group_fid_map_key_os_prefix_format;

extern const char *zfs_dirquota_prefixex;
extern const char *zfs_dirused_prefixex;
extern const char *zfs_dirpath_name_prefixex;

extern const char *zfs_dirlowdata_prefixex;
extern const char *zfs_dirlowdata_period_prefixex;
extern const char *zfs_dirlowdata_delete_period_prefixex;
extern const char *zfs_dirlowdata_period_unit_prefixex;
extern const char *zfs_dirlowdata_criteria_prefixex;
extern const char *zfs_dirlowdata_path_prefixex;

typedef struct zfs_mntopts {
	char		*z_osname;	/* Objset name */
	char		*z_mntpoint;	/* Primary mount point */
	uint64_t	z_xattr;
	boolean_t	z_readonly;
	boolean_t	z_do_readonly;
	boolean_t	z_setuid;
	boolean_t	z_do_setuid;
	boolean_t	z_exec;
	boolean_t	z_do_exec;
	boolean_t	z_devices;
	boolean_t	z_do_devices;
	boolean_t	z_do_xattr;
	boolean_t	z_atime;
	boolean_t	z_do_atime;
	boolean_t	z_relatime;
	boolean_t	z_do_relatime;
	boolean_t	z_nbmand;
	boolean_t	z_do_nbmand;
} zfs_mntopts_t;


typedef enum softquota_error {
	SOFTQUOTA_NO = 0,
	SOFTQUOTA_OVER,
	SOFTQUOTA_OVER_HARD,
} softquota_error_t;

#define SOFTQUOTA_OVER_TIME	60*60*24*7 


typedef struct zfs_sb {
	struct super_block *z_sb;	/* generic super_block */
	struct backing_dev_info z_bdi;	/* generic backing dev info */
	struct zfs_sb	*z_parent;	/* parent fs */
	objset_t	*z_os;		/* objset reference */
	zfs_mntopts_t	*z_mntopts;	/* passed mount options */
	uint64_t	z_flags;	/* super_block flags */
	uint64_t	z_root;		/* id of root znode */
	uint64_t	z_unlinkedobj;	/* id of unlinked zapobj */
	uint64_t	z_max_blksz;	/* maximum block size for files */
	uint64_t	z_fuid_obj;	/* fuid table object number */
	uint64_t	z_fuid_size;	/* fuid table size */
	avl_tree_t	z_fuid_idx;	/* fuid tree keyed by index */
	avl_tree_t	z_fuid_domain;	/* fuid tree keyed by domain */
	krwlock_t	z_fuid_lock;	/* fuid lock */
	boolean_t	z_fuid_loaded;	/* fuid tables are loaded */
	boolean_t	z_fuid_dirty;   /* need to sync fuid table ? */
	struct zfs_fuid_info	*z_fuid_replay; /* fuid info for replay */
	zilog_t		*z_log;		/* intent log pointer */
	uint_t		z_acl_inherit;	/* acl inheritance behavior */
	uint_t		z_acl_type;	/* type of ACL usable on this FS */
	zfs_case_t	z_case;		/* case-sense */
	boolean_t	z_utf8;		/* utf8-only */
	int		z_norm;		/* normalization flags */
	boolean_t	z_atime;	/* enable atimes mount option */
	boolean_t	z_relatime;	/* enable relatime mount option */
	boolean_t	z_unmounted;	/* unmounted */
	rrmlock_t	z_teardown_lock;
	krwlock_t	z_teardown_inactive_lock;
	list_t		z_all_znodes;	/* all znodes in the fs */
	uint64_t	z_nr_znodes;	/* number of znodes in the fs */
	unsigned long	z_rollback_time; /* last online rollback time */
	unsigned long	z_snap_defer_time; /* last snapshot unmount deferal */
	kmutex_t	z_znodes_lock;	/* lock for z_all_znodes */
	arc_prune_t	*z_arc_prune;	/* called by ARC to prune caches */
	struct inode	*z_ctldir;	/* .zfs directory inode */
	boolean_t	z_show_ctldir;	/* expose .zfs in the root dir */
	boolean_t	z_issnap;	/* true if this is a snapshot */
	boolean_t	z_vscan;	/* virus scan on/off */
	boolean_t	z_use_fuids;	/* version allows fuids */
	boolean_t	z_replay;	/* set during ZIL replay */
	boolean_t	z_use_sa;	/* version allow system attributes */
	boolean_t	z_xattr_sa;	/* allow xattrs to be stores as SA */
	uint64_t	z_version;	/* ZPL version */
	uint64_t	z_shares_dir;	/* hidden shares dir */
	kmutex_t	z_lock;
	uint64_t	z_replay_eof;	/* New end of file - replay only */
	sa_attr_type_t	*z_attr_table;	/* SA attr mapping->id */
	uint64_t	z_hold_size;	/* znode hold array size */
	avl_tree_t	*z_hold_trees;	/* znode hold trees */
	kmutex_t	*z_hold_locks;	/* znode hold locks */
	
	uint64_t	z_userquota_obj;
	uint64_t	z_softuserquota_obj;
	uint64_t	z_userobjquota_obj ;
	uint64_t	z_groupquota_obj;
	uint64_t	z_softgroupquota_obj;
	uint64_t	z_groupobjquota_obj;
	kmutex_t	z_quota_mutex;   /*to protect userused, groupused, userobjused, groupobjused, dirquota_used*/

	uint64_t	z_overquota;
	uint64_t	z_dirquota_obj;
	uint64_t	z_dirlowdata_obj;
	uint64_t	z_nas_group_obj;
	uint64_t*	z_group_map_objs;

	uint64_t 	z_isworm;
	uint64_t	z_autoworm;
	uint64_t	z_wormrent;

	taskq_t	  *notify_taskq;
	taskq_t	  *overquota_taskq;
	kmutex_t	z_group_dtl_obj_mutex;
	uint64_t	z_group_dtl_obj;
	uint64_t	z_group_dtl_obj_num;
	kmutex_t	z_group_dtl_tree_mutex;
	avl_tree_t	z_group_dtl_tree;
	kmutex_t	z_group_dtl_tree2_mutex;
	avl_tree_t	z_group_dtl_tree2;
	kmutex_t	z_group_dtl_obj3_mutex;
	uint64_t	z_group_dtl_obj3;
	uint64_t	z_group_dtl_obj3_num;
	kmutex_t	z_group_dtl_tree3_mutex;
	avl_tree_t	z_group_dtl_tree3;
	kmutex_t	z_group_dtl_obj4_mutex;
	uint64_t	z_group_dtl_obj4;
	uint64_t	z_group_dtl_obj4_num;
	kmutex_t	z_group_dtl_tree4_mutex;
	avl_tree_t	z_group_dtl_tree4;
	void*		z_group_sync_obj;
	boolean_t	z_is_setting_up;
	zfs_lowdata_type_t	z_lowdata;	/* How to handle low data */
	uint64_t z_lowdata_period;	/* Low data period */
	uint64_t z_lowdata_delete_period;	/* Low data delete period */
	zfs_lowdata_period_unit_t	z_lowdata_period_unit;	/* Low data period unit */
	zfs_lowdata_criteria_t	z_lowdata_criteria;		/* Low data criteria */
	
} zfs_sb_t;

#define	ZFS_SUPER_MAGIC	0x2fc12fc1

#define	ZSB_XATTR	0x0001		/* Enable user xattrs */

/*
 * Allow a maximum number of links.  While ZFS does not internally limit
 * this the inode->i_nlink member is defined as an unsigned int.  To be
 * safe we use 2^31-1 as the limit.
 */
#define	ZFS_LINK_MAX		((1U << 31) - 1U)

/*
 * Normal filesystems (those not under .zfs/snapshot) have a total
 * file ID size limited to 12 bytes (including the length field) due to
 * NFSv2 protocol's limitation of 32 bytes for a filehandle.  For historical
 * reasons, this same limit is being imposed by the Solaris NFSv3 implementation
 * (although the NFSv3 protocol actually permits a maximum of 64 bytes).  It
 * is not possible to expand beyond 12 bytes without abandoning support
 * of NFSv2.
 *
 * For normal filesystems, we partition up the available space as follows:
 *	2 bytes		fid length (required)
 *	6 bytes		object number (48 bits)
 *	4 bytes		generation number (32 bits)
 *
 * We reserve only 48 bits for the object number, as this is the limit
 * currently defined and imposed by the DMU.
 */
typedef struct zfid_short {
	uint16_t	zf_len;
	uint8_t		zf_object[6];		/* obj[i] = obj >> (8 * i) */
	uint8_t		zf_gen[4];		/* gen[i] = gen >> (8 * i) */
} zfid_short_t;

/*
 * Filesystems under .zfs/snapshot have a total file ID size of 22 bytes
 * (including the length field).  This makes files under .zfs/snapshot
 * accessible by NFSv3 and NFSv4, but not NFSv2.
 *
 * For files under .zfs/snapshot, we partition up the available space
 * as follows:
 *	2 bytes		fid length (required)
 *	6 bytes		object number (48 bits)
 *	4 bytes		generation number (32 bits)
 *	6 bytes		objset id (48 bits)
 *	4 bytes		currently just zero (32 bits)
 *
 * We reserve only 48 bits for the object number and objset id, as these are
 * the limits currently defined and imposed by the DMU.
 */
typedef struct zfid_long {
	zfid_short_t	z_fid;
	uint8_t		zf_setid[6];		/* obj[i] = obj >> (8 * i) */
	uint8_t		zf_dirquota[4];		  /* gen[i] = gen >> (8 * i) */
	uint8_t		zf_dirlowdata[4];
	uint8_t		zf_loadbalance;
} zfid_long_t;

#define	SHORT_FID_LEN	(sizeof (zfid_short_t) - sizeof (uint16_t))
#define	LONG_FID_LEN	(sizeof (zfid_long_t) - sizeof (uint16_t))

extern uint_t zfs_fsyncer_key;

extern int zfs_suspend_fs(zfs_sb_t *zsb);
extern int zfs_resume_fs(zfs_sb_t *zsb, const char *osname);
extern int zfs_userspace_one(zfs_sb_t *zsb, zfs_userquota_prop_t type,
    const char *domain, uint64_t rid, uint64_t *valuep);
extern int zfs_userspace_many(zfs_sb_t *zsb, zfs_userquota_prop_t type,
    uint64_t *cookiep, void *vbuf, uint64_t *bufsizep);
extern int zfs_set_userquota(zfs_sb_t *zsb, zfs_userquota_prop_t type,
    const char *domain, uint64_t rid, uint64_t quota);
extern boolean_t zfs_owner_overquota(zfs_sb_t *zsb, struct znode *,
    boolean_t isgroup, int flag);
extern boolean_t zfs_fuid_overquota(zfs_sb_t *zsb, boolean_t isgroup,
    uint64_t fuid, int flag);
extern int zfs_set_version(zfs_sb_t *zsb, uint64_t newvers);
extern int zfs_get_zplprop(objset_t *os, zfs_prop_t prop,
    uint64_t *value);
extern zfs_mntopts_t *zfs_mntopts_alloc(void);
extern void zfs_mntopts_free(zfs_mntopts_t *zmo);
extern int zfs_sb_create(const char *name, zfs_mntopts_t *zmo,
    zfs_sb_t **zsbp);
extern int zfs_sb_setup(zfs_sb_t *zsb, boolean_t mounting);
extern void zfs_sb_free(zfs_sb_t *zsb);
extern int zfs_sb_prune(struct super_block *sb, unsigned long nr_to_scan,
    int *objects);
extern int zfs_sb_teardown(zfs_sb_t *zsb, boolean_t unmounting);
extern int zfs_check_global_label(const char *dsname, const char *hexsl);
extern boolean_t zfs_is_readonly(zfs_sb_t *zsb);

extern int zfs_register_callbacks(zfs_sb_t *zsb);
extern void zfs_unregister_callbacks(zfs_sb_t *zsb);
extern int zfs_domount(struct super_block *sb, zfs_mntopts_t *zmo, int silent);
extern void zfs_preumount(struct super_block *sb);
extern int zfs_umount(struct super_block *sb);
extern int zfs_remount(struct super_block *sb, int *flags, zfs_mntopts_t *zmo);
extern int zfs_root(zfs_sb_t *zsb, struct inode **ipp);
extern int zfs_statvfs(struct dentry *dentry, struct kstatfs *statp);
extern int zfs_vget(struct super_block *sb, struct inode **ipp, fid_t *fidp);
extern int zfs_replay_rawdata(objset_t *os, char *data, uint64_t object,
    uint64_t offset, uint64_t length);


extern zfs_sb_t * zfs_sb_group_hold(uint64_t spa_guid, uint64_t objset, void *tag, boolean_t b_check_setting_up); 
extern void zfs_sb_group_rele(zfs_sb_t *zsb,  void *tag);

extern int zfs_set_overquota(zfs_sb_t *zsb, uint64_t dir_obj, boolean_t overquota, boolean_t remove, dmu_tx_t *tx_para);
extern int zfs_set_dir_quota(zfs_sb_t *zsb, uint64_t dir_obj, char *path, uint64_t quota);
extern boolean_t zfs_get_overquota(zfs_sb_t *zsb, uint64_t dir_obj);

extern int zfs_owner_oversoftquota(zfs_sb_t *zsb, struct znode *zp, boolean_t isgroup);
extern int zfs_get_dirquota(zfs_sb_t *zsb, uint64_t dir_obj, zfs_dirquota_t *dirquota);
extern int zfs_get_dir_qutoa_many(zfs_sb_t *zsb,  uint64_t *cookiep, void *vbuf, uint64_t *bufsizep);
extern void zfs_dir_updatequota(zfs_sb_t *zsb, struct znode *zp, uint64_t update_size,
    uint64_t update_op, dmu_tx_t *tx);
extern void zfs_fuid_updatequota(zfs_sb_t *zsb, boolean_t isgroup, uint64_t fuid, 
    uint64_t update_size, uint64_t update_op, dmu_tx_t *tx);

extern int zfs_del_dirquota(zfs_sb_t *zsb, uint64_t dir_obj);
extern int zfs_set_dir_low(zfs_sb_t *zsb, uint64_t dir_obj, char *path, 
    const char *propname, uint64_t new_value, zfs_dirlowdata_t *dir_lowdata);
extern int zfs_get_dir_low(zfs_sb_t *zsb, uint64_t dir_obj, zfs_dirlowdata_t *dir_lowdata);
extern int zfs_get_dir_lowdata_many(zfs_sb_t *zsb,  uint64_t *cookiep, void *vbuf, uint64_t *bufsizep);
extern int zfs_del_dirlowdata(zfs_sb_t *zsb, uint64_t dir_obj);
extern boolean_t zfs_overquota(zfs_sb_t *zsb, struct znode *zp, uint64_t dirquota_index, int flag);

extern int zfs_fuid_inquota(zfs_sb_t *zsb, boolean_t isgroup, uint64_t fuid);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_ZFS_VFSOPS_H */
