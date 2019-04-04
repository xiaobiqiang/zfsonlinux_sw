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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 * Copyright (c) 2013 Steven Hartland. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef	_LIBZFS_H
#define	_LIBZFS_H

#include <assert.h>
#include <libnvpair.h>
#include <sys/mnttab.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/fs/zfs.h>
#include <sys/avl.h>
#include <ucred.h>
#include <libzfs_core.h>
#include <sys/vtoc.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Miscellaneous ZFS constants
 */
#define	ZFS_MAXNAMELEN		MAXNAMELEN
#define	ZPOOL_MAXNAMELEN	MAXNAMELEN
#define	ZFS_MAXPROPLEN		MAXPATHLEN
#define	ZPOOL_MAXPROPLEN	MAXPATHLEN

/*
 * Default device paths
 */
#define	DISK_ROOT		"/dev"
#define	UDISK_ROOT		"/dev/disk"

/*
 * Default wait time for a device name to be created.
 */
#define	DISK_LABEL_WAIT		(30 * 1000)  /* 30 seconds */

#define	DEFAULT_IMPORT_PATH_SIZE	7
#define MAX_ID_BYTE 8
extern char *zpool_default_import_path[DEFAULT_IMPORT_PATH_SIZE];


/* solaris stamp write */
#define STAMP_OFFSET		2
#define ZPOOL_INIT_PROGRESS	0x0
#define ZPOOL_ON_PROGRESS	0x1
#define ZPOOL_NO_PROGRESS	0x2
#define ZPOOL_MAGIC			0xbabecafe
#define COMPANY_NAME		0x12345678
#define	VDEV_PAD_SIZE		(8 << 10)
#define	ZPOOL_STAMP_SIZE	(VDEV_PAD_SIZE / 2)

#define	GROUP_NODE_NUM		32
#define	ZFS_NAME_LEN			256

typedef struct zfs_group_sync_param
{
	boolean_t	check_only;
	boolean_t	stop_sync;
	boolean_t	all_member_online;
	boolean_t  	double_data;
	char		*output_file;
	char		*target_dir;
} zfs_grp_sync_param_t;

typedef struct zpool_stamp_para {
	uint32_t pool_magic;
	uint32_t pool_real_owener;
	uint32_t pool_current_owener;
	uint32_t pool_progress[2];
	uint32_t pool_checksum;
	uint32_t company_name;
}zpool_stamp_para_t;
typedef struct zpool_stamp {
	zpool_stamp_para_t 	para;
	uint8_t	reserved[ZPOOL_STAMP_SIZE - sizeof (zpool_stamp_para_t)];
} zpool_stamp_t;

/* solaris stamp write end */


typedef struct zfs_rpc_arg {
	uint_t	flag;
	uint_t	bufcnt;	/* param counter */
	uint_t	backoffset;
	uint_t	filelen;
	char		*filebuf;
	char		*propname;
	char		*value;
	char		*buf[ZFS_NAME_LEN];	 /* param pointer */
}zfs_rpc_arg_t;

typedef struct zfs_rpc_ret {
	uint_t	flag;
	uint_t	backlen;
	char		*backbuf;
}zfs_rpc_ret_t;

#define	RPC_DISK_CNT_MAX	(RPC_SEND_RECV_SIZE/sizeof (zfs_rpc_lun_t))


/*
 * libzfs errors
 */
typedef enum zfs_error {
	EZFS_SUCCESS = 0,	/* no error -- success */
	EZFS_NOMEM = 2000,	/* out of memory */
	EZFS_BADPROP,		/* invalid property value */
	EZFS_PROPREADONLY,	/* cannot set readonly property */
	EZFS_PROPTYPE,		/* property does not apply to dataset type */
	EZFS_PROPNONINHERIT,	/* property is not inheritable */
	EZFS_PROPSPACE,		/* bad quota or reservation */
	EZFS_BADTYPE,		/* dataset is not of appropriate type */
	EZFS_BUSY,		/* pool or dataset is busy */
	EZFS_EXISTS,		/* pool or dataset already exists */
	EZFS_NOENT,		/* no such pool or dataset */
	EZFS_BADSTREAM,		/* bad backup stream */
	EZFS_DSREADONLY,	/* dataset is readonly */
	EZFS_VOLTOOBIG,		/* volume is too large for 32-bit system */
	EZFS_INVALIDNAME,	/* invalid dataset name */
	EZFS_BADRESTORE,	/* unable to restore to destination */
	EZFS_BADBACKUP,		/* backup failed */
	EZFS_BADTARGET,		/* bad attach/detach/replace target */
	EZFS_NODEVICE,		/* no such device in pool */
	EZFS_BADDEV,		/* invalid device to add */
	EZFS_NOREPLICAS,	/* no valid replicas */
	EZFS_RESILVERING,	/* currently resilvering */
	EZFS_BADVERSION,	/* unsupported version */
	EZFS_POOLUNAVAIL,	/* pool is currently unavailable */
	EZFS_DEVOVERFLOW,	/* too many devices in one vdev */
	EZFS_BADPATH,		/* must be an absolute path */
	EZFS_CROSSTARGET,	/* rename or clone across pool or dataset */
	EZFS_ZONED,		/* used improperly in local zone */
	EZFS_MOUNTFAILED,	/* failed to mount dataset */
	EZFS_UMOUNTFAILED,	/* failed to unmount dataset */
	EZFS_UNSHARENFSFAILED,	/* unshare(1M) failed */
	EZFS_SHARENFSFAILED,	/* share(1M) failed */
	EZFS_PERM,		/* permission denied */
	EZFS_NOSPC,		/* out of space */
	EZFS_FAULT,		/* bad address */
	EZFS_IO,		/* I/O error */
	EZFS_INTR,		/* signal received */
	EZFS_ISSPARE,		/* device is a hot spare */
	EZFS_INVALCONFIG,	/* invalid vdev configuration */
	EZFS_RECURSIVE,		/* recursive dependency */
	EZFS_NOHISTORY,		/* no history object */
	EZFS_POOLPROPS,		/* couldn't retrieve pool props */
	EZFS_POOL_NOTSUP,	/* ops not supported for this type of pool */
	EZFS_POOL_INVALARG,	/* invalid argument for this pool operation */
	EZFS_NAMETOOLONG,	/* dataset name is too long */
	EZFS_OPENFAILED,	/* open of device failed */
	EZFS_NOCAP,		/* couldn't get capacity */
	EZFS_LABELFAILED,	/* write of label failed */
	EZFS_BADWHO,		/* invalid permission who */
	EZFS_BADPERM,		/* invalid permission */
	EZFS_BADPERMSET,	/* invalid permission set name */
	EZFS_NODELEGATION,	/* delegated administration is disabled */
	EZFS_UNSHARESMBFAILED,	/* failed to unshare over smb */
	EZFS_SHARESMBFAILED,	/* failed to share over smb */
	EZFS_BADCACHE,		/* bad cache file */
	EZFS_ISL2CACHE,		/* device is for the level 2 ARC */
	EZFS_VDEVNOTSUP,	/* unsupported vdev type */
	EZFS_NOTSUP,		/* ops not supported on this dataset */
	EZFS_ACTIVE_SPARE,	/* pool has active shared spare devices */
	EZFS_UNPLAYED_LOGS,	/* log device has unplayed logs */
	EZFS_REFTAG_RELE,	/* snapshot release: tag not found */
	EZFS_REFTAG_HOLD,	/* snapshot hold: tag already exists */
	EZFS_TAGTOOLONG,	/* snapshot hold/rele: tag too long */
	EZFS_PIPEFAILED,	/* pipe create failed */
	EZFS_THREADCREATEFAILED, /* thread create failed */
	EZFS_POSTSPLIT_ONLINE,	/* onlining a disk after splitting it */
	EZFS_SCRUBBING,		/* currently scrubbing */
	EZFS_NO_SCRUB,		/* no active scrub */
	EZFS_DIFF,		/* general failure of zfs diff */
	EZFS_DIFFDATA,		/* bad zfs diff data */
	EZFS_POOLREADONLY,	/* pool is in read-only mode */
	EZFS_DQUOTA,
	EZFS_NDIR,
	EZFS_UNKNOWN
} zfs_error_t;

/*
 * The following data structures are all part
 * of the zfs_allow_t data structure which is
 * used for printing 'allow' permissions.
 * It is a linked list of zfs_allow_t's which
 * then contain avl tree's for user/group/sets/...
 * and each one of the entries in those trees have
 * avl tree's for the permissions they belong to and
 * whether they are local,descendent or local+descendent
 * permissions.  The AVL trees are used primarily for
 * sorting purposes, but also so that we can quickly find
 * a given user and or permission.
 */
typedef struct zfs_perm_node {
	avl_node_t z_node;
	char z_pname[MAXPATHLEN];
} zfs_perm_node_t;

typedef struct zfs_allow_node {
	avl_node_t z_node;
	char z_key[MAXPATHLEN];		/* name, such as joe */
	avl_tree_t z_localdescend;	/* local+descendent perms */
	avl_tree_t z_local;		/* local permissions */
	avl_tree_t z_descend;		/* descendent permissions */
} zfs_allow_node_t;

typedef struct zfs_allow {
	struct zfs_allow *z_next;
	char z_setpoint[MAXPATHLEN];
	avl_tree_t z_sets;
	avl_tree_t z_crperms;
	avl_tree_t z_user;
	avl_tree_t z_group;
	avl_tree_t z_everyone;
} zfs_allow_t;

typedef struct pool_thinluns_stat {
	char		pool_name[MAXNAMELEN];
	uint64_t	pool_size;
	uint64_t	pool_thinlun_size;
} pool_thinluns_stat_t;

typedef struct zfs_thinluns_stat {
	uint32_t pool_number;
	pool_thinluns_stat_t *pools;
} zfs_thinluns_t;

typedef struct zfs_thin_luns {
	char		pool_name[MAXNAMELEN];
	char		lu_name[MAXNAMELEN];
	uint64_t	lu_size;
	uint64_t	thinlun_size;
	uint64_t	thinlun_threshold;
	char		used[16];
	char		total[16];
} zfs_thin_luns_t;

typedef struct zfs_thin_luns_stat {
	uint32_t thinluns_number;
	zfs_thin_luns_t *thinluns;
} zfs_thin_luns_stat_t;

/*
 * Basic handle types
 */
typedef struct zfs_handle zfs_handle_t;
typedef struct zpool_handle zpool_handle_t;
typedef struct libzfs_handle libzfs_handle_t;


/*
 *	Define the ZFS RPC communication type
 */
#define	ZFS_RPC_DISK_LIST		1
#define	ZFS_RPC_SET_USERQUOTA	2
#define	ZFS_RPC_GET_USERQUOTA	3
#define	ZFS_RPC_USERSPACE		4
#define	ZFS_RPC_ZPOOL_STATUS	5
#define	ZFS_RPC_REMOTE_CMD		6
#define	ZFS_RPC_DISK_TEST		7
#define	ZFS_RPC_MAX				8

#define	RPC_ADDR_SIZE			16
#define	GROUP_NODE_NUM		32
#define	ZFS_NAME_LEN			256
#define	MAX_PATH_LEN			1024
#define	RPC_SEND_RECV_SIZE	65536	/* 64*1024=65536 */
#define	RPC_BUF_SIZE_MAX	64512	/* 63*1024=64512 */
#define	RPC_USERSPACE_SIZE	32768
/* 32*1024=32768 ,max entrys=	32768/64=512 */
#define	ENTRY_USERSAPCE	64

/* disk logical unit info */
typedef struct zfs_rpc_lu {
	char portID[256];
	char osDeviceFile[256];
} zfs_rpc_lu_t;

typedef struct zfs_rpc_lun {
	char		name[128];
	char		vendor[128];
	char		model[128];
	char		status[128];
	uint64_t	en_no;
	uint64_t	lun_no;
	uint64_t	sas_wwn;
	uint64_t	lu_flag;
	uint64_t	blocks;
	uint32_t	rpm;
	uint32_t	dev_sys;
	uint32_t	slice_count;
	uint32_t	bytes_per_block;
	uint32_t	gsize;
	uint32_t 	lu_num;
	char 	dim[24];
	zfs_rpc_lu_t	lu_info;
} zfs_rpc_lun_t;


/*
 * Library initialization
 */
extern libzfs_handle_t *libzfs_init(void);
extern void libzfs_fini(libzfs_handle_t *);

extern libzfs_handle_t *zpool_get_handle(zpool_handle_t *);
extern libzfs_handle_t *zfs_get_handle(zfs_handle_t *);

extern void libzfs_print_on_error(libzfs_handle_t *, boolean_t);

extern void zfs_save_arguments(int argc, char **, char *, int);
extern int zpool_log_history(libzfs_handle_t *, const char *);

extern int libzfs_errno(libzfs_handle_t *);
extern const char *libzfs_error_init(int);
extern const char *libzfs_error_action(libzfs_handle_t *);
extern const char *libzfs_error_description(libzfs_handle_t *);
extern int zfs_standard_error(libzfs_handle_t *, int, const char *);
extern void libzfs_mnttab_init(libzfs_handle_t *);
extern void libzfs_mnttab_fini(libzfs_handle_t *);
extern void libzfs_mnttab_cache(libzfs_handle_t *, boolean_t);
extern int libzfs_mnttab_find(libzfs_handle_t *, const char *,
    struct mnttab *);
extern void libzfs_mnttab_add(libzfs_handle_t *, const char *,
    const char *, const char *);
extern void libzfs_mnttab_remove(libzfs_handle_t *, const char *);

/*
 * Basic handle functions
 */
extern zpool_handle_t *zpool_open(libzfs_handle_t *, const char *);
extern zpool_handle_t *zpool_open_canfail(libzfs_handle_t *, const char *);
extern void zpool_close(zpool_handle_t *);
extern const char *zpool_get_name(zpool_handle_t *);
extern int zpool_get_state(zpool_handle_t *);
extern char *zpool_state_to_name(vdev_state_t, vdev_aux_t);
extern const char *zpool_pool_state_to_name(pool_state_t);
extern void zpool_free_handles(libzfs_handle_t *);

/*
 * Iterate over all active pools in the system.
 */
typedef int (*zpool_iter_f)(zpool_handle_t *, void *);
extern int zpool_iter(libzfs_handle_t *, zpool_iter_f, void *);

/*
 * Functions to create and destroy pools
 */
extern int zpool_create(libzfs_handle_t *, const char *, nvlist_t *,
    nvlist_t *, nvlist_t *);
extern int zpool_destroy(zpool_handle_t *, const char *);
extern int zpool_add(zpool_handle_t *, nvlist_t *);

typedef struct splitflags {
	/* do not split, but return the config that would be split off */
	int dryrun : 1;

	/* after splitting, import the pool */
	int import : 1;
	int name_flags;
} splitflags_t;

/*
 * Functions to manipulate pool and vdev state
 */
extern int zpool_scan(zpool_handle_t *, pool_scan_func_t);
extern int zpool_clear(zpool_handle_t *, const char *, nvlist_t *);
extern int zpool_reguid(zpool_handle_t *);
extern int zpool_reopen(zpool_handle_t *);

extern int zpool_vdev_online(zpool_handle_t *, const char *, int,
    vdev_state_t *);
extern int zpool_vdev_offline(zpool_handle_t *, const char *, boolean_t);
extern int zpool_vdev_attach(zpool_handle_t *, const char *,
    const char *, nvlist_t *, int);
extern int zpool_vdev_detach(zpool_handle_t *, const char *);
extern int zpool_vdev_remove(zpool_handle_t *, const char *);
extern int zpool_vdev_split(zpool_handle_t *, char *, nvlist_t **, nvlist_t *,
    splitflags_t);

extern int zpool_vdev_fault(zpool_handle_t *, uint64_t, vdev_aux_t);
extern int zpool_vdev_degrade(zpool_handle_t *, uint64_t, vdev_aux_t);
extern int zpool_vdev_clear(zpool_handle_t *, uint64_t);

extern nvlist_t *zpool_get_nvroot(zpool_handle_t *zhp);
extern nvlist_t *zpool_find_vdev(zpool_handle_t *, const char *, boolean_t *,
    boolean_t *, boolean_t *, boolean_t *, boolean_t *);
extern nvlist_t *zpool_find_vdev_by_physpath(zpool_handle_t *, const char *,
    boolean_t *, boolean_t *, boolean_t *, boolean_t *, boolean_t *);
extern int zpool_label_disk_wait(char *, int);
extern int zpool_label_disk(libzfs_handle_t *, zpool_handle_t *, char *);

/*
 * Functions to manage pool properties
 */
extern int zpool_set_prop(zpool_handle_t *, const char *, const char *);
extern int zpool_get_prop(zpool_handle_t *, zpool_prop_t, char *,
    size_t proplen, zprop_source_t *);
extern int zpool_get_prop_literal(zpool_handle_t *, zpool_prop_t, char *,
    size_t proplen, zprop_source_t *, boolean_t literal);
extern uint64_t zpool_get_prop_int(zpool_handle_t *, zpool_prop_t,
    zprop_source_t *);

extern const char *zpool_prop_to_name(zpool_prop_t);
extern const char *zpool_prop_values(zpool_prop_t);

/*
 * Pool health statistics.
 */
typedef enum {
	/*
	 * The following correspond to faults as defined in the (fault.fs.zfs.*)
	 * event namespace.  Each is associated with a corresponding message ID.
	 */
	ZPOOL_STATUS_CORRUPT_CACHE,	/* corrupt /kernel/drv/zpool.cache */
	ZPOOL_STATUS_MISSING_DEV_R,	/* missing device with replicas */
	ZPOOL_STATUS_MISSING_DEV_NR,	/* missing device with no replicas */
	ZPOOL_STATUS_CORRUPT_LABEL_R,	/* bad device label with replicas */
	ZPOOL_STATUS_CORRUPT_LABEL_NR,	/* bad device label with no replicas */
	ZPOOL_STATUS_BAD_GUID_SUM,	/* sum of device guids didn't match */
	ZPOOL_STATUS_CORRUPT_POOL,	/* pool metadata is corrupted */
	ZPOOL_STATUS_CORRUPT_DATA,	/* data errors in user (meta)data */
	ZPOOL_STATUS_FAILING_DEV,	/* device experiencing errors */
	ZPOOL_STATUS_VERSION_NEWER,	/* newer on-disk version */
	ZPOOL_STATUS_HOSTID_MISMATCH,	/* last accessed by another system */
	ZPOOL_STATUS_IO_FAILURE_WAIT,	/* failed I/O, failmode 'wait' */
	ZPOOL_STATUS_IO_FAILURE_CONTINUE, /* failed I/O, failmode 'continue' */
	ZPOOL_STATUS_BAD_LOG,		/* cannot read log chain(s) */
	ZPOOL_STATUS_ERRATA,		/* informational errata available */

	/*
	 * If the pool has unsupported features but can still be opened in
	 * read-only mode, its status is ZPOOL_STATUS_UNSUP_FEAT_WRITE. If the
	 * pool has unsupported features but cannot be opened at all, its
	 * status is ZPOOL_STATUS_UNSUP_FEAT_READ.
	 */
	ZPOOL_STATUS_UNSUP_FEAT_READ,	/* unsupported features for read */
	ZPOOL_STATUS_UNSUP_FEAT_WRITE,	/* unsupported features for write */

	/*
	 * These faults have no corresponding message ID.  At the time we are
	 * checking the status, the original reason for the FMA fault (I/O or
	 * checksum errors) has been lost.
	 */
	ZPOOL_STATUS_FAULTED_DEV_R,	/* faulted device with replicas */
	ZPOOL_STATUS_FAULTED_DEV_NR,	/* faulted device with no replicas */

	/*
	 * The following are not faults per se, but still an error possibly
	 * requiring administrative attention.  There is no corresponding
	 * message ID.
	 */
	ZPOOL_STATUS_VERSION_OLDER,	/* older legacy on-disk version */
	ZPOOL_STATUS_FEAT_DISABLED,	/* supported features are disabled */
	ZPOOL_STATUS_RESILVERING,	/* device being resilvered */
	ZPOOL_STATUS_OFFLINE_DEV,	/* device online */
	ZPOOL_STATUS_REMOVED_DEV,	/* removed device */

	/*
	 * Finally, the following indicates a healthy pool.
	 */
	ZPOOL_STATUS_OK
} zpool_status_t;

extern unsigned long get_system_hostid(void);
extern zpool_status_t zpool_get_status(zpool_handle_t *, char **,
    zpool_errata_t *);
extern zpool_status_t zpool_import_status(nvlist_t *, char **,
    zpool_errata_t *);
extern void zpool_dump_ddt(const ddt_stat_t *dds, const ddt_histogram_t *ddh);

/*
 * Statistics and configuration functions.
 */
extern nvlist_t *zpool_get_config(zpool_handle_t *, nvlist_t **);
extern nvlist_t *zpool_get_features(zpool_handle_t *);
extern int zpool_refresh_stats(zpool_handle_t *, boolean_t *);
extern int zpool_get_errlog(zpool_handle_t *, nvlist_t **);

/*
 * Import and export functions
 */
extern int zpool_export(zpool_handle_t *, boolean_t, const char *);
extern int zpool_export_force(zpool_handle_t *, const char *);
extern int zpool_import(libzfs_handle_t *, nvlist_t *, const char *,
    char *altroot);
extern int zpool_import_props(libzfs_handle_t *, nvlist_t *, const char *,
    nvlist_t *, int);
extern void zpool_print_unsup_feat(nvlist_t *config);

/*
 * Search for pools to import
 */

typedef struct importargs {
	char **path;		/* a list of paths to search		*/
	int paths;		/* number of paths to search		*/
	char *poolname;		/* name of a pool to find		*/
	uint64_t guid;		/* guid of a pool to find		*/
	uint32_t remote_hostid;	/* remote hostid to search */
	char *cachefile;	/* cachefile to use for import		*/
	int can_be_active : 1;	/* can the pool be active?		*/
	int unique : 1;		/* does 'poolname' already exist?	*/
	int exists : 1;		/* set on return if pool already exists	*/
	int no_blkid : 1;	/* don't use libblkid */
	int cluster_switch : 1;	/* search remote's pools */
	int cluster_ignore : 1;	/* don't filter remote's pools */
} importargs_t;

extern nvlist_t *zpool_search_import(libzfs_handle_t *, importargs_t *);

/* legacy pool search routines */
extern nvlist_t *zpool_find_import(libzfs_handle_t *, int, char **);
extern nvlist_t *zpool_find_import_cached(libzfs_handle_t *, const char *,
    char *, uint64_t);

/*
 * Miscellaneous pool functions
 */
struct zfs_cmd;

extern const char *zfs_history_event_names[];

typedef enum {
	VDEV_NAME_PATH		= 1 << 0,
	VDEV_NAME_GUID		= 1 << 1,
	VDEV_NAME_FOLLOW_LINKS	= 1 << 2,
	VDEV_NAME_TYPE_ID	= 1 << 3,
} vdev_name_t;

extern char *zpool_vdev_name(libzfs_handle_t *, zpool_handle_t *, nvlist_t *,
    int name_flags);
extern int zpool_upgrade(zpool_handle_t *, uint64_t);
extern int zpool_get_history(zpool_handle_t *, nvlist_t **);
extern int zpool_history_unpack(char *, uint64_t, uint64_t *,
    nvlist_t ***, uint_t *);
extern int zpool_events_next(libzfs_handle_t *, nvlist_t **, int *, unsigned,
    int);
extern int zpool_events_clear(libzfs_handle_t *, int *);
extern int zpool_events_seek(libzfs_handle_t *, uint64_t, int);
extern void zpool_obj_to_path(zpool_handle_t *, uint64_t, uint64_t, char *,
    size_t len);
extern int zfs_ioctl(libzfs_handle_t *, int, struct zfs_cmd *);
extern int zpool_get_physpath(zpool_handle_t *, char *, size_t);
extern void zpool_explain_recover(libzfs_handle_t *, const char *, int,
    nvlist_t *);

/*
 * Basic handle manipulations.  These functions do not create or destroy the
 * underlying datasets, only the references to them.
 */
extern zfs_handle_t *zfs_open(libzfs_handle_t *, const char *, int);
extern zfs_handle_t *zfs_handle_dup(zfs_handle_t *);
extern void zfs_close(zfs_handle_t *);
extern zfs_type_t zfs_get_type(const zfs_handle_t *);
extern const char *zfs_get_name(const zfs_handle_t *);
extern zpool_handle_t *zfs_get_pool_handle(const zfs_handle_t *);

/*
 * Property management functions.  Some functions are shared with the kernel,
 * and are found in sys/fs/zfs.h.
 */

/*
 * zfs dataset property management
 */
extern const char *zfs_prop_default_string(zfs_prop_t);
extern uint64_t zfs_prop_default_numeric(zfs_prop_t);
extern const char *zfs_prop_column_name(zfs_prop_t);
extern boolean_t zfs_prop_align_right(zfs_prop_t);

extern nvlist_t *zfs_valid_proplist(libzfs_handle_t *, zfs_type_t,
    nvlist_t *, uint64_t, zfs_handle_t *, const char *);

extern const char *zfs_prop_to_name(zfs_prop_t);
extern int zfs_prop_set_extended(zfs_handle_t *, const char *, const char *,
    zprop_setflags_t);
extern int zfs_prop_set(zfs_handle_t *, const char *, const char *);
extern int zfs_prop_get(zfs_handle_t *, zfs_prop_t, char *, size_t,
    zprop_source_t *, char *, size_t, boolean_t);
extern int zfs_prop_get_recvd(zfs_handle_t *, const char *, char *, size_t,
    boolean_t);
extern int zfs_prop_get_numeric(zfs_handle_t *, zfs_prop_t, uint64_t *,
    zprop_source_t *, char *, size_t);
extern int zfs_prop_get_userquota_int(zfs_handle_t *zhp, const char *propname,
    uint64_t *propvalue);
extern int zfs_prop_get_userquota(zfs_handle_t *zhp, const char *propname,
    char *propbuf, int proplen, boolean_t literal);
extern int zfs_prop_get_written_int(zfs_handle_t *zhp, const char *propname,
    uint64_t *propvalue);
extern int zfs_prop_get_written(zfs_handle_t *zhp, const char *propname,
    char *propbuf, int proplen, boolean_t literal);
extern int zfs_prop_get_feature(zfs_handle_t *zhp, const char *propname,
    char *buf, size_t len);
extern uint64_t getprop_uint64(zfs_handle_t *, zfs_prop_t, char **);
extern uint64_t zfs_prop_get_int(zfs_handle_t *, zfs_prop_t);
extern int zfs_prop_inherit(zfs_handle_t *, const char *, boolean_t);
extern const char *zfs_prop_values(zfs_prop_t);
extern int zfs_prop_is_string(zfs_prop_t prop);
extern nvlist_t *zfs_get_user_props(zfs_handle_t *);
extern nvlist_t *zfs_get_recvd_props(zfs_handle_t *);
extern nvlist_t *zfs_get_clones_nvl(zfs_handle_t *);

typedef struct zprop_list {
	int		pl_prop;
	char		*pl_user_prop;
	struct zprop_list *pl_next;
	boolean_t	pl_all;
	size_t		pl_width;
	size_t		pl_recvd_width;
	boolean_t	pl_fixed;
} zprop_list_t;

extern int zfs_prop_get_group_userquota(libzfs_handle_t *hdl, zfs_handle_t *zhp, 
	zprop_list_t *pl, char *userquota_value);

extern int zfs_expand_proplist(zfs_handle_t *, zprop_list_t **, boolean_t,
    boolean_t);
extern void zfs_prune_proplist(zfs_handle_t *, uint8_t *);

#define	ZFS_MOUNTPOINT_NONE	"none"
#define	ZFS_MOUNTPOINT_LEGACY	"legacy"

#define	ZFS_FEATURE_DISABLED	"disabled"
#define	ZFS_FEATURE_ENABLED	"enabled"
#define	ZFS_FEATURE_ACTIVE	"active"

#define	ZFS_UNSUPPORTED_INACTIVE	"inactive"
#define	ZFS_UNSUPPORTED_READONLY	"readonly"

/*
 * zpool property management
 */
extern int zpool_expand_proplist(zpool_handle_t *, zprop_list_t **);
extern int zpool_prop_get_feature(zpool_handle_t *, const char *, char *,
    size_t);
extern const char *zpool_prop_default_string(zpool_prop_t);
extern uint64_t zpool_prop_default_numeric(zpool_prop_t);
extern const char *zpool_prop_column_name(zpool_prop_t);
extern boolean_t zpool_prop_align_right(zpool_prop_t);

/*
 * Functions shared by zfs and zpool property management.
 */
extern int zprop_iter(zprop_func func, void *cb, boolean_t show_all,
    boolean_t ordered, zfs_type_t type);
extern int zprop_get_list(libzfs_handle_t *, char *, zprop_list_t **,
    zfs_type_t);
extern void zprop_free_list(zprop_list_t *);

#define	ZFS_GET_NCOLS	5

typedef enum {
	GET_COL_NONE,
	GET_COL_NAME,
	GET_COL_PROPERTY,
	GET_COL_VALUE,
	GET_COL_RECVD,
	GET_COL_SOURCE
} zfs_get_column_t;

/*
 * Functions for printing zfs or zpool properties
 */
typedef struct zprop_get_cbdata {
	int cb_sources;
	zfs_get_column_t cb_columns[ZFS_GET_NCOLS];
	int cb_colwidths[ZFS_GET_NCOLS + 1];
	boolean_t cb_scripted;
	boolean_t cb_literal;
	boolean_t cb_first;
	zprop_list_t *cb_proplist;
	zfs_type_t cb_type;
} zprop_get_cbdata_t;

void zprop_print_one_property(const char *, zprop_get_cbdata_t *,
    const char *, const char *, zprop_source_t, const char *,
    const char *);

typedef int (*zfs_dirquota_cb_t)(const char *path, uint64_t quota,
	uint64_t used);
typedef int (*zfs_dirlowdata_cb_t)(const char *path, uint64_t lowdata,
	uint64_t low_peri, uint64_t low_peri_unit,
	uint64_t low_del_peri, uint64_t low_criteria);

/*
 * Iterator functions.
 */
typedef int (*zfs_iter_f)(zfs_handle_t *, void *);
extern int zfs_iter_root(libzfs_handle_t *, zfs_iter_f, void *);
extern int zfs_iter_children(zfs_handle_t *, zfs_iter_f, void *);
extern int zfs_iter_dependents(zfs_handle_t *, boolean_t, zfs_iter_f, void *);
extern int zfs_iter_filesystems(zfs_handle_t *, zfs_iter_f, void *);
extern int zfs_iter_snapshots(zfs_handle_t *, boolean_t, zfs_iter_f, void *);
extern int zfs_iter_snapshots_sorted(zfs_handle_t *, zfs_iter_f, void *);
extern int zfs_iter_snapspec(zfs_handle_t *, const char *, zfs_iter_f, void *);
extern int zfs_iter_bookmarks(zfs_handle_t *, zfs_iter_f, void *);

typedef struct get_all_cb {
	zfs_handle_t	**cb_handles;
	size_t		cb_alloc;
	size_t		cb_used;
	boolean_t	cb_verbose;
	int		(*cb_getone)(zfs_handle_t *, void *);
} get_all_cb_t;

void libzfs_add_handle(get_all_cb_t *, zfs_handle_t *);
int libzfs_dataset_cmp(const void *, const void *);

/*
 * Functions to create and destroy datasets.
 */
extern int zfs_create(libzfs_handle_t *, const char *, zfs_type_t,
    nvlist_t *);
extern int zfs_create_ancestors(libzfs_handle_t *, const char *);
extern int zfs_destroy(zfs_handle_t *, boolean_t);
extern int zfs_destroy_snaps(zfs_handle_t *, char *, boolean_t);
extern int zfs_destroy_snaps_nvl(libzfs_handle_t *, nvlist_t *, boolean_t);
extern int zfs_clone(zfs_handle_t *, const char *, nvlist_t *);
extern int zfs_snapshot(libzfs_handle_t *, const char *, boolean_t, nvlist_t *);
extern int zfs_snapshot_nvl(libzfs_handle_t *hdl, nvlist_t *snaps,
    nvlist_t *props);
extern int zfs_rollback(zfs_handle_t *, zfs_handle_t *, boolean_t);
extern int zfs_rename(zfs_handle_t *, const char *, boolean_t, boolean_t);

typedef struct sendflags {
	/* print informational messages (ie, -v was specified) */
	boolean_t verbose;

	/* recursive send  (ie, -R) */
	boolean_t replicate;

	/* for incrementals, do all intermediate snapshots */
	boolean_t doall;

	/* if dataset is a clone, do incremental from its origin */
	boolean_t fromorigin;

	/* do deduplication */
	boolean_t dedup;

	/* send properties (ie, -p) */
	boolean_t props;

	/* do not send (no-op, ie. -n) */
	boolean_t dryrun;

	/* parsable verbose output (ie. -P) */
	boolean_t parsable;

	/* show progress (ie. -v) */
	boolean_t progress;

	/* large blocks (>128K) are permitted */
	boolean_t largeblock;

	/* WRITE_EMBEDDED records of type DATA are permitted */
	boolean_t embed_data;
} sendflags_t;

typedef boolean_t (snapfilter_cb_t)(zfs_handle_t *, void *);

extern int zfs_send(zfs_handle_t *, const char *, const char *,
    sendflags_t *, int, snapfilter_cb_t, void *, nvlist_t **);
extern int zfs_send_one(zfs_handle_t *, const char *, int, enum lzc_send_flags);

extern int zfs_promote(zfs_handle_t *);
extern int zfs_hold(zfs_handle_t *, const char *, const char *,
    boolean_t, int);
extern int zfs_hold_nvl(zfs_handle_t *, int, nvlist_t *);
extern int zfs_release(zfs_handle_t *, const char *, const char *, boolean_t);
extern int zfs_get_holds(zfs_handle_t *, nvlist_t **);
extern uint64_t zvol_volsize_to_reservation(uint64_t, nvlist_t *);

typedef int (*zfs_userspace_cb_t)(void *arg, const char *domain,
    uid_t rid, uint64_t space);
typedef int (*zfs_remote_userspace_cb_t)(void *arg, const char *domain,
    uid_t rid, uint64_t space, char **back);

extern int zfs_userspace(zfs_handle_t *, zfs_userquota_prop_t,
    zfs_userspace_cb_t, void *);

extern int zfs_get_fsacl(zfs_handle_t *, nvlist_t **);
extern int zfs_set_fsacl(zfs_handle_t *, boolean_t, nvlist_t *);

typedef struct recvflags {
	/* print informational messages (ie, -v was specified) */
	boolean_t verbose;

	/* the destination is a prefix, not the exact fs (ie, -d) */
	boolean_t isprefix;

	/*
	 * Only the tail of the sent snapshot path is appended to the
	 * destination to determine the received snapshot name (ie, -e).
	 */
	boolean_t istail;

	/* do not actually do the recv, just check if it would work (ie, -n) */
	boolean_t dryrun;

	/* rollback/destroy filesystems as necessary (eg, -F) */
	boolean_t force;

	/* set "canmount=off" on all modified filesystems */
	boolean_t canmountoff;

	/* byteswap flag is used internally; callers need not specify */
	boolean_t byteswap;

	/* do not mount file systems as they are extracted (private) */
	boolean_t nomount;
} recvflags_t;

extern int zfs_receive(libzfs_handle_t *, const char *, recvflags_t *,
    int, avl_tree_t *);

typedef enum diff_flags {
	ZFS_DIFF_PARSEABLE = 0x1,
	ZFS_DIFF_TIMESTAMP = 0x2,
	ZFS_DIFF_CLASSIFY = 0x4
} diff_flags_t;

extern int zfs_show_diffs(zfs_handle_t *, int, const char *, const char *,
    int);

/*
 * Miscellaneous functions.
 */
extern const char *zfs_type_to_name(zfs_type_t);
extern void zfs_refresh_properties(zfs_handle_t *);
extern int zfs_name_valid(const char *, zfs_type_t);
extern zfs_handle_t *zfs_path_to_zhandle(libzfs_handle_t *, char *, zfs_type_t);
extern boolean_t zfs_dataset_exists(libzfs_handle_t *, const char *,
    zfs_type_t);
extern int zfs_spa_version(zfs_handle_t *, int *);
extern boolean_t zfs_bookmark_exists(const char *path);
extern int zfs_append_partition(char *path, size_t max_len);
extern int zfs_resolve_shortname(const char *name, char *path, size_t pathlen);
extern int zfs_strcmp_pathname(char *name, char *cmp_name, int wholedisk);

/*
 * Mount support functions.
 */
extern boolean_t is_mounted(libzfs_handle_t *, const char *special, char **);
extern boolean_t zfs_is_mounted(zfs_handle_t *, char **);
extern int zfs_mount(zfs_handle_t *, const char *, int);
extern int zfs_unmount(zfs_handle_t *, const char *, int);
extern int zfs_unmountall(zfs_handle_t *, int);

/*
 * Share support functions.
 */
extern boolean_t zfs_is_shared(zfs_handle_t *);
extern int zfs_share(zfs_handle_t *);
extern int zfs_unshare(zfs_handle_t *);

/*
 * Protocol-specific share support functions.
 */
extern boolean_t zfs_is_shared_nfs(zfs_handle_t *, char **);
extern boolean_t zfs_is_shared_smb(zfs_handle_t *, char **);
extern int zfs_share_nfs(zfs_handle_t *);
extern int zfs_share_smb(zfs_handle_t *);
extern int zfs_shareall(zfs_handle_t *);
extern int zfs_unshare_nfs(zfs_handle_t *, const char *);
extern int zfs_unshare_smb(zfs_handle_t *, const char *);
extern int zfs_unshareall_nfs(zfs_handle_t *);
extern int zfs_unshareall_smb(zfs_handle_t *);
extern int zfs_unshareall_bypath(zfs_handle_t *, const char *);
extern int zfs_unshareall(zfs_handle_t *);
extern int zfs_deleg_share_nfs(libzfs_handle_t *, char *, char *, char *,
    void *, void *, int, zfs_share_op_t);

/*
 * Utility function to convert a number to a human-readable form.
 */
extern void zfs_nicenum(uint64_t, char *, size_t);
extern int zfs_nicestrtonum(libzfs_handle_t *, const char *, uint64_t *);

/*
 * Utility functions to run an external process.
 */
#define	STDOUT_VERBOSE	0x01
#define	STDERR_VERBOSE	0x02

int libzfs_run_process(const char *, char **, int flags);

/*
 * Given a device or file, determine if it is part of a pool.
 */
extern int zpool_in_use(libzfs_handle_t *, int, pool_state_t *, char **,
    boolean_t *);

/*
 * Label manipulation.
 */
extern int zpool_read_label(int, nvlist_t **, int *);
extern int zpool_clear_label(int);

/* needby disk.c */
extern int zpool_restore_label(int fd);
extern int zpool_save_label(int fd);
extern int zpool_read_stamp(nvlist_t *pool_root, zpool_stamp_t *stamp);
extern int zpool_write_dev_stamp(char *path, zpool_stamp_t *stamp);
extern int zpool_write_stamp(nvlist_t *pool_root, zpool_stamp_t *stamp,
		int nquantum);
extern int zpool_read_stmp_by_path(char *path, zpool_stamp_t *stamp);
extern int zpool_write_dev_stamp_mark(char *path, zpool_stamp_t *stamp);
extern int zpool_cluster_set_disks(libzfs_handle_t * hdl,
	char * pool_name, uint64_t cid, uint64_t rid, uint64_t progress,
	boolean_t cluster_switch, uint32_t remote_hostid);

/*
 * Management interfaces for SMB ACL files
 */

int zfs_smb_acl_add(libzfs_handle_t *, char *, char *, char *);
int zfs_smb_acl_remove(libzfs_handle_t *, char *, char *, char *);
int zfs_smb_acl_purge(libzfs_handle_t *, char *, char *);
int zfs_smb_acl_rename(libzfs_handle_t *, char *, char *, char *, char *);

/*
 * Enable and disable datasets within a pool by mounting/unmounting and
 * sharing/unsharing them.
 */
extern int zpool_enable_datasets(zpool_handle_t *, const char *, int);
extern int zpool_disable_datasets(zpool_handle_t *, boolean_t);

/*
 * Mappings between vdev and FRU.
 */
extern void libzfs_fru_refresh(libzfs_handle_t *);
extern const char *libzfs_fru_lookup(libzfs_handle_t *, const char *);
extern const char *libzfs_fru_devpath(libzfs_handle_t *, const char *);
extern boolean_t libzfs_fru_compare(libzfs_handle_t *, const char *,
    const char *);
extern boolean_t libzfs_fru_notself(libzfs_handle_t *, const char *);
extern int zpool_fru_set(zpool_handle_t *, uint64_t, const char *);
extern void zfs_start_mirror(libzfs_handle_t *hdl, char *mirror_to,
    uint64_t flags);
extern int zfs_test_mirror(libzfs_handle_t *hdl, long int bs, long int cnt, uint8_t need_reply);
extern int zfs_comm_test(libzfs_handle_t *hdl, char *hostid, char*datalen, char*headlen);
extern int zfs_enable_clustersan(libzfs_handle_t *hd, char *clustername,
	char *linkname, nvlist_t *conf, uint64_t flags);
extern int zfs_disable_clustersan(libzfs_handle_t *hdl, uint64_t flags);
int zfs_disable_clustersan_target(libzfs_handle_t *hdl, char *linkname,
	uint64_t flags);
nvlist_t *zfs_clustersan_get_hostlist(libzfs_handle_t *hdl, uint64_t flags);
nvlist_t *zfs_clustersan_get_targetlist(libzfs_handle_t *hdl, uint64_t flags);
int zfs_clustersan_set_prop(libzfs_handle_t *hdl,
	const char *prop, const char *value);
nvlist_t *zfs_clustersan_get_nvlist(libzfs_handle_t *hdl, uint32_t cmd,
	void *arg, uint64_t flags);
nvlist_t *zfs_clustersan_sync_cmd(libzfs_handle_t *hdl, uint64_t cmd_id,
	char *cmd_str, int timeout, int remote_hostid);
int zfs_cluster_rdma_rpc_clnt_ioc(libzfs_handle_t *hdl, int cmd, void *arg);
int zfs_cluster_socket_do (libzfs_handle_t *hdl,char *hostname, uint32_t hostid,
    char *ip, int pri, int port);

typedef struct spa_quantum_index {
	uint64_t index;
	char *dev_name;
}spa_quantum_index_t;

extern uint64_t zpool_read_used(nvlist_t *pool_root, spa_quantum_index_t *index,
	uint64_t nquantum);
extern boolean_t zpool_used_index_changed(spa_quantum_index_t *last_index,
	uint64_t nquantum, spa_quantum_index_t *current_index, uint64_t *read_nquantum);

extern int zpool_remove_partner(libzfs_handle_t *hdl, char *name,
	uint32_t remote_hostid);
extern void zpool_release_pool(zpool_handle_t *hdl, char *name,
	zfs_hbx_ioc_t command, uint32_t rid);

extern void zfs_do_hbx_process(libzfs_handle_t *hdl, char *buffer, int size,
	uint64_t flags);
extern void zfs_do_hbx_process_ex(libzfs_handle_t * hdl, char * buffer, int size,
	uint64_t flags, int remote_id);
extern int zfs_do_hbx_get_nvlist(libzfs_handle_t *hdl, zfs_hbx_ioc_t cmd,
	uint32_t hostid, nvlist_t **nv_ptr);
extern int zfs_add_guide_info(char *buffer, int size, uint64_t flags);

extern int zfs_is_failover_prop(const char * prop);

extern uint64_t get_partner_id(libzfs_handle_t *hdl, uint64_t rid);

int zfs_create_lu(char *lu_name);
void zfs_import_all_lus(libzfs_handle_t *hdl, char *data);
void zfs_standby_all_lus(libzfs_handle_t *hdl, char *pool_name);
void zfs_destroy_all_lus(libzfs_handle_t *hdl, char *pool_name);
void zfs_enable_avs(libzfs_handle_t *hdl, char *data, int enabled);
/*
 * multiclus functions. 
 */
extern void zfs_start_multiclus(libzfs_handle_t *hdl, char *group_name,
    char *fs_name, uint64_t flags, void* param);
extern void zfs_migrate(libzfs_handle_t *hdl, char *fs_name, uint64_t flags, uint64_t obj);

extern int get_rpc_addr(libzfs_handle_t *hdl, uint64_t flags,
	char *groupip, uint_t *num);
extern int zfs_rpc_back_proc(uint_t rtype, char **backbuf, zfs_rpc_arg_t *recvarg,
	zfs_rpc_ret_t *backarg);
extern int zfs_rpc_call(char* host, uint32_t gettype,
        zfs_rpc_arg_t *sendarg, zfs_rpc_ret_t *backarg);
int zfs_prop_get_dirlowdata(zfs_handle_t *zhp, const char *propname,
    char *propbuf, int proplen);

extern int
zfs_prop_get_dirquota_all(zfs_handle_t *zhp,  zfs_dirquota_cb_t func);
extern int
zfs_prop_get_dirlowdata_all(zfs_handle_t *zhp, zfs_dirlowdata_cb_t func);

typedef struct zfs_pathname {
	char	*pn_buf;		/* underlying storage */
	char	*pn_path;		/* remaining pathname */
	size_t	pn_pathlen;		/* remaining length */
	size_t	pn_bufsize;		/* total size of pn_buf */
} zfs_pathname_t;

int zfs_start_rm_file_in_dir(libzfs_handle_t *hdl, char *dir);


extern int zfs_start_lun_migrate(libzfs_handle_t *hdl, const char *dst, char *pool, char *guid);
extern int zfs_stop_lun_migrate(libzfs_handle_t *hdl, const char *dst);
extern int zfs_recovery_lun_migrate(libzfs_handle_t *hdl, char *fsname);
extern int zfs_check_lun_migrate(libzfs_handle_t *hdl, char *fsname, int now);
extern int get_clusnodename(char *buf, int len);
extern uint64_t label_offset(uint64_t size, int l);
extern int zfs_prop_get_dirquota(zfs_handle_t *zhp, const char *propname,
    char *propbuf, int proplen);
extern int zfs_group_userquota_send(int flags, zfs_msg_type_t settype, int argc, char **argv, void *data);
extern uint_t num_metas(nvlist_t *nv);
extern uint_t num_lows(nvlist_t *nv);
extern void zpool_check_thin_luns(zfs_thinluns_t **statpp);
extern void zfs_check_thin_luns(zfs_thin_luns_stat_t **statpp);
extern boolean_t zfs_check_raidz_aggre_valid(nvlist_t *config, nvlist_t *nv);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBZFS_H */
