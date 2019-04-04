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

#ifndef _SYS_ZFS_GROUP_DTL_H
#define	_SYS_ZFS_GROUP_DTL_H
#include <sys/vnode.h>
#include <sys/avl.h>
#include <sys/dmu.h>
#include <sys/time.h>
#ifdef _KERNEL
#include <sys/zfs_multiclus.h>
#include <sys/zfs_group.h>
#include <sys/zfs_vfsops.h>
#include <sys/cred.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define ZFS_GROUP_DTL_AVL_NODE_MAX 0x100000

extern const char *zfs_group_dtl_prefix;

#define ZFS_GROUP_DTL_ACL_ENTRY_MAX 96
typedef struct zfs_group_dtl_vsecattr {
	uint_t		vsa_mask;	/* See below */
	int		vsa_aclcnt;	/* ACL entry count */
	uint8_t vsa_aclentp[1152];	/* pointer to ACL entries */
	int		vsa_dfaclcnt;	/* default ACL entry count */
	size_t		vsa_aclentsz;	/* ACE size in bytes of vsa_aclentp */
	uint_t		vsa_aclflags;	/* ACE ACL flags */
} zfs_group_dtl_vsecattr_t;


typedef struct zfs_group_dtl_data {
	uint64_t	obj;
	timestruc_t	gentime;
	uint64_t	data_size;
	uint8_t	data[1992]; /* data on map */
} zfs_group_dtl_data_t;

typedef struct zfs_group_dtl_node {
	avl_node_t	link;
	zfs_group_dtl_data_t data;
} zfs_group_dtl_node_t;

typedef struct zfs_group_dtl_obj {
	uint64_t	type;	/* zfs_group_dtl type */
	uint64_t	start_pos;	/* B segment old read pointer, and old DTL entry write back pointer. */
	uint64_t	end_pos;	/* B segment new DTL entry write pointer. */
	uint64_t	last_read;		/* B segment read pointer (new read pointer). */
	uint64_t	last_rewrite;	/* A segment write pointer. */
} zfs_group_dtl_obj_t;

#define	ZFS_GROUP_DTL_BLOCKSHIFT	12
#define	ZFS_GROUP_DTL_MAGIC	0x5A5F4E415344544C   /*the corresponding
	ASCIIs are 'Z_NASDTL'*/
#define ZFS_GROUP_DTL_MAX_A_SEGMENT_SIZE	0x10000000
#define ZFS_GROUP_DTL_B_SEGMENT_START		0x14000000

typedef	void (* zfs_group_dtl_output_t)(zfs_group_dtl_node_t*);

typedef struct zfs_group_dtl_create {
	uint64_t	dir_zid;
	uint64_t	dir_spa_id;
	uint64_t	dir_os_id;
	uint64_t	dir_gen;
	uint64_t	zid;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	gen;
	char	name[MAXNAMELEN];
	xvattr_t	xvap;
	boolean_t	isvapcarry;
	zfs_group_dtl_vsecattr_t	vsap;
	boolean_t	isvsapcarry;
	int	ex;
	zfs_group_cred_t	cred;
	int	mode;
	int	flag;
} zfs_group_dtl_create_t;

typedef struct zfs_group_dtl_mkdir {
	uint64_t	dir_zid;
	uint64_t	dir_spa_id;
	uint64_t	dir_os_id;
	uint64_t	dir_gen;
	uint64_t	zid;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	gen;
	char	name[MAXNAMELEN];
	xvattr_t	xvap;
	boolean_t	isvapcarry;
	zfs_group_dtl_vsecattr_t	vsap;
	boolean_t	isvsapcarry;
	int	flag;
	zfs_group_cred_t	cred;
} zfs_group_dtl_mkdir_t;

typedef struct zfs_group_dtl_symlink {
	uint64_t	dir_zid;
	uint64_t	dir_spa_id;
	uint64_t	dir_os_id;
	uint64_t	dir_gen;
	uint64_t	zid;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	gen;
	char	name[MAXNAMELEN];
	xvattr_t	xvap;
	boolean_t	isvapcarry;
	int	flag;
	char	target[MAXNAMELEN];
	zfs_group_cred_t	cred;
} zfs_group_dtl_symlink_t;

typedef struct zfs_group_dtl_link {
	uint64_t	zid;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	gen;
	uint64_t	szid;	/*source znode id*/
	uint64_t	sspa_id;
	uint64_t	sos_id;
	uint64_t	sgen;
	char	name[MAXNAMELEN];
	int	flag;
	zfs_group_cred_t	cred;
} zfs_group_dtl_link_t;

typedef struct zfs_group_dtl_remove {
	zfs_group_object_t	group_id;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	dirid;
	uint64_t	dirlowdata;
	uint64_t	dirquota;
	char	dirname[MAXNAMELEN];
	char	name[MAXNAMELEN];
	zfs_group_cred_t	cred;
	int	flag;
} zfs_group_dtl_remove_t;

typedef struct zfs_group_dtl_rmdir {
	zfs_group_object_t	group_id;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	dirid;
	uint64_t	dirlowdata;
	uint64_t	dirquota;
	char	dirname[MAXNAMELEN];
	char	name[MAXNAMELEN];
	zfs_group_cred_t	cred;
	int	flag;
} zfs_group_dtl_rmdir_t;

typedef struct zfs_group_dtl_setsecattr {
	uint64_t	zid;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	gen;
	zfs_group_dtl_vsecattr_t	vsap;
	boolean_t	isvsapcarry;
	int	flag;
	zfs_group_cred_t	cred;
} zfs_group_dtl_setsecattr_t;

typedef struct zfs_group_dtl_setattr {
	uint64_t	zid;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	gen;
	xvattr_t	xvap;
	boolean_t	isvapcarry;	
	int	flag;
	zfs_group_cred_t	cred;
} zfs_group_dtl_setattr_t;

typedef struct zfs_group_dtl_rename {
	uint64_t	zid;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	gen;
	uint64_t	nzid;	/*new znode id*/
	uint64_t	nspa_id;
	uint64_t	nos_id;
	uint64_t	ngen;
	char	name[MAXNAMELEN];
	int		flag;
	char	newname[MAXNAMELEN];
	zfs_group_cred_t	cred;
	zfs_group_object_t old_group_id;
	zfs_group_object_t new_group_id;
} zfs_group_dtl_rename_t;

typedef struct zfs_group_dtl_dirquota {
	uint64_t	zid;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	obj_id;
	uint64_t	dir_gen;
	uint64_t	quota;
	char	path[1024];
	int		flag;
} zfs_group_dtl_dirquota_t;

typedef struct zfs_group_dtl_dirlowdata {
	uint64_t	zid;
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	obj_id;
	uint64_t	dir_gen;
	uint64_t	value;
	char	path[1024];
	char	propname[MAXNAMELEN];
	int		flag;
} zfs_group_dtl_dirlowdata_t;

typedef union zfs_group_dtl{
	zfs_group_dtl_create_t	create;
	zfs_group_dtl_mkdir_t	mkdir;
	zfs_group_dtl_symlink_t	symlink;
	zfs_group_dtl_link_t	link;
	zfs_group_dtl_remove_t	remove;
	zfs_group_dtl_rmdir_t	rmdir;
	zfs_group_dtl_setsecattr_t	setsecattr;
	zfs_group_dtl_setattr_t	setattr;
	zfs_group_dtl_rename_t	rename;
	zfs_group_dtl_dirquota_t	dirquota;
	zfs_group_dtl_dirlowdata_t	dirlowdata;
}zfs_group_dtl_t;

typedef struct zfs_group_dtl_thread {
	kthread_t		*z_group_dtl_thread;
	boolean_t		z_group_dtl_thr_exit;
	kmutex_t		z_group_dtl_lock;
	kcondvar_t		z_group_dtl_cv;
} zfs_group_dtl_thread_t;


typedef struct zfs_group_dtl_carrier{
	name_operation_t	z_op;
	uint64_t	z_magic;
	zfs_group_dtl_t	z_dtl;
}zfs_group_dtl_carrier_t;

extern	void zfs_group_dtl_load(objset_t *os);
extern	void zfs_group_dtl_sync_tree134(objset_t *os);
extern	void zfs_group_dtl_sync_tree2(objset_t *os, dmu_tx_t *ptx, int zfsvfs_holden);

extern	void zfs_group_dtl_create(avl_tree_t* ptree);
extern	void zfs_group_dtl_destroy(avl_tree_t* ptree);
extern	int zfs_get_dtltree_status(uint64_t *numarray, char* fs_name);
extern void zfs_group_dtl_reset(objset_t *os, dmu_tx_t *ptx);

extern void
zfs_group_dtl_add(avl_tree_t *ptree, void* value, size_t size);

extern zfs_group_dtl_carrier_t*
zfs_group_dtl_carry(name_operation_t z_op, znode_t *pzp,	char *name,
vattr_t *vap, int ex, int mode, void *multiplex1, cred_t *credp, int flag, void* multiplex2);

extern int
zfs_group_dtl_resolve(zfs_group_dtl_carrier_t *z_carrier, zfs_multiclus_node_type_t m_node_type);

extern cred_t *
zfs_group_getcred(zfs_group_cred_t *group_credp);

extern void start_zfs_group_dtl_thread(objset_t *os);
extern boolean_t stop_zfs_group_dtl_thread(objset_t *os);
extern void zfs_group_dtl_init_obj(objset_t *os, zfs_sb_t *zsb, uint64_t *pobj, int idx);

extern int debug_nas_group_dtl;

extern void zfs_group_dtl_test(char *fsname);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZFS_GROUP_DTL_H */

