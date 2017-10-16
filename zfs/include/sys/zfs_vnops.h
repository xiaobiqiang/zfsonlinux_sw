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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_FS_ZFS_VNOPS_H
#define	_SYS_FS_ZFS_VNOPS_H

#include <sys/vnode.h>
#include <sys/xvattr.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/fcntl.h>
#include <sys/pathname.h>
#include <sys/zpl.h>
#include <sys/zfs_vfsops.h>
#include <linux/dirent.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Extended file-system independent directory entry.  This style of
 * dirent provides additional informational flag bits for each
 * directory entry.  This dirent will be returned instead of the
 * standard dirent if a VOP_READDIR() requests dirent flags via
 * V_RDDIR_ENTFLAGS, and if the file system supports the flags.
 */
typedef struct edirent {
	u64			ed_ino;		/* "inode number" of entry */
	s64			ed_off;		/* offset of disk directory entry */
	uint32_t	ed_eflags;	/* per-entry flags */
	unsigned short	ed_reclen;	/* length of this record */
	char		ed_name[1];	/* name of file */
} edirent_t;

typedef struct client_os_info{
	uint64_t spa_id;
	uint64_t os_id;
}client_os_info_t;

struct ctx_struct {
	struct linux_dirent64 * current_dir;
	struct linux_dirent64 * previous;
	int count;
	int error;
};

#define	EDIRENT_RECLEN(namelen)	\
	((offsetof(edirent_t, ed_name[0]) + 1 + (namelen) + 7) & ~ 7)
#define	DIRENT64_RECLEN(namelen)	\
	((offsetof(struct linux_dirent64, d_name[0]) + 1 + (namelen) + 7) & ~ 7)
#define	EDIRENT_NAMELEN(reclen)	\
	((reclen) - (offsetof(edirent_t, ed_name[0])))
#define	DIRENT64_NAMELEN(reclen)	\
	((reclen) - (offsetof(struct linux_dirent64, d_name[0])))	
/*
 * Flags for VOP_READDIR
 */
#define	V_RDDIR_ENTFLAGS	0x01	/* request dirent flags */
#define	V_RDDIR_ACCFILTER	0x02	/* filter out inaccessible dirents */


extern int zfs_open(struct inode *ip, int mode, int flag, cred_t *cr);
extern int zfs_close(struct inode *ip, int flag, cred_t *cr);
extern int zfs_holey(struct inode *ip, int cmd, loff_t *off);
extern int zfs_read(struct inode *ip, uio_t *uio, int ioflag, cred_t *cr);
extern int zfs_write(struct inode *ip, uio_t *uio, int ioflag, cred_t *cr);
extern int zfs_access(struct inode *ip, int mode, int flag, cred_t *cr);
extern int zfs_lookup(struct inode *dip, char *nm, struct inode **ipp,
    int flags, cred_t *cr, int *direntflags, pathname_t *realpnp);
extern int zfs_create(struct inode *dip, char *name, vattr_t *vap, int excl,
    int mode, struct inode **ipp, cred_t *cr, int flag, vsecattr_t *vsecp, client_os_info_t *clientos);
extern int zfs_remove(struct inode *dip, char *name, cred_t *cr, int flags);
extern int zfs_mkdir(struct inode *dip, char *dirname, vattr_t *vap,
    struct inode **ipp, cred_t *cr, int flags, vsecattr_t *vsecp);
extern int zfs_rmdir(struct inode *dip, char *name, struct inode *cwd,
    cred_t *cr, int flags);
extern int zfs_readdir(struct inode *ip, struct dir_context *ctx, cred_t *cr, int flags);
extern int zfs_fsync(struct inode *ip, int syncflag, cred_t *cr);
extern int zfs_getattr(struct inode *ip, vattr_t *vap, int flag, cred_t *cr);
extern int zfs_getattr_fast(struct inode *ip, struct kstat *sp);
extern int zfs_setattr(struct inode *ip, vattr_t *vap, int flag, cred_t *cr);
extern int zfs_rename(struct inode *sdip, char *snm, struct inode *tdip,
    char *tnm, cred_t *cr, int flags);
extern int zfs_symlink(struct inode *dip, char *name, vattr_t *vap,
    char *link, struct inode **ipp, cred_t *cr, int flags);
extern int zfs_follow_link(struct dentry *dentry, struct nameidata *nd);
extern int zfs_readlink(struct inode *ip, uio_t *uio, cred_t *cr, int flags);
extern int zfs_link(struct inode *tdip, struct inode *sip,
    char *name, cred_t *cr, int flags);
extern void zfs_inactive(struct inode *ip);
extern int zfs_space(struct inode *ip, int cmd, flock64_t *bfp, int flag,
    offset_t offset, cred_t *cr);
extern int zfs_fid(struct inode *ip, fid_t *fidp);
extern int zfs_getsecattr(struct inode *ip, vsecattr_t *vsecp, int flag,
    cred_t *cr);
extern int zfs_setsecattr(struct inode *ip, vsecattr_t *vsecp, int flag,
    cred_t *cr);
extern int zfs_getpage(struct inode *ip, struct page *pl[], int nr_pages);
extern int zfs_putpage(struct inode *ip, struct page *pp,
    struct writeback_control *wbc);
extern int zfs_dirty_inode(struct inode *ip, int flags);
extern int zfs_map(struct inode *ip, offset_t off, caddr_t *addrp,
    size_t len, unsigned long vm_flags);
extern void zfs_iput_async(struct inode *ip);

extern boolean_t zfs_write_overquota(zfs_sb_t *zsb, struct znode *zp);
extern int zfs_readdir_server(struct inode *ip, uio_t *uio, cred_t *cr, int *eofp, int flags);

extern void zfs_fid_remove_master_info(zfs_sb_t *zsb, uint64_t zid, uint64_t gen, dmu_tx_t *tx);

extern int zfs_print_znode_info(char *path);
extern int zfs_enable_disable_double_data(boolean_t double_data);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_ZFS_VNOPS_H */
