#ifdef _KERNEL
#include <sys/types.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/taskq.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <sys/vmsystm.h>
#include <sys/atomic.h>
#include <vm/pvn.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/unistd.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_ioctl.h>
#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/spa.h>
#include <sys/txg.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/sa.h>
#include <sys/dirent.h>
#include <sys/policy.h>
#include <sys/sunddi.h>
#include <sys/sid.h>
#include "fs/fs_subr.h"
#include <sys/zfs_ctldir.h>
#include <sys/zfs_fuid.h>
#include <sys/zfs_sa.h>
#include <sys/dnlc.h>
#include <sys/zfs_rlock.h>
#include <sys/extdirent.h>
#include <sys/kidmap.h>
#include <sys/cred.h>
#include <sys/attr.h>
#include <sys/dmu_tx.h>
#include <sys/zfs_multiclus.h>
#include <sys/zfs_group.h>
#include <sys/zfs_group_sync.h>
#include <sys/zfs_vnops.h>
#include <sys/zfs_group_dtl.h>
#include <sys/zpl.h>
#include <linux/sort.h>
#include <linux/cred.h>


extern kmutex_t	multiclus_mtx;

#define	UID_NOBODY	60001		/* user ID no body */
#define	GID_NOBODY	UID_NOBODY

uint64_t group_create_seq = 0;
extern size_t zfs_group_max_dataseg_size;

int zfs_local_read_node(struct inode *src_ip, char *buf, ssize_t bufsiz,offset_t *offsize, uint64_t vflg,cred_t *cred, ssize_t *readen);
int zfs_migrate_dataA_to_dataB(znode_t *zp,zfs_group_data_msg_t *data,uint64_t vflg);
static int zmc_remote_write_node(struct inode* src_ip,zfs_group_object_t *dst ,char* data,ssize_t data_len,ssize_t offset, uint64_t ioflag, cred_t* cr, caller_context_t* ct);
int zfs_remote_write_node(struct inode * src_ip,uint64_t dst_spa,uint64_t dst_os, uint64_t dst_object,uio_t *uiop,ssize_t nbytes, uint64_t ioflag, cred_t* cr, caller_context_t* ct);
static int zmc_remote_updata_node(struct inode *ip, zfs_group_data_msg_t *data,vattr_t *vap,uint64_t flags);
int zfs_remote_update_node(struct inode *ip, void *ptr,uint64_t dst_spa,uint64_t dst_os,uint64_t dst_object, uint64_t flags, cred_t *credp,
   caller_context_t *ct);

static void zfs_group_build_data_header(objset_t *os,
    zfs_group_header_t *hdr, uint64_t cmd, share_flag_t wait_flag, 
    uint64_t op, uint64_t length, uint64_t out_length, uint64_t server_spa, 
    uint64_t server_os, uint64_t server_object, uint64_t master_object,
    uint64_t data_spa, uint64_t data_os, uint64_t data_object,
    msg_op_type_t op_type, msg_orig_type_t orig_type);



static void
zfs_group_v32_to_v(zfs_group_vattr_t *va32p, vattr_t *vap)
{
	bzero((void *)vap, sizeof (vattr_t));
	vap->va_mask = va32p->va_mask;		
	vap->va_mode = va32p->va_mode;

	vap->va_uid = va32p->va_uid;
	vap->va_gid = va32p->va_gid;
	vap->va_nlink = va32p->va_nlink;
	vap->va_size = va32p->va_rsize;
	vap->va_nblocks = va32p->va_nblocks;

	ZFS_GROUP_TIMESPEC_TO_TIMESPEC32(&vap->va_atime, &va32p->va_atime);
	ZFS_GROUP_TIMESPEC_TO_TIMESPEC32(&vap->va_mtime, &va32p->va_mtime);
	ZFS_GROUP_TIMESPEC_TO_TIMESPEC32(&vap->va_ctime, &va32p->va_ctime);
}


cred_t *
zfs_group_getcred(zfs_group_cred_t *group_credp)
{
	cred_t *cr;
	if ((unsigned int)(group_credp->cr_ruid) > MAXUID) {
		group_credp->cr_ruid = UID_NOBODY;
	}
	if ((unsigned int)(group_credp->cr_uid) > MAXUID) {
		group_credp->cr_uid = UID_NOBODY;
	}
	if ((unsigned int)(group_credp->cr_suid) > MAXUID) {
		group_credp->cr_suid = UID_NOBODY;
	}
	if ((unsigned int)(group_credp->cr_rgid) > MAXUID) {
		group_credp->cr_rgid = GID_NOBODY;
	}
	if ((unsigned int)(group_credp->cr_gid) > MAXUID) {
		group_credp->cr_gid = GID_NOBODY;
	}
	if ((unsigned int)(group_credp->cr_sgid) > MAXUID) {
		group_credp->cr_sgid = GID_NOBODY;
	}
//	cr = crget(); 
	revert_creds(get_cred(current_real_cred()));
	cr = prepare_creds();
	crsetresuid(cr, group_credp->cr_ruid, group_credp->cr_uid,
	    group_credp->cr_suid);
	crsetresgid(cr, group_credp->cr_rgid, group_credp->cr_gid,
	    group_credp->cr_sgid);
	sort(group_credp->cr_groups, group_credp->cr_ngroups, sizeof (gid_t), gidcmp, NULL);
	crsetgroups(cr, group_credp->cr_ngroups, group_credp->cr_groups);

	return (cr);
}


static void
zfs_group_to_xvattr(zfs_group_name_attr_t *zg_attr, xvattr_t *xvap)
{
	xoptattr_t *xoap = NULL;
	uint64_t *attrs;
//	uint64_t *crtime;
//	uint32_t *bitmap;
//	void *scanstamp;


	attrs = &zg_attr->zg_attr;
	xvap->xva_vattr.va_mask |= AT_XVATTR;
	if ((xoap = xva_getxoptattr(xvap)) == NULL) {
		xvap->xva_vattr.va_mask &= ~AT_XVATTR; /* shouldn't happen */
		return;
	}
	bcopy(zg_attr->zg_attr_bitmap, xvap->xva_reqattrmap, XVA_MAPSIZE*sizeof(uint32_t));
	xvap->xva_mapsize = zg_attr->zg_attr_masksize;
	xvap->xva_magic = zg_attr->zg_magic;

	if (XVA_ISSET_REQ(xvap, XAT_HIDDEN))
		xoap->xoa_hidden = ((*attrs & XAT0_HIDDEN) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_SYSTEM))
		xoap->xoa_system = ((*attrs & XAT0_SYSTEM) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_ARCHIVE))
		xoap->xoa_archive = ((*attrs & XAT0_ARCHIVE) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_READONLY))
		xoap->xoa_readonly = ((*attrs & XAT0_READONLY) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_IMMUTABLE))
		xoap->xoa_immutable = ((*attrs & XAT0_IMMUTABLE) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_NOUNLINK))
		xoap->xoa_nounlink = ((*attrs & XAT0_NOUNLINK) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_APPENDONLY))
		xoap->xoa_appendonly = ((*attrs & XAT0_APPENDONLY) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_NODUMP))
		xoap->xoa_nodump = ((*attrs & XAT0_NODUMP) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_OPAQUE))
		xoap->xoa_opaque = ((*attrs & XAT0_OPAQUE) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_AV_MODIFIED))
		xoap->xoa_av_modified = ((*attrs & XAT0_AV_MODIFIED) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_AV_QUARANTINED))
		xoap->xoa_av_quarantined =
		    ((*attrs & XAT0_AV_QUARANTINED) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_CREATETIME))
		ZFS_TIME_DECODE(&xoap->xoa_createtime, zg_attr->zg_ctime);
	if (XVA_ISSET_REQ(xvap, XAT_AV_SCANSTAMP))
		bcopy(zg_attr->zg_scan, xoap->xoa_av_scanstamp, AV_SCANSTAMP_SZ);
	if (XVA_ISSET_REQ(xvap, XAT_REPARSE))
		xoap->xoa_reparse = ((*attrs & XAT0_REPARSE) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_OFFLINE))
		xoap->xoa_offline = ((*attrs & XAT0_OFFLINE) != 0);
	if (XVA_ISSET_REQ(xvap, XAT_SPARSE))
		xoap->xoa_sparse = ((*attrs & XAT0_SPARSE) != 0);
}

void zfs_group_to_acl(zfs_group_name_acl_t *zg_acl, vsecattr_t *vsap)
{
	char *tmp_acl;
	vsap->vsa_mask = zg_acl->mask;
	vsap->vsa_aclcnt = zg_acl->aclcnt;
	vsap->vsa_dfaclcnt = zg_acl->dfaclcnt;
	vsap->vsa_aclentsz = zg_acl->aclsz;
	vsap->vsa_aclflags = zg_acl->aclflags;
	tmp_acl = zg_acl->acls;
	if (zg_acl->aclsz > 0) {
		vsap->vsa_aclentp =
		    kmem_zalloc(zg_acl->aclsz, KM_SLEEP);
		bcopy(tmp_acl, vsap->vsa_aclentp,
		    zg_acl->aclsz);
		tmp_acl += vsap->vsa_aclcnt * sizeof(aclent_t);
	}
}

static void zfs_group_free_acl(vsecattr_t *vsap)
{
	if (vsap->vsa_aclentsz > 0 && vsap->vsa_aclentp != NULL)
		kmem_free(vsap->vsa_aclentp, vsap->vsa_aclentsz);
}

static int zfs_group_acl(znode_t *zp,
    zfs_group_name_acl_t *zg_acl, cred_t *cred, uint64_t *zg_acl_len, uint64_t flags)
{
	int error;
	vsecattr_t *vsap;
	vsap = kmem_zalloc(sizeof(vsecattr_t), KM_SLEEP);
	if (zg_acl->set) {
		zfs_group_to_acl(zg_acl, vsap);
//		error = VOP_SETSECATTR(ZTOV(zp), vsap, flags, cred, NULL);
		error = zfs_setsecattr(ZTOI(zp), vsap, flags, cred);
		*zg_acl_len = 0;
	} else {
		vsap->vsa_mask = zg_acl->mask;
//		error = VOP_GETSECATTR(ZTOV(zp), vsap, flags, cred, NULL);
		error = zfs_getsecattr(ZTOI(zp), vsap, flags, cred);
		if (error == 0) {
			zfs_group_from_acl(zg_acl, vsap);
			*zg_acl_len = sizeof(zfs_group_name_acl_t) + vsap->vsa_aclentsz;
		} else {
			*zg_acl_len = 0;
		}
	}

	zfs_group_free_acl(vsap);
	kmem_free(vsap, sizeof(vsecattr_t));

	return (error);
}

static void zfs_group_set_create_extra(char *extra_cp, size_t namesize, char *name,
    size_t xvatsize, xvattr_t *xattrp, size_t aclsize, vsecattr_t **vsapp,
    uint64_t *dirlowdata, size_t dirlowdatasize)
{
//	uint64_t seq;
	size_t tmp_extra_len;
	char *tmp_extra_cp;

	zfs_group_name_attr_t *zg_attr;
	zfs_group_name_acl_t *zg_acl;
	uint64_t *zg_dlow;
	vsecattr_t *vsap;

	tmp_extra_cp = extra_cp;
	tmp_extra_len = 0;
	if (namesize > 0) {
		bcopy(extra_cp, name, namesize);
		tmp_extra_len += namesize;
	}

	if (xvatsize > 0) {
		zg_attr = (zfs_group_name_attr_t *)(extra_cp + tmp_extra_len);
		zfs_group_to_xvattr(zg_attr, xattrp);
		tmp_extra_len += xvatsize;
	}

	if (aclsize > 0){
		zg_acl = (zfs_group_name_acl_t *)(extra_cp + tmp_extra_len);
		vsap = kmem_zalloc(sizeof(vsecattr_t), KM_SLEEP);
		zfs_group_to_acl(zg_acl, vsap);
		*vsapp = vsap;
		tmp_extra_len += aclsize;
    }

	if (dirlowdatasize > 0) {
		zg_dlow = (uint64_t *)(extra_cp + tmp_extra_len);
		*dirlowdata = *zg_dlow;
	}
}

int zfs_group_process_create_data_file(znode_t *dzp, uint64_t master_object,
	uint64_t master_gen, znode_t **zpp, uint64_t *dirlowdata, vattr_t *vap)
{
	int error, txtype; //, err_meta_tx;
	boolean_t waited;
	zfs_group_object_t group_object;

	vattr_t va;
	zfs_acl_ids_t acl_ids;

	zfs_sb_t *zsb;
	znode_t *zp;
	dmu_tx_t *tx;
	objset_t *os;

	zp = NULL;
	waited = B_FALSE;
	zsb = ZTOZSB(dzp);

top:
	bzero(&group_object, sizeof(zfs_group_object_t));
	bzero(&va, sizeof(vattr_t));
	bzero(&acl_ids, sizeof(zfs_acl_ids_t));

	os = zsb->z_os;
	va.va_mode = vap->va_mode;
	va.va_type = VREG;
	va.va_mode = va.va_mode | S_IRWXU | S_IRWXG | S_IRWXO;
	va.va_mask = AT_MODE;
	if (zsb->z_replay) {
		va.va_nodeid = vap->va_nodeid;
		va.va_ctime = vap->va_ctime;		/* see zfs_replay_create() */
		va.va_nblocks = vap->va_nblocks;
	}
	error = zfs_acl_ids_create(dzp, 0, &va, kcred, NULL, &acl_ids);
	if (error) {
		return (error);
	}
	
	group_object.master_spa = os->os_master_spa;
	group_object.master_objset = os->os_master_os;
	group_object.master_object = master_object;
	group_object.master_gen = master_gen;

	group_object.master2_spa = -1;
	group_object.master2_objset = -1;
	group_object.master2_object = -1;
	group_object.master2_gen = 0;

	group_object.master3_spa = -1;
	group_object.master3_objset = -1;
	group_object.master3_object = -1;
	group_object.master3_gen = 0;

	group_object.master4_spa = -1;
	group_object.master4_objset = -1;
	group_object.master4_object = -1;
	group_object.master4_gen = 0;

	group_object.data_spa = spa_guid(dmu_objset_spa(os));
	group_object.data_objset = dmu_objset_id(os);

	tx = dmu_tx_create(os);
	dmu_tx_hold_sa_create(tx, ZFS_SA_BASE_ATTR_SIZE);
	error = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (error) {
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
            zfs_acl_ids_free(&acl_ids);
			goto top;
		}
		zfs_acl_ids_free(&acl_ids);
		dmu_tx_abort(tx);
		return (error);
	}
	zfs_mknode(dzp, &va, tx, kcred, 0, &zp, &acl_ids);
	VERIFY(zp != NULL);
	zp->z_links ++;
	zp->z_unlinked = 0;
	group_object.data_object = zp->z_id;

	bcopy(ZIL_LOG_DATA_FILE_NAME, zp->z_filename, strlen(ZIL_LOG_DATA_FILE_NAME)+1);
	sa_update(zp->z_sa_hdl, SA_ZPL_FILENAME(ZTOZSB(zp)),
							zp->z_filename, MAXNAMELEN, tx);

	sa_update(zp->z_sa_hdl, SA_ZPL_LINKS(zsb),
		    &zp->z_links, sizeof (zp->z_links), tx);
	sa_update(zp->z_sa_hdl, SA_ZPL_DIRLOWDATA(ZTOZSB(zp)),
 		    dirlowdata, 8, tx);
	zfs_sa_set_remote_object(zp, &group_object, tx);
	txtype = zfs_log_create_txtype(Z_FILE, NULL, vap);
//	err_meta_tx = zfs_log_create(zfsvfs->z_log, tx, txtype, dzp, zp, ZIL_LOG_DATA_FILE_NAME, NULL, NULL, vap);
	(void)zfs_log_create(zsb->z_log, tx, txtype, dzp, zp, ZIL_LOG_DATA_FILE_NAME, NULL, NULL, vap);
	dmu_tx_commit(tx);
	if(zp->z_group_id.master_spa == 0 && zp->z_group_id.master_objset == 0
		&& zp->z_group_id.master_object == 0 && zp->z_group_id.data_spa == 0
		&& zp->z_group_id.data_objset == 0 && zp->z_group_id.data_object == 0){
			cmn_err(CE_WARN, "[corrupt group object] %s %s %d",
				__FILE__, __func__, __LINE__);
	}
/*
	if ( err_meta_tx ){
		txg_wait_synced(dmu_objset_pool(zsb->z_os), 0);
	}
*/
	*zpp = zp;
	zfs_acl_ids_free(&acl_ids);
	if (group_object.data_spa == 0 ||
		group_object.data_objset == 0 ||
		group_object.data_object == 0) {
		cmn_err(CE_WARN, "%s line(%d) spa=%"PRIu64" objset=%"PRIu64" object=%"PRIu64"\n", __func__, __LINE__, 
			group_object.data_spa, group_object.data_objset, group_object.data_object);
	}
	return (error);
}


int zfs_group_process_remove_data_file(zfs_sb_t *zsb, znode_t *dzp,
    uint64_t object, uint64_t dirquota)
{
	int err, err_meta_tx;
	boolean_t b_delete;
	boolean_t waited = B_FALSE;

	struct inode *ip;
	znode_t *zp;
	dmu_tx_t *tx;
	uint64_t acl_obj;

	err = zfs_zget(zsb, object, &zp);
	if (err != 0)
		return (err);

	ip = ZTOI(zp);
	top:
/*
	mutex_enter(&vp->v_lock);
	b_delete = vp->v_count == 1 && !vn_has_cached_data(vp);
	mutex_exit(&vp->v_lock);
*/
	b_delete = (atomic_read(&ip->i_count) == 1);

	tx = dmu_tx_create(zsb->z_os);

	if (b_delete) {
		dmu_tx_hold_free(tx, zp->z_id, 0,DMU_OBJECT_END);
	}

	mutex_enter(&zp->z_lock);
	if ((acl_obj = zfs_external_acl(zp)) != 0 && b_delete)
		dmu_tx_hold_free(tx, acl_obj, 0, DMU_OBJECT_END);
	mutex_exit(&zp->z_lock);

	dmu_tx_hold_zap(tx, zsb->z_unlinkedobj, FALSE, NULL);

	err = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (err != 0) {
		if (err == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		iput(ip);
		return (err);
	}

	mutex_enter(&zp->z_lock);

	if (dirquota && zfs_get_overquota(zsb, dirquota)) {
		err = zfs_set_overquota(zsb, dirquota, B_FALSE, B_FALSE, tx);
		if (err) {
			dmu_tx_commit(tx);	
			iput(ip);
			return err;
		}
	}

//	b_delete = vp->v_count == 1 && !vn_has_cached_data(vp);
	b_delete = (atomic_read(&ip->i_count) == 1);

//	vp->v_count--;
	atomic_dec(&ip->i_count);

	zp->z_unlinked = B_TRUE;
	zp->z_links = 0;
	sa_update(zp->z_sa_hdl,SA_ZPL_LINKS(zsb),
		&zp->z_links, sizeof (zp->z_links), tx);
	if (b_delete) {
//		ASSERT3U(vp->v_count, ==, 0);
		
//		mutex_exit(&vp->v_lock);
		mutex_exit(&zp->z_lock);
		zfs_znode_delete(zp, tx);
	}else {
		cmn_err(CE_WARN, "file is using, adding delete queue");
		if( ENOENT == zap_lookup_int(zsb->z_os, zsb->z_unlinkedobj, zp->z_id)){
			zfs_unlinked_add(zp, tx);
		}
//		mutex_exit(&vp->v_lock);
		mutex_exit(&zp->z_lock);
	}
//	err_meta_tx = zfs_log_remove(zfsvfs->z_log, tx, TX_REMOVE, dzp, ZIL_LOG_DATA_FILE_NAME, object);
	err_meta_tx = zfs_log_remove(zsb->z_log, tx, TX_REMOVE, dzp, ZIL_LOG_DATA_FILE_NAME, object);
	dmu_tx_commit(tx);
	if ( err_meta_tx ){
		txg_wait_synced(dmu_objset_pool(zsb->z_os), 0);
	}

	return (err);
}


static int zfs_group_process_create(zfs_group_header_t *msg_header, zfs_msg_t *msg_data, znode_t *dzp,
    cred_t *cred)
{
	int err;
	uint64_t flag;
	char *cp;
	struct inode *ip;
	size_t cp_len;
	char name[MAXNAMELEN];
//	char new_name[MAXNAMELEN];
//	caller_context_t ct;
//	zfs_group_object_t group_object;
	zfs_sb_t *zsb;

	znode_t *zp;

	vsecattr_t *vsap;
	xvattr_t *xattrp;
	uint64_t *dirlowdata = NULL;
//	zfs_group_name_attr_t *zg_attr;
//	zfs_group_name_acl_t *zg_acl;

	zfs_group_name_create_t *createp;
	zfs_group_name2_t *n2p;
	zfs_group_name_t *np;

	uint64_t client_spa;
	uint64_t client_os;
	client_os_info_t *clientosinfo = NULL;

	client_spa = msg_header->client_spa;
	client_os = msg_header->client_os;

	vsap = NULL;
	xattrp = kmem_zalloc(sizeof(xvattr_t), KM_SLEEP);
	xattrp->xva_rtnattrmapp = &(xattrp->xva_rtnattrmap)[0];
	dirlowdata = kmem_zalloc(sizeof(uint64_t), KM_SLEEP);

	np = &msg_data->call.name;
	n2p = (zfs_group_name2_t *)np;

	flag = np->flags;
	flag |= FCLUSTER;
	createp = &np->arg.p.create;
	cp = np->component;
	cp_len = 0;

	zsb = ZTOZSB(dzp);

	zfs_group_v32_to_v(&createp->vattr, &xattrp->xva_vattr);
	zfs_group_set_create_extra(cp, createp->name_len, name, createp->xattr_len,
        xattrp, createp->acl_len, &vsap, dirlowdata, createp->dirlowdata_len);

	if (msg_header->orig_type == APP_USER) {
		
//		ct.cc_sysid = BF64_GET(client_spa, 32, 32);
//		ct.cc_pid = BF64_GET(client_spa, 0, 32);
//		ct.cc_caller_id = client_os;
		clientosinfo = kmem_zalloc(sizeof(client_os_info_t), KM_SLEEP);
		clientosinfo->spa_id = client_spa;
		clientosinfo->os_id = client_os;
//		err = VOP_CREATE(ZTOV(dzp), name, &xattrp->xva_vattr,
//		    createp->ex, createp->mode, &vp, cred, flag, &ct, vsap);
		err = zfs_create(ZTOI(dzp), name, &xattrp->xva_vattr,
		    createp->ex, createp->mode, &ip, cred, flag, vsap, clientosinfo);
		if (err != 0) {
			cmn_err(CE_WARN, "Create (%s) fails(error:%lld) from user",
			    name, (longlong_t)err);
			goto error;
		}

		zp = ITOZ(ip);
		if (zp->z_group_id.data_spa == 0 ||
			zp->z_group_id.data_objset == 0 || 
			zp->z_group_id.data_object == 0) {
			cmn_err(CE_WARN, "%s line(%d) spa=%"PRIu64" objset=%"PRIu64" object=%"PRIu64"\n", __func__, __LINE__, 
				zp->z_group_id.data_spa, zp->z_group_id.data_objset, zp->z_group_id.data_object);
		}
	} else {
		err = zfs_group_process_create_data_file(dzp, msg_header->master_object,
				createp->master_gen, &zp, dirlowdata, &xattrp->xva_vattr);
		if (err != 0) {
			cmn_err(CE_WARN, "create data file(%s) fails", name);
		} else {
			ip = ZTOI(zp);
			if (zp->z_group_id.data_spa == 0 ||
				zp->z_group_id.data_objset == 0 || 
				zp->z_group_id.data_object == 0) {
				cmn_err(CE_WARN, "%s line(%d) spa=%"PRIu64" objset=%"PRIu64" object=%"PRIu64"\n", __func__, __LINE__, 
					zp->z_group_id.data_spa, zp->z_group_id.data_objset, zp->z_group_id.data_object);
			}
		}
	}
	if (err != 0)
		goto error;

	n2p->nrec.object_id = zp->z_group_id;
	if(n2p->nrec.object_id.master_spa == 0 && n2p->nrec.object_id.master_objset == 0
		&& n2p->nrec.object_id.master_object == 0 && n2p->nrec.object_id.data_spa == 0
		&& n2p->nrec.object_id.data_objset == 0 && n2p->nrec.object_id.data_object == 0){
			cmn_err(CE_WARN, "[corrupt group object] %s %s %d, msg->hdr.orig_type %llu",
				__FILE__, __func__, __LINE__, (unsigned long long)msg_header->orig_type);
	}
	zfs_group_znode_copy_phys(zp, &n2p->nrec.object_phy, B_FALSE);

	iput(ip);
	error:
	kmem_free(xattrp, sizeof(xvattr_t));
	kmem_free(dirlowdata, sizeof(uint64_t));
	kmem_free(clientosinfo, sizeof(client_os_info_t));
	if (vsap != NULL) {
		zfs_group_free_acl(vsap);
		kmem_free(vsap, sizeof(vsecattr_t));
	}

	return (err);
}

static int update_z_group_id(zfs_group_header_t *msg_header, zfs_msg_t *msg_data, znode_t *zp)
{
	int err = 0;
	zfs_sb_t *zsb = NULL;

	zfs_group_name2_t *n2p;
	zfs_group_name_t *np;

	uint64_t client_spa;
	uint64_t client_os;

	dmu_tx_t *tx = NULL;
	char buf[MAXNAMELEN];
	uint64_t map_obj = 0;

	client_spa = msg_header->client_spa;
	client_os = msg_header->client_os;


	np = &msg_data->call.name;
	n2p = (zfs_group_name2_t *)np;

	zsb = ZTOZSB(zp);


	/* in MasterX, it always takes itself as the master */
	zp->z_group_id.master_spa = msg_header->server_spa;
	zp->z_group_id.master_objset = msg_header->server_os;
	zp->z_group_id.master_object = zp->z_id;
	zp->z_group_id.master_gen = zp->z_gen;

	/*
	 * info that always the same among each Master
	 */
	zp->z_group_id.data_spa = msg_header->data_spa;
	zp->z_group_id.data_objset = msg_header->data_os;
	zp->z_group_id.data_object = msg_header->data_object;
	zp->z_group_id.data2_spa = msg_header->data2_spa;
	zp->z_group_id.data2_objset = msg_header->data2_os;
	zp->z_group_id.data2_object = msg_header->data2_object;

	/*
	 * info that different among each Master
	 */
	zp->z_group_id.master2_spa = msg_header->master2_spa;
	zp->z_group_id.master2_objset = msg_header->master2_os;
	zp->z_group_id.master2_object = msg_header->master2_object;
	zp->z_group_id.master2_gen = msg_header->master2_gen;

	zp->z_group_id.master3_spa = msg_header->master3_spa;
	zp->z_group_id.master3_objset = msg_header->master3_os;
	zp->z_group_id.master3_object = msg_header->master3_object;
	zp->z_group_id.master3_gen = msg_header->master3_gen;

	zp->z_group_id.master4_spa = msg_header->master4_spa;
	zp->z_group_id.master4_objset = msg_header->master4_os;
	zp->z_group_id.master4_object = msg_header->master4_object;
	zp->z_group_id.master4_gen = msg_header->master4_gen;

	/*
	 * update masterX info based on the creating master type
	 */
	switch(msg_header->m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			zp->z_group_id.master2_spa = msg_header->client_spa;
			zp->z_group_id.master2_objset = msg_header->client_os;
			zp->z_group_id.master2_object = msg_header->client_object;
			zp->z_group_id.master2_gen = msg_header->master_gen;
			break;

		case ZFS_MULTICLUS_MASTER3:
			zp->z_group_id.master3_spa = msg_header->client_spa;
			zp->z_group_id.master3_objset = msg_header->client_os;
			zp->z_group_id.master3_object = msg_header->client_object;
			zp->z_group_id.master3_gen = msg_header->master_gen;
			break;

		case ZFS_MULTICLUS_MASTER4:
			zp->z_group_id.master4_spa = msg_header->client_spa;
			zp->z_group_id.master4_objset = msg_header->client_os;
			zp->z_group_id.master4_object = msg_header->client_object;
			zp->z_group_id.master4_gen = msg_header->master_gen;
			break;

		default:
			return EINVAL;
	}

	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if(err != 0){
		dmu_tx_abort(tx);
		return err;
	}
	mutex_enter(&zp->z_lock);
	VERIFY(0 == sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zsb),
					&zp->z_group_id, sizeof (zp->z_group_id), tx));
	mutex_exit(&zp->z_lock);
	mutex_enter(&zsb->z_lock);

	switch(msg_header->m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			sprintf(buf, zfs_group_map_key_name_prefix_format, 
				zp->z_group_id.master2_spa, zp->z_group_id.master2_objset, 
				zp->z_group_id.master2_object, zp->z_group_id.master2_gen & ZFS_GROUP_GEN_MASK);
			map_obj = zsb->z_group_map_objs[zp->z_group_id.master2_object%NASGROUP_MAP_NUM];
			break;
		case ZFS_MULTICLUS_MASTER3:
			sprintf(buf, zfs_group_map_key_name_prefix_format, 
				zp->z_group_id.master3_spa, zp->z_group_id.master3_objset, 
				zp->z_group_id.master3_object, zp->z_group_id.master3_gen & ZFS_GROUP_GEN_MASK);
			map_obj = zsb->z_group_map_objs[zp->z_group_id.master3_object%NASGROUP_MAP_NUM];
			break;
		case ZFS_MULTICLUS_MASTER4:
			sprintf(buf, zfs_group_map_key_name_prefix_format, 
				zp->z_group_id.master4_spa, zp->z_group_id.master4_objset, 
				zp->z_group_id.master4_object, zp->z_group_id.master4_gen & ZFS_GROUP_GEN_MASK);
			map_obj = zsb->z_group_map_objs[zp->z_group_id.master4_object%NASGROUP_MAP_NUM];
			break;
		default:
			mutex_exit(&zsb->z_lock);
			dmu_tx_commit(tx);
			return EINVAL;
	}
	
	if(map_obj != 0){
		err = zap_update(zsb->z_os, map_obj, buf, 8, 1, &zp->z_group_id.master_object, tx);
		if(err != 0){
			cmn_err(CE_WARN, "[Error] %s Failed in updating zfs_group_map_key %s", __func__, buf);
			mutex_exit(&zsb->z_lock);
			dmu_tx_commit(tx);
			return err;
		}
	}
	

	mutex_exit(&zsb->z_lock);
	dmu_tx_commit(tx);

	/* info returned to Master node */
	switch(msg_header->m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			n2p->nrec.object_id.master2_spa = zp->z_group_id.master_spa;
			n2p->nrec.object_id.master2_objset = zp->z_group_id.master_objset;
			n2p->nrec.object_id.master2_object = zp->z_id;
			n2p->nrec.object_id.master2_gen = zp->z_gen;
			break;

		case ZFS_MULTICLUS_MASTER3:
			n2p->nrec.object_id.master3_spa = zp->z_group_id.master_spa;
			n2p->nrec.object_id.master3_objset = zp->z_group_id.master_objset;
			n2p->nrec.object_id.master3_object = zp->z_id;
			n2p->nrec.object_id.master3_gen = zp->z_gen;
			break;

		case ZFS_MULTICLUS_MASTER4:
			n2p->nrec.object_id.master4_spa = zp->z_group_id.master_spa;
			n2p->nrec.object_id.master4_objset = zp->z_group_id.master_objset;
			n2p->nrec.object_id.master4_object = zp->z_id;
			n2p->nrec.object_id.master4_gen = zp->z_gen;
			break;

		default:
			return EINVAL;
	}
	
	return (err);
}


static int zfs_group_process_create_backup(zfs_group_header_t *msg_header, zfs_msg_t *msg_data, znode_t *dzp,
    cred_t *cred)
{
	int err = 0;
	uint64_t flag;
	char *cp;
//	vnode_t *vp;
	struct inode *ip;
	size_t cp_len;
	char name[MAXNAMELEN];
//	char new_name[MAXNAMELEN];
//	caller_context_t ct;
	zfs_sb_t *zsb = NULL;

	znode_t *zp;

	vsecattr_t *vsap;
	xvattr_t *xattrp;
	uint64_t *dirlowdata = NULL;
//	zfs_group_name_attr_t *zg_attr;
//	zfs_group_name_acl_t *zg_acl;

	zfs_group_name_create_t *createp;
	zfs_group_name2_t *n2p;
	zfs_group_name_t *np;

	uint64_t client_spa;
	uint64_t client_os;
	uint64_t map_obj = 0;
	dmu_tx_t *tx = NULL;
	char buf[MAXNAMELEN];
	client_os_info_t *clientosinfo = NULL;

	client_spa = msg_header->client_spa;
	client_os = msg_header->client_os;

	vsap = NULL;
	xattrp = kmem_zalloc(sizeof(xvattr_t), KM_SLEEP);
	xattrp->xva_rtnattrmapp = &(xattrp->xva_rtnattrmap)[0];
	dirlowdata = kmem_zalloc(sizeof(uint64_t), KM_SLEEP);

	np = &msg_data->call.name;
	n2p = (zfs_group_name2_t *)np;

	flag = np->flags;
	flag |= FCLUSTER;
	createp = &np->arg.p.create;
	cp = np->component;
	cp_len = 0;

	zsb = ZTOZSB(dzp);


	zfs_group_v32_to_v(&createp->vattr, &xattrp->xva_vattr);
	zfs_group_set_create_extra(cp, createp->name_len, name, createp->xattr_len,
        xattrp, createp->acl_len, &vsap, dirlowdata, createp->dirlowdata_len);

	if (msg_header->orig_type == APP_USER) {
//		ct.cc_sysid = BF64_GET(client_spa, 32, 32);
//		ct.cc_pid = BF64_GET(client_spa, 0, 32);
//		ct.cc_caller_id = client_os;
		clientosinfo = kmem_zalloc(sizeof(client_os_info_t), KM_SLEEP);
		clientosinfo->spa_id = client_spa;
		clientosinfo->os_id = client_os;

		flag |= FBackupMaster;
//		err = VOP_CREATE(ZTOV(dzp), name, &xattrp->xva_vattr,
//		    createp->ex, createp->mode, &vp, cred, flag, &ct, vsap);
		err = zfs_create(ZTOI(dzp), name, &xattrp->xva_vattr,
		    createp->ex, createp->mode, &ip, cred, flag, vsap, clientosinfo);
		if (err != 0) {
			cmn_err(CE_WARN, "Create (%s) fails(error:%lld) from user",
			    name, (longlong_t)err);
			goto error;
		}

		zp = ITOZ(ip);
		/* in MasterX, it always takes itself as the master */
		zp->z_group_id.master_spa = msg_header->server_spa;
		zp->z_group_id.master_objset = msg_header->server_os;
		zp->z_group_id.master_object = zp->z_id;
		zp->z_group_id.master_gen = zp->z_gen;
			
		/*
		 * info that always the same among each Master
		 */
		zp->z_group_id.data_spa = msg_header->data_spa;
		zp->z_group_id.data_objset = msg_header->data_os;
		zp->z_group_id.data_object = msg_header->data_object;
		zp->z_group_id.data2_spa = msg_header->data2_spa;
		zp->z_group_id.data2_objset = msg_header->data2_os;
		zp->z_group_id.data2_object = msg_header->data2_object;

		/*
		 * info that different among each Master
		 */
		zp->z_group_id.master2_spa = msg_header->master2_spa;
		zp->z_group_id.master2_objset = msg_header->master2_os;
		zp->z_group_id.master2_object = msg_header->master2_object;
		zp->z_group_id.master2_gen = msg_header->master2_gen;

		zp->z_group_id.master3_spa = msg_header->master3_spa;
		zp->z_group_id.master3_objset = msg_header->master3_os;
		zp->z_group_id.master3_object = msg_header->master3_object;
		zp->z_group_id.master3_gen = msg_header->master3_gen;

		zp->z_group_id.master4_spa = msg_header->master4_spa;
		zp->z_group_id.master4_objset = msg_header->master4_os;
		zp->z_group_id.master4_object = msg_header->master4_object;
		zp->z_group_id.master4_gen = msg_header->master4_gen;

		/*
		 * update masterX info based on the creating master type
		 */
		switch(msg_header->m_node_type)
		{
			case ZFS_MULTICLUS_MASTER2:

				zp->z_group_id.master2_spa = msg_header->client_spa;
				zp->z_group_id.master2_objset = msg_header->client_os;
				zp->z_group_id.master2_object = msg_header->client_object;
				zp->z_group_id.master2_gen = msg_header->master_gen;

				break;

			case ZFS_MULTICLUS_MASTER3:

				zp->z_group_id.master3_spa = msg_header->client_spa;
				zp->z_group_id.master3_objset = msg_header->client_os;
				zp->z_group_id.master3_object = msg_header->client_object;
				zp->z_group_id.master3_gen = msg_header->master_gen;

				break;

			case ZFS_MULTICLUS_MASTER4:

				zp->z_group_id.master4_spa = msg_header->client_spa;
				zp->z_group_id.master4_objset = msg_header->client_os;
				zp->z_group_id.master4_object = msg_header->client_object;
				zp->z_group_id.master4_gen = msg_header->master_gen;

				break;

			default:
				iput(ip);
				err = EINVAL;
				goto error;
		}	

		tx = dmu_tx_create(zsb->z_os);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if(err != 0){
			dmu_tx_abort(tx);
			iput(ip);
			goto error;
		}
		mutex_enter(&zp->z_lock);
		VERIFY(0 == sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zsb),
						&zp->z_group_id, sizeof (zp->z_group_id), tx));
		mutex_exit(&zp->z_lock);

		mutex_enter(&zsb->z_lock);

		bzero(buf, MAXNAMELEN);

	
		switch(msg_header->m_node_type)
		{
			case ZFS_MULTICLUS_MASTER2:
				sprintf(buf, zfs_group_map_key_name_prefix_format, 
					zp->z_group_id.master2_spa, zp->z_group_id.master2_objset, 
					zp->z_group_id.master2_object, zp->z_group_id.master2_gen & ZFS_GROUP_GEN_MASK);
				map_obj = zsb->z_group_map_objs[zp->z_group_id.master2_object%NASGROUP_MAP_NUM];
				break;
			case ZFS_MULTICLUS_MASTER3:
				sprintf(buf, zfs_group_map_key_name_prefix_format, 
					zp->z_group_id.master3_spa, zp->z_group_id.master3_objset, 
					zp->z_group_id.master3_object, zp->z_group_id.master3_gen & ZFS_GROUP_GEN_MASK);
				map_obj = zsb->z_group_map_objs[zp->z_group_id.master3_object%NASGROUP_MAP_NUM];
				break;
			case ZFS_MULTICLUS_MASTER4:
				sprintf(buf, zfs_group_map_key_name_prefix_format, 
					zp->z_group_id.master4_spa, zp->z_group_id.master4_objset, 
					zp->z_group_id.master4_object, zp->z_group_id.master4_gen & ZFS_GROUP_GEN_MASK);
				map_obj = zsb->z_group_map_objs[zp->z_group_id.master4_object%NASGROUP_MAP_NUM];
				break;
			default:
				mutex_exit(&zsb->z_lock);
				dmu_tx_commit(tx);
				iput(ip);
				err = EINVAL;
				goto error;
		}
	
		if(map_obj != 0){
			err = zap_update(zsb->z_os, map_obj, buf, 8, 1, &zp->z_group_id.master_object, tx);
			if(err != 0){
				cmn_err(CE_WARN, "[Error] %s Failed in updating zfs_group_map_key %s, map_obj %llu", 
					__func__, buf, (unsigned long long)map_obj);
			}else if(debug_nas_group_dtl == 2){
				cmn_err(CE_WARN, "[INFO] %s Succeed in updating zfs_group_map_key %s, map_obj %llu", 
					__func__, buf, (unsigned long long)map_obj);
			}
		}else{
			if(debug_nas_group_dtl == 2){
				cmn_err(CE_WARN, "[INFO] %s %d, %s, %llu, %llu, %llu", 
					__func__, __LINE__,buf, (unsigned long long)(zp->z_group_id.master2_object%NASGROUP_MAP_NUM),
					(unsigned long long)(zp->z_group_id.master3_object%NASGROUP_MAP_NUM),
					(unsigned long long)(zp->z_group_id.master4_object%NASGROUP_MAP_NUM));
			}
		}
		
		mutex_exit(&zsb->z_lock);
		dmu_tx_commit(tx);
	} else {
		cmn_err(CE_WARN, "[Error] %s, %d, msg->hdr.orig_type is not APP_USER!", __func__, __LINE__);
		goto error;
	}


	/* info returned to Master node */
	switch(msg_header->m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			n2p->nrec.object_id.master2_spa = zp->z_group_id.master_spa;
			n2p->nrec.object_id.master2_objset = zp->z_group_id.master_objset;
			n2p->nrec.object_id.master2_object = zp->z_id;
			n2p->nrec.object_id.master2_gen = zp->z_gen;
			break;

		case ZFS_MULTICLUS_MASTER3:
			n2p->nrec.object_id.master3_spa = zp->z_group_id.master_spa;
			n2p->nrec.object_id.master3_objset = zp->z_group_id.master_objset;
			n2p->nrec.object_id.master3_object = zp->z_id;
			n2p->nrec.object_id.master3_gen = zp->z_gen;
			break;

		case ZFS_MULTICLUS_MASTER4:
			n2p->nrec.object_id.master4_spa = zp->z_group_id.master_spa;
			n2p->nrec.object_id.master4_objset = zp->z_group_id.master_objset;
			n2p->nrec.object_id.master4_object = zp->z_id;
			n2p->nrec.object_id.master4_gen = zp->z_gen;
			break;

		default:
			iput(ip);
			err = EINVAL;
			goto error;
	}
	iput(ip);

error:
	kmem_free(xattrp, sizeof(xvattr_t));
	kmem_free(dirlowdata, sizeof(uint64_t));
	kmem_free(clientosinfo, sizeof(client_os_info_t));
	if (vsap != NULL) {
		zfs_group_free_acl(vsap);
		kmem_free(vsap, sizeof(vsecattr_t));
	}

	return (err);
}


static int zfs_group_process_mkdir(zfs_msg_t *msg_data, znode_t *dzp, cred_t *cred)
{
	int err;
	uint64_t flag;
	char *cp;
	struct inode *ip;
	size_t cp_len;
	char name[MAXNAMELEN];
//	caller_context_t ct;

	znode_t *zp;

	vsecattr_t *vsap;
	xvattr_t *xattrp;
//	zfs_group_name_attr_t *zg_attr;
//	zfs_group_name_acl_t *zg_acl;

	zfs_group_name_mkdir_t *mkdirp;
	zfs_group_name2_t *n2p;
	zfs_group_name_t *np;

	vsap = NULL;
	xattrp = kmem_zalloc(sizeof(xvattr_t), KM_SLEEP);
	xattrp->xva_rtnattrmapp = &(xattrp->xva_rtnattrmap)[0];

	np = &msg_data->call.name;
	n2p = (zfs_group_name2_t *)np;

	flag = np->flags;
	flag |= FCLUSTER;
	mkdirp = &np->arg.p.mkdir;
	cp = np->component;
	cp_len = 0;

	zfs_group_v32_to_v(&mkdirp->vattr, &xattrp->xva_vattr);
	zfs_group_set_create_extra(cp, mkdirp->name_len, name, mkdirp->xattr_len,
        xattrp, mkdirp->acl_len, &vsap, NULL, 0);

//	err = VOP_MKDIR(ZTOV(dzp), name, (vattr_t *)xattrp,
//			    &vp, cred, NULL, flag, vsap);
	err = zfs_mkdir(ZTOI(dzp), name, (vattr_t *)xattrp,
			    &ip, cred, flag, vsap);

	if (err != 0)
		goto error;

	zp = ITOZ(ip);
	bcopy(&zp->z_group_id, &n2p->nrec.object_id, sizeof(zfs_group_object_t));
	zfs_group_znode_copy_phys(zp, &n2p->nrec.object_phy, B_FALSE);
	iput(ip);

	error:
	kmem_free(xattrp, sizeof(xvattr_t));
	if (vsap != NULL) {
		zfs_group_free_acl(vsap);
		kmem_free(vsap, sizeof(vsecattr_t));
	}

	return (err);
}

static int zfs_group_process_mkdir_backup(zfs_group_header_t *msg_header, zfs_msg_t *msg_data, znode_t *dzp, cred_t *cred)
{
	int err;
	uint64_t flag;
	char *cp;
	struct inode *ip;
	size_t cp_len;
	char name[MAXNAMELEN];
//	caller_context_t ct;
//	zfs_group_object_t group_object;

	znode_t *zp;

	vsecattr_t *vsap;
	xvattr_t *xattrp;
//	zfs_group_name_attr_t *zg_attr;
//	zfs_group_name_acl_t *zg_acl;

	zfs_group_name_mkdir_t *mkdirp;
	zfs_group_name2_t *n2p;
	zfs_group_name_t *np;
	uint64_t map_obj = 0;
	dmu_tx_t *tx = NULL;
	zfs_sb_t *zsb = NULL;

	char buf[MAXNAMELEN];

	zsb = ZTOZSB(dzp);

	vsap = NULL;
	xattrp = kmem_zalloc(sizeof(xvattr_t), KM_SLEEP);
	xattrp->xva_rtnattrmapp = &(xattrp->xva_rtnattrmap)[0];

	np = &msg_data->call.name;
	n2p = (zfs_group_name2_t *)np;

	flag = np->flags;
	flag |= FCLUSTER;
	flag |= FBackupMaster;
	mkdirp = &np->arg.p.mkdir;
	cp = np->component;
	cp_len = 0;

	zfs_group_v32_to_v(&mkdirp->vattr, &xattrp->xva_vattr);
	zfs_group_set_create_extra(cp, mkdirp->name_len, name, mkdirp->xattr_len,
        xattrp, mkdirp->acl_len, &vsap, NULL, 0);

//	err = VOP_MKDIR(ZTOV(dzp), name, (vattr_t *)xattrp,
//			    &vp, cred, NULL, flag, vsap);

	err = zfs_mkdir(ZTOI(dzp), name, (vattr_t *)xattrp,
			    &ip, cred, flag, vsap);
	if (err != 0)
		goto error;
	
	zp = ITOZ(ip);

	zp->z_group_id.master_spa = msg_header->server_spa;
	zp->z_group_id.master_objset = msg_header->server_os;
	zp->z_group_id.master_object = zp->z_id;
	zp->z_group_id.master_gen = zp->z_gen;

	zp->z_group_id.data_spa = msg_header->data_spa;
	zp->z_group_id.data_objset = msg_header->data_os;
	zp->z_group_id.data_object = msg_header->data_object;
	zp->z_group_id.data2_spa = msg_header->data2_spa;
	zp->z_group_id.data2_objset = msg_header->data2_os;
	zp->z_group_id.data2_object = msg_header->data2_object;

	zp->z_group_id.master2_spa = msg_header->master2_spa;
	zp->z_group_id.master2_objset = msg_header->master2_os;
	zp->z_group_id.master2_object = msg_header->master2_object;
	zp->z_group_id.master2_gen = msg_header->master2_gen;
	
	zp->z_group_id.master3_spa = msg_header->master3_spa;
	zp->z_group_id.master3_objset = msg_header->master3_os;
	zp->z_group_id.master3_object = msg_header->master3_object;
	zp->z_group_id.master3_gen = msg_header->master3_gen;
	
	zp->z_group_id.master4_spa = msg_header->master4_spa;
	zp->z_group_id.master4_objset = msg_header->master4_os;
	zp->z_group_id.master4_object = msg_header->master4_object;
	zp->z_group_id.master4_gen = msg_header->master4_gen;

	switch(msg_header->m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:

			zp->z_group_id.master2_spa = msg_header->client_spa;
			zp->z_group_id.master2_objset = msg_header->client_os;
			zp->z_group_id.master2_object = msg_header->client_object;
			zp->z_group_id.master2_gen = msg_header->master_gen;

			break;

		case ZFS_MULTICLUS_MASTER3:

			zp->z_group_id.master3_spa = msg_header->client_spa;
			zp->z_group_id.master3_objset = msg_header->client_os;
			zp->z_group_id.master3_object = msg_header->client_object;
			zp->z_group_id.master3_gen = msg_header->master_gen;

			break;

		case ZFS_MULTICLUS_MASTER4:

			zp->z_group_id.master4_spa = msg_header->client_spa;
			zp->z_group_id.master4_objset = msg_header->client_os;
			zp->z_group_id.master4_object = msg_header->client_object;
			zp->z_group_id.master4_gen = msg_header->master_gen;

			break;

		default:
			iput(ip);
			err = EINVAL;
			goto error;
	}

	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if(err != 0){
		dmu_tx_abort(tx);
		iput(ip);
		goto error;
	}
	mutex_enter(&zp->z_lock);
	VERIFY(0 == sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zsb),
					&zp->z_group_id, sizeof (zp->z_group_id), tx));
	mutex_exit(&zp->z_lock);
	mutex_enter(&zsb->z_lock);

	bzero(buf, MAXNAMELEN);
	switch(msg_header->m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			sprintf(buf, zfs_group_map_key_name_prefix_format, 
				zp->z_group_id.master2_spa, zp->z_group_id.master2_objset, 
				zp->z_group_id.master2_object, zp->z_group_id.master2_gen & ZFS_GROUP_GEN_MASK);
			map_obj = zsb->z_group_map_objs[zp->z_group_id.master2_object%NASGROUP_MAP_NUM];
			break;
		case ZFS_MULTICLUS_MASTER3:
			sprintf(buf, zfs_group_map_key_name_prefix_format, 
				zp->z_group_id.master3_spa, zp->z_group_id.master3_objset, 
				zp->z_group_id.master3_object, zp->z_group_id.master3_gen & ZFS_GROUP_GEN_MASK);
			map_obj = zsb->z_group_map_objs[zp->z_group_id.master3_object%NASGROUP_MAP_NUM];
			break;
		case ZFS_MULTICLUS_MASTER4:
			sprintf(buf, zfs_group_map_key_name_prefix_format, 
				zp->z_group_id.master4_spa, zp->z_group_id.master4_objset, 
				zp->z_group_id.master4_object, zp->z_group_id.master4_gen & ZFS_GROUP_GEN_MASK);
			map_obj = zsb->z_group_map_objs[zp->z_group_id.master4_object%NASGROUP_MAP_NUM];
			break;
		default:
			mutex_exit(&zsb->z_lock);
			dmu_tx_commit(tx);
			iput(ip);
			err = EINVAL;
			goto error;
	}
	if(map_obj != 0){
		err = zap_update(zsb->z_os, map_obj, buf, 8, 1, &zp->z_group_id.master_object, tx);
		if(err != 0){
			cmn_err(CE_WARN, "[Error] %s Failed in updating zfs_group_map_key %s", __func__, buf);
		}
	}
	mutex_exit(&zsb->z_lock);
	dmu_tx_commit(tx);

	bcopy(&zp->z_group_id, &n2p->nrec.object_id, sizeof(zfs_group_object_t));
	zfs_group_znode_copy_phys(zp, &n2p->nrec.object_phy, B_FALSE);

	switch(msg_header->m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			n2p->nrec.object_id.master2_spa = zp->z_group_id.master_spa;
			n2p->nrec.object_id.master2_objset = zp->z_group_id.master_objset;;
			n2p->nrec.object_id.master2_object = zp->z_id;
			n2p->nrec.object_id.master2_gen = zp->z_gen;
			break;
		case ZFS_MULTICLUS_MASTER3:
			n2p->nrec.object_id.master3_spa = zp->z_group_id.master_spa;
			n2p->nrec.object_id.master3_objset = zp->z_group_id.master_objset;
			n2p->nrec.object_id.master3_object = zp->z_id;
			n2p->nrec.object_id.master3_gen = zp->z_gen;
			break;
		case ZFS_MULTICLUS_MASTER4:
			n2p->nrec.object_id.master4_spa = zp->z_group_id.master_spa;
			n2p->nrec.object_id.master4_objset = zp->z_group_id.master_objset;
			n2p->nrec.object_id.master4_object = zp->z_id;
			n2p->nrec.object_id.master4_gen = zp->z_gen;
			break;
		default:
			iput(ip);
			err = EINVAL;
			goto error;
	}

	iput(ip);

error:
	kmem_free(xattrp, sizeof(xvattr_t));
	if (vsap != NULL) {
		zfs_group_free_acl(vsap);
		kmem_free(vsap, sizeof(vsecattr_t));
	}

	return (err);
}


static int zfs_group_process_remove(zfs_msg_t *msg_data, znode_t *dzp, cred_t *cred)
{
	int error;
//	int		zflg = ZEXISTS;
	uint64_t flag;
	znode_t *zp;
	zfs_group_name_t *np = &msg_data->call.name;
	zfs_group_name2_t *n2p = (zfs_group_name2_t *)np;
	zfs_dirlock_t *dl;

	flag = np->flags |FCLUSTER;
	if (!zfs_dirent_lock(&dl, dzp, np->component, &zp, ZEXISTS, NULL, NULL)) {
		n2p->nrec.object_id = zp->z_group_id;
		zfs_group_znode_copy_phys(zp, &n2p->nrec.object_phy, B_TRUE);
		d_prune_aliases(ZTOI(zp));
		zfs_dirent_unlock(dl);
		iput(ZTOI(zp));
	}	
//	error = VOP_REMOVE(ZTOV(dzp), np->component, cred, NULL, flag);	
 	error = zfs_remove(ZTOI(dzp), np->component, cred, flag);
	if (error != 0 && error != ENOENT) {
		cmn_err(CE_WARN, "Failed to remove file, file = %s, err: %d", np->component, error);
	}
	return (error);
}

static int zfs_group_process_remove_backup(zfs_msg_t *msg_data, znode_t *dzp, cred_t *cred)
{
	int error;
	uint64_t flag;
	zfs_group_name_t *np = &msg_data->call.name;
	zfs_sb_t *zsb = NULL;

	zsb = ZTOZSB(dzp);
	flag = np->flags |FCLUSTER;

	flag |= FBackupMaster;
	
//	error = VOP_REMOVE(ZTOV(dzp), np->component, cred,
//	    NULL, flag);
	error = zfs_remove(ZTOI(dzp), np->component, cred, flag);
	if (error != 0) {
		cmn_err(CE_WARN, "Failed to remove backup file, file = %s, err: %d", np->component, error);
	}
	return (error);
}


static int zfs_group_process_name_request(zfs_group_server_para_t *server_para)
{
	int	error = 1;
	uint64_t	client_spa = 0;
	uint64_t	object = 0;
	uint64_t	flags = 0;
	znode_t	*zp = NULL;
	znode_t	*dzp = NULL;
	cred_t	*cred = NULL;
	zfs_sb_t *zsb = NULL;
	zfs_msg_t	*msg_data = server_para->msg_data;
	zfs_group_header_t	*msg_header = server_para->msg_header;
	zfs_group_name_t	*np = &msg_data->call.name;
	zfs_group_name2_t	*n2p = NULL;

	union {
		vattr_t vattr;
		vsecattr_t vsecattr;
	} v;

	zsb = zfs_sb_group_hold(msg_header->server_spa, msg_header->server_os, FTAG, B_TRUE);
	if (zsb == NULL)
		return (EGHOLD);
	if (msg_header->orig_type == APP_USER) {
			object = np->parent_object.master_object;
			error = zfs_zget(zsb, object, &dzp);				
		if (error) {
			zfs_sb_group_rele(zsb, FTAG);
			return (error);
		}

		if (np->arg.dirlowdata != 0 && dzp->z_dirlowdata == 0) {
			dzp->z_dirlowdata = np->arg.dirlowdata;
		}

		if (np->arg.dirquota != 0 && dzp->z_dirquota == 0) {
			dzp->z_dirquota = np->arg.dirquota;
		}

		if (np->arg.bquota != 0 && dzp->z_bquota == 0) {
			dzp->z_bquota = np->arg.bquota;
		}
		
	} else {
		object = zsb->z_root;
		error = zfs_zget(zsb, object, &dzp);
		if (error) {
			cmn_err(CE_WARN," create data some error");
			zfs_sb_group_rele(zsb, FTAG);
			return (error);
		}
	}


	client_spa = msg_header->client_spa;
	n2p = (zfs_group_name2_t *)np;
	flags = np->flags;
	cred = zfs_group_getcred(&np->cred);
	switch (msg_header->operation) {

	case NAME_CREATE:
		error = zfs_group_process_create(msg_header, msg_data, dzp, cred);
	break;

	case NAME_REMOVE_DATA:
		error = zfs_group_process_remove_data_file(zsb, dzp, 
		    msg_header->server_object, np->arg.dirquota);
	break;

	case NAME_REMOVE:
	    error = zfs_group_process_remove(msg_data, dzp, cred);
	break;


	case NAME_RMDIR: {		
		int 	zflg = ZEXISTS;
		znode_t *zp;
		zfs_dirlock_t *dl;
		flags |= FCLUSTER;
		if (!zfs_dirent_lock(&dl, dzp, np->component, &zp, zflg, NULL, NULL)) {
			n2p->nrec.object_id = zp->z_group_id;
			zfs_group_znode_copy_phys(zp, &n2p->nrec.object_phy, B_TRUE);
			d_prune_aliases(ZTOI(zp));
			zfs_dirent_unlock(dl);
			iput(ZTOI(zp));
		}

//		error = VOP_RMDIR(ZTOV(dzp), np->component, NULL, cred, NULL, flags);
		error = zfs_rmdir(ZTOI(dzp), np->component, NULL, cred, flags);
	}
	break;


	case NAME_MKDIR:
		error = zfs_group_process_mkdir(msg_data, dzp, cred);
	break;

	case NAME_LOOKUP: {
		struct inode *ip;
		pathname_t	rpn;
		zfs_group_pathname_t *gpn;
		boolean_t get_rpn = np->arg.b_get_rpn;
		gpn = vmem_zalloc(sizeof(zfs_group_pathname_t), KM_SLEEP);
		bzero(&rpn, sizeof(pathname_t));
		bzero(gpn, sizeof(zfs_group_pathname_t));
//		pn_alloc(&rpn);
		rpn.pn_path = rpn.pn_buf = vmem_zalloc(MAXPATHLEN, KM_SLEEP);
		rpn.pn_pathlen = 0;
		rpn.pn_bufsize = MAXPATHLEN;


		flags |= FCLUSTER;
//		error = VOP_LOOKUP(ZTOV(dzp), np->component, &vp, NULL, flags,
//		    NULL,cred, NULL, NULL, get_rpn ? &rpn : NULL);
		error = zfs_lookup(ZTOI(dzp), np->component, &ip, flags,
		    cred, NULL, get_rpn ? &rpn : NULL);

		if (error != 0) {
//			pn_free(&rpn);
			vmem_free(rpn.pn_buf, rpn.pn_bufsize);
			rpn.pn_path = rpn.pn_buf = NULL;
			rpn.pn_pathlen = rpn.pn_bufsize = 0;
			goto error;
		}

		zp = ITOZ(ip);

		if (dzp->z_dirquota != 0 || dzp->z_bquota) {
			zp->z_overquota = zfs_overquota(zsb, zp, dzp->z_dirquota);
		}

		zfs_group_znode_copy_phys(zp, &n2p->nrec.object_phy, B_FALSE);
		if (zp->z_id == zsb->z_root) {
			n2p->nrec.object_id.master_spa = spa_guid(dmu_objset_spa(zsb->z_os));
			n2p->nrec.object_id.master_objset = dmu_objset_id(zsb->z_os);
			n2p->nrec.object_id.master_object = zsb->z_root;
		} else {
			bcopy(&zp->z_group_id, &n2p->nrec.object_id, sizeof(zfs_group_object_t));
		}

		if (get_rpn) {
			(void) strlcpy(gpn->pn_buf, rpn.pn_buf, rpn.pn_bufsize);
			gpn->pn_bufsize = rpn.pn_bufsize;
			gpn->pn_pathlen = rpn.pn_pathlen;
			bcopy(gpn, &n2p->nrec.rpn, sizeof(zfs_group_pathname_t));
		}
//		pn_free(&rpn);
		vmem_free(rpn.pn_buf, rpn.pn_bufsize);
		vmem_free(gpn, sizeof(zfs_group_pathname_t));
		rpn.pn_path = rpn.pn_buf = NULL;
		rpn.pn_pathlen = rpn.pn_bufsize = 0;
		iput(ip);
	}
	break;

	case NAME_RENAME : {
		znode_t *tdzp;
		flags |= FCLUSTER;
		if ((error = zfs_zget(zsb, np->arg.p.rename.new_parent_id.master_object,
		    &tdzp)) != 0) {
			goto error;
		}
//		VOP_RENAME(ZTOV(dzp), np->component, ZTOV(tdzp),
//		    &np->component[MAXNAMELEN], cred, NULL, flags);
		zfs_rename(ZTOI(dzp), np->component, ZTOI(tdzp),
		    &np->component[MAXNAMELEN], cred, flags);
		iput(ZTOI(tdzp));
	}
	break;


	case NAME_LINK: {
		znode_t *zp;
		flags |= FCLUSTER;
		object = np->arg.p.link.id.master_object;
		if ((error = zfs_zget(zsb, object,
		    &zp)) != 0) {
			goto error;
		}

//		error = VOP_LINK(ZTOV(dzp), ZTOV(zp), np->component, cred, NULL, flags);
//		VN_RELE(ZTOV(zp));
		error = zfs_link(ZTOI(dzp), ZTOI(zp), np->component, cred, flags);
		iput(ZTOI(zp));
	}
	break;
		
	case NAME_SYMLINK: {
		struct inode *ip;
		znode_t *zp;
		flags |= FCLUSTER;
		zfs_group_v32_to_v(&np->arg.p.symlink.vattr, &v.vattr);
		
//		error = VOP_SYMLINK(ZTOV(dzp), np->component,
//		    &v.vattr, &np->component[MAXNAMELEN], cred, NULL, flags);
		error = zfs_symlink(ZTOI(dzp), np->component, &v.vattr, 
			&np->component[MAXNAMELEN], &ip, cred, flags);

		zp = ITOZ(ip);
		bcopy(&zp->z_group_id, &n2p->nrec.object_id, sizeof(zfs_group_object_t));
		zfs_group_znode_copy_phys(zp, &n2p->nrec.object_phy, B_FALSE);
		iput(ip);
	}
	break;

	case NAME_ACL: {
		uint64_t mask;
		uint64_t zg_acl_len = 0;
		zfs_group_name_acl_t *zg_acl = NULL;
		flags |= FCLUSTER;
		zg_acl = (zfs_group_name_acl_t *)np->component;
		mask = zg_acl->mask;
		if (zg_acl->set) {
			error = zfs_group_acl(dzp, zg_acl, cred, &zg_acl_len, flags);
			bcopy(zg_acl, &n2p->component, sizeof(zfs_group_name_acl_t));
		} else {
			zg_acl = (zfs_group_name_acl_t *)n2p->component;
			zg_acl->mask = mask;
			error = zfs_group_acl(dzp, zg_acl, cred, &zg_acl_len, flags);
		}
		msg_header->out_length = 
			offsetof(zfs_group_name2_t, component) +
			    zg_acl_len + sizeof(zfs_group_header_t);
	}
	break;

	default:
	break;
	}

	error:
//	crfree(cred);
	abort_creds(cred);
	iput(ZTOI(dzp));
	zfs_sb_group_rele(zsb, FTAG);
	return (error);
}

static int zfs_group_process_create_data(zfs_group_header_t *msg_header, zfs_msg_t *msg_data, znode_t *dzp,
    cred_t *cred)
{
	int err;
//	int error;
	uint64_t flag;
	char *cp;
	struct inode *ip;
	size_t cp_len;
	char name[MAXNAMELEN];
	zfs_sb_t *zsb;
	dmu_tx_t* tx = NULL;

	znode_t *zp;

	vsecattr_t *vsap;
	xvattr_t *xattrp;
	uint64_t *dirlowdata = NULL;

	zfs_group_name_create_t *createp;
	zfs_group_name2_t *n2p;
	zfs_group_name_t *np;

	uint64_t client_spa;
	uint64_t client_os;

	client_spa = msg_header->client_spa;
	client_os = msg_header->client_os;

	vsap = NULL;
	xattrp = kmem_zalloc(sizeof(xvattr_t), KM_SLEEP);
	xattrp->xva_rtnattrmapp = &(xattrp->xva_rtnattrmap)[0];
	dirlowdata = kmem_zalloc(sizeof(uint64_t), KM_SLEEP);

	np = &msg_data->call.name;
	n2p = (zfs_group_name2_t *)np;

	flag = np->flags;
	flag |= FCLUSTER;
	createp = &np->arg.p.create;
	cp = np->component;
	cp_len = 0;

	zsb = ZTOZSB(dzp);

	zfs_group_v32_to_v(&createp->vattr, &xattrp->xva_vattr);
	zfs_group_set_create_extra(cp, createp->name_len, name, createp->xattr_len,
        xattrp, createp->acl_len, &vsap, dirlowdata, createp->dirlowdata_len);

	err = zfs_group_process_create_data_file(dzp, msg_header->master_object,
			createp->master_gen, &zp, dirlowdata, &xattrp->xva_vattr);
	if (err == 0) {			
		ip = ZTOI(zp);
	} else {
		goto error;
	}
	
	/* sync data's master info */
	zp->z_group_id.master_spa = msg_header->master_spa;
	zp->z_group_id.master_objset = msg_header->master_os;
	zp->z_group_id.master_object = msg_header->master_object;
	zp->z_group_id.master_gen = msg_header->master_gen;
	
	zp->z_group_id.master2_spa = msg_header->master2_spa;
	zp->z_group_id.master2_objset = msg_header->master2_os;
	zp->z_group_id.master2_object = msg_header->master2_object;
	zp->z_group_id.master2_gen = msg_header->master2_gen;
	
	zp->z_group_id.master3_spa = msg_header->master3_spa;
	zp->z_group_id.master3_objset = msg_header->master3_os;
	zp->z_group_id.master3_object = msg_header->master3_object;
	zp->z_group_id.master3_gen = msg_header->master3_gen;
	
	zp->z_group_id.master4_spa = msg_header->master4_spa;
	zp->z_group_id.master4_objset = msg_header->master4_os;
	zp->z_group_id.master4_object = msg_header->master4_object;
	zp->z_group_id.master4_gen = msg_header->master4_gen;
	
	zp->z_group_id.data_status = DATA_NODE_DIRTY;

	/* save master info */
	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err != 0) {
		dmu_tx_abort(tx);
		iput(ZTOI(zp));
		return err;
	}
	
	mutex_enter(&(zp->z_lock));
	err = sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zsb),
		&(zp->z_group_id), sizeof(zfs_group_object_t), tx);
	mutex_exit(&(zp->z_lock));
	
	dmu_tx_commit(tx);

	n2p->nrec.object_id = zp->z_group_id;
	if(n2p->nrec.object_id.master_spa == 0 && n2p->nrec.object_id.master_objset == 0
		&& n2p->nrec.object_id.master_object == 0 && n2p->nrec.object_id.data_spa == 0
		&& n2p->nrec.object_id.data_objset == 0 && n2p->nrec.object_id.data_object == 0){
			cmn_err(CE_WARN, "[corrupt group object] %s %s %d, msg->hdr.orig_type %llu",
				__FILE__, __func__, __LINE__, (unsigned long long)msg_header->orig_type);
	}
	zfs_group_znode_copy_phys(zp, &n2p->nrec.object_phy, B_FALSE);

	iput(ip);
	
	error:
	kmem_free(xattrp, sizeof(xvattr_t));
	kmem_free(dirlowdata, sizeof(uint64_t));
	if (vsap != NULL) {
		zfs_group_free_acl(vsap);
		kmem_free(vsap, sizeof(vsecattr_t));
	}

	return (err);
}



static int zfs_group_process_name_backup_request(zfs_group_server_para_t *server_para)
{
	int	error = 1;
//	int	client_ord = 0;
//	uint64_t	vflg = 0;
//	uint64_t	client_spa = 0;
//	uint64_t	dspa = 0;
//	uint64_t	dos = 0;
	uint64_t	object = 0;
	uint64_t	flags = 0;
	uint64_t	gen = 0;
//	uint64_t	dgen = 0;
	znode_t	*zp = NULL;
	znode_t	*dzp = NULL;
	cred_t	*cred = 0;
	zfs_sb_t  *zsb = NULL;
	zfs_msg_t	*msg_data = server_para->msg_data;
	zfs_dirlock_t	*dl = NULL;
	zfs_group_header_t	*msg_header = server_para->msg_header;
	zfs_group_name_t	*np = &msg_data->call.name;
	zfs_group_name2_t	*n2p = NULL;

	union {
		vattr_t vattr;
		vsecattr_t vsecattr;
	} v;

	zsb = zfs_sb_group_hold(msg_header->server_spa, msg_header->server_os, FTAG, B_TRUE);
	if (zsb == NULL)
		return (EGHOLD);
	if (msg_header->orig_type == APP_USER) {
		switch(msg_header->m_node_type)
		{
			case ZFS_MULTICLUS_MASTER2:
				object = np->parent_object.master2_object;
				gen = np->parent_object.master2_gen;
				break;
			case ZFS_MULTICLUS_MASTER3:
				object = np->parent_object.master3_object;
				gen = np->parent_object.master3_gen;
				break;
			case ZFS_MULTICLUS_MASTER4:
				object = np->parent_object.master4_object;
				gen = np->parent_object.master4_gen;
				break;
			default:
				zfs_sb_group_rele(zsb, FTAG);
				cmn_err(CE_WARN, "[Error] %s %d", __func__, __LINE__);
				return (EINVAL);
		}
		
		if(object == 0){
			object = zsb->z_root;
			gen = -1;
			if(1 == debug_nas_group_dtl){
				cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
			}
		}
		error = zfs_zget(zsb, object, &dzp);
		if (error) {
			zfs_sb_group_rele(zsb, FTAG);	
			cmn_err(CE_WARN, "[Error] %s %d", __func__, __LINE__);
			return (error);
		} else if (gen != -1 && dzp->z_gen != gen) {
			if(1 == debug_nas_group_dtl){
				cmn_err(CE_WARN, "[Error] %s %d dzp->gen 0x%llx, gen 0x%llx", 
					__func__, __LINE__, (unsigned long long)dzp->z_gen, (unsigned long long)gen);
			}
			iput(ZTOI(dzp));
			zfs_sb_group_rele(zsb, FTAG);
			return ENOENT;
		}
				
	} else if (msg_header->orig_type == APP_GROUP) {
		/* when sync data,and get one data node = NULL */
		object = zsb->z_root;
		error = zfs_zget(zsb, object, &dzp);
		if (error) {
			cmn_err(CE_WARN,"[Error] %s %d,", __func__, __LINE__);
			zfs_sb_group_rele(zsb, FTAG);
			return (error);
		}
	} else {
		zfs_sb_group_rele(zsb, FTAG);
		cmn_err(CE_WARN, "[Error] %s %d, msg->hdr.orig_type must be APP_USER. or APP_GROUP", __func__, __LINE__);
		return (error);
	}


	n2p = (zfs_group_name2_t *)np;
	flags = np->flags;
	cred = zfs_group_getcred(&np->cred);
	switch (msg_header->operation) {
		case NAME_CREATE_DATA:
			zfs_group_process_create_data(msg_header, msg_data, dzp, cred);
		break;
		case NAME_CREATE:
			error = zfs_group_process_create_backup(msg_header, msg_data, dzp, cred);
		break;

		case NAME_REMOVE:
		    error = zfs_group_process_remove_backup(msg_data, dzp, cred);
		break;

		case NAME_RMDIR: {
			flags |= FCLUSTER;
			flags |= FBackupMaster;
	//		error = VOP_RMDIR(ZTOV(dzp), np->component, NULL, cred, NULL, flags);
			error = zfs_rmdir(ZTOI(dzp), np->component, NULL, cred, flags);
		}
		break;

		case NAME_MKDIR:
			error = zfs_group_process_mkdir_backup(msg_header, msg_data, dzp, cred);
		break;

		case NAME_RENAME : {
			znode_t *tdzp;
			flags |= FCLUSTER;
			flags |= FBackupMaster;

			switch(msg_header->m_node_type)
			{
				case ZFS_MULTICLUS_MASTER2:
					object = np->arg.p.rename.new_parent_id.master2_object;
					gen =  np->arg.p.rename.new_parent_id.master2_gen;
					break;
				case ZFS_MULTICLUS_MASTER3:
					object = np->arg.p.rename.new_parent_id.master3_object;
					gen =  np->arg.p.rename.new_parent_id.master3_gen;
					break;
				case ZFS_MULTICLUS_MASTER4:
					object = np->arg.p.rename.new_parent_id.master4_object;
					gen =  np->arg.p.rename.new_parent_id.master4_gen;
					break;
				default:
					cmn_err(CE_WARN, "[Error] %s %d", __func__, __LINE__);
					error = EINVAL;
					goto error;
			}
		
			if(object == 0){
				object = zsb->z_root;
				gen = -1;
			}
		
			if ((error = zfs_zget(zsb, object,&tdzp)) != 0) {
				goto error;
			}else if(gen != -1 && tdzp->z_gen != gen){
				if(1 == debug_nas_group_dtl){
					cmn_err(CE_WARN, "[Error] %s %d tdzp->gen 0x%llx, gen 0x%llx", 
						__func__, __LINE__, (unsigned long long)tdzp->z_gen, (unsigned long long)gen);
				}
				iput(ZTOI(tdzp));
				error = ENOENT;
				goto error;
			}
	//		VOP_RENAME(ZTOV(dzp), np->component, ZTOV(tdzp),
	//		    &np->component[MAXNAMELEN], cred, NULL, flags);
			zfs_rename(ZTOI(dzp), np->component, ZTOI(tdzp),
			    &np->component[MAXNAMELEN], cred, flags);
			iput(ZTOI(tdzp));
		}
		break;


		case NAME_LINK: {
			znode_t *zp;
			flags |= FCLUSTER;
			flags |= FBackupMaster;
			
			switch(msg_header->m_node_type)
			{
				case ZFS_MULTICLUS_MASTER2:
					object = np->arg.p.link.id.master2_object;
					gen =  np->arg.p.link.id.master2_gen;
					break;
				case ZFS_MULTICLUS_MASTER3:
					object = np->arg.p.link.id.master3_object;
					gen =  np->arg.p.link.id.master3_gen;
					break;
				case ZFS_MULTICLUS_MASTER4:
					object = np->arg.p.link.id.master4_object;
					gen =  np->arg.p.link.id.master4_gen;
					break;
				default:
					error = EINVAL;
					goto error;
			}
			
			if ((error = zfs_zget(zsb, object, &zp)) != 0) {
				goto error;
			}else if(zp->z_gen != gen){
				if(1 == debug_nas_group_dtl){
					cmn_err(CE_WARN, "[Error] %s %d zp->gen 0x%llx, gen 0x%llx", 
						__func__, __LINE__, (unsigned long long)zp->z_gen, (unsigned long long)gen);
				}
				error = ENOENT;
				iput(ZTOI(zp));
				goto error;
			}

//			error = VOP_LINK(ZTOV(dzp), ZTOV(zp), np->component, cred, NULL, flags);
			error = zfs_link(ZTOI(dzp), ZTOI(zp), np->component, cred, flags);
			iput(ZTOI(zp));
		}
		break;
		
		case NAME_SYMLINK: {
			struct inode *ip;		
			flags |= FCLUSTER;
			flags |= FBackupMaster;
			zfs_group_v32_to_v(&np->arg.p.symlink.vattr, &v.vattr);
	//		error = VOP_SYMLINK(ZTOV(dzp), np->component,
	//		    &v.vattr, &np->component[MAXNAMELEN], cred, NULL, flags);
			error = zfs_symlink(ZTOI(dzp), np->component, &v.vattr, 
				&np->component[MAXNAMELEN], &ip, cred, flags);
			iput(ip);

			error = zfs_dirent_lock(&dl, dzp, np->component, &zp, 0,
			    NULL, NULL);
			if(error == 0){
				update_z_group_id(msg_header, msg_data, zp);
				zfs_dirent_unlock(dl);
			}else{
				cmn_err(CE_WARN, "[ERROR] %s %d", __func__, __LINE__);
			}
		
		}
		break;

		case NAME_ACL: {
			uint64_t mask;
			uint64_t zg_acl_len = 0;
			zfs_group_name_acl_t *zg_acl = NULL;
			flags |= FCLUSTER;
			zg_acl = (zfs_group_name_acl_t *)np->component;
			mask = zg_acl->mask;
			if (zg_acl->set) {
				flags |= FBackupMaster;
				error = zfs_group_acl(dzp, zg_acl, cred, &zg_acl_len, flags);
				bcopy(zg_acl, &n2p->component, sizeof(zfs_group_name_acl_t));
			} else {
				zg_acl = (zfs_group_name_acl_t *)n2p->component;
				zg_acl->mask = mask;
				error = zfs_group_acl(dzp, zg_acl, cred, &zg_acl_len, flags);
			}
			msg_header->out_length = 
				offsetof(zfs_group_name2_t, component) +
				    zg_acl_len + sizeof(zfs_group_header_t);
		}
		break;

		default:
		break;
	}

error:
//	crfree(cred);
	abort_creds(cred);
	iput(ZTOI(dzp));
	zfs_sb_group_rele(zsb, FTAG);
	return (error);
}


static int zfs_group_dup_iov(iovec_t **dst_iov, 
    iovec_t *s_iovec, uint64_t s_iovec_count)
{
	int i;
	iovec_t *tmp_iovp;
	tmp_iovp = kmem_zalloc(sizeof(iovec_t) * s_iovec_count, KM_SLEEP);
	for (i = 0; i < s_iovec_count; i ++) {
		bcopy(&s_iovec[i], &tmp_iovp[i], sizeof(iovec_t));
	}

	*dst_iov = tmp_iovp;
	return (s_iovec_count * sizeof(iovec_t));
}


static int zfs_group_process_data_request(zfs_group_server_para_t *server_para)
{
	int	error = 0;
	uint64_t	vflg = 0;
//	uint64_t	client_spa = 0;
//	uint64_t	dspa = 0;
//	uint64_t	dos = 0;
	uint64_t	object = 0;
	cred_t	*cred = NULL;
	znode_t	*zp = NULL;
	zfs_sb_t  *zsb =NULL;
	zfs_group_header_t	*msg_header = server_para->msg_header;
	zfs_group_data_msg_t	*data = (zfs_group_data_msg_t *)server_para->msg_data;


	vflg = data->call.data.io_flags;
	vflg |= FCLUSTER;

	zsb = zfs_sb_group_hold(msg_header->server_spa, msg_header->server_os, FTAG, B_TRUE);
	if (zsb == NULL)
		return (EGHOLD);

	if (msg_header->operation == DIR_READ || msg_header->operation == LINK_READ || msg_header->operation == XATTR_LIST )
		object = data->call.data.id.master_object;
	else
		object = data->call.data.id.data_object;
		
	error = zfs_zget(zsb, object, &zp);


	if (error) {
		zfs_sb_group_rele(zsb, FTAG);
		return (error);
	}

	if (msg_header->orig_type == APP_USER) {
		if (data->call.data.arg.dirlowdata != 0 && zp->z_dirlowdata == 0) {
			zp->z_dirlowdata = data->call.data.arg.dirlowdata;
		}
		
		if (data->call.data.arg.dirquota != 0 && zp->z_dirquota == 0) {
			zp->z_dirquota = data->call.data.arg.dirquota;
		}
	}
	
	switch(msg_header->operation) {
		case DATA_READ: {
//			ssize_t resid;
			ssize_t  readbytes = 0;
			void * addr = &data->call.data.data;
			zfs_group_data_read_t *read = &data->call.data.arg.p.read;
			cred = zfs_group_getcred(&read->cred);
//			error = vn_rdwr(UIO_READ, ZTOV(zp), addr, read->len, read->offset,
//			    UIO_SYSSPACE, vflg, RLIM64_INFINITY, cred, &resid);

			readbytes = zpl_read_common(ZTOI(zp), addr, read->len, &read->offset,
				UIO_SYSSPACE, vflg, cred);
			read->len = (uint64_t)readbytes; 
//			crfree(cred);
			abort_creds(cred);	
		}
		break;

		case DATA_WRITE:{
//			ssize_t resid;
			zfs_group_data_vectors_t *datavps;
			struct uio uio;
			size_t iov_size;
			struct iovec *iovp;
			zfs_group_data_write_t *write;

			bzero(&uio, sizeof(struct uio));
			write = &data->call.data.arg.p.write;
			bcopy(data->call.data.data, &datavps, sizeof(uint64_t));
			cred = zfs_group_getcred(&write->cred);

			iov_size = zfs_group_dup_iov(&iovp, datavps->iovps, datavps->vector_num);

			uio.uio_iov = iovp;
			uio.uio_iovcnt = datavps->vector_num;
			uio.uio_segflg = UIO_SYSSPACE;
			uio.uio_extflg = UIO_COPY_DEFAULT;
			uio.uio_loffset = write->offset;
			uio.uio_resid = write->len;
			uio.uio_fmode = FWRITE;
			uio.uio_extflg = UIO_COPY_DEFAULT;
			uio.uio_limit = RLIM64_INFINITY;
			zp->z_dirquota = write->dir_quota;

//			error = VOP_WRITE(ZTOV(zp), &uio, vflg, cred, NULL);
			error = zfs_write(ZTOI(zp), &uio, vflg, cred);
			if (error == 0) {
				write->len = write->len - uio.uio_resid;
			}

			kmem_free(iovp, iov_size);
//			crfree(cred);
			abort_creds(cred);
		}
		break;

		case DIR_READ: {
//			ssize_t resid;
			struct uio auio;
			struct iovec aiov;
			int eof = -1;
			void *addr = data->call.data.data;
			zfs_group_data_read_t *read = &data->call.data.arg.p.read;
			cred = zfs_group_getcred(&read->cred);

			bzero(&auio, sizeof(struct uio));
			bzero(&aiov, sizeof(struct iovec));
			aiov.iov_base = addr;
			aiov.iov_len = read->len;
			auio.uio_iov = &aiov;
			auio.uio_iovcnt = 1;
			auio.uio_skip = 0;
			auio.uio_loffset = read->offset;
			auio.uio_segflg = UIO_SYSSPACE;
			auio.uio_resid = read->len;
			auio.uio_fmode = 0;
			auio.uio_extflg = UIO_COPY_CACHED;

//			(void) VOP_RWLOCK(ZTOV(zp), V_WRITELOCK_FALSE, NULL); 
//			error = VOP_READDIR(ZTOV(zp), &auio, cred, &eof, NULL, vflg);
			error = zfs_readdir_server(ZTOI(zp), &auio, cred, &eof, vflg);
//			VOP_RWUNLOCK(ZTOV(zp), V_WRITELOCK_FALSE, NULL);
			if (error == 0) {
				read->eof = eof;
				read->len -= auio.uio_resid;
				read->offset = auio.uio_loffset;
			}
//			crfree(cred);
			abort_creds(cred);
		}
		break;

		case XATTR_LIST:{
			void *addr = data->call.data.data ;
			zfs_group_data_read_t *read = &data->call.data.arg.p.read ;
			size_t maxlen = read->len ;
			cred = zfs_group_getcred( &read->cred ) ;

			if( maxlen == 0 ) {
				error = zfs_xattr_list( ZTOI(zp), NULL, 0, cred ) ;
			}else {
				error = zfs_xattr_list( ZTOI( zp ), addr, maxlen, cred ) ;
			}

			if( error > 0 ) {
				read->len = error ;
				error = 0 ;
			}
			abort_creds(cred);
		}
		break ;

		case LINK_READ:{
//			uint64_t resid;
			struct uio auio;
			struct iovec aiov;
//			caller_context_t ct;
			int eof = 0;
			int flag = 0;
			void *addr = &data->call.data.data;

			zfs_group_data_read_t *read = &data->call.data.arg.p.read;
			cred = zfs_group_getcred(&read->cred);
			
			bzero(&auio, sizeof(struct uio));
			bzero(&aiov, sizeof(struct iovec));
			aiov.iov_base = addr;
			aiov.iov_len = read->len;
			auio.uio_iov = &aiov;
			auio.uio_iovcnt = 1;
			auio.uio_loffset = read->offset;
			auio.uio_segflg = UIO_SYSSPACE;
			auio.uio_resid = read->len;
			auio.uio_fmode = 0;
			auio.uio_extflg = UIO_COPY_CACHED;
			flag = FCLUSTER;
//			error = VOP_READLINK(ZTOV(zp), &auio, cred, &ct);
			error = zfs_readlink(ZTOI(zp), &auio, cred, flag);
			if (error == 0) {
				read->eof = eof;
				read->len -= auio.uio_resid;
				read->offset = auio.uio_loffset;
			}
//			crfree(cred);
			abort_creds(cred);
		}
		break;
	case MIGRATE_DATA:{
//			vnode_t *vp = NULL;
			struct inode *ip;
			vattr_t va = { 0 };
//			char vatime[129] = {"\0"};
//			char vctime[129] = {"\0"};
//			char vmtime[129] = {"\0"};
			
//			vp = ZTOV(zp);
			ip = ZTOI(zp);
			/* migrate dataA to dataB */
			error = zfs_migrate_dataA_to_dataB(zp,data,vflg);
			if (error != 0) {
				cmn_err(CE_WARN,"failed to migrate file data %s %lu, error = %d",
					zp->z_filename, zp->z_id, error);
				break;
			}

			/* get local attr */
			va.va_mask = AT_TIMES | AT_SIZE;
//			error = vp->v_op->vop_getattr(vp, &va, FCLUSTER, kcred, NULL);
			error = zfs_getattr(ip, &va, FCLUSTER, kcred);
			if (error != 0) {
				cmn_err(CE_WARN,"failed to migrate file get file attr %s %lu, error = %d",
					zp->z_filename, zp->z_id, error);
				break;
			}

			/* sync data1 data2 attr */
//			error = zmc_remote_updata_node(vp,data,&va,vflg);	
			error = zmc_remote_updata_node(ip,data,&va,vflg);
			if (error != 0) {
				cmn_err(CE_WARN,"failed to migrate file set attr file %s %lu, error = %d",
					zp->z_filename, zp->z_id, error);
				break;
			}
			
		}
		break;

		default:
		break;
	}

	iput(ZTOI(zp));
	zfs_sb_group_rele(zsb, FTAG);
	return (error);
}

int zfs_remote_updata_node_dirty(znode_t* zp, uint64_t dirty_flag,
	uint64_t dst_spa, uint64_t dst_os, uint64_t dst_object)
{
	int error = 0;
	zfs_sb_t *zsb = NULL;
	zfs_group_notify_msg_t *notify_msg = NULL;
	zfs_group_header_t *msg_header = NULL;
	zfs_group_notify_t *nop = NULL;

	if (dst_spa == -1 || dst_os == -1 || dst_object == -1
			|| dst_spa == 0 || dst_os == 0 || dst_object == 0) {
		return ENOENT;
	}
	
	notify_msg = kmem_zalloc(sizeof (zfs_group_notify_msg_t), KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	nop = &notify_msg->call.notify;

	zsb = ZTOZSB(zp);
	if (zsb == NULL) {
		kmem_free(notify_msg, sizeof (zfs_group_notify_msg_t));
		return EGHOLD;
	}
	
	nop->arg.p.dirty_notify.dirty_flag = dirty_flag;
	nop->arg.p.dirty_notify.master_object = dst_object;
	nop->arg.p.dirty_notify.data_file_no = DATA_FILE1;

	zfs_group_build_data_header(zsb->z_os,
    	msg_header, ZFS_GROUP_CMD_NOTIFY, SHARE_NOWAIT,
    	NOTIFY_DATA_DIRTY, sizeof (zfs_group_notify_msg_t), sizeof (zfs_group_notify_msg_t),
    	dst_spa, dst_os, dst_object, zp->z_group_id.data_object, dst_spa, dst_os, dst_object,
   		MSG_NOTIFY, APP_USER);
	error = zfs_client_send_to_server(zsb->z_os, msg_header, (zfs_msg_t *)notify_msg, B_TRUE);

	if (notify_msg != NULL)
		kmem_free(notify_msg, sizeof (zfs_group_notify_msg_t));
	if (msg_header != NULL)
		kmem_free(msg_header, sizeof(zfs_group_header_t));
	
	return error;
}


static int zmc_remote_updata_node(struct inode *ip, zfs_group_data_msg_t *data,vattr_t *vap,uint64_t flags)
{

	znode_t *zp;
//	uint_t mask;
	zfs_group_znode_setattr_t *setattrp;
	zfs_group_object_t *dst_obj = &data->call.data.id;
	int error;
	
	flags |= F_MIGRATE_DATA;
	zp = ITOZ(ip);
	setattrp = kmem_zalloc(sizeof(zfs_group_znode_setattr_t), KM_SLEEP);
	setattrp->flags = flags;
	 if ((error = zfs_group_v_to_v32(vap, &setattrp->vattr)) != 0) {
		goto out;
	} 
	setattrp->bxattr = 0;

	error = zfs_remote_update_node(ip, setattrp, dst_obj->data2_spa, dst_obj->data2_objset,
		dst_obj->data2_object, flags, kcred, NULL);
	if (error != 0) {
		goto out;
	}
	
	error = zfs_remote_updata_node_dirty(zp, zp->z_group_id.data_status, dst_obj->data2_spa,
		dst_obj->data2_objset, dst_obj->data2_object);
	if (error != 0) {
		goto out;
	}
out:
	kmem_free(setattrp, sizeof(zfs_group_znode_setattr_t));
	return (error);
	
}


int zfs_remote_update_node(struct inode *ip, void *ptr, uint64_t dst_spa, uint64_t dst_os, 
	uint64_t dst_object, uint64_t flags, cred_t *credp, caller_context_t *ct)
{
	uint64_t msg_len = 0;
	zfs_sb_t *zsb;
	zfs_group_znode_msg_t *znode_msg = NULL;
	zfs_group_header_t *msg_header = NULL;
	znode_t *zp = NULL;
	zfs_group_znode_t *znp = NULL;
//	zfs_group_znode2_t *z2p = NULL;
//	char msg[128];
	int error;
	
	zfs_group_znode_setattr_t *setattr;
	zp = ITOZ(ip);
	zsb = ZTOZSB(zp);
	msg_len = sizeof (zfs_group_data_msg_t);

	znode_msg = kmem_zalloc(sizeof (zfs_group_znode_msg_t), KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	znp = &znode_msg->call.znode;
	zfs_group_set_cred(credp, &znp->cred);

	znp->id = zp->z_group_id;
	znp->id.master_object = dst_object;

	setattr = (zfs_group_znode_setattr_t *)ptr;
	znp->arg.p.setattr = *setattr;
	
	zfs_group_build_data_header(zsb->z_os, msg_header, ZFS_GROUP_CMD_ZNODE, SHARE_WAIT, ZNODE_SETATTR,
			sizeof (zfs_group_znode_msg_t), sizeof (zfs_group_znode_msg_t), dst_spa, dst_os, dst_object,
			zp->z_group_id.data_object, dst_spa, dst_os, dst_object, MSG_REQUEST, APP_USER);

	error = zfs_client_send_to_server(ZTOZSB(zp)->z_os, msg_header, (zfs_msg_t *)znode_msg, B_TRUE);

	if (znode_msg != NULL)
		kmem_free(znode_msg, sizeof(zfs_group_znode_msg_t));
	if (msg_header != NULL)
		kmem_free(msg_header, sizeof(zfs_group_header_t));

	return error;
}

/*
 * Function: migrate dataA(normal health newest data)
 *
 */
int zfs_migrate_dataA_to_dataB(znode_t *zp,zfs_group_data_msg_t *data,uint64_t vflg)
{
	char *buf = NULL;
	int error;
//	ssize_t resid;
	ssize_t readen = 0,tot_readen = 0;
	offset_t offset = 0;
	cred_t *cred;
	zfs_group_data_read_t *read = &data->call.data.arg.p.read;
	zfs_group_object_t *dst_obj = &data->call.data.id;
	
	vflg = vflg | F_MIGRATE_DATA | F_DT2_NO_UP_QUOTA;
	cred = zfs_group_getcred(&read->cred);
	buf = kmem_zalloc(zfs_group_max_dataseg_size, KM_SLEEP);

	/* read local data and write data to dataB */
	while(1) {
		bzero(buf, zfs_group_max_dataseg_size);
		readen = tot_readen;	
		offset = tot_readen;
		error = zfs_local_read_node(ZTOI(zp), buf, zfs_group_max_dataseg_size, &offset,
			 vflg,cred,&readen);
		if (error != 0)
			break;

		/* read nothing current time */
		if (readen == 0)
			break;

		/* total read  */
		tot_readen += readen;
		error = zmc_remote_write_node(ZTOI(zp),dst_obj,buf,readen,offset,vflg,cred,NULL);
	
		if (zp->z_size == tot_readen)
			break;
	}
	
	kmem_free(buf,zfs_group_max_dataseg_size);
//	crfree(cred);
	abort_creds(cred);

	return error;
}

/*
 * Function: prepare send info to other os
 * 
 * parameters:
 *	dst : include dst spa os and object
 *	data: buf addr
 *	data_len: buf len
 *	offset: write offset 
 *	ioflage: judge io flage
 * Return: 0==>success;other==>fail
 *
 */

static int zmc_remote_write_node(struct inode * src_ip,zfs_group_object_t *dst, char* data,ssize_t data_len,
	ssize_t offset, uint64_t ioflag, cred_t* cr, caller_context_t* ct)
{
	int error = 0;
	uint64_t dst_spa = 0 ; 
	uint64_t dst_os = 0;
	uint64_t dst_object = 0;
	ssize_t nbytes = 0;
	znode_t *src_zp = NULL;
	struct uio uio;
	struct iovec iov;
	
	if (src_ip == NULL)
		return -1;

	if (data_len < 0)
		return (EIO);

	src_zp = ITOZ(src_ip);
	dst_spa = dst->data2_spa;
	dst_os = dst->data2_objset;
	dst_object = dst->data2_object;

	iov.iov_base = data;
	iov.iov_len = data_len;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_loffset = offset;
	uio.uio_segflg = (short)UIO_SYSSPACE;
	uio.uio_resid = data_len;
	uio.uio_limit = RLIM64_INFINITY;
	nbytes = data_len;
			
	error = zfs_remote_write_node(src_ip, dst_spa, dst_os,dst_object,
			&uio,nbytes,ioflag,cr, NULL);

	return error;
}

/*
 * Function: build header send to dataB
 */
static void zfs_group_build_data_header(objset_t *os,
    zfs_group_header_t *hdr, uint64_t cmd, share_flag_t wait_flag, 
    uint64_t op, uint64_t length, uint64_t out_length, uint64_t server_spa, 
    uint64_t server_os, uint64_t server_object, uint64_t master_object,
    uint64_t data_spa, uint64_t data_os, uint64_t data_object,
    msg_op_type_t op_type, msg_orig_type_t orig_type)
{
	hdr->magic = ZFS_GROUP_MAGIC;
	hdr->msg_type = op_type;
	hdr->orig_type = orig_type;
	hdr->wait_flag = (ushort_t)wait_flag;
	hdr->command = cmd;
	hdr->operation = op;
	hdr->length = length;
	hdr->out_length = out_length;
	hdr->error = 0;

	hdr->master_object = master_object;

	hdr->client_os = dmu_objset_id(os);
	hdr->client_spa = spa_guid(dmu_objset_spa(os));
	hdr->client_object = master_object;

	hdr->server_spa = server_spa;
	hdr->server_os = server_os;
	hdr->server_object = server_object;

	hdr->data_spa = data_spa;
	hdr->data_os = data_os;
	hdr->data_object = data_object;
	hdr->reset_seqno = 0;
}

/*
 * Function: send data to other data file
 */

int zfs_remote_write_node(struct inode * src_ip,uint64_t dst_spa,uint64_t dst_os, uint64_t dst_object,
	uio_t *uiop,ssize_t nbytes, uint64_t ioflag, cred_t* cr, caller_context_t* ct)
{
	int error;
	zfs_group_data_write_t *write;
	uint64_t msg_len = 0;
	void *addr;
	size_t cbytes;
	size_t write_len;
	int request_length;
	int reply_lenth;
	zfs_group_data_t *data = NULL;
	znode_t *src_zp = NULL;

	zfs_sb_t *zsb;
	zfs_group_data_msg_t *data_msg = NULL;
	zfs_group_header_t *msg_header = NULL;
	
	src_zp = ITOZ(src_ip);
	zsb = ZTOZSB(src_zp);

	write = kmem_alloc(sizeof(zfs_group_data_write_t), KM_SLEEP);
	write->addr = (uint64_t)(uintptr_t)uiop;
	write->offset = uiop->uio_loffset;
	write->len = nbytes;
	write->dir_quota = src_zp->z_dirquota;
	zfs_group_set_cred(kcred, &write->cred);

	write_len = (write->len + (8 -1)) & (~(8 -1));
	msg_len = sizeof(zfs_group_data_msg_t) + write_len - 8;
	data_msg = kmem_zalloc(msg_len, KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	bzero(data_msg, msg_len);
	data = &data_msg->call.data;
	addr = &data_msg->call.data.data;
	data->io_flags = ioflag;
	uiocopy(addr, write->len, UIO_WRITE, uiop, &cbytes);
	data_msg->call.data.arg.p.write = *write;
	request_length = msg_len;
	reply_lenth = sizeof(zfs_group_data_msg_t);
	data->arg.dirlowdata = src_zp->z_dirlowdata;
	data->arg.dirquota = src_zp->z_dirquota;

	zfs_group_build_data_header(zsb->z_os, msg_header, ZFS_GROUP_CMD_DATA, SHARE_WAIT, DATA_WRITE,
			request_length, reply_lenth, dst_spa, dst_os, dst_object,
			src_zp->z_group_id.data_object,dst_spa,dst_os,dst_object,MSG_REQUEST, APP_USER);

	data->id = src_zp->z_group_id;
	data->id.data_spa = dst_spa;
	data->id.data_objset = dst_os;
	data->id.data_object = dst_object;
	error = zfs_client_send_to_server(zsb->z_os, msg_header, (zfs_msg_t *)data_msg, B_TRUE);

	if (data_msg != NULL) {
		kmem_free(data_msg, msg_len);
	}
	if (msg_header != NULL) {
		kmem_free(msg_header, sizeof(zfs_group_header_t));
	}
	if (write != NULL) {
		kmem_free(write, sizeof(zfs_group_data_write_t));
	}
	return 0;
}

/*
 * Function: read local file data
 *
 */
int
zfs_local_read_node(struct inode *src_ip, char *buf, ssize_t bufsiz,offset_t *offsize, uint64_t vflg,cred_t *cred, ssize_t *readen)
{
	int 	err = 0;
	ssize_t readbytes = 0;
//	ssize_t	resid;
	ssize_t read_cnt = 0;
	ssize_t nbytes = 0;
	znode_t* src_zp = NULL;

	src_zp = ITOZ(src_ip);
	nbytes = src_zp->z_size - *readen;
	
	nbytes = MIN(nbytes, zfs_group_max_dataseg_size -
		P2PHASE(*offsize, zfs_group_max_dataseg_size));
	
	while (1) {
//		err = vn_rdwr(UIO_READ, src_vp, buf, nbytes, *offsize,
//		    UIO_SYSSPACE, vflg, RLIM64_INFINITY, cred, &resid);

		readbytes = zpl_read_common(src_ip, buf, nbytes, offsize,
		    UIO_SYSSPACE, vflg, cred);

		if (err != 0) {
			cmn_err(CE_WARN, "%s: read error %d\n",
			    src_zp->z_filename, err);
			return (err);
		}

		read_cnt += readbytes;

		if (readbytes == nbytes) {
			break;/* done */
		}

		if (readbytes == 0) {
			err = ENOSPC;
			break; 
		}

		nbytes = readbytes;
		/* readen buf */
		buf += nbytes;
		*offsize += nbytes;
		/* next loop read data */
		nbytes = nbytes - readbytes;

	}
	
	*readen = read_cnt;
	return (err);
}


static int
zfs_group_get_relativepath(znode_t *zp, zfs_group_znode2_t *z2p)
{
       struct inode *pip = NULL;
       zfs_sb_t *zsb = ZTOZSB(zp);
       struct inode *tmp_ip = ZTOI(zp);
       char path[MAXNAMELEN] = {0};
       char path_tmp[MAXNAMELEN] = {0};
       int err = 0;

       if (zp->z_id != zsb->z_root){
               while(ITOZ(tmp_ip)->z_id != zsb->z_root){
                       if (path_tmp[0] == '\0'){
                               strncpy(path_tmp, ITOZ(tmp_ip)->z_filename, strlen(ITOZ(tmp_ip)->z_filename));
                       }else {
                               sprintf(path_tmp, "%s/%s", ITOZ(tmp_ip)->z_filename, path);
                       }
                       bcopy(path_tmp, path, MAXNAMELEN);
                       err = zfs_lookup(tmp_ip, "..", &pip, 0, CRED(), NULL, NULL);
                       if (ITOZ(tmp_ip) != zp)
                               iput(tmp_ip);
                       if (err != 0){
                               return err;
                       }
                       tmp_ip = pip;
               }
               if (ITOZ(tmp_ip) != zp)
                       iput(tmp_ip);
               bcopy(path, z2p->relativepath, MAXNAMELEN);
       }
       return 0;
}


int	
zfs_group_process_znode_request(zfs_group_server_para_t *server_para)
{
	int	error = 1;
	uint64_t	object = 0;
	uint64_t	flags = 0;
	uint64_t	m_spa = 0;
	uint64_t	m_objset = 0;
	uint64_t	m_object = 0;
	uint64_t	m_gen = 0;
	char	buf[MAXNAMELEN];
	znode_t	*zp = NULL;
	cred_t	*cred = NULL;
	zfs_sb_t  *zsb = NULL;
	zfs_msg_t	*msg_data = server_para->msg_data;
	zfs_group_header_t	*msg_header = server_para->msg_header;
	zfs_group_znode_t	*znp = NULL;
	zfs_group_znode2_t	*z2p = NULL;
	zfs_group_znode_arg_t	*arg = NULL;


	znp= &msg_data->call.znode;
	arg = &znp->arg;
	z2p = (zfs_group_znode2_t *)znp;
	cred = zfs_group_getcred(&znp->cred);

	zsb = zfs_sb_group_hold(msg_header->server_spa, msg_header->server_os, FTAG, B_TRUE);
	if (zsb == NULL) {
		crfree(cred);	
		return (EGHOLD);
	}

	if(msg_header->operation == ZNODE_FREE){
		object = znp->id.data_object;
	}else{
		object = znp->id.master_object;
	}

	/* 2016 03 08, yzy, here master2 doesn't mean master2 node, if it is not emty, 
	 * it means that master should be used to look up master obj map table, 
	 * in case that Nfs session meets Master suddenly corrupted. 
	 */
	m_spa = znp->id.master2_spa;
	m_objset = znp->id.master2_objset;
	m_object = znp->id.master2_object;
	m_gen = znp->id.master2_gen;
	
	if((msg_header->operation == ZNODE_GET || msg_header->operation == ZNODE_SEARCH) && 
		m_spa != 0 && m_objset != 0 && m_object !=0 && m_gen != 0){
		bzero(buf, MAXNAMELEN);
		sprintf(buf, zfs_group_map_key_name_prefix_format, m_spa, m_objset, m_object, m_gen & ZFS_GROUP_GEN_MASK);
		error = zap_lookup(zsb->z_os, zsb->z_group_map_objs[m_object%NASGROUP_MAP_NUM], buf, 8, 1, &m_object);
		if(error == 0){
			object = m_object;
			if(debug_nas_group_dtl == 2){
				cmn_err(CE_WARN, "[INFO] %s Succeed in looking up zfs_group_map_key %s, map_obj %llu", 
					__func__, buf, (unsigned long long)zsb->z_group_map_objs[m_object%NASGROUP_MAP_NUM]);
			}
		}else {
			if(debug_nas_group_dtl == 2){
				cmn_err(CE_WARN, "[Error] %s failed in looking up zfs_group_map_key %s, map_obj %llu", 
					__func__, buf, (unsigned long long)zsb->z_group_map_objs[m_object%NASGROUP_MAP_NUM]);
			}

			crfree(cred);
			zfs_sb_group_rele(zsb, FTAG);
			cmn_err(CE_WARN, "[%s %d] err=%d", __func__, __LINE__, error);
			return (error);
		}
	}

	error = zfs_zget(zsb, object, &zp);
	if (error) {
		crfree(cred);
		zfs_sb_group_rele(zsb, FTAG);
		cmn_err(CE_WARN, "[%s %d] err=%d", __func__, __LINE__, error);
		return (error);
	}
	switch (msg_header->operation) {
	case ZNODE_SETATTR: {
		xvattr_t *xvattrp = NULL;
		zfs_group_znode_setattr_t *zg_setattr = &arg->p.setattr;
		flags = FCLUSTER;
		/* if migrate dataA to dataB we must set migrate flag. other situation keep the flags=FCLUSTER */
		if ((zg_setattr->flags&F_MIGRATE_DATA) != 0){
			flags = flags | F_MIGRATE_DATA;
		}
		
		xvattrp = kmem_zalloc(sizeof(xvattr_t), KM_SLEEP);
		xvattrp->xva_rtnattrmapp = &(xvattrp->xva_rtnattrmap)[0];
		zfs_group_v32_to_v(&zg_setattr->vattr, &xvattrp->xva_vattr);
		if (zg_setattr->bxattr == 1) {
			zfs_group_to_xvattr(&zg_setattr->xattr, xvattrp);
		}
//		error = VOP_SETATTR(ZTOV(zp), (vattr_t *)xvattrp, flags, cred, NULL);
		error = zfs_setattr(ZTOI(zp), (vattr_t *)xvattrp, flags, cred);
		kmem_free(xvattrp, sizeof(xvattr_t)); 
	}

	case ZNODE_ACCESS:
		flags = arg->p.access.flag | FCLUSTER;
//		error = VOP_ACCESS(ZTOV(zp), arg->p.access.mode, flags, cred, NULL);
		error = zfs_access(ZTOI(zp), arg->p.access.mode, flags, cred);
	break;

	case ZNODE_FREE: {
		zfs_group_znode_free_t *free = &arg->p.free;
		flags = arg->p.free.flag | FCLUSTER;
		error = zfs_freesp(zp, free->off, free->len, free->flag, B_TRUE);

		/* Make zp point to master znode, after data znode is freed. 
		 * Because  ZNODE_FREE must happen on slave fs not master fs, 
		 * So, zfs_group_zget() is called instead of zfs_zget().
		 */
		iput(ZTOI(zp));
		error = zfs_group_zget(zsb, znp->id.master_object, &zp, 0, 0, 0, B_TRUE);
		if (error) {
			zp = NULL;
			cmn_err(CE_WARN, "%s %d error=%d\n", __func__, __LINE__, error);
		}
	}
	case ZNODE_SEARCH:
	case ZNODE_GET:
	default:
	break;
	}

	if (error == 0 && zp != NULL) {
		if (zp->z_dirquota != 0) {
			zp->z_overquota = zfs_overquota(zsb, zp, zp->z_dirquota);
		}
		zfs_group_znode_copy_phys(zp, &z2p->zrec.object_phy, B_FALSE);
		z2p->inp.id = zp->z_group_id;
		if (S_ISDIR(ZTOI(zp)->i_mode) && zp->z_id != zsb->z_root){
                      error = zfs_group_get_relativepath(zp, z2p);
		}
	}
//	crfree(cred);
	abort_creds(cred);
	if (zp != NULL) {
		iput(ZTOI(zp));
	}
	zfs_sb_group_rele(zsb, FTAG);
	return (error);
}

int	
zfs_group_process_znode_request_backup(zfs_group_server_para_t *server_para)
{
	int	error = 1;
	uint64_t	object = 0;
//	uint64_t	flags = 0;
	znode_t	*zp = NULL;
	cred_t	*cred = NULL;
	zfs_sb_t  *zsb =NULL;
	zfs_msg_t	*msg_data = server_para->msg_data;
	zfs_group_header_t	*msg_header = server_para->msg_header;
	zfs_group_znode_t	*znp = NULL;
	zfs_group_znode2_t	*z2p = NULL;
	zfs_group_znode_arg_t	*arg = NULL;


	znp= &msg_data->call.znode;
	arg = &znp->arg;
	z2p = (zfs_group_znode2_t *)znp;
	cred = zfs_group_getcred(&znp->cred);
	zsb = zfs_sb_group_hold(msg_header->server_spa, msg_header->server_os, FTAG, B_TRUE);
	if (zsb == NULL) {
		crfree(cred);
		return (EGHOLD);
	}

	
	switch(msg_header->m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			object = znp->id.master2_object;
			break;
		case ZFS_MULTICLUS_MASTER3:
			object = znp->id.master3_object;
			break;
		case ZFS_MULTICLUS_MASTER4:
			object = znp->id.master4_object;
			break;
		default:
			cmn_err(CE_WARN, "[Error] %s %d", __func__, __LINE__);
			crfree(cred);
			zfs_sb_group_rele(zsb, FTAG);
			return (EINVAL);
	}
	
	error = zfs_zget(zsb, object, &zp);
	if (error) {
		crfree(cred);
		zfs_sb_group_rele(zsb, FTAG);
		return (error);
	}
	switch (msg_header->operation) {
		case ZNODE_SETATTR: {
			zfs_group_znode_setattr_t *zg_setattr = &arg->p.setattr;
			xvattr_t *xvattrp = kmem_zalloc(sizeof(xvattr_t), KM_SLEEP);
			xvattrp->xva_rtnattrmapp = &(xvattrp->xva_rtnattrmap)[0];
			zfs_group_v32_to_v(&zg_setattr->vattr, &xvattrp->xva_vattr);
			if (zg_setattr->bxattr == 1) {
				zfs_group_to_xvattr(&zg_setattr->xattr, xvattrp);
			}
			
//			error = VOP_SETATTR(ZTOV(zp), (vattr_t *)xvattrp, FCLUSTER|FBackupMaster, cred, NULL);
			error = zfs_setattr(ZTOI(zp), (vattr_t *)xvattrp, FCLUSTER|FBackupMaster, cred);
			kmem_free(xvattrp, sizeof(xvattr_t));
			
		}
		break;
		default:
		break;
	}

//	crfree(cred);
	abort_creds(cred);
	iput(ZTOI(zp));
	zfs_sb_group_rele(zsb, FTAG);
	return (error);
}


void zfs_group_update_system_space(objset_t *os,
    zfs_group_notify_system_space_t *sys_space)
{
	int i;
	int index;
	uint64_t old_avail;
	uint64_t old_used;
	uint64_t old_ios;
	uint64_t spa_id;
	uint64_t os_id;
	zfs_multiclus_group_record_t *group_recordp;
	zfs_multiclus_group_t *group = NULL;

	i = 0;
	index =0;
	group = NULL;
	group_recordp = NULL;
	old_avail = 0;
	old_used = 0;
	old_ios = 0;

	spa_id = sys_space->space_spa;
	os_id = sys_space->space_os;

	index = zfs_multiclus_get_group(os->os_group_name, &group);
	if (index == ZFS_MULTICLUS_GROUP_TABLE_SIZE || group == NULL) {
		cmn_err(CE_WARN, "group(%s) for os (%llx:%llx) has not been created",
		    os->os_group_name,
		    (longlong_t)spa_id, (longlong_t)os_id);
		return;
	}
	mutex_enter(&multiclus_mtx);
	mutex_enter(&group->multiclus_group_mutex);
	for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i ++) {
		group_recordp = &group->multiclus_group[i];
		if (group_recordp->spa_id == spa_id &&
		    group_recordp->os_id == os_id) {
			break;
		}
	}

	if (i == ZFS_MULTICLUS_GROUP_NODE_NUM) {
		mutex_exit(&group->multiclus_group_mutex);
		mutex_exit(&multiclus_mtx);
		cmn_err(CE_WARN, "os (%llx:%llx) is not in group(%s)",
		    (longlong_t)spa_id, (longlong_t)os_id, os->os_group_name);
		return;
	}

	old_avail = atomic_add_64_nv(&group_recordp->avail_size, 0);
	(void)atomic_cas_64(&group_recordp->avail_size,
	    old_avail,sys_space->space_avail);

	old_used = atomic_add_64_nv(&group_recordp->used_size, 0);
	(void)atomic_cas_64(&group_recordp->used_size, old_used,
	    sys_space->space_ref);

	old_ios = atomic_add_64_nv(&group_recordp->load_ios, 0);
	(void)atomic_cas_64(&group_recordp->load_ios, old_ios,
	    sys_space->sys_ios);
	mutex_exit(&group->multiclus_group_mutex);
	mutex_exit(&multiclus_mtx);

}

void zfs_update_quota_used(zfs_sb_t *zsb, znode_t *zp,
    uint64_t space, uint64_t update_op, dmu_tx_t *tx)
{
	zfs_dir_updatequota(zsb, zp, space, update_op, tx);
//	zfs_fuid_updatequota(zsb, B_TRUE, zp->z_gid, space, update_op, tx);
//	zfs_fuid_updatequota(zsb, B_FALSE, zp->z_uid, space, update_op, tx);
}

int zfs_group_server_update_file_info(zfs_sb_t * zsb, zfs_group_notify_file_info_t* info)
{
	znode_t* zp = NULL;
	dmu_tx_t* tx = NULL;
	int error = 0;

	if (zsb == NULL || info == NULL)
	{
		return EINVAL;
	}

	error = zfs_zget(zsb, info->dst_object, &zp);
	if (error != 0)
	{
		return error;
	}

	/*
	 * the received message may be out of order, e.g., we
	 * received the master3 info after master4 info;
	 * add the -1 check to avoid it
	 */
	/*
	 * if we want to update master1\2\3 file node info. 
	 * e.g i want to update master3's file node's master2 info, we will set info->m_node_type = ZFS_MULTICLUS_MASTER2
	 */
	switch(info->update_node_info)
	{
		case ZFS_UPDATE_FILE_NODE_MASTER2:
			if ((zp->z_group_id.master2_spa != info->group_id.master_spa 
				|| zp->z_group_id.master2_objset != info->group_id.master_objset
				|| zp->z_group_id.master2_object != info->group_id.master_object 
				|| zp->z_group_id.master2_gen != info->group_id.master_gen) 
				&& info->group_id.master2_spa != -1 && info->group_id.master2_objset != -1 
				&& info->group_id.master2_object != -1 && info->group_id.master2_gen != 0) {
				zp->z_group_id.master2_spa = info->group_id.master2_spa;
				zp->z_group_id.master2_objset = info->group_id.master2_objset;
				zp->z_group_id.master2_object = info->group_id.master2_object;
				zp->z_group_id.master2_gen = info->group_id.master2_gen;
			}
			break;

		case ZFS_UPDATE_FILE_NODE_MASTER3:
			if ((zp->z_group_id.master3_spa != info->group_id.master_spa 
				|| zp->z_group_id.master3_objset != info->group_id.master_objset
				|| zp->z_group_id.master3_object != info->group_id.master_object 
				|| zp->z_group_id.master3_gen != info->group_id.master_gen) 
				&& info->group_id.master3_spa != -1 && info->group_id.master3_objset != -1 
				&& info->group_id.master3_object != -1 && info->group_id.master3_gen != 0) {
				zp->z_group_id.master3_spa = info->group_id.master3_spa;
				zp->z_group_id.master3_objset = info->group_id.master3_objset;
				zp->z_group_id.master3_object = info->group_id.master3_object;
				zp->z_group_id.master3_gen = info->group_id.master3_gen;
			}
			break;

		case ZFS_UPDATE_FILE_NODE_MASTER4:
			if ((zp->z_group_id.master4_spa != info->group_id.master_spa 
				|| zp->z_group_id.master4_objset != info->group_id.master_objset
				|| zp->z_group_id.master4_object != info->group_id.master_object 
				|| zp->z_group_id.master4_gen != info->group_id.master_gen) 
				&& info->group_id.master4_spa != -1 && info->group_id.master4_objset != -1 
				&& info->group_id.master4_object != -1 && info->group_id.master4_gen != 0) {
				zp->z_group_id.master4_spa = info->group_id.master4_spa;
				zp->z_group_id.master4_objset = info->group_id.master4_objset;
				zp->z_group_id.master4_object = info->group_id.master4_object;
				zp->z_group_id.master4_gen = info->group_id.master4_gen;
			}
			break;

		case ZFS_UPDATE_FILE_NODE_DATA1:	
			zp->z_group_id.data_spa = info->group_id.data_spa;
			zp->z_group_id.data_objset = info->group_id.data_objset;
			zp->z_group_id.data_object = info->group_id.data_object;
			zp->z_group_id.data_status= info->group_id.data_status;
			break;

		case ZFS_UPDATE_FILE_NODE_DATA2:
			zp->z_group_id.data2_spa = info->group_id.data2_spa;
			zp->z_group_id.data2_objset = info->group_id.data2_objset;
			zp->z_group_id.data2_object = info->group_id.data2_object;
			zp->z_group_id.data2_status= info->group_id.data2_status;
			break;

		default:
			cmn_err(CE_WARN, "[Error] %s, %d, info->m_node_type must master1¡¢2¡¢3 or data1 or data2 ", 
					__func__, __LINE__);
			break;
	}

	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error != 0) {
		dmu_tx_abort(tx);
		iput(ZTOI(zp));
		return error;
	}

	mutex_enter(&(zp->z_lock));

	error = sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zsb),
		&(zp->z_group_id), sizeof(zfs_group_object_t), tx);

	mutex_exit(&(zp->z_lock));

	dmu_tx_commit(tx);

	if(zp->z_id == zp->z_group_id.data_object && zp->z_group_id.data_spa == spa_guid(dmu_objset_spa(zsb->z_os))
		&& zp->z_group_id.data_objset == dmu_objset_id(zsb->z_os) && zp->z_group_id.data_status != DATA_NODE_DIRTY){
		sa_object_size(zp->z_sa_hdl, (uint32_t *)&zp->z_blksz, (u_longlong_t *)&zp->z_nblks);
		zp->z_nblks = (unsigned long long)((zp->z_size + SPA_MINBLOCKSIZE - 1) >>
	        SPA_MINBLOCKSHIFT);
		zfs_client_notify_file_space(zp, 0, EXPAND_SPACE, B_FALSE, zp->z_group_id.data_spa,  zp->z_group_id.data_objset);
	}else if(zp->z_id == zp->z_group_id.data2_object && zp->z_group_id.data2_spa == spa_guid(dmu_objset_spa(zsb->z_os))
		&& zp->z_group_id.data2_objset == dmu_objset_id(zsb->z_os) && zp->z_group_id.data2_status != DATA_NODE_DIRTY){
		sa_object_size(zp->z_sa_hdl, (uint32_t *)&zp->z_blksz, (u_longlong_t *)&zp->z_nblks);
		zp->z_nblks = (unsigned long long)((zp->z_size + SPA_MINBLOCKSIZE - 1) >>
	        SPA_MINBLOCKSHIFT);
		zfs_client_notify_file_space(zp, 0, EXPAND_SPACE, B_FALSE, zp->z_group_id.data2_spa,  zp->z_group_id.data2_objset);
	}

	iput(ZTOI(zp));

	return 0;
}

int zfs_group_process_notify(zfs_group_server_para_t *server_para)
{
	int	error = 0;
	uint64_t	parent = 0;
	boolean_t	waited = B_FALSE;
	znode_t	*zp = NULL;
	znode_t	*dzp = NULL;
	zfs_sb_t  *zsb = NULL;
	zfs_group_header_t	*msg_header = server_para->msg_header;
	zfs_group_notify_msg_t	*nmsg = (zfs_group_notify_msg_t *)server_para->msg_data;
	zfs_group_notify_t	*notify = &nmsg->call.notify;


	zsb = zfs_sb_group_hold(msg_header->server_spa, msg_header->server_os, FTAG, B_TRUE);
	if (zsb == NULL)
		return (EGHOLD);

	switch(msg_header->operation)
	{
		case NOTIFY_SYSTEM_SPACE:
		{
			zfs_group_notify_system_space_t *system_space = &notify->arg.p.system_space;
			zfs_group_update_system_space(zsb->z_os, system_space);

			break;
		}

		case NOTIFY_FILE_SPACE:
		{
			boolean_t update_quota;
			dmu_tx_t *tx;
			sa_bulk_attr_t	bulk[7];
			int count;
			zfs_group_notify_file_space_t *file_notify;

			file_notify = &notify->arg.p.file_space;
			count = 0;
			update_quota = B_FALSE;
			error = zfs_zget(zsb, file_notify->file_object, &zp);
			if (error != 0) {
				cmn_err(CE_WARN, "Notify can not find file(%lld)",
				    (longlong_t)file_notify->file_object);
				goto error;
			}

			if (file_notify->file_gen != zp->z_gen) {
				cmn_err(CE_WARN, "%s, %d, Invalid notify, old_gen: %llu, new_gen: %llu, zid: %llu, name: %s", 
					__func__, __LINE__, (unsigned long long)file_notify->file_gen, 
					(unsigned long long)zp->z_gen, (unsigned long long)zp->z_id, zp->z_filename);
				iput(ZTOI(zp));
				error = EBADF;
				goto error;
			}

			if (((zp->z_group_id.master_spa == zp->z_group_id.data_spa
				&& zp->z_group_id.master_objset == zp->z_group_id.data_objset
				&& zp->z_group_id.master_object == zp->z_group_id.data_object)
				|| (zp->z_group_id.master_spa == zp->z_group_id.data2_spa
				&& zp->z_group_id.master_objset == zp->z_group_id.data2_objset
				&& zp->z_group_id.master_object == zp->z_group_id.data2_object))
				&& !file_notify->file_low) {
				/*
				 * the master node is also the data node, do not update it
				 *
				 * the file size in the master node will be (or has been)
				 * updated when we write the data into the data node/master
				 * node
				 */
				iput(ZTOI(zp));
				break;
			}

			bcopy(file_notify->atime, zp->z_atime, sizeof(zp->z_atime));
			bcopy(file_notify->ctime, zp->z_ctime, sizeof(zp->z_ctime));
			bcopy(file_notify->mtime, zp->z_mtime, sizeof(zp->z_mtime));
			zp->z_size = file_notify->file_size;

			SA_ADD_BULK_AMCTIME(bulk, count, zsb, zp);
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_SIZE(zsb), NULL,
			    &zp->z_size, 8);
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_NBLKS(zsb), NULL,
			    &file_notify->file_nblks, 8);
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_BLKSZ(zsb), NULL,
			    &file_notify->file_blksz, 8);
			zp->z_nblks = file_notify->file_nblks;
			zp->z_blksz = file_notify->file_blksz;
			if (zp->z_group_id.data_spa == file_notify->group_id.data_spa &&
				zp->z_group_id.data_objset == file_notify->group_id.data_objset &&
				zp->z_group_id.data_object == file_notify->group_id.data_object &&
				file_notify->file_low) {
				zp->z_low |= ZFS_DATA1_MIGRATED;
			} else if (zp->z_group_id.data2_spa == file_notify->group_id.data_spa &&
				zp->z_group_id.data2_objset == file_notify->group_id.data_objset &&
				zp->z_group_id.data2_object == file_notify->group_id.data_object &&
				file_notify->file_low) {
				zp->z_low |= ZFS_DATA2_MIGRATED;
			}

			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_LOW(zsb), NULL,
				&zp->z_low, 8);

		top:
			tx = dmu_tx_create(zsb->z_os);
			dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
			error = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
			if (error != 0) {
				if (error == ERESTART) {
					waited = B_TRUE;
					dmu_tx_wait(tx);
					dmu_tx_abort(tx);
					goto top;
				}
				dmu_tx_abort(tx);
				iput(ZTOI(zp));
				goto error;
			}

			if((error = sa_bulk_update(zp->z_sa_hdl, bulk, count, tx))!=0){
				dmu_tx_commit(tx);
				iput(ZTOI(zp));
				goto error;
			}

			if (zp->z_dirquota == 0) {
				if ((error = sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(ZTOZSB(zp)), &parent,
						sizeof (parent))) != 0){
					dmu_tx_commit(tx);
					iput(ZTOI(zp));
					goto error;
				}

				error = zfs_zget(zsb, parent, &dzp);
				if (error || dzp == NULL) {
					dmu_tx_commit(tx);
					iput(ZTOI(zp));
					goto error;
				}
				zp->z_dirquota = dzp->z_dirquota;
				iput(ZTOI(dzp));
			}

			if (file_notify->update_quota) {
				zfs_update_quota_used(zsb, zp,
				    file_notify->file_updatesize, file_notify->file_updateop, tx);
			}
			dmu_tx_commit(tx);
			iput(ZTOI(zp));
			break;
		}

		case NOTIFY_DATA_DIRTY:
		{
			dmu_tx_t *tx;
			zfs_group_object_t remote_object;
			zfs_group_notify_data_dirty_t *dirty_notify;

			dirty_notify = &notify->arg.p.dirty_notify;
		
			error = zfs_zget(zsb, dirty_notify->master_object, &zp);
			if (error != 0) {
				cmn_err(CE_WARN, "data2 notify can not find file(%lld)",
			    	(longlong_t)dirty_notify->master_object);
				goto error;
			}

		top2:
			tx = dmu_tx_create(zsb->z_os);
			dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
			error = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
			if (error != 0) {
				if (error == ERESTART) {
					waited = B_TRUE;
					dmu_tx_wait(tx);
					dmu_tx_abort(tx);
					goto top2;
				}
				dmu_tx_abort(tx);
				iput(ZTOI(zp));
				goto error;
			}

			if (dirty_notify->data_file_no == DATA_FILE1) {
				zp->z_group_id.data_status = dirty_notify->dirty_flag;
				cmn_err(CE_WARN, "%s, %d, File: %s data was set dirty!", 
					__func__, __LINE__, zp->z_filename);
			} else {
				zp->z_group_id.data2_status = dirty_notify->dirty_flag;
				cmn_err(CE_WARN, "%s, %d, File: %s, data2 was set dirty!", 
					__func__, __LINE__, zp->z_filename);
			}
			
			remote_object = zp->z_group_id;
			zfs_sa_set_remote_object(zp, &remote_object, tx);
			dmu_tx_commit(tx);
			iput(ZTOI(zp));

			break;
		}

		case NOTIFY_FILE_INFO:
			error = zfs_group_server_update_file_info(zsb, &(notify->arg.p.file_info));
			break;
			
		default:
			error = EINVAL;
			break;
	}

error:
	zfs_sb_group_rele(zsb, FTAG);	
	return (error);
}


static int zfs_group_process_fsstat(zfs_sb_t *zsb, fs_stat_t *statp, uint64_t org_type)
{
	int error = 0;

	dmu_objset_space(zsb->z_os, &statp->refdbytes,
	    &statp->availbytes, &statp->usedobjs, &statp->availobjs);

	return (error);
}


static int zfs_group_process_system_cmd(zfs_group_server_para_t *server_para)
{
	int	error = 0;
//	int64_t	object = 0;
	uint64_t	cmd_arg_size = 0;
	uint64_t	cmd_return_size = 0;
	void	*cmd_arg = NULL;
	void	*cmd_return = NULL;
//	znode_t	*zp = NULL;
	zfs_sb_t   *zsb = NULL;
	zfs_group_header_t	*msg_header = server_para->msg_header;
	zfs_group_cmd_msg_t	*cmd_msg = (zfs_group_cmd_msg_t *)server_para->msg_data;
	zfs_group_cmd_t	*cmd = &cmd_msg->call.cmd;


	cmd_arg_size = cmd->arg.arg_size;
	cmd_return_size = cmd->arg.return_size;
	cmd_arg = cmd->cmd;
	cmd_return = cmd->cmd;

	zsb = zfs_sb_group_hold(msg_header->server_spa, msg_header->server_os, FTAG, B_TRUE);
	if (zsb == NULL)
		return (EGHOLD);
	

	switch (msg_header->operation) {
	case SC_FS_STAT: {
		fs_stat_t stat;
		bzero(&stat, sizeof(fs_stat_t));
		error = zfs_group_process_fsstat(zsb, &stat, msg_header->orig_type); 
		bcopy(&stat, cmd_return, sizeof(fs_stat_t));
		cmd->arg.return_size = sizeof(fs_stat_t);
		error = 0;
	}
	break;


	case SC_FS_QUOTA: {
		if (!(zsb->z_os->os_is_master && msg_header->orig_type == APP_GROUP)) {
			znode_t *zp;
			znode_t *dzp = NULL;
			uint64_t parent = 0;
			boolean_t bover = B_FALSE;
			fs_quota_t *quota = kmem_zalloc(sizeof(fs_quota_t), KM_SLEEP);
			bcopy(cmd_arg, quota, cmd_arg_size);
			error = zfs_zget(zsb, quota->master_object, &zp);
			if (error == 0) {
				if (zp->z_dirquota == 0) {
					error = sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(ZTOZSB(zp)), &parent, sizeof (parent));
					if (error == 0) {
						error = zfs_zget(zsb, parent, &dzp);
						if (error == 0 && dzp != NULL) {
							zp->z_dirquota = dzp->z_dirquota;
							iput(ZTOI(dzp));
						}
					}
				}
				bover = zfs_overquota(zsb, zp, zp->z_dirquota);
				quota->quota_over = bover;
				bcopy(quota, cmd_return, sizeof(fs_quota_t));
				iput(ZTOI(zp));
			}
			kmem_free(quota, sizeof(fs_quota_t));
		}
	}
	break;

	case SC_FS_DIRLOWDATA: {
		if (!(zsb->z_os->os_is_master && msg_header->orig_type == APP_GROUP)) {
			znode_t *zp;
			fs_dir_lowdata_t *dirlowdata = kmem_zalloc(sizeof(fs_dir_lowdata_t), KM_SLEEP);
			bcopy(cmd_arg, dirlowdata, cmd_arg_size);
			error = zfs_zget(zsb, dirlowdata->master_object, &zp);
			if (error == 0) {
				if (zsb->z_dirlowdata_obj == 0){
					dirlowdata->ret= ENOENT;
					cmn_err(CE_WARN, "%s:get dirlowdata_obj FAIL !!! zfsvfs->z_dirlowdata_obj==0 ", __func__);
				}else{
					error = zfs_get_dir_low(zsb, zp->z_dirlowdata, &dirlowdata->dirlowdata);
					dirlowdata->ret= error;
				}
				iput(ZTOI(zp));
				bcopy(dirlowdata, cmd_return, sizeof(fs_dir_lowdata_t));
			}
			kmem_free(dirlowdata, sizeof(fs_dir_lowdata_t));
		}
	}
	break;
	
	case SC_FS_DIRQUOTA: {
		if (!(zsb->z_os->os_is_master && msg_header->orig_type == APP_GROUP)) {
			zfs_cl_set_dirquota_t *dirquota = kmem_zalloc(sizeof(zfs_cl_set_dirquota_t), 
											    KM_SLEEP);
			bcopy(cmd_arg, dirquota, cmd_arg_size);
			error = zfs_set_dir_quota(zsb, dirquota->object, dirquota->path, dirquota->quota);
			kmem_free(dirquota, sizeof(zfs_cl_set_dirquota_t));
			bcopy(&error, cmd_return, sizeof(int));
		}
	}
	break;

	case SC_FS_USERQUOTA: {
		if (!(zsb->z_os->os_is_master && msg_header->orig_type == APP_GROUP)) {
			uint64_t rid = 0;
			zfs_cl_set_userquota_t *userquota = kmem_zalloc(sizeof(zfs_cl_set_userquota_t), 
												    KM_SLEEP);
			bcopy(cmd_arg, userquota, cmd_arg_size);

			/** get rid from username **/
			
			error = zfs_set_userquota(zsb, userquota->type, userquota->domain, rid, userquota->quota);
			kmem_free(userquota, sizeof(zfs_cl_set_userquota_t));
			bcopy(&error, cmd_return, sizeof(int));
		}
	}
	break;

	case SC_ZFS_IOCTL:

	break;

	case SC_FS_GET_DATA_ATTR: {
		if (!(zsb->z_os->os_is_master && msg_header->orig_type == APP_GROUP)) {
			znode_t *zp;
			fs_data_file_attr_t *data_file_size = kmem_zalloc(sizeof(fs_data_file_attr_t), KM_SLEEP);
			bcopy(cmd_arg, data_file_size, cmd_arg_size);
			error = zfs_zget(zsb, data_file_size->data_object, &zp);
			if (error == 0) {
				data_file_size->ret= error;
				data_file_size->data_filesize = zp->z_size;

				sa_object_size(zp->z_sa_hdl,
			    (uint32_t *)&data_file_size->data_fileblksz,
			    (u_longlong_t *)&data_file_size->data_filenblks);
				
				iput(ZTOI(zp));
				bcopy(data_file_size, cmd_return, sizeof(fs_data_file_attr_t));
			}
			kmem_free(data_file_size, sizeof(fs_data_file_attr_t));
		}
	}
	break;

	case SC_UNFLAG_OVERQUOTA: {
		zfs_group_dirquota_id_t dirquota_id;
		/* get dirquota_id */
		bcopy(cmd_arg, &dirquota_id, sizeof(dirquota_id));
		if (0 == dirquota_id.new_dirquota_id && 0 != dirquota_id.old_dirquota_id) {
			zfs_set_overquota(zsb, dirquota_id.old_dirquota_id, B_FALSE, B_TRUE, NULL);
		} else if (dirquota_id.old_dirquota_id == dirquota_id.new_dirquota_id) {
			zfs_set_overquota(zsb, dirquota_id.old_dirquota_id, B_FALSE, B_FALSE, NULL);
		} /* nothing should be done for "else" */
	}
	break;

	default:
	break;
	}

	zfs_sb_group_rele(zsb, FTAG);
	return (error);
}

static void zfs_group_write_to_client(zfs_group_server_para_t *server_para)
{
	zfs_group_header_t *msg_header = server_para->msg_header;
	zfs_msg_t *msg_data = server_para->msg_data;

	if (((msg_header->error != 0 && msg_header->error != ENOSYS)
	    && !((msg_header->command == ZFS_GROUP_CMD_NAME || msg_header->command == ZFS_GROUP_CMD_NAME_BACKUP)
	    && msg_header->operation == NAME_LOOKUP && (msg_header->error == ENOENT
	    || msg_header->error == EACCES)) 
	    && !(msg_header->command == ZFS_GROUP_CMD_ZNODE
	    && (msg_header->operation == ZNODE_FREE || msg_header->operation == ZNODE_ACCESS) 
	    && (msg_header->error == ENOENT || msg_header->error == EACCES))) ||
	    msg_header->server_spa == 0 ||
	    msg_header->server_os == 0 || (msg_header->server_object == 0 &&
	    msg_header->command == ZFS_GROUP_CMD_CMD &&
	    msg_header->operation != SC_FS_STAT)) {
	    if((msg_header->command == ZFS_GROUP_CMD_ZNODE && msg_header->operation == ZNODE_SEARCH) ||
			(msg_header->command == ZFS_GROUP_CMD_NAME && msg_header->operation == NAME_REMOVE 
			&& msg_header->error == ENOENT) ||
			(msg_header->command == ZFS_GROUP_CMD_CMD && msg_header->operation == SC_FS_GET_DATA_ATTR
			&& msg_header->error == ENOENT) || 
			(msg_header->command == ZFS_GROUP_CMD_ZNODE && msg_header->operation == ZNODE_GET
			&& msg_header->error == ENOENT)){
			/* Do nothing, it it is  ZFS_GROUP_CMD_ZNODE with hdr.command == ZNODE_SEARCH. */
		}else{
			zfs_group_msg(msg_header, msg_data, B_TRUE, B_FALSE, B_TRUE);
		}
	}
}

static uint64_t
copy_nvlist(nvlist_t *nvl, char *dest)
{
	size_t size;

	VERIFY(nvlist_size(nvl, &size, NV_ENCODE_NATIVE) == 0);
	if (size > ZFS_MULTICLUS_NVLIST_MAXSIZE) {
		cmn_err(CE_WARN, "%s: size is out of memory!!!", __func__);
		return (0);
	}

	VERIFY(nvlist_pack(nvl, &dest, &size, NV_ENCODE_NATIVE,
	    KM_SLEEP) == 0);

	return (size);
}

static int zfs_group_process_stat(nvlist_t **config, uint64_t guid)
{
	int error = 0;
	spa_t *spa;
	nvlist_t *nv = NULL;
//	char *name;

	if ((spa = spa_by_guid(guid, 0)) == NULL) {
		cmn_err(CE_WARN, "%s: get spa by guid fail!!!", __func__);
		return (ENOENT);
	}
	error = spa_get_stats(spa_name(spa), &nv, NULL, 0);
	if(!error)
	{
		*config = nv;
	}

	return (error);
}

static int zfs_group_server_process_stat(zfs_group_server_para_t *server_para)
{
	int	error = 0;
	uint64_t	dst_spa = 0;
	void	*cmd_return = NULL;
	nvlist_t	*config = NULL;
	zfs_group_header_t	*msg_header = server_para->msg_header;
	zfs_group_stat_msg_t	*stat_msg = (zfs_group_stat_msg_t *)server_para->msg_data; 
	zfs_group_iostat_t	*stat = &stat_msg->call.stat;

	cmd_return = stat->stat;

	switch (msg_header->operation) {
		case SC_IOSTAT: 
			dst_spa = msg_header->server_spa;
			error = zfs_group_process_stat(&config, dst_spa); 
			if(!error)
			{
				stat->arg.return_size = copy_nvlist(config, (char *)cmd_return);
				if(config)
				{
					nvlist_free(config);
				}
			}

			break;

		case SC_STATUS:

		break;
	}

	return (error);
}

static int zfs_group_process_scrub( uint64_t spaid, uint64_t scop)
{
	spa_t *spa;
	int error;

	if ((spa = spa_by_guid(spaid, 0)) == NULL) {
		cmn_err(CE_WARN, "%s: get spa by guid fail!!!", __func__);
		return (ENOENT);
	}

	if (scop == POOL_SCAN_NONE)
		error = spa_scan_stop(spa);
	else
		error = spa_scan(spa, scop);

	return (error);
}


static int zfs_group_server_process_scrub(zfs_group_server_para_t *server_para)
{
	int	error = 0;
	fs_scrub_t	sc_info = {0};
	char	retstr[8];
	void	*cmd_return = NULL;
	zfs_group_header_t	*msg_header = server_para->msg_header;
	zfs_group_stat_msg_t	*stat_msg = (zfs_group_stat_msg_t *)server_para->msg_data; 
	zfs_group_iostat_t	*stat = &stat_msg->call.stat;


	bcopy(stat->stat, &sc_info, stat->arg.arg_size);
	cmd_return = stat->stat;

	switch (msg_header->operation) {
		case SC_SCRUB: 
			error = zfs_group_process_scrub(sc_info.spa_id, sc_info.sc_op ); 
			sprintf(retstr, "%d", error);
			bcopy(retstr, cmd_return, 7);
			stat->arg.return_size = 8;
			error = 0;

			break;

		case SC_STATUS:

			break;
	}

	return (error);
}

static int zfs_group_process_dirld(const char * dsname, nvpairvalue_t* pairvalue)
{
	int error;
	error = zfs_prop_proc_dirlowdata(dsname, pairvalue);
	return (error);
}

static int zfs_group_server_process_dirld(zfs_group_server_para_t *server_para)
{
	int	error = 0;
	uint64_t	server_spa = 0;
	uint64_t	server_os = 0;
	uint64_t	dirld_arg_size = 0;
	uint64_t	dirld_return_size = 0;
	char	dsname[MAX_FSNAME_LEN]={0};
	void	*dirld_return = NULL;
	zfs_sb_t  *zsb = NULL;
	dir_lowdata_t	*dl_info = kmem_zalloc(sizeof(dir_lowdata_t), KM_SLEEP);
	dir_lowdata_carrier_t	*dirld_carrier = kmem_zalloc(sizeof(dir_lowdata_carrier_t), KM_SLEEP);
	zfs_group_stat_msg_t	*stat_msg = (zfs_group_stat_msg_t *)server_para->msg_data; 
	zfs_group_header_t	*msg_header = server_para->msg_header;
	zfs_group_iostat_t	*stat = &stat_msg->call.stat;


	if(NULL == dirld_carrier){
		return (ENOMEM);
	}

	server_spa = msg_header->server_spa;
	server_os = msg_header->server_os;
	dirld_arg_size = stat->arg.arg_size;
	dirld_return_size = stat->arg.return_size;
	dirld_return = stat->stat;
	
	if ((error = zfs_multiclus_get_fsname(server_spa, server_os, dsname))){
		cmn_err(CE_WARN, "%s: get master fsname FAIL !!!",__func__);
		return (error);
	}

	switch (msg_header->operation) {
		
		case SC_DIR_LOW: {
	
			bcopy(dirld_return, dl_info, dirld_arg_size);
			error = zfs_group_process_dirld(dsname, &dl_info->pairvalue); 
			bcopy(&error, dirld_return, sizeof(int));
			dirld_return_size = sizeof(int);
			error = 0;
		}
			break;
			
		case SC_FS_DIRLOWDATALIST: {
		
			bcopy(dirld_return, dirld_carrier, dirld_arg_size);

			zsb = zfs_sb_group_hold(msg_header->server_spa, msg_header->server_os, FTAG, B_TRUE);
			if (zsb == NULL){
				if(NULL != dirld_carrier)
					kmem_free(dirld_carrier, sizeof(dir_lowdata_carrier_t));
				return (EGHOLD);
			}
			
			if (zsb->z_dirlowdata_obj == 0){
				dirld_carrier->dir_lowdata.ret= ENOENT;
				cmn_err(CE_WARN, "%s:get dirlowdata_obj FAIL !!! zsb->z_dirlowdata_obj==0 ", __func__);
			}else{
				error = zfs_get_dir_lowdata_many(zsb, &dirld_carrier->cookie, 
					&dirld_carrier->buf.dbuf, &dirld_carrier->bufsize);
				dirld_carrier->dir_lowdata.ret= error;
			}					

			bcopy(dirld_carrier, dirld_return, dirld_return_size);
			zfs_sb_group_rele(zsb, FTAG);
			
		}
			break;

		case SC_FS_DIRQUOTALIST: {

			bcopy(dirld_return, dirld_carrier, dirld_arg_size);
			
			zsb = zfs_sb_group_hold(msg_header->server_spa, msg_header->server_os, FTAG, B_TRUE);
			if (zsb == NULL){
				if(NULL != dirld_carrier)
					kmem_free(dirld_carrier, sizeof(dir_lowdata_carrier_t));
				return (EGHOLD);
			}
			
			if (zsb->z_dirquota_obj== 0){
				dirld_carrier->dir_lowdata.ret = ENOENT;
				cmn_err(CE_WARN, "%s:get dirquota_obj FAIL !!! zfsvfs->z_dirquota_obj==0 ", __func__);
			}else{
				error = zfs_get_dir_qutoa_many(zsb, &dirld_carrier->cookie, 
					&dirld_carrier->buf.qbuf, &dirld_carrier->bufsize);
				dirld_carrier->dir_lowdata.ret = error;
			}

			bcopy(dirld_carrier, dirld_return, dirld_return_size);
			zfs_sb_group_rele(zsb, FTAG);
			
		}
			break;
			
		case SC_FS_DIR_QUOTA:{
			zfs_dirquota_t *dirquota = NULL;
			bcopy(dirld_return, dl_info, dirld_arg_size);

			dirquota = kmem_zalloc(sizeof(zfs_dirquota_t), KM_SLEEP);

			zsb = zfs_sb_group_hold(msg_header->server_spa, msg_header->server_os, FTAG, B_TRUE);
			if (zsb == NULL){	
				if(NULL != dirquota)
				kmem_free(dirquota, sizeof(zfs_dirquota_t));
				return (EGHOLD);
			}
			
			if (zsb->z_dirquota_obj == 0){
				dl_info->ret= ENOENT;
				cmn_err(CE_WARN, "%s:get z_dirquota_obj FAIL !!! zfsvfs->z_dirquota_obj==0 ", __func__);
			}else{
				error = zfs_get_dirquota(zsb, dl_info->pairvalue.object, dirquota);
				dl_info->ret = error;
			}
			
			bcopy(dirquota, dirld_return, dirld_return_size);
			if(NULL != dirquota)
				kmem_free(dirquota, sizeof(zfs_dirquota_t));
			zfs_sb_group_rele(zsb, FTAG);
		}
			break;
			
		case SC_DIR_LOW_MAX:

			break;
	}

	if(NULL != dirld_carrier)
		kmem_free(dirld_carrier, sizeof(dir_lowdata_carrier_t));
	if(NULL != dl_info)
		kmem_free(dirld_carrier, sizeof(dir_lowdata_t));
	return (error);
}


void zfs_group_server_rx(zfs_group_server_para_t *server_para)
{
	int	error = 0;
	ushort_t	cmd = server_para->msg_header->command;
	if ((server_para->msg_header->error != 0 && server_para->msg_header->error != ENOSYS)
	    || server_para->msg_header->server_spa == 0 ||
	    server_para->msg_header->server_os == 0 || (server_para->msg_header->server_object == 0 && (server_para->msg_header->command != ZFS_GROUP_CMD_NAME_BACKUP) 
	    && !((server_para->msg_header->command == ZFS_GROUP_CMD_NAME ||
	    server_para->msg_header->command == ZFS_GROUP_CMD_STAT ||
	    server_para->msg_header->command == ZFS_GROUP_CMD_SCRUB ||
	    server_para->msg_header->command == ZFS_GROUP_CMD_DIRLD) &&
	    server_para->msg_header->orig_type == APP_GROUP))) {
	    if ((server_para->msg_header->command == ZFS_GROUP_CMD_NAME && server_para->msg_header->operation == NAME_REMOVE 
			&& server_para->msg_header->error == ENOENT) ||
			(server_para->msg_header->command == ZFS_GROUP_CMD_CMD && server_para->msg_header->operation == SC_FS_GET_DATA_ATTR
			&& server_para->msg_header->error == ENOENT) || 
			(server_para->msg_header->command == ZFS_GROUP_CMD_ZNODE && server_para->msg_header->operation == ZNODE_GET
			&& server_para->msg_header->error == ENOENT)) {
			/*Do nothing*/
		} else {
			zfs_group_msg(server_para->msg_header, server_para->msg_data, B_TRUE, B_TRUE, B_TRUE);
		}
	}
	switch(cmd) {
		case ZFS_GROUP_CMD_NAME:
			error = zfs_group_process_name_request(server_para);
		break;

		case ZFS_GROUP_CMD_NAME_BACKUP:
			error = zfs_group_process_name_backup_request(server_para);
		break;

		case ZFS_GROUP_CMD_DATA:
			error = zfs_group_process_data_request(server_para);
		break;

		case ZFS_GROUP_CMD_ZNODE:
			error = zfs_group_process_znode_request(server_para);
		break;

		case ZFS_GROUP_CMD_ZNODE_BACKUP:
			error = zfs_group_process_znode_request_backup(server_para);
		break;

		case ZFS_GROUP_CMD_NOTIFY:
			error = zfs_group_process_notify(server_para);
		break;

		case ZFS_GROUP_CMD_CMD:
			error = zfs_group_process_system_cmd(server_para);
		break;

		case ZFS_GROUP_CMD_STAT:
			error = zfs_group_server_process_stat(server_para);
		break;

		case ZFS_GROUP_CMD_SCRUB:
			error = zfs_group_server_process_scrub(server_para);
		break;

		case ZFS_GROUP_CMD_DIRLD:
			error = zfs_group_server_process_dirld(server_para);
		break;
		
		default:
			cmn_err(CE_WARN, "%s %d %d", __func__, __LINE__, cmd);
		break;
	}

	server_para->msg_header->msg_type = MSG_REPLY;
	server_para->msg_header->length = server_para->msg_header->out_length;
	server_para->msg_header->error = error;
	if (cmd != ZFS_GROUP_CMD_NOTIFY)
		zfs_group_write_to_client(server_para);
}
#endif
