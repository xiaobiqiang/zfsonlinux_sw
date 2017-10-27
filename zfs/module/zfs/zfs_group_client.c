#ifdef _KERNEL
#include <sys/ddi.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/taskq.h>
#include <sys/uio.h>
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
#include <sys/attr.h>
#include <sys/dmu_tx.h>
#include <sys/crc32.h>
#include <sys/zfs_multiclus.h>
#include <sys/zfs_group.h>
#include <sys/mode.h>
#include <sys/dsl_dataset.h>
#include <sys/zfs_group_dtl.h>
#include <sys/cred.h>
#include <sys/fs/zfs_hbx.h>


extern kmutex_t	multiclus_mtx;

int debug_print = 0;
size_t zfs_group_max_dataseg_size = 512 * 1024;
size_t zfs_group_max_dir_read_size = 32 * 1024;


const char *no_names[NAME_MAX_OP] = {
	"CREATE",
	"REMOVE",
	"REMOVE Data",
	"MKDIR",
	"RMDIR",
	"LINK",
	"RENAME",
	"SYMLINK",
	"ACL",
	"LOOKUP",
	"NAME_ZNODE_SETATTR"
};

const char *do_names[DATA_MAX_OP] = {
	"DIR_READ",
	"LINK_READ",
	"DATA_READ",
	"DATA_WRITE",
	"MIGRATE_DATA",
	"XATTR_LIST"
};

const char *zo_names[ZNODE_MAX_OP] = {
	"SET_ATTR",
	"ACCESS",
	"ACQUIRE_ZNODE",
	"FREE_ZNODE",
	"SEARCH_ZNODE"
};

const char *sc_names[SC_MAX_OP] = {
	"FS_STAT",
	"FS_QUOTA",
	"FS_DIRLOWDATA",
	"FS_DIRQUOTA",
	"FS_USERQUOTA",
	"POOL/FS IOCTL",
	"SC_FS_GET_DATA_ATTR",
	"UNFLAG_OVERQUOTA"
};

const char *cmd_names[SAM_CMD_MAX]= {
	"NAME",
	"DATA",
	"ZNODE",
	"NOTIFY",
	"SYSTEM CMD",
	"STATA",
	"SCRUB",
	"DIRLD",
	"NAME_BACKUP",
	"ZNODE_BACKUP"
};

const char *msg_names[MSG_MAX] = {
	"Request",
	"Reply",
	"Notify"
};

const char *notify_names[NOTIFY_MAX] = {
	"System Space",
	"File Size",
	"File Info",
	"Data Dirty"
};

static void zfs_group_acl_msg(char *omsg, zfs_group_name_acl_t *zg_acl);

int	zfs_group_proc_znode(znode_t *zp, znode_operation_t op, void *ptr,	
	cred_t *credp, boolean_t watting);
boolean_t zfs_server_is_online(uint64_t ser_spa, uint64_t ser_os);
// extern int zfs_nasavs_printf_clnt_group_id_dtl(const char *func, int line, zfs_group_object_t group_id);

void zfs_group_acquire_znode_error(znode_t *zp, zfs_group_object_t *group_object, 
    zfs_group_phys_t *object_phy, const char *label)
{
	int type;
	boolean_t lookup_error = B_FALSE;
	zfs_sb_t *zsb = ZTOZSB(zp);

	if (zp->z_id != zsb->z_root &&  (group_object->master_spa == 0 || group_object->master_objset ==0 ||
		group_object->master_object == 0)){
		lookup_error = B_TRUE;
	} else {
		type = IFTOVT(object_phy->zp_mode);
		if (type == VREG) {
			if (group_object->data_spa == 0 || group_object->data_objset ==0 ||
			    group_object->data_object == 0){
				lookup_error = B_TRUE;
			}
		}
	}

	if (lookup_error) {
		cmn_err(CE_WARN, "%s acquire znode fails: master_spa=%llx, "
		    "master_os=%lld, master_object=%lld"
		    "data_spa=%lld,"
		    "data_objset=%llx,  data_obejct = %lld, blocks=%lld, blksz=%lld",
		    label,
		    (longlong_t)group_object->master_spa,
		    (longlong_t)group_object->master_objset,
		    (longlong_t)group_object->master_object,
		    (longlong_t)group_object->data_spa,
		    (longlong_t)group_object->data_objset,
		    (longlong_t)group_object->data_object,
		    (longlong_t)object_phy->zp_nblocks,
		    (longlong_t)object_phy->zp_blksz);
	}
}


int print_cmd = 0;
int print_op = 0;


void zfs_group_msg(zfs_group_header_t *msg_header, zfs_msg_t *msg_data, boolean_t bserver, boolean_t brx, 
    boolean_t bprint)
{
	uint8_t cmd = msg_header->command;
	uint8_t op = msg_header->operation;
	char *str_op = NULL;
	char *para_op = NULL;
	boolean_t binter_print = B_FALSE;


	if (bprint || (print_cmd == cmd && print_op == op)){
		binter_print = B_TRUE;
	} else {
		return;
	}

	str_op = kmem_zalloc(2048, KM_SLEEP);
	para_op = kmem_zalloc(1024, KM_SLEEP);
	strcpy(str_op, "default");
	switch (cmd) {
		case ZFS_GROUP_CMD_NOTIFY:
			strcpy(str_op, notify_names[op -1]);
		break;

		case ZFS_GROUP_CMD_NAME_BACKUP:
		case ZFS_GROUP_CMD_NAME: {
			void *component = NULL;
			if ((!bserver && !brx) || (bserver && brx) ) {
				component = (zfs_group_name_acl_t *)&msg_data->call.name.component;
			} else if ((bserver && !brx) || (!bserver && brx)) {
				component = (zfs_group_name_acl_t *)&msg_data->call.name2.component;
			}
			if (op != NAME_ACL) {
				if ((!bserver && !brx) || (bserver && brx) ) {
					sprintf(str_op, "%s (%s name)", no_names[op -1], (char *)component);
				}
				else if ((bserver && !brx) || (!bserver && brx)) {
					sprintf(str_op, "%s (%s name)", no_names[op -1], (char *)component);
				}
			} else {
				zfs_group_name_acl_t *zg_acl;
				zg_acl = (zfs_group_name_acl_t *)component;
				if (zg_acl->set == 0) {
					sprintf(str_op, "%s: %s ", no_names[op -1], "Get acl");
				} else {
					sprintf(str_op, "%s: %s ", no_names[op -1], "Set acl");
				}
			zfs_group_acl_msg(para_op, zg_acl);
			binter_print = B_TRUE;
			}
		}
		break;

		case ZFS_GROUP_CMD_DATA:
			strcpy(str_op, do_names[op-1]);
		break;

		case ZFS_GROUP_CMD_ZNODE_BACKUP:
		case ZFS_GROUP_CMD_ZNODE:
			strcpy(str_op, zo_names[op -1]);
		break;

		case ZFS_GROUP_CMD_CMD:
			strcpy(str_op, sc_names[op-1]);
		break;

		default:
		break;
	}

	if (binter_print) {
		cmn_err(CE_WARN, "Error(%lld): %s %s %s %s %s cmd %s operation message:"
			
		    "(Server_spa:%llx, Server_objset:%lld  Server_object:%lld"
		    " Client_spa:%llx, Client_objset:%lld, Client_object:%lld)"
		    " Data_spa:%llx, data_objset:%lld, data_object:%lld)"
		    " Send Length(%lld)"
		    " Reply Length(%lld) Paras:%s",
		    (longlong_t)msg_header->error,
		    msg_header->orig_type == APP_USER ? "User(NFS/CIFS) " : "Group",
		    bserver ? "Server" : "client",
		    brx ? "Receive" : "Send",
		    msg_names[msg_header->msg_type -1],
		    cmd_names[cmd -1],
		    str_op,

		    (longlong_t)msg_header->server_spa,
		    (longlong_t)msg_header->server_os, 
		    (longlong_t)msg_header->server_object,
		    (longlong_t)msg_header->client_spa, 
		    (longlong_t)msg_header->client_os, 
		    (longlong_t)msg_header->client_object, 
		    (longlong_t)msg_header->data_spa, 
		    (longlong_t)msg_header->data_os, 
		    (longlong_t)msg_header->data_object, 
		    (longlong_t)msg_header->length, 
		    (longlong_t)msg_header->out_length,
		    para_op
		);
	}

	kmem_free(str_op, 2048);
	kmem_free(para_op, 1024);
}

boolean_t zfs_group_znode_data_is_master(znode_t *zp)
{
	if ((zp->z_group_id.master_spa == zp->z_group_id.data_spa
		&& zp->z_group_id.master_objset == zp->z_group_id.data_objset
		&& zp->z_group_id.master_object == zp->z_group_id.data_object)
		|| (zp->z_group_id.master2_spa == zp->z_group_id.data_spa
		&& zp->z_group_id.master2_objset == zp->z_group_id.data_objset
		&& zp->z_group_id.master2_object == zp->z_group_id.data_object)
		|| (zp->z_group_id.master3_spa == zp->z_group_id.data_spa
		&& zp->z_group_id.master3_objset == zp->z_group_id.data_objset
		&& zp->z_group_id.master3_object == zp->z_group_id.data_object)
		|| (zp->z_group_id.master4_spa == zp->z_group_id.data_spa
		&& zp->z_group_id.master4_objset == zp->z_group_id.data_objset
		&& zp->z_group_id.master4_object == zp->z_group_id.data_object)) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

boolean_t zfs_group_znode_data2_is_master(znode_t *zp)
{
	if ((zp->z_group_id.master_spa == zp->z_group_id.data2_spa
		&& zp->z_group_id.master_objset == zp->z_group_id.data2_objset
		&& zp->z_group_id.master_object == zp->z_group_id.data2_object)
		|| (zp->z_group_id.master2_spa == zp->z_group_id.data2_spa
		&& zp->z_group_id.master2_objset == zp->z_group_id.data2_objset
		&& zp->z_group_id.master2_object == zp->z_group_id.data2_object)
		|| (zp->z_group_id.master3_spa == zp->z_group_id.data2_spa
		&& zp->z_group_id.master3_objset == zp->z_group_id.data2_objset
		&& zp->z_group_id.master3_object == zp->z_group_id.data2_object)
		|| (zp->z_group_id.master4_spa == zp->z_group_id.data2_spa
		&& zp->z_group_id.master4_objset == zp->z_group_id.data2_objset
		&& zp->z_group_id.master4_object == zp->z_group_id.data2_object)) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

uint64_t zfs_group_send_seq(objset_t *os)
{
	uint64_t seq;

	seq = atomic_add_64_nv(&os->os_group_tx_seq, 1);
	return (seq);
}


static void zfs_group_build_header(objset_t *os,
    zfs_group_header_t *hdr, uint64_t cmd, share_flag_t wait_flag, 
    uint64_t op, uint64_t length, uint64_t out_length, uint64_t server_spa, 
    uint64_t server_os, uint64_t server_object, uint64_t master_object,
    uint64_t data_spa, uint64_t data_os, uint64_t data_object,
    msg_op_type_t op_type, msg_orig_type_t orig_type)
{
	hdr->magic = ZFS_GROUP_MAGIC;
	hdr->op_type = op_type;
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

static void zfs_group_build_header_backup(objset_t *os,
    zfs_group_header_t *hdr, uint64_t cmd, share_flag_t wait_flag, 
    uint64_t op, uint64_t length, uint64_t out_length, uint64_t server_spa, 
    uint64_t server_os, uint64_t server_object, uint64_t master_object,
    uint64_t data_spa, uint64_t data_os, uint64_t data_object,
    msg_op_type_t op_type, msg_orig_type_t orig_type, zfs_group_object_t* z_group_id, 
    	zfs_multiclus_node_type_t m_node_type)
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

/* Below is Parent znodes's master2 object. */
	hdr->master_object = master_object;

/* Below are child znode's mater (spa, os, obj) */
	hdr->client_os = z_group_id->master_objset;
	hdr->client_spa = z_group_id->master_spa;
	hdr->client_object = z_group_id->master_object;

/* Below is Parent znodes's masterx (spa, os, obj). */

	hdr->server_spa = server_spa;
	hdr->server_os = server_os;
	hdr->server_object = server_object;

/* Set it master x */
	hdr->master_gen = z_group_id->master_gen;

	hdr->master2_spa = z_group_id->master2_spa;
	hdr->master2_os = z_group_id->master2_objset;
	hdr->master2_object = z_group_id->master2_object;
	hdr->master2_gen = z_group_id->master2_gen;

	hdr->master3_spa = z_group_id->master3_spa;
	hdr->master3_os = z_group_id->master3_objset;
	hdr->master3_object = z_group_id->master3_object;
	hdr->master3_gen = z_group_id->master3_gen;

	hdr->master4_spa = z_group_id->master4_spa;
	hdr->master4_os = z_group_id->master4_objset;
	hdr->master4_object = z_group_id->master4_object;
	hdr->master4_gen = z_group_id->master4_gen;

	hdr->m_node_type = m_node_type;

/* Below is child znode's data file (spa, os, obj) */
	hdr->data_spa = data_spa;
	hdr->data_os = data_os;
	hdr->data_object = data_object;
	hdr->data2_spa = z_group_id->data2_spa;
	hdr->data2_os = z_group_id->data2_objset;
	hdr->data2_object = z_group_id->data2_object;
	hdr->reset_seqno = 0;
}


int zfs_group_send_to_remote_server(objset_t *os, 	zfs_group_header_t *msg_header, zfs_msg_t *msg_data)
{
	int err = 0;
	err = zfs_multiclus_write_operate_msg(os, msg_header, (void *)msg_data, msg_header->length);
	return (err);
}

int			/* ERRNO if error, 0 if successful. */
zfs_group_v_to_v32(vattr_t *vap, zfs_group_vattr_t *va32p)
{
	uint_t mask = vap->va_mask;

	bzero(va32p, sizeof (zfs_group_vattr_t));
	va32p->va_mask = vap->va_mask;		/* Bit-mask of attributes */

	if (mask & AT_MODE) {
		va32p->va_mode = vap->va_mode;	/* File access mode */
	}
	if (mask & AT_UID) {
		va32p->va_uid = vap->va_uid;	/* User id */
	}
	if (mask & AT_GID) {
		va32p->va_gid = vap->va_gid;	/* Group id */
	}
	if (mask & AT_SIZE) {
		va32p->va_rsize = vap->va_size;	/* File size in bytes */
	}
	if (mask & AT_ATIME) {
		ZFS_GROUP_TIMESPEC_TO_TIMESPEC32(&va32p->va_atime, &vap->va_atime);
	}
	if (mask & AT_MTIME) {
		ZFS_GROUP_TIMESPEC_TO_TIMESPEC32(&va32p->va_mtime, &vap->va_mtime);
	}
	if (mask & AT_CTIME) {
		ZFS_GROUP_TIMESPEC_TO_TIMESPEC32(&va32p->va_ctime, &vap->va_ctime);
	}
	return (0);
}


void
zfs_group_set_cred(cred_t *credp, zfs_group_cred_t *group_credp)
{
	int i;

	group_credp->cr_ref = crgetref(credp);
	group_credp->cr_uid = crgetuid(credp);
	group_credp->cr_gid = crgetgid(credp);
	group_credp->cr_ruid = crgetruid(credp);
	group_credp->cr_rgid = crgetrgid(credp);
	group_credp->cr_suid = crgetsuid(credp);
	group_credp->cr_sgid = crgetsgid(credp);
	group_credp->cr_ngroups = crgetngroups(credp);
	for (i = 0; i < group_credp->cr_ngroups; i++) {
	    group_credp->cr_groups[i] = crgetgroups(credp)[i];}
}



// int
// zfs_group_reset_client_acl(char *acl, int nacl, void *aclents)
// {
// 		bcopy(aclents, acl, nacl* sizeof (aclent_t));
// 		return (0);
// }

void zfs_group_znode_copy_phys(znode_t *zp, zfs_group_phys_t *dst_phys, boolean_t nosa)
{
	uint64_t blksz = 0;
	uint64_t nblks = 0;
	zfs_sb_t *zsb = ZTOZSB(zp);
	struct inode *ip = ZTOI(zp);
	bzero(dst_phys, sizeof(zfs_group_phys_t));
	dst_phys->zp_mode = zp->z_mode;
	dst_phys->zp_gid = KGID_TO_SGID(ip->i_gid);
	dst_phys->zp_uid = KUID_TO_SUID(ip->i_uid);
	dst_phys->zp_gen = zp->z_gen;
	dst_phys->zp_size = zp->z_size ;
	dst_phys->zp_links = (uint64_t)ip->i_nlink;
	dst_phys->zp_flags = zp->z_pflags;
	dst_phys->zp_blksz = zp->z_blksz;
	dst_phys->zp_dirquota = zp->z_dirquota;
	dst_phys->zp_dirlowdata = zp->z_dirlowdata;
	dst_phys->zp_low = zp->z_low;
	dst_phys->zp_overquota = zp->z_overquota;
	dst_phys->zp_old_gen = zp->z_old_gen;
	dst_phys->zp_bquota = zp->z_bquota;
	dst_phys->zp_is_ctldir = zp->z_is_ctldir;
	ZFS_TIME_ENCODE(&ip->i_atime, dst_phys->zp_atime);
	ZFS_TIME_ENCODE(&ip->i_ctime, dst_phys->zp_ctime);
	ZFS_TIME_ENCODE(&ip->i_mtime, dst_phys->zp_mtime);

	dst_phys->ino = ip->i_ino;
	if (!nosa && zp->z_sa_hdl != NULL) {
		if ((zp->z_id == zsb->z_root) ||
		    ((zp->z_group_id.data_spa == spa_guid(dmu_objset_spa(zsb->z_os)))
		    && (zp->z_group_id.data_objset == dmu_objset_id(zsb->z_os)))) {
		    sa_object_size(zp->z_sa_hdl,
			    (uint32_t *)&dst_phys->zp_blksz,
			    (u_longlong_t *)&dst_phys->zp_nblocks);
		} else {
			if (zp->z_group_id.data_spa == spa_guid(dmu_objset_spa(zsb->z_os))) {
				sa_object_size(zp->z_sa_hdl, (uint32_t *)&blksz, (u_longlong_t *)&nblks);
				dst_phys->zp_blksz = blksz;
				dst_phys->zp_nblocks = nblks;
			} else {
				sa_lookup(zp->z_sa_hdl, SA_ZPL_NBLKS(zsb),
				    &dst_phys->zp_nblocks,
				    sizeof (uint64_t));
				sa_lookup(zp->z_sa_hdl, SA_ZPL_BLKSZ(zsb),
				    &dst_phys->zp_blksz,
				    sizeof (uint64_t));
			}
		}
		sa_lookup(zp->z_sa_hdl, SA_ZPL_SCANSTAMP(zsb),
		    &dst_phys->zp_scan,
		    sizeof (uint64_t) * 4);
	} else {
		dst_phys->zp_nblocks = zp->z_nblks;
		dst_phys->zp_blksz = zp->z_blksz;
	}
}

void zfs_group_znode_reset_phys(znode_t *zp, zfs_group_phys_t *src_phys)
{
	struct inode *ip = ZTOI(zp);
	zp->z_mode = src_phys->zp_mode;
	zp->z_gid = src_phys->zp_gid;
	zp->z_uid = src_phys->zp_uid;
	ip->i_gid = SGID_TO_KGID(src_phys->zp_gid);
	ip->i_uid = SUID_TO_KUID(src_phys->zp_uid);
	zp->z_gen = src_phys->zp_gen;
	zp->z_size = src_phys->zp_size;
	zp->z_links = src_phys->zp_links;
	ip->__i_nlink = (unsigned int)src_phys->zp_links;
	zp->z_pflags = src_phys->zp_flags ;
	zp->z_blksz = src_phys->zp_blksz;
	zp->z_nblks = src_phys->zp_nblocks;
	zp->z_blksz = src_phys->zp_blksz;
	zp->z_dirquota = src_phys->zp_dirquota;
	zp->z_dirlowdata = src_phys->zp_dirlowdata;
	zp->z_old_gen = src_phys->zp_old_gen;
	zp->z_bquota = src_phys->zp_bquota ;
	bcopy(src_phys->zp_atime, zp->z_atime, sizeof(uint64_t) *2);
	bcopy(src_phys->zp_ctime, zp->z_ctime, sizeof(uint64_t) *2);
	bcopy(src_phys->zp_mtime, zp->z_mtime, sizeof(uint64_t) *2);
	ZFS_TIME_DECODE(&ip->i_atime, src_phys->zp_atime);
	ZFS_TIME_DECODE(&ip->i_mtime, src_phys->zp_mtime);
	ZFS_TIME_DECODE(&ip->i_ctime, src_phys->zp_ctime);
	ZTOI(zp)->i_ino = src_phys->ino;
}


static int zfs_group_proc_name(
    znode_t *zp, name_operation_t op,	
    void *ptr, int argsize, char *cp, uint64_t cplen,
    char *ncp, int32_t flags, cred_t *credp, void *nrec)
{

	uint64_t request_length;
	uint64_t reply_length;
	zfs_sb_t *zsb;
//	zfs_msg_t *zfs_msg;
	zfs_group_name_msg_t *name_msg;
	zfs_group_header_t *msg_header;
	zfs_group_name_t *np;
	uint64_t dst_spa;
	uint64_t dst_os;
	uint64_t dst_object;
	msg_orig_type_t msg_orig;
	int param_len = 0;
	int error;
//	int r;

	zsb = ZTOZSB(zp);
	name_msg = kmem_zalloc(sizeof(zfs_group_name_msg_t), KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	np = &name_msg->call.name;

	mutex_enter(&zp->z_lock);
	if (zp->z_id == zsb->z_root && ZFS_GROUP_OBJECT_ZERO(zp)) {
		zp->z_group_id.master_spa = zsb->z_os->os_master_spa;
		zp->z_group_id.master_objset = zsb->z_os->os_master_os;
		zp->z_group_id.master_object = zsb->z_os->os_master_root;
	}
	mutex_exit(&zp->z_lock);
	np->parent_object = zp->z_group_id;
	if (ptr != NULL) {
		bcopy(ptr, (char *)&np->arg, argsize);
	}
	np->flags = flags;
	zfs_group_set_cred(credp, &np->cred);

	switch (op) {
	case NAME_CREATE:
	case NAME_REMOVE:
	case NAME_LINK:
	case NAME_MKDIR:
	case NAME_RMDIR:
	case NAME_LOOKUP:
	case NAME_REMOVE_DATA:
		VERIFY(offsetof(zfs_group_name_t, component) + cplen + 1 <=
		    ZFS_GROUP_MAX_NAME_LEN);
		bcopy(cp, np->component, cplen);
		param_len = offsetof(zfs_group_name_t, component) + cplen + 1;
		param_len = (param_len + NBPW) & ~(NBPW-1);
		VERIFY(param_len <= ZFS_GROUP_MAX_NAME_LEN);
		reply_length = sizeof(zfs_group_name2_t);
		np->arg.dirlowdata = zp->z_dirlowdata;
		np->arg.dirquota = zp->z_dirquota;
		np->arg.bquota = zp->z_bquota;
		break;

	case NAME_RENAME:
	case NAME_SYMLINK:
		VERIFY(cplen + 1 <= MAXNAMELEN);
		VERIFY(offsetof(zfs_group_name_t, component) + MAXNAMELEN +
		    strlen(ncp) + 1 <= ZFS_GROUP_MAX_NAME_LEN);
		strncpy((char *)&np->component, cp, cplen);
		strcpy((char *)&np->component[MAXNAMELEN], ncp);
		param_len = offsetof(zfs_group_name_t, component) +
		    MAXNAMELEN + strlen(ncp) + 1;
		param_len = (param_len + NBPW) & ~(NBPW-1);
		VERIFY(param_len <= ZFS_GROUP_MAX_NAME_LEN);
		reply_length = sizeof(zfs_group_name2_t) ;
		break;

	case NAME_ACL:{
		bcopy(cp, np->component, cplen);
		param_len = cplen + offsetof(zfs_group_name_t, component);
		reply_length = MAX_ACL_ENTRIES * sizeof (aclent_t)
		    + offsetof(zfs_group_name2_t, component);
	}
	break;

	default:
		error = EPROTO;
		goto out;
	}

	if (op != NAME_REMOVE_DATA) {
		dst_spa = zp->z_group_id.master_spa;
		dst_os = zp->z_group_id.master_objset;
		dst_object = zp->z_group_id.master_object;
		msg_orig = APP_USER;
	} else {
		dst_spa = zp->z_group_id.data_spa;
		dst_os = zp->z_group_id.data_objset;
		dst_object = zp->z_group_id.data_object;
		msg_orig = APP_GROUP;
	}
	request_length = param_len;

	zfs_group_build_header(ZTOZSB(zp)->z_os, msg_header, ZFS_GROUP_CMD_NAME,
	    SHARE_WAIT, op,
	    request_length, reply_length, dst_spa, dst_os, dst_object,
	    zp->z_group_id.master_object,
	    zp->z_group_id.data_spa,
	    zp->z_group_id.data_objset,
	    zp->z_group_id.data_object,
	    MSG_REQUEST, msg_orig);

	error = zfs_client_send_to_server(zsb->z_os, msg_header, (zfs_msg_t *)name_msg, B_TRUE);

	if (error == 0 && nrec != NULL) {
		zfs_group_name2_t *n2p;
		n2p = (zfs_group_name2_t *)np;
		if (op == NAME_ACL) {
			zfs_group_name_acl_t *zg_acl = 
			    (zfs_group_name_acl_t *)n2p->component;
			zfs_group_to_acl(zg_acl, (vsecattr_t *)nrec);
		} else {
			bcopy(&n2p->nrec, nrec, sizeof(zfs_group_znode_record_t));
		}
	}

out:
	kmem_free(msg_header, sizeof(zfs_group_header_t));
	kmem_free(name_msg, sizeof (zfs_group_name_msg_t));
	return (error);
}

static int zfs_group_proc_name_backup(
    znode_t *zp, name_operation_t op,	
    void *ptr, int argsize, char *cp, uint64_t cplen,
    char *ncp, int32_t flags, cred_t *credp, void *nrec, 
    zfs_group_object_t* z_group_id, zfs_multiclus_node_type_t m_node_type)
{
	uint64_t request_length;
	uint64_t reply_length;
	zfs_sb_t *zsb;
//	zfs_msg_t *zfs_msg;
	zfs_group_name_msg_t *name_msg;
	zfs_group_header_t *msg_header;
	zfs_group_name_t *np;
	uint64_t dst_spa;
	uint64_t dst_os;
	uint64_t dst_object = 0;
	msg_orig_type_t msg_orig;
	int param_len = 0;
	int error = 0;
//	int r;
	zfs_multiclus_group_record_t *record = NULL;
	znode_t new_znode = { 0 };
	
	char master_fsname[MAX_FSNAME_LEN+1] = {0};
	char master2_fsname[MAX_FSNAME_LEN+1] = {0};
	char *p = NULL;
	int lendiff = 0;
	uint64_t update_node_info = 0;
	
	zsb = ZTOZSB(zp);

	record = zfs_multiclus_get_group_master(zsb->z_os->os_group_name, m_node_type);
	if(record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
		return EPROTO;
	}
		
	if(ncp && strlen(ncp) > MAXNAMELEN){
		cmn_err(CE_WARN, "[Error] Target Name length is longer than %d.", MAXNAMELEN);
		return EPROTO;
	}

	dmu_objset_name(zsb->z_os, master_fsname);
	strcpy(master2_fsname, (char*)&record->fsname[0]);
	
	name_msg = kmem_zalloc(sizeof(zfs_group_name_msg_t), KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	np = &name_msg->call.name;

	np->parent_object = zp->z_group_id;
	if (ptr != NULL) {
		bcopy(ptr, (char *)&np->arg, argsize);
	}
	np->flags = flags;
	zfs_group_set_cred(credp, &np->cred);

	switch (op) {
	case NAME_CREATE:
	case NAME_REMOVE:
	case NAME_LINK:
	case NAME_MKDIR:
	case NAME_RMDIR:
		VERIFY(offsetof(zfs_group_name_t, component) + cplen + 1 <=
		    ZFS_GROUP_MAX_NAME_LEN);
		/* Replace the first master_fsname in cp with master2_fsname. */
		p = strstr(cp, master_fsname);
		if(p != NULL)lendiff = p - cp;
		
		if(p != NULL){
			strncpy((char *)&np->component, cp, lendiff);
			strcpy((char *)&np->component[lendiff], master2_fsname);
			strncpy((char *)&np->component[strlen(master2_fsname) + lendiff], 
			p + strlen(master_fsname), cplen - strlen(master_fsname) - lendiff);
			cplen = cplen + strlen(master2_fsname) - strlen(master_fsname);
		}else{
			bcopy(cp, np->component, cplen);
		}

		param_len = offsetof(zfs_group_name_t, component) + cplen + 1;
		param_len = (param_len + NBPW) & ~(NBPW-1);
		VERIFY(param_len <= ZFS_GROUP_MAX_NAME_LEN);
		reply_length = sizeof(zfs_group_name2_t);
		np->arg.dirlowdata = zp->z_dirlowdata;
		np->arg.dirquota = zp->z_dirquota;
		break;

	case NAME_RENAME:
	case NAME_SYMLINK:
		VERIFY(cplen + 1 <= MAXNAMELEN);
		VERIFY(offsetof(zfs_group_name_t, component) + MAXNAMELEN +
		    strlen(ncp) + 1 <= ZFS_GROUP_MAX_NAME_LEN);
		/* Replace the first master_fsname in cp with master2_fsname. */
		p = strstr(cp, master_fsname);
		if(p != NULL)lendiff = p - cp;
		if(p != NULL){
			strncpy((char *)&np->component, cp, lendiff);
			strcpy((char *)&np->component[lendiff], master2_fsname);
			strncpy((char *)&np->component[strlen(master2_fsname) + lendiff], 
			p + strlen(master_fsname), cplen - strlen(master_fsname) - lendiff);
		}else{
			bcopy(cp, np->component, cplen);
		}

		p = strstr(ncp, master_fsname);
		if(p != NULL)lendiff = p -ncp;
		if(p != NULL){
			strncpy((char *)&np->component[MAXNAMELEN], ncp, lendiff);
			strcpy((char *)&np->component[MAXNAMELEN + lendiff], master2_fsname);
			strncpy((char *)&np->component[MAXNAMELEN + strlen(master2_fsname) + lendiff], 
			p + strlen(master_fsname), strlen(ncp) - strlen(master_fsname) - lendiff);
			lendiff = strlen(master2_fsname) - strlen(master_fsname);
		}else{
			strcpy((char *)&np->component[MAXNAMELEN], ncp);
			lendiff = 0;
		}

		param_len = offsetof(zfs_group_name_t, component) +
		    MAXNAMELEN + strlen(ncp) + 1 + lendiff;
		param_len = (param_len + NBPW) & ~(NBPW-1);
		VERIFY(param_len <= ZFS_GROUP_MAX_NAME_LEN);
		reply_length = sizeof(zfs_group_name2_t) ;
		break;

	case NAME_ACL:{
		/* Replace the first master_fsname in cp with master2_fsname. */
		p = strstr(cp, master_fsname);
		if(p != NULL)lendiff = p - cp;
		if(p){
			bcopy(cp, np->component, lendiff);
			bcopy(master2_fsname, &np->component[lendiff], strlen(master2_fsname));
			bcopy(&np->component[strlen(master2_fsname) + lendiff], 
				p + strlen(master_fsname), cplen - strlen(master_fsname) - lendiff);
			cplen = cplen + strlen(master2_fsname) - strlen(master_fsname);
		}else{
			bcopy(cp, np->component, cplen);
		}

		param_len = cplen + offsetof(zfs_group_name_t, component);
		reply_length = MAX_ACL_ENTRIES * sizeof (aclent_t)
		    + offsetof(zfs_group_name2_t, component);
	}
	break;

	default:
		cmn_err(CE_WARN, "[Error] %s %d.", __func__, __LINE__);
		error = EPROTO;
		goto out;
	}

	dst_spa = record->spa_id;
	dst_os = record->os_id;

	switch(m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			update_node_info = ZFS_UPDATE_FILE_NODE_MASTER2;
			dst_object = zp->z_group_id.master2_object;
			if(dst_object != -1 && dst_object != 0){
				dst_spa = zp->z_group_id.master2_spa;
				dst_os = zp->z_group_id.master2_objset;
			}
			break;
		case ZFS_MULTICLUS_MASTER3:
			update_node_info = ZFS_UPDATE_FILE_NODE_MASTER3;
			dst_object = zp->z_group_id.master3_object;
			if(dst_object != -1 && dst_object != 0){
				dst_spa = zp->z_group_id.master3_spa;
				dst_os = zp->z_group_id.master3_objset;
			}
			break;
		case ZFS_MULTICLUS_MASTER4:
			update_node_info = ZFS_UPDATE_FILE_NODE_MASTER4;
			dst_object = zp->z_group_id.master4_object;
			if(dst_object != -1 && dst_object != 0){
				dst_spa = zp->z_group_id.master4_spa;
				dst_os = zp->z_group_id.master4_objset;
			}
			break;
		default:
			cmn_err(CE_WARN, "[Error] %s %d.", __func__, __LINE__);
			error = EPROTO;
			goto out;
	}

	if(zp->z_id == zsb->z_root && dst_object == -1){
		if(1 == debug_nas_group_dtl){
			cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
		}
		dst_object = 0;
	}

	if(dst_object == -1){
		if(strstr(zp->z_filename, SMB_STREAM_PREFIX) != NULL){
			/* If this is a smb system hidden file, just return success to make it
			 *  removed from Nas Group DTL.
			 */
			error = 0;
			goto out;
		}else{
//			new_znode = *zp;
			bcopy(zp, &new_znode, sizeof(znode_t));
			mutex_init(&new_znode.z_lock, NULL, MUTEX_DEFAULT, NULL);
			if(zfs_group_proc_znode(&new_znode, ZNODE_SEARCH, &m_node_type, credp, B_FALSE) == 0){
				mutex_destroy(&new_znode.z_lock);
				switch(m_node_type){
					case ZFS_MULTICLUS_MASTER2:
						if(zp->z_group_id.master_spa == new_znode.z_group_id.master2_spa 
							&& zp->z_group_id.master_objset == new_znode.z_group_id.master2_objset
							&& zp->z_group_id.master_object == new_znode.z_group_id.master2_object){
							zp->z_group_id.master2_spa = dst_spa = new_znode.z_group_id.master_spa;
							zp->z_group_id.master2_objset = dst_os = new_znode.z_group_id.master_objset;
							zp->z_group_id.master2_object = dst_object = new_znode.z_group_id.master_object;
							zp->z_group_id.master2_gen = new_znode.z_group_id.master_gen;
						}else{
							if(1 == debug_nas_group_dtl){
								cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
							}
							error = EINVAL;
							goto out;
						}
						break;
					case ZFS_MULTICLUS_MASTER3:
						if(zp->z_group_id.master_spa == new_znode.z_group_id.master3_spa 
							&& zp->z_group_id.master_objset == new_znode.z_group_id.master3_objset
							&& zp->z_group_id.master_object == new_znode.z_group_id.master3_object){
							zp->z_group_id.master3_spa = dst_spa = new_znode.z_group_id.master_spa;
							zp->z_group_id.master3_objset = dst_os = new_znode.z_group_id.master_objset;
							zp->z_group_id.master3_object = dst_object = new_znode.z_group_id.master_object;
							zp->z_group_id.master3_gen = new_znode.z_group_id.master_gen;
						}else{
							if(1 == debug_nas_group_dtl){
								cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
							}
							error = EINVAL;
							goto out;
						}
						break;
					case ZFS_MULTICLUS_MASTER4:
						if(zp->z_group_id.master_spa == new_znode.z_group_id.master4_spa 
							&& zp->z_group_id.master_objset == new_znode.z_group_id.master4_objset
							&& zp->z_group_id.master_object == new_znode.z_group_id.master4_object){
							zp->z_group_id.master4_spa = dst_spa = new_znode.z_group_id.master_spa;
							zp->z_group_id.master4_objset = dst_os = new_znode.z_group_id.master_objset;
							zp->z_group_id.master4_object = dst_object = new_znode.z_group_id.master_object;
							zp->z_group_id.master4_gen = new_znode.z_group_id.master_gen;
						}else{
							if(1 == debug_nas_group_dtl){
								cmn_err(CE_WARN, "[yzy] %s %d", __func__, __LINE__);
							}
							error = EINVAL;
							goto out;
						}
						break;
					default:
						error = EINVAL;
						goto out;
				}

				if(op == NAME_CREATE || op == NAME_MKDIR || op == NAME_SYMLINK){
					if (update_master_obj_by_mx_group_id(zp, m_node_type) != 0) {
						cmn_err(CE_WARN, "[Error] %s, update_master_obj_by_mx_group_id failed! m_node_type: %d", 
							__func__, m_node_type);
					}

				
					/* send masterX info to data node and other Master node */
					if (zfs_client_notify_file_info(zp, m_node_type, update_node_info) != 0){
						cmn_err(CE_WARN, "Failed to update master file node info, file is %s, m_node_type = %d",
							zp->z_filename, m_node_type);
					}
				}
				
			}else{
				mutex_destroy(&new_znode.z_lock);
				if(op != NAME_REMOVE && op != NAME_RMDIR){
					if(1 == debug_nas_group_dtl){
						cmn_err(CE_WARN, "[Error] %s %d. file name %s, op %d", 
							__func__, __LINE__, zp->z_filename, op);
					}
					error = EPROTO;
				}else{
					error = 0;
				}
				goto out;
			}
		}
		
	}

	record = zfs_multiclus_get_record(dst_spa, dst_os);
	if(record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
		if(1 == debug_nas_group_dtl){
			cmn_err(CE_WARN, "[Error] %s %d.", __func__, __LINE__);
		}
		error = EINVAL;
		goto out;
	}
	
	msg_orig = APP_USER;
	
	request_length = param_len;

	zfs_group_build_header_backup(ZTOZSB(zp)->z_os, msg_header, ZFS_GROUP_CMD_NAME_BACKUP,
	    SHARE_WAIT, op,
	    request_length, reply_length, dst_spa, dst_os, dst_object,
	    dst_object,
	    z_group_id->data_spa,
	    z_group_id->data_objset,
	    z_group_id->data_object,
	    MSG_REQUEST, msg_orig, z_group_id, m_node_type);

	error = zfs_client_send_to_server(zsb->z_os, msg_header, (zfs_msg_t *)name_msg, B_FALSE);

	if (error == 0 && nrec != NULL) {
		zfs_group_name2_t *n2p;
		n2p = (zfs_group_name2_t *)np;
		if (op == NAME_ACL) {
			zfs_group_name_acl_t *zg_acl = 
			    (zfs_group_name_acl_t *)n2p->component;
			zfs_group_to_acl(zg_acl, (vsecattr_t *)nrec);
		} else {
			bcopy(&n2p->nrec, nrec, sizeof(zfs_group_znode_record_t));
		}
	}

out:
	kmem_free(msg_header, sizeof(zfs_group_header_t));
	kmem_free(name_msg, sizeof (zfs_group_name_msg_t));
	return (error);
}


int					/* ERRNO if error, 0 if successful. */
zfs_proc_data(zfs_sb_t *zsb, znode_t *zp,
    data_operation_t op, share_flag_t wait_flag,
    void *ptr, uint64_t io_flags, data_direction_t direction)
{
	uint64_t server_spa;
	uint64_t server_os;
	zfs_group_data_msg_t *data_msg = NULL;
	zfs_group_header_t *msg_heade = NULL;
	uint64_t msg_len = 0;
	zfs_group_data_t *data = NULL;
	int request_length = 0;
	int reply_lenth = 0;
	int error;
	uio_t *uiop;


	switch (op) {
	case DIR_READ:
	case XATTR_LIST:
	case LINK_READ:
	case DATA_READ: {
			zfs_group_data_read_t *read;
			msg_len = sizeof (zfs_group_data_msg_t);
			data_msg = vmem_zalloc(msg_len, KM_SLEEP);
			msg_heade = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
			data = &data_msg->call.data;
			data->io_flags = io_flags;
			read = (zfs_group_data_read_t *)ptr;
			data->arg.p.read = *read;
			request_length = sizeof(zfs_group_data_msg_t);
			reply_lenth = data->arg.p.read.len + sizeof(zfs_group_data_msg_t) - 8;
	}
	break;

	case DATA_WRITE: {
			void *addr;
			size_t cbytes;
			size_t write_len;
			zfs_group_data_write_t *write;
			write = (zfs_group_data_write_t *)ptr;
			uiop = (uio_t *)(uintptr_t)write->addr;
			write_len = (write->len + (8 -1)) & (~(8 -1));
			msg_len = sizeof(zfs_group_data_msg_t) + write_len - 8;
			data_msg = vmem_zalloc(msg_len, KM_SLEEP);
			msg_heade = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
			data = &data_msg->call.data;
			addr = &data_msg->call.data.data;
			data->io_flags = io_flags;
			uiocopy(addr, write->len, UIO_WRITE, uiop, &cbytes);
			data_msg->call.data.arg.p.write = *write;
			request_length = msg_len;
			reply_lenth = sizeof(zfs_group_data_msg_t);
			data->arg.dirlowdata = zp->z_dirlowdata;
			data->arg.dirquota = zp->z_dirquota;
	}
	break;

	default:
	break;
	}
	
	if (zp->z_id == ZTOZSB(zp)->z_root) {
		zp->z_group_id.master_spa = ZTOZSB(zp)->z_os->os_master_spa;
		zp->z_group_id.master_objset = ZTOZSB(zp)->z_os->os_master_os;
		zp->z_group_id.master_object = ZTOZSB(zp)->z_os->os_master_root;
	}

	data->id = zp->z_group_id;
	if (direction == DATA_TO_MASTER) {
		server_spa = zp->z_group_id.master_spa;
		server_os = zp->z_group_id.master_objset;
	} else {
		server_spa = zp->z_group_id.data_spa;
		server_os = zp->z_group_id.data_objset;
	}
	
	zfs_group_build_header(zsb->z_os, msg_heade, ZFS_GROUP_CMD_DATA, wait_flag, op,
	    request_length, reply_lenth, server_spa, server_os, zp->z_group_id.master_object,
	    zp->z_group_id.master_object,
	    zp->z_group_id.data_spa,
	    zp->z_group_id.data_objset,
	    zp->z_group_id.data_object,
	    MSG_REQUEST, APP_USER);
			
	if (zfs_server_is_online(server_spa, server_os)) {
		error = zfs_client_send_to_server(zsb->z_os, msg_heade, (zfs_msg_t *)data_msg, B_TRUE);
	} else {
		error = EOFFLINE;
	}
	
	if (data_msg != NULL) {
		vmem_free(data_msg, msg_len);
	}
	if (msg_heade) {
		kmem_free(msg_heade, sizeof(zfs_group_header_t));
	}
	return (error);
}

int					/* ERRNO if error, 0 if successful. */
zfs_proc_data2(zfs_sb_t *zsb, znode_t *zp,
    data_operation_t op, share_flag_t wait_flag,
    void *ptr, uint64_t io_flags, data_direction_t direction)
{
	uint64_t server_spa;
	uint64_t server_os;
	zfs_group_data_msg_t *data_msg = NULL;
	zfs_group_header_t *msg_header = NULL;
	uint64_t msg_len = 0;
	zfs_group_data_t *data = NULL;
	int request_length = 0;
	int reply_lenth = 0;
	int error;
	uio_t *uiop;


	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	switch (op) {
	case DIR_READ:
	case LINK_READ:
	case DATA_READ: {
			zfs_group_data_read_t *read;
			msg_len = sizeof (zfs_group_data_msg_t);
			data_msg = vmem_zalloc(msg_len, KM_SLEEP);
			data = &data_msg->call.data;
			data->io_flags = io_flags;
			read = (zfs_group_data_read_t *)ptr;
			data->arg.p.read = *read;
			request_length = sizeof(zfs_group_data_msg_t);
			reply_lenth = data->arg.p.read.len + sizeof(zfs_group_data_msg_t) - 8;
	}
	break;

	case DATA_WRITE: {
			void *addr;
			size_t cbytes;
			size_t write_len;
			zfs_group_data_write_t *write;
			write = (zfs_group_data_write_t *)ptr;
			uiop = (uio_t *)(uintptr_t)write->addr;
			write_len = (write->len + (8 -1)) & (~(8 -1));
			msg_len = sizeof(zfs_group_data_msg_t) + write_len - 8;
			data_msg = vmem_zalloc(msg_len, KM_SLEEP);
			data = &data_msg->call.data;
			addr = &data_msg->call.data.data;
			data->io_flags = io_flags;
			uiocopy(addr, write->len, UIO_WRITE, uiop, &cbytes);
			data_msg->call.data.arg.p.write = *write;
			request_length = msg_len;
			reply_lenth = sizeof(zfs_group_data_msg_t);
			data->arg.dirlowdata = zp->z_dirlowdata;
			data->arg.dirquota = zp->z_dirquota;
	}
	break;

	default:
	break;
	}

	if (zp->z_id == ZTOZSB(zp)->z_root) {
		zp->z_group_id.master_spa = ZTOZSB(zp)->z_os->os_master_spa;
		zp->z_group_id.master_objset = ZTOZSB(zp)->z_os->os_master_os;
		zp->z_group_id.master_object = ZTOZSB(zp)->z_os->os_master_root;
	}

	data->id = zp->z_group_id;
	if (direction == DATA_TO_MASTER) {
		server_spa = zp->z_group_id.master_spa;
		server_os = zp->z_group_id.master_objset;
	} else {
		server_spa = zp->z_group_id.data2_spa;
		server_os = zp->z_group_id.data2_objset;

		/*
		 * in zfs_group_process_data_request, it will extract
		 * the actual/target znode by id.data_object.
		 *
		 * we're writing data2 file here, so adjust id.data_object
		 * to id.data2_object; otherwise, the client would fail to
		 * extract the actual/target znode.
		 */
		data->id.data_object = data->id.data2_object;
	}
	
	zfs_group_build_header(zsb->z_os, msg_header, ZFS_GROUP_CMD_DATA, wait_flag, op,
	    request_length, reply_lenth, server_spa, server_os, zp->z_group_id.master_object,
	    zp->z_group_id.master_object,
	    zp->z_group_id.data2_spa,
	    zp->z_group_id.data2_objset,
	    zp->z_group_id.data2_object,
	    MSG_REQUEST, APP_USER);

	if (zfs_server_is_online(server_spa, server_os)) {
		error = zfs_client_send_to_server(zsb->z_os, msg_header, (zfs_msg_t *)data_msg, B_TRUE);
	} else {
		error = EOFFLINE;
	}

	if (data_msg != NULL) {
		vmem_free(data_msg, msg_len);
	}
	if (msg_header != NULL) {
		kmem_free(msg_header, sizeof(zfs_group_header_t));
	}
	return (error);
}


int					/* ERRNO if error, 0 if successful. */
zfs_proc_cmd(zfs_sb_t *zsb, ushort_t op, share_flag_t wait_flag,
    zfs_group_cmd_arg_t *cmd_arg, uint64_t dst_spa, uint64_t dst_os, uint64_t dst_object,
    msg_orig_type_t msg_orig)
{
	int	error = 0;
	uint64_t	msg_len = 0;
	uint64_t	return_len = 0;
	zfs_group_cmd_msg_t	*cmd_msg = 0;
	zfs_group_header_t	*msg_header = NULL;

	msg_len = sizeof(zfs_group_cmd_msg_t) + cmd_arg->arg_size;
	return_len = cmd_arg->return_size + sizeof(zfs_group_cmd_msg_t);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	cmd_msg = kmem_zalloc(msg_len, KM_SLEEP);
	
	if (cmd_arg->arg_size > 0) {
		bcopy((void *)(uintptr_t)cmd_arg->arg_ptr, cmd_msg->call.cmd.cmd, cmd_arg->arg_size);
	}
	cmd_msg->call.cmd.arg = *cmd_arg;

	zfs_group_build_header(zsb->z_os, msg_header, ZFS_GROUP_CMD_CMD, 
	    wait_flag, op, msg_len, return_len, dst_spa, dst_os, dst_object, 0, 0, 0, 0, 
	    MSG_REQUEST, msg_orig);
	error = zfs_client_send_to_server(zsb->z_os, msg_header, (zfs_msg_t *)cmd_msg, B_TRUE);

	if (cmd_msg != NULL)
		kmem_free(cmd_msg, msg_len);
	if (msg_header != NULL)
		kmem_free(msg_header, sizeof(zfs_group_header_t));
	return (error);
}

int					/* ERRNO if error, 0 if successful. */
zfs_proc_cmd_backup(znode_t *zp, ushort_t op, share_flag_t wait_flag,
    zfs_group_cmd_arg_t *cmd_arg, 
    msg_orig_type_t msg_orig, zfs_multiclus_node_type_t m_node_type)
{
	int error = 0;
	uint64_t msg_len = 0;
	uint64_t return_len = 0;
	zfs_group_cmd_msg_t *cmd_msg = NULL;
	zfs_group_header_t *msg_header = NULL;
	uint64_t dst_spa = 0;
	uint64_t dst_os = 0;
	uint64_t dst_object = 0;
	zfs_multiclus_group_record_t *record = NULL;
	
	record = zfs_multiclus_get_group_master(ZTOZSB(zp)->z_os->os_group_name, m_node_type);
	if(record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
		return EPROTO;
	}

	dst_spa = record->spa_id;
	dst_os = record->os_id;

	switch (m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			dst_object = zp->z_group_id.master2_object;
			if(dst_object != -1 && dst_object != 0)
			{
				dst_spa = zp->z_group_id.master2_spa;
				dst_os = zp->z_group_id.master2_objset;
			}
			break;

		case ZFS_MULTICLUS_MASTER3:
			dst_object = zp->z_group_id.master3_object;
			if(dst_object != -1 && dst_object != 0)
			{
				dst_spa = zp->z_group_id.master3_spa;
				dst_os = zp->z_group_id.master3_objset;
			}
			break;

		case ZFS_MULTICLUS_MASTER4:
			dst_object = zp->z_group_id.master4_object;
			if(dst_object != -1 && dst_object != 0)
			{
				dst_spa = zp->z_group_id.master4_spa;
				dst_os = zp->z_group_id.master4_objset;
			}
			break;

		default:
			cmn_err(CE_WARN, "%s, invalid node type, node_type = %d",
				__func__, m_node_type);
			return (EPROTO);
	}
	
	if(dst_object == -1 || dst_object == 0){
		cmn_err(CE_WARN, "%s dst_object is %llu", __func__, (u_longlong_t)dst_object);
		return (ENOENT);
	}

	msg_len = sizeof(zfs_group_cmd_msg_t) + cmd_arg->arg_size;
	return_len = cmd_arg->return_size + sizeof(zfs_group_cmd_msg_t);

	cmd_msg = kmem_zalloc(msg_len, KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	if (cmd_arg->arg_size > 0) {
		bcopy((void *)(uintptr_t)cmd_arg->arg_ptr, cmd_msg->call.cmd.cmd, cmd_arg->arg_size);
	}
	cmd_msg->call.cmd.arg = *cmd_arg;

	zfs_group_build_header(ZTOZSB(zp)->z_os, msg_header, ZFS_GROUP_CMD_CMD, 
	    wait_flag, op, msg_len, return_len, dst_spa, dst_os, dst_object, 0, 0, 0, 0, 
	    MSG_REQUEST, msg_orig);
	error = zfs_client_send_to_server(ZTOZSB(zp)->z_os, msg_header, (zfs_msg_t *)cmd_msg, B_FALSE);

	if (cmd_msg != NULL)
		kmem_free(cmd_msg, msg_len);
	if (msg_header != NULL)
		kmem_free(msg_header, sizeof(zfs_group_header_t));

	return (error);
}


int zfs_client_read_data(zfs_sb_t *zsb, znode_t *zp, uio_t *uiop,
    uint64_t bytes, data_operation_t op, cred_t *credp, uint64_t ioflag,
    data_direction_t direction, int *beof)
{
	int error;
	uint64_t off;
	uint64_t len;
//	size_t cbytes;
	zfs_group_data_read_t *read;
	off = uiop->uio_loffset;
	len = bytes;

	read = kmem_zalloc(sizeof(zfs_group_data_read_t), KM_SLEEP);
	read->data_ptr = (uint64_t)(uintptr_t)(uiop);
	if (beof != NULL) {
		read->eof_ptr = (uint64_t)(uintptr_t)beof;
	}
	read->offset = off;
	read->len = bytes;

	zfs_group_set_cred(credp, &read->cred);
	error = zfs_proc_data(zsb, zp,
	    op, SHARE_WAIT, (void *)read, ioflag, direction);
	kmem_free(read, sizeof(zfs_group_data_read_t));
	return (error);
}

int zfs_client_read_data2(zfs_sb_t *zsb, znode_t *zp, uio_t *uiop, 
    uint64_t bytes, data_operation_t op, cred_t *credp, uint64_t ioflag,
    data_direction_t direction, int *beof)
{
	int error;
	uint64_t off;
	uint64_t len;
//	size_t cbytes;
	zfs_group_data_read_t *read;
	off = uiop->uio_loffset;
	len = bytes ;

	read = kmem_zalloc(sizeof(zfs_group_data_read_t), KM_SLEEP);
	read->data_ptr = (uint64_t)(uintptr_t)(uiop);
	if (beof != NULL) {
		read->eof_ptr = (uint64_t)(uintptr_t)beof;
	}
	read->offset = off;
	read->len = bytes;

	zfs_group_set_cred(credp, &read->cred);
	error = zfs_proc_data2(zsb, zp,
	    op, SHARE_WAIT, (void *)read, ioflag, direction);
	kmem_free(read, sizeof(zfs_group_data_read_t));
	return (error);
}


void zfs_client_get_read_data(zfs_msg_t *omsg, zfs_group_header_t *nmsg_header, zfs_msg_t *nmsg)
{
	uio_t *uiop;
	int *eofp;
	zfs_group_data_read_t *read = NULL;
	zfs_group_data_read_t *nread = NULL; 
	zfs_group_data_msg_t *data_msg = NULL;
	zfs_group_data_msg_t *ndata_msg = NULL;
	data_msg = (zfs_group_data_msg_t *)omsg;
	ndata_msg = (zfs_group_data_msg_t *)nmsg;
	read = &data_msg->call.data.arg.p.read;
	nread = &nmsg->call.data.arg.p.read;
	uiop = (uio_t *)(uintptr_t)read->data_ptr;
	if (read->eof_ptr != 0) {
		eofp = (int *)(uintptr_t)read->eof_ptr;
		*eofp = nmsg->call.data.arg.p.read.eof;
	}

	if (nmsg_header->error == 0) {
		if( nmsg_header->operation != XATTR_LIST || uiop->uio_iov->iov_base != NULL ) {
			uiomove(nmsg->call.data.data, (size_t)nread->len, UIO_READ, uiop);
		}
		if (nmsg_header->operation == DIR_READ ) {
			uiop->uio_loffset = nread->offset;
		}
		if( nmsg_header->operation == XATTR_LIST ) {
			uiop->uio_loffset = nread->len ;
		}
	}
}

static void zfs_client_process_data(zfs_msg_t *omsg, 
	zfs_group_header_t *nmsg_header, zfs_msg_t *nmsg)
{
	if (nmsg_header->operation == DATA_READ || nmsg_header->operation == DIR_READ
	    || nmsg_header->operation == LINK_READ || nmsg_header->operation == XATTR_LIST ) {
		zfs_client_get_read_data(omsg, nmsg_header, nmsg);
	}
}

static void zfs_client_process_cmd(zfs_msg_t *omsg, zfs_msg_t *nmsg)
{
	void *arg_return;
	uint64_t arg_return_size;
	zfs_group_cmd_msg_t *old_cmd_msg = (zfs_group_cmd_msg_t *)omsg;
	zfs_group_cmd_msg_t *new_cmd_msg = (zfs_group_cmd_msg_t *)nmsg;

	arg_return_size = new_cmd_msg->call.cmd.arg.return_size;
	if (arg_return_size > 0) {
		arg_return = (void *)(uintptr_t)omsg->call.cmd.arg.return_ptr;
		bcopy(new_cmd_msg->call.cmd.cmd, arg_return, arg_return_size);
		old_cmd_msg->call.cmd.arg.return_size = arg_return_size;
	}

}

static void zfs_client_process_stat(zfs_msg_t *omsg, zfs_msg_t *nmsg)
{
	void *arg_return;
	uint64_t arg_return_size;
	zfs_group_stat_msg_t *old_stat_msg = (zfs_group_stat_msg_t *)omsg;
	zfs_group_stat_msg_t *new_stat_msg = (zfs_group_stat_msg_t *)nmsg;

	arg_return_size = new_stat_msg->call.stat.arg.return_size;
	if (arg_return_size > 0) {
		arg_return = (void *)(uintptr_t)omsg->call.stat.arg.return_ptr;
		bcopy(new_stat_msg->call.stat.stat, arg_return, arg_return_size);
		old_stat_msg->call.stat.arg.return_size = arg_return_size;
	}
}

static void zfs_client_process_scrub(zfs_msg_t *omsg, zfs_msg_t *nmsg)
{
	void *arg_return;
	uint64_t arg_return_size;
	zfs_group_stat_msg_t *old_stat_msg = (zfs_group_stat_msg_t *)omsg;
	zfs_group_stat_msg_t *new_stat_msg = (zfs_group_stat_msg_t *)nmsg;

	arg_return_size = new_stat_msg->call.stat.arg.return_size;
	if (arg_return_size > 0) {
		arg_return = (void *)(uintptr_t)omsg->call.stat.arg.return_ptr;
		bcopy(new_stat_msg->call.stat.stat, arg_return, arg_return_size);
		old_stat_msg->call.stat.arg.return_size = arg_return_size;
	}
}

void zfs_client_rx(zfs_group_header_t *omsg_header, zfs_msg_t *omsg, 
	zfs_group_header_t *nmsg_header, zfs_msg_t *nmsg)
{
	if (((nmsg_header->error != 0 && nmsg_header->error != ENOSYS)
	    && !((nmsg_header->command == ZFS_GROUP_CMD_NAME || nmsg_header->command == ZFS_GROUP_CMD_NAME_BACKUP)
	    && nmsg_header->operation == NAME_LOOKUP && (nmsg_header->error == ENOENT
	    || nmsg_header->error == EACCES))
	    && !(nmsg_header->command == ZFS_GROUP_CMD_ZNODE
	    && (nmsg_header->operation == ZNODE_FREE || nmsg_header->operation == ZNODE_ACCESS) 
	    && (nmsg_header->error == ENOENT || nmsg_header->error == EACCES)))
	    || nmsg_header->client_spa == 0 ||
	    nmsg_header->client_os == 0 || (nmsg_header->client_object == 0 &&
	    nmsg_header->command != ZFS_GROUP_CMD_CMD)) {

		if((nmsg_header->command == ZFS_GROUP_CMD_ZNODE && nmsg_header->operation == ZNODE_SEARCH) ||
			(nmsg_header->command == ZFS_GROUP_CMD_NAME && nmsg_header->operation == NAME_REMOVE 
			&& nmsg_header->error == ENOENT) || 
			(nmsg_header->command == ZFS_GROUP_CMD_CMD && nmsg_header->operation == SC_FS_GET_DATA_ATTR
			&& nmsg_header->error == ENOENT) ||
			(nmsg_header->command == ZFS_GROUP_CMD_ZNODE && nmsg_header->operation == ZNODE_GET
			&& nmsg_header->error == ENOENT)){
			/* Do nothing, it it is  ZFS_GROUP_CMD_ZNODE with hdr.command == ZNODE_SEARCH. */
		}else{
			zfs_group_msg(nmsg_header, nmsg, B_FALSE, B_TRUE, B_FALSE);
		}
	}

	switch (nmsg_header->command) {
	case ZFS_GROUP_CMD_DATA:
		bcopy((void *)nmsg, (void *)omsg, sizeof(zfs_group_data_msg_t));
		zfs_client_process_data(omsg, nmsg_header, nmsg);
	break;

	case ZFS_GROUP_CMD_CMD:
	zfs_client_process_cmd(omsg, nmsg);
	bcopy((void *)nmsg, (void *)omsg, sizeof(zfs_group_cmd_msg_t));
	break;

	case ZFS_GROUP_CMD_DIRLD:
	case ZFS_GROUP_CMD_STAT:
		bcopy((void *)nmsg, (void *)omsg, sizeof(zfs_group_stat_msg_t));
		zfs_client_process_stat(omsg, nmsg);
	break;

	case ZFS_GROUP_CMD_SCRUB:
		bcopy((void *)nmsg, (void *)omsg, sizeof(zfs_group_stat_msg_t));
		zfs_client_process_scrub(omsg, nmsg);
	break;

	default:
		bcopy((void *)nmsg, (void *)omsg, nmsg_header->out_length);
	break;
	}
}


int zfs_client_write_data(zfs_sb_t *zsb, znode_t *zp, uio_t *uiop, 
    uint64_t nbytes, cred_t *credp, uint64_t ioflag)
{
	int error;
	uint64_t off;
	uint64_t len;
//	size_t cbytes;
//	uint64_t total_len;
	zfs_group_data_write_t *write;

	off = uiop->uio_loffset;
	len = nbytes ;

	write = kmem_alloc(sizeof(zfs_group_data_write_t), KM_SLEEP);
	write->addr = (uint64_t)(uintptr_t)uiop;
	write->offset = off;
	write->len = nbytes;
	write->dir_quota = zp->z_dirquota;
	zfs_group_set_cred(credp, &write->cred);

	error = zfs_proc_data(zsb, zp,
		DATA_WRITE, SHARE_WAIT, (void *)write, ioflag, DATA_TO_DATA);

	if (error == 0) {
		uioskip(uiop, nbytes);
	}

	kmem_free(write, sizeof(zfs_group_data_write_t));
	return (error);
}
int 
zfs_client_write_data2(zfs_sb_t *zsb, znode_t *zp, uio_t *uiop, 
    uint64_t nbytes, cred_t *credp, uint64_t ioflag)
{
	int error;
	uint64_t off;
	uint64_t len;
//	size_t cbytes;
//	uint64_t total_len;
	zfs_group_data_write_t *write;

	off = uiop->uio_loffset;
	len = nbytes ;

	write = vmem_alloc(sizeof(zfs_group_data_write_t), KM_SLEEP);
	write->addr = (uint64_t)(uintptr_t)uiop;
	write->offset = off;
	write->len = nbytes;
	write->dir_quota = zp->z_dirquota;
	zfs_group_set_cred(credp, &write->cred);
	
	error = zfs_proc_data2(zsb, zp,
	    DATA_WRITE, SHARE_WAIT, (void *)write, ioflag, DATA_TO_DATA);

	if (error == 0) {
		uioskip(uiop, nbytes);
	}

	vmem_free(write, sizeof(zfs_group_data_write_t));
	return (error);
}

int		
zfs_group_proc_znode(
	znode_t *zp, znode_operation_t op, void *ptr,	
	cred_t *credp, boolean_t watting)
{
	char msg[128];
	const char *znode_op = "";
	objset_t *os;
	zfs_group_znode_msg_t *znode_msg;
	zfs_group_header_t *msg_header = NULL;
	zfs_group_znode_t *znp;
	zfs_group_znode2_t *z2p;
	share_flag_t wait_flag;
	boolean_t force_sync;
	int error;
//	int r;
//	boolean_t grabbed_mutex = FALSE;
//	int unset_nb = 0;
	zfs_multiclus_node_type_t *m_node_type_p = NULL;
	zfs_multiclus_group_record_t *record = NULL;
	uint64_t dst_spa = 0, dst_os = 0; //, dst_obj = 0;

	znode_msg = kmem_zalloc(sizeof (zfs_group_znode_msg_t), KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	znp = &znode_msg->call.znode;
	zfs_group_set_cred(credp, &znp->cred);
	wait_flag = SHARE_WAIT;
	force_sync = TRUE;
	os = ZTOZSB(zp)->z_os;


	if (zp->z_id == ZTOZSB(zp)->z_root) {
		zp->z_group_id.master_spa = os->os_master_spa;
		zp->z_group_id.master_objset = os->os_master_os;
		zp->z_group_id.master_object = os->os_master_root;
	}
	znp->id = zp->z_group_id;
	switch (op) {
	case ZNODE_SETATTR: {
		zfs_group_znode_setattr_t *setattr;

		setattr = (zfs_group_znode_setattr_t *)ptr;
		znp->arg.p.setattr = *setattr;
		znode_op = "set attr";
	}
	break;

	case ZNODE_ACCESS: {
		zfs_group_znode_access_t *access;
		access = (zfs_group_znode_access_t *)ptr;
		znp->arg.p.access = *access;
		znode_op = "access";
	}
	break;
	case ZNODE_FREE: {
		zfs_group_znode_free_t *free;
		free = (zfs_group_znode_free_t *)ptr;
		znp->arg.p.free = *free;
		znode_op = "Free";
	}
	break;

	case ZNODE_GET:
		znode_op = "Get";
	break;

	case ZNODE_SEARCH:
		znode_op = "Search";

		m_node_type_p = (zfs_multiclus_node_type_t *)ptr;
		record = zfs_multiclus_get_group_master(ZTOZSB(zp)->z_os->os_group_name, *m_node_type_p);
		if(record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
			error = ENOENT;
			goto out;
		}
		dst_spa = record->spa_id;
		dst_os  = record->os_id;
		znp->id.master2_spa = zp->z_group_id.master_spa;
		znp->id.master2_objset = zp->z_group_id.master_objset;
		znp->id.master2_object = zp->z_group_id.master_object;
		if(1 == debug_nas_group_dtl){
			cmn_err(CE_WARN, "[yzy] %s %d spa 0x%llx, os 0x%llx, obj 0x%llx", __func__, __LINE__,
				(unsigned long long)znp->id.master2_spa,(unsigned long long)znp->id.master2_objset,
				(unsigned long long)znp->id.master2_object);
		}
		
	break;
	
	default:
		error = ENOTTY;
		goto out;
	}

	if(op == ZNODE_FREE){
		zfs_group_build_header(ZTOZSB(zp)->z_os, msg_header, ZFS_GROUP_CMD_ZNODE,
		    wait_flag, op, sizeof (zfs_group_znode_msg_t), sizeof (zfs_group_znode_msg_t),
		    znp->id.data_spa, znp->id.data_objset,
	    	znp->id.data_object,
	    	zp->z_group_id.master_object,
	    	zp->z_group_id.data_spa,
	    	zp->z_group_id.data_objset,
	    	zp->z_group_id.data_object,
	    	MSG_REQUEST, APP_USER);
	}else{
		zfs_group_build_header(ZTOZSB(zp)->z_os, msg_header, ZFS_GROUP_CMD_ZNODE,
		    wait_flag, op, sizeof (zfs_group_znode_msg_t), sizeof (zfs_group_znode_msg_t),
		    op == ZNODE_SEARCH ? dst_spa : znp->id.master_spa, op == ZNODE_SEARCH ? dst_os: znp->id.master_objset,
	    	zp->z_group_id.master_object,
	    	zp->z_group_id.master_object,
	    	zp->z_group_id.data_spa,
	    	zp->z_group_id.data_objset,
	    	zp->z_group_id.data_object,
	    	MSG_REQUEST, APP_USER);
	}
	
	if ((error = zfs_client_send_to_server(ZTOZSB(zp)->z_os, msg_header, (zfs_msg_t *)znode_msg, watting)) == 0) {
		z2p = (zfs_group_znode2_t *)znp;
		mutex_enter(&zp->z_lock);
		zfs_group_znode_reset_phys(zp, &z2p->zrec.object_phy);
		zp->z_group_id = z2p->inp.id;
             bcopy(z2p->relativepath, zp->z_filename, MAXNAMELEN);
		mutex_exit(&zp->z_lock);
		sprintf(msg, "%s %s", "Acquire znode", znode_op);
		zfs_group_acquire_znode_error(zp, &z2p->inp.id, &z2p->zrec.object_phy,
		    msg);

	} else {
		cmn_err(CE_WARN, "%s %d error=%d\n", __func__, __LINE__, error);
	}
out:
	kmem_free(msg_header, sizeof(zfs_group_header_t));
	kmem_free(znode_msg, sizeof(zfs_group_znode_msg_t));
	return (error);
}

int		
zfs_group_proc_znode_backup(
	znode_t *zp, znode_operation_t op, void *ptr,	
	cred_t *credp, zfs_multiclus_node_type_t m_node_type)
{
//	char msg[128];
	const char *znode_op;
	zfs_group_znode_msg_t *znode_msg = NULL;
	zfs_group_header_t *msg_header = NULL;
	zfs_group_znode_t *znp;
//	zfs_group_znode2_t *z2p;
	share_flag_t wait_flag;
	boolean_t force_sync;
	int error = 0;
//	int r;
//	boolean_t grabbed_mutex = FALSE;
//	int unset_nb = 0;
	zfs_multiclus_group_record_t *record = NULL;
	zfs_sb_t *zsb = NULL;
	uint64_t dst_spa = 0;
	uint64_t dst_os = 0;
	uint64_t dst_object = 0;
	znode_t new_znode = { 0 };
	uint64_t update_node_info = 0;

	zsb = ZTOZSB(zp);

	znode_msg = kmem_zalloc(sizeof (zfs_group_znode_msg_t), KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	znp = &znode_msg->call.znode;
	zfs_group_set_cred(credp, &znp->cred);
	wait_flag = SHARE_WAIT;
	force_sync = TRUE;

	znp->id = zp->z_group_id;
	switch (op) {
		case ZNODE_SETATTR: {
			zfs_group_znode_setattr_t *setattr;

			setattr = (zfs_group_znode_setattr_t *)ptr;
			znp->arg.p.setattr = *setattr;
			znode_op = "set attr";
		}
		break;
		
		default:
			error = ENOTTY;
			goto out;
	}

	switch(m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			update_node_info = ZFS_UPDATE_FILE_NODE_MASTER2;
			dst_spa = znp->id.master2_spa;
			dst_os = znp->id.master2_objset;
			dst_object = znp->id.master2_object;
			break;
		case ZFS_MULTICLUS_MASTER3:
			update_node_info = ZFS_UPDATE_FILE_NODE_MASTER3;
			dst_spa = znp->id.master3_spa;
			dst_os = znp->id.master3_objset;
			dst_object = znp->id.master3_object;
			break;
		case ZFS_MULTICLUS_MASTER4:
			update_node_info = ZFS_UPDATE_FILE_NODE_MASTER4;
			dst_spa = znp->id.master4_spa;
			dst_os = znp->id.master4_objset;
			dst_object = znp->id.master4_object;
			break;
		default:
			cmn_err(CE_WARN, "[Error] %s %d, m_node_type %d.", __func__, __LINE__, m_node_type);
			error = EPROTO;
			goto out;
	}

	if(dst_spa == -1 || dst_os == -1 || dst_object == -1 || 
		dst_spa == 0 || dst_os == 0 || dst_object == 0){
		
		if(NULL == strstr(zp->z_filename, SMB_STREAM_PREFIX)){
//			new_znode = *zp;
			bcopy(zp, &new_znode, sizeof(znode_t));
			mutex_init(&new_znode.z_lock, NULL, MUTEX_DEFAULT, NULL);
			if(zfs_group_proc_znode(&new_znode, ZNODE_SEARCH, &m_node_type, credp, B_FALSE) == 0){
				mutex_destroy(&new_znode.z_lock);
				switch(m_node_type){
					case ZFS_MULTICLUS_MASTER2:
						if(zp->z_group_id.master_spa == new_znode.z_group_id.master2_spa 
							&& zp->z_group_id.master_objset == new_znode.z_group_id.master2_objset
							&& zp->z_group_id.master_object == new_znode.z_group_id.master2_object){
							zp->z_group_id.master2_spa = dst_spa = new_znode.z_group_id.master_spa;
							zp->z_group_id.master2_objset = dst_os = new_znode.z_group_id.master_objset;
							zp->z_group_id.master2_object = dst_object = new_znode.z_group_id.master_object;
							zp->z_group_id.master2_gen = new_znode.z_group_id.master_gen;
						}else{
							error = EINVAL;
							goto out;
						}
						break;
					case ZFS_MULTICLUS_MASTER3:
						if(zp->z_group_id.master_spa == new_znode.z_group_id.master3_spa 
							&& zp->z_group_id.master_objset == new_znode.z_group_id.master3_objset
							&& zp->z_group_id.master_object == new_znode.z_group_id.master3_object){
							zp->z_group_id.master3_spa = dst_spa = new_znode.z_group_id.master_spa;
							zp->z_group_id.master3_objset = dst_os = new_znode.z_group_id.master_objset;
							zp->z_group_id.master3_object = dst_object = new_znode.z_group_id.master_object;
							zp->z_group_id.master3_gen = new_znode.z_group_id.master_gen;
						}else{
							error = EINVAL;
							goto out;
						}
						break;
					case ZFS_MULTICLUS_MASTER4:
						if(zp->z_group_id.master_spa == new_znode.z_group_id.master4_spa 
							&& zp->z_group_id.master_objset == new_znode.z_group_id.master4_objset
							&& zp->z_group_id.master_object == new_znode.z_group_id.master4_object){
							zp->z_group_id.master4_spa = dst_spa = new_znode.z_group_id.master_spa;
							zp->z_group_id.master4_objset = dst_os = new_znode.z_group_id.master_objset;
							zp->z_group_id.master4_object = dst_object = new_znode.z_group_id.master_object;
							zp->z_group_id.master4_gen = new_znode.z_group_id.master_gen;
						}else{
							error = EINVAL;
							goto out;
						}
						break;
					default:
						error = EINVAL;
						goto out;
				}
				
				if (update_master_obj_by_mx_group_id(zp, m_node_type) != 0) {
					cmn_err(CE_WARN, "[Error] %s, update_master_obj_by_mx_group_id failed! m_node_type: %d", 
						__func__, m_node_type);
				}
		
				/* send masterX info to data node and other Master node */
				if (zfs_client_notify_file_info(zp, m_node_type, update_node_info) != 0){
					cmn_err(CE_WARN, "Failed to update master file node info, file is %s, m_node_type = %d",
						zp->z_filename, m_node_type);
				}
				
			}else{
				mutex_destroy(&new_znode.z_lock);
				if(1 == debug_nas_group_dtl){
					cmn_err(CE_WARN, "[yzy Error] %s %d.zp->z_id 0x%llx, filename %s, dst_spa 0x%llx, dst_os 0x%llx, dst_object 0x%llx", 
						__func__, __LINE__, (unsigned long long)zp->z_id, zp->z_filename, (unsigned long long)dst_spa, (unsigned long long)dst_os, (unsigned long long)dst_object);
				}
				error = EINVAL;
				goto out;
			}
		}else{
			error = 0;
			goto out;
		}
	}

	record = zfs_multiclus_get_record(dst_spa, dst_os);
	if(record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
		if(1 == debug_nas_group_dtl){
			cmn_err(CE_WARN, "[Error] %s %d.", __func__, __LINE__);
		}
		error = EINVAL;
		goto out;
	}

	zfs_group_build_header_backup(ZTOZSB(zp)->z_os, msg_header, ZFS_GROUP_CMD_ZNODE_BACKUP,
	    wait_flag, op, sizeof (zfs_group_znode_msg_t), sizeof (zfs_group_znode_msg_t),
	    dst_spa, dst_os,
	    dst_object,
	    dst_object,
	    zp->z_group_id.data_spa,
	    zp->z_group_id.data_objset,
	    zp->z_group_id.data_object,
	    MSG_REQUEST, APP_USER, &zp->z_group_id, m_node_type);

	if ((error = zfs_client_send_to_server(ZTOZSB(zp)->z_os, msg_header, (zfs_msg_t *)znode_msg, B_FALSE)) != 0) {
		cmn_err(CE_WARN, "[Error] %s %d zfs_client_send_to_server return %d", __func__, __LINE__, error);
	}
out:
	kmem_free(msg_header, sizeof(zfs_group_header_t));
	kmem_free(znode_msg, sizeof(zfs_group_znode_msg_t));
	return (error);
}


int zfs_group_zget(zfs_sb_t *zsb, uint64_t object, znode_t **zpp, 
	uint64_t last_master_spa, uint64_t last_master_objset, uint64_t gen, 
	boolean_t waitting)
{
	int error;
	zfs_group_object_t group_object;
	zfs_group_phys_t tmp_phy;
	znode_t *tmp_zp = NULL;

	bzero(&group_object, sizeof(zfs_group_object_t));
	bzero(&tmp_phy, sizeof(zfs_group_phys_t));
	tmp_phy.zp_links = 1;
	group_object.master_spa = zsb->z_os->os_master_spa;
	group_object.master_objset = zsb->z_os->os_master_os;
	group_object.master_object = object;

	if(last_master_spa != 0 && last_master_objset != 0 && gen != 0){
		group_object.master2_spa = last_master_spa;
		group_object.master2_objset = last_master_objset;
		group_object.master2_object = object;
		group_object.master2_gen = gen;
	}else{
		group_object.master2_spa = 0;
		group_object.master2_objset = 0;
		group_object.master2_object = 0;
		group_object.master2_gen = 0;
	}
	
	tmp_zp = zfs_znode_alloc_by_group(zsb, 0,  &group_object, &tmp_phy);
	if (NULL == tmp_zp){
		return -1;
	}
	tmp_zp->z_id = object;

	error = zfs_group_proc_znode(tmp_zp, ZNODE_GET, NULL, kcred, waitting);
	if (error == 0){
		zfs_group_znode_copy_phys(tmp_zp, &tmp_phy, B_TRUE);
		*zpp = zfs_znode_alloc_by_group(zsb, 0,  &tmp_zp->z_group_id, &tmp_phy);
		bcopy(tmp_zp->z_filename, (*zpp)->z_filename, MAXNAMELEN);
	}
	if (NULL != tmp_zp)
		iput(ZTOI(tmp_zp));

	return (error);
}

int zfs_group_get_attr_from_data_node(zfs_sb_t *zsb, znode_t *master_znode)
{
//	boolean_t bover;
	zfs_group_cmd_arg_t cmd_arg;
	fs_data_file_attr_t *fs_data_filesize = kmem_zalloc(sizeof(fs_data_file_attr_t), KM_SLEEP);
	dmu_tx_t *tx;
	sa_bulk_attr_t	bulk[7];
	int count = 0;
	int err = 0;
	boolean_t waited = B_FALSE;
	znode_t * data_zp = NULL;
	zfs_multiclus_group_record_t *record = NULL;

	if(NULL == fs_data_filesize){
		return (ENOMEM);
	}

	if (master_znode->z_group_id.master_spa == master_znode->z_group_id.data_spa &&
		master_znode->z_group_id.master_objset == master_znode->z_group_id.data_objset &&
		master_znode->z_group_id.master_object != master_znode->z_group_id.data_object) {
		err = zfs_zget(zsb, master_znode->z_group_id.data_object, &data_zp);
		if (err) {
			goto error;
		}
		fs_data_filesize->ret = 0;
		fs_data_filesize->data_filesize = data_zp->z_size;

		sa_object_size(data_zp->z_sa_hdl,
		(uint32_t *)&fs_data_filesize->data_fileblksz,
		(u_longlong_t *)&fs_data_filesize->data_filenblks);
		
		iput(ZTOI(data_zp));
	} else {
		record = zfs_multiclus_get_record(master_znode->z_group_id.data_spa, master_znode->z_group_id.data_objset);
		if(record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
			err = ENOENT;
			goto error;
		}
			
		fs_data_filesize->data_object = master_znode->z_group_id.data_object;
		cmd_arg.arg_ptr = (uintptr_t)fs_data_filesize;
		cmd_arg.arg_size = (uintptr_t)sizeof(fs_data_file_attr_t);
		cmd_arg.return_ptr = (uintptr_t)fs_data_filesize;
		cmd_arg.return_size = (uintptr_t)sizeof(fs_data_file_attr_t);
		err = zfs_proc_cmd(zsb, SC_FS_GET_DATA_ATTR, SHARE_WAIT, &cmd_arg,
			    master_znode->z_group_id.data_spa,
			    master_znode->z_group_id.data_objset,
			    master_znode->z_group_id.data_object, APP_GROUP);
	}
	
	if (err == 0) {
		if ((fs_data_filesize->ret == 0) && ((master_znode->z_size != fs_data_filesize->data_filesize) || 
			(master_znode->z_nblks != fs_data_filesize->data_filenblks) || (master_znode->z_blksz != fs_data_filesize->data_fileblksz))){
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_SIZE(zsb), NULL,
			    &fs_data_filesize->data_filesize, 8);
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_NBLKS(zsb), NULL,
			    &fs_data_filesize->data_filenblks, 8);
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_BLKSZ(zsb), NULL,
			    &fs_data_filesize->data_fileblksz, 8);
			
			mutex_enter(&master_znode->z_lock);
			master_znode->z_size = fs_data_filesize->data_filesize;
			master_znode->z_nblks = fs_data_filesize->data_filenblks;
			master_znode->z_blksz = fs_data_filesize->data_fileblksz;
			mutex_exit(&master_znode->z_lock);
		top:
			tx = dmu_tx_create(zsb->z_os);
			dmu_tx_hold_sa(tx, master_znode->z_sa_hdl, B_FALSE);
			err = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
			if (err != 0) {
				if (err == ERESTART) {
					waited = B_TRUE;
					dmu_tx_wait(tx);
					dmu_tx_abort(tx);
					goto top;
				}
				dmu_tx_abort(tx);
				goto error;
			}

			if((err = sa_bulk_update(master_znode->z_sa_hdl, bulk, count, tx))!=0){
				dmu_tx_commit(tx);
				goto error;
			}
			dmu_tx_commit(tx);
		}else{
			err = fs_data_filesize->ret;
			if(err != 0){
				cmn_err(CE_WARN, "[Error] ret=%d: get data file attr from data node FAIL!!!",err);
			}
		}
	}else{
		cmn_err(CE_WARN, "[Error] ret=%d: get data file attr from data node FAIL!!",err);
	}

error:

	if(NULL != fs_data_filesize){
		kmem_free(fs_data_filesize, sizeof(fs_data_file_attr_t));
	}
	
	return (err);
}

int 
zfs_group_get_attr_from_data2_node(zfs_sb_t *zsb, znode_t *master_znode)
{
//	boolean_t bover;
	zfs_group_cmd_arg_t cmd_arg;
	fs_data_file_attr_t *fs_data_filesize = kmem_zalloc(sizeof(fs_data_file_attr_t), KM_SLEEP);
	dmu_tx_t *tx;
	sa_bulk_attr_t	bulk[7];
	int count = 0;
	int err = 0;
	boolean_t waited = B_FALSE;
	znode_t * data_zp = NULL;
	zfs_multiclus_group_record_t *record = NULL;

	if(NULL == fs_data_filesize){
		return (ENOMEM);
	}

	if (master_znode->z_group_id.master_spa == master_znode->z_group_id.data2_spa &&
		master_znode->z_group_id.master_objset == master_znode->z_group_id.data2_objset &&
		master_znode->z_group_id.master_object != master_znode->z_group_id.data2_object) {
		err = zfs_zget(zsb, master_znode->z_group_id.data2_object, &data_zp);
		if (err) {
			goto error;
		}
		fs_data_filesize->ret = 0;
		fs_data_filesize->data_filesize = data_zp->z_size;
		fs_data_filesize->data_filenblks = data_zp->z_nblks;
		fs_data_filesize->data_fileblksz = data_zp->z_blksz;
		iput(ZTOI(data_zp));
	} else {
		record = zfs_multiclus_get_record(master_znode->z_group_id.data2_spa, master_znode->z_group_id.data2_objset);
		if(record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
			err = ENOENT;
			goto error;
		}
		
		fs_data_filesize->data_object = master_znode->z_group_id.data2_object;
		cmd_arg.arg_ptr = (uintptr_t)fs_data_filesize;
		cmd_arg.arg_size = (uintptr_t)sizeof(fs_data_file_attr_t);
		cmd_arg.return_ptr = (uintptr_t)fs_data_filesize;
		cmd_arg.return_size = (uintptr_t)sizeof(fs_data_file_attr_t);
		err = zfs_proc_cmd(zsb, SC_FS_GET_DATA_ATTR, SHARE_WAIT, &cmd_arg,
			    master_znode->z_group_id.data2_spa,
			    master_znode->z_group_id.data2_objset,
			    master_znode->z_group_id.data2_object, APP_GROUP);
	}
	
	if (err == 0) {
		if ((fs_data_filesize->ret == 0) && ((master_znode->z_size != fs_data_filesize->data_filesize) || 
			(master_znode->z_nblks != fs_data_filesize->data_filenblks) || (master_znode->z_blksz != fs_data_filesize->data_fileblksz))){
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_SIZE(zsb), NULL,
			    &fs_data_filesize->data_filesize, 8);
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_NBLKS(zsb), NULL,
			    &fs_data_filesize->data_filenblks, 8);
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_BLKSZ(zsb), NULL,
			    &fs_data_filesize->data_fileblksz, 8);

			mutex_enter(&master_znode->z_lock);
			master_znode->z_size = fs_data_filesize->data_filesize;
			master_znode->z_nblks = fs_data_filesize->data_filenblks;
			master_znode->z_blksz = fs_data_filesize->data_fileblksz;
			mutex_exit(&master_znode->z_lock);
		top:
			tx = dmu_tx_create(zsb->z_os);
			dmu_tx_hold_sa(tx, master_znode->z_sa_hdl, B_FALSE);
			err = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
			if (err != 0) {
				if (err == ERESTART) {
					waited = B_TRUE;
					dmu_tx_wait(tx);
					dmu_tx_abort(tx);
					goto top;
				}
				dmu_tx_abort(tx);
				goto error;
			}

			if((err = sa_bulk_update(master_znode->z_sa_hdl, bulk, count, tx))!=0){
				dmu_tx_commit(tx);
				goto error;
			}
			dmu_tx_commit(tx);
		}else{
			err = fs_data_filesize->ret;
			if(err != 0){ 
				cmn_err(CE_WARN, "[Error] ret=%d: get data file attr from data node FAIL!!!",err);
			}
		}
	}else{
		cmn_err(CE_WARN, "[Error] ret=%d: get data file attr from data node FAIL!!",err);
	}

error:

	if(NULL != fs_data_filesize){
		kmem_free(fs_data_filesize, sizeof(fs_data_file_attr_t));
	}
	
	return (err);
}


int zfs_group_client_space(znode_t *zp, uint64_t off,
    uint64_t len, uint64_t flags)
{
	int err;
	zfs_group_znode_free_t free;
	zfs_multiclus_group_record_t* record = NULL;
	int retry_num = 0;
retry:
	record = zfs_multiclus_get_record(zp->z_group_id.data_spa, zp->z_group_id.data_objset);
	if (record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE) {
		if (retry_num < 3) {
			retry_num++;
			cmn_err(CE_WARN, "%s %d wait num=%d\n", __func__, __LINE__, retry_num);
			zfs_group_wait(1000*1000);
			goto retry;
		}
		return ENOENT;
	}

	free.off = off;
	free.len = len;
	free.flag = flags;
	err = zfs_group_proc_znode(zp, ZNODE_FREE, &free, kcred, B_TRUE);

	return (err);
}

int zfs_group_client_space_data2(znode_t *zp, uint64_t off,
    uint64_t len, uint64_t flags)
{
	zfs_group_znode_free_t free = { 0 };
	zfs_group_object_t group_id = { 0 };
	zfs_multiclus_group_record_t* record = NULL;
	int err = 0;

	record = zfs_multiclus_get_record(zp->z_group_id.data2_spa, zp->z_group_id.data2_objset);
	if (record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE) {
		return ENOENT;
	}

	free.off = off;
	free.len = len;
	free.flag = flags;

	group_id = zp->z_group_id;
	zp->z_group_id.data_spa = group_id.data2_spa;
	zp->z_group_id.data_objset = group_id.data2_objset;
	zp->z_group_id.data_object = group_id.data2_object;

	err = zfs_group_proc_znode(zp, ZNODE_FREE, &free, kcred, B_TRUE);

	zp->z_group_id = group_id;

	return (err);
}

int
zfs_group_proc_notify(objset_t *os, 
    uint64_t dst_spa, uint64_t dst_os, uint64_t dst_object, notify_op_t op,
    zfs_group_notify_arg_t *arg)
{
	zfs_group_notify_msg_t *notify_msg;
	zfs_group_header_t *msg_header = NULL;
	zfs_group_notify_t *nop;
	int error;

	notify_msg = kmem_zalloc(sizeof (zfs_group_notify_msg_t), KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	nop = &notify_msg->call.notify;
	switch (op) {
		case NOTIFY_SYSTEM_SPACE:
			nop->arg.p.system_space = arg->p.system_space;
			break;

		case NOTIFY_FILE_SPACE:
			nop->arg.p.file_space = arg->p.file_space;
			break;

		case NOTIFY_FILE_INFO:
			nop->arg.p.file_info = arg->p.file_info;
			break;

		case NOTIFY_DATA_DIRTY:
			nop->arg.p.dirty_notify = arg->p.dirty_notify;
			break;
		
		default:
			ASSERT(arg == NULL);
			break;
	}

	zfs_group_build_header(os,
	    msg_header, ZFS_GROUP_CMD_NOTIFY, SHARE_NOWAIT,
	    op, sizeof (zfs_group_notify_msg_t), sizeof (zfs_group_notify_msg_t),
	    dst_spa, dst_os, dst_object, 0, dst_spa, dst_os, dst_object,
	    MSG_NOTIFY, APP_USER);
	error = zfs_client_send_to_server(os, msg_header, (zfs_msg_t *)notify_msg, B_FALSE);
	kmem_free(msg_header, sizeof(zfs_group_header_t));
	kmem_free(notify_msg, sizeof (zfs_group_notify_msg_t));
	return (error);
}

int zfs_client_do_notify_file_space(zfs_sb_t * zsb, zfs_group_notify_file_space_t* file_notify,
	uint64_t master_spa, uint64_t master_os, uint64_t master_object, uint64_t master_gen)
{
//	znode_t* dst_zp = NULL;
	zfs_multiclus_group_record_t *dst_recordp = NULL;

	if (master_spa == -1 || master_os == -1 || master_object == -1
		|| master_spa == 0 || master_os == 0 || master_object == 0) {
		return 0;
	}

	dst_recordp = zfs_multiclus_get_record(master_spa, master_os);
	if(dst_recordp == NULL || dst_recordp->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
		return ENOENT;
	}

	file_notify->file_object = master_object;
	file_notify->file_gen = master_gen;

	zfs_group_proc_notify(zsb->z_os, master_spa, master_os, master_object,
		NOTIFY_FILE_SPACE, (zfs_group_notify_arg_t*)file_notify);

	return 0;
}

int zfs_client_notify_file_space(znode_t *zp, uint64_t update_size, uint64_t used_op, boolean_t update_quota,
	uint64_t local_spa, uint64_t local_os)
{
	zfs_group_notify_file_space_t file_notify;
	zfs_sb_t *zsb = NULL;

	zsb = zfs_sb_group_hold(local_spa, local_os, FTAG, B_FALSE);
	if (zsb == NULL) {
		cmn_err(CE_WARN, "[Error] %s, %d, zfsvfs_group_hold failed! spa: 0x%llx, os: 0x%llx", 
			__func__, __LINE__, (unsigned long long)local_spa, (unsigned long long)local_os);
		return EGHOLD;
	}

	bzero(&file_notify, sizeof(zfs_group_notify_file_space_t));
//	bcopy(zp->z_atime, file_notify.atime, sizeof(zp->z_atime));
//	bcopy(zp->z_ctime, file_notify.ctime, sizeof(zp->z_ctime));
//	bcopy(zp->z_mtime, file_notify.mtime, sizeof(zp->z_mtime));
	ZFS_TIME_ENCODE(&ZTOI(zp)->i_atime, file_notify.atime);
	ZFS_TIME_ENCODE(&ZTOI(zp)->i_ctime, file_notify.ctime);
	ZFS_TIME_ENCODE(&ZTOI(zp)->i_mtime, file_notify.mtime);
	file_notify.file_updatesize = update_size;
	file_notify.file_updateop = used_op;
	file_notify.file_size = zp->z_size;
	file_notify.file_nblks = (uint64_t)ZTOI(zp)->i_blocks;
	file_notify.file_blksz = (uint64_t)(1 <<(ZTOI(zp)->i_blkbits));
	file_notify.file_low = zp->z_low;
	file_notify.update_quota = update_quota;
	file_notify.group_id = zp->z_group_id;

	zfs_client_do_notify_file_space(zsb, &file_notify, zp->z_group_id.master_spa,
		zp->z_group_id.master_objset, zp->z_group_id.master_object, zp->z_group_id.master_gen);

	zfs_client_do_notify_file_space(zsb, &file_notify, zp->z_group_id.master2_spa,
		zp->z_group_id.master2_objset, zp->z_group_id.master2_object, zp->z_group_id.master2_gen);

	zfs_client_do_notify_file_space(zsb, &file_notify, zp->z_group_id.master3_spa,
		zp->z_group_id.master3_objset, zp->z_group_id.master3_object, zp->z_group_id.master3_gen);

	zfs_client_do_notify_file_space(zsb, &file_notify, zp->z_group_id.master4_spa,
		zp->z_group_id.master4_objset, zp->z_group_id.master4_object, zp->z_group_id.master4_gen);

	zfs_sb_group_rele(zsb, FTAG);

	return 0;
}

void zfs_client_noify_file_space_tq(void* arg)
{
	zfs_group_notify_para_t *notify_para = (zfs_group_notify_para_t *)arg;

	if (notify_para != NULL) {
		zfs_client_notify_file_space(&notify_para->znode, notify_para->update_size, notify_para->used_op, 
			notify_para->update_quota, notify_para->local_spa, notify_para->local_os);

		kmem_free(notify_para, sizeof(zfs_group_notify_para_t));
	}
}

int zfs_client_do_notify_file_info(znode_t* zp, uint64_t dst_spa, uint64_t dst_objset, uint64_t dst_object, uint64_t update_node_info)
{
	zfs_group_notify_arg_t arg;
	zfs_multiclus_group_record_t *record = NULL;

	if (dst_spa == 0 || dst_objset == 0 || dst_object == 0
		|| dst_spa == -1 || dst_objset == -1 || dst_object == -1) {
		return 0;
	}

	record = zfs_multiclus_get_record(dst_spa, dst_objset);
	if(record == NULL){
		return 0;
	}

	if(record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
		return 0;
	}

	bzero(&arg, sizeof(zfs_group_notify_arg_t));

	arg.p.file_info.group_id = zp->z_group_id;
	arg.p.file_info.dst_spa = dst_spa;
	arg.p.file_info.dst_objset = dst_objset;
	arg.p.file_info.dst_object = dst_object;
	arg.p.file_info.update_node_info = update_node_info;

	return zfs_group_proc_notify(ZTOZSB(zp)->z_os, dst_spa, dst_objset, dst_object, NOTIFY_FILE_INFO, &arg);
}

int zfs_client_notify_file_info(znode_t* zp, zfs_multiclus_node_type_t m_node_type, uint64_t update_node_info)
{
	int error = 0;
	int ret = 0;

	if (update_node_info != ZFS_UPDATE_FILE_NODE_DATA1 && update_node_info != ZFS_UPDATE_FILE_NODE_DATA2) {
		error = zfs_client_do_notify_file_info(zp, zp->z_group_id.data_spa,
			zp->z_group_id.data_objset, zp->z_group_id.data_object, update_node_info);
			if (error != 0){
				cmn_err(CE_WARN, "[Error] Failed to update data1 file node info, error = %d, m_node_type = %d",
					error, m_node_type);
				ret = -1;
			}
	}

	if (TO_DOUBLE_DATA_FILE && update_node_info != ZFS_UPDATE_FILE_NODE_DATA1
		&& update_node_info != ZFS_UPDATE_FILE_NODE_DATA2) {
		error = zfs_client_do_notify_file_info(zp, zp->z_group_id.data2_spa,
			zp->z_group_id.data2_objset, zp->z_group_id.data2_object, update_node_info);
		if (error != 0){
			cmn_err(CE_WARN, "[Error] Failed to update data2 file node info, error = %d, m_node_type = %d",
				error, m_node_type);
			ret = -1;
		}
	}

	error = zfs_client_do_notify_file_info(zp, zp->z_group_id.master2_spa,
		zp->z_group_id.master2_objset, zp->z_group_id.master2_object, update_node_info);
	if (error != 0) {
		cmn_err(CE_WARN, "[Error] Failed to update master2 node info, error = %d, m_node_type = %d", 
			error, m_node_type);
		ret = -1;
	}

	error = zfs_client_do_notify_file_info(zp, zp->z_group_id.master3_spa,
		zp->z_group_id.master3_objset, zp->z_group_id.master3_object, update_node_info);
	if (error != 0) {
		cmn_err(CE_WARN, "[Error] Failed to update master3 node info, error = %d, m_node_type = %d", 
			error, m_node_type);
		ret = -1;
	}

	error = zfs_client_do_notify_file_info(zp, zp->z_group_id.master4_spa,
		zp->z_group_id.master4_objset, zp->z_group_id.master4_object, update_node_info);
	if (error != 0) {
		cmn_err(CE_WARN, "[Error] Failed to update master4 node info, error = %d, m_node_type = %d", 
			error, m_node_type);
		ret = -1;
	}

	return ret;
}

 int objset_notify_system_space(objset_t *os)
 {
 	int error;
 	zfs_sb_t *zsb = NULL;
 	zfs_group_notify_system_space_t sys_space;

 	if ((os->os_phys->os_type != DMU_OST_ZFS &&
 	    os->os_phys->os_type != DMU_OST_ZVOL) ||
 	    !os->os_is_group)
 		return (0);

 	mutex_enter(&os->os_user_ptr_lock);
 	zsb = (zfs_sb_t *)dmu_objset_get_user(os);
 	mutex_exit(&os->os_user_ptr_lock);
 	if (zsb == NULL)
 		return (0);

 	dmu_objset_space(os,
 	    &sys_space.space_ref, &sys_space.space_avail, &sys_space.space_usedobjs,
 	    &sys_space.space_availobjs);
 	sys_space.sys_ios = spa_get_ios(dmu_objset_spa(os));
 	sys_space.space_spa = spa_guid(dmu_objset_spa(os));
 	sys_space.space_os = dmu_objset_id(os);

 	if (os->os_is_master) {
 			zfs_group_update_system_space(os, &sys_space);
 	} else {
 		error = zfs_group_proc_notify(os, os->os_master_spa, os->os_master_os,
 		    os->os_master_root, NOTIFY_SYSTEM_SPACE,
 		    (zfs_group_notify_arg_t *)&sys_space);
 	}

 	return (error);
}


int zfs_client_group_zget(zfs_sb_t * zsb, znode_t* zp, znode_t** zpp)
{
	znode_t* tmp_zp = NULL;
	uint64_t spa = 0;
	uint64_t os = 0;
	int retry = 10;
	int error = 0;

	spa = spa_guid(dmu_objset_spa(zsb->z_os));
	os = dmu_objset_id(zsb->z_os);

	while (retry > 0) {
		if (zsb->z_os->os_master_spa == zp->z_group_id.master_spa
			&& zsb->z_os->os_master_os == zp->z_group_id.master_objset) {
			/* master is not changed */
			error = zfs_group_zget(zsb, zp->z_id, &tmp_zp, 0, 0, 0, B_TRUE);
		} else {
			/* master is changed */
			error = zfs_group_zget(zsb, zp->z_id, &tmp_zp,
						zp->z_group_id.master_spa,
						zp->z_group_id.master_objset, zp->z_group_id.master_gen, B_TRUE);
			if (error != 0) {
				break;
			}
		}

		if (error == 0) {
			*zpp = tmp_zp;
			break;
		}

		zfs_sb_group_rele(zsb, FTAG);
		zfs_group_wait(10 * ZFS_GROUP_NOTIFY_WAIT);

		zsb = zfs_sb_group_hold(spa, os, FTAG, B_FALSE);
		if (zsb == NULL) {
			error = EGHOLD;
			break;
		}

		--retry;
	}

	return error;
}

int zfs_client_do_notify_data_file_dirty(znode_t* zp, uint64_t dirty_flag,
	zfs_group_data_file_no_t data_no, zfs_multiclus_node_type_t node_type,
	uint64_t dst_spa, uint64_t dst_os, uint64_t dst_obj, 
	uint64_t local_spa, uint64_t local_os)
{
	zfs_group_notify_data_dirty_t dirty_notify = { 0 };
	zfs_sb_t *zsb = NULL;
	znode_t* dst_zp = NULL;
	int retry_cnt = 5;
	int error = 0;

	if (dst_spa == 0 || dst_os == 0 || dst_obj == 0) {
		return ENOENT;
	}

	zsb = zfs_sb_group_hold(local_spa, local_os, FTAG, B_FALSE);
	if (zsb == NULL) {
		return EGHOLD;
	}

	while (retry_cnt > 0) {
		if (dst_spa != -1 && dst_os != -1 && dst_obj != -1) {
			break;
		}

		zfs_group_wait(ZFS_GROUP_NOTIFY_WAIT);

		if (zp->z_group_role == GROUP_VIRTUAL) {
			error = zfs_client_group_zget(zsb, zp, &dst_zp);
		} else {
			error = zfs_zget(zsb, zp->z_id, &dst_zp);
		}

		if (error != 0) {
			break;
		}

		switch (node_type)
		{
			case ZFS_MULTICLUS_MASTER2:
				dst_spa = dst_zp->z_group_id.master2_spa;
				dst_os = dst_zp->z_group_id.master2_objset;
				dst_obj = dst_zp->z_group_id.master2_object;
				break;

			case ZFS_MULTICLUS_MASTER3:
				dst_spa = dst_zp->z_group_id.master3_spa;
				dst_os = dst_zp->z_group_id.master3_objset;
				dst_obj = dst_zp->z_group_id.master3_object;
				break;

			case ZFS_MULTICLUS_MASTER4:
				dst_spa = dst_zp->z_group_id.master4_spa;
				dst_os = dst_zp->z_group_id.master4_objset;
				dst_obj = dst_zp->z_group_id.master4_object;
				break;

			default:
				cmn_err(CE_WARN, "[Error] %s, invalid node type, node_type = %d",
					__func__, node_type);
				dst_spa = 0;
				dst_os = 0;
				dst_obj = 0;
				break;
		}
		
		iput(ZTOI(dst_zp));

		--retry_cnt;
	}

	if (dst_spa == -1 || dst_os == -1 || dst_obj == -1
		|| dst_spa == 0 || dst_os == 0 || dst_obj == 0) {
		zfs_sb_group_rele(zsb, FTAG);
		return ENOENT;
	}

	dirty_notify.dirty_flag = dirty_flag;
	dirty_notify.master_object = dst_obj;
	dirty_notify.data_file_no = data_no;

	error = zfs_group_proc_notify(zsb->z_os, dst_spa, dst_os, dst_obj,
		NOTIFY_DATA_DIRTY, (zfs_group_notify_arg_t *)&dirty_notify);

	zfs_sb_group_rele(zsb, FTAG);
	return error;
}

int zfs_client_notify_data_file_dirty(znode_t *zp, uint64_t dirty_flag,
	zfs_group_data_file_no_t data_no, uint64_t local_spa, uint64_t local_os)
{
	zfs_client_do_notify_data_file_dirty(zp, dirty_flag, data_no, ZFS_MULTICLUS_MASTER,
		zp->z_group_id.master_spa, zp->z_group_id.master_objset, zp->z_group_id.master_object,
		local_spa, local_os);

	zfs_client_do_notify_data_file_dirty(zp, dirty_flag, data_no, ZFS_MULTICLUS_MASTER2,
		zp->z_group_id.master2_spa, zp->z_group_id.master2_objset, zp->z_group_id.master2_object,
		local_spa, local_os);

	zfs_client_do_notify_data_file_dirty(zp, dirty_flag, data_no, ZFS_MULTICLUS_MASTER3,
		zp->z_group_id.master3_spa, zp->z_group_id.master3_objset, zp->z_group_id.master3_object,
		local_spa, local_os);

	zfs_client_do_notify_data_file_dirty(zp, dirty_flag, data_no, ZFS_MULTICLUS_MASTER4,
		zp->z_group_id.master4_spa, zp->z_group_id.master4_objset, zp->z_group_id.master4_object,
		local_spa, local_os);

	return 0;
}

void zfs_client_notify_data_file_dirty_tq(void* arg)
{
	zfs_group_dirty_notify_para_t *notify_para = (zfs_group_dirty_notify_para_t *)arg;
	if (notify_para != NULL) {
		zfs_client_notify_data_file_dirty(&notify_para->znode, notify_para->dirty_flag,
			notify_para->data_no, notify_para->local_spa, notify_para->local_os);
		kmem_free(notify_para, sizeof(zfs_group_dirty_notify_para_t));
	}
}

static void
zfs_group_from_xvattr(zfs_group_name_attr_t *zg_attr, xvattr_t *xvap)
{
//	uint32_t	*bitmap;
	uint64_t	*attrs;
//	uint64_t	*crtime;
	xoptattr_t	*xoap;
//	void		*scanstamp;
//	int		i;

	xoap = xva_getxoptattr(xvap);
	ASSERT(xoap);

	zg_attr->zg_attr_masksize = xvap->xva_mapsize;
	zg_attr->zg_magic = xvap->xva_magic;
	bcopy(xvap->xva_reqattrmap, zg_attr->zg_attr_bitmap, XVA_MAPSIZE*sizeof(uint32_t));

	attrs = &zg_attr->zg_attr;
	if (XVA_ISSET_REQ(xvap, XAT_READONLY))
		*attrs |= (xoap->xoa_readonly == 0) ? 0 :
		    XAT0_READONLY;
	if (XVA_ISSET_REQ(xvap, XAT_HIDDEN))
		*attrs |= (xoap->xoa_hidden == 0) ? 0 :
		    XAT0_HIDDEN;
	if (XVA_ISSET_REQ(xvap, XAT_SYSTEM))
		*attrs |= (xoap->xoa_system == 0) ? 0 :
		    XAT0_SYSTEM;
	if (XVA_ISSET_REQ(xvap, XAT_ARCHIVE))
		*attrs |= (xoap->xoa_archive == 0) ? 0 :
		    XAT0_ARCHIVE;
	if (XVA_ISSET_REQ(xvap, XAT_IMMUTABLE))
		*attrs |= (xoap->xoa_immutable == 0) ? 0 :
		    XAT0_IMMUTABLE;
	if (XVA_ISSET_REQ(xvap, XAT_NOUNLINK))
		*attrs |= (xoap->xoa_nounlink == 0) ? 0 :
		    XAT0_NOUNLINK;
	if (XVA_ISSET_REQ(xvap, XAT_APPENDONLY))
		*attrs |= (xoap->xoa_appendonly == 0) ? 0 :
		    XAT0_APPENDONLY;
	if (XVA_ISSET_REQ(xvap, XAT_OPAQUE))
		*attrs |= (xoap->xoa_opaque == 0) ? 0 :
		    XAT0_APPENDONLY;
	if (XVA_ISSET_REQ(xvap, XAT_NODUMP))
		*attrs |= (xoap->xoa_nodump == 0) ? 0 :
		    XAT0_NODUMP;
	if (XVA_ISSET_REQ(xvap, XAT_AV_QUARANTINED))
		*attrs |= (xoap->xoa_av_quarantined == 0) ? 0 :
		    XAT0_AV_QUARANTINED;
	if (XVA_ISSET_REQ(xvap, XAT_AV_MODIFIED))
		*attrs |= (xoap->xoa_av_modified == 0) ? 0 :
		    XAT0_AV_MODIFIED;
	if (XVA_ISSET_REQ(xvap, XAT_CREATETIME))
		ZFS_TIME_ENCODE(&xoap->xoa_createtime, zg_attr->zg_ctime);
	if (XVA_ISSET_REQ(xvap, XAT_AV_SCANSTAMP))
		bcopy(xoap->xoa_av_scanstamp, (void *)zg_attr->zg_scan, AV_SCANSTAMP_SZ);
	if (XVA_ISSET_REQ(xvap, XAT_REPARSE))
		*attrs |= (xoap->xoa_reparse == 0) ? 0 :
		    XAT0_REPARSE;
	if (XVA_ISSET_REQ(xvap, XAT_OFFLINE))
		*attrs |= (xoap->xoa_offline == 0) ? 0 :
		    XAT0_OFFLINE;
	if (XVA_ISSET_REQ(xvap, XAT_SPARSE))
		*attrs |= (xoap->xoa_sparse == 0) ? 0 :
		    XAT0_SPARSE;
}

static void zfs_group_acl_msg(char *omsg, zfs_group_name_acl_t *zg_acl)
{
	sprintf(omsg, "acl para:acl_cnt(%lld), acl_mask(%llx), acl_dfaclcnt(%lld),"
	    "aclsz(%lld), aclflags(%llx)", (longlong_t)zg_acl->aclcnt,
	    (longlong_t)zg_acl->mask, (longlong_t)zg_acl->dfaclcnt,
	    (longlong_t)zg_acl->aclsz, (longlong_t)zg_acl->aclflags);
}

void zfs_group_from_acl(zfs_group_name_acl_t *zg_acl, vsecattr_t *vsap)
{
	char *tmp_acls;
	zg_acl->aclcnt = vsap->vsa_aclcnt;
	zg_acl->mask = vsap->vsa_mask;
	zg_acl->dfaclcnt = vsap->vsa_dfaclcnt;
	zg_acl->aclsz = vsap->vsa_aclentsz;
	zg_acl->aclflags = vsap->vsa_aclflags;
	tmp_acls = zg_acl->acls;
	if (zg_acl->aclsz > 0 && vsap->vsa_aclentp != NULL) {
		bcopy(vsap->vsa_aclentp, tmp_acls, zg_acl->aclsz);
		tmp_acls += sizeof(zg_acl->aclcnt) *sizeof(aclent_t);
	}
}

zfs_group_create_extra_t *zfs_group_get_create_extra(char *name, vattr_t *vap,
    vsecattr_t *vsap, size_t *name_len, size_t *xvatlen, size_t *acl_len, 
    uint64_t *dirlowdata, size_t *dlow_len)
{
	char *cp;
	char *tmp_cp;
	uint64_t cp_len;

	size_t namesize;
	size_t aclsize;
	size_t xvatsize;
	size_t dlowdatasize;
	xvattr_t *xvap;
	zfs_group_name_attr_t *zg_attr;
	zfs_group_name_acl_t *zg_acl;
	uint64_t *zg_dlow;
	zfs_group_create_extra_t *create_extra = NULL;

	cp_len =0;
	xvatsize =0;
	namesize = 0;
	aclsize = 0;
	dlowdatasize = 0;
	xvap = (xvattr_t *)vap;


	create_extra = kmem_zalloc(sizeof(zfs_group_create_extra_t), KM_SLEEP);

	if (name != NULL)
		namesize = (strlen(name) + 1 + 7) &(~7);

#if 1
	if (vap != NULL && vap->va_mask & AT_XVATTR)
		xvatsize = sizeof(zfs_group_name_attr_t);
	if (vsap != NULL) {
		aclsize = sizeof (zfs_group_name_acl_t ) + vsap->vsa_aclentsz - 8;
	}
	if (dirlowdata != NULL) {
		dlowdatasize = ZFS_DIR_LOWDATA_MSG_LEN;
	}
#endif

	cp_len = namesize + xvatsize + aclsize + dlowdatasize;
	cp = kmem_zalloc(cp_len, KM_SLEEP);
	tmp_cp = cp;


	if (namesize > 0) {
		bcopy(name, tmp_cp, namesize -1);
		tmp_cp[namesize -1] = 0;
		tmp_cp += namesize;
		*name_len = namesize;
	}
	if(xvatsize > 0) {
		zg_attr = (zfs_group_name_attr_t *)tmp_cp;
		zfs_group_from_xvattr(zg_attr, xvap);
		tmp_cp += xvatsize;
		*xvatlen = xvatsize;
	}

	if (aclsize > 0){
		zg_acl = (zfs_group_name_acl_t *)tmp_cp;
		zfs_group_from_acl(zg_acl, vsap);
		tmp_cp += aclsize;
		*acl_len = aclsize;
	}

	if (dlowdatasize > 0) {
		zg_dlow = (uint64_t *)tmp_cp;
		*zg_dlow = *dirlowdata;
		*dlow_len = ZFS_DIR_LOWDATA_MSG_LEN;
	}

	create_extra->extra_createp = cp;
	create_extra->extra_create_plen = cp_len;

	return (create_extra);
}


int zfs_client_create(struct inode *pip, char *name, vattr_t *vap, vcexcl_t ex,
    int mode, struct inode **ipp, cred_t *credp, int flag, caller_context_t *ct,
    vsecattr_t *vsap)
{
//	char *cp;
//	char *tmp_cp;
//	uint64_t cp_len;

	size_t namesize;
	size_t aclsize;
	size_t xvatsize;
	zfs_group_create_extra_t *create_extra;


	znode_t *zp;
	znode_t *pzp; 
	zfs_group_name_create_t create;
	zfs_group_znode_record_t *nrec;
	int error = 0;

	namesize = 0;
	aclsize = 0;
	xvatsize =0;
	create_extra = NULL;
/*
	vp = dnlc_lookup(pvp, name);
	if (vp != NULL) {
		dnlc_remove(pvp, name);
		VN_RELE(vp);
	}
*/
	create_extra = zfs_group_get_create_extra(name, vap, vsap, &namesize, &xvatsize,
					    &aclsize, NULL, 0);
	create.name_len = namesize;
	create.xattr_len = xvatsize;
	create.acl_len = aclsize;
	*ipp = NULL;
	create.ex = (int32_t)ex;
	create.mode = mode;
	create.flag = flag;
	if ((error = zfs_group_v_to_v32(vap, &create.vattr)) != 0) {
		kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
		kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
		return (error);
	}

	nrec = kmem_alloc(sizeof (zfs_group_znode_record_t), KM_SLEEP);

	pzp = ITOZ(pip);
	error = zfs_group_proc_name(pzp, NAME_CREATE, &create,
	    sizeof (create), create_extra->extra_createp,
	    create_extra->extra_create_plen, NULL, flag, credp, nrec);
	if (error == 0) {
		if(nrec->object_id.master_spa == 0 && nrec->object_id.master_objset == 0
			&& nrec->object_id.master_object == 0 && nrec->object_id.data_spa == 0
			&& nrec->object_id.data_objset == 0 && nrec->object_id.data_object == 0){
			cmn_err(CE_WARN, "[corrupt group object] %s %s %d", __FILE__, __func__, __LINE__);
		}
		zp = zfs_znode_alloc_by_group(ZTOZSB(pzp), nrec->object_blksz,
		    &nrec->object_id, &nrec->object_phy);

		zfs_group_acquire_znode_error(zp, &nrec->object_id, &nrec->object_phy,
		    "group_create");
		*ipp = ZTOI(zp);
	}

	kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
	kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
	kmem_free(nrec, sizeof(zfs_group_znode_record_t));
	return (error);
}

int update_master_obj_by_mx_group_id(znode_t *zp, zfs_multiclus_node_type_t m_node_type)
{
	int err = 0;
	dmu_tx_t *tx = NULL;
	zfs_sb_t *zsb = NULL;
	char buf[MAXNAMELEN];
	uint64_t mx_spa = 0;
	uint64_t mx_os = 0;
	uint64_t mx_obj = 0;
	uint64_t mx_gen = 0;
	uint64_t map_obj = 0;

	VERIFY(zp != NULL);

	zsb = ZTOZSB(zp);

	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if(err != 0){
		dmu_tx_abort(tx);
		return (-1);
	}
	mutex_enter(&zp->z_lock);
	VERIFY(0 == sa_update(zp->z_sa_hdl, SA_ZPL_REMOTE_OBJECT(zsb),
					&zp->z_group_id, sizeof (zp->z_group_id), tx));
	mutex_exit(&zp->z_lock);
	mutex_enter(&zsb->z_lock);
	
	switch (m_node_type) {
		case ZFS_MULTICLUS_MASTER2:
			mx_spa = zp->z_group_id.master2_spa;
			mx_os = zp->z_group_id.master2_objset;
			mx_obj = zp->z_group_id.master2_object;
			mx_gen = zp->z_group_id.master2_gen;
			break;
		case ZFS_MULTICLUS_MASTER3:
			mx_spa = zp->z_group_id.master3_spa;
			mx_os = zp->z_group_id.master3_objset;
			mx_obj = zp->z_group_id.master3_object;
			mx_gen = zp->z_group_id.master3_gen;
			break;
		case ZFS_MULTICLUS_MASTER4:
			mx_spa = zp->z_group_id.master4_spa;
			mx_os = zp->z_group_id.master4_objset;
			mx_obj = zp->z_group_id.master4_object;
			mx_gen = zp->z_group_id.master4_gen;
			break;
		default:
			break;
	}
	
	if (mx_spa != 0 && mx_os != 0 && mx_obj != 0 && mx_gen != 0) {
		map_obj = zsb->z_group_map_objs[mx_obj%NASGROUP_MAP_NUM];
		bzero(buf, MAXNAMELEN);
		sprintf(buf, zfs_group_map_key_name_prefix_format, mx_spa, mx_os, mx_obj, mx_gen & ZFS_GROUP_GEN_MASK);
		if(map_obj == 0){
			cmn_err(CE_WARN, "[Error] %s %d Failed in updating zfs_group_map_key %s", 
				__func__, __LINE__, buf);
			err = -1;
		}else{
			err = zap_update(zsb->z_os, map_obj, buf, 8, 1, &zp->z_group_id.master_object, tx);
			if(err != 0){
				cmn_err(CE_WARN, "[Error] %s Failed in updating zfs_group_map_key %s", __func__, buf);
			}else if(debug_nas_group_dtl == 2){
				cmn_err(CE_WARN, "[INFO] %s Succeed in updating zfs_group_map_key %s", __func__, buf);
			}
		}
	} else {
		cmn_err(CE_WARN, "[Error] %s Failed in updating zfs_group_map_key %s, wrong m_node_type: %d", 
			__func__, buf, m_node_type);
		err = (-1);
	}

	mutex_exit(&zsb->z_lock);
	dmu_tx_commit(tx);
	return err;
}

int remove_master_obj_by_mx_group_id(znode_t *zp, dmu_tx_t *tx)
{
	int err = 0;
	zfs_sb_t *zsb = NULL;
	char buf[MAXNAMELEN];
	uint64_t map_obj = 0;

	VERIFY(zp != NULL);
	zsb = ZTOZSB(zp);
	
	mutex_enter(&zsb->z_lock);
	bzero(buf, MAXNAMELEN);
	sprintf(buf, zfs_group_map_key_name_prefix_format, 
		zp->z_group_id.master2_spa, zp->z_group_id.master2_objset, zp->z_group_id.master2_object, 
		zp->z_group_id.master2_gen & ZFS_GROUP_GEN_MASK);

	map_obj = zsb->z_group_map_objs[zp->z_group_id.master2_object%NASGROUP_MAP_NUM];
	if(map_obj != 0){
		err = zap_remove(zsb->z_os, map_obj, buf, tx);
	}

	bzero(buf, MAXNAMELEN);
	sprintf(buf, zfs_group_map_key_name_prefix_format, 
		zp->z_group_id.master3_spa, zp->z_group_id.master3_objset, zp->z_group_id.master3_object, 
		zp->z_group_id.master3_gen & ZFS_GROUP_GEN_MASK);
	map_obj = zsb->z_group_map_objs[zp->z_group_id.master3_object%NASGROUP_MAP_NUM];
	if(map_obj != 0){
		err = zap_remove(zsb->z_os, map_obj, buf, tx);
	}
	
	bzero(buf, MAXNAMELEN);
	sprintf(buf, zfs_group_map_key_name_prefix_format, 
		zp->z_group_id.master4_spa, zp->z_group_id.master4_objset, zp->z_group_id.master4_object, 
		zp->z_group_id.master4_gen & ZFS_GROUP_GEN_MASK);
	map_obj = zsb->z_group_map_objs[zp->z_group_id.master4_object%NASGROUP_MAP_NUM];
	if(map_obj != 0){
		err = zap_remove(zsb->z_os, map_obj, buf, tx);
	}

	mutex_exit(&zsb->z_lock);
	return err;
}

/*
*   Send Parent node's master2 (spa, os, obj) and current child znode's data (spa, os, obj) to Master2 host.
*   Then Master2 uses master2 (spa, os, obj) and name to create backup master node, and set data(spa, os, obj) into back master node.
*/

int zfs_client_create_backup(znode_t *pzp,	char *name, vattr_t *vap, vcexcl_t ex,
    int mode, znode_t *zp, cred_t *credp, int flag, caller_context_t *ct,
    vsecattr_t *vsap, zfs_multiclus_node_type_t m_node_type)
{
//	char *cp;
//	char *tmp_cp;
//	uint64_t cp_len;

	size_t namesize;
	size_t aclsize;
	size_t xvatsize;
	zfs_group_create_extra_t *create_extra;

	zfs_group_name_create_t create;
	zfs_group_znode_record_t *nrec;
	int error = 0;
	uint64_t update_node_info = 0;

	namesize = 0;
	aclsize = 0;
	xvatsize =0;
	create_extra = NULL;

	create_extra = zfs_group_get_create_extra(name, vap, vsap, &namesize, &xvatsize,
					    &aclsize, NULL, 0);
	create.name_len = namesize;
	create.xattr_len = xvatsize;
	create.acl_len = aclsize;
	create.ex = (int32_t)ex;
	create.mode = mode;
	create.flag = flag;
	if ((error = zfs_group_v_to_v32(vap, &create.vattr)) != 0) {
		kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
		kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
		return (error);
	}
	create.vattr.va_mask &= ~AT_SIZE;

	nrec = kmem_alloc(sizeof (zfs_group_znode_record_t), KM_SLEEP);

	error = zfs_group_proc_name_backup(pzp, NAME_CREATE, &create,
	    sizeof (create), create_extra->extra_createp,
	    create_extra->extra_create_plen, NULL, flag, credp, nrec, &zp->z_group_id, m_node_type);
	if (error == 0) {
		mutex_enter(&zp->z_lock);
		switch(m_node_type)
		{
			case ZFS_MULTICLUS_MASTER2:
				update_node_info = ZFS_UPDATE_FILE_NODE_MASTER2;
				zp->z_group_id.master2_spa = nrec->object_id.master2_spa;
				zp->z_group_id.master2_objset = nrec->object_id.master2_objset;
				zp->z_group_id.master2_object = nrec->object_id.master2_object;
				zp->z_group_id.master2_gen = nrec->object_id.master2_gen;
				if(nrec->object_id.master2_spa == 0 || nrec->object_id.master2_spa == 0xffffffffffffffff
					|| nrec->object_id.master2_objset == 0 || nrec->object_id.master2_objset == 0xffffffffffffffff
					|| nrec->object_id.master2_object == 0 || nrec->object_id.master2_object == 0xffffffffffffffff){
					cmn_err(CE_WARN, "[Error] master2 node is invalid master2_spa 0x%llx, master2_os 0x%llx, master2_obj 0x%llx",
						(unsigned long long)nrec->object_id.master2_spa, 
						(unsigned long long)nrec->object_id.master2_objset, 
						(unsigned long long)nrec->object_id.master2_object);
				}
				break;

			case ZFS_MULTICLUS_MASTER3:
				update_node_info = ZFS_UPDATE_FILE_NODE_MASTER3;
				zp->z_group_id.master3_spa = nrec->object_id.master3_spa;
				zp->z_group_id.master3_objset = nrec->object_id.master3_objset;
				zp->z_group_id.master3_object = nrec->object_id.master3_object;
				zp->z_group_id.master3_gen = nrec->object_id.master3_gen;
				if(nrec->object_id.master3_spa == 0 || nrec->object_id.master3_spa == 0xffffffffffffffff
					|| nrec->object_id.master3_objset == 0 || nrec->object_id.master3_objset == 0xffffffffffffffff
					|| nrec->object_id.master3_object == 0 || nrec->object_id.master3_object == 0xffffffffffffffff){
					cmn_err(CE_WARN, "[Error] master3 node is invalid master3_spa 0x%llx, master3_os 0x%llx, master3_obj 0x%llx",
						(unsigned long long)nrec->object_id.master3_spa, 
						(unsigned long long)nrec->object_id.master3_objset, 
						(unsigned long long)nrec->object_id.master3_object);
				}
				break;

			case ZFS_MULTICLUS_MASTER4:
				update_node_info = ZFS_UPDATE_FILE_NODE_MASTER4;
				zp->z_group_id.master4_spa = nrec->object_id.master4_spa;
				zp->z_group_id.master4_objset = nrec->object_id.master4_objset;
				zp->z_group_id.master4_object = nrec->object_id.master4_object;
				zp->z_group_id.master4_gen = nrec->object_id.master4_gen;
				if(nrec->object_id.master4_spa == 0 || nrec->object_id.master4_spa == 0xffffffffffffffff
					|| nrec->object_id.master4_objset == 0 || nrec->object_id.master4_objset == 0xffffffffffffffff
					|| nrec->object_id.master4_object == 0 || nrec->object_id.master4_object == 0xffffffffffffffff){
					cmn_err(CE_WARN, "[Error] master4 node is invalid master4_spa 0x%llx, master4_os 0x%llx, master4_obj 0x%llx",
						(unsigned long long)nrec->object_id.master4_spa, 
						(unsigned long long)nrec->object_id.master4_objset, 
						(unsigned long long)nrec->object_id.master4_object);
				}
				break;

			default:
				break;
		}
		mutex_exit(&zp->z_lock);
		if (update_master_obj_by_mx_group_id(zp, m_node_type) != 0) {
			cmn_err(CE_WARN, "[Error] %s, update_master_obj_by_mx_group_id failed! m_node_type: %d", 
				__func__, m_node_type);
		}
		
		/* send masterX info to data node and other Master node */
		if (zfs_client_notify_file_info(zp, m_node_type, update_node_info) != 0) {
			cmn_err(CE_WARN, "Failed to update master file node info, file is %s, m_node_type = %d",
					name, m_node_type);
		}
	}

	kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
	kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
	kmem_free(nrec, sizeof(zfs_group_znode_record_t));
	return (error);
}


int
zfs_client_lookup(struct inode *pip, char *cp, struct inode **ipp, 
	pathname_t *pnp, int flags, struct inode *rdir, cred_t *credp, 
	caller_context_t *ct, int *defp, struct pathname *rpnp)
{
	int error;
//	uint32_t hash;
	uint64_t cp_len;
	znode_t *pzp;
	znode_t *zp;
//	vnode_t *vp;
	zfs_group_znode_record_t *nrec;
	zfs_group_name_arg_t narg;

	bzero(&narg, sizeof(zfs_group_name_arg_t));

/*
	vp = dnlc_lookup(pvp, cp);
	if (vp != NULL) {
		dnlc_remove(pvp, cp);
		VN_RELE(vp);
	}
*/

	cp_len = (cp != NULL) ? strlen(cp) : 0;
	pzp = ITOZ(pip);
	nrec = kmem_zalloc(sizeof (zfs_group_znode_record_t), KM_SLEEP);
	narg.b_get_rpn = rpnp ? B_TRUE : B_FALSE;
	if ((error = zfs_group_proc_name(pzp, NAME_LOOKUP, &narg, sizeof(zfs_group_name_arg_t), 
		cp, cp_len, NULL, flags, credp, nrec)) == 0) {
		if (pzp->z_group_id.master_object != nrec->object_id.master_object) {
			zp = zfs_znode_alloc_by_group(ZTOZSB(pzp), nrec->object_blksz,
			    &nrec->object_id, &nrec->object_phy);
			*ipp = ZTOI(zp);
		} else {
			*ipp = ZTOI(pzp);
//			VN_HOLD(*vpp);
			igrab(*ipp);
			zp = pzp;
		}
		if (rpnp != NULL) {
			zfs_group_pathname_t *rpn = &nrec->rpn;
			(void) strlcpy(rpnp->pn_buf, rpn->pn_buf, rpnp->pn_bufsize);
		}

		zfs_group_acquire_znode_error(zp, &nrec->object_id,
		    &nrec->object_phy, "Group Lookup");
	} 
	kmem_free(nrec, sizeof (zfs_group_znode_record_t));
	return (error);
}

int zfs_client_remove(struct inode *pip, char *cp, 
	cred_t *credp, caller_context_t *ct, int flag)
{
	int error;
	int cp_len;
//	vnode_t *vp;
	zfs_group_znode_record_t *nrec;

	nrec = kmem_alloc(sizeof (zfs_group_znode_record_t), KM_SLEEP);

	cp_len = (cp != NULL) ? strlen(cp) : 0;
/*
	vp = dnlc_lookup(pvp, cp);
	if (vp != NULL) {
		dnlc_remove(pvp, cp);
		VN_RELE(vp);
	}
*/

	error = zfs_group_proc_name(ITOZ(pip), NAME_REMOVE, NULL, flag, cp, cp_len, NULL,
	    0, credp, nrec);

	zfs_fid_remove_master_info(ITOZSB(pip), nrec->object_id.master_spa, nrec->object_phy.zp_gen, NULL);
	kmem_free(nrec, sizeof(zfs_group_znode_record_t));
	return (error);
}


int zfs_client_remove_backup(znode_t *dzp,
    char *cp, cred_t *credp, caller_context_t *ct,
    int flag, zfs_multiclus_node_type_t m_node_type)
{
	int error;
	int cp_len;

	cp_len = (cp != NULL) ? strlen(cp) : 0;

	/* Because it is remove 'cp' under dzp, dzp->z_group_id is just a place holder here. */
	error = zfs_group_proc_name_backup(dzp, NAME_REMOVE, NULL, flag, cp, cp_len, NULL,
	    0, credp, NULL, &dzp->z_group_id, m_node_type);
	return (error);
}


uint64_t zfs_group_min_ios(zfs_multiclus_group_t *group,
    zfs_multiclus_group_record_t **recordpp)
{
	int i = 0;
	int tmp = 0;
	uint64_t min_ios;
	zfs_multiclus_group_record_t *group_recordp;
	static int lastidx = 0;

	min_ios = 0;
	group_recordp = NULL;
	for(i = lastidx; i < (lastidx + ZFS_MULTICLUS_GROUP_NODE_NUM); i++) {
		
		group_recordp = &group->multiclus_group[i%ZFS_MULTICLUS_GROUP_NODE_NUM];
		
		if (!group_recordp->used || group_recordp->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE)
			continue;

		if (min_ios == 0){
			tmp = i % ZFS_MULTICLUS_GROUP_NODE_NUM;
			min_ios = group_recordp->load_ios;
			*recordpp = group_recordp;
		}
		if (min_ios >= group_recordp->load_ios) {
			tmp = i % ZFS_MULTICLUS_GROUP_NODE_NUM;
			min_ios = group_recordp->load_ios;
			*recordpp = group_recordp;
		}
		
		/* After look up Reset  group->multiclus_group[i].load_ios, reset  group->multiclus_group[i].load_ios, let txg_sync() update it later. */
		group_recordp->load_ios = 0;
		
	}
	
	lastidx = tmp;
	return (min_ios);
}

uint64_t zfs_group_min_ios_condition(zfs_multiclus_group_t* group, zfs_multiclus_group_record_t** record,
	uint64_t group_id, uint64_t host_id, uint64_t spa_id, uint64_t os_id)
{
	zfs_multiclus_group_record_t* rec = NULL;
	uint64_t min_ios = (uint64_t)-1;
	int index = 0;

	*record = NULL;
	for (index = 0; index < ZFS_MULTICLUS_GROUP_NODE_NUM; ++index)
	{
		rec = &(group->multiclus_group[index]);
		if (!rec->used || rec->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE)
		{
			continue;
		}
		if (((rec->hostid - 1) / 2 + 1) == group_id || rec->hostid == host_id
			|| rec->spa_id == spa_id || rec->os_id == os_id)
		{
			continue;
		}

		if (min_ios >= rec->load_ios)
		{
			min_ios = rec->load_ios;
			*record = rec;
		}
	}

	return min_ios;
}

void zfs_group_max_avail(zfs_multiclus_group_t *group, uint64_t *min_index,
    uint64_t *max_index)
{
	int i = 0;
	int tmp_min_index;
	int tmp_max_index;
	uint64_t max_avail;
	uint64_t min_avail;
	zfs_multiclus_group_record_t *group_recordp;
	static int lastidx = 0;

	tmp_max_index = 0;
	max_avail = 0;
	tmp_min_index = 0;
	min_avail = 0;
	group_recordp = NULL;
	for(i = lastidx; i < (lastidx + ZFS_MULTICLUS_GROUP_NODE_NUM); i ++) {
		group_recordp = &group->multiclus_group[i%ZFS_MULTICLUS_GROUP_NODE_NUM];
		if (!group_recordp->used || group_recordp->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE)
			continue;
		if (max_avail == 0){
			max_avail = group_recordp->avail_size;
			tmp_max_index = i%ZFS_MULTICLUS_GROUP_NODE_NUM;
		}

		if (min_avail == 0){
			min_avail = group_recordp->avail_size;
			tmp_min_index = i%ZFS_MULTICLUS_GROUP_NODE_NUM;
		}
		if (max_avail < group_recordp->avail_size) {
			max_avail = group_recordp->avail_size;
			tmp_max_index = i%ZFS_MULTICLUS_GROUP_NODE_NUM;
		}

		if (min_avail > group_recordp->avail_size) {
			min_avail = group_recordp->avail_size;
			tmp_min_index = i%ZFS_MULTICLUS_GROUP_NODE_NUM;
		}
	}

	*min_index = tmp_min_index;
	*max_index = tmp_max_index;
	lastidx = (tmp_max_index + 1)%ZFS_MULTICLUS_GROUP_NODE_NUM;
}

uint64_t zfs_group_max_avail_condition(zfs_multiclus_group_t* group, zfs_multiclus_group_record_t** record,
	uint64_t group_id, uint64_t host_id, uint64_t spa_id, uint64_t os_id)
{
	zfs_multiclus_group_record_t* rec = NULL;
	uint64_t max_avail = 0;
	int index = 0;

	*record = NULL;
	for (index = 0; index < ZFS_MULTICLUS_GROUP_NODE_NUM; ++index)
	{
		rec = &(group->multiclus_group[index]);
		if (!rec->used || rec->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE)
		{
			continue;
		}
		if (((rec->hostid - 1) / 2 + 1) == group_id || rec->hostid == host_id
			|| rec->spa_id == spa_id || rec->os_id == os_id)
		{
			continue;
		}

		if (max_avail < rec->avail_size)
		{
			max_avail = rec->avail_size;
			*record = rec;
		}
	}

	return max_avail;
}

uint64_t debug_group_route = 0;
uint64_t debug_group_route2 = 1;
uint64_t debug_load_io = 0;


void zfs_group_route_data(zfs_sb_t *zsb, uint64_t orig_spa, uint64_t orig_os,
	uint64_t *dst_spa, uint64_t *dst_os, uint64_t *root_object, uint64_t* host_id)
{
	uint64_t max_avail_index = 0;
	uint64_t min_avail_index = 0;

	zfs_multiclus_group_record_t *min_io_group_recordp = NULL;
	zfs_multiclus_group_record_t *max_avail_group_recordp = NULL;
	zfs_multiclus_group_t *group = NULL;

	zfs_multiclus_group_record_t *org_grp_recordp = NULL;

	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "%s, %d, multiclus is disabled!", __func__, __LINE__);
		return;
	}

	zfs_multiclus_get_group(zsb->z_os->os_group_name, &group);
	VERIFY(group != NULL);

	org_grp_recordp = zfs_multiclus_get_record(orig_spa, orig_os);

	mutex_enter(&multiclus_mtx);
	mutex_enter(&group->multiclus_group_mutex);
	zfs_group_min_ios(group, &min_io_group_recordp);
	zfs_group_max_avail(group, &min_avail_index, &max_avail_index);
	max_avail_group_recordp = &group->multiclus_group[max_avail_index];

	if (!debug_group_route && org_grp_recordp != NULL
		&& org_grp_recordp->node_status.status != ZFS_MULTICLUS_NODE_OFFLINE) {
		if( org_grp_recordp != NULL && 
			org_grp_recordp->avail_size > ZFS_GROUP_ROUTE_MAX_AVAIL &&
			debug_group_route2 && org_grp_recordp->node_status.status != ZFS_MULTICLUS_NODE_OFFLINE){
			*dst_spa = orig_spa;
			*dst_os = orig_os;
			*root_object = org_grp_recordp->root;
			*host_id = org_grp_recordp->hostid;
		}else{
		
			/* If min_io_group_recordp->avail_size is larger than 75% of max_avail_group_recordp->avail_size
			* then select min_io_group_recordp at first. 
			*/
			if ( (max_avail_group_recordp->avail_size - min_io_group_recordp->avail_size) < 
			    (max_avail_group_recordp->avail_size >> 1)) {
				*dst_spa = min_io_group_recordp->spa_id;
				*dst_os = min_io_group_recordp->os_id;
				*root_object = min_io_group_recordp->root;
				*host_id = min_io_group_recordp->hostid;
			}else {
				*dst_spa = max_avail_group_recordp->spa_id;
				*dst_os = max_avail_group_recordp->os_id;
				*root_object = max_avail_group_recordp->root;
				*host_id = max_avail_group_recordp->hostid;
			}
		}
	} else {
		*dst_spa = orig_spa;
		*dst_os = orig_os;

		if (org_grp_recordp != NULL)
		{
			*root_object = org_grp_recordp->root;
			*host_id = org_grp_recordp->hostid;
		} else
		{
			*root_object = 0;
			*host_id = 0;
		}
	}

	mutex_exit(&group->multiclus_group_mutex);
	mutex_exit(&multiclus_mtx);
}

zfs_multiclus_group_record_t*
zfs_group_route_data2_helper(char* name, uint64_t orig_spa, uint64_t orig_os,
	uint64_t exclude_group, uint64_t exclude_host, uint64_t exclude_spa, uint64_t exclude_os)
{
	zfs_multiclus_group_t* group = NULL;
	zfs_multiclus_group_record_t* target = NULL;
	zfs_multiclus_group_record_t* min_io_rec = NULL;
	zfs_multiclus_group_record_t* max_avail_rec = NULL;

	target = zfs_multiclus_get_record(orig_spa, orig_os);
	if (target != NULL && target->node_status.status != ZFS_MULTICLUS_NODE_OFFLINE
		&& target->avail_size > ZFS_GROUP_ROUTE_MAX_AVAIL
		&& ((target->hostid - 1) / 2 + 1) != exclude_group && target->hostid != exclude_host
		&& target->spa_id != exclude_spa && target->os_id != exclude_os)
	{
		return target;
	}

	zfs_multiclus_get_group(name, &group);
	if (group == NULL)
	{
		return NULL;
	}

	mutex_enter(&multiclus_mtx);
	mutex_enter(&group->multiclus_group_mutex);

	zfs_group_min_ios_condition(group, &min_io_rec, exclude_group, exclude_host, exclude_spa, exclude_os);
	if (min_io_rec == NULL)
	{
		mutex_exit(&group->multiclus_group_mutex);
		mutex_exit(&multiclus_mtx);
		return NULL;
	}

	zfs_group_max_avail_condition(group, &max_avail_rec, exclude_group, exclude_host, exclude_spa, exclude_os);
	if (max_avail_rec == NULL)
	{
		mutex_exit(&group->multiclus_group_mutex);
		mutex_exit(&multiclus_mtx);
		return NULL;
	}

	if ((max_avail_rec->avail_size - min_io_rec->avail_size) < (max_avail_rec->avail_size >> 1))
    {
    	target = min_io_rec;
	} else
	{
		target = max_avail_rec;
	}

	mutex_exit(&group->multiclus_group_mutex);
	mutex_exit(&multiclus_mtx);

	return target;
}


void zfs_group_route_data2(zfs_sb_t *zsb, uint64_t orig_spa, uint64_t orig_os,
	uint64_t *dst_spa, uint64_t *dst_os, uint64_t *root_object, uint64_t* host_id,
	uint64_t exclude_spa, uint64_t exclude_os)
{
	zfs_multiclus_group_record_t* dst = NULL;

	/* try to get the best record in a different group (but in the same cluster group) */
	dst = zfs_group_route_data2_helper(zsb->z_os->os_group_name, orig_spa, orig_os,
			(*host_id - 1) / 2 + 1, 0, 0, 0);
	if (dst != NULL)
	{
		*dst_spa = dst->spa_id;
		*dst_os = dst->os_id;
		*root_object = dst->root;
		*host_id = dst->hostid;

		return;
	}

	/* 
	 * there is only one group in this cluster,
	 * try to get the best record in a different host
	 */
	dst = zfs_group_route_data2_helper(zsb->z_os->os_group_name, orig_spa, orig_os,
			0, *host_id, 0, 0);
	if (dst != NULL)
	{
		*dst_spa = dst->spa_id;
		*dst_os = dst->os_id;
		*root_object = dst->root;
		*host_id = dst->hostid;

		return;
	}

	/* 
	 * there is only one group and one host in this cluster,
	 * try to get the best record in a different pool
	 */
	dst = zfs_group_route_data2_helper(zsb->z_os->os_group_name, orig_spa, orig_os,
			0, 0, exclude_spa, 0);
	if (dst != NULL)
	{
		*dst_spa = dst->spa_id;
		*dst_os = dst->os_id;
		*root_object = dst->root;
		*host_id = dst->hostid;
	
		return;
	}

	/* 
	 * there is only one pool in this cluster,
	 * try to get the best record in a different zfs file system
	 */
	dst = zfs_group_route_data2_helper(zsb->z_os->os_group_name, orig_spa, orig_os,
			0, 0, 0, exclude_os);
	if (dst != NULL)
	{
		*dst_spa = dst->spa_id;
		*dst_os = dst->os_id;
		*root_object = dst->root;
		*host_id = dst->hostid;
	
		return;
	}

	/*
	 * there is only one zfs file system in this cluster.
	 *
	 * either we save these 2 copies of data files in the same zfs file system,
	 * or we just save one copy of the data file
	 */
	*dst_spa = 0;
	*dst_os = 0;
	*root_object = 0;
	*host_id = 0;

	return;
}

int zfs_group_create_data_file(znode_t *zp, char *name, boolean_t bregual,
	vsecattr_t *vsecp, vattr_t *vap, vcexcl_t ex, int mode, int flag,
	uint64_t orig_spa, uint64_t orig_os, uint64_t* dirlowdata, uint64_t* host_id, dmu_tx_t *tx)
{
	int err = 0;
	size_t request_length = 0;
	size_t reply_length = 0;
	char new_name[MAXNAMELEN];
	size_t namesize = 0;
	size_t aclsize = 0;
	size_t xvatsize = 0;
	size_t dirlowdatasize = 0;
	zfs_group_create_extra_t *create_extra = NULL;
	zfs_sb_t *zsb = NULL;
	uint64_t master_spa = 0;
	uint64_t master_os = 0;
	uint64_t master_object = 0;
	uint64_t dst_spa = 0;
	uint64_t dst_os = 0;
	uint64_t dst_root_object = 0;
	zfs_group_name_create_t *createp = NULL;
	zfs_group_name_t *np = NULL;
	zfs_group_name2_t *n2p = NULL;
	zfs_group_header_t *msg_header = NULL;
	zfs_group_name_msg_t *data_msg = NULL;
	zfs_group_object_t group_object = {0};
	dmu_tx_t *ptx = tx;

	zsb = ZTOZSB(zp);
	bzero(&group_object, sizeof(zfs_group_object_t));
	master_object = zp->z_id;
	master_spa = spa_guid(dmu_objset_spa(zsb->z_os));
	master_os = dmu_objset_id(zsb->z_os);

	group_object.master_spa = master_spa;
	group_object.master_objset = master_os;
	group_object.master_object = master_object;
	group_object.master_gen = zp->z_gen;

	if (bregual) {
		zfs_group_route_data(zsb, orig_spa, orig_os,
		    &dst_spa, &dst_os,&dst_root_object, host_id);
	} else {
		dst_spa = master_spa;
		dst_os = master_os;
	}

	if(dst_spa == 0 && dst_os == 0){
		cmn_err(CE_WARN, "[corrupt group object] %s %s %d", __FILE__, __func__, __LINE__);
	}

	if (dst_spa == master_spa && dst_os == master_os) {
		group_object.data_spa = master_spa;
		group_object.data_objset = master_os;
		group_object.data_object = master_object;
		err = 0;
	} else {
		data_msg = kmem_zalloc(sizeof(zfs_group_name_msg_t), KM_SLEEP);
		msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
		createp = &data_msg->call.name.arg.p.create;

		sprintf(new_name, DATA_OBJECT_NAME, (longlong_t)master_object, name);
		create_extra = zfs_group_get_create_extra(new_name, vap, vsecp,
						    &namesize, &xvatsize, &aclsize, dirlowdata, &dirlowdatasize);

		createp->name_len = namesize;
		createp->xattr_len = xvatsize;
		createp->acl_len = aclsize;
		createp->dirlowdata_len = dirlowdatasize;
		createp->master_object = master_object;
		createp->master_gen = zp->z_gen;
		createp->ex = (int32_t)ex;
		createp->mode = mode;
		createp->flag = flag;
		if ((err = zfs_group_v_to_v32(vap, &createp->vattr)) != 0) {
			kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
			kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
			kmem_free(msg_header, sizeof(zfs_group_header_t));
			kmem_free(data_msg, sizeof(zfs_group_name_msg_t));
			return (err);
		}
		createp->vattr.va_mask &= ~AT_SIZE;

		np = (zfs_group_name_t *)&data_msg->call.name;
		np->parent_object.data_spa = dst_spa;
		np->parent_object.data_objset = dst_os;
		np->parent_object.data_object = dst_root_object;

		bcopy((void *)create_extra->extra_createp,
		    np->component, create_extra->extra_create_plen);

		request_length = offsetof(zfs_group_name_t, component) +
		    create_extra->extra_create_plen + 1;
		reply_length = sizeof(zfs_group_name2_t);

		zfs_group_build_header(zsb->z_os, msg_header, ZFS_GROUP_CMD_NAME,
		    SHARE_WAIT, NAME_CREATE, request_length, reply_length,
		    dst_spa, dst_os, 0, master_object,
		    dst_spa, dst_os, 0, MSG_REQUEST, APP_GROUP);

		err = zfs_client_send_to_server(zsb->z_os, msg_header, (zfs_msg_t *)data_msg, B_TRUE);
		if (err == 0) {
			n2p = (zfs_group_name2_t *)&data_msg->call.name2;
			if(n2p->nrec.object_id.master_spa == 0 && n2p->nrec.object_id.master_objset == 0
				&& n2p->nrec.object_id.master_object == 0 && n2p->nrec.object_id.data_spa == 0
				&& n2p->nrec.object_id.data_objset == 0 && n2p->nrec.object_id.data_object == 0){
					cmn_err(CE_WARN, "[corrupt group object] %s %s %d", __FILE__, __func__, __LINE__);
			}
			group_object.data_spa = n2p->nrec.object_id.data_spa;
			group_object.data_objset = n2p->nrec.object_id.data_objset;
			group_object.data_object = n2p->nrec.object_id.data_object;
			if (group_object.data_spa == 0 ||
				group_object.data_objset == 0 ||
				group_object.data_object == 0) {
				cmn_err(CE_WARN, "%s line(%d) spa=%"PRIx64" objset=%"PRIx64" object=%"PRIx64"\n", 
					__func__, __LINE__, 
					group_object.data_spa, group_object.data_objset, group_object.data_object);
			}
		}

		kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
		kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
		kmem_free(msg_header, sizeof(zfs_group_header_t));
		kmem_free(data_msg, sizeof(zfs_group_name_msg_t));
	}

	if (err == 0) {
		if (NULL == tx) {
			ptx = dmu_tx_create(zsb->z_os);
			dmu_tx_hold_sa(ptx, zp->z_sa_hdl, B_FALSE);
			err = dmu_tx_assign(ptx, TXG_WAIT);
			if( err){
				dmu_tx_abort(ptx);
				return err;
			}
		}
		mutex_enter(&zp->z_lock);

		/* This is the first time to create a file, initialize master2 stuff as 0xff...ff. */
		group_object.master2_spa = 0xffffffffffffffff;
		group_object.master2_objset = 0xffffffffffffffff;
		group_object.master2_object = 0xffffffffffffffff;
		group_object.master2_gen = 0;

		/* This is the first time to create a file, initialize master3 stuff as 0xff...ff. */
		group_object.master3_spa = 0xffffffffffffffff;
		group_object.master3_objset = 0xffffffffffffffff;
		group_object.master3_object = 0xffffffffffffffff;
		group_object.master3_gen = 0;

		/* This is the first time to create a file, initialize master4 stuff as 0xff...ff. */
		group_object.master4_spa = 0xffffffffffffffff;
		group_object.master4_objset = 0xffffffffffffffff;
		group_object.master4_object = 0xffffffffffffffff;
		group_object.master4_gen = 0;
		
		zfs_sa_set_remote_object(zp, &group_object, ptx);
		mutex_exit(&zp->z_lock);
		if(zp->z_group_id.master_spa == 0 && zp->z_group_id.master_objset == 0
			&& zp->z_group_id.master_object == 0 && zp->z_group_id.data_spa == 0
			&& zp->z_group_id.data_objset == 0 && zp->z_group_id.data_object == 0){
			cmn_err(CE_WARN, "[corrupt group object] %s %s %d", __FILE__, __func__, __LINE__);
		}
		if (tx == NULL) {
			dmu_tx_commit(ptx);
		}
	}
	return (err);
}

int zfs_group_create_data2_file(znode_t *zp, char *name, boolean_t bregual,
	vsecattr_t *vsecp, vattr_t *vap, vcexcl_t ex, int mode, int flag,
	uint64_t orig_spa, uint64_t orig_os, uint64_t* dirlowdata, uint64_t* host_id, dmu_tx_t *tx)
{
	int err = 0;
	size_t request_length = 0;
	size_t reply_length = 0;
	char new_name[MAXNAMELEN];
	size_t namesize = 0;
	size_t aclsize = 0;
	size_t xvatsize = 0;
	size_t dirlowdatasize = 0;
	zfs_group_create_extra_t *create_extra = NULL;
	zfs_sb_t *zsb = NULL;
	uint64_t master_spa = 0;
	uint64_t master_os = 0;
	uint64_t master_object = 0;
	uint64_t dst_spa = 0;
	uint64_t dst_os = 0;
	uint64_t dst_root_object = 0;
	zfs_group_name_create_t *createp = NULL;
	zfs_group_name_t *np = NULL;
	zfs_group_name2_t *n2p = NULL;
	zfs_group_header_t *msg_header = NULL;
	zfs_group_name_msg_t *data_msg = NULL;
	zfs_group_object_t group_object = { 0 };
	dmu_tx_t *ptx = tx;;

	
	/* only support regular file */
	if (!bregual)
	{
		return 0;
	}

	zsb = ZTOZSB(zp);
	master_object = zp->z_id;
	master_spa = spa_guid(dmu_objset_spa(zsb->z_os));
	master_os = dmu_objset_id(zsb->z_os);

	/*
	 * get original info from zp, but must reset master_spa, master_objset
	 * and master_object, as these 3 fields may be 0 if it failed to create
	 * the data1 file
	 */
	group_object = zp->z_group_id;
	group_object.master_spa = master_spa;
	group_object.master_objset = master_os;
	group_object.master_object = master_object;
	group_object.master_gen = zp->z_gen;

	zfs_group_route_data2(zsb, orig_spa, orig_os, &dst_spa, &dst_os, &dst_root_object,
		host_id, zp->z_group_id.data_spa, zp->z_group_id.data_objset);
	if (dst_spa == 0 && dst_os == 0) {
		/*
		 * there is only one file system in the cluster,
		 * just save one copy of the data file
		 */
		cmn_err(CE_WARN, "[Error] failed to get data2 host for file %s", name);
		return 0;
	}

	if (dst_spa == master_spa && dst_os == master_os) {
		/*
		 * genereate info for data2 node
		 */
		group_object.data2_spa = master_spa;
		group_object.data2_objset = master_os;
		group_object.data2_object = master_object;
		err = 0;
	} else {
		data_msg = kmem_zalloc(sizeof(zfs_group_name_msg_t), KM_SLEEP);
		msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
		createp = &data_msg->call.name.arg.p.create;

		sprintf(new_name, DATA_OBJECT_NAME, (longlong_t)master_object, name);
		create_extra = zfs_group_get_create_extra(new_name, vap, vsecp,
						    &namesize, &xvatsize, &aclsize, dirlowdata, &dirlowdatasize);

		createp->name_len = namesize;
		createp->xattr_len = xvatsize;
		createp->acl_len = aclsize;
		createp->dirlowdata_len = dirlowdatasize;
		createp->master_object = master_object;
		createp->master_gen = zp->z_gen;
		createp->ex = (int32_t)ex;
		createp->mode = mode;
		createp->flag = flag;
		if ((err = zfs_group_v_to_v32(vap, &createp->vattr)) != 0) {
			kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
			kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
			kmem_free(msg_header, sizeof(zfs_group_header_t));
			kmem_free(data_msg, sizeof(zfs_group_name_msg_t));
			return (err);
		}
		createp->vattr.va_mask &= ~AT_SIZE;

		np = (zfs_group_name_t *)&data_msg->call.name;
		np->parent_object.data_spa = dst_spa;
		np->parent_object.data_objset = dst_os;
		np->parent_object.data_object = dst_root_object;

		bcopy((void *)create_extra->extra_createp, np->component, create_extra->extra_create_plen);
		request_length = offsetof(zfs_group_name_t, component) + create_extra->extra_create_plen + 1;
		reply_length = sizeof(zfs_group_name2_t);

		zfs_group_build_header(zsb->z_os, msg_header, ZFS_GROUP_CMD_NAME,
		    SHARE_WAIT, NAME_CREATE, request_length, reply_length,
		    dst_spa, dst_os, 0, master_object,
		    dst_spa, dst_os, 0, MSG_REQUEST, APP_GROUP);

		err = zfs_client_send_to_server(zsb->z_os, msg_header, (zfs_msg_t *)data_msg, B_TRUE);

		if (err == 0) {
			n2p = (zfs_group_name2_t *)&data_msg->call.name2;
			if(n2p->nrec.object_id.master_spa == 0 && n2p->nrec.object_id.master_objset == 0
				&& n2p->nrec.object_id.master_object == 0 && n2p->nrec.object_id.data_spa == 0
				&& n2p->nrec.object_id.data_objset == 0 && n2p->nrec.object_id.data_object == 0){
					cmn_err(CE_WARN, "[corrupt group object] %s %s %d", __FILE__, __func__, __LINE__);
			}

			/*
			 * genereate info for data2 node
			 */
			group_object.data2_spa = n2p->nrec.object_id.data_spa;
			group_object.data2_objset = n2p->nrec.object_id.data_objset;
			group_object.data2_object = n2p->nrec.object_id.data_object;
		}

		kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
		kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
		kmem_free(msg_header, sizeof(zfs_group_header_t));
		kmem_free(data_msg, sizeof(zfs_group_name_msg_t));
	}

	if (err == 0) {
		if (NULL == tx) {
			ptx = dmu_tx_create(zsb->z_os);
			dmu_tx_hold_sa(ptx, zp->z_sa_hdl, B_FALSE);
			err = dmu_tx_assign(ptx, TXG_WAIT);
			if (err){
				dmu_tx_abort(ptx);
				return err;
			}
		}

		mutex_enter(&zp->z_lock);
		zfs_sa_set_remote_object(zp, &group_object, ptx);
		mutex_exit(&zp->z_lock);

		if (zp->z_group_id.master_spa == 0 && zp->z_group_id.master_objset == 0
			&& zp->z_group_id.master_object == 0 && zp->z_group_id.data2_spa == 0
			&& zp->z_group_id.data2_objset == 0 && zp->z_group_id.data2_object == 0){
			cmn_err(CE_WARN, "[corrupt group object] %s %s %d", __FILE__, __func__, __LINE__);
		}

		if (tx == NULL) {
			dmu_tx_commit(ptx);
		}
	}

	return (err);
}


int zfs_remove_data_file(struct inode *pip, znode_t* zp, char *cp, cred_t *credp, 
	caller_context_t *ct, int flag)
{
	char new_name[MAXNAMELEN] = { 0 };
	int err = 0;

	if (zp->z_group_id.data_spa == 0 || zp->z_group_id.data_objset == 0) {
		return 0;
	}

	if (!zfs_group_znode_data_is_master(zp) && (zp->z_links <= 1)) {
		sprintf(new_name, DATA_OBJECT_NAME, (longlong_t)zp->z_id, cp);
		err = zfs_group_proc_name(zp, NAME_REMOVE_DATA, NULL, 0, new_name,
		    strlen(new_name), NULL, flag, credp, NULL);
	}


	return (err == ENOENT || err == EGHOLD) ? 0 : err;
}



int zfs_remove_data2_file(struct inode *pip, znode_t* zp, char* cp, cred_t* credp, 
	caller_context_t* ct, int flag)
{
	zfs_group_object_t id = { 0 };
	char new_name[MAXNAMELEN] = { 0 };
	int err = 0;

	if (zp->z_group_id.data2_spa == 0 || zp->z_group_id.data2_objset == 0) {
		return 0;
	}

	if (!zfs_group_znode_data2_is_master(zp) && (zp->z_links <= 1)) {
		id = zp->z_group_id;
		zp->z_group_id.data_spa = zp->z_group_id.data2_spa;
		zp->z_group_id.data_objset = zp->z_group_id.data2_objset;
		zp->z_group_id.data_object = zp->z_group_id.data2_object;

		sprintf(new_name, DATA_OBJECT_NAME, (longlong_t)zp->z_id, cp);
		err = zfs_group_proc_name(zp, NAME_REMOVE_DATA, NULL, 0, new_name,
			strlen(new_name), NULL, flag, credp, NULL);

		zp->z_group_id = id;
	}


	return (err == ENOENT || err == EGHOLD) ? 0 : err;
}



int zfs_client_mkdir(struct inode *pip, char *cp, vattr_t *vap, struct inode **ipp,	
    cred_t *credp, caller_context_t *ct, int flag, vsecattr_t *vsap)
{
//	int cp_len;
	znode_t *pzp;
	znode_t *zp;

	size_t namesize;
	size_t aclsize;
	size_t xvatsize;
	zfs_group_create_extra_t *create_extra;

//	zfs_group_name_attr_t *zg_attr;
//	zfs_group_name_acl_t *zg_acl;

	zfs_group_name_mkdir_t mkdir;
	zfs_group_znode_record_t *nrec;

	int error;

	namesize = 0;
	aclsize = 0;
	xvatsize =0;
	create_extra = NULL;
/*
	vp = dnlc_lookup(pvp, cp);
	if (vp != NULL) {
		dnlc_remove(pvp, cp);
		VN_RELE(vp);
	}
*/
	create_extra = zfs_group_get_create_extra(cp, vap, vsap, &namesize, &xvatsize,
					    &aclsize, NULL, 0);
	mkdir.name_len = namesize;
	mkdir.xattr_len = xvatsize;
	mkdir.acl_len = aclsize;

	pzp = ITOZ(pip);
	if ((error = zfs_group_v_to_v32(vap, &mkdir.vattr)) != 0) {
		kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
		kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
		return (error);
	}
	nrec = kmem_alloc(sizeof (zfs_group_znode_record_t), KM_SLEEP);
	if ((error = zfs_group_proc_name(ITOZ(pip), NAME_MKDIR, &mkdir,
		sizeof (mkdir), create_extra->extra_createp, create_extra->extra_create_plen,
		    NULL, flag, credp, nrec)) == 0) {
		zp = zfs_znode_alloc_by_group(ZTOZSB(pzp), nrec->object_blksz,
		    &nrec->object_id, &nrec->object_phy);
		*ipp = ZTOI(zp);
	}

	kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
	kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
	kmem_free(nrec, sizeof (*nrec));
	if (error) {
		*ipp = NULL;
	}

	return (error);
}

int zfs_client_mkdir_backup(znode_t *pzp, char *cp, vattr_t *vap, znode_t *zp,	
    cred_t *credp, caller_context_t *ct, int flag, vsecattr_t *vsap, zfs_multiclus_node_type_t m_node_type)
{
//	int cp_len;

	size_t namesize;
	size_t aclsize;
	size_t xvatsize;
	zfs_group_create_extra_t *create_extra;

//	zfs_group_name_attr_t *zg_attr;
//	zfs_group_name_acl_t *zg_acl;

	zfs_group_name_mkdir_t mkdir;
	zfs_group_znode_record_t *nrec;

	int error;
	uint64_t update_node_info = 0;

	namesize = 0;
	aclsize = 0;
	xvatsize =0;
	create_extra = NULL;

	create_extra = zfs_group_get_create_extra(cp, vap, vsap, &namesize, &xvatsize,
					    &aclsize, NULL, 0);
	mkdir.name_len = namesize;
	mkdir.xattr_len = xvatsize;
	mkdir.acl_len = aclsize;

	if ((error = zfs_group_v_to_v32(vap, &mkdir.vattr)) != 0) {
		kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
		kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
		return (error);
	}
	nrec = kmem_alloc(sizeof (zfs_group_znode_record_t), KM_SLEEP);
	if ((error = zfs_group_proc_name_backup(pzp, NAME_MKDIR, &mkdir,
		sizeof (mkdir), create_extra->extra_createp, create_extra->extra_create_plen,
		    NULL, flag, credp, nrec, &zp->z_group_id, m_node_type)) == 0) {
		mutex_enter(&zp->z_lock);
		switch(m_node_type)
		{
			case ZFS_MULTICLUS_MASTER2:

				update_node_info = ZFS_UPDATE_FILE_NODE_MASTER2;
				zp->z_group_id.master2_spa = nrec->object_id.master2_spa;
				zp->z_group_id.master2_objset = nrec->object_id.master2_objset;
				zp->z_group_id.master2_object = nrec->object_id.master2_object;
				zp->z_group_id.master2_gen = nrec->object_id.master2_gen;

				if(nrec->object_id.master2_spa == 0 || nrec->object_id.master2_spa == 0xffffffffffffffff
					|| nrec->object_id.master2_objset == 0 || nrec->object_id.master2_objset == 0xffffffffffffffff
					|| nrec->object_id.master2_object == 0 || nrec->object_id.master2_object == 0xffffffffffffffff){
					cmn_err(CE_WARN, "[Error] master2 node is invalid master2_spa 0x%llx, master2_os 0x%llx, master2_obj 0x%llx",
						(unsigned long long)nrec->object_id.master2_spa, 
						(unsigned long long)nrec->object_id.master2_objset, 
						(unsigned long long)nrec->object_id.master2_object);
				}

				break;

			case ZFS_MULTICLUS_MASTER3:

				update_node_info = ZFS_UPDATE_FILE_NODE_MASTER3;
				zp->z_group_id.master3_spa = nrec->object_id.master3_spa;
				zp->z_group_id.master3_objset = nrec->object_id.master3_objset;
				zp->z_group_id.master3_object = nrec->object_id.master3_object;
				zp->z_group_id.master3_gen = nrec->object_id.master3_gen;

				if(nrec->object_id.master3_spa == 0 || nrec->object_id.master3_spa == 0xffffffffffffffff
					|| nrec->object_id.master3_objset == 0 || nrec->object_id.master3_objset == 0xffffffffffffffff
					|| nrec->object_id.master3_object == 0 || nrec->object_id.master3_object == 0xffffffffffffffff){
					cmn_err(CE_WARN, "[Error] master3 node is invalid master3_spa 0x%llx, master3_os 0x%llx, master3_obj 0x%llx",
						(unsigned long long)nrec->object_id.master3_spa, 
						(unsigned long long)nrec->object_id.master3_objset, 
						(unsigned long long)nrec->object_id.master3_object);
				}

				break;

			case ZFS_MULTICLUS_MASTER4:

				update_node_info = ZFS_UPDATE_FILE_NODE_MASTER4;
				zp->z_group_id.master4_spa = nrec->object_id.master4_spa;
				zp->z_group_id.master4_objset = nrec->object_id.master4_objset;
				zp->z_group_id.master4_object = nrec->object_id.master4_object;
				zp->z_group_id.master4_gen = nrec->object_id.master4_gen;

				if(nrec->object_id.master4_spa == 0 || nrec->object_id.master4_spa == 0xffffffffffffffff
					|| nrec->object_id.master4_objset == 0 || nrec->object_id.master4_objset == 0xffffffffffffffff
					|| nrec->object_id.master4_object == 0 || nrec->object_id.master4_object == 0xffffffffffffffff){
					cmn_err(CE_WARN, "[Error] master4 node is invalid master4_spa 0x%llx, master4_os 0x%llx, master4_obj 0x%llx",
						(unsigned long long)nrec->object_id.master4_spa, 
						(unsigned long long)nrec->object_id.master4_objset, 
						(unsigned long long)nrec->object_id.master4_object);
				}

				break;
			default:
				mutex_exit(&zp->z_lock);
				error = EINVAL;
				goto OUT;	
		}
		
		mutex_exit(&zp->z_lock);
		if (update_master_obj_by_mx_group_id(zp, m_node_type) != 0) {
			cmn_err(CE_WARN, "[Error] %s, update_master_obj_by_mx_group_id failed! m_node_type: %d", 
				__func__, m_node_type);
		}
		/* send masterX info to data node and other Master node */
		if (zfs_client_notify_file_info(zp, m_node_type, update_node_info) != 0) {
			cmn_err(CE_WARN, "[Error] Failed to update master dir node info, dir is %s, m_node_type = %d",
					cp, m_node_type);
		}
	}
OUT:
	kmem_free(create_extra->extra_createp, create_extra->extra_create_plen);
	kmem_free(create_extra, sizeof(zfs_group_create_extra_t));
	kmem_free(nrec, sizeof (*nrec));
	
	return (error);
}


int zfs_client_rmdir(struct inode *pip, char *cp, struct inode *cdir, cred_t *credp,
    caller_context_t *ct, int flag)
{
	int cp_len;
	int error;
//	vnode_t *vp;
	zfs_group_znode_record_t *nrec;

	nrec = kmem_alloc(sizeof (zfs_group_znode_record_t), KM_SLEEP);

	cp_len = (cp != NULL) ? strlen(cp) : 0;

/*
	vp = dnlc_lookup(pvp, cp);
	if (vp != NULL) {
		dnlc_remove(pvp, cp);
		VN_RELE(vp);
	}
*/


	error = zfs_group_proc_name(ITOZ(pip), NAME_RMDIR, NULL, flag, cp, cp_len, NULL,
	    0, credp, nrec);


	zfs_fid_remove_master_info(ITOZSB(pip), nrec->object_id.master_spa, nrec->object_phy.zp_gen, NULL);

	kmem_free(nrec, sizeof(zfs_group_znode_record_t));
	return (error);
}

int zfs_client_rmdir_backup(znode_t *dzp, char *cp, struct inode *cdir, cred_t *credp,
    caller_context_t *ct, int flag, zfs_multiclus_node_type_t m_node_type)
{
	int cp_len;
	int error;

	cp_len = (cp != NULL) ? strlen(cp) : 0;

	/* Because it is remove 'cp' under dzp, dzp->z_group_id is just a place holder here. */
	error = zfs_group_proc_name_backup(dzp, NAME_RMDIR, NULL, flag, cp, cp_len, NULL,
	    0, credp, NULL, &dzp->z_group_id, m_node_type); 
	return (error);
}

int
zfs_client_xattr_list(struct inode *ip, void *buffer, size_t buffer_size, cred_t *cr)
{
	int error;
	znode_t *zp = ITOZ(ip);

	struct uio auio;
	struct iovec aiov;

	bzero(&auio, sizeof(struct uio));
	bzero(&aiov, sizeof(struct iovec));
	aiov.iov_base = buffer ;
	aiov.iov_len = buffer_size ;
	auio.uio_iov = &aiov ;
	auio.uio_iovcnt = 1;
	auio.uio_skip = 0 ;
	auio.uio_loffset = 0 ;
	auio.uio_segflg = UIO_SYSSPACE ;
	auio.uio_resid = buffer_size ;
	auio.uio_fmode = 0 ;
	auio.uio_extflg = UIO_COPY_CACHED ;

	error = zfs_client_read_data(zp->z_zsb, zp, &auio, buffer_size, XATTR_LIST, cr, 0, DATA_TO_MASTER, NULL);

	if( error < 0 )
		return (error) ;
	else
		return auio.uio_loffset ;
}

int		
zfs_client_readdir(struct inode *ip, struct dir_context *ctx, cred_t *cr, int flag)
{
	int error;
	size_t nbytes; 
	znode_t *zp = ITOZ(ip); 	

	void *buf = NULL;
	struct uio auio;
	struct iovec aiov;
	int eof = -1;

	size_t dbuflen;
	struct linux_dirent64 *dp = NULL;
	int		done = 0;

	bzero(&auio, sizeof(struct uio));
	bzero(&aiov, sizeof(struct iovec));
	aiov.iov_base = vmem_zalloc(zfs_group_max_dir_read_size, KM_NOSLEEP);
	aiov.iov_len = zfs_group_max_dir_read_size;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_skip = 0;
	auio.uio_loffset = ctx->pos;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_resid = zfs_group_max_dir_read_size;
	auio.uio_fmode = 0; 
	auio.uio_extflg = UIO_COPY_CACHED;
	
	nbytes = zfs_group_max_dir_read_size;

	error = zfs_client_read_data(ZTOZSB(zp), zp, &auio, nbytes, DIR_READ,
		   cr, flag, DATA_TO_MASTER, &eof);
	if (error != 0)
		goto out;

	dbuflen = nbytes - auio.uio_resid;
	for (dp = (struct linux_dirent64 *)aiov.iov_base;
		    (intptr_t)dp < (intptr_t)aiov.iov_base + dbuflen;
		    dp = (struct linux_dirent64 *)((intptr_t)dp + dp->d_reclen)){
		done = !dir_emit(ctx, dp->d_name, strlen(dp->d_name), dp->d_ino, dp->d_type);
		if (done)
			break;
		ctx->pos = (loff_t)dp->d_off;
	}
#if 0
	error = zfs_client_read_data(zp->z_zfsvfs, zp, uiop, DIR_READ,
	    credp, flag, DATA_TO_MASTER, eofp);
#endif
out:
	vmem_free(aiov.iov_base, zfs_group_max_dir_read_size);
	return (error);
}


int	zfs_client_symlink(struct inode *pip, char *cp, vattr_t *vap, char *tnm, 
	struct inode **ipp,	cred_t *credp, int flag)
{
	int error;
	int cp_len;
	zfs_group_name_symlink_t symlink;
	zfs_group_znode_record_t *nrec;
	znode_t *pzp = ITOZ(pip);
	znode_t *zp = NULL;

	*ipp = NULL;
	cp_len = (cp != NULL) ? strlen(cp) : 0;
	if ((error = zfs_group_v_to_v32(vap, &symlink.vattr)) != 0)
		return (error);
	symlink.comp_size = strlen(cp);
	symlink.path_size = strlen(tnm);
	nrec = kmem_zalloc(sizeof (*nrec), KM_SLEEP);

	error = zfs_group_proc_name(pzp, NAME_SYMLINK,
	    &symlink, sizeof (symlink), cp, cp_len, tnm, flag, credp, nrec);
	if (error == 0) {
		zp = zfs_znode_alloc_by_group(ZTOZSB(pzp), nrec->object_blksz,
		    &nrec->object_id, &nrec->object_phy);
		*ipp = ZTOI(zp);
	}
	kmem_free(nrec, sizeof (*nrec));
	return (error);
}


int	zfs_client_symlink_backup(
	znode_t *dzp, char *cp, vattr_t *vap, znode_t *zp, char *tnm,		
	cred_t *credp, caller_context_t *ct,int flag, zfs_multiclus_node_type_t m_node_type)
{
	int error;
	int cp_len;
	zfs_group_name_symlink_t symlink;
	zfs_group_znode_record_t *nrec;
	uint64_t update_node_info = 0;

	cp_len = (cp != NULL) ? strlen(cp) : 0;
	if ((error = zfs_group_v_to_v32(vap, &symlink.vattr)) != 0)
		return (error);
	symlink.comp_size = strlen(cp);
	symlink.path_size = strlen(tnm);
	nrec = kmem_alloc(sizeof (*nrec), KM_SLEEP);
	error = zfs_group_proc_name_backup(dzp, NAME_SYMLINK,
	    &symlink, sizeof (symlink), cp, cp_len, tnm, flag, credp, nrec, &zp->z_group_id, m_node_type);
	if (error == 0) {
		mutex_enter(&zp->z_lock);
		switch(m_node_type)
		{
			case ZFS_MULTICLUS_MASTER2:
				update_node_info = ZFS_UPDATE_FILE_NODE_MASTER2;
				zp->z_group_id.master2_spa = nrec->object_id.master2_spa;
				zp->z_group_id.master2_objset = nrec->object_id.master2_objset;
				zp->z_group_id.master2_object = nrec->object_id.master2_object;
				zp->z_group_id.master2_gen = nrec->object_id.master2_gen;
				break;
			case ZFS_MULTICLUS_MASTER3:
				update_node_info = ZFS_UPDATE_FILE_NODE_MASTER3;
				zp->z_group_id.master3_spa = nrec->object_id.master3_spa;
				zp->z_group_id.master3_objset = nrec->object_id.master3_objset;
				zp->z_group_id.master3_object = nrec->object_id.master3_object;
				zp->z_group_id.master3_gen = nrec->object_id.master3_gen;
				break;
			case ZFS_MULTICLUS_MASTER4:
				update_node_info = ZFS_UPDATE_FILE_NODE_MASTER4;
				zp->z_group_id.master4_spa = nrec->object_id.master4_spa;
				zp->z_group_id.master4_objset = nrec->object_id.master4_objset;
				zp->z_group_id.master4_object = nrec->object_id.master4_object;
				zp->z_group_id.master4_gen = nrec->object_id.master4_gen;
				break;
			default:
				mutex_exit(&zp->z_lock);
				error = EINVAL;
				goto OUT;
		}
		mutex_exit(&zp->z_lock);
		
		if (update_master_obj_by_mx_group_id(zp, m_node_type) != 0) {
			cmn_err(CE_WARN, "[Error] %s, update_master_obj_by_mx_group_id failed! m_node_type: %d", 
				__func__, m_node_type);
		}
		
		/* send masterX info to data node and other Master node */
		if (zfs_client_notify_file_info(zp, m_node_type, update_node_info) != 0){
			cmn_err(CE_WARN, "[Error] Failed to update master file node info, tnm is %s, m_node_type = %d",
					tnm, m_node_type);
		}
	}
OUT:
	kmem_free(nrec, sizeof (*nrec));
	return (error);
}



int
zfs_client_link(struct inode *tdip, struct inode *sip, char *name, cred_t *cr,
    caller_context_t *ct, int flags)
{
	int cp_len;
//	znode_t *dzp;
	zfs_group_name_link_t link;
	znode_t *zp;
	int error = 0;

	cp_len = (name != NULL) ? strlen(name) : 0;
//	zp = VTOZ(svp);
	zp = ITOZ(sip);
	link.id = zp->z_group_id;

	error = zfs_group_proc_name(ITOZ(tdip), NAME_LINK, &link, sizeof (link), name,
	    cp_len, NULL, flags, cr, NULL);

	return (error);
}

int
zfs_client_link_backup(znode_t *dzp, znode_t *szp, char *name, cred_t *cr,
    caller_context_t *ct, int flags, zfs_multiclus_node_type_t m_node_type)
{
	int cp_len;
	zfs_group_name_link_t link;
	int error = 0;

	cp_len = (name != NULL) ? strlen(name) : 0;
	link.id = szp->z_group_id;
	error = zfs_group_proc_name_backup(dzp, NAME_LINK, &link, sizeof (link), name,
	    cp_len, NULL, flags, cr, NULL, &dzp->z_group_id, m_node_type);

	return (error);
}


int
zfs_client_readlink(struct inode *ip, uio_t *uio, cred_t *cr, caller_context_t *ct)
{
	int error;
	znode_t *zp = ITOZ(ip);
	error = zfs_client_read_data(ZTOZSB(zp), zp, uio, uio->uio_resid,
	    LINK_READ, cr, 0, DATA_TO_MASTER, NULL);

	return (error);
}


int
zfs_client_rename(struct inode *sdip, char *snm, struct inode *tdip, char *tnm, cred_t *cr,
    caller_context_t *ct, int flags)
{
	int cp_len;
	int error;
//	vnode_t *realvp;
	zfs_group_name_rename_t rename;
	znode_t *opzp, *npzp;

	cp_len = (snm != NULL) ? strlen(snm) : 0;
	opzp = ITOZ(sdip);
	npzp = ITOZ(tdip);

	rename.osize = strlen(snm);
	rename.nsize = strlen(tnm);
	rename.new_parent_id = npzp->z_group_id;

	if ((error = zfs_group_proc_name(opzp, NAME_RENAME, &rename,
		    sizeof (rename), snm, cp_len, tnm, flags, cr, NULL)) == 0) {
//			dnlc_remove(sdvp, snm);
//			dnlc_remove(tdvp, tnm);
	}

	return (0);
}

int
zfs_client_rename_backup(znode_t *opzp, char *snm, znode_t *npzp,
    char *tnm, cred_t *cr,
    caller_context_t *ct, int flags, zfs_multiclus_node_type_t m_node_type)
{
	int cp_len;
	int error;
//	vnode_t *realvp;
	zfs_group_name_rename_t rename;

	cp_len = (snm != NULL) ? strlen(snm) : 0;

	rename.osize = strlen(snm);
	rename.nsize = strlen(tnm);
	rename.new_parent_id = npzp->z_group_id;

	error = zfs_group_proc_name_backup(opzp, NAME_RENAME, &rename,
		    sizeof (rename), snm, cp_len, tnm, flags, cr, NULL, &opzp->z_group_id, m_node_type);

	return (error);
}




int zfs_client_setattr(struct inode *ip, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
    znode_t *zp;
//	uint_t mask;
	zfs_group_znode_setattr_t *setattrp;
	int error;

	zp = ITOZ(ip);
	setattrp = kmem_zalloc(sizeof(zfs_group_znode_setattr_t), KM_SLEEP);
	setattrp->flags = flags;
	if ((error = zfs_group_v_to_v32(vap, &setattrp->vattr)) != 0) {
		kmem_free(setattrp, sizeof(zfs_group_znode_setattr_t));
		return (error);
	}
	if (vap->va_mask & AT_XVATTR) {
		zfs_group_from_xvattr(&setattrp->xattr, (xvattr_t *)vap);
		setattrp->bxattr = 1;
	}
	error = zfs_group_proc_znode(zp, ZNODE_SETATTR, setattrp, cr, B_TRUE);

	kmem_free(setattrp, sizeof(zfs_group_znode_setattr_t));
	return (error);
}

int zfs_client_setattr_backup(znode_t *zp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct, zfs_multiclus_node_type_t m_node_type)
{
//	uint_t mask;
	zfs_group_znode_setattr_t *setattrp;
	int error;

	setattrp = kmem_zalloc(sizeof(zfs_group_znode_setattr_t), KM_SLEEP);
	setattrp->flags = flags;
	if ((error = zfs_group_v_to_v32(vap, &setattrp->vattr)) != 0) {
		kmem_free(setattrp, sizeof(zfs_group_znode_setattr_t));
		return (error);
	}
	if (vap->va_mask & AT_XVATTR) {
		zfs_group_from_xvattr(&setattrp->xattr, (xvattr_t *)vap);
		setattrp->bxattr = 1;
	}
	error = zfs_group_proc_znode_backup(zp, ZNODE_SETATTR, setattrp, cr, m_node_type);

	kmem_free(setattrp, sizeof(zfs_group_znode_setattr_t));
	return (error);
}


int zfs_get_masterroot_attr(struct inode *ip, znode_t **tmp_root_zp)
{
	int err;
	uint64_t object;
	znode_t *zp = NULL;
	zfs_sb_t *zsb = NULL;

	zp = ITOZ(ip);
	zsb = ZTOZSB(zp);
	object = zsb->z_os->os_master_root;

	err = zfs_group_zget(zsb, object, tmp_root_zp, 0, 0, 0, B_FALSE);
	return (err);
}


int zfs_client_access(struct inode *ip, int mode, int flag, cred_t *cr)
{
	znode_t *zp;
//	uint_t mask;
	zfs_group_znode_access_t access;
	int error;

	zp = ITOZ(ip);
	access.mode = mode;
	access.flag = flag;

	error = zfs_group_proc_znode(zp, ZNODE_ACCESS, &access, cr, B_TRUE);
	return (error);
}



int zfs_client_setsecattr(struct inode *ip, vsecattr_t *vsecp, int flag, cred_t *cr,
    caller_context_t *ct)
{
	int error;
	znode_t *zp;

	size_t acl_len;
	zfs_group_name_acl_t *zg_acl;
//	char *tmp_acls;


	error = 0;
	acl_len = 0;

	zp = ITOZ(ip);

	acl_len = sizeof(zfs_group_name_acl_t) + vsecp->vsa_aclentsz - 8;
	zg_acl = kmem_zalloc(acl_len, KM_SLEEP);
	zg_acl->set = 1;
	zfs_group_from_acl(zg_acl, vsecp);

	error = zfs_group_proc_name(zp, NAME_ACL, NULL, 0,
	    (void *)zg_acl, acl_len, NULL, flag, cr, NULL);

	kmem_free(zg_acl, acl_len);
	return (error);
}

int zfs_client_setsecattr_backup(znode_t *zp, vsecattr_t *vsecp, int flag, cred_t *cr,
    caller_context_t *ct, zfs_multiclus_node_type_t m_node_type)
{
	int error;

	size_t acl_len;
	zfs_group_name_acl_t *zg_acl;
//	char *tmp_acls;


	error = 0;
	acl_len = 0;

	acl_len = sizeof(zfs_group_name_acl_t) + vsecp->vsa_aclentsz - 8;
	zg_acl = kmem_zalloc(acl_len, KM_SLEEP);
	zg_acl->set = 1;
	zfs_group_from_acl(zg_acl, vsecp);

	error = zfs_group_proc_name_backup(zp, NAME_ACL, NULL, 0,
	    (void *)zg_acl, acl_len, NULL, flag, cr, NULL, &zp->z_group_id, m_node_type);

	kmem_free(zg_acl, acl_len);
	return (error);
}

int
zfs_client_read(struct inode *ip, uio_t *uio, int ioflag, cred_t *cr)
{
	int error = 0;
	znode_t *zp;
	zfs_multiclus_group_record_t *record = NULL;
	ssize_t n, nbytes;

	zp = ITOZ(ip);
	if (zp->z_group_id.data_spa == 0 || zp->z_group_id.data_objset == 0
		|| zp->z_group_id.data_object == 0) {
		cmn_err(CE_WARN, "[Error] Failed to read file data node, file is %s, data node is not existed", zp->z_filename);
		return ENOENT;
	}

	if (zp->z_group_id.data_status == DATA_NODE_DIRTY) {
		cmn_err(CE_WARN, "[Error] Failed to read file data node, file is %s, data node is dirty", zp->z_filename);
		return EIO;
	}

	record = zfs_multiclus_get_record(zp->z_group_id.data_spa, zp->z_group_id.data_objset);
	if (record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE) {
		return ENOENT;
	}

	n = MIN(uio->uio_resid, zp->z_size - uio->uio_loffset);
	while (n > 0) {
		nbytes = MIN(n, zfs_group_max_dataseg_size -
		    P2PHASE(uio->uio_loffset, zfs_group_max_dataseg_size));

		error = zfs_client_read_data(ZTOZSB(zp), zp, uio, nbytes, DATA_READ,
		    cr, ioflag, DATA_TO_DATA, NULL);
		if (error != 0)
			break;

		n -= nbytes;
	}

	if (error != 0) {
		cmn_err(CE_WARN, "[Error] Failed to read file data node, file is %s, error = %d", zp->z_filename, error);
	}

	return (error);
}

int
zfs_client_read2(struct inode *ip, uio_t *uio, int ioflag, cred_t *cr)
{
	int error = 0;
	znode_t *zp;
	zfs_multiclus_group_record_t *record = NULL;
	ssize_t n, nbytes;

	zp = ITOZ(ip);
	if (zp->z_group_id.data2_spa == 0 || zp->z_group_id.data2_objset == 0
		|| zp->z_group_id.data2_object == 0) {
		cmn_err(CE_WARN, "[Error] Failed to read file data2 node, file is %s, data node is not existed", zp->z_filename);
		return ENOENT;
	}

	if (zp->z_group_id.data2_status == DATA_NODE_DIRTY) {
		cmn_err(CE_WARN, "[Error] Failed to read file data2 node, file is %s, data node is dirty", zp->z_filename);
		return EIO;
	}

	record = zfs_multiclus_get_record(zp->z_group_id.data2_spa, zp->z_group_id.data2_objset);
	if (record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE) {
		return ENOENT;
	}

	n = MIN(uio->uio_resid, zp->z_size - uio->uio_loffset);
	while (n > 0) {
		nbytes = MIN(n, zfs_group_max_dataseg_size -
		    P2PHASE(uio->uio_loffset, zfs_group_max_dataseg_size));

		error = zfs_client_read_data2(ZTOZSB(zp), zp, uio, nbytes, DATA_READ,
		    cr, ioflag, DATA_TO_DATA, NULL);
		if (error != 0)
			break;

		n -= nbytes;
	}

	if (error != 0) {
		cmn_err(CE_WARN, "[Error] Failed to read file data2 node, file is %s, error = %d", zp->z_filename, error);
	}

	return (error);
}

int
zfs_client_write(struct inode *ip, uio_t *uio, int ioflag, cred_t *cr, caller_context_t *ct)
{
	znode_t* zp = NULL;
	zfs_group_dirty_notify_para_t* notify_para = NULL;
	ssize_t n = 0;
	ssize_t nbytes = 0;
	int error = 0;
	zfs_sb_t  *zsb = NULL;

	zp = ITOZ(ip);
	zsb = ZTOZSB(zp);
	if (zp->z_group_id.data_spa == 0 || zp->z_group_id.data_objset == 0
		|| zp->z_group_id.data_object == 0) {
		cmn_err(CE_WARN, "[Error] Failed to write file data node, file is %s, data node is not existed", zp->z_filename);
		return ENOENT;
	}

	if (zp->z_group_id.data_status == DATA_NODE_DIRTY) {
		return EIO;
	}

	n = uio->uio_resid;
	while (n > 0) {
		nbytes = MIN(n, zfs_group_max_dataseg_size -
		    P2PHASE(uio->uio_loffset, zfs_group_max_dataseg_size));
		error = zfs_client_write_data(ZTOZSB(zp), zp, uio, nbytes,
		    cr, ioflag);
		if (error != 0)
			break;

		n -= nbytes;
	}

	if (error != 0) {
		cmn_err(CE_WARN, "[Error] Failed to write file data node, file is %s, data_spa: %llx, data_os: %llx, data_obj: %llx, error = %d",
			zp->z_filename, (unsigned long long)zp->z_group_id.data_spa, (unsigned long long)zp->z_group_id.data_objset,
			(unsigned long long)zp->z_group_id.data_object, error);

		zp->z_group_id.data_status = DATA_NODE_DIRTY;

		notify_para = kmem_zalloc(sizeof(zfs_group_dirty_notify_para_t), KM_SLEEP);
		//notify_para->znode = *zp;
		bcopy(zp, &notify_para->znode, sizeof(znode_t));
		notify_para->dirty_flag = DATA_NODE_DIRTY;
		notify_para->data_no = DATA_FILE1;
		notify_para->local_spa = spa_guid(dmu_objset_spa(zsb->z_os));
		notify_para->local_os = dmu_objset_id(zsb->z_os);

/*
		if (ddi_taskq_dispatch(zfsvfs->notify_taskq, zfs_client_notify_data_file_dirty_tq,
				(void*)notify_para, DDI_NOSLEEP) != DDI_SUCCESS) {
*/
//		if (taskq_dispatch(zsb->notify_taskq, zfs_client_notify_data_file_dirty_tq,
//				(void*)notify_para, TQ_NOSLEEP) == 0) {
			zfs_client_notify_data_file_dirty_tq((void*)notify_para);
//		}
	}

	return (error);
}

int
zfs_client_write2(struct inode *ip, uio_t *uio, int ioflag, cred_t *cr, caller_context_t *ct)
{
	znode_t* zp = NULL;
	zfs_group_dirty_notify_para_t* notify_para = NULL;
	ssize_t n = 0;
	ssize_t nbytes = 0;
	int error = 0;
	zfs_sb_t  *zsb = NULL;

	zp = ITOZ(ip);
	zsb = ZTOZSB(zp);
	if (zp->z_group_id.data2_spa == 0 || zp->z_group_id.data2_objset == 0
		|| zp->z_group_id.data2_object == 0) {
		cmn_err(CE_WARN, "[Error] Failed to write file data2 node, file is %s, data node is not existed", zp->z_filename);
		return ENOENT;
	}

	if (zp->z_group_id.data2_status == DATA_NODE_DIRTY) {
		return EIO;
	}

	n = uio->uio_resid;
	while (n > 0) {
		nbytes = MIN(n, zfs_group_max_dataseg_size -
		    P2PHASE(uio->uio_loffset, zfs_group_max_dataseg_size));
		error = zfs_client_write_data2(ZTOZSB(zp), zp, uio, nbytes,
		    cr, ioflag);
		if (error != 0)
			break;

		n -= nbytes;
	}

	if (error != 0) {
		cmn_err(CE_WARN, "[Error] Failed to write file data2 node, file is %s, error = %d", zp->z_filename, error);

		zp->z_group_id.data2_status = DATA_NODE_DIRTY;

		notify_para = kmem_zalloc(sizeof(zfs_group_dirty_notify_para_t), KM_SLEEP);
		//notify_para->znode = *zp;
		bcopy(zp, &notify_para->znode, sizeof(znode_t));
		notify_para->dirty_flag = DATA_NODE_DIRTY;
		notify_para->data_no = DATA_FILE2;
		notify_para->local_spa = spa_guid(dmu_objset_spa(zsb->z_os));
		notify_para->local_os = dmu_objset_id(zsb->z_os);
/*
		if (ddi_taskq_dispatch(zfsvfs->notify_taskq, zfs_client_notify_data_file_dirty_tq,
				(void*)notify_para, DDI_NOSLEEP) != DDI_SUCCESS) {
*/
//		if (taskq_dispatch(zsb->notify_taskq, zfs_client_notify_data_file_dirty_tq,
//				(void*)notify_para, TQ_NOSLEEP) == 0) {
			zfs_client_notify_data_file_dirty_tq((void*)notify_para);
//		}
	}

	return (error);
}

// int zfs_client_map_write(znode_t *zp, page_t *pp,
//     uint64_t off, uint64_t len, cred_t *cr, int ioflag)
// {
// 	int error;
// 	size_t bufoff;
// 	struct uio auio;
// 	struct iovec aiov;
// 	caddr_t va;
// 	caddr_t data;
	
// 	bufoff = 0;
// 	data = kmem_zalloc(len, KM_SLEEP);
// 	for (; bufoff < len; ) {
		
// 		va = zfs_map_page(pp, S_READ);
// 		bcopy(va, (char *)(data + bufoff), PAGESIZE);
// 		zfs_unmap_page(pp, va);
// 		pp = pp->p_next;
// 		bufoff += PAGESIZE;
// 	}

// 	aiov.iov_base = data;
// 	aiov.iov_len = len;
// 	auio.uio_iov = &aiov;
// 	auio.uio_iovcnt = 1;
// 	auio.uio_loffset = off;
// 	auio.uio_segflg = UIO_SYSSPACE;
// 	auio.uio_resid = len;
// 	auio.uio_fmode = 0;
// 	auio.uio_extflg = UIO_COPY_CACHED;

// //	error = zfs_client_write_data(zp->z_zfsvfs, zp, &auio, len, cr, ioflag);
// 	error = zfs_client_write_data(zp->zsb, zp, &auio, len, cr, ioflag);
// 	kmem_free(data, len);
// 	return (error);
// }

int
zfs_client_getsecattr(struct inode *ip, vsecattr_t *vsecp, int flag, cred_t *cr,
    caller_context_t *ct)
{
	int error;
//	size_t len;
	znode_t *zp;
	zfs_group_name_acl_t zg_acl;

	zp = ITOZ(ip);

	bzero(&zg_acl, sizeof(zfs_group_name_acl_t));
	zfs_group_from_acl(&zg_acl, vsecp);
	error = zfs_group_proc_name(zp, NAME_ACL, NULL, 0, (void *)&zg_acl,
	    sizeof (zfs_group_name_acl_t), NULL, flag, cr, (void *)vsecp);
	return (error);
}

int zfs_client_get_fictitious_group_fsstat(zfs_sb_t *zsb, uint64_t *refbytes,
    uint64_t *availbytes, uint64_t *refobjs, uint64_t *availobjs)
{
	int i, num = 0;
	zfs_multiclus_group_record_t *group_record;
	zfs_multiclus_group_t *group = NULL;
	uint64_t ref = 0;
	uint64_t avail = 0;
	uint64_t refob = 0;
	uint64_t availob = 0;

	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "%s, %d, multiclus is disabled!", __func__, __LINE__);
		return (-1);
	}
	if(zfs_multiclus_get_group(zsb->z_os->os_group_name, &group) >= ZFS_MULTICLUS_GROUP_TABLE_SIZE 
		|| group == NULL){
		cmn_err(CE_WARN, "%s, %d, fail in finding group %s!", __func__, __LINE__, zsb->z_os->os_group_name);
		return (-1);
	}

	dmu_objset_space(zsb->z_os,
		    &ref, &avail, &refob, &availob);

	ref = 0;
	avail = 0;
	for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i++) {
		group_record = &group->multiclus_group[i];
		if (group_record->used && group_record->node_status.status == ZFS_MULTICLUS_NODE_ONLINE){
		    num++;
			ref+=group_record->used_size;
			avail+=group_record->avail_size;
			continue;
		}
	}
	*refbytes = ref;
	*availbytes = avail;
	*refobjs = (refob*num);
	*availobjs = (availob*num);

	return (0);
}


int zfs_client_master_get_group_fsstat(zfs_sb_t *zsb, uint64_t *refbytes,
    uint64_t *availbytes, uint64_t *refobjs, uint64_t *availobjs)
{
	int i;
	int err;
	fs_stat_t *fsstat;
	zfs_multiclus_group_record_t *group_record;
	zfs_multiclus_group_t *group = NULL;

	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "%s, %d, multiclus is disabled!", __func__, __LINE__);
		return (-1);
	}
	if(zfs_multiclus_get_group(zsb->z_os->os_group_name, &group) >= ZFS_MULTICLUS_GROUP_TABLE_SIZE 
		|| group == NULL){
		cmn_err(CE_WARN, "%s, %d, fail in finding group %s!", __func__, __LINE__, zsb->z_os->os_group_name);
		return (-1);
	}
	fsstat = kmem_zalloc(sizeof(fs_stat_t), KM_SLEEP);

	dmu_objset_space(zsb->z_os,
		    refbytes, availbytes, refobjs, availobjs);
	for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i++) {
		zfs_group_cmd_arg_t cmd_arg;
		group_record = &group->multiclus_group[i];
		if (!group_record->used || group_record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE || 
		    (group_record->os_id == dmu_objset_id(zsb->z_os)
		    && group_record->spa_id == spa_guid(dmu_objset_spa(zsb->z_os)))){
			continue;
		}
		bzero(&cmd_arg, sizeof(zfs_group_cmd_arg_t));
		cmd_arg.return_ptr = (uintptr_t)fsstat;
		cmd_arg.return_size = sizeof(fs_stat_t);
		err = zfs_proc_cmd(zsb, SC_FS_STAT, SHARE_WAIT, &cmd_arg,
		    group_record->spa_id, group_record->os_id, group_record->root, APP_GROUP);
		if (err == 0) {
			*refbytes += fsstat->refdbytes;
			*availbytes += fsstat->availbytes;
			*refobjs += fsstat->usedobjs;
			*availobjs += fsstat->availobjs;
		}
		bzero(fsstat, sizeof(fs_stat_t));
	}
	kmem_free(fsstat, sizeof(fs_stat_t));

	return (0);
}


// //int zfs_client_get_fsstat(zfsvfs_t *zfsvfs, uint64_t *refbytes,
// int zfs_client_get_fsstat(zfs_sb_t *zsb, uint64_t *refbytes,
//     uint64_t *availbytes, uint64_t *refobjs, uint64_t *availobjs)
// {
// 	int err;
// 	fs_stat_t *fsstat;
// 	*refbytes = 0;
// 	*availbytes = 0;
// 	*refobjs = 0;
// 	*availobjs = 0;

// 	if (!zfs_multiclus_done())
// 		return (0);

// //	if (spa_get_group_flags(dmu_objset_spa(zfsvfs->z_os)))
// 	if (spa_get_group_flags(dmu_objset_spa(zsb->z_os)))
// 		return (0);

// //	if (zfsvfs->z_os->os_is_master) {
// //		err = zfs_client_master_get_group_fsstat(zfsvfs, refbytes, availbytes, refobjs,
// 	if (zsb->z_os->os_is_master) {
// 		err = zfs_client_master_get_group_fsstat(zsb, refbytes, availbytes, refobjs,
// 		    availobjs);
// 	} else {
// 		zfs_group_cmd_arg_t cmd_arg;
// 		fsstat = kmem_zalloc(sizeof(fs_stat_t), KM_SLEEP);
// 		bzero(&cmd_arg, sizeof(zfs_group_cmd_arg_t));
// 		cmd_arg.return_ptr = (uintptr_t)fsstat;
// 		cmd_arg.return_size = sizeof(fs_stat_t);
// /*
// 		int err = zfs_proc_cmd(zfsvfs, SC_FS_STAT, SHARE_WAIT, &cmd_arg,
// 		    zfsvfs->z_os->os_master_spa,
// 		    zfsvfs->z_os->os_master_os,
// 		    zfsvfs->z_os->os_master_root, APP_USER);
// */
// 		int err = zfs_proc_cmd(zsb, SC_FS_STAT, SHARE_WAIT, &cmd_arg,
// 		    zsb->z_os->os_master_spa,
// 		    zsb->z_os->os_master_os,
// 		    zsb->z_os->os_master_root, APP_USER);
// 		if (err == 0) {
// 			*refbytes = fsstat->refdbytes;
// 			*availbytes = fsstat->availbytes;
// 			*refobjs = fsstat->usedobjs;
// 			*availobjs = fsstat->availobjs;
// 		}

// 		kmem_free(fsstat, sizeof(fs_stat_t));
// 	}
// 	return (err);
// }


boolean_t zfs_client_overquota(zfs_sb_t *zsb, znode_t *zp, int flag)
{
	int err = 0;
	boolean_t bover;
	zfs_group_cmd_arg_t cmd_arg;
	fs_quota_t *quota = kmem_zalloc(sizeof(fs_quota_t), KM_SLEEP);

	quota->master_object = zp->z_group_id.master_object;
	quota->dirquota_index = zp->z_dirquota;
	quota->flag = flag ;
	cmd_arg.arg_ptr = (uintptr_t)quota;
	cmd_arg.arg_size = (uintptr_t)sizeof(fs_quota_t);
	cmd_arg.return_ptr = (uintptr_t)quota;
	cmd_arg.return_size = (uintptr_t)sizeof(fs_quota_t);

	err = zfs_proc_cmd(zsb, SC_FS_QUOTA, SHARE_WAIT, &cmd_arg,
		    zsb->z_os->os_master_spa,
		    zsb->z_os->os_master_os,
		    zsb->z_os->os_master_root, APP_USER);
	if (err == 0) {
			bover = quota->quota_over;
	} else {
		bover = B_FALSE;
	}

	kmem_free(quota, sizeof(fs_quota_t));
	return (bover);
}

void zfs_client_overquota_tq(void* arg)
{
	zfs_group_overquota_para_t *overquota_para = (zfs_group_overquota_para_t *)arg;
	zfs_sb_t *zsb = NULL;	
	znode_t *zp = NULL;
//	znode_t *qzp = NULL;
	if (overquota_para != NULL) {

		zsb = zfs_sb_group_hold(overquota_para->spa_id, overquota_para->objset, FTAG, B_FALSE);
		if (zsb != NULL) {
			if (zfs_zget(zsb, overquota_para->object, &zp) == 0) {
				if (zp->z_overquota != B_TRUE) {
					zp->z_overquota = zfs_client_overquota(zsb, zp, QUOTA_SPACE);
				}
				iput(ZTOI(zp));
			}
			zfs_sb_group_rele(zsb, FTAG);
		}
		kmem_free(overquota_para, sizeof(zfs_group_overquota_para_t));
	}
}

// //int zfs_client_set_userquota(zfsvfs_t *zfsvfs, zfs_userquota_prop_t type,
// int zfs_client_set_userquota(zfs_sb_t *zsb, zfs_userquota_prop_t type,
//     const char *domain, uint64_t rid, uint64_t quota)
// {
// 	char username[MAXPATHLEN];
// 	zfs_group_cmd_arg_t cmd_arg;
// 	zfs_cl_set_userquota_t *userquota = kmem_zalloc(sizeof(zfs_cl_set_userquota_t), 
// 											    KM_SLEEP);
// 	int remote_err = 0;

// 	/** get username from rid **/

// 	strncpy(userquota->domain, domain, strlen(domain));
// 	userquota->domain[strlen(domain)] = '\0';
// 	strncpy(userquota->username, username, strlen(username));
// 	userquota->username[strlen(username)] = '\0';
// 	userquota->quota = quota;
// 	cmd_arg.arg_ptr = (uintptr_t)userquota;
// 	cmd_arg.arg_size = (uintptr_t)sizeof(zfs_cl_set_userquota_t);
// 	cmd_arg.return_ptr = (uintptr_t)&remote_err;
// 	cmd_arg.return_size = (uintptr_t)sizeof(int);
// 	int err = zfs_proc_cmd(zsb, SC_FS_USERQUOTA, SHARE_WAIT, &cmd_arg,
// 		    zsb->z_os->os_master_spa,
// 		    zsb->z_os->os_master_os,
// 		    zsb->z_os->os_master_root, APP_USER);
// /*
// 	int err = zfs_proc_cmd(zfsvfs, SC_FS_USERQUOTA, SHARE_WAIT, &cmd_arg,
// 		    zfsvfs->z_os->os_master_spa,
// 		    zfsvfs->z_os->os_master_os,
// 		    zfsvfs->z_os->os_master_root, APP_USER);
// */
// 	if (err == 0) {
// 		err = remote_err;
// 	}
// 	kmem_free(userquota, sizeof(zfs_cl_set_userquota_t));
// 	return (err);
// }

// //int zfs_client_set_dirquota(zfsvfs_t *zfsvfs, uint64_t object,
// int zfs_client_set_dirquota(zfs_sb_t *zsb, uint64_t object,
//     const char *path, uint64_t quota)
// {
// 	int err = 0;
// 	zfs_group_cmd_arg_t cmd_arg = {0};
// 	zfs_cl_set_dirquota_t dirquota = {0};
// 	int remote_err = 0;
	
// 	if (zfs_multiclus_enable() == B_FALSE)
// 		return (-1);		                           

// 	dirquota.object = object;
// 	strncpy(dirquota.path, path, strlen(path));
// 	dirquota.quota = quota;
// 	cmd_arg.arg_ptr = (uintptr_t)(&dirquota);
// 	cmd_arg.arg_size = (uintptr_t)sizeof(zfs_cl_set_dirquota_t);
// 	cmd_arg.return_ptr = (uintptr_t)&remote_err;
// 	cmd_arg.return_size = (uintptr_t)sizeof(int);
// /*
// 	err = zfs_proc_cmd(zfsvfs, SC_FS_DIRQUOTA, SHARE_WAIT, &cmd_arg,
// 		    zfsvfs->z_os->os_master_spa,
// 		    zfsvfs->z_os->os_master_os,
// 		    zfsvfs->z_os->os_master_root, APP_USER);
// */
// 	err = zfs_proc_cmd(zsb, SC_FS_DIRQUOTA, SHARE_WAIT, &cmd_arg,
// 		    zsb->z_os->os_master_spa,
// 		    zsb->z_os->os_master_os,
// 		    zsb->z_os->os_master_root, APP_USER);
// 	if (err == 0) {
// 		err = remote_err;
// 	}
// 	return (err);
// }

int zfs_client_set_dirquota_backup(znode_t *zp, uint64_t object,
    const char *path, uint64_t quota, zfs_multiclus_node_type_t m_node_type)
{
	int err = 0;
	int remote_err = 0;
	zfs_group_cmd_arg_t cmd_arg; // = {0};
	zfs_cl_set_dirquota_t *dirquota = NULL;

	dirquota = kmem_zalloc(sizeof(zfs_cl_set_dirquota_t), KM_SLEEP);

	switch (m_node_type) {
		case ZFS_MULTICLUS_MASTER2:
			dirquota->object = zp->z_group_id.master2_object;
			break;
		case ZFS_MULTICLUS_MASTER3:
			dirquota->object = zp->z_group_id.master3_object;
			break;
		case ZFS_MULTICLUS_MASTER4:
			dirquota->object = zp->z_group_id.master4_object;
			break;
		default:
			cmn_err(CE_WARN, "%s, invalid node type, node_type = %d",
				__func__, m_node_type);
			if (NULL != dirquota)
				kmem_free(dirquota, sizeof(zfs_cl_set_dirquota_t));
			return (EPROTO);
	}
	strncpy(dirquota->path, path, strlen(path));
	dirquota->quota = quota;
	cmd_arg.arg_ptr = (uintptr_t)(dirquota);
	cmd_arg.arg_size = (uintptr_t)sizeof(zfs_cl_set_dirquota_t);
	cmd_arg.return_ptr = (uintptr_t)(&remote_err);
	cmd_arg.return_size = (uintptr_t)sizeof(int);
	err = zfs_proc_cmd_backup(zp, SC_FS_DIRQUOTA, SHARE_WAIT, &cmd_arg,
		APP_USER, m_node_type);
	if (err == 0) {
		if(remote_err != 0){
			err = remote_err;
			cmn_err(CE_WARN, "remote_err=%d: master set dirquota FAIL!!!", remote_err);
		}
	}

	if (NULL != dirquota)
		kmem_free(dirquota, sizeof(zfs_cl_set_dirquota_t));
	return (err);
}


int zfs_client_get_dirlowdata(zfs_sb_t *zsb, 
    znode_t *zp, zfs_dirlowdata_t *dirlowdata)
{
	int err = 0;
//	boolean_t bover;
	zfs_group_cmd_arg_t cmd_arg;
	fs_dir_lowdata_t *fs_dirlowdata = kmem_zalloc(sizeof(fs_dir_lowdata_t), KM_SLEEP);

	if(NULL == fs_dirlowdata){
		return (ENOMEM);
	}

	fs_dirlowdata->master_object = zp->z_group_id.master_object;
	fs_dirlowdata->dirlowdata_index = zp->z_dirlowdata;
	cmd_arg.arg_ptr = (uintptr_t)fs_dirlowdata;
	cmd_arg.arg_size = (uintptr_t)sizeof(fs_dir_lowdata_t);
	cmd_arg.return_ptr = (uintptr_t)fs_dirlowdata;
	cmd_arg.return_size = (uintptr_t)sizeof(fs_dir_lowdata_t);

	err = zfs_proc_cmd(zsb, SC_FS_DIRLOWDATA, SHARE_WAIT, &cmd_arg,
		    zsb->z_os->os_master_spa,
		    zsb->z_os->os_master_os,
		    zsb->z_os->os_master_root, APP_USER);
	if (err == 0) {
		if(fs_dirlowdata->ret==0){
			bcopy(&fs_dirlowdata->dirlowdata, dirlowdata, sizeof(zfs_dirlowdata_t));
		}else{
			err=fs_dirlowdata->ret;
			cmn_err(CE_WARN, "[Error] ret=%d: get dirlowdata from master FAIL!!!",err);
		}
	}else{
		cmn_err(CE_WARN, "[Error] ret=%d: get dirlowdata from master FAIL!!",err);
	}
	
	if(NULL != fs_dirlowdata){
		kmem_free(fs_dirlowdata, sizeof(fs_dir_lowdata_t));
	}
	
	return (err);
}

static int zfs_client_send_to_local_server(zfs_group_header_t *msg_header, zfs_msg_t *msg_data)
{
	uint64_t rx_length;
	void *data = NULL;
	uint64_t data_len;
	zfs_msg_t *nmsg_data = NULL;
	zfs_group_header_t *nmsg_header = NULL;
	zfs_group_server_para_t *server_para = NULL;
	

	server_para = kmem_zalloc(sizeof(zfs_group_server_para_t), KM_SLEEP);
	nmsg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	nmsg_data = (zfs_msg_t *) zfs_group_alloc_data(msg_header, 1, &rx_length);
	data_len = msg_header->length;
	data = (void *)((char *)msg_data);
	zfs_group_fill_data(msg_header, 0, 0, data_len, data, nmsg_data, nmsg_header);
	server_para->msg_data = nmsg_data;
	server_para->msg_header = nmsg_header;
	zfs_group_server_rx(server_para);
	if (msg_header->command != ZFS_GROUP_CMD_NOTIFY)
		zfs_client_rx(msg_header, msg_data, nmsg_header, nmsg_data);
	msg_header->error = nmsg_header->error;
	zfs_group_free_data(nmsg_header, (void *)nmsg_data, rx_length);
	kmem_free(nmsg_header, sizeof(zfs_group_header_t));
	kmem_free(server_para, sizeof(zfs_group_server_para_t));
	return (msg_header->error);
}

void zfs_group_wait(clock_t microsecs)
{
	clock_t time = 0;
	kcondvar_t	send_cv;
	kmutex_t	send_lock;

	cv_init(&send_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&send_lock, NULL, MUTEX_DRIVER, NULL);

	time = drv_usectohz(microsecs);/*ZFS_GROUP_SEND_WAIT*/
	mutex_enter(&send_lock);
	cv_timedwait(&send_cv, &send_lock, ddi_get_lbolt() + time);
	mutex_exit(&send_lock);

	mutex_destroy(&send_lock);
	cv_destroy(&send_cv);
}

boolean_t zfs_server_is_online(uint64_t ser_spa, uint64_t ser_os)
{
	zfs_multiclus_group_record_t *record;

	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "%s, %d, multiclus is disabled!", __func__, __LINE__);
		return B_FALSE;
	}
	
	record = zfs_multiclus_get_record(ser_spa, ser_os);

	if (record != NULL && record->node_status.status == ZFS_MULTICLUS_NODE_ONLINE) {
		return B_TRUE;
	} else {
		return B_FALSE;
	}
}

void zfs_failover_ctl(objset_t *os, int time)
{
 	spa_t	*spa = NULL;
 	char *hbx_data = kmem_zalloc(MAXNAMELEN + 4, KM_SLEEP);
	
 	spa = dmu_objset_spa(os);

 	sprintf(hbx_data, "%s:%d", spa_name(spa), time);

 	zfs_notify_clusterd(EVT_CLUSTERNAS_FAILOVER_CTL, hbx_data, MAXNAMELEN + 4);
}

int zfs_client_send_to_server(objset_t *os, zfs_group_header_t *msg_header, zfs_msg_t *msg_data, boolean_t waitting)
{
	int	error = 0;
	int	tx_error = 0;
	int	local_tx_cnt = 0;
	int	remote_tx_cnt = 0;
//	int	repeat = 0;
	int	retry = 0;
	uint64_t	dst_spa = 0;
	uint64_t	dst_os = 0;
	uint64_t	nmsg_len = 0;
	boolean_t	b_enable = B_FALSE;
	boolean_t	bprint = B_FALSE;
	spa_t	*spa = NULL;
	zfs_sb_t *zsb = NULL;
	zfs_msg_t	*nmsg_data = NULL;
	zfs_group_header_t	*nmsg_header = NULL;
//	pool_state_t	pool_state = 0;


	b_enable = zfs_multiclus_enable();
	if (!b_enable)
		return (1);

	dst_spa = msg_header->server_spa;
	dst_os = msg_header->server_os;
	if (dst_spa == 0 || dst_os == 0 || debug_print > 0) {
		bprint = B_TRUE;
	}

	zfs_group_msg(msg_header, msg_data, B_FALSE, B_FALSE, bprint);

resend:
	mutex_enter(&spa_namespace_lock);
	spa = spa_by_guid(dst_spa, 0);
	if (spa != NULL) {
		spa_open_ref(spa, FTAG);
		mutex_exit(&spa_namespace_lock);
		
		zsb = zfs_sb_group_hold(msg_header->server_spa, 
				msg_header->server_os, FTAG, B_FALSE);

		if (zsb == NULL){
			if (local_tx_cnt > ZFS_CLINT_LOCAL_MAX_TX){
				error = EGHOLD;
			} else {
				mutex_enter(&spa_namespace_lock);
				spa_close(spa, FTAG);
				mutex_exit(&spa_namespace_lock);

				zfs_group_wait(ZFS_GROUP_SEND_WAIT);
				local_tx_cnt ++;
				cmn_err(CE_WARN, "[Error] %s: send retry times: %d", __func__, local_tx_cnt);
				goto resend;
			}
		} else {			
			zfs_sb_group_rele(zsb, FTAG);
			error = zfs_client_send_to_local_server(msg_header, msg_data);
		}
		
		mutex_enter(&spa_namespace_lock);
		spa_close(spa, FTAG);
		mutex_exit(&spa_namespace_lock);
	} else {
		mutex_exit(&spa_namespace_lock);
		
resend_remote:
		tx_error = zfs_group_send_to_remote_server(os, msg_header, msg_data);
		if (tx_error == 0){
			nmsg_data = (zfs_msg_t *)(uintptr_t)(msg_header->nmsg_data);
			nmsg_header = (zfs_group_header_t *)(uintptr_t)(msg_header->nmsg_header);
			nmsg_len = msg_header->nmsg_len;
			error = nmsg_header->error;
			if (error == EGHOLD) {
				/* We do not distinguish partner or others.*/
				vmem_free(nmsg_data, nmsg_len);
				kmem_free(nmsg_header, sizeof(zfs_group_header_t));
				if(remote_tx_cnt > ZFS_CLINT_REMOTE_MAX_TX){
					error = EGHOLD;
				}else{
					remote_tx_cnt++;
					if (waitting)
						zfs_group_wait(ZFS_MULTICLUS_SECOND/2);
					goto resend;
				}
			} else {
				VERIFY(nmsg_data != NULL);
				VERIFY(nmsg_header != NULL);
				zfs_client_rx(msg_header, msg_data, nmsg_header, nmsg_data);
				error = nmsg_header->error;
				vmem_free(nmsg_data, nmsg_len);
				kmem_free(nmsg_header, sizeof(zfs_group_header_t));
			}
		} else {
			error = EOFFLINE;
		}
	}

	if (tx_error != 0 && tx_error != 1) {
		if (waitting)
			zfs_group_wait(ZFS_MULTICLUS_SECOND/2);
		 
		zsb = zfs_sb_group_hold(msg_header->server_spa, 
			msg_header->server_os, FTAG, B_TRUE);

		if (zsb == NULL){	
			if (retry < ZFS_CLINT_LOCAL_HOLD_MAX){
				retry++;
				goto resend_remote;
			} else {
				error = EGHOLD;
			}
		} else {
			zfs_sb_group_rele(zsb, FTAG);
			error = zfs_client_send_to_local_server(msg_header, msg_data);
		}
	}

	return (error);
}

// int 
// zfs_proc_stat(objset_t *os, ushort_t op, share_flag_t wait_flag,
//     zfs_multiclus_stat_arg_t *stat_arg, uint64_t dst_spa, uint64_t dst_os,
//     msg_orig_type_t msg_orig)
// {
// 	int	error = 0;
// 	uint64_t	msg_len = 0;
// 	uint64_t	return_len = 0;
// 	zfs_group_stat_msg_t	*stat_msg = NULL;
// 	zfs_group_header_t	*msg_header = NULL;


// 	msg_len = sizeof(zfs_group_stat_msg_t) + stat_arg->arg_size;
// 	return_len = sizeof(zfs_group_stat_msg_t) + stat_arg->return_size;

// 	stat_msg = kmem_zalloc(msg_len, KM_SLEEP);
// 	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
// 	if (stat_arg->arg_size > 0) {
// 		bcopy((void *)(uintptr_t)stat_arg->arg_ptr, stat_msg->call.stat.stat, stat_arg->arg_size);
// 	}
// 	bcopy(stat_arg, &(stat_msg->call.stat.arg), sizeof(zfs_multiclus_stat_arg_t));

// 	zfs_group_build_header(os, msg_header, ZFS_GROUP_CMD_STAT, 
// 		wait_flag, op, msg_len, return_len, dst_spa, dst_os, 0, 0, 0, 0, 0, 
// 		MSG_REQUEST, msg_orig);
// 	error = zfs_client_send_to_server(os, msg_header, (zfs_msg_t *)stat_msg, B_FALSE);

// 	if (stat_msg != NULL)
// 		kmem_free(stat_msg, msg_len);
// 	if (msg_header != NULL)
// 		kmem_free(msg_header, sizeof(zfs_group_header_t));
	
// 	return (error);
// }

// int zfs_get_group_iostat(char *poolname, vdev_stat_t *newvs, nvlist_t **rmconfig)
// {
// 	int i;
// 	int err=0;
// 	objset_t *os = NULL;
// 	nvlist_t *iostat[32] = {0};
// 	nvlist_t *nvchild[32] = {0}, *nvroot;
// 	char *rmpname[32] = {0}, *fnptr;
// 	int nvcnt = 0;
// 	char *ret_ptr = NULL;
// 	vdev_stat_t totalvs = {0}, *cntvs;
// 	uint_t c;
// 	uint64_t spa_id;
// 	uint64_t dsl_id;
// 	char fs_name[MAX_FSNAME_LEN] = {0};
// 	objset_t *subos = NULL;
// 	zfs_multiclus_group_record_t *group_record;
// 	zfs_multiclus_group_t *group = NULL;

// 	if (zfs_multiclus_enable() == B_FALSE)
// 	{
// 		cmn_err(CE_WARN, "%s: Multiclus is disable !!!", __func__);
// 		return (-1);
// 	}
	
// 	if (err = dmu_objset_hold(poolname, FTAG, &os)){
// 		cmn_err(CE_WARN, "%s: dmu_objset_hold FAIL !!!", __func__);
// 		return (err);
// 	}
	
// 	spa_id = spa_guid(dmu_objset_spa(os));
// 	dsl_id = os->os_dsl_dataset->ds_object;

// 	ret_ptr = kmem_alloc(ZFS_MULTICLUS_NVLIST_MAXSIZE, KM_SLEEP);

// 	group = zfs_multiclus_get_current_group(spa_id );
// 	if(NULL == group )
// 	{
// 		cmn_err(CE_WARN, "%s: FAIL to find the Group!!!", __func__);
// 		kmem_free(ret_ptr, ZFS_MULTICLUS_NVLIST_MAXSIZE);
// 		dmu_objset_rele(os, FTAG);
// 		return (-1);
// 	}

// 	for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i++) {
// 		group_record = &group->multiclus_group[i];
// 		if (group_record->spa_id == spa_id){
// 			zfs_multiclus_get_fsname(spa_id, group_record->os_id, fs_name);
// 			if (err = dmu_objset_hold(fs_name, FTAG, &subos)){
// 				cmn_err(CE_WARN, "%s: dmu_objset_hold Subos FAIL !!!", __func__);
// 				kmem_free(ret_ptr, ZFS_MULTICLUS_NVLIST_MAXSIZE);
// 				dmu_objset_rele(os, FTAG);
// 				return (err);
// 			}
// 		}
// 	}
	
// 	for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i++) {
// 		zfs_multiclus_stat_arg_t stat_arg;
// 		group_record = &group->multiclus_group[i];
// 		if (!group_record->used || 
// 			(group_record->spa_id == spa_id) || 
// 			group_record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
// 			continue;
// 		}
// 		bzero(&stat_arg, sizeof(zfs_multiclus_stat_arg_t));
// 		stat_arg.return_ptr = (uintptr_t)ret_ptr;
// 		stat_arg.return_size = ZFS_MULTICLUS_NVLIST_MAXSIZE;
// 		err = zfs_proc_stat(subos, SC_IOSTAT, SHARE_WAIT, &stat_arg,
// 		group_record->spa_id, group_record->os_id, APP_GROUP);
// 		if (err == 0) {
// 			if (nvlist_unpack((void *)(uintptr_t)stat_arg.return_ptr,
// 				stat_arg.return_size, &iostat[nvcnt], 0) != 0)
// 			{
// 				err = 1;
// 				break;
// 			}
// 			if (nvlist_lookup_nvlist(iostat[nvcnt], ZPOOL_CONFIG_VDEV_TREE,
// 					&nvroot) != 0)
// 			{
// 				nvlist_free(iostat[nvcnt]);
// 				err = 1;
// 				break;
// 			}
// 			if (nvlist_lookup_string(iostat[nvcnt], ZPOOL_CONFIG_POOL_NAME,
// 					&fnptr) != 0)
// 			{
// 				nvlist_free(iostat[nvcnt]);
// 				err = 1;
// 				break;
// 			}
// 			rmpname[nvcnt] = fnptr;
// 			if (nvlist_lookup_uint64_array(nvroot, ZPOOL_CONFIG_VDEV_STATS,
// 				(uint64_t **)&cntvs, &c) != 0)
// 			{
// 				nvlist_free(iostat[nvcnt]);
// 				err = 1;
// 				break;
// 			}
// 			totalvs.vs_space += cntvs->vs_space;
// 			totalvs.vs_alloc += cntvs->vs_alloc;
// 			totalvs.vs_ops[ZIO_TYPE_READ] += cntvs->vs_ops[ZIO_TYPE_READ];
// 			totalvs.vs_ops[ZIO_TYPE_WRITE] += cntvs->vs_ops[ZIO_TYPE_WRITE];
// 			totalvs.vs_bytes[ZIO_TYPE_READ] += cntvs->vs_bytes[ZIO_TYPE_READ];
// 			totalvs.vs_bytes[ZIO_TYPE_WRITE] += cntvs->vs_bytes[ZIO_TYPE_WRITE];
// 			nvchild[nvcnt++] = nvroot;			
// 		}else {
// 			break;
// 		}
// 		bzero(ret_ptr, ZFS_MULTICLUS_NVLIST_MAXSIZE);
// 	}
// 	dmu_objset_rele(subos, FTAG);

// 	if(0 == err)
// 	{
// 		VERIFY(nvlist_alloc(rmconfig, NV_UNIQUE_NAME, KM_SLEEP) == 0);
// 		VERIFY(nvlist_add_nvlist_array(*rmconfig,
// 			ZPOOL_CONFIG_MULTICLUS_VDEV, nvchild, nvcnt) == 0);
// 		VERIFY(nvlist_add_string_array(*rmconfig,
// 			ZPOOL_CONFIG_MULTICLUS_FSNAME, rmpname, nvcnt) == 0);
// 		VERIFY(nvlist_add_string(*rmconfig, ZPOOL_CONFIG_MULTICLUS_GNAME,
// 				group->group_name) == 0);
// 	}
// 	for(i=0; i<nvcnt; i++)
// 	{
// 		nvlist_free(iostat[i]);
// 	}

// 	if(0 == err)
// 	{
// 		bcopy(&totalvs, newvs, sizeof(vdev_stat_t));
// 	}

// 	kmem_free(ret_ptr, ZFS_MULTICLUS_NVLIST_MAXSIZE);
// 	dmu_objset_rele(os, FTAG);

// 	return (err);
// }


// int 
// zfs_proc_scrub(objset_t *os, ushort_t op, share_flag_t wait_flag,
//     zfs_multiclus_stat_arg_t *stat_arg, uint64_t dst_spa, uint64_t dst_os,
//     msg_orig_type_t msg_orig)
// {
// 	int error;
// 	uint64_t msg_len;
// 	uint64_t return_len;
// 	zfs_group_stat_msg_t *stat_msg;
// 	zfs_group_header_t *msg_header = NULL;	


// 	msg_len = sizeof(zfs_group_stat_msg_t) + stat_arg->arg_size;
// 	return_len = sizeof(zfs_group_stat_msg_t) + stat_arg->return_size;

// 	stat_msg = kmem_zalloc(msg_len, KM_SLEEP);
// 	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
// 	if (stat_arg->arg_size > 0) {
// 		bcopy((void *)(uintptr_t)stat_arg->arg_ptr, stat_msg->call.stat.stat, stat_arg->arg_size);
// 	}
// 	bcopy(stat_arg, &(stat_msg->call.stat.arg), sizeof(zfs_multiclus_stat_arg_t));

// 	zfs_group_build_header(os, msg_header, ZFS_GROUP_CMD_SCRUB, 
// 		wait_flag, op, msg_len, return_len, dst_spa, dst_os, 0, 0, 0, 0, 0, 
// 		MSG_REQUEST, msg_orig);
// 	error = zfs_client_send_to_server(os, msg_header, (zfs_msg_t *)stat_msg, B_FALSE);

// 	if (stat_msg != NULL)
// 		kmem_free(stat_msg, msg_len);
// 	if (msg_header != NULL)
// 		kmem_free(msg_header, sizeof(zfs_group_header_t));
	
// 	return (error);
// }

int 
zfs_proc_dir_low(objset_t *os, ushort_t op, share_flag_t wait_flag,
    zfs_multiclus_stat_arg_t *stat_arg, uint64_t dst_spa, uint64_t dst_os,
    msg_orig_type_t msg_orig)
{
	int error = 0;
	uint64_t msg_len = 0;
	uint64_t return_len = 0;
	zfs_group_stat_msg_t *stat_msg = NULL;
	zfs_group_header_t *msg_header = NULL;
	

	msg_len = sizeof(zfs_group_stat_msg_t) + stat_arg->arg_size;
	return_len = sizeof(zfs_group_stat_msg_t) + stat_arg->return_size;

	stat_msg = kmem_zalloc(msg_len, KM_SLEEP);
	msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	if (stat_arg->arg_size > 0) {
		bcopy((void *)(uintptr_t)stat_arg->arg_ptr, stat_msg->call.stat.stat, stat_arg->arg_size);
	}
	bcopy(stat_arg, &(stat_msg->call.stat.arg), sizeof(zfs_multiclus_stat_arg_t));

	zfs_group_build_header(os, msg_header, ZFS_GROUP_CMD_DIRLD, 
		wait_flag, op, msg_len, return_len, dst_spa, dst_os, 0, 0, 0, 0, 0, 
		MSG_REQUEST, msg_orig);
	error = zfs_client_send_to_server(os, msg_header, (zfs_msg_t *)stat_msg, B_FALSE);
	
	if (stat_msg != NULL)
		kmem_free(stat_msg, msg_len);
	if (msg_header != NULL)
		kmem_free(msg_header, sizeof(zfs_group_header_t));

	return (error);
}

 	
// int zfs_client_get_dirlowdatalist(zfs_sb_t *zsb, 
// 	uint64_t  *cookiep, void * buf, uint64_t *bufsize)
// {
// 	zfs_multiclus_stat_arg_t stat_arg;
// 	dir_lowdata_carrier_t *dirld_carrier = kmem_zalloc(sizeof(dir_lowdata_carrier_t), KM_SLEEP);

// 	if(NULL == dirld_carrier){
// 		return (ENOMEM);
// 	}

// 	dirld_carrier->cookie = *cookiep;
// 	dirld_carrier->bufsize = *bufsize;
// 	stat_arg.arg_ptr = (uintptr_t)(dirld_carrier);
// 	stat_arg.arg_size = (uintptr_t)sizeof(dir_lowdata_carrier_t);
// 	stat_arg.return_ptr = (uintptr_t)(dirld_carrier);
// 	stat_arg.return_size = (uintptr_t)sizeof(dir_lowdata_carrier_t);
	
// //	int err = zfs_proc_dir_low(zfsvfs->z_os, SC_FS_DIRLOWDATALIST, SHARE_WAIT, &stat_arg,
// //		    zfsvfs->z_os->os_master_spa,zfsvfs->z_os->os_master_os,APP_USER);
// 	int err = zfs_proc_dir_low(zsb->z_os, SC_FS_DIRLOWDATALIST, SHARE_WAIT, &stat_arg,
// 		    zsb->z_os->os_master_spa,zsb->z_os->os_master_os,APP_USER);
	
// 	if (err == 0) {
// 		if(dirld_carrier->dir_lowdata.ret != 0){
// 			err = dirld_carrier->dir_lowdata.ret;
// 			cmn_err(CE_WARN, "ret=%d: get dirlowdatalist from master FAIL!!!",err);
// 		}else{
// 			*bufsize = dirld_carrier->bufsize;
// 			*cookiep = dirld_carrier->cookie;
// 			bcopy(dirld_carrier->buf.dbuf, buf, dirld_carrier->bufsize);
// 		}
// 	}else{
// 		cmn_err(CE_WARN, "ret=%d: get dirlowdatalist from master FAIL!!",err);
// 	}

// 	if(NULL != dirld_carrier){
// 		kmem_free(dirld_carrier, sizeof(dir_lowdata_carrier_t));
// 	}
	
// 	return (err);
// }

int zfs_client_get_dirquota(zfs_sb_t *zsb,
 	uint64_t dir_obj, zfs_dirquota_t *dirquota)
{
 	zfs_multiclus_stat_arg_t stat_arg;
 	dir_lowdata_t dir_lowdata = {0};

 	dir_lowdata.pairvalue.object = dir_obj;
 	stat_arg.arg_ptr = (uintptr_t)(&dir_lowdata);
	stat_arg.arg_size = (uintptr_t)sizeof(dir_lowdata_t);
 	stat_arg.return_ptr = (uintptr_t)dirquota;
 	stat_arg.return_size = (uintptr_t)sizeof(zfs_dirquota_t);

 	int err = zfs_proc_dir_low(zsb->z_os, SC_FS_DIR_QUOTA, SHARE_WAIT, &stat_arg,
 		    zsb->z_os->os_master_spa,zsb->z_os->os_master_os,APP_USER);
	
 	if (err == 0) {
 		if(dir_lowdata.ret != 0){
 			err=dir_lowdata.ret;
 			cmn_err(CE_WARN, "ret=%d: get dirquota from master FAIL!!!",err);
 		}
 	}else{
 		cmn_err(CE_WARN, "ret=%d: get dirquota from master FAIL!!",err);
 	}
	
 	return (err);
}

  
// int zfs_client_get_dirquotalist(zfs_sb_t * zsb,  	
// 	uint64_t  *cookiep, void * buf, uint64_t *bufsize)
// {
// 	zfs_multiclus_stat_arg_t stat_arg;
// 	dir_lowdata_carrier_t *dirld_carrier = kmem_zalloc(sizeof(dir_lowdata_carrier_t), KM_SLEEP);

// 	if(NULL == dirld_carrier){
// 		return (ENOMEM);
// 	}
		
// 	dirld_carrier->cookie = *cookiep;
// 	dirld_carrier->bufsize = *bufsize;
// 	stat_arg.arg_ptr = (uintptr_t)(dirld_carrier);
// 	stat_arg.arg_size = (uintptr_t)sizeof(dir_lowdata_carrier_t);
// 	stat_arg.return_ptr = (uintptr_t)(dirld_carrier);
// 	stat_arg.return_size = (uintptr_t)sizeof(dir_lowdata_carrier_t);
	
// //	int err = zfs_proc_dir_low(zfsvfs->z_os, SC_FS_DIRQUOTALIST, SHARE_WAIT, &stat_arg,
// //		    zfsvfs->z_os->os_master_spa,zfsvfs->z_os->os_master_os,APP_USER);
// 	int err = zfs_proc_dir_low(zsb->z_os, SC_FS_DIRQUOTALIST, SHARE_WAIT, &stat_arg,
//     	    zsb->z_os->os_master_spa,zsb->z_os->os_master_os,APP_USER);
	
// 	if (err == 0) {
// 		if(dirld_carrier->dir_lowdata.ret != 0){
// 			err= dirld_carrier->dir_lowdata.ret;
// 			cmn_err(CE_WARN, "ret=%d: get dirquotalist from master FAIL!!!",err);
// 		}else{
// 			*bufsize = dirld_carrier->bufsize;
// 			*cookiep = dirld_carrier->cookie;
// 			bcopy(dirld_carrier->buf.qbuf, buf, dirld_carrier->bufsize);
// 		}
// 	}else{
// 		cmn_err(CE_WARN, "ret=%d: get dirquotalist from master FAIL!!",err);
// 	}
	
// 	if(NULL != dirld_carrier){
// 		kmem_free(dirld_carrier, sizeof(dir_lowdata_carrier_t));
// 	}
	
// 	return (err);
// }


// int zfs_set_group_scrub(char *poolname, uint64_t cookie)
// {
// 	int i;
// 	int err;
// 	objset_t *os = NULL;
// 	fs_scrub_t sc_info;
// 	uint64_t spa_id;
// 	uint64_t dsl_id;
// 	char fs_name[MAX_FSNAME_LEN] = {0};
// 	objset_t *subos = NULL;
// 	zfs_multiclus_group_record_t *group_record;
// 	zfs_multiclus_group_t *group = NULL;
// 	int node_num = 0;
// 	int current = 0;

// 	if (zfs_multiclus_enable() == B_FALSE)
// 		return (-1);

// 	if (err = dmu_objset_hold(poolname, FTAG, &os)){
// 		cmn_err(CE_WARN, "%s: dmu_objset_hold FAIL !!!", __func__);
// 		return (err);
// 	}
	
// 	spa_id = spa_guid(dmu_objset_spa(os));
// 	dsl_id = os->os_dsl_dataset->ds_object;


// 	group = zfs_multiclus_get_current_group(spa_id );
// 	if(NULL == group )
// 	{
// 		cmn_err(CE_WARN, "%s: FAIL to find the Group!!!", __func__);
// 		dmu_objset_rele(os, FTAG);
// 		return (-1);
// 	}

// 	for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i++) {
// 		group_record = &group->multiclus_group[i];
// 		if (group_record->spa_id == spa_id){
// 			zfs_multiclus_get_fsname(spa_id, group_record->os_id, fs_name);
// 			if (err = dmu_objset_hold(fs_name, FTAG, &subos)){
// 				cmn_err(CE_WARN, "%s: dmu_objset_hold Subos FAIL !!!", __func__);
// 				dmu_objset_rele(os, FTAG);
// 				return (err);
// 			}
// 		}
// 		if(group_record->used && group_record->spa_id != spa_id)
// 			node_num++;
// 	}

// 	for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i++) {
// 		zfs_multiclus_stat_arg_t stat_arg;
// 		group_record = &group->multiclus_group[i];
// 		if (!group_record->used || (group_record->spa_id == spa_id)){
// 			continue;
// 		}
// 		bzero(&stat_arg, sizeof(zfs_multiclus_stat_arg_t));
// 		sc_info.spa_id = group_record->spa_id;
// 		sc_info.sc_op = cookie;
// 		stat_arg.arg_ptr = (uintptr_t)(&sc_info);
// 		stat_arg.arg_size = sizeof(fs_scrub_t);
// 		stat_arg.return_ptr= (uintptr_t)(&sc_info);
// 		stat_arg.return_size= sizeof(fs_scrub_t);
// 		err = zfs_proc_scrub(subos, SC_SCRUB, SHARE_WAIT, &stat_arg,
// 		group_record->spa_id, group_record->os_id, APP_GROUP);
// 		current++;
// 		if (err == 0) {
// 			cmn_err(CE_WARN, "%s:total node = %d, current = %d, fs = %s, "
// 				"Success !", __func__, node_num, current, group_record->fsname);
// 		}else {
// 			cmn_err(CE_WARN, "%s:total node = %d, current = %d, fs = %s, "
// 				"Fail !", __func__, node_num, current, group_record->fsname);
// 			break;
// 		}
// 	}
// 	dmu_objset_rele(subos, FTAG);

// 	dmu_objset_rele(os, FTAG);

// 	return (err);
// }


// int zfs_client_set_dir_low(zfs_sb_t *zsb, const char *dsname, nvpairvalue_t *pairvalue)
// {	
// 	int i;
// 	int err=0;
// 	int remote_err=0;
// 	zfs_multiclus_stat_arg_t stat_arg={0};
// 	dir_lowdata_t dl_info={0};
	
// 	if (zfs_multiclus_enable() == B_FALSE)
// 		return (-1);		                           

// 	bcopy(pairvalue, &dl_info.pairvalue, sizeof(nvpairvalue_t));
	
// 	stat_arg.arg_ptr = (uintptr_t)(&dl_info);
// 	stat_arg.arg_size = sizeof(dir_lowdata_t);
// 	stat_arg.return_ptr= (uintptr_t)(&remote_err);
// 	stat_arg.return_size= sizeof(remote_err);
// //	err = zfs_proc_dir_low(zfsvfs->z_os, SC_DIR_LOW, SHARE_WAIT, &stat_arg,
// //		zfsvfs->z_os->os_master_spa, zfsvfs->z_os->os_master_os, APP_GROUP);
// 	err = zfs_proc_dir_low(zsb->z_os, SC_DIR_LOW, SHARE_WAIT, &stat_arg,
// 		zsb->z_os->os_master_spa, zsb->z_os->os_master_os, APP_GROUP);	
// 	if (err == 0) {
// 		cmn_err(CE_WARN, "%s: Send set_dir_lowdata message to master Success!!!", 
// 			__func__);
// 		if(remote_err != 0){
// 			err = remote_err;
// 			cmn_err(CE_WARN, "remote_err=%d: master set dirlowdata FAIL!!!",
// 				remote_err);
// 		}
// 	}

// 	return (err);
// }


int zfs_client_set_dirlow_backup(znode_t *zp, 
	nvpairvalue_t *pairvalue, zfs_multiclus_node_type_t m_node_type)
{	
	int err = 0;
	int remote_err = 0;
	dir_lowdata_t *dl_info = kmem_zalloc(sizeof(dir_lowdata_t), KM_SLEEP);
	zfs_multiclus_stat_arg_t stat_arg; //={0};
	uint64_t dst_spa = 0;
	uint64_t dst_os = 0;
	uint64_t dst_object = 0;
	zfs_multiclus_group_record_t *record = NULL;
	
	record = zfs_multiclus_get_group_master(ZTOZSB(zp)->z_os->os_group_name, m_node_type);
	if(record == NULL || record->node_status.status == ZFS_MULTICLUS_NODE_OFFLINE){
		if (NULL != dl_info)
			kmem_free(dl_info, sizeof(dir_lowdata_t));
		return EPROTO;
	}

	dst_spa = record->spa_id;
	dst_os = record->os_id;

	switch (m_node_type)
	{
		case ZFS_MULTICLUS_MASTER2:
			pairvalue->object = dst_object = zp->z_group_id.master2_object;
			if(dst_object != -1 && dst_object != 0)
			{
				dst_spa = zp->z_group_id.master2_spa;
				dst_os = zp->z_group_id.master2_objset;
			}
			break;

		case ZFS_MULTICLUS_MASTER3:
			pairvalue->object = dst_object = zp->z_group_id.master3_object;
			if(dst_object != -1 && dst_object != 0)
			{
				dst_spa = zp->z_group_id.master3_spa;
				dst_os = zp->z_group_id.master3_objset;
			}
			break;

		case ZFS_MULTICLUS_MASTER4:
			pairvalue->object = dst_object = zp->z_group_id.master4_object;
			if(dst_object != -1 && dst_object != 0)
			{
				dst_spa = zp->z_group_id.master4_spa;
				dst_os = zp->z_group_id.master4_objset;
			}
			break;

		default:
			cmn_err(CE_WARN, "%s, invalid node type, node_type = %d",
				__func__, m_node_type);
			if (NULL != dl_info)
				kmem_free(dl_info, sizeof(dir_lowdata_t));
			return (EPROTO);
	}
	
	if(dst_object == -1 || dst_object == 0){
		cmn_err(CE_WARN, "%s dst_object is %llu", __func__, (u_longlong_t)dst_object);
		if (NULL != dl_info)
			kmem_free(dl_info, sizeof(dir_lowdata_t));
		return (ENOENT);
	}
	
	bcopy(pairvalue, &dl_info->pairvalue, sizeof(nvpairvalue_t));
	
	stat_arg.arg_ptr = (uintptr_t)(dl_info);
	stat_arg.arg_size = sizeof(dir_lowdata_t);
	stat_arg.return_ptr= (uintptr_t)(&remote_err);
	stat_arg.return_size= sizeof(remote_err);
	err = zfs_proc_dir_low(ZTOZSB(zp)->z_os, SC_DIR_LOW, SHARE_WAIT, &stat_arg,
		dst_spa, dst_os, APP_GROUP);
	if (err == 0) {
		if(remote_err != 0){
			err = remote_err;
			cmn_err(CE_WARN, "ret=%d: master set dirlowdata FAIL!!!", remote_err);
		}
	}

	if (NULL != dl_info)
		kmem_free(dl_info, sizeof(dir_lowdata_t));
	return (err);
}


void *zfs_group_alloc_data(zfs_group_header_t *msg_header, uint64_t data_num, uint64_t *len)
{
	uint64_t	data_len;
	void	*group_data = NULL;

	data_len = (msg_header->length > msg_header->out_length) ? msg_header->length : msg_header->out_length;
	if (msg_header->command == ZFS_GROUP_CMD_DATA && msg_header->operation == DATA_WRITE &&
		(msg_header->op_type == MSG_REQUEST)) {
		zfs_group_data_msg_t *write_data = NULL;
		zfs_group_data_vectors_t *datavps = NULL;

		datavps = kmem_zalloc(sizeof(zfs_group_data_vectors_t), KM_SLEEP);
		datavps->iovps = kmem_zalloc(sizeof(struct iovec) * data_num, KM_SLEEP);
		datavps->vector_num = data_num;

		data_len = sizeof(zfs_group_data_msg_t);
		write_data = vmem_zalloc(data_len, KM_SLEEP);
		bcopy(&datavps, write_data->call.data.data, sizeof(uint64_t));
		group_data = (void *)write_data;
	} else {
		group_data = vmem_zalloc(data_len, KM_SLEEP);
	}

	*len = data_len;
	return (group_data);
}

void zfs_group_fill_data(zfs_group_header_t *hdr, uint64_t data_index, 
    uint64_t data_offset, uint64_t data_len, void *datap, void *dst_datap, void *dst_header)
{
	if (hdr->command == ZFS_GROUP_CMD_DATA && hdr->operation == DATA_WRITE &&
	    (hdr->op_type == MSG_REQUEST)) {
		zfs_group_data_vectors_t *datavps = NULL;
		struct iovec *iovp = NULL;
		void *app_data = NULL;
		size_t write_hdr_len = 0;
		zfs_group_data_msg_t *write_data = (zfs_group_data_msg_t *)dst_datap;

		app_data = NULL;
		write_hdr_len = sizeof(zfs_group_data_msg_t) - 8;
		bcopy(write_data->call.data.data, &datavps, sizeof(uint64_t));
		if (data_index == 0) {
			bcopy((void *)hdr, (void *)dst_header, sizeof(zfs_group_header_t));
			bcopy(datap, (void *)((char *)write_data), write_hdr_len);
			app_data = (char *)datap + write_hdr_len;
			iovp = &datavps->iovps[0];
			
			iovp->iov_base = vmem_zalloc((data_len - write_hdr_len), KM_SLEEP);
			bcopy(app_data, iovp->iov_base, (data_len - write_hdr_len));
			iovp->iov_len = data_len - write_hdr_len;
		} else {
			iovp = &datavps->iovps[data_index];
			iovp->iov_base = vmem_zalloc(data_len, KM_SLEEP);
			bcopy(datap, iovp->iov_base, data_len);
			iovp->iov_len = data_len;
		}
	} else {
		bcopy(hdr, dst_header, sizeof(zfs_group_header_t));
		bcopy(datap, (char *)dst_datap, data_len);
	}
}

void zfs_group_free_data(zfs_group_header_t *msg_header, void *data, uint64_t data_len)
{
	zfs_msg_t *msg = (zfs_msg_t *)data;


	if (msg_header->command == ZFS_GROUP_CMD_DATA && msg_header->operation == DATA_WRITE) {
		int i;
		zfs_group_data_vectors_t *datavps = NULL;
		zfs_group_data_msg_t *write_data = NULL;

		write_data = (zfs_group_data_msg_t *)msg;
		bcopy(write_data->call.data.data, &datavps, sizeof(uint64_t));

		for (i = 0; i < datavps->vector_num; i ++) {
			vmem_free(datavps->iovps[i].iov_base, datavps->iovps[i].iov_len);
		}

		kmem_free(datavps->iovps, sizeof(struct iovec) * datavps->vector_num);
		kmem_free(datavps, sizeof(zfs_group_data_vectors_t));
	}

	vmem_free(data, data_len);
}

/*
 * zfs_group_broadcast_unflag_overquota
 * 
 * description: 
 * 		The master node calls this function to broadcast to all slave nodes
 * during dirquota expansion, so that the slave nodes can unflag overquota field 
 * upon receiving this broadcast message.
 */

int zfs_group_broadcast_unflag_overquota(znode_t *zp, uint64_t old_dirquota_id)
{
	int err;
	int i = 0;
	zfs_group_dirquota_id_t dirquota_id;
	zfs_multiclus_group_t *group_current = NULL;
	zfs_multiclus_group_record_t *record = NULL;
	zfs_group_cmd_arg_t cmd_arg = {0};
	int remote_err = 0;
	
	if (B_FALSE == zfs_multiclus_enable())
		return (-1);
	
	/* get group(zfs_multiclus_group_t) */
	group_current = zfs_multiclus_get_current_group(zp->z_group_id.master_spa);
	
	/* build message body */
	dirquota_id.old_dirquota_id = old_dirquota_id;
	dirquota_id.new_dirquota_id = zp->z_dirquota;
	cmd_arg.arg_ptr = (uintptr_t)(&dirquota_id);
	cmd_arg.arg_size = (uintptr_t)sizeof(dirquota_id);
	cmd_arg.return_ptr = (uintptr_t)&remote_err;
	cmd_arg.return_size = (uintptr_t)sizeof(int);
	
	/* iterate group nodes */ 
	for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i++) {
		record = &(group_current->multiclus_group[i]);
		if(record->used && ZFS_MULTICLUS_MASTER != record->node_type) {
			/* process unflag */
			err = zfs_proc_cmd(ZTOZSB(zp), SC_UNFLAG_OVERQUOTA, SHARE_WAIT, &cmd_arg,
					record->spa_id, record->os_id, 0, APP_GROUP);
		}
	}

	return (0);
}
#endif
