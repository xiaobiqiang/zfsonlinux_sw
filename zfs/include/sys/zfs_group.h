#ifndef	_SYS_FS_ZFS_GROUP_H
#define	_SYS_FS_ZFS_GROUP_H

#ifdef _KERNEL
#include <sys/isa_defs.h>
#include <sys/types32.h>
#include <sys/attr.h>
#include <sys/list.h>
#include <sys/dmu.h>
#include <sys/sa.h>
#include <sys/zfs_vfsops.h>
#include <sys/rrwlock.h>
#include <sys/zfs_sa.h>
#include <sys/zfs_stat.h>
#endif
#include <sys/zfs_acl.h>
#include <sys/zil.h>
#include <sys/zfs_multiclus.h>
//#include <sys/pathname.h>
#include <sys/zfs_vnops.h>
#include <sys/vnode.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SMB_STREAM_PREFIX "SUNWsmb"
#define	SMB_STREAM_PREFIX_LEN (sizeof (SMB_STREAM_PREFIX) - 1)

typedef struct acl {
	int		a_type;		/* the type of ACL entry */
	uid_t		a_id;		/* the entry in -uid or gid */
	o_mode_t	a_perm;		/* the permission field */
} aclent_t;

#define	ZFS_GROUP_MAGIC	0x0001020304050607ULL
#define ZFS_GROUP_ROUTE_MIN_IO  1024
#define ZFS_GROUP_ROUTE_MAX_AVAIL ((uint64_t)1 << 40)
#define ZFS_GROUP_SEND_WAIT	10*1000*1000
#define ZFS_GROUP_NOTIFY_WAIT 1*1000*1000


#define ZFS_RESEND_MAX_NUMBER   2

#define	GZFS_CMD_NAME		3

#define ZFS_CLINT_LOCAL_MAX_TX   5
#define ZFS_CLINT_REMOTE_MAX_TX	120
#define ZFS_CLINT_LOCAL_HOLD_MAX 120

#define ZFS_DATA1_MIGRATED 0x00000000ffffffff
#define ZFS_DATA2_MIGRATED 0xffffffff00000000

typedef enum share_flag {
	SHARE_WAIT_ONE = 1,
	SHARE_WAIT,
	SHARE_NOTHR,
	SHARE_NOWAIT,
	SHARE_FLAG_MAX
}share_flag_t;

typedef struct zfs_group_timestruc {
	int32_t	tv_sec;
	int32_t	tv_nsec;
} zfs_group_timestruc_t;

typedef struct zfs_group_vattr {
	uint64_t	va_rsize;	/* Real file size in bytes */
	uint64_t	va_csize;	/* Current file size in bytes */
	uint64_t	va_nblocks;	/* # of blocks allocated */
	uint64_t	va_rdev;	/* Raw device */
	mode_t		va_mode;	/* File access mode */
	uint64_t	va_uid;		/* User id */
	uint64_t	va_gid;		/* Group id */
	uint32_t	va_nlink;	/* Number of references to file */
	zfs_group_timestruc_t	va_atime;	/* Time of last access */
	zfs_group_timestruc_t	va_mtime;	/* Time of last modification */
	zfs_group_timestruc_t	va_ctime;	/* Time file ``created'' */
	uint32_t	va_mask;	/* Bit-mask of attributes */
	uint32_t	va_type;	/* Vnode type (for create) */
	uint32_t	va_status;	/* Inode status attributes */
	char		va_pad[4];	/* Force pad */
} zfs_group_vattr_t;

#define	ZFS_GROUP_TIMESPEC32_TO_TIMESPEC(ts, ts32)	{	\
	(ts)->tv_sec = (time_t)(ts32)->tv_sec;		\
	(ts)->tv_nsec = (ts32)->tv_nsec;			\
}

#define	ZFS_GROUP_TIMESPEC_TO_TIMESPEC32(ts32, ts)	{	\
	(ts32)->tv_sec = (time32_t)(ts)->tv_sec;	\
	(ts32)->tv_nsec = (ts)->tv_nsec;			\
}


typedef enum name_operation {
	NAME_CREATE		= 1,
	NAME_REMOVE,
	NAME_REMOVE_DATA,
	NAME_MKDIR,
	NAME_RMDIR,
	NAME_LINK,
	NAME_RENAME,
	NAME_SYMLINK,
	NAME_ACL,
	NAME_LOOKUP,
	NAME_ZNODE_SETATTR,
	NAME_DIRQUOTA,
	NAME_DIRLOWDATA,
	NAME_CREATE_DATA,
	NAME_MAX_OP
}name_operation_t;


/*
 * NGROUPS_MAX_DEFAULT: *MUST* match NGROUPS_MAX value in limits.h.
 * Remember that the NFS protocol must rev. before this can be increased
 */
#define	NGROUPS_MAX_DEFAULT	16

typedef struct zfs_group_cred {
	uint32_t	cr_ref;		/* reference count */
	uid_t	cr_uid;			/* effective user id */
	gid_t	cr_gid;			/* effective group id */
	uid_t	cr_ruid;		/* real user id */
	gid_t	cr_rgid;		/* real group id */
	uid_t	cr_suid;		/* "saved" user id (from exec) */
	gid_t	cr_sgid;		/* "saved" group id (from exec) */
	uint32_t	cr_ngroups;		/* number of groups in cr_groups */
	gid_t	cr_groups[NGROUPS_MAX_DEFAULT];	/* supplementary group list */
} zfs_group_cred_t;

typedef enum msg_orig_type{
	APP_USER = 0,  /* Orig: slave; Dst: master (Msg from slave to master) */
	APP_GROUP    /* Orig: master; Dst: slave (Msg from master to slave) */
}msg_orig_type_t;

typedef enum msg_op_type{
	MSG_REQUEST = 1,
	MSG_REPLY,
	MSG_NOTIFY,
	MSG_MAX
}msg_op_type_t;

#define ZFS_GROUP_HDR_LENGTH	sizeof(zfs_group_header_t)

#define DATA_OBJECT_NAME	"%lld_%s"
typedef struct {
	void *extra_createp;
	size_t extra_create_plen;
}zfs_group_create_extra_t;

typedef struct {
	uint32_t	zg_attr_masksize;
	uint32_t	zg_attr_bitmap[XVA_MAPSIZE];
	uint64_t	zg_attr;
	uint64_t	zg_ctime[2];
	uint64_t	zg_scan[4];
	uint32_t	zg_magic;
} zfs_group_name_attr_t;

typedef struct zfs_group_name_create {
	zfs_group_vattr_t	vattr;		/* Vnode attributes - supplied */
	int32_t	ex;			/* Exclusive create flag. */
	int32_t	mode;			/* File mode */
	int32_t	flag;			/* Large file create flag */
	int32_t	create_type;
	int32_t	name_len;
	int32_t	xattr_len;
	int32_t	acl_len;
	int32_t dirlowdata_len;
	uint64_t master_object;
	uint64_t master_gen;
	char	pad[4];			/* Force pad */
} zfs_group_name_create_t;




typedef struct zfs_group_name_remove {
	zfs_group_object_t	id;			/* Id of file to be removed */
} zfs_group_name_remove_t;

typedef struct zfs_group_name_mkdir {
	zfs_group_vattr_t	vattr;		/* Vnode attributes - supplied */
	int32_t	name_len;
	int32_t	xattr_len;
	int32_t	acl_len;
} zfs_group_name_mkdir_t;

typedef struct zfs_group_name_rmdir {
	zfs_group_object_t	id;			/* Id of directory to be removed */
} zfs_group_name_rmdir_t;


typedef struct zfs_group_name_link {
	zfs_group_object_t	id;
} zfs_group_name_link_t;

typedef struct zfs_group_name_lookup {
	uint64_t	lookup_flags;
}zfs_group_name_lookup_t;

typedef struct zfs_group_name_rename {
	zfs_group_object_t	new_parent_id;	/* New parent id -- given */
	zfs_group_object_t	oid;		/* Old id, may be 0 */
	zfs_group_object_t	nid;		/* New id, may be 0 */
	int32_t	osize;		/* Number of characters in old component */
	int32_t	nsize;		/* Number of characters in new component */
} zfs_group_name_rename_t;

typedef struct zfs_group_name_symlink {
	zfs_group_vattr_t	vattr;	/* Vnode attributes - supplied */
	int32_t	comp_size;	/* Number of characters in component */
	int32_t	path_size;	/* Number of characters in symlink path */
} zfs_group_name_symlink_t;

typedef struct zfs_group_name_acl {
	int32_t	set;
	int32_t	mask;			/* Acl mask */
	int32_t	aclcnt;			/* Number of acl entries */
	int32_t	dfaclcnt;		/* Number of default acl entries */
	uint64_t	aclsz;
	uint64_t	aclflags;
	char	acls[8];
} zfs_group_name_acl_t;

typedef struct zfs_group_name_dirlowdata {
	uint64_t lowdata;
	uint64_t lowdata_period;
	uint64_t lowdata_delete_period;
	uint64_t lowdata_period_unit;
	uint64_t lowdata_criteria;
} zfs_group_name_dirlowdata_t;

typedef struct zfs_group_name_arg {
	union {
		zfs_group_name_create_t	create;
		zfs_group_name_remove_t	remove;
		zfs_group_name_mkdir_t	mkdir;
		zfs_group_name_rmdir_t	rmdir;
		zfs_group_name_link_t	link;
		zfs_group_name_rename_t	rename;
		zfs_group_name_symlink_t	symlink;
		zfs_group_name_acl_t		acl;
	} p;
	uint64_t dirquota;
	uint64_t dirlowdata;
	uint64_t bquota;
	boolean_t	b_get_rpn;
} zfs_group_name_arg_t;

typedef struct zfs_group_name {
	zfs_group_object_t	parent_object;		/* Parent id -- given */
	zfs_group_name_arg_t	arg;		/* Name specific args for the op */
	uint64_t	flags;
	zfs_group_cred_t	cred;		/* Credentials */
	char	component[8];		/* Ascii name(s) string */
} zfs_group_name_t;

typedef struct zfs_group_pathname {
	char	pn_buf[MAXPATHLEN];		/* underlying storage */
	size_t	pn_pathlen;		/* remaining length */
	size_t	pn_bufsize;		/* total size of pn_buf */
} zfs_group_pathname_t;

typedef struct zfs_group_znode_record {
	zfs_group_object_t	object_id;
	zfs_group_phys_t	object_phy;
	uint64_t	object_blksz;
	zfs_group_pathname_t	rpn;
} zfs_group_znode_record_t;

typedef struct zfs_group_name2 {
	zfs_group_object_t	parent_id;	/* Parent id -- given */
	zfs_group_object_t	new_id;	/* New id -- returned */
	zfs_group_znode_record_t	nrec;
	zfs_group_name_arg_t	arg;	/* returned data info */
	char	component[8];	/* returned acl (NAME_acl req only) */
} zfs_group_name2_t;

#define ZFS_GROUP_MAX_ACL_ENTRIES   16
#define	ZFS_GROUP_MAX_NAME_LEN  \
	(sizeof (zfs_group_name2_t) +   \
	 2 * MAX_ACL_ENTRIES * sizeof (aclent_t) + \
	 ZFS_DIR_LOWDATA_MSG_LEN)


typedef struct zfs_group_name_msg {
	union {
		uint64_t		fill;
		zfs_group_name_t		name;
		zfs_group_name2_t		name2;
		char	i[ZFS_GROUP_MAX_NAME_LEN];
	} call;
} zfs_group_name_msg_t;

typedef struct zfs_group_data_read {
	uint64_t	offset;		/* File offset */
	uint64_t	data_ptr;		/* Buffer pointer address passed & returned */
	uint64_t	eof_ptr;
	uint64_t	len;		/* Block size */
	uint64_t	eof;
	zfs_group_cred_t	cred;
} zfs_group_data_read_t;

typedef struct zfs_group_data_write {
	uint64_t	offset;		/* File offset */
	uint64_t	addr;		/* Buffer pointer address passed & returned */
	uint64_t	len;		/* Block size */
	uint64_t	dir_quota;
	zfs_group_cred_t	cred;
} zfs_group_data_write_t;

typedef enum data_operation {
	DIR_READ = 1,
	LINK_READ,
	DATA_READ,
	DATA_WRITE,
	MIGRATE_DATA,
	XATTR_LIST,
	DATA_MAX_OP
}data_operation_t;

typedef enum data_direction {
	DATA_TO_MASTER = 0,
	DATA_TO_DATA
}data_direction_t;

typedef struct zfs_group_data_arg {
	union {
		zfs_group_data_read_t		read;
		zfs_group_data_write_t		write;
	} p;
	uint64_t dirquota;
	uint64_t dirlowdata;
} zfs_group_data_arg_t;


typedef struct zfs_group_data {
	zfs_group_object_t	id;			/* File id -- given  (1 if getbuf) */
	zfs_group_data_arg_t	arg;
	uint64_t	io_flags;
	char	data[8];
} zfs_group_data_t;


typedef struct zfs_group_data_msg {
	union {
		uint64_t	fill;
		zfs_group_data_t	data;
	} call;
} zfs_group_data_msg_t;


typedef struct zfs_group_data_vectors {
	uint64_t	vector_num;
	struct iovec	*iovps;
}zfs_group_data_vectors_t;

typedef enum znode_operation {
	ZNODE_SETATTR = 1,
	ZNODE_ACCESS,
	ZNODE_GET,
	ZNODE_FREE,
	ZNODE_SEARCH,
	ZNODE_MAX_OP
}znode_operation_t;


typedef struct fs_stat {
	uint64_t	refdbytes;
	uint64_t	availbytes;
	uint64_t	usedobjs;
	uint64_t	availobjs;
}fs_stat_t;

typedef struct fs_scrub {
	uint64_t	sc_op;
	uint64_t	spa_id;
}fs_scrub_t;

typedef struct dir_lowdata {
	char dsname[MAX_FSNAME_LEN];
	nvpairvalue_t pairvalue;
	int32_t ret;
	int32_t resv;
}dir_lowdata_t;

typedef struct dir_lowdata_carrier {
	dir_lowdata_t dir_lowdata;
	uint64_t	cookie;
	uint64_t	bufsize;
	union {
		zfs_dirlowdata_t dbuf[MAX_DIRLOWDATA_ENTRIES+1];
		zfs_dirquota_t qbuf[MAX_QUOTA_ENTRIES+1];
	}buf;
}dir_lowdata_carrier_t;

typedef struct fs_quota {
	uint64_t	master_object;
	uint64_t	dirquota_index;
	uint64_t	quota_over;
	uint64_t	flag;
}fs_quota_t;

typedef struct fs_dir_lowdata {
	uint64_t	master_object;
	uint64_t	dirlowdata_index;
	uint64_t	quota_over;
	zfs_dirlowdata_t	dirlowdata;
	int32_t  ret;
	int32_t  resv;
}fs_dir_lowdata_t;

typedef struct fs_data_file_attr {
	uint64_t	data_object;
	uint64_t	data_filesize;
	uint64_t	data_filenblks;
	uint64_t	data_fileblksz;
	int  ret;
}fs_data_file_attr_t;

typedef enum system_cmd_operation {
	SC_FS_STAT = 1,
	SC_FS_QUOTA,
	SC_FS_DIRLOWDATA,
	SC_FS_DIRQUOTA,
	SC_FS_USERQUOTA,
	SC_ZFS_IOCTL,
	SC_FS_GET_DATA_ATTR,
	SC_UNFLAG_OVERQUOTA,
	SC_ZFS_MIGRATE,
	SC_MAX_OP
}system_cmd_operation_t;

typedef enum system_stat_operation {
	SC_IOSTAT = 1,
	SC_STATUS,
	SC_STAT_MAX
}system_stat_operation_t;

typedef enum system_scrub_operation {
	SC_SCRUB = 1,
	SC_SCRUB_MAX
}system_scrub_operation_t;

typedef enum system_dir_lowdata_operation {
	SC_DIR_LOW = 1,
	SC_FS_DIRLOWDATALIST,
	SC_FS_DIR_QUOTA,
	SC_FS_DIRQUOTALIST,
	SC_DIR_LOW_MAX
}system_dir_lowdata_operation_t;

typedef struct zfs_group_cmd_arg {
	uint64_t	arg_ptr;
	uint64_t	arg_size;
	uint64_t	return_ptr;
	uint64_t	return_size;
} zfs_group_cmd_arg_t;


typedef struct zfs_group_cmd {
	zfs_group_cmd_arg_t	arg;
	char	cmd[8];
} zfs_group_cmd_t;


typedef struct zfs_group_cmd_msg {
	union {
		uint64_t		fill;
		zfs_group_cmd_t	cmd;
	} call;
} zfs_group_cmd_msg_t;



typedef struct zfs_multiclus_stat_arg {
	uint64_t	arg_ptr;
	uint64_t	arg_size;
	uint64_t	return_ptr;
	uint64_t	return_size;
} zfs_multiclus_stat_arg_t;


typedef struct zfs_group_iostat {
	zfs_multiclus_stat_arg_t	arg;
	char	stat[8];
} zfs_group_iostat_t;

typedef struct zfs_group_stat_msg {
	union {
		uint64_t	fill;
		zfs_group_iostat_t	stat;
	} call;
} zfs_group_stat_msg_t;

typedef struct zfs_group_reg {
	uint64_t	spa_id;
	uint64_t	os_id;
	uint64_t	hostid;
	zfs_multiclus_node_type_t	node_type;
	uint64_t	avail_size;
	uint64_t	used_size;
	uint64_t	load_ios;
	uint64_t	root;
	uint64_t	txg;
	uint8_t	rpc_addr[ZFS_MULTICLUS_RPC_ADDR_SIZE];
	uint8_t	fsname[MAX_FSNAME_LEN];
	uint8_t	group_name[MAXNAMELEN];
	uint64_t	group_name_len;
	node_status_t	node_status;
} zfs_group_reg_t;

typedef struct zfs_group_znode_setattr {
	zfs_group_vattr_t	vattr;	/* Vnode attrs, supplied & returned updated */
	uint_t	flags;		/* Utime flags */
	uint_t	bxattr;
	zfs_group_name_attr_t	xattr;
} zfs_group_znode_setattr_t;

typedef struct zfs_group_znode_access {
	uint_t	mode;		/* Utime flags */
	uint_t	flag;		/* Force pad */
} zfs_group_znode_access_t;

typedef struct zfs_group_znode_free {
	uint64_t	off;
	uint64_t	len;
	uint64_t	flag;
}zfs_group_znode_free_t;

typedef struct zfs_group_znode_arg {
	union {
		zfs_group_znode_setattr_t	setattr;
		zfs_group_znode_access_t	access;
		zfs_group_znode_free_t	free;
	} p;
} zfs_group_znode_arg_t;

typedef struct zfs_group_znode {
	zfs_group_object_t	id;		/* File id -- given */
	zfs_group_znode_arg_t	arg;	/* Ino specific arguments for the operation */
	zfs_group_cred_t	cred;	/* Credentials */
} zfs_group_znode_t;

typedef struct zfs_group_znode2 {
	zfs_group_znode_t	inp;	/* Inode input parameters */
	zfs_group_znode_record_t	zrec;	/* Inode instance record */
	char relativepath[MAXNAMELEN];
} zfs_group_znode2_t;


typedef struct zfs_group_znode_msg {
	union {
		uint64_t	fill;
		zfs_group_znode_t	znode;
		zfs_group_znode2_t	znode2;
	} call;
} zfs_group_znode_msg_t;


typedef enum notify_op {
	NOTIFY_SYSTEM_SPACE = 1,
	NOTIFY_FILE_SPACE,
	NOTIFY_FILE_INFO,
	NOTIFY_DATA_DIRTY,
	NOTIFY_MAX
}notify_op_t;

typedef struct zfs_group_notify_system_space {
	uint64_t	space_ref;
	uint64_t	space_avail;
	uint64_t	space_usedobjs;
	uint64_t	space_availobjs;
	uint64_t	sys_ios;
	uint64_t	space_spa;
	uint64_t	space_os;
}zfs_group_notify_system_space_t;

typedef enum {
	DIR_QUOTA = 1,
	GROUP_QUOTA,
	USER_QUOTA
}zfs_group_quota_type_t;

typedef enum {
	EXPAND_SPACE = 1,
	REDUCE_SPACE ,
	ADD_FILE,
	REMOVE_FILE
}zfs_group_used_op_type_t;

typedef enum {
	DATA_FILE1 = 1,
	DATA_FILE2
}zfs_group_data_file_no_t;

typedef struct zfs_group_notify_file_space {
	uint64_t	atime[2];
	uint64_t	ctime[2];
	uint64_t	mtime[2];
	uint64_t	file_updatesize;
	uint64_t	file_updateop;
	uint64_t	file_size;
	uint64_t	file_nblks;
	uint64_t	file_blksz;
	uint64_t	file_low;
	boolean_t	update_quota;
	uint64_t	file_object;
	uint64_t	file_gen;
	zfs_group_object_t	group_id;
}zfs_group_notify_file_space_t;

typedef struct zfs_group_notify_file_info
{
	zfs_group_object_t group_id;
	uint64_t dst_spa;
	uint64_t dst_objset;
	uint64_t dst_object;
	uint64_t update_node_info;
} zfs_group_notify_file_info_t;

typedef struct zfs_group_notify_para{
	znode_t znode; 
	uint64_t update_size;
	uint64_t used_op;
	boolean_t update_quota;
	uint64_t local_spa;
	uint64_t local_os;
}zfs_group_notify_para_t;

typedef struct zfs_group_dirty_notify_para{
	znode_t znode; 
	uint64_t dirty_flag;
	zfs_group_data_file_no_t data_no;
	uint64_t local_spa;
	uint64_t local_os;
}zfs_group_dirty_notify_para_t;

typedef struct zfs_group_overquota_para{
	uint64_t spa_id;
	uint64_t objset;
	uint64_t object;
}zfs_group_overquota_para_t,
zfs_group_dst_t;

typedef struct zfs_group_notify_data_dirty {
	uint64_t dirty_flag;
	uint64_t master_object;
	zfs_group_data_file_no_t data_file_no;
} zfs_group_notify_data_dirty_t;

typedef struct zfs_group_notify_arg {
	union {
		zfs_group_notify_file_space_t	file_space;
		zfs_group_notify_system_space_t	system_space;
		zfs_group_notify_file_info_t	file_info;
		zfs_group_notify_data_dirty_t	dirty_notify;
	} p;
} zfs_group_notify_arg_t;


typedef struct zfs_group_notify {
	zfs_group_object_t	id;
	zfs_group_notify_arg_t	arg;	
} zfs_group_notify_t;

typedef struct zfs_group_notify_msg {
	union {
		uint64_t	fill;
		zfs_group_notify_t	notify;
	} call;
} zfs_group_notify_msg_t;

typedef struct zfs_msg {
	union {
		uint64_t	fill;
		zfs_group_name_t	name;
		zfs_group_name2_t	name2;
		zfs_group_znode_t	znode;
		zfs_group_znode2_t	znode2;
		zfs_group_data_t	data;
		zfs_group_cmd_t	cmd;
		zfs_group_iostat_t	stat;
		zfs_group_reg_t	regist;
		char	i[ZFS_GROUP_MAX_NAME_LEN];
	} call;
} zfs_msg_t;

typedef struct zfs_group_server_para {
	zfs_group_header_t *msg_header;
	zfs_msg_t *msg_data;
} zfs_group_server_para_t;

typedef struct zfs_group_dirlow {
	char propname[MAXNAMELEN];
	char	path[MAXPATHLEN];
	uint64_t	dir_obj;
	uint64_t	value;
}zfs_group_dirlow_t;


/*
 * Similar to the struct tm in userspace <time.h>, but it needs to be here so
 * that the kernel source is self contained.
 */
typedef struct todinfo {
	int	tod_sec;	/* seconds 0-59 */
	int	tod_min;	/* minutes 0-59 */
	int	tod_hour;	/* hours 0-23 */
	int	tod_dow;	/* day of week 1-7 */
	int	tod_day;	/* day of month 1-31 */
	int	tod_month;	/* month 1-12 */
	int	tod_year;	/* year 70+ */
} todinfo_t;


#define	ZFS_GROUP_CMD_NAME	1
#define	ZFS_GROUP_CMD_DATA	2
#define	ZFS_GROUP_CMD_ZNODE	3
#define	ZFS_GROUP_CMD_NOTIFY	4
#define	ZFS_GROUP_CMD_CMD	5
#define	ZFS_GROUP_CMD_STAT	6
#define	ZFS_GROUP_CMD_SCRUB	7
#define	ZFS_GROUP_CMD_DIRLD	8

/* CMDs used for Master backup node. */
#define ZFS_GROUP_CMD_NAME_BACKUP 9
#define	ZFS_GROUP_CMD_ZNODE_BACKUP 10


#define	SAM_CMD_MAX	11

#define	ZFS_UPDATE_FILE_NODE_MASTER	1
#define	ZFS_UPDATE_FILE_NODE_MASTER2	2
#define	ZFS_UPDATE_FILE_NODE_MASTER3	3
#define	ZFS_UPDATE_FILE_NODE_MASTER4	4
#define	ZFS_UPDATE_FILE_NODE_DATA1	5
#define	ZFS_UPDATE_FILE_NODE_DATA2	6

#define ZFS_GROUP_GEN_MASK -1ULL >> (64 - 8 * 4)



void zfs_group_set_cred(cred_t *credp, zfs_group_cred_t *group_credp);

int zfs_client_create(struct inode *pip,	char *name, vattr_t *vap, int ex,
    int mode, struct inode **ipp, cred_t *credp, int flag, vsecattr_t *vsap);

int zfs_client_create_backup(znode_t *pzp,	char *name, vattr_t *vap, int ex,
    int mode, znode_t *zp, cred_t *credp, int flag, vsecattr_t *vsap, zfs_multiclus_node_type_t m_node_type);

int zfs_client_lookup(struct inode *pip, char *cp,
    struct inode **ipp, 	pathname_t *pnp, int flags, struct inode *rdir,
    cred_t *credp, int *defp, struct pathname *rpnp);

int zfs_client_remove(struct inode *pip, char *cp, cred_t *credp, int flag);

int zfs_client_remove_backup(znode_t *dzp, char *cp, cred_t *credp, 
	int flag, zfs_multiclus_node_type_t m_node_type);

int zfs_client_mkdir(struct inode *pip, char *cp, vattr_t *vap, struct inode **ipp,	
    cred_t *credp, int flag,	vsecattr_t *vsap);

int zfs_client_mkdir_backup(znode_t *pzp, char *cp, vattr_t *vap, znode_t *zp,	
    cred_t *credp, int flag, vsecattr_t *vsap, zfs_multiclus_node_type_t m_node_type);

int zfs_client_rmdir(struct inode *pip, char *cp, struct inode *cdir, cred_t *credp, int flag);

int zfs_client_rmdir_backup(znode_t *dzp, char *cp, struct inode *cdir, cred_t *credp,
    int flag, zfs_multiclus_node_type_t m_node_type);

int zfs_client_readdir(struct inode *ip, struct dir_context *ctx, cred_t *cr, int flag);

int zfs_client_xattr_list(struct inode *ip, void *buffer, size_t buffer_size, cred_t *cr) ;

int zfs_client_symlink(struct inode *pip, char *cp, vattr_t *vap, char *tnm, struct inode **ipp,		
    cred_t *credp, int flag);

int zfs_client_symlink_backup(znode_t *dzp, char *cp, vattr_t *vap, znode_t *zp, char *tnm,		
    cred_t *credp, int flag, zfs_multiclus_node_type_t m_node_type);

int zfs_client_link(struct inode *tdip, struct inode *sip, char *name, cred_t *cr, int flags);

int zfs_client_link_backup(znode_t *dzp, znode_t *szp, char *name, cred_t *cr,
    int flags, zfs_multiclus_node_type_t m_node_type);

int zfs_client_readlink(struct inode *ip, uio_t *uio, cred_t *cr);

int zfs_client_rename(struct inode *sdip, char *snm, struct inode *tdip,
    char *tnm, cred_t *cr, int flags);

int zfs_client_rename_backup(znode_t *opzp, char *snm, znode_t *npzp,
    char *tnm, cred_t *cr, int flags, zfs_multiclus_node_type_t m_node_type);

int zfs_client_setattr(struct inode *ip, vattr_t *vap, int flags, cred_t *cr);

int zfs_client_setattr_backup(znode_t *zp, vattr_t *vap, int flags, cred_t *cr,
    zfs_multiclus_node_type_t m_node_type);

int zfs_client_access(struct inode *ip, int mode, int flag, cred_t *cr);

int zfs_client_setsecattr(struct inode *ip, vsecattr_t *vsecp, int flag, cred_t *cr);

int zfs_client_setsecattr_backup(znode_t *zp, vsecattr_t *vsecp, int flag, cred_t *cr,
    zfs_multiclus_node_type_t m_node_type);

int zfs_client_set_dirquota_backup(znode_t *zp, uint64_t object,
    const char *path, uint64_t quota, zfs_multiclus_node_type_t m_node_type);

int zfs_client_set_dirlow_backup(znode_t *zp, 
	nvpairvalue_t *pairvalue, zfs_multiclus_node_type_t m_node_type);

int zfs_client_read(struct inode *ip, uio_t *uio, int ioflag, cred_t *cr);

int zfs_client_read2(struct inode *ip, uio_t *uio, int ioflag, cred_t *cr);

int zfs_client_write(struct inode *ip, uio_t *uio, int ioflag, cred_t *cr);

int zfs_client_write2(struct inode *ip, uio_t *uio, int ioflag, cred_t *cr);

int zfs_client_getsecattr(struct inode *ip, vsecattr_t *vsecp, int flag, cred_t *cr);

int zfs_group_send_to_server(zfs_msg_t *msg);

void zfs_group_znode_copy_phys(znode_t *zp, zfs_group_phys_t *dst_phys, boolean_t nosa);

int zfs_client_send_to_server(objset_t *os, zfs_group_header_t *msg_header, zfs_msg_t *msg, boolean_t waitting);

int zfs_group_v_to_v32(vattr_t *vap, zfs_group_vattr_t *va32p);

int zfs_client_notify_file_space(znode_t *zp, uint64_t update_size, uint64_t used_op, boolean_t update_quota,
	uint64_t local_spa, uint64_t local_os);

void zfs_client_noify_file_space_tq(void* arg);

int zfs_client_notify_file_info(znode_t* zp, zfs_multiclus_node_type_t m_node_type, uint64_t update_node_info);

void zfs_client_overquota_tq(void* arg);

int zfs_group_zget(zfs_sb_t *zsb, uint64_t object, znode_t **zpp, 
	uint64_t last_master_spa, uint64_t last_master_objset, uint64_t gen,
	boolean_t waitting);

void zfs_group_server_rx(zfs_group_server_para_t *server_para);

void zfs_group_msg(zfs_group_header_t *msg_header, zfs_msg_t *msg_data, boolean_t bserver, boolean_t brx, 
    boolean_t bprint);

int zfs_remove_data_file(struct inode *pip, znode_t* zp, char *cp, cred_t *credp, int flag);

int zfs_remove_data2_file(struct inode *pip, znode_t* zp, char *cp, cred_t *credp, int flag);

int zfs_client_get_fsstat(zfs_sb_t *zsb, uint64_t *refbytes,
    uint64_t *availbytes, uint64_t *refobjs, uint64_t *availobjs);

int zfs_client_get_fictitious_group_fsstat(zfs_sb_t *zsb, uint64_t *refbytes,
    uint64_t *availbytes, uint64_t *refobjs, uint64_t *availobjs);

int zfs_client_master_get_group_fsstat(zfs_sb_t *zsb, uint64_t *refbytes,
    uint64_t *availbytes, uint64_t *refobjs, uint64_t *availobjs);

void zfs_group_to_acl(zfs_group_name_acl_t *zg_acl, vsecattr_t *vsap);

void zfs_group_to_dirlowdata(zfs_group_name_dirlowdata_t *zg_dirlowdata, zfs_dirlowdata_t *dirlowdata);

void zfs_group_from_acl(zfs_group_name_acl_t *zg_acl, vsecattr_t *vsap);

zfs_group_create_extra_t *zfs_group_get_create_extra(char *name, vattr_t *vap,
    vsecattr_t *vsap, size_t *name_len, size_t *xvatlen, size_t *acl_len,
    uint64_t *dirlowdata, size_t *dlow_len);

int zfs_get_group_iostat(char *poolname, vdev_stat_t *newvs, nvlist_t **config);
int zfs_set_group_scrub(char *poolname, uint64_t cookie);
int zfs_client_set_dir_low(zfs_sb_t *zsb, const char *dsname, nvpairvalue_t *pairvalue);
int zfs_set_group_dir_low(const char *dsname, nvpairvalue_t *pairvalue);
void zfs_group_update_system_space(objset_t *os, 
    zfs_group_notify_system_space_t *sys_space);

int zfs_group_create_data_file(znode_t *zp, char *name, boolean_t bregual,
	vsecattr_t *vsecp, vattr_t *vap, int ex, int mode, int flag,
	uint64_t orig_spa, uint64_t orig_os, uint64_t* dirlowdata, uint64_t* host_id, dmu_tx_t *tx);

int zfs_group_create_data2_file(znode_t *zp, char *name, boolean_t bregual,
	vsecattr_t *vsecp, vattr_t *vap, int ex, int mode, int flag,
	uint64_t orig_spa, uint64_t orig_os, uint64_t* dirlowdata, uint64_t* host_id, dmu_tx_t *tx);

void zfs_group_route_data(zfs_sb_t *zsb, uint64_t orig_spa, uint64_t orig_os,
	uint64_t *dst_spa, uint64_t *dst_os, uint64_t *root_object, uint64_t* host_id);

uint64_t zfs_group_send_seq(objset_t *os);
int zfs_group_client_space(znode_t *zp, uint64_t off, 
    uint64_t len, uint64_t flags);
int zfs_group_client_space_data2(znode_t *zp, uint64_t off,
    uint64_t len, uint64_t flags);

int zfs_get_masterroot_attr(struct inode *ip, znode_t **tmp_root_zp);
//int zfs_client_map_write(znode_t *zp, page_t *pp, 
//   uint64_t off, uint64_t len, cred_t *cr, int ioflag);
void *zfs_group_alloc_data(zfs_group_header_t *hdr, 
    uint64_t data_num, uint64_t *len);
void zfs_group_fill_data(zfs_group_header_t *hdr, uint64_t data_index, 
    uint64_t data_offset, uint64_t data_len, void *datap, void *dst_datap, void *dst_header);
void zfs_group_free_data(zfs_group_header_t *msg_header, void *data, uint64_t data_len);
void zfs_update_quota_used(zfs_sb_t *zsb, znode_t *zp,
    uint64_t space, uint64_t update_op, dmu_tx_t *tx);



boolean_t zfs_client_overquota(zfs_sb_t *zsb, znode_t *zp, int flag);
int zfs_client_set_userquota(zfs_sb_t *zsb, zfs_userquota_prop_t type,
    const char *domain, uint64_t rid, uint64_t quota);
int zfs_client_set_dirquota(zfs_sb_t *zsb, uint64_t object,
    const char *path, uint64_t quota);
int zfs_client_get_dirlowdata(zfs_sb_t *zsb, znode_t *zp, zfs_dirlowdata_t *dirlowdata);
int zfs_client_get_dirlowdatalist(zfs_sb_t *zsb,  
	uint64_t  *cookiep, void * buf ,uint64_t *bufsize);
int zfs_client_get_dirquota(zfs_sb_t *zsb,uint64_t dir_obj, zfs_dirquota_t *dirquota);
int zfs_client_get_dirquotalist(zfs_sb_t *zsb,  
	uint64_t  *cookiep, void * buf ,uint64_t *bufsize);
void zfs_group_wait(clock_t microsecs);
int zfs_group_get_attr_from_data_node(zfs_sb_t *zsb, znode_t *master_znode);
int zfs_group_get_attr_from_data2_node(zfs_sb_t *zsb, znode_t *master_znode);

int zfs_client_notify_data_file_dirty(znode_t *zp, uint64_t dirty_flag,
	zfs_group_data_file_no_t data_no, uint64_t local_spa, uint64_t local_os);
void zfs_client_notify_data_file_dirty_tq(void* arg);
int update_master_obj_by_mx_group_id(znode_t *zp, zfs_multiclus_node_type_t m_node_type);
int remove_master_obj_by_mx_group_id(znode_t *zp, dmu_tx_t *tx);
int zfs_group_process_create_data_file(znode_t *dzp, uint64_t master_object,
	uint64_t master_gen, znode_t **zpp, uint64_t *dirlowdata, vattr_t *vap);
 int zfs_group_process_remove_data_file(zfs_sb_t *zsb, znode_t *dzp,
    uint64_t object, uint64_t dirquota);
 
void zfs_failover_ctl(objset_t *os, int time);
void zfs_set_remote_object(znode_t *zp, zfs_group_object_t *group_object);
int zfs_group_get_attr_from_data_node(zfs_sb_t *zsb, znode_t *master_znode);
int zfs_client_migrate_cmd(objset_t *os, zfs_migrate_type migrate_type, uint64_t flags, uint64_t start_obj);
int zfs_client_migrate_insert_block(objset_t *os, zfs_migrate_cmd_t *migrate_insert_cmd);
extern void zfs_fid_remove_master_info(zfs_sb_t *zsb, uint64_t zid, uint64_t gen, dmu_tx_t *tx);
extern int zfs_group_broadcast_unflag_overquota(znode_t *zp, uint64_t old_dirquota_id);
extern const char *zfs_group_map_key_name_prefix_format;
extern const char *zfs_group_map_zap_obj;
extern int TO_DOUBLE_DATA_FILE;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_ZFS_GROUP_H */


