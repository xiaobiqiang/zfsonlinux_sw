#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <libdevinfo.h>
#include <libzfs.h>
#include <fcntl.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>
#include <ctype.h>
#include <disklist.h>
#include <slices.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <scsi/sg.h>
#include <linux/ioctl.h>
#include <linux/hdreg.h>

/*
 *************************************************************************
 * linux disk info interface
 *************************************************************************
 */
#define DEFAULT_DISK_INFO_PATH	"/proc/partitions"
#define DEFAULT_PATH			"/dev/"
#define SAS2IRCU		"sas2ircu 0 display"
#define SLOT			"Slot"
#define ENCLOSURE		"Enclosure"
#define SERIALNO		"Serial"
#define CMD_TMP_LEN		1024
#define ARGS_LEN		100
#define DEV_LEN			50
#define PARAM_LEN		10
#define	INQ_REPLY_LEN	96
#define	INQ_CMD_LEN		6
#define POOLLEN			64

typedef struct disk_info {
	int		dk_major;
	int		dk_minor;
	int		dk_enclosure;
	int		dk_slot;
	int		dk_is_sys;
	int		dk_rpm ;
	long	dk_gsize;
	long	dk_blocks;
	char	dk_vendor[PARAM_LEN];
	char	dk_busy[PARAM_LEN];
	char	dk_name[ARGS_LEN];
	char	dk_pool[ POOLLEN ] ;
	char	*dk_role ;
	char	dk_serial[ARGS_LEN];
	struct disk_info *next;
} disk_info_t;

typedef struct disk_table {
	disk_info_t *next;
	int			total;
} disk_table_t;

static xmlNodePtr create_xml_file();
static void close_xml_file();
static void create_lun_node(disk_info_t *di);

const char DISK_ROLE_DATA[]="data" ;
const char DISK_ROLE_CACHE[]="l2cache" ;
const char DISK_ROLE_LOW[]="lowdata" ;
const char DISK_ROLE_META[]="metadata" ;
const char DISK_ROLE_LOG[]="log" ;
const char DISK_ROLE_SPARE[]="spare" ;
const char DISK_ROLE_METASPARE[]="metaspare" ;
const char DISK_ROLE_LOWSPARE[]="lowspare" ;

static libzfs_handle_t *gzfslib_p ;

static void
get_system_disk(char *name)
{
	int ret = -1;
	FILE *fp = -1;
	char args[ARGS_LEN] = {0};
	char dev[ARGS_LEN] = {0};
	char tmp[CMD_TMP_LEN] = {0};

	fp = fopen("/etc/mtab", "r");
	if (fp == NULL) {
		return; 
	}
	
	while (fgets(tmp, sizeof(tmp), fp)) {
		if (tmp[0] == '\n' || tmp[0] == '\r') 
			continue;
		
		sscanf(tmp, "%s", dev);
		if (strncmp(dev, "/dev/sd", 7) == 0) {
			sscanf(tmp, "%*s %s", args);
			if (strcasecmp(args, "/") == 0 || strcasecmp(args, "/boot") == 0
				|| strcasecmp(args, "/home") == 0) {
				memcpy(name, dev, 8);
				break;
			}
		} else {
			continue;
		}
	}

	(void) fclose(fp);
	return;
}
	
static void
get_scsi_gsize(uint64_t blocks)
{
	double bs = blocks / 1024.0;
	if (bs >= 1024) {
		if (bs / 1024 > 1024)
			printf("%-3.2lf T\n", (bs / 1024) / 1024);
		else
			printf("%-3.2lfGB\n",bs / 1024);
	} else {
		printf("%-3.2lfMB\n",bs);
	}

	return;
}

void print_info(disk_info_t *di, int count)
{
	if (di->dk_is_sys == 1) {
		strcat(di->dk_name, " [system]");
	}

	(void) printf("%3d. %-20s %-5s %20s %8s %3d %3d ", count,
			di->dk_name,di->dk_vendor,di->dk_serial,di->dk_busy,
			di->dk_enclosure, di->dk_slot);

	(void) get_scsi_gsize(di->dk_blocks);

	return;
}

static int
get_scsi_slot(disk_info_t *di)
{
	FILE *fd = -1;
	int len = -1;
	int slot = -1;
	int enclosure = -1;
	char value_sn[ARGS_LEN] = {0};
	char args[ARGS_LEN] = {0};
	char tmp[CMD_TMP_LEN] = {0};

	len = strlen(di->dk_name);
	if (di->dk_name[len -1] >= '0' &&
		di->dk_name[len - 1] <= '9')
		return (0);

	fd = popen(SAS2IRCU, "r");
	if (fd == NULL)
		return (0);

	while (fgets(tmp, sizeof(tmp), fd)) {
		if (tmp[0] == '\n' || tmp[0] == '\r' || tmp[0] == '-')
			continue;

		sscanf(tmp, "%s", args);	
		if (strcasecmp(args, ENCLOSURE) == 0) {
			sscanf(tmp, "%*[^:]:%d", &enclosure);
		} else if (strcasecmp(args, SLOT) == 0) {
			sscanf(tmp, "%*[^:]:%d", &slot);
		} else if (strcasecmp(args, SERIALNO) == 0) {
			sscanf(tmp, "%*[^:]:%s", value_sn);
			if (di->dk_serial != NULL && slot != -1 && value_sn != -1
				&& strcasestr(di->dk_serial, value_sn) != NULL) {
				di->dk_enclosure = enclosure;
				di->dk_slot = slot;
			} else {
				slot = -1;
				enclosure = -1;
			}
		}
	}

	pclose(fd);
	return (1);
}

static void
get_scsi_status(disk_info_t *di)
{
	int i = 0;
	int fd = -1;
	int err = -1;
	int count = 0;
	struct dk_gpt *vtoc = NULL;

	if (di->dk_is_sys == 1) {
		memcpy(di->dk_busy, "busy", 4);
		return; 
	}

	fd = open(di->dk_name, O_RDWR|O_DIRECT);
	if (fd > 0) {
		err = efi_alloc_and_read(fd, &vtoc);
		if (err >= 0) {
			for (i = 0; i < vtoc->efi_nparts; i++) {
				if (vtoc->efi_parts[i].p_size != 0) {
					count = i;
					break;
				}
			}
		}
	}

	if (count == 8)
		memcpy(di->dk_busy, "free", 4);
	else
		memcpy(di->dk_busy, "busy", 4);

	efi_free(vtoc);
	(void) close(fd);
	return;
}

static int 
get_scsi_vendor(disk_info_t *di)
{
	unsigned char inq_buff[INQ_REPLY_LEN];
	unsigned char sense_buffer[32];
	unsigned char inq_cmd_blk[INQ_CMD_LEN] =
	    {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
	sg_io_hdr_t io_hdr;
	int error;
	int fd;

	/* Prepare INQUIRY command */
	memset(&io_hdr, 0, sizeof (sg_io_hdr_t));
	io_hdr.interface_id = 'S';
	io_hdr.cmd_len = sizeof (inq_cmd_blk);
	io_hdr.mx_sb_len = sizeof (sense_buffer);
	io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	io_hdr.dxfer_len = INQ_REPLY_LEN;
	io_hdr.dxferp = inq_buff;
	io_hdr.cmdp = inq_cmd_blk;
	io_hdr.sbp = sense_buffer;
	io_hdr.timeout = 10;		/* 10 milliseconds is ample time */

	if ((fd = open(di->dk_name, O_RDONLY|O_DIRECT)) < 0)
		return (0);

	error = ioctl(fd, SG_IO, (unsigned long) &io_hdr);

	(void) close(fd);

	if (error < 0)
		return (0);

	if ((io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK)
		return (0);

	memcpy(di->dk_vendor, inq_buff + 8, 8);

	return (1);
}

static int
get_scsi_serial(disk_info_t *di)
{
	int len = 0;
	int rsp_len = 0;
	char *src = NULL;
	char *dest = NULL;
	char *rsp_buf = NULL;
	char *path = di->dk_name;
	unsigned char inq_buff[INQ_REPLY_LEN];
	unsigned char sense_buffer[32];
	unsigned char inq_cmd_blk[INQ_CMD_LEN] =
	    {0x12, 1, 0x80, 0, INQ_REPLY_LEN, 0};
	sg_io_hdr_t io_hdr;
	int error;
	int fd;
	int i;

	/* Prepare INQUIRY command */
	memset(&io_hdr, 0, sizeof (sg_io_hdr_t));
	io_hdr.interface_id = 'S';
	io_hdr.cmd_len = sizeof (inq_cmd_blk);
	io_hdr.mx_sb_len = sizeof (sense_buffer);
	io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	io_hdr.dxfer_len = INQ_REPLY_LEN;
	io_hdr.dxferp = inq_buff;
	io_hdr.cmdp = inq_cmd_blk;
	io_hdr.sbp = sense_buffer;
	io_hdr.timeout = 10;		/* 10 milliseconds is ample time */

	if ((fd = open(path, O_RDONLY|O_DIRECT)) < 0)
		return (B_FALSE);

	error = ioctl(fd, SG_IO, (unsigned long) &io_hdr);

	(void) close(fd);

	if (error < 0) {
		return (B_FALSE);
	}

	if ((io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK)
		return (B_FALSE);

	rsp_len = inq_buff[3];
	rsp_buf = (char*)&inq_buff[4];
	for (i = 0, dest = rsp_buf; i < rsp_len; i++) {
		src = &rsp_buf[i];
		if (*src > 0x20) {
			if (*src == ':')
				*dest++ = ';';
			else
				*dest++ = *src;
		}
	}
	
	len = dest - rsp_buf;
	dest = rsp_buf;

	if (len > INQ_REPLY_LEN) {
		dest += len - INQ_REPLY_LEN;
		len = INQ_REPLY_LEN;
	}

	memcpy(di->dk_serial, dest, len);

	return (1);
}

/*
 * get the disk rpm
 *
 * Send a SCSI inquiry command to get VPD 0xB1, which has rpm in Byte[4] and Byte[5]
 */
static int
get_scsi_rpm( disk_info_t *disk ) {
	char *path = disk->dk_name ;
	uint8_t output[ INQ_REPLY_LEN ] ;
	uint8_t cmd[] = {0x12, 1, 0xB1, 0, INQ_REPLY_LEN, 0 } ;
	int fd ;
	sg_io_hdr_t io_hdr ;

	if( (fd = open( path, O_RDONLY ) ) == -1 ) {
		fprintf( stderr, "in %s[%d]: cann't open dev<%s> for reading, error( %s )\n", __func__, __LINE__, path, strerror( errno ) ) ;
		return B_FALSE ;
	}


	memset( &io_hdr, 0, sizeof( sg_io_hdr_t ) ) ;
	io_hdr.interface_id = 'S' ;
	io_hdr.dxfer_direction = SG_DXFER_FROM_DEV ;
	io_hdr.dxfer_len = INQ_REPLY_LEN ;
	io_hdr.dxferp = output ;
	io_hdr.cmdp = cmd ;
	io_hdr.cmd_len = 6 ;
	io_hdr.timeout = 1000 ;

	if( ioctl( fd, SG_IO, &io_hdr ) == -1 ) {
		fprintf( stderr, "in %s[%d]: ioctl failed, error( %s )\n", __func__, __LINE__, strerror( errno ) ) ;
		return B_FALSE ;
	}

	if( ( io_hdr.info & SG_INFO_OK_MASK ) != SG_INFO_OK ) {
		fprintf( stderr, "in %s[%d]: ioctl return not expected\n", __func__, __LINE__ ) ;
		return B_FALSE ;
	}

	disk->dk_rpm = output[4] * 256 + output[5] ;

	return B_TRUE ;
}

static void
do_each_vdev( disk_table_t *dtb_p, zpool_handle_t *zhp, nvlist_t *vdev, const char role[] ) {
	nvlist_t **children ;
	uint nchild ;
	uint i ;

	if( nvlist_lookup_nvlist_array( vdev, "children", &children, &nchild ) ==0 ) {
		for( i=0; i<nchild; i++ ) {
			do_each_vdev( dtb_p, zhp, children[i], role ) ;
		}
	}else {
		uint64_t flag ;
		const char *dev_name = zpool_vdev_name( gzfslib_p, zhp, vdev, 0 ) ;
		const char *pool_name = zpool_get_name( zhp ) ;
		const char *disk_role ;
		disk_info_t *diskp = dtb_p->next ;

		if( role == NULL ) {
			disk_role = DISK_ROLE_DATA ;

			flag = 0 ;
			if( ( nvlist_lookup_uint64( vdev, "is_meta", &flag ) == 0 ) && flag == 1 ) {
				disk_role = DISK_ROLE_META ;
				goto RETURN ;
			}

			flag = 0 ;
			if( ( nvlist_lookup_uint64( vdev, "is_low", &flag ) == 0 ) && flag == 1 ) {
				disk_role = DISK_ROLE_LOW ;
				goto RETURN ;
			}

			flag = 0 ;
			if( ( nvlist_lookup_uint64( vdev, "is_log", &flag ) == 0 ) && flag == 1 ) {
				disk_role = DISK_ROLE_LOG ;
				goto RETURN ;
			}
		}else {
			disk_role = role ;
		}

RETURN :
		i=0 ;
		while( (i++) < dtb_p->total ) {
			assert( strncmp( diskp->dk_name, "/dev/", 5 ) == 0 ) ;
			if( strcmp( diskp->dk_name+5, dev_name ) == 0 ) {
				strcpy( diskp->dk_pool, pool_name ) ;
				diskp->dk_role = disk_role ;

				return ;
			}
			diskp = diskp->next ;
		}

	}
}

static int
do_each_pool( zpool_handle_t *zhp, void *data ) {
	disk_table_t *dtb_p = ( disk_table_t *) data ;
	nvlist_t *config, *vdev_root, **spare, **lowspare, **metaspare, **l2cache ;
	uint_t nspare, nlowspare, nmetaspare, nl2cache ;
	nvpair_t *nvp ;
	int i ;

	if( (config = zpool_get_config( zhp, NULL ) ) == NULL ) {
		syslog( LOG_ERR, "in %s[%d]: zpool_get_config return NULL\n", __FILE__, __LINE__ ) ;
		return -1 ;
	}
	nvlist_lookup_nvlist( config, "vdev_tree", &vdev_root ) ;

	do_each_vdev( dtb_p, zhp, vdev_root, NULL ) ;

	if( nvlist_lookup_nvlist_array( vdev_root, "spares", &spare, &nspare ) == 0 ) {
		for( i=0; i<nspare; i++ ) {
			do_each_vdev( dtb_p, zhp, spare[i], DISK_ROLE_SPARE ) ;
		}
	}

	if( nvlist_lookup_nvlist_array( vdev_root, "metaspares", &metaspare, &nmetaspare ) == 0 ) {
		for( i=0; i<nmetaspare; i++ ) {
			do_each_vdev( dtb_p, zhp, metaspare[i], DISK_ROLE_METASPARE ) ;
		}
	}

	if( nvlist_lookup_nvlist_array( vdev_root, "lowspares", &lowspare, &nlowspare ) == 0 ) {
		for( i=0; i<nlowspare; i++ ) {
			do_each_vdev( dtb_p, zhp, lowspare[i], DISK_ROLE_LOWSPARE ) ;
		}
	}

	if( nvlist_lookup_nvlist_array( vdev_root, "l2cache", &l2cache, &nl2cache ) == 0 ) {
		for( i=0; i<nl2cache; i++ ) {
			do_each_vdev( dtb_p, zhp, l2cache[i], DISK_ROLE_CACHE ) ;
		}
	}

	return 0 ;
}

static int
get_disk_poolname( disk_table_t *dtb_p ) {
	if( ( gzfslib_p = libzfs_init() ) == NULL ) {
		fprintf( stderr, "in %s[%d]: can not do libzfs_init()\n", __func__, __LINE__ ) ;
		return -1 ;
	}

	if( zpool_iter( gzfslib_p, do_each_pool, dtb_p ) != 0 ) {
		return -1 ;
	}

	libzfs_fini( gzfslib_p ) ;
	gzfslib_p = NULL ;

	return 0 ;
}

static char *disk_info_find_value(disk_info_t *di, int type)
{
	disk_info_t *cur = di->next;

	if (cur != NULL) {
		if (strcasecmp(di->dk_name, cur->dk_name) == 0) {
			if (type == 0 && cur->dk_serial[0] != 0) {
				return (cur->dk_serial);
			} else if (type == 1 && cur->dk_vendor[0] != 0) {
				return (cur->dk_vendor);
			} else {
				return (disk_info_find_value(cur, type));
			}
		} else {
			return (NULL);
		}
	} else {
		return (NULL);
	}
}

static void disk_info_free(disk_table_t *tb)
{
	int i = 0;
	disk_info_t *temp = NULL;
	disk_info_t *cur = tb->next;

	for (i = 0; i < tb->total; i++) {
		if (cur == NULL)
			break;

		temp = cur->next;
		free(cur);
		cur = temp;
	}
}

static void disk_info_show(disk_table_t *tb, int all)
{
	int i = 0;
	int len = 0;
	int order = 0;
	char *pstr = NULL;
	char *value = NULL;
	disk_info_t *di_cur = NULL;
	
	di_cur = tb->next;
	for (i = 0; i < tb->total; i++) {
		if (di_cur == NULL)
			break;

		if (di_cur->dk_serial[0] == 0 &&
			(value = disk_info_find_value(di_cur, 0)) != NULL) {
			memcpy(di_cur->dk_serial, value, strlen(value));
		}

		if (di_cur->dk_vendor[0] == 0 &&
			(value = disk_info_find_value(di_cur, 1)) != NULL) {
			memcpy(di_cur->dk_vendor, value, strlen(value));
		}

		di_cur = di_cur->next;
	}

	di_cur = tb->next;
	for (i = 0; i < tb->total; i++) {
		if( strcmp( di_cur->dk_vendor, "ATA" ) == 0 )
			continue ;

		if (di_cur == NULL)
			break;

		pstr = (char*)di_cur->dk_name;
		len = strlen(di_cur->dk_name);

		if (*(pstr + len - 1) >= '0' && *(pstr + len - 1) <= '9') {
			if (all == 1) {
				create_lun_node( di_cur ) ;
				print_info(di_cur, order);
				order++;
			}
		} else {
			create_lun_node( di_cur ) ;
			print_info(di_cur, order);
			order++;
		}

		di_cur = di_cur->next;
	}

	return;
}

int list_disks(int all)
{
	int len = 0;
	int count = 0;
	char line[ARGS_LEN] = {0};
	char name[DEV_LEN] = {0};
	char sysdisk[ARGS_LEN] = {0};
	disk_info_t di;

	FILE *fd = fopen(DEFAULT_DISK_INFO_PATH, "r");
	if (fd < 0)
		return (0);

	int i = 0;
	int di_total = 0;
	disk_table_t di_tb = {0};
	disk_info_t di_head;
	disk_info_t *di_cur;
	disk_info_t *di_mark;

	create_xml_file();
	di_tb.next = NULL;
	while (fgets(line, sizeof(line), fd)) {
		if (line[0] == '\n' || line[0] == '\r')
			continue;

		di_cur = (disk_info_t*)malloc(sizeof(disk_info_t));
		bzero(di_cur, sizeof(disk_info_t));
		sscanf(line, "%u %u %lu %s %[^\n]", &di_cur->dk_major,
				&di_cur->dk_minor,&di_cur->dk_blocks, name);

		if (strncmp(name, "sd", 2) != 0 &&
				strncmp(name, "hd", 2) != 0)
			continue;

		len = strlen(name) + strlen(DEFAULT_PATH);
		snprintf(di_cur->dk_name, len + 2, "%s%s", DEFAULT_PATH, name);

		if (di_tb.next == NULL) {
			di_tb.next = di_cur;
			di_mark = di_cur;
		} else {
			di_mark->next = di_cur;
			di_mark = di_cur;
		}

		di_tb.total++;
	}

	(void) get_system_disk(sysdisk);

	di_cur = di_tb.next;
	for (i = 0; i < di_tb.total; i++)
	{
		if (strncmp(di_cur->dk_name, sysdisk, 8) == 0)
			di_cur->dk_is_sys = 1;

		get_scsi_vendor(di_cur);
		get_scsi_serial(di_cur);
		get_scsi_status(di_cur);
		get_scsi_slot(di_cur);
		get_scsi_rpm( di_cur ) ;

		di_cur = di_cur->next;
	}

	(void) get_disk_poolname( &di_tb ) ;
	(void) disk_info_show(&di_tb, all);
	(void) disk_info_free(&di_tb);

	close_xml_file();
	(void) fclose(fd);

	return (0);
}

static void disk_init_efi(char *path)
{
	int fd, ret, i;
	struct dk_gpt *table;

	fd = open(path, O_RDWR|O_DIRECT);
	if (fd < 0) {
		syslog(LOG_ERR, "disk_init: open <%s> fails",path);
		return;
	}
	
	ret = efi_alloc_and_init(fd, EFI_NUMPAR, &table);
	if (ret < 0) {
		syslog(LOG_ERR, "disk_init: get disk table <%s> fails",path);
		(void) close(fd);
		return;
	}

	for (i = 0; i < 8; i++) {
		table->efi_parts[i].p_start = 0;
		table->efi_parts[i].p_size = 0;
		table->efi_parts[i].p_tag = V_UNASSIGNED;
	}

	table->efi_parts[8].p_start = table->efi_last_u_lba - EFI_MIN_RESV_SIZE;
	table->efi_parts[8].p_size = EFI_MIN_RESV_SIZE;
	table->efi_parts[8].p_tag = V_RESERVED;

	ret = efi_write(fd, table);
	if (ret < 0) {
		syslog(LOG_ERR, "Destroy devs: write   disk table  (%s) fails", path);
	}
	(void) close(fd);
	efi_free(table);

	return;
}
/*
 ******************************************************************************************
 * end disk info interface
 ******************************************************************************************
 */

#define	OPTION_LETTERS "d:i:s:p:g:o:x"
#define	DISK_NAME_OPTION    'd'
#define	DISK_INDEX_OPTION   'i'
#define	SLICE_SIZE_OPTION   's'
#define	SLICE_INDEX_OPTION  'p'
#define	GAP_INDEX_OPTION    'g'
#define	LED_SET_OPTION    'o'
#define	LEDXY_SET_OPTION    'x'
#define MPI2_SEP_REQ_SLOTSTATUS_REQUEST_REMOVE          (0x00040000)
#define MPI2_SEP_REQ_SLOTSTATUS_IDENTIFY_REQUEST        (0x00020000)
#define MPI2_SEP_REQ_SLOTSTATUS_REBUILD_STOPPED         (0x00000200)
#define MPI2_SEP_REQ_SLOTSTATUS_HOT_SPARE               (0x00000100)
#define MPI2_SEP_REQ_SLOTSTATUS_UNCONFIGURED            (0x00000080)
#define MPI2_SEP_REQ_SLOTSTATUS_PREDICTED_FAULT         (0x00000040)
#define MPI2_SEP_REQ_SLOTSTATUS_DEV_REBUILDING          (0x00000004)
#define MPI2_SEP_REQ_SLOTSTATUS_DEV_FAULTY              (0x00000002)
#define MPI2_SEP_REQ_SLOTSTATUS_NO_ERROR                (0x00000001)

#define	CTL_VENDOR				"CONTROLLER_VENDOR"
#define	ENC_VENDOR				"ENCLOSURE_VENDOR"
#define	ENC_AMOUNT				"ENCLOSURE_AMOUNT"
#define	ENC_SLOT				"ENCLOSURE_SLOT"
#define	ENC_DISK_TYPE			"ENCLOSURE_DISK_TYPE"
#define	ENC_INTERFACE_TYPE		"ENCLOSURE_INTERFACE_TYPE"
#define	ENC_ENCRYPT_TYPE		"ENCLOSURE_ENCRYPT_TYPE"

#define	GAPS_HEADER "Gaps in"
#define	DISK_XML_PATH "/tmp/disk.xml"
#define  	FMD_DISK_XML_PATH	"/tmp/fmd_disk.xml"
#define	SET_DOTHILL_ENCLOSURE_ID "dothill"
#define	SET_ENCLOSURE_ID "displayid"
#define SET_SSD_EN_SLOT_ID "/usr/sbin/sg_inq -p 0x83 %s | grep '\\[0x' |tail -2 | awk -Fx '{print $2}'| awk -F\\] '{print $1}' > /tmp/wwn.tmp 2>/dev/null"
#define SET_SSD_EN_SLOT_ID_ONE "/usr/sbin/sg_inq -p 0x83 %s | grep '\\[0x' |tail -1 | awk -Fx '{print $2}'| awk -F\\] '{print $1}' > /tmp/wwn.tmp 2>/dev/null"
/*
 *  Forward declarations
 */
static xmlDocPtr disk_doc;
static xmlNodePtr disk_root_node;
int disk_list_slices(slice_req_t *, int);
int disk_init(slice_req_t *);
int disk_restore_init(slice_req_t *);
static int disk_check_inuse(const char *dev);
static void print_slices(char *diskname, dmg_map_t map, dmg_lun_t *lun);
static int disk_mark(slice_req_t *);
extern uint64_t vdev_label_offset(uint64_t psize, int l, uint64_t offset);
extern int disk_get_poolname(const char *dev,char *pool_name);

typedef struct zpool_list zpool_list_t;

typedef struct led_operation {
	const char *operation_name;
	uint32_t operatio_code;
}led_operation_t;

led_operation_t disk_led_operation[] = {
			{"normal", MPI2_SEP_REQ_SLOTSTATUS_NO_ERROR},
			{"fault", MPI2_SEP_REQ_SLOTSTATUS_DEV_FAULTY},
			{"rebuild", MPI2_SEP_REQ_SLOTSTATUS_DEV_REBUILDING},
			{"unconfig", MPI2_SEP_REQ_SLOTSTATUS_UNCONFIGURED},
			{"hotspare", MPI2_SEP_REQ_SLOTSTATUS_HOT_SPARE},
			{"locate", MPI2_SEP_REQ_SLOTSTATUS_IDENTIFY_REQUEST},
			{"remove", MPI2_SEP_REQ_SLOTSTATUS_REQUEST_REMOVE},
				{NULL, 0}
};
void usage(void)
{
	printf("Usage:\n"
	       "disk list\n"
	       "disk list-all\n"
	       "disk mark <-d dev path>\n"
	       "disk list-slices <-d dev path | -i dev index>\n"
	       "disk create <-d dev path | -i dev index> <-p slices index> <-s size | -g gap index>\n"
	       "disk delete <-d dev path | -i dev index> <-p slices index> \n"
	       "disk gaps <-d dev path | -i dev index>\n"
	       "disk led <-d dev path >  < -o operation (fault, locate, hotspare, remove, unconfig, normal, rebuild)>\n"
	       "disk initialize <-d dev path >\n"
	       "disk restore <-d dev path >\n");
}
static int
disk_check_sbb_enclosure()
{
	int ret = 0, rval = 0;
	char *str = NULL;
	ret = df_loadsysenv(NULL);
	if (ret == 0) {
		str = df_getsysenv(ENC_VENDOR);
		if (str && (strstr(str, "LS"))) {
			rval = 1;
		}
		df_savefree();
	}
	return rval;
}

static int
disk_check_dothill_enclosure()
{
	int ret = 0, rval = 0;
	char *str = NULL;
	ret = df_loadsysenv(NULL);
	if (ret == 0) {
		str = df_getsysenv(ENC_VENDOR);
		if (str && (strstr(str, "DH"))) {
			rval = 1;
		}
		df_savefree();
	}
	return rval;
}

static int 
disk_check_enclosure_type()
{
	int ret = 0, rval = 0;
	char *str = NULL;
	ret = df_loadsysenv(NULL);
	if (ret == 0) {
		str = df_getsysenv(ENC_INTERFACE_TYPE);
		if (str && (strstr(str, "FC"))) {
			rval = 1;
		}
		df_savefree();
	}
	return rval;
}

static int
disk_get_enclosure_num()
{
	int ret = 0, rval = 0;
	int enc_num;
	char *str = NULL;
	ret = df_loadsysenv(NULL);
	if (ret == 0) {
		str = df_getsysenv(ENC_SLOT);
		enc_num = atoi(str);
		df_savefree();
	}
	return enc_num;
}

static int
disk_get_enclosure_amount()
{
	int ret = 0, rval = 0;
	int enc_amount = 0;
	char *str = NULL;
	ret = df_loadsysenv(NULL);
	if (ret == 0) {
		str = df_getsysenv(ENC_AMOUNT);
		if(str) {
			enc_amount = atoi(str);
		}
		df_savefree();
	}
	return enc_amount;
}

static int
disk_check_enclosure_disk_type_sata()
{
	int ret = 0, rval = 0;
	char *str = NULL;
	ret = df_loadsysenv(NULL);
	if (ret == 0) {
		str = df_getsysenv(ENC_DISK_TYPE);
		if (str && (strstr(str, "SATA"))) {
			rval = 1;
		}
		df_savefree();
	}
	return rval;
}

static int
disk_check_sbb_controller()
{
	int ret = 0, rval = 0;
	char *str = NULL;
	ret = df_loadsysenv(NULL);
	if (ret == 0) {
		str = df_getsysenv(CTL_VENDOR);
		if (str && (strstr(str, "SBB"))) {
			rval = 1;
		}
		df_savefree();
	}
	return rval;
}

#if 0
static void
disk_do_ctrl_led(xmlNodePtr node, uint32_t op_code)
{
	xmlNodePtr childNode;
	xmlChar *content, *routepath;
	int fd, en_id, slot_id, ret;
	childNode = node->xmlChildrenNode;
	while (childNode != NULL) {
		if (!(xmlStrcmp(childNode->name, (const xmlChar *)"en_id"))) {
			content = xmlNodeGetContent(childNode);
			if (content != NULL) {
				en_id = strtoul((const char *)content, NULL, 10);
				xmlFree(content);
				childNode = childNode->next;
				continue;
			}
		}
		if (!(xmlStrcmp(childNode->name, (const xmlChar *)"slot_id"))) {
			content = xmlNodeGetContent(childNode);
			if (content != NULL) {
				slot_id = strtoul((const char *)content, NULL, 10) - 1;
				xmlFree(content);
				childNode = childNode->next;
				continue;
			}
		}
		if (!(xmlStrcmp(childNode->name, (const xmlChar *)"routepath"))) {
			routepath = xmlNodeGetContent(childNode);
			if (routepath != NULL) {
				childNode = childNode->next;
				continue;
			}
		}
		childNode = childNode->next;
	}
	fd = xyses_open_route((char *)routepath);
	if (fd < 0) {
		syslog(LOG_ERR, "open route disk failed");
	} else {
		ret = xyses_check(fd);
		if (ret == 0) {
			switch(op_code) {
			case MPI2_SEP_REQ_SLOTSTATUS_NO_ERROR:
				xyses_set_led_off(fd, en_id, slot_id);
				break;
			case MPI2_SEP_REQ_SLOTSTATUS_DEV_FAULTY:
				xyses_set_led_on(fd, en_id, slot_id, DEVBAY_LED_ALWAYS);
				break;
			case MPI2_SEP_REQ_SLOTSTATUS_IDENTIFY_REQUEST:
				xyses_set_led_on(fd, en_id, slot_id, DEVBAY_LED_FLASH);
				break;
			default:
				break;
			}
		}
		close(fd);
	}
	xmlFree(routepath);
}
static void
disk_do_xyses_led(char *path, uint32_t op_code)
{
	xmlDocPtr doc;
	xmlNodePtr curNode, childNode;
	xmlChar *content;
	doc = xmlReadFile("/tmp/fmd_disk.xml", "UTF-8", XML_PARSE_RECOVER);
	if (NULL == doc) {
		fprintf(stderr, "open fmd disk xml failed");
		return;
	}
	curNode = xmlDocGetRootElement(doc);
	if (NULL == curNode) {
		fprintf(stderr, "get root elem failed");
		xmlFreeDoc(doc);
		return;
	}
	if (xmlStrcmp(curNode->name, BAD_CAST"root")) {
		fprintf(stderr, "xml is not matched");
		xmlFreeDoc(doc);
		return;
	}
	curNode = curNode->xmlChildrenNode;
	while(curNode != NULL) {
		if (!(xmlStrcmp(curNode->name, (const xmlChar *)"disk"))) {
			childNode = curNode->xmlChildrenNode;
			while(childNode != NULL) {
				if (!(xmlStrcmp(childNode->name, (const xmlChar *)"linkpath"))) {
					content = xmlNodeGetContent(childNode);
					if (!xmlStrcmp(content, (xmlChar *)path)) {
						/* have found the target disk */
						xmlFree(content);
						disk_do_ctrl_led(curNode, op_code);
						goto FINISH;
					}
					xmlFree(content);
					break;
				}
				childNode = childNode->next;
			}
		}
		curNode = curNode->next;
	}
FINISH:
	xmlFreeDoc(doc);
	return;
}

int 
disk_led_ctrl_data_disk(xmlNodePtr node , uint32_t op_code, int enclosure_num)
{
	xmlNodePtr childNode;
	xmlChar *content, *routepath;
	int en_id, slot_id;
	char dev_path[256];
	char sas_address[64];
	char sas_dev_name[64];
	int ret;
	childNode = node->xmlChildrenNode;
	while (childNode != NULL) {
		if (!(xmlStrcmp(childNode->name, (const xmlChar *)"sas_wwid"))) {
			content = xmlNodeGetContent(childNode);
			if (content != NULL) {
				sprintf(sas_address, "%s", (char*)content);
				xmlFree(content);
				childNode = childNode->next;
				continue;
			}
		}

		if (!(xmlStrcmp(childNode->name, (const xmlChar *)"name"))) {
			content = xmlNodeGetContent(childNode);
			if (content != NULL) {
				sprintf(sas_dev_name, "%s", (char*)content);
				xmlFree(content);
				childNode = childNode->next;
				continue;
			}
		}
		childNode = childNode->next;
	}

	if(strcmp(sas_address, "0") != 0) {
		sprintf(dev_path,"/dev/rdsk/c0t%s", sas_address);
	} else 
		sprintf(dev_path,"%s", sas_dev_name);
	
	ret = ses_led_set_disk_led(dev_path, op_code, enclosure_num);
	xmlFree(routepath);
	return ret;
}

int 
disk_led_get_sata_disk_info(char *dev_path, uint32_t op_code, int enclosure_num )
{
	int ret = 0;
	xmlDocPtr doc;
	xmlNodePtr curNode, childNode;
	xmlChar *content;
	doc = xmlReadFile(DISK_XML_PATH, "UTF-8", XML_PARSE_RECOVER);
	if (NULL == doc) {
		fprintf(stderr, "open fmd disk xml failed");
		return -1;
	}
	curNode = xmlDocGetRootElement(doc);
	if (NULL == curNode) {
		fprintf(stderr, "get root elem failed");
		xmlFreeDoc(doc);
		return -1;
	}
	if (xmlStrcmp(curNode->name, BAD_CAST"luns")) {
		fprintf(stderr, "xml is not matched");
		xmlFreeDoc(doc);
		return -1;
	}
	curNode = curNode->xmlChildrenNode;
	while(curNode != NULL) {
		if (!(xmlStrcmp(curNode->name, (const xmlChar *)"lun"))) {
			childNode = curNode->xmlChildrenNode;
			while(childNode != NULL) {
				if (!(xmlStrcmp(childNode->name, (const xmlChar *)"name"))) {
					content = xmlNodeGetContent(childNode);
					if (!xmlStrcmp(content, (xmlChar *)dev_path)) {
						/* have found the target disk */
						ret = disk_led_ctrl_data_disk(curNode, op_code, enclosure_num);
						goto FINISH;
					}
					xmlFree(content);
					break;
				}
				childNode = childNode->next;
			}
		}
		curNode = curNode->next;
	}
FINISH:
	xmlFreeDoc(doc);
	return ret;
}
#endif

static int led_disk(slice_req_t *req, int ledxy)
{
#if 0
	int ret;
	int en_no;
	int en_count;
	int index = 0;
	uint32_t op_code = 0;
	static char *devctl_device = NULL;
	struct stat stat_buf;
	uint32_t pathlen;
	devctl_hdl_t dcp = NULL;
	for (; ; index ++) {
		if ( disk_led_operation[index].operation_name == NULL)
			break;
		if (strcasecmp(req->led_operation, disk_led_operation[index].operation_name) == 0) {
			op_code =  disk_led_operation[index].operatio_code;
			break;
		}
	}
	if (op_code == 0) {
		printf("Invalid Disk Led operation\r\n");
		return (1);
	}
	if((devctl_device = malloc(MAXPATHLEN)) == NULL) {
		(void) fprintf(stderr,
			"malloc error:%s\n", strerror(errno));
			exit(-1);
	}
	if (lstat(req->disk_name, &stat_buf) == 0) {
		if (S_ISLNK(stat_buf.st_mode)) {
			if ((pathlen = readlink(req->disk_name, devctl_device,
			    MAXPATHLEN)) == -1)  {
				(void) fprintf(stderr,
					"devctl: readlink(%s) - %s\n",
					req->disk_name, strerror(errno));
				free(devctl_device);
				exit(-1);
			}
			devctl_device[pathlen] = '\0';
		}
	}
	
	/*
	 * SBB or DotHill enclosure led process
	 */
	en_no = disk_get_enclosure_num();
	en_count = disk_get_enclosure_amount();
	ret = 0;
	if (ledxy) {
		/* 
		* XYRATEX enclosure led process 
		*/ 
		printf("led xydisk\n");
		disk_do_xyses_led(req->disk_name, op_code);
	} else {
		if(en_no > 0){
			if (disk_check_enclosure_disk_type_sata()&& disk_check_dothill_enclosure()) {
				ret = disk_led_get_sata_disk_info (req->disk_name, op_code, en_no);
			} else
				ret = ses_led_set_disk_led(req->disk_name, op_code, en_no) ;
		}
		if ((ret == -1 && (disk_check_sbb_controller()||disk_check_sbb_enclosure()) )||en_count==0) {
			dcp = devctl_device_acquire(devctl_device, 0);
			devctl_device_led(dcp, op_code);
			led_set_quntum_encloure(req->disk_name,op_code);
		}
	}
	free(devctl_device);
	return (0);
#endif
}

/************************************************************************
 *
 * Function	:	zpool_get_vdev_by_path
 *		find the pool inclue the disk which we want disk init
 * parameter:
 *		nv:	the pool nv
 *		init_diskpath: disk init disk
 * Return	: 0-->the pool dont have the disk;we can disk init
 *		  1--> the pool have the disk; we can't disk init
 **************************************************************************/
int zpool_get_vdev_by_path(nvlist_t *nv,char *init_diskpath)
{
	nvlist_t **child;
		uint_t c, children;
		int ret = 0;
		char *path;
		char *type;
		uint64_t asize = 0;
	
		if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
			&child, &children) != 0) {
			verify(nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) == 0);
		
				/*printf("path=%s;oldpath = %s\n",path,init_diskpath);*/
			if (strncmp(init_diskpath,path,strlen(init_diskpath)) == 0)
				return 1;
			return (0);
		}
	
		for (c = 0; c < children; c++){
	
			if ((ret = zpool_get_vdev_by_path(child[c], init_diskpath)) != NULL){
				return (ret);
			}
		}
		return (ret);
}


/*
 * Function : disk_analyze_partition
 *		  judge partition & get pool name en_id slot_id
 * dev 	: the disk path
 * return	: the yes or no to disk init
 */
static int disk_analyze_partition(const char *dev)
{
	char dev_path[256];
	char c = 'n';
	char pool_name[256] = {0};
	int en_id,slot_id;
	int ret;
	zpool_handle_t	*zhp;
	libzfs_handle_t *tmp_gzfs;
	nvlist_t *nvroot;
#if 0
	bzero(dev_path,256);
	if (strncmp(dev, "/dev/rdsk/", 10) != 0){
		printf("can't find the disk please check it\n");
		return c;
	}
#endif
	
	/* get en_id & slot_id */
	ret = disk_get_enid_slotid(dev,&en_id,&slot_id);
	if (ret == -1) {
	/*maybe it is a  USB flash disk*/
		en_id = 0;
		slot_id = 0;	
	}
	
	/* get pool name */
	ret = disk_get_poolname(dev,pool_name);
	
	tmp_gzfs = libzfs_init();
	/* check pool is exist or not */
	if (pool_name != NULL) {
		zhp = zpool_open_canfail(tmp_gzfs, pool_name);
		if (zhp != NULL) {
#if 0
			if (strncmp(dev, "/dev/rdsk/", 10) == 0) {
				(void) snprintf(dev_path, 256, "%s%s", "/dev/dsk/", dev + 10);
			} else {
				strcpy(dev_path,dev);
			}
#else
			memcpy(dev_path, dev, strlen(dev));
#endif

			/* if the disk in the pool;can't initialize */
			nvroot = zpool_get_nvroot(zhp);
			if (zpool_get_vdev_by_path(nvroot,dev_path) == 1) {
				printf("The pool is in the current system\n");
				libzfs_fini(tmp_gzfs);
				return c;
			}
		}
	}
	libzfs_fini(tmp_gzfs);

	
	while(1) {
		
		printf("\n\n");
		if (ret == 0){
			printf("  %3s  %3d  %3d   --\n",dev,en_id,slot_id);
		} else if(ret == 1){
			printf("  %3s  %3d  %3d  %3s\n",dev,en_id,slot_id,pool_name);
			printf("  WARNING: the disk(%s)   INUSE   by   %s\n",dev,pool_name);
		} else if(ret == 2) {
			printf("  %3s  %3d  %3d   spare\n",dev,en_id,slot_id);
			printf("  WARNING: the disk(%s)   is   hot   spare\n",dev);
		}
			/*printf("  Once The Init Won't Be Able To Recover\n");*/
			printf("  Are You Sure Initialize the disk(y or n):");
		
		c = getchar();
		c = tolower(c);
		fflush(stdin);
		
		if (c == 'y' || c == 'n') 
			return c;
	}
}


int
main(int argc, char **argv) {
	int i;
	char enid[4];
	extern char *optarg; /* argument to optChar option */
	extern int optind; /* next option to process */
	extern int optopt; /* set to 0 to suppress errors */
	int optchar;
	int status = EXIT_SUCCESS; /* from stdlib */
	slice_req_t req_parms;
	char *subcommand = "";
	char *led_operation = "";
	dmg_lun_t dmt;
	int ledxy = 0;
	int all = 0;

	if (argc > 1) {
		subcommand = *(++argv);
		argc--;
	}
	memset(&req_parms, 0, sizeof (slice_req_t));
	req_parms.disk_index = req_parms.gap_index = req_parms.slice_index = -1;
	while ((optchar = getopt(argc, argv, OPTION_LETTERS)) != EOF) {
		switch (optchar) {

			case DISK_NAME_OPTION:
				strcpy(req_parms.disk_name, optarg);
				break;

			case LED_SET_OPTION:
				strcpy(req_parms.led_operation, optarg);
				break;
				
			case LEDXY_SET_OPTION:
				ledxy = B_TRUE;
				break;
				
			case DISK_INDEX_OPTION:
				req_parms.disk_index = atoi(optarg);
				break;

			case SLICE_INDEX_OPTION:
				req_parms.slice_index = atoi(optarg);
				break;

			case GAP_INDEX_OPTION:
				req_parms.gap_index = atoi(optarg);
				break;

			case SLICE_SIZE_OPTION:
				req_parms.mbytes = atoll(optarg);
				break;

			case '?':
				/* getopt has already printed a message */
				status = EXIT_FAILURE;
				break;

			default:
				fprintf(stderr, ERROR_INTERNAL_ERROR, argv[0]);
				status = EXIT_INTERNAL_ERROR;
				break;
		}
	}
	if (!status) {
		if ((strcasecmp(subcommand, SUBC_LIST) == 0) || !argc) {
			status = list_disks(all);
		} else if (strcasecmp(subcommand, SUBC_LIST_ALL) == 0) {
			all = 1;
			status = list_disks(all);
		} else if (strcasecmp(subcommand, SUBC_LIST_SLICES) == 0) {
			status = disk_list_slices(&req_parms, 1);
		} else if (strcasecmp(subcommand, SUBC_CREATE) == 0) {
			status = create_slice(&req_parms);
		} else if (strcasecmp(subcommand, SUBC_INIT) == 0) {
			if (disk_analyze_partition(req_parms.disk_name) == 'y')
				status = disk_init(&req_parms);
		} else if (strcasecmp(subcommand, SUBC_DELETE) == 0) {
			status = delete_slice(&req_parms);
		} else if (strcasecmp(subcommand, SUBC_GAPS) == 0) {
			status = list_gaps(&req_parms);
		} else if (strcasecmp(subcommand, SUBC_LED) == 0) {
			status = led_disk(&req_parms, ledxy);
			return (status);
		} else if (strcasecmp(subcommand, SUBC_MARK) == 0) {
			status = disk_mark(&req_parms);
		} else if (strcasecmp(subcommand, SUBC_RESTORE) == 0) {
			if (disk_check_inuse(req_parms.disk_name) ==0)
				status = disk_restore_init(&req_parms);
		}
		else if (argc) {
			fprintf(stderr, ERROR_SUBCOMMAND, argv[0]);
			status = EXIT_SUBCOMMAND;
		}
	}
	switch (status) {
	case EFI_FIRST:
	case EFI_FAILS:
		printf("EFI lable error for the lun, you perhaps need to initialize it\n");
		break;
	case 0:
		break;
	default:
		usage();
	}

	return (status);
}

static int
lun_sort_compare(const void *p1, const void *p2)
{

	dmg_lun_t *a, *b;

	a = (dmg_lun_t *)p1;
	b = (dmg_lun_t *)p2;

	if (a->en_no> b->en_no)
		return (1);
	if (a->en_no <  b->en_no)
		return (-1);

	if (a->lun_no > b->lun_no)
		return (1);
	if (a->lun_no < b->lun_no)
		return (-1);
	return (0);
}


static void
lun_sort(caddr_t v, int n, int s, int (*f)())
{
	int g, i, j, ii;
	unsigned int *p1, *p2;
	unsigned int tmp;

	/* No work to do */
	if (v == NULL || n <= 1)
		return;

	for (g = n / 2; g > 0; g /= 2) {
		for (i = g; i < n; i++) {
			for (j = i - g; j >= 0 &&
			    (*f)(*((unsigned *)(v + j * s)), *((unsigned *)(v + (j + g) * s))) == 1;
			    j -= g) {
				p1 = (unsigned *)(v + j * s);
				p2 = (unsigned *)(v + (j + g) * s);
				for (ii = 0; ii < s / 4; ii++) {
					tmp = *p1;
					*p1++ = *p2;
					*p2++ = tmp;
				}
			}
		}
	}
}

static void
sort_list_slotid(dmg_lun_t *luns, int *en_array, int tot_luns, int en_count)
{
	int i, j, count =0, slot_cnt = 0, lun_flag = 0;
	dmg_lun_t *new_luns = NULL;
	dmg_lun_t *tmp_lun = NULL;

	new_luns = (dmg_lun_t *)malloc(sizeof(dmg_lun_t) * tot_luns);
	if (new_luns == NULL) {
		printf("malloc failed!\n");
		return;
	}

	while (count < en_count) {
		/* Initialize */
		slot_cnt = 0;
		
		for (i = 0;i < tot_luns; i++) {
			/* firstly check enclosure id */
			if (luns[en_array[count]].en_no ==
				luns[i].en_no) {
				/* secondly check port id */
				if (luns[i].lun_no == luns[en_array[count]].lun_no) {
					/* disk in same enclosure */
					memcpy(new_luns+lun_flag+slot_cnt, luns+i, sizeof(dmg_lun_t));
					slot_cnt++;
				}
			}
		}

		qsort((caddr_t)(new_luns+lun_flag), slot_cnt, sizeof(dmg_lun_t), lun_sort_compare);
		
		/* update info */
		lun_flag += slot_cnt;
		count++;
		
	}

	/* copy sorted info to source luns */
	memcpy(luns, new_luns, sizeof(dmg_lun_t) * tot_luns);
	free(new_luns);
}

static void
sort_list_enid(dmg_lun_t *luns, int *en_array, int count)
{
	int i, j, sort_count = 0;
	int min, val, first_turn = 1;
	int check_success = 0;
	int check_flag = 0;
	
	while(sort_count < count) {
		min = sort_count;
		check_success = 0;
		check_flag = 0;
		
		/* first turn, to get the minimum enclosure id */
		if (first_turn) {
			for (j = sort_count+1; j < count; j++) {
				if (luns[en_array[j]].en_no < luns[en_array[min]].en_no) {
						min = j;
				}
			}
			
			val = en_array[sort_count];
			en_array[sort_count] = en_array[min];
			en_array[min] = val;
			first_turn = 0;
		} else {
			min = -1;
			
			for (j = sort_count;j < count; j++) {
				/* have the sorted equal enclosure id */
				if (luns[en_array[sort_count-1]].en_no >=
					luns[en_array[j]].en_no) {
					continue;
				} else {
					if (min == -1) {
						min = j;
					} else {
						if (luns[en_array[j]].en_no < 
							luns[en_array[min]].en_no)
							min = j;
					}
					check_flag = 1;
				}
			}

			if (check_flag) {
				val = en_array[sort_count];
				en_array[sort_count] = en_array[min];
				en_array[min] = val;
			} else { /*next turn */
				first_turn = 1;
				continue;
			}
		}
		sort_count++;
	}
}

static void
sort_list_disks(dmg_lun_t *luns, int tot_luns)
{
	int i, j, m;
	int  en_flag = 0, en_count= 0, en_array[64] = {0};
	int enid_equal = 0;

	/* Initialize */
	en_array[0] = 0;
	en_count = 1;
	
	for (i = 0; i < tot_luns; i++) {
		en_flag = 0;		/* if have the record, to be valid */

		if (luns[i].en_no == 0)	/* invalid enclosure id */
			continue;
		
		for (j = 0; j < en_count; j++) {
			/* firstly check enclosure id */
			if (luns[i].en_no == luns[en_array[j]].en_no) {
				/* secondly check port id */
				if (luns[i].lu_num > 0) {
					for (m = 0;m < luns[en_array[j]].lu_num;m++) {
						if (strcmp(luns[i].lu_info[0].portID,
							luns[en_array[j]].lu_info[m].portID) == 0) {
							/* en_id is equal and portid is equal */
							en_flag = 1;
							goto NEW_RECORD;
						}
					}
				} else {
					syslog(LOG_WARNING, "sort_check_equal_enid() lu_num is invalid");
					goto QSORT;
				}
			}
		}
		
NEW_RECORD:
		/* new record, add to enclosure array */
		if (!en_flag) {
			en_array[en_count] = i;
			en_count++;
		}
	}

	/* check enid is equal */
	for (i = 0; i < en_count/2; i++) {
		for (j = i+1;j < en_count;j++) {
			if (luns[en_array[i]].en_no == luns[en_array[j]].en_no)
				enid_equal = 1;
		}
	}

	if (enid_equal) {		/* have equal id */
#if 0
		printf("have the equal enid, tot_luns:%d\n", tot_luns);

		/* dump info */
		for (i = 0;i < en_count; i++)
			printf("before sort en_array[%d] value:%d\n", i, en_array[i]);
#endif
		sort_list_enid(luns, en_array, en_count);

#if 0
		/* dump info */
		for (i = 0; i < en_count; i++)
			printf("after sort en_array[%d] value:%d\n", i, en_array[i]);
#endif
		sort_list_slotid(luns, en_array, tot_luns, en_count);
	} else {
QSORT:
		qsort((caddr_t)luns, tot_luns, sizeof(dmg_lun_t), lun_sort_compare);
	}
}

static xmlNodePtr create_xml_file(void)
{
	xmlDocPtr doc = xmlNewDoc((xmlChar *)"1.0");
	xmlNodePtr root_node = xmlNewNode(NULL, (xmlChar *)"luns");
	xmlDocSetRootElement(doc, root_node);
	disk_doc = doc;
	disk_root_node = root_node;

	return (root_node);
}

static void close_xml_file(void)
{
	   xmlChar *xmlbuff;
	  int buffersize ;
	  xmlDocDumpFormatMemory(disk_doc, &xmlbuff, &buffersize, 1);

	  xmlSaveFormatFileEnc(DISK_XML_PATH, disk_doc, "UTF-8", 1);
	  xmlFreeDoc(disk_doc);
}



static void  create_lun_node(disk_info_t *di)
{
	char buf[256];
	double double_size ;
	xmlNodePtr node, name_node,  size_node, size_kb_node, status_node, rpm_node,
		vendorid_node, enid_node, slotid_node, pool_node ;

	node = xmlNewChild(disk_root_node, NULL, (xmlChar *)"lun", NULL);

	name_node=xmlNewChild(node, NULL, (xmlChar *)"name", NULL);
	xmlNodeSetContent(name_node, (xmlChar *)di->dk_name);
/*
	saswwid_node =xmlNewChild(node, NULL, (xmlChar *)"sas_wwid", NULL);
	sprintf(buf, "%llx", luns->sas_wwn);
	xmlNodeSetContent(saswwid_node, (xmlChar *)buf);
	memset(buf, 0, 256);
*/

	size_node=xmlNewChild(node, NULL,  (xmlChar *)"size", NULL);
	double_size = di->dk_blocks / 1024.0;
	if (double_size>= 1024.0 ) {
		if (double_size/ 1024.0  > 1024.0 )
			sprintf( buf, "%-3.2lfTB", (double_size/ 1024.0 ) / 1024.0 );
		else
			sprintf( buf, "%-3.2lfGB",double_size/ 1024.0 );
	} else {
		sprintf( buf, "%-3.2lfMB",double_size );
	}
	xmlNodeSetContent( size_node, (xmlChar *)buf);
	memset(buf, 0, 256);

	size_kb_node=xmlNewChild(node, NULL,  (xmlChar *)"size_kb", NULL);
	sprintf(buf, "%ld", di->dk_blocks);
	xmlNodeSetContent( size_kb_node, (xmlChar *)buf);
	memset(buf, 0, 256);

	status_node=xmlNewChild(node, NULL, (xmlChar *)"status", NULL);
	xmlNodeSetContent(status_node, (xmlChar *)di->dk_busy);

	vendorid_node=xmlNewChild(node, NULL, (xmlChar *)"vendor", NULL);
	xmlNodeSetContent(vendorid_node, (xmlChar *)di->dk_vendor);

	
	vendorid_node=xmlNewChild(node, NULL, (xmlChar *)"serial", NULL);
	xmlNodeSetContent(vendorid_node, (xmlChar *)di->dk_serial);
	
/*
	prodid_node=xmlNewChild(node, NULL,  (xmlChar *)"vendorid", NULL);
	xmlNodeSetContent(prodid_node, (xmlChar *)luns->model);
*/
	enid_node=xmlNewChild(node, NULL, (xmlChar *)"major", NULL);
	sprintf(buf, "%d", di->dk_major);
	xmlNodeSetContent(enid_node, (xmlChar *)buf);
	memset(buf, 0, 256);

	slotid_node=xmlNewChild(node,NULL,  (xmlChar *)"minor", NULL);
	sprintf(buf, "%d", di->dk_minor);
	xmlNodeSetContent(slotid_node, (xmlChar *)buf);
	memset(buf, 0, 256);

	enid_node=xmlNewChild(node, NULL, (xmlChar *)"enid", NULL);
	sprintf(buf, "%d", di->dk_enclosure ) ;
	xmlNodeSetContent(enid_node, (xmlChar *)buf);
	memset(buf, 0, 256);

	slotid_node=xmlNewChild(node,NULL,  (xmlChar *)"slotid", NULL);
	sprintf(buf, "%d", di->dk_slot);
	xmlNodeSetContent(slotid_node, (xmlChar *)buf);
	memset(buf, 0, 256);

	rpm_node=xmlNewChild(node,NULL,  (xmlChar *)"rpm", NULL);
	sprintf(buf, "%d", di->dk_rpm);
	xmlNodeSetContent(rpm_node, (xmlChar *)buf);
	memset(buf, 0, 256);

	pool_node = xmlNewChild( node, NULL, (xmlChar *)"pool", NULL ) ;
	if( di->dk_pool[0] != '\0' ) {
		xmlNodeSetContent( pool_node, (xmlChar *) (di->dk_pool) ) ;
	}else {
		xmlNodeSetContent( pool_node, (xmlChar *) "-" ) ;
	}
}

#if 0
/*
 * List all the disks/luns attached to the system
 */
int
list_disks() {
	int ii, jj, tot_luns = 0;
	int i = 0;
	dmg_lun_t *luns;
	dmg_lun_t *trans_lun;
	dmg_lun_t *final_lun;
	char buffer[20];
	FILE *fp;
	dmg_lun_t **tmp_luns;
	dmg_map_t map;
	char dim;
	char set_ssd_cmd[128];
	const char *status;
	int ret;
	uint64_t slotid, enid;
	int total_lun = 0;

	dmg_lun_t *cur_lun;

	struct hd_driveid hd_info;
	get_hd_info("/dev/sda", &hd_info);
#if 0
	create_xml_file();
#endif
	ret = dmg_get_disk(&luns, &tot_luns);
	if (ret != 1) {
			printf(ERROR_INTERNAL_ERROR, SUBC_LIST_DISKS);
			return (EXIT_INTERNAL_ERROR);
	}

	for (cur_lun = luns; cur_lun; cur_lun = cur_lun->lun_next){
#if 0
		if (cur_lun->gsize >= -0.00001 && cur_lun->gsize <= 0.00001) {
			continue;
		}
#endif

		total_lun++;
	}
	final_lun = trans_lun = (dmg_lun_t *)malloc(sizeof (dmg_lun_t)*total_lun);
	for (cur_lun = luns; cur_lun; cur_lun = cur_lun->lun_next){
#if 0
		if (cur_lun->gsize >= -0.00001 && cur_lun->gsize <= 0.00001) {
			continue;
		}
#endif

		trans_lun->name = cur_lun->name;

		trans_lun->vendor = cur_lun->vendor;
		trans_lun->model = cur_lun->model;

		trans_lun->rpm = cur_lun->rpm;
		trans_lun->en_no = cur_lun->en_no;
		trans_lun->lun_no = cur_lun->lun_no;
		trans_lun->sas_wwn = cur_lun->sas_wwn;

		trans_lun->lu_flag = cur_lun->lu_flag;
		trans_lun->blocks = cur_lun->blocks;
		trans_lun->bytes_per_block = cur_lun->bytes_per_block;
		trans_lun->gsize = cur_lun->gsize;
		trans_lun->lu_num = cur_lun->lu_num;
		trans_lun->slice_count= cur_lun->slice_count;
		if (cur_lun->slice_count == 8){
			trans_lun->status = strdup("free");
		}else {
			trans_lun->status = strdup("busy");
			
		}

		if(cur_lun->dim != NULL)
			strncpy(trans_lun->dim, cur_lun->dim, 24);
		trans_lun->lu_info = cur_lun->lu_info;

		trans_lun++;
	}
	
	sort_list_disks_new(final_lun, total_lun);

	for (ii = 0; ii < total_lun; ii++) {
		create_lun_node(&final_lun[ii]);
		printf("%3d. %-35s %-18s %-10s %-3.2lf%-5s	%-3lld   %-3lld  %-s\n", ii, final_lun[ii].name, final_lun[ii].vendor,
			final_lun[ii].model, final_lun[ii].gsize, final_lun[ii].dim, final_lun[ii].en_no,
			final_lun[ii].lun_no, final_lun[ii].status);
		printf("\n");
	}

	dmg_free_luns(final_lun, total_lun);
	dmg_free_lunlink(luns);

	//close_xml_file();
	return (0);
}
#endif

/*
 *  List slices on a disk
*/
int
disk_list_slices(slice_req_t *req, int lba_ordered) {
	dmg_map_t map;
	int status;

	if (status = get_disk_name(req, SUBC_INIT))
		return (status);

	status = dmg_get_slices(req->disk_name, map, lba_ordered);
	switch (status) {
	case EFI_SUCCESS:
		print_slices(req->disk_name, map, NULL);
		printf("\n\n");
		break;
	case EFI_FIRST:
		syslog(LOG_INFO, "The lun has no EFI table, need to initialize");
		break;
		
	case EFI_FAILS:
		syslog(LOG_INFO, "Reading the EFI table in the lun failed");
		break;
	}
	return status;
}

static void
print_slices(char *diskname, dmg_map_t map, dmg_lun_t *lun)
{
	char dim;
	int jj;

	printf("   %22s %26s %s\n", "Starting Block",
					"Size in blocks", "   Mnt Pt / FS" );
	printf("%26s %26s   %s", "----------------",
					"------------------", "-----------");
	for (jj = 0; jj < MAX_SLICES_PER_LUN; jj++) {
		if (map[jj].assigned) {
			char start_dim, size_dim;
			double start_norm, size_norm;

			start_norm = size_down(map[jj].start, &start_dim);
			size_norm = size_down(map[jj].blocks, &size_dim);

			printf("\n   s%d %ll12d (%6.2lf%c) %ll18d (%6.2lf%c)",
				map[jj].index, map[jj].start, start_norm,
				start_dim,
					map[jj].blocks, size_norm, size_dim);
			if (map[jj].mount) 
				printf("   %s", map[jj].mount);
			else
				printf("   %s", "-------");
			
		}
	}
}

/*
 *  Completely erase all slices in a disk
 */
int
disk_init(slice_req_t *req)
{
	int status;
	zpool_stamp_t *stamp = NULL;
	zpool_stamp_t *stamp_tmp = NULL;
	char args[ARGS_LEN] = {0};
	
	if (status = get_disk_name(req, SUBC_INIT))
		return (status);
	
	(void) get_system_disk(args);
	if (strncmp(args, req->disk_name, 8) == 0) {
		printf("sorry, this is system disk!\n");
		return (-1); 
	}

	/*
	 * Initialize zfs label info
	 */
	stamp_tmp = malloc(sizeof(zpool_stamp_t));
	if (stamp_tmp != NULL) {
		bzero(stamp_tmp, sizeof(zpool_stamp_t));
		zpool_read_stmp_by_path(req->disk_name,stamp_tmp);
	}

#if 0
	/* save disk label when arg2 save_rescover==1 */
	if (zpool_restore_dev_labels(req->disk_name, 1) != 0) {
		printf("save label fail\n");
	}
	
	zpool_init_dev_labels(req->disk_name);
		
	strcpy(buffer, req->disk_name);
	len = strlen(req->disk_name);
	/*
	 * /dev/rdsk/cXtXdXp0 alway represent the whole disk
	 * /dev/rdsk/cXtXdX file only exist on efi lable
	 */
	 /* if disk_name is slice , don't run dmg_put_slices*/
	if ((buffer[len-1] == '0') && (buffer[len-2] == 'd')){
		if (strstr(req->disk_name, "/dev/did") != req->disk_name)
			strcat(req->disk_name, "p0");
		memset(map, 0, sizeof (dmg_map_t));

	if (dmg_put_slices(req->disk_name, map, B_TRUE)) {
		printf(ERROR_INTERNAL_ERROR, SUBC_INIT);
		syslog(LOG_ERR,"disk init %s; error 125: Internal error",req->disk_name,SUBC_INIT);
		return (EXIT_INTERNAL_ERROR);
		}
	}
#endif
	/* add init efi */
	(void) disk_init_efi(req->disk_name);

	/*
	 * Initialize zfs stamp info
	 */
	stamp = malloc(sizeof(zpool_stamp_t));
	if (stamp != NULL) {
		bzero(stamp, sizeof(zpool_stamp_t));
		if(stamp_tmp->para.company_name == COMPANY_NAME)
			stamp->para.company_name = stamp_tmp->para.company_name;
		zpool_write_dev_stamp(req->disk_name, stamp);
		zpool_write_dev_stamp_mark(req->disk_name, stamp);
		free(stamp);
		
	}
	free(stamp_tmp);
	//system("/usr/sbin/devfsadm");
	return (0);
}

/*
 * Function: check disk inuse. if the disk inuse can't restore it.
 *
 * Return	: 0==>can't inuse. -1==>inuse by pool.
 *
 */
static int disk_check_inuse(const char *dev)
{
	char pool_name[256] = {0};
	int ret;

	if (strncmp(dev, "/dev/rdsk/", 10) != 0){
		printf("can't find the disk please check it\n");
		return (-1);
	}

	/* get pool name */
	ret = disk_get_poolname(dev,pool_name);
	if (ret == 1) {
		printf("the disk is inuse by %s pool,can't restore\n",pool_name);
		return (-1);
	}
	return (0);
}
/*
 * Function: disk_restore_init
 *	restore disk label.it a chance to recover damage pool
 */
int
disk_restore_init(slice_req_t *req)
{
	char disk_id[256] = {0};
	char *tmp_id;
	int ret;
	libzfs_handle_t *tmp_gzfs;

	if (strncmp(req->disk_name, "/dev/rdsk/", 10) != 0) {
		printf("can't find the disk please check it\n");
		return (-1);
	}

	bzero(disk_id, 256);
	/* get disk num c0txxxxd0 */
	tmp_id = req->disk_name + 10;
	strcpy(disk_id, tmp_id);

	tmp_gzfs = libzfs_init();
	/* restore p0 */
	if (ret = zpool_label_disk(tmp_gzfs, NULL, disk_id) == -1) {
		libzfs_fini(tmp_gzfs);
		return (-1);
	}

	/* restore disk label when arg2 save_rescover==0 */
	if (zpool_restore_dev_labels(req->disk_name, 0) != 0) {
		printf("restore fail\n");
	}
	libzfs_fini(tmp_gzfs);
	return (0);
}

static int disk_mark(slice_req_t *req)
{
	int ret=0;
	char buffer[256] = {"\0"};
	zpool_stamp_t *stamp = NULL;
	int fd;
	char drv_opath[256] = {"\0"};
	int slice_count = -1;
	int i, len = 0;
	struct dk_gpt *vtoc;
	int err = -1;

	ret = get_disk_name(req, SUBC_MARK);
	if (ret)
		return (ret);
#if 0
	strcpy(buffer, req->disk_name);
	
	len = strlen(buffer);
	/*add by jbzhao 20151202 begin
	 * for disk mark slice 0~6*/
	if ( buffer[len -1] == '0' && buffer[len - 2] == 'd'){
	/*add by jbzhao 20151202 end*/

	/*
	 *read EFI label and scan all slices,
	 *if slices 0 ~ 7 p_size is 0,
	 *shows this disk is free
	 */
		sprintf(drv_opath,"%s%s",buffer,"p0");
#else
	memcpy(drv_opath, req->disk_name, strlen(req->disk_name));
#endif
	if ((fd = open(drv_opath, O_RDONLY|O_NDELAY)) >= 0) {
		if ((err = efi_alloc_and_read(fd, &vtoc)) >= 0) {
			for(i = 0; i < vtoc->efi_nparts; i++){
				if(vtoc->efi_parts[i].p_size != 0){
					slice_count = i;
					break;
				}
			}
			efi_free(vtoc);
		}
		(void) close(fd);
	}else {
		syslog(LOG_ERR, "disk mark open path:<%s> failed.", drv_opath);
		ret = 1;
		return (ret);
	}

	if(slice_count != 8){
		printf("%s is not free,don't need mark\n",buffer);
		ret = 1;
		return (ret);
	}
#if 0
/*add by jbzhao 20151202 begin*/
	}
/*add by jbzhao 20151202 end */
#endif
	stamp = malloc(sizeof(zpool_stamp_t));
	if (stamp != NULL) {
		bzero(stamp, sizeof(zpool_stamp_t));
		stamp->para.company_name = COMPANY_NAME;
		ret=zpool_write_dev_stamp_mark(req->disk_name, stamp);
		free(stamp);
	}
	if(ret)
		printf("mark fail!\n");
	return (ret);
	
}

