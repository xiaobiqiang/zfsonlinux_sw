#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <disklist.h>
#include <libdiskmgt.h>
#include <sys/efi_partition.h>
#include <sys/vtoc.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <libsysenv.h>
#include <scsi/sg.h>
#include <linux/ioctl.h>
#include <linux/hdreg.h>

#include <thread.h>
#include <pthread.h>
#include <dirent.h>

/*
 * Error messages and status codes (these should be internationalized)
 */
#define	ERROR_NO_OPERANDS "%s: Error 2: Expected one or more operands\n"
#define	ERROR_TOO_MANY_OPERANDS "%s: Error 3: Expected operands"
#define	ERROR_NO_FILE "%s: Error 6: Expected file to be specified (-o name)\n"
#define	ERROR_INTERNAL_ERROR "%s: Error 125: Internal error\n"

#define	EXIT_NO_OPERANDS 2
#define	EXIT_NO_FILE 3
#define	EXIT_INTERNAL_ERROR 125

#define	DISK_MAX_NUM	256
#define DAD_MODE_GEOMETRY 0x04

#define DISK_BOOT_LABEL		"%rd%cds$"
#define DISK_ROOT_PATH 		"/var/root_disk.tmp"
#define DISK_PRODUCT_ID		"ST33000650SS"
#define DISK_VENDOR_ID		"SEAGATE"

#define	GIG   *1024*1024*1024ULL

#define MX_ALLOC_LEN (0xc000 + 0x80)
#define VPD_UNIT_SERIAL_NUM 0x80
#define VPD_DEVICE_ID  0x83
#define DEF_ALLOC_LEN  252
#define SENSE_BUFF_LEN 64
#define DEF_TIMEOUT 60       /* 60 seconds */

#define	INQUIRY_CMD			0x12
#define	INQUIRY_CMDLEN			6
#define IMPOSSIBLE_SCSI_STATUS          0xff
#define MODE_SENSE_PC_CURRENT   (0 << 6)
#define MODE_SENSE_PC_DEFAULT   (2 << 6)
#define MODE_SENSE_PC_SAVED     (3 << 6)
#define MODESENSE_PAGE_LEN(p)   (((int)((struct mode_page *)p)->length) + \
                                    sizeof (struct mode_page))

static	char scale [4] = {'K', 'M', 'G', 'T'};


void found_slice(dm_descriptor_t *disk, dmg_lun_t *);
void found_media(dm_descriptor_t *disk, dmg_lun_t *);
void found_disk(dm_descriptor_t *disk, int, dmg_lun_t *);

extern double size_down(uint64_t, char *dim);

uint32_t disk_efi_flag[DISK_MAX_NUM];

int disk_debug = 1;
int thread_count = 0;

static int
disk_get_mpath_check()
{
	int ret = 0, rval = 0, amount = 0;
	char *str = NULL;

	ret = df_loadsysenv(NULL);
	if (ret == 0) {
		str = df_getsysenv(ENC_VENDOR);
		if (str && (strstr(str, "LS"))) {
			/* lsi enclosure has no need to get mpath info */
			rval = 1;
		} else {
			/*
			 * xyratex enclosure, if amount is no more than 7, there is no
			 * need to get mpath info 
			 */
			str = df_getsysenv(ENC_AMOUNT);
			if (str != NULL) {
				amount = strtol(str, NULL, 10);
				if (amount < 8)
					rval = 1;
			}
		}
		df_savefree();	
	}
	
	return rval;
}
#if 0
int
get_device_wwn(dmg_lun_t *lun, char *buf_wwn)
{
	int fd;
	int m;
	int pg_op = 0x83;
	int mx_resp_len;
	int err = -1;
	const unsigned char * ip;
	struct uscsi_cmd uscsi;
	unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
	unsigned char rsp_buff[MX_ALLOC_LEN + 1];
	
	/* prepare struct uscsi_cmd for ioctl */
	/* 1 cdb */
    inqCmdBlk[1] |= 1;
    inqCmdBlk[2] = (unsigned char)pg_op;
    /* 16 bit allocation length (was 8) is a recent SPC-3 addition */
	mx_resp_len = sizeof(rsp_buff);
    inqCmdBlk[3] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    inqCmdBlk[4] = (unsigned char)(mx_resp_len & 0xff);
	
	uscsi.uscsi_cdb = (char *)inqCmdBlk;
    uscsi.uscsi_cdblen = sizeof(inqCmdBlk);

	/* 2 sense */
	uscsi.uscsi_rqbuf = (char *)sense_b;
    uscsi.uscsi_rqlen = sizeof(sense_b);
    /*max_sense_len = max_sense_len;*/
	
	/* 3 data*/
	uscsi.uscsi_bufaddr = (char *)rsp_buff;
    /*uscsi.uscsi_buflen = DEF_ALLOC_LEN;*/
	uscsi.uscsi_buflen = sizeof(rsp_buff);
    uscsi.uscsi_flags = USCSI_READ | USCSI_ISOLATE | USCSI_RQENABLE;

	uscsi.uscsi_timeout = DEF_TIMEOUT;


    rsp_buff[0] = 0x7f;   /* defensive prefill */
    rsp_buff[4] = 0;

	
	/* to get device wwn info */
	if ((fd = open(lun->name, O_RDWR|O_NONBLOCK)) >= 0) {
		printf("get WWN: open device:%s success\n", lun->name);
		if (ioctl(fd, USCSICMD, &uscsi)) {
			ip = rsp_buff;
			ip = ip + 4;
			memset(buf_wwn, 0, 20);
			/*
			for (m = 0; m < 8; ++m){
            		snprintf(buf_wwn, 1, "%2x", (unsigned int)ip[m]);
			}*/
			printf("get WWN: ioctl device:%s USCSICMD success\n", lun->name);
		}else{
			printf("get WWN: ioctl device:%s USCSICMD failed\n", lun->name);
		}
		(void) close(fd);
	}else {
		printf("get WWN: open device:<%s> failed\n", lun->name);
		syslog(LOG_ERR, "open path:<%s> failed.", lun->name);
		return (-1);
	}	

	return (0);
}
#endif

static int
disk_get_enclosure_check()
{
	int ret = 0, rval = 0 ;
	char *str = NULL;

	ret = df_loadsysenv(NULL);
	if (ret == 0) {
		str = df_getsysenv(ENC_VENDOR);
		if (str && (strstr(str, "DH"))) {
			/* lsi enclosure has no need to get mpath info */
			str = df_getsysenv(CTL_VENDOR);
			if (str && (strstr(str, "SBB"))) 
				rval = 1;
		} 
		df_savefree();	
	}
	return rval;
}
static int is_root_disk(dm_descriptor_t *disk_desc)
{
	int err = 0, ret = -1, fd, idx;
	char *label = NULL, dev_path[1024] = {"\0"}, *drv_opath;
	nvlist_t *attrs;
	struct stat st;
	struct extvtoc vtoc;
	struct dk_geom geom;
	struct dk_gpt *efi;

	int fd_root, read_size;
	char buf[128] = {"\0"};

	attrs = dm_get_attributes(*disk_desc, &err);	
	if (err != 0) {
		syslog(LOG_ERR, " is_root_disk() get attr failed");
		return (-1);
	}
	
	nvlist_lookup_string(attrs, DM_OPATH, &drv_opath);
	drv_opath [strlen(drv_opath)-2] = 0;
	sprintf(dev_path, "%s%s", drv_opath, "s2");	
#if 0
	fd = open(DISK_ROOT_PATH, O_RDONLY);
	if(fd < 0){
		syslog(LOG_INFO, "the root_disk_path file open failed");
	}else{
		read_size = read(fd, buf, sizeof(buf));
        if (read_size <= 0) {
            syslog(LOG_ERR, "read root_disk_path file failed, read size:%d", read_size);
        	close(fd);
        }else{
			ret = strncmp(dev_path, buf, strlen(buf)-2);
			if(ret == 0){
				syslog(LOG_ERR, "the device %s is root disk", dev_path);
				close(fd);
				return (0);
			}else{
				/*
				syslog(LOG_ERR, "the device %s is not root disk", dev_path);
				*/
				close(fd);
				return (-1);
			}
        }
	}
#else
	if ((fd = open(dev_path, O_NONBLOCK | O_RDONLY)) >= 0) {
		if (read_extvtoc(fd, &vtoc) >= 0) {
			if (strcmp(vtoc.v_volume, DISK_BOOT_LABEL) == 0) {
				syslog(LOG_INFO, "path<%s> is boot disk", dev_path);
				ret = 0;
			}
		} else {
			if (efi_alloc_and_read(fd, &efi) >= 0) {
				for (idx = 0; idx < efi->efi_nparts; ++idx) {
					if (efi->efi_parts[idx].p_tag == V_BOOT) {
						syslog(LOG_INFO, "path<%s> is boot disk", dev_path);
						ret = 0;
						break;
					}
				}
				efi_free(efi);	
			} else {
				syslog(LOG_ERR, " get efi failed.");
			}
		}
		close(fd);
	} else {
		goto failed;
	} 
#endif
	
failed:
	nvlist_free(attrs);
	return (ret);
}

typedef struct dmg_lun_head{
        dmg_lun_t *lun_next;
}dmg_lun_head_t;

static int
get_rpm(int fd, int page_code, int page_control,uint32_t *rpm){
#if 0
	caddr_t                 mode_sense_buf;
	struct mode_header      *hdr;
	struct mode_page        *pg;
	int                     nbytes;
	struct uscsi_cmd        ucmd;
	union scsi_cdb          cdb;
	int                     status;
	int                     maximum;
	char                    rqbuf[255];
	struct mode_geometry *page_data;
	int page_size = 255;
	nbytes = sizeof (struct block_descriptor) +
		sizeof (struct mode_header) + page_size;
	nbytes = page_size;
	if ((mode_sense_buf = malloc((uint_t)nbytes)) == NULL) {
		return (0);
	}
	

	(void) memset(mode_sense_buf, 0, nbytes);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	(void) memset((char *)&cdb, 0, sizeof (union scsi_cdb));

	cdb.scc_cmd = SCMD_MODE_SENSE;
	FORMG0COUNT(&cdb, (uchar_t)nbytes);
	cdb.cdb_opaque[2] = page_control | page_code;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = mode_sense_buf;
	ucmd.uscsi_buflen = nbytes;

	ucmd.uscsi_flags |= USCSI_SILENT;
	ucmd.uscsi_flags |= USCSI_READ;
	ucmd.uscsi_timeout = 30;
	ucmd.uscsi_flags |= USCSI_RQENABLE;
	if (ucmd.uscsi_rqbuf == NULL)  {
		ucmd.uscsi_rqbuf = rqbuf;
		ucmd.uscsi_rqlen = sizeof (rqbuf);
		ucmd.uscsi_rqresid = sizeof (rqbuf);
	}
	ucmd.uscsi_rqstatus = IMPOSSIBLE_SCSI_STATUS;

	status = ioctl(fd, USCSICMD, &ucmd);

	if (status || ucmd.uscsi_status != 0) {
		free(mode_sense_buf);
		return (0);
	}

	hdr = (struct mode_header *)mode_sense_buf;
	if (hdr->bdesc_length != sizeof (struct block_descriptor) &&
		hdr->bdesc_length != 0) {
		free(mode_sense_buf);
		return (0);
	}
	pg = (struct mode_page *)((ulong_t)mode_sense_buf +
		sizeof (struct mode_header) + hdr->bdesc_length);
	if (pg->code != page_code) {
		free(mode_sense_buf);
		return (0);
	}

	maximum = page_size - sizeof (struct mode_page) - hdr->bdesc_length;
	if (((int)pg->length) > maximum) {
		free(mode_sense_buf);
		return (0);
	}

	page_data = malloc(sizeof(struct mode_geometry));
	if (page_data == NULL){
		free(mode_sense_buf);
		return (0);
	}
	
	(void) memcpy(page_data, (caddr_t)pg, MODESENSE_PAGE_LEN(pg));
	*rpm = ntohs(page_data->rpm);
	free(page_data);
	free(mode_sense_buf);
#endif
	return 1;
}

static void
disk_get_attributes_func(void *arg)
{
	struct dmg_lun_head *lun;

	dmg_lun_t *cur_lun;
	dmg_lun_t *real_lun = NULL;
	int ret, i, flag = 0;
	int fd;
	int len;
	int status;
	char *drv_prod_id, *drv_vend_id;
	uint32_t drv_type;
	char *dev_name;
	char drv_opath[128] = {"\0"};

	un_locate_info_t un_info;
	struct dk_geom   geom_info;
	struct dk_cinfo  cntrl_info;
	struct vtoc 	vtoc;

	int partition_num;
	uint64_t en_instance;
	uint64_t lu_valid_flag = 0;
	char *productid;

	productid = (char *)malloc(17);
	real_lun = (dmg_lun_t *)arg;
	len	= strlen(real_lun->name);
	//snprintf(drv_opath,  len +3, "%s%s", real_lun->name, "p0"); 
	snprintf(drv_opath, len+2, "%s", real_lun->name);

		syslog(LOG_ERR, "path = %s;name = %s",drv_opath,real_lun->name);
	/* to get media info */
	if ((fd = open(drv_opath, O_RDWR | O_NDELAY)) >= 0) {

		/* to get enclosure id and slot id info */
		/* to get media size info */
		if (ioctl(fd, DKIOCGETLUNEXT, &un_info) == 0) {

			memset(productid, 0, 17);
			for (i = 0; i < 16; i++){
				if(((un_info.productid[i] <= 'Z')&& (un_info.productid[i] >= 'A')) ||
						((un_info.productid[i] >= '0')&&(un_info.productid[i] <= '9'))){
					productid[i] = un_info.productid[i];
				}else{
					break;
				}
			}
			/*strncpy(productid, un_info.productid, 15);*/
			real_lun->blocks = un_info.block_count;
			real_lun->bytes_per_block = un_info.block_size;
			real_lun->gsize = size_down(real_lun->blocks, real_lun->dim);
			real_lun->model = strdup(un_info.vendorid);
			real_lun->vendor = productid;
			real_lun->en_no = un_info.en_id;
			real_lun->lun_no = un_info.slot_id;
			real_lun->sas_wwn = un_info.sas_wwn;
		syslog(LOG_ERR, "blocks = %d",real_lun->blocks);
			lu_valid_flag = 1;
		}
		syslog(LOG_ERR, "lu_flag = %d",lu_valid_flag);
		real_lun->lu_flag = lu_valid_flag;

		close(fd);
	} else {
		syslog(LOG_ERR, "open path:<%s> failed.", drv_opath);
	}


	if ((fd = open(drv_opath,  O_RDWR| O_NDELAY )) >= 0) {
		status = get_rpm(fd,DAD_MODE_GEOMETRY,MODE_SENSE_PC_DEFAULT,&real_lun->rpm);
		if(!status)
			get_rpm(fd,DAD_MODE_GEOMETRY,MODE_SENSE_PC_SAVED,&real_lun->rpm);
		if(!status)
			get_rpm(fd,DAD_MODE_GEOMETRY,MODE_SENSE_PC_CURRENT,&real_lun->rpm);
		close(fd);
	}
#if 0
	if(!status)
		real_lun->rpm = 15015;
#endif
#if 0
	real_lun->blocks = 1172123568;
	real_lun->bytes_per_block = 512;
	real_lun->gsize = size_down(real_lun->blocks, real_lun->dim);
	real_lun->model = strdup(DISK_VENDOR_ID);
	real_lun->vendor = strdup(DISK_PRODUCT_ID);


	/* to get media info */
	if ((fd = open(drv_opath, O_RDWR | O_NDELAY)) >= 0) {

		/* to get enclosure id and slot id info */
		/* to get media size info */
		if (ioctl(fd, DKIOCGETLUNEXT, &un_info) == 0) {



			real_lun->en_no = un_info.en_id;
			real_lun->lun_no = un_info.slot_id;
			real_lun->sas_wwn = un_info.sas_wwn;
			lu_valid_flag = 1;


		}
		real_lun->lu_flag = lu_valid_flag;

		close(fd);
	} else {
		syslog(LOG_ERR, "open path:<%s> failed.", drv_opath);
	}

#endif
#if 0
	/* to get media slice info */
	if ((fd = open(drv_opath, O_RDONLY|O_NDELAY)) >= 0) {
		struct dk_gpt *vtoc;
		int i;
		int err = -1;
		if ((err = efi_alloc_and_read(fd, &vtoc)) >= 0) {
			for(i = 0; i < vtoc->efi_nparts; i++){
				if(vtoc->efi_parts[i].p_size != 0){
					real_lun->slice_count = i;
					break;
				}
			}
			efi_free(vtoc);
		}
		(void) close(fd);
	}else {
		syslog(LOG_ERR, "open path:<%s> failed.", drv_opath);
	}
#endif

	return;
}

static int is_root_disk_new(const char *dev_path)
{
	int err = 0, ret = -1, fd, idx;
	char *label = NULL;
	char drv_path[128];
	nvlist_t *attrs;
	struct stat st;
	struct extvtoc vtoc;
	struct dk_geom geom;
	struct dk_gpt *efi;
	sprintf(drv_path,"%s%s","/dev/",dev_path);
	if ((fd = open(drv_path, O_NONBLOCK | O_RDONLY)) >= 0) {
		if (read_extvtoc(fd, &vtoc) >= 0) {
			if (strcmp(vtoc.v_volume, DISK_BOOT_LABEL) == 0) {
				syslog(LOG_ERR, "path<%s> is boot disk", drv_path);
				ret = 0;
			}
		} else {
			if (efi_alloc_and_read(fd, &efi) >= 0) {
				for (idx = 0; idx < efi->efi_nparts; ++idx) {
					if (efi->efi_parts[idx].p_tag == V_BOOT) {
						syslog(LOG_ERR, "path<%s> is boot disk", drv_path);
						ret = 0;
						break;
					}
				}
				efi_free(efi);	
			} else {
				syslog(LOG_ERR, " get efi failed.");
			}
		}
		close(fd);
	}else{
		syslog(LOG_ERR, "path<%s> can not open ", drv_path);
	}



	return (ret);
}

/*
 * Function:	get enid &sloid from dev
 * Parameters:
 *  	drv_opath	 : We get information from this drv_opath
 *	en_id  : get en_id
 *	slot_id: get slot_id
 */
	int
disk_get_enid_slotid(const char *dev ,int *en_id,int *slot_id)
{

	int fd;
	int ret = -1;
	un_locate_info_t un_info;

	if ((fd = open(dev, O_RDWR | O_NDELAY)) >= 0) {

		/* to get enclosure id and slot id info */
		if (ioctl(fd, DKIOCGETLUNEXT, &un_info) == 0) {

			*en_id = un_info.en_id;
			*slot_id = un_info.slot_id;
			ret = 0;
		}

		close(fd);
	} else {
		syslog(LOG_ERR, "open path:<%s> failed.", dev);
		ret = -1;
	}
	return ret;
}


	int
dmg_get_disk(dmg_lun_t **luns, int *tot_luns)
{
	int ret = 0;
	struct dirent64 *dp;
#if 0
	static char *default_dir = "/dev/rdsk";
#endif
	static char *default_dir = "/dev";
	struct dmg_lun_head lun_head;
	dmg_lun_t *trans_lun;
	dmg_lun_t *cur_lun;
	dmg_lun_t *mark_lun;
	int dev_count = 0;
	int link_len = 0;

	syslog(LOG_ERR, "function dmg_get_disk");

	char root_disk_path[128] = {"\0"};
	char dev_path[128] = {"\0"};
	char drv_path[128] = {"\0"};
	char trans_name[128] = {"\0"};
	int fd, read_size;
	int dfd;
	/*
	 * If opening the path fails, we fall back to using
	 * the normalized user supplied input path and ignore
	 * this optimization.
	 */
	if ((dfd = open64(default_dir, O_RDONLY)) < 0) {
		syslog(LOG_ERR, "can't not open path:%s, dmg_get_disk return", default_dir);
		(void) close(dfd);
		return (-1);
	}

	DIR *dirp = NULL;
	if ((dirp = fdopendir(dfd)) == NULL) {
		syslog(LOG_ERR, "cann't open dir:%s", default_dir);
		(void) close(dfd);
		return (-1);
	}
	/*
	 * This is not MT-safe, but we have no MT consumers
	 * of libzfs
	 */
	lun_head.lun_next = NULL;
	while ((dp = readdir64(dirp)) != NULL) {
		const char *name = dp->d_name;
		size_t len;

		if ((strncmp(name, "sd", 2) != 0) &&
				(strncmp(name, "hd", 2) != 0)) {
			continue;
		}

		dev_count++;
		memset(dev_path,0,128);
		memset(drv_path,0,128);

		len = strlen(default_dir) + strlen(name);
		(void) snprintf(dev_path, len+2, "%s/%s", default_dir, name);
		(void) snprintf(drv_path, len+2, "%s/%s", default_dir, name);
		syslog(LOG_ERR, "dev = %s; drv = %s", dev_path,drv_path);
		fd = open(drv_path, O_RDWR);	
		if(fd<0){
			syslog(LOG_ERR, "can not open device %s", drv_path);
			continue;
		}
		close(fd);

		cur_lun = (dmg_lun_t *)malloc(sizeof(dmg_lun_t));
		memset(cur_lun, 0, sizeof(dmg_lun_t));
		cur_lun->lun_next = NULL;
		cur_lun->name = strdup(dev_path);

		if(lun_head.lun_next== NULL){
			lun_head.lun_next = cur_lun;
			mark_lun = cur_lun;
		}else{
			mark_lun->lun_next = cur_lun;
			mark_lun = cur_lun;
		}
		link_len++;

	}
	(void) closedir(dirp);
	(void) close(dfd);

#if 0
	/*
	 * Create a thread pool to do all of this in parallel;
	 * rn_nozpool is not protected, so this is racy in that
	 * multiple tasks could decide that the same slice can
	 * not hold a zpool, which is benign.  Also choose
	 * double the number of processors; we hold a lot of
	 * locks in the kernel, so going beyond this doesn't
	 * buy us much.
	 */
	tpool_t *t;
	t = tpool_create(1, 2 * sysconf(_SC_NPROCESSORS_ONLN), 0, NULL);
	t = tpool_create(32, 64, 0, NULL);
#endif

	for (trans_lun = lun_head.lun_next; trans_lun; trans_lun = trans_lun->lun_next){
#if 0
		(void) tpool_dispatch(t, disk_get_attributes_func, trans_lun);
#else
		disk_get_attributes_func(trans_lun);
#endif
	}
#if 0
	tpool_wait(t);
	tpool_destroy(t);
#endif

	*luns = lun_head.lun_next;
	*tot_luns = link_len;

	return (1);
}

	int 
set_dev_info_to_sd(dmg_lun_t *luns, int tot_luns)
{
	char drv_opath[128];
	un_locate_info_t un_info;
	int len;
	int i;
	int fd;

	for(i=0;i<tot_luns;i++){
		len	= strlen(luns[i].name);
		snprintf(drv_opath,  len +3, "%s%s", luns[i].name, "s2"); 
		un_info.en_id = luns[i].en_no;
		un_info.slot_id = luns[i].lun_no;

		if ((fd = open(drv_opath, O_RDWR | O_NDELAY)) >= 0) {
			ioctl(fd, DKIOCSETLUNEXT, &un_info);
			close(fd);
		} else {
			syslog(LOG_ERR, "the device %s  open fail", drv_opath);
		}
	}
	return 1;
}

int
dmg_get_luns(dmg_lun_t **luns, int *tot_luns) {
	dm_descriptor_t *disk_dev_descrs, *disk_dev_scan;
	int filter[2], error, ii, count = 0;
	dmg_lun_t *cur_lun;
	int ret;

	/*
	 * Setup disk driver filter descriptors.  Only disks
	 * of these types will get returned from dm_get_descriptors
	 * --------------------------------------------------------------------
	 */
	filter[0] = DM_DT_FIXED;
	filter[1] = DM_FILTER_END;

	disk_dev_scan = disk_dev_descrs =
		dm_get_descriptors(DM_DRIVE, filter, &error);
	if (error != 0) {
		syslog(LOG_ERR, "dm_get_descriptors_failed.. %s\n", strerror(errno));
		return (-1);
	}

	/*
	 * Count how many devices are attached so that we can allocate memory
	 * for our caller
	 * --------------------------------------------------------------------
	 */

	for (ii = 0; *disk_dev_scan; ii++) {
		ret = is_root_disk(disk_dev_scan);
		disk_dev_scan++;
		if (ret == 0) {
			continue;
		}
		count++;
	}

	*tot_luns = count;
	cur_lun = *luns = (dmg_lun_t *)malloc(sizeof (dmg_lun_t)*ii);
	memset(*luns, 0, sizeof (dmg_lun_t)*ii);
	disk_dev_scan = disk_dev_descrs;
	for (ii = 0; *disk_dev_scan; ii++) {
		ret = is_root_disk(disk_dev_scan);
		if(ret == 0) {
			disk_dev_scan++;
			continue;
		}

		found_disk(disk_dev_scan++, ii, cur_lun);
		if(cur_lun->lu_flag == 0){
			syslog(LOG_ERR, "the device open failed\n", cur_lun->sas_wwn);
			continue;
		}


		cur_lun++;
	}

	dm_free_descriptors(disk_dev_descrs);
	return (0);
}


void
found_disk(dm_descriptor_t *disk, int disk_index, dmg_lun_t *lun) {
	int fd;
	nvlist_t *attrs;
	char *drv_prod_id, *drv_opath, *drv_vend_id;
	uint32_t drv_type;
	dm_descriptor_t *drv_media_descrs, *media_scan;
	int error, ii, ret;
	dmg_lun_t dmt;

	un_locate_info_t un_info;
	uint64_t lun_slot;
	uint64_t en_id ;
	uint64_t sas_wwn;
	uint64_t en_instance;
	uint64_t lu_valid_flag = 0;

	attrs = dm_get_attributes(*disk, &error);
	if (error != 0 || attrs == NULL) {
		/* discard lun info, because info maybe is wrong */
		memset(lun, 0, sizeof(dmg_lun_t));
		syslog(LOG_ERR, "Error getting disk attributes\n");
		return;
	}


	/* Print specific attributes */
	nvlist_lookup_string(attrs, DM_VENDOR_ID, &drv_vend_id);
	nvlist_lookup_string(attrs, DM_PRODUCT_ID, &drv_prod_id);
	nvlist_lookup_uint32(attrs, DM_RPM, &drv_type);
	nvlist_lookup_string(attrs, DM_OPATH, &drv_opath);
	drv_opath [strlen(drv_opath)-2] = 0;
	lun->name = strdup(drv_opath);
	snprintf(drv_opath, strlen(drv_opath)+3, "%s%s", lun->name, "s2");

	if(strncmp(drv_opath, "/dev/zvol/rdsk/", 15) == 0)
		return;

	if (drv_vend_id == NULL || drv_prod_id == NULL) {
		syslog(LOG_ERR, "can't get vendor id or product id");
		return;
	}
	lun->model = strdup(drv_vend_id);
	lun->vendor = strdup(drv_prod_id);
	lun->rpm = drv_type;

	if (!disk_get_mpath_check()) { 
		/* to get disk logical unit id info */
#if 0
		ret = mpathGetLogicalUnit(drv_opath, &(lun->lu_num), &(lun->lu_info));
		if (ret != 0) {
			lun->lu_num = 0;
			lun->lu_info = NULL;
		}
#endif
	} else {
		lun->lu_num = 0;
		lun->lu_info = NULL;
	}

	/* to get enclosure id and slot id info O_RDWR | O_NDELAY */
	if ((fd = open(drv_opath, O_NONBLOCK | O_RDONLY)) >= 0) {
		if (ioctl(fd, DKIOCGETLUNEXT, &un_info) == 0) {
			en_id = un_info.en_id;
			lun_slot =  un_info.slot_id;
			sas_wwn = un_info.sas_wwn;
			en_instance = un_info.instance;
			lu_valid_flag = 1;
		}
		close(fd);
	} else {
		syslog(LOG_ERR, "open path:<%s> failed.", drv_opath);
		lun->lu_flag = lu_valid_flag;
		return;
	}

	lun->lu_flag = lu_valid_flag;
	lun->en_no = en_id;
	lun->lun_no = lun_slot;
	lun->sas_wwn = sas_wwn;

	media_scan = drv_media_descrs = dm_get_associated_descriptors(*disk,
			DM_MEDIA, &error);
	if (error != 0) {
		syslog(LOG_ERR, "get_slices failed %s\n", strerror(errno));
		exit(1);
	}
	while (*media_scan) {
		found_media(media_scan++, lun);
	}

release_resource:
	dm_free_descriptors(drv_media_descrs);
}

void
found_media(dm_descriptor_t *media, dmg_lun_t *lun) {
	nvlist_t *attrs;
	dm_descriptor_t *media_slice_descrs, *slice_scan;
	int error, ii = 0;
	uint64_t drv_size;
	uint32_t blk_size;
	uint32_t tgt_no;
	int lun_count = 0;

	attrs = dm_get_attributes(*media, &error);
	if (error != 0) {
		/* discard lun info, because info maybe is wrong */
		memset(lun, 0, sizeof(dmg_lun_t));
		syslog(LOG_ERR, "Error getting media attributes\n");
		return;
	}
	nvlist_lookup_uint64(attrs, DM_SIZE, &drv_size);
	nvlist_lookup_uint32(attrs, DM_BLOCKSIZE, &blk_size);
	nvlist_lookup_uint32(attrs, DM_TARGET, &tgt_no);
	lun->blocks = drv_size;
	lun->bytes_per_block = blk_size;
	lun->gsize = size_down(lun->blocks, lun->dim);
	drv_size *= blk_size;
	while (drv_size > 1024) {
		ii++;
		drv_size /= 1024;
	}
	;
	/* Get slices */
	slice_scan = media_slice_descrs =
		dm_get_associated_descriptors(*media, DM_SLICE, &error);

	if (error == 0) {
		/*
		 * Print slices.
		 */
		while (*slice_scan) {
			lun_count ++;
			found_slice(slice_scan++, lun);
		}

		lun->slice_count = lun_count;
		dm_free_descriptors(media_slice_descrs);

	}
	nvlist_free(attrs);

}

void found_slice(dm_descriptor_t *slice, dmg_lun_t *lun) {
	nvlist_t *attrs;
	nvlist_t *slice_stats;
	uint32_t flag;
	uint32_t slice_index;
	uint64_t slice_size, slice_start;
	char *used_by = NULL, *used_name = NULL, *mountpoint = NULL;
	int error, ii = 0;
	flag = 0;
	attrs = dm_get_attributes(*slice, &error);
	nvlist_lookup_uint32(attrs, DM_INDEX, &slice_index);
	if (slice_index == MAX_SLICES_PER_LUN -1)
		return;
	nvlist_lookup_uint32(attrs, DM_FLAG, &flag);
	nvlist_lookup_uint64(attrs, DM_START, &slice_start);
	nvlist_lookup_uint64(attrs, DM_SIZE, &slice_size);

	slice_stats = dm_get_stats(*slice, 0, &error);

	if (nvlist_lookup_string(slice_stats, DM_USED_BY, &used_by) == 0) {
		lun->slices[slice_index].used_by = strdup(used_by);
		if (strcmp(lun->slices[slice_index].used_by, "exported_zpool") != 0)
			lun->dev_sys =1;
	}
	if (nvlist_lookup_string(slice_stats, DM_USED_NAME, &mountpoint) == 0)
		lun->slices[slice_index].mount = strdup(mountpoint);


	if (error != 0) {
		syslog(LOG_ERR, "Error getting slice attributes %s\n", strerror(errno));
		return;
	}


	lun->slices[slice_index].index = slice_index;
	lun->slices[slice_index].assigned = 1;
	lun->slices[slice_index].blocks = slice_size;
	lun->slices[slice_index].start = slice_start;

	slice_size *= 512;
	while (slice_size > 1000) {
		ii++;
		slice_size /= 1000;
	}
	nvlist_free(attrs);
	nvlist_free(slice_stats);
}
int
dmg_free_luns(dmg_lun_t *luns, int tot_luns) {
	int ii, jj;


	for (ii = 0; ii < tot_luns; ii++) {
#if 0
		for (jj = 0; jj < MAX_SLICES_PER_LUN; jj++) {
			if (luns[ii].slices[jj].mount)
				free(luns[ii].slices[jj].mount);
		}
#endif
		free(luns[ii].name);
		free(luns[ii].vendor);
		free(luns[ii].model);
		free(luns[ii].status);
		if (luns[ii].lu_info != NULL)
			free(luns[ii].lu_info);
	}
	free(luns);
	return (0);
}

int
dmg_free_lunlink(dmg_lun_t *luns) {

	dmg_lun_t *cur_lun, *trans_lun;
	for (luns; luns; ){
		trans_lun = luns;
		luns = luns->lun_next;
		free(trans_lun);
	}
	return (0);
}


int
efi_error(int er) {
	switch (er) {
		case VT_EIO:
			printf("VT_EIO\n");
			break;

		case VT_ERROR:
			printf("VT_Error\n");
			break;

		case VT_EINVAL:
			printf("VT_Einval\n");
			break;
	}
	return (er);
}

int dmg_put_slices(char *disk, dmg_map_t map, boolean_t first_efi) {
	dk_gpt_t *table, *table1;
	dk_gpt_t *tmp_table;
	int fd, result, ii, slice_index;

	if ((fd = open(disk, O_NDELAY)) < 0) {
		syslog(LOG_ERR, "get slices failed, when openning device \'%s\", %s\n",
				disk, strerror(errno));
		return (EFI_FAILS);
	}
	if (!first_efi) {
		if ((slice_index = efi_alloc_and_read(fd, &table)) < 0) {
			syslog(LOG_ERR, "get slices failed, when reading map for \"%s\", %s\n",
					disk, strerror(errno));
			close(fd);
			return (efi_error(slice_index));
		}
	} else {
		table = malloc(sizeof(dk_gpt_t));
		syslog(LOG_ERR, "first initialize EFI");
		if (table == NULL) {
			syslog(LOG_ERR, "Allocation efi table fails");
			return (-1);
		}

		memset(table, 0, sizeof(dk_gpt_t));
	}
	if ((result = efi_alloc_and_init(fd, 9, &table1)) < 0) {
		syslog(LOG_ERR, "get slices failed at alloc_and_init for \"%s\", %s\n",
				disk, strerror(errno));
		close(fd);
		return (efi_error(result));
	}

	if (first_efi) {
		tmp_table = table1;


	}
	else {
		tmp_table = table;
	}

	for (ii = 0; ii < MAX_SLICES_PER_LUN; ii ++) {
		tmp_table->efi_parts[ii].p_start = map [ii].start;
		tmp_table->efi_parts[ii].p_size = map[ii].blocks;
		if (map[ii].assigned == 1) {
			tmp_table->efi_parts[ii].p_tag = V_USR;
		}
		else {
			tmp_table->efi_parts[ii].p_tag = V_UNASSIGNED;
		}
	}

	if (first_efi) {
		tmp_table->efi_parts[MAX_SLICES_PER_LUN - 1].p_start  = tmp_table->efi_last_u_lba
			- EFI_MIN_RESV_SIZE;
		tmp_table->efi_parts[MAX_SLICES_PER_LUN - 1].p_size =  EFI_MIN_RESV_SIZE;
		tmp_table->efi_parts[MAX_SLICES_PER_LUN -1].p_tag = V_RESERVED;
	}

	if ((result = efi_write(fd,  tmp_table)) < 0) {
		syslog(LOG_ERR, "write efi table fails");
		close(fd);
		return (efi_error(result));
	}
	efi_free(tmp_table);
	close(fd);
	return (0);
}

void init_disk_efi_flag(uint32_t disk_index)
{
	memset((void *)disk_efi_flag, 0, sizeof(uint32_t) * 256);

}
void set_disk_efi_flag(uint32_t disk_index)
{
	disk_efi_flag[disk_index] = 1;
}

int
dmg_get_slices(char *disk, dmg_map_t map, int lba_ordered) {

	int fd, slice_index, ii;
	int efi_flag;
	dk_gpt_t *table;


	efi_flag = 0;
	memset(map, 0, sizeof (dmg_map_t));
	table = NULL;

	if ((fd = open(disk, O_NDELAY)) < 0) {
		syslog(LOG_ERR, "get slices failed, when openning device %s, %s\n",
				disk, strerror(errno));
		return (EFI_FAILS);
	}
	if ((slice_index = efi_alloc_and_read(fd, &table)) < 0) {
		syslog(LOG_ERR, "This is one raw disk");
		return (EFI_FIRST);
	}
	for (ii = 0; ii < MAX_SLICES_PER_LUN; ii++) {
		if (table != NULL && table->efi_parts[ii].p_tag) {
			map [ii].assigned = 1;
			map [ii].start = table->efi_parts[ii].p_start;
			map [ii].blocks = table->efi_parts[ii].p_size;
		}
		map[ii].index = ii;
	}
	if (table != NULL)
		efi_free(table);
	close(fd);

	if (table != NULL && lba_ordered)
		/*
		 * Sort the map in ascending order
		 * -------------------------------------------------------------
		 */
		qsort((void *)map, MAX_SLICES_PER_LUN, sizeof (dmg_slice_t),
				dmg_slice_compare);
	return (EFI_SUCCESS);
}
int
dmg_slice_compare(const void *p1, const void *p2) {
	dmg_slice_t *i = (dmg_slice_t *)p1;
	dmg_slice_t *j = (dmg_slice_t *)p2;

	if (i->start > j->start)
		return (1);
	if (i->start < j->start)
		return (-1);
	return (0);
}

/*
 ***************************************************************************
 * linux disk list interface
 ***************************************************************************
 */
typedef struct slot_record {
	int	 sr_enclosure;
	int	 sr_slot;
	struct slot_record *sr_next;
	char sr_serial[ARGS_LEN];
	char sr_guid[ARGS_LEN];
} slot_record_t;

typedef struct slot_map {
	slot_record_t *sm_head;
	int sm_total;
} slot_map_t;

void slot_map_insert(slot_map_t *sm, slot_record_t *sr)
{
	if (sm->sm_head == NULL) {
		sm->sm_head = sr;
	} else {
		sr->sr_next = sm->sm_head;
		sm->sm_head = sr;
	}

	sm->sm_total++;
}

void slot_map_free(slot_map_t *sm)
{
	slot_record_t *temp = NULL;
	slot_record_t *search = NULL;

	if (sm->sm_head == NULL)
		return;

	for (search = sm->sm_head; search != NULL;) {
		temp = search->sr_next;
		free(search);
		search = temp;
	}

	return;
}

void disk_get_slot_map(slot_map_t *sm)
{
	FILE *fd = -1;
	FILE *pfd = -1;
	FILE *vfd = -1;
	int len = -1;
	int slot = -1;
	int enclosure = -1;
	int is_ubuntu = -1;
	char value_sn[ARGS_LEN] = {0};
	char value_guid[ARGS_LEN] = {0};
	char args[ARGS_LEN] = {0};
	char version[ARGS_LEN] = {0};
	char tmp[CMD_TMP_LEN] = {0};

	pfd = popen("which gcc 2>/dev/null", "r");
	if (pfd != NULL) {
		if (fgets(tmp, sizeof(tmp), pfd) != NULL) {
			sscanf(tmp,"%s",args);
			sprintf(version, "%s --version", args);
			vfd = popen(version, "r");
			if (vfd != NULL) {
				bzero(tmp, sizeof(tmp));
				if (fgets(tmp, sizeof(tmp), vfd) != NULL) {
					if (strcasestr(tmp, "ubuntu") != NULL)
						is_ubuntu = 1;
				}
			}
		}
	}

	pclose(vfd);
	pclose(pfd);
	bzero(tmp, sizeof(tmp));
	bzero(args, sizeof(args));

	fd = (is_ubuntu == 1 ? popen(SAS3IRCU, "r") : popen(SAS2IRCU, "r"));
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
		} else if (strcasecmp(args, "GUID") == 0) {
			sscanf(tmp, "%*[^:]:%s", value_guid);
			if (value_sn[0] != '\n') {
				slot_record_t *sr = (slot_record_t*)malloc(sizeof(slot_record_t));
				sr->sr_enclosure = enclosure;
				sr->sr_slot = slot;
				sr->sr_next = NULL;
				memcpy(sr->sr_serial, value_sn, strlen(value_sn));
				memcpy(sr->sr_guid, value_guid, strlen(value_guid));
				slot_map_insert(sm, sr);
				slot = 0;
				enclosure = 0;
				memset(value_sn, '\n', sizeof(value_sn));
				memset(value_guid, '\n', sizeof(value_guid));
			}
		}
	}
}

void slot_map_find_value(slot_map_t *sm, disk_info_t *di)
{
	slot_record_t *search = NULL;

	for (search = sm->sm_head; search != NULL; search = search->sr_next) {
		if (strcasestr(di->dk_serial, search->sr_serial) != NULL ||
				strcasestr(search->sr_serial, di->dk_serial) != NULL) {
			di->dk_enclosure = search->sr_enclosure;
			di->dk_slot = search->sr_slot;
			break;
		}
	}

	return;
}

void slot_map_find_value_guid(slot_map_t *sm, disk_info_t *di)
{
	slot_record_t *search = NULL;

	for (search = sm->sm_head; search != NULL; search = search->sr_next) {
		if (strcasestr(di->dk_serial, search->sr_guid) != NULL ||
			strcasestr(search->sr_guid, di->dk_serial) != NULL) {
			di->dk_enclosure = search->sr_enclosure;
			di->dk_slot = search->sr_slot;
			break;
		}
	}

	return;
}

void disk_table_insert(disk_table_t *dt, disk_info_t *di)
{
	int slot = di->dk_slot;
	int enclosure = di->dk_enclosure;
	disk_info_t *search = dt->next;

	if (search == NULL) {
		dt->next = di;
		di->prev = NULL;
		di->next = NULL;
		dt->total++;
		return;
	}

	while (search->next != NULL && search->dk_enclosure < enclosure)
		search = search->next;

	if (slot == 0 && enclosure == 0) {
		dt->next->prev = di;
		di->next = dt->next;
		dt->next = di;
		di->prev = NULL;
		dt->total++;
		return;
	}

	while (search->next != NULL && search->dk_enclosure == enclosure
			&& search->dk_slot < slot)
		search = search->next;

	if (search->next != NULL || search->dk_slot > slot
			|| (dt->total == 1 && search->dk_enclosure > enclosure)) {
		di->prev = search->prev;
		di->next = search;
		if (search->prev == NULL) {
			dt->next = di;
		} else {
			search->prev->next = di;
		}
		search->prev = di;
	} else {
		search->next = di;
		di->prev = search;
		di->next = NULL;
	}

	dt->total++;
	return;
}

int disk_get_info(disk_table_t *dt)
{
	FILE *fd = -1;
	int i = 0;
	int sec = 0;
	int len = 0;
	slot_map_t sm;
	char *ptr = NULL;
	disk_info_t *di_cur = NULL;
	disk_info_t *di_ptr = NULL;
	char buf_scsi[ARGS_LEN] = {0};
	char buf_dev[ARGS_LEN] = {0};
	char buf_other[ARGS_LEN] = {0};
	char sysdisk[ARGS_LEN] = {0};
	char tmp[CMD_TMP_LEN] = {0};

	fd = popen(DISK_BY_ID, "r");
	if (fd == NULL)
		return (-1);

	bzero(&sm, sizeof(slot_map_t));
	disk_get_slot_map(&sm);

	while (fgets(tmp, sizeof(tmp), fd)) {
		sscanf(tmp, "%*[^:]:%d %s %s %s",&sec, buf_scsi, buf_other, buf_dev);
		len = strlen(buf_dev);
		if (buf_dev[len - 1] >= '0' && buf_dev[len - 1] <= '9') {
			continue;
		}
		
		if (strncasecmp(buf_scsi, "scsi", 4) == 0 && strlen(buf_scsi) == 22) {
			di_cur = (disk_info_t*)malloc(sizeof(disk_info_t));
			bzero(di_cur, sizeof(disk_info_t));
			snprintf(di_cur->dk_scsid, strlen(buf_scsi) + strlen(DEFAULT_SCSI) + 1, "%s%s",
					DEFAULT_SCSI, buf_scsi);

			if ((ptr = strstr(buf_dev, "sd")) != NULL) {
				snprintf(di_cur->dk_name, strlen(ptr) + strlen(DEFAULT_PATH) + 1,"%s%s",
						DEFAULT_PATH, ptr);	
			}

			disk_get_vendor(di_cur);
			disk_get_serial(di_cur);
			disk_get_status(di_cur);
			disk_get_gsize(di_cur);
			slot_map_find_value(&sm, di_cur);
			disk_table_insert(dt, di_cur);
		}
	}

	(void) disk_get_system(sysdisk);	

	for (di_cur = dt->next; di_cur != NULL; di_cur = di_cur->next) {
		if (strncmp(di_cur->dk_name, sysdisk, 8) == 0) {
			di_cur->dk_is_sys = 1;
			break;
		}
	}

	slot_map_free(&sm);
	(void) fclose(fd);
	return (0);
}

void disk_get_system(char *disk_name)
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
				memcpy(disk_name, dev, 8);
				break;
			}
		} else {
			continue;
		}
	}

	(void) fclose(fp);
}

int disk_get_gsize(disk_info_t *di)
{
	FILE *fd = -1;
	char *ptr = NULL;
	char args[ARGS_LEN] = {0};
	char major[ARGS_LEN] = {0};
	char rm[ARGS_LEN] = {0};
	char gsize[ARGS_LEN] = {0};
	char tmp[CMD_TMP_LEN] = {0};

	fd = popen(LSBLK, "r");
	if (fd == NULL)
		return (0);

	while (fgets(tmp, sizeof(tmp), fd)) {
		sscanf(tmp, "%s%s%s%s", args,major,rm,gsize);
		ptr = strstr(di->dk_name, "sd");
		if (ptr != NULL && strcasecmp(args, ptr) == 0) {
			memcpy(di->dk_gsize, gsize, strlen(gsize)); 
			break;
		}
	}
}

int disk_get_slotid(disk_info_t *di)
{
	FILE *fd = -1;
	FILE *pfd = -1;
	FILE *vfd = -1;
	int len = -1;
	int slot = -1;
	int enclosure = -1;
	int is_ubuntu = -1;
	char value_sn[ARGS_LEN] = {0};
	char args[ARGS_LEN] = {0};
	char version[ARGS_LEN] = {0};
	char tmp[CMD_TMP_LEN] = {0};

	pfd = popen("which gcc 2>/dev/null", "r");
	if (pfd != NULL) {
		if (fgets(tmp, sizeof(tmp), pfd) != NULL) {
			sscanf(tmp,"%s",args);
			sprintf(version, "%s --version", args);
			vfd = popen(version, "r");
			if (vfd != NULL) {
				bzero(tmp, sizeof(tmp));
				if (fgets(tmp, sizeof(tmp), vfd) != NULL) {
					if (strcasestr(tmp, "ubuntu") != NULL)
						is_ubuntu = 1;
				}
			}
		}
	}
	pclose(vfd);
	pclose(pfd);

	bzero(tmp, sizeof(tmp));
	bzero(args, sizeof(args));

	fd = (is_ubuntu == 1 ? popen(SAS3IRCU, "r") : popen(SAS2IRCU, "r"));
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
			if (di->dk_serial != NULL && (strcasestr(di->dk_serial, value_sn) != NULL
				|| strcasestr(value_sn, di->dk_serial) != NULL)) {
				di->dk_enclosure = enclosure;
				di->dk_slot = slot;
				pclose(fd);
				return (0);
			} else {
				slot = -1;
				enclosure = -1;
			}
		}
	}

	pclose(fd);
}

void disk_get_status(disk_info_t *di)
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
}

int disk_get_vendor(disk_info_t *di)
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

int disk_get_serial(disk_info_t *di)
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

