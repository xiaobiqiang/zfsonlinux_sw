/*
 * Copyright 2010 Ceresdata Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef	_DISKLIST_H
#define	_DISKLIST_H

#include <stdint.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	EFI_MIN_RESV_SIZE	(16 * 1024)
#define	EFI_SUCCESS	0x00000000
#define	EFI_FAILS	0x00000001
#define	EFI_FIRST	0x00000002


#define	EFI_FIRST_START_BLOCK	35

#define	MAX_SLICES_PER_LUN 9

/*
 * linux disk list info
 */
#define CMD_TMP_LEN		1024
#define ARGS_LEN		100
#define PARAM_LEN		10
#define	INQ_REPLY_LEN	96
#define	INQ_CMD_LEN		6
#define POOLLEN			64
#define SLOT			"Slot"
#define ENCLOSURE		"Enclosure"
#define SERIALNO		"Serial"
#define SAS_ADDRESS		"Addr"
#define INVALID_STR   "FFFFFFFF"

#define DEFAULT_PATH	"/dev/"
#define DEFAULT_SCSI	"/dev/disk/by-id/"
#define SAS2IRCU		"sas2ircu 0 display 2>/dev/null"
#define SAS3IRCU		"sas3ircu 0 display 2>/dev/null"
#define DISK_BY_ID		"ls -l /dev/disk/by-id 2>/dev/null"
#define LSBLK			"lsblk 2>/dev/null"

typedef struct disk_info {
	int		dk_major;
	int		dk_minor;
	int		dk_enclosure;
	int		dk_slot;
	int		dk_is_sys;
	int		dk_rpm ;
	long	dk_blocks;
	char	dk_vendor[PARAM_LEN];
	char	dk_busy[PARAM_LEN];
	char	dk_name[ARGS_LEN];
	char	dk_scsid[ARGS_LEN];
	char	dk_gsize[PARAM_LEN];
	char	dk_pool[ POOLLEN ] ;
	char	*dk_role ;
	char	dk_serial[ARGS_LEN];
	struct disk_info *prev;
	struct disk_info *next;
} disk_info_t;

typedef struct disk_table {
	int	total;
	disk_info_t *next;
} disk_table_t;

extern int disk_scan_lun(void);
extern int disk_get_info(disk_table_t *di);
extern void disk_get_system(char* name);
extern int disk_get_slotid(disk_info_t *di);
extern void disk_get_status(disk_info_t *di);
extern int disk_get_vendor(disk_info_t *di);
extern int disk_get_serial(disk_info_t *di);
extern int disk_get_gsize(disk_info_t *di);

/*
 * Disk Functions
 */
typedef struct dmg_slice {
	uint64_t start;
	uint64_t blocks;
	int assigned;
	char *mount;
	char *used_by;
	int index;
} dmg_slice_t;

typedef  dmg_slice_t dmg_map_t [MAX_SLICES_PER_LUN];

/* disk logical unit info */
typedef struct dmg_lu {
	char portID[256];
	char osDeviceFile[256];
} dmg_lu_t;

typedef struct dmg_lun {
	char	*name;
	char		*vendor;
	char		*model;
	char		*status;
	uint32_t		rpm;
	uint64_t		en_no;
	uint64_t		lun_no;
	uint64_t 		sas_wwn;
	uint64_t	    lu_flag;
	int		dev_sys;
	int		slice_count;
	uint64_t	blocks;
	uint32_t	bytes_per_block;
	double	gsize;
	char dim[24];
	dmg_map_t	slices;
	int 		lu_num;
	dmg_lu_t	*lu_info;
	struct dmg_lun *lun_next;
} dmg_lun_t;


/*
 * Allocate and get an array of dmg_lun_t structures, each of which represents
 * a fixed disk/lun that is attached to the platform.  The array does not
 * include the system drive.
 * tot_disks is the number of dmg_luns_t elements in the array.
 */
extern int dmg_get_luns(dmg_lun_t **, int *);

extern int dmg_get_disk(dmg_lun_t **, int *);


/*
 * Frees up resource allocated by dmg_get_luns
 */
extern int dmg_free_luns(dmg_lun_t *, int);

extern int dmg_free_lunlink(dmg_lun_t *);

extern int get_device_wwn(dmg_lun_t *, char *);

extern int set_dev_info_to_sd(dmg_lun_t *, int);
extern int
disk_get_enid_slotid(const char *drv_opath, int *en_id, int *slot_id);

/*
 * Fills in the array of dmg_slice_t structures.  If lba_ordered is set to 0,
 * the returned array will be sorted by slice index (i.e., s0, s1,... sn)
 * If set to non-zero, the array will be sorted in ascending order by disk LBA.
 * The array represents the partition map of the given dmg_lun_t
 * The function takes a pointer to the array dmg_map_t
 * A request to obtain a map of the system disk will fail witn EPERM
 *
 */
extern int dmg_get_slices(char *disk, dmg_map_t map, int lba_ordered);




/*
 * Create a slice map on the given lun
 * Array of slices must be ordered by index number.  That is, the first slice
 * will be recorded as s0, the second one as s1, and so on,  regardless of its
 * starting and ending block addresses within the disk.
 * If no partition map is currently present on the given lun, the function will:
 *		- Create disk partition (fdisk) given a disk logical name.
 *		- Label a disk.
 *		- Create a default partition map
 */
extern int dmg_put_slices(char *disk, dmg_map_t map, boolean_t first_efi);


/*
 * This function serves as input to qsort for sorting slices in ascending order
 * *p1 and *p2 must point to valid dmg_slice_t structures
 * Compare p1 and p2 starting LBA and return:
 *	 1 if p1->start > p2->start
 *	-1 if p1->start < p2->start
 *	 0 if p1->start == p2->start
 */
extern int dmg_slice_compare(const void *p1, const void *p2);

/*
 * This function is to get logical unit info for disks.
 */
int
mpathGetLogicalUnit(char *path, int *plu_num, dmg_lu_t **plu_info);


#ifdef	__cplusplus
}
#endif

#endif	/* _DISKLIST_H */
