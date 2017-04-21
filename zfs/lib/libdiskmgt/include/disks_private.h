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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DISKS_PRIVATE_H
#define	_DISKS_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <libdevinfo.h>
#include <devid.h>
#include <sys/dkio.h>
#include <sys/types.h>
#include <sys/dktp/fdisk.h>
#include <sys/rrwlock.h>
#include <libdiskmgt.h>

#define	FDISK_ERRNO		200
#define	FDISK_ENOLOGDRIVE	(FDISK_ERRNO + 7)
#define	FDISK_EBADLOGDRIVE	(FDISK_ERRNO + 8)
#define	FDISK_SUCCESS 0
#define FDISK_READ_DISK 0x00000001

#define DDI_DEV_T_ANY       ((dev_t)-2)
#define	DI_WALK_CONTINUE	0
#define	DDI_NT_USB_ATTACHMENT_POINT	"ddi_ctl:attachment_point:usb"
#define	DDI_NT_BLOCK	"ddi_block"

#define	DDI_NT_BLOCK_CHAN	"ddi_block:channel"
#define	DDI_NT_BLOCK_WWN	"ddi_block:wwn"
#define	DDI_NT_CD	"ddi_block:cdrom"	/* rom drives (cd-rom) */
#define	DDI_NT_CD_CHAN	"ddi_block:cdrom:channel" /* rom drives (scsi type) */
#define	DDI_NT_FD	"ddi_block:diskette"	/* floppy disks */

#define	DDI_NT_NEXUS	"ddi_ctl:devctl"	/* nexus drivers */

/*
 * Main structure used to record changes to the partitions made.
 * Changes are not written to disk everytime, but maintained in this structure.
 * This information is used when the user chooses to commit the changes.
 * A linked list of this structure represents the ondisk partitions.
 */
typedef struct logical_drive {

	/* structure holding the EBR data */
	struct ipart parts[2];

	/*
	 * Absolute beginning sector of the extended partition, and hence an
	 * indicator of where the EBR for this logical drive would go on disk.
	 * NOTE : In case the first logical drive in this extended partition is
	 * out of (disk) order, this indicates the beginning of the logical
	 * drive. The EBR will anyway be at the first sector of the extended
	 * partition, for the first logical drive.
	 */
	uint32_t abs_secnum;

	/*
	 * Offset of the logical drive from the beginning of its extended
	 * partition
	 */
	uint32_t logdrive_offset;

	/* Size of the logical drive in sectors */
	uint32_t numsect;

	/* Beginning and ending cylinders of the extended partition */
	uint32_t begcyl, endcyl;

	/*
	 * Flag to indicate if this record is to be sync'ed to disk.
	 * It takes two values : FDISK_MAJOR_WRITE and FDISK_MINOR_WRITE
	 * If it is a minor write, there is no need to update the information
	 * in the kernel structures. Example of a minor write is correction of
	 * a corrupt boot signature.
	 */
	int modified;

	/*
	 * This pointer points to the next extended partition in the order
	 * found on disk.
	 */
	struct logical_drive *next;

	/*
	 * This pointer points to the next extended partition in a sorted list
	 * sorted in the ascending order of their beginning cylinders.
	 */
	struct logical_drive *sorted_next;

} logical_drive_t;

typedef struct fdisk_disk_geom {
	ushort_t phys_cyl;
	ushort_t phys_sec;
	ushort_t phys_heads;
	ushort_t alt_cyl;
	ushort_t virt_cyl;
	ushort_t virt_sec;
	ushort_t virt_heads;
	ushort_t sectsize;
} fdisk_disk_geom_t;

typedef struct ext_part
{
	/* Structure holding geometry information about the device */
	fdisk_disk_geom_t disk_geom;

	struct ipart *mtable;

	char device_name[PATH_MAX];

	int dev_fd;

	int op_flag;

	/*
	 * Head of the in memory structure (singly linked list) of extended
	 * partition information.
	 */
	logical_drive_t *ld_head;
	logical_drive_t *sorted_ld_head;

	/* Beginning cylinder of the extended partition */
	uint32_t ext_beg_cyl;

	/* Ending cylinder of the extended partition */
	uint32_t ext_end_cyl;

	/* Beginning sector of the extended partition */
	uint32_t ext_beg_sec;

	/* Ending sector of the extended partition */
	uint32_t ext_end_sec;

	/* Count of the number of logical drives in the extended partition */
	int logical_drive_count;

	/*
	 * Flag to keep track of the update to be made to the Extended Boot
	 * Record (EBR) when all logical drives are deleted. The EBR is filled
	 * with zeroes in such a case.
	 */
	int first_ebr_is_null;

	/*
	 * Flag to indicate corrupt logical drives. Can happen when a partition
	 * manager creates an extended partition and does not null the first EBR
	 * or when important ondisk structures are overwritten by a bad program
	 */
	int corrupt_logical_drives;

	/*
	 * The boot block signature 0xAA55 might not be found on some of the
	 * EBRs. ( Even though the rest of the data might be good )
	 * The following array is used to store the list of such logical drive
	 * numbers.
	 */
	uchar_t invalid_bb_sig[MAX_EXT_PARTS];

	/*
	 * Can add  a "next" pointer here in case support for multiple
	 * extended partitions becomes the standard someday.
	 *
	 * struct ext_part *next;
	 */
} ext_part_t;


#define	DM_DEBUG	"DM_LIBDISKMGT_DEBUG"
extern int dm_debug;

#define	NVATTRS	NV_UNIQUE_NAME | NV_UNIQUE_NAME_TYPE
#define	NVATTRS_STAT	0x0

typedef struct slice_info {
	char		*devpath;
	int		slice_num;
	struct slice_info *next;
} slice_t;

typedef struct alias_info {
	char		*kstat_name;
	char		*alias;
	slice_t		*devpaths;
	slice_t		*orig_paths;
	char		*wwn;
	int		cluster;
	int		lun;
	int		target;
	struct alias_info *next;
} alias_t;

typedef struct path {
	char			*name;
	char			*ctype;
	int			*states;
	char			**wwns;
	struct disk		**disks;
	struct controller_info	*controller;
	struct path		*next;
} path_t;

typedef struct bus_info {
	char			*name;
	char			*kstat_name;
	char			*btype;
	char			*pname;
	int			freq;
	struct controller_info	**controllers;
	struct bus_info		*next;
} bus_t;

typedef struct controller_info {
	char		*name;
	char		*kstat_name;
	char		*ctype;
	int		freq;
	struct disk	**disks;
	struct path	**paths;
	struct bus_info	*bus;
	struct controller_info *next;
	int		multiplex;
	int		scsi_options;
} controller_t;

typedef struct disk {
	char		*device_id;	/* string encoded device id */
	ddi_devid_t	devid;		/* decoded device id */
	char		*kernel_name;	/* handles drives w/ no devlinks */
	char		*product_id;
	char		*vendor_id;
	controller_t	**controllers;
	path_t		**paths;
	alias_t		*aliases;
	struct disk	*next;
	int		drv_type;
	int		removable;
	int		sync_speed;
	int		rpm;
	int		wide;
	int		cd_rom;
} disk_t;

typedef struct descriptor {
	union {
	    void		*generic;
	    disk_t		*disk;
	    controller_t	*controller;
	    bus_t		*bus;
	    path_t		*path;
	} p;
	char			*name;
	char			*secondary_name;
	struct descriptor	*next;
	struct descriptor	*prev;
	dm_desc_type_t		type;
	int			refcnt;
} descriptor_t;

struct search_args {
	disk_t			*disk_listp;
	controller_t		*controller_listp;
	bus_t			*bus_listp;
	di_devlink_handle_t	handle;
	di_prom_handle_t	ph;
	di_node_t		node;
	di_minor_t		minor;
	int			dev_walk_status;
};

typedef enum {
    DM_EV_DISK_ADD = 0,
    DM_EV_DISK_DELETE
} dm_event_type_t;

/* private internal functions */
descriptor_t	**alias_get_descriptors(int filter[], int *errp);
descriptor_t	**alias_get_assoc_descriptors(descriptor_t *desc,
		    dm_desc_type_t type, int *errp);
descriptor_t	*alias_get_descriptor_by_name(char *name, int *errp);
char		*alias_get_name(descriptor_t *desc);
nvlist_t	*alias_get_attributes(descriptor_t *desc, int *errp);
nvlist_t	*alias_get_stats(descriptor_t *desc, int stat_type, int *errp);
int		alias_make_descriptors();

descriptor_t	**bus_get_descriptors(int filter[], int *errp);
descriptor_t	**bus_get_assoc_descriptors(descriptor_t *desc,
		    dm_desc_type_t type, int *errp);
descriptor_t	*bus_get_descriptor_by_name(char *name, int *errp);
char		*bus_get_name(descriptor_t *desc);
nvlist_t	*bus_get_attributes(descriptor_t *desc, int *errp);
nvlist_t	*bus_get_stats(descriptor_t *desc, int stat_type,
		    int *errp);
int		bus_make_descriptors();

descriptor_t	**controller_get_descriptors(int filter[], int *errp);
descriptor_t	**controller_get_assoc_descriptors(descriptor_t *desc,
		    dm_desc_type_t type, int *errp);
descriptor_t	*controller_get_descriptor_by_name(char *name, int *errp);
char		*controller_get_name(descriptor_t *desc);
nvlist_t	*controller_get_attributes(descriptor_t *desc, int *errp);
nvlist_t	*controller_get_stats(descriptor_t *desc, int stat_type,
		    int *errp);
int		controller_make_descriptors();

descriptor_t	**drive_get_descriptors(int filter[], int *errp);
descriptor_t	**drive_get_assoc_descriptors(descriptor_t *desc,
		    dm_desc_type_t type, int *errp);
descriptor_t	**drive_get_assocs(descriptor_t *desc, int *errp);
descriptor_t	*drive_get_descriptor_by_name(char *name, int *errp);
char		*drive_get_name(descriptor_t *desc);
nvlist_t	*drive_get_attributes(descriptor_t *desc, int *errp);
nvlist_t	*drive_get_stats(descriptor_t *desc, int stat_type, int *errp);
int		drive_make_descriptors();
int		drive_open_disk(disk_t *diskp, char *opath, int len);

descriptor_t	**media_get_descriptors(int filter[], int *errp);
descriptor_t	**media_get_assoc_descriptors(descriptor_t *desc,
		    dm_desc_type_t type, int *errp);
descriptor_t	**media_get_assocs(descriptor_t *desc, int *errp);
descriptor_t	*media_get_descriptor_by_name(char *name, int *errp);
char		*media_get_name(descriptor_t *desc);
nvlist_t	*media_get_attributes(descriptor_t *desc, int *errp);
nvlist_t	*media_get_stats(descriptor_t *desc, int stat_type, int *errp);
int		media_make_descriptors();
int		media_read_info(int fd, struct dk_minfo *minfo);
int		media_read_name(disk_t *dp, char *mname, int size);

descriptor_t	**path_get_descriptors(int filter[], int *errp);
descriptor_t	**path_get_assoc_descriptors(descriptor_t *desc,
		    dm_desc_type_t type, int *errp);
descriptor_t	*path_get_descriptor_by_name(char *name, int *errp);
char		*path_get_name(descriptor_t *desc);
nvlist_t	*path_get_attributes(descriptor_t *desc, int *errp);
nvlist_t	*path_get_stats(descriptor_t *desc, int stat_type, int *errp);
int		path_make_descriptors();

descriptor_t	**slice_get_descriptors(int filter[], int *errp);
descriptor_t	**slice_get_assoc_descriptors(descriptor_t *desc,
		    dm_desc_type_t type, int *errp);
descriptor_t	**slice_get_assocs(descriptor_t *desc, int *errp);
descriptor_t	*slice_get_descriptor_by_name(char *name, int *errp);
char		*slice_get_name(descriptor_t *desc);
nvlist_t	*slice_get_attributes(descriptor_t *desc, int *errp);
nvlist_t	*slice_get_stats(descriptor_t *desc, int stat_type, int *errp);
int		slice_make_descriptors();
void		slice_rdsk2dsk(char *rdsk, char *dsk, int size);

/* cache.c */
void		cache_free_alias(alias_t *aliasp);
void		cache_free_bus(bus_t *bp);
void		cache_free_controller(controller_t *cp);
void		cache_free_descriptor(descriptor_t *desc);
void		cache_free_descriptors(descriptor_t **desc_list);
void		cache_free_disk(disk_t *dp);
void		cache_free_path(path_t *pp);
bus_t		*cache_get_buslist();
controller_t	*cache_get_controllerlist();
descriptor_t	*cache_get_desc(int type, void *gp, char *name,
		    char *secondary_name, int *errp);
descriptor_t	**cache_get_descriptors(int type, int *errp);
disk_t		*cache_get_disklist();
int		cache_is_valid_desc(descriptor_t *d);
void		cache_load_desc(int type, void *gp, char *name,
		    char *secondary_name, int *errp);
void		cache_rlock();
void		cache_unlock();
void		cache_update(dm_event_type_t ev_type, char *devname);
void		cache_wlock();

#if 0
/* findevs.c */
void		findevs(struct search_args *args);

/* events.c */
int		events_start_event_watcher();
void		events_new_event(char *name, int dtype, char *etype);
void		events_new_slice_event(char *dev, char *type);

/* entry.c */
void		libdiskmgt_add_str(nvlist_t *attrs, char *name, char *val,
		    int *errp);
descriptor_t	**libdiskmgt_empty_desc_array(int *errp);
void		libdiskmgt_init_debug();
int		libdiskmgt_str_eq(char *nm1, char *nm2);

/* in-use detectors */
extern	int		inuse_mnt(char *slice, nvlist_t *attrs, int *errp);
extern  int		inuse_svm(char *slice, nvlist_t *attrs, int *errp);
extern	int		inuse_lu(char *slice, nvlist_t *attrs, int *errp);
extern	int		inuse_active_zpool(char *slice, nvlist_t *attrs, int *errp);
extern	int		inuse_exported_zpool(char *slice, nvlist_t *attrs, int *errp);
extern	int		inuse_dump(char *slice, nvlist_t *attrs, int *errp);
extern	int		inuse_vxvm(char *slice, nvlist_t *attrs, int *errp);
extern	int		inuse_fs(char *slice, nvlist_t *attrs, int *errp);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _DISKS_PRIVATE_H */
