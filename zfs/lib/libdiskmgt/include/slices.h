/*
 * Copyright (c) 2010 by Ceresdata Inc.
 * All rights reserved.
 */
#ifndef _SLICES_H
#define	_SLICES_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	SUBC_CREATE		"Create"
#define	SUBC_LIST		"List"
#define SUBC_LIST_ALL	"List-all"
#define	SUBC_LIST_OLD		"List-old"
#define	SUBC_LIST_DISKS		"List-disks"
#define	SUBC_LIST_SLICES	"List-slices"
#define	SUBC_ATTACH		"Attach"
#define	SUBC_GROW		"Grow"
#define	SUBC_DELETE		"Delete"
#define	SUBC_GAPS		"Gaps"
#define	SUBC_LED		"Led"
#define	SUBC_MARK		"Mark"
#define	SUBC_RESTORE		"restore"

#define	SUBC_LIST_GAPS		"List-gaps"
#define	SUBC_INIT		"Initialize"
#define	SUBC_MOUNTALL		"Mountall"
#define	SUBC_UMOUNTALL		"UMountall"

/*
 * Error messages and status codes (these should be internationalized)
 */
#define	ERROR_NAME_AND_INDEX \
"%s: error: Expected disk name (-d name) OR disk index (-i index), NOT both\n"
#define	ERROR_SIZE_AND_INDEX \
"%s: error: Expected slice size (-s size) OR gap index (-g index), NOT both\n"
#define	ERROR_NO_DISK \
"%s: error: Expected disk name (-d name) or disk index (-i index)\n"
#define	ERROR_NO_SLICES \
"%s: error: All slice definitions for this LUN have been used up\n"
#define	ERROR_NO_SPACE "%s: error: Insufficient disk space\n"
#define	ERROR_NO_MEMORY "%s: error: Insufficient memory\n"
#define	ERROR_SUBCOMMAND "Illegal command or option: %s\n"
#define	ERROR_NO_PARMS "%s: error Insufficient parameters given\n"
#define	ERROR_INTERNAL_ERROR "%s: error 125: Internal error\n"
#define	ERROR_FS_NOENT "%s error: File system \"%s\" does not exist\n"
#define	ERROR_FS_EXISTS "%s error: Duplicate file system name\n"
#define	ERROR_FS_BAD_NAME "%s error: Bad file system name\n"
#define	ERROR_FS_INUSE "%s error: File system is in use\n"


#define	EXIT_TOO_MANY_OPERANDS	-1
#define	EXIT_NO_DISK		-2
#define	EXIT_NO_SLICES		-3
#define	EXIT_NO_SPACE		-4
#define	EXIT_NO_MEMORY		-5
#define	EXIT_SUBCOMMAND		-6
#define	EXIT_NO_PARMS		-7
#define	EXIT_FS_EXISTS		-8
#define	EXIT_FS_BAD_NAME	-9
#define	EXIT_FS_NOENT		-10
#define	EXIT_FS_INUSE		-11
#define	EXIT_INTERNAL_ERROR	-128

#define	MAX_SLICE_NAME		128
#define	MAX_SLICE_STATE		16
#define	MAX_EQ_TYPE		3
#define	MAX_FS_NAME		32
#define	MAX_ADDL_PARAMS		128


typedef struct {
	char disk_name [MAX_SLICE_NAME];	/* /dev/rdsk/cxtxdx */
	char slice_name [MAX_SLICE_NAME];	/* /dev/rdsk/cxtxdxsx */
	char led_operation [MAX_SLICE_NAME];
	int disk_index;				/* 0 - 65536 */
	int slice_index;			/* 0 - 7 */
	int gap_index;				/* 0 - 6 */

	/*
	 * 4,503,599,627,264,000 mbytes (2^63 blocks * 512/1024^2)
	 */
	uint64_t mbytes;
} slice_req_t;

/*
 *  Forward declarations
 */

extern int create_slice(slice_req_t *);
void get_slice_info(int slice_fd, uint64_t *startp, uint64_t *nblocksp);
extern int delete_slice(slice_req_t *);
extern double size_down(uint64_t, char *);
extern int get_disk_name(slice_req_t *, char *subcommand);
extern int list_gaps(slice_req_t *);
int set_dev_info_to_sd(dmg_lun_t *luns, int tot_luns);



#ifdef	__cplusplus
}
#endif

#endif	/* _SLICES_H */
