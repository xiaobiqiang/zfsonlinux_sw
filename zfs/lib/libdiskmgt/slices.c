#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>
#include <disklist.h>
#include <slices.h>


#define	GAPS_HEADER "Gaps in"

int
list_gaps(slice_req_t *req) {
	int ii, status = 0;
	int jj = 0;
	dmg_map_t pmap, sorted_map;
	uint64_t gp_sz, gp_start;
	char dim;

	if (status = get_disk_name(req, SUBC_GAPS))
		return (status);
	printf("\n\n%s %s:\n", GAPS_HEADER, req->disk_name);
	memset(pmap, 0, sizeof (pmap));

	/*
	 * Get slice definitions and determine if there is a slot available
	 * ------------------------------------------------------------------
	 */
	if (status = dmg_get_slices(req->disk_name, pmap, 0)) {
		printf(ERROR_INTERNAL_ERROR, SUBC_CREATE);
		return (status);
	}
	memcpy(sorted_map, pmap, sizeof (dmg_map_t));

	/*
	 * Sort the map in ascending order to find gaps
	 * --------------------------------------------------------------------
	 */
	qsort((void *)sorted_map, MAX_SLICES_PER_LUN, sizeof (dmg_slice_t),
							dmg_slice_compare);

	/*
	 * Find the first defined slice.
	 * -----------------------------------------------------------------
	 */
	for (ii = 0; ii < MAX_SLICES_PER_LUN-1; ii++) {
		if (sorted_map[ii].start)
			break;
	}
	gp_start = 34;

	do {
		if (gp_sz = sorted_map[ii].start - gp_start) {
			printf("   g%d %ll12d, %.2lf%c \n", jj, gp_start,
			size_down(gp_sz, &dim), dim);
			jj++;
		}
		gp_start = sorted_map[ii].start + sorted_map[ii].blocks;
		ii++;
	} while (ii < MAX_SLICES_PER_LUN-1);
	if (gp_sz = sorted_map[ii].start - gp_start) {
		printf("   g%d %ll12d, %.2lf%c \n\n", jj, gp_start,
		size_down(gp_sz, &dim), dim);
	}
	return (0);
}

/*
 *  Erase a disk's slice
 */
int
delete_slice(slice_req_t *req) {
	dmg_map_t map;
	int status;
	if (status = get_disk_name(req, SUBC_DELETE))
		return (status);
	if (status = dmg_get_slices(req->disk_name, map, 0)) {
		printf(ERROR_INTERNAL_ERROR, SUBC_DELETE);
		return (status);
	}
	map[req->slice_index].blocks = 0;
	if (status = dmg_put_slices(req->disk_name, map, B_FALSE)) {
		printf(ERROR_INTERNAL_ERROR, SUBC_DELETE);
		return (status);
	}
	return (0);
}
/*
 * Determine if and where in the given disk map (partition table) we can put
 * the requested slice
 */
int
get_best_fit(dmg_map_t pmap, int slot, uint64_t req_blocks) {
	int ii;
	dmg_map_t sorted_map;
	dmg_slice_t found_gap;
	uint64_t gap_sz;
	memcpy(sorted_map, pmap, sizeof (dmg_map_t));

	/*
	 * Sort the map in ascending order so that it's easier to find gaps
	 * -----------------------------------------------------------------
	 */
	qsort((void *)sorted_map, MAX_SLICES_PER_LUN, sizeof (dmg_slice_t),
	    dmg_slice_compare);

	/*
	 * Find the first defined slice.  Here we assume that there is at least
	 * one undefined slice.  Otherwise we would have never gotten here.  So
	 * let's advance our index to the first defined slice.
	 * ------------------------------------------------------------------
	 */
	for (ii = 0; ii < MAX_SLICES_PER_LUN-1; ii++) {
		if (sorted_map[ii].start)
			break;
	}
	/*
	 * Find the best fitting gap.  This code assumes that the last slice in
	 * the map is Reserved and it points to the highest LBAs of the disk.
	 *
	 * The first gap spans from block 34 up to the beginning of the lowest
	 * defined slice, ii.
	 * (!!!!!!!!! We need to find out where the 34 blocks is #defined so
	 * we can use it here.!!!!!!!!!!)
	 * --------------------------------------------------------------------
	 */
	found_gap.start = 34;
	found_gap.blocks = sorted_map[ii].start - 34;

	/*
	 * Now, find a smaller gap
	 * --------------------------------------------------------------------
	 */
	while (ii < MAX_SLICES_PER_LUN-1) {
		gap_sz =  sorted_map[ii+1].start -
			(sorted_map[ii].start + sorted_map[ii].blocks);
		if ((req_blocks <= gap_sz) && ((gap_sz < found_gap.blocks) ||
					(found_gap.blocks < req_blocks))) {
			found_gap.start =
				sorted_map[ii].start + sorted_map[ii].blocks;
			found_gap.blocks = gap_sz;
		}
		ii++;
	}
	pmap[slot].start = found_gap.start;
	return (found_gap.blocks >= (pmap[slot].blocks = req_blocks));
}

int
get_disk_name(slice_req_t *disk_parms, char *subcommand) {
	int tot_luns = 0;
	dmg_lun_t *luns = NULL;

	if (!disk_parms->disk_name[0]) {
		syslog(LOG_ERR, ERROR_NO_DISK, subcommand);
		return (EXIT_NO_DISK);
	}
	
	return (0);
}

int
get_gap(dmg_map_t map, int slot, slice_req_t *slice_req) {
	int ii, status = 0;
	int jj = 0;
	dmg_map_t sorted_map;
	uint64_t gp_sz, gp_start;

	memcpy(sorted_map, map, sizeof (dmg_map_t));

	/*
	 * Sort the map in ascending order to find gaps
	 * --------------------------------------------------------------------
	 */
	qsort((void *)sorted_map, MAX_SLICES_PER_LUN,
				sizeof (dmg_slice_t), dmg_slice_compare);

	/*
	 * Find the first defined slice.
	 * ---------------------------------------------------------------------
	 */
	for (ii = 0; ii < MAX_SLICES_PER_LUN-1; ii++) {
		if (sorted_map[ii].start)
			break;
	}
	gp_start = 34;

	do {
		if (gp_sz = sorted_map[ii].start - gp_start) {
			if (jj == slice_req->gap_index) {
				break;
			}
			jj++;
		}
		gp_start = sorted_map[ii].start + sorted_map[ii].blocks;
		ii++;
	} while (ii < MAX_SLICES_PER_LUN-1);
	if (gp_sz = sorted_map[ii].start - gp_start) {
		if (jj == slice_req->gap_index) {
			map [slot].start = gp_start;
			map [slot].blocks = gp_sz;
			map [slot].assigned = 1;
		}
	}
	else
		return (-1);
	return (0);
}

int
create_slice(slice_req_t *slice_req)
{
	int ii;
	int err;
	dmg_map_t map;
	int status = 0;
	boolean_t bflag;

	bflag = B_FALSE;
	if (status = get_disk_name(slice_req, SUBC_CREATE))
		return (status);

	
	/*
	 * Need at least a size or an index to create a slice
	 * --------------------------------------------------------------------
	 */
	if (!(slice_req->mbytes) && (slice_req->gap_index < 0)) {
		printf(ERROR_NO_PARMS, SUBC_CREATE);
		return (EXIT_NO_PARMS);
	}
	memset(map, 0, sizeof (map));

	/*
	 * Get slice definitions and determine if there is a slot available
	 * -------------------------------------------------------------------
	 */
	status = dmg_get_slices(slice_req->disk_name, map, 0);
	
	if (status == EFI_FAILS) {
		syslog(LOG_ERR, ERROR_INTERNAL_ERROR, SUBC_CREATE);
		return (EXIT_INTERNAL_ERROR);
	}

	if (status == EFI_FIRST)
		bflag = B_TRUE;
	
	for (ii = 0; ii < MAX_SLICES_PER_LUN-1; ii++) {
		if (!map[ii].assigned) {
			break;
		}
	}

	if (ii >= MAX_SLICES_PER_LUN - 1) {
		syslog(LOG_ERR, ERROR_NO_SLICES, SUBC_CREATE);
		return (EXIT_NO_SLICES);
	}
	if (!bflag) {
		if (slice_req->gap_index < 0) {
			/*
			 * New slice can be defined in iith slot.  Now determine where
			 * in the disk we can allocate the desired space.
			 * -------------------------------------------------------------
			 */
			if (!(map[ii].assigned = get_best_fit(map, ii,
			    slice_req->mbytes*1024*1024/512))) {
				syslog(LOG_ERR, ERROR_NO_SPACE, SUBC_CREATE);
				return (EXIT_NO_SPACE);
			}
		} else {
			if (get_gap(map, ii, slice_req)) {
				syslog(LOG_ERR, ERROR_NO_SPACE, SUBC_CREATE);
				return (EXIT_NO_SPACE);
			}
		}
	}
	slice_req->slice_index = ii;

	if (slice_req->mbytes) {
		if (bflag) {
			map[ii].start = EFI_FIRST_START_BLOCK;
			map[ii].assigned = 1;
		}
		map[ii].blocks = slice_req->mbytes*1024*1024/512;
		
	}

	/*
	 * Write up the new map.
	 * ---------------------------------------------------------------------
	 */
	err = dmg_put_slices(slice_req->disk_name, map, bflag);
	return (err);
}



void get_slice_info(int slice_fd, uint64_t *startp, uint64_t *nblocksp)
{
	int start;
	int nblock;
	int part;
	dk_gpt_t *vtocp;

	part = efi_alloc_and_read(slice_fd, &vtocp);
	if (part >= 0) {
		start = vtocp->efi_parts[part].p_start;
		nblock = vtocp->efi_parts[part].p_size;
	}
	*startp = start;
	*nblocksp = nblock;
	efi_free(vtocp);
}
double size_down(uint64_t size, char *dim) {
	int ii = 0;
	static  char scale [4] = {'K', 'M', 'G', 'T'};
	size *= 512;
	double measure= (double) size;

	while (measure > 1024) {
		ii++;
		measure /= 1024;
	}
	
	/*while (size > 1024) {
		ii++;
		size /= 1024;
	}*/
	*dim = measure ? scale[ii ? ii-1 : 0] : '0';

	return (measure);
}
