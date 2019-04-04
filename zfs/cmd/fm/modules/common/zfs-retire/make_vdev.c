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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Functions to convert between a list of vdevs and an nvlist representing the
 * configuration.  Each entry in the list can be one of:
 *
 * 	Device vdevs
 * 		disk=(path=..., devid=...)
 * 		file=(path=...)
 *
 * 	Group vdevs
 * 		raidz[1|2]=(...)
 * 		mirror=(...)
 *
 * 	Hot spares
 *
 * While the underlying implementation supports it, group vdevs cannot contain
 * other group vdevs.  All userland verification of devices is contained within
 * this file.  If successful, the nvlist returned can be passed directly to the
 * kernel; we've done as much verification as possible in userland.
 *
 * Hot spares are a special case, and passed down as an array of disk vdevs, at
 * the same level as the root of the vdev tree.
 *
 * The only function exported by this file is 'make_root_vdev'.  The
 * function performs several passes:
 *
 * 	1. Construct the vdev specification.  Performs syntax validation and
 *         makes sure each device is valid.
 * 	2. Check for devices in use.  Using libdiskmgt, makes sure that no
 *         devices are also in use.  Some can be overridden using the 'force'
 *         flag, others cannot.
 * 	3. Check for replication errors if the 'force' flag is not specified.
 *         validates that the replication level is consistent across the
 *         entire pool.
 * 	4. Call libzfs to label any whole disks with an EFI label.
 */

#include <assert.h>
#include <devid.h>
#include <errno.h>
#include <fcntl.h>
//#include <libdiskmgt.h>
#include <libintl.h>
#include <libnvpair.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/efi_partition.h>
#include <sys/stat.h>
#include <sys/vtoc.h>
#include <sys/mntent.h>
#include <syslog.h>
#include <libzfs.h>
//#include <libautoslice.h>
#include <values.h>

#if 0
#include "zpool_util.h"
#endif

#define	RDISK_ROOT	"/dev/rdsk"
#define	BACKUP_SLICE	"s2"
#define	ZPOOL_CONFIG_IS_LOG		"is_log"
#define	ZPOOL_CONFIG_IS_META		"is_meta"
#define	ZPOOL_CONFIG_PATH		"path"
#define	ZPOOL_CONFIG_TYPE		"type"
#define	ZPOOL_CONFIG_IS_SPARE		"is_spare"
#define	ZPOOL_CONFIG_IS_MIRRORSPARE	"is_mirrorspare"

libzfs_handle_t *zfs_hdl = NULL;

/*
 * By "whole disk" we mean an entire physical disk (something we can
 * label, toggle the write cache on, etc.) as opposed to the full
 * capacity of a pseudo-device such as lofi or did.  We act as if we
 * are labeling the disk, which should be a pretty good test of whether
 * it's a viable device or not.  Returns B_TRUE if it is and B_FALSE if
 * it isn't.
 */
static boolean_t
is_whole_disk(const char *arg)
{
	struct dk_gpt *label;
	int	fd;
	char	path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "%s%s%s",
	    RDISK_ROOT, strrchr(arg, '/'), BACKUP_SLICE);
	if ((fd = open(path, O_RDWR | O_NDELAY)) < 0)
		return (B_FALSE);
	if (efi_alloc_and_init(fd, EFI_NUMPAR, &label) != 0) {
		(void) close(fd);
		return (B_FALSE);
	}
	efi_free(label);
	(void) close(fd);
	return (B_TRUE);
}

/*
 * Create a leaf vdev.  Determine if this is a file or a device.  If it's a
 * device, fill in the device id to make a complete nvlist.  Valid forms for a
 * leaf vdev are:
 *
 * 	/dev/dsk/xxx	Complete disk path
 * 	/xxx		Full path to file
 * 	xxx		Shorthand for /dev/dsk/xxx
 */
static nvlist_t *
make_leaf_vdev(const char *arg, uint64_t is_log, uint64_t is_meta,
	uint64_t is_spare)
{
	char path[MAXPATHLEN];
	struct stat64 statbuf;
	nvlist_t *vdev = NULL;
	char *type = NULL;
	boolean_t wholedisk = B_FALSE;

	/*
	 * Determine what type of vdev this is, and put the full path into
	 * 'path'.  We detect whether this is a device of file afterwards by
	 * checking the st_mode of the file.
	 */
	if (arg[0] == '/') {
		/*
		 * Complete device or file path.  Exact type is determined by
		 * examining the file descriptor afterwards.
		 */
		wholedisk = is_whole_disk(arg);
		if (!wholedisk && (stat64(arg, &statbuf) != 0)) {
			(void) fprintf(stderr,
			    gettext("cannot open '%s': %s\n"),
			    arg, strerror(errno));
			return (NULL);
		}

		(void) strlcpy(path, arg, sizeof (path));
	} else {
		/*
		 * This may be a short path for a device, or it could be total
		 * gibberish.  Check to see if it's a known device in
		 * /dev/dsk/.  As part of this check, see if we've been given a
		 * an entire disk (minus the slice number).
		 */
		(void) snprintf(path, sizeof (path), "%s/%s", DISK_ROOT,
		    arg);
		wholedisk = is_whole_disk(path);
		if (!wholedisk && (stat64(path, &statbuf) != 0)) {
			/*
			 * If we got ENOENT, then the user gave us
			 * gibberish, so try to direct them with a
			 * reasonable error message.  Otherwise,
			 * regurgitate strerror() since it's the best we
			 * can do.
			 */
			if (errno == ENOENT) {
				(void) fprintf(stderr,
				    gettext("cannot open '%s': no such "
				    "device in %s\n"), arg, DISK_ROOT);
				(void) fprintf(stderr,
				    gettext("must be a full path or "
				    "shorthand device name\n"));
				return (NULL);
			} else {
				(void) fprintf(stderr,
				    gettext("cannot open '%s': %s\n"),
				    path, strerror(errno));
				return (NULL);
			}
		}
	}

	/*
	 * Determine whether this is a device or a file.
	 */
	if (wholedisk || S_ISBLK(statbuf.st_mode)) {
		type = VDEV_TYPE_DISK;
	} else if (S_ISREG(statbuf.st_mode)) {
		type = VDEV_TYPE_FILE;
	} else {
		(void) fprintf(stderr, gettext("cannot use '%s': must be a "
		    "block device or regular file\n"), path);
		return (NULL);
	}

	/*
	 * Finally, we have the complete device or file, and we know that it is
	 * acceptable to use.  Construct the nvlist to describe this vdev.  All
	 * vdevs have a 'path' element, and devices also have a 'devid' element.
	 */
	verify(nvlist_alloc(&vdev, NV_UNIQUE_NAME, 0) == 0);
	verify(nvlist_add_string(vdev, ZPOOL_CONFIG_PATH, path) == 0);
	verify(nvlist_add_string(vdev, ZPOOL_CONFIG_TYPE, type) == 0);
	verify(nvlist_add_uint64(vdev, ZPOOL_CONFIG_IS_LOG, is_log) == 0);
	verify(nvlist_add_uint64(vdev, ZPOOL_CONFIG_IS_META, is_meta) == 0);
	verify(nvlist_add_uint64(vdev, ZPOOL_CONFIG_IS_SPARE, is_spare) == 0);
	verify(nvlist_add_uint64(vdev, ZPOOL_CONFIG_IS_MIRRORSPARE, 1) == 0);
	


	if (strcmp(type, VDEV_TYPE_DISK) == 0)
		verify(nvlist_add_uint64(vdev, ZPOOL_CONFIG_WHOLE_DISK,
		    (uint64_t)wholedisk) == 0);

	/*
	 * For a whole disk, defer getting its devid until after labeling it.
	 */
	if (S_ISBLK(statbuf.st_mode) && !wholedisk) {
		/*
		 * Get the devid for the device.
		 */
		int fd;
		ddi_devid_t devid;
		char *minor = NULL, *devid_str = NULL;

		if ((fd = open(path, O_RDONLY)) < 0) {
			(void) fprintf(stderr, gettext("cannot open '%s': "
			    "%s\n"), path, strerror(errno));
			nvlist_free(vdev);
			return (NULL);
		}

		if (devid_get(fd, &devid) == 0) {
			if (devid_get_minor_name(fd, &minor) == 0 &&
			    (devid_str = devid_str_encode(devid, minor)) !=
			    NULL) {
				verify(nvlist_add_string(vdev,
				    ZPOOL_CONFIG_DEVID, devid_str) == 0);
			}
			if (devid_str != NULL)
				devid_str_free(devid_str);
			if (minor != NULL)
				devid_str_free(minor);
			devid_free(devid);
		}

		(void) close(fd);
	}

	return (vdev);
}

/*
 * Go through and verify the replication level of the pool is consistent.
 * Performs the following checks:
 *
 * 	For the new spec, verifies that devices in mirrors and raidz are the
 * 	same size.
 *
 * 	If the current configuration already has inconsistent replication
 * 	levels, ignore any other potential problems in the new spec.
 *
 * 	Otherwise, make sure that the current spec (if there is one) and the new
 * 	spec have consistent replication levels.
 */
typedef struct replication_level {
	char *zprl_type;
	uint64_t zprl_children;
	uint64_t zprl_parity;
} replication_level_t;

/*
 * Go through and find any whole disks in the vdev specification, labelling them
 * as appropriate.  When constructing the vdev spec, we were unable to open this
 * device in order to provide a devid.  Now that we have labelled the disk and
 * know that slice 0 is valid, we can construct the devid now.
 *
 * If the disk was already labeled with an EFI label, we will have gotten the
 * devid already (because we were able to open the whole disk).  Otherwise, we
 * need to get the devid after we label the disk.
 */
static int
make_disks(zpool_handle_t *zhp, nvlist_t *nv)
{
	nvlist_t **child;
	uint_t c, children;
	char *type, *path, *diskname;
	char buf[MAXPATHLEN];
	uint64_t wholedisk;
	int fd;
	int ret;
	ddi_devid_t devid;
	char *minor = NULL, *devid_str = NULL;

	verify(nvlist_lookup_string(nv, ZPOOL_CONFIG_TYPE, &type) == 0);

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0) {

		if (strcmp(type, VDEV_TYPE_DISK) != 0)
			return (0);

		/*
		 * We have a disk device.  Get the path to the device
		 * and see if it's a whole disk by appending the backup
		 * slice and stat()ing the device.
		 */
		verify(nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) == 0);
		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_WHOLE_DISK,
		    &wholedisk) != 0 || !wholedisk)
			return (0);

		diskname = strrchr(path, '/');
		assert(diskname != NULL);
		diskname++;
		if (zpool_label_disk(zfs_hdl, zhp, diskname) == -1)
			return (-1);

		/*
		 * Fill in the devid, now that we've labeled the disk.
		 */
		(void) snprintf(buf, sizeof (buf), "%ss0", path);
		if ((fd = open(buf, O_RDONLY)) < 0) {
			(void) fprintf(stderr,
			    gettext("cannot open '%s': %s\n"),
			    buf, strerror(errno));
			return (-1);
		}

		if (devid_get(fd, &devid) == 0) {
			if (devid_get_minor_name(fd, &minor) == 0 &&
			    (devid_str = devid_str_encode(devid, minor)) !=
			    NULL) {
				verify(nvlist_add_string(nv,
				    ZPOOL_CONFIG_DEVID, devid_str) == 0);
			}
			if (devid_str != NULL)
				devid_str_free(devid_str);
			if (minor != NULL)
				devid_str_free(minor);
			devid_free(devid);
		}

		/*
		 * Update the path to refer to the 's0' slice.  The presence of
		 * the 'whole_disk' field indicates to the CLI that we should
		 * chop off the slice number when displaying the device in
		 * future output.
		 */
		verify(nvlist_add_string(nv, ZPOOL_CONFIG_PATH, buf) == 0);

		(void) close(fd);

		return (0);
	}

	for (c = 0; c < children; c++)
		if ((ret = make_disks(zhp, child[c])) != 0)
			return (ret);

	return (0);
}

/*
 * Construct a syntactically valid vdev specification,
 * and ensure that all devices and files exist and can be opened.
 * Note: we don't bother freeing anything in the error paths
 * because the program is just going to exit anyway.
 */
nvlist_t *
construct_spec(int argc, char **argv)
{
	nvlist_t *nvroot, *nv, **top;
	int t, toplevels;

	top = NULL;
	toplevels = 0;

	if (argc) {
		nv = NULL;
		/*
		* We have a device.  Pass off to make_leaf_vdev() to
		* construct the appropriate nvlist describing the vdev.
		*/
	
		if ((nv = make_leaf_vdev(argv[0], 0, 0, 0)) == NULL)
			return (NULL);

		toplevels++;
		top = realloc(top, toplevels * sizeof (nvlist_t *));
		if (top == NULL){
			assert(errno == ENOMEM);
			syslog(LOG_ERR, "internal error: out of memory");
			exit(1);
		}
		top[toplevels - 1] = nv;
	}

	/*
	 * Finally, create nvroot and add all top-level vdevs to it.
	 */
	verify(nvlist_alloc(&nvroot, NV_UNIQUE_NAME, 0) == 0);
	verify(nvlist_add_string(nvroot, ZPOOL_CONFIG_TYPE,
	    VDEV_TYPE_ROOT) == 0);
	verify(nvlist_add_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN,
	    top, toplevels) == 0);
	
	for (t = 0; t < toplevels; t++)
		nvlist_free(top[t]);

	free(top);

	return (nvroot);
}

/*
 * Get and validate the contents of the given vdev specification.  This ensures
 * that the nvlist returned is well-formed, that all the devices exist, and that
 * they are not currently in use by any other known consumer.  The 'poolconfig'
 * parameter is the current configuration of the pool when adding devices
 * existing pool, and is used to perform additional checks, such as changing the
 * replication level of the pool.  It can be 'NULL' to indicate that this is a
 * new pool.  The 'force' flag controls whether devices should be forcefully
 * added, even if they appear in use.
 */
nvlist_t *
make_vdev(zpool_handle_t *zhp, int check_rep,
    boolean_t replacing, boolean_t dryrun, int argc, char **argv)
{
	nvlist_t *newroot;
	nvlist_t *poolconfig = NULL;

	zfs_hdl = zpool_get_handle(zhp);
	/*
	 * Construct the vdev specification.  If this is successful, we know
	 * that we have a valid specification, and that all devices can be
	 * opened.
	 */

	if ((newroot = construct_spec(argc, argv)) == NULL)
		return (NULL);

	if (zhp && ((poolconfig = zpool_get_config(zhp, NULL)) == NULL))
		return (NULL);

	/*
	 * Run through the vdev specification and label any whole disks found.
	 */
	if (!dryrun && make_disks(zhp, newroot) != 0) {
		nvlist_free(newroot);
		return (NULL);
	}
	
	return (newroot);
}
