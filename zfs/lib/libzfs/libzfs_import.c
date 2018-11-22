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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * Pool import support functions.
 *
 * To import a pool, we rely on reading the configuration information from the
 * ZFS label of each device.  If we successfully read the label, then we
 * organize the configuration information in the following hierarchy:
 *
 * 	pool guid -> toplevel vdev guid -> label txg
 *
 * Duplicate entries matching this same tuple will be discarded.  Once we have
 * examined every device, we pick the best label txg config for each toplevel
 * vdev.  We then arrange these toplevel vdevs into a complete pool config, and
 * update any paths that have changed.  Finally, we attempt to import the pool
 * using our derived config, and record the results.
 */

#include <ctype.h>
#include <devid.h>
#include <dirent.h>
#include <errno.h>
#include <libintl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/vtoc.h>
#include <sys/dktp/fdisk.h>
#include <sys/efi_partition.h>
#include <syslog.h>
#include <sys/spa_impl.h>

#include <sys/vdev_impl.h>
#ifdef HAVE_LIBBLKID
#include <blkid/blkid.h>
#endif

#include "libzfs.h"
#include "libzfs_impl.h"

/*
 * Intermediate structures used to gather configuration information.
 */
typedef struct config_entry {
	uint64_t		ce_txg;
	nvlist_t		*ce_config;
	struct config_entry	*ce_next;
} config_entry_t;

typedef struct vdev_entry {
	uint64_t		ve_guid;
	config_entry_t		*ve_configs;
	struct vdev_entry	*ve_next;
} vdev_entry_t;

typedef struct pool_entry {
	uint64_t		pe_guid;
	vdev_entry_t		*pe_vdevs;
	struct pool_entry	*pe_next;
} pool_entry_t;

typedef struct name_entry {
	char			*ne_name;
	uint64_t		ne_guid;
	uint64_t		ne_order;
	uint64_t		ne_num_labels;
	struct name_entry	*ne_next;
} name_entry_t;

typedef struct pool_list {
	pool_entry_t		*pools;
	name_entry_t		*names;
} pool_list_t;

#define	DEV_BYID_PATH	"/dev/disk/by-id/"

static char *
get_devid(const char *path)
{
	int fd;
	ddi_devid_t devid;
	char *minor, *ret;

	if ((fd = open(path, O_RDONLY)) < 0)
		return (NULL);

	minor = NULL;
	ret = NULL;
	if (devid_get(fd, &devid) == 0) {
		if (devid_get_minor_name(fd, &minor) == 0)
			ret = devid_str_encode(devid, minor);
		if (minor != NULL)
			devid_str_free(minor);
		devid_free(devid);
	}
	(void) close(fd);

	return (ret);
}

/*
 * Wait up to timeout_ms for udev to set up the device node.  The device is
 * considered ready when the provided path have been verified to exist and
 * it has been allowed to settle.  At this point the device the device can
 * be accessed reliably.  Depending on the complexity of the udev rules thisi
 * process could take several seconds.
 */
int
zpool_label_disk_wait(char *path, int timeout_ms)
{
	int settle_ms = 50;
	long sleep_ms = 10;
	hrtime_t start, settle;
	struct stat64 statbuf;

	start = gethrtime();
	settle = 0;

	do {
		errno = 0;
		if ((stat64(path, &statbuf) == 0) && (errno == 0)) {
			if (settle == 0)
				settle = gethrtime();
			else if (NSEC2MSEC(gethrtime() - settle) >= settle_ms)
				return (0);
		} else if (errno != ENOENT) {
			return (errno);
		}

		usleep(sleep_ms * MILLISEC);
	} while (NSEC2MSEC(gethrtime() - start) < timeout_ms);

	return (ENODEV);
}

/* Interface of stamp */

static int
add_mounted_pools(zpool_handle_t *zhp, void *data)
{
	nvlist_t *config = data;
	nvlist_t *pool;
	char *name;
	
	pool = zpool_get_config(zhp, NULL);
	/* add this pool to the list of configs */
	verify(nvlist_lookup_string(pool, ZPOOL_CONFIG_POOL_NAME,
	    &name) == 0);
	if (nvlist_add_nvlist(config, name, pool) != 0) {
		fprintf(stderr, "add umount pool <%s> failed\n", name);
		return (1);
	}

	zpool_close(zhp);

	return (0);
}

static nvlist_t *get_switched_config(
	libzfs_handle_t *hdl, char *name, uint32_t remote_hostid)
{
	nvlist_t *nvl;
	zfs_cmd_t zc = {"\0"};
	int err;

	if (name != NULL) {
		strcpy(zc.zc_name, name);
	}
	zc.zc_cookie = ZFS_HBX_GET_PARTNER_POOL;
	zc.zc_guid = remote_hostid;
	if (zcmd_alloc_dst_nvlist(hdl, &zc, 0) != 0) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	while ((err = ioctl(hdl->libzfs_fd, ZFS_IOC_HBX,
	    &zc)) != 0 && errno == ENOMEM) {
		if (zcmd_expand_dst_nvlist(hdl, &zc) != 0) {
			zcmd_free_nvlists(&zc);
			return (NULL);
		}
	}

	if (err) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	if (zcmd_read_dst_nvlist(hdl, &zc, &nvl) != 0) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	zcmd_free_nvlists(&zc);
	return (nvl);
}

int
read_vtoc(int fd, struct vtoc *vtoc)
{
	struct dk_cinfo		dki_info;

	/*
	 * Read the vtoc.
	 */
	if (ioctl(fd, DKIOCGVTOC, (caddr_t)vtoc) == -1) {
		switch (errno) {
		case EIO:
			return (VT_EIO);
		case EINVAL:
			return (VT_EINVAL);
		case ENOTSUP:
			/* GPT labeled or disk > 1TB with no extvtoc support */
			return (VT_ENOTSUP);
		case EOVERFLOW:
			return (VT_EOVERFLOW);
		default:
			return (VT_ERROR);
		}
	}

	/*
	 * Sanity-check the vtoc.
	 */
	if (vtoc->v_sanity != VTOC_SANE) {
		return (VT_EINVAL);
	}

	/*
	 * Convert older-style vtoc's.
	 */
	switch (vtoc->v_version) {
	case 0:
		/*
		 * No vtoc information.  Install default
		 * nparts/sectorsz and version.  We are
		 * assuming that the driver returns the
		 * current partition information correctly.
		 */

		vtoc->v_version = V_VERSION;
		if (vtoc->v_nparts == 0)
			vtoc->v_nparts = V_NUMPAR;
		if (vtoc->v_sectorsz == 0)
			vtoc->v_sectorsz = DEV_BSIZE;

		break;

	case V_VERSION:
		break;

	default:
		return (VT_EINVAL);
	}

	/*
	 * Return partition number for this file descriptor.
	 */
	if (ioctl(fd, DKIOCINFO, (caddr_t)&dki_info) == -1) {
		switch (errno) {
		case EIO:
			return (VT_EIO);
		case EINVAL:
			return (VT_EINVAL);
		default:
			return (VT_ERROR);
		}
	}
	if (dki_info.dki_partition > V_NUMPAR) {
		return (VT_EINVAL);
	}
	return ((int)dki_info.dki_partition);
}

uint64_t
label_offset(uint64_t size, int l)
{
	ASSERT(P2PHASE_TYPED(size, sizeof (vdev_label_t), uint64_t) == 0);
	return (l * sizeof (vdev_label_t) + (l < VDEV_LABELS / 2 ?
	    0 : size - VDEV_LABELS * sizeof (vdev_label_t)));
}


static uint64_t
stamp_offset(uint64_t size, int l)
{
	ASSERT(P2PHASE_TYPED(size, sizeof (zpool_stamp_t), uint64_t) == 0);
	return (l * sizeof (vdev_label_t) + (l < VDEV_LABELS / 2 ?
	    0 : size - VDEV_LABELS * sizeof (vdev_label_t)));
}

int get_disk_stamp_offset(int disk_fd, uint64_t *offset)
{
	uint64_t size;
	struct stat64 statbuf;
	struct vtoc vtoc_info;
	uint64_t tmp_offset  = 0;
	if (fstat64(disk_fd, &statbuf) == -1)
		return (1);
	size = P2ALIGN_TYPED(statbuf.st_size, sizeof (zpool_stamp_t), uint64_t);
	if (read_vtoc(disk_fd, &vtoc_info) >= 0) {
			return (1);
	}
	tmp_offset = stamp_offset(size, VDEV_STAMP_LABEL_NO);
	*offset = tmp_offset;
	return (0);
}

int zpool_write_dev_stamp(char *path, zpool_stamp_t *stamp)
{
	int fd,ret = 1;
	uint64_t stamp_offset;
	zpool_stamp_t *stamp_tmp;
	stamp_tmp = malloc(sizeof(zpool_stamp_t));
	if (stamp_tmp != NULL) {
		bzero(stamp_tmp, sizeof(zpool_stamp_t));
	}

	fd = open(path, O_RDWR|O_NDELAY|O_SYNC);
	if (fd > 0) {
		if (get_disk_stamp_offset(fd, &stamp_offset) != 0) {
			syslog(LOG_ERR, "write stamp, get offset <%s> failed", path);
		} else {
			if (pread(fd, stamp_tmp, sizeof(zpool_stamp_t), stamp_offset) == sizeof(zpool_stamp_t)){
				if(stamp_tmp->para.company_name == COMPANY_NAME)
					stamp->para.company_name = stamp_tmp->para.company_name;
			}
			if (pwrite(fd, stamp, sizeof(zpool_stamp_t), stamp_offset) != sizeof(zpool_stamp_t)) {
				syslog(LOG_ERR, "write error, <%s>", path);
			} else {
				ret = 0;
			}
		}
		close(fd);
	} else {
		syslog(LOG_ERR, "write stamp, open <%s> failed",path);
	}
	free(stamp_tmp);

	return (ret);
}

int zpool_write_dev_stamp_mark(char *path, zpool_stamp_t *stamp)
{
	int fd,ret = 1;
	uint64_t stamp_offset;
	zpool_stamp_t *stamp_tmp;
	stamp_tmp = malloc(sizeof(zpool_stamp_t));
	if (stamp_tmp != NULL) {
		bzero(stamp_tmp, sizeof(zpool_stamp_t));
	}
	fd = open(path, O_RDWR|O_NDELAY|O_SYNC);
	if (fd > 0) {
		if (get_disk_stamp_offset(fd, &stamp_offset) != 0) {
			syslog(LOG_ERR, "write stamp, get offset <%s> failed", path);
		} else {
			stamp_offset += stamp_offset/STAMP_OFFSET;
			if (pread(fd, stamp_tmp, sizeof(zpool_stamp_t), stamp_offset) == sizeof(zpool_stamp_t)){
				if(stamp_tmp->para.company_name == COMPANY_NAME)
					stamp->para.company_name = stamp_tmp->para.company_name;
			}
			if (pwrite(fd, stamp, sizeof(zpool_stamp_t), stamp_offset) != sizeof(zpool_stamp_t)) {
				syslog(LOG_ERR, "write error, <%s>", path);
			} else {
				ret = 0;
			}
		}
		close(fd);
	} else {
		syslog(LOG_ERR, "write stamp, open <%s> failed",path);
	}
    free(stamp_tmp);
	return (ret);
}

int zpool_read_stmp_by_path(char *path, zpool_stamp_t *stamp)
{
	int fd, ret = 1,len;
	char tmp_path[1024];
	uint64_t stamp_offset = 0;
	sprintf(tmp_path, "%s", path);
	len = strlen(tmp_path);
#if 0
	if (*(tmp_path + len - 2) == 's') {
		*(tmp_path + len -2) = '\0';
	}
#endif

	fd = open(tmp_path, O_RDONLY|O_NDELAY);
	if (fd > 0) {
		if (get_disk_stamp_offset(fd, &stamp_offset) != 0) {
			syslog(LOG_ERR, "read stamp, get stamp offset failed");
			close(fd);
			return (ret);
		}
		stamp_offset += stamp_offset/STAMP_OFFSET;
		if (pread(fd, stamp, sizeof(zpool_stamp_t), stamp_offset)
		    == sizeof(zpool_stamp_t)) {
			if (stamp->para.company_name == COMPANY_NAME) {
				ret = 0;
			} else {
				syslog(LOG_ERR, "pool company name check failed");
			}
		} else {
			syslog(LOG_ERR, "read stamp failed");
		}
		close(fd);
	}
	return (ret);
}

int
zpool_read_stamp(nvlist_t *pool_root, zpool_stamp_t *stamp)
{
	char *path;
	int fd, ret = 1, err;
	nvlist_t **child;
	uint_t i, children;
	uint64_t quantum;
	int size;
	
	verify(nvlist_lookup_nvlist_array(pool_root, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0);
	for (i = 0; i < children; i ++) {
		nvlist_t **tmp_child;
		uint_t tmp_children;
		uint64_t stamp_offset = 0;

		if (nvlist_lookup_nvlist_array(child[i], ZPOOL_CONFIG_CHILDREN,
    		    &tmp_child, &tmp_children) == 0) {
    		    	ret = zpool_read_stamp(child[i], stamp);
			if (ret == 0) {
				break;
			}
		} else {
			err = nvlist_lookup_string(child[i], ZPOOL_CONFIG_PATH, &path);
			if (err != 0) {
				syslog(LOG_ERR, "pool get config path failed");
				continue;
			}

			err = nvlist_lookup_uint64(child[i], ZPOOL_CONFIG_QUANTUM_DEV, &quantum);
			if (err != 0 || quantum == 0)
				continue;
			
#if 0
			if (strncmp(path, "/dev/dsk/", 9) == 0)
				path += 9;

			(void)zpool_get_quantum_path(path);

			fd = open(tmp_path, O_RDONLY|O_NDELAY);
#endif
			fd = open(path, O_RDONLY|O_NDELAY);
			if (fd > 0) {
				if (get_disk_stamp_offset(fd, &stamp_offset) != 0) {
					syslog(LOG_ERR, "read stamp <%s>, get stamp offset failed", path);
					close(fd);
					continue;
				}
				size = pread(fd, stamp, sizeof(zpool_stamp_t), stamp_offset);
				if (size == -1)
					size = pread(fd, stamp, sizeof(zpool_stamp_t), stamp_offset);
				if (size == sizeof(zpool_stamp_t)) {
					if (stamp->para.pool_magic == ZPOOL_MAGIC) {
						ret = 0;
						close(fd);
						break;
					} else {
						syslog(LOG_ERR, "<%s> pool magic num check failed", path);
					}
				} else {
					syslog(LOG_ERR, "read stamp <%s> failed, size=%d, expected size=%d",
						path, size, sizeof(zpool_stamp_t));
				}
				close(fd);
				continue;
			}
		}
	}

	if (ret)
		syslog(LOG_ERR, "read stamp info failed");
	return (ret);
}

int zpool_write_stamp(nvlist_t *pool_root, zpool_stamp_t *stamp, int nquantum)
{
	char *path;
	int found = 0;
	nvlist_t **child;
	nvlist_t **spares;
	uint_t i, children;

	verify(nvlist_lookup_nvlist_array(pool_root, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0);
	for (i = 0; i < children; i ++) {
		nvlist_t **tmp_child;
		uint_t tmp_children;
	
		if (nvlist_lookup_nvlist_array(child[i], ZPOOL_CONFIG_CHILDREN,
    		    &tmp_child, &tmp_children) == 0) {
    		   	found += zpool_write_stamp(child[i], stamp, nquantum - found);
			if (found == nquantum) {
				break;
			}
		}  else {
			int ret;
			uint64_t quantum;
			ret = nvlist_lookup_uint64(child[i], ZPOOL_CONFIG_QUANTUM_DEV, &quantum);
			if (ret != 0 || quantum == 0)
				continue;
			nvlist_lookup_string(child[i], ZPOOL_CONFIG_PATH, &path);
#if 0
			if (strncmp(path, "/dev/dsk/", 9) == 0)
				path += 9;
			sprintf(tmp_path, "/dev/rdsk/%s", path);
			ret = zpool_write_dev_stamp(tmp_path, stamp);
#endif
			ret = zpool_write_dev_stamp(path, stamp);
			if (ret != 0) {
				continue;
			} else {
				found++;
				if (found == nquantum)
					break;
			}	
    	}
	}

	return (found);
}

/*
 *
 * Function: restore the disk label from in front of third label
 *
 * Return	: 0==>success; -1==>fail
 */
int
zpool_restore_label(int fd)
{
	struct stat64 statbuf;
	int l;
	vdev_label_t label;
	uint64_t size;
	int rv = 0;
	uint64_t wsize, woffset, tmp_woffset;

	if (fstat64(fd, &statbuf) != 0) {
		syslog(LOG_ERR, "clear label fstat failed:%s", strerror(errno));
		return (-1);
	}
	size = P2ALIGN_TYPED(statbuf.st_size, sizeof (vdev_label_t), uint64_t);

	/* offset in front of third label, because the backup label save there */
	tmp_woffset = label_offset(size, 2);
	for (l = 0; l < VDEV_LABELS; l++) {
		woffset = label_offset(size, l);
#if 0
		pread64(fd, &label, sizeof (vdev_label_t), (tmp_woffset-sizeof (vdev_label_t)*(l + 1)));
		wsize = pwrite64(fd, &label, sizeof (vdev_label_t), woffset);
#endif
		pread(fd, &label, sizeof (vdev_label_t), (tmp_woffset-sizeof (vdev_label_t)*(l + 1)));
		wsize = pwrite(fd, &label, sizeof (vdev_label_t), woffset);
		if (wsize != sizeof (vdev_label_t)) {
			printf("label:%d, woffset:0x%llx, wsize:0x%llx, size:%d\n", l,
			    (u_longlong_t)woffset, (u_longlong_t)wsize, sizeof (vdev_label_t));
			rv = -1;
		}
	}
	return (rv);
}

/*
 * Function: save disk label at end of the disk.
 *		it a opportunity to restore disk label.
 *
 * Return	: 0==>success; -1==>fail
 */
int
zpool_save_label(int fd)
{
	struct stat64 statbuf;
	int l;
	vdev_label_t label;
	uint64_t size;
	int rv = 0;
	uint64_t wsize, woffset, tmp_woffset;

	if (fstat64(fd, &statbuf) != 0) {
		syslog(LOG_ERR, "clear label fstat failed:%s", strerror(errno));
		return (-1);
	}
	size = P2ALIGN_TYPED(statbuf.st_size, sizeof (vdev_label_t), uint64_t);

	/* tmp_woffset recod the third offset */
	tmp_woffset = label_offset(size, 2);
	for (l = 0; l < VDEV_LABELS; l++) {
#if 0
		if (pwrite64(fd, label, sizeof (vdev_label_t),
		    label_offset(size, l)) != sizeof (vdev_label_t))
			rv = -1;
#else
		/* read disk label and write it in front of third */
		woffset = label_offset(size, l);
#if 0
		pread64(fd, &label, sizeof (vdev_label_t), woffset);
		/* tmp_woffset-sizeof (vdev_label_t)*(l + 1). Move forward (vdev_label_t)*(l + 1) size */
		wsize = pwrite64(fd, &label, sizeof (vdev_label_t), (tmp_woffset - sizeof (vdev_label_t)*(l + 1)));
#endif
		pread64(fd, &label, sizeof (vdev_label_t), woffset);
		/* tmp_woffset-sizeof (vdev_label_t)*(l + 1). Move forward (vdev_label_t)*(l + 1) size */
		wsize = pwrite64(fd, &label, sizeof (vdev_label_t), (tmp_woffset - sizeof (vdev_label_t)*(l + 1)));

		if (wsize != sizeof (vdev_label_t)) {
			syslog(LOG_ERR, "label:%d, woffset:0x%llx, wsize:0x%llx, size:%d\n", l,
			    (u_longlong_t)woffset, (u_longlong_t)wsize, sizeof (vdev_label_t));
			rv = -1;
		}
#endif
	}
	return (rv);
}
/* Interface of stamp end */

/*
 * Go through and fix up any path and/or devid information for the given vdev
 * configuration.
 */
static int
fix_paths(nvlist_t *nv, name_entry_t *names)
{
	nvlist_t **child;
	uint_t c, children;
	uint64_t guid;
	name_entry_t *ne, *best;
	char *path, *devid;

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++)
			if (fix_paths(child[c], names) != 0)
				return (-1);
		return (0);
	}

	/*
	 * This is a leaf (file or disk) vdev.  In either case, go through
	 * the name list and see if we find a matching guid.  If so, replace
	 * the path and see if we can calculate a new devid.
	 *
	 * There may be multiple names associated with a particular guid, in
	 * which case we have overlapping partitions or multiple paths to the
	 * same disk.  In this case we prefer to use the path name which
	 * matches the ZPOOL_CONFIG_PATH.  If no matching entry is found we
	 * use the lowest order device which corresponds to the first match
	 * while traversing the ZPOOL_IMPORT_PATH search path.
	 */
	verify(nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid) == 0);
	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) != 0)
		path = NULL;

	best = NULL;
	for (ne = names; ne != NULL; ne = ne->ne_next) {
		if (ne->ne_guid == guid) {
			if (path == NULL) {
				best = ne;
				break;
			}

			if ((strlen(path) == strlen(ne->ne_name)) &&
			    strncmp(path, ne->ne_name, strlen(path)) == 0) {
				best = ne;
				break;
			}

			if (best == NULL) {
				best = ne;
				continue;
			}

			/* Prefer paths with move vdev labels. */
			if (ne->ne_num_labels > best->ne_num_labels) {
				best = ne;
				continue;
			}

			/* Prefer paths earlier in the search order. */
			if (ne->ne_num_labels == best->ne_num_labels &&
			    ne->ne_order < best->ne_order) {
				best = ne;
				continue;
			}
		}
	}

	if (best == NULL)
		return (0);

	if (nvlist_add_string(nv, ZPOOL_CONFIG_PATH, best->ne_name) != 0)
		return (-1);

	if ((devid = get_devid(best->ne_name)) == NULL) {
		(void) nvlist_remove_all(nv, ZPOOL_CONFIG_DEVID);
	} else {
		if (nvlist_add_string(nv, ZPOOL_CONFIG_DEVID, devid) != 0)
			return (-1);
		devid_str_free(devid);
	}

	return (0);
}

/*
 * Add the given configuration to the list of known devices.
 */
static int
add_config(libzfs_handle_t *hdl, pool_list_t *pl, const char *path,
    int order, int num_labels, nvlist_t *config)
{
	uint64_t pool_guid, vdev_guid, top_guid, txg, state;
	pool_entry_t *pe;
	vdev_entry_t *ve;
	config_entry_t *ce;
	name_entry_t *ne;

	/*
	 * If this is a hot spare not currently in use or level 2 cache
	 * device, add it to the list of names to translate, but don't do
	 * anything else.
	 */
	if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
	    &state) == 0 &&
	    (state == POOL_STATE_SPARE || state == POOL_STATE_L2CACHE) &&
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_GUID, &vdev_guid) == 0) {
		if ((ne = zfs_alloc(hdl, sizeof (name_entry_t))) == NULL)
			return (-1);

		if ((ne->ne_name = zfs_strdup(hdl, path)) == NULL) {
			free(ne);
			return (-1);
		}
		ne->ne_guid = vdev_guid;
		ne->ne_order = order;
		ne->ne_num_labels = num_labels;
		ne->ne_next = pl->names;
		pl->names = ne;
		return (0);
	}

	/*
	 * If we have a valid config but cannot read any of these fields, then
	 * it means we have a half-initialized label.  In vdev_label_init()
	 * we write a label with txg == 0 so that we can identify the device
	 * in case the user refers to the same disk later on.  If we fail to
	 * create the pool, we'll be left with a label in this state
	 * which should not be considered part of a valid pool.
	 */
	if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
	    &pool_guid) != 0 ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_GUID,
	    &vdev_guid) != 0 ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_TOP_GUID,
	    &top_guid) != 0 ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
	    &txg) != 0 || txg == 0) {
		nvlist_free(config);
		return (0);
	}

	/*
	 * First, see if we know about this pool.  If not, then add it to the
	 * list of known pools.
	 */
	for (pe = pl->pools; pe != NULL; pe = pe->pe_next) {
		if (pe->pe_guid == pool_guid)
			break;
	}

	if (pe == NULL) {
		if ((pe = zfs_alloc(hdl, sizeof (pool_entry_t))) == NULL) {
			nvlist_free(config);
			return (-1);
		}
		pe->pe_guid = pool_guid;
		pe->pe_next = pl->pools;
		pl->pools = pe;
	}

	/*
	 * Second, see if we know about this toplevel vdev.  Add it if its
	 * missing.
	 */
	for (ve = pe->pe_vdevs; ve != NULL; ve = ve->ve_next) {
		if (ve->ve_guid == top_guid)
			break;
	}

	if (ve == NULL) {
		if ((ve = zfs_alloc(hdl, sizeof (vdev_entry_t))) == NULL) {
			nvlist_free(config);
			return (-1);
		}
		ve->ve_guid = top_guid;
		ve->ve_next = pe->pe_vdevs;
		pe->pe_vdevs = ve;
	}

	/*
	 * Third, see if we have a config with a matching transaction group.  If
	 * so, then we do nothing.  Otherwise, add it to the list of known
	 * configs.
	 */
	for (ce = ve->ve_configs; ce != NULL; ce = ce->ce_next) {
		if (ce->ce_txg == txg)
			break;
	}

	if (ce == NULL) {
		if ((ce = zfs_alloc(hdl, sizeof (config_entry_t))) == NULL) {
			nvlist_free(config);
			return (-1);
		}
		ce->ce_txg = txg;
		ce->ce_config = config;
		ce->ce_next = ve->ve_configs;
		ve->ve_configs = ce;
	} else {
		nvlist_free(config);
	}

	/*
	 * At this point we've successfully added our config to the list of
	 * known configs.  The last thing to do is add the vdev guid -> path
	 * mappings so that we can fix up the configuration as necessary before
	 * doing the import.
	 */
	if ((ne = zfs_alloc(hdl, sizeof (name_entry_t))) == NULL)
		return (-1);

	if ((ne->ne_name = zfs_strdup(hdl, path)) == NULL) {
		free(ne);
		return (-1);
	}

	ne->ne_guid = vdev_guid;
	ne->ne_order = order;
	ne->ne_num_labels = num_labels;
	ne->ne_next = pl->names;
	pl->names = ne;

	return (0);
}

#ifdef HAVE_LIBBLKID
static int
add_path(libzfs_handle_t *hdl, pool_list_t *pools, uint64_t pool_guid,
    uint64_t vdev_guid, const char *path, int order)
{
	nvlist_t *label;
	uint64_t guid;
	int error, fd, num_labels;

	fd = open64(path, O_RDONLY);
	if (fd < 0)
		return (errno);

	error = zpool_read_label(fd, &label, &num_labels);
	close(fd);

	if (error || label == NULL)
		return (ENOENT);

	error = nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_GUID, &guid);
	if (error || guid != pool_guid) {
		nvlist_free(label);
		return (EINVAL);
	}

	error = nvlist_lookup_uint64(label, ZPOOL_CONFIG_GUID, &guid);
	if (error || guid != vdev_guid) {
		nvlist_free(label);
		return (EINVAL);
	}

	error = add_config(hdl, pools, path, order, num_labels, label);

	return (error);
}

static int
add_configs_from_label_impl(libzfs_handle_t *hdl, pool_list_t *pools,
    nvlist_t *nvroot, uint64_t pool_guid, uint64_t vdev_guid)
{
	char udevpath[MAXPATHLEN];
	char *path;
	nvlist_t **child;
	uint_t c, children;
	uint64_t guid;
	int error;

	if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			error  = add_configs_from_label_impl(hdl, pools,
			    child[c], pool_guid, vdev_guid);
			if (error)
				return (error);
		}
		return (0);
	}

	if (nvroot == NULL)
		return (0);

	error = nvlist_lookup_uint64(nvroot, ZPOOL_CONFIG_GUID, &guid);
	if ((error != 0) || (guid != vdev_guid))
		return (0);

	error = nvlist_lookup_string(nvroot, ZPOOL_CONFIG_PATH, &path);
	if (error == 0)
		(void) add_path(hdl, pools, pool_guid, vdev_guid, path, 0);

	error = nvlist_lookup_string(nvroot, ZPOOL_CONFIG_DEVID, &path);
	if (error == 0) {
		sprintf(udevpath, "%s%s", DEV_BYID_PATH, path);
		(void) add_path(hdl, pools, pool_guid, vdev_guid, udevpath, 1);
	}

	return (0);
}

/*
 * Given a disk label call add_config() for all known paths to the device
 * as described by the label itself.  The paths are added in the following
 * priority order: 'path', 'devid', 'devnode'.  As these alternate paths are
 * added the labels are verified to make sure they refer to the same device.
 */
static int
add_configs_from_label(libzfs_handle_t *hdl, pool_list_t *pools,
    char *devname, int num_labels, nvlist_t *label)
{
	nvlist_t *nvroot;
	uint64_t pool_guid;
	uint64_t vdev_guid;
	int error;

	if (nvlist_lookup_nvlist(label, ZPOOL_CONFIG_VDEV_TREE, &nvroot) ||
	    nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_GUID, &pool_guid) ||
	    nvlist_lookup_uint64(label, ZPOOL_CONFIG_GUID, &vdev_guid))
		return (ENOENT);

	/* Allow devlinks to stabilize so all paths are available. */
	zpool_label_disk_wait(devname, DISK_LABEL_WAIT);

	/* Add alternate paths as described by the label vdev_tree. */
	(void) add_configs_from_label_impl(hdl, pools, nvroot,
	    pool_guid, vdev_guid);

	/* Add the device node /dev/sdX path as a last resort. */
	error = add_config(hdl, pools, devname, 100, num_labels, label);

	return (error);
}
#endif /* HAVE_LIBBLKID */

/*
 * Returns true if the named pool matches the given GUID.
 */
static int
pool_active(libzfs_handle_t *hdl, const char *name, uint64_t guid,
    boolean_t *isactive)
{
	zpool_handle_t *zhp;
	uint64_t theguid;

	if (zpool_open_silent(hdl, name, &zhp) != 0)
		return (-1);

	if (zhp == NULL) {
		*isactive = B_FALSE;
		return (0);
	}

	verify(nvlist_lookup_uint64(zhp->zpool_config, ZPOOL_CONFIG_POOL_GUID,
	    &theguid) == 0);

	zpool_close(zhp);

	*isactive = (theguid == guid);
	return (0);
}

static nvlist_t *
refresh_config(libzfs_handle_t *hdl, nvlist_t *config)
{
	nvlist_t *nvl;
	zfs_cmd_t zc = {"\0"};
	int err;

	if (zcmd_write_conf_nvlist(hdl, &zc, config) != 0)
		return (NULL);

	if (zcmd_alloc_dst_nvlist(hdl, &zc,
	    zc.zc_nvlist_conf_size * 2) != 0) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	while ((err = ioctl(hdl->libzfs_fd, ZFS_IOC_POOL_TRYIMPORT,
	    &zc)) != 0 && errno == ENOMEM) {
		if (zcmd_expand_dst_nvlist(hdl, &zc) != 0) {
			zcmd_free_nvlists(&zc);
			return (NULL);
		}
	}

	if (err) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	if (zcmd_read_dst_nvlist(hdl, &zc, &nvl) != 0) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	zcmd_free_nvlists(&zc);
	return (nvl);
}

/*
 * Determine if the vdev id is a hole in the namespace.
 */
boolean_t
vdev_is_hole(uint64_t *hole_array, uint_t holes, uint_t id)
{
	int c;

	for (c = 0; c < holes; c++) {

		/* Top-level is a hole */
		if (hole_array[c] == id)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Convert our list of pools into the definitive set of configurations.  We
 * start by picking the best config for each toplevel vdev.  Once that's done,
 * we assemble the toplevel vdevs into a full config for the pool.  We make a
 * pass to fix up any incorrect paths, and then add it to the main list to
 * return to the user.
 */
static nvlist_t *
get_configs(libzfs_handle_t *hdl, pool_list_t *pl, boolean_t active_ok)
{
	pool_entry_t *pe;
	vdev_entry_t *ve;
	config_entry_t *ce;
	nvlist_t *ret = NULL, *config = NULL, *tmp = NULL, *nvtop, *nvroot;
	nvlist_t **spares, **l2cache, **metaspares, **lowspares, **mirrorspares;
	uint_t i, nspares, nl2cache, nmetaspares, nlowspares, nmirrorspares;
	boolean_t config_seen;
	uint64_t best_txg;
	char *name, *hostname = NULL;
	uint64_t guid;
	uint_t children = 0;
	nvlist_t **child = NULL;
	uint_t holes;
	uint64_t *hole_array, max_id;
	uint_t c;
	boolean_t isactive;
	uint64_t hostid;
	nvlist_t *nvl;
	boolean_t valid_top_config = B_FALSE;

	if (nvlist_alloc(&ret, 0, 0) != 0)
		goto nomem;

	for (pe = pl->pools; pe != NULL; pe = pe->pe_next) {
		uint64_t id, max_txg = 0;

		if (nvlist_alloc(&config, NV_UNIQUE_NAME, 0) != 0)
			goto nomem;
		config_seen = B_FALSE;

		/*
		 * Iterate over all toplevel vdevs.  Grab the pool configuration
		 * from the first one we find, and then go through the rest and
		 * add them as necessary to the 'vdevs' member of the config.
		 */
		for (ve = pe->pe_vdevs; ve != NULL; ve = ve->ve_next) {

			/*
			 * Determine the best configuration for this vdev by
			 * selecting the config with the latest transaction
			 * group.
			 */
			best_txg = 0;
			for (ce = ve->ve_configs; ce != NULL;
			    ce = ce->ce_next) {

				if (ce->ce_txg > best_txg) {
					tmp = ce->ce_config;
					best_txg = ce->ce_txg;
				}
			}

			/*
			 * We rely on the fact that the max txg for the
			 * pool will contain the most up-to-date information
			 * about the valid top-levels in the vdev namespace.
			 */
			if (best_txg > max_txg) {
				(void) nvlist_remove(config,
				    ZPOOL_CONFIG_VDEV_CHILDREN,
				    DATA_TYPE_UINT64);
				(void) nvlist_remove(config,
				    ZPOOL_CONFIG_HOLE_ARRAY,
				    DATA_TYPE_UINT64_ARRAY);

				max_txg = best_txg;
				hole_array = NULL;
				holes = 0;
				max_id = 0;
				valid_top_config = B_FALSE;

				if (nvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_VDEV_CHILDREN, &max_id) == 0) {
					verify(nvlist_add_uint64(config,
					    ZPOOL_CONFIG_VDEV_CHILDREN,
					    max_id) == 0);
					valid_top_config = B_TRUE;
				}

				if (nvlist_lookup_uint64_array(tmp,
				    ZPOOL_CONFIG_HOLE_ARRAY, &hole_array,
				    &holes) == 0) {
					verify(nvlist_add_uint64_array(config,
					    ZPOOL_CONFIG_HOLE_ARRAY,
					    hole_array, holes) == 0);
				}
			}

			if (!config_seen) {
				/*
				 * Copy the relevant pieces of data to the pool
				 * configuration:
				 *
				 *	version
				 *	pool guid
				 *	name
				 *	comment (if available)
				 *	pool state
				 *	hostid (if available)
				 *	hostname (if available)
				 */
				uint64_t state, version;
				char *comment = NULL;

				version = fnvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_VERSION);
				fnvlist_add_uint64(config,
				    ZPOOL_CONFIG_VERSION, version);
				guid = fnvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_POOL_GUID);
				fnvlist_add_uint64(config,
				    ZPOOL_CONFIG_POOL_GUID, guid);
				name = fnvlist_lookup_string(tmp,
				    ZPOOL_CONFIG_POOL_NAME);
				fnvlist_add_string(config,
				    ZPOOL_CONFIG_POOL_NAME, name);

				if (nvlist_lookup_string(tmp,
				    ZPOOL_CONFIG_COMMENT, &comment) == 0)
					fnvlist_add_string(config,
					    ZPOOL_CONFIG_COMMENT, comment);

				state = fnvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_POOL_STATE);
				fnvlist_add_uint64(config,
				    ZPOOL_CONFIG_POOL_STATE, state);

				hostid = 0;
				if (nvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_HOSTID, &hostid) == 0) {
					fnvlist_add_uint64(config,
					    ZPOOL_CONFIG_HOSTID, hostid);
					hostname = fnvlist_lookup_string(tmp,
					    ZPOOL_CONFIG_HOSTNAME);
					fnvlist_add_string(config,
					    ZPOOL_CONFIG_HOSTNAME, hostname);
				}

				config_seen = B_TRUE;
			}

			/*
			 * Add this top-level vdev to the child array.
			 */
			verify(nvlist_lookup_nvlist(tmp,
			    ZPOOL_CONFIG_VDEV_TREE, &nvtop) == 0);
			verify(nvlist_lookup_uint64(nvtop, ZPOOL_CONFIG_ID,
			    &id) == 0);

			if (id >= children) {
				nvlist_t **newchild;

				newchild = zfs_alloc(hdl, (id + 1) *
				    sizeof (nvlist_t *));
				if (newchild == NULL)
					goto nomem;

				for (c = 0; c < children; c++)
					newchild[c] = child[c];

				free(child);
				child = newchild;
				children = id + 1;
			}
			if (nvlist_dup(nvtop, &child[id], 0) != 0)
				goto nomem;

		}

		/*
		 * If we have information about all the top-levels then
		 * clean up the nvlist which we've constructed. This
		 * means removing any extraneous devices that are
		 * beyond the valid range or adding devices to the end
		 * of our array which appear to be missing.
		 */
		if (valid_top_config) {
			if (max_id < children) {
				for (c = max_id; c < children; c++)
					nvlist_free(child[c]);
				children = max_id;
			} else if (max_id > children) {
				nvlist_t **newchild;

				newchild = zfs_alloc(hdl, (max_id) *
				    sizeof (nvlist_t *));
				if (newchild == NULL)
					goto nomem;

				for (c = 0; c < children; c++)
					newchild[c] = child[c];

				free(child);
				child = newchild;
				children = max_id;
			}
		}

		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
		    &guid) == 0);

		/*
		 * The vdev namespace may contain holes as a result of
		 * device removal. We must add them back into the vdev
		 * tree before we process any missing devices.
		 */
		if (holes > 0) {
			ASSERT(valid_top_config);

			for (c = 0; c < children; c++) {
				nvlist_t *holey;

				if (child[c] != NULL ||
				    !vdev_is_hole(hole_array, holes, c))
					continue;

				if (nvlist_alloc(&holey, NV_UNIQUE_NAME,
				    0) != 0)
					goto nomem;

				/*
				 * Holes in the namespace are treated as
				 * "hole" top-level vdevs and have a
				 * special flag set on them.
				 */
				if (nvlist_add_string(holey,
				    ZPOOL_CONFIG_TYPE,
				    VDEV_TYPE_HOLE) != 0 ||
				    nvlist_add_uint64(holey,
				    ZPOOL_CONFIG_ID, c) != 0 ||
				    nvlist_add_uint64(holey,
				    ZPOOL_CONFIG_GUID, 0ULL) != 0)
					goto nomem;
				child[c] = holey;
			}
		}

		/*
		 * Look for any missing top-level vdevs.  If this is the case,
		 * create a faked up 'missing' vdev as a placeholder.  We cannot
		 * simply compress the child array, because the kernel performs
		 * certain checks to make sure the vdev IDs match their location
		 * in the configuration.
		 */
		for (c = 0; c < children; c++) {
			if (child[c] == NULL) {
				nvlist_t *missing;
				if (nvlist_alloc(&missing, NV_UNIQUE_NAME,
				    0) != 0)
					goto nomem;
				if (nvlist_add_string(missing,
				    ZPOOL_CONFIG_TYPE,
				    VDEV_TYPE_MISSING) != 0 ||
				    nvlist_add_uint64(missing,
				    ZPOOL_CONFIG_ID, c) != 0 ||
				    nvlist_add_uint64(missing,
				    ZPOOL_CONFIG_GUID, 0ULL) != 0) {
					nvlist_free(missing);
					goto nomem;
				}
				child[c] = missing;
			}
		}

		/*
		 * Put all of this pool's top-level vdevs into a root vdev.
		 */
		if (nvlist_alloc(&nvroot, NV_UNIQUE_NAME, 0) != 0)
			goto nomem;
		if (nvlist_add_string(nvroot, ZPOOL_CONFIG_TYPE,
		    VDEV_TYPE_ROOT) != 0 ||
		    nvlist_add_uint64(nvroot, ZPOOL_CONFIG_ID, 0ULL) != 0 ||
		    nvlist_add_uint64(nvroot, ZPOOL_CONFIG_GUID, guid) != 0 ||
		    nvlist_add_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN,
		    child, children) != 0) {
			nvlist_free(nvroot);
			goto nomem;
		}

		for (c = 0; c < children; c++)
			nvlist_free(child[c]);
		free(child);
		children = 0;
		child = NULL;

		/*
		 * Go through and fix up any paths and/or devids based on our
		 * known list of vdev GUID -> path mappings.
		 */
		if (fix_paths(nvroot, pl->names) != 0) {
			nvlist_free(nvroot);
			goto nomem;
		}

		/*
		 * Add the root vdev to this pool's configuration.
		 */
		if (nvlist_add_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    nvroot) != 0) {
			nvlist_free(nvroot);
			goto nomem;
		}
		nvlist_free(nvroot);

		/*
		 * zdb uses this path to report on active pools that were
		 * imported or created using -R.
		 */
		if (active_ok)
			goto add_pool;

		/*
		 * Determine if this pool is currently active, in which case we
		 * can't actually import it.
		 */
		verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
		    &name) == 0);
		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
		    &guid) == 0);

		if (pool_active(hdl, name, guid, &isactive) != 0)
			goto error;

		if (isactive) {
			nvlist_free(config);
			config = NULL;
			continue;
		}

		if ((nvl = refresh_config(hdl, config)) == NULL) {
			nvlist_free(config);
			config = NULL;
			continue;
		}

		nvlist_free(config);
		config = nvl;

		/*
		 * Go through and update the paths for spares, now that we have
		 * them.
		 */
		verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    &nvroot) == 0);
		if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_SPARES,
		    &spares, &nspares) == 0) {
			for (i = 0; i < nspares; i++) {
				if (fix_paths(spares[i], pl->names) != 0)
					goto nomem;
			}
		}
			
		if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_METASPARES,
			&metaspares, &nmetaspares) == 0) {
			for (i = 0; i < nmetaspares; i++) {
				if (fix_paths(metaspares[i], pl->names) != 0)
					goto nomem;
			}
		}

		if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_LOWSPARES,
		    &lowspares, &nlowspares) == 0) {
			for (i = 0; i < nlowspares; i++) {
				if (fix_paths(lowspares[i], pl->names) != 0)
					goto nomem;
			}
		}

		if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_MIRRORSPARES,
		    &mirrorspares, &nmirrorspares) == 0) {
			for (i = 0; i < nmirrorspares; i++) {
				if (fix_paths(mirrorspares[i], pl->names) != 0)
					goto nomem;
			}
		}
		
		/*
		 * Update the paths for l2cache devices.
		 */
		if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_L2CACHE,
		    &l2cache, &nl2cache) == 0) {
			for (i = 0; i < nl2cache; i++) {
				if (fix_paths(l2cache[i], pl->names) != 0)
					goto nomem;
			}
		}

		/*
		 * Restore the original information read from the actual label.
		 */
		(void) nvlist_remove(config, ZPOOL_CONFIG_HOSTID,
		    DATA_TYPE_UINT64);
		(void) nvlist_remove(config, ZPOOL_CONFIG_HOSTNAME,
		    DATA_TYPE_STRING);
		if (hostid != 0) {
			verify(nvlist_add_uint64(config, ZPOOL_CONFIG_HOSTID,
			    hostid) == 0);
			verify(nvlist_add_string(config, ZPOOL_CONFIG_HOSTNAME,
			    hostname) == 0);
		}

add_pool:
		/*
		 * Add this pool to the list of configs.
		 */
		verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
		    &name) == 0);
		if (nvlist_add_nvlist(ret, name, config) != 0)
			goto nomem;

		nvlist_free(config);
		config = NULL;
	}

	return (ret);

nomem:
	(void) no_memory(hdl);
error:
	nvlist_free(config);
	nvlist_free(ret);
	for (c = 0; c < children; c++)
		nvlist_free(child[c]);
	free(child);

	return (NULL);
}

/*
 * Given a file descriptor, read the label information and return an nvlist
 * describing the configuration, if there is one.  The number of valid
 * labels found will be returned in num_labels when non-NULL.
 */
int
zpool_read_label(int fd, nvlist_t **config, int *num_labels)
{
	struct stat64 statbuf;
	int l, count = 0;
	vdev_label_t *label;
	nvlist_t *expected_config = NULL;
	uint64_t expected_guid = 0, size;

	*config = NULL;

	if (fstat64_blk(fd, &statbuf) == -1)
		return (0);
	size = P2ALIGN_TYPED(statbuf.st_size, sizeof (vdev_label_t), uint64_t);

	if ((label = malloc(sizeof (vdev_label_t))) == NULL)
		return (-1);

	for (l = 0; l < VDEV_LABELS; l++) {
		uint64_t state, guid, txg;

		if (pread64(fd, label, sizeof (vdev_label_t),
		    label_offset(size, l)) != sizeof (vdev_label_t))
			continue;

		if (nvlist_unpack(label->vl_vdev_phys.vp_nvlist,
		    sizeof (label->vl_vdev_phys.vp_nvlist), config, 0) != 0)
			continue;

		if (nvlist_lookup_uint64(*config, ZPOOL_CONFIG_GUID,
		    &guid) != 0 || guid == 0) {
			nvlist_free(*config);
			continue;
		}

		if (nvlist_lookup_uint64(*config, ZPOOL_CONFIG_POOL_STATE,
		    &state) != 0 || state > POOL_STATE_LOWSPARE) {
			nvlist_free(*config);
			continue;
		}

		if (state != POOL_STATE_SPARE && state != POOL_STATE_L2CACHE &&
			state != POOL_STATE_METASPARE && state != POOL_STATE_MIRRORSPARE &&
			state != POOL_STATE_LOWSPARE &&
		    (nvlist_lookup_uint64(*config, ZPOOL_CONFIG_POOL_TXG,
		    &txg) != 0 || txg == 0)) {
			nvlist_free(*config);
			continue;
		}

		if (expected_guid) {
			if (expected_guid == guid)
				count++;

			nvlist_free(*config);
		} else {
			expected_config = *config;
			expected_guid = guid;
			count++;
		}
	}

	if (num_labels != NULL)
		*num_labels = count;

	free(label);
	*config = expected_config;

	return (0);
}

/*
 * Given a file descriptor, clear (zero) the label information.  This function
 * is used in the appliance stack as part of the ZFS sysevent module and
 * to implement the "zpool labelclear" command.
 */
int
zpool_clear_label(int fd)
{
	struct stat64 statbuf;
	int l;
	vdev_label_t *label;
	uint64_t size;

	if (fstat64_blk(fd, &statbuf) == -1)
		return (0);
	size = P2ALIGN_TYPED(statbuf.st_size, sizeof (vdev_label_t), uint64_t);

	if ((label = calloc(sizeof (vdev_label_t), 1)) == NULL)
		return (-1);

	for (l = 0; l < VDEV_LABELS; l++) {
		if (pwrite64(fd, label, sizeof (vdev_label_t),
		    label_offset(size, l)) != sizeof (vdev_label_t)) {
			free(label);
			return (-1);
		}
	}

	free(label);
	return (0);
}

#ifdef HAVE_LIBBLKID
/*
 * Use libblkid to quickly search for zfs devices
 */
static int
zpool_find_import_blkid(libzfs_handle_t *hdl, pool_list_t *pools)
{
	blkid_cache cache;
	blkid_dev_iterate iter;
	blkid_dev dev;
	int err;

	err = blkid_get_cache(&cache, NULL);
	if (err != 0) {
		(void) zfs_error_fmt(hdl, EZFS_BADCACHE,
		    dgettext(TEXT_DOMAIN, "blkid_get_cache() %d"), err);
		goto err_blkid1;
	}

	err = blkid_probe_all(cache);
	if (err != 0) {
		(void) zfs_error_fmt(hdl, EZFS_BADCACHE,
		    dgettext(TEXT_DOMAIN, "blkid_probe_all() %d"), err);
		goto err_blkid2;
	}

	iter = blkid_dev_iterate_begin(cache);
	if (iter == NULL) {
		(void) zfs_error_fmt(hdl, EZFS_BADCACHE,
		    dgettext(TEXT_DOMAIN, "blkid_dev_iterate_begin()"));
		goto err_blkid2;
	}

	err = blkid_dev_set_search(iter, "TYPE", "zfs_member");
	if (err != 0) {
		(void) zfs_error_fmt(hdl, EZFS_BADCACHE,
		    dgettext(TEXT_DOMAIN, "blkid_dev_set_search() %d"), err);
		goto err_blkid3;
	}

	while (blkid_dev_next(iter, &dev) == 0) {
		nvlist_t *label;
		char *devname;
		int fd, num_labels;

		devname = (char *) blkid_dev_devname(dev);
		if ((fd = open64(devname, O_RDONLY)) < 0)
			continue;

		err = zpool_read_label(fd, &label, &num_labels);
		(void) close(fd);

		if (err || label == NULL)
			continue;

		add_configs_from_label(hdl, pools, devname, num_labels, label);
	}
	err = 0;

err_blkid3:
	blkid_dev_iterate_end(iter);
err_blkid2:
	blkid_put_cache(cache);
err_blkid1:
	return (err);
}
#endif /* HAVE_LIBBLKID */

static int
scsi_disk_check(const char *name)
{
	char prefix[6] = "scsi-";
	char suffix[7] = "-part1";
	char *begin, *end, *p;

	if (strncmp(name, prefix, 5) != 0)
		return (0);

	begin = name + 5;
	if ((end = strstr(begin, suffix)) == NULL)
		return (0);

	for (p = begin; p < end; p++) {
		if ((*p < '0' || *p > '9') && (*p <'a' || *p > 'f'))
			return (0);
	}

	return (1);
}

char *
zpool_default_import_path[DEFAULT_IMPORT_PATH_SIZE] = {
	"/dev/disk/by-vdev",	/* Custom rules, use first if they exist */
	"/dev/mapper",		/* Use multipath devices before components */
	"/dev/disk/by-uuid",	/* Single unique entry and persistent */
	"/dev/disk/by-id",	/* May be multiple entries and persistent */
	"/dev/disk/by-path",	/* Encodes physical location and persistent */
	"/dev/disk/by-label",	/* Custom persistent labels */
	"/dev"			/* UNSAFE device names will change */
};

/*
 * Given a list of directories to search, find all pools stored on disk.  This
 * includes partial pools which are not available to import.  If no args are
 * given (argc is 0), then the default directory (/dev/dsk) is searched.
 * poolname or guid (but not both) are provided by the caller when trying
 * to import a specific pool.
 */
static nvlist_t *
zpool_find_import_impl(libzfs_handle_t *hdl, importargs_t *iarg)
{
	int i, num_labels, dirs = iarg->paths;
	DIR *dirp = NULL;
	struct dirent64 *dp;
	char path[MAXPATHLEN];
	char *end, **dir = iarg->path;
	size_t pathleft;
	struct stat64 statbuf;
	nvlist_t *ret = NULL, *config;
	int fd;
	pool_list_t pools = { 0 };
	pool_entry_t *pe, *penext;
	vdev_entry_t *ve, *venext;
	config_entry_t *ce, *cenext;
	name_entry_t *ne, *nenext;
	int scsi_disk;
	int reopen_times;

	verify(iarg->poolname == NULL || iarg->guid == 0);

	if (dirs == 0) {
#ifdef HAVE_LIBBLKID
		if (iarg->no_blkid)
			goto dont_use_blkid;
		/* Use libblkid to scan all device for their type */
		if (zpool_find_import_blkid(hdl, &pools) == 0)
			goto skip_scanning;

		(void) zfs_error_fmt(hdl, EZFS_BADCACHE,
		    dgettext(TEXT_DOMAIN, "blkid failure falling back "
		    "to manual probing"));
dont_use_blkid:
#endif /* HAVE_LIBBLKID */

		dir = zpool_default_import_path;
		dirs = DEFAULT_IMPORT_PATH_SIZE;
	}

	/*
	 * Go through and read the label configuration information from every
	 * possible device, organizing the information according to pool GUID
	 * and toplevel GUID.
	 */
	for (i = 0; i < dirs; i++) {
		char *rdsk;
		int dfd;

		/* use realpath to normalize the path */
		if (realpath(dir[i], path) == 0) {

			/* it is safe to skip missing search paths */
			if (errno == ENOENT)
				continue;

			zfs_error_aux(hdl, strerror(errno));
			(void) zfs_error_fmt(hdl, EZFS_BADPATH,
			    dgettext(TEXT_DOMAIN, "cannot open '%s'"), dir[i]);
			goto error;
		}
		end = &path[strlen(path)];
		*end++ = '/';
		*end = 0;
		pathleft = &path[sizeof (path)] - end;

		/*
		 * Using raw devices instead of block devices when we're
		 * reading the labels skips a bunch of slow operations during
		 * close(2) processing, so we replace /dev/dsk with /dev/rdsk.
		 */
		if (strcmp(path, "/dev/dsk/") == 0)
			rdsk = "/dev/rdsk/";
		else
			rdsk = path;

		if ((dfd = open64(rdsk, O_RDONLY)) < 0 ||
		    (dirp = fdopendir(dfd)) == NULL) {
			zfs_error_aux(hdl, strerror(errno));
			(void) zfs_error_fmt(hdl, EZFS_BADPATH,
			    dgettext(TEXT_DOMAIN, "cannot open '%s'"),
			    rdsk);
			goto error;
		}

		/*
		 * This is not MT-safe, but we have no MT consumers of libzfs
		 */
		while ((dp = readdir64(dirp)) != NULL) {
			const char *name = dp->d_name;
			if (name[0] == '.' &&
			    (name[1] == 0 || (name[1] == '.' && name[2] == 0)))
				continue;

			/*
			 * Skip checking devices with well known prefixes:
			 * watchdog - A special close is required to avoid
			 *            triggering it and resetting the system.
			 * fuse     - Fuse control device.
			 * ppp      - Generic PPP driver.
			 * tty*     - Generic serial interface.
			 * vcs*     - Virtual console memory.
			 * parport* - Parallel port interface.
			 * lp*      - Printer interface.
			 * fd*      - Floppy interface.
			 * hpet     - High Precision Event Timer, crashes qemu
			 *            when accessed from a virtual machine.
			 * core     - Symlink to /proc/kcore, causes a crash
			 *            when access from Xen dom0.
			 */
			if ((strncmp(name, "watchdog", 8) == 0) ||
			    (strncmp(name, "fuse", 4) == 0) ||
			    (strncmp(name, "ppp", 3) == 0) ||
			    (strncmp(name, "tty", 3) == 0) ||
			    (strncmp(name, "vcs", 3) == 0) ||
			    (strncmp(name, "parport", 7) == 0) ||
			    (strncmp(name, "lp", 2) == 0) ||
			    (strncmp(name, "fd", 2) == 0) ||
			    (strncmp(name, "hpet", 4) == 0) ||
			    (strncmp(name, "core", 4) == 0))
				continue;

			scsi_disk = scsi_disk_check(name);

			reopen_times = 0;
reopen:
			/*
			 * Ignore failed stats.  We only want regular
			 * files and block devices.
			 */
			if (fstatat64(dfd, name, &statbuf, 0) != 0) {
				if (scsi_disk) {
					syslog(LOG_DEBUG, "%s: scsi-disk %s fstat error %d",
						__func__, name, errno);
					if (reopen_times < 3) {
						reopen_times++;
						sleep(1);
						goto reopen;
					} else {
						syslog(LOG_WARNING, "%s: fstat(%s) error %d",
							__func__, name, errno);
					}
				}
				continue;
			}

			if ( (!S_ISREG(statbuf.st_mode) &&
			    !S_ISBLK(statbuf.st_mode)))
			    continue;

			if ((fd = openat64(dfd, name, O_RDONLY)) < 0) {
				if (scsi_disk) {
					syslog(LOG_DEBUG, "%s: scsi-disk %s open error %d",
						__func__, name, errno);
					if (reopen_times < 3) {
						reopen_times++;
						sleep(1);
						goto reopen;
					} else {
						syslog(LOG_WARNING, "%s: open(%s) error %d",
							__func__, name, errno);
					}
				}
				continue;
			}

			if ((zpool_read_label(fd, &config, &num_labels))) {
				(void) close(fd);
				(void) no_memory(hdl);
				goto error;
			}

			(void) close(fd);

			if (config != NULL) {
				boolean_t matched = B_TRUE;
				char *pname;

				if ((iarg->poolname != NULL) &&
				    (nvlist_lookup_string(config,
				    ZPOOL_CONFIG_POOL_NAME, &pname) == 0)) {

					if (strcmp(iarg->poolname, pname))
						matched = B_FALSE;

				} else if (iarg->guid != 0) {
					uint64_t this_guid;

					matched = nvlist_lookup_uint64(config,
					    ZPOOL_CONFIG_POOL_GUID,
					    &this_guid) == 0 &&
					    iarg->guid == this_guid;
				}
				if (!matched) {
					nvlist_free(config);
					config = NULL;
					continue;
				}
				/* use the non-raw path for the config */
				(void) strlcpy(end, name, pathleft);
				if (add_config(hdl, &pools, path, i+1,
				    num_labels, config))
					goto error;
			}
		}

		(void) closedir(dirp);
		dirp = NULL;
	}

#ifdef HAVE_LIBBLKID
skip_scanning:
#endif
	ret = get_configs(hdl, &pools, iarg->can_be_active);

error:
	for (pe = pools.pools; pe != NULL; pe = penext) {
		penext = pe->pe_next;
		for (ve = pe->pe_vdevs; ve != NULL; ve = venext) {
			venext = ve->ve_next;
			for (ce = ve->ve_configs; ce != NULL; ce = cenext) {
				cenext = ce->ce_next;
				if (ce->ce_config)
					nvlist_free(ce->ce_config);
				free(ce);
			}
			free(ve);
		}
		free(pe);
	}

	for (ne = pools.names; ne != NULL; ne = nenext) {
		nenext = ne->ne_next;
		if (ne->ne_name)
			free(ne->ne_name);
		free(ne);
	}

	if (dirp)
		(void) closedir(dirp);

	return (ret);
}

nvlist_t *
zpool_find_import(libzfs_handle_t *hdl, int argc, char **argv)
{
	importargs_t iarg = { 0 };

	iarg.paths = argc;
	iarg.path = argv;

	return (zpool_find_import_impl(hdl, &iarg));
}

/*
 * Given a cache file, return the contents as a list of importable pools.
 * poolname or guid (but not both) are provided by the caller when trying
 * to import a specific pool.
 */
nvlist_t *
zpool_find_import_cached(libzfs_handle_t *hdl, const char *cachefile,
    char *poolname, uint64_t guid)
{
	char *buf;
	int fd;
	struct stat64 statbuf;
	nvlist_t *raw, *src, *dst;
	nvlist_t *pools;
	nvpair_t *elem;
	char *name;
	uint64_t this_guid;
	boolean_t active;

	verify(poolname == NULL || guid == 0);

	if ((fd = open(cachefile, O_RDONLY)) < 0) {
		zfs_error_aux(hdl, "%s", strerror(errno));
		(void) zfs_error(hdl, EZFS_BADCACHE,
		    dgettext(TEXT_DOMAIN, "failed to open cache file"));
		return (NULL);
	}

	if (fstat64(fd, &statbuf) != 0) {
		zfs_error_aux(hdl, "%s", strerror(errno));
		(void) close(fd);
		(void) zfs_error(hdl, EZFS_BADCACHE,
		    dgettext(TEXT_DOMAIN, "failed to get size of cache file"));
		return (NULL);
	}

	if ((buf = zfs_alloc(hdl, statbuf.st_size)) == NULL) {
		(void) close(fd);
		return (NULL);
	}

	if (read(fd, buf, statbuf.st_size) != statbuf.st_size) {
		(void) close(fd);
		free(buf);
		(void) zfs_error(hdl, EZFS_BADCACHE,
		    dgettext(TEXT_DOMAIN,
		    "failed to read cache file contents"));
		return (NULL);
	}

	(void) close(fd);

	if (nvlist_unpack(buf, statbuf.st_size, &raw, 0) != 0) {
		free(buf);
		(void) zfs_error(hdl, EZFS_BADCACHE,
		    dgettext(TEXT_DOMAIN,
		    "invalid or corrupt cache file contents"));
		return (NULL);
	}

	free(buf);

	/*
	 * Go through and get the current state of the pools and refresh their
	 * state.
	 */
	if (nvlist_alloc(&pools, 0, 0) != 0) {
		(void) no_memory(hdl);
		nvlist_free(raw);
		return (NULL);
	}

	elem = NULL;
	while ((elem = nvlist_next_nvpair(raw, elem)) != NULL) {
		src = fnvpair_value_nvlist(elem);

		name = fnvlist_lookup_string(src, ZPOOL_CONFIG_POOL_NAME);
		if (poolname != NULL && strcmp(poolname, name) != 0)
			continue;

		this_guid = fnvlist_lookup_uint64(src, ZPOOL_CONFIG_POOL_GUID);
		if (guid != 0 && guid != this_guid)
			continue;

		if (pool_active(hdl, name, this_guid, &active) != 0) {
			nvlist_free(raw);
			nvlist_free(pools);
			return (NULL);
		}

		if (active)
			continue;

		if ((dst = refresh_config(hdl, src)) == NULL) {
			nvlist_free(raw);
			nvlist_free(pools);
			return (NULL);
		}

		if (nvlist_add_nvlist(pools, nvpair_name(elem), dst) != 0) {
			(void) no_memory(hdl);
			nvlist_free(dst);
			nvlist_free(raw);
			nvlist_free(pools);
			return (NULL);
		}
		nvlist_free(dst);
	}

	nvlist_free(raw);
	return (pools);
}

static int
name_or_guid_exists(zpool_handle_t *zhp, void *data)
{
	importargs_t *import = data;
	int found = 0;

	if (import->poolname != NULL) {
		char *pool_name;

		verify(nvlist_lookup_string(zhp->zpool_config,
		    ZPOOL_CONFIG_POOL_NAME, &pool_name) == 0);
		if (strcmp(pool_name, import->poolname) == 0)
			found = 1;
	} else {
		uint64_t pool_guid;

		verify(nvlist_lookup_uint64(zhp->zpool_config,
		    ZPOOL_CONFIG_POOL_GUID, &pool_guid) == 0);
		if (pool_guid == import->guid)
			found = 1;
	}

	zpool_close(zhp);
	return (found);
}

static nvlist_t *
zpool_find_import_switched(
	libzfs_handle_t *hdl, char *poolname, uint32_t remote_hostid)
{
	nvlist_t *raw,*src,*dst;
	nvlist_t *pools;
	nvpair_t *elem;
	char *name;
	uint64_t this_guid;
	boolean_t active;
	uint64_t host_id = 0;

	host_id = get_system_hostid();

	raw = get_switched_config(hdl, poolname, remote_hostid);
	if (raw == NULL ) {
		syslog(LOG_WARNING, "get switchd config failed, poolname:%s\n", poolname);
		return (NULL);
	}

	/*
	 * Go through and get the current state of the pools and refresh their
	 * state.
	 */
	if (nvlist_alloc(&pools, NV_UNIQUE_NAME, 0) != 0) {
		(void) no_memory(hdl);
		nvlist_free(raw);
		return (NULL);
	}

	elem = NULL;
	while ((elem = nvlist_next_nvpair(raw, elem)) != NULL) {
		verify(nvpair_value_nvlist(elem, &src) == 0);

		verify(nvlist_lookup_string(src, ZPOOL_CONFIG_POOL_NAME,
		    &name) == 0);
		if (poolname != NULL && strcmp(poolname, name) != 0)
			continue;

		verify(nvlist_lookup_uint64(src, ZPOOL_CONFIG_POOL_GUID,
		    &this_guid) == 0);
		if (pool_active(hdl, name, this_guid, &active) != 0) {
			nvlist_free(raw);
			nvlist_free(pools);
			syslog(LOG_ERR, "pool active failed ");
			return (NULL);
		}
		if (active) {
			continue;
		}

		if ((dst = refresh_config(hdl, src)) == NULL) {
			nvlist_free(raw);
			nvlist_free(pools);
			syslog(LOG_ERR, "refresh config failed");
			return (NULL);
		}

		if (nvlist_add_nvlist(pools, nvpair_name(elem), dst) != 0) {
			(void) no_memory(hdl);
			nvlist_free(dst);
			nvlist_free(raw);
			nvlist_free(pools);
			syslog(LOG_ERR, "add pools failed");
			return (NULL);
		}
		nvlist_free(dst);
	}
	nvlist_free(raw);
	return (pools);
}

static nvlist_t *
zpool_filter_pools(nvlist_t *pools)
{
	uint64_t hostid;
	nvlist_t *config, *nvroot;
	nvpair_t *elem;
	zpool_stamp_t stamp;
	char *name;
	nvlist_t *ret = NULL;
	int no_pool = 1;

	hostid = get_system_hostid();

	verify(nvlist_alloc(&ret, NV_UNIQUE_NAME, 0) == 0);
	elem = NULL;
	while ((elem = nvlist_next_nvpair(pools, elem)) != NULL) {
		verify(nvpair_value_nvlist(elem, &config) == 0);
		if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, &nvroot) != 0)
			continue;
		if (nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, &name) != 0)
			continue;
		if (zpool_read_stamp(nvroot, &stamp) != 0)
			continue;
		if (stamp.para.pool_current_owener == hostid) {
			verify(nvlist_add_nvlist(ret, name, config) == 0);
			no_pool = 0;
		}
	}

	if (no_pool) {
		nvlist_free(ret);
		ret = NULL;
	}
	nvlist_free(pools);
	return (ret);
}

nvlist_t *
zpool_search_import(libzfs_handle_t *hdl, importargs_t *import)
{
	nvlist_t *pools;

	verify(import->poolname == NULL || import->guid == 0);

	if (import->unique)
		import->exists = zpool_iter(hdl, name_or_guid_exists, import);

	if (import->cachefile != NULL)
		pools = zpool_find_import_cached(hdl, import->cachefile,
		    import->poolname, import->guid);
	else if (import->cluster_switch)
		pools = zpool_find_import_switched(hdl, import->poolname,
			import->remote_hostid);
	else
		pools = zpool_find_import_impl(hdl, import);

	if (import->cluster_ignore)
		return (pools);
	return (zpool_filter_pools(pools));
}

boolean_t
find_guid(nvlist_t *nv, uint64_t guid)
{
	uint64_t tmp;
	nvlist_t **child;
	uint_t c, children;

	verify(nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &tmp) == 0);
	if (tmp == guid)
		return (B_TRUE);

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++)
			if (find_guid(child[c], guid))
				return (B_TRUE);
	}

	return (B_FALSE);
}

typedef struct aux_cbdata {
	const char	*cb_type;
	uint64_t	cb_guid;
	zpool_handle_t	*cb_zhp;
} aux_cbdata_t;

static int
find_aux(zpool_handle_t *zhp, void *data)
{
	aux_cbdata_t *cbp = data;
	nvlist_t **list;
	uint_t i, count;
	uint64_t guid;
	nvlist_t *nvroot;

	verify(nvlist_lookup_nvlist(zhp->zpool_config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) == 0);

	if (nvlist_lookup_nvlist_array(nvroot, cbp->cb_type,
	    &list, &count) == 0) {
		for (i = 0; i < count; i++) {
			verify(nvlist_lookup_uint64(list[i],
			    ZPOOL_CONFIG_GUID, &guid) == 0);
			if (guid == cbp->cb_guid) {
				cbp->cb_zhp = zhp;
				return (1);
			}
		}
	}

	zpool_close(zhp);
	return (0);
}

/*
 * Determines if the pool is in use.  If so, it returns true and the state of
 * the pool as well as the name of the pool.  Both strings are allocated and
 * must be freed by the caller.
 */
int
zpool_in_use(libzfs_handle_t *hdl, int fd, pool_state_t *state, char **namestr,
    boolean_t *inuse)
{
	nvlist_t *config;
	char *name;
	boolean_t ret;
	uint64_t guid, vdev_guid;
	zpool_handle_t *zhp;
	nvlist_t *pool_config;
	uint64_t stateval, isspare;
	aux_cbdata_t cb = { 0 };
	boolean_t isactive;

	*inuse = B_FALSE;

	if (zpool_read_label(fd, &config, NULL) != 0) {
		(void) no_memory(hdl);
		return (-1);
	}

	if (config == NULL)
		return (0);

	verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
	    &stateval) == 0);
	verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_GUID,
	    &vdev_guid) == 0);

	if (stateval != POOL_STATE_SPARE && stateval != POOL_STATE_METASPARE &&
		stateval != POOL_STATE_MIRRORSPARE && stateval != POOL_STATE_LOWSPARE &&
		stateval != POOL_STATE_L2CACHE) {
		verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
		    &name) == 0);
		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
		    &guid) == 0);
	}

	switch (stateval) {
	case POOL_STATE_EXPORTED:
		/*
		 * A pool with an exported state may in fact be imported
		 * read-only, so check the in-core state to see if it's
		 * active and imported read-only.  If it is, set
		 * its state to active.
		 */
		if (pool_active(hdl, name, guid, &isactive) == 0 && isactive &&
		    (zhp = zpool_open_canfail(hdl, name)) != NULL) {
			if (zpool_get_prop_int(zhp, ZPOOL_PROP_READONLY, NULL))
				stateval = POOL_STATE_ACTIVE;

			/*
			 * All we needed the zpool handle for is the
			 * readonly prop check.
			 */
			zpool_close(zhp);
		}

		ret = B_TRUE;
		break;

	case POOL_STATE_ACTIVE:
		/*
		 * For an active pool, we have to determine if it's really part
		 * of a currently active pool (in which case the pool will exist
		 * and the guid will be the same), or whether it's part of an
		 * active pool that was disconnected without being explicitly
		 * exported.
		 */
		if (pool_active(hdl, name, guid, &isactive) != 0) {
			nvlist_free(config);
			return (-1);
		}

		if (isactive) {
			/*
			 * Because the device may have been removed while
			 * offlined, we only report it as active if the vdev is
			 * still present in the config.  Otherwise, pretend like
			 * it's not in use.
			 */
			if ((zhp = zpool_open_canfail(hdl, name)) != NULL &&
			    (pool_config = zpool_get_config(zhp, NULL))
			    != NULL) {
				nvlist_t *nvroot;

				verify(nvlist_lookup_nvlist(pool_config,
				    ZPOOL_CONFIG_VDEV_TREE, &nvroot) == 0);
				ret = find_guid(nvroot, vdev_guid);
			} else {
				ret = B_FALSE;
			}

			/*
			 * If this is an active spare within another pool, we
			 * treat it like an unused hot spare.  This allows the
			 * user to create a pool with a hot spare that currently
			 * in use within another pool.  Since we return B_TRUE,
			 * libdiskmgt will continue to prevent generic consumers
			 * from using the device.
			 */
			if (ret && nvlist_lookup_uint64(config,
			    ZPOOL_CONFIG_IS_SPARE, &isspare) == 0 && isspare)
				stateval = POOL_STATE_SPARE;

			if (zhp != NULL)
				zpool_close(zhp);
		} else {
			stateval = POOL_STATE_POTENTIALLY_ACTIVE;
			ret = B_TRUE;
		}
		break;

	case POOL_STATE_SPARE:
		/*
		 * For a hot spare, it can be either definitively in use, or
		 * potentially active.  To determine if it's in use, we iterate
		 * over all pools in the system and search for one with a spare
		 * with a matching guid.
		 *
		 * Due to the shared nature of spares, we don't actually report
		 * the potentially active case as in use.  This means the user
		 * can freely create pools on the hot spares of exported pools,
		 * but to do otherwise makes the resulting code complicated, and
		 * we end up having to deal with this case anyway.
		 */
		cb.cb_zhp = NULL;
		cb.cb_guid = vdev_guid;
		cb.cb_type = ZPOOL_CONFIG_SPARES;
		if (zpool_iter(hdl, find_aux, &cb) == 1) {
			name = (char *)zpool_get_name(cb.cb_zhp);
			ret = TRUE;
		} else {
			ret = FALSE;
		}
		break;

	case POOL_STATE_L2CACHE:

		/*
		 * Check if any pool is currently using this l2cache device.
		 */
		cb.cb_zhp = NULL;
		cb.cb_guid = vdev_guid;
		cb.cb_type = ZPOOL_CONFIG_L2CACHE;
		if (zpool_iter(hdl, find_aux, &cb) == 1) {
			name = (char *)zpool_get_name(cb.cb_zhp);
			ret = TRUE;
		} else {
			ret = FALSE;
		}
		break;

	case POOL_STATE_METASPARE:
	
		cb.cb_zhp = NULL;
		cb.cb_guid = vdev_guid;
		cb.cb_type = ZPOOL_CONFIG_METASPARES;
		if (zpool_iter(hdl, find_aux, &cb) == 1) {
			name = (char *)zpool_get_name(cb.cb_zhp);
			ret = TRUE;
		} else {
			ret = FALSE;
		}
		break;

	case POOL_STATE_LOWSPARE:
	
		cb.cb_zhp = NULL;
		cb.cb_guid = vdev_guid;
		cb.cb_type = ZPOOL_CONFIG_LOWSPARES;
		if (zpool_iter(hdl, find_aux, &cb) == 1) {
			name = (char *)zpool_get_name(cb.cb_zhp);
			ret = TRUE;
		} else {
			ret = FALSE;
		}
		break;

	case POOL_STATE_MIRRORSPARE:

		cb.cb_zhp = NULL;
		cb.cb_guid = vdev_guid;
		cb.cb_type = ZPOOL_CONFIG_MIRRORSPARES;
		if (zpool_iter(hdl, find_aux, &cb) == 1) {
			name = (char *)zpool_get_name(cb.cb_zhp);
			ret = TRUE;
		} else {
			ret = FALSE;
		}
		break;

	default:
		ret = B_FALSE;
	}


	if (ret) {
		if ((*namestr = zfs_strdup(hdl, name)) == NULL) {
			if (cb.cb_zhp)
				zpool_close(cb.cb_zhp);
			nvlist_free(config);
			return (-1);
		}
		*state = (pool_state_t)stateval;
	}

	if (cb.cb_zhp)
		zpool_close(cb.cb_zhp);

	nvlist_free(config);
	*inuse = ret;
	return (0);
}

#define	ZPOOL_STAMP_SIZE	(VDEV_PAD_SIZE / 2)

static uint64_t
used_index_offset(uint64_t size, int l)
{
	verify(P2PHASE_TYPED(size, sizeof (vdev_use_index_t), uint64_t) == 0);
	return (l * sizeof (vdev_label_t) + (l < VDEV_LABELS / 2 ?
	    0 : size - VDEV_LABELS * sizeof (vdev_label_t)) + ZPOOL_STAMP_SIZE);
}

int
get_disk_userd_offset(int disk_fd, uint64_t *offset)
{
	uint64_t size;
	struct stat64 statbuf;
	/*struct vtoc vtoc_info;*/
	uint64_t tmp_offset  = 0;
	if (fstat64(disk_fd, &statbuf) == -1)
		return (1);
	size = P2ALIGN_TYPED(statbuf.st_size, sizeof (vdev_use_index_t), uint64_t);
#if	0
	if (read_vtoc(disk_fd, &vtoc_info) >= 0) {
			return (1);
	}
#endif
	tmp_offset = used_index_offset(size, VDEV_STAMP_LABEL_NO);
	*offset = tmp_offset;
	return (0);
}

/* 
 * description:
 *         read quantum's index
 * input:
 *         pool_root: the pool want to read
 *         index: the quantum's index, output
 *         nquantum: the num of quantums in the pool, maybe less than nquantum
 * return:
 *         real num of quantums in the pool
 */
uint64_t
zpool_read_used(nvlist_t *pool_root, spa_quantum_index_t *index,
	uint64_t nquantum)
{
	char *path;
	int fd, ret = 0;
	nvlist_t **child;
	uint_t i;
	uint_t children = 0;
	uint64_t quantum;
	uint64_t real_nquantum = 0;
	uint64_t tmp_nquantum = 0;
	char tmp_path[1024];
	spa_quantum_index_t *pindex = index;
	char *type;

	if ((nquantum == 0) || (index == NULL) || (pool_root == NULL))
		return (0);
	verify(nvlist_lookup_nvlist_array(pool_root, ZPOOL_CONFIG_CHILDREN,
		&child, &children) == 0);
	for (i = 0; i < children; i ++) {
		nvlist_t **tmp_child;
		uint_t tmp_children = 0;
		uint64_t used_offset = 0;
		vdev_use_index_t used_buf;
		
		if (nvlist_lookup_nvlist_array(child[i], ZPOOL_CONFIG_CHILDREN,
			&tmp_child, &tmp_children) == 0) {
			tmp_nquantum = zpool_read_used(child[i], pindex,
				nquantum-real_nquantum);
			pindex += tmp_nquantum;
			real_nquantum += tmp_nquantum;
			if (real_nquantum == nquantum)
				break;
		} else {
			verify(nvlist_lookup_string(child[i], ZPOOL_CONFIG_TYPE, 
				&type) == 0);
			ret = nvlist_lookup_string(child[i], ZPOOL_CONFIG_PATH, &path);
			if (ret != 0) {
				syslog(LOG_ERR, "pool get config path failed");
				continue;
			}
			ret = nvlist_lookup_uint64(child[i], ZPOOL_CONFIG_QUANTUM_DEV, &quantum);
			if (ret != 0 || quantum == 0)
				continue;
#if	0
			if (strncmp(path, "/dev/dsk/", 9) == 0)
				path += 9;
			sprintf(tmp_path, "/dev/rdsk/%s", path);
#else
			strcpy(tmp_path, path);
			syslog(LOG_WARNING, "zpool_read_used: path=%s", tmp_path);
#endif
			fd = open(tmp_path, O_RDONLY|O_NDELAY);
			if (fd > 0) {
				if (get_disk_userd_offset(fd, &used_offset) != 0) {
					syslog(LOG_ERR, "get index used offset failed");
					close(fd);
					break;
				}
				if (pread(fd, &used_buf, sizeof(vdev_use_index_t), used_offset)
					== sizeof(vdev_use_index_t)) {
					close(fd);
					pindex->index = used_buf.index;
					pindex->dev_name = path;
					pindex++ ;
					real_nquantum++ ;

					if (real_nquantum == nquantum)
						break;
				} else {
					close(fd);
					break;
				}
			}
		}
	}
	return (real_nquantum);
}

boolean_t
zpool_used_index_changed(spa_quantum_index_t *last_index, uint64_t nquantum,
	spa_quantum_index_t *current_index, uint64_t *read_nquantum)
{
	uint64_t used_offset = 0;
	vdev_use_index_t used_buf;
	char path[MAXPATHLEN];
	int fd, i;
	if (read_nquantum != NULL)
		*read_nquantum = 0;
	if ((nquantum == 0) || (last_index == NULL))
		return (B_FALSE);
	for (i = 0; i < nquantum; i++) {
		if (read_nquantum != NULL)
			(*read_nquantum)++;
		if (current_index != NULL) {
			current_index[i].index = 0;
			current_index[i].dev_name = last_index[i].dev_name;
		}
		if (last_index[i].dev_name != NULL) {
			/*sprintf(path, "/dev/rdsk/%s", last_index[i].dev_name);*/
			strcpy(path, last_index[i].dev_name);
			syslog(LOG_WARNING, "zpool_used_index_changed: path=%s", path);
			fd = open(path, O_RDONLY|O_NDELAY);
			if (fd > 0) {
				if (get_disk_userd_offset(fd, &used_offset) != 0) {
					syslog(LOG_ERR, "get index used offset failed");
					close(fd);
					continue;
				}
				if (pread(fd, &used_buf, sizeof(vdev_use_index_t), used_offset)
					== sizeof(vdev_use_index_t)) {
					close(fd);
					if (current_index != NULL)
						current_index[i].index = used_buf.index;
					if (used_buf.index != last_index[i].index)
						return (B_TRUE);
				} else {
					close(fd);
					continue;
				}
			}
		}
	}

	return (B_FALSE);
}

int
zpool_remove_partner(libzfs_handle_t *hdl, char *name, uint32_t remote_hostid)
{
	zfs_cmd_t zc = {"\0"};
	int err;
	if (name != NULL) {
		strcpy(zc.zc_name, name);
	} else {
		zc.zc_name[0] = '\0';
	}
	zc.zc_perm_action = remote_hostid;
	zc.zc_cookie = ZFS_HBX_REMOVE_PARTNER_POOL;
	err = ioctl(hdl->libzfs_fd, ZFS_IOC_HBX, &zc);
	return (err);
}

int zpool_cluster_set_disks(libzfs_handle_t *hdl, char *pool_name,
	uint64_t cid, uint64_t rid, uint64_t progress, boolean_t cluster_switch,
	uint32_t remote_hostid)
{
	uint64_t host_id = 0;
	char *pname;
	nvlist_t *pools, *config, *nvroot;
	importargs_t iarg = { 0 };
	nvpair_t *elem = NULL;
	zpool_stamp_t *stamp;

	host_id = get_system_hostid();
#if 0
	if (host_id != 1 && host_id != 2) {
		syslog(LOG_ERR, "host id is not 1 or 2, cluster set disks failed");
		if (progress == ZPOOL_NO_PROGRESS || progress == ZPOOL_ON_PROGRESS)
			return (-1);
	}
#endif
	if (host_id > 255) {
		syslog(LOG_ERR, "host id(%"PRId64") is invalid, cluster set disks failed", host_id);
		if (progress == ZPOOL_NO_PROGRESS || progress == ZPOOL_ON_PROGRESS)
			return (-1);
	}
	if (!cluster_switch)
		pools = zpool_find_import_impl(hdl, &iarg);
	else
		pools = get_switched_config(hdl, "", remote_hostid);
	if (pools == NULL) {
		if (nvlist_alloc(&pools, 0, 0) != 0) {
			syslog(LOG_ERR, "scan  pools, alloc nvlist failed");
			return (-1);
		}
	}
	if (!cluster_switch)
		(void) zpool_iter(hdl, add_mounted_pools, pools);
	
	/* Secondly, we write label info */
	stamp = malloc(sizeof(zpool_stamp_t));
	if (stamp == NULL) {
		syslog(LOG_ERR, "cluste set disk malloc failed");
		nvlist_free(pools);
		return (-1);
	}
	
	bzero(stamp, sizeof(zpool_stamp_t));
	while ((elem = nvlist_next_nvpair(pools, elem)) != NULL) {
		verify(nvpair_value_nvlist(elem, &config) == 0);
		verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
		    &pname) == 0);
		if (pool_name == NULL || (pool_name != NULL && strcmp(pname,
			pool_name) == 0)) {
        	verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
            	    &nvroot) == 0);
        	if (zpool_read_stamp(nvroot, stamp) != 0)
				continue;
			if (rid < 256) {
				stamp->para.pool_real_owener = rid;
			}

			if (cid < 256) {
				stamp->para.pool_current_owener = cid;
			}

			if (progress == ZPOOL_NO_PROGRESS || progress == ZPOOL_ON_PROGRESS) {
				stamp->para.pool_progress[(host_id + 1) % 2] = progress;
			}
			zpool_write_stamp(nvroot, stamp, SPA_NUM_OF_QUANTUM);
		}
	}

	nvlist_free(pools);
	free(stamp);
	
	return (0);
}

uint64_t
get_partner_id(libzfs_handle_t *hdl, uint64_t rid)
{
	zfs_cmd_t zc = {"\0"};
	int ret;

	if (rid != 0) {
		return (rid);
	}
	zc.zc_cookie = ZFS_HBX_GET_FAILOVER_HOST;
	zc.zc_perm_action = rid;
	zc.zc_guid = 0;
	ret = zfs_ioctl(hdl, ZFS_IOC_HBX, &zc);
	if (ret != 0) {
		syslog(LOG_WARNING, "%s: get hostid where to release failed",
			__func__);
	} else {
		syslog(LOG_NOTICE, "%s: hostid=%d", __func__, (uint32_t)zc.zc_guid);
	}
	return (zc.zc_guid);
}
