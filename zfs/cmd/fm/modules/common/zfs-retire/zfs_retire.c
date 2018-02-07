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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The ZFS retire agent is responsible for managing hot spares across all pools.
 * When we see a device fault or a device removal, we try to open the associated
 * pool and look for any hot spares.  We iterate over any available hot spares
 * and attempt a 'zpool replace' for each one.
 *
 * For vdevs diagnosed as faulty, the agent is also responsible for proactively
 * marking the vdev FAULTY (for I/O errors) or DEGRADED (for checksum errors).
 */

//#include <zfs.h>
//#include <sys/fm/fs/zfs.h>
#include <libzfs.h>
#include <libtopo.h>
//#include <fm/topo_hc.h>
//#include <fm/topo_list.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

//#include <sys/libdevid.h>
//#include <ctype.h>
//#include <libautoslice.h>

#include "../../../fmd/common/fmd_api.h"

#include "make_vdev.h"

#define	DISK_LED_CMD	"/usr/local/sbin/disk led -d %s -o fault &"
#define	DISK_LED_NORMAL_CMD	"/usr/local/sbin/disk led -d %s -o normal &"
#define ZPOOL_SCRUB_POOL	"/usr/local/sbin/zpool scrub %s &"
#define	DISK_LED_LPATH	"/dev/rdsk/%s"
#define	MAXDEVPATHLEN		128
#define	PARTATIONMAX		10

#define	FM_EREPORT_PAYLOAD_ZFS_POOL_GUID	"pool_guid"
#define	FM_EREPORT_PAYLOAD_ZFS_VDEV_GUID	"vdev_guid"
#define	ZPOOL_CONFIG_METADATA_DEV	"metadev"
#define	ZPOOL_CONFIG_IS_METASPARE	"is_metaspare"
#define	ZPOOL_CONFIG_WHOLE_DISK		"whole_disk"
#define	ZPOOL_CONFIG_ROTATION_RATE	"rotation_rate"
#define	ZPOOL_CONFIG_RESILVERING	"resilvering"
#define	ZPOOL_CONFIG_MIRRORSPARES	"mirrorspares"
#define	ZPOOL_CONFIG_METASPARES		"metaspares"

#define	FM_LIST_EVENT			"list"
#define	FM_LIST_RESOLVED_CLASS		FM_LIST_EVENT ".resolved"
#define	FM_SUSPECT_UUID			"uuid"
#define	FM_FMRI_ZFS_VDEV		"vdev"
#define	FM_FMRI_ZFS_POOL		"pool"
#define	FM_FAULT_RESOURCE		"resource"
#define	FM_FMRI_DEV_ID			"devid"
#define	FM_FMRI_SCHEME_DEV		"dev"

#define	FM_FMRI_SCHEME_HC		"hc"
#define	FM_FMRI_LEGACY_HC_PREFIX	FM_FMRI_SCHEME_HC":///" \
    FM_FMRI_LEGACY_HC"="

#define	FM_FAULT_ASRU			"asru"
#define	FM_SUSPECT_RETIRE		"retire"
#define	FM_SUSPECT_FAULT_LIST		"fault-list"
#define	FM_FMRI_SCHEME			"scheme"
#define	FM_FMRI_SCHEME_ZFS		"zfs"

#define	FM_LIST_REPAIRED_CLASS		FM_LIST_EVENT ".repaired"
#define	FM_VERSION			"version"
#define	ZFS_SCHEME_VERSION0		0

#if 0
extern int	devid_str_compare(char *devid1_str, char *devid2_str);
extern int auto_change_partition(char *disk_name, int partition_id, uint64_t partition_size);
#endif

xmlDocPtr zfsled_doc;
xmlNodePtr zfsled_root_node;

typedef struct zfs_retire_repaired {
	struct zfs_retire_repaired	*zrr_next;
	uint64_t			zrr_pool;
	uint64_t			zrr_vdev;
} zfs_retire_repaired_t;

typedef struct zfs_retire_data {
	libzfs_handle_t			*zrd_hdl;
	zfs_retire_repaired_t		*zrd_repaired;
	char *compare_path;
	int flag;
} zfs_retire_data_t;

static void
zfs_retire_clear_data(fmd_hdl_t *hdl, zfs_retire_data_t *zdp)
{
	zfs_retire_repaired_t *zrp;

	while ((zrp = zdp->zrd_repaired) != NULL) {
		zdp->zrd_repaired = zrp->zrr_next;
		fmd_hdl_free(hdl, zrp, sizeof (zfs_retire_repaired_t));
	}
}

/*
 * Find a pool with a matching GUID.
 */
typedef struct find_cbdata {
	uint64_t	cb_guid;
	const char	*cb_devid;
	const char	*cb_fru;
	zpool_handle_t	*cb_zhp;
	nvlist_t	*cb_vdev;
} find_cbdata_t;

static int
find_pool(zpool_handle_t *zhp, void *data)
{
	find_cbdata_t *cbp = data;

	if (cbp->cb_guid ==
	    zpool_get_prop_int(zhp, ZPOOL_PROP_GUID, NULL)) {
		cbp->cb_zhp = zhp;
		return (1);
	}

	zpool_close(zhp);
	return (0);
}

/*
 * Find out that if the device is replacing.
 */
static nvlist_t *
is_replacing_dev(nvlist_t *nv, const char *dev_path, int *is_replacing)
{
	nvlist_t **child;
	uint_t c, children;
	nvlist_t *ret;
	char *vdev_path;
	char *type;
	int tmp_is_replacing = 0;

	if (dev_path == NULL) {

	} else {
		/*  
		 * because vdev's fru=0, so we use vdev's devid
		 * to find the disk that will be failed.
		 */
			
		if (nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &vdev_path) == 0 &&
			/*devid_str_compare(vdev_path, (char *)dev_path) == 0*/
			strcmp(vdev_path, (char *)dev_path) == 0)
			return (nv);
	} 

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0)
		return (NULL);

	for (c = 0; c < children; c++) {
		tmp_is_replacing = 0;
		nvlist_lookup_string(child[c], ZPOOL_CONFIG_TYPE, &type);
		if ((is_replacing != NULL) && (strcmp(type, VDEV_TYPE_REPLACING) == 0))
			tmp_is_replacing = 1;
			
		if ((ret = is_replacing_dev(child[c], dev_path, is_replacing)) != NULL){
				if ((is_replacing != NULL) && (*is_replacing == 0))
					*is_replacing = tmp_is_replacing;
				return (ret);
		}
	}

	return (NULL);
}

/*
 * Find a vdev within a tree with a device path.
 */
static nvlist_t *
find_vdev_by_path(libzfs_handle_t *zhdl, nvlist_t *nv, const char *dev_path, uint64_t *available_space)
{
	nvlist_t **child;
	uint_t c, children;
	nvlist_t *ret;
	char *vdev_path;
	char *type;
	uint64_t asize = 0;

	if (dev_path == NULL) {

	} else {
		/*  
		 * because vdev's fru=0, so we use vdev's devid
		 * to find the disk that will be failed.
		 */
			
		if (nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &vdev_path) == 0 &&
			/*devid_str_compare(vdev_path, (char *)dev_path) == 0*/
			strcmp(vdev_path, (char *)dev_path) == 0)
			return (nv);
	} 

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0)
		return (NULL);

	for (c = 0; c < children; c++) {
		nvlist_lookup_string(child[c], ZPOOL_CONFIG_TYPE, &type);
		if ((available_space != NULL) && (strcmp(type, VDEV_TYPE_MIRROR) == 0))
			nvlist_lookup_uint64(child[c], ZPOOL_CONFIG_ASIZE, &asize);
			
		if ((ret = find_vdev_by_path(zhdl, child[c], dev_path, available_space)) != NULL){
				if ((available_space != NULL) && (*available_space == 0))
					*available_space = asize;
				return (ret);
		}
	}

	return (NULL);
}

/*
 * Find a vdev within a tree with a matching GUID.
 */
static nvlist_t *
find_vdev(libzfs_handle_t *zhdl, nvlist_t *nv, const char *search_devid,
    uint64_t search_guid)
{
	uint64_t guid;
	nvlist_t **child;
	uint_t c, children;
	nvlist_t *ret;
//	char *devid;

	if (search_devid != NULL) {
		/*  
		 * because vdev's fru=0, so we use vdev's devid
		 * to find the disk that will be failed.
		 */
#if 0
		if (nvlist_lookup_string(nv, ZPOOL_CONFIG_DEVID, &devid) == 0 &&
			devid_str_compare(devid, (char *)search_devid) == 0)
			return (nv);
#endif
	} else {
		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid) == 0 &&
		    guid == search_guid)
			return (nv);
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0)
		return (NULL);

	for (c = 0; c < children; c++) {
		if ((ret = find_vdev(zhdl, child[c], search_devid,
		    search_guid)) != NULL)
			return (ret);
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_L2CACHE,
	    &child, &children) != 0)
		return (NULL);

	for (c = 0; c < children; c++) {
		if ((ret = find_vdev(zhdl, child[c], search_devid,
		    search_guid)) != NULL)
			return (ret);
	}
	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_METASPARES,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			if ((ret = find_vdev(zhdl, child[c], search_devid,
			    search_guid)) != NULL)
				return (ret);
		}
	}

	return (NULL);
}

/*
 * Given a (pool, vdev) GUID pair, find the matching pool and vdev.
 */
static zpool_handle_t *
find_by_guid(libzfs_handle_t *zhdl, uint64_t pool_guid, uint64_t vdev_guid,
    nvlist_t **vdevp)
{
	find_cbdata_t cb;
	zpool_handle_t *zhp;
	nvlist_t *config, *nvroot;

	/*
	 * Find the corresponding pool and make sure the vdev still exists.
	 */
	cb.cb_guid = pool_guid;
	if (zpool_iter(zhdl, find_pool, &cb) != 1)
		return (NULL);

	zhp = cb.cb_zhp;
	config = zpool_get_config(zhp, NULL);
	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) != 0) {
		zpool_close(zhp);
		return (NULL);
	}

	if (vdev_guid != 0) {
		if ((*vdevp = find_vdev(zhdl, nvroot, NULL,
		    vdev_guid)) == NULL) {
			zpool_close(zhp);
			return (NULL);
		}
	}

	return (zhp);
}

static int
search_pool(zpool_handle_t *zhp, void *data)
{
	find_cbdata_t *cbp = data;
	nvlist_t *config;
	nvlist_t *nvroot;

	config = zpool_get_config(zhp, NULL);
	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) != 0) {
		zpool_close(zhp);
		return (0);
	}

	if ((cbp->cb_vdev = find_vdev(zpool_get_handle(zhp), nvroot,
	    cbp->cb_devid, 0)) != NULL) {
		cbp->cb_zhp = zhp;
		return (1);
	}

	zpool_close(zhp);
	return (0);
}

/*
 * Given a devid, find the matching pool and vdev.
 */
static zpool_handle_t *
find_by_devid(libzfs_handle_t *zhdl, const char *devid, nvlist_t **vdevp)
{
	find_cbdata_t cb;

	cb.cb_devid = devid;
	cb.cb_zhp = NULL;
	if (zpool_iter(zhdl, search_pool, &cb) != 1)
		return (NULL);

	*vdevp = cb.cb_vdev;
	return (cb.cb_zhp);
}

static uint64_t
get_spec_slice_size(char *disk_name, int slice_num)
{
	uint64_t	size = 0;

	return (size);
}


/*
 * Given a vdev, attempt to replace it with every known spare until one
 * succeeds.
 */
static void
replace_with_spare(fmd_hdl_t *hdl, zpool_handle_t *zhp, nvlist_t *vdev)
{
	zfs_retire_data_t *zdp = fmd_hdl_getspecific(hdl);
	nvlist_t *config, *nvroot, *replacement;
	nvlist_t **spares, **metaspares, **mirrorspares;
	nvlist_t *ret;
	nvlist_t *root;
	uint_t s, nspares, nmetaspares, nmirrorspares;
	char *dev_name;
	char *dev_path;
	char *mirrorspare_path;
	int	  dev_path_len, mirrorspare_path_len;
	int	  free_partation;
//	int		val;
	uint64_t ismeta = 0;
	uint64_t ismeta_spare = 0;
	uint64_t wholedisk = 1;/* ......   */
	uint64_t disk_type, spare_type;
	uint64_t available_space, spare_space;
	int   is_replacing = 0;
	uint64_t is_resilvering = 0;
	
	config = zpool_get_config(zhp, NULL);
	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) != 0)
		return;
	
	replacement = fmd_nvl_alloc(hdl, FMD_SLEEP);
	(void) nvlist_add_string(replacement, ZPOOL_CONFIG_TYPE,
	    VDEV_TYPE_ROOT);
	dev_name = zpool_vdev_name(NULL, zhp, vdev, B_FALSE);
	
	dev_path = fmd_hdl_zalloc(hdl, MAXDEVPATHLEN, FMD_SLEEP);
	mirrorspare_path = fmd_hdl_zalloc(hdl, MAXDEVPATHLEN, FMD_SLEEP);
	/* if the mirror create with slice, the dev_path has already with (s*)  */
	(void) snprintf(dev_path, MAXDEVPATHLEN, "%s%s", "/dev/dsk/", dev_name);
	dev_path_len = strlen(dev_path);

	syslog(LOG_ERR, "come to auto_replace, dev name:%s", dev_path);
	
	(void)nvlist_lookup_uint64(vdev, ZPOOL_CONFIG_METADATA_DEV, &ismeta);
	if (nvlist_lookup_uint64(vdev, ZPOOL_CONFIG_IS_METASPARE, &ismeta_spare) == 0)
		ismeta |= ismeta_spare; 
	(void)nvlist_lookup_uint64(vdev, ZPOOL_CONFIG_WHOLE_DISK, &wholedisk);
	(void)nvlist_lookup_uint64(vdev, ZPOOL_CONFIG_ROTATION_RATE, &disk_type);
#if 0
	syslog(LOG_ERR, "replace_with_spare: ismeta = %llu, wholedisk = %llu", 
		(long long unsigned int)ismeta, (long long unsigned int)wholedisk);
#endif
	if (!wholedisk) {
		/*
		 * Try to replace each mirrorspare, ending when we successfully
		 * replace it.
		 */
		syslog(LOG_ERR, "start to auto_replace, the err disk: %s", dev_path);
		ret = is_replacing_dev(nvroot, dev_path, &is_replacing);
		if (ret == NULL) {
			syslog(LOG_ERR, "the disk slice %s can not find in nvroot, do nothing", dev_path);
			goto out;
		}

		if (is_replacing) {
			if ((nvlist_lookup_uint64(ret, ZPOOL_CONFIG_RESILVERING,
			    &is_resilvering) == 0) && is_resilvering){
				syslog(LOG_ERR, "the disk %s is in replacing group and work for resilvering someone, "
					"but it is something wrong now, we replacing it", dev_path);
			} else {	
				syslog(LOG_ERR, "the disk slice %s is now replacing, do nothing", dev_path);
				goto out;
			}
		}

		if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_MIRRORSPARES,
			&mirrorspares, &nmirrorspares) != 0) {
			syslog(LOG_ERR, "can not find mirrorspare, do nothing");
			goto out;
		}
		for (s = 0; s < nmirrorspares; s++) {
			char *mirrorspare_name;
			free_partation = PARTATIONMAX;
			available_space = 0;

			if (nvlist_lookup_string(mirrorspares[s], ZPOOL_CONFIG_PATH,
				&mirrorspare_name) != 0)
				continue;
			if (*(mirrorspare_name + strlen(mirrorspare_name) - 2) != 's')
				(void) snprintf(mirrorspare_path, MAXDEVPATHLEN, "%s%s", mirrorspare_name, "s0");
			else
				(void) snprintf(mirrorspare_path, MAXDEVPATHLEN, "%s", mirrorspare_name);

			syslog(LOG_ERR, "name:%s, path:%s", mirrorspare_name, mirrorspare_path);
			mirrorspare_path_len = strlen(mirrorspare_path);

			/*
			 *	check if this spare device is in use !!!!!!!!!!!!
			 */
			*(mirrorspare_path + mirrorspare_path_len - 1) = *(dev_path + dev_path_len - 1);

			ret = find_vdev_by_path(zpool_get_handle(zhp), nvroot, mirrorspare_path, NULL);
			if (ret != NULL) {
				syslog(LOG_ERR, "the disk slice:%s is in use, use the next mirrorspare", mirrorspare_path);
				continue;
			} else {
				free_partation = *(uint8_t *)(mirrorspare_path + mirrorspare_path_len - 1) - 48;
			}

			if (free_partation == PARTATIONMAX) {
				continue;
			}

			syslog(LOG_ERR, "the old dev:%s, the new dev:%s, free_partation:%d", dev_path,
				mirrorspare_path, free_partation);
		
			/* 
			 *  get spare device type:SSD, Quick_Disk or Slow_Disk 
			 *
			 */
			(void)nvlist_lookup_uint64(mirrorspares[s], ZPOOL_CONFIG_ROTATION_RATE, &spare_type);

			/* check the same disk type: SSD Quick_Disk Slow_Disk */
			if (disk_type != spare_type)
				continue;

#if 1		
			ret = find_vdev_by_path(zpool_get_handle(zhp), nvroot, dev_path, &available_space);
			if (ret == NULL) {
				continue;
			}
			spare_space = get_spec_slice_size(mirrorspare_name, free_partation);
#endif				

			if (spare_space == 0) {
#if 0
				val = auto_change_partition(mirrorspare_name, free_partation, ((available_space / 512) + 1));
				if (val != 0){
					syslog(LOG_ERR, "replace_with_spare: get new partition %d failed, val = %d",
						free_partation, val);
					continue;
				}
#endif
			} else if (spare_space < ((available_space / 512) + 1)) {
				syslog(LOG_ERR, "replace_with_spare: the mirrorspace dev:%s has itself's partition %d,"
					" but it is to small", mirrorspare_name, free_partation);
				continue;
			}
				
#if 0
			syslog(LOG_ERR, "replace_with_spare: F, old_disk:%s, new_disk:%s", (strrchr(dev_path, '/') + 1),
				(strrchr(mirrorspare_path, '/') + 1));
#endif
			root = make_vdev(zhp, B_FALSE, B_TRUE, B_FALSE, 1, &mirrorspare_path);
#if 0
			syslog(LOG_ERR, "replace_with_spare: G, old_disk:%s, new_disk:%s", (strrchr(dev_path, '/') + 1),
				(strrchr(mirrorspare_path, '/') + 1));
#endif				
			if (zpool_vdev_attach(zhp, (strrchr(dev_path, '/') + 1), 
				(strrchr(mirrorspare_path, '/') + 1), root, B_TRUE) == 0) {
				syslog(LOG_ERR, "spare %s with %s success.\n", 
					(strrchr(dev_path, '/') + 1), (strrchr(mirrorspare_path, '/') + 1));
				break;
			} else {
				syslog(LOG_ERR, "spare %s with %s failed: %s\n",
					(strrchr(dev_path, '/') + 1), (strrchr(mirrorspare_path, '/') + 1),
					libzfs_error_description(zdp->zrd_hdl));
			}		
			nvlist_free(root);
			root = NULL;
		}
	} else if (ismeta == 0) {
		/*
		 * Find out if there are any hot spares available in the pool.
		 */
		if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_SPARES,
			&spares, &nspares) != 0) {
			goto out;
		}
		for (s = 0; s < nspares; s++) {
			char *spare_name;
			/* using the whole disk */
			if (nvlist_lookup_string(spares[s], ZPOOL_CONFIG_PATH,
				&spare_name) != 0)
				continue;
			
			(void) nvlist_add_nvlist_array(replacement,
			    ZPOOL_CONFIG_CHILDREN, &spares[s], 1);

			if (zpool_vdev_attach(zhp, dev_name, spare_name,
			    replacement, B_TRUE) == 0) {
			    syslog(LOG_ERR, "spare %s with %s success.\n", dev_name, spare_name);
				break;
			} else {
				syslog(LOG_ERR, "spare %s with %s failed: %s\n", dev_name, spare_name,
					libzfs_error_description(zdp->zrd_hdl));
			}
		}
	} else if (ismeta == 1) {
		if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_METASPARES,
			&metaspares, &nmetaspares) != 0) {
			goto out;
		}
		/*
		 * Try to replace each  meta spare, ending when we successfully
		 * replace it.
		 */
		for (s = 0; s < nmetaspares; s++) {
			char *metaspare_name;
			if (nvlist_lookup_string(metaspares[s], ZPOOL_CONFIG_PATH,
			    &metaspare_name) != 0)
				continue;
			(void) nvlist_add_nvlist_array(replacement,
			    ZPOOL_CONFIG_CHILDREN, &metaspares[s], 1);
			if (zpool_vdev_attach(zhp, dev_name, metaspare_name,
			    replacement, B_TRUE) == 0) {
			    syslog(LOG_ERR, "spare %s with %s success.\n", dev_name, metaspare_name);
				break;
			} else {
				syslog(LOG_ERR, "spare %s with %s failed: %s\n", dev_name, metaspare_name,
					libzfs_error_description(zdp->zrd_hdl));
			}
		}
	}

out:
	free(dev_name);
	fmd_hdl_free(hdl, dev_path, MAXDEVPATHLEN);
	fmd_hdl_free(hdl, mirrorspare_path, MAXDEVPATHLEN);
	nvlist_free(replacement);
}

/*
 * Repair this vdev if we had diagnosed a 'fault.fs.zfs.device' and
 * ASRU is now usable.  ZFS has found the device to be present and
 * functioning.
 */
/*ARGSUSED*/
void
zfs_vdev_repair(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	zfs_retire_data_t *zdp = fmd_hdl_getspecific(hdl);
	zfs_retire_repaired_t *zrp;
	uint64_t pool_guid, vdev_guid;
	nvlist_t *asru;

	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_ZFS_POOL_GUID,
	    &pool_guid) != 0 || nvlist_lookup_uint64(nvl,
	    FM_EREPORT_PAYLOAD_ZFS_VDEV_GUID, &vdev_guid) != 0)
		return;

	/*
	 * Before checking the state of the ASRU, go through and see if we've
	 * already made an attempt to repair this ASRU.  This list is cleared
	 * whenever we receive any kind of list event, and is designed to
	 * prevent us from generating a feedback loop when we attempt repairs
	 * against a faulted pool.  The problem is that checking the unusable
	 * state of the ASRU can involve opening the pool, which can post
	 * statechange events but otherwise leave the pool in the faulted
	 * state.  This list allows us to detect when a statechange event is
	 * due to our own request.
	 */
	for (zrp = zdp->zrd_repaired; zrp != NULL; zrp = zrp->zrr_next) {
		if (zrp->zrr_pool == pool_guid &&
		    zrp->zrr_vdev == vdev_guid)
			return;
	}

	asru = fmd_nvl_alloc(hdl, FMD_SLEEP);

	(void) nvlist_add_uint8(asru, FM_VERSION, ZFS_SCHEME_VERSION0);
	(void) nvlist_add_string(asru, FM_FMRI_SCHEME, FM_FMRI_SCHEME_ZFS);
	(void) nvlist_add_uint64(asru, FM_FMRI_ZFS_POOL, pool_guid);
	(void) nvlist_add_uint64(asru, FM_FMRI_ZFS_VDEV, vdev_guid);

	/*
	 * We explicitly check for the unusable state here to make sure we
	 * aren't responding to a transient state change.  As part of opening a
	 * vdev, it's possible to see the 'statechange' event, only to be
	 * followed by a vdev failure later.  If we don't check the current
	 * state of the vdev (or pool) before marking it repaired, then we risk
	 * generating spurious repair events followed immediately by the same
	 * diagnosis.
	 *
	 * This assumes that the ZFS scheme code associated unusable (i.e.
	 * isolated) with its own definition of faulty state.  In the case of a
	 * DEGRADED leaf vdev (due to checksum errors), this is not the case.
	 * This works, however, because the transient state change is not
	 * posted in this case.  This could be made more explicit by not
	 * relying on the scheme's unusable callback and instead directly
	 * checking the vdev state, where we could correctly account for
	 * DEGRADED state.
	 */
	if (!fmd_nvl_fmri_unusable(hdl, asru) && fmd_nvl_fmri_has_fault(hdl,
	    asru, FMD_HAS_FAULT_ASRU, NULL)) {
		topo_hdl_t *thp;
//		char *fmri = NULL;
//		int err;

		thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION);
#if 0
		if (topo_fmri_nvl2str(thp, asru, &fmri, &err) == 0)
			(void) fmd_repair_asru(hdl, fmri);
		fmd_hdl_topo_rele(hdl, thp);

		topo_hdl_strfree(thp, fmri);
#endif
	}

	zrp = fmd_hdl_alloc(hdl, sizeof (zfs_retire_repaired_t), FMD_SLEEP);
	zrp->zrr_next = zdp->zrd_repaired;
	zrp->zrr_pool = pool_guid;
	zrp->zrr_vdev = vdev_guid;
	zdp->zrd_repaired = zrp;
	nvlist_free(asru);
}

static int
insert_zfsled_node(char *lpath){
	int ret;
	xmlDocPtr doc;  
	xmlNodePtr cur; 
	
	doc = xmlReadFile("/gui/fmd_zfsled.xml", "UTF-8", 256);

	ret = 0;

	if (doc == NULL ) { 
		ret = -1;
       		return ret; 
	} 

	cur = xmlDocGetRootElement(doc);

	if (cur == NULL) { 
      		 xmlFreeDoc(doc); 
		 ret = -1;
      		 return ret; 
	} 
	
	if (xmlStrcmp(cur->name, (const xmlChar *) "root")) { 
       		xmlFreeDoc(doc); 
		ret = -1;
       		return ret; 
	} 

	xmlNewTextChild(cur, NULL,(const xmlChar *)"lpath",(const xmlChar *)lpath);
	xmlSaveFormatFileEnc("/tmp/fmd_zfsled.xml", doc, "UTF-8", 1);
	xmlFreeDoc(doc);
	
	return ret;

}

xmlNodePtr create_xml_file(void)
{
	xmlDocPtr doc = xmlNewDoc((xmlChar *)"1.0");
	xmlNodePtr root_node = xmlNewNode(NULL, (xmlChar *)"root");
	xmlDocSetRootElement(doc, root_node);
	zfsled_doc = doc;
	zfsled_root_node = root_node;

	return (root_node);
}

void close_xml_file(void)
{
	xmlChar *xmlbuff;
	int buffersize;

	xmlDocDumpFormatMemory(zfsled_doc, &xmlbuff, &buffersize, 1);
	xmlSaveFormatFileEnc("/tmp/fmd_zfsled.xml", zfsled_doc, "UTF-8", 1);
	xmlFreeDoc(zfsled_doc);
	xmlFree(xmlbuff);
}

void  create_zfsled_node(char *lpath)
{
	xmlNodePtr node;
	node=xmlNewChild(zfsled_root_node, NULL, (xmlChar *)"lpath", NULL);
	xmlNodeSetContent(node, (xmlChar *)lpath);
}

static void
zfs_retire_diskled(char *dev_lpath){
	int ret;
	char buf[256] = {"\0"};
	memset(buf, 256, 0);
	
	sprintf(buf, DISK_LED_CMD, dev_lpath);
	if (system(buf)!= -1){
		if ((ret = insert_zfsled_node(dev_lpath)) == -1) {
			create_xml_file();
			create_zfsled_node(dev_lpath);
			close_xml_file();
		}
	}
}

static void
zfs_recover_diskled(char *dev_lpath){
	char buf[256] = {"\0"};
	memset(buf, 256, 0);
	
	sprintf(buf, DISK_LED_NORMAL_CMD, dev_lpath);
	(void)system(buf);
}

#if 0
/*
 * Function	:
 *	when find the repair node, then change is_slow to "no"
 */
static int find_repair_slow_disk(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int err;
	zfs_retire_data_t *zdp = arg;
	tnode_t *child = NULL;
	char *devpath = NULL;

	if ((strcmp(topo_node_name(node), "bay") == 0) &&
		((child = topo_child_first(node)) != NULL) &&
		(strncmp(topo_node_name(child), "disk", 4) == 0) &&
		(topo_prop_get_string(child, TOPO_PGROUP_IO,
			TOPO_IO_DEVID, &devpath, &err) == 0)) {
		if (strcmp(zdp->compare_path, devpath) == 0) {
			if ((zdp->flag == 0) &&
				topo_prop_set_string(child, TOPO_PGROUP_IO,
				TOPO_IO_SLOW, TOPO_PROP_MUTABLE, "no", &err) != 0) {
				syslog(LOG_ERR, "change is_slow status fail");
			} else if ((zdp->flag == 1) &&
				topo_prop_set_string(child, TOPO_PGROUP_IO,
				TOPO_IO_DERR, TOPO_PROP_MUTABLE, "no", &err) != 0) {
				syslog(LOG_ERR, "change is_slow status fail");
			} else if ((zdp->flag == 2) &&
				topo_prop_set_string(child, TOPO_PGROUP_IO,
				TOPO_IO_MERR, TOPO_PROP_MUTABLE, "yes", &err) != 0) {
				syslog(LOG_ERR, "change is_slow status fail");
			}
		}
		topo_hdl_strfree(thp, devpath);
	}
	return (TOPO_WALK_NEXT);
}
#endif

/*
 * Function	:scan_disk_node
 *	scan all node, and find the repair node
 *
 */
static void
scan_disk_node(fmd_hdl_t *hdl, id_t id, void *data)
{
	topo_hdl_t *thp;
//	topo_walk_t *twp;
//	int err, ret;
//	zfs_retire_data_t *zdp = fmd_hdl_getspecific(hdl);

	thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION);
#if 0
	if ((twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC, find_repair_slow_disk,
	    zdp, &err)) == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_error(hdl, "failed to get topology: %s\n",
		    topo_strerror(err));
		syslog(LOG_ERR, "dt timeout analyze disk failed to get topo");

		return;
	}
	if (topo_walk_step(twp, TOPO_WALK_CHILD) == TOPO_WALK_ERR) {
		topo_walk_fini(twp);
		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_error(hdl, "failed to walk topology\n");
		syslog(LOG_ERR, "dt timeout analyze disk failed to walk topo");

		return;
	}

	topo_walk_fini(twp);
#endif

	fmd_hdl_topo_rele(hdl, thp);
}

static void
zfs_retire_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class)
{
	uint64_t pool_guid, vdev_guid;
	zpool_handle_t *zhp = NULL;
	nvlist_t *resource, *fault, *asru;
	nvlist_t **faults;
	uint_t f, nfaults;
	zfs_retire_data_t *zdp = fmd_hdl_getspecific(hdl);
	libzfs_handle_t *zhdl = zdp->zrd_hdl;
	boolean_t fault_device, degrade_device;
	boolean_t is_repair, is_segment_error = B_FALSE;
	char *scheme, *devid;
	nvlist_t *vdev = NULL;
	char *uuid;
	int repair_done = 0;
	boolean_t retire;
	boolean_t is_disk;
	vdev_aux_t aux;
	char *dev_name = NULL;
	char buf[256] = {"\0"};
	char dev_lpath[256] = {"\0"};

	/*
	 * If this is a resource notifying us of device removal, then simply
	 * check for an available spare and continue.
	 */
	if (strcmp(class, "resource.fs.zfs.removed") == 0 ||
		strcmp(class, "ereport.fs.zfs.vdev.unknown") == 0 ||
		strcmp(class, "ereport.fs.zfs.probe_failure") == 0) {
		if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_ZFS_POOL_GUID,
		    &pool_guid) != 0 ||
		    nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_ZFS_VDEV_GUID,
		    &vdev_guid) != 0)
			return;

		if ((zhp = find_by_guid(zhdl, pool_guid, vdev_guid,
		    &vdev)) == NULL)
			return;
		
		if (fmd_prop_get_int32(hdl, "spare_on_remove"))
			replace_with_spare(hdl, zhp, vdev);
		/* (void) zpool_vdev_clear(zhp, vdev_guid); */
		zpool_close(zhp);
		return;
	}

	if (strcmp(class, FM_LIST_RESOLVED_CLASS) == 0)
		return;

	if (strcmp(class, "resource.fs.zfs.statechange") == 0 ||
	    strcmp(class,
	    "resource.sysevent.EC_zfs.ESC_ZFS_vdev_remove") == 0) {
#if 0
		zfs_vdev_repair(hdl, nvl);
#endif
		return;
	}

	zfs_retire_clear_data(hdl, zdp);

	if (strcmp(class, FM_LIST_REPAIRED_CLASS) == 0)
		is_repair = B_TRUE;
	else
		is_repair = B_FALSE;

	/*
	 * We subscribe to zfs faults as well as all repair events.
	 */
	if (nvlist_lookup_nvlist_array(nvl, FM_SUSPECT_FAULT_LIST,
	    &faults, &nfaults) != 0)
		return;

	for (f = 0; f < nfaults; f++) {
		fault = faults[f];

		fault_device = B_FALSE;
		degrade_device = B_FALSE;
		is_disk = B_FALSE;

		if (nvlist_lookup_boolean_value(fault, FM_SUSPECT_RETIRE,
		    &retire) == 0 && retire == 0)
			continue;

		/*
		 * While we subscribe to fault.fs.zfs.*, we only take action
		 * for faults targeting a specific vdev (open failure or SERD
		 * failure).  We also subscribe to fault.io.* events, so that
		 * faulty disks will be faulted in the ZFS configuration.
		 */
		if (fmd_nvl_class_match(hdl, fault, "fault.fs.zfs.vdev.io")) {
			fault_device = B_TRUE;
		} else if (fmd_nvl_class_match(hdl, fault,
		    "fault.fs.zfs.vdev.checksum")) {
			degrade_device = B_TRUE;
		} else if (fmd_nvl_class_match(hdl, fault,
		    "fault.fs.zfs.device")) {
			fault_device = B_FALSE;
		} else if (fmd_nvl_class_match(hdl, fault, "fault.io.*")) {
			is_disk = B_TRUE;
			degrade_device = B_TRUE;
			/*fault_device = B_TRUE;*/
		} else if (fmd_nvl_class_match(hdl, fault,
		    "fault.fs.zfs.segment_error")) {
		    is_segment_error = B_TRUE;
		    syslog(LOG_ERR, "fault.fs.zfs.segment_error\n");
		} else {
			continue;
		}

		if (is_disk) {
			/*
			 * This is a disk fault.  Lookup the ASRU, because ASRU 
			 * contain devid, and attempt to find a matching vdev 
			 * by devid.
			 */
			if (nvlist_lookup_nvlist(fault, FM_FAULT_ASRU,
			    &asru) != 0 ||
			    nvlist_lookup_string(asru, FM_FMRI_SCHEME,
			    &scheme) != 0)
				continue;
			/* ASRU's scheme is dev  */
			if (strcmp(scheme, FM_FMRI_SCHEME_DEV) != 0)
				continue;

			if (zhdl == NULL || nvlist_lookup_string(asru,
			    FM_FMRI_DEV_ID, &devid) != 0)
				continue;
			
			/* if repair slow disk set is_slow no in topo.xml */
			if ((strcmp(class,"list.repaired") == 0) &&
			 	(devid != NULL)){
			 	if (fmd_nvl_class_match(hdl, fault, "fault.io.disk.slow-io")) {
					zdp->flag = 0;
				} else if (fmd_nvl_class_match(hdl, fault, "fault.io.disk.device-errors-exceeded")) {
					zdp->flag = 1;
				}
				zdp->compare_path = devid;	
//				scan_disk_node(hdl, 0, NULL);
			}

			if (fmd_nvl_class_match(hdl, fault, "fault.io.scsi.*")
				&& (is_repair == B_FALSE)) {
				zdp->flag = 2;
				zdp->compare_path = devid;	
				scan_disk_node(hdl, 0, NULL);
			}

			if ((zhp = find_by_devid(zhdl, devid, &vdev)) == NULL)
				continue;

			if (vdev != NULL)
				dev_name = zpool_vdev_name(NULL, zhp, vdev, B_FALSE);

			(void) nvlist_lookup_uint64(vdev,
			    ZPOOL_CONFIG_GUID, &vdev_guid);
			aux = VDEV_AUX_EXTERNAL;
		} else {
			/*
			 * This is a ZFS fault.  Lookup the resource, and
			 * attempt to find the matching vdev.
			 */
			if (nvlist_lookup_nvlist(fault, FM_FAULT_RESOURCE,
			    &resource) != 0 ||
			    nvlist_lookup_string(resource, FM_FMRI_SCHEME,
			    &scheme) != 0)
				continue;

			if (strcmp(scheme, FM_FMRI_SCHEME_ZFS) != 0)
				continue;

			if (nvlist_lookup_uint64(resource, FM_FMRI_ZFS_POOL,
			    &pool_guid) != 0)
				continue;

			if (nvlist_lookup_uint64(resource, FM_FMRI_ZFS_VDEV,
			    &vdev_guid) != 0) {
				if (is_repair || is_segment_error)
					vdev_guid = 0;
				else
					continue;
			}

			if ((zhp = find_by_guid(zhdl, pool_guid, vdev_guid,
			    &vdev)) == NULL)
				continue;

			if (is_segment_error && !is_repair) {
				memset(buf, 0, 256);
				sprintf(buf, ZPOOL_SCRUB_POOL, zpool_get_name(zhp));
				system(buf);
				syslog(LOG_ERR, "system %s\n", buf);
				zpool_close(zhp);
				continue;
			}

			if (vdev != NULL)
				dev_name = zpool_vdev_name(NULL, zhp, vdev, B_FALSE);
			aux = VDEV_AUX_ERR_EXCEEDED;
		}

		if (vdev_guid == 0) {
			/*
			 * For pool-level repair events, clear the entire pool.
			 */
			if (is_segment_error) {
				repair_done = 1;
//				(void) zpool_clr_zfs_recover(zhp);
			}
			zpool_close(zhp);
			continue;
		}

		/*
		 * If this is a repair event, then mark the vdev as repaired and
		 * continue.
		 */
		if (is_repair) {
			repair_done = 1;
			(void) zpool_vdev_clear(zhp, vdev_guid);
			zpool_close(zhp);
			continue;
		}

		/*
		 * Actively fault the device if needed.
		 */
		if (fault_device)
			(void) zpool_vdev_fault(zhp, vdev_guid, aux);
		if (degrade_device)
			(void) zpool_vdev_degrade(zhp, vdev_guid, aux);

		/*
		 * Attempt to substitute a hot spare.
		 */
		replace_with_spare(hdl, zhp, vdev);
		zpool_close(zhp);
	}
	
	if (strcmp(class, FM_LIST_REPAIRED_CLASS) == 0 && repair_done &&
	    nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid) == 0)
		fmd_case_uuresolved(hdl, uuid);
	
	if (dev_name != NULL && !is_repair) {
		sprintf(dev_lpath, DISK_LED_LPATH, dev_name);
		syslog(LOG_ERR,"zfs retire faild dev_name is %s", dev_lpath);
		zfs_retire_diskled(dev_lpath);
		free(dev_name);
	} else if (dev_name != NULL && is_repair) {
		sprintf(dev_lpath, DISK_LED_LPATH, dev_name);
		syslog(LOG_ERR,"zfs recover faild dev_name is %s", dev_lpath);
		zfs_recover_diskled(dev_lpath);
		free(dev_name);
	}
}

static const fmd_hdl_ops_t fmd_ops = {
	zfs_retire_recv,	/* fmdo_recv */
	NULL,			/* fmdo_timeout */
	NULL,			/* fmdo_close */
	NULL,			/* fmdo_stats */
	NULL,			/* fmdo_gc */
};

static const fmd_prop_t fmd_props[] = {
	{ "spare_on_remove", FMD_TYPE_BOOL, "true" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"ZFS Retire Agent", "1.0", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	zfs_retire_data_t *zdp;
	libzfs_handle_t *zhdl;

	if ((zhdl = libzfs_init()) == NULL)
		return;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0) {
		libzfs_fini(zhdl);
		return;
	}

	zdp = fmd_hdl_zalloc(hdl, sizeof (zfs_retire_data_t), FMD_SLEEP);
	zdp->zrd_hdl = zhdl;

	fmd_hdl_setspecific(hdl, zdp);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	zfs_retire_data_t *zdp = fmd_hdl_getspecific(hdl);

	if (zdp != NULL) {
		zfs_retire_clear_data(hdl, zdp);
		libzfs_fini(zdp->zrd_hdl);
		fmd_hdl_free(hdl, zdp, sizeof (zfs_retire_data_t));
	}
}
