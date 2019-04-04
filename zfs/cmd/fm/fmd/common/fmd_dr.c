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
 * FMD Dynamic Reconfiguration (DR) Event Handling
 *
 * Fault manager scheme plug-ins must track characteristics of individual
 * pieces of hardware.  As these components can be added or removed by a DR
 * operation, we need to provide a means by which plug-ins can determine when
 * they need to re-examine the current configuration.  We provide a simple
 * mechanism whereby this task can be implemented using lazy evaluation: a
 * simple 64-bit generation counter is maintained and incremented on *any* DR.
 * Schemes can store the generation number in scheme-specific data structures,
 * and then revalidate their contents if the current generation number has
 * changed since the resource information was cached.  This method saves time,
 * avoids the complexity of direct participation in DR, avoids the need for
 * resource-specific processing of DR events, and is relatively easy to port
 * to other systems that support dynamic reconfiguration.
 *
 * The dr generation is only incremented in response to hardware changes.  Since
 * ASRUs can be in any scheme, including the device scheme, we must also be
 * aware of software configuration changes which may affect the resource cache.
 * In addition, we take a snapshot of the topology whenever a reconfiguration
 * event occurs and notify any modules of the change.
 */

#include <sys/types.h>
//#include <sys/sunddi.h>
//#include <sys/sysevent/dr.h>
//#include <sys/sysevent/eventdefs.h>
//#include <sys/fibre-channel/fc_types.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/fmd_transport.h>
#include <libzfs.h>

#undef FMD_MUTEX_HELD
#undef FMD_RW_READ_HELD
#undef FMD_RW_WRITE_HELD

#include "fmd_asru.h"
#include "fmd_error.h"
#include "fmd_event.h"
#include "fmd_fmri.h"
#include "fmd_module.h"
#include "fmd_subr.h"
#include "fmd_topo.h"
#include "fmd.h"

#define	ZPOOL_CONFIG_LOWSPARES		"lowspares"
#define	ZPOOL_CONFIG_METASPARES		"metaspares"

typedef struct find_cbdata {
	uint64_t	cb_guid;
	const char	*cb_devid;
	const char	*cb_fru;
	zpool_handle_t	*cb_zhp;
	nvlist_t	*cb_vdev;
} find_cbdata_t;

static nvlist_t *
fmd_clear_vdev(nvlist_t *nv, void *data)
{
	find_cbdata_t *cbp = data;
	zpool_handle_t	*zhp = cbp->cb_zhp;
	nvlist_t **child;
	nvlist_t *ret;
	uint_t c, children;
	char *path;
	char buf[128];
	char *p;

	memset(buf, 0, 128);
	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) == 0) { 
		
		if (readlink(path, buf, 128) > 0) {
		
			p = buf;
			while (*p != '\0') {
				if (*p > 0x2f && *p < 0x3a) {
					*p = '\0';
					break;
				}
				p = p + 1;
			}
			p = buf + 6;
			if (*p > 96 && *p < 123 &&
				strstr(cbp->cb_devid, p) != NULL) {
				syslog(LOG_ERR, "fmdtopo: %s,path:%s, devid:%s, %s\n",
					p, path,  cbp->cb_devid, zpool_get_name(zhp));
				memset(buf, 0, 128);
				snprintf(buf, 128, "zpool clear %s %s", zpool_get_name(zhp), path);
				system(buf);
				syslog(LOG_ERR, "fmdtopo:%s\n", buf);
				sleep(1);
				memset(buf, 0, 128);
				snprintf(buf, 128, "zpool clear %s", zpool_get_name(zhp));
				system(buf);
				syslog(LOG_ERR, "fmdtopo:%s\n", buf);
				return nv;
			}
		} else syslog(LOG_ERR, "fmd_dr:readlink failed,%s\n", path);
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			if ((ret = fmd_clear_vdev(child[c], data)) != NULL)
				return (ret);
		}
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_L2CACHE,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			if ((ret = fmd_clear_vdev(child[c], data)) != NULL)
				return (ret);
		}
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_SPARES,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			if ((ret = fmd_clear_vdev(child[c], data)) != NULL)
				return (ret);
		}
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_METASPARES,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			if ((ret = fmd_clear_vdev(child[c], data)) != NULL)
				return (ret);
		}
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_LOWSPARES,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			if ((ret = fmd_clear_vdev(child[c], data)) != NULL)
				return (ret);
		}
	}
	
	return (NULL);
}

static int
fmd_callback(zpool_handle_t *zhp, void *data)
{
	find_cbdata_t *cbp = data;
	nvlist_t *config;
	nvlist_t *nvroot;

	config = zpool_get_config(zhp, NULL);
	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		&nvroot) != 0) {
		zpool_close(zhp);
		return -1;
	}

	cbp->cb_zhp = zhp;
	if (fmd_clear_vdev(nvroot, cbp) != NULL) {
		zpool_close(zhp);
		return -1;
	}
	zpool_close(zhp);
	return 0;
}

static int
fmd_clear_pool_vdev(const char *devid)
{
	libzfs_handle_t *zhdl = NULL;
	find_cbdata_t cb;
	
	if ((zhdl = libzfs_init()) == NULL ) {
		syslog(LOG_ERR, "fmd_dr: can not do libzfs_init()\n") ;
		return -1 ;
	}

	cb.cb_devid = devid;
	cb.cb_zhp = NULL;
	(void) zpool_iter(zhdl, fmd_callback, &cb);

	libzfs_fini(zhdl) ;
	return 0 ;
}

void
fmd_device_event(fmd_msg_t *msg)
{
	uint64_t gen;
	fmd_event_t *e;
	hrtime_t evtime;
	fmd_topo_t *ftp, *prev;
	char *p = NULL;

	if (msg == NULL || msg->fm_buf == NULL ||
		(strstr(msg->fm_buf, "add") == NULL &&
		strstr(msg->fm_buf, "remove") == NULL))
		return;

	if ((p = strstr(msg->fm_buf, "sd")) != NULL) {
		p = p + 3;
		while (*p != '\0') {
			if (*p > 0x2f && *p < 0x3a) {
				return;
			}
			p = p + 1;
		}
	} else {
		return;
	}

	evtime = fmd_time_gethrtime();
	prev = fmd_topo_hold();

	if (evtime <= prev->ft_time_begin &&
	    fmd.d_clockops == &fmd_timeops_native) {
		fmd_topo_rele(prev);
		return;
	}
	fmd_topo_rele(prev);

	if (strstr(msg->fm_buf, "add") != NULL) {
		syslog(LOG_ERR, "fmd_dr update:%s\n", msg->fm_buf);
		sleep(3);
		fmd_topo_update(B_TRUE, B_FALSE);
	}

	ftp = fmd_topo_hold();
	e = fmd_event_create(FMD_EVT_TOPO, ftp->ft_time_end, NULL, ftp);
	fmd_modhash_dispatch(fmd.d_mod_hash, e);

	/* if the removed disk in pool, we shold do 
	  zpool clear for the disk */
	(void) fmd_clear_pool_vdev(msg->fm_buf);
}

#if 0
void
fmd_dr_event(sysevent_t *sep)
{
	uint64_t gen;
	fmd_event_t *e;
	const char *class = sysevent_get_class_name(sep);
	const char *subclass = sysevent_get_subclass_name(sep);
	hrtime_t evtime;
	fmd_topo_t *ftp, *prev;
	boolean_t update_topo = B_FALSE, update = B_TRUE;

	if (strcmp(class, EC_DR) == 0) {
		if (strcmp(subclass, ESC_DR_AP_STATE_CHANGE) != 0 &&
		    strcmp(subclass, ESC_DR_TARGET_STATE_CHANGE) != 0)
			return;

		/*
		 * The DR generation is only changed in response to DR events.
		 */
		update_topo = B_TRUE;

		(void) pthread_mutex_lock(&fmd.d_stats_lock);
		gen = fmd.d_stats->ds_dr_gen.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&fmd.d_stats_lock);

		TRACE((FMD_DBG_XPRT, "dr event %p, gen=%llu",
		    (void *)sep, gen));
	} else if (strcmp(class, EC_DEVFS) == 0) {
		#if 0
		/*
		 * A devfs configuration event can change the topology,
		 * as disk nodes only exist when the device is configured.
		 */
		update_topo = B_TRUE;
		#endif
		/* there is no need to update topo, we assume only device added, to update topo */
		update_topo = B_FALSE;
	} else if (strcmp(class, EC_PLATFORM) == 0) {
		if (strcmp(subclass, ESC_PLATFORM_SP_RESET) == 0) {
			/*
			 * Since we rely on the SP to enumerate fans,
			 * power-supplies and sensors/leds, it would be prudent
			 * to take a new snapshot if the SP resets.
			 */
			update_topo = B_TRUE;
		}
	} else if (strcmp(class, EC_ZFS) == 0) {
		/* fm topo update is finish */
		if (strcmp(subclass, ESC_ZFS_FM_TOPO_UPDATE) == 0) {
			update_topo = B_TRUE;
			update = B_FALSE;
		}
		
		/*
		 * These events can change the resource cache.
		 */
		if (strcmp(subclass, ESC_ZFS_VDEV_CLEAR) != 0 &&
		    strcmp(subclass, ESC_ZFS_VDEV_REMOVE) != 0 &&
		    strcmp(subclass, ESC_ZFS_POOL_DESTROY) != 0 &&
		    strcmp(subclass, ESC_ZFS_FM_TOPO_UPDATE) != 0 &&
		    strcmp(subclass, ESC_ZFS_VDEV_QUANTUM) !=0)
			return;
	} else if (strcmp(class, EC_DEV_ADD) == 0 ||
	    strcmp(class, EC_DEV_REMOVE) == 0) {
		if (strcmp(subclass, ESC_DISK) != 0)
			return;

		update_topo = B_TRUE;
	} else if (strcmp(subclass, ESC_SUNFC_DEVICE_ONLINE) == 0) {
		update_topo = B_TRUE;
		sleep(20);
	} else if (strcmp(class, EC_HBA) == 0) {
		return;
	}

	/*
	 * Take a topo snapshot and notify modules of the change.  Picking an
	 * accurate time here is difficult.  On one hand, we have the timestamp
	 * of the underlying sysevent, indicating when the reconfiguration event
	 * occurred.  On the other hand, we are taking the topo snapshot
	 * asynchronously, and hence the timestamp of the snapshot is the
	 * current time.  Pretending this topo snapshot was valid at the time
	 * the sysevent was posted seems wrong, so we instead opt for the
	 * current time as an upper bound on the snapshot validity.
	 *
	 * Along these lines, we keep track of the last time we dispatched a
	 * topo snapshot.  If the sysevent occurred before the last topo
	 * snapshot, then don't bother dispatching another topo change event.
	 * We've already indicated (to the best of our ability) the change in
	 * topology.  This prevents endless topo snapshots in response to a
	 * flurry of sysevents.
	 */
	sysevent_get_time(sep, &evtime);
	prev = fmd_topo_hold();
	if (evtime <= prev->ft_time_begin &&
	    fmd.d_clockops == &fmd_timeops_native) {
		fmd_topo_rele(prev);
		return;
	}
	fmd_topo_rele(prev);

	if (update_topo) {
		syslog(LOG_INFO, "fmd topo update, class %s, sub %s\n", class, subclass);
		fmd_topo_update(B_FALSE, B_FALSE);
	}

	ftp = fmd_topo_hold();
	e = fmd_event_create(FMD_EVT_TOPO, ftp->ft_time_end, NULL, ftp);
	fmd_modhash_dispatch(fmd.d_mod_hash, e);
}
#endif
