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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <umem.h>
#include <fmd_api.h>
#include <libdiskstatus.h>
#include <libtopo.h>
#include <topo_hc.h>
#include <topo_list.h>
#include <topo_mod.h>
#include <topo_fruhash.h>
#include <limits.h>
#include <sys/scsi/scsi.h>
#include <sys/fm/protocol.h>
#include <libxml/tree.h>
#include <libdevinfo.h>
#include <libzfs.h>
//#include <sys/modctl.h>
//#include <xyses_api.h>
#include <libsysenv.h>
#include <syslog.h>
#include <topo_fruhash.h>
//#include <ses_led.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libzfs.h>
#include <libstmf.h>
#include "../link-transport/link_enum.h"
#include <strings.h>
#include "pt_zfs.h"


#define FM_EREPORT_TYPE			"type"
#define FM_EREPORT_NAME			"name"
#define FM_EREPORT_STATE		"state"
#define FM_EREPORT_STATE_DESC	"state_desc"
#define FM_EREPORT_LOCATEPATH	"locate_path"

#define PT_SUCCESS	0
#define PT_FAILED	-1

#define	DISK_LED_CMD	"/usr/sbin/disk led -d %s -o locate &"

#define	PT_FS_XML_PATH "/tmp/fs.xml"
#define	PT_LU_XML_PATH "/tmp/lu.xml"

#define PT_CMD_NAME "pool-transprt"

#define HOSTNAMELEN 32


typedef struct ck_cbdata {
	fmd_hdl_t *hdl;

} ck_cbdata_t;


typedef struct pool_fault {
	struct pool_fault	*pf_next;
	char			*pf_fru;
	uint32_t		pf_num_fails;
	boolean_t		pf_last_faulted;
	boolean_t		pf_faulted;
	boolean_t		pf_unknown;
} pool_fault_t;

typedef struct pool_transport {
	fmd_hdl_t	*pt_hdl;
	fmd_xprt_t	*pt_xprt;
	libzfs_handle_t	*pt_zhdl;
	hrtime_t	pt_interval;
	id_t		pt_timer;

	boolean_t	pt_status_changed;
} pool_transport_t;


static struct pt_stat {
	fmd_stat_t dropped;
} pt_stats = {
	{ "dropped", FMD_TYPE_UINT64, "number of dropped ereports" }
};

static xmlDocPtr pt_fs_doc;
static xmlNodePtr pt_fs_root_node;
static xmlDocPtr pt_lu_doc;
static xmlNodePtr pt_lu_root_node;

char hostname[HOSTNAMELEN];


static void pt_status_change(fmd_hdl_t *hdl, topo_hdl_t *thp);
static int pt_walk_zfs_dataset(fmd_hdl_t *hdl, pool_transport_t *ptp);

static xmlNodePtr pt_create_fsxml_file(void)
{
	xmlDocPtr doc = xmlNewDoc((xmlChar *)"1.0");
	xmlNodePtr root_node = xmlNewNode(NULL, (xmlChar *)"cefs");
	xmlDocSetRootElement(doc, root_node);
	pt_fs_doc = doc;
	pt_fs_root_node = root_node;

	return (root_node);
}

static xmlNodePtr pt_create_luxml_file(void)
{
	xmlDocPtr doc = xmlNewDoc((xmlChar *)"1.0");
	xmlNodePtr root_node = xmlNewNode(NULL, (xmlChar *)"cefs");
	xmlDocSetRootElement(doc, root_node);
	pt_lu_doc = doc;
	pt_lu_root_node = root_node;

	return (root_node);
}

static void 
pt_close_fsxml_file(void)
{
	xmlSaveFormatFileEnc(PT_FS_XML_PATH, pt_fs_doc, "UTF-8", 1);
	xmlFreeDoc(pt_fs_doc);
}

static void 
pt_close_luxml_file(void)
{
	xmlSaveFormatFileEnc(PT_LU_XML_PATH, pt_lu_doc, "UTF-8", 1);
	xmlFreeDoc(pt_lu_doc);
}

static void
pt_send_snmptrap(fmd_hdl_t		*hdl, 
					fmd_xprt_t		*xprt, 
					const char		*protocol,
					const char		*faultname,
					uint64_t		ena,
					const char		*path,
					const char 		*devpath,
					const char 		*state,
					char			*locate_path)
{

	nvlist_t *nvl;
	int e = 0;
	char fullclass[PATH_MAX];
	char state_desc[PATH_MAX];

	snprintf(fullclass, sizeof (fullclass), "%s.%s.%s",
		FM_EREPORT_CLASS, protocol, faultname);

	if(nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) == 0){
		e |= nvlist_add_string(nvl, FM_CLASS, fullclass);
		e |= nvlist_add_uint8(nvl, FM_VERSION, FM_EREPORT_VERSION);
		e |= nvlist_add_uint64(nvl, FM_EREPORT_ENA, ena);
		e |= nvlist_add_string(nvl, FM_EREPORT_TYPE, "pool");
		e |= nvlist_add_string(nvl, FM_EREPORT_NAME, devpath);
		e |= nvlist_add_uint32(nvl, FM_EREPORT_STATE, 4);
		if (state != NULL && path != NULL) {
			snprintf(state_desc, sizeof (state_desc), "%s_%s",
				path, state);
			e |= nvlist_add_string(nvl, FM_EREPORT_STATE_DESC, state_desc);
		}
		if (locate_path != NULL)
			e |= nvlist_add_string(nvl, FM_EREPORT_LOCATEPATH, locate_path);

		if(e == 0) {
			fmd_xprt_post(hdl, xprt, nvl, 0);
		} else {
			pt_stats.dropped.fmds_value.ui64++;
			nvlist_free(nvl);
		}
	} else {
		pt_stats.dropped.fmds_value.ui64++;
	}
}

static void
pt_post_ereport(fmd_hdl_t		*hdl,
				fmd_xprt_t		*xprt,
				const char		*protocol,
				const char		*faultname,
				uint64_t		ena, 
				nvlist_t		*detector,
				nvlist_t		*payload,
				nvlist_t		*asru)
{
	nvlist_t *nvl;
	int e = 0;
	char fullclass[PATH_MAX];

	(void) snprintf(fullclass, sizeof (fullclass), "%s.io.%s.disk.%s",
	    FM_EREPORT_CLASS, protocol, faultname);

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) == 0) {
		e |= nvlist_add_string(nvl, FM_CLASS, fullclass);
		e |= nvlist_add_uint8(nvl, FM_VERSION, FM_EREPORT_VERSION);
		e |= nvlist_add_uint64(nvl, FM_EREPORT_ENA, ena);
		e |= nvlist_add_nvlist(nvl, FM_EREPORT_DETECTOR, detector);
		e |= nvlist_add_nvlist(nvl, FM_FAULT_ASRU, asru);
		e |= nvlist_merge(nvl, payload, 0);

		if (e == 0) {
			fmd_xprt_post(hdl, xprt, nvl, 0);
		} else {
			nvlist_free(nvl);
			pt_stats.dropped.fmds_value.ui64++;
		}
	} else {
		pt_stats.dropped.fmds_value.ui64++;
	}
}

static void
pt_fault_execute_action(char *lpath)
{
	//int slot = 0;
	char buf[256] = {"\0"};

	if (lpath != NULL) {
		sprintf(buf, DISK_LED_CMD, lpath);
		system(buf);
	}
}

static int
pt_led_pool_disk(libzfs_handle_t	*zhdl, zpool_handle_t *zhp,
	const char *name, nvlist_t *nv, char **path)
{
	char *type;
	nvlist_t **child;
	uint_t c, children;
	vdev_stat_t *vs;
	uint_t n;
	//nvlist_t *config, *nvroot;
	char *vname;
	char buf[64];

	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_TYPE, &type) != 0)
		return PT_FAILED;

	if (strcmp(VDEV_TYPE_DISK, type) == 0 &&
		nvlist_lookup_uint64_array(nv, ZPOOL_CONFIG_VDEV_STATS,
			(uint64_t **)&vs, &n) == 0) {
		if (vs->vs_state == VDEV_STATE_HEALTHY) {
			memset(buf, 0, 64);
			snprintf(buf, sizeof(buf), "/dev/rdsk/%s", name);
			pt_fault_execute_action(buf);
			*path = strdup(buf);
			syslog(LOG_ERR,"locate_path:%s\n", *path);
			return PT_SUCCESS;
		}
	}
	
	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
		&child, &children) != 0)
		children = 0;	

	for (c = 0; c < children; c++) {
		if ((vname = zpool_vdev_name(zhdl, zhp, child[c], B_TRUE)) != NULL ) {
			if (pt_led_pool_disk(zhdl, zhp, vname, child[c], path) == 0) {
				free(vname);
				return PT_SUCCESS;
			}
			free(vname);
		}
	}
	return PT_FAILED;
}

static int
get_disk_label_state(nvlist_t *nv)
{
	int fd;
	int len;
	//int loop;
	struct stat64 statbuf;
	char spare_path[MAXPATHLEN];
	char *spare_name;
	int spare_name_len;

	/* when other control use the disk */
	nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &spare_name);
	len = strlen(spare_name) + 1;

	if (strncmp(spare_name, "/dev/dsk/", 9) == 0) {
		(void) snprintf(spare_path, len+1, "%s%s", "/dev/rdsk/", spare_name + 9);
	} else {
		printf("%s error\n", spare_name);
	}

	spare_name_len = strlen(spare_name);
	if (*(spare_name + spare_name_len -2) != 's')
		(void) snprintf(spare_path, MAXPATHLEN, "%ss0", spare_path);
	else
		(void) snprintf(spare_path, MAXPATHLEN, "%s", spare_path);

	if ((fd = open64(spare_path, O_RDONLY)) < 0) 
		return PT_FAILED;

	if (fstat64(fd, &statbuf) != 0) {
		syslog(LOG_ERR, "failed to fstate %s", spare_path);
		goto FAIL;
	}

	if (S_ISBLK(statbuf.st_mode)) {
		syslog(LOG_ERR, "failed to S_ISBLK %s", spare_path);
		goto FAIL;
	}

	(void) close(fd);
	return PT_SUCCESS;
	/* fail to get disk infor */
FAIL:
	(void) close(fd);
	return PT_FAILED;
}

static nvlist_t *
pt_check_pool_disk(nvlist_t *nv, boolean_t isspare, boolean_t *label_f)
{
	uint_t c, children;
	nvlist_t **child;
	vdev_stat_t *vs;
	nvlist_t *ret;
	char *type;

	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_TYPE, &type) != 0)
		return NULL;

	if (strcmp(VDEV_TYPE_DISK, type) == 0 &&
		nvlist_lookup_uint64_array(nv, ZPOOL_CONFIG_VDEV_STATS,
			(uint64_t **)&vs, &c) == 0) {
		if (vs->vs_state < VDEV_STATE_HEALTHY) {
			if (vs->vs_state == VDEV_STATE_CANT_OPEN &&
				vs->vs_aux == VDEV_AUX_SPARED)
				return NULL;
			else
				return nv;
		} else if (isspare && get_disk_label_state(nv) != PT_SUCCESS) {
			*label_f = B_TRUE;
			return nv;
		}
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			if ((ret = pt_check_pool_disk(child[c], B_FALSE, label_f)) != NULL)
				return ret;
		}
	}
	
	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_L2CACHE,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			if ((ret = pt_check_pool_disk(child[c], B_FALSE, label_f)) != NULL)
				return ret;
		}
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_SPARES,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			if ((ret = pt_check_pool_disk(child[c], B_TRUE, label_f)) != NULL)
				return ret;			
		}
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_METASPARES,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			if ((ret = pt_check_pool_disk(child[c], B_FALSE, label_f)) != NULL)
				return ret;
		}
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_LOWSPARES,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++) {
			if ((ret = pt_check_pool_disk(child[c], B_FALSE, label_f)) != NULL)
				return ret;
		}
	}

	return NULL;
}

void
pt_get_scan_status(pool_scan_stat_t *ps, char *scan_buf)
{
	time_t start, end;
	uint64_t elapsed, mins_left, hours_left;
	uint64_t pass_exam, examined, total;
	uint_t rate;
	double fraction_done;
	char processed_buf[7], examined_buf[7], total_buf[7], rate_buf[7];
	char migrated_buf[64],	to_migrate_buf[64];
	//char buf[1024];
	int n = 0;

	/* If there's never been a scan, there's not much to say. */
	if (ps == NULL || ps->pss_func == POOL_SCAN_NONE ||
	    ps->pss_func >= POOL_SCAN_FUNCS) {
		(void) sprintf(scan_buf, "none requested");
		return;
	}

	start = ps->pss_start_time;
	end = ps->pss_end_time;
	zfs_nicenum(ps->pss_processed, processed_buf, sizeof (processed_buf));

	assert(ps->pss_func == POOL_SCAN_SCRUB ||
	    ps->pss_func == POOL_SCAN_RESILVER || ps->pss_func == POOL_SCAN_LOW);

	/*
	 * Check Low data migration.
	 */
	if (ps->pss_func == POOL_SCAN_LOW) {
		zfs_nicenum(ps->pss_wrc_total_migrated, migrated_buf, sizeof (migrated_buf));
		zfs_nicenum(ps->pss_wrc_total_to_migrate, to_migrate_buf, sizeof (to_migrate_buf));
		n += sprintf(scan_buf+n,"process low data %s of %s.", migrated_buf, to_migrate_buf);
	}

	
	/*
	 * Scan is finished or canceled.
	 */
	if (ps->pss_state == DSS_FINISHED) {
		uint64_t minutes_taken = (end - start) / 60;
		char *fmt = NULL;

		if (ps->pss_func == POOL_SCAN_SCRUB) {
			fmt = "scrub repaired %s in %lluh%um with %llu errors on %s";
		} else if (ps->pss_func == POOL_SCAN_RESILVER) {
			fmt = "resilvered %s in %lluh%um with %llu errors on %s";
		} else if (ps->pss_func == POOL_SCAN_LOW) {
			fmt = "migrate low data %s in %lluh%um with %llu errors on %s";
		}
		
		/* LINTED */
		(void) sprintf(scan_buf+n, fmt, processed_buf,
		    (u_longlong_t)(minutes_taken / 60),
		    (uint_t)(minutes_taken % 60),
		    (u_longlong_t)ps->pss_errors,
		    ctime((time_t *)&end));
		return;
	} else if (ps->pss_state == DSS_CANCELED) {
		if (ps->pss_func == POOL_SCAN_SCRUB) {
			n += sprintf(scan_buf+n, "scrub canceled on %s",
			    ctime(&end));
		} else if (ps->pss_func == POOL_SCAN_RESILVER) {
			n += sprintf(scan_buf+n, "resilver canceled on %s",
			    ctime(&end));
		} else if (ps->pss_func == POOL_SCAN_LOW) {
			n += sprintf(scan_buf+n, "migrating low data canceled on %s",
			    ctime(&end));
		}
		return;
	}

	assert(ps->pss_state == DSS_SCANNING);

	/*
	 * Scan is in progress.
	 */
	if (ps->pss_func == POOL_SCAN_SCRUB) {
		n += sprintf(scan_buf+n, "scrub in progress since %s",
		    ctime(&start));
	} else if (ps->pss_func == POOL_SCAN_RESILVER) {
		n += sprintf(scan_buf+n, "resilver in progress since %s",
		    ctime(&start));
	} else if (ps->pss_func == POOL_SCAN_LOW) {
		n += sprintf(scan_buf+n, "migrating low data in progress since %s",
		    ctime(&start));
	}

	examined = ps->pss_examined ? ps->pss_examined : 1;
	total = ps->pss_to_examine;
	if (ps->pss_func == POOL_SCAN_LOW) {
		examined += ps->pss_wrc_total_to_migrate;
	}
	fraction_done = (double)examined / total;

	/* elapsed time for this pass */
	elapsed = time(NULL) - ps->pss_pass_start;
	elapsed = elapsed ? elapsed : 1;
	pass_exam = ps->pss_pass_exam ? ps->pss_pass_exam : 1;
	rate = pass_exam / elapsed;
	rate = rate ? rate : 1;
	mins_left = ((total - examined) / rate) / 60;
	hours_left = mins_left / 60;

	zfs_nicenum(examined, examined_buf, sizeof (examined_buf));
	zfs_nicenum(total, total_buf, sizeof (total_buf));
	zfs_nicenum(rate, rate_buf, sizeof (rate_buf));

	/*
	 * do not print estimated time if hours_left is more than 30 days
	 */
	n += sprintf(scan_buf+n, " %s scanned out of %s at %s/s",
	    examined_buf, total_buf, rate_buf);
	
	if (hours_left < (30 * 24)) {
		n += sprintf(scan_buf+n, ", %lluh%um to go",
		    (u_longlong_t)hours_left, (uint_t)(mins_left % 60));
	} else {
		n += sprintf(scan_buf+n, ", scan is slow, no estimated time");
	}

	if (ps->pss_func == POOL_SCAN_RESILVER) {
		n += sprintf(scan_buf+n, " %s resilvered, %.2f%% done",
		    processed_buf, 100 * fraction_done);
	} else if (ps->pss_func == POOL_SCAN_SCRUB) {
		n += sprintf(scan_buf+n, " %s repaired, %.2f%% done",
		    processed_buf, 100 * fraction_done);
	} else if (ps->pss_func == POOL_SCAN_LOW) {
		n += sprintf(scan_buf+n, "%s%.2f%% done",
		    migrated_buf, 100 * fraction_done);
	}
}

static int
pt_check_pool_status(zpool_handle_t *zhp, void *data)
{
	ck_cbdata_t *cbdata = data;
	pool_transport_t *ptp;
	char *health =NULL, *pool_health = NULL;
	uint64_t ena;
	nvlist_t *config, *nvroot, *ret;
	vdev_stat_t *vs;
	uint_t c;
	char *path = NULL;
	char *locate_path = NULL;
	boolean_t label_fail = B_FALSE;
	pool_scan_stat_t *ps = NULL;
	char scan_buf[1024];
	char pool_name[128];

	if ((config = zpool_get_config(zhp, NULL)) == NULL ||
		nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) != 0) {
	    zpool_close(zhp);
	    return -1;
	}
	if ((ret = pt_check_pool_disk(nvroot, B_FALSE, &label_fail)) != NULL) {	
		ptp = fmd_hdl_getspecific(cbdata->hdl);
		ena = fmd_event_ena_create(ptp->pt_hdl);
		if (nvlist_lookup_uint64_array(ret, ZPOOL_CONFIG_VDEV_STATS,
			(uint64_t **)&vs, &c) == 0) {
			if (label_fail == B_TRUE)
				health = "label_corrupt";
			else
				health = zpool_state_to_name(vs->vs_state, vs->vs_aux);
		}
		(void) nvlist_lookup_string(ret, ZPOOL_CONFIG_PATH, &path);
		/*
		 * led a disk to locate status, the disk in the pool must  be health,
		 * to avoid override warning disk.
		 */
		(void) pt_led_pool_disk(ptp->pt_zhdl, zhp, zpool_get_name(zhp),
			nvroot, &locate_path);

		(void) nvlist_lookup_uint64_array(nvroot,
			ZPOOL_CONFIG_VDEV_STATS, (uint64_t **)&vs, &c);
		pool_health = zpool_state_to_name(vs->vs_state, vs->vs_aux);
		
		(void) nvlist_lookup_uint64_array(nvroot,
		    ZPOOL_CONFIG_SCAN_STATS, (uint64_t **)&ps, &c);
		memset(scan_buf, 0, 1024);
		pt_get_scan_status(ps, scan_buf);
		
		memset(pool_name, 0, 128);
		sprintf(pool_name, "Resource/Pool/%s", zpool_get_name(zhp));
		
		(void) topo_fru_setime(pool_name, SXML_CRITICAL,
			pool_health, scan_buf, NULL, NULL);
		
		pt_send_snmptrap(ptp->pt_hdl, ptp->pt_xprt, "pool", "trapinfo",
			ena, path, zpool_get_name(zhp), health, locate_path);
		if (locate_path != NULL)
			free(locate_path);
		
		syslog(LOG_ERR, "pool: %s not healty.\n",
			zpool_get_name(zhp));
	} else {
		memset(pool_name, 0, 128);
		sprintf(pool_name, "Resource/Pool/%s", zpool_get_name(zhp));
		topo_fru_cleartime(pool_name, SXML_CRITICAL);
	}
	zpool_close(zhp);

	return 0;
}

static void
pt_pool_check(fmd_hdl_t *hdl)
{
	ck_cbdata_t cbdata;
	pool_transport_t *ptp = fmd_hdl_getspecific(hdl);
	libzfs_handle_t *zhdl = ptp->pt_zhdl;

	cbdata.hdl = hdl;
	(void) zpool_iter(zhdl, pt_check_pool_status, &cbdata);
}

static void
pt_timeout(fmd_hdl_t *hdl, id_t id, void *data)
{
	pool_transport_t *ptp;

	ptp = fmd_hdl_getspecific(hdl);
	ptp->pt_hdl = hdl;

	pt_pool_check(hdl);
	(void) topo_fru_hash_clear_flag("pool");
	
	ptp->pt_timer = fmd_timer_install(hdl, NULL, NULL, ptp->pt_interval);
	ptp->pt_status_changed = B_FALSE;
}

/*
 * Called when the topology may have changed.  We want to examine all disks in
 * case a new one has been inserted, but we don't want to overwhelm the system
 * in the event of a flurry of topology changes, as most likely only a small
 * number of disks are changing.  To avoid this, we set the timer for a small
 * but non-trivial interval (by default 1 minute), and ignore intervening
 * changes during this period.  This still gives us a reasonable response time
 * to newly inserted devices without overwhelming the system if lots of hotplug
 * activity is going on.
 */
/*ARGSUSED*/
static void
pt_status_change(fmd_hdl_t *hdl, topo_hdl_t *thp)
{
	pool_transport_t *ptp = fmd_hdl_getspecific(hdl);;
	static hrtime_t time;
	hrtime_t time1;
	uint64_t deleta;

	time1 = gethrtime();
	deleta = time1 - time;
	
	if (deleta > 0ull) {
		time = time1;
		pt_create_fsxml_file();
		pt_create_luxml_file();
		pt_walk_zfs_dataset(hdl, ptp);
		pt_close_fsxml_file();
		pt_close_luxml_file();
//		system("/usr/local/sbin/zpool status -x");
	}

	if (ptp->pt_status_changed)
		return;

	fmd_timer_remove(hdl, ptp->pt_timer);
	ptp->pt_timer = fmd_timer_install(hdl, NULL, NULL,
	    fmd_prop_get_int64(hdl, "min-interval"));
	ptp->pt_status_changed = B_TRUE;
	syslog(LOG_INFO, "pt_status_changed\n");
}

static void
pt_set_luname(xmlNodePtr node, char *strval, stmfGuidList *luList)
{
	stmfLogicalUnitProperties luProps;
	luResource hdl = NULL;
	//int ret = 0;
	char propVal[MAXNAMELEN];
	size_t propValSize = sizeof (propVal);
	int stmfRet;
	char *status = NULL;
	char *datafile = NULL;
	char *datafile_match = NULL;
	char *ActHostid = NULL;
	boolean_t match = B_FALSE;
	char sGuid[33];
	int i, j;

	for (j = 0; j < luList->cnt; j++) {

		if ((stmfRet = stmfGetLuResource(&(luList->guid[j]), &hdl))
		    != STMF_STATUS_SUCCESS) {
			switch (stmfRet) {
				case STMF_ERROR_BUSY:
					syslog(LOG_ERR, "%s: resource busy\n", PT_CMD_NAME);
					break;
				case STMF_ERROR_PERM:
 					syslog(LOG_ERR, "%s: permission denied\n", PT_CMD_NAME);
					break;
				case STMF_ERROR_NOT_FOUND:
					/* No error here */
					continue;
					break;
				default:
					syslog(LOG_ERR, "%s: %s\n", PT_CMD_NAME,
						"get extended properties failed");
					break;
			}
			continue;
		}
		
		stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_FILENAME, propVal,
		    &propValSize);
		if (stmfRet == STMF_STATUS_SUCCESS) {
			datafile = propVal;
			if (strstr(propVal, "/dev/zvol/rdsk/") != NULL)
				datafile_match = propVal + 15;
			else
				datafile_match = propVal;
			if (strcmp(strval, datafile_match) == 0) {
				match = B_TRUE;
			} else {
				(void) stmfFreeLuResource(hdl);
				continue;
			}
		} else if (stmfRet == STMF_ERROR_NO_PROP) {
			datafile = "not set";
		} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
			datafile = "prop_unavailable_in_standby";
		} else {
			datafile = "error_retrieving_property";
		}
	
		stmfRet = stmfGetLogicalUnitProperties(
			&(luList->guid[j]), &luProps);
		if (stmfRet != STMF_STATUS_SUCCESS) {
			syslog(LOG_ERR, "%s: %s  get properties failed",
		    PT_CMD_NAME, strval);
			if (match == B_FALSE) {
				(void) stmfFreeLuResource(hdl);
				continue;
			}
		} else {
			datafile = luProps.alias;
			if (strstr(datafile, "/dev/zvol/rdsk/") != NULL)
				datafile_match = datafile + 15;
			else
				datafile_match = datafile;
			if (match == B_FALSE && luProps.alias[0] != 0 &&
				strcmp(strval, datafile_match) != 0) {
				(void) stmfFreeLuResource(hdl);
				continue;
			}
			switch (luProps.status) {
				case STMF_LOGICAL_UNIT_ONLINE:
					status = "Online";
					break;
				case STMF_LOGICAL_UNIT_OFFLINE:
					status = "Offline";
					break;
				case STMF_LOGICAL_UNIT_ONLINING:
					status = "Onlining";
					break;
				case STMF_LOGICAL_UNIT_OFFLINING:
					status = "Offlining";
					break;
				case STMF_LOGICAL_UNIT_UNREGISTERED:
					status = "unregistered";
					break;
				default:
					status = "unknown";
					break;
			}
		}

		for (i = 0; i < 16; i++) {
			(void) snprintf(&sGuid[2*i], 3, "%02x", luList->guid[j].guid[i]);
		}
		sGuid[32] = '\0';
		xmlSetProp(node, (xmlChar *)"guid", (xmlChar *)sGuid);
		xmlSetProp(node, (xmlChar *)"status", (xmlChar *)status);
		xmlSetProp(node, (xmlChar *)"datafile", (xmlChar *)datafile);
		
		stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_ACCESS_STATE, propVal,
		    &propValSize);
		if (stmfRet == STMF_STATUS_SUCCESS) {
			if (strcmp(propVal, STMF_ACCESS_ACTIVE) == 0) {
				status = "Active";
			} else if (strcmp(propVal,
			    STMF_ACCESS_ACTIVE_TO_STANDBY) == 0) {
				status = "Active->Standby";
			} else if (strcmp(propVal, STMF_ACCESS_STANDBY) == 0) {
				status = "Standby";
				stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_ACTIVE_HOST_ID, propVal,
					&propValSize);
				if (stmfRet == STMF_STATUS_SUCCESS) {
					ActHostid = propVal;
				}
			} else if (strcmp(propVal, STMF_ACCESS_STANDBY_TO_ACTIVE) == 0) {
				status = "Standby->Active";
			} else {
				status = "Unknown";
			}
		} else if (stmfRet == STMF_ERROR_NO_PROP) {
			status = "not set";
		} else {
			status = "error_retrieving_property";
		}
		xmlSetProp(node, (xmlChar *)"state", (xmlChar *)status);
		xmlSetProp(node, (xmlChar *)"activeid", (xmlChar *)ActHostid);
		(void) stmfFreeLuResource(hdl);
		break;
	}
	if (j == luList->cnt) {
		xmlSetProp(node, (xmlChar *)"guid", NULL);
		xmlSetProp(node, (xmlChar *)"status", NULL);
		xmlSetProp(node, (xmlChar *)"datafile", NULL);
		xmlSetProp(node, (xmlChar *)"state", NULL);
		xmlSetProp(node, (xmlChar *)"activeid", NULL);
	}
	return;
}


static int
pt_set_callback(zfs_handle_t *zhp, int depth, void *data, stmfGuidList *luList)
{
	char buf[ZFS_MAXPROPLEN];
	zprop_get_cbdata_t *cbp = data;
	nvlist_t *user_props = zfs_get_user_props(zhp);
	zprop_list_t *pl = cbp->cb_proplist;
	nvlist_t *propval;
	char *strval;
	xmlNodePtr node = NULL;
	boolean_t setLuName = B_FALSE;
	boolean_t isVolume = B_FALSE;
	boolean_t isFs = B_FALSE;

	for (; pl != NULL; pl = pl->pl_next) {
		/*
		 * Skip the special fake placeholder.  This will also skip over
		 * the name property when 'all' is specified.
		 */
		if (pl->pl_prop == ZFS_PROP_NAME &&
		    pl == cbp->cb_proplist)
			continue;

		if (pl->pl_prop != ZPROP_INVAL) {
			if (zfs_prop_get(zhp, pl->pl_prop, buf,
			    sizeof (buf), NULL, NULL, 0, B_FALSE) != 0)
				strval = "-";
			else 
				strval = buf;
		} else {
			if (nvlist_lookup_nvlist(user_props,
			    pl->pl_user_prop, &propval) != 0) {
				strval = "-";
			} else {
				verify(nvlist_lookup_string(propval,
				    ZPROP_VALUE, &strval) == 0);
			}		
		}
		
		if (!setLuName && strcmp("type", zfs_prop_to_name(pl->pl_prop)) == 0 &&
			strcmp("volume", strval) == 0) {
			isVolume = B_TRUE;
			node = xmlNewChild(pt_lu_root_node, NULL, (xmlChar *)"lu", NULL);
			xmlSetProp(node, (xmlChar *)"hostname", (xmlChar *)hostname);
		} else if (!isVolume && !isFs) {
			isFs = B_TRUE;
			node = xmlNewChild(pt_fs_root_node, NULL, (xmlChar *)"fs", NULL);
			xmlSetProp(node, (xmlChar *)"hostname", (xmlChar *)hostname);
		}
		
		xmlSetProp(node, (xmlChar *)zfs_prop_to_name(pl->pl_prop), (xmlChar *)strval);
		
		if (!setLuName && isVolume &&
			strcmp("name", zfs_prop_to_name(pl->pl_prop)) == 0) {
			pt_set_luname(node, strval, luList);
			setLuName = B_TRUE;
		}
			
	}
	
	return (0);
}


static int
pt_walk_zfs_dataset(fmd_hdl_t *hdl, pool_transport_t *ptp)
{
	zprop_get_cbdata_t cb = { 0 };
	int flags = 0;	
	int ret = 0;
	int stmfRet;
	int limit = 0;
	zprop_list_t fake_name = { 0 };
	libzfs_handle_t	*zhdl = ptp->pt_zhdl;
	stmfGuidList *luList;
	char fields[] = "type,name,available,encryption,isworm,quota,recordsize,refreservation,"
		"sharenfs,sharesmb,sync,used,volblocksize,volsize,vscan,wormreliance";

	cb.cb_sources = ZPROP_SRC_ALL;
	cb.cb_columns[0] = GET_COL_NAME;
	cb.cb_columns[1] = GET_COL_PROPERTY;
	cb.cb_columns[2] = GET_COL_VALUE;
	cb.cb_columns[3] = GET_COL_SOURCE;
	cb.cb_type = ZFS_TYPE_DATASET;
	
	
	if (zprop_get_list(zhdl, fields, &cb.cb_proplist, ZFS_TYPE_DATASET)
	    != 0) {
		syslog (LOG_ERR, "zfs get list failed");
		return (-1);
	}

	if (cb.cb_proplist != NULL) {
		fake_name.pl_prop = ZFS_PROP_NAME;
		fake_name.pl_width = strlen("NAME");
		fake_name.pl_next = cb.cb_proplist;
		cb.cb_proplist = &fake_name;
	}

	cb.cb_first = B_TRUE;

	if ((stmfRet = stmfGetLogicalUnitList(&luList))
	    != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_SERVICE_NOT_FOUND:
				syslog(LOG_ERR, "%s: %s\n", PT_CMD_NAME,
					"STMF service not found");
				break;
			case STMF_ERROR_BUSY:
				syslog(LOG_ERR, "%s: %s\n", PT_CMD_NAME,
					"resource busy");
				break;
			case STMF_ERROR_PERM:
				syslog(LOG_ERR, "%s: %s\n", PT_CMD_NAME,
					"permission denied");
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				syslog(LOG_ERR, "%s: %s\n", PT_CMD_NAME,
					"STMF service version incorrect");
				break;
			default:
				syslog(LOG_ERR, "%s: %s\n", PT_CMD_NAME,
					"list failed");
				break;
		}
		return (-1);
	}
	
	/* run for each object */
	ret = pt_zfs_for_each(flags, ZFS_TYPE_DATASET, NULL,
	    &cb.cb_proplist, limit, pt_set_callback, &cb, zhdl, luList);

	if (cb.cb_proplist == &fake_name)
		zprop_free_list(fake_name.pl_next);
	else
		zprop_free_list(cb.cb_proplist);

	stmfFreeMemory(luList);
	return ret;
}


static void
pt_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	pool_transport_t *ptp;

	ptp = fmd_hdl_getspecific(hdl);
	ptp->pt_hdl = hdl;

	pt_create_fsxml_file();
	pt_create_luxml_file();
	pt_walk_zfs_dataset(hdl, ptp);
	pt_close_fsxml_file();
	pt_close_luxml_file();

	pt_pool_check(hdl);
	
//	system("/usr/local/sbin/zpool status -x");
}

static const fmd_prop_t fmd_props[] = {
	{ "interval", FMD_TYPE_TIME, "1h" },
	{ "min-interval", FMD_TYPE_TIME, "1min" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t fmd_ops = {
	pt_recv,		/* fmdo_recv */
	pt_timeout,		/* fmdo_timeout */
	NULL, 			/* fmdo_close */
	NULL,			/* fmdo_stats */
	NULL,			/* fmdo_gc */
	NULL,			/* fmdo_send */
	pt_status_change,/* fmdo_status_change */
};

static const fmd_hdl_info_t fmd_info = {
	"Pool Transport Agent", "1.0", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	pool_transport_t *ptp;
	libzfs_handle_t *zhdl;

	if ((zhdl = libzfs_init()) == NULL)
		return;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0) {
		libzfs_fini(zhdl);
		return;
	}
	if (gethostname(hostname, sizeof(hostname)) < 0) {
			syslog(LOG_ERR, "get hostname failed\n");
			return;
	}

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC,
	    sizeof (pt_stats) / sizeof (fmd_stat_t),
	    (fmd_stat_t *)&pt_stats);

	ptp = fmd_hdl_zalloc(hdl, sizeof (pool_transport_t), FMD_SLEEP);
	fmd_hdl_setspecific(hdl, ptp);

	ptp->pt_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY, NULL, NULL);
	ptp->pt_interval = fmd_prop_get_int64(hdl, "interval");
	ptp->pt_zhdl = zhdl;
	
	ptp->pt_timer = fmd_timer_install(hdl, NULL, NULL, 0);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	pool_transport_t *ptp;

	ptp = fmd_hdl_getspecific(hdl);
	if (ptp != NULL) {
		fmd_xprt_close(hdl, ptp->pt_xprt);
		libzfs_fini(ptp->pt_zhdl);
		fmd_hdl_free(hdl, ptp, sizeof (pool_transport_t));
	}
}
