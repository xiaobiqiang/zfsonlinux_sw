#include <unistd.h>
#include <ctype.h>
//#include <umem.h>
#include <fmd_api.h>
#include <libtopo.h>
#include <topo_hc.h>
#include <topo_mod.h>
#include <limits.h>
#include <string.h>
#include <libnvpair.h>
#include <sys/fm/protocol.h>
#include <fanpsu_enum.h>
#include "fanpsu-transport.h"

static void fpt_timeout(fmd_hdl_t *hdl, unsigned int id, void *data);

static const fmd_prop_t fmd_fanpsu_props[] = {
	{ "interval", FMD_TYPE_TIME, "10sec" },
	{ "min-interval", FMD_TYPE_TIME, "1min" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t fmd_fanpsu_ops = {
	NULL,			/* fmdo_recv */
	fpt_timeout,		/* fmdo_timeout */
	NULL, 			/* fmdo_close */
	NULL,			/* fmdo_stats */
	NULL,			/* fmdo_gc */
	NULL,			/* fmdo_send */
	NULL,		/* fmdo_topo_change */
};

static const fmd_hdl_info_t fmd_info = {/*{{{*/
	"Fanpsu Transport Agent", "1.0", &fmd_fanpsu_ops, fmd_fanpsu_props
};

static struct fpt_stat {
	fmd_stat_t dropped;
} fpt_stats = {
	{ "dropped", FMD_TYPE_UINT64, "number of dropped ereports" }
};
	
static void fpt_post_ereport(fmd_hdl_t *hdl, fmd_xprt_t *xprt, const char *protocol, const char *faultname,
	uint64_t ena, nvlist_t *detector, nvlist_t *payload){

	nvlist_t *nvl;
	int e = 0;
	char fullclass[PATH_MAX];

	snprintf(fullclass, sizeof (fullclass), "%s.%s.%s", FM_EREPORT_CLASS, protocol, faultname);

	if(0 == nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)){
		e |= nvlist_add_string(nvl, FM_CLASS, fullclass);
		e |= nvlist_add_uint8(nvl, FM_VERSION, FM_EREPORT_VERSION);
		e |= nvlist_add_uint64(nvl, FM_EREPORT_ENA, ena);
		e |= nvlist_add_nvlist(nvl, FM_EREPORT_DETECTOR, detector);
		e |= nvlist_merge(nvl, payload, 0);

		if(e == 0){
			fmd_xprt_post(hdl, xprt, nvl, 0);
		}else{
			nvlist_free(nvl);
			fpt_stats.dropped.fmds_value.ui64++;
		}
	}else{
		fpt_stats.dropped.fmds_value.ui64++;
	}
}


static int fpt_check(topo_hdl_t *thp, tnode_t *node, void *arg){
	nvlist_t *fmri;
	nvlist_t *resault;
	int err;
	fanpsu_monitor_t *fpmp = arg;
	uint64_t ena;
	char *name = topo_node_name(node);

	if(strcmp(name, FAN) && strcmp(name, PSU)) 
		return TOPO_WALK_NEXT;

#if 0
	printf(" ## name ## %s ##\n", topo_node_name(node));
#endif

	if(0 != topo_node_resource(node, &fmri, &err)){
		fmd_hdl_error(fpmp->fpm_hdl, "failed to get fmri: %s\n", topo_strerror(err));
		return TOPO_WALK_ERR;
	}

	ena = fmd_event_ena_create(fpmp->fpm_hdl);

	if(-1 == topo_method_invoke(node, TOPO_METH_STATUS, TOPO_METH_FANPSU_VERSION,
		NULL, &resault, &err)){
		syslog(LOG_ERR, "failed to run topo_method_invoke TOPO_METH_FANPSU_UPDATE_STATE in fpt_check\n");
		return TOPO_WALK_NEXT;
	}else
		syslog(LOG_ERR, "state update successed.\n");

	if(resault){
		fpt_post_ereport(fpmp->fpm_hdl, fpmp->fpm_xprt, "ceresdata", "trapinfo", ena, fmri, resault);
	}else{
		syslog(LOG_ERR, "There is no warning from fan and psu.\n");
	}
	nvlist_free(fmri);

	return TOPO_WALK_NEXT;
}

/*
 * Periodic timeout.  Iterates over all hc:// topo nodes, calling
 * lt_check_links() for each one.
 */
/*ARGSUSED*/
static void fpt_timeout(fmd_hdl_t *hdl, unsigned int id, void *data){

	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;
	fanpsu_monitor_t *fpmp = fmd_hdl_getspecific(hdl);
#if 0
	static int count = 0;
	printf("      ########    monitor count    %-5d    #########\n\n", count++);
#endif
	fpmp->fpm_hdl = hdl;

	thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION);
	if(NULL == (twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC, fpt_check, fpmp, &err))){
		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_error(hdl, "failed to get topology: %s\n",
		    topo_strerror(err));
		return;
	}

	if(TOPO_WALK_ERR == topo_walk_step(twp, TOPO_WALK_CHILD)){
		topo_walk_fini(twp);
		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_error(hdl, "failed to walk topology\n");
		return;
	}

	topo_walk_fini(twp);

	fmd_hdl_topo_rele(hdl, thp);

	fpmp->fpm_timer = fmd_timer_install(hdl, NULL, NULL, fpmp->fpm_interval);
}

void _fmd_init(fmd_hdl_t *hdl){
	fanpsu_monitor_t *fpmp;

	syslog(LOG_ERR,"fanpsu transport start.\n");
	if(0 != fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info)){
		syslog(LOG_ERR,"failed to run fmd_hdl_register in Link Transport Agent\n");
		return;
	}

	if(NULL == fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (fpt_stats) / sizeof (fmd_stat_t), (fmd_stat_t *)&fpt_stats)){
		syslog(LOG_ERR,"failed to run fmd_stat_create in Fanpsu Transport Agent\n");
		return;

	}

	fpmp = fmd_hdl_zalloc(hdl, sizeof (fanpsu_monitor_t), FMD_SLEEP);
	fmd_hdl_setspecific(hdl, fpmp);

	fpmp->fpm_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY, NULL, NULL);
	fpmp->fpm_interval = fmd_prop_get_int64(hdl, "interval");
	fpmp->fpm_timer = fmd_timer_install(hdl, NULL, NULL, 0);

	return;
}

void _fmd_fini(fmd_hdl_t *hdl){
	fanpsu_monitor_t *fpmp;

	fpmp = fmd_hdl_getspecific(hdl);
	if (fpmp) {
		fmd_xprt_close(hdl, fpmp->fpm_xprt);
		fmd_hdl_free(hdl, fpmp, sizeof (*fpmp));
	}

}
