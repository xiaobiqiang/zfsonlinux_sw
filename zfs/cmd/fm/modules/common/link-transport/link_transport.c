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
#include <libzfs.h>

/*
 * there is some macro we need to run callback methods which in topo link nodes.
 * but I don't want to change fmd's headers so if you change any definition in
 * /usr/src/lib/fm/topo/modules/common/link copy link_enum.h to here.
 * -I/data/home/lhl/workspace/nv129-git.work/proto/root_i386/usr/include you
 * know it.
 */
#include "link_enum.h"

#define THINLUN_CHECK_FLAG	1
#define QUOTA_CHECK_FLAG	2
#define AVS_CHECK_FLAG		4

typedef enum avs_state {
	logging = 0,
	needsync,
	syncing,
	replicating,
	unconfigured
} avs_state_t;

const char *avs_state_string[] = {
	"logging",
	"need_sync", 
	"syncing", 
	"replicating", 
	"unconfigured" 
};	

#if 1/*{{{*/
static struct lt_stat {
	fmd_stat_t dropped;
} lt_stats = {
	{ "dropped", FMD_TYPE_UINT64, "number of dropped ereports" }
};

typedef struct link_monitor{/*{{{*/

	fmd_hdl_t	*lm_hdl;
	fmd_xprt_t	*lm_xprt;
	id_t		lm_timer;
	hrtime_t	lm_interval;
	boolean_t	lm_timer_istopo;
}link_monitor_t;/*}}}*/

void log_null(FILE *file, ...){}

extern void zpool_check_thin_luns(zfs_thinluns_t **statp);
static uint64_t thinlunandquanta_check_time = 0;
static uint32_t check_map = 0;
static uint32_t check_interval = 60;
	
static void lt_post_ereport(fmd_hdl_t *hdl, fmd_xprt_t *xprt, const char *protocol, const char *faultname,
	uint64_t ena, nvlist_t *detector, nvlist_t *payload){

	nvlist_t *nvl;
	int e = 0;
	char fullclass[PATH_MAX];

	snprintf(fullclass, sizeof (fullclass), "%s.%s.%s", FM_EREPORT_CLASS, protocol, faultname);

	if(nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) == 0){
		e |= nvlist_add_string(nvl, FM_CLASS, fullclass);
		e |= nvlist_add_uint8(nvl, FM_VERSION, FM_EREPORT_VERSION);
		e |= nvlist_add_uint64(nvl, FM_EREPORT_ENA, ena);
		e |= nvlist_add_nvlist(nvl, FM_EREPORT_DETECTOR, detector);
		e |= nvlist_merge(nvl, payload, 0);

		if(e == 0){
			fmd_xprt_post(hdl, xprt, nvl, 0);
		}else{
			nvlist_free(nvl);
			lt_stats.dropped.fmds_value.ui64++;
		}
	}else{
		lt_stats.dropped.fmds_value.ui64++;
	}
}

/*
 * Check a single topo link node for failure.  This simply invokes the link
 * status method, and generates any ereports as necessary for snmptrap and
 * infomation for GUI.
 */
#endif/*}}}*/

#if 0
void avs_check(fmd_hdl_t *hdl, link_monitor_t *lmp)
{
	static avs_state_t avs_state = unconfigured;
	avs_state_t state;
	uint64_t ena;
	FILE *fp = NULL;
	char buff[16];
	nvlist_t *fmri, *nvl;
	
	system("/usr/sbin/sndradm -P > /tmp/avs.txt");
	if ((fp = fopen("/tmp/avs.txt", "r")) == NULL)
		return;
	memset(buff, 0, 16);
	fseek(fp, -15l, SEEK_END);
	if (fread(buff, 15, 1, fp) == 0){
		fclose(fp);
		return;
	}
	fclose(fp);
	
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
		nvlist_alloc(&fmri, NV_UNIQUE_NAME, 0) != 0 )
		return;

	if (strstr(buff, "logging") != NULL)
		state = logging;
	else if (strstr(buff, "need sync") != NULL)
		state = needsync;
	else if (strstr(buff, "syncing") != NULL)
		state = syncing;
	else if (strstr(buff, "replicating") != NULL)
		state = replicating;
	else 
		state = unconfigured;

	if (state != avs_state && 
		(state == logging || state == needsync)) {

		if (nvlist_add_string(fmri, "detector", "link transport") != 0 ||
			nvlist_add_string(nvl, TOPO_LINK_TYPE, "avs_warning") != 0 ||
			nvlist_add_string(nvl, TOPO_LINK_NAME, "avs_state") != 0 ||
			nvlist_add_uint32(nvl, TOPO_LINK_STATE, 2) != 0 ||
			nvlist_add_string(nvl, TOPO_LINK_STATE_DESC, avs_state_string[state]) != 0) {
				nvlist_free(nvl);
				nvlist_free(fmri);
				return;
		}

		lt_post_ereport(lmp->lm_hdl, lmp->lm_xprt, "ceresdata", "trapavs", ena, fmri, nvl);
	}
	
	avs_state = state;
	nvlist_free(nvl);
	nvlist_free(fmri);
}
#endif
void zpool_thinlun_check(fmd_hdl_t *hdl, link_monitor_t *lmp)
{
	int i;
	zfs_thinluns_t *statp = NULL;
	char buf[512]={0};
	uint64_t ena = 0;
	nvlist_t *fmri, *nvl;
	FILE *fp;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
		nvlist_alloc(&fmri, NV_UNIQUE_NAME, 0) != 0 )
		return;
	if ((fp = fopen("/tmp/thinlun.tmp", "w")) == NULL)
		return;
	zpool_check_thin_luns(&statp);
	if (statp != NULL) {
	   for (i = 0; i < statp->pool_number; i ++) {
	   		memset(buf, 0, 512);
			pool_thinluns_stat_t *thinlun_stat = &statp->pools[i];
			syslog(LOG_ERR, "poolsize = %lu, lun_size = %lu,pool_name = %s",
				thinlun_stat->pool_size,thinlun_stat->pool_thinlun_size,
				thinlun_stat->pool_name);
			snprintf(buf,512,"poolsize=%lu,lun_size=%lu,pool_name=%s",
				thinlun_stat->pool_size,thinlun_stat->pool_thinlun_size, 
				thinlun_stat->pool_name);
			fprintf(fp, "%s %lu##\n", 
				thinlun_stat->pool_name, thinlun_stat->pool_thinlun_size);
			if (nvlist_add_string(fmri, "detector", "link transport") != 0 ||
			    nvlist_add_string(nvl, TOPO_LINK_TYPE, "thin_luns_warning") != 0 ||
			    nvlist_add_string(nvl, TOPO_LINK_NAME, thinlun_stat->pool_name) != 0 ||
			    nvlist_add_uint32(nvl, TOPO_LINK_STATE, 0) != 0 ||
			    nvlist_add_string(nvl, TOPO_LINK_STATE_DESC, buf) != 0) {
					nvlist_free(nvl);
					nvlist_free(fmri);
					return;
			}
			lt_post_ereport(lmp->lm_hdl, lmp->lm_xprt, "ceresdata", "trapinfo", ena, fmri, nvl);

	   }
	   free(statp->pools);
	   free(statp);
	} 
				
	fclose(fp);
	(void) rename("/tmp/thinlun.tmp", "/tmp/thinlun.txt");
	nvlist_free(nvl);
	nvlist_free(fmri);	
}

#if 0
double get_number(char *q)
{

    double fq=0;
    double t=1;
    char *p;

	if(q == NULL)
		return 0;

    p = q;
    while (*p != '\0') {
            if(*p == 'K'){
                    t = 1000;
                    *p = '\0';
            }
            else if(*p == 'M') {
                    t = 1000000;
                    *p = '\0';
            }
            else if(*p == 'G') {
                    t = 1000000000;
                    *p = '\0';
            }
			else if(*p == 'T') {
			        t = 1000000000000;
                    *p = '\0';
            }
            p++;
    }

    fq = atoi(q);
    fq = fq*t;

    return fq;
}
void softquota_item_check(fmd_hdl_t *hdl, link_monitor_t *lmp, char *buf)
{
	uint64_t ena;
	nvlist_t *fmri, *nvl;
	int f1 = 1,f2 = 1, f3 = 1;
	char *q, *sq, *u, *p;
	int t = 0;
	double dq, dsq, du;
	char buffer[512] = {0};

	memcpy(buffer, buf, 512);
	for(p=buffer;*p!='\0';p++) {
		if(*p=='\t')
			*p='_';
	}

	p=buf;
    while(*p != '#') {
            if(*p == '\t'){
                    t++;
                    *p = '\0';
            }
            if(t == 2 && f1){
                    f1 = 0;
                    q = p+1;
            }
            if(t == 3 && f2) {
                    sq = p + 1;
                    f2 = 0;
            }
            if(t == 4 && f3) {
                    u = p+1;
                    f3 = 0;
            }
            p++;
    }
    *p = '\0';
	if(strcmp(q, "none") == 0)
		dq = 1000000000000000;
	else
		dq = get_number(q);
	if(strcmp(sq, "none") == 0)
		dsq = 1000000000000000;
	else
		dsq = get_number(sq);
	du = get_number(u);

	if(du >= dq || du >= dsq) {
		/*syslog(LOG_ERR, "softquota exceed:%s\n", buffer);*/
		if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
			nvlist_alloc(&fmri, NV_UNIQUE_NAME, 0) != 0 )
			return ;

		if (nvlist_add_string(fmri, "detector", "link transport") != 0 ||
		    nvlist_add_string(nvl, TOPO_LINK_TYPE, "userquota_warning") != 0 ||
		    nvlist_add_string(nvl, TOPO_LINK_NAME, buf) != 0 ||
		    nvlist_add_uint32(nvl, TOPO_LINK_STATE, 0) != 0 ||
		    nvlist_add_string(nvl, TOPO_LINK_STATE_DESC, buffer) != 0) {
				nvlist_free(nvl);
				nvlist_free(fmri);
				return ;
		}
		lt_post_ereport(lmp->lm_hdl, lmp->lm_xprt, "ceresdata", "trapinfo", ena, fmri, nvl);
		
		nvlist_free(nvl);
		nvlist_free(fmri);	
	}

}

void quota_item_check(fmd_hdl_t *hdl, link_monitor_t *lmp, char *buf)
{
	uint64_t ena;
	nvlist_t *fmri, *nvl;
	int f1 = 1,f2 = 1;
	char *q,*u, *p;
	int t = 0;
	double dq, dsq, du;
	char buffer[512] = {0};

	memcpy(buffer, buf, 512);

	for(p=buffer;*p!='\0';p++) {
		if(*p=='\t')
			*p='_';
	}	

	p=buf;
    while(*p != '#') {
            if(*p == '\t'){
                    t++;
                    *p = '\0';
            }
            if(t == 1 && f1){
                    f1 = 0;
                    q = p+1;
            }
            if(t == 2 && f2) {
                    u = p + 1;
                    f2 = 0;
            }
            p++;
    }
    *p = '\0';
	if(strcmp(q, "none") == 0)
		dq = 1000000000000000;
	else
		dq = get_number(q);
	du = get_number(u);

	if(du >= dq) {
		/*syslog(LOG_ERR, "quota exceed:%s\n", buffer);*/
		if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
			nvlist_alloc(&fmri, NV_UNIQUE_NAME, 0) != 0 )
			return;

		if (nvlist_add_string(fmri, "detector", "link transport") != 0 ||
		    nvlist_add_string(nvl, TOPO_LINK_TYPE, "quota_warning") != 0 ||
		    nvlist_add_string(nvl, TOPO_LINK_NAME, buf) != 0 ||
		    nvlist_add_uint32(nvl, TOPO_LINK_STATE, 0) != 0 ||
		    nvlist_add_string(nvl, TOPO_LINK_STATE_DESC, buffer) != 0) {
				nvlist_free(nvl);
				nvlist_free(fmri);
				return;
		}
		lt_post_ereport(lmp->lm_hdl, lmp->lm_xprt, "ceresdata", "trapinfo", ena, fmri, nvl);
		
		nvlist_free(nvl);
		nvlist_free(fmri);	
	}

}

int quota_check(fmd_hdl_t *hdl, link_monitor_t *lmp)
{
	FILE *fp;
	char buff[512];
	
	system("/gui/Java_Shell/userquota.sh");
	system("/gui/Java_Shell/quota.sh");
	fflush(NULL);
	if((fp = fopen("/tmp/userquota.txt", "r")) == NULL) {
			syslog(LOG_ERR, "open /tmp/userquota.txt error\n");
			return -1;
	}
	while(NULL != fgets(buff, 512, fp)) {
		softquota_item_check(hdl, lmp, buff);
		memset(buff, 0, 512);
	}
	fclose(fp);

	if((fp = fopen("/tmp/quota.txt", "r")) == NULL) {
			syslog(LOG_ERR, "open /tmp/quota.txt error\n");
			return -1;
	}
	memset(buff, 0, 512);
	while(NULL != fgets(buff, 512, fp)) {
		quota_item_check(hdl, lmp, buff);
		memset(buff, 0, 512);
	}
	fclose(fp);
	return 0;

}
#endif
static void get_check_conf(void)
{
	FILE *cfg = NULL;
	char s1[32], s2[32];

	memset(s1, 0, 32);
	memset(s2, 0, 32);
	if ((cfg = fopen("/etc/link_transport.conf", "r")) != NULL) {
		while (fscanf(cfg, "%31s%31s", s1, s2) != EOF) {
			if (s1[0] == '\0' || s2[0] == '\0')
				continue;
			if ((strcmp(s1, "quota_check")) == 0) {
				if ((strcmp(s2, "yes")) == 0)
					check_map |= QUOTA_CHECK_FLAG;
			} else if ((strcmp(s1, "thinlun_check")) == 0) {
				if ((strcmp(s2, "yes")) == 0)
						check_map |= THINLUN_CHECK_FLAG;
			} else if ((strcmp(s1, "avs_check")) == 0) {
				if ((strcmp(s2, "yes")) == 0)
						check_map |= AVS_CHECK_FLAG;
			} else if ((strcmp(s1, "check_interval")) == 0) {
				check_interval = atoi(s2);
				if (check_interval == 0)
					check_interval = 60;
				else
					check_interval = check_interval*6;
			}
			memset(s1, 0, 32);
			memset(s2, 0, 32);
		}
		fclose(cfg);
	}

}

static int lt_check_links(topo_hdl_t *thp, tnode_t *node, void *arg){/*{{{*/

	nvlist_t *result;
	nvlist_t *fmri;
	nvlist_t *nvl;
	nvlist_t **nvl_array = NULL;
	uint_t nvl_len = 0;
	int i;
	int err;
	link_monitor_t *lmp = arg;
	uint64_t ena;
	char *name = topo_node_name(node);
	topo_instance_t inst = topo_node_instance(node);

	if(strcmp(name, FC_LINK) && strcmp(name, ETHERNET_LINK) 
		&& strcmp(name, SAS_IPORT) && strcmp(name, HEART_LINK))
		return TOPO_WALK_NEXT;
	LOG(" ## name ## %s ##\n", topo_node_name(node));

	if(topo_node_resource(node, &fmri, &err) != 0){
		fmd_hdl_error(lmp->lm_hdl, "failed to get fmri: %s\n", topo_strerror(err));
		return TOPO_WALK_ERR;
	}
/*
	nvlist_print(log_file, fmri);
	if(topo_hdl_nvalloc(thp, &in, NV_UNIQUE_NAME) != 0){
		nvlist_free(fmri);
		return TOPO_WALK_ERR;
	}
	nvlist_free(in);
*/

	/*
	 * Try to invoke the method.  If this fails (most likely because the
	 * method is not supported), then ignore this node.
	 */
	if(topo_method_invoke(node, TOPO_METH_LINK_STATUS_CHANGED, TOPO_METH_LINK_VERSION, NULL, &result, &err) == -1){
		LOG("failed to run topo_method_invoke TOPO_METH_LINK_STATUS_CHANGED in lt_check_links\n");
		nvlist_free(fmri);
		return TOPO_WALK_NEXT;
	}

	ena = fmd_event_ena_create(lmp->lm_hdl);
	if(result){

		LOG("LHL ADD ++ change happened ena is ## %016llx\n", ena);
		/* do some inform hear */
		/*nvlist_print(log_file, result);*/
		syslog(LOG_ERR, "linknode: %s%d state changed\n", name, inst);

		if(topo_method_invoke(node, TOPO_METH_LINK_UPDATE_STATUS, TOPO_METH_LINK_VERSION,
			result, NULL, &err) == -1){
			LOG("failed to run topo_method_invoke TOPO_METH_LINK_STATUS_CHANGED in lt_check_links\n");
			nvlist_free(result);
			return TOPO_WALK_NEXT;
		}else
			LOG("state update successed.\n");

		if(!strcmp(name, SAS_IPORT)){
			/* route the error event to snmp-transport */
			nvlist_lookup_nvlist_array(result, DEV_ACTION_ARRAY, &nvl_array, &nvl_len);
			for(i = 0; i < nvl_len; i++){

				nvl = nvl_array[i];
				lt_post_ereport(lmp->lm_hdl, lmp->lm_xprt, "ceresdata", "trapinfo", ena, fmri, nvl);
			}
		}else{
			lt_post_ereport(lmp->lm_hdl, lmp->lm_xprt, "ceresdata", "trapinfo", ena, fmri, result);
		}

		nvlist_free(result);
	}else
		LOG("LHL ADD ++ No No No No No No No No\n");

	nvlist_free(fmri);
#if 0/*{{{*/
	if(nvlist_lookup_nvlist(result, "faults", &faults) == 0 && nvlist_lookup_string(result, "protocol", &protocol) == 0){
		elem = NULL;
		while((elem = nvlist_next_nvpair(faults, elem)) != NULL){
			if(nvpair_type(elem) != DATA_TYPE_BOOLEAN_VALUE)
				continue;
			nvpair_value_boolean_value(elem, &fault);
			if(!fault || nvlist_lookup_nvlist(result, nvpair_name(elem), &details) != 0)
			    continue;
			fault_occur = 1;

			lt_post_ereport(lmp->lm_hdl, lmp->lm_xprt, protocol, nvpair_name(elem), ena, fmri, details);
		}
	}

#endif/*}}}*/

	return TOPO_WALK_NEXT;
}/*}}}*/

#if 1/*{{{*/
/*
 * Periodic timeout.  Iterates over all hc:// topo nodes, calling
 * lt_check_links() for each one.
 */
/*ARGSUSED*/
static void lt_timeout(fmd_hdl_t *hdl, id_t id, void *data){/*{{{*/

	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;
	link_monitor_t *lmp = fmd_hdl_getspecific(hdl);
#if 1
	static int count = 0;
	LOG("      ########    monitor count    %-5d    #########\n\n", count++);
#endif
	lmp->lm_hdl = hdl;

	thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION);
	if((twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC, lt_check_links, lmp, &err)) == NULL){
		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_error(hdl, "failed to get topology: %s\n",
		    topo_strerror(err));
		return;
	}

	if(topo_walk_step(twp, TOPO_WALK_CHILD) == TOPO_WALK_ERR){
		topo_walk_fini(twp);
		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_error(hdl, "failed to walk topology\n");
		return;
	}

	topo_walk_fini(twp);
	thinlunandquanta_check_time++;
	if (thinlunandquanta_check_time % check_interval == 0) {
		if (check_map & THINLUN_CHECK_FLAG)
			zpool_thinlun_check(hdl, lmp);
#if 0
		if (check_map & QUOTA_CHECK_FLAG)
			quota_check(hdl, lmp);
		if (check_map & AVS_CHECK_FLAG)
			avs_check(hdl, lmp);
#endif
	}
	
	fmd_hdl_topo_rele(hdl, thp);

	lmp->lm_timer = fmd_timer_install(hdl, NULL, NULL, lmp->lm_interval);
}/*}}}*/

static const fmd_prop_t fmd_link_props[] = {/*{{{*/
/*	{ "interval", FMD_TYPE_TIME, "10sec" }, */
	{ "interval", FMD_TYPE_TIME, "10sec" },
	{ "min-interval", FMD_TYPE_TIME, "1min" },
	{ NULL, 0, NULL }
};/*}}}*/

static const fmd_hdl_ops_t fmd_link_ops = {/*{{{*/
	NULL,			/* fmdo_recv */
	lt_timeout,		/* fmdo_timeout */
	NULL, 			/* fmdo_close */
	NULL,			/* fmdo_stats */
	NULL,			/* fmdo_gc */
	NULL,			/* fmdo_send */
	NULL,		/* fmdo_topo_change */
};/*}}}*/

static const fmd_hdl_info_t fmd_info = {/*{{{*/
	"Link Transport Agent", "1.0", &fmd_link_ops, fmd_link_props
};/*}}}*/

void _fmd_init(fmd_hdl_t *hdl){/*{{{*/

	link_monitor_t *lmp;

	DMESG("LHL ADD ++ Link Transport Agent V1.0\n");
	if((log_file = fopen("/var/log/wire_transport.log", "w")) == NULL){
		DMESG("open log file /var/log/wire_transport.log Error\n");
		return;
	}
	get_check_conf();

	if(fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0){
		LOG("failed to run fmd_hdl_register in Link Transport Agent\n");
		return;
	}

	fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (lt_stats) / sizeof (fmd_stat_t), (fmd_stat_t *)&lt_stats);

	lmp = fmd_hdl_zalloc(hdl, sizeof (link_monitor_t), FMD_SLEEP);
	fmd_hdl_setspecific(hdl, lmp);

	lmp->lm_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY, NULL, NULL);
	lmp->lm_interval = fmd_prop_get_int64(hdl, "interval");

	/*
	 * Call our initial timer routine.  This will do an initial check of all
	 * the link state, and then start the periodic timeout.
	 */
	lmp->lm_timer = fmd_timer_install(hdl, NULL, NULL, 0);
}/*}}}*/

void _fmd_fini(fmd_hdl_t *hdl){/*{{{*/

	link_monitor_t *lmp;

	fclose(log_file);
	lmp = fmd_hdl_getspecific(hdl);
	if (lmp) {
		fmd_xprt_close(hdl, lmp->lm_xprt);
		fmd_hdl_free(hdl, lmp, sizeof (*lmp));
	}
}/*}}}*/
#endif/*}}}*/
