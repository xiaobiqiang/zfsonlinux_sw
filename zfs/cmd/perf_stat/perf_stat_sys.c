#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stddef.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include "parse_cmd.h"
#include "perf_stat.h"
#include "perf_util.h"

#define	SYS_TMP	    "/tmp/sys.tmp"

struct per_sys_stat {
    char        hostname[32];
    uint64_t	nic_reads;
    uint64_t	nic_writes;
    uint64_t	nic_nread;
    uint64_t	nic_nwritten;
	uint64_t    fc_reads;
    uint32_t    fc_writes;
    uint64_t    fc_nread;
    uint64_t    fc_nwritten;
    uint64_t    nfs_nread;
    uint64_t    nfs_nwritten;
	struct per_sys_stat	*next;
};

struct sys_stat_snapshot {
	uint32_t	timestamp;
	struct per_sys_stat	*head;
};

struct sys_stat_snapshot	*sys_stat_snapshot_minute = NULL;
struct sys_stat_snapshot	*sys_stat_snapshot_hour = NULL;
struct sys_stat_snapshot	*sys_stat_snapshot_day = NULL;
struct sys_stat_snapshot	*sys_stat_snapshot_week = NULL;
struct sys_stat_snapshot	*sys_stat_snapshot_month = NULL;
struct sys_stat_snapshot	*sys_stat_snapshot_year = NULL;

static uint32_t
get_hostname(char *name)
{
	char command[64];
	struct parse_result *result;
	struct line_buf *line;

	snprintf(command, 64, "hostname");
	result = parse_cmd(command);
	if (result == NULL || result->head == NULL || result->head != result->tail)
		return (0);
	line = result->head;
	if (line->bufc != 1) {
		free_parse_result(result);
		return (0);
	}
	strcpy(name,line->bufv[0]);
	free_parse_result(result);
	return (0);
}

static void
free_sys_stat_snapshot(struct sys_stat_snapshot *snap)
{
	struct per_sys_stat *p = snap->head, *q;

	while (p) {
		q = p;
		p = p->next;
		free(q);
	}
	free(snap);
}

static void
sort_sys_stat_snapshot(struct sys_stat_snapshot *snap)
{
	struct per_sys_stat *list = NULL, *p, **pp;

	while (snap->head != NULL) {
		p = snap->head;
		snap->head = p->next;
		for (pp = &list;
			*pp != NULL;
			pp = &((*pp)->next)) {
			if (strcmp((*pp)->hostname, p->hostname) > 0)
				break;
		}
		p->next = *pp;
		*pp = p;
	}
	snap->head = list;
}

static struct sys_stat_snapshot *
dup_sys_stat_snapshot(struct sys_stat_snapshot *snap)
{
	struct sys_stat_snapshot *dup;
	struct per_sys_stat *p, *stat;

	dup = malloc(sizeof(struct sys_stat_snapshot));
	if (dup == NULL)
		return (NULL);
	dup->timestamp = snap->timestamp;
	dup->head = NULL;
	for (p = snap->head; p!= NULL; p = p->next) {
		stat = malloc(sizeof(struct per_sys_stat));
		if (stat == NULL) {
			free_sys_stat_snapshot(dup);
			return (NULL);
		}
		memcpy(stat, p, offsetof(struct per_sys_stat, next));
		stat->next = dup->head;
		dup->head = stat;
	}
	sort_sys_stat_snapshot(dup);
	return (dup);
}

static void
store_sys_stat_history(struct sys_stat_snapshot *old_snap, struct sys_stat_snapshot *snap,
	const char *dir)
{
	xmlNodePtr root_node = NULL;
	xmlDocPtr perf_doc = NULL;
	xmlNodePtr sys_node, time_node, unique_node, name_node,
		reads_node, writes_node, nread_node, nwritten_node;
	struct per_sys_stat *p0, *p1;
	char buf[32];
	char path[128];
	uint32_t elapse;

	assert(old_snap->timestamp < snap->timestamp);
	elapse = snap->timestamp - old_snap->timestamp;

	if (create_xml_file(&perf_doc, &root_node) == NULL)
		return;

	for (p0 = old_snap->head, p1 = snap->head; p0 != NULL && p1 != NULL;) {
		int cmp = strcmp(p0->hostname, p1->hostname);
		if (cmp == 0) {
			uint32_t fc_diff_r, fc_diff_w, nic_diff_r, nic_diff_w, nfs_diff_r, nfs_diff_w;
			double fc_rps, fc_wps, fc_rbps, fc_wbps, nic_rbps, nic_wbps, nic_rps, nic_wps ,
                nfs_wbps, nfs_rbps,sum_rps, sum_wps, sum_rbps, sum_wbps;

			fc_diff_r = p1->fc_reads - p0->fc_reads;
			fc_rps = (double)fc_diff_r / (double)elapse;
            fc_diff_w = p1->fc_writes - p0->fc_writes;
			fc_wps = (double)fc_diff_w / (double)elapse;
            
            fc_diff_r = p1->fc_nread - p0->fc_nread;
			fc_rbps = (double)fc_diff_r / (double)elapse;
            fc_diff_w = p1->fc_nwritten - p0->fc_nwritten;
			fc_wbps = (double)fc_diff_w / (double)elapse;

            nic_diff_r = p1->nic_reads - p0->nic_reads;
            nic_rps = nic_diff_r / (double)elapse;
            nic_diff_w = p1->nic_writes - p0->nic_writes;
            nic_wps = nic_diff_w / (double)elapse; 
            
            nic_diff_r = p1->nic_nread - p0->nic_nread;
			nic_rbps = (double)nic_diff_r / (double)elapse;
            nic_diff_w = p1->nic_nwritten - p0->nic_nwritten;
			nic_wbps = (double)nic_diff_w / (double)elapse;

            nfs_diff_r = p1->nfs_nread - p0->nfs_nread;
			nfs_rbps = (double)nfs_diff_r / (double)elapse;
            nfs_diff_w = p1->nfs_nwritten - p0->nfs_nwritten;
			nfs_wbps = (double)nfs_diff_w / (double)elapse;

            sum_rps = fc_rps + nic_rps;
            sum_wps = fc_wps + nic_wps;
            sum_rbps = fc_rbps + nic_rbps + nfs_rbps;
            sum_wbps = fc_wbps + nic_wbps + nfs_wbps;
            
			sys_node = xmlNewChild(root_node, NULL, (xmlChar *)"sys", NULL);
			time_node = xmlNewChild(sys_node, NULL, (xmlChar *)"time", NULL);
			sprintf(buf, "%u", snap->timestamp);
			xmlNodeSetContent(time_node, (xmlChar *)buf);
			unique_node = xmlNewChild(sys_node, NULL, (xmlChar *)"unique", NULL);
			sprintf(buf, "%u_%s", snap->timestamp, p0->hostname);
			xmlNodeSetContent(unique_node, (xmlChar *)buf);
			name_node = xmlNewChild(sys_node, NULL, (xmlChar *)"hostname", NULL);
			sprintf(buf, "%s", p0->hostname);
			xmlNodeSetContent(name_node, (xmlChar *)buf);
			reads_node = xmlNewChild(sys_node, NULL, (xmlChar *)"reads", NULL);
			sprintf(buf, "%.2lf", sum_rps);
			xmlNodeSetContent(reads_node, (xmlChar *)buf);
			writes_node = xmlNewChild(sys_node, NULL, (xmlChar *)"writes", NULL);
			sprintf(buf, "%.2lf", sum_wps);
			xmlNodeSetContent(writes_node, (xmlChar *)buf);
			nread_node = xmlNewChild(sys_node, NULL, (xmlChar *)"nread", NULL);
			sprintf(buf, "%.2lf", sum_rbps);
			xmlNodeSetContent(nread_node, (xmlChar *)buf);
			nwritten_node = xmlNewChild(sys_node, NULL, (xmlChar *)"nwritten", NULL);
			sprintf(buf, "%.2lf", sum_wbps);
			xmlNodeSetContent(nwritten_node, (xmlChar *)buf);

			p0 = p0->next;
			p1 = p1->next;
		} 
        else if (cmp < 0)
        {
			p0 = p0->next;
        }
		else
		{
			p1 = p1->next;
		}
	}

	if (do_mkdir(dir) != 0) {
		close_xml_file(&perf_doc, NULL);
		return;
	}
	sprintf(path, "%s/%u", dir, snap->timestamp);
	close_xml_file(&perf_doc, path);
}

void
perf_stat_sys(void)
{
	struct parse_result *result;
	struct line_buf *buf;
	struct sys_stat_snapshot *snap;
	char path[128];
    (void)system("fc_stat.sh sys");
	result = parse_file(SYS_TMP);
	if (result == NULL) {
		syslog(LOG_ERR, "parse file %s failed", SYS_TMP);
		return;
	}

	snap = malloc(sizeof(struct sys_stat_snapshot));
	if (snap == NULL) {
		syslog(LOG_ERR, "alloc sys_stat_snapshot failed");
		free_parse_result(result);
		return;
	}

	bzero(snap, sizeof(struct sys_stat_snapshot));
	snap->timestamp = time(NULL);
	for (buf = result->head; buf; buf = buf->next) {
		struct per_sys_stat *stat;
		unsigned long int ul;
		if (buf->bufc < 10)
			continue;
		stat = malloc(sizeof(struct per_sys_stat));
		if (stat == NULL) {
			syslog(LOG_ERR, "alloc per_sys_stat failed");
			goto failed;
		}
		if ((ul = str2ul(buf->bufv[0])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[0]);
			free(stat);
			goto failed;
		}
		stat->fc_reads = ul;
		if ((ul = str2ul(buf->bufv[1])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[1]);
			free(stat);
			goto failed;
		}
		stat->fc_writes= ul;
        if ((ul = str2ul(buf->bufv[2])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[2]);
			free(stat);
			goto failed;
		}
		stat->fc_nread= ul;
        if ((ul = str2ul(buf->bufv[3])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[3]);
			free(stat);
			goto failed;
		}
		stat->fc_nwritten = ul;
		if ((ul = str2ul(buf->bufv[4])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[4]);
			free(stat);
			goto failed;
		}
		stat->nic_nread = ul;
		if ((ul = str2ul(buf->bufv[5])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[5]);
			free(stat);
			goto failed;
		}
		stat->nic_nwritten = ul;
        if ((ul = str2ul(buf->bufv[6])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[6]);
			free(stat);
			goto failed;
		}
		stat->nic_reads = ul;
        if ((ul = str2ul(buf->bufv[7])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[7]);
			free(stat);
			goto failed;
		}
		stat->nic_writes = ul;
        if ((ul = str2ul(buf->bufv[8])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[6]);
			free(stat);
			goto failed;
		}
		stat->nfs_nread = ul;
        if ((ul = str2ul(buf->bufv[9])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[7]);
			free(stat);
			goto failed;
		}
		stat->nfs_nwritten = ul;
        (void)get_hostname(stat->hostname);
        
		stat->next = snap->head;
		snap->head = stat;
	}

	if (snap->head == NULL || snap->timestamp == 0) {
		syslog(LOG_ERR, "get sys stat snapshot failed");
		goto failed;
	}

	sort_sys_stat_snapshot(snap);
	if (sys_stat_snapshot_minute == NULL)
		sys_stat_snapshot_minute = dup_sys_stat_snapshot(snap);
	else if (diff_time(sys_stat_snapshot_minute->timestamp, snap->timestamp) >= ONE_MINUTE) {
		sprintf(path, "%s/minute/sys", PERF_STAT_DIR);
		store_sys_stat_history(sys_stat_snapshot_minute, snap, path);
		free_sys_stat_snapshot(sys_stat_snapshot_minute);
		sys_stat_snapshot_minute = dup_sys_stat_snapshot(snap);
	}
	if (sys_stat_snapshot_hour == NULL)
		sys_stat_snapshot_hour = dup_sys_stat_snapshot(snap);
	else if (diff_time(sys_stat_snapshot_hour->timestamp, snap->timestamp) >= ONE_HOUR) {
		sprintf(path, "%s/hour/sys", PERF_STAT_DIR);
		store_sys_stat_history(sys_stat_snapshot_hour, snap, path);
		free_sys_stat_snapshot(sys_stat_snapshot_hour);
		sys_stat_snapshot_hour = dup_sys_stat_snapshot(snap);
	}
	if (sys_stat_snapshot_day == NULL)
		sys_stat_snapshot_day = dup_sys_stat_snapshot(snap);
	else if (diff_time(sys_stat_snapshot_day->timestamp, snap->timestamp) >= ONE_DAY) {
		sprintf(path, "%s/day/sys", PERF_STAT_DIR);
		store_sys_stat_history(sys_stat_snapshot_day, snap, path);
		free_sys_stat_snapshot(sys_stat_snapshot_day);
		sys_stat_snapshot_day = dup_sys_stat_snapshot(snap);
	}
	if (sys_stat_snapshot_week == NULL)
		sys_stat_snapshot_week = dup_sys_stat_snapshot(snap);
	else if (diff_time(sys_stat_snapshot_week->timestamp, snap->timestamp) >= ONE_WEEK) {
		sprintf(path, "%s/week/sys", PERF_STAT_DIR);
		store_sys_stat_history(sys_stat_snapshot_week, snap, path);
		free_sys_stat_snapshot(sys_stat_snapshot_week);
		sys_stat_snapshot_week = dup_sys_stat_snapshot(snap);
	}
	if (sys_stat_snapshot_month == NULL)
		sys_stat_snapshot_month = dup_sys_stat_snapshot(snap);
	else if (diff_date(sys_stat_snapshot_month->timestamp, snap->timestamp) >= di_month) {
		sprintf(path, "%s/month/sys", PERF_STAT_DIR);
		store_sys_stat_history(sys_stat_snapshot_month, snap, path);
		free_sys_stat_snapshot(sys_stat_snapshot_month);
		sys_stat_snapshot_month = dup_sys_stat_snapshot(snap);
	}
	if (sys_stat_snapshot_year == NULL)
		sys_stat_snapshot_year = dup_sys_stat_snapshot(snap);
	else if (diff_date(sys_stat_snapshot_year->timestamp, snap->timestamp) >= di_year) {
		sprintf(path, "%s/year/sys", PERF_STAT_DIR);
		store_sys_stat_history(sys_stat_snapshot_year, snap, path);
		free_sys_stat_snapshot(sys_stat_snapshot_year);
		sys_stat_snapshot_year = dup_sys_stat_snapshot(snap);
	}

failed:
	free_sys_stat_snapshot(snap);
	free_parse_result(result);
}


