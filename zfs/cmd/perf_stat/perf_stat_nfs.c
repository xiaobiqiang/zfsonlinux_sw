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

#define	PROC_NFSD	"/proc/net/rpc/nfsd"

struct nfs_stat_snapshot {
	uint32_t	timestamp;
	uint64_t	nread;
	uint64_t	nwritten;
};

struct nfs_stat_snapshot	*nfs_stat_snapshot_minute = NULL;
struct nfs_stat_snapshot	*nfs_stat_snapshot_hour = NULL;
struct nfs_stat_snapshot	*nfs_stat_snapshot_day = NULL;
struct nfs_stat_snapshot	*nfs_stat_snapshot_week = NULL;
struct nfs_stat_snapshot	*nfs_stat_snapshot_month = NULL;
struct nfs_stat_snapshot	*nfs_stat_snapshot_year = NULL;

static struct nfs_stat_snapshot *
dup_nfs_stat_snapshot(struct nfs_stat_snapshot *snap, struct nfs_stat_snapshot *copy)
{
	struct nfs_stat_snapshot *dup = copy;

	if (dup == NULL) {
		dup = malloc(sizeof(struct nfs_stat_snapshot));
		if (dup == NULL)
			return (NULL);
	}
	memcpy(dup, snap, sizeof(struct nfs_stat_snapshot));
	return (dup);
}

static void
store_nfs_stat_history(struct nfs_stat_snapshot *old_snap, struct nfs_stat_snapshot *snap,
	const char *dir)
{
	xmlNodePtr root_node = NULL;
	xmlDocPtr perf_doc = NULL;
	xmlNodePtr file_node, time_node, nread_node, nwritten_node;
	char buf[32];
	char path[128];
	uint32_t elapse, diff_r, diff_w;
	double rps, wps;

	assert(old_snap->timestamp < snap->timestamp);
	elapse = snap->timestamp - old_snap->timestamp;

	if (create_xml_file(&perf_doc, &root_node) == NULL)
		return;

	assert(old_snap->nread <= snap->nread);
	assert(old_snap->nwritten <= snap->nwritten);
	diff_r = snap->nread - old_snap->nread;
	rps = (double)diff_r / (double)elapse;
	diff_w = snap->nwritten - old_snap->nwritten;
	wps = (double)diff_w / (double)elapse;

	file_node = xmlNewChild(root_node, NULL, (xmlChar *)"file", NULL);
	time_node = xmlNewChild(file_node, NULL, (xmlChar *)"time", NULL);
	sprintf(buf, "%u", snap->timestamp);
	xmlNodeSetContent(time_node, (xmlChar *)buf);
	nread_node = xmlNewChild(file_node, NULL, (xmlChar *)"nread", NULL);
	sprintf(buf, "%.2lf", rps);
	xmlNodeSetContent(nread_node, (xmlChar *)buf);
	nwritten_node = xmlNewChild(file_node, NULL, (xmlChar *)"nwritten", NULL);
	sprintf(buf, "%.2lf", wps);
	xmlNodeSetContent(nwritten_node, (xmlChar *)buf);

	if (do_mkdir(dir) != 0) {
		close_xml_file(&perf_doc, NULL);
		return;
	}
	sprintf(path, "%s/%u", dir, snap->timestamp);
	close_xml_file(&perf_doc, path);
}

void
perf_stat_nfs(void)
{
	struct parse_result *result;
	struct line_buf *buf;
	struct nfs_stat_snapshot *snap;
	unsigned long int num;
	char path[128];

	result = parse_file(PROC_NFSD);
	if (result == NULL) {
		syslog(LOG_ERR, "parse file %s failed", PROC_NFSD);
		return;
	}

	snap = malloc(sizeof(struct nfs_stat_snapshot));
	if (snap == NULL) {
		syslog(LOG_ERR, "alloc nfs_stat_snapshot failed");
		free_parse_result(result);
		return;
	}

	bzero(snap, sizeof(struct nfs_stat_snapshot));
	snap->timestamp = time(NULL);
	for (buf = result->head; buf; buf = buf->next) {
		if (buf->bufc < 3)
			continue;
		if (strcmp(buf->bufv[0], "io") == 0) {
			if ((num = str2ul(buf->bufv[1])) == INVAL_UL) {
				syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[1]);
				goto failed;
			}
			snap->nread = num;
			if ((num = str2ul(buf->bufv[2])) == INVAL_UL) {
				syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[1]);
				goto failed;
			}
			snap->nwritten = num;
			break;
		}
	}

	if (buf == NULL) {
		syslog(LOG_ERR, "get nfs stat snapshot failed");
		goto failed;
	}

	if (nfs_stat_snapshot_minute == NULL)
		nfs_stat_snapshot_minute = dup_nfs_stat_snapshot(snap, NULL);
	else if (diff_time(nfs_stat_snapshot_minute->timestamp, snap->timestamp) >= ONE_MINUTE) {
		sprintf(path, "%s/minute/file", PERF_STAT_DIR);
		store_nfs_stat_history(nfs_stat_snapshot_minute, snap, path);
		(void) dup_nfs_stat_snapshot(snap, nfs_stat_snapshot_minute);
	}
	if (nfs_stat_snapshot_hour == NULL)
		nfs_stat_snapshot_hour = dup_nfs_stat_snapshot(snap, NULL);
	else if (diff_time(nfs_stat_snapshot_hour->timestamp, snap->timestamp) >= ONE_HOUR) {
		sprintf(path, "%s/hour/file", PERF_STAT_DIR);
		store_nfs_stat_history(nfs_stat_snapshot_hour, snap, path);
		(void) dup_nfs_stat_snapshot(snap, nfs_stat_snapshot_hour);
	}
	if (nfs_stat_snapshot_day == NULL)
		nfs_stat_snapshot_day = dup_nfs_stat_snapshot(snap, NULL);
	else if (diff_time(nfs_stat_snapshot_day->timestamp, snap->timestamp) >= ONE_DAY) {
		sprintf(path, "%s/day/file", PERF_STAT_DIR);
		store_nfs_stat_history(nfs_stat_snapshot_day, snap, path);
		(void) dup_nfs_stat_snapshot(snap, nfs_stat_snapshot_day);
	}
	if (nfs_stat_snapshot_week == NULL)
		nfs_stat_snapshot_week = dup_nfs_stat_snapshot(snap, NULL);
	else if (diff_time(nfs_stat_snapshot_week->timestamp, snap->timestamp) >= ONE_WEEK) {
		sprintf(path, "%s/week/file", PERF_STAT_DIR);
		store_nfs_stat_history(nfs_stat_snapshot_week, snap, path);
		(void) dup_nfs_stat_snapshot(snap, nfs_stat_snapshot_week);
	}
	if (nfs_stat_snapshot_month == NULL)
		nfs_stat_snapshot_month = dup_nfs_stat_snapshot(snap, NULL);
	else if (diff_date(nfs_stat_snapshot_month->timestamp, snap->timestamp) >= di_month) {
		sprintf(path, "%s/month/file", PERF_STAT_DIR);
		store_nfs_stat_history(nfs_stat_snapshot_month, snap, path);
		(void) dup_nfs_stat_snapshot(snap, nfs_stat_snapshot_month);
	}
	if (nfs_stat_snapshot_year == NULL)
		nfs_stat_snapshot_year = dup_nfs_stat_snapshot(snap, NULL);
	else if (diff_date(nfs_stat_snapshot_year->timestamp, snap->timestamp) >= di_year) {
		sprintf(path, "%s/year/file", PERF_STAT_DIR);
		store_nfs_stat_history(nfs_stat_snapshot_year, snap, path);
		(void) dup_nfs_stat_snapshot(snap, nfs_stat_snapshot_year);
	}

failed:
	free(snap);
	free_parse_result(result);
}
