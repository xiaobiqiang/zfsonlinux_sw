#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include "parse_cmd.h"
#include "perf_stat.h"
#include "perf_util.h"

#define	PROC_MEMINFO	"/proc/meminfo"

struct mem_stat_snapshot {
	uint32_t	timestamp;
	uint32_t	mem_total;
	uint32_t	mem_free;
};

struct mem_stat_snapshot	*mem_stat_snapshot_minute = NULL;
struct mem_stat_snapshot	*mem_stat_snapshot_hour = NULL;
struct mem_stat_snapshot	*mem_stat_snapshot_day = NULL;
struct mem_stat_snapshot	*mem_stat_snapshot_week = NULL;
struct mem_stat_snapshot	*mem_stat_snapshot_month = NULL;
struct mem_stat_snapshot	*mem_stat_snapshot_year = NULL;

static struct mem_stat_snapshot *
dup_mem_stat_snapshot(struct mem_stat_snapshot *snap, struct mem_stat_snapshot *copy)
{
	struct mem_stat_snapshot *dup = copy;

	if (dup == NULL) {
		dup = malloc(sizeof(struct mem_stat_snapshot));
		if (dup == NULL)
			return (NULL);
	}
	memcpy(dup, snap, sizeof(struct mem_stat_snapshot));
	return (dup);
}

static void
store_mem_stat_history(struct mem_stat_snapshot *snap, const char *dir)
{
	xmlNodePtr root_node = NULL;
	xmlDocPtr perf_doc = NULL;
	xmlNodePtr mem_node, time_node, total_node, free_node;
	char buf[32];
	char path[128];

	if (create_xml_file(&perf_doc, &root_node) == NULL)
		return;

	mem_node = xmlNewChild(root_node, NULL, (xmlChar *)"memory", NULL);
	time_node = xmlNewChild(mem_node, NULL, (xmlChar *)"time", NULL);
	sprintf(buf, "%u", snap->timestamp);
	xmlNodeSetContent(time_node, (xmlChar *)buf);
	total_node = xmlNewChild(mem_node, NULL, (xmlChar *)"MemTotal", NULL);
	sprintf(buf, "%u", snap->mem_total);
	xmlNodeSetContent(total_node, (xmlChar *)buf);
	free_node = xmlNewChild(mem_node, NULL, (xmlChar *)"MemFree", NULL);
	sprintf(buf, "%u", snap->mem_free);
	xmlNodeSetContent(free_node, (xmlChar *)buf);

	if (do_mkdir(dir) != 0) {
		close_xml_file(&perf_doc, NULL);
		return;
	}
	sprintf(path, "%s/%u", dir, snap->timestamp);
	close_xml_file(&perf_doc, path);
}

void
perf_stat_mem(void)
{
	struct parse_result *result;
	struct line_buf *buf;
	struct mem_stat_snapshot *snap;
	unsigned long int num;
	char path[128];

	result = parse_file(PROC_MEMINFO);
	if (result == NULL) {
		syslog(LOG_ERR, "parse file %s failed", PROC_MEMINFO);
		return;
	}

	snap = malloc(sizeof(struct mem_stat_snapshot));
	if (snap == NULL) {
		syslog(LOG_ERR, "alloc mem_stat_snapshot failed");
		free_parse_result(result);
		return;
	}

	bzero(snap, sizeof(struct mem_stat_snapshot));
	snap->timestamp = time(NULL);
	for (buf = result->head; buf; buf = buf->next) {
		if (buf->bufc < 2)
			continue;
		if (strcmp(buf->bufv[0], "MemTotal:") == 0) {
			if ((num = str2ul(buf->bufv[1])) == INVAL_UL) {
				syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[1]);
				goto failed;
			}
			snap->mem_total = num;
		} else if (strcmp(buf->bufv[0], "MemFree:") == 0) {
			if ((num = str2ul(buf->bufv[1])) == INVAL_UL) {
				syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[1]);
				goto failed;
			}
			snap->mem_free = num;
		}
	}

	if (snap->mem_total == 0 || snap->mem_free == 0) {
		syslog(LOG_ERR, "get memory stat snapshot failed");
		goto failed;
	}

	if (mem_stat_snapshot_minute == NULL)
		mem_stat_snapshot_minute = dup_mem_stat_snapshot(snap, NULL);
	else if (diff_time(mem_stat_snapshot_minute->timestamp, snap->timestamp) >= ONE_MINUTE) {
		sprintf(path, "%s/minute/memory", PERF_STAT_DIR);
		store_mem_stat_history(snap, path);
		(void) dup_mem_stat_snapshot(snap, mem_stat_snapshot_minute);
	}
	if (mem_stat_snapshot_hour == NULL)
		mem_stat_snapshot_hour = dup_mem_stat_snapshot(snap, NULL);
	else if (diff_time(mem_stat_snapshot_hour->timestamp, snap->timestamp) >= ONE_HOUR) {
		sprintf(path, "%s/hour/memory", PERF_STAT_DIR);
		store_mem_stat_history(snap, path);
		(void) dup_mem_stat_snapshot(snap, mem_stat_snapshot_hour);
	}
	if (mem_stat_snapshot_day == NULL)
		mem_stat_snapshot_day = dup_mem_stat_snapshot(snap, NULL);
	else if (diff_time(mem_stat_snapshot_day->timestamp, snap->timestamp) >= ONE_DAY) {
		sprintf(path, "%s/day/memory", PERF_STAT_DIR);
		store_mem_stat_history(snap, path);
		(void) dup_mem_stat_snapshot(snap, mem_stat_snapshot_day);
	}
	if (mem_stat_snapshot_week == NULL)
		mem_stat_snapshot_week = dup_mem_stat_snapshot(snap, NULL);
	else if (diff_time(mem_stat_snapshot_week->timestamp, snap->timestamp) >= ONE_WEEK) {
		sprintf(path, "%s/week/memory", PERF_STAT_DIR);
		store_mem_stat_history(snap, path);
		(void) dup_mem_stat_snapshot(snap, mem_stat_snapshot_week);
	}
	if (mem_stat_snapshot_month == NULL)
		mem_stat_snapshot_month = dup_mem_stat_snapshot(snap, NULL);
	else if (diff_date(mem_stat_snapshot_month->timestamp, snap->timestamp) >= di_month) {
		sprintf(path, "%s/month/memory", PERF_STAT_DIR);
		store_mem_stat_history(snap, path);
		(void) dup_mem_stat_snapshot(snap, mem_stat_snapshot_month);
	}
	if (mem_stat_snapshot_year == NULL)
		mem_stat_snapshot_year = dup_mem_stat_snapshot(snap, NULL);
	else if (diff_date(mem_stat_snapshot_year->timestamp, snap->timestamp) >= di_year) {
		sprintf(path, "%s/year/memory", PERF_STAT_DIR);
		store_mem_stat_history(snap, path);
		(void) dup_mem_stat_snapshot(snap, mem_stat_snapshot_year);
	}

failed:
	free(snap);
	free_parse_result(result);
}
