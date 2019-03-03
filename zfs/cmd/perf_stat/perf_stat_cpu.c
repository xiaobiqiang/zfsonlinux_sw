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

#define	PROC_STAT	"/proc/stat"

struct per_cpu_stat {
	int id;
	/* user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice */
	uint32_t stat[10];
	struct per_cpu_stat *next;
};

struct cpu_stat_snapshot {
	uint32_t	timestamp;
	uint32_t	btime;
	struct per_cpu_stat	*head;
};

struct cpu_stat_snapshot	*cpu_stat_snapshot_minute = NULL;
struct cpu_stat_snapshot	*cpu_stat_snapshot_hour = NULL;
struct cpu_stat_snapshot	*cpu_stat_snapshot_day = NULL;
struct cpu_stat_snapshot	*cpu_stat_snapshot_week = NULL;
struct cpu_stat_snapshot	*cpu_stat_snapshot_month = NULL;
struct cpu_stat_snapshot	*cpu_stat_snapshot_year = NULL;

static void
free_cpu_stat_snapshot(struct cpu_stat_snapshot *snap)
{
	struct per_cpu_stat *p = snap->head, *q;

	while (p) {
		q = p;
		p = p->next;
		free(q);
	}
	free(snap);
}

static void
sort_cpu_stat_snapshot(struct cpu_stat_snapshot *snap)
{
	struct per_cpu_stat *list = NULL, *p, **pp;

	while (snap->head != NULL) {
		p = snap->head;
		snap->head = p->next;
		for (pp = &list;
			*pp != NULL && (*pp)->id < p->id;
			pp = &((*pp)->next));
		p->next = *pp;
		*pp = p;
	}
	snap->head = list;
}

static struct cpu_stat_snapshot *
dup_cpu_stat_snapshot(struct cpu_stat_snapshot *snap)
{
	struct cpu_stat_snapshot *dup;
	struct per_cpu_stat *p, *stat;
	int i;

	dup = malloc(sizeof(struct cpu_stat_snapshot));
	if (dup == NULL)
		return (NULL);
	dup->timestamp = snap->timestamp;
	dup->btime = snap->btime;
	dup->head = NULL;
	for (p = snap->head; p!= NULL; p = p->next) {
		stat = malloc(sizeof(struct per_cpu_stat));
		if (stat == NULL) {
			free_cpu_stat_snapshot(dup);
			return (NULL);
		}
		stat->id = p->id;
		for (i = 0; i < 10; i++)
			stat->stat[i] = p->stat[i];
		stat->next = dup->head;
		dup->head = stat;
	}
	sort_cpu_stat_snapshot(dup);
	return (dup);
}

static void
store_cpu_stat_history(struct cpu_stat_snapshot *old_snap, struct cpu_stat_snapshot *snap,
	const char *dir)
{
	xmlNodePtr root_node = NULL;
	xmlDocPtr perf_doc = NULL;
	xmlNodePtr cpu_node, time_node, unique_node, id_node, util_node;
	struct per_cpu_stat *p0, *p1;
	char buf[32];
	char path[128];

	assert(old_snap->timestamp < snap->timestamp);

	if (create_xml_file(&perf_doc, &root_node) == NULL)
		return;

	for (p0 = old_snap->head, p1 = snap->head; p0 != NULL && p1 != NULL;) {
		if (p0->id < 0) {
			p0 = p0->next;
			continue;
		}
		if (p1->id < 0) {
			p1 = p1->next;
			continue;
		}
		if (p0->id == p1->id) {
			uint32_t total0 = 0, total1 = 0, diff, diff_idle;
			double percent;
			int i;

			for (i = 0; i < 10; i++) {
				total0 += p0->stat[i];
				total1 += p1->stat[i];
			}
			assert(total0 < total1);
			assert(p0->stat[3] <= p1->stat[3]);
			diff = total1 - total0;
			diff_idle = p1->stat[3] - p0->stat[3];
			assert(diff_idle <= diff);
			percent = 100.0 - (100.0 * (double)diff_idle / (double)diff);

			cpu_node = xmlNewChild(root_node, NULL, (xmlChar *)"cpu", NULL);
			time_node = xmlNewChild(cpu_node, NULL, (xmlChar *)"time", NULL);
			sprintf(buf, "%u", snap->timestamp);
			xmlNodeSetContent(time_node, (xmlChar *)buf);
			unique_node = xmlNewChild(cpu_node, NULL, (xmlChar *)"unique", NULL);
			sprintf(buf, "%u_%d", snap->timestamp, p0->id);
			xmlNodeSetContent(unique_node, (xmlChar *)buf);
			id_node = xmlNewChild(cpu_node, NULL, (xmlChar *)"id", NULL);
			sprintf(buf, "%d", p0->id);
			xmlNodeSetContent(id_node, (xmlChar *)buf);
			util_node = xmlNewChild(cpu_node, NULL, (xmlChar *)"util", NULL);
			sprintf(buf, "%.2lf", percent);
			xmlNodeSetContent(util_node, (xmlChar *)buf);

			p0 = p0->next;
			p1 = p1->next;
		} else if (p0->id < p1->id)
			p0 = p0->next;
		else
			p1 = p1->next;
	}

	if (do_mkdir(dir) != 0) {
		close_xml_file(&perf_doc, NULL);
		return;
	}
	sprintf(path, "%s/%u", dir, snap->timestamp);
	close_xml_file(&perf_doc, path);
}

void
perf_stat_cpu(void)
{
	struct parse_result *result;
	struct line_buf *buf;
	struct cpu_stat_snapshot *snap;
	unsigned long int num;
	char path[128];

	result = parse_file(PROC_STAT);
	if (result == NULL) {
		syslog(LOG_ERR, "parse file %s failed", PROC_STAT);
		return;
	}

	snap = malloc(sizeof(struct cpu_stat_snapshot));
	if (snap == NULL) {
		syslog(LOG_ERR, "alloc cpu_stat_snapshot failed\n");
		free_parse_result(result);
		return;
	}

	bzero(snap, sizeof(struct cpu_stat_snapshot));
	snap->timestamp = time(NULL);
	for (buf = result->head; buf; buf = buf->next) {
		if (buf->bufc < 1)
			continue;
		if (strncmp(buf->bufv[0], "cpu", 3) == 0) {
			struct per_cpu_stat *stat;
			int i;

			if (buf->bufc < 11)
				continue;
			stat = malloc(sizeof(struct per_cpu_stat));
			if (stat == NULL) {
				syslog(LOG_ERR, "alloc per_cpu_stat failed");
				goto failed;
			}
			if (strcmp(buf->bufv[0], "cpu") == 0)
				stat->id = -1;
			else {
				if ((num = str2ul(buf->bufv[0] + 3)) == INVAL_UL) {
					syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[0]);
					free(stat);
					goto failed;
				}
				stat->id = num;
			}
			for (i = 1; i < 11; i++) {
				if ((num = str2ul(buf->bufv[i])) == INVAL_UL) {
					syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[i]);
					free(stat);
					goto failed;
				}
				stat->stat[i-1] = num;
			}
			stat->next = snap->head;
			snap->head = stat;
		} else if (strcmp(buf->bufv[0], "btime") == 0) {
			if ((num = str2ul(buf->bufv[1])) == INVAL_UL) {
				syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[1]);
				goto failed;
			}
			snap->btime = num;
		}
	}

	if (snap->head == NULL || snap->timestamp == 0) {
		syslog(LOG_ERR, "get cpu stat snapshot failed");
		goto failed;
	}

	sort_cpu_stat_snapshot(snap);
	if (cpu_stat_snapshot_minute == NULL)
		cpu_stat_snapshot_minute = dup_cpu_stat_snapshot(snap);
	else if (diff_time(cpu_stat_snapshot_minute->timestamp, snap->timestamp) >= ONE_MINUTE) {
		sprintf(path, "%s/minute/cpu", PERF_STAT_DIR);
		store_cpu_stat_history(cpu_stat_snapshot_minute, snap, path);
		free_cpu_stat_snapshot(cpu_stat_snapshot_minute);
		cpu_stat_snapshot_minute = dup_cpu_stat_snapshot(snap);
	}
	if (cpu_stat_snapshot_hour == NULL)
		cpu_stat_snapshot_hour = dup_cpu_stat_snapshot(snap);
	else if (diff_time(cpu_stat_snapshot_hour->timestamp, snap->timestamp) >= ONE_HOUR) {
		sprintf(path, "%s/hour/cpu", PERF_STAT_DIR);
		store_cpu_stat_history(cpu_stat_snapshot_hour, snap, path);
		free_cpu_stat_snapshot(cpu_stat_snapshot_hour);
		cpu_stat_snapshot_hour = dup_cpu_stat_snapshot(snap);
	}
	if (cpu_stat_snapshot_day == NULL)
		cpu_stat_snapshot_day = dup_cpu_stat_snapshot(snap);
	else if (diff_time(cpu_stat_snapshot_day->timestamp, snap->timestamp) >= ONE_DAY) {
		sprintf(path, "%s/day/cpu", PERF_STAT_DIR);
		store_cpu_stat_history(cpu_stat_snapshot_day, snap, path);
		free_cpu_stat_snapshot(cpu_stat_snapshot_day);
		cpu_stat_snapshot_day = dup_cpu_stat_snapshot(snap);
	}
	if (cpu_stat_snapshot_week == NULL)
		cpu_stat_snapshot_week = dup_cpu_stat_snapshot(snap);
	else if (diff_time(cpu_stat_snapshot_week->timestamp, snap->timestamp) >= ONE_WEEK) {
		sprintf(path, "%s/week/cpu", PERF_STAT_DIR);
		store_cpu_stat_history(cpu_stat_snapshot_week, snap, path);
		free_cpu_stat_snapshot(cpu_stat_snapshot_week);
		cpu_stat_snapshot_week = dup_cpu_stat_snapshot(snap);
	}
	if (cpu_stat_snapshot_month == NULL)
		cpu_stat_snapshot_month = dup_cpu_stat_snapshot(snap);
	else if (diff_date(cpu_stat_snapshot_month->timestamp, snap->timestamp) >= di_month) {
		sprintf(path, "%s/month/cpu", PERF_STAT_DIR);
		store_cpu_stat_history(cpu_stat_snapshot_month, snap, path);
		free_cpu_stat_snapshot(cpu_stat_snapshot_month);
		cpu_stat_snapshot_month = dup_cpu_stat_snapshot(snap);
	}
	if (cpu_stat_snapshot_year == NULL)
		cpu_stat_snapshot_year = dup_cpu_stat_snapshot(snap);
	else if (diff_date(cpu_stat_snapshot_year->timestamp, snap->timestamp) >= di_year) {
		sprintf(path, "%s/year/cpu", PERF_STAT_DIR);
		store_cpu_stat_history(cpu_stat_snapshot_year, snap, path);
		free_cpu_stat_snapshot(cpu_stat_snapshot_year);
		cpu_stat_snapshot_year = dup_cpu_stat_snapshot(snap);
	}

failed:
	free_cpu_stat_snapshot(snap);
	free_parse_result(result);
}
