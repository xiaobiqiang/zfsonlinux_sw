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

#define	PROC_NETDEV	"/proc/net/dev"

struct per_netdev_stat {
	char	ifname[32];
	uint64_t	recv_bytes;
	uint64_t	xmit_bytes;
	/* Receive: packets errs drop fifo frame compressed multicast */
	uint32_t	recv_stat[7];
	/* Transmit: packets errs drop fifo colls carrier compressed */
	uint32_t	xmit_stat[7];
	struct per_netdev_stat	*next;
};

struct netdev_stat_snapshot {
	uint32_t	timestamp;
	struct per_netdev_stat	*head;
};

struct netdev_stat_snapshot	*netdev_stat_snapshot_minute = NULL;
struct netdev_stat_snapshot	*netdev_stat_snapshot_hour = NULL;
struct netdev_stat_snapshot	*netdev_stat_snapshot_day = NULL;
struct netdev_stat_snapshot	*netdev_stat_snapshot_week = NULL;
struct netdev_stat_snapshot	*netdev_stat_snapshot_month = NULL;
struct netdev_stat_snapshot	*netdev_stat_snapshot_year = NULL;

static void
free_netdev_stat_snapshot(struct netdev_stat_snapshot *snap)
{
	struct per_netdev_stat *p = snap->head, *q;

	while (p) {
		q = p;
		p = p->next;
		free(q);
	}
	free(snap);
}

static void
sort_netdev_stat_snapshot(struct netdev_stat_snapshot *snap)
{
	struct per_netdev_stat *list = NULL, *p, **pp;

	while (snap->head != NULL) {
		p = snap->head;
		snap->head = p->next;
		for (pp = &list;
			*pp != NULL;
			pp = &((*pp)->next)) {
			if (strcmp((*pp)->ifname, p->ifname) > 0)
				break;
		}
		p->next = *pp;
		*pp = p;
	}
	snap->head = list;
}

static struct netdev_stat_snapshot *
dup_netdev_stat_snapshot(struct netdev_stat_snapshot *snap)
{
	struct netdev_stat_snapshot *dup;
	struct per_netdev_stat *p, *stat;
	int i;

	dup = malloc(sizeof(struct netdev_stat_snapshot));
	if (dup == NULL)
		return (NULL);
	dup->timestamp = snap->timestamp;
	dup->head = NULL;
	for (p = snap->head; p!= NULL; p = p->next) {
		stat = malloc(sizeof(struct per_netdev_stat));
		if (stat == NULL) {
			free_netdev_stat_snapshot(dup);
			return (NULL);
		}
		strcpy(stat->ifname, p->ifname);
		stat->recv_bytes = p->recv_bytes;
		stat->xmit_bytes = p->xmit_bytes;
		for (i = 0; i < 7; i++) {
			stat->recv_stat[i] = p->recv_stat[i];
			stat->xmit_stat[i] = p->xmit_stat[i];
		}
		stat->next = dup->head;
		dup->head = stat;
	}
	sort_netdev_stat_snapshot(dup);
	return (dup);
}

static void
store_netdev_stat_history(struct netdev_stat_snapshot *old_snap, struct netdev_stat_snapshot *snap,
	const char *dir)
{
	xmlNodePtr root_node = NULL;
	xmlDocPtr perf_doc = NULL;
	xmlNodePtr nic_node, time_node, unique_node, name_node, rkps_node, wkps_node;
	struct per_netdev_stat *p0, *p1;
	char buf[32];
	char path[128];
	uint32_t elapse;

	assert(old_snap->timestamp < snap->timestamp);
	elapse = snap->timestamp - old_snap->timestamp;

	if (create_xml_file(&perf_doc, &root_node) == NULL)
		return;

	for (p0 = old_snap->head, p1 = snap->head; p0 != NULL && p1 != NULL;) {
		int cmp = strcmp(p0->ifname, p1->ifname);
		if (cmp == 0) {
			uint64_t diff_r, diff_x;
			double rkps, wkps;

			assert(p0->recv_bytes <= p1->recv_bytes);
			assert(p0->xmit_bytes <= p1->xmit_bytes);  
			diff_r = p1->recv_bytes - p0->recv_bytes;
			diff_x = p1->xmit_bytes - p0->xmit_bytes;
			rkps = (double)diff_r / (double)elapse;
			wkps = (double)diff_x / (double)elapse;

			nic_node = xmlNewChild(root_node, NULL, (xmlChar *)"NIC", NULL);
			time_node = xmlNewChild(nic_node, NULL, (xmlChar *)"time", NULL);
			sprintf(buf, "%u", snap->timestamp);
			xmlNodeSetContent(time_node, (xmlChar *)buf);
			unique_node = xmlNewChild(nic_node, NULL, (xmlChar *)"unique", NULL);
			sprintf(buf, "%u_%s", snap->timestamp, p0->ifname);
			xmlNodeSetContent(unique_node, (xmlChar *)buf);
			name_node = xmlNewChild(nic_node, NULL, (xmlChar *)"name", NULL);
			sprintf(buf, "%s", p0->ifname);
			xmlNodeSetContent(name_node, (xmlChar *)buf);
			rkps_node = xmlNewChild(nic_node, NULL, (xmlChar *)"rkps", NULL);
			sprintf(buf, "%.2lf", rkps);
			xmlNodeSetContent(rkps_node, (xmlChar *)buf);
			wkps_node = xmlNewChild(nic_node, NULL, (xmlChar *)"wkps", NULL);
			sprintf(buf, "%.2lf", wkps);
			xmlNodeSetContent(wkps_node, (xmlChar *)buf);

			p0 = p0->next;
			p1 = p1->next;
		} else if (cmp < 0)
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
perf_stat_netdev(void)
{
	struct parse_result *result;
	struct line_buf *buf;
	struct netdev_stat_snapshot *snap;
	char path[128];

	result = parse_file(PROC_NETDEV);
	if (result == NULL) {
		syslog(LOG_ERR, "parse file %s failed\n", PROC_NETDEV);
		return;
	}

	snap = malloc(sizeof(struct netdev_stat_snapshot));
	if (snap == NULL) {
		syslog(LOG_ERR, "alloc netdev_stat_snapshot failed");
		free_parse_result(result);
		return;
	}

	bzero(snap, sizeof(struct netdev_stat_snapshot));
	snap->timestamp = time(NULL);
	for (buf = result->head; buf; buf = buf->next) {
		struct per_netdev_stat *stat;
		unsigned long int ul;
		unsigned long long int ull;
		int len, i;
		if (buf->bufc < 17)
			continue;
		len = strlen(buf->bufv[0]);
		if (buf->bufv[0][len-1] != ':')
			continue;
		stat = malloc(sizeof(struct per_netdev_stat));
		if (stat == NULL) {
			syslog(LOG_ERR, "alloc per_netdev_stat failed");
			goto failed;
		}
		memcpy(stat->ifname, buf->bufv[0], len-1);
		stat->ifname[len-1] = '\0';
		stat->next = NULL;
		if ((ull = str2ull(buf->bufv[1])) == INVAL_ULL) {
			syslog(LOG_ERR, "str2ull: invalid number: %s", buf->bufv[1]);
			free(stat);
			goto failed;
		}
		stat->recv_bytes = ull;
		for (i = 2; i < 9; i++) {
			if ((ul = str2ul(buf->bufv[i])) == INVAL_UL) {
				syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[i]);
				free(stat);
				goto failed;
			}
			stat->recv_stat[i-2] = ul;
		}
		if ((ull = str2ull(buf->bufv[9])) == INVAL_ULL) {
			syslog(LOG_ERR, "str2ull: invalid number: %s", buf->bufv[9]);
			free(stat);
			goto failed;
		}
		stat->xmit_bytes = ull;
		for (i = 10; i < 17; i++) {
			if ((ul = str2ul(buf->bufv[i])) == INVAL_UL) {
				syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[i]);
				free(stat);
				goto failed;
			}
			stat->xmit_stat[i-10] = ul;
		}
		stat->next = snap->head;
		snap->head = stat;
	}

	if (snap->head == NULL || snap->timestamp == 0) {
		syslog(LOG_ERR, "get netdev stat snapshot failed");
		goto failed;
	}

	sort_netdev_stat_snapshot(snap);
	if (netdev_stat_snapshot_minute == NULL)
		netdev_stat_snapshot_minute = dup_netdev_stat_snapshot(snap);
	else if (diff_time(netdev_stat_snapshot_minute->timestamp, snap->timestamp) >= ONE_MINUTE) {
		sprintf(path, "%s/minute/nic", PERF_STAT_DIR);
		store_netdev_stat_history(netdev_stat_snapshot_minute, snap, path);
		free_netdev_stat_snapshot(netdev_stat_snapshot_minute);
		netdev_stat_snapshot_minute = dup_netdev_stat_snapshot(snap);
	}
	if (netdev_stat_snapshot_hour == NULL)
		netdev_stat_snapshot_hour = dup_netdev_stat_snapshot(snap);
	else if (diff_time(netdev_stat_snapshot_hour->timestamp, snap->timestamp) >= ONE_HOUR) {
		sprintf(path, "%s/hour/nic", PERF_STAT_DIR);
		store_netdev_stat_history(netdev_stat_snapshot_hour, snap, path);
		free_netdev_stat_snapshot(netdev_stat_snapshot_hour);
		netdev_stat_snapshot_hour = dup_netdev_stat_snapshot(snap);
	}
	if (netdev_stat_snapshot_day == NULL)
		netdev_stat_snapshot_day = dup_netdev_stat_snapshot(snap);
	else if (diff_time(netdev_stat_snapshot_day->timestamp, snap->timestamp) >= ONE_DAY) {
		sprintf(path, "%s/day/nic", PERF_STAT_DIR);
		store_netdev_stat_history(netdev_stat_snapshot_day, snap, path);
		free_netdev_stat_snapshot(netdev_stat_snapshot_day);
		netdev_stat_snapshot_day = dup_netdev_stat_snapshot(snap);
	}
	if (netdev_stat_snapshot_week == NULL)
		netdev_stat_snapshot_week = dup_netdev_stat_snapshot(snap);
	else if (diff_time(netdev_stat_snapshot_week->timestamp, snap->timestamp) >= ONE_WEEK) {
		sprintf(path, "%s/week/nic", PERF_STAT_DIR);
		store_netdev_stat_history(netdev_stat_snapshot_week, snap, path);
		free_netdev_stat_snapshot(netdev_stat_snapshot_week);
		netdev_stat_snapshot_week = dup_netdev_stat_snapshot(snap);
	}
	if (netdev_stat_snapshot_month == NULL)
		netdev_stat_snapshot_month = dup_netdev_stat_snapshot(snap);
	else if (diff_date(netdev_stat_snapshot_month->timestamp, snap->timestamp) >= di_month) {
		sprintf(path, "%s/month/nic", PERF_STAT_DIR);
		store_netdev_stat_history(netdev_stat_snapshot_month, snap, path);
		free_netdev_stat_snapshot(netdev_stat_snapshot_month);
		netdev_stat_snapshot_month = dup_netdev_stat_snapshot(snap);
	}
	if (netdev_stat_snapshot_year == NULL)
		netdev_stat_snapshot_year = dup_netdev_stat_snapshot(snap);
	else if (diff_date(netdev_stat_snapshot_year->timestamp, snap->timestamp) >= di_year) {
		sprintf(path, "%s/year/nic", PERF_STAT_DIR);
		store_netdev_stat_history(netdev_stat_snapshot_year, snap, path);
		free_netdev_stat_snapshot(netdev_stat_snapshot_year);
		netdev_stat_snapshot_year = dup_netdev_stat_snapshot(snap);
	}

failed:
	free_netdev_stat_snapshot(snap);
	free_parse_result(result);
}
