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

#define	PROC_DISKSTATS	"/proc/diskstats"

struct per_lun_stat {
	char	zvol[32];
	uint32_t	volblocksize;
	int	major;
	int	minor;
	char	dev[32];
/**
Field  1 -- # of reads completed
    This is the total number of reads completed successfully.
Field  2 -- # of reads merged, field 6 -- # of writes merged
    Reads and writes which are adjacent to each other may be merged for
    efficiency.  Thus two 4K reads may become one 8K read before it is
    ultimately handed to the disk, and so it will be counted (and queued)
    as only one I/O.  This field lets you know how often this was done.
Field  3 -- # of sectors read
    This is the total number of sectors read successfully.
Field  4 -- # of milliseconds spent reading
    This is the total number of milliseconds spent by all reads (as
    measured from __make_request() to end_that_request_last()).
Field  5 -- # of writes completed
    This is the total number of writes completed successfully.
Field  6 -- # of writes merged
    See the description of field 2.
Field  7 -- # of sectors written
    This is the total number of sectors written successfully.
Field  8 -- # of milliseconds spent writing
    This is the total number of milliseconds spent by all writes (as
    measured from __make_request() to end_that_request_last()).
Field  9 -- # of I/Os currently in progress
    The only field that should go to zero. Incremented as requests are
    given to appropriate struct request_queue and decremented as they finish.
Field 10 -- # of milliseconds spent doing I/Os
    This field increases so long as field 9 is nonzero.
Field 11 -- weighted # of milliseconds spent doing I/Os
    This field is incremented at each I/O start, I/O completion, I/O
    merge, or read of these stats by the number of I/Os in progress
    (field 9) times the number of milliseconds spent doing I/O since the
    last update of this field.  This can provide an easy measure of both
    I/O completion time and the backlog that may be accumulating.
 */
	uint32_t	stat[11];
	struct per_lun_stat	*next;
};

struct lun_stat_snapshot {
	uint32_t	timestamp;
	struct per_lun_stat	*head;
};

struct lun_stat_snapshot	*lun_stat_snapshot_minute = NULL;
struct lun_stat_snapshot	*lun_stat_snapshot_hour = NULL;
struct lun_stat_snapshot	*lun_stat_snapshot_day = NULL;
struct lun_stat_snapshot	*lun_stat_snapshot_week = NULL;
struct lun_stat_snapshot	*lun_stat_snapshot_month = NULL;
struct lun_stat_snapshot	*lun_stat_snapshot_year = NULL;

struct lun_info {
	char	zvol[32];
	char	dev[32];
	uint32_t	volblocksize;
	struct lun_info	*next;
};

struct lun_info	*lun_list = NULL;

static char *
find_dev(const char *zvol, char *path, size_t path_len)
{
	struct stat sb;
	ssize_t n;

	if (lstat(zvol, &sb) != 0)
		return (NULL);
	if ((sb.st_mode & S_IFMT) != S_IFLNK)
		return (NULL);
	if ((n = readlink(zvol, path, path_len-1)) < 0)
		return (NULL);
	path[n] = '\0';
	return (path);
}

static uint32_t
get_volblocksize(const char *zvol)
{
	char command[64];
	struct parse_result *result;
	struct line_buf *line;
	uint64_t blksize;

	snprintf(command, 64, "zfs get -H -o value volblocksize %s", zvol);
	result = parse_cmd(command);
	if (result == NULL || result->head == NULL || result->head != result->tail)
		return (0);
	line = result->head;
	if (line->bufc != 1) {
		free_parse_result(result);
		return (0);
	}
	if (nicestrtonum(line->bufv[0], &blksize) < 0)
		blksize = 0;
	free_parse_result(result);
	return ((uint32_t)blksize);
}

static int
init_lun_list(void)
{
	DIR *dirp;
	struct dirent *ent;

	dirp = opendir("/dev/zvol");
	if (dirp == NULL) {
		syslog(LOG_DEBUG, "opendir /dev/zvol error %d", errno);
		return (-1);
	}

	while ((ent = readdir(dirp)) != NULL) {
		DIR *subdir;
		char dirname[32];
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;
		snprintf(dirname, 32, "/dev/zvol/%s", ent->d_name);
		subdir = opendir(dirname);
		if (subdir != NULL) {
			struct dirent *subent;
			struct lun_info *lun;
			char zvol[32];
			char dev[32];
			uint32_t blksize;
			while ((subent = readdir(subdir)) != NULL) {
				if (strcmp(subent->d_name, ".") == 0 || strcmp(subent->d_name, "..") == 0)
					continue;
				snprintf(zvol, 32, "%s/%s", ent->d_name, subent->d_name);
				snprintf(dirname, 32, "/dev/zvol/%s", zvol);
				if (find_dev(dirname, dev, 32) == NULL)
					continue;
				if ((blksize = get_volblocksize(zvol)) == 0)
					continue;
				lun = malloc(sizeof(struct lun_info));
				strncpy(lun->zvol, zvol, 32);
				strncpy(lun->dev, path2filename(dev), 32);
				lun->volblocksize = blksize;
				lun->next = lun_list;
				lun_list = lun;
			}
			closedir(subdir);
		}
	}

	closedir(dirp);
	return (0);
}

static void
free_lun_list(void)
{
	struct lun_info *p = lun_list, *q;

	while (p) {
		q = p;
		p = p->next;
		free(q);
	}
	lun_list = NULL;
}

static struct lun_info *
find_lun(const char *dev)
{
	struct lun_info *lun;

	for (lun = lun_list; lun; lun = lun->next) {
		if (strcmp(lun->dev, dev) == 0)
			return (lun);
	}
	return (NULL);
}

static void
free_lun_stat_snapshot(struct lun_stat_snapshot *snap)
{
	struct per_lun_stat *p = snap->head, *q;

	while (p) {
		q = p;
		p = p->next;
		free(q);
	}
	free(snap);
}

static void
sort_lun_stat_snapshot(struct lun_stat_snapshot *snap)
{
	struct per_lun_stat *list = NULL, *p, **pp;

	while (snap->head != NULL) {
		p = snap->head;
		snap->head = p->next;
		for (pp = &list;
			*pp != NULL;
			pp = &((*pp)->next)) {
			if (strcmp((*pp)->zvol, p->zvol) > 0)
				break;
		}
		p->next = *pp;
		*pp = p;
	}
	snap->head = list;
}

static struct lun_stat_snapshot *
dup_lun_stat_snapshot(struct lun_stat_snapshot *snap)
{
	struct lun_stat_snapshot *dup;
	struct per_lun_stat *p, *stat;

	dup = malloc(sizeof(struct lun_stat_snapshot));
	if (dup == NULL)
		return (NULL);
	dup->timestamp = snap->timestamp;
	dup->head = NULL;
	for (p = snap->head; p!= NULL; p = p->next) {
		stat = malloc(sizeof(struct per_lun_stat));
		if (stat == NULL) {
			free_lun_stat_snapshot(dup);
			return (NULL);
		}
		memcpy(stat, p, offsetof(struct per_lun_stat, next));
		stat->next = dup->head;
		dup->head = stat;
	}
	sort_lun_stat_snapshot(dup);
	return (dup);
}

static void
store_lun_stat_history(struct lun_stat_snapshot *old_snap, struct lun_stat_snapshot *snap,
	const char *dir)
{
	xmlNodePtr root_node = NULL;
	xmlDocPtr perf_doc = NULL;
	xmlNodePtr lun_node, time_node, unique_node, name_node,
		reads_node, writes_node, nread_node, nwritten_node;
	struct per_lun_stat *p0, *p1;
	char buf[32];
	char path[128];
	uint32_t elapse;

	assert(old_snap->timestamp < snap->timestamp);
	elapse = snap->timestamp - old_snap->timestamp;

	if (create_xml_file(&perf_doc, &root_node) == NULL)
		return;

	for (p0 = old_snap->head, p1 = snap->head; p0 != NULL && p1 != NULL;) {
		int cmp = strcmp(p0->zvol, p1->zvol);
		if (cmp == 0) {
			uint32_t diff_r, diff_w;
			double rps, wps, rbps, wbps;

			assert(p0->stat[0] <= p1->stat[0]);
			assert(p0->stat[4] <= p1->stat[4]);
			assert(p0->volblocksize == p1->volblocksize);
			diff_r = p1->stat[0] - p0->stat[0];
			rps = (double)diff_r / (double)elapse;
			rbps = rps * p0->volblocksize;
			diff_w = p1->stat[4] - p0->stat[4];
			wps = (double)diff_w / (double)elapse;
			wbps = wps * p0->volblocksize;

			lun_node = xmlNewChild(root_node, NULL, (xmlChar *)"lun", NULL);
			time_node = xmlNewChild(lun_node, NULL, (xmlChar *)"time", NULL);
			sprintf(buf, "%u", snap->timestamp);
			xmlNodeSetContent(time_node, (xmlChar *)buf);
			unique_node = xmlNewChild(lun_node, NULL, (xmlChar *)"unique", NULL);
			sprintf(buf, "%u_%s", snap->timestamp, p0->zvol);
			xmlNodeSetContent(unique_node, (xmlChar *)buf);
			name_node = xmlNewChild(lun_node, NULL, (xmlChar *)"lun_name", NULL);
			sprintf(buf, "%s", p0->zvol);
			xmlNodeSetContent(name_node, (xmlChar *)buf);
			reads_node = xmlNewChild(lun_node, NULL, (xmlChar *)"reads", NULL);
			sprintf(buf, "%.2lf", rps);
			xmlNodeSetContent(reads_node, (xmlChar *)buf);
			writes_node = xmlNewChild(lun_node, NULL, (xmlChar *)"writes", NULL);
			sprintf(buf, "%.2lf", wps);
			xmlNodeSetContent(writes_node, (xmlChar *)buf);
			nread_node = xmlNewChild(lun_node, NULL, (xmlChar *)"nread", NULL);
			sprintf(buf, "%.2lf", rbps);
			xmlNodeSetContent(nread_node, (xmlChar *)buf);
			nwritten_node = xmlNewChild(lun_node, NULL, (xmlChar *)"nwritten", NULL);
			sprintf(buf, "%.2lf", wbps);
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
perf_stat_lun(void)
{
	struct parse_result *result;
	struct line_buf *buf;
	struct lun_stat_snapshot *snap;
	char path[128];

	if (init_lun_list() != 0) {
		syslog(LOG_DEBUG, "init lun list failed");
		return;
	}

	result = parse_file(PROC_DISKSTATS);
	if (result == NULL) {
		syslog(LOG_ERR, "parse file %s failed", PROC_DISKSTATS);
		free_lun_list();
		return;
	}

	snap = malloc(sizeof(struct lun_stat_snapshot));
	if (snap == NULL) {
		syslog(LOG_ERR, "alloc lun_stat_snapshot failed");
		free_parse_result(result);
		free_lun_list();
		return;
	}

	bzero(snap, sizeof(struct lun_stat_snapshot));
	snap->timestamp = time(NULL);
	for (buf = result->head; buf; buf = buf->next) {
		struct per_lun_stat *stat;
		struct lun_info *lun;
		unsigned long int ul;
		int i;
		if (buf->bufc < 14)
			continue;
		if (strncmp(buf->bufv[2], "zd", 2) != 0)
			continue;
		if ((lun = find_lun(buf->bufv[2])) == NULL)
			continue;

		stat = malloc(sizeof(struct per_lun_stat));
		if (stat == NULL) {
			syslog(LOG_ERR, "alloc per_lun_stat failed");
			goto failed;
		}
		if ((ul = str2ul(buf->bufv[0])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[0]);
			free(stat);
			goto failed;
		}
		stat->major = ul;
		if ((ul = str2ul(buf->bufv[1])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[1]);
			free(stat);
			goto failed;
		}
		stat->minor = ul;
		for (i = 3; i < 14; i++) {
			if ((ul = str2ul(buf->bufv[i])) == INVAL_UL) {
				syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[i]);
				free(stat);
				goto failed;
			}
			stat->stat[i-3] = ul;
		}
		strcpy(stat->zvol, lun->zvol);
		strcpy(stat->dev, lun->dev);
		stat->volblocksize = lun->volblocksize;

		stat->next = snap->head;
		snap->head = stat;
	}

	if (snap->head == NULL || snap->timestamp == 0) {
		syslog(LOG_ERR, "get lun stat snapshot failed");
		goto failed;
	}

	sort_lun_stat_snapshot(snap);
	if (lun_stat_snapshot_minute == NULL)
		lun_stat_snapshot_minute = dup_lun_stat_snapshot(snap);
	else if (diff_time(lun_stat_snapshot_minute->timestamp, snap->timestamp) >= ONE_MINUTE) {
		sprintf(path, "%s/minute/lun", PERF_STAT_DIR);
		store_lun_stat_history(lun_stat_snapshot_minute, snap, path);
		free_lun_stat_snapshot(lun_stat_snapshot_minute);
		lun_stat_snapshot_minute = dup_lun_stat_snapshot(snap);
	}
	if (lun_stat_snapshot_hour == NULL)
		lun_stat_snapshot_hour = dup_lun_stat_snapshot(snap);
	else if (diff_time(lun_stat_snapshot_hour->timestamp, snap->timestamp) >= ONE_HOUR) {
		sprintf(path, "%s/hour/lun", PERF_STAT_DIR);
		store_lun_stat_history(lun_stat_snapshot_hour, snap, path);
		free_lun_stat_snapshot(lun_stat_snapshot_hour);
		lun_stat_snapshot_hour = dup_lun_stat_snapshot(snap);
	}
	if (lun_stat_snapshot_day == NULL)
		lun_stat_snapshot_day = dup_lun_stat_snapshot(snap);
	else if (diff_time(lun_stat_snapshot_day->timestamp, snap->timestamp) >= ONE_DAY) {
		sprintf(path, "%s/day/lun", PERF_STAT_DIR);
		store_lun_stat_history(lun_stat_snapshot_day, snap, path);
		free_lun_stat_snapshot(lun_stat_snapshot_day);
		lun_stat_snapshot_day = dup_lun_stat_snapshot(snap);
	}
	if (lun_stat_snapshot_week == NULL)
		lun_stat_snapshot_week = dup_lun_stat_snapshot(snap);
	else if (diff_time(lun_stat_snapshot_week->timestamp, snap->timestamp) >= ONE_WEEK) {
		sprintf(path, "%s/week/lun", PERF_STAT_DIR);
		store_lun_stat_history(lun_stat_snapshot_week, snap, path);
		free_lun_stat_snapshot(lun_stat_snapshot_week);
		lun_stat_snapshot_week = dup_lun_stat_snapshot(snap);
	}
	if (lun_stat_snapshot_month == NULL)
		lun_stat_snapshot_month = dup_lun_stat_snapshot(snap);
	else if (diff_date(lun_stat_snapshot_month->timestamp, snap->timestamp) >= di_month) {
		sprintf(path, "%s/month/lun", PERF_STAT_DIR);
		store_lun_stat_history(lun_stat_snapshot_month, snap, path);
		free_lun_stat_snapshot(lun_stat_snapshot_month);
		lun_stat_snapshot_month = dup_lun_stat_snapshot(snap);
	}
	if (lun_stat_snapshot_year == NULL)
		lun_stat_snapshot_year = dup_lun_stat_snapshot(snap);
	else if (diff_date(lun_stat_snapshot_year->timestamp, snap->timestamp) >= di_year) {
		sprintf(path, "%s/year/lun", PERF_STAT_DIR);
		store_lun_stat_history(lun_stat_snapshot_year, snap, path);
		free_lun_stat_snapshot(lun_stat_snapshot_year);
		lun_stat_snapshot_year = dup_lun_stat_snapshot(snap);
	}

failed:
	free_lun_stat_snapshot(snap);
	free_parse_result(result);
	free_lun_list();
}
