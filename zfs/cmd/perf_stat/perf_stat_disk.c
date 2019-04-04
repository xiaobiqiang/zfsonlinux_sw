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

struct per_disk_stat {
	char name[32];
	uint32_t reads;
	uint32_t writes;
	uint32_t nread;
	uint32_t nwritten;
    uint32_t millisec;
    uint32_t rtime;
    uint32_t wtime;
/**
Field  1 -- # of reads completed                                        
    This is the total number of reads completed successfully.          /1.读IOPS/
Field  2 -- # of reads merged, field 6 -- # of writes merged       
    Reads and writes which are adjacent to each other may be merged for
    efficiency.  Thus two 4K reads may become one 8K read before it is
    ultimately handed to the disk, and so it will be counted (and queued)
    as only one I/O.  This field lets you know how often this was 
    done.                                                              /2.合并读IOPS/
Field  3 -- # of sectors read
    This is the total number of sectors read successfully.             /3.读流量/
Field  4 -- # of milliseconds spent reading
    This is the total number of milliseconds spent by all reads (as    
    measured from __make_request() to end_that_request_last()).        /4.读所花的时间（ms）/
Field  5 -- # of writes completed                                       
    This is the total number of writes completed successfully.         /5.写IOPS
Field  6 -- # of writes merged
    See the description of field 2.                                    /6.合并写IOPS                               
Field  7 -- # of sectors written
    This is the total number of sectors written successfully.          /7.写流量 
Field  8 -- # of milliseconds spent writing
    This is the total number of milliseconds spent by all writes (as
measured from __make_request() to end_that_request_last()).        /8.写所花的时间/
Field  9 -- # of I/Os currently in progress
    The only field that should go to zero. Incremented as requests are
    given to appropriate struct request_queue and decremented as they finish. /9.正在处理的输入/输出请求次数
Field 10 -- # of milliseconds spent doing I/Os
    This field increases so long as field 9 is nonzero.                /10.输入/输出操作花费的毫秒数
Field 11 -- weighted # of milliseconds spent doing I/Os
    This field is incremented at each I/O start, I/O completion, I/O
    merge, or read of these stats by the number of I/Os in progress
    (field 9) times the number of milliseconds spent doing I/O since the
    last update of this field.  This can provide an easy measure of both
    I/O completion time and the backlog that may be accumulating.      /11.输入/输出操作花费的加权毫秒数
 */
	struct per_disk_stat	*next;
};

struct disk_stat_snapshot {
	uint32_t	timestamp;
	struct per_disk_stat	*head;
};

struct disk_stat_snapshot	*disk_stat_snapshot_minute = NULL;
struct disk_stat_snapshot	*disk_stat_snapshot_hour = NULL;
struct disk_stat_snapshot	*disk_stat_snapshot_day = NULL;
struct disk_stat_snapshot	*disk_stat_snapshot_week = NULL;
struct disk_stat_snapshot	*disk_stat_snapshot_month = NULL;
struct disk_stat_snapshot	*disk_stat_snapshot_year = NULL;

/*static double
get_util(const char *name)
{
	char command[64];
	struct parse_result *result;
	struct line_buf *line;
	uint64_t util;

	snprintf(command, 64, "iostat -x|grep '%s'|awk '{print $14}'", name);
	result = parse_cmd(command);
	if (result == NULL || result->head == NULL || result->head != result->tail)
		return (0);
	line = result->head;
	if (line->bufc != 1) {
		free_parse_result(result);
		return (0);
	}
	util = atof(line->bufv[0]);
	free_parse_result(result);
	return (util);
}
get_iowait(const char *name)
{
	char command[64];
	struct parse_result *result;
	struct line_buf *line;
	uint64_t util;

	snprintf(command, 64, "iostat -x|grep '%s'|awk '{print $10}'", name);
	result = parse_cmd(command);
	if (result == NULL || result->head == NULL || result->head != result->tail)
		return (0);
	line = result->head;
	if (line->bufc != 1) {
		free_parse_result(result);
		return (0);
	}
	util = atof(line->bufv[0]);
	free_parse_result(result);
	return (util);
}
*/


static uint32_t
check_sd_name(char *name)
{
	uint32_t name_len;
    char last_word;
    name_len = strlen(name);
    if(name[0] == '\0')
    {
        return 0;
    }
    last_word = name[name_len-1]; 
    if((last_word >= '0') && (last_word <= '9'))
    {
        return 0;
    }
    return 1;
}

static void
free_disk_stat_snapshot(struct disk_stat_snapshot *snap)
{
	struct per_disk_stat *p = snap->head, *q;

	while (p) {
		q = p;
		p = p->next;
		free(q);
	}
	free(snap);
}

static void
sort_disk_stat_snapshot(struct disk_stat_snapshot *snap)
{
	struct per_disk_stat *list = NULL, *p, **pp;

	while (snap->head != NULL) {
		p = snap->head;
		snap->head = p->next;
		for (pp = &list;
			*pp != NULL;
			pp = &((*pp)->next)) {
			if (strcmp((*pp)->name, p->name) > 0)
				break;
		}
		p->next = *pp;
		*pp = p;
	}
	snap->head = list;
}

static struct disk_stat_snapshot *
dup_disk_stat_snapshot(struct disk_stat_snapshot *snap)
{
	struct disk_stat_snapshot *dup;
	struct per_disk_stat *p, *stat;

	dup = malloc(sizeof(struct disk_stat_snapshot));
	if (dup == NULL)
		return (NULL);
	dup->timestamp = snap->timestamp;
	dup->head = NULL;
	for (p = snap->head; p!= NULL; p = p->next) {
		stat = malloc(sizeof(struct per_disk_stat));
		if (stat == NULL) {
			free_disk_stat_snapshot(dup);
			return (NULL);
		}
		memcpy(stat, p, offsetof(struct per_disk_stat, next));
		stat->next = dup->head;
		dup->head = stat;
	}
	sort_disk_stat_snapshot(dup);
	return (dup);
}

static void
store_disk_stat_history(struct disk_stat_snapshot *old_snap, struct disk_stat_snapshot *snap,
	const char *dir)
{
	xmlNodePtr root_node = NULL;
	xmlDocPtr perf_doc = NULL;
	xmlNodePtr disk_node, time_node, unique_node, name_node,
		reads_node, writes_node, nread_node, nwritten_node,await_node,util_node;
	struct per_disk_stat *p0, *p1;
	char buf[32];
	char path[128];
	uint32_t elapse;

	assert(old_snap->timestamp < snap->timestamp);
	elapse = snap->timestamp - old_snap->timestamp;

	if (create_xml_file(&perf_doc, &root_node) == NULL)
		return;

	for (p0 = old_snap->head, p1 = snap->head; p0 != NULL && p1 != NULL;) {
		int cmp = strcmp(p0->name, p1->name);
		if (cmp == 0) {
			uint32_t diff_r, diff_w,millisec,wtime,rtime,diff_sum,time_sum;
			double rps, wps, rbps, wbps,util,await;

		    /*assert(p0->stat[0] <= p1->stat[0]);
			assert(p0->stat[4] <= p1->stat[4]);
			assert(p0->volblocksize == p1->volblocksize);*/
			diff_r = p1->reads - p0->reads;
			rps = (double)diff_r / (double)elapse;
            diff_w = p1->writes - p0->writes;
			wps = (double)diff_w / (double)elapse;
            diff_sum = diff_r + diff_w;
            
            diff_r = p1->nread - p0->nread;
			rbps = (double)diff_r / (double)elapse;
            diff_w = p1->nwritten - p0->nwritten;
			wbps = (double)diff_w / (double)elapse;
            millisec = p1->millisec - p0->millisec;
            millisec = millisec / 1000;
            util = (double)millisec / (double)elapse;
            rtime = p1->rtime - p0->rtime;
            wtime = p1->wtime - p0->wtime;
            time_sum = rtime + wtime;
            if(diff_sum != 0)
            {
                await = (double)time_sum / (double)diff_sum;
            }
            else
            {
                await = 0;  /*响应时间*/
            }
			disk_node = xmlNewChild(root_node, NULL, (xmlChar *)"disk", NULL);
			time_node = xmlNewChild(disk_node, NULL, (xmlChar *)"time", NULL);
			sprintf(buf, "%u", snap->timestamp);
			xmlNodeSetContent(time_node, (xmlChar *)buf);
			unique_node = xmlNewChild(disk_node, NULL, (xmlChar *)"unique", NULL);
			sprintf(buf, "%u_%s", snap->timestamp, p0->name);
			xmlNodeSetContent(unique_node, (xmlChar *)buf);
			name_node = xmlNewChild(disk_node, NULL, (xmlChar *)"disk_name", NULL);
			sprintf(buf, "%s", p0->name);
			xmlNodeSetContent(name_node, (xmlChar *)buf);
			reads_node = xmlNewChild(disk_node, NULL, (xmlChar *)"reads", NULL);
			sprintf(buf, "%.2lf", rps);
			xmlNodeSetContent(reads_node, (xmlChar *)buf);
			writes_node = xmlNewChild(disk_node, NULL, (xmlChar *)"writes", NULL);
			sprintf(buf, "%.2lf", wps);
			xmlNodeSetContent(writes_node, (xmlChar *)buf);
			nread_node = xmlNewChild(disk_node, NULL, (xmlChar *)"nread", NULL);
			sprintf(buf, "%.2lf", rbps);
			xmlNodeSetContent(nread_node, (xmlChar *)buf);
			nwritten_node = xmlNewChild(disk_node, NULL, (xmlChar *)"nwritten", NULL);
			sprintf(buf, "%.2lf", wbps);
			xmlNodeSetContent(nwritten_node, (xmlChar *)buf);
            await_node = xmlNewChild(disk_node, NULL, (xmlChar *)"await", NULL);
			sprintf(buf, "%.2lf", await);
			xmlNodeSetContent(await_node, (xmlChar *)buf);
            util_node = xmlNewChild(disk_node, NULL, (xmlChar *)"util", NULL);
			sprintf(buf, "%.2lf", util);
			xmlNodeSetContent(util_node, (xmlChar *)buf);

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
perf_stat_disk(void)
{
	struct parse_result *result;
	struct line_buf *buf;
	struct disk_stat_snapshot *snap;
	char path[128];

	result = parse_file(PROC_DISKSTATS);
	if (result == NULL) {
		syslog(LOG_ERR, "parse file %s failed", PROC_DISKSTATS);
		return;
	}

	snap = malloc(sizeof(struct disk_stat_snapshot));
	if (snap == NULL) {
		syslog(LOG_ERR, "alloc disk_stat_snapshot failed");
		free_parse_result(result);
		return;
	}

	bzero(snap, sizeof(struct disk_stat_snapshot));
	snap->timestamp = time(NULL);
	for (buf = result->head; buf; buf = buf->next) {
		struct per_disk_stat *stat;
		unsigned long int ul;
		if (buf->bufc < 13)
			continue;
		if (strncmp(buf->bufv[2], "sd", 2) != 0)
			continue;
		if (check_sd_name(buf->bufv[2]) == 0)
			continue;
		stat = malloc(sizeof(struct per_disk_stat));
		if (stat == NULL) {
			syslog(LOG_ERR, "alloc per_disk_stat failed");
			goto failed;
		}
        strcpy(stat->name,buf->bufv[2]);
		if ((ul = str2ul(buf->bufv[3])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[3]);
			free(stat);
			goto failed;
		}
		stat->reads = ul;
		if ((ul = str2ul(buf->bufv[5])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[5]);
			free(stat);
			goto failed;
		}
		stat->nread = ul;
        if ((ul = str2ul(buf->bufv[6])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[6]);
			free(stat);
			goto failed;
		}
		stat->rtime = ul;
        if ((ul = str2ul(buf->bufv[7])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[7]);
			free(stat);
			goto failed;
		}
		stat->writes = ul;
		if ((ul = str2ul(buf->bufv[9])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[9]);
			free(stat);
			goto failed;
		}
		stat->nwritten = ul;
		if ((ul = str2ul(buf->bufv[10])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[10]);
			free(stat);
			goto failed;
		}
		stat->wtime = ul;
        if ((ul = str2ul(buf->bufv[12])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[12]);
			free(stat);
			goto failed;
		}
		stat->millisec = ul;
        
		stat->next = snap->head;
		snap->head = stat;
	}

	if (snap->head == NULL || snap->timestamp == 0) {
		syslog(LOG_ERR, "get disk stat snapshot failed");
		goto failed;
	}

	sort_disk_stat_snapshot(snap);
	if (disk_stat_snapshot_minute == NULL)
		disk_stat_snapshot_minute = dup_disk_stat_snapshot(snap);
	else if (diff_time(disk_stat_snapshot_minute->timestamp, snap->timestamp) >= ONE_MINUTE) {
		sprintf(path, "%s/minute/disk", PERF_STAT_DIR);
		store_disk_stat_history(disk_stat_snapshot_minute, snap, path);
		free_disk_stat_snapshot(disk_stat_snapshot_minute);
		disk_stat_snapshot_minute = dup_disk_stat_snapshot(snap);
	}
	if (disk_stat_snapshot_hour == NULL)
		disk_stat_snapshot_hour = dup_disk_stat_snapshot(snap);
	else if (diff_time(disk_stat_snapshot_hour->timestamp, snap->timestamp) >= ONE_HOUR) {
		sprintf(path, "%s/hour/disk", PERF_STAT_DIR);
		store_disk_stat_history(disk_stat_snapshot_hour, snap, path);
		free_disk_stat_snapshot(disk_stat_snapshot_hour);
		disk_stat_snapshot_hour = dup_disk_stat_snapshot(snap);
	}
	if (disk_stat_snapshot_day == NULL)
		disk_stat_snapshot_day = dup_disk_stat_snapshot(snap);
	else if (diff_time(disk_stat_snapshot_day->timestamp, snap->timestamp) >= ONE_DAY) {
		sprintf(path, "%s/day/disk", PERF_STAT_DIR);
		store_disk_stat_history(disk_stat_snapshot_day, snap, path);
		free_disk_stat_snapshot(disk_stat_snapshot_day);
		disk_stat_snapshot_day = dup_disk_stat_snapshot(snap);
	}
	if (disk_stat_snapshot_week == NULL)
		disk_stat_snapshot_week = dup_disk_stat_snapshot(snap);
	else if (diff_time(disk_stat_snapshot_week->timestamp, snap->timestamp) >= ONE_WEEK) {
		sprintf(path, "%s/week/disk", PERF_STAT_DIR);
		store_disk_stat_history(disk_stat_snapshot_week, snap, path);
		free_disk_stat_snapshot(disk_stat_snapshot_week);
		disk_stat_snapshot_week = dup_disk_stat_snapshot(snap);
	}
	if (disk_stat_snapshot_month == NULL)
		disk_stat_snapshot_month = dup_disk_stat_snapshot(snap);
	else if (diff_date(disk_stat_snapshot_month->timestamp, snap->timestamp) >= di_month) {
		sprintf(path, "%s/month/disk", PERF_STAT_DIR);
		store_disk_stat_history(disk_stat_snapshot_month, snap, path);
		free_disk_stat_snapshot(disk_stat_snapshot_month);
		disk_stat_snapshot_month = dup_disk_stat_snapshot(snap);
	}
	if (disk_stat_snapshot_year == NULL)
		disk_stat_snapshot_year = dup_disk_stat_snapshot(snap);
	else if (diff_date(disk_stat_snapshot_year->timestamp, snap->timestamp) >= di_year) {
		sprintf(path, "%s/year/disk", PERF_STAT_DIR);
		store_disk_stat_history(disk_stat_snapshot_year, snap, path);
		free_disk_stat_snapshot(disk_stat_snapshot_year);
		disk_stat_snapshot_year = dup_disk_stat_snapshot(snap);
	}

failed:
	free_disk_stat_snapshot(snap);
	free_parse_result(result);
}

