#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <stddef.h>
#include "parse_cmd.h"
#include "perf_stat.h"
#include "perf_util.h"
   

#define	PROC_FCINFO	"/tmp/target.tmp"
const char* fc_stat_script = "/usr/local/sbin/fc_stat.sh";

struct per_fc_stat {
	char     name[32];
	uint32_t nread;
	uint32_t nwritten;
    uint32_t reads;
    uint32_t writes;
	struct per_fc_stat	*next;
};

struct fc_stat_snapshot {
    uint32_t timestamp;
    struct per_fc_stat	*head;   
};

struct fc_stat_snapshot	*fc_stat_snapshot_minute = NULL;
struct fc_stat_snapshot	*fc_stat_snapshot_hour = NULL;
struct fc_stat_snapshot	*fc_stat_snapshot_day = NULL;
struct fc_stat_snapshot	*fc_stat_snapshot_week = NULL;
struct fc_stat_snapshot	*fc_stat_snapshot_month = NULL;
struct fc_stat_snapshot	*fc_stat_snapshot_year = NULL;

static void log_write(const char *cmdforamt,...)
{
    va_list args;    
    char cmdbuf[512] = {0}; 
    const char *filename = "/tmp/test_perf_stat.log";
    FILE *fp = fopen(filename,"a+");
    va_start(args, cmdforamt);    
    (void)vsnprintf(cmdbuf,511,cmdforamt,args);    
    va_end(args);
    
    if(NULL == fp)
    {
        return;
    }
    
    fprintf(fp,"%s\n",cmdbuf);
    fclose(fp);
    return;
}

static void
sort_fc_stat_snapshot(struct fc_stat_snapshot *snap)
{
	struct per_fc_stat *list = NULL, *p, **pp;

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

static void
free_fc_stat_snapshot(struct fc_stat_snapshot *snap)
{
	struct per_fc_stat *p = snap->head, *q;

	while (p) {
		q = p;
		p = p->next;
		free(q);
	}
	free(snap);
}

static struct fc_stat_snapshot *
dup_fc_stat_snapshot(struct fc_stat_snapshot *snap)
{
	struct fc_stat_snapshot *dup;
	struct per_fc_stat *p, *stat;

	dup = malloc(sizeof(struct fc_stat_snapshot));
	if (dup == NULL)
		return (NULL);
	dup->timestamp = snap->timestamp;
	dup->head = NULL;
	for (p = snap->head; p!= NULL; p = p->next) {
		stat = malloc(sizeof(struct per_fc_stat));
		if (stat == NULL) {
			free_fc_stat_snapshot(dup);
			return (NULL);
		}
		memcpy(stat, p, offsetof(struct per_fc_stat, next));
		stat->next = dup->head;
		dup->head = stat;
	}
    sort_fc_stat_snapshot(dup);
	return (dup);
}

static void
store_fc_stat_history(struct fc_stat_snapshot *old_snap, struct fc_stat_snapshot *snap,
	const char *dir)
{
	xmlNodePtr root_node = NULL;
	xmlDocPtr perf_doc = NULL;
	xmlNodePtr fc_node, time_node, unique_node, name_node,
        reads_node, writes_node, nread_node, nwritten_node;
	struct per_fc_stat *p0, *p1;
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
			uint32_t diff_r, diff_w;
			double rps, wps, rbps, wbps;
//			assert(p0->reads <= p1->reads);
//			assert(p0->writes <= p1->writes);
//			assert(p0->nread <= p1->nread);
//          assert(p0->nwritten <= p1->nwritten);
                
			diff_r = p1->reads - p0->reads;
			rps = (double)diff_r / (double)elapse;
            diff_r = p1->nread - p0->nread;
			rbps = (double)diff_r / (double)elapse;
			diff_w = p1->writes - p0->writes;
			wps = (double)diff_w / (double)elapse;
            diff_w = p1->nwritten - p0->nwritten;
			wbps = (double)diff_w / (double)elapse;
            
			fc_node = xmlNewChild(root_node, NULL, (xmlChar *)"fc", NULL);
			time_node = xmlNewChild(fc_node, NULL, (xmlChar *)"time", NULL);
			sprintf(buf, "%u", snap->timestamp);
			xmlNodeSetContent(time_node, (xmlChar *)buf);
			unique_node = xmlNewChild(fc_node, NULL, (xmlChar *)"unique", NULL);
			sprintf(buf, "%u_%s", snap->timestamp, p0->name);
			xmlNodeSetContent(unique_node, (xmlChar *)buf);
			name_node = xmlNewChild(fc_node, NULL, (xmlChar *)"fc_name", NULL);
			sprintf(buf, "%s", p0->name);
			xmlNodeSetContent(name_node, (xmlChar *)buf);
			reads_node = xmlNewChild(fc_node, NULL, (xmlChar *)"reads", NULL);
			sprintf(buf, "%.2lf", rps);
			xmlNodeSetContent(reads_node, (xmlChar *)buf);
			writes_node = xmlNewChild(fc_node, NULL, (xmlChar *)"writes", NULL);
			sprintf(buf, "%.2lf", wps);
			xmlNodeSetContent(writes_node, (xmlChar *)buf);
			nread_node = xmlNewChild(fc_node, NULL, (xmlChar *)"nread", NULL);
			sprintf(buf, "%.2lf", rbps);
			xmlNodeSetContent(nread_node, (xmlChar *)buf);
			nwritten_node = xmlNewChild(fc_node, NULL, (xmlChar *)"nwritten", NULL);
			sprintf(buf, "%.2lf", wbps);
			xmlNodeSetContent(nwritten_node, (xmlChar *)buf);

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
perf_stat_fc(void)
{
	struct parse_result *result;
	struct line_buf *buf;
	struct fc_stat_snapshot *snap = NULL;
	char path[128];

    (void)system("fc_stat.sh");
	result = parse_file(PROC_FCINFO); /*file name not confirm yet*/
	if (result == NULL) {
		syslog(LOG_ERR, "parse file %s failed", PROC_FCINFO);
		return;
	}

	snap = malloc(sizeof(struct fc_stat_snapshot));
	if (snap == NULL) {
		syslog(LOG_ERR, "alloc fc_stat_snapshot failed");
		log_write("alloc fc_stat_snapshot failed");
		free_parse_result(result);
		return;
	}

	bzero(snap, sizeof(struct fc_stat_snapshot));
	//memset(snap, 0, sizeof(struct fc_stat_snapshot));
	snap->timestamp = time(NULL);
	for (buf = result->head; buf; buf = buf->next) {
		struct per_fc_stat *stat;
        unsigned long int ul;
		if (buf->bufc < 5)
			continue;
        
		stat = malloc(sizeof(struct per_fc_stat));
		if (stat == NULL) {
			syslog(LOG_ERR, "alloc per_fc_stat failed");
			log_write("alloc per_fc_stat failed");
			goto failed;
		}
        if (strncmp(buf->bufv[0], "wwn.", 4) == 0)
		{ 
            strcpy(stat->name,buf->bufv[0]);
        }
        log_write("bufv:%s",stat->name);
		if ((ul = str2ul(buf->bufv[1])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[1]);
			free(stat);
			goto failed;
		}
		stat->reads = ul;
		if ((ul = str2ul(buf->bufv[2])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[2]);
			log_write("invalid number bufv[2]");
			free(stat);
			goto failed;
		}
		stat->writes = ul;
		if ((ul = str2ul(buf->bufv[3])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[3]);
			log_write("invalid number bufv[3]");
			free(stat);
			goto failed;
		}
		stat->nread = ul;
        if ((ul = str2ul(buf->bufv[4])) == INVAL_UL) {
			syslog(LOG_ERR, "str2ul: invalid number: %s", buf->bufv[4]);
			log_write("invalid number bufv[4]");
			free(stat);
			goto failed;
		}
		stat->nwritten= ul;
        
		stat->next = snap->head;
		snap->head = stat;
	}
    
	if (snap->head == NULL || snap->timestamp == 0) {
		syslog(LOG_ERR, "get fc stat snapshot failed");
		log_write("get fc stat snapshot failed");
		goto failed;
	}
    sort_fc_stat_snapshot(snap);
	/* sort_lun_stat_snapshot(snap);    Maybe we don't need*/
	if (fc_stat_snapshot_minute == NULL)
		fc_stat_snapshot_minute = dup_fc_stat_snapshot(snap);
	else if (diff_time(fc_stat_snapshot_minute->timestamp, snap->timestamp) >= ONE_MINUTE) {
		sprintf(path, "%s/minute/fc", PERF_STAT_DIR);
		store_fc_stat_history(fc_stat_snapshot_minute, snap, path);
		free_fc_stat_snapshot(fc_stat_snapshot_minute);
		fc_stat_snapshot_minute = dup_fc_stat_snapshot(snap);
	}
	if (fc_stat_snapshot_hour == NULL)
		fc_stat_snapshot_hour = dup_fc_stat_snapshot(snap);
	else if (diff_time(fc_stat_snapshot_hour->timestamp, snap->timestamp) >= ONE_HOUR) {
		sprintf(path, "%s/hour/fc", PERF_STAT_DIR);
		store_fc_stat_history(fc_stat_snapshot_hour, snap, path);
		free_fc_stat_snapshot(fc_stat_snapshot_hour);
		fc_stat_snapshot_hour = dup_fc_stat_snapshot(snap);
	}
	if (fc_stat_snapshot_day == NULL)
		fc_stat_snapshot_day = dup_fc_stat_snapshot(snap);
	else if (diff_time(fc_stat_snapshot_day->timestamp, snap->timestamp) >= ONE_DAY) {
		sprintf(path, "%s/day/fc", PERF_STAT_DIR);
		store_fc_stat_history(fc_stat_snapshot_day, snap, path);
		free_fc_stat_snapshot(fc_stat_snapshot_day);
		fc_stat_snapshot_day = dup_fc_stat_snapshot(snap);
	}
	if (fc_stat_snapshot_week == NULL)
		fc_stat_snapshot_week = dup_fc_stat_snapshot(snap);
	else if (diff_time(fc_stat_snapshot_week->timestamp, snap->timestamp) >= ONE_WEEK) {
		sprintf(path, "%s/week/fc", PERF_STAT_DIR);
		store_fc_stat_history(fc_stat_snapshot_week, snap, path);
		free_fc_stat_snapshot(fc_stat_snapshot_week);
		fc_stat_snapshot_week = dup_fc_stat_snapshot(snap);
	}
	if (fc_stat_snapshot_month == NULL)
		fc_stat_snapshot_month = dup_fc_stat_snapshot(snap);
	else if (diff_date(fc_stat_snapshot_month->timestamp, snap->timestamp) >= di_month) {
		sprintf(path, "%s/month/fc", PERF_STAT_DIR);
		store_fc_stat_history(fc_stat_snapshot_month, snap, path);
		free_fc_stat_snapshot(fc_stat_snapshot_month);
		fc_stat_snapshot_month = dup_fc_stat_snapshot(snap);
	}
	if (fc_stat_snapshot_year == NULL)
		fc_stat_snapshot_year = dup_fc_stat_snapshot(snap);
	else if (diff_date(fc_stat_snapshot_year->timestamp, snap->timestamp) >= di_year) {
		sprintf(path, "%s/year/fc", PERF_STAT_DIR);
		store_fc_stat_history(fc_stat_snapshot_year, snap, path);
		free_fc_stat_snapshot(fc_stat_snapshot_year);
		fc_stat_snapshot_year = dup_fc_stat_snapshot(snap);
	}

failed:
	free_fc_stat_snapshot(snap);
	free_parse_result(result);
}

