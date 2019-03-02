#ifndef	_PERF_UTIL_H
#define	_PERF_UTIL_H

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <time.h>

#define	INVAL_UL	ULONG_MAX
#define	INVAL_ULL	ULLONG_MAX

#define	ONE_MINUTE	60
#define	ONE_HOUR	3600
#define	ONE_DAY	(ONE_HOUR * 24)
#define	ONE_WEEK	(ONE_DAY * 7)
#define	ONE_MONTH	(ONE_DAY * 30)
#define	ONE_YEAR	(ONE_DAY * 365)

enum date_interval {
	di_minute,
	di_hour,
	di_day,
	di_week,
	di_month,
	di_year
};

unsigned long int str2ul(const char *s);
unsigned long long int str2ull(const char *s);
uint32_t diff_time(uint32_t time0, uint32_t time1);
enum date_interval diff_date(uint32_t time0, uint32_t time1);
uint32_t time_ago(uint32_t time0, enum date_interval interval);
time_t file_mtime(const char *path);
int do_mkdir(const char *dir);
xmlNodePtr create_xml_file(xmlDocPtr *perf_doc, xmlNodePtr *perf_root_node);
void close_xml_file(xmlDocPtr *perf_doc, const char *filepath);
const char * path2filename(const char *path);
int nicestrtonum(const char *value, uint64_t *num);
void clear_perf_stat_history(void);
char *find_last_file(const char *dir, char *file, int len);

#endif
