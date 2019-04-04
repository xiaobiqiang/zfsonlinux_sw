#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <math.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <syslog.h>
#include "perf_stat.h"
#include "perf_util.h"

unsigned long int
str2ul(const char *s)
{
	char *endptr;
	unsigned long int num;

	num = strtoul(s, &endptr, 10);
	return (num == ULONG_MAX ? INVAL_UL : num);
}

unsigned long long int
str2ull(const char *s)
{
	char *endptr;
	unsigned long long int num;

	num = strtoul(s, &endptr, 10);
	return (num == ULLONG_MAX ? INVAL_ULL : num);
}

uint32_t
diff_time(uint32_t time0, uint32_t time1)
{
	return (time0 < time1 ? time1 - time0 : time0 - time1);
}

enum date_interval
diff_date(uint32_t time0, uint32_t time1)
{
	struct tm tm0, tm1;
	time_t t0, t1, t;

	if (time0 < time1) {
		t0 = (time_t)time0;
		t1 = (time_t)time1;
	} else {
		t0 = (time_t)time1;
		t1 = (time_t)time0;
	}
	gmtime_r(&t0, &tm0);
	memcpy(&tm1, &tm0, sizeof(struct tm));
	tm1.tm_year += 1;
	t = mktime(&tm1);
	if (t <= t1)
		return (di_year);
	memcpy(&tm1, &tm0, sizeof(struct tm));
	tm1.tm_mon += 1;
	if (tm1.tm_mon > 11) {
		tm1.tm_year += 1;
		tm1.tm_mon = 0;
	}
	t = mktime(&tm1);
	if (t <= t1)
		return (di_month);
	return (di_day);
}

uint32_t
time_ago(uint32_t time0, enum date_interval interval)
{
	struct tm tm0;
	time_t t0, t;

	if (interval == di_minute)
		return (time0 - ONE_MINUTE);
	else if (interval == di_hour)
		return (time0 - ONE_HOUR);
	else if (interval == di_day)
		return (time0 - ONE_DAY);
	else if (interval == di_week)
		return (time0 - ONE_WEEK);

	t0 = (time_t)time0;
	gmtime_r(&t0, &tm0);
	if (interval == di_month) {
		if (tm0.tm_mon == 0) {
			tm0.tm_mon = 11;
			tm0.tm_year -= 1;
		} else
			tm0.tm_mon -= 1;
	} else if (interval == di_year)
		tm0.tm_year -= 1;
	t = mktime(&tm0);
	return (t < 0 ? 0 : (uint32_t)t);
}

time_t
file_mtime(const char *path)
{
	struct stat sb;

	if (lstat(path, &sb) == -1)
		return ((time_t)-1);
	return (sb.st_mtime);
}

static int
_mkdir(char *dir)
{
	struct stat buf;
	if (stat(dir, &buf) == 0) {
		if ((buf.st_mode & S_IFMT) != S_IFDIR)
			return (-1);
		else
			return (0);
	}
	return mkdir(dir, 0755);
}

int
do_mkdir(const char *dir)
{
	char tmp[256] = {0};
	char *p = NULL;
	size_t len;

	snprintf(tmp, sizeof(tmp),"%s",dir);
	len = strlen(tmp);
	if(tmp[len - 1] == '/')
		tmp[len - 1] = 0;
	for(p = tmp + 1; *p; p++)
		if(*p == '/') {
			*p = 0;
			if (_mkdir(tmp) != 0)
				return (-1);
			*p = '/';
		}
	if (_mkdir(tmp) != 0)
		return (-1);
	return (0);
}

xmlNodePtr
create_xml_file(xmlDocPtr *perf_doc, xmlNodePtr *perf_root_node)
{
	xmlDocPtr doc;
	xmlNodePtr root_node;

	if ((doc = xmlNewDoc((xmlChar *)"1.0")) == NULL)
		return (NULL);
	if ((root_node = xmlNewNode(NULL, (xmlChar *)"Performance")) == NULL) {
		xmlFreeDoc(doc);
		return (NULL);
	}

	xmlDocSetRootElement(doc, root_node);
	*perf_doc = doc;
	*perf_root_node = root_node;
	return (root_node);
}

void
close_xml_file(xmlDocPtr *perf_doc, const char *filepath)
{
	xmlChar *xmlbuff;
	int buffersize;

	if (filepath) {
		xmlDocDumpFormatMemory(*perf_doc, &xmlbuff, &buffersize, 1);
		xmlSaveFormatFileEnc(filepath, *perf_doc, "UTF-8", 1);
		xmlFree(xmlbuff);
	}

	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(*perf_doc);
}

const char *
path2filename(const char *path)
{
	char *p;
	p = strrchr(path, '/');
	return (p ? ++p : path);
}

static int
str2shift(const char *buf)
{
	const char *ends = "BKMGTPEZ";
	int i;

	if (buf[0] == '\0')
		return (0);
	for (i = 0; i < strlen(ends); i++) {
		if (toupper(buf[0]) == ends[i])
			break;
	}
	if (i == strlen(ends)) {
		syslog(LOG_DEBUG, "invalid numeric suffix '%s'", buf);
		return (-1);
	}

	/*
	 * We want to allow trailing 'b' characters for 'GB' or 'Mb'.  But don't
	 * allow 'BB' - that's just weird.
	 */
	if (buf[1] == '\0' || (toupper(buf[1]) == 'B' && buf[2] == '\0' &&
	    toupper(buf[0]) != 'B'))
		return (10*i);

	syslog(LOG_DEBUG, "invalid numeric suffix '%s'", buf);
	return (-1);
}

int
nicestrtonum(const char *value, uint64_t *num)
{
	char *end;
	int shift;

	*num = 0;

	/* Check to see if this looks like a number.  */
	if ((value[0] < '0' || value[0] > '9') && value[0] != '.') {
		syslog(LOG_DEBUG, "bad numeric value '%s'", value);
		return (-1);
	}

	/* Rely on strtoull() to process the numeric portion.  */
	errno = 0;
	*num = strtoull(value, &end, 10);

	/*
	 * Check for ERANGE, which indicates that the value is too large to fit
	 * in a 64-bit value.
	 */
	if (errno == ERANGE) {
		syslog(LOG_DEBUG, "numeric value is too large");
		return (-1);
	}

	/*
	 * If we have a decimal value, then do the computation with floating
	 * point arithmetic.  Otherwise, use standard arithmetic.
	 */
	if (*end == '.') {
		double fval = strtod(value, &end);

		if ((shift = str2shift(end)) == -1)
			return (-1);

		fval *= pow(2, shift);

		if (fval > HUGE_VALF) {
			syslog(LOG_DEBUG, "numeric value is too large");
			return (-1);
		}

		*num = (uint64_t)fval;
	} else {
		if ((shift = str2shift(end)) == -1)
			return (-1);

		/* Check for overflow */
		if (shift >= 64 || (*num << shift) >> shift != *num) {
			syslog(LOG_DEBUG, "numeric value is too large");
			return (-1);
		}

		*num <<= shift;
	}

	return (0);
}

void
clear_perf_stat_history(void)
{
	time_t current;
	DIR *dirp, *dirp1, *dirp2;
	struct dirent *ent, *ent1, *ent2;
	int class = -1;
	char path[64];
	time_t mtime;

	current = time(NULL);

	dirp = opendir(PERF_STAT_DIR);
	if (dirp == NULL) {
		syslog(LOG_ERR, "opendir %s error %d", PERF_STAT_DIR, errno);
		return;
	}

	while ((ent = readdir(dirp)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;
		if (strcmp(ent->d_name, "minute") == 0)
			class = 0;
		else if (strcmp(ent->d_name, "hour") == 0)
			class = 1;
		else if (strcmp(ent->d_name, "day") == 0)
			class = 2;
		else if (strcmp(ent->d_name, "week") == 0)
			class = 3;
		else if (strcmp(ent->d_name, "month") == 0)
			class = 4;
		else if (strcmp(ent->d_name, "year") == 0)
			class = 5;
		else if (strcmp(ent->d_name, ZPOOL_IOSTAT_DIR) == 0)
			class = 6;
		else
			continue;

		snprintf(path, 64, "%s/%s", PERF_STAT_DIR, ent->d_name);
		dirp1 = opendir(path);
		if (dirp1 == NULL)
			continue;
		while ((ent1 = readdir(dirp1)) != NULL) {
			if (strcmp(ent1->d_name, ".") == 0 || strcmp(ent1->d_name, "..") == 0)
				continue;
			snprintf(path, 64, "%s/%s/%s", PERF_STAT_DIR, ent->d_name, ent1->d_name);
			if (class == 6) {
				if ((mtime = file_mtime(path)) == (time_t)-1)
					continue;
				if (diff_time((uint32_t)mtime, (uint32_t)current) <= ONE_HOUR)
					continue;
				if (unlink(path) == -1)
					syslog(LOG_ERR, "unlink %s error %d\n", path, errno);
				else
					syslog(LOG_DEBUG, "remove %s success\n", path);
				continue;
			}
			dirp2 = opendir(path);
			if (dirp2 == NULL)
				continue;
			while ((ent2 = readdir(dirp2)) != NULL) {
				if (strcmp(ent2->d_name, ".") == 0 || strcmp(ent2->d_name, "..") == 0)
					continue;
				snprintf(path, 64, "%s/%s/%s/%s",
					PERF_STAT_DIR, ent->d_name, ent1->d_name, ent2->d_name);
				if ((mtime = file_mtime(path)) == (time_t)-1)
					continue;
				if (class == 0) {
					if (diff_time((uint32_t)mtime, (uint32_t)current) <= ONE_HOUR)
						continue;
				} else if (class == 1) {
					if (diff_time((uint32_t)mtime, (uint32_t)current) <= ONE_DAY)
						continue;
				} else if (class == 2) {
					if (diff_time((uint32_t)mtime, (uint32_t)current) <= ONE_WEEK)
						continue;
				} else if (class == 3) {
					if (diff_date((uint32_t)mtime, (uint32_t)current) < di_month)
						continue;
				} else if (class == 4) {
					if (diff_date((uint32_t)mtime, (uint32_t)current) < di_year)
						continue;
				} else
					continue;
				if (unlink(path) == -1)
					syslog(LOG_ERR, "unlink %s error %d\n", path, errno);
				else
					syslog(LOG_DEBUG, "remove %s success\n", path);
			}
			closedir(dirp2);
		}
		closedir(dirp1);
	}

	closedir(dirp);
}

char *
find_last_file(const char *dir, char *file, int len)
{
	DIR *dirp;
	struct dirent *ent;

	dirp = opendir(dir);
	if (dirp == NULL)
		return (NULL);
	strcpy(file, "0");
	while ((ent = readdir(dirp)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;
		if (strcmp(file, ent->d_name) < 0)
			strncpy(file, ent->d_name, len);
	}
	closedir(dirp);
	if (strcmp(file, "0") == 0)
		return (NULL);
	else
		return (file);
}

