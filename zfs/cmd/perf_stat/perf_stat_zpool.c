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
#include <libzfs.h>
#include <sys/list.h>
#include <syslog.h>
#include "parse_cmd.h"
#include "perf_stat.h"
#include "perf_util.h"

typedef struct zpool_node {
	zpool_handle_t	*zn_handle;
	avl_node_t	zn_node;
} zpool_node_t;

avl_tree_t pool_list;
static libzfs_handle_t *g_zfs;

static int
zpool_compare(const void *larg, const void *rarg)
{
	zpool_handle_t *l = ((zpool_node_t *)larg)->zn_handle;
	zpool_handle_t *r = ((zpool_node_t *)rarg)->zn_handle;
	const char *lname = zpool_get_name(l);
	const char *rname = zpool_get_name(r);
	int cmp = strcmp(lname, rname);

	if (cmp < 0)
		return (-1);
	if (cmp > 0)
		return (1);
	return (0);
}

static int
add_pool(zpool_handle_t *zhp, void *data)
{
	zpool_node_t *node;
	avl_index_t where;

	node = malloc(sizeof (zpool_node_t));
	if (node == NULL)
		return (-1);
	node->zn_handle = zhp;
	if (avl_find(&pool_list, node, &where) != NULL) {
		zpool_close(node->zn_handle);
		free(node);
		return (-1);
	}
	avl_insert(&pool_list, node, where);

	return (0);
}

static int
pool_list_init(void)
{
	g_zfs = libzfs_init();
	if (g_zfs == NULL)
		return (-1);

	avl_create(&pool_list, zpool_compare, sizeof (zpool_node_t),
		offsetof(zpool_node_t, zn_node));
	(void) zpool_iter(g_zfs, add_pool, NULL);
	return (0);
}

static void
pool_list_fini(void)
{
	zpool_node_t *node;
	void *cookie;

	cookie = NULL;
	while ((node = avl_destroy_nodes(&pool_list, &cookie)) != NULL)
		free(node);
	avl_destroy(&pool_list);

	libzfs_fini(g_zfs);
}

struct per_zpool_stat {
	char	name[32];
	uint64_t	vs_timestamp;
	uint64_t	alloc;
	uint64_t	space;
	uint64_t	read;
	uint64_t	written;
	uint64_t	nread;
	uint64_t	nwritten;
	uint64_t	proc_nread;
	uint64_t	proc_nwritten;
	uint64_t	proc_reads;
	uint64_t	proc_writes;
	avl_node_t	node;
};

struct zpool_stat_snapshot {
	uint32_t	timestamp;
	avl_tree_t	stat;
};

struct zpool_stat_snapshot	*zpool_stat_snapshot_minute = NULL;
struct zpool_stat_snapshot	*zpool_stat_snapshot_hour = NULL;
struct zpool_stat_snapshot	*zpool_stat_snapshot_day = NULL;
struct zpool_stat_snapshot	*zpool_stat_snapshot_week = NULL;
struct zpool_stat_snapshot	*zpool_stat_snapshot_month = NULL;
struct zpool_stat_snapshot	*zpool_stat_snapshot_year = NULL;

static int
zpool_stat_compare(const void *larg, const void *rarg)
{
	struct per_zpool_stat *l = (struct per_zpool_stat *)larg;
	struct per_zpool_stat *r = (struct per_zpool_stat *)rarg;
	const char *lname = l->name;
	const char *rname = r->name;
	int cmp = strcmp(lname, rname);

	if (cmp < 0)
		return (-1);
	if (cmp > 0)
		return (1);
	return (0);
}

static void
free_zpool_stat_snapshot(struct zpool_stat_snapshot *snap)
{
	struct per_zpool_stat *node;
	void *cookie;

	cookie = NULL;
	while ((node = avl_destroy_nodes(&snap->stat, &cookie)) != NULL)
		free(node);
	avl_destroy(&snap->stat);
	free(snap);
}

static struct zpool_stat_snapshot *
dup_zpool_stat_snapshot(struct zpool_stat_snapshot *snap)
{
	struct zpool_stat_snapshot *dup;
	struct per_zpool_stat *p, *stat;

	dup = malloc(sizeof(struct zpool_stat_snapshot));
	if (dup == NULL)
		return (NULL);
	dup->timestamp = snap->timestamp;
	avl_create(&dup->stat, zpool_stat_compare, sizeof (struct per_zpool_stat),
		offsetof(struct per_zpool_stat, node));
	for (p = avl_first(&snap->stat); p; p = AVL_NEXT(&snap->stat, p)) {
		stat = malloc(sizeof(struct per_zpool_stat));
		if (stat == NULL) {
			free_zpool_stat_snapshot(dup);
			return (NULL);
		}
		memcpy(stat, p, offsetof(struct per_zpool_stat, node));
		avl_add(&dup->stat, stat);
	}
	return (dup);
}

static void
store_zpool_stat_history(struct zpool_stat_snapshot *old_snap,
	struct zpool_stat_snapshot *snap, const char *dir)
{
	xmlNodePtr root_node = NULL;
	xmlDocPtr perf_doc = NULL;
	xmlNodePtr pool_node, time_node, unique_node, name_node,
		alloc_node, free_node, reads_node, writes_node, nread_node, nwritten_node;
	struct per_zpool_stat *p0, *p1;
	char buf[32];
	char path[128];
	uint32_t elapse;

	assert(old_snap->timestamp < snap->timestamp);
	elapse = snap->timestamp - old_snap->timestamp;
	printf("elapse=%u\n", elapse);

	if (create_xml_file(&perf_doc, &root_node) == NULL)
		return;

	for (p0 = avl_first(&old_snap->stat), p1 = avl_first(&snap->stat);
		p0 != NULL && p1 != NULL;) {
		int cmp = strcmp(p0->name, p1->name);
		printf("compare(%s, %s) = %d\n", p0->name, p1->name, cmp);
		if (cmp == 0) {
			uint32_t diff_r, diff_w, diff_nr, diff_nw;
			double rps, wps, rbps, wbps;
			uint64_t tdelta;
			double scale, r_bps, w_bps;
			uint32_t p_dr, p_dw, p_dnr, p_dnw;
			double p_rps, p_wps, p_rbps, p_wbps;

			tdelta = p1->vs_timestamp - p0->vs_timestamp;
			scale = (double)NANOSEC / tdelta;

			assert(p1->alloc <= p1->space);
			assert(p0->read <= p1->read);
			assert(p0->written <= p1->written);
			assert(p0->nread <= p1->nread);
			assert(p0->nwritten <= p1->nwritten);
			diff_r = p1->read - p0->read;
			rps = (double)diff_r / (double)elapse;
			diff_w = p1->written - p0->written;
			wps = (double)diff_w / (double)elapse;
			diff_nr = p1->nread - p0->nread;
			rbps = (double)diff_nr / (double)elapse;
			diff_nw = p1->nwritten - p0->nwritten;
			wbps = (double)diff_nw / (double)elapse;
			printf("%s: p0(read=%lu, write=%lu, nread=%lu, nwritten=%lu)"
				" p1(read=%lu, write=%lu, nread=%lu, nwritten=%lu)"
				" rps=%.2lf, wps=%.2lf, rbps=%.2lf, wbps=%.2lf\n",
				p0->name, p0->read, p0->written, p0->nread, p0->nwritten,
				p1->read, p1->written, p1->nread, p1->nwritten,
				rps, wps, rbps, wbps);
			r_bps = scale * diff_nr;
			w_bps = scale * diff_nw;
			printf("tdelta=%lu, r_bps=%.2lf, w_bps=%.2lf\n",
				tdelta, r_bps, w_bps);
			p_dr = p1->proc_reads - p0->proc_reads;
			p_rps = (double)p_dr / (double)elapse;
			p_dw = p1->proc_writes - p0->proc_writes;
			p_wps = (double)p_dw / (double)elapse;
			p_dnr = p1->proc_nread - p0->proc_nread;
			p_rbps = (double)p_dnr / (double)elapse;
			p_dnw = p1->proc_nwritten - p0->proc_nwritten;
			p_wbps = (double)p_dnw / (double)elapse;
			printf("p0(proc_reads=%lu, proc_writes=%lu, proc_nread=%lu, proc_nwritten=%lu)"
				" p1(proc_reads=%lu, proc_writes=%lu, proc_nread=%lu, proc_nwritten=%lu)"
				" rps=%.2lf, wps=%.2lf, rbps=%.2lf, wbps=%.2lf\n",
				p0->proc_reads, p0->proc_writes, p0->proc_nread, p0->proc_nwritten,
				p1->proc_reads, p1->proc_writes, p1->proc_nread, p1->proc_nwritten,
				p_rps, p_wps, p_rbps, p_wbps);

			pool_node = xmlNewChild(root_node, NULL, (xmlChar *)"pool", NULL);
			time_node = xmlNewChild(pool_node, NULL, (xmlChar *)"time", NULL);
			sprintf(buf, "%u", snap->timestamp);
			xmlNodeSetContent(time_node, (xmlChar *)buf);
			unique_node = xmlNewChild(pool_node, NULL, (xmlChar *)"unique", NULL);
			sprintf(buf, "%u_%s", snap->timestamp, p0->name);
			xmlNodeSetContent(unique_node, (xmlChar *)buf);
			name_node = xmlNewChild(pool_node, NULL, (xmlChar *)"pool_name", NULL);
			sprintf(buf, "%s", p0->name);
			xmlNodeSetContent(name_node, (xmlChar *)buf);
			alloc_node = xmlNewChild(pool_node, NULL, (xmlChar *)"alloc", NULL);
			sprintf(buf, "%lu", p1->alloc);
			xmlNodeSetContent(alloc_node, (xmlChar *)buf);
			free_node = xmlNewChild(pool_node, NULL, (xmlChar *)"free", NULL);
			sprintf(buf, "%lu", p1->space - p1->alloc);
			xmlNodeSetContent(free_node, (xmlChar *)buf);
			reads_node = xmlNewChild(pool_node, NULL, (xmlChar *)"rops", NULL);
			sprintf(buf, "%.2lf", rps);
			xmlNodeSetContent(reads_node, (xmlChar *)buf);
			writes_node = xmlNewChild(pool_node, NULL, (xmlChar *)"wops", NULL);
			sprintf(buf, "%.2lf", wps);
			xmlNodeSetContent(writes_node, (xmlChar *)buf);
			nread_node = xmlNewChild(pool_node, NULL, (xmlChar *)"rbytes", NULL);
			sprintf(buf, "%.2lf", rbps);
			xmlNodeSetContent(nread_node, (xmlChar *)buf);
			nwritten_node = xmlNewChild(pool_node, NULL, (xmlChar *)"wbytes", NULL);
			sprintf(buf, "%.2lf", wbps);
			xmlNodeSetContent(nwritten_node, (xmlChar *)buf);

			p0 = AVL_NEXT(&old_snap->stat, p0);
			p1 = AVL_NEXT(&snap->stat, p1);
		} else if (cmp < 0)
			p0 = AVL_NEXT(&old_snap->stat, p0);
		else
			p1 = AVL_NEXT(&snap->stat, p1);
	}

	if (do_mkdir(dir) != 0) {
		close_xml_file(&perf_doc, NULL);
		return;
	}
	sprintf(path, "%s/%u", dir, snap->timestamp);
	close_xml_file(&perf_doc, path);
}

static int
extract_zpool_stat(struct zpool_stat_snapshot *snap)
{
	avl_tree_t *tree = &snap->stat;
	zpool_node_t *zn;
	struct per_zpool_stat *stat;
	nvlist_t *config, *nvroot;
	vdev_stat_t *vs;
	uint_t c;
	int refresh = 0;
	boolean_t missing;

	for (zn = avl_first(&pool_list); zn; zn = AVL_NEXT(&pool_list, zn)) {
again:
		config = zpool_get_config(zn->zn_handle, NULL);
		verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    	&nvroot) == 0);
		verify(nvlist_lookup_uint64_array(nvroot, ZPOOL_CONFIG_VDEV_STATS,
	    	(uint64_t **)&vs, &c) == 0);
		if (!refresh) {
			refresh = 1;
			printf("%s %lu %lu %lu %lu %lu\n", zpool_get_name(zn->zn_handle),
				vs->vs_alloc, vs->vs_ops[ZIO_TYPE_READ], vs->vs_ops[ZIO_TYPE_WRITE],
				vs->vs_bytes[ZIO_TYPE_READ], vs->vs_bytes[ZIO_TYPE_WRITE]);
			if (zpool_refresh_stats(zn->zn_handle, &missing) != 0)
				continue;
			goto again;
		}
		stat = malloc(sizeof(struct per_zpool_stat));
		if (stat == NULL)
			return (-1);
		strncpy(stat->name, zpool_get_name(zn->zn_handle), 32);
		stat->vs_timestamp = (uint64_t)vs->vs_timestamp;
		stat->alloc = vs->vs_alloc;
		stat->space = vs->vs_space;
		stat->read = vs->vs_ops[ZIO_TYPE_READ];
		stat->written = vs->vs_ops[ZIO_TYPE_WRITE];
		stat->nread = vs->vs_bytes[ZIO_TYPE_READ];
		stat->nwritten = vs->vs_bytes[ZIO_TYPE_WRITE];
		avl_add(tree, stat);
		printf("avl_add %s %lu %lu %lu %lu %lu\n", stat->name, stat->alloc,
			stat->read, stat->written, stat->nread, stat->nwritten);
	}
	return (0);
}

#define	PROC_ZFS	"/proc/spl/kstat/zfs"

static struct per_zpool_stat *
find_zpool_stat(struct zpool_stat_snapshot *snap, const char *name)
{
	struct per_zpool_stat search;
	avl_index_t where;

	strcpy(search.name, name);
	return(avl_find(&snap->stat, &search, &where));
}

static int
parse_proc_zfs(struct zpool_stat_snapshot *snap)
{
	DIR *dirp, *dirp1;
	struct dirent *ent;
	char path[64];
	struct per_zpool_stat *stat;
	struct parse_result *result;
	struct line_buf *buf;
	int find_header;
	unsigned long long int ull;

	dirp = opendir(PROC_ZFS);
	if (dirp == NULL) {
		printf("opendir %s failed\n", PROC_ZFS);
		return (-1);
	}

	while ((ent = readdir(dirp)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;
		snprintf(path, 64, "%s/%s", PROC_ZFS, ent->d_name);
		dirp1 = opendir(path);
		if (dirp1 == NULL)
			continue;
		stat = find_zpool_stat(snap, ent->d_name);
		closedir(dirp1);
		if (stat == NULL)
			continue;
		strcat(path, "/io");
		result = parse_file(path);
		if (result == NULL) {
			printf("parse file %s failed\n", path);
			closedir(dirp);
			return (-1);
		}
		printf("parse file %s\n", path);
		find_header = 0;
		for (buf = result->head; buf; buf = buf->next) {
			if (buf->bufc < 4)
				continue;
			if (find_header) {
				if ((ull = str2ull(buf->bufv[0])) == INVAL_ULL) {
					printf("str2ull: invalid number: %s\n", buf->bufv[0]);
					break;
				}
				stat->proc_nread = ull;
				if ((ull = str2ull(buf->bufv[1])) == INVAL_ULL) {
					printf("str2ull: invalid number: %s\n", buf->bufv[1]);
					break;
				}
				stat->proc_nwritten = ull;
				if ((ull = str2ull(buf->bufv[2])) == INVAL_ULL) {
					printf("str2ull: invalid number: %s\n", buf->bufv[2]);
					free(stat);
					break;
				}
				stat->proc_reads = ull;
				if ((ull = str2ull(buf->bufv[3])) == INVAL_ULL) {
					printf("str2ull: invalid number: %s\n", buf->bufv[3]);
					free(stat);
					break;
				}
				stat->proc_writes = ull;
				break;
			}
			if (strcmp(buf->bufv[0], "nread") == 0)
				find_header = 1;
		}
		free_parse_result(result);
	}

	closedir(dirp);
	return (0);
}

void
perf_stat_zpool(void)
{
	struct zpool_stat_snapshot *snap;
	char path[128];

	if (pool_list_init() != 0) {
		printf("init zpool perf stat failed\n");
		return;
	}

	snap = malloc(sizeof(struct zpool_stat_snapshot));
	if (snap == NULL) {
		printf("alloc zpool_stat_snapshot failed\n");
		pool_list_fini();
		return;
	}

	snap->timestamp = time(NULL);
	avl_create(&snap->stat, zpool_stat_compare, sizeof (struct per_zpool_stat),
		offsetof(struct per_zpool_stat, node));
	if (extract_zpool_stat(snap) == -1) {
		printf("get zpool perf stat failed\n");
		goto failed;
	}
	if (parse_proc_zfs(snap) == -1) {
		printf("parse proc zfs failed\n");
		goto failed;
	}

	if (zpool_stat_snapshot_minute == NULL)
		zpool_stat_snapshot_minute = dup_zpool_stat_snapshot(snap);
	else if (diff_time(zpool_stat_snapshot_minute->timestamp, snap->timestamp) >= ONE_MINUTE) {
		sprintf(path, "%s/minute/pool", PERF_STAT_DIR);
		store_zpool_stat_history(zpool_stat_snapshot_minute, snap, path);
		free_zpool_stat_snapshot(zpool_stat_snapshot_minute);
		zpool_stat_snapshot_minute = dup_zpool_stat_snapshot(snap);
	}
	if (zpool_stat_snapshot_hour == NULL)
		zpool_stat_snapshot_hour = dup_zpool_stat_snapshot(snap);
	else if (diff_time(zpool_stat_snapshot_hour->timestamp, snap->timestamp) >= ONE_HOUR) {
		sprintf(path, "%s/hour/pool", PERF_STAT_DIR);
		store_zpool_stat_history(zpool_stat_snapshot_hour, snap, path);
		free_zpool_stat_snapshot(zpool_stat_snapshot_hour);
		zpool_stat_snapshot_hour = dup_zpool_stat_snapshot(snap);
	}
	if (zpool_stat_snapshot_day == NULL)
		zpool_stat_snapshot_day = dup_zpool_stat_snapshot(snap);
	else if (diff_time(zpool_stat_snapshot_day->timestamp, snap->timestamp) >= ONE_DAY) {
		sprintf(path, "%s/day/pool", PERF_STAT_DIR);
		store_zpool_stat_history(zpool_stat_snapshot_day, snap, path);
		free_zpool_stat_snapshot(zpool_stat_snapshot_day);
		zpool_stat_snapshot_day = dup_zpool_stat_snapshot(snap);
	}
	if (zpool_stat_snapshot_week == NULL)
		zpool_stat_snapshot_week = dup_zpool_stat_snapshot(snap);
	else if (diff_time(zpool_stat_snapshot_week->timestamp, snap->timestamp) >= ONE_WEEK) {
		sprintf(path, "%s/week/pool", PERF_STAT_DIR);
		store_zpool_stat_history(zpool_stat_snapshot_week, snap, path);
		free_zpool_stat_snapshot(zpool_stat_snapshot_week);
		zpool_stat_snapshot_week = dup_zpool_stat_snapshot(snap);
	}
	if (zpool_stat_snapshot_month == NULL)
		zpool_stat_snapshot_month = dup_zpool_stat_snapshot(snap);
	else if (diff_date(zpool_stat_snapshot_month->timestamp, snap->timestamp) >= di_month) {
		sprintf(path, "%s/month/pool", PERF_STAT_DIR);
		store_zpool_stat_history(zpool_stat_snapshot_month, snap, path);
		free_zpool_stat_snapshot(zpool_stat_snapshot_month);
		zpool_stat_snapshot_month = dup_zpool_stat_snapshot(snap);
	}
	if (zpool_stat_snapshot_year == NULL)
		zpool_stat_snapshot_year = dup_zpool_stat_snapshot(snap);
	else if (diff_date(zpool_stat_snapshot_year->timestamp, snap->timestamp) >= di_year) {
		sprintf(path, "%s/year/pool", PERF_STAT_DIR);
		store_zpool_stat_history(zpool_stat_snapshot_year, snap, path);
		free_zpool_stat_snapshot(zpool_stat_snapshot_year);
		zpool_stat_snapshot_year = dup_zpool_stat_snapshot(snap);
	}

failed:
	free_zpool_stat_snapshot(snap);
	pool_list_fini();
}

struct per_zpool_stat2 {
	char	name[32];
	uint64_t	alloc;
	uint64_t	free;
	double	rps;
	double	wps;
	double	rbps;
	double	wbps;
	avl_node_t	node;
};

struct zpool_stat_snapshot2 {
	uint32_t	timestamp;
	avl_tree_t	stat;
	avl_node_t	node;
};

avl_tree_t	zpool_stat_snapshot_list_minute;
avl_tree_t	zpool_stat_snapshot_list_hour;
avl_tree_t	zpool_stat_snapshot_list_day;
avl_tree_t	zpool_stat_snapshot_list_week;
avl_tree_t	zpool_stat_snapshot_list_month;
avl_tree_t	zpool_stat_snapshot_list_year;

static int
per_zpool_stat_compare(const void *larg, const void *rarg)
{
	struct per_zpool_stat2 *l = (struct per_zpool_stat2 *)larg;
	struct per_zpool_stat2 *r = (struct per_zpool_stat2 *)rarg;
	const char *lname = l->name;
	const char *rname = r->name;
	int cmp = strcmp(lname, rname);

	if (cmp < 0)
		return (-1);
	if (cmp > 0)
		return (1);
	return (0);
}

static int
zpool_stat_snapshot_compare(const void *larg, const void *rarg)
{
	struct zpool_stat_snapshot2 *l = (struct zpool_stat_snapshot2 *)larg;
	struct zpool_stat_snapshot2 *r = (struct zpool_stat_snapshot2 *)rarg;

	if (l->timestamp < r->timestamp)
		return (-1);
	if (l->timestamp > r->timestamp)
		return (1);
	return (0);
}

static void
free_zpool_stat_snapshot2(struct zpool_stat_snapshot2 *snap)
{
	struct per_zpool_stat2 *node;
	void *cookie;

	cookie = NULL;
	while ((node = avl_destroy_nodes(&snap->stat, &cookie)) != NULL)
		free(node);
	avl_destroy(&snap->stat);
	free(snap);
}

static void
free_zpool_stat_snapshot_list(avl_tree_t *tree)
{
	struct zpool_stat_snapshot2 *node;
	void *cookie;

	cookie = NULL;
	while ((node = avl_destroy_nodes(tree, &cookie)) != NULL)
		free_zpool_stat_snapshot2(node);
	avl_destroy(tree);
}

void
perf_stat_zpool_init(void)
{
	avl_create(&zpool_stat_snapshot_list_minute, zpool_stat_snapshot_compare,
		sizeof (struct zpool_stat_snapshot2), 
		offsetof(struct zpool_stat_snapshot2, node));
	avl_create(&zpool_stat_snapshot_list_hour, zpool_stat_snapshot_compare,
		sizeof (struct zpool_stat_snapshot2), 
		offsetof(struct zpool_stat_snapshot2, node));
	avl_create(&zpool_stat_snapshot_list_day, zpool_stat_snapshot_compare,
		sizeof (struct zpool_stat_snapshot2), 
		offsetof(struct zpool_stat_snapshot2, node));
	avl_create(&zpool_stat_snapshot_list_week, zpool_stat_snapshot_compare,
		sizeof (struct zpool_stat_snapshot2), 
		offsetof(struct zpool_stat_snapshot2, node));
	avl_create(&zpool_stat_snapshot_list_month, zpool_stat_snapshot_compare,
		sizeof (struct zpool_stat_snapshot2), 
		offsetof(struct zpool_stat_snapshot2, node));
	avl_create(&zpool_stat_snapshot_list_year, zpool_stat_snapshot_compare,
		sizeof (struct zpool_stat_snapshot2), 
		offsetof(struct zpool_stat_snapshot2, node));
}

void
perf_stat_zpool_fini(void)
{
	free_zpool_stat_snapshot_list(&zpool_stat_snapshot_list_minute);
	free_zpool_stat_snapshot_list(&zpool_stat_snapshot_list_hour);
	free_zpool_stat_snapshot_list(&zpool_stat_snapshot_list_day);
	free_zpool_stat_snapshot_list(&zpool_stat_snapshot_list_week);
	free_zpool_stat_snapshot_list(&zpool_stat_snapshot_list_month);
	free_zpool_stat_snapshot_list(&zpool_stat_snapshot_list_year);
}

static void
store_zpool_stat_history2(struct zpool_stat_snapshot2 *snap, const char *dir)
{
	xmlNodePtr root_node = NULL;
	xmlDocPtr perf_doc = NULL;
	xmlNodePtr pool_node, time_node, unique_node, name_node,
		alloc_node, free_node, reads_node, writes_node, nread_node, nwritten_node;
	struct per_zpool_stat2 *p;
	char buf[32];
	char path[128];

	if (create_xml_file(&perf_doc, &root_node) == NULL)
		return;

	for (p = avl_first(&snap->stat); p; p = AVL_NEXT(&snap->stat, p)) {
		pool_node = xmlNewChild(root_node, NULL, (xmlChar *)"pool", NULL);
		time_node = xmlNewChild(pool_node, NULL, (xmlChar *)"time", NULL);
		sprintf(buf, "%u", snap->timestamp);
		xmlNodeSetContent(time_node, (xmlChar *)buf);
		unique_node = xmlNewChild(pool_node, NULL, (xmlChar *)"unique", NULL);
		sprintf(buf, "%u_%s", snap->timestamp, p->name);
		xmlNodeSetContent(unique_node, (xmlChar *)buf);
		name_node = xmlNewChild(pool_node, NULL, (xmlChar *)"pool_name", NULL);
		sprintf(buf, "%s", p->name);
		xmlNodeSetContent(name_node, (xmlChar *)buf);
		alloc_node = xmlNewChild(pool_node, NULL, (xmlChar *)"alloc", NULL);
		sprintf(buf, "%lu", p->alloc);
		xmlNodeSetContent(alloc_node, (xmlChar *)buf);
		free_node = xmlNewChild(pool_node, NULL, (xmlChar *)"free", NULL);
		sprintf(buf, "%lu", p->free);
		xmlNodeSetContent(free_node, (xmlChar *)buf);
		reads_node = xmlNewChild(pool_node, NULL, (xmlChar *)"rops", NULL);
		sprintf(buf, "%.2lf", p->rps);
		xmlNodeSetContent(reads_node, (xmlChar *)buf);
		writes_node = xmlNewChild(pool_node, NULL, (xmlChar *)"wops", NULL);
		sprintf(buf, "%.2lf", p->wps);
		xmlNodeSetContent(writes_node, (xmlChar *)buf);
		nread_node = xmlNewChild(pool_node, NULL, (xmlChar *)"rbytes", NULL);
		sprintf(buf, "%.2lf", p->rbps);
		xmlNodeSetContent(nread_node, (xmlChar *)buf);
		nwritten_node = xmlNewChild(pool_node, NULL, (xmlChar *)"wbytes", NULL);
		sprintf(buf, "%.2lf", p->wbps);
		xmlNodeSetContent(nwritten_node, (xmlChar *)buf);
	}

	if (do_mkdir(dir) != 0) {
		close_xml_file(&perf_doc, NULL);
		return;
	}
	sprintf(path, "%s/%u", dir, snap->timestamp);
	close_xml_file(&perf_doc, path);
}

struct psz_line {
	uint64_t	alloc;
	uint64_t	free;
	uint64_t	rps;
	uint64_t	wps;
	uint64_t	rbps;
	uint64_t	wbps;
	list_node_t	node;
};

struct psz_pool {
	char	name[32];
	list_t	list;
	avl_node_t	node;
};

static struct psz_pool *
alloc_psz_pool(const char *name)
{
	struct psz_pool *pool = NULL;

	pool = malloc(sizeof (struct psz_pool));
	if (pool == NULL)
		return (NULL);
	list_create(&pool->list, sizeof (struct psz_line),
		offsetof(struct psz_line, node));
	strcpy(pool->name, name);
	return (pool);
}

static struct psz_pool *
get_psz_pool(avl_tree_t *tree, const char *name)
{
	struct psz_pool search, *pool;
	avl_index_t where;

	strcpy(search.name, name);
	pool = avl_find(tree, &search, &where);
	if (pool == NULL) {
		pool = alloc_psz_pool(name);
		if (pool == NULL)
			return (NULL);
		avl_insert(tree, pool, where);
	}
	return (pool);
}

static int
psz_pool_compare(const void *larg, const void *rarg)
{
	struct psz_pool *l = (struct psz_pool *)larg;
	struct psz_pool *r = (struct psz_pool *)rarg;
	const char *lname = l->name;
	const char *rname = r->name;
	int cmp = strcmp(lname, rname);

	if (cmp < 0)
		return (-1);
	if (cmp > 0)
		return (1);
	return (0);
}

static void
parse_zpool_iostat_free(avl_tree_t *tree)
{
	struct psz_pool *pool;
	struct psz_line *line;
	void *cookie;

	cookie = NULL;
	while ((pool = avl_destroy_nodes(tree, &cookie)) != NULL) {
		while ((line = list_remove_tail(&pool->list)) != NULL)
			free(line);
		list_destroy(&pool->list);
		free(pool);
	}
	avl_destroy(tree);
	free(tree);
}

static avl_tree_t *
parse_zpool_iostat(const char *file)
{
	avl_tree_t *tree;
	struct parse_result *result;
	struct line_buf *buf;
	uint64_t num[6]; /* alloc, free, rps, wps, rbps, wbps */
	int i;
	struct psz_pool *pool;
	struct psz_line *line;

	result = parse_file(file);
	if (result == NULL) {
		syslog(LOG_ERR, "parse file %s failed", file);
		return (NULL);
	}

	tree = malloc(sizeof (avl_tree_t));
	if (tree == NULL) {
		free_parse_result(result);
		return (NULL);
	}
	avl_create(tree, psz_pool_compare, sizeof (struct psz_pool),
		offsetof(struct psz_pool, node));

	for (buf = result->head; buf; buf = buf->next) {
		if (buf->bufc < 7)
			continue;
		for (i = 1; i < 7; i++) {
			if (nicestrtonum(buf->bufv[i], &num[i-1]) != 0)
				break;
		}
		if (i < 7)
			continue;
		line = malloc(sizeof (struct psz_line));
		if (line == NULL)
			continue;
		line->alloc = num[0];
		line->free = num[1];
		line->rps = num[2];
		line->wps = num[3];
		line->rbps = num[4];
		line->wbps = num[5];
		pool = get_psz_pool(tree, buf->bufv[0]);
		if (pool == NULL) {
			free(line);
			continue;
		}
		list_insert_tail(&pool->list, line);
	}
	return (tree);
}

static struct zpool_stat_snapshot2 *
construct_zpool_stat_snaphost(avl_tree_t *tree)
{
	struct zpool_stat_snapshot2 *snap;
	struct psz_pool *pool;
	struct psz_line *line;
	struct per_zpool_stat2 *stat;
	uint64_t lines, alloc, fr, rps, wps, rbps, wbps;
	int error = 0;

	snap = malloc(sizeof(struct zpool_stat_snapshot2));
	if (snap == NULL)
		return (NULL);
	snap->timestamp = time(NULL);
	avl_create(&snap->stat, per_zpool_stat_compare,
		sizeof (struct per_zpool_stat2),
		offsetof(struct per_zpool_stat2, node));

	for (pool = avl_first(tree); pool; pool = AVL_NEXT(tree, pool)) {
		lines = alloc = fr = rps = wps = rbps = wbps = 0;
		for (line = list_head(&pool->list); line;
			line = list_next(&pool->list, line)) {
			alloc = line->alloc;
			fr = line->free;
			rps += line->rps;
			wps += line->wps;
			rbps += line->rbps;
			wbps += line->wbps;
			lines++;
		}
		stat = malloc(sizeof (struct per_zpool_stat2));
		if (stat == NULL) {
			error = -1;
			break;
		}
		stat->alloc = alloc;
		stat->free = fr;
		stat->rps = (double)rps / (double)lines;
		stat->wps = (double)wps / (double)lines;
		stat->rbps = (double)rbps / (double)lines;
		stat->wbps = (double)wbps / (double)lines;
		strcpy(stat->name, pool->name);
		avl_add(&snap->stat, stat);
		syslog(LOG_DEBUG, "construct_zpool_stat_snaphost: "
			"%s %lu %lu %.2lf %.2lf %.2lf %.2lf",
			stat->name, stat->alloc, stat->free,
			stat->rps, stat->wps, stat->rbps, stat->wbps);
	}

	if (error != 0) {
		free_zpool_stat_snapshot2(snap);
		return (NULL);
	}
	return (snap);
}

static struct zpool_stat_snapshot2 *
cons_from_zpool_iostat_snapshot_list(avl_tree_t *tree, uint32_t timestamp)
{
	struct zpool_stat_snapshot2 *snap, *new_snap, *p;
	struct per_zpool_stat2 *stat, *p0;
	avl_index_t where;
	unsigned int count;

	snap = avl_first(tree);
	if (snap == NULL || snap->timestamp > timestamp)
		return (NULL);

	new_snap = malloc(sizeof (struct zpool_stat_snapshot2));
	avl_create(&new_snap->stat, per_zpool_stat_compare,
		sizeof (struct per_zpool_stat2),
		offsetof(struct per_zpool_stat2, node));
	for (count = 0, p = snap; p; count++, p = AVL_NEXT(tree, p)) {
		for (p0 = avl_first(&p->stat); p0; p0 = AVL_NEXT(&p->stat, p0)) {
			stat = avl_find(&new_snap->stat, p0, &where);
			if (stat == NULL) {
				stat = malloc(sizeof (struct per_zpool_stat2));
				if (stat == NULL)
					goto failed;
				bzero(stat, sizeof (struct per_zpool_stat2));
				strcpy(stat->name, p0->name);
				avl_add(&new_snap->stat, stat);
			}
			stat->alloc = p0->alloc;
			stat->free = p0->free;
			stat->rps += p0->rps;
			stat->wps += p0->wps;
			stat->rbps += p0->rbps;
			stat->wbps += p0->wbps;
		}
	}
	for (stat = avl_first(&new_snap->stat); stat;
		stat = AVL_NEXT(&new_snap->stat, stat)) {
		stat->rps /= (double)count;
		stat->wps /= (double)count;
		stat->rbps /= (double)count;
		stat->wbps /= (double)count;
		syslog(LOG_DEBUG, "cons_from_zpool_iostat_snapshot_list: "
			"%s %lu %lu %.2lf %.2lf %.2lf %.2lf",
			stat->name, stat->alloc, stat->free,
			stat->rps, stat->wps, stat->rbps, stat->wbps);
	}

	snap = avl_last(tree);
	new_snap->timestamp = snap->timestamp;
	return (new_snap);
failed:
	free_zpool_stat_snapshot2(new_snap);
	return (NULL);
}

static void
zpool_stat_snapshot_list_add(avl_tree_t *tree,
	struct zpool_stat_snapshot2 *snap)
{
	ulong_t numnodes;
	avl_add(tree, snap);
	numnodes = avl_numnodes(tree);
	if ((tree == &zpool_stat_snapshot_list_minute && numnodes > 61) ||
		(tree == &zpool_stat_snapshot_list_hour && numnodes > 25) ||
		(tree == &zpool_stat_snapshot_list_day && numnodes > 8) ||
		(tree == &zpool_stat_snapshot_list_week && numnodes > 5) ||
		(tree == &zpool_stat_snapshot_list_month && numnodes > 13)) {
		struct zpool_stat_snapshot2 *node = avl_first(tree);
		avl_remove(tree, node);
	}
}

void
perf_stat_zpool2(void)
{
	struct zpool_stat_snapshot2 *snap, *old_snap, *s;
	char path[128], file[32];
	avl_tree_t *tree;

	snprintf(path, 128, "%s/%s", PERF_STAT_DIR, ZPOOL_IOSTAT_DIR);
	if (find_last_file(path, file, 32) == NULL) {
		syslog(LOG_DEBUG, "find_last_file error");
		return;
	}

	snprintf(path, 128, "%s/%s/%s", PERF_STAT_DIR, ZPOOL_IOSTAT_DIR, file);
	tree = parse_zpool_iostat(path);
	if (tree == NULL) {
		syslog(LOG_DEBUG, "parse_zpool_iostat error");
		return;
	}
	snap = construct_zpool_stat_snaphost(tree);
	if (snap == NULL) {
		syslog(LOG_DEBUG, "construct_zpool_stat_snaphost error");
		parse_zpool_iostat_free(tree);
		return;
	}

	old_snap = avl_last(&zpool_stat_snapshot_list_minute);
	if (old_snap && diff_time(old_snap->timestamp, snap->timestamp) >= ONE_MINUTE) {
		snprintf(path, 128, "%s/minute/pool", PERF_STAT_DIR);
		store_zpool_stat_history2(snap, path);
	}
	zpool_stat_snapshot_list_add(&zpool_stat_snapshot_list_minute, snap);

	old_snap = avl_last(&zpool_stat_snapshot_list_hour);
	if (old_snap == NULL || diff_time(old_snap->timestamp, snap->timestamp) >= ONE_HOUR) {
		s = cons_from_zpool_iostat_snapshot_list(&zpool_stat_snapshot_list_minute,
			snap->timestamp - ONE_HOUR);
		if (s) {
			snprintf(path, 128, "%s/hour/pool", PERF_STAT_DIR);
			store_zpool_stat_history2(s, path);
			zpool_stat_snapshot_list_add(&zpool_stat_snapshot_list_hour, s);
		}
	}

	old_snap = avl_last(&zpool_stat_snapshot_list_day);
	if (old_snap == NULL || diff_time(old_snap->timestamp, snap->timestamp) >= ONE_DAY) {
		s = cons_from_zpool_iostat_snapshot_list(&zpool_stat_snapshot_list_hour,
			snap->timestamp - ONE_DAY);
		if (s) {
			snprintf(path, 128, "%s/day/pool", PERF_STAT_DIR);
			store_zpool_stat_history2(s, path);
			zpool_stat_snapshot_list_add(&zpool_stat_snapshot_list_day, s);
		}
	}

	old_snap = avl_last(&zpool_stat_snapshot_list_week);
	if (old_snap == NULL || diff_time(old_snap->timestamp, snap->timestamp) >= ONE_WEEK) {
		s = cons_from_zpool_iostat_snapshot_list(&zpool_stat_snapshot_list_day,
			snap->timestamp - ONE_WEEK);
		if (s) {
			snprintf(path, 128, "%s/week/pool", PERF_STAT_DIR);
			store_zpool_stat_history2(s, path);
			zpool_stat_snapshot_list_add(&zpool_stat_snapshot_list_week, s);
		}
	}

	old_snap = avl_last(&zpool_stat_snapshot_list_month);
	if (old_snap == NULL || diff_date(old_snap->timestamp, snap->timestamp) >= di_month) {
		s = cons_from_zpool_iostat_snapshot_list(&zpool_stat_snapshot_list_week,
			snap->timestamp - ONE_MONTH);
		if (s) {
			snprintf(path, 128, "%s/month/pool", PERF_STAT_DIR);
			store_zpool_stat_history2(s, path);
			zpool_stat_snapshot_list_add(&zpool_stat_snapshot_list_month, s);
		}
	}

	old_snap = avl_last(&zpool_stat_snapshot_list_year);
	if (old_snap == NULL || diff_date(old_snap->timestamp, snap->timestamp) >= di_year) {
		s = cons_from_zpool_iostat_snapshot_list(&zpool_stat_snapshot_list_month,
			snap->timestamp - ONE_YEAR);
		if (s) {
			snprintf(path, 128, "%s/year/pool", PERF_STAT_DIR);
			store_zpool_stat_history2(s, path);
			zpool_stat_snapshot_list_add(&zpool_stat_snapshot_list_year, s);
		}
	}

	parse_zpool_iostat_free(tree);
}

void *
zpool_iostat_thread(void *arg)
{
	char command[100], path[64];
	uint32_t timestamp;
	struct thread_args *targs = (struct thread_args *)arg;

	snprintf(path, 64, "%s/%s", PERF_STAT_DIR, ZPOOL_IOSTAT_DIR);
	if (do_mkdir(path) != 0) {
		syslog(LOG_ERR, "create dir %s failed", path);
		return (NULL);
	}

	while (targs->exit_flag == 0) {
		timestamp = time(NULL);
		snprintf(command, 100, "zpool iostat 2 30 > %s/%u", path, timestamp);
		parse_cmd(command);
		syslog(LOG_DEBUG, "%s", command);
	}
	return (NULL);
}

