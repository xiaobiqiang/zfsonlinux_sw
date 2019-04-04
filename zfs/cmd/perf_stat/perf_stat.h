#ifndef	_PERF_STAT_H
#define	_PERF_STAT_H

#define	PERF_STAT_DIR	"/var/performance_stat"
#define	ZPOOL_IOSTAT_DIR	"zpool_iostat"

struct thread_args {
	int exit_flag;
};

extern void perf_stat_cpu(void);
extern void perf_stat_mem(void);
extern void perf_stat_netdev(void);
extern void perf_stat_lun(void);
extern void perf_stat_nfs(void);
extern void perf_stat_zpool(void);
extern void perf_stat_zpool_init(void);
extern void perf_stat_zpool_fini(void);
extern void perf_stat_zpool2(void);
extern void *zpool_iostat_thread(void *arg);
extern void perf_stat_fc(void);

#endif
