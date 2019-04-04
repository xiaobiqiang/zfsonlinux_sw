#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include "perf_stat.h"
#include "perf_util.h"
#include "systemd_util.h"

#define	PID_FILE	RUNSTATEDIR "/perf_stat.pid"

unsigned int alarm_seconds = 60;

#if 0
static void
sig_handler(int signo)
{
	alarm(alarm_seconds);
}
#endif

int
main(int argc, char *argv[])
{
#if 0
	struct sigaction sa;
	sigset_t newmask, oldmask, suspendmask;
#endif
	int c, daemon_disable = 0;
	pthread_t tid;
	struct timespec ts;
	pthread_cond_t cv;
	pthread_mutex_t lock;
	struct thread_args targs;

	while ((c = getopt(argc, argv, "d")) != EOF) {
		switch (c) {
		case 'd':
			daemon_disable = 1;
			break;
		default:
			break;
		}
	}

	if (!daemon_disable)
		systemd_daemonize(PID_FILE);
	else
		write_pid(PID_FILE);

	pthread_mutex_init(&lock, NULL);
	pthread_cond_init(&cv, NULL);

	targs.exit_flag = 0;
	if (pthread_create(&tid, NULL, zpool_iostat_thread, &targs) != 0) {
		syslog(LOG_ERR, "create thread failed");
		exit(1);
	}

#if 0
	sa.sa_handler = sig_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGALRM, &sa, NULL) < 0) {
		printf("sigaction error %d\n", errno);
		exit(1);
	}

	sigemptyset(&newmask);
	sigaddset(&newmask, SIGALRM);
	sigprocmask(SIG_BLOCK, &newmask, &oldmask);
	alarm(alarm_seconds);
	suspendmask = oldmask;
	sigdelset(&suspendmask, SIGALRM);
#endif

	perf_stat_zpool_init();

	while (1) {
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += alarm_seconds;

		perf_stat_cpu();
		perf_stat_mem();
		perf_stat_netdev();
		perf_stat_lun();
		perf_stat_nfs();
		perf_stat_zpool2();
        perf_stat_fc();
		clear_perf_stat_history();
#if 0
		sigsuspend(&suspendmask);
#endif
		pthread_cond_timedwait(&cv, &lock, &ts);
	}

	targs.exit_flag = 1;
	pthread_join(tid, NULL);

	perf_stat_zpool_fini();

	return (0);
}
