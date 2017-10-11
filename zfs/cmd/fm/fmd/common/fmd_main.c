/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>

#include "fmd.h"
#include "fmd_subr.h"
#include "fmd_error.h"
#include "fmd_string.h"
#include "fmd_conf.h"
#include "fmd_systemd.h"

#ifdef LHL_DBG
#include <fm/LHL_DEBUG.h>
FILE *log_file;
int log_step;
void log_null(FILE *file, const char *str){}
#endif

/* ZENGXL ADD 2014-06-05 Thu */
#include <sys/types.h>
#include <dirent.h>
/* END ADD */

fmd_t fmd;
extern pthread_t main_tid;
/*
 * For DEBUG builds, we define a set of hooks for libumem that provide useful
 * default settings for the allocator's debugging facilities.
 */
#ifdef	DEBUG
const char *
_umem_debug_init()
{
	return ("default,verbose"); /* $UMEM_DEBUG setting */
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents"); /* $UMEM_LOGGING setting */
}
#endif	/* DEBUG */

/*
 * We use a two-phase algorithm for becoming a daemon because we want the
 * daemon process (the child) to do the work of becoming MT-hot and opening our
 * event transport.  Since these operations can fail and need to result in the
 * daemon failing to start, the parent must wait until fmd_run() completes to
 * know whether it can return zero or non-zero status to the invoking command.
 * The parent waits on a pipe inside this function to read the exit status.
 * The child gets the write-end of the pipe returned by daemonize_init() and
 * then fmd_run() uses the pipe to set the exit status and detach the parent.
 */
static int
daemonize_init(void)
{
	int status, pfds[2];
	sigset_t set, oset;
	struct rlimit rlim;
	char path[PATH_MAX];
	pid_t pid;

	/*
	 * Set our per-process core file path to leave core files in our
	 * var/fm/fmd directory, named after the PID to aid in debugging,
	 * and make sure that there is no restriction on core file size.
	 */
	(void) snprintf(path, sizeof (path),
	    "%s/var/fm/fmd/core.%s.%%p", fmd.d_rootdir, fmd.d_pname);

#if 0
	(void) core_set_process_path(path, strlen(path) + 1, fmd.d_pid);
#endif
	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;

	(void) setrlimit(RLIMIT_CORE, &rlim);

	/*
	 * Claim all the file descriptors we can.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
	}

	/*
	 * Reset all of our privilege sets to the minimum set of required
	 * privileges.  We continue to run as root so that files we create
	 * such as logs and checkpoints are secured in the /var filesystem.
	 */
#if 0
	if (__init_daemon_priv(PU_RESETGROUPS | PU_LIMITPRIVS | PU_INHERITPRIVS,
	    0, 0, /* run as uid 0 and gid 0 */
	    PRIV_FILE_DAC_EXECUTE, PRIV_FILE_DAC_READ, PRIV_FILE_DAC_SEARCH,
	    PRIV_FILE_DAC_WRITE, PRIV_FILE_OWNER, PRIV_PROC_OWNER,
	    PRIV_PROC_PRIOCNTL, PRIV_SYS_ADMIN, PRIV_SYS_CONFIG,
	    PRIV_SYS_DEVICES, PRIV_SYS_RES_CONFIG, PRIV_NET_PRIVADDR,
	    PRIV_SYS_MOUNT,
	    PRIV_SYS_NET_CONFIG, NULL) != 0)
		fmd_error(EFMD_EXIT, "additional privileges required to run\n");
#endif
	/*
	 * Block all signals prior to the fork and leave them blocked in the
	 * parent so we don't get in a situation where the parent gets SIGINT
	 * and returns non-zero exit status and the child is actually running.
	 * In the child, restore the signal mask once we've done our setsid().
	 */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT);
	(void) sigprocmask(SIG_BLOCK, &set, &oset);

	if (pipe(pfds) == -1)
		fmd_error(EFMD_EXIT, "failed to create pipe for daemonize");

	if ((pid = fork()) == -1)
		fmd_error(EFMD_EXIT, "failed to fork into background");
	/*
	 * If we're the parent process, wait for either the child to send us
	 * the appropriate exit status over the pipe or for the read to fail
	 * (presumably with 0 for EOF if our child terminated abnormally).
	 * If the read fails, exit with either the child's exit status if it
	 * exited or with FMD_EXIT_ERROR if it died from a fatal signal.
	 */
	if (pid != 0) {
		(void) close(pfds[1]);

		if (read(pfds[0], &status, sizeof (status)) == sizeof (status))
			_exit(status);

		if (waitpid(pid, &status, 0) == pid && WIFEXITED(status))
			_exit(WEXITSTATUS(status));

		_exit(FMD_EXIT_ERROR);
	}

	fmd.d_pid = getpid();
	(void) setsid();
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	(void) chdir("/");
	(void) umask(022);
	(void) close(pfds[0]);

	return (pfds[1]);
}

static void
daemonize_fini(int fd)
{
	(void) close(fd);

	if ((fd = open("/dev/null", O_RDWR)) >= 0) {
		(void) dup2(fd, STDIN_FILENO);
		(void) dup2(fd, STDOUT_FILENO);
		(void) dup2(fd, STDERR_FILENO);
		(void) close(fd);
	}
}

static void
handler(int sig)
{
	if (fmd.d_signal == 0)
		fmd.d_signal = sig;
}

static int
usage(const char *arg0, FILE *fp)
{
	(void) fprintf(fp,
	    "Usage: %s [-V] [-f file] [-o opt=val] [-R dir]\n", arg0);

	return (FMD_EXIT_USAGE);
}

int
main(int argc, char *argv[])
{
	const char *opt_f = NULL, *opt_R = NULL;
	const char optstr[] = "f:o:R:V";
	int c, pfd = -1, opt_V = 0;
	char *p;

	struct sigaction act;
	sigset_t set;

	/*
	 * Parse the command-line once to validate all options and retrieve
	 * any overrides for our configuration file and root directory.
	 */
	while ((c = getopt(argc, argv, optstr)) != EOF) {
		switch (c) {
		case 'f':
			opt_f = optarg;
			break;
		case 'o':
			break; /* handle -o below */
		case 'R':
			opt_R = optarg;
			break;
		case 'V':
			opt_V++;
			break;
		default:
			return (usage(argv[0], stderr));
		}
	}

	if (optind < argc)
		return (usage(argv[0], stderr));

	if (opt_V) {
#ifdef DEBUG
		const char *debug = " (DEBUG)";
#else
		const char *debug = "";

#endif
		(void) printf("%s: version %s%s\n",
		    argv[0], _fmd_version, debug);
		return (FMD_EXIT_SUCCESS);
	}
	main_tid = pthread_self();
	fmd_create(&fmd, argv[0], opt_R, opt_f);

	/*
	 * Now that we've initialized our global state, parse the command-line
	 * again for any configuration options specified using -o and set them.
	 */
	for (optind = 1; (c = getopt(argc, argv, optstr)) != EOF; ) {
		if (c == 'o') {
			if ((p = strchr(optarg, '=')) == NULL) {
				(void) fprintf(stderr, "%s: failed to set "
				    "option -o %s: option requires value\n",
				    fmd.d_pname, optarg);
				return (FMD_EXIT_USAGE);
			}

			*p++ = '\0'; /* strike out the delimiter */

			if (p[0] == '"' && p[strlen(p) - 1] == '"') {
				p[strlen(p) - 1] = '\0';
				(void) fmd_stresc2chr(++p);
			}

			if (fmd_conf_setprop(fmd.d_conf, optarg, p) != 0) {
				(void) fprintf(stderr,
				    "%s: failed to set option -o %s: %s\n",
				    fmd.d_pname, optarg, fmd_strerror(errno));
				return (FMD_EXIT_USAGE);
			}

		}
	}

	if (fmd.d_fmd_debug & FMD_DBG_HELP) {
		fmd_help(&fmd);
		fmd_destroy(&fmd);
		return (FMD_EXIT_SUCCESS);
	}

	/*
	 * Update the value of fmd.d_fg based on "fg" in case it changed.  We
	 * use this property to decide whether to daemonize below.
	 */
	(void) fmd_conf_getprop(fmd.d_conf, "fg", &fmd.d_fg);

	/*
	 * Once we're done setting our global state up, set up signal handlers
	 * for ensuring orderly termination on SIGTERM.  If we are starting in
	 * the foreground, we also use the same handler for SIGINT and SIGHUP.
	 */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT); /* always unblocked for ASSERT() */

	(void) sigfillset(&act.sa_mask);
	act.sa_handler = handler;
	act.sa_flags = 0;

	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigdelset(&set, SIGTERM);

	if (fmd.d_fg) {
	#if 0
		(void) sigaction(SIGHUP, &act, NULL);
		(void) sigdelset(&set, SIGHUP);
		(void) sigaction(SIGINT, &act, NULL);
		(void) sigdelset(&set, SIGINT);

		(void) sigdelset(&set, SIGTSTP);
		(void) sigdelset(&set, SIGTTIN);
		(void) sigdelset(&set, SIGTTOU);
	#endif
		
		write_pid();
		(void) printf("%s: [ loading modules ... ", fmd.d_pname);
		(void) fflush(stdout);
	} else {
		systemd_daemonize();
	#if 0
		pfd = daemonize_init();
	#endif
	}
#ifdef LHL_DBG
	if((log_file = fopen("/var/log/fmd.log", "a")) == NULL)
		DMESG("LHL ADD ++ open /var/log/fmd.log failed.\n");
	LOG("       #######   FMD Let's GO ... ## %d\n", (int)getpid());
#endif

	/*
	 * Prior to this point, we are single-threaded.  Once fmd_run() is
	 * called, we will be multi-threaded from this point on.  The daemon's
	 * main thread will wait at the end of this function for signals.
	 */
	fmd_run(&fmd, pfd);

	if (fmd.d_fg) {
		(void) printf("done ]\n");
		(void) printf("%s: [ awaiting events ]\n", fmd.d_pname);
	} else
		daemonize_fini(pfd);

	while (!fmd.d_signal)
		(void) sigsuspend(&set);

	fmd_destroy(&fmd);
	return (FMD_EXIT_SUCCESS);
}
