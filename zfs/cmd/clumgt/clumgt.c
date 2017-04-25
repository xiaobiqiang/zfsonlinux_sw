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
 * Copyright 2009 CeresData Co., Ltd.  All rights reserved.
 * Use is subject to license terms.
 */

#include <string.h>
#include <stdio.h>
#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>
#include <poll.h>
#include <sys/time.h>
#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "clumgt_impl.h"
#include "clu_cmd.h"

static void clumgt_exit(int status);
//static void test_flush_thread(void);
static pid_t enter_daemon_lock(void);
static void exit_daemon_lock(int exiting);
static void daemon_update(void);
//static void usage(void);
static void detachfromtty(void);
static void parse_args(int argc, char *argv[]);

/* set if invoked via /usr/lib/clumgt/clumgtd */
static int l_daemon_mode = FALSE;

/* output directed to syslog during daemon mode if set */
static int l_logflag = FALSE;

/* the program we were invoked as; ie argv[0] */
static char *l_prog;

/* used with verbose option -v or -V */
static int l_num_verbose = 0;
static char **l_verbose = NULL;


/* /etc/dev or <rootdir>/etc/dev */
static char *l_var_run_dir = VARRUN;


/* locking variables */
static int l_hold_daemon_lock = FALSE;
static int l_daemon_lock_fd;
static char l_daemon_lockfile[PATH_MAX + 1];


int
main(int argc, char *argv[])
{
	pid_t pid;
	char	c_hostname[HOSTNAMELEN];

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	
	if ((l_prog = strrchr(argv[0], '/')) == NULL) {
		l_prog = argv[0];
	} else {
		l_prog++;
	}

	if (getuid() != 0) {
		clumgt_errprint("you must be root to run this program\n");
		clumgt_exit(1);
		/*NOTREACHED*/
	}

	/*
	 * Close all files except stdin/stdout/stderr
	 */
	//closefrom(3);

	(void) umask(0);

	parse_args(argc, argv);

	if (l_daemon_mode == TRUE) {
		/*
		 * fork before detaching from tty in order to print error
		 * message if unable to acquire file lock.  locks not preserved
		 * across forks.  Even under debug we want to fork so that
		 * when executed at boot we don't hang.
		 */
		if (fork() != 0) {
			clumgt_exit(0);
			/*NOTREACHED*/
		}

		putenv("CLUMGT=2");
		
		/* set directory to / so it coredumps there */
		if (chdir("/") == -1) {
			clumgt_errprint(CHROOT_FAILED, strerror(errno));
		}
		
		/*  initialize the sync queue */
		sync_initqueue();

		/* initialize the sync master */
		sync_init_master();
		
		/* only one daemon can run at a time */
		if ((pid = enter_daemon_lock()) == getpid()) {
			detachfromtty();

			if (get_local_hostname(c_hostname, sizeof(c_hostname)) < 0) {
				clumgt_errprint("get hostname failed\n");
				clumgt_exit(1);
			}
			
			if(clumgt_server() != 0) {
				clumgt_errprint("create server failed\n");
				clumgt_exit(1);
			}

			daemon_update();
			clumgt_exit(0);
			/*NOTREACHED*/
		} else {
			clumgt_errprint(DAEMON_RUNNING, pid);
			clumgt_exit(1);
			/*NOTREACHED*/
		}
	} else {
		/* not a daemon, so just ....*/
		return clu_cmd_handle(argc, argv);
	}
	return 0;
}

/*
 * Parse arguments for all 6 programs handled from devfsadm.
 */
static void
parse_args(int argc, char *argv[])
{

	if (strcmp(l_prog, CLUMGTD) == 0) {
		l_daemon_mode = TRUE;
	}

}


/*ARGSUSED*/
static void
print_cache_signal(int signo)
{
	if (signal(SIGUSR1, print_cache_signal) == SIG_ERR) {
		clumgt_errprint("signal SIGUSR1 failed: %s\n", strerror(errno));
		clumgt_exit(1);
		/*NOTREACHED*/
	}
}


/*
 *
 */
static void
daemon_update(void)
{
	char *fcn = "daemon_update: ";
	clumgt_print(CHATTY_MID, "%senter\n", fcn);

	if (signal(SIGUSR1, print_cache_signal) == SIG_ERR) {
		clumgt_errprint("signal SIGUSR1 failed: %s\n", strerror(errno));
		clumgt_exit(1);
		/*NOTREACHED*/
	}
	if (signal(SIGTERM, print_cache_signal) == SIG_ERR) {
		clumgt_errprint("signal SIGTERM failed: %s\n", strerror(errno));
		clumgt_exit(1);
		/*NOTREACHED*/
	}


	clumgt_print(CHATTY_MID, "%spausing\n", fcn);
	for (;;) {
		(void) pause();
	}
}


/*
 * detach from tty.  For daemon mode.
 */
void
detachfromtty()
{
	(void) setsid();
	if (CLUMGT_DEBUG_ON == TRUE) {
		return;
	}

	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) open("/dev/null", O_RDWR, 0);
	(void) dup(0);
	(void) dup(0);
	openlog(CLUMGTD, LOG_PID, LOG_DAEMON);
	(void) setlogmask(LOG_UPTO(LOG_INFO));
	l_logflag = TRUE;
}


/*
 * Prints only if level matches one of the debug levels
 * given on command line.  INFO_MID is always printed.
 *
 * See clumgt.h for a listing of globally defined levels and
 * meanings.  Modules should prefix the level with their
 * module name to prevent collisions.
 */
/*PRINTFLIKE2*/
void
clumgt_print(char *msgid, char *message, ...)
{
	va_list ap;
	static int newline = TRUE;
	int x;

	if (msgid != NULL) {
		for (x = 0; x < l_num_verbose; x++) {
			if (strcmp(l_verbose[x], msgid) == 0) {
				break;
			}
			if (strcmp(l_verbose[x], ALL_MID) == 0) {
				break;
			}
		}
		if (x == l_num_verbose) {
			return;
		}
	}

	va_start(ap, message);

	if (msgid == NULL) {
		if (l_logflag == TRUE) {
			(void) vsyslog(LOG_NOTICE, message, ap);
		} else {
			(void) vfprintf(stdout, message, ap);
		}

	} else {
		if (l_logflag == TRUE) {
			(void) syslog(LOG_DEBUG, "%s[%ld]: %s: ",
			    l_prog, getpid(), msgid);
			(void) vsyslog(LOG_DEBUG, message, ap);
		} else {
			if (newline == TRUE) {
				(void) fprintf(stdout, "%s[%ld]: %s: ",
				    l_prog, getpid(), msgid);
			}
			(void) vfprintf(stdout, message, ap);
		}
	}

	if (message[strlen(message) - 1] == '\n') {
		newline = TRUE;
	} else {
		newline = FALSE;
	}
	va_end(ap);
}


/*
 * print error messages to the terminal or to syslog
 */
/*PRINTFLIKE1*/
void
clumgt_errprint(char *message, ...)
{
	va_list ap;

	va_start(ap, message);

	if (l_logflag == TRUE) {
		(void) vsyslog(LOG_ERR, message, ap);
	} else {
		(void) fprintf(stderr, "%s: ", l_prog);
		(void) vfprintf(stderr, message, ap);
	}
	va_end(ap);
}


/*
 *
 * Use an advisory lock to ensure that only one daemon process is active
 * in the system at any point in time.	If the lock is held by another
 * process, do not block but return the pid owner of the lock to the
 * caller immediately.	The lock is cleared if the holding daemon process
 * exits for any reason even if the lock file remains, so the daemon can
 * be restarted if necessary.  The lock file is DAEMON_LOCK_FILE.
 */
pid_t
enter_daemon_lock(void)
{
	struct flock lock;

	(void) snprintf(l_daemon_lockfile, sizeof (l_daemon_lockfile),
	    "%s/%s", l_var_run_dir, DAEMON_LOCK_FILE);

	clumgt_print(LOCK_MID, "enter_daemon_lock: lock file %s\n", l_daemon_lockfile);

	l_daemon_lock_fd = open(l_daemon_lockfile, O_CREAT|O_RDWR, 0644);
	if (l_daemon_lock_fd < 0) {
		clumgt_errprint(OPEN_FAILED, l_daemon_lockfile, strerror(errno));
		clumgt_exit(1);
		/*NOTREACHED*/
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(l_daemon_lock_fd, F_SETLK, &lock) == -1) {

		if (errno == EAGAIN || errno == EDEADLK) {
			if (fcntl(l_daemon_lock_fd, F_GETLK, &lock) == -1) {
				clumgt_errprint(LOCK_FAILED, l_daemon_lockfile,
				    strerror(errno));
				clumgt_exit(1);
				/*NOTREACHED*/
			}
			return (lock.l_pid);
		}
	}
	l_hold_daemon_lock = TRUE;
	return (getpid());
}


/*
 * Drop the advisory daemon lock, close lock file
 */
void
exit_daemon_lock(int exiting)
{
	struct flock lock;

	if (l_hold_daemon_lock == FALSE) {
		return;
	}

	clumgt_print(LOCK_MID, "exit_daemon_lock: lock file %s, exiting = %d\n",
	    l_daemon_lockfile, exiting);

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(l_daemon_lock_fd, F_SETLK, &lock) == -1) {
		clumgt_errprint(UNLOCK_FAILED, l_daemon_lockfile, strerror(errno));
	}

	if (close(l_daemon_lock_fd) == -1) {
		clumgt_errprint(CLOSE_FAILED, l_daemon_lockfile, strerror(errno));
		if (!exiting)
			clumgt_exit(1);
			/*NOTREACHED*/
	}
}


/* common exit function which ensures releasing locks */
static void
clumgt_exit(int status)
{
	if (CLUMGT_DEBUG_ON) {
		clumgt_print(INFO_MID, "exit status = %d\n", status);
	}

	exit_daemon_lock(1);

	if (l_logflag == TRUE) {
		closelog();
	}

	exit(status);
	/*NOTREACHED*/
}

int get_local_hostname(char *buf, int reserved)
{
        int i=0;
        FILE *fp;
        fp = fopen("/etc/cluster_hostname", "r");
        if (fp == NULL) {
                return (-1);
        }
        fgets(buf, HOSTNAMELEN, fp);
        fclose(fp);
        for (i=0; i<HOSTNAMELEN; i++) {
                if (*(buf+i) == ' ' || *(buf+i) == '\n') {
                        break;
                }
        }
        if (i == HOSTNAMELEN)
                i = HOSTNAMELEN -1;
        *(buf+i) = 0;
        return 0;
}


int
clumgt_get_hosturl(char *url)
{
	char	hostname[HOSTNAMELEN];
	clumgt_host_t c_host[MAXWORKERS];
	int	host_num = 0;
	int found = 0;
	int i = 0;

	memset(url, 0, HOSTURLLEN);
	memset(hostname, 0, HOSTURLLEN);

	if (clumgt_get_hostnode(c_host, &host_num, NULL) != 0) {
		fprintf(stderr, "[libclumgt] get host node failed, "
			"please check config.\n");
		return (-1);
	}

	if (get_local_hostname(hostname, HOSTNAMELEN) < 0) {
			clumgt_errprint("get host name failed.\n");
			return (-1);
	}

	for(i = 0; i < host_num; i++){
		if(!strcmp(hostname, c_host[i].hostname)) {
			strcpy(url, c_host[i].hosturl);
			found = 1;
			break;
		}
	}

	if (found == 0) {
		clumgt_errprint("Cannot get local ip.\n");
		return (-1);
	}

	clumgt_print(VERBOSE_MID, "bind url: %s\n", url);
	
	return (0);
}

void *clumgt_worker (void *arg)
{
	int sockfd = (intptr_t)arg; 

	/*  Main processing loop. */

	for (;;) {

		int rc;
		uint8_t *req = NULL;
		clumgt_response_t *resp = NULL;
		void *control;
		struct nn_iovec iov;
		struct nn_msghdr hdr;
		char hostname[HOSTNAMELEN];

		memset (&hdr, 0, sizeof (hdr));
		control = NULL;
		iov.iov_base = &req;
		iov.iov_len = NN_MSG;
		hdr.msg_iov = &iov;
		hdr.msg_iovlen = 1;
		hdr.msg_control = &control;
		hdr.msg_controllen = NN_MSG;

		if (get_local_hostname(hostname, sizeof(hostname)) < 0) {
			clumgt_errprint("get hostname failed\n");
			continue;
		}
		
		rc = nn_recvmsg(sockfd, &hdr, 0);
		if (rc < 0) {
			if (nn_errno() == EBADF) {
				/* Socket closed by another thread. */
				return (NULL);
			}
			/*  Any error here is unexpected. */
			clumgt_errprint("nn_recv: %s\n", nn_strerror(nn_errno ()));
			break;
		}

		if (rc < 1) {
			clumgt_errprint("nn_recv: wanted %d, but got %d\n",
				1, rc);
			nn_freemsg(req);
			nn_freemsg(control);
			continue;
		}
		if(clumgt_parse_revcdata(req, &resp) < 0) {
			hdr.msg_iov = NULL;
			hdr.msg_iovlen = 0;
		} else {
			iov.iov_base = &resp;
			iov.iov_len = NN_MSG;
			hdr.msg_iovlen = 1;
		}
		nn_freemsg (req);
		
		rc = nn_sendmsg(sockfd, &hdr, 0);
		if (rc < 0) {
			clumgt_errprint("nn_send: %s\n", strerror(nn_errno()));
			nn_freemsg(control);
			nn_freemsg(resp);
		}
	}

	/*  We got here, so close the file.  That will cause the other threads
	    to shut down too. */

	nn_close(sockfd);
	return (NULL);
}


/*  The server runs forever. */
int clumgt_server()
{
	int			sockid;
	int 		i;
	pthread_t	m_tid;
	pthread_t 	s_tid;
	pthread_t	tids[MAXWORKERS];
	char		url[HOSTURLLEN];
	int			rc;

	if (clumgt_get_hosturl(url) < 0) {
		return (-1);
	}

	/*  Create the socket. */
	sockid = nn_socket(AF_SP_RAW, NN_REP);
	if (sockid < 0) {
		clumgt_errprint("nn_socket: %s\n", nn_strerror (nn_errno ()));
		return (-1);
	}

	/*  Bind to the URL.  This will bind to the address and listen
	    synchronously; new clients will be accepted asynchronously
	    without further action from the calling program. */

	if (nn_bind (sockid, url) < 0) {
		clumgt_errprint("nn_bind: %s\n", nn_strerror (nn_errno ()));
		nn_close (sockid);
		return (-1);
	}

	memset (tids, 0, sizeof (tids));

	/*  Start up the threads. */
	for (i = 0; i < MAXWORKERS; i++) {
		rc = pthread_create(&tids[i], NULL, clumgt_worker, (void *)(intptr_t)sockid);
		if (rc < 0) {
			clumgt_errprint(CANT_CREATE_THREAD, "daemon",
				strerror(errno));
			nn_close(sockid);
			break;
		}
	}

	(void)pthread_create(&m_tid, NULL, sync_send_msg_to_agent, NULL);

	/* create a pthread for choose cluster master */
	//(void)pthread_create(&s_tid, NULL, sync_choose_master, NULL);
	
	/*  Now wait on them to finish. */
	for (i = 0; i < MAXWORKERS; i++) {
		if (tids[i] != 0) {
			pthread_join(tids[i], NULL);
		}
	}
	
	if(m_tid != 0)
		pthread_join(m_tid, NULL);

	if (0 != s_tid)
		pthread_join(s_tid, NULL);
		
	return (-1);
}



