#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <libgen.h>
#include "fmd_systemd.h"

#define	PID_FILE	RUNSTATEDIR "/fmd.pid"

static void
_die(const char *fmt, ...)
{
	va_list vargs;

	if (fmt) {
		va_start(vargs, fmt);
		vsyslog(LOG_ERR, fmt, vargs);
		va_end(vargs);
	}
	exit(EXIT_FAILURE);
}

static struct {
	int pipe_fd[2];
	int pid_fd;
} _ctx;

static void
pipe_open(void)
{
	if (pipe(_ctx.pipe_fd) < 0)
		_die("Failed to create daemonize pipe in PID %d: %s",
		    (int) getpid(), strerror(errno));
}

static void
pipe_close_reads(void)
{
	if (close(_ctx.pipe_fd[0]) < 0)
		_die("Failed to close reads on daemonize pipe in PID %d: %s",
			(int) getpid(), strerror(errno));
}

static void
pipe_close_writes(void)
{
	if (close(_ctx.pipe_fd[1]) < 0)
		_die("Failed to close writes on daemonize pipe in PID %d: %s",
		    (int) getpid(), strerror(errno));
}

static void
pipe_wait(void)
{
	ssize_t n;
	char c;

	for (;;) {
		n = read(_ctx.pipe_fd[0], &c, sizeof (c));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			_die("Failed to read from daemonize pipe in PID %d: %s",
				(int) getpid(), strerror(errno));
		}
		if (n == 0) {
			break;
		}
	}
}

static void
_start_daemonize(void)
{
	pid_t pid;
	struct sigaction sa;

	/* Create pipe for communicating with child during daemonization. */
	pipe_open();

	/* Background process and ensure child is not process group leader. */
	pid = fork();
	if (pid < 0) {
		syslog(LOG_ERR, "Failed to create child process: %s",
		    strerror(errno));
	} else if (pid > 0) {

		/* Close writes since parent will only read from pipe. */
		pipe_close_writes();

		/* Wait for notification that daemonization is complete. */
		pipe_wait();

		pipe_close_reads();
		_exit(EXIT_SUCCESS);
	}

	/* Close reads since child will only write to pipe. */
	pipe_close_reads();

	/* Create independent session and detach from terminal. */
	if (setsid() < 0)
		syslog(LOG_ERR, "Failed to create new session: %s",
		    strerror(errno));

	/* Prevent child from terminating on HUP when session leader exits. */
	if (sigemptyset(&sa.sa_mask) < 0)
		_die("Failed to initialize sigset");

	sa.sa_flags = 0;
	sa.sa_handler = SIG_IGN;

	if (sigaction(SIGHUP, &sa, NULL) < 0)
		_die("Failed to ignore SIGHUP");

	/* Ensure process cannot re-acquire terminal. */
	pid = fork();
	if (pid < 0) {
		_die("Failed to create grandchild process: %s",
		    strerror(errno));
	} else if (pid > 0) {
		_exit(EXIT_SUCCESS);
	}
}

static void
_finish_daemonize(void)
{
	int devnull;

	/* Preserve fd 0/1/2, but discard data to/from stdin/stdout/stderr. */
	devnull = open("/dev/null", O_RDWR);
	if (devnull < 0)
		_die("Failed to open /dev/null: %s", strerror(errno));

	if (dup2(devnull, STDIN_FILENO) < 0)
		_die("Failed to dup /dev/null onto stdin: %s",
		    strerror(errno));

	if (dup2(devnull, STDOUT_FILENO) < 0)
		_die("Failed to dup /dev/null onto stdout: %s",
		    strerror(errno));

	if (dup2(devnull, STDERR_FILENO) < 0)
		_die("Failed to dup /dev/null onto stderr: %s",
		    strerror(errno));

	if (close(devnull) < 0)
		_die("Failed to close /dev/null: %s", strerror(errno));

	/* Notify parent that daemonization is complete. */
	pipe_close_writes();
}

static int
_file_lock(int fd)
{
	struct flock lock;

	if (fd < 0) {
		errno = EBADF;
		return (-1);
	}
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(fd, F_SETLK, &lock) < 0) {
		if ((errno == EACCES) || (errno == EAGAIN))
			return (1);

		return (-1);
	}
	return (0);
}

static pid_t
_file_is_locked(int fd)
{
	struct flock lock;

	if (fd < 0) {
		errno = EBADF;
		return (-1);
	}
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(fd, F_GETLK, &lock) < 0)
		return (-1);

	if (lock.l_type == F_UNLCK)
		return (0);

	return (lock.l_pid);
}

static ssize_t
_file_write_n(int fd, void *buf, size_t n)
{
	const unsigned char *p;
	size_t n_left;
	ssize_t n_written;

	p = buf;
	n_left = n;
	while (n_left > 0) {
		if ((n_written = write(fd, p, n_left)) < 0) {
			if (errno == EINTR)
				continue;
			else
				return (-1);

		}
		n_left -= n_written;
		p += n_written;
	}
	return (n);
}

static int
_write_pid(void)
{
	const mode_t dirmode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	const mode_t filemode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	char buf[PATH_MAX];
	int n;
	char *p;
	mode_t mask;
	int rv;

	/*
	 * Create PID file directory if needed.
	 */
	n = strlcpy(buf, PID_FILE, sizeof (buf));
	if (n >= sizeof (buf)) {
		errno = ENAMETOOLONG;
		syslog(LOG_ERR, "Failed to create PID file: %s",
		    strerror(errno));
		goto err;
	}
	p = strrchr(buf, '/');
	if (p)
		*p = '\0';

	if ((mkdirp(buf, dirmode) < 0) && (errno != EEXIST)) {
		syslog(LOG_ERR, "Failed to create directory \"%s\": %s",
		    buf, strerror(errno));
		goto err;
	}
	/*
	 * Obtain PID file lock.
	 */
	mask = umask(0);
	umask(mask | 022);
	_ctx.pid_fd = open(PID_FILE, (O_RDWR | O_CREAT), filemode);
	umask(mask);
	if (_ctx.pid_fd < 0) {
		syslog(LOG_ERR, "Failed to open PID file \"%s\": %s",
		    PID_FILE, strerror(errno));
		goto err;
	}
	rv = _file_lock(_ctx.pid_fd);
	if (rv < 0) {
		syslog(LOG_ERR, "Failed to lock PID file \"%s\": %s",
		    PID_FILE, strerror(errno));
		goto err;
	} else if (rv > 0) {
		pid_t pid = _file_is_locked(_ctx.pid_fd);
		if (pid < 0) {
			syslog(LOG_ERR,
			    "Failed to test lock on PID file \"%s\"",
			    PID_FILE);
		} else if (pid > 0) {
			syslog(LOG_ERR,
			    "Found PID %d bound to PID file \"%s\"",
			    pid, PID_FILE);
		} else {
			syslog(LOG_ERR,
			    "Inconsistent lock state on PID file \"%s\"",
			    PID_FILE);
		}
		goto err;
	}
	/*
	 * Write PID file.
	 */
	n = snprintf(buf, sizeof (buf), "%d\n", (int) getpid());
	if ((n < 0) || (n >= sizeof (buf))) {
		errno = ERANGE;
		syslog(LOG_ERR, "Failed to write PID file \"%s\": %s",
		    PID_FILE, strerror(errno));
	} else if (_file_write_n(_ctx.pid_fd, buf, n) != n) {
		syslog(LOG_ERR, "Failed to write PID file \"%s\": %s",
		    PID_FILE, strerror(errno));
	} else if (fdatasync(_ctx.pid_fd) < 0) {
		syslog(LOG_ERR, "Failed to sync PID file \"%s\": %s",
		    PID_FILE, strerror(errno));
	} else {
		return (0);
	}

err:
	if (_ctx.pid_fd >= 0) {
		(void) close(_ctx.pid_fd);
		_ctx.pid_fd = -1;
	}
	return (-1);
}

void
systemd_daemonize(void)
{
	(void) umask(0);

	if (chdir("/") < 0)
		_die("Failed to change to root directory");

	_start_daemonize();

	if (_write_pid() < 0)
		exit(EXIT_FAILURE);

	_finish_daemonize();
}

void
write_pid(void)
{
	if (_write_pid() < 0)
		exit(EXIT_FAILURE);
}