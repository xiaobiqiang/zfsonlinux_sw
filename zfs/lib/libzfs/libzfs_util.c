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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*
 * Internal utility routines for the ZFS library.
 */

#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/types.h>
#include <wait.h>
#include <syslog.h>
#include <sys/vdev_impl.h>
#include <sys/thread_pool.h>
#include <libzfs.h>
#include <libzfs_core.h>
#include <libstmf.h>

#include "libzfs_impl.h"
#include "zfs_prop.h"
#include "zfeature_common.h"

#define	ZFS_ILU_MAX_NTHREAD		64
#define NETCONFIG_FILE			"/dev/tcp"
#define	IFCONFIG_CMD			"/usr/sbin/ifconfig"

typedef struct zfs_ilu_list{
	struct zfs_ilu_list *next;
	struct zfs_ilu_list *prev;
	char *lu_name;
	pthread_t tid;
	boolean_t run_thread;
} zfs_ilu_list_t;

typedef struct zfs_ilu_ctx {
	char *pool_name;
	tpool_t *zic_tp;
	zfs_ilu_list_t *head;
	zfs_ilu_list_t *tail;
	int lun_cnt;
} zfs_ilu_ctx_t;

typedef struct zfs_standby_ilu_list{
	struct zfs_standby_ilu_list *next;
	char *lu_name;
	stmfGuid lu_guid;
} zfs_standby_ilu_list_t;

typedef struct zfs_standby_ilu_ctx {
	char *pool_name;
	zfs_standby_ilu_list_t *head;
	zfs_standby_ilu_list_t *tail;
	int lun_cnt;
} zfs_standby_ilu_ctx_t;

typedef struct zfs_avs_ctx {
	char *pool_name;
	uint64_t dev_no;
	int enabled;
} zfs_avs_ctx_t;

int
libzfs_errno(libzfs_handle_t *hdl)
{
	return (hdl->libzfs_error);
}

const char *
libzfs_error_init(int error)
{
	switch (error) {
	case ENXIO:
		return (dgettext(TEXT_DOMAIN, "The ZFS modules are not "
		    "loaded.\nTry running '/sbin/modprobe zfs' as root "
		    "to load them.\n"));
	case ENOENT:
		return (dgettext(TEXT_DOMAIN, "The /dev/zfs device is "
		    "missing and must be created.\nTry running 'udevadm "
		    "trigger' as root to create it.\n"));
	case ENOEXEC:
		return (dgettext(TEXT_DOMAIN, "The ZFS modules cannot be "
		    "auto-loaded.\nTry running '/sbin/modprobe zfs' as "
		    "root to manually load them.\n"));
	case EACCES:
		return (dgettext(TEXT_DOMAIN, "Permission denied the "
		    "ZFS utilities must be run as root.\n"));
	default:
		return (dgettext(TEXT_DOMAIN, "Failed to initialize the "
		    "libzfs library.\n"));
	}
}

const char *
libzfs_error_action(libzfs_handle_t *hdl)
{
	return (hdl->libzfs_action);
}

const char *
libzfs_error_description(libzfs_handle_t *hdl)
{
	if (hdl->libzfs_desc[0] != '\0')
		return (hdl->libzfs_desc);

	switch (hdl->libzfs_error) {
	case EZFS_NOMEM:
		return (dgettext(TEXT_DOMAIN, "out of memory"));
	case EZFS_BADPROP:
		return (dgettext(TEXT_DOMAIN, "invalid property value"));
	case EZFS_PROPREADONLY:
		return (dgettext(TEXT_DOMAIN, "read-only property"));
	case EZFS_PROPTYPE:
		return (dgettext(TEXT_DOMAIN, "property doesn't apply to "
		    "datasets of this type"));
	case EZFS_PROPNONINHERIT:
		return (dgettext(TEXT_DOMAIN, "property cannot be inherited"));
	case EZFS_PROPSPACE:
		return (dgettext(TEXT_DOMAIN, "invalid quota or reservation"));
	case EZFS_BADTYPE:
		return (dgettext(TEXT_DOMAIN, "operation not applicable to "
		    "datasets of this type"));
	case EZFS_BUSY:
		return (dgettext(TEXT_DOMAIN, "pool or dataset is busy"));
	case EZFS_EXISTS:
		return (dgettext(TEXT_DOMAIN, "pool or dataset exists"));
	case EZFS_NOENT:
		return (dgettext(TEXT_DOMAIN, "no such pool or dataset"));
	case EZFS_BADSTREAM:
		return (dgettext(TEXT_DOMAIN, "invalid backup stream"));
	case EZFS_DSREADONLY:
		return (dgettext(TEXT_DOMAIN, "dataset is read-only"));
	case EZFS_VOLTOOBIG:
		return (dgettext(TEXT_DOMAIN, "volume size exceeds limit for "
		    "this system"));
	case EZFS_INVALIDNAME:
		return (dgettext(TEXT_DOMAIN, "invalid name"));
	case EZFS_BADRESTORE:
		return (dgettext(TEXT_DOMAIN, "unable to restore to "
		    "destination"));
	case EZFS_BADBACKUP:
		return (dgettext(TEXT_DOMAIN, "backup failed"));
	case EZFS_BADTARGET:
		return (dgettext(TEXT_DOMAIN, "invalid target vdev"));
	case EZFS_NODEVICE:
		return (dgettext(TEXT_DOMAIN, "no such device in pool"));
	case EZFS_BADDEV:
		return (dgettext(TEXT_DOMAIN, "invalid device"));
	case EZFS_NOREPLICAS:
		return (dgettext(TEXT_DOMAIN, "no valid replicas"));
	case EZFS_RESILVERING:
		return (dgettext(TEXT_DOMAIN, "currently resilvering"));
	case EZFS_BADVERSION:
		return (dgettext(TEXT_DOMAIN, "unsupported version or "
		    "feature"));
	case EZFS_POOLUNAVAIL:
		return (dgettext(TEXT_DOMAIN, "pool is unavailable"));
	case EZFS_DEVOVERFLOW:
		return (dgettext(TEXT_DOMAIN, "too many devices in one vdev"));
	case EZFS_BADPATH:
		return (dgettext(TEXT_DOMAIN, "must be an absolute path"));
	case EZFS_CROSSTARGET:
		return (dgettext(TEXT_DOMAIN, "operation crosses datasets or "
		    "pools"));
	case EZFS_ZONED:
		return (dgettext(TEXT_DOMAIN, "dataset in use by local zone"));
	case EZFS_MOUNTFAILED:
		return (dgettext(TEXT_DOMAIN, "mount failed"));
	case EZFS_UMOUNTFAILED:
		return (dgettext(TEXT_DOMAIN, "umount failed"));
	case EZFS_UNSHARENFSFAILED:
		return (dgettext(TEXT_DOMAIN, "unshare(1M) failed"));
	case EZFS_SHARENFSFAILED:
		return (dgettext(TEXT_DOMAIN, "share(1M) failed"));
	case EZFS_UNSHARESMBFAILED:
		return (dgettext(TEXT_DOMAIN, "smb remove share failed"));
	case EZFS_SHARESMBFAILED:
		return (dgettext(TEXT_DOMAIN, "smb add share failed"));
	case EZFS_PERM:
		return (dgettext(TEXT_DOMAIN, "permission denied"));
	case EZFS_NOSPC:
		return (dgettext(TEXT_DOMAIN, "out of space"));
	case EZFS_FAULT:
		return (dgettext(TEXT_DOMAIN, "bad address"));
	case EZFS_IO:
		return (dgettext(TEXT_DOMAIN, "I/O error"));
	case EZFS_INTR:
		return (dgettext(TEXT_DOMAIN, "signal received"));
	case EZFS_ISSPARE:
		return (dgettext(TEXT_DOMAIN, "device is reserved as a hot "
		    "spare"));
	case EZFS_INVALCONFIG:
		return (dgettext(TEXT_DOMAIN, "invalid vdev configuration"));
	case EZFS_RECURSIVE:
		return (dgettext(TEXT_DOMAIN, "recursive dataset dependency"));
	case EZFS_NOHISTORY:
		return (dgettext(TEXT_DOMAIN, "no history available"));
	case EZFS_POOLPROPS:
		return (dgettext(TEXT_DOMAIN, "failed to retrieve "
		    "pool properties"));
	case EZFS_POOL_NOTSUP:
		return (dgettext(TEXT_DOMAIN, "operation not supported "
		    "on this type of pool"));
	case EZFS_POOL_INVALARG:
		return (dgettext(TEXT_DOMAIN, "invalid argument for "
		    "this pool operation"));
	case EZFS_NAMETOOLONG:
		return (dgettext(TEXT_DOMAIN, "dataset name is too long"));
	case EZFS_OPENFAILED:
		return (dgettext(TEXT_DOMAIN, "open failed"));
	case EZFS_NOCAP:
		return (dgettext(TEXT_DOMAIN,
		    "disk capacity information could not be retrieved"));
	case EZFS_LABELFAILED:
		return (dgettext(TEXT_DOMAIN, "write of label failed"));
	case EZFS_BADWHO:
		return (dgettext(TEXT_DOMAIN, "invalid user/group"));
	case EZFS_BADPERM:
		return (dgettext(TEXT_DOMAIN, "invalid permission"));
	case EZFS_BADPERMSET:
		return (dgettext(TEXT_DOMAIN, "invalid permission set name"));
	case EZFS_NODELEGATION:
		return (dgettext(TEXT_DOMAIN, "delegated administration is "
		    "disabled on pool"));
	case EZFS_BADCACHE:
		return (dgettext(TEXT_DOMAIN, "invalid or missing cache file"));
	case EZFS_ISL2CACHE:
		return (dgettext(TEXT_DOMAIN, "device is in use as a cache"));
	case EZFS_VDEVNOTSUP:
		return (dgettext(TEXT_DOMAIN, "vdev specification is not "
		    "supported"));
	case EZFS_NOTSUP:
		return (dgettext(TEXT_DOMAIN, "operation not supported "
		    "on this dataset"));
	case EZFS_ACTIVE_SPARE:
		return (dgettext(TEXT_DOMAIN, "pool has active shared spare "
		    "device"));
	case EZFS_UNPLAYED_LOGS:
		return (dgettext(TEXT_DOMAIN, "log device has unplayed intent "
		    "logs"));
	case EZFS_REFTAG_RELE:
		return (dgettext(TEXT_DOMAIN, "no such tag on this dataset"));
	case EZFS_REFTAG_HOLD:
		return (dgettext(TEXT_DOMAIN, "tag already exists on this "
		    "dataset"));
	case EZFS_TAGTOOLONG:
		return (dgettext(TEXT_DOMAIN, "tag too long"));
	case EZFS_PIPEFAILED:
		return (dgettext(TEXT_DOMAIN, "pipe create failed"));
	case EZFS_THREADCREATEFAILED:
		return (dgettext(TEXT_DOMAIN, "thread create failed"));
	case EZFS_POSTSPLIT_ONLINE:
		return (dgettext(TEXT_DOMAIN, "disk was split from this pool "
		    "into a new one"));
	case EZFS_SCRUBBING:
		return (dgettext(TEXT_DOMAIN, "currently scrubbing; "
		    "use 'zpool scrub -s' to cancel current scrub"));
	case EZFS_NO_SCRUB:
		return (dgettext(TEXT_DOMAIN, "there is no active scrub"));
	case EZFS_DIFF:
		return (dgettext(TEXT_DOMAIN, "unable to generate diffs"));
	case EZFS_DIFFDATA:
		return (dgettext(TEXT_DOMAIN, "invalid diff data"));
	case EZFS_POOLREADONLY:
		return (dgettext(TEXT_DOMAIN, "pool is read-only"));
	case EZFS_UNKNOWN:
		return (dgettext(TEXT_DOMAIN, "unknown error"));
	default:
		assert(hdl->libzfs_error == 0);
		return (dgettext(TEXT_DOMAIN, "no error"));
	}
}

/*PRINTFLIKE2*/
void
zfs_error_aux(libzfs_handle_t *hdl, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	(void) vsnprintf(hdl->libzfs_desc, sizeof (hdl->libzfs_desc),
	    fmt, ap);
	hdl->libzfs_desc_active = 1;

	va_end(ap);
}

static void
zfs_verror(libzfs_handle_t *hdl, int error, const char *fmt, va_list ap)
{
	(void) vsnprintf(hdl->libzfs_action, sizeof (hdl->libzfs_action),
	    fmt, ap);
	hdl->libzfs_error = error;

	if (hdl->libzfs_desc_active)
		hdl->libzfs_desc_active = 0;
	else
		hdl->libzfs_desc[0] = '\0';

	if (hdl->libzfs_printerr) {
		if (error == EZFS_UNKNOWN) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN, "internal "
			    "error: %s\n"), libzfs_error_description(hdl));
			abort();
		}

		(void) fprintf(stderr, "%s: %s\n", hdl->libzfs_action,
		    libzfs_error_description(hdl));
		if (error == EZFS_NOMEM)
			exit(1);
	}
}

int
zfs_error(libzfs_handle_t *hdl, int error, const char *msg)
{
	return (zfs_error_fmt(hdl, error, "%s", msg));
}

/*PRINTFLIKE3*/
int
zfs_error_fmt(libzfs_handle_t *hdl, int error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	zfs_verror(hdl, error, fmt, ap);

	va_end(ap);

	return (-1);
}

static int
zfs_common_error(libzfs_handle_t *hdl, int error, const char *fmt,
    va_list ap)
{
	switch (error) {
	case EPERM:
	case EACCES:
		zfs_verror(hdl, EZFS_PERM, fmt, ap);
		return (-1);

	case ECANCELED:
		zfs_verror(hdl, EZFS_NODELEGATION, fmt, ap);
		return (-1);

	case EIO:
		zfs_verror(hdl, EZFS_IO, fmt, ap);
		return (-1);

	case EFAULT:
		zfs_verror(hdl, EZFS_FAULT, fmt, ap);
		return (-1);

	case EINTR:
		zfs_verror(hdl, EZFS_INTR, fmt, ap);
		return (-1);
	}

	return (0);
}

int
zfs_standard_error(libzfs_handle_t *hdl, int error, const char *msg)
{
	return (zfs_standard_error_fmt(hdl, error, "%s", msg));
}

/*PRINTFLIKE3*/
int
zfs_standard_error_fmt(libzfs_handle_t *hdl, int error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (zfs_common_error(hdl, error, fmt, ap) != 0) {
		va_end(ap);
		return (-1);
	}

	switch (error) {
	case ENXIO:
	case ENODEV:
	case EPIPE:
		zfs_verror(hdl, EZFS_IO, fmt, ap);
		break;

	case ENOENT:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "dataset does not exist"));
		zfs_verror(hdl, EZFS_NOENT, fmt, ap);
		break;

	case ENOSPC:
	case EDQUOT:
		zfs_verror(hdl, EZFS_NOSPC, fmt, ap);
		return (-1);

	case EEXIST:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "dataset already exists"));
		zfs_verror(hdl, EZFS_EXISTS, fmt, ap);
		break;

	case EBUSY:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "dataset is busy"));
		zfs_verror(hdl, EZFS_BUSY, fmt, ap);
		break;
	case EROFS:
		zfs_verror(hdl, EZFS_POOLREADONLY, fmt, ap);
		break;
	case ENAMETOOLONG:
		zfs_verror(hdl, EZFS_NAMETOOLONG, fmt, ap);
		break;
	case ENOTSUP:
		zfs_verror(hdl, EZFS_BADVERSION, fmt, ap);
		break;
	case EAGAIN:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "pool I/O is currently suspended"));
		zfs_verror(hdl, EZFS_POOLUNAVAIL, fmt, ap);
		break;
	default:
		zfs_error_aux(hdl, strerror(error));
		zfs_verror(hdl, EZFS_UNKNOWN, fmt, ap);
		break;
	}

	va_end(ap);
	return (-1);
}

int
zpool_standard_error(libzfs_handle_t *hdl, int error, const char *msg)
{
	return (zpool_standard_error_fmt(hdl, error, "%s", msg));
}

/*PRINTFLIKE3*/
int
zpool_standard_error_fmt(libzfs_handle_t *hdl, int error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (zfs_common_error(hdl, error, fmt, ap) != 0) {
		va_end(ap);
		return (-1);
	}

	switch (error) {
	case ENODEV:
		zfs_verror(hdl, EZFS_NODEVICE, fmt, ap);
		break;

	case ENOENT:
		zfs_error_aux(hdl,
		    dgettext(TEXT_DOMAIN, "no such pool or dataset"));
		zfs_verror(hdl, EZFS_NOENT, fmt, ap);
		break;

	case EEXIST:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "pool already exists"));
		zfs_verror(hdl, EZFS_EXISTS, fmt, ap);
		break;

	case EBUSY:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "pool is busy"));
		zfs_verror(hdl, EZFS_BUSY, fmt, ap);
		break;

	case ENXIO:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "one or more devices is currently unavailable"));
		zfs_verror(hdl, EZFS_BADDEV, fmt, ap);
		break;

	case ENAMETOOLONG:
		zfs_verror(hdl, EZFS_DEVOVERFLOW, fmt, ap);
		break;

	case ENOTSUP:
		zfs_verror(hdl, EZFS_POOL_NOTSUP, fmt, ap);
		break;

	case EINVAL:
		zfs_verror(hdl, EZFS_POOL_INVALARG, fmt, ap);
		break;

	case ENOSPC:
	case EDQUOT:
		zfs_verror(hdl, EZFS_NOSPC, fmt, ap);
		return (-1);

	case EAGAIN:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "pool I/O is currently suspended"));
		zfs_verror(hdl, EZFS_POOLUNAVAIL, fmt, ap);
		break;

	case EROFS:
		zfs_verror(hdl, EZFS_POOLREADONLY, fmt, ap);
		break;

	default:
		zfs_error_aux(hdl, strerror(error));
		zfs_verror(hdl, EZFS_UNKNOWN, fmt, ap);
	}

	va_end(ap);
	return (-1);
}

/*
 * Display an out of memory error message and abort the current program.
 */
int
no_memory(libzfs_handle_t *hdl)
{
	return (zfs_error(hdl, EZFS_NOMEM, "internal error"));
}

/*
 * A safe form of malloc() which will die if the allocation fails.
 */
void *
zfs_alloc(libzfs_handle_t *hdl, size_t size)
{
	void *data;

	if ((data = calloc(1, size)) == NULL)
		(void) no_memory(hdl);

	return (data);
}

/*
 * A safe form of asprintf() which will die if the allocation fails.
 */
/*PRINTFLIKE2*/
char *
zfs_asprintf(libzfs_handle_t *hdl, const char *fmt, ...)
{
	va_list ap;
	char *ret;
	int err;

	va_start(ap, fmt);

	err = vasprintf(&ret, fmt, ap);

	va_end(ap);

	if (err < 0)
		(void) no_memory(hdl);

	return (ret);
}

/*
 * A safe form of realloc(), which also zeroes newly allocated space.
 */
void *
zfs_realloc(libzfs_handle_t *hdl, void *ptr, size_t oldsize, size_t newsize)
{
	void *ret;

	if ((ret = realloc(ptr, newsize)) == NULL) {
		(void) no_memory(hdl);
		return (NULL);
	}

	bzero((char *)ret + oldsize, (newsize - oldsize));
	return (ret);
}

/*
 * A safe form of strdup() which will die if the allocation fails.
 */
char *
zfs_strdup(libzfs_handle_t *hdl, const char *str)
{
	char *ret;

	if ((ret = strdup(str)) == NULL)
		(void) no_memory(hdl);

	return (ret);
}

/*
 * Convert a number to an appropriately human-readable output.
 */
void
zfs_nicenum(uint64_t num, char *buf, size_t buflen)
{
	uint64_t n = num;
	int index = 0;
	char u;

	while (n >= 1024 && index < 6) {
		n /= 1024;
		index++;
	}

	u = " KMGTPE"[index];

	if (index == 0) {
		(void) snprintf(buf, buflen, "%llu", (u_longlong_t) n);
	} else if ((num & ((1ULL << 10 * index) - 1)) == 0) {
		/*
		 * If this is an even multiple of the base, always display
		 * without any decimal precision.
		 */
		(void) snprintf(buf, buflen, "%llu%c", (u_longlong_t) n, u);
	} else {
		/*
		 * We want to choose a precision that reflects the best choice
		 * for fitting in 5 characters.  This can get rather tricky when
		 * we have numbers that are very close to an order of magnitude.
		 * For example, when displaying 10239 (which is really 9.999K),
		 * we want only a single place of precision for 10.0K.  We could
		 * develop some complex heuristics for this, but it's much
		 * easier just to try each combination in turn.
		 */
		int i;
		for (i = 2; i >= 0; i--) {
			if (snprintf(buf, buflen, "%.*f%c", i,
			    (double)num / (1ULL << 10 * index), u) <= 5)
				break;
		}
	}
}

void
libzfs_print_on_error(libzfs_handle_t *hdl, boolean_t printerr)
{
	hdl->libzfs_printerr = printerr;
}

static int
libzfs_module_loaded(const char *module)
{
	const char path_prefix[] = "/sys/module/";
	char path[256];

	memcpy(path, path_prefix, sizeof (path_prefix) - 1);
	strcpy(path + sizeof (path_prefix) - 1, module);

	return (access(path, F_OK) == 0);
}

int
libzfs_run_process(const char *path, char *argv[], int flags)
{
	pid_t pid;
	int error, devnull_fd;

	pid = vfork();
	if (pid == 0) {
		devnull_fd = open("/dev/null", O_WRONLY);

		if (devnull_fd < 0)
			_exit(-1);

		if (!(flags & STDOUT_VERBOSE))
			(void) dup2(devnull_fd, STDOUT_FILENO);

		if (!(flags & STDERR_VERBOSE))
			(void) dup2(devnull_fd, STDERR_FILENO);

		close(devnull_fd);

		(void) execvp(path, argv);
		_exit(-1);
	} else if (pid > 0) {
		int status;

		while ((error = waitpid(pid, &status, 0)) == -1 &&
			errno == EINTR);
		if (error < 0 || !WIFEXITED(status))
			return (-1);

		return (WEXITSTATUS(status));
	}

	return (-1);
}

/*
 * Verify the required ZFS_DEV device is available and optionally attempt
 * to load the ZFS modules.  Under normal circumstances the modules
 * should already have been loaded by some external mechanism.
 *
 * Environment variables:
 * - ZFS_MODULE_LOADING="YES|yes|ON|on" - Attempt to load modules.
 * - ZFS_MODULE_TIMEOUT="<seconds>"     - Seconds to wait for ZFS_DEV
 */
static int
libzfs_load_module(const char *module)
{
	char *argv[4] = {"/sbin/modprobe", "-q", (char *)module, (char *)0};
	char *load_str, *timeout_str;
	long timeout = 10; /* seconds */
	long busy_timeout = 10; /* milliseconds */
	int load = 0, fd;
	hrtime_t start;

	/* Optionally request module loading */
	if (!libzfs_module_loaded(module)) {
		load_str = getenv("ZFS_MODULE_LOADING");
		if (load_str) {
			if (!strncasecmp(load_str, "YES", strlen("YES")) ||
			    !strncasecmp(load_str, "ON", strlen("ON")))
				load = 1;
			else
				load = 0;
		}

		if (load && libzfs_run_process("/sbin/modprobe", argv, 0))
			return (ENOEXEC);
	}

	/* Module loading is synchronous it must be available */
	if (!libzfs_module_loaded(module))
		return (ENXIO);

	/*
	 * Device creation by udev is asynchronous and waiting may be
	 * required.  Busy wait for 10ms and then fall back to polling every
	 * 10ms for the allowed timeout (default 10s, max 10m).  This is
	 * done to optimize for the common case where the device is
	 * immediately available and to avoid penalizing the possible
	 * case where udev is slow or unable to create the device.
	 */
	timeout_str = getenv("ZFS_MODULE_TIMEOUT");
	if (timeout_str) {
		timeout = strtol(timeout_str, NULL, 0);
		timeout = MAX(MIN(timeout, (10 * 60)), 0); /* 0 <= N <= 600 */
	}

	start = gethrtime();
	do {
		fd = open(ZFS_DEV, O_RDWR);
		if (fd >= 0) {
			(void) close(fd);
			return (0);
		} else if (errno != ENOENT) {
			return (errno);
		} else if (NSEC2MSEC(gethrtime() - start) < busy_timeout) {
			sched_yield();
		} else {
			usleep(10 * MILLISEC);
		}
	} while (NSEC2MSEC(gethrtime() - start) < (timeout * MILLISEC));

	return (ENOENT);
}

libzfs_handle_t *
libzfs_init(void)
{
	libzfs_handle_t *hdl;
	int error;

	error = libzfs_load_module(ZFS_DRIVER);
	if (error) {
		errno = error;
		return (NULL);
	}

	if ((hdl = calloc(1, sizeof (libzfs_handle_t))) == NULL) {
		return (NULL);
	}

	if ((hdl->libzfs_fd = open(ZFS_DEV, O_RDWR)) < 0) {
		free(hdl);
		return (NULL);
	}

#ifdef HAVE_SETMNTENT
	if ((hdl->libzfs_mnttab = setmntent(MNTTAB, "r")) == NULL) {
#else
	if ((hdl->libzfs_mnttab = fopen(MNTTAB, "r")) == NULL) {
#endif
		(void) close(hdl->libzfs_fd);
		free(hdl);
		return (NULL);
	}

	hdl->libzfs_sharetab = fopen("/etc/dfs/sharetab", "r");

	if (libzfs_core_init() != 0) {
		(void) close(hdl->libzfs_fd);
		(void) fclose(hdl->libzfs_mnttab);
		(void) fclose(hdl->libzfs_sharetab);
		free(hdl);
		return (NULL);
	}

	zfs_prop_init();
	zpool_prop_init();
	zpool_feature_init();
	libzfs_mnttab_init(hdl);

	return (hdl);
}

void
libzfs_fini(libzfs_handle_t *hdl)
{
	(void) close(hdl->libzfs_fd);
	if (hdl->libzfs_mnttab)
#ifdef HAVE_SETMNTENT
		(void) endmntent(hdl->libzfs_mnttab);
#else
		(void) fclose(hdl->libzfs_mnttab);
#endif
	if (hdl->libzfs_sharetab)
		(void) fclose(hdl->libzfs_sharetab);
	zfs_uninit_libshare(hdl);
	zpool_free_handles(hdl);
	libzfs_fru_clear(hdl, B_TRUE);
	namespace_clear(hdl);
	libzfs_mnttab_fini(hdl);
	libzfs_core_fini();
	free(hdl);
}

libzfs_handle_t *
zpool_get_handle(zpool_handle_t *zhp)
{
	return (zhp->zpool_hdl);
}

libzfs_handle_t *
zfs_get_handle(zfs_handle_t *zhp)
{
	return (zhp->zfs_hdl);
}

zpool_handle_t *
zfs_get_pool_handle(const zfs_handle_t *zhp)
{
	return (zhp->zpool_hdl);
}

/*
 * Given a name, determine whether or not it's a valid path
 * (starts with '/' or "./").  If so, walk the mnttab trying
 * to match the device number.  If not, treat the path as an
 * fs/vol/snap name.
 */
zfs_handle_t *
zfs_path_to_zhandle(libzfs_handle_t *hdl, char *path, zfs_type_t argtype)
{
	struct stat64 statbuf;
	struct extmnttab entry;
	int ret;

	if (path[0] != '/' && strncmp(path, "./", strlen("./")) != 0) {
		/*
		 * It's not a valid path, assume it's a name of type 'argtype'.
		 */
		return (zfs_open(hdl, path, argtype));
	}

	if (stat64(path, &statbuf) != 0) {
		(void) fprintf(stderr, "%s: %s\n", path, strerror(errno));
		return (NULL);
	}

	/* Reopen MNTTAB to prevent reading stale data from open file */
	if (freopen(MNTTAB, "r", hdl->libzfs_mnttab) == NULL)
		return (NULL);

	while ((ret = getextmntent(hdl->libzfs_mnttab, &entry, 0)) == 0) {
		if (makedevice(entry.mnt_major, entry.mnt_minor) ==
		    statbuf.st_dev) {
			break;
		}
	}
	if (ret != 0) {
		return (NULL);
	}

	if (strcmp(entry.mnt_fstype, MNTTYPE_ZFS) != 0) {
		(void) fprintf(stderr, gettext("'%s': not a ZFS filesystem\n"),
		    path);
		return (NULL);
	}

	return (zfs_open(hdl, entry.mnt_special, ZFS_TYPE_FILESYSTEM));
}

/*
 * Append partition suffix to an otherwise fully qualified device path.
 * This is used to generate the name the full path as its stored in
 * ZPOOL_CONFIG_PATH for whole disk devices.  On success the new length
 * of 'path' will be returned on error a negative value is returned.
 */
int
zfs_append_partition(char *path, size_t max_len)
{
	int len = strlen(path);

	if (strncmp(path, UDISK_ROOT, strlen(UDISK_ROOT)) == 0) {
		if (len + 6 >= max_len)
			return (-1);

		(void) strcat(path, "-part1");
		len += 6;
	} else {
		if (len + 2 >= max_len)
			return (-1);

		if (isdigit(path[len-1])) {
			(void) strcat(path, "p1");
			len += 2;
		} else {
			(void) strcat(path, "1");
			len += 1;
		}
	}

	return (len);
}

/*
 * Given a shorthand device name check if a file by that name exists in any
 * of the 'zpool_default_import_path' or ZPOOL_IMPORT_PATH directories.  If
 * one is found, store its fully qualified path in the 'path' buffer passed
 * by the caller and return 0, otherwise return an error.
 */
int
zfs_resolve_shortname(const char *name, char *path, size_t len)
{
	int i, error = -1;
	char *dir, *env, *envdup;

	env = getenv("ZPOOL_IMPORT_PATH");
	errno = ENOENT;

	if (env) {
		envdup = strdup(env);
		dir = strtok(envdup, ":");
		while (dir && error) {
			(void) snprintf(path, len, "%s/%s", dir, name);
			error = access(path, F_OK);
			dir = strtok(NULL, ":");
		}
		free(envdup);
	} else {
		for (i = 0; i < DEFAULT_IMPORT_PATH_SIZE && error < 0; i++) {
			(void) snprintf(path, len, "%s/%s",
			    zpool_default_import_path[i], name);
			error = access(path, F_OK);
		}
	}

	return (error ? ENOENT : 0);
}

/*
 * Given a shorthand device name look for a match against 'cmp_name'.  This
 * is done by checking all prefix expansions using either the default
 * 'zpool_default_import_paths' or the ZPOOL_IMPORT_PATH environment
 * variable.  Proper partition suffixes will be appended if this is a
 * whole disk.  When a match is found 0 is returned otherwise ENOENT.
 */
static int
zfs_strcmp_shortname(char *name, char *cmp_name, int wholedisk)
{
	int path_len, cmp_len, i = 0, error = ENOENT;
	char *dir, *env, *envdup = NULL;
	char path_name[MAXPATHLEN];

	cmp_len = strlen(cmp_name);
	env = getenv("ZPOOL_IMPORT_PATH");

	if (env) {
		envdup = strdup(env);
		dir = strtok(envdup, ":");
	} else {
		dir =  zpool_default_import_path[i];
	}

	while (dir) {
		/* Trim trailing directory slashes from ZPOOL_IMPORT_PATH */
		while (dir[strlen(dir)-1] == '/')
			dir[strlen(dir)-1] = '\0';

		path_len = snprintf(path_name, MAXPATHLEN, "%s/%s", dir, name);
		if (wholedisk)
			path_len = zfs_append_partition(path_name, MAXPATHLEN);

		if ((path_len == cmp_len) && strcmp(path_name, cmp_name) == 0) {
			error = 0;
			break;
		}

		if (env) {
			dir = strtok(NULL, ":");
		} else if (++i < DEFAULT_IMPORT_PATH_SIZE) {
			dir = zpool_default_import_path[i];
		} else {
			dir = NULL;
		}
	}

	if (env)
		free(envdup);

	return (error);
}

/*
 * Given either a shorthand or fully qualified path name look for a match
 * against 'cmp'.  The passed name will be expanded as needed for comparison
 * purposes and redundant slashes stripped to ensure an accurate match.
 */
int
zfs_strcmp_pathname(char *name, char *cmp, int wholedisk)
{
	int path_len, cmp_len;
	char path_name[MAXPATHLEN];
	char cmp_name[MAXPATHLEN];
	char *dir, *dup;

	/* Strip redundant slashes if one exists due to ZPOOL_IMPORT_PATH */
	memset(cmp_name, 0, MAXPATHLEN);
	dup = strdup(cmp);
	dir = strtok(dup, "/");
	while (dir) {
		strcat(cmp_name, "/");
		strcat(cmp_name, dir);
		dir = strtok(NULL, "/");
	}
	free(dup);

	if (name[0] != '/')
		return (zfs_strcmp_shortname(name, cmp_name, wholedisk));

	(void) strlcpy(path_name, name, MAXPATHLEN);
	path_len = strlen(path_name);
	cmp_len = strlen(cmp_name);

	if (wholedisk) {
		path_len = zfs_append_partition(path_name, MAXPATHLEN);
		if (path_len == -1)
			return (ENOMEM);
	}

	if ((path_len != cmp_len) || strcmp(path_name, cmp_name))
		return (ENOENT);

	return (0);
}

/*
 * Initialize the zc_nvlist_dst member to prepare for receiving an nvlist from
 * an ioctl().
 */
int
zcmd_alloc_dst_nvlist(libzfs_handle_t *hdl, zfs_cmd_t *zc, size_t len)
{
	if (len == 0)
		len = 16 * 1024;
	zc->zc_nvlist_dst_size = len;
	if ((zc->zc_nvlist_dst = (uint64_t)(uintptr_t)
	    zfs_alloc(hdl, zc->zc_nvlist_dst_size)) == 0)
		return (-1);

	return (0);
}

/*
 * Called when an ioctl() which returns an nvlist fails with ENOMEM.  This will
 * expand the nvlist to the size specified in 'zc_nvlist_dst_size', which was
 * filled in by the kernel to indicate the actual required size.
 */
int
zcmd_expand_dst_nvlist(libzfs_handle_t *hdl, zfs_cmd_t *zc)
{
	free((void *)(uintptr_t)zc->zc_nvlist_dst);
	if ((zc->zc_nvlist_dst = (uint64_t)(uintptr_t)
	    zfs_alloc(hdl, zc->zc_nvlist_dst_size)) == 0)
		return (-1);

	return (0);
}

/*
 * Called to free the src and dst nvlists stored in the command structure.
 */
void
zcmd_free_nvlists(zfs_cmd_t *zc)
{
	free((void *)(uintptr_t)zc->zc_nvlist_conf);
	free((void *)(uintptr_t)zc->zc_nvlist_src);
	free((void *)(uintptr_t)zc->zc_nvlist_dst);
}

static int
zcmd_write_nvlist_com(libzfs_handle_t *hdl, uint64_t *outnv, uint64_t *outlen,
    nvlist_t *nvl)
{
	char *packed;
	size_t len;

	verify(nvlist_size(nvl, &len, NV_ENCODE_NATIVE) == 0);

	if ((packed = zfs_alloc(hdl, len)) == NULL)
		return (-1);

	verify(nvlist_pack(nvl, &packed, &len, NV_ENCODE_NATIVE, 0) == 0);

	*outnv = (uint64_t)(uintptr_t)packed;
	*outlen = len;

	return (0);
}

int
zcmd_write_conf_nvlist(libzfs_handle_t *hdl, zfs_cmd_t *zc, nvlist_t *nvl)
{
	return (zcmd_write_nvlist_com(hdl, &zc->zc_nvlist_conf,
	    &zc->zc_nvlist_conf_size, nvl));
}

int
zcmd_write_src_nvlist(libzfs_handle_t *hdl, zfs_cmd_t *zc, nvlist_t *nvl)
{
	return (zcmd_write_nvlist_com(hdl, &zc->zc_nvlist_src,
	    &zc->zc_nvlist_src_size, nvl));
}

/*
 * Unpacks an nvlist from the ZFS ioctl command structure.
 */
int
zcmd_read_dst_nvlist(libzfs_handle_t *hdl, zfs_cmd_t *zc, nvlist_t **nvlp)
{
	if (nvlist_unpack((void *)(uintptr_t)zc->zc_nvlist_dst,
	    zc->zc_nvlist_dst_size, nvlp, 0) != 0)
		return (no_memory(hdl));

	return (0);
}

int
zfs_ioctl(libzfs_handle_t *hdl, int request, zfs_cmd_t *zc)
{
	return (ioctl(hdl->libzfs_fd, request, zc));
}

/*
 * ================================================================
 * API shared by zfs and zpool property management
 * ================================================================
 */

static void
zprop_print_headers(zprop_get_cbdata_t *cbp, zfs_type_t type)
{
	zprop_list_t *pl = cbp->cb_proplist;
	int i;
	char *title;
	size_t len;

	cbp->cb_first = B_FALSE;
	if (cbp->cb_scripted)
		return;

	/*
	 * Start with the length of the column headers.
	 */
	cbp->cb_colwidths[GET_COL_NAME] = strlen(dgettext(TEXT_DOMAIN, "NAME"));
	cbp->cb_colwidths[GET_COL_PROPERTY] = strlen(dgettext(TEXT_DOMAIN,
	    "PROPERTY"));
	cbp->cb_colwidths[GET_COL_VALUE] = strlen(dgettext(TEXT_DOMAIN,
	    "VALUE"));
	cbp->cb_colwidths[GET_COL_RECVD] = strlen(dgettext(TEXT_DOMAIN,
	    "RECEIVED"));
	cbp->cb_colwidths[GET_COL_SOURCE] = strlen(dgettext(TEXT_DOMAIN,
	    "SOURCE"));

	/* first property is always NAME */
	assert(cbp->cb_proplist->pl_prop ==
	    ((type == ZFS_TYPE_POOL) ?  ZPOOL_PROP_NAME : ZFS_PROP_NAME));

	/*
	 * Go through and calculate the widths for each column.  For the
	 * 'source' column, we kludge it up by taking the worst-case scenario of
	 * inheriting from the longest name.  This is acceptable because in the
	 * majority of cases 'SOURCE' is the last column displayed, and we don't
	 * use the width anyway.  Note that the 'VALUE' column can be oversized,
	 * if the name of the property is much longer than any values we find.
	 */
	for (pl = cbp->cb_proplist; pl != NULL; pl = pl->pl_next) {
		/*
		 * 'PROPERTY' column
		 */
		if (pl->pl_prop != ZPROP_INVAL) {
			const char *propname = (type == ZFS_TYPE_POOL) ?
			    zpool_prop_to_name(pl->pl_prop) :
			    zfs_prop_to_name(pl->pl_prop);

			len = strlen(propname);
			if (len > cbp->cb_colwidths[GET_COL_PROPERTY])
				cbp->cb_colwidths[GET_COL_PROPERTY] = len;
		} else {
			len = strlen(pl->pl_user_prop);
			if (len > cbp->cb_colwidths[GET_COL_PROPERTY])
				cbp->cb_colwidths[GET_COL_PROPERTY] = len;
		}

		/*
		 * 'VALUE' column.  The first property is always the 'name'
		 * property that was tacked on either by /sbin/zfs's
		 * zfs_do_get() or when calling zprop_expand_list(), so we
		 * ignore its width.  If the user specified the name property
		 * to display, then it will be later in the list in any case.
		 */
		if (pl != cbp->cb_proplist &&
		    pl->pl_width > cbp->cb_colwidths[GET_COL_VALUE])
			cbp->cb_colwidths[GET_COL_VALUE] = pl->pl_width;

		/* 'RECEIVED' column. */
		if (pl != cbp->cb_proplist &&
		    pl->pl_recvd_width > cbp->cb_colwidths[GET_COL_RECVD])
			cbp->cb_colwidths[GET_COL_RECVD] = pl->pl_recvd_width;

		/*
		 * 'NAME' and 'SOURCE' columns
		 */
		if (pl->pl_prop == (type == ZFS_TYPE_POOL ? ZPOOL_PROP_NAME :
		    ZFS_PROP_NAME) &&
		    pl->pl_width > cbp->cb_colwidths[GET_COL_NAME]) {
			cbp->cb_colwidths[GET_COL_NAME] = pl->pl_width;
			cbp->cb_colwidths[GET_COL_SOURCE] = pl->pl_width +
			    strlen(dgettext(TEXT_DOMAIN, "inherited from"));
		}
	}

	/*
	 * Now go through and print the headers.
	 */
	for (i = 0; i < ZFS_GET_NCOLS; i++) {
		switch (cbp->cb_columns[i]) {
		case GET_COL_NAME:
			title = dgettext(TEXT_DOMAIN, "NAME");
			break;
		case GET_COL_PROPERTY:
			title = dgettext(TEXT_DOMAIN, "PROPERTY");
			break;
		case GET_COL_VALUE:
			title = dgettext(TEXT_DOMAIN, "VALUE");
			break;
		case GET_COL_RECVD:
			title = dgettext(TEXT_DOMAIN, "RECEIVED");
			break;
		case GET_COL_SOURCE:
			title = dgettext(TEXT_DOMAIN, "SOURCE");
			break;
		default:
			title = NULL;
		}

		if (title != NULL) {
			if (i == (ZFS_GET_NCOLS - 1) ||
			    cbp->cb_columns[i + 1] == GET_COL_NONE)
				(void) printf("%s", title);
			else
				(void) printf("%-*s  ",
				    cbp->cb_colwidths[cbp->cb_columns[i]],
				    title);
		}
	}
	(void) printf("\n");
}

/*
 * Display a single line of output, according to the settings in the callback
 * structure.
 */
void
zprop_print_one_property(const char *name, zprop_get_cbdata_t *cbp,
    const char *propname, const char *value, zprop_source_t sourcetype,
    const char *source, const char *recvd_value)
{
	int i;
	const char *str = NULL;
	char buf[128];

	/*
	 * Ignore those source types that the user has chosen to ignore.
	 */
	if ((sourcetype & cbp->cb_sources) == 0)
		return;

	if (cbp->cb_first)
		zprop_print_headers(cbp, cbp->cb_type);

	for (i = 0; i < ZFS_GET_NCOLS; i++) {
		switch (cbp->cb_columns[i]) {
		case GET_COL_NAME:
			str = name;
			break;

		case GET_COL_PROPERTY:
			str = propname;
			break;

		case GET_COL_VALUE:
			str = value;
			break;

		case GET_COL_SOURCE:
			switch (sourcetype) {
			case ZPROP_SRC_NONE:
				str = "-";
				break;

			case ZPROP_SRC_DEFAULT:
				str = "default";
				break;

			case ZPROP_SRC_LOCAL:
				str = "local";
				break;

			case ZPROP_SRC_TEMPORARY:
				str = "temporary";
				break;

			case ZPROP_SRC_INHERITED:
				(void) snprintf(buf, sizeof (buf),
				    "inherited from %s", source);
				str = buf;
				break;
			case ZPROP_SRC_RECEIVED:
				str = "received";
				break;
			}
			break;

		case GET_COL_RECVD:
			str = (recvd_value == NULL ? "-" : recvd_value);
			break;

		default:
			continue;
		}

		if (i == (ZFS_GET_NCOLS - 1) ||
		    cbp->cb_columns[i + 1] == GET_COL_NONE)
			(void) printf("%s", str);
		else if (cbp->cb_scripted)
			(void) printf("%s\t", str);
		else
			(void) printf("%-*s  ",
			    cbp->cb_colwidths[cbp->cb_columns[i]],
			    str);
	}

	(void) printf("\n");
}

/*
 * Given a numeric suffix, convert the value into a number of bits that the
 * resulting value must be shifted.
 */
static int
str2shift(libzfs_handle_t *hdl, const char *buf)
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
		if (hdl)
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "invalid numeric suffix '%s'"), buf);
		return (-1);
	}

	/*
	 * Allow 'G' = 'GB' = 'GiB', case-insensitively.
	 * However, 'BB' and 'BiB' are disallowed.
	 */
	if (buf[1] == '\0' ||
	    (toupper(buf[0]) != 'B' &&
	    ((toupper(buf[1]) == 'B' && buf[2] == '\0') ||
	    (toupper(buf[1]) == 'I' && toupper(buf[2]) == 'B' &&
	    buf[3] == '\0'))))
		return (10 * i);

	if (hdl)
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "invalid numeric suffix '%s'"), buf);
	return (-1);
}

/*
 * Convert a string of the form '100G' into a real number.  Used when setting
 * properties or creating a volume.  'buf' is used to place an extended error
 * message for the caller to use.
 */
int
zfs_nicestrtonum(libzfs_handle_t *hdl, const char *value, uint64_t *num)
{
	char *end;
	int shift;

	*num = 0;

	/* Check to see if this looks like a number.  */
	if ((value[0] < '0' || value[0] > '9') && value[0] != '.') {
		if (hdl)
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "bad numeric value '%s'"), value);
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
		if (hdl)
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "numeric value is too large"));
		return (-1);
	}

	/*
	 * If we have a decimal value, then do the computation with floating
	 * point arithmetic.  Otherwise, use standard arithmetic.
	 */
	if (*end == '.') {
		double fval = strtod(value, &end);

		if ((shift = str2shift(hdl, end)) == -1)
			return (-1);

		fval *= pow(2, shift);

		if (fval > UINT64_MAX) {
			if (hdl)
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "numeric value is too large"));
			return (-1);
		}

		*num = (uint64_t)fval;
	} else {
		if ((shift = str2shift(hdl, end)) == -1)
			return (-1);

		/* Check for overflow */
		if (shift >= 64 || (*num << shift) >> shift != *num) {
			if (hdl)
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "numeric value is too large"));
			return (-1);
		}

		*num <<= shift;
	}

	return (0);
}

/*
 * Given a propname=value nvpair to set, parse any numeric properties
 * (index, boolean, etc) if they are specified as strings and add the
 * resulting nvpair to the returned nvlist.
 *
 * At the DSL layer, all properties are either 64-bit numbers or strings.
 * We want the user to be able to ignore this fact and specify properties
 * as native values (numbers, for example) or as strings (to simplify
 * command line utilities).  This also handles converting index types
 * (compression, checksum, etc) from strings to their on-disk index.
 */
int
zprop_parse_value(libzfs_handle_t *hdl, nvpair_t *elem, int prop,
    zfs_type_t type, nvlist_t *ret, char **svalp, uint64_t *ivalp,
    const char *errbuf)
{
	data_type_t datatype = nvpair_type(elem);
	zprop_type_t proptype;
	const char *propname;
	char *value;
	boolean_t isnone = B_FALSE;

	if (type == ZFS_TYPE_POOL) {
		proptype = zpool_prop_get_type(prop);
		propname = zpool_prop_to_name(prop);
	} else {
		proptype = zfs_prop_get_type(prop);
		propname = zfs_prop_to_name(prop);
	}

	/*
	 * Convert any properties to the internal DSL value types.
	 */
	*svalp = NULL;
	*ivalp = 0;

	switch (proptype) {
	case PROP_TYPE_STRING:
		if (datatype != DATA_TYPE_STRING) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "'%s' must be a string"), nvpair_name(elem));
			goto error;
		}
		(void) nvpair_value_string(elem, svalp);
		if (strlen(*svalp) >= ZFS_MAXPROPLEN) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "'%s' is too long"), nvpair_name(elem));
			goto error;
		}
		break;

	case PROP_TYPE_NUMBER:
		if (datatype == DATA_TYPE_STRING) {
			(void) nvpair_value_string(elem, &value);
			if (strcmp(value, "none") == 0) {
				isnone = B_TRUE;
			} else if (zfs_nicestrtonum(hdl, value, ivalp)
			    != 0) {
				goto error;
			}
		} else if (datatype == DATA_TYPE_UINT64) {
			(void) nvpair_value_uint64(elem, ivalp);
		} else {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "'%s' must be a number"), nvpair_name(elem));
			goto error;
		}

		/*
		 * Quota special: force 'none' and don't allow 0.
		 */
		if ((type & ZFS_TYPE_DATASET) && *ivalp == 0 && !isnone &&
		    (prop == ZFS_PROP_QUOTA || prop == ZFS_PROP_REFQUOTA)) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "use 'none' to disable quota/refquota"));
			goto error;
		}

		/*
		 * Special handling for "*_limit=none". In this case it's not
		 * 0 but UINT64_MAX.
		 */
		if ((type & ZFS_TYPE_DATASET) && isnone &&
		    (prop == ZFS_PROP_FILESYSTEM_LIMIT ||
		    prop == ZFS_PROP_SNAPSHOT_LIMIT)) {
			*ivalp = UINT64_MAX;
		}
		break;

	case PROP_TYPE_INDEX:
		if (datatype != DATA_TYPE_STRING) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "'%s' must be a string"), nvpair_name(elem));
			goto error;
		}

		(void) nvpair_value_string(elem, &value);

		if (zprop_string_to_index(prop, value, ivalp, type) != 0) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "'%s' must be one of '%s'"), propname,
			    zprop_values(prop, type));
			goto error;
		}
		break;

	default:
		abort();
	}

	/*
	 * Add the result to our return set of properties.
	 */
	if (*svalp != NULL) {
		if (nvlist_add_string(ret, propname, *svalp) != 0) {
			(void) no_memory(hdl);
			return (-1);
		}
	} else {
		if (nvlist_add_uint64(ret, propname, *ivalp) != 0) {
			(void) no_memory(hdl);
			return (-1);
		}
	}

	return (0);
error:
	(void) zfs_error(hdl, EZFS_BADPROP, errbuf);
	return (-1);
}

static int
addlist(libzfs_handle_t *hdl, char *propname, zprop_list_t **listp,
    zfs_type_t type)
{
	int prop;
	zprop_list_t *entry;

	prop = zprop_name_to_prop(propname, type);

	if (prop != ZPROP_INVAL && !zprop_valid_for_type(prop, type, B_FALSE))
		prop = ZPROP_INVAL;

	/*
	 * When no property table entry can be found, return failure if
	 * this is a pool property or if this isn't a user-defined
	 * dataset property,
	 */
	if (prop == ZPROP_INVAL && ((type == ZFS_TYPE_POOL &&
	    !zpool_prop_feature(propname) &&
	    !zpool_prop_unsupported(propname)) ||
	    (type == ZFS_TYPE_DATASET && !zfs_prop_user(propname) &&
	    !zfs_prop_userquota(propname) && !zfs_prop_written(propname)))) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "invalid property '%s'"), propname);
		return (zfs_error(hdl, EZFS_BADPROP,
		    dgettext(TEXT_DOMAIN, "bad property list")));
	}

	if ((entry = zfs_alloc(hdl, sizeof (zprop_list_t))) == NULL)
		return (-1);

	entry->pl_prop = prop;
	if (prop == ZPROP_INVAL) {
		if ((entry->pl_user_prop = zfs_strdup(hdl, propname)) ==
		    NULL) {
			free(entry);
			return (-1);
		}
		entry->pl_width = strlen(propname);
	} else {
		entry->pl_width = zprop_width(prop, &entry->pl_fixed,
		    type);
	}

	*listp = entry;

	return (0);
}

/*
 * Given a comma-separated list of properties, construct a property list
 * containing both user-defined and native properties.  This function will
 * return a NULL list if 'all' is specified, which can later be expanded
 * by zprop_expand_list().
 */
int
zprop_get_list(libzfs_handle_t *hdl, char *props, zprop_list_t **listp,
    zfs_type_t type)
{
	*listp = NULL;

	/*
	 * If 'all' is specified, return a NULL list.
	 */
	if (strcmp(props, "all") == 0)
		return (0);

	/*
	 * If no props were specified, return an error.
	 */
	if (props[0] == '\0') {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "no properties specified"));
		return (zfs_error(hdl, EZFS_BADPROP, dgettext(TEXT_DOMAIN,
		    "bad property list")));
	}

	/*
	 * It would be nice to use getsubopt() here, but the inclusion of column
	 * aliases makes this more effort than it's worth.
	 */
	while (*props != '\0') {
		size_t len;
		char *p;
		char c;

		if ((p = strchr(props, ',')) == NULL) {
			len = strlen(props);
			p = props + len;
		} else {
			len = p - props;
		}

		/*
		 * Check for empty options.
		 */
		if (len == 0) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "empty property name"));
			return (zfs_error(hdl, EZFS_BADPROP,
			    dgettext(TEXT_DOMAIN, "bad property list")));
		}

		/*
		 * Check all regular property names.
		 */
		c = props[len];
		props[len] = '\0';

		if (strcmp(props, "space") == 0) {
			static char *spaceprops[] = {
				"name", "avail", "used", "usedbysnapshots",
				"usedbydataset", "usedbyrefreservation",
				"usedbychildren", NULL
			};
			int i;

			for (i = 0; spaceprops[i]; i++) {
				if (addlist(hdl, spaceprops[i], listp, type))
					return (-1);
				listp = &(*listp)->pl_next;
			}
		} else {
			if (addlist(hdl, props, listp, type))
				return (-1);
			listp = &(*listp)->pl_next;
		}

		props = p;
		if (c == ',')
			props++;
	}

	return (0);
}

void
zprop_free_list(zprop_list_t *pl)
{
	zprop_list_t *next;

	while (pl != NULL) {
		next = pl->pl_next;
		free(pl->pl_user_prop);
		free(pl);
		pl = next;
	}
}

typedef struct expand_data {
	zprop_list_t	**last;
	libzfs_handle_t	*hdl;
	zfs_type_t type;
} expand_data_t;

int
zprop_expand_list_cb(int prop, void *cb)
{
	zprop_list_t *entry;
	expand_data_t *edp = cb;

	if ((entry = zfs_alloc(edp->hdl, sizeof (zprop_list_t))) == NULL)
		return (ZPROP_INVAL);

	entry->pl_prop = prop;
	entry->pl_width = zprop_width(prop, &entry->pl_fixed, edp->type);
	entry->pl_all = B_TRUE;

	*(edp->last) = entry;
	edp->last = &entry->pl_next;

	return (ZPROP_CONT);
}

int
zprop_expand_list(libzfs_handle_t *hdl, zprop_list_t **plp, zfs_type_t type)
{
	zprop_list_t *entry;
	zprop_list_t **last;
	expand_data_t exp;

	if (*plp == NULL) {
		/*
		 * If this is the very first time we've been called for an 'all'
		 * specification, expand the list to include all native
		 * properties.
		 */
		last = plp;

		exp.last = last;
		exp.hdl = hdl;
		exp.type = type;

		if (zprop_iter_common(zprop_expand_list_cb, &exp, B_FALSE,
		    B_FALSE, type) == ZPROP_INVAL)
			return (-1);

		/*
		 * Add 'name' to the beginning of the list, which is handled
		 * specially.
		 */
		if ((entry = zfs_alloc(hdl, sizeof (zprop_list_t))) == NULL)
			return (-1);

		entry->pl_prop = (type == ZFS_TYPE_POOL) ?  ZPOOL_PROP_NAME :
		    ZFS_PROP_NAME;
		entry->pl_width = zprop_width(entry->pl_prop,
		    &entry->pl_fixed, type);
		entry->pl_all = B_TRUE;
		entry->pl_next = *plp;
		*plp = entry;
	}
	return (0);
}

int
zprop_iter(zprop_func func, void *cb, boolean_t show_all, boolean_t ordered,
    zfs_type_t type)
{
	return (zprop_iter_common(func, cb, show_all, ordered, type));
}

void
zfs_start_mirror(libzfs_handle_t *hdl, char *mirror_to,
    uint64_t flags)
{
    int err;
    zfs_cmd_t zc = { 0 };


    if (flags == ENABLE_MIRROR) {
        if (mirror_to != NULL) {
            zc.zc_perm_action = (uint64_t)strtol(mirror_to, NULL, 10);
        } else {
            zc.zc_perm_action = 0;
        }
    }

    zc.zc_cookie = flags;

    err = ioctl(hdl->libzfs_fd, ZFS_IOC_START_MIRROR, &zc);
    if (flags == SHOW_MIRROR) {
        printf("Mirror state:%s\r\n", zc.zc_string);
    } else if (flags == DISABLE_MIRROR) {
        if (err != 0) {
            switch ((int)zc.zc_guid) {
            case -1:
                printf("zfs mirror wasn't initialized!\r\n");
                break;
            case -2:
                printf("zfs mirror is busy now, close failed!\r\n");
                break;
            default:
                break;
            }
        }
    } else if (flags == ENABLE_MIRROR) {
        if (err != 0) {
            switch ((int)zc.zc_guid) {
            case -1:
                printf("zfs mirror alread opened!\r\n");
                break;
            case -2:
                printf("zfs mirror initialize failed!\r\n");
                break;
            default:
                break;
            }
        }
    }
}

int
zfs_test_mirror(libzfs_handle_t *hdl, long int bs, long int cnt, uint8_t need_reply)
{
	int err;
	zfs_cmd_t zc = { 0 };

	zc.zc_guid = bs;
	zc.zc_cookie = cnt;
	zc.zc_simple = need_reply;

	err = ioctl(hdl->libzfs_fd, ZFS_IOC_MIRROR_SPEED_TEST, &zc);

	return err;
}

int zfs_comm_test(libzfs_handle_t *hdl, char *hostid, char*datalen, char*headlen)
{
	int err;
	uint32_t id;
	uint32_t len;
	uint32_t exlen;
	zfs_cmd_t zc = { 0 };
	
	if (hostid == NULL) {
		(void) printf("must give the hostid\n");
		return (-1);
	}
	id = atoi(hostid);
	if (id < 1 || id > 255) {
		printf("hostid >= 1 and hostid <= 255\n");
		return (-1);
	}
	
	if (datalen==NULL || headlen==NULL){
		printf("usage: zfs clustersan comm <hostid> <datalen> <headlen>\n");
		return (-1);
	}
	len = atoi(datalen);
	if (len>2097152)/*2M*/ {
		printf("datalen >0 and datalen <= 2M\n");
		return (-1);
	}
	exlen = atoi(headlen);
	if (exlen>8192) {
		printf("headlen >= 0 and headlen <= 8KB\n");
		return (-1);
	}
	zc.zc_pad[0] = (char)id;
	zc.zc_sendobj = len;
	zc.zc_fromobj = exlen;
	zc.zc_cookie = ZFS_CLUSTERSAN_COMM_TEST;
	
	err = ioctl(hdl->libzfs_fd, ZFS_IOC_CLUSTERSAN, &zc);
	if (err != 0) {
		(void) printf("cluster comm test failed\n");
	} else {
		(void) printf("cluster comm test success\n");
	}
	return (err);
}

int zfs_enable_clustersan(libzfs_handle_t *hdl, char *clustername,
	char *linkname, nvlist_t *conf, uint64_t flags)
{
	int err;
	zfs_cmd_t zc = {"\0"};

	if ((clustername == NULL) && (linkname == NULL)) {
		(void) printf("must give the -n or -l option\n");
		return (-1);
	}
	bzero(&zc, sizeof(zfs_cmd_t));
	if (clustername != NULL) {
		strcpy(zc.zc_name, clustername);
	}
	if (linkname != NULL) {
		strcpy(zc.zc_value, linkname);
	}
	zc.zc_cookie = ZFS_CLUSTERSAN_ENABLE;
	zc.zc_guid = flags;
	zc.zc_nvlist_conf = 0;
	zc.zc_nvlist_conf_size = 0;
	if (conf != NULL) {
		if (zcmd_write_conf_nvlist(hdl, &zc, conf) != 0) {
			(void) fprintf(stderr,
				gettext("internal error: out of memory\n"));
			return (1);
		}
	}
	err = ioctl(hdl->libzfs_fd, ZFS_IOC_CLUSTERSAN, &zc);
	if (err != 0) {
		(void) printf("clustersan enable failed\n");
	}

	if (zc.zc_nvlist_conf != 0) {
		zcmd_free_nvlists(&zc);
	}
	return (err);
}

int zfs_disable_clustersan(libzfs_handle_t *hdl, uint64_t flags)
{
	int err;
	zfs_cmd_t zc = {"\0"};
	zc.zc_cookie = ZFS_CLUSTERSAN_DISABLE;
	zc.zc_guid = flags;
	err = ioctl(hdl->libzfs_fd, ZFS_IOC_CLUSTERSAN, &zc);
	if (err != 0) {
		(void) printf("clustersan not enabled\n");
	}
	
	return (err);
}

int zfs_disable_clustersan_target(libzfs_handle_t *hdl, char *linkname, uint64_t flags)
{
	int err;
	zfs_cmd_t zc = {"\0"};

	if (linkname == NULL) {
		(void) printf("linkname is NULL\n");
		return (-1);
	} else {
		strcpy(zc.zc_value, linkname);
	}
	
	zc.zc_cookie = ZFS_CLUSTERSAN_TARGET_DISABLE;
	zc.zc_guid = flags;
	err = ioctl(hdl->libzfs_fd, ZFS_IOC_CLUSTERSAN, &zc);
	if (err != 0) {
		(void) printf("clustersan target: %s not enabled\n",
			linkname);
	}
	
	return (err);
}

nvlist_t *zfs_clustersan_get_nvlist(libzfs_handle_t *hdl, uint32_t cmd,
	void *arg, uint64_t flags)
{
	int err;
	nvlist_t *nvl;
	zfs_cmd_t zc = {"\0"};
	zc.zc_cookie = cmd;
	zc.zc_perm_action = (uintptr_t)arg;
	zc.zc_guid = flags;

	if (zcmd_alloc_dst_nvlist(hdl, &zc, 0) != 0) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}
	while ((err = ioctl(hdl->libzfs_fd, ZFS_IOC_CLUSTERSAN,
	    &zc)) != 0 && errno == ENOMEM) {
		if (zcmd_expand_dst_nvlist(hdl, &zc) != 0) {
			zcmd_free_nvlists(&zc);
			return (NULL);
		}
	}

	if (err) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	if (zcmd_read_dst_nvlist(hdl, &zc, &nvl) != 0) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	zcmd_free_nvlists(&zc);
	return (nvl);
}

nvlist_t *zfs_clustersan_get_hostlist(libzfs_handle_t *hdl, uint64_t flags)
{
	return (zfs_clustersan_get_nvlist(hdl, ZFS_CLUSTERSAN_LIST_HOST, NULL, flags));
}

nvlist_t *zfs_clustersan_get_targetlist(libzfs_handle_t *hdl, uint64_t flags)
{
	return (zfs_clustersan_get_nvlist(hdl, ZFS_CLUSTERSAN_LIST_TARGET, NULL, flags));
}

int zfs_clustersan_set_prop(libzfs_handle_t *hdl,
	const char *prop, const char *value)
{
	zfs_cmd_t zc = {"\0"};
	int err;
	strcpy(zc.zc_name, prop);
	strcpy(zc.zc_value, value);
	zc.zc_cookie = ZFS_CLUSTERSAN_SET;
	err = ioctl(hdl->libzfs_fd, ZFS_IOC_CLUSTERSAN, &zc);
	if (err != 0) {
		(void) printf("clustersan set %s=%s failed\n", prop, value);
	}
	
	return (err);
}

int zfs_cluster_rdma_rpc_clnt_ioc(libzfs_handle_t *hdl, int cmd, void *arg)
{
	zfs_cmd_t zc = {"\0"};
	int err;
	zc.zc_cookie = ZFS_CLUSTERSAN_IOC_RPC_CLNT;
	zc.zc_guid = cmd;
	zc.zc_perm_action = (uintptr_t)arg;
	err = ioctl(hdl->libzfs_fd, ZFS_IOC_CLUSTERSAN, &zc);

	return (err);
}

nvlist_t *zfs_clustersan_sync_cmd(libzfs_handle_t *hdl, uint64_t cmd_id,
	char *cmd_str, int timeout, int remote_hostid)
{
	int err;
	zfs_cmd_t zc = {"\0"};
	nvlist_t *nvl;

	if (cmd_str == NULL) {
		(void) printf("command is NULL");
		return (NULL);
	}

	if (zcmd_alloc_dst_nvlist(hdl, &zc, 512 * 1024) != 0) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}
	
	strcpy(zc.zc_value, cmd_str);
	zc.zc_cookie = ZFS_CLUSTERSAN_SYNC_CMD;
	zc.zc_guid = cmd_id;
	zc.zc_objset_type = timeout;
	zc.zc_perm_action = remote_hostid;
	err = ioctl(hdl->libzfs_fd, ZFS_IOC_CLUSTERSAN, &zc);
	if (err != 0) {
		(void) printf("clustersan sync cmd failed\n");
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	if (zcmd_read_dst_nvlist(hdl, &zc, &nvl) != 0) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	zcmd_free_nvlists(&zc);
	return (nvl);
}

int
zfs_do_hbx_get_nvlist(libzfs_handle_t *hdl, zfs_hbx_ioc_t cmd,
	uint32_t hostid, nvlist_t **nv_ptr)
{
	nvlist_t *nvl;
	zfs_cmd_t zc = {"\0"};
	int err;

	zc.zc_cookie = cmd;
	zc.zc_perm_action = hostid;
	if ((err = zcmd_alloc_dst_nvlist(hdl, &zc, 0)) != 0) {
		zcmd_free_nvlists(&zc);
		return (err);
	}

	while ((err = ioctl(hdl->libzfs_fd, ZFS_IOC_HBX,
	    &zc)) != 0 && errno == ENOMEM) {
		if ((err = zcmd_expand_dst_nvlist(hdl, &zc)) != 0) {
			zcmd_free_nvlists(&zc);
			return (err);
		}
	}

	if (err) {
		zcmd_free_nvlists(&zc);
		return (err);
	}

	if ((err = zcmd_read_dst_nvlist(hdl, &zc, &nvl)) != 0) {
		zcmd_free_nvlists(&zc);
		return (err);
	}

	zcmd_free_nvlists(&zc);

	*nv_ptr = nvl;
	return (0);
}

void
zfs_do_hbx_process(libzfs_handle_t *hdl, char *buffer, int size, uint64_t flags)
{
	int err, value;
	char *string;
	zfs_cmd_t zc = {"\0"};

	if (flags == ZFS_HBX_SET) {
		if (buffer == NULL)
			return;
		
		string = strchr(buffer, '=');
		if (string == NULL)
			return;
		if (strstr(buffer, "timeout")) {
			string += 1;
			value = strtol(string, NULL, 10);
			zc.zc_perm_action = value;
		}
		strcpy(zc.zc_string, buffer);
	} else if (flags == ZFS_HBX_NIC_UPDATE || 
	              flags == ZFS_HBX_KEYFILE_UPDATE||
	              flags == ZFS_HBX_KEYPATH_UPDATE||
	              flags == ZFS_HBX_RCMD_UPDATE||
	              flags == ZFS_HBX_SYNCKEY_RESULT||
	              flags == ZFS_HBX_MPTSAS_DOWN||
	              flags == ZFS_HBX_FC_DOWN ||
	              flags == ZFS_HBX_MAC_STAT ||
	              flags == ZFS_HBX_SEND_IPMI_IP ||
	              flags == ZFS_HBX_MIRROR_TIMEOUT_SWITCH ||
	              flags == ZFS_HBX_RELEASE_POOLS ||
	              flags == ZFS_HBX_CLUSTERSAN_SYNC_CMD ||
	              flags == ZFS_HBX_SYNC_POOL) {
		zc.zc_nvlist_conf = (uintptr_t)buffer;
		zc.zc_nvlist_conf_size = size;
	}

	zc.zc_cookie = flags;
	err = ioctl(hdl->libzfs_fd, ZFS_IOC_HBX, &zc);
#if	0
	if (flags == ZFS_HBX_LIST) {
		printf("PROPERTY\t\tVALUE\n%s", zc.zc_string);
	}
#endif
}

void
zfs_do_hbx_process_ex(libzfs_handle_t * hdl, char * buffer, int size,
	uint64_t flags, int remote_id)
{
	int err;
	zfs_cmd_t zc = {"\0"};

	if (flags == ZFS_HBX_RELEASE_POOLS ||
		flags == ZFS_HBX_CLUSTER_IMPORT) {
		zc.zc_nvlist_conf = (uintptr_t)buffer;
		zc.zc_nvlist_conf_size = size;
		zc.zc_perm_action = remote_id;
	} else {
		return;
	}

	zc.zc_cookie = flags;
	err = ioctl(hdl->libzfs_fd, ZFS_IOC_HBX, &zc);
	if (err < 0) {
		syslog(LOG_ERR, "%s: ioctl failed, flags=0x%llx",
			__func__, (unsigned long long)flags);
	}
}

int
get_clusnodename(char *buf, int len)
{
#define HOSTNAMELEN 64
    int i=0;
    FILE *fp;
	len = len < HOSTNAMELEN ? len : HOSTNAMELEN;
    fp = fopen("/etc/cluster_hostname", "r");
    if (fp == NULL) {
            return (-1);
    }
    fgets(buf, len, fp);
    fclose(fp);
    for (i=0; i<len; i++) {
            if (*(buf+i) == ' ' || *(buf+i) == '\n') {
                    break;
            }
    }
    if (i == len)
            i = len -1;
    *(buf+i) = 0;
    return 0;
}

/* needby disk.c */

/*
 * Function	: disk_check_partition
 *		  get the pool name
 * dev	: disk path
 * pool_name: get the pool name
 * return	: 0 no partition;	1 hot spare; 2 disk inuse;
 *
 */
int
disk_get_poolname(const char *dev,char *pool_name)
{
	int fd;
	vdev_label_t label;
	char *path = NULL, *buf = label.vl_vdev_phys.vp_nvlist;
	size_t buflen = sizeof (label.vl_vdev_phys.vp_nvlist);
	struct stat64 statbuf;
	uint64_t psize, ashift;
	int tmp_len = strlen(dev) + 1;
	int len;
	char *tmp_path = NULL;
	int l;
	int ret = 0;

	if (strncmp(dev, "/dev/dsk/", 9) == 0) {
		tmp_len++;
		if((tmp_path = malloc(tmp_len)) == NULL) {
			return -1;
		}
		(void) snprintf(tmp_path, tmp_len, "%s%s", "/dev/rdsk/", dev + 9);
	} else {
		tmp_path = strdup(dev);
	}

	len = strlen(tmp_path) +3;
	if ((path = malloc(len + 3)) == NULL) {	
		return -1;

	}


	if (*(tmp_path + len - 2) != 's'){
		(void) snprintf(path, len, "%ss0", tmp_path);
	}else
		(void) snprintf(path, len, "%s", tmp_path);
	free(tmp_path);
	tmp_path = NULL;


	if ((fd = open64(path, O_RDONLY)) < 0) {
		free(path);
		return ret;
	}

	if (fstat64(fd, &statbuf) != 0) {
		(void) printf("failed to stat '%s': %s\n", path,
		    strerror(errno));
		free(path);
		(void) close(fd);
		return ret;

	}

	if (S_ISBLK(statbuf.st_mode)) {
		(void) printf("cannot use '%s': character device required\n",
		    path);
		free(path);
		(void) close(fd);
		return ret;
	}

	psize = statbuf.st_size;
	psize = P2ALIGN(psize, (uint64_t)sizeof (vdev_label_t));

	for (l = 0; l < VDEV_LABELS; l++) {
		nvlist_t *config = NULL;
		char *tmp_pool_name;

		if (pread64(fd, &label, sizeof (label),
		    label_offset(psize, l)) != sizeof (label)) {
			(void) printf("failed to read label %d\n", l);
			continue;
		}

		if (nvlist_unpack(buf, buflen, &config, 0) != 0) {
			/* do not have inuse */
			ret = 0;
			continue;
		} else {
			free(path);
			(void) close(fd);
			if (nvlist_lookup_string(config,
					ZPOOL_CONFIG_POOL_NAME, &tmp_pool_name) == 0) {
						ret = 1;
				strcpy(pool_name,tmp_pool_name);
			} else {
				ret = 2;
			}
			nvlist_free(config);
			return ret;
		}
	}
	
	free(path);
	(void) close(fd);
	return ret;
}

/*
 * Function	: zpool_restore_dev_labels
 *	restore or save disk label
 *
 * Parameters:
 *	save_rescover: when save_rescover==1,save labels
 *			save_rescover==0, restore labels
 * Return: Return	: 0==>success; -1==>fail
 */
int
zpool_restore_dev_labels(char *path, int save_rescover)
{
	int fd, ret = 0, len = 0;
	char dev_path[1024] = {"\0"};

	len = strlen(path);

	fd = open64(path, O_RDWR|O_SYNC);
	if (fd > 0) {
		/* first we must save label.then we can restore it */
		if (save_rescover == 1) {
			ret = zpool_save_label(fd);
		/* if save_rescover == 0 restore disk label */
		} else {
			ret = zpool_restore_label(fd);
		}
		close(fd);
	}

#if 0
	if (*(path + len -1) == '0' && *(path + len -2) == 'd') {
		strncpy(dev_path, path, strlen(path));
		strncat(dev_path, "s0", 2);
		fd = open64(dev_path, O_RDWR|O_SYNC);
		if (fd > 0) {
			/* first we must save label.then we can restore it */
			if (save_rescover == 1) {
				ret = zpool_save_label(fd);
			/* if save_rescover == 0 restore disk label */
			} else {
				ret = zpool_restore_label(fd);
			}
			close(fd);
		}
	} else {
		syslog(LOG_ERR, "init dev labev, path invalid:%s", path);
		return (-1);
	}
#endif
	return (ret);
}


int zpool_init_dev_labels(char *path)
{
	int fd, i, l, ret = 0, len = 0;
	uint64_t size;
	struct stat64 statbuf;
	vdev_label_t *label;
	char dev_path[1024] = {"\0"} ;

	fd = open64(path, O_RDWR|O_SYNC);
	if (fd > 0) {
		ret = zpool_clear_label(fd);
        close(fd);
	}
#if 0
	len = strlen(path);
	/* modify by jbzhao 20151202 begin
	 * for create pool on slices		
	 */
	if ( *(path + len - 2) == 's') {
		switch (*(path + len -1)){
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			{
				strncpy(dev_path, path, strlen(path));
				break;
			}
			default:
				break;
		}
        	fd = open64(dev_path, O_RDWR|O_SYNC);
        	if (fd > 0) {
                	ret = zpool_clear_label(fd);
                	close(fd);
        	}		
	} else if (*(path + len -1) == '0' && *(path + len -2) == 'd' ) {
			strncpy(dev_path, path, strlen(path));
			strncat(dev_path, "s0", 2);
        	fd = open64(dev_path, O_RDWR|O_SYNC);
        	if (fd > 0) {
                	ret = zpool_clear_label(fd);
                	close(fd);
        	}
	} else {
		syslog(LOG_ERR, "init dev labev, path invalid:%s", path);
		return (-1);
	}
	/* modify by jbzhao 20151202 end*/
#endif
	
	return (ret);
}

/*
 * synckey needed
 */
static void
synckey_no_receive_info(int recv)
{
	char fifo_name[512];
	long int current_id;
	current_id = getpid();

	bzero(fifo_name,512);
	sprintf(fifo_name,"/tmp/synckeyrebak%d",current_id);
	unlink(fifo_name);
	printf("send or recv fail,please check services open or not\n");
	exit(EXIT_FAILURE);
}

/*
 * Function: the function add the current PID in the buffer,
 * 		 so we can get the oppsite result.
 * Parameters
 *		buffer -- date ,we want to send
 *		size	 -- the buffer size
 *		flages -- judge choice which case
 * Return : 0 == success, -1 == faile 
 */
int 
zfs_add_guide_info( char *buffer, int size, uint64_t flags)
{
	long int current_id;
	int fifo_fd = -1;
	int chkfifo = 0;
	char fifo_name[512];
	char fifo_buffer[16];
	char *tmp_buffer=NULL;
	libzfs_handle_t *zfs_handle = NULL;
	int tmp_size = size;

	signal(SIGALRM,synckey_no_receive_info);
	alarm(5);
	
	current_id = getpid();
	bzero(fifo_name, 512);
	sprintf(fifo_name, "/tmp/synckeyrebak%d", current_id);
	chkfifo = mkfifo(fifo_name, 0777);
	if (chkfifo != 0){
		printf("Could not create FIFO\n");
		return (-1);
	}
	
	if (flags == ZFS_HBX_RCMD_UPDATE){
		tmp_buffer = malloc(size + MAX_ID_BYTE);
		if (NULL == tmp_buffer) {
			printf("malloc fail\n");
			unlink(fifo_name);
			return (-1);
		}
		sprintf(tmp_buffer,"%ld",current_id);
		bcopy(buffer, tmp_buffer + MAX_ID_BYTE, strlen(buffer));
		tmp_buffer[strlen(buffer) + MAX_ID_BYTE] = '\0';

		/* Calculate the length of the string */
		tmp_size = strlen(tmp_buffer + MAX_ID_BYTE) + MAX_ID_BYTE + 1;
	}

	if ((zfs_handle = libzfs_init()) == NULL) {
		printf("key file get zfs handle failed\n");
		if (flags == ZFS_HBX_RCMD_UPDATE)
			free(tmp_buffer);
		unlink(fifo_name);
		return (-1);
	}

	if (ZFS_HBX_KEYFILE_UPDATE == flags) {
		zfs_do_hbx_process(zfs_handle, buffer, size, flags);
	} else if (ZFS_HBX_RCMD_UPDATE == flags) {
		zfs_do_hbx_process(zfs_handle, tmp_buffer, tmp_size, flags);
	}
	
	if (flags == ZFS_HBX_RCMD_UPDATE)
		free(tmp_buffer);
	
	libzfs_fini(zfs_handle);

	fifo_fd = open(fifo_name,O_RDONLY);
	if (fifo_fd != -1){
		read(fifo_fd, fifo_buffer, sizeof(fifo_buffer));
		if (strcmp(fifo_buffer, "0") != 0){
			if (ZFS_HBX_RCMD_UPDATE == flags)
				printf("%s fail\n",buffer);
			else if (ZFS_HBX_KEYFILE_UPDATE == flags)
				printf("please check the file\n");
			}
		close(fifo_fd);
	} else {
		printf("open FIFO fail\n");
	}
	unlink(fifo_name);
	return 0;
}


int
zfs_create_lu(char *lu_name)
{
	char dev_buf[512];
	luResource hdl = NULL;
	int ret = 0;
	stmfGuid createdGuid;
	sprintf(dev_buf, "%s%s", ZVOL_FULL_DIR, lu_name);
	ret = stmfCreateLuResource(STMF_DISK, &hdl);
	if (ret != STMF_STATUS_SUCCESS) {
		syslog(LOG_ERR, "Can not Create LU Resource");
		return (1);
	}
	ret = stmfSetLuProp(hdl, STMF_LU_PROP_FILENAME, dev_buf);
	if (ret != STMF_STATUS_SUCCESS) {
		syslog(LOG_ERR, "Can Assign Name for LU");
		(void) stmfFreeLuResource(hdl);
		return (1);
	}

	ret = stmfCreateLu(hdl, &createdGuid);
	if (ret != STMF_STATUS_SUCCESS) {
		syslog(LOG_ERR, "Create LU fails");
		(void) stmfFreeLuResource(hdl);
		return (1);;
	}
	(void) stmfFreeLuResource(hdl);

	return (0);
}

int 
zfs_get_lus_call_back(zfs_handle_t *zhp, void *data)
{
	zfs_ilu_ctx_t *zicp = (zfs_ilu_ctx_t *)data;
	zfs_ilu_list_t *lu_list;
	syslog(LOG_DEBUG, "%s: zfs_name:%s", __func__, zfs_get_name(zhp));

	if (zfs_get_type(zhp) == ZFS_TYPE_VOLUME) {
		if ((zicp->pool_name != NULL) &&
			(strcmp(zhp->zpool_hdl->zpool_name, zicp->pool_name) == 0)) {
			lu_list = malloc(sizeof(zfs_ilu_list_t));
			lu_list->lu_name = malloc(strlen(zfs_get_name(zhp)) + 1);
			strcpy(lu_list->lu_name, zfs_get_name(zhp));
			lu_list->next = NULL;
			if (zicp->head == NULL) {
				zicp->head = lu_list;
			} else {
				zicp->tail->next = lu_list;
				lu_list->prev = zicp->tail;
			}
			zicp->tail = lu_list;
			zicp->lun_cnt++;
		}
	}
	zfs_close(zhp);
	return (0);
}

int 
zfs_import_pool_call_back(zfs_handle_t *zhp, void *data)
{
	zfs_ilu_ctx_t *zicp = (zfs_ilu_ctx_t *)data;
	syslog(LOG_DEBUG, "%s: zfs_name:%s", __func__, zfs_get_name(zhp));
	if (strcmp(zfs_get_name(zhp), zicp->pool_name) == 0) {
		zfs_iter_filesystems(zhp, zfs_get_lus_call_back, data);
	}
	zfs_close(zhp);
	return (0);
}

void* zfs_import_lu(void *arg)
{
	int ret;
	stmfGuid createdGuid;
	char dev_buf[512];
	char *lu_name = (char *)arg;

	syslog(LOG_DEBUG, " import lu enter, %s", lu_name);

	sprintf(dev_buf, "%s%s", ZVOL_FULL_DIR, lu_name);
	ret = stmfImportLu(STMF_DISK, dev_buf, &createdGuid);
	if (ret == 0) {
		stmfOnlineLogicalUnit(&createdGuid);
		syslog(LOG_INFO, " import lu success, %s", lu_name);
 	} else {
 		syslog(LOG_ERR, " import lu failed, %s, ret:0x%x", lu_name, ret);
 	}
	syslog(LOG_DEBUG, " import lu exit, %s", lu_name);

	free(lu_name);
	return (NULL);
}

void 
zfs_import_all_lus(libzfs_handle_t *hdl, char *data)
{
	zfs_ilu_ctx_t zic;
	zfs_ilu_list_t *lu_list;
	int ret;
	int tp_size;
	zfs_cmd_t *zc;
	int error;

	zic.pool_name = data;
	zic.head = NULL;
	zic.tail = NULL;
	zic.lun_cnt = 0;

	zfs_iter_root(hdl, zfs_import_pool_call_back, (void *)&zic);
	if (zic.lun_cnt == 0) {
		return;
	}

	/*
	tp_size = zic.lun_cnt;
	if (tp_size > ZFS_ILU_MAX_NTHREAD) {
		tp_size = ZFS_ILU_MAX_NTHREAD;
	}
	zic.zic_tp = tpool_create(1, tp_size, 0, NULL);
	while ((lu_list = zic.head) != NULL) {
		zic.head = zic.head->next;
		if (lu_list == zic.tail) {
			zic.tail = NULL;
		}
		
		ret = tpool_dispatch(zic.zic_tp, (void (*)(void *))zfs_import_lu,
			(void *)lu_list->lu_name);
		if (ret != 0) {
			zfs_import_lu(lu_list->lu_name);
		}
		free(lu_list);
	}

	if (zic.zic_tp != NULL) {
		tpool_wait(zic.zic_tp);
		tpool_destroy(zic.zic_tp);
	}
	*/
	
	lu_list = zic.head;
	while (lu_list) {
		lu_list->run_thread = B_TRUE;
		error = pthread_create(&lu_list->tid, NULL, zfs_import_lu, lu_list->lu_name);
		if (error) {
			lu_list->run_thread = B_FALSE;
			zfs_import_lu(lu_list->lu_name);
		}
		lu_list = lu_list->next;
	}
	
	while ((lu_list = zic.head) != NULL) {
		zic.head = zic.head->next;
		if (lu_list->run_thread)
			pthread_join(lu_list->tid, NULL);
		free(lu_list);
	}
	
	zc = malloc(sizeof(zfs_cmd_t));
	if (zc == NULL) {
		syslog(LOG_NOTICE, "%s: not wait pool(%s)'s zvol create minor done",
			__func__, data);
		return ;
	}
	strcpy(zc->zc_name, data);
	ret = zfs_ioctl(hdl, ZFS_IOC_ZVOL_CREATE_MINOR_DONE_WAIT, zc);
	if (ret != 0) {
		syslog(LOG_NOTICE, "%s: failed wait pool(%s)'s zvol create minor done",
			__func__, data);
	}
	free(zc);
}

int 
zfs_standby_lu_access(char *dataset, void *data)
{
	char dev_path[MAXNAMELEN];
	char prop_val[MAXNAMELEN];
	size_t prop_val_sz = sizeof(prop_val);
	stmfGuidList *lu_list;
	stmfGuid lu_guid;
	int ret;
	int lu_num;
	int len;
	luResource hdl = NULL;
	zfs_standby_ilu_ctx_t *zicp = (zfs_standby_ilu_ctx_t *)data;
	zfs_standby_ilu_list_t *ilu = NULL;
	
	sprintf(dev_path, "%s%s", ZVOL_FULL_DIR, dataset);
	
	ret = stmfGetLogicalUnitList(&lu_list);
	if (ret != STMF_STATUS_SUCCESS) {
		syslog(LOG_ERR, "standby lu access, get lu list failed");
		return (1);
	}

	for (lu_num = 0; lu_num < lu_list->cnt; lu_num ++) {
		lu_guid = lu_list->guid[lu_num];
		ret = stmfGetLuResource(&lu_guid, &hdl);
		if (ret != STMF_STATUS_SUCCESS) {
			syslog(LOG_ERR, "In standby lu access progress, Acquire LU Resource fails, error=%d"
				", guid=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", ret,
				lu_guid.guid[0], lu_guid.guid[1], lu_guid.guid[2], lu_guid.guid[3],
				lu_guid.guid[4], lu_guid.guid[5], lu_guid.guid[6], lu_guid.guid[7],
				lu_guid.guid[8], lu_guid.guid[9], lu_guid.guid[10], lu_guid.guid[11],
				lu_guid.guid[12], lu_guid.guid[13], lu_guid.guid[14], lu_guid.guid[15]);
			continue;
		}
		ret = stmfGetLuProp(hdl, STMF_LU_PROP_FILENAME, prop_val, &prop_val_sz);
		if (ret != STMF_STATUS_SUCCESS && ret != STMF_ERROR_NO_PROP_STANDBY) {
			(void) stmfFreeLuResource(hdl);
			hdl = NULL;
			syslog(LOG_ERR, "In standby lu access progress, Acquire LU Metadata Resource Fails err=%x ", ret);
			continue;
		}
		
		if (strcmp(dev_path, prop_val) == 0) {
			ret = stmfLuStandbyAccess(&lu_guid);
			if (ret != STMF_STATUS_SUCCESS) {
				stmfFreeMemory(lu_list);
				(void) stmfFreeLuResource(hdl);
				syslog(LOG_ERR, "In standby lu access progress, Standby LU Metadata Resource Fails ");
				return (1);
			}

			ilu = malloc(sizeof(zfs_standby_ilu_list_t));
			len = strlen(dev_path) + 1;
			ilu->lu_name = malloc(len);
			memset(ilu->lu_name, 0, len);
			snprintf(ilu->lu_name, len, "%s", dev_path);
			ilu->lu_guid = lu_guid;
			ilu->next = NULL;

			if (zicp->head == NULL)
				zicp->head = ilu;
			else
				zicp->tail->next = ilu;
			
			zicp->tail = ilu;
			zicp->lun_cnt++;
			break;
		}
		(void) stmfFreeLuResource(hdl);
		hdl = NULL;
	}

	stmfFreeMemory(lu_list);
	(void) stmfFreeLuResource(hdl);
	
	return (0);
}

int 
zfs_standby_lu_access_callback(zfs_handle_t *zhp, void *data)
{
	zfs_standby_ilu_ctx_t *zicp = (zfs_standby_ilu_ctx_t *)data;
	if (strcmp(zhp->zpool_hdl->zpool_name, zicp->pool_name) == 0 &&
	   zfs_get_type(zhp) == ZFS_TYPE_VOLUME) {
		zfs_standby_lu_access((char *)zfs_get_name(zhp), data);
	}
	return (0);

}

int 
zfs_standby_pool_call_back(zfs_handle_t *zhp, void *data)
{
	zfs_iter_filesystems(zhp, zfs_standby_lu_access_callback, data);
	return (0);
}
void 
zfs_standby_all_lus(libzfs_handle_t *hdl, char *pool_name)
{
	zfs_standby_ilu_ctx_t zic;
	zfs_standby_ilu_list_t *ilu = NULL;
	int ret;
	
	zic.pool_name = pool_name;
	zic.head = NULL;
	zic.tail = NULL;
	zic.lun_cnt = 0;

	zfs_iter_root(hdl, zfs_standby_pool_call_back, (void *)&zic);

	syslog(LOG_ERR, "wait 3 seconds to close zvol %s", pool_name);
	sleep(3);
	syslog(LOG_ERR, "close zvol %s", pool_name);

	if (zic.lun_cnt > 0) {
		while ((ilu = zic.head) != NULL) {
			zic.head = zic.head->next;
			ret = stmfCloseStandbyLu(&ilu->lu_guid);
			if (ret != STMF_STATUS_SUCCESS)
				syslog(LOG_ERR, "In close standby lu progress, Standby LU Metadata Resource Fails ");

			if (ilu->lu_name)
				free(ilu->lu_name);
			free(ilu);
			zic.lun_cnt--;
		}
	}
}

int 
zfs_destroy_lu(char *dataset)
{
	int stmf_proxy_door_fd;
	char dev_path[MAXNAMELEN];
	char prop_val[MAXNAMELEN];
	size_t prop_val_sz = sizeof(prop_val);
	stmfGuidList *lu_list;
	stmfViewEntryList *view_entry_list; 
	stmfGuid lu_guid;
	int ret;
	int lu_num;
	int view_num;
	luResource hdl = NULL;
	boolean_t b_destroy_partner = B_TRUE;
	boolean_t b_del_partion = B_FALSE;
	stmf_remove_proxy_view_t *proxy_remove_view_entry;

	sprintf(dev_path, "%s%s", ZVOL_FULL_DIR, dataset);
	ret = stmfGetLogicalUnitList(&lu_list);
	if (ret == STMF_STATUS_SUCCESS) {
		for (lu_num = 0; lu_num < lu_list->cnt; lu_num ++) {
			b_del_partion = B_TRUE;
			lu_guid = lu_list->guid[lu_num];
			ret = stmfGetLuResource(&lu_guid, &hdl);
			if (ret != STMF_STATUS_SUCCESS) {
				syslog(LOG_ERR, "Acquire LU Resource fails");
				return (1);
			}
			ret = stmfGetLuProp(hdl, STMF_LU_PROP_FILENAME, prop_val, &prop_val_sz);
			if (ret != STMF_STATUS_SUCCESS) {
				(void) stmfFreeLuResource(hdl);
				hdl = NULL;
				syslog(LOG_ERR, "Acquire LU Metadata Resource Fails ");
				continue;
			}
			if (strcmp(dev_path, prop_val) == 0) {
				
				ret = stmfGetViewEntryList(&lu_guid, &view_entry_list);
				if (ret != STMF_STATUS_SUCCESS) {
					syslog(LOG_ERR, "Acquire LU Partition Resource Fails ");
					b_del_partion = B_FALSE;
				}
				if (b_del_partion) {
					for (view_num = 0; view_num < view_entry_list->cnt; view_num ++) {
						stmfRemoveViewEntry(&lu_guid,
						     view_entry_list->ve[view_num].veIndex);
						proxy_remove_view_entry = malloc(sizeof(stmf_remove_proxy_view_t));
						bzero(proxy_remove_view_entry, sizeof(stmf_remove_proxy_view_t));
						proxy_remove_view_entry->head.op_type = STMF_OP_DELETE;
						proxy_remove_view_entry->head.item_type = STMF_VIEW_OP;
						bcopy(&lu_guid, &proxy_remove_view_entry->lu_guid, sizeof(stmfGuid));
						proxy_remove_view_entry->view_index = view_num;
						free(proxy_remove_view_entry);
					}
					stmfFreeMemory(view_entry_list);
				}
				
				ret = stmfOfflineLogicalUnit(&lu_guid);
				if (ret != STMF_STATUS_SUCCESS) {
					(void) stmfFreeLuResource(hdl);
					hdl = NULL;
					stmfFreeMemory(lu_list);
					syslog(LOG_ERR, "In Delete  lu progress, Offline Lun Fails ");
					return (1);
				}
				ret = stmfDeleteLu(&lu_guid);
				if (ret != STMF_STATUS_SUCCESS) {
					syslog(LOG_ERR, "Delete LU  Fails ");
					(void) stmfFreeLuResource(hdl);
					hdl = NULL;
					continue;
				}
				
				(void) stmfFreeLuResource(hdl);
				hdl = NULL;
				break;	
			}

			(void) stmfFreeLuResource(hdl);
			hdl = NULL;
			
		}
		stmfFreeMemory(lu_list);
	}


	return (0);
}


int 
zfs_destroy_lu_callback(zfs_handle_t *zhp, void *data)
{
	if (strcmp(zhp->zpool_hdl->zpool_name, (char *)data) == 0 &&
	   zfs_get_type(zhp) == ZFS_TYPE_VOLUME) {
		zfs_destroy_lu((char *)zfs_get_name(zhp));
	}
	return (0);
}

int 
zfs_destroy_pool_call_back(zfs_handle_t *zhp, void *data)
{
	zfs_iter_filesystems(zhp, zfs_destroy_lu_callback, data);
	return (0);
}
void 
zfs_destroy_all_lus(libzfs_handle_t *hdl, char *pool_name)
{
	zfs_iter_root(hdl, zfs_destroy_pool_call_back, (void *)pool_name);
}

#if 0
void
zfs_notify_export(libzfs_handle_t *hdl, char *poolname)
{
	zfs_cmd_t zc = {0};
	strncpy(zc.zc_name, poolname, sizeof(zc.zc_name));
	zc.zc_cookie = ZFS_HBX_POOL_EXPORT;
	zfs_ioctl(hdl, ZFS_IOC_HBX, &zc);
}
#endif

void
zfs_config_avs_ip(char *ip_owner, int enable)
{
	char *eth, *ip, *netmask;
	char cmd[512] = {0};
	char buf[1024] = {0};
	FILE *file;

	syslog(LOG_ERR, "%s %s %d", __func__, ip_owner, enable);

	eth = strtok(ip_owner, ",");
	ip = strtok(NULL, ",");
	netmask = strtok(NULL, ",");

	if (netmask == NULL)
		netmask = "255.255.255.0";

	if (enable)
		snprintf(cmd, sizeof(cmd), "%s %s plumb addif %s netmask %s up", 
			IFCONFIG_CMD, eth, ip, netmask);
	else
		snprintf(cmd, sizeof(cmd), "%s %s removeif %s", 
			IFCONFIG_CMD, eth, ip);

	file = popen(cmd, "r");

	if (file != NULL) {
		while (fgets(buf, sizeof(buf), file) != NULL) {
			if (buf[strlen(buf) - 1] == '\n')
				buf[strlen(buf) - 1] = '\0';
			syslog(LOG_ERR, "%s", buf);
		}
	} else {
		syslog(LOG_ERR, "%s popen %s failed", __func__, cmd);
	}
	
	pclose(file);
}

int zfs_enable_avs_iter_dataset(zfs_handle_t *zhp, void *data)
{
	zfs_avs_ctx_t *ctx = (zfs_avs_ctx_t *)data;

	if (zfs_get_type(zhp) == ZFS_TYPE_VOLUME) {
		nvlist_t *props, *nvl;
		zfs_cmd_t zc = {0};
		char *is_single_data;
#if 0
		nvpair_t *elem = NULL;
		elem_node_t *head, *tail, *curnode;
		char elems[256] = {0};
		int pos = 0;

		head = tail = NULL;
#endif
		strncpy(zc.zc_name, zfs_get_name(zhp), MAXPATHLEN);
		props = zfs_get_user_props(zhp);

		if (ctx->enabled) {

			/* single data, notify lun to become active */
			if (nvlist_lookup_nvlist(props, ZFS_SINGLE_DATA, &nvl) == 0) {
				nvlist_lookup_string(nvl, ZPROP_VALUE, &is_single_data);
				if (atoi(is_single_data)) {
					syslog(LOG_INFO, "%s %s is single data",
						__func__, zfs_get_name(zhp));
					stmfNotifyLuActive(zfs_get_name(zhp));
					goto iter_end;
				}
			}
		}

#if 0
		if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
			goto iter_end;

		nvlist_add_uint64(nvl, ZFS_RDC_NET_RDEV, ctx->dev_no);

		while ((elem = nvlist_next_nvpair(props, elem)) != NULL) {
			char *str, *data_lun, *bm_lun;
			char elem_name[256] = {0};
			char propname[512] = {0}; 
			int elem_id, is_primary;
			nvlist_t *propval;
			struct stat sb;

			str = nvpair_name(elem);
			if (strstr(str, ZFS_RDC_DESCRIPTION) == NULL)
				continue;

			strncpy(elem_name, str, strlen(str));

			if ((str = strchr(elem_name, ':')) == NULL) {
				syslog(LOG_WARNING, "%s elem %s error", 
					__func__, elem_name);
				continue;
			}
			
			*str = '\0';
			elem_id = atoi(elem_name);
			
			/* is primary */
			memset(propname, 0, sizeof(propname));
			snprintf(propname, sizeof(propname), "%d:%s", elem_id, ZFS_RDC_IS_PRIMARY);			
			nvlist_lookup_nvlist(props, propname, &propval);
			verify(nvlist_lookup_string(propval, ZPROP_VALUE, &str) == 0);
			is_primary = 
				(strncmp(str, ZFS_AVS_PRIMARY, strlen(ZFS_AVS_PRIMARY)) == 0) ? 1 : 0;
			
			/* data lun */
			data_lun = is_primary ? ZFS_RDC_SRC_DATA_LUN : ZFS_RDC_DST_DATA_LUN;
			memset(propname, 0, sizeof(propname));
			snprintf(propname, sizeof(propname), "%d:%s", elem_id, data_lun);			
			nvlist_lookup_nvlist(props, propname, &propval);
			verify(nvlist_lookup_string(propval, ZPROP_VALUE, &str) == 0);
			memset(&sb, 0, sizeof(sb));
			
			if (stat(str, &sb) < 0) {
				syslog(LOG_ERR, "%s: %s stat failed", 
					__func__, str);
				continue;
			}

			syslog(LOG_DEBUG, "%s %"PRIx64, str, sb.st_rdev);

			memset(propname, 0, sizeof(propname));
			snprintf(propname, sizeof(propname), "%d:%s", elem_id, ZFS_RDC_DATA_LUN_RDEV);
			nvlist_add_uint64(nvl, propname, sb.st_rdev);

			/* bitmap lun */
			bm_lun = is_primary ? ZFS_RDC_SRC_BM_LUN : ZFS_RDC_DST_BM_LUN;
			memset(propname, 0, sizeof(propname));
			snprintf(propname, sizeof(propname), "%d:%s", elem_id, bm_lun);			
			nvlist_lookup_nvlist(props, propname, &propval);
			verify(nvlist_lookup_string(propval, ZPROP_VALUE, &str) == 0);
			memset(&sb, 0, sizeof(sb));

			if (stat(str, &sb) < 0) {
				syslog(LOG_ERR, "%s: %s stat failed", 
					__func__, str);
				continue;
			}

			syslog(LOG_DEBUG, "%s %"PRIx64, str, sb.st_rdev);
			
			memset(propname, 0, sizeof(propname));
			snprintf(propname, sizeof(propname), "%d:%s", elem_id, ZFS_RDC_BM_LUN_RDEV);			
			nvlist_add_uint64(nvl, propname, sb.st_rdev);

			/* add to list */
			curnode = malloc(sizeof(elem_node_t));
			curnode->id = elem_id;
			curnode->next = NULL;

			if (tail) {
				tail->next = curnode;
				tail = curnode;
			} else {
				head = tail = curnode;
			}
		}

		if (head == NULL) {
			nvlist_free(nvl);
			goto iter_end;
		}

		for (curnode = head; curnode; curnode = curnode->next)
			pos += snprintf(elems + pos, sizeof(elems) - pos, "%d,", curnode->id);
		
		nvlist_add_string(nvl, ZFS_RDC_AVS_ELEMS, elems);
		zcmd_write_conf_nvlist(zhp->zfs_hdl, &zc, nvl);

		if (ctx->enabled) {			
			if (zfs_ioctl(zhp->zfs_hdl, ZFS_IOC_ENABLE_LU_AVS, &zc) != 0)
				syslog(LOG_ERR, "%s: zfs_name %s enable avs failed\n", 
					__func__, zfs_get_name(zhp));
		} else {
			if (zfs_ioctl(zhp->zfs_hdl, ZFS_IOC_DISABLE_LU_AVS, &zc) != 0)
				syslog(LOG_ERR, "%s: zfs_name %s disable avs failed\n", 
					__func__, zfs_get_name(zhp));
		}

		nvlist_free(nvl);
		
		while (head) {
			curnode = head;
			head = curnode->next;
			free(curnode);
		}
#endif
	}

iter_end:
	zfs_close(zhp);
	return (0);
}

int 
zfs_enable_avs_iter_pool(zfs_handle_t *zhp, void *data)
{
	zfs_avs_ctx_t *ctx = (zfs_avs_ctx_t *)data;
	syslog(LOG_DEBUG, "%s: zfs_name:%s", __func__, zfs_get_name(zhp));
	if (strcmp(zfs_get_name(zhp), ctx->pool_name) == 0) {
		nvlist_t *props, *propval;
		char *ip_owner;
		boolean_t b_config_ip = B_FALSE;

		props = zfs_get_user_props(zhp);
		if (nvlist_lookup_nvlist(props, ZFS_RDC_IP_OWNER, &propval) == 0) {
			verify(nvlist_lookup_string(propval, ZPROP_VALUE, &ip_owner) == 0);
			syslog(LOG_ERR, "%s: %s, %s", __func__, zfs_get_name(zhp),
				ip_owner);
			b_config_ip = B_TRUE;
		}
		
		if (ctx->enabled) {
			if (b_config_ip)
				zfs_config_avs_ip(ip_owner, ctx->enabled);
			
			zfs_iter_filesystems(zhp, zfs_enable_avs_iter_dataset, data);
		} else {
			zfs_iter_filesystems(zhp, zfs_enable_avs_iter_dataset, data);

			if (b_config_ip)
				zfs_config_avs_ip(ip_owner, ctx->enabled);
		}
	}
	zfs_close(zhp);
	return (0);
}

void 
zfs_enable_avs(libzfs_handle_t *hdl, char *data, int enabled)
{
	zfs_avs_ctx_t ctx;
	struct stat sb;	
	
	ctx.pool_name = data;
	ctx.enabled = enabled;
	
#if 0
	if (enabled) {
		if (stat(NETCONFIG_FILE, &sb) < 0) {
			syslog(LOG_ERR, "%s can't find device %s for transport\n", 
				__func__, NETCONFIG_FILE);
			return;
		}

		ctx.dev_no = sb.st_rdev;
		syslog(LOG_NOTICE, "%s dev_no = 0x%"PRIx64, __func__, ctx.dev_no);
	} else {
		/* notify pool is ready to exported */
		zfs_notify_export(hdl, data);
	}
#endif	
	zfs_iter_root(hdl, zfs_enable_avs_iter_pool, (void *)&ctx);
}

#define MAX_POOl_NUM    1024
typedef struct check_pool_thinlun_data {
        uint64_t        index;
		pool_thinluns_stat_t *thinluns_stat;
}check_pool_thinlun_data_t;

static int
zfs_check_thinlun(zfs_handle_t *zhp, void *data)
{
        uint64_t reserver_size;
	pool_thinluns_stat_t *stat = (pool_thinluns_stat_t *)data;
	reserver_size = zfs_prop_get_int(zhp, ZFS_PROP_REFRESERVATION);

        if (strcmp(zhp->zpool_hdl->zpool_name, (char *)stat->pool_name) == 0 &&
                reserver_size == 0) {
                        char used[12];
                        uint64_t thin_size = zfs_prop_get_int(zhp, ZFS_PROP_USED);
                        zfs_nicenum(thin_size, used, sizeof(used));
                        stat->pool_thinlun_size += thin_size;
        }
		zfs_close(zhp);
        return (0);
}

int zfs_check_thinluns_call_back(zfs_handle_t *zhp, void *data)
{
	int ret;
	ret = zfs_iter_filesystems(zhp, zfs_check_thinlun, data);
	zfs_close(zhp);
	return (ret);
}

int zpool_check_thinluns(libzfs_handle_t *hdl, void *data)
{
	int ret;
	ret = zfs_iter_root(hdl, zfs_check_thinluns_call_back, data);

	return (ret);
}

static int
zfs_check_pools_thinlun(zpool_handle_t *zhp, void *data)
{
    char used[12];
    pool_thinluns_stat_t thin_stat;
    pool_thinluns_stat_t *tmp_statp;
	check_pool_thinlun_data_t *cbdata;

    cbdata = (check_pool_thinlun_data_t *)data;

    bzero(&thin_stat, sizeof(pool_thinluns_stat_t));
    strcpy(thin_stat.pool_name, zpool_get_name(zhp));
    thin_stat.pool_size = zpool_get_prop_int(zhp, ZPOOL_PROP_SIZE, NULL);

    zpool_check_thinluns(zpool_get_handle(zhp),&thin_stat); 
    zfs_nicenum(thin_stat.pool_thinlun_size, used, sizeof(used));
    if (thin_stat.pool_size < (thin_stat.pool_thinlun_size * 2)) {
            tmp_statp = &cbdata->thinluns_stat[cbdata->index];
            bcopy(&thin_stat, tmp_statp, sizeof(pool_thinluns_stat_t));
            cbdata->index ++;
    }
        
	zpool_close(zhp);
	return (0);
}




void zpool_check_thin_luns(zfs_thinluns_t **statpp)
{
        int number;
        size_t size;
        libzfs_handle_t *tmp_gzfs;
        check_pool_thinlun_data_t *cbdata;
        zfs_thinluns_t *luns_stat;
        
        tmp_gzfs = libzfs_init();
        cbdata  = calloc(1, sizeof(check_pool_thinlun_data_t));
        bzero(cbdata, sizeof(check_pool_thinlun_data_t));
        cbdata->thinluns_stat = calloc(MAX_POOl_NUM, sizeof(pool_thinluns_stat_t));

        (void) zpool_iter(tmp_gzfs, zfs_check_pools_thinlun, cbdata);

        number = cbdata->index;

        if (number > 0) {
                luns_stat = calloc(1, sizeof(zfs_thinluns_t));
                luns_stat->pools = calloc(number, sizeof(pool_thinluns_stat_t));
                luns_stat->pool_number = number;
                bcopy(cbdata->thinluns_stat, luns_stat->pools,
                  sizeof(pool_thinluns_stat_t)*number);
                *statpp = luns_stat;
                
        }else {
                *statpp = NULL;
        }

        free(cbdata->thinluns_stat);
        free(cbdata);

        libzfs_fini(tmp_gzfs);
}

