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
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <libzfs.h>
#include <libzfs_core.h>
#include <libstmf.h>
#include <libzfs_rpc.h>
#include <sys/zfs_znode.h>

#include "libzfs_impl.h"
#include "zfs_prop.h"
#include "zfeature_common.h"
#include <dirent.h>

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


typedef struct path_dir_node{
	struct path_dir_node *next;
	char *dir_path;
} path_dir_node_t;

typedef struct path_dir {
	struct path_dir_node *head;
	struct path_dir_node *tail;
} path_dir_t;

#define	rm_files_thread_num  32

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
	    !zfs_prop_userquota(propname) && !zfs_prop_dirquota(propname) &&
	    !zfs_prop_written(propname) && !zfs_prop_dirlowdata(propname)))) {
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
    zfs_cmd_t zc = {"\0"};

#if defined(__sw_64)
	if (flags == ENABLE_MIRROR || flags == DISABLE_MIRROR) {
#else
    if (flags == ENABLE_MIRROR) {
#endif
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
	zfs_cmd_t zc = {"\0"};

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
	zfs_cmd_t zc = {"\0"};
	
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

int zfs_cluster_socket_do (libzfs_handle_t *hdl,
	char *hostname, uint32_t hostid, char *ip,
	int pri, int port)
{
    zfs_cmd_t zc = {"\0"};
    int err;

    zc.zc_cookie = ZFS_CLUSTERSAN_IOC_SOCKET;
    strcpy(zc.zc_value, hostname);
    strcpy(zc.zc_string, ip);
    zc.zc_guid = hostid;
    zc.zc_obj = pri;
    zc.zc_history_offset = port;
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
		flags == ZFS_HBX_CLUSTER_IMPORT ||
		flags == ZFS_HBX_MAC_STAT) {
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
	gethostname(buf, len);
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
	/*int tp_size;*/
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
	bzero(zc, sizeof(zfs_cmd_t));
	assert(zc->zc_nvlist_src_size == 0);
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
	/*int stmf_proxy_door_fd;*/
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
	/*boolean_t b_destroy_partner = B_TRUE;*/
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
		zfs_cmd_t zc = {"\0"};
		char *is_single_data;

		memset(&zc, '\0', sizeof(zfs_cmd_t));
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
	/*struct stat sb;*/
	
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

void zfs_print_separator(char septor, int cnt)
{
	int i;
	for(i=0; i<cnt; i++)
	{
		printf("%c", septor);
	}
	printf("\r\n");
}

int multiclus_info_print(libzfs_handle_t *hdl, zfs_cmd_t *zc,uint64_t flags)
{
	int err = 0;
	zfs_group_info_t (*gs)[32] = {0};
	zfs_group_info_t *ptr = NULL;
	char *gname = NULL;
	uint_t cnt = 0;
	uint_t gmcnt = 0;
	uint64_t gnum = 0;
	uint64_t *gmaster = NULL;
	int space_num = 0;
	nvlist_t *config = NULL;
	char gmas[16] = {0};
	char gnums[16] = {0};
	char spa_id[32] = {0};
	char gnode_id[16] = {0};
	char avail_size[32] = {0};
	char used_size[32] = {0};
	char load_ios[16] = {0};
	char *node_status[3] 
		= {"offline","checking","online"};
	int i = 0;
	int index = 0;
	xmlDocPtr gdoc;
	xmlNodePtr root_node;
	xmlNodePtr group_node;
	xmlNodePtr fs_node;				
	xmlChar *xmlbuff;
	int buffersize;
	uint64_t xmlfirst = 0;
	
	do{
		if (zcmd_alloc_dst_nvlist(hdl, zc, 0) != 0){
			printf("zcmd_alloc_dst_nvlist: NULL\r\n");
			return -1;
		}

		err = ioctl(hdl->libzfs_fd, ZFS_IOC_START_MULTICLUS, zc);
		if(err){
			switch(flags)
			{
				case SHOW_MULTICLUS:
					printf("Fail to show multiclus info, %d\n", err);
					break;
				case XML_MULTICLUS:
					printf("Fail to show multiclus xml info, %d\n", err);
					break;
				default:
					printf("Fail to get multiclus info, Type invalid\n");
			}
			zcmd_free_nvlists(zc);
		}else if(strcmp(zc->zc_string, "down")){
			if(zcmd_read_dst_nvlist(hdl, zc, &config) != 0){
				zcmd_free_nvlists(zc);
				return -1;
			}
		
			zcmd_free_nvlists(zc);
			/* nvlist_print(stdout, config); */
			verify(nvlist_lookup_string(config, 
				ZPOOL_CONFIG_MULTICLUS_GNAME, &gname) == 0);
			verify(nvlist_lookup_uint64_array(config,
				ZPOOL_CONFIG_MULTICLUS_MASTER, (uint64_t **)&gmaster, &gmcnt) == 0);
			verify(nvlist_lookup_uint64(config,
				ZPOOL_CONFIG_MULTICLUS_GNUM, &gnum) == 0);
			verify(nvlist_lookup_uint64_array(config, 
				ZPOOL_CONFIG_MULTICLUS,	(uint64_t **)&gs, &cnt) == 0);
			if(SHOW_MULTICLUS == flags){
				printf("Group Info:\r\n" );
				zfs_print_separator('=', 43);
				space_num = 41 - strlen("| Multiclus status | up ");
				printf("| Multiclus status | up %*s |\r\n", space_num, "");
				space_num = 20 - strlen(gname) ;
				printf("| Group name       | %s%*s |\r\n", gname, space_num, "" );
				sprintf(gmas, "%"PRIu64"", gmaster[0]);
				space_num = 20 - strlen(gmas);
				printf("| Master node id   | %s%*s |\r\n", gmas, space_num, "");
				memset(gmas, 0, 16);
				sprintf(gmas, "%"PRIu64"", gmaster[1]);
				space_num = 20 - strlen(gmas);
				printf("| Master2 node id  | %s%*s |\r\n", gmas, space_num, "");
				memset(gmas, 0, 16);
				sprintf(gmas, "%"PRIu64"", gmaster[2]);
				space_num = 20 - strlen(gmas);
				printf("| Master3 node id  | %s%*s |\r\n", gmas, space_num, "");
				memset(gmas, 0, 16);
				sprintf(gmas, "%"PRIu64"", gmaster[3]);
				space_num = 20 - strlen(gmas);
				printf("| Master4 node id  | %s%*s |\r\n", gmas, space_num, "");
				memset(gmas, 0, 16);
				sprintf(gnums, "%"PRIu64"", gnum);
				space_num = 20 - strlen(gnums);
				printf("| Group number     | %s%*s |\r\n", gnums, space_num, "");
				zfs_print_separator('=', 43);
				
				ptr = gs[0];
				/* printf("cnt : %d\r\n", cnt); */
				for(i=0; i<gnum; i++){
					space_num = 20 - strlen(ptr->gi_fsname);
					printf("| Fs name          | %s%*s |\r\n", ptr->gi_fsname, 
					space_num, "");
					ptr->node_type[MAX_FSNAME_LEN - 1] = 0;
					space_num = 20 - strlen(ptr->node_type);
					printf("| Node type        | %s%*s |\r\n", ptr->node_type, space_num, "");
					sprintf(spa_id, "%"PRIx64"", ptr->spa_id);
					space_num = 20 - strlen(spa_id);
					printf("| Spa id           | %s%*s |\r\n", spa_id, space_num, "");
					sprintf(gnode_id, "%"PRIu64"", ptr->gnode_id);
					space_num = 20 - strlen(gnode_id);
					printf("| Node id          | %s%*s |\r\n", gnode_id, space_num, "");
					nicenum(ptr->avail_size, avail_size);
					/* sprintf(avail_size, "%llx", ptr->avail_size); */
					space_num = 20 - strlen(avail_size);
					printf("| Avail size       | %s%*s |\r\n", avail_size, space_num, "");
					nicenum(ptr->used_size, used_size);
					/* sprintf(used_size, "%llx", ptr->used_size); */
					space_num = 20 - strlen(used_size);
					printf("| Used size        | %s%*s |\r\n", used_size, space_num, "");
					sprintf(load_ios, "%"PRIu64"", ptr->load_ios);
					space_num = 20 - strlen(load_ios);
					printf("| Load ios         | %s%*s |\r\n", load_ios, space_num, "");
					index = ptr->node_status;
					space_num = 20 - strlen(node_status[index]);
					printf("| Status           | %s%*s |\r\n", 
					node_status[index], space_num, "");
					ptr++;
					if(i<gnum-1){
						zfs_print_separator('-', 43);
					}
				}
				zfs_print_separator('=', 43);
				zfs_print_separator(' ', 43);
			}
			else{
				/* Create XML file */
				if(!xmlfirst){
					gdoc = xmlNewDoc((xmlChar *)"1.0");
					root_node = xmlNewNode(NULL, (xmlChar *)"multiclus");
					xmlDocSetRootElement(gdoc, root_node);
					xmlfirst = 1;
				}
				
				group_node = xmlNewChild(root_node, NULL, (xmlChar *)"group", NULL);
				xmlSetProp(group_node, (xmlChar *)"mcstate", (xmlChar *)"up");
				xmlSetProp(group_node, (xmlChar *)"gname", (xmlChar *)gname);
				sprintf(gmas, "%"PRIu64"", gmaster[0]);
				xmlSetProp(group_node, (xmlChar *)"mhostid", (xmlChar *)gmas);
				sprintf(gmas, "%"PRIu64"", gmaster[1]);
				xmlSetProp(group_node, (xmlChar *)"m2_hostid", (xmlChar *)gmas);
				sprintf(gmas, "%"PRIu64"", gmaster[2]);
				xmlSetProp(group_node, (xmlChar *)"m3_hostid", 
					(xmlChar *)gmas);
				sprintf(gmas, "%"PRIu64"", gmaster[3]);
				xmlSetProp(group_node, (xmlChar *)"m4_hostid", 
					(xmlChar *)gmas);
				sprintf(gnums, "%"PRIu64"", gnum);
				xmlSetProp(group_node, (xmlChar *)"gnum", (xmlChar *)gnums);
				
				ptr = gs[0];
				/* printf("cnt : %d\r\n", cnt); */
				for(i=0; i<gnum; i++){
					fs_node = xmlNewChild(group_node, NULL, (xmlChar *)"fsstats", NULL);
					xmlSetProp(fs_node, (xmlChar *)"fsname", (xmlChar *)ptr->gi_fsname);
					ptr->node_type[MAX_FSNAME_LEN - 1] = 0;
					xmlSetProp(fs_node, (xmlChar *)"desc", (xmlChar *)ptr->node_type);
					sprintf(gnode_id, "%"PRIu64"", ptr->gnode_id);
					xmlSetProp(fs_node, (xmlChar *)"fshostid", (xmlChar *)gnode_id);
					nicenum(ptr->avail_size, avail_size);
					/* sprintf(avail_size, "%llx", ptr->avail_size); */
					xmlSetProp(fs_node, (xmlChar *)"fsavailsize", (xmlChar *)avail_size);
					nicenum(ptr->used_size, used_size);
					/* sprintf(used_size, "%llx", ptr->used_size); */
					xmlSetProp(fs_node, (xmlChar *)"fsusedsize", (xmlChar *)used_size);
					sprintf(load_ios, "%"PRIu64"", ptr->load_ios);
					xmlSetProp(fs_node, (xmlChar *)"fsloadios", (xmlChar *)load_ios);
					index = ptr->node_status;
					xmlSetProp(fs_node, (xmlChar *)"fsstatus", (xmlChar *)node_status[index]);
					ptr++;
				}
				
				if(zc->zc_multiclus_group == 0){
					xmlDocDumpFormatMemory(gdoc, &xmlbuff, &buffersize, 1);
					
					xmlSaveFormatFileEnc("/tmp/multiclus.xml", gdoc, "UTF-8", 1);
					xmlFreeDoc(gdoc);
				}
			}
			nvlist_free(config);
		}
		else{
			if(SHOW_MULTICLUS == flags){
				printf("Multiclus_state: down\r\n");
			}
			else{
				/* Create XML file */
				gdoc = xmlNewDoc((xmlChar *)"1.0");
				root_node = xmlNewNode(NULL, (xmlChar *)"multiclus");
				xmlDocSetRootElement(gdoc, root_node);
				group_node = xmlNewChild(root_node, NULL, (xmlChar *)"group", NULL);
				xmlSetProp(group_node, (xmlChar *)"mcstate", (xmlChar *)"down");
				xmlDocDumpFormatMemory(gdoc, &xmlbuff, &buffersize, 1);
				
				xmlSaveFormatFileEnc("/tmp/multiclus.xml", gdoc, "UTF-8", 1);
				xmlFreeDoc(gdoc);
			}
			zcmd_free_nvlists(zc);
			
		}

	}while(zc->zc_multiclus_group > 0);
	
	return (err);
}


int multiclus_get_znodeinfo(libzfs_handle_t *hdl, zfs_cmd_t *zc)
{
	int err = 0;
	nvlist_t *config = NULL;
	uint_t cnt = 0;
	zfs_group_object_t *zp_info = NULL;
	char *filename = NULL;
	
	if (zcmd_alloc_dst_nvlist(hdl, zc, 0) != 0){
		printf("zcmd_alloc_dst_nvlist: NULL\n");
		return -1;
	}

	err = ioctl(hdl->libzfs_fd, ZFS_IOC_START_MULTICLUS, zc);
	if(err){
		printf("Fail to show multiclus info, %d\n", err);
		zcmd_free_nvlists(zc);
	}else if(strcmp(zc->zc_string, "up") == 0){
		if(zcmd_read_dst_nvlist(hdl, zc, &config) != 0){
			zcmd_free_nvlists(zc);
			return -1;
		}
	
		zcmd_free_nvlists(zc);
		/* nvlist_print(stdout, config); */
		verify(nvlist_lookup_uint64_array(config, 
			ZPOOL_CONFIG_MULTICLUS_ZNODEINFO,	(uint64_t **)&zp_info, &cnt) == 0);
		verify(nvlist_lookup_string(config, ZPOOL_CONFIG_MULTICLUS_ZFILENAME, &filename) == 0);
		
		printf("\tPath: %s\n", zc->zc_top_ds);
		printf("\tz_filename: %s\n", filename);
		printf("\tMaster\tspa: %"PRIx64"\tos: %"PRIx64"\tobj: %"PRIx64"\n", zp_info->master_spa, zp_info->master_objset, zp_info->master_object);
		printf("\tMaster2\tspa: %"PRIx64"\tos: %"PRIx64"\tobj: %"PRIx64"\n", zp_info->master2_spa, zp_info->master2_objset, zp_info->master2_object);
		printf("\tMaster3\tspa: %"PRIx64"\tos: %"PRIx64"\tobj: %"PRIx64"\n", zp_info->master3_spa, zp_info->master3_objset, zp_info->master3_object);
		printf("\tMaster4\tspa: %"PRIx64"\tos: %"PRIx64"\tobj: %"PRIx64"\n", zp_info->master4_spa, zp_info->master4_objset, zp_info->master4_object);
		printf("\tData\tspa: %"PRIx64"\tos: %"PRIx64"\tobj: %"PRIx64"\n", zp_info->data_spa, zp_info->data_objset, zp_info->data_object);
		printf("\tData2\tspa: %"PRIx64"\tos: %"PRIx64"\tobj: %"PRIx64"\n", zp_info->data2_spa, zp_info->data2_objset, zp_info->data2_object);
		nvlist_free(config);
	}else if (strcmp(zc->zc_string, "down") == 0) {
		printf("Multiclus_state: down\n");
		zcmd_free_nvlists(zc);
	} else {
		printf("Input is invalid.\n");
		zcmd_free_nvlists(zc);
	}
	return (err);
}


void zfs_start_multiclus(libzfs_handle_t *hdl, char *group_name,
    char *fs_name, uint64_t flags, void* param) 
{
	int err,ret;
	unsigned long interval = 0;
	zfs_cmd_t zc;
	char buf[RPC_SEND_RECV_SIZE] = {0};
	char dtl_buf[6][32] = {0};

	memset(&zc, '\0', sizeof(zfs_cmd_t));
	if (flags == ENABLE_MULTICLUS) {
		//printf("ENABLE_MULTICAST\r\n");
	} else if(flags == DISABLE_MULTICLUS) {
		//printf("DISABLE_MULTICAST\r\n");
	} else if (flags == SHOW_MULTICLUS) {
		//printf("SHOW_MULTICLUS\r\n");
	}
 	else if(flags == XML_MULTICLUS) {
		//printf("XML_MULTICLUS\r\n");
	} else if(flags == ZFS_RPC_CALL_SERVER) {
		//printf("ZFS_RPC_CALL_SERVER\r\n");
		zfs_rpc_server();
	} else if(flags == ZFS_RPC_CALL_TEST) {
		ret = zfs_rpc_msg_send(hdl, ZFS_RPC_DISK_TEST, (char*)buf);
		if(ret){
			printf("%s: Fail to call remote server!!!\n", __func__);
		}else {
			printf("%s: the remote info: %s\n", __func__, buf);
		}
		return;
	} 
	else if (flags == SYNC_MULTICLUS_GROUP) {
		zfs_grp_sync_param_t* sync_param = (zfs_grp_sync_param_t*)param;

		if (group_name != NULL) {
			strncpy(zc.zc_value, group_name, MAXPATHLEN * 2);
		}
		if (fs_name != NULL) {
			strncpy(zc.zc_string, fs_name, MAXNAMELEN);
		}

		/* reuse 'zc_multiclus_pad' to hold sync/check flag */
		zc.zc_multiclus_pad[0] = sync_param->check_only ? 1 : 0;
		zc.zc_multiclus_pad[1] = sync_param->stop_sync ? 1 : 0;

		strncpy(zc.zc_output_file, sync_param->output_file, MAXPATHLEN);

		/* reuse 'zc_top_ds' to hold target dir */
		if (sync_param->target_dir != NULL) {
			strncpy(zc.zc_top_ds, sync_param->target_dir, MAXPATHLEN);
		} else {
			zc.zc_top_ds[0] = 0; /* root dir of the zfs filesystem */
		}
	} 
	else if (flags == SYNC_MULTICLUS_GROUP_DATA) {
		zfs_grp_sync_param_t* sync_param = (zfs_grp_sync_param_t*)param;

		if (group_name != NULL) {
			strncpy(zc.zc_value, group_name, MAXPATHLEN * 2);
		}
		if (fs_name != NULL) {
			strncpy(zc.zc_string, fs_name, MAXNAMELEN);
		}

		/* reuse 'zc_multiclus_pad' to hold sync/check flag */
		zc.zc_multiclus_pad[0] = sync_param->check_only ? 1 : 0;
		zc.zc_multiclus_pad[1] = sync_param->stop_sync ? 1 : 0;
		zc.zc_multiclus_pad[2] = sync_param->all_member_online ? 1 : 0;

		strncpy(zc.zc_output_file, sync_param->output_file, MAXPATHLEN);

		/* reuse 'zc_top_ds' to hold target dir */
		if (sync_param->target_dir != NULL) {
			strncpy(zc.zc_top_ds, sync_param->target_dir, MAXPATHLEN);
		} else {
			zc.zc_top_ds[0] = 0; /* root dir of the zfs filesystem */
		}
	} else if (flags == ZNODE_INFO) {
		zfs_grp_sync_param_t* sync_param = (zfs_grp_sync_param_t*)param;
		strncpy(zc.zc_top_ds, sync_param->target_dir, MAXPATHLEN);
	} else if (flags == SET_DOUBLE_DATA) {
		strncpy(zc.zc_value, group_name, MAXPATHLEN * 2);
	}
	else {
		if (group_name) {
			//printf("group_name:%s\r\n", group_name);
			strncpy(zc.zc_value, group_name, MAXPATHLEN * 2);
		}
		if (fs_name) {
			//printf("fs_name:%s\r\n", fs_name);
			strncpy(zc.zc_string, fs_name, MAXNAMELEN);
		}
	}

	zc.zc_cookie = flags;	

	if ( SHOW_MULTICLUS == flags|| XML_MULTICLUS == flags)	{
		err = multiclus_info_print(hdl, &zc, flags);
	} else if(ZNODE_INFO == flags) {
		err = multiclus_get_znodeinfo(hdl, &zc);
	} else if(GET_MULTICLUS_DTLSTATUS == flags){
		if (group_name && isdigit(group_name[0])) {
			char *end;
			interval = strtoul(group_name, &end, 10);
			if (*end == '\0' ) {
				if (interval == 0) {
					(void) fprintf(stderr, gettext("interval "
					    "cannot be zero\n"));
				}
			} 
		}
		do{
			zc.zc_cookie = flags;
			zc.zc_nvlist_conf_size = 0;
			zc.zc_nvlist_dst_size = 0;
			zc.zc_nvlist_src_size = 0;
			zc.zc_nvlist_conf = 0;
			zc.zc_nvlist_dst = 0;
			zc.zc_nvlist_src = 0;
			err = ioctl(hdl->libzfs_fd, ZFS_IOC_START_MULTICLUS, &zc);
			if(err){
				if(ENOENT == zc.zc_cookie){
					printf("[Error]: Invalid fs name %"PRIu64"\n", zc.zc_cookie);
				}else{
					printf("Fail to get dtlstatus: %d\n", err);
				}
				interval = 0;
			}else{
				memset(dtl_buf[0], 0, 32);
				memset(dtl_buf[1], 0, 32);
				memset(dtl_buf[2], 0, 32);
				memset(dtl_buf[3], 0, 32);
				memset(dtl_buf[4], 0, 32);
				memset(dtl_buf[5], 0, 32);
				sprintf(dtl_buf[0], "%"PRIu64"", zc.zc_nvlist_conf_size);
				sprintf(dtl_buf[1], "%"PRIu64"", zc.zc_nvlist_dst_size);
				sprintf(dtl_buf[2], "%"PRIu64"", zc.zc_nvlist_src_size);
				sprintf(dtl_buf[3], "%"PRIu64"", zc.zc_nvlist_conf);
				sprintf(dtl_buf[4], "%"PRIu64"", zc.zc_nvlist_dst);
				sprintf(dtl_buf[5], "%"PRIu64"", zc.zc_nvlist_src);
				printf("===================================================================\n");
				printf("|-------master2-------------master3-------------master4-----------|\n");
				printf("|      %s/%s %*s%s/%s %*s%s/%s%*s|\n", dtl_buf[0], dtl_buf[3],19-strlen(dtl_buf[0])-1-strlen(dtl_buf[3]), "", 
					dtl_buf[1], dtl_buf[4], 19-strlen(dtl_buf[1])-1-strlen(dtl_buf[4]), "", dtl_buf[2], dtl_buf[5],	
					19-strlen(dtl_buf[2])-1-strlen(dtl_buf[5]), "");
				printf("-------------------------------------------------------------------\n");
				(void) sleep(interval);
			}
		}while(interval);
	}else{
		err = ioctl(hdl->libzfs_fd, ZFS_IOC_START_MULTICLUS, &zc);
		if(err){
			switch(flags)
			{
				case ENABLE_MULTICLUS:
					printf("Fail to enable multiclus, %d\n", err);
					break;
				case DISABLE_MULTICLUS:
					printf("Fail to disable multiclus, %d\n", err);
					break;
				case ZFS_RPC_CALL_SERVER:
					printf("Fail to call multiclus rpc server, %d\n", err);
					break;
				case ZFS_RPC_CALL_TEST:
					printf("Fail to call multiclus rpc test, :%d\n", err);
					break;
				case CREATE_MULTICLUS:
					printf("Fail to create multiclus, %d\n", err);
					break;
				case ADD_MULTICLUS:
					printf("Fail to add multiclus: %d\n", err);
					break;
				case SET_MULTICLUS_SLAVE:
					printf("Fail to set multiclus slave, %d\n", err);
					break;
				case SET_MULTICLUS_MASTER4:
					printf("Fail to set multiclus master4, %d\n", err);
					break;
				case SET_MULTICLUS_MASTER3:
					printf("Fail to set multiclus master3, %d\n", err);
					break;
				case SET_MULTICLUS_MASTER2:
					printf("Fail to set multiclus master2, %d\n", err);
					break;
				case SET_MULTICLUS_MASTER:
					printf("Fail to set multiclus master, %d\n", err);
					break;
				case CLEAN_MULTICLUS_DTLTREE:
					printf("Fail to clean multiclus dtltree, %d\n", err);
					break;
				case SYNC_MULTICLUS_GROUP:
					printf("Fail to sync/check multiclus group, %d\n", err);
					break;
				case SYNC_MULTICLUS_GROUP_DATA:
					printf("Fail to sync_data/check_data multiclus group, %d\n", err);
					break;
				default:
					printf("Fail to set multiclus, Type invalid\n");
					break;
			}
		} else {
			if (flags == SET_DOUBLE_DATA) {
				char cmd[256] = {0};
				if (zc.zc_sendobj) {
					sprintf(cmd, "cp /usr/sbin/cluster_init.sh /tmp/cluster_init.sh");
					system(cmd);
					memset(cmd, 0, 256);
					sprintf(cmd, "sed '/zfs multiclus set*/d' /tmp/cluster_init.sh > /usr/sbin/cluster_init.sh");
					system(cmd);
					memset(cmd, 0, 256);
					sprintf(cmd, "echo '/usr/local/sbin/zfs multiclus set double_data on' >> /usr/sbin/cluster_init.sh");
					system(cmd);
					printf("DOUBLE_DATA ON.\n");
				} else {
					sprintf(cmd, "cp /usr/sbin/cluster_init.sh /tmp/cluster_init.sh");
					system(cmd);
					memset(cmd, 0, 256);
					sprintf(cmd, "sed '/zfs multiclus set*/d' /tmp/cluster_init.sh > /usr/sbin/cluster_init.sh");
					system(cmd);
					memset(cmd, 0, 256);
					sprintf(cmd, "echo '/usr/local/sbin/zfs multiclus set double_data off' >> /usr/sbin/cluster_init.sh");
					system(cmd);
					printf("DOUBLE_DATA OFF.\n");
				}
			}else if (flags == GET_DOUBLE_DATA) {
				if (zc.zc_sendobj)
					printf("DOUBLE_DATA ON.\n");
				else
					printf("DOUBLE_DATA OFF.\n");
			}
		}
	}
	
}

void zfs_migrate(libzfs_handle_t *hdl, char *fs_name, uint64_t flags, uint64_t obj)
{
	int err = 0;
	zfs_cmd_t zc = { 0 };

	strcpy(zc.zc_value, fs_name);
	zc.zc_cookie = flags;
	zc.zc_obj = obj;

	err = ioctl(hdl->libzfs_fd, ZFS_IOC_DO_MIGRATE, &zc);
	if (err) {
		printf("zfs migrate failed!\n");
	}

	if (flags == STATUS_MIGRATE) {
		char migrated_buf[64],	to_migrate_buf[64];
		zfs_nicenum(zc.zc_multiclus_group, to_migrate_buf, sizeof (migrated_buf));
		zfs_nicenum(zc.zc_multiclus_break, migrated_buf, sizeof (to_migrate_buf));
		printf("fsname: %s\n", fs_name);
		printf("migrate state: %s\n", zc.zc_string);
		printf("total to migrate: %s\n", to_migrate_buf);
		printf("total migrated: %s\n", migrated_buf);
	}
}

int
get_rpc_addr(libzfs_handle_t *hdl, uint64_t flags, 
	char *groupip, uint_t *num )
{
	int err = 0;
	zfs_cmd_t zc;
	nvlist_t *config = NULL;
	char **ipaddr = NULL;
	int ii = 0;
	char *iptr = NULL;

	memset(&zc, '\0', sizeof(zfs_cmd_t));
	zc.zc_cookie = flags;
	if(GET_MASTER_IPFS == flags){
		strcpy(zc.zc_name, groupip);
	}
	if (zcmd_alloc_dst_nvlist(hdl, &zc, 0) != 0){
		printf("zcmd_alloc_dst_nvlist: NULL\n");
		return (-1);
	}
	err = ioctl(hdl->libzfs_fd, ZFS_IOC_GET_RPC_INFO, &zc);

	if(err){
		zcmd_free_nvlists(&zc);
		return (zc.zc_cookie);
	}
	
	if(zcmd_read_dst_nvlist(hdl, &zc, &config) != 0){
		printf("cookie is: %"PRIu64"\n", zc.zc_cookie);
		zcmd_free_nvlists(&zc);
		return (-2);
	}
	zcmd_free_nvlists(&zc);
	/* nvlist_print(stdout, config); */
	if(GET_GROUP_IP == flags){
		verify(nvlist_lookup_string_array(config, ZFS_RPC_GROUP_IP,
		    &ipaddr, num) == 0);
		iptr = groupip;
		for(ii=0;ii<*num;ii++){
			strncpy(iptr, ipaddr[ii], MAX_FSNAME_LEN);
			iptr += MAX_FSNAME_LEN;
		}
	} else if(GET_MASTER_IPFS == flags) {
		memset(groupip, 0, 12*MAX_FSNAME_LEN);
		verify(nvlist_lookup_string_array(config, 
			ZFS_RPC_MASTER_IP, &ipaddr, num) == 0);
		iptr = groupip;
		for(ii=0;ii<(*num);ii++)
		{
			strncpy(iptr, ipaddr[ii], MAX_FSNAME_LEN);
			iptr += MAX_FSNAME_LEN;
		}
		verify(nvlist_lookup_string_array(config, 
			ZFS_RPC_MASTER_FS, &ipaddr, num) == 0);
		for(ii=0;ii<(*num);ii++)
		{
			strncpy(iptr, ipaddr[ii], MAX_FSNAME_LEN);
			iptr += MAX_FSNAME_LEN;
		}
		verify(nvlist_lookup_string_array(config, 
			ZFS_RPC_MASTER_TYPE, &ipaddr, num) == 0);
		for(ii=0;ii<(*num);ii++)
		{
			strncpy(iptr, ipaddr[ii], MAX_FSNAME_LEN);
			iptr += MAX_FSNAME_LEN;
		}
	}
	nvlist_free(config);

	return (0);
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

uint64_t rm_file_num = 0;
tpool_t *rm_files_threadpool = NULL;
path_dir_t child_dir_list;
pthread_mutex_t child_dir_list_lock;
boolean_t rm_done = B_FALSE;

typedef struct wait_rm_file_list
{
	char path[MAXPATHLEN];
	struct wait_rm_file_list *next;
}wait_rm_file_list_t;

struct rm_file_thread_info{
	int thread_id;
	int thread_busy_flag;
}rm_file_thread_info[rm_files_thread_num] = {0};

static void
zfs_rm_files_in_a_dir(int *thread_id)
{
	path_dir_node_t *dir_node;
	DIR *dirp = NULL;
	struct dirent64 *dp = NULL;
	int error;
	char dir[MAXNAMELEN] = {0};
	char path[MAXPATHLEN] = {0};
	int free_thread_num = 0;
	wait_rm_file_list_t *wait_rm_file_node;
	int i;
	
	while(!rm_done){
		pthread_mutex_lock(&child_dir_list_lock);
		if (child_dir_list.head == NULL){
			rm_file_thread_info[*thread_id].thread_busy_flag = 0;
			free_thread_num = 0;
			for (i = 0; i < rm_files_thread_num; i++){
				if (rm_file_thread_info[i].thread_busy_flag == 0){
					free_thread_num += 1;
				}
			}
			if (free_thread_num == rm_files_thread_num){
				rm_done = B_TRUE;
				pthread_mutex_unlock(&child_dir_list_lock);
				continue;
			}
			pthread_mutex_unlock(&child_dir_list_lock);
			usleep(200);
			continue;
		} else {
			rm_file_thread_info[*thread_id].thread_busy_flag = 1;
			
			dir_node = child_dir_list.head;
			if (child_dir_list.head == child_dir_list.tail) {
				child_dir_list.tail = NULL;
				child_dir_list.head = NULL;
			} else {
				child_dir_list.head = dir_node->next;
			}
			pthread_mutex_unlock(&child_dir_list_lock);
		}
		
		strcpy(dir, dir_node->dir_path);
		free(dir_node->dir_path);
		free(dir_node);

		wait_rm_file_node = NULL;
		if ((dirp = opendir(dir)) == NULL) {
			//syslog(LOG_ERR, "cann't open dir:%s", dir);
			error = remove(dir);
			if (error != 0) {
				syslog(LOG_ERR, "remove file %s err %d\n", dir, error);
				continue;
			}
			atomic_inc_64(&rm_file_num);	
			continue;
	    }
		
		while ((dp = readdir64(dirp)) != NULL) {
			char *name = dp->d_name;
			if (strcmp(name, ".") == 0 || 
					strcmp(name, "..") == 0)
				continue;
			
			bzero(path, MAXPATHLEN);
			(void) sprintf(path, "%s/%s", dir, name);
			if (NULL == strchr(name, '.') || NULL != strstr(name, ".dir")) {
				dir_node = malloc(sizeof(path_dir_node_t));
				dir_node->dir_path = (char*)malloc(strlen(path)+1);
				bzero(dir_node->dir_path, strlen(path)+1);
				strcpy(dir_node->dir_path, path);
				dir_node->next = NULL;

				pthread_mutex_lock(&child_dir_list_lock);
				if (child_dir_list.tail == NULL){
					child_dir_list.head = dir_node;
					child_dir_list.tail = dir_node;
				}else{
					child_dir_list.tail->next = dir_node;
					child_dir_list.tail = dir_node;
				}	
				pthread_mutex_unlock(&child_dir_list_lock);
			}else {
				wait_rm_file_list_t *tmp = (wait_rm_file_list_t*)malloc(sizeof(wait_rm_file_list_t));
				strcpy(tmp->path, path);
				tmp->next = wait_rm_file_node;
				wait_rm_file_node = tmp;
			}
		}
		(void) closedir(dirp);

		if (wait_rm_file_node) {
			do {
				wait_rm_file_list_t *tmp = wait_rm_file_node;
				wait_rm_file_node = wait_rm_file_node->next;
	
				error = remove(tmp->path);
				if (error != 0) {
					syslog(LOG_ERR, "remove file %s err %d\n", tmp->path, error);
				}	
				atomic_inc_64(&rm_file_num);
				free(tmp);
			} while(wait_rm_file_node);
		}
	}
}

int zfs_start_rm_file_in_dir(libzfs_handle_t *hdl, char *dir)
{
	path_dir_node_t *dir_node;
	DIR *dirp = NULL;
	int i;

	if ((dir == NULL) || (0 == strlen(dir))) {
		/* not found in df output */
		(void) printf("Error: fail to find dir %s.\n", dir);
		return (-1);
	}

	if ((dirp = opendir(dir)) == NULL) {
		(void) printf("Error: can't find dir %s.\n", dir);
		return (-1);
	}
	(void) closedir(dirp);
	
	rm_file_num = 0;
	rm_files_threadpool = tpool_create(1, rm_files_thread_num, 0, NULL);
	
	if (NULL == rm_files_threadpool)
		return -1;

	(void)pthread_mutex_init(&child_dir_list_lock, NULL);
	child_dir_list.head = NULL;
	child_dir_list.tail = NULL;
	
	dir_node = malloc(sizeof(path_dir_node_t));
	dir_node->dir_path = (char*)malloc(strlen(dir)+1);
	bzero(dir_node->dir_path, strlen(dir)+1);
	strcpy(dir_node->dir_path, dir);
	dir_node->next = NULL;

	pthread_mutex_lock(&child_dir_list_lock);
	child_dir_list.head = dir_node;
	child_dir_list.tail = dir_node;
	pthread_mutex_unlock(&child_dir_list_lock);
	
	for (i=0; i < rm_files_thread_num; i++){
		rm_file_thread_info[i].thread_id = i;
		tpool_dispatch(rm_files_threadpool, (void (*)(void *))zfs_rm_files_in_a_dir, (void*)&rm_file_thread_info[i].thread_id);
	}

	tpool_wait(rm_files_threadpool);
	tpool_destroy(rm_files_threadpool);
	rm_files_threadpool = NULL;
	(void)pthread_mutex_destroy(&child_dir_list_lock);

	printf("%"PRIu64" files have been deleted.\n", rm_file_num);
	return 0;
}

/* zfs thin lun check */

static int
zfs_checking_thinlun(zfs_handle_t *zhp, void *data)
{
	uint64_t reserver_size;
	uint64_t volsize;
	uint64_t thold;
	zfs_thin_luns_t *tmp_statp;
	zfs_thin_luns_stat_t *cbdata;

	cbdata = (zfs_thin_luns_stat_t *)data;   	
	reserver_size = zfs_prop_get_int(zhp, ZFS_PROP_REFRESERVATION);
	volsize = zfs_prop_get_int(zhp, ZFS_PROP_VOLSIZE);
	thold = zfs_prop_get_int(zhp, ZFS_PROP_LUN_THIN_THRESHOLD);

	if (reserver_size == 0 && volsize != 0 && thold != 0) {
		uint64_t thin_size = zfs_prop_get_int(zhp, ZFS_PROP_USED);
		if (thold > 0 && thold < 100 &&
			thin_size * 100 >= volsize * thold) {
			tmp_statp = &cbdata->thinluns[cbdata->thinluns_number];
			bzero(tmp_statp, sizeof(zfs_thin_luns_t));
			strcpy(tmp_statp->pool_name, zpool_get_name(zhp->zpool_hdl));
			strcpy(tmp_statp->lu_name, zfs_get_name(zhp));
			tmp_statp->lu_size = volsize;
			tmp_statp->thinlun_size = thin_size;
			tmp_statp->thinlun_threshold = thold;
			zfs_nicenum(volsize, tmp_statp->total, sizeof(tmp_statp->total));
			zfs_nicenum(thin_size, tmp_statp->used, sizeof(tmp_statp->used));
			cbdata->thinluns_number++;
		}
	}
	zfs_close(zhp);
	return (0);
}

int zfs_check_thin_luns_cb(zfs_handle_t *zhp, void *data)
{
	int ret;
	ret = zfs_iter_filesystems(zhp, zfs_checking_thinlun, data);
	zfs_close(zhp);
	return (ret);
}

void zfs_check_thin_luns(zfs_thin_luns_stat_t **statpp)
{
        int number;
        size_t size;
        libzfs_handle_t *tmp_gzfs;
        zfs_thin_luns_stat_t *cbdata;
        zfs_thin_luns_stat_t *luns_stat;
		int i;
        
        tmp_gzfs = libzfs_init();
        cbdata  = calloc(1, sizeof(zfs_thin_luns_stat_t));
        bzero(cbdata, sizeof(zfs_thin_luns_stat_t));
        cbdata->thinluns = calloc(MAX_POOl_NUM, sizeof(zfs_thin_luns_t));

		(void) zfs_iter_root(tmp_gzfs, zfs_check_thin_luns_cb, cbdata);

        number = cbdata->thinluns_number;

        if (number > 0) {
                luns_stat = calloc(1, sizeof(zfs_thin_luns_stat_t));
                luns_stat->thinluns = calloc(number, sizeof(zfs_thin_luns_t));
                luns_stat->thinluns_number = number;
                bcopy(cbdata->thinluns, luns_stat->thinluns,
                  sizeof(zfs_thin_luns_t)*number);
                *statpp = luns_stat;
                
        } else {
                *statpp = NULL;
        }

        free(cbdata->thinluns);
        free(cbdata);

        libzfs_fini(tmp_gzfs);
}


/*
 * ***************************************************************************************************
 * lun migrate cmd route
 * ***************************************************************************************************
 */
#define GSIZE_ALIG	(1024 * 1024 * 1024)
#define GSIZE_ALIG_MB	(1024 * 1024)
static int
zfs_lun_migrate_init(libzfs_handle_t *hdl, const char *dst, char *dst_guid, const char *pool, uint64_t gsize)
{
	char *ptr = NULL;
	FILE *lfp = NULL;
	char lun[128] = { 0 };
	char buf[256] = { 0 };
	char zvol_fs[256] = { 0 };
	char dst_path[128] = { 0 };
	char readbuf[1024] = { 0 };
	char fstr[128] = { 0 };
	char fguid[128] = { 0 };
	char fdev[128] = { 0 };
	nvlist_t *result = NULL;
	long int current_id = getpid();
	zfs_cmd_t zc;

	if (strstr(dst, "/dev/disk/by-id/") == NULL) {
		printf("invalid dev.\n");
		return (-1);
	}

	/* create copy lun and lu */
	ptr = strrchr(dst,'/');
	ptr++;
	sprintf(zvol_fs,"%s/lun_%s", pool, ptr);
	if ((gsize / GSIZE_ALIG) == 0) {
		sprintf(buf,"zfs create -V %dM %s 2>/dev/null", gsize / GSIZE_ALIG_MB, zvol_fs);
	} else {
		sprintf(buf,"zfs create -V %dG %s 2>/dev/null", gsize / GSIZE_ALIG, zvol_fs);
	}

	if ( system(buf) != 0) {
		(void) printf("zfs create lun failed\n");
		return (-1);
	}

	lfp = popen("stmfadm list-lu -v 2>/dev/null", "r");
	if (lfp == NULL) {
		(void) printf("stmfadm list-lu -v failed\n");
		return (-1);
	}

	while (fgets(readbuf, sizeof(readbuf), lfp)) {
		sscanf(readbuf, "%s", fstr);

		if (strcasecmp(fstr, "LU") == 0) {
			bzero(fguid, 128);
			sscanf(readbuf, "%*[^:]:%s", fguid);
			bzero(readbuf, 1024);
			continue;
		}

		if (strstr(readbuf, zvol_fs) == NULL) {
			bzero(readbuf, 1024);
			continue;
		}

		bzero(buf, 256);
		sprintf(buf, "stmfadm delete-lu %s 2>/dev/null",fguid);
		if (system(buf) != 0) {
			(void) printf("stmfadm delete-lu %s failed\n",fguid);
			return (-1);
		}

		result = zfs_clustersan_sync_cmd(hdl, current_id, buf, 10, -1);

		break;
	}

	if (dst_guid == NULL)
		dst_guid = dst + strlen("/dev/disk/by-id/scsi-x");

	bzero(buf, 256);
	sprintf(buf,"stmfadm create-lu -p guid=%s /dev/zvol/%s",dst_guid,zvol_fs);
	if (system(buf) != 0) {
		(void) printf("stmfadm create lu failed\n");
		return (-1);
	}

	sprintf(lun,"/dev/zvol/%s", zvol_fs);
	memcpy(dst_path, dst, 128);

	bzero(&zc, sizeof(zfs_cmd_t));
	strcpy(zc.zc_string, dst);
	strcpy(zc.zc_value, dst_guid);
	strcpy(zc.zc_top_ds, lun);
	strcpy(zc.zc_name, zvol_fs);
	zc.zc_lunmigrate_total = gsize;
	zc.zc_pad[0] = 1;

	return (ioctl(hdl->libzfs_fd, ZFS_IOC_START_LUN_MEGRATE, &zc));
}

static int
zfs_lun_migrate_dev_realpath(const char *dst, char *real)
{
	int sec = 0;
	int len = 0;
	FILE *fd = NULL;
	char *ptr = NULL;
	char tmp[1024] = { 0 };
	char buf_scsi[128] = { 0 };
	char buf_other[128] = { 0 };
	char buf_dev[128] = { 0 };

	fd = popen("ls -l /dev/disk/by-id/", "r");
	if (fd == NULL)
		return (-1);

	while (fgets(tmp, sizeof(tmp), fd)) {
		sscanf(tmp, "%*[^:]:%d %s %s %s",&sec, buf_scsi, buf_other, buf_dev);
		len = strlen(buf_dev);
		if (buf_dev[len - 1] >= '0' && buf_dev[len - 1] <= '9') {
			continue;
		}

		if (strncasecmp(buf_scsi, "scsi", 4) == 0) {
			ptr = strrchr(buf_dev, '/');
			if (ptr != NULL && strstr(dst, ptr) != NULL) {
				sprintf(real, "/dev/disk/by-id/%s", buf_scsi);
				return (0);
			}
		}
	}

	return (-1);
}

static int
zfs_lun_migrate_check(libzfs_handle_t *hdl, const char *dst, char *pool, char *o_guid)
{
	int err = 0;
	char *ptr = NULL;
	FILE *fd = NULL;
	uint64_t gsize = 0;
	char cmd_buf[128] = { 0 };
	char realpath[128] = { 0 };
	char readbuf[1024] = { 0 };

	if (dst == NULL || pool == NULL) {
		printf("invliad input\n");
		return (-1);
	}

	sprintf(cmd_buf, "fdisk -s %s", dst);
	fd = popen(cmd_buf, "r");
	if (fd == NULL) {
		printf("get %s gsize faild!\n", dst);
		return (-1);
	} else {
		if (fgets(readbuf, sizeof(readbuf), fd) != NULL) {
			sscanf(readbuf, "%lld", &gsize);
		}

		gsize = gsize * 1024;
	}

	if (strstr(dst, "scsi") == NULL) {
		err = zfs_lun_migrate_dev_realpath(dst, realpath);
		if (err == 0) {
			err = zfs_lun_migrate_init(hdl, realpath, o_guid, pool, gsize);
			if (o_guid == NULL)
				o_guid = realpath + strlen("/dev/disk/by-id/scsi-x");
		} else {
			printf("invliad dev path.\n");
		}
	} else {
		err = zfs_lun_migrate_init(hdl, dst, o_guid, pool, gsize);
	}

	if (err == 0) {
		printf("lun migrate begin ...\n");
		printf("disk name : %s\n", dst);
		printf("disk size : %lld\n", gsize);
		if (o_guid == NULL)
			printf("lun  guid : %s\n", dst + strlen("/dev/disk/by-id/scsi-x"));
		else
			printf("lun  guid : %s\n", o_guid);
	} else {
		printf("lun migrate create failed\n");
	}

	return (0);
}

int
zfs_check_lun_migrate(libzfs_handle_t *hdl, char *fsname, int now)
{
	int ret = 0;
	int i = 1;
	int b = 1;
	int try = 0;
	float percent = 0;
	char bar[52] = {0};
	char *lab = "-\\|/";
	zfs_cmd_t zc;

	bzero(&zc, sizeof(zfs_cmd_t));
	strcpy(zc.zc_string, fsname);
	zc.zc_pad[0] = 4;

	while (1) {
		ret = ioctl(hdl->libzfs_fd, ZFS_IOC_START_LUN_MEGRATE, &zc);
		if (ret == 0) {
			if (zc.zc_pad[1] == 5) {
				printf("haven't or have done this lun migrate\n");
				return (1);
			}

			percent = (zc.zc_lunmigrate_cur * 1.0 / zc.zc_lunmigrate_total * 1.0);
			if (now == 1) {
				ret = (int)(percent*100);
				return (ret);
			}

			if (zc.zc_pad[1] == 2) {
				printf("[%-51s][%.0f%%][%c][stop]\r",bar,(percent * 100),lab[b%4]);
			} else {
				printf("[%-51s][%.0f%%][%c]\r",bar,(percent * 100),lab[b%4]);
			}
			fflush(stdout);
			memset(bar, 0, 52);
			for (i = 0; i < percent * 50; i++) {
				bar[i] = '#';
			}

			if (b < 3)
				b++;
			else
				b = 0;
		} else {
			try++;
			if (try >= 5) {
				printf("Lun migrate has complete!\n");
				return (1);
			}
		}

		sleep(1);
	}
	printf("\n");

	return (1);
}

int
zfs_recovery_lun_migrate(libzfs_handle_t *hdl, char *dst)
{
	zfs_cmd_t zc;

	bzero(&zc, sizeof(zfs_cmd_t));
	strcpy(zc.zc_string, dst);
	zc.zc_pad[0] = 3;

	return (ioctl(hdl->libzfs_fd, ZFS_IOC_START_LUN_MEGRATE, &zc));
}

int
zfs_stop_lun_migrate(libzfs_handle_t *hdl, const char *dst)
{
	zfs_cmd_t zc;

	bzero(&zc, sizeof(zfs_cmd_t));
	strcpy(zc.zc_string, dst);
	zc.zc_pad[0] = 2;

	return (ioctl(hdl->libzfs_fd, ZFS_IOC_START_LUN_MEGRATE, &zc));
}

int
zfs_start_lun_migrate(libzfs_handle_t *hdl, const char *dst, char *pool, char *guid)
{
	char *ret_cp = NULL;

	return (zfs_lun_migrate_check(hdl, dst, pool, guid) != 0);
}

boolean_t
zfs_check_raidz_aggre_valid(nvlist_t *config, nvlist_t *nv)
{
	nvlist_t **child, **leaf_child;
	uint_t c, children, leaf_children;
	char *type;
	uint64_t nparity;
	uint64_t is_meta;
	int align_size = 1 << 19;
	int aggre_parity = 0;
	int aggre_num = 0;
	boolean_t valid = B_TRUE;
	boolean_t has_meta = B_FALSE;
	boolean_t has_raidz = B_FALSE;
	boolean_t has_raidz_aggre = B_FALSE;

	if (config) {
		verify(nvlist_lookup_nvlist_array(config, ZPOOL_CONFIG_CHILDREN,
		    &child, &children) == 0);
		for (c = 0; c < children; c++) {
			if (strcmp(type, VDEV_TYPE_RAIDZ_AGGRE) == 0) {
				verify(nvlist_lookup_nvlist_array(child[c], ZPOOL_CONFIG_CHILDREN,
	    			&leaf_child, &leaf_children) == 0);
				verify(nvlist_lookup_uint64(child[c], ZPOOL_CONFIG_NPARITY,
					&nparity) == 0);
				aggre_parity = nparity;
				aggre_num = leaf_children - nparity;
				break;
			}
		}
	}
	
	verify(nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0);

	for (c = 0; c < children; c++) {
		verify(nvlist_lookup_string(child[c], ZPOOL_CONFIG_TYPE, &type) == 0);
		if (strcmp(type, VDEV_TYPE_RAIDZ) == 0) {
			has_raidz = B_TRUE;
		} else if (strcmp(type, VDEV_TYPE_RAIDZ_AGGRE) == 0) {
			has_raidz_aggre = B_TRUE;
			verify(nvlist_lookup_nvlist_array(child[c], ZPOOL_CONFIG_CHILDREN,
	    		&leaf_child, &leaf_children) == 0);
			verify(nvlist_lookup_uint64(child[c], ZPOOL_CONFIG_NPARITY,
				&nparity) == 0);
			if (aggre_parity == 0)
				aggre_parity = nparity;

			if (aggre_num == 0)
				aggre_num = leaf_children - nparity;

			if (nparity != aggre_parity ||
				leaf_children - nparity != aggre_num ||
				align_size % (leaf_children - nparity)) {
				valid = B_FALSE;
				break;
			}
		} else if (strcmp(type, VDEV_TYPE_DISK) == 0) {
			is_meta = 0;
			verify(nvlist_lookup_uint64(child[c], ZPOOL_CONFIG_IS_META, &is_meta) == 0);
			if (is_meta)
				has_meta = B_TRUE;
		}

		if (has_raidz && has_raidz_aggre) {
			valid = B_FALSE;
			break;
		}
	}

	if (has_raidz_aggre) 
		return (valid && has_meta);

	return (B_TRUE);
}
