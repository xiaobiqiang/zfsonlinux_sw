/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <strings.h>
#include "fmd_error.h"

static const char *const _fmd_ereports[] = {
	"ereport.fm.fmd.unknown",
	"ereport.fm.fmd.panic",
	"ereport.fm.fmd.exit",
	"ereport.fm.fmd.module",
	"ereport.fm.fmd.conf_open",
	"ereport.fm.fmd.conf_keyword",
	"ereport.fm.fmd.conf_noprop",
	"ereport.fm.fmd.conf_nodefer",
	"ereport.fm.fmd.conf_propdup",
	"ereport.fm.fmd.conf_inval",
	"ereport.fm.fmd.conf_overflow",
	"ereport.fm.fmd.conf_usage",
	"ereport.fm.fmd.conf_default",
	"ereport.fm.fmd.conf_errs",
	"ereport.fm.fmd.conf_io",
	"ereport.fm.fmd.conf_propname",
	"ereport.fm.fmd.conf_rdonly",
	"ereport.fm.fmd.conf_defer",
	"ereport.fm.fmd.conf_undef",
	"ereport.fm.fmd.mod_init",
	"ereport.fm.fmd.mod_fini",
	"ereport.fm.fmd.mod_thr",
	"ereport.fm.fmd.mod_join",
	"ereport.fm.fmd.mod_conf",
	"ereport.fm.fmd.mod_dict",
	"ereport.fm.fmd.mod_loaded",
	"ereport.fm.fmd.mod_nomod",
	"ereport.fm.fmd.mod_fail",
	"ereport.fm.fmd.mod_topo",
	"ereport.fm.fmd.rtld_open",
	"ereport.fm.fmd.rtld_init",
	"ereport.fm.fmd.bltin_name",
	"ereport.fm.fmd.bltin_init",
	"ereport.fm.fmd.event_inval",
	"ereport.fm.fmd.xprt_inval",
	"ereport.fm.fmd.xprt_payload",
	"ereport.fm.fmd.xprt_owner",
	"ereport.fm.fmd.xprt_thr",
	"ereport.fm.fmd.xprt_limit",
	"ereport.fm.fmd.time_gettod",
	"ereport.fm.fmd.log_open",
	"ereport.fm.fmd.log_close",
	"ereport.fm.fmd.log_exacct",
	"ereport.fm.fmd.log_append",
	"ereport.fm.fmd.log_minfree",
	"ereport.fm.fmd.log_commit",
	"ereport.fm.fmd.log_inval",
	"ereport.fm.fmd.log_version",
	"ereport.fm.fmd.log_unpack",
	"ereport.fm.fmd.log_replay",
	"ereport.fm.fmd.log_update",
	"ereport.fm.fmd.log_rotate",
	"ereport.fm.fmd.log_rotbusy",
	"ereport.fm.fmd.asru_nodir",
	"ereport.fm.fmd.asru_event",
	"ereport.fm.fmd.asru_fmri",
	"ereport.fm.fmd.asru_noent",
	"ereport.fm.fmd.asru_unlink",
	"ereport.fm.fmd.asru_dup",
	"ereport.fm.fmd.fmri_scheme",
	"ereport.fm.fmd.fmri_op",
	"ereport.fm.fmd.fmri_inval",
	"ereport.fm.fmd.fmri_notsup",
	"ereport.fm.fmd.ver_old",
	"ereport.fm.fmd.ver_new",
	"ereport.fm.fmd.hdl_init",
	"ereport.fm.fmd.hdl_info",
	"ereport.fm.fmd.hdl_prop",
	"ereport.fm.fmd.hdl_notreg",
	"ereport.fm.fmd.hdl_reg",
	"ereport.fm.fmd.hdl_tid",
	"ereport.fm.fmd.hdl_inval",
	"ereport.fm.fmd.hdl_abort",
	"ereport.fm.fmd.hdl_nomem",
	"ereport.fm.fmd.prop_type",
	"ereport.fm.fmd.prop_defn",
	"ereport.fm.fmd.stat_flags",
	"ereport.fm.fmd.stat_type",
	"ereport.fm.fmd.stat_badtype",
	"ereport.fm.fmd.stat_badname",
	"ereport.fm.fmd.stat_dupname",
	"ereport.fm.fmd.stat_nomem",
	"ereport.fm.fmd.case_owner",
	"ereport.fm.fmd.case_state",
	"ereport.fm.fmd.case_event",
	"ereport.fm.fmd.case_inval",
	"ereport.fm.fmd.buf_inval",
	"ereport.fm.fmd.buf_limit",
	"ereport.fm.fmd.buf_noent",
	"ereport.fm.fmd.buf_oflow",
	"ereport.fm.fmd.buf_exists",
	"ereport.fm.fmd.serd_name",
	"ereport.fm.fmd.serd_exists",
	"ereport.fm.fmd.thr_create",
	"ereport.fm.fmd.thr_limit",
	"ereport.fm.fmd.thr_inval",
	"ereport.fm.fmd.thr_join",
	"ereport.fm.fmd.timer_inval",
	"ereport.fm.fmd.timer_limit",
	"ereport.fm.fmd.ckpt_nomem",
	"ereport.fm.fmd.ckpt_mkdir",
	"ereport.fm.fmd.ckpt_create",
	"ereport.fm.fmd.ckpt_commit",
	"ereport.fm.fmd.ckpt_delete",
	"ereport.fm.fmd.ckpt_open",
	"ereport.fm.fmd.ckpt_short",
	"ereport.fm.fmd.ckpt_inval",
	"ereport.fm.fmd.ckpt_restore",
	"ereport.fm.fmd.rpc_reg",
	"ereport.fm.fmd.rpc_bound",
	"ereport.fm.fmd.nvl_inval",
	"ereport.fm.fmd.ctl_inval",
	"ereport.fm.fmd.end",
};

static const char *const _fmd_errstrs[] = {
	"unknown fault management daemon error",
	"unrecoverable fatal error in daemon occurred",
	"failed to initialize fault management daemon",
	"fmd module detected or caused an error",
	"failed to open configuration file",
	"invalid configuration file keyword",
	"invalid configuration file parameter name",
	"deferred properties not permitted in this file",
	"duplicate configuration file parameter name",
	"invalid value for configuration file property",
	"configuration value too large for data type",
	"syntax error in configuration file directive",
	"invalid default value for configuration property",
	"error(s) detected in configuration file",
	"i/o error prevented configuration file processing",
	"configuration property name is not an identifier",
	"configuration property is read-only",
	"invalid deferred configuration file property",
	"configuration property is not defined",
	"failed to initialize module",
	"failed to uninitialize module",
	"failed to create processing thread for module",
	"failed to join processing thread for module",
	"error(s) detected in module configuration file",
	"failed to open module's event code dictionary",
	"specified module is already loaded",
	"specified module is not loaded",
	"module failed due to preceding error",
	"failed to obtain topology handle",
	"rtld failed to open shared library plug-in",
	"shared library plug-in does not define _fmd_init",
	"built-in plug-in name not found in definition list",
	"built-in plug-in does not define init function",
	"event interface programming error",
	"transport interface programming error",
	"transport event has invalid payload",
	"transport can only be manipulated by owner",
	"failed to create thread for transport",
	"limit on number of open transports exceeded",
	"failed to get current time-of-day",
	"failed to open and initialize log file",
	"failed to close log file",
	"failed to perform log exacct operation",
	"failed to append event to log",
	"insufficient min fs space to append event to log",
	"failed to commit event to log",
	"invalid log header information",
	"invalid log version information",
	"failed to unpack data in log",
	"failed to replay log content",
	"failed to update log toc",
	"failed to rotate log file",
	"failed to rotate log file due to pending events",
	"failed to open asru cache directory",
	"failed to process asru event log",
	"failed to convert asru fmri to string",
	"failed to locate specified asru entry",
	"failed to delete asru cache entry",
	"asru log is a duplicate of an existing asru",
	"fmri scheme module is missing or failed to load",
	"fmri scheme module operation failed",
	"fmri nvlist is missing required element",
	"fmri scheme module does not support operation",
	"plug-in is compiled using an obsolete fmd API",
	"plug-in is compiled using a newer fmd API",
	"client handle wasn't initialized by _fmd_init",
	"client info is missing required information",
	"client info includes invalid property definition",
	"client handle has never been registered",
	"client handle has already been registered",
	"client handle must be registered by owner",
	"client handle is corrupt or not owned by caller",
	"client requested that module execution abort",
	"client memory limit exceeded",
	"property accessed using incompatible type",
	"property is not defined",
	"function",
	"invalid operation for statistic type",
	"invalid type for statistic",
	"invalid name for statistic",
	"statistic name is already defined in collection",
	"failed to allocate memory for statistics snapshot",
	"case can only be manipulated or closed by owner",
	"case is not in appropriate state for operation",
	"case operation failed due to invalid event",
	"case uuid does not match any known case",
	"buffer specification uses invalid name or size",
	"client exceeded limit on total buffer space",
	"no such buffer is currently defined by client",
	"write would overflow the size of this buffer",
	"buffer with the specified name already exists",
	"no serd engine with the specified name exists",
	"serd engine with the specified name already exists",
	"failed to create auxiliary module thread",
	"limit on module auxiliary threads exceeded",
	"invalid thread id specified for thread call",
	"failed to join with auxiliary thread",
	"invalid time delta or id specified for timer call",
	"client exceeded limit on number of pending timers",
	"failed to allocate checkpoint buffer",
	"failed to create checkpoint directory",
	"failed to create checkpoint file",
	"failed to commit checkpoint file",
	"failed to delete checkpoint file",
	"failed to open checkpoint file",
	"checkpoint file has been truncated or corrupted",
	"checkpoint file has invalid header or content",
	"failed to restore checkpoint file",
	"failed to register rpc service",
	"rpc program/version is already bound",
	"invalid nvlist function argument",
	"invalid fault manager control event",
	"end of custom errno list (to ease auto-merge)",
};

static const int _fmd_nereports =
    sizeof (_fmd_ereports) / sizeof (_fmd_ereports[0]);

static const int _fmd_nerrstrs =
    sizeof (_fmd_errstrs) / sizeof (_fmd_errstrs[0]);

const char *
fmd_errclass(int err)
{
	const char *c;

	if (err >= EFMD_UNKNOWN && (err - EFMD_UNKNOWN) < _fmd_nereports)
		c = _fmd_ereports[err - EFMD_UNKNOWN];
	else
		c = _fmd_ereports[0];

	return (c);
}

const char *
fmd_strerror(int err)
{
	const char *s;

	if (err >= EFMD_UNKNOWN && (err - EFMD_UNKNOWN) < _fmd_nerrstrs)
		s = _fmd_errstrs[err - EFMD_UNKNOWN];
	else if (err < 0 || (s = strerror(err)) == NULL)
		s = _fmd_errstrs[0];

	return (s);
}

int
fmd_set_errno(int err)
{
	errno = err;
	return (-1);
}
