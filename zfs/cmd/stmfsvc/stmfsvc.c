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

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
#include <libintl.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <libstmf.h>
#include <signal.h>
#include <pthread.h>
#include <locale.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/systeminfo.h>
#include <sys/pppt_ioctl.h>
#include "cmdparse.h"

static int svcStart(int, char **, cmdOptions_t *, void *);
static int svcStop(int, char **, cmdOptions_t *, void *);
static int online(void);

/*
 *  MAJOR - This should only change when there is an incompatible change made
 *  to the interfaces or the output.
 *
 *  MINOR - This should change whenever there is a new command or new feature
 *  with no incompatible change.
 */
#define	VERSION_STRING_MAJOR	    "1"
#define	VERSION_STRING_MINOR	    "0"
#define	VERSION_STRING_MAX_LEN	    10

/* 10 ms sleep in nanoseconds */
#define	TEN_MS_NANOSLEEP  10000000

/* tables set up based on cmdparse instructions */

/* add new options here */
optionTbl_t longOptions[] = {
	{NULL, 0, 0, 0}
};

/*
 * Add new subcommands here
 */
subCommandProps_t subcommands[] = {
	{"start", svcStart, NULL, NULL, NULL, OPERAND_NONE, NULL},
	{"stop", svcStop, NULL, NULL, NULL, OPERAND_NONE, NULL},
	{NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL}
};

/* globals */
char *cmdName;

static int
stmf_check_stmf_enable(void)
{
	return stmfCheckService();
}

static void
stmf_enable_pppt(void)
{
	int ret;
	int proxy_hdl;
	
	/* open pppt driver, should never close */
	ret = stmfInitProxyDoor(&proxy_hdl, 0);
	if (ret != 0) {
		syslog(LOG_WARNING, "stmf open proxy failed");
		ret = 0;
	} else {
		/* ctrl pppt svc */
		pppt_iocdata_t ppptIoctl = {PPPT_VERSION_1, };
		
		ret = ioctl(proxy_hdl, PPPT_ENABLE_SVC, &ppptIoctl);
		if (ret != 0) {
			syslog(LOG_WARNING, "pppt enable svc failed");
		}

		if (stmf_check_stmf_enable()) {
			/* enable pppt ksocket */
			ret = ioctl(proxy_hdl, PPPT_KSOCKET_WAKEUP, &ppptIoctl);
			if (ret != 0) {
				syslog(LOG_WARNING, "pppt enable ksocket failed");
			}
		}
		
		stmfDestroyProxyDoor(proxy_hdl);
	}
}

static void
stmf_disable_pppt(void)
{
	int ret;
	int proxy_hdl;
	
	/* open pppt driver, should never close */
	ret = stmfInitProxyDoor(&proxy_hdl, 0);
	if (ret != 0) {
		syslog(LOG_WARNING, "stmf open proxy failed");
		ret = 0;
	} else {
		pppt_iocdata_t ppptIoctl = {PPPT_VERSION_1, };
		
		ret = ioctl(proxy_hdl, PPPT_DISABLE_SVC, &ppptIoctl);
		if (ret != 0) {
			syslog(LOG_WARNING, "pppt disable svc failed");
		}
		
		stmfDestroyProxyDoor(proxy_hdl);
	}	
}

static void
stmf_update_ksocket_pppt(void)
{
	int ret;
	int proxy_hdl;
	
	/* open pppt driver, should never close */
	ret = stmfInitProxyDoor(&proxy_hdl, 0);
	if (ret != 0) {
		syslog(LOG_WARNING, "stmf open proxy failed");
		ret = 0;
	} else {
		pppt_iocdata_t ppptIoctl = {PPPT_VERSION_1, };

		ret = ioctl(proxy_hdl, PPPT_KSOCKET_WAKEUP, &ppptIoctl);
		if (ret != 0) {
			syslog(LOG_WARNING, "pppt enable ksocket update");
		}
		
		stmfDestroyProxyDoor(proxy_hdl);
	}
}

/*
 * svcStop
 *
 * Offlines the stmf service
 *
 */
/*ARGSUSED*/
static int
svcStop(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int stmfRet;
	int ret = 0;
	stmfState state;
	boolean_t serviceOffline = B_FALSE;
	struct timespec rqtp;

	bzero(&rqtp, sizeof (rqtp));

	rqtp.tv_nsec = TEN_MS_NANOSLEEP;

	if ((stmfRet = stmfOffline()) != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_OFFLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service already offline"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unable to offline service"));
				break;
		}
		return (1);
	}

	/* wait for service offline */
	while (!serviceOffline) {
		stmfRet = stmfGetState(&state);
		if (stmfRet != STMF_STATUS_SUCCESS) {
			ret = 1;
			break;
		}
		if (state.operationalState == STMF_SERVICE_STATE_OFFLINE) {
			serviceOffline = B_TRUE;
		} else {
			(void) nanosleep(&rqtp, NULL);
		}
	}

	/* disable pppt */
	stmf_disable_pppt();
	
	return (ret);
}

/*
 * loadConfig
 *
 * Loads the stmf config from the SMF repository
 *
 */
/*ARGSUSED*/
static int
svcStart(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int stmfRet;
	int ret = 0;

	if (stmf_check_stmf_enable()) {
		stmf_update_ksocket_pppt();
	}

	if ((stmfRet = stmfLoadConfig()) != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_ONLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service must be offline"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unable to load config"));
				break;
		}
		syslog(LOG_ERR, "stmf load config failed, ret=%d", stmfRet);
		return (1);
	}
	ret = online();
	if (ret != 0) {
		syslog(LOG_ERR, "stmf online failed");
		goto DONE;
	}

	/* enable pppt */
	stmf_enable_pppt();

DONE:
	return (ret);

}

/*
 * online
 *
 * Onlines the stmf service
 *
 */
/*ARGSUSED*/
static int
online(void)
{
	int stmfRet;
	int ret = 0;
	stmfState state;
	boolean_t serviceOnline = B_FALSE;
	struct timespec rqtp;

	bzero(&rqtp, sizeof (rqtp));

	rqtp.tv_nsec = TEN_MS_NANOSLEEP;

	if ((stmfRet = stmfOnline()) != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_ONLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service already online"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unable to online service"));
				break;
		}
		return (1);
	}

	/* wait for service online */
	while (!serviceOnline) {
		stmfRet = stmfGetState(&state);
		if (stmfRet != STMF_STATUS_SUCCESS) {
			ret = 1;
			break;
		}
		if (state.operationalState == STMF_SERVICE_STATE_ONLINE) {
			serviceOnline = B_TRUE;
		} else {
			(void) nanosleep(&rqtp, NULL);
		}
	}

	return (ret);
}

/*
 * killHandler
 *
 * Terminates this process on SIGQUIT, SIGINT, SIGTERM
 */
/* ARGSUSED */

/*
 * Initialization for a daemon process
 */

		/*
		 * XXX
		 * Simple approach for now - let the service go online.
		 * Later, set-up a pipe to the child and wait until the
		 * child indicates service is setup.
		 */







	/*
	 * XXX inform the parent about the service state
	 * For now, just exit on error.
	 */

/*
 * input:
 *  execFullName - exec name of program (argv[0])
 *
 *  copied from usr/src/cmd/zoneadm/zoneadm.c in OS/Net
 *  (changed name to lowerCamelCase to keep consistent with this file)
 *
 * Returns:
 *  command name portion of execFullName
 */
static char *
getExecBasename(char *execFullname)
{
	char *lastSlash, *execBasename;

	/* guard against '/' at end of command invocation */
	for (;;) {
		lastSlash = strrchr(execFullname, '/');
		if (lastSlash == NULL) {
			execBasename = execFullname;
			break;
		} else {
			execBasename = lastSlash + 1;
			if (*execBasename == '\0') {
				*lastSlash = '\0';
				continue;
			}
			break;
		}
	}
	return (execBasename);
}

int
main(int argc, char *argv[])
{
	synTables_t synTables;
	char versionString[VERSION_STRING_MAX_LEN];
	int funcRet, ret;
	void *subcommandArgs = NULL;

	(void) setlocale(LC_ALL, "");

	/*
	 * Allow SIGQUIT, SIGINT and SIGTERM signals to terminate us
	 */

	/* Install the signal handler */

	/* block all signals */

	/* unblock SIGQUIT, SIGINT, SIGTERM */


	/* time to go backstage */
	
	/* set global command name */
	cmdName = getExecBasename(argv[0]);

	(void) snprintf(versionString, VERSION_STRING_MAX_LEN, "%s.%s",
	    VERSION_STRING_MAJOR, VERSION_STRING_MINOR);
	synTables.versionString = versionString;
	synTables.longOptionTbl = &longOptions[0];
	synTables.subCommandPropsTbl = &subcommands[0];

	ret = cmdParse(argc, argv, synTables, subcommandArgs, &funcRet);
	if (ret != 0) {
		return (ret);
	}
	
	return (funcRet);
} /* end main */
