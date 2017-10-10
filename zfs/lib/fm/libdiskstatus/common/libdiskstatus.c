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
 * Disk status library
 *
 * This library is responsible for querying health and other status information
 * from disk drives.  It is intended to be a generic interface, however only
 * SCSI (and therefore SATA) disks are currently supported.  The library is
 * capable of detecting the following status conditions:
 *
 * 	- Predictive failure
 * 	- Overtemp
 * 	- Self-test failure
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libdevinfo.h>
#include <libdiskstatus.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ds_impl.h"
#include "ds_scsi.h"

/* LHL ADD 2014.03.19 Wed. */
#define ADD_DS_DBGFMD

#ifdef ADD_DS_DBGFMD

#define DISK_EINJECT_CONFPATH "/tmp/ds_errinject.conf"

#define NONDSPATH 0
#define OVERTEMP 1
#define PREDFAIL 2
#define TESTFAIL 3
#endif
/* LHL ADD END */

static ds_transport_t *ds_transports[] = {
	&ds_scsi_sim_transport,
	&ds_scsi_uscsi_transport
};

#define	NTRANSPORTS	(sizeof (ds_transports) / sizeof (ds_transports[0]))

/* LHL ADD 2014.03.19 Wed. */
/*
 * add a method to check file DISK_EINJECT_CONFPATH.
 * the form is
 * @1. disk_path<space>1
 * @2. disk_path=1
 * indicate the disk(disk_path) in err 1(overtemp).
 * if a '#' in front of line, it's a comment.
 */
#ifdef ADD_DS_DBGFMD
static char *string_strip(char *str){

	char *begin, *end;

	if(!str)
		return NULL;

	begin = str;
	end = begin + strlen(str);

	while(isspace(*begin++) && begin < end);
	while(isspace(*--end) && begin < end);

	*++end = 0;
	return --begin;
}

static int disk_error_inject(const char *path){

	FILE *fp;
	int ret;
	char buf[1024];
	char *begin, *ds_path, *failed_nu;

	if((fp = fopen(DISK_EINJECT_CONFPATH, "r")) == NULL)
		return -1;

	ret = NONDSPATH;
	while(fgets(buf, 1024, fp)){

		if(strlen(buf) < 10 || !strchr(buf, '/'))
			continue;

		begin = string_strip(buf);
		if(*begin == '#')
			continue;

		ds_path = string_strip(strtok(begin, "= "));
		failed_nu = string_strip(strtok(NULL, "= "));

		if(ds_path && !strcmp(path, ds_path))
			if(failed_nu && isdigit(*failed_nu) && strlen(failed_nu) == 1){
				ret = atoi(failed_nu);
				break;
			}
	}

	fclose(fp);
	return ret;
}
#endif
/* LHL ADD END */

/*
 * Open a handle to a disk.  This will fail if the device cannot be opened, or
 * if no suitable transport exists for communicating with the device.
 */
disk_status_t *
disk_status_open(const char *path, int *error)
{
	disk_status_t *dsp;
	ds_transport_t *t;
	int i;

	if ((dsp = calloc(sizeof (disk_status_t), 1)) == NULL) {
		*error = EDS_NOMEM;
		return (NULL);
	}

	if ((dsp->ds_fd = open(path, O_RDWR|O_DIRECT)) < 0) {
		*error = EDS_CANT_OPEN;
		free(dsp);
		return (NULL);
	}

	if ((dsp->ds_path = strdup(path)) == NULL) {
		*error = EDS_NOMEM;
		disk_status_close(dsp);
		return (NULL);
	}

	for (i = 0; i < NTRANSPORTS; i++) {
		t = ds_transports[i];

		dsp->ds_transport = t;

		nvlist_free(dsp->ds_state);
		dsp->ds_state = NULL;
		if (nvlist_alloc(&dsp->ds_state, NV_UNIQUE_NAME, 0) != 0) {
			*error = EDS_NOMEM;
			disk_status_close(dsp);
			return (NULL);
		}

		if ((dsp->ds_data = t->dt_open(dsp)) == NULL) {
			if (dsp->ds_error != EDS_NO_TRANSPORT) {
				*error = dsp->ds_error;
				disk_status_close(dsp);
				return (NULL);
			}
		} else {
			dsp->ds_error = 0;
			break;
		}
	}

	if (dsp->ds_error == EDS_NO_TRANSPORT) {
		*error = dsp->ds_error;
		disk_status_close(dsp);
		return (NULL);
	}

	return (dsp);
}

/*
 * Close a handle to a disk.
 */
void
disk_status_close(disk_status_t *dsp)
{
	nvlist_free(dsp->ds_state);
	nvlist_free(dsp->ds_predfail);
	nvlist_free(dsp->ds_overtemp);
	nvlist_free(dsp->ds_testfail);
	if (dsp->ds_data)
		dsp->ds_transport->dt_close(dsp->ds_data);
	(void) close(dsp->ds_fd);
	free(dsp->ds_path);
	free(dsp);
}

void
disk_status_set_debug(boolean_t value)
{
	ds_debug = value;
}

/*
 * Query basic information
 */
const char *
disk_status_path(disk_status_t *dsp)
{
	return (dsp->ds_path);
}

int
disk_status_errno(disk_status_t *dsp)
{
	return (dsp->ds_error);
}

nvlist_t *
disk_status_get(disk_status_t *dsp)
{
	nvlist_t *nvl = NULL;
	nvlist_t *faults = NULL;
	int err;
	
	/*
	 * Scan (or rescan) the current device.
	 */
	nvlist_free(dsp->ds_testfail);
	nvlist_free(dsp->ds_predfail);
	nvlist_free(dsp->ds_overtemp);
	dsp->ds_testfail = dsp->ds_overtemp = dsp->ds_predfail = NULL;
	dsp->ds_faults = 0;

	/*
	 * Even if there is an I/O failure when trying to scan the device, we
	 * can still return the current state.
	 */
	if (dsp->ds_transport->dt_scan(dsp->ds_data) != 0 &&
	    dsp->ds_error != EDS_IO)
		return (NULL);

	if ((err = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)) != 0)
		goto nverror;

	if ((err = nvlist_add_string(nvl, "protocol", "scsi")) != 0 ||
	    (err = nvlist_add_nvlist(nvl, "status", dsp->ds_state)) != 0)
		goto nverror;

	/*
	 * Construct the list of faults.
	 */
	if ((err = nvlist_alloc(&faults, NV_UNIQUE_NAME, 0)) != 0)
		goto nverror;

	if (dsp->ds_predfail != NULL) {
		if ((err = nvlist_add_boolean_value(faults,
		    FM_EREPORT_SCSI_PREDFAIL,
		    (dsp->ds_faults & DS_FAULT_PREDFAIL) != 0)) != 0 ||
		    (err = nvlist_add_nvlist(nvl, FM_EREPORT_SCSI_PREDFAIL,
		    dsp->ds_predfail)) != 0)
			goto nverror;
	}

	if (dsp->ds_testfail != NULL) {
		if ((err = nvlist_add_boolean_value(faults,
		    FM_EREPORT_SCSI_TESTFAIL,
		    (dsp->ds_faults & DS_FAULT_TESTFAIL) != 0)) != 0 ||
		    (err = nvlist_add_nvlist(nvl, FM_EREPORT_SCSI_TESTFAIL,
		    dsp->ds_testfail)) != 0)
			goto nverror;
	}

	if (dsp->ds_overtemp != NULL) {
		if ((err = nvlist_add_boolean_value(faults,
		    FM_EREPORT_SCSI_OVERTEMP,
		    (dsp->ds_faults & DS_FAULT_OVERTEMP) != 0)) != 0 ||
		    (err = nvlist_add_nvlist(nvl, FM_EREPORT_SCSI_OVERTEMP,
		    dsp->ds_overtemp)) != 0)
			goto nverror;
	}

/* LHL ADD 2014.03.19 Wed. */
#ifdef ADD_DS_DBGFMD
/*
 * simulate a disk error here because we can't get a real error on disk
 * and It's a complex work to inject an error into real disk via ioctl().
 */
	{
		char *einject;
		nvlist_t *errnvl;

		switch(disk_error_inject(dsp->ds_path)){

			case OVERTEMP:
				einject = FM_EREPORT_SCSI_OVERTEMP;
				break;
			case PREDFAIL:
				einject = FM_EREPORT_SCSI_PREDFAIL;
				break;
			case TESTFAIL:
				einject = FM_EREPORT_SCSI_TESTFAIL;
				break;
			default:
				einject = NULL;
		}

		if(einject){
			if(!nvlist_alloc(&errnvl, NV_UNIQUE_NAME, 0) &&
				!nvlist_add_string(errnvl, "LHL_err_inject", "haha")){

				nvlist_add_boolean_value(faults, einject, 1);
				nvlist_add_nvlist(nvl, einject, errnvl);
				nvlist_free(errnvl);
			}
		}
	}
#endif
/* LHL ADD END */
	if ((err = nvlist_add_nvlist(nvl, "faults", faults)) != 0)
		goto nverror;

	nvlist_free(faults);
	return (nvl);

nverror:
	assert(err == ENOMEM);
	nvlist_free(nvl);
	nvlist_free(faults);
	(void) ds_set_errno(dsp, EDS_NOMEM);
	return (NULL);
}
