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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libnvpair.h>
#include <alloca.h>
#include <limits.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/fmd_transport.h>

#include "fmd_api.h"
#include "fmd_thread.h"

#include "fmd_alloc.h"
#include "fmd_thread.h"
#include "fmd_module.h"
#include "fmd_error.h"
#include "fmd_subr.h"
#include "fmd_list.h"
#include "fmd.h"

static fmd_xprt_t *channel_xprt;
static fmd_hdl_t *channel_hdl;
static int channel_xprt_refcnt;

#if 1
static char *channel_channel;	/* event channel to which we are subscribed */
static char *channel_class;	/* event class to which we are subscribed */
static char *channel_device;	/* device path to use for replaying events */
static char *channel_sid;		/* event channel subscriber identifier */
#endif
static pthread_cond_t channel_cv = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t channel_mutex = PTHREAD_MUTEX_INITIALIZER;
static int channel_exiting = 0;
static int channel_replay_wait = 1;
static void channel_replay(fmd_hdl_t *hdl, id_t id, void *arg);

static struct channel_stats {
	fmd_stat_t dump_replay;
	fmd_stat_t dump_lost;
	fmd_stat_t bad_class;
	fmd_stat_t bad_attr;
	fmd_stat_t eagain;
} channel_stats = {
	{ "dump_replay", FMD_TYPE_UINT64, "events replayed from dump device" },
	{ "dump_lost", FMD_TYPE_UINT64, "events lost from dump device" },
	{ "bad_class", FMD_TYPE_UINT64, "events dropped due to invalid class" },
	{ "bad_attr", FMD_TYPE_UINT64, "events dropped due to invalid nvlist" },
	{ "eagain", FMD_TYPE_UINT64, "events retried due to low memory" },
};

static const fmd_prop_t channel_props[] = {
	{ "class", FMD_TYPE_STRING, NULL },		/* event class */
	{ "device", FMD_TYPE_STRING, NULL },	/* replay device */
	{ "channel", FMD_TYPE_STRING, NULL },	/* channel name */
	{ "sid", FMD_TYPE_STRING, "fmd" },		/* subscriber id */
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t channel_ops = {
	NULL,		/* fmdo_recv */
	channel_replay,		/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
	NULL,		/* fmdo_send */
};

static const fmd_hdl_info_t channel_info = {
	"Fmd Transport Agent", "1.0", &channel_ops, channel_props
};

/*
 * Replay saved events from the dump transport.  This function is installed as
 * the timer callback and is called only once during the module's lifetime.
 */
/*ARGSUSED*/
static void
channel_replay(fmd_hdl_t *hdl, id_t id, void *arg){
	char *dumpdev;
	//off64_t off, off0;
	//int fd, err;

	/*
	 * Determine the appropriate dump device to use for replaying pending
	 * error reports.  If the device property is NULL (default), we
	 * open and query /dev/dump to determine the current dump device.
	 */
	dumpdev = channel_device;
#if 0
	if ((dumpdev = channel_device) == NULL) {
		if ((fd = open("/dev/dump", O_RDONLY)) == -1) {
			fmd_hdl_error(hdl, "failed to open /dev/dump "
			    "to locate dump device for event replay");
			goto done;
		}

		dumpdev = alloca(PATH_MAX);
		err = ioctl(fd, DIOCGETDEV, dumpdev);
		(void) close(fd);

		if (err == -1) {
			if (errno != ENODEV) {
				fmd_hdl_error(hdl, "failed to obtain "
				    "path to dump device for event replay");
			}
			goto done;
		}
	}

	if (strcmp(dumpdev, "/dev/null") == 0)
		goto done; /* return silently and skip replay for /dev/null */

	/*
	 * Open the appropriate device and then determine the offset of the
	 * start of the ereport dump region located at the end of the device.
	 */
	if ((fd = open64(dumpdev, O_RDWR | O_DSYNC)) == -1) {
		fmd_hdl_error(hdl, "failed to open dump transport %s "
		    "(pending events will not be replayed)", dumpdev);
		goto done;
	}

	off = DUMP_OFFSET + DUMP_LOGSIZE + DUMP_ERPTSIZE;
	off = off0 = lseek64(fd, -off, SEEK_END) & -DUMP_OFFSET;

	if (off == (off64_t)-1LL) {
		fmd_hdl_error(hdl, "failed to seek dump transport %s "
		    "(pending events will not be replayed)", dumpdev);
		(void) close(fd);
		goto done;
	}

	/*
	 * The ereport dump region is a sequence of erpt_dump_t headers each of
	 * which is followed by packed nvlist data.  We iterate over them in
	 * order, unpacking and dispatching each one to our dispatch queue.
	 */
	for (;;) {
		char nvbuf[ERPT_DATA_SZ];
		uint32_t chksum;
		erpt_dump_t ed;
		nvlist_t *nvl;

		fmd_timeval_t ftv, tod;
		hrtime_t hrt;
		uint64_t ena;

		if (pread64(fd, &ed, sizeof (ed), off) != sizeof (ed)) {
			fmd_hdl_error(hdl, "failed to read from dump "
			    "transport %s (pending events lost)", dumpdev);
			break;
		}

		if (ed.ed_magic == 0 && ed.ed_size == 0)
			break; /* end of list: all zero */

		if (ed.ed_magic == 0) {
			off += sizeof (ed) + ed.ed_size;
			continue; /* continue searching */
		}

		if (ed.ed_magic != ERPT_MAGIC) {
			/*
			 * Stop reading silently if the first record has the
			 * wrong magic number; this likely indicates that we
			 * rebooted from non-FMA bits or paged over the dump.
			 */
			if (off == off0)
				break;

			fmd_hdl_error(hdl, "invalid dump transport "
			    "record at %llx (magic number %x, expected %x)\n",
			    (u_longlong_t)off, ed.ed_magic, ERPT_MAGIC);
			break;
		}

		if (ed.ed_size > ERPT_DATA_SZ) {
			fmd_hdl_error(hdl, "invalid dump transport "
			    "record at %llx size (%u exceeds limit)\n",
			    (u_longlong_t)off, ed.ed_size);
			break;
		}

		if (pread64(fd, nvbuf, ed.ed_size,
		    off + sizeof (ed)) != ed.ed_size) {
			fmd_hdl_error(hdl, "failed to read dump "
			    "transport event (offset %llx)", (u_longlong_t)off);

			sysev_stats.dump_lost.fmds_value.ui64++;
			goto next;
		}

		if ((chksum = sysev_checksum(nvbuf,
		    ed.ed_size)) != ed.ed_chksum) {
			fmd_hdl_error(hdl, "dump transport event at "
			    "offset %llx is corrupt (checksum %x != %x)\n",
			    (u_longlong_t)off, chksum, ed.ed_chksum);

			sysev_stats.dump_lost.fmds_value.ui64++;
			goto next;
		}

		if ((err = nvlist_xunpack(nvbuf,
		    ed.ed_size, &nvl, &fmd.d_nva)) != 0) {
			fmd_hdl_error(hdl, "failed to unpack dump "
			    "transport event at offset %llx: %s\n",
			    (u_longlong_t)off, fmd_strerror(err));

			sysev_stats.dump_lost.fmds_value.ui64++;
			goto next;
		}

		/*
		 * If ed_hrt_nsec is set it contains the gethrtime() value from
		 * when the event was originally enqueued for the transport.
		 * If it is zero, we use the weaker bound ed_hrt_base instead.
		 */
		if (ed.ed_hrt_nsec != 0)
			hrt = ed.ed_hrt_nsec;
		else
			hrt = ed.ed_hrt_base;

		/*
		 * If this is an FMA protocol event of class "ereport.*" that
		 * contains valid ENA, we can improve the precision of 'hrt'.
		 */
		if (nvlist_lookup_uint64(nvl, FM_EREPORT_ENA, &ena) == 0)
			hrt = fmd_time_ena2hrt(hrt, ena);

		/*
		 * Now convert 'hrt' to an adjustable TOD based on the values
		 * in ed_tod_base which correspond to one another and are
		 * sampled before reboot using the old gethrtime() clock.
		 * fmd_event_recreate() will use this TOD value to re-assign
		 * the event an updated gethrtime() value based on the current
		 * value of the non-adjustable gethrtime() clock.  Phew.
		 */
		tod.ftv_sec = ed.ed_tod_base.sec;
		tod.ftv_nsec = ed.ed_tod_base.nsec;
		fmd_time_hrt2tod(ed.ed_hrt_base, &tod, hrt, &ftv);

		(void) nvlist_remove_all(nvl, FMD_EVN_TOD);
		(void) nvlist_add_uint64_array(nvl,
		    FMD_EVN_TOD, (uint64_t *)&ftv, 2);

		fmd_xprt_post(hdl, sysev_xprt, nvl, 0);
		sysev_stats.dump_replay.fmds_value.ui64++;

next:
		/*
		 * Reset the magic number for the event record to zero so that
		 * we do not replay the same event multiple times.
		 */
		ed.ed_magic = 0;

		if (pwrite64(fd, &ed, sizeof (ed), off) != sizeof (ed)) {
			fmd_hdl_error(hdl, "failed to mark dump "
			    "transport event (offset %llx)", (u_longlong_t)off);
		}

		off += sizeof (ed) + ed.ed_size;
	}

	(void) close(fd);
#endif
//done:
	(void) pthread_mutex_lock(&channel_mutex);
	channel_replay_wait = 0;
	(void) pthread_cond_broadcast(&channel_cv);
	(void) pthread_mutex_unlock(&channel_mutex);
}

static int
fmd_msg_handle(void *arg)
{
	fmd_msg_t *msg = (fmd_msg_t *)arg;
	nvlist_t *nvl;
	hrtime_t hrt = 0;
	int64_t *time;
	char tmp[4096 * 2];
	uint_t len;
	fmd_thread_t *tp;
	char *class;
	if (NULL == msg){
		return -1;	
	}else{
		if (FMD_HOTPLUG == msg->fm_type){
			sprintf(tmp, "echo fm_type: %d fm_buf: %s >> /msg_type", msg->fm_type, msg->fm_buf);
			system(tmp);
		}else if (FMD_DISK_ERR == msg->fm_type){
			if (nvlist_unpack(msg->fm_buf, msg->fm_len, &nvl, KM_SLEEP)){
					sprintf(tmp, "echo error 1 >> /msg_type");
					system(tmp);

					return -1;
			}else if(nvlist_lookup_int64_array(nvl, "time", &time, &len)){
					sprintf(tmp, "echo error 2 >> /msg_type");
					system(tmp);

					return -1;
			}else{
				sprintf(tmp, "echo time: %ld ,%ld .>>/msg_type", time[0], time[1]);
				system(tmp);
			}
		}else{
			sprintf(tmp, "echo unkown type >> /msg_type");
			system(tmp);
		}
	}
	nvlist_lookup_string(nvl, "class", &class);
	#if 0
	printf("class is %s. \n", class);
	#endif
	pthread_mutex_lock(&channel_mutex);
	if (channel_exiting == 1) {
		while (channel_xprt_refcnt > 0)
			pthread_cond_wait(&channel_cv, &channel_mutex);
		pthread_mutex_unlock(&channel_mutex);
		return EAGAIN;
	}
	
	channel_xprt_refcnt++;
	while (channel_replay_wait)
		pthread_cond_wait(&channel_cv, &channel_mutex);
	pthread_mutex_unlock(&channel_mutex);

	tp = fmd_alloc(sizeof (fmd_thread_t), FMD_SLEEP);
//	tp->thr_mod = mp;
	tp->thr_tid = pthread_self();
	tp->thr_func = NULL;
	tp->thr_arg = NULL;
	tp->thr_trdata = fmd_trace_create();
	tp->thr_trfunc = (fmd_tracebuf_f *)fmd.d_thr_trace;
	tp->thr_errdepth = 0;
	if (pthread_setspecific(fmd.d_key, tp) != 0)
		fmd_panic("failed to initialize thread key to %p", arg);

	fmd_xprt_post(channel_hdl, channel_xprt, nvl, hrt);
	pthread_mutex_lock(&channel_mutex);
	if (--channel_xprt_refcnt == 0 && channel_exiting == 1)
		pthread_cond_broadcast(&channel_cv);
	pthread_mutex_unlock(&channel_mutex);

	return 0;
}

void
channel_init(fmd_hdl_t *hdl)
{
	if (fmd_hdl_register(hdl, FMD_API_VERSION, &channel_info) != 0)
		return; /* invalid property settings */

	channel_hdl = hdl;
	
	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (channel_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&channel_stats);
#if 1
	channel_channel = fmd_prop_get_string(hdl, "channel");
	channel_class = fmd_prop_get_string(hdl, "class");
	channel_device = fmd_prop_get_string(hdl, "device");
	channel_sid = fmd_prop_get_string(hdl, "sid");
#endif

	channel_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY |
	    FMD_XPRT_CACHE_AS_LOCAL, NULL, NULL);
	if(channel_xprt == NULL){
		fmd_hdl_abort(hdl, "failed to open xprt.\n");
		exit(-1);
	}
	fmd_timer_install(hdl, NULL, NULL, 0);
	fmd_transport_client_register((void (*)(void *))fmd_msg_handle);

}

void
channel_fini(fmd_hdl_t *hdl)
{
	fmd_transport_client_deregister();
	if (channel_xprt != NULL) {
		/*
		 * Wait callback returns before destroy the transport.
		 */
		(void) pthread_mutex_lock(&channel_mutex);
		channel_exiting = 1;
		while (channel_xprt_refcnt > 0)
			(void) pthread_cond_wait(&channel_cv, &channel_mutex);
		(void) pthread_mutex_unlock(&channel_mutex);
		fmd_xprt_close(hdl, channel_xprt);
	}

#if 0
	fmd_prop_free_string(hdl, channel_class);
	fmd_prop_free_string(hdl, channel_channel);
	fmd_prop_free_string(hdl, channel_device);
	fmd_prop_free_string(hdl, channel_sid);
#endif
}

