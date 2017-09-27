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
#include <sys/fm/util.h>
#include <pthread.h>

//#include <netdir.h>
#include <strings.h>
#include <alloca.h>
#include <limits.h>
#include <unistd.h>
#include <ucred.h>
#include <priv.h>
#include <rpc/rpc.h>

#include "fmd_rpc_api.h"
#include "fmd_rpc_adm.h"

#include "fmd_subr.h"
#include "fmd_error.h"
#include "fmd_thread.h"
#include "fmd_conf.h"
#include "fmd_api.h"
#include "fmd.h"

extern void fmd_pceo_1(struct svc_req *, SVCXPRT *);

/*
 * Define range of transient RPC program numbers to use for transient bindings.
 * These are defined in the Solaris ONC+ Developer's Guide, Appendix B, but
 * are cleverly not defined in any ONC+ standard system header file.
 */
#define	RPC_TRANS_MIN	0x40000000
#define	RPC_TRANS_MAX	0x5fffffff
#define RPC_TRANS_REMOTE	824377500
#define RPC_DOOR_VERSION	1

/*
 * We use our own private version of svc_create() which registers our services
 * only on loopback transports and enables an option whereby Solaris ucreds
 * are associated with each connection, permitting us to check privilege bits.
 */
static int
fmd_rpc_svc_create_local(void (*disp)(struct svc_req *, SVCXPRT *),
    rpcprog_t prog, rpcvers_t vers, uint_t ssz, uint_t rsz, int force)
{
	register SVCXPRT *xprt;
	
	if (force){
		pmap_unset(prog, vers);
		svc_unregister(prog, vers); /* clear stale rpcbind registrations */
	}

	xprt = svcudp_create(RPC_ANYSOCK);
	if (xprt == NULL) {
		fprintf (stderr, "%s", "cannot create udp service.");
		return(-1);
	}
	if (!svc_register(xprt, prog, vers, disp, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (TESTPROG, VERSION, udp).");
		return(-1);
	}

	xprt = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (xprt == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		return(-1);
	}
	if (!svc_register(xprt, prog, vers, disp, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (TESTPROG, VERSION, tcp).");
		return(-1);
	}

	svc_run ();
	fprintf (stderr, "%s", "svc_run returned");
	return (-1);

}
#if 0
static int
fmd_rpc_svc_create_romote(void)
{
	SVCXPRT *xprt = NULL;
	svc_register(xprt, RPC_TRANS_REMOTE, RPC_DOOR_VERSION, fmd_pceo_1, IPPROTO_UDP);

	return 1;
}
#endif
static int
fmd_rpc_svc_init(void (*disp)(struct svc_req *, SVCXPRT *),
    const char *name, const char *path, const char *prop,
    rpcprog_t pmin, rpcprog_t pmax, rpcvers_t vers,
    uint_t sndsize, uint_t rcvsize, int force)
{
	rpcprog_t prog;
	char buf[16];
	FILE *fp;

	for (prog = pmin; prog <= pmax; prog++) {
		if (fmd_rpc_svc_create_local(disp, prog, vers,
		    sndsize, rcvsize, force) == 0) {
			fmd_dprintf(FMD_DBG_RPC, "registered %s rpc service "
			    "as 0x%lx.%lx\n", name, prog, vers);

			/*
			 * To aid simulator scripts, save our RPC "digits" in
			 * the specified file for rendezvous with libfmd_adm.
			 */
			if (path != NULL && (fp = fopen(path, "w")) != NULL) {
				(void) fprintf(fp, "%ld\n", prog);
				(void) fclose(fp);
			}

			(void) snprintf(buf, sizeof (buf), "%ld", prog);
			(void) fmd_conf_setprop(fmd.d_conf, prop, buf);

			return (0);
		}
	}

	return (-1); /* errno is set for us */
}

void
fmd_rpc_init(void)
{
	int err, prog;
	uint64_t sndsize = 0, rcvsize = 0;
	const char *s;

	(void) fmd_conf_getprop(fmd.d_conf, "rpc.sndsize", &sndsize);
	(void) fmd_conf_getprop(fmd.d_conf, "rpc.rcvsize", &rcvsize);

	/*
	 * Infer whether we are the "default" fault manager or an alternate one
	 * based on whether the initial setting of rpc.adm.prog is non-zero.
	 */
	(void) fmd_conf_getprop(fmd.d_conf, "rpc.adm.prog", &prog);
	(void) fmd_conf_getprop(fmd.d_conf, "rpc.adm.path", &s);

	if (prog != 0) {
		err = fmd_rpc_svc_init(fmd_adm_1, "FMD_ADM", s, "rpc.adm.prog",
		    FMD_ADM, FMD_ADM, FMD_ADM_VERSION_1,
		    (uint_t)sndsize, (uint_t)rcvsize, TRUE);
	} else {
		err = fmd_rpc_svc_init(fmd_adm_1, "FMD_ADM", s, "rpc.adm.prog",
		    RPC_TRANS_MIN, RPC_TRANS_MAX, FMD_ADM_VERSION_1,
		    (uint_t)sndsize, (uint_t)rcvsize, FALSE);
	}

	if (err != 0)
		fmd_error(EFMD_EXIT, "failed to create rpc server bindings");

//	(void) fmd_rpc_svc_create_romote();
#if 0
	if (fmd_thread_create(fmd.d_rmod, (fmd_thread_f *)svc_run, NULL) == NULL)
		fmd_error(EFMD_EXIT, "failed to create rpc server thread");
#endif
}

void
fmd_rpc_fini(void)
{
	rpcprog_t prog;

	svc_exit(); /* force svc_run() threads to exit */

	(void) fmd_conf_getprop(fmd.d_conf, "rpc.adm.prog", &prog);
	svc_unregister(prog, FMD_ADM_VERSION_1);

	(void) fmd_conf_getprop(fmd.d_conf, "rpc.api.prog", &prog);
	svc_unregister(prog, FMD_API_VERSION_1);
}

/*
 * Utillity function to fetch the XPRT's ucred and determine if we should deny
 * the request.  For now, we implement a simple policy of rejecting any caller
 * who does not have the PRIV_SYS_CONFIG bit in their Effective privilege set,
 * unless the caller is loading a module, which requires all privileges.
 */
int
fmd_rpc_deny(struct svc_req *rqp)
{
#if 0
	ucred_t *ucp = alloca(sizeof(ucred_t));
	const priv_set_t *psp;

	if (!fmd.d_booted) {
		(void) pthread_mutex_lock(&fmd.d_fmd_lock);
		while (!fmd.d_booted)
			(void) pthread_cond_wait(&fmd.d_fmd_cv,
			    &fmd.d_fmd_lock);
		(void) pthread_mutex_unlock(&fmd.d_fmd_lock);
	}

	if (svc_getcallerucred(rqp->rq_xprt, &ucp) != 0 ||
	    (psp = ucred_getprivset(ucp, PRIV_EFFECTIVE)) == NULL)
		return (1); /* deny access if we can't get credentials */

#ifndef DEBUG
	/*
	 * For convenience of testing, we only require all privileges for a
	 * module load when running a non-DEBUG fault management daemon.
	 */
	if (rqp->rq_proc == FMD_ADM_MODLOAD)
		return (!priv_isfullset(psp));
#endif
	return (!priv_ismember(psp, PRIV_SYS_CONFIG));
#endif
	return 0;
}

