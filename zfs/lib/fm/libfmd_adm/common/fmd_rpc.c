/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include <memory.h> /* for memset */
#include "fmd_rpc_adm.h"
#ifndef _KERNEL
#include <stdio.h>
#include <stdlib.h> /* getenv, exit */
#endif /* !_KERNEL */
#include <fmd_api.h>
extern void fmd_adm_1(struct svc_req *, SVCXPRT *);
extern void fmd_pceo_1(struct svc_req *, SVCXPRT *);
extern bool_t xdr_fmd_stat(XDR *, struct fmd_stat *);
#undef	RW_READ_HELD
#undef	RW_WRITE_HELD
#undef	RW_LOCK_HELD
#undef	MUTEX_HELD

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

enum clnt_stat 
fmd_adm_modinfo_1(struct fmd_rpc_modlist *clnt_res, CLIENT *clnt)
{
	 return (clnt_call(clnt, FMD_ADM_MODINFO,
		(xdrproc_t)xdr_void, NULL,
		(xdrproc_t)xdr_fmd_rpc_modlist, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_modcstat_1(char *arg1, struct fmd_rpc_modstat *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_MODCSTAT,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_fmd_rpc_modstat, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_moddstat_1(char *arg1, struct fmd_rpc_modstat *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_MODDSTAT,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_fmd_rpc_modstat, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_modgstat_1(struct fmd_rpc_modstat *clnt_res, CLIENT *clnt)
{
	 return (clnt_call(clnt, FMD_ADM_MODGSTAT,
		(xdrproc_t)xdr_void, NULL,
		(xdrproc_t)xdr_fmd_rpc_modstat, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_modload_1(char *arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_MODLOAD,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_modunload_1(char *arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_MODUNLOAD,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_modreset_1(char *arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_MODRESET,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_modgc_1(char *arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_MODGC,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_rsrclist_1(bool_t arg1, struct fmd_rpc_rsrclist *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_RSRCLIST,
		(xdrproc_t)xdr_bool, (caddr_t)&arg1,
		(xdrproc_t)xdr_fmd_rpc_rsrclist, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_rsrcinfo_1(char *arg1, struct fmd_rpc_rsrcinfo *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_RSRCINFO,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_fmd_rpc_rsrcinfo, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_rsrcflush_1(char *arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_RSRCFLUSH,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_rsrcrepaired_1(char *arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_RSRCREPAIRED,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_serdinfo_1(char *arg1, struct fmd_rpc_serdlist *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_SERDINFO,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_fmd_rpc_serdlist, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_serdreset_1(char *arg1, char *arg2, int *clnt_res, CLIENT *clnt)
{
	fmd_adm_serdreset_1_argument arg;
	arg.arg1 = arg1;
	arg.arg2 = arg2;
	return (clnt_call(clnt, FMD_ADM_SERDRESET,
		(xdrproc_t)xdr_fmd_adm_serdreset_1_argument, (caddr_t)&arg,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_logrotate_1(char *arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_LOGROTATE,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_caserepair_1(char *arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_CASEREPAIR,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_xprtlist_1(struct fmd_rpc_xprtlist *clnt_res, CLIENT *clnt)
{
	 return (clnt_call(clnt, FMD_ADM_XPRTLIST,
		(xdrproc_t)xdr_void, NULL,
		(xdrproc_t)xdr_fmd_rpc_xprtlist, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_xprtstat_1(int32_t arg1, struct fmd_rpc_modstat *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_XPRTSTAT,
		(xdrproc_t)xdr_int32_t, (caddr_t)&arg1,
		(xdrproc_t)xdr_fmd_rpc_modstat, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_caselist_1(struct fmd_rpc_caselist *clnt_res, CLIENT *clnt)
{
	 return (clnt_call(clnt, FMD_ADM_CASELIST,
		(xdrproc_t)xdr_void, NULL,
		(xdrproc_t)xdr_fmd_rpc_caselist, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_caseinfo_1(char *arg1, struct fmd_rpc_caseinfo *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_CASEINFO,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_fmd_rpc_caseinfo, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_rsrcreplaced_1(char *arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_RSRCREPLACED,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_rsrcacquit_1(char *arg1, char *arg2, int *clnt_res, CLIENT *clnt)
{
	fmd_adm_rsrcacquit_1_argument arg;
	arg.arg1 = arg1;
	arg.arg2 = arg2;
	return (clnt_call(clnt, FMD_ADM_RSRCACQUIT,
		(xdrproc_t)xdr_fmd_adm_rsrcacquit_1_argument, (caddr_t)&arg,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_caseacquit_1(char *arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_CASEACQUIT,
		(xdrproc_t)xdr_wrapstring, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_adm_genxml_1(int arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_ADM_GENXML,
		(xdrproc_t)xdr_int, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}

enum clnt_stat 
fmd_pceo_getstate_1(int arg1, int *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, FMD_PCEO_GETSTATE,
		(xdrproc_t)xdr_int, (caddr_t)&arg1,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res,
		TIMEOUT));
}
