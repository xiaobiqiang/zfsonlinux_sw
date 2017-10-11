/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _FMD_RPC_ADM_H_RPCGEN
#define _FMD_RPC_ADM_H_RPCGEN

#include <rpc/rpc.h>

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <fmd_api.h>

enum fmd_adm_error {
	FMD_ADM_ERR_NOMEM = 1,
	FMD_ADM_ERR_PERM = 1 + 1,
	FMD_ADM_ERR_MODSRCH = 1 + 2,
	FMD_ADM_ERR_MODBUSY = 1 + 3,
	FMD_ADM_ERR_MODFAIL = 1 + 4,
	FMD_ADM_ERR_MODNOENT = 1 + 5,
	FMD_ADM_ERR_MODEXIST = 1 + 6,
	FMD_ADM_ERR_MODINIT = 1 + 7,
	FMD_ADM_ERR_MODLOAD = 1 + 8,
	FMD_ADM_ERR_RSRCSRCH = 1 + 9,
	FMD_ADM_ERR_RSRCNOTF = 1 + 10,
	FMD_ADM_ERR_SERDSRCH = 1 + 11,
	FMD_ADM_ERR_SERDFIRED = 1 + 12,
	FMD_ADM_ERR_ROTSRCH = 1 + 13,
	FMD_ADM_ERR_ROTFAIL = 1 + 14,
	FMD_ADM_ERR_ROTBUSY = 1 + 15,
	FMD_ADM_ERR_CASESRCH = 1 + 16,
	FMD_ADM_ERR_CASEOPEN = 1 + 17,
	FMD_ADM_ERR_XPRTSRCH = 1 + 18,
	FMD_ADM_ERR_CASEXPRT = 1 + 19,
	FMD_ADM_ERR_RSRCNOTR = 1 + 20,
};
typedef enum fmd_adm_error fmd_adm_error;

struct fmd_rpc_modstat {
	struct {
		u_int rms_buf_len;
		struct fmd_stat *rms_buf_val;
	} rms_buf;
	enum fmd_adm_error rms_err;
};
typedef struct fmd_rpc_modstat fmd_rpc_modstat;

struct fmd_rpc_modinfo {
	char *rmi_name;
	char *rmi_desc;
	char *rmi_vers;
	bool_t rmi_faulty;
	struct fmd_rpc_modinfo *rmi_next;
};
typedef struct fmd_rpc_modinfo fmd_rpc_modinfo;

struct fmd_rpc_modlist {
	enum fmd_adm_error rml_err;
	struct fmd_rpc_modinfo *rml_list;
	uint32_t rml_len;
};
typedef struct fmd_rpc_modlist fmd_rpc_modlist;

struct fmd_rpc_rsrcinfo {
	char *rri_fmri;
	char *rri_uuid;
	char *rri_case;
	bool_t rri_faulty;
	bool_t rri_unusable;
	bool_t rri_invisible;
	enum fmd_adm_error rri_err;
};
typedef struct fmd_rpc_rsrcinfo fmd_rpc_rsrcinfo;

struct fmd_rpc_rsrclist {
	struct {
		u_int rrl_buf_len;
		char *rrl_buf_val;
	} rrl_buf;
	uint32_t rrl_len;
	uint32_t rrl_cnt;
	enum fmd_adm_error rrl_err;
	bool_t rrl_all;
};
typedef struct fmd_rpc_rsrclist fmd_rpc_rsrclist;

struct fmd_rpc_serdinfo {
	char *rsi_name;
	uint64_t rsi_delta;
	uint32_t rsi_count;
	bool_t rsi_fired;
	uint64_t rsi_n;
	uint64_t rsi_t;
	struct fmd_rpc_serdinfo *rsi_next;
};
typedef struct fmd_rpc_serdinfo fmd_rpc_serdinfo;

struct fmd_rpc_serdlist {
	enum fmd_adm_error rsl_err;
	struct fmd_rpc_serdinfo *rsl_list;
	uint32_t rsl_len;
};
typedef struct fmd_rpc_serdlist fmd_rpc_serdlist;

struct fmd_rpc_xprtlist {
	struct {
		u_int rxl_buf_len;
		int32_t *rxl_buf_val;
	} rxl_buf;
	uint32_t rxl_len;
	enum fmd_adm_error rxl_err;
};
typedef struct fmd_rpc_xprtlist fmd_rpc_xprtlist;

struct fmd_rpc_caseinfo {
	struct {
		size_t rci_evbuf_len;
		char *rci_evbuf_val;
	} rci_evbuf;
	enum fmd_adm_error rci_err;
};
typedef struct fmd_rpc_caseinfo fmd_rpc_caseinfo;

struct fmd_rpc_caselist {
	struct {
		u_int rcl_buf_len;
		char *rcl_buf_val;
	} rcl_buf;
	uint32_t rcl_len;
	uint32_t rcl_cnt;
	enum fmd_adm_error rcl_err;
};
typedef struct fmd_rpc_caselist fmd_rpc_caselist;
extern void fmd_adm_1(struct svc_req *, SVCXPRT *);
extern void fmd_pceo_1(struct svc_req *, SVCXPRT *);
extern bool_t xdr_fmd_stat(XDR *, struct fmd_stat *);
#undef RW_READ_HELD
#undef RW_WRITE_HELD
#undef RW_LOCK_HELD
#undef MUTEX_HELD

struct fmd_adm_serdreset_1_argument {
	char *arg1;
	char *arg2;
};
typedef struct fmd_adm_serdreset_1_argument fmd_adm_serdreset_1_argument;

struct fmd_adm_rsrcacquit_1_argument {
	char *arg1;
	char *arg2;
};
typedef struct fmd_adm_rsrcacquit_1_argument fmd_adm_rsrcacquit_1_argument;

#define FMD_ADM 100169
#define FMD_ADM_VERSION_1 1

#if defined(__STDC__) || defined(__cplusplus)
#define FMD_ADM_MODINFO 1
extern  enum clnt_stat fmd_adm_modinfo_1(struct fmd_rpc_modlist *, CLIENT *);
extern  bool_t fmd_adm_modinfo_1_svc(struct fmd_rpc_modlist *, struct svc_req *);
#define FMD_ADM_MODCSTAT 2
extern  enum clnt_stat fmd_adm_modcstat_1(char *, struct fmd_rpc_modstat *, CLIENT *);
extern  bool_t fmd_adm_modcstat_1_svc(char *, struct fmd_rpc_modstat *, struct svc_req *);
#define FMD_ADM_MODDSTAT 3
extern  enum clnt_stat fmd_adm_moddstat_1(char *, struct fmd_rpc_modstat *, CLIENT *);
extern  bool_t fmd_adm_moddstat_1_svc(char *, struct fmd_rpc_modstat *, struct svc_req *);
#define FMD_ADM_MODGSTAT 4
extern  enum clnt_stat fmd_adm_modgstat_1(struct fmd_rpc_modstat *, CLIENT *);
extern  bool_t fmd_adm_modgstat_1_svc(struct fmd_rpc_modstat *, struct svc_req *);
#define FMD_ADM_MODLOAD 5
extern  enum clnt_stat fmd_adm_modload_1(char *, int *, CLIENT *);
extern  bool_t fmd_adm_modload_1_svc(char *, int *, struct svc_req *);
#define FMD_ADM_MODUNLOAD 6
extern  enum clnt_stat fmd_adm_modunload_1(char *, int *, CLIENT *);
extern  bool_t fmd_adm_modunload_1_svc(char *, int *, struct svc_req *);
#define FMD_ADM_MODRESET 7
extern  enum clnt_stat fmd_adm_modreset_1(char *, int *, CLIENT *);
extern  bool_t fmd_adm_modreset_1_svc(char *, int *, struct svc_req *);
#define FMD_ADM_MODGC 8
extern  enum clnt_stat fmd_adm_modgc_1(char *, int *, CLIENT *);
extern  bool_t fmd_adm_modgc_1_svc(char *, int *, struct svc_req *);
#define FMD_ADM_RSRCLIST 9
extern  enum clnt_stat fmd_adm_rsrclist_1(bool_t , struct fmd_rpc_rsrclist *, CLIENT *);
extern  bool_t fmd_adm_rsrclist_1_svc(bool_t , struct fmd_rpc_rsrclist *, struct svc_req *);
#define FMD_ADM_RSRCINFO 10
extern  enum clnt_stat fmd_adm_rsrcinfo_1(char *, struct fmd_rpc_rsrcinfo *, CLIENT *);
extern  bool_t fmd_adm_rsrcinfo_1_svc(char *, struct fmd_rpc_rsrcinfo *, struct svc_req *);
#define FMD_ADM_RSRCFLUSH 11
extern  enum clnt_stat fmd_adm_rsrcflush_1(char *, int *, CLIENT *);
extern  bool_t fmd_adm_rsrcflush_1_svc(char *, int *, struct svc_req *);
#define FMD_ADM_RSRCREPAIRED 12
extern  enum clnt_stat fmd_adm_rsrcrepaired_1(char *, int *, CLIENT *);
extern  bool_t fmd_adm_rsrcrepaired_1_svc(char *, int *, struct svc_req *);
#define FMD_ADM_SERDINFO 13
extern  enum clnt_stat fmd_adm_serdinfo_1(char *, struct fmd_rpc_serdlist *, CLIENT *);
extern  bool_t fmd_adm_serdinfo_1_svc(char *, struct fmd_rpc_serdlist *, struct svc_req *);
#define FMD_ADM_SERDRESET 14
extern  enum clnt_stat fmd_adm_serdreset_1(char *, char *, int *, CLIENT *);
extern  bool_t fmd_adm_serdreset_1_svc(char *, char *, int *, struct svc_req *);
#define FMD_ADM_LOGROTATE 15
extern  enum clnt_stat fmd_adm_logrotate_1(char *, int *, CLIENT *);
extern  bool_t fmd_adm_logrotate_1_svc(char *, int *, struct svc_req *);
#define FMD_ADM_CASEREPAIR 16
extern  enum clnt_stat fmd_adm_caserepair_1(char *, int *, CLIENT *);
extern  bool_t fmd_adm_caserepair_1_svc(char *, int *, struct svc_req *);
#define FMD_ADM_XPRTLIST 17
extern  enum clnt_stat fmd_adm_xprtlist_1(struct fmd_rpc_xprtlist *, CLIENT *);
extern  bool_t fmd_adm_xprtlist_1_svc(struct fmd_rpc_xprtlist *, struct svc_req *);
#define FMD_ADM_XPRTSTAT 18
extern  enum clnt_stat fmd_adm_xprtstat_1(int32_t , struct fmd_rpc_modstat *, CLIENT *);
extern  bool_t fmd_adm_xprtstat_1_svc(int32_t , struct fmd_rpc_modstat *, struct svc_req *);
#define FMD_ADM_CASELIST 19
extern  enum clnt_stat fmd_adm_caselist_1(struct fmd_rpc_caselist *, CLIENT *);
extern  bool_t fmd_adm_caselist_1_svc(struct fmd_rpc_caselist *, struct svc_req *);
#define FMD_ADM_CASEINFO 20
extern  enum clnt_stat fmd_adm_caseinfo_1(char *, struct fmd_rpc_caseinfo *, CLIENT *);
extern  bool_t fmd_adm_caseinfo_1_svc(char *, struct fmd_rpc_caseinfo *, struct svc_req *);
#define FMD_ADM_RSRCREPLACED 21
extern  enum clnt_stat fmd_adm_rsrcreplaced_1(char *, int *, CLIENT *);
extern  bool_t fmd_adm_rsrcreplaced_1_svc(char *, int *, struct svc_req *);
#define FMD_ADM_RSRCACQUIT 22
extern  enum clnt_stat fmd_adm_rsrcacquit_1(char *, char *, int *, CLIENT *);
extern  bool_t fmd_adm_rsrcacquit_1_svc(char *, char *, int *, struct svc_req *);
#define FMD_ADM_CASEACQUIT 23
extern  enum clnt_stat fmd_adm_caseacquit_1(char *, int *, CLIENT *);
extern  bool_t fmd_adm_caseacquit_1_svc(char *, int *, struct svc_req *);
#define FMD_ADM_GENXML 24
extern  enum clnt_stat fmd_adm_genxml_1(int *, CLIENT *);
extern  bool_t fmd_adm_genxml_1_svc(const int warning, int *rvp, struct svc_req *req);
extern int fmd_adm_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

#else /* K&R C */
#define FMD_ADM_MODINFO 1
extern  enum clnt_stat fmd_adm_modinfo_1();
extern  bool_t fmd_adm_modinfo_1_svc();
#define FMD_ADM_MODCSTAT 2
extern  enum clnt_stat fmd_adm_modcstat_1();
extern  bool_t fmd_adm_modcstat_1_svc();
#define FMD_ADM_MODDSTAT 3
extern  enum clnt_stat fmd_adm_moddstat_1();
extern  bool_t fmd_adm_moddstat_1_svc();
#define FMD_ADM_MODGSTAT 4
extern  enum clnt_stat fmd_adm_modgstat_1();
extern  bool_t fmd_adm_modgstat_1_svc();
#define FMD_ADM_MODLOAD 5
extern  enum clnt_stat fmd_adm_modload_1();
extern  bool_t fmd_adm_modload_1_svc();
#define FMD_ADM_MODUNLOAD 6
extern  enum clnt_stat fmd_adm_modunload_1();
extern  bool_t fmd_adm_modunload_1_svc();
#define FMD_ADM_MODRESET 7
extern  enum clnt_stat fmd_adm_modreset_1();
extern  bool_t fmd_adm_modreset_1_svc();
#define FMD_ADM_MODGC 8
extern  enum clnt_stat fmd_adm_modgc_1();
extern  bool_t fmd_adm_modgc_1_svc();
#define FMD_ADM_RSRCLIST 9
extern  enum clnt_stat fmd_adm_rsrclist_1();
extern  bool_t fmd_adm_rsrclist_1_svc();
#define FMD_ADM_RSRCINFO 10
extern  enum clnt_stat fmd_adm_rsrcinfo_1();
extern  bool_t fmd_adm_rsrcinfo_1_svc();
#define FMD_ADM_RSRCFLUSH 11
extern  enum clnt_stat fmd_adm_rsrcflush_1();
extern  bool_t fmd_adm_rsrcflush_1_svc();
#define FMD_ADM_RSRCREPAIRED 12
extern  enum clnt_stat fmd_adm_rsrcrepaired_1();
extern  bool_t fmd_adm_rsrcrepaired_1_svc();
#define FMD_ADM_SERDINFO 13
extern  enum clnt_stat fmd_adm_serdinfo_1();
extern  bool_t fmd_adm_serdinfo_1_svc();
#define FMD_ADM_SERDRESET 14
extern  enum clnt_stat fmd_adm_serdreset_1();
extern  bool_t fmd_adm_serdreset_1_svc();
#define FMD_ADM_LOGROTATE 15
extern  enum clnt_stat fmd_adm_logrotate_1();
extern  bool_t fmd_adm_logrotate_1_svc();
#define FMD_ADM_CASEREPAIR 16
extern  enum clnt_stat fmd_adm_caserepair_1();
extern  bool_t fmd_adm_caserepair_1_svc();
#define FMD_ADM_XPRTLIST 17
extern  enum clnt_stat fmd_adm_xprtlist_1();
extern  bool_t fmd_adm_xprtlist_1_svc();
#define FMD_ADM_XPRTSTAT 18
extern  enum clnt_stat fmd_adm_xprtstat_1();
extern  bool_t fmd_adm_xprtstat_1_svc();
#define FMD_ADM_CASELIST 19
extern  enum clnt_stat fmd_adm_caselist_1();
extern  bool_t fmd_adm_caselist_1_svc();
#define FMD_ADM_CASEINFO 20
extern  enum clnt_stat fmd_adm_caseinfo_1();
extern  bool_t fmd_adm_caseinfo_1_svc();
#define FMD_ADM_RSRCREPLACED 21
extern  enum clnt_stat fmd_adm_rsrcreplaced_1();
extern  bool_t fmd_adm_rsrcreplaced_1_svc();
#define FMD_ADM_RSRCACQUIT 22
extern  enum clnt_stat fmd_adm_rsrcacquit_1();
extern  bool_t fmd_adm_rsrcacquit_1_svc();
#define FMD_ADM_CASEACQUIT 23
extern  enum clnt_stat fmd_adm_caseacquit_1();
extern  bool_t fmd_adm_caseacquit_1_svc();
#define FMD_ADM_GENXML 24
extern  enum clnt_stat fmd_adm_genxml_1();
extern  bool_t fmd_adm_genxml_1_svc();
extern int fmd_adm_1_freeresult ();
#endif /* K&R C */

#define FMD_PCEO 824377500
#define FMD_PCEO_VERSION_1 1

#if defined(__STDC__) || defined(__cplusplus)
#define FMD_PCEO_GETSTATE 1
extern  enum clnt_stat fmd_pceo_getstate_1(int , int *, CLIENT *);
extern  bool_t fmd_pceo_getstate_1_svc(int , int *, struct svc_req *);
extern int fmd_pceo_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

#else /* K&R C */
#define FMD_PCEO_GETSTATE 1
extern  enum clnt_stat fmd_pceo_getstate_1();
extern  bool_t fmd_pceo_getstate_1_svc();
extern int fmd_pceo_1_freeresult ();
#endif /* K&R C */

/* the xdr functions */

#if defined(__STDC__) || defined(__cplusplus)
extern  bool_t xdr_fmd_adm_error (XDR *, fmd_adm_error*);
extern  bool_t xdr_fmd_rpc_modstat (XDR *, fmd_rpc_modstat*);
extern  bool_t xdr_fmd_rpc_modinfo (XDR *, fmd_rpc_modinfo*);
extern  bool_t xdr_fmd_rpc_modlist (XDR *, fmd_rpc_modlist*);
extern  bool_t xdr_fmd_rpc_rsrcinfo (XDR *, fmd_rpc_rsrcinfo*);
extern  bool_t xdr_fmd_rpc_rsrclist (XDR *, fmd_rpc_rsrclist*);
extern  bool_t xdr_fmd_rpc_serdinfo (XDR *, fmd_rpc_serdinfo*);
extern  bool_t xdr_fmd_rpc_serdlist (XDR *, fmd_rpc_serdlist*);
extern  bool_t xdr_fmd_rpc_xprtlist (XDR *, fmd_rpc_xprtlist*);
extern  bool_t xdr_fmd_rpc_caseinfo (XDR *, fmd_rpc_caseinfo*);
extern  bool_t xdr_fmd_rpc_caselist (XDR *, fmd_rpc_caselist*);
extern  bool_t xdr_fmd_adm_serdreset_1_argument (XDR *, fmd_adm_serdreset_1_argument*);
extern  bool_t xdr_fmd_adm_rsrcacquit_1_argument (XDR *, fmd_adm_rsrcacquit_1_argument*);

#else /* K&R C */
extern bool_t xdr_fmd_adm_error ();
extern bool_t xdr_fmd_rpc_modstat ();
extern bool_t xdr_fmd_rpc_modinfo ();
extern bool_t xdr_fmd_rpc_modlist ();
extern bool_t xdr_fmd_rpc_rsrcinfo ();
extern bool_t xdr_fmd_rpc_rsrclist ();
extern bool_t xdr_fmd_rpc_serdinfo ();
extern bool_t xdr_fmd_rpc_serdlist ();
extern bool_t xdr_fmd_rpc_xprtlist ();
extern bool_t xdr_fmd_rpc_caseinfo ();
extern bool_t xdr_fmd_rpc_caselist ();
extern bool_t xdr_fmd_adm_serdreset_1_argument ();
extern bool_t xdr_fmd_adm_rsrcacquit_1_argument ();

#endif /* K&R C */

#ifdef __cplusplus
}
#endif

#endif /* !_FMD_RPC_ADM_H_RPCGEN */
