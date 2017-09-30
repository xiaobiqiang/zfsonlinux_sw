/*
 * Copyright 2015 Ceresdata, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * libzfs_rpctest for RPC communication module
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <rpc/rpc.h>
#include <syslog.h>
#include <signal.h>
#include "libzfs.h"
#include "libzfs_rpc.h"

#define TOTAL (30)

int zfs_rpc_call(char* host, uint32_t gettype, 
	zfs_rpc_arg_t *sendarg, zfs_rpc_ret_t *backarg)
{
	struct timeval time_out;
	CLIENT *client;
	enum clnt_stat stat;

	client = clnt_create(host, RPC_TRANS_PROG, RPC_TRANS_VERS, "udp");
	if (client == (CLIENT *) NULL ){
		clnt_pcreateerror("Couldn't create client");
		return (1);
	}
	time_out.tv_sec = TOTAL;
	time_out.tv_usec = 0;
	stat = clnt_call(client, gettype,
		(xdrproc_t)xdr_argument, (caddr_t)sendarg,
		(xdrproc_t)xdr_backinfo, (caddr_t)backarg,
		time_out);
	if (stat != RPC_SUCCESS){
		clnt_perror(client, "Call failed");
		return (1);
	}
	(void) clnt_destroy(client);
	
	return (0);
}


/*
  * Caller of trivial date service
  * usage: calltime hostname
  */
int zfs_rpc_msg_send(libzfs_handle_t *hdl, uint32_t gettype,
	char* backinfo)
{
	int ret = 0;
	int ii = 0;
	char *host = NULL;
	char *fsname = NULL;
	zfs_rpc_arg_t rpcarg;
	zfs_rpc_ret_t backarg;
	char groupip[GROUP_NODE_NUM*2*MAX_FSNAME_LEN] = {0}; 
	uint_t num = 0;
	uint_t Recv_total_length = 0;
	char oldip[MAX_FSNAME_LEN] = {0};

	memset(&rpcarg, 0, sizeof(rpcarg));
	memset(&backarg, 0, sizeof(backarg));
	ret = get_rpc_addr(hdl, GET_GROUP_IP, groupip, &num);
	if(ret){
		printf("Fail to get the rpc IP, ret: <%d>\n", ret);
		return (1);
	}

	rpcarg.filebuf = "-";
	rpcarg.propname = "-";
	rpcarg.value = "-";
	for(ii=0; ii<num/2; ii++){
		host = groupip+ii*2*MAX_FSNAME_LEN;
		fsname = groupip+(ii*2+1)*MAX_FSNAME_LEN;
		printf("The remote IP:[%s] remote fsname: <%s>\n", host, fsname);
		if(strcmp(oldip, host) == 0){
			/* (void) sleep(1); */
			continue;
		}
		do{
			backarg.backbuf = backinfo+rpcarg.backoffset;
			ret = zfs_rpc_call(host, gettype, &rpcarg, &backarg);
			if(ret)
			{
				printf("%s: Fail to call remote server!!!\n", __func__);
			}
			rpcarg.flag = 1;
			rpcarg.backoffset += backarg.backlen;
			Recv_total_length += backarg.backlen;
		}while(backarg.flag);
		memset(oldip, 0, MAX_FSNAME_LEN);
		strcpy(oldip, host);
		printf("The back message length is:[%d]\n", Recv_total_length);
	}
	
	return (ret);
}

/* 
  * The server dispatch function
  */
static void
get_my_info(struct svc_req *rqstp, SVCXPRT *transp)
{
	int ret = 0;
	zfs_rpc_arg_t argument;
	zfs_rpc_ret_t backarg;
	static char *rpc_back_buf = NULL;
	
	memset(&argument, '\0', sizeof(zfs_rpc_arg_t));
	memset(&backarg, '\0', sizeof(zfs_rpc_ret_t));
	svc_getargs(transp, (xdrproc_t)xdr_argument, (caddr_t)&argument);
	ret = zfs_rpc_back_proc(rqstp->rq_proc, &rpc_back_buf, &argument, &backarg);
	svc_freeargs(transp, (xdrproc_t)xdr_argument, (caddr_t)&argument);
	if(!svc_sendreply(transp, (xdrproc_t)xdr_backinfo, (caddr_t)&backarg)){
		svcerr_systemerr(transp);
	}
	if(backarg.flag == 0 && rpc_back_buf)
	{
		free(rpc_back_buf);
		rpc_back_buf = NULL;
	}
}


static void 
unregister_svc(int sig)
{
	if (SIGINT == sig){
		svc_unregister(RPC_TRANS_PROG, RPC_TRANS_VERS);
		printf("%s %d: svc_run returned\n", __func__, __LINE__);
	}
	exit(0);
}

void* zfs_rpc_server(void)
{
	register SVCXPRT *transp;
	transp = svcudp_create(RPC_ANYSOCK);
	if (NULL == transp){
		printf("%s %d: cannot create service: udp.\n", __func__, __LINE__);
		return (NULL);
	}

	if (!svc_register(transp, RPC_TRANS_PROG, RPC_TRANS_VERS, get_my_info, IPPROTO_UDP)){
		printf("%s %d: unable to register (RPC_TRANS_PROG, RPC_TRANS_VERS, udp).\n", __func__, __LINE__);
		return (NULL);
	}
/*
	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (NULL == transp){
		printf("%s %d: cannot create service: tcp.\n", __func__, __LINE__);
		return (NULL);
	}
	if (!svc_register(transp, RPC_TRANS_PROG, RPC_TRANS_VERS, get_my_info, IPPROTO_TCP)){
		printf ("%s %d: unable to register (RPC_TRANS_PROG, RPC_TRANS_VERS, tcp).", __func__, __LINE__);
		return (NULL);
	}
*/
	printf("%s %d: Create RPC service SUCCESS---!!!\n", __func__, __LINE__);

	if (signal(SIGINT, unregister_svc) == SIG_ERR){
		svc_unregister(RPC_TRANS_PROG, RPC_TRANS_VERS);
		printf("%s %d: register exit function error\n", __func__, __LINE__);
		return (NULL);
	}
	svc_run();
	printf ("%s %d: svc_run returned\n", __func__, __LINE__);
	return (NULL);
}


bool_t
xdr_info_string(XDR *xdrsp, char *ppstring)
{
	return ((bool_t)xdr_string(xdrsp, &ppstring, RPC_SEND_RECV_SIZE));
}

bool_t
xdr_backinfo(XDR *xdrsp, zfs_rpc_ret_t *sval)
{
	if (!xdr_u_int(xdrsp, &sval->flag)){
		return (FALSE);
	}
	if (!xdr_u_int(xdrsp, &sval->backlen)){
		return (FALSE);
	}
	if (!xdr_bytes(xdrsp, &sval->backbuf,
		(uint_t *)&sval->backlen, RPC_SEND_RECV_SIZE)){
		return (FALSE);
	}
	
	return (TRUE);
}

bool_t
xdr_argument(XDR *xdrsp, zfs_rpc_arg_t *sval)
{
	int ii;
	if (!xdr_u_int(xdrsp, &sval->flag)){
		return (FALSE);
	}
	if (!xdr_u_int(xdrsp, &sval->bufcnt)){
		return (FALSE);
	}
	if (!xdr_u_int(xdrsp, &sval->backoffset)){
		return (FALSE);
	}
	if (!xdr_u_int(xdrsp, &sval->filelen)){
		return (FALSE);
	}

	if (!xdr_bytes(xdrsp, &sval->filebuf,
		(uint_t *)&sval->filelen, RPC_SEND_RECV_SIZE)){
		return (FALSE);
	}
	if (!xdr_string(xdrsp, &sval->propname, MAXPATHLEN)){
		return (FALSE);
	}
	if (!xdr_string(xdrsp, &sval->value, MAXPATHLEN)){
		return (FALSE);
	}

	for(ii=0; ii<sval->bufcnt; ii++)
	{
		if (!xdr_string(xdrsp, &sval->buf[ii], MAXPATHLEN)){
			return (FALSE);
		}
	}
	
	return (TRUE);
}


