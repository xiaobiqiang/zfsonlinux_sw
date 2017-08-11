/*
 * Copyright (c) 2015, CeresData,Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBZFS_RPC_H
#define _LIBZFS_RPC_H

#include <rpc/rpc.h>
#include <rpc/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

bool_t xdr_info_string(XDR *xdrsp, char *ppstring);
bool_t xdr_argument(XDR *xdrsp, zfs_rpc_arg_t *sval);
bool_t xdr_backinfo(XDR *xdrsp, zfs_rpc_ret_t *sval);
int get_disks(char *ppstring); 

#define RPC_TRANS_VERS 1

#define	RPC_TRANS_PROG	0x31250099



void* zfs_rpc_server(void * ntype);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBZFS_SM_H */

