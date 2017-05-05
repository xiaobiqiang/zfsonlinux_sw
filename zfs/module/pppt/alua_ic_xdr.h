/*
 * Copyright 2012 Ceresdata, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ALUA_IC_XDR_H
#define	_SYS_ALUA_IC_XDR_H

#include <sys/pppt_ic_if.h>
#include <rpc/types.h>
#include <rpc/xdr.h>

#ifdef	__cplusplus
extern "C" {
#endif

char *alua_ic_encode_common(void *data, size_t *len);
stmf_ic_msg_t * alua_ic_decode_common(char *buf, size_t len);
boolean_t xdr_alua_ic_msg(XDR *xdrs, stmf_ic_msg_t *msg);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ALUA_IC_XDR_H */
