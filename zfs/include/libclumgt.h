/*
 * Copyright (c) 2010, by Ceresdata, Inc.
 * All Rights Reserved
 */
#ifndef _LIBCLUMGT_H
#define	_LIBCLUMGT_H


#include <libzfs.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	HOSTNAMELEN			64
#define	MAXWORKERS			16
#define	HOSTURLLEN			32
#define	TMPBUFLEN			128

#define	TCPPORT				5555

#define	WAIT_RESP_TIMEOUT	120000
#define	REP_STATUS_TIMEOUT	5000
#define	REP_FCINFO_TIMEOUT	30000
#define	CHECK_SYNC_TIMEOUT	3000

#define	CLUMGT_CONFIG_FILE	"/etc/clumgt.config"
#define	CLUMGT_HOSTNAMEIGB0	"/etc/hostname.igb0"


typedef struct clumgt_response {
	uint32_t	resp_len;
	int32_t		ret_val;
	char 		hostname[HOSTNAMELEN];
	char		resp[1];
} clumgt_response_t;

typedef struct clumgt_request {
	uint32_t	req_type;
	uint32_t	req_timeout;
	uint32_t	req_len;
	char		req[1];
} clumgt_request_t;

typedef struct clumgt_host {
	char		hostname[HOSTNAMELEN];
	char		hosturl[HOSTURLLEN];
} clumgt_host_t;

typedef struct clumgt_thread_arg {
	void				**resp;
	clumgt_request_t	*req;
	clumgt_host_t		*c_host;
} clumgt_thread_arg_t;

extern int
clumgt_get_hostnode(clumgt_host_t *c_host, int *host_num, char *hostname);

extern int
clumgt_send_request(clumgt_request_t *req,
				void *resp, char *hostname, int *num);

#ifdef __cplusplus
}
#endif

#endif /* _LIBCLUMGT_H */
