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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <fcntl.h>
#include <libipmi.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>

//#include <sys/bmc_intf.h>

#include "ipmi_impl.h"

#define IPMI_IOC_MAGIC			'i'
#define IPMICTL_RECEIVE_MSG_TRUNC	_IOWR(IPMI_IOC_MAGIC, 11, struct ipmi_recv)
#define IPMICTL_RECEIVE_MSG		_IOWR(IPMI_IOC_MAGIC, 12, struct ipmi_recv)
#define IPMICTL_SEND_COMMAND		_IOR(IPMI_IOC_MAGIC, 13, struct ipmi_req)
#define IPMICTL_REGISTER_FOR_CMD	_IOR(IPMI_IOC_MAGIC, 14, struct ipmi_cmdspec)
#define IPMICTL_UNREGISTER_FOR_CMD	_IOR(IPMI_IOC_MAGIC, 15, struct ipmi_cmdspec)
#define IPMICTL_SET_GETS_EVENTS_CMD	_IOR(IPMI_IOC_MAGIC, 16, int)
#define IPMICTL_SET_MY_ADDRESS_CMD	_IOR(IPMI_IOC_MAGIC, 17, unsigned int)
#define IPMICTL_GET_MY_ADDRESS_CMD	_IOR(IPMI_IOC_MAGIC, 18, unsigned int)
#define IPMICTL_SET_MY_LUN_CMD		_IOR(IPMI_IOC_MAGIC, 19, unsigned int)
#define IPMICTL_GET_MY_LUN_CMD		_IOR(IPMI_IOC_MAGIC, 20, unsigned int)

#define IPMI_SYSTEM_INTERFACE_ADDR_TYPE	0x0c
#define IPMI_BMC_CHANNEL		0xf

#define	BMC_DEV	"/dev/ipmi0"

/*
 * IPMI transport for /dev/bmc
 */

typedef struct ipmi_bmc {
	ipmi_handle_t	*ib_ihp;	/* ipmi handle */
	int		ib_fd;		/* /dev/bmc filedescriptor */
	uint32_t	ib_msgseq;	/* message sequence number */
	bmc_msg_t	*ib_msg;	/* message buffer */
	size_t		ib_msglen;	/* size of message buffer */
} ipmi_bmc_t;

struct ipmi_msg {
	unsigned char netfn;
        unsigned char cmd;
        unsigned short data_len;
        unsigned char *data;
};

struct ipmi_req {
	unsigned char *addr;
	unsigned int addr_len;
	long msgid;
	ipmi_cmd_t msg;
};

static void
ipmi_bmc_close(void *data)
{
	ipmi_bmc_t *ibp = data;

	ipmi_free(ibp->ib_ihp, ibp->ib_msg);

	(void) close(ibp->ib_fd);

	ipmi_free(ibp->ib_ihp, ibp);
}

static void *
ipmi_bmc_open(ipmi_handle_t *ihp)
{
	ipmi_bmc_t *ibp;
	int i = 0;
	
	if ((ibp = ipmi_zalloc(ihp, sizeof (ipmi_bmc_t))) == NULL)
		return (NULL);
	ibp->ib_ihp = ihp;

	/* open /dev/ipmi0 */
	if ((ibp->ib_fd = open(BMC_DEV, O_RDWR)) < 0) {
		ipmi_free(ihp, ibp);
		(void) ipmi_set_error(ihp, EIPMI_BMC_OPEN_FAILED, "%s",
		    strerror(errno));
		return (NULL);
	}
	
	if (ioctl(ibp->ib_fd, IPMICTL_SET_GETS_EVENTS_CMD, &i) < 0) {
		ipmi_set_error(ihp, EIPMI_BMC_OPEN_FAILED, "Could not enable event receiver");
		return NULL;
	}

	if ((ibp->ib_msg = (bmc_msg_t *)ipmi_zalloc(ihp, BUFSIZ)) == NULL) {
		ipmi_bmc_close(ibp);
		return (NULL);
	}
	ibp->ib_msglen = BUFSIZ;

	return (ibp);
}
#if 0
static int
ipmi_bmc_send(void *data, ipmi_cmd_t *cmd, ipmi_cmd_t *response,
    int *completion)
{
	ipmi_bmc_t *ibp = data;
	struct strbuf sb;
	int flags = 0;
	size_t msgsz;
	bmc_msg_t *msg;
	bmc_req_t *bmcreq;
	bmc_rsp_t *bmcrsp;

	/*
	 * The length of the message structure is equal to the size of the
	 * bmc_req_t structure, PLUS any additional data space in excess of
	 * the data space already reserved in the data member + <n> for
	 * the rest of the members in the bmc_msg_t structure.
	 */
	msgsz = offsetof(bmc_msg_t, msg) + sizeof (bmc_req_t) +
	    ((cmd->ic_dlen > SEND_MAX_PAYLOAD_SIZE) ?
	    (cmd->ic_dlen - SEND_MAX_PAYLOAD_SIZE) : 0);

	/* construct and send the message */
	if ((msg = ipmi_zalloc(ibp->ib_ihp, msgsz)) == NULL)
		return (-1);
	bmcreq = (bmc_req_t *)&msg->msg[0];

	msg->m_type = BMC_MSG_REQUEST;
	msg->m_id = ibp->ib_msgseq++;
	bmcreq->fn = cmd->ic_netfn;
	bmcreq->lun = cmd->ic_lun;
	bmcreq->cmd = cmd->ic_cmd;
	bmcreq->datalength = cmd->ic_dlen;
	(void) memcpy(bmcreq->data, cmd->ic_data, cmd->ic_dlen);
	sb.len = msgsz;
	sb.buf = (char *)msg;

	if (putmsg(ibp->ib_fd, NULL, &sb, 0) < 0) {
		ipmi_free(ibp->ib_ihp, msg);
		(void) ipmi_set_error(ibp->ib_ihp, EIPMI_BMC_PUTMSG, "%s",
		    strerror(errno));
		return (-1);
	}

	ipmi_free(ibp->ib_ihp, msg);

	/* get the response from the BMC */
	sb.buf = (char *)ibp->ib_msg;
	sb.maxlen = ibp->ib_msglen;

	if (getmsg(ibp->ib_fd, NULL, &sb, &flags) < 0) {
		(void) ipmi_set_error(ibp->ib_ihp, EIPMI_BMC_GETMSG, "%s",
		    strerror(errno));
		return (-1);
	}

	switch (ibp->ib_msg->m_type) {
	case BMC_MSG_RESPONSE:
		bmcrsp = (bmc_rsp_t *)&ibp->ib_msg->msg[0];

		response->ic_netfn = bmcrsp->fn;
		response->ic_lun = bmcrsp->lun;
		response->ic_cmd = bmcrsp->cmd;
		if (bmcrsp->ccode != 0) {
			*completion = bmcrsp->ccode;
			response->ic_dlen = 0;
			response->ic_data = NULL;
		} else {
			*completion = 0;
			response->ic_dlen = bmcrsp->datalength;
			response->ic_data = bmcrsp->data;
		}
		break;

	case BMC_MSG_ERROR:
		(void) ipmi_set_error(ibp->ib_ihp, EIPMI_BMC_RESPONSE, "%s",
		    strerror(ibp->ib_msg->msg[0]));
		return (-1);

	default:
		(void) ipmi_set_error(ibp->ib_ihp, EIPMI_BMC_RESPONSE,
		    "unknown BMC message type %d", ibp->ib_msg->m_type);
		return (-1);
	}

	return (0);
}
#endif
static int
ipmi_bmc_send(void *data, ipmi_cmd_t *cmd, 	ipmi_cmd_t *response,
    int *completion){
    ipmi_bmc_t *ibp = data;
	struct ipmi_req _req;
	static int curr_seq = 0;
	
	struct ipmi_system_interface_addr {
		int addr_type;
		short channel;
		unsigned char lun;
	} bmc_addr ={
		addr_type:	IPMI_SYSTEM_INTERFACE_ADDR_TYPE,
		channel:	IPMI_BMC_CHANNEL,
	};

	if (response == NULL){
		(void) ipmi_set_error(ibp->ib_ihp, EIPMI_BMC_PUTMSG, "%s",
		    strerror(errno));
		return (-1);
	}
	
	memset(&_req, 0, sizeof(struct ipmi_req));

	bmc_addr.lun = response->ic_lun;
	_req.addr = (unsigned char *) &bmc_addr;
	_req.addr_len = sizeof(bmc_addr);
	_req.msgid = curr_seq++;
	
	if(ioctl(ibp->ib_fd,IPMICTL_SEND_COMMAND, &_req) < 0){
		(void) ipmi_set_error(ibp->ib_ihp, EIPMI_BMC_PUTMSG, "%s",
		    strerror(errno));
		return (-1);
	}
	memcpy(response, &_req.msg, sizeof(_req.msg));

	return 0;
}

ipmi_transport_t ipmi_transport_bmc = {
	ipmi_bmc_open,
	ipmi_bmc_close,
	ipmi_bmc_send
};
