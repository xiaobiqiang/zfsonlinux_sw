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
 *
 * Copyright 2009 CeresData Co., Ltd.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _CLU_SYNC_H
#define _CLU_SYNC_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "clumgt_impl.h"
#include "libclumgt.h"


#define	CLU_SYNC_MSG_QUEUE_LEN	128
#define	CLU_SYNC_CMD_LEN	128

typedef struct sync_msg {
	int 		seq_num;
	int 		key;
	char		cmd[CLU_SYNC_CMD_LEN];
	uint64_t	guid;
} sync_msg_t;

typedef struct sync_msg_queue {
	char 		hostname[HOSTNAMELEN];
	sync_msg_t *sync_msg[CLU_SYNC_MSG_QUEUE_LEN];
	int			head, tail;
	int			queuesize;
	int			msg_num;
	int			msg_seq;
	pthread_cond_t	sync_cv;	
	pthread_mutex_t	sync_lock;	

	int			cur_sync_locate;
	uint64_t	node_guid[CLU_SYNC_MSG_QUEUE_LEN];
	
} sync_msg_queue_t;

typedef struct sync_master_info {
	char master_node[HOSTNAMELEN];

	char sync_master_node_flag;
	pthread_cond_t	sync_master_node_cv;	
	pthread_mutex_t	sync_master_node_lock;	
} sync_master_info_t;


typedef enum CLUMGT_CMD_ID {
	CMD_USERADD_REQ 		= 0x00000001,
	CMD_USERADD_RESP		= 0x00000002
} CLUMGT_CMD_ID_t;

typedef struct clu_sync_head {
	int			cmd_id;
	int			length;
	int			seq_start;
	int			seq_end;
	uint64_t	guid;
}clu_sync_head_t;

typedef struct clu_sync_req {
	clu_sync_head_t msg_head;
	char msg_body[1];
}clu_sync_req_t;

typedef struct clu_sync_resp {
	clu_sync_head_t msg_head;
	int err;
}clu_sync_resp_t;

typedef struct useradd_req {
	int cmd_length;
	char cmd[1];
}useradd_req_t;





void sync_initqueue(void);
int sync_send_msg_to_master_node(void);
int sync_deal_msg_from_master_node(char *msg, clumgt_response_t **presp);
int sync_receive_msg_form_agent(char *msg, clumgt_response_t **presp);
void *sync_send_msg_to_agent (void *arg);
void sync_init_master(void);
void *sync_choose_master(void *args);

int sync_probe_mster_node(char *msg, clumgt_response_t **presp);
int sync_send_current_locate_to_master(clumgt_response_t **presp);
int sync_agent_fullscale_process(char* buf, clumgt_response_t **presp);





#ifdef	__cplusplus
}
#endif

#endif /* _CLU_SYNC_H */

