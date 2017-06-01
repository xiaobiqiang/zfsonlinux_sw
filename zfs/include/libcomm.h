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
#ifndef	_LIBCOMM_H
#define	_LIBCOMM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <mqueue.h>
#include <pthread.h>
#include <sys/list.h>

#define	COMM_SUCCESS	0
#define	COMM_FAILURE	1

#define	COMM_TYPE_CLIENT	0
#define	COMM_TYPE_SERVER	1

#define	COMM_STATE_INIT		0
#define	COMM_STATE_RUNNING	1
#define	COMM_STATE_STOP		2

typedef struct mq_msg {
	int			msg_id;
	char		in_file[256];
	char		in_sem_file[256];
	char		out_file[256];
	char		out_sem_file[256];
} mq_msg_t;

typedef struct mq_msg_node {
	list_node_t	node;
	mq_msg_t	msg;
} mq_msg_node_t;

typedef struct comm_context {
	int				comm_type;
	int				state;
	pthread_mutex_t	lock;
	char			mq_file[256];
	mqd_t			mqd;
	int				mq_buf_len;

	/* server */
	list_t			recv_queue;
	pthread_mutex_t	recv_lock;
	pthread_cond_t	queue_cv;
	pthread_t		recv_tid;
	pthread_t		process_tid;
} comm_context_t;

typedef void (*MSG_FN) (char *, int, char **, int *);

typedef struct msg_handler {
	int			msg_id;
	MSG_FN		handler;
} msg_handler_t;

typedef struct msg_handler_table {
	int				cnt;
	msg_handler_t 	elem[1];
} msg_handler_table_t;

int comm_init(int type, char *mq_file);
void comm_fini(void);
int comm_state(void);
void comm_register_msg_handler(msg_handler_t *handler_table);
int comm_send_msg(int msg_id, char *msg_buf, int msg_len, char **ret_buf, int *ret_len);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBCOMM_H */
