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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <semaphore.h>
#include <syslog.h>
#include <error.h>
#include <errno.h>
#include <libcomm.h>

#define	SEND_SHM_PREFIX		"/comm_send"
#define	SEND_SHM_SEM_PREFIX	"/comm_send_sem"
#define	RECV_SHM_PREFIX		"/comm_recv"
#define	RECV_SHM_SEM_PREFIX	"/comm_recv_sem"

comm_context_t s_context;
msg_handler_t *s_handler_table = NULL;

int
comm_state(void)
{
	int state;
	pthread_mutex_lock(&s_context.lock);
	state = s_context.state;
	pthread_mutex_unlock(&s_context.lock);
	return (state);
}

static void
comm_set_state(int state)
{
	pthread_mutex_lock(&s_context.lock);
	s_context.state = state;
	pthread_mutex_unlock(&s_context.lock);
}

static MSG_FN
comm_find_msg_handler(int msg_id)
{
	int i;
	MSG_FN fn = NULL;

	if (!s_handler_table)
		return (NULL);
	
	for (i = 0; s_handler_table[i].msg_id != -1; i++) {
		if (s_handler_table[i].msg_id == msg_id) {
			fn = s_handler_table[i].handler;
			break;
		}
	}

	return (fn);
}

static int
comm_process_msg(mq_msg_t *msg)
{
	int in_fd, out_fd;
	sem_t *in_sem, *out_sem;
	char *in_buf, *out_buf, *buf = NULL;
	int in_len, out_len;
	struct stat file_stat;
	boolean_t has_input, has_output;
	MSG_FN fn;

	in_sem = sem_open(msg->in_sem_file, O_RDONLY);
	if (in_sem == SEM_FAILED) {
		syslog(LOG_ERR, "%s open sem %s failed: %s", __func__,
			msg->in_sem_file, strerror(errno));
		return (-1);
	}
	
	sem_wait(in_sem);
	sem_close(in_sem);

	if (strlen(msg->in_file) > 0)
		has_input = B_TRUE;
	else
		has_input = B_FALSE;

	if (has_input) {
		in_fd = shm_open(msg->in_file, O_RDWR, 0);
		if (in_fd < 0) {
			syslog(LOG_ERR, "%s open shm %s failed: %s", __func__,
				msg->in_file, strerror(errno));
			return (-1);
		}

		fstat(in_fd, &file_stat);
		in_len = file_stat.st_size;
		in_buf = (char *)mmap(NULL, in_len, PROT_READ | PROT_WRITE, 
			MAP_SHARED, in_fd, 0);
		if (in_buf == MAP_FAILED) {
			syslog(LOG_ERR, "%s mmap %s failed: %s", __func__,
				msg->in_file, strerror(errno));
			return (-1);
		}
	} else {
		in_buf = NULL;
		in_len = 0;		
	}
	
	fn = comm_find_msg_handler(msg->msg_id);
	if (fn)
		(*fn)(in_buf, in_len, &buf, &out_len);

	if (has_input) {
		if (munmap(in_buf, in_len) < 0) {
			syslog(LOG_ERR, "%s munmap %s failed: %s", __func__, 
				msg->in_file, strerror(errno));
			close(in_fd);
		}
	}

	if (strlen(msg->out_file) > 0)
		has_output = B_TRUE;
	else
		has_output = B_FALSE;

	if (has_output) {
		ASSERT(buf != NULL);
		ASSERT(out_len > 0);
		out_fd = shm_open(msg->out_file, O_RDWR | O_CREAT, 0666);
		if (out_fd < 0) {
			syslog(LOG_ERR, "%s open shm %s failed: %s", __func__,
				msg->out_file, strerror(errno));
		} else {
			ftruncate(out_fd, out_len);
			out_buf = (char *)mmap(NULL, out_len, PROT_READ | PROT_WRITE, 
				MAP_SHARED, out_fd, 0);
			if (out_buf == MAP_FAILED) {
				syslog(LOG_ERR, "%s mmap %s failed: %s", __func__,
					msg->out_file, strerror(errno));
			} else {
				memmove(out_buf, buf, out_len);
				if (munmap(out_buf, out_len) < 0)
					syslog(LOG_ERR, "%s munmap %s failed: %s", __func__,
						msg->out_file, strerror(errno));
			}
			close(out_fd);
		}
	}

	if (buf)
		free(buf);

	out_sem = sem_open(msg->out_sem_file, O_WRONLY);
	sem_post(out_sem);
	sem_close(out_sem);

	return (0);
}

void *
comm_process_msg_thr(void *arg)
{
	mq_msg_node_t *node;
	while (comm_state() != COMM_STATE_STOP) {
		pthread_mutex_lock(&s_context.recv_lock);
		node = list_remove_head(&s_context.recv_queue);
		if (node) {
			pthread_mutex_unlock(&s_context.recv_lock);
			/* process msg */
			comm_process_msg(&node->msg);
		} else {
			/* wait new msg */
			pthread_cond_wait(&s_context.queue_cv, &s_context.recv_lock);
			pthread_mutex_unlock(&s_context.recv_lock);
		}
	}

	return (0);
}

static int
comm_parse_msg(char *buf, int len)
{
	int pos = 0;
	mq_msg_t *msg;
	mq_msg_node_t *msg_node;
	
	while (pos < len) {
		if (pos + sizeof(mq_msg_t) > len)
			break;

		msg = (mq_msg_t *)&buf[pos];
		msg_node = malloc(sizeof(mq_msg_node_t));
		memcpy((char *)(&msg_node->msg), buf, sizeof(mq_msg_t));
		pthread_mutex_lock(&s_context.recv_lock);
		list_insert_tail(&s_context.recv_queue, msg_node);
		pthread_cond_signal(&s_context.queue_cv);
		pthread_mutex_unlock(&s_context.recv_lock);
		pos += sizeof(mq_msg_t);
	}

	if (pos != len)
		syslog(LOG_ERR, "%s parse len %d, len %d", __func__,
			pos, len);
	
	return (pos);
}

void *
comm_recv_thr(void *arg)
{
	char *buf;
	int buf_len;
	int recv_len;

	buf_len = s_context.mq_buf_len;
	buf = calloc(buf_len, 1);

	if (buf == NULL) {
		syslog(LOG_ERR, "%s alloc buf failed", __func__);
		pthread_exit(0);
	}
	
    while(s_context.state != COMM_STATE_STOP) {
		recv_len = mq_receive(s_context.mqd, buf, buf_len, 0);
		
        if (recv_len == -1) {
			if (errno != EINTR)
				syslog(LOG_ERR, "%s mq_receive failed %d", __func__,
					errno);
        } else {
        	comm_parse_msg(buf, recv_len);
		}
    }

	free(buf);
    return (0); 
}

static int
comm_open_mq(int type, char *mq_file)
{
	int mode = O_CREAT;
	struct mq_attr msgq_attr;
	
	if (type == COMM_TYPE_CLIENT)
		mode |= O_WRONLY;
	else
		mode |= O_RDONLY;

	strncpy(s_context.mq_file, mq_file, sizeof(s_context.mq_file));
	s_context.mqd = mq_open(mq_file, mode, 0666, NULL);
	if (s_context.mqd == (mqd_t)-1) {
		syslog(LOG_ERR, "%s mq_open %s failed %d", __func__,
			mq_file, errno);
		return (-1);
	}

    if (mq_getattr(s_context.mqd, &msgq_attr) < 0) {
        syslog(LOG_ERR, "%s mq_getattr failed %d", __func__,
			errno);
        return (-1);
    }

	s_context.mq_buf_len = msgq_attr.mq_msgsize;
	return (0);
}

static void
comm_close_mq(void)
{
	if (mq_close(s_context.mqd) < 0)
		syslog(LOG_ERR, "%s mq_close failed %d", __func__,
			errno);

	if (s_context.comm_type == COMM_TYPE_SERVER) {
		if (mq_unlink(s_context.mq_file) < 0)
			syslog(LOG_ERR, "%s mq_unlink failed %d", __func__,
				errno);

	}
}

int 
comm_init(int type, char *mq_file)
{
	int ret = 0;
	s_context.state = COMM_STATE_INIT;
	pthread_mutex_init(&s_context.lock, NULL);
	s_context.comm_type = type;
	list_create(&s_context.recv_queue, sizeof(mq_msg_node_t),
		offsetof(mq_msg_node_t, node));
	pthread_mutex_init(&s_context.recv_lock, NULL);
	pthread_cond_init(&s_context.queue_cv, NULL);
	ret = comm_open_mq(type, mq_file);
	
	if (type == COMM_TYPE_SERVER) {
		pthread_create(&s_context.process_tid, NULL, comm_process_msg_thr, NULL);
		pthread_create(&s_context.recv_tid, NULL, comm_recv_thr, NULL);
	}
	
	comm_set_state(COMM_STATE_RUNNING);
	return (ret);
}

void
comm_fini()
{
	void *status;
	comm_set_state(COMM_STATE_STOP);

	if (s_context.comm_type == COMM_TYPE_SERVER) {
		pthread_kill(s_context.recv_tid, SIGUSR1);
		pthread_join(s_context.recv_tid, &status);

		pthread_mutex_lock(&s_context.recv_lock);
		pthread_cond_signal(&s_context.queue_cv);
		pthread_mutex_unlock(&s_context.recv_lock);
		pthread_join(s_context.process_tid, &status);
	}

	comm_close_mq();
	pthread_cond_destroy(&s_context.queue_cv);
	pthread_mutex_destroy(&s_context.recv_lock);
	list_destroy(&s_context.recv_queue);
	pthread_mutex_destroy(&s_context.lock);
}

void
comm_register_msg_handler(msg_handler_t *handler_table)
{
	s_handler_table = handler_table;
}

int
comm_send_msg(int msg_id, char *msg_buf, int msg_len, char **ret_buf, int *ret_len)
{
	int in_fd, out_fd;
	sem_t *in_sem, *out_sem;
	char *in_buf, *out_buf;
	int out_len;
	struct stat file_stat;
	mq_msg_t mq_msg;
	pid_t pid = getpid();
	uint64_t tid = (uint64_t)pthread_self();
	int ret = COMM_FAILURE;

	if (comm_state() != COMM_STATE_RUNNING) {
		syslog(LOG_ERR, "%s comm isn't running", __func__);
		return (ret);
	}

	/* prepare msg for mq_send */
	memset(&mq_msg, 0, sizeof(mq_msg_t));
	mq_msg.msg_id = msg_id;
	snprintf(mq_msg.in_sem_file, sizeof(mq_msg.in_sem_file), "%s_%d_%lu", 
		SEND_SHM_SEM_PREFIX, pid, tid);
	snprintf(mq_msg.out_sem_file, sizeof(mq_msg.out_sem_file), "%s_%d_%lu", 
		RECV_SHM_SEM_PREFIX, pid, tid);
	if (ret_buf) {
		*ret_buf = NULL;
		snprintf(mq_msg.out_file, sizeof(mq_msg.out_file), "%s_%d_%lu", 
			RECV_SHM_PREFIX, pid, tid);
	}

	if (msg_buf) {
		snprintf(mq_msg.in_file, sizeof(mq_msg.in_file), "%s_%d_%lu", 
			SEND_SHM_PREFIX, pid, tid);
		in_fd = shm_open(mq_msg.in_file, O_RDWR | O_CREAT, 0666);
		if (in_fd < 0) {
			syslog(LOG_ERR, "%s open shm %s failed: %s", __func__,
				mq_msg.in_file, strerror(errno));
			goto done;
		}

		ftruncate(in_fd, msg_len);
		in_buf = (char *)mmap(NULL, msg_len, PROT_READ | PROT_WRITE, 
			MAP_SHARED, in_fd, 0);
		if (in_buf == MAP_FAILED) {
			syslog(LOG_ERR, "%s mmap %s failed: %s", __func__,
				mq_msg.in_file, strerror(errno));
			close(in_fd);
			goto done;
		} else {
			memmove(in_buf, msg_buf, msg_len);
			if (munmap(in_buf, msg_len) < 0) {
				syslog(LOG_ERR, "%s munmap %s failed: %s", __func__,
					mq_msg.in_file, strerror(errno));
				close(in_fd);
				goto done;
			}
		}
		
		close(in_fd);
	}

	in_sem = sem_open(mq_msg.in_sem_file, O_CREAT, 0666, 0);
	if (in_sem == SEM_FAILED) {
		syslog(LOG_ERR, "%s open sem %s failed: %s", __func__,
			mq_msg.in_sem_file, strerror(errno));
		goto done;
	}

	out_sem = sem_open(mq_msg.out_sem_file, O_CREAT, 0666, 0);
	if (out_sem == SEM_FAILED) {
		syslog(LOG_ERR, "%s open sem %s failed: %s", __func__,
			mq_msg.out_sem_file, strerror(errno));
		sem_close(in_sem);
		goto done;
	}

	sem_post(in_sem);
	sem_close(in_sem);

	if (mq_send(s_context.mqd, (char *)&mq_msg, sizeof(mq_msg), 0) < 0) {
		syslog(LOG_ERR, "%s mq_send failed: %s", __func__,
			strerror(errno));
		sem_close(out_sem);
		goto done;
	}

	sem_wait(out_sem);
	sem_close(out_sem);

	if (ret_buf) {
		out_fd = shm_open(mq_msg.out_file, O_RDWR, 0);
		if (out_fd < 0) {
			syslog(LOG_ERR, "%s open shm %s failed: %s", __func__,
				mq_msg.out_file, strerror(errno));
			goto done;
		}

		fstat(out_fd, &file_stat);
		out_len = file_stat.st_size;
		out_buf = (char *)mmap(NULL, out_len, PROT_READ | PROT_WRITE, 
			MAP_SHARED, out_fd, 0);
		if (out_buf == MAP_FAILED) {
			syslog(LOG_ERR, "%s mmap %s failed: %s", __func__,
				mq_msg.in_file, strerror(errno));
			close(out_fd);
			goto done;
		} else {
			*ret_buf = malloc(out_len);
			if (ret_len)
				*ret_len = out_len;
			memmove(*ret_buf, out_buf, out_len);
			if (munmap(out_buf, out_len) < 0) {
				syslog(LOG_ERR, "%s munmap %s failed: %s", __func__,
					mq_msg.out_file, strerror(errno));
				close(out_fd);
				goto done;
			}
		}
		
		close(out_fd);
		ret = COMM_SUCCESS;
	}else {
		ret = COMM_SUCCESS;
	}

done:
	if (strlen(mq_msg.in_file) > 0)
		shm_unlink(mq_msg.in_file);

	if (strlen(mq_msg.out_file) > 0)
		shm_unlink(mq_msg.out_file);
		
	if (strlen(mq_msg.in_sem_file) > 0)
		sem_unlink(mq_msg.in_sem_file);
	
	if (strlen(mq_msg.out_sem_file) > 0)
		sem_unlink(mq_msg.out_sem_file);
	
	return (ret);
}

