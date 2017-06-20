#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/cn_hbx.h>
#include "cn_cluster.h"

#define	c_err	printf

struct cn_cluster {
	int	cc_fd;
	cn_cluster_rcvfunc	cc_rcv;
	pthread_t	cc_rcv_thread;
	int	cc_rcv_exit;
};

static struct cn_cluster *connector_cluster = NULL;

#ifndef	SOL_NETLINK
#define	SOL_NETLINK	270
#endif

static void *rcv_handler(void *arg)
{
	int len, err;
	char buf[BUFSIZ];
	struct iovec iov;
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct nlmsghdr *nh;
	struct cn_msg *cnmsg;
	int sock = connector_cluster->cc_fd;

	if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) {
		c_err("pthread_setcancelstate() failed: %s, error=%d\n",
			strerror(errno), errno);
		return NULL;
	}

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = CN_IDX_HBX;
	sa.nl_pid = getpid();

	while (!connector_cluster->cc_rcv_exit) {
		len = recvmsg(sock, &msg, 0);
		if (len < 0) {
			err = errno;
			c_err("recvmsg() failed: %s, error=%d\n", strerror(err), err);
			if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR)
				continue;
			else
				break;
		} else if (len == 0) {
			c_err("recvmsg() return 0, exit thread");
			break;
		}

		for (nh = (struct nlmsghdr *) buf; NLMSG_OK(nh, len);
			nh = NLMSG_NEXT(nh, len)) {
			c_err("nlmsghdr: type=%u, seq=%u\n", nh->nlmsg_type, nh->nlmsg_seq);
			cnmsg = (struct cn_msg *) NLMSG_DATA(nh);
			c_err("cn_msg: cb_id{%u, %u}, seq=%u, ack=%u, len=%u",
				cnmsg->id.idx, cnmsg->id.val,
				cnmsg->seq, cnmsg->ack, cnmsg->len);
			connector_cluster->cc_rcv(&cnmsg->data, cnmsg->len);
		}
	}

	return NULL;
}

static int setup_connector(void)
{
	int sock;
	struct sockaddr_nl sa;
	int nl_groups = CN_IDX_HBX;
	pthread_t tid;
	int ret = 0;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_CONNECTOR);
	if (sock < 0) {
		ret = errno;
		c_err("socket() failed: %s, error=%d\n", strerror(ret), ret);
		return ret;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = getpid();
	sa.nl_groups = nl_groups;
	if (bind(sock, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
		ret = errno;
		c_err("bind() failed: %s, error=%d\n", strerror(ret), ret);
		goto out;
	}

	if (setsockopt(sock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		&nl_groups, sizeof(nl_groups)) != 0) {
		ret = errno;
		c_err("setsockopt() failed: %s, error=%d\n", strerror(ret), ret);
		goto out;
	}

	connector_cluster->cc_fd = sock;
	connector_cluster->cc_rcv_exit = 0;
	if (pthread_create(&tid, NULL, rcv_handler, NULL) != 0) {
		ret = errno;
		c_err("pthread_create() failed: %s, error=%d\n", strerror(ret), ret);
		connector_cluster->cc_fd = 0;
		goto out;
	}
	connector_cluster->cc_rcv_thread = tid;

	return 0;
out:
	close(sock);
	return -ret;
}

static void cn_cluster_fini(void)
{
	if (connector_cluster != NULL) {
		if (connector_cluster->cc_rcv_thread > 0) {
			connector_cluster->cc_rcv_exit = 1;
			if (pthread_cancel(connector_cluster->cc_rcv_thread) != 0) {
				c_err("pthread_cancel() failed: %s, error=%d\n",
					strerror(errno), errno);
			}

			if (pthread_join(connector_cluster->cc_rcv_thread, NULL) != 0) {
				c_err("pthread_join() failed: %s, error=%d\n",
					strerror(errno), errno);
			} else {
				c_err("recv thread exit\n");
			}
		}

		if (connector_cluster->cc_fd > 0)
			close(connector_cluster->cc_fd);

		free(connector_cluster);
		connector_cluster = NULL;
	}
}

int cn_cluster_init(cn_cluster_rcvfunc rcv_func)
{
	int ret = 0;

	if (connector_cluster != NULL)
		cn_cluster_fini();

	if (rcv_func == NULL)
		return 0;

	connector_cluster = malloc(sizeof(struct cn_cluster));
	if (connector_cluster == NULL)
		return -ENOMEM;
	connector_cluster->cc_rcv = rcv_func;
	connector_cluster->cc_fd = 0;
	connector_cluster->cc_rcv_thread = 0;

	if ((ret = setup_connector()) != 0)
		cn_cluster_fini();

	return ret;
}