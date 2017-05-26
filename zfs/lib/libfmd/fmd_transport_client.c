#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/fmd_transport.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define c_err  printf
#define MAX_PAYLOAD 256
#define UEVENT_MSG_LEN 4096
#define HAND_MSG	"hello kernel"
#define HAND_MSG_LEN 15

struct fmd_transport {
	int			ft_pid;
	int 		ft_fd;
	int 		ft_hotplug_exit;
	int			ft_hotplug_fd;
	pthread_t 	ft_hotplug_thread;
	int 		ft_exit;
	pthread_t 	ft_thread;
	fmd_msg_callback ft_handle;
};

static struct fmd_transport *fmd_manage = NULL;

fmd_msg_t *fmd_msg_new(int len)
{
	char *nbuf = NULL;
	fmd_msg_t *new = NULL;

	new = malloc(sizeof(fmd_msg_t));
	
	if (new != NULL) {
		nbuf = malloc(len);
		if (nbuf != NULL) {
			new->fm_len = len;
			new->fm_buf = nbuf;
			return (new);
		} 
	}

	return (NULL);
}

void fmd_msg_free(fmd_msg_t *fmsg)
{
	if (fmsg != NULL) {
		if (fmsg->fm_buf != NULL) {
			free(fmsg->fm_buf);
			fmsg->fm_buf = NULL;
		}

		free(fmsg);
		fmsg = NULL;
	}
}

void fmd_client_send_msg(const fmd_msg_t *fmsg)
{
	int hlen = 0;
	int state = 0;
	struct msghdr msg;
	struct iovec iov;
	char *fbuf = NULL;
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl dest_addr;

	if (fmsg == NULL || fmsg->fm_buf == NULL) {
		return;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, sizeof(struct nlmsghdr));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	fbuf = NLMSG_DATA(nlh);
	hlen = sizeof(int) + sizeof(fmd_type_t);
	memcpy(fbuf, (char*)fmsg, hlen);
	memcpy(fbuf + hlen, (char*)fmsg->fm_buf, fmsg->fm_len);

	iov.iov_base = (void*)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void*)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	state = sendmsg(fmd_manage->ft_fd, &msg, 0);
	if (state == -1) {
		c_err("get error sendmsg = %s.\n",strerror(errno));
	}
}

static void fmd_handwith_kernel(void)
{
	fmd_msg_t *new = fmd_msg_new(HAND_MSG_LEN);

	memcpy(new->fm_buf, "hello kernel", 12);

	fmd_client_send_msg(new);
	fmd_msg_free(new);
}

static void *fmd_hotplug_thread(void *arg)
{
	fd_set	fds;
	int ret = 0;
	int rlen = 0;
	struct timeval tv;
	fmd_msg_t *fmsg = NULL;
	int sock = fmd_manage->ft_hotplug_fd;
	char msg[UEVENT_MSG_LEN + 2] = {0};

	tv.tv_sec = 0;
	tv.tv_usec = 100 * 1000;
	while (fmd_manage->ft_hotplug_exit == 0) {
		FD_ZERO(&fds);
		FD_SET(sock, &fds);

		ret = select(sock + 1, &fds, NULL, NULL, &tv);
		if (ret <= 0)
			continue;

		if (FD_ISSET(sock, &fds)) {
			rlen = recv(sock, msg, UEVENT_MSG_LEN, 0);
			if (rlen > 0) {
				fmsg = fmd_msg_new(UEVENT_MSG_LEN);
				fmsg->fm_len = UEVENT_MSG_LEN;
				fmsg->fm_type =	FMD_HOTPLUG;
				memcpy(fmsg->fm_buf, msg, UEVENT_MSG_LEN);
				fmd_manage->ft_handle(fmsg);
				fmd_msg_free(fmsg);
			}
		}
	}

	pthread_exit(0);
}

static void *fmd_getmsg_thread(void *arg)
{
	fd_set fds;
	int ret = 0;
	int hlen = 0;
	int state = 0;
	struct timeval tv;
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_nl dest_addr;
	struct fmd_msg sfm = {0};
	struct fmd_msg *fmsg = NULL;
	struct nlmsghdr *nlh = NULL;
	int sock = fmd_manage->ft_fd;

	nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if (nlh == NULL)
		return (NULL);

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_groups = 0;
	dest_addr.nl_pid = 0; 

	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	iov.iov_base = (void*)nlh;
	iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	tv.tv_sec = 0;
	tv.tv_usec = 100 * 1000;
	hlen = sizeof(int) + sizeof(fmd_type_t);
	while (fmd_manage->ft_exit == 0) {
		FD_ZERO(&fds);
		FD_SET(sock, &fds);

		ret = select(sock + 1, &fds, NULL, NULL, &tv);
		if (ret <= 0)
			continue;

		if (FD_ISSET(sock, &fds)) {
			state = recvmsg(sock, &msg, 0);
			if (state > 0) {
				memcpy(&sfm, NLMSG_DATA(nlh), hlen);
				fmsg = fmd_msg_new(sfm.fm_len);
				fmsg->fm_type = sfm.fm_type;
				fmsg->fm_len = sfm.fm_len;
				memcpy(fmsg->fm_buf, NLMSG_DATA(nlh) + hlen, fmsg->fm_len);
				fmd_manage->ft_handle(fmsg);
				fmd_msg_free(fmsg);
			}
		}
	}

	pthread_exit(0);
}

static int fmd_transport_sock_init(void)
{
	int ret = 0;
	int sock = -1;
	pthread_t tid = 0;
	struct sockaddr_nl src_addr;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_FMD);
	if (sock < 0) {
		ret = errno;
		c_err("socket() failed: %s, error=%d\n", strerror(ret), ret);
		return (ret);
	}
	
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = fmd_manage->ft_pid;
	src_addr.nl_groups = 0;

	if (bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
		ret = errno;
		c_err("bind() failed: %s, error=%d\n", strerror(ret), ret);
		close(sock);
		return (-ret);
	}

	fmd_manage->ft_exit = 0;
	fmd_manage->ft_fd = sock;

	if (pthread_create(&tid, NULL, fmd_getmsg_thread, NULL) != 0) {
		ret = errno;
		fmd_manage->ft_fd = 0;
		c_err("pthread_create() failed: %s, error=%d\n", strerror(ret), ret);
		close(sock);
		return (-ret);
	}

	(void) fmd_handwith_kernel();

	fmd_manage->ft_thread = tid;

	return (0);
}

static int fmd_hotplug_sock_init(void)
{
	int ret = -1;
	int hot_sock = -1;
	pthread_t hot_pid = -1;
	const int bufsize = 64 * 1024;
	struct sockaddr_nl src_addr;

	memset(&src_addr, 0, sizeof(struct sockaddr_nl));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = fmd_manage->ft_pid;
	src_addr.nl_groups = 1;

	hot_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
	if (hot_sock < 0) {
		c_err("fmd get socket: %s\n",strerror(errno));
		return (-1);
	}

	setsockopt(hot_sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

	ret = bind(hot_sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
	if (ret < 0) {
		c_err("bind hotplug sock failed: %s\n",strerror(errno));
		close(hot_sock);
		return (-1);
	}

	fmd_manage->ft_hotplug_exit = 0;
	fmd_manage->ft_hotplug_fd = hot_sock;

	if (pthread_create(&hot_pid, NULL, fmd_hotplug_thread, NULL) != 0) {
		fmd_manage->ft_hotplug_fd = 0;
		c_err("pthread_create() failed: %s, error=%d\n", strerror(ret), ret);
		close(hot_sock);
		return (-1);
	}

	fmd_manage->ft_hotplug_thread = hot_pid;
	return (0);
}

void fmd_transport_client_deregister(void)
{
	if (fmd_manage != NULL) {
		if (fmd_manage->ft_thread > 0) {
			fmd_manage->ft_exit = 1;
			pthread_join(fmd_manage->ft_thread, NULL);
		}

		if (fmd_manage->ft_fd > 0)
			close(fmd_manage->ft_fd);

		if (fmd_manage->ft_hotplug_thread > 0) {
			fmd_manage->ft_hotplug_exit = 1;
			pthread_join(fmd_manage->ft_hotplug_thread, NULL);
		}

		if (fmd_manage->ft_hotplug_fd > 0)
			close(fmd_manage->ft_hotplug_fd);

		free(fmd_manage);
		fmd_manage = NULL;
	}
}

void fmd_transport_client_register(fmd_msg_callback do_msg_handle)
{
	int ret = 0;

	if (fmd_manage != NULL)
		fmd_transport_client_deregister();

	fmd_manage = (struct fmd_manage*)malloc(sizeof(struct fmd_transport));

	if (fmd_manage == NULL) {
		return (-ENOMEM);
	} else {
		fmd_manage->ft_pid = getpid();
		fmd_manage->ft_handle  = do_msg_handle;

		ret = fmd_transport_sock_init();
		if (ret != 0 ) {
			fmd_transport_client_deregister();
		} else {
			(void) fmd_hotplug_sock_init();
		}

		return (ret);
	}
}
