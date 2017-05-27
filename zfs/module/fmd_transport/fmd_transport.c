#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/atomic.h>

#include <linux/types.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <sys/fmd_transport.h>

#define MAX_PAYLOAD 256
#define MAX_CLIENT  50
#define HAND_MSG	"connect ok"
#define HAND_MSG_LEN 15

int pid = -1;
struct sock *nl_sk = NULL;
static DEFINE_MUTEX(rx_queue_mutex);

int fmd_module_is_exit(void)
{
	if (nl_sk == NULL || pid == -1)
		return (0);
	else
		return (1);
}

fmd_msg_t *fmd_kernel_msg_new(int len)
{
	char *nbuf = NULL;
	fmd_msg_t *new = NULL;

	new = kmem_zalloc(sizeof(fmd_msg_t), KM_SLEEP);
	
	if (new != NULL) {
		nbuf = kmem_zalloc(len, KM_SLEEP);
		if (nbuf != NULL) {
			new->fm_len = len;
			new->fm_buf = nbuf;
			return (new);
		} 
	}

	return (NULL);
}

void fmd_kernel_msg_free(fmd_msg_t *fmsg)
{
	if (fmsg != NULL) {
		if (fmsg->fm_buf != NULL) {
			kmem_free(fmsg->fm_buf, fmsg->fm_len);
			fmsg->fm_buf = NULL;
		}

		kmem_free(fmsg, sizeof(fmd_msg_t));
		fmsg = NULL;
	}
}

int fmd_kernel_send_msg(const fmd_msg_t *fmsg)
{
	int ret = -1;
	struct nlmsghdr *nlh = NULL;
	struct sk_buff *nl_skb = NULL;
	int len = NLMSG_SPACE(MAX_PAYLOAD);

	if (fmsg == NULL)
		return;

	nl_skb = alloc_skb(len, GFP_ATOMIC);
	if (nl_skb == NULL) {
		printk("fmd netlink alloc failure.\n");
		return;
	}

	nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_FMD, len, 0);
	if (nlh == NULL) {
		printk("nlmsg_put failaure.\n");
		return;
	}

	NETLINK_CB(nl_skb).dst_group = 0;

	int hlen = sizeof(int) + sizeof(fmd_type_t);
	memcpy(NLMSG_DATA(nlh), (char*)fmsg, hlen);
	memcpy(NLMSG_DATA(nlh) + hlen, (char*)fmsg->fm_buf, fmsg->fm_len);

	ret = netlink_unicast(nl_sk, nl_skb, pid, MSG_DONTWAIT);
	printk("unicate pid = %d\n",pid);

	return (ret);
}

static void fmd_if_rx(struct sk_buff *skb)
{
	int hlen = 0;
	char *msg = NULL;
	fmd_msg_t *smsg = NULL;
	struct sk_buff *rskb = NULL;
	struct nlmsghdr *nlh = NULL;
	mutex_lock(&rx_queue_mutex);

	rskb = skb_get(skb);
	if (rskb->len >= NLMSG_SPACE(0)) {
		nlh = nlmsg_hdr(rskb);
		msg = NLMSG_DATA(nlh);
		pid = nlh->nlmsg_pid;
		printk("fmd <pid = %d> handwith kernel success\n",pid);

		hlen = sizeof(int) + sizeof(fmd_type_t);
		smsg = fmd_kernel_msg_new(HAND_MSG_LEN);
		smsg->fm_type = FMD_NOTE;
		memcpy(smsg->fm_buf, HAND_MSG, strlen(HAND_MSG));
		fmd_kernel_send_msg(smsg);
		fmd_kernel_msg_free(smsg);
	}

	mutex_unlock(&rx_queue_mutex);
}

struct netlink_kernel_cfg cfg = {
	.input = fmd_if_rx,
};

#if defined(_KERNEL) && defined(HAVE_SPL)
static int fmd_transport_init(void)
{
	nl_sk = netlink_kernel_create(&init_net, NETLINK_FMD, &cfg);

	if (!nl_sk) {
		printk(KERN_ERR "fmd create netlink socket error.\n");
		return (-EIO);
	} else {
		printk(KERN_INFO "fmd create netlink socket ok.\n");
		return (0);
	}
}

static void fmd_transport_exit(void)
{
	if (nl_sk != NULL) {
		sock_release(nl_sk->sk_socket);
		nl_sk = NULL;
		pid = -1;
	} else {
		printk(KERN_INFO "fmd netlink module exited.\n");
	}
}

module_init(fmd_transport_init);
module_exit(fmd_transport_exit);

MODULE_DESCRIPTION("fmd transport process");
MODULE_AUTHOR("jxhuang@ceresdata.com");
MODULE_LICENSE("GPL v2");

EXPORT_SYMBOL(fmd_kernel_send_msg);
EXPORT_SYMBOL(fmd_kernel_msg_free);
EXPORT_SYMBOL(fmd_kernel_msg_new);
EXPORT_SYMBOL(fmd_module_is_exit);
#endif
