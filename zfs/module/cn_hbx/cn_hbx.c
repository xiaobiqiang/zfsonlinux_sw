#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/atomic.h>
#include <sys/cn_hbx.h>

static struct cb_id cn_hbx_id = { CN_IDX_HBX, CN_VAL_HBX };
static atomic_t cn_hbx_seq = ATOMIC_INIT(0);

/* should call in single thread */
int cn_hbx_msg_send(const char *buf, size_t len)
{
	struct cn_msg *m;
	int err = 0;

	m = kzalloc(sizeof(*m) + len, GFP_ATOMIC);
	if (!m) {
		printk(KERN_ERR "failed to alloc cn_msg\n");
		return -ENOMEM;
	}

	memcpy(&m->id, &cn_hbx_id, sizeof(m->id));
	m->seq = atomic_read(&cn_hbx_seq);
	m->len = len;

	memcpy(m + 1, buf, m->len);

#ifdef USE_HENGWEI
	err = cn_netlink_send(m, 0, CN_IDX_HBX, GFP_ATOMIC);
#else
	err = cn_netlink_send(m, CN_IDX_HBX, GFP_ATOMIC);
#endif
	if (err < 0)
		printk(KERN_ERR "cn_netlink_send error %d\n", err);
	kfree(m);

	atomic_inc(&cn_hbx_seq);
	return err;
}

#if	0
static void cn_hbx_ack(int rcvd_seq, int rcvd_ack)
{
	struct cn_msg *m;
	int err = 0;

	m = kzalloc(sizeof(*m), GFP_ATOMIC);
	if (!m) {
		printk(KERN_ERR "failed to alloc cn_msg\n");
		return;
	}

	memcpy(&m->id, &cn_hbx_id, sizeof(m->id));
	m->seq = rcvd_seq;
	m->ack = rcvd_ack + 1;
	m->len = 0;

	err = cn_netlink_send(m, CN_IDX_HBX, GFP_ATOMIC);
	if (err < 0)
		printk(KERN_ERR "cn_netlink_send error %d\n", err);
	kfree(m);
}
#endif

static void cn_hbx_msg_cb(struct cn_msg *msg, struct netlink_skb_parms *nsp)
{
	printk(KERN_DEBUG "%s: %lu: idx=%x, val=%x, seq=%u, ack=%u, len=%d: %s.\n",
	        __func__, jiffies, msg->id.idx, msg->id.val,
	        msg->seq, msg->ack, msg->len,
	        msg->len ? (char *)msg->data : "");
}

#if defined(_KERNEL) && defined(HAVE_SPL)
static int __init cn_hbx_init(void)
{
	int err;

	if ((err = cn_add_callback(&cn_hbx_id, "cn_hbx",
		cn_hbx_msg_cb)) != 0) {
		printk(KERN_WARNING "cn_hbx failed to register, error %d\n", err);
		return err;
	}
	printk(KERN_INFO "cn_hbx registerd\n");

	return 0;
}

static void __exit cn_hbx_exit(void)
{
	cn_del_callback(&cn_hbx_id);
}

module_init(cn_hbx_init);
module_exit(cn_hbx_exit);

MODULE_DESCRIPTION("Connector hbx implementation");
MODULE_AUTHOR("sgguo@ceresdata.com");
MODULE_LICENSE("GPL v2");

EXPORT_SYMBOL(cn_hbx_msg_send);
#endif
