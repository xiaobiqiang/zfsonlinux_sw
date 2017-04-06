#include <sys/ddi.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <sys/taskq.h>
#include <sys/list.h>
#include <sys/cluster_san.h>
#include <sys/cluster_target_mac.h>
#include <sys/fs/zfs.h>

#define	CLUSTER_MAC_TX_MAX_REPEAT_COUNT		3
#define TARGET_PORT_NUM		2
typedef struct TARGET_PORT_ARRAY
{
	struct net_device * dev;
	cluster_target_port_t *ctp;
}TARGET_PORT_ARRAY_t;

#ifndef SOLARIS
spinlock_t target_port_lock = SPIN_LOCK_UNLOCKED;
#endif
TARGET_PORT_ARRAY_t target_port_array[TARGET_PORT_NUM]= 
{
	{
		.dev = NULL,
		.ctp = NULL,
	},
	{
		.dev = NULL,
		.ctp = NULL,
	}
};
//extern pri_t minclsyspri, maxclsyspri;
uint32_t mac_package_fill=0;
uint32_t cts_mac_throttle_max = 512 * 1024;
uint32_t cts_mac_throttle_default = 128 * 1024;

uint8_t mac_broadcast_addr[ETHERADDRL] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

uint32_t cluster_target_mac_nrxworker = 1;

#ifndef SOLARIS
#define	ETHERTYPE_CLUSTERSAN	(0x8908)	/* cluster san */
#define	ether_header	ethhdr

static int cluster_rcv(struct sk_buff *skb, struct net_device *dev,
                   struct packet_type *pt, struct net_device *orig_dev);
static int cluster_inetdev_event(struct notifier_block *this, unsigned long event,
                         void *ptr);

static struct notifier_block cluster_netdev_notifier = {
	.notifier_call = cluster_inetdev_event,
};
static struct packet_type cluster_packet_type __read_mostly = {
                .type = cpu_to_be16(ETHERTYPE_CLUSTERSAN),
                .func = cluster_rcv,
};

static void freemsg(mblk_t *mp)
{
	kfree_skb(mp->skb);
	kfree(mp);
}
static int cluster_inetdev_event(struct notifier_block *this, unsigned long event,
                         void *ptr)
{
	struct net_device *notify_dev = netdev_notifier_info_to_dev(ptr);
	cluster_target_port_mac_t* ctp = NULL;
		
	if (target_port_array[0].ctp && target_port_array[0].ctp->target_private &&
		((cluster_target_port_mac_t*)target_port_array[0].ctp->target_private)->dev == notify_dev) {
		ctp = target_port_array[0].ctp->target_private;
	} else if (target_port_array[1].ctp && target_port_array[1].ctp->target_private &&
		((cluster_target_port_mac_t*)target_port_array[1].ctp->target_private)->dev == notify_dev) {
		ctp = target_port_array[1].ctp->target_private;
	}
	if (ctp) {
		if (event == NETDEV_UP)
			ctp->mac_link_state = CLUSTER_TARGET_MAC_LINK_STATE_UP;
		else if (event == NETDEV_DOWN)
			ctp->mac_link_state = CLUSTER_TARGET_MAC_LINK_STATE_DOWN;
	}
	
	return (0);
}
#endif
static cts_fragment_data_t *
cts_mac_mblk_to_fragment (void *target_port, void *rx_msg)
{

	cluster_target_port_t *ctp = target_port;
	mblk_t *mp = rx_msg;
	cts_fragment_data_t *fragment;
	struct ether_header *eth_head;
	cluster_target_msg_header_t *ct_head;
	uint64_t len;
	size_t head_len = sizeof(struct ether_header) +
		sizeof(cluster_target_msg_header_t) + mac_package_fill;
	int ret;


#ifdef SOLARIS
	eth_head = (struct ether_header *) mp->b_rptr;
	ct_head = (cluster_target_msg_header_t *)
		(mp->b_rptr + sizeof(struct ether_header));
	
	len = MBLKL(mp) - head_len - ct_head->ex_len;
	if (len != ct_head->len) {
#else
	eth_head = (struct ether_header *)(mp->skb->head + mp->skb->mac_header);
	ct_head = (cluster_target_msg_header_t *)
		(mp->skb->head + mp->skb->mac_header + mp->skb->mac_len);
	len = mp->skb->len - sizeof(cluster_target_msg_header_t) - ct_head->ex_len;
	if (len < ct_head->len) {
#endif
		cmn_err(CE_WARN, "cluster target session rx data err,"
			" len: 0x%llx, rx len: 0x%llx",
			ct_head->len, len);
		freemsg(mp);
		return (NULL);
	}

	ret = cluster_target_port_hold(ctp);
	if (ret != 0) {
		freemsg(mp);
		return (NULL);
	}
	fragment = kmem_zalloc(sizeof(cts_fragment_data_t), KM_SLEEP);
	fragment->target_port = ctp;
	fragment->rx_msg = mp;
	fragment->len = len;
	fragment->ex_len = ct_head->ex_len;
	fragment->ct_head = ct_head;
	fragment->phy_head = eth_head;
	
#ifdef SOLARIS
	if (len != 0) {
		fragment->offset = ct_head->offset;
		fragment->data = (char *)mp->b_rptr + head_len + ct_head->ex_len;
	}
	if (ct_head->ex_len != 0) {
		fragment->ex_head = (char *)mp->b_rptr + head_len;
	}
#else
	if (len != 0) {
		fragment->offset = ct_head->offset;
		fragment->data = (char *)(mp->skb->head + mp->skb->mac_header + head_len + ct_head->ex_len);
		mac_package_fill = ((ulong_t)fragment->data) & 3;
	}
	if (ct_head->ex_len != 0) {
		fragment->ex_head = (char *)(mp->skb->head + mp->skb->mac_header + head_len);
	}
#endif
	return (fragment);
	
}

static void cts_mac_fragment_free(cts_fragment_data_t *fragment)
{
	mblk_t *mp = fragment->rx_msg;
	if (mp != NULL) {
		freemsg(mp);
	}
	cluster_target_port_rele(fragment->target_port);
	kmem_free(fragment, sizeof(cts_fragment_data_t));
}

static void cluster_target_mac_rxmsg_free(void *rxmsg)
{
	mblk_t *mp = rxmsg;
	freemsg(mp);
}

static int
cluster_target_mac_send_mp(void *port, mblk_t *mblk)
{
	cluster_target_port_t *ctp = port;
	cluster_target_port_mac_t *port_mac = ctp->target_private;
	int repeat, ret = -1;
	uint32_t tx_failed_times = 0;
#ifdef SOLARIS
	mblk_t *ret_mblk;
	mac_tx_cookie_t ret_cookie;
#else
	int ret_cookie;
#endif
	boolean_t is_print = B_FALSE;

	if (port_mac == NULL) {
		tx_failed_times = atomic_inc_32_nv(&port_mac->tx_failed_times);
		if ((tx_failed_times == 1) || ((tx_failed_times % 100) == 0)) {
			cmn_err(CE_WARN, "cluster target port(%s) isn't init, times9%d)",
				ctp->link_name, tx_failed_times);
		}
		freemsg(mblk);
		return (ret);
	}

	if (port_mac->mac_link_state == CLUSTER_TARGET_MAC_LINK_STATE_DOWN) {
		tx_failed_times = atomic_inc_32_nv(&port_mac->tx_failed_times);
		if ((tx_failed_times == 1) || ((tx_failed_times % 100) == 0)) {
			cmn_err(CE_WARN, "cluster target port(%s) link state is down,"
				" times(%d)",
				ctp->link_name, tx_failed_times);
		}
		freemsg(mblk);
		return (ret);
	}

	for (repeat = 0; repeat < CLUSTER_MAC_TX_MAX_REPEAT_COUNT; ) {
#ifdef SOLARIS
		ret_cookie = mac_tx(port_mac->mac_cli_handle, mblk, 0,
			MAC_TX_NO_ENQUEUE | MAC_TX_NO_HOLD, &ret_mblk);
		if (ret_cookie != NULL) {
#else
		ret_cookie = dev_queue_xmit(mblk->skb);
		if (unlikely(ret_cookie != 0)) {
#endif
			tx_failed_times = atomic_inc_32_nv(&port_mac->tx_failed_times);
			if ((tx_failed_times % 100) == 0) {
				is_print = B_TRUE;
			}
			mutex_enter(&port_mac->mac_tx_mtx);
#ifdef SOLARIS
			(void) cv_reltimedwait(&port_mac->mac_tx_cv, &port_mac->mac_tx_mtx,
		    	drv_usectohz(100000), TR_CLOCK_TICK);
#else
			cv_timedwait(&port_mac->mac_tx_cv, &port_mac->mac_tx_mtx,
						ddi_get_lbolt() + msecs_to_jiffies(100000));
#endif
			mutex_exit(&port_mac->mac_tx_mtx);
			if (port_mac->mac_link_state == CLUSTER_TARGET_MAC_LINK_STATE_DOWN) {
				if (is_print) {
			    	cmn_err(CE_WARN, "cluster target port(%s) link state is down",
						ctp->link_name);
				}
				break;
			} else {
				if (is_print) {
					cmn_err(CE_WARN, "cluster target port send repeat");
				}
				repeat ++;
			}
		} else {
			atomic_swap_32(&port_mac->tx_failed_times, 0);
#ifndef 	SOLARIS
			kfree(mblk);
#endif
			ret = 0;
			break;
		}
	}

	if (ret) {
		if (is_print) {
			cmn_err(CE_WARN, "cluster target port(%s) send msg failed, times(%d)",
				ctp->link_name, tx_failed_times);
		}
#ifdef SOLARIS
		freemsg(ret_mblk);
#else
		freemsg(mblk);
#endif
	}
	return (ret);
}

static int
cluster_target_mac_send(void *port, void *fragmentation)
{
	cluster_target_mac_tran_data_t *mac_tran_data;
	int ret = 0;

	mac_tran_data = fragmentation;
	ret = cluster_target_mac_send_mp(port, mac_tran_data->mp);
	kmem_free(mac_tran_data, sizeof(cluster_target_mac_tran_data_t));
	return (ret);
}

static void cts_mac_tran_throttle_wait(cluster_target_session_t *cts)
{
	cluster_target_session_mac_t *sess_mac = cts->sess_target_private;
	clock_t ret;
#ifdef SOALRIS
	ret = cv_timedwait(&sess_mac->sess_fc_cv, &sess_mac->sess_fc_mtx,
		ddi_get_lbolt() + drv_usectohz(20000));
#else
	ret = cv_timedwait(&sess_mac->sess_fc_cv, &sess_mac->sess_fc_mtx,
		ddi_get_lbolt() + msecs_to_jiffies(20000));
#endif
	if (ret == -1) {
		sess_mac->sess_fc_throttle = sess_mac->sess_fc_throttle_max >> 1;
	}
}

static int cts_mac_tran_start(cluster_target_session_t *cts, void *fragmentation)
{
	cluster_target_port_t *ctp = cts->sess_port_private;
	cluster_target_session_mac_t *sess_mac = cts->sess_target_private;
	cluster_target_mac_tran_data_t *mac_tran_data = fragmentation;
	mblk_t *mp = mac_tran_data->mp;
	int ret;
	uint32_t fc_rx_bytes;

#ifdef SOLARIS
	cluster_target_msg_header_t *ct_head = (cluster_target_msg_header_t *)
		(mp->b_rptr + sizeof(struct ether_header));
#else
	cluster_target_msg_header_t *ct_head = (cluster_target_msg_header_t *)
		(mp->skb->head+mp->skb->mac_header+sizeof(struct ether_header));
#endif

	mutex_enter(&sess_mac->sess_fc_mtx);
	while (mac_tran_data->len > sess_mac->sess_fc_throttle) {
		cts_mac_tran_throttle_wait(cts);
	}
	sess_mac->sess_fc_throttle -= mac_tran_data->len;
	mutex_exit(&sess_mac->sess_fc_mtx);

	fc_rx_bytes = atomic_swap_32(&sess_mac->sess_fc_rx_bytes, 0);
	ct_head->fc_rx_len = fc_rx_bytes;
	ct_head->fc_tx_len = mac_tran_data->len;
	ret = cluster_target_mac_send_mp(ctp, mp);

	kmem_free(mac_tran_data, sizeof(cluster_target_mac_tran_data_t));
	return (ret);
}

static void cluster_target_mac_tran_data_free(void *fragmentation)
{
	cluster_target_mac_tran_data_t *mac_tran_data;

	if (fragmentation == NULL) {
		return;
	}

	mac_tran_data = fragmentation;
	if (mac_tran_data->mp != NULL) {
		freemsg(mac_tran_data->mp);
	}
	kmem_free(mac_tran_data, sizeof(cluster_target_mac_tran_data_t));
}

static mblk_t *
cluster_target_mac_get_mblk(char *data_seg,  uint32_t data_len, uint32_t hdr_len)
{
	mblk_t *head_mblk = NULL;
#ifdef SOLARIS
	int err;
	mblk_t *data_mblk = NULL;
	if (data_seg != NULL)  {
		data_mblk = esballoc((unsigned char *)data_seg, data_len, BPRI_HI, &frnop);

		if (data_mblk == NULL) {
			return (NULL);
		}
		data_mblk->b_wptr = data_mblk->b_rptr + data_len;
	}

	while ((head_mblk = allocb((size_t)(hdr_len), BPRI_MED)) == NULL) {
		if ((err = strwaitbuf((size_t)hdr_len, BPRI_LO)) != 0) {
			freemsg(data_mblk);
			return (NULL);
		}
	}
	
	if (data_mblk != NULL)
		head_mblk->b_cont = data_mblk;
#else
	head_mblk = kmalloc(sizeof(mblk_t), GFP_KERNEL);
	if (head_mblk) {
		head_mblk->skb = alloc_skb(data_len+hdr_len+2, GFP_KERNEL);
		if (head_mblk->skb) {
			skb_reserve(head_mblk->skb, 2);
			skb_reserve(head_mblk->skb, hdr_len);
			if (data_len != 0 && data_seg != NULL) {
				skb_put(head_mblk->skb, data_len);
				memcpy(head_mblk->skb->data, data_seg, data_len);
			}
		}
	}
#endif
	return (head_mblk);
}

static int cluster_target_mac_tran_data_fragment(
	void *src, void *dst, cluster_tran_data_origin_t *origin_data,
	cluster_target_tran_data_t **fragmentations, int *cnt)
{
	int ret = 0;
	int fragment_cnt = 0;
	int do_fragment_cnt = 0;
	int i;
	uint64_t fragment_offset = 0;
	uint64_t fragment_len = 0;
	uint64_t fragment_first_len = 0;
	uint64_t fragment_other_len = 0;
	uint64_t fragment_total_len = 0;
	char *fragment_data = NULL;
	mblk_t *head_mp;
	struct ether_header *eth_head;
	cluster_target_msg_header_t *ct_head;
	size_t head_len = sizeof(struct ether_header) +
		sizeof(cluster_target_msg_header_t) + mac_package_fill;
#ifdef SOLARIS
	void *ex_head;
#endif
	uint16_t ex_len;
	cluster_target_mac_tran_data_t *mac_tran_data;
	cluster_target_tran_data_t *data_array = NULL;
	cluster_target_port_mac_t *port_mac = src;
	cluster_target_session_mac_t *sess_mac = dst;

	if (origin_data->data_len == 0) {
		fragment_cnt = 1;
	} else {
		fragment_first_len = CLUSTER_MAC_MTU - head_len - origin_data->header_len;
		if (fragment_first_len > CLUSTER_MAC_FRAGMENT_LEN) {
			fragment_first_len = CLUSTER_MAC_FRAGMENT_LEN;
			fragment_cnt = (origin_data->data_len - 1) / CLUSTER_MAC_FRAGMENT_LEN + 1;
		} else {
			if (origin_data->data_len > fragment_first_len) {
				fragment_other_len = origin_data->data_len - fragment_first_len;
				fragment_cnt = (fragment_other_len -1) / CLUSTER_MAC_FRAGMENT_LEN + 1;
			}
			fragment_cnt += 1;
		}
	}
	data_array = kmem_zalloc((sizeof(cluster_target_tran_data_t) * fragment_cnt),
		KM_SLEEP);
	ex_len = origin_data->header_len;
	while (do_fragment_cnt < fragment_cnt) {
		if (origin_data->data_len != 0) {
			fragment_data = (char *)origin_data->data + fragment_total_len;
			if (ex_len != 0) {
				/* first fragment include header, send len maybe
				 * less than CLUSTER_MAC_FRAGMENT_LEN
				 */
				if (origin_data->data_len > fragment_first_len) {
					fragment_len = fragment_first_len;
				} else {
					fragment_len = origin_data->data_len;
				}
			} else {
				if (CLUSTER_MAC_FRAGMENT_LEN < (origin_data->data_len - fragment_total_len)) {
					fragment_len = CLUSTER_MAC_FRAGMENT_LEN;
				} else {
					fragment_len = (origin_data->data_len - fragment_total_len);
				}
			}
		}
		head_mp = cluster_target_mac_get_mblk(fragment_data, fragment_len,
			head_len + ex_len);
		if (head_mp == NULL) {
			ret = -1;
			cmn_err(CE_WARN, "%s: get mblk failed, msgtype: 0x%x",
				__func__, origin_data->msg_type);
			goto GET_MBLK_FAILED;
		}
#ifdef SOLARIS
		eth_head = (struct ether_header *)head_mp->b_rptr;
		ct_head = (cluster_target_msg_header_t *)
			(head_mp->b_rptr + sizeof(struct ether_header));
		bcopy(port_mac->mac_addr,
		    eth_head->ether_shost.ether_addr_octet, 
			ETHERADDRL);
		if (dst == CLUSTER_SAN_BROADCAST_SESS) {
			bcopy(mac_broadcast_addr,
			    eth_head->ether_dhost.ether_addr_octet, 
				ETHERADDRL);
		} else {
			bcopy(sess_mac->sess_daddr,
			    eth_head->ether_dhost.ether_addr_octet, 
				ETHERADDRL);
		}
		eth_head->ether_type = htons(ETHERTYPE_CLUSTERSAN);
#else
		head_mp->skb->dev = port_mac->dev;
		head_mp->skb->priority = 0;
		if ((ex_len != 0) && (origin_data->header != NULL)) {
			memcpy(skb_push(head_mp->skb, ex_len), origin_data->header, ex_len);
		}
		ct_head = (cluster_target_msg_header_t*)skb_push(head_mp->skb, mac_package_fill + sizeof(cluster_target_msg_header_t));
		eth_head = (struct ether_header *)skb_push(head_mp->skb, sizeof(struct ether_header));
		memcpy(eth_head->h_source, port_mac->dev->dev_addr, ETH_ALEN);
		if (dst == CLUSTER_SAN_BROADCAST_SESS) {
			memcpy(eth_head->h_dest, mac_broadcast_addr, ETH_ALEN);
		} else {
			memcpy(eth_head->h_dest, sess_mac->sess_daddr, ETH_ALEN);
		}
		eth_head->h_proto = __constant_htons(ETHERTYPE_CLUSTERSAN);
#endif
		ct_head->msg_type = origin_data->msg_type;
		ct_head->index = origin_data->index;
		ct_head->len = fragment_len;
		ct_head->total_len = origin_data->data_len;
		ct_head->offset = fragment_offset;
		ct_head->need_reply = (uint8_t)(origin_data->need_reply == B_TRUE);
		ct_head->ex_len = ex_len;
#ifdef SOLARIS
		head_mp->b_wptr = head_mp->b_rptr + head_len + ex_len;
#endif
		mac_tran_data = kmem_zalloc(sizeof(cluster_target_mac_tran_data_t), KM_SLEEP);
		mac_tran_data->mp = head_mp;
		mac_tran_data->len = head_len + ex_len + fragment_len;
		data_array[do_fragment_cnt].fragmentation = mac_tran_data;
#ifdef SOLARIS
		if ((ex_len != 0) && (origin_data->header != NULL)) {
			ex_head = (void *)((uintptr_t)ct_head + sizeof(cluster_target_msg_header_t));
			bcopy(origin_data->header, ex_head, ex_len);
			ex_len = 0;
		}
#endif
		fragment_offset += fragment_len;
		fragment_total_len += fragment_len;
		do_fragment_cnt++;
	}
	*fragmentations = data_array;
	*cnt = fragment_cnt;

	return (0);
GET_MBLK_FAILED:
	for (i = 0; i < do_fragment_cnt; i++) {
		if (data_array[i].fragmentation != NULL) {
			cluster_target_mac_tran_data_free(data_array[i].fragmentation);
		}
	}
	if (data_array != NULL) {
		kmem_free(data_array, sizeof(cluster_target_tran_data_t) * fragment_cnt);
	}

	return (ret);
}

#ifdef SOLARIS
static void
cluster_target_port_mac_notify(void *arg, mac_notify_type_t type)
{
	cluster_target_port_t *ctp = (cluster_target_port_t *)arg;
	cluster_target_port_mac_t *port_mac = ctp->target_private;

	if (port_mac == NULL) {
		return ;
	}
	/*
	 * We assume that the calls to this notification callback are serialized
	 * by MAC layer
	 */

	switch (type) {
	case MAC_NOTE_LINK:
		/*
		 * This notification is sent every time the MAC driver
		 * updates the link state.
		 */
		if (mac_stat_get(port_mac->mac_handle, MAC_STAT_LINK_UP) != 0) {
			if (port_mac->mac_link_state == CLUSTER_TARGET_MAC_LINK_STATE_UP) {
				break;
			}
			port_mac->mac_link_state = CLUSTER_TARGET_MAC_LINK_STATE_UP;
		} else {
			if (port_mac->mac_link_state == CLUSTER_TARGET_MAC_LINK_STATE_DOWN) {
				break;
			}
			port_mac->mac_link_state = CLUSTER_TARGET_MAC_LINK_STATE_DOWN;
		}
		break;
	default:
		break;
	}
}
#else
/*static int inetdev_event(struct notifier_block *this, unsigned long event,
			 void *ptr)
{
}*/
#endif

static void cluster_target_mac_session_init(cluster_target_session_t *cts, void *phy_head)
{
	struct ether_header *eth_head = phy_head;
	cluster_target_session_mac_t *sess_mac;

	sess_mac = kmem_zalloc(sizeof(cluster_target_session_mac_t), KM_SLEEP);
#ifdef SOLARIS
	bcopy(eth_head->ether_shost.ether_addr_octet, sess_mac->sess_daddr, ETHERADDRL);
#else
	bcopy(eth_head->h_source, sess_mac->sess_daddr, ETHERADDRL);
#endif

	mutex_init(&sess_mac->sess_fc_mtx, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sess_mac->sess_fc_cv, NULL, CV_DRIVER, NULL);
	sess_mac->sess_fc_throttle_max = sess_mac->sess_fc_throttle =
		cts_mac_throttle_default;
	sess_mac->sess_fc_rx_bytes = 0;

	cts->sess_target_private = sess_mac;
}

static void cluster_target_mac_session_fini(cluster_target_session_t *cts)
{
	cluster_target_session_mac_t *sess_mac = cts->sess_target_private;

	mutex_destroy(&sess_mac->sess_fc_mtx);
	cv_destroy(&sess_mac->sess_fc_cv);

	kmem_free(sess_mac, sizeof(cluster_target_session_mac_t));
	cts->sess_target_private = NULL;
}

static void ctp_mac_mplist_clear(ctp_mac_mplist_t *mplist)
{
	mblk_t *mp;
	mblk_t *next;
	mp = mplist->head;
	while (mp != NULL) {
		next = mp->b_next;
		freemsg(mp);
		mp = next;
	}
	mplist->head = NULL;
	mplist->tail = NULL;
}

static void ctp_mac_mplist_insert_tail(ctp_mac_mplist_t *mplist, mblk_t *mp)
{
	if (mplist->tail != NULL) {
		mplist->tail->b_next = mp;
	} else {
		mplist->head = mp;
	}
	mp->b_prev = mplist->tail;
	mp->b_next = NULL;
	mplist->tail = mp;
}

static mblk_t *ctp_mac_mplist_remove_head(ctp_mac_mplist_t *mplist)
{
	mblk_t *mp;
	mp = mplist->head;
	if (mp != NULL) {
		mplist->head = mp->b_next;
		if (mplist->head == NULL) {
			mplist->tail = NULL;
		}
	}
	return (mp);
}

static void
ctp_mac_rx_worker_wakeup(ctp_mac_rx_worker_t *w, mblk_t *mp)
{
	mutex_enter(&w->worker_mtx);
	ctp_mac_mplist_insert_tail(w->mplist_w, mp);
	atomic_inc_32(&w->worker_ntasks);
	if (w->worker_ntasks == 1) {
		cv_broadcast(&w->worker_cv);
	}
	mutex_exit(&w->worker_mtx);
}
#ifdef SOLARIS
static void
cluster_target_mac_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
	boolean_t loopback)
{
	cluster_target_port_t *ctp = (cluster_target_port_t *)arg;
	cluster_target_port_mac_t *port_mac = ctp->target_private;
	cluster_target_session_t *cts;
	ctp_mac_rx_worker_t *ctp_w;
	mblk_t *next;
	struct ether_header *eth_head;
	uint16_t frm_type;
	uint8_t	msg_type;
	int ret;

	ret = cluster_target_port_hold(ctp);
	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (ret != 0) {
			freemsg(mp);
			mp = next;
			continue;
		}

		frm_type = ntohs(*(uint16_t *)((uintptr_t)mp->b_rptr + 
			offsetof(struct ether_header, ether_type)));
		if (frm_type != ETHERTYPE_CLUSTERSAN) {
			freemsg(mp);
			mp = next;
			continue;
		}

		cluster_target_msg_header_t *ct_head = (cluster_target_msg_header_t *)
			(mp->b_rptr + sizeof(struct ether_header));
		ctp_w = &port_mac->rx_worker[ct_head->index % port_mac->rx_worker_n];
		ctp_mac_rx_worker_wakeup(ctp_w, mp);
		mp = next;
	}
	if (ret == 0) {
		cluster_target_port_rele(ctp);
	}
}
#else
static int cluster_rcv(struct sk_buff *skb, struct net_device *dev,
                   struct packet_type *pt, struct net_device *orig_dev)
{
	cluster_target_msg_header_t *ct_head;
	cluster_target_port_mac_t *port_mac;
	cluster_target_port_t *ctp;
	ctp_mac_rx_worker_t *ctp_w;
	uint16_t frm_type;
	mblk_t *mp;
	int ret;
	
	spin_lock_irq(&target_port_lock);
	if (target_port_array[0].dev == dev) {
		 ctp = target_port_array[0].ctp;
	} else if (target_port_array[1].dev == dev) {
		 ctp = target_port_array[1].ctp;
	} else {
		if (target_port_array[0].ctp && memcmp(((cluster_target_port_mac_t*)target_port_array[0].ctp->target_private)->mac_addr, dev->dev_addr, ETHERADDRL) == 0) {
			printk("target_port_array[0].dev=%p, dev=%p\n", target_port_array[0].dev, dev);
			ctp = target_port_array[0].ctp;
		} else if (target_port_array[1].ctp && memcmp(((cluster_target_port_mac_t*)target_port_array[1].ctp->target_private)->mac_addr, dev->dev_addr, ETHERADDRL) == 0) {
			printk("target_port_array[0].dev=%p, dev=%p\n", target_port_array[1].dev, dev);
			ctp = target_port_array[1].ctp;
		} else {
			printk("receive package. mac(%x%x %x%x %x%x)\n", 
				*(dev->dev_addr), *(dev->dev_addr+1),*(dev->dev_addr+2),
				*(dev->dev_addr+3),*(dev->dev_addr+4),*(dev->dev_addr+5));
			kfree_skb(skb);
			spin_unlock_irq(&target_port_lock);
			return (0);
		}
	}
	spin_unlock_irq(&target_port_lock);
	port_mac = ctp->target_private;
	
	ret = cluster_target_port_hold(ctp);
	
	frm_type = ntohs(*(uint16_t *)(skb->head + skb->mac_header + 
		offsetof(struct ether_header, h_proto)));
	if (frm_type != ETHERTYPE_CLUSTERSAN) {
		kfree_skb(skb);
		goto out;
	}

	ct_head = (cluster_target_msg_header_t *)(skb->head + skb->mac_header + sizeof(struct ether_header));
	ctp_w = &port_mac->rx_worker[ct_head->index % port_mac->rx_worker_n];
	mp = kzalloc(sizeof(mblk_t), GFP_KERNEL);
	mp->skb = skb;
	ctp_mac_rx_worker_wakeup(ctp_w, mp);
		
out:
	if (ret == 0) {
		cluster_target_port_rele(ctp);
	}
	return (0);
}
#endif

static int cts_mac_compare(cluster_target_session_t *cts, void *phy_head)
{
	struct ether_header *eth_head = phy_head;
	boolean_t value;
	cluster_target_session_mac_t *sess_mac = cts->sess_target_private;
#ifdef SOLARIS
	value = (bcmp(sess_mac->sess_daddr, eth_head->ether_shost.ether_addr_octet, ETHERADDRL));
#else
	value = (bcmp(sess_mac->sess_daddr, eth_head->h_source, ETHERADDRL));
#endif
	return (value);
}

static cluster_target_session_t *cts_mac_find_hold(
	cluster_target_port_t *ctp, void *etheraddr)
{
	cluster_target_session_t *cts;
	cluster_target_session_mac_t *sess_mac;
	mutex_enter(&ctp->ctp_lock);
	cts = list_head(&ctp->ctp_sesslist);
	while (cts != NULL) {
		sess_mac = cts->sess_target_private;
		if ((cts->sess_port_private == (void *)ctp) &&
			(bcmp(sess_mac->sess_daddr, etheraddr, ETHERADDRL) == 0)) {
			if (cluster_target_session_hold(cts, "cts_find") != 0) {
				cts = NULL;
			}
			break;
		}
		cts = list_next(&ctp->ctp_sesslist, cts);
	}
	mutex_exit(&ctp->ctp_lock);

	return (cts);
}

static void cts_mac_send_direct_impl(cluster_target_session_t *cts,
	uint8_t msg_type, uint32_t fc_tx_bytes, uint32_t fc_rx_bytes)
{
	uint64_t tx_index;
	mblk_t *mp;
	struct ether_header *eth_head;
	cluster_target_msg_header_t *ct_head;
	cluster_target_port_t *ctp = cts->sess_port_private;
	cluster_san_hostinfo_t *cshi = cts->sess_host_private;
	cluster_target_port_mac_t *port_mac = ctp->target_private;
	cluster_target_session_mac_t *sess_mac = cts->sess_target_private;
	size_t head_len = sizeof(struct ether_header) +
		sizeof(cluster_target_msg_header_t);

	if ((cts->sess_flags & CLUSTER_TARGET_SESS_FLAG_UINIT) != 0) {
		return;
	}
	if (ctp_tx_hold(ctp) != 0) {
		return;
	}
	tx_index = atomic_inc_64_nv(&cshi->host_tx_index);
	mp = cluster_target_mac_get_mblk(NULL, 0, head_len);
	if (mp == NULL) {
		ctp_tx_rele(ctp);
		cmn_err(CE_WARN, "%s: get mblk failed, msgtype: 0x%x",
			__func__, msg_type);
		return;
	}
#ifdef SOLARIS
	eth_head = (struct ether_header *) mp->b_rptr;
	ct_head = (cluster_target_msg_header_t *)
		(mp->b_rptr + sizeof(struct ether_header));
	bcopy(port_mac->mac_addr,
	    eth_head->ether_shost.ether_addr_octet, 
		ETHERADDRL);
	bcopy(sess_mac->sess_daddr,
	    eth_head->ether_dhost.ether_addr_octet, 
		ETHERADDRL);
	eth_head->ether_type = htons(ETHERTYPE_CLUSTERSAN);
#else
	mp->skb->dev = port_mac->dev;
	mp->skb->priority = 0;
	ct_head = (cluster_target_msg_header_t*)skb_push(mp->skb, sizeof(cluster_target_msg_header_t));
	eth_head = (struct ether_header *)skb_push(mp->skb, sizeof(struct ether_header));
	bcopy(port_mac->dev->dev_addr, eth_head->h_source, ETHERADDRL);
	bcopy(sess_mac->sess_daddr, eth_head->h_dest, ETHERADDRL);
	eth_head->h_proto = __constant_htons(ETHERTYPE_CLUSTERSAN);
#endif
	ct_head->msg_type = msg_type;
	ct_head->index = tx_index;
	ct_head->len = 0;
	ct_head->total_len = 0;
	ct_head->offset = 0;
	ct_head->need_reply = 0;
	ct_head->ex_len = 0;
	ct_head->fc_tx_len = fc_tx_bytes;
	ct_head->fc_rx_len = fc_rx_bytes;
#ifdef SOLARIS
	mp->b_wptr = mp->b_rptr + head_len;
#endif
	cluster_target_mac_send_mp(ctp, mp);
	ctp_tx_rele(ctp);
}

static void ctp_mac_rx_throttle_handle(cluster_target_port_t *ctp)
{
	cluster_target_session_t *cts;
	cluster_target_session_mac_t *sess_mac;
	uint32_t rx_bytes;
	uint32_t rx_throttle_bytes;

	mutex_enter(&ctp->ctp_lock);
	cts = list_head(&ctp->ctp_sesslist);
	while (cts != NULL) {
		sess_mac = cts->sess_target_private;
		rx_throttle_bytes = atomic_swap_32(&sess_mac->sess_fc_throttle_rx, 0);
		if (rx_throttle_bytes != 0) {
			mutex_enter(&sess_mac->sess_fc_mtx);
			sess_mac->sess_fc_throttle += rx_throttle_bytes;
			if (sess_mac->sess_fc_throttle > sess_mac->sess_fc_throttle_max) {
				sess_mac->sess_fc_throttle = sess_mac->sess_fc_throttle_max;
			}
			cv_broadcast(&sess_mac->sess_fc_cv);
			mutex_exit(&sess_mac->sess_fc_mtx);
		}

		rx_bytes = atomic_swap_32(&sess_mac->sess_fc_rx_bytes, 0);
		if (rx_bytes != 0) {
			cts_mac_send_direct_impl(cts, CLUSTER_SAN_MSGTYPE_NOP,
				0, rx_bytes);
		}
		cts = list_next(&ctp->ctp_sesslist, cts);
	}
	mutex_exit(&ctp->ctp_lock);
}

static void ctp_mac_rx_worker_handle(void *arg)
{
	ctp_mac_rx_worker_t	*w = (ctp_mac_rx_worker_t *)arg;
	cluster_target_port_t *ctp = w->ctp_private;
	cluster_target_port_mac_t *port_mac = ctp->target_private;
	cluster_target_session_t *cts;
	cluster_target_session_mac_t *sess_mac;
	cluster_san_hostinfo_t *cshi;
	mblk_t *mp;
	cts_rx_worker_t *cts_w;
	cts_worker_para_t *cts_para;
	cts_fragment_data_t *fragment;
	struct ether_header *eth_head;
	cluster_target_msg_header_t *ct_head;
	

	atomic_inc_32(&port_mac->rx_worker_n);
	mutex_enter(&w->worker_mtx);
	w->worker_flags |= CLUSTER_TARGET_TH_STATE_ACTIVE;
	while ((w->worker_flags & CLUSTER_TARGET_TH_STATE_STOP) == 0) {
		mutex_exit(&w->worker_mtx);
		while (1) {
			mp = ctp_mac_mplist_remove_head(w->mplist_r);
			if (mp != NULL) {
				atomic_dec_32(&w->worker_ntasks);
				fragment = cts_mac_mblk_to_fragment(ctp, mp);
				if (fragment == NULL) {
					continue;
				}
				/* put to session */
				eth_head = fragment->phy_head;
				ct_head = fragment->ct_head;
#ifdef SOLARIS
				cts = cts_mac_find_hold(ctp,
					(void *)eth_head->ether_shost.ether_addr_octet);
#else
				cts = cts_mac_find_hold(ctp,
					(void*)eth_head->h_source);
#endif
				if (cts != NULL) {
					sess_mac = cts->sess_target_private;
					atomic_swap_32(&cts->sess_hb_timeout_cnt, 0);
					atomic_add_32(&sess_mac->sess_fc_throttle_rx, ct_head->fc_rx_len);
					switch (ct_head->msg_type) {
					case CLUSTER_SAN_MSGTYPE_JOIN:
						if (cts->sess_linkstate == CTS_LINK_DOWN) {
							atomic_inc_64(&ctp->ref_count);
							taskq_dispatch(clustersan->cs_async_taskq,
								cs_join_msg_handle, fragment, TQ_SLEEP);
						} else {
							cts_mac_fragment_free(fragment);
						}
						cluster_target_session_rele(cts, "cts_find");
						break;
					case CLUSTER_SAN_MSGTYPE_REPLY:
						cshi = cts->sess_host_private;
						cts_reply_notify(cshi, ct_head->index);
						cluster_target_session_rele(cts, "cts_find");
						cts_mac_fragment_free(fragment);
						break;
					default:
						{
						atomic_add_32(&sess_mac->sess_fc_rx_bytes, ct_head->fc_tx_len);
						cts_w = &cts->sess_rx_worker[ct_head->index % cts->sess_rx_worker_n];
						cts_para = kmem_zalloc(sizeof(cts_worker_para_t), KM_SLEEP);
						cts_para->msg_type = ct_head->msg_type;
						cts_para->worker = cts_w;
						cts_para->fragment = fragment;
						cts_para->sess = cts;
						cts_para->index = ct_head->index;
						cts_rx_worker_wakeup(cts_w, cts_para);
						}
						break;
					}
				} else {
					switch (ct_head->msg_type) {
					case CLUSTER_SAN_MSGTYPE_JOIN:
						atomic_inc_64(&ctp->ref_count);
						taskq_dispatch(clustersan->cs_async_taskq,
							cs_join_msg_handle, fragment, TQ_SLEEP);
						break;
					default:
						cts_mac_fragment_free(fragment);
						break;
					}
				}
			} else {
				break;
			}
		}
		if (w->worker_ntasks == 0) { /* can't hold w->worker_mtx */
			ctp_mac_rx_throttle_handle(ctp);
		}
		mutex_enter(&w->worker_mtx);
		if (w->worker_ntasks == 0) {
			cv_timedwait(&w->worker_cv, &w->worker_mtx, ddi_get_lbolt() + msecs_to_jiffies(5000));
		} else {
			ctp_mac_mplist_t *mplist;
			mplist = w->mplist_r;
			w->mplist_r = w->mplist_w;
			w->mplist_w = mplist;
		}
	}
	mutex_exit(&w->worker_mtx);

	w->worker_flags = 0;
	atomic_dec_32(&port_mac->rx_worker_n);
}

static void ctp_mac_rx_worker_init(cluster_target_port_t *ctp)
{
	cluster_target_port_mac_t *port_mac = ctp->target_private;
	char *tq_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	int i;

	snprintf(tq_name, MAXNAMELEN, "ctp_rx_worker_tq_%s", ctp->link_name);
	port_mac->rx_worker_tq = taskq_create(tq_name,
		cluster_target_mac_nrxworker, minclsyspri,
		cluster_target_mac_nrxworker, cluster_target_mac_nrxworker,
		TASKQ_PREPOPULATE);
	kmem_free(tq_name, MAXNAMELEN);
	port_mac->rx_worker = (ctp_mac_rx_worker_t *)kmem_zalloc(
		sizeof (ctp_mac_rx_worker_t) * cluster_target_mac_nrxworker,
		KM_SLEEP);
	for (i = 0; i < cluster_target_mac_nrxworker; i++) {
		ctp_mac_rx_worker_t *w = &port_mac->rx_worker[i];
#ifdef SOLARIS
		mutex_init(&w->worker_mtx, NULL, MUTEX_DRIVER, NULL);
		cv_init(&w->worker_cv, NULL, CV_DRIVER, NULL);
#else
		mutex_init(&w->worker_mtx, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&w->worker_cv, NULL, CV_DEFAULT, NULL);
#endif
		w->worker_flags = 0;
		w->mplist1.head = NULL;
		w->mplist1.tail = NULL;
		w->mplist2.head = NULL;
		w->mplist2.tail = NULL;
		w->mplist_r = &w->mplist1;
		w->mplist_w = &w->mplist2;
		w->ctp_private = ctp;
		(void) taskq_dispatch(port_mac->rx_worker_tq, 
		    ctp_mac_rx_worker_handle, w, TQ_SLEEP);
	}
}

static void ctp_mac_get_info(void *target_port, nvlist_t *nvl_target)
{
	cluster_target_port_t *ctp = target_port;
	cluster_target_port_mac_t *port_mac = ctp->target_private;
	char *temp_name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	snprintf(temp_name, MAXNAMELEN, "[%02x:%02x:%02x:%02x:%02x:%02x]",
		port_mac->mac_addr[0], port_mac->mac_addr[1], port_mac->mac_addr[2],
		port_mac->mac_addr[3], port_mac->mac_addr[4], port_mac->mac_addr[5]);
	VERIFY(0 == nvlist_add_string(nvl_target, CS_NVL_MAC_ADDR, temp_name));

	kmem_free(temp_name, MAXNAMELEN);
}

static void cts_mac_get_info(cluster_target_session_t *cts, nvlist_t *nvl_sess)
{
	cluster_target_session_mac_t *sess_mac = cts->sess_target_private;
	char *temp_name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	snprintf(temp_name, MAXNAMELEN, "[%02x:%02x:%02x:%02x:%02x:%02x]",
		sess_mac->sess_daddr[0], sess_mac->sess_daddr[1], sess_mac->sess_daddr[2],
		sess_mac->sess_daddr[3], sess_mac->sess_daddr[4], sess_mac->sess_daddr[5]);
	VERIFY(0 == nvlist_add_string(nvl_sess, CS_NVL_MAC_ADDR, temp_name));

	kmem_free(temp_name, MAXNAMELEN);
}

int cluster_target_mac_port_init(
	cluster_target_port_t *ctp, char *link_name, nvlist_t *nvl_conf)
{
	cluster_target_port_mac_t *port_mac;
	int link_pri = 0;
#ifdef SOLARIS
	char *cli_name = NULL;
#endif
	int ret;

	port_mac = kmem_zalloc(sizeof(cluster_target_port_mac_t), KM_SLEEP);

#ifdef SOLARIS
	ret = mac_open_by_linkname(link_name, &port_mac->mac_handle);
	if (ret != 0) {
		cmn_err(CE_WARN, "cluster target port mac_open_by_linkname %s failed",
			link_name);
		goto mac_open_by_linkname_failed;
	}
	cli_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) sprintf(cli_name, "%s-%s", "ctp_port", ctp->link_name);
	ret = mac_client_open(port_mac->mac_handle,
	    &port_mac->mac_cli_handle, cli_name, MAC_OPEN_FLAGS_IS_ZFS_MIRROR);
	if (ret != 0) {
		goto mac_client_open_failed;
	}
	/*
	 * Cache the pointer of the immutable MAC inforamtion and
	 * the current and primary MAC address
	 */
	mac_unicast_primary_get(port_mac->mac_handle,
		port_mac->mac_addr);

	ret = mac_unicast_add(port_mac->mac_cli_handle, NULL, MAC_UNICAST_PRIMARY,
	    &port_mac->mac_unicst_handle, 0, &diag);
	if (ret != 0) {
	    cmn_err(CE_WARN, "%s mac_unicast_add failed", link_name);
		goto mac_client_open_failed;
	}
	if (force_promisc) {
		port_mac->mac_force_promisc = B_TRUE;
		ret = mac_promisc_add(port_mac->mac_cli_handle,
		    MAC_CLIENT_PROMISC_FILTERED, cluster_target_mac_rx, ctp,
		    &port_mac->mac_promisc_handle,
		    MAC_PROMISC_FLAGS_NO_TX_LOOP);
		if (ret != 0) {
			cmn_err(CE_WARN, "%s mac_promisc_add failed", link_name);
			goto mac_promisc_add_failed;
		}
	} else {
		mac_rx_set(port_mac->mac_cli_handle, cluster_target_mac_rx, ctp);
	}
	
	/* Get the link state, if it's up, we will need to notify client */
	port_mac->mac_link_state =
	    mac_stat_get(port_mac->mac_handle, MAC_STAT_LINK_UP)?
	    CLUSTER_TARGET_MAC_LINK_STATE_UP:CLUSTER_TARGET_MAC_LINK_STATE_DOWN;
	/*
	 * Add a notify function so that we get updates from MAC
	 */
	port_mac->mac_notify_handle = mac_notify_add(port_mac->mac_handle,
	    cluster_target_port_mac_notify, (void *)ctp);
	mutex_init(&port_mac->mac_tx_mtx, NULL, MUTEX_DRIVER, NULL);
	cv_init(&port_mac->mac_tx_cv, NULL, CV_DRIVER, NULL);
	kmem_free(cli_name, MAXNAMELEN);
#else
	port_mac->dev = dev_get_by_name(&init_net, link_name);
	if (NULL == port_mac->dev) {
		cmn_err(CE_WARN, "cluster target port get_dev_by_name %s failed", link_name);
		goto get_dev_by_name_failed;
	}
	port_mac->mac_link_state = (dev_get_flags(port_mac->dev) & IFF_UP) ? 
	    CLUSTER_TARGET_MAC_LINK_STATE_UP:CLUSTER_TARGET_MAC_LINK_STATE_DOWN;

	
	if (!port_mac->dev->addr_len)
		memset(port_mac->mac_addr, 0, ETHERADDRL);
	else
		memcpy(port_mac->mac_addr, port_mac->dev->dev_addr, ETHERADDRL);
	
	mutex_init(&port_mac->mac_tx_mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&port_mac->mac_tx_cv, NULL, CV_DEFAULT, NULL);
	spin_lock_irq(&target_port_lock);
	if (target_port_array[0].ctp == NULL) {
		target_port_array[0].ctp = ctp;
		target_port_array[0].dev = port_mac->dev;
	} else if (target_port_array[1].ctp == NULL) {
		target_port_array[1].ctp = ctp;
		target_port_array[1].dev = port_mac->dev;
	} else {
		dev_put(port_mac->dev);
		mutex_destroy(&port_mac->mac_tx_mtx);
		cv_destroy(&port_mac->mac_tx_cv);
		spin_unlock_irq(&target_port_lock);
		ret = -EPERM;
		goto get_dev_by_name_failed;
	}
	spin_unlock_irq(&target_port_lock);
#endif
	if (nvl_conf != NULL) {
		if (nvlist_lookup_int32(nvl_conf, "link_pri", &link_pri) == 0) {
			if (link_pri != 0) {
				ctp->pri = link_pri;
			}
		}
	}

	ctp->f_send_msg = cluster_target_mac_send;
	ctp->f_tran_free = cluster_target_mac_tran_data_free;
	ctp->f_tran_fragment = cluster_target_mac_tran_data_fragment;
	ctp->f_session_tran_start = cts_mac_tran_start;
	ctp->f_session_init = cluster_target_mac_session_init;
	ctp->f_session_fini = cluster_target_mac_session_fini;
	ctp->f_rxmsg_to_fragment = cts_mac_mblk_to_fragment;
	ctp->f_fragment_free = cts_mac_fragment_free;
	ctp->f_rxmsg_free = cluster_target_mac_rxmsg_free;
	ctp->f_cts_compare = cts_mac_compare;
	ctp->f_ctp_get_info = ctp_mac_get_info;
	ctp->f_cts_get_info = cts_mac_get_info;

	ctp->target_private = port_mac;
	ctp_mac_rx_worker_init(ctp);

	return (0);
	
#ifdef SOLARIS
mac_promisc_add_failed:
	mac_unicast_remove(port_mac->mac_cli_handle,
		    port_mac->mac_unicst_handle);
mac_client_open_failed:
	if (cli_name != NULL) {
		kmem_free(cli_name, MAXNAMELEN);
	}
	mac_close(port_mac->mac_handle);
#endif

#ifdef SOLARIS
mac_open_by_linkname_failed:
#else
get_dev_by_name_failed:
#endif
	kmem_free(port_mac, sizeof(cluster_target_port_mac_t));

	return (ret);
}
int cluster_proto_register(void)
{
	dev_add_pack(&cluster_packet_type);
	register_netdevice_notifier_rh(&cluster_netdev_notifier);
	return (0);
}
int cluster_proto_unregister(void)
{
	unregister_netdevice_notifier_rh(&cluster_netdev_notifier);
	dev_remove_pack(&cluster_packet_type);
	return (0);
}
static void ctp_mac_rx_worker_thread_exit(cluster_target_port_mac_t *port_mac)
{
	ctp_mac_rx_worker_t *w;
	int i;
	for (i = 0; i < cluster_target_mac_nrxworker; i++) {
		w = &port_mac->rx_worker[i];
		mutex_enter(&w->worker_mtx);
		w->worker_flags |= CLUSTER_TARGET_TH_STATE_STOP;
		cv_signal(&w->worker_cv);
		mutex_exit(&w->worker_mtx);
	}

	taskq_destroy(port_mac->rx_worker_tq);
}

static void ctp_mac_rx_worker_fini(cluster_target_port_mac_t *port_mac)
{
	ctp_mac_rx_worker_t *w;
	int i;

	for (i = 0; i < cluster_target_mac_nrxworker; i++) {
		w = &port_mac->rx_worker[i];
		ctp_mac_mplist_clear(w->mplist_r);
		ctp_mac_mplist_clear(w->mplist_w);
		mutex_destroy(&w->worker_mtx);
		cv_destroy(&w->worker_cv);
	}

	kmem_free(port_mac->rx_worker,
		sizeof (ctp_mac_rx_worker_t) * cluster_target_mac_nrxworker);
}

void cluster_target_mac_port_fini(cluster_target_port_t *ctp)
{
	cluster_target_port_mac_t *port_mac = ctp->target_private;

	if (port_mac == NULL) {
		return ;
	}

	ctp_mac_rx_worker_thread_exit(port_mac);
#ifdef SOLARIS
	if (port_mac->mac_force_promisc) {
		mac_promisc_remove(port_mac->mac_promisc_handle);
	} else {
		mac_rx_clear(port_mac->mac_cli_handle);
	}

	mac_notify_remove(port_mac->mac_notify_handle, B_TRUE);
	mac_unicast_remove(port_mac->mac_cli_handle, port_mac->mac_unicst_handle);
	mac_client_close(port_mac->mac_cli_handle, 0);
	mac_close(port_mac->mac_handle);
#else
	dev_put(port_mac->dev);
#endif
	spin_lock_irq(&target_port_lock);
	if (target_port_array[0].ctp == ctp) {
		target_port_array[0].ctp = NULL;
		target_port_array[0].dev = NULL;
	} else if (target_port_array[1].ctp == ctp) {
		target_port_array[1].ctp = NULL;
		target_port_array[1].dev = NULL;
	}
	spin_unlock_irq(&target_port_lock);
}

void cluster_target_mac_port_destroy(cluster_target_port_t *ctp)
{
	cluster_target_port_mac_t *port_mac = ctp->target_private;

	if (port_mac == NULL) {
		return ;
	}
	ctp_mac_rx_worker_fini(port_mac);
	ctp->target_private = NULL;
	mutex_destroy(&port_mac->mac_tx_mtx);
	cv_destroy(&port_mac->mac_tx_cv);
	kmem_free(port_mac, sizeof(cluster_target_port_mac_t));
}


#ifndef SOLARIS
#undef	ether_header
#endif


