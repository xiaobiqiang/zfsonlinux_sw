#ifndef	_SYS_CLUSTER_TARGET_MAC_H
#define	_SYS_CLUSTER_TARGET_MAC_H

#include <linux/spinlock.h>

#define	CLUSTER_TARGET_MAC_LINK_STATE_DOWN		0x00
#define	CLUSTER_TARGET_MAC_LINK_STATE_UP		0x01
#define ETHERADDRL	(6)

/*
 * Message block descriptor
 */
typedef struct	msgb {
	struct	msgb	*b_next;
	struct  msgb	*b_prev;
	struct	msgb	*b_cont;
#ifdef SOLARIS
	unsigned char	*b_rptr;
	unsigned char	*b_wptr;
	struct datab 	*b_datap;
	unsigned char	b_band;
	unsigned char	b_tag;
	unsigned short	b_flag;
	queue_t		*b_queue;	/* for sync queues */
#else
	struct sk_buff* skb;
#endif
} mblk_t;

typedef struct cluster_target_mac_tran_data {
	mblk_t *mp;
	uint64_t len;
} cluster_target_mac_tran_data_t;


typedef struct ctp_mac_mplist {
	mblk_t			*head;
	mblk_t			*tail;
} ctp_mac_mplist_t;

typedef struct ctp_mac_rx_worker {
	ctp_mac_mplist_t	*mplist_r;
	ctp_mac_mplist_t	*mplist_w;
	ctp_mac_mplist_t	mplist1;
	ctp_mac_mplist_t	mplist2;
	//kmutex_t		worker_mtx;
	//kcondvar_t		worker_cv;
#ifndef SOLARIS
	spinlock_t		worker_spin;
	wait_queue_head_t	worker_queue;
#endif
	uint32_t		worker_flags;
	uint32_t		worker_ntasks;
	void 			*ctp_private;
} ctp_mac_rx_worker_t;

typedef struct cluster_target_port_mac {
#ifdef	SOLARIS
	mac_handle_t mac_handle;
	mac_client_handle_t mac_cli_handle;
	mac_promisc_handle_t mac_promisc_handle;
	mac_notify_handle_t mac_notify_handle;
	mac_unicast_handle_t mac_unicst_handle;
#else
	struct net_device * dev;
#endif
	uint8_t mac_addr[ETHERADDRL];
	boolean_t mac_force_promisc;
	uint32_t mac_link_state;

	

	kmutex_t mac_tx_mtx;
	kcondvar_t mac_tx_cv;
	uint32_t tx_failed_times;

	uint32_t rx_worker_n;
	taskq_t *rx_worker_tq;
	ctp_mac_rx_worker_t *rx_worker;
} cluster_target_port_mac_t;

typedef struct cluster_target_session_mac {
	uint8_t sess_daddr[ETHERADDRL];
	/* flow control */
	kmutex_t sess_fc_mtx;
	kcondvar_t sess_fc_cv;
	uint32_t sess_fc_throttle;
	uint32_t sess_fc_throttle_max;
	uint32_t sess_fc_rx_bytes;
	uint32_t sess_fc_throttle_rx;
} cluster_target_session_mac_t;

int cluster_target_mac_port_init(cluster_target_port_t *ctp, char *link_name,
	nvlist_t *nvl_conf);
void cluster_target_mac_port_fini(cluster_target_port_t *ctp);
void cluster_target_mac_port_destroy(cluster_target_port_t *ctp);

#endif

