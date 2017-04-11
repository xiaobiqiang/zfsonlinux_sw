#include <sys/ddi.h>
#include <sys/sysmacros.h>
#include <sys/taskq.h>
#include <sys/list.h>
#include <sys/zone.h>
#include <sys/modhash.h>
#include <sys/modhash_impl.h>
#include <linux/utsname_compat.h>
/* #include <sys/strsubr.h> */
#include <sys/atomic.h>
#include <sys/zfs_ioctl.h>
/* #include <sys/fs/zfs_hbx.h> */
#include <sys/fs/zfs.h>
#include <sys/cluster_san.h>
#include <sys/cluster_target_mac.h>
/*#include <sys/cluster_target_ntb.h>
#include <sys/cluster_target_rpc_rdma.h>
#include <sys/cluster_target_rpc_rdma_svc.h>
#include <sys/cluster_target_rpc_rdma_clnt.h>
*/

#define PRIx64	"llx"
#define	PRId64	"lld"

#define	CLUSTER_TARGET_TRAN_REPLY_HASH_SIZE		1024

#define	CTS_CALLBACK_HASH_SIZE					32

#define	CLUSTER_TARGET_SESS_HB_TIMEGAP			100 /* ms */
#define	CLUSTER_TARGET_SESS_HB_TIMEOUT_MAX		30

#define	CLUSTER_SAN_ASYNC_THREAD_MAX			1024

typedef struct cts_rx_hook_node {
	cs_rx_cb_t rx_cb;
	void *arg;
}cts_rx_hook_node_t;

typedef struct cts_link_evt_hook_node {
	list_node_t node;
	cs_link_evt_cb_t link_evt_cb;
	void *arg;
}cts_link_evt_hook_node_t;

typedef struct cts_link_evt_hook {
	list_t evt_cb_list;
	kmutex_t evt_lock;
}cts_link_evt_hook_t;

kmutex_t clustersan_lock;
krwlock_t clustersan_rwlock;
cluster_san_t *clustersan = NULL;

uint32_t cluster_target_tran_work_ndefault = 1;
uint64_t cluster_target_broadcast_index = 0;

uint32_t cluster_target_session_ntranwork = 1;
uint32_t cluster_target_session_count = 0;
uint32_t cluster_target_session_nrxworker = 1;
uint32_t cluster_san_host_nrxworker = 16;

#define	CLUSTER_SESSION_SEL_ROUNDROBIN			0x1
#define	CLUSTER_SESSION_SEL_LOADBALANCING		0x2

uint32_t cluster_session_select_strategy = CLUSTER_SESSION_SEL_ROUNDROBIN;

volatile uint64_t cts_reply_timeout = 500; /* ms */

volatile uint64_t cs_wd_polltime = 10; /* s */
volatile uint64_t cts_expired_handle_time = 10; /* s */
volatile clock_t cts_fragment_expired_time = 10000; /* ms*/

static uint64_t cluster_sync_msg_id = 0;

static cts_link_evt_hook_t *cts_link_evt_list = NULL;
static mod_hash_t *cts_rx_cb_hash = NULL;

static cts_link_evt_hook_t *csh_link_evt_list = NULL;
static mod_hash_t *csh_rx_cb_hash = NULL;

uint32_t cluster_failover_ipmi_switch = 0;

uint32_t self_hostid = 0;

utsname_t hw_utsname = {
	"Prodigy", "", "", "", "", ""
};

static void cts_remove(cluster_target_session_t *cts);
static void cluster_target_port_destroy(cluster_target_port_t *ctp);
static void cts_send_direct_impl(cluster_target_session_t *cts,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type);
static void csh_asyn_tx_init(cluster_san_hostinfo_t *cshi);
static void csh_asyn_tx_fini(cluster_san_hostinfo_t *cshi);
static void cshi_sync_tx_msg_init(cluster_san_hostinfo_t *cshi);
static void cshi_sync_tx_msg_fini(cluster_san_hostinfo_t *cshi);
static void cluster_san_host_rxworker_init(cluster_san_hostinfo_t *cshi);
static void cluster_san_host_rxworker_fini(cluster_san_hostinfo_t *cshi);
static void cluster_san_rx_sync_cmd_handle(cs_rx_data_t *cs_data);
static void cluster_san_rx_sync_cmd_return(cs_rx_data_t *cs_data);
static void cshi_sync_tx_msg_ret_rx(cs_rx_data_t *cs_data);

#define	CLUSTERSAN_MINBLOCKSHIFT	9
#define	CLUSTERSAN_MAXBLOCKSHIFT	21
#define	CLUSTERSAN_MINBLOCKSIZE		(1ULL << CLUSTERSAN_MINBLOCKSHIFT)
#define	CLUSTERSAN_MAXBLOCKSIZE		(1ULL << CLUSTERSAN_MAXBLOCKSHIFT)

#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
#define	CLUSTERSAN_KMEM_ALLOCKED_FLAG	0xa110c8ed
#define	CLUSTERSAN_KMEM_FREE_FLAG		0xf4eef4ee

volatile uint64_t cs_delayed_free_frequency = 10;
uint64_t cs_delayed_free_cnt = 0;
uint64_t cs_cache_size_used = 0;

typedef struct clustersan_kmem {
	list_node_t	node;
	uint64_t	len;
	void 		*buf;
	uint64_t	frequency;
	uint64_t	wd_index;
	uint32_t	flag;
	uint32_t	reserverd;
}clustersan_kmem_t;

typedef struct clustersan_kmem_vect {
	kmutex_t		lock;
	uint64_t		size;
	uint64_t		used_cnt;
	uint64_t		free_cnt;
	uint64_t		max_used_cnt;
	kmem_cache_t	*mem_cache;
	list_t			free_list;
	list_t			used_list;
}clustersan_kmem_vect_t;

typedef struct clustersan_kmem_private {
	void *cs_kmem_private;
}clustersan_kmem_private_t;

static kmem_cache_t *cs_kmem_t_cache;

#else /* #if (CLUSTER_SAN_MEMFREE_DEALAY == 1) */
typedef struct clustersan_kmem_vect {
	uint64_t		size;
	kmem_cache_t	*mem_cache;
}clustersan_kmem_vect_t;
#endif /* #if (CLUSTER_SAN_MEMFREE_DEALAY == 1) */

static clustersan_kmem_vect_t *cs_cache_buf[CLUSTERSAN_MAXBLOCKSIZE >> CLUSTERSAN_MINBLOCKSHIFT];


#ifdef COMM_TEST
struct COMM_ST {
	char * databuf;
	char * headbuf;
	int wait_flag;
	wait_queue_head_t wait_queue;
	int ret_value;
}comm_st;

void cluster_comm_test_rx(cs_rx_data_t *cs_data, void *arg)
{
	int ret = 0;
	int i=0;
	if (cs_data->data==NULL) {
		printk("cs_data->data=NULL\n");
		return;
	}
	if (*(cs_data->data) == 0) {
		for(i=0; i<cs_data->data_len; i++) {
			if (*(unsigned char*)(cs_data->data+i) != i%256)
				ret = 1;
		}
		for(i=0; i<cs_data->ex_len; i++) {
			if (*((unsigned char*)(cs_data->ex_head+i)) != i%256)
				ret = 1;
		}
		if (ret == 0)
			printk("%s success len=%d ex_len=%d\n", __func__, cs_data->data_len, cs_data->ex_len);
		else {
			printk("%s failed len=%d ex_len=%d\n", __func__, cs_data->data_len, cs_data->ex_len);
			for(i=0; i<cs_data->data_len; i++) {
				printk("%x ", *((unsigned char*)cs_data->data+i));
			}
			printk("exdata\n");
			for(i=0; i<cs_data->ex_len; i++) {
				printk("%x ", *((unsigned char*)cs_data->ex_head+i));
			}
			printk("\n");
		}
		*(cs_data->data) = 1;
		cluster_san_host_send(cs_data->cs_private, cs_data->data, cs_data->data_len, 
			cs_data->ex_head, cs_data->ex_len, CLUSTER_SAN_MSGTYPE_TEST, 0, B_TRUE, 2);
		csh_rx_data_free(cs_data, B_TRUE);
	} else {
		if (cs_data->data) {
			if (comm_st.databuf) {
				if (memcmp(cs_data->data+1, comm_st.databuf+1, cs_data->data_len-1) != 0)
					ret++;
			} else {
				ret++;
			}
		}

		if (cs_data->ex_head) {
			if (comm_st.headbuf) {
				if (memcmp(cs_data->ex_head, comm_st.headbuf, cs_data->ex_len) != 0)
					ret++;
			} else {
				ret++;
			}
		}
		comm_st.ret_value = ret;
		comm_st.wait_flag = 1;
		wake_up(&comm_st.wait_queue);
		csh_rx_data_free(cs_data, B_TRUE);
		if (ret == 0)
			printk("%s success len=%d ex_len=%d\n", __func__, cs_data->data_len, cs_data->ex_len);
		else
			printk("%s failed len=%d ex_len=%d\n", __func__, cs_data->data_len, cs_data->ex_len);
	}
}
int cluster_comm_test(int hostid, int datalen, int headlen)
{
	int ret ;
	int i=0;
	cluster_san_hostinfo_t	*cshi = NULL;

	if ((cshi = cluster_remote_hostinfo_hold((uint32_t)hostid)) == NULL) {
		printk("%s, %d, hold hostinfo(hostid: %d) failed!\n", 
			__func__, __LINE__, hostid);
		ret = -EINVAL;
		goto out1;
	}

	if ((comm_st.databuf = kmem_alloc(datalen, KM_SLEEP)) == NULL) {
		ret = -ENOMEM;
		goto out2;
	}

	if ((comm_st.headbuf = kmem_alloc(headlen, KM_SLEEP)) == NULL) {
		ret = -ENOMEM;
		goto out3;
	}
	
	for(i=0; i<datalen; i++) {
		*(unsigned char*)(comm_st.databuf+i) = i%256;
	}
	for(i=0; i<headlen; i++) {
		*(unsigned char*)(comm_st.headbuf+i) = i%256;
	}
	//get_random_bytes(comm_st.databuf, datalen);
	//get_random_bytes(comm_st.headbuf, headlen);

	*(comm_st.databuf) = 0;
	comm_st.wait_flag = 0;
	comm_st.ret_value = -1;
	ret = cluster_san_host_send(cshi, (void *)comm_st.databuf, datalen, (void *)comm_st.headbuf, 
		headlen, CLUSTER_SAN_MSGTYPE_TEST, 0, B_TRUE, 2);
	wait_event_timeout(comm_st.wait_queue, comm_st.wait_flag == 1, 5 * HZ);
	ret = comm_st.ret_value;

	kmem_free(comm_st.headbuf, headlen);
	comm_st.headbuf = NULL;
out3:
	kmem_free(comm_st.databuf, datalen);
	comm_st.databuf = NULL;
out2:
	cluster_san_hostinfo_rele(cshi);
out1:
	return ret;
}
#endif

void cs_cache_buf_init(void)
{
	int i;
	int cflags = 0;
	char name[64];
	size_t size;
	size_t p2;
	size_t align;

	bzero(cs_cache_buf, sizeof(clustersan_kmem_vect_t *) * 
		(CLUSTERSAN_MAXBLOCKSIZE >> CLUSTERSAN_MINBLOCKSHIFT));

	for (i = 0; i < (CLUSTERSAN_MAXBLOCKSIZE >> CLUSTERSAN_MINBLOCKSHIFT); i++) {
		
		size = (i + 1) << CLUSTERSAN_MINBLOCKSHIFT;
		p2 = size;
		cflags = KMC_NODEBUG;
		align = 0;

		while (p2 & (p2 - 1)) {
			p2 &= p2 - 1;
		}

		if (size <= 4 * CLUSTERSAN_MINBLOCKSIZE) {
			align = CLUSTERSAN_MINBLOCKSIZE;
		} else if (size <= 512 * CLUSTERSAN_MINBLOCKSIZE) {
			if (P2PHASE(size, PAGESIZE) == 0) {
				align = PAGESIZE;
			}
		} else if (size <= CLUSTERSAN_MAXBLOCKSIZE) {
			if (P2PHASE(size, 256 * CLUSTERSAN_MINBLOCKSIZE) == 0) {
				align = PAGESIZE;
			}
		} else {
			align = 0;
		}
#if 0
		if (size <= 4 * CLUSTERSAN_MINBLOCKSIZE) {
			align = CLUSTERSAN_MINBLOCKSIZE;
		} else if (P2PHASE(size, PAGESIZE) == 0) {
			align = PAGESIZE;
		} else if (P2PHASE(size, p2 >> 2) == 0) {
			align = p2 >> 2;
		} else {
			align = 0;
		}
#endif
		if (align != 0) {
			cs_cache_buf[i] = kmem_zalloc(sizeof(clustersan_kmem_vect_t), KM_SLEEP);
			cs_cache_buf[i]->size = size;
			(void) sprintf(name, "cs_cache_buf_%lu", (ulong_t)size);
			cs_cache_buf[i]->mem_cache = kmem_cache_create(name, size, align,
				NULL, NULL, NULL, NULL, NULL, 0);
#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
			cs_cache_buf[i]->free_cnt = 0;
			cs_cache_buf[i]->used_cnt = 0;
			cs_cache_buf[i]->max_used_cnt = 0;
			mutex_init(&cs_cache_buf[i]->lock, NULL, MUTEX_DRIVER, NULL);
			list_create(&cs_cache_buf[i]->free_list, sizeof(clustersan_kmem_t),
				offsetof(clustersan_kmem_t, node));
			list_create(&cs_cache_buf[i]->used_list, sizeof(clustersan_kmem_t),
				offsetof(clustersan_kmem_t, node));
#endif /* #if (CLUSTER_SAN_MEMFREE_DEALAY == 1) */
		}
	}
	while (--i != 0) {
		ASSERT(cs_cache_buf[i] != NULL);
		if (cs_cache_buf[i - 1] == NULL) {
			cs_cache_buf[i - 1] = cs_cache_buf[i];
		}
	}

#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
	cs_kmem_t_cache = kmem_cache_create("cs_kmem_t_cache", sizeof(clustersan_kmem_t),
		0, NULL, NULL, NULL, NULL, NULL, 0);
#endif
}

void cs_cache_buf_fini(void)
{
	int i;
	clustersan_kmem_vect_t *last_cs_cache_buf = NULL;
#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
	clustersan_kmem_t *cs_kmem_buf;
#endif /* #if (CLUSTER_SAN_MEMFREE_DEALAY == 1) */

	for (i = 0; i < (CLUSTERSAN_MAXBLOCKSIZE >> CLUSTERSAN_MINBLOCKSHIFT); i++) {
#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
		mutex_destroy(&cs_cache_buf[i]->lock);
		while ((cs_kmem_buf = list_head(&cs_cache_buf[i]->free_list)) != NULL) {
			list_remove(&cs_cache_buf[i]->free_list, cs_kmem_buf);
			kmem_cache_free(cs_cache_buf[i]->mem_cache, cs_kmem_buf);
		}
#endif /* #if (CLUSTER_SAN_MEMFREE_DEALAY == 1) */
		if (cs_cache_buf[i] != last_cs_cache_buf) {
			last_cs_cache_buf = cs_cache_buf[i];
			kmem_cache_destroy(cs_cache_buf[i]->mem_cache);
			cs_cache_buf[i]->mem_cache = NULL;
#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
			list_destroy(&cs_cache_buf[i]->free_list);
			list_destroy(&cs_cache_buf[i]->used_list);
#endif /* #if (CLUSTER_SAN_MEMFREE_DEALAY == 1) */
			kmem_free(cs_cache_buf[i], sizeof(clustersan_kmem_vect_t));
		}
		cs_cache_buf[i] = NULL;
	}
#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
	kmem_cache_destroy(cs_kmem_t_cache);
#endif
}

#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
clustersan_kmem_t *cs_cache_buf_alloc(uint64_t size)
{
	int i = (size -1) >> CLUSTERSAN_MINBLOCKSHIFT;
	clustersan_kmem_vect_t *cs_kmem_cache;
	clustersan_kmem_t *cs_kmem_buf;
	void *buf;
	
	ASSERT(i < (CLUSTERSAN_MAXBLOCKSIZE >> CLUSTERSAN_MINBLOCKSHIFT));
	cs_kmem_cache = cs_cache_buf[i];

	mutex_enter(&cs_kmem_cache->lock);
	if (cs_kmem_cache->free_cnt != 0) {
		cs_kmem_buf = list_head(&cs_kmem_cache->free_list);
		list_remove(&cs_kmem_cache->free_list, cs_kmem_buf);
		cs_kmem_cache->free_cnt--;
	} else {
		cs_kmem_buf = kmem_cache_alloc(cs_kmem_t_cache, KM_SLEEP);
		buf = kmem_cache_alloc(cs_kmem_cache->mem_cache,
			KM_SLEEP);
		cs_kmem_buf->len = size;
		cs_kmem_buf->buf = buf;
		cs_kmem_buf->frequency = 0;
		cs_kmem_buf->wd_index = cs_delayed_free_cnt;
		atomic_add_64(&cs_cache_size_used, cs_kmem_cache->size);
	}
	cs_kmem_cache->used_cnt++;
	if (cs_kmem_cache->used_cnt >= cs_kmem_cache->max_used_cnt) {
		cs_kmem_cache->max_used_cnt = cs_kmem_cache->used_cnt;
	}
	cs_kmem_buf->frequency++;
	cs_kmem_buf->flag = CLUSTERSAN_KMEM_ALLOCKED_FLAG;
	mutex_exit(&cs_kmem_cache->lock);

	return (cs_kmem_buf);
}

void cs_cache_buf_free(clustersan_kmem_t *cs_kmem_buf)
{
	clustersan_kmem_vect_t *cs_kmem_cache;
	int i = (cs_kmem_buf->len -1) >> CLUSTERSAN_MINBLOCKSHIFT;
	ASSERT(i < (CLUSTERSAN_MAXBLOCKSIZE >> CLUSTERSAN_MINBLOCKSHIFT));

	if (cs_kmem_buf->flag != CLUSTERSAN_KMEM_ALLOCKED_FLAG) {
		cmn_err(CE_PANIC, "cluster mem repeat free");
	}
	cs_kmem_cache = cs_cache_buf[i];
	mutex_enter(&cs_kmem_cache->lock);
	cs_kmem_buf->flag = CLUSTERSAN_KMEM_FREE_FLAG;
	if (cs_kmem_buf->wd_index < cs_delayed_free_cnt) {
		cs_kmem_buf->frequency = 0;
		cs_kmem_buf->wd_index = cs_delayed_free_cnt;
	}
	cs_kmem_cache->used_cnt--;
	list_insert_tail(&cs_kmem_cache->free_list, cs_kmem_buf);
	cs_kmem_cache->free_cnt++;
	mutex_exit(&cs_kmem_cache->lock);
}

void cs_cache_buf_timeout_clean(clustersan_kmem_vect_t *cs_kmem_cache)
{
	clustersan_kmem_t *cs_kmem_buf;
	clustersan_kmem_t *cs_kmem_buf_next;
	uint64_t now = ddi_get_time();
	int free_cnt;
	int i;
	mutex_enter(&cs_kmem_cache->lock);
	free_cnt = cs_kmem_cache->free_cnt;

	cs_kmem_buf = list_head(&cs_kmem_cache->free_list);
	while (cs_kmem_buf != NULL) {
		cs_kmem_buf_next = list_next(&cs_kmem_cache->free_list, cs_kmem_buf);
		if (cs_kmem_buf->frequency < cs_delayed_free_frequency) {
			list_remove(&cs_kmem_cache->free_list, cs_kmem_buf);
			cs_kmem_buf->flag = 0;
			kmem_cache_free(cs_kmem_cache->mem_cache, cs_kmem_buf->buf);
			kmem_cache_free(cs_kmem_t_cache, cs_kmem_buf);
			cs_kmem_cache->free_cnt--;
			atomic_add_64(&cs_cache_size_used, 0 - cs_kmem_cache->size);
		} else {
			cs_kmem_buf->frequency = 0;
			cs_kmem_buf->wd_index = cs_delayed_free_cnt;
		}
		cs_kmem_buf = cs_kmem_buf_next;
	}

	cs_kmem_cache->max_used_cnt = cs_kmem_cache->used_cnt +
		cs_kmem_cache->free_cnt;

	mutex_exit(&cs_kmem_cache->lock);
}

void cs_cache_buf_wd_handle(void)
{
	int i;
	atomic_inc_64(&cs_delayed_free_cnt);
	for (i = 0; i < (CLUSTERSAN_MAXBLOCKSIZE >> CLUSTERSAN_MINBLOCKSHIFT); i++) {
		cs_cache_buf_timeout_clean(cs_cache_buf[i]);
	}
}

#endif /* #if (CLUSTER_SAN_MEMFREE_DEALAY == 1) */

void *cs_kmem_alloc(size_t size)
{
#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
	clustersan_kmem_t *cs_kmem_buf;
	clustersan_kmem_private_t *cs_kmem_private;
	uint64_t len_temp;
	void *buf;

	if (size == 0) {
		return (NULL);
	}

	len_temp = size + sizeof(clustersan_kmem_private_t);
	if (len_temp > CLUSTERSAN_MAXBLOCKSIZE) {
		return (kmem_alloc(size, KM_SLEEP));
	}

	cs_kmem_buf = cs_cache_buf_alloc(len_temp);
	cs_kmem_private = cs_kmem_buf->buf;
	buf = (void *)((uintptr_t)cs_kmem_buf->buf + sizeof(clustersan_kmem_private_t));
	cs_kmem_private->cs_kmem_private = cs_kmem_buf;
	return (buf);
#else
	int i = (size -1) >> CLUSTERSAN_MINBLOCKSHIFT;
	clustersan_kmem_vect_t *cs_kmem_cache;
	void *buf;

	if (size == 0) {
		return (NULL);
	}

	if (size > CLUSTERSAN_MAXBLOCKSIZE) {
		return (kmem_alloc(size, KM_SLEEP));
	}

	ASSERT(i < (CLUSTERSAN_MAXBLOCKSIZE >> CLUSTERSAN_MINBLOCKSHIFT));
	cs_kmem_cache = cs_cache_buf[i];

	buf = kmem_cache_alloc(cs_kmem_cache->mem_cache,
		KM_SLEEP);

	return (buf);
#endif
}

void cs_kmem_free(void *buf, size_t size)
{
#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
	clustersan_kmem_t *cs_kmem_buf;
	clustersan_kmem_private_t *cs_kmem_private;
	if (buf == NULL) {
		return;
	}

	if (size > CLUSTERSAN_MAXBLOCKSIZE) {
		kmem_free(buf, size);
		return;
	}
	cs_kmem_private = (clustersan_kmem_private_t *)
		((uintptr_t)buf - sizeof(clustersan_kmem_private_t));
	cs_cache_buf_free(cs_kmem_private->cs_kmem_private);
#else
	int i = (size -1) >> CLUSTERSAN_MINBLOCKSHIFT;
	clustersan_kmem_vect_t *cs_kmem_cache;

	if (buf == NULL) {
		return;
	}

	if (size > CLUSTERSAN_MAXBLOCKSIZE) {
		kmem_free(buf, size);
		return;
	}

	ASSERT(i < (CLUSTERSAN_MAXBLOCKSIZE >> CLUSTERSAN_MINBLOCKSHIFT));
	cs_kmem_cache = cs_cache_buf[i];

	kmem_cache_free(cs_kmem_cache->mem_cache, buf);
#endif
}

static cs_rx_data_t *cts_rx_data_alloc(uint64_t len)
{
	cs_rx_data_t *cs_data;

	cs_data = kmem_zalloc(sizeof(cs_rx_data_t), KM_SLEEP);
	cs_data->data_len = len;
#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
	if (len != 0) {
		if (len <= CLUSTERSAN_MAXBLOCKSIZE) {
			clustersan_kmem_t *cs_kmem_buf = cs_cache_buf_alloc(len);
			cs_data->data = cs_kmem_buf->buf;
			cs_data->cs_cache_private = cs_kmem_buf;
		} else {
			cs_data->data = kmem_zalloc(len, KM_SLEEP);
		}
	}
#else
	cs_data->data = cs_kmem_alloc(len);
#endif
	return (cs_data);
}

static void cts_rx_data_free(cs_rx_data_t *cs_data, boolean_t cts_hold)
{
	if ((cs_data->data_len != 0) && (cs_data->data != NULL)) {
#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
		if (cs_data->data_len <= CLUSTERSAN_MAXBLOCKSIZE) {
			cs_cache_buf_free(cs_data->cs_cache_private);
			cs_data->data = NULL;
			cs_data->cs_cache_private = NULL;
		} else {
			kmem_free(cs_data->data, cs_data->data_len);
		}
#else
		cs_kmem_free(cs_data->data, cs_data->data_len);
#endif
	}
	if ((cs_data->ex_head != NULL) && (cs_data->ex_len != 0)) {
		kmem_free(cs_data->ex_head, cs_data->ex_len);
	}
	if (cts_hold) {
		cluster_target_session_rele(cs_data->cs_private, "cts_data");
	}
	kmem_free(cs_data, sizeof(cs_rx_data_t));
}

void csh_rx_data_free(cs_rx_data_t *cs_data, boolean_t csh_hold)
{
	if ((cs_data->data_len != 0) && (cs_data->data != NULL)) {
#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
		if (cs_data->data_len <= CLUSTERSAN_MAXBLOCKSIZE) {
			cs_cache_buf_free(cs_data->cs_cache_private);
			cs_data->data = NULL;
			cs_data->cs_cache_private = NULL;
		} else {
			kmem_free(cs_data->data, cs_data->data_len);
		}
#else
		cs_kmem_free(cs_data->data, cs_data->data_len);
#endif
	}
	if ((cs_data->ex_head != NULL) && (cs_data->ex_len != 0)) {
		kmem_free(cs_data->ex_head, cs_data->ex_len);
	}
	if (csh_hold) {
		cluster_san_hostinfo_rele(cs_data->cs_private);
	}
	kmem_free(cs_data, sizeof(cs_rx_data_t));
}

void csh_rx_data_free_ext(cs_rx_data_t *cs_data)
{
	csh_rx_data_free(cs_data, B_TRUE);
}

static void cts_rx_hook_init(void)
{
	if (cts_rx_cb_hash == NULL) {
		cts_rx_cb_hash = mod_hash_create_idhash("cts_rx_hook_list_hash",
			CTS_CALLBACK_HASH_SIZE, mod_hash_null_valdtor);
	}
}

int cts_rx_hook_add(uint32_t msg_type, cs_rx_cb_t rx_cb, void *arg)
{
	int ret = 0;

	cts_rx_hook_node_t *rx_cb_node = kmem_zalloc(sizeof(cts_rx_hook_node_t), KM_SLEEP);
	rx_cb_node->rx_cb = rx_cb;
	rx_cb_node->arg = arg;
	ret = mod_hash_insert(cts_rx_cb_hash, (mod_hash_key_t)(uintptr_t)msg_type,
		(mod_hash_val_t)rx_cb_node);
	if (ret != 0) {
		kmem_free(rx_cb_node, sizeof(cts_rx_hook_node_t));
		cmn_err(CE_WARN, "%s: the rx hook (msg_type: 0x%x) already exist",
			__func__, msg_type);
	}

	return (ret);
}

int cts_rx_hook_remove(uint32_t msg_type)
{
	cts_rx_hook_node_t *rx_cb_node;
	int ret = 0;

	if (cts_rx_cb_hash == NULL) {
		return (-1);
	}
	ret = mod_hash_remove(cts_rx_cb_hash, (mod_hash_key_t)(uintptr_t)msg_type,
		(mod_hash_val_t *)&rx_cb_node);
	if (ret == 0) {
		kmem_free(rx_cb_node, sizeof(cts_rx_hook_node_t));
	} else {
		cmn_err(CE_WARN, "%s: not found the rx hook, msg_type:0x%x",
			__func__, msg_type);
	}

	return (ret);
}

static void
cts_rx_handle_ext(cs_rx_data_t *cs_data)
{
	cts_rx_hook_node_t *rx_cb_node;
	/* uint32_t msg_type = cs_data->msg_type; */
	int ret = 0;

	ret = mod_hash_find(cts_rx_cb_hash,
		(mod_hash_key_t)(uintptr_t)cs_data->msg_type,
		(mod_hash_val_t *)&rx_cb_node);
	if (ret != 0) {
		cts_rx_data_free(cs_data, B_TRUE);
	} else {
		rx_cb_node->rx_cb(cs_data, rx_cb_node->arg);
	}
}

static void cts_link_evt_hook_init(void)
{
	if (cts_link_evt_list != NULL) {
		return;
	}
	cts_link_evt_list = kmem_zalloc(sizeof(cts_link_evt_hook_t), KM_SLEEP);
	mutex_init(&cts_link_evt_list->evt_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&cts_link_evt_list->evt_cb_list,
		sizeof(cts_link_evt_hook_node_t),
		offsetof(cts_link_evt_hook_node_t, node));
}

static void
cts_link_evt_handle_ext(cluster_target_session_t *cts, cts_link_evt_t link_evt)
{
	cts_link_evt_hook_node_t *cb_node;
	
	mutex_enter(&cts_link_evt_list->evt_lock);
	cb_node = list_head(&cts_link_evt_list->evt_cb_list);
	while (cb_node != NULL) {
		cb_node->link_evt_cb(cts, link_evt, cb_node->arg);
		cb_node = list_next(&cts_link_evt_list->evt_cb_list, cb_node);
	}
	mutex_exit(&cts_link_evt_list->evt_lock);
}

int cts_link_evt_hook_add(cs_link_evt_cb_t link_evt_cb, void *arg)
{
	cts_link_evt_hook_node_t *cb_node;
	int ret = 0;
	
	mutex_enter(&cts_link_evt_list->evt_lock);
	cb_node = list_head(&cts_link_evt_list->evt_cb_list);
	while (cb_node != NULL) {
		if (cb_node->link_evt_cb == link_evt_cb) {
			break;
		}
		cb_node = list_next(&cts_link_evt_list->evt_cb_list, cb_node);
	}

	if (cb_node == NULL) {
		cb_node = kmem_zalloc(sizeof(cts_link_evt_hook_node_t), KM_SLEEP);
		cb_node->link_evt_cb = link_evt_cb;
		cb_node->arg = arg;
		list_insert_tail(&cts_link_evt_list->evt_cb_list, cb_node);
	} else {
		cmn_err(CE_WARN, "%s: the hook (0x%p) already exist",
			__func__, link_evt_cb);
		ret = (-1);
	}
	mutex_exit(&cts_link_evt_list->evt_lock);

	return (ret);
}

int cts_link_evt_hook_remove(cs_link_evt_cb_t link_evt_cb)
{
	cts_link_evt_hook_node_t *cb_node;
	int ret = 0;

	mutex_enter(&cts_link_evt_list->evt_lock);
	cb_node = list_head(&cts_link_evt_list->evt_cb_list);
	while (cb_node != NULL) {
		if (cb_node->link_evt_cb == link_evt_cb) {
			break;
		}
		cb_node = list_next(&cts_link_evt_list->evt_cb_list, cb_node);
	}

	if (cb_node != NULL) {
		list_remove(&cts_link_evt_list->evt_cb_list, cb_node);
		kmem_free(cb_node, sizeof(cts_link_evt_hook_node_t));
	} else {
		cmn_err(CE_WARN, "%s: not found the link evt hook:0x%p",
			__func__, link_evt_cb);
		ret = (-1);
	}
	mutex_exit(&cts_link_evt_list->evt_lock);

	return (ret);
}

void cts_list_insert(list_t *sess_list, cluster_target_session_t *cts)
{
	cts_list_pri_t *cts_list;
	cts_list_pri_t *cts_list_temp;

	cts_list = list_head(sess_list);
	while (cts_list != NULL) {
		if (cts->sess_pri == cts_list->pri) {
			break;
		} else if (cts->sess_pri < cts_list->pri) {
			cts_list_temp = kmem_zalloc(sizeof(cts_list_pri_t), KM_SLEEP);
			cts_list_temp->pri = cts->sess_pri;
			list_create(&cts_list_temp->sess_list, sizeof(cluster_target_session_t),
				offsetof(cluster_target_session_t, host_node));
			list_insert_before(sess_list, cts_list, cts_list_temp);
			cts_list = cts_list_temp;
			break;
		}
		cts_list = list_next(sess_list, cts_list);
	}

	if (cts_list == NULL) {
		cts_list = kmem_zalloc(sizeof(cts_list_pri_t), KM_SLEEP);
		cts_list->pri = cts->sess_pri;
		list_create(&cts_list->sess_list, sizeof(cluster_target_session_t),
			offsetof(cluster_target_session_t, host_node));
		list_insert_tail(sess_list, cts_list);
	}

	cts->host_list = cts_list;
	list_insert_tail(&cts_list->sess_list, cts);
}

static void csh_rx_hook_init(void)
{
	if (csh_rx_cb_hash == NULL) {
		csh_rx_cb_hash = mod_hash_create_idhash("csh_rx_hook_list_hash",
			CTS_CALLBACK_HASH_SIZE, mod_hash_null_valdtor);
	}
}

int csh_rx_hook_add(uint32_t msg_type, cs_rx_cb_t rx_cb, void *arg)
{
	int ret = 0;
	
	cts_rx_hook_node_t *rx_cb_node = kmem_zalloc(sizeof(cts_rx_hook_node_t), KM_SLEEP);
	rx_cb_node->rx_cb = rx_cb;
	rx_cb_node->arg = arg;
	ret = mod_hash_insert(csh_rx_cb_hash, (mod_hash_key_t)(uintptr_t)msg_type,
		(mod_hash_val_t)rx_cb_node);
	if (ret != 0) {
		kmem_free(rx_cb_node, sizeof(cts_rx_hook_node_t));
		cmn_err(CE_WARN, "%s: the rx hook (msg_type: 0x%x) already exist",
			__func__, msg_type);
	}

	return (ret);
}

int csh_rx_hook_remove(uint32_t msg_type)
{
	cts_rx_hook_node_t *rx_cb_node;
	int ret = 0;

	if (csh_rx_cb_hash == NULL) {
		return (-1);
	}
	ret = mod_hash_remove(csh_rx_cb_hash, (mod_hash_key_t)(uintptr_t)msg_type,
		(mod_hash_val_t *)&rx_cb_node);
	if (ret == 0) {
		kmem_free(rx_cb_node, sizeof(cts_rx_hook_node_t));
	} else {
		cmn_err(CE_WARN, "%s: not found the rx hook, msg_type:0x%x",
			__func__, msg_type);
	}

	return (ret);
}

static void
csh_rx_handle_ext(cs_rx_data_t *cs_data)
{
	cts_rx_hook_node_t *rx_cb_node;
	/* uint32_t msg_type = cs_data->msg_type; */
	int ret = 0;

	ret = mod_hash_find(csh_rx_cb_hash,
		(mod_hash_key_t)(uintptr_t)cs_data->msg_type,
		(mod_hash_val_t *)&rx_cb_node);
	if (ret != 0) {
		csh_rx_data_free(cs_data, B_TRUE);
	} else {
		rx_cb_node->rx_cb(cs_data, rx_cb_node->arg);
	}
}

static void csh_link_evt_hook_init(void)
{
	if (csh_link_evt_list != NULL) {
		return;
	}
	csh_link_evt_list = kmem_zalloc(sizeof(cts_link_evt_hook_t), KM_SLEEP);
	mutex_init(&csh_link_evt_list->evt_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&csh_link_evt_list->evt_cb_list,
		sizeof(cts_link_evt_hook_node_t),
		offsetof(cts_link_evt_hook_node_t, node));
}

static void
csh_link_evt_handle_ext(cluster_san_hostinfo_t *cshi, cts_link_evt_t link_evt)
{
	cts_link_evt_hook_node_t *cb_node;
	uint32_t *hostid;
	
	mutex_enter(&csh_link_evt_list->evt_lock);
	cb_node = list_head(&csh_link_evt_list->evt_cb_list);
	while (cb_node != NULL) {
		cb_node->link_evt_cb(cshi, link_evt, cb_node->arg);
		cb_node = list_next(&csh_link_evt_list->evt_cb_list, cb_node);
	}
	mutex_exit(&csh_link_evt_list->evt_lock);

	switch(link_evt) {
		case LINK_EVT_UP_TO_DOWN:
			/* spa failover */
			hostid = kmem_zalloc(sizeof(uint32_t), KM_SLEEP);
			*hostid = cshi->hostid;
			/* zfs_notify_clusterd(EVT_REMOTE_HOST_DOWN,
				(char *)hostid, (uint64_t)sizeof(uint32_t)); */
			break;
		case LINK_EVT_DOWN_TO_UP:
			hostid = kmem_zalloc(sizeof(uint32_t), KM_SLEEP);
			*hostid = cshi->hostid;
			/* zfs_notify_clusterd(EVT_REMOTE_HOST_UP,
				(char *)hostid, (uint64_t)sizeof(uint32_t)); */
			break;
		default:
			break;
	}
}

int csh_link_evt_hook_add(cs_link_evt_cb_t link_evt_cb, void *arg)
{
	cts_link_evt_hook_node_t *cb_node;
	int ret = 0;
	
	mutex_enter(&csh_link_evt_list->evt_lock);
	cb_node = list_head(&csh_link_evt_list->evt_cb_list);
	while (cb_node != NULL) {
		if (cb_node->link_evt_cb == link_evt_cb) {
			break;
		}
		cb_node = list_next(&csh_link_evt_list->evt_cb_list, cb_node);
	}

	if (cb_node == NULL) {
		cb_node = kmem_zalloc(sizeof(cts_link_evt_hook_node_t), KM_SLEEP);
		cb_node->link_evt_cb = link_evt_cb;
		cb_node->arg = arg;
		list_insert_tail(&csh_link_evt_list->evt_cb_list, cb_node);
	} else {
		cmn_err(CE_WARN, "%s: the hook (0x%p) already exist",
			__func__, link_evt_cb);
		ret = (-1);
	}
	mutex_exit(&csh_link_evt_list->evt_lock);

	return (ret);
}

int csh_link_evt_hook_remove(cs_link_evt_cb_t link_evt_cb)
{
	cts_link_evt_hook_node_t *cb_node;
	int ret = 0;

	mutex_enter(&csh_link_evt_list->evt_lock);
	cb_node = list_head(&csh_link_evt_list->evt_cb_list);
	while (cb_node != NULL) {
		if (cb_node->link_evt_cb == link_evt_cb) {
			break;
		}
		cb_node = list_next(&csh_link_evt_list->evt_cb_list, cb_node);
	}

	if (cb_node != NULL) {
		list_remove(&csh_link_evt_list->evt_cb_list, cb_node);
		kmem_free(cb_node, sizeof(cts_link_evt_hook_node_t));
	} else {
		cmn_err(CE_WARN, "%s: not found the link evt hook:0x%p",
			__func__, link_evt_cb);
		ret = (-1);
	}
	mutex_exit(&csh_link_evt_list->evt_lock);

	return (ret);
}

int cluster_target_port_hold(cluster_target_port_t *ctp)
{
	int ret = 0;

	atomic_inc_64(&ctp->ref_count);

	if (ctp->ctp_state == CLUSTER_SAN_STATE_DISABLE) {
		atomic_dec_64(&ctp->ref_count);
		ret = -1;
	}
	return (ret);
}

void cluster_target_port_rele(cluster_target_port_t *ctp)
{
	uint64_t ref;
	ref = atomic_dec_64_nv(&ctp->ref_count);
	if (ref == 0) {
		cluster_target_port_destroy(ctp);
	}
}

int ctp_tx_hold(cluster_target_port_t *ctp)
{
	atomic_inc_64(&ctp->ref_tx_count);
	if (ctp->ctp_state == CLUSTER_SAN_STATE_DISABLE) {
		atomic_dec_64(&ctp->ref_tx_count);
		return (-1);
	}
	return (0);
}

void ctp_tx_rele(cluster_target_port_t *ctp)
{
	atomic_dec_64(&ctp->ref_tx_count);
}

int cluster_san_init()
{
	uint32_t hostid;
	char *hostname = hw_utsname.nodename;

	cs_cache_buf_init();
	mutex_init(&clustersan_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&clustersan_rwlock, NULL, RW_DRIVER, NULL);
	clustersan = kmem_zalloc(sizeof(cluster_san_t), KM_SLEEP);
	list_create(&clustersan->cs_target_list,
		sizeof(cluster_target_port_t), offsetof(cluster_target_port_t, node));
	list_create(&clustersan->cs_hostlist,
		sizeof(cluster_san_hostinfo_t), offsetof(cluster_san_hostinfo_t, node));
	clustersan->cs_hostcnt = 0;
	mutex_init(&clustersan->cs_failover_host_lock, NULL, MUTEX_DEFAULT, NULL);
	clustersan->cs_failover_host = NULL;
	cts_link_evt_hook_init();
	cts_rx_hook_init();
	csh_link_evt_hook_init();
	csh_rx_hook_init();

	hostid = zone_get_hostid(NULL);
	self_hostid = hostid;
	clustersan->cs_host.hostid = hostid;
/*	clustersan->cs_host.hostname = kmem_zalloc(strlen(hostname) + 1, KM_SLEEP);
	strcpy(clustersan->cs_host.hostname, hostname);*/
	clustersan->cs_host.hostname = hostname;
	list_create(&clustersan->cs_host.sesslist,
		sizeof(cts_list_pri_t), offsetof(cts_list_pri_t, node));
	mutex_init(&clustersan->cs_host.lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_init(&clustersan->cs_sync_cmd.sync_cmd_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&clustersan->cs_sync_cmd.sync_cmd_list,
		sizeof(cs_sync_cmd_node_t), offsetof(cs_sync_cmd_node_t, node));

	clustersan->cs_async_taskq = taskq_create("clustersan_async_tq",
		1, minclsyspri, 1, CLUSTER_SAN_ASYNC_THREAD_MAX, TASKQ_PREPOPULATE);

	/* zfs_hbx_init(); */
	/* cluster_target_rpc_rdma_svc_init(); */
	/* cluster_target_rpc_rdma_clnt_init(); */

#ifdef COMM_TEST
	init_waitqueue_head(&comm_st.wait_queue);
	csh_rx_hook_add(CLUSTER_SAN_MSGTYPE_TEST, cluster_comm_test_rx, NULL);
#endif
	return (0);
}

void cluster_san_fini()
{
	/* zfs_hbx_fini(); */
	mutex_destroy(&clustersan_lock);
	rw_destroy(&clustersan_rwlock);
	list_destroy(&clustersan->cs_target_list);
	list_destroy(&clustersan->cs_hostlist);
/*	kmem_free(clustersan->cs_host.hostname,
		strlen(clustersan->cs_host.hostname) + 1);*/
	list_destroy(&clustersan->cs_host.sesslist);
	mutex_destroy(&clustersan->cs_host.lock);
	taskq_destroy(clustersan->cs_async_taskq);
	if (clustersan->cs_host.spa_config != NULL) {
		nvlist_free(clustersan->cs_host.spa_config);
		clustersan->cs_host.spa_config = NULL;
	}
	mutex_destroy(&clustersan->cs_sync_cmd.sync_cmd_lock);
	list_destroy(&clustersan->cs_sync_cmd.sync_cmd_list);
	mutex_destroy(&clustersan->cs_failover_host_lock);
	kmem_free(clustersan, sizeof(cluster_san_t));
	clustersan = NULL;
	cs_cache_buf_fini();
	/* cluster_target_rpc_rdma_svc_fini(); */
	/* cluster_target_rpc_rdma_clnt_fini(); */
#ifdef COMM_TEST
	csh_rx_hook_remove(CLUSTER_SAN_MSGTYPE_TEST);
#endif
}

void cluster_sync_spa_config(nvlist_t *nvl, uint32_t remote_hostid)
{
	char *buf = NULL;
	size_t buflen = 0;
	cluster_san_hostinfo_t *cshi;
	cluster_evt_header_t evt_header;
	uint64_t sync_msg_id;
	int ret = 0;

	cshi = cluster_remote_hostinfo_hold(remote_hostid);

	if (cshi == NULL) {
		cmn_err(CE_WARN, "%s: don't find the host=%d from cluster",
			__func__, remote_hostid);
		return;
	}

	if (nvl != NULL) {
		VERIFY(nvlist_size(nvl, &buflen, NV_ENCODE_XDR) == 0);
		if (buflen != 0) {
			buf = kmem_alloc(buflen, KM_SLEEP);
			VERIFY(nvlist_pack(nvl, &buf, &buflen, NV_ENCODE_XDR,
			    KM_SLEEP) == 0);
			evt_header.msg_type = CLUSTER_EVT_UPDATA_REMOTE_SPA_CONFIG;
			sync_msg_id = atomic_inc_64_nv(&cluster_sync_msg_id);
			evt_header.msg_id = sync_msg_id;
			ret = cluster_san_host_sync_send_msg(CLUSTER_SAN_BROADCAST_SESS,
				buf, buflen, &evt_header, sizeof(cluster_evt_header_t),
				sync_msg_id, CLUSTER_SAN_MSGTYPE_CLUSTER, 30);
			kmem_free(buf, buflen);
		}
	} else {
		evt_header.msg_type = CLUSTER_EVT_CLEAR_REMOTE_SPA_CONFIG;
		sync_msg_id = atomic_inc_64_nv(&cluster_sync_msg_id);
		evt_header.msg_id = sync_msg_id;
		ret = cluster_san_host_sync_send_msg(CLUSTER_SAN_BROADCAST_SESS,
			NULL, 0, &evt_header, sizeof(cluster_evt_header_t),
			sync_msg_id, CLUSTER_SAN_MSGTYPE_CLUSTER, 30);
	}
	if (ret != 0) {
		cmn_err(CE_WARN, "%s: sync send failed", __func__);
	} else {
		cmn_err(CE_WARN, "%s: sync send successed", __func__);
	}
	cluster_san_hostinfo_rele(cshi);
}

void cluster_update_spa_config(nvlist_t *nvl, boolean_t sync_remote)
{
	/* updata local record */
	rw_enter(&clustersan_rwlock, RW_WRITER);
	if (clustersan->cs_host.spa_config != NULL) {
		nvlist_free(clustersan->cs_host.spa_config);
		clustersan->cs_host.spa_config = NULL;
	}
	if (nvl != NULL)  {
		VERIFY(nvlist_dup(nvl, &clustersan->cs_host.spa_config, 0) == 0);
	}
	rw_exit(&clustersan_rwlock);

	/* notify other hosts */
	if (sync_remote == B_TRUE) {
		cluster_sync_spa_config(nvl, 0);
	}
}

void cluster_update_remote_spa_config(cs_rx_data_t *cs_data)
{
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	cluster_evt_header_t *evt_header = cs_data->ex_head;
	/* nvlist_t *spa_config; */
	int err = 0;

	rw_enter(&clustersan_rwlock, RW_WRITER);
	if (cshi->spa_config != NULL) {
		nvlist_free(cshi->spa_config);
		cshi->spa_config = NULL;
	}

	if (cs_data->data != NULL) {
		err = nvlist_unpack(cs_data->data, cs_data->data_len,
			&cshi->spa_config, KM_SLEEP);
		cmn_err(CE_NOTE, "%s: update, host=%d, ret=%d", __func__,
			cshi->hostid, err);
	} else {
		cmn_err(CE_NOTE, "%s: clear, host=%d", __func__, cshi->hostid);
	}
	rw_exit(&clustersan_rwlock);

	cluster_san_host_sync_msg_ret(cshi, evt_header->msg_id,
		CLUSTER_SAN_MSGTYPE_CLUSTER, err);

	csh_rx_data_free(cs_data, B_TRUE);
}

void cluster_sync_spa_config_to_remote(uint32_t remote_hostid)
{
	nvlist_t *nvl = NULL;

	rw_enter(&clustersan_rwlock, RW_READER);
	if (clustersan->cs_host.spa_config != NULL) {
		VERIFY(nvlist_dup(clustersan->cs_host.spa_config, &nvl, 0) == 0);
	}
	rw_exit(&clustersan_rwlock);
	cluster_sync_spa_config(nvl, remote_hostid);
	cmn_err(CE_NOTE, "%s: have pool=%d ,send to host=%d",
		__func__, (nvl != NULL), remote_hostid);
	if (nvl != NULL) {
		nvlist_free(nvl);
	}
}

int cluster_get_remote_spa_config(uint32_t hostid, nvlist_t **ppnvl)
{
	nvlist_t *spa_configs = NULL;
	cluster_san_hostinfo_t *cshi;
	int ret = -1;

	rw_enter(&clustersan_rwlock, RW_READER);
	cshi = list_head(&clustersan->cs_hostlist);
	while (cshi != NULL) {
		if ((hostid == 0) || (hostid == cshi->hostid)) {
			if (cshi->spa_config != NULL) {
				if (spa_configs == NULL) {
					ret = nvlist_alloc(&spa_configs, 0, KM_SLEEP);
					if (ret != 0) {
						break;
					}
				}
				ret = nvlist_merge(spa_configs, cshi->spa_config, 0);
				if (ret != 0) {
					nvlist_free(spa_configs);
					spa_configs = NULL;
					break;
				}
			}
			if (hostid != 0) {
				break;
			}
		}
		cshi = list_next(&clustersan->cs_hostlist, cshi);
	}
	rw_exit(&clustersan_rwlock);

	*ppnvl = spa_configs;
	return (ret);
}

void cluster_remove_remote_spa_config(uint32_t hostid, char *spa_name)
{
	cluster_san_hostinfo_t *cshi;
	nvlist_t *config = NULL;
	nvpair_t *elem = NULL;
	char *name = NULL;

	rw_enter(&clustersan_rwlock, RW_WRITER);
	cshi = list_head(&clustersan->cs_hostlist);
	while (cshi != NULL) {
		if (hostid == cshi->hostid) {
			break;
		}
		cshi = list_next(&clustersan->cs_hostlist, cshi);
	}
	if (cshi != NULL) {
		if (cshi->spa_config != NULL) {
			if (spa_name[0] == '\0') {
				cmn_err(CE_NOTE, "%s: remove all host(%d)'s spa config",
					__func__, hostid);
				nvlist_free(cshi->spa_config);
				cshi->spa_config = NULL;
			} else {
				while ((elem = nvlist_next_nvpair(
					cshi->spa_config, elem))!= NULL) {
					VERIFY(nvpair_value_nvlist(elem, &config) == 0);
					VERIFY(nvlist_lookup_string(config,
						ZPOOL_CONFIG_POOL_NAME, &name) == 0);
					
					if ((name != NULL) 
						&& (0 == strncmp(name, spa_name, MAXNAMELEN))) {
						cmn_err(CE_NOTE,"%s: remove spa config(%s) from host(%d)",
							__func__, name, hostid);
						VERIFY(nvlist_remove_nvpair(cshi->spa_config, elem) == 0);
						break;
					}
				}
				if (elem == NULL) {
					cmn_err(CE_WARN,"%s: remove host(%d)'s spa config(%s) failed,"
						" may be already removed", __func__, hostid, spa_name);
				}
				if (nvlist_empty(cshi->spa_config)) {
					nvlist_free(cshi->spa_config);
					cshi->spa_config = NULL;
				}

			}
		} else {
			cmn_err(CE_NOTE, "%s: host(%d)'s spa config is NULL",
				__func__, hostid);
		}
	}
	rw_exit(&clustersan_rwlock);
}

int cluster_remote_import_pool(uint32_t remote_hostid, char *spa_name)
{
	cluster_san_hostinfo_t *cshi;
	cluster_evt_header_t evt_header;
	nvlist_t *ripool;
	char *buf;
	size_t buflen;
	uint32_t hostid = zone_get_hostid(NULL);
	int ret;

	if ((remote_hostid == 0) || (spa_name == NULL)) {
		return (-1);
	}
	cshi = cluster_remote_hostinfo_hold(remote_hostid);
	if (cshi == NULL) {
		cmn_err(CE_WARN, "%s: not found the host(%d) from cluster",
			__func__, remote_hostid);
		return (-1);
	}
	evt_header.msg_type = CLUSTER_EVT_CHANGE_POOL_OWNER;
	evt_header.msg_id = 0;
	VERIFY(nvlist_alloc(&ripool, NV_UNIQUE_NAME, KM_SLEEP) == 0);
	VERIFY(nvlist_add_uint32(ripool, "hostid", hostid) == 0);
	VERIFY(nvlist_add_string(ripool, "spa_name", spa_name) == 0);

	VERIFY(nvlist_size(ripool, &buflen, NV_ENCODE_XDR) == 0);
	buf = kmem_alloc(buflen, KM_SLEEP);
	VERIFY(nvlist_pack(ripool, &buf, &buflen, NV_ENCODE_XDR,
	    KM_SLEEP) == 0);
	nvlist_free(ripool);
	
	ret = cluster_san_host_send(cshi, buf, buflen,
		&evt_header, sizeof(cluster_evt_header_t), CLUSTER_SAN_MSGTYPE_CLUSTER,
		0, B_TRUE, 3);
	kmem_free(buf, buflen);
	if (ret != 0) {
		cmn_err(CE_WARN, "%s: notify host(%d) to import pool(%s) failed",
			__func__, remote_hostid, spa_name);
	}

	return (ret);
	
}

void cluster_change_pool_owner_handle(cs_rx_data_t *cs_data)
{
	/* cluster_san_hostinfo_t *cshi = cs_data->cs_private; */
	char *buf;

	buf = kmem_zalloc(cs_data->data_len, KM_SLEEP);
	bcopy(cs_data->data, buf, cs_data->data_len);

	/* zfs_notify_clusterd(EVT_CHANGE_POOL_OWNER,
		buf, cs_data->data_len); */
	csh_rx_data_free(cs_data, B_TRUE);
}

int cluster_sel_failover_host(
	cluster_san_hostinfo_t *cshi, uint32_t need_failover)
{
	cluster_evt_header_t evt_header;
	uint64_t sync_msg_id;
	int ret;

	if (need_failover != 0) {
		evt_header.msg_type = CLUSTER_EVT_SEL_FAILOVER_HOST;
	} else {
		evt_header.msg_type = CLUSTER_EVT_CLR_FAILOVER_HOST;
	}
	sync_msg_id = atomic_inc_64_nv(&cluster_sync_msg_id);
	evt_header.msg_id = sync_msg_id;

	ret = cluster_san_host_sync_send_msg(cshi,
		NULL, 0, &evt_header, sizeof(cluster_evt_header_t),
		sync_msg_id, CLUSTER_SAN_MSGTYPE_CLUSTER, 30);

	return (ret);
}

int cluster_change_failover_host(cluster_san_hostinfo_t *cshi)
{
	int ret = 0;

	mutex_enter(&clustersan->cs_failover_host_lock);
	if (clustersan->cs_failover_host == cshi) {
		mutex_exit(&clustersan->cs_failover_host_lock);
		return (0);
	}
	if (clustersan->cs_failover_host != NULL) {
		ret = cluster_sel_failover_host(clustersan->cs_failover_host, 0);
		if (ret == 0) {
			cluster_san_hostinfo_rele(clustersan->cs_failover_host);
			clustersan->cs_failover_host = NULL;
		} else {
			mutex_exit(&clustersan->cs_failover_host_lock);
			cmn_err(CE_WARN, "%s: clear host(%d)'s failover label failed",
				__func__, clustersan->cs_failover_host->hostid);
			return (ret);
		}
	}
	if (cshi != NULL) {
		ret = cluster_sel_failover_host(cshi, 1);
		if (ret == 0) {
			cmn_err(CE_NOTE, "%s: changed failover host to host(%d)",
				__func__, cshi->hostid);
			cluster_san_hostinfo_hold(cshi);
			clustersan->cs_failover_host = cshi;
		}
	}
	mutex_exit(&clustersan->cs_failover_host_lock);

	return (ret);
}

uint32_t cluster_get_failover_hostid()
{
	uint32_t failover_hostid = 0;

	mutex_enter(&clustersan->cs_failover_host_lock);
	if (clustersan->cs_failover_host != NULL) {
		failover_hostid = clustersan->cs_failover_host->hostid;
	}
	mutex_exit(&clustersan->cs_failover_host_lock);
	return (failover_hostid);
}

void cluster_label_failover_host(cs_rx_data_t *cs_data, uint32_t need_failover)
{
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	cluster_evt_header_t *evt_header = cs_data->ex_head;

	cmn_err(CE_NOTE, "%s: msgid(%"PRId64") label failover host, host(%d) "
		"need failover(%d)",
		__func__, evt_header->msg_id, cshi->hostid, need_failover);
	mutex_enter(&cshi->lock);
	cshi->need_failover = need_failover;
	mutex_exit(&cshi->lock);
	cluster_san_host_sync_msg_ret(cshi, evt_header->msg_id,
		CLUSTER_SAN_MSGTYPE_CLUSTER, 0);
	if (need_failover == 0) {
		/* zfs_mirror_cancel_check_spa_txg(cshi->hostid); */
	}
	csh_rx_data_free(cs_data, B_TRUE);
}

void cluster_host_cancle_failover(uint32_t hostid)
{
	cluster_san_hostinfo_t *cshi;

	cshi = cluster_remote_hostinfo_hold(hostid);
	if (cshi != NULL) {
		cmn_err(CE_NOTE, "%s: cancle failover, host(%d)",
			__func__, cshi->hostid);
		mutex_enter(&cshi->lock);
		cshi->need_failover = 0;
		mutex_exit(&cshi->lock);
		cluster_san_hostinfo_rele(cshi);
	}
}

boolean_t cluster_host_need_failover(uint32_t hostid)
{
	cluster_san_hostinfo_t *cshi;
	boolean_t need_failover = B_FALSE;

	cshi = cluster_remote_hostinfo_hold(hostid);
	if (cshi != NULL) {
		mutex_enter(&cshi->lock);
		need_failover = (cshi->need_failover == 1);
		mutex_exit(&cshi->lock);
		cluster_san_hostinfo_rele(cshi);
	}
	return (need_failover);
}

void cluster_set_host_ipmi_ip(uint32_t hostid, char *ipmi_ipaddr)
{
	cluster_san_hostinfo_t *cshi = NULL;

	cmn_err(CE_NOTE, "%s: hostid=%d, ipmi_ipaddr=%s", __func__,
		hostid, ipmi_ipaddr);
	rw_enter(&clustersan_rwlock, RW_READER);
	if (hostid == 0) {
		cshi = &(clustersan->cs_host);
	} else {
		cshi = list_head(&clustersan->cs_hostlist);
		while (cshi != NULL) {
			if (cshi->hostid == hostid) {
				break;
			}
			cshi = list_next(&clustersan->cs_hostlist, cshi);
		}
	}
	if (cshi != NULL) {
		mutex_enter(&cshi->lock);
		if ((ipmi_ipaddr == NULL) || (ipmi_ipaddr[0] == '\0')) {
			cshi->ipmi_ipaddr[0] = '\0';
		} else {
			strncpy(cshi->ipmi_ipaddr, ipmi_ipaddr, 16);
			cshi->ipmi_ipaddr[15] = '\0';
		}

		if ((ipmi_ipaddr == NULL) || (ipmi_ipaddr[16] == '\0')) {
			cshi->host_ipaddr[0] = '\0';
		} else {
			strncpy(cshi->host_ipaddr, &ipmi_ipaddr[16], 16);
			cshi->host_ipaddr[15] = '\0';
		}
		mutex_exit(&cshi->lock);
	}
	rw_exit(&clustersan_rwlock);
}

void cluster_send_ipmi_ip(uint32_t hostid, char *ipmi_ipaddr)
{
	cluster_san_hostinfo_t *cshi;
	cluster_evt_header_t evt_header;
	uint64_t sync_msg_id;
	int ret;

	if (ipmi_ipaddr == NULL) {
		return;
	}

	cshi = cluster_remote_hostinfo_hold(hostid);
	if (cshi == NULL) {
		cmn_err(CE_WARN, "%s: don't find the host=%d from cluster",
			__func__, hostid);
		return;
	}

	evt_header.msg_type = CLUSTER_EVT_RX_IMPI_IPADDR;
	sync_msg_id = atomic_inc_64_nv(&cluster_sync_msg_id);
	evt_header.msg_id = sync_msg_id;
	ret = cluster_san_host_sync_send_msg(cshi,
		ipmi_ipaddr, 32, &evt_header, sizeof(cluster_evt_header_t),
		sync_msg_id, CLUSTER_SAN_MSGTYPE_CLUSTER, 30);	
	cluster_san_hostinfo_rele(cshi);
	cmn_err(CE_WARN, "%s: hostid=%d ipmi_ipaddr=%s local_ipaddr=%s"
		" msgid=0x%"PRIx64" ret=%d",
		__func__, hostid, ipmi_ipaddr, &ipmi_ipaddr[16], sync_msg_id, ret);
}

void cluster_rx_ipmi_ip(cs_rx_data_t *cs_data)
{
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	cluster_evt_header_t *evt_header = cs_data->ex_head;
	char *ipmi_ipaddr;
	char *host_ipaddr;

	ASSERT(cs_data->data_len = 32);
	ipmi_ipaddr = kmem_zalloc(16, KM_SLEEP);
	bcopy(cs_data->data, ipmi_ipaddr, 16);
	host_ipaddr = (char *)(cs_data->data) + 16;
	cmn_err(CE_NOTE, "%s: hostid=%d ipmi_ipaddr=%s local_ipaddr=%s"
		" msgid=0x%"PRIx64,
		__func__, cshi->hostid, ipmi_ipaddr, host_ipaddr,
		evt_header->msg_id);
	mutex_enter(&cshi->lock);
	strncpy(cshi->ipmi_ipaddr, ipmi_ipaddr, 16);
	cshi->ipmi_ipaddr[15] = '\0';
	strncpy(cshi->host_ipaddr, host_ipaddr, 16);
	cshi->host_ipaddr[15] = '\0';
	mutex_exit(&cshi->lock);
	cluster_san_host_sync_msg_ret(cshi, evt_header->msg_id,
		CLUSTER_SAN_MSGTYPE_CLUSTER, 0);
	/* notify clusterd to add route */
	/* zfs_notify_clusterd(EVT_IPMI_ADD_ROUTE, ipmi_ipaddr, 16); */
	csh_rx_data_free(cs_data, B_TRUE);
}

int cluster_get_host_ipmi_ip(uint32_t hostid, char *ipmi_ipaddr)
{
	cluster_san_hostinfo_t *cshi;

	if ((hostid == 0) || (ipmi_ipaddr == NULL)) {
		return (EINVAL);
	}
	cshi = cluster_remote_hostinfo_hold(hostid);
	if (cshi == NULL) {
		cmn_err(CE_NOTE, "%s: host(%d) not found", __func__, hostid);
		return (ENODEV);
	}
	mutex_enter(&cshi->lock);
	strncpy(ipmi_ipaddr, cshi->ipmi_ipaddr, 16);
	mutex_exit(&cshi->lock);
	ipmi_ipaddr[15] = '\0';
	return (0);
}

static int csh_fragment_expired_handle(void);

static void cluster_san_wd_thread(void *arg)
{
	mutex_enter(&clustersan->cs_wd_mtx);
	clustersan->cs_wd_flags |= CLUSTER_TARGET_TH_STATE_ACTIVE;
	while ((clustersan->cs_wd_flags & CLUSTER_TARGET_TH_STATE_STOP) == 0) {
		cv_timedwait(&clustersan->cs_wd_cv, &clustersan->cs_wd_mtx,
			ddi_get_lbolt() + drv_usectohz(cs_wd_polltime * 1000 * 1000));
#if (CLUSTER_SAN_MEMFREE_DEALAY == 1)
		/* mem free delayed */
		cs_cache_buf_wd_handle();
#endif
		csh_fragment_expired_handle();
	}
	clustersan->cs_wd_flags = 0;
	mutex_exit(&clustersan->cs_wd_mtx);
}

static void cluster_san_watchdog_init(void)
{
	mutex_init(&clustersan->cs_wd_mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&clustersan->cs_wd_cv, NULL, CV_DRIVER, NULL);
	clustersan->cs_wd_tq = taskq_create("clustersan_wd_tq",
		1, minclsyspri, 1, 1, TASKQ_PREPOPULATE);
	clustersan->cs_wd_flags = 0;
	taskq_dispatch(clustersan->cs_wd_tq, cluster_san_wd_thread,
		NULL, TQ_SLEEP);
}

static void cluster_san_watchdog_fini(void)
{
	mutex_enter(&clustersan->cs_wd_mtx);
	clustersan->cs_wd_flags |= CLUSTER_TARGET_TH_STATE_STOP;
	cv_signal(&clustersan->cs_wd_cv);
	mutex_exit(&clustersan->cs_wd_mtx);

	taskq_destroy(clustersan->cs_wd_tq);
	mutex_destroy(&clustersan->cs_wd_mtx);
	cv_destroy(&clustersan->cs_wd_cv);
}
int cluster_san_set_hostname(char *hostname)
{
	if (strlen(hostname) > 64) {
		printk("hostname is too large\n", hostname);
		return (-EINVAL);
	}
	memcpy(clustersan->cs_host.hostname, hostname, strlen(hostname));
	return (0);
}
int cluster_san_set_hostid(uint32_t hostid)
{
	if (hostid < 1 || hostid > 255) {
		printk("hostid %d error. ( 1 <= hostid <= 255)\n", hostid);
		return (-EINVAL);
	}
	clustersan->cs_host.hostid = hostid;
	return (0);
}
int cluster_san_enable(char *clustername, char *linkname, nvlist_t *nvl_conf)
{
	cluster_target_port_t *ctp;

	if ((clustername == NULL) && (linkname == NULL)) {
		return (-1);
	}

	if (clustersan->cs_host.hostid < 1 || clustersan->cs_host.hostid > 255) {
		printk("please set hostid.\n");
		return (-EPERM);
	}
	if (clustersan->cs_host.hostname && strlen(clustersan->cs_host.hostname) == 0) {
		printk("please set hostname.\n");
		return (-EPERM);
	}

	rw_enter(&clustersan_rwlock, RW_WRITER);
	if ((clustername != NULL) && (clustername[0] != '\0')) {
		if (clustersan->cs_state == CLUSTER_SAN_STATE_ENABLE) {
			cmn_err(CE_WARN, "cluster san already enabled, enabled name:%s, "
				"clustername:%s",
				clustersan->cs_name, clustername);
			rw_exit(&clustersan_rwlock);
			return (-1);
		}
		strncpy(clustersan->cs_name, clustername, MAXNAMELEN);
		clustersan->cs_state = CLUSTER_SAN_STATE_ENABLE;

		cluster_san_watchdog_init();
		cmn_err(CE_NOTE, "cluster san enabled, cluster:%s",
			clustername);
	}

	if ((linkname != NULL) && (linkname[0] != '\0')) {
		if (clustersan->cs_state != CLUSTER_SAN_STATE_ENABLE) {
			rw_exit(&clustersan_rwlock);
			cmn_err(CE_WARN, "cluster san disabled, not init taret(%s)",
				linkname);
			return (-1);
		}
		ctp = cluster_target_port_init(linkname, nvl_conf, TARGET_PROTOCOL_CLUSTER);
		if (ctp == NULL) {
			rw_exit(&clustersan_rwlock);
			cmn_err(CE_WARN, "cluster san target port(%s) init failed",
				linkname);
			return (-1);
		}
		cmn_err(CE_NOTE, "cluster san target enabled, link:%s",
			linkname);
	}
	rw_exit(&clustersan_rwlock);

	return (0);
}

void cluster_san_hostinfo_hold(cluster_san_hostinfo_t *cshi)
{
	if (cshi == NULL || (cshi == CLUSTER_SAN_BROADCAST_SESS)) {
		return;
	}
	atomic_inc_64(&cshi->ref_count);
}

void cluster_san_hostinfo_rele(cluster_san_hostinfo_t *cshi)
{
	uint64_t ref_count;

	if ((cshi == NULL) || (cshi == CLUSTER_SAN_BROADCAST_SESS)) {
		return;
	}

	ref_count = atomic_dec_64_nv(&cshi->ref_count);
	if (ref_count == 0) {
		cmn_err(CE_NOTE, "clustersan: destory host(%s,%d)",
			cshi->hostname, cshi->hostid);
		csh_asyn_tx_fini(cshi);
		cshi_sync_tx_msg_fini(cshi);
		cluster_san_host_rxworker_fini(cshi);
		mod_hash_destroy_ptrhash(cshi->host_reply_hash);
		kmem_free(cshi->hostname, strlen(cshi->hostname) + 1);
		mutex_destroy(&cshi->lock);
		kmem_free(cshi, sizeof(cluster_san_hostinfo_t));
	}
}

static void cluster_san_hostinfo_remove(cluster_san_hostinfo_t *cshi)
{
	cluster_target_session_t *cts;
	cts_list_pri_t *cts_list;

	ASSERT(RW_WRITE_HELD(&clustersan_rwlock));
	cmn_err(CE_NOTE, "clustersan: remove host(%s  %d)",
		cshi->hostname, cshi->hostid);
	mutex_enter(&cshi->lock);
	list_remove(&clustersan->cs_hostlist, cshi);
	clustersan->cs_hostcnt--;
	while ((cts_list = list_remove_head(&cshi->sesslist)) != NULL) {
		while ((cts = list_head(&cts_list->sess_list)) != NULL) {
			cts_remove(cts);
		}
		list_destroy(&cts_list->sess_list);
		kmem_free(cts_list, sizeof(cts_list_pri_t));
	}
	mutex_exit(&cshi->lock);
	cluster_san_hostinfo_rele(cshi);
}

cluster_san_hostinfo_t *cluster_remote_hostinfo_hold(uint32_t hostid)
{
	cluster_san_hostinfo_t *cshi;

	if (hostid == 0) {
		return (CLUSTER_SAN_BROADCAST_SESS);
	}

	rw_enter(&clustersan_rwlock, RW_READER);
	cshi = list_head(&clustersan->cs_hostlist);
	while (cshi != NULL) {
		if (cshi->hostid == hostid) {
			cluster_san_hostinfo_hold(cshi);
			break;
		}
		cshi = list_next(&clustersan->cs_hostlist, cshi);
	}
	rw_exit(&clustersan_rwlock);

	return (cshi);
}

int cluster_san_disable()
{
	cluster_target_port_t *ctp;
	cluster_target_port_t *ctp_next;
	cluster_san_hostinfo_t *cshi;

	rw_enter(&clustersan_rwlock, RW_WRITER);
	if (clustersan->cs_state != CLUSTER_SAN_STATE_ENABLE) {
		rw_exit(&clustersan_rwlock);
		cmn_err(CE_NOTE, "cluster san not enable");
		return (-1);
	}
	clustersan->cs_state = CLUSTER_SAN_STATE_DISABLE;
	rw_exit(&clustersan_rwlock);
	taskq_wait(clustersan->cs_async_taskq);

	cluster_san_watchdog_fini();
	rw_enter(&clustersan_rwlock, RW_WRITER);
	/* todo: broadcast quit the cluster san */

	while ((ctp = list_head(&clustersan->cs_target_list)) != NULL) {
		ctp_next = list_next(&clustersan->cs_target_list, ctp);
		cluster_target_port_remove(ctp, TARGET_PROTOCOL_CLUSTER);
		ctp = ctp_next;
	}

	while ((cshi = list_head(&clustersan->cs_hostlist)) != NULL) {
		cluster_san_hostinfo_remove(cshi);
	}

	cluster_change_failover_host(NULL);

	bzero(clustersan->cs_name, MAXNAMELEN);

	rw_exit(&clustersan_rwlock);
	cmn_err(CE_NOTE, "cluster san disabled");
	return (0);
}

int cluster_san_disable_target(char *link_name)
{
	cluster_target_port_t *ctp;
	int ret = 0;

	if ((link_name == NULL) || (link_name[0] == '\0')) {
		cmn_err(CE_WARN, "%s: link_name is NULL", __func__);
		return (-1);
	}

	rw_enter(&clustersan_rwlock, RW_WRITER);
	ctp = list_head(&clustersan->cs_target_list);
	while (ctp != NULL) {
		if (strncmp(link_name, ctp->link_name, MAXNAMELEN) == 0) {
			break;
		}
		ctp = list_next(&clustersan->cs_target_list, ctp);
	}

	if (ctp != NULL) {
		cluster_target_port_remove(ctp, TARGET_PROTOCOL_CLUSTER);
	} else {
		cmn_err(CE_WARN, "%s: don't find the target", __func__);
		ret = -1;
	}
	rw_exit(&clustersan_rwlock);
	return (ret);
}

nvlist_t *cluster_san_get_hostlist(uint32_t flags)
{
	nvlist_t *hostlist = NULL;
	nvlist_t *host = NULL;
	nvlist_t *remote = NULL;
	cluster_san_hostinfo_t *cshi;
	char *temp_name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	VERIFY(0 == nvlist_alloc(&hostlist, NV_UNIQUE_NAME, KM_SLEEP));

	rw_enter(&clustersan_rwlock, RW_READER);
	if (clustersan == NULL) {
		rw_exit(&clustersan_rwlock);
		nvlist_free(hostlist);
		kmem_free(temp_name, MAXNAMELEN);
		return (NULL);
	}
	/* local */
	VERIFY(0 == nvlist_alloc(&host, NV_UNIQUE_NAME, KM_SLEEP));
	VERIFY(0 == nvlist_add_string(host, CS_NVL_HOST_NAME,
		clustersan->cs_host.hostname));
	VERIFY(0 == nvlist_add_uint32(host, CS_NVL_HOST_ID,
		clustersan->cs_host.hostid));
	VERIFY(0 == nvlist_add_nvlist(hostlist, CS_NVL_THIS_HOST,
		host));
	nvlist_free(host);
	host = NULL;

	/* remote host list */
	cshi = list_head(&clustersan->cs_hostlist);
	while (cshi != NULL) {
		if (remote == NULL) {
			VERIFY(0 == nvlist_alloc(&remote, NV_UNIQUE_NAME, KM_SLEEP));
		}
		VERIFY(0 == nvlist_alloc(&host, NV_UNIQUE_NAME, KM_SLEEP));
		VERIFY(0 == nvlist_add_string(host, CS_NVL_HOST_NAME,
			cshi->hostname));
		VERIFY(0 == nvlist_add_uint32(host, CS_NVL_HOST_ID,
			cshi->hostid));
		snprintf(temp_name, MAXNAMELEN, "hostname: %s, hostid: %d",
			cshi->hostname, cshi->hostid);
		VERIFY(0 == nvlist_add_nvlist(remote, temp_name, host));
		nvlist_free(host);
		host = NULL;
		cshi = list_next(&clustersan->cs_hostlist, cshi);
	}
	if (remote != NULL) {
		VERIFY(0 == nvlist_add_nvlist(hostlist, CS_NVL_REMOTE_HOST, remote));
		nvlist_free(remote);
		remote = NULL;
	}
	rw_exit(&clustersan_rwlock);

	kmem_free(temp_name, MAXNAMELEN);
	return (hostlist);
}

nvlist_t *cluster_san_get_hostinfo(uint32_t hostid, uint32_t flags)
{
	nvlist_t *nvl_hostinfo = NULL;
	/* nvlist_t *nvl_poollist = NULL; */
	nvlist_t *nvl_sesslist = NULL;
	nvlist_t *nvl_sess = NULL;
	cluster_san_hostinfo_t *cshi = NULL;
	cluster_target_session_t *cts = NULL;
	cluster_target_port_t *ctp = NULL;
	cts_list_pri_t *cts_list;
	char *temp_name = NULL;

	if((hostid == 0) || (flags == 0)) {
		return (NULL);
	}

	rw_enter(&clustersan_rwlock, RW_READER);
	if (hostid == clustersan->cs_host.hostid) {
		VERIFY(0 == nvlist_alloc(&nvl_hostinfo, NV_UNIQUE_NAME, KM_SLEEP));
		VERIFY(0 == nvlist_add_string(nvl_hostinfo, CS_NVL_HOST_NAME,
			clustersan->cs_host.hostname));
		VERIFY(0 == nvlist_add_uint32(nvl_hostinfo, CS_NVL_HOST_ID,
			clustersan->cs_host.hostid));
		if ((flags & ZFS_CLUSTER_GET_HOST_EXTINFO) != 0) {
			/* get local host ip */
			mutex_enter(&clustersan->cs_host.lock);
			if (clustersan->cs_host.host_ipaddr[0] != '\0') {
				VERIFY(0 == nvlist_add_string(nvl_hostinfo,
					CS_NVL_HOST_IP, clustersan->cs_host.host_ipaddr));
			}
			mutex_exit(&clustersan->cs_host.lock);
		}
		if ((flags & ZFS_CLUSTER_GET_FAILOVER_FLAG) != 0) {
			mutex_enter(&clustersan->cs_failover_host_lock);
			if (clustersan->cs_failover_host != NULL) {
				VERIFY(0 == nvlist_add_uint32(nvl_hostinfo,
					CS_NVL_FAILOVER_HOST,
					clustersan->cs_failover_host->hostid));
			} else {
				VERIFY(0 == nvlist_add_uint32(nvl_hostinfo,
					CS_NVL_FAILOVER_HOST, 0));
			}
			mutex_exit(&clustersan->cs_failover_host_lock);
			/* get ipmi addr */
			mutex_enter(&clustersan->cs_host.lock);
			if (clustersan->cs_host.ipmi_ipaddr[0] != '\0') {
				VERIFY(0 == nvlist_add_string(nvl_hostinfo,
					CS_NVL_IPMI_ADDR, clustersan->cs_host.ipmi_ipaddr));
			}
			mutex_exit(&clustersan->cs_host.lock);
		}

		if ((flags & ZFS_CLUSTER_POOL_LIST_FLAG) != 0) {
			if (clustersan->cs_host.spa_config != NULL) {
				VERIFY(0 == nvlist_add_nvlist(nvl_hostinfo, CS_NVL_POOL_LIST,
					clustersan->cs_host.spa_config));
			}
		}
	} else {
		cshi = list_head(&clustersan->cs_hostlist);
		while (cshi != NULL) {
			if (cshi->hostid == hostid) {
				cluster_san_hostinfo_hold(cshi);
				break;
			}
			cshi = list_next(&clustersan->cs_hostlist, cshi);
		}
		if (cshi == NULL) {
			goto failed;
		}
		VERIFY(0 == nvlist_alloc(&nvl_hostinfo, NV_UNIQUE_NAME, KM_SLEEP));
		VERIFY(0 == nvlist_add_string(nvl_hostinfo, CS_NVL_HOST_NAME,
			cshi->hostname));
		VERIFY(0 == nvlist_add_uint32(nvl_hostinfo, CS_NVL_HOST_ID,
			cshi->hostid));
		if ((flags & ZFS_CLUSTER_GET_HOST_EXTINFO) != 0) {
			mutex_enter(&cshi->lock);
			/* get host ip addr */
			if (cshi->ipmi_ipaddr[0] != '\0') {
				VERIFY(0 == nvlist_add_string(nvl_hostinfo,
					CS_NVL_HOST_IP, cshi->host_ipaddr));
			}
			mutex_exit(&cshi->lock);
		}
		if ((flags & ZFS_CLUSTER_GET_FAILOVER_FLAG) != 0) {
			mutex_enter(&cshi->lock);
			VERIFY(0 == nvlist_add_uint32(nvl_hostinfo, CS_NVL_NEED_FAILOVER,
				cshi->need_failover));
			/* get ipmi addr */
			if (cshi->ipmi_ipaddr[0] != '\0') {
				VERIFY(0 == nvlist_add_string(nvl_hostinfo,
					CS_NVL_IPMI_ADDR, cshi->ipmi_ipaddr));
			}
			mutex_exit(&cshi->lock);
		}

		if ((flags & ZFS_CLUSTER_SESSION_LIST_FLAG) != 0) {
			temp_name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
			VERIFY(0 == nvlist_add_uint32(nvl_hostinfo, CS_NVL_STATE,
				cshi->link_state));
			mutex_enter(&cshi->lock);
			cts_list = list_head(&cshi->sesslist);
			while (cts_list != NULL) {
				cts = list_head(&cts_list->sess_list);
				while (cts != NULL) {
					if (nvl_sesslist == NULL) {
						VERIFY(0 == nvlist_alloc(&nvl_sesslist, NV_UNIQUE_NAME, KM_SLEEP));
					}
					VERIFY(0 == nvlist_alloc(&nvl_sess, NV_UNIQUE_NAME, KM_SLEEP));
					VERIFY(0 == nvlist_add_uint32(nvl_sess, CS_NVL_LINK_PRI,
						cts->sess_pri));
					VERIFY(0 == nvlist_add_uint32(nvl_sess, CS_NVL_SESS_LINK_STATE,
						cts->sess_linkstate));
					ctp = cts->sess_port_private;
					ctp->f_cts_get_info(cts, nvl_sess);
					snprintf(temp_name, MAXNAMELEN, "session: %d", cts->sess_id);
					VERIFY(0 == nvlist_add_nvlist(nvl_sesslist, temp_name, nvl_sess));
					nvlist_free(nvl_sess);
					nvl_sess = NULL;
					cts = list_next(&cts_list->sess_list, cts);
				}
				cts_list = list_next(&cshi->sesslist, cts_list);
			}
			mutex_exit(&cshi->lock);
			if (nvl_sesslist != NULL) {
				VERIFY(0 == nvlist_add_nvlist(nvl_hostinfo, CS_NVL_SESS_LIST,
					nvl_sesslist));
				nvlist_free(nvl_sesslist);
				nvl_sesslist = NULL;
			}
		}

		if ((flags & ZFS_CLUSTER_POOL_LIST_FLAG) != 0) {
			if (cshi->spa_config != NULL) {
				VERIFY(0 == nvlist_add_nvlist(nvl_hostinfo, CS_NVL_POOL_LIST,
					cshi->spa_config));
			}
		}
	}

failed:
	rw_exit(&clustersan_rwlock);
	if (temp_name != NULL) {
		kmem_free(temp_name, MAXNAMELEN);
	}

	return (nvl_hostinfo);
}

nvlist_t *cluster_san_get_targetlist()
{
	nvlist_t *nvl_targetlist = NULL;
	nvlist_t *nvl_target = NULL;
	nvlist_t *nvl_sesslist = NULL;
	nvlist_t *nvl_sess = NULL;
	cluster_target_port_t *ctp;
	cluster_target_session_t *cts;
	char *temp_name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	VERIFY(0 == nvlist_alloc(&nvl_targetlist, NV_UNIQUE_NAME, KM_SLEEP));
	rw_enter(&clustersan_rwlock, RW_READER);
	if (clustersan == NULL) {
		rw_exit(&clustersan_rwlock);
		nvlist_free(nvl_targetlist);
		kmem_free(temp_name, MAXNAMELEN);
		return (NULL);
	}
	/* target list */
	ctp = list_head(&clustersan->cs_target_list);
	while (ctp != NULL) {
		VERIFY(0 == nvlist_alloc(&nvl_target, NV_UNIQUE_NAME, KM_SLEEP));
		VERIFY(0 == nvlist_add_uint32(nvl_target, CS_NVL_LINK_PRI, ctp->pri));
		ctp->f_ctp_get_info(ctp, nvl_target);
		/* sess list */
		VERIFY(0 == nvlist_alloc(&nvl_sesslist, NV_UNIQUE_NAME, KM_SLEEP));
		cts = list_head(&ctp->ctp_sesslist);
		while (cts != NULL) {
			VERIFY(0 == nvlist_alloc(&nvl_sess, NV_UNIQUE_NAME, KM_SLEEP));
			VERIFY(0 == nvlist_add_uint32(nvl_sess, CS_NVL_LINK_PRI,
				cts->sess_pri));
			VERIFY(0 == nvlist_add_uint32(nvl_sess, CS_NVL_SESS_LINK_STATE,
				cts->sess_linkstate));
			ctp->f_cts_get_info(cts, nvl_sess);
			snprintf(temp_name, MAXNAMELEN, "session: %d", cts->sess_id);
			VERIFY(0 == nvlist_add_nvlist(nvl_sesslist, temp_name, nvl_sess));
			nvlist_free(nvl_sess);
			nvl_sess = NULL;
			cts = list_next(&ctp->ctp_sesslist, cts);
		}
		VERIFY(0 == nvlist_add_nvlist(nvl_target, CS_NVL_SESS_LIST, nvl_sesslist));
		nvlist_free(nvl_sesslist);
		nvl_sesslist = NULL;
		VERIFY(0 == nvlist_add_nvlist(nvl_targetlist, ctp->link_name, nvl_target));
		nvlist_free(nvl_target);
		nvl_target = NULL;
		ctp = list_next(&clustersan->cs_target_list, ctp);
	}
	
	rw_exit(&clustersan_rwlock);
	kmem_free(temp_name, MAXNAMELEN);

	return (nvl_targetlist);
}

nvlist_t *cluster_san_get_targetinfo(char *name, uint32_t flags)
{
	cluster_target_port_t *ctp;
	cluster_target_session_t *cts;
	nvlist_t *nvl_target = NULL;
	nvlist_t *nvl_sesslist = NULL;
	nvlist_t *nvl_sess = NULL;
	char *temp_name;

	rw_enter(&clustersan_rwlock, RW_READER);
	if (clustersan == NULL) {
		rw_exit(&clustersan_rwlock);
		return (NULL);
	}

	ctp = list_head(&clustersan->cs_target_list);
	while (ctp != NULL) {
		if (strncmp(name, ctp->link_name, MAXNAMELEN) == 0) {
			if (cluster_target_port_hold(ctp) != 0) {
				ctp = NULL;
			}
			break;
		}
		ctp = list_next(&clustersan->cs_target_list, ctp);
	}
	rw_exit(&clustersan_rwlock);

	if (ctp != NULL) {
		VERIFY(0 == nvlist_alloc(&nvl_target, NV_UNIQUE_NAME, KM_SLEEP));
		VERIFY(0 == nvlist_add_uint32(nvl_target, CS_NVL_LINK_PRI, ctp->pri));
		temp_name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
		ctp->f_ctp_get_info(ctp, nvl_target);
		/* sess list */
		VERIFY(0 == nvlist_alloc(&nvl_sesslist, NV_UNIQUE_NAME, KM_SLEEP));
		cts = list_head(&ctp->ctp_sesslist);
		while (cts != NULL) {
			VERIFY(0 == nvlist_alloc(&nvl_sess, NV_UNIQUE_NAME, KM_SLEEP));
			VERIFY(0 == nvlist_add_uint32(nvl_sess, CS_NVL_LINK_PRI,
				cts->sess_pri));
			VERIFY(0 == nvlist_add_uint32(nvl_sess, CS_NVL_SESS_LINK_STATE,
				cts->sess_linkstate));
			ctp->f_cts_get_info(cts, nvl_sess);
			snprintf(temp_name, MAXNAMELEN, "session: %d", cts->sess_id);
			VERIFY(0 == nvlist_add_nvlist(nvl_sesslist, temp_name, nvl_sess));
			nvlist_free(nvl_sess);
			nvl_sess = NULL;
			cts = list_next(&ctp->ctp_sesslist, cts);
		}
		VERIFY(0 == nvlist_add_nvlist(nvl_target, CS_NVL_SESS_LIST, nvl_sesslist));
		nvlist_free(nvl_sesslist);
		kmem_free(temp_name, MAXNAMELEN);
		cluster_target_port_rele(ctp);
	}

	return (nvl_target);
}

nvlist_t *cluster_san_get_state()
{
	nvlist_t *nvl_state;
	char *failover;
	VERIFY(0 == nvlist_alloc(&nvl_state, NV_UNIQUE_NAME, KM_SLEEP));
	rw_enter(&clustersan_rwlock, RW_READER);
	if (clustersan == NULL) {
		rw_exit(&clustersan_rwlock);
		nvlist_free(nvl_state);
		return (NULL);
	}
	VERIFY(0 == nvlist_add_uint32(nvl_state, CS_NVL_STATE,
		clustersan->cs_state));
	if (clustersan->cs_state == CLUSTER_SAN_STATE_ENABLE) {
		VERIFY(0 == nvlist_add_string(nvl_state, CS_NVL_NAME,
			clustersan->cs_name));
		if (cluster_session_select_strategy == CLUSTER_SESSION_SEL_ROUNDROBIN) {
			failover = "roundrobin";
		} else if(cluster_session_select_strategy == CLUSTER_SESSION_SEL_LOADBALANCING) {
			failover = "loadbalance";
		} else {
			failover = "unknown";
		}
		VERIFY(0 == nvlist_add_string(nvl_state, CS_NVL_FAILOVER,
			failover));
		VERIFY(0 == nvlist_add_uint32(nvl_state, CS_NVL_IPMI_SWITCH,
			cluster_failover_ipmi_switch));
	}
	rw_exit(&clustersan_rwlock);
	return (nvl_state);
}

int cluster_san_set_prop(const char *prop, const char *value)
{
	int ret = 0;
	if ((prop == NULL) || (value == NULL)) {
		return (-1);
	}
	if (strcmp(prop, CLUSTER_PROP_FAILOVER) == 0) {
		if (strcmp(value, "roundrobin") == 0) {
			atomic_swap_32(&cluster_session_select_strategy,
				CLUSTER_SESSION_SEL_ROUNDROBIN);
		} else if (strcmp(value, "loadbalance") == 0) {
			atomic_swap_32(&cluster_session_select_strategy,
				CLUSTER_SESSION_SEL_LOADBALANCING);
		} else {
			ret = -1;
		}
	} else if (strcmp(prop, CLUSTER_PROP_IPMI_SWITCH) == 0) {
		if (strcmp(value, "on") == 0) {
 			atomic_swap_32(&cluster_failover_ipmi_switch, 1);
		} else if (strcmp(value, "off") == 0) {
			atomic_swap_32(&cluster_failover_ipmi_switch, 0);
		} else {
			ret = -1;
		}
	} else {
		ret = -1;
	}
	if (ret == 0) {
		cmn_err(CE_NOTE, "clustersan: set %s=%s", prop, value);
	} else {
		cmn_err(CE_NOTE, "clustersan: set %s=%s, failed", prop, value);
	}

	return (ret);
}

void cluster_san_host_walk(
	uint_t (*callback)(cluster_san_hostinfo_t *, void *), void *arg)
{
	cluster_san_hostinfo_t *cshi;
	uint_t ret = CS_WALK_CONTINUE;

	rw_enter(&clustersan_rwlock, RW_READER);
	if (clustersan == NULL) {
		rw_exit(&clustersan_rwlock);
		return;
	}
	cshi = list_head(&clustersan->cs_hostlist);
	while ((cshi != NULL) && (ret == CS_WALK_CONTINUE)) {
		ret = callback(cshi, arg);
		cshi = list_next(&clustersan->cs_hostlist, cshi);
	}
	rw_exit(&clustersan_rwlock);
}

typedef struct cts_fragments {
	avl_node_t		avl_node;
	list_node_t		list_node;/* time sort */
	cs_rx_data_t	*cs_data;
	uint64_t		rx_len;
	list_t			data_list;
	int64_t		active_time;/* last access time */
} cts_fragments_t;

/* static cts_fragment_data_t *
cts_mblk_to_fragment (mblk_t *mp)
{
	cts_fragment_data_t *fragment;

	return (fragment);
} */

static void cts_fragment_free(cts_fragment_data_t *fragment)
{
	cluster_target_port_t *ctp;
	if (fragment == NULL) {
		return;
	}
	ctp = fragment->target_port;
	ctp->f_fragment_free(fragment);
}

static void cluster_target_rxmsg_free(cts_fragment_data_t *fragment)
{
	cluster_target_port_t *ctp;
	if (fragment == NULL) {
		return;
	}
	ctp = fragment->target_port;
	ctp->f_rxmsg_free(fragment->rx_msg);
	fragment->data = NULL;
	fragment->phy_head = NULL;
	fragment->ct_head = NULL;
	fragment->ex_head = NULL;
	fragment->rx_msg = NULL;
}

static void cts_fragment_insert_by_sort (cts_fragments_t *ctsfs, cts_fragment_data_t *fragment)
{
	cts_fragment_data_t *prev = NULL;
	cts_fragment_data_t *next = NULL;
	cs_rx_data_t *cs_data = ctsfs->cs_data;
	uint64_t offset_temp;

	if ((fragment->offset + fragment->len) > cs_data->data_len) {
		/* overstep */
		cts_fragment_free(fragment);
		return;
	}

	prev = list_tail(&ctsfs->data_list);
	while (prev != NULL) {
		offset_temp = prev->offset;
		if (offset_temp == fragment->offset) {
			/* same fragment */
			cts_fragment_free(fragment);
			return;
		}
		if (offset_temp < fragment->offset) {
			/* The first lesser offset data */
			break;
		}
		next = prev;
		prev = list_prev(&ctsfs->data_list, prev);
	}

	if (prev != NULL) {
		if ((prev->offset + prev->len) > fragment->offset) {
			/* overlap */
			cts_fragment_free(fragment);
			return;
		}
	}
	if (next != NULL) {
		if ((fragment->offset + fragment->len) > next->offset) {
			/* overlap */
			cts_fragment_free(fragment);
			return;
		}
	}

	if (prev == NULL) {
		list_insert_head(&ctsfs->data_list, fragment);
	} else {
		list_insert_after(&ctsfs->data_list, prev, fragment);
	}
	if (fragment->len != 0) {
		bcopy(fragment->data, cs_data->data + fragment->offset, fragment->len);
		cluster_target_rxmsg_free(fragment);
	}
	atomic_add_64(&ctsfs->rx_len, fragment->len);
}

static void cts_fragments_clear_list(cts_fragments_t *ctsfs)
{
	cts_fragment_data_t *fragment;
	while ((fragment = list_remove_head(&ctsfs->data_list)) != NULL) {
		cts_fragment_free(fragment);
	}
}

static void cts_fragments_free(cts_fragments_t *ctsfs)
{
	cts_fragments_clear_list(ctsfs);
	list_destroy(&ctsfs->data_list);
	kmem_free(ctsfs, sizeof(cts_fragments_t));
}

static boolean_t cts_fragments_entired(
	cts_fragments_t *ctsfs, cts_fragment_data_t *fragment, boolean_t *is_corrupt)
{
	cs_rx_data_t *cs_data = ctsfs->cs_data;
	cts_fragment_insert_by_sort(ctsfs, fragment);
	if (ctsfs->rx_len == cs_data->data_len) {
		*is_corrupt = B_FALSE;
		return (B_TRUE);
	}
	if (ctsfs->rx_len > cs_data->data_len) {
		cmn_err(CE_WARN, "%s: the data rx failed(msg_type:0x%x, data_index:%"
			PRId64", data_len:0x%"PRIx64", rx_len:0x%"PRIx64")",
			__func__, ctsfs->cs_data->msg_type, ctsfs->cs_data->data_index,
			ctsfs->cs_data->data_len, ctsfs->rx_len);
		*is_corrupt = B_TRUE;
		return (B_TRUE);
	}
	return (B_FALSE);
}

static void cts_rx_data_check_link(cluster_target_session_t *cts)
{
	boolean_t DOWN2UP = B_FALSE;

	mutex_enter(&cts->sess_lock);
	if ((cts->sess_flags & CLUSTER_TARGET_SESS_FLAG_UINIT) != 0) {
		mutex_exit(&cts->sess_lock);
		return;
	}
	if (cts->sess_linkstate != CTS_LINK_UP) {
		cts->sess_linkstate = CTS_LINK_UP;
		DOWN2UP = B_TRUE;
	}
	mutex_exit(&cts->sess_lock);

	if (DOWN2UP) {
		if (cluster_target_session_hold(cts, "down2up evt") == 0) {
			taskq_dispatch(clustersan->cs_async_taskq,
				cts_link_down_to_up_handle, (void *)cts, TQ_SLEEP);
		}
	}
}

static void cts_rx_hb_handle(cs_rx_data_t *cs_data)
{
	cts_rx_data_free(cs_data, B_TRUE);
}

void
cts_rx_worker_wakeup(cts_rx_worker_t *w, cts_worker_para_t *para)
{
	mutex_enter(&w->worker_mtx);
	list_insert_tail(w->worker_list_w, para);
	atomic_inc_32(&w->worker_ntasks);
	if (w->worker_ntasks == 1) {
		cv_broadcast(&w->worker_cv);
	}
	mutex_exit(&w->worker_mtx);
}

static void
cluster_target_session_worker_handle(void *arg)
{
	cts_rx_worker_t	*w = (cts_rx_worker_t *)arg;
	cts_rx_worker_t	*host_rxworker;
	cluster_target_session_t *cts = w->worker_private;
	cluster_san_hostinfo_t *cshi = cts->sess_host_private;
	cts_worker_para_t *para;
	/* cts_fragments_t *fragments; */

	atomic_inc_32(&cts->sess_rx_worker_n);
	mutex_enter(&w->worker_mtx);
	w->worker_flags |= CLUSTER_TARGET_TH_STATE_ACTIVE;
	while ((w->worker_flags & CLUSTER_TARGET_TH_STATE_STOP) == 0) {
		mutex_exit(&w->worker_mtx);
		while (1) {
			para = list_remove_head(w->worker_list_r);
			if (para != NULL) {
				atomic_dec_32(&w->worker_ntasks);
				cts_rx_data_check_link(cts);
				cluster_target_session_rele(cts, "cts_find");
				if (para->msg_type == CLUSTER_SAN_MSGTYPE_HB) {
					cts_fragment_free(para->fragment);
					kmem_free(para, sizeof(cts_worker_para_t));
					continue;
				}
				host_rxworker =
					&cshi->host_rx_worker[para->index % cshi->host_rx_worker_n];
				para->worker = host_rxworker;
				cts_rx_worker_wakeup(host_rxworker, para);
			} else {
				break;
			}
		}
		mutex_enter(&w->worker_mtx);
		if (w->worker_ntasks == 0) {
			cv_timedwait(&w->worker_cv, &w->worker_mtx, ddi_get_lbolt() + msecs_to_jiffies(60000));
		} else {
			list_t *temp_list;
			temp_list = w->worker_list_r;
			w->worker_list_r = w->worker_list_w;
			w->worker_list_w = temp_list;
		}
	}
	mutex_exit(&w->worker_mtx);

	w->worker_flags = 0;
	atomic_dec_32(&cts->sess_rx_worker_n);
}

static int
cts_rxworker_avl_compare(const void *a1, const void *a2)
{
	cts_fragments_t *ctsfs_compare = (cts_fragments_t *)a1;
	cts_fragments_t *ctsfs = (cts_fragments_t *)a2;
	if (ctsfs_compare->cs_data->data_index > ctsfs->cs_data->data_index) {
		return (1);
	}
	if (ctsfs_compare->cs_data->data_index < ctsfs->cs_data->data_index) {
		return (-1);
	}
	return (0);
}

static void cluster_target_session_worker_init(cluster_target_session_t *cts)
{
	char *tq_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	int i;

	snprintf(tq_name, MAXNAMELEN, "sess_rx_worker_tq_%d", cts->sess_id);
	cts->sess_rx_worker_tq = taskq_create(tq_name,
		cluster_target_session_nrxworker, minclsyspri,
		cluster_target_session_nrxworker, cluster_target_session_nrxworker,
		TASKQ_PREPOPULATE);
	cts->sess_rx_worker = (cts_rx_worker_t *)kmem_zalloc(
		sizeof (cts_rx_worker_t) * cluster_target_session_nrxworker,
		KM_SLEEP);
	for (i = 0; i < cluster_target_session_nrxworker; i++) {
		cts_rx_worker_t *w = &cts->sess_rx_worker[i];
		mutex_init(&w->fragment_lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&w->worker_mtx, NULL, MUTEX_DRIVER, NULL);
		cv_init(&w->worker_cv, NULL, CV_DRIVER, NULL);
		w->worker_flags = 0;
		avl_create(&w->fragment_avl, cts_rxworker_avl_compare,
			sizeof(cts_fragments_t), offsetof(cts_fragments_t, avl_node));
		list_create(&w->fragment_list,
			sizeof(cts_fragments_t), offsetof(cts_fragments_t, list_node));
		list_create(&w->worker_list1,
			sizeof(cts_worker_para_t),
		    offsetof(cts_worker_para_t, node));
		list_create(&w->worker_list2,
			sizeof(cts_worker_para_t),
		    offsetof(cts_worker_para_t, node));
		w->worker_list_r = &w->worker_list1;
		w->worker_list_w = &w->worker_list2;
		/* todo: hold cts */
		w->worker_private = cts;
		w->worker_index = i;
		(void) taskq_dispatch(cts->sess_rx_worker_tq, 
		    cluster_target_session_worker_handle,
		    w, TQ_SLEEP);
	}
	kmem_free(tq_name, MAXNAMELEN);
	while (cts->sess_rx_worker_n  != cluster_target_session_nrxworker) {
		delay(drv_usectohz(10000));
	}
}

static void cts_worker_list_clear(
	cluster_target_session_t *cts, list_t *worker_list)
{
	cts_worker_para_t *para;

	while ((para = list_remove_head(worker_list)) != NULL) {
		cts_fragment_free(para->fragment);
		kmem_free(para, sizeof(cts_worker_para_t));
		cluster_target_session_rele(cts, "cts_find");
	}
}

static void cluster_target_session_worker_fini(cluster_target_session_t *cts)
{
	int i;
	cts_rx_worker_t *w;
	/* cts_worker_para_t *para; */
	cts_fragments_t *ctsfs;
	void *cookie = NULL;

	for (i = 0; i < cluster_target_session_nrxworker; i++) {
		w = &cts->sess_rx_worker[i];
		mutex_enter(&w->worker_mtx);
		w->worker_flags |= CLUSTER_TARGET_TH_STATE_STOP;
		cv_signal(&w->worker_cv);
		mutex_exit(&w->worker_mtx);
	}

	while (cts->sess_rx_worker_n != 0) {
		delay(drv_usectohz(10000));
	}
	taskq_destroy(cts->sess_rx_worker_tq);

	for (i = 0; i < cluster_target_session_nrxworker; i++) {
		w = &cts->sess_rx_worker[i];
		cts_worker_list_clear(cts, &w->worker_list1);
		cts_worker_list_clear(cts, &w->worker_list2);
		while ((ctsfs = avl_destroy_nodes(&w->fragment_avl, &cookie)) != NULL) {
			list_remove(&w->fragment_list, ctsfs);
			cts_fragments_clear_list(ctsfs);
			list_destroy(&ctsfs->data_list);
			cts_rx_data_free(ctsfs->cs_data, B_FALSE);
			kmem_free(ctsfs, sizeof(cts_fragments_t));
		}
		mutex_destroy(&w->fragment_lock);
		mutex_destroy(&w->worker_mtx);
		cv_destroy(&w->worker_cv);
		avl_destroy(&w->fragment_avl);
		list_destroy(&w->fragment_list);
		list_destroy(&w->worker_list1);
		list_destroy(&w->worker_list2);
	}

	kmem_free(cts->sess_rx_worker,
		sizeof (cts_rx_worker_t) * cluster_target_session_nrxworker);
	cts->sess_rx_worker = NULL;
}

static int cts_fragment_expired_handle(cluster_target_session_t *cts)
{
	int i;
	int cnt = 0;
	cts_rx_worker_t *w;
	cts_fragments_t *ctsfs;
	cts_fragments_t *ctsfs_next;
	list_t clean_list;
	int64_t cur_lbolt = ddi_get_lbolt64();
	int64_t expired_time = drv_usectohz(cts_fragment_expired_time);

	list_create(&clean_list,
			sizeof(cts_fragments_t), offsetof(cts_fragments_t, list_node));
	for (i = 0; i < cluster_target_session_nrxworker; i++) {
		w = &cts->sess_rx_worker[i];
		if (w == NULL) {
			continue;
		}
		mutex_enter(&w->fragment_lock);
		ctsfs = list_head(&w->fragment_list);
		while (ctsfs != NULL) {
			if ((cur_lbolt - ctsfs->active_time) < expired_time) {
				break;
			}
			ctsfs_next = list_next(&w->fragment_list, ctsfs);
			list_remove(&w->fragment_list, ctsfs);
			avl_remove(&w->fragment_avl, ctsfs);
			list_insert_tail(&clean_list, ctsfs);
			cnt++;
			ctsfs = ctsfs_next;
		}
		mutex_exit(&w->fragment_lock);
	}

	while ((ctsfs = list_remove_head(&clean_list)) != NULL) {
		cts_rx_data_free(ctsfs->cs_data, B_FALSE);
		cts_fragments_free(ctsfs);
	}
	list_destroy(&clean_list);

	return (cnt);
}

static cs_rx_data_t *cluster_san_host_rxfragment_handle(
	cts_rx_worker_t	*w,
	cts_fragment_data_t *fragment,
	uint64_t data_index, uint64_t total_len, uint8_t msg_type,
	uint8_t need_reply)
{
	cs_rx_data_t ctsrd_compare;
	cts_fragments_t ctsfs_compare;
	cs_rx_data_t *cs_data;
	cts_fragments_t *ctsfs = NULL;
	avl_index_t where;
	boolean_t is_entired;
	boolean_t is_newdata = B_FALSE;
	boolean_t is_corrupt = B_FALSE;

	ctsrd_compare.data_index = data_index;
	ctsfs_compare.cs_data = &ctsrd_compare;
	mutex_enter(&w->fragment_lock);
	ctsfs = avl_find(&w->fragment_avl, &ctsfs_compare, &where);
	if (ctsfs == NULL) {
		ctsfs = kmem_zalloc(sizeof(cts_fragments_t), KM_SLEEP);
		ctsfs->cs_data = cts_rx_data_alloc(total_len);
		ctsfs->cs_data->data_index = data_index;
		ctsfs->cs_data->msg_type = msg_type;
		ctsfs->cs_data->cs_private = w->worker_private;
		ctsfs->cs_data->need_reply = need_reply;
		ctsfs->rx_len = 0;
		list_create(&ctsfs->data_list, sizeof(cts_fragment_data_t),
			offsetof(cts_fragment_data_t, node));
		is_newdata = B_TRUE;
	}
	if (fragment->ex_len != 0) {
		if (ctsfs->cs_data->ex_head == NULL) {
			ctsfs->cs_data->ex_head = kmem_zalloc(fragment->ex_len, KM_SLEEP);
			bcopy(fragment->ex_head, ctsfs->cs_data->ex_head, fragment->ex_len);
			ctsfs->cs_data->ex_len = fragment->ex_len;
		}
	}
	is_entired = cts_fragments_entired(ctsfs, fragment, &is_corrupt);
	if (is_entired) {
		if (!is_newdata) {
			list_remove(&w->fragment_list, ctsfs);
			avl_remove(&w->fragment_avl, ctsfs);
		}
		mutex_exit(&w->fragment_lock);
		if (is_corrupt) {
			csh_rx_data_free(ctsfs->cs_data, B_FALSE);
			cs_data = NULL;
		} else {
			cs_data = ctsfs->cs_data;
		}
		cts_fragments_free(ctsfs);
		cluster_san_hostinfo_hold(cs_data->cs_private);
		return (cs_data);
	}
	
	if (is_newdata) {
		avl_add(&w->fragment_avl, ctsfs);
		ctsfs->active_time = ddi_get_lbolt64();
		list_insert_tail(&w->fragment_list, ctsfs);
	} else {
		list_remove(&w->fragment_list, ctsfs);
		ctsfs->active_time = ddi_get_lbolt64();
		list_insert_tail(&w->fragment_list, ctsfs);
	}
	mutex_exit(&w->fragment_lock);

	return (NULL);
}

cluster_target_session_t *cts_select_from_host(cluster_san_hostinfo_t *cshi)
{
	cluster_target_session_t *cur_cts;
	cluster_target_session_t *cts_temp;
	cluster_target_session_t *cts = NULL;
	cluster_target_session_t *rel_cts = NULL;
	cts_list_pri_t *cts_list;
	cts_list_pri_t *cur_cts_list;
	int cts_is_down = 0;
	int sel_next = 0;

	mutex_enter(&cshi->lock);
	cur_cts = cshi->cur_sess;
	if (cur_cts == NULL) {
		cts_is_down = 1;
		sel_next = 1;
	} else if (cur_cts->sess_linkstate == CTS_LINK_DOWN) {
		sel_next = 1;
		cts_is_down = 1;
	} else {
		if (cluster_session_select_strategy ==
			CLUSTER_SESSION_SEL_LOADBALANCING) {
			sel_next = 1;
		} else {
			sel_next = 0;
		}
	}

	if (sel_next == 1) {
		if (cur_cts != NULL) {
			cur_cts_list = cur_cts->host_list;
		} else {
			cur_cts_list = list_head(&cshi->sesslist);
			if (cur_cts_list == NULL) {
				mutex_exit(&cshi->lock);
				return (NULL);
			}
		}
		cts_list = cur_cts_list;
		cts_temp = cur_cts;
TRY_ANOTHER_PRI:
		cts = NULL;
		if (cts_temp != NULL) {
			cts = list_next(&(cts_list->sess_list), cts_temp);
		}
		if (cts == NULL) {
			cts = list_head(&(cts_list->sess_list));
		}
		while (cts_temp != cts) {
			if (cts == NULL) {
				break;
			}
			if (cts->sess_linkstate == CTS_LINK_UP) {
				if (cluster_target_session_hold(cts, "host_send") == 0) {
					rel_cts = cur_cts;
					cur_cts = cts;
					break;
				}
			}
			cts = list_next(&(cts_list->sess_list), cts);
			if (cts == NULL) {
				if (cts_temp != NULL) {
					cts = list_head(&(cts_list->sess_list));
				}
			}
		}

		if (cts_temp == cts) {
			/* not found */
			if (cts_is_down != 0) {
				cts_list = list_next(&cshi->sesslist, cts_list);
				if (cts_list == NULL) {
					cts_list = list_head(&cshi->sesslist);
				}
				if (cts_list != cur_cts_list) {
					cts_temp = NULL;
					goto TRY_ANOTHER_PRI;
				} else {
					rel_cts = cur_cts;
					cur_cts = NULL;
				}
			}
		}
	}
	cshi->cur_sess = cur_cts;
	if (cur_cts != NULL) {
		if (cluster_target_session_hold(cur_cts, "sel_cts") != 0) {
			cur_cts = NULL;
		}
	}
	mutex_exit(&cshi->lock);

	if (rel_cts != NULL) {
		cluster_target_session_rele(rel_cts, "host_send");
	}

	return (cur_cts);
}

static void csh_send_reply(cs_rx_data_t *cs_data)
{
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	cluster_target_session_t *cts;
	cluster_target_port_t *ctp;
	cluster_target_tran_data_t *data_array = NULL;
	int fragment_cnt = 0;
	cluster_tran_data_origin_t origin_data;
	int ret;

	cts = cts_select_from_host(cshi);

	if (cts == NULL) {
		return;
	}
	if ((cts->sess_flags & CLUSTER_TARGET_SESS_FLAG_UINIT) != 0) {
		cluster_target_session_rele(cts, "sel_cts");
		return;
	}
	ctp = cts->sess_port_private;
	if (ctp_tx_hold(ctp) != 0) {
		cluster_target_session_rele(cts, "sel_cts");
		return;
	}

	origin_data.msg_type = CLUSTER_SAN_MSGTYPE_REPLY;
	origin_data.need_reply = B_FALSE;
	origin_data.retry_times = 0;
	origin_data.index = cs_data->data_index;
	origin_data.data = 0;
	origin_data.data_len = 0;
	origin_data.header = 0;
	origin_data.header_len = 0;

	if (ctp->target_type == CLUSTER_TARGET_RPC_RDMA) {
		ret = ctp->f_session_tran_start(cts, &origin_data);
		ctp_tx_rele(ctp);
		cluster_target_session_rele(cts, "sel_cts");
		return;
	}

	ret = ctp->f_tran_fragment(ctp->target_private, cts->sess_target_private,
		&origin_data, &data_array, &fragment_cnt);

	if (ret == 0) {
		ASSERT(fragment_cnt == 1);
		ret = ctp->f_send_msg(ctp, data_array[0].fragmentation);
		kmem_free(data_array, sizeof(cluster_target_tran_data_t) * fragment_cnt);
	}

	ctp_tx_rele(ctp);
	cluster_target_session_rele(cts, "sel_cts");
}

static void cluster_san_rx_clusterevt_handle(cs_rx_data_t *cs_data)
{
	cluster_evt_header_t *evt_header = cs_data->ex_head;

	ASSERT(cs_data->ex_len == sizeof(cluster_evt_header_t));
	switch (evt_header->msg_type) {
		case CLUSTER_EVT_SYNC_CMD:
			cluster_san_rx_sync_cmd_handle(cs_data);
			break;
		case CLUSTER_EVT_SYNC_CMD_RET:
			cluster_san_rx_sync_cmd_return(cs_data);
			break;
		case CLUSTER_EVT_SYNC_MSG_RET:
			cshi_sync_tx_msg_ret_rx(cs_data);
			break;
		case CLUSTER_EVT_UPDATA_REMOTE_SPA_CONFIG:
			cluster_update_remote_spa_config(cs_data);
			break;
		case CLUSTER_EVT_CLEAR_REMOTE_SPA_CONFIG:
			cluster_update_remote_spa_config(cs_data);
			break;
		case CLUSTER_EVT_CHANGE_POOL_OWNER:
			cluster_change_pool_owner_handle(cs_data);
			break;
		case CLUSTER_EVT_SEL_FAILOVER_HOST:
			cluster_label_failover_host(cs_data, 1);
			break;
		case CLUSTER_EVT_CLR_FAILOVER_HOST:
			cluster_label_failover_host(cs_data, 0);
			break;
		case CLUSTER_EVT_RX_IMPI_IPADDR:
			cluster_rx_ipmi_ip(cs_data);
			break;
		default:
			cmn_err(CE_WARN, "%s: unknown evt:0x%x",
				__func__, evt_header->msg_type);
			csh_rx_data_free(cs_data, B_TRUE);
			break;
	}
}

static void cluster_san_host_rx_handle(
	cs_rx_data_t *cs_data)
{
	/* cluster_san_hostinfo_t *cshi = cs_data->cs_private; */
	uint8_t msg_type = cs_data->msg_type;

	if (cs_data->need_reply != 0) {
		csh_send_reply(cs_data);
	}
	switch (msg_type) {
	case CLUSTER_SAN_MSGTYPE_CLUSTER:
		cluster_san_rx_clusterevt_handle(cs_data);
		break;
	case CLUSTER_SAN_MSGTYPE_HB:
	case CLUSTER_SAN_MSGTYPE_NOP:
		csh_rx_data_free(cs_data, B_TRUE);
		break;
	default:
		/* rx hook */
		csh_rx_handle_ext(cs_data);
		break;
	}

}

static void
cluster_san_host_rxworker_handle(void *arg)
{
	cts_rx_worker_t	*w = (cts_rx_worker_t *)arg;
	cluster_san_hostinfo_t *cshi = w->worker_private;
	cts_worker_para_t *para;
	/* cts_fragment_data_t *fragment; */
	/* cts_fragments_t *fragments; */
	cs_rx_data_t *cs_data;
	cluster_target_msg_header_t *ct_head;
	uint64_t total_len;
	uint64_t data_index;
	uint8_t msg_type;
	uint8_t need_reply;

	mutex_enter(&w->worker_mtx);
	w->worker_flags |= CLUSTER_TARGET_TH_STATE_ACTIVE;
	atomic_inc_32(&cshi->host_rx_worker_n);
	while ((w->worker_flags & CLUSTER_TARGET_TH_STATE_STOP) == 0) {
		mutex_exit(&w->worker_mtx);
		while (1) {
			para = list_remove_head(w->worker_list_r);
			if (para != NULL) {
				atomic_dec_32(&w->worker_ntasks);
				ct_head = (cluster_target_msg_header_t *)para->fragment->ct_head;
				total_len = ct_head->total_len;
				data_index = ct_head->index;
				msg_type = ct_head->msg_type;
				need_reply = ct_head->need_reply;
				cs_data = cluster_san_host_rxfragment_handle(
					w, para->fragment, data_index, total_len, msg_type,
					need_reply);
				if (cs_data != NULL) {
					cluster_san_host_rx_handle(cs_data);
				}
				kmem_free(para, sizeof(cts_worker_para_t));
			} else {
				break;
			}
		}
		mutex_enter(&w->worker_mtx);
		if (w->worker_ntasks == 0) {
			cv_timedwait(&w->worker_cv, &w->worker_mtx, ddi_get_lbolt() + msecs_to_jiffies(60000));
		} else {
			list_t *temp_list;
			temp_list = w->worker_list_r;
			w->worker_list_r = w->worker_list_w;
			w->worker_list_w = temp_list;
		}
	}
	mutex_exit(&w->worker_mtx);

	w->worker_flags = 0;
	atomic_dec_32(&cshi->host_rx_worker_n);
}

static void cluster_san_host_rxworker_init(cluster_san_hostinfo_t *cshi)
{
	char *tq_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	int i;

	cshi->host_rx_worker_n = 0;
	snprintf(tq_name, MAXNAMELEN, "host_rx_worker_tq_%s_%d", cshi->hostname,
		cshi->hostid);
	cshi->host_rx_worker_tq = taskq_create(tq_name,
		cluster_san_host_nrxworker, minclsyspri,
		cluster_san_host_nrxworker, cluster_san_host_nrxworker,
		TASKQ_PREPOPULATE);
	cshi->host_rx_worker = (cts_rx_worker_t *)kmem_zalloc(
		sizeof (cts_rx_worker_t) * cluster_san_host_nrxworker,
		KM_SLEEP);
	for (i = 0; i < cluster_san_host_nrxworker; i++) {
		cts_rx_worker_t *w = &cshi->host_rx_worker[i];
		mutex_init(&w->fragment_lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&w->worker_mtx, NULL, MUTEX_DRIVER, NULL);
		cv_init(&w->worker_cv, NULL, CV_DRIVER, NULL);
		w->worker_flags = 0;
		avl_create(&w->fragment_avl, cts_rxworker_avl_compare,
			sizeof(cts_fragments_t), offsetof(cts_fragments_t, avl_node));
		list_create(&w->fragment_list,
			sizeof(cts_fragments_t), offsetof(cts_fragments_t, list_node));
		list_create(&w->worker_list1,
			sizeof(cts_worker_para_t),
		    offsetof(cts_worker_para_t, node));
		list_create(&w->worker_list2,
			sizeof(cts_worker_para_t),
		    offsetof(cts_worker_para_t, node));
		w->worker_list_r = &w->worker_list1;
		w->worker_list_w = &w->worker_list2;
		w->worker_private = cshi;
		w->worker_index = i;
		(void) taskq_dispatch(cshi->host_rx_worker_tq, 
		    cluster_san_host_rxworker_handle,
		    w, TQ_SLEEP);
	}
	kmem_free(tq_name, MAXNAMELEN);
	while (cshi->host_rx_worker_n != cluster_san_host_nrxworker) {
		delay(drv_usectohz(10000));
	}
}

static void cluster_san_host_rxworker_list_clear(list_t *worker_list)
{
	cts_worker_para_t *para;

	while ((para = list_remove_head(worker_list)) != NULL) {
		cts_fragment_free(para->fragment);
		kmem_free(para, sizeof(cts_worker_para_t));
	}
}

static void cluster_san_host_rxworker_fini(cluster_san_hostinfo_t *cshi)
{
	int i;
	cts_rx_worker_t *w;
	/* cts_worker_para_t *para; */
	cts_fragments_t *ctsfs;
	void *cookie = NULL;

	for (i = 0; i < cluster_san_host_nrxworker; i++) {
		w = &cshi->host_rx_worker[i];
		mutex_enter(&w->worker_mtx);
		w->worker_flags |= CLUSTER_TARGET_TH_STATE_STOP;
		cv_signal(&w->worker_cv);
		mutex_exit(&w->worker_mtx);
	}

	while (cshi->host_rx_worker_n != 0) {
		delay(drv_usectohz(10000));
	}
	taskq_destroy(cshi->host_rx_worker_tq);

	for (i = 0; i < cluster_san_host_nrxworker; i++) {
		w = &cshi->host_rx_worker[i];
		cluster_san_host_rxworker_list_clear(&w->worker_list1);
		cluster_san_host_rxworker_list_clear(&w->worker_list2);
		while ((ctsfs = avl_destroy_nodes(&w->fragment_avl, &cookie)) != NULL) {
			list_remove(&w->fragment_list, ctsfs);
			cts_fragments_clear_list(ctsfs);
			list_destroy(&ctsfs->data_list);
			csh_rx_data_free(ctsfs->cs_data, B_FALSE);
			kmem_free(ctsfs, sizeof(cts_fragments_t));
		}
		mutex_destroy(&w->fragment_lock);
		mutex_destroy(&w->worker_mtx);
		cv_destroy(&w->worker_cv);
		avl_destroy(&w->fragment_avl);
		list_destroy(&w->fragment_list);
		list_destroy(&w->worker_list1);
		list_destroy(&w->worker_list2);
	}

	kmem_free(cshi->host_rx_worker,
		sizeof (cts_rx_worker_t) * cluster_san_host_nrxworker);
	cshi->host_rx_worker = NULL;
}

static int csh_fragment_expired_handle(void)
{
	int i;
	int cnt = 0;
	cts_rx_worker_t *w;
	cts_fragments_t *ctsfs;
	cts_fragments_t *ctsfs_next;
	list_t clean_list;
	int64_t cur_lbolt = ddi_get_lbolt64();
	int64_t expired_time = drv_usectohz(cts_fragment_expired_time);
	cluster_san_hostinfo_t *cshi;

	list_create(&clean_list,
		sizeof(cts_fragments_t), offsetof(cts_fragments_t, list_node));

	rw_enter(&clustersan_rwlock, RW_READER);
	cshi = list_head(&clustersan->cs_hostlist);
	while (cshi != NULL) {
		for (i = 0; i < cluster_san_host_nrxworker; i++) {
			w = &cshi->host_rx_worker[i];
			if (w == NULL) {
				continue;
			}
			mutex_enter(&w->fragment_lock);
			ctsfs = list_head(&w->fragment_list);
			while (ctsfs != NULL) {
				if ((cur_lbolt - ctsfs->active_time) < expired_time) {
					break;
				}
				ctsfs_next = list_next(&w->fragment_list, ctsfs);
				list_remove(&w->fragment_list, ctsfs);
				avl_remove(&w->fragment_avl, ctsfs);
				list_insert_tail(&clean_list, ctsfs);
				cnt++;
				ctsfs = ctsfs_next;
			}
			mutex_exit(&w->fragment_lock);
		}
		cshi = list_next(&clustersan->cs_hostlist, cshi);
	}
	rw_exit(&clustersan_rwlock);

	while ((ctsfs = list_remove_head(&clean_list)) != NULL) {
		csh_rx_data_free(ctsfs->cs_data, B_FALSE);
		cts_fragments_free(ctsfs);
	}
	list_destroy(&clean_list);

	return (cnt);
}

static void csh_asyn_tx_tasks_clean(cluster_san_hostinfo_t *cshi);

static int csh_all_session_down(cluster_san_hostinfo_t *cshi)
{
	cluster_target_session_t *cts;
	cts_list_pri_t *cts_list;
	int ret = 1;

	cts_list = list_head(&cshi->sesslist);
	while (cts_list != NULL) {
		cts = list_head(&cts_list->sess_list);
		while (cts != NULL) {
			if (cts->sess_linkstate == CTS_LINK_UP) {
				ret = 0;
				break;
			}
			cts = list_next(&cts_list->sess_list, cts);
		}
		cts_list = list_next(&cshi->sesslist, cts_list);
	}
	return (ret);
}

void cts_link_down_to_up_handle(void *arg)
{
	cluster_target_session_t *cur_sess = NULL;
	cluster_target_session_t *cts = arg;
	cluster_san_hostinfo_t *cshi = cts->sess_host_private;

	cmn_err(CE_WARN, "cluster san: sess %d up", cts->sess_id);
	/* link evt hook */
	cts_link_evt_handle_ext(cts, LINK_EVT_DOWN_TO_UP);
	mutex_enter(&cshi->lock);
	if (cshi->link_state == CTS_LINK_DOWN) {
		cshi->link_state = CTS_LINK_UP;
		mutex_exit(&cshi->lock);
		csh_link_evt_handle_ext(cshi, LINK_EVT_DOWN_TO_UP);
	} else {
		cur_sess = cshi->cur_sess;
		if (cur_sess != NULL) {
			if (cur_sess->sess_pri > cts->sess_pri) {
				if (cluster_target_session_hold(cts, "host_send") == 0) {
					cshi->cur_sess = cts;
				} else {
					cur_sess = NULL;
				}
			} else {
				cur_sess = NULL;
			}
		}
		mutex_exit(&cshi->lock);
	}
	if (cur_sess != NULL) {
		cluster_target_session_rele(cur_sess, "host_send");
	}
	cluster_target_session_rele(cts, "down2up evt");
}

void cts_link_up_to_down_handle(void *arg)
{
	cluster_target_session_t *rel_sess = NULL;
	cluster_target_session_t *cts = arg;
	cluster_san_hostinfo_t *cshi = cts->sess_host_private;
	int cshi_lock_owned = mutex_owned(&cshi->lock);

	cmn_err(CE_WARN, "cluster san: sess %d timeout", cts->sess_id);
	cts_link_evt_handle_ext(cts, LINK_EVT_UP_TO_DOWN);
	if (cshi_lock_owned == 0) {
		mutex_enter(&cshi->lock);
	}
	if (cshi->cur_sess == cts) {
		rel_sess = cts;
		cshi->cur_sess = NULL;
	}
	if ((cshi->link_state == CTS_LINK_UP) &&
		(csh_all_session_down(cshi) != 0)) {
		cshi->link_state = CTS_LINK_DOWN;
		if (cshi_lock_owned == 0) {
			mutex_exit(&cshi->lock);
		}
		/* csh_asyn_tx_tasks_clean(cshi); */
		csh_link_evt_handle_ext(cshi, LINK_EVT_UP_TO_DOWN);
	} else {
		if (cshi_lock_owned == 0) {
			mutex_exit(&cshi->lock);
		}
	}
	if (rel_sess != NULL) {
		cluster_target_session_rele(rel_sess, "host_send");
	}
	cluster_target_session_rele(cts, "up2down evt");
}

static int cts_hb_check_timeout(cluster_target_session_t *cts)
{
	/* cluster_san_hostinfo_t *cshi = cts->sess_host_private; */
	uint32_t timeout_cnt;
	int is_timeout = 0;

	timeout_cnt = atomic_inc_32_nv(&cts->sess_hb_timeout_cnt);
	if (timeout_cnt > CLUSTER_TARGET_SESS_HB_TIMEOUT_MAX) {
		if (cts->sess_linkstate == CTS_LINK_UP) {
			is_timeout = 1;
			if (cluster_target_session_hold(cts, "up2down evt") == 0) {
				cts->sess_linkstate = CTS_LINK_DOWN;
				taskq_dispatch(clustersan->cs_async_taskq,
					cts_link_up_to_down_handle, (void *)cts, TQ_SLEEP);
			}
		}
		atomic_swap_32(&cts->sess_hb_timeout_cnt, 0);
	}
	return (is_timeout);
}

static void cts_hb_thread(void *arg)
{
	cluster_target_session_t *cts = arg;
	uint64_t cur_time_fragment_expired;
	uint64_t last_time_fragment_expired;
	cur_time_fragment_expired = last_time_fragment_expired = ddi_get_time();

	mutex_enter(&cts->sess_lock);
	cts->sess_hb_state |= CLUSTER_TARGET_TH_STATE_ACTIVE;
	while ((cts->sess_hb_state & CLUSTER_TARGET_TH_STATE_STOP) == 0) {
		mutex_exit(&cts->sess_lock);
#if 0
		cluster_target_session_send(cts, NULL, 0, NULL, 0, CLUSTER_SAN_MSGTYPE_HB,
			1, B_FALSE, 0);
#endif
		cts_send_direct_impl(cts, NULL, 0, NULL, 0, CLUSTER_SAN_MSGTYPE_HB);
		cts_hb_check_timeout(cts);

		cur_time_fragment_expired = ddi_get_time();
		if ((cur_time_fragment_expired - last_time_fragment_expired)
			> cts_expired_handle_time) {
			last_time_fragment_expired = cur_time_fragment_expired;
			cts_fragment_expired_handle(cts);
		}
		mutex_enter(&cts->sess_lock);
		cv_timedwait(&cts->sess_cv, &cts->sess_lock,
			ddi_get_lbolt() + drv_usectohz(CLUSTER_TARGET_SESS_HB_TIMEGAP * 1000 * 600));
	}
	mutex_exit(&cts->sess_lock);
}

static void cts_hb_init(cluster_target_session_t *cts)
{
	char *tq_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	snprintf(tq_name, MAXNAMELEN, "sess_hb_tq_%d", cts->sess_id);
	cts->sess_hb_tq = taskq_create(tq_name,
		1, minclsyspri, 1, 1, TASKQ_PREPOPULATE);
	kmem_free(tq_name, MAXNAMELEN);
	cts->sess_hb_state = 0;
	taskq_dispatch(cts->sess_hb_tq, cts_hb_thread, (void *)cts, TQ_SLEEP);
}

static void cts_hb_fini(cluster_target_session_t *cts)
{
	mutex_enter(&cts->sess_lock);
	cts->sess_hb_state |= CLUSTER_TARGET_TH_STATE_STOP;
	cv_signal(&cts->sess_cv);
	mutex_exit(&cts->sess_lock);
	taskq_destroy(cts->sess_hb_tq);
}

static int cts_tran_start(cluster_target_session_t *cts,
	cluster_target_tran_node_t *tran_node)
{
	cluster_target_port_t *ctp = cts->sess_port_private;
	int ret;

	if (ctp_tx_hold(ctp) != 0) {
		ctp->f_tran_free(tran_node->fragmentation);
		return (-1);
	}

	ret = ctp->f_session_tran_start(cts, tran_node->fragmentation);

	ctp_tx_rele(ctp);

	return (ret);
}

static void cts_tran_worker_thread(void *arg)
{
	cluster_target_tran_worker_t *tran_work = (cluster_target_tran_worker_t *)arg;
	cluster_target_session_t *cts = tran_work->tran_target_private;
	cluster_target_tran_node_t *tran_node;
	int ret;

	atomic_inc_32(&cts->sess_tran_running_n);

	mutex_enter(&tran_work->mtx);
	tran_work->state |= CLUSTER_TARGET_TH_STATE_ACTIVE;
	while ((tran_work->state & CLUSTER_TARGET_TH_STATE_STOP) == 0) {
		mutex_exit(&tran_work->mtx);

		while (1) {
			mutex_enter(&tran_work->lock_pri);
			tran_node = list_remove_head(tran_work->queue_pri);
			mutex_exit(&tran_work->lock_pri);

			if (tran_node == NULL) {
				tran_node = list_remove_head(tran_work->queue_r);
			}

			if (tran_node != NULL) {
				atomic_dec_32(&tran_work->node_numbers);
 				ret = cts_tran_start(cts, tran_node);
				if (tran_node->wait != 0) {
					mutex_enter(tran_node->mtx);
					tran_node->wait = 0;
					tran_node->ret = ret;
					cv_signal(tran_node->cv);
					mutex_exit(tran_node->mtx);
				} else {
					kmem_free(tran_node, sizeof(cluster_target_tran_node_t));
				}
			} else {
				break;
			}
		}

		mutex_enter(&tran_work->mtx);
		if (tran_work->node_numbers == 0) {
			/* wait for exit or tran task come */
			cv_timedwait(&tran_work->cv, &tran_work->mtx, ddi_get_lbolt() + msecs_to_jiffies(60000));
		} else {
			/* switch queue */
			list_t *queue_t;
			queue_t = tran_work->queue_r;
			tran_work->queue_r = tran_work->queue_w;
			tran_work->queue_w = queue_t;
		}
	}
	mutex_exit(&tran_work->mtx);

	atomic_dec_32(&cts->sess_tran_running_n);

	thread_exit();
}

static void cts_tran_worker_init(cluster_target_session_t *cts)
{
	int i;

	if (cluster_target_session_ntranwork == 0) {
		cts->sess_tran_worker_n = num_online_cpus();
	} else {
		cts->sess_tran_worker_n = cluster_target_session_ntranwork;
	}
	cts->sess_tran_worker = (cluster_target_tran_worker_t *)kmem_zalloc(
		sizeof(cluster_target_tran_worker_t) * cts->sess_tran_worker_n, KM_SLEEP);
	for (i = 0; i < cts->sess_tran_worker_n; i++) {
		cluster_target_tran_worker_t *tran_work = &cts->sess_tran_worker[i];
		mutex_init(&tran_work->mtx, NULL, MUTEX_DRIVER, NULL);
		cv_init(&tran_work->cv, NULL, CV_DRIVER, NULL);
		list_create(&tran_work->queue1, sizeof(cluster_target_tran_node_t),
			offsetof(cluster_target_tran_node_t, node));
		list_create(&tran_work->queue2, sizeof(cluster_target_tran_node_t),
			offsetof(cluster_target_tran_node_t, node));
		mutex_init(&tran_work->lock_pri, NULL, MUTEX_DRIVER, NULL);
		list_create(&tran_work->queue3, sizeof(cluster_target_tran_node_t),
			offsetof(cluster_target_tran_node_t, node));
		tran_work->queue_r = &tran_work->queue1;
		tran_work->queue_w = &tran_work->queue2;
		tran_work->queue_pri = &tran_work->queue3;
		tran_work->state = 0;
		tran_work->tran_target_private = cts;
		tran_work->th = thread_create(NULL, 0, cts_tran_worker_thread,
			(void*)tran_work, 0, &p0, TS_RUN, minclsyspri);
	}

	while (cts->sess_tran_running_n != cts->sess_tran_worker_n) {
		delay(drv_usectohz(10000));
	}
}

static void cluster_target_tran_queue_destroy (cluster_target_port_t *ctp, list_t *queue);

static void cts_tran_worker_fini(cluster_target_session_t *cts)
{
	cluster_target_port_t *ctp = cts->sess_port_private;
	int i;

	for (i = 0; i < cts->sess_tran_worker_n; i++) {
		cluster_target_tran_worker_t *tran_work = &cts->sess_tran_worker[i];
		mutex_enter(&tran_work->mtx);
		tran_work->state |= CLUSTER_TARGET_TH_STATE_STOP;
		cv_signal(&tran_work->cv);
		mutex_exit(&tran_work->mtx);
	}

	while (cts->sess_tran_running_n != 0) {
		delay(drv_usectohz(10000));
	}

	for (i = 0; i < cts->sess_tran_worker_n; i++) {
		cluster_target_tran_worker_t *tran_work = &cts->sess_tran_worker[i];
		cluster_target_tran_queue_destroy(ctp, tran_work->queue_r);
		cluster_target_tran_queue_destroy(ctp, tran_work->queue_w);
		cluster_target_tran_queue_destroy(ctp, tran_work->queue_pri);
		mutex_destroy(&tran_work->mtx);
		cv_destroy(&tran_work->cv);
		mutex_destroy(&tran_work->lock_pri);
	}

	kmem_free(cts->sess_tran_worker,
		sizeof(cluster_target_tran_worker_t) * cts->sess_tran_worker_n);
	cts->sess_tran_worker= NULL;
}

static int cluster_target_tran_worker_entry(
	cluster_target_tran_worker_t *tran_work,
	cluster_target_tran_data_t *data_array, int cnt,
	int pri, int wait, kcondvar_t *cv, kmutex_t *mtx);

static int cts_tran_entry(cluster_target_session_t *cts,
	cluster_target_tran_data_t *data_array, int cnt,
	int pri, int wait, kcondvar_t *cv, kmutex_t *mtx)
{
	cluster_target_tran_worker_t *tran_work;
	uint64_t tran_index;
	/* int i = 0; */
	int ret = 0;

	if (cnt == 0) {
		return (0);
	}

	tran_index = atomic_inc_64_nv(&cts->sess_tran_work_index);
	tran_work = &cts->sess_tran_worker[tran_index % cts->sess_tran_running_n];

	ret = cluster_target_tran_worker_entry(tran_work, data_array, cnt, pri,
		wait, cv, mtx);

	return (ret);
}

int cts_send_wait(cluster_target_session_t *cts,
	cluster_target_tran_data_t *data_array, int cnt, int pri)
{
	kmutex_t mtx;
	kcondvar_t cv;
	int ret;
	
	mutex_init(&mtx, NULL, MUTEX_DRIVER, NULL);
	cv_init(&cv, NULL, CV_DRIVER, NULL);

	ret = cts_tran_entry(cts, data_array, cnt, pri, 1, &cv, &mtx);

	mutex_destroy(&mtx);
	cv_destroy(&cv);

	return (ret);
}

static void cts_remove(cluster_target_session_t *cts)
{
	cluster_san_hostinfo_t *cshi;
	cluster_target_port_t *ctp;
	int ret;

	ASSERT(RW_WRITE_HELD(&clustersan_rwlock));

	cts->sess_flags |= CLUSTER_TARGET_SESS_FLAG_UINIT;
	cshi = cts->sess_host_private;
	if (cshi != NULL) {
		mutex_enter(&cshi->lock);
		if ((ret = list_link_active(&cts->host_node)) != 0) {
			list_remove(&(cts->host_list->sess_list), cts);
			cts->host_list = NULL;
		}
		if (cshi->cur_sess == cts) {
			cshi->cur_sess = NULL;
			cluster_target_session_rele(cts, "host_send");
		}
		mutex_exit(&cshi->lock);
		if (ret != 0) {
			cmn_err(CE_NOTE, "cluster san remove sess(%d) from host(%s)",
				cts->sess_id, cshi->hostname);
			cluster_target_session_rele(cts, "insert_host_list");
		}
	}
	ctp = cts->sess_port_private;
	if (ctp != NULL) {
		mutex_enter(&ctp->ctp_lock);
		if ((ret = list_link_active(&cts->target_node)) != 0) {
			list_remove(&ctp->ctp_sesslist, cts);
		}
		mutex_exit(&ctp->ctp_lock);
		if (ret != 0) {
			cmn_err(CE_NOTE, "cluster san remove sess(%d) from cluster target(%s)",
				cts->sess_id, ctp->link_name);
			cluster_target_session_rele(cts, "insert_ctarget_list");
		}
	}
	mutex_enter(&cts->sess_lock);
	if (cts->sess_linkstate == CTS_LINK_UP) {
		cts->sess_linkstate = CTS_LINK_DOWN;
		mutex_exit(&cts->sess_lock);
		/* cluster_target_session_hold(cts, "up2down evt"); */
		atomic_inc_64(&cts->sess_refcount);
		taskq_dispatch(clustersan->cs_async_taskq,
			cts_link_up_to_down_handle, (void *)cts, TQ_SLEEP);
	} else {
		mutex_exit(&cts->sess_lock);
	}

	cluster_target_session_rele(cts, "cts_init");
}

static void cluster_target_session_destroy(cluster_target_session_t *cts)
{
	cluster_target_port_t *ctp = cts->sess_port_private;
	cluster_san_hostinfo_t *cshi = cts->sess_host_private;

	cmn_err(CE_NOTE, "clustersan: destroy session(%d)", cts->sess_id);
	cts->sess_flags |= CLUSTER_TARGET_SESS_FLAG_UINIT;
	if (ctp->target_type == CLUSTER_TARGET_RPC_RDMA) {
		/* cts_rpc_rdma_hb_fini(cts); */
	} else {
		cts_hb_fini(cts);
		cluster_target_session_worker_fini(cts);
		cts_tran_worker_fini(cts);
	}
	ctp->f_session_fini(cts);
	mutex_destroy(&cts->sess_lock);
	cv_destroy(&cts->sess_cv);
	kmem_free(cts, sizeof(cluster_target_session_t));
	cluster_target_port_rele(ctp); /* rele: hold "cts_init" */
	cluster_san_hostinfo_rele(cshi);
}

static void ctp_send_join_in_msg(
	cluster_target_port_t *ctp, void *dst)
{
	uint32_t hostid = clustersan->cs_host.hostid;//zone_get_hostid(NULL);
	char *hostname = clustersan->cs_host.hostname;//hw_utsname.nodename;
	nvlist_t *hostinfo;
	char *buf;
	size_t buflen;
	cluster_target_tran_data_t *data_array = NULL;
	int fragment_cnt = 0;
	cluster_tran_data_origin_t origin_data;
	int ret;

	if (clustersan->cs_state == CLUSTER_SAN_STATE_ENABLE) {
		VERIFY(nvlist_alloc(&hostinfo, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		VERIFY(nvlist_add_string(hostinfo, "clustersanname",
    		clustersan->cs_name) == 0);
		VERIFY(nvlist_add_uint32(hostinfo, "hostid",
			hostid) == 0);
		VERIFY(nvlist_add_string(hostinfo, "hostname",
    		hostname) == 0);
		VERIFY(nvlist_size(hostinfo, &buflen, NV_ENCODE_XDR) == 0);
		buf = kmem_alloc(buflen, KM_SLEEP);
		VERIFY(nvlist_pack(hostinfo, &buf, &buflen, NV_ENCODE_XDR,
		    KM_SLEEP) == 0);
		nvlist_free(hostinfo);

		origin_data.msg_type = CLUSTER_SAN_MSGTYPE_JOIN;
		origin_data.need_reply = B_FALSE;
		origin_data.index = 0;
		origin_data.data = buf;
		origin_data.data_len = buflen;
		origin_data.header = NULL;
		origin_data.header_len = 0;
		ret = ctp->f_tran_fragment(ctp->target_private, dst, &origin_data,
			&data_array, &fragment_cnt);
		if (ret == 0) {
			ASSERT(fragment_cnt == 1);
			ctp->f_send_msg(ctp, data_array[0].fragmentation);
			kmem_free(data_array, sizeof(cluster_target_tran_data_t) * fragment_cnt);
		}

		kmem_free(buf, buflen);
	}
}

cluster_target_session_t *cluster_target_session_add(
	cluster_target_port_t *ctp, char *hostname, uint32_t hostid,
	void *phy_head, boolean_t *new_cts)
{
	cluster_san_hostinfo_t *cshi;
	cluster_target_session_t *cts = NULL;
	cts_list_pri_t *cts_list;

	if (clustersan->cs_state != CLUSTER_SAN_STATE_ENABLE) {
		goto exit;
	}
	if (hostid == clustersan->cs_host.hostid) {
		goto exit;
	}
	cshi = list_head(&clustersan->cs_hostlist);
	while (cshi != NULL) {
		if (hostid == cshi->hostid) {
			if (strncmp(hostname, cshi->hostname, MAXNAMELEN) == 0) {
				break;
			} else {
				cmn_err(CE_WARN, "cluster san hostid must different"
					"(<%s,%d> <%s,%d>)", cshi->hostname, cshi->hostid,
					hostname, hostid);
				goto exit;
			}
		}
		cshi = list_next(&clustersan->cs_hostlist, cshi);
	}
	if (cshi == NULL) {
		char *hash_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		cshi = kmem_zalloc(sizeof(cluster_san_hostinfo_t), KM_SLEEP);
		cshi->hostid = hostid;
		cshi->hostname = kmem_zalloc(strlen(hostname) + 1, KM_SLEEP);
		strcpy(cshi->hostname, hostname);
		mutex_init(&cshi->lock, NULL, MUTEX_DRIVER, NULL);
		list_create(&cshi->sesslist, sizeof(cts_list_pri_t),
			offsetof(cts_list_pri_t, node));
		cshi->link_state = CTS_LINK_DOWN;
		snprintf(hash_name, MAXNAMELEN, "reply_hash_host_%s_%d",
			cshi->hostname, cshi->hostid);
		cshi->host_reply_hash = mod_hash_create_ptrhash(hash_name,
	    	CTS_REPLY_HASH_SIZE, mod_hash_null_valdtor, 0);
		kmem_free(hash_name, MAXNAMELEN);
		cluster_san_host_rxworker_init(cshi);
		csh_asyn_tx_init(cshi);
		cshi_sync_tx_msg_init(cshi);
		cluster_san_hostinfo_hold(cshi);
		clustersan->cs_hostcnt++;
		list_insert_tail(&clustersan->cs_hostlist, cshi);
		cmn_err(CE_NOTE, "cluster san join in new host(%s,%d)",
			hostname, hostid);
	}
	cts = NULL;
	cts_list = list_head(&cshi->sesslist);
	while (cts_list != NULL) {
		cts = list_head(&cts_list->sess_list);
		while (cts != NULL) {
			if ((cts->sess_port_private == (void *)ctp) &&
				(ctp->f_cts_compare(cts, phy_head) == 0)) {
				break;
			}
			cts = list_next(&cts_list->sess_list, cts);
		}
		if (cts != NULL) {
			break;
		}
		cts_list = list_next(&cshi->sesslist, cts_list);
	}
	if (cts == NULL) {
		cts = kmem_zalloc(sizeof(cluster_target_session_t), KM_SLEEP);
		atomic_inc_64(&cts->sess_refcount); /* hold "cts_init" */
		mutex_init(&cts->sess_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&cts->sess_cv, NULL, CV_DRIVER, NULL);
		cts->sess_linkstate = CTS_LINK_DOWN;
		atomic_inc_64(&ctp->ref_count); /* hold "cts_init" */
		cts->sess_port_private = (void *)ctp;
		cts->sess_pri = ctp->pri;

		ctp->f_session_init(cts, phy_head);

		if ((ctp->protocol & TARGET_PROTOCOL_CLUSTER) != 0) {
			cts->sess_flags |= CLUSTER_TARGET_SESS_FLAG_SAN;
		}
		if ((ctp->protocol & TARGET_PROTOCOL_MIRROR) != 0) {
			cts->sess_flags |= CLUSTER_TARGET_SESS_FLAG_MIRROR;
		}
		cluster_san_hostinfo_hold(cshi);
		cts->sess_host_private = cshi;
		cts->sess_id = atomic_inc_32_nv(&cluster_target_session_count);
		if (ctp->target_type == CLUSTER_TARGET_RPC_RDMA) {
			/* cts_rpc_rdma_hb_init(cts); */
		} else {
			cts_tran_worker_init(cts);
			cluster_target_session_worker_init(cts);
			cts_hb_init(cts);
		}
		cluster_target_session_hold(cts, "insert_host_list");
		mutex_enter(&cshi->lock);
		cts_list_insert(&cshi->sesslist, cts);
		mutex_exit(&cshi->lock);
		cluster_target_session_hold(cts, "insert_ctarget_list");
		mutex_enter(&ctp->ctp_lock);
		list_insert_tail(&ctp->ctp_sesslist, cts);
		mutex_exit(&ctp->ctp_lock);
		if (new_cts != NULL) {
			*new_cts = B_TRUE;
		}
		cmn_err(CE_NOTE, "cluster san create new session:%d", cts->sess_id);
	} else {
		if ((cts->sess_linkstate == CTS_LINK_DOWN) &&
			(new_cts != NULL)) {
			*new_cts = B_TRUE;
		}
	}
exit:
	return (cts);
}

static void cluster_target_broadcast_handle(cts_fragment_data_t *fragment)
{
	nvlist_t *hostinfo;
	cluster_target_msg_header_t *ct_head;
	char *hostname;
	char *clustersanname;
	/* cluster_san_hostinfo_t *cshi; */
	cluster_target_port_t *ctp;
	cluster_target_session_t *cts;
	/* cts_list_pri_t *cts_list; */
	uint32_t hostid;
	int ret;
	boolean_t new_cts = B_FALSE;

	ctp = fragment->target_port;
	ct_head = fragment->ct_head;
	ret = nvlist_unpack(fragment->data, fragment->len, &hostinfo, KM_SLEEP);
	if (ret != 0) {
		return;
	}
	VERIFY(0 == nvlist_lookup_string(hostinfo, "clustersanname",
		&clustersanname));
	if (strncmp(clustersanname, clustersan->cs_name, MAXNAMELEN) != 0) {
		goto exit;
	}
	VERIFY(0 == nvlist_lookup_string(hostinfo, "hostname",
		&hostname));
	VERIFY(0 == nvlist_lookup_uint32(hostinfo, "hostid",
		&hostid));
	rw_enter(&clustersan_rwlock, RW_WRITER);
	cts = cluster_target_session_add(ctp, hostname, hostid, fragment->phy_head,
		&new_cts);
	rw_exit(&clustersan_rwlock);
	if (new_cts) {
		ctp_send_join_in_msg(ctp, cts->sess_target_private);
	}
exit:
	nvlist_free(hostinfo);
}

int cluster_target_session_hold(cluster_target_session_t *cts, void *tag)
{
	if (cts == NULL) {
		return (0);
	}
	atomic_inc_64(&cts->sess_refcount);
	if ((cts->sess_flags & CLUSTER_TARGET_SESS_FLAG_UINIT) != 0) {
		atomic_dec_64(&cts->sess_refcount);
		return (-1);
	}
	return (0);
}

void cluster_target_session_rele(cluster_target_session_t *cts, void *tag)
{
	uint64_t ref;
	if (cts == NULL) {
		return;
	}
	ref = atomic_dec_64_nv(&cts->sess_refcount);
	if (ref == 0) {
		ASSERT((cts->sess_flags & CLUSTER_TARGET_SESS_FLAG_UINIT) != 0);
		cluster_target_session_destroy(cts);
	}
}

typedef struct cts_reply_hash_val{
	uint64_t reply_index;
	kmutex_t reply_mtx;
	kcondvar_t reply_cv;
	boolean_t is_replyed;
}cts_reply_hash_val_t;

static cts_reply_hash_val_t *csh_create_and_insert_reply(
	cluster_san_hostinfo_t *cshi,
	uint64_t reply_index)
{
	cts_reply_hash_val_t *reply_val;
	int ret;
	reply_val = kmem_zalloc(sizeof(cts_reply_hash_val_t), KM_SLEEP);
	reply_val->reply_index = reply_index;
	mutex_init(&reply_val->reply_mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&reply_val->reply_cv, NULL, CV_DEFAULT, NULL);
	reply_val->is_replyed = B_FALSE;
	ret = mod_hash_insert(cshi->host_reply_hash,
	    (mod_hash_key_t)(uintptr_t)reply_index, (mod_hash_val_t)reply_val);
	if (ret != 0) {
		mutex_destroy(&reply_val->reply_mtx);
		cv_destroy(&reply_val->reply_cv);
		kmem_free(reply_val, sizeof(cts_reply_hash_val_t));
		reply_val = NULL;
	}
	return (reply_val);
}

static int csh_remove_and_destroy_reply(cluster_san_hostinfo_t *cshi,
	cts_reply_hash_val_t *reply_val)
{
	uint64_t reply_index = reply_val->reply_index;
	cts_reply_hash_val_t *val_temp;
	int ret;
	if (reply_val == NULL) {
		return (-1);
	}
	ret = mod_hash_remove(cshi->host_reply_hash,
	    (mod_hash_key_t)(uintptr_t)reply_index, (mod_hash_val_t *)&val_temp);
	if (ret == 0) {
		ASSERT(val_temp == reply_val);
		mutex_enter(&reply_val->reply_mtx);
		/* for preventing conflict */
		mutex_exit(&reply_val->reply_mtx);

		mutex_destroy(&reply_val->reply_mtx);
		cv_destroy(&reply_val->reply_cv);
		kmem_free(reply_val, sizeof(cts_reply_hash_val_t));
	}

	return (ret);
}

static boolean_t cts_reply_wait(cts_reply_hash_val_t *reply_val)
{
	if ((reply_val == NULL) || reply_val->is_replyed) {
		return (B_TRUE);
	}
	mutex_enter(&reply_val->reply_mtx);
	if (!reply_val->is_replyed) {
		cv_timedwait(&reply_val->reply_cv, &reply_val->reply_mtx,
			ddi_get_lbolt() + drv_usectohz(cts_reply_timeout * 1000));
	}
	mutex_exit(&reply_val->reply_mtx);

	return (reply_val->is_replyed);
}

static void cts_reply_hash_find_cb(mod_hash_key_t key, mod_hash_val_t val)
{
	cts_reply_hash_val_t *reply_val = (cts_reply_hash_val_t *)val;
	ASSERT(reply_val != NULL);
	mutex_enter(&reply_val->reply_mtx);
}

void cts_reply_notify(cluster_san_hostinfo_t *cshi, uint64_t index)
{
	cts_reply_hash_val_t *reply_val;
	int ret;
	if (cshi == NULL) {
		return;
	}
	ret = mod_hash_find_cb(cshi->host_reply_hash,
		(mod_hash_key_t)(uintptr_t)index,
		(mod_hash_val_t *)&reply_val, cts_reply_hash_find_cb);
	if (ret == 0) {
		reply_val->is_replyed = B_TRUE;
		cv_broadcast(&reply_val->reply_cv);
		mutex_exit(&reply_val->reply_mtx);
	}
}

void cs_join_msg_handle(void *arg)
{
	cts_fragment_data_t *fragment = (cts_fragment_data_t *)arg;
	cluster_target_port_t *ctp = fragment->target_port;

	cluster_target_broadcast_handle(fragment);
	cluster_target_port_rele(fragment->target_port);
	ctp->f_fragment_free(fragment);
}

static void cluster_target_port_broadcase_thread(void *arg)
{
	cluster_target_port_t *ctp = (cluster_target_port_t *)arg;

	mutex_enter(&ctp->brosan_mtx);
	ctp->brosan_state |= CLUSTER_TARGET_TH_STATE_ACTIVE;
	while ((ctp->brosan_state & CLUSTER_TARGET_TH_STATE_STOP) == 0) {
		mutex_exit(&ctp->brosan_mtx);
		ctp_send_join_in_msg(ctp, CLUSTER_SAN_BROADCAST_SESS);
		mutex_enter(&ctp->brosan_mtx);
		cv_timedwait(&ctp->brosan_cv, &ctp->brosan_mtx,
			ddi_get_lbolt() + drv_usectohz(60 * 1000 * 1000));
	}

	ctp->brosan_state = 0;
	mutex_exit(&ctp->brosan_mtx);
}

static void cluster_target_tran_worker_thread(void *arg)
{
	cluster_target_tran_worker_t *tran_work = (cluster_target_tran_worker_t *)arg;
	cluster_target_port_t * ctp = tran_work->tran_target_private;
	cluster_target_tran_node_t *tran_node;
	int ret;

	atomic_inc_32(&ctp->tran_running_n);

	mutex_enter(&tran_work->mtx);
	tran_work->state |= CLUSTER_TARGET_TH_STATE_ACTIVE;
	while ((tran_work->state & CLUSTER_TARGET_TH_STATE_STOP) == 0) {
		mutex_exit(&tran_work->mtx);

		while (1) {
			mutex_enter(&tran_work->lock_pri);
			tran_node = list_remove_head(tran_work->queue_pri);
			mutex_exit(&tran_work->lock_pri);

			if (tran_node == NULL) {
				tran_node = list_remove_head(tran_work->queue_r);
			}

			if (tran_node != NULL) {
				atomic_dec_32(&tran_work->node_numbers);
				ret = ctp->f_send_msg(ctp, tran_node->fragmentation);
				if (tran_node->wait != 0) {
					mutex_enter(tran_node->mtx);
					tran_node->wait = 0;
					tran_node->ret = ret;
					cv_signal(tran_node->cv);
					mutex_exit(tran_node->mtx);
				} else {
					kmem_free(tran_node, sizeof(cluster_target_tran_node_t));
				}
			} else {
				break;
			}
		}

		mutex_enter(&tran_work->mtx);
		if (tran_work->node_numbers == 0) {
			/* wait for exit or tran task come */
			cv_timedwait(&tran_work->cv, &tran_work->mtx, ddi_get_lbolt() + msecs_to_jiffies(60000));
		} else {
			/* switch queue */
			list_t *queue_t;
			queue_t = tran_work->queue_r;
			tran_work->queue_r = tran_work->queue_w;
			tran_work->queue_w = queue_t;
		}
	}
	mutex_exit(&tran_work->mtx);

	atomic_dec_32(&ctp->tran_running_n);

	thread_exit();
}

static void cluster_target_tran_worker_init(cluster_target_port_t *ctp)
{
	int i;

	if (ctp->tran_worker_n == 0) {
		ctp->tran_worker_n = num_online_cpus();
	}
	ctp->tran_worker = (cluster_target_tran_worker_t *)kmem_zalloc(
		sizeof(cluster_target_tran_worker_t) * ctp->tran_worker_n, KM_SLEEP);
	for (i = 0; i < ctp->tran_worker_n; i++) {
		cluster_target_tran_worker_t *tran_work = &ctp->tran_worker[i];
		mutex_init(&tran_work->mtx, NULL, MUTEX_DRIVER, NULL);
		cv_init(&tran_work->cv, NULL, CV_DRIVER, NULL);
		list_create(&tran_work->queue1, sizeof(cluster_target_tran_node_t),
			offsetof(cluster_target_tran_node_t, node));
		list_create(&tran_work->queue2, sizeof(cluster_target_tran_node_t),
			offsetof(cluster_target_tran_node_t, node));
		mutex_init(&tran_work->lock_pri, NULL, MUTEX_DRIVER, NULL);
		list_create(&tran_work->queue3, sizeof(cluster_target_tran_node_t),
			offsetof(cluster_target_tran_node_t, node));
		tran_work->queue_r = &tran_work->queue1;
		tran_work->queue_w = &tran_work->queue2;
		tran_work->queue_pri = &tran_work->queue3;
		tran_work->state = 0;
		tran_work->tran_target_private = ctp;
		tran_work->th = thread_create(NULL, 0, cluster_target_tran_worker_thread,
			(void*)tran_work, 0, &p0, TS_RUN, minclsyspri);
	}

	while (ctp->tran_running_n != ctp->tran_worker_n) {
		delay(drv_usectohz(10000));
	}
}

static void cluster_target_tran_queue_destroy (cluster_target_port_t *ctp, list_t *queue)
{
	cluster_target_tran_node_t *tran_node;
	while ((tran_node = list_remove_head(queue)) != NULL) {
		ctp->f_tran_free(tran_node->fragmentation);
		tran_node->fragmentation = NULL;
		if (tran_node->wait != 0) {
			mutex_enter(tran_node->mtx);
			tran_node->wait = 0;
			tran_node->ret = -1;
			cv_signal(tran_node->cv);
			mutex_exit(tran_node->mtx);
		} else {
			kmem_free(tran_node, sizeof(cluster_target_tran_node_t));
		}
	}
	list_destroy(queue);
}

static void cluster_target_tran_worker_thread_exit(cluster_target_port_t *ctp)
{
	int i;

	for (i = 0; i < ctp->tran_worker_n; i++) {
		cluster_target_tran_worker_t *tran_work = &ctp->tran_worker[i];
		mutex_enter(&tran_work->mtx);
		tran_work->state |= CLUSTER_TARGET_TH_STATE_STOP;
		cv_signal(&tran_work->cv);
		mutex_exit(&tran_work->mtx);
	}

	while (ctp->tran_running_n != 0) {
		delay(drv_usectohz(10000));
	}
}

static void cluster_target_tran_worker_fini(cluster_target_port_t *ctp)
{
	int i;
	cluster_target_tran_worker_thread_exit(ctp);
	for (i = 0; i < ctp->tran_worker_n; i++) {
		cluster_target_tran_worker_t *tran_work = &ctp->tran_worker[i];
		cluster_target_tran_queue_destroy(ctp, tran_work->queue_r);
		cluster_target_tran_queue_destroy(ctp, tran_work->queue_w);
		cluster_target_tran_queue_destroy(ctp, tran_work->queue_pri);
		mutex_destroy(&tran_work->mtx);
		cv_destroy(&tran_work->cv);
		mutex_destroy(&tran_work->lock_pri);
	}

	kmem_free(ctp->tran_worker,
		sizeof(cluster_target_tran_worker_t) * ctp->tran_worker_n);
	ctp->tran_worker= NULL;
}

static void cluster_target_tran_init(cluster_target_port_t *ctp)
{
	cluster_target_tran_worker_init(ctp);
}

static void cluster_target_tran_fini(cluster_target_port_t *ctp)
{
	cluster_target_tran_worker_fini(ctp);
}

/* extern cluster_target_port_t *cluster_rdma_target_port; */

cluster_target_port_t *
cluster_target_port_init(char *name, nvlist_t *nvl_conf, uint32_t protocol)
{
	cluster_target_port_t *ctp;
	cluster_target_session_t *cts;
	char *temp_name = NULL;
	/* mac_diag_t	diag; */
	int ret = -1;
	boolean_t is_rdma_rpc = B_FALSE;

	ASSERT(RW_WRITE_HELD(&clustersan_rwlock));
	ctp = list_head(&clustersan->cs_target_list);
	while (ctp != NULL) {
		if (strncmp(name, ctp->link_name, MAXNAMELEN) == 0) {
			break;
		}
		ctp = list_next(&clustersan->cs_target_list,
			ctp);
	}

	if (ctp != NULL) {
		if ((ctp->protocol & protocol) == 0) {
			atomic_inc_64(&ctp->ref_count);
		}
		ctp->protocol |= protocol;
		mutex_enter(&ctp->ctp_lock);
		cts = list_head(&ctp->ctp_sesslist);
		while (cts != NULL) {
			if ((protocol & TARGET_PROTOCOL_CLUSTER) != 0) {
				cts->sess_flags |= CLUSTER_TARGET_SESS_FLAG_SAN;
			}
			if ((protocol & TARGET_PROTOCOL_MIRROR) != 0) {
				cts->sess_flags |= CLUSTER_TARGET_SESS_FLAG_MIRROR;
			}
			cts = list_next(&ctp->ctp_sesslist, cts);
		}
		mutex_exit(&ctp->ctp_lock);
		return (ctp);
	}

	ctp = kmem_zalloc(sizeof(cluster_target_port_t), KM_SLEEP);
	atomic_inc_64(&ctp->ref_count);
	strncpy(ctp->link_name, name, MAXNAMELEN);

	mutex_init(&ctp->ctp_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&ctp->ctp_sesslist, sizeof(cluster_target_session_t),
		offsetof(cluster_target_session_t, target_node));
	if (strncmp(name, "ntb", 3) == 0) {
		ctp->target_type = CLUSTER_TARGET_NTB;
		ctp->pri = CLUSTER_TARGET_PRI_NTB;
		/* ret = cluster_target_ntb_port_init(ctp, name, nvl_conf); */
	} else if (strncmp(name, "rdma_rpc", 8) == 0) {
		ctp->target_type = CLUSTER_TARGET_RPC_RDMA;
		ctp->pri = CLUSTER_TARGET_PRI_RPC_RDMA;
		/* ret = cluster_target_rpc_rdma_port_init(ctp, name, nvl_conf); */
		is_rdma_rpc = B_TRUE;
	} else {
		/* default is ixgbe */
		ctp->target_type = CLUSTER_TARGET_MAC;
		ctp->pri = CLUSTER_TARGET_PRI_MAC;
		ret = cluster_target_mac_port_init(ctp, name, nvl_conf);
	}
	if (ret != 0) {
		cmn_err(CE_WARN, "cluster target port (%s) init failed", name);
		goto failed;
	}

	ctp->tran_worker_n = cluster_target_tran_work_ndefault;
	cluster_target_tran_init(ctp);

	ctp->protocol |= protocol;
	delay(drv_usectohz((clock_t)1000000));/* link unstable in the begining*/
	if (is_rdma_rpc) {
		ctp->ctp_state = CLUSTER_SAN_STATE_ENABLE;
		/* cluster_rdma_target_port = ctp; */
		goto finish;
	}

	ctp->ctp_state = CLUSTER_SAN_STATE_ENABLE;
	if (ctp->target_type != CLUSTER_TARGET_RPC_RDMA) {
		mutex_init(&ctp->brosan_mtx, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&ctp->brosan_cv, NULL, CV_DRIVER, NULL);
		temp_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		snprintf(temp_name, MAXNAMELEN, "cluster_target_brosan_tq_%s", name);
		ctp->brosan_tq = taskq_create(temp_name, 1,
		    minclsyspri, 1, 1, TASKQ_PREPOPULATE);
		kmem_free(temp_name, MAXNAMELEN);
		taskq_dispatch(ctp->brosan_tq, cluster_target_port_broadcase_thread,
			(void *)ctp, TQ_SLEEP);
	}
finish:
	list_insert_tail(&clustersan->cs_target_list, ctp);

	return (ctp);

failed:
	atomic_dec_64(&ctp->ref_count);
	kmem_free(ctp, sizeof(cluster_target_port_t));
	return (NULL);
}

void cluster_target_port_remove(
	cluster_target_port_t *ctp, uint32_t protocol)
{
	cluster_target_port_t *ctp_temp;
	cluster_target_session_t *cts;
	int waits = 0;
	
	ASSERT(RW_WRITE_HELD(&clustersan_rwlock));
	ctp->ctp_state = CLUSTER_SAN_STATE_DISABLE;
	ctp_temp = list_head(&clustersan->cs_target_list);
	while (ctp_temp != NULL) {
		if (ctp_temp == ctp) {
			break;
		}
		ctp_temp = list_next(&clustersan->cs_target_list,
			ctp_temp);
	}
	if (ctp_temp == NULL) {
		return;
	}
	ctp->protocol &= ~protocol;
	cts = list_head(&ctp->ctp_sesslist);
	while (cts != NULL) {
		if (protocol == TARGET_PROTOCOL_CLUSTER) {
			cts->sess_flags &= ~CLUSTER_TARGET_SESS_FLAG_SAN;
		} else if (protocol == TARGET_PROTOCOL_MIRROR) {
			cts->sess_flags &= ~CLUSTER_TARGET_SESS_FLAG_MIRROR;
		}
		cts = list_next(&ctp->ctp_sesslist, cts);
	}
	if (ctp->protocol != 0) {
		goto exit;
	}
	cmn_err(CE_NOTE, "clustersan: remove target port(%s)", ctp->link_name);
	list_remove(&clustersan->cs_target_list, ctp);

	if (ctp->target_type != CLUSTER_TARGET_RPC_RDMA) {
		mutex_enter(&ctp->brosan_mtx);
		ctp->brosan_state |= CLUSTER_TARGET_TH_STATE_STOP;
		cv_signal(&ctp->brosan_cv);
		mutex_exit(&ctp->brosan_mtx);
		taskq_destroy(ctp->brosan_tq);
	}

	rw_exit(&clustersan_rwlock);
	/* wait ctp send over */
	while (ctp->ref_tx_count != 0) {
		waits++;
		cmn_err(CE_NOTE, "cluster san: wait ctp no sender(waits: %d)",
			waits);
		delay(drv_usectohz((clock_t)500000));
	}

	if (ctp->target_type == CLUSTER_TARGET_MAC) {
		cluster_target_mac_port_fini(ctp);
	} else if (ctp->target_type == CLUSTER_TARGET_NTB) {
		/* cluster_target_ntb_port_fini(ctp); */
	} else if (ctp->target_type == CLUSTER_TARGET_RPC_RDMA) {
		/* cluster_target_rpc_rdma_port_fini(ctp); */
	} else {
		cmn_err(CE_WARN, "%s: unkonwn target: %d", __func__, ctp->target_type);
	}
	rw_enter(&clustersan_rwlock, RW_WRITER);
exit:
	if ((ctp->protocol == 0) || (protocol == TARGET_PROTOCOL_CLUSTER)) {
		while ((cts = list_head(&ctp->ctp_sesslist)) != NULL) {
			cts_remove(cts);
		}
	}

	delay(drv_usectohz((clock_t)1000000));
	cluster_target_port_rele(ctp);
}

static void cluster_target_port_destroy(cluster_target_port_t *ctp)
{
	cmn_err(CE_NOTE, "clustersan: destroy target port(%s)", ctp->link_name);
	if (ctp->target_type != CLUSTER_TARGET_RPC_RDMA) {
		mutex_destroy(&ctp->brosan_mtx);
		cv_destroy(&ctp->brosan_cv);
	}

	cluster_target_tran_fini(ctp);
	if (ctp->target_type == CLUSTER_TARGET_MAC) {
		cluster_target_mac_port_destroy(ctp);
	} else if (ctp->target_type == CLUSTER_TARGET_NTB) {
		/* cluster_target_ntb_port_destroy(ctp); */
	} else if (ctp->target_type == CLUSTER_TARGET_RPC_RDMA) {
		/* cluster_rdma_target_port = NULL; */
		/* cluster_target_rpc_rdma_destroy(ctp); */
	} else {
		cmn_err(CE_WARN, "%s: unkonwn target: %d", __func__, ctp->target_type);
	}
	mutex_destroy(&ctp->ctp_lock);
	list_destroy(&ctp->ctp_sesslist);
	kmem_free(ctp, sizeof(cluster_target_port_t));
}

static int cluster_target_tran_worker_entry(
	cluster_target_tran_worker_t *tran_work,
	cluster_target_tran_data_t *data_array, int cnt,
	int pri, int wait, kcondvar_t *cv, kmutex_t *mtx)
{
	int i;
	int ret = 0;
	cluster_target_tran_node_t *tran_node;
	cluster_target_tran_node_t *tran_wait_node;
	list_t tran_list;

	list_create(&tran_list, sizeof(cluster_target_tran_node_t),
		offsetof(cluster_target_tran_node_t, node));

	for (i = 0; i < cnt; i++) {
		tran_node = kmem_zalloc(sizeof(cluster_target_tran_node_t), KM_SLEEP);
		tran_node->fragmentation= data_array[i].fragmentation;
		data_array[i].fragmentation = NULL;
		if ((wait != 0) && ((i + 1) == cnt)) {
			tran_node->wait = wait;
			tran_node->mtx = mtx;
			tran_node->cv = cv;
			tran_wait_node = tran_node;
		}
		list_insert_tail(&tran_list, tran_node);
	}

	if (pri != 0) {
		mutex_enter(&tran_work->lock_pri);
		while ((tran_node = list_remove_head(&tran_list)) != NULL) {
			list_insert_tail(tran_work->queue_pri, tran_node);
		}
		mutex_exit(&tran_work->lock_pri);
	}

	mutex_enter(&tran_work->mtx);
	if (pri == 0) {
		while ((tran_node = list_remove_head(&tran_list)) != NULL) {
			list_insert_tail(tran_work->queue_w, tran_node);
		}
	}
	atomic_add_32(&tran_work->node_numbers, cnt);
	if (tran_work->node_numbers == cnt) {
		cv_signal(&tran_work->cv);
	}
	mutex_exit(&tran_work->mtx);

	list_destroy(&tran_list);
	if (wait != 0) {
		mutex_enter(mtx);
		if (tran_wait_node->wait != 0) {
			cv_wait(cv, mtx);
		}
		mutex_exit(mtx);
		ret = tran_wait_node->ret;
		kmem_free(tran_wait_node, sizeof(cluster_target_tran_node_t));
	}

	return (ret);
}

static int cluster_target_tran_entry(cluster_target_port_t *ctp,
	cluster_target_tran_data_t *data_array, int cnt,
	int pri, int wait, kcondvar_t *cv, kmutex_t *mtx)
{
	cluster_target_tran_worker_t *tran_work;
	uint64_t tran_index;
	int ret = 0;

	if (cnt == 0) {
		return (0);
	}

	tran_index = atomic_inc_64_nv(&ctp->tran_work_index);
	tran_work = &ctp->tran_worker[tran_index % ctp->tran_running_n];

	ret = cluster_target_tran_worker_entry(tran_work, data_array, cnt, pri,
		wait, cv, mtx);

	return (ret);
}

int cluster_target_send_wait(cluster_target_port_t *ctp,
	cluster_target_tran_data_t *data_array, int cnt, int pri)
{
	kmutex_t mtx;
	kcondvar_t cv;
	int ret;
	
	mutex_init(&mtx, NULL, MUTEX_DRIVER, NULL);
	cv_init(&cv, NULL, CV_DRIVER, NULL);

	ret = cluster_target_tran_entry(ctp, data_array, cnt, pri, 1, &cv, &mtx);

	mutex_destroy(&mtx);
	cv_destroy(&cv);

	return (ret);
}

static void cts_send_direct_impl(cluster_target_session_t *cts,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type)
{
	uint64_t tx_index;
	cluster_tran_data_origin_t origin_data;
	cluster_target_port_t *ctp = cts->sess_port_private;
	cluster_san_hostinfo_t *cshi = cts->sess_host_private;
	cluster_target_tran_data_t *data_array = NULL;
	int fragment_cnt = 0;
	int i;
	int ret;

	if ((cts->sess_flags & CLUSTER_TARGET_SESS_FLAG_UINIT) != 0) {
		return;
	}
	if (ctp_tx_hold(ctp) != 0) {
		return;
	}
	tx_index = atomic_inc_64_nv(&cshi->host_tx_index);

	origin_data.msg_type = msg_type;
	origin_data.need_reply = B_FALSE;
	origin_data.index = tx_index;
	origin_data.data = data;
	origin_data.data_len = len;
	origin_data.header = header;
	origin_data.header_len = header_len;

	ret = ctp->f_tran_fragment(ctp->target_private, cts->sess_target_private,
		&origin_data, &data_array, &fragment_cnt);

	if (ret == 0) {
		for (i = 0; i < fragment_cnt; i++) {
			ret = ctp->f_send_msg(ctp, data_array[i].fragmentation);
			if (ret != 0) {
				break;
			}
		}

		for (i = i + 1; i < fragment_cnt; i++) {
			ctp->f_tran_free(data_array[i].fragmentation);
		}
		kmem_free(data_array, sizeof(cluster_target_tran_data_t) * fragment_cnt);
	}

	ctp_tx_rele(ctp);
}

int cluster_target_broadcast_send(cluster_target_port_t *ctp,
	void *data, uint64_t len, void *header, uint64_t header_len, uint8_t msg_type, int pri)
{
	int ret = 0;
	int i;
	uint64_t tx_index;
	cluster_target_tran_data_t *data_array = NULL;
	int fragment_cnt = 0;
	cluster_tran_data_origin_t origin_data;

	tx_index = atomic_inc_64_nv(&cluster_target_broadcast_index);
	origin_data.msg_type = msg_type;
	origin_data.need_reply = B_FALSE;
	origin_data.index = tx_index;
	origin_data.data = data;
	origin_data.data_len = len;
	origin_data.header = header;
	origin_data.header_len = header_len;

	ret = ctp->f_tran_fragment(ctp->target_private, CLUSTER_SAN_BROADCAST_SESS,
		&origin_data, &data_array, &fragment_cnt);

	if (ret == 0) {
		ret = cluster_target_send_wait(ctp, data_array, fragment_cnt, pri);
	}

	if (ret != 0) {
		for (i = 0; i < fragment_cnt; i++) {
			if (data_array[i].fragmentation != NULL) {
				ctp->f_tran_free(data_array[i].fragmentation);
			}
		}
	}
	kmem_free(data_array, sizeof(cluster_target_tran_data_t) * fragment_cnt);

	return (ret);
}

int cluster_target_session_send(cluster_target_session_t *cts,
	cluster_tran_data_origin_t *origin_data, int pri)
{
	int ret = 0;
	cluster_target_port_t *ctp;
	cluster_target_tran_data_t *data_array = NULL;
	int fragment_cnt = 0;
	int i;

	if (cts == NULL) {
		return (-1);
	}
	if ((cts->sess_flags & CLUSTER_TARGET_SESS_FLAG_UINIT) != 0) {
		return (-1);
	}
	ctp = cts->sess_port_private;

	if (ctp->target_type == CLUSTER_TARGET_RPC_RDMA) {
		ret = ctp->f_session_tran_start(cts, origin_data);
		if ((ret == 0) && (origin_data->need_reply != 0)) {
			cts_reply_notify(cts->sess_host_private, origin_data->index);
		}
		return (ret);
	}

	/* fragmentation */
	ret = ctp->f_tran_fragment(ctp->target_private, cts->sess_target_private,
		origin_data, &data_array, &fragment_cnt);

	if (ret == 0) {
		ret = cts_send_wait(cts, data_array, fragment_cnt, pri);
		if (ret != 0) {
			for (i = 0; i < fragment_cnt; i++) {
				if (data_array[i].fragmentation != NULL) {
					ctp->f_tran_free(data_array[i].fragmentation);
				}
			}
		}
		kmem_free(data_array, sizeof(cluster_target_tran_data_t) * fragment_cnt);
	}

	return (ret);
}

void cluster_san_broadcast_send(
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type, int pri)
{
	cluster_san_hostinfo_t *cshi;
	cluster_target_session_t *cts;
	cluster_tran_data_origin_t origin_data;
	uint64_t tx_index;

	origin_data.msg_type = msg_type;
	origin_data.need_reply = B_FALSE;
	origin_data.data = data;
	origin_data.data_len = len;
	origin_data.header = header;
	origin_data.header_len = header_len;
	origin_data.retry_times = 0;

	rw_enter(&clustersan_rwlock, RW_READER);
	cshi = list_head(&clustersan->cs_hostlist);
	while (cshi != NULL) {
		cts = cts_select_from_host(cshi);
		if (cts != NULL) {
			tx_index = atomic_inc_64_nv(&cshi->host_tx_index);
			origin_data.index = tx_index;
			cluster_target_session_send(cts, &origin_data, pri);
			cluster_target_session_rele(cts, "sel_cts");
		}
		cshi = list_next(&clustersan->cs_hostlist, cshi);
	}
	rw_exit(&clustersan_rwlock);
}

int cluster_san_host_send(cluster_san_hostinfo_t *cshi,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type, int pri, boolean_t need_reply, int retry_times)
{
	cluster_target_session_t *cts;
	uint64_t tx_index;
	cts_reply_hash_val_t *reply_val;
	cluster_tran_data_origin_t origin_data;
	boolean_t is_replyed;
	int retry_cnt = 0;
	int ret;

	if (cshi == NULL) {
		return (-1);
	}
	/* retry and reply */
	tx_index = atomic_inc_64_nv(&cshi->host_tx_index);
	if (need_reply) {
		reply_val = csh_create_and_insert_reply(cshi, tx_index);
	}

	origin_data.msg_type = msg_type;
	origin_data.need_reply = need_reply;
	origin_data.index = tx_index;
	origin_data.data = data;
	origin_data.data_len = len;
	origin_data.header = header;
	origin_data.header_len = header_len;
	origin_data.retry_times = retry_times;

SEND_RETRY:
	cts = cts_select_from_host(cshi);

	if (cts == NULL) {
		if (need_reply) {
			csh_remove_and_destroy_reply(cshi, reply_val);
		}
		return (-1);
	}
	ret = cluster_target_session_send(cts, &origin_data, pri);
	cluster_target_session_rele(cts, "sel_cts");

	if (need_reply) {
		if (ret == 0) {
			is_replyed = cts_reply_wait(reply_val);
			if (!is_replyed) {
				if (retry_cnt < retry_times) {
					retry_cnt++;
					goto SEND_RETRY;
				} else {
					ret = -2;
				}
			}
		} else {
			if (retry_cnt < retry_times) {
				retry_cnt++;
				goto SEND_RETRY;
			}
		}
		csh_remove_and_destroy_reply(cshi, reply_val);
	}

	return (ret);
}

#define	CLUSTER_SAN_HOST_ASYN_TX_GAP		1000000 /* us */

static void csh_asyn_tx_msg_hold(csh_asyn_tx_msg_t *asyn_msg)
{
	atomic_inc_64(&asyn_msg->ref_count);
}

static void csh_asyn_tx_msg_rele(csh_asyn_tx_msg_t *asyn_msg)
{
	uint64_t ref_count;

	ref_count = atomic_dec_64_nv(&asyn_msg->ref_count);
	if (ref_count == 0) {
		asyn_msg->clean_cb(asyn_msg->data, asyn_msg->len,
			asyn_msg->header, asyn_msg->header_len, asyn_msg->private);
		kmem_free(asyn_msg, sizeof(csh_asyn_tx_msg_t));
	}
}

static void csh_asyn_tx_task_handle(void *arg)
{
	cluster_san_hostinfo_t *cshi = arg;
	csh_asyn_tx_task_node_t *asyn_tx;
	csh_asyn_tx_task_node_t *asyn_tx_next;
	int64_t curtime;
	int ret;

	mutex_enter(&cshi->host_asyn_tx_mtx);
	cshi->host_asyn_tx_state |= CLUSTER_TARGET_TH_STATE_ACTIVE;
	while ((cshi->host_asyn_tx_state & CLUSTER_TARGET_TH_STATE_STOP) == 0) {
		curtime = ddi_get_lbolt64();
		asyn_tx = list_head(&cshi->host_asyn_tx_tasks);
		while (asyn_tx != NULL) {
			asyn_tx_next = list_next(&cshi->host_asyn_tx_tasks, asyn_tx);
			if ((cshi->link_state != CTS_LINK_UP) ||
				(asyn_tx->is_clean == B_TRUE)) {
				list_remove(&cshi->host_asyn_tx_tasks, asyn_tx);
				if (asyn_tx->msg->compl_cb != NULL) {
					asyn_tx->msg->compl_cb(asyn_tx->msg->private, cshi->hostid, -1);
				}
				csh_asyn_tx_msg_rele(asyn_tx->msg);
				kmem_free(asyn_tx, sizeof(csh_asyn_tx_task_node_t));
				asyn_tx = asyn_tx_next;
				continue;
			}
			if ((curtime - asyn_tx->active_time) >
				drv_usectohz(CLUSTER_SAN_HOST_ASYN_TX_GAP)) {
				asyn_tx->active_time = curtime;
				mutex_exit(&cshi->host_asyn_tx_mtx);
				ret = cluster_san_host_send(cshi, asyn_tx->msg->data,
					asyn_tx->msg->len, asyn_tx->msg->header,
					asyn_tx->msg->header_len, asyn_tx->msg->msg_type, 0, 1, 3);
				mutex_enter(&cshi->host_asyn_tx_mtx);
				if ((ret == 0) || (cshi->link_state == CTS_LINK_DOWN) ||
					(asyn_tx->is_clean == B_TRUE)) {
					list_remove(&cshi->host_asyn_tx_tasks, asyn_tx);
					if (asyn_tx->msg->compl_cb != NULL) {
						if (ret == 0) {
							asyn_tx->msg->compl_cb(asyn_tx->msg->private, cshi->hostid, 0);
						} else {
							asyn_tx->msg->compl_cb(asyn_tx->msg->private, cshi->hostid, -1);
						}
					}
					csh_asyn_tx_msg_rele(asyn_tx->msg);
					kmem_free(asyn_tx, sizeof(csh_asyn_tx_task_node_t));
				}
			}
			asyn_tx = asyn_tx_next;
		}
		if (list_is_empty(&cshi->host_asyn_tx_tasks)) {
			cv_timedwait(&cshi->host_asyn_tx_cv, &cshi->host_asyn_tx_mtx, ddi_get_lbolt() + msecs_to_jiffies(60000));
		} else {
			cv_timedwait(&cshi->host_asyn_tx_cv, &cshi->host_asyn_tx_mtx,
				ddi_get_lbolt() + drv_usectohz(CLUSTER_SAN_HOST_ASYN_TX_GAP));
		}
	}
	while ((asyn_tx = list_remove_head(&cshi->host_asyn_tx_tasks)) != NULL) {
		if (asyn_tx->msg->compl_cb != NULL) {
			asyn_tx->msg->compl_cb(asyn_tx->msg->private, cshi->hostid, -1);
		}
		csh_asyn_tx_msg_rele(asyn_tx->msg);
		kmem_free(asyn_tx, sizeof(csh_asyn_tx_task_node_t));
	}
	mutex_exit(&cshi->host_asyn_tx_mtx);
}

static void csh_asyn_tx_init(cluster_san_hostinfo_t *cshi)
{
	char *tq_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	mutex_init(&cshi->host_asyn_tx_mtx, NULL, MUTEX_DRIVER, NULL);
	cv_init(&cshi->host_asyn_tx_cv, NULL, CV_DRIVER, NULL);
	list_create(&cshi->host_asyn_tx_tasks, sizeof(csh_asyn_tx_task_node_t),
		offsetof(csh_asyn_tx_task_node_t, node));
	snprintf(tq_name, MAXNAMELEN, "host_asyn_tx_tq_%s_%d",
		cshi->hostname, cshi->hostid);
	cshi->host_asyn_tx_tq = taskq_create(tq_name,
		1, minclsyspri, 1, 1, TASKQ_PREPOPULATE);
	kmem_free(tq_name, MAXNAMELEN);
	cshi->host_asyn_tx_state = 0;
	taskq_dispatch(cshi->host_asyn_tx_tq, csh_asyn_tx_task_handle,
		(void *)cshi, TQ_SLEEP);
}

static void csh_asyn_tx_tasks_clean(cluster_san_hostinfo_t *cshi)
{
	csh_asyn_tx_task_node_t *asyn_tx;

	mutex_enter(&cshi->host_asyn_tx_mtx);
	asyn_tx = list_head(&cshi->host_asyn_tx_tasks);
	while (asyn_tx != NULL) {
		asyn_tx->is_clean = B_TRUE;
		asyn_tx = list_next(&cshi->host_asyn_tx_tasks, asyn_tx);
	}
	mutex_exit(&cshi->host_asyn_tx_mtx);
}

static void csh_asyn_tx_fini(cluster_san_hostinfo_t *cshi)
{
	csh_asyn_tx_tasks_clean(cshi);
	mutex_enter(&cshi->host_asyn_tx_mtx);
	cshi->host_asyn_tx_state |= CLUSTER_TARGET_TH_STATE_STOP;
	cv_broadcast(&cshi->host_asyn_tx_cv);
	mutex_exit(&cshi->host_asyn_tx_mtx);
	taskq_destroy(cshi->host_asyn_tx_tq);
	list_destroy(&cshi->host_asyn_tx_tasks);
	mutex_destroy(&cshi->host_asyn_tx_mtx);
	cv_destroy(&cshi->host_asyn_tx_cv);
}

static void csh_asyn_send_impl(cluster_san_hostinfo_t *cshi,
	csh_asyn_tx_msg_t *asyn_msg)
{
	csh_asyn_tx_task_node_t *asyn_tx;

	asyn_tx = kmem_zalloc(sizeof(csh_asyn_tx_task_node_t), KM_SLEEP);
	asyn_tx->is_clean = B_FALSE;
	csh_asyn_tx_msg_hold(asyn_msg);
	asyn_tx->msg = asyn_msg;
	mutex_enter(&cshi->host_asyn_tx_mtx);
	list_insert_head(&cshi->host_asyn_tx_tasks, asyn_tx);
	cv_broadcast(&cshi->host_asyn_tx_cv);
	mutex_exit(&cshi->host_asyn_tx_mtx);
}

void cluster_san_host_asyn_send(cluster_san_hostinfo_t *cshi,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint8_t msg_type, uint32_t type, void *private,
	csh_asyn_tx_compl_cb_func_t compl_cb, csh_asyn_tx_clean_cb_func_t clean_cb,
	csh_asyn_tx_node_comp_func_t comp)
{
	cluster_san_hostinfo_t *cshi_temp;
	csh_asyn_tx_msg_t *asyn_msg;

	asyn_msg = kmem_zalloc(sizeof(csh_asyn_tx_msg_t), KM_SLEEP);
	asyn_msg->data = data;
	asyn_msg->len = len;
	asyn_msg->header = header;
	asyn_msg->header_len = header_len;
	asyn_msg->msg_type = msg_type;
	asyn_msg->asyn_type = type;
	asyn_msg->private = private;
	asyn_msg->compl_cb = compl_cb;
	asyn_msg->clean_cb = clean_cb;
	asyn_msg->comp = comp;
	asyn_msg->ref_count = 0;
	csh_asyn_tx_msg_hold(asyn_msg);

	if ((void *)cshi == CLUSTER_SAN_BROADCAST_SESS) {
		rw_enter(&clustersan_rwlock, RW_READER);
		cshi_temp = list_head(&clustersan->cs_hostlist);
		while (cshi_temp != NULL) {
			csh_asyn_send_impl(cshi_temp, asyn_msg);
			cshi_temp = list_next(&clustersan->cs_hostlist, cshi_temp);
		}
		rw_exit(&clustersan_rwlock);
	} else {
		if (cshi == NULL) {
			goto out;
		}
		csh_asyn_send_impl(cshi, asyn_msg);
	}
out:
	csh_asyn_tx_msg_rele(asyn_msg);
}

static void csh_asyn_send_clean_impl(cluster_san_hostinfo_t *cshi,
	uint32_t type, void *private)
{
	csh_asyn_tx_task_node_t *asyn_tx;
	csh_asyn_tx_task_node_t *asyn_tx_next;

	mutex_enter(&cshi->host_asyn_tx_mtx);
	asyn_tx = list_head(&cshi->host_asyn_tx_tasks);
	while (asyn_tx != NULL) {
		asyn_tx_next = list_next(&cshi->host_asyn_tx_tasks, asyn_tx);
		if ((asyn_tx->is_clean == B_FALSE) &&
			(type == asyn_tx->msg->asyn_type) &&
			(asyn_tx->msg->comp(private, asyn_tx->msg->private) == 0)) {
			asyn_tx->is_clean = B_TRUE;
		}
		asyn_tx = asyn_tx_next;
	}
	mutex_exit(&cshi->host_asyn_tx_mtx);
}

void cluster_san_host_asyn_send_clean(uint32_t type, void *private)
{
	cluster_san_hostinfo_t *cshi;

	rw_enter(&clustersan_rwlock, RW_READER);
	cshi = list_head(&clustersan->cs_hostlist);
	while (cshi != NULL) {
		csh_asyn_send_clean_impl(cshi, type, private);
		cshi = list_next(&clustersan->cs_hostlist, cshi);
	}
	rw_exit(&clustersan_rwlock);
}

static void cshi_sync_tx_msg_init(cluster_san_hostinfo_t *cshi)
{
	mutex_init(&cshi->host_sync_tx_msg_mtx, NULL, MUTEX_DRIVER, NULL);
	list_create(&cshi->host_sync_tx_msgs, sizeof(csh_sync_tx_msg_node_t),
		offsetof(csh_sync_tx_msg_node_t, node));
}

static void cshi_sync_tx_msg_fini(cluster_san_hostinfo_t *cshi)
{
	mutex_destroy(&cshi->host_sync_tx_msg_mtx);
	list_destroy(&cshi->host_sync_tx_msgs);
}

void cshi_sync_tx_msg_thread(void *arg)
{
	csh_sync_tx_msg_node_t *sync_msg = arg;
	cluster_san_hostinfo_t *cshi = sync_msg->host_private;
	int64_t current_time = ddi_get_lbolt64();
	int64_t expired_time = 0;

	if (sync_msg->timeout != 0) {
		expired_time = current_time + drv_usectohz(sync_msg->timeout * 1000000);
	}
	mutex_enter(&sync_msg->mtx);
	while (sync_msg->ret != 0) {
		if (cshi->link_state == CTS_LINK_DOWN) {
			break;
		}
		if (expired_time != 0) {
			current_time = ddi_get_lbolt64();
			if (current_time > expired_time) {
				atomic_swap_32((uint *)sync_msg->taskq_ret, 1);
				break;
			}
		}
		mutex_exit(&sync_msg->mtx);
		cluster_san_host_send(cshi, sync_msg->data,
			sync_msg->len, sync_msg->header, sync_msg->header_len,
			sync_msg->msg_type, 1, 1, 3);
		mutex_enter(&sync_msg->mtx);
		cv_timedwait(&sync_msg->cv, &sync_msg->mtx,
			ddi_get_lbolt() + drv_usectohz(1000 * 1000));
	}
	if (sync_msg->ret == 0) {
		cmn_err(CE_NOTE, "%s: host(%d) handle msg(%x, %"PRIx64") success",
			__func__, cshi->hostid, sync_msg->msg_type, sync_msg->msg_id);
	} else {
		if (sync_msg->responsed != 0) {
			cmn_err(CE_NOTE, "%s: host(%d) handle msg(%x, %"PRIx64") failed(%"PRIx64")",
				__func__,  cshi->hostid, sync_msg->msg_type, sync_msg->msg_id,
				sync_msg->ret);
		} else {
			cmn_err(CE_NOTE, "%s: host(%d) no response for msg(%x, %"PRIx64")"
				", host state(%d)",
				__func__, cshi->hostid, sync_msg->msg_type, sync_msg->msg_id,
				cshi->link_state);
		}
	}
	mutex_exit(&sync_msg->mtx);

	mutex_enter(&cshi->host_sync_tx_msg_mtx);
	list_remove(&cshi->host_sync_tx_msgs, sync_msg);
	mutex_exit(&cshi->host_sync_tx_msg_mtx);
	mutex_destroy(&sync_msg->mtx);
	cv_destroy(&sync_msg->cv);
	kmem_free(sync_msg, sizeof(csh_sync_tx_msg_node_t));

	cluster_san_hostinfo_rele(cshi);
}

int cluster_san_host_sync_send_msg(cluster_san_hostinfo_t *cshi,
	void *data, uint64_t len, void *header, uint64_t header_len,
	uint64_t msg_id, uint8_t msg_type, int timeout)
{
	cluster_san_hostinfo_t *cshi_temp;
	csh_sync_tx_msg_node_t *sync_msg;
	taskq_t *sync_tx_tq;
	list_t sync_msgs;
	int taskq_ret = 0;
	int tq_nthread = 0;
	char *tq_name = NULL;
	int ret = 0;

	if (cshi == NULL) {
		return (-1);
	}
	list_create(&sync_msgs, sizeof(csh_sync_tx_msg_node_t),
		offsetof(csh_sync_tx_msg_node_t, node));
	if ((void *)cshi == CLUSTER_SAN_BROADCAST_SESS) {
		rw_enter(&clustersan_rwlock, RW_READER);
		cshi_temp = list_head(&clustersan->cs_hostlist);
		while (cshi_temp != NULL) {
			cluster_san_hostinfo_hold(cshi_temp);
			tq_nthread++;
			sync_msg = kmem_zalloc(sizeof(csh_sync_tx_msg_node_t), KM_SLEEP);
			sync_msg->msg_id = msg_id;
			sync_msg->msg_type = msg_type;
			sync_msg->host_private = cshi_temp;
			sync_msg->data = data;
			sync_msg->len = len;
			sync_msg->header = header;
			sync_msg->header_len = header_len;
			sync_msg->timeout = timeout;
			sync_msg->taskq_ret = &taskq_ret;
			mutex_init(&sync_msg->mtx, NULL, MUTEX_DRIVER, NULL);
			cv_init(&sync_msg->cv, NULL, CV_DRIVER, NULL);
			sync_msg->ret = (0 - 1);
			sync_msg->responsed = 0;
			list_insert_tail(&sync_msgs, sync_msg);
			cshi_temp = list_next(&clustersan->cs_hostlist, cshi_temp);
		}
		rw_exit(&clustersan_rwlock);
	} else {
		cluster_san_hostinfo_hold(cshi);
		tq_nthread++;
		sync_msg = kmem_zalloc(sizeof(csh_sync_tx_msg_node_t), KM_SLEEP);
		sync_msg->msg_id = msg_id;
		sync_msg->msg_type = msg_type;
		sync_msg->host_private = cshi;
		sync_msg->data = data;
		sync_msg->len = len;
		sync_msg->header = header;
		sync_msg->header_len = header_len;
		sync_msg->timeout = timeout;
		sync_msg->taskq_ret = &taskq_ret;
		mutex_init(&sync_msg->mtx, NULL, MUTEX_DRIVER, NULL);
		cv_init(&sync_msg->cv, NULL, CV_DRIVER, NULL);
		sync_msg->ret = (0 - 1);
		sync_msg->responsed = 0;
		list_insert_tail(&sync_msgs, sync_msg);
	}
	if (tq_nthread == 0) {
		return (0);
	}
	tq_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	snprintf(tq_name, MAXNAMELEN, "host_sync_tx_tq_%x_%"PRIx64"",
		msg_type, msg_id);
	sync_tx_tq = taskq_create(tq_name, tq_nthread, minclsyspri,
		tq_nthread, tq_nthread, TASKQ_PREPOPULATE);
	kmem_free(tq_name, MAXNAMELEN);

	while ((sync_msg = list_remove_head(&sync_msgs)) != NULL) {
		cshi_temp = sync_msg->host_private;
		mutex_enter(&cshi_temp->host_sync_tx_msg_mtx);
		list_insert_tail(&cshi_temp->host_sync_tx_msgs, sync_msg);
		mutex_exit(&cshi_temp->host_sync_tx_msg_mtx);
		taskq_dispatch(sync_tx_tq, cshi_sync_tx_msg_thread,
			sync_msg, TQ_SLEEP);
	}
	taskq_wait(sync_tx_tq);
	taskq_destroy(sync_tx_tq);

	if (taskq_ret != 0) {
		ret = -2;
	}
	return (ret);
	
}

static void cshi_sync_tx_msg_ret_rx(cs_rx_data_t *cs_data)
{
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	csh_sync_tx_msg_node_t *sync_msg;
	csh_sync_tx_msg_ret_t *msg_ret = (csh_sync_tx_msg_ret_t *)cs_data->data;

	mutex_enter(&cshi->host_sync_tx_msg_mtx);
	sync_msg = list_head(&cshi->host_sync_tx_msgs);
	while (sync_msg != NULL) {
		if ((sync_msg->msg_id == msg_ret->msg_id) &&
			(sync_msg->msg_type == msg_ret->msg_type)) {
			mutex_enter(&sync_msg->mtx);
			sync_msg->responsed = 1;
			sync_msg->ret = msg_ret->ret;
			cv_broadcast(&sync_msg->cv);
			mutex_exit(&sync_msg->mtx);
			break;
		}
		sync_msg = list_next(&cshi->host_sync_tx_msgs, sync_msg);
	}
	mutex_exit(&cshi->host_sync_tx_msg_mtx);
	csh_rx_data_free(cs_data, B_TRUE);
}

void cluster_san_host_sync_msg_ret(cluster_san_hostinfo_t *cshi,
	uint64_t msg_id, uint8_t msg_type, uint64_t ret)
{
	csh_sync_tx_msg_ret_t *msg_ret;
	cluster_evt_header_t evt_header;
	uint64_t len = sizeof(csh_sync_tx_msg_ret_t);

	if ((cshi == NULL) || (cshi == CLUSTER_SAN_BROADCAST_SESS)) {
		return;
	}
	msg_ret = kmem_zalloc(sizeof(csh_sync_tx_msg_ret_t), KM_SLEEP);
	msg_ret->msg_id = msg_id;
	msg_ret->msg_type = msg_type;
	msg_ret->ret = ret;

	bzero(&evt_header, sizeof(cluster_evt_header_t));
	evt_header.msg_type = CLUSTER_EVT_SYNC_MSG_RET;
	cluster_san_host_send(cshi, (void *)msg_ret, len,
		&evt_header, sizeof(cluster_evt_header_t),
		CLUSTER_SAN_MSGTYPE_CLUSTER, 1, 1, 3);
	kmem_free(msg_ret, sizeof(csh_sync_tx_msg_ret_t));
}

static void cluster_san_sync_cmd_destroy(cs_sync_cmd_node_t *sync_cmd)
{
	cs_sync_cmd_host_node_t *cmd_host;
	uint32_t refcount;

	refcount = atomic_dec_32_nv(&sync_cmd->refcount);

	if (refcount != 0) {
		return;
	}

	while ((cmd_host = list_remove_head(&sync_cmd->cmd_host_list)) != NULL) {
		kmem_free(cmd_host, sizeof(cs_sync_cmd_host_node_t));
	}
	list_destroy(&sync_cmd->cmd_host_list);
	mutex_destroy(&sync_cmd->lock);
	cv_destroy(&sync_cmd->cv);
	kmem_free(sync_cmd, sizeof(cs_sync_cmd_node_t));
}

static void cs_asyn_tx_sync_cmd_compl(void *private, uint32_t hostid, int ret)
{
	cs_sync_cmd_node_t *sync_cmd = private;
	cs_sync_cmd_host_node_t *cmd_host;

	if (ret != 0) {
		mutex_enter(&sync_cmd->lock);
		cmd_host = list_head(&sync_cmd->cmd_host_list);
		while (cmd_host != NULL) {
			if (cmd_host->host->hostid == hostid) {
				cmd_host->ret = ret;
				sync_cmd->ret_cnt++;
				break;
			}
			cmd_host = list_next(&sync_cmd->cmd_host_list, cmd_host);
		}
		mutex_exit(&sync_cmd->lock);
	}
	return;
}

static void cs_asyn_tx_sync_cmd_clean(void *buf, uint64_t len,
	void *header, uint64_t header_len,void *private)
{
	cs_sync_cmd_node_t *sync_cmd = private;

	kmem_free(buf, len);
	kmem_free(header, header_len);
	cluster_san_sync_cmd_destroy(sync_cmd);
}

static int cs_asyn_tx_sync_cmd_comp(void *arg1, void *arg2)
{
	if (arg1 == arg2) {
		return (0);
	}
	return (-1);
}

nvlist_t *cluster_san_sync_cmd(uint64_t cmd_id, char *cmd_str,
	int timeout, int remote_hostid)
{
	cs_sync_cmd_node_t *sync_cmd;
	cs_sync_cmd_host_node_t *cmd_host;
	cluster_san_hostinfo_t *cshi;
	nvlist_t *nvl_cmd;
	nvlist_t *nvl_result = NULL;
	char hostname[64];
	size_t buflen;
	char *buf;
	cluster_evt_header_t *evt_header;
	int ret;

	cmn_err(CE_IGNORE, "Send cmd(%"PRIx64"): %s", cmd_id, cmd_str);
	sync_cmd = kmem_zalloc(sizeof(cs_sync_cmd_node_t), KM_SLEEP);
	mutex_init(&sync_cmd->lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sync_cmd->cv, NULL, CV_DRIVER, NULL);
	list_create(&sync_cmd->cmd_host_list, sizeof(cs_sync_cmd_host_node_t),
		offsetof(cs_sync_cmd_host_node_t, node));
	sync_cmd->cmd_id = cmd_id;
	sync_cmd->cmd = cmd_str;
	sync_cmd->host_cnt = 0;
	sync_cmd->ret_cnt = 0;
	sync_cmd->refcount = 1;

	rw_enter(&clustersan_rwlock, RW_READER);
	cshi = list_head(&clustersan->cs_hostlist);
	if (remote_hostid == -1) {
		while (cshi != NULL) {
			cmd_host = kmem_zalloc(sizeof(cs_sync_cmd_host_node_t), KM_SLEEP);
			/* hold host ref */
			cluster_san_hostinfo_hold(cshi);
			cmd_host->host = cshi;
			list_insert_tail(&sync_cmd->cmd_host_list, cmd_host);
			sync_cmd->host_cnt++;
			cshi = list_next(&clustersan->cs_hostlist, cshi);
		}
	} else {
		while (cshi != NULL) {
			if (cshi->hostid == remote_hostid) {
				cmd_host = kmem_zalloc(sizeof(cs_sync_cmd_host_node_t), KM_SLEEP);
				cluster_san_hostinfo_hold(cshi);
				cmd_host->host = cshi;
				list_insert_tail(&sync_cmd->cmd_host_list, cmd_host);
				sync_cmd->host_cnt++;
				break;
			} else {
				cshi = list_next(&clustersan->cs_hostlist, cshi);
			}
		}
	}
	rw_exit(&clustersan_rwlock);

	if (sync_cmd->host_cnt == 0) {
		goto out;
	}

	mutex_enter(&clustersan->cs_sync_cmd.sync_cmd_lock);
	list_insert_tail(&clustersan->cs_sync_cmd.sync_cmd_list, sync_cmd);
	mutex_exit(&clustersan->cs_sync_cmd.sync_cmd_lock);

	/* use nvlist */
	VERIFY(nvlist_alloc(&nvl_cmd, NV_UNIQUE_NAME, KM_SLEEP) == 0);
	VERIFY(nvlist_add_uint64(nvl_cmd, "cmd_id", cmd_id) == 0);
	VERIFY(nvlist_add_string(nvl_cmd, "cmd_str", cmd_str) == 0);
	VERIFY(nvlist_size(nvl_cmd, &buflen, NV_ENCODE_XDR) == 0);
	buf = kmem_alloc(buflen, KM_SLEEP);
	VERIFY(nvlist_pack(nvl_cmd, &buf, &buflen, NV_ENCODE_XDR,
	    KM_SLEEP) == 0);
	nvlist_free(nvl_cmd);
	evt_header = kmem_zalloc(sizeof(cluster_evt_header_t), KM_SLEEP);
	evt_header->msg_type = CLUSTER_EVT_SYNC_CMD;
	sync_cmd->refcount++;
	cluster_san_host_asyn_send(remote_hostid == -1 ? CLUSTER_SAN_BROADCAST_SESS : cshi,
		buf, buflen, evt_header, sizeof(cluster_evt_header_t),
		CLUSTER_SAN_MSGTYPE_CLUSTER, CLUSTER_SAN_ASYN_TX_SYNC_CMD,
		sync_cmd, cs_asyn_tx_sync_cmd_compl, cs_asyn_tx_sync_cmd_clean,
		cs_asyn_tx_sync_cmd_comp);

	mutex_enter(&sync_cmd->lock);
	while (sync_cmd->host_cnt != sync_cmd->ret_cnt) {
		ret = cv_timedwait(&sync_cmd->cv, &sync_cmd->lock,
			ddi_get_lbolt() + drv_usectohz(timeout*1000*1000));
		if (ret == -1) {
			break;
		}
	}
	mutex_exit(&sync_cmd->lock);

	cluster_san_host_asyn_send_clean(CLUSTER_SAN_ASYN_TX_SYNC_CMD,
		sync_cmd);

	mutex_enter(&clustersan->cs_sync_cmd.sync_cmd_lock);
	list_remove(&clustersan->cs_sync_cmd.sync_cmd_list, sync_cmd);
	mutex_exit(&clustersan->cs_sync_cmd.sync_cmd_lock);

out:
	/* use nvlist ret */
	VERIFY(nvlist_alloc(&nvl_result, NV_UNIQUE_NAME, KM_SLEEP) == 0);
	cmd_host = list_head(&sync_cmd->cmd_host_list);
	while (cmd_host != NULL) {
		if (cmd_host->is_synced == 0) {
			cmn_err(CE_IGNORE, "clustersan: host(%s,%d) no respond, cmd(%"PRIx64"): %s",
				cmd_host->host->hostname, cmd_host->host->hostid, cmd_id, cmd_str);
			cmd_host->ret = -1;
			
		} else {
			cmn_err(CE_IGNORE, "clustersan: host(%s,%d) run cmd(%"PRIx64"): %s, ret:%d",
				cmd_host->host->hostname, cmd_host->host->hostid, cmd_id, cmd_str,
				cmd_host->ret);
		}

		snprintf(hostname, 64, "%s,%d", cmd_host->host->hostname,
			cmd_host->host->hostid);
		VERIFY(nvlist_add_int32(nvl_result, hostname, cmd_host->ret) == 0);
		/* rele host ref */
		cluster_san_hostinfo_rele(cmd_host->host);
		cmd_host = list_next(&sync_cmd->cmd_host_list, cmd_host);
	}

	cluster_san_sync_cmd_destroy(sync_cmd);

	return (nvl_result);
}

static void cluster_san_rx_sync_cmd_handle(cs_rx_data_t *cs_data)
{
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	nvlist_t *nvl_cmd;
	/* nvlist_t *nvl_post; */
	uint64_t cmd_id;
	char *cmd_str;
	char *buf;
	size_t buflen;
	int ret;

	ret = nvlist_unpack(cs_data->data, cs_data->data_len, &nvl_cmd, KM_SLEEP);
	if (ret != 0) {
		goto out;
	}
	VERIFY(0 == nvlist_lookup_uint64(nvl_cmd, "cmd_id", &cmd_id));
	VERIFY(0 == nvlist_lookup_string(nvl_cmd, "cmd_str", &cmd_str));

	cmn_err(CE_IGNORE, "clustersan: rx cmd(%"PRIx64": %s) from the host(%s,%d)",
		cmd_id, cmd_str, cshi->hostname, cshi->hostid);

	VERIFY(nvlist_add_uint32(nvl_cmd, "hostid", cshi->hostid) == 0);
	VERIFY(nvlist_size(nvl_cmd, &buflen, NV_ENCODE_XDR) == 0);
	buf = kmem_alloc(buflen, KM_SLEEP);
	VERIFY(nvlist_pack(nvl_cmd, &buf, &buflen, NV_ENCODE_XDR,
	    KM_SLEEP) == 0);
	nvlist_free(nvl_cmd);

	/* zfs_notify_clusterd(EVT_CLUSTERSAN_SYNC_CMD, buf, buflen); */

out:
	csh_rx_data_free(cs_data, B_TRUE);
}

void cluster_san_remote_cmd_return(char *buf, uint64_t len)
{
	cluster_san_hostinfo_t *cshi;
	nvlist_t *nvl_cmd;
	cluster_evt_header_t evt_header;
	uint32_t hostid;
	int ret;

	ret = nvlist_unpack(buf, len, &nvl_cmd, KM_SLEEP);
	if (ret != 0) {
		kmem_free(buf, len);
		return;
	}
	VERIFY(0 == nvlist_lookup_uint32(nvl_cmd, "hostid", &hostid));
	
	rw_enter(&clustersan_rwlock, RW_READER);
	cshi = list_head(&clustersan->cs_hostlist);
	while (cshi != NULL) {
		if (cshi->hostid == hostid) {
			cluster_san_hostinfo_hold(cshi);
			break;
		}
		cshi = list_next(&clustersan->cs_hostlist, cshi);
	}
	rw_exit(&clustersan_rwlock);

	if (cshi != NULL) {
		bzero(&evt_header, sizeof(cluster_evt_header_t));
		evt_header.msg_type = CLUSTER_EVT_SYNC_CMD_RET;
		cluster_san_host_send(cshi, buf, len, &evt_header,
			sizeof(cluster_evt_header_t),
			CLUSTER_SAN_MSGTYPE_CLUSTER, 1, 1, 3);
		cluster_san_hostinfo_rele(cshi);
	}

	nvlist_free(nvl_cmd);
	kmem_free(buf, len);
}

static void cluster_san_rx_sync_cmd_return(cs_rx_data_t *cs_data)
{
	cluster_san_hostinfo_t *cshi = cs_data->cs_private;
	nvlist_t *nvl_cmd;
	cs_sync_cmd_node_t *sync_cmd;
	cs_sync_cmd_host_node_t *cmd_host;
	uint64_t cmd_id;
	uint32_t hostid;
	int ret;

	ret = nvlist_unpack(cs_data->data, cs_data->data_len, &nvl_cmd, KM_SLEEP);
	if (ret != 0) {
		csh_rx_data_free(cs_data, B_TRUE);
		return;
	}
	VERIFY(0 == nvlist_lookup_uint32(nvl_cmd, "hostid", &hostid));
	VERIFY(0 == nvlist_lookup_uint64(nvl_cmd, "cmd_id", &cmd_id));
	VERIFY(0 == nvlist_lookup_int32(nvl_cmd, "return", &ret));
	nvlist_free(nvl_cmd);

	cmn_err(CE_IGNORE, "clustersan: rx remote(%s,%d) cmd(%"PRIx64") return(%d)",
		cshi->hostname, cshi->hostid, cmd_id, ret);

	mutex_enter(&clustersan->cs_sync_cmd.sync_cmd_lock);
	sync_cmd = list_head(&clustersan->cs_sync_cmd.sync_cmd_list);
	while (sync_cmd != NULL) {
		if (sync_cmd->cmd_id == cmd_id) {
			break;
		}
		sync_cmd = list_next(&clustersan->cs_sync_cmd.sync_cmd_list, sync_cmd);
	}
	if (sync_cmd != NULL) {
		mutex_enter(&sync_cmd->lock);
		cmd_host = list_head(&sync_cmd->cmd_host_list);
		while (cmd_host != NULL) {
			if (cmd_host->host == cshi) {
				cmd_host->is_synced = 1;
				cmd_host->ret = ret;
				sync_cmd->ret_cnt++;
				cv_signal(&sync_cmd->cv);
				break;
			}
			cmd_host = list_next(&sync_cmd->cmd_host_list, cmd_host);
		}
		mutex_exit(&sync_cmd->lock);
	}
	mutex_exit(&clustersan->cs_sync_cmd.sync_cmd_lock);
	csh_rx_data_free(cs_data, B_TRUE);
}

int
clustersan_get_ipmi_switch(void)
{
	return (cluster_failover_ipmi_switch);
}


