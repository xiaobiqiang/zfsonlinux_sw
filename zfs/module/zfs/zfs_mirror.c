#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/crc32.h>

#include <sys/dmu.h>
#include <sys/dmu_impl.h>
#include <sys/dmu_tx.h>
#include <sys/dbuf.h>
#include <sys/dnode.h>
#include <sys/zfs_context.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_synctask.h>
#include <sys/dsl_prop.h>
#include <sys/dmu_zfetch.h>
#include <sys/zfs_ioctl.h>
#include <sys/zap.h>
#include <sys/zio_checksum.h>
#include <sys/sa.h>
#include <sys/arc.h>
#include <sys/refcount.h>
#include <sys/zfs_mirror.h>

#include <sys/spa_impl.h>
#include <sys/spa.h>
#include <sys/modhash_impl.h>
#include <sys/cluster_san.h>
#include <sys/zil_impl.h>

/* DEBUG */
int debug_msg = 0;
int zfs_mirror_new_debug_yc = 0;
int zfs_mirror_expired_handle_debug = 0;

uint32_t	zfs_mirror_aligned_tq_nthread = 8;
uint32_t	zfs_mirror_nonaligned_tq_nthread = 8;

uint32_t	zfs_mirror_log_clean_max_tasks = 512;

uint_t		zfs_mirror_spa_os_hash_size = 1024;

zfs_mirror_mac_t *zfs_mirror_mac_port  = NULL;
boolean_t	zfs_mirror_mac_initialized = B_FALSE;

static uint64_t			zfs_mirror_ref = 0;

/* align and no align cache whatchdog */
static zfs_mirror_watchdog_t *zfs_mirror_wd = NULL;
clock_t zfs_mirror_watchdog_tick = 0;/* ticks */
clock_t zfs_mirror_watchdog_interval = 1;/* seconds */
uint64_t zfs_mirror_expired_check_gap = 15; /* seconds */
uint64_t zfs_mirror_unali_timeout = 300;/* seconds */
uint64_t zfs_mirror_unali_threshold = 60;/* seconds */
uint64_t zfs_mirrro_unali_check_times = 1;
uint64_t zfs_mirror_ali_timeout = 240;/* seconds */
uint64_t zfs_mirror_ali_threshold = 30;/* seconds */
uint64_t zfs_mirror_avl_frame_blk_timeout = 5;/* seconds */

uint64_t zfs_mirror_spa_os_timeout = 120;

uint64_t zfs_mirror_no_reply_threshold = 10;

uint64_t zfs_mirror_send_txg_gap = 5;

boolean_t zfs_mirror_timeout_switch = B_TRUE;

#define	ZFS_MIRROR_WD_CHECK_GUID_N		64
#define	ZFS_MIRROR_WD_CHECK_NONALI_N	10000

#define	ZFS_MIRROR_TRACE_TIME_DEBUG		0

static kmem_cache_t *mirror_aligned_txg_cache;/* sizeof(mirror_cache_txg_list_t) */

/* spa hung monitor */
#define	ZFS_MIRROR_SPA_HUNG_TIME		120000000
typedef struct zfs_mirror_spa_txg_state {
    uint64_t last_txg;
    uint64_t last_txg_time;
}zfs_mirror_spa_txg_state_t;

uint64_t zfs_mirror_spa_hung_hz = UINT64_MAX;

#define	ISDIGIT(_c) \
    ((_c) >= '0' && (_c) <= '9')

#define	ISXDIGIT(_c) \
    (ISDIGIT(_c) || \
    ((_c) >= 'a' && (_c) <= 'f') || \
    ((_c) >= 'A' && (_c) <= 'F'))

#define	ISLOWER(_c) \
    ((_c) >= 'a' && (_c) <= 'z')

#define	ISUPPER(_c) \
    ((_c) >= 'A' && (_c) <= 'Z')

static void  zfs_mirror_insert_hash(mirror_unaligned_cache_t *unaligned_cache,
    zfs_mirror_nonali_hash_t *blk_hash);
static int zfs_mirror_clean_hash_blk(mirror_unaligned_cache_t *unaligned_cache,
    uint64_t object_id, uint64_t blk_id, uint64_t offset,
    uint64_t mirror_io_index, list_t *cache_blk_list, list_t *hash_blk_list);
static zfs_mirror_nonali_hash_t *zfs_mirror_find_hash(
    mirror_unaligned_cache_t *unaligned_cache,
    uint64_t object_id, uint64_t blk_id, uint64_t blk_offset);
static zfs_mirror_nonali_hash_t *zfs_mirror_create_hash_member(zfs_mirror_cache_data_t *cache_data);
static int zfs_mirror_destroy_hash_member(zfs_mirror_nonali_hash_t *blk_hash);
static void zfs_mirror_clean_cache_list(uint64_t spa_id, uint64_t os_id, uint64_t txg);
static void mirror_cache_list_insert_txg_sort (list_t *cache_list,
    mirror_cache_txg_list_t *txg_list);

static void zfs_mirror_watchdog_init(void);
static void zfs_mirror_watchdog_fini(void);
static void zfs_mirror_watchdog_thread(void *arg);
static int zfs_mirror_os_io_expired_handle(void);

static int zfs_mirror_aligned_expired_handle(void);
static int zfs_mirror_unaligned_expired_handle(void);
static int zfs_mirror_spa_os_expired_handle(void);
static void zfs_mirror_get_last_synced_txg(void *arg);
static void zfs_mirror_rcv_last_synced_txg(void *arg);
static void zfs_mirror_is_unaligned_actived(void *arg);
static void zfs_mirror_handle_unaligned_actived(void *arg);

static void zfs_mirror_clean_cache_txg_list(mirror_cache_txg_list_t *txg_list);
static void zfs_mirror_rx_spa_txg_handle(void *arg);


static void
debug_zfs_mirror_data_check_sum(uint64_t size, uint64_t sum1, uint64_t sum2)
{
}

/*
static void
zfs_mirror_data_checksum(const unsigned char *data, uint64_t size, mirror_cksum_t *ck)
{
    unsigned char buffer[17] = {"\0"};
    MD5_CTX context;

    MD5Init(&context);
    MD5Update(&context, data, size);
    MD5Final(buffer, &context);

    ck->mc_cksum[0] = (uint64_t)(*((uint64_t *)buffer));
    ck->mc_cksum[1] = (uint64_t)(*((uint64_t *)(buffer+8)));

    debug_zfs_mirror_data_check_sum(size, ck->mc_cksum[0], ck->mc_cksum[1]);
}
*/

/* ARGSUSED */
static int
mirror_io_cons(void *data, void *unused, int kmflag)
{
    dbuf_mirror_io_t *io = data;
    bzero(io, sizeof (dbuf_mirror_io_t));
    return (0);
}

/* ARGSUSED */
static void
mirror_io_dest(void *data, void *unused)
{
}

static void zfs_mirror_cache_buf_init(void)
{
    zfs_mirror_mac_port->mm_io_hdr = kmem_cache_create("dbuf_mirror_io_t",
        sizeof (dbuf_mirror_io_t), 0,
        mirror_io_cons, mirror_io_dest, NULL, NULL, NULL, 0);
    mirror_aligned_txg_cache = kmem_cache_create("zfs_mirror_aligned_txg_cache",
        sizeof(mirror_cache_txg_list_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
}

static void zfs_mirror_cache_buf_fini(void)
{
    kmem_cache_destroy(zfs_mirror_mac_port->mm_io_hdr);
    kmem_cache_destroy(mirror_aligned_txg_cache);
}

static mirror_cache_txg_list_t *zfs_mirror_aligned_txg_list_alloc(void)
{
    mirror_cache_txg_list_t *txg_list;

    txg_list = kmem_cache_alloc(mirror_aligned_txg_cache, KM_SLEEP);
    list_create(&txg_list->cache_txg_list, sizeof(zfs_mirror_cache_data_t),
        offsetof(zfs_mirror_cache_data_t, node));
    mutex_init(&txg_list->cache_txg_list_mtx, NULL, MUTEX_DRIVER, NULL);

    return (txg_list);
}

static void zfs_mirror_aligned_txg_list_free(
    mirror_cache_txg_list_t *txg_list)
{
    zfs_mirror_clean_cache_txg_list(txg_list);
    mutex_destroy(&txg_list->cache_txg_list_mtx);
    list_destroy(&txg_list->cache_txg_list);
    kmem_cache_free(mirror_aligned_txg_cache, txg_list);
}

static void zfs_mirror_init_kstat(zfs_mirror_mac_t *mirror_mac)
{
    if (mirror_mac == NULL)
        return;

    mirror_mac->rs_ali_cache_size = 0;
    mirror_mac->rs_nonali_cache_size = 0;
    mirror_mac->rs_nonali_modhash_frames = 0;

    mirror_mac->tx_ali_data_frames = 0;
    mirror_mac->tx_nonali_data_frames = 0;
    mirror_mac->tx_ali_clr_frames = 0;
    mirror_mac->tx_nonali_clr_frames = 0;
    mirror_mac->tx_ali_timeout_frames = 0;
    mirror_mac->tx_nonali_timeout_frames = 0;

    mirror_mac->tx_ali_reply_frame = 0;
    mirror_mac->tx_nonali_reply_frame = 0;
    mirror_mac->rx_ali_reply_frames = 0;
    mirror_mac->rx_nonali_reply_frames = 0;

    mirror_mac->rx_ali_data_frames = 0;
    mirror_mac->rx_nonali_data_frames = 0;

    mirror_mac->rx_ali_data_dec_frames = 0;
    mirror_mac->rx_nonali_data_dec_frames = 0;

    mirror_mac->rx_obsolete_frames = 0;

    mirror_mac->rx_add_blk_list = 0;
    mirror_mac->rx_dec_blk_list = 0;

    mirror_mac->rx_ali_clr_frames = 0;
    mirror_mac->rx_nonali_clr_frames = 0;
}

static int
zfs_mirror_stats_update(kstat_t *ks, int rw)
{
    zfs_mirror_mac_t *mirror_mac;
    zfs_mirror_stat_t *mirror_ks;

    if (rw == KSTAT_WRITE)
        return (EACCES);

    mirror_mac = (zfs_mirror_mac_t *)ks->ks_private;
    mirror_ks = (zfs_mirror_stat_t *)ks->ks_data;

    /*
     * Basic information
     */
    /* kstat_named_setstr(&mirror_ks->port_name, mirror_mac->port_name); */
    /* todo: protect the mirror_cur_host */
    if (mirror_mac->mirror_cur_host != NULL) {
        mirror_ks->mirror_hostid.value.ui32 = mirror_mac->mirror_cur_host->hostid;
    } else {
        mirror_ks->mirror_hostid.value.ui32 = 0;
    }

    mirror_ks->rs_ali_cache_size.value.ui64 = mirror_mac->rs_ali_cache_size;
    mirror_ks->rs_nonali_cache_size.value.ui64 = mirror_mac->rs_nonali_cache_size;
    mirror_ks->rs_nonali_modhash_num.value.ui64 = mirror_mac->rs_nonali_modhash_frames;

    mirror_ks->tx_ali_data_frames.value.ui64 = mirror_mac->tx_ali_data_frames;
    mirror_ks->tx_nonali_data_frames.value.ui64 = mirror_mac->tx_nonali_data_frames;
    mirror_ks->tx_ali_clr_frames.value.ui64 = mirror_mac->tx_ali_clr_frames;
    mirror_ks->tx_nonali_clr_frames.value.ui64 = mirror_mac->tx_nonali_clr_frames;
    mirror_ks->tx_ali_timeout_frames.value.ui64 = mirror_mac->tx_ali_timeout_frames;
    mirror_ks->tx_nonali_timeout_frames.value.ui64 = mirror_mac->tx_nonali_timeout_frames;

    mirror_ks->tx_ali_reply_frame.value.ui64 = mirror_mac->tx_ali_reply_frame;
    mirror_ks->tx_nonali_reply_frame.value.ui64 = mirror_mac->tx_nonali_reply_frame;
    mirror_ks->rx_ali_reply_frames.value.ui64 = mirror_mac->rx_ali_reply_frames;
    mirror_ks->rx_nonali_reply_frames.value.ui64 = mirror_mac->rx_nonali_reply_frames;

    mirror_ks->rx_ali_data_frames.value.ui64 = mirror_mac->rx_ali_data_frames;
    mirror_ks->rx_nonali_data_frames.value.ui64 = mirror_mac->rx_nonali_data_frames;

    mirror_ks->rx_ali_data_dec_frames.value.ui64 = mirror_mac->rx_ali_data_dec_frames;
    mirror_ks->rx_nonali_data_dec_frames.value.ui64 = mirror_mac->rx_nonali_data_dec_frames;

    mirror_ks->rx_obsolete_frames.value.ui64 = mirror_mac->rx_obsolete_frames;

    mirror_ks->rx_add_blk_list.value.ui64 = mirror_mac->rx_add_blk_list;
    mirror_ks->rx_dec_blk_list.value.ui64 = mirror_mac->rx_dec_blk_list;

    mirror_ks->rx_ali_clr_frames.value.ui64 = mirror_mac->rx_ali_clr_frames;
    mirror_ks->rx_nonali_clr_frames.value.ui64 = mirror_mac->rx_nonali_clr_frames;

    mirror_ks->tx_hbx_frames.value.ui64 = mirror_mac->tx_hbx_frames;
    mirror_ks->rx_hbx_frames.value.ui64 = mirror_mac->rx_hbx_frames;

    return (0);
}

int
zfs_mirror_stats_init(void)
{
    kstat_t *ks;
    zfs_mirror_stat_t *mirror_ks;

    /*
     * Create and init kstat
     */
    ks = kstat_create("zfs", 0, "mirror", "misc", KSTAT_TYPE_NAMED,
        sizeof(zfs_mirror_stat_t) / sizeof(kstat_named_t), KSTAT_FLAG_VIRTUAL);
    if (ks == NULL) {
        cmn_err(CE_WARN, "mirror create kstat failed");
        return (-1);
    }

    ks->ks_data = kmem_alloc(sizeof(zfs_mirror_stat_t), KM_SLEEP);
    zfs_mirror_mac_port->mirror_ks = ks;
    mirror_ks = (zfs_mirror_stat_t *)ks->ks_data;

    /*
     * Initialize all the statistics
     */
    kstat_named_init(&mirror_ks->rs_ali_cache_size, "rs_ali_cache_size",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->rs_nonali_cache_size, "rs_nonali_cache_size",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->rs_nonali_modhash_num, "rs_nonali_modhash_num",
        KSTAT_DATA_UINT64);

    /* kstat_named_init(&mirror_ks->port_name, "mirror_port_name",
        KSTAT_DATA_STRING); */
    kstat_named_init(&mirror_ks->mirror_hostid, "mirror_hostid",
        KSTAT_DATA_UINT32);
    kstat_named_init(&mirror_ks->tx_ali_data_frames, "tx_ali_data_frames",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->tx_nonali_data_frames, "tx_nonali_data_frames",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->tx_ali_clr_frames, "tx_ali_clr_frames",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->tx_nonali_clr_frames, "tx_nonali_clr_frames",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->tx_ali_timeout_frames, "tx_ali_timeout_frames",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->tx_nonali_timeout_frames, "tx_nonali_timeout_frames",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->tx_ali_reply_frame, "tx_ali_reply_frame",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->tx_nonali_reply_frame, "tx_nonali_reply_frame",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->rx_ali_reply_frames, "rx_ali_reply_frames",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->rx_nonali_reply_frames, "rx_nonali_reply_frames",
        KSTAT_DATA_UINT64);

    kstat_named_init(&mirror_ks->rx_ali_data_frames, "rx_ali_data_frames",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->rx_nonali_data_frames, "rx_nonali_data_frames",
        KSTAT_DATA_UINT64);

    kstat_named_init(&mirror_ks->rx_ali_data_dec_frames, "rx_ali_data_dec_frames",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->rx_nonali_data_dec_frames, "rx_nonali_data_dec_frames",
        KSTAT_DATA_UINT64);

    kstat_named_init(&mirror_ks->rx_obsolete_frames, "rx_obsolete_frames",
        KSTAT_DATA_UINT64);

    kstat_named_init(&mirror_ks->rx_add_blk_list, "rx_add_blk_list",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->rx_dec_blk_list, "rx_dec_blk_list",
        KSTAT_DATA_UINT64);

    kstat_named_init(&mirror_ks->rx_ali_clr_frames, "rx_ali_clr_frames",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->rx_nonali_clr_frames, "rx_nonali_clr_frames",
        KSTAT_DATA_UINT64);

    kstat_named_init(&mirror_ks->tx_hbx_frames, "tx_hbx_frames",
        KSTAT_DATA_UINT64);
    kstat_named_init(&mirror_ks->rx_hbx_frames, "rx_hbx_frames",
        KSTAT_DATA_UINT64);

    /* ks->ks_data_size += strlen(zfs_mirror_mac_port->port_name) + 1; */
    ks->ks_update = zfs_mirror_stats_update;
    ks->ks_private = (void *)zfs_mirror_mac_port;

    kstat_install(ks);

    return (0);

}

static void
zfs_mirror_clean_aligned (void *arg)
{
    cs_rx_data_t *cs_data = arg;
    zfs_mirror_msg_clean_header_t *header =
        cs_data->ex_head;

    zfs_mirror_clean_cache_list(header->spa_id, header->os_id,
        header->txg);
    atomic_inc_64(&zfs_mirror_mac_port->rx_ali_clr_frames);
    csh_rx_data_free(cs_data, B_TRUE);
}

static void mirror_cache_list_insert_txg_sort (list_t *cache_list,
    mirror_cache_txg_list_t *txg_list)
{
    mirror_cache_txg_list_t *cur;

    cur = list_tail(cache_list);
    while (cur != NULL) {
        if (cur->cache_txg_list_txg <= txg_list->cache_txg_list_txg) {
            list_insert_after(cache_list, cur, txg_list);
            return;
        }
        cur = list_prev(cache_list, cur);
    }

    if (cur == NULL) {
        list_insert_head(cache_list, txg_list);
    }
}

#define	ZFS_MIRROR_HOLD_CREATE		0x1

uint64_t zfs_mirror_located_keygen(
    uint64_t object_id, uint64_t blk_id, uint64_t offset)
{
    return (((object_id & 0xf) << 60) |
        ((blk_id & 0xffffffffff) << 20) | (offset & 0xfffff));
}

uint64_t
zfs_mirror_spa_os_keygen(uint64_t spa_id, uint64_t os_id)
{
    return (((spa_id & 0xffffffffffff) << 16) | (os_id & 0xffff));
}

static mirror_spa_os_t *
zfs_mirror_get_spa_os(uint64_t spa_id,
    uint64_t os_id, uint_t flags, uint32_t remote_hostid)
{
    mirror_spa_os_t *spa_os = NULL;
    list_t *spa_os_list = NULL;
    uint64_t hash_key;
    int ret;

    hash_key = zfs_mirror_spa_os_keygen(spa_id, os_id);

    ret = mod_hash_find(zfs_mirror_mac_port->spa_os_modhash,
        (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t *)&spa_os_list);
    if (ret != 0) {
        if ((flags & ZFS_MIRROR_HOLD_CREATE) == 0) {
            return (NULL);
        }
        spa_os_list = kmem_zalloc(sizeof(list_t), KM_SLEEP);
        list_create(spa_os_list, sizeof(mirror_spa_os_t),
            offsetof(mirror_spa_os_t, node));
        mod_hash_insert(zfs_mirror_mac_port->spa_os_modhash,
            (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t)spa_os_list);
    }
    for (spa_os = list_head(spa_os_list); spa_os != NULL;
        spa_os = list_next(spa_os_list, spa_os)) {
        if ((spa_os->spa_id == spa_id) && (spa_os->os_id == os_id)) {
            break;
        }
    }
    if (spa_os == NULL) {
        if ((flags & ZFS_MIRROR_HOLD_CREATE) == 0) {
            return (NULL);
        }
        spa_os = kmem_zalloc(sizeof(mirror_spa_os_t), KM_SLEEP);
        spa_os->spa_id = spa_id;
        spa_os->os_id = os_id;
        spa_os->parent = spa_os_list;
        list_insert_tail(spa_os_list, spa_os);
    }

    if ((flags & ZFS_MIRROR_HOLD_CREATE) != 0) {
        spa_os->active_time = ddi_get_time();
        spa_os->remote_hostid = remote_hostid;
    }

    return (spa_os);
}

static mirror_aligned_cache_t *
zfs_mirror_hold_aligned_cache(uint64_t spa_id,
    uint64_t os_id, uint_t flags, uint32_t remote_hostid, void *tag)
{
    mirror_spa_os_t *spa_os;
    mirror_aligned_cache_t *aligned_cache;
    mutex_enter(&zfs_mirror_mac_port->spa_os_lock);
    spa_os = zfs_mirror_get_spa_os(spa_id, os_id, flags, remote_hostid);
    if (spa_os == NULL) {
        mutex_exit(&zfs_mirror_mac_port->spa_os_lock);
        return (NULL);
    }
    aligned_cache = spa_os->aligned_cache;
    if (aligned_cache == NULL) {
        if ((flags & ZFS_MIRROR_HOLD_CREATE) == 0) {
            mutex_exit(&zfs_mirror_mac_port->spa_os_lock);
            return (NULL);
        }
        aligned_cache = kmem_zalloc(sizeof(mirror_aligned_cache_t), KM_SLEEP);
        mutex_init(&aligned_cache->lock, NULL, MUTEX_DEFAULT, NULL);
        refcount_create(&aligned_cache->refcount);
        list_create(&aligned_cache->aligned_list_txg,
            sizeof(mirror_cache_txg_list_t),
            offsetof(mirror_cache_txg_list_t, cache_txg_list_node));
        list_create(&aligned_cache->aligned_list_time,
            sizeof(mirror_cache_txg_list_t),
            offsetof(mirror_cache_txg_list_t, cache_time_list_node));
        spa_os->aligned_cache = aligned_cache;
    }
    refcount_add(&aligned_cache->refcount, tag);
    mutex_exit(&zfs_mirror_mac_port->spa_os_lock);

    mutex_enter(&aligned_cache->lock);

    return (aligned_cache);
}

static void
zfs_mirror_rele_aligned_cache(
    mirror_aligned_cache_t *aligned_cache, void *tag)
{
    int64_t holds;

    mutex_exit(&aligned_cache->lock);
    holds = refcount_remove(&aligned_cache->refcount, tag);
    if (holds == 0) {

    }
}

static uint_t
zfs_mirror_mod_hash_byid(void *hash_data, mod_hash_key_t key)
{
    uint64_t kval = (uint64_t)(uintptr_t)hash_data;
    return ((uint_t)((uint64_t)(uintptr_t)key * kval));
}

static int
zfs_mirror_mod_hash_idkey_cmp(mod_hash_key_t key1, mod_hash_key_t key2)
{
    uintptr_t k1 = (uintptr_t)key1;
    uintptr_t k2 = (uintptr_t)key2;
    if (k1 > k2)
        return (-1);
    else if (k1 < k2)
        return (1);
    else
        return (0);
}

static void
zfs_mirror_unaligned_hash_valdtor(mod_hash_val_t val)
{
    list_t *blk_hash_list = (list_t *)val;
    zfs_mirror_nonali_hash_t *blk_hash;
    zfs_mirror_cache_data_t *cache_data;

    while ((blk_hash = list_head(blk_hash_list)) != NULL) {
        list_remove(blk_hash_list, blk_hash);
        while (cache_data = list_remove_head(&blk_hash->hash_nonali_blk_list)) {
            csh_rx_data_free(cache_data->cs_data, B_TRUE);
            kmem_free(cache_data, sizeof(zfs_mirror_cache_data_t));
        }
        zfs_mirror_destroy_hash_member(blk_hash);
    }
    list_destroy(blk_hash_list);
    kmem_free(blk_hash_list, sizeof(list_t));
}

static mirror_unaligned_cache_t *
zfs_mirror_hold_unaligned_cache(uint64_t spa_id,
    uint64_t os_id, uint_t flags, uint32_t remote_hostid, void *tag)
{
    mirror_spa_os_t *spa_os;
    mirror_unaligned_cache_t *unaligned_cache;
    mutex_enter(&zfs_mirror_mac_port->spa_os_lock);
    spa_os = zfs_mirror_get_spa_os(spa_id, os_id, flags, remote_hostid);
    if (spa_os == NULL) {
        mutex_exit(&zfs_mirror_mac_port->spa_os_lock);
        return (NULL);
    }
    unaligned_cache = spa_os->unaligned_cache;
    if (unaligned_cache == NULL) {
        uint_t kval;
        char hash_name[64];

        if ((flags & ZFS_MIRROR_HOLD_CREATE) == 0) {
            mutex_exit(&zfs_mirror_mac_port->spa_os_lock);
            return (NULL);
        }
        unaligned_cache = kmem_zalloc(sizeof(mirror_unaligned_cache_t), KM_SLEEP);
        mutex_init(&unaligned_cache->lock, NULL, MUTEX_DEFAULT, NULL);
        refcount_create(&unaligned_cache->refcount);

        kval = mod_hash_iddata_gen(ZFS_MIRROR_NONALI_DATA_HASH_SIZE);
        snprintf(hash_name, 64, "zfs_mirror_unaligned_%"PRIx64"_%"PRIx64,
            spa_id, os_id);
        unaligned_cache->unaligned_modhash = mod_hash_create_extended(hash_name,
            ZFS_MIRROR_NONALI_DATA_HASH_SIZE, mod_hash_null_keydtor,
            zfs_mirror_unaligned_hash_valdtor, zfs_mirror_mod_hash_byid,
            (void *)(uintptr_t)kval, zfs_mirror_mod_hash_idkey_cmp, KM_SLEEP);
        list_create(&unaligned_cache->unaligned_list_time,
            sizeof(zfs_mirror_nonali_hash_t),
            offsetof(zfs_mirror_nonali_hash_t, hash_sort_node));
        spa_os->unaligned_cache = unaligned_cache;
    }
    refcount_add(&unaligned_cache->refcount, tag);
    mutex_exit(&zfs_mirror_mac_port->spa_os_lock);

    mutex_enter(&unaligned_cache->lock);

    return (unaligned_cache);
}

static void
zfs_mirror_rele_unaligned_cache(
    mirror_unaligned_cache_t *unaligned_cache, void *tag)
{
    int64_t holds;

    mutex_exit(&unaligned_cache->lock);
    holds = refcount_remove(&unaligned_cache->refcount, tag);
    if (holds == 0) {

    }
}

typedef struct zfs_mirror_os_io {
    list_node_t node;
    kmutex_t lock;
    refcount_t refcount;
    uint64_t active_time;
    void *parent;
    uint64_t spa_id;
    uint64_t os_id;
    mod_hash_t *mirror_io_h;
}zfs_mirror_os_io_t;

static void
zfs_mirror_os_io_hash_valdtor(mod_hash_val_t val)
{
    list_t *os_io_list = (list_t *)val;
    zfs_mirror_os_io_t *os_io;

    while ((os_io = list_head(os_io_list)) != NULL) {
        list_remove(os_io_list, os_io);
        mutex_destroy(&os_io->lock);
        refcount_destroy(&os_io->refcount);
        mod_hash_destroy_hash(os_io->mirror_io_h);
        kmem_free(os_io, sizeof(zfs_mirror_os_io_t));
    }
    list_destroy(os_io_list);
    kmem_free(os_io_list, sizeof(list_t));
}

static void
zfs_mirror_io_hash_valdtor(mod_hash_val_t val)
{
    list_t *mirror_io_list = (list_t *)val;
    dbuf_mirror_io_t *mirror_io;

    while ((mirror_io = list_head(mirror_io_list)) != NULL) {
        list_remove(mirror_io_list, mirror_io);
        atomic_dec_64(&zfs_mirror_mac_port->mirror_io_cnt);
    }
    list_destroy(mirror_io_list);
    kmem_free(mirror_io_list, sizeof(list_t));
}

static
zfs_mirror_os_io_t *zfs_mirror_hold_os_io(uint64_t spa_id,
    uint64_t os_id, uint_t flags, void *tag)
{
    zfs_mirror_os_io_t *os_io = NULL;
    list_t *os_io_list = NULL;
    uint64_t hash_key;
    int ret;

    hash_key = zfs_mirror_spa_os_keygen(spa_id, os_id);
    mutex_enter(&zfs_mirror_mac_port->mirror_io_list_mtx);
    ret = mod_hash_find(zfs_mirror_mac_port->mirror_io_modhash,
        (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t *)&os_io_list);
    if (ret != 0) {
        if ((flags & ZFS_MIRROR_HOLD_CREATE) == 0) {
            mutex_exit(&zfs_mirror_mac_port->mirror_io_list_mtx);
            return (NULL);
        }
        os_io_list = kmem_zalloc(sizeof(list_t), KM_SLEEP);
        list_create(os_io_list, sizeof(zfs_mirror_os_io_t),
            offsetof(zfs_mirror_os_io_t, node));
        mod_hash_insert(zfs_mirror_mac_port->mirror_io_modhash,
            (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t)os_io_list);
    }
    ASSERT(os_io_list != NULL);
    for (os_io = list_head(os_io_list); os_io != NULL;
        os_io = list_next(os_io_list, os_io)) {
        if ((os_io->spa_id == spa_id) && (os_io->os_id == os_id)) {
            break;
        }
    }
    if (os_io == NULL) {
        char hash_name[64];
        uint_t kval;

        if ((flags & ZFS_MIRROR_HOLD_CREATE) == 0) {
            mutex_exit(&zfs_mirror_mac_port->mirror_io_list_mtx);
            return (NULL);
        }

        os_io = kmem_zalloc(sizeof(zfs_mirror_os_io_t), KM_SLEEP);
        os_io->spa_id = spa_id;
        os_io->os_id = os_id;
        snprintf(hash_name, 64, "zfs_mirror_io_%"PRIx64"_%"PRIx64,
            spa_id, os_id);
        kval = mod_hash_iddata_gen(ZFS_MIRROR_NONALI_DATA_HASH_SIZE);
        os_io->mirror_io_h = mod_hash_create_extended(hash_name,
            ZFS_MIRROR_NONALI_DATA_HASH_SIZE, mod_hash_null_keydtor,
            zfs_mirror_io_hash_valdtor, zfs_mirror_mod_hash_byid,
            (void *)(uintptr_t)kval, zfs_mirror_mod_hash_idkey_cmp, KM_SLEEP);
        mutex_init(&os_io->lock, NULL, MUTEX_DEFAULT, NULL);
        refcount_create(&os_io->refcount);
        os_io->parent = (void *)os_io_list;
        list_insert_tail(os_io_list, os_io);
    }
    refcount_add(&os_io->refcount, tag);
    if ((flags & ZFS_MIRROR_HOLD_CREATE) != 0) {
        os_io->active_time = ddi_get_time();
    }
    mutex_exit(&zfs_mirror_mac_port->mirror_io_list_mtx);

    mutex_enter(&os_io->lock);

    return (os_io);
}

static void
zfs_mirror_rele_os_io(zfs_mirror_os_io_t *os_io, void *tag)
{
    int64_t holds;

    mutex_exit(&os_io->lock);
    holds = refcount_remove(&os_io->refcount, tag);
    if (holds == 0) {

    }
}

static void
zfs_mirror_destroy_os_io(zfs_mirror_os_io_t *os_io)
{
    int cnt = 0;

    while (!refcount_is_zero(&os_io->refcount)) {
        cnt++;
        cmn_err(CE_WARN, "wait os_io release, cnt:%d", cnt);
        delay(drv_usectohz((clock_t)1000000));
    }

    mutex_destroy(&os_io->lock);
    refcount_destroy(&os_io->refcount);
    mod_hash_destroy_hash(os_io->mirror_io_h);
    kmem_free(os_io, sizeof(zfs_mirror_os_io_t));
}

static void
zfs_mirror_insert_io(zfs_mirror_os_io_t *os_io,
    dbuf_mirror_io_t *mirror_io)
{
    uint64_t hash_key = mirror_io->hash_key;
    list_t *mirror_io_list = NULL;
    int ret;

    ret = mod_hash_find(os_io->mirror_io_h, (mod_hash_key_t)(uintptr_t)hash_key,
        (mod_hash_val_t *)&mirror_io_list);
    if (ret != 0) {
        mirror_io_list = kmem_zalloc(sizeof(list_t), KM_SLEEP);
        list_create(mirror_io_list, sizeof(dbuf_mirror_io_t),
            offsetof(dbuf_mirror_io_t, mirror_io_cache));
        (void) mod_hash_insert(os_io->mirror_io_h,
            (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t)mirror_io_list);
    }
    ASSERT(mirror_io_list != NULL);
    list_insert_tail(mirror_io_list, mirror_io);

    atomic_inc_64(&zfs_mirror_mac_port->mirror_io_cnt);
}

static int
zfs_mirror_remove_io(zfs_mirror_os_io_t *os_io,
    dbuf_mirror_io_t *mirror_io)
{
    uint64_t hash_key = mirror_io->hash_key;
    list_t *mirror_io_list = NULL;
    dbuf_mirror_io_t *mirror_io_temp;
    int ret;

    ret = mod_hash_find(os_io->mirror_io_h, (mod_hash_key_t)(uintptr_t)hash_key,
        (mod_hash_val_t *)&mirror_io_list);
    if ((ret != 0) || (mirror_io_list == NULL)) {
        return (-1);
    }

    ret = -2;
    for (mirror_io_temp = list_head(mirror_io_list); mirror_io_temp != NULL;
        mirror_io_temp = list_next(mirror_io_list, mirror_io_temp)) {
        if (mirror_io_temp == mirror_io) {
            list_remove(mirror_io_list, mirror_io);
            atomic_dec_64(&zfs_mirror_mac_port->mirror_io_cnt);
            ret = 0;
            break;
        }
    }
    if (list_is_empty(mirror_io_list)) {
        (void)mod_hash_remove(os_io->mirror_io_h,
            (mod_hash_key_t)(uintptr_t)hash_key,
            (mod_hash_val_t *)&mirror_io_list);
        list_destroy(mirror_io_list);
        kmem_free(mirror_io_list, sizeof(list_t));
    }

    return (ret);
}

static void
zfs_mirror_clean_cache_txg_list(mirror_cache_txg_list_t *txg_list)
{
    zfs_mirror_cache_data_t *cache_data = NULL;

    mutex_enter(&txg_list->cache_txg_list_mtx);
    while (cache_data = list_remove_head(&txg_list->cache_txg_list)) {
        atomic_inc_64(&zfs_mirror_mac_port->rx_ali_data_dec_frames);
        atomic_add_64(&zfs_mirror_mac_port->rs_ali_cache_size,
            0 - cache_data->cs_data->data_len);
        csh_rx_data_free(cache_data->cs_data, B_TRUE);
        kmem_free(cache_data, sizeof(zfs_mirror_cache_data_t));
    }
    mutex_exit(&txg_list->cache_txg_list_mtx);
}

static void
zfs_mirror_clean_unaligned_cache_list(
    uint64_t spa_id, uint64_t os_id, cs_rx_data_t *cs_data)
{
    uint64_t count = 0;
    list_t cache_blk_list;
    list_t hash_blk_list;
    os_mirror_blkptr_node_t *blkptr_node = (os_mirror_blkptr_node_t *)cs_data->data;
    uint64_t blkptr_num = cs_data->data_len / sizeof(os_mirror_blkptr_node_t);
    mirror_unaligned_cache_t *unaligned_cache;
    zfs_mirror_nonali_hash_t *hash_blk;
    zfs_mirror_cache_data_t *cache_data;
    zfs_mirror_msg_mirrordata_header_t *header =
        cs_data->ex_head;

    unaligned_cache = zfs_mirror_hold_unaligned_cache(spa_id, os_id, 0, 0, FTAG);
    if (unaligned_cache == NULL) {
        return;
    }
    list_create(&cache_blk_list, sizeof(zfs_mirror_cache_data_t),
        offsetof(zfs_mirror_cache_data_t, node));
    list_create(&hash_blk_list, sizeof(zfs_mirror_nonali_hash_t),
        offsetof(zfs_mirror_nonali_hash_t, hash_sort_node));

    while (count < blkptr_num) {
        ASSERT((spa_id == blkptr_node[count].spa_id)
            && (os_id == blkptr_node[count].os_id));
        if (zfs_mirror_clean_hash_blk(unaligned_cache,
            blkptr_node[count].object_id,blkptr_node[count].blk_id,
            blkptr_node[count].offset, blkptr_node[count].mirror_io_index,
            &cache_blk_list, &hash_blk_list) == 0) {
            if (zfs_mirror_new_debug_yc) {
                cmn_err(CE_WARN, "non clr invalid, "
                    "spa_id:0x%"PRIx64", os_id:0x%"PRIx64", "
                    "object_id:0x%"PRIx64", blk_id:0x%"PRIx64", "
                    "offset:0x%"PRIx64", mirror_io_index:0x%"PRIx64", "
                    "index:%"PRId64", len:%"PRId64", count:%"PRId64,
                    blkptr_node[count].spa_id, blkptr_node[count].os_id,
                    blkptr_node[count].object_id, blkptr_node[count].blk_id,
                    blkptr_node[count].offset, blkptr_node[count].mirror_io_index,
                    header->index, header->len,
                    count);
            }
        }
        count++;
    }

    zfs_mirror_rele_unaligned_cache(unaligned_cache, FTAG);

    while ((cache_data = list_remove_head(&cache_blk_list)) != NULL) {
        atomic_inc_64(&zfs_mirror_mac_port->rx_nonali_data_dec_frames);
        atomic_add_64(&zfs_mirror_mac_port->rs_nonali_cache_size,
            0 - cache_data->cs_data->data_len);
        csh_rx_data_free(cache_data->cs_data, B_TRUE);
        kmem_free(cache_data, sizeof(zfs_mirror_cache_data_t));
    }
    list_destroy(&cache_blk_list);
    while ((hash_blk = list_head(&hash_blk_list)) != NULL) {
        list_remove(&hash_blk_list, hash_blk);
        zfs_mirror_destroy_hash_member(hash_blk);
    }
    list_destroy(&hash_blk_list);
}

static void zfs_mirror_clean_cache_list(uint64_t spa_id, uint64_t os_id, uint64_t txg)
{
    mirror_cache_txg_list_t *txg_list;
    mirror_cache_txg_list_t *next_txg_list;
    mirror_aligned_cache_t *aligned_cache;
    list_t clean_list;

    list_create(&clean_list,
        sizeof (mirror_cache_txg_list_t),
        offsetof(mirror_cache_txg_list_t, cache_txg_list_node));

    aligned_cache = zfs_mirror_hold_aligned_cache(spa_id, os_id, 0, 0, FTAG);
    if (aligned_cache == NULL) {
        list_destroy(&clean_list);
        return;
    }
    txg_list = list_head(&aligned_cache->aligned_list_txg);
    while (txg_list != NULL) {
        next_txg_list = list_next(&aligned_cache->aligned_list_txg, txg_list);
        if (txg_list->cache_txg_list_txg > txg) {
            break;
        }
        list_remove(&aligned_cache->aligned_list_txg, txg_list);
        list_remove(&aligned_cache->aligned_list_time, txg_list);
        list_insert_tail(&clean_list, txg_list);
        txg_list = next_txg_list;
    }
    zfs_mirror_rele_aligned_cache(aligned_cache, FTAG);

    while ((txg_list = list_head(&clean_list)) != NULL) {
        list_remove(&clean_list, txg_list);
        zfs_mirror_aligned_txg_list_free(txg_list);
    }
    list_destroy(&clean_list);
}

static void
zfs_mirror_clean_unaligned (void *arg)
{
    cs_rx_data_t *cs_data = arg;
    zfs_mirror_msg_mirrordata_header_t *header =
        cs_data->ex_head;

    zfs_mirror_clean_unaligned_cache_list(header->spa_id, header->os_id, cs_data);
    atomic_inc_64(&zfs_mirror_mac_port->rx_nonali_clr_frames);
    csh_rx_data_free(cs_data, B_TRUE);
}

int
zfs_mirror_write_clean_msg(log_clear_para_t *para)
{
    cluster_san_hostinfo_t *cshi = NULL;
    zfs_mirror_host_node_t *mirror_host;
    zfs_mirror_msg_clean_header_t *header;
    void *data = NULL;
    uint64_t len = 0;
    os_mirror_blkptr_list_t *blkptr_list = NULL;
    int ret = 0;

    rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_READER);
    mirror_host = zfs_mirror_mac_port->mirror_cur_host;
    if (mirror_host != NULL) {
        cshi = mirror_host->cshi;
        cluster_san_hostinfo_hold(cshi);
    }
    rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);

    if (cshi == NULL) {
        ret = -1;
        goto failed;
    }

    header = kmem_zalloc(sizeof(zfs_mirror_msg_clean_header_t), KM_SLEEP);
    header->spa_id = para->spa_id;
    header->os_id = para->os_id;
    header->object_id = para->object_id;
    header->txg = para->txg;
    if (para->data_type == MIRROR_DATA_UNALIGNED) {
        header->msg_head.msg_type = ZFS_MIRROR_CLEAR_NONALIGNED;
        blkptr_list = para->para_data;
        data = (void *)blkptr_list->blkptr_array;
        len =  blkptr_list->blkptr_num * sizeof(os_mirror_blkptr_node_t);
        atomic_inc_64(&zfs_mirror_mac_port->tx_nonali_clr_frames);
    } else {
        header->msg_head.msg_type = ZFS_MIRROR_CLEAR_ALIGNED;
        data = NULL;
        len = 0;
        atomic_inc_64(&zfs_mirror_mac_port->tx_ali_clr_frames);
    }
    ret = cluster_san_host_send(cshi,
        data, len, header, sizeof(zfs_mirror_msg_clean_header_t),
        CLUSTER_SAN_MSGTYPE_ZFS_MIRROR, 0, B_TRUE, 1);
#ifdef LC_DEBUG
	if (ret != 0) {
		cmn_err(CE_WARN, "[zfs_mirror_write_clean_msg]: send to host(%d), datalen(%d), headlen(%d), msgtype(%d) failed", 
			cshi->hostid, len, sizeof(zfs_mirror_msg_clean_header_t), header->msg_head.msg_type);
	}
#endif
    kmem_free(header, sizeof(zfs_mirror_msg_clean_header_t));
    cluster_san_hostinfo_rele(cshi);
failed:
    if (para->data_type == MIRROR_DATA_UNALIGNED) {
        if (data == NULL) {
            blkptr_list = para->para_data;
            data = (void *)blkptr_list->blkptr_array;
            len =  blkptr_list->blkptr_num * sizeof(os_mirror_blkptr_node_t);
        }
        kmem_free(data, len);
        kmem_free(blkptr_list, sizeof(os_mirror_blkptr_list_t));
    }
    kmem_free(para, sizeof(log_clear_para_t));
    return (ret);
}

zfs_mirror_host_node_t *
zfs_mirror_host_find(uint32_t hostid)
{
    zfs_mirror_host_node_t *mirror_host;
    if (hostid == 0) {
        return (NULL);
    }

    if (hostid > zfs_mirror_mac_port->mirror_local_host->hostid) {
        mirror_host = list_next(&zfs_mirror_mac_port->mirror_host_lists,
            zfs_mirror_mac_port->mirror_local_host);
        while (mirror_host != NULL) {
            if (mirror_host->hostid == hostid) {
                break;
            }
            mirror_host = list_next(&zfs_mirror_mac_port->mirror_host_lists,
                mirror_host);
        }
    } else if (hostid < zfs_mirror_mac_port->mirror_local_host->hostid) {
        mirror_host = list_prev(&zfs_mirror_mac_port->mirror_host_lists,
            zfs_mirror_mac_port->mirror_local_host);
        while (mirror_host != NULL) {
            if (mirror_host->hostid == hostid) {
                break;
            }
            mirror_host = list_prev(&zfs_mirror_mac_port->mirror_host_lists,
                mirror_host);
        }
    } else {
        mirror_host = zfs_mirror_mac_port->mirror_local_host;
    }
    return (mirror_host);
}

zfs_mirror_host_node_t *
zfs_mirror_select_host(void)
{
    zfs_mirror_host_node_t *mirror_host;
    zfs_mirror_host_node_t *cur_host = NULL;

    if ((zfs_mirror_mac_port->mirror_local_host->hostid & 1) != 0) {
        mirror_host = list_next(&zfs_mirror_mac_port->mirror_host_lists,
            zfs_mirror_mac_port->mirror_local_host);
        if (mirror_host == NULL) {
            mirror_host = list_head(&zfs_mirror_mac_port->mirror_host_lists);
        }
        while (mirror_host != zfs_mirror_mac_port->mirror_local_host) {
            if (mirror_host->cshi != NULL) {
                if (mirror_host->cshi->link_state == CTS_LINK_UP) {
                    cur_host = mirror_host;
                    break;
                }
            }
            mirror_host = list_next(&zfs_mirror_mac_port->mirror_host_lists,
                mirror_host);
            if (mirror_host == NULL) {
                mirror_host = list_head(&zfs_mirror_mac_port->mirror_host_lists);
            }
        }
    } else {
        mirror_host = list_prev(&zfs_mirror_mac_port->mirror_host_lists,
            zfs_mirror_mac_port->mirror_local_host);
        if (mirror_host == NULL) {
            mirror_host = list_tail(&zfs_mirror_mac_port->mirror_host_lists);
        }
        while (mirror_host != zfs_mirror_mac_port->mirror_local_host) {
            if (mirror_host->cshi != NULL) {
                if (mirror_host->cshi->link_state == CTS_LINK_UP) {
                    cur_host = mirror_host;
                    break;
                }
            }
            mirror_host = list_prev(&zfs_mirror_mac_port->mirror_host_lists,
                mirror_host);
            if (mirror_host == NULL) {
                mirror_host = list_tail(&zfs_mirror_mac_port->mirror_host_lists);
            }
        }
    }
    return (cur_host);
}

int
zfs_mirror_write_data_msg(uint64_t spa_id, uint64_t os_id, uint64_t object_id,
    uint64_t blk_id, char *data,  uint64_t offset, uint64_t len, uint64_t txg,
    zfs_mirror_data_type_t data_type, dbuf_mirror_io_t *mirror_io)
{
    cluster_san_hostinfo_t *cshi = NULL;
    zfs_mirror_host_node_t *mirror_host;
    zfs_mirror_msg_mirrordata_header_t *header;
    uint64_t mm_log_index;
    int ret;

    mm_log_index = atomic_inc_64_nv(&zfs_mirror_mac_port->mm_log_index);
    if ((data_type == MIRROR_DATA_UNALIGNED) && (mirror_io != NULL)) {
        zfs_mirror_os_io_t *os_io;
        mirror_io->mirror_io_index = mm_log_index;
        os_io = zfs_mirror_hold_os_io(spa_id, os_id,
            ZFS_MIRROR_HOLD_CREATE, FTAG);
        zfs_mirror_insert_io(os_io, mirror_io);
        zfs_mirror_rele_os_io(os_io, FTAG);
    }

    rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_READER);
    mirror_host = zfs_mirror_mac_port->mirror_cur_host;
    if (mirror_host != NULL) {
        cshi = mirror_host->cshi;
        cluster_san_hostinfo_hold(cshi);
    } else {
        if (zfs_mirror_mac_port->mirror_permanent_hostid == 0) {
            mirror_host = zfs_mirror_select_host();
        } else {
            mirror_host = zfs_mirror_host_find(
                zfs_mirror_mac_port->mirror_permanent_hostid);
        }
		
        if ((mirror_host != NULL) && (mirror_host->cshi != NULL)) {
            ret = cluster_change_failover_host(mirror_host->cshi);
            if (ret == 0) {
                cshi = mirror_host->cshi;
                zfs_mirror_mac_port->mirror_failover_host = mirror_host;
                zfs_mirror_mac_port->mirror_cur_host = mirror_host;
                cluster_san_hostinfo_hold(cshi);
            }
        }
    }
    rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);

    if (cshi == NULL) {
        return (1);
    }

    header = kmem_zalloc(sizeof(zfs_mirror_msg_mirrordata_header_t), KM_SLEEP);
    header->spa_id = spa_id;
    header->os_id = os_id;
    header->object_id = object_id;
    header->blk_id = blk_id;
    header->blk_offset = offset;
    header->len = len;
    header->txg = txg;
    header->index = mm_log_index;
    header->tx_time = gethrtime();
    if (data_type == MIRROR_DATA_ALIGNED) {
        header->msg_head.msg_type = ZFS_MIRROR_DATA;
    } else if (data_type == MIRROR_DATA_UNALIGNED) {
        header->msg_head.msg_type = ZFS_MIRROR_DATA_UNALIGNED;
    } else if (data_type == MIRROR_DATA_META_ALIGNED) {
        header->msg_head.msg_type = ZFS_MIRROR_META_DATA;
    }
	
    ret = cluster_san_host_send(cshi,
        data, len, header, sizeof(zfs_mirror_msg_mirrordata_header_t),
        CLUSTER_SAN_MSGTYPE_ZFS_MIRROR, 0, B_TRUE, 1);
    kmem_free(header, sizeof(zfs_mirror_msg_mirrordata_header_t));
    cluster_san_hostinfo_rele(cshi);

    if (data_type == MIRROR_DATA_UNALIGNED) {
        atomic_add_64(&zfs_mirror_mac_port->tx_nonali_data_frames, 1);
        if (ret == -2) {
            atomic_add_64(&zfs_mirror_mac_port->tx_nonali_timeout_frames, 1);
        }
    } else {
        atomic_add_64(&zfs_mirror_mac_port->tx_ali_data_frames, 1);
        if (ret == -2) {
            atomic_add_64(&zfs_mirror_mac_port->tx_ali_timeout_frames, 1);
        }
    }

    if (ret != 0) {
        ret = 1;
    }

    return (ret);
}

int
zfs_mirror_meta(znode_t *zp, itx_t *itx, dmu_tx_t *tx)
{
    int err = 0;
    dnode_t	*dn = NULL;
    dmu_buf_t	*zdb = NULL;
    dmu_buf_impl_t	*db = NULL;
    uint64_t spa_id = 0;
    uint64_t os_id = 0;
    uint64_t object_id = 0;
    char *data = NULL;
    uint64_t len = 0;
    uint64_t txg = 0;
    zfs_mirror_data_type_t data_type;

    zdb = sa_get_db(zp->z_sa_hdl);
    db = (dmu_buf_impl_t *)zdb;
    DB_DNODE_ENTER(db);
    dn = DB_DNODE(db);
    object_id = dn->dn_object;
    DB_DNODE_EXIT(db);

    data_type = MIRROR_DATA_META_ALIGNED;
    spa_id = spa_guid(dmu_objset_spa(ZTOZSB(zp)->z_os));
    os_id = ZTOZSB(zp)->z_os->os_dsl_dataset->ds_object;
    data = (char *)&itx->itx_lr;
    len = itx->itx_lr.lrc_reclen;
    txg = tx->tx_txg;

    if (zfs_mirror_hold_to_tx() != 0) {
        return (1);
    }

    err = zfs_mirror_write_data_msg(spa_id, os_id, object_id, 0,
        data, 0, len, txg, data_type, NULL);
    zfs_mirror_rele();

    return (err);
}

static void
zfs_mirror_log_list_worker_init(void)
{
    zfs_mirror_mac_port->mirror_log_clean =
        taskq_create("mirror_log_clean", max_ncpus, minclsyspri,
        2, zfs_mirror_log_clean_max_tasks, TASKQ_PREPOPULATE);
}

static void
zfs_mirror_log_list_worker_fini(void)
{
    if (zfs_mirror_mac_port->mirror_log_clean)
        taskq_destroy(zfs_mirror_mac_port->mirror_log_clean);
}

static void
zfs_mirror_destroy_aligned_cache(mirror_aligned_cache_t *aligned_cache)
{
    mirror_cache_txg_list_t *txg_list;
    int cnt = 0;

    while (!refcount_is_zero(&aligned_cache->refcount)) {
        cnt++;
        cmn_err(CE_WARN, "wait aligned_cache release, cnt:%d", cnt);
        delay(drv_usectohz((clock_t)1000000));
    }
    while ((txg_list = list_head(&aligned_cache->aligned_list_txg)) != NULL) {
        list_remove(&aligned_cache->aligned_list_txg, txg_list);
        list_remove(&aligned_cache->aligned_list_time, txg_list);
        zfs_mirror_aligned_txg_list_free(txg_list);
    }
    list_destroy(&aligned_cache->aligned_list_txg);
    list_destroy(&aligned_cache->aligned_list_time);
    mutex_destroy(&aligned_cache->lock);
    kmem_free(aligned_cache, sizeof(mirror_aligned_cache_t));
}

static void
zfs_mirror_destroy_unaligned_cache(mirror_unaligned_cache_t *unaligned_cache)
{
    zfs_mirror_nonali_hash_t *hash_blk;
    int cnt = 0;

    while (!refcount_is_zero(&unaligned_cache->refcount)) {
        cnt++;
        cmn_err(CE_WARN, "wait unaligned_cache release, cnt:%d", cnt);
        delay(drv_usectohz((clock_t)1000000));
    }
    while ((hash_blk = list_head(&unaligned_cache->unaligned_list_time)) != NULL) {
        list_remove(&unaligned_cache->unaligned_list_time, hash_blk);
    }
    mod_hash_destroy_hash(unaligned_cache->unaligned_modhash);
    list_destroy(&unaligned_cache->unaligned_list_time);
    mutex_destroy(&unaligned_cache->lock);
    kmem_free(unaligned_cache, sizeof(mirror_unaligned_cache_t));
}

static void
zfs_mirror_spa_os_hash_valdtor(mod_hash_val_t val)
{
    list_t *spa_os_list = (list_t *)val;
    mirror_spa_os_t *spa_os;

    ASSERT(MUTEX_HELD(&zfs_mirror_mac_port->spa_os_lock));
    while ((spa_os = list_head(spa_os_list)) != NULL) {
        list_remove(spa_os_list, spa_os);
        if (spa_os->aligned_cache != NULL) {
            zfs_mirror_destroy_aligned_cache(spa_os->aligned_cache);
        }
        if (spa_os->unaligned_cache != NULL) {
            zfs_mirror_destroy_unaligned_cache(spa_os->unaligned_cache);
        }
        kmem_free(spa_os, sizeof(mirror_spa_os_t));
    }
    list_destroy(spa_os_list);
    kmem_free(spa_os_list, sizeof(list_t));
}

static void
zfs_mirror_cache_list_worker_init(void)
{
    uint_t kval;

    mutex_init(&zfs_mirror_mac_port->spa_os_lock, NULL, MUTEX_DRIVER, NULL);

    kval = mod_hash_iddata_gen(zfs_mirror_spa_os_hash_size);
    zfs_mirror_mac_port->spa_os_modhash = mod_hash_create_extended("zfs_mirror_spa_os_hash",
        zfs_mirror_spa_os_hash_size, mod_hash_null_keydtor,
        zfs_mirror_spa_os_hash_valdtor, zfs_mirror_mod_hash_byid, (void *)(uintptr_t)kval,
        zfs_mirror_mod_hash_idkey_cmp, KM_SLEEP);

}

static void
zfs_mirror_cache_list_worker_fini(void)
{
    mutex_enter(&zfs_mirror_mac_port->spa_os_lock);
    mod_hash_destroy_hash(zfs_mirror_mac_port->spa_os_modhash);
    mutex_exit(&zfs_mirror_mac_port->spa_os_lock);
    mutex_destroy(&zfs_mirror_mac_port->spa_os_lock);

}

void
zfs_mirror_log_clean(objset_t *os,
    uint64_t spa_id, uint64_t os_id, uint64_t txg,
    uint64_t blk_id, zfs_mirror_data_type_t data_type)
{
    log_clear_para_t *para = NULL;
    task_func_t *clear_func;
    uint64_t txg_id = txg & TXG_MASK;
    dbuf_mirror_io_t *mirror_io;

    if (zfs_mirror_hold_to_tx() != 0) {
        /* clean os->os_mirror_io_list */
        if (data_type == MIRROR_DATA_UNALIGNED) {
            mutex_enter(&os->os_mirror_io_mutex[txg_id]);
            if (os->os_mirror_io_num[txg_id] != 0) {
                while (mirror_io = list_head(&os->os_mirror_io_list[txg_id])) {
                    list_remove(&os->os_mirror_io_list[txg_id], mirror_io);
                    zfs_mirror_destroy(mirror_io);
                }
                os->os_mirror_io_num[txg_id] = 0;
            }
            mutex_exit(&os->os_mirror_io_mutex[txg_id]);
        }
        return;
    }

    if (zfs_mirror_enable()) {
        para = kmem_zalloc(sizeof(log_clear_para_t), KM_SLEEP);
        para->spa_id = spa_id;
        para->os_id = os_id;
        para->txg = txg;
        para->blk_id = blk_id;
        para->blk_offset = UINT64_MAX;
        para->data_type = data_type;

        clear_func =  (task_func_t *)zfs_mirror_write_clean_msg;
        if (data_type == MIRROR_DATA_UNALIGNED) {
            os_mirror_blkptr_list_t *blkptr_array = NULL;
            blkptr_array = dmu_objset_clear_mirror_io(os, txg);
            if (blkptr_array == NULL) {
                kmem_free(para, sizeof(log_clear_para_t));
                zfs_mirror_rele();
                return;
            }
            para->para_data = blkptr_array;
        }

        if (taskq_dispatch(zfs_mirror_mac_port->mirror_log_clean,
            (task_func_t *)clear_func, para, TQ_NOSLEEP) == NULL) {
            cmn_err(CE_NOTE, "mirror log clean dispath failed, %d", data_type);
            clear_func(para);
        }
    }
    zfs_mirror_rele();
}

static void zfs_mirror_aligned_handle(void *arg)
{
    cs_rx_data_t *cs_data = arg;
    cluster_san_hostinfo_t *cshi = cs_data->cs_private;
    zfs_mirror_msg_mirrordata_header_t *header;
    mirror_cache_txg_list_t *txg_list;
    mirror_aligned_cache_t *aligned_cache;
    zfs_mirror_cache_data_t *cache_data;

    atomic_inc_64(&zfs_mirror_mac_port->rx_ali_data_frames);
    atomic_add_64(&zfs_mirror_mac_port->rs_ali_cache_size,
        cs_data->data_len);
    header = cs_data->ex_head;
    aligned_cache = zfs_mirror_hold_aligned_cache(header->spa_id,
        header->os_id, ZFS_MIRROR_HOLD_CREATE, cshi->hostid, FTAG);
    txg_list = list_head(&aligned_cache->aligned_list_txg);
    while (txg_list != NULL) {
        if (txg_list->cache_txg_list_txg == header->txg) {
            break;
        }
        txg_list = list_next(&aligned_cache->aligned_list_txg, txg_list);
    }
    cache_data = kmem_zalloc(sizeof(zfs_mirror_cache_data_t), KM_SLEEP);
    cache_data->cs_data = cs_data;
    if (txg_list == NULL) {
        txg_list = zfs_mirror_aligned_txg_list_alloc();
        ASSERT(txg_list != NULL);
        txg_list->cache_txg_list_txg = header->txg;
        txg_list->spa_id = header->spa_id;
        txg_list->os_id = header->os_id;
        txg_list->active_time = ddi_get_time();
        list_insert_tail(&txg_list->cache_txg_list, cache_data);
        list_insert_tail(&aligned_cache->aligned_list_time, txg_list);
        mirror_cache_list_insert_txg_sort(&aligned_cache->aligned_list_txg, txg_list);
    } else {
        txg_list->active_time = ddi_get_time();
        list_insert_tail(&txg_list->cache_txg_list, cache_data);
        /* hold the newest txg_list is the last one */
        list_remove(&aligned_cache->aligned_list_time, txg_list);
        list_insert_tail(&aligned_cache->aligned_list_time, txg_list);
    }
    zfs_mirror_rele_aligned_cache(aligned_cache, FTAG);
}

static void
zfs_mirror_unaligned_handle (void *arg)
{
    cs_rx_data_t *cs_data = arg;
    cluster_san_hostinfo_t *cshi = cs_data->cs_private;
    zfs_mirror_msg_mirrordata_header_t *header;
    zfs_mirror_nonali_hash_t *hash_blk;
    mirror_unaligned_cache_t *unaligned_cache;
    zfs_mirror_cache_data_t *cache_data;

    atomic_inc_64(&zfs_mirror_mac_port->rx_nonali_data_frames);
    atomic_add_64(&zfs_mirror_mac_port->rs_nonali_cache_size,
        cs_data->data_len);
    header = cs_data->ex_head;
    unaligned_cache = zfs_mirror_hold_unaligned_cache(
        header->spa_id, header->os_id, ZFS_MIRROR_HOLD_CREATE,
        cshi->hostid, FTAG);
    hash_blk = zfs_mirror_find_hash(unaligned_cache, header->object_id,
        header->blk_id, header->blk_offset);
    cache_data = kmem_zalloc(sizeof(zfs_mirror_cache_data_t), KM_SLEEP);
    cache_data->cs_data = cs_data;
    if (hash_blk == NULL) {
        hash_blk = zfs_mirror_create_hash_member(cache_data);
        zfs_mirror_insert_hash(unaligned_cache, hash_blk);
    } else {
        list_insert_tail(&hash_blk->hash_nonali_blk_list, cache_data);
        hash_blk->active_time = ddi_get_time();
        list_remove(&unaligned_cache->unaligned_list_time, hash_blk);
        list_insert_tail(&unaligned_cache->unaligned_list_time, hash_blk);
    }
    zfs_mirror_rele_unaligned_cache(unaligned_cache, FTAG);
}

void
zfs_mirror_rx_cb(cs_rx_data_t *cs_data, void *arg)
{
    zfs_mirror_msg_header_t *msg_head;
    msg_head = cs_data->ex_head;
#ifdef LC_DEBUG
	if (msg_head->msg_type != ZFS_MIRROR_SPA_TXG)
		cmn_err(CE_WARN, "recv mirror msg [msg_type = %d]", msg_head->msg_type);
#endif
    switch(msg_head->msg_type) {
        case ZFS_MIRROR_DATA:
        case ZFS_MIRROR_META_DATA:
            taskq_dispatch(zfs_mirror_mac_port->tq_mirror_aligned_handle,
                zfs_mirror_aligned_handle, (void*)cs_data, TQ_SLEEP);
            break;
        case ZFS_MIRROR_DATA_UNALIGNED:
            taskq_dispatch(zfs_mirror_mac_port->tq_mirror_nonaligned_handle,
                zfs_mirror_unaligned_handle, (void*)cs_data, TQ_SLEEP);
            break;
        case ZFS_MIRROR_CLEAR_ALIGNED:
            taskq_dispatch(zfs_mirror_mac_port->tq_mirror_aligned_handle,
                zfs_mirror_clean_aligned, (void*)cs_data, TQ_SLEEP);
            break;
        case ZFS_MIRROR_CLEAR_NONALIGNED:
            taskq_dispatch(zfs_mirror_mac_port->tq_mirror_nonaligned_handle,
                zfs_mirror_clean_unaligned, (void*)cs_data, TQ_SLEEP);
            break;
        case ZFS_MIRROR_GET_LAST_SYNCED_TXG:
            taskq_dispatch(zfs_mirror_mac_port->mirror_watch_tq,
                zfs_mirror_get_last_synced_txg, (void *)cs_data, TQ_SLEEP);
            break;
        case ZFS_MIRROR_REPLY_LAST_SYNCED_TXG:
            taskq_dispatch(zfs_mirror_mac_port->mirror_watch_tq,
                zfs_mirror_rcv_last_synced_txg, (void *)cs_data, TQ_SLEEP);
            break;
        case ZFS_MIRROR_IS_NONALIGNED_ACTIVE:
            taskq_dispatch(zfs_mirror_mac_port->mirror_watch_tq,
                zfs_mirror_is_unaligned_actived, (void *)cs_data, TQ_SLEEP);
            break;
        case ZFS_MIRROR_REPLY_NONALIGNED_ACTIVE:
            taskq_dispatch(zfs_mirror_mac_port->mirror_watch_tq,
                zfs_mirror_handle_unaligned_actived, (void *)cs_data, TQ_SLEEP);
            break;
        case ZFS_MIRROR_SPA_TXG:
            taskq_dispatch(zfs_mirror_mac_port->tq_check_spa_hung,
                zfs_mirror_rx_spa_txg_handle, (void *)cs_data, TQ_SLEEP);
            break;
	case ZFS_MIRROR_SPEED_TEST:
		csh_rx_data_free(cs_data, B_TRUE);
		/* FIXME */
		break;
        default:
            break;
    }
}

zfs_mirror_host_node_t *
zfs_mirror_host_create(
    cluster_san_hostinfo_t *cshi)
{
    zfs_mirror_host_node_t *mirror_host = NULL;
    mirror_host = kmem_zalloc(sizeof(zfs_mirror_host_node_t), KM_SLEEP);
    mirror_host->hostid = cshi->hostid;
    mirror_host->cshi = cshi;
    cluster_san_hostinfo_hold(cshi);
    return (mirror_host);
}

void
zfs_mirror_host_destroy(zfs_mirror_host_node_t *mirror_host)
{
    zfs_mirror_spa_txg_state_t *txg_state;
    nvpair_t *elem;
    uint64_t temp64;

    if (mirror_host == NULL) {
        return;
    }
    if (mirror_host->spa_txg_state != NULL) {
        elem = NULL;
        while ((elem = nvlist_next_nvpair(mirror_host->spa_txg_state, elem))
            != NULL) {
            nvpair_value_uint64(elem, &temp64);
            txg_state = (zfs_mirror_spa_txg_state_t *)(uintptr_t)temp64;
            kmem_free(txg_state, sizeof(zfs_mirror_spa_txg_state_t));
        }

        nvlist_free(mirror_host->spa_txg_state);
        mirror_host->spa_txg_state = NULL;
    }
    if (mirror_host->cshi != NULL) {
        cluster_san_hostinfo_rele(mirror_host->cshi);
    }
    kmem_free(mirror_host, sizeof(zfs_mirror_host_node_t));
}

zfs_mirror_host_node_t *
zfs_mirror_host_insert (
    list_t *host_list, cluster_san_hostinfo_t *cshi)
{
    zfs_mirror_host_node_t *cur;
    zfs_mirror_host_node_t *mirror_host = NULL;

    cur = list_head(host_list);
    while (cur != NULL) {
        if (cshi->hostid < cur->hostid) {
            mirror_host = zfs_mirror_host_create(cshi);
            list_insert_before(host_list, cur, mirror_host);
            break;
        }

        if (cshi->hostid == cur->hostid) {
            if (cur->cshi == NULL) {
                cur->cshi = cshi;
                cluster_san_hostinfo_hold(cshi);
            }
            mirror_host = cur;
            break;
        }
        cur = list_next(host_list, cur);
    }
    if (cur == NULL) {
        mirror_host = zfs_mirror_host_create(cshi);
        list_insert_tail(host_list, mirror_host);
    }

    return (mirror_host);
}

zfs_mirror_host_node_t *
zfs_mirror_host_remove (
    list_t *host_list, cluster_san_hostinfo_t *cshi)
{
    zfs_mirror_host_node_t *cur;
    zfs_mirror_host_node_t *next;

    cur = list_head(host_list);
    while (cur != NULL) {
        next = list_next(host_list, cur);
        if (cur->hostid == cshi->hostid) {
            list_remove(host_list, cur);
            break;
        }
        cur = next;
    }

    return (cur);
}

zfs_mirror_host_node_t *
zfs_mirror_host_down(cluster_san_hostinfo_t *cshi)
{
    zfs_mirror_host_node_t *mirror_host;

    mirror_host = zfs_mirror_host_find(cshi->hostid);
    if (mirror_host != NULL) {
        if (mirror_host->cshi != NULL) {
            cluster_san_hostinfo_rele(mirror_host->cshi);
            mirror_host->cshi = NULL;
        }
    }

    return (mirror_host);
}

void
zfs_mirror_cs_link_evt_cb(void *private,
    cts_link_evt_t link_evt, void *arg)
{
    cluster_san_hostinfo_t *cshi = private;
    zfs_mirror_host_node_t *mirror_host;
    zfs_mirror_host_node_t *failover_host;
    int ret;

    switch(link_evt) {
        case LINK_EVT_DOWN_TO_UP:
            cmn_err(CE_NOTE, "mirror host link up ,host: %s, %d",
                cshi->hostname, cshi->hostid);
            rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_WRITER);
            mirror_host = zfs_mirror_host_insert(
                &zfs_mirror_mac_port->mirror_host_lists, cshi);
            if (zfs_mirror_mac_port->mirror_permanent_hostid == mirror_host->hostid) {
                ret = cluster_change_failover_host(cshi);
                if (ret == 0) {
                    zfs_mirror_mac_port->mirror_failover_host = mirror_host;
                    zfs_mirror_mac_port->mirror_cur_host = mirror_host;
                }
            } else {
                if (zfs_mirror_mac_port->mirror_cur_host == NULL) {
                    if (zfs_mirror_mac_port->mirror_permanent_hostid == 0) {
                        failover_host =	zfs_mirror_select_host();
                        if (failover_host != NULL) {
                            if (failover_host != zfs_mirror_mac_port->mirror_failover_host) {
                                ret = cluster_change_failover_host(failover_host->cshi);
                                if (ret == 0) {
                                    zfs_mirror_mac_port->mirror_failover_host = failover_host;
                                }
                            }
                        } else {
                            cluster_change_failover_host(NULL);
                        }
                    }
                }
            }
            rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);
            break;
        case LINK_EVT_UP_TO_DOWN:
            cmn_err(CE_NOTE, "mirror host link down ,host: %s, %d",
                cshi->hostname, cshi->hostid);
            rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_WRITER);
            mirror_host = zfs_mirror_host_down(cshi);
            if (zfs_mirror_mac_port->mirror_cur_host == mirror_host) {
                zfs_mirror_mac_port->mirror_cur_host = NULL;
            }
            if (zfs_mirror_mac_port->mirror_failover_host == mirror_host) {
                zfs_mirror_mac_port->mirror_failover_host = NULL;
                if (zfs_mirror_mac_port->mirror_permanent_hostid == 0) {
                    failover_host =	zfs_mirror_select_host();
                    if (failover_host != NULL) {
                        ret = cluster_change_failover_host(failover_host->cshi);
                        if (ret == 0) {
                            zfs_mirror_mac_port->mirror_failover_host = failover_host;
                        }
                    } else {
                        cluster_change_failover_host(NULL);
                    }
                } else {
                    cluster_change_failover_host(NULL);
                }
            }
            rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);
            break;
        default:
            break;
    }
}

uint_t
zfs_mirror_walk_host_cb(cluster_san_hostinfo_t *cshi, void *arg)
{
    zfs_mirror_host_node_t *mirror_host;
    int ret;

    if (cshi->link_state == CTS_LINK_UP) {
        rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_WRITER);
        mirror_host = zfs_mirror_host_insert(
            &zfs_mirror_mac_port->mirror_host_lists, cshi);
        if (zfs_mirror_mac_port->mirror_permanent_hostid == mirror_host->hostid) {
            ret = cluster_change_failover_host(cshi);
            if (ret == 0) {
                zfs_mirror_mac_port->mirror_failover_host = mirror_host;
                zfs_mirror_mac_port->mirror_cur_host = mirror_host;
            }
        }
        rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);
    }

    return (CS_WALK_CONTINUE);
}

static void
zfs_mirror_host_init(uint32_t mirror_hostid)
{
    zfs_mirror_host_node_t *failover_host;
    int ret;

    rw_init(&zfs_mirror_mac_port->mirror_host_rwlock, NULL, RW_DRIVER, NULL);
    list_create(&zfs_mirror_mac_port->mirror_host_lists,
        sizeof(zfs_mirror_host_node_t), offsetof(zfs_mirror_host_node_t, node));
    zfs_mirror_mac_port->mirror_local_host = kmem_zalloc(
        sizeof(zfs_mirror_host_node_t), KM_SLEEP);
    zfs_mirror_mac_port->mirror_local_host->hostid = zone_get_hostid(NULL);
    list_insert_head(&zfs_mirror_mac_port->mirror_host_lists,
        zfs_mirror_mac_port->mirror_local_host);
    zfs_mirror_mac_port->mirror_permanent_hostid = mirror_hostid;
    csh_link_evt_hook_add(zfs_mirror_cs_link_evt_cb, NULL);
    cluster_san_host_walk(zfs_mirror_walk_host_cb, NULL);

    rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_WRITER);
    if (zfs_mirror_mac_port->mirror_failover_host == NULL) {
        if (zfs_mirror_mac_port->mirror_permanent_hostid == 0) {
            failover_host =	zfs_mirror_select_host();
            if (failover_host != NULL) {
                ret = cluster_change_failover_host(failover_host->cshi);
                if (ret == 0) {
                    zfs_mirror_mac_port->mirror_failover_host = failover_host;
                }
            }
        }
    }
    rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);
}

static void
zfs_mirror_host_fini(void)
{
    zfs_mirror_host_node_t *mirror_host;
    csh_link_evt_hook_remove(zfs_mirror_cs_link_evt_cb);
    rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_WRITER);
    zfs_mirror_mac_port->mirror_local_host = NULL;
    zfs_mirror_mac_port->mirror_permanent_hostid = 0;
    while ((mirror_host = list_remove_head(&zfs_mirror_mac_port->mirror_host_lists)) != NULL) {
        zfs_mirror_host_destroy(mirror_host);
    }
    rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);

    rw_destroy(&zfs_mirror_mac_port->mirror_host_rwlock);
    list_destroy(&zfs_mirror_mac_port->mirror_host_lists);

    cluster_change_failover_host(NULL);
}

int
zfs_mirror_tx_speed_data(char *buf, size_t len)
{
    cluster_san_hostinfo_t *cshi = NULL;
    zfs_mirror_msg_header_t msg_head;
    int ret;

    rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_READER);
    if (zfs_mirror_mac_port->mirror_failover_host != NULL) {
        cshi = zfs_mirror_mac_port->mirror_failover_host->cshi;
    }
    if (cshi != NULL) {
        cluster_san_hostinfo_hold(cshi);
    }
    rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);

    msg_head.msg_type = ZFS_MIRROR_SPEED_TEST;
    ret = cluster_san_host_send(cshi, (void *)buf, len, &msg_head,
		    sizeof(zfs_mirror_msg_header_t),
		    CLUSTER_SAN_MSGTYPE_ZFS_MIRROR, 0, B_FALSE, 0);
    cluster_san_hostinfo_rele(cshi);

    return ret;
}

static void
zfs_mirror_tx_spa_txg(void *arg)
{
    cluster_san_hostinfo_t *cshi = NULL;
    zfs_mirror_msg_header_t msg_head;
    spa_t *spa;
    nvlist_t *nvl;
    size_t buflen;
    char *buf;

    /* get local spa's txg */
    spa = NULL;
    nvl = NULL;
    mutex_enter(&spa_namespace_lock);
    while ((spa = spa_next(spa)) != NULL) {
        if (strncmp(spa->spa_name, ETC_VAR_SYS_POOL_NAME, MAXNAMELEN) == 0) {
            continue;
        }
        if (spa->spa_sync_on != B_TRUE) {
            continue;
        }
        if (nvl == NULL) {
            VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME,
                KM_SLEEP) == 0);
        }
        nvlist_add_uint64(nvl, spa_name(spa), spa_last_synced_txg(spa));
    }
    mutex_exit(&spa_namespace_lock);

    rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_READER);
    if (zfs_mirror_mac_port->mirror_failover_host != NULL) {
        cshi = zfs_mirror_mac_port->mirror_failover_host->cshi;
    }
    if (cshi != NULL) {
        cluster_san_hostinfo_hold(cshi);
    }
    rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);

    if (nvl != NULL) {
        if (cshi == NULL) {
            nvlist_free(nvl);
            return;
        }
        /* send local spa's txg to remote */
        VERIFY(nvlist_size(nvl, &buflen, NV_ENCODE_XDR) == 0);
        if (buflen != 0) {
            buf = kmem_alloc(buflen, KM_SLEEP);
            VERIFY(nvlist_pack(nvl, &buf, &buflen, NV_ENCODE_XDR,
                KM_SLEEP) == 0);
            msg_head.msg_type = ZFS_MIRROR_SPA_TXG;
            cluster_san_host_send(cshi, buf, buflen, &msg_head,
                sizeof(zfs_mirror_msg_header_t), CLUSTER_SAN_MSGTYPE_ZFS_MIRROR,
                0, B_FALSE, 0);
            kmem_free(buf, buflen);
        }
        nvlist_free(nvl);
        cluster_san_hostinfo_rele(cshi);
    } else {
        if (cshi != NULL) {
            msg_head.msg_type = ZFS_MIRROR_SPA_TXG;
            cluster_san_host_send(cshi, NULL, 0, &msg_head,
                sizeof(zfs_mirror_msg_header_t), CLUSTER_SAN_MSGTYPE_ZFS_MIRROR,
                0, B_FALSE, 0);
            cluster_san_hostinfo_rele(cshi);
        }
    }
}

static void
zfs_mirror_cancel_check_spa_txg_impl(void *arg)
{
    uint32_t hostid = (uint32_t)(uintptr_t)arg;
    zfs_mirror_host_node_t *mirror_host;
    nvpair_t *elem;
    uint64_t temp64;
    zfs_mirror_spa_txg_state_t *txg_state;

    rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_WRITER);
    mirror_host = zfs_mirror_host_find(hostid);
    if (mirror_host == NULL) {
        rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);
        return;
    }
    if (mirror_host->spa_txg_state != NULL) {
        elem = NULL;
        while ((elem = nvlist_next_nvpair(mirror_host->spa_txg_state, elem))
            != NULL) {
            nvpair_value_uint64(elem, &temp64);
            txg_state = (zfs_mirror_spa_txg_state_t *)(uintptr_t)temp64;
            kmem_free(txg_state, sizeof(zfs_mirror_spa_txg_state_t));
        }

        nvlist_free(mirror_host->spa_txg_state);
        mirror_host->spa_txg_state = NULL;
    }

    rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);

}

void
zfs_mirror_cancel_check_spa_txg(uint32_t hostid)
{
    int ret;
    ret = zfs_mirror_hold();
    if (ret != 0) {
        return;
    }
    taskq_dispatch(zfs_mirror_mac_port->tq_check_spa_hung,
        zfs_mirror_cancel_check_spa_txg_impl,
        (void *)(uintptr_t)hostid, TQ_SLEEP);
    zfs_mirror_rele();
}

static void
zfs_mirror_rx_spa_txg_handle(void *arg)
{
    cs_rx_data_t *cs_data = arg;
    cluster_san_hostinfo_t *cshi = cs_data->cs_private;
    zfs_mirror_host_node_t *mirror_host;
    nvlist_t *nvl = NULL;
    zfs_mirror_spa_txg_state_t *txg_state;
    nvpair_t *elem;
    uint64_t temp64;
    char *spa_name;
    uint64_t spa_txg;
    uint64_t cur_time;
    int is_hung = 1;
    int ret;

    rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_READER);
    if (cshi->need_failover == 1) {
        if ((cs_data->data != NULL) && (cs_data->data_len != 0)) {
            nvlist_unpack(cs_data->data, cs_data->data_len, &nvl, KM_SLEEP);
        }
    }

    mirror_host = zfs_mirror_host_find(cshi->hostid);
    if (mirror_host == NULL) {
        rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);
        if (nvl != NULL) {
            nvlist_free(nvl);
        }
        csh_rx_data_free(cs_data, B_TRUE);
        return;
    }

    if (nvl == NULL) {
        if (mirror_host->spa_txg_state != NULL) {
            elem = NULL;
            while ((elem = nvlist_next_nvpair(mirror_host->spa_txg_state, elem))
                != NULL) {
                nvpair_value_uint64(elem, &temp64);
                txg_state = (zfs_mirror_spa_txg_state_t *)(uintptr_t)temp64;
                kmem_free(txg_state, sizeof(zfs_mirror_spa_txg_state_t));
            }

            nvlist_free(mirror_host->spa_txg_state);
            mirror_host->spa_txg_state = NULL;
        }

        rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);
        csh_rx_data_free(cs_data, B_TRUE);
        return;
    }

    cur_time = ddi_get_lbolt64();
    elem = NULL;
    while ((elem = nvlist_next_nvpair(nvl, elem)) != NULL) {
        spa_name = nvpair_name(elem);
        nvpair_value_uint64(elem, &spa_txg);
        txg_state = NULL;
        if (mirror_host->spa_txg_state != NULL) {
            ret = nvlist_lookup_uint64(mirror_host->spa_txg_state, spa_name,
                &temp64);
            if (ret != 0) {
                txg_state = NULL;
            } else {
                txg_state = (zfs_mirror_spa_txg_state_t *)(uintptr_t)temp64;
            }
        } else {
            nvlist_alloc(&mirror_host->spa_txg_state,
                NV_UNIQUE_NAME, KM_SLEEP);
        }

        if (txg_state == NULL) {
            txg_state = kmem_zalloc(sizeof(zfs_mirror_spa_txg_state_t),
                KM_SLEEP);
            nvlist_add_uint64(mirror_host->spa_txg_state, spa_name,
                (uint64_t)(uintptr_t)txg_state);
        }
        if (txg_state->last_txg != spa_txg) {
            txg_state->last_txg = spa_txg;
            txg_state->last_txg_time = cur_time;
            is_hung = 0;
        } else {
            if ((cur_time - txg_state->last_txg_time) >
                zfs_mirror_spa_hung_hz) {
                cmn_err(CE_WARN, "remote host(%d)'s pool:%s maybe hung at txg 0x%"PRIx64,
                    cshi->hostid, spa_name, spa_txg);
            } else {
                is_hung = 0;
            }
        }
    }

    if (mirror_host->spa_txg_state != NULL) {
        elem = NULL;
        elem = nvlist_next_nvpair(mirror_host->spa_txg_state, elem);
        while (elem != NULL) {
            spa_name = nvpair_name(elem);
            nvpair_value_uint64(elem, &temp64);
            txg_state = (zfs_mirror_spa_txg_state_t *)(uintptr_t)temp64;
            elem = nvlist_next_nvpair(mirror_host->spa_txg_state, elem);

            ret = nvlist_lookup_uint64(nvl, spa_name, &temp64);
            if (ret != 0) {
                nvlist_remove(mirror_host->spa_txg_state, spa_name,
                    DATA_TYPE_UINT64);
                kmem_free(txg_state, sizeof(zfs_mirror_spa_txg_state_t));
            } else {
                nvlist_remove(nvl, spa_name, DATA_TYPE_UINT64);
            }
        }
    }

    rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);
    nvlist_free(nvl);
#if 0
    if (is_hung == 1) {
        phostid = kmem_zalloc(sizeof(uint32_t), KM_SLEEP);
        *phostid = cshi->hostid;
        zfs_notify_clusterd(EVT_SPA_REMOTE_HUNG, (char *)phostid,
            sizeof(uint32_t));
    }
#endif
    csh_rx_data_free(cs_data, B_TRUE);
}

int
zfs_mirror_get_updated_spa(uint32_t hostid, nvlist_t **nv_ptr)
{
    zfs_mirror_host_node_t *mirror_host;
    nvlist_t *nvl = NULL;
    int ret;

    ret = zfs_mirror_hold();
    if (ret != 0) {
        return (ret);
    }
    rw_enter(&zfs_mirror_mac_port->mirror_host_rwlock, RW_READER);
    mirror_host = zfs_mirror_host_find(hostid);
    if (mirror_host == NULL) {
        rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);
        *nv_ptr = NULL;
        return (0);
    }
    if (mirror_host->spa_txg_state != NULL) {
        VERIFY(nvlist_dup(mirror_host->spa_txg_state, &nvl, 0) == 0);
    }
    rw_exit(&zfs_mirror_mac_port->mirror_host_rwlock);

    if (nvl == NULL) {
        cmn_err(CE_WARN,"get host(%d)'s updated pool null",
            hostid);
    }
    *nv_ptr = nvl;

    return (ret);
}

static void
zfs_mirror_check_spa_hung_init(void)
{
    zfs_mirror_spa_hung_hz = drv_usectohz(ZFS_MIRROR_SPA_HUNG_TIME);
    zfs_mirror_mac_port->tq_tx_spa_txg = taskq_create("tq_tx_spa_txg",
        1, minclsyspri, 1, INT_MAX, TASKQ_PREPOPULATE);
    zfs_mirror_mac_port->tq_check_spa_hung = taskq_create("tq_check_spa_hung",
        1, minclsyspri, 1, 1, TASKQ_PREPOPULATE);
}

static void
zfs_mirror_check_spa_hung_fini(void)
{
    taskq_destroy(zfs_mirror_mac_port->tq_tx_spa_txg);
    taskq_destroy(zfs_mirror_mac_port->tq_check_spa_hung);
}

int
zfs_mirror_init(uint32_t mirror_hostid)
{
    uint_t kval;

    if (zfs_mirror_mac_port != NULL)
        return (-1);/* already intialized */

    zfs_mirror_mac_initialized = B_FALSE;

    cmn_err(CE_WARN, "initialize mirror host:%d", mirror_hostid);
    zfs_mirror_mac_port = kmem_zalloc(sizeof(zfs_mirror_mac_t), KM_SLEEP);

    zfs_mirror_cache_buf_init();

    zfs_mirror_log_list_worker_init();
    zfs_mirror_cache_list_worker_init();

    /* cache nonaligned mirror_io data */
    mutex_init(&zfs_mirror_mac_port->mirror_io_list_mtx, NULL, MUTEX_DEFAULT, NULL);
    kval = mod_hash_iddata_gen(zfs_mirror_spa_os_hash_size);
    zfs_mirror_mac_port->mirror_io_modhash = mod_hash_create_extended(
        "zfs_mirror_mirror_io_hash",
        zfs_mirror_spa_os_hash_size, mod_hash_null_keydtor,
        zfs_mirror_os_io_hash_valdtor, zfs_mirror_mod_hash_byid, (void *)(uintptr_t)kval,
        zfs_mirror_mod_hash_idkey_cmp, KM_SLEEP);
    zfs_mirror_mac_port->mirror_io_cnt = 0;

    zfs_mirror_mac_port->tq_mirror_aligned_handle =
        taskq_create("tq_mirror_aligned_handle", zfs_mirror_aligned_tq_nthread,
        minclsyspri, zfs_mirror_aligned_tq_nthread, INT_MAX, TASKQ_PREPOPULATE);
    zfs_mirror_mac_port->tq_mirror_nonaligned_handle =
        taskq_create("tq_mirror_nonaligned_handle", zfs_mirror_nonaligned_tq_nthread,
        minclsyspri, zfs_mirror_nonaligned_tq_nthread, INT_MAX, TASKQ_PREPOPULATE);

    zfs_mirror_host_init(mirror_hostid);
    zfs_mirror_check_spa_hung_init();

    csh_rx_hook_add(CLUSTER_SAN_MSGTYPE_ZFS_MIRROR, zfs_mirror_rx_cb, NULL);

    zfs_mirror_stats_init();

    zfs_mirror_watchdog_init();

    zfs_mirror_mac_initialized = B_TRUE;

    cmn_err(CE_NOTE, "end of initialize port mirror");
    return (0);
}

int
zfs_mirror_fini(void)
{
    int retry = 0;

    zfs_mirror_mac_initialized = B_FALSE;

    if (zfs_mirror_mac_port == NULL)
        return (-1);/* not intialized */

    cmn_err(CE_NOTE, "%s: Wait for all mirror user exit", __func__);
    while((zfs_mirror_ref != 0) &&
        (retry < 10)) {
        delay(drv_usectohz((clock_t)1000000));
        retry++;
    }
    if (retry == 10) {
        cmn_err(CE_WARN, "%s, There were someone using mirror, busy!", __func__);
        goto failed;
    }

    /* wait mirror io cleaned */
    retry = 0;
    cmn_err(CE_NOTE, "%s: Wait for all mirror io destroyed", __func__);
    mutex_enter(&zfs_mirror_mac_port->mirror_io_list_mtx);
    while((zfs_mirror_mac_port->mirror_io_cnt != 0) &&
        (retry < 60)){
        mutex_exit(&zfs_mirror_mac_port->mirror_io_list_mtx);
        delay(drv_usectohz((clock_t)1000000));
        retry++;
        mutex_enter(&zfs_mirror_mac_port->mirror_io_list_mtx);
    }
    mutex_exit(&zfs_mirror_mac_port->mirror_io_list_mtx);

    if (retry == 60) {
        cmn_err(CE_WARN, "%s, There were some mirror io didn't destroyed!", __func__);
        goto failed;
    }

    csh_rx_hook_remove(CLUSTER_SAN_MSGTYPE_ZFS_MIRROR);

    zfs_mirror_watchdog_fini();
    zfs_mirror_check_spa_hung_fini();
    zfs_mirror_host_fini();

    taskq_destroy(zfs_mirror_mac_port->tq_mirror_aligned_handle);
    taskq_destroy(zfs_mirror_mac_port->tq_mirror_nonaligned_handle);

    zfs_mirror_log_list_worker_fini();

    zfs_mirror_cache_list_worker_fini();
    zfs_mirror_cache_buf_fini();

    mutex_destroy(&zfs_mirror_mac_port->mirror_io_list_mtx);
    mod_hash_destroy_hash(zfs_mirror_mac_port->mirror_io_modhash);

    if (zfs_mirror_mac_port->mirror_ks != NULL) {
        kmem_free(zfs_mirror_mac_port->mirror_ks->ks_data, sizeof(zfs_mirror_stat_t));
        kstat_delete((kstat_t *)zfs_mirror_mac_port->mirror_ks);
    }
    kmem_free(zfs_mirror_mac_port, sizeof(zfs_mirror_mac_t));
    zfs_mirror_mac_port = NULL;

    return (0);

failed:
    zfs_mirror_mac_initialized = B_TRUE;
    return (-2);/* busy */
}

int
zfs_mirror_hold(void)
{
    atomic_inc_64(&zfs_mirror_ref);
    if (zfs_mirror_mac_initialized == B_FALSE) {
        atomic_dec_64(&zfs_mirror_ref);
        return (-1);
    }

    return (0);
}

void
zfs_mirror_rele(void)
{
    atomic_dec_64(&zfs_mirror_ref);
}

int
zfs_mirror_hold_to_tx(void)
{
    atomic_inc_64(&zfs_mirror_ref);
    if (zfs_mirror_mac_initialized == B_FALSE) {
        atomic_dec_64(&zfs_mirror_ref);
        return (-1);
    }

    return (0);
}

boolean_t
zfs_mirror_enable(void)
{
    if (zfs_mirror_mac_port == NULL)
        return (B_FALSE);
    return (zfs_mirror_mac_initialized);
}

boolean_t
zfs_mirror_get_state(void)
{
    return (zfs_mirror_mac_initialized);
}

void
zfs_replay_worker(data_replay_para_t *para)
{
    objset_t *os;

    os = para->os;
    os->os_replay_data(os, para->data, para->object, para->offset, para->len);
    kmem_free(para, sizeof(data_replay_para_t));
}

void zfs_replay_meta_worker(meta_data_replay_para_t *meta_para)
{
    objset_t	*os = NULL;
    lr_t	*lrp = NULL;
    uint64_t	txtype = 0;
    int			err;
    int			retry = 0;
    int			retry_max = 3;

    os = meta_para->os;
    lrp = (lr_t*)meta_para->data;
    txtype = lrp->lrc_txtype;
    cmn_err(CE_NOTE,"txtype:(%"PRIu64")\n",txtype);
    err = (os->os_replay)[txtype](meta_para->usr_data, meta_para->data, (boolean_t)0);
    while( err ){
        cmn_err(CE_NOTE,"Meta Replay PHIL!!!\n");
        if ( retry++ >= retry_max ){
            err = (os->os_replay)[0](meta_para->usr_data, meta_para->data, (boolean_t)0);
            break;
        }
        err = (os->os_replay)[txtype](meta_para->usr_data, meta_para->data, (boolean_t)0);
    }
    #if 0
    kmem_free(meta_para->data, meta_para->len);
    #endif
    kmem_free(meta_para, sizeof(data_replay_para_t));
}

void zfs_replay_cache_data(objset_t *os,
    zfs_mirror_cache_data_t *cache_data)
{
    uint64_t offset;
    uint64_t total_len;
    uint64_t object_id;
    uint64_t blk_txg;
    boolean_t b_newer;
    data_replay_para_t *para;
    meta_data_replay_para_t	*meta_para = NULL;
    boolean_t b_meta_type = B_FALSE;
    zfs_mirror_msg_mirrordata_header_t *header =
        cache_data->cs_data->ex_head;

    object_id = header->object_id;
    blk_txg = header->txg;
    offset =  header->blk_offset;
    total_len = header->len;
    ASSERT(total_len == cache_data->cs_data->data_len);

    b_newer = dmu_data_newer(os, object_id, offset, blk_txg);
    if (b_newer) {
        if (header->msg_head.msg_type == ZFS_MIRROR_META_DATA) {
            b_meta_type = B_TRUE;
            meta_para = kmem_zalloc(sizeof(data_replay_para_t), KM_SLEEP);
            meta_para->data = cache_data->cs_data->data;
            meta_para->len = total_len;
            meta_para->os = os;
            mutex_enter(&os->os_user_ptr_lock);
            meta_para->usr_data = dmu_objset_get_user(os);
            mutex_exit(&os->os_user_ptr_lock);
        } else {
            para = kmem_zalloc(sizeof(data_replay_para_t), KM_SLEEP);
            para->data = cache_data->cs_data->data;
            para->object = object_id;
            para->offset = offset;
            para->len = total_len;
            para->os = os;
        }
    }

    if (b_newer) {
        if (b_meta_type == B_TRUE) {
            zfs_replay_meta_worker(meta_para);
        } else {
            zfs_replay_worker(para);
        }
    }
    if (header->msg_head.msg_type == ZFS_MIRROR_DATA) {
        atomic_inc_64(&zfs_mirror_mac_port->rx_ali_data_dec_frames);
        atomic_add_64(&zfs_mirror_mac_port->rs_ali_cache_size,
            0 - cache_data->cs_data->data_len);
    } else {
        atomic_inc_64(&zfs_mirror_mac_port->rx_nonali_data_dec_frames);
        atomic_add_64(&zfs_mirror_mac_port->rs_nonali_cache_size,
            0 - cache_data->cs_data->data_len);
    }
    csh_rx_data_free(cache_data->cs_data, B_TRUE);
    kmem_free(cache_data, sizeof(zfs_mirror_cache_data_t));
}

static void zfs_mirror_get_all_unalign_buf(objset_t *os)
{
    uint64_t spa_id = spa_guid(os->os_spa);
    uint64_t os_id = os->os_dsl_dataset->ds_object;
    mirror_unaligned_cache_t *unaligned_cache;
    list_t *blk_hash_list;
    zfs_mirror_nonali_hash_t *hash_blk;
    zfs_mirror_cache_data_t *cache_data;
    int ret;

    if (zfs_mirror_mac_port == NULL)
        return;

    unaligned_cache = zfs_mirror_hold_unaligned_cache(spa_id, os_id, 0, 0, FTAG);
    if (unaligned_cache == NULL) {
        return;
    }
    while ((hash_blk = list_remove_head(&unaligned_cache->unaligned_list_time)) != NULL) {
        ret = mod_hash_find(unaligned_cache->unaligned_modhash,
            (mod_hash_key_t)(uintptr_t)hash_blk->hash_key,
            (mod_hash_val_t *)&blk_hash_list);
        if (ret == 0) {
            list_remove(blk_hash_list, hash_blk);
            atomic_dec_64(&zfs_mirror_mac_port->rs_nonali_modhash_frames);
            if (list_is_empty(blk_hash_list)) {
                (void)mod_hash_remove(unaligned_cache->unaligned_modhash,
                    (mod_hash_key_t)(uintptr_t)hash_blk->hash_key,
                    (mod_hash_val_t *)&blk_hash_list);
                list_destroy(blk_hash_list);
                kmem_free(blk_hash_list, sizeof(list_t));
            }
        } else {
            cmn_err(CE_WARN, "%s: not find the blk_list in hash(hash_key:%"PRIx64")",
                __func__, hash_blk->hash_key);
        }

        while (cache_data = list_remove_head(&hash_blk->hash_nonali_blk_list)) {
            zil_data_record_t *data_record;
            zfs_mirror_msg_mirrordata_header_t *header =
                cache_data->cs_data->ex_head;
            data_record = kmem_zalloc(sizeof(zil_data_record_t), KM_SLEEP);
            data_record->txg = header->txg;
            data_record->gentime = header->tx_time;
            data_record->data_type = R_CACHE_DATA;
            data_record->data = (void *)cache_data;
            zil_insert_data_record_list_by_sort(os, data_record);
        }
        zfs_mirror_destroy_hash_member(hash_blk);
    }
    zfs_mirror_rele_unaligned_cache(unaligned_cache, FTAG);
}

static void zfs_mirror_get_align_buf(objset_t *os)
{
    mirror_cache_txg_list_t *txg_list;
    uint64_t synced_txg =  spa_first_txg(os->os_spa);
    uint64_t spa_id = spa_guid(os->os_spa);
    uint64_t os_id = os->os_dsl_dataset->ds_object;
    mirror_aligned_cache_t *aligned_cache;

    if (zfs_mirror_mac_port == NULL)
        return;

    aligned_cache = zfs_mirror_hold_aligned_cache(spa_id, os_id, 0, 0, FTAG);
    if (aligned_cache == NULL) {
        return;
    }
    while ((txg_list = list_head(&aligned_cache->aligned_list_txg)) != NULL) {
        list_remove(&aligned_cache->aligned_list_txg, txg_list);
        list_remove(&aligned_cache->aligned_list_time, txg_list);
        if (txg_list ->cache_txg_list_txg < synced_txg)  {
            zfs_mirror_aligned_txg_list_free(txg_list);
        } else {
            zfs_mirror_cache_data_t *cache_data;
            while ((cache_data = list_remove_head(&txg_list->cache_txg_list)) != NULL) {
                zil_data_record_t *data_record;
                zfs_mirror_msg_mirrordata_header_t *header =
                    cache_data->cs_data->ex_head;
                data_record = kmem_zalloc(sizeof(zil_data_record_t), KM_SLEEP);
                data_record->txg = header->txg;
                data_record->gentime = header->tx_time;
                data_record->data_type = R_CACHE_DATA;
                data_record->data = (void *)cache_data;
                zil_insert_data_record_list_by_sort(os, data_record);
            }
            mutex_destroy(&txg_list->cache_txg_list_mtx);
            list_destroy(&txg_list->cache_txg_list);
            kmem_cache_free(mirror_aligned_txg_cache, txg_list);
        }
    }
    zfs_mirror_rele_aligned_cache(aligned_cache, FTAG);
}

void zfs_mirror_get_all_buf(objset_t *os)
{
    taskq_wait(zfs_mirror_mac_port->tq_mirror_aligned_handle);
    zfs_mirror_get_align_buf(os);
    taskq_wait(zfs_mirror_mac_port->tq_mirror_nonaligned_handle);
    zfs_mirror_get_all_unalign_buf(os);
}

dbuf_mirror_io_t  *zfs_mirror_create(void)
{
    dbuf_mirror_io_t *mirror_io;

    if (!zfs_mirror_enable())
        return NULL;

    mirror_io = kmem_cache_alloc(zfs_mirror_mac_port->mm_io_hdr, KM_SLEEP);
    if (mirror_io == NULL)
        return NULL;

    bzero(mirror_io, sizeof (dbuf_mirror_io_t));

    mutex_init(&mirror_io->reply_hash_mtx, NULL, MUTEX_DEFAULT, NULL);

    return (mirror_io);
}

void
zfs_mirror_destroy(dbuf_mirror_io_t *mirror_io)
{
    if (mirror_io == NULL)
        return;
    if (mirror_io->data_type == MIRROR_DATA_UNALIGNED) {
        zfs_mirror_os_io_t *os_io;
        os_io = zfs_mirror_hold_os_io(mirror_io->spa_id, mirror_io->os_id, 0, FTAG);
        if (os_io != NULL) {
            zfs_mirror_remove_io(os_io, mirror_io);
            zfs_mirror_rele_os_io(os_io, FTAG);
        } else {
            cmn_err(CE_NOTE, "%s: os_io is NULL", __func__);
        }
    }

    mutex_destroy(&mirror_io->reply_hash_mtx);
    bzero(mirror_io, sizeof (dbuf_mirror_io_t));
    kmem_cache_free(zfs_mirror_mac_port->mm_io_hdr, mirror_io);
}

static void
zfs_mirror_insert_hash(mirror_unaligned_cache_t *unaligned_cache,
    zfs_mirror_nonali_hash_t *blk_hash)
{
    uint64_t hash_key;
    list_t *blk_hash_list = NULL;
    int ret;

    hash_key = blk_hash->hash_key;

    blk_hash->active_time = ddi_get_time();
    list_insert_tail(&unaligned_cache->unaligned_list_time, blk_hash);

    ret = mod_hash_find(unaligned_cache->unaligned_modhash,
        (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t *)&blk_hash_list);

    if (ret != 0) {
        blk_hash_list = kmem_zalloc(sizeof(list_t), KM_SLEEP);
        ASSERT(blk_hash_list != NULL);
        list_create(blk_hash_list, sizeof(zfs_mirror_nonali_hash_t),
            offsetof(zfs_mirror_nonali_hash_t, hash_list_node));
        list_insert_tail(blk_hash_list, blk_hash);
        (void) mod_hash_insert(unaligned_cache->unaligned_modhash,
            (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t)blk_hash_list);
    } else if (blk_hash_list != NULL) {
        list_insert_tail(blk_hash_list, blk_hash);
    }

    atomic_inc_64(&zfs_mirror_mac_port->rs_nonali_modhash_frames);
}

static int
zfs_mirror_clean_hash_blk(mirror_unaligned_cache_t *unaligned_cache,
    uint64_t object_id, uint64_t blk_id, uint64_t offset,
    uint64_t mirror_io_index, list_t *cache_blk_list, list_t *hash_blk_list)
{
    uint64_t hash_key;
    list_t *blk_hash_list = NULL;
    zfs_mirror_nonali_hash_t *blk_hash = NULL;
    zfs_mirror_cache_data_t *cache_data = NULL;
    int ret = 0;
    int cleaned = 0;

    hash_key = zfs_mirror_located_keygen(object_id, blk_id, offset);
    ret = mod_hash_find(unaligned_cache->unaligned_modhash,
        (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t *)&blk_hash_list);
    if ((ret == 0) && (blk_hash_list != NULL)) {
        for (blk_hash = list_head(blk_hash_list);
            blk_hash != NULL; blk_hash = list_next(blk_hash_list, blk_hash)) {
            if ((blk_hash->object_id == object_id)
                && (blk_hash->blk_id == blk_id)
                && (blk_hash->blk_offset == offset)) {
                break;
            }
        }
        if (blk_hash != NULL) {
            for (cache_data = list_head(&blk_hash->hash_nonali_blk_list);
                cache_data != NULL;
                cache_data = list_next(&blk_hash->hash_nonali_blk_list, cache_data)) {
                zfs_mirror_msg_mirrordata_header_t *header =
                    cache_data->cs_data->ex_head;
                if (header->index == mirror_io_index) {
                    list_remove(&blk_hash->hash_nonali_blk_list, cache_data);
                    list_insert_tail(cache_blk_list, cache_data);
                    cleaned++;
                    break;
                }
            }
            if (list_is_empty(&blk_hash->hash_nonali_blk_list)) {
                list_remove(&unaligned_cache->unaligned_list_time, blk_hash);
                list_remove(blk_hash_list, blk_hash);
                atomic_dec_64(&zfs_mirror_mac_port->rs_nonali_modhash_frames);
                list_insert_tail(hash_blk_list, blk_hash);
            }
        }
        if (list_is_empty(blk_hash_list)) {
            (void)mod_hash_remove(unaligned_cache->unaligned_modhash,
                (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t *)&blk_hash_list);
            list_destroy(blk_hash_list);
            kmem_free(blk_hash_list, sizeof(list_t));
        }
    }

    return (cleaned);
}

static zfs_mirror_nonali_hash_t *zfs_mirror_find_hash(
    mirror_unaligned_cache_t *unaligned_cache,
    uint64_t object_id, uint64_t blk_id, uint64_t blk_offset)
{
    int ret = 0;
    list_t *blk_hash_list = NULL;
    zfs_mirror_nonali_hash_t *blk_hash = NULL;
    uint64_t hash_key;

    hash_key = zfs_mirror_located_keygen(object_id, blk_id, blk_offset);
    ret = mod_hash_find(unaligned_cache->unaligned_modhash,
        (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t *)&blk_hash_list);
    if (ret == 0) {
        if (blk_hash_list != NULL) {
            for (blk_hash = list_head(blk_hash_list);
                blk_hash != NULL; blk_hash = list_next(blk_hash_list, blk_hash)) {
                if ((blk_hash->object_id == object_id)
                    && (blk_hash->blk_id == blk_id)
                    && (blk_hash->blk_offset == blk_offset)) {
                    break;
                }
            }
            if (list_is_empty(blk_hash_list)) {
                (void)mod_hash_remove(unaligned_cache->unaligned_modhash,
                    (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t *)&blk_hash_list);
                list_destroy(blk_hash_list);
                kmem_free(blk_hash_list, sizeof(list_t));
            }
        }
    }

    return (blk_hash);
}

static zfs_mirror_nonali_hash_t *
zfs_mirror_create_hash_member(zfs_mirror_cache_data_t *cache_data)
{
    zfs_mirror_nonali_hash_t *blk_hash = NULL;
    zfs_mirror_msg_mirrordata_header_t *header;

    header = cache_data->cs_data->ex_head;
    blk_hash = kmem_zalloc(sizeof(zfs_mirror_nonali_hash_t), KM_SLEEP);
    list_create(&blk_hash->hash_nonali_blk_list, sizeof(zfs_mirror_cache_data_t),
        offsetof(zfs_mirror_cache_data_t, node));

    list_insert_tail(&blk_hash->hash_nonali_blk_list, cache_data);

    blk_hash->spa_id = header->spa_id;
    blk_hash->os_id = header->os_id;
    blk_hash->object_id = header->object_id;
    blk_hash->blk_id = header->blk_id;
    blk_hash->blk_offset = header->blk_offset;
    blk_hash->hash_key = zfs_mirror_located_keygen(header->object_id,
        header->blk_id, header->blk_offset);

    return (blk_hash);
}

static int
zfs_mirror_destroy_hash_member(zfs_mirror_nonali_hash_t *blk_hash)
{
    if (blk_hash == NULL)
        return (-1);

    list_destroy(&blk_hash->hash_nonali_blk_list);
    kmem_free(blk_hash, sizeof(zfs_mirror_nonali_hash_t));

    return (0);
}

static void zfs_mirror_watchdog_init(void)
{
    if (zfs_mirror_wd != NULL)
        return;

    zfs_mirror_mac_port->mirror_watch_tq =
        taskq_create("mirror_watch_tq", 1, minclsyspri,
        1, INT_MAX, TASKQ_PREPOPULATE);

    zfs_mirror_watchdog_tick = zfs_mirror_watchdog_interval *
        drv_usectohz((clock_t)1000000);

    zfs_mirror_wd = kmem_zalloc(sizeof(zfs_mirror_watchdog_t), KM_SLEEP);
    mutex_init(&zfs_mirror_wd->wd_mxt, NULL, MUTEX_DEFAULT, NULL);
    cv_init(&zfs_mirror_wd->wd_cv, NULL, CV_DEFAULT, NULL);
    zfs_mirror_wd->wd_state = ZFS_MIRROR_WD_ACTIVE;
    zfs_mirror_wd->wd_th = thread_create(NULL, 0,
        zfs_mirror_watchdog_thread, zfs_mirror_wd, 0, &p0, TS_RUN, minclsyspri);
}

static void zfs_mirror_watchdog_fini(void)
{
    if (zfs_mirror_wd == NULL)
        return;
    mutex_enter(&zfs_mirror_wd->wd_mxt);
    zfs_mirror_wd->wd_state = ZFS_MIRROR_WD_DEACTIVATE;
    cv_broadcast(&zfs_mirror_wd->wd_cv);
    while (zfs_mirror_wd->wd_state != ZFS_MIRROR_WD_NONE) {
        cv_wait(&zfs_mirror_wd->wd_cv, &zfs_mirror_wd->wd_mxt);
    }
    mutex_exit(&zfs_mirror_wd->wd_mxt);
    mutex_destroy(&zfs_mirror_wd->wd_mxt);
    cv_destroy(&zfs_mirror_wd->wd_cv);
    kmem_free(zfs_mirror_wd, sizeof(zfs_mirror_watchdog_t));
    zfs_mirror_wd = NULL;

    taskq_destroy(zfs_mirror_mac_port->mirror_watch_tq);
}

static void zfs_mirror_watchdog_thread(void *arg)
{
    uint64_t cur_time_s;
    uint64_t last_time_expired_check;
    uint64_t last_time_spa_os;
    uint64_t last_time_tx_txg;
    cur_time_s = last_time_expired_check = last_time_spa_os = \
        last_time_tx_txg = ddi_get_time();

    mutex_enter(&zfs_mirror_wd->wd_mxt);
    while (zfs_mirror_wd->wd_state == ZFS_MIRROR_WD_ACTIVE) {
        cv_timedwait(&zfs_mirror_wd->wd_cv, &zfs_mirror_wd->wd_mxt,
            ddi_get_lbolt() + zfs_mirror_watchdog_tick);
        if (zfs_mirror_wd->wd_state == ZFS_MIRROR_WD_DEACTIVATE) {
            cmn_err(CE_WARN, "%s exit!", __func__);
            break;
        }
        cur_time_s = ddi_get_time();
        if (zfs_mirror_timeout_switch) {
            if ((cur_time_s - last_time_expired_check) >
                zfs_mirror_expired_check_gap) {
                last_time_expired_check = cur_time_s;
                /* check align cache whether or not has expired data */
                zfs_mirror_aligned_expired_handle();
                /* non align */
                zfs_mirror_unaligned_expired_handle();
            }
        }

        if ((cur_time_s - last_time_spa_os) > zfs_mirror_spa_os_timeout) {
            zfs_mirror_spa_os_expired_handle();
            zfs_mirror_os_io_expired_handle();
            last_time_spa_os = cur_time_s;
        }

        /* tx spa's txg to other host */
        if ((cur_time_s - last_time_tx_txg) > zfs_mirror_send_txg_gap) {
            last_time_tx_txg = cur_time_s;
            taskq_dispatch(zfs_mirror_mac_port->tq_tx_spa_txg,
                zfs_mirror_tx_spa_txg, NULL, TQ_NOSLEEP);
        }
    }
    zfs_mirror_wd->wd_state = ZFS_MIRROR_WD_NONE;
    cv_broadcast(&zfs_mirror_wd->wd_cv);
    mutex_exit(&zfs_mirror_wd->wd_mxt);
    thread_exit();
}

void zfs_mirror_stop_watchdog_thread(void)
{
	if (zfs_mirror_wd->wd_state == ZFS_MIRROR_WD_ACTIVE) {
		zfs_mirror_wd->wd_state = ZFS_MIRROR_WD_DEACTIVATE;
		cv_wait(&zfs_mirror_wd->wd_cv, &zfs_mirror_wd->wd_mxt);
	}

	return;
}

void zfs_mirror_data_expired_switch(boolean_t on_off)
{
    zfs_mirror_timeout_switch = on_off;
}

#define	ZFS_MIRROR_SPS_OS_CNT_MAX	4096
typedef struct zfs_mirror_spa_os_pair {
    uint64_t spa_id[ZFS_MIRROR_SPS_OS_CNT_MAX];
    uint64_t os_id[ZFS_MIRROR_SPS_OS_CNT_MAX];
    uint32_t spa_hostid[ZFS_MIRROR_SPS_OS_CNT_MAX];
    int cnt;
}zfs_mirror_spa_os_pair_t;

static uint_t zfs_mirror_get_spa_os_cb(mod_hash_key_t hash_key,
    mod_hash_val_t *val, void *arg)
{
    zfs_mirror_spa_os_pair_t *spa_os_pair = (zfs_mirror_spa_os_pair_t *)arg;
    list_t *spa_os_list = (list_t *)val;
    mirror_spa_os_t *spa_os = NULL;

    for (spa_os = list_head(spa_os_list); spa_os != NULL;
        spa_os = list_next(spa_os_list, spa_os)) {
        spa_os_pair->spa_id[spa_os_pair->cnt] = spa_os->spa_id;
        spa_os_pair->os_id[spa_os_pair->cnt] = spa_os->os_id;
        spa_os_pair->spa_hostid[spa_os_pair->cnt] = spa_os->remote_hostid;
        spa_os_pair->cnt++;
        if (spa_os_pair->cnt == ZFS_MIRROR_SPS_OS_CNT_MAX) {
            return (MH_WALK_TERMINATE);
        }
    }
    return (MH_WALK_CONTINUE);
}

typedef struct zfs_mirror_spa_host_pair {
    list_node_t node;
    uint64_t spa_guid[ZFS_MIRROR_WD_CHECK_GUID_N];
    uint32_t spa_hostid;
    int spa_cnt;
}zfs_mirror_spa_host_pair_t;

typedef struct zfs_mirror_aligned_expired_arg {
    list_t txg_clean_list;
    list_t spa_host_list;
}zfs_mirror_aligned_expired_arg_t;

static int zfs_mirror_write_get_last_synced_txg_msg(
    zfs_mirror_spa_host_pair_t *spa_host)
{
    cluster_san_hostinfo_t *cshi;
    zfs_mirror_msg_header_t msg_header;
    int ret;

    cshi = cluster_remote_hostinfo_hold(spa_host->spa_hostid);
    if (cshi == NULL) {
        return (-1);
    }
    msg_header.msg_type = ZFS_MIRROR_GET_LAST_SYNCED_TXG;
    ret = cluster_san_host_send(cshi,
        spa_host->spa_guid, spa_host->spa_cnt * sizeof(uint64_t),
        &msg_header, sizeof(zfs_mirror_msg_header_t),
        CLUSTER_SAN_MSGTYPE_ZFS_MIRROR, 1, B_TRUE, 1);
    cluster_san_hostinfo_rele(cshi);

    return (ret);
}

static uint_t zfs_mirror_aligned_expired_cb(mod_hash_key_t hash_key,
    mod_hash_val_t *val, void *arg)
{
    list_t *spa_os_list = (list_t *)val;
    zfs_mirror_aligned_expired_arg_t *aligned_expired =
        (zfs_mirror_aligned_expired_arg_t *)arg;
    mirror_spa_os_t *spa_os = NULL;
    mirror_aligned_cache_t *aligned_cache;
    mirror_cache_txg_list_t *txg_list;
    mirror_cache_txg_list_t *next_txg_list;
    uint64_t cur_time_s = ddi_get_time();
    uint64_t delta_time;
    zfs_mirror_spa_host_pair_t *spa_host;

    for (spa_os = list_head(spa_os_list); spa_os != NULL;
        spa_os = list_next(spa_os_list, spa_os)) {
        aligned_cache = spa_os->aligned_cache;
        if (aligned_cache == NULL) {
            continue;
        }
        mutex_enter(&aligned_cache->lock);
        txg_list = list_head(&aligned_cache->aligned_list_time);
        while (txg_list != NULL) {
            next_txg_list = list_next(&aligned_cache->aligned_list_time, txg_list);
            if (cur_time_s < txg_list->active_time) {
                break;
            }
            delta_time = cur_time_s - txg_list->active_time;
            if (delta_time < zfs_mirror_ali_threshold) {
                break;
            }
            if (delta_time > zfs_mirror_ali_timeout) {
                if (zfs_mirror_expired_handle_debug) {
                    cmn_err(CE_WARN, "%s: align txg_list expired, txg (0x%016"PRIx64") "
                        "spa_id(0x%016"PRIx64") os_id(0x%016"PRIx64") timeout(%"PRId64"s)",
                        __func__, txg_list->cache_txg_list_txg, txg_list->spa_id,
                        txg_list->os_id, delta_time);
                }
                list_remove(&aligned_cache->aligned_list_txg, txg_list);
                list_remove(&aligned_cache->aligned_list_time, txg_list);
                list_insert_tail(&aligned_expired->txg_clean_list, txg_list);
            } else {
                int i;

                spa_host = list_head(&aligned_expired->spa_host_list);
                while (spa_host != NULL) {
                    if (spa_host->spa_hostid == spa_os->remote_hostid) {
                        break;
                    }
                    spa_host = list_next(&aligned_expired->spa_host_list, spa_host);
                }
                if (spa_host == NULL) {
                    spa_host = kmem_zalloc(sizeof(zfs_mirror_spa_host_pair_t),
                        KM_SLEEP);
                    spa_host->spa_hostid = spa_os->remote_hostid;
                    list_insert_tail(&aligned_expired->spa_host_list, spa_host);
                }
                for (i = 0; i < spa_host->spa_cnt; i++) {
                    if (spa_host->spa_guid[i] == txg_list->spa_id) {
                        break;
                    }
                }
                if (i == spa_host->spa_cnt) {
                    spa_host->spa_guid[i] = txg_list->spa_id;
                    spa_host->spa_cnt++;
                    if (spa_host->spa_cnt == ZFS_MIRROR_WD_CHECK_GUID_N) {
                        mutex_exit(&aligned_cache->lock);
                        return (MH_WALK_TERMINATE);
                    }
                }
                break;
            }
            txg_list = next_txg_list;
        }
        mutex_exit(&aligned_cache->lock);
    }
    return (MH_WALK_CONTINUE);
}

static int zfs_mirror_aligned_expired_handle(void)
{
    zfs_mirror_aligned_expired_arg_t *aligned_expired;
    mirror_cache_txg_list_t *txg_list;
    zfs_mirror_spa_host_pair_t *spa_host;
    int cnt = 0;

    aligned_expired = kmem_alloc(sizeof(zfs_mirror_aligned_expired_arg_t),
        KM_SLEEP);
    list_create(&aligned_expired->txg_clean_list,
        sizeof (mirror_cache_txg_list_t),
        offsetof(mirror_cache_txg_list_t, cache_txg_list_node));
    list_create(&aligned_expired->spa_host_list,
        sizeof(zfs_mirror_spa_host_pair_t),
        offsetof(zfs_mirror_spa_host_pair_t, node));

    mutex_enter(&zfs_mirror_mac_port->spa_os_lock);
    mod_hash_walk(zfs_mirror_mac_port->spa_os_modhash,
        zfs_mirror_aligned_expired_cb, (void*)aligned_expired);
    mutex_exit(&zfs_mirror_mac_port->spa_os_lock);

    while ((spa_host = list_remove_head(&aligned_expired->spa_host_list)) != NULL) {
        cnt += spa_host->spa_cnt;
        zfs_mirror_write_get_last_synced_txg_msg(spa_host);
        kmem_free(spa_host, sizeof(zfs_mirror_spa_host_pair_t));
    }
    list_destroy(&aligned_expired->spa_host_list);

    while ((txg_list = list_head(&aligned_expired->txg_clean_list)) != NULL) {
        list_remove(&aligned_expired->txg_clean_list, txg_list);
        zfs_mirror_aligned_txg_list_free(txg_list);
    }
    list_destroy(&aligned_expired->txg_clean_list);

    kmem_free(aligned_expired, sizeof(zfs_mirror_aligned_expired_arg_t));

    return (cnt);
}

typedef struct zfs_mirror_io_located {
    uint64_t spa_id;
    uint64_t os_id;
    uint64_t object_id;
    uint64_t blk_id;
    uint64_t offset;
}zfs_mirror_io_located_t;

typedef struct zfs_mirror_unaligned_expired_arg {
    list_t clean_list;
    zfs_mirror_io_located_t *unaligned_located;
    int cnt;
}zfs_mirror_unaligned_expired_arg_t;

static void
zfs_mirror_remove_unaligned(
    mirror_unaligned_cache_t *unaligned_cache,
    zfs_mirror_nonali_hash_t *hash_blk)
{
    list_t *blk_hash_list = NULL;
    zfs_mirror_nonali_hash_t *hash_blk_temp;
    int ret = 0;

    ret = mod_hash_find(unaligned_cache->unaligned_modhash,
        (mod_hash_key_t)(uintptr_t)hash_blk->hash_key,
        (mod_hash_val_t *)&blk_hash_list);
    if ((ret == 0) && (blk_hash_list != NULL)) {
        for (hash_blk_temp = list_head(blk_hash_list);
            hash_blk_temp != NULL;
            hash_blk_temp = list_next(blk_hash_list, hash_blk_temp)) {
            if (hash_blk_temp == hash_blk) {
                list_remove(&unaligned_cache->unaligned_list_time, hash_blk);
                list_remove(blk_hash_list, hash_blk);
                atomic_dec_64(&zfs_mirror_mac_port->rs_nonali_modhash_frames);
                break;
            }
        }
        if (list_is_empty(blk_hash_list)) {
            (void)mod_hash_remove(unaligned_cache->unaligned_modhash,
                (mod_hash_key_t)(uintptr_t)hash_blk->hash_key,
                (mod_hash_val_t *)&blk_hash_list);
            list_destroy(blk_hash_list);
            kmem_free(blk_hash_list, sizeof(list_t));
        }
    }
}

static int zfs_mirror_unaligned_expired_handle(void)
{
    cluster_san_hostinfo_t *cshi;
    zfs_mirror_msg_header_t msg_header;
    zfs_mirror_spa_os_pair_t *spa_os_pair;
    zfs_mirror_nonali_hash_t *hash_blk;
    zfs_mirror_nonali_hash_t *hash_blk_next;
    zfs_mirror_cache_data_t *cache_data;
    mirror_unaligned_cache_t *unaligned_cache;
    zfs_mirror_io_located_t *unaligned_located;
    uint64_t cur_time_s = ddi_get_time();
    uint64_t delta_time;
    list_t clean_list;
    int cnt;
    int total = 0;
    int i;

    unaligned_located = kmem_zalloc(
        sizeof(zfs_mirror_io_located_t) * ZFS_MIRROR_WD_CHECK_NONALI_N,
        KM_SLEEP);
    list_create(&clean_list, sizeof (zfs_mirror_nonali_hash_t),
        offsetof(zfs_mirror_nonali_hash_t, hash_list_node));

    spa_os_pair = kmem_alloc(sizeof(zfs_mirror_spa_os_pair_t), KM_SLEEP);
    spa_os_pair->cnt = 0;

    mutex_enter(&zfs_mirror_mac_port->spa_os_lock);
    mod_hash_walk(zfs_mirror_mac_port->spa_os_modhash,
        zfs_mirror_get_spa_os_cb, (void*)spa_os_pair);
    mutex_exit(&zfs_mirror_mac_port->spa_os_lock);

    msg_header.msg_type = ZFS_MIRROR_IS_NONALIGNED_ACTIVE;

    for (i = 0; i < spa_os_pair->cnt; i++) {
        cnt = 0;
        unaligned_cache = zfs_mirror_hold_unaligned_cache (
            spa_os_pair->spa_id[i], spa_os_pair->os_id[i], 0, 0, FTAG);
        if (unaligned_cache == NULL) {
            continue;
        }
        hash_blk = list_head(&unaligned_cache->unaligned_list_time);
        while (hash_blk != NULL) {
            delta_time = cur_time_s - hash_blk->active_time;
            if (delta_time < zfs_mirror_unali_threshold) {
                break;
            }
            hash_blk_next = list_next(&unaligned_cache->unaligned_list_time, hash_blk);
            if ((delta_time > zfs_mirror_unali_timeout)
                && (hash_blk->check_times >= zfs_mirrro_unali_check_times)) {
                if (zfs_mirror_expired_handle_debug) {
                    cmn_err(CE_NOTE, "%s: nonalign hash_blk expired, "
                        "spa_id(0x%016"PRIx64") os_id(0x%016"PRIx64") "
                        "object_id(0x%016"PRIx64") blkd_id(0x%016"PRIx64") "
                        "offset(0x%016"PRIx64") timeout(%"PRId64"s)",
                        __func__, hash_blk->spa_id, hash_blk->os_id, hash_blk->object_id,
                        hash_blk->blk_id, hash_blk->blk_offset, delta_time);
                }
                zfs_mirror_remove_unaligned(unaligned_cache, hash_blk);
                list_insert_tail(&clean_list, hash_blk);
            } else if (delta_time > zfs_mirror_unali_threshold) {
                hash_blk->check_times++;
                unaligned_located[cnt].spa_id = hash_blk->spa_id;
                unaligned_located[cnt].os_id = hash_blk->os_id;
                unaligned_located[cnt].object_id = hash_blk->object_id;
                unaligned_located[cnt].blk_id = hash_blk->blk_id;
                unaligned_located[cnt].offset = hash_blk->blk_offset;
                cnt++;
                if (cnt >= ZFS_MIRROR_WD_CHECK_NONALI_N) {
                    break;
                }
            }
            hash_blk = hash_blk_next;
        }
        zfs_mirror_rele_unaligned_cache(unaligned_cache, FTAG);

        if (cnt != 0) {
            /* ask partner whether or not this hash_blk is active */
            cshi = cluster_remote_hostinfo_hold(spa_os_pair->spa_hostid[i]);
            if (cshi != NULL) {
                cluster_san_host_send(cshi,
                    (void *)unaligned_located, cnt * sizeof(zfs_mirror_io_located_t),
                    &msg_header, sizeof(zfs_mirror_msg_header_t),
                    CLUSTER_SAN_MSGTYPE_ZFS_MIRROR, 1, B_TRUE, 1);
                cluster_san_hostinfo_rele(cshi);
            }
            total += cnt;
        }
    }
    kmem_free(spa_os_pair, sizeof(zfs_mirror_spa_os_pair_t));
    kmem_free(unaligned_located,
        sizeof(zfs_mirror_io_located_t) * ZFS_MIRROR_WD_CHECK_NONALI_N);

    while ((hash_blk = list_remove_head(&clean_list)) != NULL) {
        while (cache_data = list_remove_head(&hash_blk->hash_nonali_blk_list)) {
            atomic_inc_64(&zfs_mirror_mac_port->rx_nonali_data_dec_frames);
            atomic_add_64(&zfs_mirror_mac_port->rs_nonali_cache_size,
                0 - cache_data->cs_data->data_len);
            csh_rx_data_free(cache_data->cs_data, B_TRUE);
            kmem_free(cache_data, sizeof(zfs_mirror_cache_data_t));
        }
        zfs_mirror_destroy_hash_member(hash_blk);
    }
    list_destroy(&clean_list);

    return (total);
}

static void zfs_mirror_get_last_synced_txg(void *arg)
{
    cs_rx_data_t *cs_data = (cs_rx_data_t *)arg;
    spa_t *spa;
    uint64_t *spa_guid;
    uint64_t spa_cnt;
    zfs_mirror_reply_synced_txg_t *reply = NULL;
    zfs_mirror_msg_header_t msg_header;
    int i = 0;

    spa_guid = (uint64_t *)cs_data->data;
    spa_cnt = cs_data->data_len / sizeof(uint64_t);
    if (spa_cnt == 0) {
        goto FINISH;
    }
    reply = kmem_zalloc(spa_cnt * sizeof(zfs_mirror_reply_synced_txg_t),
        KM_SLEEP);
    for (i = 0; i < spa_cnt; i++) {
        reply[i].spa_guid = spa_guid[i];
        mutex_enter(&spa_namespace_lock);
        spa = spa_by_guid(spa_guid[i], 0);
        if (spa == NULL) {
            reply[i].txg = UINT64_MAX;
        } else {
            reply[i].txg = spa_last_synced_txg(spa);
        }
        mutex_exit(&spa_namespace_lock);
    }
    msg_header.msg_type = ZFS_MIRROR_REPLY_LAST_SYNCED_TXG;
    cluster_san_host_send(cs_data->cs_private,
        (void *)reply, spa_cnt * sizeof(zfs_mirror_reply_synced_txg_t),
        &msg_header, sizeof(zfs_mirror_msg_header_t),
        CLUSTER_SAN_MSGTYPE_ZFS_MIRROR, 1, B_TRUE, 1);
    kmem_free(reply, spa_cnt * sizeof(zfs_mirror_reply_synced_txg_t));
FINISH:
    csh_rx_data_free(cs_data, B_TRUE);
}

typedef struct zfs_mirror_clean_aligned_arg {
    list_t txg_clean_list;
    zfs_mirror_reply_synced_txg_t *spa_txg;
    int cnt;
}zfs_mirror_clean_aligned_arg_t;

static uint_t zfs_mirror_clean_aligned_cb(mod_hash_key_t hash_key,
    mod_hash_val_t *val, void *arg)
{
    zfs_mirror_clean_aligned_arg_t *clean_aligned =
        (zfs_mirror_clean_aligned_arg_t *)arg;
    list_t *spa_os_list = (list_t *)val;
    mirror_spa_os_t *spa_os = NULL;
    mirror_aligned_cache_t *aligned_cache;
    mirror_cache_txg_list_t *txg_list;
    mirror_cache_txg_list_t *next_txg_list;
    uint64_t cur_time_s = ddi_get_time();
    uint64_t delta_time;

    for (spa_os = list_head(spa_os_list); spa_os != NULL;
        spa_os = list_next(spa_os_list, spa_os)) {
        int i;
        for (i = 0; i < clean_aligned->cnt; i++) {
            if (spa_os->spa_id == clean_aligned->spa_txg[i].spa_guid) {
                break;
            }
        }
        if (i == clean_aligned->cnt) {
            continue;
        }
        aligned_cache = spa_os->aligned_cache;
        if (aligned_cache == NULL) {
            continue;
        }
        mutex_enter(&aligned_cache->lock);
        txg_list = list_head(&aligned_cache->aligned_list_time);
        while (txg_list != NULL) {
            delta_time = cur_time_s - txg_list->active_time;
            if ((cur_time_s <= txg_list->active_time)
                || (delta_time < zfs_mirror_ali_threshold)) {
                break;
            }
            next_txg_list = list_next(&aligned_cache->aligned_list_time, txg_list);
            if (txg_list->cache_txg_list_txg > clean_aligned->spa_txg[i].txg) {
                list_remove(&aligned_cache->aligned_list_time, txg_list);
                txg_list->active_time = ddi_get_time();
                list_insert_tail(&aligned_cache->aligned_list_time, txg_list);
            } else {
                list_remove(&aligned_cache->aligned_list_txg, txg_list);
                list_remove(&aligned_cache->aligned_list_time, txg_list);
                list_insert_tail(&clean_aligned->txg_clean_list, txg_list);
            }
            txg_list = next_txg_list;
        }
        mutex_exit(&aligned_cache->lock);
    }
    return (MH_WALK_CONTINUE);
}

static void
zfs_mirror_clean_spa_aligned(zfs_mirror_reply_synced_txg_t *spa_txg, int cnt)
{
    zfs_mirror_clean_aligned_arg_t clean_aligned;
    mirror_cache_txg_list_t *txg_list;

    list_create(&clean_aligned.txg_clean_list,
        sizeof (mirror_cache_txg_list_t),
        offsetof(mirror_cache_txg_list_t, cache_txg_list_node));
    clean_aligned.spa_txg = spa_txg;
    clean_aligned.cnt = cnt;

    mutex_enter(&zfs_mirror_mac_port->spa_os_lock);
    mod_hash_walk(zfs_mirror_mac_port->spa_os_modhash,
        zfs_mirror_clean_aligned_cb, (void*)&clean_aligned);
    mutex_exit(&zfs_mirror_mac_port->spa_os_lock);

    while ((txg_list = list_head(&clean_aligned.txg_clean_list)) != NULL) {
        list_remove(&clean_aligned.txg_clean_list, txg_list);
        zfs_mirror_aligned_txg_list_free(txg_list);
    }

    list_destroy(&clean_aligned.txg_clean_list);
}

static void zfs_mirror_rcv_last_synced_txg(void *arg)
{
    cs_rx_data_t *cs_data = (cs_rx_data_t *)arg;
    zfs_mirror_reply_synced_txg_t *spa_txg;
    int cnt;

    spa_txg = (zfs_mirror_reply_synced_txg_t *)cs_data->data;
    cnt = cs_data->data_len / sizeof(zfs_mirror_reply_synced_txg_t);

    zfs_mirror_clean_spa_aligned(spa_txg, cnt);

    csh_rx_data_free(cs_data, B_TRUE);
}

static void zfs_mirror_is_unaligned_actived(void *arg)
{
    cs_rx_data_t *cs_data = (cs_rx_data_t *)arg;
    zfs_mirror_msg_header_t msg_header;
    zfs_mirror_io_located_t *unaligned_located;
    dbuf_mirror_io_t *mirror_io;
    zfs_mirror_os_io_t *os_io;
    list_t *mirror_io_list = NULL;
    uint64_t hash_key;
    uint64_t cur_time_s;
    int cnt;
    int i;
    int ret;
    zfs_mirror_unali_state_t *reply;

    ASSERT((cs_data->data_len % sizeof(zfs_mirror_io_located_t)) == 0);
    unaligned_located = (zfs_mirror_io_located_t *)cs_data->data;
    cnt = cs_data->data_len / sizeof(zfs_mirror_io_located_t);
    if (cnt == 0) {
        csh_rx_data_free(cs_data, B_TRUE);
        return;
    }
    cur_time_s = ddi_get_time();
    reply = kmem_zalloc(sizeof(zfs_mirror_unali_state_t) * cnt, KM_SLEEP);
    os_io = zfs_mirror_hold_os_io(unaligned_located[0].spa_id,
        unaligned_located[0].os_id, 0, FTAG);
    for (i = 0; i < cnt; i++) {
        reply[i].spa_id = unaligned_located[i].spa_id;
        reply[i].os_id = unaligned_located[i].os_id;
        reply[i].object_id= unaligned_located[i].object_id;
        reply[i].blk_id= unaligned_located[i].blk_id;
        reply[i].offset = unaligned_located[i].offset;
        if (os_io == NULL) {
            reply[i].state = ZFS_MIRROR_NONALI_STATE_NONE;
            continue;
        }
        hash_key = zfs_mirror_located_keygen(unaligned_located[i].object_id,
            unaligned_located[i].blk_id, unaligned_located[i].offset);
        ret =  mod_hash_find(os_io->mirror_io_h, (mod_hash_key_t)(uintptr_t)hash_key,
            (mod_hash_val_t *)&mirror_io_list);
        if ((ret != 0) || (mirror_io_list == NULL)) {
            reply[i].state = ZFS_MIRROR_NONALI_STATE_NONE;
            continue;
        }
        mirror_io = list_head(mirror_io_list);
        while (mirror_io != NULL) {
            if ((unaligned_located[i].object_id == mirror_io->object_id) &&
                (unaligned_located[i].blk_id == mirror_io->blk_id) &&
                (unaligned_located[i].offset == mirror_io->offset)) {
                reply[i].state = ZFS_MIRROR_NONALI_STATE_ACTIVE;
                break;
            }
            mirror_io = list_next(mirror_io_list, mirror_io);
        }
        if (mirror_io == NULL) {
            reply[i].state = ZFS_MIRROR_NONALI_STATE_NONE;
        }
    }
    if (os_io != NULL) {
        zfs_mirror_rele_os_io(os_io, FTAG);
    }

    msg_header.msg_type = ZFS_MIRROR_REPLY_NONALIGNED_ACTIVE;
    cluster_san_host_send(cs_data->cs_private,
        (void *)reply, cnt *sizeof(zfs_mirror_unali_state_t),
        &msg_header, sizeof(zfs_mirror_msg_header_t),
        CLUSTER_SAN_MSGTYPE_ZFS_MIRROR, 1, B_TRUE, 1);
    kmem_free(reply, sizeof(zfs_mirror_unali_state_t) * cnt);

    csh_rx_data_free(cs_data, B_TRUE);
}

static void zfs_mirror_handle_unaligned_actived(void *arg)
{
    cs_rx_data_t *cs_data = (cs_rx_data_t *)arg;
    zfs_mirror_nonali_hash_t *hash_blk = NULL;
    mirror_unaligned_cache_t *unaligned_cache;
    zfs_mirror_cache_data_t *cache_data;
    list_t *blk_hash_list = NULL;
    uint64_t spa_id;
    uint64_t os_id;
    uint64_t hash_key;
    uint64_t cur_time_s;
    uint64_t delta_time;
    zfs_mirror_unali_state_t *unali_state;
    list_t clean_list;
    int ret;
    int cnt;
    int i;

    ASSERT((cs_data->data_len % sizeof(zfs_mirror_unali_state_t)) == 0);
    unali_state = (zfs_mirror_unali_state_t *)cs_data->data;
    cnt = cs_data->data_len / sizeof(zfs_mirror_unali_state_t);

    if (cnt == 0) {
        csh_rx_data_free(cs_data, B_TRUE);
        return;
    }
    list_create(&clean_list, sizeof (zfs_mirror_nonali_hash_t),
        offsetof(zfs_mirror_nonali_hash_t, hash_list_node));

    cur_time_s = ddi_get_time();
    spa_id = unali_state[0].spa_id;
    os_id = unali_state[0].os_id;
    unaligned_cache = zfs_mirror_hold_unaligned_cache(spa_id, os_id, 0, 0, FTAG);
    if (unaligned_cache == NULL) {
        csh_rx_data_free(cs_data, B_TRUE);
        list_destroy(&clean_list);
        return;
    }
    for (i = 0; i < cnt; i++) {
        hash_key = zfs_mirror_located_keygen(unali_state[i].object_id,
            unali_state[i].blk_id, unali_state[i].offset);
        ret = mod_hash_find(unaligned_cache->unaligned_modhash,
            (mod_hash_key_t)(uintptr_t)hash_key, (mod_hash_val_t *)&blk_hash_list);
        if ((ret == 0) && (blk_hash_list != NULL)) {
            hash_blk = list_head(blk_hash_list);
            while (hash_blk != NULL) {
                if ((hash_blk->object_id == unali_state[i].object_id)
                    && (hash_blk->blk_id == unali_state[i].blk_id)
                    && (hash_blk->blk_offset == unali_state[i].offset)) {
                    break;
                }
                hash_blk = list_next(blk_hash_list, hash_blk);
            }
            if (hash_blk == NULL) {
                continue;
            }
            hash_blk->check_times = 0;
            delta_time = cur_time_s - hash_blk->active_time;
            if ((cur_time_s <= hash_blk->active_time)
                || (delta_time <= zfs_mirror_unali_threshold)) {
                continue;
            }
            if (unali_state[i].state == ZFS_MIRROR_NONALI_STATE_ACTIVE) {
                hash_blk->active_time = ddi_get_time();
                list_remove(&unaligned_cache->unaligned_list_time, hash_blk);
                list_insert_tail(&unaligned_cache->unaligned_list_time, hash_blk);
            } else {
                if (zfs_mirror_expired_handle_debug) {
                    cmn_err(CE_WARN, "%s: nonalign hash_blk expired,"
                        "spa_id(0x%016"PRIx64") os_id(0x%016"PRIx64") "
                        "object_id(0x%016"PRIx64") blkd_id(0x%016"PRIx64")"
                        " offset(0x%016"PRIx64") timeout(%"PRId64"s)",
                        __func__, hash_blk->spa_id, hash_blk->os_id,
                        hash_blk->object_id, hash_blk->blk_id,
                        hash_blk->blk_offset, delta_time);
                }
                list_remove(&unaligned_cache->unaligned_list_time, hash_blk);
                list_remove(blk_hash_list, hash_blk);
                atomic_dec_64(&zfs_mirror_mac_port->rs_nonali_modhash_frames);

                if (list_is_empty(blk_hash_list)) {
                    (void)mod_hash_remove(unaligned_cache->unaligned_modhash,
                        (mod_hash_key_t)(uintptr_t)hash_blk->hash_key,
                        (mod_hash_val_t *)&blk_hash_list);
                    list_destroy(blk_hash_list);
                    kmem_free(blk_hash_list, sizeof(list_t));
                }

                list_insert_tail(&clean_list, hash_blk);
            }
        }
    }

    zfs_mirror_rele_unaligned_cache(unaligned_cache, FTAG);

    csh_rx_data_free(cs_data, B_TRUE);

    while ((hash_blk = list_remove_head(&clean_list)) != NULL) {
        while (cache_data = list_remove_head(&hash_blk->hash_nonali_blk_list)) {
            atomic_inc_64(&zfs_mirror_mac_port->rx_nonali_data_dec_frames);
            atomic_add_64(&zfs_mirror_mac_port->rs_nonali_cache_size,
                0 - cache_data->cs_data->data_len);
            csh_rx_data_free(cache_data->cs_data, B_TRUE);
            kmem_free(cache_data, sizeof(zfs_mirror_cache_data_t));
        }
        zfs_mirror_destroy_hash_member(hash_blk);
    }
    list_destroy(&clean_list);
}

static boolean_t zfs_mirror_is_spa_os_empty(mirror_spa_os_t *spa_os)
{
    if (spa_os->aligned_cache != NULL) {
        if (!refcount_is_zero(&spa_os->aligned_cache->refcount) ||
            !list_is_empty(&spa_os->aligned_cache->aligned_list_time)) {
            return (B_FALSE);
        }
    }
    if (spa_os->unaligned_cache != NULL) {
        if (!refcount_is_zero(&spa_os->unaligned_cache->refcount) ||
            !list_is_empty(&spa_os->unaligned_cache->unaligned_list_time)) {
            return (B_FALSE);
        }
    }

    return (B_TRUE);
}

static uint_t zfs_mirror_spa_os_expired_cb(mod_hash_key_t hash_key,
    mod_hash_val_t *val, void *arg)
{
    list_t *spa_os_list = (list_t *)val;
    list_t *clean_list = (list_t *)arg;
    mirror_spa_os_t *spa_os = NULL;
    mirror_spa_os_t *spa_os_next = NULL;
    uint64_t cur_time_s = ddi_get_time();

    for (spa_os = list_head(spa_os_list); spa_os != NULL;
        spa_os = spa_os_next) {
        spa_os_next = list_next(spa_os_list, spa_os);
        if ((cur_time_s > spa_os->active_time)
            && ((cur_time_s - spa_os->active_time) > zfs_mirror_spa_os_timeout)) {
            if (zfs_mirror_is_spa_os_empty(spa_os)) {
                list_remove(spa_os_list, spa_os);
                list_insert_tail(clean_list, spa_os);
            }
        }
    }
    return (MH_WALK_CONTINUE);
}

static int zfs_mirror_spa_os_expired_handle(void)
{
    list_t clean_list;
    list_t *spa_os_list;
    mirror_spa_os_t *spa_os = NULL;
    uint64_t hash_key;
    int ret;
    int cnt = 0;

    list_create(&clean_list, sizeof(mirror_spa_os_t),
            offsetof(mirror_spa_os_t, node));

    mutex_enter(&zfs_mirror_mac_port->spa_os_lock);
    mod_hash_walk(zfs_mirror_mac_port->spa_os_modhash,
        zfs_mirror_spa_os_expired_cb, (void*)&clean_list);
    mutex_exit(&zfs_mirror_mac_port->spa_os_lock);

    while ((spa_os = list_head(&clean_list)) != NULL) {
        list_remove(&clean_list, spa_os);
        if (spa_os->aligned_cache != NULL) {
            zfs_mirror_destroy_aligned_cache(spa_os->aligned_cache);
        }
        if (spa_os->unaligned_cache != NULL) {
            zfs_mirror_destroy_unaligned_cache(spa_os->unaligned_cache);
        }
        mutex_enter(&zfs_mirror_mac_port->spa_os_lock);
        if (list_is_empty((list_t *)spa_os->parent)) {
            hash_key = zfs_mirror_spa_os_keygen(spa_os->spa_id, spa_os->os_id);
            ret = mod_hash_remove(zfs_mirror_mac_port->spa_os_modhash,
                (mod_hash_key_t)(uintptr_t)hash_key,
                (mod_hash_val_t *)&spa_os_list);
            if (ret == 0) {
                ASSERT(spa_os->parent == spa_os_list);
                list_destroy(spa_os_list);
                kmem_free(spa_os_list, sizeof(list_t));
            }
        }
        mutex_exit(&zfs_mirror_mac_port->spa_os_lock);

        kmem_free(spa_os, sizeof(mirror_spa_os_t));
        cnt++;
    }
    list_destroy(&clean_list);
    return (cnt);
}

static boolean_t zfs_mirror_is_os_io_empty(zfs_mirror_os_io_t *os_io)
{
    if (os_io->mirror_io_h != NULL) {
        if (!refcount_is_zero(&os_io->refcount)
            || (os_io->mirror_io_h->mh_stat.mhs_nelems != 0)) {
            return (B_FALSE);
        }
    }
    return (B_TRUE);
}

static uint_t zfs_mirror_os_io_expired_cb(mod_hash_key_t hash_key,
    mod_hash_val_t *val, void *arg)
{
    list_t *os_io_list = (list_t *)val;
    list_t *clean_list = (list_t *)arg;
    zfs_mirror_os_io_t *os_io = NULL;
    zfs_mirror_os_io_t *os_io_next = NULL;
    uint64_t cur_time_s = ddi_get_time();

    for (os_io = list_head(os_io_list); os_io != NULL; os_io = os_io_next) {
        os_io_next = list_next(os_io_list, os_io);
        if ((cur_time_s > os_io->active_time) &&
            ((cur_time_s - os_io->active_time) > zfs_mirror_spa_os_timeout)) {
            if (zfs_mirror_is_os_io_empty(os_io)) {
                list_remove(os_io_list, os_io);
                list_insert_tail(clean_list, os_io);
            }
        }
    }
    return (MH_WALK_CONTINUE);
}

static int zfs_mirror_os_io_expired_handle(void)
{
    zfs_mirror_os_io_t *os_io = NULL;
    list_t clean_list;
    list_t *os_io_list;
    uint64_t hash_key;
    int cnt = 0;
    int ret;

    list_create(&clean_list, sizeof(zfs_mirror_os_io_t),
            offsetof(zfs_mirror_os_io_t, node));

    mutex_enter(&zfs_mirror_mac_port->mirror_io_list_mtx);
    mod_hash_walk(zfs_mirror_mac_port->mirror_io_modhash,
        zfs_mirror_os_io_expired_cb, (void*)&clean_list);
    mutex_exit(&zfs_mirror_mac_port->mirror_io_list_mtx);

    while ((os_io = list_head(&clean_list)) != NULL) {
        list_remove(&clean_list, os_io);
        mutex_enter(&zfs_mirror_mac_port->mirror_io_list_mtx);
        if (list_is_empty(os_io->parent)) {
            hash_key = zfs_mirror_spa_os_keygen(os_io->spa_id, os_io->os_id);
            ret = mod_hash_remove(zfs_mirror_mac_port->mirror_io_modhash,
                (mod_hash_key_t)(uintptr_t)hash_key,
                (mod_hash_val_t *)&os_io_list);
            if (ret == 0) {
                ASSERT(os_io->parent == os_io_list);
                list_destroy(os_io_list);
                kmem_free(os_io_list, sizeof(list_t));
            }
        }
        mutex_exit(&zfs_mirror_mac_port->mirror_io_list_mtx);
        zfs_mirror_destroy_os_io(os_io);
        cnt++;
    }
    list_destroy(&clean_list);
    return (cnt);
}
