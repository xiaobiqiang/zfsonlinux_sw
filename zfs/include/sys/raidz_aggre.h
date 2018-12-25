#ifndef _RAIDZ_AGGRE_H
#define _RAIDZ_AGGRE_H
#define TG_MAX_DISK_NUM 16

#define AGGRE_MAP_MAX_DBUF_NUM	8

#define SPACE_RECLAIM_START		1
#define SPACE_RECLAIM_RUN		2
#define SPACE_RECLAIM_STOP		4
#define SPACE_RECLAIM_PAUSE		8

typedef enum {
	ELEM_STATE_FREE = 0,
	ELEM_STATE_REWRITE,
	ELEM_STATE_NO_CHANGE,
	ELEM_STATE_ERR
} aggre_elem_state;

typedef struct aggre_map_hdr {
	int aggre_num;
	int recsize;
	int blksize;
	uint64_t total_count;	/* always increment, provide map_index */
	uint64_t avail_count;	/* current available count, start from process_index */
	uint64_t process_index;	/* always increment, provide space recovery start index */
} aggre_map_hdr_t;

typedef struct aggre_map_elem {
	uint64_t txg;
	uint64_t timestamp;
	uint64_t objsetid;
	uint64_t objectid;
	dva_t	 dva;
	uint64_t blkid[1];
} aggre_map_elem_t;

typedef struct aggre_map {
	aggre_map_hdr_t *hdr;
	objset_t *os;
	uint64_t object;
	dmu_buf_t *dbuf_hdr;
	dmu_buf_t **dbuf_array;
	int dbuf_num;
	int dbuf_size;
	uint64_t dbuf_id;
	kmutex_t aggre_lock;
} aggre_map_t;

typedef struct map_pos {
	kmutex_t	mtx;
	uint64_t	pos;
	boolean_t	valid;
} map_pos_t;

typedef struct free_map {
	objset_t *os;
	uint64_t object;
	int blksize;
	int count;
} free_map_t;

typedef struct dirty_elem {
	uint64_t txg;
	uint64_t timestamp;
	uint64_t objsetid;
	uint64_t objectid;
	uint64_t blkid;
	dva_t    dva;
	uint32_t tofree;
} dirty_elem_t;

typedef struct dirty_map {
	objset_t *os;
	uint64_t object;
	int blksize;
	int total_count;
	int elem_count;
	int load_count;
	dmu_buf_t *dbuf_hdr;
	dmu_buf_t *dbuf;
} dirty_map_t;

typedef struct index_node {
	list_node_t node;
	int index;
} index_node_t;

typedef struct aggre_setarg {
	spa_t *spa;
	aggre_map_t *map;
	uint64_t offset;
	uint64_t process_index;
	int index;
	int cur_pro_count;
} aggre_setarg_t;

typedef struct aggre_outarg {
	int pro_count;
	int error;
} aggre_outarg_t;

typedef struct raidz_col {
	uint64_t rc_devidx;		/* child device index for I/O */
	uint64_t rc_offset;		/* device offset */
	uint64_t rc_size;		/* I/O size */
	void *rc_data;			/* I/O data */
	void *rc_gdata;			/* used to store the "good" version */
	int rc_error;			/* I/O error for this device */
	uint8_t rc_tried;		/* Did we attempt this I/O column? */
	uint8_t rc_skipped;		/* Did we skip this I/O column? */
} raidz_col_t;
typedef struct raidz_map {
	uint64_t rm_cols;		/* Regular column count */
	uint64_t rm_scols;		/* Count including skipped columns */
	uint64_t rm_bigcols;		/* Number of oversized columns */
	uint64_t rm_asize;		/* Actual total I/O size */
	uint64_t rm_missingdata;	/* Count of missing data devices */
	uint64_t rm_missingparity;	/* Count of missing parity devices */
	uint64_t rm_firstdatacol;	/* First data column/parity count */
	uint64_t rm_nskip;		/* Skipped sectors for padding */
	uint64_t rm_skipstart;	/* Column index of padding start */
	void *rm_datacopy;		/* rm_asize-buffer of copied data */
	uintptr_t rm_reports;		/* # of referencing checksum reports */
    uint32_t  rm_aggre_col;
	uint8_t	rm_freed;		/* map no longer has referencing ZIO */
	uint8_t	rm_ecksuminjected;	/* checksum error was injected */
	raidz_col_t rm_col[1];		/* Flexible array of I/O columns */
} raidz_map_t;

typedef struct tgdva_map {
	dva_t tgm_dva;
	uint64_t tgm_objsetid;
	uint64_t tgm_dnodeid;
	uint64_t tgm_blockid[TG_MAX_DISK_NUM];
} tgdva_map_t;

enum TGDVA_ALLOC_STAT {
	TGDVA_ALLOC_WAITSTART,
	TGDVA_ALLOC_FAIL,
	TGDVA_ALLOC_SUCC,
};

typedef struct aggre_io {
    int ai_ref;
	enum TGDVA_ALLOC_STAT ai_dvaalloc_stat;
	int ai_ioerror;
    kmutex_t ai_lock;
    dva_t   ai_dva[SPA_DVAS_PER_BP];
    void *ai_buf_array[TG_MAX_DISK_NUM];
	tgdva_map_t ai_map;
	int ai_syncdone;
	kmutex_t	ai_synclock;
	kcondvar_t	ai_synccv;
	uint32_t ai_wtoterr;
}aggre_io_t;

typedef struct tg_freebp_entry {
	blkptr_t	tf_blk;
	avl_node_t	tf_avl;
} tg_freebp_entry_t;

#define TGM_INIT_MAP(an_cur_io, aggrnum, objset, object) \
{	\
	bzero(&an_cur_io->ai_dva[0], sizeof(an_cur_io->ai_dva));  \
	mutex_init(&an_cur_io->ai_lock, NULL, MUTEX_DEFAULT, NULL);  \
	an_cur_io->ai_dvaalloc_stat = TGDVA_ALLOC_WAITSTART;  \
	an_cur_io->ai_ioerror = 0; \
	an_cur_io->ai_ref = aggrnum; \
	an_cur_io->ai_map.tgm_objsetid = objset; \
	an_cur_io->ai_map.tgm_dnodeid = object; \
}

#define BP_GET_BLKID(bp)	BF64_GET(bp->blk_pad[1], 0, 7)
#define BP_SET_BLKID(bp,blkid)	BF64_SET(bp->blk_pad[1], 0, 7, blkid);
#define	BP_SET_NTOGTHER(bp)	(bp->blk_pad[1] = 0x00) 

#define	BP_SET_TOGTHER(bp)	(bp->blk_pad[1] |= 0x8000) 
#define BP_IS_TOGTHER(bp)   (((bp)->blk_pad[1] & 0x8000) != 0)
#define BP_SET_CKSUMID(bp,ckid)	BF64_SET(bp->blk_pad[1], 32, 8, ckid);

/*void dbuf_aggre_leaf(list_t * plist_together, uint8_t ntogether);*/
void dbuf_aggre_leaf(void **drarray, uint8_t ntogether);

int raidz_tgbp_compare(const void *a, const void *b);
void raidz_tgbp_combine(tg_freebp_entry_t *a, tg_freebp_entry_t *b);

void raidz_aggre_create_map_obj(spa_t *spa, dmu_tx_t *tx, int aggre_num);
int raidz_aggre_map_open(spa_t *spa);
int raidz_aggre_elem_enqueue_cb(void *arg, void *data, dmu_tx_t *tx);
void raidz_aggre_map_close(spa_t *spa);

void raidz_aggre_elem_init(spa_t *spa, aggre_io_t *aio, 
	aggre_map_elem_t **pelem);


void start_space_reclaim_thread(spa_t *spa);
void stop_space_reclaim_thread(spa_t *spa);

void raidz_aggre_process_dirty_map(spa_t *spa, dmu_tx_t *tx);

void set_aggre_map_process_pos(spa_t *spa, uint64_t pos, uint64_t txg);
boolean_t get_and_clear_aggre_map_process_pos(spa_t *spa, uint64_t txg, uint64_t *ppos);
void update_aggre_map_process_pos(spa_t *spa, uint64_t pos, dmu_tx_t *tx);

extern int raidz_aggre_init(void);
extern void raidz_aggre_fini(void);

#endif

