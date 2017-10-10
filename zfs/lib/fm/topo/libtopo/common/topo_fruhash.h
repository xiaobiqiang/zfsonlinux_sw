#ifndef _TOPO_FRUHASH_H
#define _TOPO_FRUHASH_H


#ifdef __cplusplus
extern "C" {
#endif


#define TOPO_FRUHASH_BUCKETS 100


struct topo_fru {
	struct topo_fru *tf_next;	/* Next module in hash chain */
	char *tf_name;			/* Basename of module */
	time_t tf_time;			/* Full pathname of module file */
	int		tf_status;
	int		tf_ignore;
	uint32_t	err_count;
	uint32_t	nor_count;
	char		*slotid;
	char		*encid;
	char		*diskname;
	char		*product;
};

struct topo_fruhash {
	pthread_mutex_t fh_lock;	/* hash lock */
	struct topo_fru **fh_hash;	/* hash bucket array */
	uint_t fh_hashlen;		/* size of hash bucket array */
	uint_t fh_nelems;		/* number of modules in hash */
};

typedef struct topo_fru topo_fru_t;
typedef struct topo_fruhash topo_fruhash_t;

topo_fruhash_t *topo_get_fruhash(void);
topo_fru_t *topo_fru_setime(const char *name, int status, char *diskname,
		char *slotid, char *encid, char *product);
topo_fru_t *topo_fru_hash_lookup(const char *name);
topo_fru_t *topo_fru_cleartime(const char *name, int status);
void topo_fru_hash_create(void);
void topo_fru_hash_destroy(void);

#ifdef	__cplusplus
}
#endif

#endif		
