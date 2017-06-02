/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBSPL_LIBDEVINFO_H

#include <devid.h>
#include <sys/dkio.h>
#include <sys/types.h>
#include <sys/dktp/fdisk.h>
#include <sys/rrwlock.h>
#include <sys/sunddi.h>
#include <libdiskmgt.h>

typedef enum {
	DI_PATH_STATE_UNKNOWN,
	DI_PATH_STATE_OFFLINE,
	DI_PATH_STATE_STANDBY,
	DI_PATH_STATE_ONLINE,
	DI_PATH_STATE_FAULT
} di_path_state_t;

#define OPROMMAXPARAM   32768
#define	OBP_MAXBUF	OPROMMAXPARAM - sizeof (int)
#define	OBP_MAXPROPLEN	OBP_MAXBUF - OBP_MAXPROPNAME;

#define	DI_PATH_NIL		NULL
#define	DI_NODE_NIL		NULL
#define	DI_PROM_HANDLE_NIL	NULL

#define	DI_PRIMARY_LINK		0x01
#define	DI_SECONDARY_LINK	0x02
#define	DI_LINK_TYPES		0x03

#define	DI_WALK_CONTINUE	0
#define	DI_WALK_PRUNESIB	-1
#define	DI_WALK_PRUNECHILD	-2
#define	DI_WALK_TERMINATE	-3

#define	DIIOC		(0xdf<<8)
#define	DINFOSUBTREE	(DIIOC | 0x01)	/* include subtree */
#define	DINFOMINOR	(DIIOC | 0x02)	/* include minor data */
#define	DINFOPROP	(DIIOC | 0x04)	/* include properties */
#define	DINFOPATH	(DIIOC | 0x08)	/* include i/o pathing information */
#define	DINFOUSRLD	(DIIOC | 0x80)	/* copy snapshot to usrland */
#define	DINFOLODRV	(DIIOC | 0x81)	/* force load a driver */
#define	DINFOIDENT	(DIIOC | 0x82)	/* identify the driver */
#define	DINFOCACHE	(DIIOC | 0x100000) /* use cached data  */
#define	DINFOCPYALL	(DINFOSUBTREE | DINFOPROP | DINFOMINOR)

#define	DDI_NT_SCSI_NEXUS	"ddi_ctl:devctl:scsi"	/* nexus drivers */
#define	DDI_NT_SCSI_ATTACHMENT_POINT	"ddi_ctl:attachment_point:scsi"
#define	DDI_NT_FC_ATTACHMENT_POINT	"ddi_ctl:attachment_point:fc"

/* openpromio.h */
struct openpromio {
	uint_t	oprom_size;		/* real size of following array */
	union {
		char	b[1];		/* For property names and values */
					/* NB: Adjacent, Null terminated */
		int	i;
	} opio_u;
};

struct di_prom_prop {
	char *name;
	int len;
	uchar_t *data;
	struct di_prom_prop *next;	/* form a linked list */
};

struct di_prom_handle { /* handle to prom */
	kmutex_t lock;	/* synchronize access to openprom fd */
	int	fd;	/* /dev/openprom file descriptor */
	struct di_prom_prop *list;	/* linked list of prop */
	union {
		char buf[OPROMMAXPARAM];
		struct openpromio opp;
	} oppbuf;
};

/* devinfo_devlink.h */

struct db_link {
	uint32_t attr;		/* primary or secondary */
	uint32_t path;		/* link path */
	uint32_t content;	/* link content */
	uint32_t sib;		/* next link for same minor */
};

struct db_minor {
	uint32_t name;		/* minor name */
	uint32_t nodetype;	/* minor node type */
	uint32_t sib;		/* next minor for same node */
	uint32_t link;		/* next minor for same node */
};

struct db_node {
	uint32_t path;		/* node path */
	uint32_t sib;		/* node's sibling */
	uint32_t child;		/* first child for this node */
	uint32_t minor;		/* first minor for node */
};

typedef enum db_seg {
	DB_NODE = 0,
	DB_MINOR,
	DB_LINK,
	DB_STR,
	DB_TYPES,	/* Number of non-header segments */
	DB_HEADER
} db_seg_t;

struct db_hdr {
	uint32_t magic;			/* Magic number	*/
	uint32_t vers;			/* database format version */
	uint32_t root_idx;		/* index for root node */
	uint32_t dngl_idx;		/* head of DB dangling links */
	uint32_t page_sz;		/* page size for mmap alignment	*/
	uint32_t update_count;		/* updates since last /dev synch up */
	uint32_t nelems[DB_TYPES];	/* Number of elements of each type */
};


typedef	struct cache_link {
	char   *path;			/* link path */
	char   *content;		/* link content	*/
	uint_t attr;			/* link attributes */
	struct cache_link *hash;	/* next link on same hash chain */
	struct cache_link *sib;		/* next link for same minor */
	struct cache_minor *minor;	/* minor for this link */
} cache_link_t;

typedef	struct cache_minor {
	char *name;			/* minor name */
	char *nodetype;			/* minor nodetype */
	struct cache_node *node;	/* node for this minor */
	struct cache_minor *sib;	/* next minor for same node */
	struct cache_link *link;	/* first link pointing to minor */
} cache_minor_t;

typedef struct cache_node {
	char	*path;			/* path	*/
	struct cache_node *parent;	/* node's parent */
	struct cache_node *sib;		/* node's sibling */
	struct cache_node *child;	/* first child for this node */
	struct cache_minor *minor;	/* first minor for node */
} cache_node_t;

struct cache {
	uint_t	flags;			/* cache state */
	uint_t	update_count;		/* updates since /dev synchronization */
	uint_t	hash_sz;		/* number of hash chains */
	cache_link_t **hash;		/* hash table */
	cache_node_t *root;		/* root of cache tree */
	cache_link_t *dngl;		/* list of dangling links */
	cache_minor_t *last_minor;	/* last minor looked up	*/
};

struct db {
	int db_fd;			/* database file */
	uint_t flags;			/* database open mode */
	struct db_hdr *hdr;		/* DB header */
	int  seg_prot[DB_TYPES];	/* protection for  segments */
	caddr_t seg_base[DB_TYPES];	/* base address for segments */
};

struct di_devlink_handle {
	char *dev_dir;			/* <root-dir>/dev */
	char *db_dir;			/* <root-dir>/etc/dev */
	uint_t	flags;			/* handle flags	*/
	uint_t  error;			/* records errors encountered */
	int lock_fd;			/* lock file for updates */
	struct cache cache;
	struct db db;
};

typedef struct di_node		*di_node_t;		/* node */
typedef struct di_minor		*di_minor_t;		/* minor_node */
typedef struct di_path		*di_path_t;		/* path_node */
typedef struct di_link		*di_link_t;		/* link */
typedef struct di_lnode		*di_lnode_t;		/* endpoint */
typedef struct di_devlink	*di_devlink_t;		/* devlink */
typedef struct di_hp		*di_hp_t;		/* hotplug */

typedef struct di_prop		*di_prop_t;		/* node property */
typedef struct di_path_prop	*di_path_prop_t;	/* path property */
typedef struct di_prom_prop	*di_prom_prop_t;	/* prom property */

typedef struct di_prom_handle	*di_prom_handle_t;	/* prom snapshot */
typedef struct di_devlink_handle *di_devlink_handle_t;	/* devlink snapshot */

#define	_LIBSPL_LIBDEVINFO_H

#endif /* _LIBSPL_LIBDEVINFO_H */
