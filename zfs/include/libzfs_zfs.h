/*
 * CDDL HEADER SART
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_LIBFS_ZFS_H
#define	_LIBFS_ZFS_H

#include <libzfs.h> 

#ifdef	__cplusplus
extern "C" {
#endif

typedef int (*zfs_iter_cb)(zfs_handle_t *, int, void *);

typedef struct zfs_sort_column {
	struct zfs_sort_column	*sc_next;
	struct zfs_sort_column	*sc_last;
	zfs_prop_t		sc_prop;
	char			*sc_user_prop;
	boolean_t		sc_reverse;
} zfs_sort_column_t;

typedef struct callback_data {
	uu_avl_t		*cb_avl;
	int			cb_flags;
	zfs_type_t		cb_types;
	zfs_sort_column_t	*cb_sortcol;
	zprop_list_t		**cb_proplist;
	int			cb_depth_limit;
	int			cb_depth;
	uint8_t			cb_props_table[ZFS_NUM_PROPS];
} callback_data_t;

typedef struct zfs_node {
	zfs_handle_t	*zn_handle;
	uu_avl_node_t	zn_avlnode;
	/*
	 * Depth is zero for all specified (top level) datasets and N for
	 * descendant datasets (visited when the ZFS_ITER_RECURSE flag is set),
	 * where N is the number of parent datasets traversed to reach the top
	 * level dataset.
	 */
	int		zn_depth;
} zfs_node_t;

typedef struct set_cbdata {
	char		*cb_propname;
	char		*cb_value;
} set_cbdata_t;

typedef struct spare_cbdata {
	uint64_t	cb_guid;
	zpool_handle_t	*cb_zhp;
} spare_cbdata_t;

#define	VDEV_LABELS		4
#define	VDEV_UBERBLOCK_RING	(128 << 10)
#define	VDEV_PHYS_SIZE		(112 << 10)  

typedef struct vdev_phys {
	char		vp_nvlist[VDEV_PHYS_SIZE - sizeof (zio_eck_t)];
	zio_eck_t	vp_zbt;
} vdev_phys_t;

typedef struct vdev_label {
	char		vl_pad1[VDEV_PAD_SIZE];			/*  8K	*/
	char		vl_pad2[VDEV_PAD_SIZE];			/*  8K	*/
	vdev_phys_t	vl_vdev_phys;				/* 112K	*/
	char		vl_uberblock[VDEV_UBERBLOCK_RING];	/* 128K	*/
} vdev_label_t;							/* 256K total */

#define	ZFS_RPC_RECURSE	   (1 << 0)
#define	ZFS_RPC_ARGS_CAN_BE_PATHS (1 << 1)
#define	ZFS_RPC_PROP_LISTSNAPS    (1 << 2)
#define	ZFS_RPC_DEPTH_LIMIT	   (1 << 3)
#define	ZFS_RPC_RECVD_PROPS	   (1 << 4)
#define	ZFS_ITER_LITERAL_PROPS	   (1 << 5)

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBFS_ZFS_H */

