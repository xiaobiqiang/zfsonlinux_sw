/*
 * Copyright (c) 2015, CeresData,Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBZFS_RPC_H
#define _LIBZFS_RPC_H

#include <rpc/rpc.h>
#include <rpc/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

bool_t xdr_info_string(XDR *xdrsp, char *ppstring);
bool_t xdr_argument(XDR *xdrsp, zfs_rpc_arg_t *sval);
bool_t xdr_backinfo(XDR *xdrsp, zfs_rpc_ret_t *sval);
int get_disks(char *ppstring); 

#define RPC_TRANS_VERS 1

#define	RPC_TRANS_PROG	0x31250099


#define	MAX_SLICES_PER_LUN 9

/*
 * Disk Functions
 */
typedef struct dmg_slice {
	uint64_t start;
	uint64_t blocks;
	int assigned;
	char *mount;
	char *used_by;
	int index;
} dmg_slice_t;

typedef  dmg_slice_t dmg_map_t [MAX_SLICES_PER_LUN];

/* disk logical unit info */
typedef struct dmg_lu {
	char portID[256];
	char osDeviceFile[256];
} dmg_lu_t;

typedef struct dmg_lun {
	char	*name;
	char		*vendor;
	char		*model;
	char		*status;
	uint32_t		rpm;
	uint64_t		en_no;
	uint64_t		lun_no;
	uint64_t 		sas_wwn;
	uint64_t	    lu_flag;
	int		dev_sys;
	int		slice_count;
	uint64_t	blocks;
	uint32_t	bytes_per_block;
	double	gsize;
	char dim[24];
	dmg_map_t	slices;
	int 		lu_num;
	dmg_lu_t	*lu_info;
	struct dmg_lun *lun_next;
} dmg_lun_t;

void* zfs_rpc_server(void);
int zfs_rpc_msg_send(libzfs_handle_t *hdl, uint32_t gettype, char* backinfo);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBZFS_SM_H */

