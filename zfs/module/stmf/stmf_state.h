/*
 * CDDL HEADER START
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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef	_STMF_STATE_H
#define	_STMF_STATE_H

#include <sys/stmf.h>
#include <sys/taskq.h>
#include <sys/id_space.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct stmf_state {
	kmutex_t		stmf_lock;
	kcondvar_t		stmf_cv;
	/* dev_info_t		*stmf_dip; */
	stmf_i_lu_provider_t	*stmf_ilplist;
	stmf_i_port_provider_t	*stmf_ipplist;
	stmf_i_lu_t		*stmf_ilulist;
	stmf_i_local_port_t	*stmf_ilportlist;
	id_space_t		*stmf_ilport_inst_space;
	avl_tree_t		stmf_irportlist;
	id_space_t		*stmf_irport_inst_space;
	avl_tree_t		stmf_itl_kstat_list;
	int			stmf_nlps;
	int			stmf_npps;
	int			stmf_nlus;
	int			stmf_nlports;
	uint8_t			stmf_service_running:1,
				stmf_inventory_locked:1,
				stmf_exclusive_open:1,
				stmf_opened:1,
				stmf_process_initial_luns:1,
				rsvd:3;
	uint8_t			stmf_config_state; /* See stmf_ioctl.h */
	uint8_t			stmf_alua_state;
	uint16_t		stmf_alua_node;
	uint8_t			stmf_default_lu_state;
	uint8_t			stmf_default_lport_state;
	taskq_t			*stmf_svc_taskq;
	taskq_t		*stmf_online_lport;
	uint32_t		stmf_svc_flags;
	stmf_i_lu_t		*stmf_svc_ilu_draining;
	stmf_i_lu_t		*stmf_svc_ilu_timing;
	struct stmf_svc_req	*stmf_svc_active;
	struct stmf_svc_req	**stmf_svc_tailp;

	stmf_id_list_t		stmf_hg_list;
	stmf_id_list_t		stmf_tg_list;
	stmf_id_list_t		stmf_luid_list;

	stmf_ver_tg_t		*stmf_ver_tg_head;

	stmf_pp_data_t		*stmf_ppdlist;

	uint64_t 			stmf_task_abort_total_count;
	uint64_t			stmf_task_abort_stats[MAX_TASK_ABORT_TYPE];
	uint64_t 			stmf_task_done_over_thres;

	kstat_t				*stmf_task_stats;

	kmutex_t			stmf_task_checker_mtx;
	kcondvar_t			stmf_task_checker_cv;
	uint32_t			stmf_task_checker_flag;
	taskq_t				*stmf_task_checker_tq;

	kmutex_t			stmf_qos_mtx;
	kcondvar_t			stmf_qos_cv;
	taskq_t				*stmf_qos_tq;
	uint32_t			stmf_qos_tq_flags;	
} stmf_state_t;

/*
 * svc flags
 */
#define	STMF_SVC_STARTED		1
#define	STMF_SVC_ACTIVE			2
#define	STMF_SVC_TERMINATE		4

/*
 * checker flags
 */
#define	STMF_CHECKER_STARTED	1
#define	STMF_CHECKER_ACTIVE		2
#define	STMF_CHECKER_TERMINATE	4

/*
 * qos checker flags
 */
#define STMF_QOS_CHECKER_STARTED        1
#define STMF_QOS_CHECKER_ACTIVE         2
#define STMF_QOS_CHECKER_TERMINATE      4


/*
 * svc request. We probably have to modify it once more services (and probably
 * different types of services) are added to the stmf_svc_thread.
 */
typedef struct stmf_svc_req {
	struct stmf_svc_req		*svc_next;
	int				svc_req_alloc_size;
	int				svc_cmd;
	void				*svc_obj;
	struct stmf_state_change_info	svc_info;
} stmf_svc_req_t;

extern stmf_state_t stmf_state;

#ifdef	__cplusplus
}
#endif

#endif /* _STMF_STATE_H */
