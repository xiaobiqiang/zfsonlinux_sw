#ifndef __VMPT3SAS_H
#define __VMPT3SAS_H

#define MPT_NAME_LENGTH			32	/* generic length of strings */

typedef struct vmpt3sas {
	struct Scsi_Host *shost;
	u8		id;
	char	name[MPT_NAME_LENGTH];
	char	driver_name[MPT_NAME_LENGTH];
	int		logging_level;

	mod_hash_t	*vmpt_cmd_wait_hash;

	/* receive event handler */
	char		tq_req_name[20];
	taskq_t *tq_req;
	char		tq_rsp_name[20];
	taskq_t *tq_rsp;
	char		tq_ctl_name[20];
	taskq_t *tq_ctl;
	void * session;
	u32 remotehostno;
	u32 remotehostid;
	u64 req_index;
	
}vmpt3sas_t;

typedef struct vmpt3sas_rx_data {
	XDR *xdrs;
	cs_rx_data_t *cs_data;
}vmpt3sas_rx_data_t;


typedef struct vmpt3sas_cts_link_stata_evt {
	void *sess;
	cts_link_evt_t link_evt;
	void *arg;
}vmpt3sas_cts_link_stata_evt_t;


typedef enum vmpt3sas_remote_cmd {
	VMPT_CMD_REQUEST,
	VMPT_CMD_RSP,
	VMPT_CMD_CTL,
	VMPT_CMD_ADDHOST,
	VMPT_CMD_SELFUP
} vmpt3sas_remote_cmd_t;

typedef enum vmpt3sas_cmd_state {
	VMPTSAS_CMD_STATE_FREE = 0,
	VMPTSAS_CMD_STATE_PENDING,
	VMPTSAS_CMD_STATE_COMPLETED,
}vmpt3sas_cmd_state_t;

typedef struct vmpt3sas_req_scmd {
	uint64_t req_index;
	unsigned int host;
	unsigned int id;
	unsigned int lun;
	unsigned int channel;
	int data_direction;
	unsigned int cmd_len;
	char cmnd[16];
	unsigned int response; 
	char sense[24];
	unsigned int datalen;
	char *dataarr[32];
	int lendataarr[32];
	int ndata;
	void *session;
	void *shost;
}vmpt3sas_req_scmd_t;

typedef struct req_list {
	struct list_head queuelist;
	struct request *req;
}req_list_t;

typedef struct req_proxy {
	spinlock_t queue_lock;
	struct list_head done_queue;
	wait_queue_head_t waiting_wq;
	struct task_struct *thread;
}req_proxy_t;

typedef struct vmptsas_quecmd {
	struct list_head list;
	struct list_head donelist;
	struct Scsi_Host *shost;
	struct scsi_cmnd *scmd;
	int index;
}vmptsas_quecmd_t;

typedef struct vmptsas_instance {
	spinlock_t hba_lock;
	vmptsas_quecmd_t **cmd_list;
	struct list_head cmd_pool;
	int max_cmds;
	req_proxy_t qcmdproxy;
	req_proxy_t dcmdproxy;
	
	taskq_t *tq_common;
	taskq_t *tq_pexec;
	
}vmptsas_instance_t;


typedef struct vmptsas_hostmap {
	struct Scsi_Host *shost;
	int remote_hostno;
	int index;
	int hostid;
}vmptsas_hostmap_t;


#endif
