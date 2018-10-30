#ifndef __VMPT3SAS_H
#define __VMPT3SAS_H

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
	
}vmpt3sas_t;

typedef struct vmpt3sas_rx_data {
	VMPT_XDR *xdrs;
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
	VMPT_CMD_CTL
} vmpt3sas_remote_cmd_t;

typedef enum vmpt3sas_cmd_state {
	VMPTSAS_CMD_STATE_FREE = 0,
	VMPTSAS_CMD_STATE_PENDING,
	VMPTSAS_CMD_STATE_COMPLETED,
}vmpt3sas_cmd_state_t;


typedef struct vmpt3sas_cmd {
	struct scsi_cmnd	*scmd;
	kmutex_t			cmd_mutex;
	kcondvar_t			cmd_completion;
	vmpt3sas_cmd_state_t	cmd_state;
	uint64_t			req_index;
}vmpt3sas_cmd_t;



#endif
