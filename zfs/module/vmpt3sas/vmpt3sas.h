#ifndef __VMPT3SAS_H
#define __VMPT3SAS_H

typedef struct vmpt3sas {
	struct Scsi_Host *shost;
	u8		id;
	char	name[MPT_NAME_LENGTH];
	char	driver_name[MPT_NAME_LENGTH];
	int		logging_level;

	/* receive event handler */
	char		receive_event_name[20];
	taskq_t *receive_event_worker;
	spinlock_t	rc_event_lock;
	struct list_head rc_event_list;
}vmpt3sas_t;


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

#endif
