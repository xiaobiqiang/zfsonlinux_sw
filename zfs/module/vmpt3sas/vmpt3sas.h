#ifndef __VMPT3SAS_H
#define __VMPT3SAS_H

typedef struct vmptsas_cts_link_stata_evt {
	void *sess;
	cts_link_evt_t link_evt;
	void *arg;
}vmptsas_cts_link_stata_evt_t;


typedef enum vmptsas_remote_cmd {
	VMPT_CMD_REQUEST,
	VMPT_CMD_RSP,
	VMPT_CMD_CTL
} vmptsas_remote_cmd_t;

#endif
