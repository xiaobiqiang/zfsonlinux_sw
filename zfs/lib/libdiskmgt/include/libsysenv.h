/*
 * Copyright (c) 1994-2011, by Ceresdata, Inc.
 * All Rights Reserved
 */
#ifndef _LIBSYSENV_H
#define	_LIBSYSENV_H


#ifdef __cplusplus
extern "C" {
#endif


#define	SYSENV_FILE				"/etc/prodigy.conf"

#define	CTL_VENDOR				"CONTROLLER_VENDOR"
#define	CTL_TYPE				"CONTROLLER_TYPE"
#define	CTL_AMOUNT				"CONTROLLER_AMOUNT"
#define	CTL_ROLE				"CONTROLLER_ROLE"
#define	CTL_ST_INTERFACE		"CONTROLLER_ST_INTERFACE"
#define	CTL_IB					"CONTROLLER_IB"
#define	CTL_GB					"CONTROLLER_GB"
#define	CTL_10GB				"CONTROLLER_10GB"
#define	CTL_HBA					"CONTROLLER_HBA"
#define	CTL_EX_SAS				"CONTROLLER_EX_SAS"

#define	SYS_CLUSTER			"SYSTEM_CLUSTER"
#define	SYS_FIRMWARE			"SYSTEM_FIRMWARE"
#define	SYS_STMF_KS			"SYSTEM_STMF_KS"
#define	SYS_BOOT				"SYSTEM_BOOT"
#define	SYS_ISCSI_VER			"SYSTEM_ISCSI_VER"

#define	ENC_VENDOR				"ENCLOSURE_VENDOR"
#define	ENC_AMOUNT				"ENCLOSURE_AMOUNT"
#define	ENC_SLOT				"ENCLOSURE_SLOT"
#define	ENC_DISK_TYPE			"ENCLOSURE_DISK_TYPE"
#define	ENC_INTERFACE_TYPE		"ENCLOSURE_INTERFACE_TYPE"
#define	ENC_ENCRYPT_TYPE		"ENCLOSURE_ENCRYPT_TYPE"

typedef struct sysenv
{
	char *name;
	char *value;
}sysenv_t;

int df_savefree(void);
int df_get_envs(sysenv_t **, int);
int df_listenv(void);
int  df_loadsysenv(char *path);
char *df_getsysenv(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* _LIBSYSENV_H */
