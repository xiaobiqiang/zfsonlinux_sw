#ifndef _IMPTSAS_IOCTL_H
#define _IMPTSAS_IOCTL_H

#define	IMPT_IOC		('T' << 8)

typedef enum impt_ioc {
	IMPT_IOC_ADD_PATH_TEST = IMPT_IOC,
	IMPT_IOC_FREE_PATH_TEST,
	IMPT_IOC_OFFLINE_TEST,
	IMPT_IOC_ONLINE_TEST,
	IMPT_IOC_STANDBY_TEST,
	IMPT_IOC_GET_PATH,
	IMPT_IOC_TRAN_RESET,
#ifdef DEBUG
	IMPT_IOC_DEBUG_LEVEL,
#endif
}impt_ioc_t;

typedef struct impt_test_cmd {
	char lun_addr[256];
	char guid[18];
	int target;
	int ncompatible;
	char compatible[4][256];
	char nodename[256];
}impt_test_cmd_t;

#endif /* _IMPTSAS_IOCTL_H */

