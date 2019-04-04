#ifndef _FMD_DATA_H
#define _FMD_DATA_H

#include <linux/types.h>
#include <linux/connector.h>
#include <sys/kmem.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum fmd_type {
	FMD_NOTE = 1 << 0,
	FMD_WARN = 1 << 1,
	FMD_DISK_ERR = 1 << 2,
	FMD_HOTPLUG = 1 << 3,
	FMD_DEFAULT = 1 << 4
} fmd_type_t;

typedef struct fmd_msg {
	fmd_type_t fm_type;
	int		   fm_len;
	char	   *fm_buf;
} fmd_msg_t;

typedef void (*fmd_msg_callback)(void *fmsg);

#ifdef _KERNEL
extern fmd_msg_t *fmd_kernel_msg_new(int len);
extern void fmd_kernel_msg_free(fmd_msg_t *fmsg);
#else
extern fmd_msg_t *fmd_msg_new(int len);
extern void fmd_msg_free(fmd_msg_t *fmsg);
#endif

extern int fmd_module_is_exit(void);
extern void fmd_transport_client_register(fmd_msg_callback do_msg_handle);
extern void fmd_transport_client_deregister(void);
extern void fmd_client_send_msg(const fmd_msg_t *fmsg);

extern int fmd_kernel_send_msg(const fmd_msg_t *fmsg);

#define NETLINK_FMD	25
#define FMD_NET_GROUP (CN_NETLINK_USERS + 5)
#define FMD_NET_PID	 100

#ifdef	__cplusplus
}
#endif

#endif /* _FMD_DATA_H */
