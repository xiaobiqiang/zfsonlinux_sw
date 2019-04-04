#ifndef	_CN_HBX_H
#define	_CN_HBX_H

#include <linux/types.h>
#include <linux/connector.h>

#define	CN_IDX_HBX	(CN_NETLINK_USERS + 4)
#define	CN_VAL_HBX	0x4b8

extern int cn_hbx_msg_send(const char *buf, size_t len);

#endif	/* _CN_HBX_H */
