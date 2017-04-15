#ifndef	_LIBCLUSTER_H
#define	_LIBCLUSTER_H

#include <libzfs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* cluster message queue */
#define	CLUSTER_MQ_NAME		"/MQ_cluster"
#define	CLUSTER_MQ_MSGSIZ	(1024 - 2 * sizeof (int))

enum cluster_mq_msg_type {
	cluster_msgtype_mount,
	cluster_msgtype_umount,
	cluster_msgtype_set_failover,
	cluster_msgtype_remove_failover,
	cluster_msgtype_release
};

typedef struct cluster_mq_message {
	int msgtype;
	int msglen;
	char msg[CLUSTER_MQ_MSGSIZ];
} cluster_mq_message_t;

typedef struct release_pools_message {
	int remote_id;
	int pools_num;
	char *pools_list[ZPOOL_MAXNAMELEN];
} release_pools_message_t;

#ifdef __cplusplus
}
#endif

#endif	/* _LIBCLUSTER_H */
