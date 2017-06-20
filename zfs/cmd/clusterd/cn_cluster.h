#ifndef	_CN_CLUSTER_H
#define	_CN_CLUSTER_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef	void (*cn_cluster_rcvfunc)(void *, int);

extern int cn_cluster_init(cn_cluster_rcvfunc rcv_func);

#ifdef	__cplusplus
}
#endif

#endif	/* _CN_CLUSTER_H */
