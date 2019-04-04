#include <sys/ddi.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/in.h>  
#include <linux/inet.h>  
#include <linux/socket.h>  
#include <net/sock.h>
#include <sys/taskq.h>
#include <sys/list.h>
#include <sys/cluster_san.h>
#include <sys/cluster_target_socket.h>
#include <sys/fs/zfs.h>
static void cts_socket_fragment_free(cts_fragment_data_t *fragment);
static void cts_socket_hb_fini(cluster_target_session_t *cts);
static int
cluster_target_socket_send(void *port, void *fragmentation)
{
	cmn_err(CE_WARN, "%s: never come here!", __func__);
	return (0);
}

static void cluster_target_socket_tran_data_free(void *fragmentation)
{
	cmn_err(CE_WARN, "%s: never come here!", __func__);
}

static int cluster_target_socket_tran_data_fragment(
	void *src, void *dst, cluster_tran_data_origin_t *origin_data,
	cluster_target_tran_data_t **fragmentations, int *cnt)
{
	cmn_err(CE_WARN, "%s: never come here!", __func__);
	return (-1);
}

static int cts_socket_tran_start(cluster_target_session_t *cts, void *fragmentation)
{
    int ret = 0;
    struct msghdr msg;
    struct kvec vec[3];
    cluster_tran_data_origin_t *origin_data = fragmentation;
    cluster_target_session_socket_t *sess_socket = cts->sess_target_private; 
    cluster_target_msg_header_t * ct_head = kmem_zalloc(sizeof(cluster_target_msg_header_t),KM_SLEEP);
    
	ct_head->msg_type = origin_data->msg_type;
	ct_head->index = origin_data->index;
    ct_head->len = origin_data->data_len;
    ct_head->ex_len = origin_data->header_len;
    ct_head->total_len = origin_data->data_len;
    ct_head->offset = 0;

    memset(&msg, 0, sizeof(struct msghdr));
    memset(&vec, 0, 3*sizeof(struct kvec));
    
    vec[0].iov_base = ct_head;
    vec[0].iov_len = sizeof(cluster_target_msg_header_t);
    mutex_enter(&sess_socket->s_lock);
    if (sess_socket->s_socket) {
        if (origin_data->header_len == 0) {
            vec[1].iov_base = origin_data->data;
            vec[1].iov_len = origin_data->data_len;
            ret = kernel_sendmsg(sess_socket->s_socket, &msg, vec, 2, 
                        sizeof(cluster_target_msg_header_t) + ct_head->total_len);
        } else {
            vec[1].iov_base = origin_data->header;
            vec[1].iov_len = origin_data->header_len;
            vec[2].iov_base = origin_data->data;
            vec[2].iov_len = origin_data->data_len;
            ret = kernel_sendmsg(sess_socket->s_socket, &msg, vec, 3, 
                        sizeof(cluster_target_msg_header_t) + ct_head->ex_len + ct_head->total_len);
        }
    } else {
        ret = -1;
    }
    mutex_exit(&sess_socket->s_lock);
    kmem_free(ct_head, sizeof(cluster_target_msg_header_t));
    
    if (ret < 0) {
        cv_broadcast(&cts->sess_cv);
        printk("%s link should be down\n", __func__);
        return ret;  
    } else if (ret != sizeof(cluster_target_msg_header_t) + origin_data->header_len + origin_data->data_len) {
        cv_broadcast(&cts->sess_cv);
        printk("%s: ret=%d, should = %d\n", __func__, ret, 
            (int)(sizeof(cluster_target_msg_header_t)+origin_data->header_len+origin_data->data_len));  
        return ret;
    } else
        return 0;
}

cts_fragment_data_t *
cts_socket_rxframe_to_fragment (void *target_port, void *rx_msg)
{
    cts_fragment_data_t *fragment;
    cluster_target_msg_header_t *ct_head = rx_msg;
    cluster_target_port_t *ctp = target_port;
    

    fragment = kmem_zalloc(sizeof(cts_fragment_data_t), KM_SLEEP);
    fragment->target_port = ctp;
    fragment->rx_msg = rx_msg;
	fragment->len = ct_head->len;
	fragment->ex_len = ct_head->ex_len;
	fragment->ct_head = ct_head;
    if (ct_head->ex_len) {
        fragment->ex_head = rx_msg + sizeof(cluster_target_msg_header_t);
    }
    fragment->offset = 0; 
    fragment->data = rx_msg + sizeof(cluster_target_msg_header_t) + fragment->ex_len;
    //printk("%s len=%d, ex_len=%d, t_len=%d, type=%d\n", __func__, ct_head->len, ct_head->ex_len,ct_head->total_len, ct_head->msg_type);
    return fragment;
}

static void cts_socket_rcv_thread(void *arg)
{
    cluster_target_session_t *cts = arg;
    cluster_target_port_t *ctp = cts->sess_port_private;
    cluster_target_session_socket_t *sess_socket = cts->sess_target_private;
    cluster_san_hostinfo_t *cshi = cts->sess_host_private;
    cts_worker_para_t *para = NULL;
	cts_fragment_data_t *fragment = NULL;
    cts_rx_worker_t	*host_rxworker;
    struct socket *r_socket = NULL;
    static unsigned int local_index = 0;

    int ret;
    int index = 0;
    struct msghdr msg;
    struct kvec vec;
    char *recvbuf=NULL;  

    while (atomic_read(&sess_socket->rcv_thread_stop) == 0) {
        
        mutex_enter(&sess_socket->r_lock);
        if (sess_socket->r_socket == NULL) {
            cv_wait(&sess_socket->socket_cv, &sess_socket->r_lock);
        }
        r_socket = sess_socket->r_socket;
        mutex_exit(&sess_socket->r_lock);
        if (r_socket == NULL)
            continue;
        
        recvbuf=kzalloc(2*1024*1024,KM_SLEEP);
        memset(&vec,0,sizeof(vec));  
        memset(&msg,0,sizeof(msg));  
        vec.iov_base=recvbuf;  
        vec.iov_len=sizeof(cluster_target_msg_header_t); 
        
        index = ret=kernel_recvmsg(r_socket ,&msg,&vec,1,sizeof(cluster_target_msg_header_t),0); 
        if (ret <= 0) {
            mutex_enter(&sess_socket->r_lock);
            sock_release(r_socket);
            
            if (r_socket == sess_socket->r_socket) {
                r_socket = sess_socket->r_socket = NULL;
            } else {
                r_socket = NULL;
            }
            mutex_exit(&sess_socket->r_lock);
            kfree(recvbuf);
            printk("%s %d kernel_recvmsg error. (ret = %d)\n", __func__, __LINE__, ret);
            continue;
        }
retry_h:
        if (index != sizeof(cluster_target_msg_header_t)) {
            printk("%s index %d\n", __func__, index);
            memset(&vec,0,sizeof(vec)); 
            memset(&msg,0,sizeof(msg)); 
            vec.iov_base=recvbuf+index;  
            vec.iov_len=sizeof(cluster_target_msg_header_t) - index;
            ret=kernel_recvmsg(r_socket ,&msg,&vec,1,vec.iov_len,0); 
            if (ret <= 0) {
                mutex_enter(&sess_socket->r_lock);
                sock_release(r_socket);
                if (r_socket == sess_socket->r_socket) {
                    r_socket = sess_socket->r_socket = NULL;
                } else {
                    r_socket = NULL;
                }
                mutex_exit(&sess_socket->r_lock);
                cts_socket_fragment_free(fragment);
                printk("%s %d kernel_recvmsg error\n", __func__, __LINE__);
                continue;
            }
            index += ret;
            goto retry_h;
        }
        fragment = cts_socket_rxframe_to_fragment(ctp, recvbuf);
        if (fragment->ct_head->msg_type == CLUSTER_SAN_MSGTYPE_HB) {
            cts_socket_fragment_free(fragment);
            continue;
        }
retry:
        if (index < fragment->ex_len + fragment->len + sizeof(cluster_target_msg_header_t)) {
            memset(&vec,0,sizeof(vec));  
            memset(&msg,0,sizeof(msg)); 
            vec.iov_base=recvbuf+index;  
            vec.iov_len=fragment->ex_len + fragment->len + sizeof(cluster_target_msg_header_t) - index; 
            ret=kernel_recvmsg(r_socket ,&msg,&vec,1,vec.iov_len,0); 
            if (ret <= 0) {
                mutex_enter(&sess_socket->r_lock);
                sock_release(r_socket);
                
                if (r_socket == sess_socket->r_socket) {
                    r_socket = sess_socket->r_socket = NULL;
                } else {
                    r_socket = NULL;
                }
                mutex_exit(&sess_socket->r_lock);
                cts_socket_fragment_free(fragment);
                printk("%s %d kernel_recvmsg error\n", __func__, __LINE__);
                continue;
            }
            index += ret;
            goto retry;
        } else if (index > fragment->ex_len + fragment->len + sizeof(cluster_target_msg_header_t)) {
            printk("%s index%d actual=%d\n", __func__, index, 
                (int)(fragment->ex_len+fragment->len+sizeof(cluster_target_msg_header_t)));
            VERIFY(0);
        }
        //printk("%s index %d\n", __func__, index);
        
        para = kmem_zalloc(sizeof(cts_worker_para_t), KM_SLEEP);
        para->fragment = fragment;
        host_rxworker =
    		&cshi->host_rx_worker[(local_index++) % cshi->host_rx_worker_n];
    	para->worker = host_rxworker;
    	cts_rx_worker_wakeup(host_rxworker, para);
    	//kmem_free(para, sizeof(cts_worker_para_t));
        //cts_socket_fragment_free(fragment);
    } 
    if (sess_socket->r_socket != NULL) {
        sock_release(sess_socket->r_socket);
        sess_socket->r_socket = NULL;
    }
}

static void cluster_target_socket_session_init(cluster_target_session_t *cts, void *phy_head)
{
    cluster_target_socket_param_t *param = phy_head;
    cluster_target_session_socket_t *sess_socket;
    cluster_target_port_t *ctp = cts->sess_port_private;
    cluster_target_port_socket_t *port_socket = ctp->target_private;
    char buf[256]={0};

    sess_socket = kzalloc(sizeof(cluster_target_session_socket_t), GFP_KERNEL);
    sess_socket->param = param;
    sess_socket->socket_link_state = 0;
    if (param->priority != 0) {
        cts->sess_pri = param->priority;
    }
    sess_socket->s_socket = NULL;
    
    mutex_init(&sess_socket->s_lock, NULL, MUTEX_DRIVER, NULL);
    mutex_init(&sess_socket->r_lock, NULL, MUTEX_DRIVER, NULL);
    cv_init(&sess_socket->socket_cv, NULL, CV_DRIVER, NULL);
    
    memset(&sess_socket->s_addr,0,sizeof(sess_socket->s_addr));  
    sess_socket->s_addr.sin_family=AF_INET;  
    sess_socket->s_addr.sin_port=htons(param->port);  

   
    sess_socket->s_addr.sin_addr.s_addr=in_aton(param->ipaddr);
    
    printk("%s port=%d ip=%s\n", __func__, param->port, param->ipaddr);

    cts->sess_target_private = sess_socket;
    /* create receive thread */
    sprintf(buf, "rcv_tq_%s", sess_socket->param->ipaddr);
    sess_socket->rcv_tq = taskq_create(buf,
		1, minclsyspri, 1, 1, TASKQ_PREPOPULATE);

    cv_broadcast(&port_socket->css_cv);
    atomic_set(&sess_socket->rcv_thread_stop ,0);
    taskq_dispatch(sess_socket->rcv_tq, cts_socket_rcv_thread, (void *)cts, TQ_SLEEP);
}

static void cluster_target_socket_session_fini(cluster_target_session_t *cts)
{
    cluster_target_session_socket_t *sess_socket = cts->sess_target_private;

    atomic_set(&sess_socket->rcv_thread_stop ,1);
    
    mutex_enter(&sess_socket->r_lock);
    if (sess_socket->r_socket) {
        kernel_sock_shutdown(sess_socket->r_socket, SHUT_RDWR);
    }
    cv_broadcast(&sess_socket->socket_cv);
    mutex_exit(&sess_socket->r_lock);
    taskq_destroy(sess_socket->rcv_tq);

    cts_socket_hb_fini(cts);

    cv_destroy(&sess_socket->socket_cv);
    mutex_destroy(&sess_socket->r_lock);
    mutex_destroy(&sess_socket->s_lock);
    kfree(sess_socket);
}

static void cts_socket_fragment_free(cts_fragment_data_t *fragment)
{
    if (fragment) {
        if (fragment->rx_msg)
            kfree(fragment->rx_msg);
        kmem_free(fragment, sizeof(cts_fragment_data_t));
    }
}

static void cluster_target_socket_rxmsg_free(void *rx_msg)
{
    if (rx_msg)
        kfree(rx_msg);
}

static int cts_socket_compare(cluster_target_session_t *cts, void *phy_head)
{
    cluster_target_session_socket_t *sess_socket = cts->sess_target_private;
    cluster_target_socket_param_t *param = phy_head;

    if (strcmp(param->hostname, sess_socket->param->hostname) == 0) {
        if (strcmp(param->ipaddr, sess_socket->param->ipaddr) == 0) {
            if (param->port == sess_socket->param->port)
                return 0;
        }
    }
    return 1;
}

static void ctp_socket_get_info(void *target_port, nvlist_t *nvl_target)
{
}

static void cts_socket_get_info(cluster_target_session_t *cts, nvlist_t *nvl_sess)
{
}
typedef struct client_arg
{
    cluster_target_port_t *ctp;
    struct socket *client_sock;
}client_arg_t;
static void cts_socket_set_client_socket(void *arg)
{ 
    client_arg_t * client_arg = arg;
    cluster_target_port_t *ctp = client_arg->ctp;
    struct socket *client_sock = client_arg->client_sock;
    cluster_target_port_socket_t *port_socket = ctp->target_private;
    
    int ret;
	int len=0;
    struct sockaddr addr;
    cluster_target_session_socket_t *sess_socket;
    cluster_target_session_t *cts;

    kfree(arg);

    ret = kernel_getpeername(client_sock, (struct sockaddr *)&addr, &len);
    if(ret <0) {
	    printk("kernel_getpeername error!\n");
        sock_release(client_sock);
        return ;
    } else {
        printk("client socket ip addr:%d.%d.%d.%d\n", 
            (unsigned char)addr.sa_data[2],
            (unsigned char)addr.sa_data[3],
            (unsigned char)addr.sa_data[4],
            (unsigned char)addr.sa_data[5]);
    }
    
    
    while(atomic_read(&port_socket->accept_thread_stop) == 0) {
        
        mutex_enter(&ctp->ctp_lock);
        cts = list_head(&ctp->ctp_sesslist);
	    while (cts != NULL) {
            sess_socket = cts->sess_target_private;
            if (bcmp(&(addr.sa_data[2]), &(sess_socket->s_addr.sin_addr.s_addr), 4) == 0) {
                break;
            }
	    }
        mutex_exit(&ctp->ctp_lock);
        
        if (cts != NULL) {
            sess_socket = cts->sess_target_private;
            mutex_enter(&sess_socket->r_lock);
            if (atomic_read(&sess_socket->rcv_thread_stop) == 0) {
                if (sess_socket->r_socket) {
                    kernel_sock_shutdown(sess_socket->r_socket, SHUT_RDWR);
                }
                sess_socket->r_socket = client_sock;
                client_sock = NULL;
                mutex_exit(&sess_socket->r_lock);
                cv_broadcast(&sess_socket->socket_cv);
                printk("%s client ok \n", __func__);
            } else {
                mutex_exit(&sess_socket->r_lock);
            }
            break;
        } else {
            mutex_enter(&port_socket->css_lock);
            cv_timedwait(&port_socket->css_cv,&port_socket->css_lock,
                ddi_get_lbolt() + drv_usectohz(1000 * 1000));
            mutex_exit(&port_socket->css_lock);
        }
    }

    if (client_sock)
        sock_release(client_sock);
    
}
static void cts_socket_accept_thread(void *arg)
{
    cluster_target_port_t *ctp = arg;
    cluster_target_port_socket_t *port_socket = ctp->target_private;
    struct socket *client_sock;
    int ret;
    client_arg_t * client_arg;

    while (atomic_read(&port_socket->accept_thread_stop) == 0) {
        ret = kernel_accept(port_socket->srv_socket, &client_sock, 16);
        if(ret<0){  
            printk("%s:accept error. (ret = %d)\n", __func__, ret);
            continue;
        } else {
            printk("server: accept ok, Connection Established\n");
        }
        client_arg = kzalloc(sizeof(client_arg_t), GFP_KERNEL);
        client_arg->client_sock = client_sock;
        client_arg->ctp = ctp;
        taskq_dispatch(port_socket->accept_tq, cts_socket_set_client_socket, (void *)client_arg,TQ_SLEEP);
    }
}

int cluster_target_socket_port_init(
	cluster_target_port_t *ctp, char *link_name, nvlist_t *nvl_conf)
{
    char *ipaddr = NULL;
    int port = 1866;
    int link_pri = 0;
    int ret;
    char buf[256]={0};
    cluster_target_port_socket_t *port_socket;
    struct sockaddr_in s_addr;

    if (nvl_conf != NULL) {
        if (nvlist_lookup_string(nvl_conf, "ipaddr", &ipaddr) != 0) {
            return (-1);
        }
        if (nvlist_lookup_int32(nvl_conf, "port", &port) != 0) {
            port = 1866;
        }
        if (nvlist_lookup_int32(nvl_conf, "link_pri", &link_pri) == 0) {
			if (link_pri != 0) {
				ctp->pri = link_pri;
			}
		}
    } else {
        printk("must give ip addr!\n");
        return (-1);
    }

    port_socket = kzalloc(sizeof(cluster_target_port_socket_t),
		KM_SLEEP);
    
    mutex_init(&port_socket->stop_lock, NULL, MUTEX_DRIVER, NULL);
    mutex_init(&port_socket->css_lock, NULL, MUTEX_DRIVER, NULL);
    cv_init(&port_socket->css_cv, NULL, CV_DRIVER, NULL);

    port_socket->port = port;
    strcpy(port_socket->ipaddr, ipaddr);

    printk("%s port=%d ip=%s\n", __func__, port, port_socket->ipaddr);

    ret=sock_create(AF_INET, SOCK_STREAM,0,&(port_socket->srv_socket));
    if(ret){
        printk("server:socket_create error! (ret = %d)\n", ret);
        goto err1;
    }
    
    memset(&s_addr,0,sizeof(s_addr));  
    s_addr.sin_family=AF_INET;  
    s_addr.sin_port=htons(port_socket->port);  
    s_addr.sin_addr.s_addr=htonl(INADDR_ANY);
     
    ret = kernel_bind(port_socket->srv_socket,
        (struct sockaddr *)&s_addr,sizeof(struct sockaddr_in));  
    if(ret<0){  
        printk("server: bind error. (ret = %d)\n", ret);
        goto err2;
    }  

    
    ret = kernel_listen(port_socket->srv_socket, 16);
    if(ret<0){  
        printk("server: listen error. (ret = %d)\n", ret); 
        goto err2;
    }  

	ctp->f_send_msg = cluster_target_socket_send;
	ctp->f_tran_free = cluster_target_socket_tran_data_free;
	ctp->f_tran_fragment = cluster_target_socket_tran_data_fragment;
	ctp->f_session_tran_start = cts_socket_tran_start;
	ctp->f_session_init = cluster_target_socket_session_init;
	ctp->f_session_fini = cluster_target_socket_session_fini;
	ctp->f_rxmsg_to_fragment = cts_socket_rxframe_to_fragment;
	ctp->f_fragment_free = cts_socket_fragment_free;
	ctp->f_rxmsg_free = cluster_target_socket_rxmsg_free;
	ctp->f_cts_compare = cts_socket_compare;
	ctp->f_ctp_get_info = ctp_socket_get_info;
	ctp->f_cts_get_info = cts_socket_get_info;

    strcpy(buf, "client_arg");
    strcpy(buf+strlen(buf), port_socket->ipaddr);
    port_socket->accept_tq = taskq_create(buf,
		16, minclsyspri, 1, 16, TASKQ_PREPOPULATE);

	ctp->target_private = port_socket;

    atomic_set(&port_socket->accept_thread_stop ,0);

    taskq_dispatch(port_socket->accept_tq, cts_socket_accept_thread, (void *)ctp, TQ_SLEEP);

	return (0);
err2:
    sock_release(port_socket->srv_socket);
err1:
    kmem_free(port_socket, sizeof(cluster_target_port_socket_t));
    return (-1);
}
void cluster_target_socket_port_fini(cluster_target_port_t *ctp)
{
    cluster_target_port_socket_t *port_socket = ctp->target_private;

    atomic_set(&port_socket->accept_thread_stop ,1);
    kernel_sock_shutdown(port_socket->srv_socket, SHUT_RDWR);
    cv_broadcast(&port_socket->css_cv);
    taskq_destroy(port_socket->accept_tq);

    sock_release(port_socket->srv_socket);
    cv_destroy(&port_socket->css_cv);
    mutex_destroy(&port_socket->css_lock);
    mutex_destroy(&port_socket->stop_lock);
    kfree(port_socket);
}

static void cts_socket_hb_thread(void *arg)
{
    cluster_target_session_t *cts = arg;
	cluster_target_session_socket_t *sess_socket = cts->sess_target_private;
	int ret=0;
    struct msghdr msg;
    struct kvec vec;
    cluster_target_msg_header_t  ct_head;
    
	ct_head.msg_type = CLUSTER_SAN_MSGTYPE_HB;
	ct_head.index = 0;
    ct_head.len = 0;
    ct_head.ex_len = 0;
    ct_head.total_len = 0;
    
	mutex_enter(&cts->sess_lock);
	cts->sess_hb_state |= CLUSTER_TARGET_TH_STATE_ACTIVE;
	while ((cts->sess_hb_state & CLUSTER_TARGET_TH_STATE_STOP) == 0) {
        if (cts->sess_linkstate == CTS_LINK_DOWN) {
            mutex_exit(&cts->sess_lock);
            
            if (sess_socket->s_socket != NULL) {
                sock_release(sess_socket->s_socket);
                sess_socket->s_socket = NULL;
            }
            
            mutex_enter(&sess_socket->s_lock);
            ret = sock_create(AF_INET, SOCK_STREAM,0,&sess_socket->s_socket);
            if(ret){
                printk("server:socket_create error! (ret = %d)\n", ret);
                VERIFY(ret == 0);
            }
            ret = kernel_connect(sess_socket->s_socket,(struct sockaddr *)&(sess_socket->s_addr), sizeof(struct sockaddr),0);  
            if(ret==0){  
                mutex_exit(&sess_socket->s_lock);
                if (cluster_target_session_hold(cts, "down2up evt") == 0) {
                    mutex_enter(&cts->sess_lock);
                    cts->sess_linkstate = CTS_LINK_UP;
                    mutex_exit(&cts->sess_lock);
        			taskq_dispatch(clustersan->cs_async_taskq,
        				cts_link_down_to_up_handle, (void *)cts, TQ_SLEEP);
                }
                printk("%s link up\n", __func__);
            } else {
                sock_release(sess_socket->s_socket);
                sess_socket->s_socket = NULL;
                mutex_exit(&sess_socket->s_lock);
                
                printk("%s connect error. (ret = %d)\n", __func__, ret);
            }
        } else {
            mutex_exit(&cts->sess_lock);
            memset(&vec,0,sizeof(vec));  
            memset(&msg,0,sizeof(msg));  
            vec.iov_base=&ct_head;  
            vec.iov_len=sizeof(cluster_target_msg_header_t); 
            ret = kernel_sendmsg(sess_socket->s_socket, &msg, &vec, 1, 
                        sizeof(cluster_target_msg_header_t));
            if (ret > 0 && ret != sizeof(cluster_target_msg_header_t)) {
                printk("%s kernel_sendmsg return %d, should be %d\n", __func__, 
                    ret, (int)(sizeof(cluster_target_msg_header_t)));
            }
            
            if (ret < 0){
                if (cluster_target_session_hold(cts, "up2down evt") == 0) {
                    mutex_enter(&cts->sess_lock);
                    cts->sess_linkstate = CTS_LINK_DOWN;
                    mutex_exit(&cts->sess_lock);
    				taskq_dispatch(clustersan->cs_async_taskq,
    					cts_link_up_to_down_handle, (void *)cts, TQ_SLEEP);
                }
                mutex_enter(&sess_socket->s_lock);
                sock_release(sess_socket->s_socket);
                sess_socket->s_socket = NULL;
                mutex_exit(&sess_socket->s_lock);
                printk("%s link down. (ret = %d)\n", __func__, ret);
            }
        }
        
        cv_timedwait(&cts->sess_cv, &cts->sess_lock,
			ddi_get_lbolt() + drv_usectohz(1000 * 1000));
        
        mutex_enter(&cts->sess_lock);
	}
	mutex_exit(&cts->sess_lock);
    mutex_enter(&sess_socket->s_lock);
    if (sess_socket->s_socket) {
        sock_release(sess_socket->s_socket);
        sess_socket->s_socket = NULL;
    }
    mutex_exit(&sess_socket->s_lock);
    
}
void cts_socket_hb_init(cluster_target_session_t *cts)
{
	char *tq_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	snprintf(tq_name, MAXNAMELEN, "sess_hb_tq_%d", cts->sess_id);
	cts->sess_hb_tq = taskq_create(tq_name,
		1, minclsyspri, 1, 1, TASKQ_PREPOPULATE);
	kmem_free(tq_name, MAXNAMELEN);
	cts->sess_hb_state = 0;
	taskq_dispatch(cts->sess_hb_tq, cts_socket_hb_thread, (void *)cts, TQ_SLEEP);
}
void cts_socket_hb_fini(cluster_target_session_t *cts)
{
    mutex_enter(&cts->sess_lock);
    cts->sess_hb_state |= CLUSTER_TARGET_TH_STATE_STOP;
    mutex_exit(&cts->sess_lock);
    cv_broadcast(&cts->sess_cv);
    taskq_destroy(cts->sess_hb_tq);
}