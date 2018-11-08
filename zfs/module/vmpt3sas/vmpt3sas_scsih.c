
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/aer.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <asm/unaligned.h>
#include <sys/zfs_context.h>
#include <sys/cluster_san.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_transport.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_dbg.h>
#include <rpc/xdr.h>
#include "vmpt3sas.h"
//#include "vmpt3sas_base.h"

#define	VMPT3SAS_BROADCAST_SESS				((void *)(0-1))
#define	XDR_EN_FIXED_SIZE	256/* Leave allowance */
#define	XDR_DE_FIXED_SIZE	256/* Leave allowance */

#define VMPT3SAS_DRIVER_NAME		"vmpt3sas"
/*
 * logging format
 */
#define VMPT3SAS_FMT			"%s: "

static taskq_t *gvmpt3sas_tq_req;
static taskq_t *gvmpt3sas_tq_rsp;

static req_proxy_t vmptsas_proxy_done;
static struct Scsi_Host *vmptsas_shost;

typedef struct vmptsas_hostmap {
	struct Scsi_Host *shost;
	int remote_hostno;
	int index;
}vmptsas_hostmap_t;

int g_vmptsas_hostmap_total = 0;
vmptsas_hostmap_t g_vmptsas_hostmap_array[128];
struct task_struct *gproxythread;

int vmpt3sas_scsih_qcmd(struct Scsi_Host *, struct scsi_cmnd *);
int vmpt3sas_send_msg(void *, void *, u64 );
int vmpt3sas_proxy_done_thread(void *);

/* shost template for SAS 3.0 HBA devices */
static struct scsi_host_template vmpt3sas_driver_template = {
	.module				= THIS_MODULE,
	.name				= "Fusion MPT SAS Host",
	.proc_name			= VMPT3SAS_DRIVER_NAME,
	.queuecommand			= vmpt3sas_scsih_qcmd,
	.target_alloc			= NULL,
	.slave_alloc			= NULL,
	.slave_configure		= NULL,
	.target_destroy			= NULL,
	.slave_destroy			= NULL,
	.scan_finished			= NULL,
	.scan_start			= NULL,
	.change_queue_depth		= NULL,
	.eh_abort_handler		= NULL,
	.eh_device_reset_handler	= NULL,
	.eh_target_reset_handler	= NULL,
	.eh_host_reset_handler		= NULL,
	.bios_param			= NULL,
	.can_queue			= 1,
	.this_id			= -1,
	.sg_tablesize			= SCSI_MAX_SG_SEGMENTS,
	.max_sectors			= 32767,
	.cmd_per_lun			= 7,
	.use_clustering			= ENABLE_CLUSTERING,
	.shost_attrs			= NULL,
	.sdev_attrs			= NULL,
	.track_queue_depth		= 1,
};

#if 0
static struct scsi_host_template vmpt3sas_driver_template = {
	.module				= THIS_MODULE,
	.name				= "VMPT SAS Host",
	.proc_name			= VMPT3SAS_DRIVER_NAME,
	.queuecommand			= vmpt3sas_scsih_qcmd,
	
	.can_queue			= 1,
	.cmd_per_lun		= 128,
	.sg_tablesize			= SCSI_MAX_SG_SEGMENTS,
	.use_clustering			= ENABLE_CLUSTERING,
	.sdev_attrs			= NULL,
	.this_id			= 20,
	.emulated 	= 1
};
#endif

static ushort max_sectors = 0xFFFF;
module_param(max_sectors, ushort, 0);
MODULE_PARM_DESC(max_sectors, "max sectors, range 64 to 32767  default=32767");


/* command line options */
static u32 logging_level = 1;
MODULE_PARM_DESC(logging_level,
	" bits for enabling additional logging info (default=0)");
																																																																							
static void vmpt3sas_proxy_req_done(struct request *req, int error)
{
	req_list_t *reqlist;
	req_proxy_t *proxy = (req_proxy_t *)&vmptsas_proxy_done;
	
	printk(KERN_WARNING " %s is run error=[%d] sense=%p err=%x resid=%d \n", 
		__func__, error, req->sense, req->errors, req->resid_len);
	
	reqlist = kmalloc(sizeof(req_list_t),GFP_KERNEL);
	reqlist->req = req;
	
	spin_lock_irq(&proxy->queue_lock);
	list_add_tail(&reqlist->queuelist, &proxy->done_queue);
	spin_unlock_irq(&proxy->queue_lock);
	wake_up(&proxy->waiting_wq);
}

static void vmpt3sas_proxy_exec_req(struct scsi_device *sdev, vmpt3sas_req_scmd_t *reqcmd)
{
	struct request *req;
	int write = (reqcmd->data_direction == DMA_TO_DEVICE);
	unsigned int bufflen;
	void *buffer;

	req = blk_get_request(sdev->request_queue, write, GFP_KERNEL);
	if (IS_ERR(req)) {
		printk(KERN_WARNING " %s can not get request \n", __func__);
		return ;
	}
	blk_rq_set_block_pc(req);

	bufflen = reqcmd->datalen;
	buffer = reqcmd->data;
	if (bufflen &&	blk_rq_map_kern(sdev->request_queue, req,
					buffer, bufflen, GFP_KERNEL)){
		printk(KERN_WARNING " %s blk_rq_map_kern failed \n", __func__);
		goto out;
	}
	
	req->end_io_data = reqcmd;
	req->cmd_len = COMMAND_SIZE(reqcmd->cmnd[0]);
	memcpy(req->cmd, reqcmd->cmnd, req->cmd_len);
	req->sense = reqcmd->sense;
	req->sense_len = 0;
	req->retries = 3;
	req->timeout = 30*HZ;

	printk(KERN_WARNING " %s exec req in scsi system \n", __func__);
	blk_execute_rq_nowait(req->q, NULL, req, 0,
		 vmpt3sas_proxy_req_done);
	return;
out:
	blk_put_request(req);

	return;
}

static void vmpt3sas_direct_queue_cmd(struct Scsi_Host *host,vmpt3sas_req_scmd_t *reqcmd)
{
	struct scsi_cmnd *scmd;

	scmd = kmalloc(sizeof(struct scsi_cmnd),GFP_KERNEL);
	if (scmd == NULL) {
		printk(KERN_WARNING " %s can not alloc scmd \n", __func__);
		return;
	}

	scmd->scsi_done = NULL;

	host->hostt->queuecommand(host, scmd);
	
	return;
}

static void vmpt3sas_listall_scsitarget(struct Scsi_Host *shost)
{
	struct scsi_target *starget;
	/*
	 * Search for an existing target for this sdev.
	 */
	list_for_each_entry(starget, &shost->__targets, siblings) {
		printk(KERN_WARNING " %s host: %p host_no =%u chanl:%u id:%u \n", 
			__func__, shost, shost->host_no, starget->channel, starget->id);
	}
}

static struct scsi_target *vmpt3sas_get_scsitarget(struct Scsi_Host *shost,int channel)
{
	struct scsi_target *starget;
	/*
	 * Search for an existing target for this sdev.
	 */
	list_for_each_entry(starget, &shost->__targets, siblings) {
		printk(KERN_WARNING " %s host: %p host_no =%u chanl:%u id:%u \n", 
			__func__, shost, shost->host_no, starget->channel, starget->id);
		if (starget->channel)
			return starget;
	}
	return NULL;
}

static void vmpt3sas_listall_scsidev(struct Scsi_Host *shost)
{
	struct scsi_device *sdev;
	
	shost_for_each_device(sdev, shost) {
		printk(KERN_WARNING " %s host: %p host_no =%u chanl:%u id:%u lun:%u \n", 
			__func__, shost, shost->host_no, sdev->channel, sdev->id, sdev->lun);
	}
}

static void vmpt3sas_brdlocal_shost(struct Scsi_Host *shost)
{
	int len;
	void *buff;
	XDR xdr_temp;
	XDR *xdrs = &xdr_temp;
	vmpt3sas_remote_cmd_t remote_cmd;
	int tx_len;
	int i,j;
	struct scsi_device *sdev;

	i = 0;
	shost_for_each_device(sdev, shost) {
		i++;
		/*printk(KERN_WARNING " %s host: %p host_no =%u chanl:%u id:%u lun:%u \n", 
			__func__, shost, shost->host_no, sdev->channel, sdev->id, sdev->lun);
			*/
	}

	/* encode message */
	len = XDR_EN_FIXED_SIZE + sizeof(int) + sizeof(int)*(i+1);
	buff = cs_kmem_alloc(len);
	xdrmem_create(xdrs, buff, len, XDR_ENCODE);
	remote_cmd = VMPT_CMD_ADDHOST;
	xdr_int(xdrs, (int *)&remote_cmd);/* 4bytes */

	xdr_u_int(xdrs,&shost->host_no);
	i=1;
	xdr_u_int(xdrs,&i);

	i=0;j=2;
	shost_for_each_device(sdev, shost) {
		i++;
		if (i!=j) {
			continue;
		}
		xdr_u_int(xdrs,&sdev->id);
		printk(KERN_WARNING " %s (%d %d)pack id:%u  \n", __func__,i, j, sdev->id);
	}
		
	tx_len = (uint_t)((uintptr_t)xdrs->x_addr - (uintptr_t)buff);
	printk(KERN_WARNING " %s brdcast msg len: %d host_no =%d \n", __func__, tx_len, shost->host_no);
	vmpt3sas_send_msg(VMPT3SAS_BROADCAST_SESS, (void *)buff, tx_len);
	cs_kmem_free(buff, len);
}

static void vmpt3sas_addvhost_handler(void *data)
{
	unsigned int hostno;
	void * session;
	struct Scsi_Host *shost;
	vmpt3sas_rx_data_t *rx_data = (vmpt3sas_rx_data_t *)data;
	vmpt3sas_t * ioc;
	int rv;
	int i,j,k;
	
	XDR *xdrs = rx_data->xdrs;
	session = rx_data->cs_data->cs_private;
	
	xdr_u_int(xdrs, &hostno); /* 8bytes */
	xdr_u_int(xdrs, &j);
	printk(KERN_WARNING " %s hostno: %u devcount=%d ", __func__, hostno, j);
	
	shost = scsi_host_alloc(&vmpt3sas_driver_template, sizeof(struct vmpt3sas));
	if (!shost){
		printk(KERN_WARNING " %s scsi_host_alloc failed hostno: %d ", __func__, hostno );
		return;
	}

	ioc = shost_priv(shost);
	ioc->session = session;
	ioc->remotehostno = hostno;
	ioc->logging_level = logging_level;
	ioc->shost = shost;
	ioc->id = g_vmptsas_hostmap_total++;
	ioc->vmpt_cmd_wait_hash = mod_hash_create_ptrhash(
							"vmpt_cmd_wait_hash", 1024,
							mod_hash_null_valdtor, 0);
	
	rv = scsi_add_host(shost, NULL);
	if (rv) {
		/*
		pr_err(MPT3SAS_FMT "failure at %s:%d/%s()!\n",
			ioc->name, __FILE__, __LINE__, __func__);
		*/
		printk(KERN_WARNING " %s scsi_add_host failed ret: %d ", __func__, rv );
		goto out_add_shost_fail;
	}
	
	g_vmptsas_hostmap_array[g_vmptsas_hostmap_total].shost = shost;
	g_vmptsas_hostmap_array[g_vmptsas_hostmap_total].remote_hostno = hostno;

	for (i=0; i<j; i++) {
		xdr_u_int(xdrs, &k);
		
		printk(KERN_WARNING " %s scsi_add_device id:%u  \n", __func__, i);
		scsi_add_device(shost, 0, k, 0);
	}

	/*
	ioc->vmpt_cmd_wait_hash = mod_hash_create_ptrhash(
							"vmpt_cmd_wait_hash", 1024,
							mod_hash_null_valdtor, 0);
							*/
	/*
	printk(KERN_WARNING " %s to run scsi_scan_host ", __func__);
	scsi_scan_host(shost);
	*/
	return;
		
out_add_shost_fail:
	scsi_host_put(shost);
	return ;
}

void vmpt3sas_proxy_handler(void *data)
{
	vmpt3sas_rx_data_t *prx ;
	XDR *xdrs ;
	int have_sdb;
	vmpt3sas_req_scmd_t *req_scmd;
	struct scsi_device *sdev = NULL;
	struct Scsi_Host *shost;

	prx = (vmpt3sas_rx_data_t *)data;
	xdrs = prx->xdrs;

	req_scmd = kmalloc(sizeof(vmpt3sas_req_scmd_t), GFP_KERNEL);
	req_scmd->datalen = 0;
	req_scmd->data = NULL;
	req_scmd->session = prx->cs_data->cs_private;
	
	xdr_u_longlong_t(xdrs, (u64 *)&req_scmd->req_index);/* 8bytes */
	xdr_u_longlong_t(xdrs, (uint64_t *)&shost);/* 8bytes */
	req_scmd->shost = shost;
	
	xdr_int(xdrs, &req_scmd->host);
	xdr_int(xdrs, &req_scmd->channel);
	xdr_int(xdrs, &req_scmd->id);
	xdr_int(xdrs, &req_scmd->lun);
	xdr_int(xdrs, (int *)(&req_scmd->data_direction));/* 4bytes */

	printk(KERN_WARNING "%s: session=%p index=[%llu] scsicmd0 =[%x] shost=%p hostno=%d channel=%d id=%d lun=%d\n", 
		__func__, req_scmd->session, (u_longlong_t)req_scmd->req_index, req_scmd->cmnd[0], shost, req_scmd->host, req_scmd->channel, req_scmd->id, req_scmd->lun);

	xdr_u_int(xdrs, &req_scmd->cmd_len);/* 4bytes */
	xdr_opaque(xdrs, (caddr_t)req_scmd->cmnd, req_scmd->cmd_len);
	
	xdr_int(xdrs, &have_sdb);
	if (have_sdb) {
		xdr_u_int(xdrs, &(req_scmd->datalen)); /* 4bytes */
		if (!(req_scmd->datalen > 0 && req_scmd->datalen < 1024*1024)){
			printk(KERN_WARNING "%s: data_len = %d error\n", __func__, req_scmd->datalen);
			return;
		}
		
		req_scmd->data = kmalloc(req_scmd->datalen, GFP_KERNEL);
		xdr_opaque(xdrs, (caddr_t)req_scmd->data, req_scmd->datalen);
		
	} else {
		req_scmd->datalen = 0;
		req_scmd->data = NULL;
	}

	shost = scsi_host_lookup(req_scmd->host);
	if (shost == NULL) {
		printk(KERN_WARNING "%s: hostno=%d scsihost is not found\n", 
				__func__, req_scmd->host);
		return;
	}
	
	sdev = scsi_device_lookup(shost, req_scmd->channel, req_scmd->id, req_scmd->lun);
	if (sdev) {
		vmpt3sas_proxy_exec_req(sdev, req_scmd);
	}
	else {
		printk(KERN_WARNING "%s: not find scsidev hostno=%d channel=%d id=%d lun=%d\n", 
			__func__, req_scmd->host, req_scmd->channel, req_scmd->id, req_scmd->lun);
		
		/*
		struct scsi_target *starget = vmpt3sas_get_scsitarget(shost, 0);
		printk(KERN_WARNING "%s scsi target is %p  \n",	__func__,starget);
		if (starget){
			sdev = scsi_device_lookup_by_target(starget, 0);
			if (!sdev)
				sdev = scsi_alloc_sdev(starget, 0, NULL);
			
			printk(KERN_WARNING "%s scsi dev is %p  \n", __func__, sdev);
			if (sdev){
				
				vmpt3sas_proxy_exe_cmd(sdev, req_scmd);
			}
		}
		*/
	}
}

static void vmpt3sas_proxy_response(void *private, struct request *req)
{
	vmpt3sas_remote_cmd_t remote_cmd;
	
	XDR xdr_temp;
	XDR *xdrs = &xdr_temp;
	uint_t len;
	void *buff = NULL;
	vmpt3sas_req_scmd_t *reqcmd = req->end_io_data;
	struct scsi_cmnd *scmd;
	int senselen;
	int tx_len;

	scmd = req->special;
	/* encode message */
	len = XDR_EN_FIXED_SIZE + scmd->cmd_len + scmd->sdb.length;
	buff = cs_kmem_alloc(len);
	xdrmem_create(xdrs, buff, len, XDR_ENCODE);
	remote_cmd = VMPT_CMD_RSP;
	xdr_int(xdrs, (int *)&remote_cmd);/* 4bytes */
	xdr_u_longlong_t(xdrs, (u64 *)&reqcmd->req_index);/* 8bytes */
	xdr_u_longlong_t(xdrs, (u64 *)&reqcmd->shost);/* 8bytes */

	printk(KERN_WARNING " %s index=%llu shost=%p result=%d \n", 
		__func__, (u_longlong_t)reqcmd->req_index, reqcmd->shost, scmd->result);
	xdr_int(xdrs, (int *)&scmd->result);
	xdr_int(xdrs, (int *)&scmd->sdb.resid);
	senselen = 18;
	xdr_int(xdrs, (int *)&senselen);
	xdr_opaque(xdrs, (caddr_t)scmd->sense_buffer, senselen);

	if (scmd->sc_data_direction == DMA_FROM_DEVICE) {

		if (scmd->sdb.length != 0) {
			xdr_u_int(xdrs, &(scmd->sdb.length));/* 4bytes */
			scsi_sg_copy_to_buffer(scmd, xdrs->x_addr, xdrs->x_addr_end - xdrs->x_addr);
			xdrs->x_addr += scmd->sdb.length;
		}
	}

	tx_len = (uint_t)((uintptr_t)xdrs->x_addr - (uintptr_t)buff);
	vmpt3sas_send_msg(reqcmd->session, (void *)buff, tx_len);
	cs_kmem_free(buff, len);

	if (reqcmd->data)
		kfree(reqcmd->data);
	kfree(reqcmd);
	
	blk_put_request(req);
	
}

static struct Scsi_Host *vmpt3sas_lookup_shost(void)
{
	int i=0;
	struct Scsi_Host *shost = NULL;

	for (i=0; i<128; i++) {
		shost = scsi_host_lookup(i);
		if (shost) {
			if (strcmp(shost->hostt->proc_name,"mpt3sas") == 0 ||
				strcmp(shost->hostt->proc_name,"mpt2sas") == 0 ||
				strcmp(shost->hostt->proc_name, "megaraid_sas") ==0 ) {
				printk(KERN_WARNING "shost:%p is found\n", shost);
				
				vmpt3sas_listall_scsidev(shost);
				return shost;
			}
		}
	}

	printk(KERN_WARNING "mptsas shost is not found\n");
	return NULL; 
}

static void vmpt3sas_init_proxy(void) 
{
	INIT_LIST_HEAD(&vmptsas_proxy_done.done_queue);
	spin_lock_init(&vmptsas_proxy_done.queue_lock);
	init_waitqueue_head(&vmptsas_proxy_done.waiting_wq);
	
	gproxythread = kthread_create(vmpt3sas_proxy_done_thread, &vmptsas_proxy_done, "%s", "vd_proxy");
	if (IS_ERR(gproxythread)) {
		printk(KERN_WARNING "kthread_create failed");
		return ;
	}
	wake_up_process(gproxythread);

	vmptsas_shost = vmpt3sas_lookup_shost();
	if (vmptsas_shost){
		/*vmpt3sas_listall_scsidev(vmptsas_shost);*/
		vmpt3sas_brdlocal_shost(vmptsas_shost);
	}

}

int vmpt3sas_proxy_done_thread(void *data)
{
	req_list_t *reqlist;
	req_proxy_t *proxy = (req_proxy_t *)data;
	struct request *req;
	
	set_user_nice(current, -20);
	while (!kthread_should_stop() || !list_empty(&proxy->done_queue)) {
		/* wait for something to do */
		wait_event_interruptible(proxy->waiting_wq,
					 kthread_should_stop() ||
					 !list_empty(&proxy->done_queue));

		/* extract request */
		if (list_empty(&proxy->done_queue))
			continue;

		spin_lock_irq(&proxy->queue_lock);
		reqlist = list_entry(proxy->done_queue.next, req_list_t,
				 queuelist);
		list_del_init(&reqlist->queuelist);
		spin_unlock_irq(&proxy->queue_lock);
		req = reqlist->req;
		kfree(reqlist);

		vmpt3sas_proxy_response(NULL, req);
	}
	return 0;
}


void vmpt3sas_rx_data_free(vmpt3sas_rx_data_t *rx_data)
{
	kmem_free(rx_data->xdrs, sizeof(XDR));
	csh_rx_data_free_ext(rx_data->cs_data);
	kmem_free(rx_data, sizeof(vmpt3sas_rx_data_t));
}

void vmpt3sas_rsp_handler(void *data)
{
	vmpt3sas_rx_data_t *rx_data = data;
	XDR *xdrs = rx_data->xdrs;
	struct scsi_cmnd *scmd;
	u64 rsp_index;
	int ret;
	int senselen;
	struct Scsi_Host *shost;
	struct vmpt3sas *ioc;
	
	xdr_u_longlong_t(xdrs, (u64 *)&rsp_index);/* 8bytes */
	xdr_u_longlong_t(xdrs, (u64 *)&shost);/* 8bytes */
	
	printk(KERN_WARNING " %s repindex=%ld shost=[%p] \n", __func__, 
		(unsigned long)rsp_index, shost);
	
	ioc = shost_priv(shost);
	ret= mod_hash_remove(ioc->vmpt_cmd_wait_hash,
		(mod_hash_key_t)(uintptr_t)rsp_index, (mod_hash_val_t *)&scmd);

	if (ret != 0) {
		printk(KERN_WARNING " %s repindex=%ld shost=[%p] not found \n", __func__, 
		(unsigned long)rsp_index, shost);
		goto failed;
	}
	/*decode rsp data*/
	xdr_int(xdrs, (int *)&scmd->result);
	xdr_int(xdrs, (int *)&scmd->sdb.resid);

	xdr_int(xdrs, (int *)&senselen);
	xdr_opaque(xdrs, (caddr_t)scmd->sense_buffer, senselen);

	printk(KERN_WARNING " %s repindex=%ld shost=[%p] senselen=%d direction=%d sdb.len=%d\n", __func__, 
		(unsigned long)rsp_index, shost, senselen, scmd->sc_data_direction ,scmd->sdb.length);

	/*scsi data*/
	if (scmd->sc_data_direction == DMA_FROM_DEVICE) {
		xdr_u_int(xdrs, &(scmd->sdb.length));/* 4bytes */
		scsi_sg_copy_from_buffer(scmd, xdrs->x_addr, xdrs->x_addr_end - xdrs->x_addr);
		xdrs->x_addr += scmd->sdb.length;

		printk(KERN_WARNING "%s cp2scsicmd repindex=%ld shost=[%p] direction=%d sdb.len=%d\n", __func__, 
				(unsigned long)rsp_index, shost,  scmd->sc_data_direction ,scmd->sdb.length);
	}

	scmd->scsi_done(scmd);

failed:
	vmpt3sas_rx_data_free(rx_data);
	return;
}

int vmpt3sas_send_msg(void *sess, void *data, u64 len)
{
	int ret = 0;
	if (sess == VMPT3SAS_BROADCAST_SESS) {
		cluster_san_broadcast_send(data, len, NULL, 0, CLUSTER_SAN_MSGTYPE_IMPTSAS, 0);
	} else {
		ret = cluster_san_host_send(sess, data, len, NULL, 0, CLUSTER_SAN_MSGTYPE_IMPTSAS, 0,
			1, 3);
	}
	return (ret);
}

static void vmpt3sas_clustersan_rx_cb(cs_rx_data_t *cs_data, void *arg)
{
	vmpt3sas_remote_cmd_t remote_cmd;
	XDR *xdrs;
	vmpt3sas_rx_data_t *rx_data;

	if ((cs_data->data_len == 0) || (cs_data->data == NULL)) {
		printk(KERN_WARNING "%s: data is null len=%lld data=%p\n",
			__func__, cs_data->data_len, cs_data->data);
		return;
	}

	rx_data = kmem_zalloc(sizeof(vmpt3sas_rx_data_t), KM_SLEEP);
	xdrs = kmem_zalloc(sizeof(XDR), KM_SLEEP);
	rx_data->xdrs = xdrs;
	rx_data->cs_data = cs_data;
	xdrmem_create(xdrs, cs_data->data, cs_data->data_len, XDR_DECODE);
	xdr_int(xdrs, (int *)&remote_cmd);

	printk(KERN_WARNING "%s: msgtype=[%d] \n", __func__,remote_cmd);
	
	switch(remote_cmd) {
		case VMPT_CMD_REQUEST:
			taskq_dispatch(gvmpt3sas_tq_req,
				vmpt3sas_proxy_handler, (void *)rx_data, TQ_SLEEP);
			
			break;
		case VMPT_CMD_RSP:
			taskq_dispatch(gvmpt3sas_tq_req,
				vmpt3sas_rsp_handler, (void *)rx_data, TQ_SLEEP);
 			
			break;
		case VMPT_CMD_ADDHOST:
			taskq_dispatch(gvmpt3sas_tq_req,
				vmpt3sas_addvhost_handler, (void *)rx_data, TQ_SLEEP);
			break;

		default:
			vmpt3sas_rx_data_free(rx_data);
			printk(KERN_WARNING "vmptsas_remote_req_handler: Don't support");
			break;
	}
}

static void vmpt3sas_cts_link_evt_cb(void *private,
	cts_link_evt_t link_evt, void *arg)
{
	vmpt3sas_cts_link_stata_evt_t*link_state;

	link_state = kmem_zalloc(sizeof(vmpt3sas_cts_link_stata_evt_t), KM_SLEEP);
	link_state->sess = private;
	link_state->link_evt = link_evt;
	link_state->arg = arg;

	/*TODO*/
	#if 0
	ret = ddi_taskq_dispatch(gimptsas->tq_asyn,
		(void (*)(void *))imptsas_cts_link_evt_handler, (void *)link_state, DDI_SLEEP);
	if (DDI_SUCCESS != ret) {
		printk("imptsas link state change handler taskq failed");
		imptsas_cts_link_evt_handler(link_state);
	}
	#endif
}

/**
 * scsih_qcmd - main scsi request entry point
 * @scmd: pointer to scsi command object
 * @done: function pointer to be invoked on completion
 *
 * The callback index is set inside `ioc->scsi_io_cb_idx`.
 *
 * Returns 0 on success.  If there's a failure, return either:
 * SCSI_MLQUEUE_DEVICE_BUSY if the device queue is full, or
 * SCSI_MLQUEUE_HOST_BUSY if the entire host queue is full
 */
int
vmpt3sas_scsih_qcmd(struct Scsi_Host *shost, struct scsi_cmnd *scmd)
{
	vmpt3sas_remote_cmd_t remote_cmd;
	vmpt3sas_t *ioc = shost_priv(shost);
	XDR xdr_temp;
	XDR *xdrs = &xdr_temp;
	uint_t len;
	uint_t tx_len;
	void *buff = NULL;
	u64 index;
	int have_sdb;
	int err;
	
	/*encode message*/
	len = XDR_EN_FIXED_SIZE + scmd->cmd_len + scmd->sdb.length;
	buff = cs_kmem_alloc(len);
	xdrmem_create(xdrs, buff, len, XDR_ENCODE);
	remote_cmd = VMPT_CMD_REQUEST;
	xdr_int(xdrs, (int *)&remote_cmd);/* 4bytes */

	index = ioc->req_index++;
	xdr_u_longlong_t(xdrs, (u64 *)&index);/* 8bytes */
	xdr_u_longlong_t(xdrs, (uint64_t *)&shost);/* 8bytes */

	/* xdr_u_int(xdrs, &(shost->host_no)); */
	xdr_u_int(xdrs, &(ioc->remotehostno));
	xdr_u_int(xdrs, &(scmd->device->channel));/* 4bytes */
	xdr_u_int(xdrs, &(scmd->device->id));/* 4bytes */
	xdr_u_int(xdrs, (uint_t *)&(scmd->device->lun));/* 4bytes */

	xdr_int(xdrs, (int *)&(scmd->sc_data_direction));/* 4bytes */

	/*encode CDB*/
	xdr_u_int(xdrs, (uint_t *)&(scmd->cmd_len));/* 4bytes */
	xdr_opaque(xdrs, (caddr_t)scmd->cmnd, scmd->cmd_len);

	printk(KERN_WARNING "%s: index:%llu shost=%p remotehostno= %d cmd0=%x id=%d\n", 
		__func__, (u_longlong_t)index, shost, ioc->remotehostno,scmd->cmnd[0],scmd->device->id);
	
	if (ioc->logging_level)
			scsi_print_command(scmd);
	
	/*have scsi data*/
	if (scmd->sdb.length != 0) {
		have_sdb = 1;
		printk(KERN_WARNING "%s: to tansfer msg sdb_len=%d \n", __func__, scmd->sdb.length);
		if (scmd->sc_data_direction == DMA_FROM_DEVICE) {
			xdr_int(xdrs, &have_sdb);/* 4bytes */
			xdr_u_int(xdrs, &(scmd->sdb.length));/* 4bytes */
		} else {
			xdr_int(xdrs, &have_sdb);/* 4bytes */
			xdr_u_int(xdrs, &(scmd->sdb.length));/* 4bytes */
		
			/* todo: encode scsi data into xdr */
			scsi_sg_copy_to_buffer(scmd, xdrs->x_addr, xdrs->x_addr_end - xdrs->x_addr);
			xdrs->x_addr += scmd->sdb.length;
			//xdrs->x_handy -= scmd->sdb.length;
		}
		
	} else {
		have_sdb = 0;
		xdr_int(xdrs, &have_sdb);/* 4bytes */
	}

	tx_len = (uint_t)((uintptr_t)xdrs->x_addr - (uintptr_t)buff);
	mod_hash_insert(ioc->vmpt_cmd_wait_hash,
		(mod_hash_key_t)(uintptr_t)index, (mod_hash_val_t)scmd);
	
	err = vmpt3sas_send_msg(ioc->session, (void *)buff, tx_len);
	cs_kmem_free(buff, len);

	if (err != 0) {
		/*
		struct scsi_cmnd *tmp_scmd;
		mod_hash_remove(ioc->vmpt_cmd_wait_hash,
		(mod_hash_key_t)(uintptr_t)index, (mod_hash_val_t *)&tmp_scmd);
		*/
		printk(KERN_WARNING "index %llu message failed!\n", index);
		scmd->result = DID_NO_CONNECT << 16;
		scmd->scsi_done(scmd);
	}

	return 0;
	
}


/**
 * _mpt3sas_init - main entry point for this driver.
 *
 * Returns 0 success, anything else error.
 */
static int __init
_vmpt3sas_init(void)
{
	int rv;

	pr_info("%s loaded\n", VMPT3SAS_DRIVER_NAME);
	csh_rx_hook_add(CLUSTER_SAN_MSGTYPE_IMPTSAS, vmpt3sas_clustersan_rx_cb, NULL);
	vmpt3sas_init_proxy();

	/* receive thread */
	gvmpt3sas_tq_req =
	 	taskq_create("request_taskq", 8, minclsyspri,
    		8, INT_MAX, TASKQ_PREPOPULATE);
	if (gvmpt3sas_tq_req 	== NULL) {
		printk(KERN_WARNING " %s taskq_create failed:", __func__);
		rv = -ENODEV;
		goto out_thread_fail;
	}

	gvmpt3sas_tq_rsp =
        taskq_create("reponse_taskq", 8, minclsyspri,
    		8, INT_MAX, TASKQ_PREPOPULATE);
	if (gvmpt3sas_tq_rsp == NULL) {
		printk(KERN_WARNING " %s taskq_create failed:", __func__);
		rv = -ENODEV;
		goto out_thread_fail;
	}

	return 0;

out_thread_fail:
	return rv;
}

/**
 * _mpt3sas_exit - exit point for this driver (when it is a module).
 *
 */
static void __exit
_vmpt3sas_exit(void)
{
	kthread_stop(gproxythread);
	csh_rx_hook_remove(CLUSTER_SAN_MSGTYPE_IMPTSAS);
	pr_info("%s exit\n", VMPT3SAS_DRIVER_NAME);
}

module_init(_vmpt3sas_init);
module_exit(_vmpt3sas_exit);
MODULE_LICENSE("GPL");

