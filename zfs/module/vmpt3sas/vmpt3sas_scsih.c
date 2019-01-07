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
#include <asm/device.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/miscdevice.h>
#include <asm/unaligned.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_transport.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_dbg.h>
#include <sd.h>
#undef VERIFY
#include <sys/zfs_context.h>
#include <sys/modhash.h>
#include <sys/fs/zfs_hbx.h>
#include <sys/cluster_san.h>

#include <rpc/xdr.h>
#include "vmpt3sas.h"

struct subsys_private {
	struct kset subsys;
	struct kset *devices_kset;
	struct list_head interfaces;
	struct mutex mutex;

	struct kset *drivers_kset;
	struct klist klist_devices;
	struct klist klist_drivers;
	struct blocking_notifier_head bus_notifier;
	unsigned int drivers_autoprobe:1;
	struct bus_type *bus;

	struct kset glue_dirs;
	struct class *class;
};

typedef struct remote_shost{
    struct list_head    entry;
    u32                 host_id;
    u32                 shost_no;
}remote_shost_t;

typedef struct remote_shost_list{
    struct list_head    head;
    spinlock_t          lock;
}remote_shost_list_t;

typedef struct vmptsas_hostmap_list{
    struct list_head    head;
    spinlock_t          lock;
}vmptsas_hostmap_list_t;

typedef enum {
    VMPTSAS_BRDLC_SELFUP = 0x0,
    VMPTSAS_BRDLC_DOWN_CVT_UP = 0x1
} vmptsas_brdlocal_cause_e;

typedef struct {
    void *sess;
    vmptsas_brdlocal_cause_e cause;
} vmptsas_brdlocal_arg_t;

static remote_shost_list_t rshost_list;

#define	VMPT3SAS_BROADCAST_SESS				((void *)(0-1))
#define	XDR_EN_FIXED_SIZE	256/* Leave allowance */
#define	XDR_DE_FIXED_SIZE	256/* Leave allowance */

#define VMPT3SAS_DRIVER_NAME		"vmpt3sas"

typedef void (*vmpt3sas_lookup_shost_cb_fn)(void *, struct Scsi_Host *);

vmptsas_instance_t gvmpt3sas_instance;

spinlock_t     hostmap_lock;
//vmptsas_hostmap_t g_vmptsas_hostmap_array[128];
//static vmptsas_hostmap_t *gp_vmptsas_hostmap = NULL;
static int g_vmptsas_hostmap_total = 0;
static vmptsas_hostmap_list_t hostmap_list;

/*
 * the purpose of those two var is to avoid adding scsi_host
 * repeatly when module is being loaded and the event of
 * LINK_EVT_DOWN_TO_UP happens at the same time.
 */
static boolean_t is_loading = B_FALSE;
static boolean_t is_loaded = B_FALSE;

extern void sd_register_cb_state_changed(sd_state_changed_cb_func_t cbp, void *priv);
extern int cts_link_evt_hook_add(cs_link_evt_cb_t link_evt_cb, void *arg);
extern int cts_link_evt_hook_remove(cs_link_evt_cb_t link_evt_cb);

int vmpt3sas_scsih_qcmd(struct Scsi_Host *, struct scsi_cmnd *);
int vmpt3sas_send_msg(void *, void *, u64, void *, u64 , int);
int vmpt3sas_proxy_done_thread(void *);
int vmpt3sas_slave_alloc(struct scsi_device *);
int vmpt3sas_slave_configure(struct scsi_device *);
void vmpt3sas_slave_destroy(struct scsi_device *);
long vmpt3sas_unlocked_ioctl(struct file *, unsigned int , unsigned long );
int vmpt3sas_open (struct inode *, struct file *);
void vmpt3sas_rx_data_free(vmpt3sas_rx_data_t *);
void vmpt3sas_lookup_report_shost(vmpt3sas_lookup_shost_cb_fn fn, void *priv);
void vmpt3sas_proxy_response(void *req);
void vmpt3sas_lenvent_callback(void *private, cts_link_evt_t link_evt, void *arg);

static vmptsas_hostmap_t *
vmpt3sas_hostmap_alloc(int hostid, int index, int hostno, struct Scsi_Host *shost);


/* shost template for SAS 3.0 HBA devices */
static struct scsi_host_template vmpt3sas_driver_template = {
	.module				= THIS_MODULE,
	.name				= "vmpt3sas",
	.proc_name			= VMPT3SAS_DRIVER_NAME,
	.queuecommand			= vmpt3sas_scsih_qcmd,
	.target_alloc			= NULL,
	.slave_alloc			= vmpt3sas_slave_alloc,
	.slave_configure		= vmpt3sas_slave_configure,
	.target_destroy			= NULL,
	.slave_destroy			= vmpt3sas_slave_destroy,
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

static const struct file_operations vmpt3sas_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= vmpt3sas_unlocked_ioctl,
	.open		= vmpt3sas_open,
};

static struct miscdevice vmpt3sas_mm_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name   = "vmpt3sas_mm_dev",
	.fops   = &vmpt3sas_fops,
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
static u32 logging_level = 0;
MODULE_PARM_DESC(logging_level,
	" bits for enabling additional logging info (default=0)");

void vmpt3sad_print(char *data, int len)
{
	char buf[256+1];
	int i;
	memset(buf, 0, sizeof(buf));
	for(i=0;i<128;i++)
		sprintf(buf+i*2,"%02x",(unsigned char)*(data++));
	printk(KERN_WARNING "[%s]\n",buf);
}

static void vmpt3sas_proxy_req_done(struct request *req, int error)
{
	#if 0
	req_list_t *reqlist;
	req_proxy_t *proxy = &(gvmpt3sas_instance.dcmdproxy);
	/*
	printk(KERN_WARNING " %s is run error=[%d] sense=%p err=%x resid=%d \n", 
		__func__, error, req->sense, req->errors, req->resid_len);
	*/
	
	reqlist = kmalloc(sizeof(req_list_t),GFP_KERNEL);
	reqlist->req = req;

	spin_lock_irq(&proxy->queue_lock);
	list_add_tail(&reqlist->queuelist, &proxy->done_queue);
	spin_unlock_irq(&proxy->queue_lock);
	wake_up(&proxy->waiting_wq);
	#else
	taskq_dispatch(gvmpt3sas_instance.tq_pexecproxy,
				vmpt3sas_proxy_response, (void *)req, TQ_SLEEP);
	#endif
}

static void init_remote_shost_list(void)
{
    INIT_LIST_HEAD(&rshost_list.head);
    spin_lock_init(&rshost_list.lock);

    return 0;
}

static int deinit_remote_shost_list(void)
{
    /* rshost_list.head should be released here ? */
    return 0;
}

static remote_shost_t* shost_entry_alloc(int hostid, int shostno)
{
    remote_shost_t* rshost = kmalloc(sizeof(remote_shost_t), GFP_KERNEL);
    if(NULL == rshost){
        return NULL;
    }

    rshost->host_id = hostid;
    rshost->shost_no = shostno;
    INIT_LIST_HEAD(&rshost->entry);
    return rshost;
}

static void shost_entry_free(remote_shost_t* rshost)
{
    kfree(rshost);
}

static void vmpt3sas_proxy_exec_req(struct scsi_device *sdev, vmpt3sas_req_scmd_t *reqcmd)
{
	struct request *req;
	int write = (reqcmd->data_direction == DMA_TO_DEVICE);
	int i;
	int ret;

	req = blk_get_request(sdev->request_queue, write, GFP_KERNEL);
	if (IS_ERR(req)) {
		printk(KERN_WARNING " %s can not get request \n", __func__);
		return ;
	}
	blk_rq_set_block_pc(req);

	for(i=0; i<reqcmd->ndata; i++){
		
		ret = blk_rq_map_kern(sdev->request_queue, req,
			reqcmd->dataarr[i], reqcmd->lendataarr[i], GFP_NOIO);

		if(ret ){
			printk(KERN_WARNING " %s blk_rq_map_kern failed ret=%d %p %d\n", 
				__func__,ret, reqcmd->dataarr[i], reqcmd->lendataarr[i]);	
			goto out;
		}
	}
	
	req->end_io_data = reqcmd;
	req->cmd_len = COMMAND_SIZE(reqcmd->cmnd[0]);
	memcpy(req->cmd, reqcmd->cmnd, req->cmd_len);
	req->sense = reqcmd->sense;
	req->sense_len = 0;
	req->retries = 3;
	req->timeout = 30*HZ;
	
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
/*
char *vmpt3sas_get_diskname_byscsidev(struct scsi_device *sdev)
{
	struct device *dev;
	struct scsi_disk *sdkp;
	struct gendisk *gd;

	if(sdev==NULL){
		printk(KERN_WARNING " %s scsidev is NULL\n", __func__);
		return NULL;
	}
	dev = &sdev->sdev_gendev;
	
	if(dev!=NULL){
		sdkp = (struct scsi_disk *)dev_get_drvdata(dev);
		if(sdkp != NULL){
			gd = sdkp->disk;
			if(gd!=NULL)
			return gd->disk_name;
		}
		printk(KERN_WARNING " %s scsidisk is NULL\n", __func__);
	}
	printk(KERN_WARNING " %s dev is NULL\n", __func__);
	return NULL;
}
*/
static void vmpt3sas_listall_scsidev(struct Scsi_Host *shost)
{
	struct scsi_device *sdev;
	int i=0;
	shost_for_each_device(sdev, shost) {
		
		printk(KERN_WARNING " %s %s %d disk:%s %d:%d:%d:%d\n", 
			__func__,shost->hostt->proc_name, i, "name", 
			shost->host_no, sdev->channel, sdev->id, (int)sdev->lun );
		i++;
	}
	
}

static void vmpt3sas_brd_selfup(void)
{
	int len,tx_len;
	void *buff;
	XDR xdr_temp;
	XDR *xdrs = &xdr_temp;
	vmpt3sas_remote_cmd_t remote_cmd;

	uint32_t hostid = zone_get_hostid(NULL);

	/* encode message */
	len = XDR_EN_FIXED_SIZE + sizeof(int) ;
	buff = cs_kmem_alloc(len);
	xdrmem_create(xdrs, buff, len, XDR_ENCODE);
	remote_cmd = VMPT_CMD_SELFUP;
	xdr_int(xdrs, (int *)&remote_cmd);/* 4bytes */
	xdr_u_int(xdrs,&hostid);
			
	tx_len = (uint_t)((uintptr_t)xdrs->x_addr - (uintptr_t)buff);
	printk(KERN_WARNING " %s brdcast msg len: %d \n", __func__, tx_len);
	vmpt3sas_send_msg(VMPT3SAS_BROADCAST_SESS, NULL, 0, (void *)buff, tx_len, 1);
	cs_kmem_free(buff, len);
}

static void 
vmpt3sas_brdlocal_shost(void *arg, struct Scsi_Host *shost)
{
	int len;
	void *buff;
	XDR xdr_temp;
	XDR *xdrs = &xdr_temp;
	vmpt3sas_remote_cmd_t remote_cmd;
	vmptsas_brdlocal_arg_t *priv = arg;
	int tx_len;
	int i;
	struct scsi_device *sdev;
    uint32_t hostid = zone_get_hostid(NULL);
	
	i = 0;
	shost_for_each_device(sdev, shost) {
		i++;
		/*printk(KERN_WARNING " %s host: %p host_no =%u chanl:%u id:%u lun:%u \n", 
			__func__, shost, shost->host_no, sdev->channel, sdev->id, sdev->lun);
			*/
	}

	/* encode message */
    len = XDR_EN_FIXED_SIZE + sizeof(int)*4 + sizeof(int)*3*(i+1);
	buff = cs_kmem_alloc(len);
	xdrmem_create(xdrs, buff, len, XDR_ENCODE);
	remote_cmd = VMPT_CMD_ADDHOST;
	xdr_int(xdrs, (int *)&remote_cmd);/* 4bytes */
    xdr_u_int(xdrs, (unsigned *)&priv->cause);
    
    xdr_u_int(xdrs,&hostid);
	xdr_u_int(xdrs,&shost->host_no);
	xdr_u_int(xdrs,&i);

	i = 0;
	shost_for_each_device(sdev, shost) {
        i++;
		/*
		if (i!=j) {
			continue;
		}*/
		xdr_u_int(xdrs,&sdev->channel);
		xdr_u_int(xdrs,&sdev->id);
		xdr_u_int(xdrs,(unsigned int *)&sdev->lun);
		
		printk(KERN_WARNING " %s (%d)pack hostno:%d chanel:%u id:%u lun:%u \n", __func__, 
			i, shost->host_no,sdev->channel, sdev->id, (unsigned int)sdev->lun);
	}
		
	tx_len = (uint_t)((uintptr_t)xdrs->x_addr - (uintptr_t)buff);
	printk(KERN_WARNING " %s brdcast [%p] msg len: %d host_no =%d \n",
		__func__, priv->sess, tx_len, shost->host_no);
	vmpt3sas_send_msg(priv->sess, NULL, 0, (void *)buff, tx_len, 0);
	cs_kmem_free(buff, len);
}

static void vmpt3sas_brdhost_handler(void *data)
{
	vmpt3sas_rx_data_t *rx_data = (vmpt3sas_rx_data_t *)data;
	void * session;
	XDR *xdrs;
	unsigned int host_id;
	remote_shost_t *iter;
	vmptsas_brdlocal_arg_t priv;

	xdrs = rx_data->xdrs;
	session = rx_data->cs_data->cs_private;
	xdr_u_int(xdrs,&host_id);

	priv.sess = session;
	priv.cause = VMPTSAS_BRDLC_SELFUP;
	vmpt3sas_lookup_report_shost(vmpt3sas_brdlocal_shost, &priv);
	vmpt3sas_rx_data_free(rx_data);

	spin_lock(&rshost_list.lock);
    list_for_each_entry(iter, &rshost_list.head, entry) {
        if(host_id == iter->host_id) {
            spin_unlock(&rshost_list.lock);
            printk(KERN_WARNING "%s scsi_host[%u] already registered", 
                   __func__, host_id);
            return;
		}
	}
    spin_unlock(&rshost_list.lock);

	vmpt3sas_brd_selfup();
	
	return;
}

static void vmpt3sas_addvhost_handler(void *data)
{
	unsigned int shost_no;
	void * session;
	struct Scsi_Host *shost;
	vmpt3sas_rx_data_t *rx_data = (vmpt3sas_rx_data_t *)data;
	vmpt3sas_t * ioc;
	int rv;
	int i,j;
	int chanel, id ,lun;
    unsigned int host_id;
    remote_shost_t *rshost, *iter;
	vmptsas_hostmap_t *hmp = NULL;
    vmptsas_brdlocal_cause_e cause; 
    vmptsas_brdlocal_arg_t priv;
	XDR *xdrs = rx_data->xdrs;
	
	session = rx_data->cs_data->cs_private;

    xdr_u_int(xdrs, (unsigned *)&cause);

    xdr_u_int(xdrs,&host_id);
	xdr_u_int(xdrs, &shost_no); /* 8bytes */
	xdr_u_int(xdrs, &j);
	printk(KERN_WARNING " %s host:%u hostno: %u devcount=%d ", 
	       __func__, host_id, shost_no, j);

    spin_lock(&rshost_list.lock);
    list_for_each_entry(iter, &rshost_list.head, entry) {
        if(host_id == iter->host_id && shost_no == iter->shost_no) {
            spin_unlock(&rshost_list.lock);
            printk(KERN_WARNING " scsi_host[%u:%u] already registered", 
                   host_id, shost_no);
            goto err_exists;
		}
	}

    rshost = shost_entry_alloc(host_id, shost_no);
    if(NULL == rshost) {
        spin_unlock(&rshost_list.lock);
        printk(KERN_ERR "alloc mem for rshost[%u:%u] failed ", 
               host_id, shost_no);
        goto err_rshost;
    }
    list_add(&rshost->entry, &rshost_list.head);
    spin_unlock(&rshost_list.lock);
	
	shost = scsi_host_alloc(&vmpt3sas_driver_template, sizeof(struct vmpt3sas));
	if (!shost){
	    printk(KERN_WARNING " %s scsi_host_alloc failed hostno: %d ", 
	           __func__, shost_no );
		goto err_shost;
	}

	shost->max_cmd_len = 16;
	shost->max_id = 128;
	shost->max_lun = 16;
	shost->max_channel = 0;
	shost->max_sectors = 256;
	
	ioc = shost_priv(shost);
	ioc->session = session;
	ioc->remotehostno = shost_no;
	ioc->remotehostid = host_id;
	ioc->logging_level = logging_level;
	ioc->shost = shost;
	spin_lock_init(&ioc->reqindex_lock);
	ioc->req_index = 0;
	ioc->vmpt_cmd_wait_hash = mod_hash_create_ptrhash(
							"vmpt_cmd_wait_hash", 1024,
							mod_hash_null_valdtor, 0);
	
	hmp = vmpt3sas_hostmap_alloc(host_id, g_vmptsas_hostmap_total, shost_no, shost);
	if(hmp == NULL) {
	    printk(KERN_WARNING " %s hostmap_alloc failed hostid:%d hostno: %d ", 
	           __func__, host_id, shost_no );
        goto err_hostmap;
	}
	
	spin_lock(&hostmap_list.lock);
	ioc->id = g_vmptsas_hostmap_total++;
	list_add(&hmp->entry, &hostmap_list.head);
    spin_unlock(&hostmap_list.lock);
    
	rv = scsi_add_host(shost, NULL);
	if (rv) {
		printk(KERN_WARNING " %s scsi_add_host failed ret: %d ", 
		       __func__, rv );
		goto err_add_host;
	}

	for (i=0; i<j; i++) {
		xdr_u_int(xdrs, &chanel);
		xdr_u_int(xdrs, &id);
		xdr_u_int(xdrs, &lun);
		
		printk(KERN_WARNING " %s scsi_add_device host_no:%d chanel:%u id:%u lun:%u \n", 
			   __func__,shost->host_no, chanel, id, lun);
		scsi_add_device(shost, chanel, id, lun);
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
	switch(cause) {
        case VMPTSAS_BRDLC_SELFUP: break;
        case VMPTSAS_BRDLC_DOWN_CVT_UP:
            priv.sess = session;
            priv.cause = VMPTSAS_BRDLC_SELFUP;
            vmpt3sas_lookup_report_shost(vmpt3sas_brdlocal_shost, &priv);
            /*
             * when a new cluster san host is added into cluster,
             * it's a new-created session. vmpt3sas_lenvent_callback
             * added ago was discarded when this host disabled from 
             * cluster.
             */
            csh_link_evt_hook_add(vmpt3sas_lenvent_callback, NULL);
            break;
	}
	vmpt3sas_rx_data_free(rx_data);
	scsi_host_put(shost);
	return ;
	
err_add_host:
    g_vmptsas_hostmap_total--;
    list_del(&hmp->entry);
    kfree(hmp);
err_hostmap:
    if(ioc && ioc->vmpt_cmd_wait_hash)
        mod_hash_destroy_ptrhash(ioc->vmpt_cmd_wait_hash);
    kfree(shost);
err_shost:
    shost_entry_free(rshost);
err_rshost:
err_exists:   
    return;
}

void vmpt3sas_proxy_handler(void *data)
{
	vmpt3sas_rx_data_t *prx ;
	XDR *xdrs ;
	vmpt3sas_req_scmd_t *req_scmd;
	struct scsi_device *sdev = NULL;
	struct Scsi_Host *shost;

	prx = (vmpt3sas_rx_data_t *)data;
	xdrs = prx->xdrs;

	req_scmd = kmalloc(sizeof(vmpt3sas_req_scmd_t), GFP_KERNEL);
	req_scmd->ndata = 0;
	req_scmd->datalen = 0;
	
	req_scmd->session = prx->cs_data->cs_private;
	
	xdr_u_longlong_t(xdrs, (u64 *)&req_scmd->req_index);/* 8bytes */
	xdr_u_longlong_t(xdrs, (uint64_t *)&shost);/* 8bytes */
	req_scmd->shost = shost;
	
	xdr_int(xdrs, &req_scmd->host);
	xdr_int(xdrs, &req_scmd->channel);
	xdr_int(xdrs, &req_scmd->id);
	xdr_int(xdrs, &req_scmd->lun);
	xdr_int(xdrs, (int *)(&req_scmd->data_direction));/* 4bytes */
	
	xdr_u_int(xdrs, &req_scmd->cmd_len);/* 4bytes */
	xdr_opaque(xdrs, (caddr_t)req_scmd->cmnd, req_scmd->cmd_len);
	xdr_u_int(xdrs, &(req_scmd->datalen));

	

	if (req_scmd->datalen!=0) 
	{
		if (req_scmd->data_direction == DMA_TO_DEVICE)
		{ /* write io , data is in the cs_data->data */
			if (prx->cs_data->data != NULL && prx->cs_data->data_len!=0)
			{
		
				req_scmd->ndata = 1;
				req_scmd->dataarr[0] = prx->cs_data->data;
				req_scmd->lendataarr[0] = prx->cs_data->data_len;
				prx->cs_data->data = NULL;
				prx->cs_data->data_len = 0;
			}
			else
			{
				printk(KERN_WARNING "%s: cs_data error datalen=%ld data=%p\n", 
					__func__, (long)prx->cs_data->data_len, prx->cs_data->data);
				return;
			}
		}
		else
		{ /* read io */
			req_scmd->ndata = 1;
			req_scmd->dataarr[0] = kmalloc(req_scmd->datalen, GFP_KERNEL);
			req_scmd->lendataarr[0] = req_scmd->datalen;
		}
	}
	vmpt3sas_rx_data_free(prx);
	
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
	}
}

int vmpt3sas_kmem_2_sgl(void * memaddr,unsigned long size, struct sg_table *sgtable)
{
	int ret;
	int num_pages;

	unsigned int i;
	struct scatterlist *s;
	unsigned long off;
	num_pages =0;
	
	for (off = 0; off < size; off += PAGE_SIZE){
		num_pages++;
		/*(virt_to_page(memaddr + off));*/
	}

	ret = sg_alloc_table(sgtable, num_pages, GFP_KERNEL);
	if (unlikely(ret)){
		printk(KERN_WARNING " %s sg_alloc_table failed %d",	__func__, ret );
		return ret;
	}

	off=0;
	for_each_sg(sgtable->sgl, s, sgtable->orig_nents, i) {
		int chunk_size;
		chunk_size = min((int)PAGE_SIZE,size);
		/*sg_set_page(s, virt_to_page(memaddr + off), chunk_size, offset_in_page(memaddr + off));*/
		sg_set_page(s, virt_to_page(memaddr + off), chunk_size, 0);
		size -= chunk_size;
		off += PAGE_SIZE;
	}
	return 0;

}

void vmpt3sas_proxy_response( void *data )
{
	struct request *req = (struct request *)data;
	vmpt3sas_remote_cmd_t remote_cmd;
	int err;
	XDR xdr_temp;
	XDR *xdrs = &xdr_temp;
	uint_t len;
	void *buff = NULL;
	vmpt3sas_req_scmd_t *reqcmd = req->end_io_data;
	struct scsi_cmnd *scmd;
	int senselen;
	int tx_len;
	int i;
	struct sg_table sgtable;
	void *kmem;
	int kmemlen;
	int issgl = 0;

	scmd = req->special;
	/* encode message */
	len = XDR_EN_FIXED_SIZE + reqcmd->datalen;
	buff = cs_kmem_alloc(len);
	xdrmem_create(xdrs, buff, len, XDR_ENCODE);
	remote_cmd = VMPT_CMD_RSP;
	xdr_int(xdrs, (int *)&remote_cmd);/* 4bytes */
	xdr_u_longlong_t(xdrs, (u64 *)&reqcmd->req_index);/* 8bytes */
	xdr_u_longlong_t(xdrs, (u64 *)&reqcmd->shost);/* 8bytes */
		
	xdr_int(xdrs, (int *)&req->errors);
	xdr_int(xdrs, (int *)&req->resid_len);
	
	if (req->sense!=NULL) {
		xdr_int(xdrs, (int *)&req->sense_len);
		xdr_opaque(xdrs, (caddr_t)req->sense, req->sense_len);
	} else {
		senselen = 0;
		xdr_int(xdrs, (int *)&senselen);
	}
	xdr_u_int(xdrs, &(reqcmd->datalen));

	kmem = NULL;
	kmemlen = 0;
	if (scmd->sc_data_direction != DMA_TO_DEVICE)
	{
		if(reqcmd->datalen>4096)
		{
			err = vmpt3sas_kmem_2_sgl(reqcmd->dataarr[0], reqcmd->lendataarr[0], &sgtable);
			if(err)				
				return;
			kmem = &sgtable;
			kmemlen = reqcmd->lendataarr[0];
			issgl = 1;
		}
		else if (reqcmd->datalen>0){
			kmem = reqcmd->dataarr[0];
			kmemlen = reqcmd->lendataarr[0];	
			issgl = 0;
		}
	}
	
	tx_len = (uint_t)((uintptr_t)xdrs->x_addr - (uintptr_t)buff);
	vmpt3sas_send_msg(reqcmd->session, kmem, kmemlen, (void *)buff, tx_len, issgl);
	if (issgl)
		sg_free_table(&sgtable);

	cs_kmem_free(buff, len);
	for (i=0; i<reqcmd->ndata; i++)
		kfree(reqcmd->dataarr[i]);
	kfree(reqcmd);
	
	blk_put_request(req);
	
}

int vmpt3sas_shost_ndevs(struct Scsi_Host *shost)
{
	int ndevs=0;
	struct scsi_device *sdev;
	ndevs=0;
	shost_for_each_device(sdev, shost) {
		printk(KERN_WARNING " %s host: %p host_no =%d chanl:%d id:%d lun:%d inquiry_len=%x type=%x scsi_level=%x\n", 
			__func__, shost, shost->host_no, sdev->channel, sdev->id, (int)sdev->lun,
			sdev->inquiry_len, sdev->type, sdev->scsi_level );
		ndevs++;
	}
	return ndevs;
}

void 
vmpt3sas_lookup_report_shost(vmpt3sas_lookup_shost_cb_fn fn, void *priv)
{
	int i,j;
	struct Scsi_Host *shost = NULL;
	
	int ndevs=0;
	int nndevs=0;
	for (i=0; i<128; i++) {
		shost = scsi_host_lookup(i);
		if (!shost )
			continue;
		
		if (!(strcmp(shost->hostt->proc_name,"mpt3sas") == 0 ||
			strcmp(shost->hostt->proc_name,"mpt2sas") == 0 ||
			strcmp(shost->hostt->proc_name, "megaraid_sas") ==0 )) {
			continue;						
		}

		printk(KERN_WARNING "%s shost :%d is found\n", __func__,shost->host_no);
		ndevs= vmpt3sas_shost_ndevs(shost);
		
		for(j=0;j<10;j++) {
			msleep(2000);
			nndevs= vmpt3sas_shost_ndevs(shost);
			if (nndevs>0 && nndevs==ndevs){
				fn(priv, shost);
				
				break;
			}
			printk(KERN_WARNING "shost:%d wait 2s for disk ready [%d %d]\n", 
				shost->host_no, ndevs, nndevs);
			ndevs = nndevs;
		}
	}
	
	return ; 
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


static struct Scsi_Host *vmpt3sas_print_shostdevs(void)
{
	int i=0;
	struct Scsi_Host *shost = NULL;

	for (i=0; i<128; i++) {
		shost = scsi_host_lookup(i);
		if (shost) 
			vmpt3sas_listall_scsidev(shost);
	}

	printk(KERN_WARNING "mptsas shost is not found\n");
	return NULL; 
}


static vmptsas_quecmd_t *vmpt3sas_get_cmd(vmptsas_instance_t *instance)
{
	unsigned long flags;
	vmptsas_quecmd_t *cmd = NULL;

	spin_lock_irqsave(&instance->hba_lock, flags);

	if (!list_empty(&instance->cmd_pool)) {
		cmd = list_entry((&instance->cmd_pool)->next,
				 vmptsas_quecmd_t, list);
		list_del_init(&cmd->list);
	} else {
		printk(KERN_ERR "vmpt3sas: Command pool empty!\n");
	}

	spin_unlock_irqrestore(&instance->hba_lock, flags);
	return cmd;
}

static void 
vmpt3sas_return_cmd(vmptsas_instance_t *instance, vmptsas_quecmd_t *cmd)
{
	unsigned long flags;
	
	spin_lock_irqsave(&instance->hba_lock, flags);
	cmd->scmd = NULL;
	list_add(&cmd->list, (&instance->cmd_pool)->next);
	spin_unlock_irqrestore(&instance->hba_lock, flags);
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

		vmpt3sas_proxy_response(req);
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
	char p80[256+1];
	
	xdr_u_longlong_t(xdrs, (u64 *)&rsp_index);/* 8bytes */
	xdr_u_longlong_t(xdrs, (u64 *)&shost);/* 8bytes */
	
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
	if (senselen){
		VERIFY(scmd->sense_buffer != NULL);
		xdr_opaque(xdrs, (caddr_t)scmd->sense_buffer, senselen);
	}
	
	if (scmd->sc_data_direction == DMA_FROM_DEVICE) {
		
		scmd->sdb.length = rx_data->cs_data->data_len;
			
		if (scmd->cmnd[0] == 0x12 && scmd->cmnd[2]==0x83 && (xdrs->x_addr_end - xdrs->x_addr)<=256 ) {
			memcpy(p80, rx_data->cs_data->data,rx_data->cs_data->data_len);
			p80[8+0] = ioc->remotehostid;
			scsi_sg_copy_from_buffer(scmd, p80, scmd->sdb.length);	
		}
		else
			scsi_sg_copy_from_buffer(scmd, rx_data->cs_data->data,rx_data->cs_data->data_len);
		
	}

	scmd->scsi_done(scmd);

failed:
	vmpt3sas_rx_data_free(rx_data);
	return;
}

static struct Scsi_Host * 
vmpt3sas_lookup_vmptsas_shost_by_hostid_and_shostno(uint_t hostid, uint_t shostno)
{
    int found = 0;
	struct Scsi_Host *shost = NULL;
    vmpt3sas_t *ioc = NULL;
    vmptsas_hostmap_t *iter = NULL;
    vmptsas_hostmap_t *vhostmap = NULL;

    /*
    printk(KERN_WARNING "%s: hostid:%u, shostno:%u, size:%u", 
           __func__, hostid, shostno, g_vmptsas_hostmap_total);
    */
    /*
     * we only care Scsi_Host whose is added to g_vmptsas_hostmap_array before.
     */
    spin_lock(&hostmap_list.lock);
	list_for_each_entry(iter, &hostmap_list.head, entry) {
	/*
        printk(KERN_WARNING "%s: iter hostid:%u, shostno:%u", 
               __func__, hostid, shostno);
	*/
		if ( (iter->hostid == hostid) &&
		     (iter->remote_hostno == shostno) ) {
		    found = 1;
            break;
		}
	}
	spin_unlock(&hostmap_list.lock);
	shost = (found ? iter->shost : NULL);
	return shost; 
}

static void
vmpt3sas_state_change_cb_removed(void *data)
{
    int found = 0;
    vmpt3sas_rx_data_t *prx = data;
    XDR *xdrs = prx->xdrs;
    cs_rx_data_t *rx_data = prx->cs_data;
    uint_t hostid, shost_no, channel, id, lun;
    remote_shost_t *iter = NULL;
    struct Scsi_Host *shost = NULL;
    struct scsi_device *sdev = NULL;
    struct scsi_device *sdev2 = NULL;
    
    xdr_u_int(xdrs, &hostid);
    xdr_u_int(xdrs, &shost_no);

    spin_lock(&rshost_list.lock);
    list_for_each_entry(iter, &rshost_list.head, entry) {
        if( (hostid == iter->host_id) && 
            (shost_no == iter->shost_no) ) {
            found = 1;
            break;
    	}
	}
    spin_unlock(&rshost_list.lock);
	if( !found ) {
        printk(KERN_WARNING "%s: not added scsi_host[%u %u]", 
               __func__, hostid, shost_no);
        return ;
	}

    xdr_u_int(xdrs, &channel);
    xdr_u_int(xdrs, &id);
    xdr_u_int(xdrs, &lun);
    
    shost = vmpt3sas_lookup_vmptsas_shost_by_hostid_and_shostno(hostid, shost_no);
    if( (NULL == shost) ||
        ((sdev = scsi_device_lookup(shost, channel, id, lun)) == NULL) ) {
        printk(KERN_WARNING "%s: not founded scsi_device[%u %u %u %u %u %p %p]", 
               __func__, hostid, shost_no, channel, id, lun, shost, sdev);
    }

    if(sdev != NULL) {
        scsi_remove_device(sdev);
        scsi_device_put(sdev);
    }
    
    return ;
}


void
vmpt3sas_state_change_handler(void *data)
{

   vmpt3sas_rx_data_t *prx = data;
    XDR *xdrs = prx->xdrs;
    sd_state_change_types type;
    
    xdr_u_int(xdrs, &type);
    switch(type) {
        case SD_STATE_REMOVED:
            vmpt3sas_state_change_cb_removed(data);
            break;
        default:
            printk(KERN_WARNING "state_change_handler: unsupported type[%u]", type);
			break;
    }
    
    vmpt3sas_rx_data_free(prx);
    return ;
}

int vmpt3sas_send_msg(void *sess, void *data, u64 len, void *header, u64 headerlen, int issgl)
{
	int ret = 0;
	if (sess == VMPT3SAS_BROADCAST_SESS) {
		cluster_san_broadcast_send(data, len, header, headerlen, CLUSTER_SAN_MSGTYPE_IMPTSAS, 0);
	} else {

		if(issgl)
			ret = cluster_san_host_send_sgl(sess, data, len, header, headerlen, CLUSTER_SAN_MSGTYPE_IMPTSAS, 0,
				1, 3);
		else
			ret = cluster_san_host_send(sess, data, len, header, headerlen, CLUSTER_SAN_MSGTYPE_IMPTSAS, 0,
				1, 3);	
	}
	return (ret);
}

static void vmpt3sas_clustersan_rx_cb(cs_rx_data_t *cs_data, void *arg)
{
	vmpt3sas_remote_cmd_t remote_cmd;
	XDR *xdrs;
	vmpt3sas_rx_data_t *rx_data;
	taskq_t *tq_common = (taskq_t *)arg;

	if (cs_data->ex_len == 0 || cs_data->ex_head == NULL) {
		printk(KERN_WARNING "%s: exdata is null ex_len=%lld ex_data=%p\n",
			__func__, cs_data->ex_len, cs_data->ex_head);
		return;
	}	

	rx_data = kmem_zalloc(sizeof(vmpt3sas_rx_data_t), KM_SLEEP);
	xdrs = kmem_zalloc(sizeof(XDR), KM_SLEEP);
	rx_data->xdrs = xdrs;
	rx_data->cs_data = cs_data;
	/*xdrmem_create(xdrs, cs_data->data, cs_data->data_len, XDR_DECODE);*/
	
	xdrmem_create(xdrs, cs_data->ex_head, cs_data->ex_len, XDR_DECODE);
	xdr_int(xdrs, (int *)&remote_cmd);
	/*
	printk(KERN_WARNING "%s: msgtype=[%d] \n", __func__,remote_cmd);
	*/
	switch(remote_cmd) {
		case VMPT_CMD_REQUEST:
			taskq_dispatch(tq_common,
				vmpt3sas_proxy_handler, (void *)rx_data, TQ_SLEEP);
			
			break;
		case VMPT_CMD_RSP:
			taskq_dispatch(tq_common,
				vmpt3sas_rsp_handler, (void *)rx_data, TQ_SLEEP);
 			
			break;
		case VMPT_CMD_ADDHOST:
			taskq_dispatch(tq_common,
				vmpt3sas_addvhost_handler, (void *)rx_data, TQ_SLEEP);
			break;
		case VMPT_CMD_SELFUP:
			taskq_dispatch(tq_common,
				vmpt3sas_brdhost_handler, (void *)rx_data, TQ_SLEEP);
			break;
		case VMPT_CMD_STATE_CHANGE:
			taskq_dispatch(tq_common,
				vmpt3sas_state_change_handler, (void *)rx_data, TQ_SLEEP);
			break;
		default:
			vmpt3sas_rx_data_free(rx_data);
			printk(KERN_WARNING "vmptsas_remote_req_handler: Don't support");
			break;
	}
}

void vmpt3sas_debug_print_sg(struct scsi_cmnd *scmd)
{
	struct scatterlist * sg = scsi_sglist(scmd);
	int count = scsi_sg_count(scmd);
	int i=0;
	struct page *pg;
	printk(KERN_WARNING "%s: len=%d count=%d pagesize=%d\n",
		__func__, scmd->sdb.length, count, (int)PAGE_SIZE);
	while (sg){
		int iremain;
		void *paddress;

		pg = sg_page(sg);
		iremain = sg->length;
		paddress = page_address(pg);
		do {
			printk(KERN_WARNING "%s: no[%d] off=%d len=%d pageaddr=%p\n",
			__func__, i, sg->offset, sg->length, paddress);
			iremain -= PAGE_SIZE;
			pg++ ;
			paddress = page_address(pg);
		} while (iremain>0);
		
		i++;
		sg = sg_next(sg);
	}
}

int vmpt3sas_trans_sg(struct scsi_cmnd *scmd,struct sg_table *sgtable)
{
	struct scatterlist * sg = scsi_sglist(scmd);
	int count = scsi_sg_count(scmd);
	int num_pages = (scmd->sdb.length + PAGE_SIZE-1)/PAGE_SIZE;
	int ret;
	struct page *pg;
	struct scatterlist *s;
	int i;
	int chunk_size;
	int iremainlen = scmd->sdb.length;
	int isglen;
	
	ret = sg_alloc_table(sgtable, num_pages, GFP_KERNEL);
	if (unlikely(ret)){
		printk(KERN_WARNING " %s sg_alloc_table failed %d",	__func__, ret );
		return 0;
	}

	chunk_size = 0;
	isglen = sg->length;
	pg = sg_page(sg);
	
	for_each_sg(sgtable->sgl, s, sgtable->orig_nents, i) {
		chunk_size = min((int)PAGE_SIZE,iremainlen);
		
		sg_set_page(s, pg, chunk_size, 0);
		iremainlen -= chunk_size;
		isglen -= chunk_size;
		
		if(isglen >0)
			pg++;
		else{
			sg = sg_next(sg);
			if(sg){
				isglen = sg->length;
				pg = sg_page(sg);
			}
		}
	}
	
	return num_pages;
}

void
vmpt3sas_qcmd_handler(void *inputpara)
{
	struct Scsi_Host *shost = ((vmptsas_quecmd_t *)inputpara)->shost;
	struct scsi_cmnd *scmd = ((vmptsas_quecmd_t *)inputpara)->scmd;
	vmpt3sas_remote_cmd_t remote_cmd;
	vmpt3sas_t *ioc = shost_priv(shost);
	XDR xdr_temp;
	XDR *xdrs = &xdr_temp;
	uint_t len;
	uint_t tx_len;
	void *buff = NULL;
	u64 index;
	int err;
	void *kmem = NULL;
	int kmemlen = 0;
	int newsgtable=0;
	struct sg_table sgtable;
	
	/*encode message*/
	len = XDR_EN_FIXED_SIZE + scmd->cmd_len + scmd->sdb.length;
	buff = cs_kmem_alloc(len);
	xdrmem_create(xdrs, buff, len, XDR_ENCODE);
	remote_cmd = VMPT_CMD_REQUEST;
	xdr_int(xdrs, (int *)&remote_cmd);/* 4bytes */

	index = ioc->req_index;
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
	if (scmd->cmnd == NULL || scmd->cmd_len>16 || scmd->cmd_len<=0){
		printk(KERN_WARNING "scmd error cmdaddr:%p len:%d\n", scmd->cmnd, scmd->cmd_len);
		cs_kmem_free(buff, len);
		scmd->result = DID_ERROR << 16;
		scmd->scsi_done(scmd);
		vmpt3sas_return_cmd(&gvmpt3sas_instance, (vmptsas_quecmd_t *)inputpara);
	}
	
	xdr_opaque(xdrs, (caddr_t)scmd->cmnd, scmd->cmd_len);

	if (ioc->logging_level)
		scsi_print_command(scmd);

	xdr_int(xdrs, &(scmd->sdb.length));
	if (scmd->sdb.length != 0) {
		
		if (scmd->sc_data_direction != DMA_TO_DEVICE) {
			
		} else {

			int num_pages = (scmd->sdb.length + PAGE_SIZE-1)/PAGE_SIZE;
			if (num_pages != scmd->sdb.table.nents) {
				int ret = vmpt3sas_trans_sg(scmd, &sgtable);
				if (!ret){
					return;
				}
				kmem=&sgtable;
				newsgtable = 1;
			} else {
				kmem = &(scmd->sdb.table);
			}
			
			kmemlen = scmd->sdb.length; 
			/*vmpt3sas_debug_print_sg(scmd);*/
		}
	}

	tx_len = (uint_t)((uintptr_t)xdrs->x_addr - (uintptr_t)buff);
	mod_hash_insert(ioc->vmpt_cmd_wait_hash,
		(mod_hash_key_t)(uintptr_t)index, (mod_hash_val_t)scmd);
	
	err = vmpt3sas_send_msg(ioc->session, kmem, kmemlen, (void *)buff, tx_len,1);
	if(newsgtable)
		sg_free_table(&sgtable);
		
	cs_kmem_free(buff, len);
	if (err != 0) {
		printk(KERN_WARNING "index %llu message failed!\n", index);
		scmd->result = DID_NO_CONNECT << 16;
		scmd->scsi_done(scmd);
	}
	vmpt3sas_return_cmd(&gvmpt3sas_instance, (vmptsas_quecmd_t *)inputpara);
	return ;
}

int vmpt3sas_slave_alloc(struct scsi_device *sdev)
{
	
	sdev->inquiry_len = 0x4a;
	
	sdev->type = 0;
	sdev->scsi_level = 4;
	sdev->try_vpd_pages = 1;
	/*
	dump_stack();
	*/
	return 0;
}

int vmpt3sas_slave_configure(struct scsi_device *sdev)
{
	struct device *dev;
	struct bus_type *bus;
	struct subsys_private *psubsys;
	printk(KERN_WARNING "%s is run \n", __func__);
	
	dev = &sdev->sdev_gendev;
	bus = dev->bus;
	if (bus){
		psubsys = bus->p;
		printk(KERN_WARNING "%s try_vpd_pages:%d scsi_level:%d skip_vpd_pages:%d inquiry_len=%x", 
			__func__, sdev->try_vpd_pages, sdev->scsi_level, sdev->skip_vpd_pages, sdev->inquiry_len );
	}
	return 0;
}

void vmpt3sas_slave_destroy(struct scsi_device *sdev)
{
	printk(KERN_WARNING "%s id:%d lun:%d channel:%d \n", 
		__func__, sdev->id, (int)sdev->lun, (int)sdev->channel);
	dump_stack();
}

int
vmpt3sas_scsih_qcmd(struct Scsi_Host *shost, struct scsi_cmnd *scmd)
{
	vmptsas_quecmd_t *cmd;
	vmpt3sas_t *ioc = shost_priv(shost);

	cmd = vmpt3sas_get_cmd(&gvmpt3sas_instance);
	if (cmd == NULL){
		
		printk(KERN_WARNING "can not get cmd  \n");
		scmd->result = DID_NO_CONNECT << 16;
		scmd->scsi_done(scmd);
		return 0;
	}
	
	spin_lock_irq(&ioc->reqindex_lock);
	ioc->req_index++;	
	spin_unlock_irq(&ioc->reqindex_lock);
	
	cmd->scmd = scmd;
	cmd->shost = shost;

	#if 0
	req_proxy_t *proxy = &(gvmpt3sas_instance.qcmdproxy);
	spin_lock_irq(&proxy->queue_lock);
	list_add_tail(&cmd->donelist, &proxy->done_queue);
	spin_unlock_irq(&proxy->queue_lock);
	wake_up(&proxy->waiting_wq);
	#else
	taskq_dispatch(gvmpt3sas_instance.tq_pexec,
				vmpt3sas_qcmd_handler, (void *)cmd, TQ_SLEEP);
	#endif
	
	
	return 0;
}

int vmpt3sas_qcmd_done_thread(void *data)
{
	vmptsas_quecmd_t *quecmd;
	req_proxy_t *proxy = (req_proxy_t *)data;
	
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
		quecmd = list_entry(proxy->done_queue.next, vmptsas_quecmd_t,
				 donelist);
		list_del_init(&quecmd->donelist);
		spin_unlock_irq(&proxy->queue_lock);
		
		vmpt3sas_qcmd_handler(quecmd);
	}
	return 0;
}

static void
vmpt3sas_sd_state_changed_cb(struct device *dev, 
                             void *priv, sd_state_change_types type)
{
	vmpt3sas_remote_cmd_t remote_cmd;
	XDR xdr_temp;
	XDR *xdrs = &xdr_temp;
	uint_t tx_len;
	uint_t len;
	void *buff = NULL;
	int err = 0;
	uint_t host_id = zone_get_hostid(NULL);
	struct scsi_disk *sdkp = NULL;
    struct scsi_device *sdvp = NULL;
    struct Scsi_Host *shp = NULL;
    
	if( (type > SD_STATE_FAULTY) ||
	    ((sdkp = dev_get_drvdata(dev)) == NULL) ||
	    ((sdvp = sdkp->device) == NULL) ||
	    ((shp = sdvp->host) == NULL) ) {
	    printk(KERN_WARNING "sd_state_change: invalid params");
	    return ;
	}
	/*encode message*/
	len = XDR_EN_FIXED_SIZE + sizeof(uint_t)*6;
	buff = cs_kmem_alloc(len);
	xdrmem_create(xdrs, buff, len, XDR_ENCODE);
	
	remote_cmd = VMPT_CMD_STATE_CHANGE;
	xdr_int(xdrs, (int *)&remote_cmd);/* 4bytes */
	xdr_u_int(xdrs, &type);
	xdr_u_int(xdrs, &host_id);
    xdr_u_int(xdrs, &shp->host_no);
    xdr_u_int(xdrs, &sdvp->channel);
    xdr_u_int(xdrs, &sdvp->id);
    xdr_u_int(xdrs, &sdvp->lun);
    tx_len = (uint_t)((uintptr_t)xdrs->x_addr - (uintptr_t)buff);
    
    err = vmpt3sas_send_msg(VMPT3SAS_BROADCAST_SESS, 
                            NULL, 0, buff, (u64)tx_len, 0);
    if(err != 0)
        printk(KERN_WARNING "sd_state_change: send state change message fail");
        
    cs_kmem_free(buff, len);
	return ;
}

static void
vmpt3sas_hdl_up_to_down(uint_t hostid)
{
    int isfind = 0;
    vmpt3sas_t *ioc = NULL;
    struct Scsi_Host *shost = NULL;
    vmptsas_hostmap_t *iter = NULL;
    vmptsas_hostmap_t *vhostmap = NULL;

    printk(KERN_WARNING "%s hostmap:%u", __func__, g_vmptsas_hostmap_total);
    spin_lock(&hostmap_list.lock);   
    list_for_each_entry(iter, &hostmap_list.head, entry) {
        printk(KERN_WARNING "%s iter hostid:%u", __func__, iter->hostid);
        if( (iter->hostid == hostid) &&
            (shost = iter->shost) &&
            (ioc = shost_priv(shost)) &&
            (ioc->remotehostid == hostid) ) {
            isfind = 1;
            list_del(&iter->entry);
            break;
        }
    }
    spin_unlock(&hostmap_list.lock);
    printk(KERN_WARNING "%s isfind:%d shost:%p", __func__, isfind, shost);
    if(isfind) {
        scsi_remove_host(shost);
        kfree(iter);
    }
}

static void 
vmpt3sas_hdl_down_to_up(cluster_san_hostinfo_t *hostp)
{
    vmptsas_brdlocal_arg_t priv = {
        .sess = hostp,
        .cause = VMPTSAS_BRDLC_DOWN_CVT_UP
    };
    vmpt3sas_lookup_report_shost(vmpt3sas_brdlocal_shost, &priv);
}

void 
vmpt3sas_lenvent_callback(void *private, cts_link_evt_t link_evt, void *arg)
{
    int found = 0;
	remote_shost_t  *iter = NULL;
	cluster_san_hostinfo_t *hostp = private;
	u32 hostid = hostp->hostid;
	
	printk(KERN_WARNING "%s: event:%d hostid:%d", 
	       __func__, link_evt, hostid);
	switch(link_evt)
	{
	case LINK_EVT_UP_TO_DOWN:
		spin_lock(&rshost_list.lock);
	    list_for_each_entry(iter, &rshost_list.head, entry) {
	        if(hostid == iter->host_id ) {
	            found = 1;
	            break;
			}
		}

    	if(!found) {
            spin_unlock(&rshost_list.lock);
            printk(KERN_WARNING "%s: hostid[%u] not found", 
	               __func__, hostid);
	        return ;
    	}
    	
    	list_del(&iter->entry);
		spin_unlock(&rshost_list.lock);
		shost_entry_free(iter);
		printk(KERN_WARNING "%s: hostid[%u] deleted", 
	           __func__, hostid);
	           
		vmpt3sas_hdl_up_to_down(hostid);
		break;
	case LINK_EVT_DOWN_TO_UP:		
		spin_lock(&rshost_list.lock);
	    list_for_each_entry(iter, &rshost_list.head, entry) {
	        if(hostid == iter->host_id ) {
	            found = 1;
	            break;
			}
		}

        spin_unlock(&rshost_list.lock);
		if(found) {
            
            printk(KERN_WARNING "%s: hostid[%u] have registered", 
                   __func__, hostid);
            return ;
		}
		
        printk(KERN_WARNING "%s: hostid[%u] have not registered yet", 
               __func__, hostid);

        vmpt3sas_hdl_down_to_up(hostp);
		break;
	default:
		break;
	}
}

static void vmpt3sas_init_instance(vmptsas_instance_t *instance)
{
	int i,j;
	int max_cmd = 1024;
	vmptsas_quecmd_t *cmd;
	req_proxy_t *proxy;
	
	instance->max_cmds = max_cmd;
	INIT_LIST_HEAD(&instance->cmd_pool);
	spin_lock_init(&instance->hba_lock);
	
	instance->cmd_list = kcalloc(max_cmd, sizeof(vmptsas_quecmd_t *), GFP_KERNEL);
	if (!instance->cmd_list) {
		printk(KERN_DEBUG "vmpt3sas: out of memory\n");
		return ;
	}
	memset(instance->cmd_list, 0, sizeof(vmptsas_quecmd_t *) * max_cmd);

	for (i = 0; i < max_cmd; i++) {
		instance->cmd_list[i] = kmalloc(sizeof(vmptsas_quecmd_t),
			GFP_KERNEL);

		if (!instance->cmd_list[i]) {
			for (j = 0; j < i; j++)
				kfree(instance->cmd_list[j]);

			kfree(instance->cmd_list);
			instance->cmd_list = NULL;
			return ;
		}
	}

	for (i = 0; i < max_cmd; i++) {
		cmd = instance->cmd_list[i];
		memset(cmd, 0, sizeof(vmptsas_quecmd_t));
		cmd->index = i;

		list_add_tail(&cmd->list, &instance->cmd_pool);
	}
	
	proxy = &instance->qcmdproxy;
	INIT_LIST_HEAD(&proxy->done_queue);
	spin_lock_init(&proxy->queue_lock);
	init_waitqueue_head(&proxy->waiting_wq);
	
	proxy->thread = kthread_create(vmpt3sas_qcmd_done_thread, proxy, "%s", "vd_qcmd");
	if (IS_ERR(proxy->thread)) {
		printk(KERN_WARNING "kthread_create failed");
		return ;
	}
	wake_up_process(proxy->thread);

	proxy = &instance->dcmdproxy;
	INIT_LIST_HEAD(&proxy->done_queue);
	spin_lock_init(&proxy->queue_lock);
	init_waitqueue_head(&proxy->waiting_wq);
	
	proxy->thread = kthread_create(vmpt3sas_proxy_done_thread, proxy, "%s", "vd_qcmd");
	if (IS_ERR(proxy->thread)) {
		printk(KERN_WARNING "kthread_create failed");
		return ;
	}
	wake_up_process(proxy->thread);
}

static vmptsas_hostmap_t *
vmpt3sas_hostmap_alloc(int hostid, int index, int hostno, struct Scsi_Host *shost)
{
    vmptsas_hostmap_t *outp = NULL;
    if( (outp = kmalloc(sizeof(*outp), GFP_KERNEL)) == NULL ) {
        printk(KERN_WARNING "%s kmalloc fail", __func__);
        goto out;
    }
    outp->hostid = hostid;
    outp->index = index;
    outp->remote_hostno = hostno;
    outp->shost = shost;
    INIT_LIST_HEAD(&outp->entry);
out:
    return outp;
}

static void 
vmpt3sas_init_hostmap_list(void)
{
    INIT_LIST_HEAD(&hostmap_list.head);
    spin_lock_init(&hostmap_list.lock);
}

long
vmpt3sas_unlocked_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	printk(KERN_WARNING "%s runing cmd=%d \n", __func__, cmd);
	
	vmpt3sas_print_shostdevs();

	return ret;
}

int
vmpt3sas_open (struct inode *inode, struct file *filep)
{
	printk(KERN_WARNING "%s runing \n", __func__);
	return 0;
}

/*
static int vmpt3sas_cdev_init(void)
{
	int ret;
	dev_t devno;
	struct cdev cdev;
	struct class *cdev_class;
	ret = alloc_chrdev_region(&devno, 0 , 1 , "vmpt3sas_chrdev");
	if (ret) {
		printk(KERN_WARNING "alloc_chrdev_region failed");
		unregister_chrdev_region(devno, 1);
		return ret;
	}
	
	cdev_init(&cdev, &vmpt3sas_fops);
	ret = cdev_add(&cdev, devno, 1);
	if (ret) {
		printk(KERN_WARNING "cdev_add failed");
		unregister_chrdev_region(devno, 1);
		return ret;
	}

	cdev_class = class_create(THIS_MODULE, "vmpt3sas_chrdev");
	if (IS_ERR(cdev_class)) {
		printk(KERN_WARNING "class_create failed");
		unregister_chrdev_region(devno, 1);
		return -1;
	}
	
	device_create(cdev_class,NULL,devno,NULL, "vmpt3sas_chrdev");

	return 0;
}
*/

/**
 * _mpt3sas_init - main entry point for this driver.
 *
 * Returns 0 success, anything else error.
 */
static int __init
_vmpt3sas_init(void)
{
	int err;
	
	pr_info("%s loaded\n", VMPT3SAS_DRIVER_NAME);
	
    is_loading = B_TRUE;
    is_loaded = B_FALSE;
    
	init_remote_shost_list();

	/* qcmd multi_threads and  done multi_threads */
	gvmpt3sas_instance.tq_pexec=
	 	taskq_create("qdone_taskq", 8, minclsyspri,
    		8, INT_MAX, TASKQ_PREPOPULATE);
	if (gvmpt3sas_instance.tq_pexec == NULL) {
		printk(KERN_WARNING " %s taskq_create qdone_taskq failed:", __func__);
		return 0;
	}

	/* qcmd multi_threads and  done multi_threads */
	gvmpt3sas_instance.tq_pexecproxy=
	 	taskq_create("qproxy_taskq", 8, minclsyspri,
    		8, INT_MAX, TASKQ_PREPOPULATE);
	if (gvmpt3sas_instance.tq_pexec == NULL) {
		printk(KERN_WARNING " %s taskq_create qproxy_taskq failed:", __func__);
		return 0;
	}
	
	/* msg receive thread */
	gvmpt3sas_instance.tq_common =
	 	taskq_create("request_taskq", 8, minclsyspri,
    		8, INT_MAX, TASKQ_PREPOPULATE);
	if (gvmpt3sas_instance.tq_common == NULL) {
		printk(KERN_WARNING " %s taskq_create request_taskq failed:", __func__);
		return 0;
	}
	csh_rx_hook_add(CLUSTER_SAN_MSGTYPE_IMPTSAS, vmpt3sas_clustersan_rx_cb, gvmpt3sas_instance.tq_common);

	vmpt3sas_init_instance(&gvmpt3sas_instance);
	vmpt3sas_init_hostmap_list();

	/*
	clustersan_vsas_set_levent_callback(vmpt3sas_lenvent_callback, NULL);
	*/
	csh_link_evt_hook_add(vmpt3sas_lenvent_callback, NULL);
	sd_register_cb_state_changed(vmpt3sas_sd_state_changed_cb, NULL);
	
	err = misc_register(&vmpt3sas_mm_dev);
	if (err < 0) {
		printk(KERN_WARNING "%s: cannot register misc device\n", __func__);
		return err;
	}
    
	vmpt3sas_brd_selfup();
	return 0;

}

/**
 * _mpt3sas_exit - exit point for this driver (when it is a module).
 *
 */
static void __exit
_vmpt3sas_exit(void)
{
	misc_deregister(&vmpt3sas_mm_dev);
	kthread_stop(gvmpt3sas_instance.qcmdproxy.thread);
	kthread_stop(gvmpt3sas_instance.dcmdproxy.thread);
	csh_rx_hook_remove(CLUSTER_SAN_MSGTYPE_IMPTSAS);
	csh_link_evt_hook_remove(vmpt3sas_lenvent_callback);
	pr_info("%s exit\n", VMPT3SAS_DRIVER_NAME);
}

module_init(_vmpt3sas_init);
module_exit(_vmpt3sas_exit);
MODULE_LICENSE("GPL");
