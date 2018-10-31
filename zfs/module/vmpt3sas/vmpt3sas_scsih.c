/*
 * Scsi Host Layer for MPT (Message Passing Technology) based controllers
 *
 * This code is based on drivers/scsi/mpt3sas/mpt3sas_scsih.c
 * Copyright (C) 2012-2014  LSI Corporation
 * Copyright (C) 2013-2014 Avago Technologies
 *  (mailto: MPT-FusionLinux.pdl@avagotech.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * NO WARRANTY
 * THE PROGRAM IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED INCLUDING, WITHOUT
 * LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is
 * solely responsible for determining the appropriateness of using and
 * distributing the Program and assumes all risks associated with its
 * exercise of rights under this Agreement, including but not limited to
 * the risks and costs of program errors, damage to or loss of data,
 * programs or equipment, and unavailability or interruption of operations.

 * DISCLAIMER OF LIABILITY
 * NEITHER RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE OF ANY RIGHTS GRANTED
 * HEREUNDER, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

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
#include <linux/raid_class.h>
#include <asm/unaligned.h>
#include <sys/cluster_san.h>

#include "vmpt3sas_base.h"

#define	IMPT3SAS_BROADCAST_SESS				((void *)(0-1))
#define	XDR_EN_FIXED_SIZE	256/* Leave allowance */
#define	XDR_DE_FIXED_SIZE	256/* Leave allowance */

#define	VMPT3SAS_REQ_HASH_SIZE	10000
#define VMPT3SAS_DRIVER_NAME		"vmpt3sas"
/*
 * logging format
 */
#define VMPT3SAS_FMT			"%s: "

static vmpt3sas_t *gvmpt3sas;

static uint64_t greq_index = 0;
static uint32_t vmpt3_ids = 0;
static uint32_t vmpt3_receive_worker_count = 128;

static ushort max_sectors = 0xFFFF;
module_param(max_sectors, ushort, 0);
MODULE_PARM_DESC(max_sectors, "max sectors, range 64 to 32767  default=32767");

/* permit overriding the host protection capabilities mask (EEDP/T10 PI) */
static int prot_mask = -1;
module_param(prot_mask, int, 0);
MODULE_PARM_DESC(prot_mask, " host protection capabilities mask, def=7 ");

/* command line options */
static u32 logging_level;
MODULE_PARM_DESC(logging_level,
	" bits for enabling additional logging info (default=0)");


#define MPT3SAS_PROCESS_TRIGGER_DIAG (0xFFFB)
#define MPT3SAS_TURN_ON_PFA_LED (0xFFFC)
#define MPT3SAS_PORT_ENABLE_COMPLETE (0xFFFD)
#define MPT3SAS_ABRT_TASK_SET (0xFFFE)
#define MPT3SAS_REMOVE_UNRESPONDING_DEVICES (0xFFFF)

void vmpt3sas_rx_data_free(vmpt3sas_rx_data_t *rx_data)
{
	kmem_free(rx_data->xdrs, sizeof(VMPT_XDR));
	csh_rx_data_free_ext(rx_data->cs_data);
	kmem_free(rx_data, sizeof(vmpt3sas_rx_data_t));
}


static vmpt3sas_cmd_t *
vmpt3sas_alloc_cmd(uint64_t index, struct scsi_cmnd *scmd)
{
	vmpt3sas_cmd_t *cmd;

	cmd = (vmpt3sas_cmd_t *)kmem_alloc(sizeof(vmpt3sas_cmd_t), KM_SLEEP);
	memset(cmd, 0, sizeof(vmpt3sas_cmd_t));

	cmd->req_index = index;
	cmd->scmd = scmd;
	cmd->cmd_state = VMPTSAS_CMD_STATE_PENDING;

	mutex_init(&cmd->cmd_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&cmd->cmd_completion, NULL, CV_DRIVER, NULL);
}

int vmpt3sas_send_msg(void *sess, void *data, uint64_t len)
{
	int ret = 0;
	if (sess == IMPTSAS_BROADCAST_SESS) {
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
	printk("imptsas_remote_req_handler: data len(%"PRIx64")\n",
		cs_data->data_len));
	VMPT_XDR *xdrs;
	vmpt3sas_rx_data_t *rx_data;
	int ret;

	if ((cs_data->data_len == 0) || (cs_data->data == NULL)) {
		return;
	}

	rx_data = kmem_zalloc(sizeof(vmpt3sas_rx_data_t), KM_SLEEP);
	xdrs = kmem_zalloc(sizeof(VMPT_XDR), KM_SLEEP);
	rx_data->xdrs = xdrs;
	rx_data->cs_data = cs_data;
	vmpt_xdrmem_create(xdrs, cs_data->data, cs_data->data_len, VMPT_XDR_DECODE);
	vmpt_xdr_enum(xdrs, (enum_t *)&remote_cmd);
	switch(remote_cmd) {
		case VMPT_CMD_REQUEST:
			ret = taskq_dispatch(gvmpt3sas->tq_req,
				(void(*)(void *))imptsas_req_handler, (void *)rx_data, DDI_SLEEP);
			if (DDI_SUCCESS != ret) {
				/*todo*/
			}
			break;
		case VMPT_CMD_RSP:
			ret = taskq_dispatch(gvmpt3sas->tq_rsp,
				(void(*)(void *))imptsas_rsp_handler, (void *)rx_data, DDI_SLEEP);
 			if (DDI_SUCCESS != ret) {
				IMPT_DEBUG(8, (CE_WARN, "imptsas_rsp_handler taskq failed"));
				imptsas_rsp_handler(rx_data);
 			}
			break;
		case VMPT_CMD_CTL:
			ret = taskq_dispatch(gvmpt3sas->tq_ctl,
				(void(*)(void *))imptsas_ctl_handler,
				(void *)rx_data, DDI_SLEEP);
 			if (DDI_SUCCESS != ret) {
				IMPT_DEBUG(8, (CE_WARN, "imptsas_ctl_handler taskq failed"));
				imptsas_ctl_handler(rx_data);
 			}
			break;
		default:
			vmpt3sas_rx_data_free(rx_data);
			printk("vmptsas_remote_req_handler: Don't support");
			break;
	}
}

static void vmpt3sas_cts_link_evt_cb(void *private,
	cts_link_evt_t link_evt, void *arg)
{
	vmpt3sas_cts_link_stata_evt_t*link_state;
	int ret;

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
	vmpt3sas_cmd_t *cmd;
	struct vmpt3sas_t *ioc = shost_priv(shost);
	struct scatterlist *sg;
	VMPT_XDR xdr_temp;
	VMPT_XDR *xdrs = &xdr_temp;
	uint_t len;
	uint_t tx_len;
	u16 smid;
	u16 handle;
	void *buff = NULL;
	uint64_t index;
	int have_sdb;
	int i = 0;
	int ret;
	uint8_t *sg_prt  = NULL;
	uint_t sg_len;
	
	if (ioc->logging_level)
		scsi_print_command(scmd);

	cmd = (vmpt3sas_cmd_t *)kmem_alloc(sizeof(vmpt3sas_cmd_t), KM_SLEEP);
	memset(cmd, 0, sizeof(vmpt3sas_cmd_t));
	
	/*encode message*/
	len = XDR_EN_FIXED_SIZE + scmd->cmd_len + scmd->sdb.length;
	buff = cs_kmem_alloc(len);
	vmpt_xdrmem_create(xdrs, buff, len, VMPT_XDR_ENCODE);
	remote_cmd = VMPT_CMD_REQUEST;
	vmpt_xdr_enum(xdrs, (enum_t *)&remote_cmd);/* 4bytes */

	index = atomic_inc_64_nv(&greq_index);
	vmpt_xdr_uint64_t(xdrs, (uint64_t *)&index);/* 8bytes */

	cmd = vmpt3sas_alloc_cmd(index, scmd);
		
	printk("vmpt3sas %s: rep index(%"PRId64") cmd(%p) bp(%p)", __func__,
		index, scmd, scmd->sdb);

	vmpt_xdr_u_int(xdrs, &(shost->host_no));/* 4bytes */
	vmpt_xdr_u_int(xdrs, &(scmd->device->id);/* 4bytes */
	vmpt_xdr_u_int(xdrs, &(scmd->device->lun));/* 4bytes */
	vmpt_xdr_u_int(xdrs, &(scmd->device->channel));/* 4bytes */

	vmpt_xdr_enum(xdrs, (enum_t *)&(scmd->sc_data_direction));/* 4bytes */

	/*encode CDB*/
	vmpt_xdr_u_int(xdrs, &(scmd->cmd_len));/* 4bytes */
	vmpt_xdr_bytes(xdrs, &(scmd->cmnd), &(scmd->cmd_len), scmd->cmd_len);
	
	/*have scsi data*/
	if (scmd->sdb->length != 0) {
		have_sdb = 1;
		vmpt_xdr_int(xdrs, &have_sdb);/* 4bytes */
		vmpt_xdr_u_int(xdrs, &(scmd->sdb.length));/* 4bytes */
		vmpt_xdr_u_int(xdrs, &(scmd->sdb->table.nents));/* 4byte */
		/* todo: encode scsi data into xdr */
		for_each_sg(scmd->sdb->table.sgl, sg, scmd->sdb->table.nents, i) {
			sg_len = sg->length;
			vmpt_xdr_u_int(xdrs, &sg_len);/* 4bytes */
			sg_prt = sg_virt(sg);
			vmpt_xdr_bytes(xdrs, (char **)&sg_prt,
				&sg_len, sg_len);/* bp->b_bcount + 4bytes*/	
		}
		
	} else {
		have_sdb = 0;
		vmpt_xdr_int(xdrs, &have_sdb);/* 4bytes */
	}

	tx_len = (uint_t)((uintptr_t)xdrs->x_private - (uintptr_t)xdrs->x_base);

	mod_hash_insert(ioc->vmpt_cmd_wait_hash,
		(mod_hash_key_t)(uintptr_t)index, (mod_hash_val_t)cmd);

	/*todo get session*/
	err = vmpt3sas_send_msg(sess_private, (void *)xdrs->x_base, tx_len);
	cs_kmem_free(buff, len);

	if (err == 0) {
		mutex_enter(&cmd->cmd_mutex);
		while (cmd->cmd_state != VMPTSAS_CMD_STATE_COMPLETED) {
				cv_wait(&cmd->cmd_completion, &cmd->cmd_mutex);
			}
			printk("pkt completion!\n");
			//cmd->cmd_state = VMPTSAS_CMD_STATE_FREE;
		mutex_exit(&cmd->cmd_mutex);
	} else {
		printk("index %llu message failed!\n", index);
		ret = mod_hash_remove(ioc->vmpt_cmd_wait_hash,
		(mod_hash_key_t)(uintptr_t)index, (mod_hash_val_t *)&cmd);
		if(ret != NULL) {
			scmd->result = DID_NO_CONNECT << 16;
			scmd->scsi_done(scmd);
		}
	}

	return 0;
	
}

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
	.sg_tablesize			= MPT3SAS_SG_DEPTH,
	.max_sectors			= 32767,
	.cmd_per_lun			= 7,
	.use_clustering			= ENABLE_CLUSTERING,
	.shost_attrs			= NULL,
	.sdev_attrs			= NULL,
	.track_queue_depth		= 1,
};


/**
 * _mpt3sas_init - main entry point for this driver.
 *
 * Returns 0 success, anything else error.
 */
static int __init
_vmpt3sas_init(void)
{
	struct vmpt3sas *ioc;
	struct Scsi_Host *shost = NULL;
	int rv;
	int error;

	pr_info("%s loaded\n", VMPT3SAS_DRIVER_NAME);
	csh_rx_hook_add(CLUSTER_SAN_MSGTYPE_IMPTSAS, vmpt3sas_clustersan_rx_cb, NULL);
	csh_link_evt_hook_add(vmpt3sas_cts_link_evt_cb, NULL);

	
	/* Use mpt3sas driver host template for SAS 3.0 HBA's */
	shost = scsi_host_alloc(&vmpt3sas_driver_template,
	  sizeof(struct vmpt3sas));
	if (!shost)
		return -ENODEV;
	ioc = shost_priv(shost);
	gvmpt3sas = ioc;
	memset(ioc, 0, sizeof(struct MPT3SAS_ADAPTER));

	ioc->id = vmpt3_ids++;
	ioc->logging_level = logging_level;

	sprintf(ioc->driver_name, "%s", VMPT3SAS_DRIVER_NAME);

	ioc->vmpt_cmd_wait_hash = mod_hash_create_ptrhash(
			"vmpt_cmd_wait_hash", VMPT3SAS_REQ_HASH_SIZE,
			mod_hash_null_valdtor, 0);

	ioc->shost = shost;

	sprintf(ioc->name, "%s_cm%d", ioc->driver_name, ioc->id);

	/* init shost parameters */
	shost->max_cmd_len = 32;
	shost->max_lun = max_lun;
	shost->transportt = NULL;
	shost->unique_id = ioc->id;
	
	if (max_sectors != 0xFFFF) {
		if (max_sectors < 64) {
			shost->max_sectors = 64;
			pr_warn(MPT3SAS_FMT "Invalid value %d passed " \
			    "for max_sectors, range is 64 to 32767. Assigning "
			    "value of 64.\n", ioc->name, max_sectors);
		} else if (max_sectors > 32767) {
			shost->max_sectors = 32767;
			pr_warn(MPT3SAS_FMT "Invalid value %d passed " \
			    "for max_sectors, range is 64 to 32767. Assigning "
			    "default value of 32767.\n", ioc->name,
			    max_sectors);
		} else {
			shost->max_sectors = max_sectors & 0xFFFE;
			pr_info(MPT3SAS_FMT
				"The max_sectors value is set to %d\n",
				ioc->name, shost->max_sectors);
		}
	}

	/* register EEDP capabilities with SCSI layer */
	if (prot_mask > 0)
		scsi_host_set_prot(shost, prot_mask);
	else
		scsi_host_set_prot(shost, SHOST_DIF_TYPE1_PROTECTION
				   | SHOST_DIF_TYPE2_PROTECTION
				   | SHOST_DIF_TYPE3_PROTECTION);

	scsi_host_set_guard(shost, SHOST_DIX_GUARD_CRC);
	
	/* receive thread */
	snprintf(ioc->tq_req_name, sizeof(ioc->tq_req_name),
	    "req_%s%d", ioc->driver_name, ioc->id);
	ioc->tq_req =
        taskq_create(ioc->tq_req_name, max_ncpus, minclsyspri,
        1, vmpt3_receive_worker_count, TASKQ_PREPOPULATE);
	if (!ioc->tq_req) {
		pr_err(VMPT3SAS_FMT "failure at %s:%d/%s()!\n",
		    ioc->name, __FILE__, __LINE__, __func__);
		rv = -ENODEV;
		goto out_thread_fail;
	}

	snprintf(ioc->tq_rsp_name, sizeof(ioc->tq_rsp_name),
	    "rsp_%s%d", ioc->driver_name, ioc->id);
	ioc->tq_rsp =
        taskq_create(ioc->tq_rsp_name, max_ncpus, minclsyspri,
        1, vmpt3_receive_worker_count, TASKQ_PREPOPULATE);
	if (!ioc->tq_rsp) {
		pr_err(VMPT3SAS_FMT "failure at %s:%d/%s()!\n",
		    ioc->name, __FILE__, __LINE__, __func__);
		rv = -ENODEV;
		goto out_thread_fail;
	}
	
	snprintf(ioc->tq_ctl_name, sizeof(ioc->tq_ctl_name),
	    "ctl_%s%d", ioc->driver_name, ioc->id);
	ioc->tq_ctl =
        taskq_create(ioc->tq_ctl_name, max_ncpus, minclsyspri,
        1, vmpt3_receive_worker_count, TASKQ_PREPOPULATE);
	if (!ioc->tq_ctl) {
		pr_err(VMPT3SAS_FMT "failure at %s:%d/%s()!\n",
		    ioc->name, __FILE__, __LINE__, __func__);
		rv = -ENODEV;
		goto out_thread_fail;
	}

	rv = scsi_add_host(shost, NULL);
	if (rv) {
		pr_err(MPT3SAS_FMT "failure at %s:%d/%s()!\n",
		    ioc->name, __FILE__, __LINE__, __func__);
		goto out_add_shost_fail;
	}

	scsi_scan_host(shost);
	return 0;
	
out_add_shost_fail:
	scsi_host_put(shost);
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

}

module_init(_vmpt3sas_init);
module_exit(_vmpt3sas_exit);
