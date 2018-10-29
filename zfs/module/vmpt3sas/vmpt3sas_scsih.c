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

#define	IMPTSAS_BROADCAST_SESS				((void *)(0-1))
#define	XDR_EN_FIXED_SIZE	256/* Leave allowance */
#define	XDR_DE_FIXED_SIZE	256/* Leave allowance */

#define VMPT3SAS_DRIVER_NAME		"vmpt3sas"
/*
 * logging format
 */
#define VMPT3SAS_FMT			"%s: "


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
	
}

static void vmpt3sas_cts_link_evt_cb(void *private,
	cts_link_evt_t link_evt, void *arg)
{
	vmptsas_cts_link_stata_evt_t *link_state;
	int ret;

	link_state = kmem_zalloc(sizeof(vmptsas_cts_link_stata_evt_t), KM_SLEEP);
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
proxy_scsih_qcmd(struct Scsi_Host *shost, struct scsi_cmnd *scmd)
{
	vmpt3sas_remote_cmd_t remote_cmd;
	VMPT_XDR xdr_temp;
	VMPT_XDR *xdrs = &xdr_temp;
	uint_t len;
	u16 smid;
	u16 handle;
	void *buff = NULL;
	uint64_t index;
	int have_sdb;
	

	if (ioc->logging_level & MPT_DEBUG_SCSI)
		scsi_print_command(scmd);

	/*encode message*/
	len = XDR_EN_FIXED_SIZE + scmd->cmd_len + scmd->sdb.length;
	buff = cs_kmem_alloc(len);
	vmpt_xdrmem_create(xdrs, buff, len, VMPT_XDR_ENCODE);
	remote_cmd = VMPT_CMD_REQUEST;
	vmpt_xdr_enum(xdrs, (enum_t *)&remote_cmd);/* 4bytes */

	index = atomic_inc_64_nv(&greq_index);
	vmpt_xdr_uint64_t(xdrs, (uint64_t *)&index);/* 8bytes */
	printk("vmpt3sas %s: rep index(%"PRId64") cmd(%p) bp(%p)", __func__,
		index, scmd, scmd->sdb);

	vmpt_xdr_u_int(xdrs, scmd->device->id);/* 4bytes */
	vmpt_xdr_u_int(xdrs, scmd->device->lun);/* 4bytes */
	vmpt_xdr_u_int(xdrs, scmd->device->channel);/* 4bytes */
	vmpt_xdr_u_int(xdrs, scmd->cmd_len);/* 4bytes */
	vmpt_xdr_u_int(xdrs, scmd->sdb.length);/* 4bytes */
	
	vmpt_xdr_enum(xdrs, (enum_t *)&scmd->sc_data_direction);/* 4bytes */

	/*have scsi data*/
	if (scmd->sdb->length != 0) {
		have_sdb = 1;
		vmpt_xdr_int(xdrs, &have_sdb);/* 4bytes */

		/* todo: encode scsi data into xdr */
		
		
	} else {
		have_sdb = 0;
		vmpt_xdr_int(xdrs, &have_sdb);/* 4bytes */
	}
	
	/*todo:*/
	/*send to remote*/
	/*wait reply(sync or async)*/
	/*invode scsiio_done*/
	
}

/* shost template for SAS 3.0 HBA devices */
static struct scsi_host_template vmpt3sas_driver_template = {
	.module				= THIS_MODULE,
	.name				= "Fusion MPT SAS Host",
	.proc_name			= VMPT3SAS_DRIVER_NAME,
	.queuecommand			= proxy_scsih_qcmd,
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
	memset(ioc, 0, sizeof(struct MPT3SAS_ADAPTER));

	ioc->id = vmpt3_ids++;
	ioc->logging_level = logging_level;

	sprintf(ioc->driver_name, "%s", VMPT3SAS_DRIVER_NAME);

	ioc->shost = shost;

	sprintf(ioc->name, "%s_cm%d", ioc->driver_name, ioc->id);

	/* init shost parameters */
	shost->max_cmd_len = 32;
	shost->max_lun = max_lun;
	shost->transportt = NULL;
	shost->unique_id = ioc->id;

	spin_lock_init(&ioc->rc_event_lock);
	INIT_LIST_HEAD(&ioc->rc_event_list);
	
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
	snprintf(ioc->receive_event_name, sizeof(ioc->receive_event_name),
	    "rc_event_%s%d", ioc->driver_name, ioc->id);
	ioc->receive_event_worker =
        taskq_create(ioc->receive_event_name, max_ncpus, minclsyspri,
        1, vmpt3_receive_worker_count, TASKQ_PREPOPULATE);
	if (!ioc->receive_event_thread) {
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
