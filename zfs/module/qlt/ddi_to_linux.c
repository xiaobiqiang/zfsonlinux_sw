#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/stmf_defines.h>
#include <sys/fct_defines.h>
#include <sys/stmf.h>
#include <sys/portif.h>
#include <sys/fct.h>
#include "ddi_to_linux.h"
#include <linux/delay.h>
#include <sys/qla_def.h>
#include "qlt.h"
#include <asm/io.h>


uint8_t pci_config_get8(struct pci_dev *dev, off_t offset)
{
	uint8_t val = 0;
	if (pci_read_config_byte(dev, offset, &val) < 0) {
		printk("%s %d error\n", __func__, __LINE__);
	}
	return val;
}
uint16_t pci_config_get16(struct pci_dev *dev, off_t offset)
{
	uint16_t val = 0;
	if (pci_read_config_word(dev, offset, &val) < 0) {
		printk("%s %d error\n", __func__, __LINE__);
	}
	return val;
}
uint32_t pci_config_get32(struct pci_dev *dev, off_t offset)
{
	uint32_t val = 0;
	if (pci_read_config_dword(dev, offset, &val) < 0) {
		printk("%s %d error\n", __func__, __LINE__);
	}
	return val;
}
void ddi_rep_put32(ddi_acc_handle_t handle, uint32_t *host_addr, uint32_t *dev_addr,
	size_t repcount, uint_t flags)
{
	iowrite32_rep(dev_addr, host_addr, repcount);
}
uint8_t ddi_get8(ddi_acc_handle_t handle, uint8_t *addr)
{
	return ioread8(addr);
}
uint16_t ddi_get16(ddi_acc_handle_t handle, uint16_t *addr)
{
	return ioread16(addr);
}
uint32_t ddi_get32(ddi_acc_handle_t handle, uint32_t *addr)
{
	return ioread32(addr);
}
void ddi_put16(ddi_acc_handle_t handle, uint16_t *addr, uint16_t value)
{
	iowrite16(value, addr);
}
void ddi_put32(ddi_acc_handle_t handle, uint32_t *addr, uint32_t value)
{
	iowrite32(value, addr);
}

void qla2x00_config_dma_addressing(struct pci_dev *pdev)
{
	/* Assume a 32bit DMA mask. */
	//ha->flags.enable_64bit_addressing = 0;

	if (!dma_set_mask(&pdev->dev, DMA_BIT_MASK(64))) {
		/* Any upper-dword bits set? */
		if (MSD(dma_get_required_mask(&pdev->dev)) &&
		    !pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64))) {
			/* Ok, a 64bit DMA mask is applicable. */
			//ha->flags.enable_64bit_addressing = 1;
			//ha->isp_ops->calc_req_entries = qla2x00_calc_iocbs_64;
			//ha->isp_ops->build_iocbs = qla2x00_build_scsi_iocbs_64;
			return;
		}
	}

	dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
	pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
}


struct device *dev_info_to_device(struct pci_dev *pdev)
{
	return &pdev->dev;
}

int
ddi_dma_alloc_handle(struct pci_dev *pdev, ddi_dma_attr_t *attr,
	int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	*handlep = kzalloc(sizeof(struct __ddi_dma_handle), GFP_KERNEL);
	(*handlep)->dev = dev_info_to_device(pdev);
	return ((*handlep)->dev == NULL ? -1 : 0);
}

int
ddi_dma_mem_alloc(ddi_dma_handle_t dma_handle, size_t length,
	ddi_device_acc_attr_t *accattrp, uint_t flags,
	int (*waitfp)(caddr_t), caddr_t arg, caddr_t *kaddrp,
	size_t *real_length, ddi_acc_handle_t *handle)
{
	*handle = kzalloc(sizeof(struct __ddi_acc_handle), GFP_KERNEL);
	if (*handle == NULL) {
		printk("%s %d error\n", __func__, __LINE__);
		return -1;
	}
	(*handle)->dma_handle = dma_handle;
	
	dma_handle->ptr = dma_alloc_coherent(dma_handle->dev, length, &dma_handle->dma_handle, GFP_ATOMIC);
	if (dma_handle->ptr == NULL) {
		kfree(*handle);
		printk("%s %d error\n", __func__, __LINE__);
		return (-1);
	}
	
	dma_handle->size = length;
	*kaddrp = dma_handle->ptr;
	*real_length = length;
	return DDI_SUCCESS;
}

int
ddi_dma_addr_bind_handle(ddi_dma_handle_t handle, struct as *as,
	caddr_t addr, size_t len, uint_t flags, int (*waitfp)(caddr_t),
	caddr_t arg, ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	*ccountp = 1;
	cookiep->dmac_laddress = handle->dma_handle;
	return DDI_SUCCESS;
}

int
ddi_dma_unbind_handle(ddi_dma_handle_t h)
{
	return DDI_SUCCESS;
}

void
ddi_dma_mem_free(ddi_acc_handle_t *handlep)
{
	dma_free_coherent((*handlep)->dma_handle->dev, (*handlep)->dma_handle->size, 
		(*handlep)->dma_handle->ptr, (*handlep)->dma_handle->dma_handle);
	kfree(*handlep);
	*handlep = NULL;
}

void
ddi_dma_free_handle(ddi_dma_handle_t *handlep)
{
	kfree(*handlep);
}

void
ddi_dma_nextcookie(ddi_dma_handle_t handle, ddi_dma_cookie_t *cookiep)
{
}

int
ddi_dma_sync(ddi_dma_handle_t h, off_t o, size_t l, uint_t whom)
{
	return (0);
}

int
ddi_dev_regsize(dev_info_t *dev, uint_t rnumber, off_t *result)
{
	*result = pci_resource_len(dev, rnumber);
	return DDI_SUCCESS;
}

int
ddi_regs_map_setup(dev_info_t *dip, uint_t rnumber, caddr_t *addrp,
	offset_t offset, offset_t len, ddi_device_acc_attr_t *accattrp,
	ddi_acc_handle_t *handle)
{
	*handle = kzalloc(sizeof(struct __ddi_acc_handle), GFP_KERNEL);
	if (*handle == NULL) {
		printk("%s %d error\n", __func__, __LINE__);
		return -1;
	}
	(*handle)->pci_handle = kzalloc(sizeof(struct __pci_regs_grp), GFP_KERNEL);
	if ((*handle)->pci_handle == NULL) {
		kfree(*handle);
		printk("%s %d error\n", __func__, __LINE__);
		return -1;
	}
	
	*addrp = ioremap(pci_resource_start(dip, rnumber)+offset, len);
	(*handle)->pci_handle->vir_addr = *addrp;
	
	return (*addrp ? 0 : -1);
}

void
ddi_regs_map_free(ddi_acc_handle_t *handlep)
{
	iounmap((*handlep)->pci_handle->vir_addr);
	kfree((*handlep)->pci_handle);
	kfree(*handlep);
	*handlep = NULL;
}

int ddi_get_instance(dev_info_t *dip)
{
	return 0;
}

int
ddi_soft_state_zalloc(void **state, int item)
{
	*state = kzalloc(sizeof(qlt_state_t), GFP_KERNEL);
	if (*state == NULL) {
		printk("%s %d error\n", __func__, __LINE__);
		return -1;
	}
	return 0;
}
void *ddi_get_soft_state(void *state, int item)
{
	struct qlt_state *pstate = (struct qlt_state *)state;
	
	return pstate;
}

void
ddi_soft_state_free(void *state, int item)
{
	kfree(state);
}

int pci_config_setup(dev_info_t *dip, ddi_acc_handle_t *handle)
{
	return 0;
}
void pci_config_teardown(ddi_acc_handle_t *handle)
{
}
void
qla2x00_set_isp_flags(struct qla_hw_data *ha)
{
	ha->device_type = DT_EXTENDED_IDS;
	switch (ha->pdev->device) {
	case PCI_DEVICE_ID_QLOGIC_ISP2422:
		ha->device_type |= DT_ISP2422;
		ha->device_type |= DT_ZIO_SUPPORTED;
		ha->device_type |= DT_FWI2;
		ha->device_type |= DT_IIDMA;
		ha->fw_srisc_address = RISC_START_ADDRESS_2400;
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP2432:
		ha->device_type |= DT_ISP2432;
		ha->device_type |= DT_ZIO_SUPPORTED;
		ha->device_type |= DT_FWI2;
		ha->device_type |= DT_IIDMA;
		ha->fw_srisc_address = RISC_START_ADDRESS_2400;
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP8432:
		ha->device_type |= DT_ISP8432;
		ha->device_type |= DT_ZIO_SUPPORTED;
		ha->device_type |= DT_FWI2;
		ha->device_type |= DT_IIDMA;
		ha->fw_srisc_address = RISC_START_ADDRESS_2400;
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP2532:
		ha->device_type |= DT_ISP2532;
		ha->device_type |= DT_ZIO_SUPPORTED;
		ha->device_type |= DT_FWI2;
		ha->device_type |= DT_IIDMA;
		ha->fw_srisc_address = RISC_START_ADDRESS_2400;
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP8001:
		ha->device_type |= DT_ISP8001;
		ha->device_type |= DT_ZIO_SUPPORTED;
		ha->device_type |= DT_FWI2;
		ha->device_type |= DT_IIDMA;
		ha->fw_srisc_address = RISC_START_ADDRESS_2400;
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP2031:
		ha->device_type |= DT_ISP2031;
		ha->device_type |= DT_ZIO_SUPPORTED;
		ha->device_type |= DT_FWI2;
		ha->device_type |= DT_IIDMA;
		ha->device_type |= DT_T10_PI;
		ha->fw_srisc_address = RISC_START_ADDRESS_2400;
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP2071:
		ha->device_type |= DT_ISP2071;
		ha->device_type |= DT_ZIO_SUPPORTED;
		ha->device_type |= DT_FWI2;
		ha->device_type |= DT_IIDMA;
		ha->device_type |= DT_T10_PI;
		ha->fw_srisc_address = RISC_START_ADDRESS_2400;
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP2261:
		ha->device_type |= DT_ISP2261;
		ha->device_type |= DT_ZIO_SUPPORTED;
		ha->device_type |= DT_FWI2;
		ha->device_type |= DT_IIDMA;
		ha->device_type |= DT_T10_PI;
		ha->fw_srisc_address = RISC_START_ADDRESS_2400;
		break;
	}

	if (IS_QLA82XX(ha))
		ha->port_no = ha->portnum & 1;
	else {
		/* Get adapter physical port no from interrupt pin register. */
		pci_read_config_byte(ha->pdev, PCI_INTERRUPT_PIN, &ha->port_no);
		if (IS_QLA27XX(ha))
			ha->port_no--;
		else
			ha->port_no = !(ha->port_no & 1);
	}

	//ql_dbg_pci(ql_dbg_init, ha->pdev, 0x000b,
	//    "device_type=0x%x port=%d fw_srisc_address=0x%x.\n",
	//    ha->device_type, ha->port_no, ha->fw_srisc_address);
}

int ddi_intr_get_supported_types(dev_info_t *dip, int *typesp)
{
	
	struct qla_hw_data *ha = kzalloc(sizeof(struct qla_hw_data), GFP_KERNEL);
	ha->pdev = dip;
	*typesp = 0;
	qla2x00_set_isp_flags(ha);
	
	/* If possible, enable MSI-X. */
	if (!IS_QLA2432(ha) && !IS_QLA2532(ha) && !IS_QLA8432(ha) &&
	    !IS_CNA_CAPABLE(ha) && !IS_QLA2031(ha) && !IS_QLAFX00(ha) &&
	    !IS_QLA27XX(ha)) {
		*typesp = DDI_INTR_TYPE_FIXED;
		kfree(ha);
		return DDI_SUCCESS;
	}

	if (dip->subsystem_vendor == PCI_VENDOR_ID_HP &&
		(dip->subsystem_device == 0x7040 ||
		dip->subsystem_device == 0x7041 ||
		dip->subsystem_device == 0x1705)) {
		//ql_log(ql_log_warn, vha, 0x0034,
		//    "MSI-X: Unsupported ISP 2432 SSVID/SSDID (0x%X,0x%X).\n",
		//	dip->subsystem_vendor,
		//	dip->subsystem_device);
		*typesp = DDI_INTR_TYPE_MSI;
		kfree(ha);
		return DDI_SUCCESS;
	}

	if (IS_QLA2432(ha) && (dip->revision < QLA_MSIX_CHIP_REV_24XX)) {
		//ql_log(ql_log_warn, vha, 0x0035,
		//    "MSI-X; Unsupported ISP2432 (0x%X, 0x%X).\n",
		//    dip->revision, QLA_MSIX_CHIP_REV_24XX);
		*typesp = DDI_INTR_TYPE_MSI;
		kfree(ha);
		return DDI_SUCCESS;
	}
	*typesp = DDI_INTR_TYPE_MSIX;
	kfree(ha);
	return DDI_SUCCESS;
}
void drv_usecwait(unsigned int n)
{
	msleep(n);
}
