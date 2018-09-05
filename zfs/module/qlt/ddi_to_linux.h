#ifndef DMA_TO_LINUX_H
#define DMA_TO_LINUX_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/dmapool.h>
#include <linux/mempool.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/firmware.h>
#include <linux/aer.h>
#include <linux/mutex.h>
#include <linux/device.h>

#define ZTQ_FIRST_ENABLE_FULL_FUNC 0
typedef struct __ddi_dma_handle {
	struct pci_dev *dev;
	void * ptr;
	size_t size;
	dma_addr_t dma_handle;
	int flag;
}*ddi_dma_handle_t;

typedef struct ddi_dma_attr {
	uint_t		dma_attr_version;	/* version number */
	uint64_t	dma_attr_addr_lo;	/* low DMA address range */
	uint64_t	dma_attr_addr_hi;	/* high DMA address range */
	uint64_t	dma_attr_count_max;	/* DMA counter register */
	uint64_t	dma_attr_align;		/* DMA address alignment */
	uint_t		dma_attr_burstsizes;	/* DMA burstsizes */
	uint32_t	dma_attr_minxfer;	/* min effective DMA size */
	uint64_t 	dma_attr_maxxfer;	/* max DMA xfer size */
	uint64_t 	dma_attr_seg;		/* segment boundary */
	int		dma_attr_sgllen;	/* s/g length */
	uint32_t	dma_attr_granular;	/* granularity of device */
	uint_t		dma_attr_flags;		/* Bus specific DMA flags */
} ddi_dma_attr_t;

/*
 * A DMA cookie contains DMA address information required to
 * program a DMA engine
 */
typedef struct {
	union {
		uint64_t	_dmac_ll;	/* 64 bit DMA address */
		uint32_t 	_dmac_la[2];    /* 2 x 32 bit address */
	} _dmu;
	size_t		dmac_size;	/* DMA cookie size */
	uint_t		dmac_type;	/* bus specific type bits */
} ddi_dma_cookie_t;

#define	dmac_laddress	_dmu._dmac_ll
#ifdef _LONG_LONG_HTOL
#define	dmac_notused    _dmu._dmac_la[0]
#define	dmac_address    _dmu._dmac_la[1]
#else
#define	dmac_address	_dmu._dmac_la[0]
#define	dmac_notused	_dmu._dmac_la[1]
#endif

#define	DMA_ATTR_V0		0
#define	DMA_ATTR_VERSION	DMA_ATTR_V0

#define	DDI_DMA_DONTWAIT	((int (*)())0)
#define	DDI_DMA_SLEEP		((int (*)())1)
/*
 * Flag definitions for the allocation functions.
 */
#define	DDI_DMA_WRITE		0x0001	/* Direction memory --> IO 	*/
#define	DDI_DMA_READ		0x0002	/* Direction IO --> memory	*/
#define	DDI_DMA_RDWR		(DDI_DMA_READ | DDI_DMA_WRITE)

#define	DDI_DMA_SYNC_FORDEV	0x0
#define	DDI_DMA_SYNC_FORCPU	0x1
#define	DDI_DMA_SYNC_FORKERNEL	0x2

#define	DDI_DMA_CONSISTENT	0x0010
#define	DDI_DMA_EXCLUSIVE	0x0020
#define	DDI_DMA_STREAMING	0x0040


typedef	char		*caddr_t;	/* ?<core address> type */

typedef struct ddi_device_acc_attr {
	ushort_t devacc_attr_version;
	uchar_t devacc_attr_endian_flags;
	uchar_t devacc_attr_dataorder;
	uchar_t devacc_attr_access;		/* access error protection */
} ddi_device_acc_attr_t;

#define	DDI_DEVICE_ATTR_V0 	0x0001
#define	DDI_DEVICE_ATTR_V1 	0x0002

/*
 * endian-ness flags
 */
#define	 DDI_NEVERSWAP_ACC	0x00
#define	 DDI_STRUCTURE_LE_ACC	0x01
#define	 DDI_STRUCTURE_BE_ACC	0x02

/*
 * Data ordering values
 */
#define	DDI_STRICTORDER_ACC	0x00
#define	DDI_UNORDERED_OK_ACC    0x01
#define	DDI_MERGING_OK_ACC	0x02
#define	DDI_LOADCACHING_OK_ACC  0x03
#define	DDI_STORECACHING_OK_ACC 0x04



struct as
{
	void *reserved;
};

typedef struct __pci_regs_grp {
	unsigned long phys_addr;
	unsigned long vir_addr;
	unsigned long size;
}*pci_regs_grp_t;

typedef struct __ddi_acc_handle {
	ddi_dma_handle_t   dma_handle;
	pci_regs_grp_t     pci_handle;
}*ddi_acc_handle_t;

typedef struct pci_dev  dev_info_t;

typedef struct __ddi_intr_handle {
	void * reserved;
}*ddi_intr_handle_t;

/* Hardware interrupt types */
#define	DDI_INTR_TYPE_FIXED	0x1
#define	DDI_INTR_TYPE_MSI	0x2
#define	DDI_INTR_TYPE_MSIX	0x4

#define	 DDI_DEV_NO_AUTOINCR	0x0000
#define	 DDI_DEV_AUTOINCR	0x0001

#define	OTYPCNT		5
#define	OTYP_BLK	0
#define	OTYP_MNT	1
#define	OTYP_CHR	2
#define	OTYP_SWP	3
#define	OTYP_LYR	4
uint8_t pci_config_get8(struct pci_dev *dev, off_t offset);
uint16_t pci_config_get16(struct pci_dev *dev, off_t offset);
uint32_t pci_config_get32(struct pci_dev *dev, off_t offset);
void ddi_rep_put32(ddi_acc_handle_t handle, uint32_t *host_addr, uint32_t *dev_addr,
			size_t repcount, uint_t flags);
uint8_t ddi_get8(ddi_acc_handle_t handle, uint8_t *addr);
uint16_t ddi_get16(ddi_acc_handle_t handle, uint16_t *addr);
uint32_t ddi_get32(ddi_acc_handle_t handle, uint32_t *addr);
void ddi_put16(ddi_acc_handle_t handle, uint16_t *addr, uint16_t value);
void ddi_put32(ddi_acc_handle_t handle, uint32_t *addr, uint32_t value);
void qla2x00_config_dma_addressing(struct pci_dev *pdev);
struct device *dev_info_to_device(struct pci_dev *pdev);
int ddi_dma_alloc_handle(struct pci_dev *pdev, ddi_dma_attr_t *attr,
	int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep);
int ddi_dma_mem_alloc(ddi_dma_handle_t dma_handle, size_t length,
	ddi_device_acc_attr_t *accattrp, uint_t flags,
	int (*waitfp)(caddr_t), caddr_t arg, caddr_t *kaddrp,
	size_t *real_length, ddi_acc_handle_t *handle);
int ddi_dma_addr_bind_handle(ddi_dma_handle_t handle, struct as *as,
	caddr_t addr, size_t len, uint_t flags, int (*waitfp)(caddr_t),
	caddr_t arg, ddi_dma_cookie_t *cookiep, uint_t *ccountp);
int ddi_dma_unbind_handle(ddi_dma_handle_t h);
void ddi_dma_mem_free(ddi_acc_handle_t *handlep);
void ddi_dma_free_handle(ddi_dma_handle_t *handlep);
void ddi_dma_nextcookie(ddi_dma_handle_t handle, ddi_dma_cookie_t *cookiep);
int ddi_dma_sync(ddi_dma_handle_t h, off_t o, size_t l, uint_t whom);
int ddi_dev_regsize(dev_info_t *dev, uint_t rnumber, off_t *result);
int ddi_regs_map_setup(dev_info_t *dip, uint_t rnumber, caddr_t *addrp,
	offset_t offset, offset_t len, ddi_device_acc_attr_t *accattrp,
	ddi_acc_handle_t *handle);
void ddi_regs_map_free(ddi_acc_handle_t *handlep);
int ddi_get_instance(dev_info_t *dip);
int ddi_add_dev(dev_info_t *dip);
int ddi_remove_dev(dev_info_t *dip);
int ddi_soft_state_zalloc(void **state, int item);
void *ddi_get_soft_state(void *state, int item);
void ddi_soft_state_free(void *state, int item);
int pci_config_setup(dev_info_t *dip, ddi_acc_handle_t *handle);
void pci_config_teardown(ddi_acc_handle_t *handle);
int ddi_intr_get_supported_types(dev_info_t *dip, int *typesp);
void drv_usecwait(unsigned int n);
int qla24xx_pci_config(struct pci_dev* pdev);
#endif
