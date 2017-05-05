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

typedef struct __ddi_dma_handle {
	struct device *dev;
	void * ptr;
	size_t size;
	dma_addr_t *dma_handle;
	int flag;
	struct __ddi_dma_handle *self;
}ddi_dma_handle_t;

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

typedef	char		*caddr_t;	/* ?<core address> type */

typedef struct ddi_device_acc_attr {
	ushort_t devacc_attr_version;
	uchar_t devacc_attr_endian_flags;
	uchar_t devacc_attr_dataorder;
	uchar_t devacc_attr_access;		/* access error protection */
} ddi_device_acc_attr_t;

typedef struct __ddi_acc_handle {
	ddi_dma_handle_t * handle;
}ddi_acc_handle_t;

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



#endif
