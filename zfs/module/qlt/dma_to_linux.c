#include "dma_to_linux.h"

struct device *dev_info_to_device(dev_info_t *dip)
{
	
}

int
ddi_dma_alloc_handle(dev_info_t *dip, ddi_dma_attr_t *attr,
	int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	memset(handlep, 0, sizeof(ddi_dma_handle_t));
	handlep->dev = dev_info_to_device(dip);
	handlep->self = handlep;
	return (handlep->dev == NULL ? -1 : 0);
}

int
ddi_dma_mem_alloc(ddi_dma_handle_t handle, size_t length,
	ddi_device_acc_attr_t *accattrp, uint_t flags,
	int (*waitfp)(caddr_t), caddr_t arg, caddr_t *kaddrp,
	size_t *real_length, ddi_acc_handle_t *handlep)
{
	handle.self->ptr = dma_alloc_coherent(handle.self->dev, length, &handle.self->dma_handle, GFP_ATOMIC);
	if (handle.self->ptr) {
		handle.self->size = length;
		handlep->handle = handle.self;
		*kaddrp = handle.self->ptr;
		*real_length = length;
		return (0);
	}
	return (-1);
}

int
ddi_dma_addr_bind_handle(ddi_dma_handle_t handle, struct as *as,
	caddr_t addr, size_t len, uint_t flags, int (*waitfp)(caddr_t),
	caddr_t arg, ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	*ccountp = 1;
	cookiep->dmac_laddress = handle.self->dma_handle;
}

int
ddi_dma_unbind_handle(ddi_dma_handle_t h)
{
	return (0);
}

void
ddi_dma_mem_free(ddi_acc_handle_t *handlep)
{
}

void
ddi_dma_free_handle(ddi_dma_handle_t *handlep)
{
	dma_free_coherent(handlep->dev, handlep->size, handlep->ptr, handlep->dma_handle);
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