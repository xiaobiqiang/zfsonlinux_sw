#ifndef	_VMPTSAS_XDR_H
#define	_VMPTSAS_XDR_H

#include <sys/byteorder.h>	/* For all ntoh* and hton*() kind of macros */

#define	bool_t	int
#define	enum_t	int

#ifndef TRUE
#define TRUE	(1)
#define FALSE	(0)
#define	UNDEFINED	(-1)
#define	FAILED		(-2)
#endif

/*
 * constants specific to the xdr "protocol"
 */
#define	XDR_FALSE	((int32_t)0)
#define	XDR_TRUE	((int32_t)1)
#define	LASTUNSIGNED	((uint_t)0-1)

/*
 * This is the number of bytes per unit of external data.
 */
#define	BYTES_PER_XDR_UNIT	(4)
#define	RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
		    * BYTES_PER_XDR_UNIT)

#define	mem_alloc(bsize)		kmem_alloc(bsize, KM_SLEEP)
#define	mem_free(ptr, bsize)	kmem_free(ptr, bsize)

/*
 * Operations defined on a IMPT_XDR handle
 *
 * XDR		*xdrs;
 * long		*longp;
 * caddr_t	 addr;
 * uint_t	 len;
 * uint_t	 pos;
 */
#if !defined(_KERNEL)
#define	XDR_GETLONG(xdrs, longp)			\
	(*(xdrs)->x_ops->x_getlong)(xdrs, longp)
#define	xdr_getlong(xdrs, longp)			\
	(*(xdrs)->x_ops->x_getlong)(xdrs, longp)

#define	XDR_PUTLONG(xdrs, longp)			\
	(*(xdrs)->x_ops->x_putlong)(xdrs, longp)
#define	xdr_putlong(xdrs, longp)			\
	(*(xdrs)->x_ops->x_putlong)(xdrs, longp)
#endif /* KERNEL */


#if !defined(_LP64) && !defined(_KERNEL)

/*
 * For binary compatability on ILP32 we do not change the shape
 * of the XDR structure and the GET/PUTINT32 functions just use
 * the get/putlong vectors which operate on identically-sized
 * units of data.
 */

#define	XDR_GETINT32(xdrs, int32p)			\
	(*(xdrs)->x_ops->x_getlong)(xdrs, (long *)int32p)
#define	xdr_getint32(xdrs, int32p)			\
	(*(xdrs)->x_ops->x_getlong)(xdrs, (long *)int32p)

#define	XDR_PUTINT32(xdrs, int32p)			\
	(*(xdrs)->x_ops->x_putlong)(xdrs, (long *)int32p)
#define	xdr_putint32(xdrs, int32p)			\
	(*(xdrs)->x_ops->x_putlong)(xdrs, (long *)int32p)

#else /* !_LP64 && !_KERNEL */

#define	XDR_GETINT32(xdrs, int32p)			\
	(*(xdrs)->x_ops->x_getint32)(xdrs, int32p)
#define	xdr_getint32(xdrs, int32p)			\
	(*(xdrs)->x_ops->x_getint32)(xdrs, int32p)

#define	XDR_PUTINT32(xdrs, int32p)			\
	(*(xdrs)->x_ops->x_putint32)(xdrs, int32p)
#define	xdr_putint32(xdrs, int32p)			\
	(*(xdrs)->x_ops->x_putint32)(xdrs, int32p)

#endif /* !_LP64 && !_KERNEL */

#define	XDR_GETBYTES(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)
#define	xdr_getbytes(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)

#define	XDR_PUTBYTES(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)
#define	xdr_putbytes(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)

#define	XDR_GETPOS(xdrs)				\
	(*(xdrs)->x_ops->x_getpostn)(xdrs)
#define	xdr_getpos(xdrs)				\
	(*(xdrs)->x_ops->x_getpostn)(xdrs)

#define	XDR_SETPOS(xdrs, pos)				\
	(*(xdrs)->x_ops->x_setpostn)(xdrs, pos)
#define	xdr_setpos(xdrs, pos)				\
	(*(xdrs)->x_ops->x_setpostn)(xdrs, pos)

#define	XDR_INLINE(xdrs, len)				\
	(*(xdrs)->x_ops->x_inline)(xdrs, len)
#define	xdr_inline(xdrs, len)				\
	(*(xdrs)->x_ops->x_inline)(xdrs, len)

#define	XDR_DESTROY(xdrs)				\
	(*(xdrs)->x_ops->x_destroy)(xdrs)
#define	xdr_destroy(xdrs)				\
	(*(xdrs)->x_ops->x_destroy)(xdrs)

#define	XDR_CONTROL(xdrs, req, op)			\
	(*(xdrs)->x_ops->x_control)(xdrs, req, op)
#define	xdr_control(xdrs, req, op)			\
	(*(xdrs)->x_ops->x_control)(xdrs, req, op)


/*
 * Xdr operations.  XDR_ENCODE causes the type to be encoded into the
 * stream.  XDR_DECODE causes the type to be extracted from the stream.
 * XDR_FREE can be used to release the space allocated by an XDR_DECODE
 * request.
 */
enum vmpt_xdr_op {
	VMPT_XDR_ENCODE = 0,
	VMPT_XDR_DECODE = 1,
	VMPT_XDR_FREE = 2
};

struct vmpt_xdr_ops {
#if 0
	bool_t	(*x_getlong)();	/* get a long from underlying stream */
	bool_t	(*x_putlong)();	/* put a long to " */
#endif
	bool_t	(*x_getbytes)(); /* get some bytes from " */
	bool_t	(*x_putbytes)(); /* put some bytes to " */
	u_int	(*x_getpostn)(); /* returns bytes off from beginning */
	bool_t	(*x_setpostn)(); /* lets you reposition the stream */
	long *	(*x_inline)();	/* buf quick ptr to buffered data */
	void	(*x_destroy)();	/* free privates of this xdr_stream */
	bool_t	(*x_control)();
	bool_t	(*x_getint32)();
	bool_t	(*x_putint32)();
} ;


/*
 * The XDR handle.
 * Contains operation which is being applied to the stream,
 * an operations vector for the paticular implementation (e.g. see xdr_mem.c),
 * and two private fields for the use of the particular impelementation.
 */
typedef struct {
	enum vmpt_xdr_op	x_op;		/* operation; fast additional param */
	struct vmpt_xdr_ops *x_ops;
	caddr_t 	x_public;	/* users' data */
	caddr_t		x_private;	/* pointer to private data */
	caddr_t 	x_base;		/* private used for position info */
	int		x_handy;	/* extra private word */
	int		x_len;
} VMPT_XDR;

void
vmpt_xdrmem_create(VMPT_XDR *xdrs, caddr_t addr, uint_t size, enum impt_xdr_op op);

extern bool_t	vmpt_xdr_void(void);
extern bool_t	vmpt_xdr_int(VMPT_XDR *, int *);
extern bool_t	vmpt_xdr_u_int(VMPT_XDR *, uint_t *);
extern bool_t	vmpt_xdr_long(VMPT_XDR *, long *);
extern bool_t	vmpt_xdr_u_long(VMPT_XDR *, ulong_t *);
extern bool_t	vmpt_xdr_short(VMPT_XDR *, short *);
extern bool_t	vmpt_xdr_u_short(VMPT_XDR *, ushort_t *);
extern bool_t	vmpt_xdr_bool(VMPT_XDR *, bool_t *);
extern bool_t	vmpt_xdr_enum(VMPT_XDR *, enum_t *);
extern bool_t	vmpt_xdr_bytes(VMPT_XDR *, char **, uint_t *, const uint_t);
extern bool_t	vmpt_xdr_opaque(VMPT_XDR *, caddr_t, const uint_t);
extern bool_t	vmpt_xdr_string(VMPT_XDR *, char **, const uint_t);

extern bool_t   vmpt_xdr_hyper(VMPT_XDR *, longlong_t *);
extern bool_t   vmpt_xdr_longlong_t(VMPT_XDR *, longlong_t *);
extern bool_t   vmpt_xdr_u_hyper(VMPT_XDR *, u_longlong_t *);
extern bool_t   vmpt_xdr_u_longlong_t(VMPT_XDR *, u_longlong_t *);

extern bool_t	vmpt_xdr_char(VMPT_XDR *, char *);
extern bool_t	vmpt_xdr_u_char(VMPT_XDR *, uchar_t *);
extern bool_t	vmpt_xdr_wrapstring(VMPT_XDR *, char **);

extern bool_t	vmpt_xdr_int8_t(VMPT_XDR *, int8_t *);
extern bool_t	vmpt_xdr_uint8_t(VMPT_XDR *, uint8_t *);
extern bool_t	vmpt_xdr_int16_t(VMPT_XDR *, int16_t *);
extern bool_t	vmpt_xdr_uint16_t(VMPT_XDR *, uint16_t *);
extern bool_t	vmpt_xdr_int32_t(VMPT_XDR *, int32_t *);
extern bool_t	vmpt_xdr_uint32_t(VMPT_XDR *, uint32_t *);
extern bool_t	vmpt_xdr_int64_t(VMPT_XDR *, int64_t *);
extern bool_t	vmpt_xdr_uint64_t(VMPT_XDR *, uint64_t *);

#endif /* _VMPTSAS_XDR_H */

