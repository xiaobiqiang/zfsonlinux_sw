#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/isa_defs.h>

#include "vmptsas_xdr.h"

/*
 * for unit alignment
 */
static char vmpt_xdr_zero[BYTES_PER_XDR_UNIT] = { 0, 0, 0, 0 };

#pragma weak vmpt_xdr_int32_t = vmpt_xdr_int
#pragma weak vmpt_xdr_uint32_t = vmpt_xdr_u_int
#pragma weak vmpt_xdr_int64_t = vmpt_xdr_longlong_t
#pragma weak vmpt_xdr_uint64_t = vmpt_xdr_u_longlong_t
#pragma weak vmpt_xdr_int16_t = vmpt_xdr_short
#pragma weak vmpt_xdr_uint16_t = vmpt_xdr_u_short
#pragma weak vmpt_xdr_int8_t = vmpt_xdr_char
#pragma weak vmpt_xdr_uint8_t = vmpt_xdr_u_char

/* ARGSUSED */
static void
vmpt_xdrmem_destroy(VMPT_XDR *xdrs)
{
}

static bool_t
vmpt_xdrmem_getint32(VMPT_XDR *xdrs, int32_t *int32p)
{
	if ((xdrs->x_handy -= (int)sizeof (int32_t)) < 0)
		return (FALSE);
	/* LINTED pointer alignment */
	*int32p = (int32_t)ntohl((uint32_t)(*((int32_t *)(xdrs->x_private))));
	xdrs->x_private += sizeof (int32_t);
	return (TRUE);
}

static bool_t
vmpt_xdrmem_putint32(VMPT_XDR *xdrs, int32_t *int32p)
{
	if ((xdrs->x_handy -= (int)sizeof (int32_t)) < 0)
		return (FALSE);
	/* LINTED pointer alignment */
	*(int32_t *)xdrs->x_private = (int32_t)htonl((uint32_t)(*int32p));
	xdrs->x_private += sizeof (int32_t);
	return (TRUE);
}

static bool_t
vmpt_xdrmem_getbytes(VMPT_XDR *xdrs, caddr_t addr, int len)
{
	if ((xdrs->x_handy -= len) < 0)
		return (FALSE);
	bcopy(xdrs->x_private, addr, len);
	xdrs->x_private += len;
	return (TRUE);
}

static bool_t
vmpt_xdrmem_putbytes(VMPT_XDR *xdrs, caddr_t addr, int len)
{
	if ((xdrs->x_handy -= len) < 0)
		return (FALSE);
	bcopy(addr, xdrs->x_private, len);
	xdrs->x_private += len;
	return (TRUE);
}

static uint_t
vmpt_xdrmem_getpos(VMPT_XDR *xdrs)
{
	return ((uint_t)((uintptr_t)xdrs->x_private - (uintptr_t)xdrs->x_base));
}

static bool_t
vmpt_xdrmem_setpos(VMPT_XDR *xdrs, uint_t pos)
{
	caddr_t newaddr = xdrs->x_base + pos;
	caddr_t lastaddr = xdrs->x_private + xdrs->x_handy;
	ptrdiff_t diff;

	if (newaddr > lastaddr)
		return (FALSE);
	xdrs->x_private = newaddr;
	diff = lastaddr - newaddr;
	xdrs->x_handy = (int)diff;
	return (TRUE);
}

static struct vmpt_xdr_ops *
vmpt_xdrmem_ops(void)
{
	static struct vmpt_xdr_ops ops;

	if (ops.x_getint32 == NULL) {
		ops.x_getbytes = vmpt_xdrmem_getbytes;
		ops.x_putbytes = vmpt_xdrmem_putbytes;
		ops.x_getpostn = vmpt_xdrmem_getpos;
		ops.x_setpostn = vmpt_xdrmem_setpos;
		ops.x_destroy = vmpt_xdrmem_destroy;
		ops.x_getint32 = vmpt_xdrmem_getint32;
		ops.x_putint32 = vmpt_xdrmem_putint32;
	}
	return (&ops);
}

/*
 * The procedure xdrmem_create initializes a stream descriptor for a
 * memory buffer.
 */
void
vmpt_xdrmem_create(VMPT_XDR *xdrs, caddr_t addr, uint_t size, enum vmpt_xdr_op op)
{
	xdrs->x_op = op;
	xdrs->x_ops = vmpt_xdrmem_ops();
	xdrs->x_private = xdrs->x_base = addr;
	xdrs->x_handy = xdrs->x_len = size;
	xdrs->x_public = NULL;
}



/*
 * XDR nothing
 */
bool_t
vmpt_xdr_void(void)
{
	return (TRUE);
}

/*
 * XDR integers
 *
 * PSARC 2003/523 Contract Private Interface
 * xdr_int
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
bool_t
vmpt_xdr_int(VMPT_XDR *xdrs, int *ip)
{
	if (xdrs->x_op == IMPT_XDR_ENCODE)
		return (XDR_PUTINT32(xdrs, ip));

	if (xdrs->x_op == IMPT_XDR_DECODE)
		return (XDR_GETINT32(xdrs, ip));

	if (xdrs->x_op == IMPT_XDR_FREE)
		return (TRUE);

	return (FALSE);
}

/*
 * XDR unsigned integers
 *
 * PSARC 2003/523 Contract Private Interface
 * xdr_u_int
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
bool_t
vmpt_xdr_u_int(VMPT_XDR *xdrs, uint_t *up)
{
	if (xdrs->x_op == IMPT_XDR_ENCODE)
		return (XDR_PUTINT32(xdrs, (int32_t *)up));

	if (xdrs->x_op == IMPT_XDR_DECODE)
		return (XDR_GETINT32(xdrs, (int32_t *)up));

	if (xdrs->x_op == IMPT_XDR_FREE)
		return (TRUE);

	return (FALSE);
}


#if defined(_ILP32)
/*
 * xdr_long and xdr_u_long for binary compatability on ILP32 kernels.
 *
 * No prototypes since new code should not be using these interfaces.
 */
bool_t
vmpt_xdr_long(VMPT_XDR *xdrs, long *ip)
{
	return (vmpt_xdr_int(xdrs, (int *)ip));
}

bool_t
vmpt_xdr_u_long(VMPT_XDR *xdrs, unsigned long *up)
{
	return (vmpt_xdr_u_int(xdrs, (uint_t *)up));
}
#endif /* _ILP32 */


/*
 * XDR long long integers
 */
bool_t
vmpt_xdr_longlong_t(VMPT_XDR *xdrs, longlong_t *hp)
{
	if (xdrs->x_op == IMPT_XDR_ENCODE) {
#if defined(_LITTLE_ENDIAN)
		if (XDR_PUTINT32(xdrs, (int32_t *)((char *)hp +
		    BYTES_PER_XDR_UNIT)) == TRUE) {
			return (XDR_PUTINT32(xdrs, (int32_t *)hp));
		}
#elif defined(_BIG_ENDIAN)
		if (XDR_PUTINT32(xdrs, (int32_t *)hp) == TRUE) {
			return (XDR_PUTINT32(xdrs, (int32_t *)((char *)hp +
			    BYTES_PER_XDR_UNIT)));
		}
#endif
		return (FALSE);

	}
	if (xdrs->x_op == IMPT_XDR_DECODE) {
#if defined(_LITTLE_ENDIAN)
		if (XDR_GETINT32(xdrs, (int32_t *)((char *)hp +
		    BYTES_PER_XDR_UNIT)) == TRUE) {
			return (XDR_GETINT32(xdrs, (int32_t *)hp));
		}
#elif defined(_BIG_ENDIAN)
		if (XDR_GETINT32(xdrs, (int32_t *)hp) == TRUE) {
			return (XDR_GETINT32(xdrs, (int32_t *)((char *)hp +
			    BYTES_PER_XDR_UNIT)));
		}
#endif
		return (FALSE);
	}
	return (TRUE);
}

/*
 * XDR unsigned long long integers
 */
bool_t
vmpt_xdr_u_longlong_t(VMPT_XDR *xdrs, u_longlong_t *hp)
{

	if (xdrs->x_op == VMPT_XDR_ENCODE) {
#if defined(_LITTLE_ENDIAN)
		if (XDR_PUTINT32(xdrs, (int32_t *)((char *)hp +
		    BYTES_PER_XDR_UNIT)) == TRUE) {
			return (XDR_PUTINT32(xdrs, (int32_t *)hp));
		}
#elif defined(_BIG_ENDIAN)
		if (XDR_PUTINT32(xdrs, (int32_t *)hp) == TRUE) {
			return (XDR_PUTINT32(xdrs, (int32_t *)((char *)hp +
			    BYTES_PER_XDR_UNIT)));
		}
#endif
		return (FALSE);

	}
	if (xdrs->x_op == VMPT_XDR_DECODE) {
#if defined(_LITTLE_ENDIAN)
		if (XDR_GETINT32(xdrs, (int32_t *)((char *)hp +
		    BYTES_PER_XDR_UNIT)) == TRUE) {
			return (XDR_GETINT32(xdrs, (int32_t *)hp));
		}
#elif defined(_BIG_ENDIAN)
		if (XDR_GETINT32(xdrs, (int32_t *)hp) == TRUE) {
			return (XDR_GETINT32(xdrs, (int32_t *)((char *)hp +
			    BYTES_PER_XDR_UNIT)));
		}
#endif
		return (FALSE);
	}
	return (TRUE);
}

/*
 * XDR short integers
 */
bool_t
vmpt_xdr_short(VMPT_XDR *xdrs, short *sp)
{
	int32_t l;

	switch (xdrs->x_op) {

	case VMPT_XDR_ENCODE:
		l = (int32_t)*sp;
		return (XDR_PUTINT32(xdrs, &l));

	case VMPT_XDR_DECODE:
		if (!XDR_GETINT32(xdrs, &l))
			return (FALSE);
		*sp = (short)l;
		return (TRUE);

	case VMPT_XDR_FREE:
		return (TRUE);
	}
	return (FALSE);
}

/*
 * XDR unsigned short integers
 */
bool_t
vmpt_xdr_u_short(VMPT_XDR *xdrs, ushort_t *usp)
{
	uint32_t l;

	switch (xdrs->x_op) {

	case VMPT_XDR_ENCODE:
		l = (uint32_t)*usp;
		return (XDR_PUTINT32(xdrs, (int32_t *)&l));

	case VMPT_XDR_DECODE:
		if (!XDR_GETINT32(xdrs, (int32_t *)&l)) {
			return (FALSE);
		}
		*usp = (ushort_t)l;
		return (TRUE);

	case VMPT_XDR_FREE:
		return (TRUE);
	}
	return (FALSE);
}


/*
 * XDR a char
 */
bool_t
vmpt_xdr_char(VMPT_XDR *xdrs, char *cp)
{
	int i;

	i = (*cp);
	if (!vmpt_xdr_int(xdrs, &i)) {
		return (FALSE);
	}
	*cp = (char)i;
	return (TRUE);
}

/*
 * XDR an unsigned char
 */
bool_t
vmpt_xdr_u_char(VMPT_XDR *xdrs, uchar_t *cp)
{
	int i;

	switch (xdrs->x_op) {
	case VMPT_XDR_ENCODE:
		i = (*cp);
		return (XDR_PUTINT32(xdrs, &i));
	case VMPT_XDR_DECODE:
		if (!XDR_GETINT32(xdrs, &i))
			return (FALSE);
		*cp = (uchar_t)i;
		return (TRUE);
	case VMPT_XDR_FREE:
		return (TRUE);
	}
	return (FALSE);
}

/*
 * XDR booleans
 *
 * PSARC 2003/523 Contract Private Interface
 * xdr_bool
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
bool_t
vmpt_xdr_bool(VMPT_XDR *xdrs, bool_t *bp)
{
	int32_t i32b;

	switch (xdrs->x_op) {

	case VMPT_XDR_ENCODE:
		i32b = *bp ? XDR_TRUE : XDR_FALSE;
		return (XDR_PUTINT32(xdrs, &i32b));

	case VMPT_XDR_DECODE:
		if (!XDR_GETINT32(xdrs, &i32b)) {
			return (FALSE);
		}
		*bp = (i32b == XDR_FALSE) ? FALSE : TRUE;
		return (TRUE);

	case VMPT_XDR_FREE:
		return (TRUE);
	}
	return (FALSE);
}

/*
 * XDR enumerations
 *
 * PSARC 2003/523 Contract Private Interface
 * xdr_enum
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
bool_t
vmpt_xdr_enum(VMPT_XDR *xdrs, enum_t *ep)
{
	return (vmpt_xdr_int(xdrs, (int32_t *)ep));
}

/*
 * XDR opaque data
 * Allows the specification of a fixed size sequence of opaque bytes.
 * cp points to the opaque object and cnt gives the byte length.
 *
 * PSARC 2003/523 Contract Private Interface
 * xdr_opaque
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
bool_t
vmpt_xdr_opaque(VMPT_XDR *xdrs, caddr_t cp, const uint_t cnt)
{
	uint_t rndup;
	static char crud[BYTES_PER_XDR_UNIT];

	/*
	 * if no data we are done
	 */
	if (cnt == 0)
		return (TRUE);

	/*
	 * round byte count to full xdr units
	 */
	rndup = cnt % BYTES_PER_XDR_UNIT;
	if (rndup != 0)
		rndup = BYTES_PER_XDR_UNIT - rndup;

	if (xdrs->x_op == VMPT_XDR_DECODE) {
		if (!XDR_GETBYTES(xdrs, cp, cnt)) {
			return (FALSE);
		}
		if (rndup == 0)
			return (TRUE);
		return (XDR_GETBYTES(xdrs, (caddr_t)crud, rndup));
	}

	if (xdrs->x_op == VMPT_XDR_ENCODE) {
		if (!XDR_PUTBYTES(xdrs, cp, cnt)) {
			return (FALSE);
		}
		if (rndup == 0)
			return (TRUE);
		return (XDR_PUTBYTES(xdrs, vmpt_xdr_zero, rndup));
	}

	if (xdrs->x_op == VMPT_XDR_FREE)
		return (TRUE);

	return (FALSE);
}

/*
 * XDR counted bytes
 * *cpp is a pointer to the bytes, *sizep is the count.
 * If *cpp is NULL maxsize bytes are allocated
 *
 * PSARC 2003/523 Contract Private Interface
 * xdr_bytes
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
bool_t
vmpt_xdr_bytes(VMPT_XDR *xdrs, char **cpp, uint_t *sizep, const uint_t maxsize)
{
	char *sp = *cpp;  /* sp is the actual string pointer */
	uint_t nodesize;

	/*
	 * first deal with the length since xdr bytes are counted
	 */
	if (!vmpt_xdr_u_int(xdrs, sizep)) {
		return (FALSE);
	}
	nodesize = *sizep;
	if ((nodesize > maxsize) && (xdrs->x_op != IMPT_XDR_FREE)) {
		return (FALSE);
	}

	/*
	 * now deal with the actual bytes
	 */
	switch (xdrs->x_op) {
	case VMPT_XDR_DECODE:
		if (nodesize == 0)
			return (TRUE);
		if (sp == NULL)
			*cpp = sp = (char *)mem_alloc(nodesize);
		/* FALLTHROUGH */

	case VMPT_XDR_ENCODE:
		return (vmpt_xdr_opaque(xdrs, sp, nodesize));

	case VMPT_XDR_FREE:
		if (sp != NULL) {
			mem_free(sp, nodesize);
			*cpp = NULL;
		}
		return (TRUE);
	}
	return (FALSE);
}

/*
 * XDR null terminated ASCII strings
 * xdr_string deals with "C strings" - arrays of bytes that are
 * terminated by a NULL character.  The parameter cpp references a
 * pointer to storage; If the pointer is null, then the necessary
 * storage is allocated.  The last parameter is the max allowed length
 * of the string as specified by a protocol.
 */
bool_t
vmpt_xdr_string(VMPT_XDR *xdrs, char **cpp, const uint_t maxsize)
{
	char *sp = *cpp;  /* sp is the actual string pointer */
	uint_t size;
	uint_t nodesize;

	/*
	 * first deal with the length since xdr strings are counted-strings
	 */
	switch (xdrs->x_op) {
	case VMPT_XDR_FREE:
		if (sp == NULL)
			return (TRUE);	/* already free */
		/* FALLTHROUGH */
	case VMPT_XDR_ENCODE:
		size = (sp != NULL) ? (uint_t)strlen(sp) : 0;
		break;
	case VMPT_XDR_DECODE:
		break;
	}
	if (!vmpt_xdr_u_int(xdrs, &size)) {
		return (FALSE);
	}
	if (size > maxsize) {
		return (FALSE);
	}
	nodesize = size + 1;

	/*
	 * now deal with the actual bytes
	 */
	switch (xdrs->x_op) {
	case VMPT_XDR_DECODE:
		if (nodesize == 0)
			return (TRUE);
		if (sp == NULL)
			sp = (char *)mem_alloc(nodesize);
		sp[size] = 0;
		if (!vmpt_xdr_opaque(xdrs, sp, size)) {
			/*
			 * free up memory if allocated here
			 */
			if (*cpp == NULL) {
				mem_free(sp, nodesize);
			}
			return (FALSE);
		}
		if (strlen(sp) != size) {
			if (*cpp == NULL) {
				mem_free(sp, nodesize);
			}
			return (FALSE);
		}
		*cpp = sp;
		return (TRUE);

	case VMPT_XDR_ENCODE:
		return (vmpt_xdr_opaque(xdrs, sp, size));

	case VMPT_XDR_FREE:
		mem_free(sp, nodesize);
		*cpp = NULL;
		return (TRUE);
	}
	return (FALSE);
}

