/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_EXACCT_H
#define	_EXACCT_H

#include <stdio.h>
#include <unistd.h>

/*
 * exacct item, group, and object definitions as well as structure manipulation
 * and conversion routines are given in sys/exacct.h.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ea_open positioning options:  passed in via the aflags argument, these flags
 * determine whether the newly opened file is positioned for reading prior to
 * its first record, or after its last.
 */
#define	EO_HEAD		0x0	/* open file positioned at first object */
#define	EO_TAIL		0x1	/* open file positioned at last object */
#define	EO_POSN_MSK	0x1

/*
 * ea_open validation options:  passed in via the aflags argument, these flags
 * specify whether the open operation should validate the header on the input
 * file.  The EO_NO_VALID_HDR is useful in the case that no header is present on
 * the file, but the version and file type checks are omitted, meaning that
 * incompatibilities might not be caught immediately.
 */
#define	EO_VALID_HDR	0x0	/* validate header on opening file */
#define	EO_NO_VALID_HDR	0x2	/* omit header validation */
#define	EO_VALIDATE_MSK	0x2

#define	EUP_ALLOC	0x0	/* allocate new memory for vbl length objects */
#define	EUP_NOALLOC	0x1	/* use existing buffer for vbl length objects */
#define	EUP_ALLOC_MASK	0x1

#define	EXR_OK			0
#define	EXR_SYSCALL_FAIL	1
#define	EXR_CORRUPT_FILE	2
#define	EXR_EOF			3
#define	EXR_NO_CREATOR		4
#define	EXR_INVALID_BUF		5
#define	EXR_NOTSUPP		6
#define	EXR_UNKN_VERSION	7
#define	EXR_INVALID_OBJ		8

#define	EXACCT_VERSION	1



typedef enum {EO_ERROR = -1, EO_NONE = 0, EO_GROUP, EO_ITEM} ea_object_type_t;
typedef uint64_t ea_size_t;
typedef uint32_t ea_catalog_t;

typedef struct ea_item {
	/*
	 * The ei_u union is discriminated via the type field of the enclosing
	 * object's catalog tag.
	 */
	union {
		uint8_t		ei_u_uint8;
		uint16_t	ei_u_uint16;
		uint32_t	ei_u_uint32;
		uint64_t	ei_u_uint64;
		double		ei_u_double;
		char		*ei_u_string;
		void		*ei_u_object;	/* for embedded packed object */
		void		*ei_u_raw;
	}ei_u;
	ea_size_t		ei_size;
} ea_item_t;

typedef struct _ea_file {
	void		*ef_opaque_ptr[8];
	offset_t	ef_opaque_off[3];
	int		ef_opaque_int[6];
} ea_file_t;

typedef struct ea_group {
	uint32_t		eg_nobjs;
	struct ea_object	*eg_objs;
} ea_group_t;

typedef struct ea_object {
	ea_object_type_t	eo_type;
	union {
		ea_group_t	eo_u_group;
		ea_item_t	eo_u_item;
	}eo_u;
	struct ea_object	*eo_next;
	ea_catalog_t		eo_catalog;
} ea_object_t;

extern int ea_error(void);
extern int ea_open(ea_file_t *, const char *, const char *, int, int, mode_t);
extern int ea_fdopen(ea_file_t *, int, const char *, int, int);
extern void ea_clear(ea_file_t *);
extern int ea_close(ea_file_t *);
extern int ea_match_object_catalog(ea_object_t *, ea_catalog_t);
extern ea_object_type_t ea_next_object(ea_file_t *, ea_object_t *);
extern ea_object_type_t ea_previous_object(ea_file_t *, ea_object_t *);
extern ea_object_type_t ea_get_object(ea_file_t *, ea_object_t *);
extern ea_object_type_t ea_unpack_object(ea_object_t **, int, void *, size_t);
extern int ea_write_object(ea_file_t *, ea_object_t *);
extern const char *ea_get_creator(ea_file_t *);
extern const char *ea_get_hostname(ea_file_t *);
extern ea_object_t *ea_copy_object(const ea_object_t *);
extern ea_object_t *ea_copy_object_tree(const ea_object_t *);
extern ea_object_t *ea_get_object_tree(ea_file_t *, uint32_t);
extern void exacct_seterr(int errval);
extern int ea_set_group(ea_object_t *obj, ea_catalog_t tag);
extern int ea_set_item(ea_object_t *obj, ea_catalog_t tag, const void *value, size_t valsize);
extern int ea_attach_to_group(ea_object_t *group, ea_object_t *obj);
extern size_t ea_pack_object(ea_object_t *obj, void *buf, size_t bufsize);
extern int ea_free_item(ea_object_t *obj, int flag);
extern void ea_free_object(ea_object_t *obj, int flag);
extern void exacct_order32(uint32_t *);


#ifdef	__cplusplus
}
#endif

#endif	/* _EXACCT_H */
