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
#ifndef _EXACCT_CORE_H_
#define _EXACCT_CORE_H_

#include <sys/types.h>
#include "exacct.h"
#include "exacct_impl.h"

#ifndef	_KERNEL
#include <limits.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <strings.h>
#else
#include <sys/systm.h>
#endif

void *ea_alloc(size_t size);
void ea_free(void *ptr, size_t size);
char *ea_strdup(const char *ptr);
void *ea_strfree(char *ptr);
void exacct_order16(uint16_t *in);
void exacct_order32(uint32_t *in);
void exacct_order64(uint64_t *in);
int ea_match_object_catalog(ea_object_t *obj, ea_catalog_t catmask);
int ea_set_item(ea_object_t *obj, ea_catalog_t tag, const void *value, size_t valsize);
int ea_set_group(ea_object_t *obj, ea_catalog_t tag);
void ea_free_object(ea_object_t *obj, int flag);
int ea_free_item(ea_object_t *obj, int flag);
int ea_attach_to_object(ea_object_t *root, ea_object_t *obj);
int ea_attach_to_group(ea_object_t *group, ea_object_t *obj);
size_t ea_pack_object(ea_object_t *obj, void *buf, size_t bufsize);
#endif

