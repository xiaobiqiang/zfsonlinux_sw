/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _EXACCT_OPS_H_
#define _EXACCT_OPS_H_

#include "exacct.h"
#include "exacct_impl.h"

#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>

int ea_error(void);
ea_object_type_t ea_next_object(ea_file_t *ef, ea_object_t *obj);
ea_object_type_t ea_previous_object(ea_file_t *ef, ea_object_t *obj);
ea_object_type_t ea_get_object(ea_file_t *ef, ea_object_t *obj);
ea_object_type_t ea_unpack_object(ea_object_t **objp, int flag, void *buf, size_t bufsize);
int ea_write_object(ea_file_t *ef, ea_object_t *obj);
const char *ea_get_creator(ea_file_t *ef);
const char *ea_get_hostname(ea_file_t *ef);
int ea_fdopen(ea_file_t *ef, int fd, const char *creator, int aflags, int oflags);
int ea_open(ea_file_t *ef, const char *name, const char *creator, int aflags, int oflags, mode_t mode);
int ea_close(ea_file_t *ef);
void ea_clear(ea_file_t *ef);
ea_object_t *ea_copy_object(const ea_object_t *src);
ea_object_t *ea_copy_object_tree(const ea_object_t *src);
ea_object_t *ea_get_object_tree(ea_file_t *ef, uint32_t nobj);
#endif
