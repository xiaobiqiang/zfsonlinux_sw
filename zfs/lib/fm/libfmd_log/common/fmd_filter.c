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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/fm/protocol.h>

#include <strings.h>
#include <libgen.h>
#include <regex.h>
#include <libnvpair.h>

#include "fmd_log_impl.h"
#include "fmd_log.h"
#include "gmatch.h"

#define	EMBEDDED_NVL(nvp)	((nvlist_t *)(void *)NVP_VALUE(nvp))
typedef int nvpair_value_match_regex_f(nvpair_t *nvp, int ai,
    char *value, regex_t *value_regex, char **ep);

/*ARGSUSED*/
int
fmd_log_filter_class(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	nvlist_t **nva;
	uint32_t i, size;
	char *class;

	if (gmatch(rp->rec_class, arg))
		return (1);

	/* return false if the record doesn't contain valid fault list */
	if (! gmatch(rp->rec_class, FM_LIST_EVENT ".*") ||
	    nvlist_lookup_uint32(rp->rec_nvl, FM_SUSPECT_FAULT_SZ,
	    &size) != 0 || size == 0 ||
	    nvlist_lookup_nvlist_array(rp->rec_nvl, FM_SUSPECT_FAULT_LIST,
	    &nva, &size) != 0)
		return (0);

	/* return true if any fault in the list matches */
	for (i = 0; i < size; i++) {
		if (nvlist_lookup_string(nva[i], FM_CLASS, &class) == 0 &&
		    gmatch(class, arg))
			return (1);
	}

	return (0);
}


/*ARGSUSED*/
int
fmd_log_filter_uuid(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	char *uuid;

	/*
	 * Note: the uuid filter matches *any* member whose name is 'uuid'.
	 * This permits us to match not only a list.suspect uuid but any
	 * other event that decides to embed uuids, too, using the same name.
	 */
	return (nvlist_lookup_string(rp->rec_nvl,
	    "uuid", &uuid) == 0 && strcmp(uuid, arg) == 0);
}

/*ARGSUSED*/
int
fmd_log_filter_before(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	uint64_t sec = ((struct timeval *)arg)->tv_sec;
	uint64_t nsec = ((struct timeval *)arg)->tv_usec * (NANOSEC / MICROSEC);
	return (rp->rec_sec == sec ? rp->rec_nsec <= nsec : rp->rec_sec <= sec);
}

/*ARGSUSED*/
int
fmd_log_filter_after(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	uint64_t sec = ((struct timeval *)arg)->tv_sec;
	uint64_t nsec = ((struct timeval *)arg)->tv_usec * (NANOSEC / MICROSEC);
	return (rp->rec_sec == sec ? rp->rec_nsec >= nsec : rp->rec_sec >= sec);
}

/*ARGSUSED*/
int
fmd_log_filter_nv(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	fmd_log_filter_nvarg_t *argt = (fmd_log_filter_nvarg_t *)arg;
	char		*name = argt->nvarg_name;
	char		*value = argt->nvarg_value;
	regex_t		*value_regex = argt->nvarg_value_regex;
	nvpair_t	*nvp;
	int		ai;

	/* see if nvlist has named member */
	if (nvlist_lookup_nvpair_embedded_index(rp->rec_nvl, name,
	    &nvp, &ai, NULL) != 0)
		return (0);		/* name filter failure */

	/* check value match for matching nvpair */
	if ((value == NULL) ||
	    (nvpair_value_match_regex(nvp, ai, value, value_regex, NULL) == 1))
		return (1);		/* name/value filter pass */

	return (0);			/* value filter failure */
}

static int
fmd_nvlist_walk_nvpair(nvlist_t *nvl, nvpair_value_match_regex_f *func,
    		char *value, regex_t *value_regex)
{
	nvlist_t	**nva, *nvlist;
	nvpair_t	*nvp;
	long		idx;
	int		ai = -1, n;

	if (nvl == NULL)
		return (EINVAL);

	/* ensure unique names */
	if (!(nvl->nvl_nvflag & NV_UNIQUE_NAME))
		return (ENOTSUP);

	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
		nvp = nvlist_next_nvpair(nvl, nvp)) {
		if(nvpair_type_is_array(nvp)) {
			n = NVP_NELEM(nvp);
			for (ai = 0; ai < n; ai++) {
				if ((value == NULL) ||
				    (func(nvp, ai, value, value_regex, NULL) == 1))
					return (1);		/* name/value filter pass */
			}
		} else {
			ai = -1;
			if ((value == NULL) ||
			    (func(nvp, ai, value, value_regex, NULL) == 1))
				return (1);		/* name/value filter pass */
		}
			
		/* check value match for matching nvpair */
		if (nvpair_type(nvp) == DATA_TYPE_NVLIST) {
			nvlist = EMBEDDED_NVL(nvp);
			if (fmd_nvlist_walk_nvpair(nvlist, func, value, value_regex) == 1)
				return (1);
		} else if (nvpair_type(nvp) == DATA_TYPE_NVLIST_ARRAY) {
			(void) nvpair_value_nvlist_array(nvp,
			    &nva, (uint_t *)&n);
			if (n < 0)
				return (EINVAL);
			for(idx = 0; idx < n; idx++) {
				nvlist = nva[idx];
				if (fmd_nvlist_walk_nvpair(nvlist, func, value, value_regex) == 1)
					return (1);
			}
		}
	}
	return (0);
}

int
fmd_log_filter_string(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	fmd_log_filter_nvarg_t *argt = (fmd_log_filter_nvarg_t *)arg;
//	char		*name = argt->nvarg_name;
	char		*value = argt->nvarg_value;
	regex_t		*value_regex = argt->nvarg_value_regex;

	return (fmd_nvlist_walk_nvpair(rp->rec_nvl,nvpair_value_match_regex, value, value_regex));
}
