/*****************************************************************************\
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2007 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Brian Behlendorf <behlendorf1@llnl.gov>.
 *  UCRL-CODE-235197
 *
 *  This file is part of the SPL, Solaris Porting Layer.
 *  For details, see <http://zfsonlinux.org/>.
 *
 *  The SPL is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at your
 *  option) any later version.
 *
 *  The SPL is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with the SPL.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************
 *  Solaris Porting Layer (SPL) Credential Implementation.
\*****************************************************************************/

#include <sys/cred.h>

#ifdef DEBUG_SUBSYSTEM
#undef DEBUG_SUBSYSTEM
#endif

#define DEBUG_SUBSYSTEM S_CRED

static int
#ifdef HAVE_KUIDGID_T
cr_groups_search(const struct group_info *group_info, kgid_t grp)
#else
cr_groups_search(const struct group_info *group_info, gid_t grp)
#endif
{
	unsigned int left, right, mid;
	int cmp;

	if (!group_info)
		return 0;

	left = 0;
	right = group_info->ngroups;
	while (left < right) {
		mid = (left + right) / 2;
		cmp = KGID_TO_SGID(grp) -
		    KGID_TO_SGID(GROUP_AT(group_info, mid));

		if (cmp > 0)
			left = mid + 1;
		else if (cmp < 0)
			right = mid;
		else
			return 1;
	}
	return 0;
}

/* Hold a reference on the credential */
void
crhold(cred_t *cr)
{
	(void)get_cred((const cred_t *)cr);
}

/* Free a reference on the credential */
void
crfree(cred_t *cr)
{
	put_cred((const cred_t *)cr);
}

/* Return the number of supplemental groups */
int
crgetngroups(const cred_t *cr)
{
	struct group_info *gi;
	int rc;

	gi = cr->group_info;
	rc = gi->ngroups;
#ifndef HAVE_GROUP_INFO_GID
	/*
	 * For Linux <= 4.8,
	 * crgetgroups will only returns gi->blocks[0], which contains only
	 * the first NGROUPS_PER_BLOCK groups.
	 */
	if (rc > NGROUPS_PER_BLOCK) {
		WARN_ON_ONCE(1);
		rc = NGROUPS_PER_BLOCK;
	}
#endif
	return rc;
}

/*
 * Return an array of supplemental gids.  The returned address is safe
 * to use as long as the caller has taken a reference with crhold().
 *
 * Linux 4.9 API change, group_info changed from 2d array via ->blocks to 1d
 * array via ->gid.
 */
gid_t *
crgetgroups(const cred_t *cr)
{
	struct group_info *gi;
	gid_t *gids = NULL;

	gi = cr->group_info;
#ifdef HAVE_GROUP_INFO_GID
	gids = KGIDP_TO_SGIDP(gi->gid);
#else
	if (gi->nblocks > 0)
		gids = KGIDP_TO_SGIDP(gi->blocks[0]);
#endif
	return gids;
}

/* Check if the passed gid is available in supplied credential. */
int
groupmember(gid_t gid, const cred_t *cr)
{
	struct group_info *gi;
	int rc;

	gi = cr->group_info;
	rc = cr_groups_search(gi, SGID_TO_KGID(gid));

	return rc;
}

/*
 * The reference count is of interest when you want to check
 * whether it is ok to modify the credential in place.
 */
uint_t
crgetref(const cred_t *cr)
{
	int ref;
	ref = atomic_read(&cr->usage);
	return (uint_t)ref;
}


/* Return the effective user id */
uid_t
crgetuid(const cred_t *cr)
{
	return KUID_TO_SUID(cr->euid);
}

/* Return the real user id */
uid_t
crgetruid(const cred_t *cr)
{
	return KUID_TO_SUID(cr->uid);
}

/* Return the saved user id */
uid_t
crgetsuid(const cred_t *cr)
{
	return KUID_TO_SUID(cr->suid);
}

/* Return the filesystem user id */
uid_t
crgetfsuid(const cred_t *cr)
{
	return KUID_TO_SUID(cr->fsuid);
}

/* Return the effective group id */
gid_t
crgetgid(const cred_t *cr)
{
	return KGID_TO_SGID(cr->egid);
}

/* Return the real group id */
gid_t
crgetrgid(const cred_t *cr)
{
	return KGID_TO_SGID(cr->gid);
}

/* Return the saved group id */
gid_t
crgetsgid(const cred_t *cr)
{
	return KGID_TO_SGID(cr->sgid);
}

/* Return the filesystem group id */
gid_t
crgetfsgid(const cred_t *cr)
{
	return KGID_TO_SGID(cr->fsgid);
}



int
crsetresuid(cred_t *cr, uid_t r, uid_t e, uid_t s)
{
	ASSERT(cr->usage <= 2);

	if (r != -1)
		cr->uid = SUID_TO_KUID(r);
	if (e != -1)
		cr->euid = SUID_TO_KUID(e);
	if (s != -1)
		cr->suid = SUID_TO_KUID(s);

	return (0);
}

int
crsetresgid(cred_t *cr, gid_t r, gid_t e, gid_t s)
{
	ASSERT(cr->usage <= 2);

	if (r != -1)
		cr->gid = SGID_TO_KGID(r);
	if (e != -1)
		cr->egid = SGID_TO_KGID(e);
	if (s != -1)
		cr->sgid = SGID_TO_KGID(s);

	return (0);
}

int
crsetugid(cred_t *cr, uid_t uid, gid_t gid)
{
	ASSERT(cr->usage <= 2);

	cr->euid = cr->uid = cr->suid = SUID_TO_KUID(uid);
	cr->egid = cr->gid = cr->sgid = SGID_TO_KGID(gid);

	return (0);
}

int
gidcmp(const void *v1, const void *v2)
{
	gid_t g1 = *(gid_t *)v1;
	gid_t g2 = *(gid_t *)v2;

	if (g1 < g2)
		return (-1);
	else if (g1 > g2)
		return (1);
	else
		return (0);
}

int	ngroups_max = 16;

int
crsetgroups(cred_t *cr, int n, gid_t *grp)
{
	int i, ret=0;
	struct group_info *gi = NULL;
	
	ASSERT(cr->usage <= 2);

	if (n > ngroups_max || n < 0)
		return (-1);

	gi = groups_alloc(n);
	if (!gi)
		return (ENOMEM);
	
	for (i = 0 ; i < n ; i++) {
		GROUP_AT(gi, i) = SGID_TO_KGID(*grp);
		grp++;
	}

	set_groups(cr, gi);
	put_group_info(gi);

	return (ret);
}

EXPORT_SYMBOL(crhold);
EXPORT_SYMBOL(crfree);
EXPORT_SYMBOL(crgetuid);
EXPORT_SYMBOL(crgetruid);
EXPORT_SYMBOL(crgetsuid);
EXPORT_SYMBOL(crgetfsuid);
EXPORT_SYMBOL(crgetgid);
EXPORT_SYMBOL(crgetrgid);
EXPORT_SYMBOL(crgetsgid);
EXPORT_SYMBOL(crgetfsgid);
EXPORT_SYMBOL(crgetngroups);
EXPORT_SYMBOL(crgetgroups);
EXPORT_SYMBOL(groupmember);
EXPORT_SYMBOL(crgetref);
EXPORT_SYMBOL(crsetresuid);
EXPORT_SYMBOL(crsetresgid);
EXPORT_SYMBOL(gidcmp);
EXPORT_SYMBOL(crsetgroups);
EXPORT_SYMBOL(crsetugid);