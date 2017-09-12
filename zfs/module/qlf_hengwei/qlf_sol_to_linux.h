/*
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
 */
#ifndef _QLF_SOL_TO_LINUX_H
#define	_QLF_SOL_TO_LINUX_H


#include <sys/types.h>
#include <linux/mutex.h>
#include <linux/compiler_compat.h>

#define	QLF_MUTEX(mp)		(&((mp)->m_mutex))

static inline void
qlf_mutex_set_owner(kmutex_t *mp)
{
	/*
	 * kernel will handle its owner, so we don't need to do anything if it
	 * is defined.
	 */
#ifndef HAVE_MUTEX_OWNER
	mp->m_owner = current;
#endif
}

static inline void
qlf_mutex_clear_owner(kmutex_t *mp)
{
#ifndef HAVE_MUTEX_OWNER
	mp->m_owner = NULL;
#endif
}

#ifdef HAVE_MUTEX_OWNER
#define	qlf_mutex_owner(mp)		(ACCESS_ONCE(QLF_MUTEX(mp)->owner))
#else
#define	qlf_mutex_owner(mp)		(ACCESS_ONCE((mp)->m_owner))
#endif
#define	qlf_mutex_owned(mp)		(qlf_mutex_owner(mp) == current)
#define	QLF_MUTEX_HELD(mp)		qlf_mutex_owned(mp)
#define	QLF_MUTEX_NOT_HELD(mp)	(!QLF_MUTEX_HELD(mp))

/*
 * The following functions must be a #define and not static inline.
 * This ensures that the native linux mutex functions (lock/unlock)
 * will be correctly located in the users code which is important
 * for the built in kernel lock analysis tools
 */
#define	qlf_mutex_init(mp, name, type, ibc)				\
{								\
	static struct lock_class_key __key;			\
	ASSERT(type == MUTEX_DEFAULT);				\
								\
	__mutex_init(QLF_MUTEX(mp), (name) ? (#name) : (#mp), &__key); \
	spin_lock_init(&(mp)->m_lock);				\
	qlf_mutex_clear_owner(mp);				\
}

#define	qlf_mutex_destroy(mp)					\
{								\
	VERIFY3P(qlf_mutex_owner(mp), ==, NULL);			\
}

#define	qlf_mutex_tryenter(mp)					\
({								\
	int _rc_;						\
								\
	if ((_rc_ = mutex_trylock(QLF_MUTEX(mp))) == 1)		\
		qlf_mutex_set_owner(mp);			\
								\
	_rc_;							\
})

#ifdef CONFIG_DEBUG_LOCK_ALLOC
#define	qlf_mutex_enter_nested(mp, subclass)			\
{								\
	ASSERT3P(mutex_owner(mp), !=, current);			\
	mutex_lock_nested(QLF_MUTEX(mp), (subclass));		\
	qlf_mutex_set_owner(mp);				\
}
#else /* CONFIG_DEBUG_LOCK_ALLOC */
#define	qlf_mutex_enter_nested(mp, subclass)			\
{								\
	ASSERT3P(mutex_owner(mp), !=, current);			\
	mutex_lock(QLF_MUTEX(mp));					\
	qlf_mutex_set_owner(mp);				\
}
#endif /*  CONFIG_DEBUG_LOCK_ALLOC */

#define	qlf_mutex_enter(mp) qlf_mutex_enter_nested((mp), 0)

/*
 * The reason for the spinlock:
 *
 * The Linux mutex is designed with a fast-path/slow-path design such that it
 * does not guarantee serialization upon itself, allowing a race where latter
 * acquirers finish mutex_unlock before former ones.
 *
 * The race renders it unsafe to be used for serializing the freeing of an
 * object in which the mutex is embedded, where the latter acquirer could go
 * on to free the object while the former one is still doing mutex_unlock and
 * causing memory corruption.
 *
 * However, there are many places in ZFS where the mutex is used for
 * serializing object freeing, and the code is shared among other OSes without
 * this issue. Thus, we need the spinlock to force the serialization on
 * mutex_exit().
 *
 * See http://lwn.net/Articles/575477/ for the information about the race.
 */
#define	qlf_mutex_exit(mp)						\
{								\
	spin_lock(&(mp)->m_lock);				\
	qlf_mutex_clear_owner(mp);				\
	mutex_unlock(QLF_MUTEX(mp));				\
	spin_unlock(&(mp)->m_lock);				\
}

#endif

