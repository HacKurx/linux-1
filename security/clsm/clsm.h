// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file clsm.h
 *  CLSM internal header
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  @n
 *  Copyright (C) 2006-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2014 SGDSN/ANSSI
 *  All rights reserved.
 *
 */

#ifndef _LINUX_CLSM_H
#define _LINUX_CLSM_H

#ifdef __KERNEL__

#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/cred.h>

#include <linux/clip_lsm.h>
#ifdef CONFIG_VERIEXEC
#include <linux/veriexec/vcreds.h>
#include <linux/vserver/base.h>
#else
#define vx_current_xid()
#endif

/*************************************************************/
/*                    printk macros                          */
/*************************************************************/


/**
 * Output formatted message to @a facility.
 */
#define _CLSM_LOG(facility, fmt, args...) \
	printk(facility "CLSM: %s (ctx %d): " fmt, __FUNCTION__, \
						vx_current_xid(), ##args)
/**
 * Output formatted message, with task information, to @a facility.
 */
#define _CLSM_LOG_TASK(facility, fmt, tsk, comm, args...) do { \
	const struct cred *__cred = get_task_cred(tsk); \
	_CLSM_LOG(facility, "task %s (%d - %d/%d - %d/%d) " fmt, comm, \
			tsk->pid, from_kuid(&init_user_ns, __cred->euid),\
			from_kuid(&init_user_ns,	__cred->uid),\
			from_kgid(&init_user_ns, __cred->egid),\
			from_kgid(&init_user_ns, __cred->gid),\
			##args); \
} while (0)


#ifdef CONFIG_CLSM_DEBUG
/**
 * Output formatted message to KERN_DEBUG, if CONFIG_CLSM_DEBUG is defined.
 */
#define CLSM_DEBUG(fmt, args...) \
	_CLSM_LOG(KERN_DEBUG, fmt, ##args)
#else
#define CLSM_DEBUG(fmt, args...)
#endif

/**
 * Output formatted warning message to KERN_INFO
 */
#define CLSM_INFO(fmt, args...) \
	_CLSM_LOG(KERN_INFO, fmt, ##args)
/**
 * Output formatted warning message to KERN_WARNING.
 */
#define CLSM_WARN(fmt, args...) \
	_CLSM_LOG(KERN_WARNING, fmt, ##args)
/**
 * Output formatted warning message to KERN_ERR.
 */
#define CLSM_ERROR(fmt, args...) \
	_CLSM_LOG(KERN_ERR, fmt, ##args)

/**
 * Output formatted message at level lev, including the common name of
 * task tsk.
 * <b> Locks current->task_lock. </b>
 */
#define CLSM_LOG_COMM_T(lev, tsk, fmt, args...) do {\
	char _comm[TASK_COMM_LEN]; \
	get_task_comm(_comm, tsk); \
	_CLSM_LOG_TASK(lev, fmt, tsk, _comm, ##args); \
} while (0)

/**
 * Output formatted message at level lev, including the common name of
 * task tsk.
 * <b> Caller must hold current->task_lock. </b>
 */
#define CLSM_LOG_COMM_NOLOCK_T(lev, tsk, fmt, args...) do {\
	char _comm[TASK_COMM_LEN]; \
	strncpy(_comm, tsk->comm, TASK_COMM_LEN); \
	_comm[TASK_COMM_LEN - 1] = '\0'; \
	_CLSM_LOG_TASK(lev, fmt, tsk, _comm, ##args); \
} while (0)

/**
 * Output formatted message to KERN_INFO, including the common name of
 * current task.
 * <b> Locks current->task_lock. </b>
 */
#define CLSM_INFO_COMM(fmt, args...)	\
	CLSM_LOG_COMM_T(KERN_INFO, current, fmt, ##args)

/**
 * Output formatted message to KERN_INFO, including the common name of
 * current task.
 * <b> Caller must hold current->task_lock. </b>
 */
#define CLSM_INFO_COMM_NOLOCK(fmt, args...)	\
	CLSM_LOG_COMM_NOLOCK_T(KERN_INFO, current, fmt, ##args)


/**
 * Output formatted message to KERN_WARNING, including the common name of
 * current task.
 * <b> Locks current->task_lock. </b>
 */
#define CLSM_WARN_COMM(fmt, args...)	\
	CLSM_LOG_COMM_T(KERN_WARNING, current, fmt, ##args)

/**
 * Output formatted message to KERN_WARNING, including the common name of
 * current task.
 * <b> Caller must hold current->task_lock. </b>
 */
#define CLSM_WARN_COMM_NOLOCK(fmt, args...)	\
	CLSM_LOG_COMM_NOLOCK_T(KERN_WARNING, current, fmt, ##args)


/**
 * Output formatted message to KERN_ERROR, including the common name of
 * current task.
 * <b> Locks current->task_lock. </b>
 */
#define CLSM_ERROR_COMM(fmt, args...)	\
	CLSM_LOG_COMM_T(KERN_ERR, current, fmt, ##args)

/**
 * Output formatted message to KERN_ERROR, including the common name of
 * current task.
 * <b> Caller must hold current->task_lock. </b>
 */
#define CLSM_ERROR_COMM_NOLOCK(fmt, args...)	\
	CLSM_LOG_COMM_NOLOCK_T(KERN_ERR, current, fmt, ##args)


/*************************************************************/
/*                    Common tests                           */
/*************************************************************/

/** Test a CLSM flags bitmask for capraised flags
 * (CLSM_FLAG_RAISED only at this point). */
#define clsm_flags_capraised(flag) \
	((flag) & CLSM_FLAG_RAISED)

/** Test a CLSM flags bitmask for 'raised' flags. */
#define clsm_flags_raised(flag) \
	((flag) & (CLSM_FLAG_RAISED|CLSM_FLAG_INHERITED|CLSM_FLAG_BUMPED))


/**
 * Test if a cred struct is capraised.
 * @param bprm Binprm to test.
 * @return 1 if binprm is capraised, 0 if it is not.
 */
static inline int
clsm_cred_capraised(const struct cred *cred)
{
	const struct clsm_task_sec *sec = cred->security;

	if (!sec)
		return 1;
	return clsm_flags_capraised(sec->t_flags);
}

/**
 * Test if a cred struct is raised.
 * @param bprm Binprm to test.
 * @return 1 if binprm is raised, 0 if it is not.
 */
static inline int
clsm_cred_raised(const struct cred *cred)
{
	const struct clsm_task_sec *sec = cred->security;
	if (!sec)
		return 1;
	return clsm_flags_raised(sec->t_flags);
}

/**
 * Test if a task is capraised.
 * Note that kernel code is always 'capraised'.
 * @param tsk Task to test.
 * @return 1 if task is capraised, 0 if it is not.
 */
static inline int
clsm_task_capraised(const struct task_struct *tsk)
{
	int ret;

	rcu_read_lock();
	ret = clsm_cred_capraised(__task_cred(tsk));
	rcu_read_unlock();

	return ret;
}

/**
 * Test if a task is raised.
 * Note that kernel code is always 'raised'.
 * @param tsk Task to test.
 * @return 1 if task is raised, 0 if it is not.
 */
static inline int
clsm_task_raised(const struct task_struct *tsk)
{
	int ret;

	rcu_read_lock();
	ret = clsm_cred_raised(__task_cred(tsk));
	rcu_read_unlock();

	return ret;
}
/*************************************************************/
/*                    sysctl stuff                           */
/*************************************************************/

/* security_initcall */
extern int clsm_init_sysctl(void);

/* late_initcall */
extern int clsm_init_sysctl_table(void);

extern void clsm_exit_sysctl(void);

#else /* !__KERNEL__ */
#error This header must not be included in userland code
#endif /* __KERNEL__ */

#endif
