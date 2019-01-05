// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file veriexec_sec.h
 *  veriexec LSM functions header
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2008 SGDN/DCSSI
 *  Copyright (C) 2011-2014 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#ifndef _LINUX_VERIEXEC_LSM_H
#define _LINUX_VERIEXEC_LSM_H

#ifdef __KERNEL__

#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/veriexec.h>

#ifdef CONFIG_VERIEXEC
/*************************************************************/
/*                     Protos for veriexec_creds             */
/*************************************************************/

extern void veriexec_task_clear(void);
extern int veriexec_getcreds(struct linux_binprm *);
extern int veriexec_privileged_binary(const struct dentry *);

/**
 * Type of checks to be performed on a library that is being
 * loaded in a privileged process :
 *  - no check at all (default)
 *  - check a veriexec entry is present for the library (VRX_FLAG_NEEDLIBS)
 *  - perform a full check of the library's veriexec hash (VRX_FLAG_CHECKLIBS)
 */
typedef enum {
	VeriexecCheckNone,
	VeriexecCheckPresent,
	VeriexecCheckDigest,
} veriexec_lib_check_t;

extern int veriexec_updatecreds(struct file *, veriexec_lib_check_t);

/**
 * Clear 'dangerous' veriexec flags from a binprm.
 * This removes the INHERIT and SCRIPT flags from a binprm,
 * and is called when exec'ing a file while being traced or
 * in a shared state.
 * @param bprm Binprm to clear flags from.
 */
static inline void
veriexec_cred_resetopts(struct cred *cred)
{
	struct clsm_task_sec *sec = cred->security;

	sec->t_vflags &= ~(VRX_FLAG_INHERIT);
}

/*************************************************************/
/*                     Common tests                          */
/*************************************************************/

/**
 * Test if the interpreter for an executable must be checked by veriexec.
 * @param bprm Binprm for the executable.
 * @return 0 if no check is required, 1 if a simple presence test (in the
 * veriexec store) is required, and 2 if a full veriexec check is required.
 * When the return value retval is non-zero, retval - 1 is a boolean telling
 * veriexec whether a full check or simple check is required.
 */
static inline veriexec_lib_check_t
veriexec_binprm_checkinterp(const struct linux_binprm *bprm)
{
	const struct clsm_task_sec *bsec = bprm->cred->security;


	if (likely(!(bsec->t_flags & CLSM_FLAG_RAISED)))
		return VeriexecCheckNone;

	if (bsec->t_vflags & VRX_FLAG_NEEDLIBS)
		return VeriexecCheckPresent;

	if (bsec->t_vflags & VRX_FLAG_CHECKLIBS)
		return VeriexecCheckDigest;

	return VeriexecCheckNone;
}

/**
 * Test if the libraries loaded by a task be checked by veriexec.
 * @param tsk Task to check for.
 * @return 0 if no check is required, 1 if a simple presence test (in the
 * veriexec store) is required, and 2 if a full veriexec check is required.
 * When the return value retval is non-zero, retval - 1 is a boolean telling
 * veriexec whether a full check or simple check is required.
 */
static inline int
veriexec_task_checklibs(const struct task_struct *tsk)
{
	const struct clsm_task_sec *tsec;
	int ret = VeriexecCheckNone;

	rcu_read_lock();
	tsec = __task_cred(tsk)->security;
	if (unlikely((tsec->t_flags & CLSM_FLAG_RAISED))) {
		if (tsec->t_vflags & VRX_FLAG_NEEDLIBS)
			ret = VeriexecCheckPresent;

		if (tsec->t_vflags & VRX_FLAG_CHECKLIBS)
			ret = VeriexecCheckDigest;
	}
	rcu_read_unlock();

	return ret;
}

#else /* !CONFIG_VERIEXEC */

#define veriexec_cred_resetopts(cred) do {;} while (0)
#define veriexec_task_clear() do {;} while (0)
#define veriexec_getcreds(bprm) 0
#define veriexec_updatecreds(filp) 0
#define veriexec_privileged_binary(dentry) 0

#define veriexec_binprm_checkinterp(bprm) 0
#define veriexec_task_checklibs(tsk) 0

#endif /* CONFIG_VERIEXEC */

#else /* !__KERNEL__ */
#error This header must not be included in userland code
#endif /* __KERNEL__ */

#else /* !_LINUX_VERIEXEC_LSM_H */
#warning Double inclusion
#endif /*_LINUX_VERIEXEC_LSM_H */
