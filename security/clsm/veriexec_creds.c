// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file veriexec_creds.c
 *  veriexec credentials
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2008 SGDN/DCSSI
 *  Copyright (C) 2011-2014 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#include <linux/module.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/mount.h>
#include <linux/prctl.h>
#ifdef CONFIG_VERIEXEC_CACHE
#include <linux/security.h>
#endif

#include <linux/clip_lsm.h>
#include "veriexec_sec.h"

/*************************************************************/
/*                       Cache management                    */
/*************************************************************/

#ifdef CONFIG_VERIEXEC_CACHE

extern int clsm_inode_alloc_security(struct inode *inode);

/**
 * Mark an inode as verified in the Veriexec cache.
 * This adds the appropriate flag to the inode CLSM security tag.
 * <b> Called without inode->i_lock held, will lock and unlock it</b>
 * @param inode Inode to mark cached.
 */
static inline void
veriexec_inode_cache(struct inode *inode)
{
	struct clsm_inode_sec *isec = inode->i_security;

	if (unlikely(!isec)) {
		if (clsm_inode_alloc_security(inode))
			return;
		isec = inode->i_security;
	}
	/* Make sure no one is accessing that file
	 * for writing */
	spin_lock(&inode->i_lock);
	if (atomic_read(&inode->i_writecount) > 0) {
		spin_unlock(&inode->i_lock);
		return;
	}
	isec->i_flags |= CLSM_IFLAG_CACHED;
	spin_unlock(&inode->i_lock);
}

/**
 * Test if an inode has been verified according to the Veriexec cache.
 * This checks the appropriate flag in the inode CLSM security tag.
 * <b> Called without inode->i_lock held, will lock and unlock it</b>
 * @param inode Inode to check.
 * @return 1 if cached, 0 if not.
 */
static inline int
veriexec_inode_cached(struct inode *inode)
{
	int ret;
	struct clsm_inode_sec *isec = inode->i_security;

	if (unlikely(!isec))
		return 0;
	spin_lock(&inode->i_lock);
	ret = isec->i_flags & CLSM_IFLAG_CACHED;
	spin_unlock(&inode->i_lock);

	return ret;
}

#else /* !CONFIG_VERIEXEC_CACHE */

#define veriexec_inode_cache(inode) do {;} while (0)
#define veriexec_inode_cached(inode) 0

#endif /* !CONFIG_VERIEXEC_CACHE */


/*************************************************************/
/*                     Task/binprm update helpers            */
/*************************************************************/

/**
 * Clear privileges (capabilities and CLSM privs) from a credentials
 * structure.
 * @param cred Credentials structure to clear of privileges.
 */
static inline void
clear_creds(struct cred *cred)
{
	struct clsm_task_sec *tsec = cred->security;

	/* Note: we could also reestablish basic root capset if applicable,
	 * but let's just be on the cautious (and simple!) side */
	cap_clear(cred->cap_effective);
	cap_clear(cred->cap_permitted);
	cap_clear(cred->cap_inheritable);

	tsec->t_vflags = 0;
	tsec->t_privs = 0;
	tsec->t_sprivs = 0;
	tsec->t_flags &= ~(CLSM_FLAG_RAISED
				|CLSM_FLAG_BUMPED|CLSM_FLAG_INHERITED);
}

/**
 * Clear current capabilities and privileges,
 * typically after a verification failure.
 */
inline void
veriexec_task_clear(void)
{
	struct cred *cred = prepare_creds();

	/* No better way to deal with this... */
	if (!cred) {
		VERIEXEC_WARN("Out of memory clearing creds");
		BUG();
	}

	clear_creds(cred);

	/* No better way here either... */
	if (commit_creds(cred)) {
		VERIEXEC_WARN("Failed to commit cleared creds");
		BUG();
	}
}

/**
 * Raise a verified binprm's privileges.
 * This copies the matching entry's capabilities, privileges and flags
 * to the binprm's cap masks and CLSM security tag.
 * @param entry Verified entry matching the binprm.
 * @param cred Credentials for the binprm.
 */
static inline void
vrx_raise_combine(const struct veriexec_entry *entry, struct cred *cred,
		const struct linux_binprm *bprm)
{
	struct clsm_task_sec *sec = cred->security;

	/* Raise POSIX capabilities */
	if (!cap_isclear(entry->ve_caps.v_cap_e) ||
			!cap_isclear(entry->ve_caps.v_cap_p) ||
			!cap_isclear(entry->ve_caps.v_cap_i)) {
		cred->cap_effective = cap_combine(cred->cap_effective,
						entry->ve_caps.v_cap_e);
		cred->cap_permitted = cap_combine(cred->cap_permitted,
						entry->ve_caps.v_cap_p);
		cred->cap_inheritable = cap_combine(cred->cap_inheritable,
						entry->ve_caps.v_cap_i);

		VERIEXEC_DEBUG2("Raised POSIX caps for %s to "
				CAP_T_PRINT_CONV" / "CAP_T_PRINT_CONV" / "
				CAP_T_PRINT_CONV" process %d\n",
				bprm->file->f_path.dentry->d_name.name,
				CAP_T_PRINT_ARGS(cred->cap_effective),
				CAP_T_PRINT_ARGS(cred->cap_permitted),
				CAP_T_PRINT_ARGS(cred->cap_inheritable),
				current->pid);

		sec->t_flags |= CLSM_FLAG_RAISED;
	}

	/* Raise CLSM capabilities */
	if (entry->ve_privs) {
		sec->t_privs |= (entry->ve_privs & CLSM_PRIVS_COPY_VERIEXEC);
		if (sec->t_privs & CLSM_PRIVS_ROOT_MASK)
			sec->t_flags |= CLSM_FLAG_BUMPED;
		VERIEXEC_DEBUG2("Raised CLSM privs for %s to %lx for process %d\n",
				bprm->file->f_path.dentry->d_name.name,
				sec->t_privs, current->pid);
	}

	sec->t_vflags = entry->ve_flags;
}

/**
 * Intersect a verified binprm's privileges with those of a veriexec
 * entry.
 * This intersects the matching entry's capabilities, privileges and flags
 * with the binprm's cap masks and CLSM security tag. It is only appropriate
 * when applying a script interpreter's entry against a script.
 * @param entry Verified entry matching the binprm (or it's interpreter).
 * @param cred Credentials for the binprm.
 */
static inline void
vrx_raise_intersect(const struct veriexec_entry *entry, struct cred *cred,
			const struct linux_binprm *bprm)
{
	struct clsm_task_sec *sec = cred->security;

	/* Intersect POSIX capabilities */
	if (!cap_isclear(entry->ve_caps.v_cap_e) ||
			!cap_isclear(entry->ve_caps.v_cap_p) ||
			!cap_isclear(entry->ve_caps.v_cap_i)) {
		cred->cap_effective = cap_intersect(cred->cap_effective,
						entry->ve_caps.v_cap_e);
		cred->cap_permitted = cap_intersect(cred->cap_permitted,
						entry->ve_caps.v_cap_p);
		cred->cap_inheritable = cap_intersect(cred->cap_inheritable,
						entry->ve_caps.v_cap_i);

		VERIEXEC_DEBUG2("Intersected POSIX caps for %s to "
				CAP_T_PRINT_CONV" / "CAP_T_PRINT_CONV" / "
				CAP_T_PRINT_CONV"\n",
				"%x / %x / %x\n",
				bprm->file->f_path.dentry->d_name.name,
				CAP_T_PRINT_ARGS(cred->cap_effective),
				CAP_T_PRINT_ARGS(cred->cap_permitted),
				CAP_T_PRINT_ARGS(cred->cap_inheritable));

		sec->t_flags |= CLSM_FLAG_RAISED;
	}

	/* Intersect CLSM capabilities */
	if (entry->ve_privs) {
		sec->t_privs &= (entry->ve_privs & CLSM_PRIVS_COPY_VERIEXEC);
		if (sec->t_privs & CLSM_PRIVS_ROOT_MASK)
			sec->t_flags |= CLSM_FLAG_BUMPED;

		VERIEXEC_DEBUG2("Intersected CLSM privs for %s to %lx\n",
				bprm->file->f_path.dentry->d_name.name,
				sec->t_privs);
	}

	sec->t_vflags = entry->ve_flags;
}

/**
 * Modify a verified binprm's privileges.
 * This usually copies the matching entry's capabilities, privileges and flags
 * to the binprm's cap masks and CLSM security tag. There are two exceptions -
 * if the binprm is a script, and the entry is for that script's interpreter,
 * then the entry and binprm privileges are intersected. Otherwise, interpreter
 * entries are simply ignored.
 * @param entry Verified entry matching the binprm.
 * @param bprm Verified binprm.
 */
static inline void
veriexec_binprm_raise(const struct veriexec_entry *entry,
				struct linux_binprm *bprm)
{
	struct cred *cred = bprm->cred;
	struct clsm_task_sec *sec = cred->security;

#ifdef CONFIG_VERIEXEC_MNTSUID
	if (bprm->file->f_path.mnt->mnt_flags & MNT_NOSUID)
		return;
#endif

	if (unlikely(VRXF_IS_SCRIPT(sec->t_vflags))) {
		if (!VRXF_IS_INTERP(entry->ve_flags)) {
			VERIEXEC_WARN("Script interpreter is missing the "
				"INTERP flag: %s",
				bprm->file->f_path.dentry->d_name.name);
			clear_creds(cred);
			veriexec_task_clear();
			return;
		}
		vrx_raise_intersect(entry, cred, bprm);
		return;
	}

	if (unlikely(VRXF_IS_INTERP(entry->ve_flags)))
		return;

	/* We want to be careful here and not raise the
	 * ineritable set of root to rootcap inadvertently,
	 * thus we clear the bprm inheritable set that was
	 * set by set_rootcaps */
	if (VRXF_IS_INHERIT(entry->ve_flags)) {
		cap_clear(cred->cap_inheritable);
		sec->t_vflags |= VRX_FLAG_INHERIT;
		sec->t_flags |= CLSM_FLAG_INHERITED;
	}

	vrx_raise_combine(entry, cred, bprm);
}


/*************************************************************/
/*                     Main tests                            */
/*************************************************************/

/**
 * Verify an executable and give it privileges accordingly.
 * This performs the following operations in order, for an executable
 * passed as argument.
 * @li Check if veriexec is active in the current context, return if it
 * is not.
 * @li Check for a veriexec entry matching the executable in the current
 * context. Exit if not found.
 * @li Check if the entry's flag make it 'verifiable' in the current case
 * (entry is an executable, conditions on calling task are met). Exit if
 * not verifiable.
 * @li Check the veriexec cache. If not found, verify the executable's
 * fingerprint. If fingerprints do not match, exit on error (execution
 * will fail). Otherwise, cache the verification.
 * @li Raise the verified binprm's credentials (capabilities and privileges).
 * Note that the calling task's privileges are not affected directly, but will
 * be transmitted the binprm's credentials in security_bprm_apply_creds().
 * @li If the binprm corresponds to a script (based on its flags, which are
 * inherited from the script's own binprm), and no verification occurs, all
 * it's privileges are cleared.
 * @param bprm Binprm to verify.
 * @return 0 on success (no verification performed, or verification successful),
 * negative error code on failure.
 */
int
veriexec_getcreds(struct linux_binprm *bprm)
{
	struct veriexec_entry *entry;
	int lvl;
	int ret;
	int raised = 0;

	const struct clsm_task_sec *bsec = bprm->cred->security;

	ret = veriexec_get_curlvl(&lvl);
	/* The main cause for this to fail
	 * is that the current context does
	 * not have a veriexec context, so
	 * we should not return an error here
	 * (otherwise we would break e.g.
	 * vserver's watch context. */
	if (unlikely(ret)) {
		ret = 0;
		goto out_clear;
	}

	if (!VERIEXEC_LEVEL_ACTIVE(lvl))
		goto out_clear;

	entry = veriexec_lookup_f(bprm->file);
	if (likely(IS_ERR(entry)))
		goto out_clear;

	if (!VRXF_IS_EXE(entry->ve_flags)) {
		/* We deal with this as if the entry had not been found.
		 * Note that returning an error here would break e.g. ldd
		 * since that calls /lib/ld-linux.so.2, which is probably
		 * in store as a library... */
		ret = 0;
		goto out_put;
	}

	/* Do not raise the credentials if entry has the NEEDROOT flag
	 * and we're not running as root */
	if (VRXF_NEED_ROOT(entry->ve_flags)) {
		kuid_t root_uid = make_kuid(current_user_ns(), 0);
		if ((!uid_eq(current_uid(), root_uid)
				|| !uid_eq(current_euid(), root_uid))) {
			ret = 0;
			goto out_put;
		}
	}

	if (VRXF_NEED_KTHREAD(entry->ve_flags) &&
			!(bsec->t_flags & CLSM_FLAG_KTHREAD)) {
		VERIEXEC_WARN("KTHREAD needed, not present: (%d), comm: %s, 0x%x\n",
						current->pid, current->comm, bsec->t_flags);
		ret = 0;
		goto out_put;
	}

	if (likely(veriexec_inode_cached(bprm->file->f_path.dentry->d_inode))) {
		VERIEXEC_DEBUG2("Using cached verification for %s\n",
				bprm->file->f_path.dentry->d_name.name);
		veriexec_binprm_raise(entry, bprm);
		ret = 0;
		goto out_put;
	}

	ret = veriexec_digest_verify(bprm->file, entry);
	if (ret)
		goto out_put;

	veriexec_inode_cache(bprm->file->f_path.dentry->d_inode);

	veriexec_binprm_raise(entry, bprm);
	raised = 1;
	ret = 0;
	/* Fall through */
out_put:
	veriexec_entry_put(entry);
out_clear:
	if (!raised && unlikely(VRXF_IS_SCRIPT(bsec->t_flags))) {
		VERIEXEC_WARN("Dropping creds because of unverified "
				"intepreter %s (intersect required)",
				bprm->file->f_path.dentry->d_name.name);
		clear_creds(bprm->cred);
		veriexec_task_clear();
	}
	return ret;
}

/**
 * Verify a library or interpreter, and update the task's credentials.
 *
 * This verifies a file which is being mapped by a veriexec-raised task, and
 * needs to be verified. If verification is impossible (no matching entry) or
 * failed, the caller's capabilities and privileges are cleared, and mapping
 * the file fails. Additionnally, in case of verification failure, the matching
 * entry is cleared from the veriexec cache.
 *
 * @param filp  File to verify.
 * @param check Type of check to perform.
 *
 * @return 0 on success (calling task is unaffected, mapping can continue),
 *         negative error code on failure (calling task's credentials are
 *         cleared, mapping must fail).
 */
int
veriexec_updatecreds(struct file *filp, veriexec_lib_check_t check)
{
	struct veriexec_entry *entry;
	int ret = -ENOENT;

	if (unlikely(check == VeriexecCheckNone)) {
		VERIEXEC_WARN("No check to perform on library");
		return 0;
	}

	if (unlikely(!filp->f_path.dentry)) {
		VERIEXEC_WARN("Invalid file");
		return -EFAULT;
	}

	VERIEXEC_DEBUG2("Updating creds with '%s'\n", filp->f_path.dentry->d_name.name);
	entry = veriexec_lookup_f(filp);
	if (IS_ERR(entry)) {
		VERIEXEC_WARN("Could not find '%s'\n", filp->f_path.dentry->d_name.name);
		ret = PTR_ERR(entry);
		goto out;
	}

	// Check if it is a library or an executable with libcheck activated
	// NEEDS or CHECK
	if (!(VRXF_IS_LIB(entry->ve_flags) ||
		(VRXF_IS_EXE(entry->ve_flags) &&
			(entry->ve_flags & (VRX_FLAG_NEEDLIBS|VRX_FLAG_CHECKLIBS))))) {
		VERIEXEC_WARN("'%s' is not tagged as library (l) or executable"
				" with CHECKLIBS (Le) or NEEDSLIBS (Ne) in"
				" veriexec table\n",
				filp->f_path.dentry->d_name.name);
		ret = -EINVAL;
		goto out_put;
	}

	if (check == VeriexecCheckDigest) {
#ifdef CONFIG_VERIEXEC_CACHE
		if (likely(veriexec_inode_cached(filp->f_path.dentry->d_inode))) {
			VERIEXEC_DEBUG2("Using cached verification for %s\n",
					filp->f_path.dentry->d_name.name);
			ret = 0;
			goto out_put;
		}
#endif
		ret = veriexec_digest_verify(filp, entry);
#ifdef CONFIG_VERIEXEC_CACHE
		if (!ret) {
			VERIEXEC_DEBUG2("Caching verification for %s\n",
					filp->f_path.dentry->d_name.name);
			veriexec_inode_cache(filp->f_path.dentry->d_inode);
		}
#endif
	} else {
		ret = 0;
	}
	/* Fall through */

out_put:
	veriexec_entry_put(entry);
	/* Fall through */
out:
	if (ret) {
		VERIEXEC_WARN("Dropping acquired capabilities because of"
				" unverified %s\n",
				filp->f_path.dentry->d_name.name);

		veriexec_task_clear();
	}
	return ret;
}

/**
 * Check if a dentry corresponds to a privileged binary.
 * A dentry is considered to be privileged if a veriexec entry
 * matches it (in the current context, regardless of current veriexec level)
 * and that entry is of type executable with non-zero caps or 'root-only' privs.
 * @param dentry dentry to check.
 * @return 1 if privileged, 0 otherwise.
 */
int
veriexec_privileged_binary(const struct dentry *dentry)
{
	struct veriexec_entry *entry;
	int ret = 0;

	entry = veriexec_lookup_d(dentry);
	if (likely(IS_ERR(entry)))
		return 0;

	if (!VRXF_IS_EXE(entry->ve_flags))
		goto out_put;

	if (!cap_isclear(entry->ve_caps.v_cap_e) ||
			!cap_isclear(entry->ve_caps.v_cap_p) ||
			!cap_isclear(entry->ve_caps.v_cap_i) ||
			(entry->ve_privs & CLSM_PRIVS_ROOT_MASK))
		ret = 1;

	/* Fall through */
out_put:
	veriexec_entry_put(entry);
	return ret;
}

EXPORT_SYMBOL(veriexec_task_clear);
EXPORT_SYMBOL(veriexec_updatecreds);
EXPORT_SYMBOL(veriexec_getcreds);
EXPORT_SYMBOL(veriexec_privileged_binary);
