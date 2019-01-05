// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file clip_lsm.c
 *  CLIP Linux Security Module
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2009 SGDN/DCSSI
 *  Copyright (C) 2010-2014 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#include <linux/capability.h>
#include <linux/audit.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/security.h>
#include <linux/securebits.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/magic.h>
#include <linux/major.h>
#include <linux/miscdevice.h>
#include <linux/devpts_fs.h>
#include <linux/shmem_fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ptrace.h>
#include <linux/moduleparam.h>
#include <linux/prctl.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/grsecurity.h>
#include <linux/rwsem.h>
#include <linux/ioprio.h>
#include <linux/pid_namespace.h>
#include <linux/lsm_hooks.h>
#include <linux/user_namespace.h>

#ifdef CONFIG_DEVCTL
#include <linux/ima.h>
#endif

/** Yuck, this is not in any header */
#define FUSE_SUPER_MAGIC 0x65735546

/* Note : we do not use int suid_dumpable, which is a sysctl. */
#define _suid_dumpable 0

/**
 * @mainpage CLIP-LSM documentation
 * This is the inline documentation for the CLIP Linux Security Module, which
 * integrates several complementary security controls, specific to the CLIP OS,
 * into the Linux Kernel.
 * @n
 * For an overview of the different subsystems included in CLIP-LSM
 * please browse through the "Modules" section.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 * @see KCCSD inline documentation. KCCSD is a cryptographic Linux module,
 * which provides some of the cryptographic primitives needed by CLIP-LSM.
 */

#ifdef CONFIG_CLSM_FSTRACE_HASH

/**
 * Hash algorithm for FSTRACE hashes.
 */
#define FSTRACE_HASH_ALG	"md5"

/**
 * Size of binary FSTRACE hashes.
 */
#define FSTRACE_DIGEST_SIZE	16

/**
 * Common FSTRACE transform to hash file names.
 */
static struct crypto_hash *fstrace_tfm;

/**
 * Mutex protecting against concurrent accesses to
 * @a fstrace_tfm.
 */
static struct mutex fstrace_mutex;

#endif

#include "clsm.h"
#include "veriexec_sec.h"

#ifdef CONFIG_VSERVER
#include <linux/vs_context.h>
#define IDENT_CTX 	VS_IDENT 	/**< Vserver identity context */
#define ADMIN_CTX	VS_ADMIN	/**< Vserver admin context */
#define WATCH_P_CTX	VS_WATCH_P	/**< Vserver watch context */

#else /* !CONFIG_VSERVER */

#define vx_check(xid, mask) (0)
#define vx_task_xid(p) (1)
#define vx_capable(cap,vcap) capable(cap)

#endif /* !CONFIG_VSERVER */

/*************************************************************/
/*                 standard commoncap.c behaviour            */
/*************************************************************/

/**
 * Helper: the capable() LSM hook no longer takes a task_struct
 * as argument, which makes it problematic to extract the matching
 * vx_info. In most cases, it is asumed that tsk == current, which
 * makes calling the standard hook OK, but we keep this function besides
 * the standard hook for those few cases where we know that tsk != current.
 */
static inline int
clsm_task_capable(const struct task_struct *tsk, const struct cred *cred,
		struct user_namespace *targ_ns, int cap, int audit)
{
	struct vx_info *vxi = tsk->vx_info;
	struct user_namespace *ns = targ_ns;

	/* See if cred has the capability in the target user namespace
	 * by examining the target user namespace and all of the target
	 * user namespace's parents.
	 */
	for (;;) {
		/* Do we have the necessary capabilities? */
		if (ns == cred->user_ns) {
			if (vx_info_flags(vxi, VXF_STATE_SETUP, 0) &&
			    cap_raised(cred->cap_effective, cap))
				return 0;
			return vx_cap_raised(vxi, cred->cap_effective, cap) ?
				0 : -EPERM;
		}

		/* Have we tried all of the parent namespaces? */
		if (ns == &init_user_ns)
			return -EPERM;

		/*
		 * The owner of the user namespace in the parent of the
		 * user namespace has all caps.
		 */
		#if 0 /* Not on CLIP - seems dangerous and I see no
		         point to it at the moment */
		if ((ns->parent == cred->user_ns) && uid_eq(ns->owner, cred->euid))
			return 0;
		#endif

		/*
		 * If you have a capability in a parent user ns, then you have
		 * it over all children user namespaces as well.
		 */
		ns = ns->parent;
	}

	/* We never get here */
}

/**
 * Standard LSM capable hook.
 * It is assumed that the check is made for current.
 */
static int
clsm_capable(const struct cred *cred, struct user_namespace *targ_ns,
			int cap, int audit)
{
	return clsm_task_capable(current, cred, targ_ns, cap, audit);
}

static int
clsm_settime(const struct timespec64 *ts, const struct timezone *tz)
{
	if (!capable(CAP_SYS_TIME))
		return -EPERM;
	return 0;
}

static int
clsm_capget(struct task_struct *target, kernel_cap_t *effective,
		kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	const struct cred *cred;

	rcu_read_lock();
	cred = __task_cred(target);
	*effective = cred->cap_effective;
	*inheritable = cred->cap_inheritable;
	*permitted = cred->cap_permitted;
	rcu_read_unlock();
	return 0;
}

static int
clsm_capset(struct cred *new, const struct cred *old,
		const kernel_cap_t *effective,
		const kernel_cap_t *inheritable,
		const kernel_cap_t *permitted)
{
	if (!cap_issubset(*inheritable,
			cap_combine(old->cap_inheritable, old->cap_permitted))){
		/* incapable of using this inheritable set */
		return -EPERM;
	}
	if (!cap_issubset(*inheritable,
			   cap_combine(old->cap_inheritable,
				       old->cap_bset))) {
		/* no new pI capabilities outside bounding set */
		return -EPERM;
	}

	/* verify restrictions on target's new Permitted set */
	if (!cap_issubset (*permitted, old->cap_permitted)) {
		return -EPERM;
	}

	/* verify the _new_Effective_ is a subset of the _new_Permitted_ */
	if (!cap_issubset (*effective, *permitted)) {
		return -EPERM;
	}

	new->cap_effective = *effective;
	new->cap_inheritable = *inheritable;
	new->cap_permitted = *permitted;

	return 0;
}


static int
clsm_inode_setxattr(struct dentry *dentry, const char *name,
		       const void *value, size_t size, int flags)
{
	if (!strcmp(name, XATTR_NAME_CAPS)) {
		if (!capable(CAP_SETFCAP))
			return -EPERM;
		return 0;
	}

	if (!strncmp(name, XATTR_SECURITY_PREFIX,
		     sizeof(XATTR_SECURITY_PREFIX) - 1)  &&
		!vx_capable(CAP_SYS_ADMIN, VXC_FS_SECURITY))
		return -EPERM;
	return 0;
}

static int
clsm_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (!strcmp(name, XATTR_NAME_CAPS)) {
		if (!capable(CAP_SETFCAP))
			return -EPERM;
		return 0;
	}

	if (!strncmp(name, XATTR_SECURITY_PREFIX,
		     sizeof(XATTR_SECURITY_PREFIX) - 1)  &&
		!vx_capable(CAP_SYS_ADMIN, VXC_FS_SECURITY))
		return -EPERM;
	return 0;
}

static int
clsm_vm_enough_memory(struct mm_struct *mm, long pages)
{
	int cap_sys_admin = 0;

	if (clsm_capable(current_cred(), &init_user_ns,
			CAP_SYS_ADMIN, SECURITY_CAP_NOAUDIT) == 0)
		cap_sys_admin = 1;
	return __vm_enough_memory(mm, pages, cap_sys_admin);
}

static int
clsm_inode_need_killpriv(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = __vfs_getxattr(dentry, inode, XATTR_NAME_CAPS, NULL, 0);
	return error > 0;
}

static int
clsm_inode_killpriv(struct dentry *dentry)
{
	int error;

	error = __vfs_removexattr(dentry, XATTR_NAME_CAPS);
	if (error == -EOPNOTSUPP)
		error = 0;

	return error;
}

/*************************************************************/
/*                 bitmask maps for proc display             */
/*************************************************************/

/** Bitfield map for CLSM privs */
const clsm_bmap_t clsm_priv_map[] = DEFINE_CLSM_PRIV_MAP;
/** Bitfield map for CLSM flags */
const clsm_bmap_t clsm_flag_map[] = DEFINE_CLSM_FLAG_MAP;

/*************************************************************/
/*                 kmem caches for blob allocation           */
/*************************************************************/

/** @name Security tags kmem caches */
/*@{*/

/** @defgroup kmem_caches Kmem caches */
/*@{*/

/**
 * kcache for task security tags.
 * Used for the allocation of struct clsm_task_sec.
 */
static struct kmem_cache *g_tcache = NULL;
/**
 * kcache for file security tags.
 * Used for the allocation of struct clsm_file_sec.
 */
static struct kmem_cache *g_fcache = NULL;
/**
 * kcache for inode security tags.
 * Used for the allocation of struct clsm_inode_sec.
 */
static struct kmem_cache *g_icache = NULL;

/*@}*/
/*@}*/


/*************************************************************/
/*                 reduced root caps helpers                 */
/*************************************************************/

#ifdef CONFIG_CLSM_ROOTCAPS
/** Set default root capabilities */
#define cap_set_root(name) do {\
	(name).cap[0] = clsm_ctl_rootcap0; \
	(name).cap[1] = clsm_ctl_rootcap1; \
} while (0)
/** Reset capabilities to default root set */
#define clsm_reset_rootcaps(new, old, root_uid) \
	clsm_set_rootcaps(new, old, root_uid)
#else /* !CONFIG_CLSM_ROOTCAPS */
#define cap_set_root(cap) cap_set_full(cap)
#define clsm_reset_rootcaps(new, old, root_uid) \
	do {;} while (0)
#endif /* !CONFIG_CLSM_ROOTCAPS */

/** @name Task hooks called on execve() */
/*@{*/

/**
 * Set default capabilities on a new executable.
 * Pretty much the same stuff as commoncap's cap_bprm_set_security,
 * but with no issecure check and only a reduced capability set
 * for uid 0
 * @param new Credentials for the new executable (bprm)
 * @param old Current credentials (exec'ing process)
 * @param root_uid Root uid in the current namespace
 */
static inline void
clsm_set_rootcaps(struct cred *new, const struct cred *old, kuid_t root_uid)
{
	cap_clear(new->cap_effective);
	cap_clear(new->cap_permitted);
	cap_clear(new->cap_inheritable);

	if (uid_eq(new->euid, root_uid) || uid_eq(old->uid, root_uid)) {
		cap_set_root(new->cap_inheritable);
		cap_set_root(new->cap_permitted);
	}
	if (uid_eq(new->euid, root_uid))
		cap_set_root(new->cap_effective);
}

/**
 * Set the inheritable capabilities mask on a new executable.
 * This is basically the inheritable mask of the caller, to which
 * are added the bprm's mask when using a veriexec forced inheritable
 * entry.
 * @param old Parent creds.
 * @param new New creds (i.e. creds as returned by veriexec_getcreds()).
 */
static inline void
clsm_set_inheritable(struct cred *new, const struct cred *old)
{
	struct clsm_task_sec *nsec = new->security;

#ifdef CONFIG_VERIEXEC
	if (unlikely(VRXF_IS_INHERIT(nsec->t_vflags))) {
		new->cap_inheritable = cap_combine(new->cap_inheritable,
							old->cap_inheritable);
		return;
	}
#endif
	new->cap_inheritable = old->cap_inheritable;
}

/*************************************************************/
/*                 binprm sec hooks                          */
/*************************************************************/

/**
 * Helper: get current cap bounding set,
 * from current cred and lsm cap-bound sysctls.
 */
static inline kernel_cap_t
clsm_current_cap_bset(void)
{
	const struct cred *cred = current_cred();

	kernel_cap_t capbound, bset;
	capbound.cap[0] = clsm_ctl_capbound0;
	capbound.cap[1] = clsm_ctl_capbound1;
	bset = cap_intersect(capbound, cred->cap_bset);
	return bset;
}


/**
 * Update task privileges after an exec.
 * This calculates the new task's capabilities from its old caps, and those
 * attributed to the binprm by clsm_bprm_set_security(), and transfers
 * the binprm's security attributes to the new task.
 * @n
 * The capabilities transfer formula is the same as standard (old) commoncap
 * behaviour, with the slight difference that inheritable capabilities
 * do not allow bypassing the context's cap-bound (this is actually implemented
 * in clsm_bprm_set_security()), and that all complementary privileges (those
 * not attributed by default to the caller's uid) are reset if the task is
 * being traced, or in a shared state.
 * @param bprm Newly-loaded binprm.
 * @return 0 on success, negative error code on failure.
 */
static int
clsm_bprm_set_creds(struct linux_binprm *bprm)
{
	const struct cred *old = current_cred();
	struct cred *new = bprm->cred;
	const struct clsm_task_sec *osec = old->security;
	struct clsm_task_sec *nsec = new->security;
	kuid_t root_uid = make_kuid(new->user_ns, 0);

	kernel_cap_t new_permitted, working;
	int ret;

	BUG_ON(!nsec);
	BUG_ON(!osec);

	if (!VRXF_IS_SCRIPT(nsec->t_vflags)) {
		/* Flag / privs reset / propagation, not appropriate
		 * when loading the interpreter for a veriexec-enabled
		 * script.
		 */
		if (osec) {
			nsec->t_flags = osec->t_flags & CLSM_FLAGS_COPY_EXEC1;
			nsec->t_privs = osec->t_privs & CLSM_PRIVS_COPY_EXEC;
			if (osec->t_privs & CLSM_PRIVS_ROOT_MASK)
				nsec->t_flags |= CLSM_FLAG_BUMPED;
	}
#ifdef CONFIG_VERIEXEC
		/* These are set entirely from the veriexec entry */
		nsec->t_vflags = 0;
#endif

		clsm_set_rootcaps(new, old, root_uid);

		if (!current->mm)
			nsec->t_flags |= CLSM_FLAG_KTHREAD;
	}

	ret = veriexec_getcreds(bprm);
	/* Make sure we don't bypass the context's
	 * cap bound through inherited caps */
	new->cap_inheritable = cap_intersect(new->cap_inheritable,
						clsm_current_cap_bset());
	if (ret)
		return ret;


	nsec->t_flags &= CLSM_FLAGS_COPY_EXEC2;

	/* Shared state or currently ptraced : do not give caps over rootcap,
	 * do not give root privs, do not allow forced inheritable,
	 * unless specifically authorized by veriexec flags. */
	if (bprm->unsafe && clsm_flags_raised(nsec->t_flags)) {
		/* kernel runs init under unsafe 1, no big deal */
		if (likely(!is_global_init(current)
		  	&& !VRXF_ALLOW_UNSAFE(nsec->t_vflags))) {
		    CLSM_WARN("attempt to execute raised %s with unsafe %x\n",
			bprm->file->f_path.dentry->d_name.name, bprm->unsafe);
		    clsm_reset_rootcaps(new, old, root_uid);
		    cap_clear(new->cap_inheritable);
		    veriexec_cred_resetopts(new);
		    nsec->t_privs &= ~CLSM_PRIVS_ROOT_MASK;
		    nsec->t_sprivs &= ~CLSM_PRIVS_ROOT_MASK;
		    nsec->t_flags &=
		      ~(CLSM_FLAG_RAISED|CLSM_FLAG_INHERITED|CLSM_FLAG_BUMPED);
		}
	}

	/* This is straight (old) commoncap behaviour */
	new_permitted = cap_intersect(new->cap_permitted,
					clsm_current_cap_bset());
	working = cap_intersect(new->cap_inheritable, old->cap_inheritable);
	new_permitted = cap_combine(new_permitted, working);

	if (!uid_eq(new->euid, old->uid) || !gid_eq(new->egid, old->gid) ||
			!cap_issubset (new_permitted, old->cap_permitted) ||
			clsm_flags_raised(nsec->t_flags)) {
		if (current->mm)
			set_dumpable(current->mm, _suid_dumpable);
		current->pdeath_signal = 0;

		if (bprm->unsafe & ~LSM_UNSAFE_PTRACE_CAP) {
			if (!capable(CAP_SETUID)) {
				new->euid = old->uid;
				new->egid = old->gid;
			}
			if (!capable (CAP_SETPCAP)) {
				new_permitted = cap_intersect (new_permitted,
								old->cap_permitted);
			}
		}
	}

	new->suid = new->fsuid = new->euid;
	new->sgid = new->fsgid = new->egid;

	new->cap_permitted = new_permitted;
	new->cap_effective = cap_intersect(new_permitted, new->cap_effective);
	clsm_set_inheritable(new, old);

	bprm->cap_effective = clsm_cred_raised(new);

	new->securebits &= ~issecure_mask(SECURE_KEEP_CAPS);
	return 0;
}

/**
 * Hook: Check if the execve() resulting process should be linked securely.
 * When this returns an non-zero value, AT_SECURE will be passed to the
 * runtime linker through the auxiliary vector, to disable library
 * interposition and so forth. This is the case when the executable is
 * set{u,g}id (standard commoncap behaviour), or when it was given
 * complementary privileges by the veriexec backend (CLSM-specific).
 * @param bprm Binprm for the newly loaded executable.
 * @return 1 if the process should be linked securely, 0 otherwise.
 */
static int
clsm_bprm_secureexec(struct linux_binprm *bprm)
{
	const struct cred *cred = current_cred();
	const struct clsm_task_sec *sec = cred->security;
	kuid_t root_uid = make_kuid(cred->user_ns, 0);

	if (gr_acl_enable_at_secure())
		return 1;

	if (likely(sec)) {
		if ((sec->t_flags & (CLSM_FLAG_RAISED
				|CLSM_FLAG_BUMPED|CLSM_FLAG_INHERITED)) != 0)
			return 1;
	}

	if (!uid_eq(cred->uid, root_uid)) {
		if (bprm->cap_effective)
			return 1;
		if (!cap_isclear(cred->cap_permitted))
			return 1;
	}

	return (!uid_eq(cred->euid, cred->uid) ||
		!gid_eq(cred->egid, cred->gid));
}

/*@}*/

/*************************************************************/
/*                 task sec hooks                            */
/*************************************************************/

/** @name Task hooks called on fork()/exit() */
/*@{*/

/**
 * Hook: Allocate a new task's security tag.
 * @n
 * If the new task is forked from another one, the parent's security
 * attributes are partially transmitted to the child. This is also
 * where we detect if a new task is (at least initially) a kernel
 * thread.
 * @n <b> Locks and unlocks task_lock for the target task </b>.
 * @param new New credentials.
 * @param old Old credentials.
 * @param gfp Memory allocation atomicity.
 * Note that during this call, @a current still points to the parent task.
 * @return 0 on success, -ENOMEM on error.
 */
static int
clsm_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	const struct clsm_task_sec *osec = old->security;
	struct clsm_task_sec *tsec;

	tsec = kmem_cache_zalloc(g_tcache, gfp);
	if (unlikely(!tsec))
		return -ENOMEM;

	if (osec) {
		/* Propagate flags and clsm privs through clone */
		tsec->t_flags = osec->t_flags & CLSM_FLAGS_COPY_CLONE;
		tsec->t_privs = osec->t_privs & CLSM_PRIVS_COPY_CLONE;
		tsec->t_sprivs = osec->t_sprivs & CLSM_PRIVS_COPY_CLONE;
		if (tsec->t_privs & CLSM_PRIVS_ROOT_MASK)
			tsec->t_flags |= CLSM_FLAG_BUMPED;
		/* Also propagate veriexec options */
		tsec->t_vflags = osec->t_vflags;
	}

	new->security = tsec;
	return 0;
}

/**
 * Hook: Free a task's security tag.
 * Called when the task exits, or is killed with prejudice.
 * @param cred Credentials of the exiting task.
 */
static void
clsm_cred_free(struct cred *cred)
{
	struct clsm_task_sec *tsec = cred->security;

	if (likely(tsec)) {
		cred->security = NULL;
		kmem_cache_free(g_tcache, tsec);
	}
}

#ifndef CONFIG_CLIP_LSM
/**
 * Initiate a task struct's security tag.
 * This is not a LSM hook, but is used to instanciate a security tag for each
 * task when loading CLSM as a module.
 * @n
 * <b> Locks and unlocks task_lock for the target task </b>.
 * @param tsk Task to add a security tag to.
 * @return 0 on success (including 'nop' when the target task already has
 * a security tag, negative error code on failure.
 */
static int
clsm_task_init_security(struct task_struct *tsk)
{
	/* No locking here, we're protected by security_sem anyway */
	struct cred *cred = (void *)__task_cred(tsk);
	struct clsm_task_sec *tsec;

	tsec = kmem_cache_zalloc(g_tcache, GFP_KERNEL);
	if (unlikely(!tsec))
		return -ENOMEM;

	tsec->t_privs |= CLSM_PRIVS_INITIAL;
	tsec->t_flags |= CLSM_FLAG_RAISED|CLSM_FLAG_BUMPED;

	task_lock(tsk);
	if (cred->security) {
		task_unlock(tsk);
		kmem_cache_free(g_tcache, tsec);
	} else {
		cred->security = tsec;
		task_unlock(tsk);
	}

	return 0;
}
#endif

/*@}*/

/** @name Task hooks called on set*uid */
/*@{*/

/**
 * Update privileges when changind uid/euid/suid.
 * Drop all caps if :
 *  @li we change from one unprivileged user to another (unprivileged here
 *  meaning no Xuid == 0, ie joe random user with CAP_SETUID)
 *  @li we change from root to someone else and change *all* uids (i.e.setuid()
 *  to drop all root privs)
 *  @n
 *  That way we keep the expected behavior for root calling seteuid() to
 *  temporarily drop privileges, and properly deal with anyone else that
 *  might have CAP_SETUID - except we do not give them any root capability
 *  when changing to Xuid 0 ... This behaviour is additionnally extended
 *  to CLSM privileges, which are saved to the t_sprivs security tag field
 *  when changing euid from root to non-root (and retaining other uids), and
 *  restored from that same field when changing back to root euid.
 *  @n
 *  The CLSM_PRIV_KEEPPRIV privilege allows keeping one's CLSM privileges
 *  regardless of *uid changes.
 *  @n
 *  Note that this is called after the set*uid, when current->*uid are already
 *  the new IDs.
 *  @param new Credentials after set*uid.
 *  @param old Credentials before set*uid.
 *  @see CLSM_PRIV_KEEPPRIV
 *  @see CLSM_PRIVS_DROP_SETUID
 */

static inline void
clsm_emulate_setxuid(struct cred *new, const struct cred *old)
{
	struct clsm_task_sec *tsec = new->security;
	int keep_privs = tsec->t_privs & CLSM_PRIV_KEEPPRIV;
	kuid_t root_uid = make_kuid(old->user_ns, 0);

	/* Lost all root uids => revoke all privs */
	if ((uid_eq(old->uid, root_uid) ||
			   uid_eq(old->euid, root_uid) ||
			   uid_eq(old->suid, root_uid)) &&
			  (!uid_eq(new->uid, root_uid) &&
			   !uid_eq(new->euid, root_uid) &&
			   !uid_eq(new->suid, root_uid)) &&
			  !issecure(SECURE_KEEP_CAPS)) {
		cap_clear(new->cap_permitted);
		cap_clear(new->cap_effective);

		cap_clear(new->cap_inheritable);
		tsec->t_flags &= ~CLSM_FLAG_INHERITED;

		if (likely(!keep_privs)) {
			tsec->t_privs &= ~CLSM_PRIVS_DROP_SETUID;
			tsec->t_sprivs = 0;
			if (!(tsec->t_privs & CLSM_PRIVS_ROOT_MASK))
				tsec->t_flags &= ~CLSM_FLAG_BUMPED;
		}
		tsec->t_flags &= ~CLSM_FLAGS_DROP_SETUID;
	}

	/* Lost root euid => revoke effective privs */
	if (uid_eq(old->euid, root_uid) && !uid_eq(new->euid, root_uid)) {
		cap_clear(new->cap_effective);
		if (likely(!keep_privs)) {
			/* Save root clsm privs, keep BUMPED flag */
			tsec->t_sprivs = tsec->t_privs
					& CLSM_PRIVS_DROP_SETUID;
			tsec->t_privs &= ~CLSM_PRIVS_DROP_SETUID;
		}
		if (cap_isclear(new->cap_permitted) &&
				cap_isclear(new->cap_inheritable)) {
			tsec->t_flags &= ~CLSM_FLAG_RAISED;
		}
	}

	/* Regain root euid => restore permitted privs */
	if (!uid_eq(old->euid, root_uid) && uid_eq(new->euid, root_uid)) {
		/* Reestablish root privileges, if any */
		new->cap_effective = new->cap_permitted;
		if (likely(!keep_privs)) {
			tsec->t_privs |= tsec->t_sprivs;
			tsec->t_sprivs = 0;
		}
		/* TODO CLSM_FLAG_RAISED ? */
	}
}

/**
 * Hook: Update a tasks privileges after an uid change.
 * uid/suid/ruid changes are handled by the clsm_emulate_setxuid() helper.
 * fsuid changes are handled in a standard Linux way : changing to fsuid !0
 * removes all filesystem-related capabilities, changing to fsuid 0 gives
 * them back.
 *  @param new The proposed credentials.
 *  @param old The current task's current credentials
 *  @param flags Type of set*uid operation.
 *  @see clsm_emulate_setxuid().
 *  @return 0 on success, -EINVAL on failure (only caused by invalid flags).
 */
static int
clsm_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	kuid_t root_uid = make_kuid(old->user_ns, 0);
	switch (flags) {
		case LSM_SETID_RE:
		case LSM_SETID_ID:
		case LSM_SETID_RES:
			clsm_emulate_setxuid(new, old);
			break;
		case LSM_SETID_FS:
			if (uid_eq(old->fsuid, root_uid)
					&& !uid_eq(new->fsuid, root_uid)) {
				cap_drop_fs_set(new->cap_effective);
			}
			if (!uid_eq(old->fsuid, root_uid)
					&& uid_eq(new->fsuid, root_uid)) {
				cap_raise_fs_set(new->cap_effective,
						new->cap_permitted);
			}
			break;
		default:
			return -EINVAL;
	}
	return 0;
}

/*@}*/

/** @name Task hooks called on priority change */
/*@{*/

/**
 * Common helper for all priority-related hooks.
 * Allow a raised task with CAP_SYS_NICE to change the priority for any other
 * task, even raised ones. Allow a non-raised task with CAP_SYS_NICE to change
 * the priority for any non-raised task.
 * @n Otherwise, compare capabilities (permitted and inheritable)
 * @param p Task whose priority is to be changed. Could be different or equal
 * to current.
 * @return 0 if access is authorized, negative error code if it is denied.
 */

static inline int
do_task_prio(struct task_struct *p)
{
	int subset_p1, subset_p2;

	rcu_read_lock();
	if (ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE) &&
			(!clsm_cred_raised(__task_cred(p)) ||
				clsm_cred_capraised(current_cred()))) {
		rcu_read_unlock();
		return 0;
	}

	subset_p1 = cap_issubset(__task_cred(p)->cap_permitted,
					current_cred()->cap_effective);
	subset_p2 = cap_issubset(__task_cred(p)->cap_inheritable,
					current_cred()->cap_inheritable);
	rcu_read_unlock();

	if (!(subset_p1 && subset_p2))
		return -EPERM;

	return 0;
}

/**
 * Hook: check authorization to change a task's scheduling policy
 * or parameters.
 * @param p Affected task.
 * @param policy Scheduling policy (ignored).
 * @param lp Scheduling parameters (ignored).
 * @return 0 if access is authorized, negative error code if it is denied.
 */
static int
clsm_task_setscheduler(struct task_struct *p)
{
	int ret = do_task_prio(p);
	if (unlikely(ret))
		CLSM_WARN_COMM("denied setting scheduler\n");
	return ret;
}

/**
 * Hook: check authorization to change a task's nice level.
 * @param p Affected task.
 * @param nice New nice level (ignored).
 * @return 0 if access is authorized, negative error code if it is denied.
 */
static int
clsm_task_setnice(struct task_struct *p, int nice)
{
	int ret = do_task_prio(p);
	if (unlikely(ret))
		CLSM_WARN_COMM("denied setting nice\n");
	return ret;
}

/**
 * Hook: check authorization to change a task's IO priority.
 * @param p Affected task.
 * @param ioprio New IO priority.
 * @return 0 if access is authorized, negative error code if it is denied.
 */
static int
clsm_task_setioprio(struct task_struct *p, int ioprio)
{
	int ret;

	/* Allow self setting to IDLE */
	if (p == current && IOPRIO_PRIO_CLASS(ioprio) == IOPRIO_CLASS_IDLE)
		return 0;

	ret = do_task_prio(p);
	if (unlikely(ret))
		CLSM_WARN_COMM("denied setting ioprio\n");
	return ret;
}

/*@}*/

/** @name Other task hooks */
/*@{*/

/**
 * Hook: Check permission before sending a signal to a task.
 * Allow a raised task with CAP_KILL to send a signal to any other other
 * task in the same security context, raised or not. Allow a non-raised
 * task with CAP_KILL to send a signal to any other non-raised task in
 * the same context. Otherwise check caps.
 * @n Only allow @a init to send a signal, or a process with CAP_SYS_BOOT
 * in its inheritable mask, to signal a CLSM_PRIV_IMMORTAL process.
 * @n We also do the security context check in here (moved from kernel/signal.c)
 * so that we can test for CLSM_PRIV_SIGUSR.
 * @param p Target task.
 * @param sig Signal number.
 * @param info Signal information.
 * @param secid Security ID (ignored).
 * @return 0 if access is authorized, negative error code if it is denied.
 * @see CLSM_PRIV_SIGUSR
 * @see CLSM_PRIV_RECVSIG
 * @see CLSM_PRIV_IMMORTAL
 */
static int
clsm_task_kill(struct task_struct *p, struct siginfo *info, int sig, u32 secid)
{
	const struct cred *pcred = get_task_cred(p);
	const struct clsm_task_sec *psec = pcred->security;
	const struct cred *cred = current_cred();
	const struct clsm_task_sec *tsec = cred->security;

	if (info != SEND_SIG_NOINFO
			&& (info <= SEND_SIG_FORCED || SI_FROMKERNEL(info)))
		return 0;
	/* secid: not used - only sent by kernel itself, and we accept all
	 * signals sent by kernel anyway */

	/* Init can kill processes in any context, but we still perform a
	 * capability check (which should be ok, since init was probably
	 * started with all caps). */
	if (is_global_init(current))
		goto captest;

	/* 'immortal' processes can only be signaled by tasks with CAP_SYS_BOOT
	 * in their inheritable set */
	if (unlikely(psec->t_privs & CLSM_PRIV_IMMORTAL)) {
		if (!cap_raised(cred->cap_inheritable, CAP_SYS_BOOT))
			return -EPERM;
	}

	if (!vx_check(vx_task_xid(p), VS_ADMIN|VS_WATCH_P|VS_IDENT)) {
		if (unlikely((vx_task_xid(p) == 0) &&
				(tsec->t_privs & CLSM_PRIV_SIGUSR) &&
				(psec->t_privs & CLSM_PRIV_RECVSIG))) {
			switch (sig) {
				case SIGUSR1:
				case SIGUSR2:
					break;
				default:
					goto out_perm;
			}
		} else {
			goto out_srch;
		}
	}

captest:
	if (ns_capable(pcred->user_ns, CAP_KILL) &&
			(!clsm_cred_raised(pcred)
				|| clsm_cred_capraised(current_cred())))
		return 0;

	if (!cap_issubset(pcred->cap_permitted, cred->cap_effective))
		goto out_perm;
	if (!cap_issubset(pcred->cap_inheritable, cred->cap_inheritable))
		goto out_perm;

	put_cred(pcred);
	return 0;

out_perm:
	put_cred(pcred);
	CLSM_INFO_COMM("denied sending signal %i\n", sig);
	return -EPERM;
out_srch:
	put_cred(pcred);
	CLSM_INFO_COMM("denied sending signal %i over context boundaries\n",
				sig);
	return -ESRCH;
}

/**
 * Hook: Check permission before performing a prctl operation.
 * This is only used to disable the PR_SET_DUMPABLE prctl.
 * @param option Requested prctl operation.
 * @param arg2 Possible argument (ignored)
 * @param arg3 Possible argument (ignored)
 * @param arg4 Possible argument (ignored)
 * @param arg5 Possible argument (ignored)
 * @return 0 if access is authorized, negative error code if it is denied.
 */
static int
clsm_task_prctl(int option, unsigned long arg2,
		unsigned long arg3, unsigned long arg4,
		unsigned long arg5)
{
	long error = 0;

	struct cred *cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	switch (option) {
		case PR_CAPBSET_READ:
			if (!cap_valid(arg2))
				error = -EINVAL;
			else
				error = !!cap_raised(cred->cap_bset, arg2);
			goto no_change;

		case PR_CAPBSET_DROP:
			/* Unlike the vanilla file caps implementation, we do
			 * not require CAP_SETPCAP, but CAP_SYS_ADMIN, to drop
			 * the bset */
			if (!ns_capable(current_user_ns(), CAP_SYS_ADMIN)) {
				error = -EPERM;
				CLSM_WARN_COMM("Denied CAPBSET_DROP - "
							"insufficient privs");
				goto error;
			}
			if (!cap_valid(arg2)) {
				error = -EINVAL;
				goto error;
			}
			cap_lower(cred->cap_bset, arg2);
			error = 0;
			goto changed;

		case PR_SET_SECUREBITS:
			error = -EPERM;
			if ((((cred->securebits & SECURE_ALL_LOCKS) >> 1)
			     & (cred->securebits ^ arg2))			/*[1]*/
			    || ((cred->securebits & SECURE_ALL_LOCKS & ~arg2))	/*[2]*/
			    || (arg2 & ~(SECURE_ALL_LOCKS | SECURE_ALL_BITS))	/*[3]*/
			    || (clsm_capable(current_cred(),
					current_cred()->user_ns,
					CAP_SETPCAP, SECURITY_CAP_AUDIT) != 0)  /*[4]*/
				/*
				 * [1] no changing of bits that are locked
				 * [2] no unlocking of locks
				 * [3] no setting of unsupported bits
				 * [4] doing anything requires privilege (go read about
				 *     the "sendmail capabilities bug")
				 */
			    )
				/* cannot change a locked bit */
				goto error;
			cred->securebits = arg2;
			goto changed;

		case PR_GET_SECUREBITS:
			error = cred->securebits;
			goto no_change;

		case PR_GET_KEEPCAPS:
			if (issecure(SECURE_KEEP_CAPS))
				error = 1;
			goto no_change;

		case PR_SET_KEEPCAPS:
			error = -EINVAL;
			/* Note, we rely on arg2 being unsigned here */
			if (arg2 > 1)
				goto error;
			error = -EPERM;
			if (issecure(SECURE_KEEP_CAPS_LOCKED))
				goto error;
			if (arg2)
				cred->securebits |=
					issecure_mask(SECURE_KEEP_CAPS);
			else
				cred->securebits &=
					~issecure_mask(SECURE_KEEP_CAPS);
			goto changed;

		case PR_SET_DUMPABLE:
			/* Do not allow a raised process to be made dumpable, but
			 * allow it to be made 'undumpable' (which it is in any
			 * case).
			 */
			if ((arg2 != SUID_DUMP_DISABLE)
					&& clsm_cred_raised(cred)) {
				CLSM_WARN_COMM("Denied setting raised "
								"task dumpable");
				error = -EPERM;
			} else {
				/* Return -ENOSYS so sys.c:prctl() will do the
				 * rest of the work for us.
				 */
				error = -ENOSYS;
			}
			goto no_change;
		default:
			/* No functionality available in security hook */
			error = -ENOSYS;
			goto error;
	}

changed:
	return commit_creds(cred);

no_change:
error:
	abort_creds(cred);
	return error;
}

#ifdef CONFIG_VSERVER
/**
 * Hook: called before migrating a task into a new vserver context.
 * Returns the new task credentials to be applied after migration.
 * This function clears the inheritable capability mask of the
 * migrating task, and applies the appropriate CLSM flags and privs
 * restrictions.
 * @n Not an original LSM hook.
 * @param tsk Task to migrate. This should be equal to current, otherwise
 * an error will be raised.
 * @return New credentials (to be commited after migration) in case of success,
 * error pointer otherwise.
 */
static struct cred *
clsm_task_ctx_migrate(struct task_struct *tsk)
{
	struct clsm_task_sec *tsec;
	struct cred *cred;

	if (tsk != current) {
		CLSM_WARN_COMM("Attempting to migrate another task, aborted");
		return ERR_PTR(-EFAULT);
	}

	cred = prepare_creds();
	if (!cred)
		return ERR_PTR(-ENOMEM);

	tsec = cred->security;

	cap_clear(cred->cap_inheritable);
	if (likely(!(tsec->t_privs & CLSM_PRIV_KEEPPRIV))) {
		tsec->t_privs &= ~CLSM_PRIVS_DROP_CHCTX;
		if (!(tsec->t_privs & CLSM_PRIVS_ROOT_MASK))
			tsec->t_flags &= ~CLSM_FLAG_BUMPED;
	}
	tsec->t_flags &= ~CLSM_FLAGS_DROP_CHCTX;
	tsec->t_flags |= CLSM_FLAG_MIGRATED;

	return cred;
}

/**
 * Test if the current task has migrated into a vserver context, and not execve()d
 * since then.
 * @n Not an original LSM hook.
 * @return 1 if task has migrated, 0 otherwise.
 */
static int
clsm_task_ctx_migrated(void)
{
	const struct clsm_task_sec *tsec = current_cred()->security;

	return (tsec->t_flags & CLSM_FLAG_MIGRATED);
}

/**
 * Test if a task from a non-ADMIN vserver context is allowed to send a signal
 * (SIGUSR*) out of its context.
 * Note that this does not intrinsincally check the signal number, that part is
 * done by the task_kill() hook.
 * @n Not an original LSM hook.
 * @param p Task_struct for the task sending the signal.
 * @param c Task_struct for the signal target.
 * @param sig Signal number.
 * @return 0 if sending is allowed, -EPERM if it is not.
 * @see clsm_task_kill()
 */
static int
clsm_task_kill_vserver(struct task_struct *p, struct task_struct *c, int sig)
{
	const struct clsm_task_sec *psec;
	int ok;

	switch (sig) {
		case SIGUSR1:
		case SIGUSR2:
			break;
		default:
			goto out_perm;
	}

	rcu_read_lock();
	psec = __task_cred(p)->security;
	ok = (psec->t_privs & CLSM_PRIV_SIGUSR);
	rcu_read_unlock();

	if (unlikely(ok))
		return 0;

out_perm:
	CLSM_LOG_COMM_T(KERN_WARNING, p, "blocked signal sending to another context");
	return -EPERM;
}
#endif /* CONFIG_VSERVER */

#ifdef CONFIG_CLSM_CHROOT_OPENDIRS
/**
 * Check for open directories before a chroot.
 * This helper is called by clsm_task_chroot() before a chroot() treatment.
 * It goes through the caller's fd table, looking for an open directory
 * descriptor. If one is found, the access is denied.
 * @param tsk Chrooting task.
 * @return 0 if no open directories where found, -EPERM otherwise.
 */
static inline int
clsm_chroot_handle_opendirs(struct task_struct *tsk)
{
	struct fdtable *fdt;
	int i;
	struct files_struct *files = tsk->files;
	int ret = -EPERM;

	rcu_read_lock();
	fdt = files_fdtable(files);
	for (i = 0; i < fdt->max_fds; i++) {
		if (!test_bit(i, fdt->open_fds))
			continue;
		if (S_ISDIR((fdt->fd[i])->f_path.dentry->d_inode->i_mode))
			goto out;
	}

	ret = 0;
out:
	rcu_read_unlock();
	return ret;
}
#endif /* CONFIG_CLSM_CHROOT_OPENDIRS */

/**
 * Hook: Called before chrooting a task.
 * This function checks for open directories before a chroot,
 * and adds the CLSM_FLAG_CHROOTED flag to the caller. Note that
 * this is last check before the effective chroot, so chrooting cannot
 * fail once CLSM_FLAG_CHROOTED is attributed.
 * @n The CLSM_PRIV_CHROOT privilege allows bypassing the open directories
 * check.
 * @n This is not an original LSM hook.
 * @return 0 if access is authorized, negative error code on error or
 * permission denied.
 * @see clsm_chroot_handle_opendirs()
 * @see CLSM_PRIV_CHROOT
 * @see CLSM_FLAG_CHROOTED
 */
static int
clsm_task_chroot(void)
{
	struct cred *cred = NULL;
	struct clsm_task_sec *tsec;
	int ret = 0;

	/* Init calls chroot on startup, that
	 * doesn't mean every task is chrooted */
	if (is_global_init(current))
		return 0;

	cred = prepare_creds();
	if (!cred) {
		ret = -ENOMEM;
		goto err;
	}

	tsec = cred->security;

	if (tsec && (tsec->t_privs & CLSM_PRIV_CHROOT))
		goto skip_checks;

#ifdef CONFIG_CLSM_CHROOT_OPENDIRS
	if (clsm_ctl_chroot) {
		ret = clsm_chroot_handle_opendirs(current);
		if (ret) {
			CLSM_LOG_COMM_T(KERN_WARNING, current, "blocked chroot "
				"because of open directories\n");
			goto err;
		}
	}
#endif /* CONFIG_CLSM_CHROOT_OPENDIRS */

skip_checks:
	tsec->t_flags |= CLSM_FLAG_CHROOTED;
	return commit_creds(cred);

err:
	if (cred)
		abort_creds(cred);
	return ret;
}

/**
 * Test if current task is chrooted.
 * CLSM_PRIV_CHROOT means a task is not considered chrooted.
 * @param tsk Task to check.
 * @return 1 if task is chrooted, 0 if it isn't.
 * @see CLSM_PRIV_CHROOT.
 */
static int
clsm_task_chrooted(const struct task_struct *tsk)
{
	const struct clsm_task_sec *tsec;
	int ret;


	rcu_read_lock();
	tsec = __task_cred(tsk)->security;

	ret = (tsec->t_flags & CLSM_FLAG_CHROOTED &&
			!tsec->t_privs & CLSM_PRIV_CHROOT);

	rcu_read_unlock();
	return ret;
}

/**
 * Hook: check permission before allowing a task to unshare
 * its namespaces (through either clone() or unshare()).
 * @n This is not an original LSM hook.
 * @param flags Bitmask of namespaces (CLONE_NEWNS, etc.) to unshare.
 * @return 0 if new adjust is allowed, -EPERM otherwise.
 */
static int
clsm_task_unshare_ns(unsigned long flags)
{
	const struct clsm_task_sec *tsec = current_cred()->security;
#ifdef CONFIG_VSERVER
	if (vx_can_unshare(CAP_SYS_ADMIN, flags))
		return 0;
#else
	if (capable(CAP_SYS_ADMIN))
		return 0;
#endif
	if (tsec->t_privs & CLSM_PRIV_UNSHARE)
		return 0;

	CLSM_WARN_COMM("denied namespace unsharing (flags 0x%lx)", flags);
	return -EPERM;
}

/**
 * Hook: adjust task 'badness' for the Out-Of-Memory killer.
 * The tasks badness is divided by the result of this function.
 * @n This is not an original LSM hook.
 * @param tsk Task to adjust badness for.
 * @return 16 for tasks with CLSM_PRIV_IMMORTAL, 1 otherwise.
 * @see CLSM_PRIV_IMMORTAL
 */
static unsigned long
clsm_task_badness(const struct task_struct *tsk)
{
	unsigned long ret;

	const struct clsm_task_sec *tsec;

	rcu_read_lock();
	tsec = __task_cred(tsk)->security;
	if (unlikely(tsec->t_privs & CLSM_PRIV_IMMORTAL))
		ret = 16UL;
	else
		ret = 1UL;
	rcu_read_unlock();

	return ret;
}

/**
 * Hook: check permissions before adjusting a task's badness.
 *
 * Protects IMMORTAL tasks against badness raise.
 *
 * @n This is not an original LSM hook.
 * @param tsk Task being adjusted.
 * @param adj New adjust value.
 *
 * @return 0 if new adjust is allowed,
 *         -EPERM otherwise.
 *
 * @see CLSM_PRIV_IMMORTAL
 * @note Called with tsk's sighand locked.
 */
static int
clsm_task_oomadj(const struct task_struct *tsk, int adj)
{
	const struct clsm_task_sec *tsec;
	int ret;
	int curval = tsk->signal->oom_score_adj;
	int floor = tsk->signal->oom_score_adj_min;

#ifdef CONFIG_VSERVER
	if (adj < floor && !vx_capable(CAP_SYS_RESOURCE, VXC_OOM_ADJUST))
		return -EPERM;
#else
	if (adj < floor && !capable(CAP_SYS_RESOURCE))
		return -EPERM;
#endif
	rcu_read_lock();
	tsec = __task_cred(tsk)->security;
	ret = ((tsec->t_privs & CLSM_PRIV_IMMORTAL) && adj > curval);
	rcu_read_unlock();

	if (unlikely(ret)) {
		CLSM_WARN_COMM("denied raising oom kill adjust on IMMORTAL task\n");
		return -EPERM;
	}
	return 0;
}

/**
 * Hook: display supplementary info about a task in its
 * /proc/[pid]/status file.
 * @n This is not an original LSM hook.
 * @param tsk Task for which info needs to be displayed.
 * @param buffer Pointer to the output buffer.
 * @param len Maximum writable length in @a buffer.
 */
static void
clsm_task_proc_pid(struct seq_file *m, struct task_struct *tsk)
{
	const struct cred *cred = get_task_cred(tsk);
	const struct clsm_task_sec *tsec = cred->security;

	if (tsec) {
		char tmp[16];
		clsm_format_bitmask(tmp, sizeof(tmp),
					tsec->t_privs, clsm_priv_map);
		(void)seq_printf(m, "clsm privs: %s\n", tmp);

		clsm_format_bitmask(tmp, sizeof(tmp),
					tsec->t_flags, clsm_flag_map);
		(void)seq_printf(m, "clsm flags: %s\n", tmp);

#ifdef CONFIG_VERIEXEC
		clsm_format_bitmask(tmp, sizeof(tmp),
					tsec->t_vflags, veriexec_flag_map);
		(void)seq_printf(m, "veriexec flags: %s\n", tmp);
#endif
	}

	put_cred(cred);
}

/**
 * Check if access to /proc/[pid]/{fd,maps} may be allowed without
 * CAP_SYS_PTRACE.
 * This is only called when trying to access the proc files for a process
 * running under another identity.
 * @n
 * @n <b> Called with current->task_lock held </b>
 * @n
 * Not an original LSM hook.
 * @param c Task struct for the task whose fds are being accessed
 * @param log Non-zero if denied accesses should be logged.
 * @return 1 if allowed, 0 if not.
 */
static int
clsm_task_procfd(struct task_struct *c, int log)
{
	const struct clsm_task_sec *tsec = current_cred()->security;

	if (tsec->t_privs & CLSM_PRIV_PROCFD)
		return 1;
	if (log)
		CLSM_LOG_COMM_NOLOCK_T(KERN_WARNING, c, "denied procfd access\n");
	return 0;
}


static int
clsm_ptrace(struct task_struct *parent, struct task_struct *child, int log)
{
	const struct cred *pcred, *ccred;
	const struct clsm_task_sec *psec, *csec;
	clsm_privs_t cprivs;
	int subset_p1, subset_p2, subset_p3;
	int ret = -EPERM;

	rcu_read_lock();

	pcred = __task_cred(parent);
	ccred = __task_cred(child);
	psec = pcred->security;
	csec = ccred->security;

#ifdef CONFIG_CLSM_CHROOT_PTRACE
	if (clsm_ctl_chroot && (psec->t_flags & CLSM_FLAG_CHROOTED))
		goto out;
#endif /* CONFIG_CLSM_CHROOT_PTRACE */

	if (has_ns_capability(parent, ccred->user_ns, CAP_SYS_PTRACE)
						&& !clsm_cred_raised(ccred)) {
		ret = 0;
		goto out;
	}

	if (pcred->user_ns == ccred->user_ns) {
		subset_p1 = cap_issubset(ccred->cap_permitted,
						pcred->cap_effective);
		subset_p2 = cap_issubset(ccred->cap_inheritable,
						pcred->cap_inheritable);
		/* Test 'heavy' privs as well */
		cprivs = csec->t_privs & CLSM_PRIVS_ROOT_MASK;
		subset_p3 = ((psec->t_privs & cprivs) == cprivs);

		if (subset_p1 && subset_p2 && subset_p3)
			ret = 0;
	}
	/* Fall through */
out:
	rcu_read_unlock();
	if (ret && log)
		CLSM_LOG_COMM_NOLOCK_T(KERN_WARNING,
						parent, "denied ptrace\n");
	return ret;
}

static int
clsm_ptrace_traceme(struct task_struct *parent)
{
	return clsm_ptrace(parent, current, 1);
}

/**
 * Hook: Check permissions before a ptrace attach.
 * Also called before allowing a task access to another task's
 * /proc/[pid]/fd/[..] and /proc/[pid]/environment files.
 * This follows a different logic than KILL/priority hooks. We never
 * allow a task to gain 'capraised' privileges through tracing, even
 * when it has CAP_SYS_PTRACE. Hence, even a capable task, when
 * trying to trace a capraised child, must pass the cap_issubset checks.
 * @n
 * Note that this makes debugging a lot harder, unless you give
 * every damn capability to strace/gdb/etc. :)
 * @n <b> Called with current->task_lock held </b>
 * @param parent Parent task (doing the ptrace attach).
 * @param child Child task (target of the ptrace attach).
 * @return 0 if access is authorized, negative error code if it is denied.
 */

static int
clsm_ptrace_access_check(struct task_struct *child, unsigned int mode)
{
	int log;
	const struct clsm_task_sec *psec = current_cred()->security;
	if ((mode & PTRACE_MODE_PROCFD) && (psec->t_privs & CLSM_PRIV_PROCFD))
		return 0;

	log = (mode & PTRACE_MODE_NOAUDIT) ? 0 : 1;
	return clsm_ptrace(current, child, log);
}


/*@}*/

/*************************************************************/
/*                 file sec hooks                            */
/*************************************************************/

/** @name Miscellaneous file hooks */
/*@{*/

/**
 * Hook: free a task's security tag.
 * Called when freeing the file struct.
 * Note that allocation of the tag is not done systematically when allocating
 * a file, but is instead done on a as-needed basis, by alloc_or_test_fsec().
 * Therefore, most files won't have an attached security tag, and this
 * function must check the tags presence before attempting to free it.
 * @param filp File whose security tag must be freed.
 * @see alloc_or_test_fsec()
 */
static void
clsm_file_free_security(struct file *filp)
{
	if (unlikely(filp->f_security))
		kmem_cache_free(g_fcache, filp->f_security);
}

/**
 * Hook: check permission before allowing a swapon() operation.
 * Note than CAP_SYS_ADMIN is checked by the caller.
 * When CLSM_MOUNT is defined, we simply forbid any swap creation
 * once clsm_ctl_mount has been activated.
 * @n Not an original LSM hook.
 * @param filp File backing the swap.
 * @param name Path of the file backing the swap.
 * @return 0 if authorized, -EPERM if not.
 */
static int
clsm_file_swapon(struct file *filp, const char *name)
{
#ifdef CONFIG_CLSM_MOUNT
	if (clsm_ctl_mount) {
		CLSM_WARN_COMM("denied swap creation on file %s\n", name);
		return -EPERM;
	}
#endif
	return 0;
}

/**
 * Hook: check permission before accessing /dev/{mem,kmem,ports}.
 * @param filp file to be accessed.
 * @param op operation to be performed.
 * @return 0 if authorized, -EPERM if not.
 */
static int
clsm_mem_access(struct file *filp, int op)
{
	const struct clsm_task_sec *tsec = current_cred()->security;

	if (unlikely(tsec->t_privs & CLSM_PRIV_DRM)) {
		/* DRM master is authorized to open and mmap /dev/mem => should
		 * then be controlled by GRKERNSEC_KMEM */
		switch (op) {
			case SECURITY_MEM_OPEN:
			case SECURITY_MEM_MMAP:
				return 0;
		}
	}

	switch (op) {
		/* Allow tasks that already hold an open handle on the file
		 * (because they were started up before CLSM was loaded to keep
		 * accessing the file for read / write / map operations, as
		 * long as they hold CAP_SYS_RAWIO - which they should if they
		 * were started before CLSM. */
		case SECURITY_MEM_READ:
		case SECURITY_MEM_WRITE:
		case SECURITY_MEM_MMAP:
		case SECURITY_IO_IOPL:
		case SECURITY_IO_IOPERM:
			if (capable(CAP_SYS_RAWIO))
				return 0;
	}

	/* Otherwise, no access - in particular, opening any of those files is
	 * impossible once the LSM is registered. */
	CLSM_WARN_COMM("denied memory access (type 0x%x)", op);
	return -EPERM;
}

/**
 * Hook : check permission before allowing a DRM_ROOT privileged ioctl.
 * @param flags IOCTL flags.
 * @return 0 if authorized, -EPERM if not.
 */
static int
clsm_drm_access(int flags)
{
	const struct clsm_task_sec *tsec = current_cred()->security;

	if (likely(tsec->t_privs & CLSM_PRIV_DRM))
		return 0;

	if (likely(capable(CAP_SYS_ADMIN)))
		return 0;

	CLSM_WARN_COMM("denied drm access (pid %d, flags 0x%x)",
			task_pid_nr(current), flags);
	return -EPERM;
}

/*@}*/

/** @name File mapping hooks */
/*@{*/

#ifdef CONFIG_VERIEXEC

/**
 * Hook: check permissions before converting a file handle to a path.
 * This simply limits access to file handle conversion to the ADMIN
 * vserver context. This comes on top of vanilla kernel requiring
 * CAP_DAC_READ_SEARCH for any such conversion.
 * Not an original LSM hook.
 * @param dirfd Fd for the mount directory to use for conversion.
 * @param handle File handle to convert.
 * @return 0 if authorized, -EPERM if not.
 */
static int
clsm_fhandle_to_path(int dirfd, struct file_handle *handle)
{
	if (vx_check(0, VS_ADMIN))
		return 0;

	return -EPERM;
}

/**
 * Hook: called before creating a PROT_EXEC non-anonymous mapping, either
 * through mmap() or mprotect().
 * This is called just before the fs-specific mapping call is performed, to
 * check possible veriexec constraints on the file, and update the caller's
 * credentials accordingly. If a veriexec check is performed on the file,
 * writes are automatically disabled on that file before checking, and
 * won't be re-enabled until the mapping is destroyed (we could probably
 * re-enable writes if PROT_EXEC is dropped at some point before destroying
 * the mapping, but that seems too much trouble for too few actual use cases).
 * @n Not an original LSM hook, since we need to call this hook as close as
 * possible to the actual mmap/mprotect operation, to be able to deny writing
 * if needed.
 * @n <b>Called with mmap_sem held.</b>
 * @param file Source file for the requested mapping (guaranteed non-NULL
 * by the caller).
 * @return 0 if mmap() is authorized, negative error code if denied or
 * in case of error.
 * @see clsm_file_mmap()
 */
static int
clsm_file_map_exec(struct vm_area_struct *vma)
{
	int ret;
	veriexec_lib_check_t check = veriexec_task_checklibs(current);
	if (likely(check == VeriexecCheckNone))
		return 0;

	/* If we need to check the library, deny any writes to
	 * it before checking (if not already done)
	 */
	if (!(vma->vm_flags & VM_DENYWRITE)) {
		ret = deny_write_access(vma->vm_file);
		if (ret) {
			CLSM_WARN_COMM("failed to deny writes to library");
			return ret;
		}
		vma->vm_flags |= VM_DENYWRITE;
	}
	ret = veriexec_updatecreds(vma->vm_file, check);
	if (ret)
		CLSM_WARN_COMM("denied PROT_EXEC mapping");
	return ret;
}

/**
 * Hook: check permissions for a mmap operation at a given address.
 * We simply enforce the DAC min_addr restriction, with no exceptions.
 * @param addr Start address of the proposed mapping.
 * @return 0 if access is authorized, negative error code if it is denied.
 */
static int
clsm_mmap_addr(unsigned long addr)
{
	if (unlikely((addr < dac_mmap_min_addr))) {
		CLSM_WARN_COMM("denied mmap under min address");
		return -EPERM;
	}

	return 0;
}

/**
 * Hook: check permissions for a mmap operation from a given file.
 * The most significant mmap() checks are permformed by an non-LSM hook,
 * clsm_file_map_exec(), which checks executable mappings after
 * writes to the underlying file are denied.
 * This LSM hook, which is called before denying writes to the
 * possible underlying file, is retained to deal with non-file-backed
 * executable mappings, and to check permissions on executable
 * file-backed-mappings, to avoid a possible DoS through MAP_DENYWRITE.
 * @n
 * Anonymous mappings are denied altogether for 'checklibs' task, since
 * there is no way to prevent write access to a MAP_SHARED|MAP_ANONYMOUS
 * mapping
 * @n
 * File-backed executable mappings are only allowed when one has
 * exec permission on the underlying file.
 * @n <b>Called with mmap_sem held.</b>
 * @param file File to map (may be null).
 * @param reqprot Protection requested by the application (ignored).
 * @param prot Actual protection that will be applied by the kernel
 * (with, possibly, flags added to the original @a reqprot, e.g. PROT_EXEC).
 * @param flags Operational flags (ignored).
 * @return 0 if access is authorized, negative error code if it is denied.
 * @see clsm_file_map_exec()
 */

static int
clsm_mmap_file(struct file * file, unsigned long reqprot,
                          unsigned long prot, unsigned long flags)
{
	if (likely(file)) {
		if (!(prot & PROT_EXEC))
			return 0;
		if (unlikely(inode_permission(file->f_path.dentry->d_inode,
								MAY_EXEC))) {
			CLSM_WARN_COMM("denied PROT_EXEC mapping: "
					"no exec permission on file %s\n",
					file->f_path.dentry->d_name.name);
			return -EPERM;
		}
		/* Else leave the rest to clsm_file_map_exec() */
		return 0;
	}

	/* Anonymous mapping */
	if (likely(!veriexec_task_checklibs(current)))
		return 0;

	if (likely(!(prot & PROT_EXEC)))
		return 0;

	CLSM_WARN_COMM("denied mmap PROT_EXEC on "
			"anonymous mapping\n");
	veriexec_task_clear();
	return -EPERM;
}

/**
 * Hook: check permissions for a mprotect() operation.
 * The most significant mprotect() checks are permformed by an non-LSM hook,
 * clsm_file_mprotect_exec(), which checks executable mappings after
 * writes to the underlying file are denied.
 * @n
 * This LSM hook, which is called before denying writes to the
 * possible underlying file, is retained to deal with non-file-backed
 * executable mappings.
 * @n
 * Anonymous mappings are denied altogether, since there is
 * no way to prevent write access to a MAP_SHARED|MAP_ANONYMOUS
 * @n <b> Called with mmap_sem held. </b>
 * @param vma Memory region to modify.
 * @param reqprot Protection requested by the application (ignored).
 * @param prot Actual protection that will be applied by the kernel
 * (with, possibly, flags added to the original @a reqprot, e.g. PROT_EXEC).
 * @return 0 if access is authorized, negative error code if it is denied.
 * @see clsm_file_mprotect_exec()
 */

static int
clsm_file_mprotect(struct vm_area_struct *vma,
		unsigned long reqprot, unsigned long prot)
{
	if (likely(vma->vm_file)) {
		if (!(prot & PROT_EXEC))
			return 0;
		if (unlikely(inode_permission(
					vma->vm_file->f_path.dentry->d_inode,
					MAY_EXEC))) {
			CLSM_WARN_COMM("denied PROT_EXEC mprotect: "
				"no exec permission on file %s\n",
				vma->vm_file->f_path.dentry->d_name.name);
			return -EPERM;
		}
		/* Else leave the rest to clsm_file_mprotect_exec() */
		return 0;
	}
	/* Anonymous mapping */
	if (likely(!veriexec_task_checklibs(current)))
		return 0;

	if (likely(!(prot & PROT_EXEC)))
		return 0;

	CLSM_WARN_COMM("denied mprotect PROT_EXEC on "
			"anonymous mapping\n");
	veriexec_task_clear();

	return -EPERM;
}

static int
clsm_file_alloc_security(struct file *filp)
{
	struct clsm_file_sec *fsec = filp->f_security;
	const struct clsm_task_sec *tsec = current_cred()->security;
	const struct cred *cred = current_cred();

	fsec = kmem_cache_zalloc(g_fcache, GFP_KERNEL);
	if (unlikely(!fsec))
		return -ENOMEM;
	fsec->f_flags = tsec->t_flags;
	fsec->f_eff = cred->cap_effective;
	fsec->f_perm = cred->cap_permitted;
	fsec->f_inh = cred->cap_inheritable;
#ifdef CONFIG_VSERVER
	fsec->f_xid = vx_current_xid();
#endif
	filp->f_security = fsec;
	return 0;
}

/**
 * Hook: called before reading an elf interpreter into a process memory,
 * during execve() treatment.
 * This call checks possible veriexec constraints on the interpreter, and
 * updates the caller's credentials accordingly.
 * Not an original LSM hook.
 * @param bprm Binprm structure for the executable being loaded.
 * @param interp Interpreter file.
 * @return 0 if loading the interpreter is authorized, negative error code
 * if it is denied or in case of error.
 */
static int
clsm_file_interpreter(struct linux_binprm *bprm, struct file *interp)
{
	veriexec_lib_check_t check = veriexec_binprm_checkinterp(bprm);
	if (likely(check == VeriexecCheckNone))
		return 0;

	return veriexec_updatecreds(interp, check);
}

#endif /* CONFIG_VERIEXEC */

/*@}*/

/** @name IO signaling file hooks */
/*@{*/

/**
 * Common F_SETOWN / F_SETSIG handler.
 * Whenever a task sets up the fowner or the sigio number for a file,
 * we store its three capability masks and (in a vserver-enabled kernel)
 * its xid in a security
 * tag attached to the file. This complements the information
 * stored in the struct fown_struct itself (euid and so forth), and
 * allows for complementary checks when trying to deliver a signal to
 * the fowner later on.
 * If such information is already attached to the file, we simply check
 * the caps/flags attached against our own.
 * @param filp Affected file.
 * @return 0 if access is authorized (allocation successful, or privilege check
 * OK), negative error code if it is denied (failed privilege check) or in
 * case of error (allocation failed).
 */

static inline int
alloc_or_test_fsec(struct file *filp)
{
	struct clsm_file_sec *fsec = filp->f_security;
	const struct clsm_task_sec *tsec = current_cred()->security;
	const struct cred *cred = current_cred();

	if (!tsec)
		return -EFAULT;

	if (likely(!fsec)) {
		fsec = kmem_cache_zalloc(g_fcache, GFP_KERNEL);
		if (unlikely(!fsec))
			return -ENOMEM;
		fsec->f_flags = tsec->t_flags;
		fsec->f_eff = cred->cap_effective;
		fsec->f_perm = cred->cap_permitted;
		fsec->f_inh = cred->cap_inheritable;
#ifdef CONFIG_VSERVER
		fsec->f_xid = vx_current_xid();
#endif
		filp->f_security = fsec;
		return 0;
	} else {
#ifdef CONFIG_VSERVER
		if (fsec->f_xid != vx_current_xid()) {
			CLSM_WARN_COMM("denied fsec modification accross "
					"context boundaries on %s\n",
					filp->f_path.dentry->d_name.name);
			return -EPERM;
		}
#endif
		/**
		 * NB : When checking a caller's privs against those stored
		 * by the clsm_file_sec creator, we compare the saved
		 * @b capraised status versus the caller's
		 * capraised status, rather than the usual @b raised vs.
		 * capraised, to allow a bumped but not capraised task to do
		 * F_SETOWN and F_SETSIG in a row. Same goes for tasks that
		 * have only a forced inheritable mask */
		if (capable(CAP_KILL) && (!clsm_flags_capraised(fsec->f_flags)
					|| clsm_cred_capraised(current_cred())))
			return 0;
		/**
		 * NB : we alse compare @b both effective masks, rather than
		 * caller's effective versus creator's permitted, so that a task
		 * with temporarily dropped root privs can do F_SETOWN and
		 * F_SETSIG in a row - with the caveat that its effective
		 * mask (0) will then be compared to the @b permitted
		 * mask of FOWNER, when trying to deliver an I/O sig. */
		if (!cap_issubset(fsec->f_eff, cred->cap_effective))
			return -EPERM;
		if (!cap_issubset(fsec->f_inh, cred->cap_inheritable))
			return -EPERM;
		return 0;
	}
}

/**
 * Hook: called before handling a fcntl(F_SETOWN) request.
 * Stores the caller's privileges, or compare them against previously stored
 * privileges.
 * @param filp Affected file.
 * @see alloc_or_test_fsec()
 */
static void
clsm_file_set_fowner(struct file *filp)
{
	int ret = alloc_or_test_fsec(filp);
	if (unlikely(ret))
		CLSM_WARN_COMM("denied setting fowner\n");
}

/**
 * Hook: called before handling a fcntl(F_SETSIG) request.
 * If no struct clsm_file_sec is yet attached to the target file, one
 * is allocated, to store the caller's credentials. Otherwise, the caller's
 * credentials are compared with those stored in the security tag.
 * @n Not an original LSM hook.
 * @param filp Target file for the fcntl() call.
 * @param sig Signal number being set on the file.
 * @return 0 if access is authorized, negative error code if access is denied
 * or in case of error.
 * @see alloc_or_test_fsec()
 */
static int
clsm_file_fsignum(struct file *filp, int sig)
{
	int ret = alloc_or_test_fsec(filp);
	if (unlikely(ret))
		CLSM_WARN_COMM("denied setting fsignum to %d\n", sig);
	return ret;
}

/**
 * Hook: called before delivering a signal to a file's fowner.
 * When delivering a signal to a file's fowner, we perform basically
 * the same tests as for a simple kill initiated by whoever set up
 * the fowner for that file, and sent to the target fowner. Note that
 * these tests also apply to the most common case, which is that of
 * 	fcntl(fd, F_SETOWN, getpid())
 * since there is no reset for sigio stuff and the task that ends up
 * getting the signal could be any other task that gets allocated the
 * same pid later on...
 * If the kernel is vserver-enabled, we also check the fowner's xid against
 * that of the fowner setter.
 * @param tsk Task receiving the signal.
 * @param fown File owner information.
 * @param signum Signal number (ignored).
 * @return 0 if access is authorized, negative error code if access is denied
 * or in case of error.
 */
static int
clsm_file_send_sigiotask(struct task_struct *tsk,
		struct fown_struct *fown, int signum)
{
	const struct file *filp;
	const struct clsm_file_sec *fsec;
	const struct cred *cred = get_task_cred(tsk);
	const struct clsm_task_sec *tsec = cred->security;

	/* fown_struct is always referenced from within a struct file */
	filp = container_of(fown, struct file, f_owner);
	fsec = filp->f_security;
	if (unlikely(!fsec))
		goto out_perm;

	if (unlikely(tsec->t_privs & CLSM_PRIV_IMMORTAL))
		goto out_perm;

#ifdef CONFIG_VSERVER
	if (unlikely(fsec->f_xid != vx_task_xid(tsk)))
		goto out_srch;
#endif
	/* Note: we do not take a security context's bcaps mask
	 * into account here... */
	if (cap_raised(fsec->f_eff, CAP_KILL) &&
			(!clsm_cred_raised(cred) ||
			 clsm_flags_capraised(fsec->f_flags)))
		goto ok;

	if (!cap_issubset(cred->cap_permitted, fsec->f_eff))
		goto out_perm;
	if (!cap_issubset(cred->cap_inheritable, fsec->f_inh))
		goto out_perm;

ok:
	put_cred(cred);
	return 0;

out_perm:
	put_cred(cred);
	/* NB: getting more info on the original task here would be nice,
	 * but it seems too much hassle */
	CLSM_LOG_COMM_T(KERN_WARNING, tsk,
			"denied sigio (%i) reception\n", fown->signum);
	return -EPERM;
#ifdef CONFIG_VSERVER
out_srch:
	put_cred(cred);
	CLSM_LOG_COMM_T(KERN_WARNING, tsk, "denied sigio (%i) reception over "
			"context boundaries\n", fown->signum);
	return -ESRCH;
#endif
}

/*@}*/

/** @name Chroot hardening file hooks */
/*@{*/

#ifdef CONFIG_CLSM_CHROOT_SOCKFD

#ifdef CONFIG_VSERVER
/** Get a pointer to the root dentry and vfsmount of the current context.
 * Outside of any vserver context, those are read as the root of the
 * current child reaper. In a vserver context, we take the root of
 * the vx_info FS as root.
 * @param root - Storage for a pointer to the root dentry.
 * @param rootmnt - Storage for a pointer to the root vfsmount.
 */
static inline void
get_realroot(struct path *path)
{
	struct dentry *root;
	struct vfsmount *mnt;
	struct vx_info *vxi = task_get_vx_info(current);
	if (!vxi) {
		struct task_struct *reaper =
			task_active_pid_ns(current)->child_reaper;
		spin_lock(&reaper->fs->lock);
		mnt = mntget(reaper->fs->root.mnt);
		root = dget(reaper->fs->root.dentry);
		spin_unlock(&reaper->fs->lock);
	} else {
		spin_lock(&vxi->space[0].vx_fs->lock);
		mnt = mntget(vxi->space[0].vx_fs->root.mnt);
		root = dget(vxi->space[0].vx_fs->root.dentry);
		spin_unlock(&vxi->space[0].vx_fs->lock);
		put_vx_info(vxi);
	}
	path->dentry = root;
	path->mnt = mnt;
}
#else /* !CONFIG_VSERVER */
static inline void
get_realroot(struct path *path)
{
	struct dentry *root;
	struct vfsmount *mnt;
	struct task_struct *reaper =
			task_active_pid_ns(current)->child_reaper;
	spin_lock(&reaper->fs->lock);
	mnt = mntget(reaper->fs->root->mnt);
	root = dget(reaper->fs->root->dentry);
	spin_unlock(&reaper->fs->lock);
	path->dentry = root;
	path->mnt = mnt;
}
#endif /* !CONFIG_VSERVER */

/**
 * Test if a file is outside of the caller's chroot tree.
 * Plundered from grsecurity/grsec_chroot.c, local copy
 * since I'd rather avoid the complex kconfig dependencies
 * using the original would entail.
 * @n
 * Checking is done by climbing up the directory tree, until
 * either the caller's root is reached (in which case the file
 * is in the chroot), or the namespace's root is reached (which means
 * the file is outside the chroot tree).
 * @param filp File to test.
 * @return 1 if @a filp is outside the current chroot tree, 0 if it
 * is not.
 */
static int
filp_outside_chroot(struct file *filp)
{
	struct path currentroot;
	int ret = 1;

	if (!S_ISDIR(filp->f_path.dentry->d_inode->i_mode))
		return 0;

	get_realroot(&currentroot);
	if (path_is_under(&(filp->f_path), &currentroot))
		ret = 0;
	path_put(&currentroot);
	return ret;
}

/**
 * Hook: check a file descriptor received on a UNIX socket.
 * If the receiving process is in a chroot jail, this tests if the received
 * file is outside that chroot tree, in which case reception is denied.
 * @n
 * The CLSM_PRIV_CHROOT privilege allows bypassing this check.
 * @param filp Received file.
 * @return 0 if access is authorized, negative error code if it is denied.
 * @see CLSM_PRIV_CHROOT
 */
static int
clsm_file_receive(struct file *filp)
{
	const struct clsm_task_sec *tsec = current_cred()->security;

	if (!clsm_ctl_chroot)
		return 0;

	if (likely(!(tsec->t_flags & CLSM_FLAG_CHROOTED)))
		return 0;

	if (tsec->t_privs & CLSM_PRIV_CHROOT)
		return 0;

	if (filp_outside_chroot(filp)) {
		CLSM_WARN_COMM("denied reception of fd through PF_UNIX\n");
		return -EPERM;
	}

	return 0;
}
#endif /* CONFIG_CLSM_CHROOT_SOCKFD */

/*@}*/

/** @name Locking file hooks */
/*@{*/

/**
 * Hook: called before setting a lock on a file.
 * This hook applies to all kinds of file locks : fcntl(),lockf(),flock(),
 * leases. It prevents locking a file on a VFS mount that has the MNT_NOLOCK
 * restrictive flag.
 * @param filp File to be locked.
 * @param cmd Lock operation to be performed (unused).
 * @return 0 if access is authorized, negative error code if it is denied.
 */
static int
clsm_file_lock(struct file *filp, unsigned int cmd)
{
	if (filp->f_path.mnt->mnt_flags & MNT_NOLOCK) {
		CLSM_INFO_COMM("denied lock on %s\n",
				filp->f_path.dentry->d_name.name);
		return -EPERM;
	}
	return 0;
}

/** Hook: called before adding an inotify watch on a file.
 * Checks if the file is on a NOLOCK VFS mount, and denies the access in
 * that case.
 * @n Not an original LSM hook.
 * @param nd Nameidata for the target file.
 * @return 0 if access is authorized, -EPERM if denied.
 */
static int
clsm_inotify_addwatch(const struct path *path)
{
	if (path->mnt->mnt_flags & MNT_NOLOCK) {
		CLSM_INFO_COMM("denied inotify on %s\n",
				path->dentry->d_name.name);
		return -EPERM;
	}
	return 0;
}

/*@}*/

/*************************************************************/
/*                 path hooks                               */
/*************************************************************/

/** @name Path hooks */
/*@{*/


#ifdef CONFIG_CLSM_FSTRACE
/**
 * Helper: report a file creation on a traced mount.
 * Reports either the name of the created file or a hash of that name.
 * @param dentry Dentry for the created file.
 * @param mnt Traced mount.
 */
static inline void
report_traced_create(const struct dentry *dentry, const struct dentry *mnt_dentry)
{
	const char *name = dentry->d_name.name;

#ifdef CONFIG_CLSM_FSTRACE_HASH
  static const char _rep_digits[16] = "0123456789ABCDEF";
	struct hash_desc desc;
	char hbuf[FSTRACE_DIGEST_SIZE];
	char nbuf[2 * FSTRACE_DIGEST_SIZE + 1];
	struct scatterlist sg;
	char *ptr;
	unsigned int i;

	/* Should not happen... */
	if (unlikely(!fstrace_tfm)) {
		memcpy(nbuf, "<hash failed>", sizeof("<hash failed>"));
		goto report;
	}

	desc.tfm = fstrace_tfm;
	desc.flags = 0;
	sg_init_one(&sg, name, strlen(name));

	mutex_lock(&fstrace_mutex);
	crypto_hash_init(&desc);
	crypto_hash_update(&desc, &sg, sg.length);
	crypto_hash_final(&desc, hbuf);
	mutex_unlock(&fstrace_mutex);

	ptr = nbuf;
	/* Nah, I won't call sprintf just for that... */
	for (i = 0; i < sizeof(hbuf); i++) {
		*ptr++ = _rep_digits[((hbuf[i] & 0xf0) >> 4)];
		*ptr++ = _rep_digits[(hbuf[i] & 0x0f)];
	}
	*ptr = '\0';
	name = nbuf;

report:
#endif /* CONFIG_CLSM_FSTRACE_HASH */
	printk(KERN_INFO "fstrace: created file \"%s\" on "
			"traced mount \"%s\" "
#ifdef CONFIG_VSERVER
			"(task \"%s\", pid %d, uid %d, euid %d, in context %d)\n",
#else
			"(task \"%s\", pid %d, uid %d, euid %d)\n",
#endif
			name,
			mnt_dentry->d_name.name,
			current->comm, current->pid,
			from_kuid(&init_user_ns, current_cred()->uid),
#ifdef CONFIG_VSERVER
			from_kuid(&init_user_ns, current_cred()->euid),
			vx_current_xid());
#else
			current_cred()->euid);
#endif
}

/**
 * Hook: check permission when creating a file
 * This logs inode creation on MS_TRACE mounts.
 * @param dir Path of the parent directory
 * @param dentry File to be created.
 * @param mode File mode of the file to be created.
 * @param dev Undecoded device number.
 * @returns 0.
 */
static int
clsm_path_mknod(struct path *dir, struct dentry *dentry, umode_t mode,
			unsigned int dev)
{
	struct dentry *mnt_dentry;
	struct vfsmount *mnt_vfsmount;

	mnt_dentry = dir->dentry;
	mnt_vfsmount = dir->mnt;
	if (unlikely(mnt_vfsmount->mnt_flags & MNT_TRACE))
		report_traced_create(dentry, mnt_dentry);

	return 0;
}

#endif /* CONFIG_CLSM_FSTRACE */

/*************************************************************/
/*                 inode hooks                               */
/*************************************************************/

/** @name Inode hooks */
/*@{*/

/**
 * Allocate an inode security tag.
 * This is not an actual hook, and is called
 * only when caching an inode.
 * @param inode New inode.
 * @return 0 on success, -ENOMEM on failure.
 */
int
clsm_inode_alloc_security(struct inode *inode)
{
	struct clsm_inode_sec *isec;

	isec = kmem_cache_zalloc(g_icache, GFP_KERNEL);
	if (unlikely(!isec))
		return -ENOMEM;

	spin_lock(&inode->i_lock);
	if (likely(!inode->i_security)) {
		inode->i_security = isec;
		spin_unlock(&inode->i_lock);
	} else {
		spin_unlock(&inode->i_lock);
		kmem_cache_free(g_icache, isec);
	}
	return 0;
}

/**
 * Hook: free as inode security tag.
 * This is called on every inode de-allocation. Freeing
 * happens only if a security tag was indeed allocated.
 * @param inode Inode to deallocate.
 */
static void
clsm_inode_free_security(struct inode *inode)
{
	struct clsm_inode_sec *isec;

	spin_lock(&inode->i_lock);
	isec = inode->i_security;
	inode->i_security = NULL;
	spin_unlock(&inode->i_lock);

	if (unlikely(isec))
		kmem_cache_free(g_icache, isec);
}



#ifdef CONFIG_CLSM_MOUNT

#ifdef CONFIG_DEVCTL

/**
 * Common helper for block device access.
 * Check a block device open request against the devctl permissions
 * for that device. This only checks read/write access permissions.
 * @param inode Inode associated to the block device.
 * @param mask Requested access mode.
 * @return 0 if access is authorized, negative error code if it is denied.
 */
static inline int
blkdev_permission(struct inode *inode, int mask)
{
	dev_t dev = inode->i_rdev;
	devctl_perm_t mode = 0;

	if (!clsm_ctl_mount)
		return 0;

	if (mask & MAY_WRITE)
		mode |= DEVCTL_PERM_RW;
	if (mask & MAY_READ)
		mode |= DEVCTL_PERM_RO;

	if (devctl_check(dev, mode))
		return 0;

	/* We don't log denied read accesses as warning, since
	 * these are usually inocuous (i.e. cryptsetup status)
	 */
	if (mode == DEVCTL_PERM_RO)
		CLSM_INFO_COMM("denied read access "
			"to block device %u/%u\n",
			imajor(inode), iminor(inode));
	else
		CLSM_WARN_COMM("denied access (mode: 0x%x) "
			"to block device %u/%u\n",
			mode, imajor(inode), iminor(inode));

	return -EPERM;
}

#else /* !CONFIG_DEVCTL */

#define blkdev_permission(inode, mask) 0

#endif /* !CONFIG_DEVCTL */

/** Hook: check inode open permissions (restricted to block devices).
 * This check every inode open attempt, and, when the inode is a block
 * device, calls the blkdev_permission() helper to check it against
 * devctl. If the inode is a FUSE char device, this checks the FUSE-specific
 * privileges. Otherwise, the access is systematically authorized.
 * @return 0 if access is authorized, negative error code if it is denied.
 */
static int
clsm_inode_permission(struct inode *inode, int mask)
{
	if (unlikely(S_ISBLK(inode->i_mode)))
		return blkdev_permission(inode, mask);

	if (unlikely(S_ISCHR(inode->i_mode))) {
		const struct clsm_task_sec *tsec = current_cred()->security;

		if (likely(imajor(inode) != MISC_MAJOR))
			return 0;
		if (likely(iminor(inode) != FUSE_MINOR))
			return 0;

		if (!(tsec->t_privs & CLSM_PRIV_FUSE)) {
			CLSM_INFO_COMM("denied fuse mount open");
			return -EPERM;
		}
	}

	return 0;
}

/**
 * Hook: called by blkdev_open().
 * This checks the block device read/write access permission through
 * either the devctl backend, * or the simple sysctl-based major/minor
 * checks. It is called, notably, before mounting a block device,
 * before projecting it through device-mapper or a loop projection, and
 * before any direct access to the corresponding device file.
 * @n Not an original LSM hook.
 * @param inode Inode associated with the block device.
 * @param mask Access mode requested by the caller.
 * @return 0 if access is authorized, negative error code if denied or
 * in case of error.
 */

static int
clsm_inode_blkdev_open(struct inode *inode, int mask)
{
	return blkdev_permission(inode, mask);
}

#endif /* CONFIG_CLSM_MOUNT */

#ifdef CONFIG_CCSD_RNG
extern int ccsd_rng_device_open(struct inode *, struct file *);
#endif

/**
 * Try to open one of the custom CLIP-LSM memory devices.
 * This calls the memory device handler for veriexec and / or devctl.
 * @n This is not an original LSM hook.
 * @param inode Opened memory char device inode.
 * @param file Opened memory char device file, whose file_operations must
 * be updated if a minor number match is found.
 * @return 0 if a match is found, -ENXIO if it is not, other negative error
 * codes in case of failure.
 */
static int
clsm_inode_memdev_open(struct inode *inode, struct file *file)
{
	int err;

#ifdef CONFIG_VERIEXEC
	err = veriexec_device_open(inode, file);
	if (!err)
		return 0;
	if (err != -ENXIO)
		return err;
#endif
#ifdef CONFIG_DEVCTL
	err = devctl_device_open(inode, file);
	if (!err)
		return 0;
	if (err != -ENXIO)
		return err;
#endif
#ifdef CONFIG_CCSD_RNG
	err = ccsd_rng_device_open(inode, file);
	if (!err)
		return 0;
	if (err != -ENXIO)
		return err;
#endif
	return -ENXIO;
}

#ifdef CONFIG_VERIEXEC

/**
 * Remove an inode from veriexec cache.
 * This is called right before write access is granted to an inode.
 * @n This is not an original LSM hook.
 * @n <b> Must be called with inode->i_lock held. </b>
 * @param inode Inode to which write access is about to be granted.
 * @return 0.
 */
static int
clsm_inode_write_access(struct inode *inode)
{
	if (unlikely(inode->i_security))
		veriexec_inode_uncache(inode);
	return 0;
}


/**
 * Check for privileged binaries.
 * @param dentry dentry to check.
 * @return 0 if non-privileged, 1 if privileged.
 */
static int
clsm_inode_privileged_binary(const struct dentry *dentry)
{
	return veriexec_privileged_binary(dentry);
}
#endif /* CONFIG_VERIEXEC */

/*@}*/


/*************************************************************/
/*                 filesystem hooks                          */
/*************************************************************/

/** @name Filesystem hooks */
/*@{*/

/**
 * Check permission for a mount operation.
 * Not a LSM hook.
 * @param op Type of operation.
 * @param path Path of the mount operation.
 * @return 0 if OK, -EPERM / -EINVAL otherwise.
 */
static int
clsm_sb_mount_permission(int op, const struct path *path)
{
#ifdef CONFIG_VSERVER
	uint32_t vxcap;
#endif
	const char *action;
	const char *name;
	int ret;
	const struct clsm_task_sec *tsec = current_cred()->security;

	/*
	 * Ignore kernel initiated mounts. This happens when vfs_caches_init
	 * calls mount, before PID 1 is created.
	 */
	if (tsec == NULL) {
		if(current->pid == 0)
			return 0;
		else
			panic("CLIP LSM: empty security context");
	}
	switch (op) {
		case SECURITY_MOUNT_NEW:
			action = "mount";
			break;
		case SECURITY_MOUNT_REMOUNT:
			action = "remount";
			break;
		case SECURITY_MOUNT_BIND:
			action = "bind mount";
			break;
		case SECURITY_MOUNT_TYPE:
			action = "mount type change";
			break;
		case SECURITY_MOUNT_MOVE:
			action = "mount move";
			break;
		case SECURITY_MOUNT_UMOUNT:
			action = "umount";
			break;
		case SECURITY_MOUNT_BINARY:
			action = "binary mount";
			break;
		default:
			action = "<unknown mount operation>";
	}

	if (path && path->dentry)
		name = path->dentry->d_name.name;
	else
		name = "<unknown>";

	if ((tsec->t_privs & CLSM_PRIV_FUSE)) {
		if (op == SECURITY_MOUNT_NEW || op == SECURITY_MOUNT_BINARY) {
			/* Note : we cannot make sure the underlying
			 * super_block is indeed a FUSE sb in the 'new mount'
			 * case - this will however be checked by the
			 * sb_check_sb() hook before we graft the new mount
			 * into the VFS.
			 */
			CLSM_INFO_COMM("authorised (supposedly) fuse %s on %s",
						action, name);
			return 0;
		}

		if (op == SECURITY_MOUNT_UMOUNT && path && path->mnt
		  && path->mnt->mnt_sb && path->dentry
		  && (path->mnt->mnt_sb->s_magic == FUSE_SUPER_MAGIC)
		  && (uid_eq(path->dentry->d_inode->i_uid,
		  		current_uid()))) {
			CLSM_INFO_COMM("authorised fuse umount");
			return 0;
		}
	}

#ifdef CONFIG_VSERVER
	vxcap = security_mountop2vxc(op);
	if (vxcap)
		ret = (vx_capable(CAP_SYS_ADMIN, vxcap)) ? 0 : -EPERM;
	else
		ret = (capable(CAP_SYS_ADMIN)) ? 0 : -EPERM;
#else
	ret = (capable(CAP_SYS_ADMIN)) ? 0 : -EPERM;
#endif
	if (ret)
		CLSM_WARN_COMM("denied %s on %s", action, name);
	return ret;
}

#ifdef CONFIG_CLSM_MOUNT

/** Check for removal of a secure flag */
#define UNSET_P(mntflag,msflag) \
		((path->mnt->mnt_flags & mntflag) && !(flags & msflag))
/**
 * Remount helper - check a remount mount operation.
 * Remount logic : when the clsm_ctl_mount control is activated, we
 * do not allow any remount operation to :
 *  - change ro to rw (ro being either the sb flag or the mnt flag)
 *  - change nodev to dev
 *  - change noexec to exec
 *  - change nosuid to suid
 *  - change noatime to atime
 *  - change nodiratime to diratime
 * @param mnt Mount point being remounted.
 * @param flags Remount flags (MS_*, not MNT_*)
 * @return 0 if access is OK, -EPERM otherwise.
 */
static inline int
do_sb_remount(const struct path *path, unsigned long flags)
{

	if (((path->mnt->mnt_sb->s_flags & MS_RDONLY)
		|| (path->mnt->mnt_flags & MNT_READONLY))
			&& !(flags & MS_RDONLY)) {
		CLSM_WARN("Attempt to remount %s as r/w\n",
					path->dentry->d_name.name);
		return -EPERM;
	}

	/* Yuck, MNT_XXX != MS_XXX for vfsmount flags :( */


	if (	UNSET_P(MNT_NOEXEC, MS_NOEXEC) 		||
		UNSET_P(MNT_NODEV, MS_NODEV)  		||
		UNSET_P(MNT_NOSUID, MS_NOSUID) 		||
		UNSET_P(MNT_NOATIME, MS_NOATIME) 	||
		UNSET_P(MNT_NODIRATIME, MS_NODIRATIME)  ||
		UNSET_P(MNT_NOSYMFOLLOW, MS_NOSYMFOLLOW)  ||
		UNSET_P(MNT_NOLOCK, MS_NOLOCK)
	   ) {
		CLSM_WARN("Attempt to remount %s with illegal flags\n",
				path->dentry->d_name.name);
		return -EPERM;
	}

	return 0;
}
#undef UNSET_P

/** Check for removal of a secure flag */
#define UNSET_P_PATH(mntflag,msflag) \
		((dpath.mnt->mnt_flags & mntflag) && !(flags & msflag))

/**
 * Bind mount helper - check a bind mount operation.
 * Bind logic : we deal with bind mounts as we would deal (through
 * do_sb_remount()) with a remount of the underlying (source) mount,
 * in order to prevent the bind from removing some secure flags.
 * @n
 * Exception / kludge for now : we do not perform those tests on a
 * recursive-bind mounting of /, because this is needed when mounting the
 * root for a vserver jail.
 * @todo Get rid of the bind mount exception for recursive-bind mounting of /.
 * @param dev_name Source path.
 * @param flags Mount options.
 * @param dest Nameidata for the destination mount point.
 * @return 0 if access is OK, -EPERM otherwise.
 */
static inline int
do_sb_bind(const char *dev_name, unsigned long flags, const struct path *path)
{
	struct path dpath;
	int err;

	/* Recursive-bind exception */
	const char *destname = path->dentry->d_name.name;
	if (*destname == '/' && *(destname+1) == '\0' && flags & MS_REC)
		return 0;

	/* Note that the same lookup will be performed again in the mount
	 * path... */
	err = kern_path(dev_name, LOOKUP_FOLLOW, &dpath);
	if (unlikely(err))
		return err;

	/* We don't deal with superblock MS_RDONLY here, it is not
	 * bypassable by a bind mount anyway. */
	if ((dpath.mnt->mnt_flags & MNT_READONLY)
				&& !(flags & MS_RDONLY)) {
		CLSM_WARN("attempt to bind as rw part of a ro mounting : "
				"%s (%s) -> %s\n", dev_name,
				dpath.mnt->mnt_root->d_name.name,
				destname);
		path_put(&dpath);
		return -EPERM;
	}

	if (	UNSET_P_PATH(MNT_NOEXEC, MS_NOEXEC) 		||
		UNSET_P_PATH(MNT_NODEV, MS_NODEV)  		||
		UNSET_P_PATH(MNT_NOSUID, MS_NOSUID) 		||
		UNSET_P_PATH(MNT_NOATIME, MS_NOATIME) 	||
		UNSET_P_PATH(MNT_NODIRATIME, MS_NODIRATIME)	||
		UNSET_P_PATH(MNT_NOSYMFOLLOW, MS_NOSYMFOLLOW)||
		UNSET_P_PATH(MNT_NOLOCK, MS_NOLOCK)
	   ) {
		CLSM_WARN("attempt to bind mount %s (%s) to %s with illegal "
				"flags\n", dev_name,
				dpath.mnt->mnt_root->d_name.name,
				destname);
		path_put(&dpath);
		return -EPERM;
	}

	path_put(&dpath);
	return 0;
}
#undef UNSET_P_PATH

#ifdef CONFIG_DEVCTL

/** Standard kernel function, with no header */
extern void put_filesystem(struct file_system_type *);

/**
 * Filesystem type helper - check for virtual filesystems.
 * This checks if a filesystem type is virtual, i.e. does not
 * use  a block device as mount source.
 * @param typename FS type, as a string.
 * @return 1 if the filesystem is virtual, 0 if it isn't (or if it
 * is unknown by the kernel).
 */
static inline int
_nodev_fs(const char *typename)
{
	int ret;
	struct file_system_type *type = get_fs_type(typename);

	if (!type)
		return 0;

	ret = (type->fs_flags & FS_REQUIRES_DEV) ? 0 : 1;

	put_filesystem(type);
	return ret;
}


/**
 * New mount helper - check 'real' mount operations.
 * This only makes sense with CONFIG_DEVCTL set, which gives us
 * mandatory constraints on flags for new device mounts.
 * @n
 * Note that even then, no constraints apply to new mounts which are
 * not associated with a device, e.g. proc/sys/pts or network fs.
 * @n
 * Note also that this only checks the 'nodev,noexec,nosuid' flags.
 * The read / write access constraints are evaluated directly when
 * opening the underlying block device, by clsm_inode_blkdev_open().
 * @param dev_name Source device path.
 * @param flags Mount flags.
 * @param type Mount fs type, as a string.
 * @param dest Nameidata for the destination mount point (only used
 * for logging).
 * @return 0 if access is OK, -EPERM otherwise.
 * @see clsm_inode_blkdev_open()
 */

static inline int
do_sb_new(const char *dev_name, unsigned long flags, const char *type,
						const struct path *path)
{
	struct path dpath;
	dev_t dev;
	int err;
	unsigned int mode = 0;

	err = kern_path(dev_name, LOOKUP_FOLLOW, &dpath);
	if (err) {
		if (likely(err == -ENOENT))
			return (_nodev_fs(type)) ? 0 : -EPERM;
		return err;
	}

	dev = dpath.dentry->d_inode->i_rdev;
	path_put(&dpath);

	if (!(flags & MS_NOSUID)) {
		mode |= DEVCTL_PERM_SUID;
	}
	if (!(flags & MS_NOEXEC)) {
		mode |= DEVCTL_PERM_EXEC;
	}
	if (!(flags & MS_NODEV)) {
		mode |= DEVCTL_PERM_DEV;
	}

	err = devctl_check(dev, mode);
	if (!err) {
		CLSM_WARN_COMM("denied mount of %s to %s : illegal flags\n",
				dev_name, path->dentry->d_name.name);
		return -EPERM;
	}
	return 0;
}

#else /* !CONFIG_DEVCTL */

#define do_sb_new(name, flags, type, path) 0

#endif /* !CONFIG_DEVCTL */

/**
 * Move mount helper - check MS_MOVE mount operations.
 * This is a very simple test: we deny move mount to every process
 * except @a init.
 * @n
 * Note that this only applies after @a _clsm_ctl_mount has been set to
 * zero.
 * @param old_name Path of the old mount point (used for logging only).
 * @param nd Nameidata for the new mount point (used for logging only).
 * @return 0 if access is OK, -EPERM otherwise.
 * @see clip_sb_pivotroot()
 */
static inline int
do_sb_move(const char *old_name, const struct path *path)
{

	if (is_global_init(current))
		return 0;

	if (likely(old_name)) {
		CLSM_WARN_COMM("denied MS_MOVE mount of %s to %s\n",
				old_name, path->dentry->d_name.name);
	} else {
		CLSM_WARN_COMM("denied MS_MOVE mount of NULL to %s\n",
				path->dentry->d_name.name);
	}
	return -EPERM;
}

/**
 * Hook: general mount permission check.
 * This is called before every mount operation, and calls in turn
 * the appropriate specific checker for remount, bind or move operations,
 * or new mounts.
 * @n
 * Those checks are only performed once @a _clsm_ctl_mount has been set to
 * zero.
 * @param dev_name Source path of the mount operation.
 * @param nd Nameidata of the destination mount point.
 * @param type FS type of the mount, as a string.
 * @param flags Mount flags.
 * @param data Complementary mount options (not used).
 * @return 0 if access is authorized, negative error code if it is denied.
 * @see do_sb_remount()
 * @see do_sb_bind()
 * @see do_sb_new()
 * @see do_sb_move()
 */
static int
clsm_sb_mount(const char *dev_name, const struct path *path,
		const char *type, unsigned long flags, void *data)
{
	if (!clsm_ctl_mount)
		return 0;

	if (flags & MS_REMOUNT) {
		/* Same check is performed again afterwards in namespace.c:
		 * do_remount(), but let's be cautious here and do it before
		 * touching that superblock */
		if (path->dentry != path->mnt->mnt_root)
			return -EINVAL;

		return do_sb_remount(path, flags);
	} else if (flags & MS_BIND) {
		return do_sb_bind(dev_name, flags, path);
	} else if (flags & MS_MOVE) {
		return do_sb_move(dev_name, path);
	} else {
		return do_sb_new(dev_name, flags, type, path);
	}

	return 0;
}

/**
 * Hook: check pivot_root() permission.
 * pivot_root() is restricted to @a init once @a _clsm_ctl_mount as
 * been set to zero.
 * @param old_nd New location for the original root (used for logging only).
 * @param new_nd New root (used for logging only).
 * @return 0 if access is OK, -EPERM otherwise.
 * @see do_sb_move()
 */
static int
clsm_sb_pivotroot(const struct path *old_path, const struct path *new_path)
{
	if (!clsm_ctl_mount || is_global_init(current))
		return 0;

	if (unlikely(!old_path || !new_path))
		CLSM_WARN_COMM("denied pivot_root\n");
	else
		CLSM_WARN_COMM("denied pivot_root %s => %s\n",
				old_path->dentry->d_name.name,
				new_path->dentry->d_name.name);

	return -EPERM;
}

/**
 * Hook: check superblock / mount before mounting a filesystem on a given
 * path.
 * This basically performs fuse-specific checks - check for CLSM_PRIV_FUSE,
 * add noexec,nodev,nosuid mount options, only allows fuse mounts on a
 * directory which belongs to the caller.
 * @param mnt vfsmount struct to be mounted.
 * @param path Path where mount will be grafted into the VFS.
 * @return 0 if authorize, -EPERM otherwise.
 */
static int
clsm_sb_check_sb(struct vfsmount *mnt, struct dentry *dentry)
{
	const struct clsm_task_sec *tsec = current_cred()->security;

	/* Make sure that having CLSM_PRIV_FUSE does not allow us to create
	 * an arbitrary (non-fuse) mount - see clsm_sb_mount_permission() check
	 * as well.
	 */
	if (likely(mnt->mnt_sb->s_magic != FUSE_SUPER_MAGIC))
#ifdef CONFIG_VSERVER
		return (vx_capable(CAP_SYS_ADMIN, VXC_SECURE_MOUNT)) ?
				0 : -EPERM;
#else
		return (capable(CAP_SYS_ADMIN)) ? 0 : -EPERM;
#endif

	if (!(tsec->t_privs & CLSM_PRIV_FUSE)) {
		CLSM_WARN_COMM("denied fuse mount on %s - "
			"missing privileges", dentry->d_name.name);
		return -EPERM;
	}

	mnt->mnt_flags |= (MNT_NOEXEC|MNT_NODEV|MNT_NOSUID);

	/* We trace all FUSE mounts with an underlying block device - this
	 * is simply much easier than propagating MS_TRACE flags through every
	 * layer of every fuse userland application...
	 */
	if (mnt->mnt_sb->s_bdev)
		mnt->mnt_flags |= MNT_TRACE;

	if (!uid_eq(dentry->d_inode->i_uid, current_uid())) {
		CLSM_WARN_COMM("denied fuse mount on %s - "
			"uids do not match (%d != %d)",
			dentry->d_name.name,
			from_kuid(&init_user_ns, dentry->d_inode->i_uid),
			from_kuid(&init_user_ns, current_cred()->uid));
		return -EPERM;
	}

	return 0;
}

#endif /* CONFIG_CLSM_MOUNT */

/*@}*/

/*************************************************************/
/*                 socket sec hooks                          */
/*************************************************************/

#ifdef CONFIG_CLSM_NET

/** Socket family is not local, i.e. not AF_UNIX nor AF_NETLINK */
#define nonlocal_family_p(family) \
	((family) != AF_UNIX && (family) != AF_LOCAL && (family) != AF_NETLINK)

/** Current task has the CLSM_PRIV_NETCLIENT privilege */
#define clsm_net_client_ok() \
	(((struct clsm_task_sec *)current_cred()->security)->t_privs \
		& CLSM_PRIV_NETCLIENT)

/** Current task has the CLSM_PRIV_NETSERVER privilege */
#define clsm_net_server_ok() \
	(((struct clsm_task_sec *)current_cred()->security)->t_privs \
		& CLSM_PRIV_NETSERVER)

/** Current task has the CLSM_PRIV_NETLINK privilege */
#define clsm_netlink_ok() \
	(((struct clsm_task_sec *)current_cred()->security)->t_privs \
		& CLSM_PRIV_NETLINK)

/** Current task has the CLSM_PRIV_NETLINK_AUDIT privilege */
#define clsm_netlink_audit_ok() \
	(((struct clsm_task_sec *)current_cred()->security)->t_privs \
		& CLSM_PRIV_NETLINK_AUDIT)

/** Current task has at least one of the CLSM_PRIV_NET* privileges,
 * CLSM_PRIV_NETLINK excluded.
 * This allows it to create a non-local socket, and run
 * get/setsockopt() calls on it, but not necessarily to send or
 * receive packets on it. */
#define clsm_net_ok() \
	(((struct clsm_task_sec *)current_cred()->security)->t_privs \
		& (CLSM_PRIV_NETCLIENT|CLSM_PRIV_NETSERVER|CLSM_PRIV_NETOTHER))

/** Trivial helper */
#define _case(var) \
		case var:\
			return #var

/**
 * Output a socket family name string matching a family code.
 * @param family Family code.
 * @return Family name, e.g. "PF_UNIX", or "other" if family code
 * is not recognized.
 */
static inline const char *
_sock_family(int family)
{
	switch (family) {
		_case(PF_UNSPEC);
		_case(PF_UNIX);
		_case(PF_INET);
		_case(PF_AX25);
		_case(PF_IPX);
		_case(PF_APPLETALK);
		_case(PF_NETROM);
		_case(PF_BRIDGE);
		_case(PF_ATMPVC);
		_case(PF_X25);
		_case(PF_INET6);
		_case(PF_ROSE);
		_case(PF_DECnet);
		_case(PF_NETBEUI);
		_case(PF_SECURITY);
		_case(PF_KEY);
		_case(PF_NETLINK);
		_case(PF_PACKET);
		_case(PF_ASH);
		_case(PF_ECONET);
		_case(PF_ATMSVC);
		_case(PF_SNA);
		_case(PF_IRDA);
		_case(PF_PPPOX);
		_case(PF_WANPIPE);
		_case(PF_LLC);
		_case(PF_TIPC);
		_case(PF_BLUETOOTH);
		_case(PF_IUCV);
		_case(PF_RXRPC);
		default:
			return "other";
	}
}
#undef _case

/** Socket hooks */
/*@{*/

/**
 * Hook: check permissions for socket creation.
 * Allows non-local socket creation for anyone with either CLSM_PRIV_NETCLIENT,
 * CLSM_PRIV_NETSERVER, or CLSM_PRIV_NETOTHER.
 * @n
 * PF_UNIX socket can be created regardless of privileges. PF_NETLINK socket
 * creation is only allowed by the CLSM_PRIV_NETLINK privilege, except for
 * NETLINK_ROUTE sockets, which are used all over the place, and which will
 * be checked more finely by @a clsm_netlink_send().
 * Netlink sockets with the NETLINK_AUDIT protocol require the specific
 * permission CLSM_PRIV_NETLINK_AUDIT to avoid allowing all processes with the
 * CLSM_PRIV_NETLINK privilege to read audit messages.
 * @n
 * NB : All operations are authorized when @a clsm_ctl_networking is zero
 * (debugging only). In any case, all operations are authorized for kernel
 * sockets, to allow networking subsystems initialization.
 * @param family Socket family
 * @param type Communication type.
 * @param protocol Requested protocol.
 * @param kern Set to 1 if a kernel socket.
 * @return 0 if access is OK, -EPERM otherwise.
 * @see CLSM_PRIV_NETCLIENT
 * @see CLSM_PRIV_NETSERVER
 * @see CLSM_PRIV_NETOTHER
 */
static int
clsm_socket_create(int family, int type, int protocol, int kern)
{
	if (family == AF_NETLINK && protocol != NETLINK_ROUTE) {
		/* Let kernel threads do netlink userland socket creation
		 * (occurs in 4.4.13) */
		if (!current->mm)
			return 0;
		if (!clsm_netlink_ok())
			goto out_perm;
		if (protocol == NETLINK_AUDIT && !clsm_netlink_audit_ok())
			goto out_perm;
	}

	if (likely(!nonlocal_family_p(family)))
		return 0;

	if (clsm_net_ok())
		return 0;

	/* Fall through */
out_perm:
	if (unlikely(!clsm_ctl_networking || kern))
		return 0;

	CLSM_INFO_COMM("denied %s socket (protocol: %d, type: %d) creation\n",
			_sock_family(family), protocol, type);
	return -EPERM;
}

/**
 * Hook: check permissions for socket bind.
 * Allows non-local socket bind for anyone with either CLSM_PRIV_NETCLIENT,
 * CLSM_PRIV_NETSERVER, or CLSM_PRIV_NETOTHER.
 * @n
 * Local sockets can be bound regardless of privileges.
 * @n
 * NB : All operations are authorized when @a clsm_ctl_networking is zero
 * (debugging only).
 * @param sock Socket to be bound (unused)
 * @param saddr Bind address.
 * @param addrlen Bind address length (unused).
 * @return 0 if access is OK, negative error code otherwise.
 * @see CLSM_PRIV_NETSERVER
 */
static int
clsm_socket_bind(struct socket *sock, struct sockaddr *saddr,
			int addrlen)
{
	if (unlikely(!saddr))
		return -EFAULT;

	if (likely(!nonlocal_family_p(saddr->sa_family)))
		return 0;

	if (clsm_net_ok())
		return 0;

	if (unlikely(!clsm_ctl_networking))
		return 0;

	CLSM_WARN_COMM("denied %s socket bind\n",
				_sock_family(saddr->sa_family));
	return -EPERM;
}


/**
 * Hook: check permissions for socket connect.
 * Allows non-local socket bind for anyone with CLSM_PRIV_NETCLIENT.
 * @n
 * Local sockets can be connected regardless of privileges.
 * @n
 * NB : All operations are authorized when @a clsm_ctl_networking is zero
 * (debugging only).
 * @param sock Socket to connect (unused)
 * @param saddr Remote address.
 * @param addrlen Remote address length (unused).
 * @return 0 if access is OK, negative error code otherwise.
 * @see CLSM_PRIV_NETCLIENT
 */
static int
clsm_socket_connect(struct socket *sock, struct sockaddr *saddr,
			int addrlen)
{
	if (unlikely(!saddr))
		return -EFAULT;

	if (likely(!nonlocal_family_p(saddr->sa_family)))
		return 0;

	if (clsm_net_client_ok())
		return 0;

	if (unlikely(!clsm_ctl_networking))
		return 0;

	CLSM_WARN_COMM("denied %s socket connect\n",
				_sock_family(saddr->sa_family));
	return -EPERM;
}

/**
 * Hook: check permissions for socket listen.
 * Allows non-local socket listen for anyone with CLSM_PRIV_NETSERVER.
 * @n
 * Listening on local sockets is authorized regardless of privileges.
 * @n
 * NB : All operations are authorized when @a clsm_ctl_networking is zero
 * (debugging only).
 * @param sock Socket to listen on.
 * @param backlog Max length for the pending connection queue (unused).
 * @return 0 if access is OK, negative error code otherwise.
 * @see CLSM_PRIV_NETSERVER
 */
static int
clsm_socket_listen(struct socket *sock, int backlog)
{
	if (unlikely(!sock->sk))
		return -EFAULT;

	if (likely(!nonlocal_family_p(sock->sk->sk_family)))
		return 0;

	if (clsm_net_server_ok())
		return 0;

	if (unlikely(!clsm_ctl_networking))
		return 0;

	CLSM_WARN_COMM("denied %s socket listen\n",
				_sock_family(sock->sk->sk_family));
	return -EPERM;
}

/**
 * Hook: check permissions for socket accept.
 * Allows non-local socket accept for anyone with CLSM_PRIV_NETSERVER.
 * @n
 * Accept on local sockets is authorized regardless of privileges.
 * @n
 * NB : All operations are authorized when @a clsm_ctl_networking is zero
 * (debugging only).
 * @param sock Socket to accept on.
 * @param newsock Newly created connected socket (unused).
 * @return 0 if access is OK, negative error code otherwise.
 * @see CLSM_PRIV_NETSERVER
 */
static int
clsm_socket_accept(struct socket *sock, struct socket *newsock)
{
	if (unlikely(!sock->sk))
		return -EFAULT;

	if (likely(!nonlocal_family_p(sock->sk->sk_family)))
		return 0;

	if (clsm_net_server_ok())
		return 0;

	if (unlikely(!clsm_ctl_networking))
		return 0;

	CLSM_WARN_COMM("denied %s socket accept\n",
				_sock_family(sock->sk->sk_family));
	return -EPERM;
}


/**
 * Hook: check permissions for socket send.
 * We allow sendmsg for any connected non-local socket (for which access
 * control must have been performed when establishing that (pseudo-)connection,
 * or for unconnected sockets with CLSM_PRIV_NETCLIENT, i.e. UDP clients.
 * Note that UDP servers are in the SS_CONNECTED state here.
 * @n
 * Sending on local sockets is allowed regardless of privileges.
 * @n
 * NB : All operations are authorized when @a clsm_ctl_networking is zero
 * (debugging only).
 * @param sock Socket to send on.
 * @param msg Message to be transmitted (unused).
 * @param size Message length (unused).
 * @return 0 if access is OK, negative error code otherwise.
 * @see CLSM_PRIV_NETCLIENT
 */
static int
clsm_socket_sendmsg(struct socket * sock, struct msghdr * msg, int size)
{
	if (unlikely(!sock->sk))
		return -EFAULT;

	if (likely(!nonlocal_family_p(sock->sk->sk_family)))
		return 0;

	if (likely(sock->state == SS_CONNECTED) && clsm_net_ok())
		return 0;

	if (clsm_net_client_ok())
		return 0;

	if (unlikely(sock->sk->sk_family == AF_NETLINK) && clsm_netlink_ok())
		return 0;

	if (unlikely(!clsm_ctl_networking))
		return 0;

	CLSM_WARN_COMM("denied %s socket send\n",
				_sock_family(sock->sk->sk_family));
	return -EPERM;
}

/**
 * Hook: check permissions for socket recv.
 * We allow receiving messages on non-local sockets to anyone with
 * either CLSM_PRIV_NETCLIENT, CLSM_PRIV_NETSERVER or CLSM_PRIV_NETOTHER.
 * @n
 * This check is much less restrictive than the sendmsg check, and is here
 * mostly for defense in depth purposes.
 * @n
 * Sending on local sockets is allowed regardless of privileges.
 * @n
 * NB : All operations are authorized when @a clsm_ctl_networking is zero
 * (debugging only).
 * @param sock Socket to receive on.
 * @param msg Transmitted message (unused).
 * @param size Transmitted message length (unused).
 * @param flags Operational flags (unused).
 * @return 0 if access is OK, negative error code otherwise.
 * @see CLSM_PRIV_NETCLIENT
 * @see CLSM_PRIV_NETSERVER
 * @see CLSM_PRIV_NETOTHER
 */
static int
clsm_socket_recvmsg(struct socket * sock, struct msghdr * msg,
							int size, int flags)
{
	if (unlikely(!sock->sk))
		return -EFAULT;

	if (likely(!nonlocal_family_p(sock->sk->sk_family)))
		return 0;

	if (clsm_net_ok())
		return 0;

	if (unlikely(sock->sk->sk_family == AF_NETLINK) && clsm_netlink_ok())
		return 0;

	if (unlikely(!clsm_ctl_networking))
		return 0;

	CLSM_WARN_COMM("denied %s socket recv\n",
				_sock_family(sock->sk->sk_family));
	return -EPERM;
}


/**
 * Check permissions for sending a message on a netlink socket.
 * The CLSM_PRIV_NETLINK privilege is required for any netlink send,
 * except for the 'read' message types on NETLINK_ROUTE sockets (which
 * are used by glibc for pretty much any network access...).
 * @param sk Netlink socket on which a message is to be sent.
 * @param skb Message to be sent.
 * @return 0 if sending is allowed, negative error code otherwise.
 */
static int
clsm_netlink_perm(struct sock *sk, struct sk_buff *skb)
{
	struct nlmsghdr *nlh;

	if (skb->len < NLMSG_SPACE(0)) {
		CLSM_WARN_COMM("insufficient netlink length: %u", skb->len);
		return -EINVAL;
	}
	nlh = nlmsg_hdr(skb);

	if (likely(sk->sk_protocol == NETLINK_ROUTE)) {
		switch (nlh->nlmsg_type) {
			case RTM_GETLINK:
			case RTM_GETADDR:
			case RTM_GETROUTE:
			case RTM_GETNEIGH:
			case RTM_GETRULE:
			case RTM_GETQDISC:
			case RTM_GETTCLASS:
			case RTM_GETTFILTER:
			case RTM_GETACTION:
			case RTM_GETANYCAST:
			case RTM_GETNEIGHTBL:
			case RTM_GETADDRLABEL:
			case RTM_GETDCB:
				return 0;
			default:
				break;
		}
	}

	if (likely(clsm_netlink_ok()))
		return 0;

	if (unlikely(!clsm_ctl_networking))
		return 0;

	CLSM_WARN_COMM("denied netlink message of type %d "
		"on %d netlink socket", nlh->nlmsg_type, sk->sk_protocol);
	return -EPERM;
}


/**
 * Hook: check permissions for netlink socket send.
 * When CLSM Networking checks are activated, this checks the sender's
 * CLSM privileges by calling @a clsm_netlink_perm().
 * @param sk Netlink socket on which a message is to be sent.
 * @param skb Message to be sent.
 * @return 0 if sending is allowed, negative error code otherwise.
 */
static int
clsm_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	return clsm_netlink_perm(sk, skb);
}

#endif /* CONFIG_CLSM_NET */

/*@}*/

#ifdef CONFIG_SECURITY_NETWORK_XFRM

/*************************************************************/
/*                  xfrm sec hooks                           */
/*************************************************************/

/** @name XFRM hooks */
/*@{*/

/** Current task has the CLSM_PRIV_XFRMSP privilege */
#define clsm_xfrm_spd_ok() \
	(((struct clsm_task_sec *)current_cred()->security)->t_privs \
		& CLSM_PRIV_XFRMSP)

/** Current task has the CLSM_PRIV_XFRMSA privilege */
#define clsm_xfrm_sad_ok() \
	(((struct clsm_task_sec *)current_cred()->security)->t_privs \
		& CLSM_PRIV_XFRMSA)

/**
 * Check privileges before adding a SP to the SPD.
 * This checks that the caller has the CLSM_PRIV_XFRMSP privilege.
 * @n
 * Not a LSM hook.
 * @param dir Direction of the SP to be added.
 * @param xp Policy to be added.
 * @return 0 if addition is authorized, -EPERM otherwise.
 */
static int
clsm_xfrm_policy_add(int dir, struct xfrm_policy *xp)
{
	if (clsm_xfrm_spd_ok())
		return 0;
	CLSM_WARN_COMM("denied SPD policy add\n");
	return -EPERM;
}

/**
 * Check privileges before removing a SP from the SPD.
 * This checks that the caller has the CLSM_PRIV_XFRMSP privilege.
 * @param xp Policy to be removed.
 * @return 0 if removal is authorized, -EPERM otherwise.
 */
static int
clsm_xfrm_policy_delete(struct xfrm_sec_ctx *ctx)
{

	if (clsm_xfrm_spd_ok())
		return 0;
	CLSM_WARN_COMM("denied SPD policy delete\n");
	return -EPERM;
}

/**
 * Check privileges before adding a SA to the SAD.
 * This checks that the caller has the CLSM_PRIV_XFRMSA privilege.
 * @n
 * Not a LSM hook.
 * @param x State to be added to the SAD.
 * @return 0 if addition is authorized, -EPERM otherwise.
 */
static int
clsm_xfrm_state_add(struct xfrm_state *x)
{

	if (clsm_xfrm_sad_ok())
		return 0;
	CLSM_WARN_COMM("denied SAD add\n");
	return -EPERM;
}

/**
 * Check privileges before removing a SA from the SAD.
 * This checks that the caller has the CLSM_PRIV_XFRMSA privilege.
 * @param x State to be removed from the SAD.
 * @return 0 if removal is authorized, -EPERM otherwise.
 */
static int
clsm_xfrm_state_delete(struct xfrm_state *x)
{
	if (clsm_xfrm_sad_ok())
		return 0;
	CLSM_WARN_COMM("denied SAD delete\n");
	return -EPERM;
}

/*@}*/

#endif /* CONFIG_SECURITY_NETWORK_XFRM */

/*************************************************************/
/*                  other sec hooks                          */
/*************************************************************/

/**
 * Hook: check permission to access kernel log buffer.
 * This restricts all operations to tasks that have either CAP_SYS_ADMIN, or
 * the vserver VXC_SYSLOG capability, or the CLSM_PRIV_KSYSLOG privilege,
 * (in that case, except for open() operations).
 * @param type Syslog operation type.
 * @return 0 if access is OK, -EPERM otherwise.
 * @see CLSM_PRIV_KSYSLOG.
 */
static int
clsm_syslog(int type)
{
	const struct clsm_task_sec *tsec = current_cred()->security;
#ifdef CONFIG_VSERVER
	if (vx_capable(CAP_SYS_ADMIN, VXC_SYSLOG))
#else
	if (capable(CAP_SYS_ADMIN))
#endif
		return 0;
	if (type != 1 && tsec->t_privs & CLSM_PRIV_KSYSLOG)
		return 0;

	CLSM_WARN_COMM("denied access (type %d) to the kernel log buffer\n",
									type);
	return -EPERM;
}

#ifdef CONFIG_VSERVER
/**
 * Hook: allow direct acces to kernel log buffer from a non-ADMIN vserver
 * context.
 * This simply bypasses the call to vx_do_syslog().
 * @n Not an original LSM hook.
 * @param type Syslog operation type.
 * @return 0 if direct access is allowed, -EPERM otherwise.
 */
static int
clsm_syslog_vserver(int type)
{
	const struct clsm_task_sec *tsec = current_cred()->security;

	if (type != 1 && tsec->t_privs & CLSM_PRIV_KSYSLOG)
		return 0;
	else
		return -EPERM;
}
#endif

/**
 * Check permission before allowing a userland task to write
 * firmware microcode to a sysfs 'device'.
 * This limits such write access to holders of either CAP_SYS_RAWIO
 * or CLSM_PRIV_FIRMWARE.
 * @return 0 if access is OK, -EPERM otherwise.
 */
static int
clsm_firmware_write(void)
{
	const struct clsm_task_sec *tsec = current_cred()->security;

	if (capable(CAP_SYS_RAWIO))
		return 0;

	if (tsec->t_privs & CLSM_PRIV_FIRMWARE)
		return 0;

	CLSM_WARN_COMM("denied firmware write access");
	return -EPERM;
}

/*************************************************************/
/*                       LSM interface                       */
/*************************************************************/

/**  CLIP security hooks **/
static struct security_hook_list clsm_hooks[] = {
	/* Standard commoncap.c */
	LSM_HOOK_INIT(capget,clsm_capget),
	LSM_HOOK_INIT(capset,clsm_capset),
	LSM_HOOK_INIT(capable,clsm_capable),
	LSM_HOOK_INIT(settime,clsm_settime),
	LSM_HOOK_INIT(vm_enough_memory,clsm_vm_enough_memory),

	LSM_HOOK_INIT(inode_setxattr,clsm_inode_setxattr),
	LSM_HOOK_INIT(inode_removexattr,clsm_inode_removexattr),

	LSM_HOOK_INIT(inode_need_killpriv,clsm_inode_need_killpriv),
	LSM_HOOK_INIT(inode_killpriv,clsm_inode_killpriv),

	/* CLSM specific */

	/* bprm */
	LSM_HOOK_INIT(bprm_set_creds,clsm_bprm_set_creds),
	LSM_HOOK_INIT(bprm_secureexec,clsm_bprm_secureexec),


	/* file */
	LSM_HOOK_INIT(file_free_security,clsm_file_free_security),
#ifdef CONFIG_VERIEXEC
	LSM_HOOK_INIT(mmap_addr,clsm_mmap_addr),
	LSM_HOOK_INIT(mmap_file,clsm_mmap_file),
	LSM_HOOK_INIT(file_mprotect,clsm_file_mprotect),
#endif
	LSM_HOOK_INIT(file_alloc_security, clsm_file_alloc_security),
	LSM_HOOK_INIT(file_set_fowner,clsm_file_set_fowner),
	LSM_HOOK_INIT(file_send_sigiotask,clsm_file_send_sigiotask),
#ifdef CONFIG_CLSM_CHROOT_SOCKFD
	LSM_HOOK_INIT(file_receive,clsm_file_receive),
#endif
	LSM_HOOK_INIT(file_lock,clsm_file_lock),
	/* CLIP-specific */
#ifdef CONFIG_VERIEXEC
	LSM_HOOK_INIT(fhandle_to_path,clsm_fhandle_to_path),
	LSM_HOOK_INIT(file_map_exec,clsm_file_map_exec),
	LSM_HOOK_INIT(file_interpreter,clsm_file_interpreter),
#endif
	LSM_HOOK_INIT(file_fsignum,clsm_file_fsignum),
	LSM_HOOK_INIT(file_swapon,clsm_file_swapon),

	LSM_HOOK_INIT(mem_access,clsm_mem_access),
	LSM_HOOK_INIT(drm_access,clsm_drm_access),

	/* path */
#ifdef CONFIG_CLSM_FSTRACE
	LSM_HOOK_INIT(path_mknod,clsm_path_mknod),
#endif

	/* inode */
	LSM_HOOK_INIT(inode_free_security,clsm_inode_free_security),
#ifdef CONFIG_CLSM_MOUNT
	LSM_HOOK_INIT(inode_permission,clsm_inode_permission),
	/* CLIP-specific */
	LSM_HOOK_INIT(inode_blkdev_open,clsm_inode_blkdev_open),
#endif
	LSM_HOOK_INIT(inode_memdev_open,clsm_inode_memdev_open),
#ifdef CONFIG_VERIEXEC
	LSM_HOOK_INIT(inode_write_access,clsm_inode_write_access),
	LSM_HOOK_INIT(inode_privileged_binary,clsm_inode_privileged_binary),
#endif

	/* task */
	LSM_HOOK_INIT(cred_prepare,clsm_cred_prepare),
	LSM_HOOK_INIT(cred_free,clsm_cred_free),
	LSM_HOOK_INIT(task_fix_setuid,clsm_task_fix_setuid),
	LSM_HOOK_INIT(task_kill,clsm_task_kill),
	LSM_HOOK_INIT(task_setscheduler,clsm_task_setscheduler),
	LSM_HOOK_INIT(task_setnice,clsm_task_setnice),
	LSM_HOOK_INIT(task_prctl,clsm_task_prctl),
	LSM_HOOK_INIT(task_setioprio,clsm_task_setioprio),
	/* CLIP-specific */
#ifdef CONFIG_VSERVER
	LSM_HOOK_INIT(task_ctx_migrate,clsm_task_ctx_migrate),
	LSM_HOOK_INIT(task_ctx_migrated,clsm_task_ctx_migrated),
	LSM_HOOK_INIT(task_kill_vserver,clsm_task_kill_vserver),
#endif
	LSM_HOOK_INIT(task_chroot,clsm_task_chroot),
	LSM_HOOK_INIT(task_chrooted,clsm_task_chrooted),
	LSM_HOOK_INIT(task_unshare_ns,clsm_task_unshare_ns),
	LSM_HOOK_INIT(task_badness,clsm_task_badness),
	LSM_HOOK_INIT(task_oomadj,clsm_task_oomadj),
	LSM_HOOK_INIT(task_proc_pid,clsm_task_proc_pid),
	LSM_HOOK_INIT(task_procfd,clsm_task_procfd),

	/* socket */
#ifdef CONFIG_CLSM_NET
	LSM_HOOK_INIT(socket_create,clsm_socket_create),
	LSM_HOOK_INIT(socket_bind,clsm_socket_bind),
	LSM_HOOK_INIT(socket_connect,clsm_socket_connect),
	LSM_HOOK_INIT(socket_listen,clsm_socket_listen),
	LSM_HOOK_INIT(socket_accept,clsm_socket_accept),
	LSM_HOOK_INIT(socket_sendmsg,clsm_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg,clsm_socket_recvmsg),
	LSM_HOOK_INIT(netlink_send,clsm_netlink_send),

#endif /* CONFIG_CLSM_NET */
	/* xfrm */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	LSM_HOOK_INIT(xfrm_policy_delete_security,clsm_xfrm_policy_delete),
	LSM_HOOK_INIT(xfrm_state_delete_security,clsm_xfrm_state_delete),
	/* CLIP-specific */
	LSM_HOOK_INIT(xfrm_policy_add,clsm_xfrm_policy_add),
	LSM_HOOK_INIT(xfrm_state_add,clsm_xfrm_state_add),
#endif /* CONFIG_SECURITY_NETWORK_XFRM */

	/* superblock */
#ifdef CONFIG_CLSM_MOUNT
	LSM_HOOK_INIT(sb_mount,clsm_sb_mount),
	LSM_HOOK_INIT(sb_pivotroot,clsm_sb_pivotroot),
	LSM_HOOK_INIT(sb_check_sb,clsm_sb_check_sb),
#endif /* CONFIG_CLSM_MOUNT */
	LSM_HOOK_INIT(sb_mount_permission,clsm_sb_mount_permission),

	/* other */
	LSM_HOOK_INIT(ptrace_access_check,clsm_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme,clsm_ptrace_traceme),
	LSM_HOOK_INIT(syslog,clsm_syslog),
	/* CLIP-specific */
	LSM_HOOK_INIT(inotify_addwatch,clsm_inotify_addwatch),
#ifdef CONFIG_VSERVER
	LSM_HOOK_INIT(syslog_vserver,clsm_syslog_vserver),
#endif
	LSM_HOOK_INIT(firmware_write,clsm_firmware_write),

};

/** Destroy all kmem_caches used for security tag allocation */
#define __cleanup_caches() do { \
	if (g_tcache) { \
		kmem_cache_destroy(g_tcache); \
		g_tcache = 0; \
	} \
	if (g_fcache) { \
		kmem_cache_destroy(g_fcache); \
		g_fcache = 0; \
	} \
	if (g_icache) { \
		kmem_cache_destroy(g_icache); \
		g_icache = 0; \
	} \
} while (0)

/**
 * Initialise CLIP-LSM subsystem.
 * This initializes the CLIP-LSM sysctl variables, and the security tags
 * kmem_caches (see the @ref kmem_caches section), then calls the initilization
 * functions for veriexec and devctl, before registering the new security
 * framework.
 * @return 0 on success, negative error code on failure.
 */
static __init int clsm_init(void)
{
	int ret;

	if (clsm_init_sysctl()) {
		CLSM_ERROR("Could not init sysctls\n");
		return -EFAULT;
	}

	g_tcache = kmem_cache_create("clsm_tcache",
					sizeof(struct clsm_task_sec),
					0, SLAB_PANIC, NULL);
	g_fcache = kmem_cache_create("clsm_fcache",
					sizeof(struct clsm_file_sec),
					0, SLAB_PANIC, NULL);
	g_icache = kmem_cache_create("clsm_icache",
					sizeof(struct clsm_inode_sec),
					0, SLAB_PANIC, NULL);

	if (!g_tcache || !g_fcache || !g_icache) {
		CLSM_ERROR("Could not init LSM kmem_caches\n");
		__cleanup_caches();
		return -ENOMEM;
	}

#ifdef CONFIG_VERIEXEC
	ret = veriexec_init();
	if (ret) {
		CLSM_ERROR("Could not init VERIEXEC\n");
		return ret;
	}
#endif /* CONFIG_VERIEXEC */

#ifdef CONFIG_DEVCTL
	ret = devctl_init();
	if (ret) {
		CLSM_ERROR("Could not init DEVCTL\n");
		return ret;
	}
#endif /* CONFIG_DEVCTL */

#ifdef CONFIG_CLIP_LSM
	/* register hooks with the security framework */
	security_add_hooks(clsm_hooks, ARRAY_SIZE(clsm_hooks));
#endif

	printk (KERN_INFO "CLIP LSM initialized\n");
	return 0;
}

/**
 * Termination function.
 */
static void
clsm_exit(void)
{
	BUG(); /* This is not supported yet, and probably never will be. */
}

/**
 * Initialize the miscellaneous CLIP-LSM devices.
 * This is different from clsm_init() in that it is a late_initcall,
 * whereas clsm_init() is a security_initcall. This splitting is required
 * since the mem_device class needs to be initialized before the LSM
 * device initialization.
 * @return 0 on success, negative error code on failure.
 */
static int __init
clsm_device_init(void)
{
	int ret;

	ret = clsm_init_sysctl_table();
	if (ret)
		goto err;
#ifdef CONFIG_VERIEXEC
	ret = veriexec_device_init();
	if (ret)
		goto err;
#endif
#ifdef CONFIG_DEVCTL
	ret = devctl_device_init();
	if (ret)
		goto err;
#endif
	return 0;
err:
	clsm_exit();
	return ret;
}

#ifndef CONFIG_CLIP_LSM /* Not useful if clsm is built-in */

/**
 * Module initialization routine.
 * We need a unique entry point when loaded as a module, and there is
 * no need to differentiate between security/late initcalls.
 * @return 0 on success, negative error code on failure.
 */
static __init int clsm_module_init(void)
{
	int ret;
	struct task_struct *p;

	might_sleep();

	printk(KERN_INFO "CLIP-LSM module loading\n");
	ret = clsm_init();
	if (ret) {
		return ret;
	}

#ifdef CONFIG_CLSM_FSTRACE_HASH
	mutex_init(&fstrace_mutex);
	fstrace_tfm = crypto_alloc_hash(FSTRACE_HASH_ALG, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(fstrace_tfm)) {
		CLSM_ERROR("could not init fstrace hash transform");
		ret = PTR_ERR(fstrace_tfm);
		fstrace_tfm = NULL;
		goto err;
	}
#endif /* CONFIG_CLSM_FSTRACE_HASH */

	/*
	 * Block all forks until we can be sure that all our
	 * tasks have been tagged, and the task_alloc() hook
	 * is in place.
	 */
	down_write(&security_sem);
	for_each_process(p) {
		ret = clsm_task_init_security(p);
		if (ret) {
			up_write(&security_sem);
			CLSM_ERROR("could not init security for a task\n");
			goto err;
		}
	}

	/* register hooks with the security framework */
	security_add_hooks(clsm_hooks, ARRAY_SIZE(clsm_hooks));

	up_write(&security_sem);

	ret = clsm_device_init();
	if (ret) {
		CLSM_ERROR("could not initialize devices\n");
		goto err;
	}

	return 0;
err:
	clsm_exit();
	return ret;
}
#endif


#ifdef CONFIG_CLIP_LSM
security_initcall(clsm_init);
late_initcall(clsm_device_init);
#else
module_init (clsm_module_init);
module_exit (clsm_exit);
#endif


EXPORT_SYMBOL(clsm_priv_map);
EXPORT_SYMBOL(clsm_flag_map);
MODULE_AUTHOR("Vincent Strubel <clipos@ssi.gouv.fr>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CLIP LSM, with commoncap + veriexec specific checks");
