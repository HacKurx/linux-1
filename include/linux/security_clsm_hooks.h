// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file security_clsm_hooks.h
 *  CLIP Linux Security Module complementary security hooks
 *  default inline implementation.
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2009 SGDN/DCSSI
 *  Copyright (C) 2010-2014 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#ifndef _LINUX_SECURITY_CLSM_HOOKS_H
#define _LINUX_SECURITY_CLSM_HOOKS_H

#ifndef CONFIG_SECURITY

/*
 * Filesystem hooks.
 */
static inline int
security_mount_permission(int op, const struct path *path)
{
#ifdef CONFIG_VSERVER
	uint32_t vxcap = security_mountop2vxc(op);
	if (!vxcap)
		return -EINVAL;

	return (vx_capable(CAP_SYS_ADMIN, vxcap)) ? 0 : -EPERM;
#else
	return (capable(CAP_SYS_ADMIN)) ? 0 : -EPERM;
#endif
}

static inline int
security_sb_check_sb(struct vfsmount *mnt, struct dentry *dentry)
{
	return 0;
}

/*
 * Inode hooks.
 */
static inline int
security_inode_blkdev_open(struct inode *inode, int mask)
{
	return 0;
}

static inline int
security_inode_memdev_open(struct inode *inode, struct file *filp)
{
	return -ENXIO;
}

static inline int
security_inode_write_access(struct inode *inode)
{
	return 0;
}

static inline int
security_inode_privileged_binary(const struct dentry *dentry)
{
	return 0;
}

/*
 * File hooks.
 */

static inline int
security_fhandle_to_path(int dirfd, struct file_handle *handle)
{
	return 0;
}

static inline int
security_file_map_exec(struct vm_area_struct *vma)
{
	return 0;
}

static inline int
security_file_interpreter(struct linux_binprm *bprm,
		struct file *file)
{
	return 0;
}

static inline int
security_file_fsignum(struct file *file, int sig)
{
	return 0;
}

static inline int
security_file_swapon(struct file *file, const char *name)
{
	return 0;
}

static inline int
security_mem_access(struct file *file, int op)
{
	return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}

static inline int
security_drm_access(int nr, int flags)
{
	return capable(CAP_SYS_ADMIN) ? 0 : -EPERM;
}

static inline int
security_inotify_addwatch(const struct path *path)
{
	return 0;
}

/*
 * Task hooks.
 */

#ifdef CONFIG_VSERVER
static inline struct cred *
security_task_ctx_migrate(struct task_struct *tsk) {
	return prepare_creds();
}

static inline int
security_task_ctx_migrated(void)
{
	return 0;
}

static inline int
security_task_kill_vserver(struct task_struct *p,
					struct task_struct *c, int sig)
{
	return -EPERM;
}

#endif

static inline int
security_task_chroot(void);
{
	return 0;
}

static inline int
security_task_chrooted(const struct task_struct *tsk)
{
#ifdef CONFIG_GRKERNSEC
	return tsk->gr_is_chrooted;
#else
	return 0;
#endif
}

static inline int
security_task_unshare_ns(unsigned long flags)
{
#ifdef CONFIG_VSERVER
	if (!vx_can_unshare(CAP_SYS_ADMIN, flags))
		return -EPERM;
#else
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
#endif
	return 0;
}

static inline unsigned long
security_task_badness(const struct task_struct *tsk)
{
	return 1UL;
}

static inline int
security_task_oomadj(const struct task_struct *tsk, int adj)
{
	int floor = tsk->signal->oom_score_adj_min;
#ifdef CONFIG_VSERVER
	if (adj < floor && !vx_capable(CAP_SYS_RESOURCE, VXC_OOM_ADJUST))
		return -EPERM;
#else
	if (adj < floor && !capable(CAP_SYS_RESOURCE))
		return -EPERM;
#endif
	return 0;
}

static inline void
security_task_proc_pid(struct seq_file *m, struct task_struct *tsk)
{ }

static inline int
security_task_procfd(struct task_struct *c, int log)
{
	return 0;
}

/*
 * XFRM hooks.
 */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
static inline int security_xfrm_policy_add(int dir, struct xfrm_policy *policy)
{
	return 0;
}

static inline int security_xfrm_state_add(struct xfrm_state *state)
{
	return 0;
}
#endif

/*
 * Misc hooks.
 */
#ifdef CONFIG_VSERVER
static inline int security_syslog_vserver(int type)
{
	return 0;
}
#endif

static inline int security_firmware_write(void)
{
	if (capable(CAP_SYS_RAWIO))
		return 0;
	return -EPERM;
}

#endif /* ! CONFIG_SECURITY */


#endif /* _LINUX_SECURITY_CLSM_HOOKS_H */
