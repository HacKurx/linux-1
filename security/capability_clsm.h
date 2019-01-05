// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file capability_clsm.h
 *  CLIP Linux Security Module complementary security hooks
 *  default implementation for the capabilities LSM.
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2009 SGDN/DCSSI
 *  Copyright (C) 2010-2011 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#include <linux/pid_namespace.h>

/*
 * Filesystem hooks.
 */

static inline int
cap_sb_mount_permission(int op, const struct path *path)
{
#ifdef CONFIG_VSERVER
	uint32_t vxcap = security_mountop2vxc(op);
	if (vxcap)
		return (vx_capable(CAP_SYS_ADMIN, vxcap)) ? 0 : -EPERM;
	else
		return (capable(CAP_SYS_ADMIN)) ? 0 : -EPERM;
#else
	return (capable(CAP_SYS_ADMIN)) ? 0 : -EPERM;
#endif
}

static inline int
cap_sb_check_sb(struct vfsmount *mnt, struct dentry *dentry)
{
	return 0;
}

/*
 * Inode hooks.
 */

int
cap_inode_blkdev_open(struct inode *inode, int mask)
{
	return 0;
}

int
cap_inode_memdev_open(struct inode *inode, struct file *filp)
{
	return -ENXIO;
}

int
cap_inode_write_access(struct inode *inode)
{
	return 0;
}

int
cap_inode_privileged_binary(const struct dentry *dentry)
{
	return 0;
}

/*
 * File hooks.
 */

int
cap_inotify_addwatch(const struct path *path)
{
	return 0;
}

int
cap_fhandle_to_path(int dirfd, struct file_handle *handle)
{
	return 0;
}

int
cap_file_map_exec(struct vm_area_struct *vma)
{
	return 0;
}

int
cap_file_interpreter(struct linux_binprm *bprm, struct file *file)
{
	return 0;
}

int
cap_file_fsignum(struct file *file, int sig)
{
	return 0;
}

int
cap_file_swapon(struct file *file, const char *name)
{
	return 0;
}

int
cap_mem_access(struct file *filp, int op)
{
	return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}

int
cap_drm_access(int flags)
{
	return capable(CAP_SYS_ADMIN) ? 0 : -EPERM;
}

/*
 * Task hooks.
 */
#ifdef CONFIG_VSERVER

struct cred *
cap_task_ctx_migrate(struct task_struct *tsk)
{
	return prepare_creds();
}

int
cap_task_ctx_migrated(void)
{
	return 0;
}

int
cap_task_kill_vserver(struct task_struct *p, struct task_struct *c, int sig)
{
	return -EPERM;
}

#endif /* CONFIG_VSERVER */

int
cap_task_chroot(void)
{
	return 0;
}

int
cap_task_chrooted(const struct task_struct *tsk)
{
#ifdef CONFIG_GRKERNSEC
	return tsk->gr_is_chrooted;
#else
	return 0;
#endif
}

int
cap_task_unshare_ns(unsigned long flags)
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

unsigned long
cap_task_badness(const struct task_struct *tsk)
{
	return 1UL;
}

int
cap_task_oomadj(const struct task_struct *tsk, int adj)
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

void
cap_task_proc_pid(struct seq_file *m, struct task_struct *tsk)
{ }

int
cap_task_procfd(struct task_struct *c, int log)
{
	return 0;
}


/*
 * XFRM hooks.
 */

#ifdef CONFIG_SECURITY_NETWORK_XFRM

int
cap_xfrm_policy_add(int dir, struct xfrm_policy *policy)
{
	return 0;
}

int
cap_xfrm_state_add(struct xfrm_state *state)
{
	return 0;
}

#endif	/* CONFIG_SECURITY_NETWORK_XFRM */

/*
 * Misc hooks.
 */

int
cap_syslog_vserver(int type)
{
	return -EPERM;
}

int
cap_firmware_write(void)
{
	if (capable(CAP_SYS_RAWIO))
		return 0;
	return -EPERM;
}
