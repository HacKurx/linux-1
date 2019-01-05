// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file security_clsm.h
 *  CLIP Linux Security Module complementary security hooks
 *  prototypes.
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2009 SGDN/DCSSI
 *  Copyright (C) 2010-2011 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#ifndef _LINUX_SECURITY_CLSM_H
#define _LINUX_SECURITY_CLSM_H

/**
 * Mutex blocking task cred modifications while CLIP LSM
 * is being loaded and task tags are being allocated.
 */
extern struct rw_semaphore security_sem;


/*
 * CLSM-specific struct security_operations fields.
 */

/* Hook prototypes */

/*
 * Security hooks for filesystem operations.
 */

#define SECURITY_MOUNT_NEW	0x01 /**< New mount (do_new_mount) */
#define SECURITY_MOUNT_REMOUNT	0x02 /**< Remount (do_remount) */
#define SECURITY_MOUNT_BIND	0x04 /**< Loopback/bind (do_loopback) */
#define SECURITY_MOUNT_TYPE	0x08 /**< Type change (do_change_type) */
#define SECURITY_MOUNT_MOVE	0x10 /**< Mount move (do_move_mount) */
#define SECURITY_MOUNT_UMOUNT	0x20 /**< Unmount (do_umount) */
#define SECURITY_MOUNT_BINARY	0x40 /**< Special case for vserver
					  - check for VXC_BINARY_MOUNT */

#ifdef CONFIG_VSERVER
/**
 * Helper - return VXC capability associated with a given mount operation.
 * @param op Type of operation.
 */
uint32_t security_mountop2vxc(int op);
#endif

/*
 * Security hooks for superblock operations.
 */

/**
 * Check permissions (capabilities) before performing
 * a mount (new, move, remount, umount, etc.) operation.
 * @param op Type of operation.
 * @param path Path of the mount operation.
 */
int security_sb_mount_permission(int op, const struct path *path);

/**
 * Check permission before the device with superblock @mnt->sb is mounted
 * on the mount point named by @dentry.
 * @mnt contains the vfsmount for device being mounted.
 * @dentry  contains the mount point dentry.
 * Return 0 if permission is granted.
 */
int security_sb_check_sb(struct vfsmount *mnt, struct dentry *dentry);

/*
 * Security hooks for inode operations.
 */

/**
 * Check permissions before opening a block device
 * @param inode contains the inode structure for the block device
 * @param mask contains the requested access mode
 */
int security_inode_blkdev_open(struct inode *inode, int mask);

/**
 * Open wrapper for custom LSM memory devices (MEM_MAJOR).
 * Returns 0 when a custom device is found matching the requested minor,
 * and sets the file_operations for this device.
 * @param inode contains the inode structure for the memory char device
 * @param filp contains the file structure for the memory char device. The
 * file_operations pointer in that file must be set to the custom device's
 * operations if a match is found.
 */
int security_inode_memdev_open(struct inode *inode, struct file *filp);

/**
 * Update an inode's security information when write access is
 * granted to it.
 * Called with @a inode->i_lock held.
 * @param inode contains the inode structure to which write access is granted.
 */
int security_inode_write_access(struct inode *inode);

/**
 * Check if an inode is a privileged binary.
 * Returns 0 if it is not a privileged binary, non-zero otherwise.
 * @param dentry Dentry for the inode to test.
 */
int security_inode_privileged_binary(const struct dentry *dentry);

/*
 * Security hooks for file operations
 */

/**
 * Check permissions before converting a file handle to a path
 * @param dirfd Mount directory fd for conversion.
 * @param handle File handle to convert.
 */
int security_fhandle_to_path(int dirfd, struct file_handle *handle);

/**
 * Check permissions for a non-anonymous mmap/mprotect(PROT_EXEC) operation.
 * This differs from the @a file_mmap/mprotect hooks in that it is called
 * later on, right before the mapping is to be created or updated.
 * This allows, for example, to deny writes to the underlying file.
 * @param file contains the file structure for the file to map (never NULL).
 */
int security_file_map_exec(struct vm_area_struct *vma);


/**
 * Update an execve()ing task's security information based on its
 * interpreter.
 * @param bprm contains the bprm being execve()d.
 * @param file contains the file structure for the interpreter.
 */
int security_file_interpreter(struct linux_binprm *bprm, struct file *file);


/**
 * Check the caller's security information before setting the file I/O
 * signal number on a file, and update that file's security information.
 * @param file contains the file structure for which the signum is being set.
 * @param sig contains the signal number being set on file.
 */
int security_file_fsignum(struct file *file, int sig);


/**
 * Check permission before creating a swap.
 * @param file contains the file backing the swap.
 * @param name contains the path under which @file was opened.
 */
int security_file_swapon(struct file *file, const char *name);

#define SECURITY_MEM_OPEN	0x01 	/**< Open /dev/{k,}mem */
#define SECURITY_PORT_OPEN	0x02	/**< Open /dev/port */
#define SECURITY_MEM_WRITE	0x04	/**< Write to /dev/mem */
#define SECURITY_KMEM_WRITE	0x08	/**< Write to /dev/kmem */
#define SECURITY_MEM_MMAP	0x10	/**< Mmap /dev/mem */
#define SECURITY_KMEM_MMAP	0x20	/**< Mmap /dev/kmem */
#define SECURITY_MEM_READ	0x40	/**< Read /dev/mem */
#define SECURITY_KMEM_READ	0x80	/**< Read /dev/kmem */
#define SECURITY_IO_IOPL	0x100	/**< Turn on iopl() */
#define SECURITY_IO_IOPERM	0x200	/**< Turn on ioperm() */

/**
 * Check permissions before accessing /dev/{mem,kmem,ports}
 * an I/O bits.
 * @param file contains the file to be accessed (might be NULL)
 * @param op contains the operation to be performed.
 */
int security_mem_access(struct file *file, int op);


/**
 * Check permissions before allowing privileged drm ioctl.
 * @param flags drm ioctl flags.
 */
int security_drm_access(int flags);

/**
 * Check permission to add an inotify watch on a file.
 * @param path contains the path for the target file.
 */
int security_inotify_addwatch(const struct path *path);


/*
 * Security hooks for task operations
 */

#ifdef CONFIG_VSERVER

/**
 * Return the new credentials to be applied to a task after migrating
 * into a vserver context.
 * @param tsk contains the task_struct for the task to migrate
 */
struct cred * security_task_ctx_migrate(struct task_struct *tsk);

/**
 * Check if the current task has migrated into a vserver context
 * and not execve()d since then.
 * @param tsk contains the task_struct for the task to check
 */
int security_task_ctx_migrated(void);

/**
 * Allow a non-ADMIN vserver task to send a signal to another context.
 * @param p contains the task sending the signal
 * @param c contains the task targeted by the signal
 * @param sig contains the signal number
 */
int security_task_kill_vserver(struct task_struct *p,
				struct task_struct *c, int sig);

#endif /* CONFIG_VSERVER */

/**
 * Check and update current security attributes before a chroot call.
 */
int security_task_chroot(void);

/**
 * Check if a task is chrooted in its namespace.
 * @param tsk contains the task_struct for the task to check.
 */
int security_task_chrooted(const struct task_struct *tsk);

/**
 * Check permissions for current task changing its namespaces,
 * either through clone() or unshare().
 * @param flags Bitmask of namespaces to be unshared (CLONE_NEWNS, etc.)
 */
int security_task_unshare_ns(unsigned long flags);

/**
 * Return a non-null task badness divider for the OOM killer, based on a
 * task's security attributes.
 * @param tsk contains the task to evaluate badness for
 */
unsigned long security_task_badness(const struct task_struct *tsk);

/**
 * Check permissions before changing a task's oom adjust.
 * @param tsk contains the task being adjusted
 * @param oomadj contains the new oom adjust value
 */
int security_task_oomadj(const struct task_struct *tsk, int oomadj);

/**
 * Display a task's security attributes in its /proc/<pid>/status entry.
 * @param m contains the seq_file to display to
 * @param tsk contains the task_struct for the task to display.
 */
void security_task_proc_pid(struct seq_file *m, struct task_struct *tsk);

/**
 * Check permission to access /proc/<pid>/fd without CAP_SYS_PTRACE.
 * @param c contains the task_struct for the task whose proc file is accessed.
 * @param log wether denied accesses should be logged
 */
int security_task_procfd(struct task_struct *c, int log);

/*
 * Security hooks for XFRM operations.
 */

struct xfrm_policy;
struct xfrm_state;

#ifdef CONFIG_SECURITY_NETWORK_XFRM

/**
 * Check privileges before spd policy insertion
 * @param dir contains the policy direction
 * @param policy contains the policy to be inserted
 */
int security_xfrm_policy_add(int dir, struct xfrm_policy *policy);
/**
 * Check privileges before sadb insertion
 * @param state contains the state to be added
 */
int security_xfrm_state_add(struct xfrm_state *state);

#else /* ! CONFIG_SECURITY_NETWORK_XFRM */

/**
 * Check privileges before spd policy insertion
 * @param dir contains the policy direction
 * @param policy contains the policy to be inserted
 */
static inline int security_xfrm_policy_add(int dir, struct xfrm_policy *policy)
{
	return 0;
}

/**
 * Check privileges before sadb insertion
 * @param state contains the state to be added
 */
static inline int security_xfrm_state_add(struct xfrm_state *state)
{
	return 0;
}
#endif /* ! CONFIG_SECURITY_NETWORK_XFRM */

/*
 * Miscellaneous security hooks.
 */

#ifdef CONFIG_VSERVER
/**
 * Allow acces to the kernel message ring from a non-ADMIN vserver context.
 * @param type contains the type of action
 */
int security_syslog_vserver(int type);
#endif

/**
 * Allow a userspace task to write firmware ucode to a sysfs device.
 */
int security_firmware_write(void);

#define CLSM_HOOKS_BASE \
	int (*sb_mount_permission)(int op, const struct path *path); \
	int (*sb_check_sb)(struct vfsmount *mnt, struct dentry *dentry); \
	int (*inotify_addwatch)(const struct path *path); \
	int (*inode_blkdev_open)(struct inode *inode, int mask); \
	int (*inode_memdev_open)(struct inode *inode, struct file *filp); \
	int (*inode_write_access)(struct inode *inode); \
	int (*inode_privileged_binary)(const struct dentry *dentry); \
	int (*fhandle_to_path)(int dirfd, struct file_handle *handle); \
	int (*file_map_exec)(struct vm_area_struct * vma); \
	int (*file_interpreter)(struct linux_binprm * bprm, \
					struct file  *file); \
	int (*file_fsignum)(struct file *file, int sig); \
	int (*file_swapon)(struct file *file, const char *name); \
	int (*mem_access)(struct file *file, int op); \
	int (*drm_access)(int nr, int flags); \
	int (*task_chroot)(void); \
	int (*task_chrooted)(const struct task_struct * tsk); \
	int (*task_unshare_ns)(unsigned long flags); \
	unsigned long (*task_badness)(const struct task_struct * tsk); \
	int (*task_oomadj)(const struct task_struct * tsk, int oomadj); \
	void (*task_proc_pid)(struct seq_file *m, struct task_struct * tsk); \
	int (*task_procfd)(struct task_struct *c, int log); \
	int (*firmware_write)(void);

#ifdef CONFIG_VSERVER
#define CLSM_HOOKS_VSERVER \
	int (*syslog_vserver)(int type); \
	struct cred * (*task_ctx_migrate)(struct task_struct *tsk); \
	int (*task_ctx_migrated)(void); \
	int (*task_kill_vserver)(struct task_struct *p, \
				struct task_struct *c, int sig);
#else
#define CLSM_HOOKS_VSERVER
#endif

#ifdef CONFIG_SECURITY_NETWORK_XFRM
#define CLSM_HOOKS_XFRM \
	int (*xfrm_policy_add)(int dir, struct xfrm_policy *policy); \
	int (*xfrm_state_add)(struct xfrm_state *state);
#else
#define CLSM_HOOKS_XFRM
#endif

#define CLSM_HOOKS \
		CLSM_HOOKS_BASE \
		CLSM_HOOKS_VSERVER \
		CLSM_HOOKS_XFRM



#endif /* _LINUX_SECURITY_CLSM_H */
