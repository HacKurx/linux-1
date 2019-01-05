// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file clip_lsm.h
 *  CLIP Linux Security Module header
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2009 SGDN/DCSSI
 *  Copyright (C) 2010-2011 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#ifndef _LINUX_CLIP_LSM_H
#define _LINUX_CLIP_LSM_H

#ifdef __KERNEL__
/** Mapped to __user only for kernel compilation */
#define __userarg __user
#else
#define __userarg
#endif


/*************************************************************/
/*                    clsm privileges                        */
/*************************************************************/

/** CLSM privileges.
 * Significant bits are listed in the @ref clsm_flags section
 */
typedef unsigned long clsm_privs_t;

/** @name CLSM Privileges */
/*@{*/
/** @defgroup clsm_privs CLSM Privileges */
/*@{*/
#define CLSM_PRIV_NONE		0x0000	/**< Nuthin */
#define CLSM_PRIV_CHROOT	0x0001	/**< Bypass clsm checks
                                                   on chroot call */
#define CLSM_PRIV_VERICTL	0x0002	/**< Veriexec admin */
#define CLSM_PRIV_NETCLIENT	0x0004	/**< Network connect */
#define CLSM_PRIV_NETSERVER	0x0008	/**< Network bind */
#define CLSM_PRIV_NETOTHER	0x0010	/**< Other network ops :
						   create socket */
#define CLSM_PRIV_PROCFD	0x0020	/**< Access /proc/[pid]/fd/X
						   without CAP_SYS_PTRACE */
#define CLSM_PRIV_SIGUSR	0x0040	/**< Send SIGUSR back to
						   ADMIN ctx from non-admin */
#define CLSM_PRIV_RECVSIG	0x0080	/**< Receive SIGUSR from task
						   with CLSM_PRIV_SIGUSR */
#define CLSM_PRIV_NETLINK	0x0100	/**< Create Netlink socket */

#define CLSM_PRIV_KSYSLOG	0x0200	/**< Perform syslog() actions
						   other than 3 or 10, without
						   CAP_SYS_ADMIN */

#define CLSM_PRIV_IMMORTAL	0x0400	/**< Cannot be killed except by
						   init */

#define CLSM_PRIV_KEEPPRIV	0x0800	/**< Keep privs through a setuid
						   or chcontext */

#define CLSM_PRIV_XFRMSP	0x1000	/**< SPD add /delete */

#define CLSM_PRIV_XFRMSA	0x2000	/**< SAD add /delete */

#define CLSM_PRIV_FIRMWARE	0x4000	/**< Load firmware without
						   CAP_SYS_RAWIO */

#define CLSM_PRIV_PREINIT	0x8000	/**< Task started before LSM was
					   registered, and has not called
					   exec() since then. */

#define CLSM_PRIV_DRM		0x00010000 /**< Allows DRM root
					      operations without
					      CAP_SYS_ADMIN. */

#define CLSM_PRIV_FUSE		0x00020000 /**< Allows FUSE mount
						operations.  */

#define CLSM_PRIV_NETLINK_AUDIT	0x00040000 /**< Allows Netlink operations
						on NETLINK_AUDIT family.  */
#define CLSM_PRIV_UNSHARE	0x00080000 /**< Allows unshare() without
						CAP_SYS_ADMIN.  */


/**
 * Mask matching all valid CLSM privileges.
 */
#define CLSM_PRIV_MASK ( \
		CLSM_PRIV_NONE			| \
		CLSM_PRIV_CHROOT		| \
		CLSM_PRIV_VERICTL		| \
		CLSM_PRIV_NETCLIENT		| \
		CLSM_PRIV_NETSERVER		| \
		CLSM_PRIV_NETOTHER		| \
		CLSM_PRIV_PROCFD		| \
		CLSM_PRIV_SIGUSR		| \
		CLSM_PRIV_RECVSIG		| \
		CLSM_PRIV_NETLINK		| \
		CLSM_PRIV_KSYSLOG		| \
		CLSM_PRIV_IMMORTAL		| \
		CLSM_PRIV_KEEPPRIV		| \
		CLSM_PRIV_XFRMSP		| \
		CLSM_PRIV_XFRMSA		| \
		CLSM_PRIV_FIRMWARE		| \
		CLSM_PRIV_PREINIT		| \
		CLSM_PRIV_DRM			| \
		CLSM_PRIV_FUSE			| \
		CLSM_PRIV_NETLINK_AUDIT		| \
		CLSM_PRIV_UNSHARE		\
	)

/**
 * Check if a CLSM privilege mask is valid.
 */
#define CLSM_PRIV_VALID(privs) \
		( ((privs) & CLSM_PRIV_MASK) == (privs))

/**
 * Map CLSM privs to keyletters for display.
 */
#define DEFINE_CLSM_PRIV_MAP { \
	{ CLSM_PRIV_NONE		, '-'}, \
	{ CLSM_PRIV_CHROOT		, 'C'}, \
	{ CLSM_PRIV_VERICTL		, 'V'}, \
	{ CLSM_PRIV_NETCLIENT		, 'c'}, \
	{ CLSM_PRIV_NETSERVER		, 's'}, \
	{ CLSM_PRIV_NETOTHER		, 'n'}, \
	{ CLSM_PRIV_PROCFD		, 'P'}, \
	{ CLSM_PRIV_SIGUSR		, 'S'}, \
	{ CLSM_PRIV_RECVSIG		, 'r'}, \
	{ CLSM_PRIV_NETLINK		, 'N'}, \
	{ CLSM_PRIV_KSYSLOG		, 'k'}, \
	{ CLSM_PRIV_IMMORTAL		, 'I'}, \
	{ CLSM_PRIV_KEEPPRIV		, 'K'}, \
	{ CLSM_PRIV_XFRMSP		, 'X'}, \
	{ CLSM_PRIV_XFRMSA		, 'x'}, \
	{ CLSM_PRIV_FIRMWARE		, 'F'}, \
	{ CLSM_PRIV_PREINIT		, 'i'}, \
	{ CLSM_PRIV_DRM			, 'd'}, \
	{ CLSM_PRIV_FUSE		, 'f'}, \
	{ CLSM_PRIV_NETLINK_AUDIT	, 'A'}, \
	{ CLSM_PRIV_UNSHARE		, 'U'}, \
	{ 0, 0 } \
}

/**
 * Privileges that should only be available to root.
 * @n
 * Those are backed-up and masked-out when seteuid'ing from 0 to !0,
 * and reestablished when seteuid'ing to 0
 */
#define CLSM_PRIVS_ROOT_MASK	(\
					CLSM_PRIV_CHROOT 	| \
					CLSM_PRIV_VERICTL 	| \
					CLSM_PRIV_PROCFD	| \
					CLSM_PRIV_SIGUSR	| \
					CLSM_PRIV_NETLINK	| \
					CLSM_PRIV_KSYSLOG	| \
					CLSM_PRIV_IMMORTAL	| \
					CLSM_PRIV_KEEPPRIV	| \
					CLSM_PRIV_XFRMSP	| \
					CLSM_PRIV_XFRMSA	| \
					CLSM_PRIV_FIRMWARE	| \
					CLSM_PRIV_PREINIT	| \
					CLSM_PRIV_DRM		| \
					CLSM_PRIV_FUSE		| \
					CLSM_PRIV_NETLINK_AUDIT	| \
					CLSM_PRIV_UNSHARE	\
	)

/**
 * Privileges automatically propagated on exec (task to bprm).
 * @n
 * NB : all privs are transmitted from bprm to task
 */
#define CLSM_PRIVS_COPY_EXEC	0

/**
 * Privileges automatically propagated on clone (task to task).
 */
#define CLSM_PRIVS_COPY_CLONE	(~0)

/**
 * Privileges that may be gained from veriexec entries.
 */
#define CLSM_PRIVS_COPY_VERIEXEC (~CLSM_PRIV_PREINIT)

/**
 * Privileges dropped on setuid to !root  without keep_capabilities.
 * @todo make it possible for a task to drop clsm privs explicitly ?
 */
#define CLSM_PRIVS_DROP_SETUID		CLSM_PRIVS_ROOT_MASK

/**
 * Privileges dropped on vserver ctx change.
 */
#define CLSM_PRIVS_DROP_CHCTX	(~0)

/**
 * Privileges automatically given to all tasks when the LSM is
 * loaded.
 */
#define CLSM_PRIVS_INITIAL	( \
					CLSM_PRIV_PREINIT | \
					CLSM_PRIV_NETLINK | \
					CLSM_PRIV_NETCLIENT \
				)

/*@}*/
/*@}*/

#ifdef CONFIG_DEVCTL
#include <linux/devctl.h>
#endif

	/*************************************************************/
	/* * *                     END USERLAND                  * * */
	/*************************************************************/


#ifdef __KERNEL__

#ifdef CONFIG_VERIEXEC
#include <linux/veriexec/vcreds.h>
#endif

/*************************************************************/
/*                    clsm flags                             */
/*************************************************************/

/**
 * CLSM task flags.
 * Significant bits are listed in the @ref clsm_flags section
 */
typedef unsigned short clsm_flags_t;

/** @name CLSM Flags */
/*@{*/
/** @defgroup clsm_flags CLSM Flags */
/*@{*/

#define CLSM_FLAG_NONE		0x0000	/**< Nuthin */
#define CLSM_FLAG_RAISED	0x0001	/**< POSIX caps have been raised */
#define CLSM_FLAG_BUMPED	0x0002	/**< CLSM root privs have been bumped
					   (including saved privs). */
#define CLSM_FLAG_INHERITED	0x0004  /**< Task has a forced POSIX
					  inheritable capability mask */
#define CLSM_FLAG_CHROOTED	0x0008	/**< Task is chrooted */
#define CLSM_FLAG_KTHREAD	0x0010	/**< Task is a kthread (between clone
					   and exec) */
#define CLSM_FLAG_MIGRATED	0x0020	/**< Task migrated into current security
					   context, and has not called execve()
					   since then */

/**
 * Mask matching all valid CLSM flags.
 */
#define CLSM_FLAG_MASK (\
		CLSM_FLAG_NONE		| \
		CLSM_FLAG_RAISED	| \
		CLSM_FLAG_BUMPED	| \
		CLSM_FLAG_INHERITED	| \
		CLSM_FLAG_CHROOTED	| \
		CLSM_FLAG_KTHREAD	| \
		CLSM_FLAG_MIGRATED	\
 	)

/**
 * Check if a CLSM flag mask is valid.
 */
#define CLSM_FLAG_VALID(flags) \
		( ((flags) & CLSM_FLAG_MASK) == (flags))



/**
 * Map CLSM flags to keyletters for display.
 */
#define DEFINE_CLSM_FLAG_MAP { \
	{ CLSM_FLAG_NONE	, '-'}, \
	{ CLSM_FLAG_RAISED	, 'r'}, \
	{ CLSM_FLAG_BUMPED	, 'b'}, \
	{ CLSM_FLAG_INHERITED	, 'i'}, \
	{ CLSM_FLAG_CHROOTED	, 'c'}, \
	{ CLSM_FLAG_KTHREAD	, 'k'}, \
	{ CLSM_FLAG_MIGRATED	, 'm'}, \
	{ 0, 0 } \
}

/**
 * Flags automatically propagated on exec (1st step: task to bprm).
 */
#define CLSM_FLAGS_COPY_EXEC1	( \
				CLSM_FLAG_INHERITED | \
				CLSM_FLAG_KTHREAD | \
				CLSM_FLAG_CHROOTED \
)

/**
 * Flags automatically propagated on exec (2nd step: bprm to task).
 * CLSM_FLAG_KTHREAD is lost when loading userland code in a kernel
 * thread, it is only there to affect how that code is loaded
 */
#define CLSM_FLAGS_COPY_EXEC2 	~CLSM_FLAG_KTHREAD

/**
 * Flags automatically propagated on clone (task to task).
 */
#define CLSM_FLAGS_COPY_CLONE	( \
				CLSM_FLAG_RAISED    | \
				CLSM_FLAG_BUMPED    | \
				CLSM_FLAG_INHERITED | \
				CLSM_FLAG_CHROOTED  | \
				CLSM_FLAG_MIGRATED \
)

/**
 * Flags dropped on setuid to !root without keep_capabilities.
 * Nothing is systematically cleared ATM.
 * @see clsm_task_post_setuid()
 */
#define CLSM_FLAGS_DROP_SETUID	( \
					0  \
)

/** Flags dropped on vserver ctx change.
 * Resets chroot count, but only masks some POSIX caps.
 */
#define CLSM_FLAGS_DROP_CHCTX	( \
				CLSM_FLAG_INHERITED | \
				CLSM_FLAG_CHROOTED \
)
/*@}*/
/*@}*/

/**
 * CLSM Inode flags.
 * Significant bits are listed in the @ref clsm_iflags section
 */
typedef unsigned int	clsm_iflags_t;

/** @name CLSM Inode Flags */
/*@{*/
/** @defgroup clsm_iflags CLSM Inode Flags */
/*@{*/

#define CLSM_IFLAG_CACHED	0x01	/**< Valid veriexec hash check
					  in cache */

/*@}*/
/*@}*/


/*************************************************************/
/*                    sysctl stuff                           */
/*************************************************************/

/** @name Sysctl Variables */
/*@{*/
/** @defgroup sysctl Sysctl Variables */
/*@{*/

#ifdef CONFIG_CLSM_ROOTCAPS
/** Bitfield: default root capability set */
extern __u32 clsm_ctl_rootcap0;
extern __u32 clsm_ctl_rootcap1;
#endif

/** Bitfield: capability bounding set for all tasks */
extern __u32 clsm_ctl_capbound0;
extern __u32 clsm_ctl_capbound1;

#ifdef CONFIG_CLSM_CHROOT_DEVEL
/** Bool: enforce chroot-related restrictions */
extern int clsm_ctl_chroot;
#else
#define clsm_ctl_chroot 1
#endif

#ifdef CONFIG_CLSM_NET_DEVEL
/** Bool: enforce network hooks */
extern int clsm_ctl_networking;
#else
#define clsm_ctl_networking	1
#endif

#ifdef CONFIG_CLSM_MOUNT
/** Bool: enforce mount checks
 * Note: inverted, use the clsm_ctl_mount macro.
 */
extern int _clsm_ctl_mount;
/** Non-inverted boolean for _clsm_ctl_mount */
#define clsm_ctl_mount !_clsm_ctl_mount
#endif

#if (defined(CONFIG_CLSM_MOUNT) && !defined(CONFIG_DEVCTL))
/** Major number of block devices to protect
 * against any writes */
extern unsigned int clsm_ctl_ro_major;
/** Lowest minor number of block devices to protect
 * against any writes */
extern unsigned int clsm_ctl_ro_minor_low;
/** Highest minor number of block devices to protect
 * against any writes */
extern unsigned int clsm_ctl_ro_minor_high;
#endif

/*@}*/
/*@}*/

/*************************************************************/
/*                     Security tags                         */
/*************************************************************/

/** @name Security Tags */
/*@{*/
/** @defgroup tags Security Tags */
/*@{*/

/**
 * Task security tag.
 * Allocated through the g_tcache kmem_cache.
 */
struct clsm_task_sec {
	clsm_privs_t	t_privs;	/**< Effective privileges */
	clsm_privs_t	t_sprivs;	/**< Saved privileges */
	clsm_flags_t	t_flags;	/**< CLSM flags */
#ifdef CONFIG_VERIEXEC
	veriexec_flags_t t_vflags;	/**< Veriexec flags */
#endif
};

#ifdef CONFIG_VERIEXEC
/** Initialize a struct clsm_task_sec */
#define INIT_CLSM_TSEC(tsec) do { \
	(tsec)->t_vflags = 0; \
	(tsec)->t_flags = 0; \
	(tsec)->t_privs = 0; \
} while (0)
#else /* !CONFIG_VERIEXEC */
#define INIT_CLSM_TSEC(tsec) do { \
	(tsec)->t_flags = 0; \
	(tsec)->t_privs = 0; \
} while (0)
#endif /* !CONFIG_VERIEXEC */

/**
 * File security tag.
 * Used only for fowner/sigio stuff at this point,
 * stores the credentials for the task that did a
 * fcntl(fd, F_SETOWN, ...) on a given file.
 * Only allocated when this fcntl call is performed, in the g_fcache
 * kmem_cache.
 * @see g_fcache
 * @see alloc_or_test_fsec().
 */
struct clsm_file_sec {
	clsm_flags_t 	f_flags; /**< CLSM flags of creator task */
	kernel_cap_t 	f_eff;	 /**< Effective capabilities of creator task */
	kernel_cap_t 	f_perm;	 /**< Permitted capabilities of creator task */
	kernel_cap_t 	f_inh;	 /**< Inheritable capabilities of
				   creator task */
#ifdef CONFIG_VSERVER
	unsigned long	f_xid;	 /**< XID of creator task */
#endif
};

/**
 * Inode security tag.
 * Allocated in the g_icache kmem_cache.
 */
struct clsm_inode_sec {
	clsm_iflags_t	i_flags;	/**< Inode CLSM flags */
};

/*@}*/
/*@}*/

/*************************************************************/
/*                      /proc display helpers                */
/*************************************************************/

/**
 * Map one bitfield field to a keyletter.
 */
typedef struct {
	unsigned long bit;	/**< Bitfield value */
	char chr;		/**< Key letter */
} clsm_bmap_t;

/**
 * Format a bitmask for display.
 * This helper function formats a null-terminated string to represent a
 * bitmap through keyletters, based on a clsm_bmap_t array.
 * The string is output into a preallocated @a buf buffer. If the preallocated
 * size is not enough to represent the whole bitmask, the string is truncated
 * and suffixed with a '+'. The string is still null-terminated in that case.
 * @n
 * If no displayable bits were found in the input mask, the output string
 * is simply "-".
 * @param buf Buffer to output the formatted string to. This must be
 * preallocated to at least @a len bytes.
 * @param len Length of the buffer to write to. At most @a len characters
 * are written, including the null termination, and possible trailing '+'.
 * @param val Bitmask to format.
 * @param map NULL-terminated array of bitfield maps to interpret the bitmask.
 */
static inline void
clsm_format_bitmask(char *buf, size_t len, unsigned long val,
						const clsm_bmap_t *map)
{
	char *ptr = buf;
	const clsm_bmap_t *iter = map;

	if (unlikely(len <= 1)) {
		if (len)
			*ptr= '\0';
		return;
	}

	while (iter->chr != 0) {
		if ((ptr - buf) == (len - 2)) {
			*ptr++ = '+';
			*ptr = '\0';
			return;
		}
		if (val & iter->bit) {
			*ptr = iter->chr;
			ptr++;
		}
		iter++;
	}
	if (ptr == buf)
		*ptr++ = '-';
	*ptr = '\0';
	return;
}

/** @name Bitfield maps */
/** @defgroup maps Bitfield maps */
/*@{*/
/** Bitfield maps array to interpret clsm_privs_t bitfields */
extern const clsm_bmap_t clsm_priv_map[];
#ifdef CONFIG_DEVCTL
/** Bitfield maps array to interpret devctl_perm_t bitfields */
extern const clsm_bmap_t clsm_devperm_map[];
#endif
/** Bitfield maps array to interpret clsm_flags_t bitfields */
extern const clsm_bmap_t clsm_flag_map[];
#ifdef CONFIG_VERIEXEC
/** Bitfield maps array to interpret veriexec_flags_t bitfields */
extern const clsm_bmap_t veriexec_flag_map[];
#endif
/*@}*/
/*@}*/

#endif /* __KERNEL__ */

#endif /* _LINUX_CLIP_LSM_H */
