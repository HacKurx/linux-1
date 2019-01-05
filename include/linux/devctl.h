// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file devctl.h
 *  devctl header
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2008 SGDN/DCSSI
 *  Copyright (C) 2011 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#ifndef _LINUX_DEVCTL_H
#define _LINUX_DEVCTL_H

		/* blkdev permission bits */

/**
 * devctl permission bitmask.
 * Significant bit values are listed in the @ref devctl_perm section.
 */
typedef unsigned int devctl_perm_t;

/** @name Devctl Permission Bits */
/*@{*/
/** @defgroup devctl_perm Devctl Permission Bits */
/*@{*/

#define DEVCTL_PERM_NONE	0x000	/**< no permission */
#define DEVCTL_PERM_RO		0x001	/**< can be read (or mounted ro) */
#define DEVCTL_PERM_RW		0x002	/**< can be written to (mounted rw) */
#define DEVCTL_PERM_DEV		0x010	/**< can be mounted without 'nodev' */
#define DEVCTL_PERM_EXEC	0x020	/**< can be mounted without 'noexec' */
#define DEVCTL_PERM_SUID	0x040	/**< can be mounted without 'nosuid' */

/**
 * Mask defining valid permission bits.
 */
#define DEVCTL_PERM_MASK	\
	(DEVCTL_PERM_NONE|DEVCTL_PERM_RO|DEVCTL_PERM_RW|\
		DEVCTL_PERM_DEV|DEVCTL_PERM_EXEC|DEVCTL_PERM_SUID)

/**
 * Map DEVCTL permissions to keyletters for display.
 */
#define DEFINE_DEVCTL_PERM_MAP { \
	{ DEVCTL_PERM_NONE	, '-'}, \
	{ DEVCTL_PERM_RO	, 'r'}, \
	{ DEVCTL_PERM_RW	, 'w'}, \
	{ DEVCTL_PERM_DEV	, 'd'}, \
	{ DEVCTL_PERM_EXEC	, 'x'}, \
	{ DEVCTL_PERM_SUID	, 's'}, \
	{ 0, 0 } \
}

/*@}*/
/*@}*/

		/* IOCTL API */

/**
 * devctl ioctl() argument.
 * Valid ioctl() commands are listed in the @ref devctl_ioctl section.
 */
struct devctl_arg {
	unsigned int a_major;		/**< Base major for this entry */
	unsigned int a_minor;		/**< Base minor for this entry */
	unsigned int a_range; 		/**< Minor range for this entry */
	unsigned int a_priority; 	/**< Priority for this entry */
	devctl_perm_t a_perms;		/**< Permission mask for this entry */
};


/** @name Devctl IOCTL Commands */
/*@{*/

/** @defgroup devctl_ioctl Devctl IOCTL Commands */
/*@{*/

/** Base ioctl() magic number */
#define DEVCTL_IO_MAGIC 0xc1

/** Add a device entry */
#define DEVCTL_IO_LOAD		_IOW(DEVCTL_IO_MAGIC, 1, struct devctl_arg)
/** Remove a device entry */
#define DEVCTL_IO_UNLOAD	_IOW(DEVCTL_IO_MAGIC, 2, struct devctl_arg)

/** Last valid ioctl() command */
#define DEVCTL_IO_MAX	0x2

/*@}*/
/*@}*/


	/*************************************************************/
	/* * *                     END USERLAND                  * * */
	/*************************************************************/


#ifdef __KERNEL__


extern int devctl_init(void);
extern int devctl_device_init(void);
extern void devctl_exit(void);

/* Returns 1 if access is OK, 0 if access is NOK */
extern int devctl_check(dev_t, devctl_perm_t);
/*
 * Memory char device open wrapper for the devctl device.
 */
struct inode;
extern int devctl_device_open(struct inode *inode, struct file *filp);



#endif /* __KERNEL__ */

#endif /* _LINUX_DEVCTL_H */
