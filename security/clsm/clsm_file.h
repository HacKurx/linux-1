// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file clsm_file.h
 *  CLSM common file store functions header
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2008 SGDN/DCSSI
 *  @n
 *  All rights reserved.
 *
 */

#ifndef _LINUX_CLSM_FILE_H
#define _LINUX_CLSM_FILE_H

#ifdef __KERNEL__

#include <linux/fs.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <asm/uaccess.h>

/*************************************************************/
/*                  filesystem interface                     */
/*************************************************************/

/**
 * Internal identifier for an inode.
 */
struct clsm_fileid {
	ino_t 	f_inode;	/**< inode number */
	dev_t	f_dev;		/**< device number */
};

/**
 * Extract a struct clsm_fileid from a file, optionnally checking write access.
 * This extracts a struct file's information to set up a struct clsm_fileid.
 * If the @a checkwrite argument is non-zero, write access to the target inode
 * (based on mount options alone) is also tested.
 * @param filp File to extract info for.
 * @param fid Pointer to output struct clsm_fileid, which must be preallocated.
 * @param checkwrite Perform a write access check first, if non-zero.
 * @return -EROFS if a write access check was requested and access was denied
 * (i.e. the underlying VFS mount is read-only). 0 otherwise.
 */
static inline int
clsm_file2fid(const struct file *filp, struct clsm_fileid *fid, int checkwrite)
{
	if (checkwrite && ((filp->f_path.mnt->mnt_flags & MNT_READONLY) ||
				IS_RDONLY(filp->f_path.dentry->d_inode))) {
		return -EROFS;
	} else {
		fid->f_inode = filp->f_path.dentry->d_inode->i_ino;
		fid->f_dev = filp->f_path.dentry->d_sb->s_dev;
	}

	return 0;
}

/**
 * Extract a struct clsm_fileid from a file path, optionnally checking write access.
 * This sets up a struct clsm_fileid after looking up a target file path.
 * Optionnally, write access to the target file can be checked, in the same manner
 * as it is done for clsm_file2fid().
 * @param fname Target file path name.
 * @param fid Pointer to output struct clsm_fileid, which must be preallocated.
 * @param checkwrite Perform a write access check first, if non-zero.
 * @return -EROFS if a write access check was requested and access was denied
 * (i.e. the underlying VFS mount is read-only). -ENOENT if target file could
 * not be found. 0 otherwise.
 */
static inline int
clsm_name2fid(const char *fname, struct clsm_fileid *fid, int checkwrite)
{
	struct path path;
	int retval;

	/* perform lookup */
	retval  = kern_path(fname, LOOKUP_FOLLOW, &path);
	if (unlikely(retval))
		return -ENOENT;

	if (checkwrite &&
		((path.mnt->mnt_flags & MNT_READONLY)
			|| IS_RDONLY(path.dentry->d_inode))) {
		retval = -EROFS;
	} else {
		fid->f_inode = path.dentry->d_inode->i_ino;
		fid->f_dev = path.dentry->d_sb->s_dev;
	}

	path_put(&path);
	return retval;
}

#else /* !__KERNEL__ */
#error This header must not be included in userland code
#endif /* __KERNEL__ */
#else /* !_LINUX_CLSM_FILE_H */
#warning Double inclusion
#endif /* _LINUX_CLSM_FILE_H */
