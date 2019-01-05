// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file veriexec_dev.c
 *  Veriexec device driver
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2008 SGDN/DCSSI
 *  Copyright (C) 2011 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/types.h>
#include <linux/capability.h>
#include <asm/uaccess.h>

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/veriexec.h>

/**
 * Check validity of an entry IOCTL argument.
 * @param arg Pointer to the veriexec arg to check
 * (in kernel memory, but with pointer fields possibly pointing to userland).
 * @return 0 if all fields are OK, -EINVAL otherwise.
 */
static inline int
veriexec_arg_valid(const struct veriexec_arg *arg)
{
	if (unlikely(!arg->a_fname_size)) {
		VERIEXEC_WARN("Veriexec arg with no filename");
		return -EINVAL;
	}

	if (unlikely(veriexec_digest_fplen(arg->a_dig)) == -1) {
		VERIEXEC_WARN("Invalid digest type for "
				"veriexec entry: %d", arg->a_dig);
		return -EINVAL;
	}

	if (unlikely(!VRXF_VALID(arg->a_flags))) {
		VERIEXEC_WARN("Invalid veriexec flags for "
				"veriexec entry: 0x%x", arg->a_flags);
		return -EINVAL;
	}

	if (unlikely(!CLSM_PRIV_VALID(arg->a_privs))) {
		VERIEXEC_WARN("Invalid clsm privileges for "
				"veriexec entry : 0x%lx", arg->a_privs);
		return -EINVAL;
	}

	return 0;
}

/**
 * Check validity of a context IOCTL argument.
 * @param arg Pointer to the veriexec context arg to check
 * (in kernel memory, but with pointer fields possibly pointing to userland).
 * @return 0 if all fields are OK, -EINVAL otherwise.
 */
static inline int
veriexec_xarg_valid(const struct veriexec_xarg *arg)
{
	if (unlikely(!VERIEXEC_LEVEL_VALID(arg->a_lvl))) {
		VERIEXEC_WARN("Invalid veriexec context level : "
				"0x%x", arg->a_lvl);
		return -EINVAL;
	}

	if (unlikely(!CLSM_PRIV_VALID(arg->a_privset))) {
		VERIEXEC_WARN("Invalid veriexec privilege bounding set : "
				"0x%lx", arg->a_privset);
		return -EINVAL;
	}

	return 0;
}

/**
 * Check validity of a level IOCTL argument.
 * @param arg Pointer to the veriexec level arg to check
 * (in kernel memory, but with pointer fields possibly pointing to userland).
 * @return 0 if all fields are OK, -EINVAL otherwise.
 */
static inline int
veriexec_larg_valid(const struct veriexec_larg *arg)
{
	if (unlikely(!VERIEXEC_LEVEL_VALID(arg->a_lvl))) {
		VERIEXEC_WARN("Invalid veriexec context level : "
				"0x%x", arg->a_lvl);
		return -EINVAL;
	}

	return 0;
}

/**
 * File access mode check for /dev/veriexec. All accesses require both read and
 * write permission.
 */
#define FILE_MODE_OK(fmode) (fmode & FMODE_READ && fmode & FMODE_WRITE)

/**
 * Open the veriexec device.
 * This is limited to permission checks, most of which are performed by the
 * backend's register_open().
 * @param inode Opened inode (unused).
 * @param file Opened file.
 * @return 0 if access is OK, negative error code if it is not.
 */
static int
veriexec_open(struct inode *inode, struct file *file)
{
	int ret;

	if (!FILE_MODE_OK(file->f_mode))
       		return -EPERM;

	ret = veriexec_register_open();
	if (ret)
		return ret;

	return 0;
}

/**
 * Close the veriexec device.
 * This is limited to permission checks, most of which are performed by the
 * backend's register_close().
 * @param inode Inode to close (unused).
 * @param file File to close.
 * @return 0 if closing is OK, negative error code if it is not.
 */
static int
veriexec_close(struct inode *inode, struct file *file)
{
	int ret;

	if (!FILE_MODE_OK(file->f_mode))
		return -EPERM;

	ret = veriexec_register_close();
	if (ret)
		return ret;

	return 0;
}

/**
 * Veriexec level set/get IOCTL handler.
 * @param cmd IOCTL command code.
 * @param larg Veriexec level IOCTL argument (in user memory).
 * @return 0 on success, negative error code on failure.
 */
static inline int
vrxd_do_levels(unsigned int cmd, struct veriexec_larg __user *larg)
{
	int ret;
	struct veriexec_larg largs;

	if (unlikely(copy_from_user(&largs, larg, sizeof(largs))))
		return -EFAULT;

	ret = veriexec_larg_valid(&largs);
	if (unlikely(ret))
		return ret;

	switch (cmd) {
		case VERIEXEC_IO_SETLVL:
			ret = veriexec_setlvl(&largs);
			break;
		case VERIEXEC_IO_GETLVL:
			ret = veriexec_getlvl(&largs);
			if (ret)
				return ret;
			ret = copy_to_user(larg, &largs, sizeof(largs));
			break;
		default:
			VERIEXEC_WARN("unsupported level cmd %d (%d / %d)\n",
					cmd, _IOC_TYPE(cmd), _IOC_NR(cmd));
			ret = -ENOTTY;
			break;
	}

	return ret;
}

/**
 * Veriexec entry load/unload IOCTL handler.
 * @param cmd IOCTL command code.
 * @param arg Veriexec entry IOCTL argument (in user memory).
 * @return 0 on success, negative error code on failure.
 */
static inline int
vrxd_do_loads(unsigned int cmd, const struct veriexec_arg __user *arg)
{
	int ret;
	struct veriexec_arg args;

	if (unlikely(copy_from_user(&args, arg, sizeof(args))))
		return -EFAULT;

	ret = veriexec_arg_valid(&args);
	if (unlikely(ret))
		return ret;

	switch (cmd) {
		case VERIEXEC_IO_LOAD:
			ret = veriexec_add(&args);
			break;
		case VERIEXEC_IO_UNLOAD:
			ret = veriexec_del(&args);
			break;
		default:
			VERIEXEC_WARN("unsupported load cmd %d (%d / %d)\n",
					cmd, _IOC_TYPE(cmd), _IOC_NR(cmd));
			ret = -ENOTTY;
			break;
	}

	return ret;
}

/**
 * Veriexec context store add/set/delete IOCTL handler.
 * @param cmd IOCTL command code.
 * @param xarg Veriexec context IOCTL argument (in user memory).
 * @return 0 on success, negative error code on failure.
 */
static inline int
vrxd_do_ctxops(unsigned int cmd, const struct veriexec_xarg __user *xarg)
{
	int ret;
	struct veriexec_xarg xargs;


	if (unlikely(copy_from_user(&xargs, xarg, sizeof(xargs))))
		return -EFAULT;

	ret = veriexec_xarg_valid(&xargs);
	if (unlikely(ret))
		return ret;

	switch (cmd) {
		case VERIEXEC_IO_ADDCTX:
			ret = veriexec_add_ctx(&xargs);
			break;
		case VERIEXEC_IO_DELCTX:
			ret = veriexec_del_ctx(&xargs);
			break;
		case VERIEXEC_IO_SETCTX:
			ret = veriexec_set_ctx(&xargs);
			break;
		default:
			VERIEXEC_WARN("unsupported ctx cmd %d (%d / %d)\n",
					cmd, _IOC_TYPE(cmd), _IOC_NR(cmd));
			ret = -ENOTTY;
			break;
	}

	return ret;
}


/**
 * General veriexec IOCTL handler.
 * This mostly redirects to the operation-type specific handlers,
 * after checking the access rights and proper command code.
 * @param inode Inode the IOCTL is made on (unused).
 * @param file File the IOCTL is made on.
 * @param cmd IOCTL command code.
 * @param arg Pointer to user argument (address in user memory).
 * @return 0 on success, negative error code on failure.
 */
static long
veriexec_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int tmp;
	int ret = 0;

	if (unlikely(!FILE_MODE_OK(file->f_mode)))
		return -EPERM;

	if (unlikely( _IOC_TYPE(cmd) != VRX_IO_MAGIC
			|| _IOC_NR(cmd) > VERIEXEC_IO_MAXNR)) {
		VERIEXEC_WARN("wrong ioctl, type %d, nr %d\n",
			_IOC_TYPE(cmd), _IOC_NR(cmd));
		return -ENOTTY;
	}

	switch (cmd) {
		case VERIEXEC_IO_LOAD:
		case VERIEXEC_IO_UNLOAD:
			return vrxd_do_loads(cmd,
				(const struct veriexec_arg __user *)arg);
			break;

		case VERIEXEC_IO_GETLVL:
		case VERIEXEC_IO_SETLVL:
			return vrxd_do_levels(cmd,
					(struct veriexec_larg __user *)arg);
			break;

		case VERIEXEC_IO_ADDCTX:
		case VERIEXEC_IO_DELCTX:
		case VERIEXEC_IO_SETCTX:
			return vrxd_do_ctxops(cmd,
				(const struct veriexec_xarg __user *)arg);
			break;

		case VERIEXEC_IO_SETUPDATE:
			if (unlikely(get_user(tmp, (int __user *)arg)))
				return -EFAULT;

		return veriexec_set_update(tmp);
			break;

		case VERIEXEC_IO_MEMCHK:
			ret = veriexec_get_entcount(&tmp);
			if (ret)
				return ret;

			if (unlikely(put_user(tmp, (int __user *)arg)))
				return -EFAULT;

			return 0;
			break;

		case VERIEXEC_IO_VERSION:
			if (unlikely(put_user(VERIEXEC_VERSION,
						(int __user *)arg)))
				return -EFAULT;
			return 0;
			break;

		default:
			VERIEXEC_WARN("unsupported cmd %d (%d / %d)\n",
					cmd, _IOC_TYPE(cmd), _IOC_NR(cmd));
			return -ENOTTY;
	}
}

/**
 * /dev/veriexec file operations.
 * Supported operations are open(), close() and ioctl(). No read / write.
 */
static const struct file_operations veriexec_fops = {
    .open = veriexec_open,
    .release = veriexec_close,
    .unlocked_ioctl = veriexec_ioctl,
};

/**
 * Memory device open wrapper for veriexec.
 * This checks the opened minor, and if it matches the veriexec minor,
 * associates the veriexec file operations to the device.
 * @param inode Opened inode.
 * @param file Opened file, with no valid file_operations struct. The
 * file_operations struct for this file will be set to veriexec_fops
 * if the minor matches.
 * @return 0 on succes (minor matches), -ENXIO if minor does not match,
 * other negative error code on failure.
 */
int
veriexec_device_open(struct inode *inode, struct file *file)
{
	if (iminor(inode) != VERIEXEC_MINOR)
		return -ENXIO;

	file->f_op = &veriexec_fops;
	return 0;
}

EXPORT_SYMBOL(veriexec_device_open);
