// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file clsm_sysctl.c
 *  CLSM sysctls
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2008 SGDN/DCSSI
 *  Copyright (C) 2011 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#include <linux/sysctl.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>

#include "clsm.h"

#ifdef CONFIG_CLSM_ROOTCAPS
__u32 clsm_ctl_rootcap0;
__u32 clsm_ctl_rootcap1;
EXPORT_SYMBOL(clsm_ctl_rootcap0);
EXPORT_SYMBOL(clsm_ctl_rootcap1);
#endif

__u32 clsm_ctl_capbound0;
__u32 clsm_ctl_capbound1;
EXPORT_SYMBOL(clsm_ctl_capbound0);
EXPORT_SYMBOL(clsm_ctl_capbound1);

#ifdef CONFIG_CLSM_CHROOT_DEVEL
int clsm_ctl_chroot;
EXPORT_SYMBOL(clsm_ctl_chroot);
#endif

#ifdef CONFIG_CLSM_NET_DEVEL
int clsm_ctl_networking;
EXPORT_SYMBOL(clsm_ctl_networking);
#endif

#ifdef CONFIG_CLSM_MOUNT
int _clsm_ctl_mount;
EXPORT_SYMBOL(_clsm_ctl_mount);
#endif

/** CLIP-LSM sysctl table header. */
static struct ctl_table_header *clsm_table_header = NULL;

/** CLIP-LSM sysctl directory ctl name. */
#define KERN_CLSM	97

/** Main CLIP-LSM sysctl table, hooked to /proc/sys/kernel/clip/ */
static struct ctl_table clsm_inner_table[] = {

#ifdef CONFIG_CLSM_ROOTCAPS
	{
		.procname 	= "rootcap0",
		.data 		= &clsm_ctl_rootcap0,
		.maxlen		= sizeof(int),
		.mode		= 0600,
#ifdef CONFIG_CLSM_ROOTCAPS_DEVEL
		.proc_handler	= &proc_dointvec,
#else
		.proc_handler	= &proc_dointvec_bset,
#endif /* CONFIG_CLSM_ROOTCAPS_DEVEL */
	},
	{
		.procname 	= "rootcap1",
		.data 		= &clsm_ctl_rootcap1,
		.maxlen		= sizeof(int),
		.mode		= 0600,
#ifdef CONFIG_CLSM_ROOTCAPS_DEVEL
		.proc_handler	= &proc_dointvec,
#else
		.proc_handler	= &proc_dointvec_bset,
#endif /* CONFIG_CLSM_ROOTCAPS_DEVEL */
	},
#endif /* CONFIG_CLSM_ROOTCAPS */
	{
		.procname 	= "capbound0",
		.data 		= &clsm_ctl_capbound0,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_bset,
	},
	{
		.procname 	= "capbound1",
		.data 		= &clsm_ctl_capbound1,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_bset,
	},

#ifdef CONFIG_CLSM_CHROOT_DEVEL
	{
		.procname 	= "chroot",
		.data 		= &clsm_ctl_chroot,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif /* CONFIG_CLSM_CHROOT_DEVEL */

#ifdef CONFIG_CLSM_NET_DEVEL
	{
		.procname 	= "networking",
		.data 		= &clsm_ctl_networking,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
#endif /* CONFIG_CLSM_NET_DEVEL */

#ifdef CONFIG_CLSM_MOUNT
	{
		.procname 	= "mount",
		.data 		= &_clsm_ctl_mount,
		.maxlen		= sizeof(int),
		.mode		= 0600,
#ifdef CONFIG_CLSM_MOUNT_DEVEL
		.proc_handler	= &proc_dointvec,
#else
		.proc_handler	= &proc_dointvec_bset,
#endif /* CONFIG_CLSM_MOUNT_DEVEL */
	},
#endif /* CONFIG_CLSM_MOUNT */

	{  }
};

/** CLIP-LSM sysctl directory (/proc/sys/kernel/clip) */
static struct ctl_table clsm_dir_table[] = {
	{
		.procname 	= "clip",
		.mode 		= 0700,
		.child		= clsm_inner_table,
	},
	{ }
};

/** Root sysctl directory (/proc/sys/kernel) */
static struct ctl_table clsm_root_table[] = {
	{
		.procname	= "kernel",
		.mode		= 0555,
		.child		= clsm_dir_table,
	},
	{ }
};

/**
 * Initial value for clsm_ctl_rootcap* and capbound*.
 */
# define CAP_INIT_EFF_SET ((kernel_cap_t){{ ~CAP_TO_MASK(CAP_SETPCAP), ~0 }})

/**
 * Initialize CLIP-LSM sysctl variables.
 * @return 0 (no error case).
 */
int
clsm_init_sysctl(void)
{
	kernel_cap_t init = CAP_INIT_EFF_SET;
#ifdef CONFIG_CLSM_ROOTCAPS
	clsm_ctl_rootcap0 = init.cap[0];
	clsm_ctl_rootcap1 = init.cap[1];
#endif
	clsm_ctl_capbound0 = init.cap[0];
	clsm_ctl_capbound1 = init.cap[1];

#ifdef CONFIG_CLSM_CHROOT_DEVEL
	clsm_ctl_chroot = 1;
#endif

#ifdef CONFIG_CLSM_NET_DEVEL
	clsm_ctl_networking = 1;
#endif

#ifdef CONFIG_CLSM_MOUNT
	_clsm_ctl_mount = 1;
#endif

	return 0;

}

/**
 * Initialize the CLIP-LSM sysctl table.
 * This must be run as a late_initcall.
 * @return 0 on success, -EFAULT on failure.
 */
int
clsm_init_sysctl_table(void)
{
	clsm_table_header = register_sysctl_table(clsm_root_table);
	if (!clsm_table_header) {
		CLSM_WARN("Failed to register sysctl table\n");
		return -EFAULT;
	}
	return 0;
}

/**
 * Remove the CLIP-LSM sysctl table.
 */
void
clsm_exit_sysctl(void)
{
	if (clsm_table_header)
		unregister_sysctl_table(clsm_table_header);
}

EXPORT_SYMBOL(clsm_init_sysctl);
EXPORT_SYMBOL(clsm_init_sysctl_table);
EXPORT_SYMBOL(clsm_exit_sysctl);
