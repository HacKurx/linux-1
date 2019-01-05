// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file veriexec.h
 *  veriexec main header
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2009 SGDN/DCSSI
 *  Copyright (C) 2010-2014 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#ifndef _LINUX_VERIEXEC_H
#define _LINUX_VERIEXEC_H

#ifdef __KERNEL__
/** Mapped to __user only for kernel compilation */
#define __userarg __user
#include <linux/types.h>
#else
#define __userarg
#endif

#include <linux/veriexec/vdigest.h>
#include <linux/veriexec/vcreds.h>
#include <linux/clip_lsm.h>

/** Internal version number */
#define VERIEXEC_VERSION 92

/*************************************************************/
/*                   userland interaction                    */
/*************************************************************/


/** Veriexec context type, associated to a vserver context. */
typedef unsigned int veriexec_ctx_t;

/** Veriexec context security level type.
 * Supported values are listed in the @ref veriexec_lvl section. */
typedef unsigned int veriexec_lvl_t;

/** @name Veriexec Context Security Levels */
/*@{*/
/** @defgroup veriexec_lvl Veriexec Context Security Levels */
/*@{*/

/**
 * Veriexec checks enabled.
 */
#define VRXLVL_ACTIVE		0x01

/**
 * Cannot remove flags from level.
 */
#define VRXLVL_LVL_IMMUTABLE	0x04

/**
 * Cannot add/delete file entries in own context.
 */
#define VRXLVL_SELF_IMMUTABLE	0x08

/**
 * Nobody can add/delete file entries.
 */
#define VRXLVL_ADMIN_IMMUTABLE	0x10

/**
 * UPDATE context cannot add/delete file entries.
 */
#define VRXLVL_UPDATE_IMMUTABLE	0x20

/**
 * Cannot add/delete contexts (ADMIN ctx only).
 */
#define VRXLVL_CTX_IMMUTABLE	0x40

/**
 * Cannot modify context options.
 */
#define VRXLVL_CTXSET_IMMUTABLE	0x80

/**
 * Cannot modify entries on readonly mounts.
 */
#define VRXLVL_ENFORCE_MNTRO	0x100

/**
 * Inheritable CAP_FSETGID is required to add / delete entries.
 */
#define VRXLVL_ENFORCE_INHERIT	0x200

/**
 * Null level - veriexec checks are disabled.
 */
#define VERIEXEC_LVL_NULL	0

/**
 * Mask matching all valid veriexec levels.
 */
#define VRXLVL_MASK (\
		VRXLVL_ACTIVE		| \
		VRXLVL_LVL_IMMUTABLE	| \
		VRXLVL_SELF_IMMUTABLE	| \
		VRXLVL_ADMIN_IMMUTABLE	| \
		VRXLVL_UPDATE_IMMUTABLE	| \
		VRXLVL_CTX_IMMUTABLE	| \
		VRXLVL_CTXSET_IMMUTABLE	| \
		VRXLVL_ENFORCE_MNTRO	| \
		VRXLVL_ENFORCE_INHERIT \
	)


/*@}*/
/*@}*/

/** @name Veriexec Security Level Check Macros */
/*@{*/

/**
 * Level is valid.
 */
#define VERIEXEC_LEVEL_VALID(lvl) \
	( ((lvl) & VRXLVL_MASK) == (lvl) )

/**
 * Veriexec checks enabled.
 */
#define VERIEXEC_LEVEL_ACTIVE(lvl) \
			((lvl) & VRXLVL_ACTIVE)

/**
 * Cannot remove flags from level.
 */
#define VERIEXEC_LEVEL_IMMUTABLE_P(lvl) \
				((lvl) & VRXLVL_LVL_IMMUTABLE)

/**
 * Cannot add/delete file entries in own context.
 */
#define VERIEXEC_SELF_IMMUTABLE_P(lvl) \
				((lvl) & VRXLVL_SELF_IMMUTABLE)

/**
 * Nobody can add/delete file entries.
 */
#define VERIEXEC_ADMIN_IMMUTABLE_P(lvl) \
				((lvl) & VRXLVL_ADMIN_IMMUTABLE)

/**
 * UPDATE context cannot add/delete file entries.
 */
#define VERIEXEC_UPDATE_IMMUTABLE_P(lvl) \
				((lvl) & VRXLVL_ADMIN_IMMUTABLE)

/**
 * Cannot add/delete contexts (ADMIN ctx only).
 */
#define VERIEXEC_CONTEXT_IMMUTABLE_P(lvl) \
				((lvl) & VRXLVL_CTX_IMMUTABLE)

/**
 * Cannot modify context options.
 */
#define VERIEXEC_CTXSET_IMMUTABLE_P(lvl) \
				((lvl) & VRXLVL_CTXSET_IMMUTABLE)

/**
 * Cannot modify entries on readonly mounts.
 */
#define VERIEXEC_ENFORCE_MNTRO_P(lvl) \
				((lvl) & VRXLVL_ENFORCE_MNTRO)
/**
 * Inheritable CAP_FSETGID is required to add / delete entries.
 */
#define VERIEXEC_ENFORCE_INHERIT_P(lvl) \
				((lvl) & VRXLVL_ENFORCE_INHERIT)

/*@}*/

/** @name Veriexec IOCTL Arguments */
/*@{*/
/** @defgroup veriexec_ioctl_arg Veriexec IOCTL Arguments */
/*@{*/

/**
 * Entry load/unload argument.
 * Note : size fields do not include any trailing 0.
 */
struct veriexec_arg {
	veriexec_ctx_t		a_ctx;		/**< ctx for this entry.
						If -1, use current context */
	char 	__userarg 	*a_fname;	/**< filename */
	size_t 			a_fname_size;	/**< filename length */
	veriexec_dig_t 		a_dig;		/**< digest algorithm type */
	char 	__userarg 	*a_fp; 		/**< fingerprint */
	veriexec_flags_t 	a_flags;	/**< veriexec flags */
	veriexec_caps_t 	a_caps;		/**< POSIX capability set */
	clsm_privs_t		a_privs;	/**< CLSM privileges */
};

/**
 * Context add/del/set argument.
 */
struct veriexec_xarg {
	veriexec_ctx_t 		a_ctx;		/**< target context */
	veriexec_lvl_t		a_lvl;		/**< initial level */
	kernel_cap_t	  	a_capset;	/**< capability bounding mask */
	clsm_privs_t		a_privset;	/**< authorized clsm privs */
};

/**
 * Level set/get argument.
 */
struct veriexec_larg {
	veriexec_ctx_t		a_ctx;		/**< target context.
						  If -1, use current context */
	veriexec_lvl_t		a_lvl;		/**< New level if set, current
						  level storage if get. */
};

/*@}*/
/*@}*/

/** Veriexec memory device minor number. */
#define VERIEXEC_MINOR 14

/** @name Veriexec IOCTL Commands */
/*@{*/
/** @defgroup veriexec_ioctl_cmd Veriexec IOCTL Commands */
/*@{*/

/**
 * Base IO magic number.
 */
#define VRX_IO_MAGIC 0xc0

/**
 * Add a file entry.
 */
#define VERIEXEC_IO_LOAD 	_IOW(VRX_IO_MAGIC, 0x01, struct veriexec_arg)

/**
 * Delete a file entry.
 */
#define VERIEXEC_IO_UNLOAD 	_IOW(VRX_IO_MAGIC, 0x02, struct veriexec_arg)

/**
 * Set level.
 */
#define VERIEXEC_IO_SETLVL	_IOW(VRX_IO_MAGIC, 0x03, struct veriexec_larg)

/**
 * Get level.
 */
#define VERIEXEC_IO_GETLVL	_IOR(VRX_IO_MAGIC, 0x04, struct veriexec_larg)

/**
 * Add a context.
 */
#define VERIEXEC_IO_ADDCTX 	_IOW(VRX_IO_MAGIC, 0x05, struct veriexec_xarg)

/**
 * Delete a context.
 */
#define VERIEXEC_IO_DELCTX	_IOW(VRX_IO_MAGIC, 0x06, struct veriexec_xarg)

/**
 * Change a context's capability bounding set.
 */
#define VERIEXEC_IO_SETCTX	_IOW(VRX_IO_MAGIC, 0x07, struct veriexec_xarg)

/**
 * Setup an UPDATE ctx.
 */
#define VERIEXEC_IO_SETUPDATE	_IOW(VRX_IO_MAGIC, 0x08, int)

/**
 * Debug : get number of allocated entries.
 */
#define VERIEXEC_IO_MEMCHK	_IOR(VRX_IO_MAGIC, 0x09, int)

/**
 * Get version number.
 */
#define VERIEXEC_IO_VERSION	_IOR(VRX_IO_MAGIC, 0x0a, int)

/** Last valid IO command */
#define VERIEXEC_IO_MAXNR 0x0a

/*@}*/
/*@}*/

	/*************************************************************/
	/* * *                     END USERLAND                  * * */
	/*************************************************************/

#ifdef __KERNEL__

#include <linux/err.h>
#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/rcupdate.h>


/*************************************************************/
/*                         debug macros                      */
/*************************************************************/


#ifdef CONFIG_VERIEXEC_DEBUG
/**
 * Print a formatted debug message to KERN_DEBUG,
 * if CONFIG_VERIEXEC_DEBUG is set.
 */
#define VERIEXEC_DEBUG(fmt, args...) \
	printk(KERN_DEBUG "VERIEXEC: %s: " fmt, __FUNCTION__, ## args)
#else
#define VERIEXEC_DEBUG(fmt, args...)
#endif

#ifdef CONFIG_VERIEXEC_DEBUG_EXTRA
/**
 * Print a formatted debug message to KERN_DEBUG,
 * if CONFIG_VERIEXEC_DEBUG_EXTRA is set.
 */
#define VERIEXEC_DEBUG2(fmt, args...) \
	printk(KERN_DEBUG "VERIEXEC: %s: " fmt, __FUNCTION__, ## args)
#else
#define VERIEXEC_DEBUG2(fmt, args...)
#endif

/**
 * Print a formatted message to KERN_WARN.
 */
#define VERIEXEC_WARN(fmt, args...) \
	printk(KERN_WARNING "VERIEXEC: %s: " fmt, __FUNCTION__, ##args)

/**
 * Print a formatted message to KERN_ERROR.
 */
#define VERIEXEC_ERROR(fmt, args...) \
	printk(KERN_ERR "VERIEXEC: %s: " fmt, __FUNCTION__, ##args)


/*************************************************************/
/*                   per-file entries                        */
/*************************************************************/


struct file_operations;

/**
 * Veriexec backend file entry.
 */
struct veriexec_entry {
	dev_t			ve_dev;		/**< device for this entry */
	ino_t			ve_ino;		/**< inode for this entry */
	struct hlist_node 	ve_hlist;	/**< entry list */
	atomic_t		ve_refcnt;	/**< entry reference count */
	/* Entry properties */
	veriexec_dig_t 		ve_dig;		/**< digest type */
	char 			*ve_fp;		/**< fingerprint */
	veriexec_flags_t 	ve_flags;	/**< veriexec options */
	veriexec_caps_t 	ve_caps;  	/**< POSIX capabilities */
	clsm_privs_t		ve_privs;	/**< CLSM privileges */
	/* Entry identification info */
	struct rcu_head		ve_rcu;		/**< entry delete rcu handle */
};

#define VERIEXEC_ENTRY_INIT(entry) do { \
	(entry)->ve_fp = NULL; \
	(entry)->ve_dig = VERIEXEC_DIG_LAST; \
	(entry)->ve_flags = 0; \
	vrx_cap_clear((entry)->ve_caps); \
	(entry)->ve_privs = 0; \
	atomic_set(&(entry)->ve_refcnt, 0); \
	INIT_HLIST_NODE(&(entry)->ve_hlist); \
} while (0)

/*************************************************************/
/*                       External API                        */
/*************************************************************/


/*
 * Check if opening/closing /dev/veriexec is possible in
 * the current context. If it is possible, respectively
 * increment / decrement usage count (if any) for that context
 */
extern int veriexec_register_open(void);
extern int veriexec_register_close(void);

/*
 * Seclevel set / get for current context
 */
	/* VERIEXEC_IO_GETLVL */
extern int veriexec_getlvl(struct veriexec_larg *);
	/* VERIEXEC_IO_SETLVL */
extern int veriexec_setlvl(const struct veriexec_larg *);

/*
 * Add or delete entry
 */
	/* VERIEXEC_IO_LOAD */
extern int veriexec_add(const struct veriexec_arg *);
	/* VERIEXEC_IO_UNLOAD */
extern int veriexec_del (const struct veriexec_arg *);

/*
 * Add, delete or configure a context
 */
	/* VERIEXEC_IO_ADDCTX */
extern int veriexec_add_ctx(const struct veriexec_xarg *);
	/* VERIEXEC_IO_DELCTX */
extern int veriexec_del_ctx(const struct veriexec_xarg *);
	/* VERIEXEC_IO_SETCTX */
extern int veriexec_set_ctx(const struct veriexec_xarg *);

/*
 * Memleak checker : get number of allocated entries
 */
	/* VERIEXEC_IO_MEMCHK */
extern int veriexec_get_entcount(int *);


/*************************************************************/
/*                       Cache management                    */
/*************************************************************/

#ifdef CONFIG_VERIEXEC_CACHE
/**
 * Remove inode from veriexec cache.
 * Called when the inode is opened with write permission, regardless
 * of whether an actual write occurs.
 * @n <b>Called with inode->i_lock held.</b>
 * @param inode inode to remove from cache.
 */
static inline void
veriexec_inode_uncache(struct inode *inode)
{
	struct clsm_inode_sec *isec = inode->i_security;

	if (isec)
		isec->i_flags &= ~CLSM_IFLAG_CACHED;
}
#else
#define veriexec_inode_uncache(inode) do {;} while (0)
#endif

/*************************************************************/
/*                       Internal API                        */
/*************************************************************/


/*
 * Allocate a new entry for a given device and inode,
 * with otherwise 'empty' fields.
 */
extern struct veriexec_entry *veriexec_entry_new(dev_t, ino_t);

/*
 * Free an entry, and any of its allocated fields.
 */
extern void veriexec_entry_free(struct veriexec_entry *);

/**
 * Increase refcount on a veriexec entry.
 * @param entry Entry to get.
 */
static inline void
veriexec_entry_get(struct veriexec_entry *entry)
{
	BUG_ON(!entry);
	atomic_inc(&entry->ve_refcnt);
}

/**
 * Entry cleanup rcu callback.
 * This is called after a grace period once an entry's refcount has
 * reached 0. It re-tests the entry's reference count,
 * and frees the entry if that is still 0.
 * @param head RCU handle of the deleted veriexec_entry.
 */
static inline void
_veriexec_entry_cleanup_rcu(struct rcu_head *head)
{
	struct veriexec_entry *entry =
		container_of(head, struct veriexec_entry, ve_rcu);

	if (likely(!atomic_read(&entry->ve_refcnt)))
		veriexec_entry_free(entry);
}

#ifdef CONFIG_VERIEXEC_CACHE

/*
 * Remove any veriexec cache entry matching device dev and
 * inode ino.
 */
extern void veriexec_cache_clear(dev_t dev, ino_t ino);

#else
#define veriexec_cache_clear do { } while (0)
#endif

/**
 * Decrease refcount on a veriexec entry, free it if refcount reaches 0.
 * @param entry Entry to put.
 */
static inline void
veriexec_entry_put(struct veriexec_entry *entry)
{
	BUG_ON(!entry);

	if (likely(!atomic_dec_and_test(&entry->ve_refcnt)))
		return; /* Still referenced */

	/* Clear from cache before possible freeing.
	 * Note : we need to do it here, rather than in the
	 * RCU callback, since it needs to sleep (acquiring
	 * the superblock mutex, which is a big no-no in
	 * a RCU callback.
	 */
	veriexec_cache_clear(entry->ve_dev, entry->ve_ino);

	/* No longer referenced, attempt to free it after a grace period */
	call_rcu(&entry->ve_rcu, _veriexec_entry_cleanup_rcu);
}

/*
 * Setup an (allocated) entry from a user supplied argument struct.
 */
extern int veriexec_copy_args(struct veriexec_entry *,
				const struct veriexec_arg *);

/*
 * Setup an (allocated) clsm_fileid from a user supplied argument struct.
 */
struct clsm_fileid;
extern int veriexec_arg2fid(const struct veriexec_arg *,
				struct clsm_fileid *fid, int checkwrite);

/*
 * Allocate and setup an entry from a user supplied argument struct.
 */
extern struct veriexec_entry *
veriexec_entry_create(const struct veriexec_arg *, const struct clsm_fileid *);

/*
 * Print an entry to a seq_print interface.
 */
struct seq_file;
void veriexec_entry_seqprint(struct seq_file *,
				const struct veriexec_entry *);

/*
 * /proc/veriexec file operations
 */
extern const struct file_operations veriexec_proc_fops;

/*
 * Lookup entry by file pointer
 */
extern struct veriexec_entry * veriexec_lookup_f(const struct file *);

/*
 * Lookup entry by dentry
 */
extern struct veriexec_entry * veriexec_lookup_d(const struct dentry *);

/*
 * Setup an UPDATE context. NB : works only once...
 */
extern int veriexec_set_update(veriexec_ctx_t);

/*
 * Memory char device open wrapper for the veriexec device.
 */
extern int veriexec_device_open(struct inode *inode, struct file *filp);

/**
 * Get level for current context.
 * @param lvl Read level storage.
 * @return 0 on success, negative error code on failure.
 */
static inline int
veriexec_get_curlvl(int *lvl)
{
	int ret;
	struct veriexec_larg larg = {
		.a_ctx = -1
	};

	ret = veriexec_getlvl(&larg);

	*lvl = larg.a_lvl;
	return ret;
}

/*
 * Init the entry store
 */
extern int veriexec_init_store(void);

/*
 * Entry store cleanup.
 */
extern void veriexec_exit_store(void);

/*
 * Init function
 */
extern int veriexec_init(void);

/*
 * Device init function
 */
extern int veriexec_device_init(void);

/*
 * Exit function
 */
extern void veriexec_exit(void);

#endif /* __KERNEL__ */
#else  /* !_LINUX_VERIEXEC_H */
#warning Double inclusion
#endif /* _LINUX_VERIEXEC_H */
