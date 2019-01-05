// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file devctl.c
 *  devctl implementation
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2011 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/kdev_t.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <asm/atomic.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/clip_lsm.h>

#include <linux/seq_file.h>
#include <linux/proc_fs.h>

#include "clsm.h"
#include "clsm_file.h"

/** Minor number for the devctl device */
#define DEVCTL_MINOR 15

/************************************************/
/*           Bitmask map for proc display       */
/************************************************/

/** Bitfield map for devctl perms */
const clsm_bmap_t devctl_perm_map[] = DEFINE_DEVCTL_PERM_MAP;

/************************************************/
/*           Device list entry                  */
/************************************************/

/** Devctl device list entry */
struct devctl_dev {
	unsigned int d_major;		/**< base major for this entry */
	unsigned int d_minor;		/**< base minor for this entry */
	unsigned int d_range;		/**< minor range for this entry */
	unsigned int d_priority;	/**< priority for this range.
					A higher priority entry has precedence
					over a lower priority one. */
	devctl_perm_t d_perms;		/**< device access bits  */

	struct hlist_node d_list;	/**< linked list of entries */
	struct rcu_head d_rcu;		/**< entry delete rcu handle */
};

/**
 * Exact match beetween a struct devctl_dev entry and a
 * (major, minor, range) tuple.
 * Used to test exact match between two entries, or between a struct devctl_dev
 * and a struct devctl_arg.
 */
#define exact_match(Major, Minor, Range, Dev) (\
		((Major) == (Dev)->d_major) && \
		((Minor) == (Dev)->d_minor) && \
		((Range) == (Dev)->d_range) \
)
/**
 * Ranged match: test compatibility between a (major, minor) couple and
 * a struct devctl_dev (major, minor range).
 * Used to check if a struct devctl_dev matches an actual device.
 */
#define ranged_match(Major, Minor, Dev) (\
		((Major) == (Dev)->d_major) && \
		((Minor) >= (Dev)->d_minor) && \
		((Minor) <= ((Dev)->d_minor + (Dev)->d_range)) \
)

/**
 * Test wether an int is a valid minor number.
 */
#define valid_minor(min)	(MINOR((min)) == (min))

/*
 * Test wether an int is a valid permission mask.
 */
#define valid_perm(perm)	(((perm) & DEVCTL_PERM_MASK) == (perm))

/**
 * Maximum major number.
 */
#define MAJOR_MAX	MAJOR((dev_t)-1)

/**
 * Copy a struct devctl_arg fields into a struct devctl_dev.
 * @param arg Where to copy from.
 * @param dev Where to copy to.
 * @return -EINVAL in case of invalid fields in devctl_arg, 0 otherwise.
 */
static inline int
arg2device(const struct devctl_arg *arg, struct devctl_dev *dev)
{
	if (arg->a_major > MAJOR_MAX) {
		CLSM_ERROR("Invalid major: %u", arg->a_major);
		return -EINVAL;
	}
	if (!valid_minor(arg->a_minor)) {
		CLSM_ERROR("Invalid minor: %u", arg->a_minor);
		return -EINVAL;
	}
	if (!valid_minor(arg->a_minor + arg->a_range)) {
		CLSM_ERROR("Minor range too big: %u + %u",
				arg->a_minor, arg->a_range);
		return -EINVAL;
	}
	if (!valid_perm(arg->a_perms)) {
		CLSM_ERROR("Invalid devctl permissions : %x", arg->a_perms);
		return -EINVAL;
	}
	dev->d_major = arg->a_major;
	dev->d_minor = arg->a_minor;
	dev->d_range = arg->a_range;
	dev->d_priority = arg->a_priority;
	dev->d_perms = arg->a_perms;

	return 0;
}

/** @name Devctl kmem caches */
/*@{*/
/** @addtogroup kmem_caches */
/*@{*/

/** kmem_cache for struct devctl_dev allocation */
static struct kmem_cache *g_cache = NULL;

/*@}*/
/*@}*/

/**
 * Allocate a struct devctl_dev.
 * @return Pointer to allocated struct on success, NULL on failure.
 */
static inline struct devctl_dev *
devctl_new(void)
{
	struct devctl_dev *new = kmem_cache_alloc(g_cache, GFP_KERNEL);
	if (unlikely(!new))
		return NULL;

	INIT_HLIST_NODE(&new->d_list);
	/* RCU head initialization no longer needed */

	return new;
}

/**
 * Free a struct devctl_dev.
 * @param entry Structure to free.
 */
static inline void
devctl_free(struct devctl_dev *entry)
{
	BUG_ON(!entry);

	kmem_cache_free(g_cache, entry);
}


/**
 * Free a struct devctl_dev (wrapper for RCU calls).
 * @param head RCU handle of the struct devctl_dev to free.
 */
static void
devctl_del_rcu(struct rcu_head *head)
{
	struct devctl_dev *entry =
		container_of(head, struct devctl_dev, d_rcu);

	devctl_free(entry);
}


/************************************************/
/*           Linked device list                 */
/************************************************/

/** Number of hash bits in the devctl lookup table */
#define DEVCTL_HASH_BITS	4
/** Devctl lookup hash table size */
#define DEVCTL_HASH_SZ	(1<<DEVCTL_HASH_BITS)
/** Devctl lookup hash mask */
#define DEVCTL_HASH_MASK	(DEVCTL_HASH_SZ - 1)

/** Global hashed lookup table for struct devctl_dev entries. */
static struct hlist_head g_htable[DEVCTL_HASH_SZ];

/** Spinlock protecting @a g_htable against writes.
 * @see g_htable.
 */
static spinlock_t g_lock;

/**
 * Hash a struct devctl_dev to insert it in the lookup table.
 * We only 'hash' the major number, which makes the hashing
 * much less efficient, but ensures that two overlapping ranges
 * get hashed into the same hash bucket. With this reduced efficiency
 * scheme, there is no real point having a 'real' hash function, nor
 * too many hash bits. The following scheme ensures that 'real-life'
 * major numbers get hashed into separate buckets, which is all we're
 * interested in.
 * @param major d_major field of the struct devctl_dev to hash.
 * @return Hash value for @a major.
 */
static inline unsigned int
devctl_hash(unsigned int major)
{
	return (major & DEVCTL_HASH_MASK);
}

/**
 * Unlocked helper: device lookup in the global hash table.
 * This returns a struct devctl_dev from @a g_htable that matches
 * the device @a dev (i.e., such that @a dev's major equals the struct's
 * major, and @a dev's minor is within the struct's minor range).
 * If several such matching entries exist in the hash table, the one
 * with the highest priority is returned.
 * @n
 * <b>Caller must ensure proper locking, either rcu (read lookup)
 * or spinlock (@a g_lock for write lookup)</b>
 * @param dev dev_t device number for the device to lookup.
 * @return Pointer to the matching struct devctl_dev if found, error
 * pointer otherwise.
 */
static inline struct devctl_dev *
_do_ranged_lookup(dev_t dev)
{
	struct devctl_dev *cur;

	unsigned int major = MAJOR(dev);
	unsigned int minor = MINOR(dev);
	unsigned int hash = devctl_hash(major);
	struct hlist_head *head = &(g_htable[hash]);
	unsigned int bestprio = 0;
	struct devctl_dev *best = NULL;

	hlist_for_each_entry_rcu(cur, head, d_list) {
		if (!ranged_match(major, minor, cur))
			continue;
		/* We have a match, check prio */
		if (cur->d_priority > bestprio) {
			best = cur;
			bestprio = cur->d_priority;
		}
	}

	return (best) ? best : ERR_PTR(-ENOENT);
}


/**
 * Unlocked helper: add a struct devctl_dev to the global hash table.
 * This adds the device entry passed as argument to the g_htable lookup
 * table, if it isn't already present in it.
 * @n
 * <b>Caller must hold @a g_lock.</b>
 * @param new Device entry to add.
 * @return 0 on success, -EEXIST if the entry is already in the lookup table.
 */
static inline int
_do_dev_add(struct devctl_dev *new)
{
	struct devctl_dev *cur;
	unsigned int hash = devctl_hash(new->d_major);
	struct hlist_head *head = &(g_htable[hash]);

	hlist_for_each_entry_rcu(cur, head, d_list) {
		if (exact_match(new->d_major, new->d_minor, new->d_range, cur))
			return -EEXIST;
	}

	hlist_add_head_rcu(&new->d_list, head);
	return 0;
}

/**
 * Unlocked helper : lookup a device entry in the global hash table.
 * This looks for a device entry matching (exactly) the major and minor range,
 * as well as the priority passed as argument.
 * @n
 * <b>Caller must ensure proper locking, either rcu (read lookup)
 * or spinlock (@a g_lock for write lookup)</b>
 * @param major Major number to lookup.
 * @param minor Base minor number to lookup.
 * @param range Minor range width to lookup.
 * @param priority Priority to lookup.
 * @return Pointer to the matching struct devctl_dev entry in the hash table
 * if found, error pointer for ENOENT if not found.
 */
static inline struct devctl_dev *
_do_exact_lookup(unsigned int major, unsigned int minor,
			unsigned int range, unsigned int priority)
{
	struct devctl_dev *cur;
	unsigned int hash = devctl_hash(major);
	struct hlist_head *head = &(g_htable[hash]);

	hlist_for_each_entry_rcu(cur, head, d_list) {
		if (exact_match(major, minor, range, cur)
				&& cur->d_priority == priority)
			return cur;
	}

	return ERR_PTR(-ENOENT);
}


/************************************************/
/*           'External' API                     */
/************************************************/


/**
 * Permission check for devctl entry loading / unloading.
 * We only allow the operation before @a _clsm_ctl_mount has been
 * set to zero, which provides a way to irreversibly lock devctl.
 */
#define devctl_permission() (!clsm_ctl_mount && capable(CAP_SYS_ADMIN))

/**
 * Default permissions for new mounts that are not found in
 * the devctl base.
 * This forces 'nosuid,noexec,nodev' on all unreferenced mounts ('forces'
 * meaning that mounts without those flags will be denied).
 * @n
 * This is only used when @a CONFIG_DEVCTL_STRICT was not set at compile
 * time.
 */
#define DEVCTL_PERM_DEFAULT	(DEVCTL_PERM_RW|DEVCTL_PERM_RO)

/**
 * Check devctl access permission to a device.
 * This looks up the device in the devctl store, and if found, compares
 * its permissions to the requested access mode.
 * If the device is not found in the devctl store, access is OK for all
 * non-mount block device accesses (no 'exec'/'dev'/'suid' property, only
 * read / write), and OK for a mount access only if
 * the mount options include 'nodev,noexec,nosuid'. The DEVCTL_STRICT
 * config option changes this, to deny any access to non referenced devices.
 * @n
 * <b> Uses an internal RCU read lock section. </b>
 * @param dev Device number for the accessed device.
 * @param mode Requested access mode.
 * @return 1 if access is authorized, 0 otherwise.
 */
int
devctl_check(dev_t dev, devctl_perm_t mode)
{
	struct devctl_dev *entry;
	devctl_perm_t mask = DEVCTL_PERM_DEFAULT;

	rcu_read_lock();
	entry = _do_ranged_lookup(dev);
	if (!IS_ERR(entry))
		mask = entry->d_perms;
#ifdef CONFIG_DEVCTL_STRICT
	else {
		rcu_read_unlock();
		return 0;
	}
#endif
	rcu_read_unlock();

	return ((mask & mode) == mode);
}

/**
 * Add a devctl entry to the hash table.
 * This adds allocates a device entry matching what is supplied as argument,
 * and adds it to the global hash table, if such an entry does not
 * exist already.
 * @n
 * <b> This call locks the @a g_lock spinlock. </b>
 * @n
 * Note that permission for this operation is expected to have been done by
 * the general ioctl() handler.
 * @param arg Devctl ioctl() argument specifying the new entry fields.
 * @return 0 in case of success, negative error code if the entry is already
 * present or in case of error. Whenever a non-zero value is returned, no new
 * entry is left allocated by the function.
 * @see _do_ioctl_load_unload()
 */
static int
devctl_add(const struct devctl_arg *arg)
{
	struct devctl_dev *new;
	int ret;

	new = devctl_new();
	if (unlikely(!new))
		return -ENOMEM;

	ret = arg2device(arg, new);
	if (ret) {
		devctl_free(new);
		return ret;
	}

	spin_lock(&g_lock);
	ret = _do_dev_add(new);
	spin_unlock(&g_lock);

	if (ret)
		devctl_free(new);
	return ret;
}

/**
 * Remove a devctl entry from the hash table.
 * This removes from the global hash table an (single, by construction) entry
 * matching what is supplied as argument, if such an entry exists in the table.
 * The removed entry is then freed. Note that freeing is not actually done by
 * this function, but is only scheduled for the next RCU quiescent state.
 * @n
 * <b> This call locks the @a g_lock spinlock. </b>
 * @n
 * Note that permission for this operation is expected to have been done by
 * the general ioctl() handler.
 * @param arg Devctl ioctl() argument specifying the entry to delete.
 * @return 0 if an entry was found and deleted, negative error code if no entry
 * was found or an error occured.
 * @see _do_ioctl_load_unload()
 */
static int
devctl_del(const struct devctl_arg *arg)
{
	struct devctl_dev *deleted;

	spin_lock(&g_lock);
	deleted = _do_exact_lookup(arg->a_major, arg->a_minor,
					arg->a_range, arg->a_priority);
	if (IS_ERR(deleted)) {
		spin_unlock(&g_lock);
		return -ENOENT;
	}

	hlist_del_rcu(&deleted->d_list);
	spin_unlock(&g_lock);
	call_rcu(&deleted->d_rcu, devctl_del_rcu);

	return 0;
}


/************************************************/
/*           IOCTL Interface                    */
/************************************************/

/**
 * Common helper for load / unload ioctls.
 * This checks the permissions for the required operation, then copies the
 * userland arguments and calls the appropriate handler.
 * @param file File the ioctl() was made on.
 * @param cmd Ioctl command code.
 * @param arg Ioctl argument.
 * @return 0 on success, negative error code on failure.
 */
static inline int
_do_ioctl_load_unload(struct file *file, unsigned int cmd,
				const struct devctl_arg *__user arg)
{
	struct devctl_arg marg;

	if (!(file->f_mode & FMODE_WRITE))
		return -EPERM;

	/* No point doing anything here if we don't have enough privs */
	if (unlikely(!devctl_permission()))
		return -EPERM;

	if (unlikely(copy_from_user(&marg, arg, sizeof(marg))))
		return -EFAULT;

	switch (cmd) {
		case DEVCTL_IO_LOAD:
			return devctl_add(&marg);
			break;
		case DEVCTL_IO_UNLOAD:
			return devctl_del(&marg);
			break;
		default:
			return -ENOTTY;
	}
}

/**
 * Devctl ioctl handler.
 * @param inode Inode the ioctl() was made on.
 * @param file File the ioctl() was made on.
 * @param cmd Ioctl command code.
 * @param arg Ioctl argument.
 * @return 0 on success, negative error code on failure.
 */
static long
devctl_ioctl(struct file *file, unsigned int cmd,
			unsigned long arg)
{
	return _do_ioctl_load_unload(file, cmd,
			(const struct devctl_arg __user *)arg);
}

/** Devctl device (/dev/devctl) file operations */
static struct file_operations devctl_fops = {
	.unlocked_ioctl = devctl_ioctl,
};

/**
 * Memory device open wrapper for devctl.
 * This checks the opened minor, and if it matches the devctl minor,
 * associates the devctl file operations to the device.
 * @param inode Opened inode.
 * @param file Opened file, with no valid file_operations struct. The
 * file_operations struct for this file will be set to devctl_fops
 * if the minor matches.
 * @return 0 on succes (minor matches), -ENXIO if minor does not match,
 * other negative error code on failure.
 */
int
devctl_device_open(struct inode *inode, struct file *file)
{
	if (iminor(inode) != DEVCTL_MINOR)
		return -ENXIO;

	file->f_op = &devctl_fops;
	return 0;
}

/************************************************/
/*           Proc interface                     */
/************************************************/

/** Number of keyletters needed to display a devctl_perm_t bitfield.
 * Includes trailing null char. For use with clsm_format_bitmask().
 */
#define PERMLEN 8

/** @name Devctl seq_file interface */
/*@{*/

/**
 * Helper: return entry at a virtual offset in the hash table.
 * This returns the first entry in the first non-empty hash
 * bucket after offset @a pos, and updates @a pos to point
 * after that bucket.
 * @n
 * <b> This must be called under RCU read lock. </b>
 * @param s seq_file being displayed
 * @param pos Virtual offset to start search from, and where to
 * store the updated offset.
 * @return Pointer to the first entry after the offset, if such an
 * entry is found, NULL otherwise.
 */

static inline struct devctl_dev *
devctl_atpos(struct seq_file *s, loff_t *pos)
{
	size_t off;
	struct hlist_node *first;

	if (*pos >= DEVCTL_HASH_SZ)
		return NULL;

	for (off = *pos; off < DEVCTL_HASH_SZ; ++off) {
		if (hlist_empty(&(g_htable[off])))
			continue;
		*pos = off + 1;
		first = rcu_dereference(g_htable[off].first);
		return hlist_entry(first, struct devctl_dev, d_list);
	}
	*pos = DEVCTL_HASH_SZ;
	return NULL;
}

/**
 * Start a seq_file display.
 * Return first entry after the initial virtual offset.
 * @n
 * <b> This starts a RCU read-locked section, which is terminated
 * by devctl_seq_stop() </b>
 * @param s seq_file being displayed
 * @param pos Virtual offset to start search from, and where to
 * store the updated offset.
 * @return Pointer to the first entry after the offset, if such an
 * entry is found, NULL otherwise.
 * @see devctl_seq_stop()
 */
static void *
devctl_seq_start(struct seq_file *s, loff_t *pos)
{
	rcu_read_lock();
	return devctl_atpos(s, pos);
}

/**
 * Iterate over a seq_file display.
 * Return the next iterated entry, which is either the next entry in the
 * current iterator's hash bucket (in which case the virtual offset is not
 * updated), or the first entry in the next non-empty hash bucket.
 * @n
 * <b> This must be called under a RCU read lock. </b>
 * @param s seq_file being displayed
 * @param v Current iterator (pointer to a struct devctl_dev).
 * @param pos Virtual offset to start search from, and where to
 * store the updated offset.
 * @return Pointer to the first entry after the offset, if such an
 * entry is found, NULL otherwise.
 */
static void *
devctl_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct devctl_dev *entry, *next;
	struct hlist_node *next_node;

	entry = v;
	next_node = rcu_dereference(entry->d_list.next);
	if (next_node) {
		next = hlist_entry(next_node, struct devctl_dev, d_list);
	} else {
		next = devctl_atpos(s, pos);
	}
	return next;
}

/**
 * Terminate a seq_file iteration.
 * <b> This ends the RCU read-locked section started by
 * devctl_seq_start(). </b>
 * @param s seq_file being displayed
 * @param v Current iterator (pointer to a struct devctl_dev).
 * @see devctl_seq_start()
 */
static void
devctl_seq_stop(struct seq_file *s, void *v)
{
	rcu_read_unlock();
}

/**
 * Display one seq_file iteration.
 * @param s seq_file being displayed
 * @param v Current iterator (pointer to a struct devctl_dev).
 * @return 0 on success, -1 if output buffer is full.
 */
static int
devctl_seq_print(struct seq_file *s, void *v)
{
	char perms[PERMLEN];
	struct devctl_dev *d = v;
	clsm_format_bitmask(perms, sizeof(perms), d->d_perms, devctl_perm_map);

	seq_printf(s, "%u/%u +%u (prio: %u) : %s\n",
				d->d_major, d->d_minor, d->d_range,
				d->d_priority, perms);
	return 0;
}

/*@}*/

/** Devctl seq_file operations */
static const struct seq_operations devctl_seq_ops = {
	.start	= devctl_seq_start,
	.next	= devctl_seq_next,
	.stop	= devctl_seq_stop,
	.show	= devctl_seq_print,
};

/**
 * Devctl /proc file (/proc/devctl) open().
 * Redirects to seq_file operations.
 * @param inode Inode for the opened proc file.
 * @param file Opened file.
 * @return 0 on success, negative error code on failure.
 */
static int
devctl_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &devctl_seq_ops);
}

/** Devctl /proc file operations */
static const struct file_operations devctl_proc_fops = {
	.open 		= devctl_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/**
 * Devctl /proc file (/proc/devctl) registration.
 * @return 0 on success, -ENOMEM on error.
 */
static inline int
devctl_create_proc(void)
{
	struct proc_dir_entry *proc = NULL;

	proc = proc_create("devctl", 0, NULL, &devctl_proc_fops);
	if (unlikely(!proc)) {
	    	CLSM_ERROR("failed to create proc entry\n");
        	return -ENOMEM;
	}
	return 0;
}

/**
 * Devctl /proc file unregistration.
 */
static inline void
devctl_remove_proc(void)
{
	remove_proc_entry("devctl", NULL);
}

/************************************************/
/*           Initialization                     */
/************************************************/

/**
 * Memory devices class, which must be exported by the kernel.
 */
extern struct class *mem_class;

/**
 * Devctl backend initialization.
 * This creates the kmem_cache for struct devctl_dev allocation, and
 * initializes the devctl lookup hash table.
 * @return Negative error code on error, 0 on success.
 */
int
devctl_init(void)
{
	int i, ret;

	g_cache = kmem_cache_create_usercopy("devctl_cache",
					sizeof(struct devctl_dev),
					0, SLAB_PANIC,
					0, sizeof(struct devctl_dev), NULL);

	if (unlikely(!g_cache)) {
		CLSM_ERROR("failed to create kmem cache\n");
		return -ENOMEM;
	}

	spin_lock_init(&g_lock);

	for (i = 0; i< DEVCTL_HASH_SZ; i++) {
		INIT_HLIST_HEAD(&(g_htable[i]));
	}

	ret = devctl_create_proc();
	if (unlikely(ret))
		goto err_cache;

	return 0;

err_cache:
	kmem_cache_destroy(g_cache);

	return ret;
}

/**
 * Bool: one if the devctl device is initialized.
 */
static int device_initialized = 0;

/**
 * Devctl device initialization.
 * This creates the /dev/devctl device.
 * @return Negative error code on error, 0 on success.
 */
int
devctl_device_init(void)
{
	struct device *dev;
	dev = device_create(mem_class, NULL,
			MKDEV(MEM_MAJOR, DEVCTL_MINOR),
			NULL, "devctl");
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	device_initialized = 1;
	return 0;
}

/**
 * Devctl device removal.
 * This destroys the /dev/devctl device.
 */
void
devctl_exit(void)
{
	if (likely(device_initialized))
		device_destroy(mem_class, MKDEV(MEM_MAJOR, DEVCTL_MINOR));
	devctl_remove_proc();
	kmem_cache_destroy(g_cache);
}

EXPORT_SYMBOL(devctl_perm_map);
EXPORT_SYMBOL(devctl_check);
EXPORT_SYMBOL(devctl_device_open);
EXPORT_SYMBOL(devctl_init);
EXPORT_SYMBOL(devctl_device_init);
EXPORT_SYMBOL(devctl_exit);
