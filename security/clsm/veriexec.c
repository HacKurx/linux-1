// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file veriexec.c
 *  Veriexec core
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2008 SGDN/DCSSI
 *  @n
 *  All rights reserved.
 *
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/device.h>
#include <linux/major.h>

#include <linux/veriexec.h>

#include <linux/seq_file.h>
#include <linux/proc_fs.h>

#ifdef CONFIG_VSERVER
#include <linux/vserver/check.h>
/** 1 if current is in Vserver ADMIN or WATCH context, 0 otherwise. */
#define vrx_admin_watch_ctx() vx_check(0, VS_ADMIN|VS_WATCH_P)
#else
#define vrx_admin_watch_ctx() 1
#endif

#include "clsm_file.h"

/*************************************************************/
/*              bitmask map for /proc display                */
/*************************************************************/

const clsm_bmap_t veriexec_flag_map[] = DEFINE_VERIEXEC_FLAG_MAP;

/*************************************************************/
/*              fingerprint allocation                       */
/*************************************************************/

/** @name Veriexec fingerprint cache */
/*@{*/
/** @addtogroup kmem_caches Kmem caches */
/*@{*/

/** kcache for veriexec fingerprint allocation. */
static struct kmem_cache *fp_kcache = NULL;

/*@}*/
/*@}*/

/**
 * Initialize Veriexec fingerprint kcache.
 * Note that the size of cache entries is the maximum fingerprint
 * length supported by kernel, which can only be determined at runtime,
 * based on CCSD hash size.
 * <b>BUGS if fp_kcache is already allocated. </b>
 * @return 0 on success, -ENOMEM on failure.
 * @see fp_kcache
 */
static inline int
vrx_fpcache_create(void)
{
	BUG_ON(fp_kcache);

	fp_kcache = kmem_cache_create_usercopy("vrx_fp_kcache",
					veriexec_digest_fplen_max(),
					0, SLAB_PANIC,
					0, veriexec_digest_fplen_max(), NULL);

	if (!fp_kcache) {
		VERIEXEC_DEBUG("Failure creating fingerprint kcache\n");
		return -ENOMEM;
	}
	return 0;
}

/**
 * Destroy Veriexec fingerprint kcache.
 * <b>BUGS if fp_kcache is not allocated yet.</b>
 * @return 0
 * @see fp_kcache
 */
static inline int
vrx_fpcache_destroy(void)
{
	BUG_ON(!fp_kcache);
	kmem_cache_destroy(fp_kcache);
	return 0;
}


/*************************************************************/
/*                   cache management                        */
/*************************************************************/
#ifdef CONFIG_VERIEXEC_CACHE

extern void __put_super(struct super_block *sb);
extern struct super_block *user_get_super(dev_t dev);

extern spinlock_t sb_lock;

/**
 * Remove an entry from the verification cache.
 * This is done by removing the cached flag from the
 * CLSM security tag of the matching inode. This call is
 * performed when removing the entry from the veriexec store,
 * but not when the inode is accessed from writing, since in that
 * case no inode lookup is needed to find the matching inode.
 * <b>Locks and unlocks sb_lock.</b>
 * @n
 * <b>Read-locks @a dev 's superblock umount mutex.</b>
 * <b>Locks cached inode's @a i_lock spinlock.</b>
 * @param dev Device for the entry to uncache.
 * @param ino Inode number for the entry to uncache.
 */
void
veriexec_cache_clear(dev_t dev, ino_t ino)
{
	struct super_block *sb;
	struct inode *inode;

	sb = user_get_super(dev);
	if (unlikely(!sb))
		return;

	inode = ilookup(sb, ino);
	if (inode) {
		spin_lock(&inode->i_lock);
		veriexec_inode_uncache(inode);
		spin_unlock(&inode->i_lock);
		iput(inode);
	}

	up_read(&sb->s_umount);
	spin_lock(&sb_lock);
	__put_super(sb);
	spin_unlock(&sb_lock);
}

#else /* !CONFIG_VERIEXEC_CACHE */
#define vrhl_cache_clear(dev, ino) do {;} while (0)
#endif /* !CONFIG_VERIEXEC_CACHE */


/*************************************************************/
/*                entry allocation                           */
/*************************************************************/

/** @name Veriexec entry cache */
/*@{*/
/** @addtogroup kmem_caches Kmem caches */
/*@{*/

/** kcache for veriexec entry allocation. */
static struct kmem_cache *entry_kcache = NULL;

/*@}*/
/*@}*/

#ifdef CONFIG_VERIEXEC_DEBUG_MEMLEAK
/** Global veriexec entry count (all contexts) */
static atomic_t entry_count;
#endif

/**
 * Initialize Veriexec entry kcache.
 * <b>BUGS out if entry_kcache is already allocated. </b>
 * @return 0 on success, -ENOMEM on failure.
 * @see entry_kcache
 */
static inline int
vrx_ecache_create(void)
{
	BUG_ON(entry_kcache);

	entry_kcache = kmem_cache_create_usercopy("vrx_entry_kcache",
					sizeof(struct veriexec_entry),
					0, SLAB_PANIC,
					0, sizeof(struct veriexec_entry), NULL);

	if (!entry_kcache) {
		VERIEXEC_DEBUG("Failure creating entry kcache\n");
		return -ENOMEM;
	}
#ifdef CONFIG_VERIEXEC_DEBUG_MEMLEAK
	atomic_set(&entry_count, 0);
#endif
	return 0;
}

/**
 * Destroy Veriexec entry kcache.
 * <b>BUGS out if entry_kcache is not allocated yet.</b>
 * @return 0
 * @see entry_kcache
 */
static inline int
vrx_ecache_destroy(void)
{
	BUG_ON(!entry_kcache);
	kmem_cache_destroy(entry_kcache);
	return 0;
}

/**
 * Allocate a new Veriexec entry.
 * Sets the device and inode number for the entry, and sets
 * the pointer fields to NULL, but all other fields are undetermined.
 * Increases the entry count.
 * @param dev Device number for the new entry.
 * @param ino Inode number for the new entry.
 * @return Allocated entry on success, NULL on error (out of memory).
 */
struct veriexec_entry *
veriexec_entry_new(dev_t dev, ino_t ino)
{
	struct veriexec_entry *entry;

	entry = kmem_cache_alloc(entry_kcache, GFP_KERNEL);

	if (unlikely(!entry))
		return NULL;

#ifdef CONFIG_VERIEXEC_DEBUG_MEMLEAK
	atomic_inc(&entry_count);
#endif

	VERIEXEC_ENTRY_INIT(entry);

	entry->ve_dev = dev;
	entry->ve_ino = ino;
	entry->ve_fp = NULL;

	return entry;
}

/**
 * Destroy a Veriexec entry.
 * This removes the entry from the veriexec verification cache,
 * then frees it and all its fields.
 * Also decreases the entry count.
 * <b>BUGS out if @a entry is NULL.</b>
 * @param entry Entry to free.
 */
void
veriexec_entry_free(struct veriexec_entry *entry)
{
	BUG_ON(!entry);

	if (entry->ve_fp)
		kmem_cache_free(fp_kcache, entry->ve_fp);

#ifdef CONFIG_VERIEXEC_DEBUG_MEMLEAK
	atomic_dec(&entry_count);
#endif
	kmem_cache_free(entry_kcache, entry);
}

/**
 * Read global veriexec entry count into a variable.
 * This only works if CONFIG_VERIEXEC_DEBUG_MEMLEAK is set.
 * @param count Where to store the entry count.
 * @return 0 on success, -EPERM if called from a non-ADMIN non-WATCH
 * vserver context, -ENOTTY if not supported.
 */
int veriexec_get_entcount(int *count)
{
#ifdef CONFIG_VERIEXEC_DEBUG_MEMLEAK
	if (!vrx_admin_watch_ctx())
		return -EPERM;
	*count = atomic_read(&entry_count);
	return 0;
#else
	return -ENOTTY;
#endif
}

/*************************************************************/
/*              common utility functions                     */
/*************************************************************/


/**
 * Return the integer value of a lowercase hexadecimal digit.
 * @param c Hexadecimal digit. Must be a valid lowercase digit.
 * @return Integer value of @a c.
 */
static inline unsigned char
_val(char c)
{
	return isdigit(c) ? c - '0' : c - 'a' + 10;
}

/**
 * 1 if @a c is a lowercase hexadecimal digit, 0 otherwise.
 */
#define islowxdigit(c) (isdigit(c) || ( isxdigit(c) && islower(c) ))

/**
 * Pack an ASCII-armored byte array into a byte array.
 * No size checks are performed on destination.
 * @param src ASCII-armored byte array, with each byte represented by two
 * @b lowercase hexadecimal digits. This array must contain at least 2 * @a len
 * readable bytes.
 * @param dst Allocated destination, with a length of at least @a len.
 * @param len Number of bytes to write to @a dst. These are made from the first
 * 2 * @a len bytes of @a src.
 * @return 0 on success, -1 on failure (one of @a src 's bytes is not a lowercase
 * hexadecimal digit.
 */
static inline int
_pack(unsigned char *src, unsigned char *dst, size_t len)
{
	while (len--) {
		if (!islowxdigit(*src))
			return -1;
		*dst = _val(*src++) << 4;
		if (!islowxdigit(*src))
			return -1;
		*dst++ += _val(*src++);
	}
	return 0;
}

/**
 * Copy the fields from a veriexec IOCTL into a veriexec entry.
 * This allocates the entry's fingerprint and possibly name fields.
 * Note that the fingerprint is ASCII-armored in the IOCTL argument,
 * but packed in the entry.
 * <b> BUGS out if the entry's fingerprint or name fields are already
 * allocated. </b>
 * @param entry Entry to store the fields to. Must be allocated, with its
 * pointer fields not allocated.
 * @param arg IOCTL argument to read the fields from. Must be in kernel
 * memory, but with pointer fields pointing to userland memory.
 */

inline int
veriexec_copy_args(struct veriexec_entry *entry,
			const struct veriexec_arg *arg)
{
	int ret = -EFAULT;
	size_t fplen;
	char *buf = NULL;

	BUG_ON(entry->ve_fp);
	fplen = veriexec_digest_fplen(arg->a_dig);
	if (unlikely(fplen == -1))
		return -EINVAL;

	buf = kmalloc(2 * fplen + 1, GFP_USER);
	if (unlikely(!buf))
		return -ENOMEM;

	if (unlikely(copy_from_user(buf, arg->a_fp, 2*fplen))) {
		kfree(buf);
		return -EFAULT;
	}

	entry->ve_fp = kmem_cache_alloc(fp_kcache, GFP_KERNEL);
	if (unlikely(!entry->ve_fp)) {
		kfree(buf);
		return -ENOMEM;
	}

	if (unlikely(_pack(buf, entry->ve_fp, fplen))) {
		kfree(buf);
		ret = -EINVAL;
		goto out_freefp;
	}
	kfree(buf);
	entry->ve_dig = arg->a_dig;

	entry->ve_flags = arg->a_flags;
	vrx_cap_copy(arg->a_caps, entry->ve_caps);
	entry->ve_privs = arg->a_privs;
	return 0;

	/* Error handling */
out_freefp:
	kmem_cache_free(fp_kcache, entry->ve_fp);
	entry->ve_fp = NULL;
	return ret;
}

/**
 * Fill a file id structure from the file name in a Veriexec IOCTL argument.
 * This performs a path lookup to find the matching inode, and store its
 * ID in the target fileid. Optionnally, write access to the underlying
 * vfsmount can be checked before returning the ID.
 * @param arg IOCTL argument to read file name from. This must be in
 * kernel memory, but with a file name pointer field pointing to userland.
 * @param fid Pointer to a pre-allocated clsm_fileid struct to write the
 * file id to (if found and, optionnally, write access is permitted).
 * @param checkwrite If non zero, write access on the underlying vfsmount
 * is checked before returning a (found) file's id. If write access is denied,
 * an error (EPERM) is returned instead of the file's id.
 * @return 0 on success, negative error code on failure.
 */
int
veriexec_arg2fid(const struct veriexec_arg *arg,
			struct clsm_fileid *fid, int checkwrite)
{
	char *fname;
	int ret;

	/* Shut up some stupid gcc warning ... */
	fid->f_inode = 0UL;
	fid->f_dev = 0UL;

	if (unlikely(!arg->a_fname_size)) {
		VERIEXEC_DEBUG("%s: fname_size is null\n", __FUNCTION__);
		return -EINVAL;
	}

	fname = kmalloc(arg->a_fname_size+1, GFP_KERNEL);
	if (unlikely(!fname))
		return -ENOMEM;

	if (unlikely(copy_from_user(fname, arg->a_fname, arg->a_fname_size))) {
		ret = -EFAULT;
		goto out_free;
	}

	fname[arg->a_fname_size] = '\0';

	ret = clsm_name2fid(fname, fid, checkwrite);

	/* Fall through */
out_free:
	kfree(fname);
	return ret;
}

/**
 * Create a veriexec entry.
 * This allocates a new entry, and sets its fields based on a Veriexec IOCTL
 * argument, and clsm_fileid (passed here to avoid performing the same path
 * lookup twice).
 * @param arg IOCTL Argument to read fields from.
 * @param fid File ID info for the inode this entry is created for.
 * @return Pointer to newly allocated entry on success, error pointer
 * on failure.
 */
struct veriexec_entry *
veriexec_entry_create(const struct veriexec_arg *arg,
				const struct clsm_fileid *fid)
{
	struct veriexec_entry *entry;
	int ret;

	entry = veriexec_entry_new(fid->f_dev, fid->f_inode);
	if (unlikely(!entry))
		return ERR_PTR(-ENOMEM);

	ret = veriexec_copy_args(entry, arg);
	if (unlikely(ret)) {
		veriexec_entry_free(entry);
		return ERR_PTR(-EFAULT);
	}

	return entry;
}

/** Maximum length of a CLSM privs mask represented as string. */
#define PRIVLEN 16
/** Maximum length of a Veriexec flags mask represented as string. */
#define FLAGLEN 8

/* Copied out of fs/proc/array.c */
static inline void
render_cap_t(struct seq_file *m, const char *header,
		const char *footer, const kernel_cap_t *a)
{
        unsigned __capi;

        seq_printf(m, "%s", header);
        CAP_FOR_EACH_U32(__capi) {
                seq_printf(m, "%08x",
                           a->cap[(_KERNEL_CAPABILITY_U32S-1) - __capi]);
        }
        seq_printf(m, "%s", footer);
}

/**
 * Print one veriexec entry in a /proc file, through the seq_file interface.
 * Note that the fingerprint will not be printed if memory cannot be allocated.
 */
void
veriexec_entry_seqprint(struct seq_file *s, const struct veriexec_entry *entry)
{
	char *buf;
	int allocated = 0;
	char privs[PRIVLEN], flags[FLAGLEN];

	size_t fplen = veriexec_digest_fplen(entry->ve_dig);
	if (unlikely(fplen == -1))
		return;

	buf = kmalloc(2 * fplen + 1, GFP_USER);
	if (likely(buf)) {
		allocated = 1;
		veriexec_digest_hexdump(entry->ve_fp, buf, fplen);
	} else {
		buf = "<out of memory>";
	}

	clsm_format_bitmask(privs, sizeof(privs),
					entry->ve_privs, clsm_priv_map);
	clsm_format_bitmask(flags, sizeof(flags),
					entry->ve_flags, veriexec_flag_map);

	(void)seq_printf(s, "d:0x%x i:0x%lx: flags %s, caps ",
			entry->ve_dev, entry->ve_ino,
			flags);
	render_cap_t(s, "0x", ", ", &entry->ve_caps.v_cap_e);
	render_cap_t(s, "0x", ", ", &entry->ve_caps.v_cap_p);
	render_cap_t(s, "0x", ", ", &entry->ve_caps.v_cap_i);
	(void)seq_printf(s,"privs %s, %s %s\n",
			privs,
			veriexec_digest_getname(entry->ve_dig),
			buf);

	if (allocated)
		kfree(buf);
}

/*************************************************************/
/*              init and module registration                 */
/*************************************************************/

/**
 * Create the veriexec proc interface (/proc/veriexec).
 * @return 0 on success, negative error code on failure.
 */
static inline int
veriexec_create_proc(void)
{
	struct proc_dir_entry *proc = NULL;

	proc = proc_create("veriexec", 0, NULL, &veriexec_proc_fops);
	if (unlikely(!proc)) {
	    printk(KERN_ERR "veriexec could not create proc entry\n");
        	return -ENOMEM;
	}
	return 0;
}

/**
 * Remove the veriexec proc interface (/proc/veriexec).
 */
static inline void
veriexec_remove_proc(void)
{
    remove_proc_entry("veriexec", NULL);
}

/**
 * Memory char device class, as exported by the kernel.
 */
extern struct class *mem_class;

/**
 * Initialize the veriexec subsystem.
 * This performs the following steps:
 * @li Initialize the veriexec fingerprint and entry kcaches.
 * @li Call the veriexec store backend initialization.
 * @li Create the veriexec proc interface, if configured.
 * @return 0 on success, negative error code on success (in which case no
 * memory is left allocated.
 */
int
veriexec_init(void)
{
	int retval = 0;

	printk(KERN_INFO "Veriexec : starting up\n");

	retval = vrx_fpcache_create();
	if (retval)
		return retval;

	retval = vrx_ecache_create();
	if (retval)
		goto out_fp;


	retval = veriexec_init_store();
	if (retval) {
		VERIEXEC_ERROR("Could not init store\n");
		goto out_entry;
	}

	retval = veriexec_create_proc();
	if (retval) {
		VERIEXEC_ERROR("Could not init proc interface\n");
		goto out_store;
	}

	printk(KERN_INFO "Veriexec : initialization complete\n");

	return 0;

	/* Error handling */
out_store:
	veriexec_exit_store();
	/* Fall through */
out_entry:
	vrx_ecache_destroy();
	/* Fall through */
out_fp:
	vrx_fpcache_destroy();
	return retval;
}

/** Bool: one if the veriexec device is initialized. */
static int device_initialized = 0;

/**
 * Veriexec device initialization.
 * This creates the /dev/veriexec device.
 * @return Negative error code on failure, 0 on success.
 */
int
veriexec_device_init(void)
{
	struct device *dev;
	printk(KERN_INFO "Veriexec : creating device\n");

	dev = device_create(mem_class, NULL,
		MKDEV(MEM_MAJOR, VERIEXEC_MINOR), NULL, "veriexec");

	if (IS_ERR(dev)) {
		printk(KERN_ERR "Failed to create device (%ld)\n", PTR_ERR(dev));
		return PTR_ERR(dev);
	}
	device_initialized = 1;
	return 0;
}

/**
 * Destroy the veriexec subsystem.
 * This frees all memory allocated by the subsystem, and
 * removes its caches.
 * <b>Not implemented yet. </b>
 * Not __exit on purpose, since it is called in __init functions
 * error handling.
 */
void
veriexec_exit(void)
{
	if (likely(device_initialized))
		device_destroy(mem_class, MKDEV(MEM_MAJOR, VERIEXEC_MINOR));
	veriexec_remove_proc();
	veriexec_exit_store();

	/* Clear the (now empty) caches */
	vrx_ecache_destroy();
	vrx_fpcache_destroy();

	printk(KERN_INFO "Veriexec backend destroyed\n");
}

EXPORT_SYMBOL(veriexec_flag_map);
EXPORT_SYMBOL(veriexec_entry_new);
EXPORT_SYMBOL(veriexec_entry_free);
EXPORT_SYMBOL(veriexec_get_entcount);
EXPORT_SYMBOL(veriexec_copy_args);
EXPORT_SYMBOL(veriexec_arg2fid);
EXPORT_SYMBOL(veriexec_entry_create);
EXPORT_SYMBOL(veriexec_entry_seqprint);
EXPORT_SYMBOL(veriexec_init);
EXPORT_SYMBOL(veriexec_device_init);
EXPORT_SYMBOL(veriexec_exit);
