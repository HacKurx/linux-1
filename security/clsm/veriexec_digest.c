// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file veriexec_digest.c
 *  veriexec digest algorithms
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2008 SGDN/DCSSI
 *  Copyright (C) 2011 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/veriexec.h>
#include <linux/export.h>
#include <linux/uio.h>
#include <crypto/hash.h>
#include <asm/highmem.h>

/*************************************************************/
/*                     Hash mapping                          */
/*************************************************************/

/** Veriexec digest names array. */
static const char *const vrxd_names[VERIEXEC_DIG_LAST+1] = VERIEXEC_DIG_NAMES;

/**
 * Allocate and return a Veriexec digest tfm.
 * @param dig Requested digest type.
 * @return Allocated tfm on success, NULL on failure.
 */
static inline struct crypto_shash *
vrxd_get_digest(veriexec_dig_t dig)
{
	const char *name;

	if (veriexec_digest_fplen(dig) == -1) {
		VERIEXEC_DEBUG("digest type %d is not supported"
					" by this kernel\n", dig);
		return NULL;
	}

	name = vrxd_names[dig];

	return crypto_alloc_shash(name, 0, 0);
}

/**
 * Return the digest name string for a veriexec digest type.
 * @param dig Digest type.
 * @return Digest name if the digest type is supported, "<invalid>" otherwise.
 */
inline const char *
veriexec_digest_getname(veriexec_dig_t dig)
{
	if (dig >= VERIEXEC_DIG_LAST)
		return "<invalid>";
	return vrxd_names[dig];
}


/*************************************************************/
/*                     Hash calc                             */
/*************************************************************/

/**
 * Veriexec hashing read actor.
 *
 * This hashes up to one page of data. crypto_shash_init() must have been called
 * earlier.
 *
 * @param page    page to read data from
 * @param offset  offset at which to start hashing data from the page
 * @param nr      maximum number of bytes to read from this page
 * @param iter    iov iterator used to read the file
 *
 * @return        the number of octets read.
 */
static size_t
vrxd_read_actor(struct page *page, unsigned int offset, unsigned int nr,
		struct iov_iter *iter)
{
	u8 * data;
	int ret;

	unsigned long count = iter->count;
	struct shash_desc *hdesc = (struct shash_desc*) iter->iov;

	// Truncate nr to min(iter->count, PAGE_SIZE - offset)
	if (nr > count)
		nr = count;

	if (nr > PAGE_SIZE - offset)
		nr = PAGE_SIZE - offset;

	data = kmap(page);

	ret = crypto_shash_update(hdesc, data + offset, nr);
	/* hashing is implemented by calling
	 * mm/filemap.c:do_generic_mapping_read(), which loops calling
	 * the read_actor only as long as that returns the size that
	 * was passed to it. Furthermore, it is a void function, with
	 * no error code returned. Thus, returning 0 here will indeed
	 * stop the hashing, and not lose any error information.
	 */
	kunmap(page);

	if (unlikely(ret))
		return 0;

	iter->count = count - nr;
	iter->iov_offset += nr;

	return nr;
}

extern ssize_t do_actor_file_read(struct file *filp, loff_t *ppos,
		struct iov_iter *iter, ssize_t written, iter_actor_t actor);

/**
 * Hash one file.
 *
 * This calls the hashe's init(), then sends the hash through
 * generic_file_read() which will call update() on each page of the file, then
 * calls final().
 *
 * @param hdesc Hash descriptor to calculate the digest.
 * @param file File to hash.
 * @param size Number of bytes to hash from @a file (starting at offset 0).
 * @param fp Buffer to store the digest to. This must have been pre-allocated
 * by the caller, with a length sufficient for storing that hash (packed, no
 * trailling null byte.
 *
 * @return 0 on success, negative error on failure.
 */
static ssize_t
vrxd_digest_calc(struct shash_desc *hdesc, struct file *file, size_t size,
		unsigned char *fp)
{
	ssize_t ret;
	loff_t mypos = 0ll;
	struct iov_iter iter;
	int written = 0;

	memset(fp, 0, crypto_shash_digestsize(hdesc->tfm));

	ret = crypto_shash_init(hdesc);
	if (unlikely(ret))
		return ret;

	iter.iov_offset = 0;
	iter.count = size;
	iter.iov = (struct iovec*) hdesc;
	iter.type = 0;

	written = do_actor_file_read(file, &mypos, &iter, 0, vrxd_read_actor);

	// Negative values used to report errors
	if (written < 0) {
		VERIEXEC_ERROR("Hashing errors: %d errors", iter.type);
		return -EFAULT;
	}
	if (written != size) {
		VERIEXEC_ERROR("size mismatch: written is %d, size is %d\n",
				written, size);
		return -EFAULT;
	}

	ret = crypto_shash_final(hdesc, fp);
	return ret;
}

/*************************************************************/
/*                     Hash verification                     */
/*************************************************************/

/**
 * Check that a file matches its stored fingerprint.
 *
 * This hashes @a file using the digest type specified in @a entry, and
 * compares the result to the fingerprint stored in @a entry.
 *
 * @param file  File to hash.
 * @param entry Veriexec entry to check.
 *
 * @return 0 if the hashes match,
 *         negative error code in case of mismatch, or if an error was
 *         encountered.
 */
int
veriexec_digest_verify(struct file *file, const struct veriexec_entry *entry)
{

	struct crypto_shash *tfm;
	struct shash_desc *desc;
	char *fp;
	size_t fplen;
	int retval;
	int desc_size;

	loff_t fsize;
	const char *fname;

	fsize = file->f_path.dentry->d_inode->i_size;
	fname = file->f_path.dentry->d_name.name;

	tfm = vrxd_get_digest(entry->ve_dig);

	if (!tfm || IS_ERR(tfm)) {
		VERIEXEC_ERROR("could not alloc digest for dig_t %d\n",
				entry->ve_dig);
		return -EINVAL;
	}

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	fplen = crypto_shash_digestsize(tfm);

	desc = kzalloc(desc_size + fplen, GFP_KERNEL);
	if (unlikely(!desc)) {
		VERIEXEC_ERROR("could not alloc digest hash for dig_t %d, fname %s\n",
				entry->ve_dig, fname);
		retval = -ENOMEM;
		goto out_free_tfm;
	}
	fp = (void *)desc + desc_size;

	desc->tfm = tfm;
	desc->flags = 0;
	retval = vrxd_digest_calc(desc, file, fsize, fp);

	if (retval) {
		VERIEXEC_ERROR("error %d in digest calculation for file %s\n",
				retval , fname);
		goto out_free_fp;
	}

	retval = memcmp(fp, entry->ve_fp, fplen);

	if (retval) {
		char buf1[2*fplen+1];
		char buf2[2*fplen+1];

		veriexec_digest_hexdump(entry->ve_fp, buf1, fplen);
		veriexec_digest_hexdump(fp, buf2, fplen);
		VERIEXEC_ERROR("hash mismatch on '%s'\n", fname);
		VERIEXEC_ERROR("expected:    %s\n", buf1);
		VERIEXEC_ERROR("got instead: %s\n", buf2);

		retval = -EINVAL;
		goto out_free_fp;
	}

	VERIEXEC_WARN("%s: Verified '%s'\n", __FUNCTION__, fname);

	/* Fall through */
out_free_fp:
	kfree(desc);
out_free_tfm:
	crypto_free_shash(tfm);

	return retval;
}

EXPORT_SYMBOL(veriexec_digest_verify);
EXPORT_SYMBOL(veriexec_digest_getname);
