// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file vdigest.h
 *  veriexec digest header
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2008 SGDN/DCSSI
 *  Copyright (C) 2011 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#ifndef _LINUX_VERIEXEC_DIG_H
#define _LINUX_VERIEXEC_DIG_H

#ifdef __KERNEL__
#include <linux/types.h>
#ifndef CONFIG_VERIEXEC_DIG_MD5
#ifndef CONFIG_VERIEXEC_DIG_SHA1
#ifndef CONFIG_VERIEXEC_DIG_SHA256
#ifndef CONFIG_VERIEXEC_DIG_CCSD
#error No veriexec digest algorithm selected.
#endif
#endif
#endif
#endif
#endif /* __KERNEL__ */

/**
 * Veriexec digest types.
 */
enum veriexec_digest {
	VERIEXEC_DIG_MD5,
	VERIEXEC_DIG_SHA1,
	VERIEXEC_DIG_SHA256,
	VERIEXEC_DIG_CCSD,
	VERIEXEC_DIG_LAST
};

/** Initialize "digest-names" arrays. */
#define VERIEXEC_DIG_NAMES { \
	"md5", \
	"sha1", \
	"sha256", \
	"ccsd_digest", \
	"last" \
}

/**
 * Veriexec digest types.
 */
typedef enum veriexec_digest veriexec_dig_t;

#ifdef CONFIG_VERIEXEC_DIG_CCSD
/**
 * CCSD hash size getter, provided by CCSD.
 */
extern int ccsd_digest_size(void);
#endif

/**
 * Return length needed to store a fingerprint for a given digest type.
 * @param dig Digest type.
 * Note that this is the packed length. ASCII-armored storage needs
 * twice this length + possible trailing null byte.
 * @return Positive digest length for a supported digest type.
 * -1 for an unsupported digest type.
 */
static inline int
veriexec_digest_fplen(veriexec_dig_t dig)
{
	switch (dig) {
#ifdef CONFIG_VERIEXEC_DIG_MD5
	case VERIEXEC_DIG_MD5:
		return 16;
#endif
#ifdef CONFIG_VERIEXEC_DIG_SHA1
	case VERIEXEC_DIG_SHA1:
		return 20;
#endif
#ifdef CONFIG_VERIEXEC_DIG_SHA256
	case VERIEXEC_DIG_SHA256:
		return 32;
#endif
#ifdef CONFIG_VERIEXEC_DIG_CCSD
	case VERIEXEC_DIG_CCSD:
		return ccsd_digest_size();
#endif
	default:
		return -1;
	}
}

/**
 * Return maximum packed length of a veriexec fingerprint.
 * This is the maximum length for all digest types
 * supported by the kernel.
 * @return Maximum packed length in bytes.
 */
static inline int
veriexec_digest_fplen_max(void)
{
	int stat = 0, dyn = 0;
#ifdef CONFIG_VERIEXEC_DIG_MD5
	stat = 16;
#endif
#ifdef CONFIG_VERIEXEC_DIG_SHA1
	stat = 20;
#endif
#ifdef CONFIG_VERIEXEC_DIG_SHA256
	stat = 32;
#endif
#ifdef CONFIG_VERIEXEC_DIG_CCSD
	dyn = ccsd_digest_size();
#endif
	return (dyn > stat) ? dyn : stat;
}

/**
 * Format a human-readable fingerprint.
 * @param fp Non-human-readable fingerprint, with length @a len.
 * @param dest Destination storage for human-readable output.
 * Must be allocated with a size of at least 2 * @a len + 1.
 * @param len Non-human-readable fingerprint length.
 */
static inline void
veriexec_digest_hexdump(char *fp, char *dest, size_t len)
{
	while (len--) {
		/* Stupid integer expansion -> & 0xff */
		sprintf(dest, "%02x", (*fp++) & 0xff);
		dest+=2;
	}
	*dest='\0';
}

/************************* end userland **********************/

#ifdef __KERNEL__

struct file;
struct veriexec_entry;

/* Return human-readable name for a digest type */
extern const char * veriexec_digest_getname(veriexec_dig_t);

/* Check that a file matches its stored fingerprint */
extern int veriexec_digest_verify(struct file *, const struct veriexec_entry *);

#endif /*__KERNEL__*/
#endif /*_LINUX_VERIEXEC_DIG_H*/
