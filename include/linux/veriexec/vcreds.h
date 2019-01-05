// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file vcreds.h
 *  veriexec credentials header
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2008 SGDN/DCSSI
 *  Copyright (C) 2010-2011 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */
#ifndef _LINUX_VERIEXEC_CAPS_H
#define _LINUX_VERIEXEC_CAPS_H

#include <linux/capability.h>

/** Veriexec entry flags bitmask.
 * Supported values are listed in the @ref veriexec_flags section.
 */
typedef unsigned short veriexec_flags_t;

/*************************************************************/
/*                        Entry flags                        */
/*************************************************************/

/** @name Veriexec Entry Flags */
/*@{*/
/** @defgroup veriexec_flags Veriexec Flags */
/*@{*/

/**
 * Nuthin
 */
#define VRX_FLAG_NONE			0x0000

/**
 * Executable type.
 * Veriexec is called for this file on execve()
 */
#define VRX_FLAG_EXE			0x0001

/**
 * Library type.
 * Veriexec is called for this file on PROT_EXEC mappings,
 * excluding execve()
 */
#define VRX_FLAG_LIB			0x0002

/**
 * Root restriction.
 * Veriexec is called only if current->uid == 0 and current->euid == 0
 */
#define VRX_FLAG_NEEDROOT		0x0004

/**
 * Check reference of every library loaded afterwards.
 * Check every file that the raised task mmap(PROT_EXEC)'s,
 * as well as it's runtime linker. Revoke credentials if one
 * dependency fails test. This only checks the files' presence
 * in the store, not the associated fingerprints.
 */
#define VRX_FLAG_NEEDLIBS		0x0008
/**
 * Check digest of every library loaded afterwards.
 * Check every file that the raised task mmap(PROT_EXEC)'s,
 * as well as it's runtime linker. Revoke credentials if one
 * dependency fails test. This checks the files' presence
 * in the store, and verifies the associated fingerprints.
 */
#define VRX_FLAG_CHECKLIBS		0x0010

/**
 * Force inheritable capabilities.
 * Raise the inheritable capset of the exec()ing task,
 * as well as that of the bprm
 */
#define VRX_FLAG_INHERIT		0x0100

/**
 * Script mode.
 * This entry flag, when transfered to a task through that task's
 * verified binprm, makes it possible to load a second binprm in
 * that task without losing the original entry's privileges. It is
 * thus appropriate for scripts, for which the script interpreter is
 * loaded after the script itself and would otherwise mask out any
 * script-specific entry.
 * More precisely, when a task with this flag loads a second binary, the
 * original binprm's caps and privs are kept and intersected with those
 * provided by the new binprm's entry, if and only if that entry exists
 * and itself has the VRX_FLAG_INTERP flag (see below). In all other cases,
 * (no interpreter entry, or an entry without the INTERP flag, ...), all
 * caps and privs are revoked when loading a second binary.
 * Note that this is really not appropriate for executables which are not
 * scripts: in that case, the executable would be granted caps and privs
 * as usual, but would then lose them entirely if it ever does an exec().
 * In the case of a script, loading a second binary is automatic, and the
 * SCRIPT flag is lost as soon as the interpreter (which should generally
 * itself not have the SCRIPT flag) is loaded.
 */
#define VRX_FLAG_SCRIPT			0x0200

/**
 * Kernel thread restriction.
 * Veriexec is only called on first userland exec of a kernel thread,
 * e.g. kernel_execve(../sbin/hotplug...)
 */
#define VRX_FLAG_KTHREAD		0x0400

/**
 * Interpreter entry.
 * This flag is appropriate for entries which correspond to a script
 * interpreter (bash, perl, python). Such an interpreter should not
 * in itself have privileges (or else you might as well give them to
 * the whole system), but specific scripts might need some privileges
 * (note however that it is very difficult to control the execution
 * environment in e.g. shell scripts, and giving significant privileges
 * to such scripts might introduce a gaping security vulnerability).
 * Simply giving a script a regular veriexec entry would not work, as the
 * interpreter is loaded after the script and would thus mask its veriexec
 * entry. On the other hand, giving the interpreter itself all the needed
 * privileges is definitely not recommended.
 * This flag allows a script interpreter to have capabilities and privileges
 * of its own, which are not granted to the interpreter itself (and thus not
 * to every script it runs), but are used when the interpreter is loaded in
 * a task that already bears the VRX_FLAG_SCRIPT flag. In that case, the
 * original caps and privs are not reset, but instead simply intersected with
 * those of the interpreter's entry. It is thus possible to define a general
 * limit to what privileges can be granted to scripts relying on a given
 * interpreter, whithin which every script may be granted its specific subset
 * of privileges through its own veriexec entry.
 */
#define VRX_FLAG_INTERP			0x0800

/**
 * Allow privilege/capability bumping on 'unsafe' process.
 * By default, an 'unsafe' process (i.e. one which is either ptraced or which
 * shares some of its elements - fd table, etc. - with another process)
 * cannot acquire the privileges or capabilities granted by a veriexec entry.
 * Setting this flag on a veriexec entry will allow it to be used by an
 * unsafe process.
 */
#define VRX_FLAG_UNSAFE			0x1000

/**
 * Mask matching all valig veriexec flags.
 */
#define VRX_FLAG_MASK (\
		VRX_FLAG_NONE		| \
		VRX_FLAG_EXE		| \
		VRX_FLAG_LIB		| \
		VRX_FLAG_NEEDROOT	| \
		VRX_FLAG_NEEDLIBS	| \
		VRX_FLAG_CHECKLIBS	| \
		VRX_FLAG_INHERIT	| \
		VRX_FLAG_SCRIPT		| \
		VRX_FLAG_KTHREAD	| \
		VRX_FLAG_INTERP		| \
		VRX_FLAG_UNSAFE		\
	)


/**
 * Map veriexec flags to keyletters for display.
 */
#define DEFINE_VERIEXEC_FLAG_MAP { \
	{ VRX_FLAG_NONE		, '-'}, \
	{ VRX_FLAG_EXE		, 'e'}, \
	{ VRX_FLAG_LIB		, 'l'}, \
	{ VRX_FLAG_NEEDROOT	, 'r'}, \
	{ VRX_FLAG_NEEDLIBS	, 'N'}, \
	{ VRX_FLAG_CHECKLIBS	, 'L'}, \
	{ VRX_FLAG_INHERIT	, 'I'}, \
	{ VRX_FLAG_SCRIPT	, 's'}, \
	{ VRX_FLAG_KTHREAD	, 'k'}, \
	{ VRX_FLAG_INTERP	, 'i'}, \
	{ VRX_FLAG_UNSAFE	, 'u'}, \
	{ 0, 0 }, \
}

/*@}*/
/*@}*/

/** @name Veriexec Flags Check Macros */
/*@{*/

/**
 * Check if a veriexec flag mask is valid.
 */
#define VRXF_VALID(flag) \
		( ((flag) & VRX_FLAG_MASK) == (flag))

/**
 * Check for executable type.
 */
#define VRXF_IS_EXE(flag) 	(flag & VRX_FLAG_EXE)

/**
 * Check for library type.
 */
#define VRXF_IS_LIB(flag)	(flag & VRX_FLAG_LIB)

/**
 * Check for root restriction.
 */
#define VRXF_NEED_ROOT(flag)	(flag & VRX_FLAG_NEEDROOT)

/**
 * Check for library reference contstraint.
 */
#define VRXF_NEED_LIBS(flag)	(flag & VRX_FLAG_NEEDLIBS)

/**
 * Check for library fingerprint contstraint.
 */
#define VRXF_CHECK_LIBS(flag)	(flag & VRX_FLAG_CHECKLIBS)

/**
 * Check for forced inheritable.
 */
#define VRXF_IS_INHERIT(flag)	(flag & VRX_FLAG_INHERIT)

/**
 * Check for script mode.
 */
#define VRXF_IS_SCRIPT(flag)	(flag & VRX_FLAG_SCRIPT)

/**
 * Check for kernel thread restriction.
 */
#define VRXF_NEED_KTHREAD(flag)	(flag & VRX_FLAG_KTHREAD)

/**
 * Check for interpreter mode.
 */
#define VRXF_IS_INTERP(flag)	(flag & VRX_FLAG_INTERP)

/**
 * Check for allow unsafe option.
 */
#define VRXF_ALLOW_UNSAFE(flag)	(flag & VRX_FLAG_UNSAFE)


/*@}*/

/*************************************************************/
/*                        Capabilities                       */
/*************************************************************/

/** @name Veriexec Capability Sets */
/*@{*/
/** @defgroup veriexec_caps Veriexec Capability Sets */
/*@{*/

/**
 * Veriexec capability set.
 */
typedef struct veriexec_caps {
	kernel_cap_t v_cap_e;	/**< Effective mask */
	kernel_cap_t v_cap_p;	/**< Permitted mask */
	kernel_cap_t v_cap_i;	/**< Inheritable mask */
} veriexec_caps_t;

/**
 * Clear all masks in a capability set.
 */
#define vrx_cap_clear(vcap) do { \
	cap_clear(vcap.v_cap_e); \
	cap_clear(vcap.v_cap_p); \
	cap_clear(vcap.v_cap_i); \
} while (0)

/**
 * Copy a capability set.
 */
#define vrx_cap_copy(src,dest) do { \
	dest.v_cap_e = src.v_cap_e; \
	dest.v_cap_p = src.v_cap_p; \
	dest.v_cap_i = src.v_cap_i; \
} while (0)

/**
 * Intersect all masks in a capability set with a restrictive mask.
 */
#define vrx_cap_limit(vcap, lim) do { \
	kernel_cap_t _caplim; \
	_caplim = lim; \
	vcap.v_cap_e = cap_intersect(vcap.v_cap_e, _caplim); \
	vcap.v_cap_p = cap_intersect(vcap.v_cap_p, _caplim); \
	vcap.v_cap_i = cap_intersect(vcap.v_cap_i, _caplim); \
} while (0)

/**
 * Empty capability set initiator.
 */
#define VRX_CAP_EMPTY_SET {CAP_EMPTY_SET; CAP_EMPTY_SET; CAP_EMPTY_SET;}

/**
 * Conversion specifications to use in a printk format string
 * to print a kernel_cap_t.
 */
#define CAP_T_PRINT_CONV "%x:%x"

/**
 * Arguments to include in a printk argument list to display
 * a kernel_cap_t throug CAP_T_PRINT_CONV.
 */
#define CAP_T_PRINT_ARGS(_cap) (_cap).cap[0], (_cap).cap[1]

/*@}*/
/*@}*/

#endif /* _LINUX_VERIEXEC_CAPS_H */
