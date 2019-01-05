// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/**
 *  @file veriexec_vserver_hlist.c
 *  veriexec hashed lists file store, virtualized for vserver.
 *  @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Copyright (C) 2006-2008 SGDN/DCSSI
 *  Copyright (C) 2011-2014 SGDSN/ANSSI
 *  @n
 *  All rights reserved.
 *
 */

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/version.h>
#include <linux/vserver/context.h>
#include <linux/vserver/base.h>
#include <linux/vserver/check.h>

#include <linux/hash.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sched.h>

#include <linux/seq_file.h>

#include "clsm_file.h"
#include <linux/veriexec.h>

/*************************************************************/
/*                   entry list macros                       */
/*************************************************************/

/** @name Veriexec entry list macros.
 * Note that all those macros are RCU-safe. */
/**@{*/

/**
 * 1 if veriexec_entry @a node is the last element of a hlist.
 */
#define VELIST_LAST(node) \
	(!(rcu_dereference((&((node)->ve_hlist))->next)))

/**
 * Add veriexec_entry @a new as head (first significant element)
 * of hlist @a head
 */
#define VELIST_ADD_HEAD(new,head) \
	hlist_add_head_rcu(&((new)->ve_hlist), (head))

/**
 * Add veriexec_entry @a new after veriexec_entry @a prev.
 */
#define VELIST_ADD_AFTER(new,prev) \
	hlist_add_after_rcu(&((prev)->ve_hlist), &((new)->ve_hlist))

/**
 * Add veriexec_entry @a new before veriexec_entry @a next.
 */
#define VELIST_ADD_BEFORE(new,next) \
	hlist_add_before_rcu(&((new)->ve_hlist), &((next)->ve_hlist))

/**
 * Remove veriexec_entry @a node from its hlist.
 */
#define VELIST_DEL(node) \
	hlist_del_rcu(&((node)->ve_hlist))

/**
 * Delete the first significant element of hlist @a head.
 */
#define VELIST_DEL_HEAD(head) \
	hlist_del_rcu((head)->first)

/**
 * Iterate over all significant veriexec_entry elements in hlist
 * @a head. @a cur is the veriexec_entry iterator, @a h is a hlist_node
 * iterator.
 */
#define VELIST_FOREACH(cur,head) \
	hlist_for_each_entry_rcu(cur, (head), ve_hlist)

/**
 * Return the veriexec entry containing the @a h hlist_node.
 */
#define VELIST_AT(h) \
	hlist_entry(rcu_dereference(h), struct veriexec_entry, ve_hlist)

/**
 * Return the first significant veriexec_entry element in the
 * @a head hlist.
 */
#define VELIST_FIRST(head) \
	VELIST_AT((head)->first)

/**
 * Return the next veriexec_entry element in veriexec_entry @a node's hlist.
 */
#define VELIST_NEXT(node) \
	(hlist_entry(rcu_dereference((&((node)->ve_hlist))->next), \
		struct veriexec_entry, ve_hlist))

/**
 * Return the prev veriexec_entry element in veriexec_entry @a node's hlist.
 */
#define VELIST_PREV(node, type) \
	(hlist_entry(rcu_dereference((&((node)->ve_hlist))->prev), \
		struct veriexec_entry, ve_hlist))

/**@}*/


/*************************************************************/
/*                   hash table support                      */
/*************************************************************/

/** Veriexec entry hashed index. */
typedef unsigned int vrhl_hash_t;
/** Maximum hashed index for a veriexec entry. */
#define VRHL_HASH_SZ	(1<<CONFIG_VERIEXEC_HASH_BITS)

/**
 * Hash an inode number into a veriexec hashed index.
 * @param ino Inode number to hash.
 * @return Hashed index between 0 and VRHL_HASH_SZ.
 */
static inline vrhl_hash_t
vrhl_inode_hash(ino_t ino)
{
	return hash_long(ino, CONFIG_VERIEXEC_HASH_BITS);
}

/**
 * Calculate the hashed index for a veriexec entry.
 * This hashes the entry's inode number.
 * @param entry Entry to hash.
 * @return Hashed index between 0 and VRHL_HASH_SZ.
 */
static inline vrhl_hash_t
vrhl_entry_hash(struct veriexec_entry *entry)
{
	return hash_long(entry->ve_ino, CONFIG_VERIEXEC_HASH_BITS);
}


/*************************************************************/
/*                   inode/dev helpers                       */
/*************************************************************/

/** @name Linked entry list helpers */
/*@{*/



/**
 * Lookup an entry by device and inode in a linked entry hlist.
 * This is typically used to resolve a single entry in hash bucket.
 * <b>Caller must ensure proper locking, either RCU (read) or the
 * spinlock protecting writes to this list.</b>
 * @param head Head of the hlist to look in.
 * @param dev Device number to look for.
 * @param ino Inode number to look for.
 * @return Pointer to matching entry (without increasing its refcount)
 * if found, ENOENT error pointer if not found.
 */
static inline struct veriexec_entry *
vrhl_entry_lookup(struct hlist_head *head, dev_t dev, ino_t ino)
{
	struct veriexec_entry *cur;

	if (likely(hlist_empty(head)))
		return ERR_PTR(-ENOENT);

	VELIST_FOREACH(cur, head) {
		if (likely(cur->ve_ino == ino && cur->ve_dev == dev))
			return cur;
	}

	return ERR_PTR(-ENOENT);
}

/**
 * Insert an entry in a linked entry hlist.
 * This inserts the entry at the head of the list, after verifying that an
 * entry with the same device and inode is not already referenced in the list.
 * It is typically used to insert an entry in a hash bucket.
 * @n <b>Caller must lock the spinlock protecting writes to the list. </b>
 * @n <b>Caller must increment the reference count on the inserted entry on
 * success. </b>
 * @param head Head of the hlist to insert into.
 * @param new Entry to insert.
 * @return 0 on success (entry has been inserted), -EEXIST if a conflicting
 * entry is already present in the list (@a new is not inserted in that case).
 */
static int
vrhl_entry_insert(struct hlist_head *head, struct veriexec_entry *new)
{

	struct veriexec_entry *cur;

	/* clear out "insert as head" cases first */
	if (likely(hlist_empty(head)))
		goto not_found;

	VELIST_FOREACH(cur, head) {
		if (unlikely(cur->ve_ino == new->ve_ino
				&& cur->ve_dev == new->ve_dev))
			return -EEXIST;
	}
	/* Fall through */
not_found:
	VELIST_ADD_HEAD(new, head);
	return 0;
}

/**
 * Remove an entry from a linked entry hlist.
 * This looks up an entry by device and inode, and removes it from the list
 * if found. It is typically used to remove an entry from a hash bucket.
 * @n <b>Caller must lock the spinlock protecting writes to the list. </b>
 * @n <b>Caller must decrement the reference count on the removed entry on
 * success. </b>
 * @param head Head of the hlist to remove the entry from.
 * @param dev Device number of the entry to remove.
 * @param ino Inode number of the entry to remove.
 * @return Pointer to the removed entry on success, ENOENT error pointer on
 * failure (entry not found).
 */
static inline struct veriexec_entry *
vrhl_entry_delete(struct hlist_head *head, dev_t dev, ino_t ino)
{
	struct veriexec_entry *entry;

	entry = vrhl_entry_lookup(head, dev, ino);

	if (IS_ERR(entry))
		return entry;

	VELIST_DEL(entry);

	return entry;
}

/**@}*/

/*************************************************************/
/*                     ctx list item                         */
/*************************************************************/

/** Veriexec per-context entry store. */
struct vrhl_xlist {
	veriexec_ctx_t vx_ctx;		/**< context for this list */
	struct list_head vx_list;	/**< linked list of context stores */
	atomic_t vx_refcnt;		/**< reference count  */
	unsigned int vx_lvl; 		/**< veriexec level for this ctx */

	struct hlist_head vx_htable[VRHL_HASH_SZ];
	/**< entry lookup hash table */

	spinlock_t vx_lock;		/**< entry add/delete exclusive lock */
	kernel_cap_t vx_capset;		/**< cap. bounding set for this ctx */
	clsm_privs_t vx_privset;	/**< authorized CLSM privs
					  for this ctx */
	struct rcu_head vx_rcu;		/**< context delete rcu handle */
};


/*************************************************************/
/*                   global variables                        */
/*************************************************************/

/** Global spinlock protecting write accesses to the linked list
 * of contexts (struct vrhl_xlist). */
static spinlock_t g_lock;

/** Head of the linked list of contexts, also used for the default context
 * store (vserver ADMIN context). */
static struct vrhl_xlist *g_xlist;

/** Bool, set to 1 once entry store has been initialized (g_xlist is
 * allocated). */
static int vrhl_initialized = 0;

/** Context number of the UPDATE context, which is allowed to modify the
 * store of any other context that does not explicitly forbid it. */
static veriexec_ctx_t g_update_ctx = 0;


/*************************************************************/
/*                   admin privileges                        */
/*************************************************************/

/** @name Veriexec store privilege checking macros */
/*@{*/

/**
 * Current veriexec context ID, mapped to the vserver XID.
 */
#define vrhl_current_ctx() \
			vx_current_xid()

/** Veriexec ADMIN context ID, mapped to vserver's ADMIN context */
#define vrhl_admin_ctxnum	0
/** Veriexec WATCH context ID, mapped to vserver's WATCH context */
#define vrhl_watch_ctxnum	1

/**
 * 1 if current task is in ADMIN context, 0 otherwise.
 */
#define vrhl_admin_ctx() vx_check(0, VS_ADMIN)
/**
 * 1 if current task is in WATCH context, 0 otherwise.
 */
#define vrhl_watch_ctx() vx_check(0, VS_WATCH)

/**
 * 1 if UPDATE context exists and current task is in it, 0 otherwise.
 */
#define vrhl_update_ctx() (g_update_ctx != 0 && \
				vrhl_current_ctx() == g_update_ctx)

/**
 * 1 if current task has the CLSM_PRIV_VERICTL effective privilege,
 * 0 otherwise.
 */
#define vrhl_clsm_priv() \
	(((const struct clsm_task_sec *)current_cred()->security)->t_privs & \
		CLSM_PRIV_VERICTL)
/**
 * 1 if a store with level @a lvl is modifiable from the caller's context.
 */
#define vrhl_store_mutable_p(lvl) ( \
	(vrhl_admin_ctx() && !VERIEXEC_ADMIN_IMMUTABLE_P(lvl))		|| \
	(vrhl_update_ctx() && !VERIEXEC_UPDATE_IMMUTABLE_P(lvl))	|| \
	!VERIEXEC_SELF_IMMUTABLE_P(lvl))



/** @name Veriexec store privilege checks. */

/**
 * Veriexec store level get permission.
 * Access is authorized if caller is either:
 * @li in the same context as the read contex
 * @li in the ADMIN context, with CAP_CONTEXT
 * @param ctx ID of the context to read.
 * @param xlist Veriexec store for @a ctx (unused at the moment).
 * @return 0 if access is authorized, -EPERM if it is denied.
 */
static inline int
vrhl_peek_permission(veriexec_ctx_t ctx, const struct vrhl_xlist *xlist)
{
	if (!(ctx == vrhl_current_ctx() ||
	      (vrhl_admin_ctx() && capable(CAP_CONTEXT))))
		return -EPERM;

	/* NB: do *not* check for clsm_priv here, since this function
	 * is also called internally (including by callers of all execs)
	 */

	return 0;
}

	/* Entry add / del permission : allow update delegation from admin */

/**
 * Veriexec entry add / delete permission.
 * For the access to be authorized, caller must be either:
 * @li in the same context as the target context.
 * @li in the ADMIN context, with CAP_CONTEXT
 * @li in the UPDATE context, if it is defined
 * @n
 * Additionnaly, if the target context is active, access is only granted
 * if the caller holds the CLSM_PRIV_VERICTL privilege. If the target
 * context has the 'enforce_inheritable' level flag set, access is only
 * granted if the caller has CAP_FSETID in its *inheritable* mask.
 * @n <b>Caller must increment @a xlist's reference count.</b>
 * @param ctx Target ctx ID of the context to add to / remove from.
 * @param xlist Veriexec store for the target context @a ctx.
 * @return 0 if access is OK, -EPERM if it is denied.
 */
static inline int
vrhl_entry_permission(veriexec_ctx_t ctx, const struct vrhl_xlist *xlist)
{
	if (!(ctx == vrhl_current_ctx() ||
	      (vrhl_admin_ctx() && capable(CAP_CONTEXT)) ||
	      vrhl_update_ctx()))
		return -EPERM;

	if (VERIEXEC_LEVEL_ACTIVE(xlist->vx_lvl) && !vrhl_clsm_priv())
		return -EPERM;

	if (VERIEXEC_ENFORCE_INHERIT_P(xlist->vx_lvl)) {
		const struct cred *cred = current_cred();
		if (!cap_raised(cred->cap_inheritable, CAP_FSETID))
			return -EPERM;
	}

	return 0;
}

	/* Ctx add / del permission */
	/* Ctx set permission */
	/* Delegate set permission */

/**
 * Veriexec context administration permission.
 * This check is performed before allowing any of the following operations:
 * @li Context store addition / removal.
 * @li Context store capability and privilege bounding mask modification.
 * @li Definition of the UPDATE context.
 * @n
 * For the access to be granted, caller must be in the ADMIN context, and
 * hold the (effective) CAP_SYS_ADMIN and CAP_CONTEXT capabilities.
 * Additionnally, if the @b ADMIN veriexec store is active, access is only
 * granted if the caller holds the CLSM_PRIV_VERICTL privilege.
 * @return 0 if access is OK, -EPERM if it is denied.
 */
static inline int
vrhl_admin_permission(void)
{
	if (!(vrhl_admin_ctx() && capable(CAP_SYS_ADMIN)
					&& capable(CAP_CONTEXT)))
		return -EPERM;

	if (VERIEXEC_LEVEL_ACTIVE(g_xlist->vx_lvl) && !vrhl_clsm_priv())
		return -EPERM;

	return 0;
}

/**
 * Veriexec context level change permission.
 * The access is only granted if:
 * @li The caller is from the ADMIN context.
 * @li The caller holds CAP_CONTEXT if the target ctx is not ADMIN.
 * @li The caller holds CLSM_PRIV_VERICTL if the @b ADMIN context
 * store is active.
 * @return 0 if access is OK, -EPERM if it is denied.
 */
static inline int
vrhl_level_permission(veriexec_ctx_t ctx)
{
	if (!(vrhl_admin_ctx()))
		return -EPERM;

	if (ctx != vrhl_current_ctx() && !capable(CAP_CONTEXT))
		return -EPERM;

	if (VERIEXEC_LEVEL_ACTIVE(g_xlist->vx_lvl) && !vrhl_clsm_priv())
		return -EPERM;

	return 0;
}

/**@}*/

/*************************************************************/
/*                   ctx helpers                             */
/*************************************************************/

		/*********************/
		/*    List macros    */
		/*********************/

/** @name Veriexec context list macros */
/*@{*/

/** 1 if context list @a head is empty, 0 otherwise */
#define VXLIST_EMPTY_P(head) \
	list_empty(&((head)->vx_list))

/** Add veriexec context @a new after @a head, in the latter's list */
#define VXLIST_ADD_AFTER(new,head) \
	list_add_rcu(&((new)->vx_list), &((head)->vx_list))

/** Remove veriexec context @a head from its linked list */
#define VXLIST_DEL(head) \
	list_del_rcu(&((head)->vx_list))

/** Iterate with @a cur over each context in context list @a head. */
#define VXLIST_FOREACH(cur,head) \
	list_for_each_entry_rcu((cur),&((head)->vx_list),vx_list)

/** Return next context element from @a head */
#define VXLIST_NEXT(head) \
	(list_entry(rcu_dereference((&((head)->vx_list))->next), \
		struct vrhl_xlist, vx_list))

/** Return previous context element from @a head */
#define VXLIST_PREV(head) \
	(list_entry(rcu_dereference((&((head)->vx_list))->prev), \
		struct vrhl_xlist, vx_list))

		/**********************************/
		/*    Constructor / destructor    */
		/**********************************/

/** @name Context store helpers */
/*@{*/

/**
 * Allocate a new veriexec context based on an IOCTL argument.
 * This allocates (through kmalloc) a new context structure,
 * and initializes its fields with info passed as an IOCTL argument.
 * @n <b>The new context is returned with a null refcount. </b>
 * @param xarg IOCTL (context add) argument, which will provide the
 * context ID, initial level and privilege / capability bounding sets.
 * @return Allocated vrhl_xlist on success, NULL on error (out of memory).
 */
static struct vrhl_xlist *
vrhl_xlist_new(const struct veriexec_xarg *xarg)
{
	struct vrhl_xlist *xlist;
	int i;

	xlist = kmalloc(sizeof(struct vrhl_xlist), GFP_KERNEL);
	if (unlikely(!xlist))
		return NULL;

	INIT_LIST_HEAD(&xlist->vx_list);
	atomic_set(&xlist->vx_refcnt, 0);

	spin_lock_init(&xlist->vx_lock);
	for (i = 0; i < VRHL_HASH_SZ; ++i) {
		INIT_HLIST_HEAD(&(xlist->vx_htable[i]));
	}

	xlist->vx_ctx = xarg->a_ctx;
	xlist->vx_lvl = xarg->a_lvl;
	xlist->vx_capset = xarg->a_capset;
	xlist->vx_privset = xarg->a_privset;

	return xlist;
}

/**
 * Free a veriexec context.
 * This frees the context structure, and decreases the reference count
 * on every entry it links to.
 * Note: no locking is required for access to entries,
 * since we only call free when no one references the xlist
 * anymore, which means no-one can be iterating over the entry list.
 * @param xlist Struct vrhl_xlist to free. Must have a null refcount.
 */
static void
vrhl_xlist_free(struct vrhl_xlist *xlist)
{
	int i;
	struct veriexec_entry *cur;
	struct hlist_head *head;

	BUG_ON(atomic_read(&xlist->vx_refcnt));

	for (i = 0; i < VRHL_HASH_SZ; ++i) {
		head = &(xlist->vx_htable[i]);
		while (!hlist_empty(head)) {
			cur = VELIST_FIRST(head);
			VELIST_DEL(cur);
			veriexec_entry_put(cur);
		}
	}

	kfree(xlist);
	if (xlist == g_xlist)
		g_xlist = NULL;
}

		/****************************/
		/*    Reference counting    */
		/****************************/

/**
 * Increment the reference count on veriexec context.
 * @param xlist Context structure to increment.
 */
static inline void
vrhl_xlist_get(struct vrhl_xlist *xlist)
{
	BUG_ON(!xlist);
	atomic_inc(&xlist->vx_refcnt);
}

/**
 * Context store cleanup rcu callback.
 * This is called after a grace period once a context's refcount has
 * reached 0. It re-tests the context's reference count,
 * and frees it if it still 0.
 * @param head RCU handle of the deleted veriexec_entry.
 */
static void
_vrhl_xlist_delete_rcu(struct rcu_head *head)
{
	struct vrhl_xlist *xlist =
		container_of(head, struct vrhl_xlist, vx_rcu);

	if (likely(!atomic_read(&xlist->vx_refcnt)))
		vrhl_xlist_free(xlist);
}

/**
 * Decrement the reference count on a veriexec context, free it if
 * the refcount reaches zero.
 * @n <b>Caller must ensure proper rcu grace periods before putting the
 * entry. </b>
 * @param xlist Context structure to decrement.
 */
static inline void
vrhl_xlist_put(struct vrhl_xlist *xlist)
{
	if (likely(!atomic_dec_and_test(&xlist->vx_refcnt)))
		return;

	call_rcu(&xlist->vx_rcu, _vrhl_xlist_delete_rcu);
}

		/****************************/
		/*    General cleanup       */
		/****************************/

/**
 * Free all contexts.
 * This unlinks and decrements the reference count of all veriexec contexts,
 * including the default context, resulting in their eventual freeing
 * after a grace period.
 * @n <b>Locks and unlocks the global @a g_lock spinlock. </b>
 */
static void
vrhl_xlist_free_all(void)
{
	struct vrhl_xlist *xlist;

	BUG_ON(!g_xlist);

	spin_lock(&g_lock);
	VXLIST_FOREACH(xlist, g_xlist) {
		VXLIST_DEL(xlist);
		vrhl_xlist_put(xlist);
	}

	vrhl_xlist_put(g_xlist);
	spin_unlock(&g_lock);
}


		/**********************************/
		/*    ctx chained list helpers    */
		/**********************************/

/**
 * Lookup a context store in the global context list.
 * <b> Locks and unlocks RCU. </b>.
 * @n <b> Caller must take care of put()ing the context after use. </b>
 * @param ctx Context to lookup.
 * @return Pointer to context store (with incremented reference count)
 * if found, error pointer (ENOENT) if not found.
 */
static inline struct vrhl_xlist *
vrhl_xlist_lookup(veriexec_ctx_t ctx)
{
	struct vrhl_xlist *xlist;


	rcu_read_lock();
	if (ctx == 0) {
		vrhl_xlist_get(g_xlist);
		rcu_read_unlock();
		return g_xlist;
	}
	VXLIST_FOREACH(xlist, g_xlist) {
		if (xlist->vx_ctx == ctx)
			goto ctx_found;
	}
	rcu_read_unlock();
	return ERR_PTR(-ENOENT);

ctx_found:
	vrhl_xlist_get(xlist);
	rcu_read_unlock();
	return xlist;
}

/**
 * Add a new context store to the linked list of context stores.
 * <b> Locks and unlocks the @a g_lock spinlock. </b>
 * @n <b> Caller must take care of incrementing the reference count
 * of the @a new context store. </b> Note that it is better to increment
 * the refcount before adding, then decrement it in case of failure,
 * since this prevents any race condition once the store is linked,
 * and actually frees the store if the addition failed.
 * @param new Context store to add.
 * @return 0 if addition was successful, -EEXIST if it failed
 * because a context store with the same context ID is already
 * referenced in the linked list.
 */
static inline int
vrhl_xlist_add(struct vrhl_xlist *new)
{
	struct vrhl_xlist *xlist;
	int ret = -EEXIST;

	if (new->vx_ctx == 0)
		return -EEXIST;

	spin_lock(&g_lock);
	VXLIST_FOREACH(xlist, g_xlist) {
		if (xlist->vx_ctx == new->vx_ctx) {
			ret = -EEXIST;
			goto out_unlock;
		}
	}
	VXLIST_ADD_AFTER(new, g_xlist);
	ret = 0;

	/* Fall through */
out_unlock:
	spin_unlock(&g_lock);
	return ret;
}

/**
 * Remove a context store from the linked list of context stores.
 * <b> Locks and unlocks the @a g_lock spinlock. </b>
 * @n <b> Decrements (in case of success) the deleted context's reference
 * count after a grace period once the store has been unlinked. </b> This
 * should result in the eventual freeing of the context store.
 * @param ctx Context ID of the store to delete.
 * @return 0 on success, negative error count on failure (context is invalid
 * or is not linked).
 */
static inline int
vrhl_xlist_del(veriexec_ctx_t ctx)
{
	struct vrhl_xlist *xlist;

	if (!ctx)
		return -EINVAL;

	spin_lock(&g_lock);
	VXLIST_FOREACH(xlist, g_xlist) {
		if (xlist->vx_ctx == ctx)
			goto found;
	}
	spin_unlock(&g_lock);
	return -ENOENT;

found:
	VXLIST_DEL(xlist);
	spin_unlock(&g_lock);

	vrhl_xlist_put(xlist);
	return 0;
}

/*@}*/

/** Lookup the context store for the current task's context.
 * Returns a pointer to the context store (with incremented reference
 * count) if such a context exists, and an error pointer otherwise.
 */
#define vrhl_current_xlist() \
		vrhl_xlist_lookup(vrhl_current_ctx())



		/*******************************************/
		/*    Nested entry chained list helpers    */
		/*******************************************/

/** @name Entry lookup table helpers */
/*@{*/

/**
 * Lookup an entry by its file id in one context store.
 * <b>Locks and unlocks RCU. </b>
 * @param xlist Context store to look in.
 * @param fid File ID to look for.
 * @return Pointer to an entry (with an increased reference count)
 * matching @a fid in @a xlist's lookup table,
 * if such an entry exist, error pointer if no entry was found.
 */
static inline struct veriexec_entry *
vrhl_xlist_lookup_entry(struct vrhl_xlist *xlist,
				const struct clsm_fileid *fid)
{
	struct veriexec_entry *entry;
	vrhl_hash_t hash = vrhl_inode_hash(fid->f_inode);

	rcu_read_lock();
	entry = vrhl_entry_lookup(&(xlist->vx_htable[hash]),
					fid->f_dev, fid->f_inode);

	if (!IS_ERR(entry))
		veriexec_entry_get(entry);

	rcu_read_unlock();
	return entry;
}

/**
 * Add an entry to one context store.
 * <b>Locks and unlocks the context's spinlock.</b>
 * @n <b> Caller must increment the entry's reference count on success. </b>
 * @param xlist Context store to add in.
 * @param entry Entry to add.
 * @return 0 on success (entry was added),
 * negative error code on failure (e.g. an entry with
 * the same device and inode numbers already exists in the store).
 */
static inline int
vrhl_xlist_add_entry(struct vrhl_xlist *xlist, struct veriexec_entry *entry)
{
	int ret;
	vrhl_hash_t hash = vrhl_entry_hash(entry);

	spin_lock(&xlist->vx_lock);
	ret = vrhl_entry_insert(&(xlist->vx_htable[hash]), entry);
	spin_unlock(&xlist->vx_lock);
	return ret;
}

/**
 * Remove an entry from one context store.
 * <b>Locks and unlocks the context's spinlock.</b>
 * @n <b> Decrements (on success) the deleted entry's reference count, after
 * a grace period, which should eventually result in its freeing. </b>
 * @param xlist Context store to delete from.
 * @param fid File ID of the entry to delete.
 * @return 0 on success (entry was deleted), negative error code on failure
 * (e.g. no matching entry was found in the context store).
 */
static inline int
vrhl_xlist_del_entry(struct vrhl_xlist *xlist, const struct clsm_fileid *fid)
{
	struct veriexec_entry *deleted;
	vrhl_hash_t hash = vrhl_inode_hash(fid->f_inode);

	spin_lock(&xlist->vx_lock);
	deleted = vrhl_entry_delete(&(xlist->vx_htable[hash]),
					fid->f_dev, fid->f_inode);
	spin_unlock(&xlist->vx_lock);
	if (IS_ERR(deleted))
		return PTR_ERR(deleted);

	veriexec_entry_put(deleted);
	return 0;
}

/*@}*/

/*************************************************************/
/*                      main interface                       */
/*************************************************************/

		/****************/
		/*    Lookup    */
		/****************/

/** @name Main interface.
 * This is the only non-static interface.
 */
/**@{*/

/**
 * Lookup an entry by file, in the caller's context.
 * @param filp File to lookup an entry for.
 * @return Pointer to a matching entry (with increased reference
 * count) if found, error pointer if not found.
 */
struct veriexec_entry *
veriexec_lookup_f(const struct file *filp)
{
	struct clsm_fileid fid;
	struct vrhl_xlist *xlist;
	struct veriexec_entry *entry;
	int ret;

	ret = clsm_file2fid(filp, &fid, 0);
	if (unlikely(ret))
		return ERR_PTR(ret);

	xlist = vrhl_current_xlist();
	if (IS_ERR(xlist))
		return ERR_PTR(PTR_ERR(xlist));

	entry = vrhl_xlist_lookup_entry(xlist, &fid);

	vrhl_xlist_put(xlist);

	return entry;
}

/**
 * Lookup an entry by dentry, in the caller's context.
 * @param dentry Dentry to lookup an entry for.
 * @return Pointer to a matching entry (with increased reference
 * count) if found, error pointer if not found.
 */
struct veriexec_entry *
veriexec_lookup_d(const struct dentry *dentry)
{
	struct vrhl_xlist *xlist;
	struct veriexec_entry *entry;
	struct clsm_fileid fid = {
		.f_inode = dentry->d_inode->i_ino,
		.f_dev = dentry->d_sb->s_dev,
	};

	xlist = vrhl_current_xlist();
	if (IS_ERR(xlist))
		return ERR_PTR(PTR_ERR(xlist));

	entry = vrhl_xlist_lookup_entry(xlist, &fid);

	vrhl_xlist_put(xlist);

	return entry;
}

		/***************/
		/*     Add     */
		/***************/

/**
 * Create an entry and add it to the store, based on an ioctl argument.
 * This checks the caller's permission to add an entry to the target context
 * using vrhl_entry_permission(). Write access to the target file's vfsmount
 * is also checked if the target context's level warrants it.
 * @n The target context (and thus the context store the entry is added to is
 * determined by @a arg's @a a_ctx field, or by the caller's context if that
 * field is -1.
 * @param arg IOCTL add argument. Must be in kernel memory, but with pointer
 * fields pointing to user memory.
 * @return 0 on success (an entry was added), negative error code on failure.
 * @see vrhl_entry_permission().
 */
int
veriexec_add(const struct veriexec_arg *arg)
{
	struct veriexec_entry *entry;
	struct vrhl_xlist *xlist;
	struct clsm_fileid fid;
	int ret, checkwrite;
	veriexec_ctx_t ctx;

	ctx = arg->a_ctx;
	if (ctx == -1)
		ctx = vrhl_current_ctx();

	xlist = vrhl_current_xlist();
	if (unlikely(IS_ERR(xlist)))
		return PTR_ERR(xlist);

	if (vrhl_entry_permission(ctx, xlist)) {
		vrhl_xlist_put(xlist);
		VERIEXEC_WARN("Illegal entry add attempt\n");
		return -EPERM;
	}

	if (ctx != vrhl_current_ctx()) {
		vrhl_xlist_put(xlist);
		xlist = vrhl_xlist_lookup(ctx);
		if (IS_ERR(xlist))
			return PTR_ERR(xlist);
	}

	if (unlikely(!vrhl_store_mutable_p(xlist->vx_lvl))) {
		VERIEXEC_WARN("Attempt to modify immutable ctx\n");
		ret = -EPERM;
		goto out_put;
	}

	checkwrite = VERIEXEC_ENFORCE_MNTRO_P(xlist->vx_lvl);
	ret = veriexec_arg2fid(arg, &fid, checkwrite);
	if (ret)
		goto out_put;

	entry = veriexec_entry_create(arg, &fid);
	if (unlikely(IS_ERR(entry))) {
		ret = PTR_ERR(entry);
		goto out_put;
	}
	vrx_cap_limit(entry->ve_caps, xlist->vx_capset);
	entry->ve_privs &= xlist->vx_privset;
	veriexec_entry_get(entry);

	ret = vrhl_xlist_add_entry(xlist, entry);
	if (unlikely(ret))
		veriexec_entry_free(entry);
out_put:
	vrhl_xlist_put(xlist);
	return ret;
}

		/******************/
		/*     Delete     */
		/******************/

/**
 * Delete an entry from a context store based on an IOCTL argument.
 * This checks the caller's permission to delete an entry from the target
 * context using vrhl_entry_permission().
 * Write access to the target file's vfsmount is also checked if the target
 * context's level warrants it.
 * @n The target context (and thus the context store the entry is added to is
 * determined by @a arg's @a a_ctx field, or by the caller's context if that
 * field is -1.
 * @n In case of success, the deleted entry has its reference count decremented
 * after a grace period, which should result in its eventual freeing.
 * @param arg IOCTL add argument. Must be in kernel memory, but with pointer
 * fields pointing to user memory.
 * @return 0 on success (an entry was deleted), negative error code on failure.
 * @see vrhl_entry_permission().
 */
int
veriexec_del(const struct veriexec_arg *arg)
{
	struct clsm_fileid fid;
	struct vrhl_xlist *xlist;
	int ret, checkwrite;
	veriexec_ctx_t ctx;

	ctx = arg->a_ctx;
	if (ctx == -1)
		ctx = vrhl_current_ctx();

	xlist = vrhl_current_xlist();
	if (unlikely(IS_ERR(xlist)))
		return PTR_ERR(xlist);

	if (vrhl_entry_permission(ctx, xlist)) {
		vrhl_xlist_put(xlist);
		VERIEXEC_WARN("Illegal entry delete attempt\n");
		return -EPERM;
	}

	if (ctx != vrhl_current_ctx()) {
		vrhl_xlist_put(xlist);
		xlist = vrhl_xlist_lookup(ctx);
		if (IS_ERR(xlist))
			return PTR_ERR(xlist);
	}

	if (unlikely(!vrhl_store_mutable_p(xlist->vx_lvl))) {
		VERIEXEC_WARN("Attempt to modify immutable ctx\n");
		ret = -EPERM;
		goto out_put;
	}

	checkwrite = VERIEXEC_ENFORCE_MNTRO_P(xlist->vx_lvl);
	ret = veriexec_arg2fid(arg, &fid, checkwrite);
	if (ret)
		goto out_put;

	ret = vrhl_xlist_del_entry(xlist, &fid);

	/* Fall through */
out_put:
	vrhl_xlist_put(xlist);
	return ret;
}

		/*************************/
		/*    Level set / get    */
		/*************************/

/**
 * Get a veriexec context's level.
 * Reads the level for the context specified in @a level's @a a_ctx
 * field, or the caller's context if that field is -1.
 * @n Checks the caller's privileges through vrhl_peek_permission().
 * @param level IOCTL argument, for output and input both.
 * Provides the context ID to lookup as input, and stores the
 * read level as output.
 * @return 0 on success, negative error code on failure.
 * @see vrhl_peek_permission().
 */
int
veriexec_getlvl(struct veriexec_larg *level)
{
	struct vrhl_xlist *xlist;

	veriexec_ctx_t ctx = level->a_ctx;

	if (ctx == -1)
		ctx = vrhl_current_ctx();

	xlist = vrhl_xlist_lookup(ctx);
	if (unlikely(IS_ERR(xlist)))
		return PTR_ERR(xlist);

	if (vrhl_peek_permission(ctx, xlist)) {
		vrhl_xlist_put(xlist);
		return -EPERM;
	}

	level->a_lvl = xlist->vx_lvl;
	vrhl_xlist_put(xlist);
	return 0;
}

/**
 * Set a veriexec context's level.
 * Sets the level for the context specified in @a level's @a a_ctx
 * field, or the caller's context if that field is -1.
 * @n Checks the caller's privileges through vrhl_level_permission().
 * @n Note that if the target context is LEVEL_IMMUTABLE, the new
 * level will be OR-ed with the old one, rather than replace it.
 * @param level IOCTL argument that provides both the context ID and
 * the new level.
 * @return 0 on success, negative error code on failure.
 */
int
veriexec_setlvl(const struct veriexec_larg *level)
{
	struct vrhl_xlist *xlist;

	veriexec_ctx_t ctx = level->a_ctx;
	int lvl = level->a_lvl;

	if (ctx == -1)
		ctx = vrhl_current_ctx();

	if (vrhl_level_permission(ctx)) {
		VERIEXEC_WARN("Illegal level set attempt\n");
		return -EPERM;
	}

	if (!VERIEXEC_LEVEL_VALID(lvl))
		return -EINVAL;

	xlist = vrhl_xlist_lookup(ctx);
	if (unlikely(IS_ERR(xlist)))
		return PTR_ERR(xlist);

	if (VERIEXEC_LEVEL_IMMUTABLE_P(xlist->vx_lvl)) {
		xlist->vx_lvl |= lvl;
	} else {
		xlist->vx_lvl = lvl;
	}

	vrhl_xlist_put(xlist);
	return 0;
}

		/***************************/
		/*    Device open/close    */
		/***************************/

/**
 * Register an opening of the veriexec device.
 * This checks the caller's privileges, requiring CLSM_PRIV_VERICTL
 * to access the device from a context where veriexec is active.
 * @return 0 on success, negative error code on failure (permission denied
 * or no veriexec context defined in the current vserver context).
 */
int
veriexec_register_open(void)
{
	struct vrhl_xlist *xlist;
	int ret = 0;

	xlist = vrhl_current_xlist();
	if (IS_ERR(xlist))
		return PTR_ERR(xlist);

	if (VERIEXEC_LEVEL_ACTIVE(xlist->vx_lvl)) {
		struct clsm_task_sec *tsec = current_cred()->security;
		if (!(tsec->t_privs & CLSM_PRIV_VERICTL))
			ret = -EPERM;
	}

	vrhl_xlist_put(xlist);
	return ret;
}

/**
 * Register a closing of the veriexec device.
 * This is only a trivial placeholder.
 * @return 0. Should return negative error code on error, if an error was
 * possible.
 */
int
veriexec_register_close(void)
{
	return 0;
}

		/****************************/
		/*    ctx add/delete/set    */
		/****************************/

/**
 * Add a veriexec context store.
 * This performs the following checks:
 * @li Check that the caller has enough privileges to perform the call,
 * through vrhl_admin_permission().
 * @li Check that the main (0) context is not CONTEXT_IMMUTABLE
 * @li Check that the new context's privileges are a subset of those of the
 * main context.
 * @param xarg IOCTL argument (in kernel memory) defining the new context.
 * @return 0 on success, negative error code on failure (context already
 * exists, insufficient privileges, etc...)
 */
int
veriexec_add_ctx(const struct veriexec_xarg *xarg)
{
	struct vrhl_xlist *xlist;
	int ret;

	if (vrhl_admin_permission()) {
		VERIEXEC_WARN("illegal attempt to add ctx %u\n", xarg->a_ctx);
		return -EPERM;
	}

	if (xarg->a_ctx == 0)
		return -EEXIST;

	if (VERIEXEC_CONTEXT_IMMUTABLE_P(g_xlist->vx_lvl))
		return -EPERM;

	if (!cap_issubset(xarg->a_capset, g_xlist->vx_capset)) {
		VERIEXEC_DEBUG("capset for ctx %u is not a subset of "
				"main capset\n", xarg->a_ctx);
		return -EPERM;
	}
	if (xarg->a_privset & ~g_xlist->vx_privset) {
		VERIEXEC_DEBUG("privset for ctx %u is not a subset of "
				"main privset\n", xarg->a_ctx);
		return -EPERM;
	}
	VERIEXEC_DEBUG("adding ctx %u, with caps %u/%u, privs %lu\n", xarg->a_ctx,
			xarg->a_capset.cap[0], xarg->a_capset.cap[1], xarg->a_privset);

	xlist = vrhl_xlist_new(xarg);
	if (unlikely(!xlist))
		return -ENOMEM;

	vrhl_xlist_get(xlist);

	/* Critical section in that call */
	ret = vrhl_xlist_add(xlist);
	if (ret)
		vrhl_xlist_put(xlist);

	return ret;
}

/**
 * Change the capability and privilege bounding sets for a given context store.
 * This call can only reduce the bounding sets, since the new ones are
 * systematically intersected with the old ones.
 * @n Checks the caller's privileges through vrhl_admin_permission(), then checks
 * that the target context is not locked (CTXSET_IMMUTABLE level).
 * @param xarg IOCTL argument (in kernel memory) defining the new bounding sets.
 * The a_ctx field in @a xarg defines the context store to be modified, which
 * must already exist.
 * @return 0 on success, negative error code on failure.
 */
int
veriexec_set_ctx(const struct veriexec_xarg *xarg)
{
	struct vrhl_xlist *xlist;
	int ret = -EPERM;

	if (vrhl_admin_permission()) {
		VERIEXEC_WARN("illegal attempt to change parameters"
				" for context %u\n", xarg->a_ctx);
		return -EPERM;
	}

	xlist = vrhl_xlist_lookup(xarg->a_ctx);
	if (unlikely(IS_ERR(xlist)))
		return PTR_ERR(xlist);

	if (VERIEXEC_CTXSET_IMMUTABLE_P(xlist->vx_lvl)) {
		VERIEXEC_WARN("illegal attempt to modify ctx %u\n",
				vrhl_current_ctx());
		goto out_put;
	}
	xlist->vx_capset = cap_intersect(xlist->vx_capset, xarg->a_capset);
	xlist->vx_privset &= xarg->a_privset;
	ret = 0;

	/* Fall through */
out_put:
	vrhl_xlist_put(xlist);
	return ret;
}

/**
 * Delete a context store.
 * This first checks that the caller has sufficient privileges (through
 * vrhl_admin_permission(), and that the main (0) context is not
 * CONTEXT_IMMUTABLE.
 * @param xarg IOCTL argument (in kernel memory) defining the context to
 * delete. Only the a_ctx field is significant.
 * @return 0 on succes (context was deleted), negative error code on failure
 * (context does not exist, insufficient privileges, etc...).
 */
int
veriexec_del_ctx(const struct veriexec_xarg *xarg)
{
	if (vrhl_admin_permission()) {
		VERIEXEC_WARN("illegal attempt to add ctx %u\n", xarg->a_ctx);
		return -EPERM;
	}

	if (xarg->a_ctx == 0)
		return -EINVAL;

	if (VERIEXEC_CONTEXT_IMMUTABLE_P(g_xlist->vx_lvl))
		return -EPERM;

	VERIEXEC_DEBUG("deleting ctx %u\n", xarg->a_ctx);

	/* Critical section in that call */
	return vrhl_xlist_del(xarg->a_ctx);
}

/**
 * Set the UPDATE context.
 * The UPDATE context is the only non-ADMIN (!= 0) context that is allowed
 * to add or delete entries in all the contexts.
 * @n This call is one-shot : the UPDATE context is not set at boot, and cannot
 * be set to another context once it has been set. The call also checks the caller's
 * privileges through vrhl_admin_permission(). Note that the UPDATE context ID does not
 * necessarily correspond to an existing veriexec context when it is set.
 * @param ctx Context ID to set as UPDATE context.
 * @return 0 on success, negative error code on failure.
 */
int
veriexec_set_update(veriexec_ctx_t ctx)
{
	if (!ctx)
		return -EINVAL;

	if (g_update_ctx || vrhl_admin_permission())
		return -EPERM;

	g_update_ctx = ctx;
	return 0;
}

/*@}*/

/*************************************************************/
/*                      proc interface                       */
/*************************************************************/

/** @name Proc interface */
/*@{*/

		/*    seq_print helpers    */

/**
 * Print a context store header.
 * Prints the context store's fields, i.e. capability and privilege bounding
 * sets, and security level.
 * @n <b> Caller must take care of incrementing and decrementing @a xlist's reference
 * count. </b>
 * @param s Current seq_file.
 * @param xlist Context store to print a header for.
 */
static inline void
vrhl_xlist_seqprint(struct seq_file *s, const struct vrhl_xlist *xlist)
{
	char privs[16];
	unsigned __capi;
	clsm_format_bitmask(privs, sizeof(privs),
				xlist->vx_privset, clsm_priv_map);

	(void) seq_printf(s,
			"## veriexec store for context %u ##\n",
			xlist->vx_ctx);
	(void) seq_printf(s, "## level: %d, caps: ", xlist->vx_lvl);
        CAP_FOR_EACH_U32(__capi) {
                seq_printf(s, "%08x",
                           xlist->vx_capset.cap[(_KERNEL_CAPABILITY_U32S-1) - __capi]);
        }
	(void) seq_printf(s, ", privs: %s ##\n", privs);
}
		/****************************************/
		/* non-WATCH context seq_file interface */
		/****************************************/

/**
 * Veriexec entry hash-list iterator for the current context.
 * Returns first non-null hash list in a context store's lookup table,
 * starting from offset @a pos in that table, then advances @a pos
 * to the next offset in the hash table. The context store pointer is
 * passed as the seq_file's private field. It's reference count must
 * have been incremented by the caller.
 * @n <b>Caller must hold a RCU read lock. </b>
 * @param s Current seq_file.
 * @param pos Starting offset in the hashed lookup table. Gets incremented
 * to the next offset after the returned entry.
 * @return Pointer to next entry (with incremented reference count) in the lookup
 * table if found, NULL if @a pos
 * is bigger than the table size or if no more entries can be found in it (in
 * which case @a pos is made equal to the table size.
 */
static inline struct veriexec_entry *
vrhl_atpos(struct seq_file *s, loff_t *pos)
{
	size_t off;
	struct veriexec_entry *entry;

	struct vrhl_xlist *xlist = s->private;

	if (*pos >= VRHL_HASH_SZ)
		return NULL;

	/* Now we know that *pos is small enough for a size_t... */
	for (off = *pos; off < VRHL_HASH_SZ; ++off) {
		if (!hlist_empty(&(xlist->vx_htable[off]))) {
			*pos = off + 1;
			entry = VELIST_FIRST(&(xlist->vx_htable[off]));
			veriexec_entry_get(entry);
			return entry;
		}
	}
	*pos = VRHL_HASH_SZ;
	return NULL;
}

/**
 * Start a seq_print sequence for the current context.
 * This stores a pointer the caller's veriexec context in
 * the current seq_file, and increments the refcount on that context.
 * It also prints the store's header by returning SEQ_START_TOKEN
 * to seq_show() when starting at offset 0.
 * @n <b>Includes a RCU critical section. </b>.
 * @param s Seq_file to print through.
 * @param pos Initial offset in the current hash table.
 * @return Pointer to first entry to display, or SEQ_START_TOKEN
 * to display the store's header, or NULL if iteration is over,
 * error pointer on failure (no veriexec context for the current
 * context).
 */
static inline void *
vrhl_ctx_seq_start(struct seq_file *s, loff_t *pos)
{
	struct vrhl_xlist *xlist;
	struct veriexec_entry *entry;

	s->private = NULL;

	/* Start is called a second time right after
	 * stop. In that case, there is no point locking the store :
	 * let's return NULL straight away. */
	if (*pos >= VRHL_HASH_SZ)
		return NULL;

	xlist = vrhl_current_xlist();
	if (IS_ERR(xlist))
		return xlist;

	/* Store xlist, with increased refcnt, in seq_file private data */
	s->private = xlist;

	/* Return SEQ_START_TOKEN when *pos == 0 to let seq_show
	 * display the current xlist's info */
	if (*pos == 0)
		return SEQ_START_TOKEN;

	rcu_read_lock();
	entry = vrhl_atpos(s, pos);
	rcu_read_unlock();
	return entry;
}

/**
 * Return the next entry to display from the current context.
 * This first tries a fast path (return next entry in the same
 * hash bucket as the current one), then uses a slow path (return
 * the entry at the next position, by iterating over all previous
 * hash buckets) if that fails. A special case is kept for SEQ_START_TOKEN,
 * where there is no current entry. The current entry, if it exists, always
 * gets its reference count decreased, while the next one, if found, is
 * returned with an incremented reference count.
 * @n <b>Includes a RCU critical section.</b>
 * @param s Current seq_file.
 * @param v Current entry.
 * @param pos Current position (gets incremented in the slow path, but not
 * on the fast path).
 * @return Pointer to the next entry (with incremented refcount) if found,
 * NULL otherwise (end of iteration).
 */
static inline void *
vrhl_ctx_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct veriexec_entry *entry, *next;

	rcu_read_lock();
	/* entry is not valid on first call */
	if (unlikely(v == SEQ_START_TOKEN)) {
		next = vrhl_atpos(s, pos);
		goto got_next;
	}

	entry = v;

	/* We've iterated over this whole hash bucket.
	 * Move on to next non-empty hash bucket. */
	if (VELIST_LAST(entry)) {
		next = vrhl_atpos(s, pos);
	} else {
		/* Else, return next entry in hash bucket, leave pos as is */
		next = VELIST_NEXT(entry);
		veriexec_entry_get(next);
	}
	veriexec_entry_put(entry);
	/* Fall through */
got_next:
	rcu_read_unlock();
	return next;
}

/**
 * Terminate a seq_file iteration in the current context.
 * This decrements the context store reference count that was
 * incremented by vrhl_ctx_seq_start().
 * @param s Current seq_file.
 * @param v Current entry (unused). Note that this does not have
 * to be put (and may not even be valid) since the putting is done
 * by the last seq_next() call (which then returns NULL).
 */
static inline void
vrhl_ctx_seq_stop(struct seq_file *s, void *v)
{

	struct vrhl_xlist *xlist = s->private;

	/* xlist was retained by seq_start, release it */
	if (xlist) {
		s->private = NULL;
		vrhl_xlist_put(xlist);
	}
}

		/********************************/
		/* WATCH ctx seq_file interface */
		/********************************/

/**
 * Veriexec entry hash-list iterator for the watch context.
 * This is adapted to display all contexts successively, by
 * first resolving the context store at offset @a pos / VRHL_HASH_SZ in
 * the context linked list, then calling basic vrhl_atpos() on
 * that context store at offset @a pos % VRHL_HASH_SZ. The current
 * xlist has its reference count incremented, and is stored in
 * the seq_file's private field. When switching from one xlist to
 * the next, the old xlist gets its reference count decremented (and
 * SEQ_START_TOKEN is returned to print the new context header first).
 * @n <b>Caller must hold a RCU read lock. </b>
 * @n <b>Caller must make sure that s->private points to a valid xlist,
 * with an increased reference count.</b>
 * @param s Current seq_file.
 * @param pos Starting offset in the hashed lookup table. Gets incremented
 * to the next offset after the returned entry.
 * @return Pointer to next entry (with incremented reference count) in the lookup
 * table if found, NULL if @a pos
 * is bigger than the table size or if no more entries can be found in it (in
 * which case @a pos is made equal to the table size.
 * @see vrhl_atpos()
 */
static struct veriexec_entry *
vrhl_watch_atpos(struct seq_file *s, loff_t *pos)
{
	struct veriexec_entry *entry = NULL;
	struct vrhl_xlist *xlist = g_xlist;
	loff_t rpos = *pos;

	while (rpos >= VRHL_HASH_SZ) {
		xlist = VXLIST_NEXT(xlist);
		if (xlist == g_xlist) {
			/* We do the putting here ourselves */
			vrhl_xlist_put(s->private);
			s->private = ERR_PTR(-ERANGE);
			return NULL;
		}
		rpos -= VRHL_HASH_SZ;
	}

	/* New context, not displayed yet */
	if (xlist != s->private) {
		vrhl_xlist_put(s->private);
		vrhl_xlist_get(xlist);
		s->private = xlist;
		return SEQ_START_TOKEN;
	}

	entry = vrhl_atpos(s, &rpos);
	*pos += rpos - (*pos % VRHL_HASH_SZ) + 1;
	/* No more entries in this context, move on to
	 * next one */
	if (!entry)
		entry = vrhl_watch_atpos(s, pos);

	return entry;
}

/**
 * Start a seq_print sequence for the watch context.
 * This stores a pointer the main context (g_xlist) in
 * the current seq_file, and increments the refcount on that context.
 * Note that the actual starting context will be decided by the
 * vrhl_watch_atpos() call.
 * The main store's header is printed by returning SEQ_START_TOKEN
 * to seq_show() when starting at offset 0. Otherwise, the context store
 * header will be printed by vrhl_watch_atpos() returning SEQ_START_TOKEN.
 * @n <b>Includes a RCU critical section. </b>.
 * @param s Seq_file to print through.
 * @param pos Initial offset in the current hash table.
 * @return Pointer to first entry to display, or SEQ_START_TOKEN
 * to display the store's header, or NULL if iteration is over,
 * error pointer on failure (no veriexec context for the matched
 * context).
 */
static inline void *
vrhl_watch_seq_start(struct seq_file *s, loff_t *pos)
{
	struct veriexec_entry *entry;

		/* Last run */
	/* We are called again after a stop.
	 * watch_atpos looped through all xlists, and left
	 * ERR_PTR(-ERANGE) here to indicate it : there is
	 * nothing more to display */
	if (IS_ERR(s->private)) {
		s->private = NULL;
		return NULL;
	}

		/* First run */
	if (!s->private) {
		s->private = g_xlist;
		vrhl_xlist_get(g_xlist);
	}
	if (*pos == 0)
		return SEQ_START_TOKEN;

		/* All runs */
	rcu_read_lock();
	entry = vrhl_watch_atpos(s, pos);
	rcu_read_unlock();
	return entry;
}

/**
 * Return the next entry to display from the watch context.
 * This first tries a fast path (return next entry in the same
 * hash bucket as the current one), then tries a slower path (return
 * the entry at the next position in the same context, by iterating
 * over all previous hash buckets) if that fails, then uses an even slower
 * path (return the entry at the next position, switching context if that
 * position is over the context boundary).A special case is kept for SEQ_START_TOKEN,
 * where there is no current entry. The current entry, if it exists, always
 * gets its reference count decreased, while the next one, if found, is
 * returned with an incremented reference count.
 * @n <b>Includes a RCU critical section.</b>
 * @param s Current seq_file.
 * @param v Current entry or SEQ_START_TOKEN.
 * @param pos Current position (gets incremented in the slow path, but not
 * on the fast path).
 * @return Pointer to the next entry (with incremented refcount) if found,
 * NULL otherwise (end of iteration).
 */
static inline void *
vrhl_watch_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct veriexec_entry *entry, *next;

	rcu_read_lock();
	/* entry is not valid on first call */
	if (unlikely(v == SEQ_START_TOKEN)) {
		next = vrhl_watch_atpos(s, pos);
		goto got_next;
	}

	entry = v;

	/* We've iterated over this whole hash bucket.
	 * Move on to next non-empty hash bucket. */
	if (VELIST_LAST(entry)) {
		next = vrhl_atpos(s, pos);
		/* We're at the end of this xlist, move to next */
		if (!next)
			next = vrhl_watch_atpos(s, pos);
	} else {
		/* Else, return next entry in hash bucket, and leave pos as is */
		next = VELIST_NEXT(entry);
		veriexec_entry_get(next);
	}
	veriexec_entry_put(entry);
	/* Fall through */
got_next:
	rcu_read_unlock();
	return next;
}

/**
 * Terminate a seq_file iteration in the watch context.
 * This decrements the context store reference count that was
 * incremented by vrhl_watch_seq_start().
 * @param s Current seq_file.
 * @param v Current entry (unused). Note that this does not have
 * to be put (and may not even be valid) since the putting is done
 * by the last seq_next() call (which then returns NULL).
 */
static inline void
vrhl_watch_seq_stop(struct seq_file *s, void *v)
{

	struct vrhl_xlist *xlist = s->private;

	/* xlist was retained by seq_start, release it */
	if (xlist) {
		s->private = NULL;
		vrhl_xlist_put(xlist);
	}
}

		/************************************/
		/*    Actual seq_print interface    */
		/************************************/

/**
 * Start a seq_file display.
 * Runs either the current context-limited function
 * (when called from any context but WATCH), or the all-context
 * function (when called from WATCH context).
 * @param s Seq_file to print through.
 * @param pos Initial offset in the current hash table.
 * @return Pointer to first entry to display, or SEQ_START_TOKEN
 * to display the store's header, or NULL if iteration is over,
 * error pointer on failure (no veriexec context for the matched
 * context).
 */
static void *
vrhl_seq_start(struct seq_file *s, loff_t *pos)
{
	if (unlikely(vrhl_watch_ctx()))
		return vrhl_watch_seq_start(s, pos);
	else
		return vrhl_ctx_seq_start(s, pos);
}

/**
 * Return the next entry to display in a seq_file iteration.
 * Runs either the current context-limited function
 * (when called from any context but WATCH), or the all-context
 * function (when called from WATCH context).
 * @param s Current seq_file.
 * @param v Current entry or SEQ_START_TOKEN.
 * @param pos Current position (may get incremented, or not).
 * @return Pointer to the next entry (with incremented refcount) if found,
 * NULL otherwise (end of iteration).
 */
static void *
vrhl_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	if (unlikely(vrhl_watch_ctx()))
		return vrhl_watch_seq_next(s, v, pos);
	else
		return vrhl_ctx_seq_next(s, v, pos);
}

/**
 * Terminate a seq_file iteration.
 * Runs either the current context-limited function
 * (when called from any context but WATCH), or the all-context
 * function (when called from WATCH context).
 * @param s Current seq_file.
 * @param v Current entry (unused). Note that this does not have
 * to be put (and may not even be valid) since the putting is done
 * by the last seq_next() call (which then returns NULL).
 */
static void
vrhl_seq_stop(struct seq_file *s, void *v)
{
	if (unlikely(vrhl_watch_ctx()))
		vrhl_watch_seq_stop(s, v);
	else
		vrhl_ctx_seq_stop(s, v);
}

/**
 * Display an entry during a seq_file iteration run.
 * This prints the entry's fields, excepted when SEQ_START_TOKEN
 * was passed as argument (in which case the context header for
 * the context stored in s->private is printed instead).
 * @param s Current seq_file.
 * @param v Current entry, or SEQ_START_TOKEN.
 * @return 0.
 */
static int
vrhl_seq_show(struct seq_file *s, void *v)
{
	if (unlikely(v == SEQ_START_TOKEN))
		vrhl_xlist_seqprint(s, s->private);
	else
		veriexec_entry_seqprint(s, v);
	return 0;
}

/*@}*/

		/*    File interface    */

/**
 * Veriexec seq_file interface seq_operations.
 */
static const struct seq_operations vrhl_seq_ops = {
	.start	= vrhl_seq_start,
	.next	= vrhl_seq_next,
	.stop	= vrhl_seq_stop,
	.show	= vrhl_seq_show,
};

/**
 * Open the the veriexec /proc file.
 * This redirects file operations to the seq_file operations in
 * @a vrhl_seq_ops.
 */
static int
vrhl_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &vrhl_seq_ops);
}

/**
 * Veriexec /proc file file_operations (seq_file type).
 */
const struct file_operations veriexec_proc_fops = {
	.open 		= vrhl_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};


/*************************************************************/
/*                      initialization                       */
/*************************************************************/

/**
 * Initialize the veriexec hashed list store backend.
 * This allocates and initializes the main context (g_xlist).
 * @return 0 on success, negative error code on failure.
 */
int
veriexec_init_store(void)
{
	struct veriexec_xarg xarg;

	BUG_ON(vrhl_initialized);

	spin_lock_init(&g_lock);

	xarg.a_ctx = 0;
	xarg.a_lvl = 0;
	/* XXX find real bset */
	xarg.a_capset = current_cred()->cap_bset;
	xarg.a_privset = 0xffffffff;

	g_xlist = vrhl_xlist_new(&xarg);

	if (unlikely(!g_xlist))
		return -ENOMEM;

	vrhl_xlist_get(g_xlist);

	VERIEXEC_DEBUG("Initialization complete\n");

	vrhl_initialized = 1;
	return 0;
}

/**
 * Delete the veriexec hashed list store backend.
 * Not __exit on purpose, since it is called in __init functions
 * error handling.
 * This error handling is the only use ATM, but this function might also serve
 * in a future module unregistering function.
 */
void
veriexec_exit_store(void)
{
	if (g_xlist)
		vrhl_xlist_free_all();

	VERIEXEC_DEBUG("Veriexec hlist store freed");
}

EXPORT_SYMBOL(veriexec_lookup_f);
EXPORT_SYMBOL(veriexec_lookup_d);
EXPORT_SYMBOL(veriexec_add);
EXPORT_SYMBOL(veriexec_del);
EXPORT_SYMBOL(veriexec_getlvl);
EXPORT_SYMBOL(veriexec_setlvl);
EXPORT_SYMBOL(veriexec_register_open);
EXPORT_SYMBOL(veriexec_register_close);
EXPORT_SYMBOL(veriexec_add_ctx);
EXPORT_SYMBOL(veriexec_set_ctx);
EXPORT_SYMBOL(veriexec_del_ctx);
EXPORT_SYMBOL(veriexec_set_update);
EXPORT_SYMBOL(veriexec_proc_fops);
EXPORT_SYMBOL(veriexec_init_store);
EXPORT_SYMBOL(veriexec_exit_store);
