/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */


#ifndef _KERN_LOCK_PTR_H_
#define _KERN_LOCK_PTR_H_

#include <kern/lock_types.h>
#include <kern/lock_group.h>
#include <kern/lock_attr.h>
#include <vm/vm_memtag.h>

__BEGIN_DECLS
#pragma GCC visibility push(hidden)

#if CONFIG_KERNEL_TAGGING
#define HW_LCK_PTR_BITS         (64 - 4 - 1 - 1 - 16)
#else /* !CONFIG_KERNEL_TAGGING */
#define HW_LCK_PTR_BITS         (64 - 1 - 1 - 16)
#endif /* !CONFIG_KERNEL_TAGGING */

/*!
 * @typedef hw_lck_ptr_t
 *
 * @brief
 * Low level lock that can share the slot of a pointer value.
 *
 * @discussion
 * An @c hw_lck_ptr_t is a fair spinlock fitting in a single
 * pointer sized word, and allows for that word to retain
 * its original pointer value without any loss.
 *
 * It uses the top bits of the pointer which in the kernel
 * aren't significant to store an MCS queue as well as various
 * state bits.
 *
 * The pointer can't be PAC signed, but the MTESAN tag
 * is preserved (when the feature is on).
 *
 * No assumption is made on the alignment of the pointer,
 * and clients may use the low bits of the pointer to encode
 * state as they see fit.
 *
 * It is intended to be used for fine grained locking
 * in hash table bucket heads or similar structures.
 *
 * The pointer value can be changed by taking the lock,
 * (which returns the current value of the pointer),
 * and then unlock with the new pointer value.
 */
typedef union hw_lck_ptr {
	struct {
		intptr_t        lck_ptr_bits    : HW_LCK_PTR_BITS;
#if CONFIG_KERNEL_TAGGING
		uintptr_t       lck_ptr_tag     : 4;
#endif /* CONFIG_KERNEL_TAGGING */
		uintptr_t       lck_ptr_locked  : 1;
		uintptr_t       lck_ptr_stats   : 1;
		uint16_t        lck_ptr_mcs_tail __kernel_ptr_semantics;
	};
	uintptr_t               lck_ptr_value;
} hw_lck_ptr_t;


/* init/destroy */

#if !LCK_GRP_USE_ARG
#define hw_lck_ptr_init(lck, val, grp)        hw_lck_ptr_init(lck, val)
#define hw_lck_ptr_destroy(lck, grp)          hw_lck_ptr_destroy(lck)
#endif /* !LCK_GRP_USE_ARG */

/*!
 * @function hw_lck_ptr_init()
 *
 * @brief
 * Initializes an hw_lck_ptr_t with the specified pointer value.
 *
 * @discussion
 * hw_lck_ptr_destroy() must be called to destroy this lock.
 *
 * @param lck           the lock to initialize
 * @param val           the pointer value to store in the lock
 * @param grp           the lock group associated with this lock
 */
extern void hw_lck_ptr_init(
	hw_lck_ptr_t           *lck,
	void                   *val,
	lck_grp_t              *grp);

/*!
 * @function hw_lck_ptr_destroy()
 *
 * @brief
 * Detroys an hw_lck_ptr_t initialized with hw_lck_ptr_init().
 *
 * @param lck           the lock to destroy
 * @param grp           the lock group associated with this lock
 */
extern void hw_lck_ptr_destroy(
	hw_lck_ptr_t           *lck,
	lck_grp_t              *grp);

/*!
 * @function hw_lck_ptr_held()
 *
 * @brief
 * Returns whether the pointer lock is currently held by anyone.
 *
 * @param lck           the lock to check.
 */
extern bool hw_lck_ptr_held(
	hw_lck_ptr_t           *lck) __result_use_check;


/* lock */

#if !LCK_GRP_USE_ARG
#define hw_lck_ptr_lock(lck, grp)             hw_lck_ptr_lock(lck)
#define hw_lck_ptr_lock_nopreempt(lck, grp)   hw_lck_ptr_lock_nopreempt(lck)
#endif /* !LCK_GRP_USE_ARG */


/*!
 * @function hw_lck_ptr_lock()
 *
 * @brief
 * Locks a pointer lock, and returns its current value.
 *
 * @discussion
 * This call will disable preemption.
 *
 * @param lck           the lock to lock
 * @param grp           the lock group associated with this lock
 */
extern void *hw_lck_ptr_lock(
	hw_lck_ptr_t           *lck,
	lck_grp_t              *grp) __result_use_check;

/*!
 * @function hw_lck_ptr_lock_nopreempt()
 *
 * @brief
 * Locks a pointer lock, and returns its current value.
 *
 * @discussion
 * Preemption must be disabled to make this call,
 * and must stay disabled until @c hw_lck_ptr_unlock()
 * or @c hw_lck_ptr_unlock_nopreempt() is called
 *
 * @param lck           the lock to lock
 * @param grp           the lock group associated with this lock
 */
extern void *hw_lck_ptr_lock_nopreempt(
	hw_lck_ptr_t           *lck,
	lck_grp_t              *grp) __result_use_check;


/* unlock */

#if !LCK_GRP_USE_ARG
#define hw_lck_ptr_unlock(lck, val, grp) \
	hw_lck_ptr_unlock(lck, val)
#define hw_lck_ptr_unlock_nopreempt(lck, val, grp) \
	hw_lck_ptr_unlock_nopreempt(lck, val)
#endif /* !LCK_GRP_USE_ARG */


/*!
 * @function hw_lck_ptr_unlock()
 *
 * @brief
 * Unlocks a pointer lock, and update its currently held value.
 *
 * @discussion
 * This call will reenable preemption.
 *
 * @param lck           the lock to unlock
 * @param val           the value to update the pointer to
 * @param grp           the lock group associated with this lock
 */
extern void hw_lck_ptr_unlock(
	hw_lck_ptr_t           *lck,
	void                   *val,
	lck_grp_t              *grp);

/*!
 * @function hw_lck_ptr_unlock_nopreempt()
 *
 * @brief
 * Unlocks a pointer lock, and update its currently held value.
 *
 * @discussion
 * This call will not reenable preemption.
 *
 * @param lck           the lock to unlock
 * @param val           the value to update the pointer to
 * @param grp           the lock group associated with this lock
 */
extern void hw_lck_ptr_unlock_nopreempt(
	hw_lck_ptr_t           *lck,
	void                   *val,
	lck_grp_t              *grp);


/* wait_for_value */

#if !LCK_GRP_USE_ARG
#define hw_lck_ptr_wait_for_value(lck, val, grp) \
	hw_lck_ptr_wait_for_value(lck, val)
#endif /* !LCK_GRP_USE_ARG */

static inline void *
__hw_lck_ptr_value(hw_lck_ptr_t val)
{
	vm_offset_t ptr = val.lck_ptr_bits;

#if CONFIG_KERNEL_TAGGING
	if (ptr) {
		ptr = vm_memtag_add_ptr_tag(ptr, val.lck_ptr_tag);
	}
#endif /* CONFIG_KERNEL_TAGGING */
	return (void *)ptr;
}


/*!
 * @function hw_lck_ptr_value()
 *
 * @brief
 * Returns the pointer value currently held by this lock.
 *
 * @param lck           the lock to get the pointer value of.
 */
static inline void *
hw_lck_ptr_value(hw_lck_ptr_t *lck)
{
	hw_lck_ptr_t tmp;

	tmp = atomic_load_explicit((hw_lck_ptr_t _Atomic *)lck,
	    memory_order_relaxed);

	return __hw_lck_ptr_value(tmp);
}

/*!
 * @function hw_lck_ptr_wait_for_value()
 *
 * @brief
 * Spins until the pointer in the lock has the specified value.
 *
 * @discussion
 * This function has an implicit acquire barrier pairing
 * with the hw_lck_ptr_unlock() which sets the observed value.
 *
 * @param lck           the lock to spin on
 * @param val           the value to wait for
 * @param grp           the lock group associated with this lock
 */
extern void hw_lck_ptr_wait_for_value(
	hw_lck_ptr_t           *lck,
	void                   *val,
	lck_grp_t              *grp);


#pragma GCC visibility pop
__END_DECLS

#endif /* _KERN_LOCK_PTR_H_ */
