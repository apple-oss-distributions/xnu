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

#ifndef _KERN_LOCKS_INTERNAL_H_
#define _KERN_LOCKS_INTERNAL_H_

#define LOCK_PRIVATE 1
#include <sys/cdefs.h>
#include <stdint.h>
#include <kern/startup.h>
#include <kern/percpu.h>
#include <kern/lock_types.h>
#include <kern/lock_group.h>
#include <machine/locks.h>
#include <machine/cpu_number.h>
#include <os/atomic_private.h>

/*
 * This file shares implementation details for XNU lock implementations.
 * It is not meant to be shared with any other part of the code.
 */

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN

#pragma GCC visibility push(hidden)

/*!
 * @macro hw_spin_wait_until_n()
 *
 * @brief
 * Abstracts the platform specific way to spin around the value
 * of a memory location until a certain condition is met.
 *
 * @param count         how many times to spin without evaluating progress
 * @param ptr           the pointer to the memory location being observed
 * @param load_var      the variable to store the result of the load into
 * @param cond_expr     the stopping condition (can use @c load_var)
 *
 * @returns
 * - 0 if the loop stopped when the counter expired
 * - cond_expr's return value otherwise
 */
#define hw_spin_wait_until_n(count, ptr, load_var, cond_expr)  ({ \
	typeof((cond_expr)) __cond_result;                                      \
                                                                                \
	for (uint32_t __cond_init = (count), __cond_count = __cond_init;        \
	    __probable(__cond_count-- > 0);) {                                  \
	        __hw_spin_wait_load(ptr, load_var, __cond_result, cond_expr);   \
	        if (__probable(__cond_result)) {                                \
	                break;                                                  \
	        }                                                               \
	}                                                                       \
                                                                                \
	__cond_result;                                                          \
})

/*!
 * @macro hw_spin_wait_until()
 *
 * @brief
 * Conveniency wrapper for hw_spin_wait_until_n() with the typical
 * LOCK_SNOOP_SPINS counter for progress evaluation.
 */
#define hw_spin_wait_until(ptr, load_var, cond_expr) \
	hw_spin_wait_until_n(LOCK_SNOOP_SPINS, ptr, load_var, cond_expr)


#if LOCK_PRETEST
#define lck_pretestv(p, e, g)  ({ \
	__auto_type __e = (e); \
	__auto_type __v = os_atomic_load(p, relaxed); \
	if (__v != __e) { \
	        *(g) = __v; \
	} \
	__v == __e; \
})
#define lck_pretest(p, e) \
	(os_atomic_load(p, relaxed) == (e))
#else
#define lck_pretestv(p, e, g)   1
#define lck_pretest(p, e)       1
#endif

/*!
 * @function lock_cmpxchg
 *
 * @brief
 * Similar to os_atomic_cmpxchg() but with a pretest when LOCK_PRETEST is set.
 */
#define lock_cmpxchg(p, e, v, m)  ({ \
	__auto_type _p = (p);                                          \
	__auto_type _e = (e);                                          \
	lck_pretest(_p, _e) && os_atomic_cmpxchg(_p, _e, v, m);        \
})

/*!
 * @function lock_cmpxchgv
 *
 * @brief
 * Similar to os_atomic_cmpxchgv() but with a pretest when LOCK_PRETEST is set.
 */
#define lock_cmpxchgv(p, e, v, g, m)  ({ \
	__auto_type _p = (p);                                           \
	__auto_type _e = (e);                                           \
	lck_pretestv(_p, _e, g) && os_atomic_cmpxchgv(_p, _e, v, g, m); \
})

#if OS_ATOMIC_HAS_LLSC
#define lock_load_exclusive(p, m)               os_atomic_load_exclusive(p, m)
#define lock_wait_for_event()                   wait_for_event()
#define lock_store_exclusive(p, ov, nv, m)      os_atomic_store_exclusive(p, nv, m)
#else
#define lock_load_exclusive(p, m)               os_atomic_load(p, relaxed)
#define lock_wait_for_event()                   cpu_pause()
#define lock_store_exclusive(p, ov, nv, m)      os_atomic_cmpxchg(p, ov, nv, m)
#endif


/*!
 * @enum lck_type_t
 *
 * @brief
 * A one-byte type tag used in byte 3 of locks to be able to identify them.
 */
__enum_decl(lck_type_t, uint8_t, {
	LCK_TYPE_NONE           = 0x00,
	LCK_TYPE_MUTEX          = 0x22,
	LCK_TYPE_RW             = 0x33,
	LCK_TYPE_TICKET         = 0x44,
	LCK_TYPE_GATE           = 0x55,
});

#pragma GCC visibility pop

__ASSUME_PTR_ABI_SINGLE_END __END_DECLS

#endif /* _KERN_LOCKS_INTERNAL_H_ */
