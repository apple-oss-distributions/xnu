/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef _KERN_SMR_H_
#define _KERN_SMR_H_

#include <sys/cdefs.h>
#include <sys/_endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <kern/startup.h>
#include <os/atomic_private.h>

__BEGIN_DECLS

#ifdef XNU_KERNEL_PRIVATE
#pragma GCC visibility push(hidden)

/*!
 * @typedef smr_seq_t
 *
 * @brief
 * Represents an opaque SMR sequence number.
 */
typedef unsigned long           smr_seq_t;
#define SMR_SEQ_INVALID         ((smr_seq_t)0)
#define SMR_SEQ_INIT            ((smr_seq_t)1)

/*!
 * @typedef smr_clock_t
 *
 * @brief
 * Represents an SMR domain clock, internal type not manipulated by clients.
 */
typedef union {
	struct {
#if __DARWIN_BYTE_ORDER == __DARWIN_LITTLE_ENDIAN
		smr_seq_t       s_rd_seq;
		smr_seq_t       s_wr_seq;
#else
		smr_seq_t       s_wr_seq;
		smr_seq_t       s_rd_seq;
#endif
	};
#if __LP64__
	__uint128_t             s_combined;
#else
	uint64_t                s_combined;
#endif
} smr_clock_t;

/*!
 * @typedef smr_t
 *
 * @brief
 * Declares an SMR domain of synchronization.
 */
typedef struct smr {
	smr_clock_t             smr_clock;
	unsigned long           smr_pcpu;
} *smr_t;


/*
 * SMR Accessors are meant to provide safe access to SMR protected
 * pointers and prevent misuse and accidental access.
 *
 * Accessors are grouped by type:
 * entered      - Use while in a read section (between smr_enter/smr_leave())
 * serialized   - Use while holding a lock that serializes writers.
 *                Updates are synchronized with readers via included barriers.
 * unserialized - Use after the memory is out of scope and not visible to
 *                readers.
 *
 * All acceses include a parameter for an assert to verify the required
 * synchronization.
 */

/*!
 * @macro SMR_POINTER_DECL
 *
 * @brief
 * Macro to declare a pointer type that uses SMR for access.
 */
#define SMR_POINTER_DECL(name, type_t) \
	struct name { type_t volatile __smr_ptr; }

/*!
 * @macro SMR_POINTER
 *
 * @brief
 * Macro to declare a pointer that uses SMR for access.
 */
#define SMR_POINTER(type_t) \
	SMR_POINTER_DECL(, type_t)


/*!
 * @macro smr_entered_load()
 *
 * @brief
 * Read from an SMR protected pointer while in a read section.
 */
#define smr_entered_load(ptr) \
	({ (ptr)->__smr_ptr; })

/*!
 * @macro smr_entered_load_assert()
 *
 * @brief
 * Read from an SMR protected pointer while in a read section.
 */
#define smr_entered_load_assert(ptr, smr)  ({ \
	assert(smr_entered(smr)); \
	(ptr)->__smr_ptr; \
})

/*!
 * @macro smr_entered_load_acquire()
 *
 * @brief
 * Read from an SMR protected pointer while in a read section (with acquire
 * fence).
 */
#define smr_entered_load_acquire(ptr) \
	os_atomic_load(&(ptr)->__smr_ptr, acquire)

/*!
 * @macro smr_entered_load_acquire_assert()
 *
 * @brief
 * Read from an SMR protected pointer while in a read section.
 */
#define smr_entered_load_acquire_assert(ptr, smr)  ({ \
	assert(smr_entered(smr)); \
	os_atomic_load(&(ptr)->__smr_ptr, acquire); \
})

/*!
 * @macro smr_serialized_load_assert()
 *
 * @brief
 * Read from an SMR protected pointer while serialized by an
 * external mechanism.
 */
#define smr_serialized_load_assert(ptr, held_cond)  ({ \
	assertf(held_cond, "smr_serialized_load: lock not held"); \
	(ptr)->__smr_ptr; \
})

/*!
 * @macro smr_serialized_load()
 *
 * @brief
 * Read from an SMR protected pointer while serialized by an
 * external mechanism.
 */
#define smr_serialized_load(ptr) \
	smr_serialized_load_assert(ptr, true)

/*!
 * @macro smr_init_store()
 *
 * @brief
 * Store @c value to an SMR protected pointer during initialization.
 */
#define smr_init_store(ptr, value) \
	({ (ptr)->__smr_ptr = value; })

/*!
 * @macro smr_clear_store()
 *
 * @brief
 * Clear (sets to 0) an SMR protected pointer (this is always "allowed" to do).
 */
#define smr_clear_store(ptr) \
	smr_init_store(ptr, (typeof((ptr)->__smr_ptr))0)

/*!
 * @macro smr_serialized_store_assert()
 *
 * @brief
 * Store @c value to an SMR protected pointer while serialized by an
 * external mechanism.
 *
 * @discussion
 * Writers that are serialized with mutual exclusion or on a single
 * thread should use smr_serialized_store() rather than swap.
 */
#define smr_serialized_store_assert(ptr, value, held_cond)  ({ \
	assertf(held_cond, "smr_serialized_store: lock not held"); \
	os_atomic_thread_fence(release); \
	(ptr)->__smr_ptr = value; \
})

/*!
 * @macro smr_serialized_store()
 *
 * @brief
 * Store @c value to an SMR protected pointer while serialized by an
 * external mechanism.
 *
 * @discussion
 * Writers that are serialized with mutual exclusion or on a single
 * thread should use smr_serialized_store() rather than swap.
 */
#define smr_serialized_store(ptr, value) \
	smr_serialized_store_assert(ptr, value, true)

/*!
 * @macro smr_serialized_swap_assert()
 *
 * @brief
 * Swap @c value with an SMR protected pointer and return the old value
 * while serialized by an external mechanism.
 *
 * @discussion
 * Swap permits multiple writers to update a pointer concurrently.
 */
#define smr_serialized_swap_assert(ptr, value, held_cond)  ({ \
	assertf(held_cond, "smr_serialized_store: lock not held"); \
	os_atomic_xchg(&(ptr)->__smr_ptr, value, release); \
})

/*!
 * @macro smr_serialized_swap()
 *
 * @brief
 * Swap @c value with an SMR protected pointer and return the old value
 * while serialized by an external mechanism.
 *
 * @discussion
 * Swap permits multiple writers to update a pointer concurrently.
 */
#define smr_serialized_swap(ptr, value) \
	smr_serialized_swap_assert(ptr, value, true)

/*!
 * @macro smr_unserialized_load()
 *
 * @brief.
 * Read from an SMR protected pointer when no serialization is required
 * such as in the destructor callback or when the caller guarantees other
 * synchronization.
 */
#define smr_unserialized_load(ptr) \
	({ (ptr)->__smr_ptr; })

/*!
 * @macro smr_unserialized_store()
 *
 * @brief.
 * Store to an SMR protected pointer when no serialiation is required
 * such as in the destructor callback or when the caller guarantees other
 * synchronization.
 */
#define smr_unserialized_store(ptr, value) \
	({ (ptr)->__smr_ptr = value; })


/*!
 * @macro SMR_DEFINE
 *
 * @brief
 * Define a global SMR domain, which will be available when zalloc is available.
 */
#define SMR_DEFINE(var) \
	struct smr var = { \
	        .smr_clock.s_rd_seq = SMR_SEQ_INIT, \
	        .smr_clock.s_wr_seq = SMR_SEQ_INIT, \
	}; \
	STARTUP_ARG(ZALLOC, STARTUP_RANK_LAST, __smr_init, &var)

/*!
 * @macro SMR_DEFINE_EARLY
 *
 * @brief
 * Define an SMR domain that needs to be functional immediately at boot.
 */
#define SMR_DEFINE_EARLY(var) \
	SMR_DEFINE(var); \
	STARTUP_ARG(TUNABLES, STARTUP_RANK_LAST, __smr_init, &var)

extern void __smr_init(smr_t);

/*!
 * @function smr_init()
 *
 * @brief
 * Initialize an smr struct.
 */
extern void smr_init(smr_t);

/*!
 * @function smr_destroy()
 *
 * @brief
 * Destroys an smr struct previously initialized with @c smr_init().
 */
extern void smr_destroy(smr_t);

/*!
 * @function smr_entered()
 *
 * @brief
 * Returns whether an SMR critical section is entered.
 */
extern bool smr_entered(smr_t) __result_use_check;

/*!
 * @function smr_enter()
 *
 * @brief
 * Enter an SMR critical section.
 */
extern void smr_enter(smr_t);

/*!
 * @function smr_leave()
 *
 * @brief
 * Leave an SMR critical section.
 */
extern void smr_leave(smr_t);


/*!
 * @function smr_advance()
 *
 * @brief
 * Advance the write sequence and return the value
 * for use as a wait goal.
 *
 * @discussion
 * This guarantees that any changes made by the calling thread
 * prior to this call will be visible to all threads after
 * the read sequence meets or exceeds the return value.
 *
 * This function may busy loop if the readers are roughly 1 billion
 * sequence numbers behind the writers.
 */
extern smr_seq_t smr_advance(smr_t) __result_use_check;

/*!
 * @function smr_poll
 *
 * @brief
 * Poll to determine whether all readers have observed the @c goal
 * write sequence number.
 *
 * @discussion
 * This function is safe to be called from preemption disabled context
 * and its worst complexity is O(ncpu).
 *
 * @returns true if the goal is met and false if not.
 */
extern bool smr_poll(smr_t smr, smr_seq_t goal) __result_use_check;

/*!
 * @function smr_wait
 *
 * @brief
 * Wait until all readers have observed
 * the @c goal write sequence number.
 *
 * @discussion
 * This function is safe to be called from preemption disabled context
 * as it never explicitly blocks, however this is not recommended.
 */
extern void smr_wait(smr_t smr, smr_seq_t goal);

/*!
 * @function smr_synchronize()
 *
 * @brief
 * Synchronize advances the write sequence
 * and returns when all readers have observed it.
 *
 * @discussion
 * This is roughly equivalent to @c smr_wait(smr, smr_advance(smr))
 *
 * It is however better to cache a sequence number returned
 * from @c smr_advance(), and poll or wait for it at a latter time,
 * as there will be less chance of spinning while waiting for readers.
 */
extern void smr_synchronize(smr_t);

#pragma GCC visibility pop
#endif // XNU_KERNEL_PRIVATE

__END_DECLS

#endif /* _KERN_SMR_H_ */
