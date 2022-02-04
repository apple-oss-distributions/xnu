/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#ifndef _KERN_HAZARD_H_
#define _KERN_HAZARD_H_

#include <sys/cdefs.h>
#include <kern/assert.h>
#include <mach/vm_types.h>
#include <os/atomic_private.h>

__BEGIN_DECLS

#ifdef XNU_KERNEL_PRIVATE
#pragma GCC visibility push(hidden)

/*!
 * @file <kern/hazard.h>
 *
 * @brief
 * Implementation of hazard pointers.
 *
 * @discussion
 * Hazard pointers are fields that can be accessed when protected by special
 * guards rather than traditional locks.
 *
 * <h2>Concepts</h2>
 *
 * Pointers used in this way must be declared with the @c HAZARD_POINTER macro.
 *
 * Guards can be "allocated" and "freed" using @c hazard_guard_get() and
 * @c hazard_guard_set().
 *
 * Then guards can be used to "acquire" the value of a hazardous pointer.
 *
 *
 * <h2>Performance</h2>
 *
 * Acquiring through a guard has a relatively strong memory barrier,
 * and its performance is at least as expensive as acquiring
 * an uncontended lock.
 *
 * Releasing a guard (@c hazard_guard_put()) has a performance equivalent
 * to releasing an uncontended lock.
 *
 * Acquiring through a reused guard combines both costs back to back.
 *
 *
 * <h2>Recommended usage</h2>
 *
 * Hazard guards/pointers have a performance profile roughly similar
 * to an uncontended lock when accessing a single pointer.
 *
 * It means that this technology isn't really suitable to protect a linked
 * list (where the cost would have to be paid per element during a traversal),
 * but works really well to protect access to a single pointer.
 *
 * This technology also has very strong guarantees in memory overhead,
 * where the number of deferred deallocations is bounded by the number
 * of guard slots.
 *
 *
 * This is why the current implementation decides to only provide statically
 * allocated CPU-local slots, which means that @c hazard_guard_get() will
 * disable preemption and @c hazard_guard_put() re-enable it.
 *
 * Because the slots are statically allocated, oblivious nested use
 * of hazard guards is not supported (Note: this could change provided
 * a maximum "depth" of use can be guaranteed).
 */


#pragma mark - pointers allowing hazardous access

/*!
 * @macro HAZARD_POINTER_DECL
 *
 * @brief
 * Macro to declare a pointer type that uses hazard guards for access.
 */
#define HAZARD_POINTER_DECL(name, type_t) \
	struct name { type_t volatile __hazard_ptr; }

/*!
 * @macro HAZARD_POINTER
 *
 * @brief
 * Macro to declare a pointer that uses hazard guards for access.
 */
#define HAZARD_POINTER(type_t) \
	HAZARD_POINTER_DECL(, type_t)

/*!
 * @macro hazard_ptr_init()
 *
 * @brief
 * Initializes a @c HAZARD_POINTER() field to a specified value.
 *
 * @discussion
 * The memory of @c value must have been initialized prior to this call.
 *
 * This is meant to be used in object initializers only, for updates to the
 * pointer past initialization, use @c hazard_ptr_serialized_store().
 *
 * @param ptr           The hazard-protected pointer to initialize.
 * @param value         The value to initialize the poiner with.
 */
#define hazard_ptr_init(ptr, value) \
	__hazard_ptr_atomic_store(ptr, value, release)

/*!
 * @macro hazard_ptr_clear()
 *
 * @brief
 * Clears a @c HAZARD_POINTER() field.
 *
 * @param ptr           The hazard-protected pointer to clear.
 */
#define hazard_ptr_clear(ptr) \
	__hazard_ptr_atomic_store(ptr, NULL, relaxed)

/*!
 * @macro hazard_ptr_serialized_load_assert()
 *
 * @brief
 * Read from a hazard protected pointer, while serialized by an external
 * mechanism.
 *
 * @param ptr           The hazard-protected pointer to read.
 * @param held_cond     An expression that can be asserted that the external
 *                      mechanism is held.
 */
#define hazard_ptr_serialized_load_assert(ptr, held_cond)  ({ \
	assertf(held_cond, "hazard_ptr_serialized_load: lock not held"); \
	(ptr)->__hazard_ptr; \
})

/*!
 * @macro hazard_ptr_serialized_load()
 *
 * @brief
 * Read from a hazard protected pointer, while serialized by an external
 * mechanism.
 *
 * @param ptr           The hazard-protected pointer to read.
 */
#define hazard_ptr_serialized_load(ptr) \
	hazard_ptr_serialized_load_assert(ptr, true)

/*!
 * @macro hazard_ptr_load()
 *
 * @brief
 * Read from a hazard protected pointer.
 *
 * @discussion
 * Note that the returned value is not safe to dereference
 * until it has been properly guarded.
 *
 * This is typically used in conjunction with @c hazard_guard_reuse_acquire().
 *
 * @param ptr           The hazard-protected pointer to read.
 */
#define hazard_ptr_load(ptr) \
	({ (ptr)->__hazard_ptr; })

/*!
 * @macro hazard_ptr_serialized_store_assert()
 *
 * @brief
 * Updates the value of a hazard protected pointer, while serialized by an
 * external mechanism.
 *
 * @param ptr           The hazard-protected pointer to read.
 * @param value         The value to update the poiner with.
 * @param held_cond     An expression that can be asserted that the external
 *                      mechanism is held.
 */
#define hazard_ptr_serialized_store_assert(ptr, value, held_cond)  ({ \
	assertf(held_cond, "hazard_ptr_serialized_store: lock not held"); \
	__hazard_ptr_atomic_store(ptr, value, release);                   \
})

/*!
 * @macro hazard_ptr_serialized_store()
 *
 * @brief
 * Updates the value of a hazard protected pointer, while serialized by an
 * external mechanism.
 *
 * @param ptr           The hazard-protected pointer to read.
 * @param value         The value to update the poiner with.
 */
#define hazard_ptr_serialized_store(ptr, value) \
	hazard_ptr_serialized_store_assert(ptr, value, true)

/*!
 * @macro hazard_ptr_serialized_store_relaxed_assert()
 *
 * @brief
 * Updates the value of a hazard protected pointer, while serialized by an
 * external mechanism, without any barrier.
 *
 * @param ptr           The hazard-protected pointer to read.
 * @param value         The value to update the poiner with.
 * @param held_cond     An expression that can be asserted that the external
 *                      mechanism is held.
 */
#define hazard_ptr_serialized_store_relaxed_assert(ptr, value, held_cond)  ({ \
	assertf(held_cond, "hazard_ptr_serialized_store: lock not held"); \
	__hazard_ptr_atomic_store(ptr, value, relaxed);                   \
})

/*!
 * @macro hazard_ptr_serialized_store_relaxed()
 *
 * @brief
 * Updates the value of a hazard protected pointer, while serialized by an
 * external mechanism, without any barrier.
 *
 * @param ptr           The hazard-protected pointer to read.
 * @param value         The value to update the poiner with.
 */
#define hazard_ptr_serialized_store_relaxed(ptr, value) \
	hazard_ptr_serialized_store_relaxed_assert(ptr, value, true)

/*!
 * @macro hazard_retire()
 *
 * @brief
 * Retires a pointer value that used to be assigned to a @c HAZARD_POINTER().
 *
 * @param value         The value to retire (must be pointer aligned).
 * @param size          An estimate of how much memory will be freed.
 * @param destructor    The destructor for the value.
 */
extern void
hazard_retire(void *value, vm_size_t size, void (*destructor)(void *));


#pragma mark - hazard guards

/*!
 * @typedef hazard_guard_t
 *
 * @brief
 * The type for a hazard pointer guard.
 */
typedef struct hazard_guard {
	os_atomic(void *)       hg_val;
} *hazard_guard_t;

/*!
 * @typedef hazard_guard_array_t
 *
 * @brief
 * The type for a hazard pointer guard array.
 */
typedef struct hazard_guard *hazard_guard_array_t;

/*!
 * @const HAZARD_GUARD_SLOTS
 *
 * @brief
 * The number of static hazard guard slots available per CPU.
 */
#define HAZARD_GUARD_SLOTS  3

/*!
 * @function hazard_guard_get()
 *
 * @brief
 * Prepares a hazard guard slot to be used.
 *
 * @discussion
 * This function disables preemption.
 *
 * When the guard slot is not longer needed, it must be disposed of
 * using @c hazard_guard_put().
 *
 * @param slot          The static slot to start using.
 */
#define hazard_guard_get(slot)  ({ \
	static_assert(slot < HAZARD_GUARD_SLOTS, "invalid slot #"); \
	__hazard_guard_get(slot, 1); \
})

/*!
 * @function hazard_guard_get_n()
 *
 * @brief
 * Prepares @c n contiguous hazard guard slots to be used.
 *
 * @discussion
 * This function disables preemption.
 *
 * When the guard slot is not longer needed, it must be disposed of
 * using @c hazard_guard_put_n().
 *
 * @param slot          The static slot to start using.
 */
#define hazard_guard_get_n(slot, n)  ({ \
	static_assert(slot + n <= HAZARD_GUARD_SLOTS, "invalid slot #"); \
	__hazard_guard_get(slot, n); \
})

/*!
 * @function hazard_guard_put()
 *
 * @brief
 * Disposes of a hazard guard allocated with @c hazard_guard_get().
 *
 * @param guard         The hazard guard to dispose of.
 */
extern void
hazard_guard_put(hazard_guard_t guard);

/*!
 * @function hazard_guard_put_n()
 *
 * @brief
 * Disposes of @c n hazard guards allocated with @c hazard_guard_get_n().
 *
 * @param array         The hazard array to dispose of.
 * @param n             The number of guards allocated with
 *                      @c hazard_guard_get_n() (must match).
 */
extern void
hazard_guard_put_n(hazard_guard_array_t array, size_t n);

/*!
 * @function hazard_guard_dismiss()
 *
 * @brief
 * Disposes of a hazard guard allocated with @c hazard_guard_get().
 *
 * @discussion
 * This variant doesn't have a memory barrier and should only be used
 * when an external mechanism ensures that the guarded value stays pinned.
 *
 * @param guard         The hazard guard to dispose of.
 */
extern void
hazard_guard_dismiss(hazard_guard_t guard);

/*!
 * @function hazard_guard_dismiss_n()
 *
 * @brief
 * Disposes of @c n hazard guard allocated with @c hazard_guard_get_n().
 *
 * @discussion
 * This variant doesn't have a memory barrier and should only be used
 * when an external mechanism ensures that the guarded value stays pinned.
 *
 * @param guard         The first hazard guard to dispose of.
 * @param n             The number of guards allocated with
 *                      @c hazard_guard_get_n() (must match).
 */
extern void
hazard_guard_dismiss_n(hazard_guard_t guard, size_t n);

/*!
 * @function hazard_guard_set()
 *
 * @brief
 * Sets the value a guard will protect,
 * in a guard that wasn't protecting anything.
 *
 * @discussion
 * Most users will want to use the @c hazard_guard_acquire()
 * wrapper instead.
 *
 * @param guard         The hazard guard.
 * @param value         The value to protect.
 */
extern void
hazard_guard_set(hazard_guard_t guard, void *value);

/*!
 * @function hazard_guard_replace()
 *
 * @brief
 * Sets the value a guard will protect,
 * in a guard that was previously protecting a value.
 *
 * @discussion
 * Most users will want to use the @c hazard_guard_reuse_acquire()
 * wrapper instead.
 *
 * @param guard         The hazard guard.
 * @param value         The value to protect.
 */
extern void
hazard_guard_replace(hazard_guard_t guard, void *value);

/*!
 * @function hazard_guard_acquire_val()
 *
 * @brief
 * Acquire a guarded copy of a hazard pointer,
 * using a guard that wasn't protecting anything.
 *
 * @param guard         The hazard guard.
 * @param ptr           The pointer to read.
 * @param val           The current value of @c ptr
 *                      (read with @c hazard_ptr_load()).
 */
#define hazard_guard_acquire_val(guard, ptr, val) ({                    \
	__auto_type __p2 = (ptr);                                       \
	__auto_type __val = (val);                                      \
	hazard_guard_set(guard, __val);                                 \
	__hazard_guard_acquire_loop(guard, __p2, __val);                \
})

/*!
 * @function hazard_guard_acquire()
 *
 * @brief
 * Acquire a guarded copy of a hazard pointer,
 * using a guard that wasn't protecting anything.
 *
 * @param guard         The hazard guard.
 * @param ptr           The pointer to read.
 */
#define hazard_guard_acquire(guard, ptr) ({                             \
	__auto_type __p1 = (ptr);                                       \
	hazard_guard_acquire_val(guard, __p1, hazard_ptr_load(__p1));   \
})

/*!
 * @function hazard_guard_reacquire_val()
 *
 * @brief
 * Acquire a guarded copy of a hazard pointer,
 * using a guard that was previously protecting a value.
 *
 * @param guard         The hazard guard.
 * @param ptr           The pointer to read.
 * @param val           The current value of @c ptr.
 */
#define hazard_guard_reacquire_val(guard, ptr, val) ({                  \
	__auto_type __p2 = (ptr);                                       \
	__auto_type __val = (val);                                      \
	hazard_guard_replace(guard, __val);                             \
	__hazard_guard_acquire_loop(guard, __p2, __val);                \
})

/*!
 * @function hazard_guard_reacquire()
 *
 * @brief
 * Acquire a guarded copy of a hazard pointer,
 * using a guard that was previously protecting a value.
 *
 * @param guard         The hazard guard.
 * @param ptr           The pointer to read.
 */
#define hazard_guard_reacquire(guard, ptr) ({                           \
	__auto_type __p1 = (ptr);                                       \
	hazard_guard_reacquire_val(guard, __p1, hazard_ptr_load(__p1);  \
})


#pragma mark - implementation details

extern hazard_guard_array_t
__hazard_guard_get(size_t slot, size_t count);

#define __hazard_guard_acquire_loop(guard, ptr, val) ({                 \
	__auto_type __v1 = val;                                         \
	for (;;) {                                                      \
	        __auto_type __v2 = hazard_ptr_load(ptr);                \
	        if (__probable(__v1 == __v2)) {                         \
	                break;                                          \
	        }                                                       \
	        hazard_guard_set(guard, __v1 = __v2);                   \
	}                                                               \
	__v1;                                                           \
})

#define __hazard_ptr_atomic_store(ptr, value, order)  ({ \
	os_atomic_thread_fence(order);                                  \
	(ptr)->__hazard_ptr = (value);                                  \
})

#if MACH_KERNEL_PRIVATE
extern void
hazard_register_mpsc_queue(void);
#endif

#pragma GCC visibility pop
#endif // XNU_KERNEL_PRIVATE

__END_DECLS

#endif /* _KERN_HAZARD_H_ */
