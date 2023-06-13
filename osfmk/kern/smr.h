/*
 * Copyright (c) 2021-2022 Apple Inc. All rights reserved.
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
#include <stdbool.h>
#include <stdint.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/smr_types.h>
#include <kern/startup.h>
#include <os/atomic_private.h>

__BEGIN_DECLS

#pragma mark SMR pointers

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
 * @macro smr_unsafe_load()
 *
 * @brief
 * Read from an SMR protected pointer without any synchronization.
 *
 * @discussion
 * This returns an integer on purpose as dereference is generally unsafe.
 */
#define smr_unsafe_load(ptr) \
	({ (uintptr_t)((ptr)->__smr_ptr); })

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
	smr_init_store(ptr, 0)

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
 * @macro smr_serialized_store_relaxed_assert()
 *
 * @brief
 * Store @c value to an SMR protected pointer while serialized by an
 * external mechanism.
 *
 * @discussion
 * This function can be used when storing a value that was already
 * previously stored with smr_serialized_store() (for example during
 * a linked list removal).
 */
#define smr_serialized_store_relaxed_assert(ptr, value, held_cond)  ({ \
	assertf(held_cond, "smr_serialized_store_relaxed: lock not held"); \
	(ptr)->__smr_ptr = value; \
})

/*!
 * @macro smr_serialized_store_relaxed()
 *
 * @brief
 * Store @c value to an SMR protected pointer while serialized by an
 * external mechanism.
 *
 * @discussion
 * This function can be used when storing a value that was already
 * previously stored with smr_serialized_store() (for example during
 * a linked list removal).
 */
#define smr_serialized_store_relaxed(ptr, value) \
	smr_serialized_store_relaxed_assert(ptr, value, true)

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


#pragma mark SMR queues

/*
 * SMR queues are queues that are meant to be read under SMR critical sections
 * concurrently with possible updates to the queue.
 *
 * /!\ Such read operations CAN ONLY BE PERFORMED IN FORWARD DIRECTION. /!\
 *
 * Queues can be either:
 * - lists where the head is a single pointer,
 *   and insertions can only be at the head;
 * - tail queues where the head is two pointers,
 *   and insertions can be either at the head or the tail.
 *
 * Queue linkages can either be single forward pointer linkages or double
 * forward/backward linkages. The latter supports O(1) deletion.
 *
 *
 * The entire API surface uses type inference for the implementations,
 * which allows to relatively easily change between the 4 types of queues
 * with very minimal API changes (mostly the types of list heads and fields).
 */


/*!
 * @macro smrq_init
 *
 * @brief
 * Initializes an SMR queue head.
 */
#define smrq_init(head)  ({ \
	__auto_type __head = (head);                                            \
                                                                                \
	smr_init_store(&__head->first, NULL);                                   \
	if (__smrq_lastp(__head)) {                                             \
	    *__smrq_lastp(__head) = &__head->first;                             \
	}                                                                       \
})


/*!
 * @macro smrq_empty
 *
 * @brief
 * Returns whether an SMR queue is empty, can be called from any context.
 */
#define smrq_empty(head) \
	(smr_unsafe_load(&(head)->first) == 0)


/*!
 * @macro smrq_entered_first
 *
 * @brief
 * Returns the first element of an SMR queue, while in a read section.
 */
#define smrq_entered_first(head, type_t, field) \
	__container_of_safe(smr_entered_load(&(head)->first), type_t, field)


/*!
 * @macro smrq_entered_next
 *
 * @brief
 * Returns the next element of an SMR queue element, while in a read section.
 */
#define smrq_entered_next(elem, field) \
	__container_of_safe(smr_entered_load(&(elem)->field.next), \
	    typeof(*(elem)), field)


/*!
 * @macro smrq_entered_foreach
 *
 * @brief
 * Enumerates an SMR queue, while in a read section.
 */
#define smrq_entered_foreach(it, head, field) \
	for (__auto_type __it = smr_entered_load(&(head)->first);               \
	    ((it) = __container_of_safe(__it, typeof(*(it)), field));           \
	    __it = smr_entered_load(&__it->next))


/*!
 * @macro smrq_serialized_first
 *
 * @brief
 * Returns the first element of an SMR queue, while being serialized
 * by an external mechanism.
 */
#define smrq_serialized_first(head, type_t, link) \
	__container_of_safe(smr_serialized_load(&(head)->first), type_t, link)

/*!
 * @macro smrq_serialized_next
 *
 * @brief
 * Returns the next element of an SMR queue element, while being serialized
 * by an external mechanism.
 */
#define smrq_serialized_next(elem, field) \
	__container_of_safe(smr_serialized_load(&(elem)->field.next), \
	    typeof(*(elem)), field)

/*!
 * @macro smrq_serialized_foreach
 *
 * @brief
 * Enumerates an SMR queue, while being serialized
 * by an external mechanism.
 */
#define smrq_serialized_foreach(it, head, field) \
	for (__auto_type __it = smr_serialized_load(&(head)->first);            \
	    ((it) = __container_of_safe(__it, typeof(*(it)), field));           \
	    __it = smr_serialized_load(&__it->next))

/*!
 * @macro smrq_serialized_foreach_safe
 *
 * @brief
 * Enumerates an SMR queue, while being serialized
 * by an external mechanism.
 *
 * @discussion
 * This variant supports removing the current element from the queue.
 */
#define smrq_serialized_foreach_safe(it, head, field) \
	for (__auto_type __it = smr_serialized_load(&(head)->first),            \
	    __next_it = __it;                                                   \
	    ((it) = __container_of_safe(__it, typeof(*(it)), field)) &&         \
	    ((__next_it = smr_serialized_load(&__it->next)), 1);                \
	    __it = __next_it)


/*!
 * @macro smrq_serialized_insert_head
 *
 * @brief
 * Inserts an element at the head of an SMR queue, while being serialized
 * by an external mechanism.
 */
#define smrq_serialized_insert_head(head, elem)  ({ \
	__auto_type __head = (head);                                            \
                                                                                \
	__smrq_serialized_insert(&__head->first, (elem),                        \
	   smr_serialized_load(&__head->first), __smrq_lastp(__head));          \
})


/*!
 * @macro smrq_serialized_insert_tail
 *
 * @brief
 * Inserts an element at the tail of an SMR queue, while being serialized
 * by an external mechanism.
 */
#define smrq_serialized_insert_tail(head, elem)  ({ \
	__auto_type __head = (head);                                            \
                                                                                \
	__smrq_serialized_insert(__head->last, (elem),                          \
	   NULL, &__head->last);                                                \
})


/*!
 * @macro smrq_serialized_remove
 *
 * @brief
 * Removes an element from an SMR queue, while being serialized
 * by an external mechanism.
 *
 * @discussion
 * The @c head argument is actually unused for the @c smrq_list queue type.
 * It is still advised to pass it, the compiler should be able to optimize
 * the code away as computing a list head ought to have no side effects.
 */
#define smrq_serialized_remove(head, elem)  ({ \
	__auto_type __head = (head);                                            \
                                                                                \
	__smrq_serialized_remove(&__head->first, (elem), __smrq_lastp(__head)); \
})


/*!
 * @macro smrq_serialized_replace
 *
 * @brief
 * Replaces an element on an SMR queue with another at the same spot,
 * while being serialized by an external mechanism.
 */
#define smrq_serialized_replace(head, old_elem, new_elem)  ({ \
	__auto_type __head = (head);                                            \
                                                                                \
	__smrq_serialized_replace(&__head->first,                               \
	    (old_elem), (new_elem), __smrq_lastp(__head));                      \
})


/*!
 * @macro smrq_serialized_iter
 *
 * @brief
 * Enumerates an SMR singly linked queue, while being serialized
 * by an external mechanism.
 *
 * @discussion
 * This is for manual loops that typically perform erasures.
 *
 * The body of the loop must move the cursor using (once):
 * - smrq_serialized_iter_next() to to go the next element,
 * - smrq_serialized_iter_erase() to erase the current element.
 *
 * The iterator variable will _not_ be updated until the next
 * loop iteration.
 *
 * This form is prefered to smrq_serialized_foreach_safe()
 * for singly linked lists as smrq_serialized_iter_erase()
 * is O(1) as opposed to smrq_serialized_remove().
 */
#define smrq_serialized_iter(it, head, field) \
	for (__smrq_slink_t *__prev_##it = &(head)->first,                      \
	    *__chk_##it = __prev_##it;                                          \
	    ((it) = __container_of_safe(smr_serialized_load(__prev_##it),       \
	    typeof(*(it)), field));                                             \
	    assert(__chk_##it), __chk_##it = __prev_##it)

/*!
 * @macro smrq_serialized_iter_next
 *
 * @brief
 * Goes to the next element inside an smrq_serialied_iter() loop.
 */
#define smrq_serialized_iter_next(it, field)  ({ \
	assert(__chk_##it == __prev_##it);                                      \
	__chk_##it = NULL;                                                      \
	__prev_##it = &(it)->field.next;                                        \
})

/*!
 * @macro smrq_serialized_iter_erase
 *
 * @brief
 * Erases the element pointed at by the cursor.
 */
#define smrq_serialized_iter_erase(it, field)  ({ \
	assert(__chk_##it == __prev_##it);                                      \
	__chk_##it = NULL;                                                      \
	__smrq_serialized_remove_one(__prev_##it, &(it)->field, NULL);          \
})


/*!
 * @macro smrq_serialized_append
 *
 * @brief
 * Appends a given list at the end of the previous one.
 *
 * @discussion
 * /!\ WARNING /!\: this doesn't "move" the "source" queue like *_CONCAT
 * for <sys/queue.h>, as it is useful to merge/split hash queues concurrently
 * with readers while allowing readers to still read via the "source" queue.
 *
 * However, the "source" queue needs to be reset to a valid state
 * if it is to be used again.
 */
#define smrq_serialized_append(dst, src)  ({ \
	__auto_type __src = (src);                                              \
	__auto_type __dst = (dst);                                              \
                                                                                \
	__smrq_serialized_append(&__dst->first, __smrq_lastp(__dst),            \
	    &__src->first, __smrq_lastp(__src));                                \
})


#pragma mark SMR domains

/*!
 * @enum smr_flags_t
 *
 * @brief
 * Options to pass to smr_domain_create()
 *
 * @const SMR_NONE
 * Default values for the flags.
 */
__options_closed_decl(smr_flags_t, unsigned long, {
	SMR_NONE              = 0x00000000,
});

/*!
 * @function smr_domain_create()
 *
 * @brief
 * Create an SMR domain.
 */
extern smr_t smr_domain_create(smr_flags_t flags);

/*!
 * @function smr_domain_free()
 *
 * @brief
 * Destroys an SMR domain previously create with @c smr_domain_create().
 */
extern void smr_domain_free(smr_t smr);


/*!
 * @function smr_entered()
 *
 * @brief
 * Returns whether an SMR critical section is entered.
 */
extern bool smr_entered(smr_t smr) __result_use_check;

/*!
 * @function smr_enter()
 *
 * @brief
 * Enter a non preemptible SMR critical section.
 *
 * @discussion
 * Entering an SMR critical section is non reentrant.
 * (entering it recursively is undefined and will panic on development kernels)
 *
 * @c smr_leave() must be called to end this section.
 */
extern void smr_enter(smr_t smr);

/*!
 * @function smr_leave()
 *
 * @brief
 * Leave a non preemptible SMR critical section.
 */
extern void smr_leave(smr_t smr);


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
extern void smr_synchronize(smr_t smr);


#ifdef XNU_KERNEL_PRIVATE
#pragma GCC visibility push(hidden)
#pragma mark - XNU only
#pragma mark XNU only: SMR domains advanced

#define SMR_SEQ_INVALID         ((smr_seq_t)0)
#define SMR_SEQ_INIT            ((smr_seq_t)1)
#define SMR_SEQ_INC             ((smr_seq_t)2)

typedef long                    smr_delta_t;

#define SMR_SEQ_DELTA(a, b)     ((smr_delta_t)((a) - (b)))
#define SMR_SEQ_CMP(a, op, b)   (SMR_SEQ_DELTA(a, b) op 0)

/*!
 * @typedef smr_clock_t
 *
 * @brief
 * Represents an SMR domain clock, internal type not manipulated by clients.
 */
typedef struct {
	smr_seq_t               s_rd_seq;
	smr_seq_t               s_wr_seq;
} smr_clock_t;

/*!
 * @typedef smr_t
 *
 * @brief
 * Declares an SMR domain of synchronization.
 */
struct smr {
	smr_clock_t             smr_clock;
	struct smr_pcpu        *smr_pcpu;
	unsigned long           smr_flags;
	unsigned long           smr_early;
};

/*!
 * @macro SMR_DEFINE_FLAGS
 *
 * @brief
 * Define an SMR domain with specific create flags.
 */
#define SMR_DEFINE_FLAGS(var, flags) \
	struct smr var = { \
	        .smr_clock.s_rd_seq = SMR_SEQ_INIT, \
	        .smr_clock.s_wr_seq = SMR_SEQ_INIT, \
	        .smr_flags = (flags), \
	}; \
	STARTUP_ARG(TUNABLES, STARTUP_RANK_LAST, __smr_domain_init, &(var)); \
	STARTUP_ARG(ZALLOC, STARTUP_RANK_LAST, __smr_domain_init, &(var))

/*!
 * @macro SMR_DEFINE
 *
 * @brief
 * Define an SMR domain.
 */
#define SMR_DEFINE(var) \
	SMR_DEFINE_FLAGS(var, SMR_NONE)


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
 */
extern smr_seq_t smr_advance(smr_t smr) __result_use_check;

/*!
 * @function smr_deferred_advance()
 *
 * @brief
 * Pretend-advance the write sequence and return the value
 * for use as a wait goal.
 *
 * @discussion
 * This guarantees that any changes made by the calling thread
 * prior to this call will be visible to all threads after
 * the read sequence meets or exceeds the return value.
 *
 * Unlike smr_advance(), the global clock isn't really advanced,
 * it only sets a goal in the future. This can be used to control
 * the pace of updating the global clock and avoid global atomics.
 *
 * In order for the clock to advance, clients of this API must call
 * @c smr_deferred_advance_commit() with the goal returned by this call.
 *
 * Note that calls to @c smr_advance() or @c smr_wait() when passed
 * the goal returned by this function would also allow the clock
 * to make progress and are legal (yet less efficient) calls to make.
 */
extern smr_seq_t smr_deferred_advance(smr_t smr) __result_use_check;

/*!
 * @function smr_deferred_advance_commit()
 *
 * @brief
 * Actually advance the write sequence to the goal returned by a previous
 * call to @c smr_deferred_advance().
 */
extern void smr_deferred_advance_commit(smr_t smr, smr_seq_t seq);


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


#pragma mark XNU only: system global SMR

/*!
 * @brief
 * The SMR domain behind the smr_global_*() KPI.
 *
 * @discussion
 * This is provided as a fallback for when a specific SMR domain
 * would be overkill.
 */
extern struct smr smr_system;

#define smr_global_entered()           smr_entered(&smr_system)
#define smr_global_enter()             smr_enter(&smr_system)
#define smr_global_leave()             smr_leave(&smr_system)

#define smr_global_advance()           smr_advance(&smr_system)
#define smr_global_poll(goal)          smr_poll(&smr_system, goal)
#define smr_global_wait(goal)          smr_wait(&smr_system, goal)
#define smr_global_synchronize()       smr_synchronize(&smr_system)

/*!
 * @function smr_global_retire()
 *
 * @brief
 * Schedule a callback to free some memory once it is safe to collect it.
 *
 * @discussion
 * The default system wide global SMR system provides a way
 * for elements protected by it (using @c smr_global_enter()
 * and @c smr_global_leave() to protect access) to be reclaimed
 * when this is safe to.
 *
 * This function can't be called with preemption disabled as it may block.
 * In particular it can't be called from within an SMR critical section.
 *
 * @param value         the address of the element to reclaim.
 * @param size          an estimate of the size of the memory that will be freed.
 * @param destructor    the callback to run to actually destroy the element.
 */
extern void smr_global_retire(
	void                   *value,
	size_t                  size,
	void                  (*destructor)(void *));


#pragma mark XNU only: implementation details

extern void __smr_domain_init(smr_t);

#ifdef MACH_KERNEL_PRIVATE

extern bool smr_entered_cpu(smr_t smr, int cpu) __result_use_check;

extern void smr_register_mpsc_queue(void);

#endif /* MACH_KERNEL_PRIVATE */

#pragma GCC visibility pop
#endif /* XNU_KERNEL_PRIVATE */
#pragma mark - implementation details
#pragma mark implementation details: SMR queues

extern void __smr_linkage_invalid(__smrq_link_t *link) __abortlike;
extern void __smr_stail_invalid(__smrq_slink_t *link, __smrq_slink_t *last) __abortlike;
extern void __smr_tail_invalid(__smrq_link_t *link, __smrq_link_t *last) __abortlike;

__attribute__((always_inline, overloadable))
static inline __smrq_slink_t **
__smrq_lastp(struct smrq_slist_head *head __unused)
{
	return NULL;
}

__attribute__((always_inline, overloadable))
static inline __smrq_link_t **
__smrq_lastp(struct smrq_list_head *head __unused)
{
	return NULL;
}

__attribute__((always_inline, overloadable))
static inline __smrq_slink_t **
__smrq_lastp(struct smrq_stailq_head *head)
{
	__smrq_slink_t **last = &head->last;

	__builtin_assume(last != NULL);
	return last;
}

__attribute__((always_inline, overloadable))
static inline __smrq_link_t **
__smrq_lastp(struct smrq_tailq_head *head)
{
	__smrq_link_t **last = &head->last;

	__builtin_assume(last != NULL);
	return last;
}


__attribute__((always_inline, overloadable))
static inline void
__smrq_serialized_insert(
	__smrq_slink_t         *prev,
	struct smrq_slink      *elem,
	struct smrq_slink      *next,
	__smrq_slink_t        **lastp)
{
	if (next == NULL && lastp) {
		if (*lastp != prev || smr_serialized_load(prev)) {
			__smr_stail_invalid(prev, *lastp);
		}
	}

	smr_serialized_store_relaxed(&elem->next, next);
	smr_serialized_store(prev, elem);
	if (next == NULL && lastp) {
		*lastp = &elem->next;
	}
}

__attribute__((always_inline, overloadable))
static inline void
__smrq_serialized_insert(
	__smrq_link_t          *prev,
	struct smrq_link       *elem,
	struct smrq_link       *next,
	__smrq_link_t         **lastp)
{
	if (next != NULL && next->prev != prev) {
		__smr_linkage_invalid(prev);
	}
	if (next == NULL && lastp) {
		if (*lastp != prev || smr_serialized_load(prev)) {
			__smr_tail_invalid(prev, *lastp);
		}
	}

	smr_serialized_store_relaxed(&elem->next, next);
	elem->prev = prev;
	smr_serialized_store(prev, elem);

	if (next != NULL) {
		next->prev = &elem->next;
	} else if (lastp) {
		*lastp = &elem->next;
	}
}


__attribute__((always_inline, overloadable))
static inline void
__smrq_serialized_remove_one(
	__smrq_slink_t         *prev,
	struct smrq_slink      *elem,
	__smrq_slink_t        **lastp)
{
	struct smrq_slink *next;

	/*
	 * Removal "skips" a link this way:
	 *
	 *     e1 ---> e2 ---> e3  becomes e1 -----------> e3
	 *
	 * When e3 was inserted, a release barrier was issued
	 * by smr_serialized_store().  We do not need to issue
	 * a release barrier upon removal because `next` carries
	 * a dependency on that smr_serialized_store()d value.
	 */
	next = smr_serialized_load(&elem->next);
	smr_serialized_store_relaxed(prev, next);
	if (next == NULL && lastp) {
		*lastp = prev;
	}
}

__attribute__((always_inline, overloadable))
static inline void
__smrq_serialized_remove_one(
	__smrq_link_t          *prev,
	struct smrq_link       *elem,
	__smrq_link_t         **lastp)
{
	struct smrq_link *next;

	next = smr_serialized_load(&elem->next);

	if (smr_serialized_load(prev) != elem) {
		__smr_linkage_invalid(prev);
	}
	if (next && next->prev != &elem->next) {
		__smr_linkage_invalid(&elem->next);
	}

	/*
	 * Removal "skips" a link this way:
	 *
	 *     e1 ---> e2 ---> e3  becomes e1 -----------> e3
	 *
	 * When e3 was inserted, a release barrier was issued
	 * by smr_serialized_store().  We do not need to issue
	 * a release barrier upon removal because `next` carries
	 * a dependency on that smr_serialized_store()d value.
	 */
	smr_serialized_store_relaxed(prev, next);

	if (next != NULL) {
		next->prev = prev;
	} else if (lastp) {
		*lastp = prev;
	}
	elem->prev = NULL;
}


__attribute__((always_inline, overloadable))
static inline void
__smrq_serialized_remove(
	__smrq_slink_t         *first,
	struct smrq_slink      *elem,
	__smrq_slink_t        **lastp)
{
	__smrq_slink_t *prev = first;
	struct smrq_slink *cur;

	while ((cur = smr_serialized_load(prev)) != elem) {
		prev = &cur->next;
	}

	__smrq_serialized_remove_one(prev, elem, lastp);
}

__attribute__((always_inline, overloadable))
static inline void
__smrq_serialized_remove(
	__smrq_link_t          *first __unused,
	struct smrq_link       *elem,
	__smrq_link_t         **lastp)
{
	__smrq_serialized_remove_one(elem->prev, elem, lastp);
}


__attribute__((always_inline, overloadable))
static inline void
__smrq_serialized_replace(
	__smrq_slink_t         *first,
	struct smrq_slink      *old_elem,
	struct smrq_slink      *new_elem,
	__smrq_slink_t        **lastp)
{
	__smrq_slink_t *prev = first;
	struct smrq_slink *cur;
	struct smrq_slink *next;

	while ((cur = smr_serialized_load(prev)) != old_elem) {
		prev = &cur->next;
	}

	next = smr_serialized_load(&old_elem->next);
	smr_serialized_store_relaxed(&new_elem->next, next);
	smr_serialized_store(prev, new_elem);

	if (next == NULL && lastp) {
		*lastp = &new_elem->next;
	}
}

__attribute__((always_inline, overloadable))
static inline void
__smrq_serialized_replace(
	__smrq_link_t          *first __unused,
	struct smrq_link       *old_elem,
	struct smrq_link       *new_elem,
	__smrq_link_t         **lastp)
{
	__smrq_link_t *prev;
	struct smrq_link *next;

	prev = old_elem->prev;
	next = smr_serialized_load(&old_elem->next);

	if (smr_serialized_load(prev) != old_elem) {
		__smr_linkage_invalid(prev);
	}
	if (next && next->prev != &old_elem->next) {
		__smr_linkage_invalid(&old_elem->next);
	}

	smr_serialized_store_relaxed(&new_elem->next, next);
	new_elem->prev = prev;
	smr_serialized_store(prev, new_elem);

	if (next != NULL) {
		next->prev = &new_elem->next;
	} else if (lastp) {
		*lastp = &new_elem->next;
	}
	old_elem->prev = NULL;
}

__attribute__((always_inline, overloadable))
static inline void
__smrq_serialized_append(
	__smrq_slink_t         *dst_first,
	__smrq_slink_t        **dst_lastp,
	__smrq_slink_t         *src_first,
	__smrq_slink_t        **src_lastp)
{
	struct smrq_slink *src = smr_serialized_load(src_first);
	struct smrq_slink *dst;

	if (dst_lastp) {
		if (src) {
			smr_serialized_store_relaxed(*dst_lastp, src);
			*dst_lastp = *src_lastp;
		}
	} else {
		while ((dst = smr_serialized_load(dst_first))) {
			dst_first = &dst->next;
		}
		smr_serialized_store_relaxed(dst_first, src);
	}
}

__attribute__((always_inline, overloadable))
static inline void
__smrq_serialized_append(
	__smrq_link_t          *dst_first,
	__smrq_link_t         **dst_lastp,
	__smrq_link_t          *src_first,
	__smrq_link_t         **src_lastp)
{
	struct smrq_link *src = smr_serialized_load(src_first);
	struct smrq_link *dst;

	if (dst_lastp) {
		if (src) {
			smr_serialized_store_relaxed(*dst_lastp, src);
			src->prev = *dst_lastp;
			*dst_lastp = *src_lastp;
		}
	} else {
		while ((dst = smr_serialized_load(dst_first))) {
			dst_first = &dst->next;
		}
		smr_serialized_store_relaxed(dst_first, src);
		src->prev = &dst->next;
	}
}

__END_DECLS

#endif /* _KERN_SMR_H_ */
