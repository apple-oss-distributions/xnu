/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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

#ifndef _OS_REFCNT_H_
#define _OS_REFCNT_H_

/*
 * os_refcnt reference counting API
 *
 * Two flavors are provided: atomic and locked. Atomic internally uses C11 atomic
 * operations and requires no external synchronization, whereas the locked flavor
 * assumes the refcnt object is locked by the caller. It is NOT safe to
 * mix-and-match locked and atomic calls.
 *
 * 'refgrp's are a way to (hierarchically) group like refcount objects for
 * debugging purposes. The group keeps track of the total number and aggregate
 * reference count of member refcounts, and the "rlog=" boot-arg is used to enable
 * refcount logging by group name. Named groups can be created explicitly with
 * os_refgrp_decl(), or implicitly by passing NULL for the refgrp when
 * initializing a refcnt object. In the latter case, the group name is the same as
 * the function enclosing the init call. Groups are only available on DEV or DEBUG
 * builds, and are otherwise compiled out.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <os/base.h>

struct os_refcnt;
struct os_refgrp;
typedef struct os_refcnt os_refcnt_t;

/* type of the internal counter */
typedef uint32_t os_ref_count_t;
typedef _Atomic(os_ref_count_t) os_ref_atomic_t;

/*
 * OS_REF_INITIALIZER
 * OS_REF_ATOMIC_INITIALIZER
 *
 * Static initializers that create refcnt objects with safe initial values for use
 * between declaration and initialization (os_ref*_init()). Equivalent to zeroing.
 */

#ifndef KERNEL
# include <stdlib.h>
# include <stdio.h>
# ifndef __improbable
#  define __improbable(x) x
# endif
# ifndef panic
#  define panic(x, ...) do { fprintf(stderr, x, __VA_ARGS__); abort(); } while (0)
# endif
#endif

#ifndef OS_REFCNT_DEBUG
# if DEVELOPMENT || DEBUG
#  define OS_REFCNT_DEBUG 1
# else
#  define OS_REFCNT_DEBUG 0
# endif
#endif

#if __has_attribute(diagnose_if)
# define os_error_if(cond, msg) __attribute__((diagnose_if((cond), (msg), "error")))
#else
# define os_error_if(...)
#endif

__BEGIN_DECLS

/*
 * os_ref_init: initialize an os_refcnt with a count of 1
 * os_ref_init_count: initialize an os_refcnt with a specific count >= 1
 */
#define os_ref_init(rc, grp) os_ref_init_count((rc), (grp), 1)
static void os_ref_init_count(struct os_refcnt *, struct os_refgrp *, os_ref_count_t count)
os_error_if(count == 0, "Reference count must be non-zero initialized");

/*
 * os_refgrp_decl(qual, var, name, parent): declare a refgroup object 'var' with
 *   given name string and parent group.
 */

/*
 *
 * os_ref_retain: acquire a reference (increment reference count by 1) atomically.
 *
 * os_ref_release: release a reference (decrement reference count) atomically and
 *		return the new count. Memory is synchronized such that the dealloc block
 *		(i.e. code handling the final release() == 0 call) sees up-to-date memory
 *		with respect to all prior release()s on the same refcnt object. This
 *		memory ordering is sufficient for most use cases.
 *
 * os_ref_release_relaxed: same as release() but with weaker relaxed memory ordering.
 *		This can be used when the dealloc block is already synchronized with other
 *		accesses to the object (for example, with a lock).
 *
 * os_ref_release_live: release a reference that is guaranteed not to be the last one.
 */
static void os_ref_retain(struct os_refcnt *);
static os_ref_count_t os_ref_release(struct os_refcnt *) OS_WARN_RESULT;
static os_ref_count_t os_ref_release_relaxed(struct os_refcnt *) OS_WARN_RESULT;
static void os_ref_release_live(struct os_refcnt *);

/*
 * os_ref_retain_try: a variant of atomic retain that fails for objects with a
 *		zero reference count. The caller must therefore ensure that the object
 *		remains alive for any possible retain_try() caller, usually by using a
 *		lock protecting both the retain and dealloc paths. This variant is useful
 *		for objects stored in a collection, because no lock is required on the
 *		release() side until the object is deallocated.
 */
static bool os_ref_retain_try(struct os_refcnt *) OS_WARN_RESULT;

/*
 * os_ref_retain_locked: acquire a reference on an object protected by a held
 *		lock. The caller must ensure mutual exclusivity of retain_locked() and
 *		release_locked() calls on the same object.
 *
 * os_ref_release_locked: release a reference on an object protected by a held
 *		lock.
 */
static void os_ref_retain_locked(struct os_refcnt *);
static os_ref_count_t os_ref_release_locked(struct os_refcnt *) OS_WARN_RESULT;

/*
 * os_ref_get_count: return the current reference count. This is unsafe for
 *		synchronization.
 */
static os_ref_count_t os_ref_get_count(struct os_refcnt *rc);


/*!
 * @brief
 * Type for scalable percpu refcounts.
 *
 * @discussion
 * percpu refcounts are scalable refcounts that do not contend on retain/release
 * but require O(ncpu) storage.
 *
 * They also require to be explicitly "killed" with @c os_pcpu_ref_kill() before
 * the "last reference" detection logic kicks in, in which case the refcount
 * decays to a regular (contending) atomic refcount.
 *
 * This type of refcount is typically useful for objects that are in low
 * numbers, but are accessed frequently and must be protected against deletion,
 * when options like SMR critical sections can't be used.
 */
typedef uintptr_t os_pcpu_ref_t;

/*!
 * @brief
 * Initializes a scalable refcount.
 *
 * @discussion
 * The refcount is initialized with the value "1" and marked "live".
 *
 * This reference is supposed to be dropped with @c os_pcpu_ref_kill(),
 * which will mark it as "dead", which is required for os_pcpu_ref_release()
 * to become precise.
 *
 * The refcount must be destroyed with @c os_pcpu_ref_destroy() once
 * @c os_pcpu_ref_release() returns 0.
 */
extern void os_pcpu_ref_init(os_pcpu_ref_t *ref, struct os_refgrp *grp);

/*!
 * @brief
 * "Kill" the initial reference of a percpu refcount.
 *
 * @discussion
 * This drops the "creation" reference of the refcount made by
 * @c os_pcpu_ref_init().
 *
 * Once a percpu refcount is "killed" it becomes a regular atomic refcount
 * in order to do precise detection of the last reference drop.
 *
 * This returns the resulting refcount value, like @c os_pcpu_ref_release() does.
 */
extern os_ref_count_t os_pcpu_ref_kill(os_pcpu_ref_t ref, struct os_refgrp *grp) __result_use_check;

/*!
 * @brief
 * Wait for a killed refcount to hit 0.
 *
 * @discussion
 * Waiting for object death must happen after the refcount has been "killed".
 *
 * There can only be at most a single waiter, given that it is expected that
 * waiter will free resources, and having two waiters would cause use-after-free
 * accesses.
 *
 * Having two waiters, or waiting on a live refcount will result into
 * a kernel panic.
 */
extern void os_pcpu_ref_wait_for_death(os_pcpu_ref_t ref);

/*!
 * @brief
 * Destroy a scalable refcount once it has been killed and reached 0.
 *
 * @discussion
 * This must be called to destroy a scalable refcount.
 *
 * It is legal to release a scalable refcount when:
 * - @c os_pcpu_ref_kill() was called and returned 0;
 * - @c os_pcpu_ref_kill() was called and @c os_pcpu_ref_release() returned 0;
 * - the refcount was initialized with @c os_pcpu_ref_init() and never used nor
 *   killed.
 */
extern void os_pcpu_ref_destroy(os_pcpu_ref_t *ref, struct os_refgrp *grp);

/*!
 * @brief
 * Returns the value of the refcount.
 *
 * @discussion
 * If the refcount is still live (hasn't been killed yet),
 * then this function returns a "very large" value.
 */
extern os_ref_count_t os_pcpu_ref_count(os_pcpu_ref_t ref);

/*!
 * @brief
 * Acquires a +1 reference on the specified percpu refcount.
 */
extern void os_pcpu_ref_retain(os_pcpu_ref_t ref, struct os_refgrp *grp);

/*!
 * @brief
 * Tries to acquire a +1 reference on the specified percpu refcount.
 *
 * @discussion
 * Unlike a typical refcount, this function will fail as soon as
 * @c os_pcpu_ref_kill() has been called, rather than because
 * the refcount hit 0.
 */
extern bool os_pcpu_ref_retain_try(os_pcpu_ref_t ref, struct os_refgrp *grp) __result_use_check;

/*!
 * @brief
 * Release an acquired reference, knowing it is not the last one.
 */
extern void os_pcpu_ref_release_live(os_pcpu_ref_t ref, struct os_refgrp *grp);

/*!
 * @brief
 * Release an acquired reference.
 *
 * @discussion
 * If the refcount is "live" the returned value will be a "very large number"
 * that isn't really accurate.
 *
 * Once the refcount has been "killed" then this returns an accurate view of the
 * refcount.
 */
extern os_ref_count_t os_pcpu_ref_release(os_pcpu_ref_t ref, struct os_refgrp *grp) __result_use_check;


#if XNU_KERNEL_PRIVATE
#pragma GCC visibility push(hidden)

/*
 * Raw API that uses a plain atomic counter (os_ref_atomic_t) and a separate
 * refgroup. This can be used in situations where the refcount object must be
 * fixed size, for example for embedding in structures with ABI stability
 * requirements.
 */

#define os_ref_init_raw(rc, grp) os_ref_init_count_raw((rc), (grp), 1)
static void os_ref_init_count_raw(os_ref_atomic_t *, struct os_refgrp *, os_ref_count_t count)
os_error_if(count == 0, "Reference count must be non-zero initialized");
static void os_ref_retain_floor(struct os_refcnt *, os_ref_count_t f)
os_error_if(!__builtin_constant_p(f) || f == 0, "refcount floor must be >= 1");
static void os_ref_retain_raw(os_ref_atomic_t *, struct os_refgrp *);
static void os_ref_retain_floor_raw(os_ref_atomic_t *, os_ref_count_t f, struct os_refgrp *)
os_error_if(!__builtin_constant_p(f) || f == 0, "refcount floor must be >= 1");
static os_ref_count_t os_ref_release_raw(os_ref_atomic_t *, struct os_refgrp *) OS_WARN_RESULT;
static os_ref_count_t os_ref_release_raw_relaxed(os_ref_atomic_t *, struct os_refgrp *) OS_WARN_RESULT;
static void os_ref_release_live_raw(os_ref_atomic_t *, struct os_refgrp *);
static bool os_ref_retain_try_raw(os_ref_atomic_t *, struct os_refgrp *) OS_WARN_RESULT;
static bool os_ref_retain_floor_try_raw(os_ref_atomic_t *, os_ref_count_t f, struct os_refgrp *) OS_WARN_RESULT
    os_error_if(!__builtin_constant_p(f) || f == 0, "refcount floor must be >= 1");
static void os_ref_retain_locked_raw(os_ref_atomic_t *, struct os_refgrp *);
static void os_ref_retain_floor_locked_raw(os_ref_atomic_t *, os_ref_count_t f, struct os_refgrp *)
os_error_if(!__builtin_constant_p(f) || f == 0, "refcount floor must be >= 1");
static os_ref_count_t os_ref_release_locked_raw(os_ref_atomic_t *, struct os_refgrp *) OS_WARN_RESULT;
static os_ref_count_t os_ref_get_count_raw(os_ref_atomic_t *rc);


/*
 * Bitwise API: like the raw API, but allows some bits in the refcount value to be
 * reserved for other purposes. 'b' defines the number of trailing (LSB) reserved
 * bits, which the refcnt_raw API will never modify (except at init()).
 *
 * It is assumed that users of this API always use atomic ops on the
 * os_ref_atomic_t (or hold a lock for the locked variants), and never modify the
 * top (32 - 'b') bits.
 *
 * Due to guard bits, the maximum reference count is 2^(28 - 'b') - 1, and the
 * maximum 'b' is 26 bits. This API can also be used just to limit the max
 * refcount.
 *
 * The "*_raw_mask" APIs return the raw bit pattern of the refcount (with a type
 * of uint32_t), that the caller is supposed to decode. Other APIs that return
 * os_ref_count_t return a normalized refcount where the trailing bits have been
 * removed.
 *
 * "locked" variants aren't provided as the point of these interfaces
 * is to combine flags into a refcount and be able to manipulate both
 * atomically with respect to each other.
 */

/* Initialize the reference count and reserved bits */
#define os_ref_init_mask(rc, b, grp, bits) os_ref_init_count_mask((rc), (b), (grp), 1, bits)
void os_ref_init_count_mask(os_ref_atomic_t *rc, uint32_t b, struct os_refgrp *grp,
    os_ref_count_t init_count, uint32_t init_bits)
os_error_if(init_count == 0, "Reference count must be non-zero initialized")
os_error_if(b > 26, "Bitwise reference count limited to 26 bits")
os_error_if(init_bits >= (1U << b), "Bits out of range");

static uint32_t os_ref_get_raw_mask(os_ref_atomic_t *rc);
static uint32_t os_ref_get_bits_mask(os_ref_atomic_t *rc, uint32_t b);
static os_ref_count_t os_ref_get_count_mask(os_ref_atomic_t *rc, uint32_t b);

static void
os_ref_retain_mask(os_ref_atomic_t *rc, uint32_t b, struct os_refgrp *grp);
static void
os_ref_retain_acquire_mask(os_ref_atomic_t *rc, uint32_t b, struct os_refgrp *grp);
static uint32_t
os_ref_retain_try_mask(os_ref_atomic_t *, uint32_t b, uint32_t reject_mask,
    struct os_refgrp *grp) OS_WARN_RESULT;
static bool
os_ref_retain_try_acquire_mask(os_ref_atomic_t *, uint32_t b, uint32_t reject_mask,
    struct os_refgrp *grp) OS_WARN_RESULT;

static uint32_t
os_ref_release_raw_mask(os_ref_atomic_t *rc, uint32_t b, struct os_refgrp *grp) OS_WARN_RESULT;
static uint32_t
os_ref_release_raw_relaxed_mask(os_ref_atomic_t *rc, uint32_t b, struct os_refgrp *grp) OS_WARN_RESULT;
static os_ref_count_t
os_ref_release_mask(os_ref_atomic_t *rc, uint32_t b, struct os_refgrp *grp) OS_WARN_RESULT;
static os_ref_count_t
os_ref_release_relaxed_mask(os_ref_atomic_t *rc, uint32_t b, struct os_refgrp *grp) OS_WARN_RESULT;
static uint32_t
os_ref_release_live_raw_mask(os_ref_atomic_t *rc, uint32_t b, struct os_refgrp *grp);
static void
os_ref_release_live_mask(os_ref_atomic_t *rc, uint32_t b, struct os_refgrp *grp);

#pragma GCC visibility pop
#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#include <os/refcnt_internal.h>
#endif
