#if KERNEL
#include <kern/assert.h>
#include <kern/debug.h>
#include <pexpert/pexpert.h>
#include <kern/btlog.h>
#include <kern/backtrace.h>
#include <kern/zalloc.h>
#include <kern/sched_prim.h>
#include <libkern/libkern.h>
#endif
#include <os/overflow.h>
#include <os/atomic_private.h>

#include "refcnt.h"

#define OS_REFCNT_MAX_COUNT     ((os_ref_count_t)0x0FFFFFFFUL)

#if OS_REFCNT_DEBUG
extern struct os_refgrp global_ref_group;
os_refgrp_decl(, global_ref_group, "all", NULL);

extern bool ref_debug_enable;
bool ref_debug_enable = false;

#define REFLOG_GRP_DEBUG_ENABLED(grp) \
    __improbable(grp != NULL && (ref_debug_enable || \
	(grp->grp_flags & OS_REFGRP_F_ALWAYS_ENABLED) != 0))

static const size_t ref_log_nrecords = 1000000;

__enum_closed_decl(reflog_op_t, uint8_t, {
	REFLOG_RETAIN  = 1,
	REFLOG_RELEASE = 2
});

# define __debug_only
# define __os_refgrp_arg(arg)   , arg
#else
# define __debug_only __unused
# define __os_refgrp_arg(arg)
#endif /* OS_REFCNT_DEBUG */

void
os_ref_panic_live(void *rc)
{
	panic("os_refcnt: unexpected release of final reference (rc=%p)", rc);
	__builtin_unreachable();
}
void
os_ref_panic_last(void *rc)
{
	panic("os_refcnt: expected release of final reference but rc %p!=0\n", rc);
	__builtin_unreachable();
}

__abortlike
static void
os_ref_panic_underflow(void *rc)
{
	panic("os_refcnt: underflow (rc=%p)", rc);
	__builtin_unreachable();
}

__abortlike
static void
os_ref_panic_overflow(void *rc)
{
	panic("os_refcnt: overflow (rc=%p)", rc);
	__builtin_unreachable();
}

__abortlike
static void
os_ref_panic_retain(os_ref_atomic_t *rc)
{
	if (os_atomic_load(rc, relaxed) >= OS_REFCNT_MAX_COUNT) {
		panic("os_refcnt: overflow (rc=%p)", rc);
	} else {
		panic("os_refcnt: attempted resurrection (rc=%p)", rc);
	}
}

static inline void
os_ref_check_underflow(void *rc, os_ref_count_t count, os_ref_count_t n)
{
	if (__improbable(count < n)) {
		os_ref_panic_underflow(rc);
	}
}

static inline void
os_ref_check_overflow(os_ref_atomic_t *rc, os_ref_count_t count)
{
	if (__improbable(count >= OS_REFCNT_MAX_COUNT)) {
		os_ref_panic_overflow(rc);
	}
}

static inline void
os_ref_check_retain(os_ref_atomic_t *rc, os_ref_count_t count, os_ref_count_t n)
{
	if (__improbable(count < n || count >= OS_REFCNT_MAX_COUNT)) {
		os_ref_panic_retain(rc);
	}
}

#if OS_REFCNT_DEBUG
#if KERNEL
__attribute__((cold, noinline))
static void
ref_log_op(struct os_refgrp *grp, void *elem, reflog_op_t op)
{
	if (grp == NULL) {
		return;
	}

	if (grp->grp_log == NULL) {
		ref_log_op(grp->grp_parent, elem, op);
		return;
	}

	btlog_record((btlog_t)grp->grp_log, elem, op,
	    btref_get(__builtin_frame_address(0), BTREF_GET_NOWAIT));
}

__attribute__((cold, noinline))
static void
ref_log_drop(struct os_refgrp *grp, void *elem)
{
	if (!REFLOG_GRP_DEBUG_ENABLED(grp)) {
		return;
	}

	if (grp->grp_log == NULL) {
		ref_log_drop(grp->grp_parent, elem);
		return;
	}

	btlog_erase(grp->grp_log, elem);
}

__attribute__((cold, noinline))
void
os_ref_log_init(struct os_refgrp *grp)
{
	if (grp->grp_log != NULL) {
		return;
	}

	char grpbuf[128];
	char *refgrp = grpbuf;
	if (!PE_parse_boot_argn("rlog", refgrp, sizeof(grpbuf))) {
		return;
	}

	/*
	 * Enable refcount statistics if the rlog boot-arg is present,
	 * even when no specific group is logged.
	 */
	ref_debug_enable = true;

	const char *g;
	while ((g = strsep(&refgrp, ",")) != NULL) {
		if (strcmp(g, grp->grp_name) == 0) {
			/* enable logging on this refgrp */
			grp->grp_log = btlog_create(BTLOG_HASH,
			    ref_log_nrecords, 0);
			return;
		}
	}
}


__attribute__((cold, noinline))
void
os_ref_log_fini(struct os_refgrp *grp)
{
	if (grp->grp_log == NULL) {
		return;
	}

	btlog_destroy(grp->grp_log);
	grp->grp_log = NULL;
}

#else

#ifndef os_ref_log_fini
inline void
os_ref_log_fini(struct os_refgrp *grp __unused)
{
}
#endif

#ifndef os_ref_log_init
inline void
os_ref_log_init(struct os_refgrp *grp __unused)
{
}
#endif
#ifndef ref_log_op
static inline void
ref_log_op(struct os_refgrp *grp __unused, void *rc __unused, reflog_op_t op __unused)
{
}
#endif
#ifndef ref_log_drop
static inline void
ref_log_drop(struct os_refgrp *grp __unused, void *rc __unused)
{
}
#endif

#endif /* KERNEL */

/*
 * attach a new refcnt to a group
 */
__attribute__((cold, noinline))
static void
ref_attach_to_group(os_ref_atomic_t *rc, struct os_refgrp *grp, os_ref_count_t init_count)
{
	if (grp == NULL) {
		return;
	}

	if (atomic_fetch_add_explicit(&grp->grp_children, 1, memory_order_relaxed) == 0) {
		/* First reference count object in this group. Check if we should enable
		 * refcount logging. */
		os_ref_log_init(grp);
	}

	atomic_fetch_add_explicit(&grp->grp_count, init_count, memory_order_relaxed);
	atomic_fetch_add_explicit(&grp->grp_retain_total, init_count, memory_order_relaxed);

	if (grp == &global_ref_group) {
		return;
	}

	if (grp->grp_parent == NULL) {
		grp->grp_parent = &global_ref_group;
	}

	ref_attach_to_group(rc, grp->grp_parent, init_count);
}

static void
ref_retain_group(struct os_refgrp *grp)
{
	if (grp) {
		atomic_fetch_add_explicit(&grp->grp_count, 1, memory_order_relaxed);
		atomic_fetch_add_explicit(&grp->grp_retain_total, 1, memory_order_relaxed);
		ref_retain_group(grp->grp_parent);
	}
}

__attribute__((cold, noinline))
static void
ref_release_group(struct os_refgrp *grp)
{
	if (grp) {
		atomic_fetch_sub_explicit(&grp->grp_count, 1, memory_order_relaxed);
		atomic_fetch_add_explicit(&grp->grp_release_total, 1, memory_order_relaxed);

		ref_release_group(grp->grp_parent);
	}
}

__attribute__((cold, noinline))
static void
ref_drop_group(struct os_refgrp *grp)
{
	if (grp) {
		atomic_fetch_sub_explicit(&grp->grp_children, 1, memory_order_relaxed);
		ref_drop_group(grp->grp_parent);
	}
}

__attribute__((cold, noinline))
static void
ref_init_debug(void *rc, struct os_refgrp *grp, os_ref_count_t count)
{
	ref_attach_to_group(rc, grp, count);

	for (os_ref_count_t i = 0; i < count; i++) {
		ref_log_op(grp, rc, REFLOG_RETAIN);
	}
}

__attribute__((cold, noinline))
static void
ref_retain_debug(void *rc, struct os_refgrp * __debug_only grp)
{
	ref_retain_group(grp);
	ref_log_op(grp, rc, REFLOG_RETAIN);
}

__attribute__((cold, noinline))
static void
ref_release_debug(void *rc, struct os_refgrp * __debug_only grp)
{
	ref_log_op(grp, rc, REFLOG_RELEASE);
	ref_release_group(grp);
}

__attribute__((cold, noinline))
static os_ref_count_t
ref_drop_debug(void *rc, struct os_refgrp * __debug_only grp)
{
	ref_log_drop(grp, rc);
	ref_drop_group(grp);
	return 0;
}
#endif

void
os_ref_init_count_internal(os_ref_atomic_t *rc, struct os_refgrp * __debug_only grp, os_ref_count_t count)
{
	os_ref_check_underflow(rc, count, 1);
	atomic_init(rc, count);

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_init_debug(rc, grp, count);
	}
#endif
}

static inline void
__os_ref_retain(os_ref_atomic_t *rc, os_ref_count_t f,
    struct os_refgrp * __debug_only grp)
{
	os_ref_count_t old = atomic_fetch_add_explicit(rc, 1, memory_order_relaxed);
	os_ref_check_retain(rc, old, f);

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_retain_debug(rc, grp);
	}
#endif
}

void
os_ref_retain_internal(os_ref_atomic_t *rc, struct os_refgrp *grp)
{
	__os_ref_retain(rc, 1, grp);
}

void
os_ref_retain_floor_internal(os_ref_atomic_t *rc, os_ref_count_t f,
    struct os_refgrp *grp)
{
	__os_ref_retain(rc, f, grp);
}

static inline bool
__os_ref_retain_try(os_ref_atomic_t *rc, os_ref_count_t f,
    struct os_refgrp * __debug_only grp)
{
	os_ref_count_t cur, next;

	os_atomic_rmw_loop(rc, cur, next, relaxed, {
		if (__improbable(cur < f)) {
		        os_atomic_rmw_loop_give_up(return false);
		}

		next = cur + 1;
	});

	os_ref_check_overflow(rc, cur);

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_retain_debug(rc, grp);
	}
#endif

	return true;
}

bool
os_ref_retain_try_internal(os_ref_atomic_t *rc, struct os_refgrp *grp)
{
	return __os_ref_retain_try(rc, 1, grp);
}

bool
os_ref_retain_floor_try_internal(os_ref_atomic_t *rc, os_ref_count_t f,
    struct os_refgrp *grp)
{
	return __os_ref_retain_try(rc, f, grp);
}

__attribute__((always_inline))
static inline os_ref_count_t
_os_ref_release_inline(os_ref_atomic_t *rc, os_ref_count_t n,
    struct os_refgrp * __debug_only grp,
    memory_order release_order, memory_order dealloc_order)
{
	os_ref_count_t val;

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		/*
		 * Care not to use 'rc' after the decrement because it might be deallocated
		 * under us.
		 */
		ref_release_debug(rc, grp);
	}
#endif

	val = atomic_fetch_sub_explicit(rc, n, release_order);
	os_ref_check_underflow(rc, val, n);
	val -= n;
	if (__improbable(val < n)) {
		atomic_load_explicit(rc, dealloc_order);
	}

#if OS_REFCNT_DEBUG
	/*
	 * The only way to safely access the ref count or group after
	 * decrementing the count is when the count is zero (as the caller won't
	 * see the zero until the function returns).
	 */
	if (val == 0 && REFLOG_GRP_DEBUG_ENABLED(grp)) {
		return ref_drop_debug(rc, grp);
	}
#endif

	return val;
}

#if OS_REFCNT_DEBUG
__attribute__((noinline))
static os_ref_count_t
os_ref_release_n_internal(os_ref_atomic_t *rc, os_ref_count_t n,
    struct os_refgrp * __debug_only grp,
    memory_order release_order, memory_order dealloc_order)
{
	// Legacy exported interface with bad codegen due to the barriers
	// not being immediate
	//
	// Also serves as the debug function
	return _os_ref_release_inline(rc, n, grp, release_order, dealloc_order);
}
#endif

__attribute__((noinline))
os_ref_count_t
os_ref_release_internal(os_ref_atomic_t *rc, struct os_refgrp * __debug_only grp,
    memory_order release_order, memory_order dealloc_order)
{
	// Legacy exported interface with bad codegen due to the barriers
	// not being immediate
	//
	// Also serves as the debug function
	return _os_ref_release_inline(rc, 1, grp, release_order, dealloc_order);
}

os_ref_count_t
os_ref_release_barrier_internal(os_ref_atomic_t *rc,
    struct os_refgrp * __debug_only grp)
{
#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		return os_ref_release_internal(rc, grp,
		           memory_order_release, memory_order_acquire);
	}
#endif
	return _os_ref_release_inline(rc, 1, NULL,
	           memory_order_release, memory_order_acquire);
}

os_ref_count_t
os_ref_release_relaxed_internal(os_ref_atomic_t *rc,
    struct os_refgrp * __debug_only grp)
{
#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		return os_ref_release_internal(rc, grp,
		           memory_order_relaxed, memory_order_relaxed);
	}
#endif
	return _os_ref_release_inline(rc, 1, NULL,
	           memory_order_relaxed, memory_order_relaxed);
}

static inline void
__os_ref_retain_locked(os_ref_atomic_t *rc, os_ref_count_t f,
    struct os_refgrp * __debug_only grp)
{
	os_ref_count_t val = os_ref_get_count_internal(rc);
	os_ref_check_retain(rc, val, f);
	atomic_store_explicit(rc, ++val, memory_order_relaxed);

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_retain_debug(rc, grp);
	}
#endif
}

void
os_ref_retain_locked_internal(os_ref_atomic_t *rc, struct os_refgrp *grp)
{
	__os_ref_retain_locked(rc, 1, grp);
}

void
os_ref_retain_floor_locked_internal(os_ref_atomic_t *rc, os_ref_count_t f,
    struct os_refgrp *grp)
{
	__os_ref_retain_locked(rc, f, grp);
}

os_ref_count_t
os_ref_release_locked_internal(os_ref_atomic_t *rc, struct os_refgrp * __debug_only grp)
{
#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_release_debug(rc, grp);
	}
#endif

	os_ref_count_t val = os_ref_get_count_internal(rc);
	os_ref_check_underflow(rc, val, 1);
	atomic_store_explicit(rc, --val, memory_order_relaxed);

#if OS_REFCNT_DEBUG
	if (val == 0 && REFLOG_GRP_DEBUG_ENABLED(grp)) {
		return ref_drop_debug(rc, grp);
	}
#endif

	return val;
}

/*
 * Bitwise API
 */

#undef os_ref_init_count_mask
void
os_ref_init_count_mask(os_ref_atomic_t *rc, uint32_t b,
    struct os_refgrp *__debug_only grp,
    os_ref_count_t init_count, uint32_t init_bits)
{
	assert(init_bits < (1U << b));
	atomic_init(rc, (init_count << b) | init_bits);
	os_ref_check_underflow(rc, (init_count << b), 1u << b);

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_init_debug(rc, grp, init_count);
	}
#endif
}

__attribute__((always_inline))
static inline void
os_ref_retain_mask_inline(os_ref_atomic_t *rc, uint32_t n,
    struct os_refgrp *__debug_only grp, memory_order mo)
{
	os_ref_count_t old = atomic_fetch_add_explicit(rc, n, mo);
	os_ref_check_retain(rc, old, n);

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_retain_debug(rc, grp);
	}
#endif
}

void
os_ref_retain_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    struct os_refgrp *__debug_only grp)
{
	os_ref_retain_mask_inline(rc, n, grp, memory_order_relaxed);
}

void
os_ref_retain_acquire_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    struct os_refgrp *__debug_only grp)
{
	os_ref_retain_mask_inline(rc, n, grp, memory_order_acquire);
}

uint32_t
os_ref_release_barrier_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    struct os_refgrp *__debug_only grp)
{
#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		return os_ref_release_n_internal(rc, n, grp,
		           memory_order_release, memory_order_acquire);
	}
#endif

	return _os_ref_release_inline(rc, n, NULL,
	           memory_order_release, memory_order_acquire);
}

uint32_t
os_ref_release_relaxed_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    struct os_refgrp *__debug_only grp)
{
#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		return os_ref_release_n_internal(rc, n, grp,
		           memory_order_relaxed, memory_order_relaxed);
	}
#endif

	return _os_ref_release_inline(rc, n, NULL,
	           memory_order_relaxed, memory_order_relaxed);
}

uint32_t
os_ref_retain_try_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    uint32_t reject_mask, struct os_refgrp *__debug_only grp)
{
	os_ref_count_t cur, next;

	os_atomic_rmw_loop(rc, cur, next, relaxed, {
		if (__improbable(cur < n || (cur & reject_mask))) {
		        os_atomic_rmw_loop_give_up(return 0);
		}
		next = cur + n;
	});

	os_ref_check_overflow(rc, cur);

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_retain_debug(rc, grp);
	}
#endif

	return next;
}

bool
os_ref_retain_try_acquire_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    uint32_t reject_mask, struct os_refgrp *__debug_only grp)
{
	os_ref_count_t cur, next;

	os_atomic_rmw_loop(rc, cur, next, acquire, {
		if (__improbable(cur < n || (cur & reject_mask))) {
		        os_atomic_rmw_loop_give_up(return false);
		}
		next = cur + n;
	});

	os_ref_check_overflow(rc, cur);

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_retain_debug(rc, grp);
	}
#endif

	return true;
}

#pragma mark os_pcpu

#define OS_PCPU_REF_LIVE        1ull
#define OS_PCPU_REF_WAITER      2ull
#define OS_PCPU_REF_INC         4ull

typedef uint64_t _Atomic *__zpercpu     __os_pcpu_ref_t;

static inline __os_pcpu_ref_t
os_pcpu_get(os_pcpu_ref_t ref)
{
	return (__os_pcpu_ref_t)ref;
}

static inline uint64_t
os_pcpu_count_to_value(os_ref_count_t cnt)
{
	return cnt * OS_PCPU_REF_INC;
}

static inline os_ref_count_t
os_pcpu_value_to_count(uint64_t v)
{
	return (os_ref_count_t)(v / OS_PCPU_REF_INC);
}

__abortlike
static void
__os_pcpu_ref_destroy_panic(os_pcpu_ref_t *ref, uint64_t n)
{
	if (n & OS_PCPU_REF_LIVE) {
		panic("os_pcpu_ref: destroying live refcount %p at %p",
		    os_pcpu_get(*ref), ref);
	}
	if (n & OS_PCPU_REF_WAITER) {
		panic("os_pcpu_ref: destroying refcount %p with a waiter at %p",
		    os_pcpu_get(*ref), ref);
	}
	panic("os_pcpu_ref: destroying non-zero refcount %p at %p",
	    os_pcpu_get(*ref), ref);
}

__abortlike
static void
__os_pcpu_ref_overflow_panic(__os_pcpu_ref_t rc)
{
	panic("os_pcpu_ref: overflow (rc=%p)", rc);
}

__abortlike
static void
__os_pcpu_ref_retain_panic(__os_pcpu_ref_t rc, uint64_t v)
{
	if (v == 0) {
		panic("os_pcpu_ref: attempted resurrection (rc=%p)", rc);
	} else {
		__os_pcpu_ref_overflow_panic(rc);
	}
}

__abortlike
static void
__os_pcpu_ref_release_live_panic(__os_pcpu_ref_t rc)
{
	panic("os_pcpu_ref: unexpected release of final reference (rc=%p)", rc);
}

__abortlike
static void
__os_pcpu_ref_release_panic(__os_pcpu_ref_t rc)
{
	panic("os_pcpu_ref: over-release (rc=%p)", rc);
}

__abortlike
static void
__os_pcpu_ref_kill_panic(__os_pcpu_ref_t rc)
{
	panic("os_pcpu_ref: double-kill (rc=%p)", rc);
}

__abortlike
static void
__os_pcpu_ref_invalid_wait_panic(__os_pcpu_ref_t rc, uint64_t ov)
{
	if (ov & OS_PCPU_REF_WAITER) {
		panic("os_pcpu_ref: double-wait (rc=%p)", rc);
	} else {
		panic("os_pcpu_ref: wait while still live (rc=%p)", rc);
	}
}

void
(os_pcpu_ref_init)(os_pcpu_ref_t * ref, struct os_refgrp *__debug_only grp)
{
	__os_pcpu_ref_t rc;

	rc = zalloc_percpu(percpu_u64_zone, Z_WAITOK | Z_NOFAIL);
	zpercpu_foreach_cpu(cpu) {
		os_atomic_init(zpercpu_get_cpu(rc, cpu),
		    OS_PCPU_REF_LIVE + (cpu ? 0 : OS_PCPU_REF_INC));
	}

	*ref = (os_pcpu_ref_t)rc;
#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_retain_debug(rc, grp);
	}
#endif
}

void
(os_pcpu_ref_destroy)(os_pcpu_ref_t * ref, struct os_refgrp *__debug_only grp)
{
	__os_pcpu_ref_t rc = os_pcpu_get(*ref);
	uint64_t n = 0;

	n = os_atomic_load_wide(zpercpu_get_cpu(rc, 0), relaxed);
	if (n & OS_PCPU_REF_LIVE) {
		n = os_pcpu_ref_kill(*ref, grp);
	} else {
		for (int cpu = zpercpu_count(); cpu-- > 1;) {
			n |= os_atomic_load_wide(zpercpu_get_cpu(rc, cpu), relaxed);
		}
	}
	if (n) {
		__os_pcpu_ref_destroy_panic(ref, n);
	}

	*ref = 0;
	zfree_percpu(percpu_u64_zone, rc);
}

os_ref_count_t
os_pcpu_ref_count(os_pcpu_ref_t ref)
{
	uint64_t v;

	v = os_atomic_load_wide(zpercpu_get_cpu(os_pcpu_get(ref), 0), relaxed);
	if (v & OS_PCPU_REF_LIVE) {
		return OS_REFCNT_MAX_COUNT;
	}
	return os_pcpu_value_to_count(v);
}

static inline uint64_t
__os_pcpu_ref_delta(__os_pcpu_ref_t rc, int delta, int *cpup)
{
	_Atomic uint64_t *rcp;
	uint64_t v;
	int cpu;

	cpu  = cpu_number();
	rcp  = zpercpu_get_cpu(rc, cpu);
	v    = os_atomic_load_wide(rcp, relaxed);
	if (__improbable((v & OS_PCPU_REF_LIVE) == 0)) {
		*cpup = -1;
		return v;
	}

	*cpup = cpu;
	if (delta > 0) {
		return os_atomic_add_orig(rcp, OS_PCPU_REF_INC, relaxed);
	} else {
		return os_atomic_sub_orig(rcp, OS_PCPU_REF_INC, release);
	}
}

__attribute__((noinline))
static void
__os_pcpu_ref_retain_slow(__os_pcpu_ref_t rc, int cpu, uint64_t v)
{
	if (cpu > 0) {
		os_atomic_sub(zpercpu_get_cpu(rc, cpu),
		    OS_PCPU_REF_INC, relaxed);
	}

	if (cpu != 0) {
		v = os_atomic_add_orig(zpercpu_get_cpu(rc, 0),
		    OS_PCPU_REF_INC, relaxed);
		if (v & OS_PCPU_REF_LIVE) {
			/* we're doing this concurrently to an os_pcpu_ref_kill */
			return;
		}
	}

	if (v == 0 || v >= os_pcpu_count_to_value(OS_REFCNT_MAX_COUNT)) {
		__os_pcpu_ref_retain_panic(rc, v);
	}
}

void
(os_pcpu_ref_retain)(os_pcpu_ref_t ref, struct os_refgrp * __debug_only grp)
{
	__os_pcpu_ref_t rc = os_pcpu_get(ref);
	uint64_t v;
	int cpu;

	v = __os_pcpu_ref_delta(rc, +1, &cpu);
	if (__improbable((v & OS_PCPU_REF_LIVE) == 0)) {
		__os_pcpu_ref_retain_slow(rc, cpu, v);
	}

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_retain_debug(rc, grp);
	}
#endif
}

bool
(os_pcpu_ref_retain_try)(os_pcpu_ref_t ref, struct os_refgrp *__debug_only grp)
{
	__os_pcpu_ref_t rc = os_pcpu_get(ref);
	_Atomic uint64_t *rcp = zpercpu_get(rc);
	uint64_t ov, nv;

	os_atomic_rmw_loop(rcp, ov, nv, relaxed, {
		if ((ov & OS_PCPU_REF_LIVE) == 0) {
		        os_atomic_rmw_loop_give_up(return false);
		}
		nv = ov + OS_PCPU_REF_INC;
	});

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_retain_debug(rc, grp);
	}
#endif
	return true;
}

__attribute__((noinline))
static void
__os_pcpu_ref_release_live_slow(__os_pcpu_ref_t rc, int cpu, uint64_t v)
{
	if (cpu > 0) {
		os_atomic_add(zpercpu_get_cpu(rc, cpu),
		    OS_PCPU_REF_INC, relaxed);
	}
	if (cpu != 0) {
		v = os_atomic_sub_orig(zpercpu_get_cpu(rc, 0),
		    OS_PCPU_REF_INC, release);
		if (v & OS_PCPU_REF_LIVE) {
			/* we're doing this concurrently to an os_pcpu_ref_kill */
			return;
		}
	}

	if (v < os_pcpu_count_to_value(2)) {
		__os_pcpu_ref_release_live_panic(rc);
	}
}

void
(os_pcpu_ref_release_live)(os_pcpu_ref_t ref, struct os_refgrp *__debug_only grp)
{
	__os_pcpu_ref_t rc = os_pcpu_get(ref);
	uint64_t v;
	int cpu;

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		/*
		 * Care not to use 'rc' after the decrement because it might be deallocated
		 * under us.
		 */
		ref_release_debug(rc, grp);
	}
#endif

	v = __os_pcpu_ref_delta(rc, -1, &cpu);

	if (__improbable((v & OS_PCPU_REF_LIVE) == 0)) {
		__os_pcpu_ref_release_live_slow(rc, cpu, v);
	}
}

__attribute__((noinline))
static os_ref_count_t
__os_pcpu_ref_release_slow(
	__os_pcpu_ref_t         rc,
	int                     cpu,
	uint64_t                v
	__os_refgrp_arg(struct os_refgrp *grp))
{
	uint64_t _Atomic *rc0 = zpercpu_get_cpu(rc, 0);

	if (cpu > 0) {
		os_atomic_add(zpercpu_get_cpu(rc, cpu),
		    OS_PCPU_REF_INC, relaxed);
	}
	if (cpu != 0) {
		v = os_atomic_sub_orig(rc0, OS_PCPU_REF_INC, release);
		if (v & OS_PCPU_REF_LIVE) {
			/* we're doing this concurrently to an os_pcpu_ref_kill */
			return OS_REFCNT_MAX_COUNT;
		}
	}

	if (os_sub_overflow(v, OS_PCPU_REF_INC, &v)) {
		__os_pcpu_ref_release_panic(rc);
	}

	os_atomic_thread_fence(acquire);
	if (v == OS_PCPU_REF_WAITER) {
		os_atomic_andnot(rc0, OS_PCPU_REF_WAITER, release);
		thread_wakeup(rc);
		v = 0;
	}
#if OS_REFCNT_DEBUG
	if (v == 0 && REFLOG_GRP_DEBUG_ENABLED(grp)) {
		return ref_drop_debug(rc, grp);
	}
#endif
	return os_pcpu_value_to_count(v);
}

os_ref_count_t
(os_pcpu_ref_release)(os_pcpu_ref_t ref, struct os_refgrp *__debug_only grp)
{
	__os_pcpu_ref_t rc = os_pcpu_get(ref);
	uint64_t v;
	int cpu;

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_release_debug(rc, grp);
	}
#endif

	v = __os_pcpu_ref_delta(rc, -1, &cpu);
	if (__improbable((v & OS_PCPU_REF_LIVE) == 0)) {
		return __os_pcpu_ref_release_slow(rc, cpu, v __os_refgrp_arg(grp));
	}

	return OS_REFCNT_MAX_COUNT;
}

os_ref_count_t
(os_pcpu_ref_kill)(os_pcpu_ref_t ref, struct os_refgrp *__debug_only grp)
{
	__os_pcpu_ref_t rc = os_pcpu_get(ref);
	uint64_t v = 0, t = 0;

#if OS_REFCNT_DEBUG
	if (REFLOG_GRP_DEBUG_ENABLED(grp)) {
		ref_release_debug(rc, grp);
	}
#endif

	for (int cpu = zpercpu_count(); cpu-- > 1;) {
		v = os_atomic_xchg(zpercpu_get_cpu(rc, cpu), 0, relaxed);
		if ((v & OS_PCPU_REF_LIVE) == 0) {
			__os_pcpu_ref_kill_panic(rc);
		}
		t += v - OS_PCPU_REF_LIVE;
	}
	t -= OS_PCPU_REF_LIVE + OS_PCPU_REF_INC;

	v = os_atomic_add(zpercpu_get_cpu(rc, 0), t, acq_rel);
	if (v & OS_PCPU_REF_LIVE) {
		__os_pcpu_ref_kill_panic(rc);
	}

	if (v >= os_pcpu_count_to_value(OS_REFCNT_MAX_COUNT)) {
		__os_pcpu_ref_overflow_panic(rc);
	}

#if OS_REFCNT_DEBUG
	if (v == 0 && REFLOG_GRP_DEBUG_ENABLED(grp)) {
		return ref_drop_debug(rc, grp);
	}
#endif
	return os_pcpu_value_to_count(v);
}

#if KERNEL

void
os_pcpu_ref_wait_for_death(os_pcpu_ref_t ref)
{
	__os_pcpu_ref_t rc = os_pcpu_get(ref);
	uint64_t _Atomic *rc0 = zpercpu_get_cpu(rc, 0);
	uint64_t ov, nv;

	ov = os_atomic_load(rc0, relaxed);
	if (ov == 0) {
		os_atomic_thread_fence(acquire);
		return;
	}

	assert_wait(rc, THREAD_UNINT);

	os_atomic_rmw_loop(rc0, ov, nv, relaxed, {
		if (ov & (OS_PCPU_REF_WAITER | OS_PCPU_REF_LIVE)) {
		        __os_pcpu_ref_invalid_wait_panic(rc, ov);
		}
		if (ov == 0) {
		        os_atomic_rmw_loop_give_up(break);
		}
		nv = ov | OS_PCPU_REF_WAITER;
	});

	if (ov == 0) {
		os_atomic_thread_fence(acquire);
		clear_wait(current_thread(), THREAD_AWAKENED);
	} else {
		thread_block(THREAD_CONTINUE_NULL);
	}
}

#endif
