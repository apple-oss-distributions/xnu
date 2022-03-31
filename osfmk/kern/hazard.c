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

#include <kern/cpu_data.h>
#include <kern/hazard.h>
#include <kern/mpsc_queue.h>
#include <kern/percpu.h>
#include <kern/startup.h>
#include <kern/zalloc.h>
#include <sys/queue.h>

#pragma mark - Hazard types and globals

typedef struct hazard_record {
	void                   *hr_val;
	union {
		void          (*hr_dtor)(void *);
		vm_size_t       hr_size;
	};
} *hazard_record_t;

typedef struct hazard_bucket {
	union {
		struct mpsc_queue_chain     hb_mplink;
		STAILQ_ENTRY(hazard_bucket) hb_stqlink;
	};
	uint32_t                hb_count;
	uint32_t                hb_size;
	struct hazard_record    hb_recs[];
} *hazard_bucket_t;

struct hazard_guard_array {
	hazard_bucket_t         hga_bucket;
#if DEBUG || DEVELOPMENT
	unsigned long           hga_mask;
#endif
	struct hazard_guard     hga_array[HAZARD_GUARD_SLOTS];
};

STAILQ_HEAD(hazard_bucket_list, hazard_bucket);


/*! per-cpu state for hazard pointers. */
static struct hazard_guard_array PERCPU_DATA(hazard_guards_array);

/*! the minimum number of items cached in per-cpu buckets */
static TUNABLE(uint32_t, hazard_bucket_count_min, "hazard_bucket_count_min", 8);

/*! the amount of memory pending retiring that causes a foreceful flush */
#if XNU_TARGET_OS_OSX
#define HAZARD_RETIRE_THRESHOLD_DEFAULT     (256 << 10)
#else
#define HAZARD_RETIRE_THRESHOLD_DEFAULT     (64 << 10)
#endif
static TUNABLE(vm_size_t, hazard_retire_threshold, "hazard_retire_threshold",
    HAZARD_RETIRE_THRESHOLD_DEFAULT);

/*! the number of items cached in per-cpu buckets */
static SECURITY_READ_ONLY_LATE(uint32_t) hazard_bucket_count;

/*! the queue of elements that couldn't be freed immediately */
static struct hazard_bucket_list hazard_buckets_pending =
    STAILQ_HEAD_INITIALIZER(hazard_buckets_pending);

/*! the atomic queue handling deferred deallocations */
static struct mpsc_daemon_queue hazard_deallocate_queue;


#pragma mark - Hazard guards

/*
 * Memory barriers:
 *
 * 1. setting a guard cannot be reordered with subsequent accesses it protects.
 *
 *     ──[ load value ][ set guard ](1)[ reload value ][═════ use value ...
 *                           ^               │
 *                           ╰───────────────╯
 *
 *
 * 2. clearing a guard cannot be reordered with prior accesses it protects.
 *
 *     ... use value ════](2)[ clear guard ]──
 *
 *
 * 3. hazard_retire() needs to ensure that the update to the protected field
 *    is visible to any thread consulting the list of retired pointers.
 *    Note that this fence can be amortized per batch of retired pointers.
 *
 *     ──[ update value ](3)[ retire ]──
 *
 *
 * 4. hazard_scan_and_reclaim() needs to make sure that gathering
 *    retired pointers and scanning guards are fully ordered.
 *
 *    ──[ gather retired pointers ](4)[ guard scan ][ GC ]──
 *
 *
 * With this, `reload value` can't possibly be a pointer to a freed value:
 * - setting the guard "happens before" reloading the value (through (1))
 * - updating a guard value "happens before" freeing it (through (3, 4))
 *
 * Of course, (2) ensures that when the scan loads NULL, then there's no longer
 * any hazardous access in flight and reclamation is safe.
 */

__attribute__((always_inline))
hazard_guard_array_t
__hazard_guard_get(size_t slot, size_t count __assert_only)
{
	struct hazard_guard_array *hga;

	disable_preemption();
	hga = PERCPU_GET(hazard_guards_array);
#if DEBUG || DEVELOPMENT
	unsigned long mask = ((1ul << count) - 1) << slot;
	assertf((hga->hga_mask & mask) == 0, "slot %d in use",
	    __builtin_ctzl(hga->hga_mask & mask));
	hga->hga_mask |= mask;
#endif /* DEBUG || DEVELOPMENT */
	return hga->hga_array + slot;
}

static inline void
__hazard_guard_put(hazard_guard_t guard, size_t count __assert_only)
{
#if DEBUG || DEVELOPMENT
	struct hazard_guard_array *hga = PERCPU_GET(hazard_guards_array);
	size_t slot = guard - hga->hga_array;
	unsigned long mask = ((1ul << count) - 1) << slot;

	assertf(slot < HAZARD_GUARD_SLOTS, "invalid guard %p", guard);
	assertf((hga->hga_mask & mask) == mask, "slot %d free",
	    __builtin_ctzl(~hga->hga_mask & mask));
	hga->hga_mask &= ~mask;
#else
	(void)guard;
#endif /* DEBUG || DEVELOPMENT */
	enable_preemption();
}

__attribute__((always_inline))
void
hazard_guard_put(hazard_guard_t guard) /* fence (2) */
{
	os_atomic_store(&guard->hg_val, NULL, release);
	__hazard_guard_put(guard, 1);
}

__attribute__((always_inline))
void
hazard_guard_put_n(hazard_guard_t guard, size_t n) /* fence (2) */
{
	os_atomic_thread_fence(release);
	__builtin_bzero(guard, n * sizeof(guard->hg_val));
	__hazard_guard_put(guard, n);
}

__attribute__((always_inline))
void
hazard_guard_dismiss(hazard_guard_t guard)
{
	os_atomic_store(&guard->hg_val, NULL, relaxed);
	__hazard_guard_put(guard, 1);
}

__attribute__((always_inline))
void
hazard_guard_dismiss_n(hazard_guard_t guard, size_t n)
{
	__builtin_bzero(guard, n * sizeof(guard->hg_val));
	__hazard_guard_put(guard, n);
}

__attribute__((always_inline))
void
hazard_guard_set(hazard_guard_t guard, void *value) /* fence (1) */
{
#if __x86_64__ || __i386__
	os_atomic_xchg(&guard->hg_val, value, seq_cst);
#else /* c11 */
	os_atomic_store(&guard->hg_val, value, relaxed);
	os_atomic_thread_fence(seq_cst);
#endif
}

__attribute__((always_inline))
void
hazard_guard_replace(hazard_guard_t guard, void *value) /* fence (2) and (1) */
{
#if __x86_64__ || __i386__
	os_atomic_xchg(&guard->hg_val, value, seq_cst);
#else /* c11 */
	os_atomic_store(&guard->hg_val, value, release);
	os_atomic_thread_fence(seq_cst);
#endif
}


#pragma mark - Hazard GC

static hazard_bucket_t
hazard_bucket_alloc(zalloc_flags_t flags)
{
	return kalloc_type(struct hazard_bucket, struct hazard_record,
	           hazard_bucket_count, Z_ZERO | flags);
}

static void
hazard_bucket_free(hazard_bucket_t bucket)
{
	return kfree_type(struct hazard_bucket, struct hazard_record,
	           hazard_bucket_count, bucket);
}

void
hazard_retire(void *value, vm_size_t size, void (*destructor)(void *))
{
	struct hazard_guard_array *hga;
	hazard_bucket_t bucket, free_bucket = NULL;

	/* the retired pointer must be aligned */
	assert(((vm_address_t)value % sizeof(vm_offset_t)) == 0);

	if (__improbable(startup_phase < STARTUP_SUB_EARLY_BOOT)) {
		/*
		 * The system is still single threaded and this module
		 * is still not fully initialized.
		 */
		destructor(value);
		return;
	}

again:
	disable_preemption();
	hga = PERCPU_GET(hazard_guards_array);
	bucket = hga->hga_bucket;
	if (bucket == NULL) {
		if (free_bucket) {
			bucket = free_bucket;
			free_bucket = NULL;
		} else if ((bucket = hazard_bucket_alloc(Z_NOWAIT)) == NULL) {
			enable_preemption();
			free_bucket = hazard_bucket_alloc(Z_WAITOK | Z_NOFAIL);
			goto again;
		}
		hga->hga_bucket = bucket;
	}

	bucket->hb_recs[bucket->hb_count].hr_val = value;
	bucket->hb_recs[bucket->hb_count].hr_dtor = destructor;

	if (os_add_overflow(bucket->hb_size, size, &bucket->hb_size)) {
		bucket->hb_size = UINT32_MAX;
	}

	if (++bucket->hb_count == hazard_bucket_count ||
	    bucket->hb_size >= hazard_retire_threshold) {
		/*
		 * It is ok for this allocation to fail: when it fails,
		 * hga_bucket is set to NULL, and the zone will be primed
		 * which makes it more likely that the next attempt at
		 * allocating will work immediately
		 */
		hga->hga_bucket = hazard_bucket_alloc(Z_NOWAIT);

		mpsc_daemon_enqueue(&hazard_deallocate_queue,
		    &bucket->hb_mplink, MPSC_QUEUE_NONE); /* fence (3) */
	}
	enable_preemption();

	if (__improbable(free_bucket)) {
		hazard_bucket_free(free_bucket);
	}
}

/*!
 * @struct hazard_bucket_filter_state
 *
 * @brief
 * Data structure used to maintain the state during a hazard reclaim phase.
 *
 * @field hbfs_partial
 * Bucket used to keep records that can't be freed yet.
 *
 * @field hbfs_partial_pos
 * How many pointers are saved in @c hbfs_partial.
 *
 * The @c hbfs_partial->hb_count field cannot be used as the bucket
 * being "filtered" could be the same.
 *
 * @field hbfs_array
 * The array of pointers that were scanned as being active
 * and cannot be safely reclaimed yet.
 *
 * @field hbfs_array_len
 * How many entries @c hbfs_array is holding.
 */
struct hazard_bucket_filter_state {
	hazard_bucket_t     hbfs_partial;
	uint32_t            hbfs_partial_pos;
	uint32_t            hbfs_array_len;
	const void        **hbfs_array;
};

extern void
qsort(void *a, size_t n, size_t es, int (*cmp)(const void *, const void *));

static int
hazard_compare(const void *a, const void *b)
{
	void * const *x = a;
	void * const *y = b;

	if (x == y) {
		return 0;
	}
	return x < y ? 1 : -1;
}

static bool
hazard_bsearch(const void *p, const void **array, size_t l, size_t r)
{
	while (l < r) {
		size_t i = (l + r) / 2;
		if (array[i] == p) {
			return true;
		}
		if (array[i] < p) {
			r = i;
		} else {
			l = i + 1;
		}
	}

	return false;
}

/*!
 * @function hazard_filter_bucket
 *
 * @brief
 * Filter bucket records to only keep unreclaimable ones.
 *
 * @discussion
 * Pointers that can't be reclaimed are stored into @c st->hbfs_partial
 * which will eventually stay on the @c hazard_buckets_pending queue
 * until a next scan/filter occurs.
 */
static void
hazard_filter_bucket(struct hazard_bucket_filter_state *st,
    hazard_bucket_t bucket)
{
	hazard_bucket_t partial = st->hbfs_partial;
	uint32_t partial_pos = st->hbfs_partial_pos;

	for (uint32_t i = 0, r_end = bucket->hb_count; i < r_end; i++) {
		struct hazard_record hr = bucket->hb_recs[i];

		if (!hazard_bsearch(hr.hr_val, st->hbfs_array, 0, st->hbfs_array_len)) {
			hr.hr_dtor(hr.hr_val);
			continue;
		}

		partial->hb_recs[partial_pos] = hr;
		if (++partial_pos == hazard_bucket_count) {
			/* we do not keep track of per record size */
			partial->hb_size  = 0;
			partial->hb_count = partial_pos;
			STAILQ_INSERT_TAIL(&hazard_buckets_pending, partial, hb_stqlink);
			st->hbfs_partial = partial = bucket;
			partial_pos = 0;
		}
	}

	if (bucket != partial) {
		hazard_bucket_free(bucket);
	}
	st->hbfs_partial_pos = partial_pos;
}

static void
hazard_filter_finish(struct hazard_bucket_filter_state *st)
{
	if (st->hbfs_partial_pos == 0) {
		hazard_bucket_free(st->hbfs_partial);
	} else {
		hazard_bucket_t bucket = st->hbfs_partial;

		bucket->hb_count = st->hbfs_partial_pos;
		STAILQ_INSERT_TAIL(&hazard_buckets_pending, bucket, hb_stqlink);
		bzero(bucket->hb_recs + bucket->hb_count,
		    sizeof(bucket->hb_recs[0]) *
		    (hazard_bucket_count - bucket->hb_count));
	}
}

/*!
 * @function hazard_scan_and_reclaim()
 *
 * @brief
 * Perform the reclamation phase of hazard pointers.
 *
 * @discussion
 * Buckets are enqueued onto the global @c hazard_bucket_list list
 * by @c hazard_deallocate_queue_invoke().
 *
 * Then this function is called to filter this list.
 * Records that are not safe to reclaim stay on the list,
 * and will be filtered again the next time around.
 */
static void
hazard_scan_and_reclaim(void)
{
	__attribute__((uninitialized))
	const void *protected_array[MAX_CPUS * HAZARD_GUARD_SLOTS];

	struct hazard_bucket_list head = STAILQ_HEAD_INITIALIZER(head);
	struct hazard_bucket_filter_state st = {
		.hbfs_array = protected_array,
		.hbfs_partial = STAILQ_FIRST(&hazard_buckets_pending),
	};
	hazard_bucket_t bucket;
	const void *p;

	/*
	 * The mpsc daemon is called with a shallow stack depth,
	 * so we really should be able to have up 1k worth of pointers
	 * on our stack.
	 *
	 * When this becomes no longer true, we will keep a reasonnably sized
	 * stack buffer and will allocate if it overflows. Chances are that
	 * even on a very wide machine, there aren't enough live hazard
	 * pointers anyway.
	 */
	static_assert(sizeof(protected_array) <= sizeof(void *) * 1024,
	    "our stack usage is ok");

	STAILQ_CONCAT(&head, &hazard_buckets_pending);

	percpu_foreach(hga, hazard_guards_array) {
		for (size_t i = 0; i < HAZARD_GUARD_SLOTS; i++) {
			p = os_atomic_load(&hga->hga_array[i].hg_val, relaxed);
			if (p) {
				st.hbfs_array[st.hbfs_array_len++] = p;
			}
		}
	}

	qsort(st.hbfs_array, st.hbfs_array_len, sizeof(void *), hazard_compare);

	while ((bucket = STAILQ_FIRST(&head))) {
		STAILQ_REMOVE_HEAD(&head, hb_stqlink);
		hazard_filter_bucket(&st, bucket);
	}

	hazard_filter_finish(&st);
}

static void
hazard_deallocate_queue_invoke(mpsc_queue_chain_t e,
    __assert_only mpsc_daemon_queue_t dq)
{
	assert(dq == &hazard_deallocate_queue);

	/*
	 * Because we need to issue a fence before scanning for active
	 * pointers, we accumulate pending buckets in a first pass,
	 *
	 * then the MPSC system calls us with the MPSC_QUEUE_BATCH_END marker
	 * to mark the end of a batch. Realistically batches are extremely
	 * unlikely to be longer than NCPU.
	 *
	 * We enqueue all buckets onto a global list (hazard_buckets_pending)
	 * which is then filtered/trimmed by hazard_scan_and_reclaim().
	 */

	if (e != MPSC_QUEUE_BATCH_END) {
		hazard_bucket_t bucket;

		bucket = mpsc_queue_element(e, struct hazard_bucket, hb_mplink);
		STAILQ_INSERT_TAIL(&hazard_buckets_pending, bucket, hb_stqlink);
		return;
	}

	if (!STAILQ_EMPTY(&hazard_buckets_pending)) {
		os_atomic_thread_fence(seq_cst); /* fence (4) */

		hazard_scan_and_reclaim();
	}
}


#pragma mark - module initialization

void
hazard_register_mpsc_queue(void)
{
	thread_deallocate_daemon_register_queue(&hazard_deallocate_queue,
	    hazard_deallocate_queue_invoke);
	hazard_deallocate_queue.mpd_options |= MPSC_QUEUE_OPTION_BATCH;
}

static void
hazard_startup(void)
{
	hazard_bucket_count = zpercpu_count() * HAZARD_GUARD_SLOTS / 2;
	if (hazard_bucket_count < hazard_bucket_count_min) {
		hazard_bucket_count = hazard_bucket_count_min;
	}
}
STARTUP(PERCPU, STARTUP_RANK_LAST, hazard_startup);

#pragma mark - tests
#if DEBUG || DEVELOPMENT
#include <sys/errno.h>

struct hazard_test_value {
	os_refcnt_t htv_ref;
	int         htv_step;
	bool        htv_reclaim_ok;
	void       *htv_reclaimed;
};

static _Atomic uint32_t hazard_test_outstanding;

static struct hazard_test_value *
hazard_test_value_alloc(int count, int step, bool ok)
{
	struct hazard_test_value *val;

	val = kalloc_data(sizeof(struct hazard_test_value),
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);
	os_ref_init_count(&val->htv_ref, NULL, count);
	val->htv_reclaim_ok = ok;
	val->htv_step = step;
	os_atomic_inc(&hazard_test_outstanding, relaxed);
	return val;
}

static void
hazard_test_value_release(struct hazard_test_value *val)
{
	if (os_ref_release(&val->htv_ref) == 0) {
		os_atomic_dec(&hazard_test_outstanding, relaxed);
		kfree_data(val, sizeof(*val));
	}
}

static void
hazard_test_value_retire_cb(void *ptr)
{
	struct hazard_test_value *val = ptr;

	if (!val->htv_reclaim_ok) {
		panic("%p: step %d should not be reclaimed", val, val->htv_step);
	}
	os_atomic_store(&val->htv_reclaimed, (void *)1, seq_cst);
	hazard_test_value_release(val);
}

static int
hazard_basic_test(__unused int64_t in, int64_t *out)
{
	static HAZARD_POINTER(struct hazard_test_value *) pointer;

	uint32_t start, end, count;
	hazard_guard_t guard;

	if (hazard_bucket_count < 2 || hazard_bucket_count > 32) {
		printf("%s: skipping test because hazard_bucket_count is %d\n",
		    __func__, hazard_bucket_count);
	}

	printf("%s: using some guards\n", __func__);
	{
		struct hazard_test_value *val, *tmp;

		val = hazard_test_value_alloc(1, 0, false);
		hazard_ptr_serialized_store(&pointer, val);

		for (int i = 0; i < 10; i++) {
			guard = hazard_guard_get(0);
			assert(guard != NULL);

			tmp = hazard_guard_acquire(guard, &pointer);
			assert(tmp == val);

			hazard_guard_put(guard);

			delay_for_interval(1, NSEC_PER_MSEC);
		}

		hazard_ptr_clear(&pointer);
		hazard_test_value_release(val);
	}
	printf("%s: done\n", __func__);

	count = hazard_bucket_count * MAX_CPUS * 2 + 3;
	printf("%s: retiring %d values in a loop\n", __func__, count);
	{
		struct hazard_test_value *val;

		start = os_atomic_load(&hazard_test_outstanding, relaxed);
		printf("%s: starting (%d outstanding)\n", __func__, start);

		for (int i = 0; i < count; i++) {
			val = hazard_test_value_alloc(1, 1000 + i, true);
			hazard_retire(val, sizeof(*val), hazard_test_value_retire_cb);
		}

		delay_for_interval(10, NSEC_PER_MSEC);

		end = os_atomic_load(&hazard_test_outstanding, relaxed);
		printf("%s: ending (%d outstanding)\n", __func__, end);

		assert(end <= start || end - start < hazard_bucket_count * MAX_CPUS);
	}
	printf("%s: done\n", __func__);

	printf("%s: cheating and checking scan works\n", __func__);
	if (zpercpu_count() > 1 && processor_avail_count > 1) {
		struct hazard_test_value *v1, *v2, *tmp;
		hazard_bucket_t bucket = hazard_bucket_alloc(Z_WAITOK);

		v1 = hazard_test_value_alloc(2, 10000, false);
		v2 = hazard_test_value_alloc(2, 10001, true);
		hazard_ptr_serialized_store(&pointer, v1);

		/* create a fake bucket to simulate a retire in flight */
		bucket = hazard_bucket_alloc(Z_WAITOK);
		bucket->hb_count = 2;
		bucket->hb_recs[0].hr_val = v1;
		bucket->hb_recs[0].hr_dtor = &hazard_test_value_retire_cb;
		bucket->hb_recs[1].hr_val = v2;
		bucket->hb_recs[1].hr_dtor = &hazard_test_value_retire_cb;

		guard = hazard_guard_get(0);
		tmp = hazard_guard_acquire(guard, &pointer);
		assert(v1 == tmp);

		/* simulate an enqueue */
		mpsc_daemon_enqueue(&hazard_deallocate_queue,
		    &bucket->hb_mplink, MPSC_QUEUE_NONE);

		/*
		 * wait until we can observe v2 being freed,
		 * it will panic if not happening quickly enough
		 */
		hw_wait_while_equals_long(&v2->htv_reclaimed, NULL);

		/* Allow it to be reclaimed now */
		os_atomic_store(&v1->htv_reclaim_ok, true, seq_cst);

		hazard_guard_put(guard);

		printf("%s: observed %p die and %p stay\n", __func__, v2, v1);

		/* do a fake bucket again to force a flush */
		bucket = hazard_bucket_alloc(Z_WAITOK);
		bucket->hb_count = 1;
		bucket->hb_recs[0].hr_val = v2;
		bucket->hb_recs[0].hr_dtor = &hazard_test_value_retire_cb;

		/* simulate an enqueue */
		mpsc_daemon_enqueue(&hazard_deallocate_queue,
		    &bucket->hb_mplink, MPSC_QUEUE_DISABLE_PREEMPTION);

		/*
		 * wait until we can observe v1 being freed,
		 * now that there's no guard preventing it to disappear
		 */
		hw_wait_while_equals_long(&v1->htv_reclaimed, NULL);

		hazard_test_value_release(v1);
		printf("%s: observed %p die too\n", __func__, v1);
	}
	printf("%s: done\n", __func__);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(hazard_basic, hazard_basic_test);

#endif /* DEBUG || DEVELOPMENT */
