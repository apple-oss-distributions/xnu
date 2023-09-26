/*
 * Copyright (c) 2012-2021 Apple Inc. All rights reserved.
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

#include <kern/assert.h>
#include <kern/backtrace.h>
#include <kern/btlog.h>
#include <kern/smr.h>
#include <kern/startup.h>
#include <kern/thread_call.h>
#include <os/hash.h>
#include <mach/vm_map.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_memtag.h>
#include <vm/pmap.h>

#pragma mark btref & helpers

static LCK_GRP_DECLARE(bt_library_lck_grp, "bt_library");
static SMR_DEFINE(bt_library_smr, "bt library");

#define BTS_FRAMES_MAX          13
#define BTS_FRAMES_REF_MASK     0xfffffff0
#define BTS_FRAMES_REF_INC      0x00000010
#define BTS_FRAMES_LEN_MASK     0x0000000f

typedef SMR_POINTER(btref_t)    btref_smr_t;

typedef union bt_stack {
	struct {
		btref_smr_t     bts_next;
		uint32_t        bts_ref_len;
		uint32_t        bts_hash;
		uint32_t        bts_frames[BTS_FRAMES_MAX];
	};
	struct {
		uint32_t        bts_padding[3 + BTS_FRAMES_MAX - 1 - sizeof(long) / 4];
		uint32_t        bts_free_next;
		smr_seq_t       bts_free_seq;
	};
} *bt_stack_t;

static_assert(sizeof(union bt_stack) == 64); /* allocation scheme needs it */

#define BTREF_PERMANENT_BIT     0x80000000u
#define BTREF_OP_MASK           0x0000003fu
#define BTREF_VALID_MASK        0xc000003fu

#define BTL_SIZE_INIT           (1u << 20)
#define BTL_SIZE_MAX            (1u << 30)
#define BTL_SLABS               9

#define BTL_PARAM_INIT          0x00000020u
#define BTL_PARAM_PARITY(p)     ((p) >> 31)
#define BTL_PARAM_SHIFT(p)      (32 - ((p) & 0x3f))
#define BTL_PARAM_IDX(p, h)     ((uint64_t)(h) >> ((p) & 0x3f))
#define BTL_PARAM_NEXT(p)       ((p) - 0x80000001u)

#define BTL_HASH_SHIFT          8
#define BTL_HASH_COUNT          (1u << BTL_HASH_SHIFT)
#define BTL_HASH_MASK           (BTL_HASH_COUNT - 1)

static_assert((BTL_SIZE_INIT << BTL_SLABS) == BTL_SIZE_MAX / 2);

typedef struct bt_hash {
	btref_smr_t             bth_array[BTL_HASH_COUNT];
} *bt_hash_t;

#if DEBUG || DEVELOPMENT
#define BTLIB_VALIDATE          1
#else
#define BTLIB_VALIDATE          0
#endif

/*!
 * @typedef bt_library_t
 *
 * @brief
 * Describes a backtrace library.
 *
 * @discussion
 * A backtrace library is a scalable hash table of backtraces
 * used for debugging purposes.
 *
 * By default there is a single singleton one, but the code
 * is amenable to have several instances.
 *
 *
 * <h2>Data structure design</h2>
 *
 * Its hash table is structured like this:
 *
 *     par = BTL_PARAM_PARITY(btl->btl_param);
 *     sz  = 1u << BTL_PARAM_SHIFT(btl->btl_param);
 *
 *     btl->btl_hash[par]
 *           │
 *           │     ╭─────── array of size "sz" buckets ───────╮
 *           ╰───> │                                          │
 *                 ╰──────────────────────────────────┼───────╯
 *                                                    │
 *               ╭─────── struct bt_hash ───────╮     │
 *               │                              │ <───╯
 *               ╰──┼───────────────────────────╯
 *                  │
 *                  ╰──> Stack ──> Stack ──> Stack ──> X
 *
 *
 * The "btl_hash" two entries are used with the "btl_param" switch in order
 * to swap the outer array while growing the hash without perturbating
 * readers.
 *
 * The lists of stacks are also maintained in "hash" order which allows
 * for the rehashing to be a clean split of the lists.
 *
 * All stack pointers are "references" which are a smaller 32bit offset
 * within the library backing store (slabs).
 *
 */
typedef struct bt_library {
	lck_ticket_t            btl_lock;
	SMR_POINTER(uint32_t)   btl_param;

	bt_hash_t              *btl_hash[2];
	thread_call_t           btl_call;
	thread_t                btl_grower;

	btref_t                *btl_free_tail;
	btref_t                 btl_free_head;

	btref_t                 btl_deferred_head;

	bool                    btl_waiters;
	bool                    btl_in_callout;
	bool                    btl_rehashing;
	uint8_t                 btl_slab_cur;
	uint32_t                btl_alloc_pos;
	uint32_t                btl_faulted_pos;
	uint32_t                btl_max_pos;
	vm_address_t            btl_slabs[BTL_SLABS];
} *bt_library_t;

static struct bt_library        bt_library;

static size_t
__btstack_len(bt_stack_t bts)
{
	return bts->bts_ref_len & BTS_FRAMES_LEN_MASK;
}

static size_t
__btstack_size(bt_stack_t bts)
{
	return sizeof(uint32_t) * __btstack_len(bts);
}

static bool
__btstack_same(bt_stack_t a, bt_stack_t b)
{
	return a->bts_hash == b->bts_hash &&
	       __btstack_len(a) == __btstack_len(b) &&
	       memcmp(a->bts_frames, b->bts_frames, __btstack_size(a)) == 0;
}

static uint32_t
__btstack_capture(bt_stack_t bts, void *fp, bool permanent)
{
	struct backtrace_control ctl = {
		.btc_frame_addr = (vm_offset_t)fp,
	};
	size_t size;

	size = backtrace_packed(BTP_KERN_OFFSET_32, (uint8_t *)bts->bts_frames,
	    sizeof(bts->bts_frames), &ctl, NULL);
	bts->bts_ref_len = (size / sizeof(uint32_t)) +
	    (permanent ? BTS_FRAMES_REF_MASK : BTS_FRAMES_REF_INC);
	return bts->bts_hash = os_hash_jenkins(bts->bts_frames, size);
}

static btref_t
__btstack_try_retain(btref_t btref, bt_stack_t bts, btref_get_flags_t flags)
{
	uint32_t oref, nref;

	oref = bts->bts_ref_len;

	do {
		switch (oref & BTS_FRAMES_REF_MASK) {
		case 0:
			return 0;
		case BTS_FRAMES_REF_MASK:
			return btref | BTREF_PERMANENT_BIT;
		}

		nref = oref + BTS_FRAMES_REF_INC;
		if (flags & BTREF_GET_PERMANENT) {
			nref |= BTS_FRAMES_REF_MASK;
		}
	} while (!os_atomic_cmpxchgv(&bts->bts_ref_len,
	    oref, nref, &oref, relaxed));

	if ((nref & BTS_FRAMES_REF_MASK) == BTS_FRAMES_REF_MASK) {
		btref |= BTREF_PERMANENT_BIT;
	}

	return btref;
}

__abortlike
static void
__btstack_resurrect_panic(bt_stack_t bts)
{
	panic("trying to resurrect bt stack %p", bts);
}

static btref_t
__btstack_retain(btref_t btref, bt_stack_t bts, btref_get_flags_t flags)
{
	uint32_t oref, nref;

	oref = bts->bts_ref_len;

	do {
		switch (oref & BTS_FRAMES_REF_MASK) {
		case 0:
			__btstack_resurrect_panic(bts);
		case BTS_FRAMES_REF_MASK:
			return btref | BTREF_PERMANENT_BIT;
		}

		nref = oref + BTS_FRAMES_REF_INC;
		if (flags & BTREF_GET_PERMANENT) {
			nref |= BTS_FRAMES_REF_MASK;
		}
	} while (!os_atomic_cmpxchgv(&bts->bts_ref_len,
	    oref, nref, &oref, relaxed));

	if ((nref & BTS_FRAMES_REF_MASK) == BTS_FRAMES_REF_MASK) {
		btref |= BTREF_PERMANENT_BIT;
	}

	return btref;
}

__abortlike
static void
__btstack_over_release_panic(bt_stack_t bts)
{
	panic("trying to over-release bt stack %p", bts);
}

static bool
__btstack_release(bt_stack_t bts)
{
	uint32_t oref, nref;

	oref = bts->bts_ref_len;

	do {
		switch (oref & BTS_FRAMES_REF_MASK) {
		case 0:
			__btstack_over_release_panic(bts);
		case BTS_FRAMES_REF_MASK:
			return false;
		}

		nref = oref - BTS_FRAMES_REF_INC;
	} while (!os_atomic_cmpxchgv(&bts->bts_ref_len,
	    oref, nref, &oref, relaxed));

	return nref < BTS_FRAMES_REF_INC;
}

static bt_stack_t
__btlib_deref(bt_library_t btl, btref_t ref)
{
	uint32_t slab = 0;

	if (ref >= BTL_SIZE_INIT) {
		slab = __builtin_clz(BTL_SIZE_INIT) - __builtin_clz(ref) + 1;
	}
	return (bt_stack_t)(btl->btl_slabs[slab] + ref);
}

static void
__btlib_lock(bt_library_t btl)
{
	lck_ticket_lock(&btl->btl_lock, &bt_library_lck_grp);
}

static void
__btlib_unlock(bt_library_t btl)
{
	lck_ticket_unlock(&btl->btl_lock);
}

static inline btref_smr_t *
__btlib_head(bt_library_t btl, uint32_t param, uint32_t hash)
{
	uint32_t par = BTL_PARAM_PARITY(param);
	uint32_t idx = BTL_PARAM_IDX(param, hash);

	return &btl->btl_hash[par][idx]->bth_array[hash & BTL_HASH_MASK];
}

#pragma mark btref growth & rehashing

static void __btlib_remove_deferred_locked(bt_library_t btl);

static bool
__btlib_growth_needed(bt_library_t btl)
{
	if (btl->btl_faulted_pos >= btl->btl_alloc_pos + PAGE_SIZE / 2) {
		return false;
	}

	if (btl->btl_faulted_pos == btl->btl_max_pos &&
	    btl->btl_slab_cur + 1 == BTL_SLABS) {
		return false;
	}

	return true;
}

static bool
__btlib_rehash_needed(bt_library_t btl)
{
	uint32_t param = smr_serialized_load(&btl->btl_param);
	uint32_t shift = BTL_HASH_SHIFT + BTL_PARAM_SHIFT(param);

	return (btl->btl_faulted_pos >> (3 + shift)) >= sizeof(union bt_stack);
}

static void
__btlib_callout_wakeup(bt_library_t btl)
{
	if (startup_phase >= STARTUP_SUB_THREAD_CALL &&
	    !btl->btl_in_callout) {
		thread_call_enter(btl->btl_call);
	}
}

__attribute__((noinline))
static void
__btlib_grow(bt_library_t btl)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_address_t addr;

	while (btl->btl_grower) {
		btl->btl_waiters = true;
		lck_ticket_sleep_with_inheritor(&btl->btl_lock,
		    &bt_library_lck_grp, LCK_SLEEP_DEFAULT,
		    &btl->btl_grower, btl->btl_grower,
		    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
		if (!__btlib_growth_needed(btl)) {
			return;
		}
	}
	btl->btl_grower = current_thread();

	__btlib_unlock(btl);

	if (btl->btl_faulted_pos == btl->btl_max_pos) {
		uint8_t slab = btl->btl_slab_cur + 1;
		vm_size_t size = btl->btl_max_pos;

		kr = kmem_alloc(kernel_map, &addr, size,
		    KMA_KOBJECT | KMA_ZERO | KMA_VAONLY | KMA_DATA,
		    VM_KERN_MEMORY_DIAG);
		if (kr != KERN_SUCCESS) {
			goto done;
		}

		btl->btl_slab_cur = slab;
		btl->btl_slabs[slab] = addr - size;
		btl->btl_max_pos += size;
	}

	if (btl->btl_faulted_pos < btl->btl_alloc_pos + PAGE_SIZE / 2) {
		uint8_t slab = btl->btl_slab_cur;

		addr = btl->btl_slabs[slab] + btl->btl_faulted_pos;

		kr = kernel_memory_populate(addr, PAGE_SIZE,
		    KMA_KOBJECT | KMA_ZERO, VM_KERN_MEMORY_DIAG);
	}

done:
	__btlib_lock(btl);

	if (kr == KERN_SUCCESS) {
		btl->btl_faulted_pos += PAGE_SIZE;
	}

	btl->btl_grower = NULL;

	if (btl->btl_waiters) {
		btl->btl_waiters = false;
		wakeup_all_with_inheritor(&btl->btl_grower, THREAD_AWAKENED);
	}

	if (__btlib_rehash_needed(btl)) {
		__btlib_callout_wakeup(btl);
	}
}

static void
__btlib_split_step(
	bt_library_t            btl,
	bt_hash_t              *bthp,
	uint32_t                idx,
	uint32_t                mask)
{
	btref_smr_t *head, *prev;
	bt_stack_t   bts;
	btref_t      ref;

	__btlib_lock(btl);

	if (__btlib_growth_needed(btl)) {
		__btlib_grow(btl);
	}

	for (uint32_t i = 0; i < BTL_HASH_COUNT; i++) {
		prev = head = &bthp[idx]->bth_array[i];

		while ((ref = smr_serialized_load(prev)) != BTREF_NULL) {
			bts = __btlib_deref(btl, ref);
			if (bts->bts_hash & mask) {
				break;
			}
			prev = &bts->bts_next;
		}

		if (idx & 1) {
			smr_init_store(head, ref);
		} else {
			smr_clear_store(prev);
		}
	}

	__btlib_unlock(btl);
}

#if BTLIB_VALIDATE
static void
__btlib_validate(
	bt_library_t            btl,
	bt_hash_t              *bthp,
	uint32_t                size,
	uint32_t                param)
{
	bt_stack_t bts;
	btref_t ref;

	for (uint32_t i = 0; i < size; i++) {
		for (uint32_t j = 0; j < BTL_HASH_COUNT; j++) {
			ref = smr_serialized_load(&bthp[i]->bth_array[j]);
			if (ref == 0) {
				continue;
			}
			bts = __btlib_deref(btl, ref);
			assert3u(BTL_PARAM_IDX(param, bts->bts_hash), ==, i);
			assert3u(bts->bts_hash & BTL_HASH_MASK, ==, j);
		}
	}
}
#endif /* BTLIB_VALIDATE */

__attribute__((noinline))
static void
__btlib_rehash_and_lock(bt_library_t btl)
{
	uint32_t   param_old, size_old, mask;
	bt_hash_t *bthp_old;
	bt_hash_t *bthp;
	smr_seq_t  s1, s2;

	/*
	 * Step 1: compute all the right sizes and parameters
	 *         and allocate the new hash table elements.
	 */
	param_old = smr_serialized_load(&btl->btl_param);
	bthp_old  = btl->btl_hash[BTL_PARAM_PARITY(param_old)];
	size_old  = 1u << BTL_PARAM_SHIFT(param_old);
	bthp      = kalloc_type(bt_hash_t, 2 * size_old, Z_WAITOK_ZERO);
	mask      = 1u << (BTL_PARAM_NEXT(param_old) & 0x1f);

	if (bthp == NULL) {
		return;
	}

	for (uint32_t i = 0; i < size_old; i++) {
		bthp[2 * i] = bthp_old[i];
		bthp[2 * i + 1] = kalloc_type(struct bt_hash,
		    Z_WAITOK_ZERO_NOFAIL);
	}

	/*
	 * Step 2: Copy all the hash table buckets in one go.
	 *         And publish the new array.
	 *
	 * TODO: consider if we want to let go of the lock sometimes.
	 */
	__btlib_lock(btl);

	btl->btl_rehashing = true;

	for (uint32_t i = 0; i < size_old; i++) {
		memcpy(bthp[2 * i + 1], bthp[2 * i], sizeof(struct bt_hash));
	}

	btl->btl_hash[!BTL_PARAM_PARITY(param_old)] = bthp;

	smr_serialized_store(&btl->btl_param, BTL_PARAM_NEXT(param_old));

	__btlib_unlock(btl);

	smr_synchronize(&bt_library_smr);

	/*
	 * Step 3: Compute the "odd" lists
	 *
	 * When we arrive here, we have 2 buckets per list working this way,
	 * assumnig the hash bit that we are interested in changes on "C -> D":
	 *
	 * [ even ] -> A -> B -> C -> D -> E -> 0
	 * [ odd  ] ---^
	 *
	 * We will now build:
	 *
	 * [ even ] -> A -> B -> C -> D -> E -> 0
	 * [ odd  ] ------------------^
	 *
	 * Note: we try to advance the SMR clock twice,
	 *       in the hope that for larger hashes it will
	 *       help smr_wait() not to spin.
	 */

	for (uint32_t i = 0; i < size_old; i += 2) {
		__btlib_split_step(btl, bthp, i + 1, mask);
	}
	s1 = smr_advance(&bt_library_smr);

	if (size_old >= 2) {
		for (uint32_t i = size_old; i < 2 * size_old; i += 2) {
			__btlib_split_step(btl, bthp, i + 1, mask);
		}
		s2 = smr_advance(&bt_library_smr);
	}

	/*
	 * It's now possible to free the old array, do it,
	 * in a feeble attempt to give SMR readers more time before
	 * the next smr_wait().
	 */
	btl->btl_hash[BTL_PARAM_PARITY(param_old)] = NULL;
	kfree_type(bt_hash_t, size_old, bthp_old);

	/*
	 * Step 4: Split the "even" lists
	 *
	 * We will now cut the "C -> D" link in the even bucket, ending up with:
	 *
	 * [ even ] -> A -> B -> C -> 0
	 * [ odd  ] ----------------> D -> E -> 0
	 */
	smr_wait(&bt_library_smr, s1);
	for (uint32_t i = 0; i < size_old; i += 2) {
		__btlib_split_step(btl, bthp, i, mask);
	}

	if (size_old >= 2) {
		smr_wait(&bt_library_smr, s2);
		for (uint32_t i = size_old; i < 2 * size_old; i += 2) {
			__btlib_split_step(btl, bthp, i, mask);
		}
	}

	/*
	 * Help readers see the cuts.
	 */
	(void)smr_advance(&bt_library_smr);

	__btlib_lock(btl);

	btl->btl_rehashing = false;

#if BTLIB_VALIDATE
	__btlib_validate(btl, bthp, size_old * 2, BTL_PARAM_NEXT(param_old));
#endif /* BTLIB_VALIDATE */

	__btlib_remove_deferred_locked(btl);
}

static void
__btlib_callout(thread_call_param_t arg0, thread_call_param_t __unused arg1)
{
	bt_library_t btl = arg0;

	__btlib_lock(btl);
	btl->btl_in_callout = true;

	if (__btlib_growth_needed(btl)) {
		__btlib_grow(btl);
	}

	while (__btlib_rehash_needed(btl)) {
		__btlib_unlock(btl);
		__btlib_rehash_and_lock(btl);
	}

	btl->btl_in_callout = false;
	__btlib_unlock(btl);
}

static void
__btlib_init(bt_library_t btl)
{
	kern_return_t kr;
	vm_address_t  addr;
	bt_hash_t    *bthp;

	lck_ticket_init(&btl->btl_lock, &bt_library_lck_grp);
	btl->btl_free_tail = &btl->btl_free_head;
	btl->btl_call = thread_call_allocate_with_options(__btlib_callout, btl,
	    THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);

	kr = kmem_alloc(kernel_map, &addr, BTL_SIZE_INIT,
	    KMA_KOBJECT | KMA_ZERO | KMA_VAONLY | KMA_DATA,
	    VM_KERN_MEMORY_DIAG);
	if (kr != KERN_SUCCESS) {
		panic("unable to allocate initial VA: %d", kr);
	}

	bthp = kalloc_type(bt_hash_t, 1, Z_WAITOK_ZERO_NOFAIL);
	bthp[0] = kalloc_type(struct bt_hash, Z_WAITOK_ZERO_NOFAIL);

	btl->btl_slabs[0]  = addr;
	btl->btl_max_pos   = BTL_SIZE_INIT;
	btl->btl_alloc_pos = sizeof(union bt_stack);
	btl->btl_hash[0]   = bthp;
	smr_init_store(&btl->btl_param, BTL_PARAM_INIT);
}
STARTUP_ARG(ZALLOC, STARTUP_RANK_LAST, __btlib_init, &bt_library);

#pragma mark btref insertion/removal fastpaths

__attribute__((noinline))
static btref_t
__btlib_insert(
	bt_library_t            btl,
	bt_stack_t              needle,
	btref_get_flags_t       flags,
	uint32_t                hash)
{
	bt_stack_t bts;
	btref_smr_t *prev;
	btref_t ref;

	__btlib_lock(btl);

	if (__btlib_growth_needed(btl)) {
		/*
		 * Do this first so that we keep the lock held
		 * while we insert.
		 */
		if ((flags & BTREF_GET_NOWAIT) == 0) {
			__btlib_grow(btl);
		} else {
			__btlib_callout_wakeup(btl);
		}
	}

	prev = __btlib_head(btl, smr_serialized_load(&btl->btl_param), hash);
	while ((ref = smr_serialized_load(prev)) != BTREF_NULL) {
		bts = __btlib_deref(btl, ref);

#if BTLIB_VALIDATE
		assert3u(bts->bts_hash & BTL_HASH_MASK, ==,
		    hash & BTL_HASH_MASK);
#endif /* BTLIB_VALIDATE */

		if (needle->bts_hash < bts->bts_hash) {
			break;
		}
		if (__btstack_same(needle, bts)) {
			ref = __btstack_try_retain(ref, bts, flags);
			if (ref) {
				__btlib_unlock(btl);
				return ref;
			}
			break;
		}
		prev = &bts->bts_next;
	}

	if (btl->btl_free_head) {
		ref = btl->btl_free_head;
		bts = __btlib_deref(btl, btl->btl_free_head);
		if (smr_poll(&bt_library_smr, bts->bts_free_seq)) {
			if ((btl->btl_free_head = bts->bts_free_next) == 0) {
				btl->btl_free_tail = &btl->btl_free_head;
			}
			goto allocated;
		}
	}

	if (__improbable(btl->btl_alloc_pos + sizeof(union bt_stack) >
	    btl->btl_faulted_pos)) {
		__btlib_unlock(btl);
		return BTREF_NULL;
	}

	ref = btl->btl_alloc_pos;
	btl->btl_alloc_pos = ref + sizeof(union bt_stack);
	bts = __btlib_deref(btl, ref);

allocated:
	*bts = *needle;
	smr_serialized_store(&bts->bts_next, smr_serialized_load(prev));
	smr_serialized_store(prev, ref);

	__btlib_unlock(btl);

	return ref | ((flags & BTREF_GET_PERMANENT) != 0);
}

__abortlike
static void
__btlib_remove_notfound_panic(bt_library_t btl, bt_stack_t bts)
{
	panic("couldn't find stack %p in library %p", bts, btl);
}

static void
__btlib_remove_locked(bt_library_t btl, btref_t ref, bt_stack_t bts)
{
	uint32_t hash = bts->bts_hash;
	uint32_t param = smr_serialized_load(&btl->btl_param);
	btref_smr_t *prev;

	if (btl->btl_rehashing) {
		/*
		 * We can't really delete things during rehash.
		 * put them on the deferred list.
		 */
		bts->bts_free_next = btl->btl_deferred_head;
		btl->btl_deferred_head = ref;
		return;
	}

	prev = __btlib_head(btl, param, hash);
	for (;;) {
		btref_t tmp = smr_serialized_load(prev);

		if (tmp == ref) {
			break;
		}
		if (tmp == 0) {
			__btlib_remove_notfound_panic(btl, bts);
		}
		prev = &__btlib_deref(btl, tmp)->bts_next;
	}

	smr_serialized_store(prev, smr_serialized_load(&bts->bts_next));
	bts->bts_free_next = 0;
	*btl->btl_free_tail = ref;
	btl->btl_free_tail = &bts->bts_free_next;
	bts->bts_free_seq = smr_advance(&bt_library_smr);
}

static void
__btlib_remove_deferred_locked(bt_library_t btl)
{
	btref_t ref, next;
	bt_stack_t bts;

	next = btl->btl_deferred_head;
	btl->btl_deferred_head = 0;
	while ((ref = next)) {
		bts = __btlib_deref(btl, ref);
		next = bts->bts_free_next;
		__btlib_remove_locked(btl, ref, bts);
	}
}

__attribute__((noinline))
static void
__btlib_remove(bt_library_t btl, btref_t ref, bt_stack_t bts)
{
	__btlib_lock(btl);
	__btlib_remove_locked(btl, ref, bts);
	__btlib_unlock(btl);
}

static btref_t
__btlib_get(bt_library_t btl, void *fp, btref_get_flags_t flags)
{
	union bt_stack needle;
	btref_smr_t *head;
	uint32_t hash, param;
	btref_t ref;

	if (bt_library.btl_alloc_pos == 0) {
		return BTREF_NULL;
	}

	hash  = __btstack_capture(&needle, fp, (flags & BTREF_GET_PERMANENT));

	smr_enter(&bt_library_smr);

	/*
	 * The hash "params" have a single bit to select the btl_hash[]
	 * pointer that is used.
	 *
	 * The compiler knows enough about this code to break
	 * the dependency chains that we would like, generating code like this:
	 *
	 *     bthp = btl->btl_hash[0];
	 *     if (BTL_PARAM_PARITY(param)) {
	 *             bthp = btl->btl_hash[1];
	 *     }
	 *
	 * We could try to play tricks but this would be brittle, so instead,
	 * use a proper acquire barrier on param, which pairs with
	 * smr_serialized_store(&btl->btl_param, ...)
	 * in __btlib_rehash_and_lock().
	 *
	 *
	 * Similarly, because the `bts_next` fields are not dereferenced
	 * right away but used as part of complicated arithmetics,
	 * trusting the compiler's maintaining of dependencies
	 * is a tall order, sometimes, an acquire barrier is best.
	 */
	param = smr_entered_load_acquire(&btl->btl_param);
	head  = __btlib_head(btl, param, hash);
	ref   = smr_entered_load(head);

	while (ref) {
		bt_stack_t bts = __btlib_deref(btl, ref);

#if BTLIB_VALIDATE
		assert3u(bts->bts_hash & BTL_HASH_MASK, ==,
		    hash & BTL_HASH_MASK);
#endif /* BTLIB_VALIDATE */

		if (needle.bts_hash < bts->bts_hash) {
			break;
		}
		if (__btstack_same(&needle, bts) &&
		    (ref = __btstack_try_retain(ref, bts, flags))) {
			smr_leave(&bt_library_smr);
			return ref;
		}

		ref = smr_entered_load(&bts->bts_next);
	}

	smr_leave(&bt_library_smr);

	return __btlib_insert(btl, &needle, flags, hash);
}

btref_t
btref_get(void *fp, btref_get_flags_t flags)
{
	return __btlib_get(&bt_library, fp, flags);
}

__abortlike
static void
__btref_invalid(btref_t btref)
{
	panic("trying to manipulate invalid backtrace ref: 0x%08x", btref);
}

static inline bool
__btref_isvalid(btref_t btref)
{
	return ((btref & BTREF_VALID_MASK) & ~BTREF_GET_PERMANENT) == 0;
}

btref_t
btref_retain(btref_t btref)
{
	uint32_t sig  = btref & BTREF_VALID_MASK;

	if (btref && sig == 0) {
		bt_stack_t bts = __btlib_deref(&bt_library, btref);

		btref = __btstack_retain(btref, bts, 0);
	} else if (sig & ~BTREF_PERMANENT_BIT) {
		__btref_invalid(btref);
	}

	return btref;
}

void
btref_put(btref_t btref)
{
	uint32_t sig = btref & BTREF_VALID_MASK;

	if (btref && sig == 0) {
		bt_library_t btl = &bt_library;
		bt_stack_t bts = __btlib_deref(btl, btref);

		if (__improbable(__btstack_release(bts))) {
			__btlib_remove(btl, btref, bts);
		}
	} else if (sig & ~BTREF_PERMANENT_BIT) {
		__btref_invalid(btref);
	}
}

uint32_t
btref_decode_unslide(btref_t btref, mach_vm_address_t bt_out[])
{
	static_assert(sizeof(mach_vm_address_t) == sizeof(uintptr_t));

	if (__btref_isvalid(btref)) {
		bt_stack_t bts = __btlib_deref(&bt_library, btref);
		uint32_t   len = __btstack_len(bts);

		backtrace_unpack(BTP_KERN_OFFSET_32, (uintptr_t *)bt_out,
		    BTLOG_MAX_DEPTH, (uint8_t *)bts->bts_frames,
		    sizeof(uint32_t) * len);

		for (uint32_t i = 0; i < len; i++) {
			bt_out[i] = VM_KERNEL_UNSLIDE(bt_out[i]);
		}

		return len;
	}

	__btref_invalid(btref);
}

#pragma mark btlog types and helpers

struct btlog {
	btlog_type_t            btl_type;
	uint32_t                btl_disabled : 1;
	uint32_t                btl_sample_max : 23;
#define BTL_SAMPLE_LIMIT        0x007fffffu
	uint32_t                btl_count;
	lck_ticket_t            btl_lock;
	uint32_t     *__zpercpu btl_sample;
};

struct bt_log_entry {
	vm_address_t            btle_addr;
	btref_t                 btle_where;
} __attribute__((packed, aligned(4)));

struct btlog_log {
	struct btlog            btll_hdr;
#define btll_count              btll_hdr.btl_count
	uint32_t                btll_pos;
	struct bt_log_entry     btll_entries[__counted_by(btll_count)];
};


#define BT_HASH_END_MARKER      UINT32_MAX

struct bt_hash_entry {
	vm_address_t            bthe_addr;
	uint32_t                bthe_next;
	btref_t                 bthe_where;
};

struct bt_hash_head {
	uint32_t                bthh_first;
	uint32_t                bthh_last;
};

struct btlog_hash {
	struct btlog            btlh_hdr;
#define btlh_count              btlh_hdr.btl_count
	uint32_t                btlh_pos;
	struct bt_hash_head     btlh_free;
	struct bt_hash_entry    btlh_entries[__counted_by(btlh_count)];
};

typedef union {
	vm_address_t            bta;
	struct btlog           *btl;
	struct btlog_log       *btll;
	struct btlog_hash      *btlh;
} __attribute__((transparent_union)) btlogu_t;

static LCK_GRP_DECLARE(btlog_lck_grp, "btlog");

static void
__btlog_lock(btlogu_t btlu)
{
	lck_ticket_lock(&btlu.btl->btl_lock, &btlog_lck_grp);
}

static void
__btlog_unlock(btlogu_t btlu)
{
	lck_ticket_unlock(&btlu.btl->btl_lock);
}

static void *
__btlog_elem_normalize(void *addr)
{
	addr = (void *)vm_memtag_canonicalize_address((vm_offset_t)addr);
	return addr;
}

static long
__btlog_elem_encode(void *addr)
{
	return ~(long)__btlog_elem_normalize(addr);
}

static void *
__btlog_elem_decode(long addr)
{
	return (void *)~addr;
}

static struct bt_hash_head *
__btlog_hash_hash(struct btlog_hash *btlh)
{
	return (struct bt_hash_head *)(btlh->btlh_entries + btlh->btlh_count);
}

static uint32_t
__btlog_hash_count(struct btlog_hash *btlh)
{
	return btlh->btlh_count >> 2;
}

static struct bt_hash_head *
__btlog_hash_head(struct btlog_hash *btlh, void *addr)
{
	uint32_t h = os_hash_kernel_pointer(__btlog_elem_normalize(addr));
	h &= (__btlog_hash_count(btlh) - 1);
	return &__btlog_hash_hash(btlh)[h];
}

__attribute__((overloadable))
static struct btlog_size_pair {
	vm_size_t btsp_size;
	uint32_t  btsp_count;
}
__btlog_size(btlog_type_t type, uint32_t count)
{
	struct btlog_size_pair pair = {0};

	switch (type) {
	case BTLOG_LOG:
		pair.btsp_size = round_page(sizeof(struct btlog_log) +
		    count * sizeof(struct bt_log_entry));
		pair.btsp_count = (pair.btsp_size - sizeof(struct btlog_log)) /
		    sizeof(struct bt_log_entry);
		break;

	case BTLOG_HASH:
		pair.btsp_count = MAX(1u << fls(count - 1), 128u);
		pair.btsp_size = round_page(sizeof(struct btlog_hash) +
		    pair.btsp_count * sizeof(struct bt_log_entry) +
		    (pair.btsp_count >> 2) * sizeof(struct btlog_hash));
		break;
	}

	return pair;
}

__attribute__((overloadable))
static struct btlog_size_pair
__btlog_size(btlogu_t btlu)
{
	return __btlog_size(btlu.btl->btl_type, btlu.btl->btl_count);
}

static inline btref_t
__bt_ref(uint32_t stack_and_op)
{
	return stack_and_op & ~BTREF_OP_MASK;
}

static inline btref_t
__bt_op(uint32_t stack_and_op)
{
	return stack_and_op & BTREF_OP_MASK;
}

#pragma mark btlog_log

static void
__btlog_log_destroy(struct btlog_log *btll)
{
	for (uint32_t i = 0; i < btll->btll_count; i++) {
		btref_put(__bt_ref(btll->btll_entries[i].btle_where));
	}
}

static void
__btlog_log_record(struct btlog_log *btll, void *addr, uint8_t op, btref_t btref)
{
	struct bt_log_entry *btle;
	btref_t old = BTREF_NULL;
	uint32_t pos;

	__btlog_lock(btll);

	if (__improbable(btll->btll_hdr.btl_disabled)) {
		goto disabled;
	}

	pos = btll->btll_pos;
	if (pos + 1 == btll->btll_count) {
		btll->btll_pos = 0;
	} else {
		btll->btll_pos = pos + 1;
	}

	btle  = &btll->btll_entries[pos];
	old   = __bt_ref(btle->btle_where);
	*btle = (struct bt_log_entry){
		.btle_addr  = __btlog_elem_encode(addr),
		.btle_where = btref | (op & BTREF_OP_MASK),
	};

disabled:
	__btlog_unlock(btll);

	btref_put(old);
}

#pragma mark btlog_hash

static void
__btlog_hash_init(struct btlog_hash *btlh)
{
	struct bt_hash_head *hash = __btlog_hash_hash(btlh);

	btlh->btlh_free.bthh_first = BT_HASH_END_MARKER;
	btlh->btlh_free.bthh_last = BT_HASH_END_MARKER;

	for (size_t i = 0; i < __btlog_hash_count(btlh); i++) {
		hash[i].bthh_first = BT_HASH_END_MARKER;
		hash[i].bthh_last = BT_HASH_END_MARKER;
	}
}

static void
__btlog_hash_destroy(struct btlog_hash *btlh)
{
	for (uint32_t i = 0; i < btlh->btlh_count; i++) {
		btref_put(__bt_ref(btlh->btlh_entries[i].bthe_where));
	}
}

static uint32_t
__btlog_hash_stailq_pop_first(
	struct btlog_hash      *btlh,
	struct bt_hash_head    *head)
{
	struct bt_hash_entry *bthe;
	uint32_t pos = head->bthh_first;

	bthe = &btlh->btlh_entries[pos];
	btlh->btlh_free.bthh_first = bthe->bthe_next;
	if (bthe->bthe_next == BT_HASH_END_MARKER) {
		btlh->btlh_free.bthh_last = BT_HASH_END_MARKER;
	} else {
		bthe->bthe_next = BT_HASH_END_MARKER;
	}

	return pos;
}

static void
__btlog_hash_stailq_remove(
	struct bt_hash_head    *head,
	struct bt_hash_entry   *bthe,
	uint32_t               *prev,
	uint32_t                ppos)
{
	*prev = bthe->bthe_next;
	if (bthe->bthe_next == BT_HASH_END_MARKER) {
		head->bthh_last = ppos;
	} else {
		bthe->bthe_next = BT_HASH_END_MARKER;
	}
}

static void
__btlog_hash_stailq_append(
	struct btlog_hash      *btlh,
	struct bt_hash_head    *head,
	uint32_t                pos)
{
	if (head->bthh_last == BT_HASH_END_MARKER) {
		head->bthh_first = head->bthh_last = pos;
	} else {
		btlh->btlh_entries[head->bthh_last].bthe_next = pos;
		head->bthh_last = pos;
	}
}

static void
__btlog_hash_remove(
	struct btlog_hash      *btlh,
	struct bt_hash_entry   *bthe)
{
	struct bt_hash_head *head;
	uint32_t *prev;
	uint32_t ppos;

	head = __btlog_hash_head(btlh, __btlog_elem_decode(bthe->bthe_addr));
	prev = &head->bthh_first;
	ppos = BT_HASH_END_MARKER;

	while (bthe != &btlh->btlh_entries[*prev]) {
		ppos = *prev;
		prev = &btlh->btlh_entries[ppos].bthe_next;
	}

	__btlog_hash_stailq_remove(head, bthe, prev, ppos);
}

static void
__btlog_hash_record(struct btlog_hash *btlh, void *addr, uint8_t op, btref_t btref)
{
	struct bt_hash_head *head;
	struct bt_hash_entry *bthe;
	btref_t old = BTREF_NULL;
	uint32_t pos;

	head = __btlog_hash_head(btlh, __btlog_elem_normalize(addr));

	__btlog_lock(btlh);

	if (__improbable(btlh->btlh_hdr.btl_disabled)) {
		goto disabled;
	}

	if (btlh->btlh_free.bthh_first != BT_HASH_END_MARKER) {
		pos  = __btlog_hash_stailq_pop_first(btlh, &btlh->btlh_free);
		bthe = &btlh->btlh_entries[pos];
	} else {
		pos  = btlh->btlh_pos;
		if (pos + 1 == btlh->btlh_count) {
			btlh->btlh_pos = 0;
		} else {
			btlh->btlh_pos = pos + 1;
		}
		bthe = &btlh->btlh_entries[pos];
		if (bthe->bthe_addr) {
			__btlog_hash_remove(btlh, bthe);
		}
	}

	old   = __bt_ref(bthe->bthe_where);
	*bthe = (struct bt_hash_entry){
		.bthe_addr  = __btlog_elem_encode(addr),
		.bthe_where = btref | (op & BTREF_OP_MASK),
		.bthe_next  = BT_HASH_END_MARKER,
	};

	if (btref & BTREF_VALID_MASK) {
		assert(__btlib_deref(&bt_library,
		    btref & BTREF_VALID_MASK)->bts_ref_len >= BTS_FRAMES_REF_INC);
	}

	__btlog_hash_stailq_append(btlh, head, pos);

disabled:
	__btlog_unlock(btlh);

	btref_put(old);
}

static void
__btlog_hash_erase(struct btlog_hash *btlh, void *addr)
{
	struct bt_hash_head *head;
	struct bt_hash_entry *bthe;
	uint32_t *prev;
	uint32_t pos, ppos;

	addr = __btlog_elem_normalize(addr);
	head = __btlog_hash_head(btlh, addr);
	prev = &head->bthh_first;
	ppos = BT_HASH_END_MARKER;

	__btlog_lock(btlh);

	if (__improbable(btlh->btlh_hdr.btl_disabled)) {
		goto disabled;
	}

	while ((pos = *prev) != BT_HASH_END_MARKER) {
		bthe = &btlh->btlh_entries[pos];
		if (__btlog_elem_decode(bthe->bthe_addr) == addr) {
			bthe->bthe_addr = 0;
			__btlog_hash_stailq_remove(head, bthe, prev, ppos);
			__btlog_hash_stailq_append(btlh, &btlh->btlh_free, pos);
		} else {
			ppos = *prev;
			prev = &btlh->btlh_entries[ppos].bthe_next;
		}
	}

disabled:
	__btlog_unlock(btlh);
}

#pragma mark btlog APIs

static void
__btlog_init(btlogu_t btlu)
{
	switch (btlu.btl->btl_type) {
	case BTLOG_HASH:
		__btlog_hash_init(btlu.btlh);
		break;

	case BTLOG_LOG:
		break;
	}
}

btlog_t
btlog_create(btlog_type_t type, uint32_t count, uint32_t sample)
{
	struct btlog_size_pair pair = __btlog_size(type, count);
	kern_return_t kr;
	btlogu_t btlu;

	kr = kmem_alloc(kernel_map, &btlu.bta, pair.btsp_size,
	    KMA_KOBJECT | KMA_ZERO, VM_KERN_MEMORY_DIAG);

	if (kr != KERN_SUCCESS) {
		return NULL;
	}

	if (sample > BTL_SAMPLE_LIMIT) {
		sample = BTL_SAMPLE_LIMIT;
	}

	btlu.btl->btl_type = type;
	btlu.btl->btl_sample_max = sample;
	btlu.btl->btl_count = pair.btsp_count;
	lck_ticket_init(&btlu.btl->btl_lock, &btlog_lck_grp);
	assert3u(btlu.btl->btl_count, !=, 0);

	if (sample > 1) {
		btlu.btl->btl_sample = zalloc_percpu(percpu_u64_zone,
		    Z_WAITOK | Z_ZERO | Z_NOFAIL);
		zpercpu_foreach_cpu(cpu) {
			uint32_t *counter;

			counter = zpercpu_get_cpu(btlu.btl->btl_sample, cpu);
			*counter = (cpu + 1) * sample / zpercpu_count();
		}
	}

	__btlog_init(btlu);

	return btlu.btl;
}

static void
__btlog_destroy(btlogu_t btlu)
{
	switch (btlu.btl->btl_type) {
	case BTLOG_LOG:
		__btlog_log_destroy(btlu.btll);
		break;

	case BTLOG_HASH:
		__btlog_hash_destroy(btlu.btlh);
		break;
	}
}

void
btlog_destroy(btlogu_t btlu)
{
	if (!btlu.btl->btl_disabled) {
		__btlog_destroy(btlu);
	}
	if (btlu.btl->btl_sample) {
		zfree_percpu(percpu_u64_zone, btlu.btl->btl_sample);
	}
	lck_ticket_destroy(&btlu.btl->btl_lock, &btlog_lck_grp);
	kmem_free(kernel_map, btlu.bta, __btlog_size(btlu).btsp_size);
}

kern_return_t
btlog_enable(btlogu_t btlu)
{
	vm_size_t size;
	kern_return_t kr = KERN_SUCCESS;

	size = __btlog_size(btlu).btsp_size;
	if (size > PAGE_SIZE) {
		kr = kernel_memory_populate(btlu.bta + PAGE_SIZE,
		    size - PAGE_SIZE, KMA_KOBJECT | KMA_ZERO,
		    VM_KERN_MEMORY_DIAG);
	}

	if (kr == KERN_SUCCESS) {
		__btlog_init(btlu);

		__btlog_lock(btlu);
		assert(btlu.btl->btl_disabled);
		btlu.btl->btl_disabled = false;
		__btlog_unlock(btlu);
	}

	return kr;
}

void
btlog_disable(btlogu_t btlu)
{
	vm_size_t size;

	__btlog_lock(btlu);
	assert(!btlu.btl->btl_disabled);
	btlu.btl->btl_disabled = true;
	__btlog_unlock(btlu);

	__btlog_destroy(btlu);

	size = __btlog_size(btlu).btsp_size;
	bzero((char *)btlu.bta + sizeof(*btlu.btl),
	    PAGE_SIZE - sizeof(*btlu.btl));
	if (size > PAGE_SIZE) {
		kernel_memory_depopulate(btlu.bta + PAGE_SIZE,
		    size - PAGE_SIZE, KMA_KOBJECT, VM_KERN_MEMORY_DIAG);
	}
}

btlog_type_t
btlog_get_type(btlog_t btlog)
{
	return btlog->btl_type;
}

uint32_t
btlog_get_count(btlog_t btlog)
{
	return btlog->btl_count;
}

bool
btlog_sample(btlog_t btlog)
{
	uint32_t *counter;

	if (btlog->btl_sample == NULL) {
		return true;
	}

	counter = zpercpu_get(btlog->btl_sample);
	if (os_atomic_dec_orig(counter, relaxed) != 0) {
		return false;
	}

	os_atomic_store(counter, btlog->btl_sample_max - 1, relaxed);
	return true;
}

void
btlog_record(btlogu_t btlu, void *addr, uint8_t op, btref_t btref)
{
	if (btlu.btl->btl_disabled) {
		return;
	}
	switch (btlu.btl->btl_type) {
	case BTLOG_LOG:
		__btlog_log_record(btlu.btll, addr, op, btref);
		break;

	case BTLOG_HASH:
		__btlog_hash_record(btlu.btlh, addr, op, btref);
		break;
	}
}

void
btlog_erase(btlogu_t btlu, void *addr)
{
	if (btlu.btl->btl_disabled) {
		return;
	}
	switch (btlu.btl->btl_type) {
	case BTLOG_HASH:
		__btlog_hash_erase(btlu.btlh, addr);
		break;

	case BTLOG_LOG:
		break;
	}
}

extern void
qsort(void *a, size_t n, size_t es, int (*cmp)(const void *, const void *));

struct btlog_record {
	uint32_t btr_where;
	uint32_t btr_count;
};

static int
btlog_record_cmp_where(const void *e1, const void *e2)
{
	const struct btlog_record *a = e1;
	const struct btlog_record *b = e2;

	if (a->btr_where == b->btr_where) {
		return 0;
	}
	return a->btr_where > b->btr_where ? 1 : -1;
}

static bool
btlog_records_pack(struct btlog_record *array, uint32_t *countp)
{
	uint32_t r, w, count = *countp;

	qsort(array, count, sizeof(struct btlog_record), btlog_record_cmp_where);

	for (r = 1, w = 1; r < count; r++) {
		if (array[w - 1].btr_where == array[r].btr_where) {
			array[w - 1].btr_count += array[r].btr_count;
		} else {
			array[w++] = array[r];
		}
	}

	if (w == count) {
		return false;
	}

	*countp = w;
	return true;
}

static int
btlog_record_cmp_rev_count(const void *e1, const void *e2)
{
	const struct btlog_record *a = e1;
	const struct btlog_record *b = e2;

	if (a->btr_count == b->btr_count) {
		return 0;
	}
	return a->btr_count > b->btr_count ? -1 : 1;
}

kern_return_t
btlog_get_records(
	btlogu_t                btl,
	zone_btrecord_t       **records,
	unsigned int           *numrecs)
{
	struct btlog_record *btr_array;
	struct btlog_record  btr;
	zone_btrecord_t     *rec_array;
	vm_offset_t          addr, end, size, ipc_map_size;
	kern_return_t        kr;
	uint32_t             count = 0;

	/*
	 * Step 1: collect all the backtraces in the logs in wired memory
	 *
	 *         note that the ipc_kernel_map is small, and we might have
	 *         too little space.
	 *
	 *         In order to accomodate, we will deduplicate as we go.
	 *         If we still overflow space, we return KERN_NO_SPACE.
	 */

	ipc_map_size = (vm_offset_t)(vm_map_max(ipc_kernel_map) -
	    vm_map_min(ipc_kernel_map));
	size = round_page(btlog_get_count(btl.btl) * sizeof(struct btlog_record));
	if (size > ipc_map_size) {
		size = ipc_map_size / 4;
	}

	for (;;) {
		kr = kmem_alloc(ipc_kernel_map, &addr, size,
		    KMA_DATA, VM_KERN_MEMORY_IPC);
		if (kr == KERN_SUCCESS) {
			break;
		}
		if (size < (1U << 19)) {
			return kr;
		}
		size /= 2;
	}

	btr_array = (struct btlog_record *)addr;
	rec_array = (zone_btrecord_t *)addr;
	kr = KERN_NOT_FOUND;

	__btlog_lock(btl);

	if (btl.btl->btl_disabled) {
		goto disabled;
	}

	switch (btl.btl->btl_type) {
	case BTLOG_LOG:
		for (uint32_t i = 0; i < btl.btl->btl_count; i++) {
			struct bt_log_entry *btle = &btl.btll->btll_entries[i];

			if (!btle->btle_addr) {
				break;
			}
			if ((count + 1) * sizeof(struct btlog_record) > size) {
				if (!btlog_records_pack(btr_array, &count)) {
					kr = KERN_NO_SPACE;
					count = 0;
					break;
				}
			}
			btr_array[count].btr_where = btle->btle_where;
			btr_array[count].btr_count = 1;
			count++;
		}
		break;

	case BTLOG_HASH:
		for (uint32_t i = 0; i < btl.btl->btl_count; i++) {
			struct bt_hash_entry *bthe = &btl.btlh->btlh_entries[i];

			if (!bthe->bthe_addr) {
				continue;
			}
			if ((count + 1) * sizeof(struct btlog_record) > size) {
				if (!btlog_records_pack(btr_array, &count)) {
					kr = KERN_NO_SPACE;
					count = 0;
					break;
				}
			}
			btr_array[count].btr_where = bthe->bthe_where;
			btr_array[count].btr_count = 1;
			count++;
		}
		break;
	}

	/*
	 * Step 2: unique all the records, and retain them
	 */

	if (count) {
		btlog_records_pack(btr_array, &count);
		/*
		 * If the backtraces won't fit,
		 * sort them in reverse popularity order and clip.
		 */
		if (count > size / sizeof(zone_btrecord_t)) {
			qsort(btr_array, count, sizeof(struct btlog_record),
			    btlog_record_cmp_rev_count);
			count = size / sizeof(zone_btrecord_t);
		}
		for (uint32_t i = 0; i < count; i++) {
			btref_retain(__bt_ref(btr_array[i].btr_where));
		}
	}

disabled:
	__btlog_unlock(btl);

	if (count == 0) {
		kmem_free(ipc_kernel_map, addr, size);
		return kr;
	}

	/*
	 * Step 3: Expand the backtraces in place, in reverse order.
	 */

	for (uint32_t i = count; i-- > 0;) {
		btr = *(volatile struct btlog_record *)&btr_array[i];

		rec_array[i] = (zone_btrecord_t){
			.ref_count      = btr.btr_count,
			.operation_type = __bt_op(btr.btr_where),
		};
		btref_decode_unslide(__bt_ref(btr.btr_where), rec_array[i].bt);
		btref_put(__bt_ref(btr.btr_where));
	}

	/*
	 * Step 4: Free the excess memory, zero padding, and unwire the buffer.
	 */

	end = round_page((vm_offset_t)(rec_array + count));
	bzero(rec_array + count, end - (vm_address_t)(rec_array + count));
	if (end < addr + size) {
		kmem_free(ipc_kernel_map, end, addr + size - end);
	}

	kr = vm_map_unwire(ipc_kernel_map, addr, end, FALSE);
	assert(kr == KERN_SUCCESS);

	*records = rec_array;
	*numrecs = count;
	return KERN_SUCCESS;
}

uint32_t
btlog_guess_top(btlogu_t btlu, vm_address_t bt[], uint32_t *len)
{
	struct btlog_hash *btlh = btlu.btlh;
	const unsigned RECS = 8;
	struct btlog_record recs[RECS] = {0};
	bt_stack_t bts;

	if (btlu.btl->btl_type != BTLOG_HASH) {
		return 0;
	}

	if (!lck_ticket_lock_try(&btlu.btl->btl_lock, &btlog_lck_grp)) {
		return 0;
	}

	if (btlu.btl->btl_disabled || btlh->btlh_count == 0) {
		goto disabled;
	}

	/*
	 * This is called from panic context, and can't really
	 * do what btlog_get_records() do and allocate memory.
	 *
	 * Instead, we use the refcounts in the bt library
	 * as a proxy for counts (of course those backtraces
	 * can be inflated due to being shared with other logs,
	 * which is why we use `RECS` slots in the array to find
	 * the RECS more popular stacks at all).
	 *
	 * Note: this will break down if permanent backtraces get used.
	 *       if we ever go there for performance reasons,
	 *       then we'll want to find another way to do this.
	 */
	for (uint32_t i = 0; i < btlh->btlh_count; i++) {
		struct bt_hash_entry *bthe = &btlh->btlh_entries[i];
		btref_t ref;

		if (!bthe->bthe_addr) {
			continue;
		}

		ref = __bt_ref(bthe->bthe_where);
		bts = __btlib_deref(&bt_library, ref);

		for (uint32_t j = 0; j < RECS; j++) {
			if (ref == recs[j].btr_where) {
				break;
			}
			if (bts->bts_ref_len > recs[j].btr_count) {
				for (uint32_t k = j + 1; k < RECS; k++) {
					recs[k] = recs[k - 1];
				}
				recs[j].btr_count = bts->bts_ref_len;
				recs[j].btr_where = ref;
				break;
			}
		}
	}

	/*
	 * Then correct what we sampled by counting how many times
	 * the backtrace _actually_ exists in that one log.
	 */
	for (uint32_t j = 0; j < RECS; j++) {
		recs[j].btr_count = 0;
	}

	for (uint32_t i = 0; i < btlh->btlh_count; i++) {
		struct bt_hash_entry *bthe = &btlh->btlh_entries[i];
		btref_t ref;

		if (!bthe->bthe_addr) {
			continue;
		}

		ref = __bt_ref(bthe->bthe_where);

		for (uint32_t j = 0; j < RECS; j++) {
			if (recs[j].btr_where == ref) {
				recs[j].btr_count++;
				break;
			}
		}
	}

	for (uint32_t j = 1; j < RECS; j++) {
		if (recs[0].btr_count < recs[j].btr_count) {
			recs[0] = recs[j];
		}
	}
	bts = __btlib_deref(&bt_library, recs[0].btr_where);
	*len = __btstack_len(bts);

	backtrace_unpack(BTP_KERN_OFFSET_32, (uintptr_t *)bt, BTLOG_MAX_DEPTH,
	    (uint8_t *)bts->bts_frames, sizeof(uint32_t) * *len);

disabled:
	__btlog_unlock(btlu);

	return recs[0].btr_count;
}

#if DEBUG || DEVELOPMENT

void
btlog_copy_backtraces_for_elements(
	btlogu_t                btlu,
	vm_address_t           *instances,
	uint32_t               *countp,
	uint32_t                elem_size,
	leak_site_proc          proc)
{
	struct btlog_hash *btlh = btlu.btlh;
	struct bt_hash_head *head;
	uint32_t count = *countp;
	uint32_t num_sites = 0;

	if (btlu.btl->btl_type != BTLOG_HASH) {
		return;
	}

	__btlog_lock(btlh);

	if (btlu.btl->btl_disabled) {
		goto disabled;
	}

	for (uint32_t i = 0; i < count; i++) {
		vm_offset_t element = instances[i];
		void *addr = __btlog_elem_normalize((void *)element);
		btref_t ref = BTREF_NULL;
		uint32_t pos;

		if (kInstanceFlagReferenced & element) {
			continue;
		}

		element = INSTANCE_PUT(element) & ~kInstanceFlags;
		head = __btlog_hash_head(btlh, addr);
		pos  = head->bthh_first;
		while (pos != BT_HASH_END_MARKER) {
			struct bt_hash_entry *bthe = &btlh->btlh_entries[pos];

			if (__btlog_elem_decode(bthe->bthe_addr) == addr) {
				ref = __bt_ref(bthe->bthe_where);
				break;
			}

			pos = bthe->bthe_next;
		}

		if (ref != BTREF_NULL) {
			element = (ref | kInstanceFlagReferenced);
		}
		instances[num_sites++] = INSTANCE_PUT(element);
	}

	for (uint32_t i = 0; i < num_sites; i++) {
		vm_offset_t btref = instances[i];
		uint32_t site_count, dups;

		if (!(btref & kInstanceFlagReferenced)) {
			continue;
		}

		for (site_count = 1, dups = i + 1; dups < num_sites; dups++) {
			if (instances[dups] == btref) {
				site_count++;
				instances[dups] = 0;
			}
		}

		btref = INSTANCE_PUT(btref) & ~kInstanceFlags;
		proc(site_count, elem_size, (btref_t)btref);
	}

disabled:
	__btlog_unlock(btlh);

	*countp = num_sites;
}

#endif /* DEBUG || DEVELOPMENT */
