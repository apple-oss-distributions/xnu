/*
 * Copyright (c) 2010-2020 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */

#include <kern/locks_internal.h>
#include <kern/kern_types.h>
#include <kern/ledger.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/coalition.h>

#include <kern/processor.h>
#include <kern/machine.h>
#include <kern/queue.h>
#include <kern/policy_internal.h>

#include <sys/errno.h>

#include <libkern/OSAtomic.h>
#include <mach/mach_types.h>
#include <os/overflow.h>

#include <vm/pmap.h>

/*
 * Ledger entry flags.
 */
#define LEDGER_ACTION_BLOCK     0x0010
#define LEDGER_ACTION_CALLBACK  0x0020
#define LEDGER_ACTION_MASK      0x0030
#define LF_WAKE_NEEDED          0x0100  /* one or more threads are asleep */
#define LF_WAKE_INPROGRESS      0x0200  /* the wait queue is being processed */
#define LF_REFILL_SCHEDULED     0x0400  /* a refill timer has been set */
#define LF_REFILL_INPROGRESS    0x0800  /* the ledger is being refilled */
#define LF_CALLED_BACK          0x1000  /* callback was called for balance in deficit */
#define LF_WARNED               0x2000  /* callback was called for balance warning */
#define LF_PANIC_ON_NEGATIVE    0x8000  /* panic if it goes negative */
#define LF_DIAG_WARNED          0x20000 /* callback was called for balance diag */
#define LF_DIAG_DISABLED        0x40000 /* diagnostics threshold are disabled at the moment */

#define LEDGER_DIAG_MEM_THRESHOLD_INFINITY ((uint16_t)((1ULL << 16) - 1))

#define LEDGER_DIAG_MEM_THRESHOLD_SHIFT 20
#define LEDGER_DIAG_MEM_AMOUNT_TO_THRESHOLD(X)   ((X) >> (LEDGER_DIAG_MEM_THRESHOLD_SHIFT))
#define LEDGER_DIAG_MEM_AMOUNT_FROM_THRESHOLD(X) (((ledger_amount_t)(X)) << (LEDGER_DIAG_MEM_THRESHOLD_SHIFT))

/*
 * struct ledger_entry_info is available to user space and used in ledger() syscall.
 * Changing its size would cause memory corruption. See rdar://132747700
 */
static_assert(sizeof(struct ledger_entry_info) == (6 * sizeof(int64_t)));
static_assert(sizeof(struct ledger_entry_info_v2) == (11 * sizeof(int64_t)));

#if XNU_MONITOR
#define __ppl_only(...)  __VA_ARGS__
#else
#define __ppl_only(...)
#endif

typedef union ledger_pair {
	__uint128_t             lp_pair;
	struct {
		ledger_amount_t lp_credit;
		ledger_amount_t lp_debit;
	};
} ledger_pair_t;

/*!
 * @abstract
 * Type used for per-CPU open tabs for ledgers.
 *
 * @discussion
 * In order to avoid costly back and forths with the main ledger, scalable
 * ledger entries can do fast accounting with per-CPU tabs.
 *
 * Not unlike real life, when a ledger is no longer active, it must settle
 * its tab.
 */
struct ledger_tab {
	ledger_t                lt_open;      /**< which ledger has an open tab */
	uint64_t                lt_mask;      /**< mask of non 0 entries in lt_pairs[] */
	union {
		struct {
			uint32_t lt_ipi_ack;   /**< force settle flag */
			uint32_t lt_lock;      /**< reentrancy lock */
		};
		uint64_t        lt_ipi_and_lock;
	};
#if XNU_MONITOR
	bool                    lt_ppl_ast;   /**< PPL only: deferred AST */
#endif /* XNU_MONITOR */

	ledger_pair_t           lt_pairs[];
};

struct ledger {
	uint64_t                l_id;
	ledger_template_t       l_template;
	os_ref_atomic_t         l_refs;
	/* storage for ledgers follows */
} __attribute__((aligned(16)));

static_assert(sizeof(struct ledger) == LEDGER_HEADER_SIZE);

typedef struct ledger_entry_small {
	uint32_t                les_flags;
	uint16_t                les_warn_percent;
	uint16_t                les_diag_threshold_scaled;
	ledger_amount_t         les_credit;
} *ledger_entry_small_t;

static_assert(sizeof(struct ledger_entry_small) == LEDGER_ENTRY_SMALL_SIZE);

typedef struct ledger_entry {
	uint32_t                le_flags;
	uint16_t                le_warn_percent;
	uint16_t                le_diag_threshold_scaled;
	ledger_amount_t         le_credit;
	ledger_amount_t         le_debit;
	ledger_amount_t         le_limit;
	union {
		struct {
			/*
			 * XXX - the following two fields can go away if we move all of
			 * the refill logic into process policy
			 */
			uint64_t le_refill_period;
			uint64_t le_last_refill;
		};
		struct {
			ledger_amount_t le_lifetime_max; /* Process lifetime peak */
			ledger_amount_t le_interval_max; /* Interval peak XXX better name needed */
		};
	};
} *ledger_entry_t;

static_assert(sizeof(struct ledger_entry) == LEDGER_ENTRY_SIZE);

#define LEDGER_WARN_THRESHOLD_NONE     0
#define LEDGER_WARN_PERCENT_100        0x8000
#define LEDGER_DIAG_THRESHOLD_NONE     0
#define LEDGER_DIAG_STHRESHOLD_SHIFT   20

TUNABLE(bool, pmap_ledgers_panic, "pmap_ledgers_panic", LEDGER_HAS_FEAT_ASSERT_POSITIVE);
TUNABLE(int, pmap_ledgers_panic_leeway, "pmap_ledgers_panic_leeway", 3);
os_refgrp_decl(static, ledger_refgrp, "ledger", NULL);
static uint64_t ledger_next_id = 0;
static thread_t PERCPU_DATA(ledger_current_thread);


#pragma mark entry helpers

#define ENTRY_ID_OFFSET_MASK     0x0000ffff
#define ENTRY_ID_COUNTER_SHIFT   16
#define ENTRY_ID_COUNTER_MASK    0x003f0000
#define ENTRY_ID_FEATURES_MASK   0xffc00000
static_assert(ENTRY_ID_COUNTER_MASK >> ENTRY_ID_COUNTER_SHIFT ==
    LEDGER_SCALABLE_MAX - 1,
    "counter mask won't fit ledger_tab::lt_mask");

/* Determine whether a ledger entry exists */
__attribute__((const, always_inline, overloadable))
static inline bool
le_valid(ledger_t ledger, ledger_entry_id_t entry)
{
	return LEDGER_VALID(ledger) && entry != LEDGER_ENTRY_ID_INVALID;
}

__attribute__((const, always_inline, overloadable))
static inline bool
le_valid(ledger_t ledger, ledger_entry_id_t entry, ledger_id_flags_t features)
{
	return le_valid(ledger, entry) && (entry & features);
}

__attribute__((always_inline))
static inline spl_t
spl_ledger(ledger_t ledger)
{
	thread_t self = current_thread();

	/*
	 * The current thread ledger balances can be refilled and checked
	 * in interrupt context. We must as a result disable interrupts
	 * for certain updates that would affect refill.
	 *
	 * Updates to these fields must be protected:
	 * - le_last_refill
	 * - le_refill_period
	 * - le_limit
	 */
	if (ledger == self->t_threadledger || ledger == self->t_ledger) {
		return splsched();
	}
	return 0;
}

static inline void
splx_ledger(spl_t s)
{
	if (s) {
		splx(s);
	}
}

__attribute__((const, always_inline))
static ledger_entry_small_t
le_get_small(ledger_t ledger, ledger_entry_id_t entry)
{
	vm_address_t offset = (entry & ENTRY_ID_OFFSET_MASK);

	return (ledger_entry_small_t)((vm_address_t)ledger + offset);
}

__attribute__((const, always_inline))
static ledger_entry_t
le_get(ledger_t ledger, ledger_entry_id_t entry)
{
	vm_address_t offset = (entry & ENTRY_ID_OFFSET_MASK);

	return (ledger_entry_t)((vm_address_t)ledger + offset);
}

__attribute__((always_inline))
static inline uint32_t *
le_flagsp(ledger_t ledger, ledger_entry_id_t entry)
{
	return &le_get_small(ledger, entry)->les_flags;
}

__attribute__((const, always_inline))
static inline ledger_amount_t
lp_balance(ledger_pair_t pair)
{
	return pair.lp_credit - pair.lp_debit;
}

__attribute__((const, always_inline))
static inline ledger_amount_t
le_balance(const struct ledger_entry *le)
{
	return le->le_credit - le->le_debit;
}

__attribute__((const, always_inline))
static inline uint32_t
le_counter(ledger_entry_id_t entry)
{
	return (entry & ENTRY_ID_COUNTER_MASK) >> ENTRY_ID_COUNTER_SHIFT;
}

__attribute__((always_inline))
static ledger_amount_t
le_warn_limit(ledger_entry_t le)
{
	if (le->le_warn_percent != LEDGER_WARN_THRESHOLD_NONE) {
		return le->le_limit * le->le_warn_percent / LEDGER_WARN_PERCENT_100;
	}
	return LEDGER_LIMIT_INFINITY;
}

#if LEDGER_HAS_FEAT_DIAG
static inline bool ledger_is_diag_threshold_enabled_internal(struct ledger_entry *le);

__attribute__((always_inline))
static ledger_amount_t
le_diag_limit(ledger_entry_t le)
{
	if (le->le_diag_threshold_scaled == LEDGER_DIAG_MEM_THRESHOLD_INFINITY) {
		return LEDGER_LIMIT_INFINITY;
	}
	if (!ledger_is_diag_threshold_enabled_internal(le)) {
		return LEDGER_LIMIT_INFINITY;
	}
	return LEDGER_DIAG_MEM_AMOUNT_FROM_THRESHOLD(le->le_diag_threshold_scaled);
}
#endif /* LEDGER_HAS_FEAT_DIAG */

__abortlike
static void
le_balance_negative_panic(ledger_t ledger, ledger_entry_id_t entry)
{
	ledger_amount_t credit = le_get_small(ledger, entry)->les_credit;
	ledger_amount_t debit  = 0;

	if (entry & LFEAT_DEBIT) {
		debit = le_get(ledger, entry)->le_debit;
		panic("ledger(%p) has entry(%p) with negative balance:%lld,"
		    " credit:%lld, debit:%lld",
		    ledger, le_get(ledger, entry), credit - debit, credit, debit);
	} else {
		panic("ledger(%p) has entry(%p) with negative balance:%lld",
		    ledger, le_get_small(ledger, entry), credit);
	}
}

static void
le_update_maximum(ledger_entry_t le, ledger_amount_t balance)
{
	if (balance > le->le_interval_max) {
		le->le_interval_max = balance;
		if (balance > le->le_lifetime_max) {
			le->le_lifetime_max = balance;
		}
	}
}


#pragma mark ledger templates and lifecycle

#if __BUILDING_XNU_LIB_UNITTEST__
#define lt_require_data_const(lt)      ((void)0)
#else
static void
lt_require_data_const(ledger_template_t lt)
{
	extern const char data_const_start[] __SEGMENT_START_SYM("__DATA_CONST");
	extern const char data_const_end[] __SEGMENT_END_SYM("__DATA_CONST");

	assert(data_const_start <= (const char *)lt &&
	    (const char *)(lt + 1) <= data_const_end);
	if (lt->lt_cnt) {
		assert(data_const_start <= (const char *)lt->lt_entries &&
		    (const char *)(lt->lt_entries + lt->lt_cnt) <= data_const_end);
	}
}
#endif

void
ledger_template_finalize(ledger_template_t lt, ledger_tpl_options_t options)
{
	uint32_t offset   = sizeof(struct ledger);
	uint32_t counters = 0;

	assert(!lt->lt_size);
	lt_require_data_const(lt);

	for (uint16_t idx = 0; idx < lt->lt_cnt; idx++) {
		ledger_entry_template_t et = &lt->lt_entries[idx];
		ledger_id_flags_t       id = et->et_id;

		/*
		 * Validate entries
		 */
		if (!__ledger_features_valid(id)) {
			panic("Key `%s' has invalid features selected: %x",
			    et->et_key, id);
		}
		if ((options & LEDGER_TPL_SCALABLE) == 0) {
			id &= ~LFEAT_SCALABLE;
		}

		/*
		 * Fixup flags
		 */
		if (id & LFEAT_SCALABLE) {
			/* scalable counters makes this racy */
			id &= ~LFEAT_ASSERT_POSITIVE;
		}
		if (id & LFEAT_REFILL) {
			id |= LFEAT_DEBIT;
		}
		if (et->et_callback) {
			id |= LFEAT_CALLBACK;
		} else {
			id &= ~(LFEAT_DIAG | LFEAT_CALLBACK);
		}

		/*
		 * Compute offset.
		 */
		et->et_id = offset | (counters << ENTRY_ID_COUNTER_SHIFT) | id;

		if (id & LFEAT_LARGE_MASK) {
			offset += sizeof(struct ledger_entry);
		} else {
			offset += sizeof(struct ledger_entry_small);
		}
		if ((offset & ENTRY_ID_OFFSET_MASK) != offset) {
			panic("too many entries");
		}
		if (id & LFEAT_SCALABLE) {
			if (counters == LEDGER_SCALABLE_MAX) {
				panic("too many scalable counters");
			}
			lt->lt_counter_lut[counters++] = et->et_id;
		}
	}

	if (counters) {
		lt->lt_tabs = zalloc_percpu_permanent(sizeof(struct ledger_tab) +
		    sizeof(ledger_pair_t) * counters, 15);
	}

#if !CONFIG_SPTM && XNU_MONITOR
	if (options & LEDGER_TPL_SECURE_ALLOC) {
		assert(lt == &task_ledger_template);
	} else
#endif
	{
		(void)options;
		lt->lt_zone = zone_create(lt->lt_name, offset, ZC_NONE);
	}

	/* mark the ledger as initialized */
	lt->lt_size = (uint16_t)offset;
	lt->lt_counters = (uint16_t)counters;
}

void
ledger_template_copy(ledger_template_t lt, ledger_template_t src)
{
	const char *name = lt->lt_name;

	assert(!lt->lt_size && src->lt_size);
	lt_require_data_const(lt);
	lt_require_data_const(src);

	*lt = *src;
	lt->lt_name = name;
#if !CONFIG_SPTM && XNU_MONITOR
	if (lt->lt_zone == NULL) {
		lt->lt_zone = zone_create(name, lt->lt_size, ZC_NONE);
	}
#endif
	if (lt->lt_counters != 0) {
		vm_size_t size = sizeof(struct ledger_entry_template) * lt->lt_cnt;

		lt->lt_tabs = NULL;
		lt->lt_counters = 0;
		lt->lt_entries = zalloc_permanent(size,
		    ZALIGN(struct ledger_entry_template));
		for (uint16_t i = 0; i < lt->lt_cnt; i++) {
			lt->lt_entries[i] = src->lt_entries[i];
			lt->lt_entries[i].et_id &= ~LFEAT_SCALABLE;
		}

		bzero(lt->lt_counter_lut, sizeof(lt->lt_counter_lut));
	}
}

ledger_entry_id_t
ledger_key_lookup(ledger_template_t lt, const char *key, bool required)
{
	assert(lt->lt_size);

	for (uint16_t idx = 0; idx < lt->lt_cnt; idx++) {
		ledger_entry_template_t et = &lt->lt_entries[idx];

		if (strcmp(key, et->et_key) == 0) {
			return et->et_id;
		}
	}

	if (required) {
		panic("Unable to find entry `%s' in %p", key, lt);
	}
	return LEDGER_ENTRY_ID_INVALID;
}

ledger_t
ledger_instantiate(ledger_template_t lt)
{
	ledger_t ledger;

	assert(lt->lt_size);
#if !CONFIG_SPTM && XNU_MONITOR
	if (lt->lt_zone == NULL) {
		/*
		 * If the template doesn't contain a zone to allocate ledger
		 * objects from, then assume that these ledger objects were
		 * allocated by the pmap. This is done on PPL-enabled systems
		 * to give the PPL a method of validating ledger objects when
		 * updating them from within the PPL.
		 */
		ledger = pmap_ledger_alloc();
		bzero(ledger, lt->lt_size);
	} else
#endif
	{
		ledger = zalloc_flags(lt->lt_zone, Z_WAITOK_ZERO_NOFAIL);
	}

	ledger->l_id = os_atomic_inc_orig(&ledger_next_id, relaxed);
	ledger->l_template = lt;
	os_ref_init_raw(&ledger->l_refs, &ledger_refgrp);

	for (uint16_t i = 0; i < lt->lt_cnt; i++) {
		ledger_entry_template_t et  = &lt->lt_entries[i];
		ledger_entry_id_t       id  = et->et_id;
		ledger_entry_small_t    les = le_get_small(ledger, id);

		if ((id & LFEAT_ASSERT_POSITIVE) && pmap_ledgers_panic) {
			les->les_flags |= LF_PANIC_ON_NEGATIVE;
		}
		if (et->et_callback) {
			les->les_flags |= LEDGER_ACTION_CALLBACK;
		}
		if (id & LFEAT_LARGE_MASK) {
			ledger_entry_t le = le_get(ledger, id);
			le->le_limit = LEDGER_LIMIT_INFINITY;
			le->le_diag_threshold_scaled = LEDGER_DIAG_MEM_THRESHOLD_INFINITY;
		}
	}

	return ledger;
}

__attribute__((noinline))
static void
le_free(ledger_t ledger)
{
	ledger_template_t lt = ledger->l_template;

#if !CONFIG_SPTM && XNU_MONITOR
	if (lt->lt_zone == NULL) {
		/*
		 * If the template doesn't contain a zone to allocate ledger
		 * objects from, then assume that these ledger objects were
		 * allocated by the pmap. This is done on PPL-enabled systems
		 * to give the PPL a method of validating ledger objects when
		 * updating them from within the PPL.
		 */
		pmap_ledger_free(ledger);
	} else
#endif
	{
		zfree(lt->lt_zone, ledger);
	}
}

void
ledger_reference(ledger_t ledger)
{
	if (LEDGER_VALID(ledger)) {
		os_ref_retain_raw(&ledger->l_refs, &ledger_refgrp);
	}
}

void
ledger_dereference(ledger_t ledger)
{
	if (LEDGER_VALID(ledger) &&
	    os_ref_release_raw(&ledger->l_refs, &ledger_refgrp) == 0) {
		le_free(ledger);
	}
}


#pragma mark unsorted

/* ledger ast helper functions */
static uint32_t ledger_check_needblock(ledger_t l, uint64_t now);
static kern_return_t ledger_perform_blocking(ledger_t l);
static uint32_t flag_set(volatile uint32_t *flags, uint32_t bit);
static uint32_t flag_clear(volatile uint32_t *flags, uint32_t bit);

/************************************/

static uint64_t
abstime_to_nsecs(uint64_t abstime)
{
	uint64_t nsecs;

	absolutetime_to_nanoseconds(abstime, &nsecs);
	return nsecs;
}

static uint64_t
nsecs_to_abstime(uint64_t nsecs)
{
	uint64_t abstime;

	nanoseconds_to_absolutetime(nsecs, &abstime);
	return abstime;
}

static uint32_t
flag_set(volatile uint32_t *flags, uint32_t bit)
{
	return OSBitOrAtomic(bit, flags);
}

static uint32_t
flag_clear(volatile uint32_t *flags, uint32_t bit)
{
	return OSBitAndAtomic(~bit, flags);
}

/*
 * Determine whether an entry has exceeded its limit.
 */
static inline bool
limit_exceeded(struct ledger_entry *le)
{
	return le_balance(le) > le->le_limit;
}

/*
 * If the ledger value is positive, wake up anybody waiting on it.
 */
static inline void
ledger_limit_entry_wakeup(struct ledger_entry *le)
{
	if (!limit_exceeded(le)) {
		while (le->le_flags & LF_WAKE_NEEDED) {
			flag_clear(&le->le_flags, LF_WAKE_NEEDED);
			thread_wakeup((event_t)le);
		}
	}
}

/*
 * Refill the coffers.
 */
static void
ledger_refill(ledger_entry_t le, uint64_t now, ledger_amount_t *balancep)
{
	uint64_t elapsed, period, periods;
	ledger_amount_t balance, due;

	assert(le->le_limit != LEDGER_LIMIT_INFINITY);

	/*
	 * If another thread is handling the refill already, we're not
	 * needed.
	 */
	if (flag_set(&le->le_flags, LF_REFILL_INPROGRESS) & LF_REFILL_INPROGRESS) {
		return;
	}

	/*
	 * If the timestamp we're about to use to refill is older than the
	 * last refill, then someone else has already refilled this ledger
	 * and there's nothing for us to do here.
	 */
	if (now <= le->le_last_refill) {
		flag_clear(&le->le_flags, LF_REFILL_INPROGRESS);
		return;
	}

	/*
	 * See how many refill periods have passed since we last
	 * did a refill.
	 */
	period = le->le_refill_period;
	elapsed = now - le->le_last_refill;
	if ((period == 0) || (elapsed < period)) {
		flag_clear(&le->le_flags, LF_REFILL_INPROGRESS);
		return;
	}

	/*
	 * Optimize for the most common case of only one or two
	 * periods elapsing.
	 */
	periods = 0;
	while ((periods < 2) && (elapsed > 0)) {
		periods++;
		elapsed -= period;
	}

	/*
	 * OK, it's been a long time.  Do a divide to figure out
	 * how long.
	 */
	if (elapsed > 0) {
		periods = (now - le->le_last_refill) / period;
	}

	balance = le_balance(le);
	due = periods * le->le_limit;

	if (balance - due < 0) {
		due = balance;
	}

	os_atomic_add(&le->le_debit, due, relaxed);

	/*
	 * If we've completely refilled the pool, set the refill time to now.
	 * Otherwise set it to the time at which it last should have been
	 * fully refilled.
	 */
	if (balance == due) {
		le->le_last_refill = now;
	} else {
		le->le_last_refill += (le->le_refill_period * periods);
	}
	*balancep = balance - due;

	flag_clear(&le->le_flags, LF_REFILL_INPROGRESS);

	if (!limit_exceeded(le)) {
		flag_clear(&le->le_flags, LF_CALLED_BACK);
		ledger_limit_entry_wakeup(le);
	}
}

static void
le_set_ast(__ppl_only(bool from_ppl))
{
#if XNU_MONITOR
	pmap_cpu_data_t *cpu_data;

	if (from_ppl &&
	    (cpu_data = pmap_get_cpu_data())->ppl_state == PPL_STATE_DISPATCH) {
		int cpu = cpu_data->cpu_number;
		zpercpu_get_cpu(task_ledger_template.lt_tabs, cpu)->lt_ppl_ast = true;
		return;
	}
#endif
	/*
	 * The ledger AST may need to be set while already holding
	 * the thread lock.  This routine skips sending the IPI,
	 * allowing us to avoid the lock hold.
	 *
	 * However, it means the targeted thread must context switch
	 * to recognize the ledger AST.
	 */
	spl_t    spl     = splsched();
	thread_t thread  = *PERCPU_GET(ledger_current_thread);

	if (thread) {
		thread_ast_set(thread, AST_LEDGER);
	} else {
		thread = current_thread();

		thread_ast_set(thread, AST_LEDGER);
		ast_propagate(thread);
	}

	splx_ledger(spl);
}

/*!
 * @abstract
 * Perform updates needed for refills.
 *
 * @discussion
 * The caller must have checked that LFEAT_REFILL is enabled for the ledger
 * entry, and that LF_REFILL_SCHEDULED is active on this entry.
 */
__result_use_check
static ledger_amount_t
le_check_refill(ledger_entry_t le, ledger_amount_t balance)
{
	uint64_t now = mach_absolute_time();

	if ((now - le->le_last_refill) > le->le_refill_period) {
		ledger_refill(le, now, &balance);
	}

	if (balance > le->le_limit) {
		if (le->le_flags & LEDGER_ACTION_BLOCK) {
			le_set_ast(__ppl_only(false));
		}
	} else {
		if (le->le_flags & LF_WAKE_NEEDED) {
			ledger_limit_entry_wakeup(le);
		}
	}

	return balance;
}

static void
le_check_callback(ledger_entry_t le, ledger_amount_t balance __ppl_only(, bool from_ppl))
{
	if (balance > le->le_limit) {
		if (!(le->le_flags & LF_CALLED_BACK)) {
			le_set_ast(__ppl_only(from_ppl));
		}
	} else {
		if (le->le_flags & LF_CALLED_BACK) {
			flag_clear(&le->le_flags, LF_CALLED_BACK);
		}

		if (balance > le_warn_limit(le)) {
			/*
			 * If we are above the warning level and have not yet
			 * invoked the callback, set the AST so it can be done
			 * before returning to userland.
			 */
			if (!(le->le_flags & LF_WARNED)) {
				le_set_ast(__ppl_only(from_ppl));
			}
		} else {
			if (le->le_flags & LF_WARNED) {
				flag_clear(&le->le_flags, LF_WARNED);
			}
		}
	}
}

#if LEDGER_HAS_FEAT_DIAG
static void
le_check_diag(ledger_entry_t le, ledger_amount_t balance __ppl_only(, bool from_ppl))
{
	if ((le->le_flags & (LF_DIAG_DISABLED | LF_DIAG_WARNED)) == 0 &&
	    balance > le_diag_limit(le)) {
		le_set_ast(__ppl_only(from_ppl));
	}
}
#endif /* LEDGER_HAS_FEAT_DIAG */

/*
 * Returns whether the bartender will be mad if that tab keeps growing...
 */
__attribute__((always_inline))
static bool
le_should_settle(ledger_t ledger, ledger_entry_id_t entry, ledger_pair_t *pair)
{
	ledger_amount_t balance = lp_balance(*pair);

	if ((entry & LFEAT_DEBIT) == 0 && balance == 0) {
		pair->lp_pair = 0;
		return true;
	}

	if (entry & (LFEAT_MAXIMUM | LFEAT_CALLBACK)) {
		ledger_entry_t  le    = le_get(ledger, entry);
		ledger_amount_t proj  = le_balance(le) + balance * zpercpu_count();
		uint32_t        flags = le->le_flags;

		if ((entry & LFEAT_MAXIMUM) && proj > le->le_interval_max) {
			return true;
		}

		if ((entry & LFEAT_CALLBACK) && (flags & LEDGER_ACTION_CALLBACK)) {
			if ((bool)(flags & LF_CALLED_BACK) != (proj > le->le_limit)) {
				return true;
			}

			if (le->le_warn_percent != LEDGER_WARN_THRESHOLD_NONE &&
			    (bool)(flags & LF_WARNED) != (proj > le_warn_limit(le))) {
				return true;
			}

#if LEDGER_HAS_FEAT_DIAG
			if ((entry & LFEAT_DIAG) &&
			    !(flags & (LF_DIAG_DISABLED | LF_DIAG_WARNED)) &&
			    balance > le_diag_limit(le)) {
				return true;
			}
#endif /* LEDGER_HAS_FEAT_DIAG */
		}
	}

	return false;
}

__attribute__((always_inline))
static void
le_check_inline(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         balance,
	int64_t                 direction
	__ppl_only(, bool       from_ppl))
{
	bool credit = direction >= 0;
	bool debit  = direction <= 0;

	ledger_entry_t le = le_get(ledger, entry);

	if (__improbable(debit && balance < 0)) {
		if (*le_flagsp(ledger, entry) & LF_PANIC_ON_NEGATIVE) {
			le_balance_negative_panic(ledger, entry);
		}
	}

	if ((entry & LFEAT_REFILL) && (le->le_flags & LF_REFILL_SCHEDULED)) {
		balance = le_check_refill(le, balance);
	}
	if (credit && (entry & LFEAT_MAXIMUM)) {
		le_update_maximum(le, balance);
	}
	if ((entry & LFEAT_CALLBACK) && (le->le_flags & LEDGER_ACTION_CALLBACK)) {
		le_check_callback(le, balance __ppl_only(, from_ppl));
#if LEDGER_HAS_FEAT_DIAG
		if (credit && (entry & LFEAT_DIAG)) {
			le_check_diag(le, balance __ppl_only(, from_ppl));
		}
#endif /* LEDGER_HAS_FEAT_DIAG */
	}
}

__attribute__((noinline))
static void
le_check(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         balance,
	int64_t                 direction
	__ppl_only(, bool       from_ppl))
{
	le_check_inline(ledger, entry, balance, direction __ppl_only(, from_ppl));
}

__attribute__((noinline))
static void
le_check_credit(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         balance
	__ppl_only(, bool       from_ppl))
{
	le_check_inline(ledger, entry, balance, +1 __ppl_only(, from_ppl));
}

__attribute__((noinline))
static void
le_check_debit(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         balance
	__ppl_only(, bool       from_ppl))
{
	le_check_inline(ledger, entry, balance, -1 __ppl_only(, from_ppl));
}

void
ledger_check_new_balance(ledger_t ledger, ledger_entry_id_t entry)
{
	ledger_amount_t balance;

	if (ledger_get_balance(ledger, entry, LEO_SETTLE, &balance) == KERN_SUCCESS) {
		le_check(ledger, entry, balance, 0 __ppl_only(, false));
	}
}

/*
 * Add value to an entry in a ledger for a specific thread.
 */
__attribute__((always_inline))
static void
le_credit(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount
	__ppl_only(, bool       from_ppl))
{
	ledger_entry_small_t les = le_get_small(ledger, entry);
	ledger_amount_t balance;

	balance = os_atomic_add(&les->les_credit, amount, relaxed);
	if (entry & LFEAT_DEBIT) {
		balance -= le_get(ledger, entry)->le_debit;
	}

	if (entry & (LFEAT_REFILL | LFEAT_MAXIMUM | LFEAT_CALLBACK)) {
		le_check_credit(ledger, entry, balance __ppl_only(, from_ppl));
	}
}

__attribute__((always_inline))
static void
le_debit(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount
	__ppl_only(, bool       from_ppl))
{
	ledger_entry_small_t les = le_get_small(ledger, entry);
	ledger_amount_t balance;

	if (entry & LFEAT_DEBIT) {
		balance  = les->les_credit;
		balance -= os_atomic_add(&le_get(ledger, entry)->le_debit, amount, relaxed);
	} else {
		balance  = os_atomic_sub(&les->les_credit, amount, relaxed);
	}

	if (entry & (LFEAT_ASSERT_POSITIVE | LFEAT_REFILL | LFEAT_MAXIMUM | LFEAT_CALLBACK)) {
		le_check_debit(ledger, entry, balance __ppl_only(, from_ppl));
	}
}

__attribute__((always_inline))
static void
le_tab_merge(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_pair_t           pair
	__ppl_only(, bool       from_ppl))
{
	ledger_amount_t balance;

	if (entry & LFEAT_DEBIT) {
		ledger_entry_t le = le_get(ledger, entry);

		balance  = os_atomic_add(&le->le_credit,
		    pair.lp_credit, relaxed);
		balance -= os_atomic_add(&le->le_debit,
		    pair.lp_debit, relaxed);
	} else {
		ledger_entry_small_t les = le_get_small(ledger, entry);

		balance = os_atomic_add(&les->les_credit,
		    lp_balance(pair), relaxed);
	}

	if (entry & (LFEAT_MAXIMUM | LFEAT_CALLBACK)) {
		le_check(ledger, entry, balance,
		    lp_balance(pair) __ppl_only(, from_ppl));
	}
}

__attribute__((noinline))
static void
le_tab_settle(ledger_template_t lt, ledger_tab_t tab)
{
	ledger_t ledger = tab->lt_open;

	assert(!tab->lt_lock);
	os_atomic_store(&tab->lt_lock, true, compiler_acquire);

	for (uint64_t mask = tab->lt_mask; mask; mask &= mask - 1) {
		uint32_t      idx   = __builtin_ffsll(mask) - 1;
		uint32_t      entry = lt->lt_counter_lut[idx];
		ledger_pair_t pair  = tab->lt_pairs[idx];

		/*
		 * do -not- skip amount == 0, le_tab_{credit,debit}()
		 * relies on this performing the check again.
		 */

		tab->lt_pairs[idx].lp_pair = 0;
		le_tab_merge(ledger, entry, pair __ppl_only(, false));
	}

	os_atomic_thread_fence(release);
	tab->lt_mask = 0;
	tab->lt_ipi_and_lock = 0;
}

__attribute__((always_inline))
static void
le_tab_credit(
	ledger_template_t       lt,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount
	__ppl_only(, bool       from_ppl))
{
	ledger_tab_t    tab = zpercpu_get(lt->lt_tabs);
	uint32_t        idx = le_counter(entry);
	ledger_pair_t   pair;

	assert(!preemption_enabled());

	if (__improbable(!(entry & LFEAT_SCALABLE) || tab->lt_open != ledger)) {
		le_credit(ledger, entry, amount __ppl_only(, from_ppl));
		return;
	}

	assert(!tab->lt_lock);
	os_atomic_store(&tab->lt_lock, true, compiler_acquire);
	pair            = tab->lt_pairs[idx];
	pair.lp_credit += amount;

	if (le_should_settle(ledger, entry, &pair)) {
		tab->lt_pairs[idx].lp_pair = 0;
		bit_clear(tab->lt_mask, idx);
	} else {
		tab->lt_pairs[idx].lp_credit = pair.lp_credit;
		bit_set(tab->lt_mask, idx);
		pair.lp_pair = 0;
	}

	if (pair.lp_pair) {
		le_tab_merge(ledger, entry, pair __ppl_only(, from_ppl));
	}
	os_atomic_store(&tab->lt_lock, false, compiler_acq_rel);

	if (__improbable(tab->lt_ipi_ack __ppl_only(&& !from_ppl))) {
		le_tab_settle(lt, tab);
	}
}

__attribute__((always_inline))
static void
le_tab_debit(
	ledger_template_t       lt,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount
	__ppl_only(, bool       from_ppl))
{
	ledger_tab_t    tab = zpercpu_get(lt->lt_tabs);
	uint32_t        idx = le_counter(entry);
	ledger_pair_t   pair;

	assert(!preemption_enabled());

	if (__improbable(!(entry & LFEAT_SCALABLE) || tab->lt_open != ledger)) {
		le_debit(ledger, entry, amount __ppl_only(, from_ppl));
		return;
	}

	assert(!tab->lt_lock);
	os_atomic_store(&tab->lt_lock, true, compiler_acquire);
	pair           = tab->lt_pairs[idx];
	pair.lp_debit += amount;

	if (le_should_settle(ledger, entry, &pair)) {
		tab->lt_pairs[idx].lp_pair = 0;
		bit_clear(tab->lt_mask, idx);
	} else {
		tab->lt_pairs[idx].lp_debit = pair.lp_debit;
		bit_set(tab->lt_mask, idx);
		pair.lp_pair = 0;
	}

	if (pair.lp_pair) {
		le_tab_merge(ledger, entry, pair __ppl_only(, from_ppl));
	}
	os_atomic_store(&tab->lt_lock, false, compiler_acq_rel);

	if (__improbable(tab->lt_ipi_ack __ppl_only(&& !from_ppl))) {
		le_tab_settle(lt, tab);
	}
}

__attribute__((noinline))
void
ledger_reset(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         credit,
	ledger_amount_t         debit)
{
	if (__probable(le_valid(ledger, entry))) {
		if (entry & LFEAT_DEBIT) {
			ledger_entry_t le = le_get(ledger, entry);

			le->le_credit = credit;
			le->le_debit  = debit;
		} else {
			ledger_entry_small_t les = le_get_small(ledger, entry);

			les->les_credit = credit - debit;
		}
		le_check(ledger, entry, credit - debit, 0 __ppl_only(, false));
	}
}

__attribute__((noinline))
void
ledger_credit(ledger_t ledger, ledger_entry_id_t entry, ledger_amount_t amount)
{
	if (__probable(le_valid(ledger, entry) && amount > 0)) {
		ledger_template_t lt = ledger->l_template;

		if (entry & LFEAT_SCALABLE) {
			disable_preemption();
			__builtin_assume((entry & LFEAT_REFILL) == 0);
			le_tab_credit(lt, ledger, entry, amount __ppl_only(, false));
			enable_preemption();
		} else {
			le_credit(ledger, entry, amount __ppl_only(, false));
		}
	}
}

__attribute__((noinline))
void
ledger_debit(ledger_t ledger, ledger_entry_id_t entry, ledger_amount_t amount)
{
	if (__probable(le_valid(ledger, entry) && amount > 0)) {
		ledger_template_t lt = ledger->l_template;

		if (entry & LFEAT_SCALABLE) {
			disable_preemption();
			__builtin_assume((entry & LFEAT_REFILL) == 0);
			le_tab_debit(lt, ledger, entry, amount __ppl_only(, false));
			enable_preemption();
		} else {
			le_debit(ledger, entry, amount __ppl_only(, false));
		}
	}
}

__attribute__((noinline))
void
ledger_credit_nopreempt(ledger_t ledger, ledger_entry_id_t entry, ledger_amount_t amount)
{
	if (__probable(le_valid(ledger, entry) && amount > 0)) {
		le_tab_credit(ledger->l_template, ledger, entry, amount __ppl_only(, false));
	}
}

void
ledger_credit_sched(
	thread_t                thread,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount)
{
	if (__probable(le_valid(ledger, entry) && amount > 0)) {
		thread_t *override = PERCPU_GET(ledger_current_thread);

		*override = thread;
		le_tab_credit(ledger->l_template, ledger, entry, amount __ppl_only(, false));
		*override = THREAD_NULL;
	}
}

__attribute__((noinline))
void
ledger_debit_nopreempt(ledger_t ledger, ledger_entry_id_t entry, ledger_amount_t amount)
{
	if (__probable(le_valid(ledger, entry) && amount > 0)) {
		le_tab_debit(ledger->l_template, ledger, entry, amount __ppl_only(, false));
	}
}

__attribute__((noinline))
void
ledger_credit_scalable(
	ledger_template_t       lt,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount)
{
	if (__probable(le_valid(ledger, entry) && amount > 0)) {
		assert(ledger->l_template == lt && (entry & LFEAT_SCALABLE));
		__builtin_assume(entry & LFEAT_SCALABLE);
		__builtin_assume((entry & LFEAT_REFILL) == 0);
		le_tab_credit(lt, ledger, entry, amount __ppl_only(, false));
	}
}

__attribute__((noinline))
void
ledger_debit_scalable(
	ledger_template_t       lt,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount)
{
	if (__probable(le_valid(ledger, entry) && amount > 0)) {
		assert(ledger->l_template == lt && (entry & LFEAT_SCALABLE));
		__builtin_assume(entry & LFEAT_SCALABLE);
		__builtin_assume((entry & LFEAT_REFILL) == 0);
		le_tab_debit(lt, ledger, entry, amount __ppl_only(, false));
	}
}

#if XNU_MONITOR

__attribute__((noinline))
void
ledger_credit_scalable_ppl(
	ledger_template_t       lt,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount)
{
	if (__probable(le_valid(ledger, entry) && amount > 0)) {
		/*
		 * LFEAT_REFILL can't be used by the PPL as it uses
		 * current_thread() and wait queue code.
		 */
		release_assert((entry & (LFEAT_SCALABLE | LFEAT_REFILL)) == LFEAT_SCALABLE);
		assert(ledger->l_template == lt);
		__builtin_assume(entry & LFEAT_SCALABLE);
		__builtin_assume((entry & LFEAT_REFILL) == 0);
		le_tab_credit(lt, ledger, entry, amount, true);
	}
}

__attribute__((noinline))
void
ledger_debit_scalable_ppl(
	ledger_template_t       lt,
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_amount_t         amount)
{
	if (__probable(le_valid(ledger, entry) && amount > 0)) {
		/*
		 * LFEAT_REFILL can't be used by the PPL as it uses
		 * current_thread() and wait queue code.
		 */
		release_assert((entry & (LFEAT_SCALABLE | LFEAT_REFILL)) == LFEAT_SCALABLE);
		assert(ledger->l_template == lt);
		__builtin_assume(entry & LFEAT_SCALABLE);
		__builtin_assume((entry & LFEAT_REFILL) == 0);
		le_tab_debit(lt, ledger, entry, amount, true);
	}
}

void
ledger_propagate_ast_ppl(void)
{
	ledger_template_t lt = &task_ledger_template;
	ledger_tab_t      tab;

	if (__improbable(lt->lt_size == 0)) {
		return;
	}

	tab = zpercpu_get(lt->lt_tabs);
	if (__improbable(tab->lt_ppl_ast || tab->lt_ipi_ack)) {
		disable_preemption();
		tab = zpercpu_get(lt->lt_tabs);
		if (tab->lt_ppl_ast) {
			tab->lt_ppl_ast = false;
			le_set_ast(false);
		}
		if (tab->lt_ipi_ack) {
			le_tab_settle(lt, tab);
		}
		enable_preemption();
	}
}

#endif

static void
le_rollup(ledger_t dst_ledger, ledger_t src_ledger, ledger_entry_id_t entry)
{
	if (entry & LFEAT_DEBIT) {
		ledger_entry_t dst = le_get(dst_ledger, entry);
		ledger_entry_t src = le_get(src_ledger, entry);

		os_atomic_add(&dst->le_credit, src->le_credit, relaxed);
		os_atomic_add(&dst->le_debit, src->le_debit, relaxed);
	} else {
		ledger_entry_small_t dst = le_get_small(dst_ledger, entry);
		ledger_entry_small_t src = le_get_small(src_ledger, entry);

		os_atomic_add(&dst->les_credit, src->les_credit, relaxed);
	}
}

/* Add all of one ledger's values into another.
 * They must have been created from the same template.
 * This is not done atomically. Another thread (if not otherwise synchronized)
 * may see bogus values when comparing one entry to another.
 * As each entry's credit & debit are modified one at a time, the warning/limit
 * may spuriously trip, or spuriously fail to trip, or another thread (if not
 * otherwise synchronized) may see a bogus balance.
 */
kern_return_t
ledger_rollup(ledger_t dst_ledger, ledger_t src_ledger)
{
	ledger_template_t src_tpl = src_ledger->l_template;
#if MACH_ASSERT
	ledger_template_t dst_tpl = dst_ledger->l_template;
#endif /* MACH_ASSERT */

	assert(src_tpl->lt_cnt == dst_tpl->lt_cnt);
	if (src_tpl->lt_tabs) {
		ledger_tab_settle(src_tpl, src_ledger);
	}

	for (uint16_t i = 0; i < src_tpl->lt_cnt; i++) {
		ledger_entry_id_t entry = src_tpl->lt_entries[i].et_id;

		assert(((entry ^ dst_tpl->lt_entries[i].et_id) &
		    (LFEAT_DEBIT | ENTRY_ID_OFFSET_MASK)) == 0);

		le_rollup(dst_ledger, src_ledger, entry);
	}

	return KERN_SUCCESS;
}

/* Add one ledger entry value to another.
 * They must have been created from the same template.
 * Since the credit and debit values are added one
 * at a time, other thread might read the a bogus value.
 */
kern_return_t
ledger_rollup_entry(ledger_t dst_ledger, ledger_t src_ledger, ledger_entry_id_t entry)
{
	if (le_valid(src_ledger, entry) && le_valid(dst_ledger, entry)) {
		ledger_template_t src_tpl = src_ledger->l_template;

		assert(dst_ledger->l_template == src_ledger->l_template);

		if (src_tpl->lt_tabs) {
			ledger_tab_settle(src_ledger->l_template, src_ledger);
		}
		le_rollup(dst_ledger, src_ledger, entry);
	}

	return KERN_SUCCESS;
}

kern_return_t
ledger_get_limit(ledger_t ledger, ledger_entry_id_t entry, ledger_amount_t *limit)
{
	if (!le_valid(ledger, entry)) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((entry & LFEAT_LIMIT_MASK) == 0) {
		*limit = LEDGER_LIMIT_INFINITY;
	} else {
		*limit = le_get(ledger, entry)->le_limit;
	}

	return KERN_SUCCESS;
}

/*
 * Adjust the limit of a limited resource.  This does not affect the
 * current balance, so the change doesn't affect the thread until the
 * next refill.
 *
 * warn_level: If non-zero, causes the callback to be invoked when
 * the balance exceeds this level. Specified as a percentage [of the limit].
 */
kern_return_t
ledger_set_limit(ledger_t ledger, ledger_entry_id_t entry, ledger_amount_t limit,
    uint8_t warn_level_percentage)
{
	struct ledger_entry *le;
	spl_t s;

	assert(entry & LFEAT_LIMIT_MASK);
	if (!le_valid(ledger, entry, LFEAT_LIMIT_MASK)) {
		return KERN_INVALID_ARGUMENT;
	}

	s  = spl_ledger(ledger);
	le = le_get(ledger, entry);
	le->le_limit = limit;

	if (limit == LEDGER_LIMIT_INFINITY) {
		/*
		 * Caller wishes to disable the limit. This will implicitly
		 * disable automatic refill and blocking, as refills implicitly
		 * depend on the limit.
		 */
		flag_clear(&le->le_flags,
		    LF_REFILL_SCHEDULED | LEDGER_ACTION_BLOCK);
	} else if (le->le_flags & LF_REFILL_SCHEDULED) {
		le->le_last_refill = 0;
	}
	flag_clear(&le->le_flags, LF_CALLED_BACK | LF_WARNED);

	ledger_limit_entry_wakeup(le);

	if (warn_level_percentage != 0) {
		assert(warn_level_percentage <= 100);
		assert(limit > 0); /* no negative limit support for warnings */
		assert(limit != LEDGER_LIMIT_INFINITY); /* warn % without limit makes no sense */
		le->le_warn_percent = warn_level_percentage * LEDGER_WARN_PERCENT_100 / 100;
	} else {
		le->le_warn_percent = LEDGER_WARN_THRESHOLD_NONE;
	}

	splx_ledger(s);
	return KERN_SUCCESS;
}

kern_return_t
ledger_get_interval_max(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_get_options_t    options,
	ledger_amount_t        *max_interval_balance)
{
	kern_return_t kr = KERN_SUCCESS;
	struct ledger_entry *le;

	if (!le_valid(ledger, entry, LFEAT_MAXIMUM)) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((options & LEO_NO_SETTLE) == 0 && (entry & LFEAT_SCALABLE) &&
	    ledger->l_template->lt_tabs && not_in_kdp) {
		assert(!ml_at_interrupt_context());
		ledger_tab_settle(ledger->l_template, ledger, entry);
	}

	le = le_get(ledger, entry);
	*max_interval_balance = le->le_interval_max;

	if (options & LEO_RESET_INTERVAL_MAX) {
		kr = ledger_get_balance(ledger, entry,
		    (options | LEO_NO_SETTLE), &le->le_interval_max);
	}

	return kr;
}

kern_return_t
ledger_get_lifetime_max(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_get_options_t    options,
	ledger_amount_t        *max_lifetime_balance)
{
	if (!le_valid(ledger, entry, LFEAT_MAXIMUM)) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((options & LEO_NO_SETTLE) == 0 && (entry & LFEAT_SCALABLE) &&
	    ledger->l_template->lt_tabs && not_in_kdp) {
		assert(!ml_at_interrupt_context());
		ledger_tab_settle(ledger->l_template, ledger, entry);
	}

	*max_lifetime_balance = le_get(ledger, entry)->le_lifetime_max;
	return KERN_SUCCESS;
}

/*
 * Disable callback notification for a specific ledger entry.
 *
 * Otherwise, if using a ledger template which specified a
 * callback function (ledger_set_callback()), it will be invoked when
 * the resource goes into deficit.
 */
kern_return_t
ledger_disable_callback(ledger_t ledger, ledger_entry_id_t entry)
{
	struct ledger_entry *le = NULL;

	assert(entry & LFEAT_CALLBACK);
	if (!le_valid(ledger, entry, LFEAT_CALLBACK)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = le_get(ledger, entry);

	/*
	 * le_warn_percent is used to indicate *if* this ledger has a warning configured,
	 * in addition to what that warning level is set to.
	 * This means a side-effect of ledger_disable_callback() is that the
	 * warning level is forgotten.
	 */
	le->le_warn_percent = LEDGER_WARN_THRESHOLD_NONE;
	flag_clear(&le->le_flags, LEDGER_ACTION_CALLBACK);
	return KERN_SUCCESS;
}

/*
 * Enable callback notification for a specific ledger entry.
 *
 * This is only needed if ledger_disable_callback() has previously
 * been invoked against an entry; there must already be a callback
 * configured.
 */
kern_return_t
ledger_enable_callback(ledger_t ledger, ledger_entry_id_t entry)
{
	struct ledger_entry *le = NULL;

	assert(entry & LFEAT_CALLBACK);
	if (!le_valid(ledger, entry, LFEAT_CALLBACK)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = le_get(ledger, entry);

	assert(entry & LFEAT_CALLBACK);

	flag_set(&le->le_flags, LEDGER_ACTION_CALLBACK);
	return KERN_SUCCESS;
}

/*
 * Query the automatic refill period for this ledger entry.
 *
 * A period of 0 means this entry has none configured.
 */
kern_return_t
ledger_get_period(ledger_t ledger, ledger_entry_id_t entry, uint64_t *period)
{
	struct ledger_entry *le;

	if (!le_valid(ledger, entry, LFEAT_REFILL)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = le_get(ledger, entry);

	*period = abstime_to_nsecs(le->le_refill_period);
	return KERN_SUCCESS;
}

/*
 * Adjust the automatic refill period.
 */
kern_return_t
ledger_set_period(ledger_t ledger, ledger_entry_id_t entry, uint64_t period)
{
	struct ledger_entry *le = NULL;
	ledger_amount_t value;
	spl_t s;

	assert(entry & LFEAT_REFILL);
	if (!le_valid(ledger, entry, LFEAT_REFILL)) {
		return KERN_INVALID_ARGUMENT;
	}

	s  = spl_ledger(ledger);
	le = le_get(ledger, entry);

	/*
	 * A refill period refills the ledger in multiples of the limit,
	 * so if you haven't set one yet, you need a lesson on ledgers.
	 */
	assert(le->le_limit != LEDGER_LIMIT_INFINITY);

	le->le_refill_period = nsecs_to_abstime(period);

	/*
	 * Set the 'starting time' for the next refill to now. Since
	 * we're resetting the balance to zero here, we consider this
	 * moment the starting time for accumulating a balance that
	 * counts towards the limit.
	 */
	le->le_last_refill = mach_absolute_time();

	/*
	 * Zero the balance of a ledger.  Note that some clients of ledgers
	 * (notably, task wakeup statistics) require that le_credit only
	 * ever increase as a function of ledger_credit().
	 */
	value = MAX(le->le_debit, le->le_credit);
	os_atomic_max(&le->le_credit, value, relaxed);
	os_atomic_max(&le->le_debit, value, relaxed);

	flag_set(&le->le_flags, LF_REFILL_SCHEDULED);

	splx_ledger(s);
	return KERN_SUCCESS;
}

/*
 * Disable automatic refill.
 */
kern_return_t
ledger_disable_refill(ledger_t ledger, ledger_entry_id_t entry)
{
	struct ledger_entry *le = NULL;

	assert(entry & LFEAT_REFILL);
	if (!le_valid(ledger, entry, LFEAT_REFILL)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = le_get(ledger, entry);

	flag_clear(&le->le_flags, LF_REFILL_SCHEDULED);

	return KERN_SUCCESS;
}

kern_return_t
ledger_get_actions(ledger_t ledger, ledger_entry_id_t entry, int *actions)
{
	*actions = 0;

	if (!le_valid(ledger, entry, LFEAT_LIMIT_MASK)) {
		return KERN_INVALID_ARGUMENT;
	}

	*actions = (*le_flagsp(ledger, entry) & LEDGER_ACTION_MASK);
	return KERN_SUCCESS;
}

kern_return_t
ledger_set_blocking(ledger_t ledger, ledger_entry_id_t entry)
{
	assert(entry & LFEAT_REFILL);
	if (!le_valid(ledger, entry, LFEAT_REFILL)) {
		return KERN_INVALID_ARGUMENT;
	}

	flag_set(le_flagsp(ledger, entry), LEDGER_ACTION_BLOCK);
	return KERN_SUCCESS;
}

__attribute__((always_inline))
void
ledger_tab_open(ledger_template_t lt, ledger_t ledger)
{
	ledger_tab_t tab = zpercpu_get(lt->lt_tabs);

	assert(!preemption_enabled());

#if XNU_MONITOR
	if (tab->lt_ppl_ast) {
		tab->lt_ppl_ast = false;
		le_set_ast(__ppl_only(false));
	}
#endif /* XNU_MONITOR */

	if (tab->lt_open != ledger && tab->lt_mask) {
		le_tab_settle(lt, tab);
	}
	tab->lt_open = ledger;
}

void
ledger_tab_settle(
	ledger_template_t       lt,
	ledger_t                ledger,
	ledger_entry_id_t       entry)
{
#ifndef __BUILDING_XNU_LIB_UNITTEST__
	/*
	 * We need to be able be IPId by other cores settling ledger tabs to
	 * avoid potential deadlocks in the wait-for-ACK loop.
	 */
	assert(ml_get_interrupts_enabled());
#endif /* defined(__BUILDING_XNU_LIB_UNITTEST__) */

	bitmap_t     waiting[BITMAP_LEN(MAX_CPUS)] = { };
	ledger_tab_t this_tab;

	if (ledger && ledger != (ledger_t)~0) {
		assert(ledger->l_template == lt);
	}

	disable_preemption();

	this_tab = zpercpu_get(lt->lt_tabs);
	zpercpu_foreach_cpu(cpu) {
		ledger_tab_t tab = zpercpu_get_cpu(lt->lt_tabs, cpu);

		if (tab->lt_mask == 0) {
			continue;
		}

		if (ledger != (ledger_t)~0 && tab->lt_open != ledger) {
			continue;
		}

		if (tab == this_tab) {
			le_tab_settle(lt, tab);
			continue;
		}

		if (entry != LEDGER_ENTRY_ID_INVALID &&
		    !bit_test(tab->lt_mask, le_counter(entry))) {
			continue;
		}

		os_atomic_store(&tab->lt_ipi_ack, true, relaxed);
		cause_maintenance_ipi(cpu);
		bitmap_set(waiting, cpu);
	}

	/*
	 * We need to re-enable preemption before spinning (for a potentially
	 * long time) waiting for other cores to ACK our IPIs.
	 */
	enable_preemption();

	for (int cpu = bitmap_first(waiting, MAX_CPUS);
	    cpu >= 0; cpu = bitmap_next(waiting, cpu)) {
		ledger_tab_t tab = zpercpu_get_cpu(lt->lt_tabs, cpu);
		uint32_t needs_ack;

		while (__improbable(!hw_spin_wait_until(&tab->lt_ipi_ack,
		    needs_ack, !needs_ack))) {
			/* just wait for acknowledgement */
		}
	}

	os_atomic_thread_fence(acquire);
}

void
ledger_tab_settle_all(ledger_template_t tpl)
{
	ledger_tab_settle(tpl, (ledger_t)~0, LEDGER_ENTRY_ID_INVALID);
}

static void
le_tab_settle_ack_ipi(ledger_template_t lt, int cpu)
{
	ledger_tab_t tab = zpercpu_get_cpu(lt->lt_tabs, cpu);

	if (__improbable(tab->lt_ipi_ack && !tab->lt_lock)) {
		le_tab_settle(lt, tab);
	}
}

void
ledger_tab_settle_ack_ipi(int cpu)
{
	le_tab_settle_ack_ipi(&task_ledger_template, cpu);
}

void
ledger_ast(thread_t thread)
{
	struct ledger   *l   = thread->t_ledger;
	struct ledger   *thl = thread->t_threadledger;
	struct ledger   *coalition_ledger;
	uint32_t        block;
	uint64_t        now;
	uint8_t         task_flags;
	uint8_t         task_percentage;
	uint64_t        task_interval;

	kern_return_t ret;
	task_t task = get_threadtask(thread);

	assert(task != NULL);
	assert(thread == current_thread());

#if CONFIG_SCHED_RT_ALLOW
	/*
	 * The RT policy may have forced a CPU limit on the thread. Check if
	 * that's the case and apply the limit as requested.
	 */
	spl_t s = splsched();
	thread_lock(thread);

	int req_action = thread->t_ledger_req_action;
	uint8_t req_percentage = thread->t_ledger_req_percentage;
	uint64_t req_interval_ns = thread->t_ledger_req_interval_ms * NSEC_PER_MSEC;

	thread->t_ledger_req_action = 0;

	thread_unlock(thread);
	splx_ledger(s);

	if (req_action != 0) {
		assert(req_action == THREAD_CPULIMIT_DISABLE ||
		    req_action == THREAD_CPULIMIT_BLOCK);

		if (req_action == THREAD_CPULIMIT_DISABLE &&
		    (thread->options & TH_OPT_FORCED_LEDGER) != 0) {
			thread->options &= ~TH_OPT_FORCED_LEDGER;
			ret = thread_set_cpulimit(THREAD_CPULIMIT_DISABLE, 0, 0);
			assert3u(ret, ==, KERN_SUCCESS);
		}

		if (req_action == THREAD_CPULIMIT_BLOCK) {
			thread->options &= ~TH_OPT_FORCED_LEDGER;
			ret = thread_set_cpulimit(THREAD_CPULIMIT_BLOCK,
			    req_percentage, req_interval_ns);
			assert3u(ret, ==, KERN_SUCCESS);
			thread->options |= TH_OPT_FORCED_LEDGER;
		}
	}
#endif /* CONFIG_SCHED_RT_ALLOW */

top:
	/*
	 * Take a self-consistent snapshot of the CPU usage monitor parameters. The task
	 * can change them at any point (with the task locked).
	 */
	task_lock(task);
	task_flags = task->rusage_cpu_flags;
	task_percentage = task->rusage_cpu_perthr_percentage;
	task_interval = task->rusage_cpu_perthr_interval;
	task_unlock(task);

	/*
	 * Make sure this thread is up to date with regards to any task-wide per-thread
	 * CPU limit, but only if it doesn't have a thread-private blocking CPU limit.
	 */
	if (((task_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) != 0) &&
	    ((thread->options & TH_OPT_PRVT_CPULIMIT) == 0)) {
		uint8_t  percentage;
		uint64_t interval;
		int      action;

		thread_get_cpulimit(&action, &percentage, &interval);

		/*
		 * If the thread's CPU limits no longer match the task's, or the
		 * task has a limit but the thread doesn't, update the limit.
		 */
		if (((thread->options & TH_OPT_PROC_CPULIMIT) == 0) ||
		    (interval != task_interval) || (percentage != task_percentage)) {
			thread_set_cpulimit(THREAD_CPULIMIT_EXCEPTION, task_percentage, task_interval);
			assert((thread->options & TH_OPT_PROC_CPULIMIT) != 0);
		}
	} else if (((task_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) == 0) &&
	    (thread->options & TH_OPT_PROC_CPULIMIT)) {
		assert((thread->options & TH_OPT_PRVT_CPULIMIT) == 0);

		/*
		 * Task no longer has a per-thread CPU limit; remove this thread's
		 * corresponding CPU limit.
		 */
		thread_set_cpulimit(THREAD_CPULIMIT_DISABLE, 0, 0);
		assert((thread->options & TH_OPT_PROC_CPULIMIT) == 0);
	}

	/*
	 * If the task or thread is being terminated, let's just get on with it
	 */
	if ((l == NULL) || !task->active || task->halting || !thread->active) {
		return;
	}

	/*
	 * Examine all entries in deficit to see which might be eligble for
	 * an automatic refill, which require callbacks to be issued, and
	 * which require blocking.
	 */
	block = 0;
	now = mach_absolute_time();

	block |= ledger_check_needblock(thl, now);
	block |= ledger_check_needblock(l, now);
	coalition_ledger = coalition_ledger_get_from_task(task);
	if (LEDGER_VALID(coalition_ledger)) {
		block |= ledger_check_needblock(coalition_ledger, now);
	}
	ledger_dereference(coalition_ledger);
	/*
	 * If we are supposed to block on the availability of one or more
	 * resources, find the first entry in deficit for which we should wait.
	 * Schedule a refill if necessary and then sleep until the resource
	 * becomes available.
	 */
	if (block) {
		ret = ledger_perform_blocking(thl);
		if (ret != KERN_SUCCESS) {
			goto top;
		}
		ret = ledger_perform_blocking(l);
		if (ret != KERN_SUCCESS) {
			goto top;
		}
	} /* block */
}

static uint32_t
ledger_check_needblock(ledger_t l, uint64_t now)
{
	uint32_t flags, block = 0;
	ledger_template_t template = NULL;

	template = l->l_template;
	assert(template->lt_size);

	for (uint16_t i = 0; i < template->lt_cnt; i++) {
		ledger_entry_template_t et = &template->lt_entries[i];
		ledger_amount_t balance;
		ledger_callback_t cb;
		ledger_entry_t le;
		const void *p0;

		if ((et->et_id & LFEAT_LIMIT_MASK) == 0) {
			continue;
		}

		le = le_get(l, et->et_id);
		cb = et->et_callback;
		p0 = et->et_cb_param0;
		balance = le_balance(le);

		/* We're over the limit, so refill if we are eligible and past due. */
		if (le->le_flags & LF_REFILL_SCHEDULED) {
			if ((le->le_last_refill + le->le_refill_period) <= now) {
				ledger_refill(le, now, &balance);
			}
		}

		if (le->le_flags & LEDGER_ACTION_CALLBACK) {
			if (balance > le->le_limit) {
				flags = flag_set(&le->le_flags, LF_CALLED_BACK);
				if ((flags & LF_CALLED_BACK) == 0) {
					cb(LEDGER_WARNING_LEVEL_CRITICAL, p0);
				}
			} else if (balance > le_warn_limit(le)) {
				/*
				 * If needed, invoke the callback as a warning.
				 * This needs to happen both when the balance rises above
				 * the warning level, and also when it dips back below it.
				 *
				 * See le_check_callback().
				 */
				flags = flag_set(&le->le_flags, LF_WARNED);
				if ((flags & (LF_CALLED_BACK | LF_WARNED)) == 0) {
					cb(LEDGER_WARNING_LEVEL_WARNING, p0);
				}
			}
#if LEDGER_HAS_FEAT_DIAG
			if (balance > le_diag_limit(le) && !(le->le_flags & LF_DIAG_DISABLED)) {
				flags = flag_set(&le->le_flags, LF_DIAG_WARNED);
				if ((flags & LF_DIAG_WARNED) == 0) {
					cb(LEDGER_WARNING_LEVEL_DIAG, p0);
				}
			}
#endif /* LEDGER_HAS_FEAT_DIAG */
		}

		if (le->le_flags & LEDGER_ACTION_BLOCK) {
			if (balance > le->le_limit) {
				block = 1;
			}
		}
	}
	return block;
}


/* return KERN_SUCCESS to continue, KERN_FAILURE to restart */
static kern_return_t
ledger_perform_blocking(ledger_t l)
{
	kern_return_t ret;
	ledger_template_t template = NULL;

	template = l->l_template;
	assert(template->lt_size);

	for (uint16_t i = 0; i < template->lt_cnt; i++) {
		ledger_entry_template_t et = &template->lt_entries[i];
		ledger_entry_t le;

		if ((et->et_id & LFEAT_REFILL) == 0) {
			continue;
		}

		le = le_get(l, et->et_id);

		if ((!limit_exceeded(le)) ||
		    ((le->le_flags & LEDGER_ACTION_BLOCK) == 0)) {
			continue;
		}

		/* Prepare to sleep until the resource is refilled */
		ret = assert_wait_deadline(le, THREAD_INTERRUPTIBLE,
		    le->le_last_refill + le->le_refill_period);
		if (ret != THREAD_WAITING) {
			return KERN_SUCCESS;
		}

		/* Mark that somebody is waiting on this entry  */
		flag_set(&le->le_flags, LF_WAKE_NEEDED);

		ret = thread_block_reason(THREAD_CONTINUE_NULL, NULL,
		    AST_LEDGER);
		if (ret != THREAD_AWAKENED) {
			return KERN_SUCCESS;
		}

		/*
		 * The world may have changed while we were asleep.
		 * Some other resource we need may have gone into
		 * deficit.  Or maybe we're supposed to die now.
		 * Go back to the top and reevaluate.
		 */
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}


kern_return_t
ledger_get_entries(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_get_options_t    options,
	ledger_amount_t        *credit,
	ledger_amount_t        *debit)
{
	if (!le_valid(ledger, entry)) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((options & LEO_NO_SETTLE) == 0 && (entry & LFEAT_SCALABLE) &&
	    ledger->l_template->lt_tabs && not_in_kdp) {
		assert(!ml_at_interrupt_context());
		ledger_tab_settle(ledger->l_template, ledger, entry);
	}
	if (entry & LFEAT_DEBIT) {
		*credit = le_get(ledger, entry)->le_credit;
		*debit  = le_get(ledger, entry)->le_debit;
	} else {
		*credit = le_get_small(ledger, entry)->les_credit;
		*debit  = 0;
	}

	return KERN_SUCCESS;
}

kern_return_t
ledger_disable_panic_on_negative(ledger_t ledger, ledger_entry_id_t entry)
{
	if (!le_valid(ledger, entry)) {
		return KERN_INVALID_ARGUMENT;
	}

	flag_clear(le_flagsp(ledger, entry), LF_PANIC_ON_NEGATIVE);
	return KERN_SUCCESS;
}

kern_return_t
ledger_get_panic_on_negative(ledger_t ledger, ledger_entry_id_t entry, int *panic_on_negative)
{
	if (!le_valid(ledger, entry)) {
		return KERN_INVALID_ARGUMENT;
	}

	*panic_on_negative = (*le_flagsp(ledger, entry) & LF_PANIC_ON_NEGATIVE) != 0;
	return KERN_SUCCESS;
}

kern_return_t
ledger_get_balance(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	ledger_get_options_t    options,
	ledger_amount_t        *balance)
{
	kern_return_t kr;
	ledger_amount_t credit, debit;

	kr = ledger_get_entries(ledger, entry, options, &credit, &debit);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	*balance = credit - debit;

	return KERN_SUCCESS;
}

int
ledger_template_info(void **buf, int *len)
{
	struct ledger_template_info *lti;
	ledger_template_t template;
	ledger_t l = current_thread()->t_ledger;

	/*
	 * Since all tasks share a ledger template, we'll just use the
	 * caller's as the source.
	 */
	if ((*len < 0) || (l == NULL)) {
		return EINVAL;
	}
	template = l->l_template;
	assert(template->lt_size);

	if (*len > template->lt_cnt) {
		*len = template->lt_cnt;
	}
	lti = kalloc_data((*len) * sizeof(struct ledger_template_info),
	    Z_WAITOK | Z_ZERO);
	if (lti == NULL) {
		return ENOMEM;
	}
	*buf = lti;

	for (uint16_t i = 0; i < *len; i++) {
		ledger_entry_template_t et = &template->lt_entries[i];

		strlcpy(lti[i].lti_name, et->et_key, LEDGER_NAME_MAX);
		strlcpy(lti[i].lti_group, et->et_group, LEDGER_NAME_MAX);
		strlcpy(lti[i].lti_units, et->et_units, LEDGER_NAME_MAX);
	}

	return 0;
}

static kern_return_t
_ledger_fill_entry_info(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	struct ledger_entry_info *lei,
	uint64_t                now)
{
	assert(ledger != NULL);
	assert(lei != NULL);
	if (!le_valid(ledger, entry)) {
		return KERN_INVALID_ARGUMENT;
	}

	memset(lei, 0, sizeof(*lei));

	if ((entry & LFEAT_LARGE_MASK) == 0) {
		ledger_entry_small_t les = le_get_small(ledger, entry);

		lei->lei_credit = les->les_credit;
		lei->lei_limit = LEDGER_LIMIT_INFINITY;
		lei->lei_debit = 0;
		lei->lei_refill_period = 0;
		lei->lei_last_refill = abstime_to_nsecs(now);
	} else {
		ledger_entry_t le = le_get(ledger, entry);

		lei->lei_limit         = le->le_limit;
		lei->lei_credit        = le->le_credit;
		lei->lei_debit         = le->le_debit;
		lei->lei_refill_period = (le->le_flags & LF_REFILL_SCHEDULED) ?
		    abstime_to_nsecs(le->le_refill_period) : 0;
		lei->lei_last_refill   = abstime_to_nsecs(now - le->le_last_refill);
	}

	lei->lei_balance = lei->lei_credit - lei->lei_debit;

	return KERN_SUCCESS;
}

static kern_return_t
ledger_fill_entry_info(ledger_t ledger,
    int                          entry,
    void                         *lei_generic,
    uint64_t                     now,
    bool                         v2)
{
	ledger_amount_t max;
	kern_return_t kr;
	struct ledger_entry_info *lei = (struct ledger_entry_info *)lei_generic;
	struct ledger_entry_info_v2 *lei_v2 = (struct ledger_entry_info_v2 *)lei_generic;

	kr = _ledger_fill_entry_info(ledger, entry, lei, now);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	if (v2) {
		lei_v2->lei_lifetime_max = -1;
		if (KERN_SUCCESS == ledger_get_lifetime_max(ledger, entry,
		    LEO_SETTLE, &max)) {
			lei_v2->lei_lifetime_max = max;
		}
	}

	return KERN_SUCCESS;
}


int
ledger_get_task_entry_info_multiple(task_t task, void **buf, int *len, bool v2)
{
	void *lei_buf = NULL, *lei_curr = NULL;
	uint64_t now = mach_absolute_time();
	vm_size_t buf_size = 0, entry_size = 0;
	ledger_t l;
	ledger_template_t template;

	if ((*len < 0) || ((l = task->ledger) == NULL)) {
		return EINVAL;
	}
	template = l->l_template;
	assert(template->lt_size);

	if (*len > template->lt_cnt) {
		*len = template->lt_cnt;
	}
	entry_size = (v2) ? sizeof(struct ledger_entry_info_v2) : sizeof(struct ledger_entry_info);
	buf_size = (*len) * entry_size;
	lei_buf = kalloc_data(buf_size, Z_WAITOK);
	if (lei_buf == NULL) {
		return ENOMEM;
	}
	lei_curr = lei_buf;

	for (uint16_t i = 0; i < *len; i++) {
		ledger_entry_template_t et = &template->lt_entries[i];

		if (ledger_fill_entry_info(l, et->et_id, lei_curr, now, v2) != KERN_SUCCESS) {
			kfree_data(lei_buf, buf_size);
			lei_buf = NULL;
			return EINVAL;
		}
		lei_curr = (void *)((mach_vm_address_t)lei_curr + entry_size);
	}

	*buf = lei_buf;
	return 0;
}

void
ledger_get_entry_info(
	ledger_t                ledger,
	ledger_entry_id_t       entry,
	struct ledger_entry_info *lei)
{
	uint64_t now = mach_absolute_time();

	assert(ledger != NULL);
	assert(lei != NULL);

	_ledger_fill_entry_info(ledger, entry, lei, now);
}

int
ledger_info(task_t task, struct ledger_info *info)
{
	ledger_t l;

	if ((l = task->ledger) == NULL) {
		return ENOENT;
	}

	memset(info, 0, sizeof(*info));

	strlcpy(info->li_name, l->l_template->lt_name, LEDGER_NAME_MAX);
	info->li_id = l->l_id;
	info->li_entries = l->l_template->lt_cnt;
	return 0;
}

/*
 * Returns the amount that would be required to hit the limit.
 * Must be a valid, active, full-sized ledger.
 */
ledger_amount_t
ledger_get_remaining(ledger_t ledger, ledger_entry_id_t entry)
{
	const struct ledger_entry *le = le_get(ledger, entry);
	const ledger_amount_t limit = le->le_limit;
	const ledger_amount_t balance = le_balance(le);

	/* +1 here as the limit isn't hit until the limit is exceeded. */
	return limit > balance ? limit - balance + 1 : 0;
}

/*
 * Balances the ledger by modifying the debit only and sets the last refill time
 * to `now`.
 * WARNING: It is up to the caller to enforce consistency.
 * Must be a valid, active, full-sized ledger.
 */
void
ledger_restart(ledger_t ledger, ledger_entry_id_t entry, uint64_t now)
{
	struct ledger_entry *le = le_get(ledger, entry);
	spl_t s;

	s = spl_ledger(ledger);
	le->le_debit = le->le_credit;
	le->le_last_refill = now;
	splx_ledger(s);
}

/*
 * Returns the amount of time that would have to pass to expire the current
 * interval.
 * Must be a valid, active, full-sized ledger.
 */
uint64_t
ledger_get_interval_remaining(ledger_t ledger, ledger_entry_id_t entry, uint64_t now)
{
	const struct ledger_entry *le = le_get(ledger, entry);

	if ((now - le->le_last_refill) >
	    le->le_refill_period) {
		return 0;
	} else {
		return le->le_refill_period -
		       (now - le->le_last_refill) + 1;
	}
}

/*
 * Adjust the diag mem threshold limit of a resource. The diag mem threshold limit only
 * works prescaled by 20 bits (mb)
 */
#if LEDGER_HAS_FEAT_DIAG

kern_return_t
ledger_set_diag_mem_threshold(ledger_t ledger, ledger_entry_id_t entry, ledger_amount_t limit)
{
	struct ledger_entry *le;

	assert(entry & LFEAT_DIAG);
	if (!le_valid(ledger, entry, LFEAT_DIAG)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = le_get(ledger, entry);
	le->le_diag_threshold_scaled = (int16_t)LEDGER_DIAG_MEM_AMOUNT_TO_THRESHOLD(limit);
	flag_clear(&le->le_flags, LF_DIAG_WARNED);

	return KERN_SUCCESS;
}

kern_return_t
ledger_get_diag_mem_threshold(ledger_t ledger, ledger_entry_id_t entry, ledger_amount_t *limit)
{
	struct ledger_entry *le;

	if (!le_valid(ledger, entry)) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((entry & LFEAT_DIAG) == 0) {
		*limit = LEDGER_LIMIT_INFINITY;
	} else {
		le = le_get(ledger, entry);
		if (le->le_diag_threshold_scaled == LEDGER_DIAG_MEM_THRESHOLD_INFINITY) {
			*limit = LEDGER_LIMIT_INFINITY;
		} else {
			*limit = LEDGER_DIAG_MEM_AMOUNT_FROM_THRESHOLD(le->le_diag_threshold_scaled);
		}
	}

	return KERN_SUCCESS;
}

static inline void
ledger_set_diag_mem_threshold_flag_disabled_internal(struct ledger_entry *le, bool value)
{
	if (value == true) {
		flag_set(&le->le_flags, LF_DIAG_DISABLED);
	} else {
		flag_clear(&le->le_flags, LF_DIAG_DISABLED);
	}
}

static inline bool
ledger_is_diag_threshold_enabled_internal(struct ledger_entry *le)
{
	return ((le->le_flags & LF_DIAG_DISABLED) == 0)? true : false;
}

/**
 * Disable the diagnostics threshold due to overlap with footprint limit
 */
kern_return_t
ledger_set_diag_mem_threshold_disabled(ledger_t ledger, ledger_entry_id_t entry)
{
	struct ledger_entry *le;

	assert(entry & LFEAT_DIAG);
	if (!le_valid(ledger, entry, LFEAT_DIAG)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = le_get(ledger, entry);
	if (le->le_diag_threshold_scaled == LEDGER_DIAG_MEM_THRESHOLD_INFINITY) {
		return KERN_INVALID_ARGUMENT;
	}
	ledger_set_diag_mem_threshold_flag_disabled_internal(le, true);
	return KERN_SUCCESS;
}
/**
 * Enable the diagnostics threshold for a specific entry
 */
kern_return_t
ledger_set_diag_mem_threshold_enabled(ledger_t ledger, ledger_entry_id_t entry)
{
	struct ledger_entry *le;

	assert(entry & LFEAT_DIAG);
	if (!le_valid(ledger, entry, LFEAT_DIAG)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = le_get(ledger, entry);
	/*
	 *  if (le->le_diag_threshold_scaled == LEDGER_DIAG_MEM_THRESHOLD_INFINITY) {
	 *       return KERN_INVALID_ARGUMENT;
	 *  }
	 */
	ledger_set_diag_mem_threshold_flag_disabled_internal(le, false);

	return KERN_SUCCESS;
}
/**
 * Obtain the diagnostics threshold enabled flag. If the diagnostics threshold is enabled, returns true
 * else returns false.
 */
kern_return_t
ledger_is_diag_threshold_enabled(ledger_t ledger, ledger_entry_id_t entry, bool *status)
{
	struct ledger_entry *le;

	if (!le_valid(ledger, entry, LFEAT_DIAG)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = le_get(ledger, entry);
	/*
	 *  if (le->le_diag_threshold_scaled == LEDGER_DIAG_MEM_THRESHOLD_INFINITY) {
	 *       return KERN_INVALID_ARGUMENT;
	 *  }
	 */
	*status = ledger_is_diag_threshold_enabled_internal(le);
	return KERN_SUCCESS;
}

#endif /* LEDGER_HAS_FEAT_DIAG */
