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

#include <kern/cpu_data.h>
#include <kern/mpsc_queue.h>
#include <kern/percpu.h>
#include <kern/smr.h>
#include <kern/zalloc.h>
#include <sys/queue.h>

/*
 * This SMR scheme is directly FreeBSD's "Global Unbounded Sequences".
 *
 * Major differences are:
 *
 * - only eager clocks are implemented (no lazy, no implicit)
 */

typedef long                    smr_delta_t;

typedef struct smr_pcpu {
	smr_seq_t               c_rd_seq;
	unsigned long           c_rd_budget;
} *smr_pcpu_t;

#define SMR_SEQ_DELTA(a, b)     ((smr_delta_t)((a) - (b)))
#define SMR_SEQ_CMP(a, op, b)   (SMR_SEQ_DELTA(a, b) op 0)

#define SMR_SEQ_INC             2ul

#define SMR_EARLY_COUNT         32

__startup_data
static struct {
	struct smr_pcpu array[SMR_EARLY_COUNT];
	unsigned        used;
} smr_boot;


#pragma mark - manipulating an SMR clock

/*
 * SMR clocks have 3 state machines interacting at any given time:
 *
 *
 * 1. reader critical sections
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Each CPU can disable preemption and do this sequence:
 *
 *     CPU::c_rd_seq = GLOBAL::c_wr_seq;
 *
 *     < unfortunate place to receive a long IRQ >                      [I]
 *
 *     os_atomic_thread_fence(seq_cst);                                 [R1]
 *
 *     {
 *         // critical section
 *     }
 *
 *     os_atomic_store(&CPU::c_rd_seq, INVALID, release);               [R2]
 *
 *
 *
 * 2. writer sequence advances
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Each writer can increment the global write sequence
 * at any given time:
 *
 *    os_atomic_add(&GLOBAL::c_wr_seq, SMR_SEQ_INC, release);           [W]
 *
 *
 *
 * 3. synchronization sequence: poll/wait/scan
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This state machine synchronizes with the other two in order to decide
 * if a given "goal" is in the past. Only the cases when the call
 * is successful is interresting for barrier purposes, and we will focus
 * on cases that do not take an early return for failures.
 *
 * a. __smr_poll:
 *
 *     rd_seq = os_atomic_load(&GLOBAL::c_rd_seq, acquire);             [S1]
 *     if (goal < rd_seq) SUCCESS.
 *     wr_seq = os_atomic_load(&GLOBAL::c_rd_seq, relaxed);
 *
 * b. __smr_scan
 *
 *     os_atomic_thread_fence(seq_cst)                                  [S2]
 *
 *     observe the minimum CPU::c_rd_seq "min_rd_seq"
 *     value possible or rw_seq if no CPU was in a critical section.
 *     (possibly spinning until it satisfies "goal")
 *
 * c. __smr_rd_advance
 *
 *     cur_rd_seq = load_exclusive(&GLOBAL::c_rd_seq);
 *     os_atomic_thread_fence(seq_cst);                                 [S3]
 *     if (min_rd_seq > cur_rd_seq) {
 *         store_exlusive(&GLOBAL::c_rd_seq, min_rd_seq);
 *     }
 *
 *
 * One sentence summary
 * ~~~~~~~~~~~~~~~~~~~~
 *
 * A simplistic one-sentence summary of the algorithm is that __smr_scan()
 * works really hard to insert itself in the timeline of write sequences and
 * observe a reasonnable bound for first safe-to-reclaim sequence, and
 * issues [S3] to sequence everything around "c_rd_seq" (via [S3] -> [S1]):
 *
 *              GLOBAL::c_rd_seq                GLOBAL::c_wr_seq
 *                             v                v
 *       ──────────────────────┬────────────────┬─────────────────────
 *       ... safe to reclaim   │    deferred    │   future         ...
 *       ──────────────────────┴────────────────┴─────────────────────
 *
 *
 * Detailed explanation
 * ~~~~~~~~~~~~~~~~~~~~
 *
 * [W] -> [R1] establishes a "happens before" relationship between a given
 * writer and this critical section. The loaded GLOBAL::c_wr_seq might
 * however be stale with respect to the one [R1] really synchronizes with
 * (see [I] explanation below).
 *
 *
 * [R1] -> [S2] establishes a "happens before" relationship between all the
 * active critical sections and the scanner.
 * It lets us compute the oldest possible sequence pinned by an active
 * critical section.
 *
 *
 * [R2] -> [S3] establishes a "happens before" relationship between all the
 * inactive critical sections and the scanner.
 *
 *
 * [S3] -> [S1] is the typical expected fastpath: when the caller can decide
 * that its goal is older than the last update an __smr_rd_advance() did.
 * Note that [S3] doubles as an "[S1]" when two __smr_scan() race each other
 * and one of them finishes last but observed a "worse" read sequence.
 *
 *
 * [W], [S3] -> [S1] is the last crucial property: all updates to the global
 * clock are totally ordered because they update the entire 128bit state
 * every time with an RMW. This guarantees that __smr_poll() can't load
 * an `rd_seq` that is younger than the `wr_seq` it loads next.
 *
 *
 * [I] __smr_enter() also can be unfortunately delayed after observing
 * a given write sequence and right before [R1] at [I].
 *
 * However for a read sequence to have move past what __smr_enter() observed,
 * it means another __smr_scan() didn't observe the store to CPU::c_rd_seq
 * made by __smr_enter() and thought the section was inactive.
 *
 * This can only happen if the scan's [S2] was issued before the delayed
 * __smr_enter() [R1] (during the [I] window).
 *
 * As a consequence the outcome of that scan can be accepted as the "real"
 * write sequence __smr_enter() should have observed.
 *
 *
 * Litmus tests
 * ~~~~~~~~~~~~
 *
 * This is the proof of [W] -> [R1] -> [S2] being established properly:
 * - P0 sets a global and calls smr_synchronize()
 * - P1 does smr_enter() and loads the global
 *
 *     AArch64 MP
 *     {
 *         global = 0;
 *         wr_seq = 123;
 *         p1_rd_seq = 0;
 *
 *         0:x0 = global; 0:x1 = wr_seq; 0:x2 = p1_rd_seq;
 *         1:x0 = global; 1:x1 = wr_seq; 1:x2 = p1_rd_seq;
 *     }
 *      P0                     | P1                         ;
 *      MOV      X8, #2        | LDR        X8, [X1]        ;
 *      STR      X8, [X0]      | STR        X8, [X2]        ;
 *      LDADDL   X8, X9, [X1]  | DMB        SY              ;
 *      DMB      SY            | LDR        X10, [X0]       ;
 *      LDR      X10, [X2]     |                            ;
 *     exists (0:X10 = 0 /\ 1:X8 = 123 /\ 1:X10 = 0)
 *
 *
 * This is the proof that deferred advances are also correct:
 * - P0 sets a global and does a smr_deferred_advance()
 * - P1 does an smr_synchronize() and reads the global
 *
 *     AArch64 MP
 *     {
 *         global = 0;
 *         wr_seq = 123;
 *
 *         0:x0 = global; 0:x1 = wr_seq; 0:x2 = 2;
 *         1:x0 = global; 1:x1 = wr_seq; 1:x2 = 2;
 *     }
 *      P0                     | P1                         ;
 *      STR      X2, [X0]      | LDADDL     X2, X9, [X1]    ;
 *      DMB      SY            | DMB        SY              ;
 *      LDR      X9, [X1]      | LDR        X10, [X0]       ;
 *      ADD      X9, X9, X2    |                            ;
 *     exists (0:X9 = 125 /\ 1:X9 = 123 /\ 1:X10 = 0)
 *
 */

static inline smr_pcpu_t __zpercpu
smr_pcpu(smr_t smr)
{
	return (smr_pcpu_t __zpercpu)smr->smr_pcpu;
}

__startup_func
void
__smr_init(smr_t smr)
{
	if (startup_phase < STARTUP_SUB_TUNABLES) {
		smr_pcpu_t pcpu = &smr_boot.array[smr_boot.used++];
		assertf(smr_boot.used <= SMR_EARLY_COUNT,
		    "too many SMR_DEFINE_EARLY(), adjust SMR_EARLY_COUNT");
		smr->smr_pcpu = (unsigned long)__zpcpu_mangle_for_boot(pcpu);
	} else {
		smr_pcpu_t __zpercpu pcpu;

		pcpu = zalloc_percpu_permanent_type(struct smr_pcpu);
		os_atomic_store(&smr->smr_pcpu, (unsigned long)pcpu, release);
	}
}

static inline void
__smr_reset(smr_t smr, smr_seq_t seq)
{
	smr->smr_clock.s_rd_seq = seq;
	smr->smr_clock.s_wr_seq = seq;
	smr->smr_pcpu           = 0;
}

void
smr_init(smr_t smr)
{
	smr_pcpu_t __zpercpu pcpu;

	pcpu = zalloc_percpu(percpu_u64_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	__smr_reset(smr, SMR_SEQ_INIT);
	os_atomic_store(&smr->smr_pcpu, (unsigned long)pcpu, release);
}

void
smr_set_deferred_budget(smr_t smr, unsigned long budget)
{
	/*
	 * No need to update the per-cpu budget variables,
	 * calls to smr_deferred_advance() will eventually fix it.
	 *
	 * Note: we use `-1` because smr_deferred_advance_nopreempt()
	 *       checks for overflow rather than hitting 0.
	 */
	smr->smr_budget = budget ? budget - 1 : 0;
}

void
smr_destroy(smr_t smr)
{
	smr_synchronize(smr);
	zfree_percpu(percpu_u64_zone, smr_pcpu(smr));
	__smr_reset(smr, SMR_SEQ_INVALID);
}

static inline bool
smr_entered_nopreempt(smr_t smr)
{
	return zpercpu_get(smr_pcpu(smr))->c_rd_seq != SMR_SEQ_INVALID;
}

__attribute__((always_inline))
bool
smr_entered(smr_t smr)
{
	return get_preemption_level() != 0 && smr_entered_nopreempt(smr);
}

__attribute__((always_inline))
static void
__smr_enter(smr_t smr, smr_pcpu_t pcpu)
{
	smr_seq_t  s_wr_seq;
	smr_seq_t  old_seq;

	/*
	 * It is possible to have a long delay between loading the s_wr_seq
	 * and storing it to the percpu copy of it.
	 *
	 * It is unlikely but possible by that time the s_rd_seq advances
	 * ahead of what we will store. This however is still safe
	 * and handled in __smr_scan().
	 *
	 * On Intel, to achieve the ordering we want, we could use a store
	 * followed by an mfence, or any RMW (XCHG, XADD, CMPXCHG, ...).
	 * XADD is just the fastest instruction of the alternatives,
	 * but it will only ever add to '0'.
	 */
	s_wr_seq = os_atomic_load(&smr->smr_clock.s_wr_seq, relaxed);
#if __x86_64__
	/* [R1] */
	old_seq = os_atomic_add_orig(&pcpu->c_rd_seq, s_wr_seq, seq_cst);
#else
	old_seq = os_atomic_load(&pcpu->c_rd_seq, relaxed);
	os_atomic_store(&pcpu->c_rd_seq, s_wr_seq, relaxed);
	os_atomic_thread_fence(seq_cst); /* [R1] */
#endif
	assert(old_seq == SMR_SEQ_INVALID);
}

__attribute__((always_inline))
void
smr_enter(smr_t smr)
{
	disable_preemption();
	__smr_enter(smr, zpercpu_get(smr_pcpu(smr)));
}

__attribute__((always_inline))
void
smr_leave(smr_t smr)
{
	smr_pcpu_t pcpu = zpercpu_get(smr_pcpu(smr));

	/* [R2] */
	os_atomic_store(&pcpu->c_rd_seq, SMR_SEQ_INVALID, release);
	enable_preemption();
}

static inline smr_seq_t
__smr_wr_advance(smr_t smr)
{
	/* [W] */
	return os_atomic_add(&smr->smr_clock.s_wr_seq, SMR_SEQ_INC, release);
}

static inline smr_clock_t
__smr_wr_advance_combined(smr_t smr)
{
	smr_clock_t clk = { .s_wr_seq = SMR_SEQ_INC, };

	/*
	 * Do a combined increment to get consistent read/write positions.
	 */

	/* [W] */
	clk.s_combined = os_atomic_add(&smr->smr_clock.s_combined,
	    clk.s_combined, release);

	return clk;
}

static inline bool
__smr_rd_advance(smr_t smr, smr_seq_t goal, smr_seq_t rd_seq)
{
	smr_clock_t oclk, nclk;

	os_atomic_rmw_loop(&smr->smr_clock.s_combined,
	    oclk.s_combined, nclk.s_combined, relaxed, {
		nclk = oclk;

		os_atomic_thread_fence(seq_cst); /* [S3] */

		if (SMR_SEQ_CMP(rd_seq, <=, oclk.s_rd_seq)) {
		        os_atomic_rmw_loop_give_up(break);
		}
		nclk.s_rd_seq = rd_seq;
	});

	return SMR_SEQ_CMP(goal, <=, nclk.s_rd_seq);
}

__attribute__((noinline))
static bool
__smr_scan(smr_t smr, smr_seq_t goal, smr_clock_t clk, bool wait)
{
	smr_delta_t delta;
	smr_seq_t rd_seq;

	/*
	 * Validate that the goal is sane.
	 */
	delta = SMR_SEQ_DELTA(goal, clk.s_wr_seq);
	if (delta == SMR_SEQ_INC && smr->smr_budget) {
		/*
		 * This SMR clock uses deferred advance,
		 * and the goal is one inc in the future.
		 *
		 * If we can wait, then force the clock
		 * to advance, else we can't possibly succeed.
		 */
		if (!wait) {
			return false;
		}
		clk = __smr_wr_advance_combined(smr);
	} else if (delta > 0) {
		/*
		 * Invalid goal: the caller held on it for too long,
		 * and integers wrapped.
		 */
		return true;
	}

	os_atomic_thread_fence(seq_cst); /* [S2] */

	/*
	 * The read sequence can be no larger than the write sequence
	 * at the start of the poll.
	 *
	 * We know that on entry:
	 *
	 *     s_rd_seq < goal <= s_wr_seq
	 *
	 * The correctness of this algorithm relies on the fact that
	 * the SMR domain [s_rd_seq, s_wr_seq) can't possibly move
	 * by more than roughly (ULONG_MAX / 2) while __smr_scan()
	 * is running, otherwise the "rd_seq" we try to scan for
	 * might appear larger than s_rd_seq spuriously and we'd
	 * __smr_rd_advance() incorrectly.
	 *
	 * This is guaranteed by the fact that this represents
	 * advancing 2^62 times. At one advance every nanosecond,
	 * it takes more than a century, which makes it possible
	 * to call smr_wait() or smr_poll() with preemption enabled.
	 */
	rd_seq = clk.s_wr_seq;

	zpercpu_foreach(it, smr_pcpu(smr)) {
		smr_seq_t seq = os_atomic_load(&it->c_rd_seq, relaxed);

		while (seq != SMR_SEQ_INVALID) {
			/*
			 * Resolve the race documented in __smr_enter().
			 *
			 * The CPU has loaded a stale s_wr_seq, and s_rd_seq
			 * moved past this stale value.
			 *
			 * Its critical section is however properly serialized,
			 * but we can't know what the "correct" s_wr_seq it
			 * could have observed was. We have to assume `s_rd_seq`
			 * to prevent it from advancing.
			 */
			if (SMR_SEQ_CMP(seq, <, clk.s_rd_seq)) {
				seq = clk.s_rd_seq;
			}

			if (!wait || SMR_SEQ_CMP(goal, <=, seq)) {
				break;
			}

			disable_preemption();
			seq = hw_wait_while_equals_long(&it->c_rd_seq, seq);
			enable_preemption();
		}

		if (seq != SMR_SEQ_INVALID && SMR_SEQ_CMP(seq, <, rd_seq)) {
			rd_seq = seq;
		}
	}

	/*
	 * Advance the rd_seq as long as we observed a more recent value.
	 */
	return __smr_rd_advance(smr, goal, rd_seq);
}

static inline bool
__smr_poll(smr_t smr, smr_seq_t goal, bool wait)
{
	smr_clock_t clk;

	/*
	 * Load both the s_rd_seq and s_wr_seq in the right order so that we
	 * can't observe a s_rd_seq older than s_wr_seq.
	 */

	/* [S1] */
	clk.s_rd_seq = os_atomic_load(&smr->smr_clock.s_rd_seq, acquire);

	/*
	 * We expect this to be typical: the goal has already been observed.
	 */
	if (__probable(SMR_SEQ_CMP(goal, <=, clk.s_rd_seq))) {
		return true;
	}

	clk.s_wr_seq = os_atomic_load(&smr->smr_clock.s_wr_seq, relaxed);

	return __smr_scan(smr, goal, clk, wait);
}

smr_seq_t
smr_advance(smr_t smr)
{
	smr_clock_t clk;

	assert(!smr_entered(smr));

	/*
	 * We assume that there will at least be a successful __smr_poll
	 * call every 2^61 calls to smr_advance() or so, so we do not need
	 * to check if [s_rd_seq, s_wr_seq) is growing too wide.
	 */
	static_assert(sizeof(clk.s_wr_seq) == 8);
	return __smr_wr_advance(smr);
}

smr_seq_t
smr_deferred_advance_nopreempt(smr_t smr, unsigned long step)
{
	smr_pcpu_t pcpu = smr_pcpu(smr);

	assert(get_preemption_level() && !smr_entered_nopreempt(smr));

	if (os_sub_overflow(pcpu->c_rd_budget, step, &pcpu->c_rd_budget)) {
		pcpu->c_rd_budget = smr->smr_budget;
		return __smr_wr_advance(smr);
	}

	/*
	 * Deferred updates are about avoiding to touch the global c_wr_seq
	 * as often, and we return a sequence number in the future.
	 *
	 * This full barrier establishes a "happen before" relationship
	 * with the [W] barrier in the __smr_wr_advance() that will
	 * actually generate it.
	 */
	os_atomic_thread_fence(seq_cst);
	return SMR_SEQ_INC + os_atomic_load(&smr->smr_clock.s_wr_seq, relaxed);
}

smr_seq_t
smr_deferred_advance(smr_t smr, unsigned long step)
{
	smr_seq_t seq;

	disable_preemption();
	seq = smr_deferred_advance_nopreempt(smr, step);
	enable_preemption();

	return seq;
}

bool
smr_poll(smr_t smr, smr_seq_t goal)
{
	assert(!smr_entered(smr) && goal != SMR_SEQ_INVALID);
	return __smr_poll(smr, goal, false);
}

void
smr_wait(smr_t smr, smr_seq_t goal)
{
	assert(!smr_entered(smr) && goal != SMR_SEQ_INVALID);
	(void)__smr_poll(smr, goal, true);
}

void
smr_synchronize(smr_t smr)
{
	smr_clock_t clk;

	assert(!smr_entered(smr));
	clk = __smr_wr_advance_combined(smr);
	__smr_scan(smr, clk.s_wr_seq, clk, true);
}


#pragma mark - system global SMR

typedef struct smr_record {
	void                   *smrr_val;
	void                  (*smrr_dtor)(void *);
} *smr_record_t;

typedef struct smr_bucket {
	union {
		struct mpsc_queue_chain  smrb_mplink;
		STAILQ_ENTRY(smr_bucket) smrb_stqlink;
	};
	uint32_t             smrb_count;
	uint32_t             smrb_size;
	smr_seq_t            smrb_seq;
	struct smr_record    smrb_recs[];
} *smr_bucket_t;

STAILQ_HEAD(smr_bucket_list, smr_bucket);

static SMR_DEFINE_EARLY(smr_system);

/*! per-cpu state for smr pointers. */
static smr_bucket_t PERCPU_DATA(smr_bucket);

/*! the minimum number of items cached in per-cpu buckets */
static TUNABLE(uint32_t, smr_bucket_count_min, "smr_bucket_count_min", 8);

/*! the amount of memory pending retiring that causes a foreceful flush */
#if XNU_TARGET_OS_OSX
#define SMR_RETIRE_THRESHOLD_DEFAULT    (256 << 10)
#else
#define SMR_RETIRE_THRESHOLD_DEFAULT    (64 << 10)
#endif
static TUNABLE(vm_size_t, smr_retire_threshold, "smr_retire_threshold",
    SMR_RETIRE_THRESHOLD_DEFAULT);

/*! the number of items cached in per-cpu buckets */
static SECURITY_READ_ONLY_LATE(uint32_t) smr_bucket_count;

/*! the queue of elements that couldn't be freed immediately */
static struct smr_bucket_list smr_buckets_pending =
    STAILQ_HEAD_INITIALIZER(smr_buckets_pending);

/*! the atomic queue handling deferred deallocations */
static struct mpsc_daemon_queue smr_deallocate_queue;

__attribute__((always_inline))
bool
smr_global_entered(void)
{
	return smr_entered(&smr_system);
}

__attribute__((always_inline))
void
smr_global_enter(void)
{
	smr_enter(&smr_system);
}

__attribute__((always_inline))
void
smr_global_leave(void)
{
	smr_leave(&smr_system);
}

static smr_bucket_t
smr_bucket_alloc(zalloc_flags_t flags)
{
	return kalloc_type(struct smr_bucket, struct smr_record,
	           smr_bucket_count, Z_ZERO | flags);
}

static void
smr_bucket_free(smr_bucket_t bucket)
{
	return kfree_type(struct smr_bucket, struct smr_record,
	           smr_bucket_count, bucket);
}

void
smr_global_retire(void *value, size_t size, void (*destructor)(void *))
{
	smr_bucket_t *slot;
	smr_bucket_t bucket, free_bucket = NULL;

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
	slot = PERCPU_GET(smr_bucket);
	bucket = *slot;
	if (bucket && bucket->smrb_seq) {
		mpsc_daemon_enqueue(&smr_deallocate_queue,
		    &bucket->smrb_mplink, MPSC_QUEUE_NONE);
		*slot = bucket = NULL;
	}
	if (bucket == NULL) {
		if (free_bucket) {
			bucket = free_bucket;
			free_bucket = NULL;
		} else if ((bucket = smr_bucket_alloc(Z_NOWAIT)) == NULL) {
			enable_preemption();
			free_bucket = smr_bucket_alloc(Z_WAITOK | Z_NOFAIL);
			goto again;
		}
		*slot = bucket;
	}

	bucket->smrb_recs[bucket->smrb_count].smrr_val = value;
	bucket->smrb_recs[bucket->smrb_count].smrr_dtor = destructor;

	if (os_add_overflow(bucket->smrb_size, size, &bucket->smrb_size)) {
		bucket->smrb_size = UINT32_MAX;
	}

	if (++bucket->smrb_count == smr_bucket_count ||
	    bucket->smrb_size >= smr_retire_threshold) {
		/*
		 * This will be retired the next time around,
		 * to give readers a chance to notice the new clock.
		 */
		bucket->smrb_seq = smr_advance(&smr_system);
	}
	enable_preemption();

	if (__improbable(free_bucket)) {
		smr_bucket_free(free_bucket);
	}
}


static void
smr_deallocate_queue_invoke(mpsc_queue_chain_t e,
    __assert_only mpsc_daemon_queue_t dq)
{
	smr_bucket_t bucket;

	assert(dq == &smr_deallocate_queue);

	bucket = mpsc_queue_element(e, struct smr_bucket, smrb_mplink);
	smr_wait(&smr_system, bucket->smrb_seq);

	for (uint32_t i = 0; i < bucket->smrb_count; i++) {
		struct smr_record *smrr = &bucket->smrb_recs[i];

		smrr->smrr_dtor(smrr->smrr_val);
	}

	smr_bucket_free(bucket);
}

void
smr_register_mpsc_queue(void)
{
	thread_deallocate_daemon_register_queue(&smr_deallocate_queue,
	    smr_deallocate_queue_invoke);
}

static void
smr_startup(void)
{
	smr_bucket_count = zpercpu_count();
	if (smr_bucket_count < smr_bucket_count_min) {
		smr_bucket_count = smr_bucket_count_min;
	}
}
STARTUP(PERCPU, STARTUP_RANK_LAST, smr_startup);
