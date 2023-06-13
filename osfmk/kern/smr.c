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

#include <kern/locks_internal.h>
#include <kern/cpu_data.h>
#include <kern/mpsc_queue.h>
#include <kern/percpu.h>
#include <kern/smr.h>
#include <kern/smr_hash.h>
#include <kern/zalloc.h>
#include <sys/queue.h>
#include <os/hash.h>


#pragma mark - SMR domains

typedef struct smr_pcpu {
	smr_seq_t               c_rd_seq;
} *smr_pcpu_t;

/*
 * This SMR scheme is directly FreeBSD's "Global Unbounded Sequences".
 *
 * Major differences are:
 *
 * - only eager clocks are implemented (no lazy, no implicit)
 *
 *
 * SMR clocks have 3 state machines interacting at any given time:
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

#pragma mark SMR domains: init & helpers

__attribute__((always_inline, overloadable))
static inline smr_pcpu_t
__smr_pcpu(smr_t smr, int cpu)
{
	return zpercpu_get_cpu(smr->smr_pcpu, cpu);
}

__attribute__((always_inline, overloadable))
static inline smr_pcpu_t
__smr_pcpu(smr_t smr)
{
	return zpercpu_get(smr->smr_pcpu);
}

static inline void
__smr_pcpu_associate(smr_t smr, smr_pcpu_t pcpu)
{
	os_atomic_store(&smr->smr_pcpu, pcpu, release);
}

__startup_func
void
__smr_domain_init(smr_t smr)
{
	smr_pcpu_t pcpu;

	if (startup_phase < STARTUP_SUB_TUNABLES) {
		smr_seq_t *rd_seqp = &smr->smr_early;

		pcpu = __container_of(rd_seqp, struct smr_pcpu, c_rd_seq);
		smr->smr_pcpu = __zpcpu_mangle_for_boot(pcpu);
	} else {
		pcpu = zalloc_percpu_permanent_type(struct smr_pcpu);
		__smr_pcpu_associate(smr, pcpu);
	}
}

smr_t
smr_domain_create(smr_flags_t flags)
{
	smr_pcpu_t pcpu;
	smr_t smr;

	smr  = kalloc_type(struct smr, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	pcpu = zalloc_percpu(percpu_u64_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);

	smr->smr_clock.s_rd_seq = SMR_SEQ_INIT;
	smr->smr_clock.s_wr_seq = SMR_SEQ_INIT;
	smr->smr_flags = flags;

	__smr_pcpu_associate(smr, pcpu);

	return smr;
}

void
smr_domain_free(smr_t smr)
{
	smr_synchronize(smr);

	zfree_percpu(percpu_u64_zone, smr->smr_pcpu);
	kfree_type(struct smr, smr);
}

#pragma mark SMR domains: enter / leave

static inline bool
smr_entered_nopreempt(smr_t smr)
{
	return __smr_pcpu(smr)->c_rd_seq != SMR_SEQ_INVALID;
}

__attribute__((always_inline))
bool
smr_entered(smr_t smr)
{
	return get_preemption_level() != 0 && smr_entered_nopreempt(smr);
}

__attribute__((always_inline))
bool
smr_entered_cpu(smr_t smr, int cpu)
{
	return __smr_pcpu(smr, cpu)->c_rd_seq != SMR_SEQ_INVALID;
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
	old_seq = pcpu->c_rd_seq;
	os_atomic_store(&pcpu->c_rd_seq, s_wr_seq, relaxed);
	os_atomic_thread_fence(seq_cst); /* [R1] */
#endif
	assert(old_seq == SMR_SEQ_INVALID);
}

__attribute__((always_inline))
static void
__smr_leave(smr_pcpu_t pcpu)
{
	/* [R2] */
	os_atomic_store(&pcpu->c_rd_seq, SMR_SEQ_INVALID, release);
}

__attribute__((always_inline))
void
smr_enter(smr_t smr)
{
	disable_preemption();
	__smr_enter(smr, __smr_pcpu(smr));
}

__attribute__((always_inline))
void
smr_leave(smr_t smr)
{
	__smr_leave(__smr_pcpu(smr));
	enable_preemption();
}


#pragma mark SMR domains: advance, wait, poll, synchronize

static inline smr_seq_t
__smr_wr_advance(smr_t smr)
{
	/* [W] */
	return os_atomic_add(&smr->smr_clock.s_wr_seq, SMR_SEQ_INC, release);
}

static inline bool
__smr_rd_advance(smr_t smr, smr_seq_t goal, smr_seq_t rd_seq)
{
	smr_seq_t o_seq;

	os_atomic_thread_fence(seq_cst); /* [S3] */

	os_atomic_rmw_loop(&smr->smr_clock.s_rd_seq, o_seq, rd_seq, relaxed, {
		if (SMR_SEQ_CMP(rd_seq, <=, o_seq)) {
		        rd_seq = o_seq;
		        os_atomic_rmw_loop_give_up(break);
		}
	});

	return SMR_SEQ_CMP(goal, <=, rd_seq);
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
	if (delta == SMR_SEQ_INC) {
		/*
		 * This SMR clock uses deferred advance,
		 * and the goal is one inc in the future.
		 *
		 * If we can wait, then commit the sequence number,
		 * else we can't possibly succeed.
		 *
		 * Doing a commit here rather than an advance
		 * gives the hardware a chance to abort the
		 * transaction early in case of high contention
		 * compared to an unconditional advance.
		 */
		if (!wait) {
			return false;
		}
		if (lock_cmpxchgv(&smr->smr_clock.s_wr_seq,
		    clk.s_wr_seq, goal, &clk.s_wr_seq, relaxed)) {
			clk.s_wr_seq = goal;
		}
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

	zpercpu_foreach(it, smr->smr_pcpu) {
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
smr_deferred_advance(smr_t smr)
{
	os_atomic_thread_fence(seq_cst);
	return SMR_SEQ_INC + os_atomic_load(&smr->smr_clock.s_wr_seq, relaxed);
}

void
smr_deferred_advance_commit(smr_t smr, smr_seq_t seq)
{
	/*
	 * no barrier needed: smr_deferred_advance() had one already.
	 * no failure handling: it means someone updated the clock already!
	 * lock_cmpxchg: so that we pre-test for architectures needing it.
	 */
	assert(seq != SMR_SEQ_INVALID);
	lock_cmpxchg(&smr->smr_clock.s_wr_seq, seq - SMR_SEQ_INC, seq, relaxed);
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

	/*
	 * Similar to __smr_poll() but also does a deferred advance which
	 * __smr_scan will commit.
	 */

	clk.s_rd_seq = os_atomic_load(&smr->smr_clock.s_rd_seq, relaxed);
	os_atomic_thread_fence(seq_cst);
	clk.s_wr_seq = os_atomic_load(&smr->smr_clock.s_wr_seq, relaxed);

	(void)__smr_scan(smr, clk.s_wr_seq + SMR_SEQ_INC, clk, true);
}


#pragma mark system global SMR

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

SMR_DEFINE(smr_system);

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


#pragma mark - SMR hash tables

static struct smrq_slist_head *
smr_hash_alloc_array(size_t size)
{
	return kalloc_type(struct smrq_slist_head, size,
	           Z_WAITOK | Z_ZERO | Z_SPRAYQTN);
}

static void
smr_hash_free_array(struct smrq_slist_head *array, size_t size)
{
	kfree_type(struct smrq_slist_head, size, array);
}

static inline uintptr_t
smr_hash_array_encode(struct smrq_slist_head *array, uint16_t order)
{
	uintptr_t ptr;

	ptr  = (uintptr_t)array;
	ptr &= ~SMRH_ARRAY_ORDER_MASK;
	ptr |= (uintptr_t)order << SMRH_ARRAY_ORDER_SHIFT;

	return ptr;
}

#pragma mark SMR simple hash tables

void
smr_hash_init(struct smr_hash *smrh, size_t size)
{
	struct smrq_slist_head *array;
	uint16_t shift;

	assert(size);
	shift = (uint16_t)flsll(size - 1);
	size  = 1UL << shift;
	if (startup_phase >= STARTUP_SUB_LOCKDOWN) {
		assert(size * sizeof(struct smrq_slist_head) <=
		    KALLOC_SAFE_ALLOC_SIZE);
	}
	array = smr_hash_alloc_array(size);

	*smrh = (struct smr_hash){
		.smrh_array = smr_hash_array_encode(array, 64 - shift),
	};
}

void
smr_hash_destroy(struct smr_hash *smrh)
{
	struct smr_hash_array array = smr_hash_array_decode(smrh);

	smr_hash_free_array(array.smrh_array, smr_hash_size(array));
	*smrh = (struct smr_hash){ };
}

void
__smr_hash_serialized_clear(
	struct smr_hash        *smrh,
	smrh_traits_t          smrht,
	void                 (^free)(void *obj))
{
	struct smr_hash_array array = smr_hash_array_decode(smrh);

	for (size_t i = 0; i < smr_hash_size(array); i++) {
		struct smrq_slink *link;
		__smrq_slink_t *prev;

		prev = &array.smrh_array[i].first;
		while ((link = smr_serialized_load(prev))) {
			prev = &link->next;
			free(__smrht_link_to_obj(smrht, link));
		}

		smr_clear_store(&array.smrh_array[i].first);
	}

	smrh->smrh_count = 0;
}

kern_return_t
__smr_hash_shrink_and_unlock(
	struct smr_hash        *smrh,
	lck_mtx_t              *lock,
	smrh_traits_t           smrht)
{
	struct smr_hash_array decptr = smr_hash_array_decode(smrh);
	struct smrq_slist_head *newarray, *oldarray;
	uint16_t neworder = decptr.smrh_order + 1;
	size_t   oldsize  = smr_hash_size(decptr);
	size_t   newsize  = oldsize / 2;

	assert(newsize);

	if (os_atomic_load(&smrh->smrh_resizing, relaxed)) {
		lck_mtx_unlock(lock);
		return KERN_FAILURE;
	}

	os_atomic_store(&smrh->smrh_resizing, true, relaxed);
	lck_mtx_unlock(lock);

	newarray = smr_hash_alloc_array(newsize);
	if (newarray == NULL) {
		os_atomic_store(&smrh->smrh_resizing, false, relaxed);
		return KERN_RESOURCE_SHORTAGE;
	}

	lck_mtx_lock(lock);

	/*
	 * Step 1: collapse all the chains in pairs.
	 */
	oldarray = decptr.smrh_array;

	for (size_t i = 0; i < newsize; i++) {
		newarray[i] = oldarray[i];
		smrq_serialized_append(&newarray[i], &oldarray[i + newsize]);
	}

	/*
	 * Step 2: publish the new array.
	 */
	os_atomic_store(&smrh->smrh_array,
	    smr_hash_array_encode(newarray, neworder), release);

	os_atomic_store(&smrh->smrh_resizing, false, relaxed);

	lck_mtx_unlock(lock);

	/*
	 * Step 3: free the old array once readers can't observe the old values.
	 */
	smr_synchronize(smrht->domain);

	smr_hash_free_array(oldarray, oldsize);
	return KERN_SUCCESS;
}

kern_return_t
__smr_hash_grow_and_unlock(
	struct smr_hash        *smrh,
	lck_mtx_t              *lock,
	smrh_traits_t           smrht)
{
	struct smr_hash_array decptr = smr_hash_array_decode(smrh);
	struct smrq_slist_head *newarray, *oldarray;
	__smrq_slink_t **prevarray;
	uint16_t neworder = decptr.smrh_order - 1;
	size_t   oldsize  = smr_hash_size(decptr);
	size_t   newsize  = 2 * oldsize;
	bool     needs_another_round = false;

	if (smrh->smrh_resizing) {
		lck_mtx_unlock(lock);
		return KERN_FAILURE;
	}

	smrh->smrh_resizing = true;
	lck_mtx_unlock(lock);

	newarray = smr_hash_alloc_array(newsize);
	if (newarray == NULL) {
		os_atomic_store(&smrh->smrh_resizing, false, relaxed);
		return KERN_RESOURCE_SHORTAGE;
	}

	prevarray = kalloc_type(__smrq_slink_t *, newsize,
	    Z_WAITOK | Z_ZERO | Z_SPRAYQTN);
	if (prevarray == NULL) {
		smr_hash_free_array(newarray, newsize);
		os_atomic_store(&smrh->smrh_resizing, false, relaxed);
		return KERN_RESOURCE_SHORTAGE;
	}


	lck_mtx_lock(lock);

	/*
	 * Step 1: create a duplicated array with twice as many heads.
	 */
	oldarray = decptr.smrh_array;

	memcpy(newarray, oldarray, oldsize * sizeof(newarray[0]));
	memcpy(newarray + oldsize, oldarray, oldsize * sizeof(newarray[0]));

	/*
	 * Step 2: Publish the new array, and wait for readers to observe it
	 *         before we do any change.
	 */
	os_atomic_store(&smrh->smrh_array,
	    smr_hash_array_encode(newarray, neworder), release);

	smr_synchronize(smrht->domain);


	/*
	 * Step 3: split the lists.
	 */

	/*
	 * If the list we are trying to split looked like this,
	 * where L elements will go to the "left" bucket and "R"
	 * to the right one:
	 *
	 *     old_head --> L1 --> L2                -> L5
	 *                            \             /      \
	 *                             -> R3 --> R4         -> R6 --> NULL
	 *
	 * Then make sure the new heads point to their legitimate first element,
	 * leading to this state:
	 *
	 *     l_head   --> L1 --> L2                -> L5
	 *                            \             /      \
	 *     r_head   ----------------> R3 --> R4         -> R6 --> NULL
	 *
	 *
	 *     prevarray[left]  = &L2->next
	 *     prevarray[right] = &r_head
	 *     oldarray[old]    = L2
	 */

	for (size_t i = 0; i < oldsize; i++) {
		struct smrq_slink *link, *next;
		uint32_t want_mask;

		link = smr_serialized_load(&oldarray[i].first);
		if (link == NULL) {
			continue;
		}

		want_mask = smrht->obj_hash(link, 0) & oldsize;
		while ((next = smr_serialized_load(&link->next)) &&
		    (smrht->obj_hash(next, 0) & oldsize) == want_mask) {
			link = next;
		}

		if (want_mask == 0) {
			/* elements seen go to the "left" bucket */
			prevarray[i] = &link->next;
			prevarray[i + oldsize] = &newarray[i + oldsize].first;
			smr_serialized_store_relaxed(prevarray[i + oldsize], next);
		} else {
			/* elements seen go to the "right" bucket */
			prevarray[i] = &newarray[i].first;
			prevarray[i + oldsize] = &link->next;
			smr_serialized_store_relaxed(prevarray[i], next);
		}

		smr_serialized_store_relaxed(&oldarray[i].first,
		    next ? link : NULL);

		needs_another_round |= (next != NULL);
	}

	/*
	 * At this point, when we split further, we must wait for
	 * readers to observe the previous state before we split
	 * further. Indeed, reusing the example above, the next
	 * round of splitting would end up with this:
	 *
	 *     l_head   --> L1 --> L2 ----------------> L5
	 *                                          /      \
	 *     r_head   ----------------> R3 --> R4         -> R6 --> NULL
	 *
	 *
	 *     prevarray[left]  = &L2->next
	 *     prevarray[right] = &R4->next
	 *     oldarray[old]    = R4
	 *
	 * But we must be sure that no readers can observe r_head
	 * having been L1, otherwise a stale reader might skip over
	 * R3/R4.
	 *
	 * Generally speaking we need to do that each time we do a round
	 * of splitting that isn't terminating the list with NULL.
	 */

	while (needs_another_round) {
		smr_synchronize(smrht->domain);

		needs_another_round = false;

		for (size_t i = 0; i < oldsize; i++) {
			struct smrq_slink *link, *next;
			uint32_t want_mask;

			link = smr_serialized_load(&oldarray[i].first);
			if (link == NULL) {
				continue;
			}

			/*
			 * If `prevarray[i]` (left) points to the linkage
			 * we stopped at, then it means the next element
			 * will be "to the right" and vice versa.
			 *
			 * We also already know "next" exists, so only probe
			 * after it.
			 */
			if (prevarray[i] == &link->next) {
				want_mask = (uint32_t)oldsize;
			} else {
				want_mask = 0;
			}

			link = smr_serialized_load(&link->next);

			while ((next = smr_serialized_load(&link->next)) &&
			    (smrht->obj_hash(next, 0) & oldsize) == want_mask) {
				link = next;
			}

			if (want_mask == 0) {
				/* elements seen go to the "left" bucket */
				prevarray[i] = &link->next;
				smr_serialized_store_relaxed(prevarray[i + oldsize], next);
			} else {
				/* elements seen go to the "right" bucket */
				smr_serialized_store_relaxed(prevarray[i], next);
				prevarray[i + oldsize] = &link->next;
			}

			smr_serialized_store_relaxed(&oldarray[i].first,
			    next ? link : NULL);

			needs_another_round |= (next != NULL);
		}
	}

	smrh->smrh_resizing = false;
	lck_mtx_unlock(lock);

	/*
	 * Step 4: cleanup, no need to wait for readers, this happened already
	 *         at least once for splitting reasons.
	 */
	smr_hash_free_array(oldarray, oldsize);
	kfree_type(__smrq_slink_t *, newsize, prevarray);
	return KERN_SUCCESS;
}

#pragma mark SMR scalable hash tables

#define SMRSH_MIGRATED  ((struct smrq_slink *)SMRSH_BUCKET_STOP_BIT)
static LCK_GRP_DECLARE(smr_shash_grp, "smr_shash");

static inline size_t
__smr_shash_min_size(struct smr_shash *smrh)
{
	return 1ul << smrh->smrsh_min_shift;
}

static inline size_t
__smr_shash_size_for_shift(uint8_t shift)
{
	return (~0u >> shift) + 1;
}

static inline size_t
__smr_shash_cursize(smrsh_state_t state)
{
	return __smr_shash_size_for_shift(state.curshift);
}

static void
__smr_shash_bucket_init(hw_lck_ptr_t *head)
{
	hw_lck_ptr_init(head, __smr_shash_bucket_stop(head), &smr_shash_grp);
}

static void
__smr_shash_bucket_destroy(hw_lck_ptr_t *head)
{
	hw_lck_ptr_destroy(head, &smr_shash_grp);
}

__attribute__((noinline))
void *
__smr_shash_entered_find_slow(
	const struct smr_shash *smrh,
	smrh_key_t              key,
	hw_lck_ptr_t           *head,
	smrh_traits_t           traits)
{
	struct smrq_slink *link;
	smrsh_state_t state;
	uint32_t hash;

	/* wait for the rehashing to be done into their target buckets */
	hw_lck_ptr_wait_for_value(head, SMRSH_MIGRATED, &smr_shash_grp);

	state = os_atomic_load(&smrh->smrsh_state, dependency);
	hash  = __smr_shash_hash(smrh, state.newidx, key, traits);
	head  = __smr_shash_bucket(smrh, state, SMRSH_NEW, hash);

	link  = hw_lck_ptr_value(head);
	while (!__smr_shash_is_stop(link)) {
		if (traits->obj_equ(link, key)) {
			return __smrht_link_to_obj(traits, link);
		}
		link = smr_entered_load(&link->next);
	}

	assert(link == __smr_shash_bucket_stop(head));
	return NULL;
}

static const uint8_t __smr_shash_grow_ratio[] = {
	[SMRSH_COMPACT]           = 6,
	[SMRSH_BALANCED]          = 4,
	[SMRSH_BALANCED_NOSHRINK] = 4,
	[SMRSH_FASTEST]           = 2,
};

static inline uint64_t
__smr_shash_count(struct smr_shash *smrh)
{
	int64_t count = (int64_t)counter_load(&smrh->smrsh_count);

	/*
	 * negative values make no sense and is likely due to some
	 * stale values being read.
	 */
	return count < 0 ? 0ull : (uint64_t)count;
}

static inline bool
__smr_shash_should_grow(
	struct smr_shash       *smrh,
	smrsh_state_t           state,
	uint64_t                count)
{
	size_t size = __smr_shash_cursize(state);

	/* grow if elem:bucket ratio is worse than grow_ratio:1 */
	return count > __smr_shash_grow_ratio[smrh->smrsh_policy] * size;
}

static inline bool
__smr_shash_should_reseed(
	struct smr_shash       *smrh,
	size_t                  observed_depth)
{
	return observed_depth > 10 * __smr_shash_grow_ratio[smrh->smrsh_policy];
}

static inline bool
__smr_shash_should_shrink(
	struct smr_shash       *smrh,
	smrsh_state_t           state,
	uint64_t                count)
{
	size_t size = __smr_shash_cursize(state);

	switch (smrh->smrsh_policy) {
	case SMRSH_COMPACT:
		/* shrink if bucket:elem ratio is worse than 1:1 */
		return size > count && size > __smr_shash_min_size(smrh);
	case SMRSH_BALANCED:
		/* shrink if bucket:elem ratio is worse than 2:1 */
		return size > 2 * count && size > __smr_shash_min_size(smrh);
	case SMRSH_BALANCED_NOSHRINK:
	case SMRSH_FASTEST:
		return false;
	}
}

static inline void
__smr_shash_schedule_rehash(
	struct smr_shash       *smrh,
	smrh_traits_t           traits,
	smrsh_rehash_t          reason)
{
	smrsh_rehash_t rehash;

	rehash = os_atomic_load(&smrh->smrsh_rehashing, relaxed);
	if (rehash & reason) {
		return;
	}

	rehash = os_atomic_or_orig(&smrh->smrsh_rehashing, reason, relaxed);
	if (!rehash) {
		thread_call_enter1(smrh->smrsh_callout,
		    __DECONST(void *, traits));
	}
}

void *
__smr_shash_entered_get_or_insert(
	struct smr_shash       *smrh,
	smrh_key_t              key,
	struct smrq_slink      *link,
	smrh_traits_t           traits)
{
	struct smrq_slink *first;
	struct smrq_slink *other;
	uint32_t hash, depth;
	smrsh_state_t state;
	hw_lck_ptr_t *head;
	void *obj;

	state = os_atomic_load(&smrh->smrsh_state, dependency);
	hash  = __smr_shash_hash(smrh, state.curidx, key, traits);
	head  = __smr_shash_bucket(smrh, state, SMRSH_CUR, hash);
	first = hw_lck_ptr_lock_nopreempt(head, &smr_shash_grp);

	if (__improbable(first == SMRSH_MIGRATED)) {
		hw_lck_ptr_unlock_nopreempt(head, first, &smr_shash_grp);

		state = os_atomic_load(&smrh->smrsh_state, dependency);
		hash  = __smr_shash_hash(smrh, state.newidx, key, traits);
		head  = __smr_shash_bucket(smrh, state, SMRSH_NEW, hash);
		first = hw_lck_ptr_lock_nopreempt(head, &smr_shash_grp);
	}

	depth = 0;
	other = first;
	while (!__smr_shash_is_stop(other)) {
		depth++;
		if (traits->obj_equ(other, key)) {
			obj = __smrht_link_to_obj(traits, other);
			if (traits->obj_try_get(obj)) {
				hw_lck_ptr_unlock_nopreempt(head, first,
				    &smr_shash_grp);
				return obj;
			}
			break;
		}
		other = smr_serialized_load(&other->next);
	}

	counter_inc_preemption_disabled(&smrh->smrsh_count);
	smr_serialized_store_relaxed(&link->next, first);
	hw_lck_ptr_unlock_nopreempt(head, link, &smr_shash_grp);

	if (__smr_shash_should_reseed(smrh, depth)) {
		__smr_shash_schedule_rehash(smrh, traits, SMRSH_REHASH_RESEED);
	} else if (depth * 2 >= __smr_shash_grow_ratio[smrh->smrsh_policy] &&
	    __smr_shash_should_grow(smrh, state, __smr_shash_count(smrh))) {
		__smr_shash_schedule_rehash(smrh, traits, SMRSH_REHASH_GROW);
	}
	return NULL;
}

__abortlike
static void
__smr_shash_missing_elt_panic(
	struct smr_shash        *smrh,
	struct smrq_slink       *link,
	smrh_traits_t           traits)
{
	panic("Unable to find item %p (linkage %p) in %p (traits %p)",
	    __smrht_link_to_obj(traits, link), link, smrh, traits);
}

smr_shash_mut_cursor_t
__smr_shash_entered_mut_begin(
	struct smr_shash       *smrh,
	struct smrq_slink      *link,
	smrh_traits_t           traits)
{
	struct smrq_slink *first, *next;
	__smrq_slink_t *prev;
	smrsh_state_t state;
	hw_lck_ptr_t *head;
	uint32_t hash;

	state = os_atomic_load(&smrh->smrsh_state, dependency);
	hash  = __smr_shash_hash(smrh, state.curidx, link, traits);
	head  = __smr_shash_bucket(smrh, state, SMRSH_CUR, hash);
	first = hw_lck_ptr_lock_nopreempt(head, &smr_shash_grp);

	if (__improbable(first == SMRSH_MIGRATED)) {
		hw_lck_ptr_unlock_nopreempt(head, first, &smr_shash_grp);

		state = os_atomic_load(&smrh->smrsh_state, dependency);
		hash  = __smr_shash_hash(smrh, state.newidx, link, traits);
		head  = __smr_shash_bucket(smrh, state, SMRSH_NEW, hash);
		first = hw_lck_ptr_lock_nopreempt(head, &smr_shash_grp);
	}

	next = first;
	while (next != link) {
		if (__smr_shash_is_stop(next)) {
			__smr_shash_missing_elt_panic(smrh, link, traits);
		}
		prev  = &next->next;
		next  = smr_serialized_load(prev);
	}

	return (smr_shash_mut_cursor_t){ .head = head, .prev = prev };
}

void
__smr_shash_entered_mut_erase(
	struct smr_shash       *smrh,
	smr_shash_mut_cursor_t  cursor,
	struct smrq_slink      *link,
	smrh_traits_t           traits)
{
	struct smrq_slink *next, *first;
	smrsh_state_t state;

	first = hw_lck_ptr_value(cursor.head);

	next  = smr_serialized_load(&link->next);
	if (first == link) {
		hw_lck_ptr_unlock_nopreempt(cursor.head, next, &smr_shash_grp);
	} else {
		smr_serialized_store_relaxed(cursor.prev, next);
		hw_lck_ptr_unlock_nopreempt(cursor.head, first, &smr_shash_grp);
	}
	counter_dec_preemption_disabled(&smrh->smrsh_count);

	state = atomic_load_explicit(&smrh->smrsh_state, memory_order_relaxed);
	if (first == link && __smr_shash_is_stop(next) &&
	    __smr_shash_should_shrink(smrh, state, __smr_shash_count(smrh))) {
		__smr_shash_schedule_rehash(smrh, traits, SMRSH_REHASH_SHRINK);
	}
}

void
__smr_shash_entered_mut_replace(
	smr_shash_mut_cursor_t  cursor,
	struct smrq_slink      *old_link,
	struct smrq_slink      *new_link)
{
	struct smrq_slink *first, *next;

	first = hw_lck_ptr_value(cursor.head);

	next  = smr_serialized_load(&old_link->next);
	smr_serialized_store_relaxed(&new_link->next, next);
	if (first == old_link) {
		hw_lck_ptr_unlock_nopreempt(cursor.head, new_link, &smr_shash_grp);
	} else {
		smr_serialized_store_relaxed(cursor.prev, new_link);
		hw_lck_ptr_unlock_nopreempt(cursor.head, first, &smr_shash_grp);
	}
}

void
__smr_shash_entered_mut_abort(smr_shash_mut_cursor_t cursor)
{
	hw_lck_ptr_unlock_nopreempt(cursor.head,
	    hw_lck_ptr_value(cursor.head), &smr_shash_grp);
}

static kern_return_t
__smr_shash_rehash_with_target(
	struct smr_shash       *smrh,
	smrsh_state_t           state,
	uint8_t                 newshift,
	smrh_traits_t           traits)
{
	const size_t FLAT_SIZE = 256;
	struct smrq_slink *flat_queue[FLAT_SIZE];

	size_t oldsize, newsize;
	hw_lck_ptr_t *oldarray;
	hw_lck_ptr_t *newarray;
	uint32_t newseed;
	uint8_t oldidx;

	/*
	 * This function resizes a scalable hash table.
	 *
	 * It doesn't require a lock because it is the callout
	 * of a THREAD_CALL_ONCE thread call.
	 */

	oldidx         = state.curidx;
	state.newidx   = 1 - state.curidx;
	state.newshift = newshift;
	assert(__smr_shash_load_array(smrh, state.newidx) == NULL);

	oldsize = __smr_shash_cursize(state);
	newsize = __smr_shash_size_for_shift(newshift);

	oldarray = __smr_shash_load_array(smrh, state.curidx);
	newarray = (hw_lck_ptr_t *)smr_hash_alloc_array(newsize);
	newseed  = (uint32_t)early_random();

	if (newarray == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	/*
	 * Step 1: initialize the new array and seed,
	 *         and then publish the state referencing it.
	 *
	 *         We do not need to synchronize explicitly with SMR,
	 *         because readers/writers will notice rehashing when
	 *         the bucket they interact with has a SMRSH_MIGRATED
	 *         value.
	 */

	for (size_t i = 0; i < newsize; i++) {
		__smr_shash_bucket_init(&newarray[i]);
	}
	os_atomic_store(&smrh->smrsh_array[state.newidx], newarray, relaxed);
	os_atomic_store(&smrh->smrsh_seed[state.newidx], newseed, relaxed);
	os_atomic_store(&smrh->smrsh_state, state, release);

	/*
	 * Step 2: migrate buckets "atomically" under the old bucket lock.
	 *
	 *         This migration is atomic for writers because
	 *         they take the old bucket lock first, and if
	 *         they observe SMRSH_MIGRATED as the value,
	 *         go look in the new bucket instead.
	 *
	 *         This migration is atomic for readers, because
	 *         as we move elements to their new buckets,
	 *         the hash chains will not circle back to their
	 *         bucket head (the "stop" value won't match),
	 *         or the bucket head will be SMRSH_MIGRATED.
	 *
	 *         This causes a slowpath which spins waiting
	 *         for SMRSH_MIGRATED to appear and then looks
	 *         in the new bucket.
	 */
	for (size_t i = 0; i < oldsize; i++) {
		struct smrq_slink *first, *link, *next;
		hw_lck_ptr_t *head;
		uint32_t hash;
		size_t n = 0;

		link = first = hw_lck_ptr_lock(&oldarray[i], &smr_shash_grp);

		while (!__smr_shash_is_stop(link)) {
			flat_queue[n++ % FLAT_SIZE] = link;
			link = smr_serialized_load(&link->next);
		}

		while (n-- > 0) {
			for (size_t j = (n % FLAT_SIZE) + 1; j-- > 0;) {
				link = flat_queue[j];
				hash = traits->obj_hash(link, newseed);
				head = &newarray[hash >> newshift];
				next = hw_lck_ptr_lock_nopreempt(head,
				    &smr_shash_grp);
				smr_serialized_store_relaxed(&link->next, next);
				hw_lck_ptr_unlock_nopreempt(head, link,
				    &smr_shash_grp);
			}
			n &= ~(FLAT_SIZE - 1);

			/*
			 * If there were more than FLAT_SIZE elements in the
			 * chain (which is super unlikely and in many ways,
			 * worrisome), then we need to repopoulate
			 * the flattened queue array for each run.
			 *
			 * This is O(n^2) but we have worse problems anyway
			 * if we ever hit this path.
			 */
			if (__improbable(n > 0)) {
				link = first;
				for (size_t j = 0; j < n - FLAT_SIZE; j++) {
					link = smr_serialized_load(&link->next);
				}

				flat_queue[0] = link;
				for (size_t j = 1; j < FLAT_SIZE; j++) {
					link = smr_serialized_load(&link->next);
					flat_queue[j] = link;
				}
			}
		}

		hw_lck_ptr_unlock(&oldarray[i], SMRSH_MIGRATED, &smr_shash_grp);
	}

	/*
	 * Step 3: deallocate the old array of buckets,
	 *         making sure to hide it from readers.
	 */

	state.curshift = state.newshift;
	state.curidx   = state.newidx;
	os_atomic_store(&smrh->smrsh_state, state, release);

	smr_synchronize(traits->domain);

	os_atomic_store(&smrh->smrsh_array[oldidx], NULL, relaxed);
	for (size_t i = 0; i < oldsize; i++) {
		__smr_shash_bucket_destroy(&oldarray[i]);
	}
	smr_hash_free_array((struct smrq_slist_head *)oldarray, oldsize);

	return KERN_SUCCESS;
}

static void
__smr_shash_rehash(thread_call_param_t arg0, thread_call_param_t arg1)
{
	struct smr_shash *smrh   = arg0;
	smrh_traits_t     traits = arg1;
	smrsh_rehash_t    reason;
	smrsh_state_t     state;
	uint64_t          count;
	kern_return_t     kr;

	do {
		reason = os_atomic_xchg(&smrh->smrsh_rehashing,
		    SMRSH_REHASH_RUNNING, relaxed);

		state  = os_atomic_load(&smrh->smrsh_state, relaxed);
		count  = __smr_shash_count(smrh);

		if (__smr_shash_should_grow(smrh, state, count)) {
			kr = __smr_shash_rehash_with_target(smrh, state,
			    state.curshift - 1, traits);
		} else if (__smr_shash_should_shrink(smrh, state, count)) {
			kr = __smr_shash_rehash_with_target(smrh, state,
			    state.curshift + 1, traits);
		} else if (reason & SMRSH_REHASH_RESEED) {
			kr = __smr_shash_rehash_with_target(smrh, state,
			    state.curshift, traits);
		} else {
			kr = KERN_SUCCESS;
		}

		if (kr == KERN_RESOURCE_SHORTAGE) {
			uint64_t deadline;

			os_atomic_or(&smrh->smrsh_rehashing, reason, relaxed);
			nanoseconds_to_deadline(NSEC_PER_MSEC, &deadline);
			thread_call_enter1_delayed(smrh->smrsh_callout,
			    arg1, deadline);
			break;
		}
	} while (!os_atomic_cmpxchg(&smrh->smrsh_rehashing,
	    SMRSH_REHASH_RUNNING, SMRSH_REHASH_NONE, relaxed));
}

void
smr_shash_init(struct smr_shash *smrh, smrsh_policy_t policy, size_t min_size)
{
	smrsh_state_t state;
	hw_lck_ptr_t *array;
	uint8_t shift;
	size_t size;

	switch (policy) {
	case SMRSH_COMPACT:
		if (min_size < 2) {
			min_size = 2;
		}
		break;
	default:
		if (min_size < 16) {
			min_size = 16;
		}
		break;
	}

	switch (policy) {
	case SMRSH_COMPACT:
		size = MIN(2, min_size);
		break;
	case SMRSH_BALANCED:
	case SMRSH_BALANCED_NOSHRINK:
		size = MIN(16, min_size);
		break;
	case SMRSH_FASTEST:
		size = min_size;
		break;
	}

	if (size > KALLOC_SAFE_ALLOC_SIZE / sizeof(*array)) {
		size = KALLOC_SAFE_ALLOC_SIZE / sizeof(*array);
	}
	shift = (uint8_t)__builtin_clz((uint32_t)(size - 1));
	size  = (~0u >> shift) + 1;
	array = (hw_lck_ptr_t *)smr_hash_alloc_array(size);
	for (size_t i = 0; i < size; i++) {
		__smr_shash_bucket_init(&array[i]);
	}

	state = (smrsh_state_t){
		.curshift = shift,
		.newshift = shift,
	};
	*smrh = (struct smr_shash){
		.smrsh_array[0]  = array,
		.smrsh_seed[0]   = (uint32_t)early_random(),
		.smrsh_state     = state,
		.smrsh_policy    = policy,
		.smrsh_min_shift = (uint8_t)flsll(min_size - 1),
	};
	counter_alloc(&smrh->smrsh_count);
	smrh->smrsh_callout  = thread_call_allocate_with_options(__smr_shash_rehash,
	    smrh, THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
}

void
__smr_shash_destroy(
	struct smr_shash       *smrh,
	smrh_traits_t           traits,
	void                  (^free)(void *))
{
	smrsh_state_t state;
	hw_lck_ptr_t *array;
	size_t size;

	thread_call_cancel_wait(smrh->smrsh_callout);

	state = os_atomic_load(&smrh->smrsh_state, dependency);
	assert(state.curidx == state.newidx);
	assert(__smr_shash_load_array(smrh, 1 - state.curidx) == NULL);
	size  = __smr_shash_cursize(state);
	array = __smr_shash_load_array(smrh, state.curidx);

	if (free) {
		for (size_t i = 0; i < size; i++) {
			struct smrq_slink *link, *next;

			next = hw_lck_ptr_value(&array[i]);
			while (!__smr_shash_is_stop(next)) {
				link = next;
				next = smr_serialized_load(&link->next);
				free(__smrht_link_to_obj(traits, link));
			}
		}
	}
	for (size_t i = 0; i < size; i++) {
		__smr_shash_bucket_destroy(&array[i]);
	}

	thread_call_free(smrh->smrsh_callout);
	counter_free(&smrh->smrsh_count);
	smr_hash_free_array((struct smrq_slist_head *)array, size);
	bzero(smrh, sizeof(*smrh));
}


#pragma mark misc

void
__smr_linkage_invalid(__smrq_link_t *link)
{
	struct smrq_link *elem = __container_of(link, struct smrq_link, next);
	struct smrq_link *next = smr_serialized_load(&elem->next);

	panic("Invalid queue linkage: elt:%p next:%p next->prev:%p",
	    elem, next, __container_of(next->prev, struct smrq_link, next));
}

void
__smr_stail_invalid(__smrq_slink_t *link, __smrq_slink_t *last)
{
	struct smrq_slink *elem = __container_of(link, struct smrq_slink, next);
	struct smrq_slink *next = smr_serialized_load(&elem->next);

	if (next) {
		panic("Invalid queue tail (element past end): elt:%p elt->next:%p",
		    elem, next);
	} else {
		panic("Invalid queue tail (early end): elt:%p tail:%p",
		    elem, __container_of(last, struct smrq_slink, next));
	}
}

void
__smr_tail_invalid(__smrq_link_t *link, __smrq_link_t *last)
{
	struct smrq_link *elem = __container_of(link, struct smrq_link, next);
	struct smrq_link *next = smr_serialized_load(&elem->next);

	if (next) {
		panic("Invalid queue tail (element past end): elt:%p elt->next:%p",
		    elem, next);
	} else {
		panic("Invalid queue tail (early end): elt:%p tail:%p",
		    elem, __container_of(last, struct smrq_link, next));
	}
}
