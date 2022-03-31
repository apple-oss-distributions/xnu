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

#include <kern/smr.h>
#include <kern/cpu_data.h>
#include <kern/zalloc.h>

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
} *smr_pcpu_t;

#define SMR_SEQ_DELTA(a, b)     ((smr_delta_t)((a) - (b)))
#define SMR_SEQ_CMP(a, op, b)   (SMR_SEQ_DELTA(a, b) op 0)

#define SMR_SEQ_INC             2ul

#define SMR_EARLY_COUNT         32

/*
 * On 32 bit systems, the sequence numbers might wrap.
 */
#if __LP64__
#define smr_critical_enter()
#define smr_critical_leave()
#else
#define smr_critical_enter()    disable_preemption()
#define smr_critical_leave()    enable_preemption()
#endif /* !__LP64__ */

__startup_data
static struct {
	struct smr_pcpu array[SMR_EARLY_COUNT];
	unsigned        used;
} smr_boot;

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
	old_seq = os_atomic_add_orig(&pcpu->c_rd_seq, s_wr_seq, seq_cst);
#else
	old_seq = os_atomic_load(&pcpu->c_rd_seq, relaxed);
	os_atomic_store(&pcpu->c_rd_seq, s_wr_seq, relaxed);
	os_atomic_thread_fence(seq_cst);
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

	os_atomic_store(&pcpu->c_rd_seq, SMR_SEQ_INVALID, release);
	enable_preemption();
}

#if __LP64__
static inline smr_seq_t
__smr_wr_advance(smr_t smr)
{
	return os_atomic_add(&smr->smr_clock.s_wr_seq, SMR_SEQ_INC, release);
}
#endif /* __LP64__ */

static inline smr_clock_t
__smr_wr_advance_combined(smr_t smr)
{
	smr_clock_t clk = { .s_wr_seq = SMR_SEQ_INC, };

	/*
	 * Do a combined increment to get consistent read/write positions.
	 */
	clk.s_combined = os_atomic_add(&smr->smr_clock.s_combined,
	    clk.s_combined, release);

	return clk;
}

static inline smr_seq_t
__smr_rd_advance(smr_t smr, smr_seq_t rd_seq)
{
	smr_seq_t s_rd_seq;

	s_rd_seq = os_atomic_load(&smr->smr_clock.s_rd_seq, relaxed);

	if (SMR_SEQ_CMP(rd_seq, >, s_rd_seq)) {
		if (os_atomic_cmpxchgv(&smr->smr_clock.s_rd_seq,
		    s_rd_seq, rd_seq, &s_rd_seq, relaxed)) {
			return rd_seq;
		}
	}

	return s_rd_seq;
}

__attribute__((noinline))
static bool
__smr_scan(smr_t smr, smr_seq_t goal, smr_clock_t clk, bool wait)
{
	smr_seq_t rd_seq;

	/*
	 * Validate that the goal is sane.
	 */
	if (SMR_SEQ_CMP(goal, >, clk.s_wr_seq)) {
		/*
		 * Invalid goal: the caller held on it for too long,
		 * and integers wrapped.
		 */
		return true;
	}

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
	 * On LP64 this is guaranteed by the fact that this represents
	 * advancing 2^62 times. At one advance every nanosecond,
	 * it takes more than a century, which makes it possible
	 * to call smr_wait() or smr_poll() with preemption enabled.
	 *
	 * On 32bit systems, this represents 2^30 advances, which
	 * at one advance per nanosecond, would take about 1s.
	 * In order to prevent issues where a scanner would be preempted
	 * while CPUs go crazy advanding and wrapping the interval,
	 * preemption is disabled around manipulating either bounds.
	 * No supported 32bit system has a high core count which
	 * makes this protection sufficient.
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
	rd_seq = __smr_rd_advance(smr, rd_seq);

	if (SMR_SEQ_CMP(goal, <=, rd_seq)) {
		/*
		 * Pairs with smr_leave() and smr_advance()
		 */
		os_atomic_thread_fence(acquire);
		return true;
	}

	return false;
}

static inline bool
__smr_poll(smr_t smr, smr_seq_t goal, bool wait)
{
	smr_clock_t clk;

	/*
	 * Load both the s_rd_seq and s_wr_seq in the right order so that we
	 * can't observe a s_rd_seq older than s_wr_seq.
	 *
	 * the "seq_cst" barriers pair with smr_leave() and __smr_wr_advance*()
	 * This compiles to `ldar` on arm64, and acquire barriers elsewhere.
	 */
	clk.s_rd_seq = os_atomic_load(&smr->smr_clock.s_rd_seq, seq_cst);

	/*
	 * We expect this to be typical: the goal has already been observed.
	 */
	if (__probable(SMR_SEQ_CMP(goal, <=, clk.s_rd_seq))) {
		return true;
	}

	clk.s_wr_seq = os_atomic_load(&smr->smr_clock.s_wr_seq, seq_cst);

	return __smr_scan(smr, goal, clk, wait);
}

smr_seq_t
smr_advance(smr_t smr)
{
	smr_clock_t clk;

	assert(!smr_entered(smr));

#if __LP64__
	/*
	 * On LP64, we assume that there will at least be a successful
	 * __smr_poll call every 2^61 calls to smr_advance() or so,
	 * so we do not need to check if [s_rd_seq, s_wr_seq) is growing
	 * too wide.
	 */
	clk.s_wr_seq = __smr_wr_advance(smr);
#else
	smr_critical_enter();

	clk = __smr_wr_advance_combined(smr);

	/*
	 * The [s_rd_seq, s_rw_seq) interval MUST be smaller
	 * than ULONG_MAX / 2 with a comfortable margin (we pick half that).
	 *
	 * So in case we keep advancing and never poll/wait,
	 * the read sequence is forced to catch up.
	 */
	const smr_delta_t max_delta = ULONG_MAX / 4;

	if (__improbable(SMR_SEQ_DELTA(clk.s_wr_seq, clk.s_rd_seq) >= max_delta)) {
		__smr_scan(smr, clk.s_wr_seq - max_delta / 2, clk, true);
	}

	smr_critical_leave();
#endif /* !__LP64__ */

	return clk.s_wr_seq;
}

bool
smr_poll(smr_t smr, smr_seq_t goal)
{
	bool success;

	smr_critical_enter();
	assert(!smr_entered(smr));
	success = __smr_poll(smr, goal, false);
	smr_critical_leave();
	return success;
}

void
smr_wait(smr_t smr, smr_seq_t goal)
{
	smr_critical_enter();
	assert(!smr_entered(smr));
	(void)__smr_poll(smr, goal, true);
	smr_critical_leave();
}

void
smr_synchronize(smr_t smr)
{
	smr_clock_t clk;

	smr_critical_enter();
	assert(!smr_entered(smr));
	clk = __smr_wr_advance_combined(smr);
	__smr_scan(smr, clk.s_wr_seq, clk, true);
	smr_critical_leave();
}
