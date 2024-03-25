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
#include <kern/machine.h>
#include <kern/mpsc_queue.h>
#include <kern/percpu.h>
#include <kern/sched.h>
#include <kern/smr.h>
#include <kern/smr_hash.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <machine/commpage.h>
#include <os/hash.h>


#pragma mark - SMR domains

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

/*!
 * @struct smr_worker
 *
 * @brief
 * Structure tracking the per-cpu SMR workers state.
 *
 * @discussion
 * This structure is system wide and global and is used to track
 * the various active SMR domains at the granularity of a CPU.
 *
 * Each structure has an associated thread which is responsible
 * for the forward progress the @c smr_call() and @c smr_barrier()
 * interfaces.
 *
 * It also tracks all the active, non stalled, sleepable SMR sections.
 */
struct smr_worker {
	/*
	 * The thread for this worker,
	 * and conveniency pointer to the processor it is bound to.
	 */
	struct thread          *thread;
	struct processor       *processor;

	/*
	 * Thread binding/locking logic:
	 *
	 * If the worker thread is running on its canonical CPU,
	 * then locking to access the various SMR per-cpu data
	 * structures it is draining is just preemption disablement.
	 *
	 * However, if it is currently not bound to its canonical
	 * CPU because the CPU has been offlined or de-recommended,
	 * then a lock which serializes with the CPU going online
	 * again is being used.
	 */
	struct waitq            waitq;
	smr_cpu_reason_t        detach_reason;

#if CONFIG_QUIESCE_COUNTER
	/*
	 * Currently active quiescent generation for this processor,
	 * and the last timestamp when a scan of all cores was performed.
	 */
	smr_seq_t               rd_quiesce_seq;
#endif

	/*
	 * List of all the active sleepable sections that haven't
	 * been stalled.
	 */
	struct smrq_list_head   sect_queue;
	struct thread          *sect_waiter;

	/*
	 * Queue of SMR domains with pending smr_call()
	 * callouts to drain.
	 *
	 * This uses an ageing strategy in order to amortize
	 * SMR clock updates:
	 *
	 * - the "old" queue have domains whose callbacks have
	 *   a committed and aged sequence,
	 * - the "age" queue have domains whose callbacks have
	 *   a commited but fresh sequence and need ageing,
	 * - the "cur" queue have domains whose callbacks have
	 *   a sequence in the future and need for it to be committed.
	 */
	struct smr_pcpu        *whead;
	struct smr_pcpu       **wold_tail;
	struct smr_pcpu       **wage_tail;
	struct smr_pcpu       **wcur_tail;
	uint64_t                drain_ctime;

	/*
	 * Queue of smr_barrier() calls in flight,
	 * that will be picked up by the worker thread
	 * to enqueue as smr_call() entries in their
	 * respective per-CPU data structures.
	 */
	struct mpsc_queue_head  barrier_queue;
} __attribute__((aligned(64)));


typedef struct smr_pcpu {
	/*
	 * CPU private cacheline.
	 *
	 * Nothing else than the CPU this state is made for,
	 * ever writes to this cacheline.
	 *
	 * It holds the epoch activity witness (rd_seq), and
	 * the local smr_call() queue, which is structured this way:
	 *
	 *     head -> n1 -> n2 -> n3 -> n4 -> ... -> ni -> ... -> nN -> NULL
	 *                            ^            ^                  ^
	 *     qold_tail -------------'            |                  |
	 *     qage_tail --------------------------'                  |
	 *     qcur_tail ---------------------------------------------'
	 *
	 * - the "old" queue can be reclaimed once qold_seq is past,
	 *   qold_seq is always a commited sequence.
	 * - the "age" queue can be reclaimed once qage_seq is past,
	 *   qage_seq might not be commited yet.
	 * - the "cur" queue has an approximate size of qcur_size bytes,
	 *   and a length of qcur_cnt callbacks.
	 */

	smr_seq_t               c_rd_seq; /* might have SMR_SEQ_SLEEPABLE set */

	smr_node_t              qhead;

	smr_seq_t               qold_seq;
	smr_node_t             *qold_tail;

	smr_seq_t               qage_seq;
	smr_node_t             *qage_tail;

	uint32_t                qcur_size;
	uint32_t                qcur_cnt;
	smr_node_t             *qcur_tail;

	uint8_t                 __cacheline_sep[0];

	/*
	 * Drain queue.
	 *
	 * This is used to drive smr_call() via the smr worker threads.
	 * If the SMR domain is not using smr_call() or smr_barrier(),
	 * this isn't used.
	 */
	struct smr             *drain_smr;
	struct smr_pcpu        *drain_next;
	uint16_t                __check_cpu;
	uint8_t                 __check_reason;
	uint8_t                 __check_list;

	/*
	 * Stalled queue.
	 *
	 * Stalled sections are enqueued onto this queue by the scheduler
	 * when their thread blocks (see smr_mark_active_trackers_stalled()).
	 *
	 * If the SMR domain is not sleepable, then this isn't used.
	 *
	 * This list is protected by a lock.
	 *
	 * When there are stalled sections, stall_rd_seq contains
	 * the oldest active stalled sequence number.
	 *
	 * When threads want to expedite a stalled section, they set
	 * stall_waiter_goal to the sequence number they are waiting
	 * for and block via turnstile on the oldest stalled section.
	 */
	hw_lck_ticket_t         stall_lock;
	smr_seq_t               stall_rd_seq;
	smr_seq_t               stall_waiter_goal;
	struct smrq_tailq_head  stall_queue;
	struct turnstile       *stall_ts;
} __attribute__((aligned(128))) * smr_pcpu_t;

static_assert(offsetof(struct smr_pcpu, __cacheline_sep) == 64);
static_assert(sizeof(struct smr_pcpu) == 128);

#define CPU_CHECKIN_MIN_INTERVAL_US     5000         /* 5ms */
#define CPU_CHECKIN_MIN_INTERVAL_MAX_US USEC_PER_SEC /* 1s */
static uint64_t cpu_checkin_min_interval;
static uint32_t cpu_checkin_min_interval_us;

/*! the amount of memory pending retiring that causes a foreceful flush */
#if XNU_TARGET_OS_OSX
static TUNABLE(vm_size_t, smr_call_size_cap, "smr_call_size_cap", 256 << 10);
static TUNABLE(vm_size_t, smr_call_cnt_cap, "smr_call_cnt_cap", 128);
#else
static TUNABLE(vm_size_t, smr_call_size_cap, "smr_call_size_cap", 64 << 10);
static TUNABLE(vm_size_t, smr_call_cnt_cap, "smr_call_cnt_cap", 32);
#endif
/* time __smr_wait_for_oncore busy spins before going the expensive route */
static TUNABLE(uint32_t, smr_wait_spin_us, "smr_wait_spin_us", 20);

static LCK_GRP_DECLARE(smr_lock_grp, "smr");
static struct smr_worker PERCPU_DATA(smr_worker);
static struct smrq_tailq_head smr_domains = SMRQ_TAILQ_INITIALIZER(smr_domains);

SMR_DEFINE_FLAGS(smr_system, "system", SMR_NONE);
SMR_DEFINE_FLAGS(smr_system_sleepable, "system (sleepable)", SMR_SLEEPABLE);


#pragma mark SMR domains: init & helpers

#define SMR_PCPU_NOT_QUEUED     ((struct smr_pcpu *)-1)

__attribute__((always_inline, overloadable))
static inline smr_pcpu_t
__smr_pcpu(smr_t smr, int cpu)
{
	return &smr->smr_pcpu[cpu];
}

__attribute__((always_inline, overloadable))
static inline smr_pcpu_t
__smr_pcpu(smr_t smr)
{
	return __smr_pcpu(smr, cpu_number());
}

static inline bool
__smr_pcpu_queued(smr_pcpu_t pcpu)
{
	return pcpu->drain_next != SMR_PCPU_NOT_QUEUED;
}

static inline void
__smr_pcpu_set_not_queued(smr_pcpu_t pcpu)
{
	pcpu->drain_next = SMR_PCPU_NOT_QUEUED;
}

static inline void
__smr_pcpu_associate(smr_t smr, smr_pcpu_t pcpu)
{
	zpercpu_foreach_cpu(cpu) {
		pcpu[cpu].qold_tail = &pcpu[cpu].qhead;
		pcpu[cpu].qage_tail = &pcpu[cpu].qhead;
		pcpu[cpu].qcur_tail = &pcpu[cpu].qhead;

		pcpu[cpu].drain_smr = smr;
		__smr_pcpu_set_not_queued(&pcpu[cpu]);
		hw_lck_ticket_init(&pcpu[cpu].stall_lock, &smr_lock_grp);
		smrq_init(&pcpu[cpu].stall_queue);
	}

	os_atomic_store(&smr->smr_pcpu, pcpu, release);
}

static inline event64_t
__smrw_oncore_event(struct smr_worker *smrw)
{
	return CAST_EVENT64_T(&smrw->sect_queue);
}

static inline event64_t
__smrw_drain_event(struct smr_worker *smrw)
{
	return CAST_EVENT64_T(&smrw->whead);
}

static inline processor_t
__smrw_drain_bind_target(struct smr_worker *smrw)
{
	return smrw->detach_reason ? PROCESSOR_NULL : smrw->processor;
}

static inline void
__smrw_lock(struct smr_worker *smrw)
{
	waitq_lock(&smrw->waitq);
}

static inline void
__smrw_unlock(struct smr_worker *smrw)
{
	waitq_unlock(&smrw->waitq);
}

/*!
 * @function __smrw_wakeup_and_unlock()
 *
 * @brief
 * Wakes up (with binding) the SMR worker.
 *
 * @discussion
 * Wakeup the worker thread and bind it to the proper processor
 * as a side effect.
 *
 * This function must be called with interrupts disabled.
 */
static bool
__smrw_wakeup_and_unlock(struct smr_worker *smrw)
{
	thread_t thread;

	assert(!ml_get_interrupts_enabled());

	thread = waitq_wakeup64_identify_locked(&smrw->waitq,
	    __smrw_drain_event(smrw), THREAD_AWAKENED, WAITQ_UNLOCK);

	if (thread != THREAD_NULL) {
		assert(thread == smrw->thread);

		waitq_resume_and_bind_identified_thread(&smrw->waitq,
		    thread, __smrw_drain_bind_target(smrw),
		    THREAD_AWAKENED, WAITQ_WAKEUP_DEFAULT);
	}

	return thread != THREAD_NULL;
}

static void
__smr_call_drain(smr_node_t head)
{
	smr_node_t node;

	while ((node = head) != NULL) {
		head = node->smrn_next;
		node->smrn_next = NULL;
		node->smrn_cb(node);
	}
}

__startup_func
void
__smr_domain_init(smr_t smr)
{
	smr_pcpu_t pcpu;
	vm_size_t size;

	if (startup_phase < STARTUP_SUB_TUNABLES) {
		smr_seq_t *rd_seqp = &smr->smr_early;

		/*
		 * This is a big cheat, but before the EARLY_BOOT phase,
		 * all smr_* APIs that would access past the rd_seq
		 * will early return.
		 */
		pcpu = __container_of(rd_seqp, struct smr_pcpu, c_rd_seq);
		smr->smr_pcpu = pcpu - cpu_number();
		assert(&__smr_pcpu(smr)->c_rd_seq == &smr->smr_early);
	} else {
		size = zpercpu_count() * sizeof(struct smr_pcpu);
		pcpu = zalloc_permanent(size, ZALIGN(struct smr_pcpu));

		__smr_pcpu_associate(smr, pcpu);
	}
}

smr_t
smr_domain_create(smr_flags_t flags, const char *name)
{
	smr_pcpu_t pcpu;
	smr_t smr;

	smr  = kalloc_type(struct smr, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	pcpu = kalloc_type(struct smr_pcpu, zpercpu_count(),
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	smr->smr_clock.s_rd_seq = SMR_SEQ_INIT;
	smr->smr_clock.s_wr_seq = SMR_SEQ_INIT;
	smr->smr_flags = flags;
	static_assert(sizeof(struct smr) ==
	    offsetof(struct smr, smr_name) + SMR_NAME_MAX);
	strlcpy(smr->smr_name, name, sizeof(smr->smr_name));

	__smr_pcpu_associate(smr, pcpu);

	return smr;
}

void
smr_domain_free(smr_t smr)
{
	smr_barrier(smr);

	zpercpu_foreach_cpu(cpu) {
		smr_pcpu_t pcpu = __smr_pcpu(smr, cpu);

		assert(pcpu->qhead == NULL);
		hw_lck_ticket_destroy(&pcpu->stall_lock, &smr_lock_grp);
	}

	kfree_type(struct smr_pcpu, zpercpu_count(), smr->smr_pcpu);
	kfree_type(struct smr, smr);
}


#pragma mark SMR domains: enter / leave

bool
smr_entered(smr_t smr)
{
	thread_t self = current_thread();
	smr_tracker_t t;

	if (lock_preemption_level_for_thread(self) &&
	    __smr_pcpu(smr)->c_rd_seq != SMR_SEQ_INVALID) {
		return true;
	}

	if (smr->smr_flags & SMR_SLEEPABLE) {
		smrq_serialized_foreach(t, &self->smr_stack, smrt_stack) {
			if (t->smrt_domain == smr) {
				return true;
			}
		}
	}

	return false;
}

__attribute__((always_inline))
bool
smr_entered_cpu_noblock(smr_t smr, int cpu)
{
	assert((smr->smr_flags & SMR_SLEEPABLE) == 0);
	return __smr_pcpu(smr, cpu)->c_rd_seq != SMR_SEQ_INVALID;
}

__attribute__((always_inline))
static smr_seq_t
__smr_enter(smr_t smr, smr_pcpu_t pcpu, smr_seq_t sleepable)
{
	smr_seq_t  s_wr_seq;
	smr_seq_t  old_seq;

	assert(!ml_at_interrupt_context());

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
	old_seq = os_atomic_add_orig(&pcpu->c_rd_seq, s_wr_seq | sleepable, seq_cst);
#else
	old_seq = pcpu->c_rd_seq;
	os_atomic_store(&pcpu->c_rd_seq, s_wr_seq | sleepable, relaxed);
	os_atomic_thread_fence(seq_cst); /* [R1] */
#endif
	assert(old_seq == SMR_SEQ_INVALID);

	return s_wr_seq;
}

__attribute__((always_inline))
static void
__smr_leave(smr_pcpu_t pcpu)
{
	assert(!ml_at_interrupt_context());
	/* [R2] */
	os_atomic_store(&pcpu->c_rd_seq, SMR_SEQ_INVALID, release);
}

__attribute__((always_inline))
void
smr_enter(smr_t smr)
{
	disable_preemption();
	__smr_enter(smr, __smr_pcpu(smr), 0);
}

__attribute__((always_inline))
void
smr_leave(smr_t smr)
{
	__smr_leave(__smr_pcpu(smr));
	enable_preemption();
}

void
smr_enter_sleepable(smr_t smr, smr_tracker_t tracker)
{
	thread_t self = current_thread();
	struct smr_worker *smrw;
	smr_pcpu_t pcpu;

	assert(smr->smr_flags & SMR_SLEEPABLE);

	lock_disable_preemption_for_thread(self);
	lck_rw_lock_count_inc(self, smr);

	pcpu = __smr_pcpu(smr);
	smrw = PERCPU_GET(smr_worker);

	tracker->smrt_domain = smr;
	tracker->smrt_seq    = __smr_enter(smr, pcpu, SMR_SEQ_SLEEPABLE);
	smrq_serialized_insert_head_relaxed(&smrw->sect_queue, &tracker->smrt_link);
	smrq_serialized_insert_head_relaxed(&self->smr_stack, &tracker->smrt_stack);
	tracker->smrt_ctid   = 0;
	tracker->smrt_cpu    = -1;

	lock_enable_preemption();
}

__attribute__((always_inline))
static void
__smr_wake_oncore_sleepers(struct smr_worker *smrw)
{
	/*
	 * prevent reordering of making the list empty and checking for waiters.
	 */
	if (__improbable(os_atomic_load(&smrw->sect_waiter, compiler_acq_rel))) {
		if (smrq_empty(&smrw->sect_queue)) {
			os_atomic_store(&smrw->sect_waiter, NULL, relaxed);
			waitq_wakeup64_all(&smrw->waitq,
			    __smrw_oncore_event(smrw), THREAD_AWAKENED,
			    WAITQ_WAKEUP_DEFAULT);
		}
	}
}

void
smr_ack_ipi(void)
{
	/*
	 * see __smr_wait_for_oncore(): if at the time of the IPI ack
	 * the list is empty and there is still a waiter, wake it up.
	 *
	 * If the queue is not empty, then when smr_leave_sleepable()
	 * runs it can't possibly fail to observe smrw->sect_waiter
	 * being non NULL and will do the wakeup then.
	 */
	__smr_wake_oncore_sleepers(PERCPU_GET(smr_worker));
}

void
smr_mark_active_trackers_stalled(thread_t self)
{
	struct smr_worker *smrw = PERCPU_GET(smr_worker);
	int cpu = cpu_number();
	smr_tracker_t t;

	/* called at splsched */

	smrq_serialized_foreach_safe(t, &smrw->sect_queue, smrt_link) {
		smr_t smr = t->smrt_domain;
		smr_pcpu_t pcpu;

		pcpu = __smr_pcpu(smr, cpu);

		t->smrt_ctid = self->ctid;
		t->smrt_cpu  = cpu;

		hw_lck_ticket_lock_nopreempt(&pcpu->stall_lock, &smr_lock_grp);

		/*
		 * Transfer the section to the stalled queue,
		 * and _then_ leave the regular one.
		 *
		 * A store-release is sufficient to order these stores,
		 * and guarantee that __smr_scan() can't fail to observe
		 * both the @c rd_seq and @c stall_rd_seq during a transfer
		 * of a stalled section that was active when it started.
		 */
		if (smrq_empty(&pcpu->stall_queue)) {
			os_atomic_store(&pcpu->stall_rd_seq, t->smrt_seq, relaxed);
		}
		os_atomic_store(&pcpu->c_rd_seq, SMR_SEQ_INVALID, release);

		smrq_serialized_insert_tail_relaxed(&pcpu->stall_queue, &t->smrt_link);

		hw_lck_ticket_unlock_nopreempt(&pcpu->stall_lock);
	}

	smrq_init(&smrw->sect_queue);

	__smr_wake_oncore_sleepers(smrw);
}


__attribute__((noinline))
static void
__smr_leave_stalled(smr_t smr, smr_tracker_t tracker, thread_t self)
{
	smr_seq_t new_stall_seq = SMR_SEQ_INVALID;
	smr_tracker_t first = NULL;
	smr_pcpu_t pcpu;
	bool progress;

	pcpu = __smr_pcpu(smr, tracker->smrt_cpu);

	hw_lck_ticket_lock_nopreempt(&pcpu->stall_lock, &smr_lock_grp);

	progress = smrq_serialized_first(&pcpu->stall_queue,
	    struct smr_tracker, smrt_link) == tracker;

	smrq_serialized_remove(&self->smr_stack, &tracker->smrt_stack);
	smrq_serialized_remove(&pcpu->stall_queue, &tracker->smrt_link);
	bzero(tracker, sizeof(*tracker));

	if (progress) {
		if (!smrq_empty(&pcpu->stall_queue)) {
			first = smrq_serialized_first(&pcpu->stall_queue,
			    struct smr_tracker, smrt_link);
			new_stall_seq = first->smrt_seq;
			__builtin_assume(new_stall_seq != SMR_SEQ_INVALID);
			assert(SMR_SEQ_CMP(pcpu->stall_rd_seq, <=, new_stall_seq));
		}

		os_atomic_store(&pcpu->stall_rd_seq, new_stall_seq, release);

		progress = pcpu->stall_waiter_goal != SMR_SEQ_INVALID;
	}

	if (progress) {
		struct turnstile *ts;

		ts = turnstile_prepare((uintptr_t)pcpu, &pcpu->stall_ts,
		    TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);

		if (new_stall_seq == SMR_SEQ_INVALID ||
		    SMR_SEQ_CMP(pcpu->stall_waiter_goal, <=, new_stall_seq)) {
			pcpu->stall_waiter_goal = SMR_SEQ_INVALID;
			waitq_wakeup64_all(&ts->ts_waitq, CAST_EVENT64_T(pcpu),
			    THREAD_AWAKENED, WAITQ_UPDATE_INHERITOR);
		} else {
			turnstile_update_inheritor(ts, ctid_get_thread(first->smrt_ctid),
			    TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD);
		}

		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);

		turnstile_complete((uintptr_t)pcpu, &pcpu->stall_ts,
		    NULL, TURNSTILE_KERNEL_MUTEX);
	}

	/* reenables preemption disabled in smr_leave_sleepable() */
	hw_lck_ticket_unlock(&pcpu->stall_lock);

	turnstile_cleanup();
}

void
smr_leave_sleepable(smr_t smr, smr_tracker_t tracker)
{
	struct smr_worker *smrw;
	thread_t self = current_thread();

	assert(tracker->smrt_seq != SMR_SEQ_INVALID);
	assert(smr->smr_flags & SMR_SLEEPABLE);

	lock_disable_preemption_for_thread(self);

	lck_rw_lock_count_dec(self, smr);

	if (__improbable(tracker->smrt_cpu != -1)) {
		return __smr_leave_stalled(smr, tracker, self);
	}

	__smr_leave(__smr_pcpu(smr));

	smrw = PERCPU_GET(smr_worker);
	smrq_serialized_remove(&self->smr_stack, &tracker->smrt_stack);
	smrq_serialized_remove(&smrw->sect_queue, &tracker->smrt_link);
	bzero(tracker, sizeof(*tracker));

	__smr_wake_oncore_sleepers(PERCPU_GET(smr_worker));

	lock_enable_preemption();
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
static smr_seq_t
__smr_wait_for_stalled(smr_pcpu_t pcpu, smr_seq_t goal)
{
	struct turnstile *ts;
	thread_t inheritor;
	wait_result_t wr;
	smr_seq_t stall_rd_seq;

	hw_lck_ticket_lock(&pcpu->stall_lock, &smr_lock_grp);

	stall_rd_seq = pcpu->stall_rd_seq;
	if (stall_rd_seq == SMR_SEQ_INVALID ||
	    SMR_SEQ_CMP(goal, <=, stall_rd_seq)) {
		hw_lck_ticket_unlock(&pcpu->stall_lock);
		return stall_rd_seq;
	}

	if (pcpu->stall_waiter_goal == SMR_SEQ_INVALID ||
	    SMR_SEQ_CMP(goal, <, pcpu->stall_waiter_goal)) {
		pcpu->stall_waiter_goal = goal;
	}

	inheritor = ctid_get_thread(smrq_serialized_first(&pcpu->stall_queue,
	    struct smr_tracker, smrt_link)->smrt_ctid);

	ts = turnstile_prepare((uintptr_t)pcpu, &pcpu->stall_ts,
	    TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);

	turnstile_update_inheritor(ts, inheritor,
	    TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD);
	wr = waitq_assert_wait64(&ts->ts_waitq, CAST_EVENT64_T(pcpu),
	    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);

	if (wr == THREAD_WAITING) {
		hw_lck_ticket_unlock(&pcpu->stall_lock);
		thread_block(THREAD_CONTINUE_NULL);
		hw_lck_ticket_lock(&pcpu->stall_lock, &smr_lock_grp);
	}

	turnstile_complete((uintptr_t)pcpu, &pcpu->stall_ts,
	    NULL, TURNSTILE_KERNEL_MUTEX);

	stall_rd_seq = pcpu->stall_rd_seq;
	hw_lck_ticket_unlock(&pcpu->stall_lock);

	turnstile_cleanup();

	return stall_rd_seq;
}

__attribute__((noinline))
static smr_seq_t
__smr_wait_for_oncore(smr_pcpu_t pcpu, smr_seq_t goal, uint32_t cpu)
{
	thread_t self = current_thread();
	struct smr_worker *smrw;
	uint64_t deadline = 0;
	vm_offset_t base;
	smr_seq_t rd_seq;

	/*
	 * We are waiting for a currently active SMR section.
	 * Start spin-waiting for it for a bit.
	 */
	for (;;) {
		if (hw_spin_wait_until(&pcpu->c_rd_seq, rd_seq,
		    rd_seq == SMR_SEQ_INVALID || SMR_SEQ_CMP(goal, <=, rd_seq))) {
			return rd_seq;
		}

		if (deadline == 0) {
			clock_interval_to_deadline(smr_wait_spin_us,
			    NSEC_PER_USEC, &deadline);
		} else if (mach_absolute_time() > deadline) {
			break;
		}
	}

	/*
	 * This section is being active for a while,
	 * we need to move to a more passive way of waiting.
	 *
	 * We post ourselves on the remote processor tracking head,
	 * to denote we need a thread_wakeup() when the tracker head clears,
	 * then send an IPI which will have 2 possible outcomes:
	 *
	 * 1. when smr_ack_ipi() runs, the queue is already cleared,
	 *    and we will be woken up immediately.
	 *
	 * 2. when smr_ack_ipi() runs, the queue isn't cleared,
	 *    then it does nothing, but there is a guarantee that
	 *    when the queue clears, the remote core will observe
	 *    that there is a waiter, and thread_wakeup() will be
	 *    called then.
	 *
	 * In order to avoid to actually wait, we do spin some more,
	 * hoping for the remote sequence to change.
	 */
	base = other_percpu_base(cpu);
	smrw = PERCPU_GET_WITH_BASE(base, smr_worker);

	waitq_assert_wait64(&smrw->waitq, __smrw_oncore_event(smrw),
	    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);

	if (lock_cmpxchg(&smrw->sect_waiter, NULL, self, relaxed)) {
		/*
		 * only really send the IPI if we're first,
		 * to avoid IPI storms in case of a pile-up
		 * of smr_synchronize() calls stalled on the same guy.
		 */
		cause_ast_check(PERCPU_GET_WITH_BASE(base, processor));
	}

	if (hw_spin_wait_until(&pcpu->c_rd_seq, rd_seq,
	    rd_seq == SMR_SEQ_INVALID || SMR_SEQ_CMP(goal, <=, rd_seq))) {
		clear_wait(self, THREAD_AWAKENED);
		return rd_seq;
	}

	thread_block(THREAD_CONTINUE_NULL);

	return os_atomic_load(&pcpu->c_rd_seq, relaxed);
}

__attribute__((noinline))
static bool
__smr_scan(smr_t smr, smr_seq_t goal, smr_clock_t clk, bool wait)
{
	smr_delta_t delta;
	smr_seq_t rd_seq;

	if (__improbable(startup_phase < STARTUP_SUB_EARLY_BOOT)) {
		return true;
	}

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

	zpercpu_foreach_cpu(cpu) {
		smr_pcpu_t pcpu = __smr_pcpu(smr, cpu);
		smr_seq_t seq   = os_atomic_load(&pcpu->c_rd_seq, relaxed);

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
				seq &= ~SMR_SEQ_SLEEPABLE;
				break;
			}

			if (seq & SMR_SEQ_SLEEPABLE) {
				seq = __smr_wait_for_oncore(pcpu, goal, cpu);
			} else {
				disable_preemption();
				seq = hw_wait_while_equals_long(&pcpu->c_rd_seq, seq);
				enable_preemption();
			}
		}

		if (seq != SMR_SEQ_INVALID && SMR_SEQ_CMP(seq, <, rd_seq)) {
			rd_seq = seq;
		}
	}

	if (smr->smr_flags & SMR_SLEEPABLE) {
		/*
		 * Order observation of stalled sections,
		 * see smr_mark_active_trackers_stalled().
		 */
		os_atomic_thread_fence(seq_cst);

		zpercpu_foreach_cpu(cpu) {
			smr_pcpu_t pcpu = __smr_pcpu(smr, cpu);
			smr_seq_t  seq  = os_atomic_load(&pcpu->stall_rd_seq, relaxed);

			while (seq != SMR_SEQ_INVALID) {
				if (SMR_SEQ_CMP(seq, <, clk.s_rd_seq)) {
					seq = clk.s_rd_seq;
				}

				if (!wait || SMR_SEQ_CMP(goal, <=, seq)) {
					seq &= ~SMR_SEQ_SLEEPABLE;
					break;
				}

				seq = __smr_wait_for_stalled(pcpu, goal);
			}

			if (seq != SMR_SEQ_INVALID && SMR_SEQ_CMP(seq, <, rd_seq)) {
				rd_seq = seq;
			}
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
	 * call every 2^60 calls to smr_advance() or so, so we do not need
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
	if (smr->smr_flags & SMR_SLEEPABLE) {
		assert(get_preemption_level() == 0);
	}
	(void)__smr_poll(smr, goal, true);
}

void
smr_synchronize(smr_t smr)
{
	smr_clock_t clk;

	assert(!smr_entered(smr));
	assert(!ml_at_interrupt_context());
	if (smr->smr_flags & SMR_SLEEPABLE) {
		assert(get_preemption_level() == 0);
	}

	/*
	 * Similar to __smr_poll() but also does a deferred advance which
	 * __smr_scan will commit.
	 */

	clk.s_rd_seq = os_atomic_load(&smr->smr_clock.s_rd_seq, relaxed);
	os_atomic_thread_fence(seq_cst);
	clk.s_wr_seq = os_atomic_load(&smr->smr_clock.s_wr_seq, relaxed);

	(void)__smr_scan(smr, clk.s_wr_seq + SMR_SEQ_INC, clk, true);
}


#pragma mark SMR domains: smr_call & smr_barrier

/*!
 * @struct smr_barrier_ctx
 *
 * @brief
 * Data structure to track the completion of an smr_barrier() call.
 */
struct smr_barrier_ctx {
	struct smr             *smrb_domain;
	struct thread          *smrb_waiter;
	uint32_t                smrb_pending;
	uint32_t                smrb_count;
};

/*!
 * @struct smr_barrier_job
 *
 * @brief
 * Data structure used to track completion of smr_barrier() calls.
 */
struct smr_barrier_job {
	struct smr_barrier_ctx *smrj_context;
	union {
		struct smr_node smrj_node;
		struct mpsc_queue_chain smrj_link;
	};
};

#define SMR_BARRIER_SIZE        24
static_assert(sizeof(struct smr_barrier_job) == SMR_BARRIER_SIZE);
#define SMR_BARRIER_USE_STACK   (SMR_BARRIER_SIZE * MAX_CPUS <= 512)

static void
__smr_worker_check_invariants(struct smr_worker *smrw)
{
#if MACH_ASSERT
	smr_pcpu_t pcpu = smrw->whead;
	uint16_t num = (uint16_t)cpu_number();

	assert(!ml_get_interrupts_enabled() || get_preemption_level());

	for (; pcpu != *smrw->wold_tail; pcpu = pcpu->drain_next) {
		assertf(pcpu->qold_seq != SMR_SEQ_INVALID &&
		    __smr_pcpu_queued(pcpu),
		    "pcpu %p doesn't belong on %p old queue", pcpu, smrw);
		pcpu->__check_cpu = num;
		pcpu->__check_reason = (uint8_t)smrw->detach_reason;
		pcpu->__check_list = 1;
	}

	for (; pcpu != *smrw->wage_tail; pcpu = pcpu->drain_next) {
		__assert_only smr_t smr = pcpu->drain_smr;

		assertf(pcpu->qold_seq == SMR_SEQ_INVALID &&
		    pcpu->qage_seq != SMR_SEQ_INVALID &&
		    SMR_SEQ_CMP(pcpu->qage_seq, <=, smr->smr_clock.s_wr_seq) &&
		    __smr_pcpu_queued(pcpu),
		    "pcpu %p doesn't belong on %p aging queue", pcpu, smrw);
		pcpu->__check_cpu = num;
		pcpu->__check_reason = (uint8_t)smrw->detach_reason;
		pcpu->__check_list = 2;
	}

	for (; pcpu != *smrw->wcur_tail; pcpu = pcpu->drain_next) {
		assertf(pcpu->qold_seq == SMR_SEQ_INVALID &&
		    pcpu->qage_seq != SMR_SEQ_INVALID &&
		    __smr_pcpu_queued(pcpu),
		    "pcpu %p doesn't belong on %p current queue", pcpu, smrw);
		pcpu->__check_cpu = num;
		pcpu->__check_reason = (uint8_t)smrw->detach_reason;
		pcpu->__check_list = 3;
	}

	assert(pcpu == NULL);
#else
	(void)smrw;
#endif
}

__attribute__((noinline))
static void
__smr_cpu_lazy_up(struct smr_worker *smrw)
{
	spl_t spl;

	/*
	 * calling smr_call/smr_barrier() from the context of a CPU
	 * with a detached worker is illegal.
	 *
	 * However, bound threads might run on a derecommended (IGNORED)
	 * cpu which we correct for here (and the CPU will go back to IGNORED
	 * in smr_cpu_leave()).
	 */
	assert(smrw->detach_reason == SMR_CPU_REASON_IGNORED);

	spl = splsched();
	__smrw_lock(smrw);
	smrw->detach_reason &= ~SMR_CPU_REASON_IGNORED;
	__smrw_unlock(smrw);
	splx(spl);
}

static void
__smr_cpu_lazy_up_if_needed(struct smr_worker *smrw)
{
	if (__improbable(smrw->detach_reason != SMR_CPU_REASON_NONE)) {
		__smr_cpu_lazy_up(smrw);
	}
}

static bool
__smr_call_should_advance(smr_pcpu_t pcpu)
{
	if (pcpu->qcur_cnt > smr_call_cnt_cap) {
		return true;
	}
	if (pcpu->qcur_size > smr_call_size_cap) {
		return true;
	}
	return false;
}

static void
__smr_call_advance_qcur(smr_t smr, smr_pcpu_t pcpu, bool needs_commit)
{
	smr_seq_t new_seq;

	if (needs_commit || pcpu->qage_seq) {
		new_seq = smr_advance(smr);
	} else {
		new_seq = smr_deferred_advance(smr);
	}
	__builtin_assume(new_seq != SMR_SEQ_INVALID);

	pcpu->qage_seq  = new_seq;
	pcpu->qage_tail = pcpu->qcur_tail;

	pcpu->qcur_size = 0;
	pcpu->qcur_cnt  = 0;
}

static void
__smr_call_push(smr_pcpu_t pcpu, smr_node_t node, smr_cb_t cb)
{
	assert(pcpu->c_rd_seq == SMR_SEQ_INVALID);

	node->smrn_next  = NULL;
	node->smrn_cb    = cb;

	*pcpu->qcur_tail = node;
	pcpu->qcur_tail  = &node->smrn_next;
	pcpu->qcur_cnt  += 1;
}

static void
__smr_call_dispatch(struct smr_worker *smrw, smr_pcpu_t pcpu)
{
	__smr_worker_check_invariants(smrw);

	if (!__smr_pcpu_queued(pcpu)) {
		assert(pcpu->qold_seq == SMR_SEQ_INVALID);
		assert(pcpu->qage_seq != SMR_SEQ_INVALID);

		pcpu->drain_next   = NULL;
		*smrw->wcur_tail   = pcpu;
		smrw->wcur_tail    = &pcpu->drain_next;
	}
}

void
smr_call(smr_t smr, smr_node_t node, vm_size_t size, smr_cb_t cb)
{
	struct smr_worker *smrw;
	smr_pcpu_t pcpu;

	if (__improbable(startup_phase < STARTUP_SUB_EARLY_BOOT)) {
		return cb(node);
	}

	lock_disable_preemption_for_thread(current_thread());
	assert(!ml_at_interrupt_context());

	smrw = PERCPU_GET(smr_worker);
	__smr_cpu_lazy_up_if_needed(smrw);

	pcpu = __smr_pcpu(smr);
	assert(pcpu->c_rd_seq == SMR_SEQ_INVALID);

	if (os_add_overflow(pcpu->qcur_size, size, &pcpu->qcur_size)) {
		pcpu->qcur_size = UINT32_MAX;
	}

	__smr_call_push(pcpu, node, cb);
	if (__smr_call_should_advance(pcpu)) {
		if (pcpu->qage_seq == SMR_SEQ_INVALID) {
			__smr_call_advance_qcur(smr, pcpu, false);
		}
		__smr_call_dispatch(smrw, pcpu);
	}

	return lock_enable_preemption();
}

static inline event_t
__smrb_event(struct smr_barrier_ctx *ctx)
{
	return ctx;
}

static void
__smr_barrier_cb(struct smr_node *node)
{
	struct smr_barrier_job *job;
	struct smr_barrier_ctx *ctx;

	job = __container_of(node, struct smr_barrier_job, smrj_node);
	ctx = job->smrj_context;

	if (os_atomic_dec(&ctx->smrb_pending, relaxed) == 0) {
		/*
		 * It is permitted to still reach into the context
		 * because smr_barrier() always blocks, which means
		 * that the context will be valid until this wakeup
		 * happens.
		 */
		thread_wakeup_thread(__smrb_event(ctx), ctx->smrb_waiter);
	}
}

static bool
__smr_barrier_drain(struct smr_worker *smrw, bool needs_commit)
{
	mpsc_queue_chain_t head, tail, it;

	head = mpsc_queue_dequeue_batch(&smrw->barrier_queue, &tail,
	    OS_ATOMIC_DEPENDENCY_NONE);

	mpsc_queue_batch_foreach_safe(it, head, tail) {
		struct smr_barrier_job *job;
		struct smr_barrier_ctx *ctx;
		smr_pcpu_t pcpu;
		smr_t smr;

		job  = __container_of(it, struct smr_barrier_job, smrj_link);
		ctx  = job->smrj_context;
		smr  = ctx->smrb_domain;
		pcpu = __smr_pcpu(smr, smrw->processor->cpu_id);

		pcpu->qcur_size = UINT32_MAX;
		__smr_call_push(pcpu, &job->smrj_node, __smr_barrier_cb);
		__smr_call_advance_qcur(smr, pcpu, needs_commit);
		__smr_call_dispatch(smrw, pcpu);
	}

	return head != NULL;
}


void
smr_barrier(smr_t smr)
{
#if SMR_BARRIER_USE_STACK
	struct smr_barrier_job jobs[MAX_CPUS];
#else
	struct smr_barrier_job *jobs;
#endif
	struct smr_barrier_job *job;
	struct smr_barrier_ctx  ctx = {
		.smrb_domain  = smr,
		.smrb_waiter  = current_thread(),
		.smrb_pending = zpercpu_count(),
		.smrb_count   = zpercpu_count(),
	};
	spl_t spl;

	/*
	 * First wait for all readers to observe whatever it is
	 * that changed prior to this call.
	 *
	 * _then_ enqueue callbacks that push out anything ahead.
	 */
	smr_synchronize(smr);

#if !SMR_BARRIER_USE_STACK
	jobs = kalloc_type(struct smr_barrier_job, ctx.smrb_count,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);
#endif
	job  = jobs;
	spl  = splsched();

	__smr_cpu_lazy_up_if_needed(PERCPU_GET(smr_worker));

	percpu_foreach(smrw, smr_worker) {
		job->smrj_context = &ctx;
		if (mpsc_queue_append(&smrw->barrier_queue, &job->smrj_link)) {
			__smrw_lock(smrw);
			__smrw_wakeup_and_unlock(smrw);
		}
		job++;
	}

	/*
	 * Because we disabled interrupts, our own CPU's callback
	 * can't possibly have run, so just block.
	 *
	 * We must block in order to guarantee the lifetime of "ctx".
	 * (See comment in __smr_barrier_cb).
	 */
	assert_wait(__smrb_event(&ctx), THREAD_UNINT);
	assert(ctx.smrb_pending > 0);
	splx(spl);
	thread_block(THREAD_CONTINUE_NULL);

#if !SMR_BARRIER_USE_STACK
	kfree_type(struct smr_barrier_job, ctx.smrb_count, jobs);
#endif
}


#pragma mark SMR domains: smr_worker

static void
__smr_worker_drain_lock(struct smr_worker *smrw)
{
	for (;;) {
		ml_set_interrupts_enabled(false);
		__smrw_lock(smrw);

		/*
		 * Check we are on an appropriate processor
		 *
		 * Note that we might be running on the canonical
		 * processor incorrectly: if the processor has been
		 * de-recommended but isn't offline.
		 */
		if (__probable(current_processor() == smrw->processor)) {
			if (__probable(!smrw->detach_reason)) {
				break;
			}
		} else {
			if (__probable(smrw->detach_reason)) {
				break;
			}
		}

		/* go bind in the right place and retry */
		thread_bind(__smrw_drain_bind_target(smrw));
		__smrw_unlock(smrw);
		ml_set_interrupts_enabled(true);
		thread_block(THREAD_CONTINUE_NULL);
	}
}

static void
__smr_worker_drain_unlock(struct smr_worker *smrw)
{
	__smrw_unlock(smrw);
	ml_set_interrupts_enabled(true);
}

/*!
 * @function __smr_worker_tick
 *
 * @brief
 * Make the SMR worker queues make gentle progress
 *
 * @discussion
 * One round of progress will:
 * - move entries that have aged as being old,
 * - commit entries that have a deferred sequence and let them age.
 *
 * If this results into any callbacks to become "old",
 * then the worker is being woken up to start running callbacks.
 *
 * This function must run either on the processfor for this worker,
 * or under the worker drain lock being held.
 */
static void
__smr_worker_tick(struct smr_worker *smrw, uint64_t ctime, bool wakeup)
{
	smr_pcpu_t pcpu = *smrw->wold_tail;

	__smr_worker_check_invariants(smrw);

	for (; pcpu != *smrw->wage_tail; pcpu = pcpu->drain_next) {
		assert(pcpu->qold_seq == SMR_SEQ_INVALID);
		assert(pcpu->qage_seq != SMR_SEQ_INVALID);

		pcpu->qold_seq  = pcpu->qage_seq;
		pcpu->qold_tail = pcpu->qage_tail;

		pcpu->qage_seq  = SMR_SEQ_INVALID;
	}

	for (; pcpu; pcpu = pcpu->drain_next) {
		assert(pcpu->qold_seq == SMR_SEQ_INVALID);
		assert(pcpu->qage_seq != SMR_SEQ_INVALID);

		smr_deferred_advance_commit(pcpu->drain_smr, pcpu->qage_seq);
	}

	smrw->wold_tail = smrw->wage_tail;
	smrw->wage_tail = smrw->wcur_tail;
	smrw->drain_ctime = ctime;

	__smr_worker_check_invariants(smrw);

	if (wakeup && smrw->wold_tail != &smrw->whead) {
		__smrw_lock(smrw);
		__smrw_wakeup_and_unlock(smrw);
	}
}

static void
__smr_worker_update_wold_tail(struct smr_worker *smrw, smr_pcpu_t *new_tail)
{
	smr_pcpu_t *old_tail = smrw->wold_tail;

	if (smrw->wcur_tail == old_tail) {
		smrw->wage_tail = new_tail;
		smrw->wcur_tail = new_tail;
	} else if (smrw->wage_tail == old_tail) {
		smrw->wage_tail = new_tail;
	}

	smrw->wold_tail = new_tail;
}

static void
__smr_worker_drain_one(struct smr_worker *smrw, smr_pcpu_t pcpu)
{
	smr_t       smr  = pcpu->drain_smr;
	smr_seq_t   seq  = pcpu->qold_seq;
	smr_node_t  head;

	/*
	 * Step 1: pop the "old" items,
	 *         (qold_tail/qold_seq left dangling)
	 */

	assert(seq != SMR_SEQ_INVALID);
	head = pcpu->qhead;
	pcpu->qhead = *pcpu->qold_tail;
	*pcpu->qold_tail = NULL;

	/*
	 * Step 2: Reconstruct the queue
	 *         based on the sequence numbers and count fields.
	 *
	 *         Do what __smr_worker_tick() would do on this queue:
	 *         - commit the aging queue
	 *         - advance the current queue if needed
	 */

	if (pcpu->qage_seq != SMR_SEQ_INVALID) {
		assert(pcpu->qage_tail != pcpu->qold_tail);

		smr_deferred_advance_commit(smr, pcpu->qage_seq);
		pcpu->qold_seq  = pcpu->qage_seq;
		pcpu->qold_tail = pcpu->qage_tail;
	} else {
		assert(pcpu->qage_tail == pcpu->qold_tail);

		pcpu->qold_seq  = SMR_SEQ_INVALID;
		pcpu->qold_tail = &pcpu->qhead;
	}

	if (__smr_call_should_advance(pcpu)) {
		__smr_call_advance_qcur(smr, pcpu, false);
	} else {
		pcpu->qage_seq  = SMR_SEQ_INVALID;
		pcpu->qage_tail = pcpu->qold_tail;
		if (pcpu->qcur_cnt == 0) {
			pcpu->qcur_tail = pcpu->qage_tail;
		}
	}

	if (pcpu->qold_seq != SMR_SEQ_INVALID) {
		/*
		 * The node has gained an "old seq" back,
		 * it goes to the ready queue.
		 */
		pcpu->drain_next = *smrw->wold_tail;
		*smrw->wold_tail = pcpu;
		__smr_worker_update_wold_tail(smrw,
		    &pcpu->drain_next);
	} else if (pcpu->qage_seq != SMR_SEQ_INVALID) {
		/*
		 * The node has gained an "age seq" back,
		 * it needs to age and wait for a tick
		 * for its sequence number to be commited.
		 */
		pcpu->drain_next = NULL;
		*smrw->wcur_tail = pcpu;
		smrw->wcur_tail  = &pcpu->drain_next;
	} else {
		/*
		 * The node is empty or with "current"
		 * callbacks only, it can be dequeued.
		 */
		assert(!__smr_call_should_advance(pcpu));
		pcpu->__check_cpu = (uint16_t)cpu_number();
		pcpu->__check_reason = (uint8_t)smrw->detach_reason;
		pcpu->__check_list = 0;
		__smr_pcpu_set_not_queued(pcpu);
	}

	/*
	 * Step 3: drain callbacks.
	 */
	__smr_worker_check_invariants(smrw);
	__smr_worker_drain_unlock(smrw);

	__smr_poll(smr, seq, true);
	__smr_call_drain(head);

	__smr_worker_drain_lock(smrw);
}

static void
__smr_worker_continue(void *arg, wait_result_t wr __unused)
{
	smr_pcpu_t pcpu = NULL, next = NULL;
	struct smr_worker *const smrw = arg;
	uint64_t deadline;

	__smr_worker_drain_lock(smrw);
	__smr_worker_check_invariants(smrw);

	if (smrw->wold_tail != &smrw->whead) {
		next = smrw->whead;
		smrw->whead = *smrw->wold_tail;
		*smrw->wold_tail = NULL;
		__smr_worker_update_wold_tail(smrw, &smrw->whead);
	}

	/*
	 * The pipeline of per-cpu SMR data structures with pending
	 * smr_call() callbacks has three stages: wcur -> wage -> wold.
	 *
	 * In order to guarantee forward progress, a tick happens
	 * for each of them, either via __smr_worker_tick(),
	 * or via __smr_worker_drain_one().
	 *
	 * The second tick will happen either because to core stayed
	 * busy enough that a subsequent smr_cpu_tick() decided to
	 * perform it, or because the CPU idled, and smr_cpu_leave()
	 * will perform an unconditional __smr_worker_tick().
	 */
	__smr_barrier_drain(smrw, false);
	__smr_worker_tick(smrw, mach_absolute_time(), false);

	while ((pcpu = next)) {
		next = next->drain_next;
		__smr_worker_drain_one(smrw, pcpu);
	}

	if (__improbable(smrw->whead && smrw->detach_reason)) {
		/*
		 * If the thread isn't bound, we want to flush anything
		 * that is pending without causing too much contention.
		 *
		 * Sleep for a bit in order to give the system time
		 * to observe any advance commits we did.
		 */
		deadline = mach_absolute_time() + cpu_checkin_min_interval;
	} else {
		deadline = TIMEOUT_WAIT_FOREVER;
	}
	waitq_assert_wait64_locked(&smrw->waitq, __smrw_drain_event(smrw),
	    THREAD_UNINT, TIMEOUT_URGENCY_SYS_NORMAL, deadline,
	    TIMEOUT_NO_LEEWAY, smrw->thread);

	/*
	 * Make sure there's no barrier left, after we called assert_wait()
	 * in order to pair with __smr_barrier_cb(). If we do find some,
	 * we must be careful about invariants and forward progress.
	 *
	 * For affected domains, the dequeued barriers have been added
	 * to their "qage" queue. If their "qage" queue was non empty,
	 * then its "qage_seq" was already commited, and we must preserve
	 * this invariant.
	 *
	 * Affected domains that were idle before will get enqueued on this
	 * worker's "wcur" queue. In order to guarantee forward progress,
	 * we must force a tick if both the "wage" and "wold" queues
	 * of the worker are empty.
	 */
	if (__improbable(__smr_barrier_drain(smrw, true))) {
		if (smrw->wage_tail == &smrw->whead) {
			__smr_worker_tick(smrw, mach_absolute_time(), false);
		}
	}

	__smr_worker_check_invariants(smrw);
	__smr_worker_drain_unlock(smrw);

	thread_block_parameter(__smr_worker_continue, smrw);
}


#pragma mark SMR domains: scheduler integration

#if CONFIG_QUIESCE_COUNTER
__startup_data
static uint64_t _Atomic quiesce_gen_startup;
static uint64_t _Atomic *quiesce_genp = &quiesce_gen_startup;
static uint64_t _Atomic quiesce_ctime;

void
cpu_quiescent_set_storage(uint64_t _Atomic *ptr)
{
	/*
	 * Transfer to the real location for the commpage.
	 *
	 * this is ok to do like this because the system
	 * is still single threaded.
	 */
	uint64_t gen = os_atomic_load(&quiesce_gen_startup, relaxed);

	os_atomic_store(ptr, gen, relaxed);
	quiesce_genp = ptr;
}

static smr_seq_t
cpu_quiescent_gen_to_seq(uint64_t gen)
{
	return gen * SMR_SEQ_INC + SMR_SEQ_INIT;
}

static void
cpu_quiescent_advance(uint64_t gen, uint64_t ctime __kdebug_only)
{
	smr_seq_t seq = cpu_quiescent_gen_to_seq(gen);

	os_atomic_thread_fence(seq_cst);

	percpu_foreach(it, smr_worker) {
		smr_seq_t rd_seq = os_atomic_load(&it->rd_quiesce_seq, relaxed);

		if (rd_seq != SMR_SEQ_INVALID && SMR_SEQ_CMP(rd_seq, <, seq)) {
			return;
		}
	}

	os_atomic_thread_fence(seq_cst);

	if (lock_cmpxchg(quiesce_genp, gen, gen + 1, relaxed)) {
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_QUIESCENT_COUNTER),
		    gen, 0, ctime, 0);
	}
}

static void
cpu_quiescent_join(struct smr_worker *smrw)
{
	uint64_t gen = os_atomic_load(quiesce_genp, relaxed);

	assert(smrw->rd_quiesce_seq == SMR_SEQ_INVALID);
	os_atomic_store(&smrw->rd_quiesce_seq,
	    cpu_quiescent_gen_to_seq(gen), relaxed);
	os_atomic_thread_fence(seq_cst);
}

static void
cpu_quiescent_tick(struct smr_worker *smrw, uint64_t ctime, uint64_t interval)
{
	uint64_t  gen  = os_atomic_load(quiesce_genp, relaxed);
	smr_seq_t seq  = cpu_quiescent_gen_to_seq(gen);

	if (smrw->rd_quiesce_seq == SMR_SEQ_INVALID) {
		/*
		 * Likely called because of the scheduler tick,
		 * smr_maintenance() will do the right thing.
		 */
		assert(current_processor()->state != PROCESSOR_RUNNING);
	} else if (seq != smrw->rd_quiesce_seq) {
		/*
		 * Someone managed to update the sequence already,
		 * learn it, update our ctime.
		 */
		os_atomic_store(&smrw->rd_quiesce_seq, seq, release);
		os_atomic_store(&quiesce_ctime, ctime, relaxed);
		os_atomic_thread_fence(seq_cst);
	} else if ((ctime - os_atomic_load(&quiesce_ctime, relaxed)) > interval) {
		/*
		 * The system looks busy enough we want to update
		 * the counter faster than every scheduler tick.
		 */
		os_atomic_store(&quiesce_ctime, ctime, relaxed);
		cpu_quiescent_advance(gen, ctime);
	}
}

static void
cpu_quiescent_leave(struct smr_worker *smrw)
{
	assert(smrw->rd_quiesce_seq != SMR_SEQ_INVALID);
	os_atomic_store(&smrw->rd_quiesce_seq, SMR_SEQ_INVALID, release);
}
#endif /* CONFIG_QUIESCE_COUNTER */

uint32_t
smr_cpu_checkin_get_min_interval_us(void)
{
	return cpu_checkin_min_interval_us;
}

void
smr_cpu_checkin_set_min_interval_us(uint32_t new_value_us)
{
	/* clamp to something vaguely sane */
	if (new_value_us > CPU_CHECKIN_MIN_INTERVAL_MAX_US) {
		new_value_us = CPU_CHECKIN_MIN_INTERVAL_MAX_US;
	}

	cpu_checkin_min_interval_us = new_value_us;

	uint64_t abstime = 0;
	clock_interval_to_absolutetime_interval(cpu_checkin_min_interval_us,
	    NSEC_PER_USEC, &abstime);
	cpu_checkin_min_interval = abstime;
}

__startup_func
static void
smr_cpu_checkin_init_min_interval_us(void)
{
	smr_cpu_checkin_set_min_interval_us(CPU_CHECKIN_MIN_INTERVAL_US);
}
STARTUP(TUNABLES, STARTUP_RANK_FIRST, smr_cpu_checkin_init_min_interval_us);

static void
__smr_cpu_init_thread(struct smr_worker *smrw)
{
	char name[MAXTHREADNAMESIZE];
	thread_t th = THREAD_NULL;

	kernel_thread_create(__smr_worker_continue, smrw, MINPRI_KERNEL, &th);
	smrw->thread = th;

	snprintf(name, sizeof(name), "smr.reclaim:%d", smrw->processor->cpu_id);
	thread_set_thread_name(th, name);
	thread_start_in_assert_wait(th,
	    &smrw->waitq, __smrw_drain_event(smrw), THREAD_UNINT);
}

void
smr_cpu_init(struct processor *processor)
{
	struct smr_worker *smrw;

	smrw = PERCPU_GET_RELATIVE(smr_worker, processor, processor);
	smrw->processor = processor;

	waitq_init(&smrw->waitq, WQT_QUEUE, SYNC_POLICY_FIFO);
	smrw->detach_reason = SMR_CPU_REASON_OFFLINE;

	smrq_init(&smrw->sect_queue);
	smrw->wold_tail = &smrw->whead;
	smrw->wage_tail = &smrw->whead;
	smrw->wcur_tail = &smrw->whead;
	mpsc_queue_init(&smrw->barrier_queue);

	if (processor != master_processor) {
		__smr_cpu_init_thread(smrw);
	}
}
STARTUP_ARG(LOCKS, STARTUP_RANK_LAST, smr_cpu_init, master_processor);
STARTUP_ARG(THREAD_CALL, STARTUP_RANK_LAST,
    __smr_cpu_init_thread, PERCPU_GET_MASTER(smr_worker));

/*!
 * @function smr_cpu_up()
 *
 * @brief
 * Scheduler callback to notify this processor is going up.
 *
 * @discussion
 * Called at splsched() under the sched_available_cores_lock.
 */
void
smr_cpu_up(struct processor *processor, smr_cpu_reason_t reason)
{
	struct smr_worker *smrw;

	smrw = PERCPU_GET_RELATIVE(smr_worker, processor, processor);

	__smrw_lock(smrw);
	if (reason != SMR_CPU_REASON_IGNORED) {
		assert((smrw->detach_reason & reason) == reason);
	}
	smrw->detach_reason &= ~reason;
	__smrw_unlock(smrw);
}

static void
__smr_cpu_down_and_unlock(
	struct processor       *processor,
	struct smr_worker      *smrw,
	smr_cpu_reason_t        reason)
{
	bool detach = !smrw->detach_reason;

	/*
	 * When reason is SMR_CPU_REASON_IGNORED,
	 * this is called from smr_cpu_leave() on the way to idle.
	 *
	 * However this isn't sychronized with the recommendation
	 * lock, hence it is possible that the CPU might actually
	 * be recommended again while we're on the way to idle.
	 *
	 * By re-checking processor recommendation under
	 * the __smrw_lock, we serialize with smr_cpu_up().
	 */
	if (reason != SMR_CPU_REASON_IGNORED) {
		assert((smrw->detach_reason & reason) == 0);
	} else if (processor->is_recommended) {
		/*
		 * The race we try to detect happened,
		 * do nothing.
		 */
		reason = SMR_CPU_REASON_NONE;
		detach = false;
	}
	smrw->detach_reason |= reason;
	reason = smrw->detach_reason;

	if (detach && smrw->whead) {
		detach = !__smrw_wakeup_and_unlock(smrw);
	} else {
		__smrw_unlock(smrw);
	}

	if (detach) {
		thread_unbind_after_queue_shutdown(smrw->thread, processor);
	}
}

/*!
 * @function smr_cpu_down()
 *
 * @brief
 * Scheduler callback to notify this processor is going down.
 *
 * @discussion
 * Called at splsched() when the processor run queue is being shut down.
 */
void
smr_cpu_down(struct processor *processor, smr_cpu_reason_t reason)
{
	struct smr_worker *smrw;

	smrw = PERCPU_GET_RELATIVE(smr_worker, processor, processor);

	__smrw_lock(smrw);
	__smr_cpu_down_and_unlock(processor, smrw, reason);
}


/*!
 * @function smr_cpu_join()
 *
 * @brief
 * Scheduler callback to notify this processor is going out of idle.
 *
 * @discussion
 * Called at splsched().
 */
void
smr_cpu_join(struct processor *processor, uint64_t ctime __unused)
{
#if CONFIG_QUIESCE_COUNTER
	struct smr_worker *smrw;

	smrw = PERCPU_GET_RELATIVE(smr_worker, processor, processor);
	cpu_quiescent_join(smrw);
#else
	(void)processor;
#endif /* CONFIG_QUIESCE_COUNTER */
}

/*!
 * @function smr_cpu_tick()
 *
 * @brief
 * Scheduler callback invoked during the scheduler maintenance routine.
 *
 * @discussion
 * Called at splsched().
 */
void
smr_cpu_tick(uint64_t ctime, bool safe_point)
{
	struct smr_worker *smrw = PERCPU_GET(smr_worker);
	uint64_t interval = cpu_checkin_min_interval;

#if CONFIG_QUIESCE_COUNTER
	cpu_quiescent_tick(smrw, ctime, interval);
#endif /* CONFIG_QUIESCE_COUNTER */

	/*
	 * if a bound thread was woken up on a derecommended core,
	 * our detach_reason might be "IGNORED" and we want to leave
	 * it alone in that case
	 */
	if (safe_point && !smrw->detach_reason && smrw->whead &&
	    current_processor()->state == PROCESSOR_RUNNING &&
	    (ctime - smrw->drain_ctime) > interval) {
		__smr_worker_tick(smrw, ctime, true);
	}
}

/*!
 * @function smr_cpu_leave()
 *
 * @brief
 * Scheduler callback to notify this processor is going idle.
 *
 * @discussion
 * Called at splsched().
 */
void
smr_cpu_leave(struct processor *processor, uint64_t ctime)
{
	struct smr_worker *smrw;

	smrw = PERCPU_GET_RELATIVE(smr_worker, processor, processor);

	/*
	 * if a bound thread was woken up on a derecommended core,
	 * our detach_reason might be "IGNORED" and we want to leave
	 * it alone in that case
	 *
	 * See comment in __smr_worker_continue for why this must be
	 * done unconditionally otherwise.
	 */
	if (!smrw->detach_reason && smrw->whead) {
		__smr_worker_tick(smrw, ctime, true);
	}

	if (__improbable(!processor->is_recommended)) {
		__smrw_lock(smrw);
		__smr_cpu_down_and_unlock(processor, smrw, SMR_CPU_REASON_IGNORED);
	}

#if CONFIG_QUIESCE_COUNTER
	cpu_quiescent_leave(smrw);
#endif /* CONFIG_QUIESCE_COUNTER */
}

/*!
 * @function smr_maintenance()
 *
 * @brief
 * Scheduler callback called at the scheduler tick.
 *
 * @discussion
 * Called at splsched().
 */
void
smr_maintenance(uint64_t ctime)
{
#if CONFIG_QUIESCE_COUNTER
	cpu_quiescent_advance(os_atomic_load(quiesce_genp, relaxed), ctime);
#else
	(void)ctime;
#endif /* CONFIG_QUIESCE_COUNTER */
}


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
	first = hw_lck_ptr_lock(head, &smr_shash_grp);

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
				hw_lck_ptr_unlock(head, first,
				    &smr_shash_grp);
				return obj;
			}
			break;
		}
		other = smr_serialized_load(&other->next);
	}

	counter_inc_preemption_disabled(&smrh->smrsh_count);
	smr_serialized_store_relaxed(&link->next, first);
	hw_lck_ptr_unlock(head, link, &smr_shash_grp);

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
	first = hw_lck_ptr_lock(head, &smr_shash_grp);

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
		counter_dec_preemption_disabled(&smrh->smrsh_count);
		hw_lck_ptr_unlock(cursor.head, next, &smr_shash_grp);
	} else {
		smr_serialized_store_relaxed(cursor.prev, next);
		counter_dec_preemption_disabled(&smrh->smrsh_count);
		hw_lck_ptr_unlock(cursor.head, first, &smr_shash_grp);
	}

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
		hw_lck_ptr_unlock(cursor.head, new_link, &smr_shash_grp);
	} else {
		smr_serialized_store_relaxed(cursor.prev, new_link);
		hw_lck_ptr_unlock(cursor.head, first, &smr_shash_grp);
	}
}

void
__smr_shash_entered_mut_abort(smr_shash_mut_cursor_t cursor)
{
	hw_lck_ptr_unlock(cursor.head,
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
