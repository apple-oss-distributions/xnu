/*
 * Copyright (c) 2012-2020 Apple Inc. All rights reserved.
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

#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/mach_types.h>
#include <mach/telemetry_notification_server.h>

#include <kern/assert.h>
#include <kern/clock.h>
#include <kern/coalition.h>
#include <kern/counter.h>
#include <kern/debug.h>
#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/kern_types.h>
#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/thread.h>
#include <kern/telemetry.h>
#include <kern/timer_call.h>
#include <kern/policy_internal.h>
#include <kern/kcdata.h>
#include <kern/percpu.h>
#include <kern/mpsc_ring.h>

#include <pexpert/pexpert.h>

#include <string.h>
#include <vm/vm_kern_xnu.h>
#include <vm/vm_shared_region.h>

#include <kperf/callstack.h>
#include <kern/backtrace.h>
#include <kern/monotonic.h>

#include <security/mac_mach_internal.h>

#include <sys/errno.h>
#include <sys/kdebug.h>
#include <uuid/uuid.h>
#include <kdp/kdp_dyld.h>

#include <libkern/coreanalytics/coreanalytics.h>
#include <kern/thread_call.h>

struct proc;
extern int proc_pid(struct proc *);
extern char *proc_name_address(void *p);
extern char *proc_longname_address(void *p);
extern uint64_t proc_uniqueid(void *p);
extern uint64_t proc_was_throttled(void *p);
extern uint64_t proc_did_throttle(void *p);
extern boolean_t task_did_exec(task_t task);
extern boolean_t task_is_exec_copy(task_t task);

#if CONFIG_CPU_COUNTERS
#define HAS_PMI_MICROSTACKSHOTS 1
#endif /* CONFIG_CPU_COUNTERS */

struct micro_snapshot_buffer {
	vm_offset_t             buffer;
	uint32_t                size;
	uint32_t                current_position;
	uint32_t                end_point;
};

static const size_t _telemetry_sample_size_static = sizeof(struct micro_snapshot) +
    sizeof(struct task_snapshot) +
    sizeof(struct thread_snapshot);

static void telemetry_instrumentation_begin(
	struct micro_snapshot_buffer *buffer, enum micro_snapshot_flags flags);

static void telemetry_instrumentation_end(struct micro_snapshot_buffer *buffer);

static void telemetry_take_sample(thread_t thread, enum micro_snapshot_flags flags);

#if HAS_PMI_MICROSTACKSHOTS
static void _telemetry_take_sample_kernel(thread_t thread, enum micro_snapshot_flags flags);
static void _telemetry_mark_curthread(bool interrupted_userspace);
#endif /* HAS_PMI_MICROSTACKSHOTS */

#if CONFIG_MACF
static void telemetry_macf_take_sample(thread_t thread, enum micro_snapshot_flags flags);
#endif

struct telemetry_target {
	thread_t                         thread;
	uintptr_t                       *frames;
	size_t                           frames_count;
	bool                             user64_regs;
	uint16_t                         async_start_index;
	enum micro_snapshot_flags        microsnapshot_flags;
	bool                             include_metadata;
	struct micro_snapshot_buffer    *buffer;
	lck_mtx_t                       *buffer_mtx;
};

static int telemetry_process_sample(
	const struct telemetry_target *target,
	bool release_buffer_lock,
	uint32_t *out_current_record_start);

static int telemetry_buffer_gather(
	user_addr_t buffer,
	uint32_t *length,
	bool mark,
	struct micro_snapshot_buffer *current_buffer);

#define TELEMETRY_DEFAULT_BUFFER_SIZE (16 * 1024)
#define TELEMETRY_MAX_BUFFER_SIZE (64 * 1024)

#define TELEMETRY_DEFAULT_NOTIFY_LEEWAY (4*1024) // Userland gets 4k of leeway to collect data after notification
#define TELEMETRY_MAX_UUID_COUNT (128) // Max of 128 non-shared-cache UUIDs to log for symbolication

bool telemetry_sample_pmis = false;

uint32_t telemetry_timestamp = 0;

struct telemetry_metadata {
	/*
	 * The current generation of microstackshot-based telemetry.
	 * Incremented whenever the settings change.
	 */
	uint32_t tm_generation;
	/*
	 * The total number of samples recorded.
	 */
	uint64_t tm_samples_recorded;
	/*
	 * The total number of samples that were skipped.
	 */
	uint64_t tm_samples_skipped;
	/*
	 * What's triggering the microstackshot samples.
	 */
	enum telemetry_source {
		TMSRC_NONE = 0,
		TMSRC_UNKNOWN,
		TMSRC_TIME,
		TMSRC_INSTRUCTIONS,
		TMSRC_CYCLES,
	} tm_source;
	/*
	 * The interval used for periodic sampling.
	 */
	uint64_t tm_period;
};

/*
 * The telemetry_buffer is responsible
 * for timer samples and interrupt samples that are driven by
 * compute_averages().  It will notify its client (if one
 * exists) when it has enough data to be worth flushing.
 */
struct micro_snapshot_buffer telemetry_buffer = {
	.buffer = 0,
	.size = 0,
	.current_position = 0,
	.end_point = 0
};

#if CONFIG_MACF
#define TELEMETRY_MACF_DEFAULT_BUFFER_SIZE (16*1024)
/*
 * The MAC framework uses its own telemetry buffer for the purposes of auditing
 * security-related work being done by userland threads.
 */
struct micro_snapshot_buffer telemetry_macf_buffer = {
	.buffer = 0,
	.size = 0,
	.current_position = 0,
	.end_point = 0
};
#endif /* CONFIG_MACF */

int telemetry_bytes_since_last_mark = -1; // How much data since buf was last marked?
int telemetry_buffer_notify_at = 0;

LCK_GRP_DECLARE(telemetry_lck_grp, "telemetry group");
LCK_MTX_DECLARE(telemetry_mtx, &telemetry_lck_grp);
LCK_MTX_DECLARE(telemetry_pmi_mtx, &telemetry_lck_grp);
LCK_MTX_DECLARE(telemetry_macf_mtx, &telemetry_lck_grp);
LCK_SPIN_DECLARE(telemetry_metadata_lck, &telemetry_lck_grp);

#define TELEMETRY_LOCK() do { lck_mtx_lock(&telemetry_mtx); } while (0)
#define TELEMETRY_TRY_SPIN_LOCK() lck_mtx_try_lock_spin(&telemetry_mtx)
#define TELEMETRY_UNLOCK() do { lck_mtx_unlock(&telemetry_mtx); } while (0)

#define TELEMETRY_PMI_LOCK() do { lck_mtx_lock(&telemetry_pmi_mtx); } while (0)
#define TELEMETRY_PMI_UNLOCK() do { lck_mtx_unlock(&telemetry_pmi_mtx); } while (0)

#define TELEMETRY_MACF_LOCK() do { lck_mtx_lock(&telemetry_macf_mtx); } while (0)
#define TELEMETRY_MACF_UNLOCK() do { lck_mtx_unlock(&telemetry_macf_mtx); } while (0)

/*
 * Protected by the telemetry_metadata_lck spinlock.
 */
struct telemetry_metadata telemetry_metadata = { 0 };

#if HAS_PMI_MICROSTACKSHOTS
static __security_const_late thread_call_t _telemetry_kernel_notify_thread;
_Atomic bool _telemetry_kernel_notified = false;
static struct mpsc_ring _telemetry_kernel_ring;

static void _telemetry_kernel_notify(void *, void *);
#endif /* HAS_PMI_MICROSTACKSHOTS */

TUNABLE(uint32_t, telemetry_buffer_size, "telemetry_buffer_size", TELEMETRY_DEFAULT_BUFFER_SIZE);
TUNABLE(uint8_t, telemetry_kernel_buffer_size_pow_2, "telemetry_kernel_buffer_size_pow_2", 16);
TUNABLE(uint32_t, telemetry_notification_leeway, "telemetry_notification_leeway", TELEMETRY_DEFAULT_NOTIFY_LEEWAY);

__startup_func
static void
_telemetry_init(void)
{
	telemetry_buffer.size = MIN(telemetry_buffer_size, TELEMETRY_MAX_BUFFER_SIZE);

	kern_return_t ret = kmem_alloc(kernel_map, &telemetry_buffer.buffer, telemetry_buffer.size,
	    KMA_DATA | KMA_ZERO | KMA_PERMANENT, VM_KERN_MEMORY_DIAG);
	if (ret != KERN_SUCCESS) {
		printf("telemetry: allocation failed: %d\n", ret);
		return;
	}

	if (telemetry_notification_leeway >= telemetry_buffer.size) {
		printf("telemetry: nonsensical telemetry_notification_leeway boot-arg %d changed to %d\n",
		    telemetry_notification_leeway, TELEMETRY_DEFAULT_NOTIFY_LEEWAY);
		telemetry_notification_leeway = TELEMETRY_DEFAULT_NOTIFY_LEEWAY;
	}
	telemetry_buffer_notify_at = telemetry_buffer.size - telemetry_notification_leeway;

#if HAS_PMI_MICROSTACKSHOTS
#if __arm__ || __arm64__
	unsigned int cpu_count = ml_get_cpu_count();
#else // __arm__ || __arm64__
	unsigned int cpu_count = ml_early_cpu_max_number() + 1;
#endif // !__arm__ && !__arm64__

	mpsc_ring_init(&_telemetry_kernel_ring, telemetry_kernel_buffer_size_pow_2, (uint8_t)cpu_count);

	_telemetry_kernel_notify_thread = thread_call_allocate_with_options(
		_telemetry_kernel_notify, NULL, THREAD_CALL_PRIORITY_USER,
		THREAD_CALL_OPTIONS_ONCE);
	if (!_telemetry_kernel_notify_thread) {
		panic("telemetry_init: failed to allocate kernel notification thread call");
	}
#endif /* !HAS_PMI_MICROSTACKSHOTS */
}

STARTUP(MACH_IPC, STARTUP_RANK_FIRST, _telemetry_init);

/*
 * If userland has registered a port for telemetry notifications, send one now.
 */
static void
_telemetry_notify_user(telemetry_notice_t flags)
{
	mach_port_t user_port = MACH_PORT_NULL;

	kern_return_t kr = host_get_telemetry_port(host_priv_self(), &user_port);
	if ((kr != KERN_SUCCESS) || !IPC_PORT_VALID(user_port)) {
		return;
	}

	telemetry_notification(user_port, flags);
	ipc_port_release_send(user_port);
}

#if HAS_PMI_MICROSTACKSHOTS

static void
telemetry_pmi_handler(bool user_mode, __unused void *ctx)
{
	thread_t thread = current_thread();
	if (get_threadtask(thread) == kernel_task) {
		_telemetry_take_sample_kernel(thread, kPMIRecord);
	} else {
		_telemetry_mark_curthread(user_mode);
	}
}

#endif /* HAS_PMI_MICROSTACKSHOTS */

int
telemetry_pmi_setup(enum telemetry_pmi pmi_ctr, uint64_t period)
{
#if HAS_PMI_MICROSTACKSHOTS
	enum telemetry_source source = TMSRC_NONE;
	int error = 0;
	const char *name = "?";

	unsigned int ctr = 0;

	TELEMETRY_PMI_LOCK();

	switch (pmi_ctr) {
	case TELEMETRY_PMI_NONE:
		if (!telemetry_sample_pmis) {
			error = 1;
			goto out;
		}

		telemetry_sample_pmis = false;
		error = mt_microstackshot_stop();
		if (!error) {
			printf("telemetry: disabling ustackshot on PMI\n");
			int intrs_en = ml_set_interrupts_enabled(FALSE);
			lck_spin_lock(&telemetry_metadata_lck);
			telemetry_metadata.tm_period = 0;
			telemetry_metadata.tm_source = TMSRC_NONE;
			lck_spin_unlock(&telemetry_metadata_lck);
			ml_set_interrupts_enabled(intrs_en);
		}
		goto out;

	case TELEMETRY_PMI_INSTRS:
		ctr = MT_CORE_INSTRS;
		name = "instructions";
		source = TMSRC_INSTRUCTIONS;
		break;

	case TELEMETRY_PMI_CYCLES:
		ctr = MT_CORE_CYCLES;
		name = "cycles";
		source = TMSRC_CYCLES;
		break;

	default:
		error = 1;
		goto out;
	}

	telemetry_sample_pmis = true;

	error = mt_microstackshot_start(ctr, period, telemetry_pmi_handler, NULL);
	if (!error) {
		printf("telemetry: ustackshot every %llu %s\n", period, name);

		int intrs_en = ml_set_interrupts_enabled(FALSE);
		lck_spin_lock(&telemetry_metadata_lck);
		telemetry_metadata.tm_period = period;
		telemetry_metadata.tm_source = source;
		telemetry_metadata.tm_generation += 1;
		lck_spin_unlock(&telemetry_metadata_lck);
		ml_set_interrupts_enabled(intrs_en);
	}

out:
	TELEMETRY_PMI_UNLOCK();
	return error;
#else /* HAS_PMI_MICROSTACKSHOTS */
#pragma unused(pmi_ctr, period)
	return 1;
#endif /* !HAS_PMI_MICROSTACKSHOTS */
}

#if HAS_PMI_MICROSTACKSHOTS

/*
 * Mark the current thread for an interrupt-based
 * telemetry record, to be sampled at the next AST boundary.
 */
static void
_telemetry_mark_curthread(bool interrupted_userspace)
{
	uint32_t ast_bits = AST_TELEMETRY_PMI;
	thread_t thread = current_thread();

	/*
	 * PMI handler was called but microstackshot expected sampling to be
	 * disabled; log it for telemetry and ignore the sample.
	 */
	if (!telemetry_sample_pmis) {
		os_atomic_inc(&telemetry_metadata.tm_samples_skipped, relaxed);
		return;
	}

	ast_bits |= (interrupted_userspace ? AST_TELEMETRY_USER : AST_TELEMETRY_KERNEL);
	thread_ast_set(thread, ast_bits);
	ast_propagate(thread);
}

static void
_telemetry_kernel_notify(void * __unused p1, void * __unused p2)
{
	_telemetry_notify_user(TELEMETRY_NOTICE_KERNEL_MICROSTACKSHOT);
}

#endif /* HAS_PMI_MICROSTACKSHOTS */

void
telemetry_ast(thread_t thread, ast_t reasons)
{
	assert((reasons & AST_TELEMETRY_ALL) != 0);

	uint8_t record_type = 0;
	if (reasons & AST_TELEMETRY_IO) {
		record_type |= kIORecord;
	}
	if (reasons & (AST_TELEMETRY_USER | AST_TELEMETRY_KERNEL)) {
		record_type |= (reasons & AST_TELEMETRY_PMI) ? kPMIRecord :
		    kInterruptRecord;
	}

	if ((reasons & AST_TELEMETRY_MACF) != 0) {
		record_type |= kMACFRecord;
	}

	enum micro_snapshot_flags user_telemetry = (reasons & AST_TELEMETRY_USER) ? kUserMode : 0;
	enum micro_snapshot_flags microsnapshot_flags = record_type | user_telemetry;

	if ((reasons & AST_TELEMETRY_MACF) != 0) {
		telemetry_macf_take_sample(thread, microsnapshot_flags);
	}

	if ((reasons & (AST_TELEMETRY_IO | AST_TELEMETRY_KERNEL | AST_TELEMETRY_PMI
	    | AST_TELEMETRY_USER)) != 0) {
		telemetry_take_sample(thread, microsnapshot_flags);
	}
}

static bool
_telemetry_task_can_sample(task_t task)
{
	return (task != TASK_NULL) && !task_did_exec(task) && !task_is_exec_copy(task);
}

/*
 * Kernel Thread Microstackshot Support
 */

#define TELEMETRY_KERNEL_FRAMES_MAX (128)

#if HAS_PMI_MICROSTACKSHOTS

static const uint32_t TKS_MAGIC = 0x83a83f29;

/*
 * The bare minimum needed to record a sample from interrupt context, stored in
 * a ringbuffer for later collection.
 */
struct _telemetry_kernel_sample {
	clock_sec_t tks_time_secs;
	uint64_t tks_serial_number;
	uint64_t tks_telemetry_skipped;
	uint64_t tks_telemetry_period;

	uint64_t tks_system_time_in_terminated_threads;
	uint64_t tks_task_size;
	uint64_t tks_pageins;
	uint64_t tks_faults;
	uint64_t tks_cow_faults;

	uint64_t tks_thread_id;
	uint64_t tks_system_time;
	clock_usec_t tks_time_usecs;
	uint32_t tks_magic;
	uint32_t tks_thread_state;
	uint32_t tks_sched_pri;
	uint32_t tks_base_pri;
	uint32_t tks_sched_flags;
	uint32_t tks_call_stack_size;
	uint32_t tks_telemetry_source;
	uint32_t tks_telemetry_generation;
	uint8_t tks_cpu;
	uint8_t tks_io_tier;
	char tks_thread_name[MAXTHREADNAMESIZE];
};

/*
 * Only collect call stacks up to this maximum length.
 */
#define TELEMETRY_KERNEL_FRAMES_MAX (128)

/*
 * A scratch buffer that mirrors the format of data stored in the ringbuffer so
 * it can be written contiguously in a single update.
 */
struct _telemetry_scratch {
	struct _telemetry_kernel_sample ts_sample;
	uintptr_t ts_call_stack[TELEMETRY_KERNEL_FRAMES_MAX];
};

/*
 * Each writer in interrupt context needs a place off the stack to store these
 * scratch buffers.
 */
static struct _telemetry_scratch PERCPU_DATA(_telemetry_pcpu);

/*
 * Collect a sample for the current kernel thread.  Must be called in interrupt
 * context.
 */
static void
_telemetry_take_sample_kernel(thread_t thread, enum micro_snapshot_flags __unused flags)
{
	assert(ml_at_interrupt_context());
	struct _telemetry_scratch *scratch = PERCPU_GET(_telemetry_pcpu);

	/*
	 * Collect the call stack in a packed representation to fit more of these
	 * samples into the ringbuffer.
	 */
	struct backtrace_control ctl = {
		.btc_flags = BTF_KERN_INTERRUPTED,
	};
	backtrace_info_t info = BTI_NONE;
	unsigned int call_stack_count = backtrace(scratch->ts_call_stack,
	    TELEMETRY_KERNEL_FRAMES_MAX,
	    &ctl,
	    &info);
	unsigned int call_stack_size = call_stack_count * sizeof(scratch->ts_call_stack[0]);

	/*
	 * Relaxed here, which allows the samples to be non-monotonically
	 * increasing, but avoids any further synchronization with writers.
	 */
	uint64_t serial_number = os_atomic_inc(&telemetry_metadata.tm_samples_recorded, relaxed);

	struct recount_times_mach term_times = recount_task_terminated_times(kernel_task);
	struct recount_times_mach thread_times = recount_current_thread_times();

	clock_sec_t secs = 0;
	clock_usec_t usecs = 0;
	clock_get_calendar_microtime(&secs, &usecs);
	uint8_t cpu = (uint8_t)cpu_number();
	scratch->ts_sample = (struct _telemetry_kernel_sample){
		.tks_magic = TKS_MAGIC,
		.tks_serial_number = serial_number,
		.tks_telemetry_skipped = os_atomic_load(&telemetry_metadata.tm_samples_skipped, relaxed),
		.tks_telemetry_period = telemetry_metadata.tm_period,
		.tks_telemetry_source = telemetry_metadata.tm_source,
		.tks_telemetry_generation = telemetry_metadata.tm_generation,
		.tks_cpu = cpu,
		.tks_time_secs = secs,
		.tks_time_usecs = usecs,
		.tks_thread_id = thread_tid(thread),
		.tks_pageins = counter_load(&kernel_task->pageins),
		.tks_faults = counter_load(&kernel_task->faults),
		.tks_cow_faults = counter_load(&kernel_task->cow_faults),
		.tks_system_time_in_terminated_threads = term_times.rtm_system,
		.tks_system_time = thread_times.rtm_system,
		.tks_thread_state = thread->state,
		.tks_sched_pri = thread->sched_pri,
		.tks_base_pri = thread->base_pri,
		.tks_io_tier = (uint8_t)proc_get_effective_thread_policy(thread, TASK_POLICY_IO),
		.tks_call_stack_size = call_stack_size,
	};
	thread_get_thread_name(thread, scratch->ts_sample.tks_thread_name);

	/*
	 * Write just the amount needed to store the sample information and call
	 * stack.
	 */
	uint32_t size_needed = sizeof(struct _telemetry_kernel_sample) + call_stack_size;
	uint32_t available =
	    mpsc_ring_write(&_telemetry_kernel_ring, cpu, scratch, size_needed);

	/*
	 * Check that there was enough space to store the sample.
	 */
	bool skipped = available < size_needed;
	/*
	 * Incrementing samples-recorded in the metadata will cover indicating this
	 * sample is missing to user space.
	 */
	if (skipped || available - size_needed <= telemetry_notification_leeway) {
		if (os_atomic_cmpxchg(&_telemetry_kernel_notified, false, true, relaxed)) {
			thread_call_enter(_telemetry_kernel_notify_thread);
		}
	}
}

/*
 * The format of sample data that user space can parse, with no UUIDs present,
 * as is the case for kernel samples.
 */
struct _telemetry_kernel_snapshots {
	struct micro_snapshot tkse_micro_snap;
	struct task_snapshot tkse_task_snap;
	struct thread_snapshot tkse_thread_snap;
};

/*
 * Convert a kernel sample into the trio of snapshots that user space can parse.
 */
static void
_telemetry_kernel_snapshot(
	struct _telemetry_kernel_snapshots *snaps,
	struct _telemetry_kernel_sample *sample)
{
	snaps->tkse_micro_snap = (struct micro_snapshot){
		.snapshot_magic = STACKSHOT_MICRO_SNAPSHOT_MAGIC,
		.ms_flags = (uint8_t)(kPMIRecord | kKernelThread),
		.ms_cpu = sample->tks_cpu,
		.ms_time = sample->tks_time_secs,
		.ms_time_microsecs = sample->tks_time_usecs,
	};
	snaps->tkse_task_snap = (struct task_snapshot){
		.snapshot_magic = STACKSHOT_TASK_SNAPSHOT_MAGIC,
		.ss_flags = kKernel64_p,
		.pid = 0,
		.uniqueid = 0,
		.system_time_in_terminated_threads =
	    sample->tks_system_time_in_terminated_threads,
		.task_size = sample->tks_task_size,
		.faults = sample->tks_faults,
		.pageins = sample->tks_pageins,
		.cow_faults = sample->tks_cow_faults,
		.p_comm = "kernel_task",
		.was_throttled = 0,
		.did_throttle = 0,
		.p_start_sec = coalition_id(kernel_task->coalition[COALITION_TYPE_RESOURCE]),
		/* Set the on-behalf-of pids to -1. */
		.p_start_usec = UINT64_MAX,
		.latency_qos = LATENCY_QOS_TIER_UNSPECIFIED,
		.io_priority_size = {
			[0] = ((uint64_t)sample->tks_telemetry_source << 32) | sample->tks_telemetry_generation,
			[1] = sample->tks_telemetry_period,
			[2] = sample->tks_serial_number,
			[3] = sample->tks_telemetry_skipped,
		},
	};
	snaps->tkse_thread_snap = (struct thread_snapshot){
		.snapshot_magic = STACKSHOT_THREAD_SNAPSHOT_MAGIC,
		.ss_flags = kKernel64_p,
		.nkern_frames = sample->tks_call_stack_size / sizeof(uintptr_t),
		.wait_event = 0,
		.continuation = 0,
		.thread_id = sample->tks_thread_id,
		.system_time = sample->tks_system_time,
		.state = sample->tks_thread_state,
		.priority = sample->tks_base_pri,
		.sched_pri = sample->tks_sched_pri,
		.io_tier = sample->tks_io_tier,
	};
	memset(snaps->tkse_thread_snap.pth_name, 0, sizeof(snaps->tkse_thread_snap.pth_name));
	strlcpy(snaps->tkse_thread_snap.pth_name,
	    sample->tks_thread_name,
	    sizeof(snaps->tkse_thread_snap.pth_name));
}

#endif /* HAS_PMI_MICROSTACKSHOTS */

int
telemetry_kernel_gather(user_addr_t user_buffer, uint32_t *user_length)
{
#if HAS_PMI_MICROSTACKSHOTS
	int result = 0;
	/*
	 * Track how much data has been copied out to the user buffer.
	 */
	uint32_t copied = 0;
	uint32_t copy_length = *user_length;

	*user_length = 0;

	/*
	 * Get a cursor to read from the ringbuffer.
	 */
	mpsc_ring_cursor_t cursor = mpsc_ring_read_start(&_telemetry_kernel_ring);

	while (copied < copy_length) {
		/*
		 * This function is called directly off a syscall, so it can afford to
		 * use some stack space.
		 */
		struct _telemetry_kernel_snapshots snaps = { 0 };

		/*
		 * Check that the user buffer still has enough space for at least the
		 * snapshot structures.
		 */
		if (sizeof(snaps) > copy_length - copied) {
			break;
		}

		/*
		 * Read the sample from the ringbuffer.
		 */
		struct _telemetry_kernel_sample sample = { 0 };
		bool advanced = mpsc_ring_cursor_advance(
			&_telemetry_kernel_ring,
			&cursor,
			&sample,
			sizeof(sample));
		/*
		 * If there's no more data, return to user space.
		 */
		if (!advanced) {
			break;
		}

		if (sample.tks_magic != TKS_MAGIC) {
			panic("microstackshot: kernel sample magic is invalid");
		}
		/*
		 * Compute the size needed for the snapshots and call stack and bail
		 * out if there's not enough room in the user's buffer.
		 */
		assert3u(sample.tks_call_stack_size, <, sizeof(uintptr_t) * TELEMETRY_KERNEL_FRAMES_MAX);
		uint32_t size_needed = sizeof(snaps) + sample.tks_call_stack_size;
		if (size_needed > copy_length - copied) {
			break;
		}

		/*
		 * Convert the sample into snapshots suitable for user space and copy
		 * them out.
		 */
		_telemetry_kernel_snapshot(&snaps, &sample);
		result = copyout(&snaps, user_buffer + copied, sizeof(snaps));
		if (result != 0) {
			break;
		}
		copied += sizeof(snaps);

		/*
		 * Copy the call stack out of the ringbuffer.
		 */
		uintptr_t call_stack[TELEMETRY_KERNEL_FRAMES_MAX] = { 0 };
		assert3u(sizeof(call_stack), >=, sample.tks_call_stack_size);
		advanced = mpsc_ring_cursor_advance(
			&_telemetry_kernel_ring,
			&cursor,
			&call_stack,
			sample.tks_call_stack_size);
		/*
		 * There must be a call stack after the sample, otherwise something got
		 * corrupted and there's no more framing information for the reader.
		 */
		assert(advanced);
		uint32_t call_stack_count = sample.tks_call_stack_size / sizeof(uintptr_t);
		for (uint32_t i = 0; i < call_stack_count; i++) {
			/*
			 * The last frame of the call stack can sometimes be 0, ignore it.
			 */
			if (call_stack[i] != 0) {
				call_stack[i] = VM_KERNEL_UNSLIDE(call_stack[i]);
			}
		}

		/*
		 * Copy the unpacked call stack out to user space.
		 */
		result = copyout(&call_stack, user_buffer + copied,
		    sample.tks_call_stack_size);
		if (result != 0) {
			break;
		}
		copied += sample.tks_call_stack_size;
		mpsc_ring_cursor_commit(&_telemetry_kernel_ring, &cursor);
	}

	/*
	 * On success, store the number of bytes copied.
	 *
	 * Some partial data may have been copied out, but user space shouldn't
	 * try to inspect it.
	 */
	if (result == 0) {
		/*
		 * Complete the read operation and sync any progress back to the ringbuffer.
		 */
		mpsc_ring_read_finish(&_telemetry_kernel_ring, cursor);
		os_atomic_store(&_telemetry_kernel_notified, false, relaxed);
		*user_length = copied;
	} else {
		mpsc_ring_read_cancel(&_telemetry_kernel_ring, cursor);
	}
	return result;
#else /* HAS_PMI_MICROSTACKSHOTS */
#pragma unused(user_buffer, user_length)
	return ENOTSUP;
#endif /* !HAS_PMI_MICROSTACKSHOTS */
}

void
telemetry_instrumentation_begin(
	__unused struct micro_snapshot_buffer *buffer,
	__unused enum micro_snapshot_flags flags)
{
	/* telemetry_XXX accessed outside of lock for instrumentation only */
	KDBG(MACHDBG_CODE(DBG_MACH_STACKSHOT, MICROSTACKSHOT_RECORD) | DBG_FUNC_START,
	    flags, telemetry_bytes_since_last_mark, 0,
	    (&telemetry_buffer != buffer));
}

void
telemetry_instrumentation_end(__unused struct micro_snapshot_buffer *buffer)
{
	/* telemetry_XXX accessed outside of lock for instrumentation only */
	KDBG(MACHDBG_CODE(DBG_MACH_STACKSHOT, MICROSTACKSHOT_RECORD) | DBG_FUNC_END,
	    (&telemetry_buffer == buffer), telemetry_bytes_since_last_mark,
	    buffer->current_position, buffer->end_point);
}

static void
_telemetry_take_sample_user(thread_t thread, enum micro_snapshot_flags flags)
{
	uintptr_t                   frames[128];
	size_t                      frames_len = sizeof(frames) / sizeof(frames[0]);
	uint32_t                    btcount;
	struct backtrace_user_info  btinfo = BTUINFO_INIT;
	uint16_t                    async_start_index = UINT16_MAX;

	/* Collect backtrace from user thread. */
	btcount = backtrace_user(frames, frames_len, NULL, &btinfo);
	if (btinfo.btui_error != 0) {
		return;
	}
	if (btinfo.btui_async_frame_addr != 0 &&
	    btinfo.btui_async_start_index != 0) {
		/*
		 * Put the async callstack inline after the frame pointer walk call
		 * stack.
		 */
		async_start_index = (uint16_t)btinfo.btui_async_start_index;
		uintptr_t frame_addr = btinfo.btui_async_frame_addr;
		unsigned int frames_left = frames_len - async_start_index;
		struct backtrace_control ctl = { .btc_frame_addr = frame_addr, };
		btinfo = BTUINFO_INIT;
		unsigned int async_filled = backtrace_user(frames + async_start_index,
		    frames_left, &ctl, &btinfo);
		if (btinfo.btui_error == 0) {
			btcount = MIN(async_start_index + async_filled, frames_len);
		}
	}

	/*
	 * Capture any other metadata and write it to the telemetry buffer.
	 */
	struct telemetry_target target = {
		.thread = thread,
		.frames = frames,
		.frames_count = btcount,
		.user64_regs = (btinfo.btui_info & BTI_64_BIT) != 0,
		.microsnapshot_flags = flags,
		.include_metadata = flags & kPMIRecord,
		.buffer = &telemetry_buffer,
		.buffer_mtx = &telemetry_mtx,
		.async_start_index = async_start_index,
	};
	telemetry_process_sample(&target, true, NULL);
}

void
telemetry_take_sample(thread_t thread, enum micro_snapshot_flags flags)
{
	if (thread == THREAD_NULL) {
		return;
	}

	/* Ensure task is ready for taking a sample. */
	task_t task = get_threadtask(thread);
	if (!_telemetry_task_can_sample(task)) {
		os_atomic_inc(&telemetry_metadata.tm_samples_skipped, relaxed);
		return;
	}

	telemetry_instrumentation_begin(&telemetry_buffer, flags);
	_telemetry_take_sample_user(thread, flags);
	telemetry_instrumentation_end(&telemetry_buffer);
}

#if CONFIG_MACF
void
telemetry_macf_take_sample(thread_t thread, enum micro_snapshot_flags flags)
{
	task_t                        task;

	uintptr_t                     frames_stack[128];
	vm_size_t                     btcapacity     = ARRAY_COUNT(frames_stack);
	uint32_t                      btcount        = 0;
	typedef uintptr_t             telemetry_user_frame_t __kernel_data_semantics;
	telemetry_user_frame_t        *frames        = frames_stack;
	bool                          alloced_frames = false;

	struct backtrace_user_info    btinfo         = BTUINFO_INIT;
	struct backtrace_control      btctl          = BTCTL_INIT;

	uint32_t                      retry_count    = 0;
	const uint32_t                max_retries    = 10;

	bool                          initialized    = false;
	struct micro_snapshot_buffer *telbuf         = &telemetry_macf_buffer;
	uint32_t                      record_start   = 0;
	bool                          did_process    = false;
	int                           rv             = 0;

	if (thread == THREAD_NULL) {
		return;
	}

	telemetry_instrumentation_begin(telbuf, flags);

	/* Ensure task is ready for taking a sample. */
	task = get_threadtask(thread);
	if (!_telemetry_task_can_sample(task) || task == kernel_task) {
		rv = EBUSY;
		goto out;
	}

	/* Ensure MACF telemetry buffer was initialized. */
	TELEMETRY_MACF_LOCK();
	initialized = (telbuf->size > 0);
	TELEMETRY_MACF_UNLOCK();

	if (!initialized) {
		rv = ENOMEM;
		goto out;
	}

	/* Collect backtrace from user thread. */
	while (retry_count < max_retries) {
		btcount += backtrace_user(frames + btcount, btcapacity - btcount, &btctl, &btinfo);

		if ((btinfo.btui_info & BTI_TRUNCATED) != 0 && btinfo.btui_next_frame_addr != 0) {
			/*
			 * Fast path uses stack memory to avoid an allocation. We must
			 * pivot to heap memory in the case where we cannot write the
			 * complete backtrace to this buffer.
			 */
			if (frames == frames_stack) {
				btcapacity += 128;
				frames = kalloc_data(btcapacity * sizeof(*frames), Z_WAITOK);

				if (frames == NULL) {
					break;
				}

				alloced_frames = true;

				assert(btcapacity > sizeof(frames_stack) / sizeof(frames_stack[0]));
				memcpy(frames, frames_stack, sizeof(frames_stack));
			} else {
				assert(alloced_frames);
				frames = krealloc_data(frames,
				    btcapacity * sizeof(*frames),
				    (btcapacity + 128) * sizeof(*frames),
				    Z_WAITOK);

				if (frames == NULL) {
					break;
				}

				btcapacity += 128;
			}

			btctl.btc_frame_addr = btinfo.btui_next_frame_addr;
			++retry_count;
		} else {
			break;
		}
	}

	if (frames == NULL) {
		rv = ENOMEM;
		goto out;
	} else if (btinfo.btui_error != 0) {
		rv = btinfo.btui_error;
		goto out;
	}

	/* Process the backtrace. */
	struct telemetry_target target = {
		.thread = thread,
		.frames = frames,
		.frames_count = btcount,
		.user64_regs = (btinfo.btui_info & BTI_64_BIT) != 0,
		.microsnapshot_flags = flags,
		.include_metadata = false,
		.buffer = telbuf,
		.buffer_mtx = &telemetry_macf_mtx
	};
	rv = telemetry_process_sample(&target, false, &record_start);
	did_process = true;

out:
	/* Immediately deliver the collected sample to MAC clients. */
	if (rv == 0) {
		assert(telbuf->current_position >= record_start);
		mac_thread_telemetry(thread,
		    0,
		    (void *)(telbuf->buffer + record_start),
		    telbuf->current_position - record_start);
	} else {
		mac_thread_telemetry(thread, rv, NULL, 0);
	}

	/*
	 * The lock was taken by telemetry_process_sample, and we asked it not to
	 * unlock upon completion, so we must release the lock here.
	 */
	if (did_process) {
		TELEMETRY_MACF_UNLOCK();
	}

	if (alloced_frames && frames != NULL) {
		kfree_data(frames, btcapacity * sizeof(*frames));
	}

	telemetry_instrumentation_end(telbuf);
}
#endif /* CONFIG_MACF */

static void
_write_task_snapshot(
	struct task_snapshot *tsnap,
	const struct telemetry_target *target)
{
	struct task *task = get_threadtask(target->thread);
	struct proc *p = get_bsdtask_info(task);
	bool user64_va = task_has_64Bit_addr(task);

	tsnap->snapshot_magic = STACKSHOT_TASK_SNAPSHOT_MAGIC;
	tsnap->pid = proc_pid(p);
	tsnap->uniqueid = proc_uniqueid(p);
	struct recount_times_mach times = recount_task_terminated_times(task);
	tsnap->user_time_in_terminated_threads = times.rtm_user;
	tsnap->system_time_in_terminated_threads = times.rtm_system;
	tsnap->suspend_count = task->suspend_count;
	tsnap->task_size = (typeof(tsnap->task_size))(get_task_phys_footprint(task) / PAGE_SIZE);
	tsnap->faults = counter_load(&task->faults);
	tsnap->pageins = counter_load(&task->pageins);
	tsnap->cow_faults = counter_load(&task->cow_faults);
	/*
	 * The throttling counters are maintained as 64-bit counters in the proc
	 * structure. However, we reserve 32-bits (each) for them in the task_snapshot
	 * struct to save space and since we do not expect them to overflow 32-bits. If we
	 * find these values overflowing in the future, the fix would be to simply
	 * upgrade these counters to 64-bit in the task_snapshot struct
	 */
	tsnap->was_throttled = (uint32_t) proc_was_throttled(p);
	tsnap->did_throttle = (uint32_t) proc_did_throttle(p);

#if CONFIG_COALITIONS
	/*
	 * These fields are overloaded to represent the resource coalition ID of
	 * this task...
	 */
	coalition_t rsrc_coal = task->coalition[COALITION_TYPE_RESOURCE];
	tsnap->p_start_sec = rsrc_coal ? coalition_id(rsrc_coal) : 0;
	/*
	 * ... and the processes this thread is doing work on behalf of.
	 */
	pid_t origin_pid = -1, proximate_pid = -1;
	(void)thread_get_voucher_origin_proximate_pid(target->thread, &origin_pid, &proximate_pid);
	tsnap->p_start_usec = ((uint64_t)proximate_pid << 32) | (uint32_t)origin_pid;
#endif /* CONFIG_COALITIONS */

	if (task->t_flags & TF_TELEMETRY) {
		tsnap->ss_flags |= kTaskRsrcFlagged;
	}

	if (proc_get_effective_task_policy(task, TASK_POLICY_DARWIN_BG)) {
		tsnap->ss_flags |= kTaskDarwinBG;
	}

	if (proc_get_effective_task_policy(task, TASK_POLICY_ROLE) == TASK_FOREGROUND_APPLICATION) {
		tsnap->ss_flags |= kTaskIsForeground;
	}
	if (user64_va) {
		tsnap->ss_flags |= kUser64_p;
	}

	uint32_t bgstate = 0;
	proc_get_darwinbgstate(task, &bgstate);

	if (bgstate & PROC_FLAG_ADAPTIVE_IMPORTANT) {
		tsnap->ss_flags |= kTaskIsBoosted;
	}
	if (bgstate & PROC_FLAG_SUPPRESSED) {
		tsnap->ss_flags |= kTaskIsSuppressed;
	}


	tsnap->latency_qos = task_grab_latency_qos(task);

	strlcpy(tsnap->p_comm, proc_name_address(p), sizeof(tsnap->p_comm));
	const char *longname = proc_longname_address(p);
	if (longname[0] != '\0') {
		/*
		 * XXX Stash the rest of the process's name in some unused fields.
		 */
		strlcpy((char *)tsnap->io_priority_count, &longname[16], sizeof(tsnap->io_priority_count));
	}
	if (target->include_metadata) {
		tsnap->io_priority_size[0] = ((uint64_t)telemetry_metadata.tm_source << 32) | telemetry_metadata.tm_generation;
		tsnap->io_priority_size[1] = telemetry_metadata.tm_period;
		tsnap->io_priority_size[2] = os_atomic_inc(&telemetry_metadata.tm_samples_recorded, relaxed);
		tsnap->io_priority_size[3] = telemetry_metadata.tm_samples_skipped;
	}
	if (task->task_shared_region_slide != -1) {
		tsnap->shared_cache_slide = task->task_shared_region_slide;
		bcopy(task->task_shared_region_uuid, tsnap->shared_cache_identifier,
		    sizeof(task->task_shared_region_uuid));
	}
}

static void
_write_thread_snapshot(struct thread_snapshot *thsnap, const struct telemetry_target *target)
{
	struct thread *thread = target->thread;

	thsnap->snapshot_magic = STACKSHOT_THREAD_SNAPSHOT_MAGIC;
	thsnap->thread_id = thread_tid(thread);
	thsnap->state = thread->state;
	thsnap->priority = thread->base_pri;
	thsnap->sched_pri = thread->sched_pri;
	thsnap->sched_flags = thread->sched_flags;
	thsnap->ss_flags |= kStacksPCOnly;
	thsnap->ts_qos = thread->effective_policy.thep_qos;
	thsnap->ts_rqos = thread->requested_policy.thrp_qos;
	thsnap->ts_rqos_override = MAX(thread->requested_policy.thrp_qos_override,
	    thread->requested_policy.thrp_qos_workq_override);
	thsnap->nuser_frames = target->frames_count;
	memcpy(thsnap->_reserved + 1, &target->async_start_index,
	    sizeof(target->async_start_index));

	if (proc_get_effective_thread_policy(thread, TASK_POLICY_DARWIN_BG)) {
		thsnap->ss_flags |= kThreadDarwinBG;
	}
	if (target->user64_regs) {
		thsnap->ss_flags |= kUser64_p;
	}

	boolean_t interrupt_state = ml_set_interrupts_enabled(FALSE);
	struct recount_times_mach times = recount_current_thread_times();
	ml_set_interrupts_enabled(interrupt_state);
	thsnap->user_time = times.rtm_user;
	thsnap->system_time = times.rtm_system;
}

struct _telemetry_uuids {
	errno_t error;
	void *uuid_info;
	uint32_t uuid_info_count;
	uint32_t uuid_info_size;
};

/*
 * Retrieve the array of UUIDs for binaries used by this task.
 */
static struct _telemetry_uuids
_telemetry_sample_uuids(task_t task)
{
	bool const user64_va = task_has_64Bit_addr(task);
	uint32_t uuid_info_count = 0;
	mach_vm_address_t uuid_info_addr = 0;
	uint32_t uuid_info_size = 0;
	if (user64_va) {
		uuid_info_size = sizeof(struct user64_dyld_uuid_info);
		struct user64_dyld_all_image_infos task_image_infos;
		if (copyin(task->all_image_info_addr, &task_image_infos, sizeof(task_image_infos)) == 0) {
			uuid_info_count = (uint32_t)task_image_infos.uuidArrayCount;
			uuid_info_addr = task_image_infos.uuidArray;
		}
	} else {
		uuid_info_size = sizeof(struct user32_dyld_uuid_info);
		struct user32_dyld_all_image_infos task_image_infos;
		if (copyin(task->all_image_info_addr, &task_image_infos, sizeof(task_image_infos)) == 0) {
			uuid_info_count = task_image_infos.uuidArrayCount;
			uuid_info_addr = task_image_infos.uuidArray;
		}
	}

	/*
	 * If dyld is updating the data structure (indicated by a NULL uuidArray field),
	 * do not provide any UUIDs with the sample.
	 */
	if (uuid_info_addr == USER_ADDR_NULL) {
		return (struct _telemetry_uuids){};
	}

	/*
	 * The main binary and interesting non-shared-cache libraries should be in the first few images.
	 */
	uuid_info_count = MIN(uuid_info_count, TELEMETRY_MAX_UUID_COUNT);
	uint32_t uuid_info_array_size = uuid_info_count * uuid_info_size;
	char *uuid_info_array = kalloc_data(uuid_info_array_size, Z_WAITOK);
	if (uuid_info_array == NULL) {
		return (struct _telemetry_uuids){
			       .error = ENOMEM,
		};
	}

	/*
	 * Copy in the UUID info array.  Ignore any failures to copyin.
	 */
	if (copyin(uuid_info_addr, uuid_info_array, uuid_info_array_size) != 0) {
		kfree_data(uuid_info_array, uuid_info_array_size);
		uuid_info_array = NULL;
		uuid_info_array_size = 0;
	}

	return (struct _telemetry_uuids){
		       .uuid_info = uuid_info_array,
		       .uuid_info_count = uuid_info_count,
		       .uuid_info_size = uuid_info_array_size,
	};
}

static bool
_telemetry_sample_dispatch_serialno(task_t task, thread_t thread, uint64_t *serialno_out)
{
	uint64_t const dqkeyaddr = thread_dispatchqaddr(thread);
	if (dqkeyaddr != 0) {
		uint64_t dqaddr = 0;
		size_t const user_ptr_size = task_has_64Bit_addr(task) ? 8 : 4;

		uint64_t const dq_serialno_offset = get_task_dispatchqueue_serialno_offset(task);
		if ((copyin(dqkeyaddr, (char *)&dqaddr, user_ptr_size) == 0) &&
		    (dqaddr != 0) && (dq_serialno_offset != 0)) {
			uint64_t dqserialnumaddr = dqaddr + dq_serialno_offset;
			if (copyin(dqserialnumaddr, serialno_out, user_ptr_size) == 0) {
				return true;
			}
		}
	}

	return false;
}

static void *
_telemetry_buffer_alloc(struct micro_snapshot_buffer *buf, size_t size)
{
	void *alloc = (void *)(uintptr_t)(buf->buffer + buf->current_position);
	memset(alloc, 0, size);
	buf->current_position += size;
	assert3u(buf->current_position, <=, buf->size);
	return alloc;
}

int
telemetry_process_sample(const struct telemetry_target *target,
    bool release_buffer_lock,
    uint32_t *out_current_record_start)
{
	thread_t const thread = target->thread;
	size_t const btcount = target->frames_count;
	bool const user64_regs = target->user64_regs;
	struct micro_snapshot_buffer * const current_buffer = target->buffer;
	lck_mtx_t * const buffer_mtx = target->buffer_mtx;

	clock_sec_t secs;
	clock_usec_t usecs;
	bool notify = false;
	int rv = 0;

	if (thread == THREAD_NULL) {
		return EINVAL;
	}

	task_t const task = get_threadtask(thread);

	struct _telemetry_uuids uuids = _telemetry_sample_uuids(task);

	/*
	 * Look for a dispatch queue serial number, and copy it in from userland if present.
	 */
	uint64_t dqserial = 0;
	bool dqserial_valid = _telemetry_sample_dispatch_serialno(task, thread, &dqserial);

	size_t const frames_size = btcount * (user64_regs ? 8 : 4);
	size_t const sample_size = _telemetry_sample_size_static +
	    uuids.uuid_info_size + (dqserial_valid ? sizeof(dqserial) : 0) + frames_size;

	clock_get_calendar_microtime(&secs, &usecs);

	/*
	 * We do the bulk of the operation under the telemetry lock, on assumption that
	 * any page faults during execution will not cause another AST_TELEMETRY_ALL
	 * to deadlock; they will just block until we finish. This makes it easier
	 * to copy into the buffer directly. As soon as we unlock, userspace can copy
	 * out of our buffer.
	 */
	lck_mtx_lock(buffer_mtx);

	/*
	 * If the buffer has been deallocated, there's no way to take a sample.
	 */
	if (!current_buffer->buffer) {
		rv = EINVAL;
	}

	/*
	 * If the sample would be larger than the entire buffer, ignore it.
	 */
	if (rv == 0 && current_buffer->size < sample_size) {
		rv = ERANGE;
	}

	if (rv == 0) {
		if ((current_buffer->size - current_buffer->current_position) < sample_size) {
			/*
			 * We can't fit a record in the space available, so wrap around to the beginning.
			 * Save the current position as the known end point of valid data.
			 */
			current_buffer->end_point = current_buffer->current_position;
			current_buffer->current_position = 0;
		}
		uint32_t current_record_start = current_buffer->current_position;

		/*
		 * Write the snapshots and variable-length arrays into the telemetry buffer.
		 */

		struct micro_snapshot *msnap = _telemetry_buffer_alloc(current_buffer, sizeof(*msnap));
		*msnap = (struct micro_snapshot){
			.snapshot_magic = STACKSHOT_MICRO_SNAPSHOT_MAGIC,
			.ms_flags = (uint8_t)target->microsnapshot_flags,
			.ms_cpu = cpu_number(),
			.ms_time = secs,
			.ms_time_microsecs = usecs,
		};

		struct task_snapshot *tsnap = _telemetry_buffer_alloc(current_buffer, sizeof(*tsnap));
		_write_task_snapshot(tsnap, target);

		if (uuids.uuid_info_size > 0) {
			void *uuid_info_buf = _telemetry_buffer_alloc(current_buffer, uuids.uuid_info_size);
			memcpy(uuid_info_buf, uuids.uuid_info, uuids.uuid_info_size);
			tsnap->nloadinfos = uuids.uuid_info_count;
		}

		struct thread_snapshot *thsnap = _telemetry_buffer_alloc(current_buffer, sizeof(*thsnap));
		_write_thread_snapshot(thsnap, target);

		if (dqserial_valid) {
			thsnap->ss_flags |= kHasDispatchSerial;
			uint64_t *dqserial_buf = _telemetry_buffer_alloc(current_buffer, sizeof(*dqserial_buf));
			memcpy(dqserial_buf, &dqserial, sizeof(dqserial));
		}

		void *frames_buf = _telemetry_buffer_alloc(current_buffer, frames_size);
		if (user64_regs) {
			memcpy(frames_buf, target->frames, frames_size);
		} else {
			uint32_t *frames_32 = frames_buf;
			for (int i = 0; i < btcount; i++) {
				frames_32[i] = (uint32_t)target->frames[i];
			}
		}

		if (current_buffer->end_point < current_buffer->current_position) {
			/*
			 * Each time the cursor wraps around to the beginning, we leave a
			 * differing amount of unused space at the end of the buffer. Make
			 * sure the cursor pushes the end point in case we're making use of
			 * more of the buffer than we did the last time we wrapped.
			 */
			current_buffer->end_point = current_buffer->current_position;
		}

		/*
		 * Now THIS is a hack.
		 */
		if (current_buffer == &telemetry_buffer) {
			telemetry_bytes_since_last_mark += (current_buffer->current_position - current_record_start);
			if (telemetry_bytes_since_last_mark > telemetry_buffer_notify_at) {
				notify = true;
			}
		}

		if (out_current_record_start != NULL) {
			*out_current_record_start = current_record_start;
		}
	}

	if (release_buffer_lock) {
		lck_mtx_unlock(buffer_mtx);
	}

	if (notify) {
		_telemetry_notify_user(TELEMETRY_NOTICE_BASE);
	}

	if (uuids.uuid_info != NULL) {
		kfree_data(uuids.uuid_info, uuids.uuid_info_size);
	}

	return rv;
}

int
telemetry_gather(user_addr_t buffer, uint32_t *length, bool mark)
{
	return telemetry_buffer_gather(buffer, length, mark, &telemetry_buffer);
}

int
telemetry_buffer_gather(user_addr_t buffer, uint32_t *length, bool mark, struct micro_snapshot_buffer * current_buffer)
{
	int result = 0;
	uint32_t oldest_record_offset;

	KDBG(MACHDBG_CODE(DBG_MACH_STACKSHOT, MICROSTACKSHOT_GATHER) | DBG_FUNC_START,
	    mark, telemetry_bytes_since_last_mark, 0,
	    (&telemetry_buffer != current_buffer));

	TELEMETRY_LOCK();

	if (current_buffer->buffer == 0) {
		*length = 0;
		goto out;
	}

	if (*length < current_buffer->size) {
		result = KERN_NO_SPACE;
		goto out;
	}

	/*
	 * Copy the ring buffer out to userland in order sorted by time: least recent to most recent.
	 * First, we need to search forward from the cursor to find the oldest record in our buffer.
	 */
	oldest_record_offset = current_buffer->current_position;
	do {
		if (((oldest_record_offset + sizeof(uint32_t)) > current_buffer->size) ||
		    ((oldest_record_offset + sizeof(uint32_t)) > current_buffer->end_point)) {
			if (*(uint32_t *)(uintptr_t)(current_buffer->buffer) == 0) {
				/*
				 * There is no magic number at the start of the buffer, which means
				 * it's empty; nothing to see here yet.
				 */
				*length = 0;
				goto out;
			}
			/*
			 * We've looked through the end of the active buffer without finding a valid
			 * record; that means all valid records are in a single chunk, beginning at
			 * the very start of the buffer.
			 */

			oldest_record_offset = 0;
			assert(*(uint32_t *)(uintptr_t)(current_buffer->buffer) == STACKSHOT_MICRO_SNAPSHOT_MAGIC);
			break;
		}

		if (*(uint32_t *)(uintptr_t)(current_buffer->buffer + oldest_record_offset) == STACKSHOT_MICRO_SNAPSHOT_MAGIC) {
			break;
		}

		/*
		 * There are no alignment guarantees for micro-stackshot records, so we must search at each
		 * byte offset.
		 */
		oldest_record_offset++;
	} while (oldest_record_offset != current_buffer->current_position);

	/*
	 * If needed, copyout in two chunks: from the oldest record to the end of the buffer, and then
	 * from the beginning of the buffer up to the current position.
	 */
	if (oldest_record_offset != 0) {
		if ((result = copyout((void *)(current_buffer->buffer + oldest_record_offset), buffer,
		    current_buffer->end_point - oldest_record_offset)) != 0) {
			*length = 0;
			goto out;
		}
		*length = current_buffer->end_point - oldest_record_offset;
	} else {
		*length = 0;
	}

	if ((result = copyout((void *)current_buffer->buffer, buffer + *length,
	    current_buffer->current_position)) != 0) {
		*length = 0;
		goto out;
	}
	*length += (uint32_t)current_buffer->current_position;

out:

	if (mark && (*length > 0)) {
		telemetry_bytes_since_last_mark = 0;
	}

	TELEMETRY_UNLOCK();

	KDBG(MACHDBG_CODE(DBG_MACH_STACKSHOT, MICROSTACKSHOT_GATHER) | DBG_FUNC_END,
	    current_buffer->current_position, *length,
	    current_buffer->end_point, (&telemetry_buffer != current_buffer));

	return result;
}

#if CONFIG_MACF
static int
telemetry_macf_init_locked(size_t buffer_size)
{
	kern_return_t   kr;

	if (buffer_size > TELEMETRY_MAX_BUFFER_SIZE) {
		buffer_size = TELEMETRY_MAX_BUFFER_SIZE;
	}

	telemetry_macf_buffer.size = buffer_size;

	kr = kmem_alloc(kernel_map, &telemetry_macf_buffer.buffer,
	    telemetry_macf_buffer.size, KMA_DATA | KMA_ZERO | KMA_PERMANENT,
	    VM_KERN_MEMORY_SECURITY);

	if (kr != KERN_SUCCESS) {
		kprintf("Telemetry (MACF): Allocation failed: %d\n", kr);
		return ENOMEM;
	}

	return 0;
}

int
telemetry_macf_mark_curthread(void)
{
	thread_t thread = current_thread();
	task_t   task   = get_threadtask(thread);
	int      rv     = 0;

	if (task == kernel_task) {
		/* Kernel threads never return to an AST boundary, and are ineligible */
		return EINVAL;
	}

	/* Initialize the MACF telemetry buffer if needed. */
	TELEMETRY_MACF_LOCK();
	if (__improbable(telemetry_macf_buffer.size == 0)) {
		rv = telemetry_macf_init_locked(TELEMETRY_MACF_DEFAULT_BUFFER_SIZE);

		if (rv != 0) {
			return rv;
		}
	}
	TELEMETRY_MACF_UNLOCK();

	act_set_macf_telemetry_ast(thread);
	return 0;
}
#endif /* CONFIG_MACF */

static int
telemetry_backtrace_add_kernel(
	char        *buf,
	size_t       buflen)
{
	int rc = 0;
#if defined(__arm__) || defined(__arm64__)
	extern vm_offset_t   segTEXTEXECB;
	extern unsigned long segSizeTEXTEXEC;
	vm_address_t unslid = segTEXTEXECB - vm_kernel_stext;

	rc += scnprintf(buf, buflen, "%s@%lx:%lx\n",
	    kernel_uuid_string, unslid, unslid + segSizeTEXTEXEC - 1);
#elif defined(__x86_64__)
	rc += scnprintf(buf, buflen, "%s@0:%lx\n",
	    kernel_uuid_string, vm_kernel_etext - vm_kernel_stext);
#else
#pragma unused(buf, buflen)
#endif
	return rc;
}

/**
 * Generate a backtrace string which can be symbolicated off system
 *
 * All addresses are relative to the vm_kernel_stext which means that all
 * offsets will be typically <= 50M which uses 7 hex digits.
 *
 * We allow up to TOT entries from FRAMES. The result will be formatted into BUF
 * (up to BUFLEN-1 characters) with the following format:
 *
 *     <OFFSET1>\n
 *     <OFFSET2>\n
 *     ...
 *     <UUID_a>@<TEXT_EXEC_BASE_OFFSET>:<TEXT_EXEC_END_OFFSET>\n
 *     <UUID_b>@<TEXT_EXEC_BASE_OFFSET>:<TEXT_EXEC_END_OFFSET>\n
 *     ...
 *
 * In general this backtrace takes 8 bytes per "frame", with an extra 52 bytes
 * per unique UUID referenced. As a rule of thumb, with a 256 byte long output
 * buffer, at least five entries from four unique UUIDs will generally fit.
 */
void
telemetry_backtrace_to_string(
	char        *buf,
	size_t       buflen,
	uint32_t     tot,
	uintptr_t   *frames)
{
	size_t l = 0;

	for (uint32_t i = 0; i < tot; i++) {
		l += scnprintf(buf + l, buflen - l, "%lx\n",
		    frames[i] - vm_kernel_stext);
	}
	l += telemetry_backtrace_add_kernel(buf + l, buflen - l);
	telemetry_backtrace_add_kexts(buf + l, buflen - l, frames, tot);
}
