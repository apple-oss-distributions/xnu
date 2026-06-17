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
#include <kern/kern_stackshot.h>
#include <vm/vm_shared_region_xnu.h>
#include <vm/vm_ubc.h>

#include <pexpert/pexpert.h>

#include <vm/vm_kern_xnu.h>
#include <vm/vm_shared_region.h>
#include <vm/vm_protos_internal.h>

#include <kperf/callstack.h>
#include <kern/backtrace.h>
#include <kern/monotonic.h>

#include <sys/codesign.h>
#include <security/mac_mach_internal.h>

#include <sys/errno.h>
#include <sys/kdebug.h>
#include <uuid/uuid.h>
#include <kdp/kdp_dyld.h>

#include <os/base.h>
#include <string.h>
#include <libkern/OSAtomic.h>
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

extern void proc_getexecutableuuid(proc_t p, unsigned char *uuidbuf, unsigned long size);
extern task_t proc_get_task_raw(proc_t proc);

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
static void _telemetry_set_ast_pmi(bool interrupted_user);
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

// The default size of the buffer used for microstackshots (16KiB).
#define TELEMETRY_DEFAULT_BUFFER_SIZE   (16 << 10)
// The maximum size of the buffer used for microstackshots (10MiB).
#define TELEMETRY_MAX_BUFFER_SIZE       (10 << 20)
// User space gets some leeway to collect data after notification (4KiB).
#define TELEMETRY_DEFAULT_NOTIFY_LEEWAY (4 << 10)
// Maximum non-shared cache UUIDs to include for symbolication.
#define TELEMETRY_MAX_UUID_COUNT        (128)

uint64_t microstackshot_pmi_period = 0;
cpc_slot_t microstackshot_pmi_counter = 0;

bool telemetry_sample_pmis = false;

/**
 * @abstract the trigger of microstackshot samples
 */
__enum_closed_decl(telemetry_source_t, uint8_t, {
	TMSRC_NONE = 0,
	TMSRC_UNKNOWN,
	TMSRC_TIME,
	TMSRC_INSTRUCTIONS,
	TMSRC_CYCLES,
	TMSRC_VM_FAULTS,
	TMSRC_PAGE_GRABS,
});

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
	telemetry_source_t tm_source;
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
#define TELEMETRY_MIN_PMI_PERIOD (10 * 1000 * 1000)

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

#if CONFIG_CPU_COUNTERS
cpc_cyclic_t microstackshot_cpc_cyclic = NULL;

static void
_telemetry_cyclic_handler(
	struct cpc_cyclic_info * __unused info,
	uint64_t __unused count,
	uint64_t __unused extra_count,
	uintptr_t __unused pc,
	cpc_call_source_t source,
	cpc_call_flags_t __unused flags)
{
	thread_t thread = current_thread();
	if (get_threadtask(thread) == kernel_task) {
		_telemetry_take_sample_kernel(thread, kPMIRecord);
	} else {
		_telemetry_set_ast_pmi(source == CPC_CS_USER);
	}
}

#endif /* HAS_PMI_MICROSTACKSHOTS */

int
telemetry_pmi_setup(telemetry_pmi_t pmi_ctr, uint64_t period)
{
#if HAS_PMI_MICROSTACKSHOTS
	telemetry_source_t source = TMSRC_NONE;
	int error = 0;
	const char *name = "?";

	if (!cpc_cpmu_supported) {
		return ENOTSUP;
	}

	if (pmi_ctr != TELEMETRY_PMI_NONE && (period < TELEMETRY_MIN_PMI_PERIOD || period > cpc_hw_max_period(CPC_HW_CPMU))) {
		return EINVAL;
	}

	TELEMETRY_PMI_LOCK();

	switch (pmi_ctr) {
	case TELEMETRY_PMI_NONE:
		if (!telemetry_sample_pmis) {
			error = 1;
			goto out;
		}

		telemetry_sample_pmis = false;
		printf("telemetry: disabling ustackshot on PMI\n");
		cpc_cyclic_cancel(microstackshot_cpc_cyclic);
		microstackshot_pmi_counter = 0;
		microstackshot_pmi_period = 0;
		cpc_cyclic_destroy(microstackshot_cpc_cyclic);
		microstackshot_cpc_cyclic = NULL;
		int intrs_en = ml_set_interrupts_enabled(FALSE);
		lck_spin_lock(&telemetry_metadata_lck);
		telemetry_metadata.tm_period = 0;
		telemetry_metadata.tm_source = TMSRC_NONE;
		lck_spin_unlock(&telemetry_metadata_lck);
		ml_set_interrupts_enabled(intrs_en);
		goto out;

	case TELEMETRY_PMI_INSTRS:
		microstackshot_pmi_counter = cpc_fixed_event_slot(CPC_HW_CPMU, CPC_FEVT_INSTRUCTIONS);
		name = "instructions";
		source = TMSRC_INSTRUCTIONS;
		break;

	case TELEMETRY_PMI_CYCLES:
		microstackshot_pmi_counter = cpc_fixed_event_slot(CPC_HW_CPMU, CPC_FEVT_CYCLES);
		name = "cycles";
		source = TMSRC_CYCLES;
		break;

	default:
		error = 1;
		goto out;
	}

	if (microstackshot_cpc_cyclic) {
		cpc_cyclic_cancel(microstackshot_cpc_cyclic);
		cpc_cyclic_destroy(microstackshot_cpc_cyclic);
		microstackshot_cpc_cyclic = NULL;
	}

	telemetry_sample_pmis = true;

	microstackshot_pmi_period = period;
	struct cpc_cyclic_info info = {
		.cci_func = _telemetry_cyclic_handler,
		.cci_slot = microstackshot_pmi_counter,
		.cci_period = microstackshot_pmi_period,
	};
	microstackshot_cpc_cyclic = cpc_cyclic_alloc(CPC_HW_CPMU, &info);
	if (!microstackshot_cpc_cyclic) {
		panic("telemetry: failed to allocate microstackshot PMI cyclic");
	}
	cpc_cyclic_activate(microstackshot_cpc_cyclic);
	printf("telemetry: microstackshot every %llu %s\n", microstackshot_pmi_period,
	    name);
	int intrs_en = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(&telemetry_metadata_lck);
	telemetry_metadata.tm_period = period;
	telemetry_metadata.tm_source = source;
	telemetry_metadata.tm_generation += 1;
	lck_spin_unlock(&telemetry_metadata_lck);
	ml_set_interrupts_enabled(intrs_en);

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
_telemetry_set_ast_pmi(bool interrupted_userspace)
{
	telemetry_ast_t reason = TELEMETRY_AST_PMI;
	thread_t thread = current_thread();

	/*
	 * PMI handler was called but microstackshot expected sampling to be
	 * disabled; log it for telemetry and ignore the sample.
	 */
	if (!telemetry_sample_pmis) {
		os_atomic_inc(&telemetry_metadata.tm_samples_skipped, relaxed);
		return;
	}

	reason |= (interrupted_userspace ? TELEMETRY_AST_USER : TELEMETRY_AST_KERNEL);
	act_set_telemetry_ast(thread, reason);
}

static void
_telemetry_kernel_notify(void * __unused p1, void * __unused p2)
{
	_telemetry_notify_user(TELEMETRY_NOTICE_KERNEL_MICROSTACKSHOT);
}

#endif /* HAS_PMI_MICROSTACKSHOTS */

void
telemetry_handle_ast(thread_t thread, telemetry_ast_t reasons)
{
	assert(reasons != 0);

	uint32_t record_type = 0;
	if (reasons & TELEMETRY_AST_IO) {
		record_type |= kIORecord;
	}
	if (reasons & TELEMETRY_AST_VM_FAULT) {
		record_type |= kVMFaultRecord;
	}
	if (reasons & TELEMETRY_AST_PAGE_GRAB) {
		record_type |= kPageGrabRecord;
	}
	if (reasons & (TELEMETRY_AST_USER | TELEMETRY_AST_KERNEL)) {
		record_type |= (reasons & TELEMETRY_AST_PMI) ? kPMIRecord : kInterruptRecord;
	}

	if ((reasons & TELEMETRY_AST_MACF) != 0) {
		record_type |= kMACFRecord;
	}

	enum micro_snapshot_flags user_telemetry = (reasons & TELEMETRY_AST_USER) ? kUserMode : 0;
	enum micro_snapshot_flags microsnapshot_flags = record_type | user_telemetry;

	if ((reasons & TELEMETRY_AST_MACF) != 0) {
		telemetry_macf_take_sample(thread, microsnapshot_flags);
	}

	if ((reasons & (TELEMETRY_AST_PMI | TELEMETRY_AST_IO | TELEMETRY_AST_VM_FAULT | TELEMETRY_AST_PAGE_GRAB)) != 0) {
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
	uint64_t tks_pagein_count;
	uint64_t tks_fault_count;
	uint64_t tks_cow_fault_count;

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
	uint8_t cpu = (uint8_t)cpu_number();
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
		.tks_pagein_count = counter_load(&kernel_task->pageins),
		.tks_fault_count = counter_load(&kernel_task->faults),
		.tks_cow_fault_count = counter_load(&kernel_task->cow_faults),
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
	struct microstackshot_task tkse_task_snap;
	struct microstackshot_thread tkse_thread_snap;
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
	snaps->tkse_task_snap = (struct microstackshot_task){
		.mst_magic = STACKSHOT_TASK_SNAPSHOT_MAGIC,
		.mst_stackshot_flags_trunc = kKernel64_p,
		.mst_stackshot_flags = kKernel64_p,
		.mst_pid = 0,
		.mst_task_uniqueid = 0,
		.mst_system_term_mach_time = sample->tks_system_time_in_terminated_threads,
		/*
		 * This cannot be queried in the ledger while running in interrupt context.
		 */
		.mst_page_count = get_task_phys_footprint(kernel_task) / PAGE_SIZE,
		.mst_fault_count = sample->tks_fault_count,
		.mst_pagein_count = sample->tks_pagein_count,
		.mst_cow_fault_count = sample->tks_cow_fault_count,
		.mst_proc_comm_name = "kernel_task",
		.mst_was_throttled = 0,
		.mst_did_throttle = 0,
		.mst_resource_coal_id = coalition_id(kernel_task->coalition[COALITION_TYPE_RESOURCE]),
		.mst_on_behalf_origin_pid = -1,
		.mst_on_behalf_proximate_pid = -1,
		.mst_latency_qos = LATENCY_QOS_TIER_UNSPECIFIED,
		.mst_metadata = {
			.mstm_telemetry_source = sample->tks_telemetry_source,
			.mstm_telemetry_generation = sample->tks_telemetry_generation,
			.mstm_telemetry_period = sample->tks_telemetry_period,
			.mstm_serial_number = sample->tks_serial_number,
			.mstm_telemetry_skipped = sample->tks_telemetry_skipped,
		},
	};
	snaps->tkse_thread_snap = (struct microstackshot_thread){
		.msth_magic = STACKSHOT_THREAD_SNAPSHOT_MAGIC,
		.msth_stackshot_flags = kKernel64_p,
		.msth_kern_frame_count = sample->tks_call_stack_size / sizeof(uintptr_t),
		.msth_wait_event = 0,
		.msth_continuation = 0,
		.msth_thread_id = sample->tks_thread_id,
		.msth_system_mach_time = sample->tks_system_time,
		.msth_state = sample->tks_thread_state,
		.msth_base_priority = sample->tks_base_pri,
		.msth_sched_priority = sample->tks_sched_pri,
		.msth_io_tier = sample->tks_io_tier,
	};
	memset(snaps->tkse_thread_snap.msth_name, 0, sizeof(snaps->tkse_thread_snap.msth_name));
	strlcpy(snaps->tkse_thread_snap.msth_name,
	    sample->tks_thread_name,
	    sizeof(snaps->tkse_thread_snap.msth_name));
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
		.include_metadata = flags & (kPMIRecord | kVMFaultRecord | kPageGrabRecord),
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
	struct microstackshot_task *tsnap,
	const struct telemetry_target *target)
{
	struct task *task = get_threadtask(target->thread);
	struct proc *p = get_bsdtask_info(task);

	tsnap->mst_magic = STACKSHOT_TASK_SNAPSHOT_MAGIC;
	tsnap->mst_pid = proc_pid(p);
	tsnap->mst_task_uniqueid = proc_uniqueid(p);
	struct recount_times_mach times = recount_task_terminated_times(task);
	tsnap->mst_user_term_mach_time = times.rtm_user;
	tsnap->mst_system_term_mach_time = times.rtm_system;
	tsnap->mst_suspend_count = task->suspend_count;
	tsnap->mst_page_count = (typeof(tsnap->mst_page_count))(get_task_phys_footprint(task) / PAGE_SIZE);
	tsnap->mst_fault_count = counter_load(&task->faults);
	tsnap->mst_pagein_count = counter_load(&task->pageins);
	tsnap->mst_cow_fault_count = counter_load(&task->cow_faults);
	/*
	 * The throttling counters are maintained as 64-bit counters in the proc
	 * structure. However, we reserve 32-bits (each) for them in
	 * `struct microstackshot_task` struct to save space and since we do not
	 * expect them to overflow 32-bits.
	 */
	tsnap->mst_was_throttled = (uint32_t)proc_was_throttled(p);
	tsnap->mst_did_throttle = (uint32_t)proc_did_throttle(p);

#if CONFIG_COALITIONS
	coalition_t rsrc_coal = task->coalition[COALITION_TYPE_RESOURCE];
	tsnap->mst_resource_coal_id = rsrc_coal ? coalition_id(rsrc_coal) : 0;

	pid_t origin_pid = -1, proximate_pid = -1;
	(void)thread_get_voucher_origin_proximate_pid(target->thread, &origin_pid, &proximate_pid);
	tsnap->mst_on_behalf_proximate_pid = proximate_pid;
	tsnap->mst_on_behalf_origin_pid = origin_pid;
#endif /* CONFIG_COALITIONS */

	uint64_t ss_flags = kcdata_get_task_ss_flags(task, false);
	tsnap->mst_stackshot_flags = ss_flags;
	tsnap->mst_stackshot_flags_trunc = (uint32_t)ss_flags;
	tsnap->mst_energy_nj = recount_task_energy_nj(task);

	int64_t pages_grabbed = 0;
	ledger_get_balance(task->ledger, task_ledgers.pages_grabbed, 0, &pages_grabbed);
	tsnap->mst_page_grab_count = pages_grabbed;

	int64_t pages_grabbed_iopl = 0;
	ledger_get_balance(task->ledger, task_ledgers.pages_grabbed_iopl, 0, &pages_grabbed_iopl);
	int64_t pages_grabbed_upl = 0;
	ledger_get_balance(task->ledger, task_ledgers.pages_grabbed_upl, 0, &pages_grabbed_upl);
	tsnap->mst_iopl_upl_page_grab_count = pages_grabbed_iopl + pages_grabbed_upl;

	tsnap->mst_latency_qos = task_grab_latency_qos(task);

	strlcpy(tsnap->mst_proc_comm_name, proc_name_address(p), sizeof(tsnap->mst_proc_comm_name));
	const char *longname = proc_longname_address(p);
	if (longname[0] != '\0') {
		strlcpy((char *)tsnap->mst_proc_name_extra, &longname[16], sizeof(tsnap->mst_proc_name_extra));
	}
	if (target->include_metadata) {
		enum micro_snapshot_flags mss_flags = target->microsnapshot_flags;

		telemetry_source_t source = TMSRC_UNKNOWN;
		if (mss_flags & kPMIRecord) {
			source = telemetry_metadata.tm_source;
#if CONFIG_MEMORY_MICROSTACKSHOT
		} else if (mss_flags & kVMFaultRecord) {
			source = TMSRC_VM_FAULTS;
		} else if (mss_flags & kPageGrabRecord) {
			source = TMSRC_PAGE_GRABS;
#endif /* CONFIG_MEMORY_MICROSTACKSHOT */
		}

		uint64_t period = 0;
		switch (source) {
#if CONFIG_MEMORY_MICROSTACKSHOT
		case TMSRC_VM_FAULTS:
			period = telemetry_vm_fault_period;
			break;
		case TMSRC_PAGE_GRABS:
			period = telemetry_page_grab_period;
			break;
#endif /* CONFIG_MEMORY_MICROSTACKSHOT */
		default:
			period = telemetry_metadata.tm_period;
			break;
		}

		tsnap->mst_metadata.mstm_telemetry_source = source;
		tsnap->mst_metadata.mstm_telemetry_generation = telemetry_metadata.tm_generation;
		tsnap->mst_metadata.mstm_telemetry_period = period;
		tsnap->mst_metadata.mstm_serial_number = os_atomic_inc(&telemetry_metadata.tm_samples_recorded, relaxed);
		tsnap->mst_metadata.mstm_telemetry_skipped = telemetry_metadata.tm_samples_skipped;
	}
	if (task->task_shared_region_slide != -1) {
		tsnap->mst_shared_cache_slide = task->task_shared_region_slide;
		bcopy(task->task_shared_region_uuid, tsnap->mst_shared_cache_identifier,
		    sizeof(task->task_shared_region_uuid));
	}
}

static void
_write_thread_snapshot(struct microstackshot_thread *thsnap, const struct telemetry_target *target)
{
	struct thread *thread = target->thread;

	thsnap->msth_magic = STACKSHOT_THREAD_SNAPSHOT_MAGIC;
	thsnap->msth_thread_id = thread_tid(thread);
	thsnap->msth_state = thread->state;
	thsnap->msth_base_priority = thread->base_pri;
	thsnap->msth_sched_priority = thread->sched_pri;
	thsnap->msth_sched_flags = thread->sched_flags;
	thsnap->msth_effective_qos = thread->effective_policy.thep_qos;
	thsnap->msth_requested_qos = thread->requested_policy.thrp_qos;
	thsnap->msth_requested_qos_override = MAX(thread->requested_policy.thrp_qos_override,
	    thread->requested_policy.thrp_qos_workq_override);
	thsnap->msth_user_frame_count = target->frames_count;
	static_assert(MAXTHREADNAMESIZE <= STACKSHOT_MAX_THREAD_NAME_SIZE);
	thread_get_thread_name(thread, thsnap->msth_name);
	thsnap->msth_async_index = target->async_start_index;

#if CONFIG_MEMORY_MICROSTACKSHOT
	if (target->microsnapshot_flags & kVMFaultRecord) {
		thsnap->msth_fault_va = thread->t_vm_fault_info.tvfi_va;
		thsnap->msth_fault_type = thread->t_vm_fault_info.tvfi_type;
		thsnap->msth_fault_flags = thread->t_vm_fault_info.tvfi_flags;
		memset(&thread->t_vm_fault_info, 0, sizeof(thread->t_vm_fault_info));
	}

	if (target->microsnapshot_flags & kPageGrabRecord) {
		thsnap->msth_grab_vm_tag = thread->t_page_grab_info.tpgi_tag;
		thsnap->msth_grab_iopl_count = thread->t_page_grab_info.tpgi_iopl_count;
		thsnap->msth_grab_upl_count = thread->t_page_grab_info.tpgi_upl_count;
		memset(&thread->t_page_grab_info, 0, sizeof(thread->t_page_grab_info));
	}
#endif /* CONFIG_MEMORY_MICROSTACKSHOT */

	thsnap->msth_stackshot_flags |= kStacksPCOnly;
	if (proc_get_effective_thread_policy(thread, TASK_POLICY_DARWIN_BG)) {
		thsnap->msth_stackshot_flags |= kThreadDarwinBG;
	}
	if (target->user64_regs) {
		thsnap->msth_stackshot_flags |= kUser64_p;
	}

	boolean_t interrupt_state = ml_set_interrupts_enabled(FALSE);
	struct recount_times_mach times = recount_current_thread_times();
	ml_set_interrupts_enabled(interrupt_state);
	thsnap->msth_user_mach_time = times.rtm_user;
	thsnap->msth_system_mach_time = times.rtm_system;
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
_telemetry_sample_uuids(task_t task, unsigned int extra_elements)
{
	bool const user64_va = task_has_64Bit_addr(task);
	uint32_t uuid_info_count_unsafe = 0;
	mach_vm_address_t uuid_info_addr = 0;
	uint32_t uuid_info_size = 0;
	if (user64_va) {
		uuid_info_size = sizeof(struct user64_dyld_uuid_info);
		struct user64_dyld_all_image_infos task_image_infos;
		if (copyin(task->all_image_info_addr, &task_image_infos, sizeof(task_image_infos)) == 0) {
			uuid_info_count_unsafe = (uint32_t)task_image_infos.uuidArrayCount;
			uuid_info_addr = task_image_infos.uuidArray;
		}
	} else {
		uuid_info_size = sizeof(struct user32_dyld_uuid_info);
		struct user32_dyld_all_image_infos task_image_infos;
		if (copyin(task->all_image_info_addr, &task_image_infos, sizeof(task_image_infos)) == 0) {
			uuid_info_count_unsafe = task_image_infos.uuidArrayCount;
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
	unsigned int uuid_info_count = MIN(uuid_info_count_unsafe, TELEMETRY_MAX_UUID_COUNT);
	if (uuid_info_count == 0) {
		return (struct _telemetry_uuids){};
	}
	uint32_t copyin_size = uuid_info_count * uuid_info_size;
	uint32_t alloc_size = (uuid_info_count + extra_elements) * uuid_info_size;
	char *uuid_info_array = kalloc_data(alloc_size, Z_WAITOK);
	if (uuid_info_array == NULL) {
		return (struct _telemetry_uuids){
			       .error = ENOMEM,
		};
	}

	/*
	 * Copy in the UUID info array.
	 */
	if (copyin(uuid_info_addr, uuid_info_array, copyin_size) != 0) {
		/*
		 * Don't report this as an error with the sample to avoid transient
		 * dyld operations from impacting sample collection.
		 */
		kfree_data(uuid_info_array, alloc_size);
		return (struct _telemetry_uuids){};
	}

	return (struct _telemetry_uuids){
		       .uuid_info = uuid_info_array,
		       .uuid_info_count = uuid_info_count,
		       .uuid_info_size = alloc_size,
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
	buf->current_position += size;
	assert3u(buf->current_position, <=, buf->size);
	memset(alloc, 0, size);
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

	struct _telemetry_uuids uuids = _telemetry_sample_uuids(task, 0);

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
	 * any page faults during execution will not cause another AST_TELEMETRY
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

		struct microstackshot_task *tsnap = _telemetry_buffer_alloc(current_buffer, sizeof(*tsnap));
		_write_task_snapshot(tsnap, target);

		if (uuids.uuid_info_size > 0) {
			void *uuid_info_buf = _telemetry_buffer_alloc(current_buffer, uuids.uuid_info_size);
			memcpy(uuid_info_buf, uuids.uuid_info, uuids.uuid_info_size);
			tsnap->mst_loadinfo_count = uuids.uuid_info_count;
		}

		struct microstackshot_thread *thsnap = _telemetry_buffer_alloc(current_buffer, sizeof(*thsnap));
		_write_thread_snapshot(thsnap, target);

		if (dqserial_valid) {
			thsnap->msth_stackshot_flags |= kHasDispatchSerial;
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

	act_set_telemetry_ast(thread, TELEMETRY_AST_MACF);
	return 0;
}
#endif /* CONFIG_MACF */

#pragma mark - Page-in Telemetry

#if CONFIG_THREAD_GROUPS

/*
 * Global data used by the page-in telemetry subsystem.
 */
struct _telemetry_pagein_globals {
	/*
	 * The size of the buffer to create to hold page-in telemetry.
	 *
	 * Clamped to `TELEMETRY_PAGEIN_BUFFER_SIZE_MAX`.
	 */
	size_t tp_buffer_size;
	/*
	 * Any flags that affect collection.
	 */
	telemetry_pagein_flags_t tp_flags;
	/*
	 * The ID of the thread group that is currently collecting page-in
	 * telemetry.
	 *
	 * Any threads with their home thread group as this ID are eligible.
	 */
	uint64_t tp_thread_group_id;

	/*
	 * Once page-in telemetry has started, the buffer that holds the page-in
	 * data.
	 */
	struct telemetry_pagein *tp_buffer;
	/*
	 * The allocated buffer size.
	 */
	size_t tp_buffer_allocated_size;
	/*
	 * The number of page-in telemetry elements requested to be counted.
	 *
	 * This can be larger than the capacity.
	 */
	unsigned int _Atomic     tp_count;
	/*
	 * The number of entries the buffer can hold.
	 */
	unsigned int             tp_capacity;
	/*
	 * The `mach_continuous_time()` when page-in telemetry started.
	 */
	uint64_t                 tp_start_mct;
};

/*
 * A mutex to protect access to page-in telemetry globals.
 */
LCK_MTX_DECLARE(_telemetry_pagein_mtx, &telemetry_lck_grp);
/*
 * The globals protected by the `_telemetry_pagein_mtx` lock.
 */
struct _telemetry_pagein_globals _pagein_globals = { 0 };

#define TELEMETRY_PAGEIN_BUFFER_MAX_SIZE (5 << 20)

int
telemetry_pagein_setup(
	uint64_t buffer_size,
	telemetry_pagein_flags_t flags)
{
	if (buffer_size > TELEMETRY_PAGEIN_BUFFER_MAX_SIZE) {
		buffer_size = TELEMETRY_PAGEIN_BUFFER_MAX_SIZE;
	}
	if (buffer_size > 0 && buffer_size < sizeof(struct telemetry_pagein)) {
		return EINVAL;
	}

	lck_mtx_lock(&_telemetry_pagein_mtx);
	/*
	 * Consider making this a once-only configuration on release kernels?
	 */
	_pagein_globals.tp_buffer_size = buffer_size;
	_pagein_globals.tp_flags = flags;
	lck_mtx_unlock(&_telemetry_pagein_mtx);
	return 0;
}

void
telemetry_pagein_start(void *coal)
{
	if (coal == COALITION_NULL) {
		return;
	}
	struct thread_group *tg = coalition_get_thread_group(coal);
	if (!tg) {
		return;
	}
	uint64_t tgid = thread_group_get_id(tg);

	lck_mtx_lock(&_telemetry_pagein_mtx);
	uint64_t buffer_size = _pagein_globals.tp_buffer_size;
	lck_mtx_unlock(&_telemetry_pagein_mtx);

	if (buffer_size == 0) {
		return;
	}

	struct telemetry_pagein *buf = kalloc_data_tag(
		buffer_size,
		Z_WAITOK | Z_ZERO,
		VM_KERN_MEMORY_DIAG);
	if (!buf) {
		printf("telemetry: failed to allocate %lld byte buffer for page-ins", buffer_size);
		return;
	}

	bool assigned = false;

	lck_mtx_lock(&_telemetry_pagein_mtx);
	if (_pagein_globals.tp_buffer == NULL) {
		os_atomic_store(&_pagein_globals.tp_count, 0, relaxed);
		_pagein_globals.tp_buffer = buf;
		assigned = true;
		_pagein_globals.tp_buffer_allocated_size = buffer_size;
		_pagein_globals.tp_capacity = _pagein_globals.tp_buffer_size / sizeof(struct telemetry_pagein);
		_pagein_globals.tp_start_mct = mach_continuous_time();
		os_atomic_store(&_pagein_globals.tp_thread_group_id, tgid, release);
	}
	lck_mtx_unlock(&_telemetry_pagein_mtx);

	if (!assigned) {
		kfree_data(buf, buffer_size);
	}
}

static bool
_pagein_telemetry_active(uint64_t *trace_tgid_out)
{
	uint64_t tgid = _pagein_globals.tp_thread_group_id;
	if (__probable(tgid == 0)) {
		return false;
	}
	thread_t curth = current_thread();
	struct thread_group *curtg = thread_group_get_home_group(curth);
	*trace_tgid_out = tgid;
	return curtg && thread_group_get_id(curtg) == tgid;
}

static bool
_pagein_get_emit_index(unsigned int *index_out)
{
	unsigned int reserved_index = os_atomic_inc_orig(&_pagein_globals.tp_count, relaxed);
	/*
	 * Best effort to avoid expense, this is double-checked under the lock later.
	 */
	if (reserved_index >= _pagein_globals.tp_capacity) {
		return false;
	}
	*index_out = reserved_index;
	return true;
}

static void
_pagein_emit_internal(
	unsigned int index,
	uint64_t tgid,
	struct vnode *vp,
	off_t file_offset)
{
	extern int vnode_get_ids(struct vnode *vp, uint64_t *fsid_out, uint64_t *fsobj_id_out);
	uint64_t fsid, fsobj_id;
	int error = vnode_get_ids(vp, &fsid, &fsobj_id);
	if (error != 0) {
		return;
	}

	lck_mtx_lock(&_telemetry_pagein_mtx);
	bool const correct_tgid = tgid == _pagein_globals.tp_thread_group_id;
	bool const has_space = _pagein_globals.tp_capacity > index;
	if (correct_tgid && has_space) {
		_pagein_globals.tp_buffer[index] = (struct telemetry_pagein){
			.tp_fsid = fsid,
			.tp_fsobj_id = fsobj_id,
			.tp_file_offset = file_offset,
		};
	}
	lck_mtx_unlock(&_telemetry_pagein_mtx);
}

bool
telemetry_pagein_should_emit(struct telemetry_pagein_token *token)
{
	memory_object_t pager = token->tpit_pagerv_in;
	if (!memory_object_is_vnode_pager(pager)) {
		return false;
	}
	if (__probable(!_pagein_telemetry_active(&token->tpit_tgid_out))) {
		return false;
	}
	vnode_pager_reference(pager);
	return true;
}

void
telemetry_pagein_emit(struct telemetry_pagein_token *token)
{
	assert(token->tpit_tgid_out != 0);

	memory_object_t pager = token->tpit_pagerv_in;
	struct vnode *vp = vnode_pager_lookup_vnode(pager);
	if (vp != NULL) {
		unsigned int emit_index = 0;
		uint64_t const tgid = token->tpit_tgid_out;
		if (_pagein_get_emit_index(&emit_index)) {
			_pagein_emit_internal(emit_index, tgid, vp, token->tpit_file_offset_in);
		}
	}
	vnode_pager_deallocate(pager);
}

int
telemetry_pagein_read(
	unsigned int *size_out,
	user_addr_t destination,
	size_t destination_size)
{
	if (destination == USER_ADDR_NULL || destination_size == 0) {
		/*
		 * Handle user space requesting the size to allocate; more events
		 * could come in by the time this is called again.
		 */
		uint64_t count = os_atomic_load(&_pagein_globals.tp_count, relaxed);
		*size_out = sizeof(struct telemetry_pagein_header) + sizeof(struct telemetry_pagein) * count;
		return 0;
	}

	struct telemetry_pagein_header hdr = {
		.tph_magic = TELEMETRY_PAGEIN_MAGIC,
		.tph_version = 1,
	};

	if (destination_size < sizeof(hdr)) {
		return ENOSPC;
	}

	struct telemetry_pagein *buf = NULL;
	uint64_t count = 0;
	uint64_t capacity = 0;
	size_t buffer_size = 0;

	lck_mtx_lock(&_telemetry_pagein_mtx);
	_pagein_globals.tp_thread_group_id = 0;

	buf = _pagein_globals.tp_buffer;
	_pagein_globals.tp_buffer = NULL;

	count = os_atomic_load(&_pagein_globals.tp_count, relaxed);
	os_atomic_store(&_pagein_globals.tp_count, 0, relaxed);

	capacity = _pagein_globals.tp_capacity;
	_pagein_globals.tp_capacity = 0;

	buffer_size = _pagein_globals.tp_buffer_allocated_size;
	_pagein_globals.tp_buffer_allocated_size = 0;

	hdr.tph_duration_mct = mach_continuous_time() - _pagein_globals.tp_start_mct;
	_pagein_globals.tp_start_mct = 0;

	hdr.tph_pagein_count = count;
	hdr.tph_flags = _pagein_globals.tp_flags;
	lck_mtx_unlock(&_telemetry_pagein_mtx);

	int error = copyout(&hdr, destination, sizeof(hdr));
	if (error) {
		goto out;
	}
	destination += sizeof(hdr);
	destination_size -= sizeof(hdr);

	unsigned int copyout_count = MIN(count, capacity);
	size_t pageins_size = MIN(destination_size, copyout_count * sizeof(struct telemetry_pagein));
	*size_out = sizeof(hdr) + pageins_size;
	if (pageins_size > 0) {
		error = copyout(buf, destination, pageins_size);
	}

out:
	kfree_data(buf, buffer_size);
	return error;
}

#else /* CONFIG_THREAD_GROUPS */

int
telemetry_pagein_setup(
	__unused uint64_t buffer_size,
	__unused telemetry_pagein_flags_t flags)
{
	return ENOTSUP;
}

void
telemetry_pagein_start(__unused void *coal)
{
}

bool
telemetry_pagein_should_emit(__unused struct telemetry_pagein_token *token)
{
	return false;
}

void
telemetry_pagein_emit(__unused struct telemetry_pagein_token *token)
{
}

int
telemetry_pagein_read(
	__unused unsigned int *count_out,
	__unused user_addr_t destination,
	__unused size_t destination_size)
{
	return ENOTSUP;
}

#endif /* !CONFIG_THREAD_GROUPS */

#if CONFIG_MEMORY_MICROSTACKSHOT
struct telemetry_memory_usage_cpu PERCPU_DATA(telemetry_memory_usage_percpu);

TUNABLE_WRITEABLE(uint64_t, telemetry_vm_fault_period, "telemetry_mss_fault_period", 0);
TUNABLE_WRITEABLE(uint64_t, telemetry_page_grab_period, "telemetry_mss_grab_period", 0);

int
telemetry_memory_usage_setup(uint64_t page_grab_period, uint64_t vm_fault_period)
{
	telemetry_page_grab_period = page_grab_period;
	telemetry_vm_fault_period = vm_fault_period;
	return 0;
}
#else /* CONFIG_MEMORY_MICROSTACKSHOT */
int
telemetry_memory_usage_setup(uint64_t __unused page_grab_period, uint64_t __unused vm_fault_period)
{
	return ENOTSUP;
}
#endif /* !CONFIG_MEMORY_MICROSTACKSHOT */

#pragma mark - Trap Telemetry Utilities

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


CA_EVENT(os_fault_with_ustack,
    CA_STATIC_STRING(CA_PROCNAME_LEN), proc_name,
    CA_STATIC_STRING(CA_SIGNINGID_MAX_LEN), signing_id,
    CA_INT, namespace,
    CA_INT, reason_code,
    CA_STATIC_STRING(CA_UUID_LEN), shared_cache_uuid,
    CA_STATIC_STRING(CA_UUID_LEN), main_exec_uuid,
    CA_STATIC_STRING(CA_UUID_LEN), frame1UUID,
    CA_INT, frame1offset,
    CA_STATIC_STRING(CA_UUID_LEN), frame2UUID,
    CA_INT, frame2offset,
    CA_STATIC_STRING(CA_UUID_LEN), frame3UUID,
    CA_INT, frame3offset,
    CA_STATIC_STRING(CA_UUID_LEN), frame4UUID,
    CA_INT, frame4offset);



static int
compare_uuids32(const void *a, const void *b)
{
	uint32_t addr_a = ((const struct user32_dyld_uuid_info*)a)->imageLoadAddress;
	uint32_t addr_b = ((const struct user32_dyld_uuid_info*)b)->imageLoadAddress;
	if (addr_a < addr_b) {
		return -1;
	} else if (addr_a == addr_b) {
		return 0;
	} else {
		return 1;
	}
}

static int
compare_uuids64(const void *a, const void *b)
{
	uint64_t addr_a = ((const struct user64_dyld_uuid_info*)a)->imageLoadAddress;
	uint64_t addr_b = ((const struct user64_dyld_uuid_info*)b)->imageLoadAddress;
	if (addr_a < addr_b) {
		return -1;
	} else if (addr_a == addr_b) {
		return 0;
	} else {
		return 1;
	}
}

#define OS_FAULT_NUMFRAMES (4)

static uint64_t
sr_virt_base(struct vm_shared_region *sr)
{
	return sr == NULL ? 0 : sr->sr_base_address + sr->sr_first_mapping;
}

static size_t
_normalize_offset32(struct _telemetry_uuids uuids, uintptr_t addr, uuid_string_t uuid_out, struct vm_shared_region *sr)
{
	struct user32_dyld_uuid_info * elms = (struct user32_dyld_uuid_info*)uuids.uuid_info;
	struct user32_dyld_uuid_info *image = &elms[0];
	for (int img_i = 1; img_i < uuids.uuid_info_count; ++img_i) {
		if (elms[img_i].imageLoadAddress > addr) {
			break;
		}
		image = &elms[img_i];
	}
	if (addr < image->imageLoadAddress) {
		/* basic check if addr is not in the image
		 * it also covers cases when PC addr == 0
		 */
		return 0;
	}
	size_t res = addr - image->imageLoadAddress;
	if (sr && sr_virt_base(sr) == image->imageLoadAddress &&
	    res > sr->sr_size) {
		/* if shared cache and outside of range - return 0 */
		res = 0;
	} else {
		/* if shared cache - must be within range */
		uuid_unparse_upper(image->imageUUID, uuid_out);
	}
	return res;
}

static size_t
_normalize_offset64(struct _telemetry_uuids uuids, uintptr_t addr, uuid_string_t uuid_out, struct vm_shared_region *sr)
{
	struct user64_dyld_uuid_info * elms = (struct user64_dyld_uuid_info*)uuids.uuid_info;
	struct user64_dyld_uuid_info *image = &elms[0];
	for (int img_i = 1; img_i < uuids.uuid_info_count; ++img_i) {
		if (elms[img_i].imageLoadAddress > addr) {
			break;
		}
		image = &elms[img_i];
	}
	if (addr < image->imageLoadAddress) {
		/* basic check if addr is not in the image
		 * it also covers cases when PC addr == 0
		 */
		return 0;
	}
	size_t res = addr - image->imageLoadAddress;
	if (sr && sr_virt_base(sr) == image->imageLoadAddress &&
	    res > sr->sr_size) {
		/* if shared cache and outside of range - return 0 */
		res = 0;
	} else {
		/* if shared cache - must be within range */
		uuid_unparse_upper(image->imageUUID, uuid_out);
	}
	return res;
}

static inline void
_extend_uuids_with_shared_cache(
	struct _telemetry_uuids *uuids,
	bool is_64bit,
	struct vm_shared_region *shared_region)
{
	if (!shared_region) {
		return;
	}
	/* create an entry for shared cache in the images array, bc dyld doesn't keep it there */
	if (is_64bit) {
		struct user64_dyld_uuid_info * elms = (struct user64_dyld_uuid_info*)uuids->uuid_info;
		elms[uuids->uuid_info_count].imageLoadAddress = sr_virt_base(shared_region);
		memcpy(elms[uuids->uuid_info_count].imageUUID, shared_region->sr_uuid, sizeof(uuid_t));
	} else {
		struct user32_dyld_uuid_info * elms = (struct user32_dyld_uuid_info*)uuids->uuid_info;
		elms[uuids->uuid_info_count].imageLoadAddress = (uint32_t)sr_virt_base(shared_region);
		memcpy(elms[uuids->uuid_info_count].imageUUID, shared_region->sr_uuid, sizeof(uuid_t));
	}
	++uuids->uuid_info_count;
}


static struct _telemetry_uuids
_alloc_uuid_only_for_sc(task_t task)
{
	bool const user64_va = task_has_64Bit_addr(task);
	uint32_t uuid_info_size = 0;
	if (user64_va) {
		uuid_info_size = sizeof(struct user64_dyld_uuid_info);
	} else {
		uuid_info_size = sizeof(struct user32_dyld_uuid_info);
	}

	char *uuid_info_array = kalloc_data(uuid_info_size, Z_WAITOK);
	if (uuid_info_array == NULL) {
		return (struct _telemetry_uuids){
			       .error = ENOMEM,
		};
	}

	/* allocate space for shared cache but do not fill it up yet
	 * hence uuid_info_count == 0
	 */
	return (struct _telemetry_uuids){
		       .uuid_info = uuid_info_array,
		       .uuid_info_count = 0,
		       .uuid_info_size = uuid_info_size,
	};
}

extern const char *cs_identity_get(proc_t);

void
os_user_fault_send_ca_event(uint32_t reason_namespace, uint64_t reason_code)
{
	proc_t proc = current_proc();
	task_t task = current_task();
	bool platform_binary = csproc_get_platform_binary(current_proc()) != 0;
	ca_event_t ca_event = CA_EVENT_ALLOCATE_FLAGS(os_fault_with_ustack, Z_WAITOK | Z_ZERO);
	if (ca_event == NULL) {
		goto out;
	}

	CA_EVENT_TYPE(os_fault_with_ustack) * event = ca_event->data;
	struct _telemetry_uuids uuids = { };
	uuid_t uuid_parsed;
	struct vm_shared_region *shared_region = NULL;
	if (task->shared_region != NULL) {
		shared_region = task->shared_region;
		uuid_unparse_upper(shared_region->sr_uuid, event->shared_cache_uuid);
	}
	proc_getexecutableuuid(proc, uuid_parsed, sizeof(uuid_parsed));
	uuid_unparse_upper(uuid_parsed, event->main_exec_uuid);

	const char* signing_id =  platform_binary? cs_identity_get(current_proc()) : NULL;
	if (signing_id != NULL) {
		strlcpy(event->signing_id, signing_id, sizeof(event->signing_id));
	}
	event->namespace = reason_namespace;
	event->reason_code = reason_code;

	const char* proc_name = proc_name_address(proc);
	strlcpy(event->proc_name, proc_name, sizeof(event->proc_name));


	if (platform_binary) {
		/* sample uuids via dyld image info only for platform binaries */
		uuids = _telemetry_sample_uuids(task, 1);
	}

	if (uuids.uuid_info == NULL || uuids.uuid_info_count == 0) {
		uuids = _alloc_uuid_only_for_sc(task);
	}

	if (uuids.error != 0) {
		/* ignore telemetry */
		return;
	}

	assert(uuids.uuid_info != NULL);
	assert(uuids.uuid_info_size > 0);

	_extend_uuids_with_shared_cache(&uuids, task_has_64Bit_addr(task), shared_region);
	/* need to sort before we can start searching */
	size_t elm_size = task_has_64Bit_addr(task) ? sizeof(struct user64_dyld_uuid_info) : sizeof(struct user32_dyld_uuid_info);
	cmpfunc_t comparator = task_has_64Bit_addr(task) ? compare_uuids64 : compare_uuids32;
	qsort(uuids.uuid_info, uuids.uuid_info_count, elm_size, comparator);

	/* walk top 4 frames in the backtrace and find corresponding UUID of the image */
	uintptr_t user_frames[OS_FAULT_NUMFRAMES] = {};
	struct backtrace_user_info btinfo = BTUINFO_INIT;
	unsigned int frame_count = backtrace_user(user_frames, OS_FAULT_NUMFRAMES, NULL, &btinfo);
	assert(frame_count <= OS_FAULT_NUMFRAMES);
	if (btinfo.btui_error != 0) {
		goto out;
	}

	if (frame_count > 0) {
		event->frame1offset = task_has_64Bit_addr(task) ?
		    _normalize_offset64(uuids, user_frames[0], event->frame1UUID, shared_region):
		    _normalize_offset32(uuids, user_frames[0], event->frame1UUID, shared_region);
	} else {
#if __arm64__
		/* [arm64 only] fault path: if we failed to collect the backtrace - try to symbolicate PC at least */
		struct arm_saved_state *sstate = find_user_regs(current_thread());

		if (is_saved_state64(sstate)) {
			struct arm_saved_state64 *state = saved_state64(sstate);
			assert(task_has_64Bit_addr(task));
			event->frame1offset = _normalize_offset64(uuids, state->pc, event->frame1UUID, shared_region);
		} else {
			struct arm_saved_state32 *state = saved_state32(sstate);
			event->frame1offset = _normalize_offset32(uuids, state->pc, event->frame1UUID, shared_region);
		}
#endif /* #if __arm64__ */
	}

	if (frame_count > 1) {
		event->frame2offset = task_has_64Bit_addr(task) ?
		    _normalize_offset64(uuids, user_frames[1], event->frame2UUID, shared_region):
		    _normalize_offset32(uuids, user_frames[1], event->frame2UUID, shared_region);
	} else {
#if __arm64__
		/* [arm64 only] fault path: if we failed to collect the backtrace - try to symbolicate LR at least */
		struct arm_saved_state *sstate = find_user_regs(current_thread());

		if (is_saved_state64(sstate)) {
			struct arm_saved_state64 *state = saved_state64(sstate);
			assert(task_has_64Bit_addr(task));
			event->frame2offset = _normalize_offset64(uuids, state->lr, event->frame2UUID, shared_region);
		} else {
			struct arm_saved_state32 *state = saved_state32(sstate);
			event->frame2offset = _normalize_offset32(uuids, state->lr, event->frame2UUID, shared_region);
		}
#endif /* #if __arm64__ */
	}

	if (frame_count > 2) {
		event->frame3offset = task_has_64Bit_addr(task) ?
		    _normalize_offset64(uuids, user_frames[2], event->frame3UUID, shared_region):
		    _normalize_offset32(uuids, user_frames[2], event->frame3UUID, shared_region);
	}
	if (frame_count > 3) {
		event->frame4offset = task_has_64Bit_addr(task) ?
		    _normalize_offset64(uuids, user_frames[3], event->frame4UUID, shared_region):
		    _normalize_offset32(uuids, user_frames[3], event->frame4UUID, shared_region);
	}

	if (ca_event) {
		CA_EVENT_SEND(ca_event);
		ca_event = NULL; /* is consumed by send above */
	}

out:
	if (uuids.uuid_info != NULL) {
		kfree_data(uuids.uuid_info, uuids.uuid_info_size);
	}

	if (ca_event != NULL) {
		CA_EVENT_DEALLOCATE(ca_event);
	}
}
