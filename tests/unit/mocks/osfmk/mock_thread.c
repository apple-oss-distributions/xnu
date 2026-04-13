/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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

#include "mocks/std_safe.h"
#include "mocks/dt_proxy.h"
#include "mock_thread.h"
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/bsd/mock_proc.h"

#include "mocks/osfmk/fibers/fibers.h"
#include "mocks/osfmk/fibers/mutex.h"
#include "mocks/osfmk/fibers/condition.h"
#include "mocks/osfmk/fibers/rwlock.h"
#include "mocks/osfmk/fibers/random.h"
#include "mocks/osfmk/fibers/checker.h"

#include <arm/cpu_data_internal.h> // for cpu_data
#include <kern/thread.h>
#include <kern/lock_mtx.h>
#include <kern/lock_group.h>
#include <kern/compact_id.h>
#include <kern/task.h>
#include <kern/counter.h>
#include <vm/vm_object_xnu.h>
#include <ipc/ipc_space.h>
#include <sys/proc_ro.h>

#define UNDEFINED_MOCK \
	raw_printf("%s: WIP mock, this should not be called\n", __FUNCTION__); \
	print_current_backtrace();

/*
 * Unit tests that wants to use fibers must redefine this global with a value not 0.
 * The test executable should not do this directly, instead it should call macro UT_USE_FIBERS in its global scope.
 *
 * We use a weak global and not a macro that defines a constructor to avoid initialization code running before such constructor to run
 * with ut_mocks_use_fibers=0 before that the constructor change its value.
 * Switching from the pthread mocks to fibers is not supported, we must be consistent from the very beginning.
 */
int ut_mocks_use_fibers __attribute__((weak)) = 0;

/*
 * Unit tests that wants to use fibers with data race checking must redefine this global with a value not 0.
 * FIBERS_CHECKER=1 as env var will do the same job too.
 */
int ut_fibers_use_data_race_checker __attribute__((weak)) = 0;

/*
 * Unit tests can set this variable to force `lck_rw_lock_shared_to_exclusive` to fail.
 *
 * RANGELOCKINGTODO rdar://150846598 model when to return FALSE
 */
bool ut_mocks_lock_upgrade_fail = 0;

/*
 * This constructor is used to set the configuration variables of the fibers using env vars.
 * The main use case is fuzzing, unit tests should set the variables in the test function or
 * by calling the correspondig macros (UT_FIBERS_*, see mock_thread.h) in their global scope.
 */
__attribute__((constructor))
static void
initialize_fiber_settings(void)
{
	const char *debug_env = getenv("FIBERS_DEBUG");
	if (debug_env != NULL) {
		fibers_debug = atoi(debug_env);
	}

	const char *err_env = getenv("FIBERS_ABORT_ON_ERROR");
	if (err_env != NULL) {
		fibers_abort_on_error = atoi(err_env);
	}

	const char *verbose_env = getenv("FIBERS_LOG");
	if (verbose_env != NULL) {
		fibers_log_level = atoi(verbose_env);
	}

	const char *prob_env = getenv("FIBERS_MAY_YIELD_PROB");
	if (prob_env != NULL) {
		fibers_may_yield_probability = atoi(prob_env);
	}

	const char *checker_env = getenv("FIBERS_CHECK_RACES");
	if (checker_env != NULL) {
#ifndef __BUILDING_WITH_SANCOV_LOAD_STORES__
		raw_printf("==== Fibers data race checker disabled ====\n");
		raw_printf("You cannot enable the data race checker if the FIBERS_PREEMPTION=1 flag was to not used as make parameter.");
		return;
#else
		if (!ut_mocks_use_fibers) {
			raw_printf("==== Fibers data race checker disabled ====\n");
			raw_printf("You cannot enable the data race checker if the test is not using fibers (see UT_USE_FIBERS in the readme).");
			return;
		}
		ut_fibers_use_data_race_checker = atoi(checker_env);
		if (ut_fibers_use_data_race_checker) {
			raw_printf("==== Fibers data race checker enabled ====\n");
		} else {
			raw_printf("==== Fibers data race checker disabled ====\n");
		}
#endif // __BUILDING_WITH_SANCOV_LOAD_STORES__
	}
}

// --------------- proc and thread ------------------

struct proc;
typedef struct proc * proc_t;

extern void init_thread_from_template(thread_t thread);
extern void ctid_table_init(void);
extern void ctid_table_add(thread_t thread);
extern void ctid_table_remove(thread_t thread);
extern void thread_ro_create(task_t parent_task, thread_t th, thread_ro_t tro_tpl);
extern task_t proc_get_task_raw(proc_t proc);
extern void task_zone_init(void);
void cpu_data_startup_init(void);

extern struct compact_id_table ctid_table;
extern lck_grp_t thread_lck_grp;
extern size_t proc_struct_size;
extern proc_t kernproc;
extern cpu_data_entry_t CpuDataEntries[MAX_CPUS];
extern unsigned int real_ncpus;

// a pointer to this object is kept per thread in thread-local-storage
struct mock_thread {
	struct thread th;
	fiber_t fiber;
	struct mock_thread* wq_next;
	bool interrupts_disabled;
};

struct pthread_mock_event_table_entry {
	event_t ev;
	pthread_cond_t cond;
	// the condition variable is owned by the table and is initialized on the first use of the entry
	bool cond_inited;
};
#define PTHREAD_EVENTS_TABLE_SIZE 1000

struct mock_process_state {
	void *proctask; // buffer for proc and task
	struct proc *main_proc;
	struct task *main_task;
	struct cpu_data cpud;  // kept for backward compat with pthread path
	struct cpu_data **cpu_data_array;  // array of pointers to per-CPU data for fibers
	void *percpu_allocation;  // PAGE_SIZE aligned contiguous allocation for cleanup
	struct mock_thread *main_thread;
	uint64_t thread_unique_id;

	// pthread
	pthread_key_t tls_thread_key;
	bool interrupts_enabled;
	pthread_mutex_t events_mutex; // for all event condition variables
	struct pthread_mock_event_table_entry events[PTHREAD_EVENTS_TABLE_SIZE];
	// !pthread

	// fibers
	int interrupts_disabled;
	// !fibers
};

struct mock_process_state *get_proc_state(void);

struct cpu_data *
get_current_cpu_data(void)
{
	struct mock_process_state *s = get_proc_state();

	if (!ut_mocks_use_fibers) {
		return &s->cpud;
	}

	PT_QUIET; PT_ASSERT_TRUE(s->cpu_data_array != NULL, "cpu_data_array not initialized");
	return s->cpu_data_array[fibers_current->assigned_cpu];
}

struct cpu_data *
get_cpu_data(unsigned int cpu_id)
{
	struct mock_process_state *s = get_proc_state();

	if (!ut_mocks_use_fibers) {
		return &s->cpud;
	}

	PT_QUIET; PT_ASSERT_TRUE(s->cpu_data_array != NULL, "cpu_data_array not initialized");
	return s->cpu_data_array[cpu_id];
}

// see fibers.c
void
mock_thread_switch_cpu_context_out(void *mock_thread_ptr)
{
	struct mock_thread *mth = (struct mock_thread *)mock_thread_ptr;
	if (!mth) {
		return;
	}

	mth->th.machine.CpuDatap = NULL;
	mth->th.machine.pcpu_data_base_and_cpu_number = 0;
}

// see fibers.c
void
mock_thread_switch_cpu_context_in(void *mock_thread_ptr, unsigned int cpu_id)
{
	struct mock_thread *mth = (struct mock_thread *)mock_thread_ptr;
	if (!mth) {
		return;
	}

	mth->th.machine.CpuDatap = get_cpu_data(cpu_id);

	// Inline the entire calculation to avoid any function calls that might trigger preemption:
	// other_percpu_base(cpu_id) = (vm_offset_t)CpuDataEntries[cpu_id].cpu_data_vaddr - __PERCPU_ADDR(cpu_data)
	// ml_make_pcpu_base_and_cpu_number(base, cpu) = (base << 16) | cpu
	vm_offset_t base = (vm_offset_t)CpuDataEntries[cpu_id].cpu_data_vaddr - __PERCPU_ADDR(cpu_data);
	mth->th.machine.pcpu_data_base_and_cpu_number = (base << 16) | cpu_id;
}

static void
mock_destroy_thread(void *th_p)
{
	struct mock_thread *mth = (struct mock_thread *)th_p;
	// raw_printf("thread_t finished ctid=%u\n", mth->th.ctid);

	ctid_table_remove(&mth->th);

	machine_thread_destroy(&mth->th);

	free(mth->th.t_tro);
	free(mth);
}

static struct mock_thread *
mock_init_new_thread(struct mock_process_state* s, bool is_main_thread)
{
	struct mock_thread *new_mock_thread = calloc(1, sizeof(struct mock_thread));
	struct thread *new_thread = &new_mock_thread->th;

	if (ut_mocks_use_fibers) {
		new_mock_thread->fiber = fibers_current;
		fibers_current->extra = new_mock_thread;
		fibers_current->extra_cleanup_routine = &mock_destroy_thread;
	} else {
		pthread_setspecific(s->tls_thread_key, new_mock_thread);
	}

	static int mock_init_new_thread_first_call = 1;
	if (mock_init_new_thread_first_call) {
		mock_init_new_thread_first_call = 0;
		compact_id_table_init(&ctid_table);
		ctid_table_init();
	}

	init_thread_from_template(new_thread);

	// maybe call thread_create_internal() ?
	// machine is needed by _enable_preemption_write_count()
	machine_thread_create(new_thread, s->main_task, true);

	// initialize CpuDatap to point to the CPU this thread will run on
	if (ut_mocks_use_fibers) {
		// for fibers: set to current fiber's assigned CPU (main fiber is on CPU 0)
		unsigned int cpu_id = fibers_current ? fibers_current->assigned_cpu : 0;
		new_thread->machine.CpuDatap = get_cpu_data(cpu_id);
		// Inline the entire calculation to avoid function calls during initialization:
		// other_percpu_base(cpu_id) = (vm_offset_t)CpuDataEntries[cpu_id].cpu_data_vaddr - __PERCPU_ADDR(cpu_data)
		// ml_make_pcpu_base_and_cpu_number(base, cpu) = (base << 16) | cpu
		extern cpu_data_entry_t CpuDataEntries[MAX_CPUS];
		vm_offset_t base = (vm_offset_t)CpuDataEntries[cpu_id].cpu_data_vaddr - __PERCPU_ADDR(cpu_data);
		new_thread->machine.pcpu_data_base_and_cpu_number = (base << 16) | cpu_id;
	} else {
		// for pthreads: use the single CPU data
		new_thread->machine.CpuDatap = &s->cpud;
		new_thread->machine.pcpu_data_base_and_cpu_number = 0;
	}

	new_thread->thread_id = ++s->thread_unique_id;
	//new_thread->ctid = (uint32_t)new_thread->thread_id;
	ctid_table_add(new_thread);

	thread_lock_init(new_thread);
	wake_lock_init(new_thread);

	fake_init_lock(&new_thread->mutex);

	new_thread->t_tro = calloc(1, sizeof(struct thread_ro));
	new_thread->t_tro->tro_owner = new_thread;
	new_thread->t_tro->tro_task = s->main_task;
	new_thread->t_tro->tro_proc = s->main_proc;

	// for the main thread this happens before zalloc init so don't do the following which uses zalloc
	//struct thread_ro tro_tpl = { };
	//thread_ro_create(&s->main_task, new_thread, &tro_tpl);

	new_thread->state = TH_RUN;

	// raw_printf("thread_t created ctid=%u\n", new_thread->ctid);
	return new_mock_thread;
}

void
fake_init_task(task_t new_task)
{
	// can't call task_create_internal() since it does zalloc
	fake_init_lock(&new_task->lock);
	fake_init_lock(&new_task->task_objq_lock);
	queue_init(&new_task->task_objq);
	queue_init(&new_task->threads);
	new_task->suspend_count = 0;
	new_task->thread_count = 0;
	new_task->active_thread_count = 0;
	new_task->user_stop_count = 0;
	new_task->legacy_stop_count = 0;
	new_task->active = TRUE;
	new_task->halting = FALSE;
	new_task->priv_flags = 0;
	new_task->t_flags = 0;
	new_task->t_procflags = 0;
	new_task->t_returnwaitflags = 0;
	new_task->importance = 0;
	new_task->crashed_thread_id = 0;
	new_task->watchports = NULL;
	new_task->t_rr_ranges = NULL;
	new_task->t_flags |= TF_HASPROC;
	new_task->bank_context = NULL;

	new_task->pageins = calloc(1, sizeof(uint64_t));

	new_task->bsd_info_ro = calloc(1, sizeof(*new_task->bsd_info_ro));
	new_task->bsd_info_ro->pr_task = new_task;

	/* TODO: replace with ipc_task_init */
	ipc_space_t space;
	kern_return_t kr = ipc_space_create(IPC_LABEL_NONE, &space);
	PT_ASSERT_MACH_SUCCESS(kr, "ipc_space_create should succeed");
	new_task->itk_space = space;
	space->is_task = new_task;

	/*
	 * For now just set up an ESv3 IPC space.
	 * In the future we expect this all to be replaced with a more dynamic
	 * system for configuring the task in which a test runs, and constructing
	 * other tasks on the system.
	 */
	ipc_space_set_policy(space, IPC_SPACE_POLICY_ENHANCED_V3);
}


static void *
fake_allocate_task_proc_storage(void)
{
	return calloc(1, proc_struct_size + sizeof(struct task));
}

proc_t
fake_alloc_init_proc_and_task(void)
{
	void *proctask = fake_allocate_task_proc_storage();
	proc_t proc = (proc_t)proctask;
	task_t task = proc_get_task_raw(proc);
	fake_proc_init(proc);
	fake_init_task(task);
	return proc;
}

task_t
fake_alloc_init_task_and_proc(void)
{
	proc_t proc = fake_alloc_init_proc_and_task();
	return proc_get_task_raw(proc);
}

void
fake_dealloc_task_and_proc(task_t task)
{
	proc_t proc = task_get_proc_raw(task);
	fake_dealloc_proc_and_task(proc);
}

static void
mock_init_threads_state(struct mock_process_state* s)
{
	// Initialize CPU data first. Later initialization code uses these.

	fibers_multicpu_init(); // in case this happens before the constructor

	if (ut_mocks_use_fibers) {
		cpu_data_startup_init();

		s->cpu_data_array = calloc(fibers_multicpu.cpu_count, sizeof(struct cpu_data *));
		for (unsigned int cpu_id = 0; cpu_id < fibers_multicpu.cpu_count; cpu_id++) {
			cpu_data_t *cpu_datap = cpu_data_alloc(cpu_id == 0);

			// vm_offset_t base = (vm_offset_t)cpu_datap - __PERCPU_ADDR(cpu_data);
			// raw_printf("cpu %d cpu_datap %p base %p\n", cpu_id, cpu_datap, base);
			cpu_data_init(cpu_datap);
			cpu_datap->cpu_number = cpu_id;

			s->cpu_data_array[cpu_id] = cpu_datap;
			CpuDataEntries[cpu_id].cpu_data_vaddr = cpu_datap;
			CpuDataEntries[cpu_id].cpu_data_paddr = NULL;
		}
	} else {
		// for pthreads: initialize the single legacy cpud
		cpu_data_init(&s->cpud);
	}

	if (!ut_mocks_use_fibers) {
		int ret = pthread_key_create(&s->tls_thread_key, &mock_destroy_thread);
		if (ret != 0) {
			raw_printf("failed pthread_key_create");
			exit(1);
		}

		/* Start with interrupts enabled. */
		s->interrupts_enabled = true;

		ret = pthread_mutex_init(&s->events_mutex, NULL);
		if (ret != 0) {
			raw_printf("failed pthread_key_create");
			exit(1);
		}
		memset(&s->events, 0, sizeof(s->events));
	}

	//task_zone_init();
	s->proctask = calloc(1, proc_struct_size + sizeof(struct task));
	s->main_proc = (proc_t)s->proctask;
	s->main_task = proc_get_task_raw(s->main_proc);

	/*
	 * without this machine_thread_create calls into zalloc, which isn't
	 * initialized yet
	 */
	kernel_task = s->main_task;

	memset(s->main_proc, 0, proc_struct_size);
	fake_proc_init(s->main_proc);
	kernproc = s->main_proc; // set global variable

	memset(s->main_task, 0, sizeof(*s->main_task));
	fake_init_task(s->main_task);

	if (ut_mocks_use_fibers) {
		counter_alloc(&s->main_task->faults);
		counter_alloc(&s->main_task->pageins);
		counter_alloc(&s->main_task->cow_faults);
		counter_alloc(&s->main_task->messages_sent);
		counter_alloc(&s->main_task->messages_received);
	} else {
		s->main_task->faults = calloc(1, sizeof(uint64_t));
		s->main_task->pageins = calloc(1, sizeof(uint64_t));
		s->main_task->cow_faults = calloc(1, sizeof(uint64_t));
		s->main_task->messages_sent = calloc(1, sizeof(uint64_t));
		s->main_task->messages_received = calloc(1, sizeof(uint64_t));
	}

	kernel_task = s->main_task; // without this machine_thread_create allocates

	s->thread_unique_id = 100;

	s->main_thread = mock_init_new_thread(s, true);
}

struct mock_process_state *
get_proc_state(void)
{
	static struct mock_process_state s;
	static bool initialized = false;
	if (!initialized) { // TODO move to fake_kinit.c ?
		initialized = true;
		mock_init_threads_state(&s);
	}
	return &s;
}

struct mock_thread *
get_mock_thread(void)
{
	struct mock_process_state *s = get_proc_state();

	struct mock_thread *mth;
	if (ut_mocks_use_fibers) {
		mth = (struct mock_thread *)fibers_current->extra;
	} else {
		mth = pthread_getspecific(s->tls_thread_key);
	}

	if (mth == NULL) {
		mth = mock_init_new_thread(s, false);
	}
	return mth;
}

T_MOCK_F(thread_t,
current_thread_fast, (void), ())
{
	return &get_mock_thread()->th;
}

T_MOCK_F(uint32_t,
kauth_cred_getuid, (void *cred), (cred))
{
	return 0;
}

T_MOCK_F(void,
machine_thread_state_initialize, (thread_t thread), (thread))
{
}

T_MOCK(int,
task_pid,
(task_t task),
(task));

T_MOCK(struct proc *,
current_proc, (void), ());

// --------------- interrupts disable (spl) ---------------------

T_MOCK_F(boolean_t,
ml_get_interrupts_enabled, (void), ())
{
	if (ut_mocks_use_fibers) {
		return get_mock_thread()->interrupts_disabled == 0;
	} else {
		return get_proc_state()->interrupts_enabled;
	}
}

// original calls DAIF
// interupts disable can be mocked by disabling context switches with fiber_t.may_yield_disabled, but it breaks multi-cpu simulation.
T_MOCK_F(boolean_t,
ml_set_interrupts_enabled, (boolean_t enable), (enable))
{
	if (ut_mocks_use_fibers) {
		bool prev_interrupts_disabled = get_mock_thread()->interrupts_disabled;

		FIBERS_LOG(FIBERS_LOG_DEBUG, "ml_set_interrupts_enabled: enable=%d, previous state=%d, may_yield_disabled=%d", enable, !get_mock_thread()->interrupts_disabled, fibers_current->may_yield_disabled);

		fibers_may_yield_internal_with_reason(
			(enable ? FIBERS_YIELD_REASON_PREEMPTION_WILL_ENABLE : FIBERS_YIELD_REASON_PREEMPTION_WILL_DISABLE) |
			FIBERS_YIELD_REASON_ERROR_IF(enable != prev_interrupts_disabled));

		if (enable && prev_interrupts_disabled) {
			get_mock_thread()->interrupts_disabled = false;
			// sync with per-CPU state
			unsigned int cpu = fibers_multicpu.executing_cpu;
			if (cpu < fibers_multicpu.cpu_count) {
				fibers_multicpu.cpus[cpu].interrupts_disabled = false;
			}
		} else if (!enable && !prev_interrupts_disabled) {
			get_mock_thread()->interrupts_disabled = true;
			// sync with per-CPU state
			unsigned int cpu = fibers_multicpu.executing_cpu;
			if (cpu < fibers_multicpu.cpu_count) {
				fibers_multicpu.cpus[cpu].interrupts_disabled = true;
			}
		}

		FIBERS_LOG(FIBERS_LOG_DEBUG, "ml_set_interrupts_enabled exit: enable=%d, state=%d, may_yield_disabled=%d", enable, !get_mock_thread()->interrupts_disabled, fibers_current->may_yield_disabled);

		fibers_may_yield_internal_with_reason(
			(enable ? FIBERS_YIELD_REASON_PREEMPTION_DID_ENABLE : FIBERS_YIELD_REASON_PREEMPTION_DID_DISABLE) |
			FIBERS_YIELD_REASON_ERROR_IF(enable != prev_interrupts_disabled));

		return !prev_interrupts_disabled;
	} else {
		get_proc_state()->interrupts_enabled = enable;
	}
	return true;
}

T_MOCK_F(boolean_t,
ml_set_interrupts_enabled_with_debug, (boolean_t enable, boolean_t __unused debug), (enable, debug))
{
	return MOCK_ml_set_interrupts_enabled(enable);
}

T_MOCK_F(uint64_t,
ml_pac_safe_interrupts_disable, (void), ())
{
	boolean_t prev_enabled = MOCK_ml_set_interrupts_enabled(FALSE);
	return prev_enabled ? 1 : 0;
}

T_MOCK_F(void,
ml_pac_safe_interrupts_restore, (uint64_t prev_enabled), (prev_enabled))
{
	MOCK_ml_set_interrupts_enabled(prev_enabled != 0);
}

T_MOCK_F(void,
_disable_preemption, (void), ())
{
	if (ut_mocks_use_fibers) {
		fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_PREEMPTION_WILL_DISABLE);

		thread_t thread = MOCK_current_thread_fast();
		unsigned int count = thread->machine.preemption_count;
		os_atomic_store(&thread->machine.preemption_count, count + 1, compiler_acq_rel);

		fibers_current->preemption_count++;

		// sync per-CPU state from fiber
		unsigned int cpu_id = fibers_multicpu.executing_cpu;
		fibers_multicpu.cpus[cpu_id].preemption_disabled_count = fibers_current->preemption_count;
		FIBERS_LOG(FIBERS_LOG_DEBUG, "disable_preemption: cpu=%d fiber=%d assigned_cpu=%d current_fiber=%d preemption_count=%d",
		    cpu_id, fibers_current->id, fibers_current->assigned_cpu,
		    fibers_multicpu.cpus[cpu_id].current_fiber ? fibers_multicpu.cpus[cpu_id].current_fiber->id : -1,
		    fibers_current->preemption_count);

		fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_PREEMPTION_DID_DISABLE);
	} else {
		thread_t thread = MOCK_current_thread_fast();
		unsigned int count = thread->machine.preemption_count;
		os_atomic_store(&thread->machine.preemption_count, count + 1, compiler_acq_rel);
	}
}

T_MOCK_F(void,
_disable_preemption_without_measurements, (void), ())
{
	MOCK__disable_preemption();
}

T_MOCK_F(void,
lock_disable_preemption_for_thread, (thread_t t), (t))
{
	MOCK__disable_preemption();
}

T_MOCK_F(void,
_enable_preemption, (void), ())
{
	if (ut_mocks_use_fibers) {
		fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_PREEMPTION_WILL_ENABLE);

		thread_t thread = current_thread();
		unsigned int count = thread->machine.preemption_count;
		os_atomic_store(&thread->machine.preemption_count, count - 1, compiler_acq_rel);

		PT_QUIET; PT_ASSERT_TRUE(fibers_current->preemption_count > 0, "preemption underflow");

		fibers_current->preemption_count--;

		// sync per-CPU state from fiber
		unsigned int cpu_id = fibers_multicpu.executing_cpu;
		fibers_multicpu.cpus[cpu_id].preemption_disabled_count = fibers_current->preemption_count;
		FIBERS_LOG(FIBERS_LOG_DEBUG, "enable_preemption: cpu=%d fiber_preemption_count=%d", cpu_id, fibers_current->preemption_count);

		fibers_may_yield_internal_with_reason(
			FIBERS_YIELD_REASON_PREEMPTION_DID_ENABLE |
			FIBERS_YIELD_REASON_ERROR_IF(count - 1 != 0));
	} else {
		thread_t thread = current_thread();
		unsigned int count  = thread->machine.preemption_count;
		os_atomic_store(&thread->machine.preemption_count, count - 1, compiler_acq_rel);
	}
}

// --------------- mutex ------------------

struct mock_lck_mtx_t {
	union {
		pthread_mutex_t *pt_m;
		fibers_mutex_t *f_m;
	};
	lck_mtx_state_t lck_mtx;
};
static_assert(sizeof(struct mock_lck_mtx_t) == sizeof(lck_mtx_t));

void
fake_init_lock(lck_mtx_t * lck)
{
	struct mock_lck_mtx_t* mlck = (struct mock_lck_mtx_t*)lck;
	if (ut_mocks_use_fibers) {
		mlck->f_m = calloc(1, sizeof(fibers_mutex_t));
		fibers_mutex_init(mlck->f_m);
	} else {
		mlck->pt_m = calloc(1, sizeof(pthread_mutex_t));
		int ret = pthread_mutex_init(mlck->pt_m, NULL);
		PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "pthread_mutex_init");
	}
}

T_MOCK_F(void,
lck_mtx_init, (lck_mtx_t * lck, lck_grp_t * grp, lck_attr_t * attr), (lck, grp, attr))
{
	fake_init_lock(lck);
}

T_MOCK_F(void,
lck_mtx_destroy, (lck_mtx_t * lck, lck_grp_t * grp), (lck, grp))
{
	struct mock_lck_mtx_t* mlck = (struct mock_lck_mtx_t*)lck;
	if (ut_mocks_use_fibers) {
		fibers_mutex_destroy(mlck->f_m);
		free(mlck->f_m);
		mlck->f_m = NULL;
	} else {
		int ret = pthread_mutex_destroy(mlck->pt_m);
		PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "pthread_mutex_destroy");
		free(mlck->pt_m);
		mlck->pt_m = NULL;
	}
}

T_MOCK_F(void,
lck_mtx_lock, (lck_mtx_t * lock), (lock))
{
	uint32_t ctid = MOCK_current_thread_fast()->ctid;

	struct mock_lck_mtx_t* mlck = (struct mock_lck_mtx_t*)lock;
	if (ut_mocks_use_fibers) {
		fibers_mutex_lock(mlck->f_m, true);
	} else {
		int ret = pthread_mutex_lock(mlck->pt_m);
		PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "pthread_mutex_lock");
	}
	mlck->lck_mtx.owner = ctid;
}

T_MOCK_F(void,
lck_mtx_lock_spin, (lck_mtx_t * lock), (lock))
{
	uint32_t ctid = MOCK_current_thread_fast()->ctid;

	struct mock_lck_mtx_t* mlck = (struct mock_lck_mtx_t*)lock;
	if (ut_mocks_use_fibers) {
		fibers_mutex_lock(mlck->f_m, false); // do not check for disabled preemption if spinlock
	} else {
		int ret = pthread_mutex_lock(mlck->pt_m);
		PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "pthread_mutex_lock");
	}
	mlck->lck_mtx.owner = ctid;
}

T_MOCK_F(boolean_t,
lck_mtx_try_lock, (lck_mtx_t * lock), (lock))
{
	uint32_t ctid = MOCK_current_thread_fast()->ctid;

	struct mock_lck_mtx_t* mlck = (struct mock_lck_mtx_t*)lock;
	int ret;
	if (ut_mocks_use_fibers) {
		ret = fibers_mutex_try_lock(mlck->f_m);
	} else {
		int ret = pthread_mutex_trylock(mlck->pt_m);
	}
	if (ret == 0) {
		mlck->lck_mtx.owner = ctid;
		return TRUE;
	} else {
		return FALSE;
	}
}

T_MOCK_F(void,
lck_mtx_unlock, (lck_mtx_t * lock), (lock))
{
	struct mock_lck_mtx_t* mlck = (struct mock_lck_mtx_t*)lock;
	mlck->lck_mtx.owner = 0;
	if (ut_mocks_use_fibers) {
		fibers_mutex_unlock(mlck->f_m);
	} else {
		int ret = pthread_mutex_unlock(mlck->pt_m);
		PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "pthread_mutex_unlock");
	}
}

T_MOCK_F(void,
mutex_pause, (uint32_t collisions), (collisions))
{
	if (ut_mocks_use_fibers) {
		// we can't sleep to not break determinism, trigger a ctxswitch instead
		fibers_yield();
	} else {
		mutex_pause(collisions);
	}
}

// --------------- rwlocks ------------------

struct mock_lck_rw_t {
	fibers_rwlock_t *rw;
	// lck_rw_word_t   lck_rw; // RANGELOCKINGTODO rdar://150846598
	uint32_t lck_rw_owner;
};
static_assert(sizeof(struct mock_lck_rw_t) == sizeof(lck_rw_old_t));
static_assert(sizeof(struct mock_lck_rw_t) == sizeof(lck_rw_new_t));

static_assert(LCK_RW_ASSERT_SHARED == FIBERS_RWLOCK_ASSERT_SHARED);
static_assert(LCK_RW_ASSERT_EXCLUSIVE == FIBERS_RWLOCK_ASSERT_EXCLUSIVE);
static_assert(LCK_RW_ASSERT_HELD == FIBERS_RWLOCK_ASSERT_HELD);
static_assert(LCK_RW_ASSERT_NOTHELD == FIBERS_RWLOCK_ASSERT_NOTHELD);
static_assert(LCK_RW_ASSERT_NOT_OWNED == FIBERS_RWLOCK_ASSERT_NOT_OWNED);

void
fake_init_rwlock(struct mock_lck_rw_t *mlck)
{
	mlck->rw = calloc(1, sizeof(fibers_rwlock_t));
	fibers_rwlock_init(mlck->rw);
}

static boolean_t
fake_rw_try_lock(struct mock_lck_rw_t *mlck, lck_rw_type_t lck_rw_type)
{
	int ret;
	if (lck_rw_type == LCK_RW_TYPE_SHARED_SPIN || lck_rw_type == LCK_RW_TYPE_EXCLUSIVE_SPIN) {
		MOCK__disable_preemption();
	} else {
		// RANGELOCKINGTODO rdar://150846598 handle old lock can_sleep
		lck_rw_lock_count_inc(MOCK_current_thread_fast(), (const void*)mlck);
	}

	if (lck_rw_type == LCK_RW_TYPE_SHARED || lck_rw_type == LCK_RW_TYPE_SHARED_SPIN) {
		ret = fibers_rwlock_try_rdlock(mlck->rw);
	} else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE || lck_rw_type == LCK_RW_TYPE_EXCLUSIVE_SPIN) {
		ret = fibers_rwlock_try_wrlock(mlck->rw);
		if (ret == 0) {
			mlck->lck_rw_owner = MOCK_current_thread_fast()->ctid;
		}
	} else {
		PT_FAIL("lck_rw_try_lock: Invalid lock type");
	}

	if (ret != 0) {
		if ((lck_rw_type == LCK_RW_TYPE_SHARED_SPIN || lck_rw_type == LCK_RW_TYPE_EXCLUSIVE_SPIN)) {
			MOCK__enable_preemption();
		} else {
			// RANGELOCKINGTODO rdar://150846598 handle old lock can_sleep
			lck_rw_lock_count_dec(MOCK_current_thread_fast(), (const void*)mlck);
		}
	}
	return ret == 0;
}

static bool
fake_rw_lock_would_yield_exclusive(struct mock_lck_rw_t *mlck, lck_rw_yield_t mode)
{
	fibers_rwlock_assert(mlck->rw, FIBERS_RWLOCK_ASSERT_EXCLUSIVE);

	bool yield = false;
	if (mode == LCK_RW_YIELD_ALWAYS) {
		yield = true;
	} else {
		if (mlck->rw->writer_wait_queue.count > 0) {
			yield = true;
		} else if (mode == LCK_RW_YIELD_ANY_WAITER) {
			yield = (mlck->rw->reader_wait_queue.count != 0);
		}
	}
	return yield;
}

// XNU_LCK_RW_DEFAULT_TO_NEW=1 if the new rwlock implementation must replace by default the old one
// to do so __attribute__((overloadable)) is set for the old API but not for the new one.
// In the other case, it is the opposite, the old API is still the default unless the new one is explicitly used (like in vm_object).
#if XNU_LCK_RW_DEFAULT_TO_NEW
	#define T_MOCK_OLD_RW T_MOCK_OVERLOAD
	#define T_MOCK_NEW_RW T_MOCK_OVERLOAD_NOATTR
#else
	#define T_MOCK_OLD_RW T_MOCK_OVERLOAD_NOATTR
	#define T_MOCK_NEW_RW T_MOCK_OVERLOAD
#endif

T_MOCK_OLD_RW(void,
    lck_rw_init, (
	    lck_rw_old_t * lck,
	    lck_grp_t * grp,
	    lck_attr_t * attr))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_init(lck, grp, attr);
		return;
	}

	// RANGELOCKINGTODO rdar://150846598 mock attr, especially lck_rw_can_sleep
	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fake_init_rwlock(mlck);
}

T_MOCK_OLD_RW(void,
    lck_rw_destroy, (lck_rw_old_t * lck, lck_grp_t * grp))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_destroy(lck, grp);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_destroy(mlck->rw);
	free(mlck->rw);
	mlck->rw = NULL;
}

T_MOCK_OLD_RW(void,
    lck_rw_unlock, (lck_rw_old_t * lck, lck_rw_type_t lck_rw_type))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_unlock(lck, lck_rw_type);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	if (mlck->rw->writer_active) {
		mlck->lck_rw_owner = 0;
	}
	fibers_rwlock_unlock(mlck->rw);

	// RANGELOCKINGTODO rdar://150846598 handle old lock can_sleep
	lck_rw_lock_count_dec(MOCK_current_thread_fast(), (const void*)mlck);
}

static void
lck_rw_old_mock_unlock_shared(lck_rw_old_t * lck)
{
	if (!ut_mocks_use_fibers) {
		lck_rw_unlock_shared(lck);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_rdunlock(mlck->rw);

	// RANGELOCKINGTODO rdar://150846598 handle old lock can_sleep
	lck_rw_lock_count_dec(MOCK_current_thread_fast(), (const void*)mlck);
}

T_MOCK_OLD_RW(void,
    lck_rw_unlock_shared, (lck_rw_old_t * lck))
{
	lck_rw_old_mock_unlock_shared(lck);
}

T_MOCK_OLD_RW(void,
    lck_rw_unlock_exclusive, (lck_rw_old_t * lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_unlock_exclusive(lck);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	mlck->lck_rw_owner = 0;
	fibers_rwlock_wrunlock(mlck->rw);

	// RANGELOCKINGTODO rdar://150846598 handle old lock can_sleep
	lck_rw_lock_count_dec(MOCK_current_thread_fast(), (const void*)mlck);
}

T_MOCK_OLD_RW(void,
    lck_rw_lock_exclusive, (lck_rw_old_t * lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_lock_exclusive(lck);
		return;
	}

	// RANGELOCKINGTODO rdar://150846598 handle old lock can_sleep
	lck_rw_lock_count_inc(MOCK_current_thread_fast(), (const void*)lck);

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_wrlock(mlck->rw, true);
	mlck->lck_rw_owner = MOCK_current_thread_fast()->ctid;
}

T_MOCK_OLD_RW(void,
    lck_rw_lock_shared, (lck_rw_old_t * lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_lock_shared(lck);
		return;
	}

	// RANGELOCKINGTODO rdar://150846598 handle old lock can_sleep
	lck_rw_lock_count_inc(MOCK_current_thread_fast(), (const void*)lck);

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_rdlock(mlck->rw, true);
}

T_MOCK_OLD_RW(boolean_t,
    lck_rw_try_lock, (lck_rw_old_t * lck, lck_rw_type_t lck_rw_type))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_try_lock(lck, lck_rw_type);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fake_rw_try_lock(mlck, lck_rw_type);
}

T_MOCK_OLD_RW(boolean_t,
    lck_rw_try_lock_exclusive, (lck_rw_old_t * lck))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_try_lock_exclusive(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fake_rw_try_lock(mlck, LCK_RW_TYPE_EXCLUSIVE);
}

T_MOCK_OLD_RW(boolean_t,
    lck_rw_try_lock_shared, (lck_rw_old_t * lck))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_try_lock_shared(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fake_rw_try_lock(mlck, LCK_RW_TYPE_SHARED);
}

T_MOCK_OLD_RW(lck_rw_type_t,
    lck_rw_done, (lck_rw_old_t * lck))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_done(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	mlck->lck_rw_owner = 0;
	// If there is a writer locking it must be the current fiber or will trigger an assertion in fibers_rwlock_wrunlock
	lck_rw_type_t ret = mlck->rw->writer_active ? LCK_RW_TYPE_EXCLUSIVE : LCK_RW_TYPE_SHARED;
	fibers_rwlock_unlock(mlck->rw);

	// RANGELOCKINGTODO rdar://150846598 handle old lock can_sleep
	lck_rw_lock_count_dec(MOCK_current_thread_fast(), (const void*)mlck);

	return ret;
}

T_MOCK_OLD_RW(boolean_t,
    lck_rw_lock_shared_to_exclusive, (lck_rw_old_t * lck))
{
	if (ut_mocks_lock_upgrade_fail) {
		lck_rw_old_mock_unlock_shared(lck);
		return false;
	}

	if (!ut_mocks_use_fibers) {
		return lck_rw_lock_shared_to_exclusive(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fibers_rwlock_upgrade(mlck->rw);
}

T_MOCK_OLD_RW(void,
    lck_rw_lock_exclusive_to_shared, (lck_rw_old_t * lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_lock_exclusive_to_shared(lck);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_downgrade(mlck->rw);
}

T_MOCK_OLD_RW(void,
    lck_rw_assert, (
	    lck_rw_old_t * lck,
	    unsigned int type))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_assert(lck, type);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_assert(mlck->rw, type);
}

T_MOCK_OLD_RW(bool,
    lck_rw_lock_would_yield_exclusive, (
	    lck_rw_old_t * lck,
	    lck_rw_yield_t mode))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_lock_would_yield_exclusive(lck, mode);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fake_rw_lock_would_yield_exclusive(mlck, mode);
}

T_MOCK_OLD_RW(bool,
    lck_rw_lock_would_yield_shared, (lck_rw_old_t * lck))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_lock_would_yield_shared(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_assert(mlck->rw, FIBERS_RWLOCK_ASSERT_SHARED);
	return mlck->rw->writer_wait_queue.count != 0;
}

// Note: No need to mock lck_rw_sleep as it uses lck_rw_* API and waitq, we already mock everything the function uses

// Overloaded versions for new rwlocks

T_MOCK_NEW_RW(void,
    lck_rw_init, (
	    lck_rw_new_t * lck,
	    lck_grp_t * grp,
	    lck_attr_t * attr))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_init(lck, grp, attr);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fake_init_rwlock(mlck);
}

T_MOCK_NEW_RW(void,
    lck_rw_destroy, (lck_rw_new_t * lck, lck_grp_t * grp))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_destroy(lck, grp);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_destroy(mlck->rw);
	free(mlck->rw);
	mlck->rw = NULL;
}

static void
lck_rw_new_mock_unlock_shared(lck_rw_new_t * lck)
{
	if (!ut_mocks_use_fibers) {
		lck_rw_unlock_shared(lck);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_rdunlock(mlck->rw);

	lck_rw_lock_count_dec(MOCK_current_thread_fast(), (const void*)mlck);
}

T_MOCK_NEW_RW(void,
    lck_rw_unlock_shared, (lck_rw_new_t * lck))
{
	lck_rw_new_mock_unlock_shared(lck);
}

T_MOCK_NEW_RW(void,
    lck_rw_unlock_exclusive, (lck_rw_new_t * lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_unlock_exclusive(lck);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	mlck->lck_rw_owner = 0;
	fibers_rwlock_wrunlock(mlck->rw);

	lck_rw_lock_count_dec(MOCK_current_thread_fast(), (const void*)mlck);
}

T_MOCK_NEW_RW(void,
    lck_rw_lock_exclusive, (lck_rw_new_t * lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_lock_exclusive(lck);
		return;
	}

	lck_rw_lock_count_inc(MOCK_current_thread_fast(), (const void*)lck);

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_wrlock(mlck->rw, true);
	mlck->lck_rw_owner = MOCK_current_thread_fast()->ctid;
}

T_MOCK_NEW_RW(void,
    lck_rw_lock_shared, (lck_rw_new_t * lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_lock_shared(lck);
		return;
	}

	lck_rw_lock_count_inc(MOCK_current_thread_fast(), (const void*)lck);

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_rdlock(mlck->rw, true);
}

T_MOCK_NEW_RW(boolean_t,
    lck_rw_try_lock, (lck_rw_new_t * lck, lck_rw_type_t lck_rw_type))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_try_lock(lck, lck_rw_type);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fake_rw_try_lock(mlck, lck_rw_type);
}

T_MOCK_NEW_RW(boolean_t,
    lck_rw_try_lock_exclusive, (lck_rw_new_t * lck))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_try_lock_exclusive(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fake_rw_try_lock(mlck, LCK_RW_TYPE_EXCLUSIVE);
}

T_MOCK_NEW_RW(boolean_t,
    lck_rw_try_lock_shared, (lck_rw_new_t * lck))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_try_lock_shared(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fake_rw_try_lock(mlck, LCK_RW_TYPE_SHARED);
}


T_MOCK_NEW_RW(lck_rw_type_t,
    lck_rw_done, (lck_rw_new_t * lck))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_done(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	mlck->lck_rw_owner = 0;
	// If there is a writer locking it must be the current fiber or will trigger an assertion in fibers_rwlock_wrunlock
	lck_rw_type_t ret = mlck->rw->writer_active ? LCK_RW_TYPE_EXCLUSIVE : LCK_RW_TYPE_SHARED;
	fibers_rwlock_unlock(mlck->rw);

	// RANGELOCKINGTODO rdar://150846598 handle old lock can_sleep
	lck_rw_lock_count_dec(MOCK_current_thread_fast(), (const void*)mlck);

	return ret;
}

T_MOCK_NEW_RW(boolean_t,
    lck_rw_lock_shared_to_exclusive, (lck_rw_new_t * lck))
{
	if (ut_mocks_lock_upgrade_fail) {
		lck_rw_new_mock_unlock_shared(lck);
		return false;
	}

	if (!ut_mocks_use_fibers) {
		return lck_rw_lock_shared_to_exclusive(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fibers_rwlock_upgrade(mlck->rw);
}

T_MOCK_NEW_RW(void,
    lck_rw_lock_exclusive_to_shared, (lck_rw_new_t * lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_lock_exclusive_to_shared(lck);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_downgrade(mlck->rw);
}

T_MOCK_NEW_RW(void,
    lck_rw_assert, (
	    lck_rw_new_t * lck,
	    unsigned int type))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_assert(lck, type);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_assert(mlck->rw, type);
}

T_MOCK_NEW_RW(bool,
    lck_rw_lock_would_yield_exclusive, (
	    lck_rw_new_t * lck,
	    lck_rw_yield_t mode))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_lock_would_yield_exclusive(lck, mode);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fake_rw_lock_would_yield_exclusive(mlck, mode);
}

T_MOCK_NEW_RW(bool,
    lck_rw_lock_would_yield_shared, (lck_rw_new_t * lck))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_lock_would_yield_shared(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_assert(mlck->rw, FIBERS_RWLOCK_ASSERT_SHARED);
	return mlck->rw->writer_wait_queue.count != 0;
}

T_MOCK_NEW_RW(wait_result_t,
    lck_rw_sleep_deadline, (
	    lck_rw_new_t               * lck,
	    lck_sleep_action_t      lck_sleep_action,
	    event_t                 event,
	    wait_interrupt_t        interruptible,
	    uint64_t                deadline
	    ))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_sleep_deadline(lck, lck_sleep_action, event, interruptible, deadline);
	}

	PT_QUIET; PT_ASSERT_TRUE(deadline == TIMEOUT_WAIT_FOREVER, "lck_rw_sleep_deadline supports only TIMEOUT_WAIT_FOREVER");

	return lck_rw_sleep_deadline(lck, lck_sleep_action, event, interruptible, deadline);
}

// New rwlocks only functions

T_MOCK_F(void,
lck_rw_assert_held_type, (lck_rw_new_t * lck, lck_rw_type_t type), (lck, type))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_assert_held_type(lck, type);
		return;
	}

	thread_t thread;
	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	switch (type) {
	case LCK_RW_TYPE_NONE:
		fibers_rwlock_assert(mlck->rw, FIBERS_RWLOCK_ASSERT_NOTHELD);
		return;
	case LCK_RW_TYPE_SHARED_SPIN:
		thread = current_thread();
		PT_QUIET; PT_ASSERT_TRUE(thread->machine.preemption_count > 0, "preemption enabled for shared spin");
	case LCK_RW_TYPE_SHARED:
		fibers_rwlock_assert(mlck->rw, FIBERS_RWLOCK_ASSERT_SHARED);
		return;
	case LCK_RW_TYPE_EXCLUSIVE_SPIN:
		thread = current_thread();
		PT_QUIET; PT_ASSERT_TRUE(thread->machine.preemption_count > 0, "preemption enabled for exclusive spin");
	case LCK_RW_TYPE_EXCLUSIVE:
		fibers_rwlock_assert(mlck->rw, FIBERS_RWLOCK_ASSERT_EXCLUSIVE);
		return;
	case LCK_RW_TYPE_ANY:
		fibers_rwlock_assert(mlck->rw, FIBERS_RWLOCK_ASSERT_HELD);
		return;
	}

	PT_FAIL("lck_rw_assert_held_type: Invalid RW lock type");
}

T_MOCK_F(void,
lck_rw_unlock_shared_spin, (lck_rw_new_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_unlock_shared_spin(lck);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;

	fibers_rwlock_rdunlock(mlck->rw);

	MOCK__enable_preemption();
}

T_MOCK_F(void,
lck_rw_unlock_exclusive_spin, (lck_rw_new_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_unlock_exclusive_spin(lck);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	mlck->lck_rw_owner = 0;

	fibers_rwlock_wrunlock(mlck->rw);

	MOCK__enable_preemption();
}

T_MOCK_F(void,
lck_rw_lock_exclusive_spin, (lck_rw_new_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_lock_exclusive_spin(lck);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_wrlock(mlck->rw, false);
	mlck->lck_rw_owner = MOCK_current_thread_fast()->ctid;

	MOCK__disable_preemption(); // Disable preemption AFTER acquiring lock
}

T_MOCK_F(void,
lck_rw_lock_shared_spin, (lck_rw_new_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		lck_rw_lock_shared_spin(lck);
		return;
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	fibers_rwlock_rdlock(mlck->rw, false);
	mlck->lck_rw_owner = MOCK_current_thread_fast()->ctid;

	MOCK__disable_preemption(); // Disable preemption AFTER acquiring lock
}

T_MOCK_F(bool,
lck_rw_try_lock_exclusive_spin, (lck_rw_new_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_try_lock_exclusive_spin(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fake_rw_try_lock(mlck, LCK_RW_TYPE_EXCLUSIVE_SPIN);
}

T_MOCK_F(bool,
lck_rw_try_lock_shared_spin, (lck_rw_new_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_try_lock_shared_spin(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	return fake_rw_try_lock(mlck, LCK_RW_TYPE_SHARED_SPIN);
}

T_MOCK_F(bool,
lck_rw_lock_shared_to_exclusive_spin, (lck_rw_new_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		return lck_rw_lock_shared_to_exclusive_spin(lck);
	}

	struct mock_lck_rw_t* mlck = (struct mock_lck_rw_t*)lck;
	bool success = fibers_rwlock_upgrade(mlck->rw);
	if (success) {
		MOCK__disable_preemption();
	}
	// If upgrade failed, lock was released and we don't hold it anymore
	return success;
}

// --------------- hw ticket lock ------------------

#define NUM_MOCKED_TICKET_LOCKS 2048

fibers_mutex_t *ticket_lock_mtxs[NUM_MOCKED_TICKET_LOCKS];

struct mock_hw_lck_ticket_t {
	uint32_t ticket_lock_mtx_idx;
};
static_assert(sizeof(struct mock_hw_lck_ticket_t) == sizeof(hw_lck_ticket_t));

struct mock_lck_ticket_t {
	uint32_t                __lck_ticket_unused : 24;
	uint32_t                lck_ticket_type     :  8;
	uint32_t                lck_ticket_padding;
	struct mock_hw_lck_ticket_t tu;
	uint32_t                lck_ticket_owner; // ctid of owner thread
};
static_assert(sizeof(struct mock_lck_ticket_t) == sizeof(lck_ticket_t));

T_MOCK_F(void,
hw_lck_ticket_init, (hw_lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		hw_lck_ticket_init(lck, grp);
		return;
	}

	struct mock_hw_lck_ticket_t *mlck = (struct mock_hw_lck_ticket_t*)lck;

	uint32_t candidate = 0;
	for (candidate = 0; candidate < NUM_MOCKED_TICKET_LOCKS; ++candidate) {
		if (ticket_lock_mtxs[candidate] == NULL) {
			mlck->ticket_lock_mtx_idx = candidate;
			ticket_lock_mtxs[candidate] = calloc(1, sizeof(fibers_mutex_t));
			fibers_mutex_init(ticket_lock_mtxs[candidate]);

			return;
		}
	}

	PT_FAIL("Max number of hw_lck_ticket_t allowed to cohexists is NUM_MOCKED_TICKET_LOCKS");
}

T_MOCK_F(void,
hw_lck_ticket_init_locked, (hw_lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		hw_lck_ticket_init_locked(lck, grp);
		return;
	}

	struct mock_hw_lck_ticket_t *mlck = (struct mock_hw_lck_ticket_t*)lck;

	uint32_t candidate = 0;
	for (candidate = 0; candidate < 2048; ++candidate) {
		if (ticket_lock_mtxs[candidate] == NULL) {
			mlck->ticket_lock_mtx_idx = candidate;
			ticket_lock_mtxs[candidate] = calloc(1, sizeof(fibers_mutex_t));
			fibers_mutex_init(ticket_lock_mtxs[candidate]);

			MOCK__disable_preemption();
			fibers_mutex_lock(ticket_lock_mtxs[candidate], false);

			return;
		}
	}

	PT_FAIL("Max number of hw_lck_ticket_t allowed to cohexists is 2048");
}

T_MOCK_F(void,
hw_lck_ticket_destroy, (hw_lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		hw_lck_ticket_destroy(lck, grp);
		return;
	}

	struct mock_hw_lck_ticket_t *mlck = (struct mock_hw_lck_ticket_t*)lck;
	fibers_mutex_destroy(ticket_lock_mtxs[mlck->ticket_lock_mtx_idx]);
	free(ticket_lock_mtxs[mlck->ticket_lock_mtx_idx]);
	ticket_lock_mtxs[mlck->ticket_lock_mtx_idx] = NULL;
}

T_MOCK_F(void,
hw_lck_ticket_lock_nopreempt, (hw_lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		hw_lck_ticket_lock_nopreempt(lck, grp);
		return;
	}

	fibers_mutex_lock(ticket_lock_mtxs[((struct mock_hw_lck_ticket_t*)lck)->ticket_lock_mtx_idx], false);
}

T_MOCK_F(void,
hw_lck_ticket_lock, (hw_lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		hw_lck_ticket_lock(lck, grp);
		return;
	}

	fibers_mutex_lock(ticket_lock_mtxs[((struct mock_hw_lck_ticket_t*)lck)->ticket_lock_mtx_idx], false);
	MOCK__disable_preemption(); // Disable preemption AFTER acquiring lock
}

T_MOCK_F(void,
hw_lck_ticket_unlock_nopreempt, (hw_lck_ticket_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		hw_lck_ticket_unlock_nopreempt(lck);
		return;
	}

	fibers_mutex_unlock_fifo(ticket_lock_mtxs[((struct mock_hw_lck_ticket_t*)lck)->ticket_lock_mtx_idx]);
}

T_MOCK_F(void,
hw_lck_ticket_unlock, (hw_lck_ticket_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		hw_lck_ticket_unlock(lck);
		return;
	}

	fibers_mutex_unlock_fifo(ticket_lock_mtxs[((struct mock_hw_lck_ticket_t*)lck)->ticket_lock_mtx_idx]);
	MOCK__enable_preemption();
}

T_MOCK_F(void,
hw_lck_ticket_unlock_after_lookup_nopreempt, (hw_lck_ticket_t * lck, lck_dep_value_t value), (lck, value))
{
	if (!ut_mocks_use_fibers) {
		hw_lck_ticket_unlock_after_lookup_nopreempt(lck, value);
		return;
	}

	lck = os_atomic_inject_dependency(lck, value);
	fibers_mutex_unlock_fifo(ticket_lock_mtxs[((struct mock_hw_lck_ticket_t*)lck)->ticket_lock_mtx_idx]);
}

T_MOCK_F(void,
hw_lck_ticket_unlock_after_lookup, (hw_lck_ticket_t * lck, lck_dep_value_t value), (lck, value))
{
	if (!ut_mocks_use_fibers) {
		hw_lck_ticket_unlock_after_lookup(lck, value);
		return;
	}

	lck = os_atomic_inject_dependency(lck, value);
	fibers_mutex_unlock_fifo(ticket_lock_mtxs[((struct mock_hw_lck_ticket_t*)lck)->ticket_lock_mtx_idx]);
	MOCK__enable_preemption();
}

T_MOCK_F(void,
hw_lck_ticket_invalidate, (hw_lck_ticket_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		hw_lck_ticket_invalidate(lck);
		return;
	}

	// TODO
}

T_MOCK_F(bool,
hw_lck_ticket_held, (hw_lck_ticket_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		return hw_lck_ticket_held(lck);
	}

	return ticket_lock_mtxs[((struct mock_hw_lck_ticket_t*)lck)->ticket_lock_mtx_idx]->holder != NULL;
}

T_MOCK_F(hw_lock_status_t,
hw_lck_ticket_lock_to, (
	hw_lck_ticket_t        * lck,
	hw_spin_policy_t        pol,
	lck_grp_t              *grp),
(lck, pol, grp)
)
{
	if (!ut_mocks_use_fibers) {
		return hw_lck_ticket_lock_to(lck, pol, grp);
	}

	// Simple model as normal lock operation, may need more
	fibers_mutex_lock(ticket_lock_mtxs[((struct mock_hw_lck_ticket_t*)lck)->ticket_lock_mtx_idx], false);
	MOCK__disable_preemption(); // Disable preemption AFTER acquiring lock
	return HW_LOCK_ACQUIRED;
}

T_MOCK_F(bool,
hw_lck_ticket_lock_try, (hw_lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		return hw_lck_ticket_lock_try(lck, grp);
	}

	int ret = fibers_mutex_try_lock(ticket_lock_mtxs[((struct mock_hw_lck_ticket_t*)lck)->ticket_lock_mtx_idx]);
	if (ret == 0) {
		MOCK__disable_preemption();
		return true;
	}
	return false;
}

/*
 *  // For spinlocks
 *  T_MOCK_F(uint64_t,
 *  ml_get_hwclock_speculative, (void))
 *  {
 *       if (ut_mocks_use_fibers) {
 *               uint64_t val = ml_get_hwclock_speculative();
 *               return val / 100; // Avoid ticket lock timeouts
 *       }
 *
 *       return ml_get_hwclock_speculative();
 *  }
 */

// --------------- lck_ticket_t ------------------

T_MOCK_F(void,
lck_ticket_init, (lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		lck_ticket_init(lck, grp);
		return;
	}

	struct mock_lck_ticket_t *mlck = (struct mock_lck_ticket_t*)lck;
	mlck->lck_ticket_owner = 0;

	// Reuse hw_lck_ticket_t infrastructure
	MOCK_hw_lck_ticket_init((hw_lck_ticket_t*)&mlck->tu, grp);
}

T_MOCK_F(void,
lck_ticket_destroy, (lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		lck_ticket_destroy(lck, grp);
		return;
	}

	struct mock_lck_ticket_t *mlck = (struct mock_lck_ticket_t*)lck;
	MOCK_hw_lck_ticket_destroy((hw_lck_ticket_t*)&mlck->tu, grp);
}

T_MOCK_F(void,
lck_ticket_lock, (lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		lck_ticket_lock(lck, grp);
		return;
	}

	struct mock_lck_ticket_t *mlck = (struct mock_lck_ticket_t*)lck;
	MOCK_hw_lck_ticket_lock((hw_lck_ticket_t*)&mlck->tu, grp); // this handles preemption internally
	mlck->lck_ticket_owner = MOCK_current_thread_fast()->ctid;
}

T_MOCK_F(void,
lck_ticket_unlock, (lck_ticket_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		lck_ticket_unlock(lck);
		return;
	}

	struct mock_lck_ticket_t *mlck = (struct mock_lck_ticket_t*)lck;
	mlck->lck_ticket_owner = 0;
	MOCK_hw_lck_ticket_unlock((hw_lck_ticket_t*)&mlck->tu);
}

T_MOCK_F(void,
lck_ticket_lock_nopreempt, (lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		lck_ticket_lock_nopreempt(lck, grp);
		return;
	}

	struct mock_lck_ticket_t *mlck = (struct mock_lck_ticket_t*)lck;
	MOCK_hw_lck_ticket_lock_nopreempt((hw_lck_ticket_t*)&mlck->tu, grp);
	mlck->lck_ticket_owner = MOCK_current_thread_fast()->ctid;
}

T_MOCK_F(void,
lck_ticket_unlock_nopreempt, (lck_ticket_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		lck_ticket_unlock_nopreempt(lck);
		return;
	}

	struct mock_lck_ticket_t *mlck = (struct mock_lck_ticket_t*)lck;
	mlck->lck_ticket_owner = 0;
	MOCK_hw_lck_ticket_unlock_nopreempt((hw_lck_ticket_t*)&mlck->tu);
}

T_MOCK_F(bool,
lck_ticket_lock_try, (lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		return lck_ticket_lock_try(lck, grp);
	}

	struct mock_lck_ticket_t *mlck = (struct mock_lck_ticket_t*)lck;
	bool acquired = MOCK_hw_lck_ticket_lock_try((hw_lck_ticket_t*)&mlck->tu, grp); // This handles preemption internally
	if (acquired) {
		mlck->lck_ticket_owner = MOCK_current_thread_fast()->ctid;
	}
	return acquired;
}

T_MOCK_F(bool,
lck_ticket_lock_try_nopreempt, (lck_ticket_t * lck, lck_grp_t *grp), (lck, grp))
{
	if (!ut_mocks_use_fibers) {
		return lck_ticket_lock_try_nopreempt(lck, grp);
	}

	struct mock_lck_ticket_t *mlck = (struct mock_lck_ticket_t*)lck;

	// Similar to hw_lck_ticket_lock_try but without disable_preemption
	int ret = fibers_mutex_try_lock(ticket_lock_mtxs[mlck->tu.ticket_lock_mtx_idx]);
	if (ret == 0) {
		mlck->lck_ticket_owner = MOCK_current_thread_fast()->ctid;
		return true;
	}
	return false;
}

T_MOCK_F(void,
lck_ticket_assert_owned, (const lck_ticket_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		lck_ticket_assert_owned(lck);
		return;
	}

	const struct mock_lck_ticket_t *mlck = (const struct mock_lck_ticket_t*)lck;
	uint32_t current_ctid = MOCK_current_thread_fast()->ctid;
	PT_QUIET; PT_ASSERT_TRUE(mlck->lck_ticket_owner == current_ctid,
	    "lck_ticket_assert_owned: lock not owned by current thread");
}

T_MOCK_F(void,
lck_ticket_assert_not_owned, (const lck_ticket_t * lck), (lck))
{
	if (!ut_mocks_use_fibers) {
		lck_ticket_assert_not_owned(lck);
		return;
	}

	const struct mock_lck_ticket_t *mlck = (const struct mock_lck_ticket_t*)lck;
	uint32_t current_ctid = MOCK_current_thread_fast()->ctid;
	PT_QUIET; PT_ASSERT_TRUE(mlck->lck_ticket_owner != current_ctid,
	    "lck_ticket_assert_not_owned: lock is owned by current thread");
}

// --------------- waitq ------------------

#define MOCK_WAITQS_NUM 4096

struct mock_waitq_extra {
	bool valid;
	event64_t current_event; // for global waitqs to track their associated event
	fibers_condition_t cond;
	fibers_mutex_t mutex;
	struct mock_thread *waiting_threads;
	int waiting_thread_count;
};

struct mock_global_waitq {
	struct waitq wq;
	char padding[WQ_OPAQUE_SIZE - sizeof(struct waitq)];
	struct mock_waitq_extra extra;
};

#define WAITQ_HASH_SIZE 256
struct mock_waitq_hash_entry {
	struct waitq *wq;
	struct mock_waitq_extra *extra;
	struct mock_waitq_hash_entry *next;
};

struct mock_global_waitq global_mock_waitqs[MOCK_WAITQS_NUM];
struct mock_waitq_hash_entry *mock_waitq_hash_table[WAITQ_HASH_SIZE];

static inline size_t
mock_waitq_hash(struct waitq *wq)
{
	return ((uintptr_t)wq >> 6) % WAITQ_HASH_SIZE;
}

static inline struct mock_waitq_extra*
get_global_waitq_extra(struct waitq *wq)
{
	uintptr_t base = (uintptr_t)&global_mock_waitqs[0].wq;
	uintptr_t addr = (uintptr_t)wq;
	size_t stride = sizeof(struct mock_global_waitq);

	if (addr >= base && addr < base + (MOCK_WAITQS_NUM * stride)) {
		FIBERS_ASSERT(wq->waitq_type == WQT_QUEUE, "get_global_waitq_extra: global waitq %p has invalid type %d (must be WQT_QUEUE)", wq, wq->waitq_type);
		// extra is at offset WQ_OPAQUE_SIZE from wq due to padding
		return (struct mock_waitq_extra*)((char*)wq + WQ_OPAQUE_SIZE);
	}
	return NULL;
}

static struct mock_waitq_extra*
get_user_waitq_extra(struct waitq *wq)
{
	size_t idx = mock_waitq_hash(wq);
	for (struct mock_waitq_hash_entry *e = mock_waitq_hash_table[idx]; e; e = e->next) {
		if (e->wq == wq) {
			return e->extra;
		}
	}
	return NULL;
}

static inline struct mock_waitq_extra*
get_waitq_extra(struct waitq *wq)
{
	struct mock_waitq_extra *extra = get_global_waitq_extra(wq);
	return extra ? extra : get_user_waitq_extra(wq);
}

static bool
waitq_use_real_impl(waitq_t wq)
{
	waitq_type_t type = waitq_type(wq);
	return !ut_mocks_use_fibers || (type != WQT_QUEUE && type != WQT_TURNSTILE);
}

int
mock_waitq_init(struct waitq *wq)
{
	if (!wq) {
		return EINVAL;
	}

	struct mock_waitq_extra *extra = get_global_waitq_extra(wq);

	if (!extra) {
		// user created waitq, allocate and add to hash table
		extra = calloc(1, sizeof(struct mock_waitq_extra));

		struct mock_waitq_hash_entry *entry = calloc(1, sizeof(struct mock_waitq_hash_entry));
		entry->wq = wq;
		entry->extra = extra;

		size_t idx = mock_waitq_hash(wq);
		entry->next = mock_waitq_hash_table[idx];
		mock_waitq_hash_table[idx] = entry;
	}

	extra->valid = true;
	fibers_mutex_init(&extra->mutex);

	return 0;
}

int
mock_waitq_destroy(struct waitq *wq)
{
	if (!wq) {
		return EINVAL;
	}

	struct mock_waitq_extra *extra = get_waitq_extra(wq);
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "mock_waitq_destroy: no extra found");

	fibers_condition_destroy(&extra->cond);
	fibers_mutex_destroy(&extra->mutex);

	// if not global, remove from hash table and free
	if (!get_global_waitq_extra(wq)) {
		size_t idx = mock_waitq_hash(wq);
		struct mock_waitq_hash_entry **prev = &mock_waitq_hash_table[idx];

		bool found = false;
		while (*prev) {
			if ((*prev)->wq == wq) {
				struct mock_waitq_hash_entry *to_free = *prev;
				*prev = (*prev)->next;
				free(to_free->extra);
				free(to_free);
				found = true;
				break;
			}
			prev = &(*prev)->next;
		}

		FIBERS_ASSERT(found, "waitq %p not found in hash table at index %zu!\n", wq, idx);
	}

	return 0;
}

static inline bool
waitq_should_unlock(waitq_wakeup_flags_t flags)
{
	return (flags & (WAITQ_UNLOCK | WAITQ_KEEP_LOCKED)) == WAITQ_UNLOCK;
}

static inline bool
waitq_should_enable_interrupts(waitq_wakeup_flags_t flags)
{
	return (flags & (WAITQ_UNLOCK | WAITQ_KEEP_LOCKED | WAITQ_ENABLE_INTERRUPTS)) == (WAITQ_UNLOCK | WAITQ_ENABLE_INTERRUPTS);
}


T_MOCK_F(void,
waitq_init, (waitq_t wq, waitq_type_t type, int policy), (wq, type, policy))
{
	if (!ut_mocks_use_fibers || (type != WQT_QUEUE && type != WQT_TURNSTILE)) {
		waitq_init(wq, type, policy);
		return;
	}

	*wq.wq_q = (struct waitq){
		.waitq_type  = type,
		.waitq_fifo  = ((policy & SYNC_POLICY_REVERSED) == 0),
	};

	mock_waitq_init(wq.wq_q);

	if (policy & SYNC_POLICY_INIT_LOCKED) {
		struct mock_waitq_extra *extra = get_waitq_extra(wq.wq_q);
		fibers_mutex_lock(&extra->mutex, false);
	}
}

T_MOCK_F(void,
waitq_deinit, (waitq_t wq), (wq))
{
	if (waitq_use_real_impl(wq)) {
		waitq_deinit(wq);
		return;
	}

	mock_waitq_destroy(wq.wq_q);
}

T_MOCK_F(void,
waitq_lock, (waitq_t wq), (wq))
{
	if (waitq_use_real_impl(wq)) {
		waitq_lock(wq);
		return;
	}

	struct mock_waitq_extra *extra = get_waitq_extra(wq.wq_q);
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "waitq_lock: no extra found");
	fibers_mutex_lock(&extra->mutex, false);
}

T_MOCK_F(void,
waitq_unlock, (waitq_t wq), (wq))
{
	if (waitq_use_real_impl(wq)) {
		waitq_unlock(wq);
		return;
	}

	struct mock_waitq_extra *extra = get_waitq_extra(wq.wq_q);
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "waitq_unlock: no extra found");
	fibers_mutex_unlock(&extra->mutex);
}

T_MOCK_F(bool,
waitq_is_valid, (waitq_t wq), (wq))
{
	if (waitq_use_real_impl(wq)) {
		return waitq_is_valid(wq);
	}

	struct mock_waitq_extra *extra = get_waitq_extra(wq.wq_q);
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "waitq_is_valid: no extra found");
	return extra->valid;
}

T_MOCK_F(void,
waitq_invalidate, (waitq_t wq), (wq))
{
	if (waitq_use_real_impl(wq)) {
		return waitq_invalidate(wq);
	}

	struct mock_waitq_extra *extra = get_waitq_extra(wq.wq_q);
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "waitq_invalidate: no extra found");
	extra->valid = false;
}

T_MOCK_F(bool,
waitq_held, (waitq_t wq), (wq))
{
	if (waitq_use_real_impl(wq)) {
		return waitq_held(wq);
	}

	struct mock_waitq_extra *extra = get_waitq_extra(wq.wq_q);
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "waitq_held: no extra found");
	return extra->mutex.holder != NULL;
}

T_MOCK_F(void,
waitq_lock_wait, (waitq_t wq, uint32_t ticket), (wq, ticket))
{
	MOCK_waitq_lock(wq);
}

T_MOCK_F(bool,
waitq_lock_try, (waitq_t wq), (wq))
{
	if (waitq_use_real_impl(wq)) {
		return waitq_lock_try(wq);
	}

	struct mock_waitq_extra *extra = get_waitq_extra(wq.wq_q);
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "waitq_lock_try: no extra found");
	return fibers_mutex_try_lock(&extra->mutex) == 0;
}

// --------------- events ------------------

static int global_mock_waitqs_inited = 0;

__attribute__((constructor))
static void
global_mock_waitqs_init(void)
{
	if (!ut_mocks_use_fibers || global_mock_waitqs_inited) {
		return;
	}

	for (int i = 0; i < MOCK_WAITQS_NUM; ++i) {
		MOCK_waitq_init((struct waitq*)&global_mock_waitqs[i].wq, WQT_QUEUE, SYNC_POLICY_FIFO);
	}
	global_mock_waitqs_inited = 1;
}

struct waitq*
find_mock_waitq(event64_t event)
{
	if (!global_mock_waitqs_inited) {
		global_mock_waitqs_init();
	}
	for (int i = 0; i < MOCK_WAITQS_NUM; ++i) {
		if (global_mock_waitqs[i].extra.current_event == event) {
			return &global_mock_waitqs[i].wq;
		}
	}
	return NULL;
}

struct waitq*
find_or_alloc_mock_waitq(event64_t event)
{
	if (!global_mock_waitqs_inited) {
		global_mock_waitqs_init();
	}
	int first_free = -1;
	for (int i = 0; i < MOCK_WAITQS_NUM; ++i) {
		if (global_mock_waitqs[i].extra.current_event == event) {
			return &global_mock_waitqs[i].wq;
		} else if (first_free < 0 && global_mock_waitqs[i].extra.current_event == 0) {
			first_free = i;
		}
	}
	PT_QUIET; PT_ASSERT_TRUE(first_free >= 0, "no more space in global_mock_waitqs");
	global_mock_waitqs[first_free].extra.current_event = event;
	return &global_mock_waitqs[first_free].wq;
}

// --------------- waitq mocks ------------------

// pthread mocks

struct pthread_mock_event_table_entry*
find_pthread_mock_event_entry(struct mock_process_state *s, event_t ev)
{
	for (int i = 0; i < PTHREAD_EVENTS_TABLE_SIZE; ++i) {
		if (s->events[i].ev == ev) {
			return &s->events[i];
		}
	}
	return NULL;
}

T_MOCK_F(kern_return_t,
thread_wakeup_prim, (
	event_t event,
	boolean_t one_thread,
	wait_result_t result), (event, one_thread, result))
{
	if (ut_mocks_use_fibers) {
		// fibers is mocking waitq apis, go forward calling the real thread_wakeup_prim
		return thread_wakeup_prim(event, one_thread, result);
	}

	kern_return_t kr = KERN_SUCCESS;

	struct mock_process_state *s = get_proc_state();
	int ret = pthread_mutex_lock(&s->events_mutex);
	PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "thread_wakeup pthread_mutex_lock");

	struct pthread_mock_event_table_entry* event_entry = find_pthread_mock_event_entry(s, event);
	if (event_entry == NULL) {
		kr = KERN_NOT_WAITING;
		goto done;
	}
	if (one_thread) {
		ret = pthread_cond_signal(&event_entry->cond);
		PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "thread_wakeup pthread_cond_signal");
	} else {
		ret = pthread_cond_broadcast(&event_entry->cond);
		PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "thread_wakeup pthread_cond_broadcast");
	}
done:
	pthread_mutex_unlock(&s->events_mutex);
	return kr;
}

wait_result_t
pthread_mock_thread_block_reason(
	thread_continue_t continuation,
	void *parameter,
	ast_t reason)
{
	PT_QUIET; PT_ASSERT_TRUE(continuation == THREAD_CONTINUE_NULL && parameter == NULL && reason == AST_NONE, "thread_block argument");

	struct mock_process_state *s = get_proc_state();
	int ret = pthread_mutex_lock(&s->events_mutex);
	PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "thread_block pthread_mutex_lock");

	// find empty entry in table
	struct pthread_mock_event_table_entry *event_entry = find_pthread_mock_event_entry(s, 0);
	PT_QUIET; PT_ASSERT_NOTNULL(event_entry, "empty entry not found");

	// register the entry to this event
	event_entry->ev = (event_t)MOCK_current_thread_fast()->wait_event;

	// if it doesn't have a condition variable yet, create one
	if (!event_entry->cond_inited) {
		ret = pthread_cond_init(&event_entry->cond, NULL);
		PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "thread_block pthread_cond_init");
		event_entry->cond_inited = true;
	}

	// wait on variable. This releases the mutex, waits and reaquires it before returning
	ret = pthread_cond_wait(&event_entry->cond, &s->events_mutex);
	PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "thread_block pthread_cond_wait");

	// reset the entry so that it can be reused (will be done by all waiters that woke up)
	event_entry->ev = 0;

	ret = pthread_mutex_unlock(&s->events_mutex);
	PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "thread_block pthread_mutex_unlock");

	return THREAD_AWAKENED;
}

kern_return_t
pthread_mock_clear_wait(
	thread_t thread,
	wait_result_t result)
{
	struct mock_process_state *s = get_proc_state();
	int ret = pthread_mutex_lock(&s->events_mutex);
	PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "clear_wait pthread_mutex_lock");

	struct pthread_mock_event_table_entry *event_entry = find_pthread_mock_event_entry(s, 0);
	PT_QUIET; PT_ASSERT_NOTNULL(event_entry, "empty entry not found");

	event_entry->ev = 0;

	ret = pthread_mutex_unlock(&s->events_mutex);
	PT_QUIET; PT_ASSERT_POSIX_ZERO(ret, "clear_wait pthread_mutex_unlock");
	return KERN_SUCCESS;
}

// fibers mocks

T_MOCK_F(struct waitq *,
_global_eventq, (event64_t event), (event))
{
	if (!ut_mocks_use_fibers) {
		return _global_eventq(event);
	}

	struct waitq *ret = (struct waitq *)find_or_alloc_mock_waitq(event);
	FIBERS_ASSERT(get_global_waitq_extra(ret), "_global_eventq: global waitq %p not in the global map", ret);

	return ret;
}

T_MOCK_F(wait_result_t,
waitq_assert_wait64_locked, (
	waitq_t waitq,
	event64_t wait_event,
	wait_interrupt_t interruptible,
	wait_timeout_urgency_t urgency,
	uint64_t deadline,
	uint64_t leeway,
	thread_t thread), (waitq, wait_event, interruptible, urgency, deadline, leeway, thread))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_assert_wait64_locked(waitq, wait_event, interruptible, urgency, deadline, leeway, thread);
	}

	// check if thread was interrupted
	if (thread->sched_flags & TH_SFLAG_ABORT) {
		return THREAD_INTERRUPTED;
	}

	struct mock_waitq_extra *extra = get_waitq_extra(waitq.wq_q);

	PT_QUIET; PT_ASSERT_NOTNULL(waitq.wq_q, "waitq_assert_wait64_locked: NULL waitq");
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "waitq_assert_wait64_locked: NULL extra");
	PT_QUIET; PT_ASSERT_TRUE(extra->valid, "waitq_assert_wait64_locked: extra->valid is false");

	if (get_global_waitq_extra(waitq.wq_q)) {
		FIBERS_ASSERT(waitq.wq_q->waitq_type == WQT_QUEUE, "waitq_assert_wait64_locked: global waitq %p has invalid type %d (must be WQT_QUEUE)", waitq.wq_q, waitq.wq_q->waitq_type);
	}

	// verify mutex is held (this is "locked" variant)
	PT_QUIET; PT_ASSERT_TRUE(extra->mutex.holder == fibers_current,
	    "waitq_assert_wait64_locked: mutex not held by current fiber");

	FIBERS_LOG(FIBERS_LOG_DEBUG, "waitq_assert_wait64_locked wait_event=%lld", wait_event);

	struct mock_thread * mock_thread = (struct mock_thread*)thread; // !!! ASSUME every thread_t is created from mock_thread
	PT_QUIET; PT_ASSERT_NOTNULL(mock_thread, "waitq_assert_wait64_locked: NULL thread");

	// ensure wq_next is NULL before adding to list to prevent corruption
	// if thread is already in a waitq, this indicates a bug in the caller
	FIBERS_ASSERT(mock_thread->wq_next == NULL, "waitq_assert_wait64_locked: thread %p has non-NULL wq_next=%p, clearing to prevent list corruption\n", mock_thread, mock_thread->wq_next);

	mock_thread->wq_next = extra->waiting_threads;
	extra->waiting_threads = mock_thread;
	extra->waiting_thread_count++;

	thread->wait_event = wait_event; // Store waiting event in thread context
	thread->state |= TH_WAIT; // Set thread state to waiting
	thread->waitq = waitq;

	return THREAD_WAITING; // Indicate thread is now waiting, but not blocked yet
}

T_MOCK_F(wait_result_t,
waitq_assert_wait64, (
	struct waitq *waitq,
	event64_t wait_event,
	wait_interrupt_t interruptible,
	uint64_t deadline), (waitq, wait_event, interruptible, deadline))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_assert_wait64(waitq, wait_event, interruptible, deadline);
	}

	thread_t thread = MOCK_current_thread_fast();

	MOCK_waitq_lock(waitq);
	wait_result_t res = MOCK_waitq_assert_wait64_locked(waitq, wait_event, interruptible,
	    TIMEOUT_URGENCY_SYS_NORMAL, deadline, TIMEOUT_NO_LEEWAY, thread);
	MOCK_waitq_unlock(waitq);
	return res;
}

static void
mock_waitq_clear_wait(struct mock_thread * thread, struct mock_waitq_extra *extra)
{
	PT_QUIET; PT_ASSERT_NOTNULL(thread, "mock_waitq_clear_wait: NULL thread");
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "mock_waitq_clear_wait: NULL extra");
	PT_QUIET; PT_ASSERT_TRUE(extra->valid, "mock_waitq_clear_wait: extra->valid is false");

	struct mock_thread ** mock_thread = &extra->waiting_threads;
	int removed = 0;
	int iterations = 0;
	while (*mock_thread) {
		if (*mock_thread == thread) {
			*mock_thread = (*mock_thread)->wq_next;
			removed = 1;
			break;
		}
		mock_thread = &(*mock_thread)->wq_next;
	}
	PT_QUIET; PT_ASSERT_TRUE(removed, "thread_block thread not in wq");
	thread->wq_next = NULL;

	extra->waiting_thread_count--;
	PT_QUIET; PT_ASSERT_TRUE(extra->waiting_thread_count >= 0, "something bad");

	if (extra->waiting_thread_count == 0) {
		FIBERS_ASSERT(extra->waiting_threads == NULL, "extra->waiting_threads not NULL %p", extra->waiting_threads);
		extra->waiting_threads = NULL;
	}
}

static struct mock_thread *
mock_waitq_pop_wait(struct mock_waitq_extra *extra, event64_t wake_event)
{
	struct mock_thread **prev = &extra->waiting_threads;

	while (*prev) {
		struct mock_thread *thread = *prev;
		if (thread->th.wait_event == wake_event) {
			*prev = thread->wq_next;
			thread->wq_next = NULL;
			extra->waiting_thread_count--;
			PT_QUIET; PT_ASSERT_TRUE(extra->waiting_thread_count >= 0, "something bad");
			return thread;
		}
		prev = &thread->wq_next;
	}

	return NULL;
}

T_MOCK_F(wait_result_t,
thread_block_reason, (
	thread_continue_t continuation,
	void *parameter,
	ast_t reason), (continuation, parameter, reason))
{
	if (!ut_mocks_use_fibers) {
		return pthread_mock_thread_block_reason(continuation, parameter, reason);
	}

	PT_QUIET; PT_ASSERT_TRUE(continuation == THREAD_CONTINUE_NULL && parameter == NULL && reason == AST_NONE, "thread_block argument");

	thread_t thread = current_thread();

	// check if thread was interrupted
	if (thread->sched_flags & TH_SFLAG_ABORT) {
		return THREAD_INTERRUPTED;
	}

	PT_QUIET; PT_ASSERT_TRUE(thread->state & TH_WAIT, "thread_block called but thread is not aborted and state is not TH_WAIT");

	FIBERS_LOG(FIBERS_LOG_DEBUG, "thread_block_reason waitq=%p", thread->waitq);

	/*
	 * In case of a window between assert_wait and thread_block
	 * another thread could wake up the current thread after being added to the waitq
	 * but before the block.
	 * In this case, the thread will still be TH_WAIT but without an assigned waitq.
	 * TH_WAKING must be set.
	 */
	struct waitq *wq = thread->waitq.wq_q;
	if (wq == NULL) {
		PT_QUIET; PT_ASSERT_TRUE(thread->state & TH_WAKING, "with waitq == NULL there must be TH_WAKING set");
		thread->state &= ~TH_WAKING;
		goto awake_thread;
	}

	struct mock_waitq_extra *extra = get_waitq_extra(wq);
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "thread_block_reason: NULL extra");
	PT_QUIET; PT_ASSERT_TRUE(extra->valid, "thread_block_reason: extra->valid is false");

	fibers_condition_wait(&extra->cond);

	if (thread->state & TH_WAKING) {
		thread->state &= ~TH_WAKING;
	} else {
		// is this possible? TH_WAKING is always set ATM in the mocks, keep this code to be more robust
		mock_waitq_clear_wait((struct mock_thread *)thread, extra);
	}

awake_thread:
	thread->waitq.wq_q = NULL;
	thread->state &= ~TH_WAIT;
	thread->state |= TH_RUN;

	return thread->wait_result;
}

T_MOCK_F(kern_return_t,
clear_wait, (thread_t thread, wait_result_t wresult), (thread, wresult))
{
	if (!ut_mocks_use_fibers) {
		return pthread_mock_clear_wait(thread, wresult);
	}

	struct waitq *wq = thread->waitq.wq_q;
	PT_QUIET; PT_ASSERT_TRUE(wq != NULL, "thread->waitq is NULL");

	struct mock_waitq_extra *extra = get_waitq_extra(wq);
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "clear_wait: NULL extra");

	thread->state &= ~TH_WAIT;
	thread->waitq.wq_q = NULL;
	thread->wait_result = wresult;

	mock_waitq_clear_wait((struct mock_thread *)thread, extra);

	return KERN_SUCCESS;
}

typedef struct {
	wait_result_t wait_result;
	event64_t wake_event;
} waitq_wakeup_args_t;

static void
waitq_wakeup_fiber_callback(void *arg, fiber_t target)
{
	waitq_wakeup_args_t *wakeup_args = (waitq_wakeup_args_t*)arg;
	struct mock_thread *thread = (struct mock_thread *)target->extra;
	assert(thread);

	struct waitq *wq = thread->th.waitq.wq_q;
	assert(wq);

	struct mock_waitq_extra *extra = get_waitq_extra(wq);
	assert(extra);

	// Only wake threads waiting on the specified event
	if (thread->th.wait_event != wakeup_args->wake_event) {
		return;
	}

	thread->th.state |= TH_WAKING;
	thread->th.waitq.wq_q = NULL;
	thread->th.wait_result = wakeup_args->wait_result;

	mock_waitq_clear_wait(thread, extra);
}

// Called from thread_wakeup_nthreads_prim
T_MOCK_F(uint32_t,
waitq_wakeup64_nthreads_locked, (
	waitq_t waitq,
	event64_t wake_event,
	wait_result_t result,
	waitq_wakeup_flags_t flags,
	uint32_t nthreads), (waitq, wake_event, result, flags, nthreads))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_wakeup64_nthreads_locked(waitq, wake_event, result, flags, nthreads);
	}

	fibers_may_yield_internal_with_reason(
		FIBERS_YIELD_REASON_WAKEUP |
		FIBERS_YIELD_REASON_ORDER_PRE);

	// RANGELOCKINGTODO rdar://150846598 flags
	waitq_wakeup_args_t wakeup_args = {
		.wait_result = result,
		.wake_event = wake_event
	};
	int count = 0;

	struct mock_waitq_extra *extra = get_waitq_extra(waitq.wq_q);

	PT_QUIET; PT_ASSERT_NOTNULL(waitq.wq_q, "waitq_wakeup64_nthreads_locked: NULL waitq");
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "waitq_wakeup64_nthreads_locked: NULL extra");
	PT_QUIET; PT_ASSERT_TRUE(extra->valid, "waitq_wakeup64_nthreads_locked: extra->valid is false");

	if (get_global_waitq_extra(waitq.wq_q)) {
		FIBERS_ASSERT(waitq.wq_q->waitq_type == WQT_QUEUE, "waitq_wakeup64_nthreads_locked: global waitq %p has invalid type %d (must be WQT_QUEUE)", waitq.wq_q, waitq.wq_q->waitq_type);
	}

	// verify mutex is held (this is "locked" variant)
	PT_QUIET; PT_ASSERT_TRUE(extra->mutex.holder == fibers_current,
	    "waitq_wakeup64_nthreads_locked: mutex not held by current fiber");

	FIBERS_LOG(FIBERS_LOG_DEBUG, "waitq_wakeup64_nthreads_locked nthreads=%u wake_event=%lld", nthreads, wake_event);

	// Avoid to trigger a switch before a valid state in the waitq
	fibers_current->may_yield_disabled++;

	/*
	 * Manually iterate through waiting threads and wake only those matching the event.
	 * We need to use fibers_condition_wakeup_identified to wake specific fibers.
	 */
	struct mock_thread *thread = extra->waiting_threads;
	while (thread && count < nthreads) {
		struct mock_thread *next = thread->wq_next;
		/* // Yolo debugging check till ASan is still unsupported to run with the VM
		 *  if ((uintptr_t)thread < 0x1000) {
		 *       FIBERS_LOG(FIBERS_LOG_WARN, "waitq_wakeup64_nthreads_locked: ERROR corrupted thread pointer %p in waiting list for waitq %p (%s)", thread, waitq.wq_q, get_global_waitq_extra(waitq.wq_q) == NULL ? "user" : "global");
		 *       FIBERS_LOG(FIBERS_LOG_WARN, "  wake_event=%lld, count=%d, nthreads=%u, waiting_thread_count=%d", wake_event, count, nthreads, extra->waiting_thread_count);
		 *       FIBERS_ASSERT(0, "corrupted thread ptr");
		 *       extra->waiting_threads = NULL;
		 *       extra->waiting_thread_count = 0;
		 *       break;
		 *  }
		 */

		if (thread->th.wait_event == wake_event) {
			bool found = fibers_condition_wakeup_identified(&extra->cond, thread->fiber);
			if (found) {
				// fiber was waiting on the condition
				thread->th.state |= TH_WAKING;
				thread->th.waitq.wq_q = NULL;
				thread->th.wait_result = result;
				mock_waitq_clear_wait(thread, extra);
				++count;
			} else {
				// fiber not in condition queue yet (FIBER_STOP)
				PT_QUIET; PT_ASSERT_TRUE(thread->fiber->state & FIBER_STOP, "leftover fiber not in condition and not in FIBER_STOP");
				thread->th.state |= TH_WAKING;
				thread->th.waitq.wq_q = NULL;
				thread->th.wait_result = result;
				mock_waitq_clear_wait(thread, extra);
				++count;
			}
		}

		thread = next;
	}

	fibers_current->may_yield_disabled--;

post_wakeup:
	fibers_may_yield_internal_with_reason(
		FIBERS_YIELD_REASON_WAKEUP |
		FIBERS_YIELD_REASON_ORDER_POST |
		FIBERS_YIELD_REASON_ERROR_IF(count == 0));

	if (waitq_should_unlock(flags)) {
		MOCK_waitq_unlock(waitq);
	}
	if (waitq_should_enable_interrupts(flags)) {
		MOCK_ml_set_interrupts_enabled(1);
	}

	return (uint32_t)count;
}

T_MOCK_F(thread_t,
waitq_wakeup64_identify_locked, (
	waitq_t waitq,
	event64_t wake_event,
	waitq_wakeup_flags_t flags,
	bool *has_more), (waitq, wake_event, flags, has_more))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_wakeup64_identify_locked(waitq, wake_event, flags, has_more);
	}

	// RANGELOCKINGTODO rdar://150846598 flags

	struct mock_waitq_extra *extra = get_waitq_extra(waitq.wq_q);

	PT_QUIET; PT_ASSERT_NOTNULL(waitq.wq_q, "waitq_wakeup64_identify_locked: NULL waitq");
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "waitq_wakeup64_identify_locked: NULL extra");
	PT_QUIET; PT_ASSERT_TRUE(extra->valid, "waitq_wakeup64_identify_locked: extra->valid is false");

	// Find first thread waiting on this specific event
	struct mock_thread *mock_thread = extra->waiting_threads;
	while (mock_thread) {
		if (mock_thread->th.wait_event == wake_event) {
			break;
		}
		mock_thread = mock_thread->wq_next;
	}

	if (mock_thread == NULL) {
		return THREAD_NULL;
	}

	// Preemption will be re-enabled when the thread is resumed in `waitq_resume_identify_thread`
	MOCK__disable_preemption();

	mock_thread->th.state |= TH_WAKING;
	mock_thread->th.wait_result = THREAD_AWAKENED;
	/*
	 * Do not clean here waitq.wq_q so in the case thread_block is called before waitq_resume_identified_thread
	 * the thread will still be put in WAIT and waitq_resume_identified_thread will resume it correctly.
	 */
	// mock_thread->th.waitq.wq_q = NULL;

	mock_waitq_clear_wait(mock_thread, extra);

	FIBERS_LOG(FIBERS_LOG_DEBUG, "waitq_wakeup64_identify_locked identified fiber %d for event %lld", mock_thread->fiber->id, wake_event);

	if (waitq_should_unlock(flags)) {
		MOCK_waitq_unlock(waitq);
	}
	if (waitq_should_enable_interrupts(flags)) {
		MOCK_ml_set_interrupts_enabled(1);
	}

	fibers_may_yield_internal();

	return &mock_thread->th;
}

T_MOCK_F(void,
waitq_resume_identified_thread, (
	waitq_t waitq,
	thread_t thread,
	wait_result_t result,
	waitq_wakeup_flags_t flags), (waitq, thread, result, flags))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_resume_identified_thread(waitq, thread, result, flags);
	}

	// RANGELOCKINGTODO rdar://150846598 other flags

	fibers_may_yield_internal_with_reason(
		FIBERS_YIELD_REASON_WAKEUP |
		FIBERS_YIELD_REASON_ORDER_PRE);

	struct mock_thread * mock_thread = (struct mock_thread*)thread; // !!! ASSUME every thread_t is created from mock_thread
	struct mock_waitq_extra *extra = get_waitq_extra(waitq.wq_q);

	PT_QUIET; PT_ASSERT_NOTNULL(waitq.wq_q, "waitq_resume_identified_thread: NULL waitq");
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "waitq_resume_identified_thread: NULL extra");
	PT_QUIET; PT_ASSERT_TRUE(extra->valid, "waitq_resume_identified_thread: extra->valid is false");

	bool found = fibers_condition_wakeup_identified(&extra->cond, mock_thread->fiber);
	if (!found) {
		/*
		 * In case of a window in which a thread is pushed to the waitq but thread_block was still not called
		 * when the thread is identified by another one and resumed, we pop it from the waitq in waitq_wakeup64_identify_locked
		 * but we will not find it in wq->cond.wait_queue.
		 * In this case it is not needed any action as the fiber must be in FIBER_STOP and can already be scheduled.
		 * waitq.wq_q must be cleaned to prevent a thread_block call to put the thread on sleep.
		 */
		PT_QUIET; PT_ASSERT_TRUE(mock_thread->fiber->state & FIBER_STOP, "waitq_resume_identified_thread fiber not found in condition and not in FIBER_STOP");
		thread->waitq.wq_q = NULL;
	}

	// Paired with the call to `waitq_wakeup64_identify_locked`
	MOCK__enable_preemption();

	fibers_may_yield_internal_with_reason(
		FIBERS_YIELD_REASON_WAKEUP |
		FIBERS_YIELD_REASON_ORDER_POST);
}

T_MOCK_F(wait_result_t,
waitq_assert_wait64_leeway, (
	waitq_t waitq,
	event64_t wait_event,
	wait_interrupt_t interruptible,
	wait_timeout_urgency_t urgency,
	uint64_t deadline,
	uint64_t leeway), (waitq, wait_event, interruptible, urgency, deadline, leeway))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_assert_wait64_leeway(waitq, wait_event, interruptible, urgency, deadline, leeway);
	}

	thread_t thread = MOCK_current_thread_fast();
	spl_t s = 0;

	if (waitq_irq_safe(waitq)) {
		s = MOCK_ml_pac_safe_interrupts_disable();
	}
	MOCK_waitq_lock(waitq);

	wait_result_t ret = MOCK_waitq_assert_wait64_locked(waitq, wait_event, interruptible, urgency, deadline, leeway, thread);

	MOCK_waitq_unlock(waitq);
	if (waitq_irq_safe(waitq)) {
		MOCK_ml_pac_safe_interrupts_restore(s);
	}

	return ret;
}

T_MOCK_F(uint32_t,
waitq_wakeup64_nthreads, (
	waitq_t waitq,
	event64_t wake_event,
	wait_result_t result,
	waitq_wakeup_flags_t flags,
	uint32_t nthreads), (waitq, wake_event, result, flags, nthreads))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_wakeup64_nthreads(waitq, wake_event, result, flags, nthreads);
	}

	spl_t spl = 0;

	if (waitq_irq_safe(waitq)) {
		spl = MOCK_ml_pac_safe_interrupts_disable();
	}

	MOCK_waitq_lock(waitq);

	// Bypass __waitq_validate by calling the _locked variant directly
	return MOCK_waitq_wakeup64_nthreads_locked(waitq, wake_event, result,
	           flags | waitq_flags_splx(spl) | WAITQ_UNLOCK, nthreads);
}

T_MOCK_F(kern_return_t,
waitq_wakeup64_all, (
	waitq_t waitq,
	event64_t wake_event,
	wait_result_t result,
	waitq_wakeup_flags_t flags), (waitq, wake_event, result, flags))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_wakeup64_all(waitq, wake_event, result, flags);
	}

	uint32_t count = MOCK_waitq_wakeup64_nthreads(waitq, wake_event, result, flags, UINT32_MAX);
	return count ? KERN_SUCCESS : KERN_NOT_WAITING;
}

T_MOCK_F(kern_return_t,
waitq_wakeup64_one, (
	waitq_t waitq,
	event64_t wake_event,
	wait_result_t result,
	waitq_wakeup_flags_t flags), (waitq, wake_event, result, flags))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_wakeup64_one(waitq, wake_event, result, flags);
	}

	uint32_t count = MOCK_waitq_wakeup64_nthreads(waitq, wake_event, result, flags, 1);
	return count ? KERN_SUCCESS : KERN_NOT_WAITING;
}

T_MOCK_F(thread_t,
waitq_wakeup64_identify, (
	waitq_t waitq,
	event64_t wake_event,
	wait_result_t result,
	waitq_wakeup_flags_t flags), (waitq, wake_event, result, flags))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_wakeup64_identify(waitq, wake_event, result, flags);
	}

	spl_t spl = 0;

	if (waitq_irq_safe(waitq)) {
		spl = MOCK_ml_pac_safe_interrupts_disable();
	}

	MOCK_waitq_lock(waitq);

	// Bypass __waitq_validate by calling the _locked variant directly
	thread_t thread = MOCK_waitq_wakeup64_identify_locked(waitq, wake_event, flags | waitq_flags_splx(spl) | WAITQ_UNLOCK, NULL);

	if (thread != THREAD_NULL) {
		thread_reference(thread);
		MOCK_waitq_resume_identified_thread(waitq, thread, result, flags);
		return thread;
	}

	return THREAD_NULL;
}

T_MOCK_F(kern_return_t,
waitq_wakeup64_thread_and_unlock, (
	struct waitq *waitq,
	event64_t event,
	thread_t thread,
	wait_result_t result), (waitq, event, thread, result))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_wakeup64_thread_and_unlock(waitq, event, thread, result);
	}

	kern_return_t ret = KERN_NOT_WAITING;
	struct mock_thread *mock_thread = (struct mock_thread*)thread;
	struct mock_waitq_extra *extra = get_waitq_extra(waitq);

	PT_QUIET; PT_ASSERT_TRUE(waitq_irq_safe(waitq), "waitq_wakeup64_thread_and_unlock: waitq must be irq safe");
	PT_QUIET; PT_ASSERT_NOTNULL(extra, "waitq_wakeup64_thread_and_unlock: NULL extra");
	bool wq_held = MOCK_waitq_held(waitq);
	PT_QUIET; PT_ASSERT_TRUE(wq_held, "waitq_wakeup64_thread_and_unlock: waitq must be held");
	assert_thread_magic(thread);

	spl_t s = MOCK_ml_pac_safe_interrupts_disable();
	thread_lock(thread);

	if (waitq_same(thread->waitq, waitq) && thread->wait_event == event) {
		mock_waitq_clear_wait(mock_thread, extra);

		// clear thread's waitq state
		thread->state |= TH_WAKING;
		thread->waitq.wq_q = NULL;
		thread->wait_result = result;

		ret = KERN_SUCCESS;
	}

	// waitq_stats_count_wakeup(waitq, ret == KERN_SUCCESS ? 1 : 0);
	MOCK_waitq_unlock(waitq);

	if (ret == KERN_SUCCESS) {
		// wake up the fiber (similar to waitq_resume_identified_thread pattern, see the comments there)
		bool found = fibers_condition_wakeup_identified(&extra->cond, mock_thread->fiber);
		if (!found) {
			PT_QUIET; PT_ASSERT_TRUE(mock_thread->fiber->state & FIBER_STOP,
			    "waitq_wakeup64_thread_and_unlock: fiber not found in condition and not in FIBER_STOP");
		}
	}

	thread_unlock(thread);
	MOCK_ml_pac_safe_interrupts_restore(s);

	return ret;
}

T_MOCK_F(kern_return_t,
waitq_wakeup64_thread, (
	struct waitq *waitq,
	event64_t wake_event,
	thread_t thread,
	wait_result_t result), (waitq, wake_event, thread, result))
{
	if (waitq_use_real_impl(waitq)) {
		return waitq_wakeup64_thread(waitq, wake_event, thread, result);
	}

	spl_t s = MOCK_ml_pac_safe_interrupts_disable();
	kern_return_t ret;

	assert(waitq_irq_safe(waitq));
	MOCK_waitq_lock(waitq);

	ret = MOCK_waitq_wakeup64_thread_and_unlock(waitq, wake_event, thread, result);

	MOCK_ml_pac_safe_interrupts_restore(s);

	return ret;
}

// --------------- unmocked waitq API stubs ------------------
// These stub mocks warn about usage and call the original implementation

T_MOCK_F(bool,
waitq_lock_allow_invalid, (waitq_t wq), (wq))
{
	if (!waitq_use_real_impl(wq)) {
		raw_printf("WARNING: Unmocked waitq API called: %s\n", __FUNCTION__);
	}
	return waitq_lock_allow_invalid(wq);
}

T_MOCK_F(bool,
waitq_lock_reserve, (waitq_t wq, uint32_t *ticket), (wq, ticket))
{
	if (!waitq_use_real_impl(wq)) {
		raw_printf("WARNING: Unmocked waitq API called: %s\n", __FUNCTION__);
	}
	return waitq_lock_reserve(wq, ticket);
}

T_MOCK_F(void,
waitq_clear_promotion_locked, (
	waitq_t waitq,
	thread_t thread), (waitq, thread))
{
	if (!waitq_use_real_impl(waitq)) {
		raw_printf("WARNING: Unmocked waitq API called: %s\n", __FUNCTION__);
	}
	waitq_clear_promotion_locked(waitq, thread);
}

T_MOCK_F(bool,
waitq_pull_thread_locked, (
	waitq_t waitq,
	thread_t thread), (waitq, thread))
{
	if (!waitq_use_real_impl(waitq)) {
		raw_printf("WARNING: Unmocked waitq API called: %s\n", __FUNCTION__);
	}
	return waitq_pull_thread_locked(waitq, thread);
}

T_MOCK_F(void,
waitq_clear_prepost_locked, (struct waitq *waitq), (waitq))
{
	if (!waitq_use_real_impl(waitq)) {
		raw_printf("WARNING: Unmocked waitq API called: %s\n", __FUNCTION__);
	}
	waitq_clear_prepost_locked(waitq);
}

// Allow to cause a context switch from a function that can be called from XNU
T_MOCK_F(void,
ut_fibers_ctxswitch, (void), ())
{
	if (ut_mocks_use_fibers) {
		fibers_yield();
	}
}

// Allow to cause a context switch to a specific fiber from a function that can be called from XNU
T_MOCK_F(void,
ut_fibers_ctxswitch_to, (int fiber_id), (fiber_id))
{
	if (ut_mocks_use_fibers) {
		fibers_yield_to(fiber_id);
	}
}

// Get the current fiber id from a function that can be called from XNU
T_MOCK_F(int,
ut_fibers_current_id, (void), ())
{
	if (ut_mocks_use_fibers) {
		return fibers_current->id;
	}
	return -1;
}


// --------------- preemption ------------------

#ifdef __BUILDING_WITH_SANCOV_LOAD_STORES__

#define MOCK_LIB_INCLUDE_UT_FUZZ
#include "unit_test_fuzz.h"

// Optional: uncomment to enable yield at every basic block entry
/*
 *  T_MOCK_F(void,
 *  __sanitizer_cov_trace_pc_guard, (uint32_t * guard))
 *  {
 *	   fibers_may_yield();
 *  }
 */

#define IS_ALIGNED(ptr, size) ( (((uintptr_t)(ptr)) & (((uintptr_t)(size)) - 1)) == 0 )
#define IS_ATOMIC(ptr, size) ( (size) <= sizeof(uint64_t) && IS_ALIGNED(ptr, size) )

// These functions can be called from XNU to enter/exit atomic regions in which the data checker is disabled
T_MOCK_F(void,
data_race_checker_atomic_begin, (void), ())
{
	fibers_checker_atomic_begin();
}
T_MOCK_F(void,
data_race_checker_atomic_end, (void), ())
{
	fibers_checker_atomic_end();
}

/*
 * Detecting data races on memory operations:
 * Memory operation functions are used to check for data races using the fibers checkers API, a software implementation of DataCollider.
 * The idea is to set a watchpoint before context switching and report a data race every time a concurrent access (watchpoint hit) is in between a write or a write in between a load.
 * To be more robust, we also check that the value pointed the memory operation address before the context switch is still the same after the context switch.
 * If not, very likely it is a data race. Atomic memory operations should be excluded from this, we use the IS_ATOMIC macro to filter memory loads.
 * Note: atomic_fetch_add_explicit() et al. on ARM64 are compiled to LDADD et al. that seem to not be supported by __sanitizer_cov_loadX, ok for us we want to skip atomic operations.
 */
#define SANCOV_LOAD_STORE_DATA_CHECKER(type, size, access_type) do {                            \
	    if (fibers_current->may_yield_disabled || fibers_run_queue.count == 0) {                \
	        return;                                                                             \
	    }                                                                                       \
	    if (fibers_scheduler->fibers_should_yield(fibers_scheduler_context,                     \
	        fibers_may_yield_probability, FIBERS_YIELD_REASON_PREEMPTION_TRIGGER)) {            \
	        volatile type before = *addr;                                                       \
	        void *pc = __builtin_return_address(0);                                             \
	        bool has_wp = check_and_set_watchpoint(pc, (uintptr_t)addr, size, access_type);     \
                                                                                                \
	        fibers_queue_push(&fibers_run_queue, fibers_current);                               \
	        fibers_choose_next(FIBER_STOP);                                                     \
                                                                                                \
	        if (has_wp) {                                                                       \
	            post_check_and_remove_watchpoint((uintptr_t)addr, size, access_type);           \
	        }                                                                                   \
	        type after = *addr;                                                                 \
	        if (before != after) {                                                              \
	            report_value_race((uintptr_t)addr, size, access_type);                          \
	        }                                                                                   \
	    }                                                                                       \
	} while (0)

/*
 * Mock the SanitizerCoverage load/store instrumentation callbacks (original in san_attached.c).
 * The functions are execute at every memory operations in libxnu and in the test binary, libmocks is excluded.
 * Functions and files in tools/sanitizers-ignorelist are excluded from instrumentation.
 */
#define MOCK_SANCOV_LOAD_STORE(type, size)                                                                           \
	__attribute__((optnone))                                                                                         \
	_T_MOCK_INTERNAL(void,                                                                                           \
	__sanitizer_cov_load##size, (type* addr))                                                                        \
	{                                                                                                                \
	        fibers_fuzzing_feedback_trace(__builtin_return_address(0), false, (void*)addr);                          \
	        if (!ut_fibers_use_data_race_checker || IS_ATOMIC(addr, size) || fibers_current->disable_race_checker) { \
	                fibers_may_yield_with_reason(FIBERS_YIELD_REASON_PREEMPTION_TRIGGER);                            \
	                return;                                                                                          \
	        }                                                                                                        \
	        SANCOV_LOAD_STORE_DATA_CHECKER(type, size, ACCESS_TYPE_LOAD);                                            \
	}                                                                                                                \
                                                                                                                     \
	__attribute__((optnone))                                                                                         \
	_T_MOCK_INTERNAL(void,                                                                                           \
	__sanitizer_cov_store##size, (type* addr))                                                                       \
	{   /* do not care about atomicity for stores */                                                                 \
	        fibers_fuzzing_feedback_trace(__builtin_return_address(0), true, (void*)addr);                           \
	        if (!ut_fibers_use_data_race_checker || fibers_current->disable_race_checker) {                          \
	                fibers_may_yield_with_reason(FIBERS_YIELD_REASON_PREEMPTION_TRIGGER);                            \
	                return;                                                                                          \
	        }                                                                                                        \
	        SANCOV_LOAD_STORE_DATA_CHECKER(type, size, ACCESS_TYPE_STORE);                                           \
	}

MOCK_SANCOV_LOAD_STORE(uint8_t, 1)
MOCK_SANCOV_LOAD_STORE(uint16_t, 2)
MOCK_SANCOV_LOAD_STORE(uint32_t, 4)
MOCK_SANCOV_LOAD_STORE(uint64_t, 8)
MOCK_SANCOV_LOAD_STORE(__uint128_t, 16)

#endif // __BUILDING_WITH_SANCOV__
