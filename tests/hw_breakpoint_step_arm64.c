#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <mach/arm/thread_status.h>
#include <mach/mach_traps.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/task.h>

#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>

#include <signal.h>
#include <spawn.h>
#include <spawn_private.h>
#include <stdatomic.h>

#include <excserver.h>
#include <sys/syslimits.h>

#define SYNC_TIMEOUT dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)

static dispatch_semaphore_t sync_sema;
static _Atomic bool after_kill;

kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count)
{
#pragma unused(exception_port, thread, task, code, code_count)
	if (exception == EXC_BREAKPOINT || (exception == EXC_CRASH && atomic_load_explicit(&after_kill,
	    memory_order_seq_cst))) {
		T_LOG("Received exception %d", exception);
		dispatch_semaphore_signal(sync_sema);
		return KERN_SUCCESS;
	}

	T_FAIL("invalid exception type: %d", exception);

	return KERN_FAILURE;
}

kern_return_t
catch_mach_exception_raise_state(mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_state_identity(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, thread, task, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state_identity");
	return KERN_NOT_SUPPORTED;
}

static void *
exc_handler(void * arg)
{
#pragma unused(arg)
	kern_return_t kret;
	mach_port_t exception_port;

	kret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port);
	if (kret != KERN_SUCCESS) {
		T_FAIL("mach_port_allocate: %s (%d)", mach_error_string(kret), kret);
	}

	kret = mach_port_insert_right(mach_task_self(), exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND);
	if (kret != KERN_SUCCESS) {
		T_FAIL("mach_port_insert_right: %s (%d)", mach_error_string(kret), kret);
	}

	kret = task_set_exception_ports(mach_task_self(), EXC_MASK_CRASH | EXC_MASK_BREAKPOINT, exception_port,
	    (exception_behavior_t)(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES), 0);
	if (kret != KERN_SUCCESS) {
		T_FAIL("task_set_exception_ports: %s (%d)", mach_error_string(kret), kret);
	}

	dispatch_semaphore_signal(sync_sema);

	kret = mach_msg_server(mach_exc_server, MACH_MSG_SIZE_RELIABLE, exception_port, 0);
	if (kret != KERN_SUCCESS) {
		T_FAIL("mach_msg_server: %s (%d)", mach_error_string(kret), kret);
	}

	return NULL;
}

T_HELPER_DECL(hw_breakpoint_helper, "hw_breakpoint_helper")
{
	while (1) {
		sleep(1);
	}
}

// Single instruction step
// (SS bit in the MDSCR_EL1 register)
#define SS_ENABLE ((uint32_t)(1u))

static void
step_thread(mach_port_name_t task, thread_t thread)
{
	kern_return_t kr;

	arm_debug_state64_t dbg;
	mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;

	kr = thread_get_state(thread, ARM_DEBUG_STATE64,
	    (thread_state_t)&dbg, &count);
	T_ASSERT_MACH_SUCCESS(kr, "get debug state for target thread");

	dbg.__mdscr_el1 |= SS_ENABLE;

	kr = thread_set_state(thread, ARM_DEBUG_STATE64,
	    (thread_state_t)&dbg, count);
	T_ASSERT_MACH_SUCCESS(kr, "set debug state for target thread");

	kr = task_resume(task);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "resume target task");

	long err = dispatch_semaphore_wait(sync_sema, SYNC_TIMEOUT);
	T_QUIET; T_ASSERT_EQ(err, 0L, "dispatch_semaphore_wait timeout");
}

T_DECL(hw_breakpoint_step, "Ensures that a process can be single-stepped using thread_set_state / ARM_DEBUG_STATE64", T_META_ASROOT(true),
    T_META_OWNER("Samuel Lepetit <slepetit@apple.com>"))
{
	kern_return_t kr;
	pthread_t handle_thread;
	sync_sema = dispatch_semaphore_create(0);

	T_ASSERT_POSIX_ZERO(pthread_create(&handle_thread, NULL, exc_handler, NULL), "pthread_create");
	long err = dispatch_semaphore_wait(sync_sema, SYNC_TIMEOUT);
	T_QUIET; T_ASSERT_EQ(err, 0L, "dispatch_semaphore_wait timeout");

	pid_t pid;
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);

	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");

	char *args[] = { path, "-n", "hw_breakpoint_helper", NULL };
	T_EXPECT_POSIX_ZERO(posix_spawn(&pid, args[0], NULL, NULL, args, NULL), "posix_spawn helper");

	mach_port_name_t task;
	kr = task_for_pid(mach_task_self(), pid, &task);
	T_ASSERT_TRUE(kr == KERN_SUCCESS, "task_for_pid");

	kr = task_suspend(task);
	T_QUIET; T_ASSERT_TRUE(kr == KERN_SUCCESS, "task_suspend");

	thread_array_t threads = NULL;
	mach_msg_type_number_t thread_count;
	kr = task_threads(task, &threads, &thread_count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_threads");

	step_thread(task, threads[0]);

	kr = task_suspend(task);
	T_QUIET; T_ASSERT_TRUE(kr == KERN_SUCCESS, "task_suspend");

	step_thread(task, threads[0]);

	atomic_store_explicit(&after_kill, 1, memory_order_seq_cst);
	T_ASSERT_POSIX_ZERO(kill(pid, SIGKILL), "kill target process");
}
