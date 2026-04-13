#include <darwintest.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <mach/mach.h>
#include <mach/exception.h>
#include <mach/thread_status.h>
#include <mach/mach_error.h>
#include <mach/port.h>
#include <string.h>
#include <errno.h>
#include <ptrauth.h>
#include <kern/exc_guard.h>
#include <semaphore.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "../exc_helpers.h"
#include "ipc_utils.h"

#if __x86_64__
#include <mach/i386/thread_status.h>
#endif

/* Include MIG-generated server prototypes */
extern boolean_t mach_exc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

#if __arm64__
#define EXCEPTION_THREAD_STATE          ARM_THREAD_STATE64
#define EXCEPTION_THREAD_STATE_COUNT    ARM_THREAD_STATE64_COUNT
#elif __x86_64__
#define EXCEPTION_THREAD_STATE          x86_THREAD_STATE64
#define EXCEPTION_THREAD_STATE_COUNT    x86_THREAD_STATE64_COUNT
#else
#error Unsupported architecture
#endif

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"));

/*
 * Helper function to check if a child exited with a guard exception
 */

bool did_receive_exc_tss = false;
static size_t
exception_handler_callback(
	task_id_token_t token,
	uint64_t thread_id,
	exception_type_t type,
	mach_exception_data_t codes,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count,
	thread_state_t out_state,
	mach_msg_type_number_t *out_state_count)
{
    #pragma unused(token, thread_id, type, in_state, in_state_count, out_state, out_state_count)
	T_LOG("Exception received successfully");

	uint32_t exc_guard_flavor = EXC_GUARD_DECODE_GUARD_FLAVOR(codes[0]);

	if (exc_guard_flavor == kGUARD_EXC_MACH_EXC_THREAD_SET_STATE) {
		did_receive_exc_tss = true;
	}

	/* Advance PC by 4 bytes to skip the faulting instruction */
	return 4;
}

T_DECL(mach_exc_interprocess_thread_state,
    "Test that inter-process exception handler cannot modify thread state")
{
	mach_port_t exc_port = MACH_PORT_NULL;
	mach_port_t child_task = MACH_PORT_NULL;
	mach_port_t child_thread = MACH_PORT_NULL;
	pid_t child_pid;
	int status;
	sem_t *sync_sem;
	char sem_name[32];

	T_LOG("Starting inter-process mach exception thread state test");

	/* Create a unique semaphore name */
	snprintf(sem_name, sizeof(sem_name), "/exc_sync_%d", getpid());

	/* Create shared semaphore for parent-child synchronization */
	sem_unlink(sem_name); /* Clean up any stale semaphore */
	sync_sem = sem_open(sem_name, O_CREAT | O_EXCL, 0644, 0);
	T_ASSERT_NE(sync_sem, SEM_FAILED, "sem_open");

	/* Fork child process first */
	child_pid = fork();
	T_ASSERT_NE(child_pid, -1, "fork");

	if (child_pid == 0) {
		/* Child process - will trigger exception and be handled by parent */
		T_LOG("Child process %d started", getpid());

		/* Wait for parent to set up exception handler */
		T_LOG("Child waiting for parent to signal readiness");
		int ret = sem_wait(sync_sem);
		T_ASSERT_POSIX_SUCCESS(ret, "sem_wait");
		T_LOG("Child received signal from parent, proceeding");

		/* Close semaphore in child */
		sem_close(sync_sem);

		/* Trigger EXC_BAD_ACCESS exception */
		T_LOG("Child triggering EXC_BAD_ACCESS exception");
		*(volatile int*)0 = 0;
		T_LOG("Child recovered");

		exit(0);
	} else {
		/* Parent process - will act as exception handler for child */
		T_LOG("Parent process %d waiting for child %d", getpid(), child_pid);

		/* Get child's task port */
		kern_return_t kr = task_for_pid(mach_task_self(), child_pid, &child_task);
		T_ASSERT_MACH_SUCCESS(kr, "task_for_pid");
		T_ASSERT_NE(child_task, MACH_PORT_NULL, "child task port");

		/* Create exception port for EXCEPTION_STATE_IDENTITY behavior */
		exc_port = create_exception_port_behavior64(EXC_MASK_ALL,
		    EXCEPTION_STATE_IDENTITY_PROTECTED);
		T_ASSERT_NE(exc_port, MACH_PORT_NULL, "create_exception_port_behavior64");
		T_LOG("Created exception port");

		/* Register exception handler on child's task */
		kr = task_set_exception_ports(child_task, EXC_MASK_ALL,
		    exc_port, EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES, EXCEPTION_THREAD_STATE);
		T_ASSERT_MACH_SUCCESS(kr, "task_set_exception_ports");
		T_LOG("Registered exception handler for child");

		/*
		 * Start exception handler thread that will attempt to handle the child's exception.
		 * When the child crashes, the parent's exception handler will receive the exception
		 * and try to modify the child's thread state via the MIG reply. This should trigger
		 * kGUARD_EXC_MACH_EXC_THREAD_SET_STATE because the parent doesn't have proper
		 * entitlements/permissions to modify the child's thread state.
		 */
		run_exception_handler_behavior64(exc_port, NULL, exception_handler_callback,
		    EXCEPTION_STATE_IDENTITY_PROTECTED, false);

		T_LOG("Exception handler thread started, signaling child to proceed");

		/* Signal child that exception handler is ready */
		int ret = sem_post(sync_sem);
		T_ASSERT_POSIX_SUCCESS(ret, "sem_post");

		/* Wait for child to complete or be terminated */
		int wait_result = waitpid(child_pid, &status, 0);
		T_ASSERT_EQ(wait_result, child_pid, "waitpid");

		T_EXPECT_TRUE(WIFEXITED(status), "child should exit normally");
		T_EXPECT_EQ(WEXITSTATUS(status), 0, "child exited with status 0");

		/* This might fail while we are in CA telemetry mode */
		T_MAYFAIL_WITH_RADAR(164960066);
		/* Child should have received guard exception */
		T_EXPECT_TRUE(did_receive_exc_tss,
		    "should have received kGUARD_EXC_MACH_EXC_THREAD_SET_STATE");

		/* Cleanup semaphore */
		sem_close(sync_sem);
		sem_unlink(sem_name);

		T_PASS("Inter-process mach exception thread state test completed");
	}

	/* Cleanup */
	if (exc_port != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), exc_port);
	}
	if (child_task != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), child_task);
	}
	if (child_thread != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), child_thread);
	}
}
