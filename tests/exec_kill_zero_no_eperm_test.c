// Copyright (c) 2025 Apple Inc.  All rights reserved.

#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <spawn.h>
#include <mach/mach.h>
#include <mach/semaphore.h>

#include <darwintest.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.exec"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("spawn"));

// Test parameters
#define KILL_ZERO_SPIN_ITERATIONS 5000
#define KILL_ZERO_SPIN_INTERVAL_USEC 50  // 50 microseconds between kill(pid, 0) calls
#define EXEC_PROGRAMS_COUNT 3

static volatile int stop_kill_spinning = 0;
static volatile int kill_zero_eperm_count = 0;
static volatile int kill_zero_total_count = 0;
static volatile int kill_zero_esrch_count = 0;

// Different exec programs to test various exec scenarios
static char *exec_programs[][3] = {
	{"/bin/sleep", "3", NULL},       // Simple sleep
	{"/usr/bin/true", NULL, NULL},   // Quick exit
	{"/bin/echo", "exec_test", NULL}, // Quick with output
};

// Thread that continuously spins on kill(pid, 0) to check PID validity
static void *
kill_zero_spin_thread(void *arg)
{
	pid_t *child_pid_ptr = (pid_t *)arg;
	pid_t child_pid;
	int result;

	T_LOG("Starting kill(pid, 0) spin thread, waiting for pid to be set");

	// Wait for child_pid to become non-zero (mimics launchd behavior)
	while (!stop_kill_spinning && *child_pid_ptr == 0) {
		usleep(1); // Brief pause while waiting for spawn
	}

	child_pid = *child_pid_ptr;
	if (child_pid == 0) {
		T_LOG("Thread exiting - no pid was set");
		return NULL;
	}

	T_LOG("Got pid %d, starting kill(pid, 0) spinning", child_pid);

	while (!stop_kill_spinning && kill_zero_total_count < KILL_ZERO_SPIN_ITERATIONS) {
		result = kill(child_pid, 0);
		kill_zero_total_count++;

		if (result != 0) {
			if (errno == ESRCH) {
				// Process has exited - this is expected eventually
				kill_zero_esrch_count++;
				T_LOG("Process %d no longer exists after %d kill(0) calls (ESRCH)",
				    child_pid, kill_zero_total_count);
				break;
			} else if (errno == EPERM) {
				// This should NEVER happen according to UNIX semantics
				kill_zero_eperm_count++;
				T_LOG("ERROR: EPERM on kill(pid, 0) call %d for pid %d - this violates UNIX semantics!",
				    kill_zero_total_count, child_pid);
			} else {
				// Other unexpected errors - these should cause test failure
				T_FAIL("Unexpected error %d (%s) on kill(pid, 0) call %d for pid %d",
				    errno, strerror(errno), kill_zero_total_count, child_pid);
			}
		}

		// Very short delay between checks to maximize race window
		if (KILL_ZERO_SPIN_INTERVAL_USEC > 0) {
			usleep(KILL_ZERO_SPIN_INTERVAL_USEC);
		}
	}

	T_LOG("kill(pid, 0) spin thread completed: %d total calls, %d EPERM errors, %d ESRCH",
	    kill_zero_total_count, kill_zero_eperm_count, kill_zero_esrch_count);
	return NULL;
}

// Thread function for rapid-fire kill(pid, 0) spinning with no delay
static void *
rapid_fire_kill_zero_spin_thread(void *arg)
{
	struct {
		pid_t pid;
		semaphore_t ready_sem;
	} *thread_args = arg;

	pid_t pid = thread_args->pid;
	int rapid_fire_calls = 0;

	// Signal that the thread is ready to start spinning
	kern_return_t kr = semaphore_signal(thread_args->ready_sem);
	T_ASSERT_MACH_SUCCESS(kr, "semaphore_signal");

	while (!stop_kill_spinning && rapid_fire_calls < 10000) {
		int result = kill(pid, 0);
		rapid_fire_calls++;

		if (result != 0) {
			if (errno == ESRCH) {
				T_LOG("Process %d exited after %d rapid kill(0) calls", pid, rapid_fire_calls);
				break;
			} else if (errno == EPERM) {
				kill_zero_eperm_count++;
				T_LOG("CRITICAL ERROR: EPERM on rapid kill(pid, 0) call %d", rapid_fire_calls);
			} else {
				// Other unexpected errors - these should cause test failure
				T_FAIL("Unexpected error %d (%s) on rapid kill(pid, 0) call %d for pid %d",
				    errno, strerror(errno), rapid_fire_calls, pid);
			}
		}

		// NO delay - maximum race condition detection
	}

	kill_zero_total_count = rapid_fire_calls;
	T_LOG("Rapid fire spinning completed: %d calls, %d EPERM errors",
	    rapid_fire_calls, kill_zero_eperm_count);
	return NULL;
}

static void
test_kill_zero_during_spawn(char **exec_args, const char *test_desc)
{
	T_LOG("Testing kill(pid, 0) during posix_spawn of %s", test_desc);

	// Reset counters for this test iteration
	stop_kill_spinning = 0;
	kill_zero_eperm_count = 0;
	kill_zero_total_count = 0;
	kill_zero_esrch_count = 0;

	pid_t child_pid = 0; // Initialize to 0 so thread can wait for it

	// Start the kill(pid, 0) spinning thread BEFORE spawning to catch even more races
	// This mimics launchd's internal behavior of spinning on the pid memory location
	pthread_t spin_thread;
	int ret = pthread_create(&spin_thread, NULL, kill_zero_spin_thread, &child_pid);
	T_ASSERT_POSIX_SUCCESS(ret, "pthread_create");

	T_LOG("Started kill(pid, 0) thread, now calling posix_spawn");

	// Use posix_spawn to create the process - this avoids fork() issues with libdarwintest
	int spawn_result = posix_spawn(&child_pid, exec_args[0], NULL, NULL, exec_args, NULL);
	T_ASSERT_POSIX_SUCCESS(spawn_result, "posix_spawn");

	T_LOG("Spawned process %d, thread should now detect it and start spinning", child_pid);

	// Let the spinning continue for a time to catch any spawn/initialization races
	usleep(100000); // 100ms should be enough for process startup

	// Stop the kill spinning
	stop_kill_spinning = 1;

	// Wait for spin thread to complete
	ret = pthread_join(spin_thread, NULL);
	T_ASSERT_POSIX_SUCCESS(ret, "pthread_join");

	// Critical assertion: kill(pid, 0) should NEVER return EPERM during spawn
	T_ASSERT_EQ(kill_zero_eperm_count, 0,
	    "kill(pid, 0) should never return EPERM during spawn - found %d EPERM errors in %d calls",
	    kill_zero_eperm_count, kill_zero_total_count);

	// Verify we actually performed multiple kill(pid, 0) calls
	T_ASSERT_GT(kill_zero_total_count, 10,
	    "Should have performed multiple kill(pid, 0) calls during spawn (got %d)",
	    kill_zero_total_count);

	// Clean up: wait for child to exit
	int status;
	pid_t waited_pid = waitpid(child_pid, &status, 0);
	T_ASSERT_EQ(waited_pid, child_pid, "waitpid");

	// Log the status and whether the process exited normally or was killed
	if (WIFEXITED(status)) {
		T_LOG("Process %d exited normally with status %d", child_pid, WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		T_LOG("Process %d was killed by signal %d", child_pid, WTERMSIG(status));
	} else {
		T_LOG("Process %d terminated with unknown status 0x%x", child_pid, status);
	}

	T_LOG("Test completed: %s - %d kill(pid, 0) calls, %d EPERM (should be 0), %d ESRCH",
	    test_desc, kill_zero_total_count, kill_zero_eperm_count, kill_zero_esrch_count);
}

T_DECL(exec_kill_zero_no_eperm,
    "Verify that kill(pid, 0) never returns EPERM during exec",
    T_META_TAG_VM_PREFERRED)
{
	T_LOG("Testing that kill(pid, 0) never fails with EPERM during exec()");
	T_LOG("UNIX semantics guarantee that kill(pid, 0) can be used to check PID validity");

	// Test with different exec scenarios to maximize race window coverage
	for (int i = 0; i < EXEC_PROGRAMS_COUNT; i++) {
		char **exec_args = exec_programs[i];
		char test_desc[256];
		snprintf(test_desc, sizeof(test_desc), "%s", exec_args[0]);

		test_kill_zero_during_spawn(exec_args, test_desc);

		// Brief pause between test iterations
		usleep(10000);
	}

	T_PASS("All exec scenarios completed without EPERM on kill(pid, 0)");
}

T_DECL(exec_kill_zero_no_eperm_stress,
    "Stress test kill(pid, 0) across many rapid exec operations",
    T_META_TAG_VM_PREFERRED)
{
	const int stress_iterations = 20;
	int total_kill_calls = 0;
	int total_eperm_errors = 0;

	T_LOG("Running stress test with %d rapid exec iterations", stress_iterations);

	for (int iteration = 0; iteration < stress_iterations; iteration++) {
		// Alternate between different exec programs for variety
		int prog_idx = iteration % EXEC_PROGRAMS_COUNT;
		char **exec_args = exec_programs[prog_idx];

		char test_desc[256];
		snprintf(test_desc, sizeof(test_desc), "iteration_%d_%s",
		    iteration + 1, exec_args[0]);

		T_LOG("Stress iteration %d/%d: %s", iteration + 1, stress_iterations, test_desc);

		test_kill_zero_during_spawn(exec_args, test_desc);

		// Accumulate statistics
		total_kill_calls += kill_zero_total_count;
		total_eperm_errors += kill_zero_eperm_count;

		// Very brief pause to avoid overwhelming the system
		usleep(5000);
	}

	T_LOG("Stress test completed: %d total kill(pid, 0) calls across %d iterations",
	    total_kill_calls, stress_iterations);

	// Critical verification: NO EPERM errors across all iterations
	T_ASSERT_EQ(total_eperm_errors, 0,
	    "kill(pid, 0) should never return EPERM - found %d EPERM errors across %d calls",
	    total_eperm_errors, total_kill_calls);

	// Verify we actually did significant testing
	T_ASSERT_GT(total_kill_calls, stress_iterations * 10,
	    "Should have performed substantial kill(pid, 0) testing");

	T_PASS("Stress test passed: %d kill(pid, 0) calls with 0 EPERM errors", total_kill_calls);
}

T_DECL(exec_kill_zero_very_rapid_spin,
    "Test kill(pid, 0) with very rapid spinning during exec",
    T_META_TAG_VM_PREFERRED)
{
	T_LOG("Testing kill(pid, 0) with minimal delay between calls during spawn");

	// Use /bin/sleep with longer duration to ensure spawn window
	char *long_sleep_args[] = {"/bin/sleep", "5", NULL};

	// Reset counters
	stop_kill_spinning = 0;
	kill_zero_eperm_count = 0;
	kill_zero_total_count = 0;
	kill_zero_esrch_count = 0;

	// Use posix_spawn instead of fork() + exec()
	pid_t child_pid;
	int spawn_result = posix_spawn(&child_pid, long_sleep_args[0], NULL, NULL, long_sleep_args, NULL);
	T_ASSERT_POSIX_SUCCESS(spawn_result, "posix_spawn");

	T_LOG("Starting rapid fire kill(pid, 0) spinning for pid %d", child_pid);

	// Create semaphore for thread synchronization
	semaphore_t thread_ready_sem;
	kern_return_t kr = semaphore_create(mach_task_self(), &thread_ready_sem, SYNC_POLICY_FIFO, 0);
	T_ASSERT_MACH_SUCCESS(kr, "semaphore_create");

	// Prepare thread arguments
	struct {
		pid_t pid;
		semaphore_t ready_sem;
	} thread_args = {
		.pid = child_pid,
		.ready_sem = thread_ready_sem
	};

	// Create spinning thread with no delay
	pthread_t spin_thread;
	int ret = pthread_create(&spin_thread, NULL, rapid_fire_kill_zero_spin_thread, &thread_args);
	T_ASSERT_POSIX_SUCCESS(ret, "pthread_create");

	// Wait for thread to be ready instead of using usleep
	kr = semaphore_wait(thread_ready_sem);
	if (kr != KERN_SUCCESS) {
		// Ensure thread is joined even on error to prevent access to invalid stack memory
		stop_kill_spinning = 1;
		pthread_join(spin_thread, NULL);
		T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait");
	}

	// Let rapid spinning continue during spawn/exec
	usleep(200000); // 200ms

	// Stop spinning
	stop_kill_spinning = 1;

	// Wait for spinner to complete - must always happen since thread references stack memory
	ret = pthread_join(spin_thread, NULL);
	T_ASSERT_POSIX_SUCCESS(ret, "pthread_join");

	// THE CRITICAL TEST: No EPERM should ever occur
	T_ASSERT_EQ(kill_zero_eperm_count, 0,
	    "Rapid fire kill(pid, 0) should never return EPERM during exec - got %d errors in %d calls",
	    kill_zero_eperm_count, kill_zero_total_count);

	T_ASSERT_GT(kill_zero_total_count, 100,
	    "Should have performed many rapid fire kill(pid, 0) calls (got %d)",
	    kill_zero_total_count);

	// Clean up child
	int status;
	pid_t waited_pid = waitpid(child_pid, &status, 0);
	T_ASSERT_EQ(waited_pid, child_pid, "waitpid");

	// Log the status and whether the process exited normally or was killed
	if (WIFEXITED(status)) {
		T_LOG("Process %d exited normally with status %d", child_pid, WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		T_LOG("Process %d was killed by signal %d", child_pid, WTERMSIG(status));
	} else {
		T_LOG("Process %d terminated with unknown status 0x%x", child_pid, status);
	}

	// Cleanup semaphore
	semaphore_destroy(mach_task_self(), thread_ready_sem);

	T_LOG("Rapid fire test completed: %d kill(pid, 0) calls with %d EPERM errors (should be 0)",
	    kill_zero_total_count, kill_zero_eperm_count);
}
