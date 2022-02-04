#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <darwintest_utils.h>

#include <mach/mach.h>
#include <mach/task.h>
#include <mach/port.h>
#include <pthread.h>
#include <dispatch/dispatch.h>
#include <sys/proc.h>
#include <signal.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(NO));

#define BATCH 10
#define COUNT 4000

static int done;

static void *
thread_do_nothing(void *arg)
{
	return arg;
}

static void
thread_creation_bomb_one(void *_ctx __unused, size_t _i __unused)
{
	while (!done) {
		pthread_t th[BATCH];

		for (int i = 0; i < BATCH; i++) {
			int rc = pthread_create(&th[i], NULL, thread_do_nothing, NULL);
			T_QUIET; T_ASSERT_EQ(rc, 0, "pthread_create[%d]", i);
		}

		for (int i = 0; i < BATCH; i++) {
			int rc = pthread_join(th[i], NULL);
			T_QUIET; T_ASSERT_EQ(rc, 0, "pthread_join[%d]", i);
		}
	}
}

static void *
thread_creation_bomb(void *arg)
{
	done = 0;
	dispatch_apply_f((size_t)dt_ncpu(), DISPATCH_APPLY_AUTO, NULL,
	    thread_creation_bomb_one);
	return arg;
}

static void
test_race(const char *how, task_t task, pid_t pid)
{
	thread_array_t threadList;
	mach_msg_type_number_t threadCount = 0;
	kern_return_t kr;
	uint32_t ths = 0;

	T_LOG("Starting: %s (port: %#x, pid: %d)", how, task, pid);

	for (uint32_t n = 0; n < COUNT; n++) {
		kr = task_threads(task, &threadList, &threadCount);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_threads");

		for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
			mach_port_deallocate(mach_task_self(), threadList[i]);
		}

		vm_deallocate(mach_task_self(), (vm_address_t)threadList,
		    sizeof(threadList[0]) * threadCount);
		ths += threadCount;
	}

	T_PASS("Done %d loops of %s, found %d threads", COUNT, how, ths);

	if (task != mach_task_self()) {
		mach_port_deallocate(mach_task_self(), task);
	}

	if (pid) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	} else {
		done = 1;
	}
}

static void
local_test(bool control, task_t tp)
{
	pthread_t th;
	int rc;

	rc = pthread_create(&th, NULL, thread_creation_bomb, NULL);
	T_QUIET; T_ASSERT_EQ(rc, 0, "started job");

	test_race(control ? "local(ctl)" : "local(read)", tp, 0);

	rc = pthread_join(th, NULL);
	T_QUIET; T_ASSERT_EQ(rc, 0, "done");
}

static void
fork_child_test(bool control)
{
	task_t tp;
	pid_t pid;

	signal(SIGCHLD, SIG_IGN);

	pid = fork();
	if (pid == 0) {
		thread_creation_bomb(NULL);
		exit(0);
	}

	if (pid < 0) {
		T_ASSERT_POSIX_SUCCESS(pid, "fork");
	}

	if (control) {
		kern_return_t kr = task_for_pid(mach_task_self(), pid, &tp);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_for_pid");
	} else {
		int rc = task_read_for_pid(mach_task_self(), pid, &tp);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "task_read_for_pid");
	}

	test_race(control ? "remote(ctl)" : "remote(read)", tp, pid);
}

T_DECL(thred_ports_termination_race,
    "Test for various termination races with thread termination")
{
	kern_return_t kr;
	task_read_t tp;

	/*
	 * we must do the remote tests first so that we can fork()
	 * and still use dispatch.
	 */
	fork_child_test(true);

	fork_child_test(false);

	local_test(true, mach_task_self());

	kr = task_get_special_port(mach_task_self(), TASK_READ_PORT, &tp);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_get_special_port(TASK_READ_PORT)");
	local_test(false, tp);
}
