/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

/*
 * These tests verify that proc_pidinfo returns the expected exit reason and
 * namespace for signal-related process termination.
 */

#include <darwintest.h>
#include <signal.h>
#include <libproc.h>
#include <sys/wait.h>
#include <sys/reason.h>
#include <stdlib.h>
#include <dispatch/dispatch.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.misc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("misc"));

static dispatch_queue_t exit_queue;

static void
cleanup(void)
{
	dispatch_release(exit_queue);
}

static void
dispatch_test(void (^test)(void))
{
	// Use dispatch to schedule DISPATCH_PROC_EXIT blocks to read out exit reasons
	exit_queue = dispatch_queue_create("exit queue", DISPATCH_QUEUE_SERIAL);
	dispatch_async(dispatch_get_main_queue(), ^{
		test();
	});
	T_ATEND(cleanup);
	dispatch_main();
}

static void
check_exit_reason(int pid, uint64_t expected_reason_namespace, uint64_t expected_signal)
{
	T_LOG("check_exit_reason %d", expected_signal);
	int ret, status;
	struct proc_exitreasonbasicinfo exit_reason;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		ret = proc_pidinfo(pid, PROC_PIDEXITREASONBASICINFO, 1, &exit_reason, PROC_PIDEXITREASONBASICINFOSIZE),
		"verify proc_pidinfo success"
		);
	T_QUIET; T_ASSERT_EQ(ret, PROC_PIDEXITREASONBASICINFOSIZE, "retrieve basic exit reason info");

	waitpid(pid, &status, 0);
	T_QUIET; T_EXPECT_FALSE(WIFEXITED(status), "process did not exit normally");
	T_QUIET; T_EXPECT_TRUE(WIFSIGNALED(status), "process was terminated because of a signal");
	T_QUIET; T_EXPECT_EQ(WTERMSIG(status), expected_signal, "process should terminate due to signal %llu", expected_signal);

	T_EXPECT_EQ(exit_reason.beri_namespace, expected_reason_namespace, "expect OS_REASON_SIGNAL");
	T_EXPECT_EQ(exit_reason.beri_code, expected_signal, "expect reason code: %llu", expected_signal);
}

static void
wait_collect_exit_reason(int pid, int signal)
{
	dispatch_source_t ds_proc = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, pid, DISPATCH_PROC_EXIT, exit_queue);
	dispatch_semaphore_t sem = dispatch_semaphore_create(0);
	dispatch_source_set_event_handler(ds_proc, ^{
		check_exit_reason(pid, OS_REASON_SIGNAL, signal);
		dispatch_semaphore_signal(sem);
	});
	dispatch_activate(ds_proc);

	// Wait till exit reason is processed
	dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
	dispatch_release(ds_proc);
	dispatch_release(sem);
}

static void
__test_exit_reason_abort()
{
	pid_t child = fork();
	if (child > 0) {
		wait_collect_exit_reason(child, SIGABRT);
	} else {
		abort();
	}
}

T_DECL(test_exit_reason_abort, "tests exit reason for abort()")
{
	dispatch_test(^{
		__test_exit_reason_abort();
		T_END;
	});
}

static void
__test_exit_reason_external_signal(int signal)
{
	T_LOG("Testing external signal %d", signal);
	pid_t child = fork();
	if (child > 0) {
		// Send external signal
		kill(child, signal);
		wait_collect_exit_reason(child, signal);
	} else {
		pause();
	}
}

T_DECL(test_exit_reason_external_signal, "tests exit reason for external signals")
{
	dispatch_test(^{
		__test_exit_reason_external_signal(SIGABRT);
		__test_exit_reason_external_signal(SIGKILL);
		__test_exit_reason_external_signal(SIGSYS);
		__test_exit_reason_external_signal(SIGUSR1);
		T_END;
	});
}

struct pthread_kill_helper_args {
	pthread_t *pthread;
	int signal;
};

static void
pthread_kill_helper(void *msg)
{
	struct pthread_kill_helper_args *args = (struct pthread_kill_helper_args *)msg;
	pthread_kill(*args->pthread, args->signal);
}

static void
__test_exit_reason_pthread_kill_self(int signal)
{
	T_LOG("Testing pthread_kill for signal %d", signal);
	pid_t child = fork();
	if (child > 0) {
		wait_collect_exit_reason(child, signal);
	} else {
		pthread_t t;
		struct pthread_kill_helper_args args = {&t, signal};
		pthread_create(&t, NULL, pthread_kill_helper, (void *)&args);
		pthread_join(t, NULL);
	}
}

T_DECL(test_exit_reason_pthread_kill_self, "tests exit reason for pthread_kill on caller thread")
{
	dispatch_test(^{
		__test_exit_reason_pthread_kill_self(SIGABRT);
		__test_exit_reason_pthread_kill_self(SIGKILL);
		__test_exit_reason_pthread_kill_self(SIGSYS);
		__test_exit_reason_pthread_kill_self(SIGUSR1);
		T_END;
	});
}
