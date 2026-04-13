/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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
#include <darwintest.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>

#define NUM_THREADS 4
#define NUM_STEPS_PER_THREAD 50

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("misc"),
	T_META_OWNER("m_staveleytaylor"),
	T_META_RUN_CONCURRENTLY(true)
	);

typedef struct {
	int child_pid;
} thread_data_t;

[[clang::optnone]]
static void
spin_forever(void)
{
loop:   goto loop; /* the old school way */
}

static void *
stepper_thread(void *arg)
{
	thread_data_t *data = (thread_data_t *)arg;
	T_LOG("thread %p: starting to step child process %d", pthread_self(), data->child_pid);

	for (int steps_done = 0; steps_done < NUM_STEPS_PER_THREAD; steps_done++) {
		int ret = ptrace(PT_STEP, data->child_pid, (caddr_t)1, 0);
		if (ret != 0) {
			if (errno == EBUSY) {
				steps_done--;
				continue; /* target is running, try again in a moment */
			}
			T_WITH_ERRNO;
			T_ASSERT_POSIX_SUCCESS(ret, "thread %p: ptrace(PT_STEP) after %d steps", pthread_self(), steps_done);
		}
	}

	T_LOG("thread %p: completed %d steps", pthread_self(), NUM_STEPS_PER_THREAD);
	return NULL;
}

/*
 * Spawn a child process and hit it with concurrent ptrace(PT_STEP) calls to see what shakes out.
 * Previously, we had bugs in PT_STEP because we were not taking any lock. This was causing the
 * thread's state to get clobbered when calling PT_STEP concurrently, leading to panics. The test
 * here ensures we don't regress that. See e.g rdar://147670223.
 */
T_DECL(ptrace_step_multithreaded, "test that PT_STEP is thread-safe",
    T_META_ASROOT(true),
    T_META_TAG_VM_PREFERRED,
    T_META_ENABLED(/* TARGET_OS_OSX */ false) /* rdar://159282335 */)
{
	int status, ret;

	pid_t child_pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(child_pid, "fork()");
	if (child_pid == 0) {
		T_LOG("child process started with PID %d", getpid());

		spin_forever();
		exit(-1);
	}

	T_LOG("parent process: child PID is %d", child_pid);
	thread_data_t thread_data = { .child_pid = child_pid };

	ret = ptrace(PT_ATTACH, child_pid, 0, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "ptrace(PT_ATTACH)");

	T_LOG("creating %d threads to step child process", NUM_THREADS);
	pthread_t threads[NUM_THREADS];
	for (int i = 0; i < NUM_THREADS; i++) {
		ret = pthread_create(&threads[i], NULL, stepper_thread, &thread_data);
		T_ASSERT_POSIX_SUCCESS(ret, "pthread_create()");
	}

	T_LOG("joining %d threads", NUM_THREADS);
	for (int i = 0; i < NUM_THREADS; i++) {
		ret = pthread_join(threads[i], NULL);
		T_ASSERT_POSIX_SUCCESS(ret, "pthread_join()");
	}

	/* Detach and SIGKILL the child */
	ret = kill(child_pid, SIGSTOP);
	T_ASSERT_POSIX_SUCCESS(ret, "SIGSTOP child");

	do {
		/* The child might still be running, let's give it a chance to finish */
		ret = ptrace(PT_DETACH, child_pid, 0, 0);
	} while (ret == -1 && errno == EBUSY);
	T_ASSERT_POSIX_SUCCESS(ret, "PT_DETACH child");

	ret = kill(child_pid, SIGKILL);
	T_ASSERT_POSIX_SUCCESS(ret, "SIGKILL child");

	ret = waitpid(child_pid, &status, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "waitpid child");
	T_LOG("exited: %d, signaled: %d, stopped: %d", WIFEXITED(status), WIFSIGNALED(status), WIFSTOPPED(status));
	T_ASSERT_TRUE(WIFSIGNALED(status), "child was signaled");

	/* Note: SIGTRAP should not be possible here, but there's a remaining bug in concurrent PT_STEP. */
	T_ASSERT_TRUE(WTERMSIG(status) == SIGKILL || WTERMSIG(status) == SIGTRAP, "signaled with SIGKILL or SIGTRAP (was %s)", strsignal(WTERMSIG(status)));
}
