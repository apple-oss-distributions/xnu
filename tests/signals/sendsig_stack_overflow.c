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
#include <spawn.h>
#include <stdlib.h>
#include <signal.h>
#include <mach/mach.h>
#include <excserver.h>
#include <sys/param.h>
#include <darwintest_utils.h>
#include <mach-o/dyld.h>

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("signals"),
	T_META_OWNER("m_staveleytaylor"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_CHECK_LEAKS(false),
	T_META_TAG_VM_PREFERRED,
	T_META_IGNORECRASHES(".*sendsig_stack_overflow.*")
	);

char tid_file[MAXPATHLEN];
int tid_fd;

mach_port_t
create_exception_port()
{
	kern_return_t kret;
	mach_port_t exc_port = MACH_PORT_NULL;
	mach_port_t task = mach_task_self();

	kret = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &exc_port);
	T_EXPECT_MACH_SUCCESS(kret, "mach_port_allocate exc_port");

	kret = mach_port_insert_right(task, exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
	T_EXPECT_MACH_SUCCESS(kret, "mach_port_insert_right exc_port");

	return exc_port;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winfinite-recursion"
[[clang::optnone]]
static void *
trigger_stack_overflow()
{
	/* Proof that AI doesn't make stack overflow obsolete. */
	return trigger_stack_overflow();
}
#pragma clang diagnostic pop

static void
signal_handler(int sig, siginfo_t *info, void *uap)
{
	/* Should never get invoked due to the SO */
	puts("unexpectedly in sigsegv handler");
	abort();
}

static void
handle_one_exception(mach_port_t exc_port)
{
	kern_return_t kr = mach_msg_server_once(mach_exc_server, 4096, exc_port, 0);
	T_EXPECT_MACH_SUCCESS(kr, "mach_msg_server_once");
}

/* Returns the PID of the spawned proc. */
static int
spawn_helper(char *helper_name, mach_port_t exc_port, const char *tid_file)
{
	T_SETUPBEGIN;
	char path[PATH_MAX] = {};
	uint32_t path_size = sizeof(path);
	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *helper_args[] = { path, "-n", helper_name, (char *)tid_file, NULL};
	pid_t child_pid = 0;

	/* Initialize posix_spawn attributes */
	posix_spawnattr_t attrs;
	posix_spawnattr_init(&attrs);

	int ret = posix_spawnattr_setexceptionports_np(&attrs, EXC_MASK_CRASH, exc_port,
	    (exception_behavior_t) (EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES), 0);
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_setexceptionports_np");

	ret = posix_spawn(&child_pid, helper_args[0], NULL, &attrs, helper_args, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn");
	T_QUIET; T_ASSERT_NE(child_pid, 0, "posix_spawn");
	T_SETUPEND;

	return child_pid;
}

static void
register_signal_handlers()
{
	T_SETUPBEGIN;
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = signal_handler;

	/* Try (and hopefully fail) to catch the stackoverflow */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sigaction(SIGBUS, &sa, NULL), "register SIGBUS handler");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sigaction(SIGSEGV, &sa, NULL), "register SIGSEGV handler");

	/* SIGILL handler should be forcibly ignored during the error path, so this won't do anything */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sigaction(SIGILL, &sa, NULL), "register SIGILL handler");

	T_SETUPEND;
}

static uint64_t
get_thread_id(thread_t thread)
{
	kern_return_t kr;
	mach_msg_type_number_t count = THREAD_IDENTIFIER_INFO_COUNT;
	thread_identifier_info_data_t data;
	kr = thread_info(thread, THREAD_IDENTIFIER_INFO, (thread_info_t)&data, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info");
	return data.thread_id;
}

kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count)
{
#pragma unused(exception_port, task, code_count)
	uint64_t actual_tid = get_thread_id(thread);
	T_LOG("Caught exception of type %d, code 0x%llx on thread %lld", exception, *code, actual_tid);

	uint64_t expected_tid = 0;
	int ret = read(tid_fd, &expected_tid, sizeof(expected_tid));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "read");
	T_QUIET; T_ASSERT_EQ(ret, (int)sizeof(expected_tid), "read bytes");
	T_ASSERT_EQ(actual_tid, expected_tid, "tid matches");

	return KERN_FAILURE; /* Move to next level handler */
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

static void
cleanup_tid_file()
{
	unlink(tid_file);
}

static void
create_tid_file()
{
	snprintf(tid_file, sizeof(tid_file), "%s/sendsig_stack_overflow-XXXXXX", dt_tmpdir());
	tid_fd = mkstemp(tid_file);
	T_ASSERT_POSIX_SUCCESS(tid_fd, "mkstemp tid file %s\n", tid_file);
	T_ATEND(cleanup_tid_file);
}

static void
write_tid_to_file(const char *tid_file)
{
	T_SETUPBEGIN;
	FILE *file = fopen(tid_file, "a");
	T_LOG("tid file is %s", tid_file);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(file, "open tid file");

	uint64_t tid = get_thread_id(mach_thread_self());
	T_LOG("writing tid %llu to file: %s", tid, tid_file);
	T_ASSERT_POSIX_SUCCESS(fwrite(&tid, sizeof(tid), 1, file), "fwrite");

	fclose(file);
	T_SETUPEND;
}

static void *
crashing_thread_entry(void *arg)
{
	write_tid_to_file((const char *)arg);

	T_LOG("triggering stack overflow...");
	return trigger_stack_overflow();
}


/*
 * The main thread and secondary threads differ in behaviour here.
 * handle_ux_exception has special logic to check if we overflowed the main thread's stack, and assuming there's no
 * alternate stack registered to handle it, we'll terminate the process with SIGSEGV.
 * For non-main threads, we'll end up with a SIGBUS, which sendsig will convert into a SIGILL when delivery fails.
 */
T_HELPER_DECL(sendsig_failure_helper_main_thread, "")
{
	write_tid_to_file(argv[0]);
	register_signal_handlers();

	T_LOG("triggering stack overflow...");
	trigger_stack_overflow();
}

T_HELPER_DECL(sendsig_failure_helper_nonmain_thread, "")
{
	register_signal_handlers();

	pthread_t t1;
	pthread_create(&t1, NULL, crashing_thread_entry, argv[0]);
	pthread_join(t1, NULL);
}

/*
 * This test checks that when signal delivery fails, we raise a Mach exception that points to the correct thread.
 *
 * The most common way signal delivery will fail is if the signal frame copyout fails, e.g due to stack overflow.
 *
 * In this scenario, what happens is the following:
 *     1. EXC_BAD_ACCESS is raised.
 *     2. ux_handler port converts the EXC_BAD_ACCESS into an appropriate signal (SIGSEGV or SIGBUS).
 *     3. sendsig tries to push a signal frame to the thread, but hits a fault during copyout.
 *     4. We fudge the task's signal mask and forcibly deliver a SIGILL that crashes the process.
 *     5. An EXC_CRASH exception is raised. We catch this in our test and ensure the TID of the thread port is correct.
 */
T_DECL(sendsig_failure, "sendsig behaviour in presence of stack overflows")
{
	int status, child_pid;

	mach_port_t exc_port = create_exception_port();

	/*
	 * To assert that our exception points to the correct thread, we need to send the expected
	 * thread ID from the spawned proc to the parent. Pass this information (hackily) in a tmpfile.
	 */
	create_tid_file();

	/*
	 * After we spawn the crashing process, we expect to see one EXC_CRASH exception. Respond to the
	 * message (and perform our assertions) before calling waitpid, as that'd block indefinitely.
	 */

	child_pid = spawn_helper("sendsig_failure_helper_main_thread", exc_port, tid_file);
	handle_one_exception(exc_port);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(child_pid, &status, 0), "waitpid");
	T_QUIET; T_ASSERT_FALSE(WIFEXITED(status), "exited abnormally");
	T_ASSERT_TRUE(WIFSIGNALED(status), "exited with a signal");
	T_ASSERT_TRUE(WTERMSIG(status) == SIGSEGV, "signal was: %s (expected SIGSEGV)", strsignal(WTERMSIG(status)));

	child_pid = spawn_helper("sendsig_failure_helper_nonmain_thread", exc_port, tid_file);
	handle_one_exception(exc_port);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(child_pid, &status, 0), "waitpid");
	T_QUIET; T_ASSERT_FALSE(WIFEXITED(status), "exited abnormally");
	T_ASSERT_TRUE(WIFSIGNALED(status), "exited with a signal");
	T_ASSERT_TRUE(WTERMSIG(status) == SIGILL, "signal was: %s (expected SIGILL)", strsignal(WTERMSIG(status)));
}
