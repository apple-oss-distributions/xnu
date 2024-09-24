/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <mach/mach.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <darwintest_multiprocess.h>
#include <CrashReporterClient.h>

#include "exc_helpers.h"
#include "skywalk_test_driver.h"

#define SKT_DT_HELPER_TIMEOUT 16
#define SKT_DT_NUM_HELPERS    1

#define test_exit(ecode)                                                                           \
	{                                                                                          \
	        T_LOG("%s:%d := Test exiting with error code %d\n", __func__, __LINE__, (ecode));  \
	        T_END;                                                                             \
	}

static mach_port_t exc_port;
static mach_exception_data_type_t exception_code;
static mach_exception_data_type_t expected_exception_code;
static mach_exception_data_type_t expected_exception_code_ignore;
static uint64_t skywalk_features;
static bool testing_shutdown_sockets;
static bool ignore_test_failures;
bool skywalk_in_driver;

boolean_t
mach_exc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt)
{
	/* Set global variable to indicate exception received */
	if (exception != EXC_CRASH && exception != EXC_GUARD) {
		T_LOG("Unexpected exception received: %d", exception);
		test_exit(1);
		return KERN_FAILURE;
	}

	exception_code = *code;

	if (!ignore_test_failures) {
		/* If the exception code is unexpected,
		 * return failure so we generate a crash report.
		 */
		if ((exception_code ^ expected_exception_code)
		    & ~expected_exception_code_ignore) {
			return KERN_FAILURE;
		}
	}

	/* Return KERN_SUCCESS to prevent report crash from being called. */
	return KERN_SUCCESS;
}

kern_return_t
catch_mach_exception_raise_state(mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt)
{
	T_LOG("Unexpected exception handler called: %s", __func__);
	test_exit(1);
	return KERN_FAILURE;
}

kern_return_t
catch_mach_exception_raise_state_identity(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt)
{
	T_LOG("Unexpected exception handler called: %s", __func__);
	test_exit(1);
	return KERN_FAILURE;
}

static void *
server_thread(void *arg)
{
	kern_return_t kr;

	while (1) {
		/* Handle exceptions on exc_port */
		if ((kr = mach_msg_server_once(mach_exc_server, 4096, exc_port, 0)) != KERN_SUCCESS) {
			mach_error("mach_msg_server_once", kr);
			test_exit(1);
		}
	}
	return NULL;
}


static void
skywalk_test_driver_init(bool test_shutdown, bool ignore_failures)
{
	kern_return_t kr;
	pthread_t exception_thread;
	int error;
	size_t len;

	assert(!exc_port); // This routine can only be called once

	skywalk_in_driver = true;

	testing_shutdown_sockets = test_shutdown;
	ignore_test_failures = ignore_failures;

	/* Allocate and initialize new exception port */
	if ((kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port)) != KERN_SUCCESS) {
		mach_error("mach_port_allocate", kr);
		test_exit(1);
	}

	if ((kr = mach_port_insert_right(mach_task_self(), exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND)) != KERN_SUCCESS) {
		mach_error("mach_port_insert_right", kr);
		test_exit(1);
	}

	/* Create exception serving thread */
	if ((error = pthread_create(&exception_thread, NULL, server_thread, 0)) != 0) {
		T_LOG("pthread_create server_thread: %s\n", strerror(error));
		test_exit(1);
	}

	/* Query the kernel for available skywalk features */
	len = sizeof(skywalk_features);
	sysctlbyname("kern.skywalk.features", &skywalk_features, &len, NULL, 0);

	pthread_detach(exception_thread);
}

int
skywalk_test_driver_run(struct skywalk_test *skt, int argc, char **argv,
    uint32_t memfail, bool ignorefail, bool doshutdown, int itersecs)
{
	kern_return_t kr;
	mach_msg_type_number_t maskCount;
	exception_mask_t masks[2];
	exception_handler_t handlers[2];
	exception_behavior_t behaviors[2];
	thread_state_flavor_t flavors[2];
	int pid, child_status;
	int testid;
	size_t len;
	int error;
	int itercount = -1;
	struct timeval start, end;
	uint32_t memfail_original;

	len = sizeof(memfail_original);
	if (sysctlbyname("kern.skywalk.mem.region_mtbf", &memfail_original, &len, NULL, 0) != 0) {
		SKT_LOG("warning got errno %d getting kern.skywalk.mem.region_mtbf: %s\n",
		    errno, strerror(errno));
	}
	if (memfail_original) {
		CRSetCrashLogMessage("kern.skywalk.mem.region_mtbf was found already set");
	}

	if (memfail) {
		CRSetCrashLogMessage("parent set kern.skywalk.mem.region_mtbf");
	}
	T_LOG("setting kern.skywalk.mem.region_mtbf to %"PRId32, memfail);
	len = sizeof(memfail);
	if (sysctlbyname("kern.skywalk.mem.region_mtbf", NULL, NULL, &memfail, len) != 0) {
		SKT_LOG("warning got errno %d setting kern.skywalk.mem.region_mtbf: %s",
		    errno, strerror(errno));
	}

	skywalk_test_driver_init(doshutdown, ignorefail);

	gettimeofday(&start, NULL);

	do {
		/* Get Current exception ports */
		if ((kr = task_get_exception_ports(mach_task_self(), EXC_MASK_GUARD | EXC_MASK_CRASH, masks, &maskCount, handlers, behaviors, flavors))
		    != KERN_SUCCESS) {
			mach_error("task_get_exception_ports", kr);
			test_exit(1);
		}
		assert(maskCount <= 2);
		exception_code = 0;

		if (skt->skt_init != NULL) {
			T_LOG("Running init");
			skt->skt_init();
		}

		expected_exception_code = skt->skt_expected_exception_code;
		expected_exception_code_ignore = skt->skt_expected_exception_code_ignore;

		for (int j = 0; j < maskCount; j++) {
			// Set Exception Ports for Current Task
			if ((kr = task_set_exception_ports(mach_task_self(), masks[j], exc_port,
			    EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, flavors[j])) != KERN_SUCCESS) {
				mach_error("task_set_exception_ports", kr);
				test_exit(1);
			}
		}

		pid = fork();
		if (pid == 0) {
			int ret;

			len = sizeof(memfail_original);
			if (sysctlbyname("kern.skywalk.mem.region_mtbf", &memfail_original, &len, NULL, 0) != 0) {
				SKT_LOG("warning got errno %d getting kern.skywalk.mem.region_mtbf: %s\n",
				    errno, strerror(errno));
			}
			if (memfail_original) {
				CRSetCrashLogMessage("kern.skywalk.mem.region_mtbf was found already set");
			}

			ret = skt->skt_main(argc, argv);
			/* return ret; results in "Unresolved" test results */
			exit(ret);
		}
		T_QUIET;
		T_ASSERT_GT(pid, 0, "pid must be > 0");

		/* Restore exception ports for parent */
		for (int j = 0; j < maskCount; j++) {
			if ((kr = task_set_exception_ports(mach_task_self(), masks[j], handlers[j],
			    EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, flavors[j])) != KERN_SUCCESS) {
				mach_error("task_set_exception_ports reset", kr);
				test_exit(1);
			}
		}

		if (testing_shutdown_sockets) {
			int shutdown_cnt = 0;

			while (1) {
				struct timespec st = { .tv_sec = 0, .tv_nsec = 0 };
				/*
				 * st.tv_nsec = arc4random_uniform(1000000);  // 0-1 ms
				 * st.tv_nsec = arc4random_uniform(10000000); // 0-10 ms
				 */
				st.tv_nsec = arc4random_uniform(100000000); /* 0-100 ms */
				nanosleep(&st, NULL);

				error = pid_shutdown_sockets(pid, SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL);
				if (error) {
					break;
				}

				shutdown_cnt++;
			}

			if (error == -1 && errno != ESRCH) {
				SKT_LOG(stderr, "pid_shutdown_sockets: %s", strerror(errno));
				test_exit(1);
			}

			T_LOG("shutdown cnt %d", shutdown_cnt);
		}

		waitpid(pid, &child_status, 0);
		T_LOG("child_status: %d", child_status);

		if (skt->skt_fini != NULL) {
			T_LOG("Running fini");
			skt->skt_fini();
		}

		if (WIFEXITED(child_status)) {
			T_LOG("Child exited with status %d", WEXITSTATUS(child_status));
		}
		if (WIFSIGNALED(child_status)) {
			T_LOG("Child signaled with signal %d coredump %d", WTERMSIG(child_status), WCOREDUMP(child_status));
		}

		if (exception_code) {
			T_LOG("Got exception code:      Yes (Code 0x%llx)", exception_code);
		} else {
			T_LOG("Got exception code:      No");
		}
		if (skt->skt_expected_exception_code & ~skt->skt_expected_exception_code_ignore) {
			T_LOG("Expected exception code: Yes (Code 0x%llx, ignore 0x%llx)",
			    skt->skt_expected_exception_code, skt->skt_expected_exception_code_ignore);
		} else {
			T_LOG("Expected exception code: No");
		}

		if ((WIFEXITED(child_status) && WEXITSTATUS(child_status)) ||
		    ((exception_code ^ skt->skt_expected_exception_code) &
		    ~skt->skt_expected_exception_code_ignore)) {
			if (ignorefail) {
				T_PASS("Returning overall success because"
				    " ignorefail is set for Test %s: %s",
				    skt->skt_testname, skt->skt_testdesc);
			} else {
				T_FAIL("Test %s: %s", skt->skt_testname, skt->skt_testdesc);
			}
		} else {
			T_PASS("Test %s: %s", skt->skt_testname, skt->skt_testdesc);
		}

		gettimeofday(&end, NULL);
		gettimeofday(&end, NULL);
		timersub(&end, &start, &end);
	} while (--itercount > 0 || end.tv_sec < itersecs);

	memfail = 0;
	T_LOG("setting kern.skywalk.mem.region_mtbf to %"PRId32, memfail);
	len = sizeof(memfail);
	if (sysctlbyname("kern.skywalk.mem.region_mtbf", NULL, NULL, &memfail, len) != 0) {
		SKT_LOG("warning got errno %d setting kern.skywalk.mem.region_mtbf: %s",
		    errno, strerror(errno));
	}
	return 0;
}
