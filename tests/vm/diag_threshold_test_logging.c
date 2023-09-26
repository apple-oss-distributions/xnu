/**
 *  diag_threshold_test_logging.c
 *  diag_mem_threshold_logging_test
 *
 * Test that logs while sending signals between threads. That will
 * validate that test logging functionality will not have a reentrancy
 * issue.
 *
 * Copyright (c) 2023 Apple Inc. All rights reserved.
 */



#include <stdio.h>
#include "diag_threshold_test.h"
#include <sys/kern_memorystatus.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <TargetConditionals.h>


pthread_t thread_logger, thread_kicker;
static void *logger_thread(void *);
static void signal_handler(__unused int signo, __unused  siginfo_t *info, __unused void *extra);
static struct sigaction    original_action;                                           /**   Original signal handler for the process */
static void set_sig_handler(void);
static void *kicker_thread(__unused void *param);

static const double TESTING_TIME = 5.;
T_GLOBAL_META(
	T_META_ENABLED(TARGET_OS_IPHONE),
	T_META_NAMESPACE("xnu.vm.100432442"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("jsolsona"),
	T_META_RADAR_COMPONENT_VERSION("VM")
	);



T_DECL(diag_mem_threshold_logging_test,
    "Logging test, log while handling posix signals")
{
	//diag_mem_threshold_set_setup(&diag_mem_threshold_logging_test);
	int  iret1, iret2;
	iret1 = pthread_create( &thread_logger, NULL, logger_thread, (void*) NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(iret1, "Creation of the logging thread");
	iret2 = pthread_create( &thread_kicker, NULL, kicker_thread, (void*) NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(iret2, "Creation of the kick thread");
	pthread_join(thread_logger, NULL);
	pthread_join(thread_kicker, NULL);
}

/**
 *  Simple logger thread, sets a signal handler and logs for 10s
 */
static void *
logger_thread(__unused void *param)
{
	set_sig_handler();
	time_t t = time(NULL);
	while (difftime(time(NULL), t) < TESTING_TIME) {
		diag_mem_threshold_log_test("I am logging from a thread %f  seconds ", difftime(time(NULL), t));
	}
	return NULL;
}


/**
 *  Simple kicker thread, just send signals to the logger thread
 */
static void *
kicker_thread(__unused void *param)
{
	time_t t = time(NULL);
	while (difftime(time(NULL), t) < TESTING_TIME) {
		pthread_kill(thread_logger, SIGUSR1);
	}
	return NULL;
}

/**
 * Standard function to set a singal handler routine. Sets the handler for SIGUSR1 to the
 * termination_handler routine, and indeed terminates current thread.
 */
static void
set_sig_handler(void)
{
	struct sigaction action;

	action.sa_flags = SA_SIGINFO;
	action.sa_sigaction = signal_handler;

	T_QUIET; T_ASSERT_MACH_SUCCESS(sigaction(SIGUSR1, &action, &original_action), "Verification of adjustment of signal handler");
}

/**
 * Handler of the SIGUSR1 signal, just terminates the current thread.
 */
static void
signal_handler(__unused int signo, __unused  siginfo_t *info, __unused void *extra)
{
	static atomic_int recursion_level = 0;
	atomic_fetch_add_explicit(&recursion_level, 1, memory_order_relaxed);
	if (recursion_level == 1) {
		diag_mem_threshold_log_test("Logging from a signal handler");
	}
	atomic_fetch_sub_explicit(&recursion_level, 1, memory_order_relaxed);
}
