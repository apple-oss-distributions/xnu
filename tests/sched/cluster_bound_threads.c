#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdatomic.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <spawn.h>
#include <pthread.h>
#include <TargetConditionals.h>
#include <sys/sysctl.h>
#include <os/tsd.h>
#include <machine/cpu_capabilities.h>
#include <sys/kdebug.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"
#include "sched_test_utils.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_BOOTARGS_SET("enable_skstb=1"),
    T_META_ASROOT(true),
    T_META_TAG_VM_NOT_ELIGIBLE,
    XNU_T_META_SOC_SPECIFIC);

static void *
spin_thread(__unused void *arg)
{
	spin_for_duration(8);
	return NULL;
}

static void *
spin_bound_thread(void *arg)
{
	char type = (char)arg;
	bind_to_cluster_of_type(type);
	spin_for_duration(10);
	return NULL;
}

#define SPINNER_THREAD_LOAD_FACTOR (4)

T_DECL(test_cluster_bound_thread_timeshare, "Make sure the low priority bound threads get CPU in the presence of non-bound CPU spinners",
    T_META_ENABLED(TARGET_CPU_ARM64 && TARGET_OS_OSX))
{
	pthread_setname_np("main thread");

	kern_return_t kr;

	int rv;
	pthread_attr_t attr;

	rv = pthread_attr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_init");

	rv = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_setdetachstate");

	rv = pthread_attr_set_qos_class_np(&attr, QOS_CLASS_USER_INITIATED, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_set_qos_class_np");

	unsigned int ncpu = (unsigned int)dt_ncpu();
	pthread_t unbound_thread;
	pthread_t bound_thread;

	wait_for_quiescence_default(argc, argv);
	trace_handle_t trace = begin_collect_trace(argc, argv, "test_cluster_bound_thread_timeshare");

	T_LOG("creating %u non-bound threads\n", ncpu * SPINNER_THREAD_LOAD_FACTOR);

	for (unsigned int i = 0; i < ncpu * SPINNER_THREAD_LOAD_FACTOR; i++) {
		rv = pthread_create(&unbound_thread, &attr, spin_thread, NULL);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_create (non-bound)");
	}

	struct sched_param param = { .sched_priority = (int)20 };
	T_ASSERT_POSIX_ZERO(pthread_attr_setschedparam(&attr, &param), "pthread_attr_setschedparam");

	rv = pthread_create(&bound_thread, &attr, spin_bound_thread, (void *)(uintptr_t)'P');
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_create (P-bound)");

	rv = pthread_attr_destroy(&attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_destroy");

	sleep(8);

	mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
	mach_port_t thread_port = pthread_mach_thread_np(bound_thread);
	thread_basic_info_data_t bound_thread_info;

	kr = thread_info(thread_port, THREAD_BASIC_INFO, (thread_info_t)&bound_thread_info, &count);
	if (kr != KERN_SUCCESS) {
		T_FAIL("%#x == thread_info(bound_thread, THREAD_BASIC_INFO)", kr);
	}

	end_collect_trace(trace);

	uint64_t bound_usr_usec = (uint64_t)bound_thread_info.user_time.seconds * USEC_PER_SEC + (uint64_t)bound_thread_info.user_time.microseconds;

	T_ASSERT_GT(bound_usr_usec, 75000ULL, "Check that bound thread got atleast 75ms CPU time");
	T_PASS("Low priority bound threads got some CPU time in the presence of high priority unbound spinners");
}

static uint64_t
observe_thread_user_time(pthread_t thread, unsigned int seconds)
{
	kern_return_t kr;
	mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
	mach_port_t port = pthread_mach_thread_np(thread);
	thread_basic_info_data_t basic_thread_info;
	uint64_t before_user_us = 0;
	uint64_t after_user_us = 0;

	kr = thread_info(port, THREAD_BASIC_INFO, (thread_info_t)&basic_thread_info, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info(THREAD_BASIC_INFO)");
	before_user_us = (uint64_t)basic_thread_info.user_time.seconds * USEC_PER_SEC +
	    (uint64_t)basic_thread_info.user_time.microseconds;

	sleep(seconds);

	kr = thread_info(port, THREAD_BASIC_INFO, (thread_info_t)&basic_thread_info, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info(THREAD_BASIC_INFO)");
	after_user_us = (uint64_t)basic_thread_info.user_time.seconds * USEC_PER_SEC +
	    (uint64_t)basic_thread_info.user_time.microseconds;

	T_QUIET; T_ASSERT_GE(after_user_us, before_user_us, "increasing user_time values");
	return after_user_us - before_user_us;
}

T_DECL(cluster_soft_binding,
    "Make sure that cluster-binding is \"soft\" and a bound thread can run elsewhere when"
    "its bound cluster is derecommended",
    T_META_ENABLED(TARGET_CPU_ARM64))
{
	T_SETUPBEGIN;
	if (!platform_is_amp()) {
		T_SKIP("Platform is symmetric, skipping cluster-binding test");
	}

	wait_for_quiescence_default(argc, argv);

	trace_handle_t trace = begin_collect_trace(argc, argv, "cluster_soft_binding");
	T_SETUPEND;

	for (int p = 0; p < 2; p++) {
		/* Ensure all cores recommended */
		char *restore_dynamic_control_args[] = {"-d", NULL};
		execute_clpcctrl(restore_dynamic_control_args, false);
		bool all_cores_recommended = check_recommended_core_mask(NULL);
		T_QUIET; T_EXPECT_TRUE(all_cores_recommended, "Not all cores are recommended for scheduling");

		void *arg;
		if (p == 0) {
			arg = (void *)'P';
		} else {
			arg = (void *)'E';
		}
		pthread_t bound_thread;
		create_thread(&bound_thread, NULL, spin_bound_thread, arg);
		sleep(1);

		double runtime_threshold = 0.2; // Ran at least 20% of expected time
		unsigned int observe_seconds = 3;
		uint64_t recommended_user_us = observe_thread_user_time(bound_thread, observe_seconds);
		T_LOG("%c-bound thread ran %lluus with all cores recommended", (char)arg, recommended_user_us);
		T_QUIET; T_EXPECT_GE(recommended_user_us * 1.0, runtime_threshold * observe_seconds * USEC_PER_SEC,
		    "%c-bound thread didn't run at least %f of %d seconds", (char)arg, runtime_threshold, observe_seconds);

		/* Derecommend the bound cluster type */
		char *derecommend_args[] = {"-C", "X", NULL};
		if (p == 0) {
			derecommend_args[1] = "e";
		} else {
			derecommend_args[1] = "p";
		}
		execute_clpcctrl(derecommend_args, false);
		check_recommended_core_mask(NULL);
		sleep(1);

		uint64_t derecommended_user_us = observe_thread_user_time(bound_thread, observe_seconds);
		T_LOG("%c-bound thread ran %lluus with %c-cores derecommended", (char)arg, derecommended_user_us, (char)arg);
		T_EXPECT_GE(recommended_user_us * 1.0, runtime_threshold * observe_seconds * USEC_PER_SEC,
		    "%c-bound thread ran at least %f of %d seconds when %c-cores were derecommended",
		    (char)arg, runtime_threshold, observe_seconds, (char)arg);
	}

	stop_spinning_threads();
	end_collect_trace(trace);
}

static int num_cluster_bind_trials = 100000;

static void *
spin_cluster_binding(void *)
{
	uint8_t num_clusters = COMM_PAGE_READ(uint8_t, CPU_CLUSTERS);
	for (int t = 0; t < num_cluster_bind_trials; t++) {
		int bind_cluster = rand() % (num_clusters + 1);
		bool unbind = bind_cluster == num_clusters;
		if (unbind) {
			bind_cluster = -1;
		}
		bind_to_cluster_id(bind_cluster);
		if (!unbind) {
			int running_on_cluster = (int)_os_cpu_cluster_number();
			T_QUIET; T_EXPECT_EQ(running_on_cluster, bind_cluster, "Failed to reach the bound cluster");
			if (running_on_cluster != bind_cluster) {
				T_LOG("Failed on iteration %d", t);
				/* Mark this failure in the recorded trace */
				kdebug_trace(ARIADNEDBG_CODE(0, 0), (uint64_t)t, (uint64_t)bind_cluster, (uint64_t)running_on_cluster, 0);
			}
		}
	}
	return NULL;
}

T_DECL(cluster_bind_migrate,
    "Ensure cluster-binding triggers a context-switch if needed to get to the bound cluster",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_MAYFAIL("rdar://132360557, need a reasonable expectation that cores will not quickly disable"))
{
	T_SETUPBEGIN;
	if (!platform_is_amp()) {
		T_SKIP("Platform is symmetric, skipping cluster-binding test");
	}

	char *policy_name = platform_sched_policy();
	if (strcmp(policy_name, "edge") != 0) {
		T_SKIP("Platform is running the \"%s\" scheduler, which lacks strong enough cluster-binding", policy_name);
	}

	wait_for_quiescence_default(argc, argv);
	bool all_cores_recommended = check_recommended_core_mask(NULL);
	T_QUIET; T_EXPECT_TRUE(all_cores_recommended, "Not all cores are recommended for scheduling");

	srand(777767777);

	trace_handle_t trace = begin_collect_trace(argc, argv, "cluster_bind_migrate");
	T_SETUPEND;

	pthread_t *threads = create_threads(dt_ncpu(), 31, eJoinable, QOS_CLASS_UNSPECIFIED,
	    eSchedDefault, DEFAULT_STACK_SIZE, spin_cluster_binding, NULL);
	for (int i = 0; i < dt_ncpu(); i++) {
		pthread_join(threads[i], NULL);
	}

	if (T_FAILCOUNT == 0) {
		T_PASS("Correctly migrated to the bound cluster for %d trials", num_cluster_bind_trials);
	} else {
		T_FAIL("%d fails for %d cluster-bind attempts", T_FAILCOUNT, num_cluster_bind_trials);
	}
	end_collect_trace(trace);
}
