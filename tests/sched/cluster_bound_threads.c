#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <TargetConditionals.h>
#include <sys/sysctl.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"
#include "sched_test_utils.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"));


static void *
spin_thread(__unused void *arg)
{
	spin_for_duration(8);
	return NULL;
}

static void
bind_to_cluster(char type)
{
	char old_type;
	size_t type_size = sizeof(type);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.sched_thread_bind_cluster_type",
	    &old_type, &type_size, &type, sizeof(type)),
	    "bind current thread to cluster %c", type);
}

static void *
spin_bound_thread(void *arg)
{
	char type = (char)arg;
	bind_to_cluster(type);
	spin_for_duration(10);
	return NULL;
}

#define SPINNER_THREAD_LOAD_FACTOR (4)

T_DECL(test_cluster_bound_thread_timeshare, "Make sure the low priority bound threads get CPU in the presence of non-bound CPU spinners",
    T_META_BOOTARGS_SET("enable_skstb=1"), T_META_ASROOT(true), T_META_ENABLED(TARGET_CPU_ARM64 && TARGET_OS_OSX), XNU_T_META_SOC_SPECIFIC, T_META_TAG_VM_NOT_ELIGIBLE)
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

	wait_for_quiescence_default();
	trace_handle_t trace = begin_collect_trace("test_cluster_bound_thread_timeshare");

	T_LOG("creating %u non-bound threads\n", ncpu * SPINNER_THREAD_LOAD_FACTOR);

	for (int i = 0; i < ncpu * SPINNER_THREAD_LOAD_FACTOR; i++) {
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

	uint64_t bound_usr_usec = bound_thread_info.user_time.seconds * USEC_PER_SEC + bound_thread_info.user_time.microseconds;

	T_ASSERT_GT(bound_usr_usec, 75000, "Check that bound thread got atleast 75ms CPU time");
	T_PASS("Low priority bound threads got some CPU time in the presence of high priority unbound spinners");
}
