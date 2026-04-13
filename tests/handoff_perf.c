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

/*
 * handoff_perf: Tests round-trip time of eventlink, semaphore_wait_signal,
 * and mach_msg primitives between threads in the same and different processes,
 * as well as at realtime and default priorities.
 */

#include "sched/sched_test_utils.h"
#include "test_utils.h"

#include <mach/mach.h>
#include <mach/mach_eventlink.h>
#include <mach/semaphore.h>
#include <os/atomic_private.h>
#include <pthread.h>
#include <sys/sysctl.h>
#include <spawn.h>
#include <spawn_private.h>
#include <math.h>
#include <stdlib.h>
#include <mach-o/dyld.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include <darwintest_multiprocess.h>

#include <os/mach_utils.h>

//#define T_STAT_MEASURE_LOOP(stat) for (int i = 0; i < 100; i++)
//#define T_STAT_MEASURE_LOOP(s) _T_STAT_MEASURE_LOOP_BATCH( \
// //s, __COUNTER__, dt_stat_stable(s)) for (int i = 0; i < 10000; i++)

/*
 * Future ideas:
 * - Measure instructions/cycles
 * - Split up separate functions for the inner measure loop so I can have one measure code
 * - Save and restore old mach_ports_register
 * - Figure out why set_registered_ports doesn't work
 * - Env var for 100 loop (tracing) and 10000 loop (benchmark equivalence) mode
 */

T_GLOBAL_META(T_META_NAMESPACE("xnu.perf.handoff"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_OWNER("chimene"),
    T_META_RUN_CONCURRENTLY(false),
    T_META_CHECK_LEAKS(false),
    T_META_TAG_PERF,
    T_META_TIMEOUT(10),
    T_META_TAG_VM_NOT_PREFERRED);

/* <rdar://143331046> */
#define AVOID_RT_ON_VISION T_META_ENABLED(!TARGET_OS_VISION)

__enum_decl(test_scenario_mode_t, uint32_t, {
	SCENARIO_EVENTLINK,
	SCENARIO_SEMAPHORE,
	SCENARIO_MACHMSG,
	SCENARIO_MAX,
});

__enum_decl(test_scenario_flavor_t, uint32_t, {
	FLAVOR_DEFAULT,
	FLAVOR_REALTIME,
	FLAVOR_XPROCESS,
	FLAVOR_REALTIME_XPROCESS,
	FLAVOR_MAX,
});

/****************************************************************/
#pragma mark Test Definitions

static void
test_scenario_leader(test_scenario_mode_t mode,
    test_scenario_flavor_t flavor);

T_DECL(eventlink_signal_wait,
    "eventlink_signal_wait time measurement")
{
	test_scenario_leader(SCENARIO_EVENTLINK, FLAVOR_DEFAULT);
}

T_DECL(eventlink_signal_wait_realtime,
    "eventlink_signal_wait realtime time measurement",
    AVOID_RT_ON_VISION)
{
	test_scenario_leader(SCENARIO_EVENTLINK, FLAVOR_REALTIME);
}

T_DECL(eventlink_signal_wait_crossprocess,
    "eventlink_signal_wait cross-process time measurement")
{
	test_scenario_leader(SCENARIO_EVENTLINK, FLAVOR_XPROCESS);
}

T_DECL(eventlink_signal_wait_realtime_crossprocess,
    "eventlink_signal_wait realtime cross-process time measurement",
    AVOID_RT_ON_VISION)
{
	test_scenario_leader(SCENARIO_EVENTLINK, FLAVOR_REALTIME_XPROCESS);
}

T_DECL(semaphore_wait_signal,
    "semaphore_wait_signal time measurement")
{
	test_scenario_leader(SCENARIO_SEMAPHORE, FLAVOR_DEFAULT);
}

T_DECL(semaphore_wait_signal_realtime,
    "semaphore_wait_signal realtime time measurement",
    AVOID_RT_ON_VISION)
{
	test_scenario_leader(SCENARIO_SEMAPHORE, FLAVOR_REALTIME);
}

T_DECL(semaphore_wait_signal_crossprocess,
    "semaphore_wait_signal cross-process time measurement")
{
	test_scenario_leader(SCENARIO_SEMAPHORE, FLAVOR_XPROCESS);
}

T_DECL(semaphore_wait_signal_realtime_crossprocess,
    "semaphore_wait_signal realtime cross-process time measurement",
    AVOID_RT_ON_VISION)
{
	test_scenario_leader(SCENARIO_SEMAPHORE, FLAVOR_REALTIME_XPROCESS);
}

T_DECL(mach_msg,
    "mach_msg time measurement")
{
	test_scenario_leader(SCENARIO_MACHMSG, FLAVOR_DEFAULT);
}

T_DECL(mach_msg_realtime,
    "mach_msg realtime time measurement",
    AVOID_RT_ON_VISION)
{
	test_scenario_leader(SCENARIO_MACHMSG, FLAVOR_REALTIME);
}

T_DECL(mach_msg_crossprocess,
    "mach_msg cross-process time measurement")
{
	test_scenario_leader(SCENARIO_MACHMSG, FLAVOR_XPROCESS);
}

T_DECL(mach_msg_realtime_crossprocess,
    "mach_msg realtime cross-process time measurement",
    AVOID_RT_ON_VISION)
{
	test_scenario_leader(SCENARIO_MACHMSG, FLAVOR_REALTIME_XPROCESS);
}

/****************************************************************/
#pragma mark Helper Functions

static bool
flavor_is_xprocess(test_scenario_flavor_t flavor)
{
	return flavor == FLAVOR_XPROCESS || flavor == FLAVOR_REALTIME_XPROCESS;
}

static bool
flavor_is_realtime(test_scenario_flavor_t flavor)
{
	return flavor == FLAVOR_REALTIME || flavor == FLAVOR_REALTIME_XPROCESS;
}

struct port_pair {
	mach_port_t port1;
	mach_port_t port2;
};

struct thread_params {
	test_scenario_mode_t mode;
	test_scenario_flavor_t flavor;
	struct port_pair pair;
	uint64_t handoffs_start;
	uint64_t handoffs_end;
	uint64_t iterations;
	dt_stat_time_t stat_time;
	semaphore_t done_sem;
};

static const struct test_functions {
	struct port_pair (*setup_fn)( void);
	void (*cleanup_fn)(struct port_pair);
	uint64_t (*leader_fn)(dt_stat_time_t, struct port_pair);
	void (*follower_fn)(struct port_pair);
} functions[SCENARIO_MAX];

static const uint64_t DEFAULT_INTERVAL_NS = 15000000; // 15 ms

static void
set_realtime(pthread_t thread, char* prefix)
{
	kern_return_t kr;
	thread_time_constraint_policy_data_t pol;

	uint64_t interval_nanos = DEFAULT_INTERVAL_NS;

	mach_port_t target_thread = pthread_mach_thread_np(thread);
	T_QUIET; T_ASSERT_GT(target_thread, 0, "pthread_mach_thread_np");

	pol.period      = (uint32_t)nanos_to_abs(interval_nanos);
	pol.constraint  = (uint32_t)nanos_to_abs(interval_nanos);
	pol.computation = (uint32_t)nanos_to_abs(interval_nanos - 1000000);
	pol.preemptible = 0; /* Ignored by OS */

	kr = thread_policy_set(target_thread, THREAD_TIME_CONSTRAINT_POLICY,
	    (thread_policy_t)&pol, THREAD_TIME_CONSTRAINT_POLICY_COUNT);
	T_ASSERT_MACH_SUCCESS(kr,
	    "%s thread_policy_set(THREAD_TIME_CONSTRAINT_POLICY)", prefix);
}

static void
log_handoff_sysctl(void)
{
	bool development = is_development_kernel();
	T_LOG("kern.development: %d", development);

	if (!development) {
		/* kern.direct_handoff does not exist on release kernel */
		return;
	}

	int direct_handoff = 0;
	size_t size = sizeof(direct_handoff);
	T_QUIET; T_ASSERT_POSIX_ZERO(sysctlbyname("kern.direct_handoff",
	    &direct_handoff, &size, NULL, 0),
	    "sysctlbyname kern.direct_handoff");

	T_LOG("kern.direct_handoff: %d", direct_handoff);
}

static uint64_t
handoff_success_count_sysctl(void)
{
	if (!is_development_kernel()) {
		/* kern.direct_handoff does not exist on release kernel */
		return 0;
	}
	uint64_t success_count = 0;
	size_t size = sizeof(success_count);
	T_QUIET; T_ASSERT_POSIX_ZERO(sysctlbyname(
		    "kern.mach_eventlink_handoff_success_count",
		    &success_count,
		    &size, NULL, 0),
	    "sysctlbyname(kern.mach_eventlink_handoff_success_count)");
	return success_count;
}

static bool log_mach = false;

static void
log_port_desc(char* prefix, mach_port_t port)
{
	if (!log_mach) {
		return;
	}
	char* port_desc = os_mach_port_copy_description(port);
	T_LOG("%s%s\n", prefix, port_desc);
	free(port_desc);
}

static void
log_msg_desc(char* prefix, mach_msg_header_t *header)
{
	if (!log_mach) {
		return;
	}
	char* msg_desc = os_mach_msg_copy_description(header);
	T_LOG("%s%s\n", prefix, msg_desc);
	free(msg_desc);
}

/****************************************************************/
#pragma mark Execution Infrastructure

static void
set_thread_name(char* prefix, struct thread_params* params)
{
	int ret;
	char* name_str = NULL;

	ret = asprintf(&name_str, "h_p_%s %d %d", prefix,
	    params->mode, params->flavor);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "asprintf");

	pthread_setname_np(name_str);

	uint64_t thread_id = 0;
	ret = pthread_threadid_np(NULL, &thread_id);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_threadid_np");

	T_LOG("thread 0x%llx: %s", thread_id, name_str);

	free(name_str);
}

static void *
test_scenario_follower_thread(void *arg)
{
	struct thread_params* params = (struct thread_params*) arg;

	set_thread_name("follower", params);

	if (flavor_is_realtime(params->flavor)) {
		set_realtime(pthread_self(), "follower:");
	}

	functions[params->mode].follower_fn(params->pair);

	kern_return_t kr = semaphore_signal(params->done_sem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_signal");

	return NULL;
}

static void *
test_scenario_leader_thread(void *arg)
{
	struct thread_params* params = (struct thread_params*) arg;

	set_thread_name("leader", params);

	if (flavor_is_realtime(params->flavor)) {
		set_realtime(pthread_self(), "leader:");
	}

	params->handoffs_start = handoff_success_count_sysctl();

	params->iterations = functions[params->mode].leader_fn(
		params->stat_time, params->pair);

	params->handoffs_end = handoff_success_count_sysctl();

	kern_return_t kr = semaphore_signal(params->done_sem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_signal");

	return NULL;
}


T_HELPER_DECL(handoff_perf_child,
    "child that loops responding to scenario")
{
	T_QUIET; T_ASSERT_GE(argc, 2,
	    "child must have at least 2 args in argv");

	const char* errstr = "";
	test_scenario_mode_t mode = (test_scenario_mode_t)strtonum(
		argv[0], SCENARIO_EVENTLINK, SCENARIO_MAX - 1, &errstr);

	T_QUIET; T_ASSERT_NULL(errstr, "mode arg %s: %s", errstr, argv[0]);

	test_scenario_flavor_t flavor = (test_scenario_flavor_t)strtonum(
		argv[1], FLAVOR_DEFAULT, FLAVOR_MAX - 1, &errstr);

	T_QUIET; T_ASSERT_NULL(errstr, "flavor arg %s: %s", errstr, argv[1]);

	mach_port_t *stash = NULL;
	mach_msg_type_number_t stash_cnt = 0;
	kern_return_t kr;

	kr = mach_ports_lookup(mach_task_self(), &stash, &stash_cnt);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_ports_lookup");
	T_QUIET; T_ASSERT_GE(stash_cnt, 2,
	    "mach_ports_lookup must return at least 2 ports");
	T_QUIET; T_ASSERT_NOTNULL(stash,
	    "mach_ports_lookup must return stash array");

	struct port_pair pair = {stash[0], stash[1]};

	mig_deallocate((vm_address_t)stash, stash_cnt * sizeof(stash[0]));

	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(pair.port1),
	    "valid port1: 0x%x", pair.port1);
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(pair.port2),
	    "valid port2: 0x%x", pair.port2);

	log_port_desc("follower: port 1: ", pair.port1);
	log_port_desc("follower: port 2: ", pair.port2);

	/*
	 * Create a dedicated separate thread to bleach priority and
	 * make tracing easier.
	 */

	pthread_t follower_pthread = NULL;

	struct thread_params params = {
		.mode = mode,
		.flavor = flavor,
		.pair = pair,
	};

	kr = semaphore_create(mach_task_self(), &params.done_sem, SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create");

	int ret = pthread_create(&follower_pthread, NULL,
	    test_scenario_follower_thread,
	    (void *)(uintptr_t)&params);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create");

	kr = semaphore_wait(params.done_sem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait");

	ret = pthread_join(follower_pthread, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_join");

	kr = mach_port_deallocate(mach_task_self(), pair.port1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate for port1");
	kr = mach_port_deallocate(mach_task_self(), pair.port2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate for port2");
}

static pid_t
spawn_test_scenario_follower(struct thread_params* params)
{
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	int ret = _NSGetExecutablePath(path, &path_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");

	char* mode_str = NULL;
	char* flavor_str = NULL;

	ret = asprintf(&mode_str, "%d", params->mode);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "asprintf");
	ret = asprintf(&flavor_str, "%d", params->flavor);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "asprintf");

	/* Tell the child to run helper handoff_perf_child above */
	char *client_args[] = { path,
		                "-n", "handoff_perf_child", "--",
		                mode_str, flavor_str, NULL };

	mach_port_t ports[2] = { params->pair.port1, params->pair.port2 };

	posix_spawnattr_t attr;
	ret = posix_spawnattr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_init");

	// posix_spawnattr_set_registered_ports_np doesn't work here, why?
	//ret = posix_spawnattr_set_registered_ports_np(&attr, ports, 2);
	//T_QUIET; T_ASSERT_POSIX_ZERO(ret,
	//    "posix_spawnattr_set_registered_ports_np");

	kern_return_t kr;
	kr = mach_ports_register(mach_task_self(), (mach_port_array_t)&ports, 2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_ports_register");

	pid_t client_pid;

	ret = posix_spawn(&client_pid, client_args[0], NULL, attr,
	    client_args, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawned process '%s' with PID %d",
	    client_args[0], client_pid);
	T_LOG("Spawned client as PID %d", client_pid);

	free(mode_str);
	free(flavor_str);

	return client_pid;
}

static void
test_scenario_leader(test_scenario_mode_t mode, test_scenario_flavor_t flavor)
{
	log_handoff_sysctl();

	struct port_pair pair = functions[mode].setup_fn();

	dt_stat_time_t stat_time = dt_stat_time_create("round trip time");

	struct thread_params params = {
		.mode = mode,
		.flavor = flavor,
		.pair = pair,
		.stat_time = stat_time,
	};

	kern_return_t kr;
	kr = semaphore_create(mach_task_self(), &params.done_sem, SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create");

	pthread_t follower_pthread = NULL;
	pid_t child_pid = 0;
	int ret;

	if (flavor_is_xprocess(flavor)) {
		child_pid = spawn_test_scenario_follower(&params);
	} else {
		ret = pthread_create(&follower_pthread, NULL,
		    test_scenario_follower_thread,
		    (void *)(uintptr_t)&params);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create");
	}

	pthread_t leader_pthread = NULL;

	/*
	 * Create a dedicated separate thread to bleach priority and
	 * make tracing easier.
	 */

	ret = pthread_create(&leader_pthread, NULL,
	    test_scenario_leader_thread,
	    (void *)(uintptr_t)&params);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create");

	kr = semaphore_wait(params.done_sem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait");

	ret = pthread_join(leader_pthread, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_join");

	functions[mode].cleanup_fn(pair);

	uint64_t total_handoffs = params.handoffs_end - params.handoffs_start;
	double handoffs_per_iter = (double)total_handoffs / (double)params.iterations;

	/* Crush to 2 significant figures */
	handoffs_per_iter = round(handoffs_per_iter * 100) / 100;

	T_LOG("%s: direct handoffs per iteration = %.2f",
	    T_NAME, handoffs_per_iter);

	dt_stat_set_variable((dt_stat_t)stat_time,
	    "handoffs", handoffs_per_iter);

	dt_stat_finalize(stat_time);

	if (flavor_is_xprocess(flavor)) {
		/* wait for child process to exit */
		int exit_status = 0, signum = 0;

		T_QUIET; T_ASSERT_TRUE(dt_waitpid(child_pid,
		    &exit_status, &signum, 5),
		    "wait for child (%d) complete", child_pid);

		T_QUIET; T_ASSERT_EQ(exit_status, 0, "dt_waitpid: exit_status");
		T_QUIET; T_ASSERT_EQ(signum, 0, "dt_waitpid: signum");
	} else {
		ret = pthread_join(follower_pthread, NULL);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_join");
	}
}

/****************************************************************/
#pragma mark mach_eventlink tests

static struct port_pair
perf_eventlink_setup(void)
{
	eventlink_port_pair_t pair;
	kern_return_t kr;

	kr = mach_eventlink_create(mach_task_self(),
	    MELC_OPTION_NO_COPYIN, pair);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_create");

	return (struct port_pair){pair[0], pair[1]};
}

static uint64_t
perf_eventlink_leader(dt_stat_time_t stat_time,
    struct port_pair pair)
{
	mach_port_t eventlink_port = pair.port2;

	/* Associate thread and wait_signal the eventlink */
	kern_return_t kr = mach_eventlink_associate(eventlink_port,
	    mach_thread_self(), 0, 0, 0, 0, MELA_OPTION_NONE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate port2");

	uint64_t count = 0;

	kr = mach_eventlink_signal_wait_until(eventlink_port, &count, 0,
	    MELSW_OPTION_NONE, KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_wait_until");
	T_QUIET; T_EXPECT_EQ(count, (uint64_t)1,
	    "mach_eventlink_wait_until returned correct count value");

	T_LOG("Test begin");
	usleep(1000);

	uint64_t iterations = 0;

	T_STAT_MEASURE_LOOP(stat_time) {
		iterations++;
		kr = mach_eventlink_signal_wait_until(eventlink_port, &count, 0,
		    MELSW_OPTION_NONE, KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);
	}

	usleep(1000);
	T_LOG("Test end");

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr,
	    "main thread: mach_eventlink_signal_wait_until");

	return iterations;
}

static void
perf_eventlink_follower(struct port_pair pair)
{
	mach_port_t eventlink_port = pair.port1;

	/* Associate thread with eventlink port */
	kern_return_t kr = mach_eventlink_associate(eventlink_port,
	    mach_thread_self(), 0, 0, 0, 0, MELA_OPTION_NONE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate");

	uint64_t count = 0;

	/* Wait on the eventlink */
	kr = mach_eventlink_wait_until(eventlink_port, &count,
	    MELSW_OPTION_NONE, KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_wait_until");
	T_QUIET; T_EXPECT_EQ(count, (uint64_t)1,
	    "mach_eventlink_wait_until returned correct count value");

	while (kr == KERN_SUCCESS) {
		/* Signal wait the eventlink */
		kr = mach_eventlink_signal_wait_until(eventlink_port, &count, 0,
		    MELSW_OPTION_NONE, KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);
	}

	T_QUIET; T_ASSERT_MACH_ERROR(kr, KERN_TERMINATED,
	    "eventlink should have been terminated");
}

static void
perf_eventlink_cleanup(struct port_pair pair)
{
	kern_return_t kr;

	kr = mach_eventlink_destroy(pair.port1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_destroy for port1");
	kr = mach_eventlink_destroy(pair.port2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_destroy for port2");
}

/****************************************************************/
#pragma mark semaphore_wait_signal tests

static struct port_pair
perf_semaphore_setup(void)
{
	kern_return_t kr;
	struct port_pair pair = {};

	kr = semaphore_create(mach_task_self(), &pair.port1, SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create");
	kr = semaphore_create(mach_task_self(), &pair.port2, SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create");

	return pair;
}

static uint64_t
perf_semaphore_leader(dt_stat_time_t stat_time, struct port_pair pair)
{
	kern_return_t kr = semaphore_wait_signal(pair.port1, pair.port2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "main thread: semaphore_wait_signal");

	T_LOG("Test begin");
	usleep(1000);
	uint64_t iterations = 0;

	T_STAT_MEASURE_LOOP(stat_time) {
		iterations++;
		kr = semaphore_wait_signal(pair.port1, pair.port2);
	}

	usleep(1000);
	T_LOG("Test end");

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "main thread: semaphore_wait_signal");
	return iterations;
}

static void
perf_semaphore_follower(struct port_pair pair)
{
	/* Consume the first preposted signal from the leader */
	kern_return_t kr = semaphore_wait(pair.port2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait");

	usleep(1000);

	while (kr == KERN_SUCCESS) {
		kr = semaphore_wait_signal(pair.port2, pair.port1);
	}
	T_QUIET; T_ASSERT_MACH_ERROR(kr, KERN_TERMINATED,
	    "Semaphore should have been terminated");
}

static void
perf_semaphore_cleanup(struct port_pair pair)
{
	kern_return_t kr;

	kr = semaphore_destroy(mach_task_self(), pair.port1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_destroy for port1");
	kr = semaphore_destroy(mach_task_self(), pair.port2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_destroy for port2");
}

/****************************************************************/
#pragma mark mach_msg tests

static const uint64_t CONN_CONTEXT = 0xfeedface;

static struct port_pair
perf_mach_setup(void)
{
	kern_return_t kr;
	mach_port_t conn_port;

	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT | MPO_CONTEXT_AS_GUARD,
	};

	kr = mach_port_construct(mach_task_self(), &opts,
	    CONN_CONTEXT, &conn_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");

	return (struct port_pair){conn_port, conn_port};
}

static const mach_msg_id_t request_msghid = 0x1001;
static const mach_msg_id_t reply_msghid   = 0x1002;

static uint64_t
perf_mach_leader(dt_stat_time_t stat_time, struct port_pair pair)
{
	kern_return_t kr;
	mach_port_t conn_port = pair.port1;

	struct {
		mach_msg_header_t header;
		mach_msg_trailer_t trailer;
	} msg = {};

	kr = mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg), conn_port, 0, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_msg: buf %lu size %d",
	    sizeof(msg), msg.header.msgh_size);

	log_msg_desc("leader: rcv: ", &msg.header);
	log_port_desc("leader: conn_port: ", conn_port);
	log_port_desc("leader: reply_port: ", msg.header.msgh_remote_port);

	T_LOG("Test begin");
	usleep(1000);

	uint64_t iterations = 0;

	T_STAT_MEASURE_LOOP(stat_time) {
		iterations++;
		/*
		 * Reflect the message back to the sender with the local port
		 * cleared.
		 * Note: msgh_local_port in a received message does not convey
		 * a right, so we're not leaking it here.
		 */
		msg.header.msgh_bits = MACH_MSGH_BITS(
			MACH_MSGH_BITS_REMOTE(msg.header.msgh_bits), 0);
		msg.header.msgh_local_port = MACH_PORT_NULL;
		msg.header.msgh_id = reply_msghid,

		kr = mach_msg(&msg.header, MACH_SEND_MSG | MACH_RCV_MSG,
		    sizeof(msg.header), sizeof(msg), conn_port, 0, 0);
		if (kr == KERN_SUCCESS) {
			if (__improbable(msg.header.msgh_id != request_msghid)) {
				T_ASSERT_EQ(msg.header.msgh_id, reply_msghid,
				    "Expected a request message");
			}
		} else {
			T_LOG("leader: error: 0x%x %s\n", kr,
			    mach_error_string(kr));
			log_msg_desc("leader: error on msg: ", &msg.header);
			goto end;
		}
	}

end:
	usleep(1000);

	T_LOG("Test end");
	log_port_desc("leader: conn_port: ", conn_port);
	log_port_desc("leader: reply_port: ", msg.header.msgh_remote_port);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "main thread: mach_msg");

	/* Wake up the follower by destroying the reply port send once right */
	mach_msg_destroy(&msg.header);
	return iterations;
}

static void
perf_mach_follower(struct port_pair pair)
{
	mach_port_t conn_port = pair.port1;
	mach_port_t special_reply_port = thread_get_special_reply_port();

	log_port_desc("follower: conn_port: ", conn_port);
	log_port_desc("follower: reply_port: ", special_reply_port);

	usleep(1000);

	kern_return_t kr = KERN_SUCCESS;

	while (kr == KERN_SUCCESS) {
		/*
		 * Make a request to the leader asking for a reply.
		 * Avoid execute T_ checks inside the critical loop unless
		 * they will fail and abort, as they are too expensive.
		 */

		struct {
			mach_msg_header_t header;
			mach_msg_trailer_t trailer;
		} msg = {
			.header = {
				.msgh_remote_port = conn_port,
				.msgh_local_port  = special_reply_port,
				.msgh_bits        = MACH_MSGH_BITS_SET(
					MACH_MSG_TYPE_COPY_SEND,
					MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, 0),
				.msgh_id          = request_msghid,
				.msgh_size        = sizeof(msg.header),
			},
		};
		kr = mach_msg(&msg.header, MACH_SEND_MSG | MACH_RCV_MSG,
		    sizeof(msg.header), sizeof(msg), special_reply_port, 0, 0);
		if (kr == KERN_SUCCESS) {
			if (msg.header.msgh_remote_port != MACH_PORT_NULL) {
				T_ASSERT_EQ(msg.header.msgh_remote_port,
				    MACH_PORT_NULL,
				    "Should not get a right in reply");
			}
			if (msg.header.msgh_id != reply_msghid &&
			    msg.header.msgh_id != MACH_NOTIFY_SEND_ONCE) {
				T_ASSERT_EQ(msg.header.msgh_id, reply_msghid,
				    "Expected a reply message");
			}
		}
	}

	log_port_desc("follower: conn_port: ", conn_port);
	log_port_desc("follower: reply_port: ", special_reply_port);

	T_QUIET; T_ASSERT_MACH_ERROR(kr, MACH_SEND_INVALID_DEST,
	    "conn_port should have reported as died");
}

static void
perf_mach_cleanup(struct port_pair pair)
{
	kern_return_t kr;
	mach_port_t conn_port = pair.port1;

	kr = mach_port_destruct(mach_task_self(), conn_port, -1, CONN_CONTEXT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_destruct conn_port");
}

/****************************************************************/
#pragma mark Test Function Dispatch

static const
struct test_functions functions[SCENARIO_MAX] = {
	[SCENARIO_EVENTLINK] = {
		.setup_fn    = perf_eventlink_setup,
		.cleanup_fn  = perf_eventlink_cleanup,
		.leader_fn   = perf_eventlink_leader,
		.follower_fn = perf_eventlink_follower,
	},
	[SCENARIO_SEMAPHORE] = {
		.setup_fn    = perf_semaphore_setup,
		.cleanup_fn  = perf_semaphore_cleanup,
		.leader_fn   = perf_semaphore_leader,
		.follower_fn = perf_semaphore_follower,
	},
	[SCENARIO_MACHMSG] = {
		.setup_fn    = perf_mach_setup,
		.cleanup_fn  = perf_mach_cleanup,
		.leader_fn   = perf_mach_leader,
		.follower_fn = perf_mach_follower,
	},
};
