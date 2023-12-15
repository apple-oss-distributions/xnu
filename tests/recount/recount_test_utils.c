// Copyright (c) 2021-2022 Apple Inc.  All rights reserved.

#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <mach/semaphore.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach-o/dyld.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include "recount_test_utils.h"

bool
has_user_system_times(void)
{
	static dispatch_once_t user_system_once;
	static bool precise_times = false;
	dispatch_once(&user_system_once, ^{
		int precise_times_int = 0;
		size_t precise_times_size = sizeof(precise_times_int);
		T_SETUPBEGIN;
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.precise_user_kernel_time",
				&precise_times_int, &precise_times_size, NULL, 0),
				"sysctl kern.precise_user_kernel_time");
		T_SETUPEND;
		precise_times = precise_times_int != 0;
	});
	return precise_times;
}

bool
has_cpi(void)
{
	static dispatch_once_t cpi_once;
	static int cpi = 0;
	dispatch_once(&cpi_once, ^{
		size_t cpi_size = sizeof(cpi);
		T_SETUPBEGIN;
		int ret = sysctlbyname("kern.monotonic.supported", &cpi, &cpi_size,
				NULL, 0);
		// ENOENT also means that CPI is unavailable.
		if (ret != 0 && errno != ENOENT) {
			T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.monotonic.supported");
		}
		T_SETUPEND;
	});
	return cpi != 0;
}

bool
has_energy(void)
{
	static dispatch_once_t energy_once;
	static int energy = false;
	dispatch_once(&energy_once, ^{
		size_t energy_size = sizeof(energy);
		T_SETUPBEGIN;
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pervasive_energy",
				&energy, &energy_size, NULL, 0),
				"sysctl kern.pervasive_energy");
		T_SETUPEND;
	});
	return energy != 0;
}

unsigned int
perf_level_count(void)
{
	static dispatch_once_t count_once;
	static unsigned int count = 0;
	dispatch_once(&count_once, ^{
		T_SETUPBEGIN;
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("hw.nperflevels", &count,
				&(size_t){ sizeof(count) }, NULL, 0),
				"sysctl hw.nperflevels");
		T_SETUPEND;
	});
	return count;
}

static const char **
_perf_level_names(void)
{
	static char names[2][32] = { 0 };
	static dispatch_once_t names_once;
	dispatch_once(&names_once, ^{
		T_SETUPBEGIN;
		unsigned int count = perf_level_count();
		for (unsigned int i = 0; i < count; i++) {
			char sysctl_name[64] = { 0 };
			snprintf(sysctl_name, sizeof(sysctl_name), "hw.perflevel%d.name",
					i);
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(sysctlbyname(sysctl_name, &names[i],
					&(size_t){ sizeof(names[i]) }, NULL, 0),
					"sysctl %s", sysctl_name);
		}
		T_SETUPEND;
	});
	static const char *ret_names[] = {
		(char *)&names[0],
		(char *)&names[1],
	};
	return ret_names;
}

const char *
perf_level_name(unsigned int perf_level)
{
	return _perf_level_names()[perf_level];
}

unsigned int
perf_level_index(const char *name)
{
	unsigned int count = perf_level_count();
	const char **names = _perf_level_names();
	for (unsigned int i = 0; i < count; i++) {
		if (strcmp(name, names[i]) == 0) {
			return i;
		}
	}
	T_ASSERT_FAIL("cannot find perf level named %s", name);
}

void
bind_to_cluster(char type)
{
	int ret = sysctlbyname("kern.sched_thread_bind_cluster_type", NULL, NULL,
			&type, sizeof(type));
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.sched_thread_bind_cluster_type");
	// Ensure the thread has seen a context switch while bound.
	usleep(10000);
}

void
run_on_all_perf_levels(void)
{
	if (perf_level_count() == 1) {
		return;
	}

	T_SETUPBEGIN;
	bind_to_cluster('P');
	bind_to_cluster('E');
	// Return to the kernel to synchronize timings with the scheduler.
	(void)getppid();
	T_SETUPEND;
}

uint64_t
ns_from_mach(uint64_t mach_time)
{
	mach_timebase_info_data_t tbi = { 0 };
	mach_timebase_info(&tbi);
	return mach_time * tbi.numer / tbi.denom;
}

uint64_t
ns_from_timeval(struct timeval tv)
{
	return (uint64_t)tv.tv_sec * NSEC_PER_SEC + (uint64_t)tv.tv_usec * 1000;
}

struct timeval
timeval_from_ns(uint64_t ns)
{
	return (struct timeval){
		.tv_sec = ns / NSEC_PER_SEC,
		.tv_usec = (ns % NSEC_PER_SEC) / 1000,
	};
}

uint64_t
ns_from_time_value(struct time_value tv)
{
	return (uint64_t)tv.seconds * NSEC_PER_SEC +
			(uint64_t)tv.microseconds * 1000;
}

struct time_value
time_value_from_ns(uint64_t ns)
{
	return (struct time_value){
		.seconds = (integer_t)(ns / NSEC_PER_SEC),
		.microseconds = (ns % NSEC_PER_SEC) / 1000,
	};
}

static void *
spin_role(void *arg)
{
	volatile uintptr_t *keep_spinning = arg;
	while (*keep_spinning) {
		;
	}
	return NULL;
}

struct wait_start {
	semaphore_t ws_wait;
	semaphore_t ws_start;
};

static void *
wait_role(void *arg)
{
	struct wait_start *ws = arg;
	semaphore_wait_signal(ws->ws_wait, ws->ws_start);
	return NULL;
}

struct scene *
scene_start(unsigned int n, role_t *roles)
{
	if (n == 0) {
		return NULL;
	}

	T_SETUPBEGIN;

	size_t scene_size = sizeof(struct scene) + (n + 1) * sizeof(struct actor);
	struct scene *scene = malloc(scene_size);
	T_QUIET; T_WITH_ERRNO;
	T_ASSERT_NOTNULL(scene, "scene = malloc(%zu)", scene_size);

	bzero(scene, scene_size);
	unsigned int role_i = 0;
	unsigned int wait_count = 0;
	for (unsigned int i = 0; i < n; i++) {
		role_t role = roles[role_i];
		if (role == ROLE_NONE) {
			role_i = 0;
			role = roles[role_i];
		}
		if (role == ROLE_WAIT) {
			wait_count++;
		}
		scene->scn_actors[i].act_role = role;
		role_i++;
	}

	struct wait_start ws = { 0 };
	kern_return_t kr = semaphore_create(mach_task_self(), &ws.ws_wait,
			SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create(... wait ...)");
	kr = semaphore_create(mach_task_self(), &ws.ws_start,
			SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create(... start ...)");

	for (unsigned int i = 0; i < n; i++) {
		struct actor *act = &scene->scn_actors[i];
		void *(*action)(void *) = NULL;
		void *sync = NULL;
		switch (act->act_role) {
		case ROLE_SPIN:
			sync = &scene->scn_spin_sync;
			action = spin_role;
			break;
		case ROLE_WAIT:
			sync = &ws;
			action = wait_role;
			break;
		default:
			T_ASSERT_FAIL("unexpected role: %d", act->act_role);
		}
		int error = pthread_create(&act->act_thread, NULL, action, sync);
		T_QUIET; T_ASSERT_POSIX_ZERO(error, "pthread_create");
	}

	T_SETUPEND;
	for (unsigned int i = 0; i < wait_count; i++) {
		semaphore_wait(ws.ws_start);
	}
	semaphore_destroy(mach_task_self(), ws.ws_start);
	scene->scn_wait_sync = (void *)(uintptr_t)ws.ws_wait;
	return scene;
}

void
scene_end(struct scene *scene)
{
	if (!scene) {
		return;
	}

	scene->scn_spin_sync = 0;
	semaphore_signal_all((semaphore_t)scene->scn_wait_sync);
	semaphore_destroy(mach_task_self(), (semaphore_t)scene->scn_wait_sync);
	struct actor *act = scene->scn_actors;
	while (act->act_role != ROLE_NONE) {
		int error = pthread_join(act->act_thread, NULL);
		T_QUIET; T_ASSERT_POSIX_ZERO(error, "pthread_join");
		act++;
	}
	free(scene);
}

pid_t
launch_helper(char *name)
{
	char bin_path[MAXPATHLEN];
	uint32_t path_size = sizeof(bin_path);

	T_SETUPBEGIN;
	int ret = _NSGetExecutablePath(bin_path, &path_size);
	T_QUIET;
	T_ASSERT_EQ(ret, 0, "_NSGetExecutablePath()");
	pid_t pid = 0;
	ret = dt_launch_tool(&pid, (char *[]){ bin_path, name, NULL}, false, NULL,
	    NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "dt_launch_tool(... %s, %s ...)", bin_path,
	    name);
	T_SETUPEND;

	return pid;
}
