// Copyright (c) 2021-2022 Apple Inc.  All rights reserved.

#pragma once

#include <mach/time_value.h>
#include <os/base.h>
#include <pthread/pthread.h>
#include <stdbool.h>
#include <stdint.h>

#define ARRAY_COUNT(_a) (sizeof((_a)) / sizeof((_a[0])))

#define REQUIRE_RECOUNT_PMCS \
    T_META_REQUIRES_SYSCTL_EQ("kern.monotonic.supported", 1)
#define REQUIRE_RECOUNT_ENERGY \
    T_META_REQUIRES_SYSTCL_EQ("kern.pervasive_energy", 1)
#define REQUIRE_MULTIPLE_PERF_LEVELS \
    T_META_REQUIRES_SYSCTL_NE("hw.nperflevels", 1)
#define SET_THREAD_BIND_BOOTARG \
    T_META_BOOTARGS_SET("enable_skstb=1")

// Returns true if the system implicitly tracks CPI.
bool has_cpi(void);

// Returns true if precise user kernel (system) times are being tracked,
// and false otherwise.
bool has_user_system_times(void);

// Returns true if the system can track energy usage.
bool has_energy(void);

// Returns the number of perf-levels on the system.
unsigned int perf_level_count(void);

// Returns the name of the specified perf-level.
const char *perf_level_name(unsigned int perf_level);

// Run periodically on all perf levels -- must have `SET_THREAD_BIND_BOOTARG`.
void run_on_all_perf_levels(void);

// Return the nanoseconds represented by a Mach time.
uint64_t ns_from_mach(uint64_t mach_time);

// Return the nanoseconds represented by a timeval.
uint64_t ns_from_timeval(struct timeval tv);

// Return the timeval represented by nanoseconds.
struct timeval timeval_from_ns(uint64_t ns);

// Return the nanoseconds represented by a Mach time_value.
uint64_t ns_from_time_value(struct time_value tv);

// Return the Mach time_value represented by nanoseconds.
struct time_value time_value_from_ns(uint64_t ns);

// What an actor should do when it's running.
__enum_decl(role_t, uint32_t, {
	ROLE_NONE,
	ROLE_SPIN,
	ROLE_WAIT,
});

// A thread doing work according to a script.
struct actor {
	pthread_t act_thread;
	role_t act_role;
	void *act_context;
};

struct scene {
	unsigned int scn_actor_count;
	uintptr_t scn_spin_sync;
	void *scn_wait_sync;
	struct actor scn_actors[];
};

// Start `n` threads that follow a given pattern of scripts.
struct scene *scene_start(unsigned int n, role_t *roles);

// Stop and destroy previously-started actors.
void scene_end(struct scene *scene);

// Launch a `T_HELPER_DECL`-based helper.
pid_t launch_helper(char *name);
