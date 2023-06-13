#include <sys/sysctl.h>

#include <darwintest.h>
#include <darwintest_perf.h>
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("jharmening"),
	XNU_T_META_SOC_SPECIFIC);

T_DECL(pmap_call_benchmark, "pmap call overhead benchmark")
{
	int num_loops = 100000;
	dt_stat_time_t s = dt_stat_time_create("average pmap function call overhead for %d calls", num_loops);
	while (!dt_stat_stable(s)) {
		dt_stat_token start = dt_stat_time_begin(s);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_call_overhead_test", NULL, NULL,
		    &num_loops, sizeof(num_loops)), "invoke pmap call overhead test sysctl");
		dt_stat_time_end_batch(s, num_loops, start);
	}
	dt_stat_finalize(s);
}

T_DECL(pmap_page_protect_benchmark, "pmap_page_protect() overhead benchmark")
{
	struct {
		unsigned int num_loops;
		unsigned int num_aliases;
	} ppo_in;
	ppo_in.num_loops = 1000;
	uint64_t duration;
	size_t duration_size = sizeof(duration);
	for (ppo_in.num_aliases = 1; ppo_in.num_aliases <= 128; ppo_in.num_aliases <<= 1) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_page_protect_overhead_test",
		    &duration, &duration_size, &ppo_in, sizeof(ppo_in)),
		    "invoke pmap_page_protect() overhead test sysctl");
		T_LOG("%u-loop duration (in ticks) for %u aliases: %llu", ppo_in.num_loops, ppo_in.num_aliases, duration);
	}
}
