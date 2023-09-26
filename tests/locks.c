#include <sys/sysctl.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <spawn.h>
#include <pthread.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.sync"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_CHECK_LEAKS(false),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("locks"));

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}

T_DECL(hw_lck_ticket_allow_invalid, "hw_lck_ticket_allow_invalid",
    T_META_RUN_CONCURRENTLY(false))
{
	T_EXPECT_EQ(1ll, run_sysctl_test("hw_lck_ticket_allow_invalid", 0), "test succeeded");
}

T_DECL(smr_hash_basic, "smr_hash basic test")
{
	T_EXPECT_EQ(1ll, run_sysctl_test("smr_hash_basic", 0), "test succeeded");
}

T_DECL(smr_shash_basic, "smr_shash basic test")
{
	T_EXPECT_EQ(1ll, run_sysctl_test("smr_shash_basic", 0), "test succeeded");
}

static void
clpc_set_core_count(int ncpus)
{
#if __arm64__
	char arg[20];
	char *const clpcctrl_args[] = {
		"/usr/local/bin/clpcctrl",
		"-c",
		arg,
		NULL,
	};
	pid_t pid;
	int rc;

	snprintf(arg, sizeof(arg), "%d", ncpus);
	rc = posix_spawn(&pid, clpcctrl_args[0], NULL, NULL, clpcctrl_args, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "posix_spawn");
	waitpid(pid, &rc, 0);
#else
	(void)ncpus;
#endif
}

static void *
toggle_cpus_thread(void *donep)
{
	int ncpus = dt_ncpu();

	do {
		usleep(200 * 1000);
		clpc_set_core_count(ncpus - 1);
		usleep(200 * 1000);
		clpc_set_core_count(ncpus);
	} while (!*(bool *)donep);

	return NULL;
}

T_DECL(smr_sleepable_stress, "smr_sleepable_stress_test",
    T_META_RUN_CONCURRENTLY(false))
{
	uint32_t secs = 4;
	pthread_t pth;
	bool done = false;
	int rc;

	rc = pthread_create(&pth, NULL, toggle_cpus_thread, &done);
	T_ASSERT_POSIX_SUCCESS(rc, "pthread_create");

	T_EXPECT_EQ(1ll, run_sysctl_test("smr_sleepable_stress", secs), "test succeeded");

	done = true;
	pthread_join(pth, NULL);
}
