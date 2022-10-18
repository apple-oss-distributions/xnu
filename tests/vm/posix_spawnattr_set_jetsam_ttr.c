#include <mach-o/dyld.h>
#include <spawn.h>
#include <spawn_private.h>
#include <stdlib.h>
#include <sys/spawn_internal.h>
#include <sys/sysctl.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

static void
set_small_relaunch_values(posix_spawnattr_t *attrs)
{
	static const uint32_t kNumRelaunchValues = 16;
	static uint32_t relaunch_values[kNumRelaunchValues] = {0};
	int ret;
	/*
	 * Set the relaunch times to very small values (in m.s.).
	 * Everything under 5 seconds is expected to fall in the high relaunch behavior bucket.
	 */
	for (uint32_t i = 0; i < kNumRelaunchValues; i++) {
		relaunch_values[i] = i;
	}
	ret = posix_spawnattr_set_jetsam_ttr_np(attrs, kNumRelaunchValues, relaunch_values);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_set_jetsam_ttr_np");
}

T_DECL(set_high_relaunch_behavior, "supply very small time to relaunch values")
{
	posix_spawnattr_t attrs;
	_posix_spawnattr_t psattr;
	uint32_t relaunch_flags = 0;

	posix_spawnattr_init(&attrs);
	set_small_relaunch_values(&attrs);

	psattr = *(_posix_spawnattr_t *)&attrs;

	relaunch_flags = psattr->psa_jetsam_flags & POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_MASK;
	T_QUIET; T_ASSERT_EQ(relaunch_flags, POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_HIGH, "relaunch behavior is high");

	posix_spawnattr_destroy(&attrs);
}

T_DECL(set_medium_relaunch_behavior, "supply very large time to relaunch values")
{
	posix_spawnattr_t attrs;
	_posix_spawnattr_t psattr;
	int ret;
	static const uint32_t kNumRelaunchValues = 16;
	static uint32_t relaunch_values[kNumRelaunchValues] = {0};
	uint32_t relaunch_flags = 0;

	posix_spawnattr_init(&attrs);

	/*
	 * Set the relaunch times to medium large values (in m.s.).
	 * Everything over between 5 and 10 seconds is expected to fall in the medium relaunch behavior bucket.
	 */
	for (uint32_t i = 0; i < kNumRelaunchValues; i++) {
		relaunch_values[i] = 5000 + i;
	}
	ret = posix_spawnattr_set_jetsam_ttr_np(&attrs, kNumRelaunchValues, relaunch_values);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_set_jetsam_ttr_np");

	psattr = *(_posix_spawnattr_t *)&attrs;

	relaunch_flags = psattr->psa_jetsam_flags & POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_MASK;
	T_QUIET; T_ASSERT_EQ(relaunch_flags, POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_MED, "relaunch behavior is medium");

	posix_spawnattr_destroy(&attrs);
}


T_DECL(set_low_relaunch_behavior, "supply very large time to relaunch values")
{
	posix_spawnattr_t attrs;
	_posix_spawnattr_t psattr;
	int ret;
	static const uint32_t kNumRelaunchValues = 16;
	static uint32_t relaunch_values[kNumRelaunchValues] = {0};
	uint32_t relaunch_flags = 0;

	posix_spawnattr_init(&attrs);

	/*
	 * Set the relaunch times to very large values (in m.s.).
	 * Everything over 10 seconds is expected to fall in the low relaunch behavior bucket.
	 */
	for (uint32_t i = 0; i < kNumRelaunchValues; i++) {
		relaunch_values[i] = 10000 + i;
	}
	ret = posix_spawnattr_set_jetsam_ttr_np(&attrs, kNumRelaunchValues, relaunch_values);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_set_jetsam_ttr_np");

	psattr = *(_posix_spawnattr_t *)&attrs;

	relaunch_flags = psattr->psa_jetsam_flags & POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_MASK;
	T_QUIET; T_ASSERT_EQ(relaunch_flags, POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_LOW, "relaunch behavior is low");

	posix_spawnattr_destroy(&attrs);
}

T_DECL(set_high_relaunch_with_mixed_histogram, "supply slightly more small values than large values")
{
	posix_spawnattr_t attrs;
	_posix_spawnattr_t psattr;
	int ret;
	static const uint32_t kNumRelaunchValues = 16;
	static uint32_t relaunch_values[kNumRelaunchValues] = {0};
	uint32_t relaunch_flags = 0;

	posix_spawnattr_init(&attrs);

	/*
	 * Make sure the high likelihood bucket (<5 seconds) is a bit larger than the others
	 */
	for (uint32_t i = 0; i < kNumRelaunchValues; i++) {
		if (i % 2 == 0) {
			relaunch_values[i] = i;
		} else {
			if (i % 3 == 0) {
				relaunch_values[i] = 10000 + i;
			} else {
				relaunch_values[i] = 5000 + i;
			}
		}
	}
	ret = posix_spawnattr_set_jetsam_ttr_np(&attrs, kNumRelaunchValues, relaunch_values);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_set_jetsam_ttr_np");

	psattr = *(_posix_spawnattr_t *)&attrs;

	relaunch_flags = psattr->psa_jetsam_flags & POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_MASK;
	T_QUIET; T_ASSERT_EQ(relaunch_flags, POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_HIGH, "relaunch behavior is high");

	posix_spawnattr_destroy(&attrs);
}

extern char **environ;
T_HELPER_DECL(check_relaunch_flags, "Check that we have the high relaunch likelihood flag set")
{
	int relaunch_flags;
	size_t size = sizeof(relaunch_flags);
	int ret = sysctlbyname("kern.memorystatus_relaunch_flags", &relaunch_flags, &size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "failed to query vm.pagesize");
	T_QUIET; T_ASSERT_EQ(relaunch_flags, POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_HIGH, "relaunch behavior is high");
}

T_HELPER_DECL(exec_into_check_relaunch_flags, "Do an exec into check_relaunch_flags")
{
	posix_spawnattr_t attrs;
	int ret;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	char **arguments;

	testpath_buf_size = sizeof(testpath);
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");

	arguments = (char *[]) {
		testpath,
		"-n",
		"check_relaunch_flags",
		NULL
	};
	posix_spawnattr_init(&attrs);
	ret = posix_spawnattr_setflags(&attrs, POSIX_SPAWN_SETEXEC);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix spawn set exec flag");
	ret = posix_spawn(NULL, testpath, NULL, &attrs, arguments, environ);
	T_FAIL("posix_spawn failed with %s\n", strerror(ret));
}

static void
posix_spawn_helper_and_wait_for_exit(char *name)
{
	posix_spawnattr_t attrs;
	int ret;
	pid_t child_pid;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	char **arguments;

	testpath_buf_size = sizeof(testpath);
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");

	posix_spawnattr_init(&attrs);
	set_small_relaunch_values(&attrs);

	arguments = (char *[]) {
		testpath,
		"-n",
		name,
		NULL
	};

	ret = posix_spawn(&child_pid, testpath, NULL, &attrs, arguments, environ);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawn");

	while (true) {
		int status;
		pid_t rc = waitpid(child_pid, &status, 0);
		if (rc == -1 && errno == EINTR) {
			continue;
		}
		T_QUIET; T_ASSERT_EQ(rc, child_pid, "waitpid");
		T_QUIET; T_ASSERT_TRUE(WIFEXITED(status), "Exited cleanly");
		T_QUIET; T_ASSERT_EQ(WEXITSTATUS(status), 0, "return code was 0");
		break;
	}

	posix_spawnattr_destroy(&attrs);
}

T_DECL(posix_spawn_sets_relaunch_flags, "Check that posix_spawn sets the relaunch flags on the new proc")
{
	posix_spawn_helper_and_wait_for_exit("check_relaunch_flags");
}

T_DECL(relaunch_flags_persist_across_exec, "Check that the relaunch flags persist across exec")
{
	posix_spawn_helper_and_wait_for_exit("exec_into_check_relaunch_flags");
}
