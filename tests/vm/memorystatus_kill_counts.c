#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#include <sys/kern_memorystatus.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(false),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

#define MAX_TRIES 3

static int
get_kill_counts(uint32_t *buffer, size_t buffer_size, int band, int flags)
{
	return memorystatus_control(MEMORYSTATUS_CMD_GET_KILL_COUNTS, band, flags, buffer, buffer_size);
}

T_HELPER_DECL(thrown_overboard, "child to be jetsammed") {
	for (;;) {
		sleep(1);
	}
}

static void
spawn_and_jetsam(int32_t band)
{
	static char path[PATH_MAX] = {0};
	static uint32_t path_size = sizeof(path);
	int error;
	pid_t child;
	memorystatus_priority_properties_t prop;

	if (!path[0]) {
		T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	}

	char *args[] = { path, "-n", "thrown_overboard", NULL};
	error = dt_launch_tool(&child, args, false, NULL, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(error, "spawn child");
	prop.priority = band;
	prop.user_data = 0;
	error = memorystatus_control(MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES, child, 0, &prop, sizeof(prop));
	T_QUIET; T_ASSERT_POSIX_ZERO(error, "set child properties");
	error = memorystatus_control(MEMORYSTATUS_CMD_TEST_JETSAM, child, 0, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_ZERO(error, "jetsam child");
}

#define N_TEST_BANDS 5
int32_t test_bands[N_TEST_BANDS] = {0, 30, 35, 40, 45};
int32_t proc_counts[N_TEST_BANDS] = {2, 3, 1, 2, 4};

#define BUFFER_SIZE (sizeof(uint32_t) * (JETSAM_REASON_MEMORYSTATUS_MAX + 1))

T_DECL(memorystatus_kill_counts, "jetsam kill counts",
    T_META_ASROOT(true))
{
	int i, j;
	uint32_t *buffers[N_TEST_BANDS];

	/* Spawn a handful of children and kill them */
	for (i = 0; i < N_TEST_BANDS; i++) {
		buffers[i] = malloc(BUFFER_SIZE);
		T_QUIET; T_ASSERT_POSIX_NOTNULL(buffers[i], "malloc()");
		for (j = 0; j < proc_counts[i]; j++) {
			spawn_and_jetsam(test_bands[i]);
		}
	}

	void (^get_all_kill_counts)(uint32_t**, int) = ^(uint32_t **buffers, int flags){
		int i, error;
		for (i = 0; i < N_TEST_BANDS; i++) {
			error = get_kill_counts(buffers[i], BUFFER_SIZE, test_bands[i], flags);
			T_ASSERT_POSIX_ZERO(error, "get kill counts (band %d)", test_bands[i]);
		}
	};

	/* Query for size */
	void (^check_buffer)(uint32_t**, bool) = ^(uint32_t **buffers, bool expect_missing) {
		int i;
		bool missing_proc;

		missing_proc = false;
		for (i = 0; i < N_TEST_BANDS; i++) {
			uint32_t count = buffers[i][kMemorystatusKilled];
			missing_proc = missing_proc || (count < proc_counts[i]);
			if (!expect_missing) {
				T_QUIET; T_EXPECT_LE(proc_counts[i], count, "Children in band %d found in kill list.", test_bands[i]);
			}
		}

		if (!expect_missing) {
			T_EXPECT_FALSE(missing_proc, "Found all children in kill list");
		} else {
			T_EXPECT_TRUE(missing_proc, "Previously cleared entries not in list");
		}
	};

	/* Get the list once, and don't clear it. */
	T_LOG("--- Getting kill counts (without clear) ---");
	get_all_kill_counts(buffers, 0);
	check_buffer(buffers, false);

	/* Check again (w/ clear) - The list should still have the same entries. */
	T_LOG("--- Getting kill counts (with clear) ---");
	get_all_kill_counts(buffers, MEMORYSTATUS_GET_KILL_COUNTS_CLEAR);
	check_buffer(buffers, false);

	/*
	 * Check one last time - The list should have been cleared.
	 * Things could have been jetsammed since we cleared the list, but we only
	 * care about the presence of our test children who have a generic
	 * jetsam reason - that shouldn't happen elsewhere.
	 */
	T_LOG("--- Getting kill counts (after clear) ---");
	get_all_kill_counts(buffers, 0);
	check_buffer(buffers, true);
}
