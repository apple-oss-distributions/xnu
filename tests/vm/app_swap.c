#include <signal.h>
#include <spawn_private.h>
#include <sys/coalition.h>
#include <sys/types.h>
#include <sys/spawn_internal.h>
#include <sys/sysctl.h>
#include <sys/kern_memorystatus.h>
#include <mach/coalition.h>
#include <mach-o/dyld.h>
#include <TargetConditionals.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ENABLED(TARGET_OS_IOS)
	);

T_HELPER_DECL(helper, "Dummy helper")
{
	exit(0);
}

static pid_t
get_coalition_leader(pid_t p)
{
	static const size_t kMaxPids = 500;
	int ret;
	int pid_list[kMaxPids];
	size_t pid_list_size = sizeof(pid_list);

	int iparam[3];
#define p_type  iparam[0]
#define p_order iparam[1]
#define p_pid   iparam[2]
	p_type = COALITION_TYPE_JETSAM;
	p_order = COALITION_SORT_DEFAULT;
	p_pid = p;

	ret = sysctlbyname("kern.coalition_pid_list", pid_list, &pid_list_size, iparam, sizeof(iparam));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.coalition_pid_list");
	T_QUIET; T_ASSERT_LE(pid_list_size, kMaxPids * sizeof(int), "coalition is small enough");

	for (size_t i = 0; i < pid_list_size / sizeof(int); i++) {
		int curr_pid = pid_list[i];
		int roles[COALITION_NUM_TYPES] = {};
		size_t roles_size = sizeof(roles);

		ret = sysctlbyname("kern.coalition_roles", roles, &roles_size, &curr_pid, sizeof(curr_pid));
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.coalition_roles");
		if (roles[COALITION_TYPE_JETSAM] == COALITION_TASKROLE_LEADER) {
			return curr_pid;
		}
	}

	T_FAIL("No leader in coalition!");
	return 0;
}

static pid_t child_pid = 0;
static uint64_t resource_coalition_id = 0;
static uint64_t jetsam_coalition_id = 0;

static void
continue_child_and_wait_for_exit()
{
	int ret, stat;
	/* Resume the child and wait for it to exit. It should exit cleanly. */
	ret = kill(child_pid, SIGCONT);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "failed to send SIGCONT to child process");
	ret = waitpid(child_pid, &stat, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "waitpid");
	T_QUIET; T_ASSERT_TRUE(WIFEXITED(stat), "child exited.");
	T_QUIET; T_ASSERT_EQ(WEXITSTATUS(stat), 0, "child exited cleanly.");
}

static int original_unrestrict_coalitions_val;

static void
unrestrict_coalitions()
{
	int ret, val = 1;
	size_t val_size = sizeof(val);
	size_t original_unrestrict_coalitions_size = sizeof(original_unrestrict_coalitions_val);
	ret = sysctlbyname("kern.unrestrict_coalitions", &original_unrestrict_coalitions_val, &original_unrestrict_coalitions_size, &val, val_size);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "unrestrict_coalitions");
}

static void
reset_unrestrict_coalitions()
{
	size_t size = sizeof(original_unrestrict_coalitions_val);
	int ret = sysctlbyname("kern.unrestrict_coalitions", NULL, NULL, &original_unrestrict_coalitions_val, size);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "unrestrict_coalitions");
}

static uint64_t
create_coalition(int type)
{
	uint64_t id = 0;
	uint32_t flags = 0;
	uint64_t param[2];
	int ret;

	COALITION_CREATE_FLAGS_SET_TYPE(flags, type);
	ret = coalition_create(&id, flags);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "coalition_create");
	T_QUIET; T_ASSERT_GE(id, 0ULL, "coalition_create returned a valid id");

	/* disable notifications for this coalition so launchd doesn't freak out */
	param[0] = id;
	param[1] = 0;
	ret = sysctlbyname("kern.coalition_notify", NULL, NULL, param, sizeof(param));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kern.coalition_notify");

	return id;
}

static void
terminate_and_reap_coalition(uint64_t coalition_id)
{
	int ret = 0;
	ret = coalition_terminate(coalition_id, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "coalition_terminate");

	ret = coalition_reap(coalition_id, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "coalition_reap");
}

static void
terminate_and_reap_coalitions()
{
	terminate_and_reap_coalition(jetsam_coalition_id);
	terminate_and_reap_coalition(resource_coalition_id);
}

/*
 * Spawns the given command as the leader of the given coalitions.
 * Process will start in a stopped state (waiting for SIGCONT)
 */
static pid_t
spawn_coalition_leader(const char *path, char *const *argv, uint64_t resource_coal_id, uint64_t jetsam_coal_id)
{
	int ret;
	posix_spawnattr_t attr;
	extern char **environ;
	pid_t new_pid = 0;
	short spawn_flags = POSIX_SPAWN_START_SUSPENDED;

	ret = posix_spawnattr_init(&attr);
	T_QUIET; T_ASSERT_EQ(ret, 0, "posix_spawnattr_init failed with %s", strerror(ret));

	ret = posix_spawnattr_setcoalition_np(&attr, jetsam_coal_id,
	    COALITION_TYPE_JETSAM, COALITION_TASKROLE_LEADER);
	T_QUIET; T_ASSERT_EQ(ret, 0, "posix_spawnattr_setcoalition_np failed with %s", strerror(ret));
	ret = posix_spawnattr_setcoalition_np(&attr, resource_coal_id,
	    COALITION_TYPE_RESOURCE, COALITION_TASKROLE_LEADER);
	T_QUIET; T_ASSERT_EQ(ret, 0, "posix_spawnattr_setcoalition_np failed with %s", strerror(ret));

	ret = posix_spawnattr_setflags(&attr, spawn_flags);
	T_QUIET; T_ASSERT_EQ(ret, 0, "posix_spawnattr_setflags failed with %s", strerror(ret));

	ret = posix_spawn(&new_pid, path, NULL, &attr, argv, environ);
	T_QUIET; T_ASSERT_EQ(ret, 0, "posix_spawn failed with %s", strerror(ret));

	ret = posix_spawnattr_destroy(&attr);
	T_QUIET; T_ASSERT_EQ(ret, 0, "posix_spawnattr_destroy failed with %s\n", strerror(ret));
	return new_pid;
}

T_DECL(mark_coalition_swappable, "Set coalition is swappable",
    T_META_ASROOT(true),
    T_META_BOOTARGS_SET("kern.swap_all_apps=1"))
{
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	int ret = 0;
	pid_t leader_pid;

	unrestrict_coalitions();
	T_ATEND(reset_unrestrict_coalitions);

	resource_coalition_id = create_coalition(COALITION_TYPE_RESOURCE);
	jetsam_coalition_id = create_coalition(COALITION_TYPE_JETSAM);
	T_ATEND(terminate_and_reap_coalitions);

	testpath_buf_size = sizeof(testpath);
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");

	char *const args[] = {
		testpath,
		"-n",
		"helper",
		NULL
	};
	child_pid = spawn_coalition_leader(testpath, args, resource_coalition_id, jetsam_coalition_id);

	T_ATEND(continue_child_and_wait_for_exit);

	ret = memorystatus_control(MEMORYSTATUS_CMD_GET_PROCESS_COALITION_IS_SWAPPABLE, child_pid, 0, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "MEMORYSTATUS_CMD_GET_PROCESS_COALITION_IS_SWAPPABLE");
	T_QUIET; T_ASSERT_EQ(ret, 0, "process is not swappable at launch");

	leader_pid = get_coalition_leader(child_pid);

	ret = memorystatus_control(MEMORYSTATUS_CMD_MARK_PROCESS_COALITION_SWAPPABLE, leader_pid, 0, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "MEMORYSTATUS_CMD_MARK_PROCESS_COALITION_SWAPPABLE");

	ret = memorystatus_control(MEMORYSTATUS_CMD_GET_PROCESS_COALITION_IS_SWAPPABLE, child_pid, 0, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "MEMORYSTATUS_CMD_GET_PROCESS_COALITION_IS_SWAPPABLE");
	T_QUIET; T_ASSERT_EQ(ret, 1, "process is swappable");
}
