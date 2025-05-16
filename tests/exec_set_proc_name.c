#include <spawn.h>
#include <libproc.h>
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.spawn"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("spawn"),
	T_META_RUN_CONCURRENTLY(TRUE));

static void
check_myself(char *name)
{
	struct proc_bsdinfo pinfo = {0};
	int ret = proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &pinfo, sizeof(pinfo));
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pidinfo");

	T_LOG("my process name is '%s' (comm is '%s')", pinfo.pbi_name, pinfo.pbi_comm);

	char *found = strstr(pinfo.pbi_name, "exec_set_proc_name");
	T_ASSERT_NOTNULL(found, "proc name of %s", name);
}

T_HELPER_DECL(spawned_helper, "spawned helper")
{
	check_myself("child");
}

T_DECL(set_proc_name, "check process name is correct", T_META_TAG_VM_PREFERRED)
{
	int pid, ret, status;

	check_myself("parent");

	char binpath[MAXPATHLEN];
	uint32_t size = sizeof(binpath);
	ret = _NSGetExecutablePath(binpath, &size);
	T_QUIET; T_ASSERT_EQ(ret, 0, "get binary path");

	ret = dt_launch_tool(&pid, (char *[]) { binpath, "-n", "spawned_helper", NULL }, false, NULL, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn");

	ret = waitpid(pid, &status, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "waitpid");
	T_ASSERT_TRUE(WIFEXITED(status), "child exited");
	T_ASSERT_EQ(WEXITSTATUS(status), 0, "child exit code");
}
