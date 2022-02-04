#include <darwintest.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdlib.h>

#include <TargetConditionals.h>

T_DECL(posix_spawn_alt_rosetta, "verify posix_spawn_set_alt_rosetta_np switches to alternative rosetta runtime",
    T_META_ASROOT(true), T_META_REQUIRES_SYSCTL_EQ("kern.development", 1))
{
#if TARGET_OS_OSX && defined(__arm64__)
	int ret, pid;
	posix_spawnattr_t spawnattr;
	char path[1024];
	uint32_t size = sizeof(path);
	cpu_type_t cpuprefs[] = { CPU_TYPE_X86_64 };
	cpu_type_t subcpuprefs[] = { CPU_SUBTYPE_ANY };
	int wait_ret = 0;

	if (access("/Library/Apple/usr/libexec/oah/libRosettaRuntime", O_RDONLY) != 0) {
		T_SKIP("Rosetta not installed");
		return;
	}

	if (access("/usr/local/libexec/rosetta/runtime_internal", O_RDONLY) != 0) {
		system("mkdir -p /usr/local/libexec/oah");
		system("cp /Library/Apple/usr/libexec/rosetta/runtime /usr/local/libexec/rosetta/runtime_internal");
	}

	T_QUIET; T_ASSERT_EQ(_NSGetExecutablePath(path, &size), 0, NULL);
	T_QUIET; T_ASSERT_LT(strlcat(path, "_helper", size), (unsigned long)size, NULL);

	ret = posix_spawnattr_init(&spawnattr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_init");

	// 1) Run natively

	ret = posix_spawn(&pid, path, NULL, &spawnattr, NULL, NULL);
	T_ASSERT_EQ(ret, 0, "posix_spawn should succeed");
	ret = waitpid(pid, &wait_ret, 0);
	T_QUIET; T_ASSERT_EQ(ret, pid, "child pid");
	T_QUIET; T_ASSERT_EQ(WIFEXITED(wait_ret), 1, "child process should have called exit()");
	T_ASSERT_EQ(WEXITSTATUS(wait_ret), 0, "running natively should return 0");

	// 2) Set archpref to run under Rosetta

	ret = posix_spawnattr_setarchpref_np(&spawnattr, sizeof(cpuprefs) / sizeof(cpuprefs[0]), cpuprefs, subcpuprefs, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_setarchpref_np");

	ret = posix_spawn(&pid, path, NULL, &spawnattr, NULL, NULL);
	T_ASSERT_EQ(ret, 0, "posix_spawn should succeed");
	ret = waitpid(pid, &wait_ret, 0);
	T_QUIET; T_ASSERT_EQ(ret, pid, "child pid");
	T_QUIET; T_ASSERT_EQ(WIFEXITED(wait_ret), 1, "child process should have called exit()");
	T_ASSERT_EQ(WEXITSTATUS(wait_ret), 1, "running in rosetta should return 1");

	// 3) Request alternative Rosetta runtime

	ret = posix_spawnattr_set_alt_rosetta_np(&spawnattr, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_setarchpref_np");

	ret = posix_spawn(&pid, path, NULL, &spawnattr, NULL, NULL);
	T_ASSERT_EQ(ret, 0, "posix_spawn should succeed");
	ret = waitpid(pid, &wait_ret, 0);
	T_QUIET; T_ASSERT_EQ(ret, pid, "child pid");
	T_QUIET; T_ASSERT_EQ(WIFEXITED(wait_ret), 1, "child process should have called exit()");
	T_ASSERT_EQ(WEXITSTATUS(wait_ret), 2, "running with alternative rosetta runtime should return 2");

	ret = posix_spawnattr_destroy(&spawnattr);
	T_QUIET; T_ASSERT_EQ(ret, 0, "posix_spawnattr_destroy");
#else
	T_SKIP("Not arm64 macOS");
#endif
}
