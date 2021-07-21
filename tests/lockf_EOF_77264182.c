#include <fcntl.h>
#include <sys/fcntl.h>
#include <darwintest.h>
#include <darwintest_utils.h>


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_OWNER("jonathan_w_adams"),
	T_META_RUN_CONCURRENTLY(TRUE));

/*
 * See rdar://77264182: xnu's lockf implementation had trouble
 * with l_len = 0 (e.g. go to EOF) being treated differently
 * than (l_start + l_len - 1) == OFF_MAX, even though they are
 * effectively the same thing.  ~25 loops of this test was enough
 * to get an Intel mac into an infinite loop in the kernel.
 */
T_DECL(lockf_EOF_77264182,
    "try to stress out lockf requests around OFF_MAX/EOF",
    T_META_CHECK_LEAKS(false))
{
	const char *dir = dt_tmpdir();
	int fd;
	T_ASSERT_POSIX_SUCCESS(chdir(dir), "chdir(%s)", dir);

	T_ASSERT_POSIX_SUCCESS((fd = open("lockf_EOF_test", O_CREAT | O_RDWR, 0666)), "open(lockf_EOF_test)");

	/*
	 * At each loop, we do:
	 *	write lock [OFF_MAX - loop, EOF)
	 *	unlock     [OFF_MAX - loop, OFF_MAX)
	 *	write lock [OFF_MAX - loop - 1, OFF_MAX)
	 */
	int loops;
	for (loops = 0; loops < 100; loops++) {
		struct flock fl = {
			.l_start = OFF_MAX - loops,
			.l_len = 0,
			.l_pid = getpid(),
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET
		};
		T_ASSERT_POSIX_SUCCESS(fcntl(fd, F_SETLK, &fl), "wrlock");
		fl.l_len = OFF_MAX - fl.l_start + 1;
		fl.l_type = F_UNLCK;
		T_ASSERT_POSIX_SUCCESS(fcntl(fd, F_SETLK, &fl), "unlock");
		fl.l_start--;
		fl.l_len++;
		fl.l_type = F_WRLCK;
		T_ASSERT_POSIX_SUCCESS(fcntl(fd, F_SETLK, &fl), "wrlock 2");
	}
	T_PASS("did %d loops", loops);
}
