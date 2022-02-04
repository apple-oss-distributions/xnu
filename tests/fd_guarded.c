#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <sys/guarded.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.fd"),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(fd_guard_monitored, "Test that we can guard fds in kevent")
{
	static int pfd[2];
	static dispatch_source_t ds;
	guardid_t guard = (uintptr_t)&pfd;

	T_ASSERT_POSIX_SUCCESS(pipe(pfd), "pipe");

	ds = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
	    (uintptr_t)pfd[0], 0, NULL);
	dispatch_source_set_event_handler(ds, ^{ });
	dispatch_activate(ds);

	T_EXPECT_POSIX_SUCCESS(change_fdguard_np(pfd[0], NULL, 0,
	    &guard, GUARD_DUP | GUARD_CLOSE, NULL), "change_fdguard_np");
}
