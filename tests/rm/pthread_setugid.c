#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <sys/unistd.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.rm"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("rm"),
    T_META_OWNER("phabouzit")
    );

T_DECL(pthread_setugid_np_81523076,
    "Make sure pthread_setugid_np() isn't sticky to workqueue threads",
    T_META_CHECK_LEAKS(false),
    T_META_ASROOT(true))
{
	int rc;

	rc = pthread_setugid_np(501, getgid());
	T_ASSERT_POSIX_SUCCESS(rc, "pthread_setugid_np(501, getgid())");

	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		T_ASSERT_EQ(getuid(), 0, "getuid should still be 0");
		T_END;
	});
	pause();
}
