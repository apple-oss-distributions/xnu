#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <sys/kauth.h>
#include <sys/param.h>
#include <sys/unistd.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.rm"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("rm"),
    T_META_OWNER("phabouzit")
    );

T_DECL(pthread_setugid_np_81523076,
    "Make sure pthread_setugid_np() isn't sticky to workqueue threads",
    T_META_CHECK_LEAKS(false),
    T_META_ASROOT(true),
    T_META_TAG_VM_PREFERRED)
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

T_DECL(pthread_setugid_np_124671138,
    "Make sure pthread_setugid_np() isn't sticky to workqueue threads",
    T_META_CHECK_LEAKS(false),
    T_META_ASROOT(true),
    T_META_ENABLED(false), /* this test takes 10+minutes on some HW */
    T_META_TAG_VM_PREFERRED)
{
	size_t batch = 1024;
	size_t count = roundup(0x0FFFFFFFUL + 10, batch);

	if (dt_ncpu() < 10) {
		T_SKIP("too slow of a test");
	}

	dispatch_apply(count / batch, DISPATCH_APPLY_AUTO, ^(size_t n) {
		int rc;

		for (int i = 0; i < batch; i++) {
		        rc = pthread_setugid_np(501, 501);
		        assert(rc == 0);
		        rc = pthread_setugid_np(KAUTH_UID_NONE, KAUTH_UID_NONE);
		        assert(rc == 0);
		}
		if ((n * batch) % (1024 * batch) == 0) {
		        T_LOG("%.2f\n", n * batch * 100. / count);
		}
	});

	T_PASS("the kernel shouldn't panic due to a leak");
}
