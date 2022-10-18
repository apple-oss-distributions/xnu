#include <sys/sysctl.h>
#include <time.h>

#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

/*
 * trying phys offsets from start of dram of:
 * macOS 3Gig
 */
#define USEBOOTARG "ecc_bad_pages=3221225472 bad_static_mfree=1"

T_DECL(retired_pages_test,
    "Test retiring pages at boot",
    T_META_BOOTARGS_SET(USEBOOTARG),
    T_META_ASROOT(true),
    T_META_CHECK_LEAKS(false),
    T_META_ENABLED(0))
{
	/* TODO: Joe will update/enable test in rdar://70008487 */

	int err;
	unsigned int count = 0;
	size_t s = sizeof(count);

	/*
	 * Get the number of pages retired from the kernel
	 */
	err = sysctlbyname("vm.retired_pages_count", &count, &s, NULL, 0);

	/* If the sysctl isn't supported, test succeeds */
	if (err == ENOENT) {
		T_SKIP("sysctl vm.retired_pages_count not found, skipping test");
	}
	T_ASSERT_POSIX_SUCCESS(err, "sysctl vm.retired_pages_count");

	T_ASSERT_GT_INT(count, 0, "Expect retired pages");
}
