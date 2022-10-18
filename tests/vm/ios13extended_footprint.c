#include <darwintest.h>

#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/kern_memorystatus.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

T_DECL(ios13extended_footprint_entitled, "Verify entitled memory limit can be set and queried")
{
	int ret;
	uint64_t memsize = 0;
	size_t memsize_size = sizeof(memsize);
	int32_t ios13extended_footprint_limit_mb = 0;
	size_t ios13extended_footprint_limit_mb_size = sizeof(ios13extended_footprint_limit_mb);

	memorystatus_memlimit_properties2_t mmprops;

	ret = sysctlbyname("hw.memsize", &memsize, &memsize_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get memsize.");

	if (memsize < 1500ULL * 1024 * 1024 ||
	    memsize > 2ULL * 1024 * 1024 * 1024) {
		T_SKIP("This entitlement is only supported on 2GB devices");
	}

	ret = sysctlbyname("kern.ios13extended_footprint_limit_mb", &ios13extended_footprint_limit_mb, &ios13extended_footprint_limit_mb_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get extended limit.");

	mmprops.v1.memlimit_active = -1;
	mmprops.v1.memlimit_inactive = -1;
	ret = memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, getpid(), 0, &mmprops.v1, sizeof(mmprops.v1));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	/* Check our memlimt */
	ret = memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, getpid(), 0, &mmprops, sizeof(mmprops));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	T_QUIET; T_ASSERT_EQ(mmprops.v1.memlimit_active, ios13extended_footprint_limit_mb, "active limit");
	T_QUIET; T_ASSERT_EQ(mmprops.v1.memlimit_inactive, ios13extended_footprint_limit_mb, "inactive limit");

	/* Verify MEMORYSTATUS_CMD_CONVERT_MEMLIMIT_MB */
	ret = memorystatus_control(MEMORYSTATUS_CMD_CONVERT_MEMLIMIT_MB, getpid(), (uint32_t) -1, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");
	T_QUIET; T_ASSERT_EQ(ret, ios13extended_footprint_limit_mb, "got extended footprint");
}
