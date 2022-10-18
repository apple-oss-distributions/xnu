#include <sys/kern_memorystatus.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include "memorystatus_assertion_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_CHECK_LEAKS(false)
	);

#if ENTITLED
T_DECL(can_use_internal_bands_with_entitlement, "Can move process into internal bands with entitlement")
#else
T_DECL(can_not_use_internal_bands_without_entitlement, "Can not move process into internal bands with entitlement")
#endif
{
	for (int32_t band = JETSAM_PRIORITY_IDLE + 1; band <= JETSAM_PRIORITY_ENTITLED_MAX; band++) {
		int ret = set_priority(getpid(), band, 0, false);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "set_priority");

		int32_t set_band, limit;
		uint64_t user_data;
		uint32_t state;
		bool success = get_priority_props(getpid(), false, &set_band, &limit, &user_data, &state);
		T_QUIET; T_ASSERT_TRUE(success, "get_priority_props");
#if ENTITLED
		T_QUIET; T_ASSERT_EQ(set_band, band, "Able to use entitled band");
#else
		T_QUIET; T_ASSERT_EQ(set_band, JETSAM_PRIORITY_IDLE, "Fell through to idle band");
#endif
	}
}
