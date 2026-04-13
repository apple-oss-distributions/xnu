#include <darwintest_utils.h>
#include <net/if.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("omer_shapira")
	);

T_DECL(bounds_safety,
    "verify compilation including net/if.h works with and without bounds_safety")
{
#if __has_ptrcheck
	T_PASS("bounds_safety enabled");
#else
	T_PASS("bounds_safety disabled");
#endif
}
