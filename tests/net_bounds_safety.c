#include <darwintest_utils.h>
#include <net/if.h>

T_DECL(net_bounds_safety,
    "verify compilation including net/if.h works with and without bounds_safety")
{
#if __has_ptrcheck
	T_PASS("bounds_safety enabled");
#else
	T_PASS("bounds_safety disabled");
#endif
}
