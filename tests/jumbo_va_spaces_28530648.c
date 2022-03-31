#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include "jumbo_va_spaces_common.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(TESTNAME,
	"Verify that a required entitlement is present in order to be granted an extra-large "
	"VA space on arm64",
	T_META_CHECK_LEAKS(false))
{
	if (!dt_64_bit_kernel()) {
		T_SKIP("This test is only applicable to arm64");
	}

#if defined(ENTITLED)
	verify_jumbo_va(true);
#else
	verify_jumbo_va(false);
#endif
}
