#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include <sys/kern_debug.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.debug"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("joster"),
	T_META_ENABLED(FALSE)
	);

T_DECL(debug_enable_syscall_rejection,
    "Verify that syscall rejection works")
{
	syscall_rejection_selector_t masks[] = {
		SYSCALL_REJECTION_ALLOW(SYSCALL_REJECTION_ALL),
		SYSCALL_REJECTION_DENY(2)
	};

	int ret = debug_syscall_reject(masks, 2);

	T_WITH_ERRNO; T_ASSERT_POSIX_SUCCESS(ret, "debug_syscall_reject");

	ret = chdir("/tmp");

	printf("chdir: %i\n", ret);
}
