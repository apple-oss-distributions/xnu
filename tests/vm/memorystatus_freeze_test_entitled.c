/*
 * Freezer unit tests that require the memorystatus entitlement.
 * All other freezer unit tests should go in vm/memorystatus_freeze_test.c
 */

#include <dispatch/dispatch.h>
#include <signal.h>
#include <sys/kern_memorystatus.h>
#include <sys/kern_memorystatus_freeze.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_CHECK_LEAKS(false)
	);


T_HELPER_DECL(simple_bg, "no-op bg process") {
	signal(SIGUSR1, SIG_IGN);
	dispatch_source_t ds_signal = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
	if (ds_signal == NULL) {
		T_LOG("[fatal] dispatch source create failed.");
		exit(2);
	}

	dispatch_source_set_event_handler(ds_signal, ^{
		exit(0);
	});

	dispatch_activate(ds_signal);
	dispatch_main();
}

static pid_t helper_pid;
static void
signal_helper_process(void)
{
	kill(helper_pid, SIGUSR1);
}

T_DECL(memorystatus_disable_freeze_in_other_process, "memorystatus_disable_freezer for another process",
    T_META_BOOTARGS_SET("freeze_enabled=1"),
    T_META_REQUIRES_SYSCTL_EQ("vm.freeze_enabled", 1))
{
	helper_pid = launch_background_helper("simple_bg", true, true);
	T_ATEND(signal_helper_process);

	kern_return_t kern_ret = memorystatus_control(MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE, helper_pid, 0, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kern_ret, "set helper process as not freezable");
}
