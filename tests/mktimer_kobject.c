#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mk_timer.h>

#include <darwintest.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true),
    T_META_NAMESPACE("xnu.ipc"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("IPC"));

T_DECL(mktimer_kobject, "mktimer_kobject()", T_META_ALL_VALID_ARCHS(true), T_META_IGNORECRASHES(".*mktimer_kobject.*"))
{
	mach_port_t timer_port = MACH_PORT_NULL;
	mach_port_t notify_port = MACH_PORT_NULL;

	kern_return_t kr = KERN_SUCCESS;
	task_exc_guard_behavior_t old, new;

	/*
	 * Disable [optional] Mach port guard exceptions to avoid fatal crash
	 */
	kr = task_get_exc_guard_behavior(mach_task_self(), &old);
	T_ASSERT_MACH_SUCCESS(kr, "task_get_exc_guard_behavior");
	new = (old & ~TASK_EXC_GUARD_MP_DELIVER);
	kr = task_set_exc_guard_behavior(mach_task_self(), new);
	T_ASSERT_MACH_SUCCESS(kr, "task_set_exc_guard_behavior new");

	/*
	 * timer port
	 * This is a receive right which is also a kobject
	 */
	timer_port = mk_timer_create();
	T_ASSERT_NE(timer_port, (mach_port_t)MACH_PORT_NULL, "mk_timer_create: %s", mach_error_string(kr));

	mach_port_set_context(mach_task_self(), timer_port, (mach_port_context_t) 0x1);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_set_context(timer_port): %s", mach_error_string(kr));

	/* notification port for the mk_timer port to come back on */
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify_port);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_allocate(notify_port): %s", mach_error_string(kr));

	kr = mach_port_set_context(mach_task_self(), notify_port, (mach_port_context_t) 0x2);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_set_context(notify_port): %s", mach_error_string(kr));

	T_LOG("timer: 0x%x, notify: 0x%x", timer_port, notify_port);

	/*
	 * This code generates a mach port guard exception and should be tested with an exception catcher.
	 * Will be updated in <rdar://problem/70971318>
	 */
	mach_port_t previous = MACH_PORT_NULL;

	/* request a port-destroyed notification on the timer port */
	kr = mach_port_request_notification(mach_task_self(), timer_port, MACH_NOTIFY_PORT_DESTROYED,
	    0, notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);
	/* this will ordinarily fail with a guard exception! */
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_RIGHT, "notifications should NOT work on mk_timer ports!");

	/* restore the old guard behavior */
	kr = task_set_exc_guard_behavior(mach_task_self(), old);
	T_ASSERT_MACH_SUCCESS(kr, "task_set_exc_guard_behavior old");

	T_LOG("done");
}
