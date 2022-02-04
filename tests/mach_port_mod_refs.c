#include <darwintest.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true),
    T_META_NAMESPACE("xnu.ipc"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("IPC"));

T_DECL(mach_port_mod_refs, "mach_port_mod_refs"){
	mach_port_t port_set;
	mach_port_t port;
	task_exc_guard_behavior_t old, new;
	int ret;

	ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &port_set);
	T_ASSERT_MACH_SUCCESS(ret, "mach_port_allocate MACH_PORT_RIGHT_PORT_SET");

	ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	T_ASSERT_MACH_SUCCESS(ret, "mach_port_allocate MACH_PORT_RIGHT_RECEIVE");

	/*
	 * Disable [optional] Mach port guard exceptions to avoid fatal crash
	 */
	ret = task_get_exc_guard_behavior(mach_task_self(), &old);
	T_ASSERT_MACH_SUCCESS(ret, "task_get_exc_guard_behavior");
	new = (old & ~TASK_EXC_GUARD_MP_DELIVER);
	ret = task_set_exc_guard_behavior(mach_task_self(), new);
	T_ASSERT_MACH_SUCCESS(ret, "task_set_exc_guard_behavior new");

	/*
	 * Test all known variants of port rights on each type of port
	 */

	/* can't subtract a send right if it doesn't exist */
	ret = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_RIGHT, "mach_port_mod_refs SEND: -1 on a RECV right");

	/* can't subtract a send once right if it doesn't exist */
	ret = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND_ONCE, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_RIGHT, "mach_port_mod_refs SEND_ONCE: -1 on a RECV right");

	/* can't subtract a PORT SET right if it's not a port set */
	ret = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_PORT_SET, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_RIGHT, "mach_port_mod_refs PORT_SET: -1 on a RECV right");

	/* can't subtract a dead name right if it doesn't exist */
	ret = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_DEAD_NAME, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_RIGHT, "mach_port_mod_refs DEAD_NAME: -1 on a RECV right");

	/* can't subtract a LABELH right if it doesn't exist */
	ret = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_LABELH, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_RIGHT, "mach_port_mod_refs LABELH: -1 on a RECV right");

	/* can't subtract an invalid right-type */
	ret = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_NUMBER, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_VALUE, "mach_port_mod_refs NUMBER: -1 on a RECV right");

	/* can't subtract an invalid right-type */
	ret = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_NUMBER + 1, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_VALUE, "mach_port_mod_refs NUMBER+1: -1 on a RECV right");


	/* can't subtract a send right if it doesn't exist */
	ret = mach_port_mod_refs(mach_task_self(), port_set, MACH_PORT_RIGHT_SEND, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_RIGHT, "mach_port_mod_refs SEND: -1 on a PORT_SET right");

	/* can't subtract a send once right if it doesn't exist */
	ret = mach_port_mod_refs(mach_task_self(), port_set, MACH_PORT_RIGHT_SEND_ONCE, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_RIGHT, "mach_port_mod_refs SEND_ONCE: -1 on a PORT_SET right");

	/* can't subtract a receive right if it's a port set */
	ret = mach_port_mod_refs(mach_task_self(), port_set, MACH_PORT_RIGHT_RECEIVE, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_RIGHT, "mach_port_mod_refs RECV: -1 on a PORT_SET right");

	/* can't subtract a dead name right if it doesn't exist */
	ret = mach_port_mod_refs(mach_task_self(), port_set, MACH_PORT_RIGHT_DEAD_NAME, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_RIGHT, "mach_port_mod_refs DEAD_NAME: -1 on a PORT_SET right");

	/* can't subtract a LABELH right if it doesn't exist */
	ret = mach_port_mod_refs(mach_task_self(), port_set, MACH_PORT_RIGHT_LABELH, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_RIGHT, "mach_port_mod_refs LABELH: -1 on a PORT_SET right");

	/* can't subtract an invalid right-type */
	ret = mach_port_mod_refs(mach_task_self(), port_set, MACH_PORT_RIGHT_NUMBER, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_VALUE, "mach_port_mod_refs NUMBER: -1 on a PORT_SET right");

	/* can't subtract an invalid right-type */
	ret = mach_port_mod_refs(mach_task_self(), port_set, MACH_PORT_RIGHT_NUMBER + 1, -1);
	T_ASSERT_EQ(ret, KERN_INVALID_VALUE, "mach_port_mod_refs NUMBER+1: -1 on a PORT_SET right");

	/* restore the old guard behavior */
	ret = task_set_exc_guard_behavior(mach_task_self(), old);
	T_ASSERT_MACH_SUCCESS(ret, "task_set_exc_guard_behavior old");

	/*
	 * deallocate the ports/sets
	 */
	ret = mach_port_mod_refs(mach_task_self(), port_set, MACH_PORT_RIGHT_PORT_SET, -1);
	T_ASSERT_MACH_SUCCESS(ret, "mach_port_mod_refs(PORT_SET, -1)");

	ret = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
	T_ASSERT_MACH_SUCCESS(ret, "mach_port_mod_refs(RECV_RIGHT, -1)");
}
