#include <darwintest.h>
#include <darwintest_utils.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/message.h>
#include <mach/mach_error.h>
#include <mach/task.h>

#include <pthread.h>
#include <pthread/workqueue_private.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"));

T_DECL(mach_port_insert_right_123724977, "regression test for 123724977")
{
	mach_port_name_t pset;
	kern_return_t kr;

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &pset);
	T_ASSERT_MACH_SUCCESS(kr, "creating port set");

	kr = mach_port_insert_right(mach_task_self(), pset, pset,
	    MACH_MSG_TYPE_MAKE_SEND);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_RIGHT, "insert right fails");
}
