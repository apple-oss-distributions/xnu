#include <darwintest.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include <dlfcn_private.h>
#include <mach-o/dyld.h>
#include <dispatch/dispatch.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_RUN_CONCURRENTLY(TRUE));

T_DECL(task_dyld_process_info_notify_register,
    "check that task_dyld_process_info_notify_register works")
{
	mach_port_name_t port = MACH_PORT_NULL;
	dispatch_source_t ds;

	T_ASSERT_MACH_SUCCESS(mach_port_allocate(mach_task_self(),
	    MACH_PORT_RIGHT_RECEIVE, &port), "allocate notif port");

	ds = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, port, 0,
	    dispatch_get_global_queue(0, 0));
	dispatch_source_set_event_handler(ds, ^{
		T_PASS("received a message for dlopen!");
		T_END;
	});
	dispatch_activate(ds);

	T_ASSERT_MACH_SUCCESS(task_dyld_process_info_notify_register(mach_task_self(), port),
	    "register dyld notification");

	dlopen("/usr/lib/swift/libswiftRemoteMirror.dylib", RTLD_LAZY);
}
