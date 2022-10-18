#include <darwintest.h>
#include <darwintest_utils.h>

#include <TargetConditionals.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/mach_error.h>
#include <mach/task.h>

#include <servers/bootstrap.h>

#include <sys/resource.h>

#include <kern/kcdata.h>

#include <os/reason_private.h>

#include <System/uuid/uuid.h>
#include "exc_helpers.h"

#include <unistd.h>
#include <errno.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"));


bool expect_backtrace = TRUE;

static kern_return_t
exc_handler_backtrace(
	mach_port_t kcdata_object,
	exception_type_t exception,
	mach_exception_data_t codes)
{
	kern_return_t kr;
	mach_vm_address_t btinfo_begin;
	mach_vm_size_t btinfo_size;

	if (expect_backtrace == FALSE) {
		T_FAIL("Does not expect backtrace for this test case");
	}

	T_LOG("Received backtrace exception.");
	T_ASSERT_EQ(exception, EXC_CORPSE_NOTIFY, "Exception should be corpse notify");
	T_ASSERT_EQ(codes[0], EXC_GUARD, "Effective exception should be EXC_GUARD");

	kr = task_map_kcdata_object_64(mach_task_self(), kcdata_object, &btinfo_begin, &btinfo_size);
	T_ASSERT_MACH_SUCCESS(kr, "task_map_kcdata_object_64() should succeed");

	kcdata_iter_t btdata = kcdata_iter((void *)btinfo_begin, (unsigned long)btinfo_size);
	if (kcdata_iter_valid(btdata) && kcdata_iter_type(btdata) == TASK_BTINFO_BEGIN) {
		/* loop through data provided by kernel */
		KCDATA_ITER_FOREACH(btdata) {
			switch (kcdata_iter_type(btdata)) {
			case TASK_BTINFO_GID: {
				int gid = *(int *)(kcdata_iter_payload(btdata));
				T_LOG("Found TASK_BTINFO_GID: %d", gid);
				break;
			}
			case TASK_BTINFO_CPUTYPE: {
				cpu_type_t type = *(cpu_type_t *)(kcdata_iter_payload(btdata));
				T_LOG("Found TASK_BTINFO_CPUTYPE: %d", type);
				break;
			}
			case TASK_BTINFO_THREAD_STATE: {
				struct btinfo_thread_state_data_t data = *(struct btinfo_thread_state_data_t *)(kcdata_iter_payload(btdata));
				T_LOG("Found TASK_BTINFO_THREAD_STATE: Flavor %d, Count %d", data.flavor, data.count);
				break;
			}
			case TASK_BTINFO_THREAD_EXCEPTION_STATE: {
				struct btinfo_thread_state_data_t data = *(struct btinfo_thread_state_data_t *)(kcdata_iter_payload(btdata));
				T_LOG("Found TASK_BTINFO_THREAD_EXCEPTION_STATE: Flavor %d, Count %d", data.flavor, data.count);
				break;
			}
			case TASK_BTINFO_PROC_NAME: {
		    #define MAXCOMLEN 16
				char process_name[MAXCOMLEN + 1];
				memcpy(process_name, kcdata_iter_payload(btdata), MAXCOMLEN); // limited to 16 chars
				process_name[MAXCOMLEN] = '\0'; // ensure string is null terminated
				T_LOG("Found TASK_BTINFO_PROC_NAME: %s", process_name);
				break;
			}
			case TASK_BTINFO_PROC_PATH: {
				const char *c_str = (const char *)kcdata_iter_payload(btdata);
				T_LOG("Found TASK_BTINFO_PROC_PATH: %s", c_str);
				break;
			}
			case TASK_BTINFO_PLATFORM: {
				uint32_t platform = *(uint32_t *)(kcdata_iter_payload(btdata));
				T_LOG("Found TASK_BTINFO_PLATFORM: %d", platform);
				break;
			}
			case TASK_BTINFO_RUSAGE_INFO: {
				struct rusage_info_v0 rui = *(struct rusage_info_v0 *)kcdata_iter_payload(btdata);
				uuid_string_t uuid;
				uint64_t _proc_start_abstime = rui.ri_proc_start_abstime;
				uint64_t _proc_exit_abstime = rui.ri_proc_exit_abstime;
				uuid_unparse(rui.ri_uuid, uuid);
				T_LOG("Found TASK_BTINFO_RUSAGE_INFO: uuid: %s, start time: %llu, \
					exit time: %llu", uuid, _proc_start_abstime, _proc_exit_abstime);
				break;
			}
			case TASK_BTINFO_SC_LOADINFO64: {
				struct btinfo_sc_load_info64 info = *(struct btinfo_sc_load_info64 *)kcdata_iter_payload(btdata);
				uuid_string_t uuid;
				uuid_unparse(info.sharedCacheUUID, uuid);
				T_LOG("Found TASK_BTINFO_SC_LOADINFO64: uuid: %s, slide: %llu, base: %llu",
				    uuid, info.sharedCacheSlide, info.sharedCacheBaseAddress);
				break;
			}
			case TASK_BTINFO_SC_LOADINFO: {
				struct btinfo_sc_load_info info = *(struct btinfo_sc_load_info *)kcdata_iter_payload(btdata);
				uuid_string_t uuid;
				uuid_unparse(info.sharedCacheUUID, uuid);
				T_LOG("Found TASK_BTINFO_SC_LOADINFO: uuid: %s, slide: %d, base: %d",
				    uuid, info.sharedCacheSlide, info.sharedCacheBaseAddress);
				break;
			}
			case EXIT_REASON_SNAPSHOT: {
				struct exit_reason_snapshot *snapshot = (struct exit_reason_snapshot *)kcdata_iter_payload(btdata);
				T_LOG("Found EXIT_REASON_SNAPSHOT with namespace %x code %x", snapshot->ers_namespace, snapshot->ers_code);
				break;
			}
			case KCDATA_TYPE_ARRAY: {
				int count = kcdata_iter_array_elem_count(btdata);
				uint32_t type = kcdata_iter_array_elem_type(btdata);
				uint32_t size = kcdata_iter_array_elem_size(btdata);

				if (type == TASK_BTINFO_BACKTRACE64) {
					T_LOG("Found TASK_BTINFO_BACKTRACE64, with %d backtrace frames", count);
					T_QUIET; T_ASSERT_EQ(size, sizeof(uint64_t), "Address size should be 64 bits");

					for (int i = 0; i < count; i++) {
						T_LOG("Frame %d: %p", i, ((uint64_t *)kcdata_iter_payload(btdata))[i]);
					}
				} else if (type == TASK_BTINFO_DYLD_LOADINFO64) {
					T_LOG("Found TASK_BTINFO_DYLD_LOADINFO64, with %d image infos", count);
					T_QUIET; T_ASSERT_EQ(size, sizeof(struct dyld_uuid_info_64), "Struct size should match");

					for (int i = 0; i < count; i++) {
						uuid_string_t uuid_str;
						uuid_unparse(((struct dyld_uuid_info_64 *)kcdata_iter_payload(btdata))[i].imageUUID, uuid_str);

						T_LOG("Image %d: <%s, %p>", i, uuid_str,
						    ((struct dyld_uuid_info_64 *)kcdata_iter_payload(btdata))[i].imageLoadAddress);
					}
				} else if (type == TASK_BTINFO_BACKTRACE) {
					T_LOG("Found TASK_BTINFO_BACKTRACE, with %d backtrace frames", count);
					T_QUIET; T_ASSERT_EQ(size, sizeof(uint64_t), "Address size on arm64_32 should be 64 bits");

					for (int i = 0; i < count; i++) {
						T_LOG("Frame %d: %p", i, ((uint32_t *)kcdata_iter_payload(btdata))[i]);
					}
				} else if (type == TASK_BTINFO_DYLD_LOADINFO) {
					T_LOG("Found TASK_BTINFO_DYLD_LOADINFO, with %d image infos", count);
					T_QUIET; T_ASSERT_EQ(size, sizeof(struct dyld_uuid_info_32), "Struct size should match");

					for (int i = 0; i < count; i++) {
						uuid_string_t uuid_str;
						uuid_unparse(((struct dyld_uuid_info_32 *)kcdata_iter_payload(btdata))[i].imageUUID, uuid_str);

						T_LOG("Image %d: <%s, %p>", i, uuid_str,
						    ((struct dyld_uuid_info_32 *)kcdata_iter_payload(btdata))[i].imageLoadAddress);
					}
				}
				break;
			}
			case TASK_BTINFO_THREAD_ID: {
				uint64_t thread_id = *(uint64_t *)(kcdata_iter_payload(btdata));
				T_LOG("Found TASK_BTINFO_THREAD_ID: 0x%lx", thread_id);
				break;
			}
			default:
				break;
			}
		}
	} else {
		T_FAIL("Unexpected kcdata object type");
	}

	mach_vm_deallocate(mach_task_self(), btinfo_begin, btinfo_size);
	mach_port_deallocate(mach_task_self(), kcdata_object);

	T_END;
}

static size_t
exc_handler_identity_protected(
	task_id_token_t token,
	__unused uint64_t thread_id,
	__unused exception_type_t type,
	__unused exception_data_t codes)
{
	mach_port_t port1, port2;
	kern_return_t kr;

	if (expect_backtrace) {
		T_FAIL("Expect backtrace for this test case");
	}

	T_LOG("Got protected exception!");

	port1 = mach_task_self();
	kr = task_identity_token_get_task_port(token, TASK_FLAVOR_CONTROL, &port2); /* Immovable control port for self */
	T_ASSERT_MACH_SUCCESS(kr, "task_identity_token_get_task_port() - CONTROL");
	T_EXPECT_EQ(port1, port2, "Control port matches!");

	T_END;
}

/* Lightweight corpse not enabled on macOS yet */
#if !TARGET_OS_OSX
T_DECL(corpse_backtrace_os_log_lightweight,
    "Test os_log_fault() fast backtracing with lightweight corpse",
    T_META_CHECK_LEAKS(false)) /* Test may otherwise time out after T_END */
{
	mach_port_t exc_port = MACH_PORT_NULL;

	expect_backtrace = TRUE;

	exc_port = create_exception_port_behavior64(EXC_MASK_CORPSE_NOTIFY,
	    EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_BACKTRACE_PREFERRED);

	T_ASSERT_NE(exc_port, MACH_PORT_NULL, "Exception port should be valid.");

	T_LOG("Exception port: %d\n", exc_port);

	run_exception_handler_behavior64(exc_port, exc_handler_backtrace, NULL,
	    EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_BACKTRACE_PREFERRED);

	/* Generate a non-fatal EXC_GUARD */
	uint64_t payload = 0xDEADBEEF;
	int ret = os_fault_with_payload(OS_REASON_LIBSYSTEM, OS_REASON_LIBSYSTEM_CODE_FAULT,
	    &payload, sizeof(payload), "Generating a user fault", 0);
	T_QUIET; T_ASSERT_EQ(ret, 0, "os_fault_with_payload should succeed");

	T_LOG("Wait for exception on main thread..");
	for (int i = 0; i < 10; i++) {
		sleep(2);
	}

	T_FAIL("Did not receive exception within timeout");
}
#endif

T_DECL(corpse_backtrace_bad_access,
    "Test os_bad_access fast backtracing with lightweight corpse",
    T_META_CHECK_LEAKS(false))
{
	mach_port_t exc_port = MACH_PORT_NULL;

	expect_backtrace = FALSE;
	/* Prefer backtrace on EXC_BAD_ACCESS, but should be ignored by kernel */
	exc_port = create_exception_port_behavior64(EXC_MASK_BAD_ACCESS,
	    EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_BACKTRACE_PREFERRED);

	T_ASSERT_NE(exc_port, MACH_PORT_NULL, "Exception port should be valid.");

	T_LOG("Exception port 2: %d\n", exc_port);

	run_exception_handler_behavior64(exc_port, exc_handler_backtrace, exc_handler_identity_protected,
	    EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_BACKTRACE_PREFERRED);

	/* Generate an EXC_BAD_ACCESS */
	*(void *volatile*)0 = 0;

	T_FAIL("Should not reach here");
}

T_DECL(corpse_backtrace_os_log_lightweight_reportcrash,
    "Test os_log_fault() fast backtracing with lightweight corpse and report crash",
    T_META_ENABLED(false))
{
	mach_port_t rc_port = MACH_PORT_NULL, bootstrap = MACH_PORT_NULL;
	kern_return_t kr;

	expect_backtrace = TRUE;

	kr = task_get_bootstrap_port(mach_task_self(), &bootstrap);

	kr = bootstrap_look_up(bootstrap, "com.apple.ReportCrash", &rc_port);

	T_ASSERT_NE(rc_port, MACH_PORT_NULL, "Exception port should be valid.");

	T_LOG("ReportCrash exception port: %d\n", rc_port);

#ifndef ARM_THREAD_STATE
#define ARM_THREAD_STATE 1
#endif

	kr = task_set_exception_ports(mach_task_self(),
	    EXC_MASK_CORPSE_NOTIFY,
	    rc_port,
	    EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_BACKTRACE_PREFERRED | MACH_EXCEPTION_CODES,
	    ARM_THREAD_STATE);

	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Registration with ReportCrash should succeed");

	/* Generate a non-fatal EXC_GUARD */
	uint64_t payload = 0xDEADBEEF;
	int ret = os_fault_with_payload(OS_REASON_LIBSYSTEM, OS_REASON_LIBSYSTEM_CODE_FAULT,
	    &payload, sizeof(payload), "Generating a user fault", 0);
	T_QUIET; T_ASSERT_EQ(ret, 0, "os_fault_with_payload should succeed");

	T_LOG("Kernel should have delivered a message to ReportCrash. Exit now.");
	T_END;
}
