/*
 * Copyright (c) 2023 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 *	File:	vm/vm_sanitize_telemetry.c
 *
 *	Telemetry for VM functions to detect issues and risks as part of VM API
 *	hygiene work.
 */

/*
 * Implementation relies on CoreAnalytics for telemetry infrastructure.
 * It relies on telemetry.c for getting and encoding UUIDs and slides.
 */

#include <kern/backtrace.h>
#include <kern/telemetry.h>
#include <libkern/coreanalytics/coreanalytics.h>
#include <mach/resource_monitors.h>
#include <mach/sdt.h>
#include <os/log.h>
#include <sys/kdebug_triage.h>
#include <vm/vm_sanitize_telemetry.h>
#include <vm/vm_protos.h>

#pragma mark KTriage strings

static const char *vm_sanitize_triage_strings[] =
{
	[KDBG_TRIAGE_VM_SANITIZE_PREFIX] = "VM API - Unsanitary input passed to ",
	[KDBG_TRIAGE_VM_SANITIZE_MACH_MAKE_MEMORY_ENTRY]     = "mach_make_memory_entry\n",
	[KDBG_TRIAGE_VM_SANITIZE_MACH_MEMORY_ENTRY_PAGE_OP]  = "mach_memory_entry_page_op\n",
	[KDBG_TRIAGE_VM_SANITIZE_MACH_MEMORY_ENTRY_RANGE_OP] = "mach_memory_entry_range_op\n",
	[KDBG_TRIAGE_VM_SANITIZE_MACH_MEMORY_ENTRY_MAP_SIZE] = "mach_memory_entry_map_size\n",
	[KDBG_TRIAGE_VM_SANITIZE_MACH_MEMORY_OBJECT_MEMORY_ENTRY] = "mach_memory_object_memory_entry\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_ALLOCATE_FIXED]          = "vm_allocate(VM_FLAGS_FIXED)\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_ALLOCATE_ANYWHERE]       = "vm_allocate(VM_FLAGS_ANYWHERE)\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_DEALLOCATE]              = "vm_deallocate\n",
	[KDBG_TRIAGE_VM_SANITIZE_MUNMAP]                     = "munmap\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_REMAP]               = "vm_remap or vm_remap_new\n",
	[KDBG_TRIAGE_VM_SANITIZE_MMAP]                       = "mmap\n",
	[KDBG_TRIAGE_VM_SANITIZE_MAP_WITH_LINKING_NP]        = "map_with_linking_np\n",
	[KDBG_TRIAGE_VM_SANITIZE_ENTER_MEM_OBJ]              = "vm_map\n",
	[KDBG_TRIAGE_VM_SANITIZE_ENTER_MEM_OBJ_CTL]          = "vm_map\n",
	[KDBG_TRIAGE_VM_SANITIZE_MREMAP_ENCRYPTED]           = "mremap_encrypted\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_WIRE_USER]               = "vm_wire\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_UNWIRE_USER]             = "vm_wire\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_WIRE]                = "vm_map_wire\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_UNWIRE]              = "vm_map_unwire\n",
	[KDBG_TRIAGE_VM_SANITIZE_VSLOCK]                     = "vslock\n",
	[KDBG_TRIAGE_VM_SANITIZE_VSUNLOCK]                   = "vsunlock\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_COPY_OVERWRITE]      = "vm_map_copy_overwrite\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_COPYIN]              = "vm_map_copyin\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_READ_USER]           = "vm_read\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_WRITE_USER]          = "vm_write\n",
	[KDBG_TRIAGE_VM_SANITIZE_MACH_VM_INHERIT]            = "mach_vm_inherit\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_INHERIT]                 = "vm_inherit\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM32_INHERIT]               = "vm32_inherit\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_INHERIT]             = "vm_map_inherit\n",
	[KDBG_TRIAGE_VM_SANITIZE_MINHERIT]                   = "minherit\n",
	[KDBG_TRIAGE_VM_SANITIZE_MACH_VM_PROTECT]            = "mach_vm_protect\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_PROTECT]                 = "vm_protect\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM32_PROTECT]               = "vm32_protect\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_PROTECT]             = "vm_map_protect\n",
	[KDBG_TRIAGE_VM_SANITIZE_MPROTECT]                   = "mprotect\n",
	[KDBG_TRIAGE_VM_SANITIZE_USERACC]                    = "useracc\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_MSYNC]               = "vm_map_msync\n",
	[KDBG_TRIAGE_VM_SANITIZE_MSYNC]                      = "msync\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_MACHINE_ATTRIBUTE]   = "vm_map_machine_attribute\n",
	[KDBG_TRIAGE_VM_SANITIZE_MINCORE]                    = "mincore\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_PAGE_RANGE_INFO]     = "vm_map_page_range_info\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_MAP_PAGE_RANGE_QUERY]    = "vm_map_page_range_query\n",
	[KDBG_TRIAGE_VM_SANITIZE_VM_BEHAVIOR_SET]            = "vm_behavior_set\n",
	[KDBG_TRIAGE_VM_SANITIZE_MADVISE]                    = "madvise\n",
	[KDBG_TRIAGE_VM_SANITIZE_MACH_VM_DEFERRED_RECLAMATION_BUFFER_INIT] = "mach_vm_deferred_reclamation_buffer_init\n",
	[KDBG_TRIAGE_VM_SANITIZE_MACH_VM_RANGE_CREATE]       = "mach_vm_range_create\n",
	[KDBG_TRIAGE_VM_SANITIZE_SHARED_REGION_MAP_AND_SLIDE_2_NP] = "shared_region_map_and_slide_2_np\n",
	[KDBG_TRIAGE_VM_SANITIZE_TEST]                       = "vm_sanitize_run_test\n",
};

static ktriage_strings_t ktriage_vm_sanitize_subsystem_strings = {VM_SANITIZE_MAX_TRIAGE_STRINGS, vm_sanitize_triage_strings};


#pragma mark Lengths for CA event fields

#define VM_SANITIZE_BACKTRACE_FRAME_COUNT (10)
#define CA_VM_PROCESS_NAME_LEN 33

static_assert(CA_VM_PROCESS_NAME_LEN == (2 * MAXCOMLEN + 1));

#define CA_VM_BACKTRACE_AND_SYM_LEN 340

#define CA_VM_BACKTRACE_BYTES_PER_FRAME (8)
#define CA_VM_SYM_INFO_ENTRY_LEN (52)
#define CA_VM_MAX_EXPECTED_KEXTS (4)

#define CA_VM_BT_LEN (VM_SANITIZE_BACKTRACE_FRAME_COUNT * CA_VM_BACKTRACE_BYTES_PER_FRAME)
#define CA_VM_KERNEL_UUID_DATA_LEN (CA_VM_SYM_INFO_ENTRY_LEN)
#define CA_VM_KEXT_UUID_DATA_LEN (CA_VM_MAX_EXPECTED_KEXTS * CA_VM_SYM_INFO_ENTRY_LEN)

static_assert(CA_VM_BACKTRACE_AND_SYM_LEN == CA_VM_BT_LEN + CA_VM_KERNEL_UUID_DATA_LEN + CA_VM_KEXT_UUID_DATA_LEN);

#pragma mark Packing for method and checker

/*
 *
 * 63       60 59       40 39       20 19       0
 * +----------+-----------+-----------+---------+
 * | reserved |checker cnt|  checker  |  method |
 * +----------+-----------+-----------+---------+
 */

#define CA_VM_PACKING_METHOD_OFFSET (0)
#define CA_VM_PACKING_CHECKER_OFFSET (20)
#define CA_VM_PACKING_CHECKER_COUNT_OFFSET (40)

#define CA_VM_PACK(method, checker, checker_count) (               \
	((method) << CA_VM_PACKING_METHOD_OFFSET)                  \
	| ((checker) << CA_VM_PACKING_CHECKER_OFFSET)              \
	| ((checker_count) << CA_VM_PACKING_CHECKER_COUNT_OFFSET))

#pragma mark Extern declarations for BSD functions

extern const char *proc_best_name(struct proc *proc);
extern void proc_getexecutableuuid(void *p, unsigned char *uuidbuf, unsigned long size);

#pragma mark Event declaration

/*
 * DO NOT change the event name, or we will stop getting telemetry.
 * DO NOT rename fields, or that data will be lost.
 * Ideally, DO NOT change this event at all.
 */
CA_EVENT(vm_sanitize_updated_return_code,
    CA_STATIC_STRING(CA_VM_BACKTRACE_AND_SYM_LEN), backtrace,
    CA_STATIC_STRING(CA_VM_PROCESS_NAME_LEN), process_name,
    CA_STATIC_STRING(CA_UUID_LEN), process_uuid,
    CA_INT, method_checker_info,
    CA_INT, arg1,
    CA_INT, arg2,
    CA_INT, arg3,
    CA_INT, arg4,
    CA_INT, future_ret,
    CA_INT, past_ret);

#pragma mark Globals

#if !(DEBUG || DEVELOPMENT)
static const
#endif
// Set by a sysctl to disable telemetry while tests are running.
uint32_t disable_vm_sanitize_telemetry = 0;

#pragma mark CoreAnalytics wrapper implementation

static void
vm_sanitize_populate_symbolicatable_backtrace_string(uintptr_t addr, char *buffer, size_t buf_size)
{
	uintptr_t frames[VM_SANITIZE_BACKTRACE_FRAME_COUNT];
	struct backtrace_control ctl = BTCTL_INIT;
	ctl.btc_frame_addr = addr;
	backtrace_info_t info = 0;
	int backtrace_count = backtrace(frames, VM_SANITIZE_BACKTRACE_FRAME_COUNT, &ctl, &info);
	telemetry_backtrace_to_string(buffer, buf_size, backtrace_count, frames);
}

static void
vm_sanitize_populate_process_name(struct proc *proc, char buffer[static CA_VM_PROCESS_NAME_LEN])
{
	const char *proc_name = proc_best_name(proc);
	strlcpy(buffer, proc_name, CA_VM_PROCESS_NAME_LEN);
}

static void
vm_sanitize_populate_process_uuid(struct proc *proc, char buffer[static sizeof(uuid_string_t)])
{
	uuid_t parsed_uuid = { 0 };
	proc_getexecutableuuid(proc, parsed_uuid, sizeof(parsed_uuid));
	uuid_unparse(parsed_uuid, buffer);
}

static void
vm_sanitize_send_telemetry_core_analytics(
	vm_sanitize_method_t method,
	vm_sanitize_checker_t checker,
	vm_sanitize_checker_count_t checker_count,
	uint64_t arg1,
	uint64_t arg2,
	uint64_t arg3,
	uint64_t arg4,
	uint64_t future_ret,
	uint64_t past_ret)
{
	struct proc *proc = current_proc();
	ca_event_t ca_event = CA_EVENT_ALLOCATE_FLAGS(vm_sanitize_updated_return_code, Z_NOWAIT | Z_ZERO);
	if (NULL == ca_event) {
		os_log_error(OS_LOG_DEFAULT, "Failed to allocate event for VM API telemetry.");
		return;
	}
	CA_EVENT_TYPE(vm_sanitize_updated_return_code) * event_data = ca_event->data;

	vm_sanitize_populate_symbolicatable_backtrace_string((uintptr_t)__builtin_frame_address(0), event_data->backtrace, sizeof(event_data->backtrace));

	vm_sanitize_populate_process_name(proc, event_data->process_name);

	vm_sanitize_populate_process_uuid(proc, event_data->process_uuid);

	event_data->method_checker_info = CA_VM_PACK(method, checker, checker_count);
	event_data->arg1 = arg1;
	event_data->arg2 = arg2;
	event_data->arg3 = arg3;
	event_data->arg4 = arg4;
	event_data->future_ret = future_ret;
	event_data->past_ret = past_ret;

	CA_EVENT_SEND(ca_event);
	return;
}

#pragma mark KTriage wrapper implementation

static bool ktriage_initialized = false;

static void
vm_sanitize_initialize_ktriage()
{
	if (ktriage_initialized) {
		return;
	}
	if (__improbable(0 != ktriage_register_subsystem_strings(
		    KDBG_TRIAGE_SUBSYS_VM_SANITIZE,
		    &ktriage_vm_sanitize_subsystem_strings))) {
		panic("Failed to set up ktriage for VM sanitization.");
	}
	ktriage_initialized = true;
}

static void
vm_sanitize_ktriage_record(
	enum vm_sanitize_subsys_error_codes ktriage_code,
	uint64_t past_ret)
{
	vm_sanitize_initialize_ktriage();
	if (ktriage_code != KDBG_TRIAGE_VM_SANITIZE_SKIP) {
		ktriage_record(thread_tid(current_thread()),
		    KDBG_TRIAGE_EVENTID(
			    KDBG_TRIAGE_SUBSYS_VM_SANITIZE,
			    KDBG_TRIAGE_RESERVED,
			    ktriage_code),
		    past_ret /* arg */);
	}
}

#pragma mark Entry point implementation

void
vm_sanitize_send_telemetry(
	vm_sanitize_method_t method,
	vm_sanitize_checker_t checker,
	vm_sanitize_checker_count_t checker_count,
	enum vm_sanitize_subsys_error_codes ktriage_code,
	uint64_t arg1,
	uint64_t arg2,
	uint64_t arg3,
	uint64_t arg4,
	uint64_t future_ret,
	uint64_t past_ret)
{
	if (0 == disable_vm_sanitize_telemetry) {
		vm_sanitize_send_telemetry_core_analytics(
			method, checker, checker_count,
			arg1, arg2, arg3, arg4,
			future_ret, past_ret);
	}

	DTRACE_VM7(vm_sanitize,
	    uint64_t, CA_VM_PACK(method, checker, checker_count),
	    uint64_t, arg1,
	    uint64_t, arg2,
	    uint64_t, arg3,
	    uint64_t, arg4,
	    uint64_t, future_ret,
	    uint64_t, past_ret);

	vm_sanitize_ktriage_record(ktriage_code, past_ret);

	return;
}
