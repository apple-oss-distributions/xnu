/*
 * Copyright (c) 2024 Apple Computer, Inc. All rights reserved.
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

#include <arm_acle.h>
#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <launch.h>
#include <mach/mach_vm.h>
#include <mach/message.h>
#include <mach-o/dyld.h>
#include <servers/bootstrap.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_RUN_CONCURRENTLY(false),
	T_META_IGNORECRASHES(".*mte_mach_msg.*"),
	T_META_CHECK_LEAKS(false));

#define SERVICE_NAME "com.apple.xnu.test.arm_mte_sharing"
#define VIRTUAL_COPY_SZ ((32 * 1024) + 15)

static const mach_vm_size_t sz_rounded = (VIRTUAL_COPY_SZ + (MTE_GRANULE_SIZE - 1)) & (unsigned)~((signed)(MTE_GRANULE_SIZE - 1));
static const mach_msg_size_t memory_size_options[] = { MTE_GRANULE_SIZE, MTE_GRANULE_SIZE*4, KERNEL_BUFFER_COPY_THRESHOLD, VIRTUAL_COPY_SZ };
#define count_of(x) (sizeof(x) / sizeof(x[0]))

typedef struct {
	mach_msg_header_t header;
	mach_msg_body_t body;
	mach_msg_ool_descriptor_t dsc;
	mach_msg_trailer_t trailer;
} ipc_complex_ool_message;

typedef struct {
	mach_msg_header_t header;
	mach_msg_body_t body;
	mach_msg_port_descriptor_t dsc;
	bool is_share;
	memory_object_size_t size;
	mach_msg_trailer_t trailer;
} ipc_complex_port_message;

static const uint64_t DATA = 0xFEDBCA;
/* Helpers */
static mach_port_t
server_checkin(void)
{
	mach_port_t mp;

	kern_return_t kr = bootstrap_check_in(bootstrap_port, SERVICE_NAME, &mp);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "bootstrap_check_in");
	return mp;
}

static mach_port_t
server_lookup(void)
{
	mach_port_t mp;

	kern_return_t kr = bootstrap_look_up(bootstrap_port, SERVICE_NAME, &mp);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "bootstrap_look_up");
	return mp;
}

static unsigned short
get_shadow_depth(void* ptr)
{
	vm_address_t address = (vm_address_t) ptr;
	unsigned int depth = 1;
	vm_size_t size;
	struct vm_region_submap_info_64 info;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kern_return_t kr = vm_region_recurse_64(mach_task_self(), &address, &size,
	    &depth, (vm_region_info_t) &info, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "get_shadow_depth: vm_region_recurse_64");
	return info.shadow_depth;
}

/* Client/server code for out-of-line memory tests */
static void
send_ool_memory(
	mach_port_t svc_port,
	void *addr,
	bool deallocate,
	mach_msg_copy_options_t copy,
	mach_msg_size_t size)
{
	ipc_complex_ool_message msg;
	bzero(&msg, sizeof(ipc_complex_ool_message));
	mach_msg_header_t hdr = {
		.msgh_remote_port = svc_port,
		.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX),
		.msgh_id = 1,
		.msgh_size = offsetof(ipc_complex_ool_message, trailer),
	};
	mach_msg_ool_descriptor_t dsc = {
		.address = addr,
		.deallocate = deallocate,
		.copy = copy,
		.size = size,
		.type = MACH_MSG_OOL_DESCRIPTOR,
	};
	msg.header = hdr;
	msg.body.msgh_descriptor_count = 1;
	msg.dsc = dsc;

	T_LOG("sending message, size: %u, deallocate: %d, copy option: %s",
	    size,
	    deallocate,
	    (copy == MACH_MSG_VIRTUAL_COPY) ? "virtual copy" : "physical copy");
	kern_return_t kr = mach_msg(&msg.header, MACH_SEND_MSG, msg.header.msgh_size,
	    0, MACH_PORT_NULL, 10000, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_msg send");
}

static uint64_t *
tag_pointer(uint64_t **untagged_ptr)
{
	uint64_t mask;

	/* Tag the memory */
	uint64_t *tagged_ptr = __arm_mte_create_random_tag(*untagged_ptr, mask);
	T_QUIET; T_EXPECT_NE_PTR(*untagged_ptr, tagged_ptr,
	    "Random tag was not taken from excluded tag set");

	for (uint64_t i = 0; i < sz_rounded / MTE_GRANULE_SIZE; ++i) {
		uintptr_t cur_ptr = (uintptr_t)tagged_ptr + i * MTE_GRANULE_SIZE;
		__arm_mte_set_tag((void*) cur_ptr);
	}

	/* Write to the tagged memory */
	for (uint64_t i = 0; i < sz_rounded / sizeof(*tagged_ptr); ++i) {
		tagged_ptr[i] = DATA;
	}
	return tagged_ptr;
}

static void
send_ool_memory_helper(
	void *addr,
	boolean_t deallocate,
	mach_msg_copy_options_t copy_option,
	mach_msg_size_t size,
	boolean_t is_memory_tagged,
	boolean_t expect_pass)
{
	if (expect_pass) {
		mach_port_t port = server_lookup();
		send_ool_memory(port, addr, deallocate, copy_option, size);
	} else {
		char description[100];
		snprintf(description, sizeof(description),
		    "(copy_options = %d) (is memory tagged = %d) (size = %d) mach_msg(deallocate=%d)",
		    copy_option, is_memory_tagged, size, deallocate);
		expect_sigkill(^{
			/* expect_sigkill forks, and the child does not gain the parent's port rights */
			mach_port_t port = server_lookup();
			send_ool_memory(port, addr, deallocate, copy_option, size);
		}, description);
	}
}

static void
reset_tagged_pointer(uint64_t *ptr)
{
	uint64_t mask;
	/* We want to allocate the max amount of memory we'll need for the test */
	uint64_t *untagged_ptr;
	untagged_ptr = allocate_tagged_memory(sz_rounded, &mask);
	ptr = tag_pointer(&untagged_ptr);

	/* Write to the memory */
	for (uint64_t i = 0; i < sz_rounded / sizeof(*ptr); ++i) {
		ptr[i] = DATA;
	}
}

static void
ool_memory_assertions(uint64_t *ptr)
{
	/*
	 * The last parameter of send_memory_entry_helper
	 * denotes whether the case is expected to complete normally or not.
	 */
	send_ool_memory_helper(ptr, FALSE, MACH_MSG_VIRTUAL_COPY, MTE_GRANULE_SIZE, true, true);
	send_ool_memory_helper(ptr, FALSE, MACH_MSG_VIRTUAL_COPY, MTE_GRANULE_SIZE * 4, true, true);
	send_ool_memory_helper(ptr, FALSE, MACH_MSG_VIRTUAL_COPY, KERNEL_BUFFER_COPY_THRESHOLD, true, true);

	/*
	 * Sending >32k bytes of tagged memory as a virtual copy (deallocate == false)
	 * should always succeed under contemporary VM policy.
	 */
	send_ool_memory_helper(ptr, FALSE, MACH_MSG_VIRTUAL_COPY, VIRTUAL_COPY_SZ, true, true);

	send_ool_memory_helper(ptr, FALSE, MACH_MSG_PHYSICAL_COPY, MTE_GRANULE_SIZE, true, true);
	send_ool_memory_helper(ptr, FALSE, MACH_MSG_PHYSICAL_COPY, MTE_GRANULE_SIZE * 4, true, true);
	send_ool_memory_helper(ptr, FALSE, MACH_MSG_PHYSICAL_COPY, KERNEL_BUFFER_COPY_THRESHOLD, true, true);
	send_ool_memory_helper(ptr, FALSE, MACH_MSG_PHYSICAL_COPY, VIRTUAL_COPY_SZ, true, true);

	/*
	 * mach_msg(deallocate=true) on a tagged pointer is an illegal operation, as
	 * this is functionally equivalent to vm_deallocate() on that same tagged
	 * pointer.
	 */
	send_ool_memory_helper(ptr, TRUE, MACH_MSG_VIRTUAL_COPY, MTE_GRANULE_SIZE, true, false);
	send_ool_memory_helper(ptr, TRUE, MACH_MSG_VIRTUAL_COPY, MTE_GRANULE_SIZE * 4, true, false);
	send_ool_memory_helper(ptr, TRUE, MACH_MSG_VIRTUAL_COPY, KERNEL_BUFFER_COPY_THRESHOLD, true, false);
	/* rdar://152970401: We take the kernel buffer path even above the virtual copy threshold for local MTE movement */
	send_ool_memory_helper(ptr, TRUE, MACH_MSG_VIRTUAL_COPY, VIRTUAL_COPY_SZ, true, false);
	reset_tagged_pointer(ptr);

	send_ool_memory_helper(ptr, TRUE, MACH_MSG_PHYSICAL_COPY, MTE_GRANULE_SIZE, true, false);
	send_ool_memory_helper(ptr, TRUE, MACH_MSG_PHYSICAL_COPY, MTE_GRANULE_SIZE * 4, true, false);
	send_ool_memory_helper(ptr, TRUE, MACH_MSG_PHYSICAL_COPY, KERNEL_BUFFER_COPY_THRESHOLD, true, false);
	/* rdar://152970401: We take the kernel buffer path even above the virtual copy threshold for local MTE movement */
	send_ool_memory_helper(ptr, TRUE, MACH_MSG_PHYSICAL_COPY, VIRTUAL_COPY_SZ, true, false);
	reset_tagged_pointer(ptr);
}

static uint64_t *
untagged_ool_memory_assertions(uint64_t *untagged_ptr)
{
	const mach_msg_copy_options_t copy_options[] = { MACH_MSG_VIRTUAL_COPY, MACH_MSG_PHYSICAL_COPY};
	const int copy_options_size = *(&copy_options + 1) - copy_options;

	for (int mem_size_index = 0; mem_size_index < count_of(memory_size_options); mem_size_index++) {
		for (int copy_index = 0; copy_index < copy_options_size; copy_index++) {
			mach_msg_size_t mem_size = memory_size_options[mem_size_index];
			mach_msg_copy_options_t copy_option = copy_options[copy_index];
			/*
			 * The last parameter of send_memory_entry_helper
			 * denotes whether the case is expected to complete normally or not.
			 * We expect the process to complete normally for all combinations
			 * of untagged memory
			 */
			send_ool_memory_helper(untagged_ptr, FALSE, copy_option, mem_size, false, true);
			send_ool_memory_helper(untagged_ptr, TRUE, copy_option, mem_size, false, true);
			/* Reallocate the untagged memory for the next invocation, since we used DEALLOCATE=TRUE above */
			untagged_ptr = allocate_untagged_memory(sz_rounded);
			for (uint64_t i = 0; i < sz_rounded / sizeof(uint64_t); ++i) {
				untagged_ptr[i] = DATA;
			}
		}
	}
	return untagged_ptr;
}

static void
ool_memory_client_template(bool is_tagged)
{
	assert_normal_exit(^{
		T_SETUPBEGIN;
		validate_proc_pidinfo_mte_status(getpid(), true);
		if (T_STATE == T_STATE_SETUPFAIL) {
		        T_FAIL("client was not spawned under MTE");
		        return;
		}

		uint64_t mask;
		/* We want to allocate the max amount of memory we'll need for the test */
		uint64_t *untagged_ptr;
		if (is_tagged) {
		        untagged_ptr = allocate_tagged_memory(sz_rounded, &mask);
		} else {
		        untagged_ptr = allocate_untagged_memory(sz_rounded);
		}

		/* Tag the memory */
		uint64_t *tagged_ptr = NULL;
		if (is_tagged) {
		        tagged_ptr = tag_pointer(&untagged_ptr);
		}

		/* Write to the memory */
		for (uint64_t i = 0; i < sz_rounded / sizeof(uint64_t); ++i) {
		        if (is_tagged) {
		                tagged_ptr[i] = DATA;
			} else {
		                untagged_ptr[i] = DATA;
			}
		}
		T_SETUPEND;

		if (!is_tagged) {
		        /* mach_msg_send should ALWAYS succeed on all untagged memory entry sizes */
		        untagged_ptr = untagged_ool_memory_assertions(untagged_ptr);
		} else {
		        ool_memory_assertions(tagged_ptr);
		}

		T_EXPECT_MACH_SUCCESS(vm_deallocate(mach_task_self(), (vm_address_t)untagged_ptr, sz_rounded), "vm_deallocate");
	}, "ool_memory_client_template");
}

T_HELPER_DECL(ool_memory_client_tagged, "ool_memory_client_tagged")
{
	ool_memory_client_template(true);
}

T_HELPER_DECL(ool_memory_client_untagged, "ool_memory_client_untagged") {
	ool_memory_client_template(false);
}

static void
receive_ool_memory(mach_port_t rcv_port, bool is_relaxed)
{
	ipc_complex_ool_message msg;

	kern_return_t kr = mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg),
	    rcv_port, 0, 0);
	T_ASSERT_MACH_SUCCESS(kr, "received msg");

	switch (msg.dsc.copy) {
	case MACH_MSG_VIRTUAL_COPY:
	{
		/* No validations to perform right now */
	}
	case MACH_MSG_PHYSICAL_COPY:
	{
		/* Verify that the received data is correct */
		uint64_t *received_data = (uint64_t*) msg.dsc.address;
		for (uint i = 0; i < msg.dsc.size / sizeof(uint64_t); ++i) {
			T_QUIET; T_ASSERT_EQ_ULLONG(DATA, received_data[i],
			    "received_data[%u] == expected data", i);
		}
		T_LOG("Successfully read and verified received %u bytes of data", msg.dsc.size);
		break;
	}
	default:
	{
		/* We're not expecting the other cases for this test for now */
		T_FAIL("Unexpected copy option: %d", msg.dsc.copy);
	}
	}
}

static void
ool_memory_server(bool is_relaxed, bool has_mte)
{
	validate_proc_pidinfo_mte_status(getpid(), has_mte);
	/* Get the server's receive right */
	mach_port_t svc_port = server_checkin();

	while (true) {
		receive_ool_memory(svc_port, is_relaxed);
	}
}

T_HELPER_DECL(ool_memory_server_with_mte, "ool_memory_server_with_mte")
{
	ool_memory_server(false, true);
}

T_HELPER_DECL(ool_memory_server_with_mte_relaxed, "ool_memory_server_with_mte_relaxed")
{
	ool_memory_server(true, true);
}

T_HELPER_DECL(ool_memory_server_without_mte_relaxed, "ool_memory_server_without_mte_relaxed")
{
	ool_memory_server(true, false);
}

/* Client/server code for memory descriptor tests */
static void
send_memory_entry(
	mach_port_t svc_port,
	void *ptr,
	vm_prot_t flags,
	mach_msg_size_t size)
{
	mach_port_t memory_entry;
	memory_object_size_t memory_entry_size = size;
	bool is_share = !(flags & MAP_MEM_VM_COPY); /* flags = 0 is also a true-share case */
	vm_offset_t mask = is_share ? ~MTE_TAG_MASK : ~0ULL; /* copy cases need tags to do copyin */
	vm_offset_t addr = (vm_offset_t) ptr & mask;
	kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &memory_entry_size,
	    addr, flags | VM_PROT_DEFAULT, &memory_entry, MACH_PORT_NULL);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "make memory entry, size=%llu, flags=%#x",
	    memory_entry_size, flags);
	if (kr != KERN_SUCCESS) {
		return;
	}

	ipc_complex_port_message msg;
	bzero(&msg, sizeof(ipc_complex_port_message));
	mach_msg_header_t hdr = {
		.msgh_remote_port = svc_port,
		.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX),
		.msgh_id = 1,
		.msgh_size = offsetof(ipc_complex_port_message, trailer),
	};
	mach_msg_port_descriptor_t dsc = {
		.name = memory_entry,
		.disposition = MACH_MSG_TYPE_COPY_SEND,
		.type = MACH_MSG_PORT_DESCRIPTOR
	};
	msg.header = hdr;
	msg.body.msgh_descriptor_count = 1;
	msg.dsc = dsc;
	msg.is_share = is_share;
	msg.size = size;

	T_LOG("sending message, size: %u, flags: %#x", size, flags);
	kr = mach_msg(&msg.header, MACH_SEND_MSG, msg.header.msgh_size, 0,
	    MACH_PORT_NULL, 10000, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_msg send");
}

static void
send_memory_entry_helper(
	void *addr,
	vm_prot_t flag,
	mach_msg_size_t size,
	boolean_t is_memory_tagged,
	boolean_t expect_pass)
{
	if (expect_pass) {
		mach_port_t port = server_lookup();
		send_memory_entry(port, addr, flag, size);
	} else {
		char description[100];
		snprintf(description, sizeof(description),
		    "(flags = %d) (is memory tagged = %d) (size = %d)", flag, is_memory_tagged, size);
		expect_sigkill(^{
			/* expect_sigkill forks, and the child does not gain the parent's port rights */
			mach_port_t port = server_lookup();
			send_memory_entry(port, addr, flag, size);
		}, description);
	}
}

static void
default_tagged_memory_entry_assertions(uint64_t *tagged_ptr)
{
	/*
	 * Creating a shared memory entry of tagged memory is a violation of
	 * security policy. The last parameter of send_memory_entry_helper
	 * denotes whether the case is expected to complete normally or not.
	 * Most of these cases expect the process to be killed.
	 */
	send_memory_entry_helper(tagged_ptr, 0, MTE_GRANULE_SIZE, true, false);
	send_memory_entry_helper(tagged_ptr, 0, MTE_GRANULE_SIZE * 4, true, false);
	send_memory_entry_helper(tagged_ptr, 0, KERNEL_BUFFER_COPY_THRESHOLD, true, false);
	send_memory_entry_helper(tagged_ptr, 0, VIRTUAL_COPY_SZ, true, false);

	send_memory_entry_helper(tagged_ptr, MAP_MEM_VM_SHARE, MTE_GRANULE_SIZE, true, false);
	send_memory_entry_helper(tagged_ptr, MAP_MEM_VM_SHARE, MTE_GRANULE_SIZE * 4, true, false);
	send_memory_entry_helper(tagged_ptr, MAP_MEM_VM_SHARE, KERNEL_BUFFER_COPY_THRESHOLD, true, false);
	send_memory_entry_helper(tagged_ptr, MAP_MEM_VM_SHARE, VIRTUAL_COPY_SZ, true, false);

	/* These next three cases are the only ones in which the process is not expected to terminate) */
	send_memory_entry_helper(tagged_ptr, MAP_MEM_VM_COPY, MTE_GRANULE_SIZE, true, true);
	send_memory_entry_helper(tagged_ptr, MAP_MEM_VM_COPY, MTE_GRANULE_SIZE * 4, true, true);
	send_memory_entry_helper(tagged_ptr, MAP_MEM_VM_COPY, KERNEL_BUFFER_COPY_THRESHOLD, true, true);
	/* Copies above 32k are also allowed under VM policies v3 */
	send_memory_entry_helper(tagged_ptr, MAP_MEM_VM_COPY, VIRTUAL_COPY_SZ, true, true);
}

static void
relaxed_memory_entry_assertions(uint64_t *ptr)
{
	const int vm_flags[] = { 0, MAP_MEM_VM_SHARE, MAP_MEM_VM_COPY };
	for (int mem_size_index = 0; mem_size_index < count_of(memory_size_options); mem_size_index++) {
		for (int vm_flags_index = 0; vm_flags_index < count_of(vm_flags); vm_flags_index++) {
			mach_msg_size_t mem_size = memory_size_options[mem_size_index];
			int vm_flag = vm_flags[vm_flags_index];
			send_memory_entry_helper(ptr, vm_flag, mem_size, false, true);
		}
	}
}

/*
 *  memory_entry_client_template(bool is_tagged)
 *       [is_tagged]: is the memory being send tagged
 */
static void
memory_entry_client_template(bool is_tagged)
{
	T_SETUPBEGIN;
	validate_proc_pidinfo_mte_status(getpid(), true);
	if (T_STATE == T_STATE_SETUPFAIL) {
		T_FAIL("client was not spawned under MTE");
		return;
	}

	uint64_t mask;
	/* We want to allocate the max amount of memory we'll need for the test */
	uint64_t *untagged_ptr;
	if (is_tagged) {
		untagged_ptr = allocate_tagged_memory(sz_rounded, &mask);
	} else {
		untagged_ptr = allocate_untagged_memory(sz_rounded);
	}

	/* Tag the memory */
	uint64_t *tagged_ptr = NULL;
	if (is_tagged) {
		tagged_ptr = tag_pointer(&untagged_ptr);
	}

	/* Write to the memory */
	for (uint64_t i = 0; i < sz_rounded / sizeof(uint64_t); ++i) {
		if (is_tagged) {
			tagged_ptr[i] = DATA;
		} else {
			untagged_ptr[i] = DATA;
		}
	}
	T_SETUPEND;

	/*
	 * libdarwintest will automatically end the test when one of the helpers
	 * terminates. The server never terminates in this test setup, so this
	 * only happens if the client terminates, but it also doesn't trigger if
	 * the client is killed rather than ending normally, resulting in a hang.
	 *
	 * Therefore, the helper launches a child process to run the actual test,
	 * so that the helper process can exit normally even on a SIGKILL.
	 */
	assert_normal_exit(^{
		if (!is_tagged) {
		        /* mach_msg_send should ALWAYS succeed on all tagged memory entry sizes */
		        relaxed_memory_entry_assertions(untagged_ptr);
		} else {
		        /*
		         * Creating a shared memory entry of tagged memory is a violation of
		         * security policy.
		         */
		        default_tagged_memory_entry_assertions(tagged_ptr);
		}

		T_EXPECT_MACH_SUCCESS(vm_deallocate(mach_task_self(), (vm_address_t) untagged_ptr, sz_rounded), "vm_deallocate");
	}, "memory_entry_client_template");
}

T_HELPER_DECL(memory_entry_client_tagged, "memory_entry_client")
{
	/* VM security policies should be observed on tagged memory */
	memory_entry_client_template(true);
}

T_HELPER_DECL(memory_entry_client_untagged, "memory_entry_client")
{
	/* VM security policies should be relaxed on untagged memory */
	memory_entry_client_template(false);
}

static void
receive_memory_entry(mach_port_t rcv_port, bool is_relaxed)
{
	ipc_complex_port_message msg;

	kern_return_t kr = mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg), rcv_port, 0, 0);
	T_ASSERT_MACH_SUCCESS(kr, "received msg");
	if (!is_relaxed) {
		T_EXPECT_FALSE(msg.is_share, "it should not be possible to create + send a tagged share memory entry");
	}

	if (!msg.is_share && msg.size <= KERNEL_BUFFER_COPY_THRESHOLD) {
		mach_vm_address_t addr = 0;
		kr = mach_vm_map(mach_task_self(), &addr, msg.size, /* mask = */ 0,
		    VM_FLAGS_ANYWHERE, msg.dsc.name, /* offset = */ 0, /* copy = */ false,
		    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
		T_EXPECT_MACH_SUCCESS(kr, "map copy memory entry, copy = false, size = %llu", addr);
		if (kr == KERN_SUCCESS) {
			kr = mach_vm_deallocate(mach_task_self(), addr, msg.size);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "cleanup mach_vm_map(copy = false)");
		}
		kr = mach_vm_map(mach_task_self(), &addr, msg.size, /* mask = */ 0,
		    VM_FLAGS_ANYWHERE, msg.dsc.name, /* offset = */ 0, /* copy = */ true,
		    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
		T_EXPECT_MACH_SUCCESS(kr, "map copy memory entry, copy = true, size = %llu", addr);
		if (kr == KERN_SUCCESS) {
			kr = mach_vm_deallocate(mach_task_self(), addr, msg.size);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "cleanup mach_vm_map(copy = true)");
		}
	}
}

static void
memory_entry_server(bool is_relaxed, bool has_mte)
{
	validate_proc_pidinfo_mte_status(getpid(), has_mte);
	/* Get the server's receive right */
	mach_port_t svc_port = server_checkin();

	while (true) {
		receive_memory_entry(svc_port, is_relaxed);
	}
}

T_HELPER_DECL(memory_entry_server_with_mte, "memory_entry_server_with_mte")
{
	memory_entry_server(false, true);
}

T_HELPER_DECL(memory_entry_server_with_mte_relaxed, "memory_entry_server_with_mte_relaxed")
{
	memory_entry_server(true, true);
}

T_HELPER_DECL(memory_entry_server_without_mte_relaxed, "memory_entry_server_without_mte_relaxed")
{
	memory_entry_server(true, false);
}

static void
spawn_helper_with_flags(char *helper_name, posix_spawn_secflag_options flags)
{
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *args[] = { path, "-n", helper_name, NULL};
	posix_spawn_with_flags_and_assert_successful_exit(args, flags, true, false);
}

T_HELPER_DECL(memory_entry_client_tagged_with_mte, "memory_entry_client_with_mte")
{
	spawn_helper_with_flags("memory_entry_client_tagged", 0);
}

T_HELPER_DECL(memory_entry_client_untagged_with_mte, "memory_entry_client_with_mte")
{
	spawn_helper_with_flags("memory_entry_client_untagged", 0);
}

T_HELPER_DECL(ool_memory_client_tagged_with_mte, "ool_memory_client_tagged_with_mte")
{
	spawn_helper_with_flags("ool_memory_client_tagged", 0);
}

T_HELPER_DECL(ool_memory_client_untagged_with_mte, "ool_memory_client_untagged_with_mte")
{
	spawn_helper_with_flags("ool_memory_client_untagged", 0);
}

static void
client_server_template(char *launchd_plist, char *server_helper, char *client_helper)
{
	#if __arm64__
	dt_helper_t helpers[] = {
		dt_launchd_helper_domain(launchd_plist,
	    server_helper, NULL, LAUNCH_SYSTEM_DOMAIN),
		dt_fork_helper(client_helper)
	};
	dt_run_helpers(helpers, 2, 600);
	#endif /* __arm64__ */
}

/* Actual test definitions */
T_DECL(mte_mach_msg_send_ool_tagged_entitled,
    "Send tagged memory OOL in a mach msg from MTE-enabled -> MTE-enabled process",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true),
    // T_META_ENABLED(__arm64__)
    T_META_ENABLED(false) /* rdar://153934699 */
    )
{
	client_server_template("com.apple.xnu.test.arm_mte_sharing_hardened.plist",
	    "ool_memory_server_with_mte", "ool_memory_client_tagged_with_mte");
}

T_DECL(mte_mach_msg_send_ool_untagged_entitled,
    "Send untagged memory OOL in a mach msg from MTE-enabled -> MTE-enabled process",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true),
    T_META_ENABLED(__arm64__))
{
	client_server_template("com.apple.xnu.test.arm_mte_sharing_hardened.plist",
	    "ool_memory_server_with_mte_relaxed", "ool_memory_client_untagged_with_mte");
}

T_DECL(mte_mach_msg_send_ool_tagged_entitled_to_unentitled,
    "Send tagged memory OOL in a mach msg from MTE-enabled -> non MTE-enabled process",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true),
    T_META_ENABLED(__arm64__))
{
	client_server_template("com.apple.xnu.test.arm_mte_sharing_unhardened.plist",
	    "ool_memory_server_without_mte_relaxed", "ool_memory_client_tagged_with_mte");
}

T_DECL(mte_mach_msg_send_memory_entry_tagged_entitled,
    "Send tagged memory entries in a mach msg from MTE-enabled -> MTE-enabled process",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true),
    // T_META_ENABLED(__arm64__)
    T_META_ENABLED(false) /* rdar://153934699 */
    )
{
	client_server_template("com.apple.xnu.test.arm_mte_sharing_hardened.plist",
	    "memory_entry_server_with_mte", "memory_entry_client_tagged_with_mte");
}

T_DECL(mte_mach_msg_send_memory_entry_untagged_entitled,
    "Send untagged memory entries in a mach msg from MTE-enabled -> MTE-enabled process",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true),
    T_META_ENABLED(__arm64__))
{
	client_server_template("com.apple.xnu.test.arm_mte_sharing_hardened.plist",
	    "memory_entry_server_with_mte_relaxed", "memory_entry_client_untagged_with_mte");
}

T_DECL(mte_mach_msg_send_memory_entry_tagged_entitled_to_unentitled,
    "Send tagged memory entries in a mach msg from MTE-enabled -> non MTE-enabled process",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true),
    T_META_ENABLED(__arm64__))
{
	client_server_template("com.apple.xnu.test.arm_mte_sharing_unhardened.plist",
	    "memory_entry_server_without_mte_relaxed", "memory_entry_client_tagged_with_mte");
}
