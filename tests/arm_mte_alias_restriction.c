#if __arm64__
#include <arm_acle.h>
#include <darwintest.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <sys/mman.h>
#include <spawn.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <fcntl.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	XNU_T_META_SOC_SPECIFIC
	);

/*
 * Processes which explicitly declare themselves as being unsafe to receive untagged aliases to tagged memory
 *  are killed by the system when the system conspires to grant them an untagged alias.
 * This test ensure that processes that opt into restrictions on aliasing tagged memory may not receive aliases:
 *  we launch a binary signed with an ID hard-coded into AMFI to opt in to this restriction, then attempt
 *  to remap tagged memory into this target.
 */
T_DECL(process_with_alias_restricted_opt_in_cannot_receive_mte_alias,
    "Ensure a process which opts in to alias restrictions may not receive "
    "an alias to tagged memory, and that an attempt to do so triggers a fatal guard.",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    /* Disabled in BATS due to signing issues */
    T_META_ENABLED(false),
    XNU_T_META_SOC_SPECIFIC) {
	/*
	 * Given a binary signed in such a way that it should never be allowed to
	 * receive aliases to untagged memory from elsewhere on the system.
	 */

	/* And we fork() so that we can observe the eventual SIGKILL */
	expect_sigkill(^{
		/* When we create some tagged memory in our context */
		mach_vm_address_t address = 0;
		mach_vm_size_t size = PAGE_SIZE;
		kern_return_t kr = mach_vm_allocate(mach_task_self(), &address, size, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
		T_ASSERT_MACH_SUCCESS(kr, "allocate MTE memory");

		/* And we spawn the process which is not allowed to receive aliases to tagged memory */
		pid_t target_pid;
		char* target_argv[] = {"arm_mte_alias_restriction_helper", NULL};
		int ret = posix_spawn(&target_pid, target_argv[0], NULL, NULL, target_argv, NULL);
		T_ASSERT_POSIX_ZERO(ret, "posix_spawn(%s)", target_argv[0]);
		T_ASSERT_NE(target_pid, 0, "posix_spawn(%s)", target_argv[0]);

		/* And we fetch a task port for the target */
		task_port_t target_task_port;
		kr = task_for_pid(mach_task_self(), target_pid, &target_task_port);
		T_ASSERT_MACH_SUCCESS(kr, "task_for_pid for target");

		/* When we attempt to remap the tagged memory into the target */
		mach_vm_address_t remap_addr = 0;
		vm_prot_t curprot = VM_PROT_WRITE | VM_PROT_READ;
		vm_prot_t maxprot = VM_PROT_WRITE | VM_PROT_READ;
		kr = mach_vm_remap_new(target_task_port, &remap_addr, size,
		/* mask = */ 0, VM_FLAGS_ANYWHERE, mach_task_self(), address,
		/* copy = */ FALSE, &curprot, &maxprot, VM_INHERIT_DEFAULT);
		T_ASSERT_MACH_SUCCESS(kr, "remap tagged memory");
		if (kr != KERN_SUCCESS) {
		        fprintf(stderr, "failed to remap tagged memory\n");
		        exit(1);
		}

		/* And we wire the memory in the target to trigger the policy check */
		mach_port_t host_priv = HOST_PRIV_NULL;
		kr = host_get_host_priv_port(mach_host_self(), &host_priv); \
		T_ASSERT_MACH_SUCCESS(kr, "host_get_host_priv_port");
		kr = mach_vm_wire(host_priv, target_task_port, remap_addr, size, VM_PROT_READ | VM_PROT_WRITE);
		T_ASSERT_MACH_SUCCESS(kr, "mach_vm_wire in target");

		/* Then the system should have killed the actor that attempted to enter this memory */
		T_FAIL("Expected the system to prevent us from receiving an alias to tagged memory");
	}, "Attempt to map an untagged alias to tagged memory in a restricted receiver");
}

T_DECL(vm_update_pointers_with_remote_tags_without_debugger,
    "Ensure mach_vm_update_pointers_with_remote_tags is unusable when not debugged",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC) {
	/* Given a tagged buffer */
	const mach_vm_size_t alloc_size = PAGE_SIZE;
	const mach_vm_size_t halfway = alloc_size / 2;
	vm_address_t tagged_addr = allocate_and_tag_range(alloc_size, 0xa);
	uint8_t* tagged_ptr = (uint8_t*)((uintptr_t)tagged_addr);
	vm_address_t untagged_addr = tagged_addr & ~MTE_TAG_MASK;
	uint8_t* untagged_ptr = (uint8_t*)((uintptr_t)untagged_addr);

	mach_vm_offset_t addresses_to_tag[1] = {(mach_vm_offset_t)untagged_ptr};

	/* And we grab a task port */
	task_port_t target_task_port;
	kern_return_t kr = task_for_pid(mach_task_self(), getpid(), &target_task_port);
	T_ASSERT_MACH_SUCCESS(kr, "task_for_pid for target");

	/* When we request the pointers be rewritten with their MTE tags */
	mach_vm_offset_t resigned_addresses[1] = {0};
	mach_vm_offset_list_t input_list = addresses_to_tag;
	mach_vm_offset_list_t output_list = resigned_addresses;

	int count = 1;
	kr = mach_vm_update_pointers_with_remote_tags(
		target_task_port,
		input_list,
		count,
		output_list,
		&count
		);

	/* Then it fails, because the input task wasn't debugged */
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "Expected mach_vm_update_pointers_with_remote_tags to fail when map !debugged");
}

T_DECL(vm_update_pointers_with_remote_tags_invalid_inputs,
    "Ensure mach_vm_update_pointers_with_remote_tags fails when the input sizes don't match",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_REQUIRES_SYSCTL_EQ("security.mac.amfi.developer_mode_status", 1),
    /* It's not straightforward to ptrace on platforms other than macOS, so don't bother */
    T_META_ENABLED(TARGET_CPU_ARM64 && TARGET_OS_OSX),
    XNU_T_META_SOC_SPECIFIC) {
	/* Given we fork off into a debugger and debugee (and Developer Mode is enabled) */
	/* And we set up a shared comms channel between parent and child */
	int ret;
	const char* memory_path = "vm_update_pointers";
	shm_unlink(memory_path);
	int shm_fd = shm_open(memory_path, O_RDWR | O_CREAT | O_EXCL);
	T_ASSERT_POSIX_SUCCESS(shm_fd, "Created shared memory");

	const mach_msg_type_number_t count = 1;
	struct shared_data {
		bool has_parent_connected;
		bool has_child_populated_pointers;
		bool has_parent_finished_inspecting_child;
		bool has_child_acked_exit;
		uint8_t* tagged_ptr;
		uint8_t* differently_tagged_ptr;
		mach_vm_offset_t addresses_to_tag[count];
	};

	ret = ftruncate(shm_fd, sizeof(struct shared_data));
	T_ASSERT_POSIX_SUCCESS(ret, "ftruncate");
	struct shared_data* shm = (struct shared_data*)mmap(NULL, sizeof(struct shared_data), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

	const mach_vm_size_t alloc_size = PAGE_SIZE;
	const mach_vm_size_t halfway = alloc_size / 2;

	pid_t pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		/* Allow the parent to attach */
		while (!shm->has_parent_connected) {
			sleep(1);
		}

		/* And a tagged buffer */
		vm_address_t tagged_addr = allocate_and_tag_range(alloc_size, 0xa);
		shm->tagged_ptr = (uint8_t*)((uintptr_t)tagged_addr);
		vm_address_t untagged_addr = tagged_addr & ~MTE_TAG_MASK;
		uint8_t* untagged_ptr = (uint8_t*)((uintptr_t)untagged_addr);

		shm->addresses_to_tag[0] = (mach_vm_offset_t)&untagged_ptr[0];

		/* Let the parent know we're ready to go */
		shm->has_child_populated_pointers = true;

		/* Allow the parent to interrogate our address space */
		while (!shm->has_parent_finished_inspecting_child) {
			sleep(1);
		}
		shm->has_child_acked_exit = true;
		exit(0);
	}

	/* Attach to the child so it's marked as being debugged */
	ret = ptrace(PT_ATTACHEXC, pid, 0, 0);
	T_EXPECT_POSIX_SUCCESS(ret, "ptrace PT_ATTACHEXC");

	/* And let the child know that it can carry on */
	shm->has_parent_connected = true;

	/* And ensure the child has set up the memory */
	while (!(shm->has_child_populated_pointers)) {
		sleep(1);
	}

	/* And we grab a task port */
	task_port_t target_task_port;
	kern_return_t kr = task_for_pid(mach_task_self(), pid, &target_task_port);
	T_ASSERT_MACH_SUCCESS(kr, "task_for_pid for target");

	/* When we request the pointers be rewritten with their MTE tags */
	mach_vm_offset_t resigned_addresses[count] = {0};
	mach_vm_offset_list_t input_list = &shm->addresses_to_tag[0];
	mach_vm_offset_list_t output_list = resigned_addresses;

	/* But our output array has a size mismatched from the input array */
	const mach_msg_type_number_t mismatched_count = 2;

	kr = mach_vm_update_pointers_with_remote_tags(
		target_task_port,
		input_list,
		count,
		output_list,
		&mismatched_count
		);
	/* Then it fails, because the input task wasn't debugged */
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "Expected mach_vm_update_pointers_with_remote_tags to fail input array sizes mismatch");

	/* Cleanup: let the child know that it's fine to exit */
	shm->has_parent_finished_inspecting_child = true;
	while (!(shm->has_child_acked_exit)) {
		sleep(1);
	}

	T_ASSERT_POSIX_SUCCESS(close(shm_fd), "Closed shm fd");
	T_ASSERT_POSIX_SUCCESS(shm_unlink(memory_path), "Unlinked");
}

T_DECL(vm_update_pointers_with_remote_tags,
    "Validate the behavior of the API that allows reading remote tag info",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_REQUIRES_SYSCTL_EQ("security.mac.amfi.developer_mode_status", 1),
    /* It's not straightforward to ptrace on platforms other than macOS, so don't bother */
    T_META_ENABLED(TARGET_CPU_ARM64 && TARGET_OS_OSX),
    XNU_T_META_SOC_SPECIFIC) {
	/* Given we fork off into a debugger and debugee (and Developer Mode is enabled) */
	/* And we set up a shared comms channel between parent and child */
	int ret;
	const char* memory_path = "vm_update_pointers";
	shm_unlink(memory_path);
	int shm_fd = shm_open(memory_path, O_RDWR | O_CREAT | O_EXCL);
	T_ASSERT_POSIX_SUCCESS(shm_fd, "Created shared memory");

	const mach_msg_type_number_t count = 4;
	struct shared_data {
		bool has_parent_connected;
		bool has_child_populated_pointers;
		bool has_parent_finished_inspecting_child;
		bool has_child_acked_exit;
		uint8_t* tagged_ptr;
		uint8_t* differently_tagged_ptr;
		uint8_t* untagged_ptr;
		mach_vm_offset_t addresses_to_tag[count];
	};

	ret = ftruncate(shm_fd, sizeof(struct shared_data));
	T_ASSERT_POSIX_SUCCESS(ret, "ftruncate");
	struct shared_data* shm = (struct shared_data*)mmap(NULL, sizeof(struct shared_data), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

	const mach_vm_size_t alloc_size = PAGE_SIZE;
	const mach_vm_size_t halfway = alloc_size / 2;

	pid_t pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		/* Allow the parent to attach */
		while (!shm->has_parent_connected) {
			sleep(1);
		}

		/* Given an untagged buffer */
		void* untagged_buffer_addr = allocate_untagged_memory(alloc_size);
		shm->untagged_ptr = untagged_buffer_addr;

		/* And a tagged buffer */
		vm_address_t tagged_addr = allocate_and_tag_range(alloc_size, 0xa);
		shm->tagged_ptr = (uint8_t*)((uintptr_t)tagged_addr);
		vm_address_t untagged_addr = tagged_addr & ~MTE_TAG_MASK;
		uint8_t* untagged_ptr = (uint8_t*)((uintptr_t)untagged_addr);

		/* And a different tag is used halfway through the tagged buffer */
		uint64_t different_tag = 0xb;
		shm->differently_tagged_ptr = (uint8_t*)((uintptr_t) untagged_ptr | (different_tag << MTE_TAG_SHIFT));
		for (mach_vm_size_t offset = halfway; offset < alloc_size; offset += MTE_GRANULE_SIZE) {
			__arm_mte_set_tag(&shm->differently_tagged_ptr[offset]);
		}

		/* And a pointer to a bogus address */
		mach_vm_offset_t bogus_pointer = 0xaaaaaaaa;
		/* And one of the pointers points to a region that we try ensure isn't resident */
		T_ASSERT_POSIX_ZERO(madvise(untagged_buffer_addr, alloc_size, MADV_DONTNEED), "madvise(DONTNEED)");

		shm->addresses_to_tag[0] = (mach_vm_offset_t)&untagged_ptr[0];
		shm->addresses_to_tag[1] = (mach_vm_offset_t)&untagged_ptr[halfway];
		shm->addresses_to_tag[2] = (mach_vm_offset_t)untagged_buffer_addr;
		shm->addresses_to_tag[3] = (mach_vm_offset_t)bogus_pointer;

		/* Let the parent know we're ready to go */
		shm->has_child_populated_pointers = true;

		/* Allow the parent to interrogate our address space */
		while (!shm->has_parent_finished_inspecting_child) {
			sleep(1);
		}
		shm->has_child_acked_exit = true;
		exit(0);
	}

	/* Attach to the child so it's marked as being debugged */
	ret = ptrace(PT_ATTACHEXC, pid, 0, 0);
	T_EXPECT_POSIX_SUCCESS(ret, "ptrace PT_ATTACHEXC");

	/* And let the child know that it can carry on */
	shm->has_parent_connected = true;

	/* And ensure the child has set up the memory */
	while (!(shm->has_child_populated_pointers)) {
		sleep(1);
	}

	/* And we grab a task port */
	task_port_t target_task_port;
	kern_return_t kr = task_for_pid(mach_task_self(), pid, &target_task_port);
	T_ASSERT_MACH_SUCCESS(kr, "task_for_pid for target");

	/* When we request the pointers be rewritten with their MTE tags */
	mach_vm_offset_t resigned_addresses[count] = {0};
	mach_vm_offset_list_t input_list = &shm->addresses_to_tag[0];
	mach_vm_offset_list_t output_list = resigned_addresses;

	kr = mach_vm_update_pointers_with_remote_tags(
		target_task_port,
		input_list,
		count,
		output_list,
		&count
		);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_update_pointers_with_remote_tags");

	/* Then the pointers have been rewritten as expected */
	T_ASSERT_EQ_ULONG((unsigned long)output_list[0], (unsigned long)&(shm->tagged_ptr)[0], "Expected pointer 1 to be correctly rewritten");
	T_ASSERT_EQ_ULONG((unsigned long)output_list[1], (unsigned long)&(shm->differently_tagged_ptr)[halfway], "Expected pointer 2 to be correctly rewritten");
	/* A non-MTE-enabled object is returned as-is in the output list */
	T_ASSERT_EQ_ULONG((unsigned long)output_list[2], shm->untagged_ptr, "Expected a non-MTE address to be returned as-is");
	/* An invalid input pointer is returned as zero in the output list */
	T_ASSERT_EQ_ULONG((unsigned long)output_list[3], 0, "Expected an unmapped address to be transformed to 0");

	/* And let the child know that it's fine to exit */
	shm->has_parent_finished_inspecting_child = true;
	while (!(shm->has_child_acked_exit)) {
		sleep(1);
	}

	/* Cleanup */
	T_ASSERT_POSIX_SUCCESS(close(shm_fd), "Closed shm fd");
	T_ASSERT_POSIX_SUCCESS(shm_unlink(memory_path), "Unlinked");
}
#endif /* __arm64__ */
