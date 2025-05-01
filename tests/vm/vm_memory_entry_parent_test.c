#include <darwintest.h>
#include <darwintest_utils.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdlib.h>
#include <string.h>

#define KB4 ((mach_vm_size_t)4*1024)
#define KB16 ((mach_vm_size_t)16*1024)

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ALL_VALID_ARCHS(true));

#ifdef __x86_64__
// return true if the process is running under Rosetta translation
// https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment#Determine-Whether-Your-App-Is-Running-as-a-Translated-Binary
static bool
isRosetta(void)
{
	int out_value = 0;
	size_t io_size = sizeof(out_value);
	if (sysctlbyname("sysctl.proc_translated", &out_value, &io_size, NULL, 0) == 0) {
		assert(io_size >= sizeof(out_value));
		return out_value;
	}
	return false;
}
#endif /* __x86_64__ */

T_DECL(vm_memory_entry_parent,
    "Test that we properly align child memory_entries after vm_map",
    T_META_RUN_CONCURRENTLY(true))
{
	mach_vm_address_t src_addr, mapped_addr;
	mach_vm_size_t size, parent_offset;
	mach_port_t       named_me_port, child_me_port;
	kern_return_t     kr;

	size = KB16 * 2;

	kr = mach_vm_allocate(mach_task_self(), &src_addr, size, VM_FLAGS_ANYWHERE);
	T_EXPECT_MACH_SUCCESS(kr, "vm_allocate");

	for (size_t i = 0; i < size / KB4; i++) {
		memset((void *)(src_addr + KB4 * i), (i + 1) * 0x11, KB4);
	}

	/*
	 * Create a memory entry offset by KB4 * 2.
	 * On userspaces with a vm_map_page_size of KB16,
	 * this should be rounded back to 0 when used as the offset in the kernel.
	 */
	parent_offset = KB4 * 2;
	mach_vm_size_t parent_entry_size = size;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &parent_entry_size,
	    src_addr + parent_offset,
	    VM_PROT_READ | VM_PROT_WRITE,
	    &named_me_port,
	    MACH_PORT_NULL);
	T_EXPECT_MACH_SUCCESS(kr, "parent mach_make_memory_entry()");

	/*
	 * Create a memory entry offset into its parent by KB4 * 3.
	 * On kernels with a PAGE_SIZE of KB16,
	 * this should be rounded back to 0 when used as the offset in the kernel.
	 */
	mach_vm_offset_t child_offset = KB4 * 3;
	mach_vm_size_t child_entry_size = KB4 * 1;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &child_entry_size,
	    child_offset,
	    VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_USE_DATA_ADDR,
	    &child_me_port,
	    named_me_port
	    );
	T_EXPECT_MACH_SUCCESS(kr, "child mach_make_memory_entry()");

	/*
	 * Map in our child memory entry.
	 */
	kr = mach_vm_map(mach_task_self(),
	    &mapped_addr,
	    child_entry_size,
	    0,
	    VM_FLAGS_ANYWHERE,
	    child_me_port,
	    0,
	    false,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_NONE);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_map()");

	/*
	 * On rosetta, we expect the mapped address to be offset by the offset of the parent.
	 * On arm64, we expect the child offset to be ignored, and the mapped address to be offset by 0 from the src.
	 * On intel, we expect the mapped address to by offset by KB16.
	 */

#if __x86_64__
	if (isRosetta()) {
		T_ASSERT_EQ(0, memcmp((void *)mapped_addr, (void *) (src_addr + parent_offset), child_entry_size), "Mapped values equal src values");
	} else {
		T_ASSERT_EQ(0, memcmp((void *)mapped_addr, (void *) (src_addr + (parent_offset + child_offset)), child_entry_size), "Mapped values equal src values");
	}
#else
	T_ASSERT_EQ(0, memcmp((void *)mapped_addr, (void *) src_addr, child_entry_size), "Mapped values equal src values");
#endif
}

T_DECL(vm_memory_entry_named_reuse_parent,
    "Test that we re-use the parent entry when possible with MAP_MEM_NAMED_REUSE",
    T_META_RUN_CONCURRENTLY(true), T_META_TAG_VM_PREFERRED)
{
	/*
	 * Test setup - get a memory entry, then map it into the address space.
	 */
	mach_port_t parent_handle, entry_handle;

	kern_return_t kr = mach_memory_object_memory_entry_64(mach_host_self(), 1,
	    KB16, VM_PROT_READ | VM_PROT_WRITE, 0, &parent_handle);
	T_ASSERT_MACH_SUCCESS(kr, "make parent_handle return value");

	mach_vm_address_t alloced_addr;
	kr = mach_vm_map(mach_task_self(), &alloced_addr, KB16, 0, VM_FLAGS_ANYWHERE,
	    parent_handle, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "map parent_handle");


	/*
	 * Attempt to use MAP_MEM_NAMED_REUSE to have the process "share" the memory
	 * entry with itself. We expect to see that the handle returned is identical
	 * to the handle provided, unlike with MAP_MEM_VM_SHARE where a new handle
	 * to the same region would be returned.
	 */
	memory_object_size_t entry_size = KB16;
	kr = mach_make_memory_entry_64(mach_task_self(), &entry_size, alloced_addr,
	    MAP_MEM_NAMED_REUSE | VM_PROT_DEFAULT, &entry_handle, parent_handle);
	T_EXPECT_MACH_SUCCESS(kr, "make entry_handle return value");
	T_EXPECT_EQ(parent_handle, entry_handle, "NAMED_REUSE should re-use parent_handle");
}

T_DECL(vm_memory_entry_parent_copy,
    "Test that making a memory entry fails if the parent is a copy entry",
    T_META_RUN_CONCURRENTLY(true), T_META_TAG_VM_PREFERRED)
{
	/*
	 * Test setup - allocate a region and get a copy entry to it.
	 */
	mach_vm_address_t alloced_addr;
	kern_return_t kr = mach_vm_allocate(mach_task_self(), &alloced_addr, KB16, VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_allocate");

	memory_object_size_t parent_size = KB16;
	mach_port_t parent_handle;
	kr = mach_make_memory_entry_64(mach_task_self(), &parent_size, alloced_addr,
	    MAP_MEM_VM_COPY | VM_PROT_DEFAULT, &parent_handle, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "make parent_handle return value");

	/*
	 * Attempt to make a new entry with the copy entry as parent.
	 */
	memory_object_size_t entry_size = KB16;
	mach_port_t invalid_handle = (mach_port_t) 0xdeadbeef;
	mach_port_t entry_handle = invalid_handle;
	kr = mach_make_memory_entry_64(mach_task_self(), &entry_size, alloced_addr,
	    MAP_MEM_VM_COPY | VM_PROT_DEFAULT, &entry_handle, parent_handle);
	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "make entry_handle return value");
	T_EXPECT_EQ(entry_handle, invalid_handle, "make entry_handle handle unchanged on error");
	T_EXPECT_EQ(entry_size, KB16, "make entry_handle size unchanged on error");
}

T_DECL(vm_memory_entry_from_parent_entry_insufficient_permissions,
    "Test that parent permissions are correctly checked in mach_make_memory_entry_from_parent_entry",
    T_META_RUN_CONCURRENTLY(true), T_META_TAG_VM_PREFERRED)
{
	/*
	 * Test setup - create parent entry with read-only permissions.
	 */
	mach_port_t parent_handle;
	kern_return_t kr = mach_memory_object_memory_entry_64(mach_host_self(), 1,
	    KB16, VM_PROT_READ, 0, &parent_handle);
	T_ASSERT_MACH_SUCCESS(kr, "make parent_handle return value");


	/*
	 * Attempt to create a new entry with read-write permissions.
	 */
	memory_object_size_t entry_size = KB16;
	mach_port_t invalid_handle = (mach_port_t) 0xdeadbeef;
	mach_port_t entry_handle = invalid_handle;
	kr = mach_make_memory_entry_64(mach_task_self(), &entry_size, 0,
	    VM_PROT_READ | VM_PROT_WRITE, &entry_handle, parent_handle);
	T_EXPECT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE, "return value without mask_permissions");
	T_EXPECT_EQ(entry_handle, invalid_handle, "handle unchanged on failure");
	T_EXPECT_EQ(entry_size, KB16, "size unchanged on failure");

	/*
	 * Try again with mask_permissions set, and validate that we only get the
	 * read permissions allowed.
	 */
	kr = mach_make_memory_entry_64(mach_task_self(), &entry_size, 0,
	    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_IS_MASK, &entry_handle, parent_handle);
	T_EXPECT_MACH_SUCCESS(kr, "return value with mask_permissions");

	// To validate the permissions, attempt to map it into the address space
	mach_vm_address_t alloced_addr;
	kr = mach_vm_map(mach_task_self(), &alloced_addr, KB16, 0, VM_FLAGS_ANYWHERE,
	    parent_handle, 0, false, VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_RIGHT, "entry shouldn't have write permissions");
	kr = mach_vm_map(mach_task_self(), &alloced_addr, KB16, 0, VM_FLAGS_ANYWHERE,
	    parent_handle, 0, false, VM_PROT_READ, VM_PROT_READ, VM_INHERIT_DEFAULT);
	T_EXPECT_MACH_SUCCESS(kr, "entry should have read permissions");
}
