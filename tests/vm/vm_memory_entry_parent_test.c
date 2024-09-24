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
