#include <darwintest.h>

#include <stdlib.h>

#include <mach/mach_host.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

T_DECL(vm_test_102067976, "Test dangling PTE due to mis-aligned memory entry")
{
	kern_return_t kr;
	mach_vm_size_t vm_named_entry_size, vm_map_entry_size;
	mach_vm_offset_t vm_named_entry_offset, vm_map_entry_offset;
	mach_port_t named_entry;
	mach_vm_address_t address;

	vm_named_entry_size = 2 * PAGE_SIZE + 1; /* misaligned! */
	vm_named_entry_offset = 0;
	vm_map_entry_size = 2 * PAGE_SIZE;
	vm_map_entry_offset = PAGE_SIZE;

	named_entry = MACH_PORT_NULL;
	kr = mach_memory_object_memory_entry(mach_host_self(),
	    1, (vm_size_t) vm_named_entry_size,
	    VM_PROT_READ | VM_PROT_WRITE,
	    MEMORY_OBJECT_NULL, &named_entry);
	if (kr == MIG_BAD_ID) {
		T_FAIL("mach_memory_object_memory_entry() returned MIG_BAD_ID");
		return;
	}
#if __arm64__ && !__LP64__
	/*
	 * mach_memory_object_memory_entry() is broken on arm64_32.
	 */
	if (kr == MIG_BAD_ARGUMENTS) {
		T_SKIP("mach_memory_object_memory_entry() returned MIG_BAD_ARGUMENTS (because broken on arm64_32)");
		return;
	}
#endif /* __arm64__ && !__LP64__ */
	T_ASSERT_MACH_SUCCESS(kr, "mach_memory_object_memory_entry()");
	T_QUIET; T_ASSERT_NE(named_entry, MACH_PORT_NULL, "named_entry is not null");

	/* map the memory to our space */
	address = 0;
	kr = mach_vm_map(mach_task_self(),
	    &address,
	    (-1),                        /* not 0 but rounds up to 0 */
	    0,                           /* mask */
	    VM_FLAGS_ANYWHERE,
	    named_entry,
	    vm_map_entry_offset,         /* offset */
	    FALSE,                       /* copy */
	    VM_PROT_DEFAULT,
	    VM_PROT_DEFAULT,
	    VM_INHERIT_DEFAULT);
	if (kr == KERN_INVALID_ARGUMENT) {
		/* no longer vulnerable */
		T_PASS("mach_vm_map(size=-1) no longer succeeds");
		return;
	}
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_map()");

	/* fault in last page + dangling one */
	memset((char *)address, 'x', vm_map_entry_size);

	/* unmap the memory */
	kr = mach_vm_deallocate(mach_task_self(), address, vm_map_entry_size);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate()");

	/* release named entry */
	kr = mach_port_deallocate(mach_task_self(), named_entry);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate()");

	T_PASS("no panic!");
}
