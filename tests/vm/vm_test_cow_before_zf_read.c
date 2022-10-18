#include <darwintest.h>

#include <stdlib.h>

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

void
test_cow_before_zf_read(
	boolean_t write_first,
	boolean_t share_it)
{
	kern_return_t kr;
	mach_vm_size_t vm_size = 1024 * 1024;

	uint64_t first_layer_addr = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &first_layer_addr,
	    vm_size,
	    VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_allocate()");

	uint64_t cow_addr = 0;
	if (share_it) {
		// sharing this allocation will make it COPY_DELAY
		// rather than COPY_SYMMETRIC.
		memory_object_size_t me_size = vm_size;
		mach_port_t first_layer_entry_port = 0;
		kr = mach_make_memory_entry_64(mach_task_self(),
		    &me_size,
		    first_layer_addr,
		    MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE,
		    &first_layer_entry_port,
		    MACH_PORT_NULL);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(VM_SHARE)");

		// remap the COW way
		vm_prot_t cur_prot, max_prot;
		kr = mach_vm_remap(mach_task_self(),
		    &cow_addr,
		    vm_size,
		    0,                               /* mask */
		    VM_FLAGS_ANYWHERE,
		    mach_task_self(),
		    first_layer_addr,
		    TRUE,                               /* copy */
		    &cur_prot,
		    &max_prot,
		    VM_INHERIT_DEFAULT);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_remap(copy=TRUE)");
	} else {
		// touch 2nd page to force object creation, as COPY_SYMMETRIC
		*(int*)(first_layer_addr + 0x4000) = 0xabcd;
		// create a COW mapping
		vm_offset_t cow_offset = 0;
		mach_msg_type_number_t cow_size;
		kr = mach_vm_read(mach_task_self(),
		    first_layer_addr,
		    vm_size,
		    &cow_offset,
		    &cow_size);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_read()");
		cow_addr = (uint64_t)(uintptr_t)cow_offset;
	}

	if (write_first) {
		// writing first would avoid the bug ...
		*(int*)first_layer_addr = 0;
	}

	// trigger a zero-fill read fault on original mapping
	T_LOG("*(int*)first_layer_addr = 0x%x\n", *(int*)first_layer_addr);
	// then trigger a write fault
	T_LOG("write 0xbaad to *(int*)first_layer_addr");
	*(int*)first_layer_addr = 0xbaad;
	T_LOG("*(int*)cow_addr = 0x%x\n", *(int*)cow_addr);

	if (*(int*)cow_addr != 0) {
		T_FAIL("COW failed for write_first=%d share_it=%d",
		    write_first, share_it);
	} else {
		T_PASS("COW worked for write_first=%d share_it=%d",
		    write_first, share_it);
	}
	return;
}

T_DECL(vm_test_cow_before_zf_read, "Test COW before a zero-fill read fault")
{
	test_cow_before_zf_read(FALSE, FALSE);
	test_cow_before_zf_read(FALSE, TRUE);
	test_cow_before_zf_read(TRUE, FALSE);
	test_cow_before_zf_read(TRUE, TRUE);
}
