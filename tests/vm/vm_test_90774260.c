#include <darwintest.h>

#include <stdlib.h>

#include <mach/mach_host.h>
#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

void
test_90774260(void)
{
	kern_return_t kr;
	mach_vm_size_t vm_size = 1024 * 1024;
	int fail = 0;
	int original_value;

	uint64_t first_layer_addr = 0;
	mach_port_t first_layer_entry_port = 0;
	kr = mach_memory_object_memory_entry(mach_host_self(),
	    1, (vm_size_t) vm_size,
	    VM_PROT_READ | VM_PROT_WRITE,
	    0, &first_layer_entry_port);
	if (kr == MIG_BAD_ID) {
		T_FAIL("mach_memory_object_memory_entry() returned MIG_BAD_ID");
		return;
	}
#if __arm64__ && !__LP64__
	/*
	 * mach_memory_object_memory_entry() is broken on arm64_32.
	 * Use mach_make_memory_entry_64(MAP_MEM_NAMED_CREATE) instead.
	 */
	if (kr == MIG_BAD_ARGUMENTS) {
		T_LOG("mach_memory_object_memory_entry() returned MIG_BAD_ARGUMENTS (because broken on arm64_32)");

		memory_object_size_t me_size = vm_size;
		kr = mach_make_memory_entry_64(mach_task_self(),
		    &me_size,
		    0,
		    VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_NAMED_CREATE,
		    &first_layer_entry_port,
		    MACH_PORT_NULL);
		T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(MAP_MEM_NAMED_CREATE)");
	} else
#endif /* __arm64__ && !__LP64__ */
	{
		T_ASSERT_MACH_SUCCESS(kr, "mach_memory_object_memory_entry()");
	}

	// map the memory to our space
	kr = mach_vm_map(mach_task_self(),
	    &first_layer_addr,
	    vm_size,
	    0,                           /* mask */
	    VM_FLAGS_ANYWHERE,
	    first_layer_entry_port,
	    0,                           /* offset */
	    0,                           /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_map(first_layer_addr)");

	original_value = 0xabcd;
	*(int*)first_layer_addr = original_value;

	// create a COW port
	mach_port_t cow_port = MACH_PORT_NULL;
	mach_vm_size_t me_size = vm_size;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &me_size,
	    first_layer_addr,
	    (VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_VM_COPY),
	    &cow_port,
	    0);
	T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64()");
	T_QUIET; T_ASSERT_EQ(me_size, vm_size, "incomplete memory entry");

	// map cow port to a new address in the shared way
	uint64_t shared_addr = 0;
	kr = mach_vm_map(mach_task_self(),
	    &shared_addr,
	    vm_size,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    cow_port,
	    0,              /* offset */
	    0,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_map(shared_addr)");

	// map cow port to a new address in the COW way
	uint64_t cow_addr = 0;
	kr = mach_vm_map(mach_task_self(),
	    &cow_addr,
	    vm_size,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    cow_port,
	    0,              /* offset */
	    1,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_map(cow_addr)");

//	T_LOG("first_layer_addr = 0x%llx", first_layer_addr);
//	T_LOG("shared_addr = 0x%llx\n", shared_addr);
//	T_LOG("cow_addr = 0x%llx\n", cow_addr);

//	T_LOG("*(int*)first_layer_addr = 0x%x", *(int*)first_layer_addr);
//	T_LOG("*(int*)shared_addr = 0x%x\n", *(int*)shared_addr);
//	T_LOG("*(int*)shared_addr2 = 0x%x\n", *(int*)shared_addr2);
//	T_LOG("*(int*)cow_addr = 0x%x\n", *(int*)cow_addr);

	T_LOG("write 0x%x to *(int*)shared_addr", 0x1234);
	*(int*)shared_addr = 0x1234;

	T_LOG("*(int*)first_layer_addr = 0x%x", *(int*)first_layer_addr);
	T_LOG("*(int*)shared_addr = 0x%x\n", *(int*)shared_addr);
	T_LOG("*(int*)cow_addr = 0x%x\n", *(int*)cow_addr);

	if (*(int*)first_layer_addr != original_value) {
		T_FAIL("first_layer_addr should not have changed");
		fail++;
	}
	if (*(int *)shared_addr != 0x1234) {
		T_FAIL("shared_addr should have changed");
		fail++;
	}
	if (*(int*)cow_addr != original_value) {
		T_FAIL("cow_addr should not have changed");
		fail++;
	}
//	T_LOG("pause...");
//	getchar();
}

T_DECL(vm_test_90774260, "Test MAP_MEM_VM_COPY security")
{
	test_90774260();
}
