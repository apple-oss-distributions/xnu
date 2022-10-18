#include <darwintest.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>

#include <mach/mach_error.h>
#include <mach/mach_init.h>
#include <mach/mach_vm.h>

#define ANON_MAX_PAGES 0xFFFFFFFFULL
#define ANON_MAX_SIZE (ANON_MAX_PAGES * vm_kernel_page_size)

T_DECL(anon_max_size, "Test an ALLOC_MAX_SIZE allocation",
    T_META_NAMESPACE("xnu.vm"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("VM"),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1))
{
	kern_return_t kr;
	mach_vm_address_t vm_addr;
	mach_vm_size_t vm_size;
	unsigned char *cp;
	int ret;
	unsigned char vec;

	/* allocate the largest anonymous size possible */
	vm_size = ANON_MAX_SIZE;
	/* truncate to avoid going over actual max size when rounding up */
	vm_size &= ~PAGE_MASK;
	vm_addr = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &vm_addr,
	    vm_size,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	if (kr == KERN_NO_SPACE) {
		T_SKIP("not enough address space...");
	}
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(0x%llx)", ANON_MAX_SIZE);

	/* dirty the first and last pages */
	cp = (unsigned char *)(uintptr_t)vm_addr;
	cp[0] = 'a';
	cp[vm_size - 1] = 'z';

	/* trigger the VM compressor for that VM object */
	ret = madvise(cp, (size_t)vm_size, MADV_PAGEOUT);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "madvise(MADV_PAGEOUT)");

	/* wait for the pages to be (asynchronously) compressed */
	T_QUIET; T_LOG("waiting for first page to be paged out...");
	do {
		ret = mincore(&cp[0], 1, (char *)&vec);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore(1st)");
	} while (vec & MINCORE_INCORE);
	T_QUIET; T_LOG("waiting for last page to be paged out...");
	do {
		ret = mincore(&cp[vm_size - 1], 1, (char *)&vec);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore(last)");
	} while (vec & MINCORE_INCORE);

	/* trigger pageins and check the contents */
	T_QUIET; T_ASSERT_EQ(cp[0], 'a', "first page intact");
	T_QUIET; T_ASSERT_EQ(cp[vm_size - 1], 'z', "last page intact");

	/* success */
	return;
}
