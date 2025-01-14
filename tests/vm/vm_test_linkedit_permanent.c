#include <darwintest.h>

#include <stdlib.h>

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

static char *_prot_str[] = {
	/* 0 */ "---",
	/* 1 */ "r--",
	/* 2 */ "-w-",
	/* 3 */ "rw-",
	/* 4 */ "--x",
	/* 5 */ "r-x",
	/* 6 */ "-wx",
	/* 7 */ "rwx"
};
static char *
prot_str(vm_prot_t prot)
{
	return _prot_str[prot & VM_PROT_ALL];
}

static void
print_region_info(
	mach_vm_address_t vmaddr,
	mach_vm_size_t vmsize,
	vm_region_submap_short_info_64_t ri,
	mach_vm_address_t vmaddr2,
	mach_vm_size_t vmsize2,
	vm_region_submap_short_info_64_t ri2)
{
	T_LOG("   [ 0x%016llx - 0x%016llx ] size 0x%016llx prot 0x%x/0x%x %s/%s submap %d\n",
	    (uint64_t)vmaddr, (uint64_t)(vmaddr + vmsize), (uint64_t)vmsize,
	    ri->protection, ri->max_protection,
	    prot_str(ri->protection),
	    prot_str(ri->max_protection),
	    ri->is_submap);
	if (ri2) {
		T_LOG("-> [ 0x%016llx - 0x%016llx ] size 0x%016llx prot 0x%x/0x%x %s/%s submap %d\n",
		    (uint64_t)vmaddr2, (uint64_t)(vmaddr2 + vmsize2),
		    (uint64_t)vmsize2,
		    ri2->protection, ri2->max_protection,
		    prot_str(ri2->protection), prot_str(ri2->max_protection),
		    ri2->is_submap);
	}
}

static bool
find_first_read_only_mapping(
	mach_vm_address_t *vmaddr_p,
	mach_vm_size_t *vmsize_p,
	vm_region_submap_short_info_64_t ri)
{
	kern_return_t kr;
	mach_vm_address_t vmaddr;
	mach_vm_size_t vmsize;
	natural_t depth;
	mach_msg_type_number_t count;

	T_LOG("===== Looking for first read-only mapping");
	/* find the first read-only mapping */
	for (vmaddr = 0;; vmaddr += vmsize) {
		depth = 0;
		count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &vmaddr,
		    &vmsize,
		    &depth,
		    (vm_region_recurse_info_t)ri,
		    &count);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr);
		if (kr != KERN_SUCCESS) {
			/* end of address space */
			T_FAIL("could not find first read-only mapping");
			return false;
		}
		if (ri->is_submap) {
			/* submap: keep looking */
			continue;
		}
		if (ri->max_protection != VM_PROT_READ) {
			/* not read-only: keep looking */
			continue;
		}
		T_PASS("Found first read-only mapping at 0x%llx size 0x%llx\n", (uint64_t)vmaddr, (uint64_t)vmsize);
		*vmaddr_p = vmaddr;
		*vmsize_p = vmsize;
		return true;
	}
	return false;
}

T_DECL(vm_test_linkedit_permanent, "Tests that LINKEDIT mapping can't be overwritten", T_META_TAG_VM_PREFERRED)
{
	kern_return_t kr;
	mach_vm_address_t vmaddr, vmaddr_linkedit, vmaddr_tmp, vmaddr_buf;
	mach_vm_size_t vmsize, vmsize_linkedit, vmsize_tmp;
	natural_t depth1, depth2;
	mach_msg_type_number_t count;
	vm_region_submap_short_info_data_64_t ri1, ri2;
	vm_prot_t cur_prot, max_prot;

#if __x86_64__
	T_SKIP("x86_64: LINKEDIT mappings are not protected");
	return;
#endif /* __x86_64 */

#define ASSERT_UNCHANGED(clip_ok, object_change_ok)                     \
	do {                                                            \
	        if (clip_ok) {                                          \
	                T_EXPECT_GE(vmaddr_tmp, vmaddr,                 \
	                    "vmaddr clipped 0x%llx -> 0x%llx",          \
	                    (uint64_t)vmaddr, (uint64_t)vmaddr_tmp);    \
	                T_EXPECT_LE(vmsize_tmp, vmsize,                 \
	                    "vmsize clipped 0x%llx -> 0x%llx",          \
	                    (uint64_t)vmsize, (uint64_t)vmsize_tmp);    \
	        } else {                                                \
	                T_EXPECT_EQ(vmaddr_tmp, vmaddr,                 \
	                    "vmaddr unchanged 0x%llx -> 0x%llx",        \
	                    (uint64_t)vmaddr, (uint64_t)vmaddr_tmp);    \
	                T_EXPECT_EQ(vmsize_tmp, vmsize,                 \
	                            "vmsize unchanged 0x%llx -> 0x%llx", \
	                            (uint64_t)vmsize, (uint64_t)vmsize_tmp); \
	        }                                                       \
	        T_EXPECT_LE(ri2.protection, VM_PROT_READ,               \
	                    "should not become writable");              \
	        T_EXPECT_LE(ri2.max_protection, VM_PROT_READ,           \
	                    "should not become able to become writable"); \
	        if (!object_change_ok) {                                \
	                T_EXPECT_EQ(ri2.object_id, ri1.object_id,       \
	                            "object id should not change");     \
	        }                                                       \
	} while (0)

	T_LOG("==========================================");
	if (!find_first_read_only_mapping(&vmaddr_linkedit, &vmsize_linkedit, &ri2)) {
		T_FAIL("could not find appropriate mapping");
		return;
	}
	T_LOG("==========================================");
	/* get top-level mapping protections */
	vmaddr = vmaddr_linkedit;
	depth1 = 0;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr,
	    &vmsize,
	    &depth1,
	    (vm_region_recurse_info_t)&ri1,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_linkedit);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_linkedit, vmsize_linkedit, &ri2);



	/* vm_write() on LINKEDIT mapping */
	T_LOG("==========================================");
	T_LOG("===== vm_write() on LINKEDIT mapping");
	T_LOG("==========================================");
	T_EXPECT_EQ(ri1.is_submap, 0, "mapping should be nested");
	/* get a temporary buffer */
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr_buf,
	    vmsize_linkedit,
	    VM_FLAGS_ANYWHERE);
	T_EXPECT_MACH_SUCCESS(kr, "vm_allocate(0x%llx)", vmsize_linkedit);
	/* copy the data to avoid undue crash */
	memcpy((char *)(uintptr_t)vmaddr_buf,
	    (char *)(uintptr_t)vmaddr_linkedit,
	    (size_t)vmsize_linkedit);
	kr = mach_vm_write(mach_task_self(),
	    vmaddr_linkedit,           /* destination address */
	    vmaddr_buf,                /* source buffer */
	    (mach_msg_type_number_t) vmsize_linkedit);
	T_EXPECT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE,
	    "vm_write() on LINKEDIT mapping fails with KERN_PROTECTION_FAILURE");
	/* check protections again */
	depth2 = 0;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	vmaddr_tmp = vmaddr_linkedit;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_linkedit);
	print_region_info(vmaddr_linkedit, vmsize_linkedit, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(false, false);
	T_EXPECT_EQ(ri2.is_submap, 0, "mapping should not be nested");

	/* vm_allocate(VM_FLAGS_OVERWRITE) on top of LINKEDIT */
	T_LOG("==========================================");
	T_LOG("===== vm_allocate(VM_FLAGS_OVERWRITE) on LINKEDIT mapping");
	T_LOG("==========================================");
	T_EXPECT_EQ(ri1.is_submap, 0, "mapping should not be nested");
	vmaddr_tmp = vmaddr_linkedit;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr_tmp,
	    vmsize_linkedit,
	    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
	T_EXPECT_MACH_ERROR(kr, KERN_NO_SPACE, "vm_allocate(OVERWRITE) fails with KERN_NO_SPACE");
	T_EXPECT_EQ(vmaddr_linkedit, vmaddr_tmp, "vmaddr is unchanged");
	/* check protections again */
	depth2 = 0;
	vmaddr_tmp = vmaddr_linkedit;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_linkedit);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(false, false);
	T_EXPECT_EQ(ri2.is_submap, 0, "mapping should not be nested");

	/* vm_remap(VM_FLAGS_OVERWRITE) on top of submap */
	T_LOG("==========================================");
	T_LOG("===== vm_remap(VM_FLAGS_OVERWRITE) on LINKEDIT mapping");
	T_LOG("==========================================");
	T_EXPECT_EQ(ri1.is_submap, 0, "mapping should not be nested");
	vmaddr_tmp = vmaddr_linkedit;
	kr = mach_vm_remap(mach_task_self(),
	    &vmaddr_tmp,
	    vmsize_linkedit,
	    0,
	    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
	    mach_task_self(),
	    vmaddr_buf,
	    TRUE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	T_EXPECT_MACH_ERROR(kr, KERN_NO_SPACE, "vm_remap(OVERWRITE) fails with KERN_NO_SPACE");
	T_EXPECT_EQ(vmaddr_linkedit, vmaddr_tmp, "vmaddr is unchanged");
	/* check protections again */
	depth2 = 0;
	vmaddr_tmp = vmaddr_linkedit;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_linkedit);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(false, false);
	T_EXPECT_EQ(ri2.is_submap, 0, "mapping should not be nested");

	/* vm_protect(VM_PROT_COPY) on LINKEDIT mapping */
	T_LOG("==========================================");
	T_LOG("===== vm_protect(VM_PROT_COPY) on LINKEDIT mapping");
	T_LOG("==========================================");
	ri1 = ri2;
	T_EXPECT_EQ(ri1.is_submap, 0, "mapping should not be nested");
	kr = mach_vm_protect(mach_task_self(),
	    vmaddr_linkedit,
	    vmsize_linkedit,
	    FALSE,                  /* set_maximum */
	    VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);
	T_EXPECT_MACH_ERROR(kr, KERN_NO_SPACE,
	    "vm_protect(VM_PROT_COPY) fails with KERN_NO_SPACE");
	/* check protections again */
	depth2 = 0;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	vmaddr_tmp = vmaddr_linkedit;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_linkedit);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(false, true);
	T_EXPECT_EQ(ri2.is_submap, 0, "mapping should not be nested");

//	T_LOG("pausing..."); getchar();
}
