#include <darwintest.h>

#include <stdlib.h>

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

char *_prot_str[] = {
	/* 0 */ "---",
	/* 1 */ "r--",
	/* 2 */ "-w-",
	/* 3 */ "rw-",
	/* 4 */ "--x",
	/* 5 */ "r-x",
	/* 6 */ "-wx",
	/* 7 */ "rwx"
};
char *
prot_str(vm_prot_t prot)
{
	return _prot_str[prot & VM_PROT_ALL];
}

void
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
find_nested_read_only_mapping(
	mach_vm_address_t *vmaddr_p,
	mach_vm_size_t *vmsize_p,
	vm_region_submap_short_info_64_t ri)
{
	kern_return_t kr;
	mach_vm_address_t vmaddr_sub;
	mach_vm_size_t vmsize_sub;
	natural_t depth;
	mach_msg_type_number_t count;

	T_LOG("===== Looking for read-only mapping in shared region");
	/* find a read-only mapping in the shared region */
	for (vmaddr_sub = 0;; vmaddr_sub += vmsize_sub) {
		depth = 1;
		count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &vmaddr_sub,
		    &vmsize_sub,
		    &depth,
		    (vm_region_recurse_info_t)ri,
		    &count);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_sub);
		if (kr != KERN_SUCCESS) {
			/* end of address space */
			T_FAIL("could not find shared region");
			return false;
		}
		if (depth == 0) {
			/* not the shared region, keep looking */
			continue;
		}
		if (ri->max_protection != VM_PROT_READ) {
			/* not read-only: keep looking */
			continue;
		}
		T_PASS("Found read-only mapping in shared region at 0x%llx size 0x%llx\n", (uint64_t)vmaddr_sub, (uint64_t)vmsize_sub);
		*vmaddr_p = vmaddr_sub;
		*vmsize_p = vmsize_sub;
		return true;
	}
	return false;
}

T_DECL(vm_test_shreg_ro, "Tests that read-only shared-region mappings can't be overwritten")
{
	kern_return_t kr;
	mach_vm_address_t vmaddr, vmaddr_sub, vmaddr_tmp, vmaddr_buf;
	mach_vm_size_t vmsize, vmsize_sub, vmsize_tmp;
	natural_t depth1, depth2;
	mach_msg_type_number_t count;
	vm_region_submap_short_info_data_64_t ri1, ri2;
	vm_prot_t cur_prot, max_prot;

#if __x86_64__
	T_SKIP("x86_64: read-only shared region mappings are not protected");
	return;
#endif /* __x86_64 */

#define ASSERT_UNCHANGED(clip_ok)                                       \
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
	} while (0)

	T_LOG("==========================================");
	if (!find_nested_read_only_mapping(&vmaddr_sub, &vmsize_sub, &ri2)) {
		T_FAIL("could not find appropriate mapping");
		return;
	}
	T_LOG("==========================================");
	/* get top-level mapping protections */
	vmaddr = vmaddr_sub;
	depth1 = 0;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr,
	    &vmsize,
	    &depth1,
	    (vm_region_recurse_info_t)&ri1,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_sub);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_sub, vmsize_sub, &ri2);



	/* vm_allocate(VM_FLAGS_OVERWRITE) on top of submap */
	T_LOG("==========================================");
	T_LOG("===== vm_allocate(VM_FLAGS_OVERWRITE) on nested mapping");
	T_LOG("==========================================");
	T_EXPECT_EQ(ri1.is_submap, 1, "mapping should be nested");
	vmaddr_tmp = vmaddr_sub;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr_tmp,
	    vmsize_sub,
	    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
	T_EXPECT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE, "vm_allocate(OVERWRITE) fails with KERN_PROTECTION_FAILURE");
	T_EXPECT_EQ(vmaddr_sub, vmaddr_tmp, "vmaddr is unchanged");
	/* check protections again */
	depth2 = 0;
	vmaddr_tmp = vmaddr_sub;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_sub);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(false);
	T_EXPECT_EQ(ri2.is_submap, 1, "mapping should still be nested");

	/* vm_remap(VM_FLAGS_OVERWRITE) on top of submap */
	T_LOG("==========================================");
	T_LOG("===== vm_remap(VM_FLAGS_OVERWRITE) on nested mapping");
	T_LOG("==========================================");
	T_EXPECT_EQ(ri1.is_submap, 1, "mapping should be nested");
	vmaddr_tmp = vmaddr_sub;
	kr = mach_vm_remap(mach_task_self(),
	    &vmaddr_tmp,
	    vmsize_sub,
	    0,
	    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
	    mach_task_self(),
	    vmaddr_sub,
	    TRUE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	T_EXPECT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE, "vm_remap(OVERWRITE) fails with KERN_PROTECTION_FAILURE");
	T_EXPECT_EQ(vmaddr_sub, vmaddr_tmp, "vmaddr is unchanged");
	/* check protections again */
	depth2 = 0;
	vmaddr_tmp = vmaddr_sub;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_sub);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(false);
	T_EXPECT_EQ(ri2.is_submap, 1, "mapping should still be nested");

	/* vm_protect(VM_PROT_COPY) on submap mapping */
	T_LOG("==========================================");
	T_LOG("===== vm_protect(VM_PROT_COPY) on nested mapping");
	T_LOG("==========================================");
	ri1 = ri2;
	T_EXPECT_EQ(ri1.is_submap, 1, "mapping should be nested");
	kr = mach_vm_protect(mach_task_self(),
	    vmaddr_sub,
	    vmsize_sub,
	    FALSE,                                   /* set_maximum */
	    VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);
	T_EXPECT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE, "vm_protect(VM_PROT_COPY) fails with KERN_PROTECTION_FAILURE");
	/* check protections again */
	depth2 = 0;
	vmaddr_tmp = vmaddr_sub;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_sub);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(true);
	/* clipping expected (pmap unnesting), so reset expectations */
	vmaddr = vmaddr_tmp;
	vmsize = vmsize_tmp;
	T_EXPECT_EQ(ri2.is_submap, 0, "mapping should now be unnnested");

	/* vm_protect(VM_PROT_COPY) on unnested mapping */
	T_LOG("==========================================");
	T_LOG("===== vm_protect(VM_PROT_COPY) on unnested mapping");
	T_LOG("==========================================");
	ri1 = ri2;
	T_EXPECT_EQ(ri1.is_submap, 0, "mapping should not be nested");
	kr = mach_vm_protect(mach_task_self(),
	    vmaddr_sub,
	    vmsize_sub,
	    FALSE,                  /* set_maximum */
	    VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);
	T_EXPECT_MACH_ERROR(kr, KERN_NO_SPACE,
	    "vm_protect(VM_PROT_COPY) fails with KERN_NO_SPACE");
	/* check protections again */
	depth2 = 0;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	vmaddr_tmp = vmaddr_sub;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_sub);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(false);
	T_EXPECT_EQ(ri2.is_submap, 0, "mapping should still be unnested");

	/* vm_allocate(VM_FLAGS_OVERWRITE) on top of unnested mapping */
	T_LOG("==========================================");
	T_LOG("===== vm_allocate(VM_FLAGS_OVERWRITE) on unnested mapping");
	T_LOG("==========================================");
	ri1 = ri2;
	T_EXPECT_EQ(ri1.is_submap, 0, "mapping should be unnested");
	vmaddr_tmp = vmaddr_sub;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr_tmp,
	    vmsize_sub,
	    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
	T_EXPECT_MACH_ERROR(kr, KERN_NO_SPACE, "vm_allocate(OVERWRITE) fails with KERN_NO_SPACE");
	T_EXPECT_EQ(vmaddr, vmaddr_tmp, "vmaddr is unchanged");
	/* check protections again */
	depth2 = 0;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	vmaddr_tmp = vmaddr_sub;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_sub);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(false);
	T_EXPECT_EQ(ri2.is_submap, 0, "mapping should still be unnested");


	/* find a new nested read-only mapping */
	T_LOG("==========================================");
	T_LOG("");
	T_LOG("==========================================");
	if (!find_nested_read_only_mapping(&vmaddr_sub, &vmsize_sub, &ri2)) {
		T_FAIL("could not find appropriate mapping");
		return;
	}
	T_LOG("==========================================");
	/* get top-level mapping protections */
	vmaddr = vmaddr_sub;
	depth1 = 0;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr,
	    &vmsize,
	    &depth1,
	    (vm_region_recurse_info_t)&ri1,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_sub);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_sub, vmsize_sub, &ri2);


	/* vm_write() on top of submap */
	T_LOG("==========================================");
	T_LOG("===== vm_write() on nested mapping");
	T_LOG("==========================================");
	T_EXPECT_EQ(ri1.is_submap, 1, "mapping should be nested");
	/* get a temporary buffer */
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr_buf,
	    vmsize_sub,
	    VM_FLAGS_ANYWHERE);
	T_EXPECT_MACH_SUCCESS(kr, "vm_allocate(0x%llx)", vmsize_sub);
	/* copy the data to avoid undue crash */
	memcpy((char *)(uintptr_t)vmaddr_buf,
	    (char *)(uintptr_t)vmaddr_sub,
	    (size_t)vmsize_sub);
	kr = mach_vm_write(mach_task_self(),
	    vmaddr_sub,                /* destination address */
	    vmaddr_buf,                /* source buffer */
	    vmsize_sub);
	T_EXPECT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE,
	    "vm_write() on nested mapping fails with KERN_PROTECTION_FAILURE");
	/* check protections again */
	depth2 = 0;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	vmaddr_tmp = vmaddr_sub;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_sub);
	print_region_info(vmaddr_sub, vmsize_sub, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(true);
	T_EXPECT_EQ(ri2.is_submap, 1, "mapping should still be nested");
	/* clipping expected (pmap unnesting), so reset expectations */
	vmaddr = vmaddr_tmp;
	vmsize = vmsize_tmp;

	/* force un-nesting of that mapping */
	T_LOG("==========================================");
	T_LOG("===== unnesting the mapping");
	T_LOG("==========================================");
	ri1 = ri2;
	T_EXPECT_EQ(ri1.is_submap, 1, "mapping should be nested");
	kr = mach_vm_protect(mach_task_self(),
	    vmaddr_sub,
	    vmsize_sub,
	    FALSE,                  /* set_maximum */
	    VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);
	T_EXPECT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE, "vm_protect(0x%llx,0x%llx,VM_PROT_COPY) fails with KERN_PROTECTION_FAILURE", (uint64_t)vmaddr_sub, (uint64_t)vmsize_sub);
	/* check protections again */
	depth2 = 0;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	vmaddr_tmp = vmaddr_sub;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_sub);
	print_region_info(vmaddr, vmsize, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(true);
	/* clipping expected (pmap unnesting), so reset expectations */
	vmaddr = vmaddr_tmp;
	vmsize = vmsize_tmp;
	T_EXPECT_EQ(ri2.is_submap, 0, "mapping should now be unnested");

	/* vm_write() on top of unnested mapping */
	T_LOG("==========================================");
	T_LOG("===== vm_write() on unnested mapping");
	T_LOG("==========================================");
	ri1 = ri2;
	T_EXPECT_EQ(ri1.is_submap, 0, "mapping should be unnested");
	/* we re-use vmaddr_buf from test above... */
	kr = mach_vm_write(mach_task_self(),
	    vmaddr_sub,                /* destination address */
	    vmaddr_buf,                /* source buffer */
	    vmsize_sub);
	T_EXPECT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE,
	    "vm_write() on unnested mapping fails with KERN_PROTECTION_FAILURE");
	/* check protections again */
	depth2 = 0;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	vmaddr_tmp = vmaddr_sub;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &vmaddr_tmp,
	    &vmsize_tmp,
	    &depth2,
	    (vm_region_recurse_info_t)&ri2,
	    &count);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region_recurse(0x%llx)\n", vmaddr_sub);
	print_region_info(vmaddr_sub, vmsize_sub, &ri1, vmaddr_tmp, vmsize_tmp, &ri2);
	ASSERT_UNCHANGED(false);
	T_EXPECT_EQ(ri2.is_submap, 0, "mapping should still be unnested");

//	T_LOG("pausing..."); getchar();
}

T_DECL(shared_region_x86_writable, "Tests shared region PROT_WRITE is permitted on Intel only, and fails on all other architectures",
    T_META_ALL_VALID_ARCHS(true))
{
	mach_vm_address_t vmaddr_sub;
	mach_vm_size_t vmsize_sub;
	vm_region_submap_short_info_data_64_t ri;

	if (!find_nested_read_only_mapping(&vmaddr_sub, &vmsize_sub, &ri)) {
		T_FAIL("could not find appropriate mapping");
		return;
	}

	kern_return_t kr;
	kr = mach_vm_protect(mach_task_self(), vmaddr_sub, vmsize_sub, FALSE, VM_PROT_READ | VM_PROT_WRITE);

#if defined(__x86_64__) || defined(__i386__)
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_protect()");
#else /* defined(__x86_64__) || defined(__i386__) */
	T_ASSERT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE, "mach_vm_protect()");
#endif /* defined(__x86_64__) || defined(__i386__) */
}
