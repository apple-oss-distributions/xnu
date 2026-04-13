/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <mach/mach_vm.h>

#include <vm/pmap.h>
#include <vm/vm_fault.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_map_xnu.h>
#include <vm/vm_pageout_xnu.h>
#include <vm/vm_sanitize_internal.h>

#include <sys/errno.h> /* for the sysctl tests */

#if HAS_MTE
#include <vm/vm_mteinfo_internal.h>


/*
 * This test verifies that the KMA_COMPRESSOR flag translates to tag storage
 * pages getting allocated when `vm_mte_tag_storage_for_compressor` is on.
 */
static int
vm_mte_test_tag_storage_for_compressor(int64_t in, int64_t *out)
{
	kern_return_t   kr = KERN_FAILURE;
	kma_flags_t     flags = KMA_NOFAIL | KMA_COMPRESSOR;
	vm_size_t       page_count = 0;
	vm_page_t       page = NULL;
	vm_page_t       page_list = NULL;
	uint64_t        cpu_free_claimed_count = 0;
	uint32_t        correct_alloc_count = 0;
	bool            expect_tag_storage = (bool)in;
	int             ret = 0;

	*out = 1;
	disable_preemption();
	cpu_free_claimed_count = counter_load(&vm_cpu_free_claimed_count);
	enable_preemption();
	if (cpu_free_claimed_count) {
		page_count = MIN(cpu_free_claimed_count, VMP_FREE_BATCH_SIZE);
		printf("%s: page count: %lu\n", __func__, page_count);
	} else {
		printf("%s: no pages on CPU free claimed queue. Skipping...\n",
		    __func__);
		*out = 1;
		return 0;
	}

	kr = vm_page_alloc_list(page_count, flags, &page_list);
	if (kr != KERN_SUCCESS) {
		printf("%s: vm_page_alloc_list failed, kr=%d\n", __func__, kr);
		*out = 0;
		return ENOMEM;
	}

	/*
	 * We can't guarantee that _all_ pages will be tag storage (if we want that),
	 * so if at least one page is tag storage when we want it to be, we will be
	 * happy.
	 *
	 * If we are not expecting tag storage, _no_ page can be tag storage.
	 */
	_vm_page_list_foreach(page, page_list) {
		if (expect_tag_storage == vm_page_is_tag_storage(page)) {
			correct_alloc_count++;
		}
	}
	if ((expect_tag_storage && !correct_alloc_count) ||
	    (!expect_tag_storage && (correct_alloc_count != page_count))) {
		printf("%s: %lu tag storage pages were allocated.\n",
		    __func__,
		    expect_tag_storage ? correct_alloc_count : (page_count - correct_alloc_count));
		*out = 0;
		ret = ENOMEM;
		goto done;
	}

done:
	vm_page_free_list(page_list, FALSE);
	return ret;
}
SYSCTL_TEST_REGISTER(vm_mte_tag_storage_for_compressor, vm_mte_test_tag_storage_for_compressor);

/*
 * This test verifies that if VM_MEMORY_STACK is specified in the mte_ts_vmtag
 * boot-arg, we get a tag storage page back.
 */
static int
vm_mte_test_tag_storage_for_vm_tag(int64_t in, int64_t *out)
{
	kern_return_t                   kr = KERN_FAILURE;
	mach_vm_offset_ut               addr_u;
	mach_vm_address_t               addr;
	uint64_t                        cpu_free_claimed_count = 0;
	ppnum_t                         pnum = -1;
	vm_map_kernel_flags_t           vmk_flags = VM_MAP_KERNEL_FLAGS_ANYWHERE();
	int                             error = -1;
	int                             ret = 0;
	struct {
		uint32_t vm_tag;
		bool mte;
		bool expect_ts;
	} args;

	*out = 1;
	error = copyin(in, &args, sizeof(args));
	if (error) {
		printf("%s: copyin from userspace failed, error: %d.\n",
		    __func__, error);
		*out = 0;
		return 1;
	}

	vmk_flags.vmf_mte = args.mte;
	vmk_flags.vm_tag = args.vm_tag;
	disable_preemption();
	cpu_free_claimed_count = counter_load(&vm_cpu_free_claimed_count);
	enable_preemption();
	if (!cpu_free_claimed_count) {
		printf("%s: no pages on CPU free claimed queue.\n", __func__);
		*out = 1;
		return 0;
	}
	printf("%s: free claimed count: %llu\n",
	    __func__, cpu_free_claimed_count);

	kr = mach_vm_allocate_kernel(current_map(), &addr_u, vm_sanitize_wrap_size(PAGE_SIZE),
	    vmk_flags);
	if (kr != KERN_SUCCESS) {
		printf("%s: mach_vm_allocate_kernel failed with kr=%d.\n",
		    __func__, kr);
		*out = 0;
		return 1;
	}

	/* Fault in the page */
	addr = vm_sanitize_addr(current_map(), addr_u);
	kr = vm_fault(
		current_map(),
		addr,
		VM_PROT_READ | VM_PROT_WRITE,
		FALSE, /* change_wiring */
		VM_KERN_MEMORY_NONE,
		THREAD_UNINT,
		NULL,
		0);
	if (kr != KERN_SUCCESS) {
		printf("%s: vm_fault failed with kr=%d.\n", __func__, kr);
		*out = 0;
		ret = 1;
		goto done;
	}

	/* Check the physical page */
	pnum = vm_map_get_phys_page(current_map(), (vm_offset_t)addr);
	if (vm_page_is_tag_storage(vm_page_find_canonical(pnum)) ^ args.expect_ts) {
		printf("%s: tag: %d, expected tag storage: %d, mte: %d, pnum: %d\n",
		    __func__, args.vm_tag, args.expect_ts, args.mte, pnum);
		if (args.expect_ts) {
			/* We can't guarantee that we get a tag storage page, so pass anyway. */
			goto done;
		}
		*out = 0;
		ret = 1;
		goto done;
	}

done:
	mach_vm_deallocate_kernel(current_map(), addr, PAGE_SIZE);
	return ret;
}
SYSCTL_TEST_REGISTER(vm_mte_tag_storage_for_vm_tag, vm_mte_test_tag_storage_for_vm_tag);

#endif /* HAS_MTE */
