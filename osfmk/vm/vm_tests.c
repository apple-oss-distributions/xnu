/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include <mach_assert.h>

#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/memory_object.h>
#include <mach/vm_map.h>
#include <mach/vm_statistics.h>
#include <mach/vm32_map_server.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/upl.h>

#include <kern/ledger.h>
#include <kern/host.h>

#include <device/device_port.h>
#include <vm/memory_object_internal.h>
#include <vm/vm_fault.h>
#include <vm/vm_fault_internal.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_pageout_internal.h>
#include <vm/vm_protos.h>
#include <vm/vm_memtag.h>
#include <vm/vm_memory_entry_xnu.h>
#include <vm/vm_kern_xnu.h>
#include <vm/vm_iokit.h>
#include <vm/vm_page_internal.h>
#include <vm/vm_shared_region_xnu.h>
#include <vm/vm_test_utils_internal.h>
#include <vm/vm_far.h>
#include <vm/vm_upl.h>

#include <kern/zalloc.h>
#include <kern/zalloc_internal.h>

#include <sys/code_signing.h>
#include <sys/errno.h> /* for the sysctl tests */

#include <tests/xnupost.h> /* for testing-related functions and macros */

#if HAS_MTE
#include <arm_acle.h>
#endif /* HAS_MTE */

extern kern_return_t
vm_map_copy_adjust_to_target(
	vm_map_copy_t           copy_map,
	vm_map_offset_t         offset,
	vm_map_size_t           size,
	vm_map_t                target_map,
	boolean_t               copy,
	vm_map_copy_t           *target_copy_map_p,
	vm_map_offset_t         *overmap_start_p,
	vm_map_offset_t         *overmap_end_p,
	vm_map_offset_t         *trimmed_start_p);

#define VM_TEST_COLLAPSE_COMPRESSOR             0
#define VM_TEST_WIRE_AND_EXTRACT                0
#define VM_TEST_PAGE_WIRE_OVERFLOW_PANIC        0
#if __arm64__
#define VM_TEST_KERNEL_OBJECT_FAULT             0
#endif /* __arm64__ */
#define VM_TEST_DEVICE_PAGER_TRANSPOSE          (DEVELOPMENT || DEBUG)

#if VM_TEST_COLLAPSE_COMPRESSOR
extern boolean_t vm_object_collapse_compressor_allowed;
#include <IOKit/IOLib.h>
static void
vm_test_collapse_compressor(void)
{
	vm_object_size_t        backing_size, top_size;
	vm_object_t             backing_object, top_object;
	vm_map_offset_t         backing_offset, top_offset;
	unsigned char           *backing_address, *top_address;
	kern_return_t           kr;

	printf("VM_TEST_COLLAPSE_COMPRESSOR:\n");

	/* create backing object */
	backing_size = 15 * PAGE_SIZE;
	backing_object = vm_object_allocate(backing_size, kernel_map->serial_id);
	assert(backing_object != VM_OBJECT_NULL);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: created backing object %p\n",
	    backing_object);
	/* map backing object */
	backing_offset = 0;
	kr = vm_map_enter(kernel_map, &backing_offset, backing_size, 0,
	    VM_MAP_KERNEL_FLAGS_DATA_SHARED_ANYWHERE(),
	    backing_object, 0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
	backing_address = (unsigned char *) backing_offset;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "mapped backing object %p at 0x%llx\n",
	    backing_object, (uint64_t) backing_offset);
	/* populate with pages to be compressed in backing object */
	backing_address[0x1 * PAGE_SIZE] = 0xB1;
	backing_address[0x4 * PAGE_SIZE] = 0xB4;
	backing_address[0x7 * PAGE_SIZE] = 0xB7;
	backing_address[0xa * PAGE_SIZE] = 0xBA;
	backing_address[0xd * PAGE_SIZE] = 0xBD;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "populated pages to be compressed in "
	    "backing_object %p\n", backing_object);
	/* compress backing object */
	vm_object_pageout(backing_object);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: compressing backing_object %p\n",
	    backing_object);
	/* wait for all the pages to be gone */
	while (*(volatile int *)&backing_object->resident_page_count != 0) {
		IODelay(10);
	}
	printf("VM_TEST_COLLAPSE_COMPRESSOR: backing_object %p compressed\n",
	    backing_object);
	/* populate with pages to be resident in backing object */
	backing_address[0x0 * PAGE_SIZE] = 0xB0;
	backing_address[0x3 * PAGE_SIZE] = 0xB3;
	backing_address[0x6 * PAGE_SIZE] = 0xB6;
	backing_address[0x9 * PAGE_SIZE] = 0xB9;
	backing_address[0xc * PAGE_SIZE] = 0xBC;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "populated pages to be resident in "
	    "backing_object %p\n", backing_object);
	/* leave the other pages absent */
	/* mess with the paging_offset of the backing_object */
	assert(backing_object->paging_offset == 0);
	backing_object->paging_offset = 3 * PAGE_SIZE;

	/* create top object */
	top_size = 9 * PAGE_SIZE;
	top_object = vm_object_allocate(top_size, backing_object->vmo_provenance);
	assert(top_object != VM_OBJECT_NULL);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: created top object %p\n",
	    top_object);
	/* map top object */
	top_offset = 0;
	kr = vm_map_enter(kernel_map, &top_offset, top_size, 0,
	    VM_MAP_KERNEL_FLAGS_DATA_SHARED_ANYWHERE(),
	    top_object, 0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
	top_address = (unsigned char *) top_offset;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "mapped top object %p at 0x%llx\n",
	    top_object, (uint64_t) top_offset);
	/* populate with pages to be compressed in top object */
	top_address[0x3 * PAGE_SIZE] = 0xA3;
	top_address[0x4 * PAGE_SIZE] = 0xA4;
	top_address[0x5 * PAGE_SIZE] = 0xA5;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "populated pages to be compressed in "
	    "top_object %p\n", top_object);
	/* compress top object */
	vm_object_pageout(top_object);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: compressing top_object %p\n",
	    top_object);
	/* wait for all the pages to be gone */
	while (top_object->resident_page_count != 0) {
		IODelay(10);
	}
	printf("VM_TEST_COLLAPSE_COMPRESSOR: top_object %p compressed\n",
	    top_object);
	/* populate with pages to be resident in top object */
	top_address[0x0 * PAGE_SIZE] = 0xA0;
	top_address[0x1 * PAGE_SIZE] = 0xA1;
	top_address[0x2 * PAGE_SIZE] = 0xA2;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "populated pages to be resident in "
	    "top_object %p\n", top_object);
	/* leave the other pages absent */

	/* link the 2 objects */
	vm_object_reference(backing_object);
	top_object->shadow = backing_object;
	top_object->vo_shadow_offset = 3 * PAGE_SIZE;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: linked %p and %p\n",
	    top_object, backing_object);

	/* unmap backing object */
	vm_map_remove(kernel_map,
	    backing_offset,
	    backing_offset + backing_size,
	    VM_MAP_REMOVE_NO_FLAGS);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "unmapped backing_object %p [0x%llx:0x%llx]\n",
	    backing_object,
	    (uint64_t) backing_offset,
	    (uint64_t) (backing_offset + backing_size));

	/* collapse */
	printf("VM_TEST_COLLAPSE_COMPRESSOR: collapsing %p\n", top_object);
	vm_object_lock(top_object);
	vm_object_collapse(top_object, 0, FALSE);
	vm_object_unlock(top_object);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: collapsed %p\n", top_object);

	/* did it work? */
	if (top_object->shadow != VM_OBJECT_NULL) {
		printf("VM_TEST_COLLAPSE_COMPRESSOR: not collapsed\n");
		printf("VM_TEST_COLLAPSE_COMPRESSOR: FAIL\n");
		if (vm_object_collapse_compressor_allowed) {
			panic("VM_TEST_COLLAPSE_COMPRESSOR: FAIL");
		}
	} else {
		/* check the contents of the mapping */
		unsigned char expect[9] =
		{ 0xA0, 0xA1, 0xA2,             /* resident in top */
		  0xA3, 0xA4, 0xA5,             /* compressed in top */
		  0xB9,         /* resident in backing + shadow_offset */
		  0xBD,         /* compressed in backing + shadow_offset + paging_offset */
		  0x00 };                       /* absent in both */
		unsigned char actual[9];
		unsigned int i, errors;

		errors = 0;
		for (i = 0; i < sizeof(actual); i++) {
			actual[i] = (unsigned char) top_address[i * PAGE_SIZE];
			if (actual[i] != expect[i]) {
				errors++;
			}
		}
		printf("VM_TEST_COLLAPSE_COMPRESSOR: "
		    "actual [%x %x %x %x %x %x %x %x %x] "
		    "expect [%x %x %x %x %x %x %x %x %x] "
		    "%d errors\n",
		    actual[0], actual[1], actual[2], actual[3],
		    actual[4], actual[5], actual[6], actual[7],
		    actual[8],
		    expect[0], expect[1], expect[2], expect[3],
		    expect[4], expect[5], expect[6], expect[7],
		    expect[8],
		    errors);
		if (errors) {
			panic("VM_TEST_COLLAPSE_COMPRESSOR: FAIL");
		} else {
			printf("VM_TEST_COLLAPSE_COMPRESSOR: PASS\n");
		}
	}
}
#else /* VM_TEST_COLLAPSE_COMPRESSOR */
#define vm_test_collapse_compressor()
#endif /* VM_TEST_COLLAPSE_COMPRESSOR */

#if VM_TEST_WIRE_AND_EXTRACT
extern ppnum_t vm_map_get_phys_page(vm_map_t map,
    vm_offset_t offset);
static void
vm_test_wire_and_extract(void)
{
	ledger_t                ledger;
	vm_map_t                user_map, wire_map;
	mach_vm_address_t       user_addr, wire_addr;
	mach_vm_size_t          user_size, wire_size;
	mach_vm_offset_t        cur_offset;
	vm_prot_t               cur_prot, max_prot;
	ppnum_t                 user_ppnum, wire_ppnum;
	kern_return_t           kr;

	ledger = ledger_instantiate(&task_ledger_template);
	pmap_t user_pmap = pmap_create_options(ledger, 0, PMAP_CREATE_64BIT);
	assert(user_pmap);
	user_map = vm_map_create_options(user_pmap,
	    0x100000000ULL,
	    0x200000000ULL,
	    VM_MAP_CREATE_DEFAULT);
	wire_map = vm_map_create_options(NULL,
	    0x100000000ULL,
	    0x200000000ULL,
	    VM_MAP_CREATE_DEFAULT);
	user_addr = 0;
	user_size = 0x10000;
	kr = mach_vm_allocate(user_map,
	    &user_addr,
	    user_size,
	    VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);
	wire_addr = 0;
	wire_size = user_size;
	kr = mach_vm_remap(wire_map,
	    &wire_addr,
	    wire_size,
	    0,
	    VM_FLAGS_ANYWHERE,
	    user_map,
	    user_addr,
	    FALSE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_NONE);
	assert(kr == KERN_SUCCESS);
	for (cur_offset = 0;
	    cur_offset < wire_size;
	    cur_offset += PAGE_SIZE) {
		kr = vm_map_wire_and_extract(wire_map,
		    wire_addr + cur_offset,
		    VM_PROT_DEFAULT | VM_PROT_MEMORY_TAG_MAKE(VM_KERN_MEMORY_OSFMK),
		    TRUE,
		    &wire_ppnum);
		assert(kr == KERN_SUCCESS);
		user_ppnum = vm_map_get_phys_page(user_map,
		    user_addr + cur_offset);
		printf("VM_TEST_WIRE_AND_EXTRACT: kr=0x%x "
		    "user[%p:0x%llx:0x%x] wire[%p:0x%llx:0x%x]\n",
		    kr,
		    user_map, user_addr + cur_offset, user_ppnum,
		    wire_map, wire_addr + cur_offset, wire_ppnum);
		if (kr != KERN_SUCCESS ||
		    wire_ppnum == 0 ||
		    wire_ppnum != user_ppnum) {
			panic("VM_TEST_WIRE_AND_EXTRACT: FAIL");
		}
	}
	cur_offset -= PAGE_SIZE;
	kr = vm_map_wire_and_extract(wire_map,
	    wire_addr + cur_offset,
	    VM_PROT_DEFAULT,
	    TRUE,
	    &wire_ppnum);
	assert(kr == KERN_SUCCESS);
	printf("VM_TEST_WIRE_AND_EXTRACT: re-wire kr=0x%x "
	    "user[%p:0x%llx:0x%x] wire[%p:0x%llx:0x%x]\n",
	    kr,
	    user_map, user_addr + cur_offset, user_ppnum,
	    wire_map, wire_addr + cur_offset, wire_ppnum);
	if (kr != KERN_SUCCESS ||
	    wire_ppnum == 0 ||
	    wire_ppnum != user_ppnum) {
		panic("VM_TEST_WIRE_AND_EXTRACT: FAIL");
	}

	printf("VM_TEST_WIRE_AND_EXTRACT: PASS\n");
}
#else /* VM_TEST_WIRE_AND_EXTRACT */
#define vm_test_wire_and_extract()
#endif /* VM_TEST_WIRE_AND_EXTRACT */

#if VM_TEST_PAGE_WIRE_OVERFLOW_PANIC
static void
vm_test_page_wire_overflow_panic(void)
{
	vm_object_t object;
	vm_page_t page;

	printf("VM_TEST_PAGE_WIRE_OVERFLOW_PANIC: starting...\n");

	object = vm_object_allocate(PAGE_SIZE, VM_MAP_SERIAL_NONE);
	while ((page = vm_page_grab()) == VM_PAGE_NULL) {
		VM_PAGE_WAIT();
	}
	vm_object_lock(object);
	vm_page_insert(page, object, 0);
	vm_page_lock_queues();
	do {
		vm_page_wire(page, 1, FALSE);
	} while (page->wire_count != 0);
	vm_page_unlock_queues();
	vm_object_unlock(object);
	panic("FBDP(%p,%p): wire_count overflow not detected",
	    object, page);
}
#else /* VM_TEST_PAGE_WIRE_OVERFLOW_PANIC */
#define vm_test_page_wire_overflow_panic()
#endif /* VM_TEST_PAGE_WIRE_OVERFLOW_PANIC */

#if __arm64__ && VM_TEST_KERNEL_OBJECT_FAULT
extern int copyinframe(vm_address_t fp, char *frame, boolean_t is64bit);
static void
vm_test_kernel_object_fault(void)
{
	vm_offset_t stack;
	uintptr_t frameb[2];
	int ret;

	kmem_alloc(kernel_map, &stack,
	    kernel_stack_size + ptoa(2),
	    KMA_NOFAIL | KMA_KSTACK | KMA_KOBJECT |
	    KMA_GUARD_FIRST | KMA_GUARD_LAST,
	    VM_KERN_MEMORY_STACK);

	ret = copyinframe((uintptr_t)stack, (char *)frameb, TRUE);
	if (ret != 0) {
		printf("VM_TEST_KERNEL_OBJECT_FAULT: PASS\n");
	} else {
		printf("VM_TEST_KERNEL_OBJECT_FAULT: FAIL\n");
	}

	kmem_free_guard(kernel_map, stack, kernel_stack_size + ptoa(2),
	    KMF_GUARD_FIRST | KMF_GUARD_LAST, KMEM_GUARD_NONE);
	stack = 0;
}
#else /* __arm64__ && VM_TEST_KERNEL_OBJECT_FAULT */
#define vm_test_kernel_object_fault()
#endif /* __arm64__ && VM_TEST_KERNEL_OBJECT_FAULT */

#if VM_TEST_DEVICE_PAGER_TRANSPOSE
static void
vm_test_device_pager_transpose(void)
{
	memory_object_t device_pager;
	vm_object_t     anon_object, device_object;
	vm_size_t       size;
	vm_map_offset_t device_mapping;
	kern_return_t   kr;

	size = 3 * PAGE_SIZE;
	anon_object = vm_object_allocate(size, kernel_map->serial_id);
	assert(anon_object != VM_OBJECT_NULL);
	device_pager = device_pager_setup(NULL, 0, size, 0);
	assert(device_pager != NULL);
	device_object = memory_object_to_vm_object(device_pager);
	assert(device_object != VM_OBJECT_NULL);
#if 0
	/*
	 * Can't actually map this, since another thread might do a
	 * vm_map_enter() that gets coalesced into this object, which
	 * would cause the test to fail.
	 */
	vm_map_offset_t anon_mapping = 0;
	kr = vm_map_enter(kernel_map, &anon_mapping, size, 0,
	    VM_MAP_KERNEL_FLAGS_ANYWHERE(),
	    anon_object, 0, FALSE, VM_PROT_DEFAULT, VM_PROT_ALL,
	    VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
#endif
	device_mapping = 0;
	kr = mach_vm_map_kernel(kernel_map,
	    vm_sanitize_wrap_addr_ref(&device_mapping),
	    size,
	    0,
	    VM_MAP_KERNEL_FLAGS_DATA_SHARED_ANYWHERE(),
	    (void *)device_pager,
	    0,
	    FALSE,
	    VM_PROT_DEFAULT,
	    VM_PROT_ALL,
	    VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
	memory_object_deallocate(device_pager);

	vm_object_lock(anon_object);
	vm_object_activity_begin(anon_object);
	anon_object->blocked_access = TRUE;
	vm_object_unlock(anon_object);
	vm_object_lock(device_object);
	vm_object_activity_begin(device_object);
	device_object->blocked_access = TRUE;
	vm_object_unlock(device_object);

	assert(os_ref_get_count_raw(&anon_object->ref_count) == 1);
	assert(!anon_object->named);
	assert(os_ref_get_count_raw(&device_object->ref_count) == 2);
	assert(device_object->named);

	kr = vm_object_transpose(device_object, anon_object, size);
	assert(kr == KERN_SUCCESS);

	vm_object_lock(anon_object);
	vm_object_activity_end(anon_object);
	anon_object->blocked_access = FALSE;
	vm_object_unlock(anon_object);
	vm_object_lock(device_object);
	vm_object_activity_end(device_object);
	device_object->blocked_access = FALSE;
	vm_object_unlock(device_object);

	assert(os_ref_get_count_raw(&anon_object->ref_count) == 2);
	assert(anon_object->named);
#if 0
	kr = vm_deallocate(kernel_map, anon_mapping, size);
	assert(kr == KERN_SUCCESS);
#endif
	assert(os_ref_get_count_raw(&device_object->ref_count) == 1);
	assert(!device_object->named);
	kr = vm_deallocate(kernel_map, device_mapping, size);
	assert(kr == KERN_SUCCESS);

	printf("VM_TEST_DEVICE_PAGER_TRANSPOSE: PASS\n");
}
#else /* VM_TEST_DEVICE_PAGER_TRANSPOSE */
#define vm_test_device_pager_transpose()
#endif /* VM_TEST_DEVICE_PAGER_TRANSPOSE */

extern kern_return_t vm_allocate_external(vm_map_t        map,
    vm_offset_t     *addr,
    vm_size_t       size,
    int             flags);
extern kern_return_t vm_remap_external(vm_map_t                target_map,
    vm_offset_t             *address,
    vm_size_t               size,
    vm_offset_t             mask,
    int                     flags,
    vm_map_t                src_map,
    vm_offset_t             memory_address,
    boolean_t               copy,
    vm_prot_t               *cur_protection,
    vm_prot_t               *max_protection,
    vm_inherit_t            inheritance);
#if PMAP_CREATE_FORCE_4K_PAGES && MACH_ASSERT
extern int debug4k_panic_on_misaligned_sharing;
void vm_test_4k(void);
void
vm_test_4k(void)
{
	pmap_t test_pmap;
	vm_map_t test_map;
	kern_return_t kr;
	vm_address_t expected_addr;
	vm_address_t alloc1_addr, alloc2_addr, alloc3_addr, alloc4_addr;
	vm_address_t alloc5_addr, dealloc_addr, remap_src_addr, remap_dst_addr;
	vm_size_t alloc1_size, alloc2_size, alloc3_size, alloc4_size;
	vm_size_t alloc5_size, remap_src_size;
	vm_address_t fault_addr;
	vm_prot_t cur_prot, max_prot;
	int saved_debug4k_panic_on_misaligned_sharing;

	printf("\n\n\nVM_TEST_4K:%d creating 4K map...\n", __LINE__);
	test_pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT | PMAP_CREATE_FORCE_4K_PAGES);
	assert(test_pmap != NULL);
	test_map = vm_map_create_with_page_shift(test_pmap,
	    MACH_VM_MIN_ADDRESS,
	    MACH_VM_MAX_ADDRESS,
	    FOURK_PAGE_SHIFT,
	    VM_MAP_CREATE_DEFAULT);
	assert(test_map != VM_MAP_NULL);
	printf("VM_TEST_4K:%d map %p pmap %p page_size 0x%x\n", __LINE__, test_map, test_pmap, VM_MAP_PAGE_SIZE(test_map));

	alloc1_addr = 0;
	alloc1_size = 1 * FOURK_PAGE_SIZE;
	expected_addr = 0x1000;
	printf("VM_TEST_4K:%d vm_allocate(%p, 0x%lx, 0x%lx)...\n", __LINE__, test_map, alloc1_addr, alloc1_size);
	kr = vm_allocate_external(test_map,
	    &alloc1_addr,
	    alloc1_size,
	    VM_FLAGS_ANYWHERE);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	assertf(alloc1_addr == expected_addr, "alloc1_addr = 0x%lx expected 0x%lx", alloc1_addr, expected_addr);
	printf("VM_TEST_4K:%d -> 0x%lx\n", __LINE__, alloc1_addr);
	expected_addr += alloc1_size;

	printf("VM_TEST_4K:%d vm_deallocate(%p, 0x%lx, 0x%lx)...\n", __LINE__, test_map, alloc1_addr, alloc1_size);
	kr = vm_deallocate(test_map, alloc1_addr, alloc1_size);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	printf("VM_TEST_4K:%d -> 0x%lx\n", __LINE__, alloc1_addr);

	alloc1_addr = 0;
	alloc1_size = 1 * FOURK_PAGE_SIZE;
	expected_addr = 0x1000;
	printf("VM_TEST_4K:%d vm_allocate(%p, 0x%lx, 0x%lx)...\n", __LINE__, test_map, alloc1_addr, alloc1_size);
	kr = vm_allocate_external(test_map,
	    &alloc1_addr,
	    alloc1_size,
	    VM_FLAGS_ANYWHERE);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	assertf(alloc1_addr == expected_addr, "alloc1_addr = 0x%lx expected 0x%lx", alloc1_addr, expected_addr);
	printf("VM_TEST_4K:%d -> 0x%lx\n", __LINE__, alloc1_addr);
	expected_addr += alloc1_size;

	alloc2_addr = 0;
	alloc2_size = 3 * FOURK_PAGE_SIZE;
	printf("VM_TEST_4K:%d vm_allocate(%p, 0x%lx, 0x%lx)...\n", __LINE__, test_map, alloc2_addr, alloc2_size);
	kr = vm_allocate_external(test_map,
	    &alloc2_addr,
	    alloc2_size,
	    VM_FLAGS_ANYWHERE);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	assertf(alloc2_addr == expected_addr, "alloc2_addr = 0x%lx expected 0x%lx", alloc2_addr, expected_addr);
	printf("VM_TEST_4K:%d -> 0x%lx\n", __LINE__, alloc2_addr);
	expected_addr += alloc2_size;

	alloc3_addr = 0;
	alloc3_size = 18 * FOURK_PAGE_SIZE;
	printf("VM_TEST_4K:%d vm_allocate(%p, 0x%lx, 0x%lx)...\n", __LINE__, test_map, alloc3_addr, alloc3_size);
	kr = vm_allocate_external(test_map,
	    &alloc3_addr,
	    alloc3_size,
	    VM_FLAGS_ANYWHERE);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	assertf(alloc3_addr == expected_addr, "alloc3_addr = 0x%lx expected 0x%lx\n", alloc3_addr, expected_addr);
	printf("VM_TEST_4K:%d -> 0x%lx\n", __LINE__, alloc3_addr);
	expected_addr += alloc3_size;

	alloc4_addr = 0;
	alloc4_size = 1 * FOURK_PAGE_SIZE;
	printf("VM_TEST_4K:%d vm_allocate(%p, 0x%lx, 0x%lx)...\n", __LINE__, test_map, alloc4_addr, alloc4_size);
	kr = vm_allocate_external(test_map,
	    &alloc4_addr,
	    alloc4_size,
	    VM_FLAGS_ANYWHERE);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	assertf(alloc4_addr == expected_addr, "alloc4_addr = 0x%lx expected 0x%lx", alloc4_addr, expected_addr);
	printf("VM_TEST_4K:%d -> 0x%lx\n", __LINE__, alloc3_addr);
	expected_addr += alloc4_size;

	printf("VM_TEST_4K:%d vm_protect(%p, 0x%lx, 0x%lx, READ)...\n", __LINE__, test_map, alloc2_addr, (1UL * FOURK_PAGE_SIZE));
	kr = vm_protect(test_map,
	    alloc2_addr,
	    (1UL * FOURK_PAGE_SIZE),
	    FALSE,
	    VM_PROT_READ);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);

	for (fault_addr = alloc1_addr;
	    fault_addr < alloc4_addr + alloc4_size + (2 * FOURK_PAGE_SIZE);
	    fault_addr += FOURK_PAGE_SIZE) {
		printf("VM_TEST_4K:%d write fault at 0x%lx...\n", __LINE__, fault_addr);
		kr = vm_fault(test_map,
		    fault_addr,
		    VM_PROT_WRITE,
		    FALSE,
		    VM_KERN_MEMORY_NONE,
		    THREAD_UNINT,
		    NULL,
		    0);
		printf("VM_TEST_4K:%d -> 0x%x\n", __LINE__, kr);
		if (fault_addr == alloc2_addr) {
			assertf(kr == KERN_PROTECTION_FAILURE, "fault_addr = 0x%lx kr = 0x%x expected 0x%x", fault_addr, kr, KERN_PROTECTION_FAILURE);
			printf("VM_TEST_4K:%d read fault at 0x%lx...\n", __LINE__, fault_addr);
			kr = vm_fault(test_map,
			    fault_addr,
			    VM_PROT_READ,
			    FALSE,
			    VM_KERN_MEMORY_NONE,
			    THREAD_UNINT,
			    NULL,
			    0);
			assertf(kr == KERN_SUCCESS, "fault_addr = 0x%lx kr = 0x%x expected 0x%x", fault_addr, kr, KERN_SUCCESS);
			printf("VM_TEST_4K:%d -> 0x%x\n", __LINE__, kr);
		} else if (fault_addr >= alloc4_addr + alloc4_size) {
			assertf(kr == KERN_INVALID_ADDRESS, "fault_addr = 0x%lx kr = 0x%x expected 0x%x", fault_addr, kr, KERN_INVALID_ADDRESS);
		} else {
			assertf(kr == KERN_SUCCESS, "fault_addr = 0x%lx kr = 0x%x expected 0x%x", fault_addr, kr, KERN_SUCCESS);
		}
	}

	alloc5_addr = 0;
	alloc5_size = 7 * FOURK_PAGE_SIZE;
	printf("VM_TEST_4K:%d vm_allocate(%p, 0x%lx, 0x%lx)...\n", __LINE__, test_map, alloc5_addr, alloc5_size);
	kr = vm_allocate_external(test_map,
	    &alloc5_addr,
	    alloc5_size,
	    VM_FLAGS_ANYWHERE);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	assertf(alloc5_addr == expected_addr, "alloc5_addr = 0x%lx expected 0x%lx", alloc5_addr, expected_addr);
	printf("VM_TEST_4K:%d -> 0x%lx\n", __LINE__, alloc5_addr);
	expected_addr += alloc5_size;

	dealloc_addr = vm_map_round_page(alloc5_addr, PAGE_SHIFT);
	dealloc_addr += FOURK_PAGE_SIZE;
	printf("VM_TEST_4K:%d vm_deallocate(%p, 0x%lx, 0x%x)...\n", __LINE__, test_map, dealloc_addr, FOURK_PAGE_SIZE);
	kr = vm_deallocate(test_map, dealloc_addr, FOURK_PAGE_SIZE);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	printf("VM_TEST_4K:%d -> 0x%x\n", __LINE__, kr);

	remap_src_addr = vm_map_round_page(alloc3_addr, PAGE_SHIFT);
	remap_src_addr += FOURK_PAGE_SIZE;
	remap_src_size = 2 * FOURK_PAGE_SIZE;
	remap_dst_addr = 0;
	printf("VM_TEST_4K:%d vm_remap(%p, 0x%lx, 0x%lx, 0x%lx, copy=0)...\n", __LINE__, test_map, remap_dst_addr, remap_src_size, remap_src_addr);
	kr = vm_remap_external(test_map,
	    &remap_dst_addr,
	    remap_src_size,
	    0,                    /* mask */
	    VM_FLAGS_ANYWHERE,
	    test_map,
	    remap_src_addr,
	    FALSE,                    /* copy */
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	assertf(remap_dst_addr == expected_addr, "remap_dst_addr = 0x%lx expected 0x%lx", remap_dst_addr, expected_addr);
	printf("VM_TEST_4K:%d -> 0x%lx\n", __LINE__, remap_dst_addr);
	expected_addr += remap_src_size;

	for (fault_addr = remap_dst_addr;
	    fault_addr < remap_dst_addr + remap_src_size;
	    fault_addr += 4096) {
		printf("VM_TEST_4K:%d write fault at 0x%lx...\n", __LINE__, fault_addr);
		kr = vm_fault(test_map,
		    fault_addr,
		    VM_PROT_WRITE,
		    FALSE,
		    VM_KERN_MEMORY_NONE,
		    THREAD_UNINT,
		    NULL,
		    0);
		assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
		printf("VM_TEST_4K:%d -> 0x%x\n", __LINE__, kr);
	}

	printf("VM_TEST_4K:\n");
	remap_dst_addr = 0;
	remap_src_addr = alloc3_addr + 0xc000;
	remap_src_size = 0x5000;
	printf("VM_TEST_4K: vm_remap(%p, 0x%lx, 0x%lx, %p, copy=0) from 4K to 16K\n", test_map, remap_src_addr, remap_src_size, kernel_map);
	kr = vm_remap_external(kernel_map,
	    &remap_dst_addr,
	    remap_src_size,
	    0,                    /* mask */
	    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
	    test_map,
	    remap_src_addr,
	    FALSE,                    /* copy */
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	printf("VM_TEST_4K: -> remapped (shared) in map %p at addr 0x%lx\n", kernel_map, remap_dst_addr);

	printf("VM_TEST_4K:\n");
	remap_dst_addr = 0;
	remap_src_addr = alloc3_addr + 0xc000;
	remap_src_size = 0x5000;
	printf("VM_TEST_4K: vm_remap(%p, 0x%lx, 0x%lx, %p, copy=1) from 4K to 16K\n", test_map, remap_src_addr, remap_src_size, kernel_map);
	kr = vm_remap_external(kernel_map,
	    &remap_dst_addr,
	    remap_src_size,
	    0,                    /* mask */
	    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
	    test_map,
	    remap_src_addr,
	    TRUE,                    /* copy */
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	printf("VM_TEST_4K: -> remapped (COW) in map %p at addr 0x%lx\n", kernel_map, remap_dst_addr);

	printf("VM_TEST_4K:\n");
	saved_debug4k_panic_on_misaligned_sharing = debug4k_panic_on_misaligned_sharing;
	debug4k_panic_on_misaligned_sharing = 0;
	remap_dst_addr = 0;
	remap_src_addr = alloc1_addr;
	remap_src_size = alloc1_size + alloc2_size;
	printf("VM_TEST_4K: vm_remap(%p, 0x%lx, 0x%lx, %p, copy=0) from 4K to 16K\n", test_map, remap_src_addr, remap_src_size, kernel_map);
	kr = vm_remap_external(kernel_map,
	    &remap_dst_addr,
	    remap_src_size,
	    0,                    /* mask */
	    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
	    test_map,
	    remap_src_addr,
	    FALSE,                    /* copy */
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	assertf(kr != KERN_SUCCESS, "kr = 0x%x", kr);
	printf("VM_TEST_4K: -> remap (SHARED) in map %p at addr 0x%lx kr=0x%x\n", kernel_map, remap_dst_addr, kr);
	debug4k_panic_on_misaligned_sharing = saved_debug4k_panic_on_misaligned_sharing;

	printf("VM_TEST_4K:\n");
	remap_dst_addr = 0;
	remap_src_addr = alloc1_addr;
	remap_src_size = alloc1_size + alloc2_size;
	printf("VM_TEST_4K: vm_remap(%p, 0x%lx, 0x%lx, %p, copy=1) from 4K to 16K\n", test_map, remap_src_addr, remap_src_size, kernel_map);
	kr = vm_remap_external(kernel_map,
	    &remap_dst_addr,
	    remap_src_size,
	    0,                    /* mask */
	    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
	    test_map,
	    remap_src_addr,
	    TRUE,                    /* copy */
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
#if 000
	assertf(kr != KERN_SUCCESS, "kr = 0x%x", kr);
	printf("VM_TEST_4K: -> remap (COPY) in map %p at addr 0x%lx kr=0x%x\n", kernel_map, remap_dst_addr, kr);
#else /* 000 */
	assertf(kr == KERN_SUCCESS, "kr = 0x%x", kr);
	printf("VM_TEST_4K: -> remap (COPY) in map %p at addr 0x%lx kr=0x%x\n", kernel_map, remap_dst_addr, kr);
#endif /* 000 */


#if 00
	printf("VM_TEST_4K:%d vm_map_remove(%p, 0x%llx, 0x%llx)...\n", __LINE__, test_map, test_map->min_offset, test_map->max_offset);
	vm_map_remove(test_map, test_map->min_offset, test_map->max_offset);
#endif

	printf("VM_TEST_4K: PASS\n\n\n\n");
}
#endif /* PMAP_CREATE_FORCE_4K_PAGES && MACH_ASSERT */

#if MACH_ASSERT
static void
vm_test_map_copy_adjust_to_target_one(
	vm_map_copy_t copy_map,
	vm_map_t target_map)
{
	kern_return_t kr;
	vm_map_copy_t target_copy;
	vm_map_offset_t overmap_start, overmap_end, trimmed_start;

	target_copy = VM_MAP_COPY_NULL;
	/* size is 2 (4k) pages but range covers 3 pages */
	kr = vm_map_copy_adjust_to_target(copy_map,
	    0x0 + 0xfff,
	    0x1002,
	    target_map,
	    FALSE,
	    &target_copy,
	    &overmap_start,
	    &overmap_end,
	    &trimmed_start);
	assert(kr == KERN_SUCCESS);
	assert(overmap_start == 0);
	assert(overmap_end == 0);
	assert(trimmed_start == 0);
	assertf(target_copy->size == 0x3000,
	    "target_copy %p size 0x%llx\n",
	    target_copy, (uint64_t)target_copy->size);
	vm_map_copy_discard(target_copy);

	/* 1. adjust_to_target() for bad offset -> error */
	/* 2. adjust_to_target() for bad size -> error */
	/* 3. adjust_to_target() for the whole thing -> unchanged */
	/* 4. adjust_to_target() to trim start by less than 1 page */
	/* 5. adjust_to_target() to trim end by less than 1 page */
	/* 6. adjust_to_target() to trim start and end by less than 1 page */
	/* 7. adjust_to_target() to trim start by more than 1 page */
	/* 8. adjust_to_target() to trim end by more than 1 page */
	/* 9. adjust_to_target() to trim start and end by more than 1 page */
	/* 10. adjust_to_target() to trim start by more than 1 entry */
	/* 11. adjust_to_target() to trim start by more than 1 entry */
	/* 12. adjust_to_target() to trim start and end by more than 1 entry */
	/* 13. adjust_to_target() to trim start and end down to 1 entry */
}

static void
vm_test_map_copy_adjust_to_target(void)
{
	kern_return_t kr;
	vm_map_t map4k, map16k;
	vm_object_t obj1, obj2, obj3, obj4;
	vm_map_offset_t addr4k, addr16k;
	vm_map_size_t size4k, size16k;
	vm_map_copy_t copy4k, copy16k;
	vm_prot_t curprot, maxprot;
	vm_map_kernel_flags_t vmk_flags;

	/* create a 4k map */
	map4k = vm_map_create_with_page_shift(PMAP_NULL, 0, (uint32_t)-1,
	    12, VM_MAP_CREATE_DEFAULT);

	/* create a 16k map */
	map16k = vm_map_create_with_page_shift(PMAP_NULL, 0, (uint32_t)-1,
	    14, VM_MAP_CREATE_DEFAULT);

	/* create 4 VM objects */
	obj1 = vm_object_allocate(0x100000, map4k->serial_id);
	obj2 = vm_object_allocate(0x100000, map4k->serial_id);
	obj3 = vm_object_allocate(0x100000, map4k->serial_id);
	obj4 = vm_object_allocate(0x100000, map4k->serial_id);

	/* map objects in 4k map */
	vm_object_reference(obj1);
	addr4k = 0x1000;
	size4k = 0x3000;
	kr = vm_map_enter(map4k, &addr4k, size4k, 0,
	    VM_MAP_KERNEL_FLAGS_DATA_SHARED_ANYWHERE(), obj1, 0,
	    FALSE, VM_PROT_DEFAULT, VM_PROT_DEFAULT,
	    VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
	assert(addr4k == 0x1000);

	/* map objects in 16k map */
	vm_object_reference(obj1);
	addr16k = 0x4000;
	size16k = 0x8000;
	kr = vm_map_enter(map16k, &addr16k, size16k, 0,
	    VM_MAP_KERNEL_FLAGS_DATA_SHARED_ANYWHERE(), obj1, 0,
	    FALSE, VM_PROT_DEFAULT, VM_PROT_DEFAULT,
	    VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
	assert(addr16k == 0x4000);

	/* test for <rdar://60959809> */
	ipc_port_t mem_entry;
	memory_object_size_t mem_entry_size;
	mach_vm_size_t map_size;
	mem_entry_size = 0x1002;
	mem_entry = IPC_PORT_NULL;
	kr = mach_make_memory_entry_64(map16k, &mem_entry_size, addr16k + 0x2fff,
	    MAP_MEM_VM_SHARE | MAP_MEM_USE_DATA_ADDR | VM_PROT_READ,
	    &mem_entry, IPC_PORT_NULL);
	assertf(kr == KERN_SUCCESS, "kr 0x%x\n", kr);
	assertf(mem_entry_size == 0x5001, "mem_entry_size 0x%llx\n", (uint64_t) mem_entry_size);
	map_size = 0;
	kr = mach_memory_entry_map_size(mem_entry, map4k, 0, 0x1002, &map_size);
	assertf(kr == KERN_SUCCESS, "kr 0x%x\n", kr);
	assertf(map_size == 0x3000, "mem_entry %p map_size 0x%llx\n", mem_entry, (uint64_t)map_size);
	mach_memory_entry_port_release(mem_entry);

	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_remap_legacy_mode = true;

	/* create 4k copy map */
	curprot = VM_PROT_NONE;
	maxprot = VM_PROT_NONE;
	kr = vm_map_copy_extract(map4k, addr4k, 0x3000,
	    FALSE, &copy4k, &curprot, &maxprot,
	    VM_INHERIT_DEFAULT, vmk_flags);
	assert(kr == KERN_SUCCESS);
	assert(copy4k->size == 0x3000);

	/* create 16k copy map */
	curprot = VM_PROT_NONE;
	maxprot = VM_PROT_NONE;
	kr = vm_map_copy_extract(map16k, addr16k, 0x4000,
	    FALSE, &copy16k, &curprot, &maxprot,
	    VM_INHERIT_DEFAULT, vmk_flags);
	assert(kr == KERN_SUCCESS);
	assert(copy16k->size == 0x4000);

	/* test each combination */
//	vm_test_map_copy_adjust_to_target_one(copy4k, map4k);
//	vm_test_map_copy_adjust_to_target_one(copy16k, map16k);
//	vm_test_map_copy_adjust_to_target_one(copy4k, map16k);
	vm_test_map_copy_adjust_to_target_one(copy16k, map4k);

	/* assert 1 ref on 4k map */
	assert(os_ref_get_count_raw(&map4k->map_refcnt) == 1);
	/* release 4k map */
	vm_map_deallocate(map4k);
	/* assert 1 ref on 16k map */
	assert(os_ref_get_count_raw(&map16k->map_refcnt) == 1);
	/* release 16k map */
	vm_map_deallocate(map16k);
	/* deallocate copy maps */
	vm_map_copy_discard(copy4k);
	vm_map_copy_discard(copy16k);
	/* assert 1 ref on all VM objects */
	assert(os_ref_get_count_raw(&obj1->ref_count) == 1);
	assert(os_ref_get_count_raw(&obj2->ref_count) == 1);
	assert(os_ref_get_count_raw(&obj3->ref_count) == 1);
	assert(os_ref_get_count_raw(&obj4->ref_count) == 1);
	/* release all VM objects */
	vm_object_deallocate(obj1);
	vm_object_deallocate(obj2);
	vm_object_deallocate(obj3);
	vm_object_deallocate(obj4);
}
#endif /* MACH_ASSERT */

#if __arm64__ && !KASAN
__attribute__((noinline))
static void
vm_test_per_mapping_internal_accounting(void)
{
	ledger_t ledger;
	pmap_t user_pmap;
	vm_map_t user_map;
	kern_return_t kr;
	ledger_amount_t balance;
	mach_vm_address_t user_addr, user_remap;
	vm_map_offset_t device_addr;
	mach_vm_size_t user_size;
	vm_prot_t cur_prot, max_prot;
	upl_size_t upl_size;
	upl_t upl;
	unsigned int upl_count;
	upl_control_flags_t upl_flags;
	upl_page_info_t *pl;
	ppnum_t ppnum;
	vm_object_t device_object;
	vm_map_offset_t map_start, map_end;
	int pmap_flags;

	pmap_flags = 0;
	if (sizeof(vm_map_offset_t) == 4) {
		map_start = 0x100000000ULL;
		map_end = 0x200000000ULL;
		pmap_flags |= PMAP_CREATE_64BIT;
	} else {
		map_start = 0x10000000;
		map_end = 0x20000000;
	}
	/* create a user address space */
	ledger = ledger_instantiate(&task_ledger_template);
	assert(ledger);
	user_pmap = pmap_create_options(ledger, 0, pmap_flags);
	assert(user_pmap);
	user_map = vm_map_create_options(user_pmap,
	    map_start,
	    map_end,
	    VM_MAP_CREATE_DEFAULT);
	assert(user_map);
	/* check ledger */
	kr = ledger_get_balance(ledger, task_ledgers.internal, LEO_SETTLE, &balance);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	assertf(balance == 0, "balance=0x%llx", balance);
	/* allocate 1 page in that address space */
	user_addr = 0;
	user_size = PAGE_SIZE;
	kr = mach_vm_allocate(user_map,
	    &user_addr,
	    user_size,
	    VM_FLAGS_ANYWHERE);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	/* check ledger */
	kr = ledger_get_balance(ledger, task_ledgers.internal, LEO_SETTLE, &balance);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	assertf(balance == 0, "balance=0x%llx", balance);
	/* remap the original mapping */
	user_remap = 0;
	kr = mach_vm_remap(user_map,
	    &user_remap,
	    PAGE_SIZE,
	    0,
	    VM_FLAGS_ANYWHERE,
	    user_map,
	    user_addr,
	    FALSE,                /* copy */
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	/* check ledger */
	kr = ledger_get_balance(ledger, task_ledgers.internal, LEO_SETTLE, &balance);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	assertf(balance == 0, "balance=0x%llx", balance);
	/* create a UPL from the original mapping */
	upl_size = PAGE_SIZE;
	upl = NULL;
	upl_count = 0;
	upl_flags = UPL_FILE_IO | UPL_NO_SYNC | UPL_SET_INTERNAL | UPL_SET_LITE | UPL_SET_IO_WIRE;
	kr = vm_map_create_upl(user_map,
	    (vm_map_offset_t)user_addr,
	    &upl_size,
	    &upl,
	    NULL,
	    &upl_count,
	    &upl_flags,
	    VM_KERN_MEMORY_DIAG);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	pl = UPL_GET_INTERNAL_PAGE_LIST(upl);
	assert(upl_page_present(pl, 0));
	ppnum = upl_phys_page(pl, 0);
	/* check ledger */
	kr = ledger_get_balance(ledger, task_ledgers.internal, LEO_SETTLE, &balance);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	assertf(balance == 0, "balance=0x%llx", balance);
	device_object = vm_object_allocate(PAGE_SIZE, kernel_map->serial_id);
	assert(device_object);
	vm_object_lock(device_object);
	VM_OBJECT_SET_PRIVATE(device_object, TRUE);
	VM_OBJECT_SET_PHYS_CONTIGUOUS(device_object, TRUE);
	device_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
	vm_object_unlock(device_object);
	kr = vm_object_populate_with_private(device_object, 0,
	    ppnum, PAGE_SIZE);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);

	/* check ledger */
	kr = ledger_get_balance(ledger, task_ledgers.internal, LEO_SETTLE, &balance);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	assertf(balance == 0, "balance=0x%llx", balance);
	/* deallocate the original mapping */
	kr = mach_vm_deallocate(user_map, user_addr, PAGE_SIZE);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	/* map the device_object in the kernel */
	device_addr = 0;
	vm_object_reference(device_object);
	kr = vm_map_enter(kernel_map,
	    &device_addr,
	    PAGE_SIZE,
	    0,
	    VM_MAP_KERNEL_FLAGS_DATA_SHARED_ANYWHERE(),
	    device_object,
	    0,
	    FALSE,               /* copy */
	    VM_PROT_DEFAULT,
	    VM_PROT_DEFAULT,
	    VM_INHERIT_NONE);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	/* access the device pager mapping */
	*(char *)device_addr = 'x';
	printf("%s:%d 0x%llx: 0x%x\n", __FUNCTION__, __LINE__, (uint64_t)device_addr, *(uint32_t *)device_addr);
	/* check ledger */
	kr = ledger_get_balance(ledger, task_ledgers.internal, LEO_SETTLE, &balance);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	assertf(balance == 0, "balance=0x%llx", balance);
	/* fault in the remap addr */
	kr = vm_fault(user_map, (vm_map_offset_t)user_remap, VM_PROT_READ,
	    FALSE, 0, TRUE, NULL, 0);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	/* check ledger */
	kr = ledger_get_balance(ledger, task_ledgers.internal, LEO_SETTLE, &balance);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	assertf(balance == PAGE_SIZE, "balance=0x%llx", balance);
	/* deallocate remapping */
	kr = mach_vm_deallocate(user_map, user_remap, PAGE_SIZE);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	/* check ledger */
	kr = ledger_get_balance(ledger, task_ledgers.internal, LEO_SETTLE, &balance);
	assertf(kr == KERN_SUCCESS, "kr=0x%x", kr);
	assertf(balance == 0, "balance=0x%llx", balance);
	/* TODO: cleanup... */
	printf("%s:%d PASS\n", __FUNCTION__, __LINE__);
}
#endif /* __arm64__ && !KASAN */

static void
vm_test_kernel_tag_accounting_kma(kma_flags_t base, kma_flags_t bit)
{
	vm_tag_t tag = VM_KERN_MEMORY_REASON; /* unused during POST */
	uint64_t init_size = vm_tag_get_size(tag);
	__assert_only uint64_t final_size = init_size + PAGE_SIZE;
	vm_address_t  address;
	kern_return_t kr;

	/*
	 * Test the matrix of:
	 *  - born with or without bit
	 *  - bit flipped or not
	 *  - dies with or without bit
	 */
	for (uint32_t i = 0; i < 4; i++) {
		kma_flags_t flags1 = base | ((i & 1) ? bit : KMA_NONE);
		kma_flags_t flags2 = base | ((i & 2) ? bit : KMA_NONE);

		kr = kmem_alloc(kernel_map, &address, PAGE_SIZE, flags1, tag);
		assert3u(kr, ==, KERN_SUCCESS);

		if (flags1 & (KMA_VAONLY | KMA_PAGEABLE)) {
			assert3u(init_size, ==, vm_tag_get_size(tag));
		} else {
			assert3u(final_size, ==, vm_tag_get_size(tag));
		}

		if ((flags1 ^ flags2) == KMA_VAONLY) {
			if (flags1 & KMA_VAONLY) {
				kernel_memory_populate(address, PAGE_SIZE,
				    KMA_KOBJECT | KMA_NOFAIL, tag);
			} else {
				kernel_memory_depopulate(address, PAGE_SIZE,
				    KMA_KOBJECT, tag);
			}
		}

		if ((flags1 ^ flags2) == KMA_PAGEABLE) {
			if (flags1 & KMA_PAGEABLE) {
				kr = vm_map_wire_kernel(kernel_map,
				    address, address + PAGE_SIZE,
				    VM_PROT_DEFAULT, tag, false);
				assert3u(kr, ==, KERN_SUCCESS);
			} else {
				kr = vm_map_unwire(kernel_map,
				    address, address + PAGE_SIZE, false);
				assert3u(kr, ==, KERN_SUCCESS);
			}
		}

		if (flags2 & (KMA_VAONLY | KMA_PAGEABLE)) {
			assert3u(init_size, ==, vm_tag_get_size(tag));
		} else {
			assert3u(final_size, ==, vm_tag_get_size(tag));
		}

		kmem_free(kernel_map, address, PAGE_SIZE);
		assert3u(init_size, ==, vm_tag_get_size(tag));
	}
}

__attribute__((noinline))
static void
vm_test_kernel_tag_accounting(void)
{
	printf("%s: test running\n", __func__);

	printf("%s: account (KMA_KOBJECT + populate)...\n", __func__);
	vm_test_kernel_tag_accounting_kma(KMA_KOBJECT, KMA_VAONLY);
	printf("%s:     PASS\n", __func__);

	printf("%s: account (regular object + wiring)...\n", __func__);
	vm_test_kernel_tag_accounting_kma(KMA_NONE, KMA_PAGEABLE);
	printf("%s:     PASS\n", __func__);

	printf("%s: test passed\n", __func__);

#undef if_bit
}

__attribute__((noinline))
static void
vm_test_collapse_overflow(void)
{
	vm_object_t object, backing_object;
	vm_object_size_t size;
	vm_page_t m;

	/* create an object for which (int)(size>>PAGE_SHIFT) = 0 */
	size = 0x400000000000ULL;
	assert((int)(size >> PAGE_SHIFT) == 0);
	backing_object = vm_object_allocate(size + PAGE_SIZE, VM_MAP_SERIAL_NONE);
	assert(backing_object);
	vm_object_reference(backing_object);
	/* insert a page */
	m = VM_PAGE_NULL;
	while (m == VM_PAGE_NULL) {
		m = vm_page_grab();
		if (m == VM_PAGE_NULL) {
			VM_PAGE_WAIT();
		}
	}
	assert(m);
	vm_object_lock(backing_object);
	vm_page_insert(m, backing_object, 0);
	vm_object_unlock(backing_object);
	/* make it back another object */
	object = vm_object_allocate(size, VM_MAP_SERIAL_NONE);
	assert(object);
	vm_object_reference(object);
	object->shadow = backing_object;
	vm_object_reference(backing_object);
	/* trigger a bypass */
	vm_object_lock(object);
	vm_object_collapse(object, 0, TRUE);
	/* check that it did not bypass the backing object */
	if (object->shadow != backing_object) {
		panic("%s:%d FAIL\n", __FUNCTION__, __LINE__);
	}
	vm_object_unlock(object);

	/* remove the page from the backing object */
	vm_object_lock(backing_object);
	vm_page_remove(m);
	vm_object_unlock(backing_object);
	/* trigger a bypass */
	vm_object_lock(object);
	vm_object_collapse(object, 0, TRUE);
	/* check that it did bypass the backing object */
	if (object->shadow == backing_object) {
		panic("%s:%d FAIL\n", __FUNCTION__, __LINE__);
	}
	vm_page_insert(m, object, 0);
	vm_object_unlock(object);

	/* cleanup */
	vm_object_deallocate(object);
	/* "backing_object" already lost its reference during the bypass */
//	vm_object_deallocate(backing_object);

	printf("%s:%d PASS\n", __FUNCTION__, __LINE__);
}

__attribute__((noinline))
static void
vm_test_physical_size_overflow(void)
{
	vm_map_address_t start;
	mach_vm_size_t size;
	kern_return_t kr;
	mach_vm_size_t phys_size;
	bool fail;
	int failures = 0;

	/* size == 0 */
	start = 0x100000;
	size = 0x0;
	kr = vm_map_range_physical_size(kernel_map,
	    start,
	    size,
	    &phys_size);
	fail = (kr != KERN_SUCCESS || phys_size != 0);
	printf("%s:%d %s start=0x%llx size=0x%llx -> kr=%d phys_size=0x%llx\n",
	    __FUNCTION__, __LINE__,
	    (fail ? "FAIL" : "PASS"),
	    (uint64_t)start, size, kr, phys_size);
	failures += fail;

	/* plain wraparound */
	start = 0x100000;
	size = 0xffffffffffffffff - 0x10000;
	kr = vm_map_range_physical_size(kernel_map,
	    start,
	    size,
	    &phys_size);
	fail = (kr != KERN_INVALID_ARGUMENT || phys_size != 0);
	printf("%s:%d %s start=0x%llx size=0x%llx -> kr=%d phys_size=0x%llx\n",
	    __FUNCTION__, __LINE__,
	    (fail ? "FAIL" : "PASS"),
	    (uint64_t)start, size, kr, phys_size);
	failures += fail;

	/* wraparound after rounding */
	start = 0xffffffffffffff00;
	size = 0xf0;
	kr = vm_map_range_physical_size(kernel_map,
	    start,
	    size,
	    &phys_size);
	fail = (kr != KERN_INVALID_ARGUMENT || phys_size != 0);
	printf("%s:%d %s start=0x%llx size=0x%llx -> kr=%d phys_size=0x%llx\n",
	    __FUNCTION__, __LINE__,
	    (fail ? "FAIL" : "PASS"),
	    (uint64_t)start, size, kr, phys_size);
	failures += fail;

	/* wraparound to start after rounding */
	start = 0x100000;
	size = 0xffffffffffffffff;
	kr = vm_map_range_physical_size(kernel_map,
	    start,
	    size,
	    &phys_size);
	fail = (kr != KERN_INVALID_ARGUMENT || phys_size != 0);
	printf("%s:%d %s start=0x%llx size=0x%llx -> kr=%d phys_size=0x%llx\n",
	    __FUNCTION__, __LINE__,
	    (fail ? "FAIL" : "PASS"),
	    (uint64_t)start, size, kr, phys_size);
	failures += fail;

	if (failures) {
		panic("%s: FAIL (failures=%d)", __FUNCTION__, failures);
	}
	printf("%s: PASS\n", __FUNCTION__);
}

#define PTR_UPPER_SHIFT 60
#define PTR_TAG_SHIFT 56
#define PTR_BITS_MASK (((1ULL << PTR_TAG_SHIFT) - 1) | (0xfULL << PTR_UPPER_SHIFT))

#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
static inline vm_map_t
create_map(mach_vm_address_t map_start, mach_vm_address_t map_end, int pageshift);

static inline void
cleanup_map(vm_map_t *map);
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */

__attribute__((noinline))
static void
vm_test_address_canonicalization(void)
{
#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
	kern_return_t kr;
	mach_vm_address_t kernel_addr, user_addr;
	mach_vm_address_t canonicalized_addr;
	mach_vm_address_t intended_result;
	vm_address_t const tag = 0x5;
	T_SETUPBEGIN;
	T_LOG("%s: Allocating an address in the kernel map", __func__);
	kr = mach_vm_allocate(kernel_map, &kernel_addr, PAGE_SIZE, VM_FLAGS_ANYWHERE);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "mach_vm_allocate in kernel map");
	T_LOG("%s: Allocated kernel addr: 0x%llx", __func__, kernel_addr);
	mach_vm_address_t const tagged_kernel_addr = (kernel_addr & PTR_BITS_MASK) |
	    (tag << PTR_TAG_SHIFT);
	T_LOG("%s: Tagged kernel address: 0x%llx", __func__, tagged_kernel_addr);

	/* Create userland VM map and vm allocate an address from there */
	vm_map_t user_map = create_map(MACH_VM_MIN_ADDRESS, MACH_VM_MAX_ADDRESS, PAGE_SHIFT);
	T_ASSERT_NOTNULL(user_map, "VM map creation");
	kr = mach_vm_allocate(user_map, &user_addr, PAGE_SIZE, VM_FLAGS_ANYWHERE);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "mach_vm_allocate in user map");
	T_LOG("%s: Allocated user address: 0x%llx", __func__, user_addr);
	mach_vm_address_t const tagged_user_addr = (user_addr & PTR_BITS_MASK) |
	    (tag << PTR_TAG_SHIFT);
	T_LOG("%s: Tagged user address: 0x%llx", __func__, tagged_user_addr);
	T_SETUPEND;

	T_BEGIN("VM address canonicalization test");
	/* canonicalize kernel address with kernel map */
	intended_result = kernel_addr;
	canonicalized_addr = (mach_vm_address_t)vm_memtag_canonicalize(kernel_map, tagged_kernel_addr);
	T_EXPECT_EQ_ULLONG(canonicalized_addr, intended_result,
	    "kernel address with kernel map: canonicalized kernel addr: 0x%llx, intended addr: 0x%llx",
	    canonicalized_addr, intended_result);

	/* canonicalize kernel address with user map */
	intended_result = (kernel_addr & PTR_BITS_MASK) | ((mach_vm_address_t)0x0 << PTR_TAG_SHIFT);
	canonicalized_addr = (mach_vm_address_t)vm_memtag_canonicalize(user_map, tagged_kernel_addr);
	T_EXPECT_EQ_ULLONG(canonicalized_addr, intended_result,
	    "kernel address with user map: canonicalized kernel addr: 0x%llx, intended addr: 0x%llx",
	    canonicalized_addr, intended_result);

	/* canonicalize user address with kernel map */
	intended_result = (user_addr & PTR_BITS_MASK) | ((mach_vm_address_t)0xf << PTR_TAG_SHIFT);
	canonicalized_addr = (mach_vm_address_t)vm_memtag_canonicalize(kernel_map, tagged_user_addr);
	T_EXPECT_EQ_ULLONG(canonicalized_addr, intended_result,
	    "user address with kernel map: canonicalized user addr: 0x%llx, intended addr: 0x%llx",
	    canonicalized_addr, intended_result);

	/* canonicalize user address with user map */
	intended_result = user_addr;
	canonicalized_addr = (mach_vm_address_t)vm_memtag_canonicalize(user_map, tagged_user_addr);
	T_EXPECT_EQ_ULLONG(canonicalized_addr, intended_result,
	    "user address with user map: canonicalized user addr: 0x%llx, intended addr: 0x%llx",
	    canonicalized_addr, intended_result);
	cleanup_map(&user_map);
#else /* !HAS_MTE && !HAS_MTE_EMULATION_SHIMS */
	T_SKIP("System not designed to support this test, skipping...");
#endif /* !HAS_MTE && !HAS_MTE_EMULATION_SHIMS */
}


kern_return_t
vm_tests(void)
{
	kern_return_t kr = KERN_SUCCESS;

	/* Avoid VM panics because some of our test vm_maps don't have a pmap. */
	thread_test_context_t ctx CLEANUP_THREAD_TEST_CONTEXT = {
		.test_option_vm_map_allow_null_pmap = true,
	};
	thread_set_test_context(&ctx);

	vm_test_collapse_compressor();
	vm_test_wire_and_extract();
	vm_test_page_wire_overflow_panic();
	vm_test_kernel_object_fault();
	vm_test_device_pager_transpose();
#if MACH_ASSERT
	vm_test_map_copy_adjust_to_target();
#endif /* MACH_ASSERT */
#if PMAP_CREATE_FORCE_4K_PAGES && MACH_ASSERT
	vm_test_4k();
#endif /* PMAP_CREATE_FORCE_4K_PAGES && MACH_ASSERT */
#if __arm64__ && !KASAN
	vm_test_per_mapping_internal_accounting();
#endif /* __arm64__ && !KASAN */
	vm_test_kernel_tag_accounting();
	vm_test_collapse_overflow();
	vm_test_physical_size_overflow();
	vm_test_address_canonicalization();

	return kr;
}

#if MACH_ASSERT
static int
vm_startup_tests(__unused int64_t in, int64_t *out)
{
	kern_return_t kr = vm_tests();
	assert(kr == KERN_SUCCESS);
	*out = 1;
	return 0;
}
/* make the startup test also available as sysctl for systems that don't run it at startup */
SYSCTL_TEST_REGISTER(vm_startup_tests, vm_startup_tests);
#endif /* MACH_ASSERT */

static inline vm_map_t
create_map(mach_vm_address_t map_start, mach_vm_address_t map_end, int pageshift)
{
	ledger_t ledger = ledger_instantiate(&task_ledger_template);
	pmap_t pmap = pmap_create_options(ledger, 0, PMAP_CREATE_64BIT);
	assert(pmap);
	ledger_dereference(ledger);  // now retained by pmap
	vm_map_t map = vm_map_create_with_page_shift(pmap, map_start, map_end,
	    pageshift, VM_MAP_CREATE_DEFAULT);//vm_compute_max_offset
	assert(map);

#if CONFIG_SPTM
	/* Ensure the map serial looks fine */
	if (map->serial_id != pmap->associated_vm_map_serial_id) {
		panic("Expected a map and its pmap to have exactly the same serial");
	}
#endif /* CONFIG_SPTM */

	return map;
}

static inline void
cleanup_map(vm_map_t *map)
{
	assert(*map);
	kern_return_t kr = vm_map_terminate(*map);
	assert(kr == 0);
	vm_map_deallocate(*map);  // also destroys pmap
}

kern_return_t
mach_vm_remap_new_external(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         size,
	mach_vm_offset_ut       mask,
	int                     flags,
	mach_port_t             src_tport,
	mach_vm_offset_ut       memory_address,
	boolean_t               copy,
	vm_prot_ut             *cur_protection_u,
	vm_prot_ut             *max_protection_u,
	vm_inherit_ut           inheritance);
kern_return_t
vm_remap_new_external(
	vm_map_t                target_map,
	vm_offset_ut           *address,
	vm_size_ut              size,
	vm_offset_ut            mask,
	int                     flags,
	mach_port_t             src_tport,
	vm_offset_ut            memory_address,
	boolean_t               copy,
	vm_prot_ut             *cur_protection,
	vm_prot_ut             *max_protection,
	vm_inherit_ut           inheritance);
kern_return_t
mach_vm_remap_external(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         size,
	mach_vm_offset_ut       mask,
	int                     flags,
	vm_map_t                src_map,
	mach_vm_offset_ut       memory_address,
	boolean_t               copy,
	vm_prot_ut             *cur_protection,
	vm_prot_ut             *max_protection,
	vm_inherit_ut           inheritance);
kern_return_t
mach_vm_map_external(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         initial_size,
	mach_vm_offset_ut       mask,
	int                     flags,
	ipc_port_t              port,
	memory_object_offset_ut offset,
	boolean_t               copy,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	vm_inherit_ut           inheritance);
kern_return_t
mach_vm_wire_external(
	host_priv_t             host_priv,
	vm_map_t                map,
	mach_vm_address_ut      start,
	mach_vm_size_ut         size,
	vm_prot_ut              access);
kern_return_t
mach_vm_purgable_control_external(
	mach_port_t             target_tport,
	mach_vm_offset_ut       address_u,
	vm_purgable_t           control,
	int                    *state);
kern_return_t
vm_purgable_control_external(
	mach_port_t             target_tport,
	vm_offset_ut            address,
	vm_purgable_t           control,
	int                     *state);

static int
vm_map_null_tests(__unused int64_t in, int64_t *out)
{
	kern_return_t kr;

	mach_vm_address_t alloced_addr, throwaway_addr;
	mach_vm_address_ut throwaway_addr_ut;
	vm_address_t vm_throwaway_addr;
	vm_address_ut vm_throwaway_addr_ut;
	vm32_address_ut alloced_addr32, throwaway_addr32_u;
	mach_vm_size_t throwaway_size, size_16kb, read_overwrite_data_size;
	vm_size_t vm_size, vm_read_overwrite_data_size, vm_throwaway_size;
	vm_size_ut throwaway_size_ut;
	vm32_size_t data_size32, size32_16kb;
	vm32_size_ut data_size32_u, throwaway_size32_u;
	mach_msg_type_number_t read_data_size;
	mach_port_t mem_entry_result;
	pointer_t read_data;
	pointer_ut read_data_u;
	vm_prot_t prot_default;
	vm_prot_ut prot_allexec_u, prot_default_ut;
	vm_map_t map64, map32;
	vm_machine_attribute_val_t vm_throwaway_attr_val;
	vm_region_extended_info_data_t vm_throwaway_region_extended_info;
	vm_region_recurse_info_t vm_throwaway_region_recurse_info;
	vm_region_recurse_info_64_t vm_throwaway_region_recurse_info_64;
	int throwaway_state;
	uint32_t throwaway_depth;
	vm_page_info_t page_info;

	page_info = 0;
	throwaway_state = VM_PURGABLE_STATE_MAX;
	vm_throwaway_region_recurse_info_64 = 0;
	vm_throwaway_region_recurse_info = 0;
	vm_throwaway_attr_val = MATTR_VAL_OFF;

	map64 = create_map(0, vm_compute_max_offset(true), PAGE_SHIFT);
	map32 = create_map(0, vm_compute_max_offset(false), PAGE_SHIFT);

	prot_allexec_u = vm_sanitize_wrap_prot(VM_PROT_ALLEXEC);
	prot_default_ut = vm_sanitize_wrap_prot(VM_PROT_DEFAULT);
	prot_default = VM_PROT_DEFAULT;

	size_16kb = 16 * 1024;
	size32_16kb = (vm32_size_t) size_16kb;

	/*
	 * Allocate some address in the map, just so we can pass a valid looking address to functions so they don't
	 * return before checking VM_MAP_NULL
	 */
	kr = mach_vm_allocate(map64, &alloced_addr, size_16kb, VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);
	kr = vm32_vm_allocate(map32, &alloced_addr32, size32_16kb, VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);

	/*
	 * Call a bunch of MIG entrypoints with VM_MAP_NULL. The goal is to verify they check map != VM_MAP_NULL.
	 * There are no requirements put on the return, so don't assert kr. Just verify no crash occurs.
	 */
	throwaway_size = size_16kb;
	kr = _mach_make_memory_entry(VM_MAP_NULL, &throwaway_size, alloced_addr, VM_PROT_DEFAULT, &mem_entry_result, IPC_PORT_NULL);
	assert(kr != KERN_SUCCESS);
	throwaway_size32_u = vm32_sanitize_wrap_size(size32_16kb);
	kr = vm32_mach_make_memory_entry(VM_MAP_NULL, &throwaway_size32_u, alloced_addr32, VM_PROT_DEFAULT, &mem_entry_result, IPC_PORT_NULL);
	assert(kr != KERN_SUCCESS);
	throwaway_size_ut = vm_sanitize_wrap_size(size_16kb);
	kr = vm32_mach_make_memory_entry_64(VM_MAP_NULL, &throwaway_size_ut, alloced_addr, VM_PROT_DEFAULT, &mem_entry_result, IPC_PORT_NULL);
	assert(kr != KERN_SUCCESS);
	throwaway_size = size_16kb;
	kr = mach_make_memory_entry_64(VM_MAP_NULL, &throwaway_size, alloced_addr, VM_PROT_DEFAULT, &mem_entry_result, IPC_PORT_NULL);
	assert(kr != KERN_SUCCESS);
	vm_size = size_16kb;
	kr = mach_make_memory_entry(VM_MAP_NULL, &vm_size, alloced_addr, VM_PROT_DEFAULT, &mem_entry_result, IPC_PORT_NULL);
	assert(kr != KERN_SUCCESS);

	kr = mach_memory_object_memory_entry(HOST_NULL, true, size_16kb, VM_PROT_DEFAULT, MEMORY_OBJECT_NULL, &mem_entry_result);
	assert(kr != KERN_SUCCESS);
	kr = mach_memory_object_memory_entry_64(HOST_NULL, true, size_16kb, VM_PROT_DEFAULT, MEMORY_OBJECT_NULL, &mem_entry_result);
	assert(kr != KERN_SUCCESS);

	throwaway_addr = alloced_addr;
	kr = mach_vm_allocate(VM_MAP_NULL, &throwaway_addr, size_16kb, VM_FLAGS_ANYWHERE);
	assert(kr != KERN_SUCCESS);
	throwaway_addr32_u = alloced_addr32;
	kr = vm32_vm_allocate(VM_MAP_NULL, &throwaway_addr32_u, size32_16kb, VM_FLAGS_ANYWHERE);
	assert(kr != KERN_SUCCESS);
	kr = vm_allocate_external(VM_MAP_NULL, &vm_throwaway_addr, size_16kb, VM_FLAGS_ANYWHERE);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_deallocate(VM_MAP_NULL, alloced_addr, size_16kb);
	assert(kr != KERN_SUCCESS);
	kr = vm_deallocate(VM_MAP_NULL, alloced_addr, size_16kb);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_deallocate(VM_MAP_NULL, throwaway_addr32_u, size32_16kb);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_map(VM_MAP_NULL, &throwaway_addr, size_16kb, 0, VM_FLAGS_ANYWHERE, IPC_PORT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = mach_vm_map_external(VM_MAP_NULL, &throwaway_addr_ut, size_16kb, 0, VM_FLAGS_ANYWHERE, IPC_PORT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);

	vm_throwaway_addr = alloced_addr;
	kr = vm_map(VM_MAP_NULL, &vm_throwaway_addr, size_16kb, 0, VM_FLAGS_ANYWHERE, IPC_PORT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_map(VM_MAP_NULL, &throwaway_addr32_u, size32_16kb, 0, VM_FLAGS_ANYWHERE, IPC_PORT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_map_64(VM_MAP_NULL, &throwaway_addr32_u, size32_16kb, 0, VM_FLAGS_ANYWHERE, IPC_PORT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_remap(map64, &throwaway_addr, size_16kb, 0, VM_FLAGS_ANYWHERE, VM_MAP_NULL, 0, false, &prot_default, &prot_default, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = mach_vm_remap(VM_MAP_NULL, &throwaway_addr, size_16kb, 0, VM_FLAGS_ANYWHERE, map64, 0, false, &prot_default, &prot_default, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = mach_vm_remap_external(map64, &throwaway_addr_ut, size_16kb, 0, VM_FLAGS_ANYWHERE, VM_MAP_NULL, 0, false, &prot_default_ut, &prot_default_ut, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = mach_vm_remap_external(VM_MAP_NULL, &throwaway_addr_ut, size_16kb, 0, VM_FLAGS_ANYWHERE, map64, 0, false, &prot_default_ut, &prot_default_ut, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm_remap_external(map64, &vm_throwaway_addr, size_16kb, 0, VM_FLAGS_ANYWHERE, VM_MAP_NULL, 0, false, &prot_default, &prot_default, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm_remap_external(VM_MAP_NULL, &vm_throwaway_addr, size_16kb, 0, VM_FLAGS_ANYWHERE, map64, 0, false, &prot_default, &prot_default, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_remap(map32, &throwaway_addr32_u, size32_16kb, 0, VM_FLAGS_ANYWHERE, VM_MAP_NULL, 0, false, &prot_default_ut, &prot_default_ut, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_remap(VM_MAP_NULL, &throwaway_addr32_u, size32_16kb, 0, VM_FLAGS_ANYWHERE, map32, 0, false, &prot_default_ut, &prot_default_ut, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_remap_new_external(VM_MAP_NULL, &throwaway_addr_ut, size_16kb, 0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, false, &prot_default_ut, &prot_default_ut, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = mach_vm_remap_new_external(map64, &throwaway_addr_ut, size_16kb, 0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, false, &prot_default_ut, &prot_default_ut, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_remap_new_external(VM_MAP_NULL, &throwaway_addr_ut, size_16kb, 0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, false, &prot_allexec_u, &prot_allexec_u, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = mach_vm_remap_new_external(map64, &throwaway_addr_ut, size_16kb, 0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, false, &prot_allexec_u, &prot_allexec_u, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);

	kr = vm_remap_new_external(VM_MAP_NULL, &vm_throwaway_addr_ut, size_16kb, 0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, false, &prot_default_ut, &prot_default_ut, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm_remap_new_external(map64, &vm_throwaway_addr_ut, size_16kb, 0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, false, &prot_default_ut, &prot_default_ut, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_wire_external(host_priv_self(), VM_MAP_NULL, throwaway_addr_ut, size_16kb, VM_PROT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = mach_vm_wire_external(HOST_PRIV_NULL, map64, throwaway_addr_ut, size_16kb, VM_PROT_DEFAULT);
	assert(kr != KERN_SUCCESS);

	kr = vm_wire(host_priv_self(), VM_MAP_NULL, throwaway_addr, size_16kb, VM_PROT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm_wire(HOST_PRIV_NULL, map64, throwaway_addr, size_16kb, VM_PROT_DEFAULT);
	assert(kr != KERN_SUCCESS);

	kr = task_wire(VM_MAP_NULL, false);
	assert(kr != KERN_SUCCESS);
	kr = vm32_task_wire(VM_MAP_NULL, false);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_read(VM_MAP_NULL, alloced_addr, size_16kb, &read_data, &read_data_size);
	assert(kr != KERN_SUCCESS);
	kr = vm_read(VM_MAP_NULL, alloced_addr, size_16kb, &read_data, &read_data_size);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_read(VM_MAP_NULL, alloced_addr32, size32_16kb, &read_data_u, &data_size32);
	assert(kr != KERN_SUCCESS);

	mach_vm_read_entry_t * mach_re = kalloc_type(mach_vm_read_entry_t, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	(*mach_re)[0].address = alloced_addr;
	(*mach_re)[0].size = size_16kb;

	vm_read_entry_t * re = kalloc_type(vm_read_entry_t, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	(*re)[0].address = alloced_addr;
	(*re)[0].size = (vm_size_t) size_16kb;

	vm32_read_entry_t * re_32 = kalloc_type(vm32_read_entry_t, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	(*re_32)[0].address = (vm32_address_t) alloced_addr;
	(*re_32)[0].size = (vm32_size_t) size_16kb;

	kr = mach_vm_read_list(VM_MAP_NULL, *mach_re, 1);
	assert(kr != KERN_SUCCESS);
	kr = vm_read_list(VM_MAP_NULL, *re, 1);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_read_list(VM_MAP_NULL, *re_32, 1);
	assert(kr != KERN_SUCCESS);

	kfree_type(mach_vm_read_entry_t, mach_re);
	kfree_type(vm_read_entry_t, re);
	kfree_type(vm32_read_entry_t, re_32);

	kr = mach_vm_read_overwrite(VM_MAP_NULL, alloced_addr, size_16kb, alloced_addr, &read_overwrite_data_size);
	assert(kr != KERN_SUCCESS);
	kr = vm_read_overwrite(VM_MAP_NULL, alloced_addr, size_16kb, alloced_addr, &vm_read_overwrite_data_size);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_read_overwrite(VM_MAP_NULL, alloced_addr32, size32_16kb, alloced_addr32, &data_size32_u);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_copy(VM_MAP_NULL, alloced_addr, size_16kb, alloced_addr);
	assert(kr != KERN_SUCCESS);
	kr = vm_copy(VM_MAP_NULL, alloced_addr, size_16kb, alloced_addr);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_copy(VM_MAP_NULL, alloced_addr32, size32_16kb, alloced_addr32);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_write(VM_MAP_NULL, alloced_addr, alloced_addr, (mach_msg_type_number_t) size_16kb);
	assert(kr != KERN_SUCCESS);
	kr = vm_write(VM_MAP_NULL, alloced_addr, alloced_addr, (mach_msg_type_number_t) size_16kb);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_write(VM_MAP_NULL, alloced_addr32, alloced_addr, (mach_msg_type_number_t) size_16kb);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_inherit(VM_MAP_NULL, alloced_addr, size_16kb, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm_inherit(VM_MAP_NULL, alloced_addr, size_16kb, VM_INHERIT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_inherit(VM_MAP_NULL, alloced_addr32, size32_16kb, VM_INHERIT_DEFAULT);

	kr = mach_vm_protect(VM_MAP_NULL, alloced_addr, size_16kb, FALSE, VM_PROT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm_protect(VM_MAP_NULL, alloced_addr, size_16kb, FALSE, VM_PROT_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_protect(VM_MAP_NULL, alloced_addr32, size32_16kb, FALSE, VM_PROT_DEFAULT);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_behavior_set(VM_MAP_NULL, alloced_addr, size_16kb, VM_BEHAVIOR_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm_behavior_set(VM_MAP_NULL, alloced_addr, size_16kb, VM_BEHAVIOR_DEFAULT);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_behavior_set(VM_MAP_NULL, alloced_addr32, size32_16kb, VM_BEHAVIOR_DEFAULT);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_msync(VM_MAP_NULL, alloced_addr, size_16kb, VM_SYNC_ASYNCHRONOUS);
	assert(kr != KERN_SUCCESS);
	kr = vm_msync(VM_MAP_NULL, alloced_addr, size_16kb, VM_SYNC_ASYNCHRONOUS);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_msync(VM_MAP_NULL, alloced_addr32, size32_16kb, VM_SYNC_ASYNCHRONOUS);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_machine_attribute(VM_MAP_NULL, alloced_addr, size_16kb, MATTR_CACHE, &vm_throwaway_attr_val);
	assert(kr != KERN_SUCCESS);
	kr = vm_machine_attribute(VM_MAP_NULL, alloced_addr, size_16kb, MATTR_CACHE, &vm_throwaway_attr_val);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_machine_attribute(VM_MAP_NULL, alloced_addr32, size32_16kb, MATTR_CACHE, &vm_throwaway_attr_val);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_purgable_control_external(MACH_PORT_NULL, throwaway_addr_ut, VM_PURGABLE_PURGE_ALL, &throwaway_state);
	assert(kr != KERN_SUCCESS);
	kr = vm_purgable_control_external(MACH_PORT_NULL, throwaway_addr_ut, VM_PURGABLE_PURGE_ALL, &throwaway_state);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_purgable_control(VM_MAP_NULL, alloced_addr32, VM_PURGABLE_PURGE_ALL, &throwaway_state);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_region(VM_MAP_NULL, &throwaway_addr, &throwaway_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&vm_throwaway_region_extended_info, &read_data_size, &mem_entry_result);
	assert(kr != KERN_SUCCESS);
	kr = vm_region(VM_MAP_NULL, &vm_throwaway_addr, &vm_throwaway_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&vm_throwaway_region_extended_info, &read_data_size, &mem_entry_result);
	assert(kr != KERN_SUCCESS);
	kr = vm_region_64(VM_MAP_NULL, &vm_throwaway_addr, &vm_throwaway_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&vm_throwaway_region_extended_info, &read_data_size, &mem_entry_result);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_region(VM_MAP_NULL, &throwaway_addr32_u, &throwaway_size32_u, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&vm_throwaway_region_extended_info, &read_data_size, &mem_entry_result);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_region_64(VM_MAP_NULL, &throwaway_addr32_u, &throwaway_size32_u, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&vm_throwaway_region_extended_info, &read_data_size, &mem_entry_result);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_region_recurse(VM_MAP_NULL, &throwaway_addr, &throwaway_size, &throwaway_depth, vm_throwaway_region_recurse_info, &read_data_size);
	assert(kr != KERN_SUCCESS);
	kr = vm_region_recurse(VM_MAP_NULL, &vm_throwaway_addr, &vm_throwaway_size, &throwaway_depth, vm_throwaway_region_recurse_info, &read_data_size);
	assert(kr != KERN_SUCCESS);
	kr = vm_region_recurse_64(VM_MAP_NULL, &vm_throwaway_addr, &vm_throwaway_size, &throwaway_depth, vm_throwaway_region_recurse_info_64, &read_data_size);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_region_recurse(VM_MAP_NULL, &throwaway_addr32_u, &throwaway_size32_u, &throwaway_depth, vm_throwaway_region_recurse_info, &read_data_size);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_region_recurse_64(VM_MAP_NULL, &throwaway_addr32_u, &throwaway_size32_u, &throwaway_depth, vm_throwaway_region_recurse_info_64, &read_data_size);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_page_info(VM_MAP_NULL, alloced_addr, VM_PAGE_INFO_BASIC, page_info, &read_data_size);
	assert(kr != KERN_SUCCESS);
	kr = mach_vm_page_query(VM_MAP_NULL, alloced_addr, &throwaway_state, &throwaway_state);
	assert(kr != KERN_SUCCESS);
	kr = vm_map_page_query(VM_MAP_NULL, vm_throwaway_addr, &throwaway_state, &throwaway_state);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_map_page_query(VM_MAP_NULL, throwaway_addr32_u, &throwaway_state, &throwaway_state);
	assert(kr != KERN_SUCCESS);

	kr = mach_vm_reallocate(VM_MAP_NULL, alloced_addr, size_16kb, &throwaway_addr, 2 * size_16kb, 0, VM_BEHAVIOR_DEFAULT, VM_FLAGS_ANYWHERE);
	assert(kr != KERN_SUCCESS);
	kr = vm_reallocate(VM_MAP_NULL, alloced_addr, size_16kb, (vm_address_t *)&throwaway_addr, 2 * size_16kb, 0, VM_BEHAVIOR_DEFAULT, VM_FLAGS_ANYWHERE);
	assert(kr != KERN_SUCCESS);
	kr = vm32_vm_reallocate(VM_MAP_NULL, alloced_addr32, size32_16kb, &throwaway_addr32_u, 2 * size32_16kb, 0, VM_BEHAVIOR_DEFAULT, VM_FLAGS_ANYWHERE);
	assert(kr != KERN_SUCCESS);

	/*
	 * Cleanup our allocations and maps
	 */
	kr = mach_vm_deallocate(map64, alloced_addr, size_16kb);
	assert(kr == KERN_SUCCESS);
	kr = vm32_vm_deallocate(map32, alloced_addr32, size32_16kb);
	assert(kr == KERN_SUCCESS);

	cleanup_map(&map64);
	cleanup_map(&map32);

	/*
	 * If we made it far without crashing, the test works.
	 */

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_null, vm_map_null_tests);

#if HAS_MTE
static unsigned int const MTE_GRANULE_SIZE = 16;

static inline unsigned int
extract_mte_tag(void *ptr)
{
	/* TODO: Eventually refactor this symbol entirely */
	return vm_memtag_extract_tag((vm_offset_t)ptr);
}
#endif /* HAS_MTE */

static int
vm_map_copyio_test(__unused int64_t in, int64_t *out)
{
#if HAS_MTE
	T_SETUPBEGIN;
	uint64_t const test_buf_size = (32 * 1024) + 1; /* 32K + 1 */

	/* Allocate a tagged kernel buffer to copy from */
	vm_offset_t kern_addr;
	kern_return_t kr = kmem_alloc(
		kernel_map,
		&kern_addr,
		test_buf_size,
		KMA_ZERO | KMA_TAG | KMA_KOBJECT, VM_KERN_MEMORY_DIAG);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "kmem_alloc(KMA_TAG) - allocate an MTE enabled page");
	char *tagged_ptr = (char *)kern_addr;
	T_ASSERT_NOTNULL(tagged_ptr, "kmem_alloc(KMA_TAG) ptr not null");
	unsigned int tag = extract_mte_tag(tagged_ptr);
	T_LOG("Allocated ptr: %p, tag assigned: %zx", tagged_ptr, tag);

	/* Put some data in the kernel buffer */
	for (size_t i = 0; i < test_buf_size; ++i) {
		tagged_ptr[i] = (char)i;
	}
	T_SETUPEND;

	T_BEGIN("vm_map_copy test");
	/* Do a vm_map_copyin from a kernel buffer */
	vm_map_address_ut tagged_ptr_u;
	vm_map_size_ut len_u;
	vm_map_copy_t copy;
	VM_SANITIZE_UT_SET(tagged_ptr_u, (vm_map_address_t)tagged_ptr);
	VM_SANITIZE_UT_SET(len_u, msg_ool_size_small);
	kr = vm_map_copyin(kernel_map, tagged_ptr_u, len_u, false, &copy);
	T_EXPECT_EQ_INT(kr, KERN_SUCCESS, "vm_map_copyin on 32K");

	/* Do a vm_map_copyout into this process's address space */
	vm_map_address_t dst_addr;
	kr = vm_map_copyout(kernel_map, &dst_addr, copy);
	T_EXPECT_EQ_INT(kr, KERN_SUCCESS, "vm_map_copyout");

	/* Make sure we read back the same data */
	char *dst_ptr = (char *)dst_addr;
	T_LOG("dst_ptr: %p", dst_ptr);
	int ret = memcmp(tagged_ptr, dst_ptr, msg_ool_size_small);
	T_EXPECT_EQ_INT(0, ret, "memcmp");

	/* Do a vm_map_copyin that's > msg_ool_size_small, should fail */
	vm_map_size_ut len_large_u;
	VM_SANITIZE_UT_SET(len_large_u, test_buf_size);
	kr = vm_map_copyin(kernel_map, tagged_ptr_u, len_large_u, false, &copy);
	T_EXPECT_EQ_INT(kr, KERN_NOT_SUPPORTED, "vm_map_copyin on 32K+1");

	/* Clean up */
	kmem_free(kernel_map, kern_addr, test_buf_size, KMF_TAG);
	T_END;
	*out = 1;
#else /* !HAS_MTE */
	/* Test is not supported */
	*out = ENOTSUP;
#endif /* HAS_MTE */
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_copyio, vm_map_copyio_test);

static int
vm_page_relocate_test(__unused int64_t in, int64_t *out)
{
#if HAS_MTE
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);
	vm_map_t map = current_map();

	/* `in` will contain the address of the memory we have written to */
	vm_map_entry_t entry = NULL;
	vm_map_offset_t tagged_addr = (vm_map_offset_t)in;
	vm_map_offset_t canonical_addr = vm_memtag_canonicalize(map, tagged_addr);

	vm_page_t m = VM_PAGE_NULL;
	vm_object_t object = VM_OBJECT_NULL;
	ppnum_t old_phys_page = 0;
	kern_return_t kr;
	while (true) {
		if (!pmap_find_phys(map->pmap, canonical_addr)) {
			/*
			 * There's no physical page associated with the memory;
			 * we need to fault it in
			 */
			/* Fault in the page with the data we care about */
			kr = vm_fault(
				map,
				tagged_addr,
				VM_PROT_WRITE,
				FALSE, /* change_wiring */
				VM_KERN_MEMORY_NONE,
				THREAD_INTERRUPTIBLE, /* interruptible */
				NULL, /* caller pmap */
				0);
			T_EXPECT_EQ_INT(kr, 0, "vm_fault");
		}

		/* Look up page */
		kr = vm_map_find_entry_sh_locked(ctx, &map, canonical_addr, VMRL_FIND_SH_DEFAULT);
		T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_find_entry_sh_locked");
		entry = vm_map_found_entry_get_entry(ctx);
		object = VME_OBJECT(entry);
		T_ASSERT_NOTNULL(object, "vm object should not be null");
		vm_object_lock(object);
		/* There shouldn't be a shadow chain for MTE objects */
		T_ASSERT_EQ_INT(object->shadowed, FALSE, "vm object should not have a shadow");
		m = vm_page_lookup(
			object,
			(VME_OFFSET(entry) + (canonical_addr - entry->vme_start)));
		old_phys_page = VM_PAGE_GET_PHYS_PAGE(m);
		T_QUIET; T_ASSERT_NE_UINT(old_phys_page, 0, "physical page should not be 0");
		T_LOG("old physical page: 0x%x, vm_page_t: 0x%llx", old_phys_page, m);
		if (m != VM_PAGE_NULL) {
			break;
		}
		vm_object_unlock(object);
		vm_map_found_entry_sh_unlock(ctx, &map);
	}
	vm_object_lock_assert_held(object);
	int compressed_pages = 0;
	vm_page_lock_queues();
	kr = vm_page_relocate(m, &compressed_pages, VM_RELOCATE_REASON_CONTIGUOUS, NULL);
	vm_page_unlock_queues();
	T_EXPECT_EQ_INT(kr, 0, "vm_page_relocate");
	vm_page_t new_m = vm_page_lookup(
		object,
		(VME_OFFSET(entry) + (canonical_addr - entry->vme_start)));
	T_EXPECT_NOTNULL(new_m, "new VM page is not null");
	ppnum_t new_phys_page = VM_PAGE_GET_PHYS_PAGE(new_m);
	T_LOG("ppnum of relocated page: %u", new_phys_page);
	T_EXPECT_NE_UINT(old_phys_page, new_phys_page,
	    "old and new physical pages should be different");
	vm_object_unlock(object);
	vm_map_found_entry_sh_unlock(ctx, &map);

	/* There shouldn't be a PTE associated with addr at the moment */
	ppnum_t phys_page = pmap_find_phys(map->pmap, canonical_addr);
	T_EXPECT_EQ_UINT(phys_page, 0, "pmap_find_phys should return 0");

	/* Kernel touches the page, faulting in new page if not already resident */
	char c = 'b';
	int result = copyout((void *)&c, (user_addr_t)tagged_addr, sizeof(c));
	T_EXPECT_EQ_INT(result, 0, "copyout %c to 0x%llx", c, tagged_addr);
	c = 'c';
	result = copyout((void *)&c, (user_addr_t)(canonical_addr + MTE_GRANULE_SIZE), sizeof(c));
	T_EXPECT_EQ_INT(result, 0, "copyout %c to 0x%llx", c, (canonical_addr + MTE_GRANULE_SIZE));

	/* There should be a physical page now */
	phys_page = pmap_find_phys(map->pmap, canonical_addr);
	T_EXPECT_NE_UINT(phys_page, 0,
	    "there's a PTE for 0x%llx after writing to it, phys_page: 0x%x",
	    canonical_addr, phys_page);
	*out = 1;
#else /* !HAS_MTE */
	/* Test is not supported */
	*out = ENOTSUP;
#endif /* HAS_MTE */
	return 0;
}
SYSCTL_TEST_REGISTER(vm_page_relocate, vm_page_relocate_test);

#define PAGE_SHIFT_4K 12
#define PAGE_SHIFT_16K 14
static int
vm_map_copy_entry_subrange_test(__unused int64_t in, int64_t *out)
{
	mach_vm_size_t size_4kb, size_16kb;
	vm_map_t map_4k, map_16k;
	mach_vm_address_t alloced_addr, mapped_addr;
	mach_vm_size_t entry_size;
	mach_port_t entry_handle;
	mach_vm_size_t mapped_size;
	vm_region_basic_info_data_64_t region_info;
	mach_msg_type_number_t region_info_count;

	kern_return_t kr;

	size_4kb = 4 * 1024;
	size_16kb = 16 * 1024;

	map_4k = create_map(0, vm_compute_max_offset(true), PAGE_SHIFT_4K);
	map_16k = create_map(0, vm_compute_max_offset(true), PAGE_SHIFT_16K);

	/*
	 * Test mapping a portion of a copy entry from a 4k map to a 16k one.
	 * The result size should be aligned to the destination's page size (16k).
	 */
	// Get a copy entry to map into the system
	kr = mach_vm_allocate(map_4k, &alloced_addr, size_16kb, VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);

	entry_size = size_16kb;
	kr = mach_make_memory_entry_64(map_4k, &entry_size, alloced_addr,
	    MAP_MEM_VM_COPY | MAP_MEM_USE_DATA_ADDR | VM_PROT_DEFAULT,
	    &entry_handle, MACH_PORT_NULL);
	assert(kr == KERN_SUCCESS);
	assert(entry_size == size_16kb);

	// Attempt to map a portion of the entry into the 16k map
	kr = mach_vm_map(map_16k, &mapped_addr, size_4kb, 0, VM_FLAGS_ANYWHERE,
	    entry_handle, 0, true, VM_PROT_DEFAULT, VM_PROT_DEFAULT,
	    VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);

	// Ensure the entry is actually mapped whole
	region_info_count = VM_REGION_BASIC_INFO_COUNT_64;
	kr = mach_vm_region(map_16k, &mapped_addr, &mapped_size, VM_REGION_BASIC_INFO_64,
	    (vm_region_info_t) &region_info, &region_info_count, NULL);
	assert(kr == KERN_SUCCESS);
	assert(mapped_size == entry_size);

	// Cleanup
	mach_memory_entry_port_release(entry_handle);
	kr = mach_vm_deallocate(map_16k, mapped_addr, size_16kb);
	assert(kr == KERN_SUCCESS);
	kr = mach_vm_deallocate(map_4k, alloced_addr, size_16kb);
	assert(kr == KERN_SUCCESS);
	cleanup_map(&map_4k);
	cleanup_map(&map_16k);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_copy_entry_subrange, vm_map_copy_entry_subrange_test);


static int
vm_memory_entry_map_size_null_test(__unused int64_t in, int64_t *out)
{
	mach_vm_size_t size_16kb, map_size;
	vm_map_t map;

	kern_return_t kr;

	map = create_map(0, vm_compute_max_offset(true), PAGE_SHIFT);
	size_16kb = 16 * 1024;

	map_size = 0xdeadbeef;
	kr = mach_memory_entry_map_size(MACH_PORT_NULL, map, 0, size_16kb, &map_size);
	assert(kr == KERN_INVALID_ARGUMENT);
	assert(map_size == 0);

	cleanup_map(&map);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_memory_entry_map_size_null, vm_memory_entry_map_size_null_test);

static int
vm_memory_entry_map_size_overflow_tests(__unused int64_t in, int64_t *out)
{
	mach_vm_size_t size_16kb, entry_size, map_size;
	vm_map_t map;
	mach_port_t parent_handle, entry_handle;
	mach_vm_address_t alloced_addr;
	vm_map_offset_t entry_offset;
	memory_object_offset_t maximum_offset;

	kern_return_t kr;

	size_16kb = 16 * 1024;
	map = create_map(0, vm_compute_max_offset(true), PAGE_SHIFT);
	/*
	 * (1) Attempt to overflow offset + mem_entry->offset
	 */
	// Setup - create an entry with nonzero offset
	kr = mach_memory_object_memory_entry_64((host_t) 1, 1,
	    size_16kb * 2, VM_PROT_DEFAULT, 0, &parent_handle);
	assert(kr == KERN_SUCCESS);

	entry_size = size_16kb;
	kr = mach_make_memory_entry_64(map, &entry_size, size_16kb,
	    VM_PROT_DEFAULT, &entry_handle, parent_handle);
	assert(kr == KERN_SUCCESS);

	// Pass in maximum offset to attempt overflow
	maximum_offset = (memory_object_offset_t) -1;
	kr = mach_memory_entry_map_size(entry_handle, map, maximum_offset, size_16kb,
	    &map_size);
	assert(kr == KERN_INVALID_ARGUMENT);

	// Cleanup
	mach_memory_entry_port_release(parent_handle);
	mach_memory_entry_port_release(entry_handle);

	/*
	 * (2) Attempt to overflow offset + mem_entry->data_offset
	 */
	// Setup - create an entry with nonzero data_offset
	kr = mach_vm_allocate(map, &alloced_addr, 2 * size_16kb, VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);

	entry_size = size_16kb;
	entry_offset = alloced_addr + (size_16kb / 2);
	kr = mach_make_memory_entry_64(map, &entry_size, entry_offset,
	    MAP_MEM_VM_COPY | MAP_MEM_USE_DATA_ADDR | VM_PROT_DEFAULT,
	    &entry_handle, MACH_PORT_NULL);
	assert(kr == KERN_SUCCESS);

	// Pass in maximum offset to attempt overflow
	kr = mach_memory_entry_map_size(entry_handle, map, maximum_offset, size_16kb,
	    &map_size);
	assert(kr == KERN_INVALID_ARGUMENT);

	// Cleanup
	mach_memory_entry_port_release(entry_handle);
	kr = mach_vm_deallocate(map, alloced_addr, 2 * size_16kb);
	assert(kr == KERN_SUCCESS);
	cleanup_map(&map);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_memory_entry_map_size_overflow, vm_memory_entry_map_size_overflow_tests);

static int
vm_memory_entry_map_size_copy_tests(__unused int64_t in, int64_t *out)
{
	mach_vm_size_t size_2kb, size_4kb, size_16kb;
	mach_vm_size_t entry_size_4k, entry_size_16k;
	mach_vm_size_t map_size;
	vm_map_t map_4k, map_16k;
	mach_port_t entry_4k, entry_16k;
	mach_vm_address_t alloced_addr_4k, alloced_addr_16k;

	kern_return_t kr;

	size_2kb = 2 * 1024;
	size_4kb = 4 * 1024;
	size_16kb = 16 * 1024;

	/*
	 * Setup - initialize maps and create copy entries for each
	 */
	// 4k map and entry
	map_4k = create_map(0, vm_compute_max_offset(true), PAGE_SHIFT_4K);

	kr = mach_vm_allocate(map_4k, &alloced_addr_4k, size_16kb, VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);

	entry_size_4k = size_16kb;
	kr = mach_make_memory_entry_64(map_4k, &entry_size_4k, alloced_addr_4k,
	    MAP_MEM_VM_COPY | VM_PROT_DEFAULT, &entry_4k, MACH_PORT_NULL);
	assert(kr == KERN_SUCCESS);
	assert(entry_size_4k == size_16kb);

	// 16k map and entry
	map_16k = create_map(0, vm_compute_max_offset(true), PAGE_SHIFT_16K);

	kr = mach_vm_allocate(map_16k, &alloced_addr_16k, size_16kb, VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);

	entry_size_16k = size_16kb;
	kr = mach_make_memory_entry_64(map_16k, &entry_size_16k, alloced_addr_16k,
	    MAP_MEM_VM_COPY | VM_PROT_DEFAULT, &entry_16k, MACH_PORT_NULL);
	assert(kr == KERN_SUCCESS);
	assert(entry_size_16k == size_16kb);

	/*
	 * (1) Test 4k map with 4k entry and 16k map with 16k entry. Page-aligned
	 * ranges should have no size adjustment.
	 */
	for (mach_vm_size_t i = 1; i <= 4; i++) {
		kr = mach_memory_entry_map_size(entry_4k, map_4k, 0, i * size_4kb, &map_size);
		assert(kr == KERN_SUCCESS);
		assert(map_size == (i * size_4kb));
	}
	kr = mach_memory_entry_map_size(entry_16k, map_16k, 0, size_16kb, &map_size);
	assert(kr == KERN_SUCCESS);
	assert(map_size == size_16kb);

	/*
	 * (2) Test 4k map with 16k entry. Since we have a 4k map, we should be able
	 * to map a 4k range of the entry, but to map a 2k range we will need to map
	 * a full 4k page.
	 */
	kr = mach_memory_entry_map_size(entry_16k, map_4k, 0, size_16kb, &map_size);
	assert(kr == KERN_SUCCESS);
	assert(map_size == size_16kb);
	kr = mach_memory_entry_map_size(entry_16k, map_4k, 0, size_4kb, &map_size);
	assert(kr == KERN_SUCCESS);
	assert(map_size == size_4kb);
	kr = mach_memory_entry_map_size(entry_16k, map_4k, 0, size_2kb, &map_size);
	assert(kr == KERN_SUCCESS);
	assert(map_size == size_4kb);

	/*
	 * (3) Test 16k map with 4k entry. Since we have a 16k map, we will need to
	 * map the whole 16kb memory entry even if a smaller range is requested.
	 */
	kr = mach_memory_entry_map_size(entry_4k, map_16k, 0, size_16kb, &map_size);
	assert(kr == KERN_SUCCESS);
	assert(map_size == size_16kb);
	kr = mach_memory_entry_map_size(entry_4k, map_16k, 0, size_4kb, &map_size);
	assert(kr == KERN_SUCCESS);
	assert(map_size == size_16kb);
	kr = mach_memory_entry_map_size(entry_4k, map_16k, 0, size_2kb, &map_size);
	assert(kr == KERN_SUCCESS);
	assert(map_size == size_16kb);

	/*
	 * (4) Detect error in the case where the size requested is too large.
	 */
	map_size = 0xdeadbeef;
	kr = mach_memory_entry_map_size(entry_4k, map_16k, 0, 2 * size_16kb, &map_size);
	assert(kr == KERN_INVALID_ARGUMENT);
	assert(map_size == 0);

	/*
	 * Clean up memory entries, allocations, and maps
	 */
	mach_memory_entry_port_release(entry_4k);
	mach_memory_entry_port_release(entry_16k);
	kr = mach_vm_deallocate(map_4k, alloced_addr_4k, size_16kb);
	assert(kr == KERN_SUCCESS);
	kr = mach_vm_deallocate(map_16k, alloced_addr_16k, size_16kb);
	assert(kr == KERN_SUCCESS);
	cleanup_map(&map_4k);
	cleanup_map(&map_16k);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_memory_entry_map_size_copy, vm_memory_entry_map_size_copy_tests);

static int
vm_memory_entry_parent_submap_tests(__unused int64_t in, int64_t *out)
{
	vm_shared_region_t shared_region;
	mach_port_t parent_handle, entry_handle;
	vm_named_entry_t parent_entry;
	mach_vm_size_t entry_size;
	vm_prot_t vmflags;

	kern_return_t kr;

	/*
	 * Use shared region to get a named_entry which refers to a submap
	 */
	shared_region = vm_shared_region_get(current_task());
	parent_handle = shared_region->sr_mem_entry;
	assert(parent_handle != NULL);
	parent_entry = mach_memory_entry_from_port(parent_handle);
	assert(parent_entry->is_sub_map);

	/*
	 * We should be able to create an entry using the submap entry as the parent
	 */
	entry_size = parent_entry->size;
	vmflags = VM_PROT_DEFAULT;
	kr = mach_make_memory_entry_64(VM_MAP_NULL, &entry_size, 0, vmflags,
	    &entry_handle, parent_handle);
	assert(kr == KERN_SUCCESS);
	mach_memory_entry_port_release(entry_handle);

	/*
	 * Should fail if using mach_make_memory_entry_mem_only since the parent
	 * entry is not an object
	 */
	vmflags |= MAP_MEM_ONLY;
	kr = mach_make_memory_entry_64(VM_MAP_NULL, &entry_size, 0, vmflags,
	    &entry_handle, parent_handle);
	assert(kr == KERN_INVALID_ARGUMENT);

	/*
	 * Cleanup
	 */
	vm_shared_region_deallocate(shared_region);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_memory_entry_parent_submap, vm_memory_entry_parent_submap_tests);

static int
vm_cpu_map_pageout_test(int64_t in, int64_t *out)
{
#if HAS_MTE
	/*
	 * Since we now allow untagged kernel mappings of tagged user data, we want
	 * to be sure that the underlying physical page is always handled correctly.
	 *
	 * The following sequence may be of particular concern:
	 * 1. We create & populate an MTE userspace mapping
	 * 2. We create an untagged kernel mapping of the user tagged memory
	 * 3. The page is paged out
	 * 4. We fault in the kernel mapping (without first faulting on the user mapping)
	 *
	 * We want to be certain that in this case, we set the correct (MTE-enabled)
	 * cache attributes on the underlying physical page when we fault on our
	 * (non-MTE-enabled) kernel mapping.
	 */

	/* Get the tagged userspace mapping from the userspace side of the test */
	struct {
		mach_vm_size_t size;
		char *ptr;
		char value;
	} args;
	kern_return_t kr = copyin(in, &args, sizeof(args));
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "copyin arguments from userspace");

	/*
	 * Create an untagged kernel mapping of the user tagged memory.
	 */
	memory_object_size_ut size = vm_sanitize_wrap_size(args.size);
	memory_object_offset_t offset = (memory_object_offset_t)vm_memtag_canonicalize_user((vm_map_address_t)args.ptr);
	/*
	 * This path is specifically intended for IOMD::map(), so we pretend to be
	 * an IOKit caller to get the correct security policies.
	 */
	vm_named_entry_kernel_flags_t vmne_kflags = { .vmnekf_is_iokit = true };
	ipc_port_t memory_entry;
	kr = mach_make_memory_entry_internal(current_map(), &size, offset,
	    MAP_MEM_VM_SHARE | VM_PROT_DEFAULT, vmne_kflags, &memory_entry,
	    /* parent = */ MACH_PORT_NULL);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "make memory entry from tagged user memory");

	mach_vm_offset_t kernel_address = 0;
	kr = mach_vm_map_kernel(kernel_map, (mach_vm_offset_ut*)&kernel_address,
	    args.size, /* mask = */ 0,
	    /* IOMD mappings of user memory are bucketed into the shared data range */
	    VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmkf_range_id = KMEM_RANGE_ID_DATA_SHARED, .vmf_mte = true),
	    memory_entry,
	    /* offset = */ 0, /* copy = */ false, VM_PROT_DEFAULT, VM_PROT_DEFAULT,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "remap userspace memory into kernel");

	/* Validate that the mapping is correct and untagged: */
	assert(extract_mte_tag((void*)kernel_address) == 0xF);
	assert(extract_mte_tag(args.ptr) != 0xF);
	char *kernel_ptr = (char*)kernel_address;
	assert(kernel_ptr[0] == args.value);
	kernel_ptr[0]++;

	/* Force pageout */
	kr = vm_map_behavior_set(kernel_map, kernel_address,
	    kernel_address + args.size, VM_BEHAVIOR_PAGEOUT);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "force pageout of tagged mapping");

	/*
	 * Page in kernel mapping and validate cache attributes. Wire the memory
	 * first to ensure the mapping doesn't go away while we're doing checks on
	 * it.
	 */
	kr = vm_map_wire_kernel(kernel_map, kernel_address, kernel_address + args.size,
	    VM_PROT_READ | VM_PROT_WRITE, VM_KERN_MEMORY_DIAG, false);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "wire user-tagged memory");
	kernel_ptr[0]++;
	ppnum_t pn = vm_map_get_phys_page(kernel_map, kernel_address);
	assert(pn);
	T_ASSERT(pmap_is_tagged_page(pn), "page has MTE cache attribute");
	T_ASSERT(!pmap_is_tagged_mapping(vm_map_pmap(kernel_map), kernel_address), "kernel mapping is untagged");

	/* Now, fault in the user mapping... */
	kr = vm_fault(current_map(), offset, VM_PROT_READ | VM_PROT_WRITE,
	    /* change_wiring */ FALSE, VM_KERN_MEMORY_NONE, THREAD_ABORTSAFE,
	    /* caller_pmap */ NULL, /* caller_pmap_addr */ 0);

	/* ... and make sure everything still looks good */
	T_ASSERT(pmap_is_tagged_page(pn), "page retains MTE cache attribute");
	T_ASSERT(!pmap_is_tagged_mapping(vm_map_pmap(kernel_map), kernel_address), "kernel mapping remains untagged");
	T_ASSERT(pmap_is_tagged_mapping(vm_map_pmap(current_map()), offset), "user mapping is tagged");

	/* Cleanup */
	kr = vm_map_unwire(kernel_map, kernel_address, kernel_address + args.size, false);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "unwire user-tagged memory");
	kr = mach_vm_deallocate(kernel_map, kernel_address, args.size);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "remove kernel mapping");
	*out = 1;
#else /* HAS_MTE */
	/* Test is not supported */
	(void)in;
	*out = ENOTSUP;
#endif /* HAS_MTE */
	return 0;
}
SYSCTL_TEST_REGISTER(vm_cpu_map_pageout, vm_cpu_map_pageout_test);

static int
vm_get_wimg_mode(int64_t in, int64_t *out)
{
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;
	mach_vm_offset_t addr = (mach_vm_offset_t)in;
	vm_map_t map = current_map();

	kr = vm_map_find_entry_sh_locked(ctx, &map, addr, VMRL_FIND_SH_DEFAULT);
	if (kr != KERN_SUCCESS) {
		/* entry not found in map */
		return EINVAL;
	}

	vm_map_entry_t entry = vm_map_found_entry_get_entry(ctx);
	if (entry->is_sub_map) {
		vm_map_found_entry_sh_unlock(ctx, &map);
		return ENOTSUP;
	}

	*out = 0;
	vm_object_t obj = VME_OBJECT(entry);
	if (obj != VM_OBJECT_NULL) {
		*out = obj->wimg_bits;
	}

	vm_map_found_entry_sh_unlock(ctx, &map);
	return 0;
}
SYSCTL_TEST_REGISTER(vm_get_wimg_mode, vm_get_wimg_mode);

/*
 * Make sure copies from 4k->16k maps doesn't lead to address space holes
 */
static int
vm_map_4k_16k_test(int64_t in, int64_t *out)
{
#if PMAP_CREATE_FORCE_4K_PAGES
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	const mach_vm_size_t alloc_size = (36 * 1024);
	assert((alloc_size % FOURK_PAGE_SHIFT) == 0);
	assert((alloc_size % SIXTEENK_PAGE_SHIFT) != 0);
	assert(alloc_size > msg_ool_size_small); // avoid kernel buffer copy optimization

	/* initialize maps */
	pmap_t pmap_4k, pmap_16k;
	vm_map_t map_4k, map_16k;
	pmap_4k = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT | PMAP_CREATE_FORCE_4K_PAGES);
	assert(pmap_4k);
	map_4k = vm_map_create_with_page_shift(pmap_4k, MACH_VM_MIN_ADDRESS, MACH_VM_MAX_ADDRESS,
	    FOURK_PAGE_SHIFT, VM_MAP_CREATE_DEFAULT);
	assert(map_4k != VM_MAP_NULL);

	pmap_16k = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	assert(pmap_16k);
	map_16k = vm_map_create_with_page_shift(pmap_16k, MACH_VM_MIN_ADDRESS, MACH_VM_MAX_ADDRESS,
	    SIXTEENK_PAGE_SHIFT, VM_MAP_CREATE_DEFAULT);
	assert(map_16k != VM_MAP_NULL);
	assert(VM_MAP_PAGE_SHIFT(map_16k) == SIXTEENK_PAGE_SHIFT);

	/* create mappings in 4k map */
	/* allocate space */
	vm_address_t address_4k;
	kern_return_t kr = vm_allocate_external(map_4k, &address_4k, alloc_size, VM_FLAGS_ANYWHERE);
	assert3u(kr, ==, KERN_SUCCESS); /* reserve space for 4k entries in 4k map */

	/* overwrite with a bunch of 4k entries */
	for (mach_vm_address_t addr = address_4k; addr < (address_4k + alloc_size); addr += FOURK_PAGE_SIZE) {
		/* allocate 128MB objects, so that they don't get coalesced, preventing entry simplification */
		vm_object_t object = vm_object_allocate(ANON_CHUNK_SIZE, map_4k->serial_id);
		kr = vm_map_enter(map_4k, &addr, FOURK_PAGE_SIZE, /* mask */ 0,
		    VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = TRUE), object, /* offset */ 0,
		    /* copy */ false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
		assert3u(kr, ==, KERN_SUCCESS); /* overwrite the 4k chunk at addr with its own entry */
	}

	/* set up vm_map_copy_t */
	vm_map_copy_t copy;
	kr = vm_map_copyin(map_4k, address_4k, alloc_size, true, &copy);
	assert3u(kr, ==, KERN_SUCCESS); /* copyin from 4k map succeeds */

	/* write out the vm_map_copy_t to the 16k map */
	vm_address_t address_16k;
	if (in == 0) {
		/* vm_map_copyout */
		vm_map_address_t tmp_address;
		kr = vm_map_copyout(map_16k, &tmp_address, copy);
		assert3u(kr, ==, KERN_SUCCESS); /* copyout into 16k map suceeds */
		address_16k = (vm_address_t)tmp_address;
	} else if (in == 1) {
		/* vm_map_copy_overwrite */
		/* reserve space */
		kr = vm_allocate_external(map_16k, &address_16k, alloc_size, VM_FLAGS_ANYWHERE);
		assert3u(kr, ==, KERN_SUCCESS); /* reserve space in 16k map succeeds */

		/* do the overwrite */
		kr = vm_map_copy_overwrite(map_16k, address_16k, copy, alloc_size,
#if HAS_MTE
		    false,
#endif
		    true);
		assert3u(kr, ==, KERN_SUCCESS); /* copy_overwrite into 16k map succeds */
	} else {
		panic("invalid vm_map_4k_16k_test variant: %lld", in);
	}

	/* validate that everything is combined into one large 16k-aligned entry */
	mach_vm_size_t expected_size = VM_MAP_ROUND_PAGE(alloc_size, SIXTEENK_PAGE_MASK);
	kr = vm_map_find_entry_sh_locked(ctx, &map_16k, address_16k, VMRL_FIND_SH_DEFAULT);
	assert3u(kr, ==, KERN_SUCCESS); /* address_16k found in map_16k */
	vm_map_entry_t entry = vm_map_found_entry_get_entry(ctx);
	assert3u((entry->vme_end - entry->vme_start), ==, expected_size); /* 4k entries combined into a single 16k entry */
	vm_map_found_entry_sh_unlock(ctx, &map_16k);
#else /* !PMAP_CREATE_FORCE_4K_PAGES */
	(void)in;
#endif /* !PMAP_CREATE_FORCE_4K_PAGES */
	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_4k_16k, vm_map_4k_16k_test);


static void
vm_map_get_phys_page_test()
{
	kern_return_t kr;
	mach_vm_offset_t addr = 0;
	ppnum_t physpage;
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_t map = kernel_map;

	kr = mach_vm_allocate_kernel(map, (mach_vm_offset_ut *) &addr, PAGE_SIZE, VM_MAP_KERNEL_FLAGS_ANYWHERE());
	assert(kr == KERN_SUCCESS);

	/* wire the mapping */
	kr = vm_map_wire_kernel(map, addr, addr + PAGE_SIZE,
	    VM_PROT_DEFAULT, VM_KERN_MEMORY_DIAG, false);
	assert(kr == KERN_SUCCESS);

	kr = vm_map_range_sh_lock(ctx, &map, addr, addr + PAGE_SIZE, VMRL_SH_ATOMIC);
	assert(kr == KERN_SUCCESS);

	vm_map_entry_t entry = vm_map_range_atomic_next(ctx);
	assert(entry);

	vm_object_t object = VME_OBJECT(entry);

	vm_object_lock_shared(object);
	vm_page_t page = vm_page_lookup(object, VME_OFFSET(entry));
	assert(page->vmp_wire_count);
	physpage = VM_PAGE_GET_PHYS_PAGE(page);
	vm_object_unlock(object);

	vm_map_range_sh_unlock(ctx, &map);

	ppnum_t pn = vm_map_get_phys_page(map, addr);
	assert(pn == physpage);
}



static int
vm_misc_tests(int64_t in __unused, int64_t *out)
{
	vm_map_get_phys_page_test();
	*out = 1;
	return 0;
}

SYSCTL_TEST_REGISTER(vm_misc_tests, vm_misc_tests);


static int
vm_vector_upl_test(int64_t in, int64_t *out)
{
	extern upl_t vector_upl_create(vm_offset_t, uint32_t);
	extern boolean_t vector_upl_set_subupl(upl_t, upl_t, uint32_t);

	upl_t vector_upl = NULL;
	vm_address_t kva = 0;

	*out = 0;

	struct {
		uint64_t iov;
		uint16_t iovcnt;
	} args;

	struct {
		uint64_t base;
		uint32_t len;
	} *iov;

	size_t iovsize = 0;
	iov = NULL;

	int error = copyin((user_addr_t)in, &args, sizeof(args));
	if ((error != 0) || (args.iovcnt == 0)) {
		goto vector_upl_test_done;
	}

	iovsize = sizeof(*iov) * args.iovcnt;

	iov = kalloc_data(iovsize, Z_WAITOK_ZERO);
	if (iov == NULL) {
		error = ENOMEM;
		goto vector_upl_test_done;
	}

	error = copyin((user_addr_t)args.iov, iov, iovsize);
	if (error != 0) {
		goto vector_upl_test_done;
	}

	vector_upl = vector_upl_create(iov->base & PAGE_MASK, args.iovcnt);
	upl_size_t vector_upl_size = 0;

	/* Create each sub-UPL and append it to the top-level vector UPL. */
	for (uint16_t i = 0; i < args.iovcnt; i++) {
		upl_t subupl;
		upl_size_t upl_size = iov[i].len;
		unsigned int upl_count = 0;
		upl_control_flags_t upl_flags = UPL_SET_IO_WIRE | UPL_SET_LITE | UPL_WILL_MODIFY | UPL_SET_INTERNAL;
		kern_return_t kr = vm_map_create_upl(current_map(),
		    (vm_map_offset_t)iov[i].base,
		    &upl_size,
		    &subupl,
		    NULL,
		    &upl_count,
		    &upl_flags,
		    VM_KERN_MEMORY_DIAG);
		if (kr != KERN_SUCCESS) {
			printf("vm_map_create_upl[%d](%p, 0x%lx) returned 0x%x\n",
			    (int)i, (void*)iov[i].base, (unsigned long)iov[i].len, kr);
			error = EIO;
			goto vector_upl_test_done;
		}
		/* This effectively transfers our reference to subupl over to vector_upl. */
		vector_upl_set_subupl(vector_upl, subupl, upl_size);
		vector_upl_set_iostate(vector_upl, subupl, vector_upl_size, upl_size);
		vector_upl_size += upl_size;
	}

	/* Map the vector UPL as a single KVA region and modify the page contents by adding 1 to each char. */
	kern_return_t kr = vm_upl_map(kernel_map, vector_upl, &kva);
	if (kr != KERN_SUCCESS) {
		error = ENOMEM;
		goto vector_upl_test_done;
	}

	char *buf = (char*)kva;
	for (upl_size_t i = 0; i < vector_upl_size; i++) {
		buf[i] = buf[i] + 1;
	}
	*out = (int64_t)vector_upl_size;

vector_upl_test_done:

	if (kva != 0) {
		vm_upl_unmap(kernel_map, vector_upl);
	}

	if (vector_upl != NULL) {
		/* Committing the vector UPL will release and deallocate each of its sub-UPLs. */
		upl_commit(vector_upl, NULL, 0);
		upl_deallocate(vector_upl);
	}

	if (iov != NULL) {
		kfree_data(iov, iovsize);
	}

	return error;
}
SYSCTL_TEST_REGISTER(vm_vector_upl, vm_vector_upl_test);

/*
 * Test that wiring copy delay memory pushes pages to its copy object
 */
static int
vm_map_wire_copy_delay_memory_test(__unused int64_t in, int64_t *out)
{
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;
	vm_map_t map;
	mach_vm_address_t address_a, address_b, address_c;
	vm_prot_t cur_prot, max_prot;
	vm_object_t object;
	vm_page_t m;

	T_BEGIN("vm_map_wire_copy_delay_memory_test");
	map = create_map(0x100000000ULL, 0x200000000ULL, PAGE_SHIFT);

	address_a = 0;
	kr = mach_vm_allocate(
		map,
		&address_a,
		/* size */ PAGE_SIZE,
		VM_FLAGS_ANYWHERE);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "mach_vm_allocate A");

	address_b = 0;
	kr = mach_vm_remap(
		map,
		&address_b,
		/* size */ PAGE_SIZE,
		/* mask */ 0,
		VM_FLAGS_ANYWHERE,
		map,
		address_a,
		/* copy */ FALSE,
		&cur_prot,
		&max_prot,
		VM_INHERIT_NONE);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "mach_vm_remap A->B");

	address_c = 0;
	kr = mach_vm_remap(
		map,
		&address_c,
		/* size */ PAGE_SIZE,
		/* mask */ 0,
		VM_FLAGS_ANYWHERE,
		map,
		address_b,
		/* copy */ TRUE,
		&cur_prot,
		&max_prot,
		VM_INHERIT_NONE);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "mach_vm_remap B->C");

	kr = mach_vm_protect(
		map,
		address_c,
		/* size */ PAGE_SIZE,
		/* set_max */ FALSE,
		VM_PROT_READ);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "mach_vm_protect C");

	kr = vm_map_wire_kernel(
		map,
		/* begin */ address_b,
		/* end */ address_b + PAGE_SIZE,
		VM_PROT_NONE,
		VM_KERN_MEMORY_OSFMK,
		false);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_wire_kernel B");

	kr = vm_map_find_entry_sh_locked(ctx, &map, address_c, VMRL_FIND_SH_DEFAULT);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_find_entry_sh_locked");

	object = VME_OBJECT(vm_map_found_entry_get_entry(ctx));
	T_ASSERT_NOTNULL(object, "C's object should not be null");
	vm_object_lock(object);

	m = vm_page_lookup(object, /* offset */ 0);
	T_ASSERT_NOTNULL(m, "C should have a page pushed to it");

	/* cleanup */
	vm_object_unlock(object);
	vm_map_found_entry_sh_unlock(ctx, &map);
	cleanup_map(&map);

	T_END;
	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_wire_copy_delay_memory, vm_map_wire_copy_delay_memory_test);

#if HAS_MTE

static void
create_two_mte_maps(vm_map_t* out_mte_map1, vm_map_t* out_mte_map2)
{
	*out_mte_map1 = create_map(MACH_VM_MIN_ADDRESS, MACH_VM_MAX_ADDRESS, PAGE_SHIFT);
	vm_map_set_sec_enabled(*out_mte_map1);
	*out_mte_map2 = create_map(MACH_VM_MIN_ADDRESS, MACH_VM_MAX_ADDRESS, PAGE_SHIFT);
	vm_map_set_sec_enabled(*out_mte_map2);

	/* And the second map receives a new ID */
	if ((*out_mte_map1)->serial_id == (*out_mte_map2)->serial_id) {
		panic("Expected each map to receive a new ID");
	}
}

static void
create_mte_and_non_mte_map(vm_map_t* out_mte_map, vm_map_t* out_non_mte_map)
{
	*out_mte_map = create_map(MACH_VM_MIN_ADDRESS, MACH_VM_MAX_ADDRESS, PAGE_SHIFT);
	vm_map_set_sec_enabled(*out_mte_map);
	*out_non_mte_map = create_map(MACH_VM_MIN_ADDRESS, MACH_VM_MAX_ADDRESS, PAGE_SHIFT);

	/* And the second map receives a new ID */
	if ((*out_mte_map)->serial_id == (*out_non_mte_map)->serial_id) {
		panic("Expected each map to receive a new ID");
	}
}

static vm_object_t
create_mte_vm_object(vm_object_size_t size, vm_map_serial_t provenance)
{
	vm_object_t mte_object = vm_object_allocate(size, provenance);
	assert(mte_object != VM_OBJECT_NULL);
	mte_object->wimg_bits = VM_WIMG_MTE;
	/* Specify the expected copy strategy for MTE objects */
	mte_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
	return mte_object;
}

static vm_object_t
vm_object_for_address(vm_map_t map, vm_map_offset_t address)
{
	vm_map_entry_t map_entry;

	vm_map_ilk_lock(map);
	map_entry = vm_map_lookup(map, address);
	assert(map_entry);
	vm_map_ilk_unlock(map);

	vm_object_t object = VME_OBJECT(map_entry);
	assert(object);
	return object;
}

static vm_map_offset_t
map_object_and_expect_mte(vm_map_t map, vm_object_t obj)
{
	vm_map_offset_t mapped_address;
	kern_return_t kr = vm_map_enter(map, &mapped_address, obj->vo_size, 0,
	    /* We want the object to be mapped as MTE-enabled */
	    VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_mte = true),
	    obj, 0, false,
	    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);

	/* And the entry is MTE-enabled as expected */
	assert(vm_object_is_mte_mappable(vm_object_for_address(map, mapped_address)));

	return mapped_address;
}

static vm_object_t
expect_object_at_address_to_be_mapped_with_mte_state(
	vm_map_t map,
	vm_map_offset_t address,
	bool expect_mapping_to_be_mte_enabled
	)
{
	vm_object_t alias_object = vm_object_for_address(map, address);
	ppnum_t pn = vm_map_get_phys_page(map, address);
	T_ASSERT(pn != 0, "Expected a non-zero page number");
	/* The page itself should be tagged */
	assert(vm_object_is_mte_mappable(alias_object));
	T_ASSERT(pmap_is_tagged_page(pn), "Expected backing page to be tagged");

	if (expect_mapping_to_be_mte_enabled) {
		/* And our specific mapping should be tagged */
		T_ASSERT(pmap_is_tagged_mapping(vm_map_pmap(map), address), "Expected alias mapping to be tagged");
	} else {
		/* But our mapping should not be tagged */
		T_ASSERT(!pmap_is_tagged_mapping(vm_map_pmap(map), address), "Expected alias mapping to be untagged");
	}

	return alias_object;
}

static vm_object_t
expect_object_at_address_to_be_mte_mapped(
	vm_map_t map,
	vm_map_offset_t address)
{
	return expect_object_at_address_to_be_mapped_with_mte_state(
		map,
		address,
		true);
}

static void
share_object_and_expect_mapped_with_mte_state(
	vm_map_t src_map,
	vm_map_t dst_map,
	vm_map_offset_t src_address,
	vm_object_t obj,
	vm_map_offset_t* out_dst_address,
	vm_object_t* out_dst_object,
	bool expect_mapping_to_be_mte_enabled)
{
	assert(out_dst_address && out_dst_object);

	/* Share the object into the target map */
	vm_map_offset_t alias_mapped_address = 0;
	vm_prot_t cur_prot = VM_PROT_DEFAULT;
	vm_prot_t max_prot = VM_PROT_DEFAULT;
	kern_return_t kr = vm_map_remap(
		dst_map,
		vm_sanitize_wrap_addr_ref(&alias_mapped_address),
		obj->vo_size,
		0,
		/* The object may be MTE enabled */
		VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_mte = true),
		src_map,
		src_address,
		false,
		vm_sanitize_wrap_prot_ref(&cur_prot),
		vm_sanitize_wrap_prot_ref(&max_prot),
		VM_INHERIT_DEFAULT
		);
	assert(kr == KERN_SUCCESS);

	/* Fault in the object so we can inspect the pmap state */
	kr = vm_fault(
		dst_map,
		alias_mapped_address,
		VM_PROT_READ,
		false,
		VM_KERN_MEMORY_NONE,
		THREAD_UNINT,
		NULL, 0);
	assert(kr == KERN_SUCCESS);

	vm_object_t alias_object = expect_object_at_address_to_be_mapped_with_mte_state(
		dst_map,
		alias_mapped_address,
		expect_mapping_to_be_mte_enabled);

	*out_dst_address = alias_mapped_address;
	*out_dst_object = alias_object;
}

static void
share_object_and_expect_non_mte(
	vm_map_t src_map,
	vm_map_t dst_map,
	vm_map_offset_t src_address,
	vm_object_t obj,
	vm_map_offset_t* out_dst_address,
	vm_object_t* out_dst_object
	)
{
	share_object_and_expect_mapped_with_mte_state(
		src_map,
		dst_map,
		src_address,
		obj,
		out_dst_address,
		out_dst_object,
		false);
}

static void
share_object_and_expect_mte(
	vm_map_t src_map,
	vm_map_t dst_map,
	vm_map_offset_t src_address,
	vm_object_t obj,
	vm_map_offset_t* out_dst_address,
	vm_object_t* out_dst_object
	)
{
	share_object_and_expect_mapped_with_mte_state(
		src_map,
		dst_map,
		src_address,
		obj,
		out_dst_address,
		out_dst_object,
		true);
}

static int
vm_map_id_fork_test(__unused int64_t in, int64_t *out)
{
	/* Given a map */
	vm_map_t parent_map = create_map(MACH_VM_MIN_ADDRESS, MACH_VM_MAX_ADDRESS, PAGE_SHIFT);

	/* When we fork it into a new map */
	ledger_t map_ledger = parent_map->pmap->ledger;
	vm_map_t child_map = vm_map_fork(map_ledger, parent_map, 0);

	/* Then the forked map shares the same ID as its parent map */
	if (parent_map->serial_id != child_map->serial_id) {
		panic("Expected a forked map to share its parent's ID");
	}

	/* Cleanup */
	cleanup_map(&child_map);
	cleanup_map(&parent_map);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_id_fork, vm_map_id_fork_test);

static int
vm_map_alias_mte_mapping_in_other_non_mte_map_test(__unused int64_t in, int64_t *out)
{
	/* Given an MTE map and a non-MTE map */
	vm_map_t mte_map, non_mte_map;
	create_mte_and_non_mte_map(&mte_map, &non_mte_map);

	/* And an MTE-enabled object in the MTE map */
	vm_object_t mte_object = create_mte_vm_object(PAGE_SIZE, mte_map->serial_id);
	vm_map_offset_t mte_map_mapped_address = map_object_and_expect_mte(mte_map, mte_object);

	/* When the mapping is entered into a non-MTE map */
	/* Then the object has been entered as non-MTE in the non-MTE map */
	vm_map_offset_t alias_address;
	vm_object_t alias_object;
	share_object_and_expect_non_mte(mte_map, non_mte_map, mte_map_mapped_address, mte_object, &alias_address, &alias_object);

	/* And when we remap again back into the original map */
	/* Then the object has been entered as MTE, because it went back to its original map */
	vm_map_offset_t remapped_address;
	vm_object_t remapped_object;
	share_object_and_expect_mte(non_mte_map, mte_map, alias_address, alias_object, &remapped_address, &remapped_object);

	/* Cleanup */
	cleanup_map(&non_mte_map);
	cleanup_map(&mte_map);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_alias_mte_mapping_in_other_non_mte_map, vm_map_alias_mte_mapping_in_other_non_mte_map_test);

static int
vm_map_alias_mte_mapping_in_other_mte_map_test(__unused int64_t in, int64_t *out)
{
	/* Given two MTE maps */
	vm_map_t mte_map1, mte_map2;
	create_two_mte_maps(&mte_map1, &mte_map2);

	/* And an MTE-enabled object in the first map */
	vm_object_t mte_object = create_mte_vm_object(PAGE_SIZE, mte_map1->serial_id);
	vm_map_offset_t mte_map1_mapped_address = map_object_and_expect_mte(mte_map1, mte_object);

	/* When the mapping is entered into the second MTE map */
	/* Then the object has been entered as non-MTE (because the MTE state of the destination map doesn't matter) */
	vm_map_offset_t alias_address;
	vm_object_t alias_object;
	share_object_and_expect_non_mte(
		mte_map1,
		mte_map2,
		mte_map1_mapped_address,
		mte_object,
		&alias_address,
		&alias_object);

	/* And when we remap again back into the original map */
	/* Then the object has been entered as MTE, because it went back to its original map */
	vm_map_offset_t remapped_address;
	vm_object_t remapped_object;
	share_object_and_expect_mte(
		mte_map2,
		mte_map1,
		alias_address,
		alias_object,
		&remapped_address,
		&remapped_object);

	/* Cleanup */
	cleanup_map(&mte_map2);
	cleanup_map(&mte_map1);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_alias_mte_mapping_in_other_mte_map, vm_map_alias_mte_mapping_in_other_mte_map_test);

static int
vm_map_alias_mte_mapping_in_fork_map_test(__unused int64_t in, int64_t *out)
{
	/* Given an MTE parent map */
	vm_map_t parent_map = create_map(MACH_VM_MIN_ADDRESS, MACH_VM_MAX_ADDRESS, PAGE_SHIFT);
	vm_map_set_sec_enabled(parent_map);

	/* And an MTE mapping that was created prior to forking */
	vm_object_t mte_object_from_before_fork = create_mte_vm_object(PAGE_SIZE, parent_map->serial_id);
	vm_map_offset_t mapped_address_of_mte_object_from_before_fork = map_object_and_expect_mte(parent_map, mte_object_from_before_fork);

	/* And a forked child map */
	vm_map_t child_map = vm_map_fork(parent_map->pmap->ledger, parent_map, 0);

	/*
	 * Then the MTE object that was present in the child is also MTE in the parent
	 * (which is expected via our forking strategy).
	 * (We also need to fault in the mapping in the child first.)
	 */
	kern_return_t kr = vm_fault(
		child_map,
		mapped_address_of_mte_object_from_before_fork,
		VM_PROT_READ,
		false,
		VM_KERN_MEMORY_NONE,
		THREAD_UNINT,
		NULL, 0);
	assert(kr == KERN_SUCCESS);

	expect_object_at_address_to_be_mte_mapped(
		child_map,
		mapped_address_of_mte_object_from_before_fork
		);

	/* And when we enter a new MTE object into the parent after the fork() */
	vm_object_t mte_object_after_fork = create_mte_vm_object(PAGE_SIZE, parent_map->serial_id);
	vm_map_offset_t mapped_address_of_mte_object_after_fork = map_object_and_expect_mte(parent_map, mte_object_after_fork);

	/* And we share this object into the child */
	/* Then the child's alias to this object is MTE enabled (because fork maps share the same serial as their parent) */
	vm_map_offset_t aliased_address;
	vm_object_t aliased_object;
	share_object_and_expect_mte(
		parent_map,
		child_map,
		mapped_address_of_mte_object_after_fork,
		mte_object_after_fork,
		&aliased_address,
		&aliased_object);

	/* And when we remap again back into the original parent map */
	/* Then the object has been entered as MTE, because it went back to its original map */
	vm_map_offset_t remapped_address;
	vm_object_t remapped_object;
	share_object_and_expect_mte(
		parent_map,
		child_map,
		mapped_address_of_mte_object_after_fork,
		mte_object_after_fork,
		&remapped_address,
		&remapped_object);

	/* Cleanup */
	cleanup_map(&child_map);
	cleanup_map(&parent_map);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_alias_mte_mapping_in_fork_map, vm_map_alias_mte_mapping_in_fork_map_test);

static int
vm_object_transpose_provenance_test(__unused int64_t in, int64_t *out)
{
	/* Given two MTE maps */
	vm_map_t mte_map1, mte_map2;
	create_two_mte_maps(&mte_map1, &mte_map2);

	/* And an object from each map */
	vm_object_t obj1 = create_mte_vm_object(PAGE_SIZE, mte_map1->serial_id);
	vm_object_t obj2 = create_mte_vm_object(PAGE_SIZE, mte_map2->serial_id);

	/* When we transpose the objects */
	vm_map_serial_t original_obj1_prov = obj1->vmo_provenance;
	vm_map_serial_t original_obj2_prov = obj2->vmo_provenance;

	vm_object_lock(obj1);
	vm_object_activity_begin(obj1);
	obj1->blocked_access = TRUE;
	vm_object_unlock(obj1);
	vm_object_lock(obj2);
	vm_object_activity_begin(obj2);
	obj2->blocked_access = TRUE;
	vm_object_unlock(obj2);

	vm_object_transpose(obj2, obj1, PAGE_SIZE);

	vm_object_lock(obj1);
	vm_object_activity_end(obj1);
	obj1->blocked_access = FALSE;
	vm_object_unlock(obj1);
	vm_object_lock(obj2);
	vm_object_activity_end(obj2);
	obj2->blocked_access = FALSE;
	vm_object_unlock(obj2);

	/* Then the IDs have been transposed */
	assert(obj1->vmo_provenance == original_obj2_prov);
	assert(obj2->vmo_provenance == original_obj1_prov);

	/* Cleanup */
	cleanup_map(&mte_map2);
	cleanup_map(&mte_map1);

	*out = 1;
	return 0;
}

SYSCTL_TEST_REGISTER(vm_object_transpose_provenance, vm_object_transpose_provenance_test);


#endif /* HAS_MTE */

/*
 * Compare the contents of an original userspace buffer with that kernel mapping of a UPL created
 * against that userspace buffer.  Also validate that the physical pages in the UPL's page list
 * match the physical pages backing the kernel mapping at the pmap layer.  Furthermore, if UPL creation
 * was expected to copy the original buffer, validate that the backing pages for the userspace buffer
 * don't match the kernel/UPL pages, otherwise validate that they do match.
 */
static int
upl_buf_compare(user_addr_t src, upl_t upl, const void *upl_buf, upl_size_t size, bool copy_expected)
{
	int error = 0;
	void *temp = kalloc_data(PAGE_SIZE, Z_WAITOK);

	upl_size_t i = 0;
	while (i < size) {
		size_t bytes = MIN(size - i, PAGE_SIZE);
		error = copyin(src + i, temp, bytes);
		if (!error && (memcmp(temp, (const void*)((uintptr_t)upl_buf + i), bytes) != 0)) {
			printf("%s: memcmp(%p, %p, %zu) failed, src[0] = 0x%llx, buf[0] = 0x%llx\n",
			    __func__, (void*)(src + i), (const void*)((uintptr_t)upl_buf + i), bytes, *((unsigned long long*)temp), *((unsigned long long*)((uintptr_t)upl_buf + i)));
			error = EINVAL;
		}
		if (!error) {
			ppnum_t user_pa = pmap_find_phys(current_map()->pmap, (addr64_t)src + i);
			ppnum_t upl_pa = pmap_find_phys(kernel_pmap, (addr64_t)upl_buf + i);
			if ((upl_pa == 0) || /* UPL is wired, PA should always be valid */
			    (!copy_expected && (upl_pa != user_pa)) ||
			    (copy_expected && (upl_pa == user_pa)) ||
			    (upl_pa != (upl->page_list[i >> PAGE_SHIFT].phys_addr))) {
				printf("%s: PA verification[%u] failed: copy=%u, upl_pa = 0x%lx, user_pa = 0x%lx, page list PA = 0x%lx\n",
				    __func__, (unsigned)i, (unsigned)copy_expected, (unsigned long)upl_pa, (unsigned long)user_pa,
				    (unsigned long)upl->page_list[i].phys_addr);
				error = EFAULT;
			}
		}
		if (error) {
			break;
		}
		i += bytes;
	}

	kfree_data(temp, PAGE_SIZE);

	return error;
}

static int
vm_upl_test(int64_t in, int64_t *out __unused)
{
	upl_t upl = NULL;
	vm_address_t kva = 0;

	struct {
		uint64_t ptr; /* Base address of buffer in userspace */
		uint32_t size; /* Size of userspace buffer (in bytes) */
		char test_pattern; /* Starting char of test pattern we should write (if applicable) */
		bool copy_expected; /* Is UPL creation expected to create a copy of the original buffer? */
		bool should_fail; /* Is UPL creation expected to fail due to permissions checking? */
		bool upl_rw; /* Should the UPL be created RW (!UPL_COPYOUT_FROM) instead of RO? */
	} args;
	int error = copyin((user_addr_t)in, &args, sizeof(args));
	if ((error != 0) || (args.size == 0)) {
		goto upl_test_done;
	}

	upl_size_t upl_size = args.size;
	unsigned int upl_count = 0;
	upl_control_flags_t upl_flags = UPL_SET_IO_WIRE | UPL_SET_LITE | UPL_SET_INTERNAL;
	if (!args.upl_rw) {
		upl_flags |= UPL_COPYOUT_FROM;
	} else {
		upl_flags |= UPL_WILL_MODIFY;
	}
	kern_return_t kr = vm_map_create_upl(current_map(),
	    (vm_map_offset_t)args.ptr,
	    &upl_size,
	    &upl,
	    NULL,
	    &upl_count,
	    &upl_flags,
	    VM_KERN_MEMORY_DIAG);
	if (args.should_fail && (kr == KERN_PROTECTION_FAILURE)) {
		goto upl_test_done;
	} else if (args.should_fail && (kr == KERN_SUCCESS)) {
		printf("%s: vm_map_create_upl(%p, 0x%lx) did not fail as expected\n",
		    __func__, (void*)args.ptr, (unsigned long)args.size);
		error = EIO;
		goto upl_test_done;
	} else if (kr != KERN_SUCCESS) {
		printf("%s: vm_map_create_upl(%p, 0x%lx) returned 0x%x\n",
		    __func__, (void*)args.ptr, (unsigned long)args.size, kr);
		error = kr;
		goto upl_test_done;
	}

	kr = vm_upl_map(kernel_map, upl, &kva);
	if (kr != KERN_SUCCESS) {
		error = kr;
		printf("%s: vm_upl_map() returned 0x%x\n", __func__, kr);
		goto upl_test_done;
	}

	/* Ensure the mapped UPL contents match the original user buffer contents */
	error = upl_buf_compare((user_addr_t)args.ptr, upl, (void*)kva, upl_size, args.copy_expected);

	if (error) {
		printf("%s: upl_buf_compare(%p, %p, %zu) failed\n",
		    __func__, (void*)args.ptr, (void*)kva, (size_t)upl_size);
	}

	if (!error && args.upl_rw) {
		/*
		 * If the UPL is writable, update the contents so that userspace can
		 * validate that it sees the updates.
		 */
		for (unsigned int i = 0; i < (upl_size / sizeof(unsigned int)); i++) {
			((unsigned int*)kva)[i] = (unsigned int)args.test_pattern + i;
		}
	}

upl_test_done:

	if (kva != 0) {
		vm_upl_unmap(kernel_map, upl);
	}

	if (upl != NULL) {
		upl_commit(upl, NULL, 0);
		upl_deallocate(upl);
	}

	return error;
}
SYSCTL_TEST_REGISTER(vm_upl, vm_upl_test);

static int
vm_upl_submap_test(int64_t in, int64_t *out __unused)
{
	vm_map_address_t start = 0x180000000ULL;
	vm_map_address_t end = start + 0x180000000ULL;

	upl_t upl = NULL;
	vm_address_t kva = 0;
	int error = 0;

	/*
	 * Create temporary pmap and VM map for nesting our submap.
	 * We can't directly nest our submap into the current user map, because it will
	 * have already nested the shared region, and our security model doesn't allow
	 * multiple nested pmaps.
	 */
	pmap_t temp_pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);

	vm_map_t temp_map = VM_MAP_NULL;
	if (temp_pmap != PMAP_NULL) {
		temp_map = vm_map_create_options(temp_pmap, 0, 0xfffffffffffff, 0);
	}

	/* Now create the pmap and VM map that will back the submap entry in 'temp_map'. */
	pmap_t nested_pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT | PMAP_CREATE_NESTED);

	vm_map_t nested_map = VM_MAP_NULL;
	if (nested_pmap != PMAP_NULL) {
#if defined(__arm64__)
		pmap_set_nested(nested_pmap);
#endif /* defined(__arm64__) */
#if CODE_SIGNING_MONITOR
		csm_setup_nested_address_space(nested_pmap, start, end - start);
#endif
		nested_map = vm_map_create_options(nested_pmap, 0, end - start, 0);
	}

	if (temp_map == VM_MAP_NULL || nested_map == VM_MAP_NULL) {
		error = ENOMEM;
		printf("%s: failed to create VM maps\n", __func__);
		goto upl_submap_test_done;
	}

	nested_map->is_nested_map = TRUE;
	nested_map->vmmap_sealed = VM_MAP_WILL_BE_SEALED;

	struct {
		uint64_t ptr; /* Base address of original buffer in userspace */
		uint64_t upl_base; /* Base address in 'temp_map' against which UPL should be created */
		uint32_t size; /* Size of userspace buffer in bytes */
		uint32_t upl_size; /* Size of UPL to create in bytes */
		bool upl_rw; /* Should the UPL be created RW (!UPL_COPYOUT_FROM) instead of RO? */
	} args;
	error = copyin((user_addr_t)in, &args, sizeof(args));
	if ((error != 0) || (args.size == 0) || (args.upl_size == 0)) {
		goto upl_submap_test_done;
	}

	/*
	 * Remap the original userspace buffer into the nested map, with CoW protection.
	 * This will not actually instantiate new mappings in 'nested_pmap', but will instead create
	 * new shadow object of the original object for the userspace buffer in the nested map.
	 * Mappings would only be created in 'nested_pmap' upon a later non-CoW fault of the nested region,
	 * which we aren't doing here.  That's fine, as we're not testing pmap functionality here; we
	 * only care that UPL creation produces the expected results at the VM map/entry level.
	 */
	mach_vm_offset_t submap_start = 0;

	vm_prot_ut remap_cur_prot = vm_sanitize_wrap_prot(VM_PROT_READ);
	vm_prot_ut remap_max_prot = vm_sanitize_wrap_prot(VM_PROT_READ);

	kern_return_t kr = mach_vm_remap_new_kernel(nested_map, (mach_vm_offset_ut*)&submap_start, args.size, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vm_tag = VM_KERN_MEMORY_OSFMK), current_map(), args.ptr, TRUE,
	    &remap_cur_prot, &remap_max_prot, VM_INHERIT_NONE);
	if (kr != KERN_SUCCESS) {
		printf("%s: failed to remap source buffer to nested map: 0x%x\n", __func__, kr);
		error = kr;
		goto upl_submap_test_done;
	}

	vm_map_seal(nested_map, true);
	pmap_set_shared_region(temp_pmap, nested_pmap, start, end - start);

	/* Do the actual nesting. */
	vm_map_reference(nested_map);
	kr = vm_map_enter(temp_map, &start, end - start, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = TRUE, .vmkf_nested_pmap =  TRUE), (vm_object_t)(uintptr_t) nested_map, 0,
	    true, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);

	if (kr != KERN_SUCCESS) {
		error = kr;
		printf("%s: failed to enter nested map in test map: 0x%x\n", __func__, kr);
		vm_map_deallocate(nested_map);
		goto upl_submap_test_done;
	}

	/* Validate that the nesting operation produced the expected submap entry in 'temp_map'. */
	vm_map_entry_t submap_entry;
	vm_map_ilk_lock(temp_map);
	submap_entry = vm_map_lookup(temp_map, args.upl_base);
	if (submap_entry == VM_MAP_ENTRY_NULL || !submap_entry->is_sub_map) {
		vm_map_ilk_unlock(temp_map);
		error = ENOENT;
		printf("%s: did not find submap entry at beginning of UPL region\n", __func__);
		goto upl_submap_test_done;
	}
	vm_map_ilk_unlock(temp_map);

	upl_size_t upl_size = args.upl_size;
	unsigned int upl_count = 0;
	upl_control_flags_t upl_flags = UPL_SET_IO_WIRE | UPL_SET_LITE | UPL_SET_INTERNAL;
	if (!args.upl_rw) {
		upl_flags |= UPL_COPYOUT_FROM;
	}
	kr = vm_map_create_upl(temp_map,
	    (vm_map_offset_t)args.upl_base,
	    &upl_size,
	    &upl,
	    NULL,
	    &upl_count,
	    &upl_flags,
	    VM_KERN_MEMORY_DIAG);

	if (kr != KERN_SUCCESS) {
		error = kr;
		printf("%s: failed to create UPL for submap: 0x%x\n", __func__, kr);
		goto upl_submap_test_done;
	}

	/* Validate that UPL creation unnested a portion of the submap entry. */
	vm_map_ilk_lock(temp_map);
	submap_entry = vm_map_lookup(temp_map, args.upl_base);
	if (submap_entry == VM_MAP_ENTRY_NULL || submap_entry->is_sub_map) {
		vm_map_ilk_unlock(temp_map);
		error = ENOENT;
		printf("%s: did not find non-submap entry at beginning of UPL region\n", __func__);
		goto upl_submap_test_done;
	}
	vm_map_ilk_unlock(temp_map);

	kr = vm_upl_map(kernel_map, upl, &kva);
	if (kr != KERN_SUCCESS) {
		error = kr;
		goto upl_submap_test_done;
	}

	/*
	 * Compare the original userspace buffer to the ultimate kernel mapping of the UPL.
	 * The unnesting and CoW faulting performed as part of UPL creation should have copied the original buffer
	 * pages, so we expect the two buffers to be backed by different pages.
	 */
	error = upl_buf_compare((user_addr_t)args.ptr + (args.upl_base - start), upl, (void*)kva, upl_size, true);

	if (!error) {
		/*
		 * Now validate that the nested region in 'temp_map' matches the original buffer.
		 * The unnesting and CoW faulting performed as part of UPL creation should have acted directly
		 * upon 'temp_map', so the backing pages should be the same here.
		 */
		vm_map_switch_context_t switch_ctx = vm_map_switch_to(temp_map);
		error = upl_buf_compare((user_addr_t)args.upl_base, upl, (void*)kva, upl_size, false);
		vm_map_switch_back(switch_ctx);
	}

upl_submap_test_done:

	if (kva != 0) {
		vm_upl_unmap(kernel_map, upl);
	}

	if (upl != NULL) {
		upl_commit(upl, NULL, 0);
		upl_deallocate(upl);
	}

	if (temp_map != VM_MAP_NULL) {
		vm_map_deallocate(temp_map);
		temp_pmap = PMAP_NULL;
	}
	if (nested_map != VM_MAP_NULL) {
		vm_map_deallocate(nested_map);
		nested_pmap = PMAP_NULL;
	}

	if (temp_pmap != PMAP_NULL) {
		pmap_destroy(temp_pmap);
	}
	if (nested_pmap != PMAP_NULL) {
		pmap_destroy(nested_pmap);
	}

	return error;
}
SYSCTL_TEST_REGISTER(vm_upl_submap, vm_upl_submap_test);

static int
vm_map_cs_associated_obj_test(int64_t in __unused, int64_t *out)
{
	mach_vm_offset_t user_addr = (mach_vm_address_t) in;
	kern_return_t kr;
	vm_map_offset_t kernel_addr;
	vm_map_copy_t copy;

	/*
	 * Copy the mapping from user -> kernel, and fault it.
	 */
	printf("running %s(%llx)\n", __func__, user_addr);

	kr = vm_map_copyin_internal(current_map(), user_addr, PAGE_SIZE, VM_MAP_COPYIN_ENTRY_LIST, &copy);
	assert(kr == KERN_SUCCESS);

	kr = vm_map_copyout(kernel_map, &kernel_addr, copy);
	assert(kr == KERN_SUCCESS);

	kr = vm_fault(kernel_map, kernel_addr, VM_PROT_READ, false, VM_KERN_MEMORY_NONE, THREAD_UNINT, NULL, 0);
	assert(kr == KERN_SUCCESS);

	kr = vm_deallocate(kernel_map, kernel_addr, PAGE_SIZE);
	assert(kr == KERN_SUCCESS);

	*out = 1;
	return 0;
}

SYSCTL_TEST_REGISTER(vm_map_cs_associated_obj, vm_map_cs_associated_obj_test);


#ifdef HAS_MTE
#include <arm64/mte_xnu.h>

static int
vm_map_page_tags_get_test(int64_t in __unused, int64_t *out)
{
	uint64_t MAP_BASE = 0x10000000;
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, 0xffffffffff00000, 0);
	kern_return_t kr;
	uint64_t buf[64];

	/* empty map */
	kr = vm_map_page_tags_get(map, MAP_BASE, buf, sizeof(buf));
	assert3u(kr, ==, KERN_INVALID_ADDRESS);

	vm_map_entry_t entry = vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);

	/* null objs */
	kr = vm_map_page_tags_get(map, MAP_BASE, buf, sizeof(buf));
	assert3u(kr, ==, KERN_FAILURE);

	/* submap test */
	vm_map_entry_t entry2 = vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 2);
	entry2->is_sub_map = true;
	vm_map_t submap = vm_map_create_options(NULL, MAP_BASE, 0xfffffffffffff, 0);
	assert(vm_entry_try_lock_exclusive(entry2));
	VME_SUBMAP_SET(entry2, submap);
	vm_entry_unlock_exclusive(map, entry2);

	kr = vm_map_page_tags_get(map, MAP_BASE + PAGE_SIZE, buf, sizeof(buf));
	assert3u(kr, ==, KERN_FAILURE);

	vm_object_t obj = vm_object_allocate(PAGE_SIZE, map->serial_id);
	assert(vm_entry_try_lock_exclusive(entry));
	VME_OBJECT_SET(entry, obj, false, 0);
	vm_entry_unlock_exclusive(map, entry);

	/* with an obj */
	kr = vm_map_page_tags_get(map, MAP_BASE, buf, sizeof(buf));
	assert3u(kr, ==, KERN_FAILURE);

	/* with a mte obj but no page */
	obj->wimg_bits = VM_WIMG_MTE;
	kr = vm_map_page_tags_get(map, MAP_BASE, buf, sizeof(buf));
	assert3u(kr, ==, KERN_FAILURE);

	/* grab a page, mark it wired, fill the tag buffer */
	vm_page_t page = VM_PAGE_NULL;
	while (page == VM_PAGE_NULL) {
		page = vm_page_grab_options(VM_PAGE_GRAB_MTE);
		if (page == VM_PAGE_NULL) {
			VM_PAGE_WAIT();
		}
	}

	vm_object_lock(obj);
	page->vmp_wire_count++;
	vm_page_insert(page, obj, 0);
	vm_page_wakeup_done(obj, page);
	vm_object_unlock(obj);


	uint64_t written_tags[64];
	written_tags[0] = 1;
	ppnum_t page_phys = VM_PAGE_GET_PHYS_PAGE(page);
	/* fill the buffer with the page's tags */
	vm_address_t vcur = phystokv(ptoa(page_phys));
	mte_bulk_write_tags((caddr_t)vcur, PAGE_SIZE, (mte_bulk_taglist_t *)written_tags, sizeof(written_tags));

	/* with a page */
	kr = vm_map_page_tags_get(map, MAP_BASE, buf, sizeof(buf));
	assert3u(kr, ==, KERN_SUCCESS);

	page->vmp_wire_count--;

	vm_map_ilk_lock(map);
	assert(vm_entry_try_lock_exclusive(entry2));
	vm_map_store_remove(map, entry2,
	    VMS_REMOVE_FREE_ENTRY | VMS_REMOVE_FREE_SLOTS);
	vm_map_ilk_unlock(map);
	vm_map_destroy(map);

	/* make sure the tags are what we wrote */
	assert3u(0, ==, memcmp(&buf, &written_tags, sizeof(buf)));

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_page_tags_get_test, vm_map_page_tags_get_test);
#endif

#define VM_MAP_WIRE_RACE_TEST_NUM_OBJECTS 50
#define VM_MAP_WIRE_RACE_TEST_SIZE (PAGE_SIZE * 250)
struct vm_map_wire_race_test_ctx {
	vm_object_t * objects;
	vm_map_entry_t entry;
	vm_address_t addr;
	bool done;
	int races_at_start;
	vm_map_t map;
};

struct vm_map_wire_race_test_ctx * wire_test_ctx;
extern int wire_restarts_due_to_kernel_wiring;

static int
vm_map_wire_race_test_setup(int64_t in __unused, int64_t *out)
{
	wire_test_ctx = kalloc_type(struct vm_map_wire_race_test_ctx, Z_ZERO | Z_WAITOK);
	wire_test_ctx->done = false;
	wire_test_ctx->addr = 0;
	wire_test_ctx->races_at_start = os_atomic_load(&wire_restarts_due_to_kernel_wiring, relaxed);
	wire_test_ctx->objects = kalloc_type(vm_object_t, VM_MAP_WIRE_RACE_TEST_NUM_OBJECTS, Z_ZERO | Z_WAITOK);

	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);
	wire_test_ctx->map = map;

	for (int i = 0; i < VM_MAP_WIRE_RACE_TEST_NUM_OBJECTS; i++) {
		wire_test_ctx->objects[i] = vm_object_allocate(VM_MAP_WIRE_RACE_TEST_SIZE, map->serial_id);
	}

	kern_return_t kr = vm_allocate_external(map, &wire_test_ctx->addr, VM_MAP_WIRE_RACE_TEST_SIZE, VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);

	vm_map_ilk_lock(map);
	wire_test_ctx->entry = vm_map_lookup(map, wire_test_ctx->addr);
	assert(wire_test_ctx->entry);

	/* give the entry some object to start */
	assert(vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE,
	    wire_test_ctx->entry, wire_test_ctx->addr, THREAD_UNINT) == KERN_SUCCESS);
	VME_OBJECT_SET(wire_test_ctx->entry, wire_test_ctx->objects[0], false, 0);
	vm_entry_unlock_exclusive(map, wire_test_ctx->entry);
	vm_map_ilk_unlock(map);


	*out = 1;
	return 0;
}

static int
vm_map_wire_race_test_thread_one(int64_t in __unused, int64_t *out)
{
	/* Just do kernel wire and unwire in a loop */
	while (!wire_test_ctx->done) {
		kern_return_t kr = vm_map_wire_kernel(wire_test_ctx->map, wire_test_ctx->addr,
		    wire_test_ctx->addr + VM_MAP_WIRE_RACE_TEST_SIZE, VM_PROT_DEFAULT, VM_KERN_MEMORY_OSFMK, false);
		assert(kr == KERN_SUCCESS);
		kr = vm_map_unwire(wire_test_ctx->map, wire_test_ctx->addr, wire_test_ctx->addr + VM_MAP_WIRE_RACE_TEST_SIZE, false);
		assert(kr == KERN_SUCCESS);
	}

	*out = 1;
	return 0;
}

static int
vm_map_wire_race_test_thread_two(int64_t in __unused, int64_t *out)
{
	int index = 1;

	/* Change the object from the pool of allocated objects */
	while (!wire_test_ctx->done) {
		vm_map_ilk_lock(wire_test_ctx->map);
		if (vm_entry_lock_exclusive(wire_test_ctx->map, LCK_RW_TYPE_EXCLUSIVE,
		    wire_test_ctx->entry, 0, THREAD_UNINT) == KERN_SUCCESS) {
			if (wire_test_ctx->entry->wired_count == 0) {
				/*
				 * Given it's not wired, it's valid for us to change the object.
				 * Additionally remove any old pmap mappings to the old object.
				 */
				pmap_remove(wire_test_ctx->map->pmap, wire_test_ctx->entry->vme_start, wire_test_ctx->entry->vme_end);

				VME_OBJECT_SET(wire_test_ctx->entry, wire_test_ctx->objects[(index++) % VM_MAP_WIRE_RACE_TEST_NUM_OBJECTS], false, 0);
			}
			vm_entry_unlock_exclusive(wire_test_ctx->map, wire_test_ctx->entry);
		}
		vm_map_ilk_unlock(wire_test_ctx->map);
	}
	*out = 1;
	return 0;
}

static int
vm_map_wire_race_test_signal_end(int64_t in __unused, int64_t *out)
{
	wire_test_ctx->done = true;

	*out = os_atomic_load(&wire_restarts_due_to_kernel_wiring, relaxed) - wire_test_ctx->races_at_start;
	return 0;
}

static int
vm_map_wire_race_test_cleanup(int64_t in __unused, int64_t *out)
{
	vm_object_t * objects = wire_test_ctx->objects;

	assert(vm_entry_try_lock_exclusive(wire_test_ctx->entry));
	pmap_remove(wire_test_ctx->map->pmap, wire_test_ctx->entry->vme_start, wire_test_ctx->entry->vme_end);
	VME_OBJECT_SET(wire_test_ctx->entry, VM_OBJECT_NULL, false, 0);
	vm_entry_unlock_exclusive(wire_test_ctx->map, wire_test_ctx->entry);

	vm_map_destroy(wire_test_ctx->map);

	for (int i = 0; i < VM_MAP_WIRE_RACE_TEST_NUM_OBJECTS; i++) {
		vm_object_deallocate(wire_test_ctx->objects[i]);
	}

	kfree_type(vm_object_t, VM_MAP_WIRE_RACE_TEST_NUM_OBJECTS, objects);
	kfree_type(struct vm_map_wire_race_test_ctx, wire_test_ctx);


	*out = 1;
	return 0;
}


/*
 * This group of tests is meant to test concurrent changing of objects (which wire sees as deletion)
 * against kernel wiring calls.
 * This provokes wire to take a special restart path that would be otherwise
 * uncovered.
 */
SYSCTL_TEST_REGISTER(vm_map_wire_race_test_setup, vm_map_wire_race_test_setup);
SYSCTL_TEST_REGISTER(vm_map_wire_race_test_thread_one, vm_map_wire_race_test_thread_one);
SYSCTL_TEST_REGISTER(vm_map_wire_race_test_thread_two, vm_map_wire_race_test_thread_two);
SYSCTL_TEST_REGISTER(vm_map_wire_race_test_signal_end, vm_map_wire_race_test_signal_end);
SYSCTL_TEST_REGISTER(vm_map_wire_race_test_cleanup, vm_map_wire_race_test_cleanup);

struct vm_copy_overwrite_busy_race_ctx {
	vm_map_entry_t entry;
	vm_address_t addr;
	bool done;
	vm_map_t map;
};

struct vm_copy_overwrite_busy_race_ctx * copy_overwrite_ctx;


#define REGION_SIZE PAGE_SIZE * 10
static int
vm_map_copy_overwrite_wire_race_setup(int64_t  in __unused, int64_t *out __unused)
{
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	vm_object_t dst_object = vm_object_allocate(PAGE_SIZE * 12, map->serial_id);
	dst_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;

	/* to take slow_copy path */

	copy_overwrite_ctx = kalloc_type(struct vm_copy_overwrite_busy_race_ctx, Z_ZERO | Z_WAITOK);
	copy_overwrite_ctx->map = map;

	copy_overwrite_ctx->addr = 0;
	kern_return_t kr = vm_allocate(map, &copy_overwrite_ctx->addr, REGION_SIZE, VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);

	vm_map_ilk_lock(map);
	copy_overwrite_ctx->entry = vm_map_lookup(map, copy_overwrite_ctx->addr);
	assert(copy_overwrite_ctx->entry);
	assert(vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, copy_overwrite_ctx->entry, copy_overwrite_ctx->addr, THREAD_UNINT) == KERN_SUCCESS);
	VME_OBJECT_SET(copy_overwrite_ctx->entry, dst_object, false, 0);
	copy_overwrite_ctx->entry->is_shared = true;
	vm_entry_unlock_exclusive(map, copy_overwrite_ctx->entry);
	vm_map_ilk_unlock(map);

	*out = 1;
	return 0;
}


static int
vm_map_copy_overwrite_wire_race_copy_thread(int64_t  in __unused, int64_t *out __unused)
{
	size_t copied_size = 0;
	while (!copy_overwrite_ctx->done) {
		kern_return_t kr;
		vm_map_entry_t entry;
		vm_map_t cur_map = copy_overwrite_ctx->map;

		/* Call vm_fault_copy in a loop. Make sure we don't have any deadlocks. */
		VM_MAP_LOCK_CTX_DECLARE(vml_ctx);
		kr = vm_map_range_ex_lock(vml_ctx, &cur_map, copy_overwrite_ctx->addr, copy_overwrite_ctx->addr + PAGE_SIZE, VMRL_EX_STREAM);
		while ((entry = vm_map_range_stream_next(vml_ctx))) {
			vm_object_t object = VME_OBJECT(entry);
			vm_map_size_t copy_size = REGION_SIZE - PAGE_SIZE;
			vm_object_reference(object);
			kr = vm_fault_copy(vml_ctx, object, PAGE_SIZE, &copy_size, &entry, object, 0, true);
			vm_object_deallocate(object);
			assert(kr == KERN_SUCCESS);
			copied_size += copy_size;
		}
		vm_map_range_ex_unlock(vml_ctx, &cur_map);
	}

	*out = 1;
	return 0;
}

/*
 * This a thread simulating the lock ordering of wire.
 * We take a range lock, and take the object lock
 * We then take and release the busy bit under that lock.
 * */
static int
vm_map_copy_overwrite_wire_race_busy_thread(int64_t  in __unused, int64_t *out __unused)
{
	while (!copy_overwrite_ctx->done) {
		kern_return_t kr;
		vm_map_entry_t entry;
		VM_MAP_LOCK_CTX_DECLARE(vml_ctx);
		vm_map_t cur_map = copy_overwrite_ctx->map;

		kr = vm_map_range_ex_lock(vml_ctx, &cur_map, copy_overwrite_ctx->addr, copy_overwrite_ctx->addr + PAGE_SIZE, VMRL_EX_STREAM);
		if (kr == KERN_SUCCESS) {
			while ((entry = vm_map_range_stream_next(vml_ctx))) {
				vm_object_t object = VME_OBJECT(entry);
				vm_object_lock(object);
				for (vm_object_offset_t offset = 0; offset < object->vo_size; offset += PAGE_SIZE) {
					/* for every page, busy it */
relookup_page:                          ;
					vm_page_t page = vm_page_lookup(object, offset);
					if (page == VM_PAGE_NULL) {
						continue;
					}
					if (page->vmp_busy) {
						wait_result_t wait_result = vm_page_sleep(object, page, THREAD_UNINT, LCK_SLEEP_DEFAULT);

						if (wait_result != THREAD_AWAKENED) {
							continue;
						}
						goto relookup_page;
					}
					/* Page isn't busy. Let's busy it */
					page->vmp_busy = true;
					/* Busied it, do the wakeup */
					vm_page_wakeup_done(object, page);
				}
				vm_object_unlock(object);
			}
			vm_map_range_ex_unlock(vml_ctx, &cur_map);
		}
	}

	*out = 1;
	return 0;
}

static int
vm_map_copy_overwrite_wire_race_signal_end(int64_t in __unused, int64_t *out)
{
	copy_overwrite_ctx->done = true;

	*out = 1;
	return 0;
}

static int
vm_map_copy_overwrite_wire_race_cleanup(int64_t in __unused, int64_t *out)
{
	vm_map_destroy(copy_overwrite_ctx->map);
	kfree_type(struct vm_copy_overwrite_busy_race_ctx, copy_overwrite_ctx);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_copy_overwrite_wire_race_setup, vm_map_copy_overwrite_wire_race_setup);
SYSCTL_TEST_REGISTER(vm_map_copy_overwrite_wire_race_copy_thread, vm_map_copy_overwrite_wire_race_copy_thread);
SYSCTL_TEST_REGISTER(vm_map_copy_overwrite_wire_race_busy_thread, vm_map_copy_overwrite_wire_race_busy_thread);
SYSCTL_TEST_REGISTER(vm_map_copy_overwrite_wire_race_signal_end, vm_map_copy_overwrite_wire_race_signal_end);
SYSCTL_TEST_REGISTER(vm_map_copy_overwrite_wire_race_cleanup, vm_map_copy_overwrite_wire_race_cleanup);

struct vm_map_remove_test_unwire_args {
	vm_map_t map;
	vm_map_address_t start;
	vm_map_address_t end;
	bool called;
};

static void
vm_map_remove_test_unwire_async(thread_call_param_t param0, __unused thread_call_param_t param1)
{
	struct vm_map_remove_test_unwire_args *args = (struct vm_map_remove_test_unwire_args*)param0;

	args->called = true;
	kern_return_t kr = vm_map_unwire(args->map, args->start, args->end, false /* kernel wire */);
	assert3u(kr, ==, KERN_SUCCESS);
}

static void
vm_map_remove_test_add_entry(vm_map_t map, vm_offset_t *start,
    vm_map_size_t size)
{
	kern_return_t kr;
	*start = 0;
	kr = mach_vm_map_kernel(map,
	    (mach_vm_offset_ut*)start,
	    size,
	    0,
	    VM_MAP_KERNEL_FLAGS_ANYWHERE(),
	    IP_NULL,
	    0,
	    false,
	    VM_PROT_DEFAULT,
	    VM_PROT_DEFAULT,
	    VM_INHERIT_DEFAULT);
	assert3u(kr, ==, KERN_SUCCESS);
}

static vm_map_t
vm_map_remove_test_setup(vm_offset_t *start, vm_map_size_t size)
{
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);

	vm_map_t map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	vm_map_remove_test_add_entry(map, start, size);

	return map;
}

static void
vm_map_remove_test_kernel_unwire_simple()
{
	kern_return_t kr;
	vm_offset_t  start;
	vm_map_size_t size = 0x20000;

	vm_map_remove_test_add_entry(kernel_map, &start, size);
	vm_map_address_t end = start + size;

	kr = vm_map_wire_kernel(kernel_map, start, end, VM_PROT_DEFAULT, VM_KERN_MEMORY_DIAG, false);
	assert3u(kr, ==, KERN_SUCCESS);

	kr = vm_map_remove_guard(kernel_map, start, end, VM_MAP_REMOVE_KUNWIRE, KMEM_GUARD_NONE);
	assert3u(kr, ==, KERN_SUCCESS);
}

static void
vm_map_remove_test_kernel_unwire_block_with_kunwire()
{
	kern_return_t kr;
	vm_offset_t  start;
	vm_map_size_t size = 0x20000;

	vm_map_remove_test_add_entry(kernel_map, &start, size);

	kr = vm_map_wire_kernel(kernel_map, start, start + size, VM_PROT_DEFAULT, VM_KERN_MEMORY_DIAG, false);
	assert3u(kr, ==, KERN_SUCCESS);

	kr = vm_map_wire_kernel(kernel_map, start, start + size, VM_PROT_DEFAULT, VM_KERN_MEMORY_DIAG, false);
	assert3u(kr, ==, KERN_SUCCESS);

	struct vm_map_remove_test_unwire_args args = {
		.map = kernel_map,
		.start = start,
		.end = start + size,
		.called = false
	};

	thread_call_t wakeup = thread_call_allocate_with_priority(&vm_map_remove_test_unwire_async, (thread_call_param_t)&args, THREAD_CALL_PRIORITY_LOW);

	uint64_t deadline;
	clock_interval_to_deadline(100, NSEC_PER_MSEC, &deadline);
	thread_call_enter_delayed(wakeup, deadline);
	kr = vm_map_remove_guard(kernel_map, start, start + size, VM_MAP_REMOVE_KUNWIRE, KMEM_GUARD_NONE);
	assert3u(kr, ==, KERN_SUCCESS);
	assert(args.called);

	thread_call_free(wakeup);
}

static void
vm_map_remove_test_kernel_unwire_block_without_kunwire()
{
	kern_return_t kr;
	vm_offset_t  start;
	vm_map_size_t size = 0x20000;

	vm_map_remove_test_add_entry(kernel_map, &start, size);
	vm_map_address_t end = start + size;

	kr = vm_map_wire_kernel(kernel_map, start, end, VM_PROT_DEFAULT, VM_KERN_MEMORY_DIAG, false);
	assert3u(kr, ==, KERN_SUCCESS);

	struct vm_map_remove_test_unwire_args args = {
		.map = kernel_map,
		.start = start,
		.end = end,
		.called = false
	};

	thread_call_t wakeup = thread_call_allocate_with_priority(&vm_map_remove_test_unwire_async, (thread_call_param_t)&args, THREAD_CALL_PRIORITY_LOW);

	uint64_t deadline;
	clock_interval_to_deadline(100, NSEC_PER_MSEC, &deadline);
	thread_call_enter_delayed(wakeup, deadline);
	kr = vm_map_remove_guard(kernel_map, start, end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	assert3u(kr, ==, KERN_SUCCESS);
	assert(args.called);

	thread_call_free(wakeup);
}

static void
vm_map_remove_test_user_unwire_simple()
{
	kern_return_t kr;
	vm_offset_t start;
	vm_map_size_t size = 0x20000;
	vm_map_t map = vm_map_remove_test_setup(&start, size);
	vm_map_address_t end = start + size;

	kr = vm_map_wire_kernel(map, start, end, VM_PROT_DEFAULT, VM_KERN_MEMORY_DIAG, true);
	assert3u(kr, ==, KERN_SUCCESS);

	assert3u(map->hdr.links.next->wired_count, ==, 1);

	kr = vm_map_remove_guard(map, start, end, 0, KMEM_GUARD_NONE);
	assert3u(kr, ==, KERN_SUCCESS);
}

static void
vm_map_remove_test_user_unwire_block()
{
	kern_return_t kr;
	vm_offset_t start;
	vm_map_size_t size = 0x20000;
	vm_map_t map = vm_map_remove_test_setup(&start, size);
	vm_map_address_t end = start + size;

	kr = vm_map_wire_kernel(map, start, end, VM_PROT_DEFAULT, VM_KERN_MEMORY_DIAG, true);
	assert3u(kr, ==, KERN_SUCCESS);

	kr = vm_map_wire_kernel(map, start, end, VM_PROT_DEFAULT, VM_KERN_MEMORY_DIAG, true);
	assert3u(kr, ==, KERN_SUCCESS);

	// Increase the kernel wire count to block
	kr = vm_map_wire_kernel(map, start, end, VM_PROT_DEFAULT, VM_KERN_MEMORY_DIAG, false);
	assert3u(kr, ==, KERN_SUCCESS);

	assert3u(map->hdr.links.next->wired_count, ==, 2);

	struct vm_map_remove_test_unwire_args args = {
		.map = map,
		.start = start,
		.end = end,
		.called = false
	};

	thread_call_t wakeup = thread_call_allocate_with_priority(&vm_map_remove_test_unwire_async, (thread_call_param_t)&args, THREAD_CALL_PRIORITY_LOW);

	uint64_t deadline;
	clock_interval_to_deadline(100, NSEC_PER_MSEC, &deadline);
	thread_call_enter_delayed(wakeup, deadline);

	kr = vm_map_remove_guard(map, start, end, 0, KMEM_GUARD_NONE);
	assert3u(kr, ==, KERN_SUCCESS);

	thread_call_free(wakeup);
}

static void
vm_map_remove_test_unwire()
{
	printf("%s: Remove an entry with VM_MAP_REMOVE_KUNWIRE\n", __func__);
	vm_map_remove_test_kernel_unwire_simple();

	printf("%s: Remove an entry, block waiting for an unwire with a pending VM_MAP_REMOVE_KUNWIRE\n", __func__);
	vm_map_remove_test_kernel_unwire_block_with_kunwire();

	printf("%s: Remove an entry, block waiting without a pending VM_MAP_REMOVE_KUNWIRE\n", __func__);
	vm_map_remove_test_kernel_unwire_block_without_kunwire();

	printf("%s: Remove an entry with any user_wire_count without waiting\n", __func__);
	vm_map_remove_test_user_unwire_simple();

	printf("%s: Remove an entry with any user_wire_count by waiting for wired_count to drop to 1\n", __func__);
	vm_map_remove_test_user_unwire_block();
}

struct vm_map_remove_test_remover_args {
	vm_map_t map;
	vm_offset_t start;
	vm_offset_t end;
};

static void
vm_map_remove_test_remove_async(thread_call_param_t param0,
    __unused thread_call_param_t param1)
{
	struct vm_map_remove_test_remover_args *args = (struct vm_map_remove_test_remover_args*)param0;

	kern_return_t kr = vm_map_remove_guard(args->map, args->start, args->end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	assert3u(kr, ==, KERN_SUCCESS);
};

static void __attribute__((noreturn))
vm_map_remove_wait_detect_hang(__unused thread_call_param_t param0,
    __unused thread_call_param_t param1)
{
	panic("Failed to wakeup vm_map_enter");
}

static void
vm_map_remove_test_wait_for_space()
{
	printf("%s: Removing an entry should wake any thread waiting for free space\n", __func__);

	vm_offset_t start;
	vm_map_size_t size = 0x20000;
	vm_map_t map = vm_map_create_options(NULL, 0, 2 * size - 1, VM_MAP_CREATE_DEFAULT);

	vm_map_remove_test_add_entry(map, &start, size);
	vm_map_address_t end = start + size;

	map->wait_for_space = true;

	struct vm_map_remove_test_remover_args args = {
		.map = map,
		.start = start,
		.end = end,
	};

	thread_call_t async_remover = thread_call_allocate_with_priority(
		&vm_map_remove_test_remove_async,
		(thread_call_param_t)&args,
		THREAD_CALL_PRIORITY_HIGH);

	thread_call_t hang_detector = thread_call_allocate_with_priority(
		&vm_map_remove_wait_detect_hang,
		(thread_call_param_t)0,
		THREAD_CALL_PRIORITY_HIGH);

	uint64_t deadline;
	clock_interval_to_deadline(100, NSEC_PER_MSEC, &deadline);
	thread_call_enter_delayed(async_remover, deadline);

	clock_interval_to_deadline(1000, NSEC_PER_MSEC, &deadline);
	thread_call_enter_delayed(hang_detector, deadline);

	vm_map_remove_test_add_entry(map, &start, size);

	thread_call_cancel(hang_detector);

	assert(thread_call_free(hang_detector));
	assert(thread_call_free(async_remover));
}

static void __attribute__((noreturn))
vm_map_remove_interruptible_test_lock_entry(thread_call_param_t param0,
    thread_call_param_t param1)
{
	kern_return_t kr = vm_map_dbg_lock_vm_entry_and_block((vm_map_t)param0, *(vm_address_t*)param1, PAGE_SIZE,
	    DBG_LCK_FLAG_EXCLUSIVE | DBG_LCK_FLAG_ATOMIC);
	panic("interruptible blocker returned with %d", kr);
}

static void
vm_map_remove_interruptible_wake_delayed(thread_call_param_t param0,
    __unused thread_call_param_t param1)
{
	clear_wait((thread_t)param0, THREAD_INTERRUPTED);
}

static void __attribute__((noreturn))
vm_map_remove_interruptible_detect_hang(__unused thread_call_param_t param0,
    __unused thread_call_param_t param1)
{
	panic("Failed to interrupt vm_map_remove\n");
}

static void
vm_map_remove_test_interruptible(bool terminated)
{
	printf("%s: Removing an entry should be interruptible if requested\n", __func__);

	kern_return_t kr;
	uint64_t deadline;
	vm_address_t start;
	vm_map_size_t size = 0x20000;
	vm_map_t map = vm_map_remove_test_setup(&start, size);

	vm_map_ilk_lock(map);
	map->terminated = terminated;
	vm_map_ilk_unlock(map);

	thread_call_t blocker = thread_call_allocate_with_priority(&vm_map_remove_interruptible_test_lock_entry,
	    (thread_call_param_t)map,
	    THREAD_CALL_PRIORITY_HIGH);

	thread_call_t interrupter = thread_call_allocate_with_priority(&vm_map_remove_interruptible_wake_delayed,
	    (thread_call_param_t)current_thread(),
	    THREAD_CALL_PRIORITY_HIGH);

	thread_call_t hang_detector = thread_call_allocate_with_priority(&vm_map_remove_interruptible_detect_hang,
	    (thread_call_param_t)0,
	    THREAD_CALL_PRIORITY_HIGH);

	thread_call_enter1(blocker, &start);

	// Allow the blocker to take exclusive access
	delay_for_interval(100, NSEC_PER_MSEC);

	clock_interval_to_deadline(100, NSEC_PER_MSEC, &deadline);
	thread_call_enter_delayed(interrupter, deadline);

	clock_interval_to_deadline(1000, NSEC_PER_MSEC, &deadline);
	thread_call_enter_delayed(hang_detector, deadline);

	kr = vm_map_remove_guard(map, start, start + size, VM_MAP_REMOVE_INTERRUPTIBLE, KMEM_GUARD_NONE);
	assert3u(kr, ==, KERN_ABORTED);

	thread_call_cancel(hang_detector);

	thread_call_free(hang_detector);
	thread_call_free(blocker);
	thread_call_free(interrupter);
}

static void
vm_map_remove_test_interruptible_unwire()
{
	printf("%s: Removing an entry should be interruptible if requested\n", __func__);

	kern_return_t kr;
	uint64_t deadline;
	vm_address_t start;
	vm_map_size_t size = 0x20000;
	vm_map_t map = vm_map_remove_test_setup(&start, size);

	kr = vm_map_wire_kernel(map, start, start + size, VM_PROT_DEFAULT, VM_KERN_MEMORY_DIAG, false);
	assert3u(kr, ==, KERN_SUCCESS);

	thread_call_t interrupter = thread_call_allocate_with_priority(&vm_map_remove_interruptible_wake_delayed,
	    (thread_call_param_t)current_thread(),
	    THREAD_CALL_PRIORITY_HIGH);

	thread_call_t hang_detector = thread_call_allocate_with_priority(&vm_map_remove_interruptible_detect_hang,
	    (thread_call_param_t)0,
	    THREAD_CALL_PRIORITY_HIGH);

	clock_interval_to_deadline(100, NSEC_PER_MSEC, &deadline);
	thread_call_enter_delayed(interrupter, deadline);

	clock_interval_to_deadline(1000, NSEC_PER_MSEC, &deadline);
	thread_call_enter_delayed(hang_detector, deadline);

	kr = vm_map_remove_guard(map, start, start + size, VM_MAP_REMOVE_INTERRUPTIBLE, KMEM_GUARD_NONE);
	assert3u(kr, ==, KERN_ABORTED);

	thread_call_cancel(hang_detector);

	thread_call_free(hang_detector);
	thread_call_free(interrupter);
}

static int
vm_map_remove_test(__unused int64_t in, int64_t *out)
{
	printf("%s: test running\n", __func__);

	vm_map_remove_test_unwire();
	vm_map_remove_test_wait_for_space();
	vm_map_remove_test_interruptible(false);
	vm_map_remove_test_interruptible(true);
	vm_map_remove_test_interruptible_unwire();

	printf("%s: test complete\n", __func__);

	*out = 1;
	return 0;
}

SYSCTL_TEST_REGISTER(vm_map_remove_test, vm_map_remove_test);

static int
vm_map_range_configure_test(__unused int64_t in, int64_t *out)
{
#if CONFIG_MAP_RANGES
	vm_map_address_t MAP_BASE = 0x010000000; // avoid the pmap_shared_region

	/* invalid configuration to create ranges, it's a 32 bit addr space */
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, MAP_BASE + PAGE_SIZE * 20, 0);
	kern_return_t kr = vm_map_range_configure(map, false);
	assert3u(kr, ==, KERN_NOT_SUPPORTED);
	vm_map_destroy(map);

	/* invalid config, it's already jumboed */
	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, 0x61ull << 40, 0); /* from range_configure */
	kr = vm_map_range_configure(map, false);
	assert3u(kr, ==, KERN_NO_SPACE);
	vm_map_destroy(map);

	/* try with no entries */
	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, vm_compute_max_offset(true), 0);
	kr = vm_map_range_configure(map, false);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3u((int)map->uses_user_ranges, ==, true);
	vm_map_destroy(map);

	/* try with entry way late in the map, after the jumbo space. This entry is like the commpage */
	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, vm_compute_max_offset(true), 0);
	vm_test_add_map_entry(map, MACH_VM_JUMBO_ADDRESS, MACH_VM_JUMBO_ADDRESS + PAGE_SIZE);
	kr = vm_map_range_configure(map, false);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3u((int)map->uses_user_ranges, ==, true);
	vm_map_destroy(map);

	/* try with entry way late in the map, after the jumbo space. (this one starts PAGE_SIZE after the map end. may never exist) */
	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, vm_compute_max_offset(true), 0);
	vm_test_add_map_entry(map, MACH_VM_JUMBO_ADDRESS + PAGE_SIZE, MACH_VM_JUMBO_ADDRESS + PAGE_SIZE * 2);
	kr = vm_map_range_configure(map, false);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3u((int)map->uses_user_ranges, ==, true);
	vm_map_destroy(map);

	/* try with an entry in the jumbo space. This probably never happens realistically. */
	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, vm_compute_max_offset(true), 0);
	vm_test_add_map_entry(map, MACH_VM_JUMBO_ADDRESS - PAGE_SIZE, MACH_VM_JUMBO_ADDRESS);
	kr = vm_map_range_configure(map, false);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3u((int)map->uses_user_ranges, ==, true);
	vm_map_destroy(map);

	/* try with entry before the jumbo space. This is just like a normal entry such as the program text. */
	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, vm_compute_max_offset(true), 0);
	vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	kr = vm_map_range_configure(map, false);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3u((int)map->uses_user_ranges, ==, true);
	vm_map_destroy(map);

	/* try extra jumbo */
	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, vm_compute_max_offset(true), 0);
	kr = vm_map_range_configure(map, true);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3u((int)map->uses_user_ranges, ==, true);
	vm_map_destroy(map);
#endif /* CONFIG_MAP_RANGES */

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_range_configure_test, vm_map_range_configure_test);

#if CONFIG_SPTM

static void
page_clean_timeout(thread_call_param_t param0, __unused thread_call_param_t param1)
{
	vm_page_t m = (vm_page_t)param0;
	vm_object_t object = VM_PAGE_OBJECT(m);
	vm_object_lock(object);
	m->vmp_cleaning = false;
	vm_page_wakeup(object, m);
	vm_object_unlock(object);
}

/**
 * This sysctl is meant to exercise very specific functionality that can't be exercised through
 * the normal vm_map_create_upl() path.  It operates directly against the vm_object backing
 * the specified address range, and does not take any locks against the VM map to guarantee
 * stability of the specified address range.  It is therefore meant to be used against
 * VM regions directly allocated by the userspace caller and guaranteed to not be altered by
 * other threads.  The regular vm_upl/vm_upl_submap sysctls should be preferred over this
 * if at all possible.
 */
static int
vm_upl_object_test(int64_t in, int64_t *out __unused)
{
	upl_t upl = NULL;

	struct {
		uint64_t ptr; /* Base address of buffer in userspace */
		uint32_t size; /* Size of userspace buffer (in bytes) */
		bool upl_rw;
		bool should_fail; /* Is UPL creation expected to fail due to permissions checking? */
		uint8_t fault_prot;
	} args;
	int error = copyin((user_addr_t)in, &args, sizeof(args));
	if ((error != 0) || (args.size == 0)) {
		goto upl_object_test_done;
	}

	upl_size_t upl_size = args.size;
	unsigned int upl_count = 0;
	upl_control_flags_t upl_flags = UPL_SET_IO_WIRE | UPL_SET_LITE | UPL_SET_INTERNAL;
	if (!args.upl_rw) {
		upl_flags |= UPL_COPYOUT_FROM;
	} else {
		upl_flags |= UPL_WILL_MODIFY;
	}

	vm_map_entry_t entry;
	vm_object_t object;
	vm_page_t m __unused;

	vm_map_ilk_lock(current_map());
	entry = vm_map_lookup(current_map(), args.ptr);
	if (entry == VM_MAP_ENTRY_NULL || entry->is_sub_map) {
		vm_map_ilk_unlock(current_map());
		error = ENOENT;
		printf("%s: did not find entry at beginning of UPL region\n", __func__);
		goto upl_object_test_done;
	}
	vm_map_ilk_unlock(current_map());

	object = VME_OBJECT(entry);
	if (object == VM_OBJECT_NULL) {
		error = ENOENT;
		printf("%s: No VM object associated with entry at beginning of UPL region\n", __func__);
		goto upl_object_test_done;
	}

	vm_object_reference(object);

	kern_return_t kr = vm_object_iopl_request(object,
	    (vm_object_offset_t)(args.ptr - entry->vme_start + VME_OFFSET(entry)),
	    upl_size,
	    &upl,
	    NULL,
	    &upl_count,
	    upl_flags,
	    VM_KERN_MEMORY_DIAG);

	if (args.fault_prot != VM_PROT_NONE) {
		/*
		 * The page may have already been retyped to its "final" executable type by a prior fault,
		 * so simulate a page recycle operation in order to ensure that our simulated exec fault below
		 * will attempt to retype it.
		 */
		vm_object_lock(object);
		m = vm_page_lookup(object, (VME_OFFSET(entry) + ((vm_map_address_t)args.ptr - entry->vme_start)));
		assert(m != VM_PAGE_NULL);
		assert(VM_PAGE_IOPL_WIRED(m));
		ppnum_t pn = VM_PAGE_GET_PHYS_PAGE(m);
		pmap_disconnect(pn);
		pmap_lock_phys_page(pn);
		pmap_recycle_page(pn);
		pmap_unlock_phys_page(pn);
		assertf(pmap_will_retype(current_map()->pmap, (vm_map_address_t)args.ptr, VM_PAGE_GET_PHYS_PAGE(m), args.fault_prot,
		    (entry->vme_xnu_user_debug ? PMAP_OPTIONS_XNU_USER_DEBUG : 0), PMAP_MAPPING_TYPE_INFER),
		    "pmap will not retype for vm_page_t %p, prot 0x%x", m, (unsigned int)args.fault_prot);
		vm_object_unlock(object);
	}

	if (args.should_fail && (kr == KERN_PROTECTION_FAILURE)) {
		goto upl_object_test_done;
	} else if (args.should_fail && (kr == KERN_SUCCESS)) {
		printf("%s: vm_object_iopl_request(%p, 0x%lx) did not fail as expected\n",
		    __func__, (void*)args.ptr, (unsigned long)args.size);
		error = EIO;
		goto upl_object_test_done;
	} else if (kr != KERN_SUCCESS) {
		printf("%s: vm_object_iopl_request(%p, 0x%lx) returned 0x%x\n",
		    __func__, (void*)args.ptr, (unsigned long)args.size, kr);
		error = kr;
		goto upl_object_test_done;
	}

	if (args.fault_prot != VM_PROT_NONE) {
		kr = vm_fault(current_map(),
		    (vm_map_address_t)args.ptr,
		    args.fault_prot,
		    FALSE,
		    VM_KERN_MEMORY_NONE,
		    THREAD_UNINT,
		    NULL,
		    0);
		/* Page retype attempt with in-flight IOPL should be forbidden. */
		if (kr != KERN_PROTECTION_FAILURE) {
			printf("%s: vm_fault(%p) did not fail as expected\n", __func__, (void*)args.ptr);
			error = ((kr == KERN_SUCCESS) ? EIO : kr);
			goto upl_object_test_done;
		}
		assertf(pmap_will_retype(current_map()->pmap, (vm_map_address_t)args.ptr, VM_PAGE_GET_PHYS_PAGE(m), args.fault_prot,
		    (entry->vme_xnu_user_debug ? PMAP_OPTIONS_XNU_USER_DEBUG : 0), PMAP_MAPPING_TYPE_INFER),
		    "pmap will not retype for vm_page_t %p, prot 0x%x", m, (unsigned int)args.fault_prot);
	}

upl_object_test_done:

	if (upl != NULL) {
		upl_commit(upl, NULL, 0);
		upl_deallocate(upl);
	}

	if ((error == 0) && (args.fault_prot != VM_PROT_NONE)) {
		/*
		 * Exec page retype attempt without in-flight IOPL should ultimately succeed, but should
		 * block if the page is being cleaned.  Simulate that scenario with a thread call to "finish"
		 * the clean operation and wake up the waiting fault handler after 1s.
		 */
		vm_object_lock(object);
		assert(!VM_PAGE_IOPL_WIRED(m));
		m->vmp_cleaning = true;
		vm_object_unlock(object);
		thread_call_t page_clean_timer_call = thread_call_allocate(page_clean_timeout, m);
		uint64_t deadline;
		clock_interval_to_deadline(1, NSEC_PER_SEC, &deadline);
		thread_call_enter_delayed(page_clean_timer_call, deadline);
		kr = vm_fault(current_map(),
		    (vm_map_address_t)args.ptr,
		    args.fault_prot,
		    FALSE,
		    VM_KERN_MEMORY_NONE,
		    THREAD_UNINT,
		    NULL,
		    0);
		/*
		 * Thread call should no longer be active, as its expiry should have been the thing that
		 * unblocked the fault above.
		 */
		assert(!thread_call_isactive(page_clean_timer_call));
		thread_call_free(page_clean_timer_call);
		if (kr != KERN_SUCCESS) {
			printf("%s: vm_fault(%p) did not succeed as expected\n", __func__, (void*)args.ptr);
			error = kr;
		}
	}

	if (object != VM_OBJECT_NULL) {
		vm_object_deallocate(object);
	}

	return error;
}
SYSCTL_TEST_REGISTER(vm_upl_object, vm_upl_object_test);

#endif /* CONFIG_SPTM */

static int
vm_test_vm_map_protect_pmap_max(int64_t in __unused, int64_t *out)
{
#if CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS
	vm_map_t map = current_map();
	vm_map_address_t pmap_max = 0;
	mach_vm_offset_t addr = 0;
	kern_return_t kr;
	mach_vm_size_t size;
	vm_map_kernel_flags_t flags;

	assert(map->pmap);
	pmap_max = map->pmap->max;
	assert(!(pmap_max & (PAGE_SIZE - 1)));
	if (pmap_max > map->max_offset) {
		size = roundup(pmap_max - (map->max_offset - 1), PAGE_SIZE);
	} else {
		size = PAGE_SIZE;
	}
	/* Make sure that `addr` is below map->max_offset so mach_vm_protect works */
	addr = pmap_max - size;
	assert3u(addr, <, map->max_offset);

	flags = VM_MAP_KERNEL_FLAGS_FIXED();
	/* It's possible for pmap->max > map->max */
	flags.vmkf_beyond_max = true;

	/* Allocate a page at addr */
	kr = mach_vm_allocate_kernel(
		map,
		(mach_vm_offset_ut *)&addr,
		size,
		flags);
	assert3u(kr, ==, KERN_SUCCESS);

	mach_vm_offset_t end = addr + size;
	assert3u(end, ==, pmap_max);

	/* Change the protections for the entry. */
	kr = mach_vm_protect(
		map,
		addr,
		size,
		FALSE,
		VM_PROT_READ);
	assert3u(kr, ==, KERN_SUCCESS);
#endif /* CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS */
	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_map_protect_pmap_max, vm_test_vm_map_protect_pmap_max);
