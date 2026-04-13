/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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

#include <darwintest.h>

#include <stdint.h>
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_vm.h"

#include <vm/vm_object_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_page_internal.h>
#include <vm/vm_entry_lock_internal.h>
#include <vm/memory_object_internal.h>
#include <kern/page_decrypt.h>
#include <sys/mman.h>
#include <mach/vm32_map_server.h>
#include <sys/bsdtask_info.h>
#include <vm/vm_fault.h>
#include <vm/vm_iokit.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_protos.h>
#include <vm/vm_test_utils_internal.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.vm_map_misc_api_tests"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true)
	);


static vm_map_entry_t
assert_lookup_entry(vm_map_t map, mach_vm_address_t addr)
{
	vm_map_ilk_lock(map);
	vm_map_entry_t entry = vm_map_lookup(map, addr);
	T_ASSERT_NE_PTR(entry, NULL,
	    "expected a map entry at map %p address 0x%llx",
	    map, addr);
	vm_map_ilk_unlock(map);
	return entry;
}

static __attribute__((overloadable)) vm_map_entry_t
enter_obj_entry(vm_map_t map, vm_map_address_t start, vm_map_size_t size, vm_prot_t cur_prot,
    bool needs_copy, vm_object_t obj, vm_object_offset_t offset)
{
	kern_return_t kr = vm_map_enter(map, &start, size, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(),
	    obj, offset, needs_copy, cur_prot, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");
	return assert_lookup_entry(map, start);
}

static __attribute__((overloadable)) vm_map_entry_t
enter_obj_entry(vm_map_t map, vm_map_address_t start, vm_map_size_t size, vm_prot_t cur_prot,
    bool needs_copy, vm_object_t obj)
{
	return enter_obj_entry(map, start, size, cur_prot, needs_copy, obj, 0);
}

static __attribute__((overloadable)) vm_map_entry_t
enter_obj_entry(vm_map_t map, vm_map_address_t start, vm_map_size_t size, vm_prot_t cur_prot,
    bool needs_copy)
{
	/* non NULL obj to avoid coalesce */
	return enter_obj_entry(map, start, size, cur_prot, needs_copy, vm_object_allocate(size, map->serial_id));
}

vm_map_address_t MAP_BASE = 0x010000000; // avoid the pmap_shared_region

__enum_closed_decl(map_options_t, uint8_t, {
	WITH_PAGE,
	WITH_OBJECT,
	NO_OBJECT,
	NO_OBJECT_NOT_WRITABLE,
	WITH_SUBMAP,
});

static vm_map_t
create_map(map_options_t options, bool two_entries)
{
	vm_map_address_t start = MAP_BASE;
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	kern_return_t kr;
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_FIXED();
	vm_object_t object = VM_OBJECT_NULL;

	if (options == WITH_OBJECT || options == WITH_PAGE) {
		object = vm_object_allocate(PAGE_SIZE, map->serial_id);
		if (options == WITH_PAGE) {
			vm_page_t m = vm_page_grab_options(0);
			T_ASSERT_NOTNULL(m, "page");
			m->vmp_busy = FALSE;
			vm_object_lock(object);
			vm_page_insert(m, object, vm_object_trunc_page(0));
			vm_object_unlock(object);
		}
	}
	if (options == WITH_SUBMAP) {
		vm_map_t submap = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
		submap->is_nested_map = true;
		submap->vmmap_sealed = VM_MAP_WILL_BE_SEALED;
		start = 0x180000000ULL;
		kr = vm_map_enter(map, &start, 0x180000000ULL, 0,
		    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true, .vmkf_nested_pmap = true), (vm_object_t) submap,
		    0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	} else {
		vm_prot_t prot = VM_PROT_DEFAULT;
		if (options == NO_OBJECT_NOT_WRITABLE) {
			prot = VM_PROT_READ;
		}
		kr = vm_map_enter(map, &start, PAGE_SIZE, 0,
		    VM_MAP_KERNEL_FLAGS_FIXED(), object,
		    0, false, prot, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	}

	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");

	if (two_entries) {
		start += PAGE_SIZE;
		kr = vm_map_enter(map, &start, PAGE_SIZE, 0,
		    VM_MAP_KERNEL_FLAGS_FIXED(),
		    object, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	}


	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");
	return map;
}

vm_page_t
get_first_page(vm_map_t map, vm_map_offset_t addr)
{
	vm_map_entry_t entry;

	entry = assert_lookup_entry(map, addr);

	vm_object_t object = VME_OBJECT(entry);
	vm_object_lock_shared(object);
	vm_page_t page = vm_page_lookup(object, 0);
	vm_object_unlock(object);

	// vm_entry_unlock_shared(map, entry);
	return page;
}

T_DECL(vm_map_sign_tests, "test vm_map_sign_tests")
{
	/* Test vm_map_sign working */
	vm_map_t map = create_map(WITH_PAGE, false);
	kern_return_t kr = vm_map_sign(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	vm_page_t page = get_first_page(map, MAP_BASE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_sign");
	T_ASSERT_EQ((int) page->vmp_cs_validated, VMP_CS_ALL_TRUE, "Sign worked");


	/* Test vm_map_sign changing bits  */
	page = get_first_page(map, MAP_BASE);
	page->vmp_busy = true;
	page->vmp_cs_validated = VMP_CS_ALL_FALSE;
	kr = vm_map_sign(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	T_ASSERT_EQ(kr, KERN_FAILURE, "vm_map_sign");
	T_ASSERT_EQ((int) page->vmp_cs_validated, VMP_CS_ALL_FALSE, "bits changed");

	/* Test vm_map_sign failing with null page */
	map = create_map(WITH_OBJECT, false);
	kr = vm_map_sign(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	page = get_first_page(map, MAP_BASE);
	T_ASSERT_EQ(kr, KERN_FAILURE, "vm_map_sign");

	/* Test vm_map_sign failing with no obj */
	map = create_map(NO_OBJECT, false);
	kr = vm_map_sign(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "vm_map_sign");

	/* Test vm_map_sign failing with a range too large*/
	map = create_map(WITH_PAGE, true);
	kr = vm_map_sign(map, MAP_BASE, MAP_BASE + PAGE_SIZE * 2);
	page = get_first_page(map, MAP_BASE);
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "vm_map_sign");
	T_ASSERT_EQ((int) page->vmp_cs_validated, VMP_CS_ALL_FALSE, "bits changed");

	/* Test vm_map_sign failing with submap */
	map = create_map(WITH_SUBMAP, false);
	kr = vm_map_sign(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "vm_map_sign");

	/* Test vm_map_sign failing with no map */
	kr = vm_map_sign(VM_MAP_NULL, MAP_BASE, MAP_BASE + PAGE_SIZE);
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "vm_map_sign");

	/* Test vm_map_sign failing with overflow */
	kr = vm_map_sign(map, MAP_BASE, MAP_BASE - PAGE_SIZE);
	T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "vm_map_sign");

	/* Test vm_map_sign failing with empty range */
	kr = vm_map_sign(vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0)
	    , MAP_BASE, MAP_BASE - PAGE_SIZE);
	T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "vm_map_sign");
}

struct pmap_remove_options_call;
typedef struct pmap_remove_options_call *pmap_remove_options_call_t;

extern pmap_remove_options_call_t make_pmap_remove_options_intercept(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	int options);

extern void _prepare_for_pmap_remove_options_call(pmap_remove_options_call_t *calls, uint32_t calls_count);
extern bool verify_pmap_remove_options_intercept_calls();
#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))
#define prepare_for_pmap_remove_options_call(calls) _prepare_for_pmap_remove_options_call((calls), countof((calls)))


T_DECL(vm_map_disconnect_page_mappings_tests, "test vm_map_disconnect_page_mappings")
{
	vm_map_t map = create_map(WITH_OBJECT, false);
	prepare_for_pmap_remove_options_call((pmap_remove_options_call_t[]){make_pmap_remove_options_intercept(map->pmap, MAP_BASE, MAP_BASE + PAGE_SIZE, 0)});
	int result = vm_map_disconnect_page_mappings(map, false);
	T_ASSERT_TRUE(verify_pmap_remove_options_intercept_calls(), "pmap remove worked");
	T_ASSERT_EQ(result, 0, "no physical footprint");

	map = create_map(NO_OBJECT, false);
	prepare_for_pmap_remove_options_call((pmap_remove_options_call_t[]){});
	result = vm_map_disconnect_page_mappings(map, false);
	T_ASSERT_TRUE(verify_pmap_remove_options_intercept_calls(), "pmap remove worked");
	T_ASSERT_EQ(result, 0, "no physical footprint");

	map = create_map(WITH_OBJECT, true);
	pmap_remove_options_call_t first = make_pmap_remove_options_intercept(map->pmap, MAP_BASE, MAP_BASE + PAGE_SIZE, 0);
	pmap_remove_options_call_t second = make_pmap_remove_options_intercept(map->pmap, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 2, 0);
	pmap_remove_options_call_t calls[] = {first, second};
	prepare_for_pmap_remove_options_call(calls);
	result = vm_map_disconnect_page_mappings(map, false);
	T_ASSERT_TRUE(verify_pmap_remove_options_intercept_calls(), "pmap remove worked");
	T_ASSERT_EQ(result, 0, "no physical footprint");

	map = create_map(WITH_SUBMAP, false);
	prepare_for_pmap_remove_options_call((pmap_remove_options_call_t[]){make_pmap_remove_options_intercept(map->pmap, 0x180000000ULL, 0x180000000ULL + 0x180000000ULL, 0)});
	result = vm_map_disconnect_page_mappings(map, true);
	T_ASSERT_TRUE(verify_pmap_remove_options_intercept_calls(), "pmap remove worked");
	T_ASSERT_EQ(result, 0, "no physical footprint");
}


T_DECL(vm_map_check_protection_tests, "test vm_map_check_protection")
{
	bool success;
	uint64_t map_start = 0x00001000000000;
	uint64_t map_end =   0xfffffffff00000;
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), map_start, map_end, 0);

	/* empty map */
	success = vm_map_check_protection(map, map_start, map_end, VM_PROT_DEFAULT, NULL);
	T_ASSERT_FALSE(success, "empty");

	/* Size zero test, no entry */
	success = vm_map_check_protection(map, map_start, map_start, VM_PROT_DEFAULT, NULL);
	T_ASSERT_FALSE(success, "size zero");

	vm_map_entry_t vm_entry = enter_obj_entry(map, map_start, PAGE_SIZE, VM_PROT_DEFAULT, false);

	/* Size zero test, yes entry */
	success = vm_map_check_protection(map, map_start, map_start, VM_PROT_DEFAULT, NULL);
	T_ASSERT_TRUE(success, "size zero with entry");

	/* normal call */
	success = vm_map_check_protection(map, map_start, map_start + PAGE_SIZE, VM_PROT_DEFAULT, NULL);
	T_ASSERT_TRUE(success, "valid call");

	success = vm_map_check_protection(map, map_start, map_start + PAGE_SIZE * 2, VM_PROT_DEFAULT, NULL);
	T_ASSERT_FALSE(success, "partially mapped range");

	vm_entry->protection = VM_PROT_READ;
	success = vm_map_check_protection(map, map_start, map_start + PAGE_SIZE, VM_PROT_DEFAULT, NULL);
	T_ASSERT_FALSE(success, "bad prots");

	map = create_map(WITH_OBJECT, false);
	bool result = vm_map_check_protection(map, MAP_BASE, MAP_BASE + PAGE_SIZE, VM_PROT_ALL, (vm_sanitize_caller_t) 1);
	T_ASSERT_TRUE(!result, "vm_map_check_protection");

	result = vm_map_check_protection(map, MAP_BASE, MAP_BASE + PAGE_SIZE, VM_PROT_DEFAULT, (vm_sanitize_caller_t) 1);
	T_ASSERT_TRUE(result, "vm_map_check_protection");
}


T_DECL(vm_map_purgable_control, "test vm_map_purgable_control")
{
	int state;
	vm_map_t map = create_map(WITH_SUBMAP, false);
	kern_return_t kr = vm_map_purgable_control(map, MAP_BASE, VM_PURGABLE_GET_STATE, &state);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ADDRESS, "vm_map_purgable_control");


	map = create_map(NO_OBJECT, false);
	kr = vm_map_purgable_control(map, MAP_BASE * 0x500, VM_PURGABLE_GET_STATE, &state);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ADDRESS, "vm_map_purgable_control");

	kr = vm_map_purgable_control(map, MAP_BASE, VM_PURGABLE_GET_STATE, &state);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ARGUMENT, "vm_map_purgable_control");

	map = create_map(NO_OBJECT_NOT_WRITABLE, false);
	kr = vm_map_purgable_control(map, MAP_BASE, VM_PURGABLE_SET_STATE, &state);
	T_ASSERT_EQ_INT(kr, KERN_PROTECTION_FAILURE, "vm_map_purgable_control");
}

T_DECL(vm_map_sizes, "test vm_map_sizes")
{
	uint64_t map_end = 0xfffffffff00000;
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, map_end, 0);
	mach_vm_size_t size, free, largest_free;

	/* Test with empty map */
	vm_map_sizes(map, &size, &free, &largest_free);
	T_ASSERT_EQ_ULLONG(size, map_end - MAP_BASE, "size");
	T_ASSERT_EQ_ULLONG(free, map_end - MAP_BASE, "free");
	T_ASSERT_EQ_ULLONG(largest_free, map_end - MAP_BASE, "largest free");

	/* test with one entry */
	vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	vm_map_sizes(map, &size, &free, &largest_free);
	T_ASSERT_EQ_ULLONG(size, map_end - MAP_BASE, "size");
	T_ASSERT_EQ_ULLONG(free, map_end - MAP_BASE - PAGE_SIZE, "free");
	T_ASSERT_EQ_ULLONG(largest_free, map_end - MAP_BASE - PAGE_SIZE, "largest free");

	/* Test largest_free != free */
	vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE * 3, MAP_BASE + PAGE_SIZE * 4);
	vm_map_sizes(map, &size, &free, &largest_free);
	T_ASSERT_EQ_ULLONG(size, map_end - MAP_BASE, "size");
	T_ASSERT_EQ_ULLONG(free, map_end - MAP_BASE - PAGE_SIZE * 2, "free");
	T_ASSERT_EQ_ULLONG(largest_free, map_end - MAP_BASE - PAGE_SIZE * 4, "largest free");

	/* null map */
	vm_map_sizes(VM_MAP_NULL, &size, &free, &largest_free);
	T_ASSERT_EQ_ULLONG(size, 0ULL, "size");
	T_ASSERT_EQ_ULLONG(free, 0ULL, "free");
	T_ASSERT_EQ_ULLONG(largest_free, 0ULL, "largest free");
}


T_DECL(vm_map_raise_min_offset, "test vm_map_raise_min_offset")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, 0xfffffffffffff, 0);

	kern_return_t kr = vm_map_raise_min_offset(map, MAP_BASE + PAGE_SIZE);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_raise_min_offset");
	T_ASSERT_EQ_ULLONG(map->min_offset, MAP_BASE + PAGE_SIZE, "min_offset");

	/* Try moving it back */
	kr = vm_map_raise_min_offset(map, MAP_BASE);
	T_ASSERT_NE_INT(kr, KERN_SUCCESS, "vm_map_raise_min_offset");
	T_ASSERT_EQ_ULLONG(map->min_offset, MAP_BASE + PAGE_SIZE, "min_offset");

	/* Try past max offset */
	kr = vm_map_raise_min_offset(map, 0xfffffffffffff + 1);
	T_ASSERT_NE_INT(kr, KERN_SUCCESS, "vm_map_raise_min_offset");
	T_ASSERT_EQ_ULLONG(map->min_offset, MAP_BASE + PAGE_SIZE, "min_offset");

	/* try past an entry */
	vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 2);
	kr = vm_map_raise_min_offset(map, MAP_BASE + PAGE_SIZE * 2);
	T_ASSERT_NE_INT(kr, KERN_SUCCESS, "vm_map_raise_min_offset");
	T_ASSERT_EQ_ULLONG(map->min_offset, MAP_BASE + PAGE_SIZE, "min_offset");
}

static void
check_tpro(vm_map_entry_t entry)
{
	T_ASSERT_EQ_INT((bool) entry->vme_permanent, true, "Permanent set");
	T_ASSERT_EQ_INT((bool) entry->used_for_tpro, true, "tpro set");
	T_ASSERT_EQ_INT((int) entry->protection, VM_PROT_READ, "prot set");
}

static void
check_not_tpro(vm_map_entry_t entry)
{
	T_ASSERT_EQ_INT((bool) entry->vme_permanent, false, "Permanent set");
	T_ASSERT_EQ_INT((bool) entry->used_for_tpro, false, "tpro set");
	T_ASSERT_EQ_INT((int) entry->protection, VM_PROT_DEFAULT, "prot set");
}

static void
init_entry_for_tpro(vm_map_entry_t entry)
{
	entry->vme_permanent = false;
	entry->max_protection = VM_PROT_DEFAULT;
	entry->protection = VM_PROT_DEFAULT;
	entry->used_for_tpro = false;
}

T_DECL(vm_map_set_tpro_range, "vm_map_set_tpro_range")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, 0xfffffffffffff, 0);
	vm_map_set_tpro(map);

	/* empty range */
	bool result = vm_map_set_tpro_range(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	T_ASSERT_EQ_INT(result, false, "vm_map_set_tpro_range");

	/* range with two entry */
	vm_map_entry_t entry = vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	vm_map_entry_t entry2 = vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 2);

	init_entry_for_tpro(entry);
	init_entry_for_tpro(entry2);
	result = vm_map_set_tpro_range(map, MAP_BASE, MAP_BASE + PAGE_SIZE * 2);
	T_ASSERT_EQ_INT(result, true, "vm_map_set_tpro_range");
	check_tpro(entry);
	check_tpro(entry2);

	/* test with submap in range */
	entry->is_sub_map = true;
	init_entry_for_tpro(entry);
	init_entry_for_tpro(entry2);

	result = vm_map_set_tpro_range(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	T_ASSERT_EQ_INT(result, false, "vm_map_set_tpro_range");
	check_not_tpro(entry);
	check_not_tpro(entry2);

	/* test with hole */
	entry->is_sub_map = false;
	vm_map_entry_t entry3 = vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE * 3, MAP_BASE + PAGE_SIZE * 4);
	result = vm_map_set_tpro_range(map, MAP_BASE, MAP_BASE + PAGE_SIZE * 4);
	T_ASSERT_EQ_INT(result, false, "vm_map_set_tpro_range");
	check_tpro(entry);
	check_tpro(entry2);
	check_not_tpro(entry3);

	/* test null map */
	result = vm_map_set_tpro_range(VM_MAP_NULL, MAP_BASE, MAP_BASE + PAGE_SIZE);
	T_ASSERT_EQ_INT(result, false, "vm_map_set_tpro_range");
}


#if VM_SCAN_FOR_SHADOW_CHAIN

T_DECL(vm_map_shadow_max, "test vm_map_shadow_max")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, 0xfffffffffffff, 0);

	/* null map */
	int result = vm_map_shadow_max(VM_MAP_NULL);
	T_ASSERT_EQ_INT(result, 0, "null map");

	/* empty map */
	result = vm_map_shadow_max(map);
	T_ASSERT_EQ_INT(result, 0, "empty map");

	vm_map_entry_t entry = vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	vm_map_entry_t entry2 = vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 2);

	/* null objs */
	result = vm_map_shadow_max(map);
	T_ASSERT_EQ_INT(result, 0, "null obj");

	/* submap too */
	vm_map_entry_t entry3 = vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE * 2, MAP_BASE + PAGE_SIZE * 3);
	entry3->is_sub_map = true;
	vm_map_t submap = vm_map_create_options(kernel_pmap, MAP_BASE, 0xfffffffffffff, 0);
	assert(vm_entry_try_lock_exclusive(entry3));
	VME_SUBMAP_SET(entry3, submap);
	vm_entry_unlock_exclusive(map, entry3);

	result = vm_map_shadow_max(map);
	T_ASSERT_EQ_INT(result, 0, "with submap");

	vm_object_t obj = vm_object_allocate(PAGE_SIZE, map->serial_id);
	assert(vm_entry_try_lock_exclusive(entry));
	VME_OBJECT_SET(entry, obj, false, 0);
	vm_entry_unlock_exclusive(map, entry);

	/* with an obj */
	result = vm_map_shadow_max(map);
	T_ASSERT_EQ_INT(result, 0, "no shadow");

	/* with obj with shadow depth 1 */
	obj->shadow = vm_object_allocate(PAGE_SIZE, map->serial_id);
	result = vm_map_shadow_max(map);
	T_ASSERT_EQ_INT(result, 1, "depth 1");

	/* and with obj of shadow depth 2 */
	vm_object_t obj2 = vm_object_allocate(PAGE_SIZE, map->serial_id);
	assert(vm_entry_try_lock_exclusive(entry2));
	VME_OBJECT_SET(entry2, obj2, false, 0);
	vm_entry_unlock_exclusive(map, entry2);
	obj2->shadow = vm_object_allocate(PAGE_SIZE, map->serial_id);
	obj2->shadow->shadow = vm_object_allocate(PAGE_SIZE, map->serial_id);

	result = vm_map_shadow_max(map);
	T_ASSERT_EQ_INT(result, 2, "depth 2");
}
#endif /* VM_SCAN_FOR_SHADOW_CHAIN */

T_DECL(vm_map_entry_has_device_pager, "test vm_map_entry_has_device_pager")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, MAP_BASE + PAGE_SIZE * 20, 0); /* from range_configure */

	/* NULL MAP*/
	bool result = vm_map_entry_has_device_pager(VM_MAP_NULL, MAP_BASE);
	T_ASSERT_EQ_INT(result, false, "null map");

	/* no entry */
	result = vm_map_entry_has_device_pager(map, MAP_BASE);
	T_ASSERT_EQ_INT(result, false, "no entry");

	vm_map_entry_t entry = vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);

	/* no obj */
	result = vm_map_entry_has_device_pager(map, MAP_BASE);
	T_ASSERT_EQ_INT(result, false, "no obj");


	/* no pager */
	vm_object_t obj = vm_object_allocate(PAGE_SIZE, map->serial_id);
	assert(vm_entry_try_lock_exclusive(entry));
	VME_OBJECT_SET(entry, obj, false, 0);
	vm_entry_unlock_exclusive(map, entry);
	result = vm_map_entry_has_device_pager(map, MAP_BASE);
	T_ASSERT_EQ_INT(result, false, "no pager");

	/* wrong pager */
	vm_object_lock(obj);
	vm_object_compressor_pager_create(obj);
	vm_object_unlock(obj);
	result = vm_map_entry_has_device_pager(map, MAP_BASE);
	T_ASSERT_EQ_INT(result, false, "wrong pager");

	/* And right pager*/
	vm_object_t device_pager_obj = memory_object_to_vm_object(device_pager_setup((memory_object_t) NULL, (uintptr_t) NULL, PAGE_SIZE, 0));
	assert(vm_entry_try_lock_exclusive(entry));
	VME_OBJECT_SET(entry, device_pager_obj, false, 0);
	vm_entry_unlock_exclusive(map, entry);
	result = vm_map_entry_has_device_pager(map, MAP_BASE);
	T_ASSERT_EQ_INT(result, true, "device pager");
}

T_DECL(vm_map_set_cache_attr, "test vm_map_set_cache_attr")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, 0xfffffffffff0000, 0);
	kern_return_t kr;

	/* empty map */
	kr = vm_map_set_cache_attr(map, MAP_BASE);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ADDRESS, "empty map");

	vm_map_entry_t entry = vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);

	/* null objs */
	kr = vm_map_set_cache_attr(map, MAP_BASE);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ARGUMENT, "null obj");

	/* submap test */
	vm_map_entry_t entry2 = vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 2);
	entry2->is_sub_map = true;
	vm_map_t submap = vm_map_create_options(kernel_pmap, MAP_BASE, 0xfffffffffffff, 0);
	assert(vm_entry_try_lock_exclusive(entry2));
	VME_SUBMAP_SET(entry2, submap);
	vm_entry_unlock_exclusive(map, entry2);

	kr = vm_map_set_cache_attr(map, MAP_BASE + PAGE_SIZE);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ARGUMENT, "with submap");

	vm_object_t obj = vm_object_allocate(PAGE_SIZE, map->serial_id);
	assert(vm_entry_try_lock_exclusive(entry));
	VME_OBJECT_SET(entry, obj, false, 0);
	vm_entry_unlock_exclusive(map, entry);

	/* with an obj */
	obj->set_cache_attr = false;
	kr = vm_map_set_cache_attr(map, MAP_BASE);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_set_cache_attr");
	T_ASSERT_EQ_INT((int)obj->set_cache_attr, true, "vm_map_set_cache_attr");
}

T_DECL(vm_map_apple_protected, "test vm_map_apple_protected")
{
	struct pager_crypt_info crypt_info = {};
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, 0xfffffffffff0000, 0);
	kern_return_t kr;

	/* empty map */
	kr = vm_map_apple_protected(map, MAP_BASE, MAP_BASE + PAGE_SIZE, 0, &crypt_info, CRYPTID_APP_ENCRYPTION);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ADDRESS, "empty map");

	vm_map_entry_t entry = vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);
	T_ASSERT_EQ(entry->vme_start, (vm_map_offset_t)MAP_BASE, "entry");

	/* null objs */
	kr = vm_map_apple_protected(map, MAP_BASE, MAP_BASE + PAGE_SIZE, 0, &crypt_info, CRYPTID_APP_ENCRYPTION);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ARGUMENT, "null obj");
	T_ASSERT_EQ_PTR(entry, assert_lookup_entry(map, MAP_BASE), "entry should not change");

	/* overflowing values */
	kr = vm_map_apple_protected(map, MAP_BASE, MAP_BASE - PAGE_SIZE, 0, &crypt_info, CRYPTID_APP_ENCRYPTION);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ADDRESS, "overflow");
	T_ASSERT_EQ_PTR(entry, assert_lookup_entry(map, MAP_BASE), "entry should not change");

	vm_map_entry_t entry2 = vm_test_add_map_entry(map, 0x180000000ULL, 0x180000000ULL * 2);
	entry2->is_sub_map = true;
	vm_map_t submap = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	submap->is_nested_map = true;
	assert(vm_entry_try_lock_exclusive(entry2));
	VME_SUBMAP_SET(entry2, submap);
	vm_entry_unlock_exclusive(map, entry2);

	/* submap */
	kr = vm_map_apple_protected(map, 0x180000000ULL, 0x180000000ULL + PAGE_SIZE * 2, 0, &crypt_info, CRYPTID_APP_ENCRYPTION);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ARGUMENT, "with submap");
	T_ASSERT_EQ_PTR(entry, assert_lookup_entry(map, MAP_BASE), "entry should not change");

	vm_object_t obj = vm_object_allocate(PAGE_SIZE, map->serial_id);
	assert(vm_entry_try_lock_exclusive(entry));
	VME_OBJECT_SET(entry, obj, false, 0);
	vm_entry_unlock_exclusive(map, entry);

	/* with obj */
	kr = vm_map_apple_protected(map, MAP_BASE, MAP_BASE + PAGE_SIZE, 0, &crypt_info, CRYPTID_APP_ENCRYPTION);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ARGUMENT, "with obj bad perms");
	T_ASSERT_EQ_PTR(entry, assert_lookup_entry(map, MAP_BASE), "entry should not change");

	/* add exec, strip write, try again */
	entry->protection |= VM_PROT_EXECUTE;
	entry->protection &= ~VM_PROT_WRITE;
	kr = vm_map_apple_protected(map, MAP_BASE, MAP_BASE + PAGE_SIZE, 0, &crypt_info, CRYPTID_APP_ENCRYPTION);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_apple_protected valid setup");
	{
		vm_map_entry_t new_entry = assert_lookup_entry(map, MAP_BASE);
		T_ASSERT_NE_PTR(entry, new_entry, "entry should change");
		entry = new_entry;
	}

	/* strip exec, try model */
	entry->protection &= ~VM_PROT_EXECUTE;
	kr = vm_map_apple_protected(map, MAP_BASE, MAP_BASE + PAGE_SIZE, 0, &crypt_info, CRYPTID_MODEL_ENCRYPTION);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_apple_protected valid setup");
	{
		vm_map_entry_t new_entry = assert_lookup_entry(map, MAP_BASE);
		T_ASSERT_NE_PTR(entry, new_entry, "entry should change");
		entry = new_entry;
	}

	/* test clipping */
	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, 0xfffffffffff0000, 0);
	entry = vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE * 3);
	obj = vm_object_allocate(PAGE_SIZE * 3, map->serial_id);
	assert(vm_entry_try_lock_exclusive(entry));
	VME_OBJECT_SET(entry, obj, false, 0);
	vm_entry_unlock_exclusive(map, entry);

	kr = vm_map_apple_protected(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 2, 0, &crypt_info, CRYPTID_MODEL_ENCRYPTION);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_apple_protected valid setup");
	entry = assert_lookup_entry(map, MAP_BASE + PAGE_SIZE);
	T_ASSERT_EQ_ULLONG(entry->vme_start, MAP_BASE + PAGE_SIZE, "clipped start");
	T_ASSERT_EQ_ULLONG(entry->vme_end, MAP_BASE + PAGE_SIZE * 2, "clipped end");
}


#ifdef HAS_MTE
extern kern_return_t vm_map_page_tags_get(vm_map_t map, vm_address_t page_addr, uint64_t *buf, vm_size_t size);
T_DECL(vm_map_page_tags_get, "test vm_map_page_tags_get")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, 0xfffffffffff0000, 0);
	kern_return_t kr;
	uint64_t buf[64];


	/* empty map */
	kr = vm_map_page_tags_get(map, MAP_BASE, buf, sizeof(buf));
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ADDRESS, "empty map");

	vm_map_entry_t entry = vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);

	/* null objs */
	kr = vm_map_page_tags_get(map, MAP_BASE, buf, sizeof(buf));
	T_ASSERT_EQ_INT(kr, KERN_FAILURE, "null obj");

	/* submap test */
	vm_map_entry_t entry2 = vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 2);
	entry2->is_sub_map = true;
	vm_map_t submap = vm_map_create_options(kernel_pmap, MAP_BASE, 0xfffffffffffff, 0);
	assert(vm_entry_try_lock_exclusive(entry2));
	VME_SUBMAP_SET(entry2, submap);
	vm_entry_unlock_exclusive(map, entry2);

	kr = vm_map_page_tags_get(map, MAP_BASE, buf, sizeof(buf));
	T_ASSERT_EQ_INT(kr, KERN_FAILURE, "with submap");

	vm_object_t obj = vm_object_allocate(PAGE_SIZE, map->serial_id);
	assert(vm_entry_try_lock_exclusive(entry));
	VME_OBJECT_SET(entry, obj, false, 0);
	vm_entry_unlock_exclusive(map, entry);

	/* with an obj */
	kr = vm_map_page_tags_get(map, MAP_BASE, buf, sizeof(buf));
	T_ASSERT_EQ_INT(kr, KERN_FAILURE, "vm_map_set_cache_attr");

	/* with a mte obj */
	obj->wimg_bits = VM_WIMG_MTE;
	kr = vm_map_page_tags_get(map, MAP_BASE, buf, sizeof(buf));
	T_ASSERT_EQ_INT(kr, KERN_FAILURE, "no page");

	/* grab a page, mark it wired, fill the tag buffer */
	vm_page_t page = vm_page_grab_options(VM_PAGE_GRAB_MTE);
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
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "no page");

	page->vmp_wire_count--;

	T_ASSERT_EQ_INT(0, memcmp(&buf, &written_tags, sizeof(buf)), "memcmp");
}

#endif

#ifdef CONFIG_FREEZE
#include <vm/vm_pageout.h>
T_DECL(vm_map_freeze, "test vm_map_freeze")
{
	uint32_t purge_count, wired_count, clean_count, dirty_count, dirty_budget = 100, shared_count;
	int error;

	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, 0xfffffffffff0000, 0);
	kern_return_t kr;
	current_task()->map = map;
	vm_config.freezer_swap_is_active = true;

	/* test empty map */
	kr = vm_map_freeze(current_task(), &purge_count, &wired_count, &clean_count, &dirty_count, dirty_budget, &shared_count, &error, FREEZE_NONE);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_freeze");

	vm_map_entry_t entry = vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);

	/* test no object */
	kr = vm_map_freeze(current_task(), &purge_count, &wired_count, &clean_count, &dirty_count, dirty_budget, &shared_count, &error, FREEZE_NONE);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_freeze");


	/* Test with a page */
	vm_object_t obj = vm_object_allocate(PAGE_SIZE, map->serial_id);
	assert(vm_entry_try_lock_exclusive(entry));
	VME_OBJECT_SET(entry, obj, false, 0);
	vm_entry_unlock_exclusive(map, entry);

	vm_page_t page = vm_page_grab_options(0);
	vm_object_lock(obj);
	vm_page_insert(page, obj, vm_object_trunc_page(0));
	vm_object_unlock(obj);

	kr = vm_map_freeze(current_task(), &purge_count, &wired_count, &clean_count, &dirty_count, dirty_budget, &shared_count, &error, FREEZE_NONE);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_freeze");
	vm_object_lock_shared(obj);
	T_ASSERT_TRUE(vm_page_queue_empty(&obj->memq), "pages removed");
	vm_object_unlock(obj);

	/* test with shared object and page */
	vm_object_reference(obj);

	page = vm_page_grab_options(0);
	vm_object_lock(obj);
	vm_page_insert(page, obj, vm_object_trunc_page(0));
	vm_object_unlock(obj);

	kr = vm_map_freeze(current_task(), &purge_count, &wired_count, &clean_count, &dirty_count, dirty_budget, &shared_count, &error, FREEZE_NONE);
	T_ASSERT_EQ_INT(kr, KERN_FAILURE, "vm_map_freeze");
	vm_object_lock_shared(obj);
	T_ASSERT_TRUE(!vm_page_queue_empty(&obj->memq), "pages not removed");
	vm_object_unlock(obj);

	/* and test eval only doesn't do anything */
	vm_object_deallocate(obj);
	kr = vm_map_freeze(current_task(), &purge_count, &wired_count, &clean_count, &dirty_count, dirty_budget, &shared_count, &error, FREEZE_EVAL_ONLY);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_freeze");
	vm_object_lock_shared(obj);
	T_ASSERT_TRUE(!vm_page_queue_empty(&obj->memq), "pages not removed");
	vm_object_unlock(obj);
}
#endif /* CONFIG_FREEZE */

static vm_map_t
setup_vm_map_region_recurse_64_submap_map()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	kern_return_t kr;
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_FIXED();
	vm_object_t object = VM_OBJECT_NULL;

	vm_map_address_t start = MAP_BASE;

	/* MAP_BASE object */
	kr = vm_map_enter(map, &start, PAGE_SIZE, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL,
	    0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);

	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");

	/* 0x180000000ULL submap */
	vm_map_t submap = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	submap->is_nested_map = true;
	start = 0x180000000ULL;
	submap->vmmap_sealed = VM_MAP_WILL_BE_SEALED;
	kr = vm_map_enter(map, &start, 0x180000000ULL, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true, .vmkf_nested_pmap = true), (vm_object_t) submap,
	    0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_SHARE);

	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");

	/* Entry at 0 of submap */
	start = 0;
	kr = vm_map_enter(submap, &start, PAGE_SIZE, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(),
	    VM_OBJECT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");

	/* Entry at PAGE_SIZE * 2 of submap */
	start = PAGE_SIZE * 2;
	kr = vm_map_enter(submap, &start, PAGE_SIZE * 2, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(),
	    VM_OBJECT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");


	vm_map_seal(submap, true);

	return map;
}

/* test we get the proper share_mode from region recurse */
static void
vm_map_region_recurse_64_share_tests()
{
	vm_map_t map = create_map(WITH_OBJECT, false);
	vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 2);
	vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE * 3, MAP_BASE + PAGE_SIZE * 4);
	vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE * 5, MAP_BASE + PAGE_SIZE * 15);

	vm_map_entry_t entry;
	struct vm_region_submap_info_64 submap_info;
	vm_map_address_t addr = MAP_BASE;
	vm_map_size_t size;
	natural_t depth = 1;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	vm_object_t obj;
	kern_return_t kr;
	entry = assert_lookup_entry(map, addr);
	obj = VME_OBJECT(entry);
	/* Take one obj ref outside of map */
	vm_object_reference(obj);

	vm_object_lock(obj);
	obj->has_been_shared_permanently = true; /* Mark it has been shared, but never clipped */
	vm_object_unlock(obj);
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");
	T_ASSERT_EQ_INT(submap_info.share_mode, SM_SHARED, "Should be shared");

	/* And mark it clipped */
	vm_object_lock(obj);
	obj->has_been_clipped = true;
	vm_object_unlock(obj);
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");
	T_ASSERT_EQ_INT(submap_info.share_mode, SM_SHARED_ALIASED, "Should be shared and aliased");


	/* And unmark it shared */
	vm_object_lock(obj);
	obj->has_been_shared_permanently = false;
	vm_object_unlock(obj);
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");
	T_ASSERT_EQ_INT(submap_info.share_mode, SM_PRIVATE_ALIASED, "Should be private aliased");
}

/* test the short info flavor of vm_map_region_recurse*/
static void
vm_map_region_recurse_64_short_info_tests()
{
	vm_map_t map = setup_vm_map_region_recurse_64_submap_map();

	/* Quick test to make sure short_info isn't completely broken */
	struct vm_region_submap_short_info_64 submap_info;
	vm_map_address_t addr = MAP_BASE;
	vm_map_size_t size;
	natural_t depth = 1;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;

	kern_return_t kr = vm_map_region_recurse_64(map, &addr, &size, &depth, (vm_region_submap_info_64_t) &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");
}
#include <vm/vm_iokit.h>
#include <kern/ledger.h>

static void
init_task_with_ledgers(task_t new_task)
{
	task_objq_lock_init(new_task);
	lck_mtx_init(&new_task->lock, &task_lck_grp, &task_lck_attr);

	queue_init(&new_task->task_objq);

	task_t ktask = kernel_task;
	kernel_task = NULL;
	init_task_ledgers();
	current_task()->ledger = ledger_instantiate(&task_ledger_template);
	kernel_task = ktask;
}

static vm_map_t
create_vm_map_with_ledger_tagged_obj(
	mach_vm_address_t addr,
	vm_object_t obj,
	mach_vm_size_t mapping_size)
{
	/* Make a map, add the object */
	pmap_t pmap = pmap_create_options(current_task()->ledger, 0, PMAP_CREATE_64BIT);
	vm_map_t map = vm_map_create_options(pmap, 0, 0xffff00000, 0); /* smaller map so we can test footprint feature */
	T_ASSERT_EQ_PTR(current_task()->ledger, map->pmap->ledger, "pmap");

	/* And create an object that will be billed in the ledger */
	vm_object_lock(obj);
	obj->copy_strategy = MEMORY_OBJECT_COPY_NONE;

	kern_return_t kr = vm_object_ownership_change(
		obj,
		VM_LEDGER_TAG_DEFAULT,
		current_task(),                 /* new owner */
		0,
		FALSE);                 /* task_objq locked? */
	vm_object_unlock(obj);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_object_ownership_change");

	kr = vm_map_enter(map, &addr, mapping_size, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(), obj,
	    0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "mach_vm_map");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "addr correct");

	return map;
}

static void
insert_page_into_obj_to_increase_phys_footprint(vm_object_t obj)
{
	/* Insert a page, so we can increase the physical footprint */
	vm_page_t m = vm_page_grab_options(0);
	T_ASSERT_NOTNULL(m, "page");
	vm_object_lock(obj);
	obj->purgable = VM_PURGABLE_VOLATILE;
	vm_page_insert(m, obj, vm_object_trunc_page(0));
	vm_page_lockspin_queues();
	vm_page_wire(m, VM_KERN_MEMORY_OSFMK, false);
	vm_page_unlock_queues();
	vm_object_unlock(obj);
}

/*
 * Test to see if the proper thing is returned when there is a physical footprint
 * and task_region_footprint is true.
 * It should be a "fake entry" after the last entry in the map
 */
static void
vm_map_region_recurse_64_physical_footprint_tests()
{
	kern_return_t kr;
	mach_vm_size_t size;
	ipc_port_t mem_entry;
	mach_vm_address_t addr = MAP_BASE;

	/* Setup the task/ledger */
	init_task_with_ledgers(current_task());
	task_self_region_footprint_set(true);

	/* Make a map, add the object */
	vm_object_t obj = vm_object_allocate(PAGE_SIZE * 2, VM_MAP_SERIAL_NONE);
	vm_map_t map = create_vm_map_with_ledger_tagged_obj(addr, obj, PAGE_SIZE);

	/* Check simple case vm region works */
	struct vm_region_submap_info_64 submap_info;
	natural_t depth = 1;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;

	/* first entry */
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");

	/* Check vm_region's fake region. We have no footprint yet, so this should fail */
	addr = MAP_BASE + PAGE_SIZE;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ADDRESS, "vm_map_region_recurse_64");

	insert_page_into_obj_to_increase_phys_footprint(obj);

	/* And check the physical footprint actually accounts for the page we added */
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE + PAGE_SIZE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");
}

/*
 * Test region recurse on a map with a submap.
 * Make sure the address/depth work properly
 */
static void
vm_map_region_recurse_64_submap_tests()
{
	vm_map_t map = setup_vm_map_region_recurse_64_submap_map();


	struct vm_region_submap_info_64 submap_info;
	vm_map_address_t addr = MAP_BASE;
	vm_map_size_t size;
	natural_t depth = 1;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;

	/* first entry */
	kern_return_t kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");

	/* first entry again, addr in the entry */
	addr = MAP_BASE + 1;
	depth = 1;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");

	/* Test we get the submap entry with a depth = 0, addr before start */
	addr = MAP_BASE + PAGE_SIZE;
	depth = 0;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, 0x180000000ULL, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) 0x180000000ULL, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");

	/* Test we get the submap entry with a depth = 0, addr at start */
	addr = 0x180000000ULL;
	depth = 0;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, 0x180000000ULL, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) 0x180000000ULL, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");

	/* Test we get the submap entry with a depth = 0, addr in entry */
	addr = 0x190000000ULL;
	depth = 0;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, 0x180000000ULL, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) 0x180000000ULL, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");


	/* And now the with depth != 0 */

	/* addr before entry */
	addr = MAP_BASE + PAGE_SIZE + 1;
	depth = 100;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, 0x180000000ULL, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 1, "depth correct");

	/* Addr at start */
	addr = 0x180000000ULL;
	depth = 100;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, 0x180000000ULL, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 1, "depth correct");

	/* Addr in entry */
	addr = 0x180000001ULL;
	depth = 100;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, 0x180000000ULL, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 1, "depth correct");

	/* Addr in auto inserted hole filling gap in sealed submap */
	addr = 0x180000000ULL + PAGE_SIZE;
	depth = 100;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, 0x180000000ULL + PAGE_SIZE * 1, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 1, "depth correct");

	/* Addr at second entry in submap */
	addr = 0x180000000ULL + PAGE_SIZE * 2;
	depth = 100;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, 0x180000000ULL + PAGE_SIZE * 2, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE * 2, "size correct");
	T_ASSERT_EQ_INT(depth, 1, "depth correct");

	/* Addr at gap at the end */
	addr = 0x180000000ULL + PAGE_SIZE * 4;
	depth = 100;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, 0x180000000ULL + PAGE_SIZE * 4, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) 0x17fff0000, "size correct");
	T_ASSERT_EQ_INT(depth, 1, "depth correct");

	/* Addr still in gap at the end */
	addr = 0x190000000ULL;
	depth = 100;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, 0x180000000ULL + PAGE_SIZE * 4, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) 0x17fff0000, "size correct");
	T_ASSERT_EQ_INT(depth, 1, "depth correct");

	/* Addr after the end of everything */
	addr = 0x180000000ULL * 2;
	depth = 100;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ADDRESS, "vm_map_region_recurse_64");

	/* then test after anything (depth=0)*/
	addr = 0x180000000ULL * 2;
	depth = 0;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ADDRESS, "vm_map_region_recurse_64");
}

/*
 * Check region recurse gives the right addr/size/depth for various calls
 * on a basic map. The map includes a gap from MAP_BASE + PAGE_SIZE * 2 to
 * MAP_BASE + PAGE_SIZE * 3 and PAGE_SIZE*4, PAGE_SIZE*5
 */
static void
vm_map_region_recurse_64_basic_map_tests()
{
	vm_map_t map = create_map(NO_OBJECT, false);
	vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 2);
	vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE * 3, MAP_BASE + PAGE_SIZE * 4);
	vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE * 5, MAP_BASE + PAGE_SIZE * 15);


	struct vm_region_submap_info_64 submap_info;
	vm_map_address_t addr = MAP_BASE;
	vm_map_size_t size;
	natural_t depth = 1;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	/* first entry, addr at start */
	kern_return_t kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");

	/* first entry again, addr in the entry */
	addr = MAP_BASE + 1;
	depth = 1;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");

	/* first entry again, addr near the end of the entry */
	addr = MAP_BASE + PAGE_SIZE - 1;
	depth = 1;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");


	/* second entry, addr at start */
	addr = MAP_BASE + PAGE_SIZE;
	depth = 1;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE + PAGE_SIZE, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");

	/* third entry , checking the gap is handled correctly */
	addr = MAP_BASE + PAGE_SIZE * 2;
	depth = 1;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE + PAGE_SIZE * 3, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");

	/* fourth entry, checking the unusual size is handled correctly */
	addr = MAP_BASE + PAGE_SIZE * 4;
	depth = 1;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "vm_map_region_recurse_64");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE + PAGE_SIZE * 5, "addr correct");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE * 10, "size correct");
	T_ASSERT_EQ_INT(depth, 0, "depth correct");

	/* then test after anything */
	addr = MAP_BASE + PAGE_SIZE * 15;
	depth = 100;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	kr = vm_map_region_recurse_64(map, &addr, &size, &depth, &submap_info, &count);
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ADDRESS, "vm_map_region_recurse_64");
}


T_DECL(vm_map_region_recurse, "test vm_map_region_recurse")
{
	vm_map_region_recurse_64_basic_map_tests();
	vm_map_region_recurse_64_submap_tests();
	vm_map_region_recurse_64_share_tests();
	vm_map_region_recurse_64_short_info_tests();
	vm_map_region_recurse_64_physical_footprint_tests();
}

static void
basic_checker(void * data, vm_prot_t prot)
{
	vm_region_basic_info_t basic = (vm_region_basic_info_t) data;
	T_ASSERT_EQ_INT(basic->protection, prot, "protection");
}

static void
basic64_checker(void * data, vm_prot_t prot)
{
	vm_region_basic_info_64_t basic  = (vm_region_basic_info_64_t)data;
	T_ASSERT_EQ_INT(basic->protection, prot, "protection");
}

static void
extended_checker(void * data, vm_prot_t prot)
{
	vm_region_extended_info_t extended = (vm_region_extended_info_t) data;
	T_ASSERT_EQ_INT(extended->protection, prot, "protection");
	T_ASSERT_EQ_INT(extended->share_mode, SM_EMPTY, "share mode");
}


static void
extended_checker__legacy(void * data, vm_prot_t prot)
{
	vm_region_extended_info_t extended = (vm_region_extended_info_t) data;
	T_ASSERT_EQ_INT(extended->protection, prot, "protection");
	T_ASSERT_EQ_INT(extended->share_mode, SM_EMPTY, "share mode");
}

static void
top_checker(void * data, vm_prot_t prot)
{
	vm_region_top_info_t top = (vm_region_top_info_t) data;
	T_ASSERT_EQ_INT(top->shared_pages_resident, 0, "pages resident");
	T_ASSERT_EQ_INT(top->share_mode, SM_EMPTY, "share mode");
}

/*
 * Run a variety of tests, checking the address and size are always as expected
 * Additionally a checker can be supplied to verify the protection
 * (and any other flavor specific attributes are correct)
 */
static void
run_vm_region_tests(
	vm_map_t map,
	void * type,
	void (*checker)(void *, vm_prot_t),
	vm_region_flavor_t flavor,
	int count_expected)
{
	mach_vm_size_t size;
	mach_vm_address_t addr;
	kern_return_t kr;
	mach_msg_type_number_t count = count_expected;

	addr = MAP_BASE;
	kr = vm_map_region(map, &addr, &size, flavor, (vm_region_info_t) type, &count, NULL);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "region ");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "region addr");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size");
	checker(type, VM_PROT_READ);

	addr += 1;
	kr = vm_map_region(map, &addr, &size, flavor, (vm_region_info_t) type, &count, NULL);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "region (VM_REGION_BASIC_INFO)");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE, "region (VM_REGION_BASIC_INFO) addr");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size");
	checker(type, VM_PROT_READ);

	addr += PAGE_SIZE;
	kr = vm_map_region(map, &addr, &size, flavor, (vm_region_info_t) type, &count, NULL);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "region (VM_REGION_BASIC_INFO)");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE + PAGE_SIZE, "region (VM_REGION_BASIC_INFO) addr");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE, "size");
	checker(type, VM_PROT_DEFAULT);

	addr = MAP_BASE + PAGE_SIZE * 5;
	kr = vm_map_region(map, &addr, &size, flavor, (vm_region_info_t) type, &count, NULL);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "region (VM_REGION_BASIC_INFO)");
	T_ASSERT_EQ_ULLONG(addr, MAP_BASE + PAGE_SIZE * 3, "region (VM_REGION_BASIC_INFO) addr");
	T_ASSERT_EQ_ULLONG(size, (unsigned long long) PAGE_SIZE * 12, "size");
	checker(type, VM_PROT_DEFAULT);
}

T_DECL(vm_map_region, "test vm_map_region")
{
	vm_map_t map = create_map(NO_OBJECT_NOT_WRITABLE, false);
	vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 2);
	vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE * 3, MAP_BASE + PAGE_SIZE * 15);

	struct vm_region_basic_info basic;
	run_vm_region_tests(map, &basic, basic_checker, VM_REGION_BASIC_INFO, VM_REGION_BASIC_INFO_COUNT);

	struct vm_region_basic_info_64 basic64;
	run_vm_region_tests(map, &basic64, basic64_checker, VM_REGION_BASIC_INFO_64, VM_REGION_BASIC_INFO_COUNT_64);

	struct vm_region_extended_info extended;
	run_vm_region_tests(map, &extended, extended_checker, VM_REGION_EXTENDED_INFO, VM_REGION_EXTENDED_INFO_COUNT);

	struct vm_region_extended_info__legacy extended_legacy;
	run_vm_region_tests(map, &extended, extended_checker__legacy, VM_REGION_EXTENDED_INFO__legacy, VM_REGION_EXTENDED_INFO_COUNT__legacy);

	struct vm_region_top_info top;
	run_vm_region_tests(map, &top, top_checker, VM_REGION_TOP_INFO, VM_REGION_TOP_INFO_COUNT);
}



static vm_page_info_basic_t
call_vm_map_page_range_info_internal(
	vm_map_t map,
	mach_vm_address_t start,
	mach_vm_address_t end,
	kern_return_t expected_kr)
{
	uint64_t num_pages = end - start;
	vm_map_size_t info_size = num_pages * sizeof(vm_page_info_basic_data_t);
	void * info = kalloc_data(info_size, Z_WAITOK);
	mach_msg_type_number_t count = VM_PAGE_INFO_BASIC_COUNT;

	kern_return_t kr = vm_map_page_range_info_internal(map, start, end,
	    vm_map_page_shift(map), VM_PAGE_INFO_BASIC, info, &count);
	T_ASSERT_EQ_INT(kr, expected_kr, "vm_map_page_range_info_internal");

	return (vm_page_info_basic_t)info;
}

static void
check_vm_page_info_basic_t(
	vm_page_info_basic_t info,
	int ref_count,
	int depth,
	int disposition,
	mach_vm_offset_t offset)
{
	T_QUIET; T_ASSERT_EQ_INT(info->ref_count, ref_count, "Ref count");
	T_QUIET; T_ASSERT_EQ_ULLONG(info->offset, offset, "offset");
	T_QUIET; T_ASSERT_EQ_INT(info->depth, depth, "depth");
	T_QUIET; T_ASSERT_EQ_INT(info->disposition, disposition, "disposition");
}
/* Check to make sure the physical footprint option works properly */
static void
test_vm_map_page_range_info_internal_footprint()
{
	vm_object_t obj = vm_object_allocate(PAGE_SIZE * 2, VM_MAP_SERIAL_NONE);

	init_task_with_ledgers(current_task());
	task_self_region_footprint_set(true);

	vm_map_t map = create_vm_map_with_ledger_tagged_obj(MAP_BASE, obj, PAGE_SIZE);
	kern_return_t kr;

	/* Basic test to make sure simple calls work */
	vm_page_info_basic_t info = call_vm_map_page_range_info_internal(map, MAP_BASE, MAP_BASE + PAGE_SIZE, KERN_SUCCESS);
	T_ASSERT_NE_PTR(NULL, info, "call_vm_map_page_range_info_internal");
	check_vm_page_info_basic_t(info, 1, 0, 0, 0);

	/* Check the fake region. We have no footprint yet, but it assumes any calls are valid and returns info for it. */
	info = call_vm_map_page_range_info_internal(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 3, KERN_SUCCESS);
	T_ASSERT_NE_PTR(NULL, info, "call_vm_map_page_range_info_internal");
	check_vm_page_info_basic_t(info, 1, 0, VM_PAGE_QUERY_PAGE_PAGED_OUT, 0);
	check_vm_page_info_basic_t(&info[1], 1, 0, VM_PAGE_QUERY_PAGE_PRESENT | VM_PAGE_QUERY_PAGE_DIRTY | VM_PAGE_QUERY_PAGE_REF, 0);

	insert_page_into_obj_to_increase_phys_footprint(obj);

	/* And now redo the call with a page. */
	info = call_vm_map_page_range_info_internal(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 3, KERN_SUCCESS);
	check_vm_page_info_basic_t(info, 1, 0, VM_PAGE_QUERY_PAGE_PAGED_OUT, 0);
	check_vm_page_info_basic_t(&info[1], 1, 0, VM_PAGE_QUERY_PAGE_PRESENT | VM_PAGE_QUERY_PAGE_DIRTY | VM_PAGE_QUERY_PAGE_REF, 0);

	/* And then turn off the footprint option, check we get 0s for the gap. */
	task_self_region_footprint_set(false);
	info = call_vm_map_page_range_info_internal(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 3, KERN_SUCCESS);
	T_ASSERT_NE_PTR(NULL, info, "call_vm_map_page_range_info_internal");
	check_vm_page_info_basic_t(info, 0, 0, 0, 0);
	check_vm_page_info_basic_t(&info[1], 0, 0, 0, 0);
}

/* Check to make sure we get the function doesn't change any ref counts accidentally */
static void
test_vm_map_page_range_info_internal_obj_refcount()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	vm_object_t object = vm_object_allocate(PAGE_SIZE, map->serial_id);
	vm_object_t shadow = vm_object_allocate(PAGE_SIZE, map->serial_id);
	object->shadow = shadow;
	shadow->vo_copy = object;

	vm_object_reference(shadow); /* Make it have refcount of 2 */
	enter_obj_entry(map, MAP_BASE, PAGE_SIZE, VM_PROT_DEFAULT, false, object);

	call_vm_map_page_range_info_internal(map, MAP_BASE, MAP_BASE + PAGE_SIZE, KERN_SUCCESS);
	T_ASSERT_EQ(os_ref_get_count_raw(&shadow->ref_count), 2, "shadow refcount");
	T_ASSERT_EQ(os_ref_get_count_raw(&object->ref_count), 1, "object refcount");
}

/* Test if the call starts below map min we get the right behavior */
static void
test_vm_map_page_range_beyond_map_min()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE - PAGE_SIZE, MAP_BASE + PAGE_SIZE, 0);

	vm_object_t obj1 = vm_object_allocate(PAGE_SIZE, map->serial_id);
	vm_object_t obj2 = vm_object_allocate(PAGE_SIZE, map->serial_id);
	vm_object_reference(obj1);
	enter_obj_entry(map, MAP_BASE - PAGE_SIZE, PAGE_SIZE, VM_PROT_DEFAULT, false, obj1); /* entry before map min */
	enter_obj_entry(map, MAP_BASE, PAGE_SIZE, VM_PROT_DEFAULT, false, obj2);
	map->min_offset += PAGE_SIZE;

	vm_page_info_basic_t info;

	/* Test before map min */
	info = call_vm_map_page_range_info_internal(map, MAP_BASE - PAGE_SIZE, MAP_BASE + PAGE_SIZE, KERN_SUCCESS);
	check_vm_page_info_basic_t(info, 2, 0, 0, 0);
	check_vm_page_info_basic_t(&info[1], 1, 0, 0, 0);
}


/* Test if the call starts above map max we get the right behavior */
static void
test_vm_map_page_range_beyond_map_max()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), MAP_BASE, MAP_BASE + PAGE_SIZE * 2, 0);

	vm_object_t obj1 = vm_object_allocate(PAGE_SIZE, map->serial_id);
	vm_object_t obj2 = vm_object_allocate(PAGE_SIZE, map->serial_id);
	vm_object_reference(obj1);
	enter_obj_entry(map, MAP_BASE, PAGE_SIZE, VM_PROT_DEFAULT, false, obj1); /* entry before map min */
	enter_obj_entry(map, MAP_BASE + PAGE_SIZE, PAGE_SIZE, VM_PROT_DEFAULT, false, obj2);
	map->min_offset -= PAGE_SIZE;

	vm_page_info_basic_t info;

	/* Test after map max */
	info = call_vm_map_page_range_info_internal(map, MAP_BASE, MAP_BASE + PAGE_SIZE * 2, KERN_SUCCESS);
	check_vm_page_info_basic_t(info, 2, 0, 0, 0);
	check_vm_page_info_basic_t(&info[1], 1, 0, 0, 0);
}

/* Check we get the proper offsets returned */
static void
test_vm_map_page_range_offsets()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_object_t obj1 = vm_object_allocate(PAGE_SIZE, map->serial_id);
	vm_object_t obj2 = vm_object_allocate(PAGE_SIZE, map->serial_id);

	enter_obj_entry(map, MAP_BASE, PAGE_SIZE, VM_PROT_DEFAULT, false, obj1); /* entry before map min */
	/* PAGE_SIZE gap */
	enter_obj_entry(map, MAP_BASE + PAGE_SIZE * 2, PAGE_SIZE * 3, VM_PROT_DEFAULT, false, obj2);
	/* obj2 is [page, empty ]*/
	insert_page_into_obj_to_increase_phys_footprint(obj2);

	vm_page_info_basic_t info;
	info = call_vm_map_page_range_info_internal(map, MAP_BASE, MAP_BASE + PAGE_SIZE * 6, KERN_SUCCESS);
	check_vm_page_info_basic_t(info, 1, 0, 0, 0);
	check_vm_page_info_basic_t(&info[1], 0, 0, 0, 0);
	check_vm_page_info_basic_t(&info[2], 1, 0, VM_PAGE_QUERY_PAGE_PRESENT, 0);
	check_vm_page_info_basic_t(&info[3], 1, 0, 0, PAGE_SIZE);
	check_vm_page_info_basic_t(&info[4], 1, 0, 0, PAGE_SIZE * 2);
	check_vm_page_info_basic_t(&info[5], 0, 0, 0, 0);

	T_LOG("done with %p", map);
}


/* Check we get the right shadow chain depth */
static void
test_vm_map_page_range_depth()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_object_t obj1 = vm_object_allocate(PAGE_SIZE, map->serial_id);
	vm_object_t obj2 = vm_object_allocate(PAGE_SIZE, map->serial_id);
	vm_object_reference(obj2); /* prevent panic on shadow chain collapse */

	enter_obj_entry(map, MAP_BASE, PAGE_SIZE, VM_PROT_DEFAULT, false, obj2);

	obj2->shadow = obj1;
	insert_page_into_obj_to_increase_phys_footprint(obj1);

	vm_page_info_basic_t info;
	info = call_vm_map_page_range_info_internal(map, MAP_BASE, MAP_BASE + PAGE_SIZE, KERN_SUCCESS);
	check_vm_page_info_basic_t(info, 2, 1, VM_PAGE_QUERY_PAGE_PRESENT, 0);
}

static void
test_vm_map_page_range_submap()
{
	vm_map_t map = setup_vm_map_region_recurse_64_submap_map();
	task_self_region_footprint_set(true);

	vm_page_info_basic_t info;
	info = call_vm_map_page_range_info_internal(map, 0x180000000ULL, 0x180000000ULL + PAGE_SIZE * 2, KERN_SUCCESS);
	check_vm_page_info_basic_t(info, 1, 0, 0, 0);
}

static void
test_vm_map_page_range_hole_at_end()
{
	vm_object_t obj = vm_object_allocate(PAGE_SIZE * 2, VM_MAP_SERIAL_NONE);

	/* First, let's test without the footprint */
	vm_map_t map = create_vm_map_with_ledger_tagged_obj(MAP_BASE, obj, PAGE_SIZE);
	/* and throw an entry super late in the map */
	vm_test_add_map_entry(map, MAP_BASE + PAGE_SIZE * 50, MAP_BASE + PAGE_SIZE * 51);
	kern_return_t kr;
	task_self_region_footprint_set(false);

	/* Basic test to make sure simple calls work. Include a gap at the end */
	vm_page_info_basic_t info = call_vm_map_page_range_info_internal(map, MAP_BASE, MAP_BASE + PAGE_SIZE * 2, KERN_SUCCESS);
	T_ASSERT_NE_PTR(NULL, info, "call_vm_map_page_range_info_internal");
	check_vm_page_info_basic_t(info, 1, 0, 0, 0);
	check_vm_page_info_basic_t(&info[1], 0, 0, 0, 0); /* gap */

	/* starting and ending in the gap */
	info = call_vm_map_page_range_info_internal(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 3, KERN_SUCCESS);
	T_ASSERT_NE_PTR(NULL, info, "call_vm_map_page_range_info_internal");
	check_vm_page_info_basic_t(info, 0, 0, 0, 0);
	check_vm_page_info_basic_t(&info[1], 0, 0, 0, 0); /* gap */
	check_vm_page_info_basic_t(&info[2], 0, 0, 0, 0); /* gap */

	/* at the fake region, starting in gap  */
	info = call_vm_map_page_range_info_internal(map, MAP_BASE + PAGE_SIZE * 49, MAP_BASE + PAGE_SIZE * 51, KERN_SUCCESS);
	check_vm_page_info_basic_t(info, 0, 0, 0, 0);
	check_vm_page_info_basic_t(&info[1], 0, 0, 0, 0); /* gap */

	/* enable the footprint */
	task_self_region_footprint_set(true);

	insert_page_into_obj_to_increase_phys_footprint(obj);

	/* valid start, end in gap */
	info = call_vm_map_page_range_info_internal(map, MAP_BASE, MAP_BASE + PAGE_SIZE * 2, KERN_SUCCESS);
	T_ASSERT_NE_PTR(NULL, info, "call_vm_map_page_range_info_internal");
	check_vm_page_info_basic_t(info, 1, 0, 0, 0);
	check_vm_page_info_basic_t(&info[1], 0, 0, 0, 0); /* gap */

	/* starting an ending in the gap */
	info = call_vm_map_page_range_info_internal(map, MAP_BASE + PAGE_SIZE, MAP_BASE + PAGE_SIZE * 3, KERN_SUCCESS);
	check_vm_page_info_basic_t(info, 0, 0, 0, 0);
	check_vm_page_info_basic_t(&info[1], 0, 0, 0, 0); /* gap */
	check_vm_page_info_basic_t(&info[2], 0, 0, 0, 0); /* gap */

	/* at the fake region, starting in gap  */
	info = call_vm_map_page_range_info_internal(map, MAP_BASE + PAGE_SIZE * 49, MAP_BASE + PAGE_SIZE * 52, KERN_SUCCESS);
	check_vm_page_info_basic_t(info, 0, 0, 0, 0);
	check_vm_page_info_basic_t(&info[1], 0, 0, 0, 0); /* gap */
	check_vm_page_info_basic_t(&info[2], 1, 0, VM_PAGE_QUERY_PAGE_PAGED_OUT, 0); /* fake region */
}

T_DECL(vm_map_page_range_info_internal, "test vm_map_page_range_info_internal")
{
	/* This function already has pretty thorough tests from the vm_configurator via mincore. */

	test_vm_map_page_range_info_internal_footprint();
	test_vm_map_page_range_info_internal_obj_refcount();
	test_vm_map_page_range_beyond_map_min();
	test_vm_map_page_range_beyond_map_max();
	test_vm_map_page_range_offsets();
	test_vm_map_page_range_depth();
	test_vm_map_page_range_submap();
	test_vm_map_page_range_hole_at_end();
}


static void
vm_map_corpse_tests()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	T_ASSERT_EQ_INT(vm_map_is_corpse_source(map), false, "vm_map_is_corpse_source");
	vm_map_set_corpse_source(map);
	T_ASSERT_EQ_INT(vm_map_is_corpse_source(map), true, "vm_map_is_corpse_source");
	vm_map_unset_corpse_source(map);
	T_ASSERT_EQ_INT(vm_map_is_corpse_source(map), false, "vm_map_is_corpse_source");

	vm_map_destroy(map);
}

static void
vm_map_alien_tests()
{
#if XNU_TARGET_OS_OSX
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	T_ASSERT_EQ_INT(vm_map_is_alien(map), false, "alien");
	vm_map_mark_alien(map);
	T_ASSERT_EQ_INT(vm_map_is_alien(map), true, "alien");
	vm_map_destroy(map);
#endif /* XNU_TARGET_OS_OSX */
}



static void
vm_map_sec_access_tests()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	T_ASSERT_EQ_INT(vm_map_has_sec_access(map), false, "sec_access");
	vm_map_mark_has_sec_access(map);
	T_ASSERT_EQ_INT(vm_map_has_sec_access(map), true, "sec_access");
	vm_map_remove_sec_access(map);
	T_ASSERT_EQ_INT(vm_map_has_sec_access(map), false, "sec_access");
	vm_map_ilk_lock(map);
	vm_map_mark_has_sec_access_ilocked(map);
	vm_map_ilk_unlock(map);
	T_ASSERT_EQ_INT(vm_map_has_sec_access(map), true, "sec_access");

	vm_map_destroy(map);
}

static void
vm_map_tpro_tests()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	T_ASSERT_EQ_INT(vm_map_tpro_enforcement(map), false, "tpro off");
	map->pmap->xprr_tpro_enabled = true;
	vm_map_set_tpro_enforcement(map);
	T_ASSERT_EQ_INT(vm_map_tpro_enforcement(map), true, "tpro on");

	vm_map_destroy(map);
}


static void
vm_map_single_jit_tests()
{
#if XNU_TARGET_OS_OSX
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	T_ASSERT_EQ_INT((int) map->single_jit, false, "single_jit");
	vm_map_single_jit(map);
	T_ASSERT_EQ_INT((int) map->single_jit, true, "single_jit");
	vm_map_destroy(map);
#endif  /* XNU_TARGET_OS_OSX */
}

static void
vm_map_setup_tests()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	vm_map_setup(map, current_task());
	T_ASSERT_EQ_PTR(map->owning_task, current_task(), "task set");

	vm_map_destroy(map);
}

static void
vm_map_max_addr_tests()
{
	vm_map_address_t starting_max = 0xffffc0000;
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, starting_max, 0);
	vm_map_set_max_addr(map, starting_max - PAGE_SIZE, false);
	T_ASSERT_EQ_ULLONG(map->max_offset, starting_max, "unchanged when shrunk");
	vm_map_set_max_addr(map, starting_max + PAGE_SIZE, false);
	T_ASSERT_EQ_ULLONG(map->max_offset, starting_max + PAGE_SIZE, "changed");

	vm_map_address_t last_max_offset = map->max_offset;
	kern_return_t kr = vm_map_raise_max_offset(map, last_max_offset - PAGE_SIZE);
	T_ASSERT_EQ_ULLONG(map->max_offset, last_max_offset, "unchanged when shrunk");
	T_ASSERT_EQ_INT(kr, KERN_INVALID_ADDRESS, "offset shrunk");

	kr = vm_map_raise_max_offset(map, last_max_offset + PAGE_SIZE);
	T_ASSERT_EQ_ULLONG(map->max_offset, last_max_offset + PAGE_SIZE, "grew");
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "offset shrunk");

	vm_map_destroy(map);
}

static void
vm_map_limit_tests()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	vm_map_set_size_limit(map, 0);
	T_ASSERT_EQ_ULLONG(map->size_limit, 0ULL, "size limit set");

	vm_map_set_data_limit(map, 0);
	T_ASSERT_EQ_ULLONG(map->data_limit, 0ULL, "size limit set");

	vm_map_destroy(map);
}

static void
vm_map_switch_protect_tests()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	vm_map_switch_protect(map, true);
	T_ASSERT_EQ_INT((int) map->switch_protect, true, "switch_protect");
	vm_map_switch_protect(map, false);
	T_ASSERT_EQ_INT((int) map->switch_protect, false, "switch_protect");

	vm_map_destroy(map);
}

static void
vm_map_cs_debugged_set_tests()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	T_ASSERT_EQ_INT((int) map->cs_debugged, false, "cs_debugged");
	vm_map_cs_debugged_set(map, true);
	T_ASSERT_EQ_INT((int) map->cs_debugged, true, "cs_debugged");

	vm_map_destroy(map);
}

static void
vm_map_cs_enforcement_set_tests()
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	T_ASSERT_EQ_INT((int) map->cs_enforcement, false, "cs_debugged");
	vm_map_cs_enforcement_set(map, true);
	T_ASSERT_EQ_INT((int) map->cs_enforcement, true, "cs_debugged");

	vm_map_destroy(map);
}


T_DECL(bit_set_apis, "Test a bunch of bit setting APIs")
{
	vm_map_corpse_tests();
	vm_map_alien_tests();
	vm_map_sec_access_tests();
	vm_map_tpro_tests();
	vm_map_setup_tests();
	vm_map_max_addr_tests();
	vm_map_limit_tests();
	vm_map_switch_protect_tests();
	vm_map_cs_debugged_set_tests();
	vm_map_cs_enforcement_set_tests();
	vm_map_single_jit_tests();
}

T_DECL(vm_map_machine_attribute, "test vm_map_machine_attribute")
{
	vm_map_t map = create_map(WITH_PAGE, true);
	vm_machine_attribute_val_t value = 0;
	kern_return_t kr = vm_map_machine_attribute(map, MAP_BASE, MAP_BASE + PAGE_SIZE, MATTR_CACHE, &value);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_machine_attribute");
}

static void
test_fill_procregioninfo_footprint()
{
	int ret;
	struct proc_regioninfo_internal pinfo;
	uintptr_t vnodeaddr;
	uint32_t vid;

	task_t task = current_task();

	/* Setup the task/ledger */
	init_task_with_ledgers(task);
	task_self_region_footprint_set(true);

	/* Make a map, add the object */
	vm_object_t obj = vm_object_allocate(PAGE_SIZE * 2, VM_MAP_SERIAL_NONE);
	vm_map_t map = create_vm_map_with_ledger_tagged_obj(MAP_BASE, obj, PAGE_SIZE);
	task->map = map;

	/* empty ledgers */
	bzero(&pinfo, sizeof(pinfo));
	ret = fill_procregioninfo(task, MAP_BASE + PAGE_SIZE, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(0, ret, "fill_procregioninfo");

	insert_page_into_obj_to_increase_phys_footprint(obj);

	bzero(&pinfo, sizeof(pinfo));
	ret = fill_procregioninfo(task, MAP_BASE + PAGE_SIZE, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "fill_procregioninfo");

	task_self_region_footprint_set(false);
}


T_DECL(test_fill_procregioninfo, "Call fill_procregioninfo")
{
	int ret;
	struct proc_regioninfo_internal pinfo;
	uintptr_t vnodeaddr;
	uint32_t vid;
	task_t task = current_task();

	/* Setup the task/ledger */
	task_self_region_footprint_set(false);

	uint64_t map_start = 0x00001000000000;
	uint64_t map_end =   0xfffffffff00000;
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), map_start, map_end, 0);
	task->map = map;

	/* empty map */
	ret = fill_procregioninfo(task, map_start, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(0, ret, "Simple call fails because there is no entry");

	vm_map_entry_t vm_entry = enter_obj_entry(map, map_start, PAGE_SIZE, VM_PROT_READ, false);
	vm_map_entry_t vm_submap = vm_test_add_map_entry(map, map_start + PAGE_SIZE * 2, map_start + PAGE_SIZE * 4);
	vm_map_entry_t vm_entry1 = enter_obj_entry(map, map_start + PAGE_SIZE * 10, PAGE_SIZE, VM_PROT_DEFAULT, false);

	vm_submap->is_sub_map = true;
	vm_map_t submap = vm_map_create_options(NULL, 0x00001000000000, 0x00001000000000 + PAGE_SIZE, 0);
	submap->vmmap_sealed = VM_MAP_WILL_BE_SEALED;
	vm_map_seal(submap, false);
	assert(vm_entry_try_lock_exclusive(vm_submap));
	VME_SUBMAP_SET(vm_submap, submap);
	vm_entry_unlock_exclusive(map, vm_submap);

	vm_map_ilk_lock(map);
	assert3u(KERN_SUCCESS, ==, vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, vm_entry, map_start, THREAD_UNINT));
	vm_object_t obj = VME_OBJECT(vm_entry);
	vm_entry->protection = VM_PROT_READ;
	vm_entry_unlock_exclusive(map, vm_entry);
	vm_map_ilk_unlock(map);

	/* 1st entry */
	bzero(&pinfo, sizeof(pinfo));
	ret = fill_procregioninfo(task, map_start, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "fill_procregioninfo");
	T_ASSERT_EQ_INT(VM_PROT_READ, pinfo.pri_protection, "prot");
	T_ASSERT_EQ_INT(pinfo.pri_share_mode, SM_PRIVATE, "share_mode");
	T_ASSERT_EQ_ULLONG(pinfo.pri_address, map_start, "pri_address");
	T_ASSERT_EQ_INT(pinfo.pri_flags, 0, "pri_flags");

	/* submap */
	bzero(&pinfo, sizeof(pinfo));
	ret = fill_procregioninfo(task, map_start + PAGE_SIZE * 2, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "fill_procregioninfo");
	T_ASSERT_EQ_INT(VM_PROT_DEFAULT, pinfo.pri_protection, "prot");
	T_ASSERT_EQ_INT(pinfo.pri_share_mode, SM_EMPTY, "share_mode");
	T_ASSERT_EQ_ULLONG(pinfo.pri_address, map_start + PAGE_SIZE * 2, "pri_address");
	T_ASSERT_EQ_ULLONG(pinfo.pri_size, (uint64_t)PAGE_SIZE * 2, "pri_size");
	T_ASSERT_EQ_INT(pinfo.pri_flags, PROC_REGION_SUBMAP, "pri_flags");

	/* 3rd entry */
	bzero(&pinfo, sizeof(pinfo));
	ret = fill_procregioninfo(task, map_start + PAGE_SIZE * 10, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "fill_procregioninfo");
	T_ASSERT_EQ_INT(VM_PROT_DEFAULT, pinfo.pri_protection, "prot");
	T_ASSERT_EQ_INT(pinfo.pri_share_mode, SM_PRIVATE, "share_mode");
	T_ASSERT_EQ_ULLONG(pinfo.pri_address, map_start + PAGE_SIZE * 10, "pri_address");
	T_ASSERT_EQ_ULLONG(pinfo.pri_size, (uint64_t)PAGE_SIZE, "pri_size");
	T_ASSERT_EQ_INT(pinfo.pri_flags, 0, "pri_flags");

	/* 3rd entry starting before */
	bzero(&pinfo, sizeof(pinfo));
	ret = fill_procregioninfo(task, map_start + PAGE_SIZE * 9, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "fill_procregioninfo");
	T_ASSERT_EQ_INT(VM_PROT_DEFAULT, pinfo.pri_protection, "prot");
	T_ASSERT_EQ_INT(pinfo.pri_share_mode, SM_PRIVATE, "share_mode");
	T_ASSERT_EQ_ULLONG(pinfo.pri_address, map_start + PAGE_SIZE * 10, "pri_address");
	T_ASSERT_EQ_ULLONG(pinfo.pri_size, (uint64_t)PAGE_SIZE, "pri_size");
	T_ASSERT_EQ_INT(pinfo.pri_flags, 0, "pri_flags");

	/* last entry end */
	bzero(&pinfo, sizeof(pinfo));
	ret = fill_procregioninfo(task, map_start + PAGE_SIZE * 11, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(0, ret, "fill_procregioninfo");

	test_fill_procregioninfo_footprint();

	vm_map_guard_object_slab_init(map);
	task->map = map;

	vm_map_address_t guard_addr;
	kern_return_t kr = vm_map_enter(map, &guard_addr, 3 * PAGE_SIZE,
	    0, VM_MAP_KERNEL_FLAGS_ANYWHERE(),
	    VM_OBJECT_NULL, 0, false, VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "First guard object allocation should succeed");

	/* 3rd entry starting before */
	bzero(&pinfo, sizeof(pinfo));
	ret = fill_procregioninfo(task, guard_addr + 3 * PAGE_SIZE, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "fill_procregioninfo");
	T_ASSERT_EQ_INT(VM_PROT_NONE, pinfo.pri_protection, "prot");
	T_ASSERT_EQ_INT(pinfo.pri_share_mode, SM_EMPTY, "share_mode");
	T_ASSERT_EQ_ULLONG(pinfo.pri_address, guard_addr + 3 * PAGE_SIZE, "pri_address");
}

/*
 * Read-faults an address.
 * Requires the mocks installed by scoped_mocks_for_fault_addr().
 */
static void
fault_addr(vm_map_t map, mach_vm_address_t addr)
{
	kern_return_t kr;
	kr = vm_fault(map, addr, VM_PROT_READ, false, VM_KERN_MEMORY_NONE, 0, NULL, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "read fault map %p address 0x%llx", map, addr);
}

/*
 * Install the mocks needed by fault_addr().
 * These mocks expire at end of scope.
 */
#define scoped_mocks_for_fault_addr(void)                               \
	T_MOCK_SET_RETVAL(vm_fault_enter_prepare, kern_return_t, KERN_SUCCESS); \
	T_MOCK_SET_RETVAL(vm_fault_attempt_pmap_enter, kern_return_t, KERN_SUCCESS)

struct test_page_range_info_allocation {
	mach_vm_address_t start;
	mach_vm_address_t end;
	bool has_object;
};

static mach_vm_address_t
alloc_for_page_range_info_test(
	vm_map_t map,
	struct test_page_range_info_allocation *allocs)
{
	mach_vm_address_t last_end = 0;
	for (int i = 0; allocs[i].end != 0; i++) {
		mach_vm_address_t addr = allocs[i].start;
		mach_vm_size_t size = allocs[i].end - allocs[i].start;
		last_end = allocs[i].end;

		kern_return_t kr = mach_vm_allocate_kernel(map, &addr, size,
		    VM_MAP_KERNEL_FLAGS_FIXED());
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "alloc #%d addr 0x%llx size 0x%llx",
		    i, addr, size);

		if (allocs[i].has_object) {
			fault_addr(map, addr);
		}
	}
	return last_end;
}

static void
dealloc_for_page_range_info_test(
	vm_map_t map,
	struct test_page_range_info_allocation *allocs)
{
	for (int i = 0; allocs[i].end != 0; i++) {
		mach_vm_address_t addr = allocs[i].start;
		mach_vm_size_t size = allocs[i].end - allocs[i].start;

		kern_return_t kr = mach_vm_deallocate_kernel(map, addr, size);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "dealloc #%d addr 0x%llx size 0x%llx",
		    i, addr, size);
	}
}

static void
call_page_range_info_internal_with_page_shift(
	vm_map_t map,
	mach_vm_address_t query_start,
	mach_vm_address_t query_end,
	int effective_page_shift,
	const char *message)
{
	T_QUIET; T_ASSERT_TRUE(effective_page_shift == FOURK_PAGE_SHIFT ||
	    effective_page_shift == SIXTEENK_PAGE_SHIFT, "page size");
	int effective_page_size = 1 << effective_page_shift;

	T_QUIET; T_ASSERT_EQ(query_start % effective_page_size, 0ULL, "alignment");
	T_QUIET; T_ASSERT_EQ(query_end % effective_page_size, 0ULL, "alignment");
	unsigned int info_count = (query_end - query_start) / effective_page_size;
	vm_page_info_basic_data_t *info_array = calloc(sizeof(vm_page_info_basic_data_t), info_count + 2);
	unsigned int guard_prefix = 0;
	unsigned int guard_suffix = info_count + 1;
	memset(&info_array[guard_prefix], 0xAA, sizeof(info_array[guard_prefix]));
	memset(&info_array[guard_suffix], 0xAA, sizeof(info_array[guard_suffix]));

	mach_msg_type_number_t mig_count = VM_PAGE_INFO_BASIC_COUNT;
	kern_return_t kr = vm_map_page_range_info_internal(map,
	    query_start, query_end, effective_page_shift,
	    VM_PAGE_INFO_BASIC, (vm_page_info_t)&info_array[1], &mig_count);
	T_ASSERT_MACH_SUCCESS(kr, "vm_map_page_range_info_internal (%s)", message);
	T_QUIET; T_ASSERT_EQ(info_array[guard_prefix].depth, 0xAAAAAAAA, "prefix guard info (%s)", message);
	T_QUIET; T_ASSERT_EQ(info_array[guard_suffix].depth, 0xAAAAAAAA, "suffix guard info (%s)", message);
	free(info_array);
}

T_DECL(vm_map_page_range_info_internal_page_size_mismatch,
    "Test vm_map_page_range_info_internal where the "
    "effective page size is not the map's page size")
{
	/* TODO write more tests of these cases (rdar://160878279) */

	scoped_mocks_for_fault_addr();

	/*
	 * rdar://160380938
	 * If effective_page_size > map page size then
	 * `address += effective_page_size` may skip over an entire map entry.
	 *
	 * rdar://163529903
	 * `address += effective_page_size` may skip over an entire map entry
	 * and land in the next entry beyond its start.
	 *
	 * randomized seed 3156194068
	 * 4K-aligned hole with 16K-aligned size should not fill too many info elements.
	 *
	 * The loop in vm_map_page_range_info_internal must allow these.
	 *
	 * TODO (rdar://160878279) also verify the returned page info
	 */
	init_task_with_ledgers(current_task());

	mach_vm_address_t map_start = 0x100000000;
	mach_vm_address_t map_end = map_start * 2;
	T_QUIET; T_ASSERT_EQ(map_start % SIXTEENK_PAGE_SIZE, 0ULL, "16K alignment");

	vm_map_t map = vm_map_create_with_page_shift(
		pmap_create_options(NULL, 0, PMAP_CREATE_64BIT),
		map_start, map_end, FOURK_PAGE_SHIFT, 0);
	T_QUIET; T_ASSERT_NOTNULL(map, "map");

	mach_vm_address_t allocs_end;
	mach_vm_size_t size;
	kern_return_t kr;

	/* rdar://160380938 */
	struct test_page_range_info_allocation alloc_160380938[] = {
		{ .start = map_start + FOURK_PAGE_SIZE * 0, .end = map_start + FOURK_PAGE_SIZE * 1, .has_object = true  },
		{ .start = map_start + FOURK_PAGE_SIZE * 1, .end = map_start + FOURK_PAGE_SIZE * 2, .has_object = false },
		{ .start = map_start + FOURK_PAGE_SIZE * 2, .end = map_start + FOURK_PAGE_SIZE * 3, .has_object = false },
		{ .start = map_start + FOURK_PAGE_SIZE * 3, .end = map_start + FOURK_PAGE_SIZE * 4, .has_object = false },
		{ .start = map_start + FOURK_PAGE_SIZE * 4, .end = map_start + FOURK_PAGE_SIZE * 5, .has_object = false },
		{ .start = map_start + FOURK_PAGE_SIZE * 5, .end = map_start + FOURK_PAGE_SIZE * 6, .has_object = false },
		{ .start = map_start + FOURK_PAGE_SIZE * 6, .end = map_start + FOURK_PAGE_SIZE * 7, .has_object = false },
		{ .start = map_start + FOURK_PAGE_SIZE * 7, .end = map_start + FOURK_PAGE_SIZE * 8, .has_object = false },
		{ .end = 0 },
	};
	allocs_end = alloc_for_page_range_info_test(map, alloc_160380938);
	task_self_region_footprint_set(true);
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, FOURK_PAGE_SHIFT, "rdar://160380938 4K footprint");
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, SIXTEENK_PAGE_SHIFT, "rdar://160380938 16K footprint");
	task_self_region_footprint_set(false);
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, FOURK_PAGE_SHIFT, "rdar://160380938 4K no-footprint");
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, SIXTEENK_PAGE_SHIFT, "rdar://160380938 16K no-footprint");
	dealloc_for_page_range_info_test(map, alloc_160380938);

	/* rdar://163529903 */
	struct test_page_range_info_allocation alloc_163529903[] = {
		{ .start = map_start + FOURK_PAGE_SIZE * 0, .end = map_start + FOURK_PAGE_SIZE * 1, .has_object = true  },
		{ .start = map_start + FOURK_PAGE_SIZE * 1, .end = map_start + FOURK_PAGE_SIZE * 2, .has_object = false },
		{ .start = map_start + FOURK_PAGE_SIZE * 2, .end = map_start + FOURK_PAGE_SIZE * 3, .has_object = false },
		{ .start = map_start + FOURK_PAGE_SIZE * 3, .end = map_start + FOURK_PAGE_SIZE * 8, .has_object = false },
		{ .end = 0 },
	};
	allocs_end = alloc_for_page_range_info_test(map, alloc_163529903);
	task_self_region_footprint_set(true);
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, FOURK_PAGE_SHIFT, "rdar://163529903 4K footprint");
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, SIXTEENK_PAGE_SHIFT, "rdar://163529903 16K footprint");
	task_self_region_footprint_set(false);
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, FOURK_PAGE_SHIFT, "rdar://163529903 4K no-footprint");
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, SIXTEENK_PAGE_SHIFT, "rdar://163529903 16K no-footprint");
	dealloc_for_page_range_info_test(map, alloc_163529903);

	/* randomized seed 3156194068 */
	struct test_page_range_info_allocation alloc_3156194068[] = {
		{ .start = map_start + FOURK_PAGE_SIZE *  0, .end = map_start + FOURK_PAGE_SIZE *  2, .has_object = true },
		/* unallocated size FOURK_PAGE_SIZE * 12 */
		{ .start = map_start + FOURK_PAGE_SIZE * 14, .end = map_start + FOURK_PAGE_SIZE * 24, .has_object = true },
		{ .end = 0 },
	};
	allocs_end = alloc_for_page_range_info_test(map, alloc_3156194068);
	task_self_region_footprint_set(true);
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, FOURK_PAGE_SHIFT, "seed 3156194068 4K footprint");
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, SIXTEENK_PAGE_SHIFT, "seed 3156194068 16K footprint");
	task_self_region_footprint_set(false);
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, FOURK_PAGE_SHIFT, "seed 3156194068 4K no-footprint");
	call_page_range_info_internal_with_page_shift(map,
	    map_start, allocs_end, SIXTEENK_PAGE_SHIFT, "seed 3156194068 16K no-footprint");
	dealloc_for_page_range_info_test(map, alloc_3156194068);
}

static bool
random_hole(unsigned *seedp)
{
	/* 1/8 chance of hole */
	int r = rand_r(seedp);
	return r % 8 == 0;
}

static bool
random_fault(unsigned *seedp)
{
	/* 1/2 chance of fault */
	int r = rand_r(seedp);
	return r % 2 == 0;
}

static mach_vm_size_t
random_size_4K(unsigned *seedp)
{
	/* even distribution of (1..16) * FOURK_PAGE_SIZE */
	int r = rand_r(seedp);
	r = r % 16 + 1;
	return r * FOURK_PAGE_SIZE;
}

T_DECL(vm_map_page_range_info_internal_randomized,
    "Test vm_map_page_range_info_internal across randomized allocations and gaps")
{
	unsigned initial_seed;
	if (argc >= 1) {
		initial_seed = atoi(argv[0]);
		T_LOG("USING SPECIFIED RANDOM SEED %u\n", initial_seed);
	} else {
		initial_seed = arc4random();
		T_LOG("note: run `env VERBOSE=1 vm_map_misc_api_tests "
		    "-n vm_map_page_range_info_internal_randomized %u` to "
		    "re-run with this random seed and print the address space",
		    initial_seed);
	}
	unsigned seed = initial_seed;

	bool verbose = getenv("VERBOSE");

	scoped_mocks_for_fault_addr();
	init_task_with_ledgers(current_task());

	mach_vm_address_t map_start = 0x100000000;
	mach_vm_address_t map_end = map_start + 0x1000000;
	T_QUIET; T_ASSERT_EQ(map_start % SIXTEENK_PAGE_SIZE, 0ULL, "16K alignment");

	vm_map_t map = vm_map_create_with_page_shift(
		pmap_create_options(NULL, 0, PMAP_CREATE_64BIT),
		map_start, map_end, FOURK_PAGE_SHIFT, 0);
	T_QUIET; T_ASSERT_NOTNULL(map, "map");

	kern_return_t kr;

	/*
	 * Make many randomly-sized allocations and unallocated holes.
	 * Randomly fault in some of them to force an object to be created.
	 */
	mach_vm_address_t addr = map_start;
	while (addr < map_end) {
		bool hole = random_hole(&seed);
		bool fault = random_fault(&seed);
		mach_vm_size_t size = random_size_4K(&seed);

		if (addr + size >= map_end) {
			break;
		}

		if (hole) {
			if (verbose) {
				raw_printf("0x%llx..0x%llx hole\n", addr, addr + size);
			}
			addr += size;
			continue;
		}

		if (verbose) {
			raw_printf("0x%llx..0x%llx allocation%s\n",
			    addr, addr + size, fault ? " (faulted)" : "");
		}

		kr = mach_vm_allocate_kernel(map, &addr, size, VM_MAP_KERNEL_FLAGS_FIXED());
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "alloc addr 0x%llx size 0x%llx", addr, size);
		if (fault) {
			fault_addr(map, addr);
		}

		addr += size;
	}

	char *message;

	asprintf(&message, "random seed %u, 4K footprint", initial_seed);
	task_self_region_footprint_set(true);
	call_page_range_info_internal_with_page_shift(map,
	    map_start, map_end, FOURK_PAGE_SHIFT, message);
	free(message);

	asprintf(&message, "random seed %u, 4K no-footprint", initial_seed);
	task_self_region_footprint_set(false);
	call_page_range_info_internal_with_page_shift(map,
	    map_start, map_end, FOURK_PAGE_SHIFT, message);
	free(message);

	asprintf(&message, "random seed %u, 16K footprint", initial_seed);
	task_self_region_footprint_set(true);
	call_page_range_info_internal_with_page_shift(map,
	    map_start, map_end, SIXTEENK_PAGE_SHIFT, message);
	free(message);

	asprintf(&message, "random seed %u, 16K no-footprint", initial_seed);
	task_self_region_footprint_set(false);
	call_page_range_info_internal_with_page_shift(map,
	    map_start, map_end, SIXTEENK_PAGE_SHIFT, message);
	free(message);
}
