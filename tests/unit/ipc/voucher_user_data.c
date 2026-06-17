/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
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

/*
 * Unit tests for the user_data voucher attribute manager (ipc_voucher.c).
 *
 * Covers the fix for rdar://172346729: KEY_TEST (key 8) was registered to
 * the same manager and element pool as KEY_USER_DATA (key 7), causing
 * deduplication to produce a shared e_made counter that diverged from each
 * key's ivace_made, leading to zombie ivace entries and a UAF via counter
 * wraparound.  The fix removes the KEY_TEST registration entirely.
 */

#include <darwintest.h>
#include <ipc/ipc_voucher.h>
#include <mach/mach_voucher_types.h>
#include <stdint.h>

#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_TAG_VM_PREFERRED);

extern const struct ipc_voucher_attr_manager user_data_manager;

/*
 * e_made is the first field (uint32_t at offset 0) of user_data_value_element.
 * ivam_get_value returns an out_value that is a pointer to the element cast to
 * mach_voucher_attr_value_handle_t (uint64_t).  Casting back to uint32_t * and
 * dereferencing gives e_made as an lvalue.
 *
 * This direct field access is safe only in single-threaded unit test context.
 */
#define ELEM_E_MADE(handle) (*(uint32_t *)(uintptr_t)(handle))

/* Distinct content string used by each test to avoid cross-test dedup. */
static const uint8_t kContentDedup[] = "uaf_test_same_key_dedup_content";

static kern_return_t
store_element(
	mach_voucher_attr_key_t                  key,
	const uint8_t                           *content,
	size_t                                   content_size,
	mach_voucher_attr_value_handle_t        *out_handle)
{
	mach_voucher_attr_value_flags_t flags = MACH_VOUCHER_ATTR_VALUE_FLAGS_NONE;
	ipc_voucher_t out_voucher = IPC_VOUCHER_NULL;

	return user_data_manager.ivam_get_value(
		&user_data_manager,
		key,
		MACH_VOUCHER_ATTR_USER_DATA_STORE,
		/* prev_values */ NULL,
		/* prev_value_count */ 0,
		(mach_voucher_attr_content_t)(uintptr_t)content,
		(mach_voucher_attr_content_size_t)content_size,
		out_handle,
		&flags,
		&out_voucher);
}

static kern_return_t
release_element(
	mach_voucher_attr_key_t                  key,
	mach_voucher_attr_value_handle_t         handle,
	uint32_t                                 sync)
{
	return user_data_manager.ivam_release_value(
		&user_data_manager,
		key,
		handle,
		sync);
}

/*
 * Verify that deduplication within a single key still works correctly.
 * Two STOREs with the same content and the same key must return the same
 * element handle (deduplicated), and a full release with sync == e_made
 * must free the element.
 */
T_DECL(user_data_same_key_dedup_still_works,
    "Deduplication within a single key must still work")
{
	mach_voucher_attr_value_handle_t handle1 = 0, handle2 = 0;
	kern_return_t kr;

	kr = store_element(MACH_VOUCHER_ATTR_KEY_USER_DATA,
	    kContentDedup, sizeof(kContentDedup), &handle1);
	T_ASSERT_MACH_SUCCESS(kr, "first STORE via KEY_USER_DATA succeeds");

	kr = store_element(MACH_VOUCHER_ATTR_KEY_USER_DATA,
	    kContentDedup, sizeof(kContentDedup), &handle2);
	T_ASSERT_MACH_SUCCESS(kr, "second STORE via KEY_USER_DATA (same content) succeeds");

	/* Same key + same content -> same element handle (dedup). */
	T_ASSERT_EQ(handle1, handle2,
	    "two STOREs for the same key and content return the same element handle");
	T_ASSERT_EQ(ELEM_E_MADE(handle1), (uint32_t)2,
	    "e_made == 2 after two references via the same key");

	/*
	 * Partial release: sync=1 < e_made=2.  The manager must report that
	 * the element is still live (KERN_FAILURE), not free it.
	 */
	kr = release_element(MACH_VOUCHER_ATTR_KEY_USER_DATA, handle1, 1);
	T_ASSERT_EQ(kr, KERN_FAILURE,
	    "release with sync=1 < e_made=2 returns KERN_FAILURE (element still live)");
	T_ASSERT_EQ(ELEM_E_MADE(handle1), (uint32_t)2, "e_made unchanged after partial release");

	/* Full release: sync=2 == e_made=2.  Element must be freed. */
	kr = release_element(MACH_VOUCHER_ATTR_KEY_USER_DATA, handle1, 2);
	T_ASSERT_MACH_SUCCESS(kr,
	    "release with sync=2 == e_made=2 returns KERN_SUCCESS and frees element");
}
