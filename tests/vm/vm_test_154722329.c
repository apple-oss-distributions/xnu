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

#include <darwintest/darwintest.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach-o/utils_priv.h>
#include <objc/runtime.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true));

/*
 * ObjC block trampolines vm_remap an entire dylib text segment.
 * This succeeds only when the source memory is a single VM map entry.
 * Some apps also examine the dylib's text segment for analytics
 * or crash reporting. Test that their VM operations do not cause
 * unexpected map entry clipping that interferes with block trampolines.
 */

/*
 * rdar://154722329
 * App calls into mach_make_memory_entry_share which cannot clip its source.
 */

static bool test_154722329_saw_trampoline_library = false;

static void
test_154722329_read_loaded_library(
	const struct mach_header *mh,
	intptr_t vmaddr_slide __unused)
{
	/*
	 * app's calls:
	 * mach_make_memory_entry_64(one page, no flags)
	 * vm_map(fixed|overwrite)
	 */

	/* Get library name and note if we saw the trampoline library. */
	const char *name = macho_dylib_install_name(mh);
	if (name == NULL) {
		return;  /* image is not a dylib, ignore it */
	}
	if (strstr(name, "/libobjc-trampolines.dylib")) {
		T_LOG("found libobjc-trampolines at %p '%s'", mh, name);
		test_154722329_saw_trampoline_library = true;
	}

	/*
	 * Make a memory entry from the first page of the library.
	 * Note that mh may not be page-aligned.
	 */
	kern_return_t kr;
	memory_object_size_t size = PAGE_SIZE;
	mach_port_t mem_port;
	kr = mach_make_memory_entry_64(mach_task_self(), &size, (mach_vm_address_t)mh,
	    VM_PROT_READ, &mem_port, 0 /* parent_entry */);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64");

	/* Map it. */
	mach_vm_address_t dst = 0;
	kr = mach_vm_allocate(mach_task_self(), &dst, size, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_allocate");
	kr = mach_vm_map(mach_task_self(), &dst, size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
	    mem_port, 0, false, VM_PROT_READ, VM_PROT_READ, VM_INHERIT_COPY);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_map");

	/* Memory contents should match. */
	int cmp = memcmp((const void *)trunc_page((mach_vm_address_t)mh), (const void *)dst, size);
	T_QUIET; T_ASSERT_EQ(cmp, 0, "memory contents should be equal");

	/* Clean up. */
	kr = mach_vm_deallocate(mach_task_self(), dst, size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate remapping");
	kr = mach_port_deallocate(mach_task_self(), mem_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate port");
}

T_DECL(test_154722329_objc_block_trampolines,
    "rdar://154722329 test objc block trampolines and app compatibility")
{
	/*
	 * Register a dyld callback that reads the first page of each library.
	 * The callback will be run for any already-loaded libraries during this call.
	 */
	_dyld_register_func_for_add_image(test_154722329_read_loaded_library);

	/*
	 * Create a block object trampoline. This loads the trampoline
	 * library if not loaded already, and remaps its text segment.
	 */
	__block bool block_called = false;
	id receiver = (id)objc_getClass("NSObject");
	T_QUIET; T_ASSERT_NOTNULL(receiver, "class NSObject");
	void (^block)(id) = ^(id self) {
		T_QUIET; T_ASSERT_EQ(self, receiver, "block args");
		block_called = true;
	};
	IMP imp = imp_implementationWithBlock((id)block);
	T_QUIET; T_ASSERT_NOTNULL(imp, "imp");

	T_ASSERT_TRUE(test_154722329_saw_trampoline_library,
	    "block trampoline library seen by image callback");

	/*
	 * Execute the block object through the trampoline.
	 * This will crash if the remapped trampoline library text
	 * is not executable or has an invalid code signature.
	 */
	T_QUIET; T_ASSERT_FALSE(block_called, "block not called yet");
	((void (*)(id))imp)(receiver);
	T_ASSERT_TRUE(block_called, "block and trampoline called successfully");
}
