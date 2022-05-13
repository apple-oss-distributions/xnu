/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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

#ifndef _KASAN_TBI_H_
#define _KASAN_TBI_H_

#include <mach/mach_types.h>

/* Catch obvious mismatches */
#if KASAN && !__has_feature(hwaddress_sanitizer)
#error "KASAN selected, but not enabled in compiler"
#endif

#if !KASAN && __has_feature(hwaddress_sanitizer)
#error "hwaddress_sanitizer enabled in compiler, but kernel is not configured for KASAN"
#endif

/* old-style configs. */
#define KASAN_DEBUG 0
#define KASAN_KALLOC 0
#define KASAN_ZALLOC 0
#define KASAN_DYNAMIC_BLACKLIST 1
#define KASAN_FAKESTACK 0

/* Granularity is 16 bytes */
#define KASAN_SIZE_ALIGNMENT        0xFUL
/* TBI reserves the topmost 8 bits, we use the lower 4 of this reserved range */
#define KASAN_TBI_ADDR_SIZE         56
#define KASAN_TBI_TAG_SIZE          4
#define KASAN_TBI_PAD_SIZE          4

union kasan_tbi_ptr {
	long value;

	struct {
		long ptr_no_tbi: KASAN_TBI_ADDR_SIZE;
		uint8_t ptr_tag:    KASAN_TBI_TAG_SIZE;
		long ptr_pad:    KASAN_TBI_PAD_SIZE;
	};
};

static inline long
kasan_tbi_tag_ptr(long ptr, uint8_t tag)
{
	union kasan_tbi_ptr p = {
		.value = ptr,
	};

	p.ptr_tag = tag;
	return p.value;
}

static inline uint8_t
kasan_tbi_get_tag(long ptr)
{
	union kasan_tbi_ptr p = {
		.value = ptr,
	};

	return p.ptr_tag;
}

/*
 * KASAN_TBI inline insturmentation emits a brk instruction as a violation
 * report. The ESR value encodes both the access type and size.
 * osfmk/arm64/sleh.c needs to now the right ranges to proxy this information
 * back to the kasan runtime.
 */
#define KASAN_TBI_ESR_BASE          (0x900)
#define KASAN_TBI_ESR_WRITE         (0x10)
#define KASAN_TBI_ESR_IGNORE        (0x20)
#define KASAN_TBI_ESR_SIZE_MASK     (0xF)
#define KASAN_TBI_ESR_TOP           (KASAN_TBI_ESR_BASE | KASAN_TBI_ESR_WRITE |     \
	                            KASAN_TBI_ESR_IGNORE | KASAN_TBI_ESR_SIZE_MASK)
#define KASAN_TBI_GET_SIZE(x)       (1 << ((x) & KASAN_TBI_ESR_SIZE_MASK))

void __hwasan_tag_memory(uintptr_t, unsigned char, uintptr_t);
unsigned char __hwasan_generate_tag(void);
void kasan_tbi_copy_tags(vm_offset_t, vm_offset_t, vm_size_t);
vm_offset_t kasan_tbi_tag_zalloc(vm_offset_t, vm_size_t, vm_size_t, boolean_t);
vm_offset_t kasan_tbi_tag_zfree(vm_offset_t, vm_offset_t, boolean_t);
vm_offset_t kasan_tbi_tag_zalloc_default(vm_offset_t, vm_size_t, boolean_t);
vm_offset_t kasan_tbi_fix_address_tag(vm_offset_t);
void kasan_handle_brk_failure(vm_offset_t, uint16_t);

#endif /* _KASAN_TBI_H_ */
