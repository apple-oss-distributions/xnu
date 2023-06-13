/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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

#ifndef _KASAN_CLASSIC_H_
#define _KASAN_CLASSIC_H_

#include <mach/mach_types.h>

/* Catch obvious mismatches */
#if KASAN && !__has_feature(address_sanitizer)
#error "KASAN selected, but not enabled in compiler"
#endif

#if !KASAN && __has_feature(address_sanitizer)
#error "ASAN enabled in compiler, but kernel is not configured for KASAN"
#endif

/* Granularity is 8 bytes */
#define KASAN_SIZE_ALIGNMENT    0x7UL

typedef uintptr_t uptr;

#define KASAN_DEBUG  0
#define KASAN_DYNAMIC_BLACKLIST 1
#define KASAN_FAKESTACK 1
/*
 * KASAN features and config
 */
#define FAKESTACK_QUARANTINE (1 && KASAN_FAKESTACK)
#define QUARANTINE_ENTRIES 5000
#define QUARANTINE_MAXSIZE MiB(4)

/*
 * KASAN-CLASSIC shadow table entry values.
 *  - 0:                the full 8 bytes are addressable
 *  - [1,7]:            the byte is partially addressable (as many valid bytes
 *                      as specified)
 *  - 0xFx, 0xAC, 0xE9: byte is not addressable and poisoned somehow.
 */
#define ASAN_VALID          0x00
#define ASAN_PARTIAL1       0x01
#define ASAN_PARTIAL2       0x02
#define ASAN_PARTIAL3       0x03
#define ASAN_PARTIAL4       0x04
#define ASAN_PARTIAL5       0x05
#define ASAN_PARTIAL6       0x06
#define ASAN_PARTIAL7       0x07
#define ASAN_ARRAY_COOKIE   0xac // kAsanArrayCookieMagic
#define ASAN_STACK_RZ       0xf0 // XNU only
#define ASAN_STACK_LEFT_RZ  0xf1 // kAsanStackLeftRedzoneMagic
#define ASAN_STACK_MID_RZ   0xf2 // kAsanStackMidRedzoneMagic
#define ASAN_STACK_RIGHT_RZ 0xf3 // kAsanStackRightRedzoneMagic
#define ASAN_STACK_FREED    0xf5 // kAsanStackAfterReturnMagic
//                          0xf6 // kAsanInitializationOrderMagic
//                          0xf7 // kAsanUserPoisonedMemoryMagic
#define ASAN_STACK_OOSCOPE  0xf8 // kAsanStackUseAfterScopeMagic
#define ASAN_GLOBAL_RZ      0xf9 // kAsanGlobalRedzoneMagic
#define ASAN_HEAP_RZ        0xe9 // XNU only, not used in shadow
#define ASAN_HEAP_LEFT_RZ   0xfa // kAsanHeapLeftRedzoneMagic
#define ASAN_HEAP_RIGHT_RZ  0xfb // XNU only
//                          0xfc // kAsanContiguousContainerOOBMagic
#define ASAN_HEAP_FREED     0xfd // kAsanHeapFreeMagic
//                          0xfe // kAsanInternalHeapMagic

#define KASAN_GUARD_SIZE (16)
#define KASAN_GUARD_PAD  (KASAN_GUARD_SIZE * 2)

#define KASAN_HEAP_ZALLOC    0
#define KASAN_HEAP_FAKESTACK 1
#define KASAN_HEAP_TYPES     2

__BEGIN_DECLS

/* KASAN-CLASSIC zalloc hooks */

extern void kasan_zmem_add(
	vm_address_t            addr,
	vm_size_t               size,
	vm_offset_t             esize,
	vm_offset_t             offs,
	vm_offset_t             rzsize);

extern void kasan_zmem_remove(
	vm_address_t            addr,
	vm_size_t               size,
	vm_offset_t             esize,
	vm_offset_t             offs,
	vm_offset_t             rzsize);

extern void kasan_alloc(
	vm_address_t            addr,
	vm_size_t               size,
	vm_size_t               usize,
	vm_size_t               rzsize,
	bool                    percpu,
	void                   *fp);

extern void kasan_free(
	vm_address_t            addr,
	vm_size_t               size,
	vm_size_t               usize,
	vm_size_t               rzsize,
	bool                    percpu,
	void                   *fp);

extern void kasan_alloc_large(
	vm_address_t            addr,
	vm_size_t               req_size);

extern vm_size_t kasan_user_size(
	vm_address_t            addr);

extern void kasan_check_alloc(
	vm_address_t            addr,
	vm_size_t               size,
	vm_size_t               usize);

struct kasan_quarantine_result {
	vm_address_t            addr;
	struct zone            *zone;
};

extern struct kasan_quarantine_result kasan_quarantine(
	vm_address_t            addr,
	vm_size_t               size);

/* in zalloc.c */
extern vm_size_t kasan_quarantine_resolve(
	vm_address_t            addr,
	struct zone           **zonep);

__END_DECLS

#endif /* _KASAN_CLASSIC_H_ */
