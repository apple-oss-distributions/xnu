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
#define KASAN_KALLOC 1
#define KASAN_ZALLOC 1
#define KASAN_DYNAMIC_BLACKLIST 1
/*
 * KASAN features and config
 */
#define FAKESTACK     1
/* KASAN_KALLOC defined in kasan.h */
/* KASAN_ZALLOC defined in kasan.h */
#define FAKESTACK_QUARANTINE (1 && FAKESTACK)

#define QUARANTINE_ENTRIES 5000
#define QUARANTINE_MAXSIZE MiB(10)

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
#define ASAN_ARRAY_COOKIE   0xac
#define ASAN_STACK_RZ       0xf0
#define ASAN_STACK_LEFT_RZ  0xf1
#define ASAN_STACK_MID_RZ   0xf2
#define ASAN_STACK_RIGHT_RZ 0xf3
#define ASAN_STACK_FREED    0xf5
#define ASAN_STACK_OOSCOPE  0xf8
#define ASAN_GLOBAL_RZ      0xf9
#define ASAN_HEAP_RZ        0xe9
#define ASAN_HEAP_LEFT_RZ   0xfa
#define ASAN_HEAP_RIGHT_RZ  0xfb
#define ASAN_HEAP_FREED     0xfd

#define KASAN_GUARD_SIZE (16)
#define KASAN_GUARD_PAD  (KASAN_GUARD_SIZE * 2)

#define KASAN_HEAP_ZALLOC    0
#define KASAN_HEAP_KALLOC    1
#define KASAN_HEAP_FAKESTACK 2
#define KASAN_HEAP_TYPES     3

__BEGIN_DECLS
/* KASAN-CLASSIC zalloc hooks */
vm_size_t kasan_alloc_resize(vm_size_t);
vm_address_t kasan_alloc(vm_offset_t, vm_size_t, vm_size_t, vm_size_t);
vm_address_t kasan_realloc(vm_offset_t, vm_size_t, vm_size_t, vm_size_t);
vm_address_t kasan_dealloc(vm_offset_t, vm_size_t *);
vm_size_t kasan_user_size(vm_offset_t);
void kasan_check_free(vm_offset_t, vm_size_t, unsigned);
void kasan_free(void **, vm_size_t *, int, zone_t *, vm_size_t, bool);

/* KASAN-CLASSIC Quarantine (zalloc) hooks */
void kasan_free(void **, vm_size_t *, int, zone_t *, vm_size_t, bool);
void __asan_poison_cxx_array_cookie(uptr);
uptr __asan_load_cxx_array_cookie(uptr *);
void kasan_unpoison_cxx_array_cookie(void *);

__END_DECLS
#endif /* _KASAN_CLASSIC_H_ */
