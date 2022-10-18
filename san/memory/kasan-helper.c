/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
 * This file contains all the necessary helpers that the compiler
 * instrumentation inserts for KASAN. Due to the way the INSTALL phase is
 * performed in our build system, it's non-trivial to support independent
 * .exports for System.kext, therefore we take the easy way out and have
 * a common set of exports between KASAN-CLASSIC (asan based) and KASAN-TBI
 * (hwasan based). This also simplifies any backward compatibility without
 * requiring to duplicate symbols.
 *
 * For checking and reporting functions, KASAN-TBI is built with
 * -mllvm -hwasan-memory-access-callback-prefix="___asan" which allows to
 * commonize the implementation. This also imposes that KASAN-CLASSIC and
 * KASAN-TBI agree on the definition of access types (TYPE_LOAD/TYPE_STORE),
 * which is a fair requirement.
 *
 * NOTE: there is a vast predominance of asan symbols due to the original
 * implementation being based on the userland address sanitizer. For hwasan,
 * the kernel-hwaddress sanitizer already strips out a non-trivial amount
 * of non-kernel-applicable instrumentation/APIs.
 */

#include <libkern/libkern.h>
#include "kasan.h"
#include "kasan_internal.h"



/* Report and checking for any size-based access. */
#define REPORT_DECLARE(n) \
	void OS_NORETURN __asan_report_load##n(uptr p)  { kasan_crash_report(p, n, TYPE_LOAD,  0); } \
	void OS_NORETURN __asan_report_store##n(uptr p) { kasan_crash_report(p, n, TYPE_STORE, 0); } \
	void OS_NORETURN UNSUPPORTED_API(__asan_report_exp_load##n, uptr a, int32_t b); \
	void OS_NORETURN UNSUPPORTED_API(__asan_report_exp_store##n, uptr a, int32_t b);

REPORT_DECLARE(1)
REPORT_DECLARE(2)
REPORT_DECLARE(4)
REPORT_DECLARE(8)
REPORT_DECLARE(16)

void OS_NORETURN
__asan_report_load_n(uptr p, unsigned long sz)
{
	kasan_crash_report(p, sz, TYPE_LOAD, 0);
}
void OS_NORETURN
__asan_report_store_n(uptr p, unsigned long sz)
{
	kasan_crash_report(p, sz, TYPE_STORE, 0);
}

#define ACCESS_CHECK_DECLARE(type, sz, access) \
	void __asan_##type##sz(uptr addr) { \
	        kasan_check_range((const void *)addr, sz, access); \
	} \
	void OS_NORETURN UNSUPPORTED_API(__asan_exp_##type##sz, uptr a, int32_t b);

#define ACCESS_CHECK_DECLARE(type, sz, access) \
	void __asan_##type##sz(uptr addr) { \
	        kasan_check_range((const void *)addr, sz, access); \
	} \
	void OS_NORETURN UNSUPPORTED_API(__asan_exp_##type##sz, uptr a, int32_t b);

ACCESS_CHECK_DECLARE(load, 1, TYPE_LOAD);
ACCESS_CHECK_DECLARE(load, 2, TYPE_LOAD);
ACCESS_CHECK_DECLARE(load, 4, TYPE_LOAD);
ACCESS_CHECK_DECLARE(load, 8, TYPE_LOAD);
ACCESS_CHECK_DECLARE(load, 16, TYPE_LOAD);
ACCESS_CHECK_DECLARE(store, 1, TYPE_STORE);
ACCESS_CHECK_DECLARE(store, 2, TYPE_STORE);
ACCESS_CHECK_DECLARE(store, 4, TYPE_STORE);
ACCESS_CHECK_DECLARE(store, 8, TYPE_STORE);
ACCESS_CHECK_DECLARE(store, 16, TYPE_STORE);

void
__asan_loadN(uptr addr, size_t sz)
{
	kasan_check_range((const void *)addr, sz, TYPE_LOAD);
}

void
__asan_storeN(uptr addr, size_t sz)
{
	kasan_check_range((const void *)addr, sz, TYPE_STORE);
}

static void
kasan_set_shadow(uptr addr, size_t sz, uint8_t val)
{
	__nosan_memset((void *)addr, val, sz);
}

#define SET_SHADOW_DECLARE(val) \
	void __asan_set_shadow_##val(uptr addr, size_t sz) { \
	        kasan_set_shadow(addr, sz, 0x##val); \
	}

SET_SHADOW_DECLARE(00)
SET_SHADOW_DECLARE(f1)
SET_SHADOW_DECLARE(f2)
SET_SHADOW_DECLARE(f3)
SET_SHADOW_DECLARE(f5)
SET_SHADOW_DECLARE(f8)

#if KASAN_CLASSIC
#include "kasan-classic.h"

uptr
__asan_load_cxx_array_cookie(uptr *p)
{
	uint8_t *shadow = SHADOW_FOR_ADDRESS((uptr)p);
	if (*shadow == ASAN_ARRAY_COOKIE) {
		return *p;
	} else if (*shadow == ASAN_HEAP_FREED) {
		return 0;
	} else {
		return *p;
	}
}

void
__asan_poison_cxx_array_cookie(uptr p)
{
	uint8_t *shadow = SHADOW_FOR_ADDRESS(p);
	*shadow = ASAN_ARRAY_COOKIE;
}

unsigned char
__hwasan_generate_tag()
{
	return 0;
}

void
__hwasan_tag_memory(uintptr_t __unused p, unsigned char __unused tag, uintptr_t __unused sz)
{
}
#else /* KASAN_CLASSIC */
uptr
__asan_load_cxx_array_cookie(uptr __unused *p)
{
	return 0;
}

void
__asan_poison_cxx_array_cookie(uptr __unused p)
{
}
#endif /* KASAN_CLASSIC */

/*
 * Unused ABI.
 *
 * These symbols must be present for KASAN to work correctly and for some
 * external dependency tool to operate properly. E.g. Vortex relies on
 * asan_init() being defined to identify a KASAN artifact.
 */
#define UNUSED_ABI(func, ...) \
	_Pragma("clang diagnostic push") \
	_Pragma("clang diagnostic ignored \"-Wunused-parameter\"") \
	void func(__VA_ARGS__); \
	void func(__VA_ARGS__) {}; \
	_Pragma("clang diagnostic pop")

UNUSED_ABI(__asan_alloca_poison, uptr addr, uptr size);
UNUSED_ABI(__asan_allocas_unpoison, uptr top, uptr bottom);
UNUSED_ABI(__sanitizer_ptr_sub, uptr a, uptr b);
UNUSED_ABI(__sanitizer_ptr_cmp, uptr a, uptr b);
UNUSED_ABI(__sanitizer_annotate_contiguous_container, const void *a, const void *b, const void *c, const void *d);
UNUSED_ABI(__asan_poison_stack_memory, uptr addr, size_t size);
UNUSED_ABI(__asan_unpoison_stack_memory, uptr a, uptr b);
UNUSED_ABI(__asan_init, void);
UNUSED_ABI(__asan_register_image_globals, uptr a);
UNUSED_ABI(__asan_unregister_image_globals, uptr a);
UNUSED_ABI(__asan_before_dynamic_init, uptr a);
UNUSED_ABI(__asan_after_dynamic_init, void);
UNUSED_ABI(__asan_version_mismatch_check_v8, void);
UNUSED_ABI(__asan_version_mismatch_check_apple_802, void);
UNUSED_ABI(__asan_version_mismatch_check_apple_900, void);
UNUSED_ABI(__asan_version_mismatch_check_apple_902, void);
UNUSED_ABI(__asan_version_mismatch_check_apple_1000, void);
UNUSED_ABI(__asan_version_mismatch_check_apple_1001, void);
UNUSED_ABI(__asan_version_mismatch_check_apple_clang_1100, void);
UNUSED_ABI(__asan_version_mismatch_check_apple_clang_1200, void);

/* Panic if any of those is inserted by the instrumentation. */
void OS_NORETURN UNSUPPORTED_API(__asan_init_v5, void);
void OS_NORETURN UNSUPPORTED_API(__asan_register_globals, uptr a, uptr b);
void OS_NORETURN UNSUPPORTED_API(__asan_unregister_globals, uptr a, uptr b);
void OS_NORETURN UNSUPPORTED_API(__asan_register_elf_globals, uptr a, uptr b, uptr c);
void OS_NORETURN UNSUPPORTED_API(__asan_unregister_elf_globals, uptr a, uptr b, uptr c);
void OS_NORETURN UNSUPPORTED_API(__asan_exp_loadN, uptr addr, size_t sz, int32_t e);
void OS_NORETURN UNSUPPORTED_API(__asan_exp_storeN, uptr addr, size_t sz, int32_t e);
void OS_NORETURN UNSUPPORTED_API(__asan_report_exp_load_n, uptr addr, unsigned long b, int32_t c);
void OS_NORETURN UNSUPPORTED_API(__asan_report_exp_store_n, uptr addr, unsigned long b, int32_t c);
