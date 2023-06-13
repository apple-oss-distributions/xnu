/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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

#ifndef _KASAN_H_
#define _KASAN_H_

#include <mach/mach_types.h>
#include <sys/queue.h>

#if KERNEL_PRIVATE

typedef uintptr_t uptr;

#if KASAN

#if KASAN_CLASSIC
#include "kasan-classic.h"
#elif KASAN_TBI
#include "kasan-tbi.h"
#else
#error "No kasan model specified"
#endif

/*
 * When mapping shadow memory, decide whether the created mapping can be later
 * updated/poisoned or whether it should just stay marked accessible for its
 * lifetime (and catch incorrect attempts at poisoning it).
 *
 * Consumed by: kasan_map_shadow()
 */
#define KASAN_CANNOT_POISON             true
#define KASAN_MAY_POISON                false

__BEGIN_DECLS

void kasan_map_shadow(vm_offset_t, vm_size_t, bool);

/* KASAN enable/disable and general initialization. */
void kasan_init(void);
void kasan_late_init(void);
void kasan_reserve_memory(void *);
void kasan_notify_stolen(vm_offset_t);

/*
 * Helper functions to run the necessary initialization and cleanup
 * at every KEXT load/unload.
 */
void kasan_load_kext(vm_offset_t, vm_size_t, const void *);
void kasan_unload_kext(vm_offset_t, vm_size_t);

/*
 * API for the kernel to communicate to KASAN that a new range needs to be
 * accounted for in the shadow table.
 */
void kasan_notify_address(vm_offset_t, vm_size_t);
void kasan_notify_address_nopoison(vm_offset_t, vm_size_t);

/*
 * Control the shadow table state for a given range.
 */
void kasan_poison(vm_offset_t, vm_size_t, vm_size_t, vm_size_t, uint8_t);
void kasan_unpoison(void *, vm_size_t);
void kasan_poison_range(vm_offset_t, vm_size_t, uint8_t);
void kasan_unpoison_stack(vm_offset_t, vm_size_t);
void kasan_unpoison_curstack(bool);
bool kasan_check_shadow(vm_address_t, vm_size_t, uint8_t);
void kasan_unpoison_cxx_array_cookie(void *);

/* Fakestack */
void kasan_fakestack_drop(thread_t); /* mark all fakestack entries for thread as unused */
void kasan_fakestack_gc(thread_t);   /* free and poison all unused fakestack objects for thread */
void kasan_fakestack_suspend(void);
void kasan_fakestack_resume(void);
void kasan_unpoison_fakestack(thread_t);

/* KDP support */
typedef int (*pmap_traverse_callback)(vm_map_offset_t, vm_map_offset_t, void *);
int kasan_traverse_mappings(pmap_traverse_callback, void *);
void kasan_kdp_disable(void);

/* Tests API */
struct kasan_test {
	int (* func)(struct kasan_test *);
	void (* cleanup)(struct kasan_test *);
	const char *name;
	int result;
	void *data;
	size_t datasz;
};
void __kasan_runtests(struct kasan_test *, int numtests);

#if XNU_KERNEL_PRIVATE
extern unsigned shadow_pages_total;

#if __arm64__
void kasan_notify_address_zero(vm_offset_t, vm_size_t);
#elif __x86_64__
extern void kasan_map_low_fixed_regions(void);
extern unsigned shadow_stolen_idx;
#endif /* __arm64__ */

#endif /* XNU_KERNEL_PRIVATE */

#if HIBERNATION
/*
 * hibernate_write_image() needs to know the current extent of the shadow table
 */
extern vm_offset_t shadow_pnext, shadow_ptop;
#endif /* HIBERNATION */

/* thread interface */
struct kasan_thread_data {
	LIST_HEAD(fakestack_header_list, fakestack_header) fakestack_head;
};
struct kasan_thread_data *kasan_get_thread_data(thread_t);
void kasan_init_thread(struct kasan_thread_data *);

/*
 * ASAN callbacks - inserted by the compiler
 */

extern int __asan_option_detect_stack_use_after_return;
extern const uintptr_t __asan_shadow_memory_dynamic_address;

#define KASAN_DECLARE_FOREACH_WIDTH(ret, func, ...) \
	ret func ## 1(__VA_ARGS__); \
	ret func ## 2(__VA_ARGS__); \
	ret func ## 4(__VA_ARGS__); \
	ret func ## 8(__VA_ARGS__); \
	ret func ## 16(__VA_ARGS__)

KASAN_DECLARE_FOREACH_WIDTH(void, __asan_report_load, uptr);
KASAN_DECLARE_FOREACH_WIDTH(void, __asan_report_store, uptr);
KASAN_DECLARE_FOREACH_WIDTH(void, __asan_store, uptr);
KASAN_DECLARE_FOREACH_WIDTH(void, __asan_report_exp_load, uptr, int32_t);
KASAN_DECLARE_FOREACH_WIDTH(void, __asan_report_exp_store, uptr, int32_t);
KASAN_DECLARE_FOREACH_WIDTH(void, __asan_exp_load, uptr, int32_t);
KASAN_DECLARE_FOREACH_WIDTH(void, __asan_exp_store, uptr, int32_t);
KASAN_DECLARE_FOREACH_WIDTH(void, __asan_load, uptr);

void __asan_report_load_n(uptr, unsigned long);
void __asan_report_store_n(uptr, unsigned long);
void __asan_handle_no_return(void);
uptr __asan_stack_malloc_0(size_t);
uptr __asan_stack_malloc_1(size_t);
uptr __asan_stack_malloc_2(size_t);
uptr __asan_stack_malloc_3(size_t);
uptr __asan_stack_malloc_4(size_t);
uptr __asan_stack_malloc_5(size_t);
uptr __asan_stack_malloc_6(size_t);
uptr __asan_stack_malloc_7(size_t);
uptr __asan_stack_malloc_8(size_t);
uptr __asan_stack_malloc_9(size_t);
uptr __asan_stack_malloc_10(size_t);
void __asan_stack_free_0(uptr, size_t);
void __asan_stack_free_1(uptr, size_t);
void __asan_stack_free_2(uptr, size_t);
void __asan_stack_free_3(uptr, size_t);
void __asan_stack_free_4(uptr, size_t);
void __asan_stack_free_5(uptr, size_t);
void __asan_stack_free_6(uptr, size_t);
void __asan_stack_free_7(uptr, size_t);
void __asan_stack_free_8(uptr, size_t);
void __asan_stack_free_9(uptr, size_t);
void __asan_stack_free_10(uptr, size_t);
void __asan_poison_cxx_array_cookie(uptr);
uptr __asan_load_cxx_array_cookie(uptr *);
void __asan_poison_stack_memory(uptr, size_t);
void __asan_unpoison_stack_memory(uptr, size_t);
void __asan_alloca_poison(uptr, uptr);
void __asan_allocas_unpoison(uptr, uptr);
void __asan_loadN(uptr, size_t);
void __asan_storeN(uptr, size_t);
void __sanitizer_ptr_sub(uptr, uptr);
void __sanitizer_ptr_cmp(uptr, uptr);
void __sanitizer_annotate_contiguous_container(const void *, const void *,
    const void *, const void *n);

void __asan_exp_loadN(uptr, size_t, int32_t);
void __asan_exp_storeN(uptr, size_t, int32_t);
void __asan_report_exp_load_n(uptr, unsigned long, int32_t);
void __asan_report_exp_store_n(uptr, unsigned long, int32_t);

void __asan_set_shadow_00(uptr, size_t);
void __asan_set_shadow_f1(uptr, size_t);
void __asan_set_shadow_f2(uptr, size_t);
void __asan_set_shadow_f3(uptr, size_t);
void __asan_set_shadow_f5(uptr, size_t);
void __asan_set_shadow_f8(uptr, size_t);

void __asan_init_v5(void);
void __asan_register_globals(uptr, uptr);
void __asan_unregister_globals(uptr, uptr);
void __asan_register_elf_globals(uptr, uptr, uptr);
void __asan_unregister_elf_globals(uptr, uptr, uptr);

void __asan_before_dynamic_init(uptr);
void __asan_after_dynamic_init(void);
void __asan_init(void);
void __asan_unregister_image_globals(uptr);
void __asan_register_image_globals(uptr);

void __hwasan_tag_memory(uintptr_t, unsigned char, uintptr_t);
unsigned char __hwasan_generate_tag(void);

__END_DECLS

#endif /* KASAN */

#if __has_feature(address_sanitizer)
#define NOKASAN __attribute__ ((no_sanitize_address))
#elif __has_feature(hwaddress_sanitizer)
#define NOKASAN __attribute__((no_sanitize("kernel-hwaddress")))
#else /* address_sanitizer || hwaddress_sanitizer */
#define NOKASAN
#endif

/*
 * KASAN provides a description of each global variable in the
 * __DATA.__asan_globals section. This description is walked for xnu at boot
 * and at each KEXT load/unload operation, to allow the KASAN implementation
 * to perform the necessary redzoning around each variable.
 *
 * Consumed in OSKext.cpp, so must stay outside KASAN-specific defines.
 */
#define KASAN_GLOBAL_SEGNAME  "__DATA"
#define KASAN_GLOBAL_SECTNAME "__asan_globals"

#endif /* KERNEL_PRIVATE */
#endif /* _KASAN_H_ */
