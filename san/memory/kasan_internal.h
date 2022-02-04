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

#ifndef _KASAN_INTERNAL_H_
#define _KASAN_INTERNAL_H_

#include <stdbool.h>
#include <mach/mach_vm.h>
#include <kern/zalloc.h>
#include <sys/sysctl.h>

typedef uintptr_t uptr;
#define MiB(x) ((x) * 1024UL * 1024)
#define BIT(x) (1U << (x))

/* Sanity checks */
#ifndef KASAN
#error KASAN undefined
#endif

#ifndef KASAN_OFFSET
#error KASAN_OFFSET undefined
#endif

#ifndef KASAN_SCALE
#error KASAN_SCALE undefined
#endif

#if defined(__x86_64__)
# define _JBLEN ((9 * 2) + 3 + 16)
#elif defined(__arm64__)
# define _JBLEN ((14 + 8 + 2) * 2)
#else
# error "Unknown arch"
#endif

#if KASAN_DEBUG
#define NOINLINE OS_NOINLINE
#else
#define NOINLINE
#endif
#define ALWAYS_INLINE inline __attribute__((always_inline))
#define CLANG_MIN_VERSION(x) (defined(__apple_build_version__) && (__apple_build_version__ >= (x)))

#if KASAN_CLASSIC
#define KASAN_MODEL_STR                 "kasan-classic"
#define KASAN_STRIP_ADDR(_x)    (_x)
#elif KASAN_TBI
#define KASAN_MODEL_STR                 "kasan-tbi"
#define KASAN_STRIP_ADDR(_x)    (VM_KERNEL_STRIP_UPTR(_x))
#else
#error "No kasan model specified"
#endif /* KASAN_CLASSIC || KASAN_TBI */

extern vm_address_t     kernel_vbase;
extern vm_address_t     kernel_vtop;
extern unsigned                 shadow_pages_used;

/* boot-arg configurable */
extern unsigned                 kasan_enabled;
extern int                              fakestack_enabled;
extern bool                             report_suppressed_checks;

#define KASAN_GRANULE                   (1UL << KASAN_SCALE)
#define KASAN_GRANULE_MASK              (KASAN_GRANULE - 1UL)
#define kasan_granule_trunc(x)          (x & ~KASAN_GRANULE_MASK)
#define kasan_granule_round(x)          ((x + KASAN_GRANULE_MASK) & ~KASAN_GRANULE_MASK)
#define kasan_granule_partial(x)        (x & KASAN_GRANULE_MASK)

#define ADDRESS_FOR_SHADOW(x) (((KASAN_STRIP_ADDR(x)) - KASAN_OFFSET) << KASAN_SCALE)
#define SHADOW_FOR_ADDRESS(x) (uint8_t *)(((KASAN_STRIP_ADDR(x)) >> KASAN_SCALE) + KASAN_OFFSET)

enum __attribute__((flag_enum)) kasan_access_types {
	/* Common to all KASAN versions */
	TYPE_LOAD    = BIT(0),  /* regular memory load */
	TYPE_STORE   = BIT(1),  /* regular store */
	TYPE_MEMR    = BIT(2),  /* memory intrinsic (read) */
	TYPE_MEMW    = BIT(3),  /* memory intrinsic (write) */
	TYPE_STRR    = BIT(4),  /* string intrinsic (read) */
	TYPE_STRW    = BIT(5),  /* string intrinsic (write) */

	/* KASAN-classic specific */
	TYPE_KFREE   = BIT(6),  /* kfree() */
	TYPE_ZFREE   = BIT(7),  /* zfree() */
	TYPE_FSFREE  = BIT(8),  /* fakestack free */

	TYPE_UAF           = BIT(12),
	TYPE_POISON_GLOBAL = BIT(13),
	TYPE_POISON_HEAP   = BIT(14),
	/* no TYPE_POISON_STACK, because the runtime does not control stack poisoning */
	TYPE_TEST          = BIT(15),

	/* masks */
	TYPE_MEM     = TYPE_MEMR | TYPE_MEMW,            /* memory intrinsics */
	TYPE_STR     = TYPE_STRR | TYPE_STRW,            /* string intrinsics */
	TYPE_READ    = TYPE_LOAD | TYPE_MEMR | TYPE_STRR,  /* all reads */
	TYPE_WRITE   = TYPE_STORE | TYPE_MEMW | TYPE_STRW, /* all writes */
	TYPE_RW      = TYPE_READ | TYPE_WRITE,           /* reads and writes */
	TYPE_FREE    = TYPE_KFREE | TYPE_ZFREE | TYPE_FSFREE,
	TYPE_NORMAL  = TYPE_RW | TYPE_FREE,
	TYPE_DYNAMIC = TYPE_NORMAL | TYPE_UAF,
	TYPE_POISON  = TYPE_POISON_GLOBAL | TYPE_POISON_HEAP,
	TYPE_ALL     = ~0U,
};

enum kasan_violation_types {
	REASON_POISONED =       0, /* read or write of poisoned data */
	REASON_BAD_METADATA =   1, /* incorrect kasan metadata */
	REASON_INVALID_SIZE =   2, /* free size did not match alloc size */
	REASON_MOD_AFTER_FREE = 3, /* object modified after free */
	REASON_MOD_OOB =        4, /* out of bounds modification of object */
};

typedef enum kasan_access_types access_t;
typedef enum kasan_violation_types violation_t;

/*
 * KASAN may support different shadow table formats and different checking
 * strategies. _impl functions are called from the format-independent
 * kasan code to the format dependent implementations.
 */
void kasan_impl_report_internal(uptr, uptr, access_t, violation_t, bool);
void kasan_impl_poison_range(vm_offset_t, vm_size_t, uint8_t);
void kasan_impl_kdp_disable(void);
void kasan_impl_init(void);
void kasan_impl_late_init(void);
void kasan_impl_fill_valid_range(uintptr_t, size_t);

/*
 * Poisoning comes from KASAN CLASSIC nomenclature. KASAN CLASSIC is based on
 * identifying valid memory vs poisoned memory (memory that shouldn't be accessed).
 * This terminology isn't great for KASAN TBI, but is kept for compatibility.
 */
void kasan_poison(vm_offset_t, vm_size_t, vm_size_t, vm_size_t, uint8_t);

/*
 * Runtime checking. kasan_check_range() is consumed by the inlined
 * instrumentation. See kasan-helper.c
 */
bool kasan_check_enabled(access_t);
bool kasan_impl_check_enabled(access_t);
void kasan_check_range(const void *, size_t, access_t);

/* dynamic blacklist */
void kasan_init_dybl(void);
bool kasan_is_blacklisted(access_t);
void kasan_dybl_load_kext(uintptr_t, const char *);
void kasan_dybl_unload_kext(uintptr_t);

/* arch-specific interface */
void kasan_arch_init(void);
bool kasan_is_shadow_mapped(uintptr_t);

/* Locking */
void kasan_lock(boolean_t *);
void kasan_unlock(boolean_t);
bool kasan_lock_held(thread_t);

/* Subsystem helpers */
void kasan_free_internal(void **addrp, vm_size_t *sizep, int type, zone_t *, vm_size_t user_size, int locked, bool doquarantine);
void kasan_init_fakestack(void);

/*
 * Global variables need to be explicitly handled at runtime, both for xnu
 * and for KEXTs.
 */
void kasan_init_globals(vm_offset_t, vm_size_t);

/*
 * Handle KASAN detected issues. If modifying kasan_crash_report(), remember
 * that is called by the instrumentation as well, see kasan-helper.c.
 */
void kasan_violation(uintptr_t, size_t, access_t, violation_t);
size_t kasan_impl_decode_issue(char *, size_t, uptr, uptr, access_t, violation_t);
void NOINLINE OS_NORETURN kasan_crash_report(uptr, uptr, access_t, violation_t);

void kasan_handle_test(void);

SYSCTL_DECL(kasan);
SYSCTL_DECL(_kern_kasan);

#endif /* _KASAN_INTERNAL_H_ */
