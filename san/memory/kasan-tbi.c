/*
 * Copyright (c) 2016-2020 Apple Inc. All rights reserved.
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
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <kern/assert.h>
#include <kern/cpu_data.h>
#include <kern/backtrace.h>
#include <machine/machine_routines.h>
#include <kern/locks.h>
#include <kern/debug.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <libkern/libkern.h>
#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/machine/vm_param.h>
#include <mach/sdt.h>
#include <machine/atomic.h>

#include "kasan.h"
#include "kasan_internal.h"
#include "memintrinsics.h"

uintptr_t kasan_tbi_tag_range(uintptr_t, size_t, uint8_t);

#define P2ALIGN(x, align)           ((x) & -(align))
#define P2ROUNDUP(x, align)         (-(-(x) & -(align)))

/* Configuration options */
bool kasan_tbi_check_tag = false;
bool kasan_tbi_enabled = false;

/* Reserved tags */
#define KASAN_TBI_DEFAULT_TAG       0xFF
#define KASAN_TBI_ZALLOC_FREE_TAG   0xF0
#define KASAN_TBI_REDZONE_POISON    0x80

#if defined(ARM_LARGE_MEMORY)
#define KASAN_TBI_SHADOW_MIN        (VM_MAX_KERNEL_ADDRESS+1)
#define KASAN_TBI_SHADOW_MAX        0xffffffffffffffffULL
#else
#define KASAN_TBI_SHADOW_MIN        0xfffffffe00000000ULL
#define KASAN_TBI_SHADOW_MAX        0xffffffffc0000000ULL
#endif

#if !CONFIG_KERNEL_TBI
#error "KASAN-TBI requires KERNEL DATA TBI enabled"
#endif /* CONFIG_KERNEL_TBI */

/*
 * Untagged kernel addresses start with 0xFF. Match that whenever we create
 * valid regions.
 */
void
kasan_impl_fill_valid_range(uintptr_t page, size_t size)
{
	(void) __nosan_memset((void *)page, 0xFF, size);
}

void
kasan_impl_init(void)
{
	/*
	 * KASAN depends on CONFIG_KERNEL_TBI, therefore (DATA) TBI has been
	 * set for us already at bootstrap.
	 */
	kasan_tbi_enabled = true;

	/* Enable checking early on */
	kasan_tbi_check_tag = true;

	/*
	 * Sanity check on features that are effectively disabled, but might have
	 * erroneously been setup by legacy boot-args
	 */
	if (fakestack_enabled) {
		fakestack_enabled = 0;
	}
}

void NOINLINE
kasan_init_globals(vm_offset_t __unused base, vm_size_t __unused size)
{
	/*
	 * KASAN-TBI global support awaits compiler fixes to generate descriptive
	 * structures similar to KASAN-CLASSIC (see rdar://73914854)
	 */
}

void
kasan_impl_kdp_disable(void)
{
	kasan_tbi_check_tag = false;
	kasan_tbi_enabled = false;
}

/* redzones are not necessary with HWASAN */
void
kasan_unpoison_cxx_array_cookie(void __unused *ptr)
{
	return;
}

static char *
kasan_tbi_decode_access(access_t access)
{
	if (access & TYPE_LOAD) {
		return "read from";
	}
	if (access & TYPE_WRITE) {
		return "write to";
	}

	return "acccess to";
}

size_t
kasan_impl_decode_issue(char *logbuf, size_t bufsize, uptr p, uptr width, access_t access, violation_t __unused reason)
{
	size_t n = 0;

	n += scnprintf(logbuf, bufsize, "KASAN_TBI: invalid %lu-byte %s %#lx\n",
	    width, kasan_tbi_decode_access(access), p);

	return n;
}

void OS_NORETURN
kasan_handle_brk_failure(vm_offset_t addr, uint16_t esr)
{
	uptr width = KASAN_TBI_GET_SIZE(esr);
	access_t access;

	if (esr & KASAN_TBI_ESR_WRITE) {
		access = TYPE_STORE;
	} else {
		access = TYPE_LOAD;
	}

	kasan_crash_report(addr, width, access, REASON_MOD_OOB);
}

/*
 * To a large extent, KASAN TBI doesn't require any poisoning, since versions
 * mismatch is enough of a sentinel. Notwithstanding this, kasan_poison() is
 * maintained for compatibility and to detect unexpected usages. And is still
 * at the base of our initial global variables support for feature parity
 * with KASAN CLASSIC.
 */
void NOINLINE
kasan_poison(vm_offset_t base, vm_size_t size, vm_size_t leftrz,
    vm_size_t rightrz, uint8_t __unused flags)
{
	/* ensure base, leftrz and total allocation size are granule-aligned */
	assert(kasan_granule_partial(base) == 0);
	assert(kasan_granule_partial(leftrz) == 0);
	assert(kasan_granule_partial(leftrz + size + rightrz) == 0);

	kasan_tbi_tag_range(base, leftrz, KASAN_TBI_REDZONE_POISON);
	kasan_tbi_tag_range(base + leftrz, size, KASAN_TBI_DEFAULT_TAG);
	kasan_tbi_tag_range(base + leftrz + size, rightrz, KASAN_TBI_REDZONE_POISON);
}

void OS_NOINLINE
kasan_impl_late_init(void)
{
}

uintptr_t
kasan_tbi_tag_range(uintptr_t addr, size_t sz, uint8_t tag)
{
	if (sz == 0) {
		return addr;
	}

	uint8_t *shadow_first = SHADOW_FOR_ADDRESS(addr);
	uint8_t *shadow_last = SHADOW_FOR_ADDRESS(addr + P2ROUNDUP(sz, 16));

	__nosan_memset((void *)shadow_first, tag, shadow_last - shadow_first);
	return (uintptr_t)kasan_tbi_tag_ptr((long)addr, tag);
}

/*
 * This is a simplified, slightly inefficient and not randomized implementation
 * of an odd/even tagging model. Tags 0 and 15 are reserved.
 */
uint8_t kasan_tbi_odd_tags[] = {1, 3, 5, 7, 9, 11, 13};
uint8_t kasan_tbi_even_tags[] = {2, 4, 6, 8, 10, 12, 14};
uint8_t kasan_tbi_odd_index = 0;
uint8_t kasan_tbi_even_index = 0;

static uint8_t
kasan_tbi_odd_tag(void)
{
	uint8_t tag = kasan_tbi_odd_tags[kasan_tbi_odd_index++ %
	    sizeof(kasan_tbi_odd_tags)];

	return tag | 0xF0;
}

static uint8_t
kasan_tbi_even_tag(void)
{
	uint8_t tag = kasan_tbi_even_tags[kasan_tbi_even_index++ %
	    sizeof(kasan_tbi_even_tags)];

	return tag | 0xF0;
}

static vm_offset_t
kasan_tbi_do_tag_zone_object(vm_offset_t addr, vm_offset_t elem_size, uint8_t tag, boolean_t zxcpu)
{
	vm_offset_t retaddr = kasan_tbi_tag_range(addr, elem_size, tag);
	/*
	 * If the allocation comes from the per-cpu zones, extend the tag to all
	 * the adjacent, per cpu, instances.
	 */
	if (zxcpu) {
		zpercpu_foreach_cpu(index) {
			(void)kasan_tbi_tag_range(addr + ptoa(index), elem_size, tag);
		}
	}

	return retaddr;
}

void
kasan_tbi_copy_tags(vm_offset_t new_addr, vm_offset_t old_addr, vm_size_t size)
{
	assert((new_addr & KASAN_GRANULE_MASK) == 0);
	assert((old_addr & KASAN_GRANULE_MASK) == 0);
	assert((size & KASAN_GRANULE_MASK) == 0);

	uint8_t *new_shadow = SHADOW_FOR_ADDRESS(new_addr);
	uint8_t *old_shadow = SHADOW_FOR_ADDRESS(old_addr);
	uint8_t *old_end    = SHADOW_FOR_ADDRESS(old_addr + size);

	__nosan_memcpy(new_shadow, old_shadow, old_end - old_shadow);
}

vm_offset_t
kasan_tbi_tag_zalloc(vm_offset_t addr, vm_size_t size, vm_size_t used, boolean_t zxcpu)
{
	uint8_t tag;

	if ((addr / size) % 2) {
		tag = kasan_tbi_odd_tag();
	} else {
		tag = kasan_tbi_even_tag();
	}

	used = kasan_granule_round(used);
	if (used < size) {
		kasan_tbi_tag_zfree(addr + used, size - used, zxcpu);
	}
	return kasan_tbi_do_tag_zone_object(addr, used, tag, zxcpu);
}

vm_offset_t
kasan_tbi_tag_zalloc_default(vm_offset_t addr, vm_size_t size, boolean_t zxcpu)
{
	return kasan_tbi_do_tag_zone_object(addr, size, KASAN_TBI_DEFAULT_TAG, zxcpu);
}

vm_offset_t
kasan_tbi_tag_zfree(vm_offset_t addr, vm_offset_t elem_size, boolean_t zxcpu)
{
	return kasan_tbi_do_tag_zone_object(addr, elem_size, KASAN_TBI_ZALLOC_FREE_TAG, zxcpu);
}

void
__hwasan_tag_memory(uintptr_t p, unsigned char tag, uintptr_t sz)
{
	if (kasan_tbi_enabled) {
		(void)kasan_tbi_tag_range(p, sz, tag);
	}
}

static uint8_t tag_cycle = 0;

unsigned char
__hwasan_generate_tag()
{
	uint8_t tag;

	if (kasan_tbi_enabled) {
		tag = (tag_cycle++ & 0xF) | 0xF0;
	} else {
		tag = 0xFF;
	}
	return tag;
}

/* Query the shadow table and tag the address accordingly */
vm_offset_t
kasan_tbi_fix_address_tag(vm_offset_t addr)
{
	uint8_t *shadow = SHADOW_FOR_ADDRESS(addr);
	return (uintptr_t)kasan_tbi_tag_ptr((long)addr, *shadow);
}

/* Single out accesses to the reserve free tag */
static violation_t
kasan_tbi_estimate_reason(uint8_t __unused access_tag, uint8_t stored_tag)
{
	if (stored_tag == KASAN_TBI_ZALLOC_FREE_TAG) {
		return REASON_MOD_AFTER_FREE;
	}

	return REASON_MOD_OOB;
}

void OS_NOINLINE
kasan_check_range(const void *a, size_t sz, access_t access)
{
	uintptr_t addr = (uintptr_t)a;

	if (!kasan_tbi_check_tag) {
		return;
	}

	/*
	 * Inlining code expects to match the topmost 8 bits, while we only use
	 * four. Unconditionally set to one the others.
	 */
	uint8_t tag = kasan_tbi_get_tag(addr) | 0xF0;

	uint8_t *shadow_first = SHADOW_FOR_ADDRESS(addr);
	uint8_t *shadow_last = SHADOW_FOR_ADDRESS(addr + P2ROUNDUP(sz, 16));

	for (uint8_t *p = shadow_first; p < shadow_last; p++) {
		if (tag == *p) {
			continue;
		}

		/* Tag mismatch, prepare the reporting */
		violation_t reason = kasan_tbi_estimate_reason(tag, *p);
		kasan_violation(addr, sz, access, reason);
	}
}
