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
#include <vm/vm_memtag.h>
#include <kern/assert.h>
#include <machine/machine_routines.h>
#include <kern/locks.h>
#include <kern/debug.h>
#include <kern/telemetry.h>
#include <kern/thread.h>
#include <libkern/libkern.h>
#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/machine/vm_param.h>
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
#define KASAN_TBI_DEFAULT_FREE_TAG  0xF0
#define KASAN_TBI_REDZONE_POISON    0x80

#if defined(ARM_LARGE_MEMORY)
#define KASAN_TBI_SHADOW_MIN        (VM_MAX_KERNEL_ADDRESS+1)
#define KASAN_TBI_SHADOW_MAX        0xffffffffffffffffULL
#else
#define KASAN_TBI_SHADOW_MIN        0xfffffffe00000000ULL
#define KASAN_TBI_SHADOW_MAX        0xffffffffc0000000ULL
#endif

#if !CONFIG_KERNEL_TAGGING
#error "KASAN-TBI requires KERNEL TAGGING"
#endif /* CONFIG_KERNEL_TAGGING */

KERNEL_BRK_DESCRIPTOR_DEFINE(kasan_desc,
    .type                = KERNEL_BRK_TYPE_KASAN,
    .base                = KASAN_TBI_ESR_BASE,
    .max                 = KASAN_TBI_ESR_TOP,
    .options             = KERNEL_BRK_UNRECOVERABLE,
    .handle_breakpoint   = kasan_handle_brk_failure);

#if KASAN_LIGHT
extern bool kasan_zone_maps_owned(vm_address_t, vm_size_t);
#endif /* KASAN_LIGHT */
extern uint64_t ml_get_speculative_timebase(void);

/* Stack and large allocations use the whole set of tags. Tags 0 and 15 are reserved. */
static uint8_t kasan_tbi_full_tags[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};

/* Randomize tag allocation through a simple LFSR */
static uint32_t kasan_tbi_lfsr;

/*
 * LLVM contains enough logic to inline check operations against the shadow
 * table and uses this symbol as an anchor to find it in memory.
 */
const uintptr_t __hwasan_shadow_memory_dynamic_address = KASAN_OFFSET;
/* Make LLDB/automated tools happy for now */
const uintptr_t __asan_shadow_memory_dynamic_address = __hwasan_shadow_memory_dynamic_address;

/*
 * Untagged kernel addresses start with 0xFF. Match that whenever we create
 * valid regions.
 */
void
kasan_impl_fill_valid_range(uintptr_t page, size_t size)
{
	(void) __nosan_memset((void *)page, KASAN_TBI_DEFAULT_TAG, size);
}

void
kasan_impl_init(void)
{
	kasan_tbi_lfsr = (uint32_t)ml_get_speculative_timebase();

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
kasan_handle_brk_failure(void* tstate, uint16_t esr)
{
	arm_saved_state_t* state = (arm_saved_state_t *)tstate;
	vm_offset_t addr = saved_state64(state)->x[0];
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
    vm_size_t rightrz, uint8_t flags)
{
	if (!kasan_tbi_enabled) {
		return;
	}

	/* ensure base, leftrz and total allocation size are granule-aligned */
	assert(kasan_granule_partial(base) == 0);
	assert(kasan_granule_partial(leftrz) == 0);
	assert(kasan_granule_partial(leftrz + size + rightrz) == 0);

	uint8_t tag = flags ? flags : KASAN_TBI_DEFAULT_TAG;

	kasan_tbi_tag_range(base, leftrz, KASAN_TBI_REDZONE_POISON);
	kasan_tbi_tag_range(base + leftrz, size, tag);
	kasan_tbi_tag_range(base + leftrz + size, rightrz, KASAN_TBI_REDZONE_POISON);
}

void OS_NOINLINE
kasan_impl_late_init(void)
{
}

static inline uint32_t
kasan_tbi_lfsr_next(void)
{
	uint32_t v = kasan_tbi_lfsr;
	v = (v >> 1) ^ (-(v & 1) & 0x04C11DB7);
	kasan_tbi_lfsr = v;
	return v;
}

static inline uint8_t
kasan_tbi_full_tag(void)
{
	return kasan_tbi_full_tags[kasan_tbi_lfsr_next() %
	       sizeof(kasan_tbi_full_tags)] | 0xF0;
}

uintptr_t
kasan_tbi_tag_range(uintptr_t addr, size_t sz, uint8_t tag)
{
	if (sz == 0) {
		return addr;
	}

	if (tag == 0) {
		tag = KASAN_TBI_DEFAULT_TAG;
	}

#if KASAN_LIGHT
	if (!kasan_zone_maps_owned(addr, sz)) {
		tag = KASAN_TBI_DEFAULT_TAG;
		return (uintptr_t)vm_memtag_add_ptr_tag((long)addr, tag);
	}
#endif /* KASAN_LIGHT */

	uint8_t *shadow_first = SHADOW_FOR_ADDRESS(addr);
	uint8_t *shadow_last = SHADOW_FOR_ADDRESS(addr + P2ROUNDUP(sz, 16));

	__nosan_memset((void *)shadow_first, tag | 0xF0, shadow_last - shadow_first);
	return (uintptr_t)vm_memtag_add_ptr_tag((long)addr, tag);
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

void
__hwasan_tag_memory(uintptr_t p, unsigned char tag, uintptr_t sz)
{
	if (kasan_tbi_enabled) {
#if KASAN_DEBUG
		/* Detect whether we'd be silently overwriting dirty stack */
		if (tag != 0) {
			(void)kasan_check_range((void *)p, sz, 0);
		}
#endif /* KASAN_DEBUG */
		(void)kasan_tbi_tag_range(p, sz, tag);
	}
}

unsigned char
__hwasan_generate_tag(void)
{
	uint8_t tag = KASAN_TBI_DEFAULT_TAG;

#if !KASAN_LIGHT
	if (kasan_tbi_enabled) {
		tag = kasan_tbi_full_tag();
	}
#endif /* !KASAN_LIGHT */

	return tag;
}

/* Get the tag location inside the shadow tag table */
uint8_t *
kasan_tbi_get_tag_address(vm_offset_t address)
{
	return SHADOW_FOR_ADDRESS(address);
}

static inline uint8_t
kasan_tbi_get_tag(vm_offset_t address)
{
	return *kasan_tbi_get_tag_address(address);
}

/* Single out accesses to the reserve free tag */
static violation_t
kasan_tbi_estimate_reason(uint8_t __unused access_tag, uint8_t stored_tag)
{
	if (stored_tag == KASAN_TBI_DEFAULT_FREE_TAG) {
		return REASON_MOD_AFTER_FREE;
	}

	return REASON_MOD_OOB;
}

bool
kasan_check_shadow(vm_address_t addr, vm_size_t sz, uint8_t shadow_match_value)
{
	if (shadow_match_value == 0) {
		kasan_check_range((void *)addr, sz, 1);
	}

	return true;
}

void OS_NOINLINE
kasan_check_range(const void *a, size_t sz, access_t access)
{
	uintptr_t addr = (uintptr_t)a;

	if (!kasan_tbi_check_tag) {
		return;
	}

	/* No point in checking a NULL pointer tag */
	if (a == NULL) {
		return;
	}

	/*
	 * Inlining code expects to match the topmost 8 bits, while we only use
	 * four. Unconditionally set to one the others.
	 */
	uint8_t tag = vm_memtag_extract_tag(addr) | 0xF0;

	/*
	 * Stay on par with inlining instrumentation, that considers untagged
	 * addresses as wildcards.
	 */
	if (tag == KASAN_TBI_DEFAULT_TAG) {
		return;
	}

	uint8_t *shadow_first = SHADOW_FOR_ADDRESS(addr);
	uint8_t *shadow_last = SHADOW_FOR_ADDRESS(addr + P2ROUNDUP(sz, 16));

	/*
	 * Address is tagged. Tag value must match what is present in the
	 * shadow table.
	 */
	for (uint8_t *p = shadow_first; p < shadow_last; p++) {
		if (tag == *p) {
			continue;
		}

		/* Tag mismatch, prepare the reporting */
		violation_t reason = kasan_tbi_estimate_reason(tag, *p);
		uintptr_t fault_addr = vm_memtag_add_ptr_tag(ADDRESS_FOR_SHADOW((uintptr_t)p), tag);
		kasan_violation(fault_addr, sz, access, reason);
	}
}

/*
 * Whenever more than the required space is allocated in a bucket,
 * kasan_tbi_retag_unused_space() can be called to fill-up the remaining
 * chunks (if present) with a newly randomly generated tag value, to catch
 * off-by-small accesses.
 */
void
kasan_tbi_retag_unused_space(vm_offset_t addr, vm_size_t size, vm_size_t used)
{
	used = kasan_granule_round(used);
	if (used < size) {
		vm_offset_t unused_tag_addr = vm_memtag_assign_tag(addr + used, size - used);
		vm_memtag_set_tag(unused_tag_addr, size - used);
	}
}

/*
 * KASAN-TBI tagging is based on virtual address ranges. Whenever we unwire
 * pages from a portion of the VA space in a page based allocator, we reset
 * that VA range to the default free tag value, to catch use-after-free
 * accesses.
 */
void
kasan_tbi_mark_free_space(vm_offset_t addr, vm_size_t size)
{
	addr = vm_memtag_add_ptr_tag(addr, KASAN_TBI_DEFAULT_TAG);
	vm_memtag_set_tag(addr, size);
}

/*
 * KASAN-TBI sanitizer is an implementation of vm_memtag.
 */
__attribute__((always_inline))
void
vm_memtag_bzero(void *buf, vm_size_t n)
{
	bzero(buf, n);
}

/* Query the shadow table and return the associated tag. */
__attribute__((always_inline))
uint8_t
vm_memtag_get_tag(vm_offset_t address)
{
	return kasan_tbi_get_tag(address);
}

__attribute__((always_inline))
vm_offset_t
vm_memtag_fixup_ptr(vm_offset_t address)
{
	return vm_memtag_add_ptr_tag(address, vm_memtag_get_tag(address));
}

__attribute__((always_inline))
void
vm_memtag_set_tag(vm_offset_t address, vm_offset_t size)
{
	uint8_t tag = vm_memtag_extract_tag(address);
	kasan_tbi_tag_range(address, kasan_granule_round(size), tag);
}

__attribute__((always_inline))
vm_offset_t
vm_memtag_assign_tag(vm_offset_t address, __unused vm_size_t size)
{
	uint8_t tag = kasan_tbi_full_tag();
	return vm_memtag_add_ptr_tag((long)address, tag);
}

__attribute__((always_inline)) void
vm_memtag_verify_tag(vm_offset_t tagged_address)
{
	__asan_load1(tagged_address);
}

__attribute__((always_inline)) void
vm_memtag_disable_checking()
{
	/* Nothing to do with KASAN-TBI */
}

__attribute__((always_inline)) void
vm_memtag_enable_checking()
{
	/* Nothing to do with KASAN-TBI */
}
