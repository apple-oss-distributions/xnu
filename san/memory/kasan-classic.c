/*
 * Copyright (c) 2016-2021 Apple Inc. All rights reserved.
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
#include <kern/assert.h>
#include <kern/cpu_data.h>
#include <machine/machine_routines.h>
#include <kern/locks.h>
#include <kern/simple_lock.h>
#include <kern/debug.h>
#include <kern/backtrace.h>
#include <kern/thread.h>
#include <libkern/libkern.h>
#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/machine/vm_param.h>
#include <mach/sdt.h>
#include <machine/atomic.h>
#include <sys/sysctl.h>

#include "kasan.h"
#include "kasan_internal.h"
#include "memintrinsics.h"
#include "kasan-classic.h"


/*
 * KASAN-CLASSIC
 *
 * This implementation relies on a shadow table that matches each
 * byte with 8 bytes of the kernel virtual address space. The value of this
 * byte is either:
 *
 *  - 0:                the full 8 bytes are addressable
 *  - [1,7]:            the byte is partially addressable (as many valid bytes
 *                      as specified)
 *  - 0xFx, 0xAC, 0xE9: byte is not addressable and poisoned somehow (for a
 *                      complete list, check kasan-classic.h)
 *
 * Through instrumentation of every load and store and through modifications
 * to the kernel to properly record and/or quarantine memory regions as a
 * consequence of memory management operations, KASAN can detect nearly any
 * type of memory corruption, with two big caveats: linear overflows and
 * use-after-free. These are solved by redzoning and quarantines.
 *
 * For linear overflows, if the adjacent memory is valid (as it is common on
 * both stack and heap), KASAN must add redzones next to each buffer.
 * For use-after-free, free'd buffers are not returned immediately on subsequent
 * memory allocation calls, but are 'stored' in a quarantined region, de-facto
 * delaying reallocation.
 *
 * KASAN-CLASSIC has significant memory cost:
 *  1) ~13% of available memory for the shadow table (4G phone -> ~512MB)
 *  2) ~20-30MB of quarantine space
 *  3) extra padding introduced to support redzones
 *
 * (1) and (2) is backed by stealing memory at boot. (3) is instead added at
 * runtime on top of each allocation.
 */

/* Configuration options */
static unsigned quarantine_enabled = 1;               /* Quarantine on/off */
static unsigned free_yield = 0;                       /* ms yield after each free */
static bool checks_enabled = false;                   /* Poision checking on/off */

void
kasan_impl_init(void)
{
	unsigned arg;

	if (PE_parse_boot_argn("kasan.free_yield_ms", &arg, sizeof(arg))) {
		free_yield = arg;
	}

	/* Quarantine is enabled by default */
	quarantine_enabled = 1;

	/* Enable shadow checking early on. */
	checks_enabled = true;
}

void
kasan_impl_kdp_disable(void)
{
	quarantine_enabled = 0;
	__asan_option_detect_stack_use_after_return = 0;
	fakestack_enabled = 0;
	checks_enabled = false;
}

void NOINLINE
kasan_impl_late_init(void)
{
	kasan_init_fakestack();
}

/* Describes the source location where a global is defined. */
struct asan_global_source_location {
	const char *filename;
	int line_no;
	int column_no;
};

/* Describes an instrumented global variable. */
struct asan_global {
	uptr addr;
	uptr size;
	uptr size_with_redzone;
	const char *name;
	const char *module;
	uptr has_dynamic_init;
	struct asan_global_source_location *location;
#if CLANG_MIN_VERSION(8020000)
	uptr odr_indicator;
#endif
};

/* Walk through the globals section and set them up at boot */
void NOINLINE
kasan_init_globals(vm_offset_t base, vm_size_t size)
{
	struct asan_global *glob = (struct asan_global *)base;
	struct asan_global *glob_end = (struct asan_global *)(base + size);
	for (; glob < glob_end; glob++) {
		/*
		 * Add a redzone after each global variable.
		 * size=variable size, leftsz=0, rightsz=redzone
		 */
		kasan_poison(glob->addr, glob->size, 0, glob->size_with_redzone - glob->size, ASAN_GLOBAL_RZ);
	}
}

/* Reporting */
static const char *
kasan_classic_access_to_str(access_t type)
{
	if (type & TYPE_READ) {
		return "load from";
	} else if (type & TYPE_WRITE) {
		return "store to";
	} else if (type & TYPE_FREE) {
		return "free of";
	} else {
		return "access of";
	}
}

static const char *kasan_classic_shadow_strings[] = {
	[ASAN_VALID] =          "VALID",
	[ASAN_PARTIAL1] =       "PARTIAL1",
	[ASAN_PARTIAL2] =       "PARTIAL2",
	[ASAN_PARTIAL3] =       "PARTIAL3",
	[ASAN_PARTIAL4] =       "PARTIAL4",
	[ASAN_PARTIAL5] =       "PARTIAL5",
	[ASAN_PARTIAL6] =       "PARTIAL6",
	[ASAN_PARTIAL7] =       "PARTIAL7",
	[ASAN_STACK_LEFT_RZ] =  "STACK_LEFT_RZ",
	[ASAN_STACK_MID_RZ] =   "STACK_MID_RZ",
	[ASAN_STACK_RIGHT_RZ] = "STACK_RIGHT_RZ",
	[ASAN_STACK_FREED] =    "STACK_FREED",
	[ASAN_STACK_OOSCOPE] =  "STACK_OOSCOPE",
	[ASAN_GLOBAL_RZ] =      "GLOBAL_RZ",
	[ASAN_HEAP_LEFT_RZ] =   "HEAP_LEFT_RZ",
	[ASAN_HEAP_RIGHT_RZ] =  "HEAP_RIGHT_RZ",
	[ASAN_HEAP_FREED] =     "HEAP_FREED",
	[0xff] =                NULL
};

size_t
kasan_impl_decode_issue(char *logbuf, size_t bufsize, uptr p, uptr width, access_t access, violation_t reason)
{
	uint8_t *shadow_ptr = SHADOW_FOR_ADDRESS(p);
	uint8_t shadow_type = *shadow_ptr;
	size_t n = 0;

	const char *shadow_str = kasan_classic_shadow_strings[shadow_type];
	if (!shadow_str) {
		shadow_str = "<invalid>";
	}

	if (reason == REASON_MOD_OOB || reason == REASON_BAD_METADATA) {
		n += scnprintf(logbuf, bufsize, "KASan: free of corrupted/invalid object %#lx\n", p);
	} else if (reason == REASON_MOD_AFTER_FREE) {
		n += scnprintf(logbuf, bufsize, "KASan: UaF of quarantined object %#lx\n", p);
	} else {
		n += scnprintf(logbuf, bufsize, "KASan: invalid %lu-byte %s %#lx [%s]\n",
		    width, kasan_classic_access_to_str(access), p, shadow_str);
	}

	return n;
}

static inline bool
kasan_poison_active(uint8_t flags)
{
	switch (flags) {
	case ASAN_GLOBAL_RZ:
		return kasan_check_enabled(TYPE_POISON_GLOBAL);
	case ASAN_HEAP_RZ:
	case ASAN_HEAP_LEFT_RZ:
	case ASAN_HEAP_RIGHT_RZ:
	case ASAN_HEAP_FREED:
		return kasan_check_enabled(TYPE_POISON_HEAP);
	default:
		return true;
	}
}

/*
 * Create a poisoned redzone at the top and at the end of a (marked) valid range.
 * Parameters:
 *    base: starting address (including the eventual left red zone)
 *    size: size of the valid range
 *    leftrz: size (multiple of KASAN_GRANULE) of the left redzone
 *    rightrz: size (multiple of KASAN_GRANULE) of the right redzone
 *    flags: select between different poisoning options (e.g. stack vs heap)
 */
void NOINLINE
kasan_poison(vm_offset_t base, vm_size_t size, vm_size_t leftrz,
    vm_size_t rightrz, uint8_t flags)
{
	uint8_t *shadow = SHADOW_FOR_ADDRESS(base);
	/*
	 * Buffer size is allowed to not be a multiple of 8. Create a partial
	 * entry in the shadow table if so.
	 */
	uint8_t partial = (uint8_t)kasan_granule_partial(size);
	vm_size_t total = leftrz + size + rightrz;
	vm_size_t i = 0;

	/* ensure base, leftrz and total allocation size are granule-aligned */
	assert(kasan_granule_partial(base) == 0);
	assert(kasan_granule_partial(leftrz) == 0);
	assert(kasan_granule_partial(total) == 0);

	if (!kasan_enabled || !kasan_poison_active(flags)) {
		return;
	}

	leftrz >>= KASAN_SCALE;
	size >>= KASAN_SCALE;
	total >>= KASAN_SCALE;

	uint8_t l_flags = flags;
	uint8_t r_flags = flags;

	if (flags == ASAN_STACK_RZ) {
		l_flags = ASAN_STACK_LEFT_RZ;
		r_flags = ASAN_STACK_RIGHT_RZ;
	} else if (flags == ASAN_HEAP_RZ) {
		l_flags = ASAN_HEAP_LEFT_RZ;
		r_flags = ASAN_HEAP_RIGHT_RZ;
	}

	/*
	 * poison the redzones and unpoison the valid bytes
	 */
	for (; i < leftrz; i++) {
		shadow[i] = l_flags;
	}
	for (; i < leftrz + size; i++) {
		shadow[i] = ASAN_VALID; /* XXX: should not be necessary */
	}
	/* Do we have any leftover valid byte? */
	if (partial && (i < total)) {
		shadow[i] = partial;
		i++;
	}
	for (; i < total; i++) {
		shadow[i] = r_flags;
	}
}

/*
 * write junk into the redzones
 */
static void NOINLINE
kasan_rz_clobber(vm_offset_t base, vm_size_t size, vm_size_t leftrz, vm_size_t rightrz)
{
#if KASAN_DEBUG
	vm_size_t i;
	const uint8_t deadbeef[] = { 0xde, 0xad, 0xbe, 0xef };
	const uint8_t c0ffee[] = { 0xc0, 0xff, 0xee, 0xc0 };
	uint8_t *buf = (uint8_t *)base;

	assert(kasan_granule_partial(base) == 0);
	assert(kasan_granule_partial(leftrz) == 0);
	assert(kasan_granule_partial(size + leftrz + rightrz) == 0);

	for (i = 0; i < leftrz; i++) {
		buf[i] = deadbeef[i % 4];
	}

	for (i = 0; i < rightrz; i++) {
		buf[i + size + leftrz] = c0ffee[i % 4];
	}
#else
	(void)base;
	(void)size;
	(void)leftrz;
	(void)rightrz;
#endif
}

/*
 * Check the shadow table to determine whether [base, base+size) is valid or
 * is poisoned.
 */
static bool NOINLINE
kasan_range_poisoned(vm_offset_t base, vm_size_t size, vm_offset_t *first_invalid)
{
	uint8_t         *shadow;
	vm_size_t       i;

	if (!kasan_enabled) {
		return false;
	}

	size += kasan_granule_partial(base);
	base = kasan_granule_trunc(base);

	shadow = SHADOW_FOR_ADDRESS(base);
	size_t limit = (size + KASAN_GRANULE - 1) / KASAN_GRANULE;

	/* Walk the shadow table, fail on any non-valid value */
	for (i = 0; i < limit; i++, size -= KASAN_GRANULE) {
		assert(size > 0);
		uint8_t s = shadow[i];
		if (s == 0 || (size < KASAN_GRANULE && s >= size && s < KASAN_GRANULE)) {
			/* valid */
			continue;
		} else {
			goto fail;
		}
	}

	return false;

fail:
	if (first_invalid) {
		/* XXX: calculate the exact first byte that failed */
		*first_invalid = base + i * 8;
	}
	return true;
}

/* An 8-byte valid range is indetified by 0 in kasan classic shadow table */
void
kasan_impl_fill_valid_range(uintptr_t page, size_t size)
{
	__nosan_bzero((void *)page, size);
}

/*
 * Verify whether an access to memory is valid. A valid access is one that
 * doesn't touch any region marked as a poisoned redzone or invalid.
 * 'access' records whether the attempted access is a read or a write.
 */
void NOINLINE
kasan_check_range(const void *x, size_t sz, access_t access)
{
	uintptr_t invalid;
	uintptr_t ptr = (uintptr_t)x;

	if (!checks_enabled) {
		return;
	}

	if (kasan_range_poisoned(ptr, sz, &invalid)) {
		size_t remaining = sz - (invalid - ptr);
		kasan_violation(invalid, remaining, access, REASON_POISONED);
	}
}

/*
 * Return true if [base, base+sz) is unpoisoned or matches the passed in
 * shadow value.
 */
bool
kasan_check_shadow(vm_address_t addr, vm_size_t sz, uint8_t shadow_match_value)
{
	/* round 'base' up to skip any partial, which won't match 'shadow' */
	uintptr_t base = kasan_granule_round(addr);
	sz -= base - addr;

	uintptr_t end = base + sz;

	while (base < end) {
		uint8_t *sh = SHADOW_FOR_ADDRESS(base);
		if (*sh && *sh != shadow_match_value) {
			return false;
		}
		base += KASAN_GRANULE;
	}
	return true;
}

static const size_t BACKTRACE_BITS       = 4;
static const size_t BACKTRACE_MAXFRAMES  = (1UL << BACKTRACE_BITS) - 1;

/*
 * KASAN zalloc hooks
 *
 * KASAN can only distinguish between valid and unvalid memory accesses.
 * This property severely limits its applicability to zalloc (and any other
 * memory allocator), whereby linear overflows are generally to valid
 * memory and non-simple use-after-free can hit an already reallocated buffer.
 *
 * To overcome these limitations, KASAN requires a bunch of fairly invasive
 * changes to zalloc to add both red-zoning and quarantines.
 */

struct kasan_alloc_header {
	uint16_t magic;
	uint16_t crc;
	uint32_t alloc_size;
	uint32_t user_size;
	struct {
		uint32_t left_rz : 32 - BACKTRACE_BITS;
		uint32_t frames  : BACKTRACE_BITS;
	};
};
_Static_assert(sizeof(struct kasan_alloc_header) <= KASAN_GUARD_SIZE, "kasan alloc header exceeds guard size");

struct kasan_alloc_footer {
	uint32_t backtrace[0];
};
_Static_assert(sizeof(struct kasan_alloc_footer) <= KASAN_GUARD_SIZE, "kasan alloc footer exceeds guard size");

#define LIVE_XOR ((uint16_t)0x3a65)
#define FREE_XOR ((uint16_t)0xf233)

static uint16_t
magic_for_addr(vm_offset_t addr, uint16_t magic_xor)
{
	uint16_t magic = addr & 0xFFFF;
	magic ^= (addr >> 16) & 0xFFFF;
	magic ^= (addr >> 32) & 0xFFFF;
	magic ^= (addr >> 48) & 0xFFFF;
	magic ^= magic_xor;
	return magic;
}

static struct kasan_alloc_header *
header_for_user_addr(vm_offset_t addr)
{
	return (void *)(addr - sizeof(struct kasan_alloc_header));
}

static struct kasan_alloc_footer *
footer_for_user_addr(vm_offset_t addr, vm_size_t *size)
{
	struct kasan_alloc_header *h = header_for_user_addr(addr);
	vm_size_t rightrz = h->alloc_size - h->user_size - h->left_rz;
	*size = rightrz;
	return (void *)(addr + h->user_size);
}

/*
 * size: user-requested allocation size
 * ret:  minimum size for the real allocation
 */
vm_size_t
kasan_alloc_resize(vm_size_t size)
{
	vm_size_t tmp;
	if (os_add_overflow(size, 4 * PAGE_SIZE, &tmp)) {
		panic("allocation size overflow (%lu)", size);
	}

	if (size >= 128) {
		/* Add a little extra right redzone to larger objects. Gives us extra
		 * overflow protection, and more space for the backtrace. */
		size += 16;
	}

	/* add left and right redzones */
	size += KASAN_GUARD_PAD;

	/* ensure the final allocation is a multiple of the granule */
	size = kasan_granule_round(size);

	return size;
}

extern vm_offset_t vm_kernel_slid_base;

static vm_size_t
kasan_alloc_bt(uint32_t *ptr, vm_size_t sz, vm_size_t skip)
{
	uintptr_t buf[BACKTRACE_MAXFRAMES];
	uintptr_t *bt = buf;

	sz /= sizeof(uint32_t);
	vm_size_t frames = sz;

	if (frames > 0) {
		frames = min((uint32_t)(frames + skip), BACKTRACE_MAXFRAMES);
		frames = backtrace(bt, (uint32_t)frames, NULL, NULL);

		while (frames > sz && skip > 0) {
			bt++;
			frames--;
			skip--;
		}

		/* only store the offset from kernel base, and cram that into 32
		 * bits */
		for (vm_size_t i = 0; i < frames; i++) {
			ptr[i] = (uint32_t)(bt[i] - vm_kernel_slid_base);
		}
	}
	return frames;
}

/* addr: user address of allocation */
static uint16_t
kasan_alloc_crc(vm_offset_t addr)
{
	struct kasan_alloc_header *h = header_for_user_addr(addr);
	vm_size_t rightrz = h->alloc_size - h->user_size - h->left_rz;

	uint16_t crc_orig = h->crc;
	h->crc = 0;

	uint16_t crc = 0;
	crc = __nosan_crc16(crc, (void *)(addr - h->left_rz), h->left_rz);
	crc = __nosan_crc16(crc, (void *)(addr + h->user_size), rightrz);

	h->crc = crc_orig;

	return crc;
}

/*
 * addr: base address of full allocation (including redzones)
 * size: total size of allocation (include redzones)
 * req:  user-requested allocation size
 * lrz:  size of the left redzone in bytes
 * ret:  address of usable allocation
 */
vm_address_t
kasan_alloc(vm_offset_t addr, vm_size_t size, vm_size_t req, vm_size_t leftrz)
{
	if (!addr) {
		return 0;
	}
	assert(size > 0);
	assert(kasan_granule_partial(addr) == 0);
	assert(kasan_granule_partial(size) == 0);

	vm_size_t rightrz = size - req - leftrz;

	kasan_poison(addr, req, leftrz, rightrz, ASAN_HEAP_RZ);
	kasan_rz_clobber(addr, req, leftrz, rightrz);

	addr += leftrz;

	/* stash the allocation sizes in the left redzone */
	struct kasan_alloc_header *h = header_for_user_addr(addr);
	h->magic = magic_for_addr(addr, LIVE_XOR);
	h->left_rz = (uint32_t)leftrz;
	h->alloc_size = (uint32_t)size;
	h->user_size = (uint32_t)req;

	/* ... and a backtrace in the right redzone */
	vm_size_t fsize;
	struct kasan_alloc_footer *f = footer_for_user_addr(addr, &fsize);
	h->frames = (uint32_t)kasan_alloc_bt(f->backtrace, fsize, 2);

	/* checksum the whole object, minus the user part */
	h->crc = kasan_alloc_crc(addr);

	return addr;
}

/*
 * addr: address of usable allocation (excluding redzones)
 * size: total size of allocation (include redzones)
 * req:  user-requested allocation size
 * lrz:  size of the left redzone in bytes
 * ret:  address of usable allocation
 */
vm_address_t
kasan_realloc(vm_offset_t addr, vm_size_t size, vm_size_t req, vm_size_t leftrz)
{
	return kasan_alloc(addr - leftrz, size, req, leftrz);
}

/*
 * addr: user pointer
 * size: returns full original allocation size
 * ret:  original allocation ptr
 */
vm_address_t
kasan_dealloc(vm_offset_t addr, vm_size_t *size)
{
	assert(size && addr);
	struct kasan_alloc_header *h = header_for_user_addr(addr);
	*size = h->alloc_size;
	h->magic = 0; /* clear the magic so the debugger doesn't find a bogus object */
	return addr - h->left_rz;
}

/*
 * return the original user-requested allocation size
 * addr: user alloc pointer
 */
vm_size_t
kasan_user_size(vm_offset_t addr)
{
	struct kasan_alloc_header *h = header_for_user_addr(addr);
	assert(h->magic == magic_for_addr(addr, LIVE_XOR));
	return h->user_size;
}

/*
 * Verify that `addr' (user pointer) is a valid allocation of `type'
 */
void
kasan_check_free(vm_offset_t addr, vm_size_t size, unsigned heap_type)
{
	struct kasan_alloc_header *h = header_for_user_addr(addr);

	if (!checks_enabled) {
		return;
	}

	/* map heap type to an internal access type */
	access_t type = heap_type == KASAN_HEAP_KALLOC    ? TYPE_KFREE  :
	    heap_type == KASAN_HEAP_ZALLOC    ? TYPE_ZFREE  :
	    heap_type == KASAN_HEAP_FAKESTACK ? TYPE_FSFREE : 0;

	/* check the magic and crc match */
	if (h->magic != magic_for_addr(addr, LIVE_XOR)) {
		kasan_violation(addr, size, type, REASON_BAD_METADATA);
	}
	if (h->crc != kasan_alloc_crc(addr)) {
		kasan_violation(addr, size, type, REASON_MOD_OOB);
	}

	/* check the freed size matches what we recorded at alloc time */
	if (h->user_size != size) {
		kasan_violation(addr, size, type, REASON_INVALID_SIZE);
	}

	vm_size_t rightrz_sz = h->alloc_size - h->left_rz - h->user_size;

	/* Check that the redzones are valid */
	if (!kasan_check_shadow(addr - h->left_rz, h->left_rz, ASAN_HEAP_LEFT_RZ) ||
	    !kasan_check_shadow(addr + h->user_size, rightrz_sz, ASAN_HEAP_RIGHT_RZ)) {
		kasan_violation(addr, size, type, REASON_BAD_METADATA);
	}

	/* Check the allocated range is not poisoned */
	kasan_check_range((void *)addr, size, type);
}

/*
 * KASAN Quarantine
 */

struct freelist_entry {
	uint16_t magic;
	uint16_t crc;
	STAILQ_ENTRY(freelist_entry) list;
	union {
		struct {
			vm_size_t size      : 28;
			vm_size_t user_size : 28;
			vm_size_t frames    : BACKTRACE_BITS; /* number of frames in backtrace */
			vm_size_t __unused  : 8 - BACKTRACE_BITS;
		};
		uint64_t bits;
	};
	zone_t zone;
	uint32_t backtrace[];
};
_Static_assert(sizeof(struct freelist_entry) <= KASAN_GUARD_PAD, "kasan freelist header exceeds padded size");

struct quarantine {
	STAILQ_HEAD(freelist_head, freelist_entry) freelist;
	unsigned long entries;
	unsigned long max_entries;
	vm_size_t size;
	vm_size_t max_size;
};

struct quarantine quarantines[] = {
	{ STAILQ_HEAD_INITIALIZER((quarantines[KASAN_HEAP_ZALLOC].freelist)), 0, QUARANTINE_ENTRIES, 0, QUARANTINE_MAXSIZE },
	{ STAILQ_HEAD_INITIALIZER((quarantines[KASAN_HEAP_KALLOC].freelist)), 0, QUARANTINE_ENTRIES, 0, QUARANTINE_MAXSIZE },
	{ STAILQ_HEAD_INITIALIZER((quarantines[KASAN_HEAP_FAKESTACK].freelist)), 0, QUARANTINE_ENTRIES, 0, QUARANTINE_MAXSIZE }
};

static uint16_t
fle_crc(struct freelist_entry *fle)
{
	return __nosan_crc16(0, &fle->bits, fle->size - offsetof(struct freelist_entry, bits));
}

/*
 * addr, sizep: pointer/size of full allocation including redzone
 */
void NOINLINE
kasan_free_internal(void **addrp, vm_size_t *sizep, int type,
    zone_t *zone, vm_size_t user_size, int locked,
    bool doquarantine)
{
	vm_size_t size = *sizep;
	vm_offset_t addr = *(vm_offset_t *)addrp;

	assert(type >= 0 && type < KASAN_HEAP_TYPES);
	if (type == KASAN_HEAP_KALLOC) {
		/* zero-size kalloc allocations are allowed */
		assert(!zone);
	} else if (type == KASAN_HEAP_ZALLOC) {
		assert(zone && user_size);
	} else if (type == KASAN_HEAP_FAKESTACK) {
		assert(zone && user_size);
	}

	/* clobber the entire freed region */
	kasan_rz_clobber(addr, 0, size, 0);

	if (!doquarantine || !quarantine_enabled) {
		goto free_current;
	}

	/* poison the entire freed region */
	uint8_t flags = (type == KASAN_HEAP_FAKESTACK) ? ASAN_STACK_FREED : ASAN_HEAP_FREED;
	kasan_poison(addr, 0, size, 0, flags);

	struct freelist_entry *fle, *tofree = NULL;
	struct quarantine *q = &quarantines[type];
	assert(size >= sizeof(struct freelist_entry));

	/* create a new freelist entry */
	fle = (struct freelist_entry *)addr;
	fle->magic = magic_for_addr((vm_offset_t)fle, FREE_XOR);
	fle->size = size;
	fle->user_size = user_size;
	fle->frames = 0;
	fle->zone = ZONE_NULL;
	if (zone) {
		fle->zone = *zone;
	}
	if (type != KASAN_HEAP_FAKESTACK) {
		/* don't do expensive things on the fakestack path */
		fle->frames = kasan_alloc_bt(fle->backtrace, fle->size - sizeof(struct freelist_entry), 3);
		fle->crc = fle_crc(fle);
	}

	boolean_t flg;
	if (!locked) {
		kasan_lock(&flg);
	}

	if (q->size + size > q->max_size) {
		/*
		 * Adding this entry would put us over the max quarantine size. Free the
		 * larger of the current object and the quarantine head object.
		 */
		tofree = STAILQ_FIRST(&q->freelist);
		if (fle->size > tofree->size) {
			goto free_current_locked;
		}
	}

	STAILQ_INSERT_TAIL(&q->freelist, fle, list);
	q->entries++;
	q->size += size;

	/* free the oldest entry, if necessary */
	if (tofree || q->entries > q->max_entries) {
		tofree = STAILQ_FIRST(&q->freelist);
		STAILQ_REMOVE_HEAD(&q->freelist, list);

		assert(q->entries > 0 && q->size >= tofree->size);
		q->entries--;
		q->size -= tofree->size;

		if (type != KASAN_HEAP_KALLOC) {
			assert((vm_offset_t)zone >= VM_MIN_KERNEL_AND_KEXT_ADDRESS &&
			    (vm_offset_t)zone <= VM_MAX_KERNEL_ADDRESS);
			*zone = tofree->zone;
		}

		size = tofree->size;
		addr = (vm_offset_t)tofree;

		/* check the magic and crc match */
		if (tofree->magic != magic_for_addr(addr, FREE_XOR)) {
			kasan_violation(addr, size, TYPE_UAF, REASON_MOD_AFTER_FREE);
		}
		if (type != KASAN_HEAP_FAKESTACK && tofree->crc != fle_crc(tofree)) {
			kasan_violation(addr, size, TYPE_UAF, REASON_MOD_AFTER_FREE);
		}

		/* clobber the quarantine header */
		__nosan_bzero((void *)addr, sizeof(struct freelist_entry));
	} else {
		/* quarantine is not full - don't really free anything */
		addr = 0;
	}

free_current_locked:
	if (!locked) {
		kasan_unlock(flg);
	}

free_current:
	*addrp = (void *)addr;
	if (addr) {
		kasan_unpoison((void *)addr, size);
		*sizep = size;
	}
}

void NOINLINE
kasan_free(void **addrp, vm_size_t *sizep, int type, zone_t *zone,
    vm_size_t user_size, bool quarantine)
{
	kasan_free_internal(addrp, sizep, type, zone, user_size, 0, quarantine);

	if (free_yield) {
		thread_yield_internal(free_yield);
	}
}

/*
 * Unpoison the C++ array cookie (if it exists). We don't know exactly where it
 * lives relative to the start of the buffer, but it's always the word immediately
 * before the start of the array data, so for naturally-aligned objects we need to
 * search at most 2 shadow bytes.
 */
void
kasan_unpoison_cxx_array_cookie(void *ptr)
{
	uint8_t *shadow = SHADOW_FOR_ADDRESS((uptr)ptr);
	for (size_t i = 0; i < 2; i++) {
		if (shadow[i] == ASAN_ARRAY_COOKIE) {
			shadow[i] = ASAN_VALID;
			return;
		} else if (shadow[i] != ASAN_VALID) {
			/* must have seen the cookie by now */
			return;
		}
	}
}

SYSCTL_UINT(_kern_kasan, OID_AUTO, quarantine, CTLFLAG_RW, &quarantine_enabled, 0, "");
