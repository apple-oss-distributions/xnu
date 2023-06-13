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
#include <kern/btlog.h>
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

_Static_assert(!KASAN_LIGHT, "Light mode not supported by KASan Classic.");

/* Configuration options */
static unsigned quarantine_enabled = 1;               /* Quarantine on/off */
static bool checks_enabled = false;                   /* Poision checking on/off */

/*
 * LLVM contains enough logic to inline check operations against the shadow
 * table and uses this symbol as an anchor to find it in memory.
 */
const uintptr_t __asan_shadow_memory_dynamic_address = KASAN_OFFSET;

void
kasan_impl_init(void)
{
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
	vm_size_t pos = 0;

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
	__nosan_memset(shadow + pos, l_flags, leftrz);
	pos += leftrz;

	__nosan_memset(shadow + pos, ASAN_VALID, size);
	pos += size;

	/* Do we have any leftover valid byte? */
	if (partial && pos < total) {
		shadow[pos++] = partial;
	}

	__nosan_memset(shadow + pos, r_flags, total - pos);
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

__enum_decl(kasan_alloc_state_t, uint16_t, {
	KASAN_STATE_FREED,
	KASAN_STATE_ALLOCATED,
	KASAN_STATE_QUARANTINED,
});

typedef struct kasan_alloc_header {
	union {
		struct {
			kasan_alloc_state_t state;
			uint16_t left_rz;
			uint32_t user_size;
		};
		struct {
			kasan_alloc_state_t state2;
			intptr_t next : 48;
		};
	};
	btref_t  alloc_btref;
	btref_t  free_btref;
} *kasan_alloc_header_t;
static_assert(sizeof(struct kasan_alloc_header) == KASAN_GUARD_SIZE);

static kasan_alloc_header_t
header_for_user_addr(vm_offset_t addr)
{
	return (void *)(addr - sizeof(struct kasan_alloc_header));
}

void
kasan_zmem_add(
	vm_address_t            addr,
	vm_size_t               size,
	vm_offset_t             esize,
	vm_offset_t             offs,
	vm_offset_t             rzsize)
{
	uint8_t *shadow = SHADOW_FOR_ADDRESS(addr);

	assert(kasan_granule_partial(esize) == 0);
	assert(kasan_granule_partial(offs) == 0);
	assert(kasan_granule_partial(rzsize) == 0);
	assert((size - offs) % esize == 0);

	size   >>= KASAN_SCALE;
	esize  >>= KASAN_SCALE;
	offs   >>= KASAN_SCALE;
	rzsize >>= KASAN_SCALE;

	__nosan_memset(shadow, ASAN_HEAP_FREED, size);

	__nosan_memset(shadow, ASAN_HEAP_LEFT_RZ, offs);

	for (vm_offset_t pos = offs; pos < size; pos += esize) {
		__nosan_memset(shadow + pos, ASAN_HEAP_LEFT_RZ, rzsize);
	}
}

void
kasan_zmem_remove(
	vm_address_t            addr,
	vm_size_t               size,
	vm_offset_t             esize,
	vm_offset_t             offs,
	vm_offset_t             rzsize)
{
	uint8_t *shadow = SHADOW_FOR_ADDRESS(addr);

	assert(kasan_granule_partial(esize) == 0);
	assert(kasan_granule_partial(offs) == 0);
	assert(kasan_granule_partial(rzsize) == 0);
	assert((size - offs) % esize == 0);

	if (rzsize) {
		for (vm_offset_t pos = offs + rzsize; pos < size; pos += esize) {
			kasan_alloc_header_t h;

			h = header_for_user_addr(addr + pos);

			assert(h->state == KASAN_STATE_FREED);
			btref_put(h->alloc_btref);
			btref_put(h->free_btref);
		}
	}

	__nosan_memset(shadow, ASAN_VALID, size >> KASAN_SCALE);
}

void
kasan_alloc(
	vm_address_t            addr,
	vm_size_t               size,
	vm_size_t               req,
	vm_size_t               rzsize,
	bool                    percpu,
	void                   *fp)
{
	assert(kasan_granule_partial(addr) == 0);
	assert(kasan_granule_partial(size) == 0);
	assert(kasan_granule_partial(rzsize) == 0);

	if (rzsize) {
		/* stash the allocation sizes in the left redzone */
		kasan_alloc_header_t h = header_for_user_addr(addr);

		btref_put(h->free_btref);
		btref_put(h->alloc_btref);

		h->state       = KASAN_STATE_ALLOCATED;
		h->left_rz     = (uint16_t)rzsize;
		h->user_size   = (uint32_t)req;
		h->alloc_btref = btref_get(fp, BTREF_GET_NOWAIT);
		h->free_btref  = 0;
	}

	kasan_poison(addr, req, 0, size - req, ASAN_HEAP_RZ);
	if (percpu) {
		for (uint32_t i = 1; i < zpercpu_count(); i++) {
			addr += PAGE_SIZE;
			kasan_poison(addr, req, 0, size - req, ASAN_HEAP_RZ);
		}
	}
}

void
kasan_free(
	vm_address_t            addr,
	vm_size_t               size,
	vm_size_t               req,
	vm_size_t               rzsize,
	bool                    percpu,
	void                   *fp)
{
	uint8_t *shadow = SHADOW_FOR_ADDRESS(addr);

	if (rzsize) {
		kasan_alloc_header_t h = header_for_user_addr(addr);

		kasan_check_alloc(addr, size, req);
		assert(h->free_btref == 0);
		h->state      = KASAN_STATE_FREED;
		h->next       = 0;
		h->free_btref = btref_get(fp, BTREF_GET_NOWAIT);
	}

	__nosan_memset(shadow, ASAN_HEAP_FREED, size >> KASAN_SCALE);
	if (percpu) {
		for (uint32_t i = 1; i < zpercpu_count(); i++) {
			shadow += PAGE_SIZE >> KASAN_SCALE;
			__nosan_memset(shadow, ASAN_HEAP_FREED,
			    size >> KASAN_SCALE);
		}
	}
}

void
kasan_alloc_large(vm_address_t addr, vm_size_t req_size)
{
	vm_size_t l_rz = PAGE_SIZE;
	vm_size_t r_rz = round_page(req_size) - req_size + PAGE_SIZE;

	kasan_poison(addr - l_rz, req_size, l_rz, r_rz, ASAN_HEAP_RZ);
}

/*
 * return the original user-requested allocation size
 * addr: user alloc pointer
 */
vm_size_t
kasan_user_size(vm_offset_t addr)
{
	kasan_alloc_header_t h = header_for_user_addr(addr);

	assert(h->state == KASAN_STATE_ALLOCATED);
	return h->user_size;
}

/*
 * Verify that `addr' (user pointer) is a valid allocation
 */
void
kasan_check_alloc(vm_offset_t addr, vm_size_t size, vm_size_t req)
{
	kasan_alloc_header_t h = header_for_user_addr(addr);

	if (!checks_enabled) {
		return;
	}

	if (h->state != KASAN_STATE_ALLOCATED) {
		kasan_violation(addr, req, TYPE_ZFREE, REASON_BAD_METADATA);
	}

	/* check the freed size matches what we recorded at alloc time */
	if (h->user_size != req) {
		kasan_violation(addr, req, TYPE_ZFREE, REASON_INVALID_SIZE);
	}

	vm_size_t rightrz_sz = size - h->user_size;

	/* Check that the redzones are valid */
	if (!kasan_check_shadow(addr - h->left_rz, h->left_rz, ASAN_HEAP_LEFT_RZ) ||
	    !kasan_check_shadow(addr + h->user_size, rightrz_sz, ASAN_HEAP_RIGHT_RZ)) {
		kasan_violation(addr, req, TYPE_ZFREE, REASON_BAD_METADATA);
	}

	/* Check the allocated range is not poisoned */
	kasan_check_range((void *)addr, req, TYPE_ZFREE);
}

/*
 * KASAN Quarantine
 */

typedef struct kasan_quarantine {
	kasan_alloc_header_t  head;
	kasan_alloc_header_t  tail;
	uint32_t              size;
	uint32_t              count;
} *kasan_quarantine_t;

static struct kasan_quarantine PERCPU_DATA(kasan_quarantine);

extern int get_preemption_level(void);

struct kasan_quarantine_result
kasan_quarantine(vm_address_t addr, vm_size_t size)
{
	kasan_alloc_header_t h = header_for_user_addr(addr);
	kasan_quarantine_t   q = PERCPU_GET(kasan_quarantine);
	struct kasan_quarantine_result kqr = { };

	assert(h->state == KASAN_STATE_FREED && h->next == 0);

	h->state = KASAN_STATE_QUARANTINED;

	q->size += size;
	q->count++;
	if (q->tail == NULL) {
		q->head = h;
	} else {
		q->tail->next = (intptr_t)h;
	}
	q->tail = h;

	if (q->size >= QUARANTINE_MAXSIZE || q->count > QUARANTINE_ENTRIES) {
		h = q->head;
		assert(h->state == KASAN_STATE_QUARANTINED);

		q->head  = (kasan_alloc_header_t)(intptr_t)h->next;
		h->state = KASAN_STATE_FREED;
		h->next  = 0;

		kqr.addr = (vm_address_t)(h + 1);
		q->size -= kasan_quarantine_resolve(kqr.addr, &kqr.zone);
		q->count--;
	}

	return kqr;
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
