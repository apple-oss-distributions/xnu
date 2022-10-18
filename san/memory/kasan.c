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
#include <kern/backtrace.h>
#include <machine/machine_routines.h>
#include <kern/locks.h>
#include <kern/simple_lock.h>
#include <kern/debug.h>
#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/machine/vm_param.h>
#include <mach/sdt.h>
#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/kernel_mach_header.h>
#include <sys/queue.h>
#include <kern/thread.h>
#include <machine/atomic.h>

#include "kasan.h"
#include "kasan_internal.h"
#include "memintrinsics.h"

/*
 * KASAN - Kernel Address SANitizer
 *
 * Address Sanitizer goal is to detect memory corruption issues as they
 * happen. In XNU, we use a couple of different strategies/optimizations,
 * heavily inspired by Google's various sanitizers.
 * Each implementation locks down some amount of memory at boot to implment
 * a shadow table that is then consulted by compiler-inserted
 * instrumentation (mainly) and developer-added calls (mostly for management)
 * at every memory operation.
 *
 * Each of the individual implementations is self contained
 * in its own file.
 *
 * KASAN-CLASSIC (kasan-classic.c)
 *
 * For each 8-byte granule in the address space, one byte is reserved in the shadow
 * table. Cost: ~13% of memory + 20-30MB of quarantine/redzones.
 * See kasan-classic.c for details.
 *
 * KASAN-TBI (kasan-tbi.c)
 *
 * For each 16-byte granule in the address space, one byte is reserved in the
 * shadow table. TBI (Top Byte Ignore) is used to associate a tag to each
 * VA pointer and to match it with the shadow table backing storage. This
 * mode of operation is similar to hardware memory tagging solutions (e.g. MTE)
 * and is not available on x86-64. Cost: ~8% of memory. No need for redzones
 * or quarantines. See kasan-tbi.c for details.
 */

/* Statistics: Track every KEXT that successfully initializes under KASAN */
static unsigned kexts_loaded;

/* Statistics: Track shadow table usage */
unsigned shadow_pages_total;
unsigned shadow_pages_used;

/* Kernel VA shadow table initialization, populated in arch specific code */
vm_offset_t kernel_vbase;
vm_offset_t kernel_vtop;

thread_t kasan_lock_holder;

/* Global KASAN configuration. */
unsigned kasan_enabled;
unsigned kasan_enabled_checks = TYPE_ALL;
int fakestack_enabled;

/* imported osfmk functions */
extern vm_offset_t ml_stack_base(void);
extern vm_size_t ml_stack_size(void);

/*
 * Return true if 'thread' holds the kasan lock. Only safe if 'thread' == current
 * thread
 */
bool
kasan_lock_held(thread_t thread)
{
	return thread && thread == kasan_lock_holder;
}

bool
kasan_check_enabled(access_t access)
{
	return kasan_enabled && (kasan_enabled_checks & access) && !kasan_is_blacklisted(access);
}

void
kasan_poison_range(vm_offset_t base, vm_size_t size, uint8_t flags)
{
	assert(kasan_granule_partial(base) == 0);
	assert(kasan_granule_partial(size) == 0);

	/* size=0, leftsz=0, rightsz=size */
	kasan_poison(base, 0, 0, size, flags);
}

void NOINLINE
kasan_unpoison(void *base, vm_size_t size)
{
	/* size=size, leftsz=0, rightsz=0 */
	kasan_poison((vm_offset_t)base, size, 0, 0, 0);
}

void NOINLINE
kasan_unpoison_stack(uintptr_t base, size_t size)
{
	assert(base > 0);
	assert(size > 0);

	size_t partial = kasan_granule_partial(base);
	base = kasan_granule_trunc(base);
	size = kasan_granule_round(size + partial);

	kasan_unpoison((void *)base, size);
}

void NOINLINE
kasan_unpoison_curstack(bool whole_stack)
{
	uintptr_t base = ml_stack_base();
	size_t sz = ml_stack_size();
	uintptr_t cur = (uintptr_t)&base;

	if (whole_stack) {
		cur = base;
	}

	if (cur >= base && cur < base + sz) {
		/* unpoison from current stack depth to the top */
		size_t unused = cur - base;
		kasan_unpoison_stack(cur, sz - unused);
	}
}

void NOINLINE
__asan_handle_no_return(void)
{
	kasan_unpoison_curstack(false);

	/*
	 * No need to free any fakestack objects because they must stay alive until
	 * we drop the real stack, at which point we can drop the entire fakestack
	 * anyway.
	 */
}

void NOINLINE
kasan_load_kext(vm_offset_t base, vm_size_t __unused size, const void *bundleid)
{
	unsigned long sectsz;
	void *sect;

#if KASAN_DYNAMIC_BLACKLIST
	kasan_dybl_load_kext(base, bundleid);
#endif

	/* find the kasan globals segment/section */
	sect = getsectdatafromheader((void *)base, KASAN_GLOBAL_SEGNAME, KASAN_GLOBAL_SECTNAME, &sectsz);
	if (sect) {
		kasan_init_globals((vm_address_t)sect, (vm_size_t)sectsz);
		kexts_loaded++;
	}
}

void NOINLINE
kasan_unload_kext(vm_offset_t base, vm_size_t size)
{
	unsigned long sectsz;
	void *sect;

	/* find the kasan globals segment/section */
	sect = getsectdatafromheader((void *)base, KASAN_GLOBAL_SEGNAME, KASAN_GLOBAL_SECTNAME, &sectsz);
	if (sect) {
		kasan_unpoison((void *)base, size);
		kexts_loaded--;
	}

#if KASAN_DYNAMIC_BLACKLIST
	kasan_dybl_unload_kext(base);
#endif
}

/*
 * It is not possible to fully enable/disable kasan. Try to disable as much checks
 * as possible to allow panic code path to create a coredump without recursing into
 * KASAN failures.
 *
 * Compiler inlined checks require us to keep running with kasan_enabled = 1 so the
 * shadow map gets properly updated.
 */
void NOINLINE
kasan_kdp_disable(void)
{
	kasan_enabled_checks = 0;
	kasan_impl_kdp_disable();
}

static void NOINLINE
kasan_init_xnu_globals(void)
{
	const char *seg = KASAN_GLOBAL_SEGNAME;
	const char *sect = KASAN_GLOBAL_SECTNAME;
	unsigned long _size;
	vm_offset_t globals;
	vm_size_t size;
	kernel_mach_header_t *header = (kernel_mach_header_t *)&_mh_execute_header;

	if (!header) {
		printf("KASan: failed to find kernel mach header\n");
		printf("KASan: redzones for globals not poisoned\n");
		return;
	}

	globals = (vm_offset_t)getsectdatafromheader(header, seg, sect, &_size);
	if (!globals) {
		printf("KASan: failed to find segment %s section %s\n", seg, sect);
		printf("KASan: redzones for globals not poisoned\n");
		return;
	}
	size = (vm_size_t)_size;

	printf("KASan: found (%s,%s) at %#lx + %lu\n", seg, sect, globals, size);
	kasan_init_globals(globals, size);
}

void NOINLINE
kasan_late_init(void)
{
#if KASAN_DYNAMIC_BLACKLIST
	kasan_init_dybl();
#endif
	kasan_init_xnu_globals();
	kasan_impl_late_init();
}

void NOINLINE
kasan_notify_stolen(vm_offset_t top)
{
	kasan_map_shadow(kernel_vtop, top - kernel_vtop, KASAN_MAY_POISON);
}

static void NOINLINE
kasan_debug_touch_mappings(vm_offset_t base, vm_size_t sz)
{
#if KASAN_DEBUG
	vm_size_t i;
	uint8_t tmp1, tmp2;

	/* Hit every byte in the shadow map. Don't write due to the zero mappings. */
	for (i = 0; i < sz; i += sizeof(uint64_t)) {
		vm_offset_t addr = base + i;
		uint8_t *x = SHADOW_FOR_ADDRESS(addr);
		tmp1 = *x;
		asm volatile ("" ::: "memory");
		tmp2 = *x;
		asm volatile ("" ::: "memory");
		assert(tmp1 == tmp2);
	}
#else
	(void)base;
	(void)sz;
#endif
}

/* Valid values for kasan= boot-arg */
#define KASAN_ARGS_FAKESTACK       0x0010U
#define KASAN_ARGS_REPORTIGNORED   0x0020U
#define KASAN_ARGS_NODYCHECKS      0x0100U
#define KASAN_ARGS_NOPOISON_HEAP   0x0200U
#define KASAN_ARGS_NOPOISON_GLOBAL 0x0400U

void NOINLINE
kasan_init(void)
{
	unsigned arg;

	kasan_lock_init();
	/* Map all of the kernel text and data */
	kasan_map_shadow(kernel_vbase, kernel_vtop - kernel_vbase, false);
	kasan_arch_init();

	/* handle KASan boot-args */
	if (PE_parse_boot_argn("kasan.checks", &arg, sizeof(arg))) {
		kasan_enabled_checks = arg;
	}

	if (PE_parse_boot_argn("kasan", &arg, sizeof(arg))) {
		if (arg & KASAN_ARGS_FAKESTACK) {
			fakestack_enabled = 1;
		}
		if (arg & KASAN_ARGS_REPORTIGNORED) {
			report_suppressed_checks = true;
		}
		if (arg & KASAN_ARGS_NODYCHECKS) {
			kasan_enabled_checks &= ~TYPE_DYNAMIC;
		}
		if (arg & KASAN_ARGS_NOPOISON_HEAP) {
			kasan_enabled_checks &= ~TYPE_POISON_HEAP;
		}
		if (arg & KASAN_ARGS_NOPOISON_GLOBAL) {
			kasan_enabled_checks &= ~TYPE_POISON_GLOBAL;
		}
	}

	/* Model specifi handling */
	kasan_impl_init();
	kasan_enabled = 1;
}

static void NOINLINE
kasan_notify_address_internal(vm_offset_t address, vm_size_t size, bool cannot_poison)
{
	assert(address < VM_MAX_KERNEL_ADDRESS);

	if (!kasan_enabled) {
		return;
	}

	if (address < VM_MIN_KERNEL_AND_KEXT_ADDRESS || size == 0) {
		/* only map kernel addresses and actual allocations */
		return;
	}

	boolean_t flags;
	kasan_lock(&flags);
	kasan_map_shadow(address, size, cannot_poison);
	kasan_unlock(flags);
	kasan_debug_touch_mappings(address, size);
}

/*
 * This routine is called throughout xnu to synchronize KASAN's shadow map
 * view with the virtual memory layout modifications.
 */
void
kasan_notify_address(vm_offset_t address, vm_size_t size)
{
	kasan_notify_address_internal(address, size, KASAN_MAY_POISON);
}

/*
 * Notify a range that is always valid and that will never change state.
 * (in KASAN CLASSIC speak, that will never get poisoned).
 */
void
kasan_notify_address_nopoison(vm_offset_t address, vm_size_t size)
{
	kasan_notify_address_internal(address, size, KASAN_CANNOT_POISON);
}

/*
 * Call 'cb' for each contiguous range of the shadow map. This could be more
 * efficient by walking the page table directly.
 */
int
kasan_traverse_mappings(pmap_traverse_callback cb, void *ctx)
{
	uintptr_t shadow_base = (uintptr_t)SHADOW_FOR_ADDRESS(VM_MIN_KERNEL_AND_KEXT_ADDRESS);
	uintptr_t shadow_top = (uintptr_t)SHADOW_FOR_ADDRESS(VM_MAX_KERNEL_ADDRESS);
	shadow_base = vm_map_trunc_page(shadow_base, PAGE_MASK);
	shadow_top = vm_map_round_page(shadow_top, PAGE_MASK);

	uintptr_t start = 0, end = 0;

	for (uintptr_t addr = shadow_base; addr < shadow_top; addr += PAGE_SIZE) {
		if (kasan_is_shadow_mapped(addr)) {
			if (start == 0) {
				start = addr;
			}
			end = addr + PAGE_SIZE;
		} else if (start && end) {
			cb(start, end, ctx);
			start = end = 0;
		}
	}

	if (start && end) {
		cb(start, end, ctx);
	}

	return 0;
}

/*
 * Expose KASAN configuration and an interface to trigger the set of tests
 * through sysctl.
 */
SYSCTL_NODE(_kern, OID_AUTO, kasan, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "");
SYSCTL_COMPAT_INT(_kern_kasan, OID_AUTO, available, CTLFLAG_RD, NULL, KASAN, "");

SYSCTL_UINT(_kern_kasan, OID_AUTO, enabled, CTLFLAG_RD, &kasan_enabled, 0, "");
SYSCTL_STRING(_kern_kasan, OID_AUTO, model, CTLFLAG_RD, KASAN_MODEL_STR, 0, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, checks, CTLFLAG_RW, &kasan_enabled_checks, 0, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, memused, CTLFLAG_RD, &shadow_pages_used, 0, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, memtotal, CTLFLAG_RD, &shadow_pages_total, 0, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, kexts, CTLFLAG_RD, &kexts_loaded, 0, "");

/* Old-style configuration options, maintained for compatibility */
SYSCTL_COMPAT_UINT(_kern_kasan, OID_AUTO, light, CTLFLAG_RD, NULL, KASAN_LIGHT, "");
SYSCTL_COMPAT_UINT(_kern_kasan, OID_AUTO, debug, CTLFLAG_RD, NULL, KASAN_DEBUG, "");
SYSCTL_COMPAT_UINT(_kern_kasan, OID_AUTO, zalloc, CTLFLAG_RD, NULL, KASAN_ZALLOC, "");
SYSCTL_COMPAT_UINT(_kern_kasan, OID_AUTO, kalloc, CTLFLAG_RD, NULL, KASAN_KALLOC, "");
SYSCTL_COMPAT_UINT(_kern_kasan, OID_AUTO, dynamicbl, CTLFLAG_RD, NULL, KASAN_DYNAMIC_BLACKLIST, "");
