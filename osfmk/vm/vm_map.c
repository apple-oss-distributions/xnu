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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	vm/vm_map.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Virtual memory mapping module.
 */

#include <mach/vm_types.h>
#include <mach_assert.h>

#include <vm/vm_options.h>

#include <libkern/OSAtomic.h>

#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <mach/vm_behavior.h>
#include <mach/vm_statistics.h>
#include <mach/memory_object.h>
#include <mach/mach_vm_server.h>
#include <machine/cpu_capabilities.h>
#include <mach/sdt.h>

#include <kern/assert.h>
#include <kern/backtrace.h>
#include <kern/counter.h>
#include <kern/exc_guard.h>
#include <kern/kalloc.h>
#include <kern/zalloc_internal.h>
#include <kern/telemetry.h>
#include <kern/trap_telemetry.h>

#include <vm/cpm_internal.h>
#include <vm/vm_log.h>
#include <vm/memory_types.h>
#include <vm/vm_compressor_xnu.h>
#include <vm/vm_compressor_pager_internal.h>
#include <vm/vm_init_xnu.h>
#include <vm/vm_fault_internal.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_page_internal.h>
#include <vm/vm_pageout.h>
#include <vm/pmap.h>
#include <vm/vm_kern_internal.h>
#include <ipc/ipc_port.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/thread_call.h>

#include <mach/vm_map_server.h>
#include <mach/mach_host_server.h>
#include <vm/vm_memtag.h>
#include <vm/vm_protos_internal.h>
#include <vm/vm_purgeable_internal.h>

#include <vm/vm_iokit.h>
#include <vm/vm_lock_perf.h>
#include <vm/vm_entry_lock_internal.h>
#include <vm/vm_shared_region_internal.h>
#include <vm/vm_map_store_internal.h>
#include <vm/vm_memory_entry_xnu.h>
#include <vm/memory_object_internal.h>
#include <vm/vm_memory_entry.h>
#include <vm/vm_sanitize_internal.h>
#include <vm/vm_reclaim_xnu.h>
#if HAS_MTE
#include <vm/vm_mteinfo_internal.h>
#include <arm64/mte.h>
#include <arm64/mte_xnu.h>
#endif /* HAS_MTE */

#include <vm/vm_map_lock_internal.h>
#include <vm/vm_entry_lock_internal.h>
#if DEVELOPMENT || DEBUG
#include <vm/vm_compressor_info.h>
#endif /* DEVELOPMENT || DEBUG */
#include <ptrcheck.h>
#include <san/kasan.h>

#include <sys/resource.h>
#include <sys/random.h>
#include <sys/codesign.h>
#include <sys/code_signing.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/kdebug_triage.h>
#include <sys/reason.h>

#include <os/log.h>

#include <libkern/section_keywords.h>
#include <libkern/coreanalytics/coreanalytics.h>

#include <os/hash.h>

#if DEVELOPMENT || DEBUG
extern int proc_selfcsflags(void);
int vm_log_xnu_user_debug = 0;
int panic_on_unsigned_execute = 0;
int panic_on_mlock_failure = 0;
int vm_has_range_locking = 1;
#endif /* DEVELOPMENT || DEBUG */

#if DEVELOPMENT || DEBUG
int debug4k_filter = 0;
char debug4k_proc_name[1024] = "";
int debug4k_proc_filter = (int)-1 & ~(1 << __DEBUG4K_FAULT);
int debug4k_panic_on_misaligned_sharing = 0;
const char *debug4k_category_name[] = {
	"error",        /* 0 */
	"life",         /* 1 */
	"load",         /* 2 */
	"fault",        /* 3 */
	"copy",         /* 4 */
	"share",        /* 5 */
	"adjust",       /* 6 */
	"pmap",         /* 7 */
	"mementry",     /* 8 */
	"iokit",        /* 9 */
	"upl",          /* 10 */
	"exc",          /* 11 */
	"vfs"           /* 12 */
};
#endif /* DEVELOPMENT || DEBUG */
int debug4k_no_cow_copyin = 0;


#if __arm64__
extern const int fourk_binary_compatibility_unsafe;
#endif /* __arm64__ */
extern int proc_selfpid(void);
extern char *proc_name_address(void *p);
extern const char *proc_best_name(struct proc *p);

#if VM_MAP_DEBUG_APPLE_PROTECT
int vm_map_debug_apple_protect = 0;
#endif /* VM_MAP_DEBUG_APPLE_PROTECT */
#if VM_MAP_DEBUG_FOURK
int vm_map_debug_fourk = 0;
#endif /* VM_MAP_DEBUG_FOURK */

#if DEBUG || DEVELOPMENT
static TUNABLE(bool, vm_map_executable_immutable,
    "vm_map_executable_immutable", true);
#else
#define vm_map_executable_immutable true
#endif

TUNABLE_WRITEABLE(int, vm_lock_contention_debug,
    "vm_lock_contention_debug", 1);

void
vm_map_set_lock_contention_debug(vm_map_t map, bool enable)
{
	vm_map_ilk_lock(map);
	map->lock_contention_debug = enable;
	vm_map_ilk_unlock(map);
}

/** Do not enforce the kernel allocation size limit */
#define VM_MAP_KERNEL_ALLOC_LIMIT_MODE_BYPASS (0)
/** Enforce the kernel allocation limit by refusing too large requests */
#define VM_MAP_KERNEL_ALLOC_LIMIT_MODE_REJECT (1)
/** Enforce the kernel allocation limit by panicking on any too large request */
#define VM_MAP_KERNEL_ALLOC_LIMIT_MODE_PANIC (2)
/** Do not enforce the kernel allocation limit but generate a telemetry trap */
#define VM_MAP_KERNEL_ALLOC_LIMIT_MODE_TRAP (3)

#if DEVELOPMENT || DEBUG
static TUNABLE(int, vm_map_kernel_alloc_limit_mode,
    "vm_map_kernel_alloc_limit_mode", VM_MAP_KERNEL_ALLOC_LIMIT_MODE_REJECT);
#else
#define vm_map_kernel_alloc_limit_mode VM_MAP_KERNEL_ALLOC_LIMIT_MODE_REJECT
#endif

os_refgrp_decl(static, map_refgrp, "vm_map", NULL);

struct vm_map_zap;
extern u_int32_t random(void);  /* from <libkern/libkern.h> */
/* Internal prototypes
 */

extern kern_return_t vm_map_wire_external(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              prot_u,
	boolean_t               user_wire) __exported;

#if XNU_PLATFORM_MacOSX
extern /* exported via Private.<arch>.MacOSX.exports on macOS */
#else
static
#endif
kern_return_t vm_map_copyin_common(
	vm_map_t                src_map,
	vm_map_address_ut       src_addr,
	vm_map_size_ut          len,
	boolean_t               src_destroy,
	boolean_t               src_volatile,
	vm_map_copy_t          *copy_result,                           /* OUT */
	boolean_t               use_maxprot);

static vm_map_entry_t   vm_map_entry_create_locked_and_insert(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_map_kernel_flags_t   vmk_flags,
	boolean_t               needs_copy,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance);

__static_testable void vm_map_simplify_range(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end);   /* forward */

__static_testable kern_return_t vm_map_delete_and_iunlock(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vmr_flags_t             flags,
	kmem_guard_t            guard,
	vm_map_entry_t         *sentinel,
	struct vm_map_zap      *zap);

__options_closed_decl(vm_map_copyin_strategy, uint8_t, {
	VM_MAP_COPYIN_STRATEGY_INVALID_ARGUMENT,
	VM_MAP_COPYIN_STRATEGY_KERNEL_BUFFER,
	/*
	 * If we decided to bounce to the kernel buffer for security reasons
	 * (MTE region or data private range), we avoid COW and allow large buffers.
	 */
	VM_MAP_COPYIN_STRATEGY_KERNEL_LARGE_BUFFER,
	VM_MAP_COPYIN_STRATEGY_VIRTUAL_COPY,
});

static kern_return_t    vm_map_copyin_kernel_buffer(
	vm_map_t        src_map,
	vm_map_address_t src_addr,
	vm_map_size_t   len,
	vm_map_copyin_strategy strategy,
	boolean_t       src_destroy,
	vm_map_copy_t   *copy_result);  /* OUT */

static kern_return_t    vm_map_copyout_kernel_buffer(
	vm_map_t        map,
	vm_map_address_t *addr, /* IN/OUT */
	vm_map_copy_t   copy,
	vm_map_size_t   copy_size,
	boolean_t       overwrite,
#if HAS_MTE
	boolean_t       sec_override,
#endif
	boolean_t       consume_on_success);

static void             vm_map_fork_share(
	vm_map_lock_ctx_t old_ctx,
	vm_map_entry_t    old_entry,
	vm_map_t          new_map);

static boolean_t        vm_map_fork_copy(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t    old_entry,
	vm_map_t          new_map,
	int               vm_map_copyin_flags);

static kern_return_t    vm_map_remap_extract(
	vm_map_t                map,
	vm_map_offset_t         addr,
	vm_map_size_t           size,
	const bool              do_copy,
	vm_map_copy_t           map_copy,
	vm_prot_t               *cur_protection,
	vm_prot_t               *max_protection,
	vm_inherit_t            inheritance,
	vm_map_kernel_flags_t   vmk_flags);

static void             vm_map_region_look_for_page(
	vm_map_t                   map,
	vm_map_offset_t            va,
	vm_object_t                object,
	vm_object_offset_t         offset,
	int                        max_refcnt,
	unsigned short             depth,
	vm_region_extended_info_t  extended,
	mach_msg_type_number_t count);

static kern_return_t    vm_map_willneed(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end);

static kern_return_t    vm_map_reuse_pages(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end);

static kern_return_t    vm_map_reusable_pages(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end);

static kern_return_t    vm_map_can_reuse(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end);

__static_testable kern_return_t    vm_map_zero(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end);

#if CONFIG_MAP_RANGES

static vm_map_range_id_t vm_map_user_range_resolve(
	vm_map_t                map,
	mach_vm_address_t       addr,
	mach_vm_address_t       size,
	mach_vm_range_t         range);

#endif /* CONFIG_MAP_RANGES */
#if MACH_ASSERT

static kern_return_t    vm_map_pageout(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end);

#endif /* MACH_ASSERT */

kern_return_t vm_map_corpse_footprint_collect(
	vm_map_t        old_map,
	vm_map_entry_t  old_entry,
	vm_map_t        new_map);
void vm_map_corpse_footprint_collect_done(
	vm_map_t        new_map);
void vm_map_corpse_footprint_destroy(
	vm_map_t        map);
kern_return_t vm_map_corpse_footprint_query_page_info(
	vm_map_t        map,
	vm_map_offset_t va,
	int             *disposition_p);
void vm_map_footprint_query_page_info(
	vm_map_t        map,
	vm_map_entry_t  map_entry,
	vm_map_offset_t curr_s_offset,
	int             *disposition_p);

#if CONFIG_MAP_RANGES
static void vm_map_range_map_init(void);
#endif /* CONFIG_MAP_RANGES */

pid_t find_largest_process_vm_map_entries(void);

uint8_t vm_map_entry_info_flags(
	vm_map_entry_t entry);

static bool
vm_map_entry_should_cow_for_true_share(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t    entry);

#if CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS
/*
 * Generic function to strip an address out of all its metadata bits (PAC, MTE, TBI).
 */
vm_map_address_t
vm_map_strip_addr(vm_map_t map, vm_map_address_t ptr)
{
	assert(map && map->pmap);
	return pmap_strip_addr(map->pmap, ptr);
}
#endif /* CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS */

#if DEBUG || DEVELOPMENT
#define panic_on_release_builds(format, ...) \
	({})
#else  /* not DEBUG || DEVELOPMENT */
#define panic_on_release_builds(format, ...) \
	panic(format __VA_OPT__(,) __VA_ARGS__)
#endif /* not DEBUG || DEVELOPMENT */

#pragma mark vm flags / vm map kernel flags

__attribute__((always_inline))
int
vm_map_kernel_flags_vmflags(vm_map_kernel_flags_t vmk_flags)
{
	int flags = vmk_flags.__vm_flags & VM_FLAGS_ANY_MASK;

	/* in vmk flags the meaning of fixed/anywhere is inverted */
	return flags ^ (VM_FLAGS_FIXED | VM_FLAGS_ANYWHERE);
}

__attribute__((always_inline, overloadable))
void
vm_map_kernel_flags_set_vmflags(
	vm_map_kernel_flags_t  *vmk_flags,
	int                     vm_flags,
	vm_tag_t                vm_tag)
{
	vm_flags ^= (VM_FLAGS_FIXED | VM_FLAGS_ANYWHERE);
	vmk_flags->__vm_flags &= ~VM_FLAGS_ANY_MASK;
	vmk_flags->__vm_flags |= (vm_flags & VM_FLAGS_ANY_MASK);
	vmk_flags->vm_tag = vm_tag;
}

__attribute__((always_inline, overloadable))
void
vm_map_kernel_flags_set_vmflags(
	vm_map_kernel_flags_t  *vmk_flags,
	int                     vm_flags_and_tag)
{
	vm_flags_and_tag ^= (VM_FLAGS_FIXED | VM_FLAGS_ANYWHERE);
	vmk_flags->__vm_flags &= ~VM_FLAGS_ANY_MASK;
	vmk_flags->__vm_flags |= (vm_flags_and_tag & VM_FLAGS_ANY_MASK);
	VM_GET_FLAGS_ALIAS(vm_flags_and_tag, vmk_flags->vm_tag);
}

__attribute__((always_inline))
void
vm_map_kernel_flags_and_vmflags(
	vm_map_kernel_flags_t  *vmk_flags,
	int                     vm_flags_mask)
{
	/* this function doesn't handle the inverted FIXED/ANYWHERE */
	assert(vm_flags_mask & VM_FLAGS_ANYWHERE);
	vmk_flags->__vm_flags &= vm_flags_mask;
}

__attribute__((always_inline))
bool
vm_map_kernel_flags_check_vm_and_kflags(
	vm_map_kernel_flags_t   vmk_flags,
	int                     vm_flags_mask)
{
	return (vmk_flags.__vm_flags & ~vm_flags_mask) == 0;
}

bool
vm_map_kernel_flags_check_vmflags(
	vm_map_kernel_flags_t   vmk_flags,
	int                     vm_flags_mask)
{
	int vmflags = vmk_flags.__vm_flags & VM_FLAGS_ANY_MASK;

	static_assert(sizeof(vm_map_kernel_flags_t) == 8);

#if DEBUG || DEVELOPMENT
	/*
	 * All of this compiles to nothing if all checks pass.
	 */
#define check(field, value)  ({ \
	vm_map_kernel_flags_t fl = VM_MAP_KERNEL_FLAGS_NONE; \
	fl.__vm_flags = (value); \
	fl.field = 0; \
	assert(fl.__vm_flags == 0); \
})

	/* bits 0-7 */
	check(vmf_fixed, VM_FLAGS_ANYWHERE); // kind of a lie this is inverted
	check(vmf_purgeable, VM_FLAGS_PURGABLE);
	check(vmf_4gb_chunk, VM_FLAGS_4GB_CHUNK);
	check(vmf_random_addr, VM_FLAGS_RANDOM_ADDR);
	check(vmf_no_cache, VM_FLAGS_NO_CACHE);
	check(vmf_resilient_codesign, VM_FLAGS_RESILIENT_CODESIGN);
	check(vmf_resilient_media, VM_FLAGS_RESILIENT_MEDIA);
	check(vmf_permanent, VM_FLAGS_PERMANENT);

	/* bits 8-15 */
	check(vmf_tpro, VM_FLAGS_TPRO);
#if HAS_MTE
	check(vmf_mte, VM_FLAGS_MTE);
#endif /* HAS_MTE */
	check(vmf_overwrite, VM_FLAGS_OVERWRITE);

	/* bits 16-23 */
	check(vmf_superpage_size, VM_FLAGS_SUPERPAGE_MASK);
	check(vmf_return_data_addr, VM_FLAGS_RETURN_DATA_ADDR);
	check(vmf_guard_object_optout, VM_FLAGS_GUARD_OBJECT_OPTOUT);
	check(vmf_return_4k_data_addr, VM_FLAGS_RETURN_4K_DATA_ADDR);

	{
		vm_map_kernel_flags_t fl = VM_MAP_KERNEL_FLAGS_NONE;

		/* check user tags will never clip */
		fl.vm_tag = VM_MEMORY_COUNT - 1;
		assert(fl.vm_tag == VM_MEMORY_COUNT - 1);

		/* check kernel tags will never clip */
		fl.vm_tag = VM_MAX_TAG_VALUE - 1;
		assert(fl.vm_tag == VM_MAX_TAG_VALUE - 1);
	}


#undef check
#endif /* DEBUG || DEVELOPMENT */

	return (vmflags & ~vm_flags_mask) == 0;
}


#pragma mark vm map entry create/copy/reinit_after_copy/free

/*
 *	_vm_map_entry_create:	[ internal use only ]
 *
 *	This is the backend of vm_map_entry_create_locked()
 *	and vm_map_copy_entry_create().
 *
 *	Do not call directly.
 *
 *	The VM entry will be zero initialized, except for:
 *	- behavior set to VM_BEHAVIOR_DEFAULT
 *	- inheritance set to VM_INHERIT_DEFAULT
 */
static vm_map_entry_t
_vm_map_entry_create(vm_map_address_t start, vm_map_address_t end)
{
	vm_map_entry_t entry = VM_MAP_ENTRY_NULL;

	entry = zalloc_id(ZONE_ID_VM_MAP_ENTRY, Z_WAITOK_ZERO_NOFAIL);

	/*
	 * Help the compiler with what we know to be true,
	 * so that the further bitfields inits have good codegen.
	 *
	 * See rdar://87041299
	 */
	__builtin_assume(entry->vme_object_value == 0);
	__builtin_assume(*(uint64_t *)(&entry->vme_object_value + 1) == 0);
	__builtin_assume(*(uint64_t *)(&entry->vme_object_value + 2) == 0);

	static_assert(VM_MAX_TAG_VALUE <= VME_ALIAS_MASK,
	    "VME_ALIAS_MASK covers tags");

	static_assert(VM_BEHAVIOR_DEFAULT == 0,
	    "can skip zeroing of the behavior field");
	entry->inheritance = VM_INHERIT_DEFAULT;
	entry->vme_start = start;
	entry->vme_end   = end;

#if MAP_ENTRY_CREATION_DEBUG
//	entry->vme_creation_maphdr = map_header;
#endif
	return entry;
}

/*
 *	_vm_map_entry_copy:	[ internal use only ]
 *
 *	This is the backend of vm_map_entry_copy_locked*()
 *	and vm_map_copy_entry_copy*().
 *
 *	Do not call directly.
 *
 *	Whether the entry owns a reference on the object/submap
 *	depends on the "own_obj" parameer.
 */
static vm_map_entry_t
_vm_map_entry_copy(vm_map_entry_t original, bool own_obj)
{
	vm_map_entry_t copy;

	assert(!VME_IS_SENTINEL(original));

	copy = _vm_map_entry_create(0, 0);

	/* Retain the btref in the old entry to account for its copy */
#if MAP_ENTRY_CREATION_DEBUG
	btref_retain(original->vme_creation_bt);
#endif
#if MAP_ENTRY_INSERTION_DEBUG
	btref_retain(original->vme_insertion_bt);
#endif
#if VM_BTLOG_TAGS
	if (original->vme_kernel_object) {
		btref_retain(original->vme_tag_btref);
	}
#endif /* VM_BTLOG_TAGS */
	if (own_obj) {
		if (original->is_sub_map) {
			vm_map_reference(VME_SUBMAP(original));
		} else if (!VME_IS_SENTINEL(original)) {
			vm_object_reference(VME_OBJECT(original));
		}
	}

	*copy = *original;
	copy->vme_chunk = VMS_POINTER_NULL;
	copy->vme_prev  = VM_MAP_ENTRY_NULL;
	copy->vme_next  = VM_MAP_ENTRY_NULL;
	/* caller will init the lock properly */

	return copy;
}

/*
 *	_vm_map_entry_free:	[ internal use only ]
 *
 *	This is the backend of vm_map_entry_free_locked()
 *	and vm_map_copy_entry_free().
 *
 *	Do not call directly
 */
static void
_vm_map_entry_free(vm_map_entry_t entry, bool own_obj)
{
	assert(entry->vme_next == VM_MAP_ENTRY_NULL &&
	    entry->vme_prev == VM_MAP_ENTRY_NULL);

	if (own_obj) {
		if (entry->is_sub_map) {
			vm_map_deallocate(VME_SUBMAP(entry));
		} else if (!VME_IS_SENTINEL(entry)) {
			vm_object_deallocate(VME_OBJECT(entry));
		}
	}
#if VM_BTLOG_TAGS
	if (entry->vme_kernel_object) {
		btref_put(entry->vme_tag_btref);
	}
#endif /* VM_BTLOG_TAGS */
#if MAP_ENTRY_CREATION_DEBUG
	btref_put(entry->vme_creation_bt);
#endif
#if MAP_ENTRY_INSERTION_DEBUG
	btref_put(entry->vme_insertion_bt);
#endif
	zfree(vm_map_entry_zone, entry);
}

vm_map_entry_t
vm_map_entry_create_locked(
	vm_map_t                map,
	vm_map_address_t        start,
	vm_map_address_t        end)
{
	vm_map_entry_t entry;

	entry = _vm_map_entry_create(start, end);

#if MAP_ENTRY_CREATION_DEBUG
	entry->vme_creation_bt = btref_get(__builtin_frame_address(0),
	    BTREF_GET_NOWAIT);
#endif

	vm_entry_lock_init_locked_exclusive(map, entry);
	return entry;
}

vm_map_entry_t
vm_map_entry_create_sentinel_locked(
	vm_map_t                map,
	mach_vm_address_t       start,
	mach_vm_address_t       end)
{
	vm_map_entry_t sentinel = vm_map_entry_create_locked(map, start, end);

	sentinel->use_pmap = true;
	VME_OBJECT_SET(sentinel, sentinel_object, false, 0);
	VME_OFFSET_SET(sentinel, start);
	return sentinel;
}

/*!
 * @function vm_map_entry_copy_locked
 *
 * @brief Make a copy of an entry.
 *
 * @param map   The map the entry belongs to.
 * @param entry The entry to copy.
 *
 * @return The copied entry, exclusively locked.
 */
vm_map_entry_t
vm_map_entry_copy_locked(vm_map_t map, vm_map_entry_t entry)
{
	vm_map_entry_t new_entry;
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	new_entry = _vm_map_entry_copy(entry, true);
	vm_entry_lock_init_locked_exclusive(map, new_entry);
	return new_entry;
}

/*!
 * @function vm_map_entry_copy_locked_no_ownership
 *
 * @brief Make a copy of an entry without taking a reference on the object.
 *
 * @discussion This is intended to facilitate entry copies in certain copy
 * functions that have complex refcounting. We should remove it after we
 * rework that refcounting.
 *
 * @param map   The map the entry belongs to.
 * @param entry The entry to copy.
 *
 * @return The copied entry, exclusively locked.
 */
static vm_map_entry_t
vm_map_entry_copy_locked_no_ownership(vm_map_t map, vm_map_entry_t entry)
{
	vm_map_entry_t new_entry;
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	new_entry = _vm_map_entry_copy(entry, false);
	vm_entry_lock_init_locked_exclusive(map, new_entry);
	return new_entry;
}

void
vm_map_entry_free_locked(vm_map_t map, vm_map_entry_t entry)
{
	vm_entry_unlock_exclusive_and_destroy(map, entry);
	_vm_map_entry_free(entry, true);
}

__static_testable vm_map_entry_t
vm_map_copy_entry_create(
	vm_map_copy_t           copy __unused,
	vm_map_address_t        start,
	vm_map_address_t        end)
{
	vm_map_entry_t entry;

	entry = _vm_map_entry_create(start, end);

#if MAP_ENTRY_CREATION_DEBUG
	entry->vme_creation_bt = btref_get(__builtin_frame_address(0),
	    BTREF_GET_NOWAIT);
#endif

	vm_entry_lock_init_invalid(entry, VMEL_INVALID_REASON_COPY_ENTRY);
	return entry;
}

vm_map_entry_t
vm_map_copy_entry_copy(vm_map_copy_t copy __unused, vm_map_entry_t entry)
{
	vm_map_entry_t new_entry;

	new_entry = _vm_map_entry_copy(entry, true);
	vm_entry_lock_init_invalid(new_entry, VMEL_INVALID_REASON_COPY_ENTRY);
	return new_entry;
}

static vm_map_entry_t
vm_map_copy_entry_copy_no_ownership(vm_map_copy_t copy __unused, vm_map_entry_t entry)
{
	vm_map_entry_t new_entry;

	new_entry = _vm_map_entry_copy(entry, false);
	vm_entry_lock_init_invalid(new_entry, VMEL_INVALID_REASON_COPY_ENTRY);
	return new_entry;
}

/*!
 * @function vm_map_copy_entry_convert
 *
 * @brief
 * Converts a vm_map_entry intended for use in a copy_map into a locked
 * vm_map_entry ready to be inserted into a real map.
 *
 * @param [in]      copy The copy map from which the entry comes.
 * @param [in]      map The map the entry will be inserted into.
 * @param [in,out]  entry The entry being converted.
 */
static void
vm_map_copy_entry_convert(
	vm_map_copy_t           copy __unused,
	vm_map_t                map,
	vm_map_entry_t          entry)
{
	VM_ENTRY_ASSERT_LOCK_INVALID(entry, VMEL_INVALID_REASON_COPY_ENTRY);
	vm_entry_lock_init_locked_exclusive(map, entry);
}

static void
vm_map_copy_entry_free(vm_map_copy_t copy __unused, vm_map_entry_t entry)
{
	vm_entry_lock_destroy_invalid(entry);
	_vm_map_entry_free(entry, true);
}

static void
vm_map_copy_entry_free_no_ownership(vm_map_copy_t copy __unused, vm_map_entry_t entry)
{
	vm_entry_lock_destroy_invalid(entry);
	_vm_map_entry_free(entry, false);
}

static inline void
vm_map_entry_reinit_csm_assoc_after_copy(
	vm_map_t                map __assert_only,
	vm_map_entry_t          entry __assert_only)
{
#if CODE_SIGNING_MONITOR
	/* when code signing monitor is enabled, we want to reset on copy */
	entry->csm_associated = false;
#else
	/* when code signing monitor is not enabled, assert as a sanity check */
	assert(entry->csm_associated == false);
#endif
#if DEVELOPMENT || DEBUG
	if (entry->vme_xnu_user_debug && vm_log_xnu_user_debug) {
		printf("FBDP %d[%s] %s:%d map %p entry %p [ 0x%llx 0x%llx ] vme_xnu_user_debug\n",
		    proc_selfpid(),
		    (get_bsdtask_info(current_task())
		    ? proc_name_address(get_bsdtask_info(current_task()))
		    : "?"),
		    __FUNCTION__, __LINE__,
		    map, entry, entry->vme_start, entry->vme_end);
	}
#endif /* DEVELOPMENT || DEBUG */
#if XNU_TARGET_OS_OSX
	/*
	 * On macOS, entries with "vme_xnu_user_debug" can be copied during fork()
	 * and we want the child's entry to keep its "vme_xnu_user_debug" to avoid
	 * trigggering CSM assertions when the child accesses its mapping.
	 */
#else /* XNU_TARGET_OS_OSX */
	entry->vme_xnu_user_debug = false;
#endif /* XNU_TARGET_OS_OSX */
}

/*
 * The "used_for_jit" flag was copied from OLD to NEW in
 * vm_map_entry_reinit_after_copy().
 *
 * But for security reasons on some platforms, we don't want the
 * new mapping to be "used for jit", so we reset the flag here.
 */
static inline void
vm_map_entry_reinit_code_signing_after_copy(vm_map_t map, vm_map_entry_t entry)
{
	if (!VM_MAP_POLICY_ALLOW_JIT_COPY(map) && entry->used_for_jit) {
		DTRACE_VM3(cs_wx,
		    uint64_t, entry->vme_start,
		    uint64_t, entry->vme_end,
		    vm_prot_t, entry->protection);
		printf("CODE SIGNING: %d[%s] %s: curprot cannot be write+execute. %s\n",
		    proc_selfpid(),
		    (get_bsdtask_info(current_task())
		    ? proc_name_address(get_bsdtask_info(current_task()))
		    : "?"),
		    __FUNCTION__,
		    "removing execute access");
		entry->protection &= ~VM_PROT_EXECUTE;
		entry->max_protection &= ~VM_PROT_EXECUTE;
		entry->used_for_jit = false;
	}
}

static inline void
vm_map_entry_reinit_after_copy(vm_map_t map, vm_map_entry_t entry)
{
	entry->is_shared = false;
	entry->wired_count = 0;
	entry->user_wired_count = 0;
	entry->vme_permanent = false;
	vm_map_entry_reinit_code_signing_after_copy(map, entry);
	vm_map_entry_reinit_csm_assoc_after_copy(map, entry);
	if (entry->iokit_acct) {
		assert(!entry->use_pmap);
		entry->iokit_acct = false;
		entry->use_pmap = true;
	}
	entry->vme_resilient_codesign = false;
	entry->vme_resilient_media = false;
	entry->vme_atomic = false;
	entry->vme_no_copy_on_read = false;
}


#pragma mark vm map zap

/*
 * A zap list is a list containing entries which were removed from a map.
 * The purpose of the zap list is to allow us to roll back some deletion if
 * something goes wrong. In that case, the zap list is iterated and the entries
 * reinserted into the map (see vm_map_enter).
 */
typedef struct vm_map_zap {
	vm_map_entry_t          vmz_head;
	vm_map_entry_t         *vmz_tail;
} *vm_map_zap_t;

#define VM_MAP_ZAP_DECLARE(zap) \
	struct vm_map_zap zap = { .vmz_tail = &zap.vmz_head }

static vm_map_entry_t
vm_map_zap_first_entry(vm_map_zap_t list)
{
	return list->vmz_head;
}

static vm_map_entry_t
vm_map_zap_last_entry(vm_map_zap_t list)
{
	assert(vm_map_zap_first_entry(list));
	return __container_of(list->vmz_tail, struct vm_map_entry, vme_next);
}

static void
vm_map_zap_append(vm_map_zap_t list, vm_map_entry_t entry)
{
	assert(!VME_IS_SENTINEL(entry));
	entry->vme_next = VM_MAP_ENTRY_NULL;
	*list->vmz_tail = entry;
	list->vmz_tail = &entry->vme_next;
}

static vm_map_entry_t
vm_map_zap_pop(vm_map_zap_t list)
{
	vm_map_entry_t head = list->vmz_head;

	if (head != VM_MAP_ENTRY_NULL) {
		if ((list->vmz_head = head->vme_next) == VM_MAP_ENTRY_NULL) {
			list->vmz_tail = &list->vmz_head;
		}
		head->vme_next = VM_MAP_ENTRY_NULL;
	}

	return head;
}

static void
vm_map_zap_dispose(vm_map_t map __unused, vm_map_zap_t list)
{
	vm_map_entry_t          entry;

	while ((entry = vm_map_zap_pop(list))) {
		/*
		 * RANGELOCKINGTODO:
		 * we don't know whether the entry came from map or one of its
		 * submaps. vm_map_entry_free_locked doesn't rely on the map
		 * param at this point so we pass NULL to force a crash if that
		 * changes in the future.
		 * We should resolve this situation at
		 * rdar://145705126 (Consider dropping the unused map param to vm_entry_unlock_exclusive)
		 */
		vm_map_entry_free_locked(NULL, entry);
	}
}


#pragma mark unsorted

/*!
 * @function kdp_vm_map_is_acquired_exclusive
 *
 * @abstract
 * Checks if vm map is acquired exclusive.
 *
 * @discussion
 * NOT SAFE: To be used only by kernel debugger.
 *
 * @param map map to check
 *
 * @returns TRUE if the map is acquired exclusively.
 */
boolean_t
kdp_vm_map_is_acquired_exclusive(vm_map_t map)
{
	return kdp_lck_rw_lock_is_acquired_exclusive(&map->ilock);
}

/*
 * Routines to get the page size the caller should
 * use while inspecting the target address space.
 * Use the "_safely" variant if the caller is dealing with a user-provided
 * array whose size depends on the page size, to avoid any overflow or
 * underflow of a user-allocated buffer.
 */
int
vm_self_region_page_shift_safely(
	vm_map_t target_map)
{
	int effective_page_shift = 0;

	if (PAGE_SIZE == (4096)) {
		/* x86_64 and 4k watches: always use 4k */
		return PAGE_SHIFT;
	}
	/* did caller provide an explicit page size for this thread to use? */
	effective_page_shift = thread_self_region_page_shift();
	if (effective_page_shift) {
		/* use the explicitly-provided page size */
		return effective_page_shift;
	}
	/* no explicit page size: use the caller's page size... */
	effective_page_shift = VM_MAP_PAGE_SHIFT(current_map());
	if (effective_page_shift == VM_MAP_PAGE_SHIFT(target_map)) {
		/* page size match: safe to use */
		return effective_page_shift;
	}
	/* page size mismatch */
	return -1;
}
int
vm_self_region_page_shift(
	vm_map_t target_map)
{
	int effective_page_shift;

	effective_page_shift = vm_self_region_page_shift_safely(target_map);
	if (effective_page_shift == -1) {
		/* no safe value but OK to guess for caller */
		effective_page_shift = MIN(VM_MAP_PAGE_SHIFT(current_map()),
		    VM_MAP_PAGE_SHIFT(target_map));
	}
	return effective_page_shift;
}


/*
 *	Decide if we want to allow processes to execute from their data or stack areas.
 *	override_nx() returns true if we do.  Data/stack execution can be enabled independently
 *	for 32 and 64 bit processes.  Set the VM_ABI_32 or VM_ABI_64 flags in allow_data_exec
 *	or allow_stack_exec to enable data execution for that type of data area for that particular
 *	ABI (or both by or'ing the flags together).  These are initialized in the architecture
 *	specific pmap files since the default behavior varies according to architecture.  The
 *	main reason it varies is because of the need to provide binary compatibility with old
 *	applications that were written before these restrictions came into being.  In the old
 *	days, an app could execute anything it could read, but this has slowly been tightened
 *	up over time.  The default behavior is:
 *
 *	32-bit PPC apps		may execute from both stack and data areas
 *	32-bit Intel apps	may exeucte from data areas but not stack
 *	64-bit PPC/Intel apps	may not execute from either data or stack
 *
 *	An application on any architecture may override these defaults by explicitly
 *	adding PROT_EXEC permission to the page in question with the mprotect(2)
 *	system call.  This code here just determines what happens when an app tries to
 *      execute from a page that lacks execute permission.
 *
 *	Note that allow_data_exec or allow_stack_exec may also be modified by sysctl to change the
 *	default behavior for both 32 and 64 bit apps on a system-wide basis. Furthermore,
 *	a Mach-O header flag bit (MH_NO_HEAP_EXECUTION) can be used to forcibly disallow
 *	execution from data areas for a particular binary even if the arch normally permits it. As
 *	a final wrinkle, a posix_spawn attribute flag can be used to negate this opt-in header bit
 *	to support some complicated use cases, notably browsers with out-of-process plugins that
 *	are not all NX-safe.
 */

extern int allow_data_exec, allow_stack_exec;

int
override_nx(vm_map_t map, uint32_t user_tag) /* map unused on arm */
{
	int current_abi;

	if (map->pmap == kernel_pmap) {
		return FALSE;
	}

	/*
	 * Determine if the app is running in 32 or 64 bit mode.
	 */

	if (vm_map_is_64bit(map)) {
		current_abi = VM_ABI_64;
	} else {
		current_abi = VM_ABI_32;
	}

	/*
	 * Determine if we should allow the execution based on whether it's a
	 * stack or data area and the current architecture.
	 */

	if (user_tag == VM_MEMORY_STACK) {
		return allow_stack_exec & current_abi;
	}

	return (allow_data_exec & current_abi) && (map->map_disallow_data_exec == FALSE);
}


/*
 *	Virtual memory maps provide for the mapping, protection,
 *	and sharing of virtual memory objects.  In addition,
 *	this module provides for an efficient virtual copy of
 *	memory from one map to another.
 *
 *	Synchronization is required prior to most operations.
 *
 *	Maps consist of an ordered doubly-linked list of simple
 *	entries; a single hint is used to speed up lookups.
 *
 *	Sharing maps have been deleted from this version of Mach.
 *	All shared objects are now mapped directly into the respective
 *	maps.  This requires a change in the copy on write strategy;
 *	the asymmetric (delayed) strategy is used for shared temporary
 *	objects instead of the symmetric (shadow) strategy.  All maps
 *	are now "top level" maps (either task map, kernel map or submap
 *	of the kernel map).
 *
 *	Since portions of maps are specified by start/end addreses,
 *	which may not align with existing map entries, all
 *	routines merely "clip" entries to these start/end values.
 *	[That is, an entry is split into two, bordering at a
 *	start or end value.]  Note that these clippings may not
 *	always be necessary (as the two resulting entries are then
 *	not changed); however, the clipping is done for convenience.
 *	No attempt is currently made to "glue back together" two
 *	abutting entries.
 *
 *	The symmetric (shadow) copy strategy implements virtual copy
 *	by copying VM object references from one map to
 *	another, and then marking both regions as copy-on-write.
 *	It is important to note that only one writeable reference
 *	to a VM object region exists in any map when this strategy
 *	is used -- this means that shadow object creation can be
 *	delayed until a write operation occurs.  The symmetric (delayed)
 *	strategy allows multiple maps to have writeable references to
 *	the same region of a vm object, and hence cannot delay creating
 *	its copy objects.  See vm_object_copy_quickly() in vm_object.c.
 *	Copying of permanent objects is completely different; see
 *	vm_object_copy_strategically() in vm_object.c.
 */

ZONE_DECLARE_ID(ZONE_ID_VM_MAP_COPY, struct vm_map_copy);

#define VM_MAP_ZFLAGS           (ZC_NOENCRYPT | ZC_VM)

#define VM_MAP_ZONE_NAME        "maps"
#define VM_MAP_ENTRY_ZONE_NAME  "VM map entries"
#define VM_MAP_NODES_ZONE_NAME  "VM map nodes"

/*
 * Asserts that a vm_map_copy object is coming from the
 * vm_map_copy_zone to ensure that it isn't a fake constructed
 * anywhere else.
 */
void
vm_map_copy_require(struct vm_map_copy *copy)
{
	zone_id_require(ZONE_ID_VM_MAP_COPY, sizeof(struct vm_map_copy), copy);
}

/*
 *	vm_map_require:
 *
 *	Ensures that the argument is memory allocated from the genuine
 *	vm map zone. (See zone_id_require_allow_foreign).
 */
void
vm_map_require(vm_map_t map)
{
	zone_id_require(ZONE_ID_VM_MAP, sizeof(struct _vm_map), map);
}

#define VM_MAP_EARLY_COUNT_MAX         16
static __startup_data vm_offset_t      map_stolen_data;
static __startup_data vm_size_t        map_data_size;
static __startup_data vm_size_t        kentry_data_size;
static __startup_data vm_size_t        map_nodes_data_size;
static __startup_data vm_map_t        *early_map_owners[VM_MAP_EARLY_COUNT_MAX];
static __startup_data uint32_t         early_map_count;

#if XNU_TARGET_OS_OSX
#define         NO_COALESCE_LIMIT  ((1024 * 128) - 1)
#else /* XNU_TARGET_OS_OSX */
#define         NO_COALESCE_LIMIT  0
#endif /* XNU_TARGET_OS_OSX */

/* Skip acquiring locks if we're in the midst of a kernel core dump */
unsigned int not_in_kdp = 1;

unsigned int vm_map_set_cache_attr_count = 0;

kern_return_t
vm_map_set_cache_attr(
	vm_map_t        map,
	vm_map_offset_t va)
{
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t  map_entry;
	vm_object_t     object;
	kern_return_t   kr = KERN_SUCCESS;

	vmlp_api_start(VM_MAP_SET_CACHE_ATTR);

	kr = vm_map_find_entry_sh_locked(ctx, &map, va, VMRL_FIND_SH_DEFAULT);
	if (kr != KERN_SUCCESS) {
		goto done_unlocked;
	}

	map_entry = vm_map_found_entry_get_entry(ctx);
	if (map_entry->is_sub_map) {
		/*
		 * that memory is not properly mapped
		 */
		kr = KERN_INVALID_ARGUMENT;
		goto done;
	}

	object = VME_OBJECT(map_entry);

	if (object == VM_OBJECT_NULL) {
		/*
		 * there should be a VM object here at this point
		 */
		kr = KERN_INVALID_ARGUMENT;
		goto done;
	}
	vm_object_lock(object);
	object->set_cache_attr = TRUE;
	vm_object_unlock(object);

	vm_map_set_cache_attr_count++;
done:
	vm_map_found_entry_sh_unlock(ctx, &map);
done_unlocked:
	vmlp_api_end(VM_MAP_SET_CACHE_ATTR, kr);
	return kr;
}


#if CONFIG_CODE_DECRYPTION
/*
 * vm_map_apple_protected:
 * This remaps the requested part of the object with an object backed by
 * the decrypting pager.
 * crypt_info contains entry points and session data for the crypt module.
 * The crypt_info block will be copied by vm_map_apple_protected. The data structures
 * referenced in crypt_info must remain valid until crypt_info->crypt_end() is called.
 */
kern_return_t
vm_map_apple_protected(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_object_offset_t      crypto_backing_offset,
	struct pager_crypt_info *crypt_info,
	uint32_t                cryptid)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t   kr;
	vm_map_entry_t  map_entry;
	struct vm_map_entry tmp_entry;
	memory_object_t unprotected_mem_obj = MEMORY_OBJECT_NULL;
	vm_object_t     protected_object;
	vm_object_offset_t protected_offset;
	vm_map_offset_t map_addr;
	vm_map_offset_t start_aligned, end_aligned;
	vm_object_offset_t      crypto_start, crypto_end;
	boolean_t       cache_pager;
	vm_map_copy_t   copy_map = VM_MAP_COPY_NULL;
	vm_prot_t       cur_prot, max_prot;
	vm_map_entry_t  copy_entry;

	vmlp_api_start(VM_MAP_APPLE_PROTECTED);

	/*
	 * This function is intended for userspace maps only,
	 * in Mach-O loading and mremap_encrypted().
	 * Kernel transparent submaps are unimplemented below.
	 */
	assert(!vm_kernel_map_is_kernel(map));

	if (__improbable(vm_map_range_overflows(map, start, end - start))) {
		vmlp_api_end(VM_MAP_APPLE_PROTECTED, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}
	start_aligned = vm_map_trunc_page(start, PAGE_MASK_64);
	end_aligned = vm_map_round_page(end, PAGE_MASK_64);
	start_aligned = vm_map_trunc_page(start_aligned, VM_MAP_PAGE_MASK(map));
	end_aligned = vm_map_round_page(end_aligned, VM_MAP_PAGE_MASK(map));

#if __arm64__
	/*
	 * "start" and "end" might be 4K-aligned but not 16K-aligned,
	 * so we might have to loop and establish up to 3 mappings:
	 *
	 * + the first 16K-page, which might overlap with the previous
	 *   4K-aligned mapping,
	 * + the center,
	 * + the last 16K-page, which might overlap with the next
	 *   4K-aligned mapping.
	 * Each of these mapping might be backed by a vnode pager (if
	 * properly page-aligned) or a "fourk_pager", itself backed by a
	 * vnode pager (if 4K-aligned but not page-aligned).
	 */
#endif /* __arm64__ */

	/* extract a copy-on-write copy of the range to be unprotected */
	vm_map_kernel_flags_t vmk_flags_copy = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags_copy.vmkf_copy_same_map = true;
	cur_prot = VM_PROT_READ;
	if (cryptid != CRYPTID_MODEL_ENCRYPTION) {
		cur_prot |= VM_PROT_EXECUTE;
	}
	max_prot = cur_prot;
	/* XXX flag to prevent copying submap entries? */
	copy_map = VM_MAP_COPY_NULL;
	kr = vm_map_copy_extract(map, start_aligned, end_aligned - start_aligned,
	    true /* copy */, &copy_map, &cur_prot, &max_prot, VM_INHERIT_NONE, vmk_flags_copy);
	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_APPLE_PROTECTED, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}
	assert(copy_map != VM_MAP_COPY_NULL);
	assert3u(copy_map->type, ==, VM_MAP_COPY_ENTRY_LIST);

	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
		/*
		 * We require there to be an existing object, otherwise the
		 * memory is not properly mapped for this call.
		 */
		if (vme->is_sub_map) {
		        return KERN_INVALID_ARGUMENT;
		}
		if (VME_OBJECT(vme) == VM_OBJECT_NULL) {
		        return KERN_INVALID_ARGUMENT;
		}

		/* ensure mapped memory is mapped as executable
		 * except for model decryption flow */
		if ((cryptid != CRYPTID_MODEL_ENCRYPTION) &&
		!(vme->protection & VM_PROT_EXECUTE)) {
		        return KERN_INVALID_ARGUMENT;
		}

		return KERN_SUCCESS;
	});


	kr = vm_map_range_ex_lock(ctx, &map, start_aligned, end_aligned,
	    VMRL_EX_STREAM);
	if (kr != KERN_SUCCESS) {
		vm_map_copy_discard(copy_map);
		copy_map = VM_MAP_COPY_NULL;
		vmlp_api_end(VM_MAP_APPLE_PROTECTED, kr);
		return kr;
	}

	copy_entry = vm_map_copy_first_entry(copy_map);
	while ((map_entry = vm_map_range_stream_next_with_error(ctx, &kr))) {
		/*
		 * No submap descent. Exclusive range lock does not descend
		 * into constant submaps, and transparent submaps don't happen
		 * because the map is not a kernel map (as asserted above).
		 */
		assert(!vm_map_lock_ctx_is_descended(ctx));

		if (copy_entry == VM_MAP_ENTRY_NULL ||
		    copy_entry == vm_map_copy_to_entry(copy_map)) {
			kr = KERN_INVALID_ADDRESS;
			goto done;
		}
		assert(!copy_entry->is_sub_map);
		if (copy_entry->is_sub_map) {
			kr = KERN_INVALID_ADDRESS;
			goto done;
		}
		if ((copy_entry->vme_end - copy_entry->vme_start) !=
		    (map_entry->vme_end - map_entry->vme_start)) {
			/* map entry size mismatch: something changed, give up */
			kr = KERN_INVALID_ADDRESS;
			goto done;
		}

		/*
		 * Get the relevant (copied) object from the copy_entry,
		 * then drop the lock on the current entry.
		 * The copy_entry holds a reference on the protected_object so
		 * it won't go away until we discard copy_map.
		 */
		protected_object = VME_OBJECT(copy_entry);
		if (protected_object == VM_OBJECT_NULL) {
			kr = KERN_INVALID_ADDRESS;
			goto done;
		}
		protected_offset = VME_OFFSET(copy_entry);

		tmp_entry = *map_entry;
		vm_map_range_stream_drop(ctx);
		map_entry = VM_MAP_ENTRY_NULL; /* not valid after unlocking entry */

		/*
		 * This map entry might be only partially encrypted
		 * (if not fully "page-aligned").
		 */
		crypto_start = 0;
		crypto_end = tmp_entry.vme_end - tmp_entry.vme_start;
		if (tmp_entry.vme_start < start) {
			if (tmp_entry.vme_start != start_aligned) {
				kr = KERN_INVALID_ADDRESS;
				goto done;
			}
			crypto_start += (start - tmp_entry.vme_start);
		}
		if (tmp_entry.vme_end > end) {
			if (tmp_entry.vme_end != end_aligned) {
				kr = KERN_INVALID_ADDRESS;
				goto done;
			}
			crypto_end -= (tmp_entry.vme_end - end);
		}

		/*
		 * This "extra backing offset" is needed to get the decryption
		 * routine to use the right key.  It adjusts for the possibly
		 * relative offset of an interposed "4K" pager...
		 */
		if (crypto_backing_offset == (vm_object_offset_t) -1) {
			crypto_backing_offset = VME_OFFSET(&tmp_entry);
		}

		cache_pager = TRUE;
#if XNU_TARGET_OS_OSX
		vm_map_ilk_lock(ctx->vmlc_map);
		if (vm_map_is_alien(ctx->vmlc_map)) {
			cache_pager = FALSE;
		}
		vm_map_ilk_unlock(ctx->vmlc_map);
#endif /* XNU_TARGET_OS_OSX */

		/*
		 * Lookup (and create if necessary) the protected memory object
		 * matching that VM object.
		 * If successful, this also grabs a reference on the memory object,
		 * to guarantee that it doesn't go away before we get a chance to map
		 * it.
		 */
		unprotected_mem_obj = apple_protect_pager_setup(
			protected_object,
			VME_OFFSET(&tmp_entry),
			crypto_backing_offset,
			crypt_info,
			crypto_start,
			crypto_end,
			cache_pager);
		if (unprotected_mem_obj == NULL) {
			kr = KERN_FAILURE;
			goto done;
		}

		/* can overwrite an immutable mapping */
		vm_map_kernel_flags_t vmk_flags = {
			.vmf_fixed = true,
			.vmf_overwrite = true,
			.vmkf_overwrite_immutable = true,
		};
		/* make the new mapping as "permanent" as the one it replaces */
		vmk_flags.vmf_permanent = tmp_entry.vme_permanent;

		/* map this memory object in place of the current one */
		map_addr = tmp_entry.vme_start;
		kr = mach_vm_map_kernel(ctx->vmlc_map,
		    vm_sanitize_wrap_addr_ref(&map_addr),
		    (tmp_entry.vme_end -
		    tmp_entry.vme_start),
		    (mach_vm_offset_t) 0,
		    vmk_flags,
		    (ipc_port_t)(uintptr_t) unprotected_mem_obj,
		    0,
		    TRUE,
		    tmp_entry.protection,
		    tmp_entry.max_protection,
		    tmp_entry.inheritance);
		assertf(kr == KERN_SUCCESS,
		    "kr = 0x%x\n", kr);
		assertf(map_addr == tmp_entry.vme_start,
		    "map_addr=0x%llx vme_start=0x%llx tmp_entry=%p\n",
		    (uint64_t)map_addr,
		    (uint64_t) tmp_entry.vme_start,
		    &tmp_entry);

#if VM_MAP_DEBUG_APPLE_PROTECT
		if (vm_map_debug_apple_protect) {
			printf("APPLE_PROTECT: map %p [0x%llx:0x%llx] pager %p:"
			    " backing:[object:%p,offset:0x%llx,"
			    "crypto_backing_offset:0x%llx,"
			    "crypto_start:0x%llx,crypto_end:0x%llx]\n",
			    vm_map_lock_ctx_get_map(ctx),
			    (uint64_t) map_addr,
			    (uint64_t) (map_addr + (tmp_entry.vme_end -
			    tmp_entry.vme_start)),
			    unprotected_mem_obj,
			    protected_object,
			    VME_OFFSET(&tmp_entry),
			    crypto_backing_offset,
			    crypto_start,
			    crypto_end);
		}
#endif /* VM_MAP_DEBUG_APPLE_PROTECT */

		/*
		 * Release the reference obtained by
		 * apple_protect_pager_setup().
		 * The mapping (if it succeeded) is now holding a reference on
		 * the memory object.
		 */
		memory_object_deallocate(unprotected_mem_obj);
		unprotected_mem_obj = MEMORY_OBJECT_NULL;

		/* continue with next map entry */
		crypto_backing_offset += (tmp_entry.vme_end -
		    tmp_entry.vme_start);
		crypto_backing_offset -= crypto_start;
		/* and next copy entry */
		copy_entry = copy_entry->vme_next;
	}

done:
	if (copy_map) {
		vm_map_copy_discard(copy_map);
		copy_map = VM_MAP_COPY_NULL;
	}
	vmlp_api_end(VM_MAP_APPLE_PROTECTED, kr);
	vm_map_range_ex_unlock(ctx, &map);
	return kr;
}
#endif  /* CONFIG_CODE_DECRYPTION */


LCK_GRP_DECLARE(vm_map_lck_grp, "vm_map");
LCK_ATTR_DECLARE(vm_map_lck_attr, 0, 0);
LCK_ATTR_DECLARE(vm_map_lck_rw_attr, 0, LCK_ATTR_DEBUG);

#if XNU_TARGET_OS_OSX
#define MALLOC_NO_COW_DEFAULT 1
#define MALLOC_NO_COW_EXCEPT_FORK_DEFAULT 1
#else /* XNU_TARGET_OS_OSX */
#define MALLOC_NO_COW_DEFAULT 1
#define MALLOC_NO_COW_EXCEPT_FORK_DEFAULT 0
#endif /* XNU_TARGET_OS_OSX */
TUNABLE(int, malloc_no_cow, "malloc_no_cow", MALLOC_NO_COW_DEFAULT);
TUNABLE(int, malloc_no_cow_except_fork, "malloc_no_cow_except_fork", MALLOC_NO_COW_EXCEPT_FORK_DEFAULT);
uint64_t vm_memory_malloc_no_cow_mask = 0ULL;

#if MACH_ASSERT

/*
 * Debugging options.
 *
 * To enable individual options:
 * - set variable 'vm_your_option_name' below to true
 * - OR set boot-arg 'vm_your_option_name=1'
 *
 * To enable all options:
 * - set boot-arg 'vm_debug=1'
 * - set boot-arg 'vm_your_option_name=0' to override that and disable an option
 *
 * Test vm/vm_boot_with_debug_boot_args boots the test device
 * with boot-arg 'vm_debug=1' and passes if it boots successfully.
 */

static struct {
	bool *option_variable;
	const char *name;
} vm_debug_options[] = {
};

/*
 * true if any of the above vm_debug options are set.
 * Used as a fast path shortcut in performance-sensitive code.
 */
bool vm_debug_any_options_enabled = false;

/*
 * Decode the vm_debug boot-args and set debug option variables.
 */
static void
vm_debug_parse_boot_args(void)
{
	unsigned option_count =
	    sizeof(vm_debug_options) / sizeof(vm_debug_options[0]);
	bool enable_all_options = false;

	/* vm_debug=1 enables all options */
	PE_parse_boot_argn("vm_debug",
	    &enable_all_options, sizeof(enable_all_options));
	if (enable_all_options) {
		printf("vm_debug option vm_debug=1 is set; "
		    "enabling all vm_debug options by default\n");
	}

	for (unsigned i = 0; i < option_count; i++) {
		bool *option_variable = vm_debug_options[i].option_variable;
		const char *option_name = vm_debug_options[i].name;

		if (enable_all_options) {
			*option_variable = true;
		}
		/*
		 * Parse each boot-arg after handling enable_all_options
		 * to allow options to be disabled individually
		 * (i.e. "vm_debug=1 vm_some_debug_option=0" works).
		 */
		PE_parse_boot_argn(option_name,
		    option_variable, sizeof(*option_variable));
		if (*option_variable) {
			printf("vm_debug option %s is enabled; "
			    "disable with boot-arg %s=0\n",
			    option_name, option_name);
			vm_debug_any_options_enabled = true;
		} else {
			printf("vm_debug option %s is disabled; "
			    "enable with boot-arg %s=1\n",
			    option_name, option_name);
		}
	}

	if (!enable_all_options) {
		printf("Enable all vm_debug options with boot-arg vm_debug=1\n");
	}
}

#endif /* MACH_ASSERT */

#if DEBUG || DEVELOPMENT


/*
 * Thread ID of the thread currently holding a VM map entry lock.
 * This variable is used for testing stackshot functionality.
 * In the test, this variable helps in:
 * 1. Identifying which thread is acting as the "blocker" (holding the lock)
 * 2. Ensuring proper lock acquisition ordering in multi-threaded test scenarios
 */
_Atomic uint64_t vm_stackshot_test_blocker_tid = 0;

/*
 * Only for debugging the entry lock. Helps easily cause a situation
 * where a thread holds the lock for a while. used by the sysctl vm_lock_entry.
 * Useful for debugging stackshot support for vm_entry_lock.
 */
kern_return_t
vm_map_dbg_lock_vm_entry_and_block(vm_map_t map, vm_address_t addr, uint64_t size, uint32_t flags)
{
	kern_return_t kr;
	uint64_t current_tid = thread_tid(current_thread());

	vm_map_t original_map = map;
	bool is_stream = (flags & DBG_LCK_FLAG_STREAM);
	/* default is atomic, even if DBG_LCK_FLAG_ATOMIC is not passed */

	VM_MAP_LOCK_CTX_DECLARE(ctx);

	switch (flags & DBG_LCK_FLAG_CALL_TYPE_MASK) {
	case DBG_LCK_FLAG_EXCLUSIVE:
		printf("vm_map_dbg: trying to lock ex with thread (%llu)\n", current_tid);
		kr = vm_map_range_ex_lock(ctx, &map, addr, addr + size, is_stream ? VMRL_EX_STREAM : VMRL_EX_ATOMIC);
		if (kr != KERN_SUCCESS) {
			printf("vm_map_dbg: failed ex lock %d\n", kr);
			return kr;
		}
		printf("vm_map_dbg: locked excl (%p)\n", ctx->vmlc_map);
		os_atomic_cmpxchg(&vm_stackshot_test_blocker_tid, 0, current_tid, relaxed);
		assert(original_map == ctx->vmlc_map);  /* submap descent is unimplemented */
		assert_wait(ctx->vmlc_map, THREAD_UNINT);
		thread_block(THREAD_CONTINUE_NULL);

		vm_map_range_ex_unlock(ctx, &map);
		printf("vm_map_dbg: unlocked excl\n");
		break;
	case DBG_LCK_FLAG_SHARED:
		printf("vm_map_dbg: trying to lock sh with thread (%llu)\n", current_tid);
		kr = vm_map_range_sh_lock(ctx, &map, addr, addr + size, is_stream ? VMRL_SH_STREAM : VMRL_SH_ATOMIC);
		if (kr != KERN_SUCCESS) {
			printf("vm_map_dbg: failed sh lock %d\n", kr);
			return kr;
		}
		printf("vm_map_dbg: locked sh (%p)\n", ctx->vmlc_map);
		os_atomic_cmpxchg(&vm_stackshot_test_blocker_tid, 0, current_tid, relaxed);
		assert(original_map == ctx->vmlc_map);  /* submap descent is unimplemented */
		assert_wait(ctx->vmlc_map, THREAD_UNINT);
		thread_block(THREAD_CONTINUE_NULL);

		vm_map_range_sh_unlock(ctx, &map);
		printf("vm_map_dbg: unlocked sh\n");
		break;
	default:
		printf("vm_map_dbg: Unknown call-type %x\n", flags);
		return KERN_INVALID_ARGUMENT;
	}

	/* Clean up vm_stackshot_test_blocker_tid if this thread was the blocker */
	if (os_atomic_load(&vm_stackshot_test_blocker_tid, relaxed) == current_tid) {
		os_atomic_store(&vm_stackshot_test_blocker_tid, 0, relaxed);
	}

	return KERN_SUCCESS;
}
#endif /* DEBUG || DEVELOPMENT */

/*
 *	vm_map_init:
 *
 *	Initialize the vm_map module.  Must be called before
 *	any other vm_map routines.
 *
 *	Map and entry structures are allocated from zones -- we must
 *	initialize those zones.
 *
 *	There are three zones of interest:
 *
 *	vm_map_zone:		used to allocate maps.
 *	vm_map_entry_zone:	used to allocate map entries.
 *
 *	LP32:
 *	vm_map_entry_reserved_zone:     fallback zone for kernel map entries
 *
 *	The kernel allocates map entries from a special zone that is initially
 *	"crammed" with memory.  It would be difficult (perhaps impossible) for
 *	the kernel to allocate more memory to a entry zone when it became
 *	empty since the very act of allocating memory implies the creation
 *	of a new entry.
 */
__startup_func
void
vm_map_init(void)
{
	uint16_t cpus = (uint16_t)(ml_early_cpu_max_number() + 1);

#if MACH_ASSERT
	PE_parse_boot_argn("debug4k_filter", &debug4k_filter,
	    sizeof(debug4k_filter));
#endif /* MACH_ASSERT */

	zone_create_ext(VM_MAP_ZONE_NAME, sizeof(struct _vm_map),
	    VM_MAP_ZFLAGS, ZONE_ID_VM_MAP, NULL);

	/*
	 * Don't quarantine because we always need elements available
	 * Disallow GC on this zone... to aid the GC.
	 */
	zone_create_ext(VM_MAP_ENTRY_ZONE_NAME, sizeof(struct vm_map_entry),
	    VM_MAP_ZFLAGS, ZONE_ID_VM_MAP_ENTRY, ^(zone_t z) {
		z->z_elems_rsv = 32 * cpus;
	});

	zone_create_ext(VM_MAP_NODES_ZONE_NAME, sizeof(struct vm_map_store_node),
	    VM_MAP_ZFLAGS, ZONE_ID_VM_MAP_NODES, ^(zone_t z) {
		z->z_elems_rsv = 8 * cpus;
	});

	zone_create_ext("VM map copies", sizeof(struct vm_map_copy),
	    VM_MAP_ZFLAGS, ZONE_ID_VM_MAP_COPY, NULL);

	zone_create_ext("VM guard object chunks", sizeof(struct vm_guard_object_chunk),
	    VM_MAP_ZFLAGS, ZONE_ID_VM_GO_CHUNKS, NULL);

	/*
	 * Add the stolen memory to zones, adjust zone size and stolen counts.
	 */
	zone_cram_early(vm_map_zone, map_stolen_data, map_data_size);
	map_stolen_data += map_data_size;

	zone_cram_early(vm_map_entry_zone, map_stolen_data, kentry_data_size);
	map_stolen_data += kentry_data_size;

	zone_cram_early(vm_map_nodes_zone, map_stolen_data, map_nodes_data_size);
	map_stolen_data += map_nodes_data_size;

	printf("VM bootstrap: %d maps, %d entries and %d nodes available\n",
	    zone_count_free(vm_map_zone),
	    zone_count_free(vm_map_entry_zone),
	    zone_count_free(vm_map_nodes_zone));

	/*
	 * Since these are covered by zones, remove them from stolen page accounting.
	 */
	VM_PAGE_MOVE_STOLEN(atop_64(map_data_size) +
	    atop_64(kentry_data_size) +
	    atop_64(map_nodes_data_size));

#if VM_MAP_DEBUG_APPLE_PROTECT
	PE_parse_boot_argn("vm_map_debug_apple_protect",
	    &vm_map_debug_apple_protect,
	    sizeof(vm_map_debug_apple_protect));
#endif /* VM_MAP_DEBUG_APPLE_PROTECT */
#if VM_MAP_DEBUG_APPLE_FOURK
	PE_parse_boot_argn("vm_map_debug_fourk",
	    &vm_map_debug_fourk,
	    sizeof(vm_map_debug_fourk));
#endif /* VM_MAP_DEBUG_FOURK */
#if MACH_ASSERT
	vm_debug_parse_boot_args();
#endif /* MACH_ASSERT */

	if (malloc_no_cow) {
		vm_memory_malloc_no_cow_mask = 0ULL;
		vm_memory_malloc_no_cow_mask |= 1ULL << VM_MEMORY_MALLOC;
		vm_memory_malloc_no_cow_mask |= 1ULL << VM_MEMORY_MALLOC_SMALL;
		vm_memory_malloc_no_cow_mask |= 1ULL << VM_MEMORY_MALLOC_MEDIUM;
#if XNU_TARGET_OS_OSX
		/*
		 * On macOS, keep copy-on-write for MALLOC_LARGE because
		 * realloc() may use vm_copy() to transfer the old contents
		 * to the new location.
		 */
#else /* XNU_TARGET_OS_OSX */
		vm_memory_malloc_no_cow_mask |= 1ULL << VM_MEMORY_MALLOC_LARGE;
		vm_memory_malloc_no_cow_mask |= 1ULL << VM_MEMORY_MALLOC_LARGE_REUSABLE;
		vm_memory_malloc_no_cow_mask |= 1ULL << VM_MEMORY_MALLOC_LARGE_REUSED;
#endif /* XNU_TARGET_OS_OSX */
//		vm_memory_malloc_no_cow_mask |= 1ULL << VM_MEMORY_MALLOC_HUGE;
//		vm_memory_malloc_no_cow_mask |= 1ULL << VM_MEMORY_REALLOC;
		vm_memory_malloc_no_cow_mask |= 1ULL << VM_MEMORY_MALLOC_TINY;
		vm_memory_malloc_no_cow_mask |= 1ULL << VM_MEMORY_MALLOC_NANO;
//		vm_memory_malloc_no_cow_mask |= 1ULL << VM_MEMORY_TCMALLOC;
		PE_parse_boot_argn("vm_memory_malloc_no_cow_mask",
		    &vm_memory_malloc_no_cow_mask,
		    sizeof(vm_memory_malloc_no_cow_mask));
	}

#if CONFIG_MAP_RANGES
	vm_map_range_map_init();
#endif /* CONFIG_MAP_RANGES */

#if DEVELOPMENT || DEBUG
	PE_parse_boot_argn("panic_on_unsigned_execute",
	    &panic_on_unsigned_execute,
	    sizeof(panic_on_unsigned_execute));
	PE_parse_boot_argn("panic_on_mlock_failure",
	    &panic_on_mlock_failure,
	    sizeof(panic_on_mlock_failure));
#endif /* DEVELOPMENT || DEBUG */
}

__startup_func
static void
vm_map_steal_memory(void)
{
#if HAS_MTE
	/*
	 * Initialize the mteinfo structure here, because mteinfo steals memory
	 * which shouldn't be in the vm page array.
	 */
	if (mte_enabled()) {
		mteinfo_init(mte_tag_storage_count);
	}
#endif /* HAS_MTE */

	/*
	 * We need to reserve enough memory to support boostraping VM maps
	 * and the zone subsystem.
	 *
	 * The VM Maps that need to function before zones can support them
	 * are the ones registered with vm_map_will_allocate_early_map(),
	 * which are:
	 * - the kernel map
	 * - the various submaps used by zones (meta, ...)
	 *
	 * We also need enough entries and nodes to support them
	 * until zone_metadata_init() is called, which is when
	 * the zone allocator becomes capable of expanding dynamically.
	 *
	 * We need:
	 * - VM_MAP_EARLY_COUNT_MAX worth of VM Maps.
	 * - To allow for 3-4 entries per map, but the kernel map
	 *   needs a multiple of VM_MAP_EARLY_COUNT_MAX entries
	 *   to describe the submaps, so double it (and make it 8x too)
	 */
	map_data_size = zone_get_early_alloc_size(VM_MAP_ZONE_NAME,
	    sizeof(struct _vm_map), VM_MAP_ZFLAGS,
	    VM_MAP_EARLY_COUNT_MAX);

	kentry_data_size = zone_get_early_alloc_size(VM_MAP_ENTRY_ZONE_NAME,
	    sizeof(struct vm_map_entry), VM_MAP_ZFLAGS,
	    8 * VM_MAP_EARLY_COUNT_MAX);

	map_nodes_data_size = zone_get_early_alloc_size(VM_MAP_NODES_ZONE_NAME,
	    sizeof(struct vm_map_store_node), VM_MAP_ZFLAGS,
	    VM_MAP_EARLY_COUNT_MAX);

	/*
	 * Note: vm_map_entry -copies- don't need early memory because none
	 * are created at this stage. However, later on they will join
	 * the above zones in the VM submap, as they will be packed and unpacked
	 * in the same way entries will, so having them in addresses that
	 * are close to one another is valuable for that cause.
	 */

	/*
	 * Steal a contiguous range of memory so that a simple range check
	 * can validate early addresses being freed/crammed to these
	 * zones
	 */
	map_stolen_data = zone_early_mem_init(map_data_size + kentry_data_size +
	    map_nodes_data_size);
}
STARTUP(PMAP_STEAL, STARTUP_RANK_FIRST, vm_map_steal_memory);

__startup_func
static void
vm_kernel_boostraped(void)
{
	zone_enable_caching(&zone_array[ZONE_ID_VM_MAP_ENTRY]);
	zone_enable_caching(&zone_array[ZONE_ID_VM_MAP_NODES]);
	zone_enable_caching(&zone_array[ZONE_ID_VM_MAP_COPY]);
	zone_enable_caching(&zone_array[ZONE_ID_VM_GO_CHUNKS]);

	printf("VM bootstrap done: %d maps, %d entries and %d nodes left\n",
	    zone_count_free(vm_map_zone),
	    zone_count_free(vm_map_entry_zone),
	    zone_count_free(vm_map_nodes_zone));
}
STARTUP(ZALLOC, STARTUP_RANK_SECOND, vm_kernel_boostraped);

#if __x86_64__
void
vm_map_disable_hole_optimization(vm_map_t map)
{
	/* this function is exported to kexts on Intel */
	(void)map;
}
#endif /* __x86_64__ */

boolean_t
vm_kernel_map_is_kernel(vm_map_t map)
{
	return map->pmap == kernel_pmap;
}

__unused /* pending non-assert uses */
static bool
vm_map_is_transparent_submap(vm_map_t map)
{
	/* Transparent submap has kernel's pmap but is not the kernel map itself. */
	return map != kernel_map && vm_kernel_map_is_kernel(map);
}

/*
 *	vm_map_create:
 *
 *	Creates and returns a new empty VM map with
 *	the given physical map structure, and having
 *	the given lower and upper address bounds.
 */

extern vm_map_t vm_map_create_external(
	pmap_t                  pmap,
	vm_map_offset_t         min_off,
	vm_map_offset_t         max_off,
	boolean_t               pageable);

vm_map_t
vm_map_create_external(
	pmap_t                  pmap,
	vm_map_offset_t         min,
	vm_map_offset_t         max,
	__unused boolean_t      pageable)
{
	return vm_map_create_options(pmap, min, max, VM_MAP_CREATE_DEFAULT);
}

__startup_func
void
vm_map_will_allocate_early_map(vm_map_t *owner)
{
	if (early_map_count >= VM_MAP_EARLY_COUNT_MAX) {
		panic("VM_MAP_EARLY_COUNT_MAX is too low");
	}

	early_map_owners[early_map_count++] = owner;
}

__startup_func
void
vm_map_relocate_early_maps(vm_offset_t delta)
{
	for (uint32_t i = 0; i < early_map_count; i++) {
		vm_address_t addr = (vm_address_t)*early_map_owners[i];

		*early_map_owners[i] = (vm_map_t)(addr + delta);
	}

	early_map_count = ~0u;
}

/*
 *	Routine:	vm_map_relocate_early_elem
 *
 *	Purpose:
 *		Early zone elements are allocated in a temporary part
 *		of the address space.
 *
 *		Once the zones live in their final place, the early
 *		VM maps, map entries and map holes need to be relocated.
 *
 *		It involves rewriting any vm_map_t, vm_map_entry_t or
 *		pointers to vm_map_links. Other pointers to other types
 *		are fine.
 *
 *		Fortunately, pointers to those types are self-contained
 *		in those zones, _except_ for pointers to VM maps,
 *		which are tracked during early boot and fixed with
 *		vm_map_relocate_early_maps().
 */
__startup_func
void
vm_map_relocate_early_elem(
	uint32_t                zone_id,
	vm_offset_t             new_addr,
	vm_offset_t             delta)
{
#define relocate(type_t, field)  ({ \
	typeof(((type_t)NULL)->field) *__field = &((type_t)new_addr)->field;    \
	if (*__field) {                                                         \
	        *__field = (typeof(*__field))((vm_offset_t)*__field + delta);   \
	}                                                                       \
})

#define relocate_vmn(type_t, field, shift)  ({ \
	vm_map_store_node_ptr_t *__ptr = &((type_t)new_addr)->field;            \
                                                                                \
	if (__ptr->vmsp_packed) {                                               \
	        __ptr->vmsp_packed += delta >> (shift);                         \
	}                                                                       \
})

#define relocate_vmv(type_t, field, shift)  ({ \
	vm_map_store_val_ptr_t *__ptr = &((type_t)new_addr)->field;             \
                                                                                \
	if (__ptr->vmsp_packed) {                                               \
	        __ptr->vmsp_packed += delta >> (shift);                         \
	}                                                                       \
})

	switch (zone_id) {
	case ZONE_ID_VM_MAP:
		relocate(vm_map_t, hdr.links.next);
		relocate(vm_map_t, hdr.links.prev);
		((vm_map_t)new_addr)->pmap = kernel_pmap;
		relocate_vmn(vm_map_t, root.vmsr_root, VMN_PACKED_PTR_SHIFT);
		relocate(vm_map_t, root.vmsr_hint);
		relocate(vm_map_t, vmmap_corpse_footprint);
		return;

	case ZONE_ID_VM_MAP_NODES:
		relocate_vmn(vm_map_store_node_t, vmsn_next_sibling,
		    VMN_PACKED_PTR_SHIFT);
		if (((vm_map_store_node_t)new_addr)->vmsn_leaf) {
			for (int i = 0; i < VMS_LEAF_FANOUT; i++) {
				relocate_vmv(vm_map_store_node_t, vmsl_ptrs[i],
				    VME_PACKED_PTR_SHIFT);
			}
		} else {
			for (int i = 0; i < VMS_NODE_FANOUT; i++) {
				relocate_vmn(vm_map_store_node_t, vmsn_ptrs[i],
				    VMN_PACKED_PTR_SHIFT);
			}
		}
		return;

	case ZONE_ID_VM_MAP_ENTRY:
		relocate(vm_map_entry_t, links.next);
		relocate(vm_map_entry_t, links.prev);
		if (((vm_map_entry_t)new_addr)->is_sub_map) {
			/* no object to relocate because we haven't made any */
			((vm_map_entry_t)new_addr)->vme_submap +=
			    delta >> VME_SUBMAP_SHIFT;
		}
#if MAP_ENTRY_CREATION_DEBUG
//		relocate(vm_map_entry_t, vme_creation_maphdr);
#endif /* MAP_ENTRY_CREATION_DEBUG */
		return;

	default:
		panic("Unexpected zone ID %d", zone_id);
	}
#undef relocate_vmv
#undef relocate_vmn
#undef relocate
}

/*
 * Generate a serial ID to identify a newly allocated vm_map
 */
static uintptr_t vm_map_serial_current = 0;
vm_map_serial_t vm_map_serial_generate(void);
void vm_map_assign_serial(vm_map_t, vm_map_serial_t);

vm_map_serial_t
vm_map_serial_generate(void)
{
	vm_map_serial_t serial = (void *)os_atomic_inc(&vm_map_serial_current, relaxed);
	return serial;
}

void
vm_map_assign_serial(vm_map_t map, vm_map_serial_t serial)
{
	map->serial_id = serial;
#if CONFIG_SPTM
	/* Copy through our ID to the pmap (only available on SPTM systems) */
	if (map->pmap) {
		map->pmap->associated_vm_map_serial_id = map->serial_id;
	}
#endif /* CONFIG_SPTM */
}

static inline void
vm_map_lock_init(vm_map_t map)
{
	lck_rw_init(&map->ilock, &vm_map_lck_grp, LCK_ATTR_NULL);
	map->unlink_timestamp = 0;
}

vm_map_t
vm_map_create_with_page_shift(
	pmap_t                  pmap,
	vm_map_offset_t         min,
	vm_map_offset_t         max,
	int                     pageshift,
	vm_map_create_options_t options)
{
	vm_map_t result;

#if DEBUG || DEVELOPMENT
	if (__improbable(startup_phase < STARTUP_SUB_ZALLOC)) {
		if (early_map_count != ~0u && early_map_count !=
		    zone_count_allocated(vm_map_zone) + 1) {
			panic("allocating %dth early map, owner not known",
			    zone_count_allocated(vm_map_zone) + 1);
		}
		if (early_map_count != ~0u && pmap && pmap != kernel_pmap) {
			panic("allocating %dth early map for non kernel pmap",
			    early_map_count);
		}
	}
#endif /* DEBUG || DEVELOPMENT */

	result = zalloc_id(ZONE_ID_VM_MAP, Z_WAITOK | Z_NOFAIL | Z_ZERO);

	vm_map_store_init(result, pageshift);

	result->size_limit      = RLIM_INFINITY;        /* default unlimited */
	result->data_limit      = RLIM_INFINITY;        /* default unlimited */
	result->user_wire_limit = MACH_VM_MAX_ADDRESS;  /* default limit is unlimited */
	os_ref_init_count_raw(&result->map_refcnt, &map_refgrp, 1);

	result->pmap = pmap;

	/*
	 * Immediately give ourselves an ID
	 * Unless this map is being created as part of a fork, in which case
	 * the caller will reassign the ID of the parent (so don't waste an
	 *  increment here).
	 * Reusing parent IDs on fork enacts our policy that fork() pairs share
	 *  a domain and can freely alias tagged MTE mappings between themselves.
	 */
	if ((options & VM_MAP_CREATE_VIA_FORK) == 0) {
		vm_map_assign_serial(result, vm_map_serial_generate());
	}

	result->min_offset = vm_map_round_page(min, VM_MAP_PAGE_MASK(result));
	result->max_offset = vm_map_trunc_page(max, VM_MAP_PAGE_MASK(result));

	if (options & VM_MAP_CREATE_NEVER_FAULTS) {
		assert(pmap == kernel_pmap);
		result->never_faults = true;
	}

	if (options & VM_MAP_CREATE_CORPSE_FOOTPRINT) {
		result->has_corpse_footprint = true;
	}

	/* Set without the interlock, but no one else has the map yet */
	result->lock_contention_debug = vm_lock_contention_debug;
	vm_map_lock_init(result);

	return result;
}

vm_map_t
vm_map_create_options(
	pmap_t                  pmap,
	vm_map_offset_t         min,
	vm_map_offset_t         max,
	vm_map_create_options_t options)
{
	return vm_map_create_with_page_shift(pmap, min, max, PAGE_SHIFT, options);
}

/*
 * Adjusts a submap that was made by kmem_suballoc()
 * before it knew where it would be mapped,
 * so that it has the right min/max offsets.
 *
 * We do not need to hold any locks:
 * only the caller knows about this map,
 * and it is not published on any entry yet.
 */
static void
vm_map_adjust_offsets(
	vm_map_t                map,
	vm_map_offset_t         min_off,
	vm_map_offset_t         max_off)
{
	assert(map->min_offset == 0);
	assert(map->max_offset == max_off - min_off);
	assert(map->hdr.nentries == 0);
	assert(os_ref_get_count_raw(&map->map_refcnt) == 2);

	map->min_offset = min_off;
	map->max_offset = max_off;
}


vm_map_size_t
vm_map_adjusted_size(vm_map_t map)
{
	const struct vm_reserved_region *regions = NULL;
	size_t num_regions = 0;
	mach_vm_size_t  reserved_size = 0, map_size = 0;

	if (map == NULL || (map->size == 0)) {
		return 0;
	}

	map_size = map->size;

	if (map->reserved_regions == FALSE || !vm_map_is_exotic(map) || map->terminated) {
		/*
		 * No special reserved regions or not an exotic map or the task
		 * is terminating and these special regions might have already
		 * been deallocated.
		 */
		return map_size;
	}

	num_regions = ml_get_vm_reserved_regions(vm_map_is_64bit(map), &regions);
	assert((num_regions == 0) || (num_regions > 0 && regions != NULL));

	while (num_regions) {
		reserved_size += regions[--num_regions].vmrr_size;
	}

	/*
	 * There are a few places where the map is being switched out due to
	 * 'termination' without that bit being set (e.g. exec and corpse purging).
	 * In those cases, we could have the map's regions being deallocated on
	 * a core while some accounting process is trying to get the map's size.
	 * So this assert can't be enabled till all those places are uniform in
	 * their use of the 'map->terminated' bit.
	 *
	 * assert(map_size >= reserved_size);
	 */

	return (map_size >= reserved_size) ? (map_size - reserved_size) : map_size;
}

#if DEVELOPMENT || DEBUG
/*
 * @function vm_map_delete_transparent_submap_entries
 *
 * @abstract Deal with test transparent submaps in destroy.
 *
 * @discussion
 * Since real-world uses of transparent submaps are limited to the kernel
 * map, we would not expect to have to deal with them in
 * vm_map_destroy_options which should only ever be called on user maps.
 * However, various tests do create temporary maps with nested transparent
 * submaps, and they need to destroy those maps to avoid leaking memory.
 * This is challenging because:
 *     1. Deleting entries in the transparent submap from the parent map is
 *        not allowed.
 *     2. The range lock used by delete will never return the parent map
 *        entry.
 * So we expose an option that can be used to trigger this custom path that
 * deletes everything by hand.
 */
static void
vm_map_delete_transparent_submap_entries(vm_map_t map)
{
	vm_map_entry_t entry;
	vm_map_entry_t next_entry;

	for (entry = vm_map_first_entry(map); entry != vm_map_to_entry(map); entry = next_entry) {
		next_entry = entry->vme_next;
		if (!(entry->is_sub_map && entry->vme_permanent && entry->vme_atomic)) {
			/* Only work on transparent submap entries. */
			continue;
		}
		kern_return_t kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE,
		    entry, entry->vme_start, THREAD_UNINT);
		assert3u(kr, ==, KERN_SUCCESS);
		/*
		 * Freeing the entry destroys the submap,
		 * which deletes the entries in the submap.
		 */
		vm_map_store_remove(map, entry,
		    VMS_REMOVE_FREE_ENTRY | VMS_REMOVE_FREE_SLOTS);
	}
}
#endif

static void
vm_map_unseal(vm_map_t map)
{
	vm_map_entry_t entry;

	/*
	 * "Unsealing" is generally not allowed as an operation.
	 * Sealed submaps are meant to be constant for their lifetime.
	 *
	 * However, we have to bypass assertions around sealed submaps and allow
	 * the entries to be modified when destroying a sealed submap.
	 *
	 * Therefore, we only allow this operation once the map has been
	 * terminated as a part of destroying it.
	 */
	assert(map->terminated);
	assert(vm_map_is_sealed(map));

	for (entry = vm_map_first_entry(map);
	    entry != vm_map_to_entry(map);
	    entry = entry->vme_next) {
		vm_entry_assert_lock_is_invalid(entry,
		    VMEL_INVALID_REASON_SEALED_SUBMAP);
		vm_entry_lock_init_locked_exclusive(map, entry);
		vm_entry_unlock_exclusive(map, entry);
	}
	map->vmmap_sealed = VM_MAP_NOT_SEALED;
}

/*
 *	vm_map_destroy_options:
 *
 *	Actually destroy a map.
 */
void
vm_map_destroy_options(vm_map_t map, vm_map_destroy_options_t options __unused)
{
	__assert_only kern_return_t kr;
	VM_MAP_ZAP_DECLARE(zap);

	vmlp_api_start(VM_MAP_DESTROY);
	vmlp_range_event_all(map);
	vm_map_ilk_lock_allow_sealed(map);

	map->terminated = true;
	if (vm_map_is_sealed(map)) {
		vm_map_unseal(map);
	} else if (vm_map_will_be_sealed(map)) {
		/*
		 * It's possible, for example, for a process to be Jetsammed
		 * while still in the process of setting up its shared region.
		 * In this case, we may drop the last ref to the shared region
		 * map and destroy it.
		 */
		map->vmmap_sealed = VM_MAP_NOT_SEALED;
	}
	vm_map_corpse_footprint_destroy(map);

#if DEVELOPMENT || DEBUG
	if (__improbable(options & VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP)) {
		vm_map_delete_transparent_submap_entries(map);
	}
#endif /* DEVELOPMENT || DEBUG */

	kr = vm_map_delete_and_iunlock(map, 0x0, -VM_MAP_PAGE_SIZE(map),
	    VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE, NULL, &zap);
	assert3u(kr, ==, KERN_SUCCESS);
	assert3u(map->hdr.nentries, ==, 0);

	vm_map_zap_dispose(map, &zap);

	if (map->pmap) {
		pmap_destroy(map->pmap);
	}
	if (map->guard_object_slabs) {
		vm_map_guard_object_slab_destroy(map);
	}
	assert(map->guard_object_user == NULL);

	lck_rw_destroy(&map->ilock, &vm_map_lck_grp);

#if CONFIG_MAP_RANGES
	kfree_data(map->extra_ranges,
	    map->extra_ranges_count * sizeof(struct vm_map_user_range));
#endif

	vm_map_store_destroy(map);
	zfree_id(ZONE_ID_VM_MAP, map);
	vmlp_api_end(VM_MAP_DESTROY, 0);
}

void
vm_map_destroy(vm_map_t map)
{
	vm_map_destroy_options(map, VM_MAP_DESTROY_DEFAULT);
}

/*
 * Returns pid of the task with the largest number of VM map entries.
 * Used in the zone-map-exhaustion jetsam path.
 */
pid_t
find_largest_process_vm_map_entries(void)
{
	pid_t victim_pid = -1;
	int max_vm_map_entries = 0;
	task_t task = TASK_NULL;
	queue_head_t *task_list = &tasks;

	lck_mtx_lock(&tasks_threads_lock);
	queue_iterate(task_list, task, task_t, tasks) {
		if (task == kernel_task || !task->active) {
			continue;
		}

		vm_map_t task_map = task->map;
		if (task_map != VM_MAP_NULL) {
			int task_vm_map_entries = task_map->hdr.nentries;
			if (task_vm_map_entries > max_vm_map_entries) {
				max_vm_map_entries = task_vm_map_entries;
				victim_pid = pid_from_task(task);
			}
		}
	}
	lck_mtx_unlock(&tasks_threads_lock);

	printf("zone_map_exhaustion: victim pid %d, vm region count: %d\n", victim_pid, max_vm_map_entries);
	return victim_pid;
}

static inline vm_map_address_t
vm_map_lookup_sanitize_address(vm_map_t map, vm_map_address_t address)
{
	if (not_in_kdp) {
		/* kdp_lightweight_fault also calls this with no locks */
		assert_vm_map_ilk_owned_ignore_sealed(map, LCK_RW_TYPE_ANY);
	}

#if HAS_MTE
#if DEVELOPMENT || DEBUG
	/* Addresses getting here must be canonical. The lookup won't work otherwise. */
	if (address != 0 && map != NULL && vm_memtag_canonicalize(map, address) != address) {
		mte_report_non_canonical_address((caddr_t)address, map, __func__);
	}
#endif /* DEVELOPMENT || DEBUG */
#endif /* HAS_MTE */

	return address;
}

__attribute__((noinline, flatten))
vm_map_entry_t
vm_map_lookup(vm_map_t map, vm_map_address_t address)
{
	address = vm_map_lookup_sanitize_address(map, address);
	return vm_map_store_lookup_entry(map, address, false);
}

/*
 *	vm_map_lookup_or_next:	[ internal use only ]
 *
 *	Calls into the vm map store layer to find the map
 *	entry containing (or immediately following) the
 *	specified address in the given map; the entry is returned
 *	in the "entry_p" parameter.  The boolean
 *	result indicates whether the address is
 *	actually contained in the entry.
 */
__attribute__((noinline, flatten))
bool
vm_map_lookup_or_next(vm_map_t map, vm_map_offset_t address, vm_map_entry_t *entry_p)
{
	vm_map_entry_t entry;

	address = vm_map_lookup_sanitize_address(map, address);
	*entry_p = entry = vm_map_store_lookup_entry(map, address, true);
	return entry != vm_map_to_entry(map) && entry->vme_start <= address;
}


/*
 *	Routine:	vm_map_get_range
 *	Purpose:
 *			Adjust bounds based on security policy.
 */
static struct mach_vm_range
vm_map_get_range(
	vm_map_t                map,
	vm_map_kernel_flags_t  *vmk_flags,
	vm_guard_object_slab_t *slab)
{
	struct mach_vm_range range = {};

	if (map == kernel_map) {
		if (vmk_flags->vmf_guard_object_optout) {
			*slab = NULL;
		} else {
			*slab = kmem_slab(*vmk_flags);
		}
		return *kmem_range(vmk_flags->vmkf_range_id);
	}

	/*
	 * If minimum is 0, bump it up by PAGE_SIZE.  We want to limit
	 * allocations of PAGEZERO to explicit requests since its
	 * normal use is to catch dereferences of NULL and many
	 * applications also treat pointers with a value of 0 as
	 * special and suddenly having address 0 contain useable
	 * memory would tend to confuse those applications.
	 */
	if (vmk_flags->vmf_guard_object_optout || map->terminated) {
		*slab = NULL;
	} else {
		*slab = map->guard_object_slabs;
	}
	range.min_address = MAX(map->min_offset, VM_MAP_PAGE_SIZE(map));
	range.max_address = map->max_offset;

#if CONFIG_MAP_RANGES
	if (map->uses_user_ranges && !map->disable_vmentry_reuse) {
		switch (vmk_flags->vmkf_range_id) {
		case UMEM_RANGE_ID_DEFAULT:
			if (*slab == NULL) {
				range = map->default_range;
			} else {
				/* allocate from left */
				vmk_flags->vmkf_last_free = true;
			}
			break;
		case UMEM_RANGE_ID_LARGE_FILE:
			if (mach_vm_range_size(&map->large_file_range) != 0) {
				/* large file range is configured and should be used */
				range = map->large_file_range;
				*slab = NULL;
				break;
			}
			/*
			 * the user asking for this user range might not have the
			 * permissions to use the large file range (i.e., it
			 * doesn't hold the correct entitlement), so we give it
			 * the data range instead
			 */
			OS_FALLTHROUGH;
		case UMEM_RANGE_ID_HEAP:
			if (*slab) {
				/* allocate from right */
				vmk_flags->vmkf_last_free = true;
				*slab += 1;
			} else {
				range = map->data_range;
			}
			break;
		case UMEM_RANGE_ID_FIXED:
			/*
			 * anywhere allocations with an address in "FIXED"
			 * makes no sense.
			 */
			range.min_address = range.max_address = 0;
			break;

		default:
			release_assert(false && "invalid range ID");
		}
	}
#endif /* CONFIG_MAP_RANGES */
#if XNU_TARGET_OS_OSX
	if (vmk_flags->vmkf_32bit_map_va) {
		assert(map->pmap != kernel_pmap);
		range.max_address = MIN(map->max_offset, 0x00000000FFFFF000ULL);
	}
#endif /* XNU_TARGET_OS_OSX */
	return range;
}

kern_return_t
vm_map_locate_space_anywhere(
	vm_map_t                map,
	vm_map_address_t        hint,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_store_rsv_t     *rsv)
{
	struct mach_vm_range    effective_range = {};
	struct mach_vm_range    range = {};
	vm_guard_object_slab_t  slab = NULL;
	kern_return_t           kr;

	/*
	 * Holding the interlock is enough to guarantee the stability of the map
	 * throughout our search for space (unless we need to wait for space, in
	 * which case we temporarily drop the interlock and start over).
	 */
	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);

	/*
	 * Only supported by vm_map_enter() with a fixed address.
	 */
	assert(!vmk_flags.vmf_fixed);
	assert(!vmk_flags.vmkf_beyond_max);

	if (__improbable(map->wait_for_space)) {
		/*
		 * support for "wait_for_space" is minimal,
		 * its only consumer is the ipc_kernel_copy_map.
		 */
		assert(!vmk_flags.vmkf_keep_map_ilocked &&
		    !vmk_flags.vmkf_map_jit &&
		    !vmk_flags.vmf_random_addr &&
		    hint <= map->min_offset);
	} else if (vmk_flags.vmkf_last_free) {
		assert(!vmk_flags.vmkf_map_jit &&
		    !vmk_flags.vmf_random_addr);
	}

	if (vmk_flags.vmkf_map_jit) {
		if (map->jit_entry_exists &&
		    !VM_MAP_POLICY_ALLOW_MULTIPLE_JIT(map)) {
			return KERN_INVALID_ARGUMENT;
		}
		if (VM_MAP_POLICY_ALLOW_JIT_RANDOM_ADDRESS(map)) {
			vmk_flags.vmf_random_addr = true;
		}
	}

	if (__improbable(!vm_map_is_map_size_valid(
		    map, size, vmk_flags.vmkf_no_soft_limit))) {
		return KERN_NO_SPACE;
	}

	/*
	 * Validate range_id from flags and get associated range
	 */
	effective_range = vm_map_get_range(map, &vmk_flags, &slab);

	if (slab) {
		/* hint is ignored when guard objects are used */
		kr = vm_guard_object_find_space_anywhere(map, slab,
		    effective_range, vmk_flags, size, mask, rsv);
		if (kr != KERN_NOT_SUPPORTED) {
			return kr;
		}
		slab = NULL;
		if (vmk_flags.vmkf_last_free) {
			hint = effective_range.max_address;
		} else {
			hint = effective_range.min_address;
		}
	}

again:
	if (vmk_flags.vmkf_last_free) {
		range.min_address = effective_range.min_address;
		range.max_address = hint;
	} else {
		range.min_address = hint;
		range.max_address = effective_range.max_address;
#if __x86_64__
		if ((range.min_address == 0 || range.min_address == vm_map_min(map)) &&
		    !map->disable_vmentry_reuse &&
		    map->vmmap_high_start != 0) {
			range.min_address = map->vmmap_high_start;
		}
#endif /* __x86_64__ */
	}
	range.min_address = MAX(range.min_address, effective_range.min_address);
	if (range.max_address == 0 || range.max_address > effective_range.max_address) {
		range.max_address = effective_range.max_address;
	}
	if (range.max_address <= range.min_address ||
	    mach_vm_range_size(&range) < size) {
		return KERN_NO_SPACE;
	}

	kr = vm_map_store_find_space(map, range, vmk_flags, size, mask, rsv);

	if (__improbable(kr == KERN_NO_SPACE && map->wait_for_space)) {
		/*
		 * Wait for vm_map_delete_and_iunlock to
		 * thread_wakeup the map.
		 */
		vm_map_ilk_sleep(map, (event_t)map, THREAD_ABORTSAFE);
		goto again;
	}

	return kr;
}

/*!
 * @function vm_map_locate_space_fixed()
 *
 * @brief
 * Locate (no reservation) a range in the specified VM map at a fixed address.
 *
 * @param map           the map to scan for memory. interlock must be held.
 * @param start         the fixed address trying to be reserved
 * @param size          the size of the allocation to make.
 * @param mask          an alignment mask the allocation must respect,
 * @param vmk_flags     the vm map kernel flags to influence this call.
 *                      vmk_flags.vmf_anywhere must not be set.
 * @param rsv           the reservation made by this call.
 * @param zap_list      a zap list of entries to clean up after the call.
 *
 * @returns
 * - KERN_SUCCESS in case of success and no conflicting entry is found,
 *   in which case entry_out is set to the entry before the hole.
 *
 * - KERN_INVALID_ADDRESS if the specified @c start or @c size
 *   would result in a mapping outside of the map.
 *
 * - KERN_NO_SPACE for various cases of unrecoverable failures.
 *
 * @note
 * This function may sleep and temporarily release the interlock, but it always
 * returns with it held.
 */
static kern_return_t
vm_map_locate_space_fixed(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_store_rsv_t     *rsv,
	vm_map_zap_t            zap_list)
{
	vm_map_offset_t effective_min_offset, effective_max_offset;
	vm_map_offset_t end;

	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);
	assert(vmk_flags.vmf_fixed);

	effective_min_offset = map->min_offset;
	effective_max_offset = map->max_offset;

	if (vmk_flags.vmkf_beyond_max) {
		/*
		 * Allow an insertion beyond the map's max offset.
		 */
		effective_max_offset = 0x00000000FFFFF000ULL;
		if (vm_map_is_64bit(map)) {
			effective_max_offset = 0xFFFFFFFFFFFFF000ULL;
		}
#if XNU_TARGET_OS_OSX
	} else if (__improbable(vmk_flags.vmkf_32bit_map_va)) {
		effective_max_offset = MIN(map->max_offset, 0x00000000FFFFF000ULL);
#endif /* XNU_TARGET_OS_OSX */
	}

	if (VM_MAP_PAGE_SHIFT(map) < PAGE_SHIFT &&
	    !vmk_flags.vmf_overwrite &&
	    map->pmap == kernel_pmap &&
	    vmk_flags.vm_tag == VM_MEMORY_REALLOC) {
		/*
		 * Force realloc() to switch to a new allocation,
		 * to prevent 4k-fragmented virtual ranges.
		 */
//		DEBUG4K_ERROR("no realloc in place");
		return KERN_NO_SPACE;
	}

	/*
	 *	Verify that:
	 *		the address doesn't itself violate
	 *		the mask requirement.
	 */

	if ((start & mask) != 0) {
		return KERN_NO_SPACE;
	}

	if (__improbable(!vm_map_is_map_size_valid(
		    map, size, vmk_flags.vmkf_no_soft_limit))) {
		return KERN_NO_SPACE;
	}

#if CONFIG_MAP_RANGES
	if (map->uses_user_ranges && !map->disable_vmentry_reuse) {
		struct mach_vm_range r;

		vm_map_user_range_resolve(map, start, 1, &r);
		if (r.max_address == 0) {
			return KERN_INVALID_ADDRESS;
		}
		effective_min_offset = r.min_address;
		effective_max_offset = r.max_address;
	}
#endif /* CONFIG_MAP_RANGES */

	if ((startup_phase >= STARTUP_SUB_ZALLOC) && !vmk_flags.vmkf_submap &&
	    (map == kernel_map)) {
		mach_vm_range_t r = kmem_validate_range_for_overwrite(start, size);
		effective_min_offset = r->min_address;
		effective_max_offset = r->max_address;
	}

	/*
	 *	...	the address is within bounds
	 */

	end = start + size;

	if ((start < effective_min_offset) ||
	    (end > effective_max_offset) ||
	    (start >= end)) {
		return KERN_INVALID_ADDRESS;
	}

	if (vmk_flags.vmf_overwrite) {
		vmr_flags_t remove_flags = VM_MAP_REMOVE_TO_OVERWRITE;
		vm_map_entry_t sentinel = VM_MAP_ENTRY_NULL;
		kern_return_t remove_kr;

		/*
		 * Fixed mapping and "overwrite" flag: attempt to
		 * remove all existing mappings in the specified
		 * address range, saving them in our "zap_list".
		 */

		if (vmk_flags.vmkf_overwrite_immutable) {
			/* we can overwrite immutable mappings */
			remove_flags |= VM_MAP_REMOVE_IMMUTABLE;
		}
		if (vmk_flags.vmkf_remap_prot_copy) {
			remove_flags |= VM_MAP_REMOVE_IMMUTABLE_CODE;
		}
		remove_kr = vm_map_delete_and_iunlock(map, start, end,
		    remove_flags, KMEM_GUARD_NONE, &sentinel, zap_list);
		vm_map_ilk_lock(map);

		/*
		 * vm_map_delete_and_iunlock(OVERWRITE) is atomic:
		 * it either succeeds, or fails and removes nothing.
		 */
		if (remove_kr == KERN_SUCCESS) {
			assert(VM_MAP_ENTRY_NULL != sentinel);
			vm_map_store_remove(map, sentinel,
			    VMS_REMOVE_FREE_ENTRY);
			goto out_success;
		}

		assert(sentinel == VM_MAP_ENTRY_NULL);
		assert(zap_list->vmz_head == VM_MAP_ENTRY_NULL);
		return remove_kr;
	}

	if (vm_map_store_lookup_hole(map, start, effective_max_offset) < end - start) {
		return KERN_NO_SPACE;
	}

out_success:
	{
		vm_map_entry_t e;

		vm_map_lookup_or_next(map, start, &e);
		*rsv = vmsr_make(start, e);
	}
	return KERN_SUCCESS;
}

static boolean_t
vm_memory_malloc_no_cow(
	int alias)
{
	uint64_t alias_mask;

	if (!malloc_no_cow) {
		return FALSE;
	}
	if (alias > 63) {
		return FALSE;
	}
	alias_mask = 1ULL << alias;
	if (alias_mask & vm_memory_malloc_no_cow_mask) {
		return TRUE;
	}
	return FALSE;
}

__static_testable __mockable kern_return_t
vm_superpage_size(unsigned int superpage_size, __unused vm_map_size_t *size)
{
	switch (superpage_size) {
		/*
		 * Note that the current implementation only supports
		 * a single size for superpages, SUPERPAGE_SIZE, per
		 * architecture. As soon as more sizes are supposed
		 * to be supported, SUPERPAGE_SIZE has to be replaced
		 * with a lookup of the size depending on superpage_size.
		 */
#if x86_64
	case SUPERPAGE_SIZE_ANY:
		/* handle it like 2 MB and round up to page size */
		*size = (*size + 2 * 1024 * 1024 - 1) & ~(2 * 1024 * 1024 - 1);
		OS_FALLTHROUGH;
	case SUPERPAGE_SIZE_2MB:
		break;
#endif
	default:
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

#if CONFIG_LARGE_SIZE_TELEMETRY
/*
 * Threshold (bytes) at which to send guard objects telemetry.
 */
TUNABLE(vm_map_size_t, gobj_telemetry_threshold, "gobj_telemetry_threshold", (1 << 30));
#define GUARD_OBJECTS_TELEMETRY_DISABLED ((vm_map_size_t) -1)
#define GUARD_OBJECTS_TELEMETRY_NOT_SENT (0)

#if DEVELOPMENT || DEBUG
TUNABLE(bool, gobj_do_simulated_crashes, "gobj_do_simulated_crashes", true);
#endif /* DEVELOPMENT || DEBUG */

CA_EVENT(guard_objects_deny_allocation,
    CA_STATIC_STRING(CA_PROCNAME_LEN), proc_name,
    CA_INT, size);

void
vm_map_enter_large_telemetry_ast(void)
{
	vm_map_size_t size = os_atomic_load(&current_task()->large_allocation_size, relaxed);

	ca_event_t ca_event = CA_EVENT_ALLOCATE(guard_objects_deny_allocation);
	CA_EVENT_TYPE(guard_objects_deny_allocation) * event = ca_event->data;
	strlcpy(event->proc_name, proc_name_address(current_proc()), CA_PROCNAME_LEN);
	event->size = size;
	CA_EVENT_SEND(ca_event);

#if DEVELOPMENT || DEBUG
	if (!gobj_do_simulated_crashes) {
		return;
	}

	mach_exception_code_t    code    = 0;
	mach_exception_subcode_t subcode = size;

	EXC_GUARD_ENCODE_TYPE(code, GUARD_TYPE_VIRT_MEMORY);
	EXC_GUARD_ENCODE_FLAVOR(code, kGUARD_EXC_LARGE_ALLOCATION_TELEMETRY);
	EXC_GUARD_ENCODE_TARGET(code, 0);

	kern_return_t kr = task_exception_notify(EXC_GUARD, code, subcode, FALSE);
	if (kr != KERN_SUCCESS) {
		/* Simulated crash. */
		(void) task_violated_guard(code, subcode, NULL, TRUE);
	}
#endif /* DEVELOPMENT || DEBUG */
}
#endif /* CONFIG_LARGE_SIZE_TELEMETRY */

uint64_t vm_map_enter_RLIMIT_AS_count = 0;
uint64_t vm_map_enter_RLIMIT_DATA_count = 0;
/*
 *	Routine:	vm_map_enter
 *
 *	Description:
 *		Allocate a range in the specified virtual address map.
 *		The resulting range will refer to memory defined by
 *		the given memory object and offset into that object.
 *
 *		Arguments are as defined in the vm_map call.
 */
__static_testable unsigned int vm_map_enter_restore_successes = 0;
__static_testable unsigned int vm_map_enter_restore_failures = 0;
kern_return_t
vm_map_enter(
	vm_map_t                map,
	vm_map_offset_t         *address,       /* IN/OUT */
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_object_t             object,
	vm_object_offset_t      offset,
	boolean_t               needs_copy,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance)
{
	vm_map_store_rsv_t      rsv = vmsr_make(*address, VM_MAP_ENTRY_NULL);
	vm_map_entry_t          entry = VM_MAP_ENTRY_NULL;
	vm_map_offset_t         tmp_start;
	vm_map_offset_t         end, tmp_end;
	vm_map_offset_t         tmp2_start, tmp2_end;
	vm_map_offset_t         step;
	kern_return_t           result = KERN_SUCCESS;
	bool                    map_ilocked = false;
	bool                    map_lock_dropped = false;
	bool                    pmap_empty = TRUE;
	bool                    new_mapping_established = FALSE;
	const bool              keep_map_ilocked = vmk_flags.vmkf_keep_map_ilocked;
	const bool              keep_entries_locked = vmk_flags.vmkf_keep_entries_locked;
	const bool              anywhere = !vmk_flags.vmf_fixed;
	const bool              purgable = vmk_flags.vmf_purgeable;
	const bool              no_cache = vmk_flags.vmf_no_cache;
	const bool              is_submap = vmk_flags.vmkf_submap;
	const bool              permanent = vmk_flags.vmf_permanent;
	const bool              no_copy_on_read = vmk_flags.vmkf_no_copy_on_read;
	const bool              entry_for_jit = vmk_flags.vmkf_map_jit;
	const bool              iokit_acct = vmk_flags.vmkf_iokit_acct;
	const bool              resilient_codesign = vmk_flags.vmf_resilient_codesign;
	const bool              resilient_media = vmk_flags.vmf_resilient_media;
	const bool              entry_for_tpro = vmk_flags.vmf_tpro;
#if HAS_MTE
	/* This flag signifies an 'MTE-aware' code path, but doesn't necessarily indicate
	 * that we're actually attempting to insert an MTE-enabled object.
	 */
	const bool              is_caller_mte_aware = vmk_flags.vmf_mte;
	/* This flag is disjoint from the flag above, and provides a stronger guarantee:
	 * the object we've been passed actually has MTE enabled.
	 */
	bool                    is_caller_entering_mte_memory = false;

	/* If the object we're provided is MTE enabled, the code path we're on must
	 * be MTE-aware (signified by `vmk_flags.vmf_mte`).
	 * We've encountered cases where code paths perform unexpected operations on
	 * MTE-enabled objects (such as aliasing them elsewhere).
	 *
	 * If `is_submap`, we've actually been passed a vm_map_t rather than a vm_object_t,
	 * and therefore should not attempt to access the WIMG bits.
	 */
	if (is_submap) {
		if (vmk_flags.vmf_mte) {
			panic("vm_map_enter() received a request to enter MTE memory on a submap, which is unexpected");
		}
	} else if (object == VM_OBJECT_NULL) {
		/* 'Old' semantics: vmf_mte means "please enter MTE memory" */
		is_caller_entering_mte_memory = is_caller_mte_aware;
	} else if (vm_object_is_mte_mappable(object)) {
		if (!is_caller_mte_aware) {
			panic("vm_map_enter() passed an MTE-enabled object, but the caller didn't specify vmf_mte.");
		} else {
			is_caller_entering_mte_memory = true;
		}
	}
#endif /* HAS_MTE */
	const unsigned int      superpage_size = vmk_flags.vmf_superpage_size;
	const vm_tag_t          alias = vmk_flags.vm_tag;
	vm_tag_t                user_alias;
	kern_return_t           kr;
	vm_map_size_t           chunk_size = 0;
	vm_object_t             caller_object;
	VM_MAP_ZAP_DECLARE(zap_old_list);
	VM_MAP_ZAP_DECLARE(zap_new_list);

	vmlp_api_start(VM_MAP_ENTER);

	caller_object = object;

#if CONFIG_LARGE_SIZE_TELEMETRY
	/*
	 * Send telemetry on large, non-fixed user allocations from tasks with guard
	 * objects enabled that haven't already sent telemetry. In the future,
	 * allocations matching these criteria will be denied.
	 */
	if (gobj_telemetry_threshold != GUARD_OBJECTS_TELEMETRY_DISABLED &&
	    size >= gobj_telemetry_threshold &&
	    !vmk_flags.vmf_fixed &&
	    !vm_kernel_map_is_kernel(map) &&
	    task_has_guard_objects(current_task()) &&
	    !vmk_flags.vmf_guard_object_optout &&
	    (vmk_flags.vm_tag != VM_MEMORY_JAVASCRIPT_CORE) &&     /* Exceptions for WebKit's gigacage. */
	    (vmk_flags.vm_tag != VM_MEMORY_TCMALLOC) &&            /* Exceptions for WebKit's allocator. */
	    (vmk_flags.vm_tag != VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR) &&
	    os_atomic_cmpxchg(
		    &current_task()->large_allocation_size,
		    GUARD_OBJECTS_TELEMETRY_NOT_SENT,
		    size, relaxed)) {
		thread_ast_set(current_thread(), AST_LARGE_ENTER_TELEMETRY);
	}
#endif /* CONFIG_LARGE_SIZE_TELEMETRY */

	if (vmk_flags.vmf_4gb_chunk) {
#if defined(__LP64__)
		chunk_size = (4ULL * 1024 * 1024 * 1024); /* max. 4GB chunks for the new allocation */
#else /* __LP64__ */
		chunk_size = ANON_CHUNK_SIZE;
#endif /* __LP64__ */
	} else {
		chunk_size = ANON_CHUNK_SIZE;
	}


#if HAS_MTE
	if (is_caller_entering_mte_memory && inheritance == VM_INHERIT_SHARE) {
		/* we have no space allocated yet, so just report an address of 0 */
		vm_mte_operation_flags_t mte_operation = VM_MTE_OPERATION_TYPE_INHERIT_SHARE;
		mte_operation |= vm_kernel_map_is_kernel(map) ? VM_MTE_OPERATION_DEST_KERNEL : VM_MTE_OPERATION_DEST_USER;
		if (!vm_map_allow_mte_operation(map, 0, size, mte_operation, optional_vm_object_none() /* irrelevant here */)) {
			vmlp_api_end(VM_MAP_ENTER, KERN_NO_ACCESS);
			return KERN_NO_ACCESS;
		}
	}
#endif /* HAS_MTE */

	if (superpage_size) {
		if (object != VM_OBJECT_NULL) {
			/* caller can't provide their own VM object */
			vmlp_api_end(VM_MAP_ENTER, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}

		kr = vm_superpage_size(superpage_size, &size);
		if (kr != KERN_SUCCESS) {
			vmlp_api_end(VM_MAP_ENTER, kr);
			return kr;
		}
		mask = SUPERPAGE_SIZE - 1;
		if (size & (SUPERPAGE_SIZE - 1)) {
			vmlp_api_end(VM_MAP_ENTER, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}
		inheritance = VM_INHERIT_NONE;  /* fork() children won't inherit superpages */
	}


	if ((cur_protection & VM_PROT_WRITE) &&
	    (cur_protection & VM_PROT_EXECUTE) &&
#if XNU_TARGET_OS_OSX
	    map->pmap != kernel_pmap &&
	    (cs_process_global_enforcement() ||
	    (vmk_flags.vmkf_cs_enforcement_override
	    ? vmk_flags.vmkf_cs_enforcement
	    : (vm_map_cs_enforcement(map)
#if __arm64__
	    || !VM_MAP_IS_EXOTIC(map)
#endif /* __arm64__ */
	    ))) &&
#endif /* XNU_TARGET_OS_OSX */
#if CODE_SIGNING_MONITOR
	    (csm_address_space_exempt(map->pmap) != KERN_SUCCESS) &&
#endif
	    (VM_MAP_POLICY_WX_FAIL(map) ||
	    VM_MAP_POLICY_WX_STRIP_X(map)) &&
	    !entry_for_jit) {
		boolean_t vm_protect_wx_fail = VM_MAP_POLICY_WX_FAIL(map);

		DTRACE_VM3(cs_wx,
		    uint64_t, 0,
		    uint64_t, 0,
		    vm_prot_t, cur_protection);
		printf("CODE SIGNING: %d[%s] %s: curprot cannot be write+execute. %s\n",
		    proc_selfpid(),
		    (get_bsdtask_info(current_task())
		    ? proc_name_address(get_bsdtask_info(current_task()))
		    : "?"),
		    __FUNCTION__,
		    (vm_protect_wx_fail ? "failing" : "turning off execute"));
		cur_protection &= ~VM_PROT_EXECUTE;
		if (vm_protect_wx_fail) {
			vmlp_api_end(VM_MAP_ENTER, KERN_PROTECTION_FAILURE);
			return KERN_PROTECTION_FAILURE;
		}
	}

	if (entry_for_jit
	    && cur_protection != VM_PROT_ALL) {
		/*
		 * Native macOS processes and all non-macOS processes are
		 * expected to create JIT regions via mmap(MAP_JIT, RWX) but
		 * the RWX requirement was not enforced, and thus, we must live
		 * with our sins. We are now dealing with a JIT mapping without
		 * RWX.
		 *
		 * We deal with these by letting the MAP_JIT stick in order
		 * to avoid CS violations when these pages are mapped executable
		 * down the line. In order to appease the page table monitor (you
		 * know what I'm talking about), these pages will end up being
		 * marked as XNU_USER_DEBUG, which will be allowed because we
		 * don't enforce the code signing monitor on macOS systems. If
		 * the user-space application ever changes permissions to RWX,
		 * which they are allowed to since the mapping was originally
		 * created with MAP_JIT, then they'll switch over to using the
		 * XNU_USER_JIT type, and won't be allowed to downgrade any
		 * more after that.
		 *
		 * When not on macOS, a MAP_JIT mapping without VM_PROT_ALL is
		 * strictly disallowed.
		 */

#if XNU_TARGET_OS_OSX
		/*
		 * Continue to allow non-RWX JIT
		 */
#else
		/* non-macOS: reject JIT regions without RWX */
		DTRACE_VM3(cs_wx,
		    uint64_t, 0,
		    uint64_t, 0,
		    vm_prot_t, cur_protection);
		printf("CODE SIGNING: %d[%s] %s(%d): JIT requires RWX: failing. \n",
		    proc_selfpid(),
		    (get_bsdtask_info(current_task())
		    ? proc_name_address(get_bsdtask_info(current_task()))
		    : "?"),
		    __FUNCTION__,
		    cur_protection);
		vmlp_api_end(VM_MAP_ENTER, KERN_PROTECTION_FAILURE);
		return KERN_PROTECTION_FAILURE;
#endif
	}

	/*
	 * If the task has requested executable lockdown,
	 * deny any new executable mapping.
	 */
	if (map->map_disallow_new_exec == TRUE) {
		if (cur_protection & VM_PROT_EXECUTE) {
			vmlp_api_end(VM_MAP_ENTER, KERN_PROTECTION_FAILURE);
			return KERN_PROTECTION_FAILURE;
		}
	}

	if (resilient_codesign) {
		assert(!is_submap);
		int reject_prot = (needs_copy ? VM_PROT_ALLEXEC : (VM_PROT_WRITE | VM_PROT_ALLEXEC));
		if ((cur_protection | max_protection) & reject_prot) {
			vmlp_api_end(VM_MAP_ENTER, KERN_PROTECTION_FAILURE);
			return KERN_PROTECTION_FAILURE;
		}
	}

	if (resilient_media) {
		assert(!is_submap);
//		assert(!needs_copy);
		if (object != VM_OBJECT_NULL &&
		    !object->internal) {
			/*
			 * This mapping is directly backed by an external
			 * memory manager (e.g. a vnode pager for a file):
			 * we would not have any safe place to inject
			 * a zero-filled page if an actual page is not
			 * available, without possibly impacting the actual
			 * contents of the mapped object (e.g. the file),
			 * so we can't provide any media resiliency here.
			 */
			vmlp_api_end(VM_MAP_ENTER, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}
	}

	if (entry_for_tpro) {
		/*
		 * TPRO overrides the effective permissions of the region
		 * and explicitly maps as RW. Ensure we have been passed
		 * the expected permissions. We accept `cur_protections`
		 * RO as that will be handled on fault.
		 */
		if (!(max_protection & VM_PROT_READ) ||
		    !(max_protection & VM_PROT_WRITE) ||
		    !(cur_protection & VM_PROT_READ)) {
			vmlp_api_end(VM_MAP_ENTER, KERN_PROTECTION_FAILURE);
			return KERN_PROTECTION_FAILURE;
		}

		/*
		 * We can now downgrade the cur_protection to RO. This is a mild lie
		 * to the VM layer. But TPRO will be responsible for toggling the
		 * protections between RO/RW
		 */
		cur_protection = VM_PROT_READ;
	}

	if (is_submap) {
		vm_map_t submap;
		if (purgable) {
			/* submaps can not be purgeable */
			vmlp_api_end(VM_MAP_ENTER, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}
		if (object == VM_OBJECT_NULL) {
			/* submaps can not be created lazily */
			vmlp_api_end(VM_MAP_ENTER, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}
		submap = (vm_map_t)(uintptr_t)object;
		if (VM_MAP_PAGE_SHIFT(submap) != VM_MAP_PAGE_SHIFT(map)) {
			/* page size mismatch */
			vmlp_api_end(VM_MAP_ENTER, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}
		/* Enforce constant/transparent dichotomy */
		if (vmk_flags.vmkf_submap_atomic) {
			/* Transparent submap */
			if (!vmk_flags.vmf_permanent) {
				panic("Transparent submaps should be permanent.");
			}
			/* vm_map_adjust_offsets handling will update offset */
			offset = 0;
		} else {
			/* Constant submap */
			if (submap->vmmap_sealed == VM_MAP_NOT_SEALED) {
				panic("Constant submap being entered was not properly setup.");
			}
		}
	}

	if (size == 0 ||
	    (offset & MIN(VM_MAP_PAGE_MASK(map), PAGE_MASK_64)) != 0) {
		*address = 0;
		vmlp_api_end(VM_MAP_ENTER, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	if (map->pmap == kernel_pmap) {
		user_alias = VM_KERN_MEMORY_NONE;
	} else {
		user_alias = alias;
	}

	if (user_alias == VM_MEMORY_MALLOC_MEDIUM) {
		chunk_size = MALLOC_MEDIUM_CHUNK_SIZE;
	}

	assertf(VM_MAP_PAGE_ALIGNED(vmsr_start(rsv), VM_MAP_PAGE_MASK(map)),
	    "0x%llx", (uint64_t)vmsr_start(rsv));
	assertf(VM_MAP_PAGE_ALIGNED(size, VM_MAP_PAGE_MASK(map)),
	    "0x%llx", (uint64_t)size);

	/*
	 * Only zero-fill objects are allowed to be purgable.
	 * LP64todo - limit purgable objects to 32-bits for now
	 */
	if (purgable &&
	    (offset != 0 ||
	    (object != VM_OBJECT_NULL &&
	    (object->vo_size != size ||
	    object->purgable == VM_PURGABLE_DENY))
#if __LP64__
	    || size > ANON_MAX_SIZE
#endif
	    )) {
		vmlp_api_end(VM_MAP_ENTER, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	if (__improbable(!vm_map_is_map_size_valid(
		    map, size, vmk_flags.vmkf_no_soft_limit))) {
		vmlp_api_end(VM_MAP_ENTER, KERN_NO_SPACE);
		return KERN_NO_SPACE;
	}

	vm_map_ilk_lock(map);
	map_ilocked = true;

#define RETURN(value)   { result = value; goto BailOut; }

#if HAS_MTE
	/*
	 * If we're in an MTE disabled map and we're trying to enter *our own*
	 * MTE memory (rather than MTE memory that we're aliasing from some other
	 *  actor on the system), we must deny the request since it's conceptually
	 * invalid for MTE-disabled actors to map owned MTE-enabled memory.
	 */
	if (is_caller_entering_mte_memory) {
		task_t task = map->owning_task;
		/*
		 * !task means either:
		 * 1. This map has been terminated, in which case the result doesn't matter.
		 * 2. This map is a submap.
		 * 3. This map is not a submap, but doesn't correspond to a task (e.g. the
		 * guest map allocated in hv_space).
		 * 4. We're in one of our unit tests that constructs maps without attaching them
		 * to a task.
		 * Allowing the operation to proceed is useful for #4, and is benign for
		 * the others.
		 */
		bool is_map_mte_enabled = task && task_has_sec(task);
		if (!task && !vm_kernel_map_is_kernel(map)) {
			/* We're not attached to a task, allow entering */
			goto proceed_with_enter_mte_memory_request;
		}
		if (!is_map_mte_enabled) {
			if (object == VM_OBJECT_NULL) {
				/*
				 * If we're not entering an object, there's no way we're aliasing
				 * another actor's MTE memory and therefore we must reject this mapping
				 */
				goto fail_enter_mte_memory_request;
			} else {
				/* Don't allow !MTE tasks to enter their own MTE memory */
				bool is_memory_owned_by_map = (object->vmo_provenance == map->serial_id);
				if (is_memory_owned_by_map) {
					goto fail_enter_mte_memory_request;
				}
			}
		}
		/* All checks passed */
		goto proceed_with_enter_mte_memory_request;
fail_enter_mte_memory_request:
		RETURN(KERN_INVALID_ARGUMENT);
	}
proceed_with_enter_mte_memory_request:
#endif /* HAS_MTE */

	if (anywhere) {
		result = vm_map_locate_space_anywhere(map, vmsr_start(rsv),
		    size, mask, vmk_flags, &rsv);
	} else {
		result = vm_map_locate_space_fixed(map, vmsr_start(rsv),
		    size, mask, vmk_flags, &rsv, &zap_old_list);
	}

	vmlp_range_event(map, vmsr_start(rsv), size);
	end = vmsr_start(rsv) + size;
	if (vmsr_is_entry(rsv) && vmsr_entry(rsv)->vme_prev != vm_map_to_entry(map)) {
		/*
		 * No coalescing of guard object mappings.
		 *
		 * In the ANYWHERE case then vmsr_is_entry(rsv) should be
		 * accurate so we wouldn't reach here.
		 *
		 * In the FIXED case the vm_map_store will tell us there is no
		 * free space to allocate in.
		 *
		 * That leaves us with having to check for the case where we
		 * overwrite a range inside a chunk.
		 */
		if (!vm_map_zap_first_entry(&zap_old_list) ||
		    vms_is_null(vm_map_zap_first_entry(&zap_old_list)->vme_chunk)) {
			entry = vmsr_entry(rsv)->vme_prev;
		}
	}

	assert(VM_MAP_PAGE_ALIGNED(vmsr_start(rsv), VM_MAP_PAGE_MASK(map)));

	/*
	 * Check if what's already there is what we want.
	 */
	if (result != KERN_SUCCESS) {
		goto BailOut;
	}

	/*
	 *	At this point,
	 *		"start" and "end" should define the endpoints of the
	 *			available new range, and
	 *		"entry" should refer to the region before the new
	 *			range, and
	 *
	 *		the map should be locked.
	 */

	/*
	 *	See whether we can avoid creating a new entry (and object) by
	 *	extending one of our neighbors.  [So far, we only attempt to
	 *	extend from below.]  Note that we can never extend/join
	 *	purgable objects because they need to remain distinct
	 *	entities in order to implement their "volatile object"
	 *	semantics.
	 */

	if (purgable ||
	    entry_for_jit ||
	    entry_for_tpro ||
#if HAS_MTE
	    is_caller_entering_mte_memory ||
#endif /* HAS_MTE */
	    vm_memory_malloc_no_cow(user_alias)) {
		if (superpage_size) {
			/*
			 * For "super page" allocations, we will allocate
			 * special physically-contiguous VM objects later on,
			 * so we should not have flags instructing us to create
			 * a differently special VM object here.
			 */
			RETURN(KERN_INVALID_ARGUMENT);
		}

		if (object == VM_OBJECT_NULL) {
			assert(!superpage_size);
			object = vm_object_allocate(size, map->serial_id);
			vm_object_lock(object);
			object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
			VM_OBJECT_SET_TRUE_SHARE(object, FALSE);
			if (malloc_no_cow_except_fork &&
			    !purgable &&
			    !entry_for_jit &&
			    !entry_for_tpro &&
#if HAS_MTE
			    !is_caller_entering_mte_memory &&
#endif
			    vm_memory_malloc_no_cow(user_alias)) {
				object->copy_strategy = MEMORY_OBJECT_COPY_DELAY_FORK;
				VM_OBJECT_SET_TRUE_SHARE(object, TRUE);
			}
			if (entry_for_jit) {
				object->vo_inherit_copy_none = true;
			}
#if HAS_MTE
			if (is_caller_entering_mte_memory) {
				object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
				needs_copy = false;
				object->wimg_bits = VM_WIMG_MTE;
			}
#endif /* HAS_MTE */
			if (purgable) {
				task_t owner;
				VM_OBJECT_SET_PURGABLE(object, VM_PURGABLE_NONVOLATILE);
				if (map->pmap == kernel_pmap) {
					/*
					 * Purgeable mappings made in a kernel
					 * map are "owned" by the kernel itself
					 * rather than the current user task
					 * because they're likely to be used by
					 * more than this user task (see
					 * execargs_purgeable_allocate(), for
					 * example).
					 */
					owner = kernel_task;
				} else {
					owner = current_task();
				}
				assert(object->vo_owner == NULL);
				assert(object->resident_page_count == 0);
				assert(object->wired_page_count == 0);
				vm_purgeable_nonvolatile_enqueue(object, owner);
			}
			vm_object_unlock(object);
			offset = (vm_object_offset_t)0;
		}
	} else if (VM_MAP_PAGE_SHIFT(map) < PAGE_SHIFT) {
		/* no coalescing if address space uses sub-pages */
	} else if (keep_entries_locked) {
		/* no coalescing if caller wants the entries returned still locked. */
	} else if ((is_submap == FALSE) &&
	    (object == VM_OBJECT_NULL) &&
	    (entry != VM_MAP_ENTRY_NULL) &&
	    !VME_IN_CHUNK(entry) &&
	    (entry->vme_end == vmsr_start(rsv))) {
		if (vm_entry_try_lock_exclusive(entry)) {
			if ((entry->vme_end == vmsr_start(rsv)) &&
			    (!entry->is_shared) &&
			    (!entry->is_sub_map) &&
			    (entry->behavior == VM_BEHAVIOR_DEFAULT) &&
			    (entry->protection == cur_protection) &&
			    (entry->max_protection == max_protection) &&
			    (entry->inheritance == inheritance) &&
			    ((user_alias == VM_MEMORY_REALLOC) ||
			    (VME_ALIAS(entry) == alias)) &&
			    (entry->no_cache == no_cache) &&
			    (entry->vme_permanent == permanent) &&
			    /* no coalescing for immutable executable mappings */
			    !((entry->protection & VM_PROT_EXECUTE) &&
			    entry->vme_permanent) &&
			    (!entry->superpage_size && !superpage_size) &&
			    (!entry->zero_wired_pages) &&
			    (!entry->used_for_jit && !entry_for_jit) &&
#if __arm64e__
			    (!entry->used_for_tpro && !entry_for_tpro) &&
#endif
			    (!entry->csm_associated) &&
			    (entry->iokit_acct == iokit_acct) &&
			    (!entry->vme_resilient_codesign) &&
			    (!entry->vme_resilient_media) &&
			    (!entry->vme_atomic) &&
			    (entry->vme_no_copy_on_read == no_copy_on_read) &&

			    ((entry->vme_end - entry->vme_start) + size <=
			    (user_alias == VM_MEMORY_REALLOC ?
			    ANON_CHUNK_SIZE :
			    NO_COALESCE_LIMIT)) &&

			    (entry->wired_count == 0)) {        /* implies user_wired_count == 0 */
				if (vm_object_coalesce(VME_OBJECT(entry), VM_OBJECT_NULL,
				    VME_OFFSET(entry), (vm_object_offset_t)0,
				    (vm_map_size_t)(entry->vme_end - entry->vme_start),
				    (vm_map_size_t)(end - entry->vme_end))) {
					/*
					 *	Coalesced the two objects - can extend
					 *	the previous map entry to include the
					 *	new range.
					 */
					vm_map_store_extend_right(map, entry, end);
					vm_entry_unlock_exclusive(map, entry);
					new_mapping_established = TRUE;
					RETURN(KERN_SUCCESS);
				}
			}
			vm_entry_unlock_exclusive(map, entry);
		}
	}

	step = superpage_size ? SUPERPAGE_SIZE : size;

	if (vmk_flags.vmkf_submap_atomic) {
		vm_map_adjust_offsets((vm_map_t)(uintptr_t)caller_object,
		    vmsr_start(rsv), end);
		offset = vmsr_start(rsv);
	}

	if (!is_submap && needs_copy) {
		assert(object);
		assert(object->internal);
		assert3u(object->copy_strategy, ==, MEMORY_OBJECT_COPY_SYMMETRIC);
		if (!object->shadowed) {
			vm_object_lock(object);
			VM_OBJECT_SET_SHADOWED(object, TRUE);
			vm_object_unlock(object);
		}
		assert(object->shadowed);
	}

	for (tmp2_start = vmsr_start(rsv); tmp2_start < end; tmp2_start += step) {
		tmp2_end = tmp2_start + step;
		/*
		 *	Create a new entry
		 *
		 * XXX FBDP
		 * The reserved "page zero" in each process's address space can
		 * be arbitrarily large.  Splitting it into separate objects and
		 * therefore different VM map entries serves no purpose and just
		 * slows down operations on the VM map, so let's not split the
		 * allocation into chunks if the max protection is NONE.  That
		 * memory should never be accessible, so it will never get to the
		 * default pager.
		 */
		tmp_start = tmp2_start;
		if (!is_submap &&
		    object == VM_OBJECT_NULL &&
		    size > chunk_size &&
		    max_protection != VM_PROT_NONE &&
		    superpage_size == 0) {
			tmp_end = tmp_start + chunk_size;
		} else {
			tmp_end = tmp2_end;
		}
		do {
			if (!is_submap &&
			    object != VM_OBJECT_NULL &&
			    object->internal &&
			    offset + (tmp_end - tmp_start) > object->vo_size) {
//				printf("FBDP object %p size 0x%llx overmapping offset 0x%llx size 0x%llx\n", object, object->vo_size, offset, (uint64_t)(tmp_end - tmp_start));
				DTRACE_VM5(vm_map_enter_overmap,
				    vm_map_t, map,
				    vm_map_address_t, tmp_start,
				    vm_map_address_t, tmp_end,
				    vm_object_offset_t, offset,
				    vm_object_size_t, object->vo_size);
			}
			vm_map_entry_t new_entry = vm_map_entry_create_locked_and_insert(map,
			    tmp_start, tmp_end,
			    object, offset, vmk_flags,
			    needs_copy,
			    cur_protection, max_protection,
			    (entry_for_jit && !VM_MAP_POLICY_ALLOW_JIT_INHERIT(map) ?
			    VM_INHERIT_NONE : inheritance));
#if HAS_MTE
			if (object == kernel_object_tagged) {
				assert(new_entry->vme_is_tagged);
			} else if (object == kernel_object_default) {
				assert(!new_entry->vme_is_tagged);
			}
#endif

			assert(!is_kernel_object(object) || (VM_KERN_MEMORY_NONE != alias));

			if (resilient_codesign) {
				int reject_prot = (needs_copy ? VM_PROT_ALLEXEC : (VM_PROT_WRITE | VM_PROT_ALLEXEC));
				if (!((cur_protection | max_protection) & reject_prot)) {
					new_entry->vme_resilient_codesign = TRUE;
				}
			}

			if (resilient_media &&
			    (object == VM_OBJECT_NULL ||
			    object->internal)) {
				new_entry->vme_resilient_media = TRUE;
			}

			assert(!new_entry->iokit_acct);
			if (!is_submap &&
			    object != VM_OBJECT_NULL &&
			    object->internal &&
			    (object->purgable != VM_PURGABLE_DENY ||
			    object->vo_ledger_tag)) {
				assert(new_entry->use_pmap);
				assert(!new_entry->iokit_acct);
				/*
				 * Turn off pmap accounting since
				 * purgeable (or tagged) objects have their
				 * own ledgers.
				 */
				new_entry->use_pmap = FALSE;
			} else if (!is_submap &&
			    iokit_acct &&
			    object != VM_OBJECT_NULL &&
			    object->internal) {
				/* alternate accounting */
				assert(!new_entry->iokit_acct);
				assert(new_entry->use_pmap);
				new_entry->iokit_acct = TRUE;
				new_entry->use_pmap = FALSE;
				DTRACE_VM4(
					vm_map_iokit_mapped_region,
					vm_map_t, map,
					vm_map_offset_t, new_entry->vme_start,
					vm_map_offset_t, new_entry->vme_end,
					int, VME_ALIAS(new_entry));
				vm_map_iokit_mapped_region(
					map,
					(new_entry->vme_end -
					new_entry->vme_start));
			} else if (!is_submap) {
				assert(!new_entry->iokit_acct);
				assert(new_entry->use_pmap);
			}

			if (is_submap) {
				vm_map_t        submap;
				boolean_t       submap_is_64bit;
				boolean_t       use_pmap;

				assert(new_entry->is_sub_map);
				assert(!new_entry->use_pmap);
				assert(!new_entry->iokit_acct);
				submap = (vm_map_t)(uintptr_t)object;
				submap_is_64bit = vm_map_is_64bit(submap);
				use_pmap = vmk_flags.vmkf_nested_pmap;
#ifndef NO_NESTED_PMAP
				if (use_pmap && submap->pmap == NULL) {
					ledger_t ledger = map->pmap->ledger;
					/* we need a sub pmap to nest... */
					submap->pmap = pmap_create_options(ledger, 0,
					    submap_is_64bit ? PMAP_CREATE_64BIT | PMAP_CREATE_NESTED : PMAP_CREATE_NESTED);
					if (submap->pmap == NULL) {
						/* let's proceed without nesting... */
					}
#if defined(__arm64__)
					else {
						/*
						 * When a nested pmap is created within vm_shared_region_create, we
						 * need to call csm_setup_nested_address_space, but the same doesn't
						 * need to happen here.
						 *
						 * We only enter the parent if-block if use_pmap is set to true, which
						 * is based on vmkf_nested_pmap. This flag is only set by two functions,
						 * vm_shared_region_enter, and vm_commpage_enter. The former performs a
						 * shared region lookup, which uses vm_shared_region_create. This path
						 * already creates a pmap, so submap->pmap != NULL. The latter doesn't
						 * go through the VM layer on arm64 systems anymore. As a result, there
						 * is no case on arm64 where a nested pmap is actually in this path.
						 */
						pmap_set_nested(submap->pmap);
					}
#endif
				}
				if (use_pmap && submap->pmap != NULL) {
					if (VM_MAP_PAGE_SHIFT(map) != VM_MAP_PAGE_SHIFT(submap)) {
						DEBUG4K_ERROR("map %p (%d) submap %p (%d): incompatible page sizes\n", map, VM_MAP_PAGE_SHIFT(map), submap, VM_MAP_PAGE_SHIFT(submap));
						kr = KERN_FAILURE;
					} else {
						kr = pmap_nest(map->pmap,
						    submap->pmap,
						    tmp_start,
						    tmp_end - tmp_start);
					}
					if (kr != KERN_SUCCESS) {
						printf("vm_map_enter: "
						    "pmap_nest(0x%llx,0x%llx) "
						    "error 0x%x\n",
						    (long long)tmp_start,
						    (long long)tmp_end,
						    kr);
					} else {
						/* we're now nested ! */
						new_entry->use_pmap = TRUE;
						pmap_empty = FALSE;
					}
				}
#endif /* NO_NESTED_PMAP */
			}
			entry = new_entry;

			if (superpage_size) {
				vm_page_t pages, m;
				vm_object_t sp_object;
				vm_object_offset_t sp_offset;

				assert(object == VM_OBJECT_NULL);
				VME_OFFSET_SET(entry, 0);

				/* allocate one superpage */
				kr = cpm_allocate(SUPERPAGE_SIZE, &pages, 0, SUPERPAGE_NBASEPAGES - 1, TRUE, 0);
				if (kr != KERN_SUCCESS) {
					/* deallocate whole range... */
					new_mapping_established = TRUE;
					/* ... but only up to "tmp_end" */
					size -= end - tmp_end;
					vm_entry_unlock_exclusive(map, entry);
					RETURN(kr);
				}

				/* create one vm_object per superpage */
				sp_object = vm_object_allocate((vm_map_size_t)(entry->vme_end - entry->vme_start), map->serial_id);
				vm_object_lock(sp_object);
				sp_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
				VM_OBJECT_SET_PHYS_CONTIGUOUS(sp_object, TRUE);
				sp_object->vo_shadow_offset = (vm_object_offset_t)VM_PAGE_GET_PHYS_PAGE(pages) * PAGE_SIZE;
				VME_OBJECT_SET(entry, sp_object, false, 0);
				assert(entry->use_pmap);

				/* enter the base pages into the object */
				for (sp_offset = 0;
				    sp_offset < SUPERPAGE_SIZE;
				    sp_offset += PAGE_SIZE) {
					m = pages;
					pmap_zero_page(VM_PAGE_GET_PHYS_PAGE(m));
					pages = NEXT_PAGE(m);
					*(NEXT_PAGE_PTR(m)) = VM_PAGE_NULL;
					vm_page_insert_wired(m, sp_object, sp_offset, VM_KERN_MEMORY_OSFMK);
				}
				vm_object_unlock(sp_object);
			}

			/*
			 * Unlock the new entry we created locked at
			 * vm_map_entry_create_locked_and_insert.
			 */
			if (!keep_entries_locked) {
				vm_entry_unlock_exclusive(map, entry);
			}
		} while (tmp_end != tmp2_end &&
		    (tmp_start = tmp_end) &&
		    (tmp_end = (tmp2_end - tmp_end > chunk_size) ?
		    tmp_end + chunk_size : tmp2_end));
	}

	new_mapping_established = TRUE;
#if HAS_MTE
	if (vmk_flags.vmf_mte) {
		vm_map_mark_has_sec_access_ilocked(map);
	}
#endif /* HAS_MTE*/


BailOut:
	assert(map_ilocked);

	/*
	 * Address space limit enforcement (RLIMIT_AS and RLIMIT_DATA):
	 * If we have identified and possibly established the new mapping(s),
	 * make sure we did not go beyond the address space limit.
	 */
	if (result == KERN_SUCCESS) {
		if (map->size_limit != RLIM_INFINITY &&
		    map->size > map->size_limit) {
			/*
			 * Establishing the requested mappings would exceed
			 * the process's RLIMIT_AS limit: fail with
			 * KERN_NO_SPACE.
			 */
			result = KERN_NO_SPACE;
			printf("%d[%s] %s: map size 0x%llx over RLIMIT_AS 0x%llx\n",
			    proc_selfpid(),
			    (get_bsdtask_info(current_task())
			    ? proc_name_address(get_bsdtask_info(current_task()))
			    : "?"),
			    __FUNCTION__,
			    (uint64_t) map->size,
			    (uint64_t) map->size_limit);
			DTRACE_VM2(vm_map_enter_RLIMIT_AS,
			    vm_map_size_t, map->size,
			    uint64_t, map->size_limit);
			vm_map_enter_RLIMIT_AS_count++;
		} else if (map->data_limit != RLIM_INFINITY &&
		    map->size > map->data_limit) {
			/*
			 * Establishing the requested mappings would exceed
			 * the process's RLIMIT_DATA limit: fail with
			 * KERN_NO_SPACE.
			 */
			result = KERN_NO_SPACE;
			printf("%d[%s] %s: map size 0x%llx over RLIMIT_DATA 0x%llx\n",
			    proc_selfpid(),
			    (get_bsdtask_info(current_task())
			    ? proc_name_address(get_bsdtask_info(current_task()))
			    : "?"),
			    __FUNCTION__,
			    (uint64_t) map->size,
			    (uint64_t) map->data_limit);
			DTRACE_VM2(vm_map_enter_RLIMIT_DATA,
			    vm_map_size_t, map->size,
			    uint64_t, map->data_limit);
			vm_map_enter_RLIMIT_DATA_count++;
		}

		if (result == KERN_NO_SPACE && anywhere) {
			vm_guard_object_find_space_abort(map, rsv);
		}
	}

	if (result == KERN_SUCCESS) {
		vm_prot_t pager_prot;
		memory_object_t pager;

#if DEBUG
		/*
		 * Usually, we have no pmap mappings when we are creating a new entry.
		 * However, during early startup, to reserve the VM space, we create a
		 * VM mapping that sits on top of pre-existing mappings in the kernel
		 * pmap.
		 */
		if (pmap_empty && startup_phase >= STARTUP_SUB_KMEM) {
			assert(pmap_is_empty(map->pmap, rsv.rsv_start, end));
		}
#endif /* DEBUG */

		/*
		 * For "named" VM objects, let the pager know that the
		 * memory object is being mapped.  Some pagers need to keep
		 * track of this, to know when they can reclaim the memory
		 * object, for example.
		 * VM calls memory_object_map() for each mapping (specifying
		 * the protection of each mapping) and calls
		 * memory_object_last_unmap() when all the mappings are gone.
		 */
		pager_prot = max_protection;
		if (needs_copy) {
			/*
			 * Copy-On-Write mapping: won't modify
			 * the memory object.
			 */
			pager_prot &= ~VM_PROT_WRITE;
		}
		if (!is_submap &&
		    object != VM_OBJECT_NULL &&
		    object->named &&
		    object->pager != MEMORY_OBJECT_NULL) {
			vm_object_lock(object);
			pager = object->pager;
			if (object->named &&
			    pager != MEMORY_OBJECT_NULL) {
				assert(object->pager_ready);
				vm_object_mapping_wait(object, THREAD_UNINT);
				/* object might have lost its pager while waiting */
				pager = object->pager;
				if (object->named && pager != MEMORY_OBJECT_NULL) {
					vm_object_mapping_begin(object);
					vm_object_unlock(object);

					kr = memory_object_map(pager, pager_prot);
					assert(kr == KERN_SUCCESS);

					vm_object_lock(object);
					vm_object_mapping_end(object);
				}
			}
			vm_object_unlock(object);
		}
	}

	assert(map_ilocked);

	if (new_mapping_established) {
		/*
		 * If we release the map interlock for any reason below,
		 * another thread could deallocate our new mapping,
		 * releasing the caller's reference on "caller_object",
		 * which was transferred to the mapping.
		 * If this was the only reference, the object could be
		 * destroyed.
		 *
		 * We need to take an extra reference on "caller_object"
		 * to keep it alive if we need to return the caller's
		 * reference to the caller in case of failure.
		 */
		if (is_submap) {
			vm_map_reference((vm_map_t)(uintptr_t)caller_object);
		} else {
			vm_object_reference(caller_object);
		}
	}

	/* Make sure we don't accidentally use entry past this point. */
	entry = VM_MAP_ENTRY_NULL;

	if (result == KERN_SUCCESS) {
		/*
		 *	We can't hold the map interlock if we enter this block:
		 *
		 *	Wire down the new entry if the user
		 *	requested a superpage.
		 */
		if (superpage_size) {
			vm_map_ilk_unlock(map);
			map_ilocked = false;
			map_lock_dropped = true;

			assert(!keep_entries_locked);
			assert(!keep_map_ilocked);
			pmap_empty = FALSE; /* pmap won't be empty */
			kr = vm_map_wire_kernel(map, vmsr_start(rsv), end,
			    cur_protection, VM_KERN_MEMORY_MLOCK, TRUE);
			result = kr;
		}
	}

	if (result != KERN_SUCCESS) {
		if (new_mapping_established) {
			kern_return_t remove_kr = KERN_SUCCESS;
			vmr_flags_t remove_flags = VM_MAP_REMOVE_TO_OVERWRITE;
			vm_map_entry_t sentinel = VM_MAP_ENTRY_NULL;

			/*
			 * We have to get rid of the new mappings since we
			 * won't make them available to the user.
			 * Try and do that atomically, to minimize the risk
			 * that someone else create new mappings that range.
			 */
			if (!map_ilocked) {
				vm_map_ilk_lock(map);
				map_ilocked = true;
			}
			if (permanent) {
				remove_flags |= VM_MAP_REMOVE_IMMUTABLE;
			}
			if (keep_entries_locked) {
				/*
				 * The entries weren't unlocked when we created them, so now we
				 * need to unlock each of them before they are deleted.
				 */
				vm_map_entry_t cur_entry = vm_map_store_lookup_entry(map, *address, false);
				if (!cur_entry) {
					panic("entries modified while locked");
				}

				while (cur_entry != vm_map_to_entry(map) &&
				    cur_entry->vme_end < (*address + size)) {
					vm_entry_unlock_exclusive(map, cur_entry);
					cur_entry = cur_entry->vme_next;
				}
			}
			remove_kr = vm_map_delete_and_iunlock(map,
			    vmsr_start(rsv), end, remove_flags,
			    KMEM_GUARD_NONE, &sentinel, &zap_new_list);
#if !defined(__x86_64__) && !defined(__BUILDING_XNU_LIB_UNITTEST__)
			/*
			 * !__BUILDING_XNU_LIB_UNITTEST__ to allow testing
			 * superpages on non x86 devices
			 */

			/*
			 * We never dropped the ilk between when we created
			 * the mapping above and now, so our delete should
			 * always succeed.
			 */
			if (remove_kr != KERN_SUCCESS) {
				panic("couldn't remove what we just made in %p", map);
			}
			assert(VM_MAP_ENTRY_NULL != sentinel);
#else /* __x86_64__ || __BUILDING_XNU_LIB_UNITTEST__*/
			/*
			 * on x86, we may drop the ilk for superpages so we can't
			 * make guarantees about this delete being atomic with
			 * our creation of the mapping.
			 * If we drop the map lock, the delete could fail.
			 */
			if (map_lock_dropped == false && remove_kr != KERN_SUCCESS) {
				panic("couldn't remove what we just made in %p", map);
			}
#endif
			vm_map_ilk_lock(map);
			if (sentinel && remove_kr == KERN_SUCCESS) {
				vm_map_store_remove(map, sentinel,
				    VMS_REMOVE_FREE_ENTRY);
			}
		}

		/*
		 * Reinstating the zap_old_list shouldn't fail -but-, it may
		 * when superpages are used because we drop the lock when we
		 * call vm_map_wire_kernel().
		 *
		 * Super pages do not exist on arm64 though.
		 */

		if (vm_map_zap_first_entry(&zap_old_list)) {
			vm_map_address_t z_start, z_end;

			/*
			 * The new mapping failed.  Attempt to restore
			 * the old mappings, saved in the "zap_old_map".
			 */
			if (!map_ilocked) {
				vm_map_ilk_lock(map);
				map_ilocked = true;
			}

			/* first check if the coast is still clear */
			z_start = vm_map_zap_first_entry(&zap_old_list)->vme_start;
			z_end   = vm_map_zap_last_entry(&zap_old_list)->vme_end;

			if (!vm_map_store_has_entries(map, z_start, z_end)) {
				/*
				 * Transfer the saved map entries from
				 * "zap_old_map" to the original "map".
				 */
				while ((entry = vm_map_zap_pop(&zap_old_list))) {
					assert(!VME_IS_SENTINEL(entry));
					vm_map_store_insert(map, entry);
					vm_entry_unlock_exclusive(map, entry);
				}
				vm_map_enter_restore_successes++;
			} else {
				/*
				 * Part of that range has already been
				 * re-mapped:  we can't restore the old
				 * mappings...
				 */
				assert(map_lock_dropped);
				vm_map_enter_restore_failures++;
			}
		}
	}

	/*
	 * The caller is responsible for releasing the interlock if it requested to
	 * keep the interlocked held, unless we failed to enter its mapping, in
	 * which case we should consistently release the interlock before we return.
	 */
	if (map_ilocked && (!keep_map_ilocked || result != KERN_SUCCESS)) {
		vm_map_ilk_unlock(map);
	}

	vm_map_zap_dispose(map, &zap_old_list);
	vm_map_zap_dispose(map, &zap_new_list);

	if (new_mapping_established) {
		/*
		 * The caller had a reference on "caller_object" and we
		 * transferred that reference to the mapping.
		 * We also took an extra reference on "caller_object" to keep
		 * it alive while the map was unlocked.
		 */
		if (result == KERN_SUCCESS) {
			/*
			 * On success, the caller's reference on the object gets
			 * tranferred to the mapping.
			 * Release our extra reference.
			 */
			if (is_submap) {
				vm_map_deallocate((vm_map_t)(uintptr_t)caller_object);
			} else {
				vm_object_deallocate(caller_object);
			}
		} else {
			/*
			 * On error, the caller expects to still have a
			 * reference on the object it gave us.
			 * Let's use our extra reference for that.
			 */
		}
	}

	if (result == KERN_SUCCESS) {
		*address = vmsr_start(rsv);
	}
	vmlp_api_end(VM_MAP_ENTER, result);
	return result;

#undef  RETURN
}

/*
 * Counters for the prefault optimization.
 */
int64_t vm_prefault_nb_pages = 0;
int64_t vm_prefault_nb_bailout = 0;
int64_t vm_prefault_nb_no_page = 0;
int64_t vm_prefault_nb_wrong_page = 0;


static kern_return_t
vm_map_enter_adjust_offset(
	vm_object_offset_t *obj_offs,
	vm_object_offset_t *obj_end,
	vm_object_offset_t  quantity)
{
	if (os_add_overflow(*obj_offs, quantity, obj_offs) ||
	    os_add_overflow(*obj_end, quantity, obj_end) ||
	    vm_map_round_page_mask(*obj_end, PAGE_MASK) == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_enter_mem_object_sanitize(
	vm_map_t                target_map,
	vm_map_offset_ut        address_u,
	vm_map_size_ut          initial_size_u,
	vm_map_offset_ut        mask_u,
	vm_object_offset_ut     offset_u,
	vm_prot_ut              cur_protection_u,
	vm_prot_ut              max_protection_u,
	vm_inherit_ut           inheritance_u,
	vm_map_kernel_flags_t   vmk_flags,
	ipc_port_t              port,
	vm_map_address_t       *map_addr,
	vm_map_size_t          *map_size,
	vm_map_offset_t        *mask,
	vm_object_offset_t     *obj_offs,
	vm_object_offset_t     *obj_end,
	vm_object_size_t       *obj_size,
	vm_prot_t              *cur_protection,
	vm_prot_t              *max_protection,
	vm_inherit_t           *inheritance)
{
	kern_return_t           result;

	result = vm_sanitize_cur_and_max_prots(cur_protection_u, max_protection_u,
	    VM_SANITIZE_CALLER_ENTER_MEM_OBJ, target_map,
	    VM_PROT_IS_MASK, cur_protection,
	    max_protection);
	if (__improbable(result != KERN_SUCCESS)) {
		return result;
	}

	result = vm_sanitize_inherit(inheritance_u, VM_SANITIZE_CALLER_ENTER_MEM_OBJ,
	    inheritance);
	if (__improbable(result != KERN_SUCCESS)) {
		return result;
	}

	result = vm_sanitize_mask(mask_u, VM_SANITIZE_CALLER_ENTER_MEM_OBJ, mask);
	if (__improbable(result != KERN_SUCCESS)) {
		return result;
	}

	if (vmk_flags.vmf_fixed) {
		vm_map_address_t        map_end;

		result = vm_sanitize_addr_size(address_u, initial_size_u,
		    VM_SANITIZE_CALLER_ENTER_MEM_OBJ,
		    target_map,
		    VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS | VM_SANITIZE_FLAGS_REALIGN_START,
		    map_addr, &map_end, map_size);
		if (__improbable(result != KERN_SUCCESS)) {
			return result;
		}
	} else {
		*map_addr = vm_sanitize_addr(target_map, address_u);
		result = vm_sanitize_size(0, initial_size_u,
		    VM_SANITIZE_CALLER_ENTER_MEM_OBJ, target_map,
		    VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS, map_size);
		if (__improbable(result != KERN_SUCCESS)) {
			return result;
		}
	}

	*obj_size = vm_object_round_page(*map_size);
	if (__improbable(*obj_size == 0)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(port)) {
		result = vm_sanitize_addr_size(offset_u, *obj_size,
		    VM_SANITIZE_CALLER_ENTER_MEM_OBJ,
		    PAGE_MASK,
		    VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS |
		    VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES,
		    obj_offs, obj_end, obj_size);
		if (__improbable(result != KERN_SUCCESS)) {
			return result;
		}
	} else {
		*obj_offs = 0;
		*obj_end  = *obj_size;
	}

	return KERN_SUCCESS;
}

uint64_t vm_map_copy_extra_adjustments = 0;
kern_return_t
vm_map_enter_mem_object(
	vm_map_t                target_map,
	vm_map_offset_ut       *address_u,
	vm_map_size_ut          initial_size_u,
	vm_map_offset_ut        mask_u,
	vm_map_kernel_flags_t   vmk_flags,
	ipc_port_t              port,
	vm_object_offset_ut     offset_u,
	boolean_t               copy,
	vm_prot_ut              cur_protection_u,
	vm_prot_ut              max_protection_u,
	vm_inherit_ut           inheritance_u,
	upl_page_list_ptr_t     page_list,
	unsigned int            page_list_count)
{
	vm_map_offset_t         mask;
	vm_prot_t               cur_protection;
	vm_prot_t               max_protection;
	vm_inherit_t            inheritance;
	vm_map_address_t        map_addr, map_mask;
	vm_map_size_t           map_size;
	vm_object_t             object = VM_OBJECT_NULL;
	vm_object_offset_t      obj_offs, obj_end;
	vm_object_size_t        obj_size;
	kern_return_t           result;
	boolean_t               mask_cur_protection, mask_max_protection;
	boolean_t               kernel_prefault, try_prefault = (page_list_count != 0);
	vm_map_offset_t         offset_in_mapping = 0;

	vmlp_api_start(VM_MAP_ENTER_MEM_OBJECT);

	if (VM_MAP_PAGE_SHIFT(target_map) < PAGE_SHIFT) {
		/* XXX TODO4K prefaulting depends on page size... */
		try_prefault = FALSE;
	}

	/*
	 * Check arguments for validity
	 */
	if ((target_map == VM_MAP_NULL) ||
	    (try_prefault && (copy || !page_list))) {
		vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	map_mask = vm_map_page_mask(target_map);

	/*
	 * Sanitize any input parameters that are addr/size/prot/inherit
	 */
	result = vm_map_enter_mem_object_sanitize(
		target_map,
		*address_u,
		initial_size_u,
		mask_u,
		offset_u,
		cur_protection_u,
		max_protection_u,
		inheritance_u,
		vmk_flags,
		port,
		&map_addr,
		&map_size,
		&mask,
		&obj_offs,
		&obj_end,
		&obj_size,
		&cur_protection,
		&max_protection,
		&inheritance);
	if (__improbable(result != KERN_SUCCESS)) {
		vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, vm_sanitize_get_kr(result));
		return vm_sanitize_get_kr(result);
	}

	vm_map_kernel_flags_update_range_id(&vmk_flags, target_map, map_size);

	mask_cur_protection = cur_protection & VM_PROT_IS_MASK;
	mask_max_protection = max_protection & VM_PROT_IS_MASK;
	cur_protection &= ~VM_PROT_IS_MASK;
	max_protection &= ~VM_PROT_IS_MASK;

#if __arm64__
	if (cur_protection & VM_PROT_EXECUTE) {
		cur_protection |= VM_PROT_READ;
		max_protection |= VM_PROT_READ;
	}
#endif /* __arm64__ */

	/*
	 * Find the vm object (if any) corresponding to this port.
	 */
	if (!IP_VALID(port)) {
		object = VM_OBJECT_NULL;
		copy = FALSE;
	} else if (ip_type(port) == IKOT_NAMED_ENTRY) {
		vm_named_entry_t        named_entry;
		vm_object_size_t        initial_size;

		named_entry = mach_memory_entry_from_port(port);

		if (named_entry->is_copy ||
		    vmk_flags.vmf_return_data_addr ||
		    vmk_flags.vmf_return_4k_data_addr) {
			result = vm_map_enter_adjust_offset(&obj_offs,
			    &obj_end, named_entry->data_offset);
			if (__improbable(result)) {
				vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, result);
				return result;
			}
		}

		/* a few checks to make sure user is obeying rules */
		if (mask_max_protection) {
			max_protection &= named_entry->protection;
		}
		if (mask_cur_protection) {
			cur_protection &= named_entry->protection;
		}
		if ((named_entry->protection & max_protection) !=
		    max_protection) {
			vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, KERN_INVALID_RIGHT);
			return KERN_INVALID_RIGHT;
		}
		if ((named_entry->protection & cur_protection) !=
		    cur_protection) {
			vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, KERN_INVALID_RIGHT);
			return KERN_INVALID_RIGHT;
		}

		/*
		 * unwrap is safe because we know obj_size is larger and doesn't
		 * overflow
		 */
		initial_size = VM_SANITIZE_UNSAFE_UNWRAP(initial_size_u);
		if (named_entry->size < obj_offs + initial_size) {
			vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}

		if (named_entry->is_copy &&
		    (obj_size != named_entry->size) &&
		    (vm_map_round_page(obj_size, map_mask) == named_entry->size)) {
			/*
			 * XXX FBDP use the rounded size that covers the whole entry...
			 * vm_map_copy_adjust_to_target() should take care of this now,
			 * so this is harmless but probably no longer needed.
			 */
			obj_end += named_entry->size - obj_size;
			obj_size = named_entry->size;
		}

		if (named_entry->offset) {
			/*
			 * the callers parameter offset is defined to be the
			 * offset from beginning of named entry offset in object
			 *
			 * Because we checked above that
			 *   obj_offs + obj_size < named_entry_size
			 * these overflow checks should be redundant...
			 */
			result = vm_map_enter_adjust_offset(&obj_offs,
			    &obj_end, named_entry->offset);
			if (__improbable(result)) {
				vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, result);
				return result;
			}
		}

		if (!VM_MAP_PAGE_ALIGNED(obj_size, map_mask)) {
			/*
			 * Let's not map more than requested;
			 * vm_map_enter() will handle this "not map-aligned"
			 * case.
			 */
			map_size = obj_size;
		}

		named_entry_lock(named_entry);

		// rdar://130307561 (Combine copy, object, and submap fields of vm_named_entry into an enum)
		assert(named_entry->is_copy || named_entry->is_object || named_entry->is_sub_map);

		if (named_entry->is_sub_map) {
			vm_map_t                submap;

			assert(!named_entry->is_copy);
			assert(!named_entry->is_object);

			if (vmk_flags.vmf_return_data_addr ||
			    vmk_flags.vmf_return_4k_data_addr) {
				panic("VM_FLAGS_RETURN_DATA_ADDR not expected for submap.");
			}

			submap = named_entry->backing.map;
			vm_map_reference(submap);
			named_entry_unlock(named_entry);

			vmk_flags.vmkf_submap = TRUE;
			result = vm_map_enter(target_map,
			    &map_addr,
			    map_size,
			    mask,
			    vmk_flags,
			    (vm_object_t)(uintptr_t) submap,
			    obj_offs,
			    copy,
			    cur_protection,
			    max_protection,
			    inheritance);
			if (result != KERN_SUCCESS) {
				vm_map_deallocate(submap);
				vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, result);
				return result;
			}
			/*
			 * No need to lock "submap" just to check its
			 * "mapped" flag: that flag is never reset
			 * once it's been set and if we race, we'll
			 * just end up setting it twice, which is OK.
			 */
			if (submap->mapped_in_other_pmaps == FALSE &&
			    vm_map_pmap(submap) != PMAP_NULL &&
			    vm_map_pmap(submap) !=
			    vm_map_pmap(target_map)) {
				/*
				 * This submap is being mapped in a map
				 * that uses a different pmap.
				 * Set its "mapped_in_other_pmaps" flag
				 * to indicate that we now need to
				 * remove mappings from all pmaps rather
				 * than just the submap's pmap.
				 */
				vm_map_ilk_lock(submap);
				submap->mapped_in_other_pmaps = TRUE;
				vm_map_ilk_unlock(submap);
			}
			goto out;
		}

		if (named_entry->is_copy) {
			kern_return_t   kr;
			vm_map_copy_t   copy_map;
			vm_map_entry_t  copy_entry;
			vm_map_offset_t copy_addr;
			vm_map_copy_t   target_copy_map;
			vm_map_offset_t overmap_start, overmap_end;
			vm_map_offset_t trimmed_start;
			vm_map_size_t   target_size;

			assert(!named_entry->is_object);
			assert(!named_entry->is_sub_map);

			int allowed_flags = VM_FLAGS_FIXED |
			    VM_FLAGS_ANYWHERE |
			    VM_FLAGS_OVERWRITE |
			    VM_FLAGS_RETURN_4K_DATA_ADDR |
			    VM_FLAGS_RETURN_DATA_ADDR;
#if HAS_MTE
			if (vmk_flags.vmf_mte) {
				allowed_flags |= VM_FLAGS_MTE;
			}
#endif /* HAS_MTE */

			if (!vm_map_kernel_flags_check_vmflags(vmk_flags, allowed_flags)) {
				named_entry_unlock(named_entry);
				vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, KERN_INVALID_ARGUMENT);
				return KERN_INVALID_ARGUMENT;
			}

			copy_map = named_entry->backing.copy;
			vm_map_copy_require(copy_map);
			assert(copy_map->type == VM_MAP_COPY_ENTRY_LIST);
			if (copy_map->type != VM_MAP_COPY_ENTRY_LIST) {
				/* unsupported type; should not happen */
				printf("vm_map_enter_mem_object: "
				    "memory_entry->backing.copy "
				    "unsupported type 0x%x\n",
				    copy_map->type);
				named_entry_unlock(named_entry);
				vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, KERN_INVALID_ARGUMENT);
				return KERN_INVALID_ARGUMENT;
			}

			if (VM_MAP_PAGE_SHIFT(target_map) != copy_map->cpy_hdr.page_shift) {
				DEBUG4K_SHARE("copy_map %p offset %llx size 0x%llx pgshift %d -> target_map %p pgshift %d\n", copy_map, obj_offs, (uint64_t)map_size, copy_map->cpy_hdr.page_shift, target_map, VM_MAP_PAGE_SHIFT(target_map));
			}

			if (vmk_flags.vmf_return_data_addr ||
			    vmk_flags.vmf_return_4k_data_addr) {
				offset_in_mapping = obj_offs & map_mask;
				if (vmk_flags.vmf_return_4k_data_addr) {
					offset_in_mapping &= ~((signed)(0xFFF));
				}
			}

			target_copy_map = VM_MAP_COPY_NULL;
			overmap_start = 0;
			overmap_end = 0;
			trimmed_start = 0;
			DEBUG4K_ADJUST("adjusting...\n");
			kr = vm_map_copy_adjust_to_target(
				copy_map,
				obj_offs,
				initial_size,
				target_map,
				copy,
				&target_copy_map,
				&overmap_start,
				&overmap_end,
				&trimmed_start);
			if (kr != KERN_SUCCESS) {
				named_entry_unlock(named_entry);
				vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, kr);
				return kr;
			}
			target_size = target_copy_map->size;
			if (target_copy_map != copy_map &&
			    target_size != copy_map->size &&
			    copy_map->cpy_hdr.page_shift == VM_MAP_PAGE_SHIFT(target_map)) {
//				printf("*** FBDP :%d adjust off 0x%llx sz 0x%llx e[doff 0x%llx off 0x%llx sz 0x%llx] objoffs 0x%llx i_size 0x%llx map_size 0x%llx copy size 0x%llx -> 0x%llx oim 0x%llx trim 0x%llx over 0x%llx/0x%llx tgt [0x%llx/0x%llx 0x%llx/0x%llx]\n", __LINE__, VM_SANITIZE_UNSAFE_UNWRAP(offset_u), VM_SANITIZE_UNSAFE_UNWRAP(initial_size_u), named_entry->data_offset, named_entry->offset, named_entry->size, obj_offs, initial_size, map_size, copy_map->size, target_copy_map->size, offset_in_mapping, trimmed_start, overmap_start, overmap_end, vm_map_copy_first_entry(target_copy_map)->vme_start, VME_OFFSET(vm_map_copy_first_entry(target_copy_map)), vm_map_copy_last_entry(target_copy_map)->vme_end, VME_OFFSET(vm_map_copy_last_entry(target_copy_map)));
				vm_map_copy_extra_adjustments++;
				ktriage_record(thread_tid(current_thread()), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_VM_MAP_ENTER_MEM_ENTRY_PARTIAL), vm_map_copy_extra_adjustments /* arg */);
			}

			vm_map_kernel_flags_t rsv_flags = vmk_flags;

			vm_map_kernel_flags_and_vmflags(&rsv_flags,
			    (VM_FLAGS_FIXED |
			    VM_FLAGS_ANYWHERE |
			    VM_FLAGS_OVERWRITE |
			    VM_FLAGS_RETURN_4K_DATA_ADDR |
			    VM_FLAGS_RETURN_DATA_ADDR));

			/* reserve a contiguous range */
			kr = vm_map_enter(target_map,
			    &map_addr,
			    vm_map_round_page(target_size, map_mask),
			    mask,
			    rsv_flags,
			    VM_OBJECT_NULL,
			    0,
			    FALSE,               /* copy */
			    cur_protection,
			    max_protection,
			    inheritance);
			if (kr != KERN_SUCCESS) {
				DEBUG4K_ERROR("kr 0x%x\n", kr);
				if (target_copy_map != copy_map) {
					vm_map_copy_discard(target_copy_map);
					target_copy_map = VM_MAP_COPY_NULL;
				}
				named_entry_unlock(named_entry);
				vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, kr);
				return kr;
			}

			copy_addr = map_addr;

			for (copy_entry = vm_map_copy_first_entry(target_copy_map);
			    copy_entry != vm_map_copy_to_entry(target_copy_map);
			    copy_entry = copy_entry->vme_next) {
				vm_map_t                copy_submap = VM_MAP_NULL;
				vm_object_t             copy_object = VM_OBJECT_NULL;
				vm_map_size_t           copy_size;
				vm_object_offset_t      copy_offset;
				boolean_t               do_copy = false;

				if (copy_entry->is_sub_map) {
					copy_submap = VME_SUBMAP(copy_entry);
					copy_object = (vm_object_t)copy_submap;
				} else {
					copy_object = VME_OBJECT(copy_entry);
				}

				if (copy_object) {
					do_copy = copy || copy_entry->needs_copy;
				}

				copy_offset = VME_OFFSET(copy_entry);
				copy_size = (copy_entry->vme_end -
				    copy_entry->vme_start);

				/* sanity check */
				if ((copy_addr + copy_size) >
				    (map_addr + target_size)) {
					/* over-mapping too much !? */
					kr = KERN_INVALID_ARGUMENT;
					DEBUG4K_ERROR("kr 0x%x\n", kr);
					/* abort */
					break;
				}

				/* take a reference on the object */
				if (copy_entry->is_sub_map) {
					vm_map_reference(copy_submap);
				} else {
					if (!copy && copy_object != VM_OBJECT_NULL) {
						if (copy_object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
							bool is_writable;

							/*
							 * We need to resolve our side of this
							 * "symmetric" copy-on-write now; we
							 * need a new object to map and share,
							 * instead of the current one which
							 * might still be shared with the
							 * original mapping.
							 *
							 * Note: A "vm_map_copy_t" does not
							 * have a lock but we're protected by
							 * the named entry's lock here.
							 */
							if (!copy_object->shadowed) {
								vm_object_lock(copy_object);
								VM_OBJECT_SET_SHADOWED(copy_object, TRUE);
								vm_object_unlock(copy_object);
							}
							VME_OBJECT_SHADOW(copy_entry, copy_size, TRUE);
							assert(copy_object != VME_OBJECT(copy_entry));
							is_writable = false;
							if (copy_entry->protection & VM_PROT_WRITE) {
								is_writable = true;
#if __arm64e__
							} else if (copy_entry->used_for_tpro) {
								is_writable = true;
#endif /* __arm64e__ */
							}
							if (!copy_entry->needs_copy && is_writable) {
								vm_prot_t prot;

								prot = copy_entry->protection & ~VM_PROT_WRITE;
								vm_object_pmap_protect(copy_object,
								    copy_offset,
								    copy_size,
								    PMAP_NULL,
								    PAGE_SIZE,
								    0,
								    prot);
							}
							copy_entry->needs_copy = FALSE;
							do_copy = FALSE;
							copy_entry->is_shared = TRUE;
							copy_object = VME_OBJECT(copy_entry);
							copy_offset = VME_OFFSET(copy_entry);
							vm_object_lock(copy_object);
							/* we're about to make a shared mapping of this object */
							copy_object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
							VM_OBJECT_SET_TRUE_SHARE(copy_object, TRUE);
						} else {
							vm_object_lock(copy_object);
						}
						vm_object_mark_shared(copy_object, VM_SHARE_TYPE_PERMANENT);
						vm_object_unlock(copy_object);
					}

					if (copy_object != VM_OBJECT_NULL &&
					    copy_object->named &&
					    copy_object->pager != MEMORY_OBJECT_NULL &&
					    copy_object->copy_strategy != MEMORY_OBJECT_COPY_NONE) {
						memory_object_t pager;
						vm_prot_t       pager_prot;

						/*
						 * For "named" VM objects, let the pager know that the
						 * memory object is being mapped.  Some pagers need to keep
						 * track of this, to know when they can reclaim the memory
						 * object, for example.
						 * VM calls memory_object_map() for each mapping (specifying
						 * the protection of each mapping) and calls
						 * memory_object_last_unmap() when all the mappings are gone.
						 */
						pager_prot = max_protection;
						if (copy) {
							/*
							 * Copy-On-Write mapping: won't modify the
							 * memory object.
							 */
							pager_prot &= ~VM_PROT_WRITE;
						}
						vm_object_lock(copy_object);
						pager = copy_object->pager;
						if (copy_object->named &&
						    pager != MEMORY_OBJECT_NULL &&
						    copy_object->copy_strategy != MEMORY_OBJECT_COPY_NONE) {
							assert(copy_object->pager_ready);
							vm_object_mapping_wait(copy_object, THREAD_UNINT);
							/*
							 * Object might have lost its pager
							 * while waiting.
							 */
							pager = copy_object->pager;
							if (copy_object->named &&
							    pager != MEMORY_OBJECT_NULL) {
								vm_object_mapping_begin(copy_object);
								vm_object_unlock(copy_object);

								kr = memory_object_map(pager, pager_prot);
								assert(kr == KERN_SUCCESS);

								vm_object_lock(copy_object);
								vm_object_mapping_end(copy_object);
							}
						}
						vm_object_unlock(copy_object);
					}

					/*
					 *	Perform the copy if requested
					 */

					if (copy && copy_object != VM_OBJECT_NULL) {
						vm_object_t             new_object;
						vm_object_offset_t      new_offset;

						result = vm_object_copy_strategically(copy_object, copy_offset,
						    copy_size,
						    false,                                   /* forking */
						    &new_object, &new_offset,
						    &do_copy);


						if (result == KERN_MEMORY_RESTART_COPY) {
							boolean_t success;
							boolean_t src_needs_copy;

							/*
							 * XXX
							 * We currently ignore src_needs_copy.
							 * This really is the issue of how to make
							 * MEMORY_OBJECT_COPY_SYMMETRIC safe for
							 * non-kernel users to use. Solution forthcoming.
							 * In the meantime, since we don't allow non-kernel
							 * memory managers to specify symmetric copy,
							 * we won't run into problems here.
							 */
							new_object = copy_object;
							new_offset = copy_offset;
							success = vm_object_copy_quickly(new_object,
							    new_offset,
							    copy_size,
							    &src_needs_copy,
							    &do_copy);
							assert(success);
							result = KERN_SUCCESS;
						}
						if (result != KERN_SUCCESS) {
							kr = result;
							break;
						}

						copy_object = new_object;
						copy_offset = new_offset;
						/*
						 * No extra object reference for the mapping:
						 * the mapping should be the only thing keeping
						 * this new object alive.
						 */
					} else {
						/*
						 * We already have the right object
						 * to map.
						 */
						copy_object = VME_OBJECT(copy_entry);
						copy_offset = VME_OFFSET(copy_entry);
						/* take an extra ref for the mapping below */
						vm_object_reference(copy_object);
					}
				}

				/*
				 * If the caller does not want a specific
				 * tag for this new mapping:  use
				 * the tag of the original mapping.
				 */
				vm_map_kernel_flags_t vmk_remap_flags = {
					.vmkf_submap = copy_entry->is_sub_map,
				};

				vm_map_kernel_flags_set_vmflags(&vmk_remap_flags,
				    vm_map_kernel_flags_vmflags(vmk_flags),
				    vmk_flags.vm_tag ?: VME_ALIAS(copy_entry));

				/* over-map the object into destination */
				vmk_remap_flags.vmf_fixed = true;
				vmk_remap_flags.vmf_overwrite = true;

				if (!copy && !copy_entry->is_sub_map) {
					/*
					 * copy-on-write should have been
					 * resolved at this point, or we would
					 * end up sharing instead of copying.
					 */
					assert(!copy_entry->needs_copy);
				}
#if XNU_TARGET_OS_OSX
				if (copy_entry->used_for_jit) {
					vmk_remap_flags.vmkf_map_jit = TRUE;
				}
#endif /* XNU_TARGET_OS_OSX */

				/*
				 * vm_object_copy_strategically() could set do_copy to FALSE, so let's use
				 * this info while deciding "copy" in vm_map_enter().
				 */
				kr = vm_map_enter(target_map,
				    &copy_addr,
				    copy_size,
				    (vm_map_offset_t) 0,
				    vmk_remap_flags,
				    copy_object,
				    copy_offset,
				    do_copy,
				    cur_protection,
				    max_protection,
				    inheritance);
				if (kr != KERN_SUCCESS) {
					DEBUG4K_SHARE("failed kr 0x%x\n", kr);
					if (copy_entry->is_sub_map) {
						vm_map_deallocate(copy_submap);
					} else {
						vm_object_deallocate(copy_object);
					}
					/* abort */
					break;
				}

				/* next mapping */
				copy_addr += copy_size;
			}

			named_entry_unlock(named_entry);
			if (target_copy_map != copy_map) {
				vm_map_copy_discard(target_copy_map);
				target_copy_map = VM_MAP_COPY_NULL;
			}

			if (kr == KERN_SUCCESS) {
				if (overmap_start) {
					DEBUG4K_SHARE("map %p map_addr 0x%llx offset_in_mapping 0x%llx overmap_start 0x%llx -> *address 0x%llx\n", target_map, (uint64_t)map_addr, (uint64_t)offset_in_mapping, (uint64_t)overmap_start, (uint64_t)(map_addr + offset_in_mapping + overmap_start));
				}
				offset_in_mapping += overmap_start;
			} else if (!vmk_flags.vmf_overwrite) {
				/* deallocate the contiguous range */
				vm_map_remove(target_map, map_addr,
				    map_addr + map_size);
			}
			result = kr;
			goto out;
		}

		if (named_entry->is_object) {
			unsigned int    access;
			uint8_t         wimg_mode;

			assert(!named_entry->is_copy);
			assert(!named_entry->is_sub_map);

			/* we are mapping a VM object */

			access = named_entry->access;

			if (vmk_flags.vmf_return_data_addr ||
			    vmk_flags.vmf_return_4k_data_addr) {
				offset_in_mapping = obj_offs & map_mask;
				if (vmk_flags.vmf_return_4k_data_addr) {
					offset_in_mapping &= ~((signed)(0xFFF));
				}
				obj_offs -= offset_in_mapping;
				map_size  = vm_map_round_page(initial_size +
				    offset_in_mapping, map_mask);
			}

			object = vm_named_entry_to_vm_object(named_entry);
			assert(object != VM_OBJECT_NULL);
			vm_object_lock(object);
			named_entry_unlock(named_entry);

			wimg_mode = object->wimg_bits;
			vm_prot_to_wimg(access, &wimg_mode);
			if (object->wimg_bits != wimg_mode) {
#if HAS_MTE
				if (vm_object_is_mte_mappable(object)) {
					vm_object_unlock(object);
					result = KERN_INVALID_ARGUMENT;
					goto out;
				}
#endif /* HAS_MTE */
				vm_object_change_wimg_mode(object, wimg_mode);
			}

			vm_object_reference_locked(object);
			vm_object_unlock(object);
		} else {
			panic("invalid VM named entry %p", named_entry);
		}
	} else if (ip_type(port) == IKOT_MEMORY_OBJECT) {
		/*
		 * JMM - This is temporary until we unify named entries
		 * and raw memory objects.
		 *
		 * Detected fake object type for a memory object.  In
		 * this case, the port isn't really a port at all, but
		 * instead is just a raw memory object.
		 */
		if (vmk_flags.vmf_return_data_addr ||
		    vmk_flags.vmf_return_4k_data_addr) {
			panic("VM_FLAGS_RETURN_DATA_ADDR not expected for raw memory object.");
		}

		object = memory_object_to_vm_object((memory_object_t)port);
		if (object == VM_OBJECT_NULL) {
			vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, KERN_INVALID_OBJECT);
			return KERN_INVALID_OBJECT;
		}
		vm_object_reference(object);

		/* wait for object (if any) to be ready */
		if (object != VM_OBJECT_NULL) {
			if (is_kernel_object(object)) {
				printf("Warning: Attempt to map kernel object"
				    " by a non-private kernel entity\n");
				vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, KERN_INVALID_OBJECT);
				return KERN_INVALID_OBJECT;
			}
			if (!object->pager_ready) {
				vm_object_lock(object);

				while (!object->pager_ready) {
					vm_object_sleep(object,
					    VM_OBJECT_EVENT_PAGER_READY,
					    THREAD_UNINT,
					    LCK_SLEEP_EXCLUSIVE);
				}
				vm_object_unlock(object);
			}
		}
	} else {
		vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, KERN_INVALID_OBJECT);
		return KERN_INVALID_OBJECT;
	}

	if (object != VM_OBJECT_NULL &&
	    object->named &&
	    object->pager != MEMORY_OBJECT_NULL &&
	    object->copy_strategy != MEMORY_OBJECT_COPY_NONE) {
		memory_object_t pager;
		vm_prot_t       pager_prot;
		kern_return_t   kr;

		/*
		 * For "named" VM objects, let the pager know that the
		 * memory object is being mapped.  Some pagers need to keep
		 * track of this, to know when they can reclaim the memory
		 * object, for example.
		 * VM calls memory_object_map() for each mapping (specifying
		 * the protection of each mapping) and calls
		 * memory_object_last_unmap() when all the mappings are gone.
		 */
		pager_prot = max_protection;
		if (copy) {
			/*
			 * Copy-On-Write mapping: won't modify the
			 * memory object.
			 */
			pager_prot &= ~VM_PROT_WRITE;
		}
		vm_object_lock(object);
		pager = object->pager;
		if (object->named &&
		    pager != MEMORY_OBJECT_NULL &&
		    object->copy_strategy != MEMORY_OBJECT_COPY_NONE) {
			assert(object->pager_ready);
			vm_object_mapping_wait(object, THREAD_UNINT);
			/* object might have lost its pager while waiting */
			pager = object->pager;
			if (object->named && pager != MEMORY_OBJECT_NULL) {
				vm_object_mapping_begin(object);
				vm_object_unlock(object);

				kr = memory_object_map(pager, pager_prot);
				assert(kr == KERN_SUCCESS);

				vm_object_lock(object);
				vm_object_mapping_end(object);
			}
		}
		vm_object_unlock(object);
	}

	/*
	 *	Perform the copy if requested
	 */

	if (copy) {
		vm_object_t             new_object;
		vm_object_offset_t      new_offset;

		result = vm_object_copy_strategically(object,
		    obj_offs,
		    map_size,
		    false,                                   /* forking */
		    &new_object, &new_offset,
		    &copy);


		if (result == KERN_MEMORY_RESTART_COPY) {
			boolean_t success;
			boolean_t src_needs_copy;

			/*
			 * XXX
			 * We currently ignore src_needs_copy.
			 * This really is the issue of how to make
			 * MEMORY_OBJECT_COPY_SYMMETRIC safe for
			 * non-kernel users to use. Solution forthcoming.
			 * In the meantime, since we don't allow non-kernel
			 * memory managers to specify symmetric copy,
			 * we won't run into problems here.
			 */
			new_object = object;
			new_offset = obj_offs;
			success = vm_object_copy_quickly(new_object,
			    new_offset,
			    map_size,
			    &src_needs_copy,
			    &copy);
			assert(success);
			result = KERN_SUCCESS;
		}
		/*
		 *	Throw away the reference to the
		 *	original object, as it won't be mapped.
		 */

		vm_object_deallocate(object);

		if (result != KERN_SUCCESS) {
			vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, result);
			return result;
		}

		object   = new_object;
		obj_offs = new_offset;
	}

	/*
	 * If non-kernel users want to try to prefault pages, the mapping and prefault
	 * needs to be atomic.
	 */
	kernel_prefault = (try_prefault && vm_kernel_map_is_kernel(target_map));
	vmk_flags.vmkf_keep_map_ilocked = (try_prefault && !kernel_prefault);

	if (try_prefault) {
		/* take an extra reference to keep object alive during "prefault" */
		vm_object_reference(object);
	}

	result = vm_map_enter(target_map,
	    &map_addr, map_size,
	    (vm_map_offset_t)mask,
	    vmk_flags,
	    object, obj_offs,
	    copy,
	    cur_protection, max_protection,
	    inheritance);
	if (result != KERN_SUCCESS) {
		vm_object_deallocate(object);
	}

	/*
	 * Try to prefault, and do not forget to release the map interlock.
	 */
	if (result == KERN_SUCCESS && try_prefault) {
		mach_vm_address_t va = map_addr;
		vm_object_offset_t page_offset;
		kern_return_t kr = KERN_SUCCESS;
		unsigned int i = 0;
		int pmap_options;

		pmap_options = kernel_prefault ? 0 : PMAP_OPTIONS_NOWAIT;

		vm_object_lock(object);
		page_offset = obj_offs;
		for (i = 0; i < page_list_count; ++i) {
			if (!UPL_VALID_PAGE(page_list, i)) {
				if (kernel_prefault) {
					assertf(FALSE, "kernel_prefault && !UPL_VALID_PAGE");
					result = KERN_MEMORY_ERROR;
					break;
				}
			} else {
				if (object->phys_contiguous) {
					/* no VM page to look up... */
				} else {
					vm_page_t p;

					p = vm_page_lookup(object, page_offset);
					assertf(p, "offset 0x%llx: no VM page", page_offset);
					if (p == VM_PAGE_NULL) {
						/*
						 * No VM page , so nothing to prefault.
						 * Note that this should not happen if
						 * we really had the page in the UPL,
						 * so let's give up on prefaulting...
						 */
						vm_prefault_nb_no_page++;
						break;
					} else if (VM_PAGE_GET_PHYS_PAGE(p) !=
					    UPL_PHYS_PAGE(page_list, i)) {
						/*
						 * Different physical page; that should
						 * also not happen, so let's give up...
						 */
						assertf(VM_PAGE_GET_PHYS_PAGE(p) == UPL_PHYS_PAGE(page_list, i),
						    "offset 0x%llx: page %p phys 0x%x != 0x%x\n",
						    page_offset, p,
						    VM_PAGE_GET_PHYS_PAGE(p),
						    UPL_PHYS_PAGE(page_list, i));
						vm_prefault_nb_wrong_page++;
						break;
					} else {
						/*
						 * Register that this VM page was pmapped,
						 * so that we know to clean up its pmap
						 * mappings if we end up reclaiming it
						 * before this mapping goes away...
						 */
						if (!p->vmp_pmapped) {
							p->vmp_pmapped = true;
						}
					}
				}
				/*
				 * If this function call failed, we should stop
				 * trying to optimize, other calls are likely
				 * going to fail too.
				 *
				 * We are not gonna report an error for such
				 * failure though. That's an optimization, not
				 * something critical.
				 */
				kr = pmap_enter_object_options_check(target_map->pmap,
				    va, 0, object, UPL_PHYS_PAGE(page_list, i),
				    cur_protection, VM_PROT_NONE,
				    TRUE, pmap_options);
				if (kr != KERN_SUCCESS) {
					OSIncrementAtomic64(&vm_prefault_nb_bailout);
					if (kernel_prefault) {
						result = kr;
					}
					break;
				}
				OSIncrementAtomic64(&vm_prefault_nb_pages);
			}

			/* Next virtual address */
			va += PAGE_SIZE;
			page_offset += PAGE_SIZE;
		}
		vm_object_unlock(object);
		if (vmk_flags.vmkf_keep_map_ilocked) {
			vm_map_ilk_unlock(target_map);
		}
	}

	if (try_prefault) {
		/* release our extra "prefault" reference */
		vm_object_deallocate(object);
	}

out:
	if (result == KERN_SUCCESS) {
#if KASAN
		if (target_map->pmap == kernel_pmap) {
			kasan_notify_address(map_addr, map_size);
		}
#endif
		*address_u = vm_sanitize_wrap_addr(map_addr + offset_in_mapping);
		vmlp_range_event(target_map, map_addr, map_size);
	}
	vmlp_api_end(VM_MAP_ENTER_MEM_OBJECT, result);
	return result;
}

kern_return_t
vm_map_enter_mem_object_prefault(
	vm_map_t                target_map,
	vm_map_offset_ut       *address,
	vm_map_size_ut          initial_size,
	vm_map_offset_ut        mask,
	vm_map_kernel_flags_t   vmk_flags,
	ipc_port_t              port,
	vm_object_offset_ut     offset,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	upl_page_list_ptr_t     page_list,
	unsigned int            page_list_count)
{
	/* range_id is set by vm_map_enter_mem_object */
	return vm_map_enter_mem_object(target_map,
	           address,
	           initial_size,
	           mask,
	           vmk_flags,
	           port,
	           offset,
	           FALSE,
	           cur_protection,
	           max_protection,
	           VM_INHERIT_DEFAULT,
	           page_list,
	           page_list_count);
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_enter_mem_object_control_sanitize(
	vm_map_t                target_map,
	vm_map_offset_ut        address_u,
	vm_map_size_ut          initial_size_u,
	vm_map_offset_ut        mask_u,
	vm_object_offset_ut     offset_u,
	vm_prot_ut              cur_protection_u,
	vm_prot_ut              max_protection_u,
	vm_inherit_ut           inheritance_u,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_address_t       *map_addr,
	vm_map_size_t          *map_size,
	vm_map_offset_t        *mask,
	vm_object_offset_t     *obj_offs,
	vm_object_offset_t     *obj_end,
	vm_object_size_t       *obj_size,
	vm_prot_t              *cur_protection,
	vm_prot_t              *max_protection,
	vm_inherit_t           *inheritance)
{
	kern_return_t           kr;

	kr = vm_sanitize_cur_and_max_prots(cur_protection_u, max_protection_u,
	    VM_SANITIZE_CALLER_ENTER_MEM_OBJ_CTL, target_map,
	    cur_protection, max_protection);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	kr = vm_sanitize_inherit(inheritance_u, VM_SANITIZE_CALLER_ENTER_MEM_OBJ_CTL,
	    inheritance);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	kr = vm_sanitize_mask(mask_u, VM_SANITIZE_CALLER_ENTER_MEM_OBJ_CTL, mask);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}
	/*
	 * Ensure arithmetic doesn't overflow in vm_object space (kernel
	 * pages).
	 * We keep unaligned values for now. The call we eventually make to
	 * vm_map_enter does guarantee that offset_u is page aligned for EITHER
	 * target_map pages or kernel pages. But this isn't enough to guarantee
	 * kernel space alignment.
	 */
	kr = vm_sanitize_addr_size(offset_u, initial_size_u,
	    VM_SANITIZE_CALLER_ENTER_MEM_OBJ_CTL, PAGE_MASK,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS |
	    VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES,
	    obj_offs, obj_end, obj_size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	/*
	 * There is no vm_sanitize_addr_size variant that also adjusts for
	 * a separate offset. Rather than create one for this one-off issue,
	 * we sanitize map_addr and map_size individually, relying on
	 * vm_sanitize_size to incorporate the offset. Then, we perform the
	 * overflow check manually below.
	 */
	*map_addr = vm_sanitize_addr(target_map, address_u);
	kr = vm_sanitize_size(offset_u, initial_size_u,
	    VM_SANITIZE_CALLER_ENTER_MEM_OBJ_CTL, target_map,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS, map_size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	/*
	 * Ensure arithmetic doesn't overflow in target_map space.
	 * The computation of map_size above accounts for the possibility that
	 * offset_u might be unaligned in target_map space.
	 */
	if (vmk_flags.vmf_fixed) {
		vm_map_address_t map_end;

		if (__improbable(os_add_overflow(*map_addr, *map_size, &map_end))) {
			return KERN_INVALID_ARGUMENT;
		}
	}

	return KERN_SUCCESS;
}

kern_return_t
vm_map_enter_mem_object_control(
	vm_map_t                target_map,
	vm_map_offset_ut       *address_u,
	vm_map_size_ut          initial_size_u,
	vm_map_offset_ut        mask_u,
	vm_map_kernel_flags_t   vmk_flags,
	memory_object_control_t control,
	vm_object_offset_ut     offset_u,
	boolean_t               needs_copy,
	vm_prot_ut              cur_protection_u,
	vm_prot_ut              max_protection_u,
	vm_inherit_ut           inheritance_u)
{
	vm_map_offset_t         mask;
	vm_prot_t               cur_protection;
	vm_prot_t               max_protection;
	vm_inherit_t            inheritance;
	vm_map_address_t        map_addr;
	vm_map_size_t           map_size;
	vm_object_t             object;
	vm_object_offset_t      obj_offs, obj_end;
	vm_object_size_t        obj_size;
	kern_return_t           result;
	memory_object_t         pager;
	vm_prot_t               pager_prot;
	kern_return_t           kr;

	/*
	 * Check arguments for validity
	 */
	if (target_map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * We only support vmf_return_data_addr-like behavior.
	 */
	vmk_flags.vmf_return_data_addr = true;

	/*
	 * Sanitize any input parameters that are addr/size/prot/inherit
	 */
	kr = vm_map_enter_mem_object_control_sanitize(target_map,
	    *address_u,
	    initial_size_u,
	    mask_u,
	    offset_u,
	    cur_protection_u,
	    max_protection_u,
	    inheritance_u,
	    vmk_flags,
	    &map_addr,
	    &map_size,
	    &mask,
	    &obj_offs,
	    &obj_end,
	    &obj_size,
	    &cur_protection,
	    &max_protection,
	    &inheritance);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	object = memory_object_control_to_vm_object(control);

	if (object == VM_OBJECT_NULL) {
		return KERN_INVALID_OBJECT;
	}

	if (is_kernel_object(object)) {
		printf("Warning: Attempt to map kernel object"
		    " by a non-private kernel entity\n");
		return KERN_INVALID_OBJECT;
	}

	vm_object_lock(object);
	os_ref_retain_locked_raw(&object->ref_count, &vm_object_refgrp);


	/*
	 * For "named" VM objects, let the pager know that the
	 * memory object is being mapped.  Some pagers need to keep
	 * track of this, to know when they can reclaim the memory
	 * object, for example.
	 * VM calls memory_object_map() for each mapping (specifying
	 * the protection of each mapping) and calls
	 * memory_object_last_unmap() when all the mappings are gone.
	 */
	pager_prot = max_protection;
	if (needs_copy) {
		pager_prot &= ~VM_PROT_WRITE;
	}
	pager = object->pager;
	if (object->named &&
	    pager != MEMORY_OBJECT_NULL &&
	    object->copy_strategy != MEMORY_OBJECT_COPY_NONE) {
		assert(object->pager_ready);
		vm_object_mapping_wait(object, THREAD_UNINT);
		/* object might have lost its pager while waiting */
		pager = object->pager;
		if (object->named && pager != MEMORY_OBJECT_NULL) {
			vm_object_mapping_begin(object);
			vm_object_unlock(object);

			kr = memory_object_map(pager, pager_prot);
			assert(kr == KERN_SUCCESS);

			vm_object_lock(object);
			vm_object_mapping_end(object);
		}
	}
	vm_object_unlock(object);

	/*
	 *	Perform the copy if requested
	 */

	if (needs_copy) {
		vm_object_t             new_object;
		vm_object_offset_t      new_offset;

		result = vm_object_copy_strategically(object, obj_offs, obj_size,
		    false,                                   /* forking */
		    &new_object, &new_offset,
		    &needs_copy);


		if (result == KERN_MEMORY_RESTART_COPY) {
			boolean_t success;
			boolean_t src_needs_copy;

			/*
			 * XXX
			 * We currently ignore src_needs_copy.
			 * This really is the issue of how to make
			 * MEMORY_OBJECT_COPY_SYMMETRIC safe for
			 * non-kernel users to use. Solution forthcoming.
			 * In the meantime, since we don't allow non-kernel
			 * memory managers to specify symmetric copy,
			 * we won't run into problems here.
			 */
			new_object = object;
			new_offset = obj_offs;
			success = vm_object_copy_quickly(new_object,
			    new_offset, obj_size,
			    &src_needs_copy,
			    &needs_copy);
			assert(success);
			result = KERN_SUCCESS;
		}
		/*
		 *	Throw away the reference to the
		 *	original object, as it won't be mapped.
		 */

		vm_object_deallocate(object);

		if (result != KERN_SUCCESS) {
			return result;
		}

		object   = new_object;
		obj_offs = new_offset;
	}

	result = vm_map_enter(target_map,
	    &map_addr, map_size,
	    (vm_map_offset_t)mask,
	    vmk_flags,
	    object,
	    obj_offs,
	    needs_copy,
	    cur_protection, max_protection,
	    inheritance);

	if (result == KERN_SUCCESS) {
		*address_u = vm_sanitize_wrap_addr(
			map_addr + (obj_offs & vm_map_page_mask(target_map)));
	} else {
		vm_object_deallocate(object);
	}

	return result;
}

/*
 *	VM_MAP_CLAMP_TO_MAP_BOUNDS:	[ internal use only ]
 *
 *	Clamp the starting and ending region to
 *	addresses fall within the valid range of the map.
 */
#define VM_MAP_CLAMP_TO_MAP_BOUNDS(map, start, end)     \
	MACRO_BEGIN                             \
	if (start < vm_map_min(map))            \
	        start = vm_map_min(map);        \
	if (end > vm_map_max(map))              \
	        end = vm_map_max(map);          \
	if (start > end)                        \
	        start = end;                    \
	MACRO_END


static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_protect_sanitize(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              new_prot_u,
	vm_map_offset_t        *start,
	vm_map_offset_t        *end,
	vm_prot_t              *new_prot)
{
	kern_return_t           kr;
	vm_map_size_t           size;

#if CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS
	kr = vm_sanitize_canonicalize_ut_addr_end(
		map,
		&start_u,
		&end_u);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}
#endif /* CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS */

	kr = vm_sanitize_prot(new_prot_u, VM_SANITIZE_CALLER_VM_MAP_PROTECT,
	    map, VM_PROT_COPY, new_prot);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	kr = vm_sanitize_addr_end(start_u, end_u, VM_SANITIZE_CALLER_VM_MAP_PROTECT,
	    map, VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS, start, end, &size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	return KERN_SUCCESS;
}

/*
 * Run the preflight for vm_map_protect. This function is responsible for making
 * sure an entry is valid to change the protections to *new_prot_p.
 *
 * It primarily checks entry protections being enough to do so, some jit checks,
 * tpro checks, and has codesigning checks.
 *
 * Due to legacy behavior, this function may actually MODIFY the value in
 * *new_prot_p. This is unintuitive, but is consistent with past behavior.
 */
static kern_return_t
vm_map_protect_preflight(
	vm_map_lock_ctx_t       vctx,
	vm_map_entry_t          entry,
	bool                    set_max,
	vm_prot_t              *const new_prot_p)
{
	vm_map_t map = vctx->vmlc_map;
	vm_prot_t new_prot = *new_prot_p;
	vm_prot_t new_max = entry->max_protection;

#if defined(__x86_64__)
	/* Allow max mask to include execute prot bits if this map doesn't enforce CS */
	if (set_max && (new_prot & VM_PROT_ALLEXEC) && !vm_map_cs_enforcement(map)) {
		new_max = (new_max & ~VM_PROT_ALLEXEC) | (new_prot & VM_PROT_ALLEXEC);
	}
#elif CODE_SIGNING_MONITOR
	if (set_max && (new_prot & VM_PROT_EXECUTE) && (csm_address_space_exempt(map->pmap) == KERN_SUCCESS)) {
		new_max |= VM_PROT_EXECUTE;
	}
#else
	(void) set_max;
#endif
	if ((new_prot & new_max) != new_prot) {
		return KERN_PROTECTION_FAILURE;
	}

	if (entry->used_for_jit &&
	    pmap_has_prot_policy(map->pmap, entry->translated_allow_execute, entry->protection)) {
		return KERN_PROTECTION_FAILURE;
	}

#if __arm64e__
	/* Disallow protecting hw assisted TPRO mappings */
	if (entry->used_for_tpro) {
		return KERN_PROTECTION_FAILURE;
	}
#endif /* __arm64e__ */

	if ((new_prot & VM_PROT_WRITE) &&
	    (new_prot & VM_PROT_ALLEXEC) &&
#if XNU_TARGET_OS_OSX
	    map->pmap != kernel_pmap &&
	    (vm_map_cs_enforcement(map)
#if __arm64__
	    || !VM_MAP_IS_EXOTIC(map)
#endif /* __arm64__ */
	    ) &&
#endif /* XNU_TARGET_OS_OSX */
#if CODE_SIGNING_MONITOR
	    (csm_address_space_exempt(map->pmap) != KERN_SUCCESS) &&
#endif
	    !(entry->used_for_jit)) {
		DTRACE_VM3(cs_wx,
		    uint64_t, (uint64_t) entry->vme_start,
		    uint64_t, (uint64_t) entry->vme_end,
		    vm_prot_t, new_prot);
		printf("CODE SIGNING: %d[%s] %s:%d(0x%llx,0x%llx,0x%x) can't have both write and exec at the same time\n",
		    proc_selfpid(),
		    (get_bsdtask_info(current_task())
		    ? proc_name_address(get_bsdtask_info(current_task()))
		    : "?"),
		    __FUNCTION__, __LINE__,
#if DEVELOPMENT || DEBUG
		    (uint64_t)entry->vme_start,
		    (uint64_t)entry->vme_end,
#else /* DEVELOPMENT || DEBUG */
		    (uint64_t)0,
		    (uint64_t)0,
#endif /* DEVELOPMENT || DEBUG */
		    new_prot);
		new_prot &= ~VM_PROT_ALLEXEC;
		*new_prot_p = new_prot;
		if (VM_MAP_POLICY_WX_FAIL(map)) {
			return KERN_PROTECTION_FAILURE;
		}
	}

	/*
	 * If the task has requested executable lockdown,
	 * deny both:
	 * - adding executable protections OR
	 * - adding write protections to an existing executable mapping.
	 */
	if (map->map_disallow_new_exec == TRUE) {
		if ((new_prot & VM_PROT_ALLEXEC) ||
		    ((entry->protection & VM_PROT_EXECUTE) && (new_prot & VM_PROT_WRITE))) {
			return KERN_PROTECTION_FAILURE;
		}
	}
	return KERN_SUCCESS;
}

/*
 *	vm_map_protect:
 *
 *	Sets the protection of the specified address
 *	region in the target map.  If "set_max" is
 *	specified, the maximum protection is to be set;
 *	otherwise, only the current protection is affected.
 */
kern_return_t
vm_map_protect(
	vm_map_t                original_map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	boolean_t               set_max,
	vm_prot_ut              new_prot_u)
{
	vm_map_entry_t                  entry;
	__block vm_prot_t               new_prot;
	int                             pmap_options = 0;
	kern_return_t                   kr;
	vm_map_offset_t                 start;
	vm_map_offset_t                 end;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_PROTECT);

	kr = vm_map_protect_sanitize(original_map,
	    start_u,
	    end_u,
	    new_prot_u,
	    &start,
	    &end,
	    &new_prot);
	if (__improbable(kr != KERN_SUCCESS)) {
		kr = vm_sanitize_get_kr(kr);
		vmlp_api_end(VM_MAP_PROTECT, kr);
		return kr;
	}

	if (new_prot & VM_PROT_COPY) {
		vm_map_offset_t         new_start;
		vm_prot_t               cur_prot, max_prot;
		vm_map_kernel_flags_t   kflags;

		/* LP64todo - see below */
		if (start >= original_map->max_offset) {
			vmlp_api_end(VM_MAP_PROTECT, KERN_INVALID_ADDRESS);
			return KERN_INVALID_ADDRESS;
		}

		if ((new_prot & VM_PROT_ALLEXEC) &&
		    original_map->pmap != kernel_pmap &&
		    (vm_map_cs_enforcement(original_map)
#if XNU_TARGET_OS_OSX && __arm64__
		    || !VM_MAP_IS_EXOTIC(original_map)
#endif /* XNU_TARGET_OS_OSX && __arm64__ */
		    ) &&
		    VM_MAP_POLICY_WX_FAIL(original_map)) {
			DTRACE_VM3(cs_wx,
			    uint64_t, (uint64_t) start,
			    uint64_t, (uint64_t) end,
			    vm_prot_t, new_prot);
			printf("CODE SIGNING: %d[%s] %s:%d(0x%llx,0x%llx,0x%x) can't have both write and exec at the same time\n",
			    proc_selfpid(),
			    (get_bsdtask_info(current_task())
			    ? proc_name_address(get_bsdtask_info(current_task()))
			    : "?"),
			    __FUNCTION__, __LINE__,
#if DEVELOPMENT || DEBUG
			    (uint64_t)start,
			    (uint64_t)end,
#else /* DEVELOPMENT || DEBUG */
			    (uint64_t)0,
			    (uint64_t)0,
#endif /* DEVELOPMENT || DEBUG */
			    new_prot);
			vmlp_api_end(VM_MAP_PROTECT, KERN_PROTECTION_FAILURE);
			return KERN_PROTECTION_FAILURE;
		}

		/*
		 * Let vm_map_remap_extract() know that it will need to:
		 * + make a copy of the mapping
		 * + add VM_PROT_WRITE to the max protections
		 * + remove any protections that are no longer allowed from the
		 *   max protections (to avoid any WRITE/EXECUTE conflict, for
		 *   example).
		 * Note that "max_prot" is an IN/OUT parameter only for this
		 * specific (VM_PROT_COPY) case.  It's usually an OUT parameter
		 * only (and the resulting value is not used).
		 */
		max_prot = new_prot & (VM_PROT_ALL | VM_PROT_ALLEXEC);
		cur_prot = VM_PROT_NONE;
		kflags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true);
		kflags.vmkf_remap_prot_copy = true;
		kflags.vmkf_tpro_enforcement_override = !vm_map_tpro_enforcement(original_map);
		new_start = start;
		kr = vm_map_remap(original_map,
		    vm_sanitize_wrap_addr_ref(&new_start),
		    end - start,
		    0, /* mask */
		    kflags,
		    original_map,
		    start,
		    TRUE, /* copy-on-write remapping! */
		    vm_sanitize_wrap_prot_ref(&cur_prot), /* IN/OUT */
		    vm_sanitize_wrap_prot_ref(&max_prot), /* IN/OUT */
		    VM_INHERIT_DEFAULT);
		if (kr != KERN_SUCCESS) {
			vmlp_api_end(VM_MAP_PROTECT, kr);
			return kr;
		}
		new_prot &= ~VM_PROT_COPY;
	}

	vmlp_range_event(original_map, start, end - start);

	vm_map_ilk_lock(original_map);

	if (start >= original_map->max_offset) {
		vm_map_ilk_unlock(original_map);
		vmlp_api_end(VM_MAP_PROTECT, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}

	/*
	 *      Lookup the entry.  If it doesn't start in a valid
	 *	entry, return an error.
	 */
	entry = vm_map_lookup(original_map, start);
	if (entry == VM_MAP_ENTRY_NULL) {
		vm_map_ilk_unlock(original_map);
		vmlp_api_end(VM_MAP_PROTECT, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}
	if (entry->superpage_size) {
		if ((start & (SUPERPAGE_SIZE - 1))) { /* extend request to whole entry */
			start = SUPERPAGE_ROUND_DOWN(start);
		}
		end = SUPERPAGE_ROUND_UP(end);
	}

	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
		return vm_map_protect_preflight(vctx, vme, set_max, &new_prot /*in/out*/);
	});

	/*
	 * This does VMRL_EX_NO_MIN_MAX_CHECK and the manual max_offset check (above) to maintain
	 * binary compatibility. That's because previously only the start address
	 * was checked, not the end.
	 */
	kr = vm_map_range_ex_lock(ctx, &original_map, start, end,
	    VMRL_EX_ATOMIC | VMRL_EX_ILK_LOCKED | VMRL_EX_SIMPLIFY | VMRL_EX_NO_MIN_MAX_CHECK);
	if (KERN_SUCCESS != kr) {
		vmlp_api_end(VM_MAP_PROTECT, kr);
		return kr;
	}

	/*
	 *	Preflight passed, fix up the protections
	 */
	while ((entry = vm_map_range_atomic_next(ctx))) {
		/*
		 * No constant submap descent. Transparent submaps are okay.
		 * Then don't use variable `original_map` again inside this
		 * loop because we may be descended into a transparent submap.
		 */
		vm_map_t cur_map = vm_map_lock_ctx_get_map(ctx);
		assert(!vm_map_lock_ctx_in_constant_submap(ctx));

		vm_prot_t       old_prot;
#if DEVELOPMENT || DEBUG
		if (entry->csm_associated && vm_log_xnu_user_debug) {
			printf("FBDP %d[%s] %s(0x%llx,0x%llx,0x%x) on map %p entry %p [0x%llx:0x%llx 0x%x/0x%x] csm_associated\n",
			    proc_selfpid(),
			    (get_bsdtask_info(current_task())
			    ? proc_name_address(get_bsdtask_info(current_task()))
			    : "?"),
			    __FUNCTION__,
			    (uint64_t)start,
			    (uint64_t)end,
			    new_prot,
			    cur_map, entry,
			    entry->vme_start,
			    entry->vme_end,
			    entry->protection,
			    entry->max_protection);
		}
#endif /* DEVELOPMENT || DEBUG */

		if (entry->is_sub_map) {
			/* range lock did unnest if needed */
			assert(!entry->use_pmap);
		}

		old_prot = entry->protection;

		if (set_max) {
			entry->max_protection = new_prot;
			/* Consider either EXECUTE or UEXEC as EXECUTE for this masking */
			entry->protection = (new_prot & old_prot);
		} else {
			entry->protection = new_prot;
		}

#if CODE_SIGNING_MONITOR
		if (/* a !csm_associated mapping becoming executable */
			((!entry->csm_associated &&
			!(old_prot & VM_PROT_EXECUTE) &&
			(entry->protection & VM_PROT_EXECUTE))
			||
			/* a csm_associated mapping becoming writable */
			(entry->csm_associated &&
			!(old_prot & VM_PROT_WRITE) &&
			(entry->protection & VM_PROT_WRITE)))) {
			/*
			 * This mapping has not already been marked as
			 * "user_debug" and it is either:
			 * 1. not code-signing-monitored and becoming executable
			 * 2. code-signing-monitored and becoming writable,
			 * so inform the CodeSigningMonitor and mark the
			 * mapping as "user_debug" if appropriate.
			 */
			vm_map_kernel_flags_t vmk_flags;
			vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
			/* pretend it's a vm_protect(VM_PROT_COPY)... */
			vmk_flags.vmkf_remap_prot_copy = true;
			kr = vm_map_entry_cs_associate(cur_map, entry, vmk_flags);
#if DEVELOPMENT || DEBUG
			if (vm_log_xnu_user_debug) {
				printf("FBDP %d[%s] %s:%d map %p entry %p [ 0x%llx 0x%llx ] prot 0x%x -> 0x%x cs_associate -> %d user_debug=%d\n",
				    proc_selfpid(),
				    (get_bsdtask_info(current_task()) ? proc_name_address(get_bsdtask_info(current_task())) : "?"),
				    __FUNCTION__, __LINE__,
				    cur_map, entry,
				    entry->vme_start, entry->vme_end,
				    old_prot, entry->protection,
				    kr, entry->vme_xnu_user_debug);
			}
#endif /* DEVELOPMENT || DEBUG */
		}
#endif /* CODE_SIGNING_MONITOR */

		/*
		 *	Update physical map if necessary.
		 *	If the request is to turn off write protection,
		 *	we won't do it for real (in pmap). This is because
		 *	it would cause copy-on-write to fail.  We've already
		 *	set, the new protection in the map, so if a
		 *	write-protect fault occurred, it will be fixed up
		 *	properly, COW or not.
		 */
		if (entry->protection != old_prot) {
			/* Look one level in we support nested pmaps */
			/* from mapped submaps which are direct entries */
			/* in our map */

			vm_prot_t prot;

			prot = entry->protection;
			if (entry->is_sub_map || (VME_OBJECT(entry) == NULL) || (VME_OBJECT(entry) != compressor_object)) {
				prot &= ~VM_PROT_WRITE;
			} else {
				assert(!VME_OBJECT(entry)->code_signed);
				assert(VME_OBJECT(entry)->copy_strategy == MEMORY_OBJECT_COPY_NONE);
				if (prot & VM_PROT_WRITE) {
					/*
					 * For write requests on the
					 * compressor, we wil ask the
					 * pmap layer to prevent us from
					 * taking a write fault when we
					 * attempt to access the mapping
					 * next.
					 */
					pmap_options |= PMAP_OPTIONS_PROTECT_IMMEDIATE;
				}
			}

			if (override_nx(cur_map, VME_ALIAS(entry)) && prot) {
				prot |= VM_PROT_EXECUTE;
			}

#if DEVELOPMENT || DEBUG
			if (!(old_prot & VM_PROT_EXECUTE) &&
			    (prot & VM_PROT_EXECUTE) &&
			    panic_on_unsigned_execute &&
			    (proc_selfcsflags() & CS_KILL)) {
				panic("vm_map_protect(%p,0x%llx,0x%llx) old=0x%x new=0x%x - <rdar://23770418> code-signing bypass?", cur_map, (uint64_t)entry->vme_start, (uint64_t)entry->vme_end, old_prot, prot);
			}
#endif /* DEVELOPMENT || DEBUG */

			if (pmap_has_prot_policy(cur_map->pmap, entry->translated_allow_execute, prot)) {
				if (entry->wired_count) {
					panic("vm_map_protect(%p,0x%llx,0x%llx) new=0x%x wired=%x",
					    cur_map, (uint64_t)entry->vme_start, (uint64_t)entry->vme_end, prot, entry->wired_count);
				}

				/* If the pmap layer cares about this
				 * protection type, force a fault for
				 * each page so that vm_fault will
				 * repopulate the page with the full
				 * set of protections.
				 */
				/*
				 * TODO: We don't seem to need this,
				 * but this is due to an internal
				 * implementation detail of
				 * pmap_protect.  Do we want to rely
				 * on this?
				 */
				prot = VM_PROT_NONE;
			}

			if (entry->is_sub_map && entry->use_pmap) {
				pmap_protect(VME_SUBMAP(entry)->pmap,
				    entry->vme_start,
				    entry->vme_end,
				    prot);
			} else {
				pmap_protect_options(cur_map->pmap,
				    entry->vme_start,
				    entry->vme_end,
				    prot,
				    pmap_options,
				    NULL);
			}
		}
	}

	vm_map_range_ex_unlock(ctx, &original_map);

	vmlp_api_end(VM_MAP_PROTECT, KERN_SUCCESS);
	return KERN_SUCCESS;
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_inherit_sanitize(
	vm_map_t                        map,
	vm_map_offset_ut                start_u,
	vm_map_offset_ut                end_u,
	vm_inherit_ut                   new_inheritance_u,
	vm_map_offset_t                *start,
	vm_map_offset_t                *end,
	vm_inherit_t                   *new_inheritance)
{
	kern_return_t   kr;
	vm_map_size_t   size;

	kr = vm_sanitize_inherit(new_inheritance_u,
	    VM_SANITIZE_CALLER_VM_MAP_INHERIT, new_inheritance);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

#if CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS
	kr = vm_sanitize_canonicalize_ut_addr_end(
		map,
		&start_u,
		&end_u);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}
#endif /* CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS */

	kr = vm_sanitize_addr_end(start_u, end_u, VM_SANITIZE_CALLER_VM_MAP_INHERIT,
	    map, VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS, start, end, &size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	return KERN_SUCCESS;
}

/*
 * Note: KERN_INVALID_ADDRESS gets translated to KERN_SUCCESS,
 * so don't add a new case returning that.
 */
static kern_return_t
vm_map_inherit_preflight(
	vm_map_t        map __unused,
	vm_map_entry_t  entry,
	vm_inherit_t    new_inheritance)
{
	if (entry->is_sub_map) {
		if (new_inheritance == VM_INHERIT_COPY) {
			return KERN_INVALID_ARGUMENT;
		}
	}
#if HAS_MTE
	if (new_inheritance == VM_INHERIT_SHARE) {
		if (!entry->is_sub_map && VME_OBJECT(entry) && vm_object_is_mte_mappable(VME_OBJECT(entry))) {
			vm_size_t size = entry->vme_end - entry->vme_start;
			vm_mte_operation_flags_t mte_operation = VM_MTE_OPERATION_TYPE_INHERIT_SHARE;
			mte_operation |= vm_kernel_map_is_kernel(map) ? VM_MTE_OPERATION_DEST_KERNEL : VM_MTE_OPERATION_DEST_USER;
			if (!vm_map_allow_mte_operation(map, entry->vme_start, size, mte_operation, optional_vm_object_none() /* irrelevant here */)) {
				return KERN_NO_ACCESS;
			}
		}
	}
#endif /* HAS_MTE */
	return KERN_SUCCESS;
}

/*
 *	vm_map_inherit:
 *
 *	Sets the inheritance of the specified address
 *	range in the target map.  Inheritance
 *	affects how the map will be shared with
 *	child maps at the time of vm_map_fork.
 */
kern_return_t
vm_map_inherit(
	vm_map_t                        map,
	vm_map_offset_ut                start_u,
	vm_map_offset_ut                end_u,
	vm_inherit_ut                   new_inheritance_u)
{
	vm_map_entry_t  entry;
	kern_return_t   kr;
	vm_map_offset_t start;
	vm_map_offset_t end;
	vm_inherit_t    new_inheritance;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_INHERIT);

	kr = vm_map_inherit_sanitize(map,
	    start_u,
	    end_u,
	    new_inheritance_u,
	    &start,
	    &end,
	    &new_inheritance);
	if (__improbable(kr != KERN_SUCCESS)) {
		kr = vm_sanitize_get_kr(kr);
		vmlp_api_end(VM_MAP_INHERIT, kr);
		return kr;
	}

	VM_MAP_CLAMP_TO_MAP_BOUNDS(map, start, end);
	vmlp_range_event(map, start, end - start);

	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
		kern_return_t ret = vm_map_inherit_preflight(vctx->vmlc_map, vme, new_inheritance);
		assert(ret != KERN_INVALID_ADDRESS); /* translated by upper layer */
		return ret;
	});

	kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_STREAM);

	if (kr != KERN_SUCCESS) {
		if (kr == KERN_INVALID_ADDRESS) {
			/* vm_map_inherit(unmapped range) returns KERN_SUCCESS */
			kr = KERN_SUCCESS;
		}
		vmlp_api_end(VM_MAP_INHERIT, kr);
		return kr;
	}

	while ((entry = vm_map_range_next_with_error(ctx, &kr))) {
		entry->inheritance = new_inheritance;
	}

	vm_map_range_ex_unlock(ctx, &map);
	vmlp_api_end(VM_MAP_INHERIT, kr);
	return kr;
}


/*
 * This function needs the interlock to read a stable value for the map variables
 * user_wire_size and user_wire_limit
 */
static kern_return_t
vm_map_preflight_user_wire_space_ilocked(
	vm_map_t        map,
	vm_map_size_t   size)
{
	if (size + map->user_wire_size > MIN(map->user_wire_limit, vm_per_task_user_wire_limit)) {
		os_atomic_inc(&vm_add_wire_count_over_user_limit, relaxed);
#if DEVELOPMENT || DEBUG
		if (panic_on_mlock_failure) {
			panic("mlock: Over process wire limit. "
			    "%llu bytes wired and requested to wire %llu bytes more",
			    (uint64_t)map->user_wire_size, (uint64_t)size);
		}
#endif /* DEVELOPMENT || DEBUG */
		return KERN_RESOURCE_SHORTAGE;
	}
	return KERN_SUCCESS;
}

static kern_return_t
vm_map_preflight_global_wire_space(
	vm_map_size_t   size)
{
	unsigned int total_wire_count =  vm_page_wire_count + vm_lopage_free_count;
	if (size + ptoa_64(total_wire_count) > vm_global_user_wire_limit) {
#if DEVELOPMENT || DEBUG
		if (panic_on_mlock_failure) {
			panic("mlock: Over global wire limit. "
			    "%llu bytes wired and requested to wire %llu bytes more",
			    ptoa_64(total_wire_count), (uint64_t)size);
		}
#endif /* DEVELOPMENT || DEBUG */
		os_atomic_inc(&vm_add_wire_count_over_global_limit, relaxed);
		return KERN_RESOURCE_SHORTAGE;
	}

	return KERN_SUCCESS;
}

static kern_return_t
vm_map_preflight_wire_space(
	vm_map_t        map,
	vm_map_entry_t  entry,
	bool            user_wire,
	vm_map_size_t   *const size_that_would_be_wired)
{
	if (entry->is_sub_map) {
		/* We don't actually wire submap entries */
		return KERN_SUCCESS;
	}

	if (user_wire && entry->user_wired_count == 0) {
		/*
		 * Since this is the first time the user is wiring this map entry,
		 * check to see if we're exceeding the user wire limits. There is a
		 * per map limit which is the smaller of either the process's rlimit or
		 * the global vm_per_task_user_wire_limit which caps this value.
		 * There is also a system-wide limit on the amount of memory all users
		 * can wire.  If the user is over either limit, then we fail.
		 */

		kern_return_t kr;
		vm_map_size_t entry_wire_size = entry->vme_end - entry->vme_start;
		vm_map_size_t total_wire_size = entry_wire_size + *size_that_would_be_wired;

		vm_map_ilk_lock(map);
		kr = vm_map_preflight_user_wire_space_ilocked(map, total_wire_size);
		vm_map_ilk_unlock(map);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
		kr = vm_map_preflight_global_wire_space(total_wire_size);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
		*size_that_would_be_wired += entry_wire_size;
	}

	return KERN_SUCCESS;
}

/*
 * Update the accounting for the amount of wired memory in this map.  If the user has
 * exceeded the defined limits, then we fail.  Wiring on behalf of the kernel never fails.
 */
static kern_return_t
vm_map_wire_count_add(
	vm_map_t        map,
	vm_map_entry_t  entry,
	bool            user_wire)
{
	kern_return_t kr;
	vm_map_size_t size;

	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	if (user_wire) {
		if (entry->user_wired_count >= MAX_WIRE_COUNT) {
			return KERN_FAILURE;
		}

		if (entry->user_wired_count > 0) {
			assert(entry->wired_count);
			entry->user_wired_count++;
			return KERN_SUCCESS;
		}

		if (entry->wired_count >= MAX_WIRE_COUNT) {
			return KERN_FAILURE;
		}

		size = entry->vme_end - entry->vme_start;

		/*
		 * We need the interlock so that the two concurrent calls to this
		 * function don't ever do concurrent adds to the user_wire_size.
		 * Essentially, the interlock guarantees user_wire_size cannot
		 * increase after we read it in vm_map_preflight_user_wire_space_ilocked.
		 * We do not need to check the global wire limit here because
		 * the pages have already been wired and accounted for in the
		 * global count.
		 */
		vm_map_ilk_lock(map);
		kr = vm_map_preflight_user_wire_space_ilocked(map, size);
		if (kr != KERN_SUCCESS) {
			vm_map_ilk_unlock(map);
			return kr;
		}
		os_atomic_add(&map->user_wire_size, size, relaxed);
		vm_map_ilk_unlock(map);
		entry->user_wired_count++;
	} else if (entry->wired_count >= MAX_WIRE_COUNT) {
		panic("vm_map_wire: too many wirings");
	}
	entry->wired_count++;
	if (entry->wired_count == 1) {
		vme_btref_consider_and_set(entry, __builtin_frame_address(0));
	}

	return KERN_SUCCESS;
}



__abortlike
static void
__vm_map_kunwire_panic(vm_map_t map, vm_map_entry_t entry)
{
	panic("vm_map_unwire(%p, %p): entry is already unwired", map, entry);
}

/*
 * Update the memory wiring accounting now that the given map entry is being unwired.
 */
static bool
vm_map_wire_count_sub(vm_map_t map, vm_map_entry_t entry, bool user_wire)
{
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	if (user_wire) {
		/*
		 * We're unwiring memory at the request of the user.
		 * See if we're removing the last user wire reference.
		 */
		if (entry->user_wired_count == 0) {
			/*
			 * Unwiring region that's already unwired.
			 * Do nothing
			 */
			return false;
		}

		entry->user_wired_count--;
		if (entry->user_wired_count > 0) {
			return false;
		}

		/*
		 * We're removing the last user wire reference.
		 * Decrement the wired_count and the total
		 * user wired memory for this map.
		 */
		assert(map->user_wire_size >= entry->vme_end - entry->vme_start);
		os_atomic_sub(&map->user_wire_size,
		    entry->vme_end - entry->vme_start, relaxed);
	}

	if (entry->wired_count == 0) {
		__vm_map_kunwire_panic(map, entry);
	}

	entry->wired_count--;
	vme_btref_consider_and_put(entry);
	if (entry->wired_count <= 1) {
		/*
		 * Wake up waiters even if the wire count is 1 because of the
		 * VM_MAP_REMOVE_KUNWIRE flag of vm_map_delete that allows a wire
		 * count to be removed there.
		 *
		 * Also wakeup if the wire count is less than one.
		 */
		vm_entry_wakeup_kunwire_waiters(entry);
	}
	return entry->wired_count == 0;
}

int cs_executable_wire = 0;



static kern_return_t
vm_map_wire_preflight(vm_map_lock_ctx_t vctx, vm_map_entry_t entry, vm_prot_t access_type)
{
	__unused vm_map_t map = vctx->vmlc_map;
	bool deny_unnest_executable = true;
	/*
	 * Wiring would copy the pages to the shadow object.
	 * The shadow object would not be code-signed so
	 * attempting to execute code from these copied pages
	 * would trigger a code-signing violation.
	 */
	if ((entry->protection & VM_PROT_EXECUTE)
#if XNU_TARGET_OS_OSX
	    &&
	    map->pmap != kernel_pmap &&
	    (vm_map_cs_enforcement(map)
#if __arm64__
	    || !VM_MAP_IS_EXOTIC(map)
#endif /* __arm64__ */
	    )
#endif /* XNU_TARGET_OS_OSX */
#if CODE_SIGNING_MONITOR
	    &&
	    (csm_address_space_exempt(map->pmap) != KERN_SUCCESS)
#endif
	    ) {
#if MACH_ASSERT
		printf("pid %d[%s] wiring executable range from "
		    "0x%llx to 0x%llx: rejected to preserve "
		    "code-signing\n",
		    proc_selfpid(),
		    (get_bsdtask_info(current_task())
		    ? proc_name_address(get_bsdtask_info(current_task()))
		    : "?"),
		    (uint64_t) entry->vme_start,
		    (uint64_t) entry->vme_end);
#endif /* MACH_ASSERT */
		DTRACE_VM2(cs_executable_wire,
		    uint64_t, (uint64_t)entry->vme_start,
		    uint64_t, (uint64_t)entry->vme_end);
		cs_executable_wire++;
		return KERN_PROTECTION_FAILURE;
	}

	if (entry->is_sub_map &&
	    entry->needs_copy) {
		assert(vm_map_is_sealed(VME_SUBMAP(entry)));
		/* we'll check the permissions of the submap entries below */
	} else if ((entry->protection & access_type) != access_type) {
		if (entry->wired_count == 0) {
			/* Historically this has only been required for the first wiring */
			return KERN_PROTECTION_FAILURE;
		}
	}


#if XNU_TARGET_OS_OSX
	if (map->pmap == kernel_pmap ||
	    !vm_map_cs_enforcement(map)) {
		deny_unnest_executable = false;
	}
#endif /* XNU_TARGET_OS_OSX */
#if CODE_SIGNING_MONITOR
	if (csm_address_space_exempt(map->pmap) == KERN_SUCCESS) {
		deny_unnest_executable = false;
	}
#endif /* CODE_SIGNING_MONITOR */

	if (entry->is_sub_map && entry->needs_copy) {
		vm_map_t submap = VME_SUBMAP(entry);
		vm_map_entry_t submap_entry;
		vm_map_address_t start_addr, end_addr, submap_end, submap_start;

		assert(vm_map_is_sealed(submap));

		vm_map_lock_ctx_bounds(vctx, &start_addr, &end_addr, NULL);
		submap_start = vm_map_lock_ctx_offset_for_address(vctx, start_addr);
		submap_end = vm_map_lock_ctx_offset_for_address(vctx, end_addr);
		submap_entry = vm_map_lookup(submap, submap_start);

		if (submap_entry == VM_MAP_ENTRY_NULL) {
			panic("Unable to find entry in sealed submap");
		}

		while (submap_entry->vme_start < submap_end &&
		    submap_entry != vm_map_to_entry(submap)) {
			if (deny_unnest_executable &&
			    (submap_entry->protection & VM_PROT_EXECUTE)) {
				ktriage_record(thread_tid(current_thread()),
				    KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM,
				    KDBG_TRIAGE_RESERVED,
				    KDBG_TRIAGE_VM_SUBMAP_NO_COW_ON_EXECUTABLE),
				    0 /* arg */);
				DTRACE_VM4(submap_no_copy_executable,
				    vm_map_t, submap,
				    vm_object_offset_t, VME_OFFSET(submap_entry),
				    vm_object_size_t, submap_entry->vme_end - submap_entry->vme_start,
				    int, KERN_PROTECTION_FAILURE);
				return KERN_PROTECTION_FAILURE;
			}

			/* compute expected permissions if we unnest this submap entry */
			vm_prot_t expected_prot;
			expected_prot = entry->protection;
			/* propagate the submap entry's protections */
			if (entry->protection != VM_PROT_READ) {
				/*
				 * Someone has already altered the top entry's
				 * protections via vm_protect(VM_PROT_COPY).
				 * Respect these new values and ignore the
				 * submap entry's protections.
				 */
			} else {
				/*
				 * Regular copy-on-write: propagate the submap
				 * entry's protections and the top map entry.
				 */
				expected_prot |= submap_entry->protection;
			}
			if ((expected_prot & access_type) != access_type) {
				return KERN_PROTECTION_FAILURE;
			}

			submap_entry = submap_entry->vme_next;
		}
	}

	return KERN_SUCCESS;
}

static kern_return_t
vm_map_wire_and_extract_preflight(vm_map_lock_ctx_t vctx, vm_map_entry_t entry, vm_prot_t access_type)
{
	/*
	 * wire_and_extract wants to share the memory with the caller.
	 * We can't do that if CoW would need to be resolved
	 */
	if (entry->is_sub_map) {
		return KERN_INVALID_ARGUMENT;
	}
	if (entry->needs_copy || VME_OBJECT(entry) == VM_OBJECT_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	if (VME_OBJECT(entry)->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
		return KERN_INVALID_ARGUMENT;
	}
	if ((entry->protection & access_type) != access_type) {
		/* vm_map_wire_preflight has a similar but less strict check */
		return KERN_PROTECTION_FAILURE;
	}
	if (entry->vme_end - entry->vme_start != PAGE_SIZE) {
		return KERN_INVALID_ARGUMENT;
	}
	return vm_map_wire_preflight(vctx, entry, access_type);
}

/*!
 * @function vm_map_wire_stabilize_entry_object
 *
 * @brief
 * This function takes an arbitrary entry an transforms that entry to a state that
 * it is ready to be wired.
 * It will force Copy-On-Write if needed, and make it so that the object cannot
 * be COPY_SYMMETRIC.
 * At the end of this function, the object associated with the passed entry is
 * guaranteed to be permanently stable, meaning that without some sort of deletion
 * or overwrite, the entry's object will never change.
 *
 * @param map - the map containing the passed entry
 * @param entry - the entry to stabilize (must be exclusively locked)
 */
static void
vm_map_wire_stabilize_entry_object(vm_map_t map, vm_map_entry_t entry)
{
	vm_map_offset_t size = entry->vme_end - entry->vme_start;

	VM_ENTRY_ASSERT_EXCL_OWNER(entry);
	vm_object_t entry_object = VME_OBJECT(entry);
	if (entry_object == VM_OBJECT_NULL && entry->max_protection == VM_PROT_NONE) {
		/*
		 * Map entries with max_prot == PROT_NONE ordinarily
		 * do not get a vm_object allocated. Wire requires an
		 * object in this case (specifically for mlock(PROT_NONE)),
		 * so allocate it here.
		 */
		vm_map_entry_lock_allocate_object(entry, vm_map_maybe_serial_id(map));
		entry_object = VME_OBJECT(entry);
	}
	assert(entry_object);

	if (entry_object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
		vm_object_t orig_object, new_object;
		vm_object_offset_t orig_offset;
		/*
		 * Force an unrequested "copy-on-write" but only for
		 * the range we're wiring.
		 */
		orig_object = entry_object;
		orig_offset = VME_OFFSET(entry);
		if (!orig_object->shadowed) {
			vm_object_lock(orig_object);
			VM_OBJECT_SET_SHADOWED(orig_object, TRUE);
			vm_object_unlock(orig_object);
		}
		VME_OBJECT_SHADOW(entry, size, vm_map_always_shadow(map));
		new_object = VME_OBJECT(entry);
		if (new_object != orig_object) {
			/*
			 * This mapping has not been shared (or it would be
			 * COPY_DELAY instead of COPY_SYMMETRIC) and it has
			 * not been copied-on-write (or it would be marked
			 * as "needs_copy" and would have been handled by the
			 * range lock by VMRL_EX_RESOLVE_COW_AND_OBJ and
			 * also already write-protected).
			 * We still need to write-protect here to prevent
			 * other threads from modifying these pages while
			 * we're in the process of copying and wiring
			 * the copied pages.
			 * Since the mapping is neither shared nor COWed,
			 * we only need to write-protect the PTEs for this
			 * mapping.
			 */
			vm_object_pmap_protect(orig_object,
			    orig_offset,
			    size,
			    map->pmap,
			    VM_MAP_PAGE_SIZE(map),
			    entry->vme_start,
			    entry->protection & ~VM_PROT_WRITE);
		}

		/*
		 * Make the object COPY_DELAY to get a stable object
		 * to wire.
		 * That should avoid creating long shadow chains while
		 * wiring/unwiring the same range repeatedly.
		 * That also prevents part of the object from being
		 * wired while another part is "needs_copy", which
		 * could result in conflicting rules wrt copy-on-write.
		 */
		vm_object_lock(new_object);
		if (new_object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
			assertf(vm_object_round_page(VME_OFFSET(entry) + size) - vm_object_trunc_page(VME_OFFSET(entry)) == new_object->vo_size,
			    "object %p size 0x%llx entry %p [0x%llx:0x%llx:0x%llx] size 0x%llx\n",
			    new_object, (uint64_t)new_object->vo_size,
			    entry,
			    (uint64_t)entry->vme_start,
			    (uint64_t)entry->vme_end,
			    (uint64_t)VME_OFFSET(entry),
			    (uint64_t)size);
			assertf(os_ref_get_count_raw(&new_object->ref_count) == 1,
			    "object %p ref_count %d\n",
			    new_object, os_ref_get_count_raw(&new_object->ref_count));
			assertf(!entry->needs_copy,
			    "entry %p\n", entry);
			new_object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
			VM_OBJECT_SET_TRUE_SHARE(new_object, TRUE);
		}

		entry_object = new_object; /* unlock at the end of the function */
	} else {
		vm_object_lock(entry_object);
	}
	/* Wiring is considered as sharing with the physical aperture */
	vm_object_mark_shared(entry_object, VM_SHARE_TYPE_PERMANENT);
	vm_object_unlock(entry_object);
}

/*
 * There are 3 states a wire copy can be in:
 * ENTRY_WIRED: the copy is entirely wired. The corresponding entry had
 * the wire_count updated, the pmap made pageable, and the pages wired.
 *
 * OBJ_WIRED: the pages in the object are wired. The entry had no change to
 * the wire count and the pmap has not been informed of the entry.
 *
 * NOT_WIRED: nothing about the entry is wired.
 */
__enum_decl(vm_wire_state_t, unsigned char, {
	ENTRY_WIRED   = 0,
	OBJ_WIRED     = 1,
	NOT_WIRED     = 2,
});

/*
 * This struct represents a copy of entry state at the beginning of wire.
 * One wire_copy_node corresponds 1:1 with an entry at the end of Stage 1 in
 * vm_map_wire_impl.
 *
 * If this struct is changed update the corresponding lldb macro showwirecopylist
 */
typedef struct wire_copy_node {
	TAILQ_ENTRY(wire_copy_node)     chain;
	vm_map_offset_t                 start;
	vm_map_offset_t                 end;
	vm_object_offset_t              offset;
	vm_wire_state_t                 wire_state;
	bool                            is_sub_map;
	vm_object_t                     object;
} *wire_copy_list_t;


TAILQ_HEAD(wire_copy_list_head, wire_copy_node);

__abortlike
static void
__vm_map_wire_kernel_deletion_panic(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_map_offset_t         entry_start,
	vm_map_offset_t         entry_end)
{
	panic("vm_map_wire(%p,0x%llx,0x%llx): kernel wiring raced against concurrent deletion on entry (%llx, %llx]",
	    map, (uint64_t)start, (uint64_t)end, entry_start, entry_end);
}

/*
 * This function cleans up all the resources we've allocated to track
 * copies of vm_map_entry_ts in wire_copy_nodes.
 */
static void
vm_map_wire_cleanup_wire_copy_list(struct wire_copy_list_head * head)
{
	wire_copy_list_t cur, tmp;
	TAILQ_FOREACH_SAFE(cur, head, chain, tmp) {
		TAILQ_REMOVE(head, cur, chain);

		if (!cur->is_sub_map) {
			vm_object_deallocate(cur->object);
		}
		kfree_type(struct wire_copy_node, cur);
	}
}

/*
 * Given an entry and a copy of an entry, check if the object is the same, and if
 * so, that the offset into the object refers to the same address.
 */
static bool
vm_entry_obj_and_offs_match(vm_map_entry_t entry, wire_copy_list_t copy_entry)
{
	if (entry->is_sub_map || copy_entry->is_sub_map ||
	    VME_OBJECT(entry) != copy_entry->object) {
		return false;
	}

	/* this allows for clipping/simplify to not prevent a wiring */
	if (copy_entry->offset - VME_OFFSET(entry) != copy_entry->start - entry->vme_start) {
		return false;
	}
	return true;
}

/*
 * If the entry's end is less than its copy's end, split the copy up to
 * match the entry's end.
 * Having every copy be contained by a single entry lets us record
 * the wiring status of each copy and have it directly correspond to an entry.
 *
 * Practically this should not happen much because it requires
 * concurrent VM operations to be splitting/coalescing these entries
 * during this call to wire.
 */
static void
clip_wire_copy_end(
	struct wire_copy_list_head     *copy_list,
	wire_copy_list_t                cur_copy,
	vm_map_address_t                entry_end)
{
	if (cur_copy->end > entry_end) {
		/*
		 * We want to split our copy up into a new copy.
		 * the new copy starts at the end of the entry.
		 */
		wire_copy_list_t new_copy = kalloc_type(struct wire_copy_node, Z_WAITOK);
		*new_copy = *cur_copy;
		/* null the linkages */
		new_copy->chain.tqe_next = NULL;
		new_copy->chain.tqe_prev = NULL;

		if (new_copy->is_sub_map) {
			/* We don't store submaps in the wire copies, so no ref */
		} else {
			vm_object_reference(cur_copy->object);
		}

		vm_map_offset_t difference = entry_end - cur_copy->start;
		new_copy->offset += difference;
		new_copy->start = entry_end;
		TAILQ_INSERT_AFTER(copy_list, cur_copy, new_copy, chain);
		cur_copy->end = entry_end;
	}
}

/*
 * Find the physical page to return to someone who asked to wire and "extract"
 * the wired page.
 */
static ppnum_t
get_page_for_wire_and_extract(vm_map_entry_t entry)
{
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_page_t               m;
	ppnum_t                 physpage;

	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	/*
	 * We don't have to "wire" the page again
	 * but we still have to extract its
	 * physical page number.
	 */
	object = VME_OBJECT(entry);
	offset = VME_OFFSET(entry);
	/* need exclusive object lock to update m->dirty */
	if (entry->protection & VM_PROT_WRITE) {
		vm_object_lock(object);
	} else {
		vm_object_lock_shared(object);
	}
	m = vm_page_lookup(object, offset);
	if (m == VM_PAGE_NULL || !VM_PAGE_WIRED(m)) {
		panic("Tried to lookup a wired page, but the page wasn't wired page=%p start=%llx end=%llx entry=%p",
		    m, entry->vme_start, entry->vme_end, entry);
	}
	physpage = VM_PAGE_GET_PHYS_PAGE(m);
	if (entry->protection & VM_PROT_WRITE) {
		/*
		 * We're passing a physpage num for a writable page to a client,
		 * we need to mark it dirty.
		 */
		vm_object_lock_assert_exclusive(object);
		m->vmp_dirty = TRUE;
	}
	vm_object_unlock(object);
	return physpage;
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_wire_sanitize(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              prot_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_offset_t        *start,
	vm_map_offset_t        *end,
	vm_map_size_t          *size,
	vm_prot_t              *prot)
{
	kern_return_t   kr;

#if CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS
	kr = vm_sanitize_canonicalize_ut_addr_end(
		map,
		&start_u,
		&end_u);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}
#endif /* CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS */

	kr = vm_sanitize_addr_end(start_u, end_u, vm_sanitize_caller, map,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS, start, end, size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	kr = vm_sanitize_prot(prot_u, vm_sanitize_caller, map, prot);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	return KERN_SUCCESS;
}

/*!
 * Copy an entry and add the copy to the copy_list passed in.
 *
 * If the entry is already wired, go ahead and set the state to ENTRY_WIRED and
 * increment the wire counts directly.
 * If it is not wired, just preflight we have the space to wire that entry.
 *
 * @param entry - the entry to copy/preflight
 * @param user_wire - is it a userspace initiated wiring
 * @param copy_list - the list of entry copies we should add our new copy to.
 * @param size_that_would_be_wired - IN/OUT. At in time, it contains how much
 * space we have already preflighted. At out time, it adds the size of `entry` to
 * the space we have already preflighted.
 *
 * return KERN_SUCCESS if the preflight was successful
 * otherwise, the preflight of space failed and we cannot wire the entry.
 */
static kern_return_t
vm_map_wire_copy_entry_and_preflight_space(
	vm_map_t                        map,
	vm_map_entry_t                  entry,
	bool                            user_wire,
	struct wire_copy_list_head     *copy_list,
	vm_map_size_t                  * const size_that_would_be_wired)
{
	kern_return_t kr;
	wire_copy_list_t wire_copy = kalloc_type(struct wire_copy_node, Z_WAITOK);

	/*
	 * If we don't need to wire the pages,
	 * note that we are already wired
	 * so later stages don't wire the pages again
	 * Also increment the wire count.
	 */
	bool entry_already_wired = entry->wired_count != 0;
	if (entry_already_wired) {
		kr = vm_map_wire_count_add(map, entry, user_wire);
		if (kr != KERN_SUCCESS) {
			kfree_type(struct wire_copy_node, wire_copy);
			return kr;
		}
		wire_copy->wire_state = ENTRY_WIRED;
	} else {
		kr = vm_map_preflight_wire_space(map, entry, user_wire, size_that_would_be_wired);
		if (kr != KERN_SUCCESS) {
			kfree_type(struct wire_copy_node, wire_copy);
			return kr;
		}
		wire_copy->wire_state = NOT_WIRED;
	}

	wire_copy->start = entry->vme_start;
	wire_copy->end = entry->vme_end;
	wire_copy->offset = VME_OFFSET(entry);
	wire_copy->is_sub_map = entry->is_sub_map;
	if (entry->is_sub_map) {
		/*
		 * We don't actually do anything to wire submaps.
		 * Just mark it as wired without doing anything.
		 */
		wire_copy->wire_state = ENTRY_WIRED;
		wire_copy->object = VM_OBJECT_NULL;
	} else {
		wire_copy->object = VME_OBJECT(entry);
		vm_object_reference(VME_OBJECT(entry));
	}

	TAILQ_INSERT_TAIL(copy_list, wire_copy, chain);
	return KERN_SUCCESS;
}

#if DEBUG || DEVELOPMENT
int wire_restarts_due_to_kernel_wiring;
#endif /* DEBUG || DEVELOPMENT */
/*
 * This function is broken into a 3 stage process:
 * Stage 1: copy all the entries in the range
 * Stage 2: wire all the objects (NOT_WIRED -> OBJ_WIRED)
 * Stage 3: wire all the entries (OBJ_WIRED -> ENTRY_WIRED)
 *
 * This allows the page level wiring to be done without any lock held.
 *
 *
 * These invariants should always be true:
 * submaps cannot be wired:
 *   - transparent submaps are automatically descended into, so their entries
 *     will be wired, but the entry pointing to the submap itself is not wired.
 *   - the shared cache is unnested at the time of wiring (VMRL_RESOLVE_COW_AND_OBJ).
 *   - the intel commpage cannot be wired
 *   - therefore this routine just considers them ENTRY_WIRED so that no more work
 *     is done on them.
 *
 * the wire count of a page must be >= 1 if an entry is wired.
 *
 * For a given entry, one page level wire count is taken regardless of how
 * many times that entry is wired. That means a single entry have a wired_count
 * higher than the page wire count so long as one of those page wirings is due
 * to the entry wired_count.
 *
 * @param prot_u - the protections the entry must have. A mapping with all
 * the protections of the corresponding entry will still be entered into the pmap.
 */
kern_return_t
vm_map_wire_impl(
	vm_map_t                original_map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              prot_u,
	vm_tag_t                tag,
	boolean_t               user_wire,
	ppnum_t                *physpage_p,
	vm_sanitize_caller_t    vm_sanitize_caller)
{
	/*
	 * original_map is the map passed in by the caller.
	 * cur_map is the map or transparent submap that we are changing.
	 */
	vm_map_t                cur_map;
	vm_map_offset_t         start, end;
	vm_map_size_t           wire_size;
	vm_prot_t               caller_prot;
	kern_return_t           kr;
	vm_map_entry_t          entry;
	vm_prot_t               access_type;
	bool                    wire_and_extract;
	vmrl_ex_flags_t         flags;
	vm_map_size_t           size_that_would_be_wired;
	wire_copy_list_t        cur_copy;
	bool                    need_restart = false;
	uint32_t                wire_restarts = 0;
	struct wire_copy_list_head copy_list;
	TAILQ_INIT(&copy_list);
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_WIRE_IMPL);
	/*
	 * Sanitize any input parameters that are addr/size/prot/inherit
	 */
	kr = vm_map_wire_sanitize(original_map,
	    start_u,
	    end_u,
	    prot_u,
	    vm_sanitize_caller,
	    &start,
	    &end,
	    &wire_size,
	    &caller_prot);
	if (__improbable(kr != KERN_SUCCESS)) {
		if (physpage_p) {
			*physpage_p = 0;
		}
		kr = vm_sanitize_get_kr(kr);
		vmlp_api_end(VM_MAP_WIRE_IMPL, kr);
		return kr;
	}

restart:
	/* Include ALLEXEC so that we don't silently drop the UEXEC bit if we're on Intel */
	access_type = (caller_prot & (VM_PROT_ALL | VM_PROT_ALLEXEC));

	wire_and_extract = false;
	if (physpage_p != NULL) {
		/*
		 * The caller wants the physical page number of the
		 * wired page.  We return only one physical page number
		 * so this works for only one page at a time.
		 *
		 * The only caller (vm_map_wire_and_extract)
		 * guarantees it.
		 */
		assert(end - start == VM_MAP_PAGE_SIZE(original_map));
		wire_and_extract = true;
		*physpage_p = 0;
	}

	if (wire_and_extract) {
		ctx->vmlc_preflight = ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
			return vm_map_wire_and_extract_preflight(vctx, vme, access_type);
		};
	} else {
		ctx->vmlc_preflight = ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
			return vm_map_wire_preflight(vctx, vme, access_type);
		};
	}

	VM_MAP_CLAMP_TO_MAP_BOUNDS(original_map, start, end);
	assert(VM_MAP_PAGE_ALIGNED(start, VM_MAP_PAGE_MASK(original_map)));
	assert(VM_MAP_PAGE_ALIGNED(end, VM_MAP_PAGE_MASK(original_map)));
	if (start == end) {
		/* We wired what the caller asked for, zero pages */
		vmlp_api_end(VM_MAP_WIRE_IMPL, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	/* We want an atomic lock that resolves CoW and unnests submaps */
	flags = VMRL_EX_ATOMIC | VMRL_EX_RESOLVE_COW_AND_OBJ;
	if (user_wire) {
		/* And user wires should be interruptible */
		flags |= VMRL_EX_INTERRUPTIBLE;
	}

	/*
	 * Stage 1:
	 * Verify we have space in map->user_wire_size
	 * And copy every entry (object, offset, start, end, wire_state)
	 */
	kr = vm_map_range_ex_lock(ctx, &original_map, start, end, flags);
	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_WIRE_IMPL, kr);
		return kr;
	}

	/*
	 * No constant submap descent. We do descend into transparent submaps.
	 * It is an error for the transparent submap configuration to change
	 * in this address range during the call. We record the current map
	 * here and verify that it does not change in later stages.
	 */
	cur_map = vm_map_lock_ctx_get_map(ctx);

	size_that_would_be_wired = 0;
	while ((entry = vm_map_range_atomic_next(ctx))) {
		if (!entry->is_sub_map) {
			/*
			 * First, stabilize the entry's object so it will
			 * not change without a deletion
			 */
			vm_map_wire_stabilize_entry_object(cur_map, entry);
		}
		/*
		 * This leaves each copy state as (ENTRY_WIRED or NOT_WIRED).
		 * ENTRY_WIRED if the entry was already wired and we could just
		 * increment the wire count.
		 *
		 * NOT_WIRED if the entry wasn't previously wired.
		 */
		kr = vm_map_wire_copy_entry_and_preflight_space(cur_map,
		    entry, user_wire, &copy_list, &size_that_would_be_wired);
		if (kr != KERN_SUCCESS) {
			vm_map_range_ex_unlock(ctx, &original_map);

			goto wire_error_unlocked;
		}
	}

	vm_map_range_ex_unlock(ctx, &original_map);

	/*
	 * Stage 2:
	 * Transition our copies from NOT_WIRED -> OBJ_WIRED
	 * To do this, wire all the pages in our copies.
	 */
	TAILQ_FOREACH(cur_copy, &copy_list, chain) {
		if (cur_copy->wire_state == ENTRY_WIRED) {
			/* We already wired it. Don't do anything */
			continue;
		}

		wait_interrupt_t interrupt_level;
		if (user_wire) {
			interrupt_level = THREAD_ABORTSAFE;
		} else {
			interrupt_level = THREAD_UNINT;
		}
		assert(!cur_copy->is_sub_map);
		kr = vm_fault_wire_object_pages(cur_map, cur_copy->object, cur_copy->offset,
		    cur_copy->end - cur_copy->start, tag, interrupt_level);
		if (kr != KERN_SUCCESS) {
			goto wire_error_unlocked;
		}
		cur_copy->wire_state = OBJ_WIRED;
	}

	/*
	 * Stage 3:
	 * Transition our copies from OBJ_WIRED -> ENTRY_WIRED
	 * Update the wire count and fault the wired pages
	 */
	kr = vm_map_range_ex_lock(ctx, &original_map, start, end, flags | VMRL_EX_SIMPLIFY);
	if (kr != KERN_SUCCESS) {
		goto wire_error_unlocked;
	}

	/* We should be in the same map or submap as Stage 1. */
	if (vm_map_lock_ctx_get_map(ctx) != cur_map) {
		panic("transparent submap configuration unexpectedly changed during vm_map_wire");
	}

	cur_copy = TAILQ_FIRST(&copy_list);
	while ((entry = vm_map_range_atomic_next(ctx))) {
		bool faulted_pages = false;
		/*
		 * Clip the end so we have the guarantee an entry
		 * and the copy are of the same size. This prevents
		 * an entry corresponding to two copies in different
		 * states (invalid), or a copy corresponding to two different
		 * entries (not inherently invalid, but makes the accounting trickier)
		 *
		 * Note we only need to clip the end, as that will clip the start
		 * of the next entry.  The range lock guarantees the first copy
		 * and the first entry start at the same address.
		 */
		assert(cur_copy->start == entry->vme_start);
		clip_wire_copy_end(&copy_list, cur_copy, entry->vme_end);
		vm_map_range_lock_clip_end(ctx, entry, cur_copy->end);

		assert(cur_copy->wire_state != NOT_WIRED);

		if (cur_copy->wire_state == OBJ_WIRED) {
			if (vm_entry_obj_and_offs_match(entry, cur_copy)) {
				bool entry_already_wired = entry->wired_count != 0;
				if (entry_already_wired) {
					/*
					 * Someone raced us and wired the entry.
					 * We therefore want to undo the object wiring we did before.
					 */
					vm_fault_unwire_object_pages(cur_map, cur_copy->object,
					    cur_copy->offset, cur_copy->end - cur_copy->start);
					cur_copy->wire_state = NOT_WIRED;
				}

				kr = vm_map_wire_count_add(cur_map, entry, user_wire);
				if (kr != KERN_SUCCESS) {
					vm_map_range_ex_unlock(ctx, &original_map);
					cur_copy->wire_state = NOT_WIRED;

					goto wire_error_unlocked;
				}

				if (!entry_already_wired) {
					kr = vm_fault_wire_resident_pages(cur_map,
					    entry, caller_prot, tag, physpage_p, ctx);
					if (kr != KERN_SUCCESS) {
						/*
						 * on error, vm_fault_wire_resident_pages
						 * unwires everything in the range
						 */
						vm_map_wire_count_sub(cur_map, entry, user_wire);
						cur_copy->wire_state = NOT_WIRED;

						vm_map_range_ex_unlock(ctx, &original_map);

						goto wire_error_unlocked;
					}
					faulted_pages = true;
				}
				cur_copy->wire_state = ENTRY_WIRED;
			} else {
				/*
				 * Some intermediate deletion happened.
				 * Unless otherwise noted, pretend that
				 * deletion happened after the wiring.
				 * That means the new memory would be unwired by the
				 * deletion and thus not need to be wired by this call.
				 */
				if (!user_wire && vm_kernel_map_is_kernel(cur_map)) {
					/*
					 * Kernel initiated wire that raced against deletion
					 * on the kernel map
					 * This is a bug, and thus we should panic
					 */
					__vm_map_wire_kernel_deletion_panic(cur_map, start,
					    end, entry->vme_start, entry->vme_end);
				} else if (!user_wire) {
					/*
					 * Kernel initiated wire that raced against deletion
					 * on a user map.
					 * We can't say the deletion happened after the wiring,
					 * because the deletion would have waited for the wire
					 * count to go to zero.
					 * That means we have to pretend the deletion happened
					 * before the wiring.
					 * That means we need to restart from the top.
					 * goto the error path to drop all our state
					 * and let it restart.
					 */
					need_restart = true;
					vm_map_range_ex_unlock(ctx, &original_map);

					goto wire_error_unlocked;
				}

				vm_fault_unwire_object_pages(cur_map, cur_copy->object,
				    cur_copy->offset, cur_copy->end - cur_copy->start);
				cur_copy->wire_state = NOT_WIRED;
			}
		}
		assert(cur_copy->wire_state == ENTRY_WIRED || cur_copy->wire_state == NOT_WIRED);

		/*
		 * If we didn't already get the ppnum from faulting the pages,
		 * get it now.
		 */
		if (!faulted_pages && wire_and_extract) {
			assert(!entry->is_sub_map); // enforced by preflight
			if (cur_copy->wire_state == NOT_WIRED) {
				kr = KERN_INVALID_ADDRESS;
				vm_map_range_ex_unlock(ctx, &original_map);

				goto wire_error_unlocked;
			}
			*physpage_p = get_page_for_wire_and_extract(entry);
		}

		cur_copy = TAILQ_NEXT(cur_copy, chain);
	}

	vm_map_range_ex_unlock(ctx, &original_map);

	/* cleanup our copies */
	vm_map_wire_cleanup_wire_copy_list(&copy_list);
	vmlp_api_end(VM_MAP_WIRE_IMPL, KERN_SUCCESS);
	return KERN_SUCCESS;

wire_error_unlocked:
	/*
	 * Note that this error path cannot be _locked, as we will wire
	 * entries in stage 1 and then drop it for stage 2. Therefore there is
	 * some path to this where the range lock is dropped
	 * and we later need to unwire entries.
	 *
	 * There are 3 states a copy can be in:
	 * 1) ENTRY_WIRED: We already wired the entry, so unwire that same range.
	 * 2) OBJ_WIRED: The obj is wired, so unwire it.
	 * 3) NOT_WIRED: nothing to do
	 */
	assert(kr != KERN_SUCCESS || need_restart);

	TAILQ_FOREACH(cur_copy, &copy_list, chain) {
		if (cur_copy->wire_state == ENTRY_WIRED) {
			if (!cur_copy->is_sub_map) {
				vm_map_unwire(cur_map, cur_copy->start, cur_copy->end,
				    user_wire);
			}
		} else if (cur_copy->wire_state == OBJ_WIRED) {
			mach_vm_size_t size = cur_copy->end - cur_copy->start;
			assert(!cur_copy->is_sub_map);
			vm_fault_unwire_object_pages(cur_map, cur_copy->object,
			    cur_copy->offset, size);
		}
	}

	vm_map_wire_cleanup_wire_copy_list(&copy_list);

	if (need_restart) {
		/*
		 * We need to restart, but want to do exponential backoff from
		 * mutex_pause to prevent an attacker from causing us to busy
		 * loop in the kernel.
		 * We expect in practice hitting this is uncommon as we never
		 * hit this race in months of testing a branch that panicked here
		 * instead.
		 */
		mutex_pause(wire_restarts);
		/* overflow isn't a problem, this is used for backoff only */
		wire_restarts++;
		need_restart = false;
#if DEBUG || DEVELOPMENT
		os_atomic_add(&wire_restarts_due_to_kernel_wiring, 1, relaxed);
#endif /* DEBUG || DEVELOPMENT */
		goto restart;
	}

	vmlp_api_end(VM_MAP_WIRE_IMPL, kr);

	return kr;
}

kern_return_t
vm_map_wire_external(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              prot_u,
	boolean_t               user_wire)
{
	vm_tag_t tag = vm_tag_bt();

	return vm_map_wire_kernel(map, start_u, end_u, prot_u, tag, user_wire);
}

__mockable kern_return_t
vm_map_wire_kernel(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              prot_u,
	vm_tag_t                tag,
	boolean_t               user_wire)
{
	return vm_map_wire_impl(map, start_u, end_u, prot_u, tag,
	           user_wire, NULL, VM_SANITIZE_CALLER_VM_MAP_WIRE);
}

#if XNU_PLATFORM_MacOSX

kern_return_t
vm_map_wire_and_extract(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_prot_ut              prot_u,
	boolean_t               user_wire,
	ppnum_t                *physpage_p)
{
	vm_tag_t         tag    = vm_tag_bt();
	vm_map_size_ut   size_u = vm_sanitize_wrap_size(VM_MAP_PAGE_SIZE(map));
	vm_map_offset_ut end_u  = vm_sanitize_compute_ut_end(start_u, size_u);

	return vm_map_wire_impl(map, start_u, end_u, prot_u, tag,
	           user_wire, physpage_p, VM_SANITIZE_CALLER_VM_MAP_WIRE);
}

#endif /* XNU_PLATFORM_MacOSX */

kern_return_t
vm_map_unwire(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	boolean_t               user_wire)
{
	return vm_map_unwire_impl(map, start_u, end_u, user_wire,
	           VM_SANITIZE_CALLER_VM_MAP_UNWIRE);
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_unwire_sanitize(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_offset_t        *start,
	vm_map_offset_t        *end,
	vm_map_size_t          *size)
{
#if CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS
	kern_return_t kr;

	kr = vm_sanitize_canonicalize_ut_addr_end(
		map,
		&start_u,
		&end_u);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}
#endif /* CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS */

	return vm_sanitize_addr_end(start_u, end_u, vm_sanitize_caller, map,
	           VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS, start, end, size);
}

kern_return_t
vm_map_unwire_impl(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	boolean_t               user_wire,
	vm_sanitize_caller_t    vm_sanitize_caller)
{
	vm_map_offset_t         start, end;
	vm_map_size_t           size;
	vm_map_entry_t          entry;
	kern_return_t           kr;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	/*
	 * Sanitize any input parameters that are addr/size/prot/inherit
	 */
	kr = vm_map_unwire_sanitize(
		map,
		start_u,
		end_u,
		vm_sanitize_caller,
		&start,
		&end,
		&size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	vmlp_api_start(VM_MAP_UNWIRE_IMPL);

	VM_MAP_CLAMP_TO_MAP_BOUNDS(map, start, end);
	assert(VM_MAP_PAGE_ALIGNED(start, VM_MAP_PAGE_MASK(map)));
	assert(VM_MAP_PAGE_ALIGNED(end, VM_MAP_PAGE_MASK(map)));
	vmlp_range_event(map, start, end - start);

	if (start == end) {
		/* We unwired what the caller asked for: zero pages */
		vmlp_api_end(VM_MAP_UNWIRE_IMPL, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	ctx->vmlc_preflight = ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
		(void)vctx;
		if (vme->superpage_size) {
			return KERN_INVALID_ADDRESS;
		}
		return KERN_SUCCESS;
	};

	kr = vm_map_range_ex_lock(ctx, &map, start, end,
	    VMRL_EX_ATOMIC | VMRL_EX_SIMPLIFY);
	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_UNWIRE_IMPL, kr);
		return kr;
	}

	while ((entry = vm_map_range_atomic_next(ctx))) {
		if (vm_map_wire_count_sub(ctx->vmlc_map, entry, user_wire)) {
			assert(!entry->is_sub_map);

			entry->zero_wired_pages = FALSE;
			vm_fault_unwire(ctx->vmlc_map, entry, false, ctx->vmlc_map->pmap,
			    entry->vme_start, entry->vme_end);
		}
	}

	vm_map_range_ex_unlock(ctx, &map);
	vmlp_api_end(VM_MAP_UNWIRE_IMPL, KERN_SUCCESS);
	return KERN_SUCCESS;
}



/*
 *     virt_memory_guard_ast:
 *
 *     Handle the AST callout for a virtual memory guard.
 *	   raise an EXC_GUARD exception and terminate the task
 *     if configured to do so.
 */
void
virt_memory_guard_ast(
	thread_t thread,
	mach_exception_data_type_t code,
	mach_exception_data_type_t subcode)
{
	task_t task = get_threadtask(thread);
	assert(task != kernel_task);
	assert(task == current_task());
	kern_return_t sync_exception_result;
	uint32_t behavior;

	behavior = task->task_exc_guard;

#if HAS_MTE
	/*
	 * Defer fixing rdar://150503373 (MTE Exceptions should not overload VM_GUARD exceptions and instead have their own)
	 * at a quieter time. For now, simply call into the code that would handle that guard from within the
	 * VM AST handling code. VM 3.0 Security Policy violations are still handled as regular virtual memory guards, whereby
	 * MTE fault guards get routed to the MTE handler.
	 */
	if (vm_guard_is_mte_fault(EXC_GUARD_DECODE_GUARD_FLAVOR(code))) {
		mte_guard_ast(thread, code, subcode);
		return;
	}
#endif /* HAS_MTE */

	/* Is delivery enabled */
	if ((behavior & TASK_EXC_GUARD_VM_DELIVER) == 0) {
		return;
	}

	/* If only once, make sure we're that once */
	while (behavior & TASK_EXC_GUARD_VM_ONCE) {
		uint32_t new_behavior = behavior & ~TASK_EXC_GUARD_VM_DELIVER;

		if (OSCompareAndSwap(behavior, new_behavior, &task->task_exc_guard)) {
			break;
		}
		behavior = task->task_exc_guard;
		if ((behavior & TASK_EXC_GUARD_VM_DELIVER) == 0) {
			return;
		}
	}

	const bool fatal = task->task_exc_guard & TASK_EXC_GUARD_VM_FATAL;
	/* Raise exception synchronously and see if handler claimed it */
	sync_exception_result = task_exception_notify(EXC_GUARD, code, subcode, fatal);

	if (fatal) {
		/*
		 * If Synchronous EXC_GUARD delivery was successful then
		 * kill the process and return, else kill the process
		 * and deliver the exception via EXC_CORPSE_NOTIFY.
		 */
		uint32_t flags = PX_FLAGS_NONE;
		if (sync_exception_result == KERN_SUCCESS) {
			flags |= PX_NO_CRASH_REPORT;
		}

		exception_info_t info = {
			.os_reason = OS_REASON_GUARD,
			.exception_type = EXC_GUARD,
			.mx_code = code,
			.mx_subcode = subcode
		};

		/* kill the task, unconditionally and fatally */
		exit_with_mach_exception(current_proc(), info, flags);
	} else if (task->task_exc_guard & TASK_EXC_GUARD_VM_CORPSE) {
		/*
		 * If the synchronous EXC_GUARD delivery was not successful,
		 * raise a simulated crash.
		 */
		if (sync_exception_result != KERN_SUCCESS) {
			task_violated_guard(code, subcode, NULL, FALSE);
		}
	}
}

/*
 * Validate policy for VM guard exceptions and encode the correct Mach exception
 * code and subcode if the policy allows delivering a guard exception here.
 */
static bool
vm_map_guard_exception_internal(
	vm_map_t                   map,
	vm_map_offset_t            address,
	unsigned                   reason,
	mach_exception_code_t      *code,
	mach_exception_data_type_t *subcode)
{
	unsigned int guard_type = GUARD_TYPE_VIRT_MEMORY;
	unsigned int target = 0; /* should we pass in pid associated with map? */

	task_t task = current_task_early();

	/* Can't deliver exceptions to a NULL task (early boot) or kernel task */
	if (task == NULL || task == kernel_task) {
		return false;
	}

	/* No point delivering an exception when the map being operated on is terminated. */
	if (map->terminated) {
		return false;
	}

	*code = 0;
	EXC_GUARD_ENCODE_TYPE(*code, guard_type);
	EXC_GUARD_ENCODE_FLAVOR(*code, reason);
	EXC_GUARD_ENCODE_TARGET(*code, target);
	*subcode = (uint64_t)address;

	return true;
}

/*
 *     vm_map_guard_exception:
 *
 *     Generate a GUARD_TYPE_VIRTUAL_MEMORY EXC_GUARD exception.
 *
 *         `reason` is kGUARD_EXC_DEALLOC_GAP when we find nothing mapped,
 *     or if there is a gap in the mapping when a user address space
 *     was requested. We report the address of the first gap found.
 */
#if HAS_MTE
/*     `reason` is kGUARD_EXC_SEC_COPY_DENIED when we are trying to
 *     share > 32K bytes of tagged memory via `vm_map_copyin`.
 *     We report the tagged address.
 *
 *     `reason` is kGUARD_EXC_SEC_SHARING_DENIED when a task is trying to
 *     share tagged memory to itself via `vm_map_remap` or `mach_make_memory_entry`.
 *     We report the source address.
 *
 *     Both exceptions above are always fatal.
 */
#endif /* HAS_MTE */

void
vm_map_guard_exception(
	vm_map_t                   map,
	vm_map_offset_t            address,
	unsigned                   reason)
{
	mach_exception_code_t code;
	mach_exception_data_type_t subcode;
	if (vm_map_guard_exception_internal(map, address, reason, &code, &subcode)) {
		task_t task = current_task();
		bool sticky = task->task_exc_guard & TASK_EXC_GUARD_VM_FATAL;
#if HAS_MTE
		if (vm_guard_is_mte_policy(EXC_GUARD_DECODE_GUARD_FLAVOR(code))) {
			sticky = true;
		}
#endif /* HAS_MTE */
		thread_guard_violation(current_thread(), code, subcode, sticky);
	}
}

/*
 * Special MTE and Guard Object AST handler for asyncronous traps raised while
 * in a kernel thread context. For these traps we have to synthesize from thin
 * air the exception, as the only thing we saved at the time of the fault was
 * the faulting address.
 *
 * There's also no notion of a thread to blame, due to the disjoint nature of
 * registering for some work (e.g. IOMD) and later performing it. This leads to
 * the special AST_SYNTHESIZE_MACH ast to be flagged on all threads of the
 * victim task. We use magic sentinel values to avoid delivering to more than
 * a single target, but the picked one is completely random and likely entirely
 * unrelated at its execution point.
 */
void
vm_map_synthesize_guard_exception(vm_map_t map, thread_t thread)
{
	vm_map_async_fault_t clear_fault = { 0, VM_ASYNC_TAG_FAULT_ALREADY_REPORTED };
	vm_map_async_fault_t async_fault;
	task_t task = get_threadtask(thread);

	assert(task == current_task_early());

	/* Bail out if we have a wrong task. */
	if (task == NULL || task == kernel_task) {
		return;
	}

	async_fault = *(volatile vm_map_async_fault_t *)&map->async_fault;

	if (async_fault.code == 0 ||
	    async_fault.code == VM_ASYNC_TAG_FAULT_ALREADY_REPORTED ||
	    !os_atomic_cmpxchg(&map->async_fault, async_fault, clear_fault, relaxed)) {
		/*
		 * Someone handled that fault already, just return
		 */
		return;
	}

	/*
	 * Some kernel thread doing work on behalf of our task
	 * asynchronously reported an MTE tag check fault or guard
	 * object fault.
	 */
#if HAS_MTE
	if (task_has_sec_soft_mode(task) &&
	    vm_guard_is_mte_fault(EXC_GUARD_DECODE_GUARD_FLAVOR(async_fault.code))) {
		async_fault.code |= kGUARD_EXC_MTE_SOFT_MODE;
		return mte_guard_ast(thread, async_fault.code, async_fault.address);
	}
#endif /* HAS_MTE */

	/* Perform fatal exception logic. */
	exit_with_fatal_exception_and_notify(current_proc(), OS_REASON_GUARD,
	    EXC_GUARD, async_fault.code, async_fault.address, PX_FLAGS_NONE);
}

#if HAS_MTE
__assert_only static bool
exactly_one_bit_set(uint32_t val)
{
	return __builtin_popcount(val) == 1;
}

/*
 * Gates vm_map_entry_t copy operations (copy and shares) of MTE-tagged memory
 * according to security policy. Depending on the appropriate action to be
 * applied, this function will either throw a guard exception, panic, or return
 * a boolean value indicating whether the operation should be permitted.
 *
 * `maybe_source_vm_object` must be provided in the `VM_MTE_OPERATION_TYPE_COPY` case.
 */
bool
vm_map_allow_mte_operation(vm_map_t source_map, vm_map_offset_t addr, vm_size_t size, vm_mte_operation_flags_t flags,
    optional_vm_object_t maybe_source_vm_object)
{
	/* Basic policy checks */
	assert(exactly_one_bit_set(flags & VM_MTE_OPERATION_TYPE_MASK));
	bool source_is_kernel = vm_kernel_map_is_kernel(source_map);
	if (flags & VM_MTE_OPERATION_FORK) {
		assert(!source_is_kernel && (flags & VM_MTE_OPERATION_DEST_USER));
	}

	/*
	 * Allow creating UPLs out of tagged memory for IOMDs to work.
	 */
	if (flags & VM_MTE_OPERATION_TYPE_CREATE_UPL) {
		return true;
	}

	/*
	 * All operations besides CREATE_UPL require information on the destination
	 * to be able to determine the policy. The destination can either be a user
	 * map, a kernel map, or unknown (e.g. a memory entry that can be sent
	 * to any destination map via IPC).
	 */
	assert(exactly_one_bit_set(flags & VM_MTE_OPERATION_DEST_MASK));

	/*
	 * Currently, we never allow you to set VM_INHERIT_SHARE on an MTE entry,
	 * except in specific cases along the corpse-fork path which don't call this
	 * function.
	 */
	if (flags & VM_MTE_OPERATION_TYPE_INHERIT_SHARE) {
		/*
		 * ... unless we're creating a memory entry. In this case, the VM_INHERIT
		 * value provided is unimportant, since it doesn't matter until the
		 * memory entry is mapped, where it will be overridden anyway by the
		 * inheritance value passed to vm_map_enter.
		 */
		if (flags & VM_MTE_OPERATION_DEST_UNKNOWN) {
			return true;
		}
		goto prohibit_mte_operation;
	}

	/*
	 * Copy and share operations that are internal to XNU (i.e. the vm_map_copy_t
	 * gets discarded instead of inserted into a map or memory entry) are
	 * permitted to avoid breaking unrelated APIs.
	 */
	if (flags & VM_MTE_OPERATION_DEST_INTERNAL) {
		return true;
	}

	/* Share cases: */
	if (flags & VM_MTE_OPERATION_TYPE_SHARE) {
		/*
		 * Violations of kernel memory sharing policy are enforced by SPTM for
		 * PMAP_MAPPING_TYPE_RESTRICTED memory, not by this function.
		 */
		if (source_is_kernel) {
			return true;
		}

		/*
		 * fork() is allowed to share tagged memory, as this behavior is required
		 * along the corpse fork path. It is not allowed in the normal case,
		 * which we enforce by preventing setting VM_INHERIT_SHARE on entries
		 * pointing to tagged VM objects.
		 */
		if (flags & VM_MTE_OPERATION_FORK) {
			/*
			 * Beware that vm_map_copyin_internal_for_entry relies on this
			 * function always returning success when fork is its caller.
			 */
			return true;
		}

		/*
		 * In userspace, share operations are allowed if we hold the task port
		 * of the destination process. We rely on the IPC layer to enforce any
		 * security policies related to obtaining the task port of other
		 * processes.
		 *
		 * Note that this includes the case of you holding your own task port,
		 * so it is totally legal to vm_remap your own tagged memory to share
		 * with yourself.
		 */
		if (flags & VM_MTE_OPERATION_DEST_USER) {
			return true;
		}

		if (flags & VM_MTE_OPERATION_IOKIT) {
			/*
			 * Allow IOKit to create memory entries out of tagged user memory as
			 * this is used by some flavors of IOMemoryDescriptor.
			 */
			if (flags & VM_MTE_OPERATION_DEST_UNKNOWN) {
				return true;
			}

			/*
			 * This is currently unreachable. No paths currently pass
			 * vmkf_is_iokit to any calls besides make_memory_entry. If you
			 * want to add new policy here, you need to plumb through that
			 * flag first.
			 */
			panic("unreachable");
		}

		/*
		 * All other sharing of tagged userspace memory is prohibited.
		 */
		goto prohibit_mte_operation;
	}

	/* Copy cases: */
	if (flags & VM_MTE_OPERATION_TYPE_COPY) {
		/*
		 * Copying MTE memory is always allowed, since our VM MTE sharing policies
		 * v3 ensures that alias mappings of MTE memory into new maps always
		 * results in an untagged mapping, which allows convenient sharing for
		 * minimal security cost.
		 *
		 * Note that in the code we still have carveouts for code paths that were
		 * specially allowed here, before we opened the floodgates (for example,
		 *  VM_MTE_OPERATION_FORK still exists and was previously special-cased
		 * here to allow CoW of tagged memory).
		 *
		 * Note that it's the caller's responsibility to ensure other MTE
		 * invariants are upheld: for example, if we allowed creating virtual
		 * copies of large MTE objects, we'd have to do something extra to ensure
		 * that local callers used a validly-tagged MTE buffer to create the copy.
		 * For now, we mandate that local MTE copyin takes the byte-by-byte copy
		 * path, sidestepping this issue for that case.
		 *
		 * To validate our expectation that we'll always hit the byte-by-byte
		 * copy path, ensure we never try to create a local MTE copy along this
		 * path (except for certain operations which we've specifically decided
		 * are allowed to do this for now, such as vm_map_remap_extract).
		 *
		 * It's the caller's responsibility to provide this object on relevant
		 * code paths. In an attempt to help catch programmer error, panic if
		 * this is not provided.
		 * As far as I can tell, this panic is 'safe' in the sense that
		 * we shouldn't hit it due to incidental VM behavior: since MTE VM objects
		 * are always eagerly allocated, if we're on a code path where we're copying
		 * an MTE VM entry there should always be a corresponding VM object.
		 */
		vm_object_t source_vm_object = OPTIONAL_EXPECT(maybe_source_vm_object, "Programming error? VM_MTE_OPERATION_TYPE_COPY but no VM object was provided");

		if (
			/* Is this a local copy? */
			source_vm_object->vmo_provenance == source_map->serial_id &&
			/* Is this an MTE object? */
			vm_object_is_mte_mappable(source_vm_object) &&
			/*
			 * vm_map_fork_copy() reads entries directly off the VM map,
			 * so it definitely won't be providing correctly tagged inputs.
			 * Don't restrict this case.
			 */
			!(flags & VM_MTE_OPERATION_FORK) &&
			/*
			 * vm_map_remap_extract() is currently allowed to hit this path
			 * with local MTE copies, don't restrict it.
			 */
			!(flags & VM_MTE_OPERATION_REMAP_EXTRACT) &&
			/*
			 * mach_make_memory_entry() is allowed to hit this with local MTE copies.
			 */
			!(flags & VM_MTE_OPERATION_MAKE_MEMORY_ENTRY)
			) {
			panic("We expect to never hit this path with an MTE-enabled object");
		}
		return true;
	}

	/* should be unreachable */
	panic("vm_map_allow_mte_operation: unimplemented operation type %u", flags & VM_MTE_OPERATION_TYPE_MASK);


prohibit_mte_operation:;
	/*
	 * Handle error cases.
	 */
	char *op_name = (flags & VM_MTE_OPERATION_TYPE_COPY ? "copy" :
	    (flags & VM_MTE_OPERATION_TYPE_SHARE ? "share" :
	    (flags & VM_MTE_OPERATION_TYPE_INHERIT_SHARE ? "inherit_share" :
	    (flags & VM_MTE_OPERATION_TYPE_CREATE_UPL ? "create_upl" : "unknown"))));
	if (source_is_kernel) {
		panic("illegal %s operation on tagged kernel memory: addr=%llu, size=%lu, flags=%#x",
		    op_name, addr, size, flags);
	}
	if (flags & VM_MTE_OPERATION_IOKIT) {
		/* IOKit will handle its own errors */
		return false;
	}
	if (current_task() == kernel_task) {
		panic("kernel performing illegal %s operation on tagged user memory: addr=%llu, size=%lu, flags=%#x",
		    op_name, addr, size, flags);
	}
	bool is_share = (flags & VM_MTE_OPERATION_TYPE_SHARE) || (flags & VM_MTE_OPERATION_TYPE_INHERIT_SHARE);
	vm_map_guard_exception(source_map, addr, is_share ? kGUARD_EXC_SEC_SHARING_DENIED : kGUARD_EXC_SEC_COPY_DENIED);
	/*
	 * When vm_sec is enforcing, we throw a fatal guard exception and cause the
	 * caller to return early. When sec_bypass is enabled, we throw a non-fatal
	 * guard exception but allow the caller to perform the operation and
	 * continue running. This results in a simulated crash.
	 */
	return false;
}
#endif /* HAS_MTE */


__abortlike
static void
__vm_map_delete_misaligned_panic(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end)
{
	panic("vm_map_delete(%p,0x%llx,0x%llx): start is not aligned to 0x%x",
	    map, (uint64_t)start, (uint64_t)end, VM_MAP_PAGE_SIZE(map));
}

__abortlike
static void
__vm_map_delete_wired_panic(vm_map_t map, vm_map_entry_t entry)
{
	panic("vm_map_delete(%p,0x%llx,0x%llx): entry %p is still wired",
	    map, entry->vme_start, entry->vme_end, entry);
}

__abortlike
static void
__vm_map_delete_failed_panic(vm_map_lock_ctx_t ctx, kern_return_t kr)
{
	panic("vm_map_delete(%p,0x%llx,0x%llx): failed unexpected with %d",
	    ctx->vmlc_map, ctx->vmlc_req_start, ctx->vmlc_req_end, kr);
}

__abortlike
static void
__vm_map_delete_permanent_panic(vm_map_lock_ctx_t ctx, vm_map_entry_t entry)
{
	panic("vm_map_delete(%p,0x%llx,0x%llx): "
	    "Attempting to remove permanent VM map entry %p [0x%llx:0x%llx]",
	    ctx->vmlc_map, ctx->vmlc_req_start, ctx->vmlc_req_end,
	    entry, (uint64_t)entry->vme_start, (uint64_t)entry->vme_end);
}

/*
 * vm_map_clamp_to_pmap(map, start, end)
 *
 * Modify *start and *end so they fall within the bounds of map->pmap.
 */
#if MACH_ASSERT
static void
vm_map_clamp_to_pmap(vm_map_t map, vm_map_address_t *start, vm_map_address_t *end)
{
	vm_map_address_t min;
	vm_map_address_t max;

#if __x86_64__
	/* x86_64 struct pmap does not have min and max fields */
	if (map->pmap == kernel_pmap) {
		min = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
		max = VM_MAX_KERNEL_ADDRESS;
	} else {
		min = VM_MAP_MIN_ADDRESS;
		max = VM_MAP_MAX_ADDRESS;
	}
#else
	min = map->pmap->min;
	max = map->pmap->max;
#endif

	if (*start < min) {
		*start = min;
	} else if (*start > max) {
		*start = max;
	}
	if (*end < min) {
		*end = min;
	} else if (*end > max) {
		*end = max;
	}
}
#endif

/*
 * Swaps the given entry with an identical zero-filled entry. The old entry is
 * not freed, and remains locked. The new entry is unlocked.
 *
 * Must be called with the interlock held and the entry locked exclusively.
 */
static void
vm_map_entry_unlink_and_make_zero_copy(vm_map_t map, vm_map_entry_t entry)
{
	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);

	vm_map_entry_t new_entry = vm_map_entry_create_locked(
		map,
		entry->vme_start,
		entry->vme_end);
	new_entry->protection     = entry->protection;
	new_entry->max_protection = entry->max_protection;
	new_entry->inheritance    = entry->inheritance;
	new_entry->needs_copy     = FALSE;
	new_entry->use_pmap       = TRUE;
	VME_OBJECT_SET(new_entry, VM_OBJECT_NULL, false, 0);
	VME_OFFSET_SET(new_entry, 0);

	vm_map_store_swap(map, entry, new_entry);
	vm_entry_unlock_exclusive(map, new_entry);
}

/*
 * Unlink an entry, then optionally extend a sentinel to cover it.
 * Update other map data to match:
 * - map->size
 * - kmem_free_space
 */
static void
vm_map_entry_unlink_and_extend_sentinel(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_map_entry_t          sentinel_or_null)
{
	vm_map_entry_t sentinel = sentinel_or_null;

	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	if (sentinel_or_null == NULL) {
		vm_map_store_remove(map, entry, VMS_REMOVE_FREE_SLOTS);
	} else if (sentinel->vme_next == NULL) {
		/* New sentinel. Link it into the map. */
		sentinel->vme_start = entry->vme_start;
		sentinel->vme_end   = entry->vme_end;
		vm_map_store_swap(map, entry, sentinel);
	} else {
		/*
		 * Extend a sentinel.
		 * It must currently end at the start of the unlinked entry.
		 */
		vm_map_store_merge_left(map, sentinel, entry);
	}
}

int vm_log_map_delete_permanent_prot_none = 0;
static kern_return_t
vm_map_delete_preflight_submap(
	vm_map_entry_t          entry,
	vm_map_offset_t         start,
	vm_map_offset_t         end)
{
	vm_map_offset_t submap_start, submap_end;
	vm_map_entry_t submap_entry;
	kern_return_t kr = KERN_SUCCESS;
	vm_map_t submap;

	/*
	 * Verify that the submap does not contain any "permanent" entries
	 * within the specified range. We permit TPRO ranges to be overwritten
	 * as we only reach this path if TPRO const protection is disabled for a
	 * given map.
	 */

	/* compute the clipped range in the submap */
	submap       = VME_SUBMAP(entry);
	submap_start = start - entry->vme_start + VME_OFFSET(entry);
	submap_end   = end - entry->vme_start + VME_OFFSET(entry);

	assert(vm_map_is_sealed(submap)); /* Transparent submaps descend. */

	vm_map_lookup_or_next(submap, submap_start, &submap_entry);

	for (;
	    submap_entry != vm_map_to_entry(submap) &&
	    submap_entry->vme_start < submap_end;
	    submap_entry = submap_entry->vme_next) {
		if (submap_entry->vme_permanent
#ifdef __arm64e__
		    /* allow TPRO submap entries to be overwritten */
		    && !submap_entry->used_for_tpro
#endif
		    ) {
			/* "permanent" entry -> fail */
			kr = KERN_PROTECTION_FAILURE;
			break;
		}
	}

	if (kr != KERN_SUCCESS) {
		/*
		 * There are some "permanent" mappings
		 * in the submap: we are not allowed
		 * to remove this range.
		 */
		printf("%d[%s] removing permanent submap entry "
		    "%p [0x%llx:0x%llx] prot 0x%x/0x%x -> KERN_PROT_FAILURE\n",
		    proc_selfpid(),
		    (get_bsdtask_info(current_task())
		    ? proc_name_address(get_bsdtask_info(current_task()))
		    : "?"), entry,
		    (uint64_t)entry->vme_start,
		    (uint64_t)entry->vme_end,
		    entry->protection,
		    entry->max_protection);
		DTRACE_VM6(vm_map_delete_permanent_deny_submap,
		    vm_map_entry_t, entry,
		    vm_map_offset_t, entry->vme_start,
		    vm_map_offset_t, entry->vme_end,
		    vm_prot_t, entry->protection,
		    vm_prot_t, entry->max_protection,
		    int, VME_ALIAS(entry));
	}

	return kr;
}

static kern_return_t
vm_map_delete_preflight(
	vm_map_lock_ctx_t       ctx,
	vm_map_entry_t          entry,
	vmr_flags_t             flags,
	kmem_guard_t            guard)
{
#define VM_MAP_DELETE_PREFLIGHT_LOG 0

	vm_map_offset_t start, end;
	vm_map_t        map = ctx->vmlc_map;

	vm_map_lock_ctx_bounds(ctx, &start, &end, NULL);

	if (VME_IS_SENTINEL(entry)) {
		DTRACE_VM3(kern_vm_deallocate_gap,
		    vm_map_offset_t, start,
		    vm_map_offset_t, ctx->vmlc_req_start,
		    vm_map_offset_t, ctx->vmlc_req_end);

		if (flags & VM_MAP_REMOVE_GAPS_FAIL) {
			return KERN_INVALID_VALUE;
		}
		vm_map_guard_exception(map, start, kGUARD_EXC_DEALLOC_GAP);
		return VMRL_ERR_SKIP_PREPARE;
	}

	if (vmrl_is_kernel_pmap(ctx)) {
		/*
		 * In the kernel map and its submaps,
		 * permanent entries never die, even
		 * if VM_MAP_REMOVE_IMMUTABLE is passed.
		 */
		if (entry->vme_permanent) {
			__vm_map_delete_permanent_panic(ctx, entry);
		}

		/*
		 * In the kernel map and its submaps,
		 * the removal of an atomic/guarded entry is strict.
		 *
		 * An atomic entry is processed only if it was
		 * specifically targeted.
		 *
		 * We might have deleted non-atomic entries before
		 * we reach this this point however...
		 */
		kmem_entry_validate_guard(map, entry, start, end - start, guard);
	}

	/*
	 * Validate what we do about permanent entries.
	 */
	if (!entry->vme_permanent) {
		/*
		 * If non permanent, it's ok!  For the rest follow the same
		 * order as vm_map_delete_handle_permanent().
		 */
	} else if ((flags & VM_MAP_REMOVE_IMMUTABLE_CODE) &&
	    developer_mode_state() &&
	    ((entry->protection & VM_PROT_EXECUTE) || entry->is_sub_map)) {
		/*
		 * a. we're in "developer" mode (for
		 *    breakpoints, dtrace probes, ...).
		 *    pre-adoption code did not check protection on submaps.
		 */

#if VM_MAP_DELETE_PREFLIGHT_LOG
		printf("FBDP %s:%d flags & REMOVE_IMMUTABLE_CODE\n", __FUNCTION__, __LINE__);
#endif
	} else if (flags & VM_MAP_REMOVE_IMMUTABLE) {
		/*
		 * b. explicitly requested by the kernel caller.
		 */

#if VM_MAP_DELETE_PREFLIGHT_LOG
		printf("FBDP %s:%d flags & REMOVE_IMMUTABLE\n", __FUNCTION__, __LINE__);
#endif
	} else if (map->terminated) {
		/*
		 * c. this is the final address space cleanup.
		 */

#if VM_MAP_DELETE_PREFLIGHT_LOG
		printf("FBDP %s:%d map->terminated\n", __FUNCTION__, __LINE__);
#endif
#if CODE_SIGNING_MONITOR
	} else if ((entry->protection & VM_PROT_EXECUTE) && !csm_enabled()) {
#endif
#if VM_MAP_DELETE_PREFLIGHT_LOG
		printf("FBDP %s:%d executable && !csm_enabled()\n", __FUNCTION__, __LINE__);
#endif
	} else if (entry->is_sub_map) {
		kern_return_t kr = KERN_SUCCESS;

		kr = vm_map_delete_preflight_submap(entry, start, end);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
	} else if (flags & VM_MAP_REMOVE_TO_OVERWRITE) {
		return KERN_PROTECTION_FAILURE;
	}

	if (entry->wired_count) {
		unsigned short wired_count = entry->wired_count;

		if (vmrl_is_kernel_pmap(ctx)) {
			assert(entry->user_wired_count == 0);
			/*
			 * rdar://144237810 (vm_map_delete should reject VM_MAP_REMOVE_KUNWIRE calls when the wired_count is 0)
			 */
			if (flags & VM_MAP_REMOVE_KUNWIRE) {
				wired_count -= 1;
			}
		} else {
			assert((flags & VM_MAP_REMOVE_KUNWIRE) == 0);
			if (entry->user_wired_count) {
				assert(wired_count > 0);
				wired_count -= 1;
			}
		}

		if (wired_count > 0) {
			return VMRL_ERR_WAIT_FOR_KUNWIRE;
		}
	}

	return KERN_SUCCESS;

#undef VM_MAP_DELETE_PREFLIGHT_LOG
}

static void
vm_map_delete_handle_wired(vm_map_t map, vm_map_entry_t entry, vmr_flags_t flags)
{
	if (entry->user_wired_count) {
		/*
		 * Collapse the wire count to 1, which will cause
		 * vm_map_wire_count_sub() to cleanup the user wiring.
		 */
		entry->user_wired_count = 1;
	}

	if (entry->user_wired_count || (flags & VM_MAP_REMOVE_KUNWIRE)) {
		vm_map_wire_count_sub(map, entry, entry->user_wired_count != 0);
	}

	if (entry->wired_count) {
		__vm_map_delete_wired_panic(map, entry);
	}

	if (!entry->is_sub_map) {
		vm_map_offset_t entry_end = entry->vme_end;

		if (flags & VM_MAP_REMOVE_NOKUNWIRE_LAST) {
			entry_end -= PAGE_SIZE;
		}
		if (entry->vme_kernel_object) {
			pmap_protect_options(map->pmap, entry->vme_start,
			    entry_end, VM_PROT_NONE, PMAP_OPTIONS_REMOVE, NULL);
		}
		vm_fault_unwire(map, entry, entry->vme_kernel_object,
		    map->pmap, entry->vme_start, entry_end);
	}
}

static void
vm_map_delete_handle_permanent(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vmr_flags_t             flags)
{
	/* Keep this logic in sync with vm_map_delete_preflight() */

	if ((flags & VM_MAP_REMOVE_IMMUTABLE_CODE) &&
	    (entry->protection & VM_PROT_EXECUTE) &&
	    developer_mode_state()) {
		/*
		 * Allow debuggers to undo executable mappings
		 * when developer mode is on.
		 */
#if 0
		printf("FBDP %d[%s] removing permanent executable entry "
		    "%p [0x%llx:0x%llx] prot 0x%x/0x%x\n",
		    proc_selfpid(),
		    (current_task()->bsd_info
		    ? proc_name_address(current_task()->bsd_info)
		    : "?"), entry,
		    (uint64_t)entry->vme_start,
		    (uint64_t)entry->vme_end,
		    entry->protection,
		    entry->max_protection);
#endif
		entry->vme_permanent = FALSE;
	} else if ((flags & VM_MAP_REMOVE_IMMUTABLE) || map->terminated) {
#if 0
		printf("FBDP %d[%s] removing permanent entry "
		    "%p [0x%llx:0x%llx] prot 0x%x/0x%x\n",
		    proc_selfpid(),
		    (current_task()->bsd_info
		    ? proc_name_address(current_task()->bsd_info)
		    : "?"), entry,
		    (uint64_t)entry->vme_start,
		    (uint64_t)entry->vme_end,
		    entry->protection,
		    entry->max_protection);
#endif
		entry->vme_permanent = FALSE;
#if CODE_SIGNING_MONITOR
	} else if ((entry->protection & VM_PROT_EXECUTE) && !csm_enabled()) {
		printf("%d[%s]: "
		    "code signing monitor disabled, allowing for permanent executable entry [0x%llx:0x%llx] "
		    "prot 0x%x/0x%x\n",
		    proc_selfpid(),
		    (get_bsdtask_info(current_task())
		    ? proc_name_address(get_bsdtask_info(current_task()))
		    : "?"),
		    (uint64_t)entry->vme_start,
		    (uint64_t)entry->vme_end,
		    entry->protection,
		    entry->max_protection);

		entry->vme_permanent = FALSE;
#endif
	} else if (entry->is_sub_map) {
		/*
		 * We already went through validate which did not deny
		 * the removal of this "permanent" and "is_sub_map"
		 * entry.
		 *
		 * Now that we've clipped what we actually want to
		 * delete, undo the "permanent" part to allow the
		 * removal to proceed.
		 */
		DTRACE_VM6(vm_map_delete_permanent_allow_submap,
		    vm_map_entry_t, entry,
		    vm_map_offset_t, entry->vme_start,
		    vm_map_offset_t, entry->vme_end,
		    vm_prot_t, entry->protection,
		    vm_prot_t, entry->max_protection,
		    int, VME_ALIAS(entry));
		entry->vme_permanent = false;
	} else {
		DTRACE_VM6(vm_map_delete_permanent,
		    vm_map_entry_t, entry,
		    vm_map_offset_t, entry->vme_start,
		    vm_map_offset_t, entry->vme_end,
		    vm_prot_t, entry->protection,
		    vm_prot_t, entry->max_protection,
		    int, VME_ALIAS(entry));
	}
}

/*!
 * @function vm_map_delete_handle_entry
 *
 * @abstract
 * Helper function for removing an entry from a map.
 *
 * @discussion
 * The entry (and the sentinel entry, if any) should be locked when calling
 * this function. The interlock should not be held. It may be acquired by this
 * function, but will be release before return.
 *
 * @param map           the map the entry belongs to.
 * @param entry         the entry to remove.
 * @param sentinel      the sentinel entry that should grow to replace the
 *                      entry. this is only relevant when the caller intends
 *                      to overwrite the mappings, pass NULL otherwise.
 * @param flags         deletion flags to control behavior. see vmr_flags_t
 *                      declaration for details.
 *
 * @returns true if the entry was successfully removed from the map (in which
 *          case the caller should add it to a zap list or delete it), false
 *          if the entry could not be removed because it is permanent.
 */
__result_use_check
static bool
vm_map_delete_handle_entry(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_map_entry_t          sentinel,
	vmr_flags_t             flags)
{
	vm_map_offset_t e_start = entry->vme_start;
	vm_map_offset_t e_end   = entry->vme_end;

	/*
	 * Step 1: unwire entries, we know they are clipped and ready,
	 *         it can't fail.
	 */

	if (entry->wired_count) {
		vm_map_delete_handle_wired(map, entry, flags);
	}

	/*
	 * Step 2: Deal with permanent entries.
	 */

	if (entry->vme_permanent) {
		vm_map_delete_handle_permanent(map, entry, flags);
	}

	/*
	 * Step 3: Cleanup the pmap
	 */
	if (VME_IS_SENTINEL(entry)) {
		/*
		 * We have a sentinel entry added by the range lock to fill holes.
		 * They never have pages inserted into them, and never have
		 * anything in the pmap. Nothing to do.
		 */
	} else if (entry->is_sub_map) {
		assertf(VM_MAP_PAGE_SHIFT(VME_SUBMAP(entry)) >= VM_MAP_PAGE_SHIFT(map),
		    "map %p (%d) entry %p submap %p (%d)\n",
		    map, VM_MAP_PAGE_SHIFT(map), entry,
		    VME_SUBMAP(entry),
		    VM_MAP_PAGE_SHIFT(VME_SUBMAP(entry)));

		assert(!map->mapped_in_other_pmaps);
		if (!entry->use_pmap) {
			pmap_remove(map->pmap, e_start, e_end);
		} else if (map->terminated) {
			/*
			 * This is the final cleanup of the address space being
			 * terminated.  No new mappings are expected and we
			 * don't really need to unnest the shared region (and
			 * lose the "global" pmap mappings, if applicable).
			 *
			 * Tell the pmap layer that we're "clean" wrt nesting.
			 */
			pmap_unnest_options(map->pmap, e_start, e_end - e_start,
			    PMAP_UNNEST_CLEAN);
			entry->use_pmap = false;
		} else {
			pmap_unnest(map->pmap, e_start, e_end - e_start);
			entry->use_pmap = false;
		}
	} else if (entry->vme_kernel_object ||
	    VME_OBJECT(entry) == compressor_object) {
		/*
		 * nothing to do
		 */
	} else if (map->mapped_in_other_pmaps &&
	    os_ref_get_count_raw(&map->map_refcnt) != 0) {
		vm_object_pmap_protect_options(VME_OBJECT(entry),
		    VME_OFFSET(entry), e_end - e_start, PMAP_NULL, PAGE_SIZE,
		    e_start, VM_PROT_NONE, PMAP_OPTIONS_REMOVE);
	} else if ((VME_OBJECT(entry) != VM_OBJECT_NULL) ||
	    map->pmap == kernel_pmap) {
		/* Remove translations associated
		 * with this range unless the entry
		 * does not have an object, or
		 * it's the kernel map or a descendant
		 * since the platform could potentially
		 * create "backdoor" mappings invisible
		 * to the VM. It is expected that
		 * objectless, non-kernel ranges
		 * do not have such VM invisible
		 * translations.
		 */
		vm_map_address_t remove_start = e_start;
		vm_map_address_t remove_end = e_end;
#if MACH_ASSERT
		/*
		 * Prevent panics in pmap_remove() from some vm test code
		 * which uses virtual address ranges that pmap disallows.
		 */
		if (thread_get_test_option(test_option_vm_map_clamp_pmap_remove)) {
			vm_map_clamp_to_pmap(map, &remove_start, &remove_end);
		}
#endif /* MACH_ASSERT */
		pmap_remove(map->pmap, remove_start, remove_end);
	}

#if DEBUG
	/*
	 * All pmap mappings for this map entry must have been
	 * cleared by now.
	 */
	assert(pmap_is_empty(map->pmap, e_start, e_end));
#endif /* DEBUG */

	/*
	 * Step 4: Perform the deletion itself
	 */

	if (entry->iokit_acct) {
		/* alternate accounting */
		DTRACE_VM4(vm_map_iokit_unmapped_region,
		    vm_map_t, map,
		    vm_map_offset_t, e_start,
		    vm_map_offset_t, e_end,
		    int, VME_ALIAS(entry));
		vm_map_iokit_unmapped_region(map, e_end - e_start);
		entry->iokit_acct = FALSE;
		entry->use_pmap = FALSE;
	}

	if (__improbable(entry->vme_permanent)) {
		/*
		 * A permanent entry can not be removed, so leave it
		 * in place but remove all access permissions.
		 */
		if (__improbable(vm_log_map_delete_permanent_prot_none)) {
			printf("%s:%d %d[%s] map %p entry %p [ 0x%llx - 0x%llx ] submap %d prot 0x%x/0x%x -> 0/0\n",
			    __FUNCTION__, __LINE__,
			    proc_selfpid(),
			    (get_bsdtask_info(current_task())
			    ? proc_name_address(get_bsdtask_info(current_task()))
			    : "?"),
			    map,
			    entry,
			    (uint64_t)e_start,
			    (uint64_t)e_end,
			    entry->is_sub_map,
			    entry->protection,
			    entry->max_protection);
		}
		DTRACE_VM6(vm_map_delete_permanent_prot_none,
		    vm_map_entry_t, entry,
		    vm_map_offset_t, e_start,
		    vm_map_offset_t, e_end,
		    vm_prot_t, entry->protection,
		    vm_prot_t, entry->max_protection,
		    int, VME_ALIAS(entry));
		entry->protection = VM_PROT_NONE;
		entry->max_protection = VM_PROT_NONE;
#ifdef __arm64e__
		entry->used_for_tpro = FALSE;
#endif
		return false;
	}

	assert(VM_MAP_PAGE_ALIGNED(e_start, FOURK_PAGE_MASK));
	assert(VM_MAP_PAGE_ALIGNED(e_end, FOURK_PAGE_MASK));
	if (VM_MAP_PAGE_MASK(map) >= PAGE_MASK) {
		assert(page_aligned(e_start));
		assert(page_aligned(e_end));
	}
	assert(entry->wired_count == 0);
	assert(entry->user_wired_count == 0);
	assert(!entry->vme_permanent);

	vm_map_ilk_lock(map);
	if (flags & VM_MAP_REMOVE_ZERO_FILL) {
		vm_map_entry_unlink_and_make_zero_copy(map, entry);
	} else {
		vm_map_entry_unlink_and_extend_sentinel(map, entry, sentinel);
	}
	vm_map_ilk_unlock(map);

	return true;
}

static kern_return_t
vm_map_delete_and_iunlock_internal(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vmr_flags_t             flags,
	kmem_guard_t            guard,
	vm_map_entry_t         *sentinel_out,
	vm_map_zap_t            zap,
	vm_map_lock_ctx_t       ctx_already_locked)
{
	kern_return_t           kr = KERN_SUCCESS;
	vmrl_ex_flags_t         vmrl_flags;
	vm_map_entry_t          sentinel;
	vm_map_entry_t          entry;
	vm_map_t                orig_map = map;
	bool                    already_locked = flags & VM_MAP_REMOVE_RANGE_LOCKED;
	VM_MAP_LOCK_CTX_DECLARE(ctx_local);
	vm_map_lock_ctx_t       ctx = already_locked ? ctx_already_locked : ctx_local;

	vmlp_api_start(VM_MAP_DELETE_AND_IUNLOCK);
	vmlp_range_event(map, start, end - start);

	/*
	 * Range cannot be both zero-filled and filled with a sentinel.
	 */
	assert(!((flags & VM_MAP_REMOVE_ZERO_FILL) && (flags & VM_MAP_REMOVE_TO_OVERWRITE)));

	if (map->corpse_source &&
	    !(flags & VM_MAP_REMOVE_TO_OVERWRITE) &&
	    !map->terminated) {
		/*
		 * The map is being used for corpses related diagnostics.
		 * So skip any entry removal to avoid perturbing the map state.
		 * The cleanup will happen in task_terminate_internal after the
		 * call to task_port_no_senders.
		 */
		vm_map_ilk_unlock(map);
		vmlp_api_end(VM_MAP_DELETE_AND_IUNLOCK, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	if (start & VM_MAP_PAGE_MASK(map)) {
		__vm_map_delete_misaligned_panic(map, start, end);
	}

	/*
	 *	Find the start of the region.
	 *
	 *	If in a superpage, extend the range
	 *	to include the start of the mapping.
	 */
	while (vm_map_lookup_or_next(map, start, &entry)) {
		if (entry->superpage_size && (start & ~SUPERPAGE_MASK)) {
			start = SUPERPAGE_ROUND_DOWN(start);
		} else {
			break;
		}
	}
	if (entry != vm_map_to_entry(map) && entry->superpage_size) {
		end = SUPERPAGE_ROUND_UP(end);
	}

	vmrl_flags = VMRL_EX_ILK_LOCKED | VMRL_EX_NO_PMAP_UNNEST;
	if (map->terminated && !(flags & VM_MAP_REMOVE_TO_OVERWRITE)) {
		/*
		 * When the map is terminated, we want to allow streaming to make
		 * it easier for vm_map_terminate to proceed.
		 * We can't do this when VM_MAP_REMOVE_TO_OVERWRITE because we need
		 * atomic locking to be able to create a sentinel to return to the
		 * caller.
		 */
		vmrl_flags |= VMRL_EX_STREAM | VMRL_EX_NO_MIN_MAX_CHECK;
	} else {
		/*
		 * allow-holes, so that we can handle them specially
		 * during our preflight (and possibly actually fail).
		 */
		vmrl_flags |= VMRL_EX_ATOMIC_ALLOW_HOLES;
	}
	if (flags & VM_MAP_REMOVE_INTERRUPTIBLE) {
		/*
		 * We don't allow this flag for the kernel map. That's because
		 * the only previous client that used it would have directly
		 * lead to a memory leak, and we usually panic on deletion errors
		 * on the kernel map.
		 */
		assert(!vm_kernel_map_is_kernel(map));
		vmrl_flags |= VMRL_EX_INTERRUPTIBLE;
	}

	if (!already_locked) {
		vm_map_lock_ctx_set_preflight(
			ctx,
			^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
			return vm_map_delete_preflight(vctx, vme, flags, guard);
		});

		kr = vm_map_range_ex_lock(ctx, &map, start, end, vmrl_flags);
	} else {
		/*
		 * Caller already locked the range; pretend like we just locked it.
		 */
		vm_map_ilk_unlock(map);
		kr = KERN_SUCCESS;
	}
	if (kr == KERN_SUCCESS) {
		if (flags & VM_MAP_REMOVE_TO_OVERWRITE) {
			/* initially zero-length, will be extended by vm_map_delete_handle_entry */
			sentinel = vm_map_entry_create_sentinel_locked(orig_map, start, start);
			*sentinel_out = sentinel;
		}

		while ((entry = vm_map_range_ex_pop_with_error(ctx, &kr))) {
			if (vm_map_lock_ctx_is_descended(ctx)) {
				/*
				 * Entering an entry into a transparent submap through a parent
				 * map is not supported today. Entry insertion should be done
				 * via the submap pointer directly.
				 */
				panic("Attempt to delete through transparent submap.");
			}
			if (vm_map_delete_handle_entry(ctx->vmlc_map, entry, sentinel, flags)) {
				if (ctx->vmlc_map != orig_map) {
					/*
					 * wait_for_space wakeup below does not
					 * work when deleting from a transparent
					 * submap through the parent map.
					 */
					assert(ctx->vmlc_map->wait_for_space == false);
				}
				if (VME_IS_SENTINEL(entry)) {
					/*
					 * We don't want to restore sentinel entries, there's no
					 * point in adding it to the zap list. Just free it now.
					 */
					vm_map_entry_free_locked(ctx->vmlc_map, entry);
				} else {
					vm_map_zap_append(zap, entry);
				}
			} else {
				if (flags & VM_MAP_REMOVE_TO_OVERWRITE) {
					panic("Fixed overwrite failed to delete entry.");
				}
				vm_entry_unlock_exclusive(ctx->vmlc_map, entry);
			}
		}
		if (kr != KERN_SUCCESS) {
			assert(kr == KERN_ABORTED);
			assert(vmrl_is_streaming(ctx));
			/*
			 * We were doing a streaming deletion and got interrupted.
			 * Just bail out of the delete being done and return.
			 */
		}

		/*
		 * Pass NULL (skip map-is-scribbled check) if using external context.
		 */
		vm_map_range_ex_unlock(ctx, already_locked ? NULL : &map);

		if (map->wait_for_space) {
			thread_wakeup((event_t) map);
		}
	} else if (vmrl_is_kernel_pmap(ctx)) {
		__vm_map_delete_failed_panic(ctx, kr);
	} else if (kr == KERN_INVALID_ADDRESS && vmrl_is_streaming(vmrl_flags) &&
	    !(flags & VM_MAP_REMOVE_GAPS_FAIL)) {
		assert(map->terminated);
		assert(!(flags & VM_MAP_REMOVE_TO_OVERWRITE));
		/*
		 * Streaming lock fails on empty range, but we rewrite that to a
		 * success because the range is deleted.
		 */
		kr = KERN_SUCCESS;
	} else if (kr == KERN_INVALID_ADDRESS) {
		DTRACE_VM3(kern_vm_deallocate_gap,
		    vm_map_offset_t, start,
		    vm_map_offset_t, start,
		    vm_map_offset_t, end);

		if (flags & VM_MAP_REMOVE_GAPS_FAIL) {
			kr = KERN_INVALID_VALUE;
		} else {
			vm_map_guard_exception(map, start, kGUARD_EXC_DEALLOC_GAP);
			kr = KERN_SUCCESS;
		}
	}

	vmlp_api_end(VM_MAP_DELETE_AND_IUNLOCK, kr);

	return kr;
}

/*
 *	vm_map_delete_and_iunlock:	[ internal use only ]
 *
 *	Deallocates the given address range from the target map.
 *	Removes all user wirings. Unwires one kernel wiring if
 *	VM_MAP_REMOVE_KUNWIRE is set.
 *
 *	Sleeps interruptibly if VM_MAP_REMOVE_INTERRUPTIBLE is set.
 *
 *	When the map is a kernel map, then any error in removing mappings
 *	will lead to a panic so that clients do not have to repeat the panic
 *	code at each call site.
 *
 *	This routine is called with the interlock locked and returns with it
 *	unlocked.
 */
__static_testable kern_return_t
vm_map_delete_and_iunlock(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vmr_flags_t             flags,
	kmem_guard_t            guard,
	vm_map_entry_t         *sentinel_out,
	vm_map_zap_t            zap)
{
	assert(!(flags & VM_MAP_REMOVE_RANGE_LOCKED));
	return vm_map_delete_and_iunlock_internal(
		map,
		start,
		end,
		flags,
		guard,
		sentinel_out,
		zap,
		NULL);
}

/*
 * vm_map_delete_and_iunlock_with_range_locked:		[ internal use only ]
 *
 * Variant of vm_map_delete_and_iunlock to be used when the range being deleted
 * is already locked exclusively by the caller.
 *
 * Upon success, ctx_already_locked will have all entries removed from its
 * purview, and will be unlocked. Note that the entries themselves will remain
 * locked despite being unlinked from the map.
 */
static kern_return_t
vm_map_delete_and_iunlock_with_range_locked(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vmr_flags_t             flags,
	kmem_guard_t            guard,
	vm_map_entry_t         *sentinel_out,
	vm_map_zap_t            zap,
	vm_map_lock_ctx_t       ctx_already_locked)
{
	/*
	 * Verify that the range is actually locked, and it's OK to delete.
	 */
	assert(vmrl_is_atomic(ctx_already_locked));
	assert(vmrl_is_exclusive(ctx_already_locked));

	vm_map_entry_t entry = VM_MAP_ENTRY_NULL;
	vm_map_offset_t ctx_start = ~0, ctx_end = 0;
	while ((entry = vm_map_range_atomic_next(ctx_already_locked))) {
		/*
		 * Verify this entry can be deleted, since we should not trust the
		 * caller to have done this.
		 */
		kern_return_t kr = vm_map_delete_preflight(
			ctx_already_locked,
			entry,
			flags,
			guard);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		/*
		 * Verify that exactly the range specified is locked, and that map is
		 * correct for every entry, because vm_map_delete_and_iunlock_internal
		 * will use it prior to where it would ordinarily lock the range.
		 */
		vm_map_offset_t entry_start, entry_end;
		assert(vm_map_lock_ctx_get_map(ctx_already_locked) == map);
		vm_map_lock_ctx_bounds(ctx_already_locked, &entry_start, &entry_end, NULL);

		ctx_start = MIN(ctx_start, entry_start);
		ctx_end = MAX(ctx_end, entry_end);
	}
	if (ctx_start != start || ctx_end != end) {
		return KERN_INVALID_ADDRESS;
	}
	vm_map_range_atomic_reset(ctx_already_locked);

	return vm_map_delete_and_iunlock_internal(
		map,
		start,
		end,
		flags | VM_MAP_REMOVE_RANGE_LOCKED,
		guard,
		sentinel_out,
		zap,
		ctx_already_locked);
}


void
vm_map_remove_entry(vm_map_t map, vm_map_entry_t entry, vmr_flags_t flags)
{
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);
	assert(!entry->vme_permanent);

	(void)vm_map_delete_handle_entry(map, entry, VM_MAP_ENTRY_NULL, flags);
}

kern_return_t
vm_map_remove_and_iunlock(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end,
	vmr_flags_t     flags,
	kmem_guard_t    guard)
{
	kern_return_t ret;
	VM_MAP_ZAP_DECLARE(zap);

	vmlp_api_start(VM_MAP_REMOVE_AND_IUNLOCK);
	vmlp_range_event(map, start, end - start);

	assert(!(flags & VM_MAP_REMOVE_TO_OVERWRITE));

	ret = vm_map_delete_and_iunlock(map, start, end, flags, guard, NULL, &zap);
	vm_map_zap_dispose(map, &zap);

	vmlp_api_end(VM_MAP_REMOVE_AND_IUNLOCK, ret);
	return ret;
}

/*
 *	vm_map_remove_guard:
 *
 *	Remove the given address range from the target map.
 *	This is the exported form of vm_map_delete.
 */
kern_return_t
vm_map_remove_guard(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vmr_flags_t             flags,
	kmem_guard_t            guard)
{
	kern_return_t ret;
	vmlp_api_start(VM_MAP_REMOVE_GUARD);
	vm_map_ilk_lock(map);
	vmlp_range_event(map, start, end - start);

	ret = vm_map_remove_and_iunlock(map, start, end, flags, guard);
	vmlp_api_end(VM_MAP_REMOVE_GUARD, ret);
	return ret;
}


/*
 *  vm_map_setup:
 *
 *  Perform any required setup on a new task's map. Must be called before the task
 *  is enabled for IPC access, since after this point other threads may be able
 *  to look up the task port and make VM API calls.
 */
void
vm_map_setup(vm_map_t map, task_t task)
{
	/*
	 * map does NOT take a reference on owning_task. If the map has terminated,
	 * it is possible that the pointer is NULL, so reads of owning_task must
	 * happen under the map lock and explicitly check for NULL.
	 */
	vm_map_ilk_lock(map);
	assert(!map->owning_task);
	map->owning_task = task;
	vm_map_ilk_unlock(map);
#if CONFIG_DEFERRED_RECLAIM
	vm_deferred_reclamation_metadata_t vdrm = task->deferred_reclamation_metadata;
	if (vdrm) {
		vm_deferred_reclamation_task_fork_register(vdrm);
	}
#endif /* CONFIG_DEFERRED_RECLAIM */
}

/*
 *	vm_map_terminate:
 *
 *	Clean out a task's map.
 */
kern_return_t
vm_map_terminate(
	vm_map_t        map)
{
	vmlp_api_start(VM_MAP_TERMINATE);
	vmlp_range_event_all(map);

	vm_map_ilk_lock(map);

	map->terminated = true;
	map->owning_task = NULL;

	(void)vm_map_remove_and_iunlock(map, map->min_offset, map->max_offset,
	    VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);

	vmlp_api_end(VM_MAP_TERMINATE, KERN_SUCCESS);

	return KERN_SUCCESS;
}

/*
 *	Routine:	vm_map_copy_allocate
 *
 *	Description:
 *		Allocates and initializes a map copy object.
 */
__static_testable vm_map_copy_t
vm_map_copy_allocate(uint16_t type, uint32_t pageshift)
{
	vm_map_copy_t new_copy;

	new_copy = zalloc_id(ZONE_ID_VM_MAP_COPY, Z_WAITOK | Z_ZERO);
	new_copy->type = type;
	if (type == VM_MAP_COPY_ENTRY_LIST) {
		vm_map_copy_store_init(new_copy, pageshift);
	}
	return new_copy;
}

/*
 *	Routine:	vm_map_copy_discard
 *
 *	Description:
 *		Dispose of a map copy object (returned by
 *		vm_map_copyin).
 */
void
vm_map_copy_discard(
	vm_map_copy_t   copy)
{
	if (copy == VM_MAP_COPY_NULL) {
		return;
	}

	/*
	 * Assert that the vm_map_copy is coming from the right
	 * zone and hasn't been forged
	 */
	vm_map_copy_require(copy);

	switch (copy->type) {
	case VM_MAP_COPY_ENTRY_LIST:
		while (vm_map_copy_first_entry(copy) !=
		    vm_map_copy_to_entry(copy)) {
			vm_map_entry_t  entry = vm_map_copy_first_entry(copy);

			vm_map_copy_store_remove(copy, entry);
			vm_map_copy_entry_free(copy, entry);
		}
		break;
	case VM_MAP_COPY_KERNEL_BUFFER:

		/*
		 * The vm_map_copy_t and possibly the data buffer were
		 * allocated by a single call to kalloc_data(), i.e. the
		 * vm_map_copy_t was not allocated out of the zone.
		 */
		if ((copy->size > msg_ool_size_small && !copy->cpy_uses_large_buffers) || copy->offset) {
			panic("Invalid vm_map_copy_t sz:%lld, ofst:%lld",
			    (long long)copy->size, (long long)copy->offset);
		}
		kfree_data(copy->cpy_kdata, copy->size);
	}
	zfree_id(ZONE_ID_VM_MAP_COPY, copy);
}

#if XNU_PLATFORM_MacOSX

__exported
extern vm_map_copy_t vm_map_copy_copy(vm_map_copy_t copy);

/*
 *	Routine:	vm_map_copy_copy
 *
 *	Description:
 *			Move the information in a map copy object to
 *			a new map copy object, leaving the old one
 *			empty.
 *
 *			This is used by kernel routines that need
 *			to look at out-of-line data (in copyin form)
 *			before deciding whether to return SUCCESS.
 *			If the routine returns FAILURE, the original
 *			copy object will be deallocated; therefore,
 *			these routines must make a copy of the copy
 *			object and leave the original empty so that
 *			deallocation will not fail.
 */
vm_map_copy_t
vm_map_copy_copy(
	vm_map_copy_t   copy)
{
	vm_map_copy_t   new_copy;

	if (copy == VM_MAP_COPY_NULL) {
		return VM_MAP_COPY_NULL;
	}

	/*
	 * Assert that the vm_map_copy is coming from the right
	 * zone and hasn't been forged
	 */
	vm_map_copy_require(copy);

	/*
	 * Allocate a new copy object, and copy the information
	 * from the old one into it.
	 */

	new_copy = zalloc_id(ZONE_ID_VM_MAP_COPY, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	memcpy((void *) new_copy, (void *) copy, sizeof(struct vm_map_copy));
#if __has_feature(ptrauth_calls)
	if (copy->type == VM_MAP_COPY_KERNEL_BUFFER) {
		new_copy->cpy_kdata = copy->cpy_kdata;
	}
#endif

	if (copy->type == VM_MAP_COPY_ENTRY_LIST) {
		/*
		 * The links in the entry chain must be
		 * changed to point to the new copy object.
		 */
		vm_map_copy_first_entry(copy)->vme_prev =
		    vm_map_copy_to_entry(new_copy);
		vm_map_copy_last_entry(copy)->vme_next =
		    vm_map_copy_to_entry(new_copy);
	}

	/*
	 * Change the old copy object into one that contains
	 * nothing to be deallocated.
	 */
	bzero(copy, sizeof(struct vm_map_copy));
	copy->type = VM_MAP_COPY_KERNEL_BUFFER;

	/*
	 * Return the new object.
	 */
	return new_copy;
}

#endif /* XNU_PLATFORM_MacOSX */

static boolean_t
vm_map_entry_is_overwritable(
	vm_map_t        dst_map __unused,
	vm_map_entry_t  entry)
{
	assert(!entry->is_sub_map);

	if (!(entry->protection & VM_PROT_WRITE)) {
		/* can't overwrite if not writable */
		return FALSE;
	}
#if !__x86_64__
	assert_vm_map_ilk_owned(dst_map, LCK_RW_TYPE_ANY);
	if (entry->used_for_jit &&
	    vm_map_cs_enforcement(dst_map) &&
	    !dst_map->cs_debugged) {
		/*
		 * Can't overwrite a JIT region while cs_enforced
		 * and not cs_debugged.
		 */
		return FALSE;
	}

#if __arm64e__
	/* Do not allow overwrite HW assisted TPRO entries */
	if (entry->used_for_tpro) {
		return FALSE;
	}
#endif /* __arm64e__ */

	if (entry->vme_permanent) {
		/*
		 * Do not allow overwriting of a "permanent"
		 * entry.
		 */
		DTRACE_VM6(vm_map_delete_permanent_deny_overwrite,
		    vm_map_entry_t, entry,
		    vm_map_offset_t, entry->vme_start,
		    vm_map_offset_t, entry->vme_end,
		    vm_prot_t, entry->protection,
		    vm_prot_t, entry->max_protection,
		    int, VME_ALIAS(entry));
		return FALSE;
	}
#endif /* !__x86_64__ */

#if HAS_MTE
	/* Do not allow overwriting of MTE objects */
	if (VME_OBJECT(entry) && vm_object_is_mte_mappable(VME_OBJECT(entry))) {
		return FALSE;
	}
#endif /* HAS_MTE */

	return TRUE;
}

static kern_return_t
vm_map_copy_overwrite_preflight(vm_map_t map, vm_map_entry_t entry, bool interruptible)
{
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);
	if (entry->is_sub_map) {
		/* copy_overwrite(constant submap) is not supported */
		return KERN_PROTECTION_FAILURE;
	}

	if (!vm_map_entry_is_overwritable(map, entry)) {
		return KERN_PROTECTION_FAILURE;
	}

	if (interruptible &&
	    ((VME_OBJECT(entry) != VM_OBJECT_NULL) &&
	    ((!VME_OBJECT(entry)->internal) ||
	    (VME_OBJECT(entry)->true_share)))) {
		/* Not allowed to have interruptible and external objects */
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}


int vm_map_copy_overwrite_aligned_src_not_internal = 0;
int vm_map_copy_overwrite_aligned_src_not_symmetric = 0;
int vm_map_copy_overwrite_aligned_src_large = 0;

/*
 * Resolve the entry for copy overwrite. This does what the
 * VMRL_RESOLVE_COW_AND_OBJ flag would, but doesn't need to deal with submaps.
 * returns:
 * - true if the entry was changed to do so.
 * - false if nothing changed
 */
static bool
vm_map_copy_overwrite_resolve_entry(vm_map_t map, vm_map_entry_t entry)
{
	bool changed_entry = false;

	assert(!entry->is_sub_map);

	if (entry->needs_copy) {
		vm_map_entry_lock_resolve_symmetric_cow(map, entry);
		changed_entry = true;
	}

	if (VME_OBJECT(entry) == VM_OBJECT_NULL) {
		vm_map_entry_lock_allocate_object(entry, vm_map_maybe_serial_id(map));
		changed_entry = true;
	}

	return changed_entry;
}


/*
 * Verify that after a page is faulted, it can be copied to at the physical level
 * This checks the entry does not need to be stablilized, and then makes sure the
 * same physical page is present in the object as the one already wired.
 * This function is expected to be called with no object locks held, but may return
 * with the object lock corresponding to the entry held.
 *
 * Returns:
 * - false if we should not do the physical page copy because something has changed.
 *         The object corresponding to the entry is unlocked upon return.
 * - true if we can do the physical page copy.  The object corresponding to the
 *        entry is left locked exclusively upon return.  The caller must unlock
 *        the object after completing the copy.
 */
bool
vm_map_copy_overwrite_can_page_copy(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_object_offset_t      offset,
	vm_page_t               old_page,
	vm_object_t             old_copy_object,
	uint64_t                old_copy_version)
{
	vm_object_t object = VME_OBJECT(entry);
	vm_map_size_t entry_size = entry->vme_end - entry->vme_start;
	vm_page_t entry_page;

	/* If we needed to stabilize the entry, we shouldn't do the page copy */
	if (vm_map_copy_overwrite_resolve_entry(map, entry)) {
		return false;
	}

	/* Make sure the offset is within the view of the entry */
	if ((offset < VME_OFFSET(entry)) || (offset >= (VME_OFFSET(entry) + entry_size))) {
		return false;
	}

	assert(object != VM_OBJECT_NULL);

	vm_object_lock(object);
	entry_page = vm_page_lookup(object, vm_object_trunc_page(offset));

	/* Make sure the page is the same one */
	if (entry_page != old_page) {
		vm_object_unlock(object);
		return false;
	}

	/* And verify the CoW status of the object is unchanged */
	if (object->vo_copy != old_copy_object ||
	    object->vo_copy_version != old_copy_version) {
		vm_object_unlock(object);
		return false;
	}

	/* Return with the object locked so that the caller can safely do the copy. */
	return true;
}


/*!
 * @discussion
 * This function tries to overwrite memory at a given address with copy_entry.
 * It will not necessarily overwrite the entire destination entry at one time,
 * or consume the entire copy_entry.
 * This uses the slow physical copy @c vm_fault_copy provides.
 *
 * NOTE: the ctx may be unlocked and the lock reacquired.
 *
 * Callers of this function must call vm_map_copy_require on
 * previously created vm_map_copy_t or pass a newly created
 * one to ensure that it hasn't been forged.
 *
 * We attempt to copy as much memory in one go as possibly, however
 * vm_fault_copy copies within 1 memory object so we have to find the smaller
 * of "the copy size (copy->size)", "source object data size (src_size)",
 * and "target object data size (dst_size)".
 * The source (copy) and target (dst) object should be one map entry
 *
 * @param ctx          the lock ctx
 * @param dst_addr     the address to start the copy at
 * @param dst_entry_p  (in/out) a pointer to the entry being copied into
 * @param copy         the vm_map_copy_t to copy from
 * @param copy_entry   the entry to copy from
 * @param size_copied  (out) how much data was copied
 *
 * @returns
 * KERN_SUCCESS       *size_copied data was copied succesfully
 * other              some invalid error occured
 */
static kern_return_t
vm_map_entry_copy_overwrite_slow_copy(
	vm_map_lock_ctx_t ctx,
	vm_map_address_t  dst_addr,
	vm_map_entry_t   *const dst_entry_p, /* IN/OUT */
	vm_map_copy_t     copy,
	vm_map_entry_t    copy_entry,
	vm_map_size_t    *const size_copied /* OUT */)
{
	kern_return_t   kr;
	vm_map_t        dst_map = ctx->vmlc_map;
	vm_map_offset_t dst_offset;
	vm_object_t     dst_object;
	vm_map_size_t   copy_size;
	vm_map_entry_t  dst_entry = *dst_entry_p;
	vm_map_offset_t src_offset = copy->offset - copy_entry->vme_start +
	    VME_OFFSET(copy_entry);
	vm_map_size_t   src_size = copy_entry->vme_end - copy->offset;
	vm_map_size_t   dst_size = dst_entry->vme_end - dst_addr;

	VM_ENTRY_ASSERT_EXCL_OWNER(dst_entry);
	assert(!dst_entry->is_sub_map);

	/*
	 * The size of this copy should be the minimum of the space available
	 * in either the src entry, the dst entry, and the total copy size.
	 */
	copy_size = MIN(dst_size, src_size);
	copy_size = MIN(copy_size, copy->size);

	/*
	 * First, let's resolve the entry like the VMRL_RESOLVE_COW_AND_OBJ flag would,
	 * but we don't want the lock to do that because sometimes we would
	 * replace the object in the aligned paths.
	 */
	vm_map_copy_overwrite_resolve_entry(dst_map, dst_entry);

	dst_object = VME_OBJECT(dst_entry);
	dst_offset = VME_OFFSET(dst_entry) + dst_addr - dst_entry->vme_start;

	/*
	 * Take an object reference so vm_fault_copy can release the entry lock
	 */
	vm_object_reference(dst_object);

	/*
	 * Copy as much as possible in one pass
	 */
	kr = vm_fault_copy(
		ctx,
		VME_OBJECT(copy_entry),
		src_offset,
		&copy_size,
		&dst_entry,
		dst_object,
		dst_offset,
		THREAD_UNINT);
	*dst_entry_p = dst_entry;

	/*
	 *	Release the object reference
	 */
	vm_object_deallocate(dst_object);

	/*
	 *	If an error occurred, return it now
	 */
	if (kr != KERN_SUCCESS) {
		*size_copied = 0;
		return kr;
	}

	*size_copied = copy_size;
	return KERN_SUCCESS;
}


/*!
 * @brief
 * Determine if copy_overwrite should transfer the object between two
 * entries or do a slow physical copy.
 * This considers various tradeoffs such as the size of the copy,
 * the copy_strategies of the objects involved, and the internal/externalness.
 *
 * This function assumes various permissions checks have already been done.
 */
static bool
vm_map_copy_overwrite_should_transfer_object(
	vm_map_t        dst_map,
	vm_map_entry_t  dst_entry,
	vm_map_entry_t  copy_entry)
{
#if XNU_TARGET_OS_OSX
#define __TRADEOFF1_OBJ_SIZE (64 * 1024 * 1024) /* 64 MB */
#define __TRADEOFF1_COPY_SIZE (128 * 1024)      /* 128 KB */
	if (VME_OBJECT(copy_entry) != VM_OBJECT_NULL &&
	    VME_OBJECT(copy_entry)->vo_size >= __TRADEOFF1_OBJ_SIZE &&
	    copy_entry->vme_end - copy_entry->vme_start <= __TRADEOFF1_COPY_SIZE) {
		/*
		 * Virtual vs. Physical copy tradeoff #1.
		 *
		 * Copying only a few pages out of a large object:
		 * do a physical copy instead of a virtual copy,
		 * to avoid possibly keeping the entire large object alive
		 * because of those few copy-on-write pages.
		 */
		vm_map_copy_overwrite_aligned_src_large++;
		return false;
	}
#endif /* XNU_TARGET_OS_OSX */

	if ((dst_map->pmap != kernel_pmap) &&
	    (VME_ALIAS(dst_entry) >= VM_MEMORY_MALLOC) &&
	    (VME_ALIAS(dst_entry) <= VM_MEMORY_MALLOC_MEDIUM)) {
		vm_object_t new_object, new_shadow;

		/*
		 * We're about to map something over a mapping
		 * established by malloc()...
		 */
		new_object = VME_OBJECT(copy_entry);
		if (new_object != VM_OBJECT_NULL) {
			vm_object_lock_shared(new_object);
		}
		while (new_object != VM_OBJECT_NULL &&
#if XNU_TARGET_OS_OSX
		    !new_object->true_share &&
		    new_object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC &&
#endif /* XNU_TARGET_OS_OSX */
		    new_object->internal) {
			new_shadow = new_object->shadow;
			if (new_shadow == VM_OBJECT_NULL) {
				break;
			}
			vm_object_lock_shared(new_shadow);
			vm_object_unlock(new_object);
			new_object = new_shadow;
		}
		if (new_object != VM_OBJECT_NULL) {
			if (!new_object->internal) {
				/*
				 * The new mapping is backed by an
				 * external object. We don't want
				 * malloc'ed memory to be replaced with
				 * such a non-anonymous mapping, so
				 * let's go off the optimized path...
				 */
				vm_map_copy_overwrite_aligned_src_not_internal++;
				vm_object_unlock(new_object);
				return false;
			}
#if XNU_TARGET_OS_OSX
			if (new_object->true_share ||
			    new_object->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC) {
				/*
				 * Same if there's a "true_share" object
				 * in the shadow chain, or an object
				 * with a non-default (SYMMETRIC) copy
				 * strategy.
				 */
				vm_map_copy_overwrite_aligned_src_not_symmetric++;
				vm_object_unlock(new_object);
				return false;
			}
#endif /* XNU_TARGET_OS_OSX */
			vm_object_unlock(new_object);
		}
		/*
		 * The new mapping is still backed by anonymous
		 * (internal) memory, so it's OK to substitute it for
		 * the original malloc() mapping.
		 */
	}
	return true;
}


/*!
 * @brief
 * This function transfers an object from one entry to another.
 *
 * Callers of this function must have already checked it is valid to
 * transfer the object before calling this.
 */
static void
vm_map_copy_overwrite_transfer_object(
	vm_map_t        dst_map,
	vm_map_entry_t  dst_entry,
	vm_map_entry_t  copy_entry)
{
	vm_object_t old_object = VME_OBJECT(dst_entry);

	assert(!dst_entry->is_sub_map);
	assert(!copy_entry->is_sub_map);
	assert(!dst_map->mapped_in_other_pmaps);
	assert3u(dst_entry->user_wired_count, ==, 0);
	assert3u(dst_entry->wired_count, ==, 0);

	/* transfer the object to the entry */
	if (old_object != VM_OBJECT_NULL) {
		assert3u(old_object->copy_strategy, ==, MEMORY_OBJECT_COPY_SYMMETRIC);
		assert(!dst_entry->vme_permanent);
		pmap_remove(dst_map->pmap,
		    dst_entry->vme_start,
		    dst_entry->vme_end);
		vm_object_deallocate(old_object);
	}

	if (dst_entry->iokit_acct) {
		/* keep using iokit accounting */
		dst_entry->use_pmap = FALSE;
	} else {
		/* use pmap accounting */
		dst_entry->use_pmap = TRUE;
	}
	vm_object_reference(VME_OBJECT(copy_entry));
	VME_OBJECT_SET(dst_entry, VME_OBJECT(copy_entry), false, 0);
	dst_entry->needs_copy = copy_entry->needs_copy;
	dst_entry->wired_count = 0;
	dst_entry->user_wired_count = 0;
	VME_OFFSET_SET(dst_entry, VME_OFFSET(copy_entry));
}


/*!
 * @discussion
 * This function tries to overwrite an entry with a passed in copy_entry.
 * It tries to overwrite memory from [dst_addr, dst_addr + copy_entry_size).
 * or [dst_addr, dst_entry->vme_end), whichever comes first.
 *
 * In the common cases, it is able to do so with an optimization that just
 * replaces the object of the old entry.
 * In more complicated cases, it is forced to revert to a physical copy
 * (@c vm_map_entry_copy_overwrite_slow_copy). The physical copy can overwrite
 * only part of the requested region. The size_copied parameter says how much
 * data was copied.
 *
 * NOTE: the ctx may be unlocked and the lock reacquired.
 *
 * Callers of this function must call vm_map_copy_require on
 * previously created vm_map_copy_t or pass a newly created
 * one to ensure that it hasn't been forged.
 *
 * @param ctx          the lock ctx
 * @param dst_addr     the address to copy to
 * @param dst_entry_p  (in/out) a pointer to the entry being copied into
 * @param copy         the vm_map_copy_t to copy from
 * @param copy_entry   the entry to copy from
 * @param size_copied  (out) how much data was copied
 *
 * @returns
 * KERN_SUCCESS       *size_copied data was copied succesfully
 * other              some invalid error occured
 */
static kern_return_t
vm_map_entry_copy_overwrite_aligned(
	vm_map_lock_ctx_t ctx,
	vm_map_address_t  dst_addr,
	vm_map_entry_t   *const dst_entry_p, /* IN/OUT */
	vm_map_copy_t     copy,
	vm_map_entry_t    copy_entry,
	vm_map_size_t    *const size_copied /* OUT */)
{
	vm_map_t                dst_map = ctx->vmlc_map;
	vm_map_entry_t          dst_entry = *dst_entry_p;
	vm_map_size_t           dst_entry_size;
	vm_map_size_t           copy_entry_size;
	vm_object_t             object = VME_OBJECT(dst_entry);
	kern_return_t           kr;

	vmlp_api_start(VM_MAP_COPY_OVERWRITE_ALIGNED);

	VM_ENTRY_ASSERT_EXCL_OWNER(dst_entry);
	assert(!dst_entry->is_sub_map);

	vmlp_range_event_entry(dst_map, dst_entry);

	/*
	 * Clip dst_entry to dst_addr and copy_entry to copy->offset so that we
	 * can directly work off the contents of the entry
	 */
	vm_map_range_lock_clip_start(ctx, dst_entry, dst_addr);
	vm_map_copy_store_clip_start(copy, copy_entry, copy->offset);

	copy_entry_size = copy_entry->vme_end - copy_entry->vme_start;
	dst_entry_size = dst_entry->vme_end - dst_entry->vme_start;

	/*
	 * Clip dst_entry and copy_entry to match each other in size
	 * so we can do a more direct entry replacement
	 */
	if (copy_entry_size < dst_entry_size) {
		vm_map_range_lock_clip_end(ctx, dst_entry, dst_entry->vme_start + copy_entry_size);

		dst_entry_size = dst_entry->vme_end - dst_entry->vme_start;
	} else if (dst_entry_size < copy_entry_size) {
		vm_map_copy_store_clip_end(copy, copy_entry,
		    copy_entry->vme_start + dst_entry_size);
		copy_entry_size = dst_entry_size;
	}

	assert(dst_entry_size == copy_entry->vme_end - copy_entry->vme_start);
	assert(dst_addr == dst_entry->vme_start);
	assert(copy->offset == copy_entry->vme_start);

	/*
	 *	If the destination contains temporary unshared memory,
	 *	we can perform the copy by throwing it away and
	 *	installing the source data.
	 *
	 *	Exceptions for mappings with special semantics:
	 *	+ shared entries
	 *	+ "permanent" entries,
	 *	+ JIT regions,
	 *	+ TPRO regions,
	 *	+ pmap-specific protection policies,
	 *	+ VM objects that could be shared (i.e. not NULL and not COPY_SYMMETRIC)
	 */
	if (!dst_entry->is_shared &&
	    dst_entry->wired_count == 0 && /* wiring affects both entry and object */
	    !dst_entry->vme_permanent &&
	    !dst_entry->used_for_jit &&
#if __arm64e__
	    !dst_entry->used_for_tpro &&
#endif /* __arm64e__ */
	    !(dst_entry->protection & VM_PROT_EXECUTE) &&
	    !pmap_has_prot_policy(dst_map->pmap, dst_entry->translated_allow_execute, dst_entry->protection) &&
	    /* can only replace object if it could not have been shared */
	    (object == VM_OBJECT_NULL ||
	    object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC)) {
		vm_object_t         old_object = VME_OBJECT(dst_entry);
		vm_object_offset_t  old_offset = VME_OFFSET(dst_entry);

		assert(!dst_entry->vme_permanent);

		/*
		 * Ensure that the source and destination aren't identical
		 */
		if (old_object == VME_OBJECT(copy_entry) &&
		    old_offset == VME_OFFSET(copy_entry)) {
			goto aligned_copy_success;
		}

		/*
		 * We now know it's safe to transfer the object, but is it
		 * a good optimization?
		 */
		if (!vm_map_copy_overwrite_should_transfer_object(dst_map,
		    dst_entry, copy_entry)) {
			goto aligned_slow_copy;
		}

		vm_map_copy_overwrite_transfer_object(
			dst_map, dst_entry, copy_entry);

		/*
		 * we could try to push pages into the pmap at this point, BUT
		 * this optimization only saved on average 2 us per page if ALL
		 * the pages in the source were currently mapped
		 * and ALL the pages in the dest were touched, if there were fewer
		 * than 2/3 of the pages touched, this optimization actually cost more cycles
		 * it also puts a lot of pressure on the pmap layer w/r to mapping structures
		 */

aligned_copy_success:
		*dst_entry_p = dst_entry;
		*size_copied = dst_entry_size;
		vmlp_api_end(VM_MAP_COPY_OVERWRITE_ALIGNED, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

aligned_slow_copy:

	kr = vm_map_entry_copy_overwrite_slow_copy(ctx, dst_entry->vme_start,
	    dst_entry_p, copy, copy_entry, size_copied);
	vmlp_api_end(VM_MAP_COPY_OVERWRITE_ALIGNED, kr);
	return kr;
}


/*!
 * @brief
 * Overwrite a region of memory with a vm_map_copy_t.
 * The memory in the destination should already be allocated and writable.
 * This function will attempt to avoid physically copying the memory
 * if possible, but sometimes needs to fall back to slower physical
 * (@c vm_map_entry_copy_overwrite_slow_copy) copies.
 *
 * @param orig_dst_map        the map to be overwritten
 * @param dst_start_unaligned the address to do the overwrite
 * @param copy                the vm_map_copy_t to overwrite memory with
 * @param interruptible       this function cannot be interrupted
 * @param discard_on_success  this function will disacrd @c copy on success
 */
static kern_return_t
vm_map_copy_overwrite_impl(
	vm_map_t         orig_dst_map,
	vm_map_address_t dst_start_unaligned,
	vm_map_copy_t    copy,
	bool             interruptible,
#if HAS_MTE
	boolean_t                  sec_override,
#endif
	bool             discard_on_success)
{
	kern_return_t           kr;
	uint16_t                copy_page_shift;
	bool                    aligned = true;
	vm_map_address_t        dst_start_aligned;
	vm_map_address_t        dst_end_aligned, dst_end_unaligned;
	vm_map_address_t        dst_addr;
	vm_map_entry_t          dst_entry, copy_entry;
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vmlp_api_start(VM_MAP_COPY_OVERWRITE_IMPL);


	/*
	 *	Check for special kernel buffer allocated
	 *	by new_ipc_kmsg_copyin.
	 */
	if (copy->type == VM_MAP_COPY_KERNEL_BUFFER) {
		kr = vm_map_copyout_kernel_buffer(
			orig_dst_map,
			&dst_start_unaligned,
			copy,
			copy->size,
			TRUE,
#if HAS_MTE
			sec_override,
#endif
			discard_on_success);
		vmlp_api_end(VM_MAP_COPY_OVERWRITE_IMPL, kr);
		return kr;
	}

	assert(copy->type == VM_MAP_COPY_ENTRY_LIST);

	if (copy->size == 0) {
		if (discard_on_success) {
			vm_map_copy_discard(copy);
		}
		vmlp_api_end(VM_MAP_COPY_OVERWRITE_IMPL, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	copy_page_shift = copy->cpy_hdr.page_shift;

	/*
	 *	We have to trunc the destination
	 *	address and round the copy size or we'll end up
	 *	splitting entries in strange ways.
	 */
	dst_end_unaligned = dst_start_unaligned + copy->size;
	dst_end_aligned = vm_map_round_page(dst_start_unaligned + copy->size,
	    VM_MAP_PAGE_MASK(orig_dst_map));
	dst_start_aligned = vm_map_trunc_page(dst_start_unaligned, VM_MAP_PAGE_MASK(orig_dst_map));

	vm_map_lock_ctx_set_preflight(ctx,
	    ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
		return vm_map_copy_overwrite_preflight(vctx->vmlc_map, vme, interruptible);
	});

	kr = vm_map_range_ex_lock(ctx, &orig_dst_map, dst_start_aligned,
	    dst_end_aligned, VMRL_EX_STREAM_NO_HOLES);

	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_COPY_OVERWRITE_IMPL, kr);
		return kr;
	}

	copy_entry = vm_map_copy_first_entry(copy);
	dst_entry = vm_map_range_stream_next_with_error(ctx, &kr);
	dst_addr = dst_start_unaligned;

	/*
	 * Loop while we have an entry to copy into and we
	 * haven't copied everything.
	 *
	 * At all points in this loop:
	 * copy->offset is the address we are copying from (within the vm_map_copy_t).
	 * copy_entry is the entry we copy from. It contains copy->offset
	 *
	 * dst_addr is the address we are copying to.
	 * dst_entry is the entry we copy to, It contains dst_addr.
	 */
	while (dst_entry != NULL && dst_addr != dst_end_unaligned) {
		vm_map_size_t size_copied = 0;
		vm_map_t dst_map = ctx->vmlc_map;

		if (!VM_MAP_PAGE_ALIGNED(copy->size, VM_MAP_PAGE_MASK(dst_map)) ||
		    !VM_MAP_PAGE_ALIGNED(copy->offset, VM_MAP_PAGE_MASK(dst_map)) ||
		    !VM_MAP_PAGE_ALIGNED(dst_addr, VM_MAP_PAGE_MASK(dst_map)) ||
		    copy_page_shift != VM_MAP_PAGE_SHIFT(dst_map)) {
			aligned = false;
		}

		assert(dst_addr >= dst_entry->vme_start && dst_addr < dst_entry->vme_end);
		assert(copy->offset >= copy_entry->vme_start && copy->offset < copy_entry->vme_end);
		assert(copy_entry->vme_start < copy_entry->vme_end);
		assert(copy_entry != vm_map_copy_to_entry(copy));
		assert(dst_entry != vm_map_to_entry(dst_map));

		if (aligned) {
			kr = vm_map_entry_copy_overwrite_aligned(ctx, dst_addr,
			    &dst_entry, copy, copy_entry, &size_copied);
		} else {
			kr = vm_map_entry_copy_overwrite_slow_copy(ctx, dst_addr,
			    &dst_entry, copy, copy_entry, &size_copied);
		}

		if (kr != KERN_SUCCESS) {
			break;
		}

		/*
		 * Update the accounting of the addresses and copy_entry
		 */
		if (size_copied != 0) {
			/*
			 * If we made it to the end of the copy entry with
			 * this iteration, move on to the next.
			 */
			assert(copy->offset + size_copied <= copy_entry->vme_end);
			if (copy->offset + size_copied == copy_entry->vme_end) {
				copy_entry = copy_entry->vme_next;
			}

			dst_addr += size_copied;
			copy->offset += size_copied;
			copy->size -= size_copied;
		}

		/*
		 * VMRL_EX_STREAM_NO_HOLES should guarantee we won't have a hole
		 * show up in the map while we were unlocked
		 */
		assert(dst_entry->vme_start <= dst_addr);

		/*
		 * Find the next entry that contains dst_addr. Loop to deal
		 * with clipping/coalescing that may have happened.
		 */
		while (dst_entry && dst_addr >= dst_entry->vme_end) {
			dst_entry = vm_map_range_stream_next_with_error(ctx, &kr);
		}
	}

	vm_map_range_ex_unlock(ctx, &orig_dst_map);

	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_COPY_OVERWRITE_IMPL, kr);
		return kr;
	}

	if (discard_on_success) {
		vm_map_copy_discard(copy);
	}
	vmlp_api_end(VM_MAP_COPY_OVERWRITE_IMPL, KERN_SUCCESS);
	return KERN_SUCCESS;
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_copy_addr_size_sanitize(
	vm_map_t                map,
	vm_map_offset_ut        addr_u,
	vm_map_size_ut          size_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_offset_t        *addr,
	vm_map_offset_t        *end,
	vm_map_size_t          *size)
{
	vm_sanitize_flags_t flags = VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH |
	    VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES |
	    VM_SANITIZE_FLAGS_CHECK_ADDR_RANGE;

	return vm_sanitize_addr_size(addr_u, size_u,
	           vm_sanitize_caller, map,
	           flags,
	           addr, end, size);
}


/*
 *	Routine:	vm_map_copy_overwrite
 *
 *	Description:
 *		Copy the memory described by the map copy
 *		object (copy; returned by vm_map_copyin) onto
 *		the specified destination region (dst_map, dst_addr).
 *		The destination must be writeable.
 *
 *		Unlike vm_map_copyout, this routine actually
 *		writes over previously-mapped memory.  If the
 *		previous mapping was to a permanent (user-supplied)
 *		memory object, it is preserved.
 *
 *		The attributes (protection and inheritance) of the
 *		destination region are preserved.
 *
 *		If successful, consumes the copy object.
 *		Otherwise, the caller is responsible for it.
 *
 *	Implementation notes:
 *		To overwrite aligned temporary virtual memory, it is
 *		sufficient to remove the previous mapping and insert
 *		the new copy.  This replacement is done either on
 *		the whole region (if no permanent virtual memory
 *		objects are embedded in the destination region) or
 *		in individual map entries.
 *
 *		To overwrite permanent virtual memory , it is necessary
 *		to copy each page, as the external memory management
 *		interface currently does not provide any optimizations.
 *
 *		Unaligned memory also has to be copied.  It is possible
 *		to use 'vm_trickery' to copy the aligned data.  This is
 *		not done but not hard to implement.
 *
 *		Once a page of permanent memory has been overwritten,
 *		it is impossible to interrupt this function; otherwise,
 *		the call would be neither atomic nor location-independent.
 *		The kernel-state portion of a user thread must be
 *		interruptible.
 *
 *		It may be expensive to forward all requests that might
 *		overwrite permanent memory (vm_write, vm_copy) to
 *		uninterruptible kernel threads.  This routine may be
 *		called by interruptible threads; however, success is
 *		not guaranteed -- if the request cannot be performed
 *		atomically and interruptibly, an error indication is
 *		returned.
 *
 *		Callers of this function must call vm_map_copy_require on
 *		previously created vm_map_copy_t or pass a newly created
 *		one to ensure that it hasn't been forged.
 */
kern_return_t
vm_map_copy_overwrite(
	vm_map_t                dst_map,
	vm_map_offset_ut        dst_addr_u,
	vm_map_copy_t           copy,
	vm_map_size_ut          copy_size_u,
#if HAS_MTE
	boolean_t               sec_override,
#endif
	boolean_t               interruptible)
{
	vm_map_offset_t dst_addr, dst_end;
	vm_map_size_t   copy_size;
	vm_map_size_t   head_size, tail_size;
	vm_map_copy_t   head_copy, tail_copy;
	vm_map_offset_t head_addr, tail_addr;
	vm_map_entry_t  entry;
	kern_return_t   kr;
	vm_map_offset_t effective_page_mask, effective_page_size;
	uint16_t        copy_page_shift;
	enum vm_subsys_error_codes copy_err_code;
	unsigned int    err_line;

	vmlp_api_start(VM_MAP_COPY_OVERWRITE);

	head_size = 0;
	tail_size = 0;
	head_copy = NULL;
	tail_copy = NULL;
	head_addr = 0;
	tail_addr = 0;

	/*
	 *	Check for null copy object.
	 */
	if (copy == VM_MAP_COPY_NULL) {
		vmlp_api_end(VM_MAP_COPY_OVERWRITE, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	/*
	 * Sanitize any input parameters that are addr/size/prot/inherit
	 */
	kr = vm_map_copy_addr_size_sanitize(
		dst_map,
		dst_addr_u,
		copy_size_u,
		VM_SANITIZE_CALLER_VM_MAP_COPY_OVERWRITE,
		&dst_addr,
		&dst_end,
		&copy_size);
	if (__improbable(kr != KERN_SUCCESS)) {
		kern_return_t ret = vm_sanitize_get_kr(kr);
		vmlp_api_end(VM_MAP_COPY_OVERWRITE, ret);
		return ret;
	}

	vmlp_range_event(dst_map, dst_addr, copy_size);

	/*
	 * Assert that the vm_map_copy is coming from the right
	 * zone and hasn't been forged
	 */
	vm_map_copy_require(copy);

	if (interruptible ||
	    copy->type != VM_MAP_COPY_ENTRY_LIST) {
		/*
		 * We can't split the "copy" map if we're interruptible
		 * or if we don't have a "copy" map...
		 */
blunt_copy:
		kr = vm_map_copy_overwrite_impl(dst_map, dst_addr, copy,
		    interruptible,
#if HAS_MTE
		    sec_override,
#endif
		    true);

		if (kr) {
			ktriage_record(thread_tid(current_thread()), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_VM_COPYOVERWRITE_FULL_ERROR), kr /* arg */);
		}
		vmlp_api_end(VM_MAP_COPY_OVERWRITE, kr);
		return kr;
	}

	copy_page_shift = VM_MAP_COPY_PAGE_SHIFT(copy);
	if (copy_page_shift < PAGE_SHIFT ||
	    VM_MAP_PAGE_SHIFT(dst_map) < PAGE_SHIFT) {
		goto blunt_copy;
	}

	if (VM_MAP_PAGE_SHIFT(dst_map) < PAGE_SHIFT) {
		effective_page_mask = VM_MAP_PAGE_MASK(dst_map);
	} else {
		effective_page_mask = MAX(VM_MAP_PAGE_MASK(dst_map), PAGE_MASK);
		effective_page_mask = MAX(VM_MAP_COPY_PAGE_MASK(copy),
		    effective_page_mask);
	}
	effective_page_size = effective_page_mask + 1;

	if (copy_size < VM_MAP_COPY_OVERWRITE_OPTIMIZATION_THRESHOLD_PAGES * effective_page_size) {
		/*
		 * Too small to bother with optimizing...
		 */
		goto blunt_copy;
	}

	if ((dst_addr & effective_page_mask) !=
	    (copy->offset & effective_page_mask)) {
		/*
		 * Incompatible mis-alignment of source and destination...
		 */
		goto blunt_copy;
	}

	/*
	 * Proper alignment or identical mis-alignment at the beginning.
	 * Let's try and do a small unaligned copy first (if needed)
	 * and then an aligned copy for the rest.
	 */
	if (!vm_map_page_aligned(dst_addr, effective_page_mask)) {
		head_addr = dst_addr;
		head_size = (effective_page_size -
		    (copy->offset & effective_page_mask));
		head_size = MIN(head_size, copy_size);
	}
	if (!vm_map_page_aligned(copy->offset + copy_size,
	    effective_page_mask)) {
		/*
		 * Mis-alignment at the end.
		 * Do an aligned copy up to the last page and
		 * then an unaligned copy for the remaining bytes.
		 */
		tail_size = ((copy->offset + copy_size) &
		    effective_page_mask);
		tail_size = MIN(tail_size, copy_size);
		tail_addr = dst_addr + copy_size - tail_size;
		assert(tail_addr >= head_addr + head_size);
	}
	assert(head_size + tail_size <= copy_size);

	if (head_size + tail_size == copy_size) {
		/*
		 * It's all unaligned, no optimization possible...
		 */
		goto blunt_copy;
	}

	if (head_size) {
		/*
		 * Unaligned copy of the first "head_size" bytes, to reach
		 * a page boundary.
		 */

		/*
		 * Extract "head_copy" out of "copy".
		 */
		head_copy = vm_map_copy_allocate(VM_MAP_COPY_ENTRY_LIST,
		    copy_page_shift);

		entry = vm_map_copy_first_entry(copy);
		if (entry->vme_end < copy->offset + head_size) {
			head_size = entry->vme_end - copy->offset;
		}

		head_copy->offset = copy->offset;
		head_copy->size = head_size;
		copy->offset += head_size;
		copy->size -= head_size;
		copy_size -= head_size;
		assert(copy_size > 0);

		vm_map_copy_store_clip_end(copy, entry, copy->offset);
		vm_map_copy_store_remove(copy, entry);
		vm_map_copy_store_insert_tail(head_copy, entry);

		/*
		 * Do the unaligned copy.
		 */
		kr = vm_map_copy_overwrite_impl(dst_map,
		    head_addr,
		    head_copy,
		    interruptible,
#if HAS_MTE
		    sec_override,
#endif
		    false);

		if (kr != KERN_SUCCESS) {
			copy_err_code = KDBG_TRIAGE_VM_COPYOVERWRITE_PARTIAL_HEAD_ERROR;
			err_line = __LINE__;
			goto done;
		}
	}

	if (tail_size) {
		/*
		 * Extract "tail_copy" out of "copy".
		 */
		tail_copy = vm_map_copy_allocate(VM_MAP_COPY_ENTRY_LIST,
		    copy_page_shift);

		tail_copy->offset = copy->offset + copy_size - tail_size;
		tail_copy->size = tail_size;

		copy->size -= tail_size;
		copy_size -= tail_size;
		assert(copy_size > 0);

		entry = vm_map_copy_last_entry(copy);
		vm_map_copy_store_clip_start(copy, entry, tail_copy->offset);
		entry = vm_map_copy_last_entry(copy);
		vm_map_copy_store_remove(copy, entry);
		vm_map_copy_store_insert_tail(tail_copy, entry);
	}

	/*
	 * If we are here from ipc_kmsg_copyout_ool_descriptor(),
	 * we want to avoid TOCTOU issues w.r.t copy->size but
	 * we don't need to change vm_map_copy_overwrite_impl()
	 * and all other vm_map_copy_overwrite variants.
	 *
	 * So we assign the original copy_size that was passed into
	 * this routine back to copy.
	 *
	 * This use of local 'copy_size' passed into this routine is
	 * to try and protect against TOCTOU attacks where the kernel
	 * has been exploited. We don't expect this to be an issue
	 * during normal system operation.
	 */
	assertf(copy->size == copy_size,
	    "Mismatch of copy sizes. Expected 0x%llx, Got 0x%llx\n", (uint64_t) copy_size, (uint64_t) copy->size);
	copy->size = copy_size;

	/*
	 * Copy most (or possibly all) of the data.
	 */
	kr = vm_map_copy_overwrite_impl(dst_map,
	    dst_addr + head_size,
	    copy,
	    interruptible,
#if HAS_MTE
	    sec_override,
#endif
	    false);
	if (kr != KERN_SUCCESS) {
		copy_err_code = KDBG_TRIAGE_VM_COPYOVERWRITE_PARTIAL_ERROR;
		err_line = __LINE__;
		goto done;
	}

	if (tail_size) {
		kr = vm_map_copy_overwrite_impl(dst_map,
		    tail_addr,
		    tail_copy,
		    interruptible,
#if HAS_MTE
		    sec_override,
#endif
		    false);
		if (kr != KERN_SUCCESS) {
			copy_err_code = KDBG_TRIAGE_VM_COPYOVERWRITE_PARTIAL_TAIL_ERROR;
			err_line = __LINE__;
			goto done;
		}
	}

done:
	assert(copy->type == VM_MAP_COPY_ENTRY_LIST);

	if (kr != KERN_SUCCESS) {
		ktriage_record(thread_tid(current_thread()), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM, KDBG_TRIAGE_RESERVED, copy_err_code), kr /* arg */);
	}

	if (kr == KERN_SUCCESS) {
		/*
		 * Discard all the copy maps.
		 */
		vm_map_copy_discard(head_copy);
		vm_map_copy_discard(copy);
		vm_map_copy_discard(tail_copy);
		head_copy = copy = tail_copy = NULL;
	} else {
		/*
		 * Re-assemble the original copy map.
		 */
		if (head_copy) {
			entry = vm_map_copy_first_entry(head_copy);
			vm_map_copy_store_remove(head_copy, entry);
			vm_map_copy_store_insert_head(copy, entry);
			copy->offset -= head_size;
			copy->size += head_size;
			vm_map_copy_discard(head_copy);
			head_copy = NULL;
		}
		if (tail_copy) {
			entry = vm_map_copy_last_entry(tail_copy);
			vm_map_copy_store_remove(tail_copy, entry);
			vm_map_copy_store_insert_tail(copy, entry);
			copy->size += tail_size;
			vm_map_copy_discard(tail_copy);
			tail_copy = NULL;
		}
	}
	vmlp_api_end(VM_MAP_COPY_OVERWRITE, kr);
	return kr;
}

/*
 *	Routine: vm_map_copyin_kernel_buffer [internal use only]
 *
 *	Description:
 *		Copy in data to a kernel buffer from space in the
 *		source map. The original space may be optionally
 *		deallocated.
 *
 *		If successful, returns a new copy object.
 */
static kern_return_t
vm_map_copyin_kernel_buffer(
	vm_map_t        src_map,
	vm_map_offset_t src_addr,
	vm_map_size_t   len,
	vm_map_copyin_strategy strategy,
	boolean_t       src_destroy,
	vm_map_copy_t   *copy_result)
{
	kern_return_t kr;
	vm_map_copy_t copy;
	void *kdata;

	/*
	 * Large kernel buffer copies are only allowed for security-sensitive
	 * operations that require avoiding COW (NO_COW strategy).
	 */
	if (len > msg_ool_size_small && strategy != VM_MAP_COPYIN_STRATEGY_KERNEL_LARGE_BUFFER) {
		return KERN_INVALID_ARGUMENT;
	}

	kdata = kalloc_data(len, Z_WAITOK);
	if (kdata == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}
	kr = copyinmap(src_map, src_addr, kdata, (vm_size_t)len);
	if (kr != KERN_SUCCESS) {
		kfree_data(kdata, len);
		return kr;
	}

	copy = vm_map_copy_allocate(VM_MAP_COPY_KERNEL_BUFFER, 0);
	copy->cpy_kdata = kdata;
	copy->size = len;
	copy->offset = 0;
	copy->cpy_uses_large_buffers = (strategy == VM_MAP_COPYIN_STRATEGY_KERNEL_LARGE_BUFFER);

	if (src_destroy) {
		vmr_flags_t remove_flags;

		if (src_map == kernel_map) {
			remove_flags = VM_MAP_REMOVE_KUNWIRE;
		} else if (vm_kernel_map_is_kernel(src_map)) {
			/*
			 * This historically didn't ask for VM_MAP_REMOVE_KUNWIRE, and
			 * whether that could introduce problems isn't completely obvious.
			 */
			remove_flags = VM_MAP_REMOVE_NO_FLAGS;
		} else {
			/*
			 * Not allowed for kernel maps, but this is historically done for
			 * userspace maps.
			 */
			remove_flags = VM_MAP_REMOVE_INTERRUPTIBLE;
		}

		(void)vm_map_remove_guard(src_map,
		    vm_map_trunc_page(src_addr, VM_MAP_PAGE_MASK(src_map)),
		    vm_map_round_page(src_addr + len, VM_MAP_PAGE_MASK(src_map)),
		    remove_flags, KMEM_GUARD_NONE);
	}

	*copy_result = copy;
	return KERN_SUCCESS;
}

/*
 *	Routine: vm_map_copyout_kernel_buffer	[internal use only]
 *
 *	Description:
 *		Copy out data from a kernel buffer into space in the
 *		destination map. The space may be otpionally dynamically
 *		allocated.
 *
 *		If successful, consumes the copy object.
 *		Otherwise, the caller is responsible for it.
 *
 *		Callers of this function must call vm_map_copy_require on
 *		previously created vm_map_copy_t or pass a newly created
 *		one to ensure that it hasn't been forged.
 */
static int vm_map_copyout_kernel_buffer_failures = 0;
static kern_return_t
vm_map_copyout_kernel_buffer(
	vm_map_t                map,
	vm_map_address_t        *addr,  /* IN/OUT */
	vm_map_copy_t           copy,
	vm_map_size_t           copy_size,
	boolean_t               overwrite,
#if HAS_MTE
	boolean_t               sec_override,
#endif
	boolean_t               consume_on_success)
{
	kern_return_t kr = KERN_SUCCESS;
	thread_t thread = current_thread();

	assert(copy->size == copy_size);

	/*
	 * check for corrupted vm_map_copy structure
	 */
	bool is_corrupt_vm_map_copy_detected = copy->offset != 0;
	if (copy_size > msg_ool_size_small) {
		/* Large security-sensitive buffers are allowed */
		if (!copy->cpy_uses_large_buffers) {
			is_corrupt_vm_map_copy_detected = true;
		}
	}
	if (is_corrupt_vm_map_copy_detected) {
		panic("Invalid vm_map_copy_t sz:%lld, ofst:%lld",
		    (long long)copy->size, (long long)copy->offset);
	}

	if (!overwrite) {
		/*
		 * Allocate space in the target map for the data
		 */
		vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_ANYWHERE();

		if (map == kernel_map) {
			vmk_flags.vmkf_range_id = KMEM_RANGE_ID_DATA_SHARED;
		}

		*addr = 0;
		kr = vm_map_enter(map,
		    addr,
		    vm_map_round_page(copy_size,
		    VM_MAP_PAGE_MASK(map)),
		    (vm_map_offset_t) 0,
		    vmk_flags,
		    VM_OBJECT_NULL,
		    (vm_object_offset_t) 0,
		    FALSE,
		    VM_PROT_DEFAULT,
		    VM_PROT_ALL,
		    VM_INHERIT_DEFAULT);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
#if KASAN
		if (map->pmap == kernel_pmap) {
			kasan_notify_address(*addr, copy->size);
		}
#endif
	}

	/*
	 * Copyout the data from the kernel buffer to the target map.
	 */
	if (thread->map == map) {
		/*
		 * If the target map is the current map, just do
		 * the copy.
		 */
		assert((vm_size_t)copy_size == copy_size);
		if (copyout(copy->cpy_kdata, *addr, (vm_size_t)copy_size)) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_switch_context_t switch_ctx;

		/*
		 * If the target map is another map, assume the
		 * target's address space identity for the duration
		 * of the copy.
		 */
		vm_map_reference(map);
#if HAS_MTE
		switch_ctx = vm_map_switch_with_sec_override(map, sec_override);
#else
		switch_ctx = vm_map_switch_to(map);
#endif

		assert((vm_size_t)copy_size == copy_size);
		if (copyout(copy->cpy_kdata, *addr, (vm_size_t)copy_size)) {
			vm_map_copyout_kernel_buffer_failures++;
			kr = KERN_INVALID_ADDRESS;
		}

		vm_map_switch_back(switch_ctx);
		vm_map_deallocate(map);
	}

	if (kr != KERN_SUCCESS) {
		/* the copy failed, clean up */
		if (!overwrite) {
			/*
			 * Deallocate the space we allocated in the target map.
			 */
			(void) vm_map_remove(map,
			    vm_map_trunc_page(*addr,
			    VM_MAP_PAGE_MASK(map)),
			    vm_map_round_page((*addr +
			    vm_map_round_page(copy_size,
			    VM_MAP_PAGE_MASK(map))),
			    VM_MAP_PAGE_MASK(map)));
			*addr = 0;
		}
	} else {
		/* copy was successful, dicard the copy structure */
		if (consume_on_success) {
			kfree_data(copy->cpy_kdata, copy_size);
			zfree_id(ZONE_ID_VM_MAP_COPY, copy);
		}
	}

	return kr;
}

/*
 *	Routine:	vm_map_copy_insert      [internal use only]
 *
 *	Description:
 *		Link a copy chain ("copy") into a map at the
 *		specified location (as cached by "rsv")
 *
 *		Callers of this function must call vm_map_copy_require on
 *		previously created vm_map_copy_t or pass a newly created
 *		one to ensure that it hasn't been forged.
 *	Side effects:
 *		The copy chain is destroyed.
 */
static void
vm_map_copy_insert(
	vm_map_t                map,
	vm_map_copy_t           copy,
	vm_map_store_rsv_t      rsv,
	vm_map_kernel_flags_t   vmk_flags)
{
	vm_map_entry_t entry;

	while (vm_map_copy_first_entry(copy) != vm_map_copy_to_entry(copy)) {
		entry = vm_map_copy_first_entry(copy);
		vm_map_copy_store_remove(copy, entry);
		vm_map_copy_entry_convert(copy, map, entry);
		vm_map_store_insert(map, entry, rsv, vmk_flags);
		vm_entry_unlock_exclusive(map, entry);
		vmlp_range_event_entry(map, entry);
	}
	zfree_id(ZONE_ID_VM_MAP_COPY, copy);
}

/*
 * Callers of this function must call vm_map_copy_require on
 * previously created vm_map_copy_t or pass a newly created
 * one to ensure that it hasn't been forged.
 */
static void
vm_map_copy_remap(
	vm_map_t                map,
	vm_map_copy_t           copy,
	vm_map_store_rsv_t      rsv,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_offset_t         adjustment,
	vm_prot_t               cur_prot,
	vm_prot_t               max_prot,
	vm_inherit_t            inheritance)
{
	vm_map_entry_t  copy_entry, new_entry;

	for (copy_entry = vm_map_copy_first_entry(copy);
	    !entry_is_copy_end(copy, copy_entry);
	    copy_entry = copy_entry->vme_next) {
		/* get a new VM map entry for the map */
		new_entry = vm_map_copy_entry_copy(copy, copy_entry);
		vm_map_copy_entry_convert(copy, map, new_entry);

		vm_map_entry_reinit_after_copy(map, new_entry);
		/* adjust "start" and "end" */
		new_entry->vme_start += adjustment;
		new_entry->vme_end += adjustment;
		/* clear some attributes */
#if __arm64e__
		if (new_entry->used_for_tpro) {
			new_entry->protection = VM_PROT_READ;
			new_entry->max_protection = VM_PROT_DEFAULT;
		} else
#endif /* __arm64e__ */
		{
			new_entry->protection = cur_prot;
			new_entry->max_protection = max_prot;
		}
		new_entry->inheritance = inheritance;
		new_entry->behavior = VM_BEHAVIOR_DEFAULT;
		/* insert the new entry in the map */
		vm_map_store_insert(map, new_entry, rsv, vmk_flags);
		vm_entry_unlock_exclusive(map, new_entry);
		vmlp_range_event_entry(map, new_entry);
		/* continue inserting the "copy entries" after the new entry */
	}
}


/*
 * Returns true if *size matches (or is in the range of) copy->size.
 * Upon returning true, the *size field is updated with the actual size of the
 * copy object (may be different for VM_MAP_COPY_ENTRY_LIST types)
 */
boolean_t
vm_map_copy_validate_size(
	vm_map_t                dst_map,
	vm_map_copy_t           copy,
	vm_map_size_t           *size)
{
	if (copy == VM_MAP_COPY_NULL) {
		return FALSE;
	}

	/*
	 * Assert that the vm_map_copy is coming from the right
	 * zone and hasn't been forged
	 */
	vm_map_copy_require(copy);

	vm_map_size_t copy_sz = copy->size;
	vm_map_size_t sz = *size;
	switch (copy->type) {
	case VM_MAP_COPY_KERNEL_BUFFER:
		if (sz == copy_sz) {
			return TRUE;
		}
		break;
	case VM_MAP_COPY_ENTRY_LIST:
		/*
		 * potential page-size rounding prevents us from exactly
		 * validating this flavor of vm_map_copy, but we can at least
		 * assert that it's within a range.
		 */
		if (copy_sz >= sz &&
		    copy_sz <= vm_map_round_page(sz, VM_MAP_PAGE_MASK(dst_map))) {
			*size = copy_sz;
			return TRUE;
		}
		break;
	default:
		break;
	}
	return FALSE;
}

/*
 * Insert the entries from a copy object to an available space in a destination map
 * @arg dst_map map to insert to
 * @arg dst_addr OUT the start address the entries were added to
 * @arg copy the copy to get entries from
 *      if copy has a non-page-aligned offset, the alignment offset is added to the dst entries as well
 * @arg copy_size_u size validation, must be equal to the size of the copy
 * @arg consume_on_success set to true if this function should free the given copy
 * @arg cur_protection, max_protection, inheritance
 *		consume_on_success == false: these parameters are used for creating the entries of the new mapping
 *		consume_on_success == true: the new entries are reset to default values
 *			                        (VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT)
 *      Note: in both cases, the protection and inheritance from the original copy are disregarded and not checked.
 */
static kern_return_t
vm_map_copyout_internal(
	vm_map_t                dst_map,
	vm_map_address_t       *dst_addr,      /* OUT */
	vm_map_copy_t           copy,
	vm_map_size_ut          copy_size_u,
	boolean_t               consume_on_success,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance)
{
	vm_map_store_rsv_t      rsv = { };
	vm_map_size_t           size, copy_size;
	vm_map_size_t           adjustment;
	vm_object_offset_t      vm_copy_start;
	vm_map_entry_t          entry;
	vm_map_copy_t           original_copy;
	kern_return_t           kr;
	vm_map_kernel_flags_t   vmk_flags = VM_MAP_KERNEL_FLAGS_ANYWHERE();

	vmlp_api_start(VM_MAP_COPYOUT_INTERNAL);

	/*
	 *	Check for null copy object.
	 */

	if (copy == VM_MAP_COPY_NULL) {
		*dst_addr = 0;
		vmlp_api_end(VM_MAP_COPYOUT_INTERNAL, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	/*
	 * Assert that the vm_map_copy is coming from the right
	 * zone and hasn't been forged
	 */
	vm_map_copy_require(copy);

	if (!VM_SANITIZE_UNSAFE_IS_EQUAL(copy_size_u, copy->size)) {
		*dst_addr = 0;
		ktriage_record(thread_tid(current_thread()),
		    KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM,
		    KDBG_TRIAGE_RESERVED,
		    KDBG_TRIAGE_VM_COPYOUT_INTERNAL_SIZE_ERROR),
		    KERN_FAILURE /* arg */);
		vmlp_api_end(VM_MAP_COPYOUT_INTERNAL, KERN_FAILURE);
		return KERN_FAILURE;
	}
	copy_size = copy->size;

	/*
	 *	Check for special kernel buffer allocated
	 *	by new_ipc_kmsg_copyin.
	 */

	if (copy->type == VM_MAP_COPY_KERNEL_BUFFER) {
		kr = vm_map_copyout_kernel_buffer(dst_map, dst_addr,
		    copy, copy_size, FALSE,
#if HAS_MTE
		    FALSE,
#endif
		    consume_on_success);
		if (kr) {
			ktriage_record(thread_tid(current_thread()),
			    KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM,
			    KDBG_TRIAGE_RESERVED,
			    KDBG_TRIAGE_VM_COPYOUT_KERNEL_BUFFER_ERROR), kr /* arg */);
		}
		vmlp_api_end(VM_MAP_COPYOUT_INTERNAL, kr);
		return kr;
	}

#if HAS_MTE
	if (inheritance == VM_INHERIT_SHARE) {
		for (entry = vm_map_copy_first_entry(copy); !entry_is_copy_end(copy, entry); entry = entry->vme_next) {
			if (!entry->is_sub_map && VME_OBJECT(entry) && vm_object_is_mte_mappable(VME_OBJECT(entry))) {
				/* we have no space allocated yet, so just report an address of 0 */
				vm_size_t entry_size = entry->vme_end - entry->vme_start;
				vm_mte_operation_flags_t mte_operation = VM_MTE_OPERATION_TYPE_INHERIT_SHARE;
				mte_operation |= vm_kernel_map_is_kernel(dst_map) ? VM_MTE_OPERATION_DEST_KERNEL : VM_MTE_OPERATION_DEST_USER;
				if (!vm_map_allow_mte_operation(dst_map, 0, entry_size, mte_operation, optional_vm_object_none() /* irrelevant here */)) {
					vmlp_api_end(VM_MAP_COPYOUT_INTERNAL, KERN_NO_ACCESS);
					return KERN_NO_ACCESS;
				}
			}
		}
	}
#endif /* HAS_MTE */

	original_copy = copy;
	if (copy->cpy_hdr.page_shift != VM_MAP_PAGE_SHIFT(dst_map)) { // Rosetta case 16k kernel -> 4k user map
		vm_map_copy_t target_copy;
		vm_map_offset_t overmap_start, overmap_end, trimmed_start;

		target_copy = VM_MAP_COPY_NULL;
		DEBUG4K_ADJUST("adjusting...\n");
		kr = vm_map_copy_adjust_to_target(
			copy,
			0, /* offset */
			copy->size, /* size */
			dst_map,
			TRUE, /* copy */
			&target_copy,
			&overmap_start,
			&overmap_end,
			&trimmed_start);
		if (kr != KERN_SUCCESS) {
			DEBUG4K_COPY("adjust failed 0x%x\n", kr);
			ktriage_record(thread_tid(current_thread()), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_VM_COPYOUT_INTERNAL_ADJUSTING_ERROR), kr /* arg */);
			vmlp_api_end(VM_MAP_COPYOUT_INTERNAL, kr);
			return kr;
		}
		DEBUG4K_COPY("copy %p (%d 0x%llx 0x%llx) dst_map %p (%d) target_copy %p (%d 0x%llx 0x%llx) overmap_start 0x%llx overmap_end 0x%llx trimmed_start 0x%llx\n", copy, copy->cpy_hdr.page_shift, copy->offset, (uint64_t)copy->size, dst_map, VM_MAP_PAGE_SHIFT(dst_map), target_copy, target_copy->cpy_hdr.page_shift, target_copy->offset, (uint64_t)target_copy->size, (uint64_t)overmap_start, (uint64_t)overmap_end, (uint64_t)trimmed_start);
		if (target_copy != copy) {
			copy = target_copy;
		}
		copy_size = copy->size;
	}

	/*
	 *	Find space for the data
	 */

	vm_copy_start = vm_map_trunc_page((vm_map_size_t)copy->offset,
	    VM_MAP_COPY_PAGE_MASK(copy));
	size = vm_map_round_page((vm_map_size_t)copy->offset + copy_size,
	    VM_MAP_COPY_PAGE_MASK(copy))
	    - vm_copy_start;

	vm_map_kernel_flags_update_range_id(&vmk_flags, dst_map, size);

	vm_map_ilk_lock(dst_map);
	kr = vm_map_locate_space_anywhere(dst_map, 0, size, 0, vmk_flags, &rsv);
	if (kr != KERN_SUCCESS) {
		vm_map_ilk_unlock(dst_map);
		ktriage_record(thread_tid(current_thread()), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_VM_COPYOUT_INTERNAL_SPACE_ERROR), kr /* arg */);
		vmlp_api_end(VM_MAP_COPYOUT_INTERNAL, kr);

		return kr;
	}

	adjustment = vmsr_start(rsv) - vm_copy_start;
	if (!consume_on_success) {
		/*
		 * We're not allowed to consume "copy", so we'll have to
		 * copy its map entries into the destination map below.
		 * No need to re-allocate map entries, since we'll get new map entries
		 * during the transfer.
		 * We'll also adjust the map entries's "start" and "end"
		 * during the transfer, to keep "copy"'s entries consistent
		 * with its "offset".
		 * consume_on_success = FALSE only comes from vm_map_copy_to_physcopy().
		 * This goto also skips mapping of wired pages, which we don't care about when coming from there
		 * since it's creating only a temp copy, not the final one.
		 */
		goto after_adjustments;
	}

	/*
	 *	Adjust the addresses in the copy chain, and
	 *	reset the region attributes.
	 */

	for (entry = vm_map_copy_first_entry(copy); !entry_is_copy_end(copy, entry); entry = entry->vme_next) {
		entry->vme_start += adjustment;
		entry->vme_end += adjustment;

		assert(VM_MAP_PAGE_ALIGNED(entry->vme_start,
		    VM_MAP_PAGE_MASK(dst_map)));
		assert(VM_MAP_PAGE_ALIGNED(entry->vme_end,
		    VM_MAP_PAGE_MASK(dst_map)));

#if __arm64e__
		if (entry->used_for_tpro) {
			entry->protection = VM_PROT_READ;
			entry->max_protection = VM_PROT_DEFAULT;
		} else
#endif /* __arm64e__ */
		{
			entry->protection = VM_PROT_DEFAULT;
			entry->max_protection = VM_PROT_ALL;
		}
		entry->inheritance = VM_INHERIT_DEFAULT;
		entry->behavior = VM_BEHAVIOR_DEFAULT;

		/*
		 * If the entry is now wired,
		 * map the pages into the destination map.
		 */
		if (entry->wired_count != 0) {
			vm_map_offset_t va;
			vm_object_offset_t       offset;
			vm_object_t object;
			vm_prot_t prot;
			int     type_of_fault;
			uint8_t object_lock_type = OBJECT_LOCK_EXCLUSIVE;

			/* TODO4K would need to use actual page size */
			assert(VM_MAP_PAGE_SHIFT(dst_map) == PAGE_SHIFT);

			object = VME_OBJECT(entry);
			offset = VME_OFFSET(entry);
			va = entry->vme_start;

			pmap_pageable(dst_map->pmap,
			    entry->vme_start,
			    entry->vme_end,
			    TRUE);

			while (va < entry->vme_end) {
				vm_page_t       m;
				struct vm_object_fault_info fault_info = {
					.interruptible = THREAD_UNINT,
				};

				/*
				 * Look up the page in the object.
				 * Assert that the page will be found in the
				 * top object:
				 * either
				 *	the object was newly created by
				 *	vm_object_copy_slowly, and has
				 *	copies of all of the pages from
				 *	the source object
				 * or
				 *	the object was moved from the old
				 *	map entry; because the old map
				 *	entry was wired, all of the pages
				 *	were in the top-level object.
				 *	(XXX not true if we wire pages for
				 *	 reading)
				 */
				vm_object_lock(object);

				m = vm_page_lookup(object, offset);
				if (m == VM_PAGE_NULL || !VM_PAGE_WIRED(m) ||
				    m->vmp_absent) {
					panic("vm_map_copyout: wiring %p", m);
				}

				prot = entry->protection;

				if (override_nx(dst_map, VME_ALIAS(entry)) &&
				    prot) {
					prot |= VM_PROT_EXECUTE;
				}

				type_of_fault = DBG_CACHE_HIT_FAULT;

				fault_info.user_tag = VME_ALIAS(entry);
				fault_info.pmap_options = 0;
				if (entry->iokit_acct ||
				    (!entry->is_sub_map && !entry->use_pmap)) {
					fault_info.pmap_options |= PMAP_OPTIONS_ALT_ACCT;
				}
				if (entry->vme_xnu_user_debug &&
				    !VM_PAGE_OBJECT(m)->code_signed) {
					/*
					 * Modified code-signed executable
					 * region: this page does not belong
					 * to a code-signed VM object, so it
					 * must have been copied and should
					 * therefore be typed XNU_USER_DEBUG
					 * rather than XNU_USER_EXEC.
					 */
					fault_info.pmap_options |= PMAP_OPTIONS_XNU_USER_DEBUG;
				}

				bool page_sleep_needed = false;
				bool need_retry = false;
				vm_fault_enter(m,
				    dst_map->pmap,
				    va,
				    PAGE_SIZE, 0,
				    prot,
				    prot,
				    VM_PAGE_WIRED(m),
				    VM_KERN_MEMORY_NONE,            /* tag - not wiring */
				    &fault_info,
				    &need_retry,
				    &type_of_fault,
				    &object_lock_type, /*Exclusive mode lock. Will remain unchanged.*/
				    &page_sleep_needed);

				vm_object_unlock(object);
				assert(!page_sleep_needed);

				offset += PAGE_SIZE_64;
				va += PAGE_SIZE;
			}
		}
	}

after_adjustments:

	/*
	 *	Correct the page alignment for the result
	 */

	*dst_addr = vmsr_start(rsv) + (copy->offset - vm_copy_start);

#if KASAN
	kasan_notify_address(*dst_addr, size);
#endif

	/*
	 *	Link in the copy
	 */

	if (consume_on_success) {
		vm_map_copy_insert(dst_map, copy, rsv, vmk_flags);
		if (copy != original_copy) {
			/* the copy discarded in vm_map_copy_insert() might have been one which
			 * vm_map_copy_adjust_to_target() created. in that case, free the original as well */
			vm_map_copy_discard(original_copy);
			original_copy = VM_MAP_COPY_NULL;
		}
	} else {
		vm_map_copy_remap(dst_map, copy, rsv, vmk_flags,
		    adjustment, cur_protection, max_protection, inheritance);
		if (copy != original_copy && original_copy != VM_MAP_COPY_NULL) {
			/* if vm_map_copy_adjust_to_target() created a local copy, free it now */
			vm_map_copy_discard(copy);
			copy = original_copy;
		}
	}


	vm_map_ilk_unlock(dst_map);
	vmlp_api_end(VM_MAP_COPYOUT_INTERNAL, KERN_SUCCESS);

	return KERN_SUCCESS;
}

/*
 *	Routine:	vm_map_copyout_size
 *
 *	Description:
 *		Copy out a copy chain ("copy") into newly-allocated
 *		space in the destination map. Uses a prevalidated
 *		size for the copy object (vm_map_copy_validate_size).
 *
 *		If successful, consumes the copy object.
 *		Otherwise, the caller is responsible for it.
 */
kern_return_t
vm_map_copyout_size(
	vm_map_t                dst_map,
	vm_map_address_t       *dst_addr,      /* OUT */
	vm_map_copy_t           copy,
	vm_map_size_ut          copy_size)
{
	return vm_map_copyout_internal(dst_map, dst_addr, copy, copy_size,
	           TRUE,                     /* consume_on_success */
	           VM_PROT_DEFAULT,
	           VM_PROT_ALL,
	           VM_INHERIT_DEFAULT);
}

/*
 *	Routine:	vm_map_copyout
 *
 *	Description:
 *		Copy out a copy chain ("copy") into newly-allocated
 *		space in the destination map.
 *
 *		If successful, consumes the copy object.
 *		Otherwise, the caller is responsible for it.
 */
kern_return_t
vm_map_copyout(
	vm_map_t                dst_map,
	vm_map_address_t       *dst_addr,      /* OUT */
	vm_map_copy_t           copy)
{
	return vm_map_copyout_internal(dst_map, dst_addr, copy, copy ? copy->size : 0,
	           TRUE,                     /* consume_on_success */
	           VM_PROT_DEFAULT,
	           VM_PROT_ALL,
	           VM_INHERIT_DEFAULT);
}

/*
 *	Routine:	vm_map_copyin
 *
 *	Description:
 *		see vm_map_copyin_common.  Exported via Unsupported.exports.
 *
 */
kern_return_t
vm_map_copyin(
	vm_map_t                src_map,
	vm_map_address_ut       src_addr,
	vm_map_size_ut          len,
	boolean_t               src_destroy,
	vm_map_copy_t          *copy_result)   /* OUT */
{
	return vm_map_copyin_common(src_map, src_addr, len, src_destroy,
	           FALSE, copy_result, FALSE);
}

/*
 *	Routine:	vm_map_copyin_common
 *
 *	Description:
 *		Copy the specified region (src_addr, len) from the
 *		source address space (src_map), possibly removing
 *		the region from the source address space (src_destroy).
 *
 *	Returns:
 *		A vm_map_copy_t object (copy_result), suitable for
 *		insertion into another address space (using vm_map_copyout),
 *		copying over another address space region (using
 *		vm_map_copy_overwrite).  If the copy is unused, it
 *		should be destroyed (using vm_map_copy_discard).
 *
 *	In/out conditions:
 *		The source map should not be locked on entry.
 */

kern_return_t
vm_map_copyin_common(
	vm_map_t                src_map,
	vm_map_address_ut       src_addr,
	vm_map_size_ut          len,
	boolean_t               src_destroy,
	__unused boolean_t      src_volatile,
	vm_map_copy_t          *copy_result,   /* OUT */
	boolean_t               use_maxprot)
{
	int flags;

	flags = 0;
	if (src_destroy) {
		flags |= VM_MAP_COPYIN_SRC_DESTROY;
	}
	if (use_maxprot) {
		flags |= VM_MAP_COPYIN_USE_MAXPROT;
	}
#if HAS_MTE
	flags |= VM_MAP_COPYIN_DEST_UNKNOWN;
#endif
	return vm_map_copyin_internal(src_map,
	           src_addr,
	           len,
	           flags,
	           copy_result);
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_copyin_sanitize(
	vm_map_t                src_map,
	vm_map_address_ut       src_addr_u,
	vm_map_size_ut          len_u,
	vm_map_offset_t        *src_start,
	vm_map_offset_t        *src_end,
	vm_map_size_t          *len,
#if HAS_MTE
	vm_map_offset_t        *src_addr_unaligned,
	vm_map_offset_t        *src_addr_unaligned_tagged)
#else /* HAS_MTE */
	vm_map_offset_t        *src_addr_unaligned)
#endif /* HAS_MTE */
{
	kern_return_t   kr;
	vm_sanitize_flags_t flags = VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS |
	    VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES |
	    VM_SANITIZE_FLAGS_CHECK_ADDR_RANGE;

	kr = vm_sanitize_addr_size(src_addr_u, len_u,
	    VM_SANITIZE_CALLER_VM_MAP_COPYIN,
	    src_map,
	    flags,
	    src_start, src_end, len);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	/*
	 *	Compute (page aligned) start and end of region
	 */
	*src_addr_unaligned  = *src_start; /* remember unaligned value */
	*src_start = vm_map_trunc_page(*src_addr_unaligned,
	    VM_MAP_PAGE_MASK(src_map));
	*src_end   = vm_map_round_page(*src_end, VM_MAP_PAGE_MASK(src_map));

#if CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS
#if HAS_MTE
	*src_addr_unaligned_tagged = *src_addr_unaligned;
#endif /* HAS_MTE */
	/*
	 * Full stripping here may allow a trashed address to pass through,
	 * so we limit the operation to just an MTE canonicalization for the range
	 * checks. The copyin operation is more destructive than a simple range
	 * verification, so our policy is to be conservative.
	 */
	bool sanitize_tag_bits = false;

#if KASAN_TBI
	if (vm_kernel_map_is_kernel(src_map)) {
		sanitize_tag_bits = true;
	}
#endif

#if HAS_MTE
	if (mte_kern_enabled() && vm_kernel_map_is_kernel(src_map)) {
		sanitize_tag_bits = true;
	}

	if (mte_enabled() && current_task_has_sec_enabled()) {
		sanitize_tag_bits = true;
	}
#endif /* HAS_MTE */

	if (sanitize_tag_bits) {
		*src_start = vm_memtag_canonicalize(src_map, *src_start);
		*src_end = vm_memtag_canonicalize(src_map, *src_end);
		*src_addr_unaligned = vm_memtag_canonicalize(src_map, *src_addr_unaligned);
	}
#endif /* CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS */

	return KERN_SUCCESS;
}

#if HAS_MTE
/*
 * Take a look at all the objects backing the region and return whether
 * any of them are MTE mappable and originate from the local domain.
 *
 * Preconditions:
 *      - Map unlocked
 *      - No entries locked
 *
 * Returns:
 *	- Multiple error signifiers, so all of them are out-parameters to ensure
 *    there's no ambiguity w.r.t return value.
 *    If `!out_is_region_well_formed`, other out-returns are irrelevant.
 */
static void
_is_any_object_in_region_local_mte_mappable(
	bool* out_is_region_well_formed,
	bool* out_is_any_object_mte_mappable,
	vm_map_t src_map,
	vm_map_offset_t src_start,
	vm_map_offset_t src_end
	)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t curr_entry;
	kern_return_t kr;
	vm_map_serial_t local_serial_id = src_map->serial_id;

	if (src_start == src_end) {
		/*
		 * Special case: vm_map_copyin_internal succeeds with size = 0.
		 * The range lock will reject an empty range, so special-case this.
		 */
		*out_is_region_well_formed = true;
		*out_is_any_object_mte_mappable = false;
		return;
	}

	/* Start off with good intent */
	*out_is_region_well_formed = true;

	kr = vm_map_range_sh_lock(ctx, &src_map, src_start, src_end, VMRL_SH_ATOMIC);

	/* Check for holes in the region */
	if (kr != KERN_SUCCESS) {
		*out_is_region_well_formed = false;
		return;
	}

	while ((curr_entry = vm_map_range_atomic_next(ctx))) {
		if (curr_entry->is_sub_map) {
			/* Not a relevant MTE object... */
			continue;
		}

		vm_object_t obj = VME_OBJECT(curr_entry);
		if (obj == VM_OBJECT_NULL) {
			/* Not a relevant MTE object... */
			continue;
		}

		if (!vm_object_is_mte_mappable(obj)) {
			/* Only relevant to MTE objects... */
			continue;
		}

		if (obj->vmo_provenance != local_serial_id) {
			/* Only relevant to local copies... */
			continue;
		}

		/* Found an MTE object in the region, we're done. */
		*out_is_any_object_mte_mappable = true;
		vm_map_range_sh_unlock(ctx, &src_map);
		return;
	}
	*out_is_any_object_mte_mappable = false;
	vm_map_range_sh_unlock(ctx, &src_map);
}
#endif /* HAS_MTE */

static vm_map_copyin_strategy
_vm_map_copyin_select_strategy(
	vm_map_t src_map,
	vm_map_size_t   len,
	vm_map_offset_t src_start,
	vm_map_offset_t src_end,
	boolean_t use_maxprot,
	boolean_t preserve_purgeable,
	int flags
	)
{
#if HAS_MTE
	bool is_region_well_formed;
	bool is_any_object_in_region_local_mte_mappable;
#endif /* HAS_MTE */
	/*
	 * If the copy is sufficiently small, use a kernel buffer instead
	 * of making a virtual copy.  The theory being that the cost of
	 * setting up VM (and taking C-O-W faults) dominates the copy costs
	 * for small regions.
	 */
	if ((len <= msg_ool_size_small) &&
	    !use_maxprot &&
	    !preserve_purgeable &&
	    !(flags & VM_MAP_COPYIN_ENTRY_LIST) &&
	    /*
	     * Since the "msg_ool_size_small" threshold was increased and
	     * vm_map_copyin_kernel_buffer() doesn't handle accesses beyond the
	     * address space limits, we revert to doing a virtual copy if the
	     * copied range goes beyond those limits.  Otherwise, mach_vm_read()
	     * of the commpage would now fail when it used to work.
	     */
	    (src_start >= vm_map_min(src_map) &&
	    src_start < vm_map_max(src_map) &&
	    src_end >= vm_map_min(src_map) &&
	    src_end < vm_map_max(src_map))) {
		return VM_MAP_COPYIN_STRATEGY_KERNEL_BUFFER;
	}

#if HAS_MTE
	/*
	 * Note that there are more conditions under which we must be sure to go down
	 * the kernel buffer path. Notably, we mandate doing this, rather than making
	 * a virtual copy, if we're creating a local copy of MTE-enabled memory.
	 * This avoids any hijinks where a caller could create a virtual copy of
	 * local MTE memory whose tags they don't know.
	 * The thought is that although this would be expensive for large copies,
	 * we don't expect to hit this often because we don't expect to have many
	 * large MTE objects floating around.
	 * Note also that copies of MTE memory into other contexts are fine, because
	 * they're not a risk under VM MTE policies v3.
	 */
	/*
	 * However, vm_map_fork_copy() reads entries directly off the VM map,
	 * so it definitely won't be providing correctly tagged inputs and certainly
	 * shouldn't be subject to universal byte-by-byte copies.
	 * Don't restrict this case.
	 */
	if (flags & VM_MAP_COPYIN_FORK) {
		return VM_MAP_COPYIN_STRATEGY_VIRTUAL_COPY;
	}
	/* Additionally, mach_make_memory_entry conceptually should go down the kernel
	 * buffer path for the reason outlined above, but today it cannot do so because
	 * the relevant code paths only know how to manipulate entry list-style copy
	 * maps (see rdar://22611816).
	 * The blast radius of allowing it to continue using virtual copies is limited,
	 * so we'll maintain this carveout for now.
	 */
	if (flags & VM_MAP_COPYIN_ENTRY_LIST) {
		return VM_MAP_COPYIN_STRATEGY_VIRTUAL_COPY;
	}

	_is_any_object_in_region_local_mte_mappable(
		&is_region_well_formed,
		&is_any_object_in_region_local_mte_mappable,
		src_map,
		src_start,
		src_end);

	if (!is_region_well_formed) {
		return VM_MAP_COPYIN_STRATEGY_INVALID_ARGUMENT;
	}

	/*
	 * Local copyin of an MTE-enabled object requires a kernel buffer
	 * instead of a virtual copy to avoid COW.
	 */
	if (is_any_object_in_region_local_mte_mappable) {
		return VM_MAP_COPYIN_STRATEGY_KERNEL_LARGE_BUFFER;
	}
#endif /* HAS_MTE */

	/*
	 * Check if the source is in the data private range.
	 * If so, we must use a kernel buffer to avoid COW.
	 */
	if (vm_kernel_map_is_kernel(src_map) &&
	    kalloc_is_data_private((void *)src_start, len)) {
		return VM_MAP_COPYIN_STRATEGY_KERNEL_LARGE_BUFFER;
	}

	return VM_MAP_COPYIN_STRATEGY_VIRTUAL_COPY;
}


#define DEBUG4K_NO_COW_COPYIN_ON_MAP(map) \
	(debug4k_no_cow_copyin && VM_MAP_PAGE_SHIFT((map)) < PAGE_SHIFT)

#if HAS_MTE
/**
 * @function _vm_map_copyin_internal_check_mte_policy
 *
 * @brief Validate that a copyin is allowed on an entry based on MTE policy.
 * Can be called on non-MTE entries.
 *
 * @param src_entry is the entry we are checking. It should be safe to access
 *                  (locked or child entry of a constant submap). It should not
 *                  be a submap entry.
 * @param addr      start addr of the copied range.
 * @param size      size of the copied range.
 *
 * @warning addr/size must cover the range for the whole copy operation, not
 *          just this one entry.
 *
 */
static kern_return_t
_vm_map_copyin_internal_check_mte_policy(
	vm_map_t        src_map,
	vm_map_entry_t  src_entry,
	vm_map_offset_t addr,
	vm_size_t       size,
	int             copyin_flags)
{
	vm_object_t src_object = VME_OBJECT(src_entry);

	if (src_object == VM_OBJECT_NULL) {
		return KERN_SUCCESS;
	}

	if (!vm_object_is_mte_mappable(src_object)) {
		return KERN_SUCCESS;
	}
	/*
	 * Usually, small copies take the kernel buffer path, but do not do so
	 * in the paths from mach_make_memory_entry or vm_map_fork_copy. In those
	 * cases, as well as other paths that do virtual copies (e.g. large copies),
	 * we must verify MTE policy before permitting the operation.
	 *
	 * If the operation is allowed to succeed, the virtual copy path does an
	 * EAGER copy (i.e., no copy-on-write aka copy strategy of MEMORY_OBJECT_COPY_NONE)
	 *
	 * In the future, the VM object will have a copy strategy of
	 * MEMORY_OBJECT_COPY_DELAY_FORK (rdar://126656127)
	 */
	vm_mte_operation_flags_t mte_operation = VM_MTE_OPERATION_TYPE_COPY;

	/* set copy destination based on copyin flags */
	if (copyin_flags & VM_MAP_COPYIN_DEST_USER) {
		mte_operation |= VM_MTE_OPERATION_DEST_USER;
	} else if (copyin_flags & VM_MAP_COPYIN_DEST_KERNEL) {
		mte_operation |= VM_MTE_OPERATION_DEST_KERNEL;
	} else if (copyin_flags & VM_MAP_COPYIN_DEST_UNKNOWN) {
		mte_operation |= VM_MTE_OPERATION_DEST_UNKNOWN;
	} else {
		panic("MTE vm_map_copyin without setting VM_MAP_COPYIN_DEST");
	}

	/* Pass through additional policy flags based on our called context */
	mte_operation |=
	    (copyin_flags & VM_MAP_COPYIN_IOKIT) ? VM_MTE_OPERATION_IOKIT : 0;
	mte_operation |=
	    (copyin_flags & VM_MAP_COPYIN_FORK) ? VM_MTE_OPERATION_FORK : 0;
	mte_operation |=
	    (copyin_flags & VM_MAP_COPYIN_ENTRY_LIST) ? VM_MTE_OPERATION_MAKE_MEMORY_ENTRY : 0;

	if (!vm_map_allow_mte_operation(src_map, addr, size, mte_operation, OPTIONAL_SOME(src_object))) {
		return KERN_NOT_SUPPORTED;
	}
	return KERN_SUCCESS;
}
#endif /* HAS_MTE */

/*!
 * @function vm_map_copyin_internal_for_entry
 *
 * @brief
 * Helper function that copies a locked entry, handling some CoW logic,
 * purgeability, etc...
 *
 * @warning
 * It is the caller's responsibility to make sure symmetric CoW is properly
 * setup on entries with a COPY_SYMMETRIC object without the needs_copy bit.
 * This means the caller should detect this scenario in the lock preflight and
 * return @c VMRL_ERR_SETUP_SYMMETRIC_COW.
 *
 * @param [in]      ctx       The lock context being passed down from the
 *                            caller. It should be using a streaming range lock.
 * @param [in]      src_entry The entry to copy. The entry should be safe to
 *                            access (i.e. locked excl or shared, or a child
 *                            entry in a locked constant submap). The entry lock
 *                            may be dropped before this function returns.
 * @param [in]      flags     copyin flags to specify copy behavior.
 * @param [in,out]  copy      A pre-allocated @c vm_map_copy_t. On success, a
 *                            new entry will be added to it.
 *
 * @note
 * Callers passing submap entries will need to adjust vme_start/vme_end in the
 * resulting copy entry, as those will initially be set to in-submap addresses
 * that do not account for the submap offset or the parent entry's start
 * address.
 *
 * @note
 * This function does not implement the "kernel buffer" copy optimization for
 * small copies. This responsibility rests with the caller.
 *
 * @returns A kernel return code. @c copy has an extra entry on success. It is
 *          unchanged on failure.
 */
static kern_return_t
vm_map_copyin_internal_for_entry(
	vm_map_lock_ctx_t       ctx,
	vm_map_entry_t          src_entry,
	int                     flags,
	vm_map_copy_t           copy)
{
	vm_map_t           src_map;
	bool               was_wired = false;     /* Was source wired? */
	vm_object_t        src_object = NULL;     /* Object to copy */
	vm_object_offset_t src_offset = 0;
	vm_map_size_t      src_size = 0;          /* Size of source map entry (in both maps) */
	kern_return_t      result;                /* Return value from vm_object_copy_*. */
	vm_map_entry_t     new_entry = VM_MAP_ENTRY_NULL;  /* Map entry for copy */
	vm_map_offset_t    src_start; /* Start of current entry --  where copy is taking place now */
	bool               use_maxprot;
	bool               preserve_purgeable;

	/* for copying: range-lock should descend to submap */
	/* for fork: fork simply skips copying submap entries */
	assert(!src_entry->is_sub_map);
	/* range lock can descend to submap, so make sure we're on the right map */
	src_map = ctx->vmlc_map;
	/* this gets updated when we descend/ascend from submaps.
	 * while in a submap, if the range crosses the end of the submap, this just points to the end of the submap */
	src_object = VME_OBJECT(src_entry);

	use_maxprot = flags & VM_MAP_COPYIN_USE_MAXPROT;
	preserve_purgeable = flags & VM_MAP_COPYIN_PRESERVE_PURGEABLE;

#define RETURN(x)                                                 \
    MACRO_BEGIN                                                   \
	if (new_entry != VM_MAP_ENTRY_NULL) {                         \
	        vm_map_copy_entry_free_no_ownership(copy, new_entry); \
	}                                                             \
	MACRO_RETURN(x);                                              \
	MACRO_END

	if (src_object != VM_OBJECT_NULL && src_object->phys_contiguous) {
		/* This is not, supported for now.In future */
		/* we will need to detect the phys_contig   */
		/* condition and then upgrade copy_slowly   */
		/* to do physical copy from the device mem  */
		/* based object. We can piggy-back off of   */
		/* the was wired boolean to set-up the      */
		/* proper handling */
		RETURN(KERN_PROTECTION_FAILURE);
	}

	/* Verify that the region can be read. */
	if (((src_entry->protection & VM_PROT_READ) == VM_PROT_NONE && !use_maxprot) ||
	    (src_entry->max_protection & VM_PROT_READ) == 0) {
		RETURN(KERN_PROTECTION_FAILURE);
	}

	/* The current entry bounds from the lock rather than vme_start since the shared lock doesn't clip or
	 * we might have advanced in this entry in a previous iteration */
	vm_map_lock_ctx_bounds(ctx, &src_start, NULL, &src_size);
	vm_map_lock_ctx_offset_bounds(ctx, &src_offset, NULL, NULL);
	/* src_start is the the current start of the region we're copying in this iteration
	 * src_size is the size of the region we're copying in this iteration, either until the end of the entry or
	 *    until the end of the context range, whichever comes first
	 * src_offset is the object offset of src_start in the view given by this entry */

#if HAS_MTE
	/*
	 * We only run this as an assert because fork should be allowed to CoW
	 * regardless of size, and copyin should check MTE policy at its layer
	 * (it has the right addr/size representing the whole copy, which we lack
	 * here).
	 */
	assert3u(KERN_SUCCESS, ==,
	    _vm_map_copyin_internal_check_mte_policy(
		    src_map, src_entry, src_start, src_size, flags));
#endif /* HAS_MTE */

	was_wired = (src_entry->wired_count != 0);

	assert(src_start >= src_entry->vme_start);

	/* the entry is created here without ownership of an object because the object
	 * pointer is going to be determined next in vm_object_copy_quickly/slowly/strategically
	 * each of these take care to have a reference for the object for this new entry */
	new_entry = vm_map_copy_entry_copy_no_ownership(copy, src_entry);
	vm_map_entry_reinit_after_copy(src_map, new_entry);
	assert(src_object == VME_OBJECT(new_entry));

	/* we did not clip src_entry: "clip" new_entry */
	new_entry->vme_start = src_start;
	new_entry->vme_end = src_start + src_size;
	VME_OFFSET_SET(new_entry, src_offset);

	/*
	 * We're dealing with a copy-on-write operation,
	 * so the resulting mapping should not inherit the
	 * original mapping's accounting settings.
	 * "iokit_acct" should have been cleared in
	 * vm_map_entry_reinit_after_copy().
	 * "use_pmap" should be reset to its default (TRUE)
	 * so that the new mapping gets accounted for in
	 * the task's memory footprint.
	 */
	assert(!new_entry->iokit_acct);
	/* sanity before setting use_pmap, new entry can't be a submap entry because we are descending to submaps */
	assert(!new_entry->is_sub_map);
	new_entry->use_pmap = TRUE;

	/*
	 *	Attempt non-blocking copy-on-write optimizations.
	 */

	/* did we decide we'll need to call copy_quickly in the preflight callback? */
	if (src_object == VM_OBJECT_NULL ||
	    (src_entry->needs_copy && !DEBUG4K_NO_COW_COPYIN_ON_MAP(src_map))) {
		boolean_t src_needs_copy;
		boolean_t new_entry_needs_copy;

		__assert_only boolean_t ok_quickly = vm_object_copy_quickly(
			VME_OBJECT(new_entry),
			src_offset,
			src_size,
			&src_needs_copy,
			&new_entry_needs_copy);
		/* this call shouldn't return false since the preflight_state says the conditions for it to return
		 * true are met */
		assert(ok_quickly == true);
		/* sanity check that vm_object_copy_quickly() set src_needs_copy as the preflight expected */
		assert(src_needs_copy == (src_object != VM_OBJECT_NULL && src_entry->needs_copy));

		new_entry->needs_copy = new_entry_needs_copy;

		/* The entry->needs_copy and the pmap protection change happened inside the lock
		 * as a result of preflight retuning VMRL_ERR_SETUP_SYMMETRIC_COW.
		 * This needed to happen inside the lock since it needs the entry lock upgraded to exclusive
		 * while this iteration is a shared lock */

		/*  The entry has never been unlocked, so it's safe
		 *	to move to the next entry rather than doing
		 *	another lookup (this is detected by the range lock). */
		goto CopySuccessful;
	}

	/* Take an object reference, so that we may drop the entry lock. */
	assert(src_object != VM_OBJECT_NULL);
	vm_object_reference(src_object);

	vm_map_range_stream_drop(ctx);
	src_entry = VM_MAP_ENTRY_NULL; /* nulled to signify we don't have the entry lock */

	/*
	 *	Perform the copy
	 */
	if (was_wired ||
	    (src_object->copy_strategy == MEMORY_OBJECT_COPY_DELAY_FORK && !(flags & VM_MAP_COPYIN_FORK)) ||
	    (DEBUG4K_NO_COW_COPYIN_ON_MAP(src_map))) {
		vm_object_t new_copy_object = NULL; /* vm_object_copy_* result */
		/* special cases where COPY_NONE overrides the copy-strategy */
		vm_object_lock(src_object);
		result = vm_object_copy_slowly(
			src_object,
			src_offset,
			src_size,
			THREAD_UNINT,
#if HAS_MTE
			false, /* create_mte_object */
#endif /* HAS_MTE */
			&new_copy_object);
		VM_OBJECT_SET_KEEP_JIT(new_entry, new_copy_object, false, 0);
		VME_OFFSET_SET(new_entry, src_offset - vm_object_trunc_page(src_offset));
		new_entry->needs_copy = FALSE;
	} else {
		/* SYMMETRIC was already handled above by copy_quickly */
		assert(src_object->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC);

		vm_object_t new_copy_object = NULL; /* vm_object_copy_* result */
		vm_object_offset_t new_offset = 0;
		boolean_t new_entry_needs_copy = false;
		new_offset = VME_OFFSET(new_entry);
		result = vm_object_copy_strategically(src_object,
		    src_offset,
		    src_size,
		    (flags & VM_MAP_COPYIN_FORK),
		    &new_copy_object,
		    &new_offset,
		    &new_entry_needs_copy);
		/* any valid MEMORY_OBJECT_COPY_SYMMETRIC cases should have been handled above,
		 * so there shouldn't be a case that we get KERN_MEMORY_RESTART_COPY */
		assert(result != KERN_MEMORY_RESTART_COPY);
		VM_OBJECT_SET_KEEP_JIT(new_entry, new_copy_object, false, 0);
		if (new_offset != VME_OFFSET(new_entry)) {
			VME_OFFSET_SET(new_entry, new_offset);
		}

		new_entry->needs_copy = new_entry_needs_copy;
	}

	if (result == KERN_SUCCESS &&
	    ((preserve_purgeable && src_object->purgable != VM_PURGABLE_DENY) ||
	    new_entry->used_for_jit)) {
		/*
		 * Purgeable objects should be COPY_NONE, true share;
		 * this should be propogated to the copy.
		 *
		 * Also force mappings the pmap specially protects to
		 * be COPY_NONE; trying to COW these mappings would
		 * change the effective protections, which could have
		 * side effects if the pmap layer relies on the
		 * specified protections.
		 */

		vm_object_t     new_object;

		new_object = VME_OBJECT(new_entry);
		assert(new_object != src_object);
		vm_object_lock(new_object);
		assert(os_ref_get_count_raw(&new_object->ref_count) == 1);
		assert(new_object->shadow == VM_OBJECT_NULL);
		assert(new_object->vo_copy == VM_OBJECT_NULL);
		assert(new_object->vo_owner == NULL);

		new_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;

		if (preserve_purgeable && src_object->purgable != VM_PURGABLE_DENY) {
			VM_OBJECT_SET_TRUE_SHARE(new_object, TRUE);

			/* start as non-volatile with no owner... */
			VM_OBJECT_SET_PURGABLE(new_object, VM_PURGABLE_NONVOLATILE);
			vm_purgeable_nonvolatile_enqueue(new_object, NULL);
			/* ... and move to src_object's purgeable state */
			if (src_object->purgable != VM_PURGABLE_NONVOLATILE) {
				int state;
				state = src_object->purgable;
				vm_object_purgable_control(
					new_object,
					VM_PURGABLE_SET_STATE_FROM_KERNEL,
					&state);
			}
			/* no pmap accounting for purgeable objects */
			new_entry->use_pmap = FALSE;
		}

		vm_object_unlock(new_object);
		new_object = VM_OBJECT_NULL;
	}

	/*
	 *	All codepaths above replaced src_object
	 *	in new_entry with a new object (new_copy_object),
	 *	release the reference we took above before dropping the lock.
	 */
	vm_object_deallocate(src_object);

	if (result != KERN_SUCCESS) {
		/* any error cases already deallocated the object that set to the copy entry */
		RETURN(result);
	}

#undef RETURN

CopySuccessful:
	/*  Link in the new copy entry.  */
	vm_map_copy_store_insert_tail(copy, new_entry);
	return KERN_SUCCESS;
}

/*
 * Create a vm_map_copy_t object of the requested range from the given map.
 * The copy object can contain either:
 * - a kernel buffer (small sizes optimization)
 * - a list of vm_map_entry_t which are copies of the map's entries, with
 *   appropriate COW SETUP where needed.
 * If the range is inside or crosses into a submap, the entries of the submap are copied
 * (not the entry that points to the submap)
 *
 * Returns an error if the range contains any holes or if the protection of an entry
 * doesn't allow it to be copied.
 * In case of an error, a possible side-effect is that some COPY_SYMMETRIC entries may be
 * setup for COW (needs_copy) even though there's no need.
 */
kern_return_t
vm_map_copyin_internal(
	vm_map_t                src_map,
	vm_map_address_ut       src_addr_u,
	vm_map_size_ut          len_u,
	int                     flags,
	vm_map_copy_t          *copy_result)   /* OUT */
{
	vm_map_offset_t src_start;      /* Start of current entry --  where copy is taking place now */
	vm_map_offset_t src_end;        /* End of entire region to be copied */
	vm_map_offset_t src_addr_unaligned;
#if HAS_MTE
	vm_map_offset_t src_addr_unaligned_tagged;
#endif /* HAS_MTE */
	vm_map_size_t   len;
	vm_map_entry_t  src_entry = NULL;

	vm_map_copy_t   copy;           /* Resulting copy */
	boolean_t       src_destroy;
	boolean_t       use_maxprot;
	boolean_t       preserve_purgeable;

	kern_return_t   kr;

	vmlp_api_start(VM_MAP_COPYIN_INTERNAL);

	if (flags & ~VM_MAP_COPYIN_ALL_FLAGS) {
		vmlp_api_end(VM_MAP_COPYIN_INTERNAL, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Check for copies of zero bytes.
	 */
	if (VM_SANITIZE_UNSAFE_IS_ZERO(len_u)) {
		*copy_result = VM_MAP_COPY_NULL;
		vmlp_api_end(VM_MAP_COPYIN_INTERNAL, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	/*
	 * Sanitize any input parameters that are addr/size/prot/inherit
	 */
	kr = vm_map_copyin_sanitize(
		src_map,
		src_addr_u,
		len_u,
		&src_start,
		&src_end,
		&len,
#if HAS_MTE
		&src_addr_unaligned,
		&src_addr_unaligned_tagged);
#else /* HAS_MTE */
		&src_addr_unaligned);
#endif /* HAS_MTE */
	if (__improbable(kr != KERN_SUCCESS)) {
		kr = vm_sanitize_get_kr(kr);
		vmlp_api_end(VM_MAP_COPYIN_INTERNAL, kr);
		return kr;
	}
	vmlp_range_event(src_map, src_start, len);

	src_destroy = (flags & VM_MAP_COPYIN_SRC_DESTROY) ? TRUE : FALSE;
	use_maxprot = (flags & VM_MAP_COPYIN_USE_MAXPROT) ? TRUE : FALSE;
	preserve_purgeable = (flags & VM_MAP_COPYIN_PRESERVE_PURGEABLE) ? TRUE : FALSE;

	vm_map_copyin_strategy strategy = _vm_map_copyin_select_strategy(
		src_map,
		len,
		src_start,
		src_end,
		use_maxprot,
		preserve_purgeable,
		flags);
	if (strategy == VM_MAP_COPYIN_STRATEGY_INVALID_ARGUMENT) {
		return KERN_INVALID_ADDRESS;
	} else if (
		strategy == VM_MAP_COPYIN_STRATEGY_KERNEL_LARGE_BUFFER ||
		strategy == VM_MAP_COPYIN_STRATEGY_KERNEL_BUFFER) {
#if HAS_MTE
		kr = vm_map_copyin_kernel_buffer(src_map, src_addr_unaligned_tagged,
		    len, strategy, src_destroy, copy_result);
#else /* HAS_MTE */
		kr = vm_map_copyin_kernel_buffer(src_map, src_addr_unaligned, len, strategy,
		    src_destroy, copy_result);
#endif /* HAS_MTE */
		vmlp_api_end(VM_MAP_COPYIN_INTERNAL, kr);
		return kr;
	}

	/* Ensure we don't forget about a newly defined type */
	assert(strategy == VM_MAP_COPYIN_STRATEGY_VIRTUAL_COPY);

	/*
	 *	Allocate a header element for the list.
	 *
	 *	Use the start and end in the header to
	 *	remember the endpoints prior to rounding.
	 */

	copy = vm_map_copy_allocate(VM_MAP_COPY_ENTRY_LIST,
	    VM_MAP_PAGE_SHIFT(src_map));
	copy->offset = src_addr_unaligned;
	copy->size = len;

	/* for error return cases */
#define RETURN(x)                                           \
	MACRO_BEGIN                                         \
	vm_map_range_sh_unlock(ctx, &src_map);              \
    RETURN_UNLOCKED(x);                                     \
    MACRO_END

#define RETURN_UNLOCKED(x)                                  \
    MACRO_BEGIN                                             \
	vm_map_copy_discard(copy);                              \
	vmlp_api_end(VM_MAP_COPYIN_INTERNAL, x);               \
	MACRO_RETURN(x);                                        \
	MACRO_END

	/* The top-level map we're iterating is not allowed to be a sealed submap. this was a limitation before
	 * range lock was introduced */
	assert(!vm_map_is_sealed(src_map));
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	/* vm_object_copy_quickly() can't be in the preflight since it takes object reference and preflight may be called
	 * more than once on an entry.
	 * so the code here recreates the conditions vm_object_copy_quickly() checks, without taking the object reference */
	/* BEGIN IGNORE CODESTYLE */
	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
		/* 
		 * Submaps are being descended into by the lock. 
		 * We preflight the child entries within the submap. 
		 */
		assert(!vme->is_sub_map);

		__assert_only boolean_t was_wired = (vme->wired_count != 0);
		vm_object_t src_object = VME_OBJECT(vme);

		if (src_object == VM_OBJECT_NULL) {  /* NULL means region was never populated */
			return KERN_SUCCESS;
		}
		/* MEMORY_OBJECT_COPY_SYMMETRIC case */

		if (src_object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC && !DEBUG4K_NO_COW_COPYIN_ON_MAP(vctx->vmlc_map)) {
			assert(!vm_map_lock_ctx_in_constant_submap(vctx));

			/* COPY_SYMMETRIC + non-zero wired_count should not be possible since wire changes it to delay */
			assert(!was_wired);
			/* COPY_SYMMETRIC + is_shared should not be possible */
			assert(!vme->is_shared);

			if (!vme->needs_copy) {     /* symmetric COW was not already setup for this entry */
				/* tell the lock it needs to setup COW on the current entry, if it's not already set.
				 * This will set vme->needs_copy = true
				 * This will also clip the entry if needed (as was the pre-range-lock implementation) */
				return VMRL_ERR_SETUP_SYMMETRIC_COW;
			}
		}
		return KERN_SUCCESS;
	});
	/* END IGNORE CODESTYLE */

	/* Needs to be a stream lock since we might need to drop the entry lock during the iteration in order to fault
	 * need to descend to submaps since the copy should only reference objects, not submaps
	 * VMRL_EX_SIMPLIFY is not relevant because this is a shared lock. instead, we call simplify on the entire
	 * range at the end
	 * VMRL_SH_NO_MIN_MAX_CHECK so that it's possible to remap the x86 commpage */
	kr = vm_map_range_sh_lock(ctx, &src_map, src_start, src_end,
	    VMRL_SH_STREAM_NO_HOLES | VMRL_SH_DESCEND_INTO_CONSTANT | VMRL_SH_NO_MIN_MAX_CHECK);
	if (kr != KERN_SUCCESS) {
		RETURN_UNLOCKED(kr);
	}

	/* Iterate the range entries */
	while ((src_entry = vm_map_range_stream_next_with_error(ctx, &kr)) != VM_MAP_ENTRY_NULL) {
		assert(kr == KERN_SUCCESS);
#if HAS_MTE
		kr = _vm_map_copyin_internal_check_mte_policy(
			ctx->vmlc_map,
			src_entry,
			src_addr_unaligned_tagged,
			len,
			flags);
		if (kr != KERN_SUCCESS) {
			RETURN(kr);
		}
#endif /* HAS_MTE */
		kr = vm_map_copyin_internal_for_entry(ctx, src_entry, flags, copy);
		if (kr != KERN_SUCCESS) {
			RETURN(kr);
		}
	}
	/* check failure from vm_map_range_stream_next_with_error() */
	if (kr != KERN_SUCCESS) {
		RETURN(kr); /* copy is going to be destroyed */
	}

	vm_map_range_sh_unlock(ctx, &src_map);
	/*
	 * If the source should be destroyed, do it now, since the
	 * copy was successful.
	 */
	if (src_destroy) {
		vmr_flags_t remove_flags = VM_MAP_REMOVE_NO_FLAGS;
		if (src_map == kernel_map) {
			remove_flags |= VM_MAP_REMOVE_KUNWIRE;
		}
		vm_map_ilk_lock(src_map);
		(void)vm_map_remove_and_iunlock(src_map, src_start, src_end,
		    remove_flags, KMEM_GUARD_NONE);
	} else {
		/* fix up the damage we did in the top level map (which is never going to be a sealed submap) */
		vm_map_simplify_range(src_map, src_start, src_end);
	}

	assert(VM_MAP_PAGE_SHIFT(src_map) == VM_MAP_COPY_PAGE_SHIFT(copy)); /* sanity, this was assigned earlier */

	/* Fix-up start and end points in copy.  This is necessary */
	/* when the various entries in the copy object were picked */
	/* up from different sub-maps which might have different offsets */

	vm_map_entry_t tmp_entry = vm_map_copy_first_entry(copy);
	vm_map_size_t copy_size = 0; /* compute actual size */
	while (tmp_entry != vm_map_copy_to_entry(copy)) {
		assert(tmp_entry->vme_start < tmp_entry->vme_end);
		vm_map_offset_t entry_len = tmp_entry->vme_end - tmp_entry->vme_start;
		assert(VM_MAP_PAGE_ALIGNED(src_start + entry_len, MIN(VM_MAP_COPY_PAGE_MASK(copy), PAGE_MASK)));
		assert(VM_MAP_PAGE_ALIGNED(src_start, MIN(VM_MAP_COPY_PAGE_MASK(copy), PAGE_MASK)));

		tmp_entry->vme_start = src_start;
		tmp_entry->vme_end = src_start + entry_len;

		src_start += entry_len;
		copy_size += entry_len;

		tmp_entry = tmp_entry->vme_next;
	}
	assert(src_start == src_end);

	if (VM_MAP_PAGE_SHIFT(src_map) != PAGE_SHIFT && copy_size < copy->size) {
		/*
		 * The actual size of the VM map copy is smaller than what
		 * was requested by the caller.  This must be because some
		 * PAGE_SIZE-sized pages are missing at the end of the last
		 * VM_MAP_PAGE_SIZE(src_map)-sized chunk of the range.
		 * The caller might not have been aware of those missing
		 * pages and might not want to be aware of it, which is
		 * fine as long as they don't try to access (and crash on)
		 * those missing pages.
		 * Let's adjust the size of the "copy", to avoid failing
		 * in vm_map_copyout() or vm_map_copy_overwrite().
		 */
		assert(vm_map_round_page(copy_size, VM_MAP_PAGE_MASK(src_map)) ==
		    vm_map_round_page(copy->size, VM_MAP_PAGE_MASK(src_map)));
		copy->size = copy_size;
	}

	*copy_result = copy;
	vmlp_api_end(VM_MAP_COPYIN_INTERNAL, KERN_SUCCESS);
	return KERN_SUCCESS;

#undef  RETURN
#undef RETURN_UNLOCKED
}

kern_return_t
vm_map_copy_extract(
	vm_map_t                src_map,
	vm_map_address_t        src_addr,
	vm_map_size_t           len,
	boolean_t               do_copy,
	vm_map_copy_t           *copy_result,   /* OUT */
	vm_prot_t               *cur_prot,      /* IN/OUT */
	vm_prot_t               *max_prot,      /* IN/OUT */
	vm_inherit_t            inheritance,
	vm_map_kernel_flags_t   vmk_flags)
{
	vm_map_copy_t   copy;
	kern_return_t   kr;
	vm_prot_t required_cur_prot, required_max_prot;

	/* Check for copies of zero bytes. */
	if (len == 0) {
		*copy_result = VM_MAP_COPY_NULL;
		return KERN_SUCCESS;
	}

	/* Check that the end address doesn't overflow */
	if (src_addr + len < src_addr) {
		return KERN_INVALID_ADDRESS;
	}
	if (__improbable(vm_map_range_overflows(src_map, src_addr, len))) {
		return KERN_INVALID_ADDRESS;
	}

	if (VM_MAP_PAGE_SIZE(src_map) < PAGE_SIZE) {
		DEBUG4K_SHARE("src_map %p src_addr 0x%llx src_end 0x%llx\n", src_map, (uint64_t)src_addr, (uint64_t)(src_addr + len));
	}

	required_cur_prot = *cur_prot;
	required_max_prot = *max_prot;

	/*
	 *	Allocate a header element for the list.
	 *	Use the start and end in the header to
	 *	remember the endpoints prior to rounding.
	 */
	copy = vm_map_copy_allocate(VM_MAP_COPY_ENTRY_LIST,
	    VM_MAP_PAGE_SHIFT(src_map));

	copy->offset = 0;
	copy->size = len;

	kr = vm_map_remap_extract(src_map,
	    src_addr,
	    len,
	    do_copy,             /* copy */
	    copy,
	    cur_prot,            /* IN/OUT */
	    max_prot,            /* IN/OUT */
	    inheritance,
	    vmk_flags);
	if (kr != KERN_SUCCESS) {
		vm_map_copy_discard(copy);
		if ((kr == KERN_INVALID_ADDRESS || kr == KERN_INVALID_ARGUMENT) && src_map->terminated) {
			/* tell the caller that this address space is gone */
			kr = KERN_TERMINATED;
		}
		return kr;
	}
	if (required_cur_prot != VM_PROT_NONE) {
		assert((*cur_prot & required_cur_prot) == required_cur_prot);
		assert((*max_prot & required_max_prot) == required_max_prot);
	}

	*copy_result = copy;
	return KERN_SUCCESS;
}


/*
 * Test if it is valid to change the copy_strategy from SYMMETRIC->DELAY
 * for the object backing only after doing a vm_object_shadow, or if we can
 * change the copy strategy of the existing object directly.
 *
 * Return true if we must shadow it, false if we can change it directly.
 */
static bool
vm_map_entry_must_shadow_to_change_copy_strategy(vm_map_entry_t src_entry)
{
	vm_object_t object = VME_OBJECT(src_entry);
	vm_map_size_t entry_size = (vm_map_size_t)(src_entry->vme_end - src_entry->vme_start);

	if (object == VM_OBJECT_NULL ||
	    object->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC) {
		/*
		 * Not ready to directly do a copy_strategy change, no need to shadow
		 * (it's ok to check this without the object lock, it will never go
		 * back to symmetric)
		 */
		return false;
	}

	bool needed = (src_entry->needs_copy ||         /* case 1 */
	    object->shadowed ||                         /* case 2 */
	    (object->internal && !object->true_share && /* case 3 */
	    !src_entry->is_shared && object->vo_size > entry_size));
	/*
	 * There are three cases here.
	 * In the first case, we need to complete a deferred symmetrical copy that we participated in.
	 * In the second and third cases, we need to create the shadow so that changes that we're about to make to the
	 * object do not interfere with any symmetrical copies which have occured (case 2) or which might occur (case 3).
	 *
	 * The first case is when we had deferred shadow object creation via the entry->needs_copy mechanism.
	 * This mechanism only works when only one entry points to the source object, and we are about to create
	 * a second entry pointing to the same object. The problem is that there is no way of getting from
	 * an object to the entries pointing to it. (Deferred shadow creation works with one entry because it occurs
	 * at fault time, and there we walk from the entry to the object when handling the fault.)
	 *
	 * The second case is when the object to be shared has already been copied with a symmetric copy, but we point
	 * directly to the object without needs_copy set in our entry. (This can happen because different ranges
	 * of an object can be pointed to by different entries. In particular, a single entry pointing to an object
	 * can be split by a call to vm_inherit, which, combined with task_create, can result in the different entries
	 * having different needs_copy values.)
	 * The shadowed flag in the object allows us to detect this case. The problem with this case is that if this object
	 * has or will have shadows, then we must not perform an asymmetric copy of this object, since such a copy
	 * allows the object to be changed, which will break the previous symmetrical copies (which rely upon the object
	 * not changing). In a sense, the 'shadowed' flag says "don't change this object".
	 * We fix this by creating a shadow object for this object, and sharing that. This works because we are free
	 * to change the shadow object (and thus to use an asymmetric copy strategy); this is also semantically correct,
	 * since this object is temporary, and therefore a copy of the object is as good as the object itself.
	 *
	 * The third case is when the object to be shared has parts sticking outside of the entry we're working
	 * with, and thus may in the future be subject to a symmetrical copy. (This is a preemptive version of case 2.)
	 * The check for object->internal in this case is because object->vo_size is valid only in that case.
	 */
	return needed;
}

bool
vm_map_should_shadow_to_change_copy_strategy(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t    src_entry,
	bool              apply_upl_optimization)
{
	if (vm_map_entry_must_shadow_to_change_copy_strategy(src_entry)) {
		return true;
	}

	if (apply_upl_optimization &&
	    vm_map_entry_should_cow_for_true_share(ctx, src_entry)) {
		return true;
	}
	return false;
}

/*
 * This function takes some COPY_SYMMETRIC backed entry, and transforms it to an entry with an entirely private
 * COPY_SYMMETRIC object. We first test for the cases where the entry's object may be pointed to by multiple
 * places. If none apply, the entry's object is already private.
 * If it's not, we do VME_OBJECT_SHADOW to get a private object. The original object may have writable mappings to it
 * and allowing direct writes to a copied object would bypass CoW, so we need to then revoke the writable
 * permissions to the mapping.
 * needs_copy is set to false on the entry because it is the only entry at this time that points to the object.
 * This is equivalent to CoW setup and resolve in one go.
 * pre-condition: The entry must be locked.
 */
static vm_object_t
vm_map_create_private_symmetric_object(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t    src_entry,
	bool              is_mapped_entry,
	bool              apply_upl_optimization)
{
	vm_object_t   object = VME_OBJECT(src_entry);
	vm_map_size_t entry_size = (vm_map_size_t)(src_entry->vme_end - src_entry->vme_start);
	vm_map_t      map = vm_map_lock_ctx_get_map(ctx);

	assert(object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC);

	/* is it needed to shadow to change the copy strategy for this entry? */
	bool needed = vm_map_should_shadow_to_change_copy_strategy(
		ctx, src_entry, apply_upl_optimization);

	if (!needed) {
		return object;
	}

	if (is_mapped_entry) {
		VM_ENTRY_ASSERT_EXCL_OWNER(src_entry);
		assert(!vm_map_is_sealed(map)); /* should not change entry in sealed map */
	} else {
		VM_ENTRY_ASSERT_LOCK_INVALID(src_entry, VMEL_INVALID_REASON_COPY_ENTRY);
	}
	if (!object->shadowed) {
		vm_object_lock(object);
		VM_OBJECT_SET_SHADOWED(object, TRUE);
		vm_object_unlock(object);
	}
	VME_OBJECT_SHADOW(src_entry, entry_size, vm_map_always_shadow(map));
	assert(src_entry->use_pmap);

	/*
	 * If we're making a shadow for other than
	 * copy on write reasons, then we have
	 * to remove write permission.
	 */

	bool is_writable = false;
	if (src_entry->protection & VM_PROT_WRITE) {
		is_writable = true;
#if __arm64e__
	} else if (src_entry->used_for_tpro) {
		is_writable = true;
#endif /* __arm64e__ */
	}
	if (!src_entry->needs_copy && is_writable) {
		/* This is CoW SETUP */
		vm_prot_t prot;
		if (pmap_has_prot_policy(map->pmap, src_entry->translated_allow_execute, src_entry->protection)) {
			panic("%s: map %p pmap %p entry %p 0x%llx:0x%llx prot 0x%x",
			    __FUNCTION__,
			    map, map->pmap,
			    src_entry,
			    (uint64_t)src_entry->vme_start,
			    (uint64_t)src_entry->vme_end,
			    src_entry->protection);
		}

		prot = src_entry->protection & ~VM_PROT_WRITE;

		if (override_nx(map, VME_ALIAS(src_entry)) && prot) {
			prot |= VM_PROT_EXECUTE;
		}

		if (pmap_has_prot_policy(map->pmap, src_entry->translated_allow_execute, prot)) {
			panic("%s: map %p pmap %p entry %p 0x%llx:0x%llx prot 0x%x",
			    __FUNCTION__,
			    map, map->pmap,
			    src_entry,
			    (uint64_t)src_entry->vme_start,
			    (uint64_t)src_entry->vme_end,
			    prot);
		}

		if (map->mapped_in_other_pmaps) {
			/* The top of this function assets the object at the top of the entry we're working on is SYMMETRIC
			 * and this should not be the case in a sealed submap due to the transformation in vm_map_seal() */
			panic("Found COPY_SYMMETRIC object in mapped_in_other_pmaps map");
#if MACH_ASSERT
		} else if (__improbable(map->pmap == PMAP_NULL)) {
			/* Some VM tests (in vm_tests.c) sometimes want to use a VM map without a pmap.
			 * Otherwise, this should never happen. */
			if (!thread_get_test_option(test_option_vm_map_allow_null_pmap)) {
				panic("null pmap");
			}
#endif /* MACH_ASSERT */
		} else {
			pmap_protect(vm_map_pmap(map),
			    src_entry->vme_start,
			    src_entry->vme_end,
			    prot);
		}
	}

	object = VME_OBJECT(src_entry); /* new object after resolve */
	src_entry->needs_copy = FALSE;
	return object;
}

static void
vm_map_fork_share(
	vm_map_lock_ctx_t old_ctx,
	vm_map_entry_t    old_entry,
	vm_map_t          new_map)
{
	vm_map_t        old_map = vm_map_lock_ctx_get_map(old_ctx);
	vm_object_t     object;
	vm_map_entry_t  new_entry;

	/*
	 *	New sharing code.  New map entry
	 *	references original object.  Internal
	 *	objects use asynchronous copy algorithm for
	 *	future copies.  First make sure we have
	 *	the right object.  If we need a shadow,
	 *	or someone else already has one, then
	 *	make a new shadow and share it.
	 */

	VM_ENTRY_ASSERT_EXCL_OWNER(old_entry);
	assert_vm_map_ilk_owned(new_map, LCK_RW_TYPE_EXCLUSIVE);

	if (!old_entry->is_sub_map) {
		object = VME_OBJECT(old_entry);
	}

	if (old_entry->is_sub_map) {
		assert(old_entry->wired_count == 0);
#ifndef NO_NESTED_PMAP
		if (old_entry->use_pmap) {
			kern_return_t   result;

			result = pmap_nest(new_map->pmap,
			    (VME_SUBMAP(old_entry))->pmap,
			    (addr64_t)old_entry->vme_start,
			    (uint64_t)(old_entry->vme_end - old_entry->vme_start));
			if (result) {
				panic("vm_map_fork_share: pmap_nest failed!");
			}
		}
#endif  /* NO_NESTED_PMAP */
	} else if (object == VM_OBJECT_NULL) {
		object = vm_object_allocate((vm_map_size_t)(old_entry->vme_end -
		    old_entry->vme_start), old_map->serial_id);
		VME_OFFSET_SET(old_entry, 0);
		VME_OBJECT_SET(old_entry, object, false, 0);
		old_entry->use_pmap = TRUE;
//		assert(!old_entry->needs_copy);
	} else if (object->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC) {
		/*
		 *	We are already using an asymmetric
		 *	copy, and therefore we already have
		 *	the right object.
		 */

		assert(!old_entry->needs_copy);
	} else {
		/* RANGELOCKINGTODO change this to use VMRL_ERR_PREPARE_FOR_SHARE_NOCLIP rdar://154928030 */
		object = vm_map_create_private_symmetric_object(old_ctx, old_entry,
		    /*is_mapped_entry=*/ true, /* upl_optimization */ false);
	}

	/*
	 *	If object was using a symmetric copy strategy,
	 *	change its copy strategy to the default
	 *	asymmetric copy strategy, which is copy_delay.
	 */
	if (!old_entry->is_sub_map) {
		vm_object_lock(object);
		if (object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
			object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
		}
		vm_object_mark_shared(object, VM_SHARE_TYPE_PERMANENT);
		vm_object_unlock(object);
	}

	/*
	 *	Clone the entry.
	 *	Mark both entries as shared.
	 */

	new_entry = vm_map_entry_copy_locked(new_map, old_entry);
	vm_map_entry_reinit_after_copy(old_map, new_entry);
	old_entry->is_shared = TRUE;
	new_entry->is_shared = TRUE;

	/*
	 * We're dealing with a shared mapping, so the resulting mapping
	 * should inherit some of the original mapping's accounting settings.
	 * "iokit_acct" should have been cleared in
	 * vm_map_entry_reinit_after_copy().
	 * "use_pmap" should stay the same as before (if it hasn't been reset
	 * to TRUE when we cleared "iokit_acct").
	 */
	assert(!new_entry->iokit_acct);

	/*
	 *	If old entry's inheritence is VM_INHERIT_NONE,
	 *	the new entry is for corpse fork, remove the
	 *	write permission from the new entry.
	 */
	if (old_entry->inheritance == VM_INHERIT_NONE) {
		new_entry->protection &= ~VM_PROT_WRITE;
		new_entry->max_protection &= ~VM_PROT_WRITE;
	}

	/*
	 *	Insert the entry into the new map -- we
	 *	know we're inserting at the end of the new
	 *	map.
	 */

	vm_map_store_insert(new_map, new_entry);
	vm_entry_unlock_exclusive(new_map, new_entry);

	/*
	 *	Update the physical map
	 */

	if (old_entry->is_sub_map) {
		/* Bill Angell pmap support goes here */
	} else {
		pmap_copy(new_map->pmap, old_map->pmap, new_entry->vme_start,
		    old_entry->vme_end - old_entry->vme_start,
		    old_entry->vme_start);
	}
}

static boolean_t
vm_map_fork_copy(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t    old_entry,
	vm_map_t          new_map,
	int               vm_map_copyin_flags)
{
	vm_map_copy_t copy;

	VM_ENTRY_ASSERT_EXCL_OWNER(old_entry);
	assert_vm_map_ilk_owned(new_map, LCK_RW_TYPE_EXCLUSIVE);

	vmlp_api_start(VM_MAP_FORK_COPY);

	copy = vm_map_copy_allocate(VM_MAP_COPY_ENTRY_LIST,
	    VM_MAP_PAGE_SHIFT(ctx->vmlc_map));
	copy->offset = old_entry->vme_start;
	copy->size = old_entry->vme_end - old_entry->vme_start;

	/*
	 *	Use maxprot version of copyin because we
	 *	care about whether this memory can ever
	 *	be accessed, not just whether it's accessible
	 *	right now.
	 */
	vm_map_copyin_flags |= VM_MAP_COPYIN_USE_MAXPROT;
#if HAS_MTE
	assert(!vm_kernel_map_is_kernel(new_map));
	vm_map_copyin_flags |= VM_MAP_COPYIN_DEST_USER;
#endif
	if (vm_map_copyin_internal_for_entry(
		    ctx, old_entry, vm_map_copyin_flags, copy) != KERN_SUCCESS) {
		vm_map_copy_discard(copy);
		vmlp_api_end(VM_MAP_FORK_COPY, FALSE);
		return FALSE;
	}
	/* Clear pointer to avoid misuse of unlocked old_entry */
	old_entry = VM_MAP_ENTRY_NULL;

	/* Insert the copy into the new map and free it. */
	vm_map_copy_insert(new_map, copy, (vm_map_store_rsv_t){ },
	    VM_MAP_KERNEL_FLAGS_FIXED());

	vmlp_api_end(VM_MAP_FORK_COPY, TRUE);
	return TRUE;
}

void
vm_map_inherit_limits(vm_map_t new_map, const struct _vm_map *old_map)
{
	new_map->size_limit = old_map->size_limit;
	new_map->data_limit = old_map->data_limit;
	new_map->user_wire_limit = old_map->user_wire_limit;
	new_map->reserved_regions = old_map->reserved_regions;
}

/*
 * For internal use by vm_map_fork and related functions only.
 * Not compatible with vm_inherit_t (do not cast from one to the other).
 */
__enum_closed_decl(vm_inherit_extended_t, uint32_t, {
	VM_INHERIT_EXT_NONE = 0x1,
	VM_INHERIT_EXT_SHARE,
	VM_INHERIT_EXT_COPY_FAST_PATH,
	VM_INHERIT_EXT_COPY_SLOW_PATH,
});

/*
 * Compute the adjusted inheritance for the entry, adjusting for options
 * passed by the caller and determining whether a quick copy would be
 * successful or not based on entry and object properties.
 */
static vm_inherit_extended_t
vm_map_fork_compute_extended_inheritance(
	vm_map_t       map,
	vm_map_entry_t entry,
	int            options)
{
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	switch (entry->inheritance) {
	case VM_INHERIT_NONE:
		/*
		 * If the caller used the VM_MAP_FORK_SHARE_IF_INHERIT_NONE option,
		 * share VM_INHERIT_NONE entries that are not backed by a device pager.
		 */
		if ((options & VM_MAP_FORK_SHARE_IF_INHERIT_NONE) &&
		    (entry->protection & VM_PROT_READ) &&
		    !(!entry->is_sub_map &&
		    VME_OBJECT(entry) != NULL &&
		    VME_OBJECT(entry)->pager != NULL &&
		    is_device_pager_ops(
			    VME_OBJECT(entry)->pager->mo_pager_ops))) {
			return VM_INHERIT_EXT_SHARE;
		}
		return VM_INHERIT_EXT_NONE;
	case VM_INHERIT_SHARE:
#if HAS_MTE
		if (!entry->is_sub_map && VME_OBJECT(entry) && vm_object_is_mte_mappable(VME_OBJECT(entry))) {
			/*
			 * Setting VM_INHERIT_SHARE on an entry pointing to an MTE object
			 * should always be forbidden, except along the corpse-fork path,
			 * which is handled in separate cases of this switch statement.
			 */
			panic("Entry with share inheritance unexpectedly points to MTE object.");
		}
#endif /* HAS_MTE */
		return VM_INHERIT_EXT_SHARE;
	case VM_INHERIT_COPY:
		if (entry->is_sub_map) {
			return VM_INHERIT_EXT_NONE;
		}

		vm_object_t object = VME_OBJECT(entry);

		if (object == VM_OBJECT_NULL) {
			assert3u(entry->wired_count, ==, 0);
			return VM_INHERIT_EXT_COPY_FAST_PATH;
		}

		if (options & VM_MAP_FORK_SHARE_IF_OWNED) {
			task_t owner;
			owner = VM_OBJECT_OWNER(object);
			if (owner != TASK_NULL &&
			    owner->map == map) {
				/*
				 * This mapping points at a VM object owned by the task being
				 * forked.
				 * Some tools reporting memory accounting info rely on the
				 * object ID, so share this mapping instead of copying, to make
				 * the corpse look exactly like the original task in that
				 * respect.
				 */
				assert(object->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC);
				return VM_INHERIT_EXT_SHARE;
			}
		}

		if ((object->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC) ||
		    (entry->wired_count != 0) ||
		    (object->true_share)) {
			return VM_INHERIT_EXT_COPY_SLOW_PATH;
		}

		return VM_INHERIT_EXT_COPY_FAST_PATH;
	default:
		panic("Unexpected inheritance value 0x%x.", entry->inheritance);
	}
}

/*
 *	vm_map_fork:
 *
 *	Create and return a new map based on the old
 *	map, according to the inheritance values on the
 *	regions in that map and the options.
 *
 *	The source map must not be locked.
 */
vm_map_t
vm_map_fork(
	ledger_t        ledger,
	vm_map_t        old_map,
	int             options)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	pmap_t          new_pmap;
	vm_map_t        new_map;
	vm_map_entry_t  old_entry;
	vm_map_entry_t  new_entry;
	boolean_t       src_needs_copy;
	boolean_t       new_entry_needs_copy;
	boolean_t       pmap_is64bit;
	int             vm_map_copyin_flags;
	int             map_create_options;
	kern_return_t   footprint_collect_kr;
	vm_inherit_extended_t extended_inheritance;

	vmlp_api_start(VM_MAP_FORK);

	/* Can't fork a kernel map. */
	if (vm_kernel_map_is_kernel(old_map)) {
		panic("vm_map_fork(%p): attempting to fork from a kernel map", old_map);
	}

	if (options & ~(VM_MAP_FORK_SHARE_IF_INHERIT_NONE |
	    VM_MAP_FORK_PRESERVE_PURGEABLE |
	    VM_MAP_FORK_CORPSE_FOOTPRINT |
	    VM_MAP_FORK_SHARE_IF_OWNED)) {
		/* unsupported option */
		vmlp_api_end(VM_MAP_FORK, -1);
		return VM_MAP_NULL;
	}

	pmap_is64bit =
#if defined(__i386__) || defined(__x86_64__)
	    old_map->pmap->pm_task_map != TASK_MAP_32BIT;
#elif defined(__arm64__)
	    old_map->pmap->is_64bit;
#else
#error Unknown architecture.
#endif

	unsigned int pmap_flags = 0;
	pmap_flags |= pmap_is64bit ? PMAP_CREATE_64BIT : 0;
#if defined(HAS_APPLE_PAC)
	pmap_flags |= old_map->pmap->disable_jop ? PMAP_CREATE_DISABLE_JOP : 0;
#endif
#if CONFIG_ROSETTA
	pmap_flags |= old_map->pmap->is_rosetta ? PMAP_CREATE_ROSETTA : 0;
#endif
#if PMAP_CREATE_FORCE_4K_PAGES
	if (VM_MAP_PAGE_SIZE(old_map) == FOURK_PAGE_SIZE &&
	    PAGE_SIZE != FOURK_PAGE_SIZE) {
		pmap_flags |= PMAP_CREATE_FORCE_4K_PAGES;
	}
#endif /* PMAP_CREATE_FORCE_4K_PAGES */
	new_pmap = pmap_create_options(ledger, (vm_map_size_t) 0, pmap_flags);
	if (new_pmap == NULL) {
		vmlp_api_end(VM_MAP_FORK, -1);
		return VM_MAP_NULL;
	}

	vm_map_reference(old_map);
	vm_map_ilk_lock(old_map);

	/* Note that we're creating a map out of fork() */
	map_create_options = VM_MAP_CREATE_VIA_FORK;
	if (options & VM_MAP_FORK_CORPSE_FOOTPRINT) {
		map_create_options |= VM_MAP_CREATE_CORPSE_FOOTPRINT;
		footprint_collect_kr = KERN_SUCCESS;
	}
	new_map = vm_map_create_with_page_shift(new_pmap,
	    old_map->min_offset,
	    old_map->max_offset,
	    VM_MAP_PAGE_SHIFT(old_map),
	    map_create_options);

	/* Inherit our parent's ID. */
#if HAS_MTE
	/*
	 * If we assigned a new ID to forked children, then MTE CoW mappings would be
	 * faulted into the child as non-MTE, which seems wrong.
	 */
#endif /* HAS_MTE */
	vm_map_assign_serial(new_map, old_map->serial_id);
#if HAS_MTE
	/* Inherit parent restrictions on receiving untagged aliases to MTE pages */
	new_pmap->restrict_receiving_aliases_to_tagged_memory =
	    vm_map_get_pmap(old_map)->restrict_receiving_aliases_to_tagged_memory;
#endif /* HAS_MTE */

	/* inherit cs_enforcement */
	vm_map_cs_enforcement_set(new_map, old_map->cs_enforcement);

	vm_map_ilk_lock(new_map);
	vm_commit_pagezero_status(new_map);

	/* inherit the parent rlimits */
	vm_map_inherit_limits(new_map, old_map);

#if CONFIG_MAP_RANGES
	/* inherit the parent map's VM ranges */
	vm_map_range_fork(new_map, old_map);
#endif

#if CODE_SIGNING_MONITOR
	/* Prepare the monitor for the fork */
	csm_fork_prepare(old_map->pmap, new_pmap);
#endif

	/*
	 * Pre-nest the shared region's pmap.
	 */
	pmap_fork_nest(old_map->pmap, new_pmap);

	/* BEGIN IGNORE CODESTYLE */
	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
		vm_inherit_extended_t ext_inheritance =
		    vm_map_fork_compute_extended_inheritance(vctx->vmlc_map, vme, options);
		if ((ext_inheritance == VM_INHERIT_EXT_COPY_FAST_PATH) &&
		    (VME_OBJECT(vme) != VM_OBJECT_NULL) &&
		    !vme->needs_copy) {
			return VMRL_ERR_SETUP_SYMMETRIC_COW;
		}
		return KERN_SUCCESS;
	});
	/* END IGNORE CODESTYLE */
	vm_map_t tmp_old_map = old_map; /* range lock NULLS the map param, but fork wants to use the old map */
	vmrl_ex_flags_t vmrl_flags = VMRL_EX_STREAM | VMRL_EX_WHOLE_MAP | VMRL_EX_ILK_LOCKED | VMRL_EX_NO_PMAP_UNNEST;
	kern_return_t kr = vm_map_range_ex_lock(ctx, &tmp_old_map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END, vmrl_flags);
	if (kr != KERN_SUCCESS) {
		assert3u(kr, ==, KERN_INVALID_ADDRESS);
		/* No entries in the map at all, jump over the iteration. */
		goto after_loop;
	}

	while ((old_entry = vm_map_range_stream_next(ctx))) {
		/*
		 * No submap descent. Exclusive range lock does not descend
		 * into constant submaps, and transparent submaps don't happen
		 * because the map is not a kernel map (as asserted above).
		 */
		assert(!vm_map_lock_ctx_is_descended(ctx));

		vmlp_range_event_entry(old_map, old_entry);
		/*
		 * Abort any corpse collection if the system is shutting down.
		 */
		if ((options & VM_MAP_FORK_CORPSE_FOOTPRINT) &&
		    get_system_inshutdown()) {
			vm_map_corpse_footprint_collect_done(new_map);
			vm_map_ilk_unlock(new_map);
			vm_map_range_ex_unlock(ctx, &tmp_old_map);
			vm_map_deallocate(new_map);
			vm_map_deallocate(old_map);
			printf("Aborting corpse map due to system shutdown\n");
			vmlp_api_end(VM_MAP_FORK, -1);
			return VM_MAP_NULL;
		}

		extended_inheritance =
		    vm_map_fork_compute_extended_inheritance(old_map, old_entry, options);

		if (extended_inheritance != VM_INHERIT_EXT_NONE &&
		    (options & VM_MAP_FORK_CORPSE_FOOTPRINT) &&
		    footprint_collect_kr == KERN_SUCCESS) {
			/*
			 * The corpse won't have old_map->pmap to query
			 * footprint information, so collect that data now
			 * and store it in new_map->vmmap_corpse_footprint
			 * for later autopsy.
			 */
			vm_map_ilk_lock(old_map);
			footprint_collect_kr =
			    vm_map_corpse_footprint_collect(old_map,
			    old_entry,
			    new_map);
			vm_map_ilk_unlock(old_map);
		}

		switch (extended_inheritance) {
		case VM_INHERIT_EXT_NONE:
			break;

		case VM_INHERIT_EXT_SHARE:
			vm_map_fork_share(ctx, old_entry, new_map);
			break;

		case VM_INHERIT_EXT_COPY_FAST_PATH:
			assert(!old_entry->used_for_jit);
			new_entry = vm_map_entry_copy_locked_no_ownership(new_map, old_entry);
			vm_map_entry_reinit_after_copy(old_map, new_entry);
			assert(!new_entry->is_sub_map);
			if (old_entry->vme_permanent) {
				/* inherit "permanent" on fork() */
				new_entry->vme_permanent = TRUE;
			}

			/*
			 * We're dealing with a copy-on-write operation,
			 * so the resulting mapping should not inherit
			 * the original mapping's accounting settings.
			 * "iokit_acct" should have been cleared in
			 * vm_map_entry_reinit_after_copy().
			 * "use_pmap" should be reset to its default
			 * (TRUE) so that the new mapping gets
			 * accounted for in the task's memory footprint.
			 */
			assert(!new_entry->iokit_acct);
			new_entry->use_pmap = TRUE;

			__assert_only bool ok_quickly = vm_object_copy_quickly(
				VME_OBJECT(new_entry),
				VME_OFFSET(old_entry),
				(old_entry->vme_end -
				old_entry->vme_start),
				&src_needs_copy,
				&new_entry_needs_copy);
			if (!ok_quickly) {
				/* vm_map_fork_compute_extended_inheritance should never be wrong */
				panic(
					"Failed to make a quick copy of an object despite preflight (%d).",
					VME_OBJECT(new_entry)->copy_strategy);
			}

			/*
			 * CoW should have been setup on the source entry by the lock at
			 * the preflight's request.
			 */
			if (VME_OBJECT(old_entry) != VM_OBJECT_NULL) {
				assert(old_entry->needs_copy);
			}
			new_entry->needs_copy = new_entry_needs_copy;

			/*
			 *	Insert the entry at the end
			 *	of the map.
			 */

			vm_map_store_insert(new_map, new_entry);
			vm_entry_unlock_exclusive(new_map, new_entry);
			vmlp_range_event_entry(new_map, new_entry);
			break;
		case VM_INHERIT_EXT_COPY_SLOW_PATH:
			vm_map_copyin_flags = VM_MAP_COPYIN_FORK;
			if (options & VM_MAP_FORK_PRESERVE_PURGEABLE) {
				vm_map_copyin_flags |=
				    VM_MAP_COPYIN_PRESERVE_PURGEABLE;
			}
			if (!old_entry->wired_count &&
			    ((VME_OBJECT(old_entry) == VM_OBJECT_NULL) ||
			    !(VME_OBJECT(old_entry)->true_share))) {
				/*
				 * Don't update jit_entry_exists for wired entries or true
				 * share objects to match existing behavior.
				 */
				if (old_entry->used_for_jit == TRUE &&
				    VM_MAP_POLICY_ALLOW_JIT_COPY(old_map)) {
					new_map->jit_entry_exists = TRUE;
				}
			}
			vm_map_fork_copy(ctx, old_entry, new_map,
			    vm_map_copyin_flags);
			break;
		default:
			panic("Unexpected extended inheritance.");
		}
	}
	vm_map_range_ex_unlock(ctx, &tmp_old_map);
after_loop:

#if defined(__arm64__)
	pmap_insert_commpage(new_map->pmap);
#endif /* __arm64__ */

	if (options & VM_MAP_FORK_CORPSE_FOOTPRINT) {
		vm_map_corpse_footprint_collect_done(new_map);
	}

	vm_map_ilk_lock(old_map);

	/* Propagate JIT entitlement for the pmap layer. */
	if (pmap_get_jit_entitled(old_map->pmap)) {
		/* Tell the pmap that it supports JIT. */
		pmap_set_jit_entitled(new_map->pmap);
	}

	/* Propagate TPRO settings for the pmap layer */
	if (pmap_get_tpro(old_map->pmap)) {
		/* Tell the pmap that it supports TPRO */
		pmap_set_tpro(new_map->pmap);
	}

#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
	/* Propagate sec properties from the old map to the new map. */
	if (vm_map_has_sec_access(old_map)) {
		vm_map_mark_has_sec_access_ilocked(new_map);
	}
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */

	vm_map_ilk_unlock(new_map);
	vm_map_ilk_unlock(old_map);
	vm_map_deallocate(old_map);

	vmlp_api_end(VM_MAP_FORK, 0);
	return new_map;
}

/*
 * vm_map_exec:
 *
 *      Setup the "new_map" with the proper execution environment according
 *	to the type of executable (platform, 64bit, chroot environment).
 *	Map the comm page and shared region, etc...
 */
kern_return_t
vm_map_exec(
	vm_map_t        new_map,
	task_t          task,
	boolean_t       is64bit,
	void            *fsroot,
	cpu_type_t      cpu,
	cpu_subtype_t   cpu_subtype,
	boolean_t       reslide,
	boolean_t       is_driverkit,
	uint32_t        rsr_version)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: task %p: vm_map_exec(%p,%p,%p,0x%x,0x%x): ->\n",
		(void *)VM_KERNEL_ADDRPERM(current_task()),
		(void *)VM_KERNEL_ADDRPERM(new_map),
		(void *)VM_KERNEL_ADDRPERM(task),
		(void *)VM_KERNEL_ADDRPERM(fsroot),
		cpu,
		cpu_subtype));
	(void) vm_commpage_enter(new_map, task, is64bit);

	(void) vm_shared_region_enter(new_map, task, is64bit, fsroot, cpu, cpu_subtype, reslide, is_driverkit, rsr_version);

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: task %p: vm_map_exec(%p,%p,%p,0x%x,0x%x): <-\n",
		(void *)VM_KERNEL_ADDRPERM(current_task()),
		(void *)VM_KERNEL_ADDRPERM(new_map),
		(void *)VM_KERNEL_ADDRPERM(task),
		(void *)VM_KERNEL_ADDRPERM(fsroot),
		cpu,
		cpu_subtype));

	/*
	 * Some devices have region(s) of memory that shouldn't get allocated by
	 * user processes. The following code creates dummy vm_map_entry_t's for each
	 * of the regions that needs to be reserved to prevent any allocations in
	 * those regions.
	 */
	kern_return_t kr = KERN_FAILURE;
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_FIXED_PERMANENT();
	vmk_flags.vmkf_beyond_max = true;

	const struct vm_reserved_region *regions = NULL;
	size_t num_regions = ml_get_vm_reserved_regions(is64bit, &regions);
	assert((num_regions == 0) || (num_regions > 0 && regions != NULL));

	for (size_t i = 0; i < num_regions; ++i) {
		vm_map_offset_t address = regions[i].vmrr_addr;

		kr = vm_map_enter(
			new_map,
			&address,
			regions[i].vmrr_size,
			(vm_map_offset_t)0,
			vmk_flags,
			VM_OBJECT_NULL,
			(vm_object_offset_t)0,
			FALSE,
			VM_PROT_NONE,
			VM_PROT_NONE,
			VM_INHERIT_COPY);

		if (kr != KERN_SUCCESS) {
			os_log_error(OS_LOG_DEFAULT, "Failed to reserve %s region in user map %p %d", regions[i].vmrr_name, new_map, kr);
			return KERN_FAILURE;
		}
	}

	new_map->reserved_regions = (num_regions ? TRUE : FALSE);

	return KERN_SUCCESS;
}

#if HAS_MTE

/*
 * vm_map_page_tags_get:
 *
 * Given a virtual address and a VM map,
 * Resolve the correspnonding resident memory,
 * and copy the corresponding tags for the containing physical page.
 * If the memory turns out to not be resident, no data will be retrieved.
 */
kern_return_t
vm_map_page_tags_get(vm_map_t map, vm_address_t page_addr, uint64_t *buf, vm_size_t size)
{
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);
	assert((page_addr & PAGE_MASK) == 0);

	/* validate the page is resident and MTE-enabled */
	kern_return_t error;
	vm_map_entry_t entry;

	error = vm_map_find_entry_sh_locked(ctx, &map, page_addr, VMRL_FIND_SH_DEFAULT);
	if (error != KERN_SUCCESS) {
		goto out_unlocked;
	}

	entry = vm_map_found_entry_get_entry(ctx);

	/* rdar://134321998 simplifying for now.. implications might be minor currently,
	 * but this should could be made to descend rather than giveup on constant submaps
	 */
	if (entry->is_sub_map) {
		error = KERN_FAILURE;
		goto out_unlock_entry;
	}

	vm_object_t object = VME_OBJECT(entry);
	if (object == VM_OBJECT_NULL) {
		error = KERN_FAILURE;
		goto out_unlock_entry;
	}

	vm_object_lock(object);

	/* verify object/page has MTE enabled*/
	if (!vm_object_is_mte_mappable(object)) {
		error = KERN_FAILURE;
		goto out_unlock_entry_and_object;
	}

	/* rdar://134321998 we need to take care of shadow chains here. */

	vm_object_offset_t offset = vm_map_lock_ctx_offset_for_address(ctx,
	    page_addr);
	vm_page_t page = vm_page_lookup(object, vm_object_trunc_page(offset));
	if (page == VM_PAGE_NULL) {
		error = KERN_FAILURE;
		goto out_unlock_entry_and_object;
	}

	ppnum_t page_phys = VM_PAGE_GET_PHYS_PAGE(page);
	if (!pmap_valid_page(page_phys)) {
		error = KERN_FAILURE;
		goto out_unlock_entry_and_object;
	}

	/* fill the buffer with the page's tags */
	vm_address_t vcur = phystokv(ptoa(page_phys));
	mte_bulk_read_tags((caddr_t)vcur, PAGE_SIZE, (mte_bulk_taglist_t *)buf, size);


out_unlock_entry_and_object:
	vm_object_unlock(object);
out_unlock_entry:
	vm_map_found_entry_sh_unlock(ctx, &map);
out_unlocked:
	return error;
}
#endif /* HAS_MTE */

/* Helper function to interrogate a VM entry's state for vm_map_region_recurse */
uint8_t
vm_map_entry_info_flags(vm_map_entry_t entry)
{
	uint8_t flags = 0;
#if HAS_MTE
	vm_object_t object = VME_OBJECT(entry);
#endif /* HAS_MTE */
	if (entry->used_for_jit) {
		flags |= VM_REGION_FLAG_JIT_ENABLED;
	}


#if HAS_MTE
	if (object != VM_OBJECT_NULL && vm_object_is_mte_mappable(object)) {
		flags |= VM_REGION_FLAG_MTE_ENABLED;
	}
#endif /* HAS_MTE */
	return flags;
}

/*!
 * @abstract
 * Helper for to optionally synthesize guard object "fake" entries.
 *
 * @discussion
 * Callers of vm_region() and friends will assume that when there are holes they
 * can do fixed mappings in said holes, which guard objects will reject.
 *
 * As a result, fake ---/--- entries are generated for holes in guard object
 * slots so that caller's expectations are respected.
 *
 * @param map           The map "entry" belongs to.
 * @param address       The address being looked up.
 * @param entry         The entry that contains @c address or is right past it.
 * @param fake_entry    A pointer to a vm map entry buffer to be used for fake
 *                      synthesized entries.
 */
static vm_map_entry_t
vm_map_region_synthesize_guard_object_hole(
	vm_map_t                map,
	vm_map_address_t        address,
	vm_map_entry_t          entry,
	vm_map_entry_t          fake_entry)
{
	vm_guard_object_chunk_t chunk = NULL;
	vm_map_address_t        start, end;
	vm_map_entry_t          prev;

	if (map->guard_object_slabs == NULL && map->guard_object_user == NULL) {
		return entry;
	}

	if (entry != vm_map_to_entry(map) && entry->vme_start <= address) {
		return entry;
	}

	vm_map_ilk_lock_shared(map);
	prev = entry->vme_prev;

	if (map->terminated) {
		/*
		 * when a map is terminated, invariants about entries
		 * no longer hold.
		 */
		chunk = NULL;
	} else if (VME_IN_CHUNK(prev) &&
	    address < vmgo_chunk_end(vms_chunk(prev->vme_chunk))) {
		chunk   = vms_chunk(prev->vme_chunk);
		start   = prev->vme_end;
		end     = vmgo_chunk_end(chunk);
		if (entry != vm_map_to_entry(map) && entry->vme_start < end) {
			end = entry->vme_start;
		}
	} else if (VME_IN_CHUNK(entry)) {
		chunk   = vms_chunk(entry->vme_chunk);
		start   = vmgo_chunk_start(chunk);
		end     = entry->vme_start;
	} else {
		chunk  = NULL;
	}

	if (chunk) {
		*fake_entry = (struct vm_map_entry){
			.vme_start   = start,
			.vme_end     = end,
			.vme_alias   = VM_MEMORY_GUARD,
			.inheritance = VM_INHERIT_NONE,
		};
		vm_entry_lock_init_invalid(fake_entry,
		    VMEL_INVALID_REASON_FAKE_ENTRY);
		entry = fake_entry;
	}

	vm_map_ilk_unlock_shared(map);

	return entry;
}

vm_map_entry_t
vm_map_region_resolve_entry(
	vm_map_lock_ctx_t       ctx,
	vm_map_t               *mapp,
	vm_map_address_t        start,
	vmrl_sh_flags_t         flags,
	vm_map_entry_t          fake_entry,
	kern_return_t          *kr_out)
{
	vm_map_t       map = *mapp;
	vm_map_entry_t entry;
	kern_return_t  kr;

	kr = vm_map_range_sh_lock(ctx, mapp, start, VMRL_END_VA(map),
	    VMRL_SH_STREAM | flags);
	if (kr == KERN_SUCCESS) {
		map   = vm_map_lock_ctx_get_map(ctx);
		entry = vm_map_range_stream_next(ctx);
	} else {
		entry = vm_map_to_entry(map);
	}

	entry = vm_map_region_synthesize_guard_object_hole(map,
	    start, entry, fake_entry);

	if (entry == vm_map_to_entry(map)) {
		entry = VM_MAP_ENTRY_NULL;
	}

	*kr_out = kr;
	return entry;
}

void
vm_map_region_resolve_done(vm_map_lock_ctx_t ctx, vm_map_t *mapp, kern_return_t kr)
{
	if (kr == KERN_SUCCESS) {
		vm_map_range_sh_unlock(ctx, mapp);
	}
}

/*
 *	vm_region_recurse: A form of vm_region which follows the
 *	submaps in a target map
 *	If *nesting_depth is passed as zero, vm_region_recurse will give information
 *      about the top level map (`map`) and not descend into submaps.
 *	If it is passed as nonzero, it will give information about the entries
 *	within any submaps it may encounter.
 *	On exit, *nesting_depth is set to 0 if the information is about a top-level
 *	entry, and 1 if it information is about an entry within a submap.
 */
kern_return_t
vm_map_region_recurse_64(
	vm_map_t                map,
	vm_map_offset_ut       *address_u,      /* IN/OUT */
	vm_map_size_ut         *size_u,         /* OUT */
	natural_t              *nesting_depth,  /* IN/OUT */
	vm_region_submap_info_64_t submap_info, /* IN/OUT */
	mach_msg_type_number_t *count)          /* IN/OUT */
{
	struct vm_map_entry     fake;
	mach_msg_type_number_t  original_count;
	vm_region_extended_info_data_t  extended;
	vm_map_offset_t                 user_address;
	/*
	 * "curr_entry" is the VM map entry following or including the
	 * address we're looking for.
	 */
	vm_map_entry_t                  curr_entry;
	bool                            look_for_pages;
	vm_region_submap_short_info_64_t short_info;
	bool                            do_region_footprint;
	int                             effective_page_size, effective_page_shift;
	boolean_t                       submap_needed_copy = false;
	vm_map_address_t                region_start; /* start of the region we're looking at */
	vm_map_address_t                region_end; /* end of the region we're looking at */
	vm_object_id_t                  object_id_full;
	kern_return_t                   resolve_kr;
	vm_map_address_t                final_entry_end; /* end of last entry in the map.
	                                                  *  Used to report the physical
	                                                  *  footprint */
	vmrl_sh_flags_t lock_flags;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_REGION_RECURSE_64);

	if (map == VM_MAP_NULL) {
		/* no address space to work on */
		vmlp_api_end(VM_MAP_REGION_RECURSE_64, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	user_address = vm_sanitize_addr(map, *address_u);

#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
	/*
	 * Ideally we'd like to emulate vm_sanitize_validate_non_canonical_ut_addr() behavior
	 * by rejecting virtual addresses containing metadata (PAC, TBI, MTE), but we have to
	 * account for the "fake_region" therefore we settle to just refuse metadata in the
	 * MTE bits. Due to compatibility with callers expecting to find the end of the
	 * addressable user range, we return KERN_INVALID_ADDRESS rather than KERN_INVALID_AGUMENT.
	 * with callers expecting to find the end of the addressable user range,
	 */
	if (user_address != vm_memtag_canonicalize(map, user_address)) {
		vmlp_api_end(VM_MAP_REGION_RECURSE_64, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */

	effective_page_shift = vm_self_region_page_shift(map);
	effective_page_size = (1 << effective_page_shift);

	if (*count < VM_REGION_SUBMAP_SHORT_INFO_COUNT_64) {
		/*
		 * "info" structure is not big enough and would overflow
		 */
		vmlp_api_end(VM_MAP_REGION_RECURSE_64, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	do_region_footprint = task_self_region_footprint();
	original_count = *count;

	if (original_count < VM_REGION_SUBMAP_INFO_V0_COUNT_64) {
		*count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
		look_for_pages = FALSE;
		short_info = (vm_region_submap_short_info_64_t) submap_info;
		submap_info = NULL;
	} else {
		look_for_pages = TRUE;
		*count = VM_REGION_SUBMAP_INFO_V0_COUNT_64;
		short_info = NULL;

		if (original_count >= VM_REGION_SUBMAP_INFO_V1_COUNT_64) {
			*count = VM_REGION_SUBMAP_INFO_V1_COUNT_64;
		}
		if (original_count >= VM_REGION_SUBMAP_INFO_V2_COUNT_64) {
			*count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
		}
	}

	lock_flags = VMRL_SH_STREAM | VMRL_SH_NO_MIN_MAX_CHECK;
	if ((*nesting_depth) != 0) {
		/*
		 * If requested, descend into submaps
		 */
		lock_flags |= VMRL_SH_DESCEND_INTO_CONSTANT;
	} else {
		/*
		 * Otherwise, don't do any descent by default,
		 * even for otherwise transparent submaps.
		 * Callers of this may care about the address space available,
		 * and a submap entry still takes away the address space even if
		 * the submap is empty.
		 */
		lock_flags |= VMRL_SH_NO_DESCEND_TRANSPARENT;
	}
	assert(not_in_kdp);

	vm_map_ilk_lock(map);
	final_entry_end = vm_map_last_entry(map)->vme_end;

	lock_flags |= VMRL_SH_ILK_LOCKED;

	curr_entry = vm_map_region_resolve_entry(ctx, &map, user_address,
	    lock_flags, &fake, &resolve_kr);

	if (curr_entry == VM_MAP_ENTRY_NULL) {
		/*
		 * No entry at this address or later in the map.
		 * If we want to give the fake region for the physical footprint,
		 * do that.
		 * Otherwise, just return KERN_INVALID_ADDRESS
		 */

		vm_map_region_resolve_done(ctx, &map, resolve_kr);

		if (do_region_footprint && user_address <= final_entry_end) {
			ledger_amount_t ledger_resident = 0, ledger_compressed = 0;
			/*
			 * Add a fake memory region to account for
			 * purgeable and/or ledger-tagged memory that
			 * counts towards this task's memory footprint,
			 * i.e. the resident/compressed pages of non-volatile
			 * objects owned by that task.
			 */
			if (__improbable(map->pmap == NULL)) {
				/* Some VM tests reach this. (TODO make this more strict, rdar://148290198) */
				panic_on_release_builds("null pmap");
			} else {
				task_ledgers_footprint(map->pmap->ledger,
				    &ledger_resident,
				    &ledger_compressed);
			}
			if (ledger_resident + ledger_compressed == 0) {
				/* no purgeable memory usage to report */
				vmlp_api_end(VM_MAP_REGION_RECURSE_64, KERN_INVALID_ADDRESS);
				return KERN_INVALID_ADDRESS;
			}
			/* fake region to show nonvolatile footprint */
			if (look_for_pages) {
				submap_info->protection = VM_PROT_DEFAULT;
				submap_info->max_protection = VM_PROT_DEFAULT;
				submap_info->inheritance = VM_INHERIT_DEFAULT;
				submap_info->offset = 0;
				submap_info->user_tag = -1;
				submap_info->pages_resident = (unsigned int) (ledger_resident / effective_page_size);
				submap_info->pages_shared_now_private = 0;
				submap_info->pages_swapped_out = (unsigned int) (ledger_compressed / effective_page_size);
				submap_info->pages_dirtied = submap_info->pages_resident;
				submap_info->ref_count = 1;
				submap_info->shadow_depth = 0;
				submap_info->external_pager = 0;
				submap_info->share_mode = SM_PRIVATE;
				submap_info->is_submap = 0;
				submap_info->behavior = VM_BEHAVIOR_DEFAULT;
				submap_info->object_id = VM_OBJECT_ID_FAKE(map, task_ledgers.purgeable_nonvolatile);
				submap_info->user_wired_count = 0;
				submap_info->pages_reusable = 0;
			} else {
				short_info->user_tag = -1;
				short_info->offset = 0;
				short_info->protection = VM_PROT_DEFAULT;
				short_info->inheritance = VM_INHERIT_DEFAULT;
				short_info->max_protection = VM_PROT_DEFAULT;
				short_info->behavior = VM_BEHAVIOR_DEFAULT;
				short_info->user_wired_count = 0;
				short_info->is_submap = 0;
				short_info->object_id = VM_OBJECT_ID_FAKE(map, task_ledgers.purgeable_nonvolatile);
				short_info->external_pager = 0;
				short_info->shadow_depth = 0;
				short_info->share_mode = SM_PRIVATE;
				short_info->ref_count = 1;
			}
			*nesting_depth = 0;
			*address_u = vm_sanitize_wrap_addr(final_entry_end);
			*size_u    = vm_sanitize_wrap_size(ledger_resident + ledger_compressed);
			vmlp_api_end(VM_MAP_REGION_RECURSE_64, KERN_SUCCESS);
			return KERN_SUCCESS;
		}
		vmlp_api_end(VM_MAP_REGION_RECURSE_64, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}

	/*
	 * region_start/end is the start/end of the entry we are considering.
	 * they could be smaller than the actual entry if we are in a submap
	 * and the parent map gives a window smaller than the entry.
	 */
	region_start = curr_entry->vme_start;
	region_end = curr_entry->vme_end;

	if (ctx->__vmlc_descended == VMLC_NOT_DESCENDED) {
		*nesting_depth = 0;

		/*
		 * We're not descended.
		 * Return the start of the relevant region
		 */
		*address_u = vm_sanitize_wrap_addr(region_start);
	} else {
		vm_map_address_t parent_window_start, parent_window_end;
		submap_needed_copy = vm_map_lock_ctx_is_in_needs_copy_submap(ctx);

		/* Our submaps are all depth 1 */
		*nesting_depth = 1;

		/*
		 * The region start needs to be adjusted to the window the submap entry
		 * actually grants to us, even if the entry goes outside of the bounds
		 * of that window.
		 * So we always clamp the region to the relevant bounds, which
		 * means MAXing the start and MINing the end.
		 */
		vm_map_lock_ctx_get_parent_entry_window(ctx,
		    &parent_window_start, &parent_window_end);

		region_start = MAX(region_start, parent_window_start);
		region_end = MIN(region_end, parent_window_end);

		*address_u = vm_sanitize_wrap_addr(
			vm_map_lock_ctx_to_parent_address(ctx, region_start));
	}

	*size_u = vm_sanitize_wrap_size(region_end - region_start);

	if (look_for_pages) {
		submap_info->user_tag = VME_ALIAS(curr_entry);
		submap_info->offset = VME_OFFSET(curr_entry);
		submap_info->protection = curr_entry->protection;
		submap_info->inheritance = curr_entry->inheritance;
		submap_info->max_protection = curr_entry->max_protection;
		submap_info->behavior = curr_entry->behavior;
		submap_info->user_wired_count = curr_entry->user_wired_count;
		submap_info->is_submap = curr_entry->is_sub_map;
		if (curr_entry->is_sub_map) {
			submap_info->object_id = VM_OBJECT_ID(VME_SUBMAP(curr_entry));
		} else {
			submap_info->object_id = VM_OBJECT_ID(VME_OBJECT(curr_entry));
			submap_info->flags = vm_map_entry_info_flags(curr_entry);
		}
	} else {
		short_info->user_tag = VME_ALIAS(curr_entry);
		short_info->offset = VME_OFFSET(curr_entry);
		short_info->protection = curr_entry->protection;
		short_info->inheritance = curr_entry->inheritance;
		short_info->max_protection = curr_entry->max_protection;
		short_info->behavior = curr_entry->behavior;
		short_info->user_wired_count = curr_entry->user_wired_count;
		short_info->is_submap = curr_entry->is_sub_map;
		if (curr_entry->is_sub_map) {
			short_info->object_id = VM_OBJECT_ID(VME_SUBMAP(curr_entry));
		} else {
			short_info->object_id = VM_OBJECT_ID(VME_OBJECT(curr_entry));
			short_info->flags = vm_map_entry_info_flags(curr_entry);
		}
	}

	extended.pages_resident = 0;
	extended.pages_swapped_out = 0;
	extended.pages_shared_now_private = 0;
	extended.pages_dirtied = 0;
	extended.pages_reusable = 0;
	extended.external_pager = 0;
	extended.shadow_depth = 0;
	extended.share_mode = SM_EMPTY;
	extended.ref_count = 0;

	if (curr_entry->is_sub_map) {
		object_id_full = (vm_object_id_t)VM_KERNEL_ADDRHASH(VME_SUBMAP(curr_entry));
	} else if (VME_OBJECT(curr_entry)) {
		object_id_full = (vm_object_id_t)VM_KERNEL_ADDRHASH(VME_OBJECT(curr_entry));
	} else {
		object_id_full = 0ull;
	}


	/* Gather more information about the region, fill it in extended */
	if (!curr_entry->is_sub_map) {
		vm_map_region_walk(ctx->vmlc_map,
		    region_start,
		    curr_entry,
		    (VME_OFFSET(curr_entry) +
		    (region_start - curr_entry->vme_start)),
		    region_end - region_start,
		    &extended,
		    look_for_pages, VM_REGION_EXTENDED_INFO_COUNT);
		if (submap_needed_copy) {
			extended.share_mode = SM_COW;
		}
	} else {
		if (curr_entry->use_pmap) {
			extended.share_mode = SM_TRUESHARED;
		} else {
			extended.share_mode = SM_PRIVATE;
		}
		extended.ref_count = os_ref_get_count_raw(&VME_SUBMAP(curr_entry)->map_refcnt);
	}

	/* Fill in the information we just gathered into the info */
	if (look_for_pages) {
		submap_info->pages_resident = extended.pages_resident;
		submap_info->pages_swapped_out = extended.pages_swapped_out;
		submap_info->pages_shared_now_private =
		    extended.pages_shared_now_private;
		submap_info->pages_dirtied = extended.pages_dirtied;
		submap_info->external_pager = extended.external_pager;
		submap_info->shadow_depth = extended.shadow_depth;
		submap_info->share_mode = extended.share_mode;
		submap_info->ref_count = extended.ref_count;

		if (original_count >= VM_REGION_SUBMAP_INFO_V1_COUNT_64) {
			submap_info->pages_reusable = extended.pages_reusable;
		}
		if (original_count >= VM_REGION_SUBMAP_INFO_V2_COUNT_64) {
			submap_info->object_id_full = (vm_object_id_t)object_id_full;
		}
	} else {
		short_info->external_pager = extended.external_pager;
		short_info->shadow_depth = extended.shadow_depth;
		short_info->share_mode = extended.share_mode;
		short_info->ref_count = extended.ref_count;
	}

	vm_map_region_resolve_done(ctx, &map, resolve_kr);
	vmlp_api_end(VM_MAP_REGION_RECURSE_64, KERN_SUCCESS);
	return KERN_SUCCESS;
}

/*!
 * vm_map_region:
 *
 * @abstract
 * User call to obtain information about a region in a task's address map.
 * Many flavors are supported.
 *
 * Notably these calls will not descend into submaps.
 * For configurable descent, vm_map_region_recurse_64 can be used instead.
 *
 * @param map - the map to inspect
 * @param address_u - the address to begin the search at. If there is an entry
 * containing that address, information about that entry is provided.
 * If there is no entry, information about the next entry is provided.
 * If there are no more entries, KERN_INVALID_ADDRESS is returned.
 * @param size_u - outparameter containing the size of the entry.
 * @param flavor - allows the flavor of vm_region to be specified.
 */
kern_return_t
vm_map_region(
	vm_map_t                map,
	vm_map_offset_ut       *address_u,      /* IN/OUT */
	vm_map_size_ut         *size_u,         /* OUT */
	vm_region_flavor_t      flavor,         /* IN */
	vm_region_info_t        info,           /* OUT */
	mach_msg_type_number_t *count,          /* IN/OUT */
	mach_port_t            *object_name)    /* OUT */
{
	struct vm_map_entry     fake;
	vm_map_entry_t          entry;
	vm_map_offset_t         start;
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	vmlp_api_start(VM_MAP_REGION);

	start = vm_sanitize_addr(map, *address_u);

#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
	/*
	 * Ideally we'd like to emulate vm_sanitize_validate_non_canonical_ut_addr() behavior
	 * by rejecting virtual addresses containing metadata (PAC, TBI, MTE), but we have to
	 * account for the "fake_region" therefore we settle to just refuse metadata in the
	 * MTE bits. Due to compatibility with callers expecting to find the end of the
	 * addressable user range, we return KERN_INVALID_ADDRESS rather than KERN_INVALID_AGUMENT.
	 * with callers expecting to find the end of the addressable user range,
	 */
	if (start != vm_memtag_canonicalize(map, start)) {
		vmlp_api_end(VM_MAP_REGION, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */

	switch (flavor) {
	case VM_REGION_BASIC_INFO:
		/* legacy for old 32-bit objects info */
	{
		vm_region_basic_info_t  basic;
		kern_return_t           resolve_kr;

		if (*count < VM_REGION_BASIC_INFO_COUNT) {
			vmlp_api_end(VM_MAP_REGION, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}

		basic = (vm_region_basic_info_t) info;
		*count = VM_REGION_BASIC_INFO_COUNT;

		entry = vm_map_region_resolve_entry(ctx, &map, start,
		    VMRL_SH_NO_MIN_MAX_CHECK | VMRL_SH_NO_DESCEND_TRANSPARENT,
		    &fake, &resolve_kr);
		if (entry == VM_MAP_ENTRY_NULL) {
			vmlp_api_end(VM_MAP_REGION, resolve_kr);
			return resolve_kr;
		}

		start = entry->vme_start;

		basic->offset = (uint32_t)VME_OFFSET(entry);
		basic->protection = entry->protection;
		basic->inheritance = entry->inheritance;
		basic->max_protection = entry->max_protection;
		basic->behavior = entry->behavior;
		basic->user_wired_count = entry->user_wired_count;
		basic->reserved = entry->is_sub_map;

		*address_u = vm_sanitize_wrap_addr(start);
		*size_u    = vm_sanitize_wrap_size(entry->vme_end - start);

		if (object_name) {
			*object_name = IP_NULL;
		}
		if (entry->is_sub_map) {
			basic->shared = FALSE;
		} else {
			basic->shared = entry->is_shared;
		}

		vm_map_region_resolve_done(ctx, &map, resolve_kr);
		vmlp_api_end(VM_MAP_REGION, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	case VM_REGION_BASIC_INFO_64:
	{
		vm_region_basic_info_64_t basic;
		kern_return_t             resolve_kr;

		if (*count < VM_REGION_BASIC_INFO_COUNT_64) {
			vmlp_api_end(VM_MAP_REGION, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}

		basic = (vm_region_basic_info_64_t) info;
		*count = VM_REGION_BASIC_INFO_COUNT_64;

		entry = vm_map_region_resolve_entry(ctx, &map, start,
		    VMRL_SH_NO_MIN_MAX_CHECK | VMRL_SH_NO_DESCEND_TRANSPARENT,
		    &fake, &resolve_kr);
		if (entry == VM_MAP_ENTRY_NULL) {
			vmlp_api_end(VM_MAP_REGION, resolve_kr);
			return resolve_kr;
		}

		start = entry->vme_start;

		basic->offset = VME_OFFSET(entry);
		basic->protection = entry->protection;
		basic->inheritance = entry->inheritance;
		basic->max_protection = entry->max_protection;
		basic->behavior = entry->behavior;
		basic->user_wired_count = entry->user_wired_count;
		basic->reserved = entry->is_sub_map;

		*address_u = vm_sanitize_wrap_addr(start);
		*size_u    = vm_sanitize_wrap_size(entry->vme_end - start);

		if (object_name) {
			*object_name = IP_NULL;
		}
		if (entry->is_sub_map) {
			basic->shared = FALSE;
		} else {
			basic->shared = entry->is_shared;
		}

		vm_map_region_resolve_done(ctx, &map, resolve_kr);
		vmlp_api_end(VM_MAP_REGION, KERN_SUCCESS);
		return KERN_SUCCESS;
	}
	case VM_REGION_EXTENDED_INFO:
		if (*count < VM_REGION_EXTENDED_INFO_COUNT) {
			vmlp_api_end(VM_MAP_REGION, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}
		OS_FALLTHROUGH;
	case VM_REGION_EXTENDED_INFO__legacy:
	{
		vm_region_extended_info_t extended;
		mach_msg_type_number_t    original_count;
		kern_return_t             resolve_kr;

		if (*count < VM_REGION_EXTENDED_INFO_COUNT__legacy) {
			vmlp_api_end(VM_MAP_REGION, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}

		extended = (vm_region_extended_info_t) info;

		entry = vm_map_region_resolve_entry(ctx, &map, start,
		    VMRL_SH_NO_MIN_MAX_CHECK | VMRL_SH_NO_DESCEND_TRANSPARENT,
		    &fake, &resolve_kr);
		if (entry == VM_MAP_ENTRY_NULL) {
			vmlp_api_end(VM_MAP_REGION, resolve_kr);
			return resolve_kr;
		}

		start = entry->vme_start;

		extended->protection = entry->protection;
		extended->user_tag = VME_ALIAS(entry);
		extended->pages_resident = 0;
		extended->pages_swapped_out = 0;
		extended->pages_shared_now_private = 0;
		extended->pages_dirtied = 0;
		extended->external_pager = 0;
		extended->shadow_depth = 0;

		original_count = *count;
		if (flavor == VM_REGION_EXTENDED_INFO__legacy) {
			*count = VM_REGION_EXTENDED_INFO_COUNT__legacy;
		} else {
			extended->pages_reusable = 0;
			*count = VM_REGION_EXTENDED_INFO_COUNT;
		}

		*address_u = vm_sanitize_wrap_addr(start);
		*size_u    = vm_sanitize_wrap_size(entry->vme_end - start);

		vm_map_region_walk(ctx->vmlc_map, start, entry,
		    VME_OFFSET(entry), entry->vme_end - start, extended, TRUE, *count);

		if (object_name) {
			*object_name = IP_NULL;
		}

		vm_map_region_resolve_done(ctx, &map, resolve_kr);
		vmlp_api_end(VM_MAP_REGION, KERN_SUCCESS);
		return KERN_SUCCESS;
	}
	case VM_REGION_TOP_INFO:
	{
		vm_region_top_info_t    top;
		kern_return_t           resolve_kr;

		if (*count < VM_REGION_TOP_INFO_COUNT) {
			vmlp_api_end(VM_MAP_REGION, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}

		top = (vm_region_top_info_t) info;
		*count = VM_REGION_TOP_INFO_COUNT;

		entry = vm_map_region_resolve_entry(ctx, &map, start,
		    VMRL_SH_NO_MIN_MAX_CHECK | VMRL_SH_NO_DESCEND_TRANSPARENT,
		    &fake, &resolve_kr);
		if (entry == VM_MAP_ENTRY_NULL) {
			vmlp_api_end(VM_MAP_REGION, resolve_kr);
			return resolve_kr;
		}

		start = entry->vme_start;

		top->private_pages_resident = 0;
		top->shared_pages_resident = 0;

		vm_map_region_top_walk(entry, top);

		if (object_name) {
			*object_name = IP_NULL;
		}

		*address_u = vm_sanitize_wrap_addr(start);
		*size_u    = vm_sanitize_wrap_size(entry->vme_end - start);

		vm_map_region_resolve_done(ctx, &map, resolve_kr);
		vmlp_api_end(VM_MAP_REGION, KERN_SUCCESS);
		return KERN_SUCCESS;
	}
	default:
		vmlp_api_end(VM_MAP_REGION, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}
}

#define OBJ_RESIDENT_COUNT(obj, entry_size)                             \
	MIN((entry_size),                                               \
	    ((obj)->all_reusable ?                                      \
	     (obj)->wired_page_count :                                  \
	     (obj)->resident_page_count - (obj)->reusable_page_count))

void
vm_map_region_top_walk(
	vm_map_entry_t             entry,
	vm_region_top_info_t       top)
{
	if (entry->is_sub_map || VME_OBJECT(entry) == 0) {
		top->share_mode = SM_EMPTY;
		top->ref_count = 0;
		top->obj_id = 0;
		return;
	}

	{
		struct  vm_object *obj, *tmp_obj;
		int             ref_count;
		uint32_t        entry_size;

		entry_size = (uint32_t) ((entry->vme_end - entry->vme_start) / PAGE_SIZE_64);

		obj = VME_OBJECT(entry);

		vm_object_lock(obj);

		if ((ref_count = os_ref_get_count_raw(&obj->ref_count)) > 1 &&
		    obj->paging_in_progress) {
			ref_count--;
		}

		assert(obj->reusable_page_count <= obj->resident_page_count);
		if (obj->shadow) {
			if (ref_count == 1) {
				top->private_pages_resident =
				    OBJ_RESIDENT_COUNT(obj, entry_size);
			} else {
				top->shared_pages_resident =
				    OBJ_RESIDENT_COUNT(obj, entry_size);
			}
			top->ref_count  = ref_count;
			top->share_mode = SM_COW;

			while ((tmp_obj = obj->shadow)) {
				vm_object_lock(tmp_obj);
				vm_object_unlock(obj);
				obj = tmp_obj;

				if ((ref_count = os_ref_get_count_raw(&obj->ref_count)) > 1 &&
				    obj->paging_in_progress) {
					ref_count--;
				}

				assert(obj->reusable_page_count <= obj->resident_page_count);
				top->shared_pages_resident +=
				    OBJ_RESIDENT_COUNT(obj, entry_size);
				top->ref_count += ref_count - 1;
			}
		} else {
			if (entry->superpage_size) {
				top->share_mode = SM_LARGE_PAGE;
				top->shared_pages_resident = 0;
				top->private_pages_resident = entry_size;
			} else if (entry->needs_copy) {
				top->share_mode = SM_COW;
				top->shared_pages_resident =
				    OBJ_RESIDENT_COUNT(obj, entry_size);
			} else {
				if (ref_count == 1 ||
				    (ref_count == 2 && obj->named)) {
					top->share_mode = SM_PRIVATE;
					top->private_pages_resident =
					    OBJ_RESIDENT_COUNT(obj,
					    entry_size);
				} else {
					top->share_mode = SM_SHARED;
					top->shared_pages_resident =
					    OBJ_RESIDENT_COUNT(obj,
					    entry_size);
				}
			}
			top->ref_count = ref_count;
		}

		vm_object_unlock(obj);

		/* XXX K64: obj_id will be truncated */
		top->obj_id = (unsigned int) (uintptr_t)VM_KERNEL_ADDRHASH(obj);
	}
}

/*
 * Walk the pages contained in a vm_map_entry
 * Fill in accounting/debugging information about
 * that region to the "extended" parameter.
 *
 * @precondition
 * entry should be lock shared and come from the ctx.
 *
 * @postcondition
 * entry is invalid
 * the ctx has been unlocked.
 */
void
vm_map_region_walk(
	vm_map_t                        map,
	vm_map_offset_t                 va,
	vm_map_entry_t                  entry,
	vm_object_offset_t              offset,
	vm_object_size_t                range,
	vm_region_extended_info_t       extended,
	boolean_t                       look_for_pages,
	mach_msg_type_number_t count)
{
	struct vm_object *obj, *tmp_obj;
	vm_map_offset_t       last_offset;
	int               i;
	int               ref_count;
	struct vm_object        *shadow_object;
	unsigned short          shadow_depth;
	boolean_t         do_region_footprint;
	int                     effective_page_size, effective_page_shift;
	vm_map_offset_t         effective_page_mask;

	do_region_footprint = task_self_region_footprint();

	if ((entry->is_sub_map) ||
	    (VME_OBJECT(entry) == VM_OBJECT_NULL) ||
	    (VME_OBJECT(entry)->phys_contiguous &&
	    !entry->superpage_size)) {
		extended->share_mode = SM_EMPTY;
		extended->ref_count = 0;

		return;
	}

	if (entry->superpage_size) {
		extended->shadow_depth = 0;
		extended->share_mode = SM_LARGE_PAGE;
		extended->ref_count = 1;
		extended->external_pager = 0;

		/* TODO4K: Superpage in 4k mode? */
		extended->pages_resident = (unsigned int)(range >> PAGE_SHIFT);
		extended->shadow_depth = 0;
		return;
	}

	effective_page_shift = vm_self_region_page_shift(map);
	effective_page_size = (1 << effective_page_shift);
	effective_page_mask = effective_page_size - 1;

	offset = vm_map_trunc_page(offset, effective_page_mask);

	obj = VME_OBJECT(entry);

	vm_object_lock(obj);

	if ((ref_count = os_ref_get_count_raw(&obj->ref_count)) > 1 &&
	    obj->paging_in_progress) {
		ref_count--;
	}

	if (look_for_pages) {
		for (last_offset = offset + range;
		    offset < last_offset;
		    offset += effective_page_size, va += effective_page_size) {
			if (do_region_footprint) {
				int disp;

				disp = 0;
				if (map->has_corpse_footprint) {
					/*
					 * Query the page info data we saved
					 * while forking the corpse.
					 */
					vm_map_corpse_footprint_query_page_info(
						map,
						va,
						&disp);
				} else {
					/*
					 * Query the pmap.
					 */
					vm_map_footprint_query_page_info(
						map,
						entry,
						va,
						&disp);
				}
				if (disp & VM_PAGE_QUERY_PAGE_PRESENT) {
					extended->pages_resident++;
				}
				if (disp & VM_PAGE_QUERY_PAGE_REUSABLE) {
					extended->pages_reusable++;
				}
				if (disp & VM_PAGE_QUERY_PAGE_DIRTY) {
					extended->pages_dirtied++;
				}
				if (disp & PMAP_QUERY_PAGE_COMPRESSED) {
					extended->pages_swapped_out++;
				}
				continue;
			}

			vm_map_region_look_for_page(map, va, obj,
			    vm_object_trunc_page(offset), ref_count,
			    0, extended, count);
		}

		if (do_region_footprint) {
			goto collect_object_info;
		}
	} else {
collect_object_info:
		shadow_object = obj->shadow;
		shadow_depth = 0;

		if (!(obj->internal)) {
			extended->external_pager = 1;
		}

		if (shadow_object != VM_OBJECT_NULL) {
			vm_object_lock(shadow_object);
			for (;
			    shadow_object != VM_OBJECT_NULL;
			    shadow_depth++) {
				vm_object_t     next_shadow;

				if (!(shadow_object->internal)) {
					extended->external_pager = 1;
				}

				next_shadow = shadow_object->shadow;
				if (next_shadow) {
					vm_object_lock(next_shadow);
				}
				vm_object_unlock(shadow_object);
				shadow_object = next_shadow;
			}
		}
		extended->shadow_depth = shadow_depth;
	}

	if (extended->shadow_depth || entry->needs_copy) {
		extended->share_mode = SM_COW;
	} else {
		if (ref_count == 1) {
			extended->share_mode = SM_PRIVATE;
		} else {
			if (obj->true_share) {
				extended->share_mode = SM_TRUESHARED;
			} else {
				extended->share_mode = SM_SHARED;
			}
		}
	}
	extended->ref_count = ref_count - extended->shadow_depth;

	for (i = 0; i < extended->shadow_depth; i++) {
		if ((tmp_obj = obj->shadow) == 0) {
			break;
		}
		vm_object_lock(tmp_obj);
		vm_object_unlock(obj);

		if ((ref_count = os_ref_get_count_raw(&tmp_obj->ref_count)) > 1 &&
		    tmp_obj->paging_in_progress) {
			ref_count--;
		}

		extended->ref_count += ref_count;
		obj = tmp_obj;
	}
	vm_object_unlock(obj);

	if (extended->external_pager && extended->ref_count == 2 && extended->share_mode == SM_SHARED) {
		extended->share_mode = SM_PRIVATE;
	} else if (extended->share_mode == SM_SHARED && !(task_self_region_info_flags() & VM_REGION_INFO_FLAGS_NO_ALIASED)) {
		obj = VME_OBJECT(entry);
		vm_object_lock_shared(obj);

		if (vm_object_has_been_permanently_shared(obj) || !obj->internal) {
			if (obj->has_been_clipped) {
				extended->share_mode = SM_SHARED_ALIASED;
			} else {
				extended->share_mode = SM_SHARED;
			}
		} else {
			extended->share_mode = SM_PRIVATE_ALIASED;
		}

		vm_object_unlock(obj);
	}

	return;
}


/* object is locked on entry and locked on return */
static void
vm_map_region_look_for_page(
	__unused vm_map_t               map,
	__unused vm_map_offset_t        va,
	vm_object_t                     object,
	vm_object_offset_t              offset,
	int                             max_refcnt,
	unsigned short                  depth,
	vm_region_extended_info_t       extended,
	mach_msg_type_number_t count)
{
	vm_page_t       p;
	vm_object_t     shadow;
	int             ref_count;
	vm_object_t     caller_object;

	shadow = object->shadow;
	caller_object = object;


	while (TRUE) {
		if (!(object->internal)) {
			extended->external_pager = 1;
		}

		if ((p = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
			if (shadow && (max_refcnt == 1)) {
				extended->pages_shared_now_private++;
			}

			if (!vm_page_is_fictitious(p) &&
			    (p->vmp_dirty || pmap_is_modified(VM_PAGE_GET_PHYS_PAGE(p)))) {
				extended->pages_dirtied++;
			} else if (count >= VM_REGION_EXTENDED_INFO_COUNT) {
				if (p->vmp_reusable || object->all_reusable) {
					extended->pages_reusable++;
				}
			}

			extended->pages_resident++;

			if (object != caller_object) {
				vm_object_unlock(object);
			}

			return;
		}
		if (object->internal &&
		    object->alive &&
		    !object->terminating &&
		    object->pager_ready) {
			if (vm_object_compressor_pager_state_get(object, offset)
			    == VM_EXTERNAL_STATE_EXISTS) {
				/* the pager has that page */
				extended->pages_swapped_out++;
				if (object != caller_object) {
					vm_object_unlock(object);
				}
				return;
			}
		}

		if (shadow) {
			vm_object_lock(shadow);
			if ((ref_count = os_ref_get_count_raw(&shadow->ref_count)) > 1 &&
			    shadow->paging_in_progress) {
				ref_count--;
			}

			if (++depth > extended->shadow_depth) {
				extended->shadow_depth = depth;
			}

			if (ref_count > max_refcnt) {
				max_refcnt = ref_count;
			}

			if (object != caller_object) {
				vm_object_unlock(object);
			}

			offset = offset + object->vo_shadow_offset;
			object = shadow;
			shadow = object->shadow;
			continue;
		}
		if (object != caller_object) {
			vm_object_unlock(object);
		}
		break;
	}
}

/*
 * Simplfy the entries between (start, end].
 * If there are any holes in the range, the function will not attempt to simplify
 */
__static_testable void
vm_map_simplify_range(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end)
{
	kern_return_t kr;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_SIMPLIFY_RANGE);

	assert(!vm_map_is_sealed(map));
	assert(start <= end); /* Don't panic on size zero */

	start = vm_map_trunc_page(start, VM_MAP_PAGE_MASK(map));
	end = vm_map_round_page(end, VM_MAP_PAGE_MASK(map));

	/*
	 * Don't pmap unnest, we won't be changing anything about the entries
	 * other than increasing their size.
	 */
	kr = vm_map_range_ex_lock(ctx, &map, start, end,
	    VMRL_EX_ATOMIC | VMRL_EX_SIMPLIFY | VMRL_EX_NO_PMAP_UNNEST);
	if (kr != KERN_SUCCESS) {
		/* There was a hole in the range, give up */
		vmlp_api_end(VM_MAP_SIMPLIFY_RANGE, -1);
		return;
	}
	/* unlocking the atomic lock setup with SIMPLIFY will do the simplification */
	vm_map_range_ex_unlock(ctx, &map);
	vmlp_api_end(VM_MAP_SIMPLIFY_RANGE, 0);
}

#if CONFIG_COREDUMP

int
get_vmmap_entries(
	vm_map_t        map)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;
	vm_map_entry_t entry;
	int total_entries = 0;

	vmlp_api_start(GET_VMMAP_ENTRIES);

	kr = vm_map_range_sh_lock(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END,
	    VMRL_SH_STREAM | VMRL_SH_DESCEND_INTO_CONSTANT | VMRL_SH_WHOLE_MAP);
	if (kr != KERN_SUCCESS) {
		assert(kr == KERN_INVALID_ADDRESS);
		assert(map->hdr.nentries == 0);
		vmlp_api_end(GET_VMMAP_ENTRIES, 0);
		return 0;
	}

	while ((entry = vm_map_range_stream_next(ctx))) {
		total_entries += 1;
	}
	vm_map_range_sh_unlock(ctx, &map);

	vmlp_api_end(GET_VMMAP_ENTRIES, total_entries);
	return total_entries;
}
#endif /* CONFIG_COREDUMP */

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_machine_attribute_sanitize(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	mach_vm_offset_t       *start,
	mach_vm_offset_t       *end,
	vm_map_size_t          *size)
{
#if CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS
	kern_return_t kr;

	kr = vm_sanitize_canonicalize_ut_addr_end(
		map,
		&start_u,
		&end_u);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}
#endif /* CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS */

	return vm_sanitize_addr_end(start_u, end_u,
	           VM_SANITIZE_CALLER_VM_MAP_MACHINE_ATTRIBUTE, map,
	           VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS, start, end, size);
}

/*!
 * @function vm_map_entry_machine_attribute
 *
 * @abstract
 * Run a pmap_attribute_cache_sync on every relevant page in the range.
 * The function ignores errors and keeps trying to cache_sync the entire range
 * even if an earlier call to pmap_attribute_cache_sync fails.
 *
 * The entry is exclusively locked (or in the case of a sealed submap, the parent entry)
 * This exclusivity is following legacy behavior, and is done even though the
 * entry state is not mutated.
 *
 * @param entry - exclusively locked entry
 * @param start - the start of the range
 * @param end - the end of the range
 * @param attribute - the attribute to sync
 * @param value - a pointer to the value to sync
 */
static kern_return_t
vm_map_entry_machine_attribute(
	vm_map_entry_t                  entry,
	vm_map_offset_t                 start,
	vm_map_offset_t                 end,
	vm_machine_attribute_t          attribute __unused,
	vm_machine_attribute_val_t     *value /* IN */ __unused)
{
	vm_page_t               m;
	vm_object_t             object = VME_OBJECT(entry);
	vm_object_t             last_object = NULL;
	vm_object_t             base_object;
	vm_object_offset_t      offset;
	vm_object_offset_t      base_offset;
	vm_map_size_t           range;
	kern_return_t           kr = KERN_SUCCESS;

	base_object = object;
	range = end - start;
	offset = vm_object_trunc_page(start - entry->vme_start + VME_OFFSET(entry));
	base_offset = offset;

	vm_object_lock(object);

	while (range) {
		m = vm_page_lookup(
			object, offset);

		if (m && !vm_page_is_fictitious(m)) {
			kr = pmap_attribute_cache_sync( VM_PAGE_GET_PHYS_PAGE(m),
			    PAGE_SIZE, attribute, value);
			/*
			 * even if one call fails, keep trying to sync the rest
			 * of the range
			 */
		} else if (object->shadow) {
			offset = offset + object->vo_shadow_offset;
			last_object = object;
			object = object->shadow;
			vm_object_lock(last_object->shadow);
			vm_object_unlock(last_object);
			continue;
		}
		if (range < PAGE_SIZE) {
			range = 0;
		} else {
			range -= PAGE_SIZE;
		}

		if (base_object != object) {
			vm_object_unlock(object);
			vm_object_lock(base_object);
			object = base_object;
		}
		/* Bump to the next page */
		base_offset += PAGE_SIZE;
		offset = base_offset;
	}
	vm_object_unlock(object);
	return kr;
}


/*
 *	Routine:	vm_map_machine_attribute
 *	Purpose:
 *		Provide machine-specific attributes to mappings,
 *		such as cachability etc. for machines that provide
 *		them.  NUMA architectures and machines with big/strange
 *		caches will use this.
 *	Note:
 *		Responsibilities for locking and checking are handled here,
 *		everything else in the pmap module. If any non-volatile
 *		information must be kept, the pmap module should handle
 *		it itself. [This assumes that attributes do not
 *		need to be inherited, which seems ok to me]
 */
kern_return_t
vm_map_machine_attribute(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_machine_attribute_t  attribute,
	vm_machine_attribute_val_t *value) /* IN/OUT */
{
	mach_vm_offset_t start, end;
	vm_map_size_t    sync_size;
	kern_return_t    ret;
	vm_map_entry_t   entry;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_MACHINE_ATTRIBUTE);

	ret = vm_map_machine_attribute_sanitize(map,
	    start_u,
	    end_u,
	    &start,
	    &end,
	    &sync_size);
	if (__improbable(ret != KERN_SUCCESS)) {
		ret = vm_sanitize_get_kr(ret);
		vmlp_api_end(VM_MAP_MACHINE_ATTRIBUTE, ret);
		return ret;
	}

	if (start < vm_map_min(map) || end > vm_map_max(map)) {
		vmlp_api_end(VM_MAP_MACHINE_ATTRIBUTE, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}

	if (attribute != MATTR_CACHE) {
		/*
		 * MATTR_CACHE is the only attribute currently supported.
		 * KERN_INVALID_ADDRESS matches historical behavior.
		 */
		vmlp_api_end(VM_MAP_MACHINE_ATTRIBUTE, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}

	/* lock exclusive for serializing access to pmap at that range */
	ret = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC | VMRL_EX_SIMPLIFY | VMRL_EX_DESCEND_INTO_CONSTANT);
	if (ret != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_MACHINE_ATTRIBUTE, KERN_FAILURE);
		return KERN_FAILURE;
	}

	/*
	 * Start with KERN_SUCCESS, we run machine_attribute for
	 * every entry in the range even if one fails.
	 */
	ret = KERN_SUCCESS;

	while ((entry = vm_map_range_atomic_next(ctx))) {
		assert(!entry->is_sub_map);
		if (VME_OBJECT(entry)) {
			ret = vm_map_entry_machine_attribute(entry,
			    entry->vme_start, entry->vme_end, attribute, value);
		} else {
			/* no object, nothing to do */
		}
	}

	vm_map_range_ex_unlock(ctx, &map);

	vmlp_api_end(VM_MAP_MACHINE_ATTRIBUTE, ret);
	return ret;
}

/*
 * Map entry preflight for vm_map_behavior_set(VM_BEHAVIOR_ZERO_WIRED_PAGES).
 */
static kern_return_t
vm_behavior_set_zero_wired_pages_preflight(
	vm_map_lock_ctx_t   vctx __unused,
	vm_map_entry_t      entry)
{
	/* VM_BEHAVIOR_ZERO_WIRED_PAGES requires write access. */
	if (!(entry->protection & VM_PROT_WRITE) ||
#if __arm64e__
	    entry->used_for_tpro ||
#endif /* __arm64e__ */
	    entry->used_for_jit) {
		return KERN_PROTECTION_FAILURE;
	}
	return KERN_SUCCESS;
}

/*
 *	vm_map_behavior_set:
 *
 *	Sets the paging reference behavior of the specified address
 *	range in the target map.  Paging reference behavior affects
 *	how pagein operations resulting from faults on the map will be
 *	clustered.
 */
kern_return_t
vm_map_behavior_set(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end,
	vm_behavior_t   new_behavior)
{
	kern_return_t kr;
	vm_map_entry_t  entry;

	vmlp_api_start(VM_MAP_BEHAVIOR_SET);
	vmlp_range_event(map, start, end - start);

	if (start > end ||
	    start < vm_map_min(map) ||
	    end > vm_map_max(map)) {
		vmlp_api_end(VM_MAP_BEHAVIOR_SET, KERN_NO_SPACE);
		return KERN_NO_SPACE;
	}
	if (__improbable(vm_map_range_overflows(map, start, end - start))) {
		vmlp_api_end(VM_MAP_BEHAVIOR_SET, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}

	switch (new_behavior) {
	/*
	 * This first block of behaviors all set a persistent state on the specified
	 * memory range.  All we have to do here is to record the desired behavior
	 * in the vm_map_entry_t's.
	 */

	case VM_BEHAVIOR_DEFAULT:
	case VM_BEHAVIOR_RANDOM:
	case VM_BEHAVIOR_SEQUENTIAL:
	case VM_BEHAVIOR_RSEQNTL:
	case VM_BEHAVIOR_ZERO_WIRED_PAGES:
	{
		VM_MAP_LOCK_CTX_DECLARE(ctx);

		/* VM_BEHAVIOR_ZERO_WIRED_PAGES requires write access. */
		vm_map_lock_preflight_t zwp_preflight =
		    ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t vme) {
			return vm_behavior_set_zero_wired_pages_preflight(vctx, vme);
		};
		if (new_behavior == VM_BEHAVIOR_ZERO_WIRED_PAGES) {
			vm_map_lock_ctx_set_preflight(ctx, zwp_preflight);
		}
		/*
		 * The entire address range must be valid for the map.
		 * The atomic lock guarantees the lack of holes.
		 */
		kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_ATOMIC);
		if (kr != KERN_SUCCESS) {
			vmlp_api_end(VM_MAP_BEHAVIOR_SET, kr);
			return kr;
		}

		while ((entry = vm_map_range_atomic_next(ctx))) {
			if (entry->is_sub_map) {
				assert(!entry->use_pmap);
			}

			if (new_behavior == VM_BEHAVIOR_ZERO_WIRED_PAGES) {
				assert(entry->protection & VM_PROT_WRITE);
#if __arm64e__
				assert(!entry->used_for_tpro);
#endif /* __arm64e__ */
				assert(!entry->used_for_jit);
				entry->zero_wired_pages = TRUE;
			} else {
				entry->behavior = new_behavior;
			}
		}

		kr = KERN_SUCCESS;
		vm_map_range_ex_unlock(ctx, &map);
		break;
	}
	/*
	 * The rest of these are different from the above in that they cause
	 * an immediate action to take place as opposed to setting a behavior that
	 * affects future actions.
	 */

	case VM_BEHAVIOR_WILLNEED:
		kr = vm_map_willneed(map, start, end);
		break;

	case VM_BEHAVIOR_DONTNEED:
		kr = vm_map_msync(map, start, end - start, VM_SYNC_DEACTIVATE | VM_SYNC_CONTIGUOUS);
		break;

	case VM_BEHAVIOR_FREE:
		kr = vm_map_msync(map, start, end - start, VM_SYNC_KILLPAGES | VM_SYNC_CONTIGUOUS);
		break;

	case VM_BEHAVIOR_REUSABLE:
		kr = vm_map_reusable_pages(map, start, end);
		break;

	case VM_BEHAVIOR_REUSE:
		kr = vm_map_reuse_pages(map, start, end);
		break;

	case VM_BEHAVIOR_CAN_REUSE:
		kr = vm_map_can_reuse(map, start, end);
		break;

#if MACH_ASSERT
	case VM_BEHAVIOR_PAGEOUT:
		kr = vm_map_pageout(map, start, end);
		break;
#endif /* MACH_ASSERT */

	case VM_BEHAVIOR_ZERO:
		kr = vm_map_zero(map, start, end);
		break;

	default:
		kr = KERN_INVALID_ARGUMENT;
		break;
	}

	vmlp_api_end(VM_MAP_BEHAVIOR_SET, kr);
	return kr;
}


/*
 * Internals for madvise(MADV_WILLNEED) system call.
 *
 * The implementation is to do:-
 * a) read-ahead if the mapping corresponds to a mapped regular file
 * b) or, fault in the pages (zero-fill, decompress etc) if it's an anonymous mapping
 */
static kern_return_t
vm_map_willneed(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end
	)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t  entry;
	kern_return_t   kr;
	vm_map_offset_t addr = start;
	vm_map_size_t   region_size;

	vmlp_api_start(VM_MAP_WILLNEED);

	KDBG(VMDBG_CODE(DBG_VM_MAP_WILLNEED) | DBG_FUNC_START,
	    start, end);
	struct vm_object_fault_info fault_info = {
		.interruptible = THREAD_UNINT,
		.behavior = VM_BEHAVIOR_SEQUENTIAL,
		/* Do not activate pages after faulting */
		.stealth = true,
		/* Don't wait for busy pages */
		.fi_no_sleep = true,
	};

	/*
	 * The MADV_WILLNEED operation doesn't require any changes to the
	 * vm_map_entry_t's, so the shared lock is sufficient.
	 * We stream because we will want the ability to drop the lock during
	 * slow object-level operations.
	 *
	 * The madvise semantics require that the address range be fully
	 * allocated with no holes.  Otherwise, we're required to return
	 * an error.
	 */
	vmlp_range_event(map, start, end);

	kr = vm_map_range_sh_lock(ctx, &map, start, end, VMRL_SH_STREAM_NO_HOLES | VMRL_SH_INTERRUPTIBLE);
	if (kr != KERN_SUCCESS) {
		kr = KERN_INVALID_ADDRESS;
		goto done;
	}

	/*
	 * Examine each vm_map_entry_t in the range.
	 */
	while ((entry = vm_map_range_stream_next_with_error(ctx, &kr))) {
		/*
		 * Set the length so we don't go beyond the end of the
		 * map_entry or beyond the end of the range we were given.
		 * This range could span also multiple map entries all of which
		 * map different files, so make sure we only do the right amount
		 * of I/O for each object.  Note that it's possible for there
		 * to be multiple map entries all referring to the same object
		 * but with different page permissions, but it's not worth
		 * trying to optimize that case.
		 */
		vm_map_lock_ctx_bounds(ctx, &addr, NULL, &region_size);

		vm_size_t effective_page_mask = MIN(vm_map_page_mask(ctx->vmlc_map), PAGE_MASK);
		vm_map_offset_t effective_page_size = effective_page_mask + 1;

		/*
		 * Write-fault if the entry supports it to preclude subsequent soft-faults
		 */
		vm_prot_t fault_prot = entry->protection & VM_PROT_WRITE ?
		    VM_PROT_WRITE : VM_PROT_READ;

		vm_map_range_stream_drop(ctx);

		while (region_size) {
			/*
			 * Provide a hint for how much clustering we would like. Note that
			 * each individual fault will limit the size of each request to
			 * MAX_UPL_TRANSFER_BYTES.
			 */
			fault_info.cluster_size = region_size;
			kr = vm_pre_fault_with_info(
				ctx->vmlc_map,
				vm_map_trunc_page(addr, effective_page_mask),
				fault_prot,
				&fault_info);
			if (kr == KERN_ALREADY_WAITING) {
				/*
				 * The page is busy being faulted/paged by another thread.
				 */
				KDBG(VMDBG_CODE(DBG_VM_MAP_WILLNEED) | DBG_FUNC_NONE,
				    task_pid(current_task()), addr, kr);
				kr = KERN_SUCCESS;
			} else if (kr != KERN_SUCCESS) {
				vm_map_range_sh_unlock(ctx, &map);
				goto done;
			}
			region_size -= effective_page_size;
			addr += effective_page_size;
		}
	}

	vm_map_range_sh_unlock(ctx, &map);
done:
	KDBG(VMDBG_CODE(DBG_VM_MAP_WILLNEED) | DBG_FUNC_END,
	    addr, kr);
	vmlp_api_end(VM_MAP_WILLNEED, kr);
	return kr;
}

static boolean_t
vm_map_entry_is_reusable(
	vm_map_entry_t entry)
{
	vm_object_t object;

	/* Only user map entries */
	if (entry->is_sub_map) {
		return FALSE;
	}

	switch (VME_ALIAS(entry)) {
	case VM_MEMORY_MALLOC:
	case VM_MEMORY_MALLOC_SMALL:
	case VM_MEMORY_MALLOC_LARGE:
	case VM_MEMORY_REALLOC:
	case VM_MEMORY_MALLOC_TINY:
	case VM_MEMORY_MALLOC_LARGE_REUSABLE:
	case VM_MEMORY_MALLOC_LARGE_REUSED:
		/*
		 * This is a malloc() memory region: check if it's still
		 * in its original state and can be re-used for more
		 * malloc() allocations.
		 */
		break;
	default:
		/*
		 * Not a malloc() memory region: let the caller decide if
		 * it's re-usable.
		 */
		return TRUE;
	}

	if (/*entry->is_shared ||*/
		entry->is_sub_map ||
		entry->protection != VM_PROT_DEFAULT ||
		entry->max_protection != VM_PROT_ALL ||
		entry->inheritance != VM_INHERIT_DEFAULT ||
		entry->no_cache ||
		entry->vme_permanent ||
		entry->superpage_size != FALSE ||
		entry->zero_wired_pages ||
		entry->wired_count != 0 ||
		entry->user_wired_count != 0) {
		return FALSE;
	}

	object = VME_OBJECT(entry);
	if (object == VM_OBJECT_NULL) {
		return TRUE;
	}
	if (
#if 0
		/*
		 * Let's proceed even if the VM object is potentially
		 * shared.
		 * We check for this later when processing the actual
		 * VM pages, so the contents will be safe if shared.
		 *
		 * But we can still mark this memory region as "reusable" to
		 * acknowledge that the caller did let us know that the memory
		 * could be re-used and should not be penalized for holding
		 * on to it.  This allows its "resident size" to not include
		 * the reusable range.
		 */
		object->ref_count == 1 &&
#endif
		object->vo_copy == VM_OBJECT_NULL &&
		object->shadow == VM_OBJECT_NULL &&
		object->internal &&
		object->purgable == VM_PURGABLE_DENY &&
		HAS_DEFAULT_CACHEABILITY(object->wimg_bits & VM_WIMG_MASK) &&
		!object->code_signed) {
		return TRUE;
	}
	return FALSE;
}

static kern_return_t
vm_map_reuse_pages(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t entry;
	kern_return_t  kr;

	vmlp_api_start(VM_MAP_REUSE_PAGES);


	if (VM_MAP_PAGE_SHIFT(map) < PAGE_SHIFT) {
		/*
		 * XXX TODO4K
		 * need to figure out what reusable means for a
		 * portion of a native page.
		 */
		vmlp_api_end(VM_MAP_REUSE_PAGES, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	assert(map->pmap != kernel_pmap);       /* protect alias access */

	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
		if (!vm_map_entry_is_reusable(vme)) {
		        return KERN_INVALID_ADDRESS;
		}
		return KERN_SUCCESS;
	});

	/*
	 * The MADV_REUSE operation doesn't require any changes to the
	 * vm_map_entry_t's, so the shared lock is sufficient.
	 * The madvise semantics require that the address range be fully
	 * allocated with no holes.  Otherwise, we're required to return
	 * an error.
	 * Using an atomic lock guarantees the lack of holes.
	 */
	kr = vm_map_range_sh_lock(ctx, &map, start, end, VMRL_SH_ATOMIC);
	if (kr != KERN_SUCCESS) {
		vm_page_stats_reusable.reuse_pages_failure++;
		vmlp_api_end(VM_MAP_REUSE_PAGES, kr);
		return kr;
	}

	/*
	 * Examine each vm_map_entry_t in the range.
	 */
	while ((entry = vm_map_range_atomic_next(ctx))) {
		vm_object_offset_t obj_start, obj_end;
		vm_object_t        object;

		/* here we know the entry is reusable because it passed the preflight */

		object = VME_OBJECT(entry);
		vm_map_lock_ctx_offset_bounds(ctx, &obj_start, &obj_end, NULL);

		if (object != VM_OBJECT_NULL) {
			vm_object_lock(object);
			vm_object_reuse_pages(object, obj_start, obj_end, TRUE);
			vm_object_unlock(object);
		}

		if (VME_ALIAS(entry) == VM_MEMORY_MALLOC_LARGE_REUSABLE) {
			/*
			 * XXX
			 * We do not hold the entry lock exclusively here.
			 * The "alias" field is not that critical, so it's
			 * safe to update it here, as long as it is the only
			 * one that can be modified while holding the VM entry
			 * "shared".
			 */
			VME_ALIAS_SET(entry, VM_MEMORY_MALLOC_LARGE_REUSED);
		}
	}

	vm_map_range_sh_unlock(ctx, &map);
	vm_page_stats_reusable.reuse_pages_success++;
	vmlp_api_end(VM_MAP_REUSE_PAGES, KERN_SUCCESS);
	return KERN_SUCCESS;
}


static kern_return_t
vm_map_reusable_pages(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t  entry;
	kern_return_t   kr;

	vmlp_api_start(VM_MAP_REUSABLE_PAGES);

	if (VM_MAP_PAGE_SHIFT(map) < PAGE_SHIFT) {
		/*
		 * XXX TODO4K
		 * need to figure out what reusable means for a portion
		 * of a native page.
		 */
		vmlp_api_end(VM_MAP_REUSABLE_PAGES, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	assert(map->pmap != kernel_pmap);       /* protect alias access */

	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
		/*
		 * Sanity check on the VM map entry.
		 */
		if (!vm_map_entry_is_reusable(vme)) {
		        return KERN_INVALID_ADDRESS;
		}

		if (!(vme->protection & VM_PROT_WRITE) &&
#if __arm64e__
		!vme->used_for_tpro &&
#endif
		!vme->used_for_jit) {
		        /* not writable: can't discard contents */
		        vm_page_stats_reusable.reusable_nonwritable++;
		        return KERN_PROTECTION_FAILURE;
		}

		return KERN_SUCCESS;
	});

	/*
	 * The MADV_REUSABLE operation doesn't require any changes to the
	 * vm_map_entry_t's, so the shared lock is sufficient.
	 * The madvise semantics require that the address range be fully
	 * allocated with no holes.  Otherwise, we're required to return
	 * an error.
	 * Using an atomic lock guarantees the lack of holes.
	 */
	kr = vm_map_range_sh_lock(ctx, &map, start, end, VMRL_SH_ATOMIC);
	if (kr != KERN_SUCCESS) {
		vm_page_stats_reusable.reusable_pages_failure++;
		vmlp_api_end(VM_MAP_REUSABLE_PAGES, kr);
		return kr;
	}

	/*
	 * Examine each vm_map_entry_t in the range.
	 */
	while ((entry = vm_map_range_atomic_next(ctx))) {
		vm_object_offset_t  obj_start;
		vm_object_size_t    obj_size;
		vm_map_offset_t     pmap_offset;
		vm_object_t         object;
		boolean_t           kill_no_write = FALSE;

		vm_map_lock_ctx_bounds(ctx, &pmap_offset, NULL, NULL);
		vm_map_lock_ctx_offset_bounds(ctx, &obj_start, NULL, &obj_size);

		object = VME_OBJECT(entry);
		if (object == VM_OBJECT_NULL) {
			continue;
		}

		if ((entry->protection & VM_PROT_EXECUTE) ||
		    entry->vme_xnu_user_debug) {
			/*
			 * Executable or user debug pages might be write-protected by
			 * hardware, so do not attempt to write to these pages.
			 */
			kill_no_write = TRUE;
		}

		vm_object_lock(object);
		if (vm_object_no_shadowing(object, true) /* no shadowing: we can kill pages */
		    &&
		    /*
		     * "iokit_acct" entries are billed for their virtual size
		     * (rather than for their resident pages only), so they
		     * wouldn't benefit from making pages reusable, and it
		     * would be hard to keep track of pages that are both
		     * "iokit_acct" and "reusable" in the pmap stats and
		     * ledgers.
		     */
		    !(entry->iokit_acct ||
		    (!entry->is_sub_map && !entry->use_pmap))) {
			if (os_ref_get_count_raw(&object->ref_count) != 1) {
				vm_page_stats_reusable.reusable_shared++;
			}
			vm_object_deactivate_pages(object, obj_start, obj_size,
			    1, TRUE /*reusable_pages*/,
			    kill_no_write, ctx->vmlc_map->pmap, pmap_offset);
		} else {
			vm_page_stats_reusable.reusable_pages_shared++;
			DTRACE_VM4(vm_map_reusable_pages_shared,
			    unsigned int, VME_ALIAS(entry),
			    vm_map_t, ctx->vmlc_map,
			    vm_map_entry_t, entry,
			    vm_object_t, object);
		}
		vm_object_unlock(object);

		if (VME_ALIAS(entry) == VM_MEMORY_MALLOC_LARGE ||
		    VME_ALIAS(entry) == VM_MEMORY_MALLOC_LARGE_REUSED) {
			/*
			 * XXX
			 * We do not hold the entry lock exclusively here.
			 * The "alias" field is not that critical, so it's
			 * safe to update it here, as long as it is the only
			 * one that can be modified while holding the VM entry
			 * "shared".
			 */
			VME_ALIAS_SET(entry, VM_MEMORY_MALLOC_LARGE_REUSABLE);
		}
	}

	vm_map_range_sh_unlock(ctx, &map);
	vm_page_stats_reusable.reusable_pages_success++;
	vmlp_api_end(VM_MAP_REUSABLE_PAGES, KERN_SUCCESS);
	return KERN_SUCCESS;
}


static kern_return_t
vm_map_can_reuse(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;

	vmlp_api_start(VM_MAP_CAN_REUSE);
	vmlp_range_event(map, start, end - start);

	assert(map->pmap != kernel_pmap);       /* protect alias access */

	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
		if (!vm_map_entry_is_reusable(vme)) {
		        return KERN_INVALID_ADDRESS;
		}
		return KERN_SUCCESS;
	});

	/*
	 * The MADV_CAN_REUSE operation doesn't require any changes to the
	 * vm_map_entry_t's, so the shared lock is sufficient.
	 * The madvise semantics require that the address range be fully
	 * allocated with no holes.  Otherwise, we're required to return
	 * an error.
	 * Using an atomic lock guarantees the lack of holes.
	 */
	kr = vm_map_range_sh_lock(ctx, &map, start, end, VMRL_SH_ATOMIC);
	if (kr != KERN_SUCCESS) {
		vm_page_stats_reusable.can_reuse_failure++;
		vmlp_api_end(VM_MAP_CAN_REUSE, kr);
		return kr;
	}

	vm_map_range_sh_unlock(ctx, &map);
	vm_page_stats_reusable.can_reuse_success++;
	vmlp_api_end(VM_MAP_CAN_REUSE, KERN_SUCCESS);
	return KERN_SUCCESS;
}

#if MACH_ASSERT

static kern_return_t
vm_map_pageout(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t                  entry;
	kern_return_t                   kr;

	vmlp_api_start(VM_MAP_PAGEOUT);

	/*
	 * The MADV_PAGEOUT operation doesn't require any changes to the
	 * vm_map_entry_t's, so the read lock is sufficient.
	 *
	 * The madvise semantics require that the address range be fully
	 * allocated with no holes.  Otherwise, we're required to return
	 * an error.
	 */
	vmlp_range_event(map, start, end - start);


	kr = vm_map_range_sh_lock(ctx, &map, start, end,
	    VMRL_SH_ATOMIC | VMRL_SH_DESCEND_INTO_CONSTANT);
	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_PAGEOUT, kr);
		return kr;
	}

	/*
	 * Examine each vm_map_entry_t in the range.
	 */
	while ((entry = vm_map_range_atomic_next(ctx))) {
		vm_object_t object = VME_OBJECT(entry);
		if (object == VM_OBJECT_NULL || !object->internal) {
			continue;
		}

		vm_object_pageout(object);
	}

	vm_map_range_sh_unlock(ctx, &map);
	vmlp_api_end(VM_MAP_PAGEOUT, KERN_SUCCESS);

	return KERN_SUCCESS;
}

#endif /* MACH_ASSERT */

/*
 * This function determines if the zero operation can be run on the
 * respective entry. Additional checks on the object are in
 * vm_object_zero_preflight.
 */
static kern_return_t
vm_map_zero_entry_preflight(vm_map_entry_t entry)
{
	/*
	 * Zeroing is restricted to writable non-executable entries and non-JIT
	 * regions.
	 */
	if (!(entry->protection & VM_PROT_WRITE) ||
	    (entry->protection & VM_PROT_EXECUTE) ||
	    entry->used_for_jit ||
	    entry->vme_xnu_user_debug) {
		return KERN_PROTECTION_FAILURE;
	}

	/*
	 * Zeroing for copy on write isn't yet supported. Zeroing is also not
	 * allowed for submaps.
	 */
	if (entry->needs_copy || entry->is_sub_map) {
		return KERN_NO_ACCESS;
	}

	return KERN_SUCCESS;
}

/*
 * This function iterates through the entries in the requested range
 * and zeroes any resident pages in the corresponding objects. Compressed
 * pages are dropped instead of being faulted in and zeroed.
 */
__static_testable kern_return_t
vm_map_zero(
	vm_map_t        map,
	vm_map_offset_t range_start,
	vm_map_offset_t range_end)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t          entry;
	kern_return_t           kr;
	vm_map_address_t        cur_addr;
	assert(map->pmap != kernel_pmap); /* protect alias access */

	vmlp_api_start(VM_MAP_ZERO);

	/*
	 * This operation isn't supported where the map page size is less than
	 * the hardware page size. Caller will need to handle error and
	 * explicitly zero memory if needed.
	 */
	if (VM_MAP_PAGE_SHIFT(map) < PAGE_SHIFT) {
		vmlp_api_end(VM_MAP_ZERO, KERN_NO_ACCESS);
		return KERN_NO_ACCESS;
	}

	/*
	 * The MADV_ZERO operation doesn't require any changes to the
	 * vm_map_entry_t's, so the shared lock is sufficient.
	 * We need to stream because we want the ability to drop the lock
	 * during slow object-level operations.
	 */
	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
		return vm_map_zero_entry_preflight(vme);
	});

	kr = vm_map_range_sh_lock(ctx, &map, range_start, range_end, VMRL_SH_STREAM_NO_HOLES);
	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_ZERO, kr);
		return kr;
	}

	cur_addr = range_start;

	/*
	 * Loop over all entries in the range.
	 * cur_addr contains the address we want to zero from
	 * entry is the entry containing cur_addr we want to zero part or all of.
	 */
	while (cur_addr < range_end) {
		vm_map_offset_t cur_offset, start_offset, end_offset;
		vm_map_address_t entry_start_addr;
		vm_object_t object;

		entry = vm_map_range_stream_next_with_error(ctx, &kr);
		if (entry == VM_MAP_ENTRY_NULL) {
			break;
		}

		assert(cur_addr >= entry->vme_start);

		if (cur_addr >= entry->vme_end) {
			/*
			 * entry ends before cur_addr; presumably the map changed
			 * while the lock was dropped. Proceed to the next entry.
			 */
			continue;
		}

		object = VME_OBJECT(entry);
		if (object == NULL) {
			/* entry has no object, which counts as zeroed. Advance past it. */
			cur_addr = entry->vme_end;
			continue;
		}

		vm_map_lock_ctx_offset_bounds(ctx, &start_offset, &end_offset, NULL);
		vm_map_lock_ctx_bounds(ctx, &entry_start_addr, NULL, NULL);

		/* Account for however far we already are into the entry */
		start_offset += cur_addr - entry_start_addr;

		/*
		 * Take a reference on the object as vm_object_zero
		 * will drop the object lock when it encounters a busy page.
		 */
		vm_object_lock(object);
		vm_object_reference_locked(object);
		vm_map_range_stream_drop_without_advance(ctx);
		entry = VM_MAP_ENTRY_NULL; /* null on unlock */

		cur_offset = start_offset;
		assert(cur_offset < end_offset);
		kr = vm_object_zero(object, &cur_offset, end_offset);

		vm_object_unlock(object);
		vm_object_deallocate(object);

		if (kr != KERN_SUCCESS) {
			/* error from vm_object_zero, we should give up */
			break;
		}

		/*
		 * Advance cur_addr as vm_object_zero has succeeded.
		 * It can bail out early if it had to unlock a COPY_SYMMETRIC object, so
		 * the processed range is [start_offset:cur_offset).
		 * We automatically re-run the preflight when calling stream_next,
		 * so it's fine if the mapping became "needs_copy" while the
		 * object (and the entry) was unlocked.
		 */
		cur_addr += (cur_offset - start_offset);
	}

	vm_map_range_sh_unlock(ctx, &map);
	vmlp_api_end(VM_MAP_ZERO, kr);
	return kr;
}

/*
 *	Routine:	vm_map_entry_create_locked_and_insert
 *
 *	Description:	This routine inserts a new vm_entry in a locked map.
 */
static vm_map_entry_t
vm_map_entry_create_locked_and_insert(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_map_kernel_flags_t   vmk_flags,
	boolean_t               needs_copy,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance)
{
	vm_map_entry_t  new_entry;

	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);

	__assert_only vm_object_offset_t      end_offset = 0;
	assertf(!os_add_overflow(end - start, offset, &end_offset), "size 0x%llx, offset 0x%llx caused overflow", (uint64_t)(end - start), offset);

	assert(VM_MAP_PAGE_ALIGNED(start, VM_MAP_PAGE_MASK(map)));
	assert(VM_MAP_PAGE_ALIGNED(end, VM_MAP_PAGE_MASK(map)));
	assert(start < end);

	new_entry = vm_map_entry_create_locked(map, start, end);

	if (vmk_flags.vmkf_submap) {
		new_entry->vme_atomic = vmk_flags.vmkf_submap_atomic;
		VME_SUBMAP_SET(new_entry, (vm_map_t)(uintptr_t)object);
	} else {
		VME_OBJECT_SET(new_entry, object, false, 0);
	}
	VME_OFFSET_SET(new_entry, offset);
	VME_ALIAS_SET(new_entry, vmk_flags.vm_tag);

	new_entry->needs_copy = needs_copy;
	new_entry->inheritance = inheritance;
	new_entry->protection = cur_protection;
	new_entry->max_protection = max_protection;
	/*
	 * submap: "use_pmap" means "nested".
	 * default: false.
	 *
	 * object: "use_pmap" means "use pmap accounting" for footprint.
	 * default: true.
	 */
	new_entry->use_pmap = !vmk_flags.vmkf_submap;
	new_entry->no_cache = vmk_flags.vmf_no_cache;
	new_entry->vme_permanent = vmk_flags.vmf_permanent;
	new_entry->translated_allow_execute = vmk_flags.vmkf_translated_allow_execute;
	new_entry->vme_no_copy_on_read = vmk_flags.vmkf_no_copy_on_read;
	new_entry->superpage_size = (vmk_flags.vmf_superpage_size != 0);

	if (vmk_flags.vmkf_map_jit) {
		if (!(map->jit_entry_exists) ||
		    VM_MAP_POLICY_ALLOW_MULTIPLE_JIT(map)) {
			new_entry->used_for_jit = TRUE;
			map->jit_entry_exists = TRUE;
		}
	}

	/*
	 *	Insert the new entry into the list.
	 */

	vm_map_store_insert(map, new_entry,
	    (vm_map_store_rsv_t){ }, vmk_flags);
	return new_entry;
}

static void
vm_map_check_accounting_state_consistency(
	__assert_only vm_map_t  map,
	vm_map_entry_t          src_entry,
	vm_object_t             object)
{
	if (src_entry->iokit_acct) {
		/* This entry uses "IOKit accounting".  */
	} else if (object != VM_OBJECT_NULL && object->internal &&
	    (object->purgable != VM_PURGABLE_DENY || object->vo_ledger_tag != VM_LEDGER_TAG_NONE)) {
		/* Purgeable objects have their own accounting: no pmap accounting for them. */
		assertf(!src_entry->use_pmap,
		    "map=%p src_entry=%p [0x%llx:0x%llx] 0x%x/0x%x %d",
		    map,
		    src_entry,
		    (uint64_t)src_entry->vme_start,
		    (uint64_t)src_entry->vme_end,
		    src_entry->protection,
		    src_entry->max_protection,
		    VME_ALIAS(src_entry));
	} else {
		/* Not IOKit or purgeable: must be accounted by pmap stats. */
		assertf(src_entry->use_pmap,
		    "map=%p src_entry=%p [0x%llx:0x%llx] 0x%x/0x%x %d",
		    map,
		    src_entry,
		    (uint64_t)src_entry->vme_start,
		    (uint64_t)src_entry->vme_end,
		    src_entry->protection,
		    src_entry->max_protection,
		    VME_ALIAS(src_entry));
	}
}

#if HAS_MTE
static kern_return_t
_vm_map_remap_check_mte_policy(
	vm_map_t                map,
	vm_map_offset_t         addr,
	vm_map_size_t           size,
	vm_map_entry_t          src_entry,
	bool                    do_copy,
	vm_inherit_t            inheritance,
	vm_map_kernel_flags_t   vmk_flags)
{
	if (VME_OBJECT(src_entry) && vm_object_is_mte_mappable(VME_OBJECT(src_entry))) {
		vm_mte_operation_flags_t mte_operation = VM_MTE_OPERATION_REMAP_EXTRACT;
		mte_operation |= vmk_flags.vmkf_is_iokit ? VM_MTE_OPERATION_IOKIT : 0;
		switch (vmk_flags.vmkf_copy_dest) {
		case VM_COPY_DESTINATION_USER:
			mte_operation |= VM_MTE_OPERATION_DEST_USER;
			break;
		case VM_COPY_DESTINATION_KERNEL:
			mte_operation |= VM_MTE_OPERATION_DEST_KERNEL;
			break;
		case VM_COPY_DESTINATION_UNKNOWN:
			mte_operation |= VM_MTE_OPERATION_DEST_UNKNOWN;
			break;
		case VM_COPY_DESTINATION_INTERNAL:
			mte_operation |= VM_MTE_OPERATION_DEST_INTERNAL;
			break;
		default:
			/* should be unreachable */
			panic("vm_map_remap_extract: unimplemented vmk_flags.vmkf_copy_dest %u", vmk_flags.vmkf_copy_dest);
		}

		if (inheritance == VM_INHERIT_SHARE) {
			mte_operation |= VM_MTE_OPERATION_TYPE_INHERIT_SHARE;
			if (!vm_map_allow_mte_operation(map, addr, size, mte_operation, optional_vm_object_none() /* irrelevant here */)) {
				return KERN_NO_ACCESS;
			}
			mte_operation &= ~VM_MTE_OPERATION_TYPE_INHERIT_SHARE;
		}

		mte_operation |= do_copy ? VM_MTE_OPERATION_TYPE_COPY : VM_MTE_OPERATION_TYPE_SHARE;
		if (!vm_map_allow_mte_operation(map, addr, size, mte_operation, OPTIONAL_SOME(VME_OBJECT(src_entry)))) {
			return KERN_NO_ACCESS;
		}
	}
	return KERN_SUCCESS;
}
#endif /* HAS_MTE */

static bool
_vm_map_remap_check_not_kernel(vm_object_t object)
{
	/*
	 * Prevent kernel_object from being exposed to
	 * user space.
	 */
	if (__improbable(is_kernel_object(object))) {
		void *bsd_info = get_bsdtask_info(current_task());
		printf("%d[%s]: rejecting attempt to extract from kernel_object\n",
		    proc_selfpid(), (bsd_info ? proc_name_address(bsd_info) : "?"));
		DTRACE_VM(extract_kernel_only);
		return false;
	}
	return true;
}

/*
 * This function makes sure that the given entry in the given map is ready to be
 * shared, which includes changing the copy_strategy.
 * A new vm_object may be created for the entry so the entry needs to be locked.
 * entry is in src_map only if is_mapped_entry == true
 */
vm_object_t
vm_map_stabilize_object_for_share(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t entry,
	bool is_mapped_entry,
	bool share_with_upl)
{
	vm_map_t src_map = vm_map_lock_ctx_get_map(ctx);
	if (is_mapped_entry && !vm_map_is_sealed(src_map)) {
		VM_ENTRY_ASSERT_OWNER(entry);
	}
	vm_object_t object = VME_OBJECT(entry);

	/* This sanity checks are done here before we shadow the original object*/
	vm_map_check_accounting_state_consistency(src_map, entry, object);

	if (object == VM_OBJECT_NULL) {
		assert(!entry->needs_copy);
		assert(entry->max_protection == VM_PROT_NONE);
		assert(entry->protection == VM_PROT_NONE);
		assert(entry->use_pmap);
		assert(!src_map->mapped_in_other_pmaps);
		/*
		 * Remap passes VMO_ALLOCATE to the range lock, so object
		 * allocation is usually already handled by now.
		 * However VM_PROT_NONE entries are never given objects even by
		 * VMO_ALLOCATE. This entry is a reserved range with nothing to
		 * share or copy. There could also be all sorts of pmap
		 * shenanigans within that reserved range, such as with the arm
		 * commpage.
		 * object remains VM_OBJECT_NULL
		 */
	} else if (object->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC) {
		/* (entry->wired_count > 0) case should go to this branch, hence the assert for it in the else that follows
		 * - A wired memory entry should not have any pending copy-on-write (needs_copy) and needs to
		 * keep pointing at the VM object that contains the wired pages.
		 * - We're about to share this memory, and we'll share this VM object. and use the new VM object for the remapping.
		 * Or, we are already using an asymmetric copy, and therefore we already have the right object. */
		assert(!entry->needs_copy);
	} else {
		/* wired objects can't be COPY_SYMMETRIC */
		assert(entry->wired_count == 0);
		/* constant submap are going to have all objects
		 * MEMORY_OBJECT_COPY_DELAY so we're not going to get here */
		object = vm_map_create_private_symmetric_object(ctx, entry, is_mapped_entry, share_with_upl);
		assert3p(object, ==, VME_OBJECT(entry)); /* sanity */
	}

	if (object != VM_OBJECT_NULL) {
		vm_object_lock(object);
		if (share_with_upl) {
			/* Objects shared with a UPL are only transiently shared */
			vm_object_mark_shared(object, VM_SHARE_TYPE_TRANSIENT);
#if VM_OBJECT_TRACKING_OP_TRUESHARE
			if (!object->true_share && vm_object_tracking_btlog) {
				btlog_record(vm_object_tracking_btlog, object,
				    VM_OBJECT_TRACKING_OP_TRUESHARE,
				    btref_get(__builtin_frame_address(0), 0));
			}
#endif /* VM_OBJECT_TRACKING_OP_TRUESHARE */
		} else {
			vm_object_mark_shared(object, VM_SHARE_TYPE_PERMANENT);
		}
		if (object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
			/* we want to share this object, it needs to be COPY_DELAY. We're allowed to change this because
			 * we just created this object or we know no other entry points to it
			 * object->ref_count can be more than 1 if vm_fault happens to be working on this object as well */
			object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
			VM_OBJECT_SET_TRUE_SHARE(object, TRUE);
		}
		vm_object_unlock(object);
	}
	return object;
}

/*
 * This function returns a copy object that contains a list of entries via sharing or CoW,
 * depending on the `top_do_copy` argument.
 * - The entries in the copy start from address 0 and need to be moved to the destination address
 */
static kern_return_t
vm_map_remap_extract(
	vm_map_t                map,
	vm_map_offset_t         addr,
	vm_map_size_t           size,
	const bool              top_do_copy,
	vm_map_copy_t           map_copy,
	vm_prot_t               *cur_protection,   /* IN/OUT */
	vm_prot_t               *max_protection,   /* IN/OUT */
	vm_inherit_t            inheritance,
	vm_map_kernel_flags_t   vmk_flags)
{
	kern_return_t           kr = KERN_SUCCESS;
	vm_map_entry_t          src_entry;     /* current entry of the iteration */
	vm_map_offset_t         map_address;   /* current address we're at in the iteration */
	vm_map_offset_t         src_start;     /* start of region to map */
	vm_map_offset_t         src_end;       /* end of region to be mapped */

	vm_prot_t               max_prot_for_prot_copy = VM_PROT_NONE;
	vm_map_offset_t         effective_page_mask;
	vm_prot_t               required_cur_prot, required_max_prot;

	/* 'X_do_copy' controls if we're creating a CoW copy or a share copy
	 * top_do_copy represents the user request and controls copy entries that originate from the top-level map.
	 * cur_do_copy is evaluated every iteration and may change from top_do_copy when top_do_copy=false and
	 * we've descended into a submap with needs_copy=true. Possible states:
	 *   top_do_copy:false, cur_do_copy:false - user requested share copy, this entry is copied share
	 *   top_do_copy:false, cur_do_copy:true  - user requested share copy, this entry is copied CoW due to needs_copy
	 *   top_do_copy:true,  cur_do_copy:true  - user requested CoW copy, this entry is copied CoW
	 *   top_do_copy:true,  cur_do_copy:false - not possible
	 */

	vmlp_api_start(VM_MAP_REMAP_EXTRACT);

	effective_page_mask = MIN(PAGE_MASK, VM_MAP_PAGE_MASK(map));

	assert(map != VM_MAP_NULL);
	assert(size != 0);
	assert(size == vm_map_round_page(size, effective_page_mask));
	assert(inheritance == VM_INHERIT_NONE || inheritance == VM_INHERIT_COPY || inheritance == VM_INHERIT_SHARE);
	assert(!(*cur_protection & ~(VM_PROT_ALL | VM_PROT_ALLEXEC)));
	assert(!(*max_protection & ~(VM_PROT_ALL | VM_PROT_ALLEXEC)));
	assert((*cur_protection & *max_protection) == *cur_protection);
	/* top-level map can't be a constant submap, this was a limitation before the range-lock change */
	assert(!vm_map_is_sealed(map));

	/* Compute start and end of region. */
	src_start = vm_map_trunc_page(addr, effective_page_mask);
	src_end = vm_map_round_page(src_start + size, effective_page_mask);

	if (vmk_flags.vmkf_remap_prot_copy) {
		/* This flag is only supported with copy=true since that's how vm_protect() uses it. */
		assert(top_do_copy);
		/* Special case for vm_map_protect(VM_PROT_COPY):
		 * we want to set the new mappings' max protection to the specified *max_protection... */
		max_prot_for_prot_copy = *max_protection & (VM_PROT_ALL | VM_PROT_ALLEXEC);
		/* ... but we still want to use the vm_remap() legacy mode (which won't reset the
		 * all the new entries to the same protection) */
		vmk_flags.vmkf_remap_legacy_mode = true;
	}

	if (vmk_flags.vmkf_remap_legacy_mode) {
		/*
		 * vm_remap() legacy mode:
		 * Extract all memory regions in the specified range and
		 * collect the strictest set of protections allowed on the
		 * entire range, so the caller knows what they can do with
		 * the remapped range.
		 * We start with VM_PROT_ALL and we'll remove the protections
		 * missing from each memory region.
		 */
		*cur_protection = VM_PROT_ALL;
		*max_protection = VM_PROT_ALL;
		required_cur_prot = VM_PROT_NONE;
		required_max_prot = VM_PROT_NONE;
	} else {
		/*
		 * vm_remap_new() mode:
		 * Extract all memory regions in the specified range and
		 * ensure that they have at least the protections specified
		 * by the caller via *cur_protection and *max_protection.
		 * The resulting mapping should then have these exact protections.
		 * required_cur_prot, required_max_prot is set every iteration below
		 * according to cur_do_copy
		 */
	}

	map_address = 0; /* address of the copy starts at 0, also the size added to copy while iterating */

	/* The specified source virtual space might correspond to multiple map entries, need to loop on them. */
	vmlp_range_event(map, addr, size);

	if (map->pmap == kernel_pmap) {
		map_copy->is_kernel_range = true;
		map_copy->orig_range = kmem_addr_get_range(addr, size);
#if CONFIG_MAP_RANGES
	} else if (map->uses_user_ranges) {
		map_copy->is_user_range = true;
		/* The map ilk protects the atomicity of finding the range-id for the address, but there is no
		 * atomicity guarantee to copying the range-id from the source of remap to the destination.
		 * someone may race to lock this right after this is done and before anything actually gets copied */
		vm_map_ilk_lock(map);
		map_copy->orig_range = vm_map_user_range_resolve(map, addr, size, NULL);
		vm_map_ilk_unlock(map);
#endif /* CONFIG_MAP_RANGES */
	}

	if (VM_MAP_PAGE_SHIFT(map) < PAGE_SHIFT) {
		/*
		 * This address space uses sub-pages so the range might
		 * not be re-mappable in an address space with larger
		 * pages. Re-assemble any broken-up VM map entries to
		 * improve our chances of making it work.
		 */
		vm_map_simplify_range(map, src_start, src_end);
	}

	VM_MAP_LOCK_CTX_DECLARE(ctx);

	/* BEGIN IGNORE CODESTYLE */
	vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
		assert(!vme->is_sub_map);

		if (vm_map_lock_ctx_in_constant_submap(ctx)) {
			/* 
			 * remap special cases the sharing for constant submaps. 
			 * The preflight here doesn't need to worry about that 
			 * (or CoW, as we're not COPY_SYMMETRIC).
			 */
			return KERN_SUCCESS;
		}

		/* recreate cur_do_copy the same way as the main iteration */
		bool cur_do_copy = top_do_copy || vm_map_lock_ctx_is_in_needs_copy_submap(ctx);

		if (!cur_do_copy) {
			/* at this time (in the preflight) object can still be NULL since the lock didn't have the chance
			 * to do anything about VMO_ALLOCATE for this entry yet */
			return VMRL_ERR_PREPARE_FOR_SHARE_NOCLIP;
		}
		vm_object_t object = VME_OBJECT(vme);

		if (object == VM_OBJECT_NULL) {
			/*
			 * We passed VMO_ALLOCATE, so we still want CoW setup
			 * on the new object.
			*/
			return VMRL_ERR_SETUP_SYMMETRIC_COW_NOCLIP;
		}

		if (object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
			/* COPY_SYMMETRIC + non-zero wired_count should not be possible since wire changes it to delay */
			assert(vme->wired_count == 0);
			/* COPY_SYMMETRIC + is_shared should not be possible */
			assert(!vme->is_shared);

			if (!vme->needs_copy) {
				return VMRL_ERR_SETUP_SYMMETRIC_COW_NOCLIP;
			}
		}
		return KERN_SUCCESS;
	});
	/* END IGNORE CODESTYLE */

	/* flags:
	 * VMRL_SH_STREAM_NO_HOLES - by design can't remap a range that has holes
	 *		use a stream lock since we need to drop the entry lock for potentially faulting COPY_NONE objects
	 *		or COPY_DELAY objects that can go to copy_slowly
	 * VMRL_SH_DESCEND_INTO_CONSTANT -
	 *		we descend into transparent submaps by default.
	 *		this flag also causes descension in constant submaps
	 * VMRL_SH_VMO_ALLOCATE -
	 *              historically remap has allocated objects both in the copy
	 *              and the share cases. In the share case, this is required
	 *              for correctness of sharing. In the copy case, it is relied
	 *              on by vm_map_entry_cs_associate.
	 *	_NO_MIN_MAX_CHECK - so that it's possible to remap the x86 commpage
	 */
	kr = vm_map_range_sh_lock(ctx, &map, src_start, src_end,
	    VMRL_SH_STREAM_NO_HOLES | VMRL_SH_DESCEND_INTO_CONSTANT |
	    VMRL_SH_NO_MIN_MAX_CHECK | VMRL_SH_VMO_ALLOCATE);
	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_REMAP_EXTRACT, kr);
		return kr;
	}

	/* iterate source range */
	while ((src_entry = vm_map_range_stream_next_with_error(ctx, &kr)) != VM_MAP_ENTRY_NULL) {
		assert(src_entry != VM_MAP_ENTRY_NULL);
		vm_map_t             src_map = vm_map_lock_ctx_get_map(ctx);
#if DEBUG4K_UNSAFE_LOGGING
		vm_map_entry_t       save_src_entry = src_entry; /* for logging after src_entry is dropped and nulled */
#endif
		vm_object_t          object;
		vm_object_offset_t   offset;
		/* size of region to copy in the current entry (may be smaller than whole entry if it's the first or last) */
		vm_map_size_t        tmp_size;

		vm_map_lock_ctx_bounds(ctx, NULL, NULL, &tmp_size);
		/* range lock descends into submaps */
		assert(!src_entry->is_sub_map);
		assert(ctx->vmlc_vme != VM_MAP_ENTRY_NULL);

		/*
		 * if cur_do_copy is true, we will extract CoW entries.
		 * This happens in two cases:
		 * 1) The caller requested a remap(copy = True), in which case
		 * we need to do CoW.
		 * 2) We are descended into a needs_copy submap. We can't
		 * directly share entries in a needs_copy submap, and need to
		 * instead extract CoW copies. This happens in the shared-cache
		 */
		bool cur_do_copy = top_do_copy || vm_map_lock_ctx_is_in_needs_copy_submap(ctx);

		if (!vmk_flags.vmkf_remap_legacy_mode) {
			/* this needs to be evaluated every iteration according to cur_do_copy */
			if (cur_do_copy) {
				required_cur_prot = VM_PROT_NONE;
				required_max_prot = VM_PROT_READ;
			} else {
				required_cur_prot = *cur_protection;
				required_max_prot = *max_protection;
			}
		}

		if (((src_entry->protection & required_cur_prot) != required_cur_prot) ||
		    ((src_entry->max_protection & required_max_prot) != required_max_prot)) {
			if (vmk_flags.vmkf_copy_single_object) {
				/* In single_object mode, there's only 1 iteration, so we could not have mapped anything yet */
				assert(map_address == 0);
			}
			/* VM range extraction. Required protection is not available for this part of the range: fail. */
			kr = KERN_PROTECTION_FAILURE;
			break;
		}

		/* in the share case, the object has already been stabilized due to preflight returning VMRL_ERR_PREPARE_FOR_SHARE_NOCLIP */
		object = VME_OBJECT(src_entry);

		if (!_vm_map_remap_check_not_kernel(object)) {
			kr = KERN_INVALID_RIGHT;
			break;
		}
		vm_map_check_accounting_state_consistency(src_map, src_entry, object);

		if (object == VM_OBJECT_NULL) {
			offset = 0; /* no object => no offset */
		} else {
			/* take a temporary object ref. until we decide what to do with this object tag:REMAP-OBJ-REF */
			vm_object_reference(object);
			/* This moves offset from the value it was in src_entry to what it needs to be in the
			 * copy entry, considering src_start may not start at the start of the entry */
			vm_map_lock_ctx_offset_bounds(ctx, &offset, NULL, NULL);
		}

#if HAS_MTE
		/* verify MTE policy before allowing CoW/share operations
		 * This verifies the current entry and map and takes the argument addr,size for user interaction */
		kr = _vm_map_remap_check_mte_policy(src_map, addr, size, src_entry, cur_do_copy, inheritance, vmk_flags);
		if (kr != KERN_SUCCESS) {
			vm_object_deallocate(object); /* tag:REMAP-OBJ-REF */
			break;
		}
#endif /* HAS_MTE */

		vm_map_entry_t new_entry = vm_map_copy_entry_copy_no_ownership(map_copy, src_entry);
		vm_map_entry_reinit_after_copy(src_map, new_entry);
		assert3p(object, ==, VME_OBJECT(new_entry)); /* sanity */
		/* The entry points to the object but still this entry is not in the vm_map_copy_t so the
		 * object ownership still belongs to this scope to be set tag:REMAP-OBJ-REF */

		if (cur_do_copy) {
			/* We're dealing with a copy-on-write operation,
			 * so the resulting mapping should not inherit the
			 * original mapping's accounting settings.
			 * "use_pmap" should be reset to its default (TRUE)
			 * so that the new mapping gets accounted for in
			 * the task's memory footprint. */
			new_entry->use_pmap = TRUE;
		}
		/* "iokit_acct" was cleared in vm_map_entry_reinit_after_copy() */
		assert(!new_entry->iokit_acct);

		new_entry->vme_start = map_address;
		new_entry->vme_end = map_address + tmp_size;
		assert(new_entry->vme_start < new_entry->vme_end);
		/*
		 * set protection properties of new_entry
		 */
		if (vmk_flags.vmkf_remap_prot_copy) {
			/* security: keep "permanent" and "csm_associated" */
			new_entry->vme_permanent = src_entry->vme_permanent;
			new_entry->csm_associated = src_entry->csm_associated;
			/*
			 * Remapping for vm_map_protect(VM_PROT_COPY)
			 * to convert a read-only mapping into a
			 * copy-on-write version of itself but
			 * with write access:
			 * keep the original inheritance but let's not
			 * add VM_PROT_WRITE to the max protection yet
			 * since we want to do more security checks against
			 * the target map.
			 */
			new_entry->inheritance = src_entry->inheritance;
			new_entry->protection &= max_prot_for_prot_copy;

#ifdef __arm64e__
			/*
			 * Remapping for vm_map_protect(VM_PROT_COPY) to remap a TPRO
			 * region to be explicitly writable without TPRO is only permitted
			 * if TPRO enforcement has been overridden.
			 *
			 * In this case we ensure any entries reset the TPRO state
			 * and we permit the region to be downgraded from permanent.
			 */
			if (new_entry->used_for_tpro) {
				if (vmk_flags.vmkf_tpro_enforcement_override) {
					new_entry->used_for_tpro = FALSE;
					new_entry->vme_permanent = FALSE;
				} else {
					kr = KERN_PROTECTION_FAILURE;
					vm_object_deallocate(object); /* tag:REMAP-OBJ-REF */
					vm_map_copy_entry_free_no_ownership(map_copy, new_entry);
					new_entry = VM_MAP_ENTRY_NULL;
					break;
				}
			}
#endif /* __arm64e__ */
		} else { /* vmk_flags.vmkf_remap_prot_copy */
			new_entry->inheritance = inheritance;
			if (!vmk_flags.vmkf_remap_legacy_mode) { /* _new semantics, set the given protection to the new entries */
				new_entry->protection = *cur_protection;
				new_entry->max_protection = *max_protection;
			}
		}

		VME_OFFSET_SET(new_entry, offset);

		/*
		 * The new region has to be copied now if required.
		 */
		if (!cur_do_copy) { /* share case */
			if (src_entry->used_for_jit == TRUE) {
				if (vmk_flags.vmkf_copy_same_map) {
				} else if (!VM_MAP_POLICY_ALLOW_JIT_SHARING(src_map)) {
					/* Cannot allow an entry describing a JIT region to be shared across address spaces. */
					kr = KERN_INVALID_ARGUMENT;
				}
				if (kr != KERN_SUCCESS) {
					vm_object_deallocate(object); /* tag:REMAP-OBJ-REF */
					vm_map_copy_entry_free_no_ownership(map_copy, new_entry);
					new_entry = VM_MAP_ENTRY_NULL;
					break;
				}
			}

			/* set is_shared in new_entry, setting src_entry->is_shared was done in the lock in response to preflight
			 * returning VMRL_ERR_PREPARE_FOR_SHARE_NOCLIP  */
			if (object == VM_OBJECT_NULL) {
				/* no accessible memory; nothing to share */
				assert(new_entry->protection == VM_PROT_NONE);
				assert(new_entry->max_protection == VM_PROT_NONE);
				new_entry->is_shared = FALSE;
			} else {
				new_entry->is_shared = TRUE;
			}

			assert(new_entry->needs_copy == FALSE);
		} else if (object == VM_OBJECT_NULL || src_entry->needs_copy) { /* quick copy case */
			if (object == VM_OBJECT_NULL) {
				assert(!src_entry->needs_copy);
				if (src_entry->max_protection == VM_PROT_NONE) {
					assert(src_entry->protection == VM_PROT_NONE);
				}
				assert(src_entry->use_pmap);
				assert(!src_map->mapped_in_other_pmaps);
			}

			/* CoW setup and src_entry->needs_copy=true was done in preflight */
			boolean_t src_needs_copy;
			boolean_t new_entry_needs_copy;

			__assert_only boolean_t ok_quickly = vm_object_copy_quickly(
				VME_OBJECT(new_entry),
				VME_OFFSET(new_entry),
				(new_entry->vme_end - new_entry->vme_start),
				&src_needs_copy,
				&new_entry_needs_copy);

			assert(ok_quickly == true);
			/* sanity check that vm_object_copy_quickly() set src_needs_copy as the preflight expected */
			assert(src_needs_copy == (object != VM_OBJECT_NULL && src_entry->needs_copy));

			new_entry->needs_copy = new_entry_needs_copy;
			new_entry->is_shared = FALSE;
			assertf(new_entry->use_pmap, "map %p new_entry %p\n", src_map, new_entry);
			/* CoW setup was done in the lock following the preflight under an exclusive
			 * entry lock (even in the case of shared-lock here) */

			/* discard temporary reference to object, copy_quickly() took the reference for the copy */
			vm_object_deallocate(object);
		} else { /* slow copy path */
			new_entry->is_shared = FALSE;
			assertf(new_entry->use_pmap, "map %p new_entry %p\n", src_map, new_entry);

			bool src_entry_was_wired = (src_entry->wired_count > 0);
			src_entry = VM_MAP_ENTRY_NULL;

			/* The map can be safely unlocked since we already hold a reference on the object. */
			vm_map_range_stream_drop(ctx);

			/*
			 * Perform the copy.
			 */
			if (src_entry_was_wired) {
				vm_object_t new_copy_object;     /* vm_object_copy_* result */
				vm_object_lock(object);
				kr = vm_object_copy_slowly(
					object,
					offset,
					(new_entry->vme_end - new_entry->vme_start),
					THREAD_UNINT,
#if HAS_MTE
					false, /* create_mte_object */
#endif /* HAS_MTE */
					&new_copy_object);
				VM_OBJECT_SET_KEEP_JIT(new_entry, new_copy_object, false, 0);
				VME_OFFSET_SET(new_entry, offset - vm_object_trunc_page(offset));
				new_entry->needs_copy = FALSE;
			} else {
				assert(object->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC);
				vm_object_t new_copy_object;     /* vm_object_copy_* result */
				vm_object_offset_t new_offset;
				boolean_t new_entry_needs_copy = false;

				new_offset = VME_OFFSET(new_entry);
				kr = vm_object_copy_strategically(
					object,
					offset,
					(new_entry->vme_end - new_entry->vme_start),
					false, /* forking */
					&new_copy_object,
					&new_offset,
					&new_entry_needs_copy);
				/* cases of MEMORY_OBJECT_COPY_SYMMETRIC should have already been handled */
				assert(kr != KERN_MEMORY_RESTART_COPY);

				VM_OBJECT_SET_KEEP_JIT(new_entry, new_copy_object, false, 0);
				if (new_offset != VME_OFFSET(new_entry)) {
					VME_OFFSET_SET(new_entry, new_offset);
				}

				new_entry->needs_copy = new_entry_needs_copy;
			}

			/* discard the temporary reference, vm_object_copy_*() took a reference for the copy if needed. tag:REMAP-OBJ-REF */
			vm_object_deallocate(object);

			if (kr != KERN_SUCCESS) {
				vm_map_copy_entry_free_no_ownership(map_copy, new_entry);
				break;
			}
		} /* slow copy path */

		if (cur_do_copy && !top_do_copy) {
			/* We were asked for a "shared" re-mapping but had to do a "copy-on-write" remapping of the
			 * submap's mapping to honor the submap's "needs_copy".
			 * We now need to resolve that pending "copy-on-write" to get something we can share.
			 * Example use-case: trying to share the CoW data-segment of a dylib in the shared-cache */

			/* Verify we're in a constant submap, do sanity check here since this controls what
			 * vm_map_stabilize_object_for_share()->vm_map_create_private_symmetric_object() does.
			 * transparent submaps don't have mapped_in_other_pmaps=true but also don't have needs_copy=true
			 * (see kmem_suballoc()) so won't reach here. */
			assert(src_map->mapped_in_other_pmaps);
			assert(vm_map_is_sealed(src_map));
			vm_map_stabilize_object_for_share(ctx, new_entry,
			    /*is_mapped_entry=*/ false,    /* since this entry is in the copy, no need to make sure it's locked */
			    /* share_with_upl=*/ false
			    );
		}

		vm_map_copy_store_insert_tail(map_copy, new_entry);
		/* ownership of the entry and object is transferred to the copy tag:REMAP-OBJ-REF */

		/* protections for submap mapping are irrelevant here */
		if (vmk_flags.vmkf_remap_legacy_mode) {
			/* old semantics - return the old protection from the source */
			*cur_protection &= new_entry->protection;
			*max_protection &= new_entry->max_protection;
		}

		map_address += tmp_size;
		src_start += tmp_size;

		if (vmk_flags.vmkf_copy_single_object) {
			if (map_address != size) {
				DEBUG4K_SHARE("map %p addr 0x%llx size 0x%llx clipped copy at mapped_size 0x%llx\n",
				    src_map, addr, size, map_address); /* map_address starts at 0 so it's the same as mapped_size */
#if DEBUG4K_UNSAFE_LOGGING
				/* The check for printing this log is unsafe due to unlocked access to vme_next, but it may be useful
				 *  for some debugging situations */
				if (!entry_is_map_end(src_map, save_src_entry->vme_next) &&
				    save_src_entry->vme_next->vme_object_value == save_src_entry->vme_object_value) {
					/* XXX TODO4K */
					DEBUG4K_ERROR("could have extended copy to next entry...\n");
				}
#endif /* DEBUG4K_UNSAFE_LOGGING */
			}
			break;
		}
	} /* end entry iteration while */


	vm_map_range_sh_unlock(ctx, &map);

	if (kr != KERN_SUCCESS) {
		/* Free all allocated elements.  empty the copy of its content */
		vm_map_entry_t next_entry = VM_MAP_ENTRY_NULL;
		for (src_entry = vm_map_copy_first_entry(map_copy);
		    !entry_is_copy_end(map_copy, src_entry);
		    src_entry = next_entry) {
			next_entry = src_entry->vme_next;
			vm_map_copy_store_remove(map_copy, src_entry);
			vm_map_copy_entry_free(map_copy, src_entry);
		}
	}
	vmlp_api_end(VM_MAP_REMAP_EXTRACT, kr);
	return kr;
}

bool
vm_map_is_exotic(
	vm_map_t map)
{
	return VM_MAP_IS_EXOTIC(map);
}

bool
vm_map_is_alien(
	vm_map_t map)
{
	return VM_MAP_IS_ALIEN(map);
}

#if XNU_TARGET_OS_OSX
void
vm_map_mark_alien(
	vm_map_t map)
{
	vmlp_api_start(VM_MAP_MARK_ALIEN);
	vm_map_ilk_lock(map);
	vmlp_range_event_none(map);
	map->is_alien = true;
	vm_map_ilk_unlock(map);
	vmlp_api_end(VM_MAP_MARK_ALIEN, 0);
}

void
vm_map_single_jit(
	vm_map_t map)
{
	vmlp_api_start(VM_MAP_SINGLE_JIT);
	vm_map_ilk_lock(map);
	vmlp_range_event_none(map);
	map->single_jit = true;
	vm_map_ilk_unlock(map);
	vmlp_api_end(VM_MAP_SINGLE_JIT, 0);
}
#endif /* XNU_TARGET_OS_OSX */

#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
bool
vm_map_has_sec_access(vm_map_t map)
{
	return map->has_sec_access;
}

void
vm_map_mark_has_sec_access_ilocked(vm_map_t map)
{
	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);
	map->has_sec_access = true;
}

#if CONFIG_XNUPOST
void
vm_map_mark_has_sec_access(vm_map_t map)
{
	vm_map_ilk_lock(map);
	map->has_sec_access = true;
	vm_map_ilk_unlock(map);
}

void
vm_map_remove_sec_access(vm_map_t map)
{
	assert(map != kernel_map);
	vm_map_ilk_lock(map);
	map->has_sec_access = false;
	vm_map_ilk_unlock(map);
}
#endif /* CONFIG_XNUPOST */
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */


/*
 * Callers of this function must call vm_map_copy_require on
 * previously created vm_map_copy_t or pass a newly created
 * one to ensure that it hasn't been forged.
 */
static kern_return_t
vm_map_copy_to_physcopy(
	vm_map_copy_t   copy_map,
	vm_map_t        target_map)
{
	vm_map_size_t           size;
	vm_map_entry_t          entry;
	vm_map_entry_t          new_entry;
	vm_object_t             new_object;
	unsigned int            pmap_flags;
	pmap_t                  new_pmap;
	vm_map_t                new_map;
	vm_map_address_t        src_start, src_end, src_cur;
	vm_map_address_t        dst_start, dst_end, dst_cur;
	kern_return_t           kr;
	void                    *kbuf;

	/*
	 * Perform the equivalent of vm_allocate() and memcpy().
	 * Replace the mappings in "copy_map" with the newly allocated mapping.
	 */
	DEBUG4K_COPY("copy_map %p (%d %d 0x%llx 0x%llx) BEFORE\n", copy_map, copy_map->cpy_hdr.page_shift, copy_map->cpy_hdr.nentries, copy_map->offset, (uint64_t)copy_map->size);

	assert(copy_map->cpy_hdr.page_shift != VM_MAP_PAGE_MASK(target_map));

	/* create a new pmap to map "copy_map" */
	pmap_flags = 0;
	assert(copy_map->cpy_hdr.page_shift == FOURK_PAGE_SHIFT);
#if PMAP_CREATE_FORCE_4K_PAGES
	pmap_flags |= PMAP_CREATE_FORCE_4K_PAGES;
#endif /* PMAP_CREATE_FORCE_4K_PAGES */
	pmap_flags |= PMAP_CREATE_64BIT;
	new_pmap = pmap_create_options(NULL, (vm_map_size_t)0, pmap_flags);
	if (new_pmap == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	/* allocate new VM object */
	size = VM_MAP_ROUND_PAGE(copy_map->size, PAGE_MASK);
	new_object = vm_object_allocate(size, VM_MAP_SERIAL_NONE);
	assert(new_object);

	/* allocate new VM map entry */
	new_entry = vm_map_copy_entry_create(copy_map, 0, size);
	assert(new_entry);

	/* finish initializing new VM map entry */
	new_entry->protection = VM_PROT_DEFAULT;
	new_entry->max_protection = VM_PROT_DEFAULT;
	new_entry->use_pmap = TRUE;

	/* make new VM map entry point to new VM object */
	VME_OBJECT_SET(new_entry, new_object, false, 0);
	VME_OFFSET_SET(new_entry, 0);

	/* create a new pageable VM map to map "copy_map" */
	new_map = vm_map_create_with_page_shift(new_pmap, 0, MACH_VM_MAX_ADDRESS,
	    copy_map->cpy_hdr.page_shift, VM_MAP_CREATE_DEFAULT);
	assert(new_map);

	/* map "copy_map" in the new VM map */
	src_start = 0;
	kr = vm_map_copyout_internal(
		new_map,
		&src_start,
		copy_map,
		copy_map->size,
		FALSE, /* consume_on_success */
		VM_PROT_DEFAULT,
		VM_PROT_DEFAULT,
		VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
	src_end = src_start + copy_map->size;

	/* map "new_object" in the new VM map */
	vm_object_reference(new_object);
	dst_start = 0;
	kr = vm_map_enter(new_map,
	    &dst_start,
	    size,
	    0,               /* mask */
	    VM_MAP_KERNEL_FLAGS_ANYWHERE(.vm_tag = VM_KERN_MEMORY_OSFMK),
	    new_object,
	    0,               /* offset */
	    FALSE,               /* needs copy */
	    VM_PROT_DEFAULT,
	    VM_PROT_DEFAULT,
	    VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
	dst_end = dst_start + size;

	/* get a kernel buffer */
	kbuf = kalloc_data(PAGE_SIZE, Z_WAITOK | Z_NOFAIL);

	/* physically copy "copy_map" mappings to new VM object */
	for (src_cur = src_start, dst_cur = dst_start;
	    src_cur < src_end;
	    src_cur += PAGE_SIZE, dst_cur += PAGE_SIZE) {
		vm_size_t bytes;

		bytes = PAGE_SIZE;
		if (src_cur + PAGE_SIZE > src_end) {
			/* partial copy for last page */
			bytes = src_end - src_cur;
			assert(bytes > 0 && bytes < PAGE_SIZE);
			/* rest of dst page should be zero-filled */
		}
		/* get bytes from src mapping */
		kr = copyinmap(new_map, src_cur, kbuf, bytes);
		if (kr != KERN_SUCCESS) {
			DEBUG4K_COPY("copyinmap(%p, 0x%llx, %p, 0x%llx) kr 0x%x\n", new_map, (uint64_t)src_cur, kbuf, (uint64_t)bytes, kr);
		}
		/* put bytes in dst mapping */
		assert(dst_cur < dst_end);
		assert(dst_cur + bytes <= dst_end);
		kr = copyoutmap(new_map, kbuf, dst_cur, bytes);
		if (kr != KERN_SUCCESS) {
			DEBUG4K_COPY("copyoutmap(%p, %p, 0x%llx, 0x%llx) kr 0x%x\n", new_map, kbuf, (uint64_t)dst_cur, (uint64_t)bytes, kr);
		}
	}

	/* free kernel buffer */
	kfree_data(kbuf, PAGE_SIZE);

	/* destroy new map */
	vm_map_destroy(new_map);
	new_map = VM_MAP_NULL;

	/* dispose of the old map entries in "copy_map" */
	while (vm_map_copy_first_entry(copy_map) !=
	    vm_map_copy_to_entry(copy_map)) {
		entry = vm_map_copy_first_entry(copy_map);
		vm_map_copy_store_remove(copy_map, entry);
		vm_map_copy_entry_free(copy_map, entry);
	}

	/* change "copy_map"'s page_size to match "target_map" */
	copy_map->cpy_hdr.page_shift = (uint16_t)VM_MAP_PAGE_SHIFT(target_map);
	copy_map->offset = 0;
	copy_map->size = size;

	/* insert new map entry in "copy_map" */
	assert(vm_map_copy_last_entry(copy_map) == vm_map_copy_to_entry(copy_map));
	vm_map_copy_store_insert_tail(copy_map, new_entry);

	DEBUG4K_COPY("copy_map %p (%d %d 0x%llx 0x%llx) AFTER\n", copy_map, copy_map->cpy_hdr.page_shift, copy_map->cpy_hdr.nentries, copy_map->offset, (uint64_t)copy_map->size);
	return KERN_SUCCESS;
}

void
vm_map_copy_adjust_get_target_copy_map(
	vm_map_copy_t   copy_map,
	vm_map_copy_t   *target_copy_map_p);
void
vm_map_copy_adjust_get_target_copy_map(
	vm_map_copy_t   copy_map,
	vm_map_copy_t   *target_copy_map_p)
{
	vm_map_copy_t   target_copy_map;
	vm_map_entry_t  entry, target_entry;

	if (*target_copy_map_p != VM_MAP_COPY_NULL) {
		/* the caller already has a "target_copy_map": use it */
		return;
	}

	/* the caller wants us to create a new copy of "copy_map" */
	assert(copy_map->type == VM_MAP_COPY_ENTRY_LIST);
	target_copy_map = vm_map_copy_allocate(copy_map->type,
	    copy_map->cpy_hdr.page_shift);
	target_copy_map->offset = copy_map->offset;
	target_copy_map->size = copy_map->size;
	for (entry = vm_map_copy_first_entry(copy_map);
	    entry != vm_map_copy_to_entry(copy_map);
	    entry = entry->vme_next) {
		target_entry = vm_map_copy_entry_copy(target_copy_map, entry);
		vm_map_copy_store_insert_tail(target_copy_map, target_entry);
	}
	entry = VM_MAP_ENTRY_NULL;
	*target_copy_map_p = target_copy_map;
}

/*
 * Callers of this function must call vm_map_copy_require on
 * previously created vm_map_copy_t or pass a newly created
 * one to ensure that it hasn't been forged.
 */
static void
vm_map_copy_trim(
	vm_map_copy_t   copy_map,
	uint16_t        new_page_shift,
	vm_map_offset_t trim_start,
	vm_map_offset_t trim_end)
{
	uint16_t        copy_page_shift;
	vm_map_entry_t  entry, next_entry;

	assert(copy_map->type == VM_MAP_COPY_ENTRY_LIST);
	assert(copy_map->cpy_hdr.nentries > 0);

	trim_start += vm_map_copy_first_entry(copy_map)->vme_start;
	trim_end += vm_map_copy_first_entry(copy_map)->vme_start;

	/* use the new page_shift to do the clipping */
	copy_page_shift = VM_MAP_COPY_PAGE_SHIFT(copy_map);
	copy_map->cpy_hdr.page_shift = new_page_shift;

	for (entry = vm_map_copy_first_entry(copy_map);
	    entry != vm_map_copy_to_entry(copy_map);
	    entry = next_entry) {
		next_entry = entry->vme_next;
		if (entry->vme_end <= trim_start) {
			/* entry fully before trim range: skip */
			continue;
		}
		if (entry->vme_start >= trim_end) {
			/* entry fully after trim range: done */
			break;
		}
		/* clip entry if needed */
		vm_map_copy_store_clip_start(copy_map, entry, trim_start);
		vm_map_copy_store_clip_end(copy_map, entry, trim_end);
		next_entry = entry->vme_next;
		/* dispose of entry */
		copy_map->size -= entry->vme_end - entry->vme_start;
		vm_map_copy_store_remove(copy_map, entry);
		vm_map_copy_entry_free(copy_map, entry);
		entry = VM_MAP_ENTRY_NULL;
	}

	/* restore copy_map's original page_shift */
	copy_map->cpy_hdr.page_shift = copy_page_shift;
}

/*
 * Make any necessary adjustments to "copy_map" to allow it to be
 * mapped into "target_map".
 * If no changes were necessary, "target_copy_map" points to the
 * untouched "copy_map".
 * If changes are necessary, changes will be made to "target_copy_map".
 * If "target_copy_map" was NULL, we create a new "vm_map_copy_t" and
 * copy the original "copy_map" to it before applying the changes.
 * The caller should discard "target_copy_map" if it's not the same as
 * the original "copy_map".
 */
/* TODO4K: also adjust to sub-range in the copy_map -> add start&end? */
kern_return_t
vm_map_copy_adjust_to_target(
	vm_map_copy_t           src_copy_map,
	vm_map_offset_ut        offset_u,
	vm_map_size_ut          size_u,
	vm_map_t                target_map,
	boolean_t               copy,
	vm_map_copy_t           *target_copy_map_p,
	vm_map_offset_t         *overmap_start_p,
	vm_map_offset_t         *overmap_end_p,
	vm_map_offset_t         *trimmed_start_p)
{
	vm_map_copy_t           copy_map, target_copy_map;
	vm_map_size_t           target_size;
	vm_map_size_t           src_copy_map_size;
	vm_map_size_t           overmap_start, overmap_end;
	int                     misalignments;
	vm_map_entry_t          entry, target_entry;
	vm_map_offset_t         addr_adjustment;
	vm_map_offset_t         new_start, new_end;
	int                     copy_page_mask, target_page_mask;
	uint16_t                copy_page_shift, target_page_shift;
	vm_map_offset_t         trimmed_end;
	vm_map_size_t           map_size;
	kern_return_t           kr;

	/*
	 * Sanitize any input parameters that are addr/size/prot/inherit
	 */
	kr = vm_map_copy_addr_size_sanitize(
		target_map,
		offset_u,
		size_u,
		VM_SANITIZE_CALLER_MACH_MEMORY_ENTRY_MAP_SIZE,
		&new_start,
		&new_end,
		&map_size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	/*
	 * Assert that the vm_map_copy is coming from the right
	 * zone and hasn't been forged
	 */
	vm_map_copy_require(src_copy_map);
	assert(src_copy_map->type == VM_MAP_COPY_ENTRY_LIST);

	/*
	 * Start working with "src_copy_map" but we'll switch
	 * to "target_copy_map" as soon as we start making adjustments.
	 */
	copy_map = src_copy_map;
	src_copy_map_size = src_copy_map->size;

	copy_page_shift = VM_MAP_COPY_PAGE_SHIFT(copy_map);
	copy_page_mask = VM_MAP_COPY_PAGE_MASK(copy_map);
	target_page_shift = (uint16_t)VM_MAP_PAGE_SHIFT(target_map);
	target_page_mask = VM_MAP_PAGE_MASK(target_map);

	DEBUG4K_ADJUST("copy_map %p (%d offset 0x%llx size 0x%llx) target_map %p (%d) copy %d offset 0x%llx size 0x%llx target_copy_map %p...\n", copy_map, copy_page_shift, (uint64_t)copy_map->offset, (uint64_t)copy_map->size, target_map, target_page_shift, copy, (uint64_t)VM_SANITIZE_UNSAFE_UNWRAP(offset_u), (uint64_t)VM_SANITIZE_UNSAFE_UNWRAP(size_u), *target_copy_map_p);

	target_copy_map = *target_copy_map_p;
	if (target_copy_map != VM_MAP_COPY_NULL) {
		vm_map_copy_require(target_copy_map);
	}

	if (new_end > copy_map->size) {
		DEBUG4K_ERROR("copy_map %p (%d->%d) copy_map->size 0x%llx offset 0x%llx size 0x%llx KERN_INVALID_ARGUMENT\n", copy_map, copy_page_shift, target_page_shift, (uint64_t)copy_map->size, (uint64_t)VM_SANITIZE_UNSAFE_UNWRAP(offset_u), (uint64_t)VM_SANITIZE_UNSAFE_UNWRAP(size_u));
		return KERN_INVALID_ARGUMENT;
	}

	/* trim the end */
	trimmed_end = 0;
	new_end = VM_MAP_ROUND_PAGE(new_end, target_page_mask);
	if (new_end < copy_map->size) {
		trimmed_end = src_copy_map_size - new_end;
		DEBUG4K_ADJUST("copy_map %p (%d->%d) copy %d offset 0x%llx size 0x%llx target_copy_map %p... trim end from 0x%llx to 0x%llx\n", copy_map, copy_page_shift, target_page_shift, copy, (uint64_t)VM_SANITIZE_UNSAFE_UNWRAP(offset_u), (uint64_t)VM_SANITIZE_UNSAFE_UNWRAP(size_u), target_copy_map, (uint64_t)new_end, (uint64_t)copy_map->size);
		/* get "target_copy_map" if needed and adjust it */
		vm_map_copy_adjust_get_target_copy_map(copy_map,
		    &target_copy_map);
		copy_map = target_copy_map;
		vm_map_copy_trim(target_copy_map, target_page_shift,
		    new_end, copy_map->size);
	}

	/* trim the start */
	new_start = VM_MAP_TRUNC_PAGE(new_start, target_page_mask);
	if (new_start != 0) {
		DEBUG4K_ADJUST("copy_map %p (%d->%d) copy %d offset 0x%llx size 0x%llx target_copy_map %p... trim start from 0x%llx to 0x%llx\n", copy_map, copy_page_shift, target_page_shift, copy, (uint64_t)VM_SANITIZE_UNSAFE_UNWRAP(offset_u), (uint64_t)VM_SANITIZE_UNSAFE_UNWRAP(size_u), target_copy_map, (uint64_t)0, (uint64_t)new_start);
		/* get "target_copy_map" if needed and adjust it */
		vm_map_copy_adjust_get_target_copy_map(copy_map,
		    &target_copy_map);
		copy_map = target_copy_map;
		vm_map_copy_trim(target_copy_map, target_page_shift,
		    0, new_start);
	}
	*trimmed_start_p = new_start;

	/* target_size starts with what's left after trimming */
	target_size = copy_map->size;
	assertf(target_size == src_copy_map_size - *trimmed_start_p - trimmed_end,
	    "target_size 0x%llx src_copy_map_size 0x%llx trimmed_start 0x%llx trimmed_end 0x%llx\n",
	    (uint64_t)target_size, (uint64_t)src_copy_map_size,
	    (uint64_t)*trimmed_start_p, (uint64_t)trimmed_end);

	/* check for misalignments but don't adjust yet */
	misalignments = 0;
	overmap_start = 0;
	overmap_end = 0;
	if (copy_page_shift < target_page_shift) {
		/*
		 * Remapping from 4K to 16K: check the VM object alignments
		 * throughout the range.
		 * If the start and end of the range are mis-aligned, we can
		 * over-map to re-align, and adjust the "overmap" start/end
		 * and "target_size" of the range accordingly.
		 * If there is any mis-alignment within the range:
		 *     if "copy":
		 *         we can do immediate-copy instead of copy-on-write,
		 *     else:
		 *         no way to remap and share; fail.
		 */
		for (entry = vm_map_copy_first_entry(copy_map);
		    entry != vm_map_copy_to_entry(copy_map);
		    entry = entry->vme_next) {
			vm_object_offset_t object_offset_start, object_offset_end;

			object_offset_start = VME_OFFSET(entry);
			object_offset_end = object_offset_start;
			object_offset_end += entry->vme_end - entry->vme_start;
			if (object_offset_start & target_page_mask) {
				if (entry == vm_map_copy_first_entry(copy_map) && !copy) {
					overmap_start++;
				} else {
					misalignments++;
				}
			}
			if (object_offset_end & target_page_mask) {
				if (entry->vme_next == vm_map_copy_to_entry(copy_map) && !copy) {
					overmap_end++;
				} else {
					misalignments++;
				}
			}
		}
	}
	entry = VM_MAP_ENTRY_NULL;

	/* decide how to deal with misalignments */
	assert(overmap_start <= 1);
	assert(overmap_end <= 1);
	if (!overmap_start && !overmap_end && !misalignments) {
		/* copy_map is properly aligned for target_map ... */
		if (*trimmed_start_p) {
			/* ... but we trimmed it, so still need to adjust */
		} else {
			/* ... and we didn't trim anything: we're done */
			if (target_copy_map == VM_MAP_COPY_NULL) {
				target_copy_map = copy_map;
			}
			*target_copy_map_p = target_copy_map;
			*overmap_start_p = 0;
			*overmap_end_p = 0;
			DEBUG4K_ADJUST("copy_map %p (%d offset 0x%llx size 0x%llx) target_map %p (%d) copy %d target_copy_map %p (%d offset 0x%llx size 0x%llx) -> trimmed 0x%llx overmap start 0x%llx end 0x%llx KERN_SUCCESS\n", copy_map, copy_page_shift, (uint64_t)copy_map->offset, (uint64_t)copy_map->size, target_map, target_page_shift, copy, *target_copy_map_p, VM_MAP_COPY_PAGE_SHIFT(*target_copy_map_p), (uint64_t)(*target_copy_map_p)->offset, (uint64_t)(*target_copy_map_p)->size, (uint64_t)*trimmed_start_p, (uint64_t)*overmap_start_p, (uint64_t)*overmap_end_p);
			return KERN_SUCCESS;
		}
	} else if (misalignments && !copy) {
		/* can't "share" if misaligned */
		DEBUG4K_ADJUST("unsupported sharing\n");
#if MACH_ASSERT
		if (debug4k_panic_on_misaligned_sharing) {
			panic("DEBUG4k %s:%d unsupported sharing", __FUNCTION__, __LINE__);
		}
#endif /* MACH_ASSERT */
		DEBUG4K_ADJUST("copy_map %p (%d) target_map %p (%d) copy %d target_copy_map %p -> KERN_NOT_SUPPORTED\n", copy_map, copy_page_shift, target_map, target_page_shift, copy, *target_copy_map_p);
		return KERN_NOT_SUPPORTED;
	} else {
		/* can't virtual-copy if misaligned (but can physical-copy) */
		DEBUG4K_ADJUST("mis-aligned copying\n");
	}

	/* get a "target_copy_map" if needed and switch to it */
	vm_map_copy_adjust_get_target_copy_map(copy_map, &target_copy_map);
	copy_map = target_copy_map;

	if (misalignments && copy) {
		vm_map_size_t target_copy_map_size;

		/*
		 * Can't do copy-on-write with misaligned mappings.
		 * Replace the mappings with a physical copy of the original
		 * mappings' contents.
		 */
		target_copy_map_size = target_copy_map->size;
		kr = vm_map_copy_to_physcopy(target_copy_map, target_map);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
		*target_copy_map_p = target_copy_map;
		*overmap_start_p = 0;
		*overmap_end_p = target_copy_map->size - target_copy_map_size;
		DEBUG4K_ADJUST("copy_map %p (%d offset 0x%llx size 0x%llx) target_map %p (%d) copy %d target_copy_map %p (%d offset 0x%llx size 0x%llx)-> trimmed 0x%llx overmap start 0x%llx end 0x%llx PHYSCOPY\n", copy_map, copy_page_shift, (uint64_t)copy_map->offset, (uint64_t)copy_map->size, target_map, target_page_shift, copy, *target_copy_map_p, VM_MAP_COPY_PAGE_SHIFT(*target_copy_map_p), (uint64_t)(*target_copy_map_p)->offset, (uint64_t)(*target_copy_map_p)->size, (uint64_t)*trimmed_start_p, (uint64_t)*overmap_start_p, (uint64_t)*overmap_end_p);
		return KERN_SUCCESS;
	}

	/* apply the adjustments */
	misalignments = 0;
	overmap_start = 0;
	overmap_end = 0;
	/* remove copy_map->offset, so that everything starts at offset 0 */
	addr_adjustment = copy_map->offset;
	/* also remove whatever we trimmed from the start */
	addr_adjustment += *trimmed_start_p;
	for (target_entry = vm_map_copy_first_entry(target_copy_map);
	    target_entry != vm_map_copy_to_entry(target_copy_map);
	    target_entry = target_entry->vme_next) {
		vm_object_offset_t object_offset_start, object_offset_end;

		DEBUG4K_ADJUST("copy %p (%d 0x%llx 0x%llx) entry %p [ 0x%llx 0x%llx ] object %p offset 0x%llx BEFORE\n", target_copy_map, VM_MAP_COPY_PAGE_SHIFT(target_copy_map), target_copy_map->offset, (uint64_t)target_copy_map->size, target_entry, (uint64_t)target_entry->vme_start, (uint64_t)target_entry->vme_end, VME_OBJECT(target_entry), VME_OFFSET(target_entry));
		object_offset_start = VME_OFFSET(target_entry);
		if (object_offset_start & target_page_mask) {
			DEBUG4K_ADJUST("copy %p (%d 0x%llx 0x%llx) entry %p [ 0x%llx 0x%llx ] object %p offset 0x%llx misaligned at start\n", target_copy_map, VM_MAP_COPY_PAGE_SHIFT(target_copy_map), target_copy_map->offset, (uint64_t)target_copy_map->size, target_entry, (uint64_t)target_entry->vme_start, (uint64_t)target_entry->vme_end, VME_OBJECT(target_entry), VME_OFFSET(target_entry));
			if (target_entry == vm_map_copy_first_entry(target_copy_map)) {
				/*
				 * start of 1st entry is mis-aligned:
				 * re-adjust by over-mapping.
				 */
				overmap_start = object_offset_start - trunc_page_mask_64(object_offset_start, target_page_mask);
				DEBUG4K_ADJUST("entry %p offset 0x%llx copy %d -> overmap_start 0x%llx\n", target_entry, VME_OFFSET(target_entry), copy, (uint64_t)overmap_start);
				VME_OFFSET_SET(target_entry, VME_OFFSET(target_entry) - overmap_start);
			} else {
				misalignments++;
				DEBUG4K_ADJUST("entry %p offset 0x%llx copy %d -> misalignments %d\n", target_entry, VME_OFFSET(target_entry), copy, misalignments);
				assert(copy);
			}
		}

		if (target_entry == vm_map_copy_first_entry(target_copy_map)) {
			target_size += overmap_start;
		} else {
			target_entry->vme_start += overmap_start;
		}
		target_entry->vme_end += overmap_start;

		object_offset_end = VME_OFFSET(target_entry) + target_entry->vme_end - target_entry->vme_start;
		if (object_offset_end & target_page_mask) {
			DEBUG4K_ADJUST("copy %p (%d 0x%llx 0x%llx) entry %p [ 0x%llx 0x%llx ] object %p offset 0x%llx misaligned at end\n", target_copy_map, VM_MAP_COPY_PAGE_SHIFT(target_copy_map), target_copy_map->offset, (uint64_t)target_copy_map->size, target_entry, (uint64_t)target_entry->vme_start, (uint64_t)target_entry->vme_end, VME_OBJECT(target_entry), VME_OFFSET(target_entry));
			if (target_entry->vme_next == vm_map_copy_to_entry(target_copy_map)) {
				/*
				 * end of last entry is mis-aligned: re-adjust by over-mapping.
				 */
				overmap_end = round_page_mask_64(object_offset_end, target_page_mask) - object_offset_end;
				DEBUG4K_ADJUST("entry %p offset 0x%llx copy %d -> overmap_end 0x%llx\n", target_entry, VME_OFFSET(target_entry), copy, (uint64_t)overmap_end);
				target_entry->vme_end += overmap_end;
				target_size += overmap_end;
			} else {
				misalignments++;
				DEBUG4K_ADJUST("entry %p offset 0x%llx copy %d -> misalignments %d\n", target_entry, VME_OFFSET(target_entry), copy, misalignments);
				assert(copy);
			}
		}
		target_entry->vme_start -= addr_adjustment;
		target_entry->vme_end -= addr_adjustment;
		DEBUG4K_ADJUST("copy %p (%d 0x%llx 0x%llx) entry %p [ 0x%llx 0x%llx ] object %p offset 0x%llx AFTER\n", target_copy_map, VM_MAP_COPY_PAGE_SHIFT(target_copy_map), target_copy_map->offset, (uint64_t)target_copy_map->size, target_entry, (uint64_t)target_entry->vme_start, (uint64_t)target_entry->vme_end, VME_OBJECT(target_entry), VME_OFFSET(target_entry));
	}

	target_copy_map->size = target_size;
	target_copy_map->offset += overmap_start;
	target_copy_map->offset -= addr_adjustment;
	target_copy_map->cpy_hdr.page_shift = target_page_shift;

//	assert(VM_MAP_PAGE_ALIGNED(target_copy_map->size, target_page_mask));
//	assert(VM_MAP_PAGE_ALIGNED(target_copy_map->offset, FOURK_PAGE_MASK));
	assert(overmap_start < VM_MAP_PAGE_SIZE(target_map));
	assert(overmap_end < VM_MAP_PAGE_SIZE(target_map));

	*target_copy_map_p = target_copy_map;
	*overmap_start_p = overmap_start;
	*overmap_end_p = overmap_end;

	DEBUG4K_ADJUST("copy_map %p (%d offset 0x%llx size 0x%llx) target_map %p (%d) copy %d target_copy_map %p (%d offset 0x%llx size 0x%llx) -> trimmed 0x%llx overmap start 0x%llx end 0x%llx KERN_SUCCESS\n", copy_map, copy_page_shift, (uint64_t)copy_map->offset, (uint64_t)copy_map->size, target_map, target_page_shift, copy, *target_copy_map_p, VM_MAP_COPY_PAGE_SHIFT(*target_copy_map_p), (uint64_t)(*target_copy_map_p)->offset, (uint64_t)(*target_copy_map_p)->size, (uint64_t)*trimmed_start_p, (uint64_t)*overmap_start_p, (uint64_t)*overmap_end_p);
	return KERN_SUCCESS;
}

kern_return_t
vm_map_range_physical_size(
	vm_map_t         map,
	vm_map_address_t start,
	mach_vm_size_t   size,
	mach_vm_size_t * phys_size)
{
	kern_return_t   kr;
	vm_map_copy_t   copy_map, target_copy_map;
	vm_map_offset_t adjusted_start, adjusted_end;
	vm_map_size_t   adjusted_size;
	vm_prot_t       cur_prot, max_prot;
	vm_map_offset_t overmap_start, overmap_end, trimmed_start, end;
	vm_map_kernel_flags_t vmk_flags;

	if (size == 0) {
		DEBUG4K_SHARE("map %p start 0x%llx size 0x%llx -> phys_size 0!\n", map, (uint64_t)start, (uint64_t)size);
		*phys_size = 0;
		return KERN_SUCCESS;
	}

	adjusted_start = vm_map_trunc_page(start, VM_MAP_PAGE_MASK(map));
	adjusted_end = vm_map_round_page(start + size, VM_MAP_PAGE_MASK(map));
	if (__improbable(os_add_overflow(start, size, &end) ||
	    adjusted_end <= adjusted_start)) {
		/* wraparound */
		printf("%s:%d(start=0x%llx, size=0x%llx) pgmask 0x%x: wraparound\n", __FUNCTION__, __LINE__, (uint64_t)start, (uint64_t)size, VM_MAP_PAGE_MASK(map));
		*phys_size = 0;
		return KERN_INVALID_ARGUMENT;
	}
	if (__improbable(vm_map_range_overflows(map, start, size))) {
		*phys_size = 0;
		return KERN_INVALID_ADDRESS;
	}
	assert(adjusted_end > adjusted_start);
	adjusted_size = adjusted_end - adjusted_start;
	*phys_size = adjusted_size;
	if (VM_MAP_PAGE_SIZE(map) == PAGE_SIZE) {
		return KERN_SUCCESS;
	}
	if (start == 0) {
		adjusted_start = vm_map_trunc_page(start, PAGE_MASK);
		adjusted_end = vm_map_round_page(start + size, PAGE_MASK);
		if (__improbable(adjusted_end <= adjusted_start)) {
			/* wraparound */
			printf("%s:%d(start=0x%llx, size=0x%llx) pgmask 0x%x: wraparound\n", __FUNCTION__, __LINE__, (uint64_t)start, (uint64_t)size, PAGE_MASK);
			*phys_size = 0;
			return KERN_INVALID_ARGUMENT;
		}
		assert(adjusted_end > adjusted_start);
		adjusted_size = adjusted_end - adjusted_start;
		*phys_size = adjusted_size;
		return KERN_SUCCESS;
	}

	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_copy_same_map = TRUE;
	assert(adjusted_size != 0);
	cur_prot = VM_PROT_NONE; /* legacy mode */
	max_prot = VM_PROT_NONE; /* legacy mode */
#if HAS_MTE
	/* this means the copy_map is discarded instead of being inserted into a map */
	vmk_flags.vmkf_copy_dest = VM_COPY_DESTINATION_INTERNAL;
#endif /* HAS_MTE */
	vmk_flags.vmkf_remap_legacy_mode = true;
	kr = vm_map_copy_extract(map, adjusted_start, adjusted_size,
	    FALSE /* copy */,
	    &copy_map,
	    &cur_prot, &max_prot, VM_INHERIT_DEFAULT,
	    vmk_flags);
	if (kr != KERN_SUCCESS) {
		DEBUG4K_ERROR("map %p start 0x%llx 0x%llx size 0x%llx 0x%llx kr 0x%x\n", map, (uint64_t)start, (uint64_t)adjusted_start, size, (uint64_t)adjusted_size, kr);
		//assert(0);
		*phys_size = 0;
		return kr;
	}
	assert(copy_map != VM_MAP_COPY_NULL);
	target_copy_map = copy_map;
	DEBUG4K_ADJUST("adjusting...\n");
	kr = vm_map_copy_adjust_to_target(
		copy_map,
		start - adjusted_start, /* offset */
		size, /* size */
		kernel_map,
		FALSE,                          /* copy */
		&target_copy_map,
		&overmap_start,
		&overmap_end,
		&trimmed_start);
	if (kr == KERN_SUCCESS) {
		if (target_copy_map->size != *phys_size) {
			DEBUG4K_ADJUST("map %p (%d) start 0x%llx size 0x%llx adjusted_start 0x%llx adjusted_end 0x%llx overmap_start 0x%llx overmap_end 0x%llx trimmed_start 0x%llx phys_size 0x%llx -> 0x%llx\n", map, VM_MAP_PAGE_SHIFT(map), (uint64_t)start, (uint64_t)size, (uint64_t)adjusted_start, (uint64_t)adjusted_end, (uint64_t)overmap_start, (uint64_t)overmap_end, (uint64_t)trimmed_start, (uint64_t)*phys_size, (uint64_t)target_copy_map->size);
		}
		*phys_size = target_copy_map->size;
	} else {
		DEBUG4K_ERROR("map %p start 0x%llx 0x%llx size 0x%llx 0x%llx kr 0x%x\n", map, (uint64_t)start, (uint64_t)adjusted_start, size, (uint64_t)adjusted_size, kr);
		//assert(0);
		*phys_size = 0;
	}
	vm_map_copy_discard(copy_map);
	copy_map = VM_MAP_COPY_NULL;

	return kr;
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_remap_sanitize(
	vm_map_t                src_map,
	vm_map_t                target_map,
	vm_map_address_ut       address_u,
	vm_map_size_ut          size_u,
	vm_map_offset_ut        mask_u,
	vm_map_offset_ut        memory_address_u,
	vm_prot_ut              cur_protection_u,
	vm_prot_ut              max_protection_u,
	vm_inherit_ut           inheritance_u,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_address_t       *target_addr,
	vm_map_address_t       *mask,
	vm_map_offset_t        *memory_address,
	vm_map_offset_t        *memory_end,
	vm_map_size_t          *memory_size,
	vm_prot_t              *cur_protection,
	vm_prot_t              *max_protection,
	vm_inherit_t           *inheritance)
{
	kern_return_t           result;
	vm_sanitize_flags_t     vm_sanitize_flags;

	result = vm_sanitize_inherit(inheritance_u, VM_SANITIZE_CALLER_VM_MAP_REMAP,
	    inheritance);
	if (__improbable(result != KERN_SUCCESS)) {
		return result;
	}

	result = vm_sanitize_cur_and_max_prots(cur_protection_u, max_protection_u,
	    VM_SANITIZE_CALLER_VM_MAP_REMAP, target_map,
	    cur_protection, max_protection);
	if (__improbable(result != KERN_SUCCESS)) {
		return result;
	}

	result = vm_sanitize_mask(mask_u, VM_SANITIZE_CALLER_VM_MAP_REMAP, mask);
	if (__improbable(result != KERN_SUCCESS)) {
		return result;
	}

	/*
	 * If the user is requesting that we return the address of the
	 * first byte of the data (rather than the base of the page),
	 * then we use different rounding semantics: specifically,
	 * we assume that (memory_address, size) describes a region
	 * all of whose pages we must cover, rather than a base to be truncated
	 * down and a size to be added to that base.  So we figure out
	 * the highest page that the requested region includes and make
	 * sure that the size will cover it.
	 *
	 * The key example we're worried about it is of the form:
	 *
	 *              memory_address = 0x1ff0, size = 0x20
	 *
	 * With the old semantics, we round down the memory_address to 0x1000
	 * and round up the size to 0x1000, resulting in our covering *only*
	 * page 0x1000.  With the new semantics, we'd realize that the region covers
	 * 0x1ff0-0x2010, and compute a size of 0x2000.  Thus, we cover both page
	 * 0x1000 and page 0x2000 in the region we remap.
	 *
	 * VM_SANITIZE_FLAGS_REALIGN_START asks for the old (broken) semantics.
	 */
	vm_sanitize_flags = VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS;
	if (!vmk_flags.vmf_return_data_addr) {
		vm_sanitize_flags |= VM_SANITIZE_FLAGS_REALIGN_START;
	}

	result = vm_sanitize_addr_size(memory_address_u, size_u,
	    VM_SANITIZE_CALLER_VM_MAP_REMAP, src_map,
	    vm_sanitize_flags, memory_address, memory_end,
	    memory_size);
	if (__improbable(result != KERN_SUCCESS)) {
		return result;
	}

	*target_addr = vm_sanitize_addr(target_map, address_u);
	return KERN_SUCCESS;
}

/*
 *	Routine: vm_map_remap
 *
 *	Map portion of a task's address space to a different address.
 *	Protections behaviour behaviour depend on flags.vmkf_remap_legacy_mode,
 *	see comment on mach_vm_remap_new_external() and mach_vm_remap_external()
 *	Inheritance attributes remain the same as in the original task.
 *	Source and Target task can be identical
 *	Other attributes are identical as for vm_map()
 *	@arg copy: true means to create a CoW mapping, false means create a shared mapping
 *	@arg address_u: IN: the target address to map to
 *	                    if !vmk_flags.vmf_fixed this is still used as a hint
 *	                OUT: the address in the target we ended up mapping to (on success)
 *	@arg memory_address_u: the source address
 */
kern_return_t
vm_map_remap(
	vm_map_t                target_map,
	vm_map_address_ut      *address_u, /* target address IO/OUT */
	vm_map_size_ut          size_u,
	vm_map_offset_ut        mask_u,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_t                src_map,
	vm_map_offset_ut        memory_address_u, /* src address */
	boolean_t               copy,
	vm_prot_ut             *cur_protection_u, /* IN/OUT */
	vm_prot_ut             *max_protection_u, /* IN/OUT */
	vm_inherit_ut           inheritance_u)
{
	vm_map_store_rsv_t      rsv = { };
	vm_map_address_t        target_addr; /* aligned to map page */
	vm_map_address_t        mask;
	vm_map_size_t           target_size;
	vm_map_offset_t         memory_address, memory_end;  /* source */
	vm_map_size_t           memory_size;
	vm_prot_t               cur_protection, max_protection;
	vm_inherit_t            inheritance;
	kern_return_t           result;
	vm_map_copy_t           copy_map;
	vm_map_offset_t         offset_in_mapping; /* if the source address is not page aligned, this is the reminder */
	vm_map_size_t           src_page_mask, target_page_mask;
	vm_map_size_t           initial_size;
	VM_MAP_ZAP_DECLARE(zap_list);

	vmlp_api_start(VM_MAP_REMAP);

	if (target_map == VM_MAP_NULL || src_map == VM_MAP_NULL) {
		vmlp_api_end(VM_MAP_REMAP, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}
	src_page_mask    = VM_MAP_PAGE_MASK(src_map);
	target_page_mask = VM_MAP_PAGE_MASK(target_map);

	if (src_page_mask != target_page_mask) {
		if (copy) {
			DEBUG4K_COPY("src_map %p pgsz 0x%x addr 0x%llx size 0x%llx copy %d -> target_map %p pgsz 0x%x\n", src_map, VM_MAP_PAGE_SIZE(src_map), VM_SANITIZE_UNSAFE_UNWRAP(memory_address_u), VM_SANITIZE_UNSAFE_UNWRAP(size_u), copy, target_map, VM_MAP_PAGE_SIZE(target_map));
		} else {
			DEBUG4K_SHARE("src_map %p pgsz 0x%x addr 0x%llx size 0x%llx copy %d -> target_map %p pgsz 0x%x\n", src_map, VM_MAP_PAGE_SIZE(src_map), VM_SANITIZE_UNSAFE_UNWRAP(memory_address_u), VM_SANITIZE_UNSAFE_UNWRAP(size_u), copy, target_map, VM_MAP_PAGE_SIZE(target_map));
		}
	}

	/*
	 * Sanitize any input parameters that are addr/size/prot/inherit
	 */
	result = vm_map_remap_sanitize(src_map,
	    target_map,
	    *address_u,
	    size_u,
	    mask_u,
	    memory_address_u,
	    *cur_protection_u,
	    *max_protection_u,
	    inheritance_u,
	    vmk_flags,
	    &target_addr,
	    &mask,
	    &memory_address,
	    &memory_end,
	    &memory_size,
	    &cur_protection,
	    &max_protection,
	    &inheritance);
	if (__improbable(result != KERN_SUCCESS)) {
		result = vm_sanitize_get_kr(result);
		vmlp_api_end(VM_MAP_REMAP, result);
		return result;
	}

	vmlp_range_event(target_map, target_addr, memory_size);
	vmlp_range_event(src_map, memory_address, memory_size);

	if (vmk_flags.vmf_return_data_addr) {
		/*
		 * This is safe to unwrap now that the quantities
		 * have been validated and rounded up normally.
		 */
		offset_in_mapping = vm_sanitize_offset_in_page(src_map, memory_address_u);
		initial_size = VM_SANITIZE_UNSAFE_UNWRAP(size_u);
	} else {
		/*
		 * IMPORTANT:
		 * This legacy code path is broken: for the range mentioned
		 * above [ memory_address = 0x1ff0,size = 0x20 ], which spans
		 * two 4k pages, it yields [ memory_address = 0x1000,
		 * size = 0x1000 ], which covers only the first 4k page.
		 * BUT some code unfortunately depends on this bug, so we
		 * can't fix it without breaking something.
		 * New code should get automatically opted in the new
		 * behavior with the new VM_FLAGS_RETURN_DATA_ADDR flags.
		 */
		offset_in_mapping = 0;
		initial_size = memory_size;
	}

	if (vmk_flags.vmf_resilient_media) {
		/* must be copy-on-write to be "media resilient" */
		if (!copy) {
			vmlp_api_end(VM_MAP_REMAP, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}
	}

	vmk_flags.vmkf_copy_same_map = (src_map == target_map);
#if HAS_MTE
	vmk_flags.vmkf_copy_dest = vm_kernel_map_is_kernel(target_map) ? VM_COPY_DESTINATION_KERNEL : VM_COPY_DESTINATION_USER;
#endif

	assert(memory_size != 0);
	result = vm_map_copy_extract(src_map,
	    memory_address,
	    memory_size,
	    copy, &copy_map,
	    &cur_protection, /* IN/OUT */
	    &max_protection, /* IN/OUT */
	    inheritance,
	    vmk_flags);
	if (result != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_REMAP, result);
		return result;
	}
	assert(copy_map != VM_MAP_COPY_NULL);

	/*
	 * Handle the policy for vm map ranges
	 *
	 * If the maps differ, the target_map policy applies like for vm_map()
	 * For same mapping remaps, we preserve the range.
	 */
	if (vmk_flags.vmkf_copy_same_map) {
		vmk_flags.vmkf_range_id = copy_map->orig_range;
	} else {
		vm_map_kernel_flags_update_range_id(&vmk_flags, target_map, memory_size);
	}

	target_size = memory_size;
	if (src_page_mask != target_page_mask) {
		vm_map_copy_t   target_copy_map;
		vm_map_offset_t overmap_start = 0;
		vm_map_offset_t overmap_end   = 0;
		vm_map_offset_t trimmed_start = 0;

		target_copy_map = copy_map; /* can modify "copy_map" itself */
		DEBUG4K_ADJUST("adjusting...\n");
		result = vm_map_copy_adjust_to_target(
			copy_map,
			offset_in_mapping, /* offset */
			initial_size,
			target_map,
			copy,
			&target_copy_map,
			&overmap_start,
			&overmap_end,
			&trimmed_start);
		if (result != KERN_SUCCESS) {
			DEBUG4K_COPY("failed to adjust 0x%x\n", result);
			vm_map_copy_discard(copy_map);
			vmlp_api_end(VM_MAP_REMAP, result);
			return result;
		}
		if (trimmed_start == 0) {
			/* nothing trimmed: no adjustment needed */
		} else if (trimmed_start >= offset_in_mapping) {
			/* trimmed more than offset_in_mapping: nothing left */
			assert(overmap_start == 0);
			assert(overmap_end == 0);
			offset_in_mapping = 0;
		} else {
			/* trimmed some of offset_in_mapping: adjust */
			assert(overmap_start == 0);
			assert(overmap_end == 0);
			offset_in_mapping -= trimmed_start;
		}
		offset_in_mapping += overmap_start;
		target_size = target_copy_map->size;
	}

	/*
	 * Allocate/check a range of free virtual address
	 * space for the target
	 */
	target_size = vm_map_round_page(target_size, target_page_mask);

	if (target_size == 0) {
		vm_map_copy_discard(copy_map);
		vmlp_api_end(VM_MAP_REMAP, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	if (__improbable(!vm_map_is_map_size_valid(
		    target_map, target_size, vmk_flags.vmkf_no_soft_limit))) {
		vm_map_copy_discard(copy_map);
		vmlp_api_end(VM_MAP_REMAP, KERN_NO_SPACE);
		return KERN_NO_SPACE;
	}

	vm_map_ilk_lock(target_map);

	if (vmk_flags.vmf_fixed) {
		/*
		 * vm_map_locate_space_fixed will reject overflowing
		 * target_addr + target_size values
		 */
		result = vm_map_locate_space_fixed(target_map, target_addr,
		    target_size, mask, vmk_flags, &rsv, &zap_list);
	} else {
		result = vm_map_locate_space_anywhere(target_map, target_addr,
		    target_size, mask, vmk_flags, &rsv);
	}

	if (result == KERN_SUCCESS) {
		while (vm_map_copy_first_entry(copy_map) != vm_map_copy_to_entry(copy_map)) {
			vm_map_entry_t entry = vm_map_copy_first_entry(copy_map);

			vm_map_copy_store_remove(copy_map, entry);

			if (vmk_flags.vmkf_remap_prot_copy) {
				/*
				 * This vm_map_remap() is for a
				 * vm_protect(VM_PROT_COPY), so the caller
				 * expects to be allowed to add write access
				 * to this new mapping.  This is done by
				 * adding VM_PROT_WRITE to each entry's
				 * max_protection... unless some security
				 * settings disallow it.
				 */
				bool allow_write = false;
				if (entry->vme_permanent) {
					/* immutable mapping... */
					if ((entry->max_protection & VM_PROT_EXECUTE) &&
					    developer_mode_state()) {
						/*
						 * ... but executable and
						 * possibly being debugged,
						 * so let's allow it to become
						 * writable, for breakpoints
						 * and dtrace probes, for
						 * example.
						 */
						allow_write = true;
					} else {
						printf("%d[%s] vm_remap(0x%llx,0x%llx) VM_PROT_COPY denied on permanent mapping prot 0x%x/0x%x developer %d\n",
						    proc_selfpid(),
						    (get_bsdtask_info(current_task())
						    ? proc_name_address(get_bsdtask_info(current_task()))
						    : "?"),
						    (uint64_t)memory_address,
						    (uint64_t)memory_size,
						    entry->protection,
						    entry->max_protection,
						    developer_mode_state());
						DTRACE_VM6(vm_map_delete_permanent_deny_protcopy,
						    vm_map_entry_t, entry,
						    vm_map_offset_t, entry->vme_start,
						    vm_map_offset_t, entry->vme_end,
						    vm_prot_t, entry->protection,
						    vm_prot_t, entry->max_protection,
						    int, VME_ALIAS(entry));
					}
				} else {
					allow_write = true;
				}

				/*
				 * VM_PROT_COPY: allow this mapping to become
				 * writable, unless it was "permanent".
				 */
				if (allow_write) {
					entry->max_protection |= VM_PROT_WRITE;
				}
			}
			if (vmk_flags.vmf_resilient_codesign) {
				/* no codesigning -> read-only access */
				entry->max_protection = VM_PROT_READ;
				entry->protection = VM_PROT_READ;
				entry->vme_resilient_codesign = TRUE;
			}
			entry->vme_start += vmsr_start(rsv); /* the copy starts at address 0 */
			entry->vme_end += vmsr_start(rsv);
			if (vmk_flags.vmf_resilient_media &&
			    !entry->is_sub_map &&
			    (VME_OBJECT(entry) == VM_OBJECT_NULL ||
			    VME_OBJECT(entry)->internal)) {
				entry->vme_resilient_media = TRUE;
			}
#if HAS_MTE
			if (VME_OBJECT(entry) && vm_object_is_mte_mappable(VME_OBJECT(entry))) {
				vm_map_mark_has_sec_access_ilocked(target_map);
			}
#endif /* HAS_MTE */
			vm_map_copy_entry_convert(copy_map, target_map, entry);
			vm_map_store_insert(target_map, entry, rsv, vmk_flags);
			vm_entry_unlock_exclusive(target_map, entry);
		}
	}

	if (vmk_flags.vmf_resilient_codesign) {
		cur_protection = VM_PROT_READ;
		max_protection = VM_PROT_READ;
	}

	vm_map_ilk_unlock(target_map);

	vm_map_zap_dispose(target_map, &zap_list); /* if when result is not KERN_SUCCESS we could have added something */

	if (result == KERN_SUCCESS) {
#if KASAN
		if (target_map->pmap == kernel_pmap) {
			kasan_notify_address(vmsr_start(rsv), target_size);
		}
#endif
		/*
		 * If requested, return the address of the data pointed to by the
		 * request, rather than the base of the resulting page.
		 *
		 * Update OUT parameters.
		 */
		if (vmk_flags.vmf_return_data_addr) {
			*address_u = vm_sanitize_wrap_addr(vmsr_start(rsv) +
			    offset_in_mapping);
		} else {
			*address_u = vm_sanitize_wrap_addr(vmsr_start(rsv));
		}

		*cur_protection_u = vm_sanitize_wrap_prot(cur_protection);
		*max_protection_u = vm_sanitize_wrap_prot(max_protection);
	}

	if (src_page_mask != target_page_mask) {
		DEBUG4K_SHARE("vm_remap(%p 0x%llx 0x%llx copy=%d-> %p 0x%llx 0x%llx  result=0x%x\n",
		    src_map, (uint64_t)memory_address, (uint64_t)target_size, copy,
		    target_map, (uint64_t)vmsr_start(rsv), (uint64_t)offset_in_mapping, result);
	}
	vm_map_copy_discard(copy_map);
	copy_map = VM_MAP_COPY_NULL;

	vmlp_api_end(VM_MAP_REMAP, result);
	return result;
}

static inline kern_return_t
vm_map_reallocate_sanitize(
	vm_map_t                map,
	vm_map_address_ut       src_u,          /* IN */
	vm_map_size_ut          src_size_u,     /* IN */
	vm_map_address_ut      *dst_inout_u,    /* IN */
	vm_map_size_ut          dst_size_u,     /* IN */
	vm_map_offset_ut        align_mask_u,   /* IN */
	int                     options,        /* IN */
	int                     flags,          /* IN */
	vm_map_address_t       *src,            /* OUT */
	vm_map_size_t          *src_size,       /* OUT */
	vm_map_address_t       *dst_inout,      /* OUT */
	vm_map_size_t          *dst_size,       /* OUT */
	vm_map_offset_t        *align_mask)     /* OUT */
{
	kern_return_t   kr;
	vm_map_offset_t end_ignore;

	/*
	 * ANYWHERE, FIXED, and OVERWRITE are the only valid flags.
	 */
	if (__improbable(flags & ~(VM_FLAGS_ANYWHERE | VM_FLAGS_OVERWRITE | VM_FLAGS_ALIAS_MASK))) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = vm_sanitize_mask(align_mask_u, VM_SANITIZE_CALLER_VM_MAP_REALLOCATE, align_mask);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	/*
	 * DEFAULT and ZERO_FILL_SOURCE are the only valid options.
	 */
	if (__improbable(options & ~(VM_REALLOCATE_DEALLOCATE_SOURCE | VM_REALLOCATE_ZERO_FILL_SOURCE))) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Destination doesn't need to be aligned for VM_FLAGS_ANYWHERE.
	 */
	kr = vm_sanitize_addr_size(*dst_inout_u,
	    dst_size_u,
	    VM_SANITIZE_CALLER_VM_MAP_REALLOCATE,
	    map,
	    VM_SANITIZE_FLAGS_CHECK_ALIGNED_SIZE |
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS |
	    (flags & VM_FLAGS_ANYWHERE ? 0 : VM_SANITIZE_FLAGS_CHECK_ALIGNED_START),
	    dst_inout,
	    &end_ignore,
	    dst_size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}
	if (__improbable(!(flags & VM_FLAGS_ANYWHERE) && *dst_inout & *align_mask)) {
		return KERN_INVALID_ADDRESS;
	}

	return vm_sanitize_addr_size(src_u, src_size_u,
	           VM_SANITIZE_CALLER_VM_MAP_REALLOCATE, map,
	           VM_SANITIZE_FLAGS_CHECK_ALIGNED_START |
	           VM_SANITIZE_FLAGS_CHECK_ALIGNED_SIZE |
	           VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS,
	           src, &end_ignore, src_size);
}

/*
 *	Routine:	vm_map_reallocate
 *
 *			Stub called by vm_reallocate to reallocate a virtual range into a
 *          (possibly new) range of equal or greater size.
 *
 */
kern_return_t
vm_map_reallocate(
	vm_map_t            map,
	vm_map_address_ut   src_u,
	vm_map_size_ut      src_size_u,
	vm_map_address_ut  *dst_inout_u,
	vm_map_size_ut      dst_size_u,
	vm_map_offset_ut    align_mask_u,
	int                 options,
	int                 flags)
{
	vm_map_address_t        src, dst_inout;
	vm_map_size_t           src_size, dst_size;
	vm_map_offset_t         align_mask;
	vm_map_kernel_flags_t   vmk_flags;
	kern_return_t           kr;

	KDBG(VMDBG_CODE(DBG_VM_REALLOCATE_CALL) | DBG_FUNC_START);
	kr = vm_map_reallocate_sanitize(map,
	    src_u,
	    src_size_u,
	    dst_inout_u,
	    dst_size_u,
	    align_mask_u,
	    options,
	    flags,
	    &src,
	    &src_size,
	    &dst_inout,
	    &dst_size,
	    &align_mask);
	if (__improbable(kr != KERN_SUCCESS)) {
		KDBG(VMDBG_CODE(DBG_VM_REALLOCATE_CALL) | DBG_FUNC_END, 0);
		*dst_inout_u = vm_sanitize_wrap_addr(0);
		return vm_sanitize_get_kr(kr);
	}

	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vm_map_kernel_flags_set_vmflags(&vmk_flags, flags);
	kr = vm_map_relocate(
		map,
		src,
		src_size,
		&dst_inout,
		dst_size,
		align_mask,
		options,
		vmk_flags);
	if (kr != KERN_SUCCESS) {
		dst_inout = 0;
	}
	*dst_inout_u = vm_sanitize_wrap_addr(dst_inout);
	KDBG(VMDBG_CODE(DBG_VM_REALLOCATE_CALL) | DBG_FUNC_END, 1);

	return kr;
}

static kern_return_t
vm_map_relocate_preflight(vm_map_t map, vm_map_entry_t entry)
{
	if (entry == vm_map_to_entry(map)
#if HAS_MTE
	    || (VME_OBJECT(entry) && vm_object_is_mte_mappable(VME_OBJECT(entry)))
#endif /* HAS_MTE */
	    || entry->is_sub_map
	    || entry->vme_permanent
#if __arm64e__
	    || entry->used_for_tpro
#endif /* __arm64e__ */
	    || entry->used_for_jit) {
		return KERN_INVALID_ADDRESS;
	}

	return KERN_SUCCESS;
}

/*
 *  Routine:	vm_map_relocate
 *
 *			Implements vm_map_reallocate. Relocates entries from given source
 *          range into a destination range.
 *
 *			The destination is treated as a hint unless FIXED is specified
 *          (allowably in conjunction with OVERWRITE). Reallocation will fail if
 *          the destination is already occupied and FIXED is specified.
 *
 *          Reallocation is atomic; both the source and destination are secured
 *          before the source mapping is modified, thus if reallocation fails
 *          the map will not have been modified.
 *
 */
kern_return_t
vm_map_relocate(
	vm_map_t                map,
	vm_map_address_t        src,
	vm_map_size_t           src_size,
	vm_map_address_t       *dst_inout,
	vm_map_size_t           dst_size,
	vm_map_offset_t         align_mask,
	int                     options,
	vm_map_kernel_flags_t   vmk_flags)
{
	kern_return_t    kr;
	vm_map_address_t end_of_src = src + src_size;
	vm_map_offset_t  dst_mask = align_mask | vm_map_page_mask(map); /* Guarantee page-aligned. */
	bool             src_aligned = !(src & dst_mask);
	bool             zero_fill = options & VM_REALLOCATE_ZERO_FILL_SOURCE;

	if (vm_kernel_map_is_kernel(map)) {
		/*
		 * Reallocation within the kernel will be disallowed until a case is
		 * made for why it should be allowed. As of yet there are no kernel
		 * adopters, and so this path should never be reached.
		 */
		panic("%s: tried to relocate entries in the kernel map (map = %p)", __func__, map);
	} else if (VM_MAP_PAGE_SIZE(map) != PAGE_SIZE) {
		/* Disallow reallocation with non-native page size. */
		return KERN_NOT_SUPPORTED;
	} else if (dst_size < src_size) {
		/* Shrinking must be handled by the allocator. */
		return KERN_INVALID_ARGUMENT;
	} else if (vmk_flags.vmf_fixed && vmk_flags.vmf_overwrite) {
		vm_map_address_t end_of_dst = *dst_inout + dst_size;
		bool dst_overlaps_src = end_of_dst > src && end_of_src > *dst_inout;
		if (dst_overlaps_src) {
			/* The destination must not overwrite the source. */
			return KERN_INVALID_ADDRESS;
		}
	} else if (dst_size == src_size && src_aligned && !vmk_flags.vmf_fixed) {
		/* The source already satisfied the request; this is a no-op. */
		*dst_inout = src;
		return KERN_SUCCESS;
	}

	/*
	 * Due to lock ordering constraints, a fixed overwrite of a destination
	 * starting /before/ the source must occur prior to locking the source, and
	 * visa versa when the destination is /after/ the source.
	 */
	bool overwrite_dst_first = *dst_inout < src &&
	    vmk_flags.vmf_fixed &&
	    vmk_flags.vmf_overwrite;

	vm_map_t dst_map = map;
	VM_MAP_LOCK_CTX_DECLARE(dst_ctx);
	vm_map_kernel_flags_t dst_flags = vmk_flags;
	dst_flags.vmkf_keep_entries_locked = TRUE;

	if (overwrite_dst_first) {
		kr = vm_map_enter(
			map,
			dst_inout,
			dst_size,
			dst_mask,
			dst_flags,
			VM_OBJECT_NULL, /* If we abort later, destination will be zero-filled. */
			0,
			FALSE,
			VM_PROT_NONE,
			VM_PROT_NONE,
			VM_INHERIT_NONE);
		if (kr != KERN_SUCCESS) {
			return kr == KERN_NO_SPACE ? KERN_NO_SPACE : KERN_NOT_SUPPORTED;
		}

		kr = vm_map_lock_ctx_from_locked_entries(dst_ctx, &dst_map, *dst_inout, dst_size);
		assert(kr == KERN_SUCCESS);
	}

	/*
	 * Acquire exclusive atomic range lock on the source and bail out if any
	 * entries should not be relocatable. We intentionally do not allow holes.
	 */
	VM_MAP_LOCK_CTX_DECLARE(src_ctx);
	vm_map_lock_ctx_set_preflight(src_ctx, ^kern_return_t (vm_map_lock_ctx_t vctx, vm_map_entry_t entry) {
		return vm_map_relocate_preflight(vm_map_lock_ctx_get_map(vctx), entry);
	});

	vm_map_t src_map = map;
	kr = vm_map_range_ex_lock(src_ctx, &src_map, src, src + src_size, VMRL_EX_ATOMIC);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/*
	 * Try to expand the allocation in-place if the source is already aligned.
	 */
	vm_map_entry_t  first_entry = vm_map_range_atomic_next(src_ctx);
	vm_map_range_atomic_reset(src_ctx);
	vm_prot_t       cur_protection  = first_entry->protection;
	vm_prot_t       max_protection  = first_entry->max_protection;
	vm_inherit_t    inheritance     = first_entry->inheritance;
	if (!vmk_flags.vmf_fixed && src_aligned) {
		KDBG(VMDBG_CODE(DBG_VM_RELOCATE_TRY_IN_PLACE));
		kr = vm_map_enter(
			map,
			&end_of_src,
			dst_size - src_size,
			vm_map_page_mask(map),
			VM_MAP_KERNEL_FLAGS_FIXED(.vm_tag = vmk_flags.vm_tag),
			VM_OBJECT_NULL,
			0,
			FALSE,
			cur_protection,
			max_protection,
			inheritance);
		if (kr == KERN_SUCCESS) {
			vm_map_range_ex_unlock(src_ctx, &src_map);
			*dst_inout = src;
			KDBG(VMDBG_CODE(DBG_VM_RELOCATE_SUCCESS_IN_PLACE));
			return KERN_SUCCESS;
		}
		/* vm_map_enter will NULL the address it was given on failure. */
		end_of_src = src + src_size;
	}

	/*
	 * We didn't overwrite the destination before locking the source, so we need
	 * to reserve the destination range, and put it into a lock context.
	 */
	if (!overwrite_dst_first) {
		kr = vm_map_enter(
			map,
			dst_inout,
			dst_size,
			dst_mask,
			dst_flags,
			VM_OBJECT_NULL,
			0,
			FALSE,
			VM_PROT_NONE,
			VM_PROT_NONE,
			VM_INHERIT_NONE);
		if (kr != KERN_SUCCESS) {
			vm_map_range_ex_unlock(src_ctx, &src_map);
			return kr == KERN_NO_SPACE ? KERN_NO_SPACE : KERN_NOT_SUPPORTED;
		}

		kr = vm_map_lock_ctx_from_locked_entries(dst_ctx, &dst_map, *dst_inout, dst_size);
		assert(kr == KERN_SUCCESS);
	}

	/*
	 * We've guaranteed there will be space to relocate the source to after it
	 * has been unmapped, so it is safe to unmap the source and potentially
	 * allow another mapping to be created in its place before we've returned.
	 * The source entries are placed into a zap list until later re-linked.
	 */
	VM_MAP_ZAP_DECLARE(zap);
	vm_map_ilk_lock(map);
	vmr_flags_t vmr_flags = VM_MAP_REMOVE_RANGE_LOCKED |
	    (zero_fill ? VM_MAP_REMOVE_ZERO_FILL : 0);
	kr = vm_map_delete_and_iunlock_with_range_locked(
		map,
		src,
		end_of_src,
		vmr_flags,
		KMEM_GUARD_NONE,
		NULL,
		&zap,
		src_ctx);
	if (kr != KERN_SUCCESS) {
		panic("%s failed to delete source; it must have changed after it was locked (kr = %d)", __func__, kr);
	}

	/*
	 * Remove range which will be occupied by source from the range lock's view.
	 */
	vm_map_entry_t entry = VM_MAP_ENTRY_NULL;
	vm_map_entry_t prev_entry = VM_MAP_ENTRY_NULL;
	vm_map_offset_t end_of_relocated_src = *dst_inout + src_size;

	/*
	 * Lock ordering prevents us from always inspecting the source before
	 * mapping the destination. The protection and inheritance traits must now
	 * be transferred while the context can still be iterated.
	 */
	while ((entry = vm_map_range_atomic_next(dst_ctx))) {
		entry->protection     = cur_protection;
		entry->max_protection = max_protection;
		entry->inheritance    = inheritance;
	}
	vm_map_range_atomic_reset(dst_ctx);

	while ((entry = vm_map_range_atomic_peek(dst_ctx)) != VM_MAP_ENTRY_NULL) {
		if (entry->vme_start >= end_of_relocated_src) {
			break;
		} else if (entry->vme_end > end_of_relocated_src) {
			/*
			 * Clip entry straddling the end of the relocated source range.
			 */
			vm_map_range_lock_clip_end(dst_ctx, entry, end_of_relocated_src);
		} else {
			/*
			 * Pop entries that will be replaced by the relocated source range.
			 */
			entry = vm_map_range_ex_atomic_pop(dst_ctx);
			prev_entry = entry;
		}
	}

	/*
	 * Delete entries occupying the range into which source will be relocated.
	 */
	vm_map_ilk_lock(map);
	entry = prev_entry;
	while (entry->vme_start >= *dst_inout) {
		prev_entry = VME_PREV(entry);
		vm_map_store_remove(map, entry, VMS_REMOVE_FREE_ENTRY);
		entry = prev_entry;
	}

	/*
	 * Relocate source entries into the hole we just made.
	 */
	vm_map_offset_t delta = *dst_inout - src;
	while ((entry = vm_map_zap_pop(&zap))) {
		/*
		 * This arithmetic is safe because we already guaranteed the destination
		 * range is valid and unmapped via the call to vm_map_locate_space_*.
		 */
		entry->vme_start += delta;
		entry->vme_end += delta;

		VME_ALIAS_SET(entry, vmk_flags.vm_tag);
		vm_map_store_insert(map, entry);
		vm_entry_unlock_exclusive(map, entry); /* vm_map_delete_and_iunlock puts exclusive-locked entries into zap. */
		prev_entry = entry;
	}
	vm_map_ilk_unlock(map);
	vm_map_range_ex_unlock(dst_ctx, &dst_map);

	KDBG(VMDBG_CODE(DBG_VM_RELOCATE_SUCCESS_OUT_OF_PLACE));

	return KERN_SUCCESS;
}

/*
 *	vm_map_switch_with_sec_override:
 *
 *	Set the address map for the current thread to the specified map.
 *  Optionally sets the `sec_override` property on the current thread for
 *  the duration of the switch.
 *  Returns a struct containing info about the previous map, which should be
 *  restored with `vm_map_switch_back`
 */

vm_map_switch_context_t
vm_map_switch_with_sec_override(vm_map_t map, boolean_t sec_override)
{
	thread_t thread = current_thread();
	vm_map_t oldmap = thread->map;

	/*
	 * Deactivate the current map and activate the requested map
	 */
	mp_disable_preemption();
#if HAS_MTE
	if (sec_override) {
		ml_thread_set_sec_override(thread, true);
	}
#endif
	PMAP_SWITCH_USER(thread, map, cpu_number());
	mp_enable_preemption();

	vm_map_ilk_lock(map);
	task_t task = map->owning_task;
	if (task) {
		task_reference(task);
	}
	vm_map_ilk_unlock(map);

	return (vm_map_switch_context_t) { oldmap, task, sec_override };
}

void
vm_map_switch_back(vm_map_switch_context_t ctx)
{
	thread_t thread = current_thread();
	task_t task = ctx.task;
	vm_map_t map = ctx.map;

	if (task) {
		uint64_t code;

		/*
		 * While the map was switched, we may have incurred an asynchronous tag
		 * check fault; we now need to kill the owner of the switched-to map.
		 *
		 * This can race; another thread could have already sent the ASTs. In
		 * this case, we spuriously set the ASTs again and in the worst case
		 * cause an extra AST check which will be ignored.
		 */
		code = os_atomic_load(&thread->map->async_fault.code, relaxed);
		if (code && code != VM_ASYNC_TAG_FAULT_ALREADY_REPORTED) {
			task_set_ast_synthesize_async_fault_mach_exception(task);
		}
		task_deallocate(task);
	} else {
		/*
		 * We want to make sure that vm_map_setup was not called while the
		 * map was switched. This allows us to guarantee the property that
		 * we always have a reference on current_map()->owning_task if it is
		 * not NULL.
		 */
		assert(!thread->map->owning_task);
	}

	/*
	 * Restore the original map from prior to vm_map_switch_to
	 */
	mp_disable_preemption();
#if HAS_MTE
	if (ctx.sec_overridden) {
		ml_thread_set_sec_override(thread, false);
	}
#endif
	PMAP_SWITCH_USER(thread, map, cpu_number());
	mp_enable_preemption();
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_rw_user_sanitize(
	vm_map_t                map,
	vm_map_address_ut       addr_u,
	vm_size_ut              size_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_address_t       *addr,
	vm_map_address_t       *end,
	vm_map_size_t          *size)
{
	vm_sanitize_flags_t flags = VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH |
	    VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES |
	    VM_SANITIZE_FLAGS_CHECK_ADDR_RANGE;

	return vm_sanitize_addr_size(addr_u, size_u,
	           vm_sanitize_caller, map,
	           flags,
	           addr, end, size);
}

/*
 *	Routine:	vm_map_write_user
 *
 *	Description:
 *		Copy out data from a kernel space into space in the
 *		destination map. The space must already exist in the
 *		destination map.
 *		NOTE:  This routine should only be called by threads
 *		which can block on a page fault. i.e. kernel mode user
 *		threads.
 *
 */
kern_return_t
vm_map_write_user(
	vm_map_t                map,
	void                   *src_p,
	vm_map_address_ut       dst_addr_u,
	vm_size_ut              size_u)
{
	kern_return_t    kr;
	vm_map_address_t dst_addr, dst_end;
	vm_map_size_t    size;

	/*
	 * src_p isn't validated: [src_p, src_p + size_u)
	 * is trusted kernel input.
	 *
	 * dst_addr_u and size_u are untrusted and need to be sanitized.
	 */
	kr = vm_map_rw_user_sanitize(map,
	    dst_addr_u,
	    size_u,
	    VM_SANITIZE_CALLER_VM_MAP_WRITE_USER,
	    &dst_addr,
	    &dst_end,
	    &size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	if (current_map() == map) {
		if (copyout(src_p, dst_addr, size)) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_switch_context_t switch_ctx;

		/* take on the identity of the target map while doing */
		/* the transfer */

		vm_map_reference(map);
		switch_ctx = vm_map_switch_to(map);
		if (copyout(src_p, dst_addr, size)) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch_back(switch_ctx);
		vm_map_deallocate(map);
	}
	return kr;
}

/*
 *	Routine:	vm_map_read_user
 *
 *	Description:
 *		Copy in data from a user space source map into the
 *		kernel map. The space must already exist in the
 *		kernel map.
 *		NOTE:  This routine should only be called by threads
 *		which can block on a page fault. i.e. kernel mode user
 *		threads.
 *
 */
kern_return_t
vm_map_read_user(
	vm_map_t                map,
	vm_map_address_ut       src_addr_u,
	void                   *dst_p,
	vm_size_ut              size_u)
{
	kern_return_t    kr;
	vm_map_address_t src_addr, src_end;
	vm_map_size_t    size;

	/*
	 * dst_p isn't validated: [dst_p, dst_p + size_u)
	 * is trusted kernel input.
	 *
	 * src_addr_u and size_u are untrusted and need to be sanitized.
	 */
	kr = vm_map_rw_user_sanitize(map,
	    src_addr_u,
	    size_u,
	    VM_SANITIZE_CALLER_VM_MAP_READ_USER,
	    &src_addr,
	    &src_end,
	    &size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	if (current_map() == map) {
		if (copyin(src_addr, dst_p, size)) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_switch_context_t switch_ctx;

		/* take on the identity of the target map while doing */
		/* the transfer */

		vm_map_reference(map);
		switch_ctx = vm_map_switch_to(map);
		if (copyin(src_addr, dst_p, size)) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch_back(switch_ctx);
		vm_map_deallocate(map);
	}
	return kr;
}


static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_check_protection_sanitize(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              protection_u,
	vm_sanitize_caller_t    vm_sanitize_caller,
	vm_map_offset_t        *start,
	vm_map_offset_t        *end,
	vm_prot_t              *protection)
{
	kern_return_t           kr;
	vm_map_size_t           size;

	kr = vm_sanitize_addr_end(start_u, end_u, vm_sanitize_caller, map,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH, start, end,
	    &size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	/*
	 * Given that the protection is used only for comparisons below
	 * no sanitization is being applied on it.
	 */
	*protection = VM_SANITIZE_UNSAFE_UNWRAP(protection_u);

	return KERN_SUCCESS;
}

/*
 *	vm_map_check_protection:
 *
 *	Assert that the target map allows the specified
 *	privilege on the entire address region given.
 *	The entire region must be allocated.
 */
boolean_t
vm_map_check_protection(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              protection_u,
	vm_sanitize_caller_t    vm_sanitize_caller)
{
	vm_map_entry_t entry;
	vm_map_offset_t start;
	vm_map_offset_t end;
	vm_prot_t protection;
	kern_return_t kr;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_CHECK_PROTECTION);

	kr = vm_map_check_protection_sanitize(map,
	    start_u,
	    end_u,
	    protection_u,
	    vm_sanitize_caller,
	    &start,
	    &end,
	    &protection);
	if (__improbable(kr != KERN_SUCCESS)) {
		kr = vm_sanitize_get_kr(kr);
		if (kr == KERN_SUCCESS) {
			vmlp_api_end(VM_MAP_CHECK_PROTECTION, 0);
			return true;
		}
		vmlp_api_end(VM_MAP_CHECK_PROTECTION, -1);
		return false;
	}

	kr = vm_map_range_sh_lock(ctx, &map, start, end, VMRL_SH_ATOMIC);
	if (kr != KERN_SUCCESS) {
		/* size=0 with an entry at the addr should still return true */
		if (end - start == 0) {
			/*
			 * Our lock ctx will automatically
			 * descend into transparent submaps here.
			 */
			VM_MAP_FIND_LOCK_CTX_DECLARE(find_ctx);
			kr = vm_map_find_entry_sh_locked(find_ctx, &map,
			    start, VMRL_FIND_SH_DEFAULT);
			if (kr != KERN_SUCCESS) {
				/* no entry -> false */
				vmlp_api_end(VM_MAP_CHECK_PROTECTION, -1);
				return false;
			}
			/* some entry -> true */
			vm_map_found_entry_sh_unlock(find_ctx, &map);
			vmlp_api_end(VM_MAP_CHECK_PROTECTION, 0);
			return true;
		}

		vmlp_api_end(VM_MAP_CHECK_PROTECTION, -1);
		return false;
	}

	while ((entry = vm_map_range_atomic_next(ctx))) {
		/*
		 * Check protection associated with entry.
		 */
		if ((entry->protection & protection) != protection) {
			vm_map_range_sh_unlock(ctx, &map);
			vmlp_api_end(VM_MAP_CHECK_PROTECTION, -1);
			return false;
		}
	}
	vm_map_range_sh_unlock(ctx, &map);
	vmlp_api_end(VM_MAP_CHECK_PROTECTION, 0);
	return true;
}

kern_return_t
vm_map_purgable_control(
	vm_map_t                map,
	vm_map_offset_ut        address_u,
	vm_purgable_t           control,
	int                    *state)
{
	vm_map_offset_t         address;
	vm_map_entry_t          entry;
	vm_object_t             object;
	kern_return_t           kr;
	boolean_t               was_nonvolatile;
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_PURGABLE_CONTROL);

	/*
	 * Vet all the input parameters and current type and state of the
	 * underlaying object.  Return with an error if anything is amiss.
	 */
	if (map == VM_MAP_NULL) {
		vmlp_api_end(VM_MAP_PURGABLE_CONTROL, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	if (control != VM_PURGABLE_SET_STATE &&
	    control != VM_PURGABLE_GET_STATE &&
	    control != VM_PURGABLE_PURGE_ALL &&
	    control != VM_PURGABLE_SET_STATE_FROM_KERNEL) {
		vmlp_api_end(VM_MAP_PURGABLE_CONTROL, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	if (control == VM_PURGABLE_PURGE_ALL) {
		vm_purgeable_object_purge_all();
		vmlp_api_end(VM_MAP_PURGABLE_CONTROL, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	if ((control == VM_PURGABLE_SET_STATE ||
	    control == VM_PURGABLE_SET_STATE_FROM_KERNEL) &&
	    (((*state & ~(VM_PURGABLE_ALL_MASKS)) != 0) ||
	    ((*state & VM_PURGABLE_STATE_MASK) > VM_PURGABLE_STATE_MASK))) {
		vmlp_api_end(VM_MAP_PURGABLE_CONTROL, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	address = vm_sanitize_addr(map, address_u);

	/*
	 * NO_MIN_MAX_CHECK for ABI compatibility, as this function didn't used to reject
	 * addr > vm_map_max()
	 */
	kr = vm_map_find_entry_sh_locked(ctx, &map, address, VMRL_FIND_SH_NO_MIN_MAX_CHECK);
	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_PURGABLE_CONTROL, kr);
		return kr;
	}

	entry = vm_map_found_entry_get_entry(ctx);

	if (entry->is_sub_map) {
		/*
		 * Must pass a non-submap address.
		 */
		vm_map_found_entry_sh_unlock(ctx, &map);
		vmlp_api_end(VM_MAP_PURGABLE_CONTROL, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}

	if ((entry->protection & VM_PROT_WRITE) == 0 &&
	    control != VM_PURGABLE_GET_STATE) {
		/*
		 * Can't apply purgable controls to something you can't write.
		 */
		vm_map_found_entry_sh_unlock(ctx, &map);
		vmlp_api_end(VM_MAP_PURGABLE_CONTROL, KERN_PROTECTION_FAILURE);
		return KERN_PROTECTION_FAILURE;
	}

	object = VME_OBJECT(entry);
	if (object == VM_OBJECT_NULL || object->purgable == VM_PURGABLE_DENY) {
		/*
		 * Object must already be present and be purgeable.
		 */
		vm_map_found_entry_sh_unlock(ctx, &map);
		vmlp_api_end(VM_MAP_PURGABLE_CONTROL, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	vm_object_lock(object);

#if 00
	if (VME_OFFSET(entry) != 0 ||
	    entry->vme_end - entry->vme_start != object->vo_size) {
		/*
		 * Can only apply purgable controls to the whole (existing)
		 * object at once.
		 */
		vm_map_found_entry_sh_unlock(ctx, &map);
		vm_object_unlock(object);
		return KERN_INVALID_ARGUMENT;
	}
#endif

	assert(!entry->is_sub_map);
	assert(!entry->use_pmap); /* purgeable has its own accounting */

	vm_map_found_entry_sh_unlock(ctx, &map);

	was_nonvolatile = (object->purgable == VM_PURGABLE_NONVOLATILE);

	kr = vm_object_purgable_control(object, control, state);

	if (was_nonvolatile &&
	    object->purgable != VM_PURGABLE_NONVOLATILE &&
	    map->pmap == kernel_pmap) {
#if DEBUG
		object->vo_purgeable_volatilizer = kernel_task;
#endif /* DEBUG */
	}

	vm_object_unlock(object);

	vmlp_api_end(VM_MAP_PURGABLE_CONTROL, kr);
	return kr;
}

/*
 * The entry lock should be held in shared mode.
 * No interlock is needed, because only const properties of the map are queried.
 */
void
vm_map_footprint_query_page_info(
	vm_map_t        map,
	vm_map_entry_t  map_entry,
	vm_map_offset_t curr_s_offset,
	int             *disposition_p)
{
	int             pmap_disp;
	vm_object_t     object = VM_OBJECT_NULL;
	int             disposition;
	int             effective_page_size;

	assert(!map->has_corpse_footprint); /* const property, no lock needed */
	assert(curr_s_offset >= map_entry->vme_start);
	assert(curr_s_offset < map_entry->vme_end);

	if (map_entry->is_sub_map) {
		if (!map_entry->use_pmap) {
			/* nested pmap: no footprint */
			*disposition_p = 0;
			return;
		}
	} else {
		object = VME_OBJECT(map_entry);
		if (object == VM_OBJECT_NULL) {
			/* nothing mapped here: no need to ask */
			*disposition_p = 0;
			return;
		}
	}

	effective_page_size = MIN(PAGE_SIZE, VM_MAP_PAGE_SIZE(map));

	pmap_disp = 0;

	/*
	 * Query the pmap.
	 */
	pmap_query_page_info(map->pmap, curr_s_offset, &pmap_disp);

	/*
	 * Compute this page's disposition.
	 */
	disposition = 0;

	/* deal with "alternate accounting" first */
	if (!map_entry->is_sub_map &&
	    object->vo_no_footprint) {
		/* does not count in footprint */
//		assertf(!map_entry->use_pmap, "offset 0x%llx map_entry %p", (uint64_t) curr_s_offset, map_entry);
	} else if (!map_entry->is_sub_map &&
	    !object->internal &&
	    object->vo_ledger_tag &&
	    VM_OBJECT_OWNER(object) != NULL &&
	    VM_OBJECT_OWNER(object)->map == map) {
		/* owned external object: wired pages count in footprint */
		assertf(map_entry->use_pmap, "offset 0x%llx map_entry %p", (uint64_t) curr_s_offset, map_entry);
		if ((((curr_s_offset
		    - map_entry->vme_start
		    + VME_OFFSET(map_entry))
		    / effective_page_size) <
		    object->wired_page_count)) {
			/*
			 * External object owned by this task: report the first
			 * "#wired" pages as "resident" (to show that they
			 * contribute to the footprint) but not "dirty"
			 * (to avoid double-counting with the fake "owned"
			 * region we'll report at the end of the address space
			 * to account for all (mapped or not) owned memory
			 * owned by this task.
			 */
			disposition |= VM_PAGE_QUERY_PAGE_PRESENT;
		}
	} else if (!map_entry->is_sub_map &&
	    object->internal &&
	    (object->purgable == VM_PURGABLE_NONVOLATILE ||
	    (object->purgable == VM_PURGABLE_DENY &&
	    object->vo_ledger_tag)) &&
	    VM_OBJECT_OWNER(object) != NULL &&
	    VM_OBJECT_OWNER(object)->map == map) {
		assertf(!map_entry->use_pmap, "offset 0x%llx map_entry %p", (uint64_t) curr_s_offset, map_entry);
		if ((((curr_s_offset
		    - map_entry->vme_start
		    + VME_OFFSET(map_entry))
		    / effective_page_size) <
		    (object->resident_page_count +
		    vm_compressor_pager_get_count(object->pager)))) {
			/*
			 * Non-volatile purgeable object owned
			 * by this task: report the first
			 * "#resident + #compressed" pages as
			 * "resident" (to show that they
			 * contribute to the footprint) but not
			 * "dirty" (to avoid double-counting
			 * with the fake "non-volatile" region
			 * we'll report at the end of the
			 * address space to account for all
			 * (mapped or not) non-volatile memory
			 * owned by this task.
			 */
			disposition |= VM_PAGE_QUERY_PAGE_PRESENT;
		}
	} else if (!map_entry->is_sub_map &&
	    object->internal &&
	    (object->purgable == VM_PURGABLE_VOLATILE ||
	    object->purgable == VM_PURGABLE_EMPTY) &&
	    VM_OBJECT_OWNER(object) != NULL &&
	    VM_OBJECT_OWNER(object)->map == map) {
		if (object->internal) {
			assertf(!map_entry->use_pmap, "offset 0x%llx map_entry %p", (uint64_t) curr_s_offset, map_entry);
		}
		if ((((curr_s_offset
		    - map_entry->vme_start
		    + VME_OFFSET(map_entry))
		    / effective_page_size) <
		    object->wired_page_count)) {
			/*
			 * Volatile|empty purgeable object owned
			 * by this task: report the first
			 * "#wired" pages as "resident" (to
			 * show that they contribute to the
			 * footprint) but not "dirty" (to avoid
			 * double-counting with the fake
			 * "non-volatile" region we'll report
			 * at the end of the address space to
			 * account for all (mapped or not)
			 * non-volatile memory owned by this
			 * task.
			 */
			disposition |= VM_PAGE_QUERY_PAGE_PRESENT;
		}
	} else if (!map_entry->is_sub_map &&
	    map_entry->iokit_acct &&
	    object->internal &&
	    object->purgable == VM_PURGABLE_DENY) {
		/*
		 * Non-purgeable IOKit memory: phys_footprint
		 * includes the entire virtual mapping.
		 */
		assertf(!map_entry->use_pmap, "offset 0x%llx map_entry %p", (uint64_t) curr_s_offset, map_entry);
		disposition |= VM_PAGE_QUERY_PAGE_PRESENT;
		disposition |= VM_PAGE_QUERY_PAGE_DIRTY;
	} else if (pmap_disp & (PMAP_QUERY_PAGE_ALTACCT |
	    PMAP_QUERY_PAGE_COMPRESSED_ALTACCT)) {
		/* alternate accounting */
#if __arm64__ && (DEVELOPMENT || DEBUG)
		if (map->pmap->footprint_was_suspended) {
			/*
			 * The assertion below can fail if dyld
			 * suspended footprint accounting
			 * while doing some adjustments to
			 * this page;  the mapping would say
			 * "use pmap accounting" but the page
			 * would be marked "alternate
			 * accounting".
			 */
		} else
#endif /* __arm64__ && (DEVELOPMENT || DEBUG) */
		{
			assertf(!map_entry->use_pmap, "offset 0x%llx map_entry %p", (uint64_t) curr_s_offset, map_entry);
		}
		disposition = 0;
	} else {
		if (pmap_disp & PMAP_QUERY_PAGE_PRESENT) {
			assertf(map_entry->use_pmap, "offset 0x%llx map_entry %p", (uint64_t) curr_s_offset, map_entry);
			disposition |= VM_PAGE_QUERY_PAGE_PRESENT;
			disposition |= VM_PAGE_QUERY_PAGE_REF;
			if (pmap_disp & PMAP_QUERY_PAGE_INTERNAL) {
				disposition |= VM_PAGE_QUERY_PAGE_DIRTY;
			} else {
				disposition |= VM_PAGE_QUERY_PAGE_EXTERNAL;
			}
			if (pmap_disp & PMAP_QUERY_PAGE_REUSABLE) {
				disposition |= VM_PAGE_QUERY_PAGE_REUSABLE;
			}
		} else if (pmap_disp & PMAP_QUERY_PAGE_COMPRESSED) {
			assertf(map_entry->use_pmap, "offset 0x%llx map_entry %p", (uint64_t) curr_s_offset, map_entry);
			disposition |= VM_PAGE_QUERY_PAGE_PAGED_OUT;
		}
	}

	*disposition_p = disposition;
}

kern_return_t
vm_map_page_info(
	vm_map_t                map,
	vm_map_offset_ut        offset_u,
	vm_page_info_flavor_t   flavor,
	vm_page_info_t          info,
	mach_msg_type_number_t  *count)
{
	return vm_map_page_range_info_internal(map,
	           offset_u, /* start of range */
	           vm_sanitize_compute_ut_end(offset_u, 1), /* this will get rounded in the call to the page boundary */
	           (int)-1, /* effective_page_shift: unspecified */
	           flavor,
	           info,
	           count);
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_page_range_info_sanitize(
	vm_map_t                map,
	vm_map_offset_ut        start_offset_u,
	vm_map_offset_ut        end_offset_u,
	vm_map_offset_t         effective_page_mask,
	vm_map_offset_t        *start,
	vm_map_offset_t        *end,
	vm_map_offset_t        *offset_in_page)
{
	kern_return_t           retval;
	vm_map_size_t           size;

	/*
	 * Perform validation against map's mask but don't align start/end,
	 * as we need for those to be aligned wrt effective_page_mask
	 */
	retval = vm_sanitize_addr_end(start_offset_u, end_offset_u,
	    VM_SANITIZE_CALLER_VM_MAP_PAGE_RANGE_INFO, map,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH |
	    VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES, start,
	    end, &size);
	if (retval != KERN_SUCCESS) {
		return retval;
	}

	retval = vm_sanitize_addr_end(start_offset_u, end_offset_u,
	    VM_SANITIZE_CALLER_VM_MAP_PAGE_RANGE_INFO, effective_page_mask,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH, start,
	    end, &size);
	if (retval != KERN_SUCCESS) {
		return retval;
	}

	*offset_in_page = vm_sanitize_offset_in_page(effective_page_mask,
	    start_offset_u);

	return KERN_SUCCESS;
}

static void
vm_map_page_info_populate(
	vm_page_info_flavor_t   flavor,
	uintptr_t               info_addr,
	vm_object_id_t          object_id,
	vm_object_offset_t      offset,
	os_ref_count_t          ref_count,
	int                     depth,
	vm_page_disposition_t   disp)
{
	vm_page_info_basic_t basic_info;

	switch (flavor) {
	case VM_PAGE_INFO_BASIC:
		basic_info = (vm_page_info_basic_t)info_addr;
		basic_info->disposition = disp;
		basic_info->ref_count = ref_count;
		basic_info->depth = depth;
		basic_info->object_id = object_id;
		basic_info->offset = offset;
		break;
	}
}

/*!
 * @function vm_map_page_range_info_internal
 *
 * @abstract
 * Gather debugging information about the region [start, end] in the passed map.
 * That information is stored in the array info, which should have room for
 * ((end - start) >> effective_page_shift) vm_page_info_basic's.
 */
kern_return_t
vm_map_page_range_info_internal(
	vm_map_t                original_map,
	vm_map_offset_ut        start_offset_u,
	vm_map_offset_ut        end_offset_u,
	int                     effective_page_shift,
	vm_page_info_flavor_t   flavor,
	vm_page_info_t          orig_info,
	mach_msg_type_number_t *count)
{
	char                   *info = (char *)orig_info;
	kern_return_t           kr = KERN_SUCCESS;
	vm_map_offset_t         start = 0; /* the start of the requested range */
	vm_map_offset_t         end = 0; /* the end of the requested range */
	vm_map_offset_t         curr_s_offset = 0; /* the current address we are looking at */
	boolean_t               do_region_footprint;
	ledger_amount_t         ledger_resident = 0, ledger_compressed = 0;
	int                     effective_page_size;
	vm_map_offset_t         effective_page_mask;
	vm_map_offset_t         final_entry_end; /* end of the last entry in the map
	                                          * if a request goes to this,
	                                          * we report some information from
	                                          * the ledgers.
	                                          */
	vm_map_offset_t         offset_in_page = 0;
	vm_map_t                map = original_map;
	vm_size_t               stride;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_PAGE_RANGE_INFO_INTERNAL);

	switch (flavor) {
	case VM_PAGE_INFO_BASIC:
		if (*count != VM_PAGE_INFO_BASIC_COUNT) {
			/*
			 * The "vm_page_info_basic_data" structure was not
			 * properly padded, so allow the size to be off by
			 * one to maintain backwards binary compatibility...
			 */
			if (*count != VM_PAGE_INFO_BASIC_COUNT - 1) {
				vmlp_api_end(VM_MAP_PAGE_RANGE_INFO_INTERNAL, KERN_INVALID_ARGUMENT);
				return KERN_INVALID_ARGUMENT;
			}
		}
		stride = sizeof(vm_page_info_basic_data_t);
		break;
	default:
		vmlp_api_end(VM_MAP_PAGE_RANGE_INFO_INTERNAL, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	if (effective_page_shift == -1) {
		effective_page_shift = vm_self_region_page_shift_safely(original_map);
		if (effective_page_shift == -1) {
			vmlp_api_end(VM_MAP_PAGE_RANGE_INFO_INTERNAL, KERN_INVALID_ARGUMENT);
			return KERN_INVALID_ARGUMENT;
		}
	}
	effective_page_size = (1 << effective_page_shift);
	effective_page_mask = effective_page_size - 1;

	kr = vm_map_page_range_info_sanitize(original_map,
	    start_offset_u,
	    end_offset_u,
	    effective_page_mask,
	    &start,
	    &end,
	    &offset_in_page);
	if (kr != KERN_SUCCESS) {
		kr = vm_sanitize_get_kr(kr);
		vmlp_api_end(VM_MAP_PAGE_RANGE_INFO_INTERNAL, kr);
		return kr;
	}

	assert3u((end - start) & effective_page_mask, ==, 0);
	assert((end - start) <= MAX_PAGE_RANGE_QUERY);

	do_region_footprint = task_self_region_footprint();

	vm_map_ilk_lock(original_map);
	final_entry_end = vm_map_last_entry(original_map)->vme_end;
	vm_map_ilk_unlock(original_map);

	if (__improbable(original_map->pmap == NULL)) {
		/* Some VM tests reach this. (TODO make this more strict, rdar://148290198) */
		panic_on_release_builds("null pmap");
	} else {
		task_ledgers_footprint(original_map->pmap->ledger, &ledger_resident, &ledger_compressed);
	}

	/*
	 * This loop is responsible for implementing the bulk of the function
	 * It iterates until the end of the range (or there are no more entries),
	 * filling the info buffer with the information for the information
	 * in the range.
	 *
	 * If there is a gap after the last entry, it ends the loop and
	 * lets the end of the function handle that.
	 */
	for (curr_s_offset = start; curr_s_offset < end;) {
		vm_map_offset_t     entry_end; /* The end of the current entry */
		vm_map_offset_t     entry_start; /* the start of the current entry */
		vm_map_entry_t      entry;
		struct vm_map_entry fake;
		kern_return_t       resolve_kr;
		vm_map_offset_t     object_offs;
		int                 object_ref;
		vm_object_t         object;
		vm_page_t           m = VM_PAGE_NULL;
		int                 depth = 0;

		entry = vm_map_region_resolve_entry(ctx, &map, curr_s_offset,
		    VMRL_SH_DESCEND_INTO_CONSTANT | VMRL_SH_NO_MIN_MAX_CHECK,
		    &fake, &resolve_kr);

		if (entry == VM_MAP_ENTRY_NULL) {
			break;
		}

		vm_map_lock_ctx_bounds_in_parent(ctx,
		    &entry_start, &entry_end, NULL);
		entry_start = MAX(entry_start, start);

		/*
		 * If we have a hole between where the entry starts and where
		 * the last one ended, we need to zero-fill that area.
		 */
		if (curr_s_offset < entry_start) {
			vm_map_offset_t size = MIN(end, entry_start) - curr_s_offset;
			uint64_t        num_pages;

			num_pages = (size + effective_page_mask) >> effective_page_shift;
			bzero(info, num_pages * stride);
			info          += num_pages * stride;
			curr_s_offset += num_pages << effective_page_shift;

			if (curr_s_offset >= MIN(end, entry_end)) {
				vm_map_region_resolve_done(ctx, &map, resolve_kr);
				continue;
			}
		}

		/*
		 * If we don't have an object, there are no pages to inspect.
		 * We'll fill up the info structure appropriately.
		 */
		object    = VME_OBJECT(entry);
		entry_end = MIN(end, entry_end);
		if (object == VM_OBJECT_NULL) {
			vm_map_offset_t size = entry_end - curr_s_offset;
			uint64_t        num_pages;

			num_pages = (size + effective_page_mask) >> effective_page_shift;
			bzero(info, num_pages * stride);
			info          += num_pages * stride;
			curr_s_offset += num_pages << effective_page_shift;

			vm_map_region_resolve_done(ctx, &map, resolve_kr);
			continue;
		}

		if (do_region_footprint) {
			/*
			 * We may be in a submap, so consider the addr
			 * as it is in the context of the map we are in,
			 * not just the parent
			 */
			vm_map_address_t adjusted_addr = vm_map_lock_ctx_from_parent_address(ctx, curr_s_offset);
			int              disposition   = 0;

			if (ctx->vmlc_map->has_corpse_footprint) {
				/*
				 * Query the page info data we saved
				 * while forking the corpse.
				 */
				vm_map_corpse_footprint_query_page_info(
					ctx->vmlc_map,
					adjusted_addr,
					&disposition);
			} else {
				/*
				 * Query the live pmap for footprint info
				 * about this page.
				 */
				vm_map_footprint_query_page_info(
					ctx->vmlc_map,
					entry,
					adjusted_addr,
					&disposition);
			}

			vm_map_page_info_populate(flavor, (uintptr_t)info,
			    VM_OBJECT_ID_FAKE(original_map, task_ledgers.purgeable_nonvolatile),
			    0, 1, 0, disposition);

			info          += stride;
			curr_s_offset += effective_page_size;
			vm_map_region_resolve_done(ctx, &map, resolve_kr);
			continue;
		}

		object_offs = vm_map_lock_ctx_offset_for_address(ctx,
		    vm_map_lock_ctx_from_parent_address(ctx, entry_start));
		object_ref  = os_ref_get_count_raw(&object->ref_count);

		/*
		 * Shared mode -- so we can allow other readers
		 * to grab the lock too.
		 */
		vm_object_reference(object);
		vm_object_lock_shared(object);
		vm_map_region_resolve_done(ctx, &map, resolve_kr);
		entry = VM_MAP_ENTRY_NULL; /* ctx is unlocked, the entry is no longer valid. */

		while (curr_s_offset < entry_end) {
			vm_object_t     curr_object    = object;
			int             disposition    = 0;
			vm_map_offset_t curr_object_offs;

			curr_object_offs = object_offs + (curr_s_offset - entry_start);

			for (;;) {
				vm_object_t shadow = curr_object->shadow;

				m = vm_page_lookup(curr_object,
				    vm_object_trunc_page(curr_object_offs));

				if (m != VM_PAGE_NULL) {
					disposition |= VM_PAGE_QUERY_PAGE_PRESENT;
					break;
				}

				if (curr_object->internal &&
				    curr_object->alive &&
				    !curr_object->terminating &&
				    curr_object->pager_ready) {
					if (vm_object_compressor_pager_state_get(curr_object,
					    vm_object_trunc_page(curr_object_offs)) ==
					    VM_EXTERNAL_STATE_EXISTS) {
						/* the pager has that page */
						disposition |= VM_PAGE_QUERY_PAGE_PAGED_OUT;
						break;
					}
				}

				/*
				 * Go down the VM object shadow chain until
				 * we find the page we're looking for.
				 */

				if (shadow == VM_OBJECT_NULL) {
					break;
				}

				curr_object_offs += curr_object->vo_shadow_offset;
				vm_object_lock_shared(shadow);
				vm_object_unlock(curr_object);
				curr_object = shadow;
				depth++;
			}

			/*
			 * The ref_count is not strictly accurate, it measures
			 * the number of entities holding a ref on the object,
			 * they may not be mapping the object or may not be
			 * mapping the section holding the target page but its
			 * still a ball park number and though an over-count,
			 * it picks up the copy-on-write cases
			 *
			 * We could also get a picture of page sharing from
			 * pmap_attributes but this would under count as only
			 * faulted-in mappings would  show up.
			 */

			if ((curr_object == object) && curr_object->shadow) {
				disposition |= VM_PAGE_QUERY_PAGE_COPIED;
			}

			if (!curr_object->internal) {
				disposition |= VM_PAGE_QUERY_PAGE_EXTERNAL;
			}

			if (m == VM_PAGE_NULL) {
				/* nothing to do */
			} else if (vm_page_is_fictitious(m)) {
				disposition |= VM_PAGE_QUERY_PAGE_FICTITIOUS;
			} else {
				if (m->vmp_dirty || pmap_is_modified(VM_PAGE_GET_PHYS_PAGE(m))) {
					disposition |= VM_PAGE_QUERY_PAGE_DIRTY;
				}

				if (m->vmp_reference || pmap_is_referenced(VM_PAGE_GET_PHYS_PAGE(m))) {
					disposition |= VM_PAGE_QUERY_PAGE_REF;
				}

				if (m->vmp_q_state == VM_PAGE_ON_SPECULATIVE_Q) {
					disposition |= VM_PAGE_QUERY_PAGE_SPECULATIVE;
				}

				/*
				 * XXX TODO4K:
				 * when this routine deals with 4k
				 * pages, check the appropriate CS bit
				 * here.
				 */
				if (m->vmp_cs_validated) {
					disposition |= VM_PAGE_QUERY_PAGE_CS_VALIDATED;
				}
				if (m->vmp_cs_tainted) {
					disposition |= VM_PAGE_QUERY_PAGE_CS_TAINTED;
				}
				if (m->vmp_cs_nx) {
					disposition |= VM_PAGE_QUERY_PAGE_CS_NX;
				}
				if (m->vmp_reusable || curr_object->all_reusable) {
					disposition |= VM_PAGE_QUERY_PAGE_REUSABLE;
				}
			}

			vm_map_page_info_populate(flavor, (uintptr_t)info,
			    (vm_object_id_t)VM_KERNEL_ADDRHASH(curr_object),
			    curr_object_offs + offset_in_page,
			    object_ref, depth, disposition);
			info          += stride;
			curr_s_offset += effective_page_size;

			/*
			 * This doesn't really make sense for any offset
			 * other than the starting offset.
			 */
			offset_in_page = 0;

			if (curr_object != object) {
				vm_object_unlock(curr_object);
				vm_object_lock_shared(object);
			} else {
				vm_object_lock_yield_shared(object);
			}
		}

		vm_object_unlock(object);
		vm_object_deallocate(object);
	}

	/*
	 * We still aren't done. That's because either there's a gap at
	 * the end of the queried area, and/or a footprint information we
	 * need to report.
	 */
	if (curr_s_offset < end) {
		vm_map_address_t fill_end = end;

		/*
		 * Set up to fill up to the end of what we want, which is
		 * the end of the request (end) in the normal case, or
		 * the end of the last entry in the map if (do_region_footprint)
		 */
		if (do_region_footprint) {
			fill_end = MIN(final_entry_end, end);
		}

		if (curr_s_offset < fill_end) {
			vm_map_offset_t size = fill_end - curr_s_offset;
			uint64_t        num_pages;

			num_pages = (size + effective_page_mask) >> effective_page_shift;
			bzero(info, num_pages * stride);
			info          += num_pages * stride;
			curr_s_offset += num_pages << effective_page_shift;
		}
	}

	while (do_region_footprint && curr_s_offset < end) {
		int disposition = 0;

		assert(curr_s_offset >= final_entry_end);

		/*
		 * Request for "footprint" info about a page beyond
		 * the end of address space: this must be for
		 * the fake region vm_map_region_recurse_64()
		 * reported to account for non-volatile purgeable
		 * memory owned by this task.
		 */
		if (curr_s_offset - final_entry_end <= (unsigned)ledger_compressed) {
			/*
			 * We haven't reported all the "non-volatile
			 * compressed" pages yet, so report this fake
			 * page as "compressed".
			 */
			disposition |= VM_PAGE_QUERY_PAGE_PAGED_OUT;
		} else {
			/*
			 * We've reported all the non-volatile
			 * compressed page but not all the non-volatile
			 * pages , so report this fake page as
			 * "resident dirty".
			 */
			disposition |= VM_PAGE_QUERY_PAGE_PRESENT;
			disposition |= VM_PAGE_QUERY_PAGE_DIRTY;
			disposition |= VM_PAGE_QUERY_PAGE_REF;
		}

		vm_map_page_info_populate(flavor, (uintptr_t)info,
		    VM_OBJECT_ID_FAKE(original_map, task_ledgers.purgeable_nonvolatile),
		    0, 1, 0, disposition);
		info          += stride;
		curr_s_offset += effective_page_size;
	}

	vmlp_api_end(VM_MAP_PAGE_RANGE_INFO_INTERNAL, KERN_SUCCESS);
	return KERN_SUCCESS;
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
vm_map_msync_sanitize(
	vm_map_t                map,
	vm_map_address_ut       address_u,
	vm_map_size_ut          size_u,
	vm_object_offset_t     *address,
	vm_map_size_t          *size)
{
	vm_object_offset_t      end;
#if CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS
	address_u = vm_sanitize_canonicalize_ut_addr(map, address_u);
#endif /* CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS */

	return vm_sanitize_addr_size(address_u, size_u,
	           VM_SANITIZE_CALLER_VM_MAP_MSYNC,
	           map, VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS, address, &end, size);
}

/*
 *	vm_map_msync
 *
 *	Synchronises the memory range specified with its backing store
 *	image by either flushing or cleaning the contents to the appropriate
 *	memory manager engaging in a memory object synchronize dialog with
 *	the manager.  The client doesn't return until the manager issues
 *	m_o_s_completed message.  MIG Magically converts user task parameter
 *	to the task's address map.
 *
 *	interpretation of sync_flags
 *	VM_SYNC_INVALIDATE	- discard pages, only return precious
 *				  pages to manager.
 *
 *	VM_SYNC_INVALIDATE & (VM_SYNC_SYNCHRONOUS | VM_SYNC_ASYNCHRONOUS)
 *				- discard pages, write dirty or precious
 *				  pages back to memory manager.
 *
 *	VM_SYNC_SYNCHRONOUS | VM_SYNC_ASYNCHRONOUS
 *				- write dirty or precious pages back to
 *				  the memory manager.
 *
 *	VM_SYNC_CONTIGUOUS	- does everything normally, but if there
 *				  is a hole in the region, and we would
 *				  have returned KERN_SUCCESS, return
 *				  KERN_INVALID_ADDRESS instead.
 *
 *	NOTE
 *	The memory object attributes have not yet been implemented, this
 *	function will have to deal with the invalidate attribute
 *
 *	RETURNS
 *	KERN_INVALID_TASK		Bad task parameter
 *	KERN_INVALID_ARGUMENT		both sync and async were specified.
 *	KERN_SUCCESS			The usual.
 *	KERN_INVALID_ADDRESS		There was a hole in the region.
 */

kern_return_t
vm_map_msync(
	vm_map_t                map,
	vm_map_address_ut       address_u,
	vm_map_size_ut          size_u,
	vm_sync_t               sync_flags)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t          entry;
	vm_map_size_t           size;
	vm_object_offset_t      address;
	boolean_t               do_sync_req;
	vmrl_ex_flags_t         vmrl_flags;
	kern_return_t           kr;

	vmlp_api_start(VM_MAP_MSYNC);

	if ((sync_flags & VM_SYNC_ASYNCHRONOUS) &&
	    (sync_flags & VM_SYNC_SYNCHRONOUS)) {
		vmlp_api_end(VM_MAP_MSYNC, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	if (map == VM_MAP_NULL) {
		vmlp_api_end(VM_MAP_MSYNC, KERN_INVALID_TASK);
		return KERN_INVALID_TASK;
	}

	kr = vm_map_msync_sanitize(map,
	    address_u,
	    size_u,
	    &address,
	    &size);
	if (VM_MAP_PAGE_MASK(map) < PAGE_MASK) {
		DEBUG4K_SHARE("map %p address 0x%llx size 0x%llx flags 0x%x\n", map, (uint64_t)address, (uint64_t)size, sync_flags);
	}
	if (__improbable(kr != KERN_SUCCESS)) {
		kr = vm_sanitize_get_kr(kr);
		vmlp_api_end(VM_MAP_MSYNC, kr);
		return kr;
	}
	const vm_object_offset_t start = address;
	const vm_object_offset_t end = address + size;

	/*
	 * Use VMRL_SH_NO_MIN_MAX_CHECK for backward compatibility, calls that go beyond
	 * the map were not rejected before the range-lock change.
	 *
	 * For VM_SYNC_KILLPAGES, there should be no holes in the range,
	 * since we couldn't prevent someone else from allocating in that hole
	 * and we wouldn't want to "kill" their pages.
	 *
	 * For VM_SYNC_CONTIGUOUS, the caller has requested an error on holes.
	 */
	if ((sync_flags & VM_SYNC_KILLPAGES) || (sync_flags & VM_SYNC_CONTIGUOUS)) {
		vmrl_flags = VMRL_SH_STREAM_NO_HOLES | VMRL_SH_NO_MIN_MAX_CHECK;
	} else {
		vmrl_flags = VMRL_SH_STREAM | VMRL_SH_NO_MIN_MAX_CHECK;
	}

	kr = vm_map_range_sh_lock(ctx, &map, start, end, vmrl_flags);

	if (kr != KERN_SUCCESS) {
		if (!(sync_flags & VM_SYNC_CONTIGUOUS)) {
			/*
			 * If holes are allowed (VM_SYNC_CONTIGUOUS not set) then we should
			 * return success even if no entries are present in the range.
			 * For the specific set of flags we pass, the only case where
			 * vm_map_range_sh_lock returns an error is when no entries are
			 * present in the range, it is thus safe to overwrite the return
			 * value.
			 */
			assert(kr == KERN_INVALID_ADDRESS);
			kr = KERN_SUCCESS;
		}
		vmlp_api_end(VM_MAP_MSYNC, kr);
		return kr;
	}

	while ((entry = vm_map_range_stream_next_with_error(ctx, &kr))) {
		vm_map_address_t ent_start;
		vm_map_offset_t  obj_start, obj_end;
		vm_object_t      object;

		vm_map_lock_ctx_bounds(ctx, &ent_start, NULL, NULL);
		vm_map_lock_ctx_offset_bounds(ctx, &obj_start, &obj_end, NULL);

		if (entry->is_sub_map) {
			assert(vm_map_is_sealed(VME_SUBMAP(entry)));
			/*
			 * We've never supported this calls for sealed submaps.
			 */
			continue;
		}
		/*
		 * Descending into a transparent submap (with
		 * the same pmap as its parent) is allowed.
		 * Constant is not.
		 */
		assert(!vm_map_lock_ctx_in_constant_submap(ctx));

		object = VME_OBJECT(entry);

		/*
		 * We can't sync this object if the object has not been
		 * created yet
		 */
		if (object == VM_OBJECT_NULL) {
			continue;
		}

		/*
		 * This is a destructive operation and so we
		 * err on the side of limiting the range of
		 * the operation.
		 */
		obj_start = vm_object_round_page(obj_start);
		obj_end   = vm_object_trunc_page(obj_end);
		ent_start = vm_object_round_page(ent_start);

		if (obj_start >= obj_end) {
			continue;
		}

		vm_object_lock(object);

		if (sync_flags & (VM_SYNC_KILLPAGES | VM_SYNC_DEACTIVATE)) {
			int kill_pages = 0;

			if (sync_flags & VM_SYNC_KILLPAGES) {
				if (vm_object_no_shadowing(object, true)) {
					/* no shadowing: we can kill pages */
					if (os_ref_get_count_raw(&object->ref_count) != 1) {
						vm_page_stats_reusable.free_shared++;
					}
					kill_pages = 1;
				} else {
					kill_pages = -1;
				}
			}
			if (kill_pages != -1) {
				boolean_t kill_no_write = FALSE;

				if ((entry->protection & VM_PROT_EXECUTE) ||
				    entry->vme_xnu_user_debug) {
					/*
					 * Executable or user debug pages might be write-protected by
					 * hardware, so do not attempt to write to these pages.
					 */
					kill_no_write = TRUE;
				}
				vm_object_deactivate_pages(object, obj_start,
				    (obj_end - obj_start), kill_pages,
				    FALSE, /* reusable_pages */
				    kill_no_write, ctx->vmlc_map->pmap, ent_start);
			}
			vm_object_unlock(object);
			continue;
		}
		/*
		 * We can't sync this object if there isn't a pager.
		 * Don't bother to sync internal objects, since there can't
		 * be any "permanent" storage for these objects anyway.
		 */
		if ((object->pager == MEMORY_OBJECT_NULL) ||
		    (object->internal) || (object->private)) {
			vm_object_unlock(object);
			continue;
		}
		/*
		 * keep reference on the object until syncing is done
		 */
		vm_object_reference_locked(object);
		vm_map_range_stream_drop(ctx);
		vm_object_unlock(object);

		do_sync_req = vm_object_sync(object, obj_start,
		    (obj_end - obj_start),
		    sync_flags & VM_SYNC_INVALIDATE,
		    ((sync_flags & VM_SYNC_SYNCHRONOUS) ||
		    (sync_flags & VM_SYNC_ASYNCHRONOUS)),
		    sync_flags & VM_SYNC_SYNCHRONOUS);

		if ((sync_flags & VM_SYNC_INVALIDATE) && object->resident_page_count == 0) {
			/*
			 * clear out the clustering and read-ahead hints
			 */
			vm_object_lock(object);

			object->pages_created = 0;
			object->pages_used = 0;
			object->sequential = 0;
			object->last_alloc = 0;

			vm_object_unlock(object);
		}
		vm_object_deallocate(object);
	}

	if (!(sync_flags & VM_SYNC_CONTIGUOUS)) {
		/*
		 * For VM_SYNC_KILLPAGES we use VMRL_SH_STREAM_NO_HOLES to break
		 * early but, unless VM_SYNC_CONTIGUOUS is set, we don't want to
		 * return an error (for backward compatibility reasons).
		 */
		if (kr != KERN_SUCCESS) {
			assert(sync_flags & VM_SYNC_KILLPAGES);
			assert(kr == KERN_INVALID_ADDRESS);
		}
		kr = KERN_SUCCESS;
	}

	vm_map_range_sh_unlock(ctx, &map);
	vmlp_api_end(VM_MAP_MSYNC, kr);
	return kr;
}

void
vm_named_entry_associate_vm_object(
	vm_named_entry_t        named_entry,
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size,
	vm_prot_t               prot)
{
	vm_map_copy_t copy;
	vm_map_entry_t copy_entry;

	assert(!named_entry->is_sub_map);
	assert(!named_entry->is_copy);
	assert(!named_entry->is_object);
	assert(!named_entry->internal);
	assert(named_entry->backing.copy == VM_MAP_COPY_NULL);

	copy = vm_map_copy_allocate(VM_MAP_COPY_ENTRY_LIST, PAGE_SHIFT);
	copy->offset = offset;
	copy->size = size;

	copy_entry = vm_map_copy_entry_create(copy,
	    VM_MAP_TRUNC_PAGE(offset, PAGE_MASK),
	    VM_MAP_ROUND_PAGE(offset + size, PAGE_MASK));
	copy_entry->protection = prot;
	copy_entry->max_protection = prot;
	copy_entry->use_pmap = TRUE;
	VME_OBJECT_SET(copy_entry, object, false, 0);
	VME_OFFSET_SET(copy_entry, vm_object_trunc_page(offset));
	vm_map_copy_store_insert_tail(copy, copy_entry);

	named_entry->backing.copy = copy;
	named_entry->is_object = TRUE;
	if (object->internal) {
		named_entry->internal = TRUE;
	}

	vm_object_lock(object);
	vm_object_mark_shared(object, VM_SHARE_TYPE_PERMANENT);
	vm_object_unlock(object);

	DEBUG4K_MEMENTRY("named_entry %p copy %p object %p offset 0x%llx size 0x%llx prot 0x%x\n",
	    named_entry, copy, object, offset, size, prot);
}

vm_object_t
vm_named_entry_to_vm_object(
	vm_named_entry_t named_entry)
{
	vm_map_copy_t   copy;
	vm_map_entry_t  copy_entry;
	vm_object_t     object;

	assert(!named_entry->is_sub_map);
	assert(!named_entry->is_copy);
	assert(named_entry->is_object);
	copy = named_entry->backing.copy;
	assert(copy != VM_MAP_COPY_NULL);
	/*
	 * Assert that the vm_map_copy is coming from the right
	 * zone and hasn't been forged
	 */
	vm_map_copy_require(copy);
	assert(copy->cpy_hdr.nentries == 1);
	copy_entry = vm_map_copy_first_entry(copy);
	object = VME_OBJECT(copy_entry);

	DEBUG4K_MEMENTRY("%p -> %p -> %p [0x%llx 0x%llx 0x%llx 0x%x/0x%x ] -> %p offset 0x%llx size 0x%llx prot 0x%x\n", named_entry, copy, copy_entry, (uint64_t)copy_entry->vme_start, (uint64_t)copy_entry->vme_end, copy_entry->vme_offset, copy_entry->protection, copy_entry->max_protection, object, named_entry->offset, named_entry->size, named_entry->protection);

	return object;
}

/*
 *	Routine:	convert_port_entry_to_map
 *	Purpose:
 *		Convert from a port specifying an entry or a task
 *		to a map. Doesn't consume the port ref; produces a map ref,
 *		which may be null.  Unlike convert_port_to_map, the
 *		port may be task or a named entry backed.
 *	Conditions:
 *		Nothing locked.
 */

vm_map_t
convert_port_entry_to_map(
	ipc_port_t      port)
{
	vm_map_t map = VM_MAP_NULL;
	vm_named_entry_t named_entry;

	if (!IP_VALID(port)) {
		return VM_MAP_NULL;
	}

	if (ip_type(port) != IKOT_NAMED_ENTRY) {
		return convert_port_to_map(port);
	}

	named_entry = mach_memory_entry_from_port(port);

	if ((named_entry->is_sub_map) &&
	    (named_entry->protection & VM_PROT_WRITE)) {
		map = named_entry->backing.map;
		if (map->pmap != PMAP_NULL) {
			if (map->pmap == kernel_pmap) {
				panic("userspace has access "
				    "to a kernel map %p", map);
			}
			pmap_require(map->pmap);
		}
		vm_map_reference(map);
	}

	return map;
}

/*
 * Export routines to other components for the things we access locally through
 * macros.
 */
#undef current_map
vm_map_t
current_map(void)
{
	return current_map_fast();
}

/*
 *	vm_map_reference:
 *
 *	Takes a reference on the specified map.
 */
void
vm_map_reference(
	vm_map_t        map)
{
	if (__probable(map != VM_MAP_NULL)) {
		vm_map_require(map);
		os_ref_retain_raw(&map->map_refcnt, &map_refgrp);
	}
}

/*
 *	vm_map_deallocate:
 *
 *	Removes a reference from the specified map,
 *	destroying it if no references remain.
 *	The map should not be locked.
 */
void
vm_map_deallocate(
	vm_map_t        map)
{
	if (__probable(map != VM_MAP_NULL)) {
		vm_map_require(map);
		if (os_ref_release_raw(&map->map_refcnt, &map_refgrp) == 0) {
			vm_map_destroy(map);
		}
	}
}

void
vm_map_inspect_deallocate(
	vm_map_inspect_t      map)
{
	vm_map_deallocate((vm_map_t)map);
}

void
vm_map_read_deallocate(
	vm_map_read_t      map)
{
	vm_map_deallocate((vm_map_t)map);
}


void
vm_map_disable_NX(vm_map_t map)
{
	if (map == NULL) {
		return;
	}
	if (map->pmap == NULL) {
		return;
	}

	pmap_disable_NX(map->pmap);
}

void
vm_map_disallow_data_exec(vm_map_t map)
{
	if (map == NULL) {
		return;
	}

	map->map_disallow_data_exec = TRUE;
}

/*
 * Expand the maximum size of an existing map to 64GB.
 */
void
vm_map_set_jumbo(vm_map_t map)
{
#if defined (__arm64__) && !XNU_TARGET_OS_OSX
	vm_map_set_max_addr(map, ~0, false);
#else /* arm64 */
	(void) map;
#endif
}

#if XNU_TARGET_OS_IOS && EXTENDED_USER_VA_SUPPORT
/*
 * Expand the maximum size of an existing map to the maximum supported.
 */
void
vm_map_set_extra_jumbo(vm_map_t map)
{
#if defined (__arm64__) && !XNU_TARGET_OS_OSX
	vm_map_set_max_addr(map, ~0, true);
#else /* arm64 */
	(void) map;
#endif
}
#endif /* XNU_TARGET_OS_IOS && EXTENDED_USER_VA_SUPPORT */

/*
 * This map has a JIT entitlement
 */
void
vm_map_set_jit_entitled(vm_map_t map)
{
#if defined (__arm64__)
	pmap_set_jit_entitled(map->pmap);
#else /* arm64 */
	(void) map;
#endif
}

void
vm_map_set_platform_binary(
	vm_map_t map,
	bool is_platform_binary)
{
	/* map should be locked by caller, unless still private */
	map->cs_platform_binary = is_platform_binary;
}

bool
vm_map_is_platform_binary(
	vm_map_t map)
{
	/* map should be locked by caller, unless still private */
	return map->cs_platform_binary;
}

/*
 * Get status of this maps TPRO flag
 */
boolean_t
vm_map_tpro(vm_map_t map)
{
#if defined (__arm64e__)
	return pmap_get_tpro(map->pmap);
#else /* arm64e */
	(void) map;
	return FALSE;
#endif
}

/*
 * This map has TPRO enabled
 */
void
vm_map_set_tpro(vm_map_t map)
{
#if defined (__arm64e__)
	pmap_set_tpro(map->pmap);
#else /* arm64e */
	(void) map;
#endif
}

#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
/*
 * This map has security checks enabled
 */
void
vm_map_set_sec_enabled(vm_map_t map)
{
#if CONFIG_SPTM && HAS_MTE
	pmap_set_tag_check_enabled(map->pmap);
#endif /* CONFIG_SPTM && HAS_MTE */
	(void) map;
}

/*
 * This map has security checks disabled
 */
void
vm_map_set_sec_disabled(vm_map_t map)
{
#if CONFIG_SPTM && HAS_MTE
	pmap_set_user_tag_check_faults_disabled(map->pmap);
#endif /* CONFIG_SPTM && HAS_MTE */
	(void) map;
}
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */

#if HAS_MTE
void
vm_map_set_restrict_receiving_aliases_to_tagged_memory(vm_map_t map, bool must_restrict)
{
	map->pmap->restrict_receiving_aliases_to_tagged_memory = must_restrict;
}
#endif /* HAS_MTE */

/*
 * Does this map have TPRO enforcement enabled
 */
boolean_t
vm_map_tpro_enforcement(vm_map_t map)
{
	return map->tpro_enforcement;
}

/*
 * Set TPRO enforcement for this map
 */
void
vm_map_set_tpro_enforcement(vm_map_t map)
{
	vmlp_api_start(VM_MAP_SET_TPRO_ENFORCEMENT);
	vmlp_range_event_none(map);
	if (vm_map_tpro(map)) {
		vm_map_ilk_lock(map);
		map->tpro_enforcement = TRUE;
		vm_map_ilk_unlock(map);
	}
	vmlp_api_end(VM_MAP_SET_TPRO_ENFORCEMENT, 0);
}

/*
 * Enable TPRO on the requested region
 *
 * Note:
 *     This routine is primarily intended to be called during/soon after map
 *     creation before the associated task has been released to run. It is only
 *     currently safe when we have no resident pages.
 */
boolean_t
vm_map_set_tpro_range(
	__unused vm_map_t map,
	__unused vm_map_address_t start,
	__unused vm_map_address_t end)
{
	vmlp_api_start(VM_MAP_SET_TPRO_RANGE);

	vmlp_api_end(VM_MAP_SET_TPRO_RANGE, 0);
	return TRUE;
}

/*
 * Expand the maximum size of an existing map.
 */
void
vm_map_set_max_addr(
	vm_map_t map,
	vm_map_offset_t new_max_offset,
	__unused bool extra_jumbo)
{
	vmlp_api_start(VM_MAP_SET_MAX_ADDR);

#if defined(__arm64__)
	vm_map_offset_t max_supported_offset;
	vm_map_offset_t old_max_offset;
	unsigned int option = ARM_PMAP_MAX_OFFSET_JUMBO;

	vm_map_ilk_lock(map);

	vmlp_range_event_none(map);

	old_max_offset = map->max_offset;
#if XNU_TARGET_OS_IOS && EXTENDED_USER_VA_SUPPORT
	if (extra_jumbo) {
		option = ARM_PMAP_MAX_OFFSET_EXTRA_JUMBO;
	}
#endif /* XNU_TARGET_OS_IOS && EXTENDED_USER_VA_SUPPORT */
	max_supported_offset = pmap_max_offset(vm_map_is_64bit(map), option);

	new_max_offset = trunc_page(new_max_offset);

	/* The address space cannot be shrunk using this routine. */
	if (old_max_offset >= new_max_offset) {
		vm_map_ilk_unlock(map);
		vmlp_api_end(VM_MAP_SET_MAX_ADDR, 0);
		return;
	}

	if (max_supported_offset < new_max_offset) {
		new_max_offset = max_supported_offset;
	}

	map->max_offset = new_max_offset;

	vm_map_ilk_unlock(map);
#else
	(void)map;
	(void)new_max_offset;
#endif
	vmlp_api_end(VM_MAP_SET_MAX_ADDR, 0);
}

vm_map_offset_t
vm_compute_max_offset(boolean_t is64)
{
#if defined(__arm64__)
	return pmap_max_offset(is64, ARM_PMAP_MAX_OFFSET_DEVICE);
#else
	return is64 ? (vm_map_offset_t)MACH_VM_MAX_ADDRESS : (vm_map_offset_t)VM_MAX_ADDRESS;
#endif
}

void
vm_map_get_max_aslr_slide_section(
	vm_map_t                map __unused,
	int64_t                 *max_sections,
	int64_t                 *section_size)
{
#if defined(__arm64__)
	*max_sections = 3;
	*section_size = ARM_TT_TWIG_SIZE;
#else
	*max_sections = 1;
	*section_size = 0;
#endif
}

uint64_t
vm_map_get_max_aslr_slide_pages(vm_map_t map)
{
#if defined(__arm64__)
	/* Limit arm64 slide to 16MB to conserve contiguous VA space in the more
	 * limited embedded address space; this is also meant to minimize pmap
	 * memory usage on 16KB page systems.
	 */
	return 1 << (24 - VM_MAP_PAGE_SHIFT(map));
#else
	return 1 << (vm_map_is_64bit(map) ? 16 : 8);
#endif
}

uint64_t
vm_map_get_max_loader_aslr_slide_pages(vm_map_t map)
{
#if defined(__arm64__)
	/* We limit the loader slide to 4MB, in order to ensure at least 8 bits
	 * of independent entropy on 16KB page systems.
	 */
	return 1 << (22 - VM_MAP_PAGE_SHIFT(map));
#else
	return 1 << (vm_map_is_64bit(map) ? 16 : 8);
#endif
}

boolean_t
vm_map_is_64bit(
	vm_map_t map)
{
	return map->max_offset > ((vm_map_offset_t)VM_MAX_ADDRESS);
}

boolean_t
vm_map_has_hard_pagezero(
	vm_map_t        map,
	vm_map_offset_t pagezero_size)
{
	/*
	 * XXX FBDP
	 * We should lock the VM map (for read) here but we can get away
	 * with it for now because there can't really be any race condition:
	 * the VM map's min_offset is changed only when the VM map is created
	 * and when the zero page is established (when the binary gets loaded),
	 * and this routine gets called only when the task terminates and the
	 * VM map is being torn down, and when a new map is created via
	 * load_machfile()/execve().
	 */
	return map->min_offset >= pagezero_size;
}

/*
 * Raise a VM map's maximun offset.
 */
kern_return_t
vm_map_raise_max_offset(
	vm_map_t        map,
	vm_map_offset_t new_max_offset)
{
	kern_return_t   ret;

	vmlp_api_start(VM_MAP_RAISE_MAX_OFFSET);

	vm_map_ilk_lock(map);

	vmlp_range_event_none(map);

	ret = KERN_INVALID_ADDRESS;

	if (new_max_offset >= map->max_offset) {
		if (!vm_map_is_64bit(map)) {
			if (new_max_offset <= (vm_map_offset_t)VM_MAX_ADDRESS) {
				map->max_offset = new_max_offset;
				ret = KERN_SUCCESS;
			}
		} else {
			if (new_max_offset <= (vm_map_offset_t)MACH_VM_MAX_ADDRESS) {
				map->max_offset = new_max_offset;
				ret = KERN_SUCCESS;
			}
		}
	}

	vm_map_ilk_unlock(map);
	vmlp_api_end(VM_MAP_RAISE_MAX_OFFSET, ret);
	return ret;
}


/*
 * Raise a VM map's minimum offset.
 * To strictly enforce "page zero" reservation.
 */
kern_return_t
vm_map_raise_min_offset(
	vm_map_t        map,
	vm_map_offset_t new_min_offset)
{
	vm_map_entry_t  first_entry;

	vmlp_api_start(VM_MAP_RAISE_MIN_OFFSET);

	new_min_offset = vm_map_round_page(new_min_offset,
	    VM_MAP_PAGE_MASK(map));

	vm_map_ilk_lock(map);

	if (new_min_offset < map->min_offset) {
		/*
		 * Can't move min_offset backwards, as that would expose
		 * a part of the address space that was previously, and for
		 * possibly good reasons, inaccessible.
		 */
		vm_map_ilk_unlock(map);
		vmlp_api_end(VM_MAP_RAISE_MIN_OFFSET, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}
	if (new_min_offset >= map->max_offset) {
		/* can't go beyond the end of the address space */
		vm_map_ilk_unlock(map);
		vmlp_api_end(VM_MAP_RAISE_MIN_OFFSET, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}

	first_entry = vm_map_first_entry(map);

	if (first_entry != vm_map_to_entry(map) &&
	    first_entry->vme_start < new_min_offset) {
		/*
		 * Some memory was already allocated below the new
		 * minimun offset.  It's too late to change it now...
		 */
		vm_map_ilk_unlock(map);
		vmlp_api_end(VM_MAP_RAISE_MIN_OFFSET, KERN_NO_SPACE);
		return KERN_NO_SPACE;
	}

	map->min_offset = new_min_offset;

	vm_map_ilk_unlock(map);

	vmlp_api_end(VM_MAP_RAISE_MIN_OFFSET, KERN_SUCCESS);
	return KERN_SUCCESS;
}

/*
 * Set the limit on the maximum amount of address space and user wired memory allowed for this map.
 * This is basically a copy of the RLIMIT_AS and RLIMIT_MEMLOCK rlimit value maintained by the BSD
 * side of the kernel. The limits are checked in the mach VM side, so we keep a copy so we don't
 * have to reach over to the BSD data structures.
 */

uint64_t vm_map_set_size_limit_count = 0;
kern_return_t
vm_map_set_size_limit(vm_map_t map, uint64_t new_size_limit)
{
	kern_return_t kr;

	vmlp_api_start(VM_MAP_SET_SIZE_LIMIT);

	vm_map_ilk_lock(map);

	vmlp_range_event_none(map);

	if (new_size_limit < map->size) {
		/* new limit should not be lower than its current size */
		DTRACE_VM2(vm_map_set_size_limit_fail,
		    vm_map_size_t, map->size,
		    uint64_t, new_size_limit);
		kr = KERN_FAILURE;
	} else if (new_size_limit == map->size_limit) {
		/* no change */
		kr = KERN_SUCCESS;
	} else {
		/* set new limit */
		DTRACE_VM2(vm_map_set_size_limit,
		    vm_map_size_t, map->size,
		    uint64_t, new_size_limit);
		if (new_size_limit != RLIM_INFINITY) {
			vm_map_set_size_limit_count++;
		}
		map->size_limit = new_size_limit;
		kr = KERN_SUCCESS;
	}
	vm_map_ilk_unlock(map);
	vmlp_api_end(VM_MAP_SET_SIZE_LIMIT, kr);
	return kr;
}

uint64_t vm_map_set_data_limit_count = 0;
kern_return_t
vm_map_set_data_limit(vm_map_t map, uint64_t new_data_limit)
{
	kern_return_t kr;

	vmlp_api_start(VM_MAP_SET_DATA_LIMIT);

	vm_map_ilk_lock(map);

	vmlp_range_event_none(map);

	if (new_data_limit < map->size) {
		/* new limit should not be lower than its current size */
		DTRACE_VM2(vm_map_set_data_limit_fail,
		    vm_map_size_t, map->size,
		    uint64_t, new_data_limit);
		kr = KERN_FAILURE;
	} else if (new_data_limit == map->data_limit) {
		/* no change */
		kr = KERN_SUCCESS;
	} else {
		/* set new limit */
		DTRACE_VM2(vm_map_set_data_limit,
		    vm_map_size_t, map->size,
		    uint64_t, new_data_limit);
		if (new_data_limit != RLIM_INFINITY) {
			vm_map_set_data_limit_count++;
		}
		map->data_limit = new_data_limit;
		kr = KERN_SUCCESS;
	}
	vm_map_ilk_unlock(map);
	vmlp_api_end(VM_MAP_SET_DATA_LIMIT, kr);
	return kr;
}

void
vm_map_set_user_wire_limit(vm_map_t     map,
    vm_size_t    limit)
{
	vmlp_api_start(VM_MAP_SET_USER_WIRE_LIMIT);
	vm_map_ilk_lock(map);
	vmlp_range_event_none(map);
	map->user_wire_limit = limit;
	vm_map_ilk_unlock(map);
	vmlp_api_end(VM_MAP_SET_USER_WIRE_LIMIT, 0);
}


void
vm_map_switch_protect(vm_map_t map, bool val)
{
	vmlp_api_start(VM_MAP_SWITCH_PROTECT);
	vmlp_range_event_none(map);
	vm_map_ilk_lock(map);
	map->switch_protect = val;
	vm_map_ilk_unlock(map);
	vmlp_api_end(VM_MAP_SWITCH_PROTECT, 0);
}

extern int cs_process_enforcement_enable;
boolean_t
vm_map_cs_enforcement(
	vm_map_t map)
{
	if (cs_process_enforcement_enable) {
		return TRUE;
	}
	return map->cs_enforcement;
}

kern_return_t
vm_map_cs_wx_enable(
	__unused vm_map_t map)
{
#if CODE_SIGNING_MONITOR
	kern_return_t ret = csm_allow_invalid_code(vm_map_pmap(map));
	if ((ret == KERN_SUCCESS) || (ret == KERN_NOT_SUPPORTED)) {
		return KERN_SUCCESS;
	}
	return ret;
#else
	/* The VM manages WX memory entirely on its own */
	return KERN_SUCCESS;
#endif
}

kern_return_t
vm_map_csm_allow_jit(
	__unused vm_map_t map)
{
#if CODE_SIGNING_MONITOR
	return csm_allow_jit_region(vm_map_pmap(map));
#else
	/* No code signing monitor to enforce JIT policy */
	return KERN_SUCCESS;
#endif
}

void
vm_map_cs_debugged_set(
	vm_map_t map,
	boolean_t val)
{
	vmlp_api_start(VM_MAP_CS_DEBUGGED_SET);
	vm_map_ilk_lock(map);
	vmlp_range_event_none(map);
	map->cs_debugged = val;
	vm_map_ilk_unlock(map);
	vmlp_api_end(VM_MAP_CS_DEBUGGED_SET, 0);
}

void
vm_map_cs_enforcement_set(
	vm_map_t map,
	boolean_t val)
{
	vmlp_api_start(VM_MAP_CS_ENFORCEMENT_SET);
	vm_map_ilk_lock(map);
	vmlp_range_event_none(map);
	map->cs_enforcement = val;
	pmap_set_vm_map_cs_enforced(map->pmap, val);
	vm_map_ilk_unlock(map);
	vmlp_api_end(VM_MAP_CS_ENFORCEMENT_SET, 0);
}

/*
 * IOKit has mapped a region into this map; adjust the pmap's ledgers appropriately.
 * phys_footprint is a composite limit consisting of iokit + physmem, so we need to
 * bump both counters.
 */
void
vm_map_iokit_mapped_region(vm_map_t map, vm_size_t bytes)
{
	ledger_t ledger = vm_map_pmap(map)->ledger;

	disable_preemption();
	ledger_credit_scalable(&task_ledger_template, ledger,
	    task_ledgers.iokit_mapped, bytes);
	ledger_credit_scalable(&task_ledger_template, ledger,
	    task_ledgers.phys_footprint, bytes);
	enable_preemption();
}

void
vm_map_iokit_unmapped_region(vm_map_t map, vm_size_t bytes)
{
	ledger_t ledger = vm_map_pmap(map)->ledger;

	disable_preemption();
	ledger_debit_scalable(&task_ledger_template, ledger,
	    task_ledgers.iokit_mapped, bytes);
	ledger_debit_scalable(&task_ledger_template, ledger,
	    task_ledgers.phys_footprint, bytes);
	enable_preemption();
}

/* Add (generate) code signature for memory range */
#if CONFIG_DYNAMIC_CODE_SIGNING

kern_return_t
vm_map_sign(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end)
{
	vm_map_entry_t entry;
	vm_page_t m;
	vm_object_t object;
	kern_return_t kr;
	vm_map_offset_t entry_start;
	vm_object_offset_t entry_offset;
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_SIGN);

	/*
	 * Vet all the input parameters and current type and state of the
	 * underlaying object.  Return with an error if anything is amiss.
	 */
	if (map == VM_MAP_NULL) {
		vmlp_api_end(VM_MAP_SIGN, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	if (__improbable(vm_map_range_overflows(map, start, end - start))) {
		vmlp_api_end(VM_MAP_SIGN, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}

	/*
	 * Streaming so that it can unlock the entry lock while holding the object lock.
	 * VMRL_SH_NO_MIN_MAX_CHECK for ABI compatibility
	 */
	kr = vm_map_find_entry_sh_locked(ctx, &map, start,
	    VMRL_FIND_SH_NO_MIN_MAX_CHECK);
	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_SIGN, kr);
		return kr;
	}

	entry = ctx->vmlc_vme;

	if (entry->is_sub_map) {
		/*
		 * Must pass a valid non-submap, non user-chunk address.
		 */
		vm_map_found_entry_sh_unlock(ctx, &map);
		vmlp_api_end(VM_MAP_SIGN, KERN_INVALID_ADDRESS);
		return KERN_INVALID_ADDRESS;
	}

	if ((entry->vme_start > start) || (entry->vme_end < end)) {
		/*
		 * Map entry doesn't cover the requested range. Not handling
		 * this situation currently.
		 */
		vm_map_found_entry_sh_unlock(ctx, &map);
		vmlp_api_end(VM_MAP_SIGN, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	object = VME_OBJECT(entry);
	if (object == VM_OBJECT_NULL) {
		/*
		 * Object must already be present or we can't sign.
		 */
		vm_map_found_entry_sh_unlock(ctx, &map);
		vmlp_api_end(VM_MAP_SIGN, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	vm_object_lock(object);

	entry_start = entry->vme_start;
	entry_offset = VME_OFFSET(entry);

	vm_map_found_entry_sh_unlock(ctx, &map);
	entry = VM_MAP_ENTRY_NULL; /* no longer valid after unlocking range */

	while (start < end) {
		uint32_t refmod;

		m = vm_page_lookup(object,
		    start - entry_start + entry_offset);
		if (m == VM_PAGE_NULL) {
			/* shoud we try to fault a page here? we can probably
			 * demand it exists and is locked for this request */
			vm_object_unlock(object);
			vmlp_api_end(VM_MAP_SIGN, KERN_FAILURE);
			return KERN_FAILURE;
		}
		/* deal with special page status */
		if (m->vmp_busy ||
		    (m->vmp_unusual && (VMP_ERROR_GET(m) || m->vmp_restart ||
		    vm_page_is_private(m) || m->vmp_absent))) {
			vm_object_unlock(object);
			vmlp_api_end(VM_MAP_SIGN, KERN_FAILURE);
			return KERN_FAILURE;
		}

		/* Page is OK... now "validate" it */
		/* This is the place where we'll call out to create a code
		 * directory, later */
		/* XXX TODO4K: deal with 4k subpages individually? */
		m->vmp_cs_validated = VMP_CS_ALL_TRUE;

		/* The page is now "clean" for codesigning purposes. That means
		 * we don't consider it as modified (wpmapped) anymore. But
		 * we'll disconnect the page so we note any future modification
		 * attempts. */
		m->vmp_wpmapped = FALSE;
		refmod = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));

		/* Pull the dirty status from the pmap, since we cleared the
		 * wpmapped bit */
		if ((refmod & VM_MEM_MODIFIED) && !m->vmp_dirty) {
			SET_PAGE_DIRTY(m, FALSE);
		}

		/* On to the next page */
		start += PAGE_SIZE;
	}
	vm_object_unlock(object);

	vmlp_api_end(VM_MAP_SIGN, KERN_SUCCESS);
	return KERN_SUCCESS;
}

#endif /* CONFIG_DYNAMIC_CODE_SIGNING */
#if DEVELOPMENT || DEBUG

int
vm_map_disconnect_page_mappings(
	vm_map_t map,
	boolean_t do_unnest)
{
	vm_map_entry_t entry;
	ledger_amount_t byte_count = 0;
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;

	vmlp_api_start(VM_MAP_DISCONNECT_PAGE_MAPPINGS);

	/*
	 * Not supported for the kernel.  That means we won't descend into
	 * transparent submaps, so we have no descension to worry about.
	 */
	assert(!vm_kernel_map_is_kernel(map));

	if (do_unnest == TRUE) {
#ifndef NO_NESTED_PMAP
		/*
		 * Streaming so that it iterates the whole map.
		 * WHOLE_MAP so the range isn't artificially constrained
		 */
		kr = vm_map_range_ex_lock(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END, VMRL_EX_STREAM | VMRL_EX_WHOLE_MAP);
		if (kr == KERN_SUCCESS) {
			while ((entry = vm_map_range_stream_next(ctx))) {
				/*
				 * Intentionally empty loop. pmap_unnesting is
				 * done by the exclusive range lock
				 */
			}
			vm_map_range_ex_unlock(ctx, &map);
		}
#endif
	}

	/*
	 * Streaming so that it iterates the whole map.
	 * WHOLE_MAP so the range isn't artificially constrained
	 */
	ledger_get_balance(map->pmap->ledger, task_ledgers.phys_mem, LEO_SETTLE, &byte_count);
	kr = vm_map_range_sh_lock(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END, VMRL_SH_STREAM | VMRL_SH_WHOLE_MAP);


	if (kr == KERN_SUCCESS) {
		while ((entry = vm_map_range_stream_next(ctx))) {
			if (!entry->is_sub_map && ((VME_OBJECT(entry) == 0) ||
			    (VME_OBJECT(entry)->phys_contiguous))) {
				continue;
			}
			if (entry->is_sub_map) {
				assert(!entry->use_pmap);
			}

			pmap_remove_options(ctx->vmlc_map->pmap, entry->vme_start, entry->vme_end, 0);
		}
		vm_map_range_sh_unlock(ctx, &map);
	}

	vmlp_api_end(VM_MAP_DISCONNECT_PAGE_MAPPINGS, 0);
	return (int) (byte_count / VM_MAP_PAGE_SIZE(map));
}

kern_return_t
vm_map_inject_error(vm_map_t map, vm_map_offset_t vaddr)
{
	vm_object_t object = NULL;
	kern_return_t result;
	vm_map_entry_t entry;
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_INJECT_ERROR);

	vaddr = vm_map_trunc_page(vaddr, PAGE_MASK);

	result = vm_map_find_entry_sh_locked(ctx, &map, vaddr,
	    VMRL_FIND_SH_DESCEND_INTO_CONSTANT | VMRL_FIND_SH_NO_MIN_MAX_CHECK);
	if (result != KERN_SUCCESS) {
		/* no entry -> no pager */
		result = KERN_MEMORY_ERROR;
		goto return_unlocked;
	}

	entry = vm_map_found_entry_get_entry(ctx);

	if (!(entry->protection & VM_PROT_READ)) {
		/* not readable, don't bother */
		result = KERN_MEMORY_ERROR;
		goto unlock_ctx_and_return;
	}
	object = VME_OBJECT(entry);
	if (object == NULL) {
		/* no object -> no pager */
		result = KERN_MEMORY_ERROR;
		goto unlock_ctx_and_return;
	}

	vm_object_lock(object);
	if (object->pager) {
		result = vm_compressor_pager_inject_error(object->pager,
		    vm_map_lock_ctx_offset_for_address(ctx, vaddr));
	} else {
		result = KERN_MEMORY_PRESENT;
	}
	vm_object_unlock(object);

unlock_ctx_and_return:
	vm_map_found_entry_sh_unlock(ctx, &map);

return_unlocked:
	vmlp_api_end(VM_MAP_INJECT_ERROR, result);
	return result;
}

/* iterate over map entries. Call the first argument block for the number of entries and the second for every entry
 * returns: KERN_SUCCESS if iteration completed ok,
 *      error code if callback returned an error
 *      KERN_FAILURE if there was a race of adding/removing entries during the iteration and the number of entries
 *      iterated is different from the number in the first call
 */
kern_return_t
vm_map_entries_foreach(vm_map_t map, kern_return_t (^entry_handler)(void* entry))
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	/* locking the entire space since entries can be outside min/max_offset
	 * holes are allowed by default for stream lock. VMRL_WHOLE_MAP added for range to go beyond
	 * what's covered by map entries. */
	kern_return_t kr = vm_map_range_sh_lock(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END, VMRL_SH_STREAM | VMRL_SH_WHOLE_MAP);

	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* iterate until we loop back to the map, see get_vmmap_entries() */
	vm_map_entry_t entry;
	while ((entry = vm_map_range_stream_next(ctx)) != VM_MAP_ENTRY_NULL) {
		kr = entry_handler(entry);
		if (kr != KERN_SUCCESS) {
			break;
		}
	}
	vm_map_range_sh_unlock(ctx, &map);
	return kr;
}


/*
 * Dump info about the entry into the given buffer.
 * return true on success, false if there was not enough space in the give buffer
 * argument size in: bytes free in the given buffer, out: bytes written
 */
kern_return_t
vm_map_dump_entry_and_compressor_pager(void* pentry, char *buf, size_t *size)
{
	size_t insize = *size;
	kern_return_t kr;
	size_t offset = 0;

	*size = 0;
	if (sizeof(struct vm_map_entry_info) > insize) {
		return KERN_NO_SPACE;
	}

	vm_map_entry_t entry = (vm_map_entry_t)pentry;
	struct vm_map_entry_info *out_entry = (struct vm_map_entry_info*)buf;
	out_entry->vmei_start = entry->vme_start;
	out_entry->vmei_end = entry->vme_end;
	out_entry->vmei_alias = VME_ALIAS(entry);
	out_entry->vmei_offset = VME_OFFSET(entry);
	out_entry->vmei_is_sub_map = entry->is_sub_map;
	out_entry->vmei_protection = entry->protection;
	offset += sizeof(struct vm_map_entry_info);

	out_entry->vmei_slot_mapping_count = 0;
	out_entry->vmei_is_compressor_pager = false;
	*size = offset;
	if (out_entry->vmei_is_sub_map) {
		return KERN_SUCCESS; // TODO: sub_map interrogation not supported yet
	}
	/* have a vm_object? */
	vm_object_t object = VME_OBJECT(entry);
	if (object == VM_OBJECT_NULL || !object->internal) {
		return KERN_SUCCESS;
	}
	/* objects has a pager? */
	memory_object_t pager = object->pager;
	if (pager != MEMORY_OBJECT_NULL) {
		return KERN_SUCCESS;
	}
	bool is_compressor = false;
	unsigned int slot_mapping_count = 0;
	size_t pager_info_size = insize - offset;
	kr = vm_compressor_pager_dump(pager, buf + offset, &pager_info_size, &is_compressor, &slot_mapping_count);
	if (kr != KERN_SUCCESS) {
		/* didn't have enough space for everything we want to write, caller needs to retry */
		return kr;
	}
	offset += pager_info_size;
	/* if we got here, is_compressor should be true due to the object->internal check above, so this assignment
	 * is just for sanity sake */
	out_entry->vmei_is_compressor_pager = is_compressor;
	out_entry->vmei_slot_mapping_count = slot_mapping_count;
	*size = offset;
	return KERN_SUCCESS;
}

#endif /* DEVELOPMENT || DEBUG */
#if CONFIG_FREEZE


extern struct freezer_context freezer_context_global;
AbsoluteTime c_freezer_last_yield_ts = 0;

extern unsigned int memorystatus_freeze_private_shared_pages_ratio;
extern unsigned int memorystatus_freeze_shared_mb_per_process_max;

/*
 * This function uses a two-step pass loop when deciding to and later doing the freezing.
 * 1) It loops each entry in the map. It looks at how much memory is resident,
 * and whether that is shared or private.
 * It then sums all of that information, and decides whether it should actually
 * do the freezing.
 *
 * 2) If it decides to do that freezing, it again loops every entry in the map
 * and then freezes each one (essentially pages the backing object out).
 *
 * There is a lack of atomicity between phase 1 and 2. That means it is possible
 * for some of those exact numbers about page status to change, but it's unlikely
 * this will meaningfully change the decision of whether we want to freeze or not,
 * which is already a heuristic.
 */
kern_return_t
vm_map_freeze(
	task_t           task,
	unsigned int    *purgeable_count,
	unsigned int    *wired_count,
	unsigned int    *clean_count,
	unsigned int    *dirty_count,
	unsigned int     dirty_budget,
	unsigned int    *shared_count,
	int             *freezer_error_code,
	freeze_options_t opts)
{
	bool            skip_shared = !(opts & FREEZE_SHARED);
	bool            eval_only = opts & FREEZE_EVAL_ONLY;
	vm_map_entry_t  entry2 = VM_MAP_ENTRY_NULL;
	kern_return_t   kr = KERN_SUCCESS;
	boolean_t       evaluation_phase = TRUE;
	vm_object_t     cur_shared_object = NULL;
	int             cur_shared_obj_ref_cnt = 0;
	unsigned int    dirty_private_count = 0, dirty_shared_count = 0, obj_pages_snapshot = 0;
	vm_map_t map = task->map;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_FREEZE);

	*purgeable_count = *wired_count = *clean_count = *dirty_count = *shared_count = 0;

	assert(VM_CONFIG_COMPRESSOR_IS_PRESENT);

	if (vm_compressor_low_on_space() || vm_swap_low_on_space()) {
		if (vm_compressor_low_on_space()) {
			*freezer_error_code = FREEZER_ERROR_NO_COMPRESSOR_SPACE;
		}

		if (vm_swap_low_on_space()) {
			*freezer_error_code = FREEZER_ERROR_NO_SWAP_SPACE;
		}

		kr = KERN_NO_SPACE;
		goto done;
	}

	if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE == FALSE) {
		/*
		 * In-memory compressor backing the freezer. No disk.
		 * So no need to do the evaluation phase.
		 */
		evaluation_phase = FALSE;

		if (eval_only) {
			/*
			 * We don't support 'eval_only' mode
			 * in this non-swap config.
			 */
			*freezer_error_code = FREEZER_ERROR_GENERIC;
			kr = KERN_INVALID_ARGUMENT;
			goto done;
		}

		freezer_context_global.freezer_ctx_uncompressed_pages = 0;
		clock_get_uptime(&c_freezer_last_yield_ts);
	}
again:
	/*
	 * We take the exclusive lock here to block any page faults concurrent
	 * to the freezing. This is mainly done for historical reasons, along with
	 * one theory being vm_object_compressed_freezer_pageout is somehow relying
	 * on that for synchronization.
	 *
	 * We aren't actually changing the entries, so no reason to pmap_unnest.
	 */
	kr = vm_map_range_ex_lock(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END, VMRL_EX_STREAM | VMRL_EX_WHOLE_MAP | VMRL_EX_NO_PMAP_UNNEST);
	if (kr != KERN_SUCCESS) {
		goto after_loop_evaluation;
	}

	while ((entry2 = vm_map_range_stream_next(ctx))) {
		vm_object_t src_object;

		if (entry2->is_sub_map) {
			continue;
		}

		src_object = VME_OBJECT(entry2);
		if (!src_object ||
		    src_object->phys_contiguous ||
		    !src_object->internal) {
			continue;
		}

		/* If eligible, scan the entry, moving eligible pages over to our parent object */

		if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
			/*
			 * We skip purgeable objects during evaluation phase only.
			 * If we decide to freeze this process, we'll explicitly
			 * purge these objects before we go around again with
			 * 'evaluation_phase' set to FALSE.
			 */

			if ((src_object->purgable == VM_PURGABLE_EMPTY) || (src_object->purgable == VM_PURGABLE_VOLATILE)) {
				/*
				 * We want to purge objects that may not belong to this task but are mapped
				 * in this task alone. Since we already purged this task's purgeable memory
				 * at the end of a successful evaluation phase, we want to avoid doing no-op calls
				 * on this task's purgeable objects. Hence the check for only volatile objects.
				 */
				if (evaluation_phase ||
				    src_object->purgable != VM_PURGABLE_VOLATILE ||
				    os_ref_get_count_raw(&src_object->ref_count) != 1) {
					continue;
				}
				vm_object_lock(src_object);
				if (src_object->purgable == VM_PURGABLE_VOLATILE &&
				    os_ref_get_count_raw(&src_object->ref_count) == 1) {
					purgeable_q_t old_queue;

					/* object should be on a purgeable queue */
					assert(src_object->objq.next != NULL &&
					    src_object->objq.prev != NULL);
					/* move object from its volatile queue to the nonvolatile queue */
					old_queue = vm_purgeable_object_remove(src_object);
					assert(old_queue);
					if (src_object->purgeable_when_ripe) {
						/* remove a token from that volatile queue */
						vm_page_lock_queues();
						vm_purgeable_token_delete_first(old_queue);
						vm_page_unlock_queues();
					}
					/* purge the object */
					vm_object_purge(src_object, 0);
				}
				vm_object_unlock(src_object);
				continue;
			}

			/*
			 * Pages belonging to this object could be swapped to disk.
			 * Make sure it's not a shared object because we could end
			 * up just bringing it back in again.
			 *
			 * We try to optimize somewhat by checking for objects that are mapped
			 * more than once within our own map. But we don't do full searches,
			 * we just look at the entries following our current entry.
			 */

			if (os_ref_get_count_raw(&src_object->ref_count) > 1) {
				if (src_object != cur_shared_object) {
					obj_pages_snapshot = (src_object->resident_page_count - src_object->wired_page_count) + vm_compressor_pager_get_count(src_object->pager);
					dirty_shared_count += obj_pages_snapshot;

					cur_shared_object = src_object;
					cur_shared_obj_ref_cnt = 1;

					if (skip_shared) {
						continue;
					}
				} else {
					cur_shared_obj_ref_cnt++;
					if (os_ref_get_count_raw(&src_object->ref_count) == cur_shared_obj_ref_cnt) {
						/*
						 * Fall through to below and treat this object as private.
						 * So deduct its pages from our shared total and add it to the
						 * private total.
						 */

						dirty_shared_count -= obj_pages_snapshot;
						dirty_private_count += obj_pages_snapshot;
					} else if (skip_shared) {
						continue;
					}
				}
			}


			if (os_ref_get_count_raw(&src_object->ref_count) == 1) {
				dirty_private_count += (src_object->resident_page_count - src_object->wired_page_count) + vm_compressor_pager_get_count(src_object->pager);
			}

			if (evaluation_phase == TRUE) {
				continue;
			}
		}

		uint32_t paged_out_count = vm_object_compressed_freezer_pageout(src_object, dirty_budget);
		*wired_count += src_object->wired_page_count;

		if (vm_compressor_low_on_space() || vm_swap_low_on_space()) {
			if (vm_compressor_low_on_space()) {
				*freezer_error_code = FREEZER_ERROR_NO_COMPRESSOR_SPACE;
			}

			if (vm_swap_low_on_space()) {
				*freezer_error_code = FREEZER_ERROR_NO_SWAP_SPACE;
			}

			kr = KERN_NO_SPACE;
			break;
		}
		if (paged_out_count >= dirty_budget) {
			break;
		}
		dirty_budget -= paged_out_count;
	}
	vm_map_range_ex_unlock(ctx, &map);

after_loop_evaluation:
	*shared_count = (unsigned int) ((dirty_shared_count * PAGE_SIZE_64) / (1024 * 1024ULL));
	if (evaluation_phase) {
		if (memorystatus_freeze_shared_mb_per_process_max) {
			unsigned int shared_pages_threshold = (memorystatus_freeze_shared_mb_per_process_max * 1024 * 1024ULL) / PAGE_SIZE_64;
			if (dirty_shared_count > shared_pages_threshold) {
				vm_log("vm_map_freeze: FREEZER_ERROR_EXCESS_SHARED_MEMORY. %d pages for pid %d, versus maximum limit of %d\n",
				    dirty_shared_count, pid_from_task(task), shared_pages_threshold);
				*freezer_error_code = FREEZER_ERROR_EXCESS_SHARED_MEMORY;
				kr = KERN_FAILURE;
				goto done;
			}
		}

		if (skip_shared &&
		    dirty_shared_count &&
		    ((dirty_private_count / dirty_shared_count) < memorystatus_freeze_private_shared_pages_ratio)) {
			vm_log("vm_map_freeze: FREEZER_ERROR_LOW_PRIVATE_SHARED_RATIO. %d/%d pages = ratio of %d for pid %d, versus minimum ratio of %d\n",
			    dirty_private_count, dirty_shared_count, (dirty_private_count / dirty_shared_count),
			    pid_from_task(task), memorystatus_freeze_private_shared_pages_ratio);
			*freezer_error_code = FREEZER_ERROR_LOW_PRIVATE_SHARED_RATIO;
			kr = KERN_FAILURE;
			goto done;
		}

		evaluation_phase = FALSE;
		dirty_shared_count = dirty_private_count = 0;

		freezer_context_global.freezer_ctx_uncompressed_pages = 0;
		clock_get_uptime(&c_freezer_last_yield_ts);

		if (eval_only) {
			kr = KERN_SUCCESS;
			goto done;
		}

		vm_purgeable_purge_task_owned(task);

		goto again;
	} else {
		kr = KERN_SUCCESS;
	}

done:

	if (!eval_only && (kr == KERN_SUCCESS)) {
		vm_object_compressed_freezer_done();
	}
	vmlp_api_end(VM_MAP_FREEZE, kr);
	return kr;
}

#endif

/*
 * vm_map_entry_should_cow_for_true_share:
 *
 * Determines if the map entry should be clipped and setup for copy-on-write
 * to avoid applying "true_share" to a large VM object when only a subset is
 * targeted.
 *
 * For now, we target only the map entries created for the Objective C
 * Garbage Collector, which initially have the following properties:
 *	- alias == VM_MEMORY_MALLOC
 *      - wired_count == 0
 *      - !needs_copy
 * and a VM object with:
 *      - internal
 *      - copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC
 *      - !true_share
 *      - vo_size == ANON_CHUNK_SIZE
 *
 * Only non-kernel map entries.
 */
static bool
vm_map_entry_should_cow_for_true_share(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t    entry)
{
	vm_object_t     object;
	vm_map_t        map = vm_map_lock_ctx_get_map(ctx);
	vm_map_offset_t size;
	vm_map_lock_ctx_bounds(ctx, NULL, NULL, &size);

	if (vm_kernel_map_is_kernel(map)) {
		/*
		 * Don't apply this heuristic to the kernel map.
		 * Nothing there should be malloc tagged anyways
		 */
		return false;
	}

	if (entry->is_sub_map) {
		/* entry does not point at a VM object */
		return FALSE;
	}

	if (entry->needs_copy) {
		/* already set for copy_on_write: done! */
		return FALSE;
	}

	if (VME_ALIAS(entry) != VM_MEMORY_MALLOC &&
	    VME_ALIAS(entry) != VM_MEMORY_MALLOC_SMALL) {
		/* not a malloc heap or Obj-C Garbage Collector heap */
		return FALSE;
	}

	if (entry->wired_count) {
		/* wired: can't change the map entry... */
		vm_counters.should_cow_but_wired++;
		return FALSE;
	}

	object = VME_OBJECT(entry);

	if (object == VM_OBJECT_NULL) {
		/* no object yet... */
		return FALSE;
	}

	if (!object->internal) {
		/* not an internal object */
		return FALSE;
	}

	if (size >= object->vo_size) {
		/*
		 * The size of the request is greater than or equal to the size
		 * of the vm object. There's no point in trying to avoid marking
		 * the whole object true share as it's inevitable it will be.
		 */
		return false;
	}

	if (object->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC) {
		/* not the default copy strategy */
		return FALSE;
	}

	if (object->true_share) {
		/* already true_share: too late to avoid it */
		return FALSE;
	}

	if (VME_ALIAS(entry) == VM_MEMORY_MALLOC &&
	    object->vo_size != ANON_CHUNK_SIZE) {
		/* ... not an object created for the ObjC Garbage Collector */
		return FALSE;
	}

	if (VME_ALIAS(entry) == VM_MEMORY_MALLOC_SMALL &&
	    object->vo_size != 2048 * 4096) {
		/* ... not a "MALLOC_SMALL" heap */
		return FALSE;
	}

	/*
	 * All the criteria match: we have a large object being targeted for "true_share".
	 * To limit the adverse side-effects linked with "true_share", tell the caller to
	 * try and avoid setting up the entire object for "true_share" by clipping the
	 * targeted range and setting it up for copy-on-write.
	 */
	return TRUE;
}

uint64_t vm_map_range_overflows_count = 0;
TUNABLE_WRITEABLE(boolean_t, vm_map_range_overflows_log, "vm_map_range_overflows_log", FALSE);
bool
vm_map_range_overflows(
	vm_map_t map,
	vm_map_offset_t addr,
	vm_map_size_t size)
{
	vm_map_offset_t start, end, sum;
	vm_map_offset_t pgmask;

	if (size == 0) {
		/* empty range -> no overflow */
		return false;
	}
	pgmask = vm_map_page_mask(map);
	start = vm_map_trunc_page_mask(addr, pgmask);
	end = vm_map_round_page_mask(addr + size, pgmask);
	if (__improbable(os_add_overflow(addr, size, &sum) || end <= start)) {
		vm_map_range_overflows_count++;
		if (vm_map_range_overflows_log) {
			printf("%d[%s] vm_map_range_overflows addr 0x%llx size 0x%llx pgmask 0x%llx\n",
			    proc_selfpid(),
			    proc_best_name(current_proc()),
			    (uint64_t)addr,
			    (uint64_t)size,
			    (uint64_t)pgmask);
		}
		DTRACE_VM4(vm_map_range_overflows,
		    vm_map_t, map,
		    uint32_t, pgmask,
		    uint64_t, (uint64_t)addr,
		    uint64_t, (uint64_t)size);
		return true;
	}
	return false;
}

vm_map_offset_t
vm_map_round_page_mask(
	vm_map_offset_t offset,
	vm_map_offset_t mask)
{
	return VM_MAP_ROUND_PAGE(offset, mask);
}

vm_map_offset_t
vm_map_trunc_page_mask(
	vm_map_offset_t offset,
	vm_map_offset_t mask)
{
	return VM_MAP_TRUNC_PAGE(offset, mask);
}

boolean_t
vm_map_page_aligned(
	vm_map_offset_t offset,
	vm_map_offset_t mask)
{
	return ((offset) & mask) == 0;
}

int
vm_map_page_shift(
	vm_map_t map)
{
	return VM_MAP_PAGE_SHIFT(map);
}

int
vm_map_page_size(
	vm_map_t map)
{
	return VM_MAP_PAGE_SIZE(map);
}

vm_map_offset_t
vm_map_page_mask(
	vm_map_t map)
{
	return VM_MAP_PAGE_MASK(map);
}

kern_return_t
vm_map_query_volatile_and_iunlock(
	vm_map_t        map,
	mach_vm_size_t  *volatile_virtual_size_p,
	mach_vm_size_t  *volatile_resident_size_p,
	mach_vm_size_t  *volatile_compressed_size_p,
	mach_vm_size_t  *volatile_pmap_size_p,
	mach_vm_size_t  *volatile_compressed_pmap_size_p)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;
	mach_vm_size_t  volatile_virtual_size;
	mach_vm_size_t  volatile_resident_count;
	mach_vm_size_t  volatile_compressed_count;
	mach_vm_size_t  volatile_pmap_count;
	mach_vm_size_t  volatile_compressed_pmap_count;
	mach_vm_size_t  resident_count;
	vm_map_entry_t  entry;
	vm_object_t     object;


	/* map should be ilocked by caller */
	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);

	volatile_virtual_size = 0;
	volatile_resident_count = 0;
	volatile_compressed_count = 0;
	volatile_pmap_count = 0;
	volatile_compressed_pmap_count = 0;

	kr = vm_map_range_sh_lock(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END,
	    VMRL_SH_STREAM | VMRL_SH_ILK_LOCKED | VMRL_WHOLE_MAP);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	while ((entry = vm_map_range_stream_next(ctx))) {
		mach_vm_size_t  pmap_resident_bytes, pmap_compressed_bytes;

		if (entry->is_sub_map) {
			continue;
		}
		if (!(entry->protection & VM_PROT_WRITE)) {
			continue;
		}
		object = VME_OBJECT(entry);
		if (object == VM_OBJECT_NULL) {
			continue;
		}
		if (object->purgable != VM_PURGABLE_VOLATILE &&
		    object->purgable != VM_PURGABLE_EMPTY) {
			continue;
		}
		if (VME_OFFSET(entry)) {
			/*
			 * If the map entry has been split and the object now
			 * appears several times in the VM map, we don't want
			 * to count the object's resident_page_count more than
			 * once.  We count it only for the first one, starting
			 * at offset 0 and ignore the other VM map entries.
			 */
			continue;
		}
		resident_count = object->resident_page_count;
		if ((VME_OFFSET(entry) / PAGE_SIZE) >= resident_count) {
			resident_count = 0;
		} else {
			resident_count -= (VME_OFFSET(entry) / PAGE_SIZE);
		}

		volatile_virtual_size += entry->vme_end - entry->vme_start;
		volatile_resident_count += resident_count;
		if (object->pager) {
			volatile_compressed_count +=
			    vm_compressor_pager_get_count(object->pager);
		}
		pmap_compressed_bytes = 0;
		pmap_resident_bytes =
		    pmap_query_resident(ctx->vmlc_map->pmap,
		    entry->vme_start,
		    entry->vme_end,
		    &pmap_compressed_bytes);
		volatile_pmap_count += (pmap_resident_bytes / PAGE_SIZE);
		volatile_compressed_pmap_count += (pmap_compressed_bytes
		    / PAGE_SIZE);
	}

	vm_map_range_sh_unlock(ctx, &map);

	*volatile_virtual_size_p = volatile_virtual_size;
	*volatile_resident_size_p = volatile_resident_count * PAGE_SIZE;
	*volatile_compressed_size_p = volatile_compressed_count * PAGE_SIZE;
	*volatile_pmap_size_p = volatile_pmap_count * PAGE_SIZE;
	*volatile_compressed_pmap_size_p = volatile_compressed_pmap_count * PAGE_SIZE;

	return KERN_SUCCESS;
}

void
vm_map_sizes(vm_map_t map,
    vm_map_size_t * psize,
    vm_map_size_t * pfree,
    vm_map_size_t * plargest_free)
{
	vm_map_entry_t  entry;
	vm_map_offset_t prev;
	vm_map_size_t   free, total_free, largest_free;
	kern_return_t   kr;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_SIZES);

	if (!map) {
		*psize = *pfree = *plargest_free = 0;
		vmlp_api_end(VM_MAP_SIZES, 0);
		return;
	}
	total_free = largest_free = 0;

	vm_map_ilk_lock(map);
	if (psize) {
		*psize = map->max_offset - map->min_offset;
	}

	prev = map->min_offset;

	kr = vm_map_range_sh_lock(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END,
	    VMRL_SH_STREAM | VMRL_SH_WHOLE_MAP | VMRL_SH_ILK_LOCKED |
	    VMRL_SH_NO_DESCEND_TRANSPARENT);
	if (kr == KERN_SUCCESS) {
		/* Find the space/free between all the entries in the map */
		while ((entry = vm_map_range_stream_next(ctx))) {
			free = entry->vme_start - prev;

			total_free += free;
			if (free > largest_free) {
				largest_free = free;
			}
			prev = entry->vme_end;
		}
		vm_map_range_sh_unlock(ctx, &map);
	}

	/* And add the space from the end of the map, the last free region */
	vm_map_ilk_lock(map);
	free = vm_map_to_entry(map)->vme_end - prev;
	total_free += free;
	if (free > largest_free) {
		largest_free = free;
	}

	vm_map_ilk_unlock(map);
	if (pfree) {
		*pfree = total_free;
	}
	if (plargest_free) {
		*plargest_free = largest_free;
	}
	vmlp_api_end(VM_MAP_SIZES, 0);
}

#if VM_SCAN_FOR_SHADOW_CHAIN
int
vm_map_shadow_max(
	vm_map_t map)
{
	int             shadows, shadows_max;
	vm_map_entry_t  entry;
	vm_object_t     object, next_object;
	kern_return_t   kr;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_SHADOW_MAX);

	if (map == NULL) {
		vmlp_api_end(VM_MAP_SHADOW_MAX, -1);
		return 0;
	}

	shadows_max = 0;

	kr = vm_map_range_sh_lock(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END,
	    VMRL_SH_STREAM | VMRL_SH_WHOLE_MAP);
	if (kr == KERN_SUCCESS) {
		while ((entry = vm_map_range_stream_next(ctx))) {
			if (entry->is_sub_map) {
				continue;
			}

			object = VME_OBJECT(entry);
			if (object == NULL) {
				continue;
			}
			vm_object_lock_shared(object);
			for (shadows = 0;
			    object->shadow != NULL;
			    shadows++, object = next_object) {
				next_object = object->shadow;
				vm_object_lock_shared(next_object);
				vm_object_unlock(object);
			}
			vm_object_unlock(object);
			if (shadows > shadows_max) {
				shadows_max = shadows;
			}
		}
		vm_map_range_sh_unlock(ctx, &map);
	}

	vmlp_api_end(VM_MAP_SHADOW_MAX, 0);
	return shadows_max;
}
#endif /* VM_SCAN_FOR_SHADOW_CHAIN */

void
vm_commit_pagezero_status(vm_map_t lmap)
{
	pmap_advise_pagezero_range(lmap->pmap, lmap->min_offset);
}

#if __x86_64__
void
vm_map_set_high_start(
	vm_map_t        map,
	vm_map_offset_t high_start)
{
	map->vmmap_high_start = high_start;
}
#endif /* __x86_64__ */

#if CODE_SIGNING_MONITOR

__mockable kern_return_t
vm_map_entry_cs_associate(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_map_kernel_flags_t   vmk_flags)
{
	vm_object_t cs_object, cs_shadow, backing_object;
	vm_object_offset_t cs_offset, backing_offset;
	void *cs_blobs;
	struct vnode *cs_vnode;
	kern_return_t cs_ret;

	if (map->pmap == NULL ||
	    entry->is_sub_map || /* XXX FBDP: recurse on sub-range? */
	    (csm_address_space_exempt(map->pmap) == KERN_SUCCESS) ||
	    VME_OBJECT(entry) == VM_OBJECT_NULL) {
		return KERN_SUCCESS;
	}

	if (!(entry->protection & VM_PROT_EXECUTE)) {
		/*
		 * This memory region is not executable, so the code-signing
		 * monitor would usually not care about it...
		 */
		if (vmk_flags.vmkf_remap_prot_copy &&
		    (entry->max_protection & VM_PROT_EXECUTE)) {
			/*
			 * ... except if the memory region is being remapped
			 * from r-x/r-x to rw-/rwx via vm_protect(VM_PROT_COPY)
			 * which is what a debugger or dtrace would be doing
			 * to prepare to modify an executable page to insert
			 * a breakpoint or activate a probe.
			 * In that case, fall through so that we can mark
			 * this region as being "debugged" and no longer
			 * strictly code-signed.
			 */
		} else {
			/*
			 * Really not executable, so no need to tell the
			 * code-signing monitor.
			 */
			return KERN_SUCCESS;
		}
	}

	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	/*
	 * Check for a debug association mapping before we check for used_for_jit. This
	 * allows non-RWX JIT on macOS systems to masquerade their mappings as USER_DEBUG
	 * pages instead of USER_JIT. These non-RWX JIT pages cannot be marked as USER_JIT
	 * since they are mapped with RW or RX permissions, which the page table monitor
	 * denies on USER_JIT pages. Given that, if they're not mapped as USER_DEBUG,
	 * they will be mapped as USER_EXEC, and that will cause another page table monitor
	 * violation when those USER_EXEC pages are mapped as RW.
	 *
	 * Since these pages switch between RW and RX through mprotect, they mimic what
	 * we expect a debugger to do. As the code signing monitor does not enforce mappings
	 * on macOS systems, this works in our favor here and allows us to continue to
	 * support these legacy-programmed applications without sacrificing security on
	 * the page table or the code signing monitor. We don't need to explicitly check
	 * for entry_for_jit here and the mapping permissions. If the initial mapping is
	 * created with RX, then the application must map it as RW in order to first write
	 * to the page (MAP_JIT mappings must be private and anonymous). The switch to
	 * RX will cause vm_map_protect to mark the entry as vmkf_remap_prot_copy.
	 * Similarly, if the mapping was created as RW, and then switched to RX,
	 * vm_map_protect will again mark the entry as a copy, and both these cases
	 * lead to this if-statement being entered.
	 *
	 * For more information: rdar://115313336.
	 */
	if (vmk_flags.vmkf_remap_prot_copy) {
		cs_ret = csm_associate_debug_region(
			map->pmap,
			entry->vme_start,
			entry->vme_end - entry->vme_start);

		/*
		 * csm_associate_debug_region returns not supported when the code signing
		 * monitor is disabled. This is intentional, since cs_ret is checked towards
		 * the end of the function, and if it is not supported, then we still want the
		 * VM to perform code-signing enforcement on this entry. That said, if we don't
		 * mark this as a xnu_user_debug page when the code-signing monitor is disabled,
		 * then it never gets retyped to XNU_USER_DEBUG frame type, which then causes
		 * an issue with debugging (since it'll be mapped in as XNU_USER_EXEC in some
		 * cases, which will cause a violation when attempted to be mapped as writable).
		 */
		if ((cs_ret == KERN_SUCCESS) || (cs_ret == KERN_NOT_SUPPORTED)) {
			entry->vme_xnu_user_debug = TRUE;
		}
#if DEVELOPMENT || DEBUG
		if (vm_log_xnu_user_debug) {
			printf("FBDP %d[%s] %s:%d map %p entry %p [ 0x%llx 0x%llx ]  vme_xnu_user_debug=%d cs_ret %d\n",
			    proc_selfpid(),
			    (get_bsdtask_info(current_task()) ? proc_name_address(get_bsdtask_info(current_task())) : "?"),
			    __FUNCTION__, __LINE__,
			    map, entry,
			    (uint64_t)entry->vme_start, (uint64_t)entry->vme_end,
			    entry->vme_xnu_user_debug,
			    cs_ret);
		}
#endif /* DEVELOPMENT || DEBUG */
		goto done;
	}

	if (entry->used_for_jit) {
		cs_ret = csm_associate_jit_region(
			map->pmap,
			entry->vme_start,
			entry->vme_end - entry->vme_start);
		goto done;
	}

	cs_object = VME_OBJECT(entry);
	vm_object_lock_shared(cs_object);
	cs_offset = VME_OFFSET(entry);

	/* find the VM object backed by the code-signed vnode */
	for (;;) {
		/* go to the bottom of cs_object's shadow chain */
		for (;
		    cs_object->shadow != VM_OBJECT_NULL;
		    cs_object = cs_shadow) {
			cs_shadow = cs_object->shadow;
			cs_offset += cs_object->vo_shadow_offset;
			vm_object_lock_shared(cs_shadow);
			vm_object_unlock(cs_object);
		}
		if (cs_object->internal ||
		    cs_object->pager == MEMORY_OBJECT_NULL) {
			vm_object_unlock(cs_object);
			return KERN_SUCCESS;
		}

		cs_offset += cs_object->paging_offset;

		/*
		 * cs_object could be backed by a:
		 *      vnode_pager
		 *	apple_protect_pager
		 *      shared_region_pager
		 *	fourk_pager (multiple backing objects -> fail?)
		 * ask the pager if it has a backing VM object
		 */
		if (!memory_object_backing_object(cs_object->pager,
		    cs_offset,
		    &backing_object,
		    &backing_offset)) {
			/* no backing object: cs_object is it */
			break;
		}

		/* look down the backing object's shadow chain */
		vm_object_lock_shared(backing_object);
		vm_object_unlock(cs_object);
		cs_object = backing_object;
		cs_offset = backing_offset;
	}

	cs_vnode = vnode_pager_lookup_vnode(cs_object->pager);
	if (cs_vnode == NULL) {
		/* no vnode, no code signatures to associate */
		cs_ret = KERN_SUCCESS;
	} else {
		cs_ret = vnode_pager_get_cs_blobs(cs_vnode,
		    &cs_blobs);
		assert(cs_ret == KERN_SUCCESS);
		cs_ret = cs_associate_blob_with_mapping(map->pmap,
		    entry->vme_start,
		    (entry->vme_end - entry->vme_start),
		    cs_offset,
		    cs_blobs);
	}
	vm_object_unlock(cs_object);
	cs_object = VM_OBJECT_NULL;

done:
	if (cs_ret == KERN_SUCCESS) {
		DTRACE_VM2(vm_map_entry_cs_associate_success,
		    vm_map_offset_t, entry->vme_start,
		    vm_map_offset_t, entry->vme_end);
		if (vm_map_executable_immutable) {
			/*
			 * Prevent this executable
			 * mapping from being unmapped
			 * or modified.
			 */
			entry->vme_permanent = TRUE;
		}
		/*
		 * pmap says it will validate the
		 * code-signing validity of pages
		 * faulted in via this mapping, so
		 * this map entry should be marked so
		 * that vm_fault() bypasses code-signing
		 * validation for faults coming through
		 * this mapping.
		 */
		entry->csm_associated = TRUE;
	} else if (cs_ret == KERN_NOT_SUPPORTED) {
		/*
		 * pmap won't check the code-signing
		 * validity of pages faulted in via
		 * this mapping, so VM should keep
		 * doing it.
		 */
		DTRACE_VM3(vm_map_entry_cs_associate_off,
		    vm_map_offset_t, entry->vme_start,
		    vm_map_offset_t, entry->vme_end,
		    int, cs_ret);
	} else {
		/*
		 * A real error: do not allow
		 * execution in this mapping.
		 */
		DTRACE_VM3(vm_map_entry_cs_associate_failure,
		    vm_map_offset_t, entry->vme_start,
		    vm_map_offset_t, entry->vme_end,
		    int, cs_ret);
		if (vmk_flags.vmkf_overwrite_immutable) {
			/*
			 * We can get here when we remap an apple_protect pager
			 * on top of an already cs_associated executable mapping
			 * with the same code signatures, so we don't want to
			 * lose VM_PROT_EXECUTE in that case...
			 */
		} else {
			entry->protection &= ~VM_PROT_ALLEXEC;
			entry->max_protection &= ~VM_PROT_ALLEXEC;
		}
	}

	return cs_ret;
}

#endif /* CODE_SIGNING_MONITOR */

inline bool
vm_map_is_corpse_source(vm_map_t map)
{
	bool status = false;
	vmlp_api_start(VM_MAP_IS_CORPSE_SOURCE);
	vmlp_range_event_none(map);
	if (map) {
		vm_map_ilk_lock(map);
		status = map->corpse_source;
		vm_map_ilk_unlock(map);
	}
	vmlp_api_end(VM_MAP_IS_CORPSE_SOURCE, 0);
	return status;
}

inline void
vm_map_set_corpse_source(vm_map_t map)
{
	vmlp_api_start(VM_MAP_SET_CORPSE_SOURCE);
	vmlp_range_event_none(map);
	if (map) {
		vm_map_ilk_lock(map);
		map->corpse_source = true;
		vm_map_ilk_unlock(map);
	}
	vmlp_api_end(VM_MAP_SET_CORPSE_SOURCE, 0);
}

inline void
vm_map_unset_corpse_source(vm_map_t map)
{
	vmlp_api_start(VM_MAP_UNSET_CORPSE_SOURCE);
	vmlp_range_event_none(map);
	if (map) {
		vm_map_ilk_lock(map);
		map->corpse_source = false;
		vm_map_ilk_unlock(map);
	}
	vmlp_api_end(VM_MAP_UNSET_CORPSE_SOURCE, 0);
}
/*
 * FORKED CORPSE FOOTPRINT
 *
 * A forked corpse gets a copy of the original VM map but its pmap is mostly
 * empty since it never ran and never got to fault in any pages.
 * Collecting footprint info (via "sysctl vm.self_region_footprint") for
 * a forked corpse would therefore return very little information.
 *
 * When forking a corpse, we can pass the VM_MAP_FORK_CORPSE_FOOTPRINT option
 * to vm_map_fork() to collect footprint information from the original VM map
 * and its pmap, and store it in the forked corpse's VM map.  That information
 * is stored in place of the VM map's "hole list" since we'll never need to
 * lookup for holes in the corpse's map.
 *
 * The corpse's footprint info looks like this:
 *
 * vm_map->vmmap_corpse_footprint points to pageable kernel memory laid out
 * as follows:
 *                     +---------------------------------------+
 *            header-> | cf_size                               |
 *                     +-------------------+-------------------+
 *                     | cf_last_region    | cf_last_zeroes    |
 *                     +-------------------+-------------------+
 *           region1-> | cfr_vaddr                             |
 *                     +-------------------+-------------------+
 *                     | cfr_num_pages     | d0 | d1 | d2 | d3 |
 *                     +---------------------------------------+
 *                     | d4 | d5 | ...                         |
 *                     +---------------------------------------+
 *                     | ...                                   |
 *                     +-------------------+-------------------+
 *                     | dy | dz | na | na | cfr_vaddr...      | <-region2
 *                     +-------------------+-------------------+
 *                     | cfr_vaddr (ctd)   | cfr_num_pages     |
 *                     +---------------------------------------+
 *                     | d0 | d1 ...                           |
 *                     +---------------------------------------+
 *                       ...
 *                     +---------------------------------------+
 *       last region-> | cfr_vaddr                             |
 *                     +---------------------------------------+
 *                     + cfr_num_pages     | d0 | d1 | d2 | d3 |
 *                     +---------------------------------------+
 *                       ...
 *                     +---------------------------------------+
 *                     | dx | dy | dz | na | na | na | na | na |
 *                     +---------------------------------------+
 *
 * where:
 *      cf_size:	total size of the buffer (rounded to page size)
 *      cf_last_region:	offset in the buffer of the last "region" sub-header
 *	cf_last_zeroes: number of trailing "zero" dispositions at the end
 *			of last region
 *	cfr_vaddr:	virtual address of the start of the covered "region"
 *	cfr_num_pages:	number of pages in the covered "region"
 *	d*:		disposition of the page at that virtual address
 * Regions in the buffer are word-aligned.
 *
 * We estimate the size of the buffer based on the number of memory regions
 * and the virtual size of the address space.  While copying each memory region
 * during vm_map_fork(), we also collect the footprint info for that region
 * and store it in the buffer, packing it as much as possible (coalescing
 * contiguous memory regions to avoid having too many region headers and
 * avoiding long streaks of "zero" page dispositions by splitting footprint
 * "regions", so the number of regions in the footprint buffer might not match
 * the number of memory regions in the address space.
 *
 * We also have to copy the original task's "nonvolatile" ledgers since that's
 * part of the footprint and will need to be reported to any tool asking for
 * the footprint information of the forked corpse.
 */

uint64_t vm_map_corpse_footprint_count = 0;
uint64_t vm_map_corpse_footprint_size_avg = 0;
uint64_t vm_map_corpse_footprint_size_max = 0;
uint64_t vm_map_corpse_footprint_full = 0;
uint64_t vm_map_corpse_footprint_no_buf = 0;

struct vm_map_corpse_footprint_header {
	vm_size_t       cf_size;        /* allocated buffer size */
	uint32_t        cf_last_region; /* offset of last region in buffer */
	union {
		uint32_t cfu_last_zeroes; /* during creation:
		                           * number of "zero" dispositions at
		                           * end of last region */
		uint32_t cfu_hint_region; /* during lookup:
		                           * offset of last looked up region */
#define cf_last_zeroes cfu.cfu_last_zeroes
#define cf_hint_region cfu.cfu_hint_region
	} cfu;
};
typedef uint8_t cf_disp_t;
struct vm_map_corpse_footprint_region {
	vm_map_offset_t cfr_vaddr; /* region start virtual address */
	uint32_t        cfr_num_pages; /* number of pages in this "region" */
	cf_disp_t       cfr_disposition[] __counted_by(cfr_num_pages); /* disposition of each page */
} __attribute__((packed));

static cf_disp_t
vm_page_disposition_to_cf_disp(
	int disposition)
{
	assert(sizeof(cf_disp_t) == 1);
	/* relocate bits that don't fit in a "uint8_t" */
	if (disposition & VM_PAGE_QUERY_PAGE_REUSABLE) {
		disposition |= VM_PAGE_QUERY_PAGE_FICTITIOUS;
	}
	/* cast gets rid of extra bits */
	return (cf_disp_t) disposition;
}

static int
vm_page_cf_disp_to_disposition(
	cf_disp_t cf_disp)
{
	int disposition;

	assert(sizeof(cf_disp_t) == 1);
	disposition = (int) cf_disp;
	/* move relocated bits back in place */
	if (cf_disp & VM_PAGE_QUERY_PAGE_FICTITIOUS) {
		disposition |= VM_PAGE_QUERY_PAGE_REUSABLE;
		disposition &= ~VM_PAGE_QUERY_PAGE_FICTITIOUS;
	}
	return disposition;
}

static kmem_guard_t
vm_map_corpse_footprint_guard(vm_map_t map)
{
	return (kmem_guard_t){
		       .kmg_atomic = true,
		       .kmg_tag = VM_KERN_MEMORY_DIAG,
		       .kmg_context = os_hash_kernel_pointer(&map->vmmap_corpse_footprint),
	};
}

/*
 * vm_map_corpse_footprint_new_region:
 *      closes the current footprint "region" and creates a new one
 *
 * Returns NULL if there's not enough space in the buffer for a new region.
 */
static struct vm_map_corpse_footprint_region *
vm_map_corpse_footprint_new_region(
	struct vm_map_corpse_footprint_header *footprint_header)
{
	uintptr_t       footprint_edge;
	uint32_t        new_region_offset;
	struct vm_map_corpse_footprint_region *footprint_region;
	struct vm_map_corpse_footprint_region *new_footprint_region;

	footprint_edge = ((uintptr_t)footprint_header +
	    footprint_header->cf_size);
	footprint_region = ((struct vm_map_corpse_footprint_region *)
	    ((char *)footprint_header +
	    footprint_header->cf_last_region));
	assert((uintptr_t)footprint_region + sizeof(*footprint_region) <=
	    footprint_edge);

	/* get rid of trailing zeroes in the last region */
	assert(footprint_region->cfr_num_pages >=
	    footprint_header->cf_last_zeroes);
	footprint_region->cfr_num_pages -=
	    footprint_header->cf_last_zeroes;
	footprint_header->cf_last_zeroes = 0;

	/* reuse this region if it's now empty */
	if (footprint_region->cfr_num_pages == 0) {
		return footprint_region;
	}

	/* compute offset of new region */
	new_region_offset = footprint_header->cf_last_region;
	new_region_offset += sizeof(*footprint_region);
	new_region_offset += (footprint_region->cfr_num_pages * sizeof(cf_disp_t));
	new_region_offset = roundup(new_region_offset, sizeof(int));

	/* check if we're going over the edge */
	if (((uintptr_t)footprint_header +
	    new_region_offset +
	    sizeof(*footprint_region)) >=
	    footprint_edge) {
		/* over the edge: no new region */
		return NULL;
	}

	/* adjust offset of last region in header */
	footprint_header->cf_last_region = new_region_offset;

	new_footprint_region = (struct vm_map_corpse_footprint_region *)
	    ((char *)footprint_header +
	    footprint_header->cf_last_region);
	new_footprint_region->cfr_vaddr = 0;
	new_footprint_region->cfr_num_pages = 0;
	/* caller needs to initialize new region */

	return new_footprint_region;
}

TUNABLE(vm_size_t, vm_map_corpse_footprint_max_buffer_size, "vm_cf_max_buf_size",
#if XNU_TARGET_OS_OSX
    MiB(8));
#else /* !XNU_TARGET_OS_OSX */
    KiB(512));
#endif /* XNU_TARGET_OS_OSX */

/*
 * vm_map_corpse_footprint_collect:
 *	collect footprint information for "old_entry" in "old_map" and
 *	stores it in "new_map"'s vmmap_footprint_info.
 */
kern_return_t
vm_map_corpse_footprint_collect(
	vm_map_t        old_map,
	vm_map_entry_t  old_entry,
	vm_map_t        new_map)
{
	vm_map_offset_t va;
	kmem_return_t kmr;
	struct vm_map_corpse_footprint_header *footprint_header;
	struct vm_map_corpse_footprint_region *footprint_region;
	struct vm_map_corpse_footprint_region *new_footprint_region;
	cf_disp_t       *next_disp_p;
	uintptr_t       footprint_edge;
	uint32_t        num_pages_tmp;
	int             effective_page_size;

	assert_vm_map_ilk_owned(old_map, LCK_RW_TYPE_EXCLUSIVE);
	assert_vm_map_ilk_owned(new_map, LCK_RW_TYPE_EXCLUSIVE);
	VM_ENTRY_ASSERT_OWNER(old_entry);

	effective_page_size = MIN(PAGE_SIZE, VM_MAP_PAGE_SIZE(old_map));

	va = old_entry->vme_start;


	assert(new_map->has_corpse_footprint);
	assert(!old_map->has_corpse_footprint);
	if (!new_map->has_corpse_footprint ||
	    old_map->has_corpse_footprint) {
		/*
		 * This can only transfer footprint info from a
		 * map with a live pmap to a map with a corpse footprint.
		 */
		return KERN_NOT_SUPPORTED;
	}

	if (new_map->vmmap_corpse_footprint == NULL) {
		vm_size_t buf_size;

		buf_size = (sizeof(*footprint_header) +
		    (old_map->hdr.nentries
		    *
		    (sizeof(*footprint_region) +
		    +3))            /* potential alignment for each region */
		    +
		    ((old_map->size / effective_page_size)
		    *
		    sizeof(cf_disp_t)));      /* disposition for each page */
		vm_log_debug("corpse map %p guestimate footprint size 0x%llx\n", new_map, (uint64_t)buf_size);
		buf_size = round_page(buf_size);

		/* limit size to a somewhat sane amount */
		if (buf_size > vm_map_corpse_footprint_max_buffer_size) {
			vm_log("WARNING truncating corpse footprint buffer (%lu KiB) to maximum "
			    "size (%lu KiB) -- footprint data may be lost\n",
			    buf_size >> 10, vm_map_corpse_footprint_max_buffer_size >> 10);
			buf_size = vm_map_corpse_footprint_max_buffer_size;
		}
		kmem_guard_t guard = vm_map_corpse_footprint_guard(new_map);
		kmr = kmem_alloc_guard(kernel_map, buf_size + PAGE_SIZE, 0,
		    KMA_DATA | KMA_GUARD_LAST | KMA_KOBJECT | KMA_ZERO,
		    guard);
		if (kmr.kmr_return != KERN_SUCCESS) {
			vm_map_corpse_footprint_no_buf++;
			return kmr.kmr_return;
		}

		/* initialize header and 1st region */
		footprint_header = (struct vm_map_corpse_footprint_header *)kmr.kmr_ptr;
		assert3p(footprint_header, !=, NULL);
		new_map->vmmap_corpse_footprint = footprint_header;

		footprint_header->cf_size = buf_size;
		footprint_header->cf_last_region =
		    sizeof(*footprint_header);
		footprint_header->cf_last_zeroes = 0;

		footprint_region = (struct vm_map_corpse_footprint_region *)
		    ((char *)footprint_header +
		    footprint_header->cf_last_region);
		footprint_region->cfr_vaddr = 0;
		footprint_region->cfr_num_pages = 0;
	} else {
		/* retrieve header and last region */
		footprint_header = (struct vm_map_corpse_footprint_header *)
		    new_map->vmmap_corpse_footprint;
		footprint_region = (struct vm_map_corpse_footprint_region *)
		    ((char *)footprint_header +
		    footprint_header->cf_last_region);
	}
	footprint_edge = ((uintptr_t)footprint_header +
	    footprint_header->cf_size);

	if ((!old_entry->is_sub_map && VME_OBJECT(old_entry) == VM_OBJECT_NULL) ||
	    (old_entry->is_sub_map && !old_entry->use_pmap)) {
		/*
		 * This entry has no vm-object or is a nested pmap and therefore no page
		 * dispositions to record.
		 */
		return KERN_SUCCESS;
	}

	if ((footprint_region->cfr_vaddr +
	    (((vm_map_offset_t)footprint_region->cfr_num_pages) *
	    effective_page_size))
	    != old_entry->vme_start) {
		uint64_t num_pages_delta, num_pages_delta_size;
		uint32_t region_offset_delta_size;

		/*
		 * Not the next contiguous virtual address:
		 * start a new region or store "zero" dispositions for
		 * the missing pages?
		 */
		/* size of gap in actual page dispositions */
		num_pages_delta = ((old_entry->vme_start -
		    footprint_region->cfr_vaddr) / effective_page_size)
		    - footprint_region->cfr_num_pages;
		num_pages_delta_size = num_pages_delta * sizeof(cf_disp_t);
		/* size of gap as a new footprint region header */
		region_offset_delta_size =
		    (sizeof(*footprint_region) +
		    roundup(((footprint_region->cfr_num_pages -
		    footprint_header->cf_last_zeroes) * sizeof(cf_disp_t)),
		    sizeof(int)) -
		    ((footprint_region->cfr_num_pages -
		    footprint_header->cf_last_zeroes) * sizeof(cf_disp_t)));
		DTRACE_VM5(corpse_footprint_collect,
		    uint32_t, footprint_header->cf_last_region,
		    vm_map_offset_t, footprint_region->cfr_vaddr,
		    uint32_t, footprint_region->cfr_num_pages,
		    vm_map_offset_t, old_entry->vme_start,
		    uin64_t, num_pages_delta);
		if (region_offset_delta_size < num_pages_delta_size ||
		    os_add3_overflow(footprint_region->cfr_num_pages,
		    (uint32_t) num_pages_delta,
		    1,
		    &num_pages_tmp)) {
			/*
			 * Storing data for this gap would take more space
			 * than inserting a new footprint region header:
			 * let's start a new region and save space. If it's a
			 * tie, let's avoid using a new region, since that
			 * would require more region hops to find the right
			 * range during lookups.
			 *
			 * If the current region's cfr_num_pages would overflow
			 * if we added "zero" page dispositions for the gap,
			 * no choice but to start a new region.
			 */
			DTRACE_VM3(corpse_footprint_collect_new_region,
			    vm_map_offset_t, old_entry->vme_start,
			    vm_map_offset_t, footprint_region->cfr_vaddr,
			    uint64_t, num_pages_delta);
			new_footprint_region =
			    vm_map_corpse_footprint_new_region(footprint_header);
			/* check that we're not going over the edge */
			if (new_footprint_region == NULL) {
				goto over_the_edge;
			}
			footprint_region = new_footprint_region;
			/* initialize new region as empty */
			footprint_region->cfr_vaddr = old_entry->vme_start;
			footprint_region->cfr_num_pages = 0;
		} else {
			/*
			 * Store "zero" page dispositions for the missing
			 * pages.
			 */
			DTRACE_VM3(corpse_footprint_collect_zero_gap,
			    vm_map_offset_t, old_entry->vme_start,
			    vm_map_offset_t, footprint_region->cfr_vaddr,
			    uint64_t, num_pages_delta);
			for (; num_pages_delta > 0; num_pages_delta--) {
				next_disp_p = (cf_disp_t *)
				    ((uintptr_t) footprint_region +
				    sizeof(*footprint_region));
				next_disp_p += footprint_region->cfr_num_pages;
				/* check that we're not going over the edge */
				if ((uintptr_t)next_disp_p >= footprint_edge) {
					goto over_the_edge;
				}
				/* store "zero" disposition for this gap page */
				footprint_region->cfr_num_pages++;
				*next_disp_p = (cf_disp_t) 0;
				footprint_header->cf_last_zeroes++;
			}
		}
	}

	for (va = old_entry->vme_start;
	    va < old_entry->vme_end;
	    va += effective_page_size) {
		int             disposition;
		cf_disp_t       cf_disp;

		vm_map_footprint_query_page_info(old_map,
		    old_entry,
		    va,
		    &disposition);
		cf_disp = vm_page_disposition_to_cf_disp(disposition);

		DTRACE_VM2(corpse_footprint_collect_page_info,
		    vm_map_offset_t, va,
		    cf_disp_t, cf_disp);

		if (cf_disp == 0 && footprint_region->cfr_num_pages == 0) {
			/*
			 * Ignore "zero" dispositions at start of
			 * region: just move start of region.
			 */
			footprint_region->cfr_vaddr += effective_page_size;
			continue;
		}

		/* would region's cfr_num_pages overflow? */
		if (os_add_overflow(footprint_region->cfr_num_pages, 1,
		    &num_pages_tmp)) {
			/* overflow: create a new region */
			new_footprint_region =
			    vm_map_corpse_footprint_new_region(
				footprint_header);
			if (new_footprint_region == NULL) {
				goto over_the_edge;
			}
			footprint_region = new_footprint_region;
			footprint_region->cfr_vaddr = va;
			footprint_region->cfr_num_pages = 0;
		}

		next_disp_p = (cf_disp_t *) ((uintptr_t) footprint_region +
		    sizeof(*footprint_region));
		next_disp_p += footprint_region->cfr_num_pages;
		/* check that we're not going over the edge */
		if ((uintptr_t)next_disp_p >= footprint_edge) {
			goto over_the_edge;
		}
		/* store this dispostion */
		*next_disp_p = cf_disp;
		footprint_region->cfr_num_pages++;

		if (cf_disp != 0) {
			/* non-zero disp: break the current zero streak */
			footprint_header->cf_last_zeroes = 0;
			/* done */
			continue;
		}

		/* zero disp: add to the current streak of zeroes */
		footprint_header->cf_last_zeroes++;
		if ((footprint_header->cf_last_zeroes +
		    roundup(((footprint_region->cfr_num_pages -
		    footprint_header->cf_last_zeroes) * sizeof(cf_disp_t)) &
		    (sizeof(int) - 1),
		    sizeof(int))) <
		    (sizeof(*footprint_header))) {
			/*
			 * There are not enough trailing "zero" dispositions
			 * (+ the extra padding we would need for the previous
			 * region); creating a new region would not save space
			 * at this point, so let's keep this "zero" disposition
			 * in this region and reconsider later.
			 */
			continue;
		}
		/*
		 * Create a new region to avoid having too many consecutive
		 * "zero" dispositions.
		 */
		new_footprint_region =
		    vm_map_corpse_footprint_new_region(footprint_header);
		if (new_footprint_region == NULL) {
			goto over_the_edge;
		}
		footprint_region = new_footprint_region;
		/* initialize the new region as empty ... */
		footprint_region->cfr_num_pages = 0;
		/* ... and skip this "zero" disp */
		footprint_region->cfr_vaddr = va + effective_page_size;
	}
	return KERN_SUCCESS;

over_the_edge:
	vm_log_error("corpse footprint buffer was exhausted at 0x%llx -- footprint "
	    "data may be lost\n", va);
	vm_map_corpse_footprint_full++;
	return KERN_RESOURCE_SHORTAGE;
}

/*
 * vm_map_corpse_footprint_collect_done:
 *	completes the footprint collection by getting rid of any remaining
 *	trailing "zero" dispositions and trimming the unused part of the
 *	kernel buffer
 */
void
vm_map_corpse_footprint_collect_done(
	vm_map_t        new_map)
{
	struct vm_map_corpse_footprint_header *footprint_header;
	struct vm_map_corpse_footprint_region *footprint_region;
	vm_size_t       buf_size, actual_size;

	assert_vm_map_ilk_owned(new_map, LCK_RW_TYPE_EXCLUSIVE);

	assert(new_map->has_corpse_footprint);
	if (!new_map->has_corpse_footprint ||
	    new_map->vmmap_corpse_footprint == NULL) {
		return;
	}

	footprint_header = (struct vm_map_corpse_footprint_header *)
	    new_map->vmmap_corpse_footprint;
	buf_size = footprint_header->cf_size;

	footprint_region = (struct vm_map_corpse_footprint_region *)
	    ((char *)footprint_header +
	    footprint_header->cf_last_region);

	/* get rid of trailing zeroes in last region */
	assert(footprint_region->cfr_num_pages >= footprint_header->cf_last_zeroes);
	footprint_region->cfr_num_pages -= footprint_header->cf_last_zeroes;
	footprint_header->cf_last_zeroes = 0;

	actual_size = (vm_size_t)(footprint_header->cf_last_region +
	    sizeof(*footprint_region) +
	    (footprint_region->cfr_num_pages * sizeof(cf_disp_t)));

//	printf("FBDP map %p buf_size 0x%llx actual_size 0x%llx\n", new_map, (uint64_t) buf_size, (uint64_t) actual_size);
	vm_map_corpse_footprint_size_avg =
	    (((vm_map_corpse_footprint_size_avg *
	    vm_map_corpse_footprint_count) +
	    actual_size) /
	    (vm_map_corpse_footprint_count + 1));
	vm_map_corpse_footprint_count++;
	if (actual_size > vm_map_corpse_footprint_size_max) {
		vm_map_corpse_footprint_size_max = actual_size;
	}

	actual_size = round_page(actual_size);
	assert3u(buf_size, >=, actual_size);
	if (buf_size > actual_size) {
		/*
		 * Free unused space at the end of the buffer
		 */
		kmem_guard_t guard = vm_map_corpse_footprint_guard(new_map);
		kmem_return_t kmr = kmem_realloc_guard(kernel_map,
		    (vm_offset_t)footprint_header,
		    /* Account for guard page */
		    buf_size + PAGE_SIZE,
		    actual_size + PAGE_SIZE,
		    KMR_DATA | KMR_GUARD_LAST | KMR_FREEOLD | KMR_KOBJECT,
		    guard);
		assertf(kmr.kmr_return == KERN_SUCCESS,
		    "trim: footprint_header %p buf_size 0x%llx actual_size 0x%llx kr=0x%x\n",
		    footprint_header,
		    (uint64_t) buf_size,
		    (uint64_t) actual_size,
		    kmr.kmr_return);
		footprint_header = (struct vm_map_corpse_footprint_header *)kmr.kmr_ptr;
		assert3p(footprint_header, !=, NULL);
		new_map->vmmap_corpse_footprint = footprint_header;
		footprint_region = NULL;
	}

	footprint_header->cf_size = actual_size;
}

/*
 * vm_map_corpse_footprint_query_page_info:
 *	retrieves the disposition of the page at virtual address "vaddr"
 *	in the forked corpse's VM map
 *
 * This is the equivalent of vm_map_footprint_query_page_info() for a forked corpse.
 */
kern_return_t
vm_map_corpse_footprint_query_page_info(
	vm_map_t        map,
	vm_map_offset_t va,
	int             *disposition_p)
{
	struct vm_map_corpse_footprint_header *footprint_header;
	struct vm_map_corpse_footprint_region *footprint_region;
	uint32_t        footprint_region_offset;
	vm_map_offset_t region_start, region_end;
	int             disp_idx;
	kern_return_t   kr;
	int             effective_page_size;
	cf_disp_t       cf_disp;

	vm_map_ilk_lock(map);
	if (!map->has_corpse_footprint) {
		*disposition_p = 0;
		vm_map_ilk_unlock(map);
		kr = KERN_INVALID_ARGUMENT;
		goto done;
	}

	footprint_header = map->vmmap_corpse_footprint;
	if (footprint_header == NULL) {
		*disposition_p = 0;
		vm_map_ilk_unlock(map);
//		if (va < SHARED_REGION_BASE_ARM64) printf("FBDP %d query map %p va 0x%llx disp 0x%x\n", __LINE__, map, va, *disposition_p);
		kr = KERN_INVALID_ARGUMENT;
		goto done;
	}
	vm_map_ilk_unlock(map);

	/* start looking at the hint ("cf_hint_region") */
	footprint_region_offset = footprint_header->cf_hint_region;

	effective_page_size = MIN(PAGE_SIZE, VM_MAP_PAGE_SIZE(map));

lookup_again:
	if (footprint_region_offset < sizeof(*footprint_header)) {
		/* hint too low: start from 1st region */
		footprint_region_offset = sizeof(*footprint_header);
	}
	if (footprint_region_offset > footprint_header->cf_last_region) {
		/* hint too high: re-start from 1st region */
		footprint_region_offset = sizeof(*footprint_header);
	}
	footprint_region = (struct vm_map_corpse_footprint_region *)
	    ((char *)footprint_header + footprint_region_offset);
	region_start = footprint_region->cfr_vaddr;
	region_end = (region_start +
	    ((vm_map_offset_t)(footprint_region->cfr_num_pages) *
	    effective_page_size));
	if (va < region_start &&
	    footprint_region_offset != sizeof(*footprint_header)) {
		/* our range starts before the hint region */

		/* reset the hint (in a racy way...) */
		footprint_header->cf_hint_region = sizeof(*footprint_header);
		/* lookup "va" again from 1st region */
		footprint_region_offset = sizeof(*footprint_header);
		goto lookup_again;
	}

	while (va >= region_end) {
		if (footprint_region_offset >= footprint_header->cf_last_region) {
			break;
		}
		/* skip the region's header */
		footprint_region_offset += sizeof(*footprint_region);
		/* skip the region's page dispositions */
		footprint_region_offset += (footprint_region->cfr_num_pages * sizeof(cf_disp_t));
		/* align to next word boundary */
		footprint_region_offset =
		    roundup(footprint_region_offset,
		    sizeof(int));
		footprint_region = (struct vm_map_corpse_footprint_region *)
		    ((char *)footprint_header + footprint_region_offset);
		region_start = footprint_region->cfr_vaddr;
		region_end = (region_start +
		    ((vm_map_offset_t)(footprint_region->cfr_num_pages) *
		    effective_page_size));
	}
	if (va < region_start || va >= region_end) {
		/* page not found */
		*disposition_p = 0;
//		if (va < SHARED_REGION_BASE_ARM64) printf("FBDP %d query map %p va 0x%llx disp 0x%x\n", __LINE__, map, va, *disposition_p);
		kr = KERN_SUCCESS;
		goto done;
	}

	/* "va" found: set the lookup hint for next lookup (in a racy way...) */
	footprint_header->cf_hint_region = footprint_region_offset;

	/* get page disposition for "va" in this region */
	disp_idx = (int) ((va - footprint_region->cfr_vaddr) / effective_page_size);
	cf_disp = footprint_region->cfr_disposition[disp_idx];
	*disposition_p = vm_page_cf_disp_to_disposition(cf_disp);
	kr = KERN_SUCCESS;
done:
//	if (va < SHARED_REGION_BASE_ARM64) printf("FBDP %d query map %p va 0x%llx disp 0x%x\n", __LINE__, map, va, *disposition_p);
	/* dtrace -n 'vminfo:::footprint_query_page_info { printf("map 0x%p va 0x%llx disp 0x%x kr 0x%x", arg0, arg1, arg2, arg3); }' */
	DTRACE_VM4(footprint_query_page_info,
	    vm_map_t, map,
	    vm_map_offset_t, va,
	    int, *disposition_p,
	    kern_return_t, kr);

	return kr;
}

void
vm_map_corpse_footprint_destroy(
	vm_map_t        map)
{
	if (map->has_corpse_footprint &&
	    map->vmmap_corpse_footprint != NULL) {
		struct vm_map_corpse_footprint_header *footprint_header;
		vm_size_t buf_size;

		footprint_header = map->vmmap_corpse_footprint;
		buf_size = footprint_header->cf_size;
		kmem_guard_t guard = vm_map_corpse_footprint_guard(map);
		kmem_free_guard(kernel_map, (vm_offset_t)footprint_header,
		    buf_size + PAGE_SIZE,
		    KMF_GUARD_LAST, guard);
		map->vmmap_corpse_footprint = NULL;
		map->has_corpse_footprint = FALSE;
	}
}

/*
 * vm_map_copy_footprint_ledgers:
 *	copies any ledger that's relevant to the memory footprint of "old_task"
 *	into the forked corpse's task ("new_task")
 */
void
vm_map_copy_footprint_ledgers(
	task_t  old_task,
	task_t  new_task)
{
	ledger_tab_settle(&task_ledger_template, old_task->ledger);

	vm_map_copy_ledger(old_task, new_task, task_ledgers.phys_footprint);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.purgeable_nonvolatile);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.purgeable_nonvolatile_compress);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.internal);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.internal_compressed);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.iokit_mapped);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.alternate_accounting);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.alternate_accounting_compressed);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.page_table);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.tagged_footprint);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.tagged_footprint_compressed);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.network_nonvolatile);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.network_nonvolatile_compressed);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.media_footprint);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.media_footprint_compressed);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.graphics_footprint);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.graphics_footprint_compressed);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.neural_footprint);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.neural_footprint_compressed);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.wired_mem);
	vm_map_copy_ledger(old_task, new_task, task_ledgers.neural_nofootprint_total);
}

/*
 * vm_map_copy_ledger:
 *	copy a single ledger from "old_task" to "new_task"
 */
void
vm_map_copy_ledger(
	task_t  old_task,
	task_t  new_task,
	int     ledger_entry)
{
	ledger_amount_t old_balance, new_balance, delta;

	assert(new_task->map->has_corpse_footprint);
	if (!new_task->map->has_corpse_footprint) {
		return;
	}

	/* turn off sanity checks for the ledger we're about to mess with */
	ledger_disable_panic_on_negative(new_task->ledger,
	    ledger_entry);

	/* adjust "new_task" to match "old_task" */
	ledger_get_balance(old_task->ledger,
	    ledger_entry, LEO_NO_SETTLE, &old_balance);
	ledger_get_balance(new_task->ledger,
	    ledger_entry, LEO_NO_SETTLE, &new_balance);
	if (new_balance == old_balance) {
		/* new == old: done */
	} else if (new_balance > old_balance) {
		/* new > old ==> new -= new - old */
		delta = new_balance - old_balance;
		ledger_debit(new_task->ledger, ledger_entry, delta);
	} else {
		/* new < old ==> new += old - new */
		delta = old_balance - new_balance;
		ledger_credit(new_task->ledger, ledger_entry, delta);
	}
}

/*
 * vm_map_get_pmap:
 * returns the pmap associated with the vm_map
 */
pmap_t
vm_map_get_pmap(vm_map_t map)
{
	return vm_map_pmap(map);
}

ppnum_t
vm_map_get_phys_page(
	vm_map_t                map,
	vm_offset_t             addr)
{
	vm_object_offset_t      offset;
	vm_object_t             object;
	vm_map_offset_t         map_offset;
	vm_map_entry_t          entry;
	ppnum_t                 phys_page = 0;
	kern_return_t           kr;

	vmlp_api_start(VM_MAP_GET_PHYS_PAGE);

	map_offset = vm_map_trunc_page(addr, PAGE_MASK);

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

restart:
	kr = vm_map_find_entry_sh_locked(ctx, &map, addr, VMRL_FIND_SH_DESCEND_INTO_CONSTANT);
	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_GET_PHYS_PAGE, kr);
		return (ppnum_t) 0;
	}

	entry = vm_map_found_entry_get_entry(ctx);

	if (VME_OBJECT(entry) == VM_OBJECT_NULL) {
		vm_map_found_entry_sh_unlock(ctx, &map);
		vmlp_api_end(VM_MAP_GET_PHYS_PAGE, 0);
		return (ppnum_t) 0;
	}

	if (VME_OBJECT(entry)->phys_contiguous) {
		/* These are  not standard pageable memory mappings */
		/* If they are not present in the object they will  */
		/* have to be picked up from the pager through the  */
		/* fault mechanism.  */
		if (VME_OBJECT(entry)->vo_shadow_offset == 0) {
			/* need to call vm_fault */
			vm_map_found_entry_sh_unlock(ctx, &map);
			vm_fault(map, map_offset, VM_PROT_NONE,
			    FALSE /* change_wiring */, VM_KERN_MEMORY_NONE,
			    THREAD_UNINT, NULL, 0);
			goto restart;
		}
		offset = (VME_OFFSET(entry) + (map_offset - entry->vme_start));
		phys_page = (ppnum_t)
		    ((VME_OBJECT(entry)->vo_shadow_offset
		    + offset) >> PAGE_SHIFT);
		goto unlock_and_return;
	}


	offset = (VME_OFFSET(entry) + (map_offset - entry->vme_start));
	object = VME_OBJECT(entry);
	vm_object_lock(object);
	while (TRUE) {
		vm_page_t dst_page = vm_page_lookup(object, offset);
		if (dst_page == VM_PAGE_NULL) {
			if (object->shadow) {
				vm_object_t old_object;
				vm_object_lock(object->shadow);
				old_object = object;
				offset = offset + object->vo_shadow_offset;
				object = object->shadow;
				vm_object_unlock(old_object);
			} else {
				vm_object_unlock(object);
				goto unlock_and_return;
			}
		} else {
			phys_page = (ppnum_t)(VM_PAGE_GET_PHYS_PAGE(dst_page));
			vm_object_unlock(object);
			goto unlock_and_return;
		}
	}

unlock_and_return:
	vm_map_found_entry_sh_unlock(ctx, &map);

	vmlp_api_end(VM_MAP_GET_PHYS_PAGE, phys_page);
	return phys_page;
}

#if CONFIG_MAP_RANGES
static bitmap_t vm_map_user_range_heap_map[BITMAP_LEN(VM_MEMORY_COUNT)];
static bitmap_t vm_map_user_range_large_file_map[BITMAP_LEN(VM_MEMORY_COUNT)];

static_assert((int)UMEM_RANGE_ID_DEFAULT == MACH_VM_RANGE_DEFAULT);
static_assert((int)UMEM_RANGE_ID_HEAP == MACH_VM_RANGE_DATA);

/*
 * vm_map_range_map_init:
 *  initializes the VM range ID map to enable index lookup
 *  of user VM ranges based on VM tag from userspace.
 */
static void
vm_map_range_map_init(void)
{
	/*
	 * VM_MEMORY_MALLOC{,_NANO} are skipped on purpose:
	 * - the former is malloc metadata which should be kept separate
	 * - the latter has its own ranges
	 */
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_MALLOC_HUGE);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_MALLOC_LARGE);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_MALLOC_LARGE_REUSED);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_MALLOC_MEDIUM);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_MALLOC_PROB_GUARD);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_MALLOC_SMALL);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_MALLOC_TINY);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_TCMALLOC);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_LIBNETWORK);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_IOACCELERATOR);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_IOSURFACE);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_IMAGEIO);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_COREGRAPHICS);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_CORESERVICES);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_COREDATA);
	bitmap_set(vm_map_user_range_heap_map, VM_MEMORY_LAYERKIT);
	bitmap_set(vm_map_user_range_large_file_map, VM_MEMORY_IOACCELERATOR);
	bitmap_set(vm_map_user_range_large_file_map, VM_MEMORY_IOSURFACE);
}

static struct mach_vm_range
vm_map_range_random_uniform(
	vm_map_size_t           req_size,
	vm_map_offset_t         min_addr,
	vm_map_offset_t         max_addr,
	vm_map_offset_t         offmask)
{
	vm_map_offset_t random_addr;
	struct mach_vm_range alloc;

	req_size = (req_size + offmask) & ~offmask;
	min_addr = (min_addr + offmask) & ~offmask;
	max_addr = max_addr & ~offmask;

	read_random(&random_addr, sizeof(random_addr));
	random_addr %= (max_addr - req_size - min_addr);
	random_addr &= ~offmask;

	alloc.min_address = min_addr + random_addr;
	alloc.max_address = min_addr + random_addr + req_size;
	return alloc;
}

static vm_map_offset_t
vm_map_range_offmask(void)
{
	uint32_t pte_depth;

	/*
	 * PTE optimizations
	 *
	 *
	 * 16k pages systems
	 * ~~~~~~~~~~~~~~~~~
	 *
	 * A single L1 (sub-)page covers the address space.
	 * - L2 pages cover 64G,
	 * - L3 pages cover 32M.
	 *
	 * On embedded, the dynamic VA range is 64G and uses a single L2 page.
	 * As a result, we really only need to align the ranges to 32M to avoid
	 * partial L3 pages.
	 *
	 * On macOS, the usage of L2 pages will increase, so as a result we will
	 * want to align ranges to 64G in order to utilize them fully.
	 *
	 *
	 * 4k pages systems
	 * ~~~~~~~~~~~~~~~~
	 *
	 * A single L0 (sub-)page covers the address space.
	 * - L1 pages cover 512G,
	 * - L2 pages cover 1G,
	 * - L3 pages cover 2M.
	 *
	 * The long tail of processes on a system will tend to have a VA usage
	 * (ignoring the shared regions) in the 100s of MB order of magnitnude.
	 * This is achievable with a single L1 and a few L2s without
	 * randomization.
	 *
	 * However once randomization is introduced, the system will immediately
	 * need several L1s and many more L2s. As a result:
	 *
	 * - on embedded devices, the cost of these extra pages isn't
	 *   sustainable, and we just disable the feature entirely,
	 *
	 * - on macOS we align ranges to a 512G boundary so that the extra L1
	 *   pages can be used to their full potential.
	 */

	/*
	 * note, this function assumes _non exotic mappings_
	 * which is why it uses the native kernel's PAGE_SHIFT.
	 */
#if XNU_PLATFORM_MacOSX
	pte_depth = PAGE_SHIFT > 12 ? 2 : 3;
#else /* !XNU_PLATFORM_MacOSX */
	pte_depth = PAGE_SHIFT > 12 ? 1 : 0;
#endif /* !XNU_PLATFORM_MacOSX */

	if (pte_depth == 0) {
		return 0;
	}

	return (1ull << ((PAGE_SHIFT - 3) * pte_depth + PAGE_SHIFT)) - 1;
}

/*
 * vm_map_range_configure:
 *	configures the user vm_map ranges by increasing the maximum VA range of
 *  the map and carving out a range at the end of VA space (searching backwards
 *  in the newly expanded map).
 */
kern_return_t
vm_map_range_configure(vm_map_t map, __unused bool needs_extra_jumbo_va)
{
	const vm_map_offset_t offmask = vm_map_range_offmask();
	vm_map_offset_t       default_end, hole_start, hole_end;
	struct mach_vm_range  data_range;
	vm_map_entry_t        entry;

	vmlp_api_start(VM_MAP_RANGE_CONFIGURE);

	if (!vm_map_is_64bit(map) || vm_map_is_exotic(map) || offmask == 0) {
		/*
		 * No point doing vm ranges in a 32bit address space.
		 */
		vmlp_api_end(VM_MAP_RANGE_CONFIGURE, KERN_NOT_SUPPORTED);
		return KERN_NOT_SUPPORTED;
	}

	/* Should not be applying ranges to kernel map or kernel map submaps */
	assert(vm_map_pmap(map) != kernel_pmap);

#if XNU_PLATFORM_MacOSX

	/*
	 * on macOS, the address space is a massive 47 bits (128T),
	 * with several carve outs that processes can't use:
	 * - the shared region
	 * - the commpage region
	 * - the GPU carve out (if applicable)
	 *
	 * and when nano-malloc is in use it desires memory at the 96T mark.
	 *
	 * However, their location is architecture dependent:
	 * - On intel, the shared region and commpage are
	 *   at the very end of the usable address space (above +127T),
	 *   and there is no GPU carve out, and pthread wants to place
	 *   threads at the 112T mark (0x70T).
	 *
	 * - On arm64, these are in the same spot as on embedded devices:
	 *   o shared region:   [ 6G,  10G)  [ will likely grow over time ]
	 *   o commpage region: [63G,  64G)
	 *   o GPU carve out:   [64G, 448G)
	 *
	 * This is conveninent because the mappings at the end of the address
	 * space (when they exist) are made by the kernel.
	 *
	 * The policy is to allocate a random 1T for the data heap
	 * in the end of the address-space in the:
	 * - [0x71, 0x7f) range on Intel (to leave space for pthread stacks)
	 * - [0x61, 0x7f) range on ASM (to leave space for Nano malloc).
	 */

	/* see NANOZONE_SIGNATURE in libmalloc */
#if __x86_64__
	default_end = 0x71ull << 40;
#else
	default_end = 0x61ull << 40;
#endif
	data_range  = vm_map_range_random_uniform(1ull << 40,
	        default_end, 0x7full << 40, offmask);

#else /* !XNU_PLATFORM_MacOSX */

	/*
	 * Embedded devices:
	 *
	 *   The default VA Size scales with the device physical memory.
	 *
	 *   Out of that:
	 *   - the "zero" page typically uses 4G + some slide
	 *   - the shared region uses SHARED_REGION_SIZE bytes (4G)
	 *
	 *   Without the use of jumbo or any adjustment to the address space,
	 *   a default VM map typically looks like this:
	 *
	 *       0G -->╒════════════╕
	 *             │  pagezero  │
	 *             │  + slide   │
	 *      ~4G -->╞════════════╡<-- vm_map_min(map)
	 *             │            │
	 *       6G -->├────────────┤
	 *             │   shared   │
	 *             │   region   │
	 *      10G -->├────────────┤
	 *             │            │
	 *   max_va -->├────────────┤<-- vm_map_max(map)
	 *             │            │
	 *             ╎   jumbo    ╎
	 *             ╎            ╎
	 *             │            │
	 *      63G -->╞════════════╡<-- MACH_VM_MAX_ADDRESS
	 *             │  commpage  │
	 *      64G -->├────────────┤<-- MACH_VM_MIN_GPU_CARVEOUT_ADDRESS
	 *             │            │
	 *             ╎    GPU     ╎
	 *             ╎  carveout  ╎
	 *             │            │
	 *     448G -->├────────────┤<-- MACH_VM_MAX_GPU_CARVEOUT_ADDRESS
	 *             │            │
	 *             ╎            ╎
	 *             ╎            ╎
	 *             │            │
	 *     512G -->╘════════════╛<-- (1ull << ARM_16K_TT_L1_SHIFT)
	 *
	 *   When this drawing was made, "max_va" was smaller than
	 *   ARM64_MAX_OFFSET_DEVICE_LARGE (~15.5G), leaving shy of
	 *   12G of address space for the zero-page, slide, files,
	 *   binaries, heap ...
	 *
	 *   We will want to make a "heap/data" carve out inside
	 *   the jumbo range of half of that usable space, assuming
	 *   that this is less than a forth of the jumbo range.
	 *
	 *   The assert below intends to catch when max_va grows
	 *   too large for this heuristic.
	 */

	vm_map_ilk_lock(map);
	default_end = vm_map_max(map);
	vm_map_ilk_unlock(map);

	/*
	 * Check that we're not already jumbo'd,
	 * or our address space was somehow modified.
	 *
	 * If so we cannot guarantee that we can set up the ranges
	 * safely without interfering with the existing map.
	 */
	if (default_end > vm_compute_max_offset(true)) {
		vmlp_api_end(VM_MAP_RANGE_CONFIGURE, KERN_NO_SPACE);
		return KERN_NO_SPACE;
	}

	if (pmap_max_offset(true, ARM_PMAP_MAX_OFFSET_DEFAULT)) {
		/*
		 * an override boot-arg was set, disable user-ranges
		 *
		 * XXX: this is problematic because it means these boot-args
		 *      no longer test the behavior changing the value
		 *      of ARM64_MAX_OFFSET_DEVICE_* would have.
		 */
		vmlp_api_end(VM_MAP_RANGE_CONFIGURE, KERN_NOT_SUPPORTED);
		return KERN_NOT_SUPPORTED;
	}

	/* expand the default VM space to 64GB */
	vm_map_set_jumbo(map);

	assert3u(7 * GiB(10) / 2, <=, vm_map_max(map) - default_end);
	data_range = vm_map_range_random_uniform(GiB(10),
	    default_end + PAGE_SIZE, vm_map_max(map), offmask);

#endif /* !XNU_PLATFORM_MacOSX */

	/*
	 * Poke holes so that ASAN or people listing regions
	 * do not think this space is free.
	 */

	vm_map_ilk_lock(map);

	hole_start = default_end;
	hole_end   = data_range.min_address;

	if (hole_start != hole_end) {
		entry = vm_map_entry_create_locked(map, hole_start, hole_end);
		entry->use_pmap       = true;
		entry->vme_permanent  = true;
		entry->protection     = VM_PROT_NONE;
		entry->max_protection = VM_PROT_NONE;
		VME_ALIAS_SET(entry, VM_MEMORY_GUARD);
		vm_map_store_insert(map, entry);
		vm_entry_unlock_exclusive(map, entry);
	}

	hole_start = data_range.max_address;
	hole_end   = hole_start + vm_map_store_lookup_hole(map,
	    hole_start, vm_map_max(map));

	if (hole_start != hole_end) {
		entry = vm_map_entry_create_locked(map, hole_start, hole_end);
		entry->use_pmap       = true;
		entry->vme_permanent  = true;
		entry->protection     = VM_PROT_NONE;
		entry->max_protection = VM_PROT_NONE;
		VME_ALIAS_SET(entry, VM_MEMORY_GUARD);
		vm_map_store_insert(map, entry);
		vm_entry_unlock_exclusive(map, entry);
	}

	vm_map_ilk_unlock(map);

#if XNU_TARGET_OS_IOS && EXTENDED_USER_VA_SUPPORT
	if (needs_extra_jumbo_va) {
		/* This will grow the address space to MACH_VM_MAX_ADDRESS */
		vm_map_set_extra_jumbo(map);
	}
#endif /* XNU_TARGET_OS_IOS && EXTENDED_USER_VA_SUPPORT */

	vm_map_ilk_lock(map);
	map->default_range.min_address = vm_map_min(map);
	map->default_range.max_address = default_end;
	map->data_range = data_range;
#if XNU_TARGET_OS_IOS && EXTENDED_USER_VA_SUPPORT
	/* If process has "extra jumbo" entitlement, enable large file range */
	if (needs_extra_jumbo_va) {
		map->large_file_range = vm_map_range_random_uniform(TiB(1),
		    MACH_VM_JUMBO_ADDRESS, MACH_VM_MAX_ADDRESS, offmask);
	}
#endif /* XNU_TARGET_OS_IOS && EXTENDED_USER_VA_SUPPORT */
	map->uses_user_ranges = true;
	vm_map_ilk_unlock(map);

	vmlp_api_end(VM_MAP_RANGE_CONFIGURE, KERN_SUCCESS);
	return KERN_SUCCESS;
}

/*
 * vm_map_range_fork:
 *	clones the array of ranges from old_map to new_map in support
 *  of a VM map fork.
 */
void
vm_map_range_fork(vm_map_t new_map, vm_map_t old_map)
{
	assert_vm_map_ilk_owned(old_map, LCK_RW_TYPE_EXCLUSIVE);
	assert_vm_map_ilk_owned(new_map, LCK_RW_TYPE_EXCLUSIVE);

	if (!old_map->uses_user_ranges) {
		/* nothing to do */
		return;
	}

	new_map->default_range = old_map->default_range;
	new_map->data_range = old_map->data_range;

	if (old_map->extra_ranges_count) {
		vm_map_user_range_t otable, ntable;
		uint16_t count;

		otable = old_map->extra_ranges;
		count  = old_map->extra_ranges_count;
		ntable = kalloc_data(count * sizeof(struct vm_map_user_range),
		    Z_WAITOK | Z_ZERO | Z_NOFAIL);
		memcpy(ntable, otable,
		    count * sizeof(struct vm_map_user_range));

		new_map->extra_ranges_count = count;
		new_map->extra_ranges = ntable;
	}

	new_map->uses_user_ranges = true;
}

/*
 * vm_map_get_user_range:
 *	copy the VM user range for the given VM map and range ID.
 */
kern_return_t
vm_map_get_user_range(
	vm_map_t                map,
	vm_map_range_id_t       range_id,
	mach_vm_range_t         range)
{
	if (map == NULL || !map->uses_user_ranges || range == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (range_id) {
	case UMEM_RANGE_ID_DEFAULT:
		*range = map->default_range;
		return KERN_SUCCESS;

	case UMEM_RANGE_ID_HEAP:
		*range = map->data_range;
		return KERN_SUCCESS;

	case UMEM_RANGE_ID_LARGE_FILE:
		/*
		 * Because this function tells a user-space process about the user
		 * ranges in its VM map, this case communicates whether the large file
		 * range is in use. Note that this is different from how the large file
		 * range ID is handled in `vm_map_get_range()`: there, we "resolve" the
		 * VA policy and return either the large file range or data range,
		 * depending on whether the large file range is enabled.
		 */
		if (map->large_file_range.min_address != map->large_file_range.max_address) {
			/* large file range is configured and should be used */
			*range = map->large_file_range;
		} else {
			return KERN_INVALID_ARGUMENT;
		}
		return KERN_SUCCESS;

	default:
		return KERN_INVALID_ARGUMENT;
	}
}

static vm_map_range_id_t
vm_map_user_range_resolve(
	vm_map_t                map,
	mach_vm_address_t       addr,
	mach_vm_size_t          size,
	mach_vm_range_t         range)
{
	struct mach_vm_range tmp;

	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);

	static_assert((int)UMEM_RANGE_ID_DEFAULT == MACH_VM_RANGE_DEFAULT);
	static_assert((int)UMEM_RANGE_ID_HEAP == MACH_VM_RANGE_DATA);

	if (mach_vm_range_contains(&map->default_range, addr, size)) {
		if (range) {
			*range = map->default_range;
		}
		return UMEM_RANGE_ID_DEFAULT;
	}

	if (mach_vm_range_contains(&map->data_range, addr, size)) {
		if (range) {
			*range = map->data_range;
		}
		return UMEM_RANGE_ID_HEAP;
	}

	if (mach_vm_range_contains(&map->large_file_range, addr, size)) {
		if (range) {
			*range = map->large_file_range;
		}
		return UMEM_RANGE_ID_LARGE_FILE;
	}

	for (size_t i = 0; i < map->extra_ranges_count; i++) {
		vm_map_user_range_t r = &map->extra_ranges[i];

		tmp.min_address = r->vmur_min_address;
		tmp.max_address = r->vmur_max_address;

		if (mach_vm_range_contains(&tmp, addr, size)) {
			if (range) {
				*range = tmp;
			}
			return r->vmur_range_id;
		}
	}

	if (range) {
		range->min_address = range->max_address = 0;
	}
	return UMEM_RANGE_ID_DEFAULT;
}
#endif /* CONFIG_MAP_RANGES */

void
vm_map_kernel_flags_update_range_id(
	vm_map_kernel_flags_t *vmkf,
	vm_map_t map,
	__unused vm_map_size_t size)
{
	if (map == kernel_map) {
		if (vmkf->vmkf_range_id == KMEM_RANGE_ID_NONE) {
			vmkf->vmkf_range_id = KMEM_RANGE_ID_DATA_SHARED;
		}
#if CONFIG_MAP_RANGES
	} else if (vmkf->vm_tag < VM_MEMORY_COUNT &&
	    vmkf->vmkf_range_id == UMEM_RANGE_ID_DEFAULT) {
		if (bitmap_test(vm_map_user_range_large_file_map, vmkf->vm_tag)
		    || size >= VM_LARGE_FILE_THRESHOLD) {
			/*
			 * if the map doesn't have the large file range configured,
			 * the range will get resolved to the heap range in `vm_map_get_range`
			 */
			vmkf->vmkf_range_id = UMEM_RANGE_ID_LARGE_FILE;
		} else if (bitmap_test(vm_map_user_range_heap_map, vmkf->vm_tag)) {
			vmkf->vmkf_range_id = UMEM_RANGE_ID_HEAP;
		}
#endif /* CONFIG_MAP_RANGES */
	}
}

/*
 * vm_map_entry_has_device_pager:
 * Check if the vm map entry specified by the virtual address has a device pager.
 * If the vm map entry does not exist or if the map is NULL, this returns FALSE.
 */
boolean_t
vm_map_entry_has_device_pager(vm_map_t map, vm_map_offset_t vaddr)
{
	vm_map_entry_t entry;
	vm_object_t object;
	boolean_t result;
	kern_return_t kr;
	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);

	vmlp_api_start(VM_MAP_ENTRY_HAS_DEVICE_PAGER);

	if (map == NULL) {
		vmlp_api_end(VM_MAP_ENTRY_HAS_DEVICE_PAGER, FALSE);
		return FALSE;
	}

	kr = vm_map_find_entry_sh_locked(ctx, &map, vaddr, VMRL_FIND_SH_DESCEND_INTO_CONSTANT);
	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_ENTRY_HAS_DEVICE_PAGER, false);
		return false;
	}

	entry = vm_map_found_entry_get_entry(ctx);
	result = false;
	object = VME_OBJECT(entry);
	if (object != NULL && object->pager != NULL &&
	    is_device_pager_ops(object->pager->mo_pager_ops)) {
		result = true;
	}
	vm_map_found_entry_sh_unlock(ctx, &map);

	vmlp_api_end(VM_MAP_ENTRY_HAS_DEVICE_PAGER, result);
	return result;
}

/*!
 * @abstract
 * Create an entry with PROT_NONE protections in order for sealed submaps
 * to never have any hole, but also never zero fill if accessed.
 */
static void
vm_map_seal_fill_hole(
	vm_map_t                map,
	vm_map_address_t        start,
	vm_map_address_t        end)
{
	vm_map_entry_t new_entry;

	new_entry = vm_map_entry_create_locked(map, start, end);
	new_entry->use_pmap = true;
	new_entry->protection = VM_PROT_NONE;
	new_entry->max_protection = VM_PROT_NONE;

	vm_map_store_insert(map, new_entry);
	vm_entry_lock_invalidate(new_entry, VMEL_INVALID_REASON_SEALED_SUBMAP);
}

void
vm_map_seal(
	vm_map_t map,
	bool nested_pmap)
{
	vm_map_address_t cur  = vm_map_min(map);
	vm_map_offset_t  mask = vm_map_page_mask(map);
	vm_map_entry_t   entry;

	vm_map_ilk_lock(map);

	assert3u(map->vmmap_sealed, ==, VM_MAP_WILL_BE_SEALED);
	if (nested_pmap && map->pmap != PMAP_NULL) {
		map->mapped_in_other_pmaps = true;
	}

	for (entry = vm_map_first_entry(map);
	    entry != vm_map_to_entry(map);
	    entry = entry->vme_next) {
		vm_object_t object;

		if (cur < entry->vme_start) {
			vm_map_seal_fill_hole(map, cur, entry->vme_start);
		}

		assert(!entry->is_sub_map);
		__assert_only bool locked = vm_entry_try_lock_exclusive(entry);
		assert(locked);

		if (VME_OBJECT(entry) == VM_OBJECT_NULL) {
			object = vm_object_allocate(entry->vme_end - entry->vme_start, map->serial_id);
			VME_OBJECT_SET(entry, object, true, 0);
			VME_OFFSET_SET(entry, 0);
			entry->needs_copy = false;
		}

		/* An entry that points to a COPY_SYMMETRIC object may need to change when a shadow object needs to be created.
		 * We stabilize the object pointer here so it doesn't need to be changed later.
		 * If the object is COPY_SYMMETRIC and the entry has needs_copy, create a shadow for it and make that
		 * shadow COPY_DELAY */

		object = VME_OBJECT(entry);
		if (entry->needs_copy) {
			assert(object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC);
			VME_OBJECT_SHADOW(entry, entry->vme_end - entry->vme_start, TRUE);
			entry->needs_copy = FALSE;
			object = VME_OBJECT(entry);
		}
		/* setting is_shared here, otherwise the first time the entry gets shared would want to
		 * set this flag, violating the constness of the entry. */
		entry->is_shared = TRUE;

		vm_object_lock(object);
		if (object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
			object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
			VM_OBJECT_SET_TRUE_SHARE(object, true);
		}
		vm_object_mark_shared(object, VM_SHARE_TYPE_PERMANENT);
		vm_object_unlock(object);
		assert(VME_OBJECT(entry) != VM_OBJECT_NULL);
		assert(VME_OBJECT(entry)->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC);

		vm_entry_lock_invalidate(entry, VMEL_INVALID_REASON_SEALED_SUBMAP);

		cur = entry->vme_end;
	}

	if (cur < vm_map_trunc_page(vm_map_max(map), mask)) {
		vm_map_seal_fill_hole(map, cur,
		    vm_map_trunc_page(vm_map_max(map), mask));
	}

	map->vmmap_sealed = VM_MAP_SEALED;
	vm_map_ilk_unlock_allow_sealed(map);
}


#if DEVELOPMENT || DEBUG

kern_return_t
get_vm_entry_read_count(vm_map_t map, vm_map_offset_t address, uint16_t* read_count)
{
	vm_map_entry_t entry;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	vm_map_ilk_lock(map);
	entry = vm_map_lookup(map, address);
	if (entry == VM_MAP_ENTRY_NULL) {
		vm_map_ilk_unlock(map);
		return KERN_NOT_FOUND;
	}

	/*
	 * Here entry is guaranteed to contain the address
	 * since vm_map_store_lookup_entry() was called with or_next=false
	 * and only returns non-NULL entries that contain the requested address.
	 */
	assert(entry != vm_map_to_entry(map));
	assert(address >= entry->vme_start && address < entry->vme_end);

	vm_entry_lock_t state = os_atomic_load(&entry->vme_lock, relaxed);
	*read_count = state.vmel_read_count;

	vm_map_ilk_unlock(map);
	return KERN_SUCCESS;
}

/*
 * Support functions for userspace tests of constant submaps.
 *
 * Two functions below can be called by userspace via sysctl:
 * vm_map_testing_make_sealed_submap()
 * vm_map_testing_remap_submap()
 *
 * To write a test that uses a submap:
 * 1. Create allocations in your map that will become the new submap's contents.
 * 2. Call vm_map_testing_make_sealed_submap() to replace those
 *    allocations with a submap containing those allocations.
 * 3. Call vm_map_testing_remap_submap() to create additional
 *    mappings of the submap (or portions thereof) in the parent map.
 */

/*
 * Look for a submap mapped in parent_map at submap_base_address.
 * Panic if it is not there.
 */
static void
vm_map_testing_require_submap_at_address(
	vm_map_t                parent_map,
	mach_vm_address_t       address,
	vm_map_t * const        out_submap,
	vm_map_entry_t * const  out_parent_entry)
{
	vm_map_entry_t entry;

	assert_vm_map_ilk_owned(parent_map, LCK_RW_TYPE_ANY);

	entry = vm_map_lookup(parent_map, address);
	assertf(entry != VM_MAP_ENTRY_NULL, "no map entry contains address");
	assertf(entry->vme_start == address,
	    "submap test: submap_base_address is not the start of a map entry");
	assertf(entry->is_sub_map,
	    "submap test: entry at submap_base_address is not a submap");

	if (out_submap) {
		*out_submap = VME_SUBMAP(entry);
	}
	if (out_parent_entry) {
		*out_parent_entry = entry;
	}
}

/*
 * Map a submap into current_map().
 * current_map's submap entry will be at [start, end).
 * The start of the mapping will be at submap_offset in the submap.
 *
 * parent_map's interlock must be locked on entry and is unlocked on exit.
 *
 * For testing purposes only.
 */
static void
vm_map_testing_remap_submap_and_iunlock(
	vm_map_t            parent_map,
	vm_map_t            submap,
	mach_vm_address_t   start,
	mach_vm_address_t   end,
	mach_vm_address_t   submap_offset)
{
	kern_return_t           kr;
	mach_vm_address_t       submap_end_offset;
	mach_vm_address_t       new_start;
	vm_prot_t               cur_prot, max_prot;
	vm_map_kernel_flags_t   vmk_flags;
	bool                    overflowed;

	assert_vm_map_ilk_owned(parent_map, LCK_RW_TYPE_EXCLUSIVE);
	assertf(!vm_kernel_map_is_kernel(parent_map),
	    "submap test: for userspace maps only");
	assertf(!vm_map_is_sealed(parent_map),
	    "submap test: parent map may not be sealed");

	assertf(parent_map != submap,
	    "submap test: parent map and submap must be distinct");
	assertf(!vm_kernel_map_is_kernel(submap),
	    "submap test: submap must not be the kernel map");
	assertf(vm_map_is_sealed(submap),
	    "submap test: submap must be sealed");
	assertf(VM_MAP_PAGE_MASK(parent_map) == VM_MAP_PAGE_MASK(submap),
	    "submap test: parent map and submap must have the same page size");

	assertf((start & VM_MAP_PAGE_MASK(parent_map)) == 0,
	    "submap test: start address must be page-aligned");
	assertf((end & VM_MAP_PAGE_MASK(parent_map)) == 0,
	    "submap test: end address must be page-aligned");
	assertf((submap_offset & VM_MAP_PAGE_MASK(parent_map)) == 0,
	    "submap test: offset in submap must be page-aligned");
	assertf(start < end,
	    "submap test: start must precede end");

	/* submap_end_offset = submap_offset + (end - start) */
	overflowed = os_add_overflow(submap_offset, end - start, &submap_end_offset);
	assertf(!overflowed, "arithmetic overflow in submap_offset + (end - start)");

	/*
	 * The range to be mapped must exist in the submap.
	 * We assume here that a sealed map has no holes.
	 */
	assertf(vm_map_first_entry(submap) != vm_map_to_entry(submap),
	    "submap test: submap must not be empty");
	assertf(vm_map_first_entry(submap)->vme_start <= submap_offset,
	    "submap test: submap range to remap is unmapped in the submap");
	assertf(vm_map_last_entry(submap)->vme_end >= submap_end_offset,
	    "submap test: submap range to remap is unmapped in the submap");

	vmk_flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true);

	/*
	 * Compute protections for the submap's map entry in the parent map.
	 * Copied from vm_shared_region_insert_submap(): we want to do as
	 * many of the same things as real shared region submaps as we can.
	 */
	cur_prot = VM_PROT_READ;
	if (VM_MAP_POLICY_WRITABLE_SHARED_REGION(parent_map)) {
		max_prot = VM_PROT_ALL;
	} else {
		max_prot = VM_PROT_READ;
		vmk_flags.vmf_permanent = true;
	}

	vm_map_reference(submap);  /* to be owned by the parent map entry */
	vm_map_ilk_unlock(parent_map);

	/* Map the submap. */
	new_start = start;
	kr = vm_map_enter(parent_map, &new_start, end - start, 0,
	    vmk_flags, (vm_object_t)(uintptr_t)submap, submap_offset, true /* copy */,
	    cur_prot, max_prot, VM_INHERIT_SHARE /* same as vm_shared_region.c */);
	assertf(kr == KERN_SUCCESS,
	    "submap test: vm_map_enter of submap entry into parent map failed");
	assertf(new_start == start,
	    "submap test: submap entry was inserted at the wrong address");
}

/*
 * Map part of a submap as a new submap entry in parent_map.
 * The submap must already be mapped in its entirety at submap_base_address.
 * The remapping destination is [start..end) in parent_map.
 * The remapping source is [offset, offset + (end-start)) in the submap.
 *
 * For testing purposes only.
 */
void
vm_map_testing_remap_submap(
	vm_map_t            parent_map,
	mach_vm_address_t   submap_base_address,
	mach_vm_address_t   start,
	mach_vm_address_t   end,
	mach_vm_address_t   offset)
{
	vm_map_t        submap;
	vm_map_ilk_lock(parent_map);

	/* Find the submap. It is mapped in parent_map at submap_base_address. */
	vm_map_testing_require_submap_at_address(
		parent_map, submap_base_address, &submap, NULL);

	/* Map the submap as requested. */
	vm_map_testing_remap_submap_and_iunlock(parent_map, submap, start, end, offset);
}

/*
 * Create a new constant/sealed submap. Map it into parent_map at [start, end).
 * The new submap's contents are the map entries initially in the range [start, end).
 * The new submap does not use a nested pmap.
 * On entry: there must be no holes in [start, end).
 *
 * For testing purposes only.
 */
void
vm_map_testing_make_sealed_submap(
	vm_map_t            parent_map,
	mach_vm_address_t   start,
	mach_vm_address_t   end)
{
	kern_return_t           kr;
	vm_map_t                submap;
	vm_map_entry_t          entry;
	vm_map_entry_t          sentinel;
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	VM_MAP_ZAP_DECLARE(zap);
	vm_map_t map = parent_map;

	vm_map_ilk_lock(parent_map);

	assertf(!vm_kernel_map_is_kernel(parent_map),
	    "submap test: for userspace maps only");
	assertf(!vm_map_is_sealed(parent_map),
	    "submap test: parent map may not be sealed");

	assertf((start & VM_MAP_PAGE_MASK(parent_map)) == 0,
	    "submap test: start address must be page-aligned");
	assertf((end & VM_MAP_PAGE_MASK(parent_map)) == 0,
	    "submap test: end address must be page-aligned");
	assertf(start < end,
	    "submap test: start must precede end");

	/*
	 * Create the map that will become the submap.
	 *
	 * Submap's address range starts at 0 to match the real shared region.
	 *
	 * PPL/SPTM allows only one pmap_nested submap per map.
	 * The real shared region gets that, so we can't test pmap nesting.
	 * Instead this submap gets a NULL pmap.
	 */
	submap = vm_map_create_with_page_shift(NULL /* pmap */, 0, end - start,
	    VM_MAP_PAGE_SHIFT(parent_map), VM_MAP_CREATE_DEFAULT);
	assert(submap);
	submap->is_nested_map = true;
	submap->vmmap_sealed = VM_MAP_WILL_BE_SEALED;

	/*
	 * Preflight entries in the parent map:
	 *
	 * Submap entries are disallowed.
	 * Sentinel entries are disallowed.
	 *
	 * Executable or TPRO memory is unimplemented.
	 * Real shared region submaps get vm_map_set_tpro()
	 * and vm_map_cs_enforcement_set(true).
	 */
	/* BEGIN IGNORE CODESTYLE */
	vm_map_lock_ctx_set_preflight(ctx,
	    ^kern_return_t(vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
		assertf(!vme->is_sub_map,
		    "submap test: nested submaps are not allowed");
		assertf(!VME_IS_SENTINEL(vme),
		    "submap test: sentinels are not allowed");
		assertf((vme->protection & VM_PROT_ALLEXEC) == 0,
		    "submap test: executable memory is unimplemented");
		assertf((vme->max_protection & VM_PROT_ALLEXEC) == 0,
		    "submap test: executable memory is unimplemented");
#if __arm64e__
		assertf(!vme->used_for_tpro,
		    "submap test: TPRO memory is unimplemented");
#endif
		return KERN_SUCCESS;
	    });
	/* END IGNORE CODESTYLE */

	/*
	 * Extract map entries from the parent map into a zap list.
	 * Replace them with a sentinel entry in the parent map.
	 * There must be no holes in the parent map range.
	 * Entries must pass the preflight above.
	 *
	 * This is not a copy+delete operation because for testing purposes
	 * we want to preserve as much of the map entry state as possible.
	 * This operation temporarily overrides things like wire count and
	 * permanent, but for testing purposes that is acceptable.
	 */

	/* sentinel initially zero-length, will be extended below */
	sentinel = vm_map_entry_create_sentinel_locked(parent_map, start, start);
	kr = vm_map_range_ex_lock(ctx, &map, start, end,
	    VMRL_EX_ATOMIC /* no holes */ | VMRL_EX_ILK_LOCKED);
	assertf(kr == 0,
	    "submap test: range lock to make submap failed (range might have holes?)");
	while ((entry = vm_map_range_ex_pop(ctx))) {
		assert(ctx->vmlc_map == parent_map);
		vm_map_ilk_lock(parent_map);
		if (VME_OBJECT(entry) != VM_OBJECT_NULL) {
			pmap_remove(parent_map->pmap, entry->vme_start, entry->vme_end);
		}
		vm_map_entry_unlink_and_extend_sentinel(parent_map, entry, sentinel);
		vm_map_ilk_unlock(parent_map);

		/* Destroy the entry's lock. It will be re-inititialized in the submap. */
		vm_entry_unlock_exclusive_and_destroy(parent_map, entry);
		vm_map_zap_append(&zap, entry);
	}
	vm_map_range_ex_unlock(ctx, &map);

	/* Submap's intended range in the parent map is now covered by a locked sentinel. */
	assertf(sentinel->vme_start == start,
	    "submap test: accumulated sentinel did not match the requested range");
	assertf(sentinel->vme_end == end,
	    "submap test: accumulated sentinel did not match the requested range");

	/*
	 * Slide map entries to the submap address range
	 * and insert them into the submap.
	 */
	vm_map_ilk_lock(submap);
	while ((entry = vm_map_zap_pop(&zap))) {
		/* Re-create the lock that we destroyed above. */
		vm_entry_lock_init_locked_exclusive(submap, entry);

		/*
		 * Address `start` in the parent map is address 0 in the submap.
		 * Subtract `start` from the entry's bounds to move it to its
		 * place in the submap.
		 */
		entry->vme_start -= start;
		entry->vme_end -= start;

		vm_map_store_insert(submap, entry);
		vm_entry_unlock_exclusive(submap, entry);
	}
	vm_map_ilk_unlock(submap);

	/* Submap is now populated. Seal it. */
	vm_map_seal(submap, false /* nested_pmap */);

	/*
	 * The submap is not really mapped in other pmaps, but there are
	 * assertions elsewhere that require constant submaps to have this set.
	 */
	submap->mapped_in_other_pmaps = true;

	/*
	 * Map the submap into the parent map at the same range we depopulated.
	 * Overwrites the sentinel entry.
	 */
	vm_map_ilk_lock(parent_map);

	/*
	 * RANGELOCKINGTODO it would be better to replace the sentinel with
	 * the submap entry atomically. Needs refactor of vm_map_enter().
	 * This is for test code only so the race ought to be benign.
	 * rdar://149584081 (Refactor vm_map_enter...)
	 */
	vm_map_store_remove(parent_map, sentinel,
	    VMS_REMOVE_FREE_ENTRY | VMS_REMOVE_FREE_SLOTS);

	vm_map_testing_remap_submap_and_iunlock(parent_map, submap,
	    start, end, /* parent map range */
	    0 /* start offset in the submap we created */);
	vm_map_deallocate(submap);  /* now referenced only by the map entry */
}

#endif  /* DEVELOPMENT || DEBUG */

#if MACH_ASSERT

#define LEDGER_DRIFT(__LEDGER)                    \
	int             __LEDGER##_over;          \
	ledger_amount_t __LEDGER##_over_total;    \
	ledger_amount_t __LEDGER##_over_max;      \
	int             __LEDGER##_under;         \
	ledger_amount_t __LEDGER##_under_total;   \
	ledger_amount_t __LEDGER##_under_max

struct {
	uint64_t        num_pmaps_checked;

	LEDGER_DRIFT(phys_footprint);
	LEDGER_DRIFT(internal);
	LEDGER_DRIFT(internal_compressed);
	LEDGER_DRIFT(external);
	LEDGER_DRIFT(reusable);
	LEDGER_DRIFT(iokit_mapped);
	LEDGER_DRIFT(alternate_accounting);
	LEDGER_DRIFT(alternate_accounting_compressed);
	LEDGER_DRIFT(page_table);
	LEDGER_DRIFT(purgeable_volatile);
	LEDGER_DRIFT(purgeable_nonvolatile);
	LEDGER_DRIFT(purgeable_volatile_compress);
	LEDGER_DRIFT(purgeable_nonvolatile_compress);
	LEDGER_DRIFT(tagged_nofootprint);
	LEDGER_DRIFT(tagged_footprint);
	LEDGER_DRIFT(tagged_nofootprint_compressed);
	LEDGER_DRIFT(tagged_footprint_compressed);
	LEDGER_DRIFT(network_volatile);
	LEDGER_DRIFT(network_nonvolatile);
	LEDGER_DRIFT(network_volatile_compressed);
	LEDGER_DRIFT(network_nonvolatile_compressed);
	LEDGER_DRIFT(media_nofootprint);
	LEDGER_DRIFT(media_footprint);
	LEDGER_DRIFT(media_nofootprint_compressed);
	LEDGER_DRIFT(media_footprint_compressed);
	LEDGER_DRIFT(graphics_nofootprint);
	LEDGER_DRIFT(graphics_footprint);
	LEDGER_DRIFT(graphics_nofootprint_compressed);
	LEDGER_DRIFT(graphics_footprint_compressed);
	LEDGER_DRIFT(neural_nofootprint);
	LEDGER_DRIFT(neural_footprint);
	LEDGER_DRIFT(neural_nofootprint_compressed);
	LEDGER_DRIFT(neural_footprint_compressed);
	LEDGER_DRIFT(neural_nofootprint_total);
} pmap_ledgers_drift;

void
vm_map_pmap_check_ledgers(
	pmap_t          pmap,
	ledger_t        ledger,
	int             pid,
	char            *procname)
{
	ledger_amount_t bal;
	boolean_t       do_panic;

	do_panic = FALSE;

	pmap_ledgers_drift.num_pmaps_checked++;

#define LEDGER_CHECK_BALANCE(__LEDGER)                                  \
MACRO_BEGIN                                                             \
	int panic_on_negative = TRUE;                                   \
	ledger_get_balance(ledger,                                      \
	                   task_ledgers.__LEDGER,                       \
	                   LEO_NO_SETTLE,                               \
	                   &bal);                                       \
	ledger_get_panic_on_negative(ledger,                            \
	                             task_ledgers.__LEDGER,             \
	                             &panic_on_negative);               \
	if (bal != 0) {                                                 \
	        if (panic_on_negative ||                                \
	            (pmap_ledgers_panic &&                              \
	             pmap_ledgers_panic_leeway > 0 &&                   \
	             (bal > (pmap_ledgers_panic_leeway * PAGE_SIZE) ||  \
	              bal < (-pmap_ledgers_panic_leeway * PAGE_SIZE)))) { \
	                do_panic = TRUE;                                \
	        }                                                       \
	        printf("LEDGER BALANCE proc %d (%s) "                   \
	               "\"%s\" = %lld\n",                               \
	               pid, procname, #__LEDGER, bal);                  \
	        if (bal > 0) {                                          \
	                pmap_ledgers_drift.__LEDGER##_over++;           \
	                pmap_ledgers_drift.__LEDGER##_over_total += bal; \
	                if (bal > pmap_ledgers_drift.__LEDGER##_over_max) { \
	                        pmap_ledgers_drift.__LEDGER##_over_max = bal; \
	                }                                               \
	        } else if (bal < 0) {                                   \
	                pmap_ledgers_drift.__LEDGER##_under++;          \
	                pmap_ledgers_drift.__LEDGER##_under_total += bal; \
	                if (bal < pmap_ledgers_drift.__LEDGER##_under_max) { \
	                        pmap_ledgers_drift.__LEDGER##_under_max = bal; \
	                }                                               \
	        }                                                       \
	}                                                               \
MACRO_END

	/*
	 * no need to settle the ledger, if we're destroying the pmap,
	 * it can't have an active ledger.
	 */
	LEDGER_CHECK_BALANCE(phys_footprint);
	LEDGER_CHECK_BALANCE(internal);
	LEDGER_CHECK_BALANCE(internal_compressed);
	LEDGER_CHECK_BALANCE(external);
	LEDGER_CHECK_BALANCE(reusable);
	LEDGER_CHECK_BALANCE(iokit_mapped);
	LEDGER_CHECK_BALANCE(alternate_accounting);
	LEDGER_CHECK_BALANCE(alternate_accounting_compressed);
	LEDGER_CHECK_BALANCE(page_table);
	LEDGER_CHECK_BALANCE(purgeable_volatile);
	LEDGER_CHECK_BALANCE(purgeable_nonvolatile);
	LEDGER_CHECK_BALANCE(purgeable_volatile_compress);
	LEDGER_CHECK_BALANCE(purgeable_nonvolatile_compress);
	LEDGER_CHECK_BALANCE(tagged_nofootprint);
	LEDGER_CHECK_BALANCE(tagged_footprint);
	LEDGER_CHECK_BALANCE(tagged_nofootprint_compressed);
	LEDGER_CHECK_BALANCE(tagged_footprint_compressed);
	LEDGER_CHECK_BALANCE(network_volatile);
	LEDGER_CHECK_BALANCE(network_nonvolatile);
	LEDGER_CHECK_BALANCE(network_volatile_compressed);
	LEDGER_CHECK_BALANCE(network_nonvolatile_compressed);
	LEDGER_CHECK_BALANCE(media_nofootprint);
	LEDGER_CHECK_BALANCE(media_footprint);
	LEDGER_CHECK_BALANCE(media_nofootprint_compressed);
	LEDGER_CHECK_BALANCE(media_footprint_compressed);
	LEDGER_CHECK_BALANCE(graphics_nofootprint);
	LEDGER_CHECK_BALANCE(graphics_footprint);
	LEDGER_CHECK_BALANCE(graphics_nofootprint_compressed);
	LEDGER_CHECK_BALANCE(graphics_footprint_compressed);
	LEDGER_CHECK_BALANCE(neural_nofootprint);
	LEDGER_CHECK_BALANCE(neural_footprint);
	LEDGER_CHECK_BALANCE(neural_nofootprint_compressed);
	LEDGER_CHECK_BALANCE(neural_footprint_compressed);
	LEDGER_CHECK_BALANCE(neural_nofootprint_total);

	if (do_panic) {
		if (pmap_ledgers_panic) {
			panic("pmap_destroy(%p) %d[%s] has imbalanced ledgers",
			    pmap, pid, procname);
		} else {
			printf("pmap_destroy(%p) %d[%s] has imbalanced ledgers\n",
			    pmap, pid, procname);
		}
	}
}

void
vm_map_pmap_set_process(
	vm_map_t map,
	int pid,
	char *procname)
{
	pmap_set_process(vm_map_pmap(map), pid, procname);
}

#endif /* MACH_ASSERT */

__attribute__((always_inline))
vm_size_t
vm_map_kernel_max_simple_mappable_size(void)
{
#ifdef __arm64__
	return (2ULL << 30) - PAGE_SIZE;
#else
	/* No particular size limit */
	return -1;
#endif
}

/**
 * Check if a given given map operation size is valid for the given map, taking
 * in to account whether or not the map operation has overridden the soft limit.
 *
 * This function is meant to be inlined wherever possible as it can, in some
 * modes, generates telemetry events which capture shallow backtraces. To
 * maximize the usefulness of this backtrace, we want to minize the depth at
 * which the backtrace is taken.
 */
__attribute__((always_inline))
bool
vm_map_is_map_size_valid(
	vm_map_t target_map,
	vm_size_t size,
	bool no_soft_limit)
{
#ifdef __x86_64__
	// Do not enforce any additional limits on x64
	(void)target_map;
	(void)size;
	(void)no_soft_limit;
	return true;
#else
	if (__probable(target_map->pmap != kernel_pmap ||
	    size <= vm_map_kernel_max_simple_mappable_size() || no_soft_limit)) {
		// Allocation size matches policy
		return true;
	}

	switch (vm_map_kernel_alloc_limit_mode) {
	default:
	case VM_MAP_KERNEL_ALLOC_LIMIT_MODE_BYPASS:
		return true;
	case VM_MAP_KERNEL_ALLOC_LIMIT_MODE_TRAP:
		trap_telemetry_report_kernel_soft_error(
			TRAP_TELEMETRY_KERNEL_SOFT_ERROR_VM_KERNEL_MAX_ALLOC_SIZE,
			/* report_once_per_site */ false);
		return true;
	case VM_MAP_KERNEL_ALLOC_LIMIT_MODE_REJECT:
		return false;
	case VM_MAP_KERNEL_ALLOC_LIMIT_MODE_PANIC:
		panic("2,000,000K ought to be enough for anybody "
		    "(requested %lu bytes)", size);
	}
#endif /* __x86_64__ */
}

vm_map_serial_t
vm_map_maybe_serial_id(vm_map_t maybe_vm_map)
{
	return maybe_vm_map != NULL ? maybe_vm_map->serial_id : VM_MAP_SERIAL_NONE;
}
