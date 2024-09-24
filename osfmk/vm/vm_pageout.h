/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 *	File:	vm/vm_pageout.h
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Declarations for the pageout daemon interface.
 */

#ifndef _VM_VM_PAGEOUT_H_
#define _VM_VM_PAGEOUT_H_

#ifdef  KERNEL_PRIVATE

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/machine/vm_types.h>
#include <mach/memory_object_types.h>

#include <kern/kern_types.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>
#include <kern/bits.h>

#include <libkern/OSAtomic.h>


#include <vm/vm_options.h>

#ifdef  MACH_KERNEL_PRIVATE
#include <vm/vm_page.h>
#endif

#include <sys/kdebug.h>

#define VM_PAGE_AVAILABLE_COUNT()               ((unsigned int)(vm_page_cleaned_count))

/* externally manipulated counters */
extern unsigned int vm_pageout_cleaned_fault_reactivated;

#if CONFIG_FREEZE
extern boolean_t memorystatus_freeze_enabled;

struct freezer_context {
	/*
	 * All these counters & variables track the task
	 * being frozen.
	 * Currently we only freeze one task at a time. Should that
	 * change, we'll need to add support for multiple freezer contexts.
	 */

	task_t  freezer_ctx_task; /* Task being frozen. */

	void    *freezer_ctx_chead; /* The chead used to track c_segs allocated */
	                            /* to freeze the task.*/

	uint64_t        freezer_ctx_swapped_bytes; /* Tracks # of compressed bytes.*/

	int     freezer_ctx_uncompressed_pages; /* Tracks # of uncompressed pages frozen. */

	char    *freezer_ctx_compressor_scratch_buf; /* Scratch buffer for the compressor algorithm. */
};

#endif /* CONFIG_FREEZE */

#define VM_DYNAMIC_PAGING_ENABLED() (VM_CONFIG_COMPRESSOR_IS_ACTIVE)

#if VM_PRESSURE_EVENTS
extern boolean_t vm_pressure_events_enabled;
#endif /* VM_PRESSURE_EVENTS */

extern int      vm_debug_events;

#define VM_DEBUG_EVENT(name, event, control, ...)    \
	MACRO_BEGIN                                             \
	if (__improbable(vm_debug_events)) {                    \
	        KDBG_FILTERED((VMDBG_CODE(event)) | control, __VA_ARGS__); \
	}                                                       \
	MACRO_END

#define VM_DEBUG_CONSTANT_EVENT(name, event, control, ...)   \
	MACRO_BEGIN                                             \
	        KDBG((VMDBG_CODE(event)) | control, __VA_ARGS__); \
	MACRO_END

extern upl_size_t upl_get_size(
	upl_t                   upl);


extern kern_return_t    mach_vm_pressure_level_monitor(boolean_t wait_for_pressure, unsigned int *pressure_level);
#if KERNEL_PRIVATE
extern kern_return_t    mach_vm_wire_level_monitor(int64_t requested_pages);
#endif /* KERNEL_PRIVATE */



#if UPL_DEBUG
extern kern_return_t  upl_ubc_alias_set(
	upl_t upl,
	uintptr_t alias1,
	uintptr_t alias2);
extern int  upl_ubc_alias_get(
	upl_t upl,
	uintptr_t * al,
	uintptr_t * al2);
#endif /* UPL_DEBUG */

extern void vm_countdirtypages(void);

extern kern_return_t upl_transpose(
	upl_t   upl1,
	upl_t   upl2);

extern kern_return_t mach_vm_pressure_monitor(
	boolean_t       wait_for_pressure,
	unsigned int    nsecs_monitored,
	unsigned int    *pages_reclaimed_p,
	unsigned int    *pages_wanted_p);

extern kern_return_t
vm_set_buffer_cleanup_callout(
	boolean_t       (*func)(int));

struct vm_page_stats_reusable {
	SInt32          reusable_count;
	uint64_t        reusable;
	uint64_t        reused;
	uint64_t        reused_wire;
	uint64_t        reused_remove;
	uint64_t        all_reusable_calls;
	uint64_t        partial_reusable_calls;
	uint64_t        all_reuse_calls;
	uint64_t        partial_reuse_calls;
	uint64_t        reusable_pages_success;
	uint64_t        reusable_pages_failure;
	uint64_t        reusable_pages_shared;
	uint64_t        reuse_pages_success;
	uint64_t        reuse_pages_failure;
	uint64_t        can_reuse_success;
	uint64_t        can_reuse_failure;
	uint64_t        reusable_reclaimed;
	uint64_t        reusable_nonwritable;
	uint64_t        reusable_shared;
	uint64_t        free_shared;
};
extern struct vm_page_stats_reusable vm_page_stats_reusable;

extern int hibernate_flush_memory(void);
extern void hibernate_reset_stats(void);
extern void hibernate_create_paddr_map(void);

extern void vm_set_restrictions(unsigned int num_cpus);

extern int vm_compressor_mode;
extern kern_return_t vm_pageout_compress_page(void **, char *, vm_page_t);
extern kern_return_t vm_pageout_anonymous_pages(void);
extern void vm_pageout_disconnect_all_pages(void);
extern int vm_toggle_task_selfdonate_pages(task_t);
extern void vm_task_set_selfdonate_pages(task_t, bool);

struct  vm_config {
	boolean_t       compressor_is_present;          /* compressor is initialized and can be used by the freezer, the sweep or the pager */
	boolean_t       compressor_is_active;           /* pager can actively compress pages...  'compressor_is_present' must be set */
	boolean_t       swap_is_present;                /* swap is initialized and can be used by the freezer, the sweep or the pager */
	boolean_t       swap_is_active;                 /* pager can actively swap out compressed segments... 'swap_is_present' must be set */
	boolean_t       freezer_swap_is_active;         /* freezer can swap out frozen tasks... "compressor_is_present + swap_is_present" must be set */
};

extern  struct vm_config        vm_config;


#define VM_PAGER_NOT_CONFIGURED                         0x0     /* no compresser or swap configured */
#define VM_PAGER_DEFAULT                                0x1     /* Use default pager... DEPRECATED */
#define VM_PAGER_COMPRESSOR_NO_SWAP                     0x2     /* Active in-core compressor only. */
#define VM_PAGER_COMPRESSOR_WITH_SWAP                   0x4     /* Active in-core compressor + swap backend. */
#define VM_PAGER_FREEZER_DEFAULT                        0x8     /* Freezer backed by default pager... DEPRECATED */
#define VM_PAGER_FREEZER_COMPRESSOR_NO_SWAP             0x10    /* Freezer backed by in-core compressor only i.e. frozen data remain in-core compressed.*/
#define VM_PAGER_COMPRESSOR_NO_SWAP_PLUS_FREEZER_COMPRESSOR_WITH_SWAP   0x20    /* Active in-core compressor + Freezer backed by in-core compressor with swap support too.*/

#define VM_PAGER_MAX_MODES                              6       /* Total number of vm compressor modes supported */


#define VM_CONFIG_COMPRESSOR_IS_PRESENT         (vm_config.compressor_is_present == TRUE)
#define VM_CONFIG_COMPRESSOR_IS_ACTIVE          (vm_config.compressor_is_active == TRUE)
#define VM_CONFIG_SWAP_IS_PRESENT               (vm_config.swap_is_present == TRUE)
#define VM_CONFIG_SWAP_IS_ACTIVE                (vm_config.swap_is_active == TRUE)
#define VM_CONFIG_FREEZER_SWAP_IS_ACTIVE        (vm_config.freezer_swap_is_active == TRUE)

#endif  /* KERNEL_PRIVATE */


#endif  /* _VM_VM_PAGEOUT_H_ */
