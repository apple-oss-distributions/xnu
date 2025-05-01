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
 *	File:	vm_object_xnu.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Virtual memory object module definitions.
 */

#ifndef _VM_VM_OBJECT_XNU_H_
#define _VM_VM_OBJECT_XNU_H_

#ifdef XNU_KERNEL_PRIVATE

#include <kern/queue.h>

#ifdef MACH_KERNEL_PRIVATE

#include <debug.h>
#include <mach_assert.h>

#include <mach/kern_return.h>
#include <mach/boolean.h>
#include <mach/memory_object_types.h>
#include <mach/port.h>
#include <mach/vm_prot.h>
#include <mach/vm_param.h>
#include <mach/machine/vm_types.h>
#include <kern/locks.h>
#include <kern/assert.h>
#include <kern/misc_protos.h>
#include <vm/pmap.h>
#include <vm/vm_external.h>
#include <vm/vm_options.h>
#include <kern/macro_help.h>
#include <ipc/ipc_types.h>
#include <vm/vm_page.h>


struct vm_page;

/*
 *	Types defined:
 *
 *	vm_object_t		Virtual memory object.
 *	vm_object_fault_info_t	Used to determine cluster size.
 */

struct vm_object_fault_info {
	int             interruptible;
	uint32_t        user_tag;
	vm_size_t       cluster_size;
	vm_behavior_t   behavior;
	vm_object_offset_t lo_offset;
	vm_object_offset_t hi_offset;
	unsigned int
	/* boolean_t */ no_cache:1,
	/* boolean_t */ stealth:1,
	/* boolean_t */ io_sync:1,
	/* boolean_t */ cs_bypass:1,
	/* boolean_t */ csm_associated:1,
	/* boolean_t */ mark_zf_absent:1,
	/* boolean_t */ batch_pmap_op:1,
	/* boolean_t */ resilient_media:1,
	/* boolean_t */ no_copy_on_read:1,
	/* boolean_t */ fi_xnu_user_debug:1,
	/* boolean_t */ fi_used_for_tpro:1,
	/* boolean_t */ fi_change_wiring:1,
	/* boolean_t */ fi_no_sleep:1,
	__vm_object_fault_info_unused_bits:19;
	int             pmap_options;
};

#define vo_size                         vo_un1.vou_size
#define vo_cache_pages_to_scan          vo_un1.vou_cache_pages_to_scan
#define vo_shadow_offset                vo_un2.vou_shadow_offset
#define vo_cache_ts                     vo_un2.vou_cache_ts
#define vo_owner                        vo_un2.vou_owner

struct vm_object {
	/*
	 * on 64 bit systems we pack the pointers hung off the memq.
	 * those pointers have to be able to point back to the memq.
	 * the packed pointers are required to be on a 64 byte boundary
	 * which means 2 things for the vm_object...  (1) the memq
	 * struct has to be the first element of the structure so that
	 * we can control it's alignment... (2) the vm_object must be
	 * aligned on a 64 byte boundary... for static vm_object's
	 * this is accomplished via the 'aligned' attribute... for
	 * vm_object's in the zone pool, this is accomplished by
	 * rounding the size of the vm_object element to the nearest
	 * 64 byte size before creating the zone.
	 */
	vm_page_queue_head_t    memq;           /* Resident memory - must be first */
	lck_rw_t                Lock;           /* Synchronization */

	union {
		vm_object_size_t  vou_size;     /* Object size (only valid if internal) */
		int               vou_cache_pages_to_scan;      /* pages yet to be visited in an
		                                                 * external object in cache
		                                                 */
	} vo_un1;

	struct vm_page          *memq_hint;
	os_ref_atomic_t         ref_count;        /* Number of references */
	unsigned int            resident_page_count;
	/* number of resident pages */
	unsigned int            wired_page_count; /* number of wired pages
	                                           *  use VM_OBJECT_WIRED_PAGE_UPDATE macros to update */
	unsigned int            reusable_page_count;

	struct vm_object        *vo_copy;       /* Object that should receive
	                                         * a copy of my changed pages,
	                                         * for copy_delay, or just the
	                                         * temporary object that
	                                         * shadows this object, for
	                                         * copy_call.
	                                         */
	uint32_t                vo_copy_version;
	uint32_t                vo_inherit_copy_none:1,
	    __vo_unused_padding:31;
	struct vm_object        *shadow;        /* My shadow */
	memory_object_t         pager;          /* Where to get data */

	union {
		vm_object_offset_t vou_shadow_offset;   /* Offset into shadow */
		clock_sec_t     vou_cache_ts;   /* age of an external object
		                                 * present in cache
		                                 */
		task_t          vou_owner;      /* If the object is purgeable
		                                 * or has a "ledger_tag", this
		                                 * is the task that owns it.
		                                 */
	} vo_un2;

	vm_object_offset_t      paging_offset;  /* Offset into memory object */
	memory_object_control_t pager_control;  /* Where data comes back */

	memory_object_copy_strategy_t
	    copy_strategy;                      /* How to handle data copy */

	/*
	 * Some user processes (mostly VirtualMachine software) take a large
	 * number of UPLs (via IOMemoryDescriptors) to wire pages in large
	 * VM objects and overflow the 16-bit "activity_in_progress" counter.
	 * Since we never enforced any limit there, let's give them 32 bits
	 * for backwards compatibility's sake.
	 */
	uint16_t                paging_in_progress;
	uint16_t                vo_size_delta;
	uint32_t                activity_in_progress;

	/* The memory object ports are
	 * being used (e.g., for pagein
	 * or pageout) -- don't change
	 * any of these fields (i.e.,
	 * don't collapse, destroy or
	 * terminate)
	 */

	unsigned int
	/* boolean_t array */ all_wanted:7,     /* Bit array of "want to be
	                                         * awakened" notations.  See
	                                         * VM_OBJECT_EVENT_* items
	                                         * below */
	/* boolean_t */ pager_created:1,        /* Has pager been created? */
	/* boolean_t */ pager_initialized:1,    /* Are fields ready to use? */
	/* boolean_t */ pager_ready:1,          /* Will pager take requests? */

	/* boolean_t */ pager_trusted:1,        /* The pager for this object
	                                         * is trusted. This is true for
	                                         * all internal objects (backed
	                                         * by the default pager)
	                                         */
	/* boolean_t */ can_persist:1,          /* The kernel may keep the data
	                                         * for this object (and rights
	                                         * to the memory object) after
	                                         * all address map references
	                                         * are deallocated?
	                                         */
	/* boolean_t */ internal:1,             /* Created by the kernel (and
	                                         * therefore, managed by the
	                                         * default memory manger)
	                                         */
	/* boolean_t */ private:1,              /* magic device_pager object,
	                                        * holds private pages only */
	/* boolean_t */ pageout:1,              /* pageout object. contains
	                                         * private pages that refer to
	                                         * a real memory object. */
	/* boolean_t */ alive:1,                /* Not yet terminated */

	/* boolean_t */ purgable:2,             /* Purgable state.  See
	                                         * VM_PURGABLE_*
	                                         */
	/* boolean_t */ purgeable_only_by_kernel:1,
	/* boolean_t */ purgeable_when_ripe:1,         /* Purgeable when a token
	                                                * becomes ripe.
	                                                */
	/* boolean_t */ shadowed:1,             /* Shadow may exist */
	/* boolean_t */ true_share:1,
	/* This object is mapped
	 * in more than one place
	 * and hence cannot be
	 * coalesced */
	/* boolean_t */ terminating:1,
	/* Allows vm_object_lookup
	 * and vm_object_deallocate
	 * to special case their
	 * behavior when they are
	 * called as a result of
	 * page cleaning during
	 * object termination
	 */
	/* boolean_t */ named:1,                /* An enforces an internal
	                                         * naming convention, by
	                                         * calling the right routines
	                                         * for allocation and
	                                         * destruction, UBC references
	                                         * against the vm_object are
	                                         * checked.
	                                         */
	/* boolean_t */ shadow_severed:1,
	/* When a permanent object
	 * backing a COW goes away
	 * unexpectedly.  This bit
	 * allows vm_fault to return
	 * an error rather than a
	 * zero filled page.
	 */
	/* boolean_t */ phys_contiguous:1,
	/* Memory is wired and
	 * guaranteed physically
	 * contiguous.  However
	 * it is not device memory
	 * and obeys normal virtual
	 * memory rules w.r.t pmap
	 * access bits.
	 */
	/* boolean_t */ nophyscache:1,
	/* When mapped at the
	 * pmap level, don't allow
	 * primary caching. (for
	 * I/O)
	 */
	/* boolean_t */ for_realtime:1,
	/* Might be needed for realtime code path */
	/* vm_object_destroy_reason_t */ no_pager_reason:3,
	/* differentiate known and unknown causes */
#if FBDP_DEBUG_OBJECT_NO_PAGER
	/* boolean_t */ fbdp_tracked:1;
#else /* FBDP_DEBUG_OBJECT_NO_PAGER */
	__object1_unused_bits:1;
#endif /* FBDP_DEBUG_OBJECT_NO_PAGER */

	queue_chain_t           cached_list;    /* Attachment point for the
	                                         * list of objects cached as a
	                                         * result of their can_persist
	                                         * value
	                                         */
	/*
	 * the following fields are not protected by any locks
	 * they are updated via atomic compare and swap
	 */
	vm_object_offset_t      last_alloc;     /* last allocation offset */
	vm_offset_t             cow_hint;       /* last page present in     */
	                                        /* shadow but not in object */
	int                     sequential;     /* sequential access size */

	uint32_t                pages_created;
	uint32_t                pages_used;
	/* hold object lock when altering */
	unsigned        int
	    wimg_bits:8,                /* cache WIMG bits         */
	    code_signed:1,              /* pages are signed and should be
	                                 *  validated; the signatures are stored
	                                 *  with the pager */
	    transposed:1,               /* object was transposed with another */
	    mapping_in_progress:1,      /* pager being mapped/unmapped */
	    phantom_isssd:1,
	    volatile_empty:1,
	    volatile_fault:1,
	    all_reusable:1,
	    blocked_access:1,
	    set_cache_attr:1,
	    object_is_shared_cache:1,
	    purgeable_queue_type:2,
	    purgeable_queue_group:3,
	    io_tracking:1,
	    no_tag_update:1,            /*  */
#if CONFIG_SECLUDED_MEMORY
	    eligible_for_secluded:1,
	    can_grab_secluded:1,
#else /* CONFIG_SECLUDED_MEMORY */
	__object3_unused_bits:2,
#endif /* CONFIG_SECLUDED_MEMORY */
#if VM_OBJECT_ACCESS_TRACKING
	    access_tracking:1,
#else /* VM_OBJECT_ACCESS_TRACKING */
	__unused_access_tracking:1,
#endif /* VM_OBJECT_ACCESS_TRACKING */
	vo_ledger_tag:3,
	    vo_no_footprint:1;

#if VM_OBJECT_ACCESS_TRACKING
	uint32_t        access_tracking_reads;
	uint32_t        access_tracking_writes;
#endif /* VM_OBJECT_ACCESS_TRACKING */

	uint8_t                 scan_collisions;
	uint8_t                 __object4_unused_bits[1];
	vm_tag_t                wire_tag;

#if CONFIG_PHANTOM_CACHE
	uint32_t                phantom_object_id;
#endif
#if CONFIG_IOSCHED || UPL_DEBUG
	queue_head_t            uplq;           /* List of outstanding upls */
#endif

#ifdef  VM_PIP_DEBUG
/*
 * Keep track of the stack traces for the first holders
 * of a "paging_in_progress" reference for this VM object.
 */
#define VM_PIP_DEBUG_STACK_FRAMES       25      /* depth of each stack trace */
#define VM_PIP_DEBUG_MAX_REFS           10      /* track that many references */
	struct __pip_backtrace {
		void *pip_retaddr[VM_PIP_DEBUG_STACK_FRAMES];
	} pip_holders[VM_PIP_DEBUG_MAX_REFS];
#endif  /* VM_PIP_DEBUG  */

	queue_chain_t           objq;      /* object queue - currently used for purgable queues */
	queue_chain_t           task_objq; /* objects owned by task - protected by task lock */

#if !VM_TAG_ACTIVE_UPDATE
	queue_chain_t           wired_objq;
#endif /* !VM_TAG_ACTIVE_UPDATE */

#if DEBUG
	void *purgeable_owner_bt[16];
	task_t vo_purgeable_volatilizer; /* who made it volatile? */
	void *purgeable_volatilizer_bt[16];
#endif /* DEBUG */
};

#define VM_OBJECT_PURGEABLE_FAULT_ERROR(object)                         \
	((object)->volatile_fault &&                                    \
	 ((object)->purgable == VM_PURGABLE_VOLATILE ||                 \
	  (object)->purgable == VM_PURGABLE_EMPTY))

extern const vm_object_t kernel_object_default;  /* the default kernel object */

extern const vm_object_t compressor_object;      /* the single compressor object, allocates pages for compressed
                                                  * buffers (not the segments) */

extern const vm_object_t retired_pages_object;   /* pages retired due to ECC, should never be used */


#define is_kernel_object(object) ((object) == kernel_object_default)


extern const vm_object_t exclaves_object;        /* holds VM pages owned by exclaves */

# define        VM_MSYNC_INITIALIZED                    0
# define        VM_MSYNC_SYNCHRONIZING                  1
# define        VM_MSYNC_DONE                           2


extern lck_grp_t                vm_map_lck_grp;
extern lck_attr_t               vm_map_lck_attr;

/** os_refgrp_t for vm_objects */
os_refgrp_decl_extern(vm_object_refgrp);

#ifndef VM_TAG_ACTIVE_UPDATE
#error VM_TAG_ACTIVE_UPDATE
#endif

#if VM_TAG_ACTIVE_UPDATE
#define VM_OBJECT_WIRED_ENQUEUE(object) panic("VM_OBJECT_WIRED_ENQUEUE")
#define VM_OBJECT_WIRED_DEQUEUE(object) panic("VM_OBJECT_WIRED_DEQUEUE")
#else /* VM_TAG_ACTIVE_UPDATE */
#define VM_OBJECT_WIRED_ENQUEUE(object)                                 \
	MACRO_BEGIN                                                     \
	lck_spin_lock_grp(&vm_objects_wired_lock, &vm_page_lck_grp_bucket);                          \
	assert(!(object)->wired_objq.next);                             \
	assert(!(object)->wired_objq.prev);                             \
	queue_enter(&vm_objects_wired, (object),                        \
	            vm_object_t, wired_objq);                           \
	lck_spin_unlock(&vm_objects_wired_lock);                        \
	MACRO_END
#define VM_OBJECT_WIRED_DEQUEUE(object)                                 \
	MACRO_BEGIN                                                     \
	if ((object)->wired_objq.next) {                                \
	        lck_spin_lock_grp(&vm_objects_wired_lock, &vm_page_lck_grp_bucket);                  \
	        queue_remove(&vm_objects_wired, (object),               \
	                     vm_object_t, wired_objq);                  \
	        lck_spin_unlock(&vm_objects_wired_lock);                \
	}                                                               \
	MACRO_END
#endif /* VM_TAG_ACTIVE_UPDATE */

#define VM_OBJECT_WIRED(object, tag)                                    \
    MACRO_BEGIN                                                         \
    assert(VM_KERN_MEMORY_NONE != (tag));                               \
    assert(VM_KERN_MEMORY_NONE == (object)->wire_tag);                  \
    (object)->wire_tag = (tag);                                         \
    if (!VM_TAG_ACTIVE_UPDATE) {                                        \
	VM_OBJECT_WIRED_ENQUEUE((object));                              \
    }                                                                   \
    MACRO_END

#define VM_OBJECT_UNWIRED(object)                                                       \
    MACRO_BEGIN                                                                         \
    if (!VM_TAG_ACTIVE_UPDATE) {                                                        \
	    VM_OBJECT_WIRED_DEQUEUE((object));                                          \
    }                                                                                   \
    if (VM_KERN_MEMORY_NONE != (object)->wire_tag) {                                    \
	vm_tag_update_size((object)->wire_tag, -ptoa_64((object)->wired_page_count), (object));   \
	(object)->wire_tag = VM_KERN_MEMORY_NONE;                                       \
    }                                                                                   \
    MACRO_END

// These two macros start & end a C block
#define VM_OBJECT_WIRED_PAGE_UPDATE_START(object)                                       \
    MACRO_BEGIN                                                                         \
    {                                                                                   \
	int64_t __wireddelta = 0; vm_tag_t __waswired = (object)->wire_tag;

#define VM_OBJECT_WIRED_PAGE_UPDATE_END(object, tag)                                    \
	if (__wireddelta) {                                                             \
	    boolean_t __overflow __assert_only =                                        \
	    os_add_overflow((object)->wired_page_count, __wireddelta,                   \
	                    &(object)->wired_page_count);                               \
	    assert(!__overflow);                                                        \
	    if (!(object)->internal &&                                  \
	        (object)->vo_ledger_tag &&                              \
	        VM_OBJECT_OWNER((object)) != NULL) {                    \
	            vm_object_wired_page_update_ledgers(object, __wireddelta); \
	    }                                                           \
	    if (!(object)->pageout && !(object)->no_tag_update) {                       \
	        if (__wireddelta > 0) {                                                 \
	            assert (VM_KERN_MEMORY_NONE != (tag));                              \
	            if (VM_KERN_MEMORY_NONE == __waswired) {                            \
	                VM_OBJECT_WIRED((object), (tag));                               \
	            }                                                                   \
	            vm_tag_update_size((object)->wire_tag, ptoa_64(__wireddelta), (object));      \
	        } else if (VM_KERN_MEMORY_NONE != __waswired) {                         \
	            assert (VM_KERN_MEMORY_NONE != (object)->wire_tag);                 \
	            vm_tag_update_size((object)->wire_tag, ptoa_64(__wireddelta), (object));      \
	            if (!(object)->wired_page_count) {                                  \
	                VM_OBJECT_UNWIRED((object));                                    \
	            }                                                                   \
	        }                                                                       \
	    }                                                                           \
	}                                                                               \
    }                                                                                   \
    MACRO_END

#define VM_OBJECT_WIRED_PAGE_COUNT(object, delta)               \
    __wireddelta += delta; \

#define VM_OBJECT_WIRED_PAGE_ADD(object, m)                     \
    if (vm_page_is_canonical(m)) __wireddelta++;

#define VM_OBJECT_WIRED_PAGE_REMOVE(object, m)                  \
    if (vm_page_is_canonical(m)) __wireddelta--;

#define OBJECT_LOCK_SHARED      0
#define OBJECT_LOCK_EXCLUSIVE   1

extern lck_grp_t        vm_object_lck_grp;
extern lck_attr_t       vm_object_lck_attr;
extern lck_attr_t       kernel_object_lck_attr;
extern lck_attr_t       compressor_object_lck_attr;

extern vm_object_t      vm_pageout_scan_wants_object;

extern void             vm_object_lock(vm_object_t);
extern bool             vm_object_lock_check_contended(vm_object_t);
extern boolean_t        vm_object_lock_try(vm_object_t);
extern boolean_t        _vm_object_lock_try(vm_object_t);
extern boolean_t        vm_object_lock_avoid(vm_object_t);
extern void             vm_object_lock_shared(vm_object_t);
extern boolean_t        vm_object_lock_yield_shared(vm_object_t);
extern boolean_t        vm_object_lock_try_shared(vm_object_t);
extern void             vm_object_unlock(vm_object_t);
extern boolean_t        vm_object_lock_upgrade(vm_object_t);

extern void             kdp_vm_object_sleep_find_owner(
	event64_t          wait_event,
	block_hint_t       wait_type,
	thread_waitinfo_t *waitinfo);

#endif /* MACH_KERNEL_PRIVATE */

#if CONFIG_IOSCHED
struct io_reprioritize_req {
	uint64_t        blkno;
	uint32_t        len;
	int             priority;
	struct vnode    *devvp;
	struct mpsc_queue_chain iorr_elm;
};
typedef struct io_reprioritize_req *io_reprioritize_req_t;

extern void vm_io_reprioritize_init(void);
#endif

extern void page_worker_init(void);


#endif /* XNU_KERNEL_PRIVATE */

#endif  /* _VM_VM_OBJECT_XNU_H_ */
