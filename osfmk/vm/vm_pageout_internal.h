/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#ifndef _VM_VM_PAGEOUT_INTERNAL_H_
#define _VM_VM_PAGEOUT_INTERNAL_H_

#include <sys/cdefs.h>
#include <vm/vm_pageout_xnu.h>

__BEGIN_DECLS

#ifdef XNU_KERNEL_PRIVATE

#ifdef MACH_KERNEL_PRIVATE

#define VM_PAGEOUT_GC_INIT      ((void *)0)
#define VM_PAGEOUT_GC_COLLECT   ((void *)1)
extern void vm_pageout_garbage_collect(void *, wait_result_t);

/* UPL exported routines and structures */

#define upl_lock_init(object)   lck_mtx_init(&(object)->Lock, &vm_object_lck_grp, &vm_object_lck_attr)
#define upl_lock_destroy(object)        lck_mtx_destroy(&(object)->Lock, &vm_object_lck_grp)
#define upl_lock(object)        lck_mtx_lock(&(object)->Lock)
#define upl_unlock(object)      lck_mtx_unlock(&(object)->Lock)
#define upl_try_lock(object)    lck_mtx_try_lock(&(object)->Lock)
#define upl_lock_sleep(object, event, thread)                           \
	lck_mtx_sleep_with_inheritor(&(object)->Lock,                   \
	              LCK_SLEEP_DEFAULT,                                \
	              (event_t) (event),                                \
	              (thread),                                         \
	              THREAD_UNINT,                                     \
	              TIMEOUT_WAIT_FOREVER)
#define upl_wakeup(event) wakeup_all_with_inheritor((event), THREAD_AWAKENED)

extern void vm_object_set_pmap_cache_attr(
	vm_object_t             object,
	upl_page_info_array_t   user_page_list,
	unsigned int            num_pages,
	boolean_t               batch_pmap_op);

extern kern_return_t vm_object_iopl_request(
	vm_object_t             object,
	vm_object_offset_t      offset,
	upl_size_t              size,
	upl_t                  *upl_ptr,
	upl_page_info_array_t   user_page_list,
	unsigned int           *page_list_count,
	upl_control_flags_t     cntrl_flags,
	vm_tag_t                tag);

/* should be just a regular vm_map_enter() */
extern kern_return_t vm_map_enter_upl(
	vm_map_t                map,
	upl_t                   upl,
	vm_map_offset_t         *dst_addr);

/* should be just a regular vm_map_remove() */
extern kern_return_t vm_map_remove_upl(
	vm_map_t                map,
	upl_t                   upl);

extern kern_return_t vm_map_enter_upl_range(
	vm_map_t                map,
	upl_t                   upl,
	vm_object_offset_t             offset,
	vm_size_t               size,
	vm_prot_t               prot,
	vm_map_offset_t         *dst_addr);

extern kern_return_t vm_map_remove_upl_range(
	vm_map_t                map,
	upl_t                   upl,
	vm_object_offset_t             offset,
	vm_size_t               size);


extern struct vm_page_delayed_work*
vm_page_delayed_work_get_ctx(void);

extern void
vm_page_delayed_work_finish_ctx(struct vm_page_delayed_work* dwp);

extern void vm_pageout_throttle_up(vm_page_t page);

extern kern_return_t vm_paging_map_object(
	vm_page_t               page,
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_prot_t               protection,
	boolean_t               can_unlock_object,
	vm_map_size_t           *size,          /* IN/OUT */
	vm_map_offset_t         *address,       /* OUT */
	boolean_t               *need_unmap);   /* OUT */
extern void vm_paging_unmap_object(
	vm_object_t             object,
	vm_map_offset_t         start,
	vm_map_offset_t         end);
decl_simple_lock_data(extern, vm_paging_lock);


/*
 * Backing store throttle when BS is exhausted
 */
extern unsigned int    vm_backing_store_low;

extern void vm_pageout_steal_laundry(
	vm_page_t page,
	boolean_t queues_locked);


#endif /* MACH_KERNEL_PRIVATE */

#endif /* XNU_KERNEL_PRIVATE */
__END_DECLS

#endif  /* _VM_VM_PAGEOUT_INTERNAL_H_ */
