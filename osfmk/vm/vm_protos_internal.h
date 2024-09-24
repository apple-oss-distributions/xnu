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

#ifndef _VM_VM_PROTOS_INTERNAL_H_
#define _VM_VM_PROTOS_INTERNAL_H_

#include <sys/cdefs.h>
#include <vm/vm_protos.h>

__BEGIN_DECLS

#ifdef XNU_KERNEL_PRIVATE

extern kern_return_t
vnode_pager_get_object_vnode(
	memory_object_t mem_obj,
	uintptr_t * vnodeaddr,
	uint32_t * vid);

#if CONFIG_CODE_DECRYPTION
extern memory_object_t apple_protect_pager_setup(
	vm_object_t             backing_object,
	vm_object_offset_t      backing_offset,
	vm_object_offset_t      crypto_backing_offset,
	struct pager_crypt_info *crypt_info,
	vm_object_offset_t      crypto_start,
	vm_object_offset_t      crypto_end,
	boolean_t               cache_pager);
#endif /* CONFIG_CODE_DECRYPTION */

extern memory_object_t shared_region_pager_setup(
	vm_object_t             backing_object,
	vm_object_offset_t      backing_offset,
	struct vm_shared_region_slide_info *slide_info,
	uint64_t                jop_key);

extern uint64_t apple_protect_pager_purge_all(void);
extern uint64_t shared_region_pager_purge_all(void);
extern uint64_t dyld_pager_purge_all(void);

#if __has_feature(ptrauth_calls)
extern memory_object_t shared_region_pager_match(
	vm_object_t             backing_object,
	vm_object_offset_t      backing_offset,
	struct vm_shared_region_slide_info *slide_info,
	uint64_t                jop_key);

extern void shared_region_pager_match_task_key(memory_object_t memobj, task_t task);
#endif /* __has_feature(ptrauth_calls) */

extern void vnode_pager_was_dirtied(
	struct vnode *,
	vm_object_offset_t,
	vm_object_offset_t);

extern uint32_t vnode_trim(struct vnode *, int64_t offset, unsigned long len);

extern vm_object_offset_t vnode_pager_get_filesize(
	struct vnode *);
extern uint32_t vnode_pager_isinuse(
	struct vnode *);
extern boolean_t vnode_pager_isSSD(
	struct vnode *);
#if FBDP_DEBUG_OBJECT_NO_PAGER
extern bool vnode_pager_forced_unmount(
	struct vnode *);
#endif /* FBDP_DEBUG_OBJECT_NO_PAGER */
extern void vnode_pager_throttle(
	void);
extern uint32_t vnode_pager_return_throttle_io_limit(
	struct vnode *,
	uint32_t     *);
extern kern_return_t vnode_pager_get_name(
	struct vnode    *vp,
	char            *pathname,
	vm_size_t       pathname_len,
	char            *filename,
	vm_size_t       filename_len,
	boolean_t       *truncated_path_p);
struct timespec;
extern kern_return_t vnode_pager_get_mtime(
	struct vnode    *vp,
	struct timespec *mtime,
	struct timespec *cs_mtime);
extern kern_return_t vnode_pager_get_cs_blobs(
	struct vnode    *vp,
	void            **blobs);

#if CONFIG_IOSCHED
void vnode_pager_issue_reprioritize_io(
	struct vnode    *devvp,
	uint64_t        blkno,
	uint32_t        len,
	int             priority);
#endif

extern kern_return_t vnode_pager_get_object_size(
	memory_object_t,
	memory_object_offset_t *);

extern void vnode_pager_dirtied(
	memory_object_t,
	vm_object_offset_t,
	vm_object_offset_t);
extern kern_return_t vnode_pager_get_isinuse(
	memory_object_t,
	uint32_t *);
extern kern_return_t vnode_pager_get_isSSD(
	memory_object_t,
	boolean_t *);
#if FBDP_DEBUG_OBJECT_NO_PAGER
extern kern_return_t vnode_pager_get_forced_unmount(
	memory_object_t,
	bool *);
#endif /* FBDP_DEBUG_OBJECT_NO_PAGER */
extern kern_return_t vnode_pager_get_throttle_io_limit(
	memory_object_t,
	uint32_t *);
extern kern_return_t vnode_pager_get_object_name(
	memory_object_t mem_obj,
	char            *pathname,
	vm_size_t       pathname_len,
	char            *filename,
	vm_size_t       filename_len,
	boolean_t       *truncated_path_p);
struct timespec;
extern kern_return_t vnode_pager_get_object_mtime(
	memory_object_t mem_obj,
	struct timespec *mtime,
	struct timespec *cs_mtime);

#if CHECK_CS_VALIDATION_BITMAP
extern kern_return_t vnode_pager_cs_check_validation_bitmap(
	memory_object_t mem_obj,
	memory_object_offset_t  offset,
	int             optype);
#endif /* CHECK_CS_VALIDATION_BITMAP */

extern kern_return_t vnode_pager_data_request(
	memory_object_t,
	memory_object_offset_t,
	memory_object_cluster_size_t,
	vm_prot_t,
	memory_object_fault_info_t);
extern kern_return_t vnode_pager_data_return(
	memory_object_t,
	memory_object_offset_t,
	memory_object_cluster_size_t,
	memory_object_offset_t *,
	int *,
	boolean_t,
	boolean_t,
	int);
extern kern_return_t vnode_pager_data_initialize(
	memory_object_t,
	memory_object_offset_t,
	memory_object_cluster_size_t);
extern void vnode_pager_reference(
	memory_object_t         mem_obj);
extern kern_return_t vnode_pager_map(
	memory_object_t         mem_obj,
	vm_prot_t               prot);
extern kern_return_t vnode_pager_last_unmap(
	memory_object_t         mem_obj);

extern kern_return_t vnode_pager_terminate(
	memory_object_t);
extern struct vnode *vnode_pager_lookup_vnode(
	memory_object_t);

extern bool memory_object_is_vnode_pager(memory_object_t mem_obj);

struct vm_map_entry;
extern struct vm_object *find_vnode_object(struct vm_map_entry *entry);

extern boolean_t is_device_pager_ops(const struct memory_object_pager_ops *pager_ops);

extern void log_stack_execution_failure(addr64_t vaddr, vm_prot_t prot);
extern void log_unnest_badness(
	vm_map_t map,
	vm_map_offset_t start_unnest,
	vm_map_offset_t end_unnest,
	boolean_t is_nested_map,
	vm_map_offset_t lowest_unnestable_addr);

extern vm_object_t vm_named_entry_to_vm_object(
	vm_named_entry_t        named_entry);
extern void vm_named_entry_associate_vm_object(
	vm_named_entry_t        named_entry,
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size,
	vm_prot_t               prot);

extern int macx_backing_store_compaction(int flags);
extern unsigned int mach_vm_ctl_page_free_wanted(void);

extern kern_return_t compressor_memory_object_create(
	memory_object_size_t,
	memory_object_t *);

u_int32_t vnode_trim_list(struct vnode *vp, struct trim_list *tl, boolean_t route_only);

extern void vm_start_ecc_thread(void);
extern void vm_ecc_lock(void);
extern void vm_ecc_unlock(void);

void vm_purgeable_nonvolatile_owner_update(task_t       owner,
    int          delta);
void vm_purgeable_volatile_owner_update(task_t          owner,
    int             delta);

#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif  /* _VM_VM_PROTOS_INTERNAL_H_ */
