/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include <vm/vm_upl.h>
#include <vm/vm_pageout_internal.h>
#include <vm/vm_page_internal.h>
#include <vm/vm_map_internal.h>
#include <mach/upl_server.h>
#include <kern/host_statistics.h>
#include <vm/vm_purgeable_internal.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_ubc.h>

extern boolean_t hibernate_cleaning_in_progress;

/* map a (whole) upl into an address space */
kern_return_t
vm_upl_map(
	vm_map_t                map,
	upl_t                   upl,
	vm_address_t            *dst_addr)
{
	vm_map_offset_t         map_addr;
	kern_return_t           kr;

	if (VM_MAP_NULL == map) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = vm_map_enter_upl(map, upl, &map_addr);
	*dst_addr = CAST_DOWN(vm_address_t, map_addr);
	return kr;
}

kern_return_t
vm_upl_unmap(
	vm_map_t                map,
	upl_t                   upl)
{
	if (VM_MAP_NULL == map) {
		return KERN_INVALID_ARGUMENT;
	}

	return vm_map_remove_upl(map, upl);
}

/* map a part of a upl into an address space with requested protection. */
kern_return_t
vm_upl_map_range(
	vm_map_t                map,
	upl_t                   upl,
	vm_offset_t             offset_to_map,
	vm_size_t               size_to_map,
	vm_prot_t               prot_to_map,
	vm_address_t            *dst_addr)
{
	vm_map_offset_t         map_addr, aligned_offset_to_map, adjusted_offset;
	kern_return_t           kr;

	if (VM_MAP_NULL == map) {
		return KERN_INVALID_ARGUMENT;
	}
	aligned_offset_to_map = vm_map_trunc_page(offset_to_map, vm_map_page_mask(map));
	adjusted_offset =  offset_to_map - aligned_offset_to_map;
	size_to_map = vm_map_round_page(size_to_map + adjusted_offset, vm_map_page_mask(map));

	kr = vm_map_enter_upl_range(map, upl, aligned_offset_to_map, size_to_map, prot_to_map, &map_addr);
	*dst_addr = CAST_DOWN(vm_address_t, (map_addr + adjusted_offset));
	return kr;
}

/* unmap a part of a upl that was mapped in the address space. */
kern_return_t
vm_upl_unmap_range(
	vm_map_t                map,
	upl_t                   upl,
	vm_offset_t             offset_to_unmap,
	vm_size_t               size_to_unmap)
{
	vm_map_offset_t         aligned_offset_to_unmap, page_offset;

	if (VM_MAP_NULL == map) {
		return KERN_INVALID_ARGUMENT;
	}

	aligned_offset_to_unmap = vm_map_trunc_page(offset_to_unmap, vm_map_page_mask(map));
	page_offset =  offset_to_unmap - aligned_offset_to_unmap;
	size_to_unmap = vm_map_round_page(size_to_unmap + page_offset, vm_map_page_mask(map));

	return vm_map_remove_upl_range(map, upl, aligned_offset_to_unmap, size_to_unmap);
}

/* Retrieve a upl for an object underlying an address range in a map */

kern_return_t
vm_map_get_upl(
	vm_map_t                map,
	vm_map_offset_t         map_offset,
	upl_size_t              *upl_size,
	upl_t                   *upl,
	upl_page_info_array_t   page_list,
	unsigned int            *count,
	upl_control_flags_t     *flags,
	vm_tag_t                tag,
	int                     force_data_sync)
{
	upl_control_flags_t map_flags;
	kern_return_t       kr;

	if (VM_MAP_NULL == map) {
		return KERN_INVALID_ARGUMENT;
	}

	map_flags = *flags & ~UPL_NOZEROFILL;
	if (force_data_sync) {
		map_flags |= UPL_FORCE_DATA_SYNC;
	}

	kr = vm_map_create_upl(map,
	    map_offset,
	    upl_size,
	    upl,
	    page_list,
	    count,
	    &map_flags,
	    tag);

	*flags = (map_flags & ~UPL_FORCE_DATA_SYNC);
	return kr;
}

uint64_t upl_pages_wired_busy = 0;

kern_return_t
upl_abort_range(
	upl_t                   upl,
	upl_offset_t            offset,
	upl_size_t              size,
	int                     error,
	boolean_t               *empty)
{
	upl_size_t              xfer_size, subupl_size;
	vm_object_t             shadow_object;
	vm_object_t             object;
	vm_object_offset_t      target_offset;
	upl_offset_t            subupl_offset = offset;
	int                     occupied;
	struct  vm_page_delayed_work    dw_array;
	struct  vm_page_delayed_work    *dwp, *dwp_start;
	bool                    dwp_finish_ctx = TRUE;
	int                     dw_count;
	int                     dw_limit;
	int                     isVectorUPL = 0;
	upl_t                   vector_upl = NULL;
	vm_object_offset_t      obj_start, obj_end, obj_offset;
	kern_return_t           kr = KERN_SUCCESS;

//	DEBUG4K_UPL("upl %p (u_offset 0x%llx u_size 0x%llx) object %p offset 0x%llx size 0x%llx error 0x%x\n", upl, (uint64_t)upl->u_offset, (uint64_t)upl->u_size, upl->map_object, (uint64_t)offset, (uint64_t)size, error);

	dwp_start = dwp = NULL;

	subupl_size = size;
	*empty = FALSE;

	if (upl == UPL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((upl->flags & UPL_IO_WIRE) && !(error & UPL_ABORT_DUMP_PAGES)) {
		return upl_commit_range(upl, offset, size, UPL_COMMIT_FREE_ABSENT, NULL, 0, empty);
	}

	dw_count = 0;
	dw_limit = DELAYED_WORK_LIMIT(DEFAULT_DELAYED_WORK_LIMIT);
	dwp_start = vm_page_delayed_work_get_ctx();
	if (dwp_start == NULL) {
		dwp_start = &dw_array;
		dw_limit = 1;
		dwp_finish_ctx = FALSE;
	}

	dwp = dwp_start;

	if ((isVectorUPL = vector_upl_is_valid(upl))) {
		vector_upl = upl;
		upl_lock(vector_upl);
	} else {
		upl_lock(upl);
	}

process_upl_to_abort:
	if (isVectorUPL) {
		size = subupl_size;
		offset = subupl_offset;
		if (size == 0) {
			upl_unlock(vector_upl);
			kr = KERN_SUCCESS;
			goto done;
		}
		upl =  vector_upl_subupl_byoffset(vector_upl, &offset, &size);
		if (upl == NULL) {
			upl_unlock(vector_upl);
			kr = KERN_FAILURE;
			goto done;
		}
		subupl_size -= size;
		subupl_offset += size;
	}

	*empty = FALSE;

#if UPL_DEBUG
	if (upl->upl_commit_index < UPL_DEBUG_COMMIT_RECORDS) {
		upl->upl_commit_records[upl->upl_commit_index].c_btref = btref_get(__builtin_frame_address(0), 0);
		upl->upl_commit_records[upl->upl_commit_index].c_beg = offset;
		upl->upl_commit_records[upl->upl_commit_index].c_end = (offset + size);
		upl->upl_commit_records[upl->upl_commit_index].c_aborted = 1;

		upl->upl_commit_index++;
	}
#endif
	if (upl->flags & UPL_DEVICE_MEMORY) {
		xfer_size = 0;
	} else if ((offset + size) <= upl_adjusted_size(upl, PAGE_MASK)) {
		xfer_size = size;
	} else {
		if (!isVectorUPL) {
			upl_unlock(upl);
		} else {
			upl_unlock(vector_upl);
		}
		DEBUG4K_ERROR("upl %p (u_offset 0x%llx u_size 0x%x) offset 0x%x size 0x%x\n", upl, upl->u_offset, upl->u_size, offset, size);
		kr = KERN_FAILURE;
		goto done;
	}
	object = upl->map_object;

	if (upl->flags & UPL_SHADOWED) {
		vm_object_lock(object);
		shadow_object = object->shadow;
	} else {
		shadow_object = object;
	}

	target_offset = (vm_object_offset_t)offset;

	if (upl->flags & UPL_KERNEL_OBJECT) {
		vm_object_lock_shared(shadow_object);
	} else {
		vm_object_lock(shadow_object);
	}

	if (upl->flags & UPL_ACCESS_BLOCKED) {
		assert(shadow_object->blocked_access);
		shadow_object->blocked_access = FALSE;
		vm_object_wakeup(object, VM_OBJECT_EVENT_UNBLOCKED);
	}

	if ((error & UPL_ABORT_DUMP_PAGES) && (upl->flags & UPL_KERNEL_OBJECT)) {
		panic("upl_abort_range: kernel_object being DUMPED");
	}

	obj_start = target_offset + upl->u_offset - shadow_object->paging_offset;
	obj_end = obj_start + xfer_size;
	obj_start = vm_object_trunc_page(obj_start);
	obj_end = vm_object_round_page(obj_end);
	for (obj_offset = obj_start;
	    obj_offset < obj_end;
	    obj_offset += PAGE_SIZE) {
		vm_page_t       t, m;
		unsigned int    pg_num;
		boolean_t       needed;

		pg_num = (unsigned int) (target_offset / PAGE_SIZE);
		assert(pg_num == target_offset / PAGE_SIZE);

		needed = FALSE;

		if (upl->flags & UPL_INTERNAL) {
			needed = upl->page_list[pg_num].needed;
		}

		dwp->dw_mask = 0;
		m = VM_PAGE_NULL;

		if (upl->flags & UPL_LITE) {
			if (bitmap_test(upl->lite_list, pg_num)) {
				bitmap_clear(upl->lite_list, pg_num);

				if (!(upl->flags & UPL_KERNEL_OBJECT)) {
					m = vm_page_lookup(shadow_object, obj_offset);
				}
			}
		}
		if (upl->flags & UPL_SHADOWED) {
			if ((t = vm_page_lookup(object, target_offset)) != VM_PAGE_NULL) {
				t->vmp_free_when_done = FALSE;

				VM_PAGE_FREE(t);

				if (m == VM_PAGE_NULL) {
					m = vm_page_lookup(shadow_object, target_offset + object->vo_shadow_offset);
				}
			}
		}
		if ((upl->flags & UPL_KERNEL_OBJECT)) {
			goto abort_next_page;
		}

		if (m != VM_PAGE_NULL) {
			assert(m->vmp_q_state != VM_PAGE_USED_BY_COMPRESSOR);

			if (m->vmp_absent) {
				boolean_t must_free = TRUE;

				/*
				 * COPYOUT = FALSE case
				 * check for error conditions which must
				 * be passed back to the pages customer
				 */
				if (error & UPL_ABORT_RESTART) {
					m->vmp_restart = TRUE;
					m->vmp_absent = FALSE;
					m->vmp_unusual = TRUE;
					must_free = FALSE;
				} else if (error & UPL_ABORT_UNAVAILABLE) {
					m->vmp_restart = FALSE;
					m->vmp_unusual = TRUE;
					must_free = FALSE;
				} else if (error & UPL_ABORT_ERROR) {
					m->vmp_restart = FALSE;
					m->vmp_absent = FALSE;
					m->vmp_error = TRUE;
					m->vmp_unusual = TRUE;
					must_free = FALSE;
				}
				if (m->vmp_clustered && needed == FALSE) {
					/*
					 * This page was a part of a speculative
					 * read-ahead initiated by the kernel
					 * itself.  No one is expecting this
					 * page and no one will clean up its
					 * error state if it ever becomes valid
					 * in the future.
					 * We have to free it here.
					 */
					must_free = TRUE;
				}
				m->vmp_cleaning = FALSE;

				if (m->vmp_overwriting && !m->vmp_busy) {
					/*
					 * this shouldn't happen since
					 * this is an 'absent' page, but
					 * it doesn't hurt to check for
					 * the 'alternate' method of
					 * stabilizing the page...
					 * we will mark 'busy' to be cleared
					 * in the following code which will
					 * take care of the primary stabilzation
					 * method (i.e. setting 'busy' to TRUE)
					 */
					dwp->dw_mask |= DW_vm_page_unwire;
				}
				m->vmp_overwriting = FALSE;

				dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP);

				if (must_free == TRUE) {
					dwp->dw_mask |= DW_vm_page_free;
				} else {
					dwp->dw_mask |= DW_vm_page_activate;
				}
			} else {
				/*
				 * Handle the trusted pager throttle.
				 */
				if (m->vmp_laundry) {
					dwp->dw_mask |= DW_vm_pageout_throttle_up;
				}

				if (upl->flags & UPL_ACCESS_BLOCKED) {
					/*
					 * We blocked access to the pages in this UPL.
					 * Clear the "busy" bit and wake up any waiter
					 * for this page.
					 */
					dwp->dw_mask |= DW_clear_busy;
				}
				if (m->vmp_overwriting) {
					if (VM_PAGE_WIRED(m)) {
						/*
						 * deal with the 'alternate' method
						 * of stabilizing the page...
						 * we will either free the page
						 * or mark 'busy' to be cleared
						 * in the following code which will
						 * take care of the primary stabilzation
						 * method (i.e. setting 'busy' to TRUE)
						 */
						if (m->vmp_busy) {
//							printf("*******   FBDP %s:%d page %p object %p ofsfet 0x%llx wired and busy\n", __FUNCTION__, __LINE__, m, VM_PAGE_OBJECT(m), m->vmp_offset);
							upl_pages_wired_busy++;
						}
						dwp->dw_mask |= DW_vm_page_unwire;
					} else {
						assert(m->vmp_busy);
						dwp->dw_mask |= DW_clear_busy;
					}
					m->vmp_overwriting = FALSE;
				}
				m->vmp_free_when_done = FALSE;
				m->vmp_cleaning = FALSE;

				if (error & UPL_ABORT_DUMP_PAGES) {
					pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));

					dwp->dw_mask |= DW_vm_page_free;
				} else {
					if (!(dwp->dw_mask & DW_vm_page_unwire)) {
						if (error & UPL_ABORT_REFERENCE) {
							/*
							 * we've been told to explictly
							 * reference this page... for
							 * file I/O, this is done by
							 * implementing an LRU on the inactive q
							 */
							dwp->dw_mask |= DW_vm_page_lru;
						} else if (!VM_PAGE_PAGEABLE(m)) {
							dwp->dw_mask |= DW_vm_page_deactivate_internal;
						}
					}
					dwp->dw_mask |= DW_PAGE_WAKEUP;
				}
			}
		}
abort_next_page:
		target_offset += PAGE_SIZE_64;
		xfer_size -= PAGE_SIZE;

		if (dwp->dw_mask) {
			if (dwp->dw_mask & ~(DW_clear_busy | DW_PAGE_WAKEUP)) {
				VM_PAGE_ADD_DELAYED_WORK(dwp, m, dw_count);

				if (dw_count >= dw_limit) {
					vm_page_do_delayed_work(shadow_object, VM_KERN_MEMORY_NONE, dwp_start, dw_count);

					dwp = dwp_start;
					dw_count = 0;
				}
			} else {
				if (dwp->dw_mask & DW_clear_busy) {
					m->vmp_busy = FALSE;
				}

				if (dwp->dw_mask & DW_PAGE_WAKEUP) {
					vm_page_wakeup(shadow_object, m);
				}
			}
		}
	}
	if (dw_count) {
		vm_page_do_delayed_work(shadow_object, VM_KERN_MEMORY_NONE, dwp_start, dw_count);
		dwp = dwp_start;
		dw_count = 0;
	}

	if (upl->flags & UPL_DEVICE_MEMORY) {
		occupied = 0;
	} else if (upl->flags & UPL_LITE) {
		uint32_t pages = (uint32_t)atop(upl_adjusted_size(upl, PAGE_MASK));

		occupied = !bitmap_is_empty(upl->lite_list, pages);
	} else {
		occupied = !vm_page_queue_empty(&upl->map_object->memq);
	}
	if (occupied == 0) {
		/*
		 * If this UPL element belongs to a Vector UPL and is
		 * empty, then this is the right function to deallocate
		 * it. So go ahead set the *empty variable. The flag
		 * UPL_COMMIT_NOTIFY_EMPTY, from the caller's point of view
		 * should be considered relevant for the Vector UPL and
		 * not the internal UPLs.
		 */
		if ((upl->flags & UPL_COMMIT_NOTIFY_EMPTY) || isVectorUPL) {
			*empty = TRUE;
		}

		if (object == shadow_object && !(upl->flags & UPL_KERNEL_OBJECT)) {
			/*
			 * this is not a paging object
			 * so we need to drop the paging reference
			 * that was taken when we created the UPL
			 * against this object
			 */
			vm_object_activity_end(shadow_object);
			vm_object_collapse(shadow_object, 0, TRUE);
		} else {
			/*
			 * we dontated the paging reference to
			 * the map object... vm_pageout_object_terminate
			 * will drop this reference
			 */
		}
	}
	vm_object_unlock(shadow_object);
	if (object != shadow_object) {
		vm_object_unlock(object);
	}

	if (!isVectorUPL) {
		upl_unlock(upl);
	} else {
		/*
		 * If we completed our operations on an UPL that is
		 * part of a Vectored UPL and if empty is TRUE, then
		 * we should go ahead and deallocate this UPL element.
		 * Then we check if this was the last of the UPL elements
		 * within that Vectored UPL. If so, set empty to TRUE
		 * so that in ubc_upl_abort_range or ubc_upl_abort, we
		 * can go ahead and deallocate the Vector UPL too.
		 */
		if (*empty == TRUE) {
			*empty = vector_upl_set_subupl(vector_upl, upl, 0);
			upl_deallocate(upl);
		}
		goto process_upl_to_abort;
	}

	kr = KERN_SUCCESS;

done:
	if (dwp_start && dwp_finish_ctx) {
		vm_page_delayed_work_finish_ctx(dwp_start);
		dwp_start = dwp = NULL;
	}

	return kr;
}

kern_return_t
upl_abort(
	upl_t   upl,
	int     error)
{
	boolean_t       empty;

	if (upl == UPL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return upl_abort_range(upl, 0, upl->u_size, error, &empty);
}

kern_return_t
upl_commit_range(
	upl_t                   upl,
	upl_offset_t            offset,
	upl_size_t              size,
	int                     flags,
	upl_page_info_t         *page_list,
	mach_msg_type_number_t  count,
	boolean_t               *empty)
{
	upl_size_t              xfer_size, subupl_size;
	vm_object_t             shadow_object;
	vm_object_t             object;
	vm_object_t             m_object;
	vm_object_offset_t      target_offset;
	upl_offset_t            subupl_offset = offset;
	int                     entry;
	int                     occupied;
	int                     clear_refmod = 0;
	int                     pgpgout_count = 0;
	struct  vm_page_delayed_work    dw_array;
	struct  vm_page_delayed_work    *dwp, *dwp_start;
	bool                    dwp_finish_ctx = TRUE;
	int                     dw_count;
	int                     dw_limit;
	int                     isVectorUPL = 0;
	upl_t                   vector_upl = NULL;
	boolean_t               should_be_throttled = FALSE;

	vm_page_t               nxt_page = VM_PAGE_NULL;
	int                     fast_path_possible = 0;
	int                     fast_path_full_commit = 0;
	int                     throttle_page = 0;
	int                     unwired_count = 0;
	int                     local_queue_count = 0;
	vm_page_t               first_local, last_local;
	vm_object_offset_t      obj_start, obj_end, obj_offset;
	kern_return_t           kr = KERN_SUCCESS;

//	DEBUG4K_UPL("upl %p (u_offset 0x%llx u_size 0x%llx) object %p offset 0x%llx size 0x%llx flags 0x%x\n", upl, (uint64_t)upl->u_offset, (uint64_t)upl->u_size, upl->map_object, (uint64_t)offset, (uint64_t)size, flags);

	dwp_start = dwp = NULL;

	subupl_size = size;
	*empty = FALSE;

	if (upl == UPL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	dw_count = 0;
	dw_limit = DELAYED_WORK_LIMIT(DEFAULT_DELAYED_WORK_LIMIT);
	dwp_start = vm_page_delayed_work_get_ctx();
	if (dwp_start == NULL) {
		dwp_start = &dw_array;
		dw_limit = 1;
		dwp_finish_ctx = FALSE;
	}

	dwp = dwp_start;

	if (count == 0) {
		page_list = NULL;
	}

	if ((isVectorUPL = vector_upl_is_valid(upl))) {
		vector_upl = upl;
		upl_lock(vector_upl);
	} else {
		upl_lock(upl);
	}

process_upl_to_commit:

	if (isVectorUPL) {
		size = subupl_size;
		offset = subupl_offset;
		if (size == 0) {
			upl_unlock(vector_upl);
			kr = KERN_SUCCESS;
			goto done;
		}
		upl =  vector_upl_subupl_byoffset(vector_upl, &offset, &size);
		if (upl == NULL) {
			upl_unlock(vector_upl);
			kr = KERN_FAILURE;
			goto done;
		}
		page_list = upl->page_list;
		subupl_size -= size;
		subupl_offset += size;
	}

#if UPL_DEBUG
	if (upl->upl_commit_index < UPL_DEBUG_COMMIT_RECORDS) {
		upl->upl_commit_records[upl->upl_commit_index].c_btref = btref_get(__builtin_frame_address(0), 0);
		upl->upl_commit_records[upl->upl_commit_index].c_beg = offset;
		upl->upl_commit_records[upl->upl_commit_index].c_end = (offset + size);

		upl->upl_commit_index++;
	}
#endif
	if (upl->flags & UPL_DEVICE_MEMORY) {
		xfer_size = 0;
	} else if ((offset + size) <= upl_adjusted_size(upl, PAGE_MASK)) {
		xfer_size = size;
	} else {
		if (!isVectorUPL) {
			upl_unlock(upl);
		} else {
			upl_unlock(vector_upl);
		}
		DEBUG4K_ERROR("upl %p (u_offset 0x%llx u_size 0x%x) offset 0x%x size 0x%x\n", upl, upl->u_offset, upl->u_size, offset, size);
		kr = KERN_FAILURE;
		goto done;
	}
	if (upl->flags & UPL_SET_DIRTY) {
		flags |= UPL_COMMIT_SET_DIRTY;
	}
	if (upl->flags & UPL_CLEAR_DIRTY) {
		flags |= UPL_COMMIT_CLEAR_DIRTY;
	}

	object = upl->map_object;

	if (upl->flags & UPL_SHADOWED) {
		vm_object_lock(object);
		shadow_object = object->shadow;
	} else {
		shadow_object = object;
	}
	entry = offset / PAGE_SIZE;
	target_offset = (vm_object_offset_t)offset;

	if (upl->flags & UPL_KERNEL_OBJECT) {
		vm_object_lock_shared(shadow_object);
	} else {
		vm_object_lock(shadow_object);
	}

	VM_OBJECT_WIRED_PAGE_UPDATE_START(shadow_object);

	if (upl->flags & UPL_ACCESS_BLOCKED) {
		assert(shadow_object->blocked_access);
		shadow_object->blocked_access = FALSE;
		vm_object_wakeup(object, VM_OBJECT_EVENT_UNBLOCKED);
	}

	if (shadow_object->code_signed) {
		/*
		 * CODE SIGNING:
		 * If the object is code-signed, do not let this UPL tell
		 * us if the pages are valid or not.  Let the pages be
		 * validated by VM the normal way (when they get mapped or
		 * copied).
		 */
		flags &= ~UPL_COMMIT_CS_VALIDATED;
	}
	if (!page_list) {
		/*
		 * No page list to get the code-signing info from !?
		 */
		flags &= ~UPL_COMMIT_CS_VALIDATED;
	}
	if (!VM_DYNAMIC_PAGING_ENABLED() && shadow_object->internal) {
		should_be_throttled = TRUE;
	}

	if ((upl->flags & UPL_IO_WIRE) &&
	    !(flags & UPL_COMMIT_FREE_ABSENT) &&
	    !isVectorUPL &&
	    shadow_object->purgable != VM_PURGABLE_VOLATILE &&
	    shadow_object->purgable != VM_PURGABLE_EMPTY) {
		if (!vm_page_queue_empty(&shadow_object->memq)) {
			if (shadow_object->internal && size == shadow_object->vo_size) {
				nxt_page = (vm_page_t)vm_page_queue_first(&shadow_object->memq);
				fast_path_full_commit = 1;
			}
			fast_path_possible = 1;

			if (!VM_DYNAMIC_PAGING_ENABLED() && shadow_object->internal &&
			    (shadow_object->purgable == VM_PURGABLE_DENY ||
			    shadow_object->purgable == VM_PURGABLE_NONVOLATILE ||
			    shadow_object->purgable == VM_PURGABLE_VOLATILE)) {
				throttle_page = 1;
			}
		}
	}
	first_local = VM_PAGE_NULL;
	last_local = VM_PAGE_NULL;

	obj_start = target_offset + upl->u_offset - shadow_object->paging_offset;
	obj_end = obj_start + xfer_size;
	obj_start = vm_object_trunc_page(obj_start);
	obj_end = vm_object_round_page(obj_end);
	for (obj_offset = obj_start;
	    obj_offset < obj_end;
	    obj_offset += PAGE_SIZE) {
		vm_page_t       t, m;

		dwp->dw_mask = 0;
		clear_refmod = 0;

		m = VM_PAGE_NULL;

		if (upl->flags & UPL_LITE) {
			unsigned int    pg_num;

			if (nxt_page != VM_PAGE_NULL) {
				m = nxt_page;
				nxt_page = (vm_page_t)vm_page_queue_next(&nxt_page->vmp_listq);
				target_offset = m->vmp_offset;
			}
			pg_num = (unsigned int) (target_offset / PAGE_SIZE);
			assert(pg_num == target_offset / PAGE_SIZE);

			if (bitmap_test(upl->lite_list, pg_num)) {
				bitmap_clear(upl->lite_list, pg_num);

				if (!(upl->flags & UPL_KERNEL_OBJECT) && m == VM_PAGE_NULL) {
					m = vm_page_lookup(shadow_object, obj_offset);
				}
			} else {
				m = NULL;
			}
		}
		if (upl->flags & UPL_SHADOWED) {
			if ((t = vm_page_lookup(object, target_offset)) != VM_PAGE_NULL) {
				t->vmp_free_when_done = FALSE;

				VM_PAGE_FREE(t);

				if (!(upl->flags & UPL_KERNEL_OBJECT) && m == VM_PAGE_NULL) {
					m = vm_page_lookup(shadow_object, target_offset + object->vo_shadow_offset);
				}
			}
		}
		if (m == VM_PAGE_NULL) {
			goto commit_next_page;
		}

		m_object = VM_PAGE_OBJECT(m);

		if (m->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
			assert(m->vmp_busy);

			dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP);
			goto commit_next_page;
		}

		if (flags & UPL_COMMIT_CS_VALIDATED) {
			/*
			 * CODE SIGNING:
			 * Set the code signing bits according to
			 * what the UPL says they should be.
			 */
			m->vmp_cs_validated |= page_list[entry].cs_validated;
			m->vmp_cs_tainted |= page_list[entry].cs_tainted;
			m->vmp_cs_nx |= page_list[entry].cs_nx;
		}
		if (flags & UPL_COMMIT_WRITTEN_BY_KERNEL) {
			m->vmp_written_by_kernel = TRUE;
		}

		if (upl->flags & UPL_IO_WIRE) {
			if (page_list) {
				page_list[entry].phys_addr = 0;
			}

			if (flags & UPL_COMMIT_SET_DIRTY) {
				SET_PAGE_DIRTY(m, FALSE);
			} else if (flags & UPL_COMMIT_CLEAR_DIRTY) {
				m->vmp_dirty = FALSE;

				if (!(flags & UPL_COMMIT_CS_VALIDATED) &&
				    m->vmp_cs_validated &&
				    m->vmp_cs_tainted != VMP_CS_ALL_TRUE) {
					/*
					 * CODE SIGNING:
					 * This page is no longer dirty
					 * but could have been modified,
					 * so it will need to be
					 * re-validated.
					 */
					m->vmp_cs_validated = VMP_CS_ALL_FALSE;

					VM_PAGEOUT_DEBUG(vm_cs_validated_resets, 1);

					pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));
				}
				clear_refmod |= VM_MEM_MODIFIED;
			}
			if (upl->flags & UPL_ACCESS_BLOCKED) {
				/*
				 * We blocked access to the pages in this UPL.
				 * Clear the "busy" bit and wake up any waiter
				 * for this page.
				 */
				dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP);
			}
			if (fast_path_possible) {
				assert(m_object->purgable != VM_PURGABLE_EMPTY);
				assert(m_object->purgable != VM_PURGABLE_VOLATILE);
				if (m->vmp_absent) {
					assert(m->vmp_q_state == VM_PAGE_NOT_ON_Q);
					assert(m->vmp_wire_count == 0);
					assert(m->vmp_busy);

					m->vmp_absent = FALSE;
					dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP);
				} else {
					if (m->vmp_wire_count == 0) {
						panic("wire_count == 0, m = %p, obj = %p", m, shadow_object);
					}
					assert(m->vmp_q_state == VM_PAGE_IS_WIRED);

					/*
					 * XXX FBDP need to update some other
					 * counters here (purgeable_wired_count)
					 * (ledgers), ...
					 */
					assert(m->vmp_wire_count > 0);
					m->vmp_wire_count--;

					if (m->vmp_wire_count == 0) {
						m->vmp_q_state = VM_PAGE_NOT_ON_Q;
						unwired_count++;

					}
				}
				if (m->vmp_wire_count == 0) {
					assert(m->vmp_pageq.next == 0 && m->vmp_pageq.prev == 0);

					if (last_local == VM_PAGE_NULL) {
						assert(first_local == VM_PAGE_NULL);

						last_local = m;
						first_local = m;
					} else {
						assert(first_local != VM_PAGE_NULL);

						m->vmp_pageq.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_local);
						first_local->vmp_pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(m);
						first_local = m;
					}
					local_queue_count++;

					if (throttle_page) {
						m->vmp_q_state = VM_PAGE_ON_THROTTLED_Q;
					} else {
						if (flags & UPL_COMMIT_INACTIVATE) {
							if (shadow_object->internal) {
								m->vmp_q_state = VM_PAGE_ON_INACTIVE_INTERNAL_Q;
							} else {
								m->vmp_q_state = VM_PAGE_ON_INACTIVE_EXTERNAL_Q;
							}
						} else {
							m->vmp_q_state = VM_PAGE_ON_ACTIVE_Q;
						}
					}
				}
			} else {
				if (flags & UPL_COMMIT_INACTIVATE) {
					dwp->dw_mask |= DW_vm_page_deactivate_internal;
					clear_refmod |= VM_MEM_REFERENCED;
				}
				if (m->vmp_absent) {
					if (flags & UPL_COMMIT_FREE_ABSENT) {
						dwp->dw_mask |= DW_vm_page_free;
					} else {
						m->vmp_absent = FALSE;
						dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP);

						if (!(dwp->dw_mask & DW_vm_page_deactivate_internal)) {
							dwp->dw_mask |= DW_vm_page_activate;
						}
					}
				} else {
					dwp->dw_mask |= DW_vm_page_unwire;
				}
			}
			goto commit_next_page;
		}
		assert(m->vmp_q_state != VM_PAGE_USED_BY_COMPRESSOR);

		if (page_list) {
			page_list[entry].phys_addr = 0;
		}

		/*
		 * make sure to clear the hardware
		 * modify or reference bits before
		 * releasing the BUSY bit on this page
		 * otherwise we risk losing a legitimate
		 * change of state
		 */
		if (flags & UPL_COMMIT_CLEAR_DIRTY) {
			m->vmp_dirty = FALSE;

			clear_refmod |= VM_MEM_MODIFIED;
		}
		if (m->vmp_laundry) {
			dwp->dw_mask |= DW_vm_pageout_throttle_up;
		}

		if (VM_PAGE_WIRED(m)) {
			m->vmp_free_when_done = FALSE;
		}

		if (!(flags & UPL_COMMIT_CS_VALIDATED) &&
		    m->vmp_cs_validated &&
		    m->vmp_cs_tainted != VMP_CS_ALL_TRUE) {
			/*
			 * CODE SIGNING:
			 * This page is no longer dirty
			 * but could have been modified,
			 * so it will need to be
			 * re-validated.
			 */
			m->vmp_cs_validated = VMP_CS_ALL_FALSE;

			VM_PAGEOUT_DEBUG(vm_cs_validated_resets, 1);

			pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));
		}
		if (m->vmp_overwriting) {
			/*
			 * the (COPY_OUT_FROM == FALSE) request_page_list case
			 */
			if (VM_PAGE_WIRED(m)) {
				/*
				 * alternate (COPY_OUT_FROM == FALSE) page_list case
				 * Occurs when the original page was wired
				 * at the time of the list request
				 */
				if (m->vmp_busy) {
//					printf("*******   FBDP %s:%d page %p object %p ofsfet 0x%llx wired and busy\n", __FUNCTION__, __LINE__, m, VM_PAGE_OBJECT(m), m->vmp_offset);
					upl_pages_wired_busy++;
				}
				assert(!m->vmp_absent);
				dwp->dw_mask |= DW_vm_page_unwire; /* reactivates */
			} else {
				assert(m->vmp_busy);
#if CONFIG_PHANTOM_CACHE
				if (m->vmp_absent && !m_object->internal) {
					dwp->dw_mask |= DW_vm_phantom_cache_update;
				}
#endif
				m->vmp_absent = FALSE;

				dwp->dw_mask |= DW_clear_busy;
			}
			m->vmp_overwriting = FALSE;
		}
		m->vmp_cleaning = FALSE;

		if (m->vmp_free_when_done) {
			/*
			 * With the clean queue enabled, UPL_PAGEOUT should
			 * no longer set the pageout bit. Its pages now go
			 * to the clean queue.
			 *
			 * We don't use the cleaned Q anymore and so this
			 * assert isn't correct. The code for the clean Q
			 * still exists and might be used in the future. If we
			 * go back to the cleaned Q, we will re-enable this
			 * assert.
			 *
			 * assert(!(upl->flags & UPL_PAGEOUT));
			 */
			assert(!m_object->internal);

			m->vmp_free_when_done = FALSE;

			if ((flags & UPL_COMMIT_SET_DIRTY) ||
			    (m->vmp_pmapped && (pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m)) & VM_MEM_MODIFIED))) {
				/*
				 * page was re-dirtied after we started
				 * the pageout... reactivate it since
				 * we don't know whether the on-disk
				 * copy matches what is now in memory
				 */
				SET_PAGE_DIRTY(m, FALSE);

				dwp->dw_mask |= DW_vm_page_activate | DW_PAGE_WAKEUP;

				if (upl->flags & UPL_PAGEOUT) {
					counter_inc(&vm_statistics_reactivations);
					DTRACE_VM2(pgrec, int, 1, (uint64_t *), NULL);
				}
			} else if (m->vmp_busy && !(upl->flags & UPL_HAS_BUSY)) {
				/*
				 * Someone else might still be handling this
				 * page (vm_fault() for example), so let's not
				 * free it or "un-busy" it!
				 * Put that page in the "speculative" queue
				 * for now (since we would otherwise have freed
				 * it) and let whoever is keeping the page
				 * "busy" move it if needed when they're done
				 * with it.
				 */
				dwp->dw_mask |= DW_vm_page_speculate;
			} else {
				/*
				 * page has been successfully cleaned
				 * go ahead and free it for other use
				 */
				if (m_object->internal) {
					DTRACE_VM2(anonpgout, int, 1, (uint64_t *), NULL);
				} else {
					DTRACE_VM2(fspgout, int, 1, (uint64_t *), NULL);
				}
				m->vmp_dirty = FALSE;
				if (!(upl->flags & UPL_HAS_BUSY)) {
					assert(!m->vmp_busy);
				}
				m->vmp_busy = TRUE;

				dwp->dw_mask |= DW_vm_page_free;
			}
			goto commit_next_page;
		}
		/*
		 * It is a part of the semantic of COPYOUT_FROM
		 * UPLs that a commit implies cache sync
		 * between the vm page and the backing store
		 * this can be used to strip the precious bit
		 * as well as clean
		 */
		if ((upl->flags & UPL_PAGE_SYNC_DONE) || (flags & UPL_COMMIT_CLEAR_PRECIOUS)) {
			m->vmp_precious = FALSE;
		}

		if (flags & UPL_COMMIT_SET_DIRTY) {
			SET_PAGE_DIRTY(m, FALSE);
		} else {
			m->vmp_dirty = FALSE;
		}

		/* with the clean queue on, move *all* cleaned pages to the clean queue */
		if (hibernate_cleaning_in_progress == FALSE && !m->vmp_dirty && (upl->flags & UPL_PAGEOUT)) {
			pgpgout_count++;

			counter_inc(&vm_statistics_pageouts);
			DTRACE_VM2(pgout, int, 1, (uint64_t *), NULL);

			dwp->dw_mask |= DW_enqueue_cleaned;
		} else if (should_be_throttled == TRUE && (m->vmp_q_state == VM_PAGE_NOT_ON_Q)) {
			/*
			 * page coming back in from being 'frozen'...
			 * it was dirty before it was frozen, so keep it so
			 * the vm_page_activate will notice that it really belongs
			 * on the throttle queue and put it there
			 */
			SET_PAGE_DIRTY(m, FALSE);
			dwp->dw_mask |= DW_vm_page_activate;
		} else {
			if ((flags & UPL_COMMIT_INACTIVATE) && !m->vmp_clustered && (m->vmp_q_state != VM_PAGE_ON_SPECULATIVE_Q)) {
				dwp->dw_mask |= DW_vm_page_deactivate_internal;
				clear_refmod |= VM_MEM_REFERENCED;
			} else if (!VM_PAGE_PAGEABLE(m)) {
				if (m->vmp_clustered || (flags & UPL_COMMIT_SPECULATE)) {
					dwp->dw_mask |= DW_vm_page_speculate;
				} else if (m->vmp_reference) {
					dwp->dw_mask |= DW_vm_page_activate;
				} else {
					dwp->dw_mask |= DW_vm_page_deactivate_internal;
					clear_refmod |= VM_MEM_REFERENCED;
				}
			}
		}
		if (upl->flags & UPL_ACCESS_BLOCKED) {
			/*
			 * We blocked access to the pages in this URL.
			 * Clear the "busy" bit on this page before we
			 * wake up any waiter.
			 */
			dwp->dw_mask |= DW_clear_busy;
		}
		/*
		 * Wakeup any thread waiting for the page to be un-cleaning.
		 */
		dwp->dw_mask |= DW_PAGE_WAKEUP;

commit_next_page:
		if (clear_refmod) {
			pmap_clear_refmod(VM_PAGE_GET_PHYS_PAGE(m), clear_refmod);
		}

		target_offset += PAGE_SIZE_64;
		xfer_size -= PAGE_SIZE;
		entry++;

		if (dwp->dw_mask) {
			if (dwp->dw_mask & ~(DW_clear_busy | DW_PAGE_WAKEUP)) {
				VM_PAGE_ADD_DELAYED_WORK(dwp, m, dw_count);

				if (dw_count >= dw_limit) {
					vm_page_do_delayed_work(shadow_object, VM_KERN_MEMORY_NONE, dwp_start, dw_count);

					dwp = dwp_start;
					dw_count = 0;
				}
			} else {
				if (dwp->dw_mask & DW_clear_busy) {
					m->vmp_busy = FALSE;
				}

				if (dwp->dw_mask & DW_PAGE_WAKEUP) {
					vm_page_wakeup(m_object, m);
				}
			}
		}
	}
	if (dw_count) {
		vm_page_do_delayed_work(shadow_object, VM_KERN_MEMORY_NONE, dwp_start, dw_count);
		dwp = dwp_start;
		dw_count = 0;
	}

	if (fast_path_possible) {
		assert(shadow_object->purgable != VM_PURGABLE_VOLATILE);
		assert(shadow_object->purgable != VM_PURGABLE_EMPTY);

		if (local_queue_count || unwired_count) {
			if (local_queue_count) {
				vm_page_t       first_target;
				vm_page_queue_head_t    *target_queue;

				if (throttle_page) {
					target_queue = &vm_page_queue_throttled;
				} else {
					if (flags & UPL_COMMIT_INACTIVATE) {
						if (shadow_object->internal) {
							target_queue = &vm_page_queue_anonymous;
						} else {
							target_queue = &vm_page_queue_inactive;
						}
					} else {
						target_queue = &vm_page_queue_active;
					}
				}
				/*
				 * Transfer the entire local queue to a regular LRU page queues.
				 */
				vm_page_lockspin_queues();

				first_target = (vm_page_t) vm_page_queue_first(target_queue);

				if (vm_page_queue_empty(target_queue)) {
					target_queue->prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_local);
				} else {
					first_target->vmp_pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_local);
				}

				target_queue->next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_local);
				first_local->vmp_pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(target_queue);
				last_local->vmp_pageq.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_target);

				/*
				 * Adjust the global page counts.
				 */
				if (throttle_page) {
					vm_page_throttled_count += local_queue_count;
				} else {
					if (flags & UPL_COMMIT_INACTIVATE) {
						if (shadow_object->internal) {
							vm_page_anonymous_count += local_queue_count;
						}
						vm_page_inactive_count += local_queue_count;

						token_new_pagecount += local_queue_count;
					} else {
						vm_page_active_count += local_queue_count;
					}

					if (shadow_object->internal) {
						vm_page_pageable_internal_count += local_queue_count;
					} else {
						vm_page_pageable_external_count += local_queue_count;
					}
				}
			} else {
				vm_page_lockspin_queues();
			}
			if (unwired_count) {
				vm_page_wire_count -= unwired_count;
				VM_CHECK_MEMORYSTATUS;
			}
			vm_page_unlock_queues();

			VM_OBJECT_WIRED_PAGE_COUNT(shadow_object, -unwired_count);
		}
	}

	if (upl->flags & UPL_DEVICE_MEMORY) {
		occupied = 0;
	} else if (upl->flags & UPL_LITE) {
		uint32_t pages = (uint32_t)atop(upl_adjusted_size(upl, PAGE_MASK));

		occupied = !fast_path_full_commit &&
		    !bitmap_is_empty(upl->lite_list, pages);
	} else {
		occupied = !vm_page_queue_empty(&upl->map_object->memq);
	}
	if (occupied == 0) {
		/*
		 * If this UPL element belongs to a Vector UPL and is
		 * empty, then this is the right function to deallocate
		 * it. So go ahead set the *empty variable. The flag
		 * UPL_COMMIT_NOTIFY_EMPTY, from the caller's point of view
		 * should be considered relevant for the Vector UPL and not
		 * the internal UPLs.
		 */
		if ((upl->flags & UPL_COMMIT_NOTIFY_EMPTY) || isVectorUPL) {
			*empty = TRUE;
		}

		if (object == shadow_object && !(upl->flags & UPL_KERNEL_OBJECT)) {
			/*
			 * this is not a paging object
			 * so we need to drop the paging reference
			 * that was taken when we created the UPL
			 * against this object
			 */
			vm_object_activity_end(shadow_object);
			vm_object_collapse(shadow_object, 0, TRUE);
		} else {
			/*
			 * we dontated the paging reference to
			 * the map object... vm_pageout_object_terminate
			 * will drop this reference
			 */
		}
	}
	VM_OBJECT_WIRED_PAGE_UPDATE_END(shadow_object, shadow_object->wire_tag);
	vm_object_unlock(shadow_object);
	if (object != shadow_object) {
		vm_object_unlock(object);
	}

	if (!isVectorUPL) {
		upl_unlock(upl);
	} else {
		/*
		 * If we completed our operations on an UPL that is
		 * part of a Vectored UPL and if empty is TRUE, then
		 * we should go ahead and deallocate this UPL element.
		 * Then we check if this was the last of the UPL elements
		 * within that Vectored UPL. If so, set empty to TRUE
		 * so that in ubc_upl_commit_range or ubc_upl_commit, we
		 * can go ahead and deallocate the Vector UPL too.
		 */
		if (*empty == TRUE) {
			*empty = vector_upl_set_subupl(vector_upl, upl, 0);
			upl_deallocate(upl);
		}
		goto process_upl_to_commit;
	}
	if (pgpgout_count) {
		DTRACE_VM2(pgpgout, int, pgpgout_count, (uint64_t *), NULL);
	}

	kr = KERN_SUCCESS;
done:
	if (dwp_start && dwp_finish_ctx) {
		vm_page_delayed_work_finish_ctx(dwp_start);
		dwp_start = dwp = NULL;
	}

	return kr;
}

/* an option on commit should be wire */
kern_return_t
upl_commit(
	upl_t                   upl,
	upl_page_info_t         *page_list,
	mach_msg_type_number_t  count)
{
	boolean_t       empty;

	if (upl == UPL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return upl_commit_range(upl, 0, upl->u_size, 0,
	           page_list, count, &empty);
}
