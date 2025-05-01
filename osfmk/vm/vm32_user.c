/*
 * Copyright (c) 2008-2016 Apple Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 *	File:	vm/vm32_user.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	User-exported virtual memory functions.
 */

#include <debug.h>

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/mach_types.h>    /* to get vm_address_t */
#include <mach/memory_object.h>
#include <mach/std_types.h>     /* to get pointer_t */
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <mach/vm_statistics.h>
#include <mach/mach_syscalls.h>

#include <mach/host_priv_server.h>
#include <mach/mach_vm_server.h>
#include <mach/vm32_map_server.h>

#include <kern/host.h>
#include <kern/task.h>
#include <kern/misc_protos.h>
#include <vm/vm_fault.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_object_xnu.h>
#include <vm/vm_page.h>
#include <vm/memory_object.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <vm/vm_iokit.h>
#include <vm/vm_sanitize_internal.h>
#include <vm/vm_map_internal.h>

#ifdef VM32_SUPPORT

/*
 * See vm_user.c for the real implementation of all of these functions.
 * We call through to the mach_ "wide" versions of the routines, and trust
 * that the VM system verifies the arguments and only returns address that
 * are appropriate for the task's address space size.
 *
 * New VM call implementations should not be added here, because they would
 * be available only to 32-bit userspace clients. Add them to vm_user.c
 * and the corresponding prototype to mach_vm.defs (subsystem 4800).
 */

kern_return_t
vm32_vm_allocate(
	vm_map_t                map,
	vm32_address_ut        *addr32,
	vm32_size_ut            size32,
	int                     flags)
{
	mach_vm_address_ut      addr;
	mach_vm_size_ut         size;
	kern_return_t           kr;

	addr    = vm_sanitize_expand_addr_to_64(*addr32);
	size    = vm_sanitize_expand_size_to_64(size32);
	kr      = mach_vm_allocate_external(map, &addr, size, flags);
	*addr32 = vm_sanitize_trunc_addr_to_32(addr);

	return kr;
}

kern_return_t
vm32_vm_deallocate(
	vm_map_t                map,
	vm32_offset_ut          start32,
	vm32_size_ut            size32)
{
	mach_vm_offset_ut start;
	mach_vm_size_ut   size;
	vm32_address_ut   discard;

	if (vm_sanitize_add_overflow(start32, size32, &discard)) {
		return KERN_INVALID_ARGUMENT;
	}

	start = vm_sanitize_expand_addr_to_64(start32);
	size = vm_sanitize_expand_size_to_64(size32);

	return mach_vm_deallocate(map, start, size);
}

kern_return_t
vm32_vm_inherit(
	vm_map_t                map,
	vm32_offset_ut          start32,
	vm32_size_ut            size32,
	vm_inherit_ut           new_inheritance)
{
	mach_vm_offset_ut start;
	mach_vm_size_ut   size;
	vm32_address_ut   discard;

	if (map == VM_MAP_NULL ||
	    vm_sanitize_add_overflow(start32, size32, &discard)) {
		return KERN_INVALID_ARGUMENT;
	}

	start = vm_sanitize_expand_addr_to_64(start32);
	size = vm_sanitize_expand_size_to_64(size32);

	return mach_vm_inherit(map,
	           start,
	           size,
	           new_inheritance);
}

kern_return_t
vm32_vm_protect(
	vm_map_t                map,
	vm32_offset_ut          start32,
	vm32_size_ut            size32,
	boolean_t               set_maximum,
	vm_prot_ut              new_protection)
{
	mach_vm_offset_ut start;
	mach_vm_size_ut   size;
	vm32_address_ut   discard;

	if (map == VM_MAP_NULL ||
	    vm_sanitize_add_overflow(start32, size32, &discard)) {
		return KERN_INVALID_ARGUMENT;
	}

	start = vm_sanitize_expand_addr_to_64(start32);
	size = vm_sanitize_expand_size_to_64(size32);

	return mach_vm_protect(map, start,
	           size,
	           set_maximum,
	           new_protection);
}

kern_return_t
vm32_vm_machine_attribute(
	vm_map_t                map,
	vm32_address_ut         addr32,
	vm32_size_ut            size32,
	vm_machine_attribute_t  attribute,
	vm_machine_attribute_val_t *value) /* IN/OUT */
{
	mach_vm_offset_ut addr;
	mach_vm_size_ut   size;
	vm32_address_ut   discard;

	if (map == VM_MAP_NULL ||
	    vm_sanitize_add_overflow(addr32, size32, &discard)) {
		return KERN_INVALID_ARGUMENT;
	}

	addr = vm_sanitize_expand_addr_to_64(addr32);
	size = vm_sanitize_expand_size_to_64(size32);

	return mach_vm_machine_attribute(map, addr, size, attribute, value);
}

kern_return_t
vm32_vm_read(
	vm_map_t                map,
	vm32_address_ut         addr32,
	vm32_size_ut            size32,
	pointer_ut             *data,
	mach_msg_type_number_t *data_size)
{
	mach_vm_offset_ut addr;
	mach_vm_size_ut   size;

	addr = vm_sanitize_expand_addr_to_64(addr32);
	size = vm_sanitize_expand_size_to_64(size32);

	return mach_vm_read(map, addr, size, data, data_size);
}

kern_return_t
vm32_vm_read_list(
	vm_map_t                map,
	vm32_read_entry_t       data_list,
	natural_t               count)
{
	mach_vm_read_entry_t    mdata_list;
	mach_msg_type_number_t  i;
	kern_return_t                   result;

	for (i = 0; i < VM_MAP_ENTRY_MAX; i++) {
		mdata_list[i].address = data_list[i].address;
		mdata_list[i].size = data_list[i].size;
	}

	result = mach_vm_read_list(map, mdata_list, count);

	for (i = 0; i < VM_MAP_ENTRY_MAX; i++) {
		data_list[i].address = CAST_DOWN_EXPLICIT(vm32_address_t, mdata_list[i].address);
		data_list[i].size = CAST_DOWN_EXPLICIT(vm32_size_t, mdata_list[i].size);
	}

	return result;
}

kern_return_t
vm32_vm_read_overwrite(
	vm_map_t                map,
	vm32_address_ut         addr32,
	vm32_size_ut            size32,
	vm32_address_ut         data32,
	vm32_size_ut           *data_size32)
{
	mach_vm_offset_ut addr, data;
	mach_vm_size_ut   size, data_size;
	kern_return_t     result;

	addr = vm_sanitize_expand_addr_to_64(addr32);
	size = vm_sanitize_expand_size_to_64(size32);
	data = vm_sanitize_expand_addr_to_64(data32);
	data_size = vm_sanitize_expand_size_to_64(*data_size32);

	result = mach_vm_read_overwrite(map, addr, size, data, &data_size);
	*data_size32 = vm_sanitize_trunc_size_to_32(data_size);

	return result;
}

kern_return_t
vm32_vm_write(
	vm_map_t                map,
	vm32_address_ut         addr32,
	pointer_ut              data,
	mach_msg_type_number_t  size)
{
	mach_vm_offset_ut addr;

	addr = vm_sanitize_expand_addr_to_64(addr32);
	return mach_vm_write(map, addr, data, size);
}

kern_return_t
vm32_vm_copy(
	vm_map_t                map,
	vm32_address_ut         src_addr32,
	vm32_size_ut            size32,
	vm32_address_ut         dst_addr32)
{
	mach_vm_offset_ut src_addr, dst_addr;
	mach_vm_size_ut   size;

	src_addr = vm_sanitize_expand_addr_to_64(src_addr32);
	size     = vm_sanitize_expand_size_to_64(size32);
	dst_addr = vm_sanitize_expand_addr_to_64(dst_addr32);

	return mach_vm_copy(map, src_addr, size, dst_addr);
}

kern_return_t
vm32_vm_map_64(
	vm_map_t                target_map,
	vm32_offset_ut         *addr32,
	vm32_size_ut            size32,
	vm32_offset_ut          mask32,
	int                     flags,
	ipc_port_t              port,
	memory_object_offset_ut offset,
	boolean_t               copy,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	vm_inherit_ut           inheritance)
{
	mach_vm_offset_ut addr, mask;
	mach_vm_size_ut   size;
	kern_return_t     result;

	addr = vm_sanitize_expand_addr_to_64(*addr32);
	size = vm_sanitize_expand_size_to_64(size32);
	mask = vm_sanitize_expand_addr_to_64(mask32);

	result  = mach_vm_map_external(target_map, &addr, size, mask,
	    flags, port, offset, copy,
	    cur_protection, max_protection, inheritance);
	*addr32 = vm_sanitize_trunc_addr_to_32(addr);

	return result;
}

kern_return_t
vm32_vm_map(
	vm_map_t                target_map,
	vm32_offset_ut         *address,
	vm32_size_ut            size,
	vm32_offset_ut          mask,
	int                     flags,
	ipc_port_t              port,
	vm32_offset_ut          offset32,
	boolean_t               copy,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	vm_inherit_ut           inheritance)
{
	memory_object_offset_ut offset;

	offset = vm_sanitize_expand_addr_to_64(offset32);
	return vm32_vm_map_64(target_map, address, size, mask,
	           flags, port, offset, copy,
	           cur_protection, max_protection, inheritance);
}

kern_return_t
vm32_vm_remap(
	vm_map_t                target_map,
	vm32_offset_ut         *addr32,
	vm32_size_ut            size32,
	vm32_offset_ut          mask32,
	boolean_t               anywhere,
	vm_map_t                src_map,
	vm32_offset_ut          src_addr32,
	boolean_t               copy,
	vm_prot_ut             *cur_protection,
	vm_prot_ut             *max_protection,
	vm_inherit_ut           inheritance)
{
	mach_vm_offset_ut addr, mask, src_addr;
	mach_vm_size_ut   size;
	kern_return_t     result;

	addr = vm_sanitize_expand_addr_to_64(*addr32);
	size = vm_sanitize_expand_size_to_64(size32);
	mask = vm_sanitize_expand_addr_to_64(mask32);
	src_addr = vm_sanitize_expand_addr_to_64(src_addr32);

	result  = mach_vm_remap_external(target_map, &addr, size, mask,
	    anywhere, src_map, src_addr, copy,
	    cur_protection, max_protection, inheritance);
	*addr32 = vm_sanitize_trunc_addr_to_32(addr);


	return result;
}

kern_return_t
vm32_vm_msync(
	vm_map_t                map,
	vm32_address_ut         addr32,
	vm32_size_ut            size32,
	vm_sync_t               sync_flags)
{
	mach_vm_offset_ut addr;
	mach_vm_size_ut   size;

	addr = vm_sanitize_expand_addr_to_64(addr32);
	size = vm_sanitize_expand_size_to_64(size32);
	return mach_vm_msync(map, addr, size, sync_flags);
}

kern_return_t
vm32_vm_behavior_set(
	vm_map_t                map,
	vm32_offset_ut           start32,
	vm32_size_ut             size32,
	vm_behavior_ut           new_behavior)
{
	vm_address_ut     start;
	vm_size_ut        size;
	vm32_address_ut   discard;

	if (vm_sanitize_add_overflow(start32, size32, &discard)) {
		return KERN_INVALID_ARGUMENT;
	}

	start = vm_sanitize_expand_addr_to_64(start32);
	size = vm_sanitize_expand_size_to_64(size32);

	return mach_vm_behavior_set(map, start, size, new_behavior);
}

static inline kern_return_t
vm32_region_get_kern_return(
	kern_return_t           kr,
	vm_offset_ut            addr,
	vm_size_ut              size)
{
	vm_offset_ut end = vm_sanitize_compute_ut_end(addr, size);

	if (KERN_SUCCESS == kr && VM_SANITIZE_UNSAFE_UNWRAP(end) > VM32_MAX_ADDRESS) {
		return KERN_INVALID_ADDRESS;
	}
	return kr;
}

kern_return_t
vm32_vm_region_64(
	vm_map_t                map,
	vm32_offset_ut         *addr32,         /* IN/OUT */
	vm32_size_ut           *size32,         /* OUT */
	vm_region_flavor_t      flavor,         /* IN */
	vm_region_info_t        info,           /* OUT */
	mach_msg_type_number_t *count,          /* IN/OUT */
	mach_port_t            *object_name)    /* OUT */
{
	mach_vm_offset_ut addr;
	mach_vm_size_ut   size;
	kern_return_t     kr;

	addr = vm_sanitize_expand_addr_to_64(*addr32);
	size = vm_sanitize_expand_size_to_64(*size32);

	kr = mach_vm_region(map, &addr, &size, flavor, info, count, object_name);

	*addr32 = vm_sanitize_trunc_addr_to_32(addr);
	*size32 = vm_sanitize_trunc_size_to_32(size);

	return kr;
}

kern_return_t
vm32_vm_region(
	vm_map_t                map,
	vm32_address_ut        *addr32,         /* IN/OUT */
	vm32_size_ut           *size32,         /* OUT */
	vm_region_flavor_t      flavor,         /* IN */
	vm_region_info_t        info,           /* OUT */
	mach_msg_type_number_t *count,          /* IN/OUT */
	mach_port_t            *object_name)    /* OUT */
{
	mach_vm_offset_ut addr;
	mach_vm_size_ut   size;
	kern_return_t     kr;

	if (VM_MAP_NULL == map) {
		return KERN_INVALID_ARGUMENT;
	}

	addr = vm_sanitize_expand_addr_to_64(*addr32);
	size = vm_sanitize_expand_size_to_64(*size32);

	kr = vm_map_region(map, &addr, &size, flavor, info, count, object_name);

	*addr32 = vm_sanitize_trunc_addr_to_32(addr);
	*size32 = vm_sanitize_trunc_size_to_32(size);

	return vm32_region_get_kern_return(kr, addr, size);
}

kern_return_t
vm32_vm_region_recurse_64(
	vm_map_t                map,
	vm32_address_ut        *addr32,
	vm32_size_ut           *size32,
	uint32_t               *depth,
	vm_region_recurse_info_64_t info,
	mach_msg_type_number_t *infoCnt)
{
	mach_vm_offset_ut addr;
	mach_vm_size_ut   size;
	kern_return_t     kr;

	addr = vm_sanitize_expand_addr_to_64(*addr32);
	size = vm_sanitize_expand_size_to_64(*size32);

	kr = mach_vm_region_recurse(map, &addr, &size, depth, info, infoCnt);

	*addr32 = vm_sanitize_trunc_addr_to_32(addr);
	*size32 = vm_sanitize_trunc_size_to_32(size);

	return kr;
}

kern_return_t
vm32_vm_region_recurse(
	vm_map_t                map,
	vm32_offset_ut         *addr32,         /* IN/OUT */
	vm32_size_ut           *size32,         /* OUT */
	natural_t              *depth,          /* IN/OUT */
	vm_region_recurse_info_t info32,        /* IN/OUT */
	mach_msg_type_number_t *infoCnt)        /* IN/OUT */
{
	vm_region_submap_info_data_64_t info64;
	vm_region_submap_info_t info;
	mach_vm_offset_ut       addr;
	mach_vm_size_ut         size;
	kern_return_t           kr;

	if (VM_MAP_NULL == map || *infoCnt < VM_REGION_SUBMAP_INFO_COUNT) {
		return KERN_INVALID_ARGUMENT;
	}


	addr = vm_sanitize_expand_addr_to_64(*addr32);
	size = vm_sanitize_expand_size_to_64(*size32);
	info = (vm_region_submap_info_t)info32;
	*infoCnt = VM_REGION_SUBMAP_INFO_COUNT_64;

	kr = mach_vm_region_recurse(map, &addr, &size,
	    depth, (vm_region_recurse_info_t)&info64, infoCnt);

	info->protection = info64.protection;
	info->max_protection = info64.max_protection;
	info->inheritance = info64.inheritance;
	info->offset = (uint32_t)info64.offset; /* trouble-maker */
	info->user_tag = info64.user_tag;
	info->pages_resident = info64.pages_resident;
	info->pages_shared_now_private = info64.pages_shared_now_private;
	info->pages_swapped_out = info64.pages_swapped_out;
	info->pages_dirtied = info64.pages_dirtied;
	info->ref_count = info64.ref_count;
	info->shadow_depth = info64.shadow_depth;
	info->external_pager = info64.external_pager;
	info->share_mode = info64.share_mode;
	info->is_submap = info64.is_submap;
	info->behavior = info64.behavior;
	info->object_id = info64.object_id;
	info->user_wired_count = info64.user_wired_count;

	*addr32 = vm_sanitize_trunc_addr_to_32(addr);
	*size32 = vm_sanitize_trunc_size_to_32(size);
	*infoCnt = VM_REGION_SUBMAP_INFO_COUNT;

	return vm32_region_get_kern_return(kr, addr, size);
}

kern_return_t
vm32_vm_purgable_control(
	vm_map_t                map,
	vm32_offset_ut          addr32,
	vm_purgable_t           control,
	int                    *state)
{
	mach_vm_offset_ut addr;

	addr = vm_sanitize_expand_addr_to_64(addr32);
	return mach_vm_purgable_control(map, addr, control, state);
}

kern_return_t
vm32_vm_map_page_query(
	vm_map_t                map,
	vm32_offset_t           offset32,
	int                     *disposition,
	int                     *ref_count)
{
	vm_offset_ut offset = vm_sanitize_expand_addr_to_64(offset32);

	return mach_vm_page_query(map, offset, disposition, ref_count);
}

kern_return_t
vm32_mach_make_memory_entry_64(
	vm_map_t                target_map,
	memory_object_size_ut  *size,
	memory_object_offset_ut offset,
	vm_prot_ut              permission,
	ipc_port_t              *object_handle,
	ipc_port_t              parent_handle)
{
	// use the existing entrypoint
	return _mach_make_memory_entry(target_map, size, offset, permission, object_handle, parent_handle);
}

kern_return_t
vm32_mach_make_memory_entry(
	vm_map_t                target_map,
	vm32_size_ut           *size,
	vm32_offset_ut          offset,
	vm_prot_ut              permission,
	ipc_port_t              *object_handle,
	ipc_port_t              parent_entry)
{
	memory_object_size_ut   mo_size = vm_sanitize_expand_size_to_64(*size);
	memory_object_offset_ut mo_offset = vm_sanitize_expand_addr_to_64(offset);
	kern_return_t           kr;

	kr = _mach_make_memory_entry(target_map, &mo_size,
	    mo_offset, permission, object_handle, parent_entry);
	*size = vm_sanitize_trunc_size_to_32(mo_size);
	return kr;
}

kern_return_t
vm32_task_wire(
	vm_map_t        map,
	boolean_t       must_wire __unused)
{
	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_NOT_SUPPORTED;
}

kern_return_t
vm32_vm_map_exec_lockdown(
	vm_map_t        map)
{
	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	vm_map_lock(map);
	map->map_disallow_new_exec = TRUE;
	vm_map_unlock(map);

	return KERN_SUCCESS;
}


#endif /* VM32_SUPPORT */
