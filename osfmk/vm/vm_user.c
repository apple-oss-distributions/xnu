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
 *	File:	vm/vm_user.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	User-exported virtual memory functions.
 */

/*
 * There are three implementations of the "XXX_allocate" functionality in
 * the kernel: mach_vm_allocate (for any task on the platform), vm_allocate
 * (for a task with the same address space size, especially the current task),
 * and vm32_vm_allocate (for the specific case of a 32-bit task). vm_allocate
 * in the kernel should only be used on the kernel_task. vm32_vm_allocate only
 * makes sense on platforms where a user task can either be 32 or 64, or the kernel
 * task can be 32 or 64. mach_vm_allocate makes sense everywhere, and is preferred
 * for new code.
 *
 * The entrypoints into the kernel are more complex. All platforms support a
 * mach_vm_allocate-style API (subsystem 4800) which operates with the largest
 * size types for the platform. On platforms that only support U32/K32,
 * subsystem 4800 is all you need. On platforms that support both U32 and U64,
 * subsystem 3800 is used disambiguate the size of parameters, and they will
 * always be 32-bit and call into the vm32_vm_allocate APIs. On non-U32/K32 platforms,
 * the MIG glue should never call into vm_allocate directly, because the calling
 * task and kernel_task are unlikely to use the same size parameters
 *
 * New VM call implementations should be added here and to mach_vm.defs
 * (subsystem 4800), and use mach_vm_* "wide" types.
 */

#include <debug.h>

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/mach_types.h>    /* to get vm_address_t */
#include <mach/memory_object.h>
#include <mach/std_types.h>     /* to get pointer_t */
#include <mach/upl.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <mach/vm_statistics.h>
#include <mach/mach_syscalls.h>
#include <mach/sdt.h>
#include <mach/memory_entry.h>

#include <mach/host_priv_server.h>
#include <mach/mach_vm_server.h>
#include <mach/memory_entry_server.h>
#include <mach/vm_map_server.h>

#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/misc_protos.h>
#include <vm/vm_fault.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_object_xnu.h>
#include <vm/vm_kern.h>
#include <vm/vm_page_internal.h>
#include <vm/memory_object_internal.h>
#include <vm/vm_pageout_internal.h>
#include <vm/vm_protos.h>
#include <vm/vm_purgeable_internal.h>
#include <vm/vm_memory_entry_xnu.h>
#include <vm/vm_kern_internal.h>
#include <vm/vm_iokit.h>
#include <vm/vm_sanitize_internal.h>
#if CONFIG_DEFERRED_RECLAIM
#include <vm/vm_reclaim_internal.h>
#endif /* CONFIG_DEFERRED_RECLAIM */
#include <vm/vm_init_xnu.h>

#include <san/kasan.h>

#include <libkern/OSDebug.h>
#include <IOKit/IOBSD.h>
#include <sys/kdebug_triage.h>

/*
 *	mach_vm_allocate allocates "zero fill" memory in the specfied
 *	map.
 */
kern_return_t
mach_vm_allocate_external(
	vm_map_t                map,
	mach_vm_offset_ut      *addr,
	mach_vm_size_ut         size,
	int                     flags)
{
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;

	/* filter out any kernel-only flags */
	if (flags & ~VM_FLAGS_USER_ALLOCATE) {
		ktriage_record(thread_tid(current_thread()),
		    KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM,
		    KDBG_TRIAGE_RESERVED,
		    KDBG_TRIAGE_VM_ALLOCATE_KERNEL_BADFLAGS_ERROR),
		    KERN_INVALID_ARGUMENT /* arg */);
		return KERN_INVALID_ARGUMENT;
	}

	vm_map_kernel_flags_set_vmflags(&vmk_flags, flags);

	return mach_vm_allocate_kernel(map, addr, size, vmk_flags);
}

/*
 *	vm_allocate
 *	Legacy routine that allocates "zero fill" memory in the specfied
 *	map (which is limited to the same size as the kernel).
 */
kern_return_t
vm_allocate_external(
	vm_map_t        map,
	vm_offset_ut   *addr,
	vm_size_ut      size,
	int             flags)
{
	return mach_vm_allocate_external(map, addr, size, flags);
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
mach_vm_deallocate_sanitize(
	vm_map_t                map,
	mach_vm_offset_ut       start_u,
	mach_vm_size_ut         size_u,
	mach_vm_offset_t       *start,
	mach_vm_offset_t       *end,
	mach_vm_size_t         *size)
{
	return vm_sanitize_addr_size(start_u, size_u,
	           VM_SANITIZE_CALLER_VM_DEALLOCATE, map,
	           VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS, start,
	           end, size);
}

/*
 *	mach_vm_deallocate -
 *	deallocates the specified range of addresses in the
 *	specified address map.
 */
kern_return_t
mach_vm_deallocate(
	vm_map_t                map,
	mach_vm_offset_ut       start_u,
	mach_vm_size_ut         size_u)
{
	mach_vm_offset_t start, end;
	mach_vm_size_t   size;
	kern_return_t    kr;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = mach_vm_deallocate_sanitize(map,
	    start_u,
	    size_u,
	    &start,
	    &end,
	    &size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	return vm_map_remove_guard(map, start, end,
	           VM_MAP_REMOVE_NO_FLAGS,
	           KMEM_GUARD_NONE).kmr_return;
}

/*
 *	vm_deallocate -
 *	deallocates the specified range of addresses in the
 *	specified address map (limited to addresses the same
 *	size as the kernel).
 */
kern_return_t
vm_deallocate(
	vm_map_t                map,
	vm_offset_ut            start,
	vm_size_ut              size)
{
	return mach_vm_deallocate(map, start, size);
}

/*
 *	mach_vm_inherit -
 *	Sets the inheritance of the specified range in the
 *	specified map.
 */
kern_return_t
mach_vm_inherit(
	vm_map_t                map,
	mach_vm_offset_ut       start_u,
	mach_vm_size_ut         size_u,
	vm_inherit_ut           new_inheritance_u)
{
	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (VM_SANITIZE_UNSAFE_IS_ZERO(size_u)) {
		return KERN_SUCCESS;
	}

	return vm_map_inherit(map,
	           start_u,
	           vm_sanitize_compute_ut_end(start_u, size_u),
	           new_inheritance_u);
}

/*
 *	vm_inherit -
 *	Sets the inheritance of the specified range in the
 *	specified map (range limited to addresses
 */
kern_return_t
vm_inherit(
	vm_map_t                map,
	vm_offset_ut            start_u,
	vm_size_ut              size_u,
	vm_inherit_ut           new_inheritance_u)
{
	return mach_vm_inherit(map, start_u, size_u, new_inheritance_u);
}

/*
 *	mach_vm_protect -
 *	Sets the protection of the specified range in the
 *	specified map.
 */

kern_return_t
mach_vm_protect(
	vm_map_t                map,
	mach_vm_address_ut      start_u,
	mach_vm_size_ut         size_u,
	boolean_t               set_maximum,
	vm_prot_ut              new_protection_u)
{
	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (VM_SANITIZE_UNSAFE_IS_ZERO(size_u)) {
		return KERN_SUCCESS;
	}

	return vm_map_protect(map,
	           start_u,
	           vm_sanitize_compute_ut_end(start_u, size_u),
	           set_maximum,
	           new_protection_u);
}

/*
 *	vm_protect -
 *	Sets the protection of the specified range in the
 *	specified map. Addressability of the range limited
 *	to the same size as the kernel.
 */

kern_return_t
vm_protect(
	vm_map_t                map,
	vm_offset_ut            start_u,
	vm_size_ut              size_u,
	boolean_t               set_maximum,
	vm_prot_ut              new_protection_u)
{
	return mach_vm_protect(map, start_u, size_u, set_maximum, new_protection_u);
}

/*
 * mach_vm_machine_attributes -
 * Handle machine-specific attributes for a mapping, such
 * as cachability, migrability, etc.
 */
kern_return_t
mach_vm_machine_attribute(
	vm_map_t                map,
	mach_vm_address_ut      addr_u,
	mach_vm_size_ut         size_u,
	vm_machine_attribute_t  attribute,
	vm_machine_attribute_val_t *value) /* IN/OUT */
{
	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (VM_SANITIZE_UNSAFE_IS_ZERO(size_u)) {
		return KERN_SUCCESS;
	}

	return vm_map_machine_attribute(map,
	           addr_u,
	           vm_sanitize_compute_ut_end(addr_u, size_u),
	           attribute,
	           value);
}

/*
 * vm_machine_attribute -
 * Handle machine-specific attributes for a mapping, such
 * as cachability, migrability, etc. Limited addressability
 * (same range limits as for the native kernel map).
 */
kern_return_t
vm_machine_attribute(
	vm_map_t                map,
	vm_address_ut           addr_u,
	vm_size_ut              size_u,
	vm_machine_attribute_t  attribute,
	vm_machine_attribute_val_t *value) /* IN/OUT */
{
	return mach_vm_machine_attribute(map, addr_u, size_u, attribute, value);
}

/*
 * mach_vm_read -
 * Read/copy a range from one address space and return it to the caller.
 *
 * It is assumed that the address for the returned memory is selected by
 * the IPC implementation as part of receiving the reply to this call.
 * If IPC isn't used, the caller must deal with the vm_map_copy_t object
 * that gets returned.
 *
 * JMM - because of mach_msg_type_number_t, this call is limited to a
 * single 4GB region at this time.
 *
 */
kern_return_t
mach_vm_read(
	vm_map_t                map,
	mach_vm_address_ut      addr,
	mach_vm_size_ut         size,
	pointer_ut             *data,
	mach_msg_type_number_t *data_size)
{
	kern_return_t   error;
	vm_map_copy_t   ipc_address;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * mach_msg_type_number_t is a signed int,
	 * make sure we do not overflow it.
	 */
	if (!VM_SANITIZE_UNSAFE_FITS(size, mach_msg_type_number_t)) {
		return KERN_INVALID_ARGUMENT;
	}

	error = vm_map_copyin(map, addr, size, FALSE, &ipc_address);

	if (KERN_SUCCESS == error) {
		VM_SANITIZE_UT_SET(*data, (pointer_t) ipc_address);
		/* On success we know size was validated by vm_map_copyin. */
		*data_size =
		    (mach_msg_type_number_t)VM_SANITIZE_UNSAFE_UNWRAP(size);
	}
	return error;
}

/*
 * vm_read -
 * Read/copy a range from one address space and return it to the caller.
 * Limited addressability (same range limits as for the native kernel map).
 *
 * It is assumed that the address for the returned memory is selected by
 * the IPC implementation as part of receiving the reply to this call.
 * If IPC isn't used, the caller must deal with the vm_map_copy_t object
 * that gets returned.
 */
kern_return_t
vm_read(
	vm_map_t                map,
	vm_address_ut           addr,
	vm_size_ut              size,
	pointer_ut             *data,
	mach_msg_type_number_t *data_size)
{
	return mach_vm_read(map, addr, size, data, data_size);
}

/*
 * mach_vm_read_list -
 * Read/copy a list of address ranges from specified map.
 *
 * MIG does not know how to deal with a returned array of
 * vm_map_copy_t structures, so we have to do the copyout
 * manually here.
 */
kern_return_t
mach_vm_read_list(
	vm_map_t                        map,
	mach_vm_read_entry_t            data_list,
	natural_t                       count)
{
	mach_msg_type_number_t  i;
	kern_return_t   error;
	vm_map_copy_t   copy;

	if (map == VM_MAP_NULL ||
	    count > VM_MAP_ENTRY_MAX) {
		return KERN_INVALID_ARGUMENT;
	}

	error = KERN_SUCCESS;
	for (i = 0; i < count; i++) {
		vm_map_address_t map_addr;
		vm_map_size_t map_size;

		map_addr = (vm_map_address_t)(data_list[i].address);
		map_size = (vm_map_size_t)(data_list[i].size);

		if (map_size != 0) {
			error = vm_map_copyin(map,
			    map_addr,
			    map_size,
			    FALSE,              /* src_destroy */
			    &copy);
			if (KERN_SUCCESS == error) {
				error = vm_map_copyout(
					current_task()->map,
					&map_addr,
					copy);
				if (KERN_SUCCESS == error) {
					data_list[i].address = map_addr;
					continue;
				}
				vm_map_copy_discard(copy);
			}
		}
		data_list[i].address = (mach_vm_address_t)0;
		data_list[i].size = (mach_vm_size_t)0;
	}
	return error;
}

/*
 * vm_read_list -
 * Read/copy a list of address ranges from specified map.
 *
 * MIG does not know how to deal with a returned array of
 * vm_map_copy_t structures, so we have to do the copyout
 * manually here.
 *
 * The source and destination ranges are limited to those
 * that can be described with a vm_address_t (i.e. same
 * size map as the kernel).
 *
 * JMM - If the result of the copyout is an address range
 * that cannot be described with a vm_address_t (i.e. the
 * caller had a larger address space but used this call
 * anyway), it will result in a truncated address being
 * returned (and a likely confused caller).
 */

kern_return_t
vm_read_list(
	vm_map_t                map,
	vm_read_entry_t data_list,
	natural_t               count)
{
	mach_msg_type_number_t  i;
	kern_return_t   error;
	vm_map_copy_t   copy;

	if (map == VM_MAP_NULL ||
	    count > VM_MAP_ENTRY_MAX) {
		return KERN_INVALID_ARGUMENT;
	}

	error = KERN_SUCCESS;
	for (i = 0; i < count; i++) {
		vm_map_address_t map_addr;
		vm_map_size_t map_size;

		map_addr = (vm_map_address_t)(data_list[i].address);
		map_size = (vm_map_size_t)(data_list[i].size);

		if (map_size != 0) {
			error = vm_map_copyin(map,
			    map_addr,
			    map_size,
			    FALSE,              /* src_destroy */
			    &copy);
			if (KERN_SUCCESS == error) {
				error = vm_map_copyout(current_task()->map,
				    &map_addr,
				    copy);
				if (KERN_SUCCESS == error) {
					data_list[i].address =
					    CAST_DOWN(vm_offset_t, map_addr);
					continue;
				}
				vm_map_copy_discard(copy);
			}
		}
		data_list[i].address = (mach_vm_address_t)0;
		data_list[i].size = (mach_vm_size_t)0;
	}
	return error;
}

/*
 * mach_vm_read_overwrite -
 * Overwrite a range of the current map with data from the specified
 * map/address range.
 *
 * In making an assumption that the current thread is local, it is
 * no longer cluster-safe without a fully supportive local proxy
 * thread/task (but we don't support cluster's anymore so this is moot).
 */

kern_return_t
mach_vm_read_overwrite(
	vm_map_t                map,
	mach_vm_address_ut      address,
	mach_vm_size_ut         size,
	mach_vm_address_ut      data,
	mach_vm_size_ut        *data_size)
{
	kern_return_t   error;
	vm_map_copy_t   copy;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	error = vm_map_copyin(map, address, size, FALSE, &copy);

	if (KERN_SUCCESS == error) {
		if (copy) {
			assert(VM_SANITIZE_UNSAFE_IS_EQUAL(size, copy->size));
		}

		error = vm_map_copy_overwrite(current_thread()->map,
		    data, copy, size, FALSE);
		if (KERN_SUCCESS == error) {
			*data_size = size;
			return error;
		}
		vm_map_copy_discard(copy);
	}
	return error;
}

/*
 * vm_read_overwrite -
 * Overwrite a range of the current map with data from the specified
 * map/address range.
 *
 * This routine adds the additional limitation that the source and
 * destination ranges must be describable with vm_address_t values
 * (i.e. the same size address spaces as the kernel, or at least the
 * the ranges are in that first portion of the respective address
 * spaces).
 */

kern_return_t
vm_read_overwrite(
	vm_map_t                map,
	vm_address_ut           address,
	vm_size_ut              size,
	vm_address_ut           data,
	vm_size_ut             *data_size)
{
	return mach_vm_read_overwrite(map, address, size, data, data_size);
}


/*
 * mach_vm_write -
 * Overwrite the specified address range with the data provided
 * (from the current map).
 */
kern_return_t
mach_vm_write(
	vm_map_t                map,
	mach_vm_address_ut      address,
	pointer_ut              data_u,
	mach_msg_type_number_t  size)
{
	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * data is created by the kernel's MIG server from a userspace buffer,
	 * so it is safe to unwrap.
	 */
	vm_map_copy_t data = (vm_map_copy_t) VM_SANITIZE_UNSAFE_UNWRAP(data_u);

	return vm_map_copy_overwrite(map, address,
	           data, size, FALSE /* interruptible XXX */);
}

/*
 * vm_write -
 * Overwrite the specified address range with the data provided
 * (from the current map).
 *
 * The addressability of the range of addresses to overwrite is
 * limited bu the use of a vm_address_t (same size as kernel map).
 * Either the target map is also small, or the range is in the
 * low addresses within it.
 */
kern_return_t
vm_write(
	vm_map_t                map,
	vm_address_ut           address,
	pointer_ut              data,
	mach_msg_type_number_t  size)
{
	return mach_vm_write(map, address, data, size);
}

/*
 * mach_vm_copy -
 * Overwrite one range of the specified map with the contents of
 * another range within that same map (i.e. both address ranges
 * are "over there").
 */
kern_return_t
mach_vm_copy(
	vm_map_t                map,
	mach_vm_address_ut      source_address,
	mach_vm_size_ut         size,
	mach_vm_address_ut      dest_address)
{
	vm_map_copy_t copy;
	kern_return_t kr;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = vm_map_copyin(map, source_address, size, FALSE, &copy);

	if (KERN_SUCCESS == kr) {
		if (copy) {
			assert(VM_SANITIZE_UNSAFE_IS_EQUAL(size, copy->size));
		}

		kr = vm_map_copy_overwrite(map, dest_address,
		    copy, size, FALSE /* interruptible XXX */);

		if (KERN_SUCCESS != kr) {
			vm_map_copy_discard(copy);
		}
	}
	return kr;
}

kern_return_t
vm_copy(
	vm_map_t                map,
	vm_address_ut           source_address,
	vm_size_ut              size,
	vm_address_ut           dest_address)
{
	return mach_vm_copy(map, source_address, size, dest_address);
}

/*
 * mach_vm_map -
 * Map some range of an object into an address space.
 *
 * The object can be one of several types of objects:
 *	NULL - anonymous memory
 *	a named entry - a range within another address space
 *	                or a range within a memory object
 *	a whole memory object
 *
 */
kern_return_t
mach_vm_map_external(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         initial_size,
	mach_vm_offset_ut       mask,
	int                     flags,
	ipc_port_t              port,
	memory_object_offset_ut offset,
	boolean_t               copy,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	vm_inherit_ut           inheritance)
{
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;

	/* filter out any kernel-only flags */
	if (flags & ~VM_FLAGS_USER_MAP) {
		return KERN_INVALID_ARGUMENT;
	}

	vm_map_kernel_flags_set_vmflags(&vmk_flags, flags);
	/* range_id is set by mach_vm_map_kernel */
	return mach_vm_map_kernel(target_map, address, initial_size, mask,
	           vmk_flags, port, offset, copy,
	           cur_protection, max_protection,
	           inheritance);
}

/* legacy interface */
__attribute__((always_inline))
kern_return_t
vm_map_64_external(
	vm_map_t                target_map,
	vm_offset_ut           *address,
	vm_size_ut              size,
	vm_offset_ut            mask,
	int                     flags,
	ipc_port_t              port,
	memory_object_offset_ut offset,
	boolean_t               copy,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	vm_inherit_ut           inheritance)
{
	return mach_vm_map_external(target_map, address,
	           size, mask, flags, port, offset, copy,
	           cur_protection, max_protection, inheritance);
}

/* temporary, until world build */
__attribute__((always_inline))
kern_return_t
vm_map_external(
	vm_map_t                target_map,
	vm_offset_ut           *address,
	vm_size_ut              size,
	vm_offset_ut            mask,
	int                     flags,
	ipc_port_t              port,
	vm_offset_ut            offset,
	boolean_t               copy,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	vm_inherit_ut           inheritance)
{
	return mach_vm_map_external(target_map, address,
	           size, mask, flags, port, offset, copy,
	           cur_protection, max_protection, inheritance);
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
mach_vm_remap_new_external_sanitize(
	vm_map_t                target_map,
	vm_prot_ut              cur_protection_u,
	vm_prot_ut              max_protection_u,
	vm_prot_t              *cur_protection,
	vm_prot_t              *max_protection)
{
	return vm_sanitize_cur_and_max_prots(cur_protection_u, max_protection_u,
	           VM_SANITIZE_CALLER_VM_MAP_REMAP, target_map,
	           cur_protection, max_protection);
}

/*
 * mach_vm_remap_new -
 * Behaves like mach_vm_remap, except that VM_FLAGS_RETURN_DATA_ADDR is always set
 * and {cur,max}_protection are in/out.
 */
kern_return_t
mach_vm_remap_new_external(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         size,
	mach_vm_offset_ut       mask,
	int                     flags,
	mach_port_t             src_tport,
	mach_vm_offset_ut       memory_address,
	boolean_t               copy,
	vm_prot_ut             *cur_protection_u,   /* IN/OUT */
	vm_prot_ut             *max_protection_u,   /* IN/OUT */
	vm_inherit_ut           inheritance)
{
	vm_map_kernel_flags_t   vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vm_map_t                src_map;
	vm_prot_t               cur_protection, max_protection;
	kern_return_t           kr;

	if (target_map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/* filter out any kernel-only flags */
	if (flags & ~VM_FLAGS_USER_REMAP) {
		return KERN_INVALID_ARGUMENT;
	}

	vm_map_kernel_flags_set_vmflags(&vmk_flags,
	    flags | VM_FLAGS_RETURN_DATA_ADDR);

	/*
	 * We don't need cur_protection here, but sanitizing it before
	 * enforcing W^X below matches historical error codes better.
	 */
	kr = mach_vm_remap_new_external_sanitize(target_map,
	    *cur_protection_u,
	    *max_protection_u,
	    &cur_protection,
	    &max_protection);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	if ((max_protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) ==
	    (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
		/*
		 * XXX FBDP TODO
		 * enforce target's "wx" policies
		 */
		return KERN_PROTECTION_FAILURE;
	}

	if (copy || max_protection == VM_PROT_READ || max_protection == VM_PROT_NONE) {
		src_map = convert_port_to_map_read(src_tport);
	} else {
		src_map = convert_port_to_map(src_tport);
	}

	/* range_id is set by vm_map_remap */
	kr = vm_map_remap(target_map,
	    address,
	    size,
	    mask,
	    vmk_flags,
	    src_map,
	    memory_address,
	    copy,
	    cur_protection_u,    /* IN/OUT */
	    max_protection_u,    /* IN/OUT */
	    inheritance);

	vm_map_deallocate(src_map);

	if (kr == KERN_SUCCESS) {
		ipc_port_release_send(src_tport);  /* consume on success */
	}
	return kr;
}

/*
 * mach_vm_remap -
 * Remap a range of memory from one task into another,
 * to another address range within the same task, or
 * over top of itself (with altered permissions and/or
 * as an in-place copy of itself).
 */
kern_return_t
mach_vm_remap_external(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         size,
	mach_vm_offset_ut       mask,
	int                     flags,
	vm_map_t                src_map,
	mach_vm_offset_ut       memory_address,
	boolean_t               copy,
	vm_prot_ut             *cur_protection,    /* OUT */
	vm_prot_ut             *max_protection,    /* OUT */
	vm_inherit_ut           inheritance)
{
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;

	/* filter out any kernel-only flags */
	if (flags & ~VM_FLAGS_USER_REMAP) {
		return KERN_INVALID_ARGUMENT;
	}

	vm_map_kernel_flags_set_vmflags(&vmk_flags, flags);

	*cur_protection = vm_sanitize_wrap_prot(VM_PROT_NONE);
	*max_protection = vm_sanitize_wrap_prot(VM_PROT_NONE);
	vmk_flags.vmkf_remap_legacy_mode = true;

	/* range_id is set by vm_map_remap */
	return vm_map_remap(target_map,
	           address,
	           size,
	           mask,
	           vmk_flags,
	           src_map,
	           memory_address,
	           copy,
	           cur_protection,
	           max_protection,
	           inheritance);
}

/*
 * vm_remap_new -
 * Behaves like vm_remap, except that VM_FLAGS_RETURN_DATA_ADDR is always set
 * and {cur,max}_protection are in/out.
 */
kern_return_t
vm_remap_new_external(
	vm_map_t                target_map,
	vm_offset_ut           *address,
	vm_size_ut              size,
	vm_offset_ut            mask,
	int                     flags,
	mach_port_t             src_tport,
	vm_offset_ut            memory_address,
	boolean_t               copy,
	vm_prot_ut             *cur_protection,       /* IN/OUT */
	vm_prot_ut             *max_protection,       /* IN/OUT */
	vm_inherit_ut           inheritance)
{
	return mach_vm_remap_new_external(target_map,
	           address,
	           size,
	           mask,
	           flags,
	           src_tport,
	           memory_address,
	           copy,
	           cur_protection, /* IN/OUT */
	           max_protection, /* IN/OUT */
	           inheritance);
}

/*
 * vm_remap -
 * Remap a range of memory from one task into another,
 * to another address range within the same task, or
 * over top of itself (with altered permissions and/or
 * as an in-place copy of itself).
 *
 * The addressability of the source and target address
 * range is limited by the size of vm_address_t (in the
 * kernel context).
 */
kern_return_t
vm_remap_external(
	vm_map_t                target_map,
	vm_offset_ut           *address,
	vm_size_ut              size,
	vm_offset_ut            mask,
	int                     flags,
	vm_map_t                src_map,
	vm_offset_ut            memory_address,
	boolean_t               copy,
	vm_prot_ut             *cur_protection,    /* OUT */
	vm_prot_ut             *max_protection,    /* OUT */
	vm_inherit_ut           inheritance)
{
	return mach_vm_remap_external(target_map, address,
	           size, mask, flags, src_map, memory_address, copy,
	           cur_protection, max_protection, inheritance);
}

/*
 * NOTE: these routine (and this file) will no longer require mach_host_server.h
 * when mach_vm_wire and vm_wire are changed to use ledgers.
 */
#include <mach/mach_host_server.h>
/*
 *	mach_vm_wire
 *	Specify that the range of the virtual address space
 *	of the target task must not cause page faults for
 *	the indicated accesses.
 *
 *	[ To unwire the pages, specify VM_PROT_NONE. ]
 */
kern_return_t
mach_vm_wire_external(
	host_priv_t             host_priv,
	vm_map_t                map,
	mach_vm_address_ut      start,
	mach_vm_size_ut         size,
	vm_prot_ut              access)
{
	kern_return_t     rc;
	mach_vm_offset_ut end;

	if (host_priv == HOST_PRIV_NULL) {
		return KERN_INVALID_HOST;
	}

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_TASK;
	}

	end = vm_sanitize_compute_ut_end(start, size);
	if (VM_SANITIZE_UNSAFE_IS_ZERO(access)) {
		rc = vm_map_unwire_impl(map, start, end, true,
		    VM_SANITIZE_CALLER_VM_UNWIRE_USER);
	} else {
		rc = vm_map_wire_impl(map, start, end, access,
		    VM_KERN_MEMORY_MLOCK, true, NULL, VM_SANITIZE_CALLER_VM_WIRE_USER);
	}

	return rc;
}

/*
 *	vm_wire -
 *	Specify that the range of the virtual address space
 *	of the target task must not cause page faults for
 *	the indicated accesses.
 *
 *	[ To unwire the pages, specify VM_PROT_NONE. ]
 */
kern_return_t
vm_wire(
	host_priv_t             host_priv,
	vm_map_t                map,
	vm_offset_ut            start,
	vm_size_ut              size,
	vm_prot_ut              access)
{
	return mach_vm_wire_external(host_priv, map, start, size, access);
}

/*
 *	vm_msync
 *
 *	Synchronises the memory range specified with its backing store
 *	image by either flushing or cleaning the contents to the appropriate
 *	memory manager.
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
 *	RETURNS
 *	KERN_INVALID_TASK		Bad task parameter
 *	KERN_INVALID_ARGUMENT		both sync and async were specified.
 *	KERN_SUCCESS			The usual.
 *	KERN_INVALID_ADDRESS		There was a hole in the region.
 */

kern_return_t
mach_vm_msync(
	vm_map_t                map,
	mach_vm_address_ut      address_u,
	mach_vm_size_ut         size_u,
	vm_sync_t               sync_flags)
{
	if (map == VM_MAP_NULL) {
		return KERN_INVALID_TASK;
	}

	if (VM_SANITIZE_UNSAFE_IS_ZERO(size_u)) {
		return KERN_SUCCESS;
	}

	return vm_map_msync(map, address_u, size_u, sync_flags);
}

/*
 *	vm_msync
 *
 *	Synchronises the memory range specified with its backing store
 *	image by either flushing or cleaning the contents to the appropriate
 *	memory manager.
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
 *	The addressability of the range is limited to that which can
 *	be described by a vm_address_t.
 *
 *	RETURNS
 *	KERN_INVALID_TASK		Bad task parameter
 *	KERN_INVALID_ARGUMENT		both sync and async were specified.
 *	KERN_SUCCESS			The usual.
 *	KERN_INVALID_ADDRESS		There was a hole in the region.
 */

kern_return_t
vm_msync(
	vm_map_t        map,
	vm_address_ut   address_u,
	vm_size_ut      size_u,
	vm_sync_t       sync_flags)
{
	return mach_vm_msync(map, address_u, size_u, sync_flags);
}


int
vm_toggle_entry_reuse(int toggle, int *old_value)
{
	vm_map_t map = current_map();

	assert(!map->is_nested_map);
	if (toggle == VM_TOGGLE_GETVALUE && old_value != NULL) {
		*old_value = map->disable_vmentry_reuse;
	} else if (toggle == VM_TOGGLE_SET) {
		vm_map_entry_t map_to_entry;

		vm_map_lock(map);
		vm_map_disable_hole_optimization(map);
		map->disable_vmentry_reuse = TRUE;
		__IGNORE_WCASTALIGN(map_to_entry = vm_map_to_entry(map));
		if (map->first_free == map_to_entry) {
			map->highest_entry_end = vm_map_min(map);
		} else {
			map->highest_entry_end = map->first_free->vme_end;
		}
		vm_map_unlock(map);
	} else if (toggle == VM_TOGGLE_CLEAR) {
		vm_map_lock(map);
		map->disable_vmentry_reuse = FALSE;
		vm_map_unlock(map);
	} else {
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}


static __attribute__((always_inline, warn_unused_result))
kern_return_t
mach_vm_behavior_set_sanitize(
	vm_map_t                map,
	mach_vm_offset_ut       start_u,
	mach_vm_size_ut         size_u,
	vm_behavior_ut          new_behavior_u,
	mach_vm_offset_t       *start,
	mach_vm_offset_t       *end,
	mach_vm_size_t         *size,
	vm_behavior_t          *new_behavior)
{
	mach_vm_offset_t align_mask;
	kern_return_t    kr;

	kr = vm_sanitize_behavior(new_behavior_u, VM_SANITIZE_CALLER_VM_BEHAVIOR_SET, new_behavior);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	/* Choose alignment of addr/size based on the behavior being set. */
	switch (*new_behavior) {
	case VM_BEHAVIOR_REUSABLE:
	case VM_BEHAVIOR_REUSE:
	case VM_BEHAVIOR_CAN_REUSE:
	case VM_BEHAVIOR_ZERO:
		/*
		 * Align to the hardware page size, to allow
		 * malloc() to maximize the amount of re-usability,
		 * even on systems with larger software page size.
		 */
		align_mask = PAGE_MASK;
		break;
	default:
		align_mask = VM_MAP_PAGE_MASK(map);
		break;
	}

	kr = vm_sanitize_addr_size(start_u, size_u, VM_SANITIZE_CALLER_VM_BEHAVIOR_SET,
	    align_mask, map,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS,
	    start, end, size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	return KERN_SUCCESS;
}

/*
 *	mach_vm_behavior_set
 *
 *	Sets the paging behavior attribute for the  specified range
 *	in the specified map.
 *
 *	This routine will fail with KERN_INVALID_ADDRESS if any address
 *	in [start,start+size) is not a valid allocated memory region.
 */
kern_return_t
mach_vm_behavior_set(
	vm_map_t                map,
	mach_vm_offset_ut       start_u,
	mach_vm_size_ut         size_u,
	vm_behavior_ut          new_behavior_u)
{
	kern_return_t    kr;
	mach_vm_offset_t start, end;
	mach_vm_size_t   size;
	vm_behavior_t    new_behavior;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = mach_vm_behavior_set_sanitize(map,
	    start_u, size_u, new_behavior_u,
	    &start, &end, &size, &new_behavior);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	return vm_map_behavior_set(map,
	           start,
	           end,
	           new_behavior);
}

/*
 *	vm_behavior_set
 *
 *	Sets the paging behavior attribute for the  specified range
 *	in the specified map.
 *
 *	This routine will fail with KERN_INVALID_ADDRESS if any address
 *	in [start,start+size) is not a valid allocated memory region.
 *
 *	This routine is potentially limited in addressibility by the
 *	use of vm_offset_t (if the map provided is larger than the
 *	kernel's).
 */
kern_return_t
vm_behavior_set(
	vm_map_t                map,
	vm_offset_ut            start,
	vm_size_ut              size,
	vm_behavior_ut          new_behavior)
{
	return mach_vm_behavior_set(map,
	           start,
	           size,
	           new_behavior);
}

/*
 *	mach_vm_region:
 *
 *	User call to obtain information about a region in
 *	a task's address map. Currently, only one flavor is
 *	supported.
 *
 *	XXX The reserved and behavior fields cannot be filled
 *	    in until the vm merge from the IK is completed, and
 *	    vm_reserve is implemented.
 *
 *	XXX Dependency: syscall_vm_region() also supports only one flavor.
 */

kern_return_t
mach_vm_region(
	vm_map_t                map,
	mach_vm_offset_ut      *address_u,      /* IN/OUT */
	mach_vm_size_ut        *size_u,         /* OUT */
	vm_region_flavor_t      flavor,         /* IN */
	vm_region_info_t        info,           /* OUT */
	mach_msg_type_number_t *count,          /* IN/OUT */
	mach_port_t            *object_name)    /* OUT */
{
	if (VM_MAP_NULL == map) {
		return KERN_INVALID_ARGUMENT;
	}

	/* legacy conversion */
	if (VM_REGION_BASIC_INFO == flavor) {
		flavor = VM_REGION_BASIC_INFO_64;
	}

	return vm_map_region(map, address_u, size_u, flavor, info, count,
	           object_name);
}

static inline kern_return_t
vm_region_get_kern_return(
	kern_return_t           kr,
	vm_offset_ut            addr_u,
	vm_size_ut              size_u)
{
	vm_offset_ut end_u = vm_sanitize_compute_ut_end(addr_u, size_u);

	if (KERN_SUCCESS == kr && VM_SANITIZE_UNSAFE_UNWRAP(end_u) > VM_MAX_ADDRESS) {
		return KERN_INVALID_ADDRESS;
	}
	return kr;
}

/*
 *	vm_region_64 and vm_region:
 *
 *	User call to obtain information about a region in
 *	a task's address map. Currently, only one flavor is
 *	supported.
 *
 *	XXX The reserved and behavior fields cannot be filled
 *	    in until the vm merge from the IK is completed, and
 *	    vm_reserve is implemented.
 *
 *	XXX Dependency: syscall_vm_region() also supports only one flavor.
 */

kern_return_t
vm_region_64(
	vm_map_t                map,
	vm_offset_ut           *address_u,      /* IN/OUT */
	vm_size_ut             *size_u,         /* OUT */
	vm_region_flavor_t      flavor,         /* IN */
	vm_region_info_t        info,           /* OUT */
	mach_msg_type_number_t *count,          /* IN/OUT */
	mach_port_t            *object_name)    /* OUT */
{
	kern_return_t kr;

	kr = mach_vm_region(map, address_u, size_u, flavor, info, count,
	    object_name);

	return vm_region_get_kern_return(kr, *address_u, *size_u);
}

kern_return_t
vm_region(
	vm_map_t                map,
	vm_address_ut          *address_u,      /* IN/OUT */
	vm_size_ut             *size_u,         /* OUT */
	vm_region_flavor_t      flavor,         /* IN */
	vm_region_info_t        info,           /* OUT */
	mach_msg_type_number_t *count,          /* IN/OUT */
	mach_port_t            *object_name)    /* OUT */
{
	kern_return_t kr;

	if (VM_MAP_NULL == map) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = vm_map_region(map, address_u, size_u, flavor, info, count,
	    object_name);

	return vm_region_get_kern_return(kr, *address_u, *size_u);
}

/*
 *	vm_region_recurse: A form of vm_region which follows the
 *	submaps in a target map
 *
 */
kern_return_t
mach_vm_region_recurse(
	vm_map_t                map,
	mach_vm_address_ut     *address_u,
	mach_vm_size_ut        *size_u,
	uint32_t               *depth,
	vm_region_recurse_info_t info,
	mach_msg_type_number_t *infoCnt)
{
	if (VM_MAP_NULL == map) {
		return KERN_INVALID_ARGUMENT;
	}

	return vm_map_region_recurse_64(map, address_u, size_u, depth,
	           (vm_region_submap_info_64_t)info, infoCnt);
}

/*
 *	vm_region_recurse: A form of vm_region which follows the
 *	submaps in a target map
 *
 */
kern_return_t
vm_region_recurse_64(
	vm_map_t                map,
	vm_address_ut          *address_u,
	vm_size_ut             *size_u,
	uint32_t               *depth,
	vm_region_recurse_info_64_t info,
	mach_msg_type_number_t *infoCnt)
{
	kern_return_t kr;

	kr = mach_vm_region_recurse(map, address_u, size_u, depth,
	    (vm_region_recurse_info_t)info, infoCnt);

	return vm_region_get_kern_return(kr, *address_u, *size_u);
}

kern_return_t
vm_region_recurse(
	vm_map_t                map,
	vm_offset_ut           *address_u,      /* IN/OUT */
	vm_size_ut             *size_u,         /* OUT */
	natural_t              *depth,          /* IN/OUT */
	vm_region_recurse_info_t info32,        /* IN/OUT */
	mach_msg_type_number_t *infoCnt)        /* IN/OUT */
{
	vm_region_submap_info_data_64_t info64;
	vm_region_submap_info_t info;
	kern_return_t           kr;

	if (VM_MAP_NULL == map || *infoCnt < VM_REGION_SUBMAP_INFO_COUNT) {
		return KERN_INVALID_ARGUMENT;
	}

	info = (vm_region_submap_info_t)info32;
	*infoCnt = VM_REGION_SUBMAP_INFO_COUNT_64;

	kr = vm_map_region_recurse_64(map, address_u, size_u,
	    depth, &info64, infoCnt);

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

	*infoCnt = VM_REGION_SUBMAP_INFO_COUNT;

	return vm_region_get_kern_return(kr, *address_u, *size_u);
}

kern_return_t
mach_vm_purgable_control(
	vm_map_t                map,
	mach_vm_offset_ut       address_u,
	vm_purgable_t           control,
	int                    *state)
{
	if (VM_MAP_NULL == map) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (control) {
	case VM_PURGABLE_SET_STATE:
	case VM_PURGABLE_GET_STATE:
	case VM_PURGABLE_PURGE_ALL:
		break;
	case VM_PURGABLE_SET_STATE_FROM_KERNEL:
	default:
		/* not allowed from user-space */
		return KERN_INVALID_ARGUMENT;
	}

	return vm_map_purgable_control(map, address_u, control, state);
}

kern_return_t
mach_vm_purgable_control_external(
	mach_port_t             target_tport,
	mach_vm_offset_ut       address_u,
	vm_purgable_t           control,
	int                    *state)
{
	vm_map_t map;
	kern_return_t kr;

	if (control == VM_PURGABLE_GET_STATE) {
		map = convert_port_to_map_read(target_tport);
	} else {
		map = convert_port_to_map(target_tport);
	}

	kr = mach_vm_purgable_control(map, address_u, control, state);
	vm_map_deallocate(map);

	return kr;
}

kern_return_t
vm_purgable_control_external(
	mach_port_t             target_tport,
	vm_offset_ut            address,
	vm_purgable_t           control,
	int                     *state)
{
	return mach_vm_purgable_control_external(target_tport, address, control, state);
}


kern_return_t
mach_vm_page_query(
	vm_map_t                map,
	mach_vm_offset_ut       offset_u,
	int                    *disposition,
	int                    *ref_count)
{
	kern_return_t                   kr;
	vm_page_info_basic_data_t       info;
	mach_msg_type_number_t          count;

	if (VM_MAP_NULL == map) {
		return KERN_INVALID_ARGUMENT;
	}

	count = VM_PAGE_INFO_BASIC_COUNT;
	kr = vm_map_page_info(map, offset_u, VM_PAGE_INFO_BASIC,
	    (vm_page_info_t) &info, &count);
	if (kr == KERN_SUCCESS) {
		*disposition = info.disposition;
		*ref_count = info.ref_count;
	} else {
		*disposition = 0;
		*ref_count = 0;
	}

	return kr;
}

kern_return_t
vm_map_page_query(
	vm_map_t                map,
	vm_offset_ut            offset,
	int                    *disposition,
	int                    *ref_count)
{
	return mach_vm_page_query(map, offset, disposition, ref_count);
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
mach_vm_page_range_query_sanitize(
	mach_vm_offset_ut       address_u,
	mach_vm_size_ut         size_u,
	int                     effective_page_mask,
	mach_vm_address_ut      dispositions_addr_u,
	mach_vm_size_ut         dispositions_count_u,
	mach_vm_offset_t       *start,
	mach_vm_size_t         *size,
	mach_vm_address_t      *dispositions_addr,
	mach_vm_size_t         *disp_buf_req_size)
{
	mach_vm_offset_t  end;
	mach_vm_size_t    dispositions_count;
	mach_vm_address_t discard;

	/*
	 * There are no alignment requirements on
	 * dispositions_addr_u/dispositions_count_u, those are derived into
	 * inputs into copyout. So it is safe to unwrap them. We do want to
	 * check that the range starting at dispositions_addr_u and ending
	 * after dispositions_count_u integers is sound (i.e., doesn't wrap
	 * around due to integer overflow).
	 */
	*dispositions_addr = VM_SANITIZE_UNSAFE_UNWRAP(dispositions_addr_u);
	dispositions_count = VM_SANITIZE_UNSAFE_UNWRAP(dispositions_count_u);
	if (
		os_mul_overflow(
			dispositions_count,
			sizeof(int),
			disp_buf_req_size) ||
		os_add_overflow(
			*dispositions_addr,
			*disp_buf_req_size,
			&discard)) {
		return KERN_INVALID_ARGUMENT;
	}

	return vm_sanitize_addr_size(address_u, size_u,
	           VM_SANITIZE_CALLER_VM_MAP_PAGE_RANGE_QUERY,
	           effective_page_mask,
	           VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH, start,
	           &end, size);
}

kern_return_t
mach_vm_page_range_query(
	vm_map_t                map,
	mach_vm_offset_ut       address_u,
	mach_vm_size_ut         size_u,
	mach_vm_address_ut      dispositions_addr_u,
	mach_vm_size_ut        *dispositions_count_u)
{
	kern_return_t           kr;
	int                     num_pages = 0, i = 0;
	mach_vm_size_t          curr_sz = 0, copy_sz = 0;
	mach_vm_size_t          disp_buf_req_size = 0, disp_buf_total_size = 0;
	mach_msg_type_number_t  count = 0;
	mach_vm_address_t       dispositions_addr;

	void                    *info = NULL;
	void                    *local_disp = NULL;
	vm_map_size_t           info_size = 0, local_disp_size = 0;
	mach_vm_offset_t        start = 0;
	vm_map_size_t           size;
	int                     effective_page_shift, effective_page_size, effective_page_mask;

	if (map == VM_MAP_NULL || dispositions_count_u == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	effective_page_shift = vm_self_region_page_shift_safely(map);
	if (effective_page_shift == -1) {
		return KERN_INVALID_ARGUMENT;
	}
	effective_page_size = (1 << effective_page_shift);
	effective_page_mask = effective_page_size - 1;

	kr = mach_vm_page_range_query_sanitize(address_u,
	    size_u,
	    effective_page_mask,
	    dispositions_addr_u,
	    *dispositions_count_u,
	    &start,
	    &size,
	    &dispositions_addr,
	    &disp_buf_req_size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	if (disp_buf_req_size == 0 || size == 0) {
		return KERN_SUCCESS;
	}

	/*
	 * For large requests, we will go through them
	 * MAX_PAGE_RANGE_QUERY chunk at a time.
	 */

	curr_sz = MIN(size, MAX_PAGE_RANGE_QUERY);
	num_pages = (int) (curr_sz >> effective_page_shift);

	info_size = num_pages * sizeof(vm_page_info_basic_data_t);
	info = kalloc_data(info_size, Z_WAITOK);

	local_disp_size = num_pages * sizeof(int);
	local_disp = kalloc_data(local_disp_size, Z_WAITOK);

	if (info == NULL || local_disp == NULL) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	while (size) {
		count = VM_PAGE_INFO_BASIC_COUNT;
		kr = vm_map_page_range_info_internal(
			map,
			start,
			vm_map_round_page(start + curr_sz, effective_page_mask),
			effective_page_shift,
			VM_PAGE_INFO_BASIC,
			(vm_page_info_t) info,
			&count);

		assert(kr == KERN_SUCCESS);

		for (i = 0; i < num_pages; i++) {
			((int*)local_disp)[i] = ((vm_page_info_basic_t)info)[i].disposition;
		}

		copy_sz = MIN(disp_buf_req_size, num_pages * sizeof(int) /* an int per page */);
		kr = copyout(local_disp, (mach_vm_address_t)dispositions_addr, copy_sz);

		start += curr_sz;
		disp_buf_req_size -= copy_sz;
		disp_buf_total_size += copy_sz;

		if (kr != 0) {
			break;
		}

		if ((disp_buf_req_size == 0) || (curr_sz >= size)) {
			/*
			 * We might have inspected the full range OR
			 * more than it esp. if the user passed in
			 * non-page aligned start/size and/or if we
			 * descended into a submap. We are done here.
			 */

			size = 0;
		} else {
			dispositions_addr += copy_sz;

			size -= curr_sz;

			curr_sz = MIN(vm_map_round_page(size, effective_page_mask), MAX_PAGE_RANGE_QUERY);
			num_pages = (int)(curr_sz >> effective_page_shift);
		}
	}

	VM_SANITIZE_UT_SET(
		*dispositions_count_u,
		disp_buf_total_size / sizeof(int));

out:
	kfree_data(local_disp, local_disp_size);
	kfree_data(info, info_size);
	return kr;
}

kern_return_t
mach_vm_page_info(
	vm_map_t                map,
	mach_vm_address_ut      address,
	vm_page_info_flavor_t   flavor,
	vm_page_info_t          info,
	mach_msg_type_number_t  *count)
{
	kern_return_t   kr;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = vm_map_page_info(map, address, flavor, info, count);
	return kr;
}

/*
 *	task_wire
 *
 *	Set or clear the map's wiring_required flag.  This flag, if set,
 *	will cause all future virtual memory allocation to allocate
 *	user wired memory.  Unwiring pages wired down as a result of
 *	this routine is done with the vm_wire interface.
 */
kern_return_t
task_wire(
	vm_map_t        map,
	boolean_t       must_wire __unused)
{
	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_NOT_SUPPORTED;
}

kern_return_t
vm_map_exec_lockdown(
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

#if XNU_PLATFORM_MacOSX
/*
 * Now a kernel-private interface (for BootCache
 * use only).  Need a cleaner way to create an
 * empty vm_map() and return a handle to it.
 */

kern_return_t
vm_region_object_create(
	vm_map_t                target_map,
	vm_size_t               size,
	ipc_port_t              *object_handle)
{
	vm_named_entry_t        user_entry;
	vm_map_t                new_map;

	user_entry = mach_memory_entry_allocate(object_handle);

	/* Create a named object based on a submap of specified size */

	new_map = vm_map_create_options(PMAP_NULL, VM_MAP_MIN_ADDRESS,
	    vm_map_round_page(size, VM_MAP_PAGE_MASK(target_map)),
	    VM_MAP_CREATE_PAGEABLE);
	vm_map_set_page_shift(new_map, VM_MAP_PAGE_SHIFT(target_map));

	user_entry->backing.map = new_map;
	user_entry->internal = TRUE;
	user_entry->is_sub_map = TRUE;
	user_entry->offset = 0;
	user_entry->protection = VM_PROT_ALL;
	user_entry->size = size;

	return KERN_SUCCESS;
}
#endif /* XNU_PLATFORM_MacOSX */

extern boolean_t proc_is_simulated(struct proc *p);

kern_return_t
mach_vm_deferred_reclamation_buffer_allocate(
	task_t           task,
	mach_vm_address_ut *address,
	uint32_t initial_capacity,
	uint32_t max_capacity)
{
#if CONFIG_DEFERRED_RECLAIM
	if (task != current_task()) {
		/* Remote buffer operations are not supported*/
		return KERN_INVALID_TASK;
	}
	struct proc *p = task_get_proc_raw(task);
	if (proc_is_simulated(p)) {
		return KERN_NOT_SUPPORTED;
	}
	return vm_deferred_reclamation_buffer_allocate_internal(task, address, initial_capacity, max_capacity);
#else
	(void) task;
	(void) address;
	(void) size;
	return KERN_NOT_SUPPORTED;
#endif /* CONFIG_DEFERRED_RECLAIM */
}

kern_return_t
mach_vm_deferred_reclamation_buffer_flush(
	task_t task,
	uint32_t num_entries_to_reclaim)
{
#if CONFIG_DEFERRED_RECLAIM
	if (task != current_task()) {
		/* Remote buffer operations are not supported */
		return KERN_INVALID_TASK;
	}
	return vm_deferred_reclamation_buffer_flush_internal(task, num_entries_to_reclaim);
#else
	(void) task;
	(void) num_entries_to_reclaim;
	return KERN_NOT_SUPPORTED;
#endif /* CONFIG_DEFERRED_RECLAIM */
}

kern_return_t
mach_vm_deferred_reclamation_buffer_update_reclaimable_bytes(
	task_t task,
	mach_vm_size_ut reclaimable_bytes_u)
{
#if CONFIG_DEFERRED_RECLAIM
	/*
	 * This unwrapping is safe as reclaimable_bytes is not to be
	 * interpreted as the size of range of addresses.
	 */
	mach_vm_size_t reclaimable_bytes =
	    VM_SANITIZE_UNSAFE_UNWRAP(reclaimable_bytes_u);
	if (task != current_task()) {
		/* Remote buffer operations are not supported */
		return KERN_INVALID_TASK;
	}
	return vm_deferred_reclamation_buffer_update_reclaimable_bytes_internal(task, reclaimable_bytes);
#else
	(void) task;
	(void) reclaimable_bytes;
	return KERN_NOT_SUPPORTED;
#endif /* CONFIG_DEFERRED_RECLAIM */
}

kern_return_t
mach_vm_deferred_reclamation_buffer_resize(task_t task,
    uint32_t capacity)
{
#if CONFIG_DEFERRED_RECLAIM
	if (task != current_task()) {
		/* Remote buffer operations are not supported */
		return KERN_INVALID_TASK;
	}
	return vm_deferred_reclamation_buffer_resize_internal(task, capacity);
#else
	(void) task;
	(void) size;
	return KERN_NOT_SUPPORTED;
#endif /* CONFIG_DEFERRED_RECLAIM */
}

#if CONFIG_MAP_RANGES

extern void qsort(void *a, size_t n, size_t es, int (*cmp)(const void *, const void *));

static int
vm_map_user_range_cmp(const void *e1, const void *e2)
{
	const struct vm_map_user_range *r1 = e1;
	const struct vm_map_user_range *r2 = e2;

	if (r1->vmur_min_address != r2->vmur_min_address) {
		return r1->vmur_min_address < r2->vmur_min_address ? -1 : 1;
	}

	return 0;
}

static int
mach_vm_range_recipe_v1_cmp(const void *e1, const void *e2)
{
	const mach_vm_range_recipe_v1_t *r1 = e1;
	const mach_vm_range_recipe_v1_t *r2 = e2;

	if (r1->range.min_address != r2->range.min_address) {
		return r1->range.min_address < r2->range.min_address ? -1 : 1;
	}

	return 0;
}

static inline __result_use_check kern_return_t
mach_vm_range_create_v1_sanitize(
	vm_map_t                map,
	mach_vm_range_recipe_v1_ut *recipe_u,
	uint32_t count,
	mach_vm_range_recipe_v1_t **recipe_p)
{
	kern_return_t kr;

	for (size_t i = 0; i < count; i++) {
		vm_map_offset_t start, end;
		vm_map_size_t size;
		mach_vm_range_ut * range_u = &recipe_u[i].range_u;
		kr = vm_sanitize_addr_end(
			range_u->min_address_u,
			range_u->max_address_u,
			VM_SANITIZE_CALLER_MACH_VM_RANGE_CREATE,
			map,
			VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS
			| VM_SANITIZE_FLAGS_CHECK_ALIGNED_START
			| VM_SANITIZE_FLAGS_CHECK_ALIGNED_SIZE,
			&start, &end, &size); // Ignore return values
		if (__improbable(kr != KERN_SUCCESS)) {
			return kr;
		}
	}
	/*
	 * Sanitization only checked properties of recipe_u.
	 * We can now see it through the lens of the safe type.
	 * The cast is undefined behavior, but of the kind VM sanitization
	 * relies on anyway, so we don't expect this to cause issues.
	 */
	*recipe_p = (mach_vm_range_recipe_v1_t *)recipe_u;

	return KERN_SUCCESS;
}

/*!
 * @function mach_vm_range_create_v1()
 *
 * @brief
 * Handle the backend for mach_vm_range_create() for the
 * MACH_VM_RANGE_FLAVOR_V1 flavor.
 *
 * @description
 * This call allows to create "ranges" in the map of a task
 * that have special semantics/policies around placement of
 * new allocations (in the vm_map_locate_space() sense).
 *
 * @returns
 * - KERN_SUCCESS on success
 * - KERN_INVALID_ARGUMENT for incorrect arguments
 * - KERN_NO_SPACE if the maximum amount of ranges would be exceeded
 * - KERN_MEMORY_PRESENT if any of the requested ranges
 *   overlaps with existing ranges or allocations in the map.
 */
static kern_return_t
mach_vm_range_create_v1(
	vm_map_t                   map,
	mach_vm_range_recipe_v1_ut *recipe_u,
	uint32_t                   new_count)
{
	mach_vm_range_recipe_v1_t *recipe;
	vm_map_user_range_t table;
	kern_return_t kr = KERN_SUCCESS;
	uint16_t count;

	struct mach_vm_range void1 = {
		.min_address = map->default_range.max_address,
		.max_address = map->data_range.min_address,
	};
	struct mach_vm_range void2 = {
		.min_address = map->data_range.max_address,
#if XNU_TARGET_OS_IOS && EXTENDED_USER_VA_SUPPORT
		.max_address = MACH_VM_JUMBO_ADDRESS,
#else /* !XNU_TARGET_OS_IOS || !EXTENDED_USER_VA_SUPPORT */
		.max_address = vm_map_max(map),
#endif /* XNU_TARGET_OS_IOS && EXTENDED_USER_VA_SUPPORT */
	};

	kr = mach_vm_range_create_v1_sanitize(map, recipe_u, new_count, &recipe);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	qsort(recipe, new_count, sizeof(mach_vm_range_recipe_v1_t),
	    mach_vm_range_recipe_v1_cmp);

	/*
	 * Step 1: Validate that the recipes have no intersections.
	 */

	for (size_t i = 0; i < new_count; i++) {
		mach_vm_range_t r = &recipe[i].range;
		mach_vm_size_t s;

		if (recipe[i].flags) {
			return KERN_INVALID_ARGUMENT;
		}

		static_assert((int)UMEM_RANGE_ID_FIXED == MACH_VM_RANGE_FIXED);
		switch (recipe[i].range_tag) {
		case MACH_VM_RANGE_FIXED:
			break;
		default:
			return KERN_INVALID_ARGUMENT;
		}

		s = mach_vm_range_size(r);
		if (!mach_vm_range_contains(&void1, r->min_address, s) &&
		    !mach_vm_range_contains(&void2, r->min_address, s)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (i > 0 && recipe[i - 1].range.max_address >
		    recipe[i].range.min_address) {
			return KERN_INVALID_ARGUMENT;
		}
	}

	vm_map_lock(map);

	table = map->extra_ranges;
	count = map->extra_ranges_count;

	if (count + new_count > VM_MAP_EXTRA_RANGES_MAX) {
		kr = KERN_NO_SPACE;
		goto out_unlock;
	}

	/*
	 * Step 2: Check that there is no intersection with existing ranges.
	 */

	for (size_t i = 0, j = 0; i < new_count && j < count;) {
		mach_vm_range_t     r1 = &recipe[i].range;
		vm_map_user_range_t r2 = &table[j];

		if (r1->max_address <= r2->vmur_min_address) {
			i++;
		} else if (r2->vmur_max_address <= r1->min_address) {
			j++;
		} else {
			kr = KERN_MEMORY_PRESENT;
			goto out_unlock;
		}
	}

	/*
	 * Step 3: commit the new ranges.
	 */

	static_assert(VM_MAP_EXTRA_RANGES_MAX * sizeof(struct vm_map_user_range) <=
	    KALLOC_SAFE_ALLOC_SIZE);

	table = krealloc_data(table,
	    count * sizeof(struct vm_map_user_range),
	    (count + new_count) * sizeof(struct vm_map_user_range),
	    Z_ZERO | Z_WAITOK | Z_NOFAIL);

	for (size_t i = 0; i < new_count; i++) {
		static_assert(MACH_VM_MAX_ADDRESS < (1ull << 56));

		table[count + i] = (struct vm_map_user_range){
			.vmur_min_address = recipe[i].range.min_address,
			.vmur_max_address = recipe[i].range.max_address,
			.vmur_range_id    = (vm_map_range_id_t)recipe[i].range_tag,
		};
	}

	qsort(table, count + new_count,
	    sizeof(struct vm_map_user_range), vm_map_user_range_cmp);

	map->extra_ranges_count += new_count;
	map->extra_ranges = table;

out_unlock:
	vm_map_unlock(map);

	if (kr == KERN_SUCCESS) {
		for (size_t i = 0; i < new_count; i++) {
			vm_map_kernel_flags_t vmk_flags = {
				.vmf_fixed = true,
				.vmf_overwrite = true,
				.vmkf_overwrite_immutable = true,
				.vm_tag = recipe[i].vm_tag,
			};
			__assert_only kern_return_t kr2;

			kr2 = vm_map_enter(map, &recipe[i].range.min_address,
			    mach_vm_range_size(&recipe[i].range),
			    0, vmk_flags, VM_OBJECT_NULL, 0, FALSE,
			    VM_PROT_NONE, VM_PROT_ALL,
			    VM_INHERIT_DEFAULT);
			assert(kr2 == KERN_SUCCESS);
		}
	}
	return kr;
}

kern_return_t
mach_vm_range_create(
	vm_map_t                map,
	mach_vm_range_flavor_t  flavor,
	mach_vm_range_recipes_raw_t recipe,
	natural_t               size)
{
	if (map != current_map()) {
		return KERN_INVALID_ARGUMENT;
	}

	if (!map->uses_user_ranges) {
		return KERN_NOT_SUPPORTED;
	}

	if (size == 0) {
		return KERN_SUCCESS;
	}

	if (flavor == MACH_VM_RANGE_FLAVOR_V1) {
		mach_vm_range_recipe_v1_ut *array;

		if (size % sizeof(mach_vm_range_recipe_v1_ut)) {
			return KERN_INVALID_ARGUMENT;
		}

		size /= sizeof(mach_vm_range_recipe_v1_ut);
		if (size > VM_MAP_EXTRA_RANGES_MAX) {
			return KERN_NO_SPACE;
		}

		array = (mach_vm_range_recipe_v1_ut *)recipe;
		return mach_vm_range_create_v1(map, array, size);
	}

	return KERN_INVALID_ARGUMENT;
}

#else /* !CONFIG_MAP_RANGES */

kern_return_t
mach_vm_range_create(
	vm_map_t                map,
	mach_vm_range_flavor_t  flavor,
	mach_vm_range_recipes_raw_t recipe,
	natural_t               size)
{
#pragma unused(map, flavor, recipe, size)
	return KERN_NOT_SUPPORTED;
}

#endif /* !CONFIG_MAP_RANGES */

/*
 * These symbols are looked up at runtime by vmware, VirtualBox,
 * despite not being exported in the symbol sets.
 */

#if defined(__x86_64__)

extern typeof(mach_vm_remap_external) mach_vm_remap;
extern typeof(mach_vm_map_external) mach_vm_map;
extern typeof(vm_map_external) vm_map;

kern_return_t
mach_vm_map(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         initial_size,
	mach_vm_offset_ut       mask,
	int                     flags,
	ipc_port_t              port,
	memory_object_offset_ut offset,
	boolean_t               copy,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	vm_inherit_ut           inheritance)
{
	return mach_vm_map_external(target_map, address, initial_size, mask, flags, port,
	           offset, copy, cur_protection, max_protection, inheritance);
}

kern_return_t
mach_vm_remap(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         size,
	mach_vm_offset_ut       mask,
	int                     flags,
	vm_map_t                src_map,
	mach_vm_offset_ut       memory_address,
	boolean_t               copy,
	vm_prot_ut             *cur_protection,   /* OUT */
	vm_prot_ut             *max_protection,   /* OUT */
	vm_inherit_ut           inheritance)
{
	return mach_vm_remap_external(target_map, address, size, mask, flags, src_map, memory_address,
	           copy, cur_protection, max_protection, inheritance);
}

kern_return_t
vm_map(
	vm_map_t                target_map,
	vm_offset_ut           *address,
	vm_size_ut              size,
	vm_offset_ut            mask,
	int                     flags,
	ipc_port_t              port,
	vm_offset_ut            offset,
	boolean_t               copy,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	vm_inherit_ut           inheritance)
{
	return mach_vm_map(target_map, address,
	           size, mask, flags, port, offset, copy,
	           cur_protection, max_protection, inheritance);
}

#endif /* __x86_64__ */
