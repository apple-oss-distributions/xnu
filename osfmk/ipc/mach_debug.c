/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1991,1990 Carnegie Mellon University
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
 *	File:	ipc/mach_debug.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Exported IPC debug calls.
 */
#include <mach/vm_param.h>
#include <mach/kern_return.h>
#include <mach/machine/vm_types.h>
#include <mach/mach_host_server.h>
#include <mach/mach_port_server.h>
#include <mach_debug/ipc_info.h>
#include <mach_debug/hash_info.h>

#include <kern/host.h>
#include <kern/misc_protos.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <ipc/port.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_right.h>

#include <security/mac_mach_internal.h>
#include <device/device_types.h>

/*
 *	Routine:	mach_port_get_srights [kernel call]
 *	Purpose:
 *		Retrieve the number of extant send rights
 *		that a receive right has.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Retrieved number of send rights.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote receive rights.
 */

kern_return_t
mach_port_get_srights(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_port_rights_t      *srightsp)
{
	ipc_port_t port;
	kern_return_t kr;
	mach_port_rights_t srights;

	if (space == IS_NULL) {
		return KERN_INVALID_TASK;
	}

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* port is locked and active */

	srights = port->ip_srights;
	ip_mq_unlock(port);

	*srightsp = srights;
	return KERN_SUCCESS;
}


/*
 *	Routine:	mach_port_space_info
 *	Purpose:
 *		Returns information about an IPC space.
 *	Conditions:
 *		Nothing locked.  Obeys CountInOut protocol.
 *	Returns:
 *		KERN_SUCCESS		Returned information.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

static kern_return_t
mach_port_space_info(
	ipc_space_t                     space,
	ipc_info_space_t                *infop,
	ipc_info_name_array_t           *tablep,
	mach_msg_type_number_t          *tableCntp,
	__unused ipc_info_tree_name_array_t     *treep,
	__unused mach_msg_type_number_t         *treeCntp)
{
	const uint32_t BATCH_SIZE = 4 << 10;
	ipc_info_name_t *table_info;
	vm_offset_t table_addr = 0;
	vm_size_t table_size, table_size_needed;
	ipc_entry_table_t table;
	ipc_entry_num_t tsize;
	kern_return_t kr;
	vm_map_copy_t copy;

	if (space == IS_NULL) {
		return KERN_INVALID_TASK;
	}

	/* start with in-line memory */
	table_size = 0;

	is_read_lock(space);

allocate_loop:
	for (;;) {
		if (!is_active(space)) {
			is_read_unlock(space);
			if (table_size != 0) {
				kmem_free(ipc_kernel_map,
				    table_addr, table_size);
			}
			return KERN_INVALID_TASK;
		}

		table = is_active_table(space);
		tsize = ipc_entry_table_count(table);

		table_size_needed =
		    vm_map_round_page(tsize * sizeof(ipc_info_name_t),
		    VM_MAP_PAGE_MASK(ipc_kernel_map));

		if (table_size_needed <= table_size) {
			break;
		}

		is_read_unlock(space);

		if (table_size != 0) {
			kmem_free(ipc_kernel_map, table_addr, table_size);
		}
		kr = kmem_alloc(ipc_kernel_map, &table_addr, table_size_needed,
		    KMA_DATA, VM_KERN_MEMORY_IPC);
		if (kr != KERN_SUCCESS) {
			return KERN_RESOURCE_SHORTAGE;
		}
		table_size = table_size_needed;

		is_read_lock(space);
	}
	/* space is read-locked and active; we have enough wired memory */

	/* walk the table for this space */
	table_info = (ipc_info_name_array_t)table_addr;
	for (mach_port_index_t index = 0; index < tsize; index++) {
		ipc_info_name_t *iin = &table_info[index];
		ipc_entry_t entry = ipc_entry_table_get_nocheck(table, index);
		ipc_entry_bits_t bits;

		if (index == 0) {
			bits = IE_BITS_GEN_MASK;
		} else {
			bits = entry->ie_bits;
		}
		iin->iin_name = MACH_PORT_MAKE(index, IE_BITS_GEN(bits));
		iin->iin_collision = 0;
		iin->iin_type = IE_BITS_TYPE(bits);
		if ((bits & MACH_PORT_TYPE_PORT_RIGHTS) != MACH_PORT_TYPE_NONE &&
		    entry->ie_request != IE_REQ_NONE) {
			ipc_port_t port = ip_object_to_port(entry->ie_object);

			assert(IP_VALID(port));
			ip_mq_lock(port);
			iin->iin_type |= ipc_port_request_type(port, iin->iin_name, entry->ie_request);
			ip_mq_unlock(port);
		}

		iin->iin_urefs = IE_BITS_UREFS(bits);
		iin->iin_object = (natural_t)VM_KERNEL_ADDRPERM((uintptr_t)entry->ie_object);
		iin->iin_next = entry->ie_next;
		iin->iin_hash = entry->ie_index;

		if (index + 1 < tsize && (index + 1) % BATCH_SIZE == 0) {
			/*
			 * Give the system some breathing room,
			 * and check if anything changed,
			 * if yes start over.
			 */
			is_read_unlock(space);
			is_read_lock(space);
			if (!is_active(space)) {
				goto allocate_loop;
			}
			table = is_active_table(space);
			if (tsize < ipc_entry_table_count(table)) {
				goto allocate_loop;
			}
			tsize = ipc_entry_table_count(table);
		}
	}

	/* get the overall space info */
	infop->iis_genno_mask = MACH_PORT_NGEN(MACH_PORT_DEAD);
	infop->iis_table_size = tsize;

	is_read_unlock(space);

	/* prepare the table out-of-line data for return */
	if (table_size > 0) {
		vm_map_size_t used = tsize * sizeof(ipc_info_name_t);
		vm_map_size_t keep = vm_map_round_page(used,
		    VM_MAP_PAGE_MASK(ipc_kernel_map));

		if (keep < table_size) {
			kmem_free(ipc_kernel_map, table_addr + keep,
			    table_size - keep);
			table_size = keep;
		}
		if (table_size > used) {
			bzero(&table_info[infop->iis_table_size],
			    table_size - used);
		}

		kr = vm_map_unwire(ipc_kernel_map, table_addr,
		    table_addr + table_size, FALSE);
		assert(kr == KERN_SUCCESS);
		kr = vm_map_copyin(ipc_kernel_map, table_addr, used, TRUE, &copy);
		assert(kr == KERN_SUCCESS);
		*tablep = (ipc_info_name_t *)copy;
		*tableCntp = infop->iis_table_size;
	} else {
		*tablep = (ipc_info_name_t *)0;
		*tableCntp = 0;
	}

	/* splay tree is obsolete, no work to do... */
	*treep = (ipc_info_tree_name_t *)0;
	*treeCntp = 0;
	return KERN_SUCCESS;
}

kern_return_t
mach_port_space_info_from_user(
	mach_port_t                     port,
	ipc_info_space_t                *infop,
	ipc_info_name_array_t           *tablep,
	mach_msg_type_number_t          *tableCntp,
	__unused ipc_info_tree_name_array_t     *treep,
	__unused mach_msg_type_number_t         *treeCntp)
{
	kern_return_t kr;

	ipc_space_t space = convert_port_to_space_read_no_eval(port);

	if (space == IPC_SPACE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = mach_port_space_info(space, infop, tablep, tableCntp, treep, treeCntp);

	ipc_space_release(space);
	return kr;
}

/*
 *	Routine:	mach_port_space_basic_info
 *	Purpose:
 *		Returns basic information about an IPC space.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Returned information.
 *		KERN_FAILURE		The call is not supported.
 *		KERN_INVALID_TASK	The space is dead.
 */

kern_return_t
mach_port_space_basic_info(
	ipc_space_t                     space,
	ipc_info_space_basic_t          *infop)
{
	ipc_entry_num_t tsize;

	if (space == IS_NULL) {
		return KERN_INVALID_TASK;
	}

	is_read_lock(space);
	if (!is_active(space)) {
		is_read_unlock(space);
		return KERN_INVALID_TASK;
	}

	tsize = ipc_entry_table_count(is_active_table(space));

	/* get the basic space info */
	infop->iisb_genno_mask = MACH_PORT_NGEN(MACH_PORT_DEAD);
	infop->iisb_table_size = tsize;
	infop->iisb_table_inuse = tsize - space->is_table_free - 1;
	infop->iisb_reserved[0] = 0;
	infop->iisb_reserved[1] = 0;

	is_read_unlock(space);

	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_port_dnrequest_info
 *	Purpose:
 *		Returns information about the dead-name requests
 *		registered with the named receive right.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Retrieved information.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote receive rights.
 */

kern_return_t
mach_port_dnrequest_info(
	ipc_space_t                     space,
	mach_port_name_t                name,
	unsigned int                    *totalp,
	unsigned int                    *usedp)
{
	ipc_port_request_table_t requests;
	unsigned int total = 0, used = 0;
	ipc_port_t port;
	kern_return_t kr;

	if (space == IS_NULL) {
		return KERN_INVALID_TASK;
	}

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* port is locked and active */

	requests = port->ip_requests;
	if (requests) {
		ipc_port_request_t ipr = ipc_port_request_table_base(requests);

		while ((ipr = ipc_port_request_table_next_elem(requests, ipr))) {
			if (ipr->ipr_soright != IP_NULL &&
			    ipr->ipr_name != IPR_HOST_NOTIFY) {
				used++;
			}
		}

		total = ipc_port_request_table_count(requests);
	}
	ip_mq_unlock(port);

	*totalp = total;
	*usedp = used;
	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_port_kobject [kernel call]
 *	Purpose:
 *		Retrieve the type and address of the kernel object
 *		represented by a send or receive right. Returns
 *		the kernel address in a mach_vm_address_t to
 *		mask potential differences in kernel address space
 *		size.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Retrieved kernel object info.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote
 *					send or receive rights.
 */

static kern_return_t
mach_port_kobject_description(
	ipc_space_t                     space,
	mach_port_name_t                name,
	natural_t                       *typep,
	mach_vm_address_t               *addrp,
	kobject_description_t           desc)
{
	ipc_entry_bits_t bits;
	ipc_object_t object;
	kern_return_t kr;
	mach_vm_address_t kaddr = 0;
	io_object_t obj = NULL;

	if (space == IS_NULL) {
		return KERN_INVALID_TASK;
	}

	kr = ipc_right_lookup_read(space, name, &bits, &object);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* object is locked and active */

	if ((bits & MACH_PORT_TYPE_SEND_RECEIVE) == 0) {
		io_unlock(object);
		return KERN_INVALID_RIGHT;
	}

	*typep = (unsigned int)io_kotype(object);
	if (io_is_kobject(object)) {
		ipc_port_t port = ip_object_to_port(object);
		kaddr = (mach_vm_address_t)ipc_kobject_get_raw(port, io_kotype(object));
	}
	*addrp = 0;

	if (desc) {
		*desc = '\0';
		switch (io_kotype(object)) {
		case IKOT_IOKIT_OBJECT:
		case IKOT_IOKIT_CONNECT:
		case IKOT_IOKIT_IDENT:
		case IKOT_UEXT_OBJECT:
			obj = (io_object_t) kaddr;
			iokit_add_reference(obj, IKOT_IOKIT_OBJECT);
			break;

		default:
			break;
		}
	}
#if (DEVELOPMENT || DEBUG)
	*addrp = VM_KERNEL_UNSLIDE_OR_PERM(kaddr);
#endif

	io_unlock(object);

	if (obj) {
		iokit_port_object_description(obj, desc);
		iokit_remove_reference(obj);
	}

	return KERN_SUCCESS;
}

kern_return_t
mach_port_kobject_description_from_user(
	mach_port_t                     port,
	mach_port_name_t                name,
	natural_t                       *typep,
	mach_vm_address_t               *addrp,
	kobject_description_t           desc)
{
	kern_return_t kr;

	ipc_space_t space = convert_port_to_space_read_no_eval(port);

	if (space == IPC_SPACE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = mach_port_kobject_description(space, name, typep, addrp, desc);

	ipc_space_release(space);
	return kr;
}

kern_return_t
mach_port_kobject_from_user(
	mach_port_t                     port,
	mach_port_name_t                name,
	natural_t                       *typep,
	mach_vm_address_t               *addrp)
{
	return mach_port_kobject_description_from_user(port, name, typep, addrp, NULL);
}

#if (DEVELOPMENT || DEBUG)
kern_return_t
mach_port_special_reply_port_reset_link(
	ipc_space_t             space,
	mach_port_name_t        name,
	boolean_t               *srp_lost_link)
{
	ipc_port_t port;
	kern_return_t kr;
	thread_t thread = current_thread();

	if (space != current_space()) {
		return KERN_INVALID_TASK;
	}

	if (!MACH_PORT_VALID(name)) {
		return KERN_INVALID_NAME;
	}

	if (!IP_VALID(thread->ith_special_reply_port)) {
		return KERN_INVALID_VALUE;
	}

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	if (thread->ith_special_reply_port != port) {
		ip_mq_unlock(port);
		return KERN_INVALID_ARGUMENT;
	}

	*srp_lost_link = (port->ip_srp_lost_link == 1)? TRUE : FALSE;
	port->ip_srp_lost_link = 0;

	ip_mq_unlock(port);
	return KERN_SUCCESS;
}
#else
kern_return_t
mach_port_special_reply_port_reset_link(
	__unused ipc_space_t            space,
	__unused mach_port_name_t       name,
	__unused boolean_t              *srp_lost_link)
{
	return KERN_NOT_SUPPORTED;
}
#endif
