/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
 *	File:	vm/vm_debug.c.
 *	Author:	Rich Draves
 *	Date:	March, 1990
 *
 *	Exported kernel calls.  See mach_debug/mach_debug.defs.
 */
#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach_debug/vm_info.h>
#include <mach_debug/page_info.h>
#include <mach_debug/hash_info.h>

#define __DEBUG_ONLY __unused

#ifdef VM32_SUPPORT

#include <mach/vm32_map_server.h>
#include <mach/vm_map.h>
#include <vm/vm_map_xnu.h>
#include <vm/vm_lock_perf.h>

/*
 *	Routine:	mach_vm_region_info [kernel call]
 *	Purpose:
 *		Retrieve information about a VM region,
 *		including info about the object chain.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Retrieve region/object info.
 *		KERN_INVALID_TASK	The map is null.
 *		KERN_NO_SPACE		There is no entry at/after the address.
 *		KERN_RESOURCE_SHORTAGE	Can't allocate memory.
 */

kern_return_t
vm32_mach_vm_region_info(
	__DEBUG_ONLY vm_map_t                   map,
	__DEBUG_ONLY vm32_offset_ut             address_u,
	__DEBUG_ONLY vm_info_region_t           *regionp,
	__DEBUG_ONLY vm_info_object_array_t     *objectsp,
	__DEBUG_ONLY mach_msg_type_number_t     *objectsCntp)
{
	vmlp_api_start(VM32_REGION_INFO);

	vmlp_api_end(VM32_REGION_INFO, KERN_FAILURE);
	return KERN_FAILURE;
}

/*
 *  Temporary call for 64 bit data path interface transiotion
 */

kern_return_t
vm32_mach_vm_region_info_64(
	__DEBUG_ONLY vm_map_t                   map,
	__DEBUG_ONLY vm32_offset_ut             address_u,
	__DEBUG_ONLY vm_info_region_64_t        *regionp,
	__DEBUG_ONLY vm_info_object_array_t     *objectsp,
	__DEBUG_ONLY mach_msg_type_number_t     *objectsCntp)
{
	vmlp_api_start(VM32_REGION_INFO_64);

	vmlp_api_end(VM32_REGION_INFO_64, KERN_FAILURE);
	return KERN_FAILURE;
}
/*
 * Return an array of virtual pages that are mapped to a task.
 */
kern_return_t
vm32_vm_mapped_pages_info(
	__DEBUG_ONLY vm_map_t                   map,
	__DEBUG_ONLY page_address_array_t       *pages,
	__DEBUG_ONLY mach_msg_type_number_t     *pages_count)
{
	return KERN_FAILURE;
}

#endif /* VM32_SUPPORT */

/*
 *	Routine:	host_virtual_physical_table_info
 *	Purpose:
 *		Return information about the VP table.
 *	Conditions:
 *		Nothing locked.  Obeys CountInOut protocol.
 *	Returns:
 *		KERN_SUCCESS		Returned information.
 *		KERN_INVALID_HOST	The host is null.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
host_virtual_physical_table_info(
	__DEBUG_ONLY host_t                     host,
	__DEBUG_ONLY hash_info_bucket_array_t   *infop,
	__DEBUG_ONLY mach_msg_type_number_t     *countp)
{
	return KERN_FAILURE;
}
