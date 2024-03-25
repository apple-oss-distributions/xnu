/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * File:	mach/memory_object_control.h
 *
 * Abstract:
 *	Basic Mach external memory management interface declaration.
 */


#ifndef _MACH_MEMORY_OBJECT_CONTROL_
#define _MACH_MEMORY_OBJECT_CONTROL_

/* Module memory_object_control */

#include <string.h>
#include <mach/ndr.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/notify.h>
#include <mach/mach_types.h>
#include <mach/message.h>
#include <mach/mig_errors.h>
#include <mach/port.h>

#include <vm/vm_protos.h>

__BEGIN_DECLS
#pragma GCC visibility push(hidden)

extern kern_return_t memory_object_change_attributes(
	memory_object_control_t memory_control,
	memory_object_flavor_t flavor,
	memory_object_info_t attributes,
	mach_msg_type_number_t attributesCnt);

extern kern_return_t memory_object_lock_request(
	memory_object_control_t memory_control,
	memory_object_offset_t offset,
	memory_object_size_t size,
	memory_object_offset_t *resid_offset,
	integer_t *io_errno,
	memory_object_return_t should_return,
	integer_t flags,
	vm_prot_t lock_value);

extern kern_return_t memory_object_destroy(
	memory_object_control_t                         memory_control,
	vm_object_destroy_reason_t   reason);

extern kern_return_t memory_object_upl_request(
	memory_object_control_t memory_control,
	memory_object_offset_t offset,
	upl_size_t size,
	upl_t *upl,
	upl_page_info_array_t page_list,
	mach_msg_type_number_t *page_listCnt,
	integer_t cntrl_flags,
	integer_t tag);

extern kern_return_t memory_object_cluster_size(
	memory_object_control_t control,
	memory_object_offset_t *start,
	vm_size_t *length,
	uint32_t *io_streaming,
	memory_object_fault_info_t fault_info);

__exported
extern kern_return_t memory_object_page_op(
	memory_object_control_t memory_control,
	memory_object_offset_t offset,
	integer_t ops,
	uint32_t *phys_entry,
	integer_t *flags);

extern kern_return_t memory_object_range_op(
	memory_object_control_t memory_control,
	memory_object_offset_t offset_beg,
	memory_object_offset_t offset_end,
	integer_t ops,
	integer_t *range);

#pragma GCC visibility pop
__END_DECLS

#endif   /* _MACH_MEMORY_OBJECT_CONTROL_ */
