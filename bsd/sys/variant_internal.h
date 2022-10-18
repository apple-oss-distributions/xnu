/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef _SYS_VARIANT_INTERNAL_H_
#define _SYS_VARIANT_INTERNAL_H_

__BEGIN_DECLS

enum os_variant_check_status {
	OS_VARIANT_S_UNKNOWN = 0,
	OS_VARIANT_S_NO = 2,
	OS_VARIANT_S_YES = 3
};

/*
 * Bit allocation in kern.osvariant_status (all ranges inclusive):
 * - [0-27] are 2-bit check_status values
 * - [28-31] are 0xF
 * - [32-32+VP_MAX-1] encode variant_property booleans
 * - [48-51] encode the boot mode, if known
 * - [60-62] are 0x7
 */
#define OS_VARIANT_STATUS_INITIAL_BITS 0x70000000F0000000ULL
#define OS_VARIANT_STATUS_BIT_WIDTH 2
#define OS_VARIANT_STATUS_SET 0x2
#define OS_VARIANT_STATUS_MASK 0x3

enum os_variant_status_flags_positions {
	OS_VARIANT_SFP_INTERNAL_CONTENT = 0,
	OS_VARIANT_SFP_INTERNAL_RELEASE_TYPE = 2,
	OS_VARIANT_SFP_INTERNAL_DIAGS_PROFILE = 3,
};

enum os_variant_property {
	OS_VARIANT_PROPERTY_CONTENT,
	OS_VARIANT_PROPERTY_DIAGNOSTICS
};

__END_DECLS

#ifdef KERNEL_PRIVATE

__BEGIN_DECLS

bool os_variant_has_internal_diagnostics(const char *subsystem);

__END_DECLS
#endif /* KERNEL_PRIVATE */

#endif /* _SYS_VARIANT_INTERNAL_H_ */
