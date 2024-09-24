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

#ifndef _SYS_COALITION_PRIVATE_H_
#define _SYS_COALITION_PRIVATE_H_

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

#define COALITION_POLICY_ENTITLEMENT "com.apple.private.coalition-policy"

__enum_decl(coalition_policy_flavor_t, uint32_t, {
	COALITION_POLICY_SUPPRESS = 1,
});

__enum_decl(coalition_policy_suppress_t, uint32_t, {
	COALITION_POLICY_SUPPRESS_NONE = 0,
	COALITION_POLICY_SUPPRESS_DARWIN_BG = 1,
});

#ifndef KERNEL
/* Userspace syscall prototypes */
int coalition_policy_set(uint64_t cid, coalition_policy_flavor_t flavor, uint32_t value);
int coalition_policy_get(uint64_t cid, coalition_policy_flavor_t flavor);
#endif /* #ifndef KERNEL */

__END_DECLS

#endif /* _SYS_COALITION_PRIVATE_H_ */
