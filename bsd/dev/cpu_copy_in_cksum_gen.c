/*
 * Copyright (c) 2016-2017 Apple Computer, Inc. All rights reserved.
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
 * This is the reference code for platform-specific implementations
 * of combined copy and 16-bit one's complement sum.
 */

#if !defined(__arm__) && !defined(__arm64__) && !defined(__x86_64__)
#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/conf.h>
#ifndef KERNEL
#include <strings.h>
#ifndef LIBSYSCALL_INTERFACE
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */
#endif /* !KERNEL */

extern uint32_t os_cpu_copy_in_cksum(void *, void *, uint32_t, uint32_t);
extern uint32_t os_cpu_in_cksum(const void *, uint32_t, uint32_t);

uint32_t
os_cpu_copy_in_cksum(void *src, void *dst, uint32_t len, uint32_t sum0)
{
	bcopy(src, dst, len);
	return os_cpu_in_cksum(dst, len, sum0);
}
#endif /* !__arm__ && !__arm64__ && !__x86_64__ */
