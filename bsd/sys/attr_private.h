/*
 * Copyright (c) 2000-2018, 2023 Apple Computer, Inc. All rights reserved.
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
 * attr.h - attribute data structures and interfaces
 *
 * Copyright (c) 1998, Apple Computer, Inc.  All Rights Reserved.
 */

#ifndef _SYS_ATTR_PRIVATE_H_
#define _SYS_ATTR_PRIVATE_H_

#include <sys/appleapiopts.h>
#include <sys/attr.h>

#ifdef __APPLE_API_UNSTABLE

#define FSOPT_EXCHANGE_DATA_ONLY 0x0000010

#define FSOPT_LIST_SNAPSHOT     0x00000040
#endif /* __APPLE_API_UNSTABLE */
#define FSOPT_NOFIRMLINKPATH     0x00000080
#ifdef __APPLE_API_UNSTABLE
#define FSOPT_FOLLOW_FIRMLINK    0x00000100
#endif /* __APPLE_API_UNSTABLE */
#define FSOPT_ISREALFSID         FSOPT_RETURN_REALDEV
#ifdef __APPLE_API_UNSTABLE
#define FSOPT_UTIMES_NULL        0x00000400

/* Volume supports kqueue notifications for remote events */
#define VOL_CAP_INT_REMOTE_EVENT                0x00008000

#endif /* __APPLE_API_UNSTABLE */
#endif /* !_SYS_ATTR_PRIVATE_H_ */
