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

#ifndef _KERN_LOCK_ATTR_H_
#define _KERN_LOCK_ATTR_H_

#include <kern/lock_types.h>

__BEGIN_DECLS

#ifdef  XNU_KERNEL_PRIVATE
typedef struct _lck_attr_ {
	unsigned int    lck_attr_val;
} lck_attr_t;

extern lck_attr_t       lck_attr_default;

#define LCK_ATTR_NONE                   0
#define LCK_ATTR_DEBUG                  0x00000001
#define LCK_ATTR_RW_SHARED_PRIORITY     0x00010000
#else /* !XNU_KERNEL_PRIVATE */
typedef struct __lck_attr__ lck_attr_t;
#endif /* !XNU_KERNEL_PRIVATE */

#define LCK_ATTR_NULL ((lck_attr_t *)NULL)

extern  lck_attr_t      *lck_attr_alloc_init(void);

extern  void            lck_attr_setdefault(
	lck_attr_t              *attr);

extern  void            lck_attr_setdebug(
	lck_attr_t              *attr);

extern  void            lck_attr_cleardebug(
	lck_attr_t              *attr);

extern  void            lck_attr_free(
	lck_attr_t              *attr);

#ifdef  XNU_KERNEL_PRIVATE
/*!
 * @function lck_attr_rw_shared_priority
 *
 * @abstract
 * Changes the rw lock behaviour by setting reader priority over writer.
 *
 * @discussion
 * The attribute needs to be set before calling lck_rw_init().
 * This attribute changes the locking behaviour by possibly starving the writers.
 * Readers will always be able to lock the lock as long as a writer is not holding it.
 * This attribute was added to allow recursive locking in shared mode.
 *
 * @param attr	attr to modify
 */
extern  void            lck_attr_rw_shared_priority(
	lck_attr_t              *attr);
#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_LOCK_ATTR_H_ */
