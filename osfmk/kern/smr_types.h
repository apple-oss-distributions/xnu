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

#ifndef _KERN_SMR_TYPES_H_
#define _KERN_SMR_TYPES_H_

#include <sys/cdefs.h>
#include <stdbool.h>
#include <stdint.h>

__BEGIN_DECLS

/*!
 * @typedef smr_seq_t
 *
 * @brief
 * Represents an opaque SMR sequence number.
 */
typedef unsigned long           smr_seq_t;

/*!
 * @typedef smr_t
 *
 * @brief
 * Type for an SMR domain.
 */
typedef struct smr             *smr_t;


/*!
 * @macro SMR_POINTER_DECL
 *
 * @brief
 * Macro to declare a pointer type that uses SMR for access.
 */
#define SMR_POINTER_DECL(name, type_t) \
	struct name { type_t volatile __smr_ptr; }

/*!
 * @macro SMR_POINTER
 *
 * @brief
 * Macro to declare a pointer that uses SMR for access.
 */
#define SMR_POINTER(type_t) \
	SMR_POINTER_DECL(, type_t)


/* internal types that clients should not use directly */
typedef SMR_POINTER(struct smrq_slink *) __smrq_slink_t;
typedef SMR_POINTER(struct smrq_link *)  __smrq_link_t;


/*!
 * @struct smrq_slink
 *
 * @brief
 * Type used to represent a linkage in an SMR queue
 * (single form, with O(n) deletion).
 */
struct smrq_slink {
	__smrq_slink_t          next;
};

/*!
 * @struct smrq_link
 *
 * @brief
 * Type used to represent a linkage in an SMR queue
 * (double form, with O(1) deletion).
 */
struct smrq_link {
	__smrq_link_t           next;
	__smrq_link_t          *prev;
};


/*!
 * @struct smrq_slist_head
 *
 * @brief
 * Type used to represent the head of a singly linked list.
 *
 * @discussion
 * This must be used with @c smrq_slink linkages.
 *
 * This type supports:
 * - insertion at the head,
 * - O(n) removal / replacement.
 */
struct smrq_slist_head {
	__smrq_slink_t          first;
};

#define SMRQ_SLIST_INITIALIZER(name) \
	{ .first = { NULL } }

/*!
 * @struct smrq_list_head
 *
 * @brief
 * Type used to represent the head of a doubly linked list.
 *
 * @discussion
 * This must be used with @c smrq_link linkages.
 *
 * This type supports:
 * - insertion at the head,
 * - O(1) removal / replacement.
 */
struct smrq_list_head {
	__smrq_link_t           first;
};

#define SMRQ_LIST_INITIALIZER(name) \
	{ .first = { NULL } }

/*!
 * @struct smrq_stailq_head
 *
 * @brief
 * Type used to represent the head of a singly linked tail-queue.
 *
 * @discussion
 * This must be used with @c smrq_slink linkages.
 *
 * This type supports:
 * - insertion at the head,
 * - insertion at the tail,
 * - O(n) removal / replacement.
 */
struct smrq_stailq_head {
	__smrq_slink_t          first;
	__smrq_slink_t         *last;
};

#define SMRQ_STAILQ_INITIALIZER(name) \
	{ .first = { NULL }, .last = &(name).first }

/*!
 * @struct smrq_tailq_head
 *
 * @brief
 * Type used to represent the head of a doubly linked tail-queue.
 *
 * @discussion
 * This must be used with @c smrq_link linkages.
 *
 * This type supports:
 * - insertion at the head,
 * - insertion at the tail,
 * - O(1) removal / replacement.
 */
struct smrq_tailq_head {
	__smrq_link_t           first;
	__smrq_link_t          *last;
};

#define SMRQ_TAILQ_INITIALIZER(name) \
	{ .first = { NULL }, .last = &(name).first }

__END_DECLS

#endif /* _KERN_SMR_TYPES_H_ */
