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

/*
 * mblist.h
 */

#ifndef _NET_MBLIST_H
#define _NET_MBLIST_H

#include <sys/kpi_mbuf.h>
#include <stdint.h>

/*
 * Type: mblist
 * Purpose:
 *   Simple type to store head, tail pointers for a list of mbuf packets.
 */
typedef struct {
	mbuf_t          head;
	mbuf_t          tail;
	uint32_t        bytes;
	uint32_t        count;
} mblist, * mblist_t;

static inline void
mblist_init(mblist_t list)
{
	bzero(list, sizeof(*list));
}

static inline void
mblist_append(mblist_t list, mbuf_t m)
{
	if (list->head == NULL) {
		list->head = m;
	} else {
		list->tail->m_nextpkt = m;
	}
	list->tail = m;
	list->count++;
	list->bytes += mbuf_pkthdr_len(m);
}

static inline void
mblist_append_list(mblist_t list, mblist append)
{
	VERIFY(append.head != NULL);
	if (list->head == NULL) {
		*list = append;
	} else {
		VERIFY(list->tail != NULL);
		list->tail->m_nextpkt = append.head;
		list->tail = append.tail;
		list->count += append.count;
		list->bytes += append.bytes;
	}
}

#endif /* _NET_MBLIST_H */
