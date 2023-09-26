/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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
#ifndef _NET_SOCKADDRD_UTILS_H_
#define _NET_SOCKADDRD_UTILS_H_

#ifdef XNU_KERNEL_PRIVATE

#include <sys/mcache.h>
#include <sys/socket.h>

/*
 * Various helper routines for dealing with socket addreses.
 */

/*
 * Copy the contents of the sockadddr `from' into the memory pointed by `to',
 * which has at least `len' bytes.
 */
#define SOCKADDR_COPY_LEN(from, to, len) do {                               \
    caddr_t from_bytes __bidi_indexable = NULL;                             \
    caddr_t to_bytes __bidi_indexable = NULL;                               \
    uint32_t from_len;                                                      \
    VERIFY((to) != NULL && (from) != NULL);                                 \
    VERIFY(offsetof(struct sockaddr, sa_data) <= (len));                    \
    from_len = *((uint8_t*)(void*)(from));                                  \
    VERIFY(from_len <= (len));                                              \
    from_bytes = __unsafe_forge_bidi_indexable(caddr_t, (from), from_len);  \
    to_bytes = __unsafe_forge_bidi_indexable(caddr_t, (to), from_len);      \
    *to_bytes = *from_bytes;                                                \
    *(to_bytes + offsetof(struct sockaddr, sa_family)) =                    \
	*(from_bytes + offsetof(struct sockaddr, sa_family));               \
    if (offsetof(struct sockaddr, sa_data) < from_len) {                    \
	bcopy(from_bytes + offsetof(struct sockaddr, sa_data),              \
	        to_bytes + offsetof(struct sockaddr, sa_data),              \
	        from_len - offsetof(struct sockaddr, sa_data));             \
    }                                                                       \
} while(0)

/*
 * Copy the contents of the sockaddr `from' into the pointee of `to'.
 */
#define SOCKADDR_COPY(from, to) do {                                        \
    VERIFY((to) != NULL && (from) != NULL);                                 \
    SOCKADDR_COPY_LEN(from, to, sizeof(*(to)));                             \
} while(0)

#endif /* XNU_KERNEL_PRIVATE */

#endif /* _NET_SOCKADDRD_UTILS_H_ */
