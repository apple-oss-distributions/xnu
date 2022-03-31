/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#ifndef _SKYWALK_PACKET_PACKETQUEUE_H_
#define _SKYWALK_PACKET_PACKETQUEUE_H_

#ifdef BSD_KERNEL_PRIVATE

/*
 * Simple __kern_packet queueing system
 * This is basically a SIMPLEQ adapted to skywalk __kern_packet use.
 */
#define KPKTQ_HEAD(name)                                        \
struct name {                                                   \
	struct __kern_packet *kq_first; /* first packet */              \
	struct __kern_packet **kq_last; /* addr of last next packet */  \
	uint32_t kq_len; /* number of packets in queue */       \
}

#define KPKTQ_INIT(q)           do {                            \
	KPKTQ_FIRST(q) = NULL;                                  \
	(q)->kq_last = &KPKTQ_FIRST(q);                         \
	(q)->kq_len = 0;                                        \
} while (0)

#define KPKTQ_FINI(q)           do {                            \
	ASSERT(KPKTQ_EMPTY(q));                                 \
	ASSERT(KPKTQ_LEN(q) == 0);                              \
	KPKTQ_INIT(q);                                          \
} while (0)

#define KPKTQ_DISPOSE(q)        KPKTQ_INIT(q)

#define KPKTQ_CONCAT(q1, q2)    do {                            \
	if (!KPKTQ_EMPTY(q2)) {                                 \
	        *(q1)->kq_last = KPKTQ_FIRST(q2);               \
	        (q1)->kq_last = (q2)->kq_last;                  \
	        (q1)->kq_len += (q2)->kq_len;                   \
	        KPKTQ_DISPOSE((q2));                            \
	}                                                       \
} while (0)

#define KPKTQ_PREPEND(q, p)     do {                            \
	if ((KPKTQ_NEXT(p) = KPKTQ_FIRST(q)) == NULL) {         \
	        ASSERT((q)->kq_len == 0);                       \
	        (q)->kq_last = &KPKTKQ_NEXT(p);                 \
	}                                                       \
	KPKTQ_FIRST(q) = (p);                                   \
	(q)->kq_len++;                                          \
} while (0)

#define KPKTQ_ENQUEUE(q, p)     do {                            \
	ASSERT(KPKTQ_NEXT(p) == NULL);                          \
	*(q)->kq_last = (p);                                    \
	(q)->kq_last = &KPKTQ_NEXT(p);                          \
	(q)->kq_len++;                                          \
} while (0)

#define KPKTQ_ENQUEUE_MULTI(q, p, n, c)    do {                 \
	KPKTQ_NEXT(n) = NULL;                                   \
	*(q)->kq_last = (p);                                    \
	(q)->kq_last = &KPKTQ_NEXT(n);                          \
	(q)->kq_len += c;                                       \
} while (0)

#define KPKTQ_ENQUEUE_LIST(q, p)           do {                 \
	uint32_t _c = 1;                                        \
	struct __kern_packet *_n = (p);                         \
	while (__improbable(KPKTQ_NEXT(_n) != NULL)) {          \
	        _c++;                                           \
	        _n = KPKTQ_NEXT(_n);                            \
	}                                                       \
	KPKTQ_ENQUEUE_MULTI(q, p, _n, _c);                      \
} while (0)

#define KPKTQ_DEQUEUE(q, p)     do {                            \
	if (((p) = KPKTQ_FIRST(q)) != NULL) {                   \
	        (q)->kq_len--;                                  \
	        if ((KPKTQ_FIRST(q) = KPKTQ_NEXT(p)) == NULL) { \
	                ASSERT((q)->kq_len == 0);               \
	                (q)->kq_last = &KPKTQ_FIRST(q);         \
	        } else {                                        \
	                KPKTQ_NEXT(p) = NULL;                   \
	        }                                               \
	}                                                       \
} while (0)

#define KPKTQ_REMOVE(q, p)      do {                            \
	if (KPKTQ_FIRST(q) == (p)) {                            \
	        KPKTQ_DEQUEUE(q, p);                            \
	} else {                                                \
	        struct __kern_packet *_p = KPKTQ_FIRST(q);      \
	        while (KPKTQ_NEXT(_p) != (p))                   \
	                _p = KPKTQ_NEXT(_p);                    \
	        if ((KPKTQ_NEXT(_p) =                           \
	            KPKTQ_NEXT(KPKTQ_NEXT(_p))) == NULL) {      \
	                (q)->kq_last = &KPKTQ_NEXT(_p);         \
	        }                                               \
	        (q)->kq_len--;                                  \
	        KPKTQ_NEXT(p) = NULL;                           \
	}                                                       \
} while (0)

#define KPKTQ_FOREACH(p, q)                                     \
	for ((p) = KPKTQ_FIRST(q);                              \
	    (p);                                                \
	    (p) = KPKTQ_NEXT(p))

#define KPKTQ_FOREACH_SAFE(p, q, tvar)                          \
	for ((p) = KPKTQ_FIRST(q);                              \
	    (p) && ((tvar) = KPKTQ_NEXT(p), 1);                 \
	    (p) = (tvar))

#define KPKTQ_EMPTY(q)          ((q)->kq_first == NULL)
#define KPKTQ_FIRST(q)          ((q)->kq_first)
#define KPKTQ_NEXT(p)           ((p)->pkt_nextpkt)
#define KPKTQ_LEN(q)            ((q)->kq_len)

/*
 * kq_last is initialized to point to kq_first, so check if they're
 * equal and return NULL when the list is empty.  Otherwise, we need
 * to subtract the offset of KPKTQ_NEXT (i.e. pkt_nextpkt field) to get
 * to the base packet address to return to caller.
 */
#define KPKTQ_LAST(head)                                        \
	(((head)->kq_last == &KPKTQ_FIRST(head)) ? NULL :       \
	((struct __kern_packet *)(void *)((char *)(head)->kq_last -     \
	    (size_t)(&KPKTQ_NEXT((struct __kern_packet *)0)))))

/*
 * struct pktq serves as basic common batching data structure using KPKTQ.
 * Elementary types of batch data structure, e.g. packet array, should be named
 * as pkts.
 * For instance:
 * rx_dequeue_pktq(struct pktq *pktq);
 * rx_dequeue_pkts(struct __kern_packet *pkts[], uint32_t n_pkts);
 */
KPKTQ_HEAD(pktq);

#endif /* BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_PACKET_PACKETQUEUE_H_ */
