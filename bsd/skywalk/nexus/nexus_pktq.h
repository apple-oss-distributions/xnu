/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
#ifndef _SKYWALK_NEXUS_PKTQ_H_
#define _SKYWALK_NEXUS_PKTQ_H_

#include <kern/locks.h>
#include <net/classq/classq.h>

#define NX_PKTQ_NO_LIMIT ((uint32_t)-1)

/*
 * These function implement an packet tailq with an optional lock.
 * The base functions act ONLY ON THE QUEUE, whereas the "safe"
 * variants (nx_pktq_safe_*) also handle the lock.
 */

/* A FIFO queue of packets with an optional lock. */
struct nx_pktq {
	decl_lck_mtx_data(, nx_pktq_lock);
	class_queue_t           nx_pktq_q;
	lck_grp_t               *nx_pktq_grp;
	struct __kern_channel_ring *nx_pktq_kring;
};

__attribute__((always_inline))
static inline void
nx_pktq_lock(struct nx_pktq *q)
{
	lck_mtx_lock(&q->nx_pktq_lock);
}

__attribute__((always_inline))
static inline void
nx_pktq_lock_spin(struct nx_pktq *q)
{
	lck_mtx_lock_spin(&q->nx_pktq_lock);
}

__attribute__((always_inline))
static inline void
nx_pktq_convert_spin(struct nx_pktq *q)
{
	lck_mtx_convert_spin(&q->nx_pktq_lock);
}

__attribute__((always_inline))
static inline void
nx_pktq_unlock(struct nx_pktq *q)
{
	lck_mtx_unlock(&q->nx_pktq_lock);
}

__attribute__((always_inline))
static inline struct __kern_packet *
nx_pktq_peek(struct nx_pktq *q)
{
	return qhead(&q->nx_pktq_q);
}

__attribute__((always_inline))
static inline unsigned int
nx_pktq_len(struct nx_pktq *q)
{
	return qlen(&q->nx_pktq_q);
}

__attribute__((always_inline))
static inline size_t
nx_pktq_size(struct nx_pktq *q)
{
	u_int64_t qsize = qsize(&q->nx_pktq_q);
	VERIFY(qsize <= UINT_MAX);
	return (size_t)qsize;
}

__attribute__((always_inline))
static inline unsigned int
nx_pktq_limit(struct nx_pktq *q)
{
	return qlimit(&q->nx_pktq_q);
}

__attribute__((always_inline))
static inline void
__nx_pktq_enq(struct nx_pktq *q, struct __kern_packet *p)
{
	classq_pkt_t pkt;

	CLASSQ_PKT_INIT_PACKET(&pkt, p);
	_addq(&q->nx_pktq_q, &pkt);
}

__attribute__((always_inline))
static inline void
nx_pktq_safe_enq(struct nx_pktq *q, struct __kern_packet *p)
{
	nx_pktq_lock(q);
	__nx_pktq_enq(q, p);
	nx_pktq_unlock(q);
}

__attribute__((always_inline))
static inline void
nx_pktq_enq(struct nx_pktq *q, struct __kern_packet *p)
{
	__nx_pktq_enq(q, p);
}

__attribute__((always_inline))
static inline void
__nx_pktq_enq_multi(struct nx_pktq *q, struct __kern_packet *p_head,
    struct __kern_packet *p_tail,
    uint32_t cnt, uint32_t size)
{
	classq_pkt_t head, tail;

	CLASSQ_PKT_INIT_PACKET(&head, p_head);
	CLASSQ_PKT_INIT_PACKET(&tail, p_tail);
	_addq_multi(&q->nx_pktq_q, &head, &tail, cnt, size);
}

__attribute__((always_inline))
static inline void
nx_pktq_safe_enq_multi(struct nx_pktq *q, struct __kern_packet *p_head,
    struct __kern_packet *p_tail, uint32_t cnt, uint32_t size)
{
	nx_pktq_lock(q);
	__nx_pktq_enq_multi(q, p_head, p_tail, cnt, size);
	nx_pktq_unlock(q);
}

__attribute__((always_inline))
static inline void
nx_pktq_enq_multi(struct nx_pktq *q, struct __kern_packet *p_head,
    struct __kern_packet *p_tail, uint32_t cnt, uint32_t size)
{
	__nx_pktq_enq_multi(q, p_head, p_tail, cnt, size);
}

__attribute__((always_inline))
static inline struct __kern_packet *
__pktq_deq(struct nx_pktq *q)
{
	classq_pkt_t pkt = CLASSQ_PKT_INITIALIZER(pkt);

	_getq(&q->nx_pktq_q, &pkt);
	ASSERT((pkt.cp_kpkt == NULL) || (pkt.cp_ptype == QP_PACKET));
	return pkt.cp_kpkt;
}

__attribute__((always_inline))
static inline struct __kern_packet *
nx_pktq_safe_deq(struct nx_pktq *q)
{
	struct __kern_packet *ret;

	nx_pktq_lock(q);
	ret = __pktq_deq(q);
	nx_pktq_unlock(q);

	return ret;
}

__attribute__((always_inline))
static inline struct __kern_packet *
nx_pktq_deq(struct nx_pktq *q)
{
	return __pktq_deq(q);
}

__attribute__((always_inline))
static inline struct __kern_packet *
__pktq_deq_all(struct nx_pktq *q, struct __kern_packet **plast, uint32_t *qlenp,
    uint64_t *qsizep)
{
	classq_pkt_t first = CLASSQ_PKT_INITIALIZER(first);
	classq_pkt_t last = CLASSQ_PKT_INITIALIZER(last);

	_getq_all(&q->nx_pktq_q, &first, &last, qlenp, qsizep);
	*plast = last.cp_kpkt;
	ASSERT((first.cp_kpkt == NULL) || (first.cp_ptype == QP_PACKET));
	return first.cp_kpkt;
}

__attribute__((always_inline))
static inline struct __kern_packet *
nx_pktq_safe_deq_all(struct nx_pktq *q, struct __kern_packet **last,
    uint32_t *qlenp, uint64_t *qsizep)
{
	struct __kern_packet *ret;

	nx_pktq_lock(q);
	ret = __pktq_deq_all(q, last, qlenp, qsizep);
	nx_pktq_unlock(q);

	return ret;
}

__attribute__((always_inline))
static inline struct __kern_packet *
nx_pktq_deq_all(struct nx_pktq *q, struct __kern_packet **last, uint32_t *qlenp,
    uint64_t *qsizep)
{
	return __pktq_deq_all(q, last, qlenp, qsizep);
}

__BEGIN_DECLS
extern void nx_pktq_init(struct nx_pktq *q, uint32_t lim);
extern void nx_pktq_concat(struct nx_pktq *q1, struct nx_pktq *q2);
extern boolean_t nx_pktq_empty(struct nx_pktq *q);
extern void nx_pktq_destroy(struct nx_pktq *q);
extern void nx_pktq_purge(struct nx_pktq *q);

extern void nx_pktq_safe_init(struct __kern_channel_ring *kr, struct nx_pktq *q,
    uint32_t lim, lck_grp_t *lck_grp, lck_attr_t *lck_attr);
extern void nx_pktq_safe_destroy(struct nx_pktq *q);
extern void nx_pktq_safe_purge(struct nx_pktq *q);
__END_DECLS
#endif /* _SKYWALK_NEXUS_PKTQ_H_ */
