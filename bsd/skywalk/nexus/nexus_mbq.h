/*
 * Copyright (c) 2015-2018 Apple Inc. All rights reserved.
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
 * Copyright (C) 2013-2014 Vincenzo Maffione. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SKYWALK_NEXUS_MBQ_H_
#define _SKYWALK_NEXUS_MBQ_H_

#include <sys/mbuf.h>
#include <kern/locks.h>
#include <net/classq/classq.h>

#define NX_MBQ_NO_LIMIT ((uint32_t)-1)

/*
 * These function implement an mbuf tailq with an optional lock.
 * The base functions act ONLY ON THE QUEUE, whereas the "safe"
 * variants (nx_mbq_safe_*) also handle the lock.
 */

/* A FIFO queue of mbufs with an optional lock. */
struct nx_mbq {
	decl_lck_mtx_data(, nx_mbq_lock);
	class_queue_t           nx_mbq_q;
	lck_grp_t               *nx_mbq_grp;
	struct __kern_channel_ring *nx_mbq_kring;
};

__attribute__((always_inline))
static inline void
nx_mbq_lock(struct nx_mbq *q)
{
	lck_mtx_lock(&q->nx_mbq_lock);
}

__attribute__((always_inline))
static inline void
nx_mbq_lock_spin(struct nx_mbq *q)
{
	lck_mtx_lock_spin(&q->nx_mbq_lock);
}

__attribute__((always_inline))
static inline void
nx_mbq_convert_spin(struct nx_mbq *q)
{
	lck_mtx_convert_spin(&q->nx_mbq_lock);
}

__attribute__((always_inline))
static inline void
nx_mbq_unlock(struct nx_mbq *q)
{
	lck_mtx_unlock(&q->nx_mbq_lock);
}

__attribute__((always_inline))
static inline struct mbuf *
nx_mbq_peek(struct nx_mbq *q)
{
	return qhead(&q->nx_mbq_q);
}

__attribute__((always_inline))
static inline unsigned int
nx_mbq_len(struct nx_mbq *q)
{
	return qlen(&q->nx_mbq_q);
}

__attribute__((always_inline))
static inline size_t
nx_mbq_size(struct nx_mbq *q)
{
	u_int64_t qsize = qsize(&q->nx_mbq_q);
	VERIFY(qsize <= UINT_MAX);
	return (size_t)qsize;
}

__attribute__((always_inline))
static inline unsigned int
nx_mbq_limit(struct nx_mbq *q)
{
	return qlimit(&q->nx_mbq_q);
}

__attribute__((always_inline))
static inline void
__nx_mbq_enq(struct nx_mbq *q, struct mbuf *m)
{
	classq_pkt_t pkt;

	CLASSQ_PKT_INIT_MBUF(&pkt, m);
	_addq(&q->nx_mbq_q, &pkt);
}

__attribute__((always_inline))
static inline void
nx_mbq_safe_enq(struct nx_mbq *q, struct mbuf *m)
{
	nx_mbq_lock(q);
	__nx_mbq_enq(q, m);
	nx_mbq_unlock(q);
}

__attribute__((always_inline))
static inline void
nx_mbq_enq(struct nx_mbq *q, struct mbuf *m)
{
	__nx_mbq_enq(q, m);
}

__attribute__((always_inline))
static inline void
__nx_mbq_enq_multi(struct nx_mbq *q, struct mbuf *m_head, struct mbuf *m_tail,
    uint32_t cnt, uint32_t size)
{
	classq_pkt_t head, tail;

	CLASSQ_PKT_INIT_MBUF(&head, m_head);
	CLASSQ_PKT_INIT_MBUF(&tail, m_tail);
	_addq_multi(&q->nx_mbq_q, &head, &tail, cnt, size);
}

__attribute__((always_inline))
static inline void
nx_mbq_safe_enq_multi(struct nx_mbq *q, struct mbuf *m_head,
    struct mbuf *m_tail, uint32_t cnt, uint32_t size)
{
	nx_mbq_lock(q);
	__nx_mbq_enq_multi(q, m_head, m_tail, cnt, size);
	nx_mbq_unlock(q);
}

__attribute__((always_inline))
static inline void
nx_mbq_enq_multi(struct nx_mbq *q, struct mbuf *m_head, struct mbuf *m_tail,
    uint32_t cnt, uint32_t size)
{
	__nx_mbq_enq_multi(q, m_head, m_tail, cnt, size);
}

__attribute__((always_inline))
static inline struct mbuf *
__mbq_deq(struct nx_mbq *q)
{
	classq_pkt_t pkt = CLASSQ_PKT_INITIALIZER(pkt);

	_getq(&q->nx_mbq_q, &pkt);
	ASSERT((pkt.cp_mbuf == NULL) || (pkt.cp_ptype == QP_MBUF));
	return pkt.cp_mbuf;
}

__attribute__((always_inline))
static inline struct mbuf *
nx_mbq_safe_deq(struct nx_mbq *q)
{
	struct mbuf *ret;

	nx_mbq_lock(q);
	ret = __mbq_deq(q);
	nx_mbq_unlock(q);

	return ret;
}

__attribute__((always_inline))
static inline struct mbuf *
nx_mbq_deq(struct nx_mbq *q)
{
	return __mbq_deq(q);
}

__attribute__((always_inline))
static inline struct mbuf *
__mbq_deq_all(struct nx_mbq *q, struct mbuf **mlast, uint32_t *qlenp,
    uint64_t *qsizep)
{
	classq_pkt_t first = CLASSQ_PKT_INITIALIZER(first);
	classq_pkt_t last = CLASSQ_PKT_INITIALIZER(last);

	_getq_all(&q->nx_mbq_q, &first, &last, qlenp, qsizep);
	*mlast = last.cp_mbuf;
	ASSERT((first.cp_mbuf == NULL) || (first.cp_ptype == QP_MBUF));
	return first.cp_mbuf;
}

__attribute__((always_inline))
static inline struct mbuf *
nx_mbq_safe_deq_all(struct nx_mbq *q, struct mbuf **last, uint32_t *qlenp,
    uint64_t *qsizep)
{
	struct mbuf *ret;

	nx_mbq_lock(q);
	ret = __mbq_deq_all(q, last, qlenp, qsizep);
	nx_mbq_unlock(q);

	return ret;
}

__attribute__((always_inline))
static inline struct mbuf *
nx_mbq_deq_all(struct nx_mbq *q, struct mbuf **last, uint32_t *qlenp,
    uint64_t *qsizep)
{
	return __mbq_deq_all(q, last, qlenp, qsizep);
}

__BEGIN_DECLS
extern void nx_mbq_init(struct nx_mbq *q, uint32_t lim);
extern void nx_mbq_concat(struct nx_mbq *, struct nx_mbq *);
extern boolean_t nx_mbq_empty(struct nx_mbq *);
extern void nx_mbq_destroy(struct nx_mbq *q);
extern void nx_mbq_purge(struct nx_mbq *q);

extern void nx_mbq_safe_init(struct __kern_channel_ring *kr, struct nx_mbq *q,
    uint32_t lim, lck_grp_t *lck_grp, lck_attr_t *lck_attr);
extern void nx_mbq_safe_destroy(struct nx_mbq *q);
extern void nx_mbq_safe_purge(struct nx_mbq *q);
__END_DECLS
#endif /* _SKYWALK_NEXUS_MBQ_H_ */
