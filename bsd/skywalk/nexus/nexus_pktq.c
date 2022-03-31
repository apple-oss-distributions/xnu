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
#include <stdint.h>
#include <sys/cdefs.h> /* prerequisite */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <skywalk/nexus/nexus_pktq.h>

static void __nx_pktq_init(struct nx_pktq *q, uint32_t, lck_grp_t *lck_grp);

__attribute__((always_inline))
static inline void
__nx_pktq_init(struct nx_pktq *q, uint32_t lim, lck_grp_t *lck_grp)
{
	bzero(q, sizeof(*q));
	_qinit(&q->nx_pktq_q, Q_DROPTAIL, lim, QP_PACKET);
	q->nx_pktq_grp = lck_grp;
}

void
nx_pktq_safe_init(struct __kern_channel_ring *kr, struct nx_pktq *q,
    uint32_t lim, lck_grp_t *lck_grp, lck_attr_t *lck_attr)
{
	q->nx_pktq_kring = kr;
	__nx_pktq_init(q, lim, lck_grp);
	lck_mtx_init(&q->nx_pktq_lock, lck_grp, lck_attr);
}

void
nx_pktq_init(struct nx_pktq *q, uint32_t lim)
{
	__nx_pktq_init(q, lim, NULL);
}

void
nx_pktq_concat(struct nx_pktq *q1, struct nx_pktq *q2)
{
	uint32_t qlen;
	uint64_t qsize;
	classq_pkt_t first = CLASSQ_PKT_INITIALIZER(first);
	classq_pkt_t last = CLASSQ_PKT_INITIALIZER(last);

	/* caller is responsible for locking */
	if (!nx_pktq_empty(q2)) {
		_getq_all(&q2->nx_pktq_q, &first, &last, &qlen, &qsize);
		ASSERT(first.cp_kpkt != NULL && last.cp_kpkt != NULL);
		_addq_multi(&q1->nx_pktq_q, &first, &last, qlen, qsize);
		ASSERT(nx_pktq_empty(q2));
	}
}

boolean_t
nx_pktq_empty(struct nx_pktq *q)
{
	return qempty(&q->nx_pktq_q) && qhead(&q->nx_pktq_q) == NULL;
}

void
nx_pktq_purge(struct nx_pktq *q)
{
	_flushq(&q->nx_pktq_q);
}

void
nx_pktq_safe_purge(struct nx_pktq *q)
{
	nx_pktq_lock(q);
	_flushq(&q->nx_pktq_q);
	nx_pktq_unlock(q);
}

void
nx_pktq_safe_destroy(struct nx_pktq *q)
{
	VERIFY(nx_pktq_empty(q));
	lck_mtx_destroy(&q->nx_pktq_lock, q->nx_pktq_grp);
}

void
nx_pktq_destroy(struct nx_pktq *q)
{
	VERIFY(nx_pktq_empty(q));
}
