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
 *      documentation and/or other materials provided with the distribution.
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


#include <stdint.h>
#include <sys/cdefs.h> /* prerequisite */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <skywalk/nexus/nexus_mbq.h>

static void __nx_mbq_init(struct nx_mbq *q, uint32_t, lck_grp_t *lck_grp);

__attribute__((always_inline))
static inline void
__nx_mbq_init(struct nx_mbq *q, uint32_t lim, lck_grp_t *lck_grp)
{
	bzero(q, sizeof(*q));
	_qinit(&q->nx_mbq_q, Q_DROPTAIL, lim, QP_MBUF);
	q->nx_mbq_grp = lck_grp;
}

void
nx_mbq_safe_init(struct __kern_channel_ring *kr, struct nx_mbq *q,
    uint32_t lim, lck_grp_t *lck_grp, lck_attr_t *lck_attr)
{
	q->nx_mbq_kring = kr;
	__nx_mbq_init(q, lim, lck_grp);
	lck_mtx_init(&q->nx_mbq_lock, lck_grp, lck_attr);
}

void
nx_mbq_init(struct nx_mbq *q, uint32_t lim)
{
	__nx_mbq_init(q, lim, NULL);
}

void
nx_mbq_concat(struct nx_mbq *q1, struct nx_mbq *q2)
{
	uint32_t qlen;
	uint64_t qsize;
	classq_pkt_t first = CLASSQ_PKT_INITIALIZER(first);
	classq_pkt_t last = CLASSQ_PKT_INITIALIZER(last);

	/* caller is responsible for locking */
	if (!nx_mbq_empty(q2)) {
		_getq_all(&q2->nx_mbq_q, &first, &last, &qlen, &qsize);
		ASSERT(first.cp_mbuf != NULL && last.cp_mbuf != NULL);
		_addq_multi(&q1->nx_mbq_q, &first, &last, qlen, qsize);
		ASSERT(nx_mbq_empty(q2));
	}
}

boolean_t
nx_mbq_empty(struct nx_mbq *q)
{
	return qempty(&q->nx_mbq_q) && qhead(&q->nx_mbq_q) == NULL;
}

void
nx_mbq_purge(struct nx_mbq *q)
{
	_flushq(&q->nx_mbq_q);
}

void
nx_mbq_safe_purge(struct nx_mbq *q)
{
	nx_mbq_lock(q);
	_flushq(&q->nx_mbq_q);
	nx_mbq_unlock(q);
}

void
nx_mbq_safe_destroy(struct nx_mbq *q)
{
	VERIFY(nx_mbq_empty(q));
	lck_mtx_destroy(&q->nx_mbq_lock, q->nx_mbq_grp);
}

void
nx_mbq_destroy(struct nx_mbq *q)
{
	VERIFY(nx_mbq_empty(q));
}
