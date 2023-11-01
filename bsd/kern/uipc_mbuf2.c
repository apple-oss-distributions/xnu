/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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
/*	$NetBSD: uipc_mbuf.c,v 1.40 1999/04/01 00:23:25 thorpej Exp $	*/

/*
 * Copyright (C) 1999 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1982, 1986, 1988, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)uipc_mbuf.c	8.4 (Berkeley) 2/14/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

/*#define PULLDOWN_DEBUG*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mcache.h>
#include <sys/sysctl.h>

#include <netinet/in.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>

#include <kern/assert.h>

#include <os/log.h>

#include <libkern/OSDebug.h>

#include <ptrauth.h>

#if defined(__i386__) || defined(__x86_64__)
#define MB_TAG_MBUF_DEFAULT 1
#else
#define MB_TAG_MBUF_DEFAULT 0
#endif /* defined(__i386__) || defined(__x86_64__) */

SYSCTL_DECL(_kern_ipc);

unsigned int mb_tag_mbuf = MB_TAG_MBUF_DEFAULT;
SYSCTL_UINT(_kern_ipc, OID_AUTO, mb_tag_mbuf,
    CTLFLAG_RD | CTLFLAG_LOCKED, &mb_tag_mbuf, 0, "");

struct m_tag_type_entry {
	m_tag_kalloc_func_t mt_alloc_func;
	m_tag_kfree_func_t mt_free_func;
	uint16_t mt_type;
	uint16_t mt_len;
};

struct m_tag_type_stats {
	uint64_t mt_alloc_count;
	uint64_t mt_alloc_failed;
	uint64_t mt_free_count;
};

SECURITY_READ_ONLY_LATE(static struct m_tag_type_entry) m_tag_type_table[KERNEL_TAG_TYPE_COUNT] = {};

static struct m_tag_type_stats m_tag_type_stats[KERNEL_TAG_TYPE_COUNT] = {};

static struct m_tag *m_tag_create_mbuf(uint32_t, uint16_t, uint16_t, int, struct mbuf *);

/*
 * ensure that [off, off + len) is contiguous on the mbuf chain "m".
 * packet chain before "off" is kept untouched.
 * if offp == NULL, the target will start at <retval, 0> on resulting chain.
 * if offp != NULL, the target will start at <retval, *offp> on resulting chain.
 *
 * on error return (NULL return value), original "m" will be freed.
 *
 * XXX M_TRAILINGSPACE/M_LEADINGSPACE on shared cluster (sharedcluster)
 */
struct mbuf *
m_pulldown(struct mbuf *m, int off, int len, int *offp)
{
	struct mbuf *n = NULL, *o = NULL;
	int hlen = 0, tlen = 0, olen = 0;
	int sharedcluster = 0;

	/* check invalid arguments. */
	VERIFY(len >= 0 && off >= 0);

	if (m == NULL) {
		panic("m == NULL in m_pulldown()");
	}
	if (len > MCLBYTES) {
		m_freem(m);
		return NULL;    /* impossible */
	}
	int tmp_len = 0;
	if (os_add_overflow(off, len, &tmp_len)) {
		m_free(m);
		return NULL;
	}

#ifdef PULLDOWN_DEBUG
	{
		struct mbuf *t;
		printf("before:");
		for (t = m; t; t = t->m_next) {
			printf(" %d", t->m_len);
		}
		printf("\n");
	}
#endif
	n = m;

	/*
	 * Iterate and make n point to the mbuf
	 * within which the first byte at length
	 * offset is contained from the start of
	 * mbuf chain.
	 */
	while (n != NULL && off > 0) {
		if (n->m_len > off) {
			break;
		}
		off -= n->m_len;
		n = n->m_next;
	}

	/* be sure to point non-empty mbuf */
	while (n != NULL && n->m_len == 0) {
		n = n->m_next;
	}

	if (!n) {
		m_freem(m);
		return NULL;    /* mbuf chain too short */
	}

	/*
	 * the target data is on <n, off>.
	 * if we got enough data on the mbuf "n", we're done.
	 *
	 * It should be noted, that we should only do this either
	 * when offset is 0, i.e. data is pointing to the start
	 * or when the caller specifies an out argument to get
	 * the offset value in the mbuf to work with data pointer
	 * correctly.
	 *
	 * If offset is not 0 and caller did not provide out-argument
	 * to get offset, we should split the mbuf even when the length
	 * is contained in current mbuf.
	 */
	if ((off == 0 || offp) && len <= n->m_len - off) {
		goto ok;
	}

	/*
	 * when len <= n->m_len - off and off != 0, it is a special case.
	 * len bytes from <n, off> sits in single mbuf, but the caller does
	 * not like the starting position (off).
	 * chop the current mbuf into two pieces, set off to 0.
	 */
	if (len <= n->m_len - off) {
		o = m_copym(n, off, n->m_len - off, M_DONTWAIT);
		if (o == NULL) {
			m_freem(m);
			return NULL;    /* ENOBUFS */
		}
		n->m_len = off;
		o->m_next = n->m_next;
		n->m_next = o;
		n = n->m_next;
		off = 0;
		goto ok;
	}

	/*
	 * we need to take hlen from <n, off> and tlen from <n->m_next, 0>,
	 * and construct contiguous mbuf with m_len == len.
	 * note that hlen + tlen == len, and tlen > 0.
	 *
	 * Read these variables as head length and tail length
	 */
	hlen = n->m_len - off;
	tlen = len - hlen;

	/*
	 * ensure that we have enough trailing data on mbuf chain.
	 * if not, we can do nothing about the chain.
	 */
	olen = 0;
	for (o = n->m_next; o != NULL; o = o->m_next) {
		olen += o->m_len;
	}
	if (hlen + olen < len) {
		m_freem(m);
		return NULL;    /* mbuf chain too short */
	}

	/*
	 * easy cases first.
	 * we need to use m_copydata() to get data from <n->m_next, 0>.
	 */
	if ((n->m_flags & M_EXT) == 0) {
		sharedcluster = 0;
	} else {
		if (m_get_ext_free(n) != NULL) {
			sharedcluster = 1;
		} else if (m_mclhasreference(n)) {
			sharedcluster = 1;
		} else {
			sharedcluster = 0;
		}
	}

	/*
	 * If we have enough space left in current mbuf to accomodate
	 * tail length, copy tail length worth of data starting with next mbuf
	 * and adjust the length of next one accordingly.
	 */
	if ((off == 0 || offp) && M_TRAILINGSPACE(n) >= tlen
	    && !sharedcluster) {
		m_copydata(n->m_next, 0, tlen, mtod(n, caddr_t) + n->m_len);
		n->m_len += tlen;
		m_adj(n->m_next, tlen);
		goto ok;
	}

	/*
	 * If have enough leading space in next mbuf to accomodate head length
	 * of current mbuf, and total resulting length of next mbuf is greater
	 * than or equal to requested len bytes, then just copy hlen from
	 * current to the next one and adjust sizes accordingly.
	 */
	if ((off == 0 || offp) && M_LEADINGSPACE(n->m_next) >= hlen &&
	    (n->m_next->m_len + hlen) >= len && !sharedcluster) {
		n->m_next->m_data -= hlen;
		n->m_next->m_len += hlen;
		bcopy(mtod(n, caddr_t) + off, mtod(n->m_next, caddr_t), hlen);
		n->m_len -= hlen;
		n = n->m_next;
		off = 0;
		goto ok;
	}

	/*
	 * now, we need to do the hard way.  don't m_copy as there's no room
	 * on both end.
	 */
	MGET(o, M_DONTWAIT, m->m_type);
	if (o == NULL) {
		m_freem(m);
		return NULL;    /* ENOBUFS */
	}
	if (len > MHLEN) {      /* use MHLEN just for safety */
		MCLGET(o, M_DONTWAIT);
		if ((o->m_flags & M_EXT) == 0) {
			m_freem(m);
			m_free(o);
			return NULL;    /* ENOBUFS */
		}
	}
	/* get hlen from <n, off> into <o, 0> */
	o->m_len = hlen;
	bcopy(mtod(n, caddr_t) + off, mtod(o, caddr_t), hlen);
	n->m_len -= hlen;
	/* get tlen from <n->m_next, 0> into <o, hlen> */
	m_copydata(n->m_next, 0, tlen, mtod(o, caddr_t) + o->m_len);
	o->m_len += tlen;
	m_adj(n->m_next, tlen);
	o->m_next = n->m_next;
	n->m_next = o;
	n = o;
	off = 0;

ok:
#ifdef PULLDOWN_DEBUG
	{
		struct mbuf *t;
		printf("after:");
		for (t = m; t; t = t->m_next) {
			printf("%c%d", t == n ? '*' : ' ', t->m_len);
		}
		printf(" (off=%d)\n", off);
	}
#endif
	if (offp) {
		*offp = off;
	}
	return n;
}

static struct m_tag *
m_tag_kalloc_notsupp(__unused uint32_t id, __unused uint16_t type, __unused uint16_t len, __unused int wait)
{
	return NULL;
}

static void
m_tag_kfree_notsupp(__unused struct m_tag *tag)
{
	return;
}

#if defined(HAS_APPLE_PAC)
/*
 * combine into a uintptr_t the m_tag_type that is 16 bits with the m_tag_id is 32 bits
 */
static uintptr_t
m_tag_cookie_from_id_and_type(struct m_tag *tag)
{
	uintptr_t cookie;

#ifdef __LP64__
	/*
	 * upper 4 bytes: 2 bytes of type
	 * lower 4 bytes: 4 bytes of id
	 */
	cookie = (((uintptr_t)tag->m_tag_type) << 32) | (uintptr_t)tag->m_tag_id;
#else
	/*
	 * upper 2 bytes: 2 bytes of type or-ed with upper 2 bytes of id
	 * lower 2 bytes: lower 2 bytes of id
	 */
	cookie = (((uintptr_t)tag->m_tag_type) << 16) | (uintptr_t)tag->m_tag_id;
#endif
	return cookie;
}

void
m_tag_create_cookie(struct m_tag *tag)
{
	uintptr_t cookie = m_tag_cookie_from_id_and_type(tag);

	tag->m_tag_cookie = (uintptr_t) ptrauth_sign_unauthenticated((void *)cookie,
	    ptrauth_key_process_independent_data,
	    ptrauth_blend_discriminator((void *)(uintptr_t)(tag->m_tag_type | tag->m_tag_id),
	    ptrauth_string_discriminator("m_tag.m_tag_cookie")));
}

static void
m_tag_verify_cookie(struct m_tag *tag)
{
	uintptr_t cookie = m_tag_cookie_from_id_and_type(tag);
	uintptr_t auth_cookie;

	auth_cookie = (uintptr_t) ptrauth_auth_data((void *)(uintptr_t)tag->m_tag_cookie,
	    ptrauth_key_process_independent_data,
	    ptrauth_blend_discriminator((void *)(uintptr_t)(tag->m_tag_type | tag->m_tag_id),
	    ptrauth_string_discriminator("m_tag.m_tag_cookie")));
	if (cookie != auth_cookie) {
		panic("verify_m_tag_cookie bad m_tag cookie");
	}
}

#else /* defined(HAS_APPLE_PAC) */

void
m_tag_create_cookie(struct m_tag *tag)
{
	tag->m_tag_cookie = M_TAG_VALID_PATTERN;
}

static void
m_tag_verify_cookie(struct m_tag *tag)
{
	VERIFY(tag->m_tag_cookie == M_TAG_VALID_PATTERN);
}

#endif /* defined(HAS_APPLE_PAC) */


struct m_tag *
m_tag_create(uint32_t id, uint16_t type, int len, int wait, struct mbuf *buf)
{
	if (mb_tag_mbuf != 0) {
		/*
		 * Create and return an m_tag, either by re-using space in a previous tag
		 * or by allocating a new mbuf/cluster
		 */
		return m_tag_create_mbuf(id, type, (uint16_t)len, wait, buf);
	} else {
		/*
		 * Each packet tag has its own allocation
		 */
		return m_tag_alloc(id, type, (uint16_t)len, wait);
	}
}

/* Get a packet tag structure along with specified data following. */
static struct m_tag *
m_tag_alloc_mbuf(u_int32_t id, u_int16_t type, uint16_t len, int wait)
{
	struct m_tag *t;
	void *mb_cl = NULL;

	if (M_TAG_ALIGN(len) + sizeof(struct m_taghdr) <= MLEN) {
		struct mbuf *m = m_get(wait, MT_TAG);
		struct m_taghdr *hdr;

		if (m == NULL) {
			return NULL;
		}
		mb_cl = m;

		m->m_flags |= M_TAGHDR;

		hdr = (struct m_taghdr *)(void *)m->m_data;
		VERIFY(IS_P2ALIGNED(hdr + 1, sizeof(u_int64_t)));
		hdr->mth_refcnt = 1;
		m->m_len += sizeof(struct m_taghdr);
		t = (struct m_tag *)(void *)(m->m_data + m->m_len);
		VERIFY(IS_P2ALIGNED(t, sizeof(u_int64_t)));
		m->m_len += M_TAG_ALIGN(len);
		VERIFY(m->m_len <= MLEN);
	} else if (len + sizeof(struct m_tag) <= MCLBYTES) {
		mb_cl = m_mclalloc(wait);
		t = (struct m_tag *)(void *)mb_cl;
	} else {
		t = NULL;
	}

	if (__improbable(t == NULL)) {
		return NULL;
	}

	VERIFY(IS_P2ALIGNED(t, sizeof(u_int64_t)));
	M_TAG_INIT(t, id, type, len, (void *)(t + 1), mb_cl);
	if (len > 0) {
		bzero(t->m_tag_data, len);
	}
	return t;
}

static struct m_tag *
m_tag_create_mbuf(uint32_t id, uint16_t type, uint16_t len, int wait, struct mbuf *buf)
{
	struct m_tag *t = NULL;
	struct m_tag *p;
	void *mb_cl = NULL;

	if (len + sizeof(struct m_tag) + sizeof(struct m_taghdr) > MLEN) {
		return m_tag_alloc(id, type, len, wait);
	}

	/*
	 * We've exhausted all external cases. Now, go through the m_tag
	 * chain and see if we can fit it in any of them.
	 * If not (t == NULL), call m_tag_alloc to store it in a new mbuf.
	 */
	p = SLIST_FIRST(&buf->m_pkthdr.tags);
	while (p != NULL) {
		/* 2KCL m_tag */
		if (M_TAG_ALIGN(p->m_tag_len) +
		    sizeof(struct m_taghdr) > MLEN) {
			p = SLIST_NEXT(p, m_tag_link);
			continue;
		}

		m_tag_verify_cookie(p);

		struct mbuf *m = p->m_tag_mb_cl;
		struct m_taghdr *hdr = (struct m_taghdr *)(void *)m->m_data;

		VERIFY(IS_P2ALIGNED(hdr + 1, sizeof(u_int64_t)));
		VERIFY(m->m_flags & M_TAGHDR && !(m->m_flags & M_EXT));

		/* The mbuf can store this m_tag */
		if (M_TAG_ALIGN(len) <= MLEN - m->m_len) {
			mb_cl = m;
			t = (struct m_tag *)(void *)(m->m_data + m->m_len);
			VERIFY(IS_P2ALIGNED(t, sizeof(u_int64_t)));
			hdr->mth_refcnt++;
			m->m_len += M_TAG_ALIGN(len);
			VERIFY(m->m_len <= MLEN);
			break;
		}

		p = SLIST_NEXT(p, m_tag_link);
	}

	if (t == NULL) {
		return m_tag_alloc(id, type, len, wait);
	}

	M_TAG_INIT(t, id, type, len, (void *)(t + 1), mb_cl);
	if (len > 0) {
		bzero(t->m_tag_data, len);
	}
	return t;
}

static void
m_tag_free_mbuf(struct m_tag *t)
{
	if (__improbable(t == NULL)) {
		return;
	}

	if (M_TAG_ALIGN(t->m_tag_len) + sizeof(struct m_taghdr) <= MLEN) {
		struct mbuf * m = t->m_tag_mb_cl;

		VERIFY(m->m_flags & M_TAGHDR);
		struct m_taghdr *hdr = (struct m_taghdr *)(void *)m->m_data;

		VERIFY(IS_P2ALIGNED(hdr + 1, sizeof(u_int64_t)));

		/* No other tags in this mbuf */
		if (--hdr->mth_refcnt == 0) {
			m_free(m);
			return;
		}

		/* Pattern-fill the header */
		u_int64_t *fill_ptr = (u_int64_t *)t;
		u_int64_t *end_ptr = (u_int64_t *)(t + 1);
		while (fill_ptr < end_ptr) {
			*fill_ptr = M_TAG_FREE_PATTERN;
			fill_ptr++;
		}
	} else {
		m_mclfree((caddr_t)t);
	}
}

/*
 * Allocations for external data are known to not have pointers for
 * most platforms -- for macOS this is not guaranteed
 */
#if XNU_TARGET_OS_OSX

__typed_allocators_ignore_push

static inline void *
m_tag_data_kalloc(uint16_t len, int wait)
{
	return kheap_alloc(KHEAP_DEFAULT, len, wait | M_ZERO);
}

static inline void
m_tag_data_free(struct m_tag *tag)
{
	kheap_free(KHEAP_DEFAULT, tag->m_tag_data, tag->m_tag_len);
}
__typed_allocators_ignore_pop

#else /* XNU_TARGET_OS_OSX */

static inline void *
m_tag_data_kalloc(uint16_t len, int wait)
{
	return kalloc_data(len, wait | M_ZERO);
}

static inline void
m_tag_data_free(struct m_tag *tag)
{
	kfree_data(tag->m_tag_data, tag->m_tag_len);
}

#endif /* XNU_TARGET_OS_OSX */

static struct m_tag *
m_tag_kalloc_external(uint32_t id, uint16_t type, uint16_t len, int wait)
{
	struct m_tag *tag;
	void *data = NULL;

	tag = kalloc_type(struct m_tag, wait | M_ZERO);
	if (__improbable(tag == NULL)) {
		return NULL;
	}

	if (len > 0) {
		data = m_tag_data_kalloc(len, wait);
		if (__improbable(data == NULL)) {
			kfree_type(struct m_tag, tag);
			return NULL;
		}
	}

	M_TAG_INIT(tag, id, type, len, data, NULL);

	return tag;
}

static void
m_tag_kfree_external(struct m_tag *tag)
{
	if (tag->m_tag_data != NULL) {
		m_tag_data_free(tag);
	}
	kfree_type(struct m_tag, tag);
}

static struct m_tag_type_entry *
get_m_tag_type_entry(uint32_t id, uint16_t type, struct m_tag_type_stats **pmtts)
{
	struct m_tag_type_entry *mtte = &m_tag_type_table[KERNEL_TAG_TYPE_NONE];

	if (pmtts != NULL) {
		*pmtts = &m_tag_type_stats[KERNEL_TAG_TYPE_NONE];
	}

	if (id == KERNEL_MODULE_TAG_ID) {
		switch (type) {
		case KERNEL_TAG_TYPE_DUMMYNET:
		case KERNEL_TAG_TYPE_IPFILT:
		case KERNEL_TAG_TYPE_ENCAP:
		case KERNEL_TAG_TYPE_INET6:
		case KERNEL_TAG_TYPE_IPSEC:
		case KERNEL_TAG_TYPE_CFIL_UDP:
		case KERNEL_TAG_TYPE_PF_REASS:
		case KERNEL_TAG_TYPE_AQM:
		case KERNEL_TAG_TYPE_DRVAUX:
			mtte = &m_tag_type_table[type];
			if (pmtts != NULL) {
				*pmtts = &m_tag_type_stats[type];
			}
			break;
		default:
#if DEBUG || DEVELOPMENT
			if (type > 0 && type < KERNEL_TAG_TYPE_COUNT) {
				panic("get_m_tag_type_entry unexpected m_tag type %u",
				    type);
			}
#endif /* DEBUG || DEVELOPMENT */
			break;
		}
	}

	return mtte;
}

static struct m_tag *
m_tag_kalloc(uint32_t id, uint16_t type, uint16_t len, int wait, struct m_tag_type_entry *mtte)
{
	struct m_tag *tag = NULL;

	tag = mtte->mt_alloc_func(id, type, len, wait);

	if (__probable(tag != NULL)) {
		VERIFY(IS_P2ALIGNED(tag, sizeof(uint64_t)));

		if (__improbable(tag->m_tag_data == NULL)) {
			VERIFY(len == 0);
		} else {
			VERIFY(len != 0);
			VERIFY(IS_P2ALIGNED(tag->m_tag_data, sizeof(uint64_t)));
		}
	}
	return tag;
}

static void
m_tag_kfree(struct m_tag *tag, struct m_tag_type_entry *mtte)
{
	mtte->mt_free_func(tag);
}

struct m_tag *
m_tag_alloc(uint32_t id, uint16_t type, int len, int wait)
{
	struct m_tag *tag = NULL;
	struct m_tag_type_entry *mtte = NULL;
	struct m_tag_type_stats *mtts = NULL;

	mtte = get_m_tag_type_entry(id, type, &mtts);

	if (__improbable(len < 0 || len >= MCLBYTES - sizeof(struct m_tag))) {
		goto done;
	}

	if (mb_tag_mbuf != 0) {
		tag = m_tag_alloc_mbuf(id, type, (uint16_t)len, wait);
	} else {
		/*
		 * Using Z_NOWAIT could cause retransmission delays when there aren't
		 * many other colocated types in the zone that would prime it. Use
		 * Z_NOPAGEWAIT instead which will only fail to allocate when zalloc
		 * needs to block on the VM for pages.
		 */
		if (wait & Z_NOWAIT) {
			wait &= ~Z_NOWAIT;
			wait |= Z_NOPAGEWAIT;
		}
		tag = m_tag_kalloc(id, type, (uint16_t)len, wait, mtte);
	}
done:
	if (__probable(tag != NULL)) {
		m_tag_verify_cookie(tag);
		assert3u(tag->m_tag_id, ==, id);
		assert3u(tag->m_tag_type, ==, type);
		assert3u(tag->m_tag_len, ==, len);

		os_atomic_inc(&mtts->mt_alloc_count, relaxed);
	} else {
		os_atomic_inc(&mtts->mt_alloc_failed, relaxed);
	}

	return tag;
}

/* Free a packet tag. */
void
m_tag_free(struct m_tag *tag)
{
	struct m_tag_type_entry *mtte = NULL;
	struct m_tag_type_stats *mtts = NULL;

	if (__improbable(tag == NULL)) {
		return;
	}

	m_tag_verify_cookie(tag);

	mtte = get_m_tag_type_entry(tag->m_tag_id, tag->m_tag_type, &mtts);

	if (mb_tag_mbuf != 0) {
		m_tag_free_mbuf(tag);
	} else {
		m_tag_kfree(tag, mtte);
	}

	os_atomic_inc(&mtts->mt_free_count, relaxed);
}

void
mbuf_tag_init(void)
{
	for (uint16_t type = 0; type < KERNEL_TAG_TYPE_COUNT; type++) {
		m_tag_type_table[type].mt_type = type;
		m_tag_type_table[type].mt_len = 0;
		m_tag_type_table[type].mt_alloc_func = m_tag_kalloc_notsupp;
		m_tag_type_table[type].mt_free_func = m_tag_kfree_notsupp;
	}
	m_tag_type_table[KERNEL_TAG_TYPE_NONE].mt_alloc_func = m_tag_kalloc_external;
	m_tag_type_table[KERNEL_TAG_TYPE_NONE].mt_free_func = m_tag_kfree_external;
	m_tag_type_table[KERNEL_TAG_TYPE_DRVAUX].mt_alloc_func = m_tag_kalloc_external;
	m_tag_type_table[KERNEL_TAG_TYPE_DRVAUX].mt_free_func = m_tag_kfree_external;

#if NETWORKING
	extern void pktsched_register_m_tag(void);
	pktsched_register_m_tag();
#endif /* NETWORKING */

#if INET
	extern void ip6_register_m_tag(void);
	ip6_register_m_tag();

	extern void ipfilter_register_m_tag(void);
	ipfilter_register_m_tag();

	extern void encap_register_m_tag(void);
	encap_register_m_tag();
#endif /* INET */

#if IPSEC
	extern void ipsec_register_m_tag(void);
	ipsec_register_m_tag();
#endif /* IPSEC */

#if DUMMYNET
	extern void dummynet_register_m_tag(void);
	dummynet_register_m_tag();
#endif /* DUMMYNET */

#if PF
	extern void pf_register_m_tag(void);
	pf_register_m_tag();
#endif /* PF */

#if CONTENT_FILTER
	extern void cfil_register_m_tag(void);
	cfil_register_m_tag();
#endif /* CONTENT_FILTER */
}

int
m_register_internal_tag_type(uint16_t type, uint16_t len,
    m_tag_kalloc_func_t alloc_func, m_tag_kfree_func_t free_func)
{
	int error = 0;

	if (type <= 0 || type >= KERNEL_TAG_TYPE_DRVAUX) {
		error = EINVAL;
		goto done;
	}
	m_tag_type_table[type].mt_type = type;
	m_tag_type_table[type].mt_len = len;
	m_tag_type_table[type].mt_alloc_func = alloc_func;
	m_tag_type_table[type].mt_free_func = free_func;

done:
	return error;
}

/* Prepend a packet tag. */
void
m_tag_prepend(struct mbuf *m, struct m_tag *t)
{
	VERIFY(m != NULL && t != NULL);

	SLIST_INSERT_HEAD(&m->m_pkthdr.tags, t, m_tag_link);
}

/* Unlink a packet tag. */
void
m_tag_unlink(struct mbuf *m, struct m_tag *t)
{
	VERIFY(m->m_flags & M_PKTHDR);
	VERIFY(t != NULL);

	SLIST_REMOVE(&m->m_pkthdr.tags, t, m_tag, m_tag_link);
}

/* Unlink and free a packet tag. */
void
m_tag_delete(struct mbuf *m, struct m_tag *t)
{
	m_tag_unlink(m, t);
	m_tag_free(t);
}

/* Unlink and free a packet tag chain, starting from given tag. */
void
m_tag_delete_chain(struct mbuf *m)
{
	struct m_tag *p, *q;

	VERIFY(m->m_flags & M_PKTHDR);

	p = SLIST_FIRST(&m->m_pkthdr.tags);
	if (p == NULL) {
		return;
	}

	while ((q = SLIST_NEXT(p, m_tag_link)) != NULL) {
		m_tag_delete(m, q);
	}
	m_tag_delete(m, p);
}

/* Find a tag, starting from a given position. */
struct m_tag *
m_tag_locate(struct mbuf *m, uint32_t id, uint16_t type)
{
	struct m_tag *p;

	VERIFY(m->m_flags & M_PKTHDR);

	p = SLIST_FIRST(&m->m_pkthdr.tags);

	while (p != NULL) {
		if (p->m_tag_id == id && p->m_tag_type == type) {
			m_tag_verify_cookie(p);
			return p;
		}
		p = SLIST_NEXT(p, m_tag_link);
	}
	return NULL;
}

/* Copy a single tag. */
struct m_tag *
m_tag_copy(struct m_tag *t, int how)
{
	struct m_tag *p;

	VERIFY(t != NULL);

	p = m_tag_alloc(t->m_tag_id, t->m_tag_type, t->m_tag_len, how);
	if (p == NULL) {
		return NULL;
	}
	bcopy(t->m_tag_data, p->m_tag_data, t->m_tag_len); /* Copy the data */
	return p;
}

/*
 * Copy two tag chains. The destination mbuf (to) loses any attached
 * tags even if the operation fails. This should not be a problem, as
 * m_tag_copy_chain() is typically called with a newly-allocated
 * destination mbuf.
 */
int
m_tag_copy_chain(struct mbuf *to, struct mbuf *from, int how)
{
	struct m_tag *p, *t, *tprev = NULL;

	VERIFY((to->m_flags & M_PKTHDR) && (from->m_flags & M_PKTHDR));

	m_tag_delete_chain(to);
	SLIST_FOREACH(p, &from->m_pkthdr.tags, m_tag_link) {
		m_tag_verify_cookie(p);
		t = m_tag_copy(p, how);
		if (t == NULL) {
			m_tag_delete_chain(to);
			return 0;
		}
		if (tprev == NULL) {
			SLIST_INSERT_HEAD(&to->m_pkthdr.tags, t, m_tag_link);
		} else {
			SLIST_INSERT_AFTER(tprev, t, m_tag_link);
			tprev = t;
		}
	}
	return 1;
}

/* Initialize dynamic and static tags on an mbuf. */
void
m_tag_init(struct mbuf *m, int all)
{
	VERIFY(m->m_flags & M_PKTHDR);

	SLIST_INIT(&m->m_pkthdr.tags);
	/*
	 * If the caller wants to preserve static mbuf tags
	 * (e.g. m_dup_pkthdr), don't zero them out.
	 */
	if (all) {
		bzero(&m->m_pkthdr.builtin_mtag._net_mtag,
		    sizeof(m->m_pkthdr.builtin_mtag._net_mtag));
	}
}

/* Get first tag in chain. */
struct m_tag *
m_tag_first(struct mbuf *m)
{
	VERIFY(m->m_flags & M_PKTHDR);

	return SLIST_FIRST(&m->m_pkthdr.tags);
}

/* Get next tag in chain. */
struct m_tag *
m_tag_next(struct mbuf *m, struct m_tag *t)
{
#pragma unused(m)
	VERIFY(t != NULL);

	return SLIST_NEXT(t, m_tag_link);
}

int
m_set_traffic_class(struct mbuf *m, mbuf_traffic_class_t tc)
{
	uint32_t val = MBUF_TC2SCVAL(tc);      /* just the val portion */

	return m_set_service_class(m, m_service_class_from_val(val));
}

mbuf_traffic_class_t
m_get_traffic_class(struct mbuf *m)
{
	return MBUF_SC2TC(m_get_service_class(m));
}

int
m_set_service_class(struct mbuf *m, mbuf_svc_class_t sc)
{
	int error = 0;

	VERIFY(m->m_flags & M_PKTHDR);

	if (MBUF_VALID_SC(sc)) {
		m->m_pkthdr.pkt_svc = sc;
	} else {
		error = EINVAL;
	}

	return error;
}

mbuf_svc_class_t
m_get_service_class(struct mbuf *m)
{
	mbuf_svc_class_t sc;

	VERIFY(m->m_flags & M_PKTHDR);

	if (MBUF_VALID_SC(m->m_pkthdr.pkt_svc)) {
		sc = m->m_pkthdr.pkt_svc;
	} else {
		sc = MBUF_SC_BE;
	}

	return sc;
}

mbuf_svc_class_t
m_service_class_from_idx(uint32_t i)
{
	mbuf_svc_class_t sc = MBUF_SC_BE;

	switch (i) {
	case SCIDX_BK_SYS:
		return MBUF_SC_BK_SYS;

	case SCIDX_BK:
		return MBUF_SC_BK;

	case SCIDX_BE:
		return MBUF_SC_BE;

	case SCIDX_RD:
		return MBUF_SC_RD;

	case SCIDX_OAM:
		return MBUF_SC_OAM;

	case SCIDX_AV:
		return MBUF_SC_AV;

	case SCIDX_RV:
		return MBUF_SC_RV;

	case SCIDX_VI:
		return MBUF_SC_VI;

	case SCIDX_VO:
		return MBUF_SC_VO;

	case SCIDX_CTL:
		return MBUF_SC_CTL;

	default:
		break;
	}

	VERIFY(0);
	/* NOTREACHED */
	return sc;
}

mbuf_svc_class_t
m_service_class_from_val(uint32_t v)
{
	mbuf_svc_class_t sc = MBUF_SC_BE;

	switch (v) {
	case SCVAL_BK_SYS:
		return MBUF_SC_BK_SYS;

	case SCVAL_BK:
		return MBUF_SC_BK;

	case SCVAL_BE:
		return MBUF_SC_BE;

	case SCVAL_RD:
		return MBUF_SC_RD;

	case SCVAL_OAM:
		return MBUF_SC_OAM;

	case SCVAL_AV:
		return MBUF_SC_AV;

	case SCVAL_RV:
		return MBUF_SC_RV;

	case SCVAL_VI:
		return MBUF_SC_VI;

	case SCVAL_VO:
		return MBUF_SC_VO;

	case SCVAL_CTL:
		return MBUF_SC_CTL;

	default:
		break;
	}

	VERIFY(0);
	/* NOTREACHED */
	return sc;
}

uint16_t
m_adj_sum16(struct mbuf *m, uint32_t start, uint32_t dataoff,
    uint32_t datalen, uint32_t sum)
{
	uint32_t total_sub = 0;                 /* total to subtract */
	uint32_t mlen = m_pktlen(m);            /* frame length */
	uint32_t bytes = (dataoff + datalen);   /* bytes covered by sum */
	int len;

	ASSERT(bytes <= mlen);

	/*
	 * Take care of excluding (len > 0) or including (len < 0)
	 * extraneous octets at the beginning of the packet, taking
	 * into account the start offset.
	 */
	len = (dataoff - start);
	if (len > 0) {
		total_sub = m_sum16(m, start, len);
	} else if (len < 0) {
		sum += m_sum16(m, dataoff, -len);
	}

	/*
	 * Take care of excluding any postpended extraneous octets.
	 */
	len = (mlen - bytes);
	if (len > 0) {
		struct mbuf *m0 = m;
		uint32_t extra = m_sum16(m, bytes, len);
		uint32_t off = bytes, off0 = off;

		while (off > 0) {
			if (__improbable(m == NULL)) {
				panic("%s: invalid mbuf chain %p [off %u, "
				    "len %u]", __func__, m0, off0, len);
				/* NOTREACHED */
			}
			if (off < m->m_len) {
				break;
			}
			off -= m->m_len;
			m = m->m_next;
		}

		/* if we started on odd-alignment, swap the value */
		if ((uintptr_t)(mtod(m, uint8_t *) + off) & 1) {
			total_sub += ((extra << 8) & 0xffff) | (extra >> 8);
		} else {
			total_sub += extra;
		}

		total_sub = (total_sub >> 16) + (total_sub & 0xffff);
	}

	/*
	 * 1's complement subtract any extraneous octets.
	 */
	if (total_sub != 0) {
		if (total_sub >= sum) {
			sum = ~(total_sub - sum) & 0xffff;
		} else {
			sum -= total_sub;
		}
	}

	/* fold 32-bit to 16-bit */
	sum = (sum >> 16) + (sum & 0xffff);     /* 17-bit */
	sum = (sum >> 16) + (sum & 0xffff);     /* 16-bit + carry */
	sum = (sum >> 16) + (sum & 0xffff);     /* final carry */

	return sum & 0xffff;
}

uint16_t
m_sum16(struct mbuf *m, uint32_t off, uint32_t len)
{
	int mlen;

	/*
	 * Sanity check
	 *
	 * Use m_length2() instead of m_length(), as we cannot rely on
	 * the caller setting m_pkthdr.len correctly, if the mbuf is
	 * a M_PKTHDR one.
	 */
	if ((mlen = m_length2(m, NULL)) < (off + len)) {
		panic("%s: mbuf %p len (%d) < off+len (%d+%d)", __func__,
		    m, mlen, off, len);
		/* NOTREACHED */
	}

	return (uint16_t)os_cpu_in_cksum_mbuf(m, len, off, 0);
}

static int
sysctl_mb_tag_stats(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error = 0;

	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = KERNEL_TAG_TYPE_COUNT * sizeof(struct m_tag_stats);
		return 0;
	}
	if (req->newptr != USER_ADDR_NULL) {
		return EPERM;
	}

	for (uint16_t i = 0; i < KERNEL_TAG_TYPE_COUNT; i++) {
		struct m_tag_stats m_tag_stats = {};

		m_tag_stats.mts_id = KERNEL_MODULE_TAG_ID;
		m_tag_stats.mts_type = i;
		m_tag_stats.mts_len = m_tag_type_table[i].mt_len;
		m_tag_stats.mts_alloc_count = m_tag_type_stats[i].mt_alloc_count;
		m_tag_stats.mts_alloc_failed = m_tag_type_stats[i].mt_alloc_failed;
		m_tag_stats.mts_free_count = m_tag_type_stats[i].mt_free_count;

		error = SYSCTL_OUT(req, &m_tag_stats, sizeof(struct m_tag_stats));
	}

	return error;
}

SYSCTL_PROC(_kern_ipc, OID_AUTO, mb_tag_stats,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, NULL, 0,
    sysctl_mb_tag_stats, "S,m_tag_stats", "");

#if DEBUG || DEVELOPMENT

struct m_tag_test_entry {
	bool            mtte_test_id;
	bool            mtte_alloc_must_fail;
	uint16_t        mtte_type;
	int             mtte_len;
};

struct m_tag_test_entry
    m_tag_test_table[] = {
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = false,
		.mtte_type = KERNEL_TAG_TYPE_DUMMYNET,
		.mtte_len = 0,
	},
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = false,
		.mtte_type = KERNEL_TAG_TYPE_IPFILT,
		.mtte_len = 0,
	},
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = false,
		.mtte_type = KERNEL_TAG_TYPE_ENCAP,
		.mtte_len = 0,
	},
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = false,
		.mtte_type = KERNEL_TAG_TYPE_INET6,
		.mtte_len = 0,
	},
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = false,
		.mtte_type = KERNEL_TAG_TYPE_IPSEC,
		.mtte_len = 0,
	},
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = false,
		.mtte_type = KERNEL_TAG_TYPE_CFIL_UDP,
		.mtte_len = 0,
	},
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = false,
		.mtte_type = KERNEL_TAG_TYPE_PF_REASS,
		.mtte_len = 0,
	},
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = false,
		.mtte_type = KERNEL_TAG_TYPE_AQM,
		.mtte_len = 0,
	},
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = false,
		.mtte_type = KERNEL_TAG_TYPE_DRVAUX,
		.mtte_len = 0,
	},

	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = false,
		.mtte_type = 0,
		.mtte_len = MLEN,
	},
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = false,
		.mtte_type = KERNEL_TAG_TYPE_COUNT,
		.mtte_len = MLEN,
	},
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = true,
		.mtte_type = 0,
		.mtte_len = MCLBYTES,
	},
	{
		.mtte_test_id = false,
		.mtte_alloc_must_fail = true,
		.mtte_type = KERNEL_TAG_TYPE_COUNT,
		.mtte_len = MCLBYTES,
	},

	{
		.mtte_test_id = true,
		.mtte_alloc_must_fail = false,
		.mtte_type = 0,
		.mtte_len = 0,
	},
	{
		.mtte_test_id = true,
		.mtte_alloc_must_fail = false,
		.mtte_type = 0,
		.mtte_len = MLEN,
	},
	{
		.mtte_test_id = true,
		.mtte_alloc_must_fail = true,
		.mtte_type = 0,
		.mtte_len = -1,
	},
	{
		.mtte_test_id = true,
		.mtte_alloc_must_fail = true,
		.mtte_type = 0,
		.mtte_len = MCLBYTES,
	},
};

#define M_TAG_TEST_TABLE_COUNT (sizeof(m_tag_test_table) / sizeof(struct m_tag_test_entry))

#define M_TAG_TEST_ID "com.apple.test.m_tag"

static int
do_m_tag_test(mbuf_tag_id_t test_tag_id)
{
	int error = 0;
	struct mbuf *m = NULL;

	m = m_getpacket();
	if (m == NULL) {
		os_log_error(OS_LOG_DEFAULT, "%s: m_getpacket failed", __func__);
		error = ENOMEM;
		goto done;
	}

	for (int i = 0; i < M_TAG_TEST_TABLE_COUNT; i++) {
		struct m_tag_test_entry *entry = &m_tag_test_table[i];
		struct m_tag *tag = NULL;
		uint32_t id = test_tag_id;
		int len = entry->mtte_len;
		uint16_t type = entry->mtte_type;

		if (entry->mtte_test_id == false) {
			id = KERNEL_MODULE_TAG_ID;
			switch (type) {
			case KERNEL_TAG_TYPE_DUMMYNET:
			case KERNEL_TAG_TYPE_IPFILT:
			case KERNEL_TAG_TYPE_ENCAP:
			case KERNEL_TAG_TYPE_INET6:
			case KERNEL_TAG_TYPE_IPSEC:
			case KERNEL_TAG_TYPE_CFIL_UDP:
			case KERNEL_TAG_TYPE_PF_REASS:
			case KERNEL_TAG_TYPE_AQM:
				/* subsystems that use mbuf tags are optional */
				if (m_tag_type_table[type].mt_alloc_func == m_tag_kalloc_notsupp) {
					continue;
				}
				len = m_tag_type_table[type].mt_len;
				if (entry->mtte_alloc_must_fail == true) {
					os_log_error(OS_LOG_DEFAULT,
					    "%s: FAIL m_tag_create(%u, %u, %u) must not fail",
					    __func__, id, type, len);
					error = EINVAL;
					goto done;
				}
				break;
			default:
				break;
			}
		}
		tag = m_tag_create(id, type, len, M_WAIT, m);
		if (tag == NULL) {
			if (entry->mtte_alloc_must_fail == false) {
				os_log_error(OS_LOG_DEFAULT,
				    "%s: FAIL m_tag_create(%u, %u, %u) unexpected failure",
				    __func__, id, type, len);
				error = ENOMEM;
				goto done;
			} else {
				os_log(OS_LOG_DEFAULT,
				    "%s: PASS m_tag_create(%u, %u, %u) expected failure",
				    __func__, id, type, len);
			}
		} else {
			if (entry->mtte_alloc_must_fail == true) {
				os_log_error(OS_LOG_DEFAULT,
				    "%s: FAIL m_tag_create(%u, %u, %u) unexpected success",
				    __func__, id, type, len);
				error = EINVAL;
				goto done;
			} else {
				os_log(OS_LOG_DEFAULT,
				    "%s: PASS m_tag_create(%u, %u, %u) expected success",
				    __func__, id, type, len);
			}
			m_tag_prepend(m, tag);
		}
	}
done:
	if (m != NULL) {
		m_freem(m);
	}
	os_log_error(OS_LOG_DEFAULT,
	    "%s: %s error %d",
	    __func__, error == 0 ? "PASS" : "FAIL", error);
	return error;
}

static int
do_test_m_tag_unlink(mbuf_tag_id_t test_tag_id)
{
	struct mbuf *m = NULL;
	int error = 0;

	m = m_gethdr(M_WAITOK, MT_DATA);
	if (m == NULL) {
		error = ENOMEM;
		goto done;
	}
	for (int i = 0; i < M_TAG_TEST_TABLE_COUNT; i++) {
		struct m_tag_test_entry *entry = &m_tag_test_table[i];
		struct m_tag *tag = NULL;
		uint32_t id = test_tag_id;
		int len = entry->mtte_len;
		uint16_t type = entry->mtte_type;

		if (entry->mtte_alloc_must_fail == true) {
			continue;
		}

		if (entry->mtte_test_id == false) {
			id = KERNEL_MODULE_TAG_ID;
			switch (type) {
			case KERNEL_TAG_TYPE_DUMMYNET:
			case KERNEL_TAG_TYPE_IPFILT:
			case KERNEL_TAG_TYPE_ENCAP:
			case KERNEL_TAG_TYPE_INET6:
			case KERNEL_TAG_TYPE_IPSEC:
			case KERNEL_TAG_TYPE_CFIL_UDP:
			case KERNEL_TAG_TYPE_PF_REASS:
			case KERNEL_TAG_TYPE_AQM:
				/* subsystems that use mbuf tags are optional */
				if (m_tag_type_table[type].mt_alloc_func == m_tag_kalloc_notsupp) {
					continue;
				}
				len = m_tag_type_table[type].mt_len;
				break;
			default:
				continue;
			}
		}
		tag = m_tag_create(id, type, len, M_WAIT, m);
		if (tag == NULL) {
			os_log_error(OS_LOG_DEFAULT,
			    "%s: FAIL m_tag_create(%u, %u, %u) failure",
			    __func__, id, type, len);
			error = ENOMEM;
			goto done;
		} else {
			os_log_error(OS_LOG_DEFAULT,
			    "%s: PASS m_tag_create(%u, %u, %u) success",
			    __func__, id, type, len);
			m_tag_prepend(m, tag);
		}
	}

	struct m_tag *cfil_tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_CFIL_UDP);
	if (cfil_tag == NULL) {
		os_log_error(OS_LOG_DEFAULT,
		    "%s: FAIL m_tag_locate(KERNEL_TAG_TYPE_CFIL_UDP) failure",
		    __func__);
		error = EINVAL;
		goto done;
	} else {
		os_log_error(OS_LOG_DEFAULT,
		    "%s: PASS m_tag_locate(KERNEL_TAG_TYPE_CFIL_UDP) success",
		    __func__);
	}

	/*
	 * Unlink the mbuf tag, free the mbuf and finally free the mbuf tag
	 */
	m_tag_unlink(m, cfil_tag);

	m_freem(m);
	m = NULL;

	m_tag_free(cfil_tag);

done:
	if (m != NULL) {
		m_freem(m);
	}
	os_log_error(OS_LOG_DEFAULT,
	    "%s: %s error %d",
	    __func__, error == 0 ? "PASS" : "FAIL", error);
	return error;
}

static int
sysctl_mb_tag_test(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error;
	int newvalue;
	int changed;
	int value = 0;
	mbuf_tag_id_t test_tag_id;

	if ((error = sysctl_io_number(req, value, sizeof(int),
	    &newvalue, &changed)) != 0) {
		goto done;
	}
	if (!changed && newvalue == value) {
		goto done;
	}
	error = mbuf_tag_id_find(M_TAG_TEST_ID, &test_tag_id);
	if (error != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s: mbuf_tag_id_find failed error %d",
		    __func__, error);
		goto done;
	}
	error = do_m_tag_test(test_tag_id);
	if (error != 0) {
		goto done;
	}
	error = do_test_m_tag_unlink(test_tag_id);
	if (error != 0) {
		goto done;
	}
done:
	return error;
}

SYSCTL_PROC(_kern_ipc, OID_AUTO, mb_tag_test,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, NULL, 0,
    sysctl_mb_tag_test, "I", "mbuf test");

#endif /* DEBUG || DEVELOPMENT */
