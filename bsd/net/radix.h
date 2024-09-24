/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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
 * Copyright (c) 1988, 1989, 1993
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
 *	@(#)radix.h	8.2 (Berkeley) 10/31/94
 * $FreeBSD: src/sys/net/radix.h,v 1.16.2.1 2000/05/03 19:17:11 wollman Exp $
 */

#ifndef _RADIX_H_
#define _RADIX_H_

#include <sys/appleapiopts.h>
#include <sys/cdefs.h>
#include <sys/socket.h>
#include <stdint.h>

#if KERNEL_PRIVATE
#include <kern/kalloc.h>
#endif /* KERNEL_PRIVATE */

#ifdef PRIVATE

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_RTABLE);
#endif


#define __RN_INLINE_LENGTHS (__BIGGEST_ALIGNMENT__ > 4)

/*
 * Radix search tree node layout.
 */

struct radix_node {
	struct  radix_mask *rn_mklist;  /* list of masks contained in subtree */
	struct  radix_node *rn_parent;  /* parent */
	short   rn_bit;                 /* bit offset; -1-index(netmask) */
	char    rn_bmask;               /* node: mask for bit test*/
	u_char  rn_flags;               /* enumerated next */
#define RNF_NORMAL      1               /* leaf contains normal route */
#define RNF_ROOT        2               /* leaf is root leaf for tree */
#define RNF_ACTIVE      4               /* This node is alive (for rtfree) */
#if __RN_INLINE_LENGTHS
	u_char  __rn_keylen;
	u_char  __rn_masklen;
	short   pad2;
#endif /* __RN_INLINE_LENGTHS */
	union {
		struct {                        /* leaf only data: */
			caddr_t rn_Key;         /* object of search */
			caddr_t rn_Mask;        /* netmask, if present */
			struct  radix_node *rn_Dupedkey;
		} rn_leaf;
		struct {                        /* node only data: */
			int     rn_Off;         /* where to start compare */
			struct  radix_node *rn_L;/* progeny */
			struct  radix_node *rn_R;/* progeny */
		} rn_node;
	}               rn_u;
#ifdef RN_DEBUG
	int rn_info;
	struct radix_node *rn_twin;
	struct radix_node *rn_ybro;
#endif

#if __arm__ && (__BIGGEST_ALIGNMENT__ > 4)
/* For the newer ARMv7k ABI where 64-bit types are 64-bit aligned, but pointers
 * are 32-bit:
 * Aligned to 64-bit since this is cast to rtentry, which is 64-bit aligned.
 */
} __attribute__ ((aligned(8)));
#else
};
#endif

#define rn_dupedkey     rn_u.rn_leaf.rn_Dupedkey
#define rn_offset       rn_u.rn_node.rn_Off
#define rn_left         rn_u.rn_node.rn_L
#define rn_right        rn_u.rn_node.rn_R

/*
 * The `__rn_key' and `__rn_mask' fields are considered
 * private in the BSD codebase, and should not be accessed directly.
 * Outside of the BSD codebase these fields are exposed for the
 * backwards compatibility.
 */
#define __rn_key          rn_u.rn_leaf.rn_Key
#define __rn_mask         rn_u.rn_leaf.rn_Mask

#if !defined(BSD_KERNEL_PRIVATE)
#define rn_key __rn_key
#define rn_mask __rn_mask
#endif /* !defined(BSD_KERNEL_PRIVATE) */

typedef struct radix_node * __single radix_node_ref_t;

#define rn_is_leaf(r) ((r)->rn_bit < 0)


/*
 * Sets the routing key bytes and length.
 */
static inline void
__attribute__((always_inline))
rn_set_key(struct radix_node *rn, void *key __sized_by(keylen), uint8_t keylen)
{
#if __RN_INLINE_LENGTHS
	rn->__rn_keylen = keylen;
#else /* !__RN_INLINE_LENGTHS */
	(void)keylen;
#endif /* !__RN_INLINE_LENGTHS */
	rn->__rn_key = key;
}

/*
 * Returns the routing key length.
 */
static inline uint8_t
__attribute__((always_inline)) __stateful_pure
rn_get_keylen(struct radix_node *rn)
{
#if __RN_INLINE_LENGTHS
	return rn->__rn_keylen;
#else /* !__RN_INLINE_LENGTHS */
	if (rn->__rn_key != NULL) {
		return *((uint8_t *)rn->__rn_key);
	} else {
		return 0;
	}
#endif /* !__RN_INLINE_LENGTHS */
}

/*
 * Returns the pointer to the routing key associated with
 * the radix tree node.
 * If the `-fbounds-safety' feature is both available and enabled,
 * the returned value is sized by the corresponding key len.
 * Otherwise, the returned value is a plain C pointer.
 */
static inline char * __header_indexable
__attribute__((always_inline)) __stateful_pure
rn_get_key(struct radix_node *rn)
{
	return __unsafe_forge_bidi_indexable(char *, rn->rn_u.rn_leaf.rn_Key,
	           rn_get_keylen(rn));
}

/*
 * Sets the routing mask bytes and length.
 */
static inline void
__attribute__((always_inline))
rn_set_mask(struct radix_node *rn, void *mask __sized_by(masklen), uint8_t masklen)
{
#if __RN_INLINE_LENGTHS
	/*
	 * Unlike the keys, the masks are always sockaddrs.
	 * The first byte is the length of the addressable bytes,
	 * whereas the second is the address family.
	 *
	 * To avoid memory traps, we are taking into the consideration
	 * both the addressable length and the address family.
	 */
	uint8_t sa_len = *((uint8_t*)mask);
	uint8_t sa_family = *(((uint8_t*)mask) + 1);
	uint8_t allocation_size =
	    (sa_family == AF_INET)    ? 16     /* sizeof(struct sockaddr_in) */
	    : (sa_family == AF_INET6) ? 28     /* sizeof(struct sockaddr_in6) */
	    : masklen;
	/* Set the allocation size to be the max(sa_len, masklen, allocation_size) */
	allocation_size = allocation_size < sa_len ? sa_len : allocation_size;
	allocation_size = allocation_size < masklen ? masklen : allocation_size;
	rn->__rn_masklen = allocation_size;
#else /* !__RN_INLINE_LENGTHS */
	(void)masklen;
#endif /* !__RN_INLINE_LENGTHS */
	rn->__rn_mask = mask;
}

/*
 * Returns the routing mask length.
 */
static inline uint8_t
__attribute__((always_inline)) __stateful_pure
rn_get_masklen(struct radix_node *rn)
{
#if __RN_INLINE_LENGTHS
	return rn->__rn_masklen;
#else /* !__RN_INLINE_LENGTHS */
	if (rn->__rn_mask != NULL) {
		return *((uint8_t *)rn->__rn_mask);
	} else {
		return 0;
	}
#endif /* !__RN_INLINE_LENGTHS */
}

/*
 * Returns the pointer to the routing mask associated with
 * the radix tree node.
 * If the `-fbounds-safety' feature is both available and enabled,
 * the returned value is sized by the corresponding mask len.
 * Otherwise, the returned value is a plain C pointer.
 */
static inline char * __header_indexable
__attribute__((always_inline)) __stateful_pure
rn_get_mask(struct radix_node *rn)
{
	return __unsafe_forge_bidi_indexable(char *, rn->rn_u.rn_leaf.rn_Mask,
	           rn_get_masklen(rn));
}

/*
 * Annotations to tree concerning potential routes applying to subtrees.
 */
struct radix_mask {
	short   rm_bit;                 /* bit offset; -1-index(netmask) */
	char    rm_unused;              /* cf. rn_bmask */
	u_char  rm_flags;               /* cf. rn_flags */
#if __RN_INLINE_LENGTHS
	u_char  __rm_masklen;
	u_char  pad[3];
#endif /* __RN_INNLINE_LENGTHS */
	struct  radix_mask *rm_mklist;  /* more masks to try */
	union   {
		caddr_t __rm_mask;              /* the mask, see note below. */
		struct  radix_node *rm_leaf;    /* for normal routes */
	};
	int     rm_refs;                /* # of references to this struct */
};

typedef struct radix_mask * __single radix_mask_ref_t;

/*
 * The `__rm_mask' field is considered private in the BSD
 * codebase, and should not be accessed directly.
 * Outside of the BSD codebase it is exposed for the
 * backwards compatibility.
 */
#if !defined(BSD_KERNEL_PRIVATE)
#define rm_mask __rm_mask
#endif /* !defined(BSD_KERNEL_PRIVATE) */

static inline void
rm_set_mask(struct radix_mask *rm, void *mask __sized_by(masklen), uint8_t masklen)
{
#if __RN_INLINE_LENGTHS
	rm->__rm_masklen = masklen;
#else /* !__RN_INLINE_LENGTHS */
	(void)masklen;
#endif /* !__RN_INLINE_LENGTHS */
	rm->__rm_mask = mask;
}


/*
 * Returns the routing mask length.
 */
static inline uint8_t
__attribute__((always_inline)) __stateful_pure
rm_get_masklen(struct radix_mask *rm)
{
#if __RN_INLINE_LENGTHS
	return rm->__rm_masklen;
#else /* !__RN_INLINE_LENGTHS */
	if (rn->__rn_mask != NULL) {
		return *((uint8_t *)rm->__rm_mask);
	} else {
		return 0;
	}
#endif /* !__RN_INLINE_LENGTHS */
}

/*
 * Returns the pointer to the routing mask associated with
 * the radix tree mask node.
 * If the `-fbounds-safety' feature is both available and enabled,
 * the returned value is sized by the corresponding mask len.
 * Otherwise, the returned value is a plain C pointer.
 */
static inline char * __header_indexable
__attribute__((always_inline)) __stateful_pure
rm_get_mask(struct radix_mask *rm)
{
	return __unsafe_forge_bidi_indexable(char *, rm->__rm_mask,
	           rm_get_masklen(rm));
}

#define MKGet(m) {\
	if (rn_mkfreelist) {\
	        m = rn_mkfreelist; \
	        rn_mkfreelist = (m)->rm_mklist; \
	} else { \
	        m = kalloc_type(struct radix_mask, Z_WAITOK_ZERO_NOFAIL); \
	} \
}

#define MKFree(m) { (m)->rm_mklist = rn_mkfreelist; rn_mkfreelist = (m);}

typedef int walktree_f_t(struct radix_node *, void *);
typedef int rn_matchf_t(struct radix_node *, void *);

#if KERNEL_PRIVATE
KALLOC_TYPE_DECLARE(radix_node_head_zone);
#endif

struct radix_node_head {
	struct  radix_node *rnh_treetop;
	int     rnh_addrsize;           /* permit, but not require fixed keys */
	int     rnh_pktsize;            /* permit, but not require fixed keys */
	struct  radix_node *(*rnh_addaddr)      /* add based on sockaddr */
	(void *v, void *mask,
	    struct radix_node_head *head, struct radix_node nodes[]);
	struct  radix_node *(*rnh_addpkt)       /* add based on packet hdr */
	(void *v, void *mask,
	    struct radix_node_head *head, struct radix_node nodes[]);
	struct  radix_node *(*rnh_deladdr)      /* remove based on sockaddr */
	(void *v, void *mask, struct radix_node_head *head);
	struct  radix_node *(*rnh_delpkt)       /* remove based on packet hdr */
	(void *v, void *mask, struct radix_node_head *head);
	struct  radix_node *(*rnh_matchaddr)    /* locate based on sockaddr */
	(void *v, struct radix_node_head *head);
	/* locate based on sockaddr and rn_matchf_t() */
	struct  radix_node *(*rnh_matchaddr_args)
	(void *v, struct radix_node_head *head,
	    rn_matchf_t *f, void *w);
	struct  radix_node *(*rnh_lookup)       /* locate based on sockaddr */
	(void *v, void *mask, struct radix_node_head *head);
	/* locate based on sockaddr, mask and rn_matchf_t() */
	struct  radix_node *(*rnh_lookup_args)
	(void *v, void *mask, struct radix_node_head *head,
	    rn_matchf_t *f, void *);
	struct  radix_node *(*rnh_matchpkt)     /* locate based on packet hdr */
	(void *v, struct radix_node_head *head);
	int     (*rnh_walktree)                 /* traverse tree */
	(struct radix_node_head *head, walktree_f_t *f, void *w);
	int     (*rnh_walktree_from)            /* traverse tree below a */
	(struct radix_node_head *head, void *a, void *m,
	walktree_f_t *f, void *w);
	void    (*rnh_close)    /* do something when the last ref drops */
	(struct radix_node *rn, struct radix_node_head *head);
	struct  radix_node rnh_nodes[3];        /* empty tree for common case */
	int     rnh_cnt;                        /* tree dimension */
};

typedef struct radix_node_head * __single radix_node_head_ref_t;

#ifndef KERNEL
#define Bcmp(a, b, n) bcmp(((char *)(a)), ((char *)(b)), (n))
#define Bcopy(a, b, n) bcopy(((char *)(a)), ((char *)(b)), (unsigned)(n))
#define Bzero(p, n) bzero((char *)(p), (int)(n));
#else
#define Bcmp(a, b, n) bcmp(((caddr_t)(a)), ((caddr_t)(b)), (unsigned)(n))
#define Bcopy(a, b, n) bcopy(((caddr_t)(a)), ((caddr_t)(b)), (unsigned)(n))
#define Bzero(p, n) bzero((caddr_t)(p), (unsigned)(n));
#endif /*KERNEL*/

void     rn_init(void);
int      rn_inithead(void **, int);
int      rn_refines(void *, void *);
struct radix_node *rn_addmask(void *, int, int);
struct radix_node *rn_addroute(void *, void *, struct radix_node_head *,
    struct radix_node [2]);
struct radix_node *rn_delete(void *, void *, struct radix_node_head *);
struct radix_node *rn_lookup(void *v_arg, void *m_arg, struct radix_node_head *head);
struct radix_node *rn_lookup_args(void *v_arg, void *m_arg, struct radix_node_head *head,
    rn_matchf_t *, void *);
struct radix_node *rn_match(void *, struct radix_node_head *);
struct radix_node *rn_match_args(void *, struct radix_node_head *, rn_matchf_t *, void *);

#endif /* PRIVATE */
#endif /* _RADIX_H_ */
