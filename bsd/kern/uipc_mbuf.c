/*
 * Copyright (c) 1998-2022 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
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
 *	@(#)uipc_mbuf.c	8.2 (Berkeley) 1/4/94
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <ptrauth.h>

#include <stdint.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/queue.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/file_internal.h>

#include <vm/vm_kern_xnu.h>

#include <dev/random/randomdev.h>

#include <kern/kern_types.h>
#include <kern/simple_lock.h>
#include <kern/queue.h>
#include <kern/sched_prim.h>
#include <kern/backtrace.h>
#include <kern/percpu.h>
#include <kern/zalloc.h>

#include <libkern/OSDebug.h>
#include <libkern/libkern.h>

#include <os/log.h>
#include <os/ptrtools.h>

#include <machine/limits.h>
#include <machine/machine_routines.h>

#include <net/droptap.h>
#include <net/ntstat.h>

#if INET
extern int tcp_reass_qlen_space(struct socket *);
#endif /* INET */

/*
 * MBUF IMPLEMENTATION NOTES (using zalloc).
 *
 * There are a total of 4 zones and 3 zcaches.
 *
 * MC_MBUF:
 *	This is a zone of rudimentary objects of _MSIZE in size; each
 *	object represents an mbuf structure.  This cache preserves only
 *	the m_type field of the mbuf during its transactions.
 *
 * MC_CL:
 *	This is a zone of rudimentary objects of MCLBYTES in size; each
 *	object represents a mcluster structure.  This cache does not
 *	preserve the contents of the objects during its transactions.
 *
 * MC_BIGCL:
 *	This is a zone of rudimentary objects of MBIGCLBYTES in size; each
 *	object represents a mbigcluster structure.  This cache does not
 *	preserve the contents of the objects during its transaction.
 *
 * MC_16KCL:
 *	This is a zone of rudimentary objects of M16KCLBYTES in size; each
 *	object represents a m16kcluster structure.  This cache does not
 *	preserve the contents of the objects during its transaction.
 *
 * MC_MBUF_CL:
 *	This is a cache of mbufs each having a cluster attached to it.
 *	It is backed by MC_MBUF and MC_CL rudimentary caches.  Several
 *	fields of the mbuf related to the external cluster are preserved
 *	during transactions.
 *
 * MC_MBUF_BIGCL:
 *	This is a cache of mbufs each having a big cluster attached to it.
 *	It is backed by MC_MBUF and MC_BIGCL rudimentary caches.  Several
 *	fields of the mbuf related to the external cluster are preserved
 *	during transactions.
 *
 * MC_MBUF_16KCL:
 *	This is a cache of mbufs each having a big cluster attached to it.
 *	It is backed by MC_MBUF and MC_16KCL rudimentary caches.  Several
 *	fields of the mbuf related to the external cluster are preserved
 *	during transactions.
 *
 * OBJECT ALLOCATION:
 *
 * Allocation requests are handled first at the zalloc per-CPU layer
 * before falling back to the zalloc depot.  Performance is optimal when
 * the request is satisfied at the CPU layer. zalloc has an additional
 * overflow layer called the depot, not pictured in the diagram below.
 *
 * Allocation paths are different depending on the class of objects:
 *
 * a. Rudimentary object:
 *
 *	{ m_get_common(), m_clattach(), m_mclget(),
 *	  m_mclalloc(), m_bigalloc(), m_copym_with_hdrs(),
 *	  composite object allocation }
 *			|	^
 *			|	|
 *			|	+------- (done) --------+
 *			v				|
 *	      zalloc_flags/zalloc_n()	              KASAN
 *			|				^
 *			v				|
 *      +----> [zalloc per-CPU cache] -----> (found?) --+
 *	|		|				|
 *	|		v				|
 *	|  [zalloc recirculation layer] --> (found?) ---+
 *	|		|
 *	|		v
 *	+--<<-- [zone backing store]
 *
 * b. Composite object:
 *
 *	{ m_getpackets_internal(), m_allocpacket_internal() }
 *			|	^
 *			|	|
 *			|	+------	(done) ---------+
 *			v				|
 *              mz_composite_alloc()                  KASAN
 *			|				^
 *                      v                               |
 *                zcache_alloc_n()                      |
 *			|                               |
 *			v                               |
 *	     [zalloc per-CPU cache] --> mark_valid() ---+
 *			|				|
 *			v				|
 *	  [zalloc recirculation layer] -> mark_valid() -+
 *			|				|
 *			v				|
 *               mz_composite_build()                   |
 *			|				|
 *			v				|
 *		(rudimentary objects)			|
 *                   zalloc_id() ---------------->>-----+
 *
 * Auditing notes: If KASAN enabled, buffers will be subjected to
 * integrity checks by the AddressSanitizer.
 *
 * OBJECT DEALLOCATION:
 *
 * Freeing an object simply involves placing it into the CPU cache; this
 * pollutes the cache to benefit subsequent allocations.  The depot
 * will only be entered if the object is to be purged out of the cache.
 * Objects may be purged based on the overall memory pressure or
 * during zone garbage collection.
 * To improve performance, objects are not zero-filled when freed
 * as it's custom for other zalloc zones.
 *
 * Deallocation paths are different depending on the class of objects:
 *
 * a. Rudimentary object:
 *
 *	{ m_free(), m_freem_list(), composite object deallocation }
 *			|	^
 *			|	|
 *			|	+------	(done) ---------+
 *			v				|
 *	          zfree_nozero()                        |
 *			|			        |
 *                      v                               |
 *                    KASAN                             |
 *			|				|
 *			v				|
 *	     [zalloc per-CPU cache] -> (not purging?) --+
 *			|				|
 *			v				|
 *	    [zalloc recirculation layer] --->>----------+
 *
 *
 * b. Composite object:
 *
 *	{ m_free(), m_freem_list() }
 *			|	^
 *			|	|
 *			|	+------	(done) ---------+
 *			v				|
 *	        mz_composite_free()	                |
 *			|			        |
 *			v				|
 *                zcache_free_n()                       |
 *                      |                               |
 *			v				|
 *                    KASAN                             |
 *			|				|
 *			v				|
 *	     [zalloc per-CPU cache] -> mark_invalid() --+
 *			|				|
 *			v				|
 *	        mz_composite_destroy()                  |
 *			|				|
 *			v				|
 *		(rudimentary object)			|
 *	           zfree_nozero() -------------->>------+
 *
 * Auditing notes: If KASAN enabled, buffers will be subjected to
 * integrity checks by the AddressSanitizer.
 *
 * DEBUGGING:
 *
 * Debugging mbufs can be done by booting a KASAN enabled kernel.
 */


/*
 * Convention typedefs for local __single pointers.
 */
typedef typeof(*((zone_t)0)) *__single zone_ref_t;
typedef void * __single any_ref_t;

/* Global lock */
static LCK_GRP_DECLARE(mbuf_mlock_grp, "mbuf");
static LCK_MTX_DECLARE(mbuf_mlock_data, &mbuf_mlock_grp);
#if !CONFIG_MBUF_MCACHE
static
#endif
lck_mtx_t *const mbuf_mlock = &mbuf_mlock_data;

/* Globals */
#if !CONFIG_MBUF_MCACHE
static
#endif
int nclusters;                  /* # of clusters for non-jumbo (legacy) sizes */
int njcl;                       /* # of clusters for jumbo sizes */
int njclbytes;                  /* size of a jumbo cluster */
int max_linkhdr;                /* largest link-level header */
int max_protohdr;              /* largest protocol header */
int max_hdr;                    /* largest link+protocol header */
int max_datalen;                /* MHLEN - max_hdr */

/* Lock to protect the completion callback table */
static LCK_GRP_DECLARE(mbuf_tx_compl_tbl_lck_grp, "mbuf_tx_compl_tbl");
LCK_RW_DECLARE(mbuf_tx_compl_tbl_lock, &mbuf_tx_compl_tbl_lck_grp);

#define m_stats(c)      mbuf_table[c].mtbl_stats
#define m_ctotal(c)     mbuf_table[c].mtbl_stats->mbcl_ctotal

#if !CONFIG_MBUF_MCACHE
/*
 * Note: number of entries in mbuf_table must not exceed
 * MB_STAT_MAX_MB_CLASSES
 */
static mbuf_table_t mbuf_table[] = {
	{ .mtbl_class = MC_MBUF },
	{ .mtbl_class = MC_CL },
	{ .mtbl_class = MC_BIGCL },
	{ .mtbl_class = MC_16KCL },
	{ .mtbl_class = MC_MBUF_CL },
	{ .mtbl_class = MC_MBUF_BIGCL },
	{ .mtbl_class = MC_MBUF_16KCL },
};
#endif /* !CONFIG_MBUF_MCACHE */

#if !CONFIG_MBUF_MCACHE
static
#endif /* !CONFIG_MBUF_MCACHE */
unsigned int mb_memory_pressure_percentage = 80;

static int mbstat_sysctl SYSCTL_HANDLER_ARGS;
static int mb_stat_sysctl SYSCTL_HANDLER_ARGS;
#if !CONFIG_MBUF_MCACHE
static void mbuf_watchdog_defunct(thread_call_param_t, thread_call_param_t);
static void mbuf_watchdog_drain_composite(thread_call_param_t, thread_call_param_t);
static struct mbuf *mz_alloc(zalloc_flags_t);
static void mz_free(struct mbuf *);
static struct ext_ref *mz_ref_alloc(zalloc_flags_t);
static void mz_ref_free(struct ext_ref *);
static void * __bidi_indexable mz_cl_alloc(zone_id_t, zalloc_flags_t);
static void mz_cl_free(zone_id_t, void *);
static struct mbuf *mz_composite_alloc(mbuf_class_t, zalloc_flags_t);
static zstack_t mz_composite_alloc_n(mbuf_class_t, unsigned int, zalloc_flags_t);
static void mz_composite_free(mbuf_class_t, struct mbuf *);
static void mz_composite_free_n(mbuf_class_t, zstack_t);
static void *mz_composite_build(zone_id_t, zalloc_flags_t);
static void *mz_composite_mark_valid(zone_id_t, void *);
static void *mz_composite_mark_invalid(zone_id_t, void *);
static void  mz_composite_destroy(zone_id_t, void *);

ZONE_DEFINE_ID(ZONE_ID_MBUF_REF, "mbuf.ref", struct ext_ref,
    ZC_CACHING | ZC_KASAN_NOQUARANTINE);
ZONE_DEFINE_ID(ZONE_ID_MBUF, "mbuf", struct mbuf,
    ZC_CACHING | ZC_KASAN_NOQUARANTINE);
ZONE_DEFINE_ID(ZONE_ID_CLUSTER_2K, "mbuf.cluster.2k", union mcluster,
    ZC_CACHING | ZC_KASAN_NOQUARANTINE | ZC_SHARED_DATA);
ZONE_DEFINE_ID(ZONE_ID_CLUSTER_4K, "mbuf.cluster.4k", union mbigcluster,
    ZC_CACHING | ZC_KASAN_NOQUARANTINE | ZC_SHARED_DATA);
ZONE_DEFINE_ID(ZONE_ID_CLUSTER_16K, "mbuf.cluster.16k", union m16kcluster,
    ZC_CACHING | ZC_KASAN_NOQUARANTINE | ZC_SHARED_DATA);
static_assert(sizeof(union mcluster) == MCLBYTES);
static_assert(sizeof(union mbigcluster) == MBIGCLBYTES);
static_assert(sizeof(union m16kcluster) == M16KCLBYTES);

static const struct zone_cache_ops mz_composite_ops = {
	.zc_op_alloc        = mz_composite_build,
	.zc_op_mark_valid   = mz_composite_mark_valid,
	.zc_op_mark_invalid = mz_composite_mark_invalid,
	.zc_op_free         = mz_composite_destroy,
};
ZCACHE_DEFINE(ZONE_ID_MBUF_CLUSTER_2K, "mbuf.composite.2k", struct mbuf,
    sizeof(struct mbuf) + sizeof(struct ext_ref) + MCLBYTES,
    &mz_composite_ops);
ZCACHE_DEFINE(ZONE_ID_MBUF_CLUSTER_4K, "mbuf.composite.4k", struct mbuf,
    sizeof(struct mbuf) + sizeof(struct ext_ref) + MBIGCLBYTES,
    &mz_composite_ops);
ZCACHE_DEFINE(ZONE_ID_MBUF_CLUSTER_16K, "mbuf.composite.16k", struct mbuf,
    sizeof(struct mbuf) + sizeof(struct ext_ref) + M16KCLBYTES,
    &mz_composite_ops);
static_assert(ZONE_ID_MBUF + MC_MBUF == ZONE_ID_MBUF);
static_assert(ZONE_ID_MBUF + MC_CL == ZONE_ID_CLUSTER_2K);
static_assert(ZONE_ID_MBUF + MC_BIGCL == ZONE_ID_CLUSTER_4K);
static_assert(ZONE_ID_MBUF + MC_16KCL == ZONE_ID_CLUSTER_16K);
static_assert(ZONE_ID_MBUF + MC_MBUF_CL == ZONE_ID_MBUF_CLUSTER_2K);
static_assert(ZONE_ID_MBUF + MC_MBUF_BIGCL == ZONE_ID_MBUF_CLUSTER_4K);
static_assert(ZONE_ID_MBUF + MC_MBUF_16KCL == ZONE_ID_MBUF_CLUSTER_16K);

/* Converts a an mbuf class to a zalloc zone ID. */
__attribute__((always_inline))
static inline zone_id_t
m_class_to_zid(mbuf_class_t class)
{
	return ZONE_ID_MBUF + class - MC_MBUF;
}

__attribute__((always_inline))
static inline mbuf_class_t
m_class_from_zid(zone_id_t zid)
{
	return MC_MBUF + zid - ZONE_ID_MBUF;
}

static thread_call_t mbuf_defunct_tcall;
static thread_call_t mbuf_drain_tcall;
#endif /* !CONFIG_MBUF_MCACHE */

static int m_copyback0(struct mbuf **, int, int len, const void * __sized_by_or_null(len), int, int);
static struct mbuf *m_split0(struct mbuf *, int, int, int);

/* flags for m_copyback0 */
#define M_COPYBACK0_COPYBACK    0x0001  /* copyback from cp */
#define M_COPYBACK0_PRESERVE    0x0002  /* preserve original data */
#define M_COPYBACK0_COW         0x0004  /* do copy-on-write */
#define M_COPYBACK0_EXTEND      0x0008  /* extend chain */

/*
 * The structure that holds all mbuf class statistics exportable via sysctl.
 * Similar to mbstat structure, the mb_stat structure is protected by the
 * global mbuf lock.  It contains additional information about the classes
 * that allows for a more accurate view of the state of the allocator.
 */
struct mb_stat *mb_stat;
struct omb_stat *omb_stat;      /* For backwards compatibility */

#define MB_STAT_SIZE(n) \
	__builtin_offsetof(mb_stat_t, mbs_class[n])

#define OMB_STAT_SIZE(n) \
	__builtin_offsetof(struct omb_stat, mbs_class[n])

/*
 * The legacy structure holding all of the mbuf allocation statistics.
 * The actual statistics used by the kernel are stored in the mbuf_table
 * instead, and are updated atomically while the global mbuf lock is held.
 * They are mirrored in mbstat to support legacy applications (e.g. netstat).
 * Unlike before, the kernel no longer relies on the contents of mbstat for
 * its operations (e.g. cluster expansion) because the structure is exposed
 * to outside and could possibly be modified, therefore making it unsafe.
 * With the exception of the mbstat.m_mtypes array (see below), all of the
 * statistics are updated as they change.
 */
struct mbstat mbstat;

#define MBSTAT_MTYPES_MAX \
	(sizeof (mbstat.m_mtypes) / sizeof (mbstat.m_mtypes[0]))

#if !CONFIG_MBUF_MCACHE
static
#endif
mbuf_mtypes_t PERCPU_DATA(mbuf_mtypes);

__private_extern__ inline struct ext_ref *
m_get_rfa(struct mbuf *m)
{
	return m->m_ext.ext_refflags;
}

__private_extern__ inline m_ext_free_func_t
m_get_ext_free(struct mbuf *m)
{
	if (m->m_ext.ext_free == NULL) {
		return NULL;
	}

	return ptrauth_nop_cast(m_ext_free_func_t, m->m_ext.ext_free);
}

#if !CONFIG_MBUF_MCACHE
static
#endif
caddr_t
m_get_ext_arg(struct mbuf *m)
{
	return (caddr_t)m->m_ext.ext_arg;
}

#if !CONFIG_MBUF_MCACHE
static
#endif
void
m_set_ext(struct mbuf *m, struct ext_ref *rfa, m_ext_free_func_t ext_free,
    caddr_t ext_arg)
{
	VERIFY(m->m_flags & M_EXT);
	if (rfa != NULL) {
		m->m_ext.ext_refflags = rfa;
		if (ext_free != NULL) {
			m->m_ext.ext_free = ptrauth_nop_cast(m_ext_free_func_t, ext_free);
			m->m_ext.ext_arg = ext_arg;
		} else {
			m->m_ext.ext_free = NULL;
			m->m_ext.ext_arg = NULL;
		}
	} else {
		if (ext_free != NULL) {
			m->m_ext.ext_free = ptrauth_nop_cast(m_ext_free_func_t, ext_free);
			m->m_ext.ext_arg = ext_arg;
		} else {
			m->m_ext.ext_free = NULL;
			m->m_ext.ext_arg = NULL;
		}
		m->m_ext.ext_refflags = NULL;
	}
}

#if !CONFIG_MBUF_MCACHE
static
#endif
void
mext_init(struct mbuf *m, void *__sized_by(size)buf, u_int size,
    m_ext_free_func_t free, caddr_t free_arg, struct ext_ref *rfa,
    u_int16_t min, u_int16_t ref, u_int16_t pref, u_int16_t flag,
    u_int32_t priv, struct mbuf *pm)
{
	m->m_ext.ext_buf = buf;
	m->m_ext.ext_size = size;
	m->m_data = (uintptr_t)m->m_ext.ext_buf;
	m->m_len = 0;
	m->m_flags |= M_EXT;
	m_set_ext(m, rfa, free, free_arg);
	MEXT_MINREF(m) = min;
	MEXT_REF(m) = ref;
	MEXT_PREF(m) = pref;
	MEXT_FLAGS(m) = flag;
	MEXT_PRIV(m) = priv;
	MEXT_PMBUF(m) = pm;
}

#if !CONFIG_MBUF_MCACHE
static
#endif
void
mbuf_mtypes_sync(void)
{
	mbuf_mtypes_t mtc;

	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	mtc = *PERCPU_GET_MASTER(mbuf_mtypes);
	percpu_foreach_secondary(mtype, mbuf_mtypes) {
		for (int n = 0; n < MT_MAX; n++) {
			mtc.cpu_mtypes[n] += mtype->cpu_mtypes[n];
		}
	}

	for (int n = 0; n < MT_MAX; n++) {
		mbstat.m_mtypes[n] = mtc.cpu_mtypes[n];
	}
}

#if !CONFIG_MBUF_MCACHE
static void
mbuf_stat_sync(void)
{
	mb_class_stat_t *sp;
	int k;
	uint64_t drops = 0;


	LCK_MTX_ASSERT(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	for (k = 0; k < MC_MAX; k++) {
		const zone_id_t zid = m_class_to_zid(m_class(k));
		const zone_ref_t zone = zone_by_id(zid);
		struct zone_basic_stats stats = {};

		sp = m_stats(k);
		zone_get_stats(zone, &stats);
		drops += stats.zbs_alloc_fail;
		sp->mbcl_total = stats.zbs_avail;
		sp->mbcl_active = stats.zbs_alloc;
		/*
		 * infree is what mcache considers the freelist (uncached)
		 * free_cnt contains all the cached/uncached elements
		 * in a zone.
		 */
		sp->mbcl_infree = stats.zbs_free - stats.zbs_cached;
		sp->mbcl_fail_cnt = stats.zbs_alloc_fail;
		sp->mbcl_ctotal = sp->mbcl_total;

		/* These stats are not available in zalloc. */
		sp->mbcl_alloc_cnt = 0;
		sp->mbcl_free_cnt = 0;
		sp->mbcl_notified = 0;
		sp->mbcl_purge_cnt = 0;
		sp->mbcl_slab_cnt = 0;
		sp->mbcl_release_cnt = 0;

		/* zalloc caches are always on. */
		sp->mbcl_mc_state = MCS_ONLINE;
		sp->mbcl_mc_cached = stats.zbs_cached;
		/* These stats are not collected by zalloc. */
		sp->mbcl_mc_waiter_cnt = 0;
		sp->mbcl_mc_wretry_cnt = 0;
		sp->mbcl_mc_nwretry_cnt = 0;
	}
	/* Deduct clusters used in composite cache */
	m_ctotal(MC_MBUF) -= (m_total(MC_MBUF_CL) +
	    m_total(MC_MBUF_BIGCL) -
	    m_total(MC_MBUF_16KCL));
	m_ctotal(MC_CL) -= m_total(MC_MBUF_CL);
	m_ctotal(MC_BIGCL) -= m_total(MC_MBUF_BIGCL);
	m_ctotal(MC_16KCL) -= m_total(MC_MBUF_16KCL);

	/* Update mbstat. */
	mbstat.m_mbufs = m_total(MC_MBUF);
	mbstat.m_clusters = m_total(MC_CL);
	mbstat.m_clfree = m_infree(MC_CL) + m_infree(MC_MBUF_CL);
	mbstat.m_drops = drops;
	mbstat.m_bigclusters = m_total(MC_BIGCL);
	mbstat.m_bigclfree = m_infree(MC_BIGCL) + m_infree(MC_MBUF_BIGCL);
}
#endif /* !CONFIG_MBUF_MCACHE */

static int
mbstat_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	lck_mtx_lock(mbuf_mlock);
	mbuf_stat_sync();
	mbuf_mtypes_sync();
	lck_mtx_unlock(mbuf_mlock);

	return SYSCTL_OUT(req, &mbstat, sizeof(mbstat));
}

static int
mb_stat_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	any_ref_t statp;
	int k, statsz, proc64 = proc_is64bit(req->p);

	lck_mtx_lock(mbuf_mlock);
	mbuf_stat_sync();

	if (!proc64) {
		struct omb_class_stat *oc;
		struct mb_class_stat *c;

		omb_stat->mbs_cnt = mb_stat->mbs_cnt;
		oc = &omb_stat->mbs_class[0];
		c = &mb_stat->mbs_class[0];
		for (k = 0; k < omb_stat->mbs_cnt; k++, oc++, c++) {
			(void) snprintf(oc->mbcl_cname, sizeof(oc->mbcl_cname),
			    "%s", c->mbcl_cname);
			oc->mbcl_size = c->mbcl_size;
			oc->mbcl_total = c->mbcl_total;
			oc->mbcl_active = c->mbcl_active;
			oc->mbcl_infree = c->mbcl_infree;
			oc->mbcl_slab_cnt = c->mbcl_slab_cnt;
			oc->mbcl_alloc_cnt = c->mbcl_alloc_cnt;
			oc->mbcl_free_cnt = c->mbcl_free_cnt;
			oc->mbcl_notified = c->mbcl_notified;
			oc->mbcl_purge_cnt = c->mbcl_purge_cnt;
			oc->mbcl_fail_cnt = c->mbcl_fail_cnt;
			oc->mbcl_ctotal = c->mbcl_ctotal;
			oc->mbcl_release_cnt = c->mbcl_release_cnt;
			oc->mbcl_mc_state = c->mbcl_mc_state;
			oc->mbcl_mc_cached = c->mbcl_mc_cached;
			oc->mbcl_mc_waiter_cnt = c->mbcl_mc_waiter_cnt;
			oc->mbcl_mc_wretry_cnt = c->mbcl_mc_wretry_cnt;
			oc->mbcl_mc_nwretry_cnt = c->mbcl_mc_nwretry_cnt;
		}
		statp = omb_stat;
		statsz = OMB_STAT_SIZE(MC_MAX);
	} else {
		statp = mb_stat;
		statsz = MB_STAT_SIZE(MC_MAX);
	}

	lck_mtx_unlock(mbuf_mlock);

	return SYSCTL_OUT(req, statp, statsz);
}

#if !CONFIG_MBUF_MCACHE
static void
mbuf_mcheck(struct mbuf *m)
{
	if (__improbable(m->m_type != MT_FREE && !MBUF_IS_PAIRED(m))) {
		panic("MCHECK: m_type=%d m=%p",
		    (u_int16_t)(m)->m_type, m);
	}
}
#endif /* !CONFIG_MBUF_MCACHE */

static void
m_scratch_init(struct mbuf *m)
{
	struct pkthdr *pkt = &m->m_pkthdr;

	VERIFY(m->m_flags & M_PKTHDR);

	/* See comments in <rdar://problem/14040693> */
	if (pkt->pkt_flags & PKTF_PRIV_GUARDED) {
		panic_plain("Invalid attempt to modify guarded module-private "
		    "area: mbuf %p, pkt_flags 0x%x\n", m, pkt->pkt_flags);
		/* NOTREACHED */
	}

	bzero(&pkt->pkt_mpriv, sizeof(pkt->pkt_mpriv));
}


static void
mbuf_init_pkthdr(struct mbuf *m)
{
	m->m_pkthdr.rcvif = NULL;
	m->m_pkthdr.pkt_hdr = NULL;
	m->m_pkthdr.len = 0;
	m->m_pkthdr.csum_flags = 0;
	m->m_pkthdr.csum_data = 0;
	m->m_pkthdr.vlan_tag = 0;
	m->m_pkthdr.comp_gencnt = 0;
	m->m_pkthdr.pkt_crumbs = 0;
	m_classifier_init(m, 0);
	m_tag_init(m, 1);
	m_scratch_init(m);
}

#if !CONFIG_MBUF_MCACHE
static
#endif
void
mbuf_init(struct mbuf *m, int pkthdr, int type)
{
	mbuf_mcheck(m);
	m->m_next = m->m_nextpkt = NULL;
	m->m_len = 0;
	m->m_type = type;
	if (pkthdr == 0) {
		m->m_data = (uintptr_t)m->m_dat;
		m->m_flags = 0;
	} else {
		m->m_data = (uintptr_t)m->m_pktdat;
		m->m_flags = M_PKTHDR;
		mbuf_init_pkthdr(m);
	}
}


#if !CONFIG_MBUF_MCACHE
/*
 * The following functions are wrappers around mbuf
 * allocation for zalloc.  They all have the prefix "mz"
 * which was chosen to avoid conflicts with the mbuf KPIs.
 *
 * Z_NOPAGEWAIT is used in place of Z_NOWAIT because
 * Z_NOPAGEWAIT maps closer to MCR_TRYHARD. Z_NOWAIT will
 * fail immediately if it has to take a mutex and that
 * may cause packets to be dropped more frequently.
 * In general, the mbuf subsystem can sustain grabbing a mutex
 * during "non-blocking" allocation and that's the reason
 * why Z_NOPAGEWAIT was chosen.
 *
 * mbufs are elided (removed all pointers) before they are
 * returned to the cache. The exception are composite mbufs which
 * are re-initialized on allocation.
 */
__attribute__((always_inline))
static inline void
m_elide(struct mbuf *m)
{
	m->m_next = m->m_nextpkt = NULL;
	m->m_data = 0;
	memset(&m->m_ext, 0, sizeof(m->m_ext));
	m->m_pkthdr.rcvif = NULL;
	m->m_pkthdr.pkt_hdr = NULL;
	m->m_flags |= M_PKTHDR;
	m_tag_init(m, 1);
	m->m_pkthdr.pkt_flags = 0;
	m_scratch_init(m);
	m->m_flags &= ~M_PKTHDR;
}

__attribute__((always_inline))
static inline struct mbuf *
mz_alloc(zalloc_flags_t flags)
{
	if (flags & Z_NOWAIT) {
		flags ^= Z_NOWAIT | Z_NOPAGEWAIT;
	} else if (!(flags & Z_NOPAGEWAIT)) {
		flags |= Z_NOFAIL;
	}
	return zalloc_id(ZONE_ID_MBUF, flags | Z_NOZZC);
}

__attribute__((always_inline))
static inline zstack_t
mz_alloc_n(uint32_t count, zalloc_flags_t flags)
{
	if (flags & Z_NOWAIT) {
		flags ^= Z_NOWAIT | Z_NOPAGEWAIT;
	} else if (!(flags & Z_NOPAGEWAIT)) {
		flags |= Z_NOFAIL;
	}
	return zalloc_n(ZONE_ID_MBUF, count, flags | Z_NOZZC);
}

__attribute__((always_inline))
static inline void
mz_free(struct mbuf *m)
{
#if KASAN
	zone_require(zone_by_id(ZONE_ID_MBUF), m);
#endif
	m_elide(m);
	zfree_nozero(ZONE_ID_MBUF, m);
}

__attribute__((always_inline))
static inline void
mz_free_n(zstack_t list)
{
	/* Callers of this function have already elided the mbuf. */
	zfree_nozero_n(ZONE_ID_MBUF, list);
}

__attribute__((always_inline))
static inline struct ext_ref *
mz_ref_alloc(zalloc_flags_t flags)
{
	if (flags & Z_NOWAIT) {
		flags ^= Z_NOWAIT | Z_NOPAGEWAIT;
	}
	return zalloc_id(ZONE_ID_MBUF_REF, flags | Z_NOZZC);
}

__attribute__((always_inline))
static inline void
mz_ref_free(struct ext_ref *rfa)
{
	VERIFY(rfa->minref == rfa->refcnt);
#if KASAN
	zone_require(zone_by_id(ZONE_ID_MBUF_REF), rfa);
#endif
	zfree_nozero(ZONE_ID_MBUF_REF, rfa);
}

__attribute__((always_inline))
static inline void * __bidi_indexable
mz_cl_alloc(zone_id_t zid, zalloc_flags_t flags)
{
	void * p __unsafe_indexable;
	if (flags & Z_NOWAIT) {
		flags ^= Z_NOWAIT | Z_NOPAGEWAIT;
	} else if (!(flags & Z_NOPAGEWAIT)) {
		flags |= Z_NOFAIL;
	}
	flags |= Z_NOZZC;

	/*
	 * N.B. Invoking `(zalloc_id)' directly, vs. via `zalloc_id' macro.
	 */
	p = (zalloc_id)(zid, flags);
	return __unsafe_forge_bidi_indexable(void *, p, zone_get_elem_size(zone_by_id(zid)));
}

__attribute__((always_inline))
static inline void
mz_cl_free(zone_id_t zid, void *cl)
{
#if KASAN
	zone_require(zone_by_id(zid), cl);
#endif
	zfree_nozero(zid, cl);
}

__attribute__((always_inline))
static inline zstack_t
mz_composite_alloc_n(mbuf_class_t class, unsigned int n, zalloc_flags_t flags)
{
	if (flags & Z_NOWAIT) {
		flags ^= Z_NOWAIT | Z_NOPAGEWAIT;
	}
	return (zcache_alloc_n)(m_class_to_zid(class), n, flags,
	       &mz_composite_ops);
}

__attribute__((always_inline))
static inline struct mbuf *
mz_composite_alloc(mbuf_class_t class, zalloc_flags_t flags)
{
	zstack_t list = {};
	list = mz_composite_alloc_n(class, 1, flags);
	if (!zstack_empty(list)) {
		return zstack_pop(&list);
	} else {
		return NULL;
	}
}

__attribute__((always_inline))
static inline void
mz_composite_free_n(mbuf_class_t class, zstack_t list)
{
	(zcache_free_n)(m_class_to_zid(class), list, &mz_composite_ops);
}

__attribute__((always_inline))
static inline void
mz_composite_free(mbuf_class_t class, struct mbuf *m)
{
	zstack_t list = {};
	zstack_push(&list, m);
	(zcache_free_n)(m_class_to_zid(class), list, &mz_composite_ops);
}

/* Converts composite zone ID to the cluster zone ID. */
__attribute__((always_inline))
static inline zone_id_t
mz_cl_zid(zone_id_t zid)
{
	return ZONE_ID_CLUSTER_2K + zid - ZONE_ID_MBUF_CLUSTER_2K;
}

static void *
mz_composite_build(zone_id_t zid, zalloc_flags_t flags)
{
	const zone_id_t cl_zid = mz_cl_zid(zid);
	struct mbuf *m = NULL;
	struct ext_ref *rfa = NULL;
	void *cl = NULL;

	cl = mz_cl_alloc(cl_zid, flags);
	if (__improbable(cl == NULL)) {
		goto out;
	}
	rfa = mz_ref_alloc(flags);
	if (__improbable(rfa == NULL)) {
		goto out_free_cl;
	}
	m = mz_alloc(flags);
	if (__improbable(m == NULL)) {
		goto out_free_rfa;
	}
	mbuf_init(m, 0, MT_FREE);
	if (zid == ZONE_ID_MBUF_CLUSTER_2K) {
		MBUF_CL_INIT(m, cl, rfa, 0, EXTF_COMPOSITE);
	} else if (zid == ZONE_ID_MBUF_CLUSTER_4K) {
		MBUF_BIGCL_INIT(m, cl, rfa, 0, EXTF_COMPOSITE);
	} else {
		MBUF_16KCL_INIT(m, cl, rfa, 0, EXTF_COMPOSITE);
	}
	VERIFY(m->m_flags == M_EXT);
	VERIFY(m_get_rfa(m) != NULL && MBUF_IS_COMPOSITE(m));

	return m;
out_free_rfa:
	mz_ref_free(rfa);
out_free_cl:
	mz_cl_free(cl_zid, cl);
out:
	return NULL;
}

static void *
mz_composite_mark_valid(zone_id_t zid, void *p)
{
	mbuf_ref_t m = p;

	m = zcache_mark_valid_single(zone_by_id(ZONE_ID_MBUF), m);
#if KASAN
	struct ext_ref *rfa __single = m_get_rfa(m);
	const zone_id_t cl_zid = mz_cl_zid(zid);
	void *cl = m->m_ext.ext_buf;

	cl = __unsafe_forge_bidi_indexable(void *,
	    zcache_mark_valid(zone_by_id(cl_zid), cl),
	    zone_get_elem_size(zone_by_id(cl_zid)));
	rfa = __unsafe_forge_single(struct ext_ref *,
	    zcache_mark_valid(zone_by_id(ZONE_ID_MBUF_REF), rfa));
	m->m_data = (uintptr_t)cl;
	m->m_ext.ext_buf = cl;
	m->m_ext.ext_size = m->m_ext.ext_size;
	m->m_ext.ext_refflags = rfa;
#else
#pragma unused(zid)
#endif
	VERIFY(MBUF_IS_COMPOSITE(m));

	return m;
}

static void *
mz_composite_mark_invalid(zone_id_t zid, void *p)
{
	mbuf_ref_t m = p;

	VERIFY(MBUF_IS_COMPOSITE(m));
	VERIFY(MEXT_REF(m) == MEXT_MINREF(m));
#if KASAN
	struct ext_ref *rfa __single = m_get_rfa(m);
	const zone_id_t cl_zid = mz_cl_zid(zid);
	void *cl = m->m_ext.ext_buf;

	cl = __unsafe_forge_bidi_indexable(void *,
	    zcache_mark_invalid(zone_by_id(cl_zid), cl),
	    zone_get_elem_size(zone_by_id(cl_zid)));
	rfa = __unsafe_forge_single(struct ext_ref *,
	    zcache_mark_invalid(zone_by_id(ZONE_ID_MBUF_REF), rfa));
	m->m_data = (uintptr_t)cl;
	m->m_ext.ext_buf = cl;
	m->m_ext.ext_size = m->m_ext.ext_size;
	m->m_ext.ext_refflags = rfa;
#else
#pragma unused(zid)
#endif

	return zcache_mark_invalid_single(zone_by_id(ZONE_ID_MBUF), m);
}

static void
mz_composite_destroy(zone_id_t zid, void *p)
{
	const zone_id_t cl_zid = mz_cl_zid(zid);
	struct ext_ref *rfa = NULL;
	mbuf_ref_t m = p;

	VERIFY(MBUF_IS_COMPOSITE(m));

	MEXT_MINREF(m) = 0;
	MEXT_REF(m) = 0;
	MEXT_PREF(m) = 0;
	MEXT_FLAGS(m) = 0;
	MEXT_PRIV(m) = 0;
	MEXT_PMBUF(m) = NULL;

	rfa = m_get_rfa(m);
	m_set_ext(m, NULL, NULL, NULL);

	m->m_type = MT_FREE;
	m->m_flags = m->m_len = 0;
	m->m_next = m->m_nextpkt = NULL;

	mz_cl_free(cl_zid, m->m_ext.ext_buf);
	m->m_ext.ext_size = 0;
	m->m_ext.ext_buf = NULL;
	mz_ref_free(rfa);
	mz_free(m);
}
#endif /* !CONFIG_MBUF_MCACHE */

#if !CONFIG_MBUF_MCACHE
static
#endif
void
m_incref(struct mbuf *m)
{
	uint16_t new = os_atomic_inc(&MEXT_REF(m), relaxed);

	VERIFY(new != 0);
	/*
	 * If cluster is shared, mark it with (sticky) EXTF_READONLY;
	 * we don't clear the flag when the refcount goes back to the
	 * minimum, to simplify code calling m_mclhasreference().
	 */
	if (new > (MEXT_MINREF(m) + 1) && !(MEXT_FLAGS(m) & EXTF_READONLY)) {
		os_atomic_or(&MEXT_FLAGS(m), EXTF_READONLY, relaxed);
	}
}

#if !CONFIG_MBUF_MCACHE
static
#endif
uint16_t
m_decref(struct mbuf *m)
{
	VERIFY(MEXT_REF(m) != 0);

	return os_atomic_dec(&MEXT_REF(m), acq_rel);
}

/* By default, mbuf_limit is enabled. Except when serverperfmode is set. */
static int mbuf_limit = 1;

#if !CONFIG_MBUF_MCACHE
static
#endif
void
mbuf_table_init(void)
{
	unsigned int b, c, s;
	int m;

	omb_stat = zalloc_permanent(OMB_STAT_SIZE(MC_MAX),
	    ZALIGN(struct omb_stat));

	mb_stat = zalloc_permanent(MB_STAT_SIZE(MC_MAX),
	    ZALIGN(mb_stat_t));

	mb_stat->mbs_cnt = MC_MAX;
	for (m = 0; m < MC_MAX; m++) {
		mbuf_table[m].mtbl_stats = &mb_stat->mbs_class[m];
	}

	/*
	 * Set aside 1/3 of the mbuf cluster map for jumbo
	 * clusters; we do this only on platforms where jumbo
	 * cluster pool is enabled.
	 */
	njcl = nmbclusters / 3;
	njclbytes = M16KCLBYTES;

	/*
	 * nclusters holds both the 2KB and 4KB pools, so ensure it's
	 * a multiple of 4KB clusters.
	 */
	nclusters = P2ROUNDDOWN(nmbclusters - njcl, NCLPG);

	/*
	 * Each jumbo cluster takes 8 2KB clusters, so make
	 * sure that the pool size is evenly divisible by 8;
	 * njcl is in 2KB unit, hence treated as such.
	 */
	njcl = P2ROUNDDOWN(nmbclusters - nclusters, NCLPJCL);

	/* Update nclusters with rounded down value of njcl */
	nclusters = P2ROUNDDOWN(nmbclusters - njcl, NCLPG);

	/*
	 * njcl is valid only on platforms with 16KB jumbo clusters or
	 * with 16KB pages, where it is configured to 1/3 of the pool
	 * size.  On these platforms, the remaining is used for 2KB
	 * and 4KB clusters.  On platforms without 16KB jumbo clusters,
	 * the entire pool is used for both 2KB and 4KB clusters.  A 4KB
	 * cluster can either be splitted into 16 mbufs, or into 2 2KB
	 * clusters.
	 *
	 *  +---+---+------------ ... -----------+------- ... -------+
	 *  | c | b |              s             |        njcl       |
	 *  +---+---+------------ ... -----------+------- ... -------+
	 *
	 * 1/32th of the shared region is reserved for pure 2KB and 4KB
	 * clusters (1/64th each.)
	 */
	c = P2ROUNDDOWN((nclusters >> 6), NCLPG);       /* in 2KB unit */
	b = P2ROUNDDOWN((nclusters >> (6 + NCLPBGSHIFT)), NBCLPG);  /* in 4KB unit */
	s = nclusters - (c + (b << NCLPBGSHIFT));       /* in 2KB unit */

	/*
	 * 1/64th (c) is reserved for 2KB clusters.
	 */
	m_minlimit(MC_CL) = c;
	if (mbuf_limit) {
		m_maxlimit(MC_CL) = s + c;                      /* in 2KB unit */
	} else {
		m_maxlimit(MC_CL) = INT_MAX;
	}
	m_maxsize(MC_CL) = m_size(MC_CL) = MCLBYTES;
	snprintf(m_cname(MC_CL), MAX_MBUF_CNAME, "cl");

	/*
	 * Another 1/64th (b) of the map is reserved for 4KB clusters.
	 * It cannot be turned into 2KB clusters or mbufs.
	 */
	m_minlimit(MC_BIGCL) = b;
	if (mbuf_limit) {
		m_maxlimit(MC_BIGCL) = (s >> NCLPBGSHIFT) + b;  /* in 4KB unit */
	} else {
		m_maxlimit(MC_BIGCL) = INT_MAX;
	}
	m_maxsize(MC_BIGCL) = m_size(MC_BIGCL) = MBIGCLBYTES;
	snprintf(m_cname(MC_BIGCL), MAX_MBUF_CNAME, "bigcl");

	/*
	 * The remaining 31/32ths (s) are all-purpose (mbufs, 2KB, or 4KB)
	 */
	m_minlimit(MC_MBUF) = 0;
	if (mbuf_limit) {
		m_maxlimit(MC_MBUF) = s * NMBPCL;       /* in mbuf unit */
	} else {
		m_maxlimit(MC_MBUF) = INT_MAX;
	}
	m_maxsize(MC_MBUF) = m_size(MC_MBUF) = _MSIZE;
	snprintf(m_cname(MC_MBUF), MAX_MBUF_CNAME, "mbuf");

	/*
	 * Set limits for the composite classes.
	 */
	m_minlimit(MC_MBUF_CL) = 0;
	if (mbuf_limit) {
		m_maxlimit(MC_MBUF_CL) = m_maxlimit(MC_CL);
	} else {
		m_maxlimit(MC_MBUF_CL) = INT_MAX;
	}
	m_maxsize(MC_MBUF_CL) = MCLBYTES;
	m_size(MC_MBUF_CL) = m_size(MC_MBUF) + m_size(MC_CL);
	snprintf(m_cname(MC_MBUF_CL), MAX_MBUF_CNAME, "mbuf_cl");

	m_minlimit(MC_MBUF_BIGCL) = 0;
	if (mbuf_limit) {
		m_maxlimit(MC_MBUF_BIGCL) = m_maxlimit(MC_BIGCL);
	} else {
		m_maxlimit(MC_MBUF_BIGCL) = INT_MAX;
	}
	m_maxsize(MC_MBUF_BIGCL) = MBIGCLBYTES;
	m_size(MC_MBUF_BIGCL) = m_size(MC_MBUF) + m_size(MC_BIGCL);
	snprintf(m_cname(MC_MBUF_BIGCL), MAX_MBUF_CNAME, "mbuf_bigcl");

	/*
	 * And for jumbo classes.
	 */
	m_minlimit(MC_16KCL) = 0;
	if (mbuf_limit) {
		m_maxlimit(MC_16KCL) = (njcl >> NCLPJCLSHIFT);  /* in 16KB unit */
	} else {
		m_maxlimit(MC_16KCL) = INT_MAX;
	}
	m_maxsize(MC_16KCL) = m_size(MC_16KCL) = M16KCLBYTES;
	snprintf(m_cname(MC_16KCL), MAX_MBUF_CNAME, "16kcl");

	m_minlimit(MC_MBUF_16KCL) = 0;
	if (mbuf_limit) {
		m_maxlimit(MC_MBUF_16KCL) = m_maxlimit(MC_16KCL);
	} else {
		m_maxlimit(MC_MBUF_16KCL) = INT_MAX;
	}
	m_maxsize(MC_MBUF_16KCL) = M16KCLBYTES;
	m_size(MC_MBUF_16KCL) = m_size(MC_MBUF) + m_size(MC_16KCL);
	snprintf(m_cname(MC_MBUF_16KCL), MAX_MBUF_CNAME, "mbuf_16kcl");

	/*
	 * Initialize the legacy mbstat structure.
	 */
	bzero(&mbstat, sizeof(mbstat));
	mbstat.m_msize = m_maxsize(MC_MBUF);
	mbstat.m_mclbytes = m_maxsize(MC_CL);
	mbstat.m_minclsize = MINCLSIZE;
	mbstat.m_mlen = MLEN;
	mbstat.m_mhlen = MHLEN;
	mbstat.m_bigmclbytes = m_maxsize(MC_BIGCL);
}

#if !CONFIG_MBUF_MCACHE
static
#endif
int
mbuf_get_class(struct mbuf *m)
{
	if (m->m_flags & M_EXT) {
		uint32_t composite = (MEXT_FLAGS(m) & EXTF_COMPOSITE);
		m_ext_free_func_t m_free_func = m_get_ext_free(m);

		if (m_free_func == NULL) {
			if (composite) {
				return MC_MBUF_CL;
			} else {
				return MC_CL;
			}
		} else if (m_free_func == m_bigfree) {
			if (composite) {
				return MC_MBUF_BIGCL;
			} else {
				return MC_BIGCL;
			}
		} else if (m_free_func == m_16kfree) {
			if (composite) {
				return MC_MBUF_16KCL;
			} else {
				return MC_16KCL;
			}
		}
	}

	return MC_MBUF;
}

#if !CONFIG_MBUF_MCACHE
bool
mbuf_class_under_pressure(struct mbuf *m)
{
	struct zone_basic_stats stats = {};
	zone_ref_t zone;
	zone_id_t zid;
	int mclass;

	if (mbuf_limit == 0) {
		return false;
	}

	mclass = mbuf_get_class(m);

	/*
	 * Grab the statistics from zalloc.
	 * We can't call mbuf_stat_sync() since that requires a lock.
	 */
	zid = m_class_to_zid(m_class(mclass));
	zone = zone_by_id(zid);

	zone_get_stats(zone, &stats);
	if (stats.zbs_avail - stats.zbs_free >= (m_maxlimit(mclass) * mb_memory_pressure_percentage) / 100) {
		os_log(OS_LOG_DEFAULT,
		    "%s memory-pressure on mbuf due to class %u, total %llu free %llu max %u",
		    __func__, mclass, stats.zbs_avail, stats.zbs_free, m_maxlimit(mclass));
		return true;
	}

	return false;
}
#endif /* CONFIG_MBUF_MCACHE */

#if defined(__LP64__)
typedef struct ncl_tbl {
	uint64_t nt_maxmem;     /* memory (sane) size */
	uint32_t nt_mbpool;     /* mbuf pool size */
} ncl_tbl_t;

static const ncl_tbl_t ncl_table[] = {
	{ (1ULL << GBSHIFT) /*  1 GB */, (64 << MBSHIFT) /*  64 MB */ },
	{ (1ULL << (GBSHIFT + 2)) /*  4 GB */, (96 << MBSHIFT) /*  96 MB */ },
	{ (1ULL << (GBSHIFT + 3)) /* 8 GB */, (128 << MBSHIFT) /* 128 MB */ },
	{ (1ULL << (GBSHIFT + 4)) /* 16 GB */, (256 << MBSHIFT) /* 256 MB */ },
	{ (1ULL << (GBSHIFT + 5)) /* 32 GB */, (512 << MBSHIFT) /* 512 MB */ },
	{ 0, 0 }
};
#endif /* __LP64__ */

__private_extern__ unsigned int
mbuf_default_ncl(uint64_t mem)
{
#if !defined(__LP64__)
	unsigned int n;
	/*
	 * 32-bit kernel (default to 64MB of mbuf pool for >= 1GB RAM).
	 */
	if ((n = ((mem / 16) / MCLBYTES)) > 32768) {
		n = 32768;
	}
#else
	unsigned int n, i;
	/*
	 * 64-bit kernel (mbuf pool size based on table).
	 */
	n = ncl_table[0].nt_mbpool;
	for (i = 0; ncl_table[i].nt_mbpool != 0; i++) {
		if (mem < ncl_table[i].nt_maxmem) {
			break;
		}
		n = ncl_table[i].nt_mbpool;
	}
	n >>= MCLSHIFT;
#endif /* !__LP64__ */
	return n;
}

#if !CONFIG_MBUF_MCACHE
__private_extern__ void
mbinit(void)
{
	unsigned int m;

	/*
	 * These MBUF_ values must be equal to their private counterparts.
	 */
	static_assert(MBUF_EXT == M_EXT);
	static_assert(MBUF_PKTHDR == M_PKTHDR);
	static_assert(MBUF_EOR == M_EOR);
	static_assert(MBUF_LOOP == M_LOOP);
	static_assert(MBUF_BCAST == M_BCAST);
	static_assert(MBUF_MCAST == M_MCAST);
	static_assert(MBUF_FRAG == M_FRAG);
	static_assert(MBUF_FIRSTFRAG == M_FIRSTFRAG);
	static_assert(MBUF_LASTFRAG == M_LASTFRAG);
	static_assert(MBUF_PROMISC == M_PROMISC);
	static_assert(MBUF_HASFCS == M_HASFCS);

	static_assert(MBUF_TYPE_FREE == MT_FREE);
	static_assert(MBUF_TYPE_DATA == MT_DATA);
	static_assert(MBUF_TYPE_HEADER == MT_HEADER);
	static_assert(MBUF_TYPE_SOCKET == MT_SOCKET);
	static_assert(MBUF_TYPE_PCB == MT_PCB);
	static_assert(MBUF_TYPE_RTABLE == MT_RTABLE);
	static_assert(MBUF_TYPE_HTABLE == MT_HTABLE);
	static_assert(MBUF_TYPE_ATABLE == MT_ATABLE);
	static_assert(MBUF_TYPE_SONAME == MT_SONAME);
	static_assert(MBUF_TYPE_SOOPTS == MT_SOOPTS);
	static_assert(MBUF_TYPE_FTABLE == MT_FTABLE);
	static_assert(MBUF_TYPE_RIGHTS == MT_RIGHTS);
	static_assert(MBUF_TYPE_IFADDR == MT_IFADDR);
	static_assert(MBUF_TYPE_CONTROL == MT_CONTROL);
	static_assert(MBUF_TYPE_OOBDATA == MT_OOBDATA);

	static_assert(MBUF_TSO_IPV4 == CSUM_TSO_IPV4);
	static_assert(MBUF_TSO_IPV6 == CSUM_TSO_IPV6);
	static_assert(MBUF_CSUM_REQ_SUM16 == CSUM_PARTIAL);
	static_assert(MBUF_CSUM_TCP_SUM16 == MBUF_CSUM_REQ_SUM16);
	static_assert(MBUF_CSUM_REQ_ZERO_INVERT == CSUM_ZERO_INVERT);
	static_assert(MBUF_CSUM_REQ_IP == CSUM_IP);
	static_assert(MBUF_CSUM_REQ_TCP == CSUM_TCP);
	static_assert(MBUF_CSUM_REQ_UDP == CSUM_UDP);
	static_assert(MBUF_CSUM_REQ_TCPIPV6 == CSUM_TCPIPV6);
	static_assert(MBUF_CSUM_REQ_UDPIPV6 == CSUM_UDPIPV6);
	static_assert(MBUF_CSUM_DID_IP == CSUM_IP_CHECKED);
	static_assert(MBUF_CSUM_IP_GOOD == CSUM_IP_VALID);
	static_assert(MBUF_CSUM_DID_DATA == CSUM_DATA_VALID);
	static_assert(MBUF_CSUM_PSEUDO_HDR == CSUM_PSEUDO_HDR);

	static_assert(MBUF_WAITOK == M_WAIT);
	static_assert(MBUF_DONTWAIT == M_DONTWAIT);
	static_assert(MBUF_COPYALL == M_COPYALL);

	static_assert(MBUF_SC2TC(MBUF_SC_BK_SYS) == MBUF_TC_BK);
	static_assert(MBUF_SC2TC(MBUF_SC_BK) == MBUF_TC_BK);
	static_assert(MBUF_SC2TC(MBUF_SC_BE) == MBUF_TC_BE);
	static_assert(MBUF_SC2TC(MBUF_SC_RD) == MBUF_TC_BE);
	static_assert(MBUF_SC2TC(MBUF_SC_OAM) == MBUF_TC_BE);
	static_assert(MBUF_SC2TC(MBUF_SC_AV) == MBUF_TC_VI);
	static_assert(MBUF_SC2TC(MBUF_SC_RV) == MBUF_TC_VI);
	static_assert(MBUF_SC2TC(MBUF_SC_VI) == MBUF_TC_VI);
	static_assert(MBUF_SC2TC(MBUF_SC_SIG) == MBUF_TC_VI);
	static_assert(MBUF_SC2TC(MBUF_SC_VO) == MBUF_TC_VO);
	static_assert(MBUF_SC2TC(MBUF_SC_CTL) == MBUF_TC_VO);

	static_assert(MBUF_TC2SCVAL(MBUF_TC_BK) == SCVAL_BK);
	static_assert(MBUF_TC2SCVAL(MBUF_TC_BE) == SCVAL_BE);
	static_assert(MBUF_TC2SCVAL(MBUF_TC_VI) == SCVAL_VI);
	static_assert(MBUF_TC2SCVAL(MBUF_TC_VO) == SCVAL_VO);

	/* Module specific scratch space (32-bit alignment requirement) */
	static_assert(!(offsetof(struct mbuf, m_pkthdr.pkt_mpriv) % sizeof(uint32_t)));

	if (nmbclusters == 0) {
		nmbclusters = NMBCLUSTERS;
	}

	/* This should be a sane (at least even) value by now */
	VERIFY(nmbclusters != 0 && !(nmbclusters & 0x1));

	PE_parse_boot_argn("mbuf_limit", &mbuf_limit, sizeof(mbuf_limit));
	if (serverperfmode) {
		mbuf_limit = 0;
	}

	/* Setup the mbuf table */
	mbuf_table_init();

	static_assert(sizeof(struct mbuf) == _MSIZE);

	/*
	 * We have yet to create the non composite zones
	 * and thus we haven't asked zalloc to allocate
	 * anything yet, which means that at this point
	 * m_total() is zero.  Once we create the zones and
	 * raise the reserve, m_total() will be calculated,
	 * but until then just assume that we will have
	 * at least the minium limit allocated.
	 */
	m_total(MC_BIGCL) = m_minlimit(MC_BIGCL);
	m_total(MC_CL) = m_minlimit(MC_CL);

	for (m = 0; m < MC_MAX; m++) {
		/* Make sure we didn't miss any */
		VERIFY(m_minlimit(m_class(m)) == 0 ||
		    m_total(m_class(m)) >= m_minlimit(m_class(m)));
	}

	/* Create the cache for each class */
	for (m = 0; m < MC_MAX; m++) {
		if (!MBUF_CLASS_COMPOSITE(m)) {
			zone_ref_t zone = zone_by_id(m_class_to_zid(m));

			if (mbuf_limit) {
				zone_set_exhaustible(zone, m_maxlimit(m), false);
			}
			zone_raise_reserve(zone, m_minlimit(m));
			/*
			 * Pretend that we have allocated m_total() items
			 * at this point.  zalloc will eventually do that
			 * but it's an async operation.
			 */
			m_total(m) = m_minlimit(m);
		}
	}

	/*
	 * Set the max limit on sb_max to be 1/16 th of the size of
	 * memory allocated for mbuf clusters.
	 */
	high_sb_max = (nmbclusters << (MCLSHIFT - 4));
	if (high_sb_max < sb_max) {
		/* sb_max is too large for this configuration, scale it down */
		if (high_sb_max > (1 << MBSHIFT)) {
			/* We have atleast 16 M of mbuf pool */
			sb_max = high_sb_max;
		} else if ((nmbclusters << MCLSHIFT) > (1 << MBSHIFT)) {
			/*
			 * If we have more than 1M of mbufpool, cap the size of
			 * max sock buf at 1M
			 */
			sb_max = high_sb_max = (1 << MBSHIFT);
		} else {
			sb_max = high_sb_max;
		}
	}

	mbuf_defunct_tcall =
	    thread_call_allocate_with_options(mbuf_watchdog_defunct,
	    NULL,
	    THREAD_CALL_PRIORITY_KERNEL,
	    THREAD_CALL_OPTIONS_ONCE);
	mbuf_drain_tcall =
	    thread_call_allocate_with_options(mbuf_watchdog_drain_composite,
	    NULL,
	    THREAD_CALL_PRIORITY_KERNEL,
	    THREAD_CALL_OPTIONS_ONCE);
	printf("%s: done [%d MB total pool size, (%d/%d) split]\n", __func__,
	    (nmbclusters << MCLSHIFT) >> MBSHIFT,
	    (nclusters << MCLSHIFT) >> MBSHIFT,
	    (njcl << MCLSHIFT) >> MBSHIFT);
}

static inline struct mbuf *
m_get_common(int wait, short type, int hdr)
{
	struct mbuf *m;

	m = mz_alloc(wait);
	if (m != NULL) {
		mbuf_init(m, hdr, type);
		mtype_stat_inc(type);
		mtype_stat_dec(MT_FREE);
	}
	return m;
}
#endif /* !CONFIG_MBUF_MCACHE */

/*
 * Space allocation routines; these are also available as macros
 * for critical paths.
 */
#define _M_GET(wait, type)      m_get_common(wait, type, 0)
#define _M_GETHDR(wait, type)   m_get_common(wait, type, 1)
#define _M_RETRY(wait, type)    _M_GET(wait, type)
#define _M_RETRYHDR(wait, type) _M_GETHDR(wait, type)
#define _MGET(m, how, type)     ((m) = _M_GET(how, type))
#define _MGETHDR(m, how, type)  ((m) = _M_GETHDR(how, type))

struct mbuf *
m_get(int wait, int type)
{
	return _M_GET(wait, type);
}

struct mbuf *
m_gethdr(int wait, int type)
{
	return _M_GETHDR(wait, type);
}

struct mbuf *
m_retry(int wait, int type)
{
	return _M_RETRY(wait, type);
}

struct mbuf *
m_retryhdr(int wait, int type)
{
	return _M_RETRYHDR(wait, type);
}

struct mbuf *
m_getclr(int wait, int type)
{
	struct mbuf *m;

	_MGET(m, wait, type);
	if (m != NULL) {
		bzero(mtod(m, caddr_t), MLEN);
	}
	return m;
}

#if !CONFIG_MBUF_MCACHE
static
#endif
int
m_free_paired(struct mbuf *m)
{
	VERIFY((m->m_flags & M_EXT) && (MEXT_FLAGS(m) & EXTF_PAIRED));

	os_atomic_thread_fence(seq_cst);
	if (MEXT_PMBUF(m) == m) {
		/*
		 * Paired ref count might be negative in case we lose
		 * against another thread clearing MEXT_PMBUF, in the
		 * event it occurs after the above memory barrier sync.
		 * In that case just ignore as things have been unpaired.
		 */
		int16_t prefcnt = os_atomic_dec(&MEXT_PREF(m), acq_rel);
		if (prefcnt > 1) {
			return 1;
		} else if (prefcnt == 1) {
			m_ext_free_func_t m_free_func = m_get_ext_free(m);
			VERIFY(m_free_func != NULL);
			(*m_free_func)(m->m_ext.ext_buf,
			    m->m_ext.ext_size, m_get_ext_arg(m));
			return 1;
		} else if (prefcnt == 0) {
			VERIFY(MBUF_IS_PAIRED(m));

			/*
			 * Restore minref to its natural value, so that
			 * the caller will be able to free the cluster
			 * as appropriate.
			 */
			MEXT_MINREF(m) = 0;

			/*
			 * Clear MEXT_PMBUF, but leave EXTF_PAIRED intact
			 * as it is immutable.  atomic_set_ptr also causes
			 * memory barrier sync.
			 */
			os_atomic_store(&MEXT_PMBUF(m), (mbuf_ref_t)0, release);

			switch (m->m_ext.ext_size) {
			case MCLBYTES:
				m_set_ext(m, m_get_rfa(m), NULL, NULL);
				break;

			case MBIGCLBYTES:
				m_set_ext(m, m_get_rfa(m), m_bigfree, NULL);
				break;

			case M16KCLBYTES:
				m_set_ext(m, m_get_rfa(m), m_16kfree, NULL);
				break;

			default:
				VERIFY(0);
				/* NOTREACHED */
			}
		}
	}

	/*
	 * Tell caller the unpair has occurred, and that the reference
	 * count on the external cluster held for the paired mbuf should
	 * now be dropped.
	 */
	return 0;
}

#if !CONFIG_MBUF_MCACHE
struct mbuf *
m_free(struct mbuf *m)
{
	struct mbuf *n = m->m_next;

	if (m->m_type == MT_FREE) {
		panic("m_free: freeing an already freed mbuf");
	}

	if (m->m_flags & M_PKTHDR) {
		/* Free the aux data and tags if there is any */
		m_tag_delete_chain(m);

		m_do_tx_compl_callback(m, NULL);
	}

	if (m->m_flags & M_EXT) {
		if (MBUF_IS_PAIRED(m) && m_free_paired(m)) {
			return n;
		}
		/*
		 * Make sure that we don't touch any ext_ref
		 * member after we decrement the reference count
		 * since that may lead to use-after-free
		 * when we do not hold the last reference.
		 */
		const bool composite = !!(MEXT_FLAGS(m) & EXTF_COMPOSITE);
		const m_ext_free_func_t m_free_func = m_get_ext_free(m);
		const uint16_t minref = MEXT_MINREF(m);
		const uint16_t refcnt = m_decref(m);

		if (refcnt == minref && !composite) {
			if (m_free_func == NULL) {
				mz_cl_free(ZONE_ID_CLUSTER_2K, m->m_ext.ext_buf);
			} else if (m_free_func == m_bigfree) {
				mz_cl_free(ZONE_ID_CLUSTER_4K, m->m_ext.ext_buf);
			} else if (m_free_func == m_16kfree) {
				mz_cl_free(ZONE_ID_CLUSTER_16K, m->m_ext.ext_buf);
			} else {
				(*m_free_func)(m->m_ext.ext_buf,
				    m->m_ext.ext_size, m_get_ext_arg(m));
			}
			mz_ref_free(m_get_rfa(m));
			m_set_ext(m, NULL, NULL, NULL);
		} else if (refcnt == minref && composite) {
			VERIFY(!(MEXT_FLAGS(m) & EXTF_PAIRED));

			mtype_stat_dec(m->m_type);
			mtype_stat_inc(MT_FREE);

			m->m_type = MT_FREE;
			m->m_flags = M_EXT;
			m->m_len = 0;
			m->m_next = m->m_nextpkt = NULL;
			/*
			 * MEXT_FLAGS is safe to access here
			 * since we are now sure that we held
			 * the last reference to ext_ref.
			 */
			MEXT_FLAGS(m) &= ~EXTF_READONLY;

			/* "Free" into the intermediate cache */
			if (m_free_func == NULL) {
				mz_composite_free(MC_MBUF_CL, m);
			} else if (m_free_func == m_bigfree) {
				mz_composite_free(MC_MBUF_BIGCL, m);
			} else {
				VERIFY(m_free_func == m_16kfree);
				mz_composite_free(MC_MBUF_16KCL, m);
			}
			return n;
		}
	}

	mtype_stat_dec(m->m_type);
	mtype_stat_inc(MT_FREE);

	m->m_type = MT_FREE;
	m->m_flags = m->m_len = 0;
	m->m_next = m->m_nextpkt = NULL;

	mz_free(m);

	return n;
}

__private_extern__ struct mbuf *
m_clattach(struct mbuf *m, int type, caddr_t extbuf __sized_by(extsize),
    void (*extfree)(caddr_t, u_int, caddr_t), size_t extsize, caddr_t extarg,
    int wait, int pair)
{
	struct ext_ref *rfa = NULL;

	/*
	 * If pairing is requested and an existing mbuf is provided, reject
	 * it if it's already been paired to another cluster.  Otherwise,
	 * allocate a new one or free any existing below.
	 */
	if ((m != NULL && MBUF_IS_PAIRED(m)) ||
	    (m == NULL && (m = _M_GETHDR(wait, type)) == NULL)) {
		return NULL;
	}

	if (m->m_flags & M_EXT) {
		/*
		 * Make sure that we don't touch any ext_ref
		 * member after we decrement the reference count
		 * since that may lead to use-after-free
		 * when we do not hold the last reference.
		 */
		const bool composite = !!(MEXT_FLAGS(m) & EXTF_COMPOSITE);
		VERIFY(!(MEXT_FLAGS(m) & EXTF_PAIRED) && MEXT_PMBUF(m) == NULL);
		const m_ext_free_func_t m_free_func = m_get_ext_free(m);
		const uint16_t minref = MEXT_MINREF(m);
		const uint16_t refcnt = m_decref(m);

		if (refcnt == minref && !composite) {
			if (m_free_func == NULL) {
				mz_cl_free(ZONE_ID_CLUSTER_2K, m->m_ext.ext_buf);
			} else if (m_free_func == m_bigfree) {
				mz_cl_free(ZONE_ID_CLUSTER_4K, m->m_ext.ext_buf);
			} else if (m_free_func == m_16kfree) {
				mz_cl_free(ZONE_ID_CLUSTER_16K, m->m_ext.ext_buf);
			} else {
				(*m_free_func)(m->m_ext.ext_buf,
				    m->m_ext.ext_size, m_get_ext_arg(m));
			}
			/* Re-use the reference structure */
			rfa = m_get_rfa(m);
		} else if (refcnt == minref && composite) {
			VERIFY(m->m_type != MT_FREE);

			mtype_stat_dec(m->m_type);
			mtype_stat_inc(MT_FREE);

			m->m_type = MT_FREE;
			m->m_flags = M_EXT;
			m->m_len = 0;
			m->m_next = m->m_nextpkt = NULL;

			/*
			 * MEXT_FLAGS is safe to access here
			 * since we are now sure that we held
			 * the last reference to ext_ref.
			 */
			MEXT_FLAGS(m) &= ~EXTF_READONLY;

			/* "Free" into the intermediate cache */
			if (m_free_func == NULL) {
				mz_composite_free(MC_MBUF_CL, m);
			} else if (m_free_func == m_bigfree) {
				mz_composite_free(MC_MBUF_BIGCL, m);
			} else {
				VERIFY(m_free_func == m_16kfree);
				mz_composite_free(MC_MBUF_16KCL, m);
			}
			/*
			 * Allocate a new mbuf, since we didn't divorce
			 * the composite mbuf + cluster pair above.
			 */
			if ((m = _M_GETHDR(wait, type)) == NULL) {
				return NULL;
			}
		}
	}

	if (rfa == NULL &&
	    (rfa = mz_ref_alloc(wait)) == NULL) {
		m_free(m);
		return NULL;
	}

	if (!pair) {
		mext_init(m, extbuf, extsize, extfree, extarg, rfa,
		    0, 1, 0, 0, 0, NULL);
	} else {
		mext_init(m, extbuf, extsize, extfree, (caddr_t)m, rfa,
		    1, 1, 1, EXTF_PAIRED, 0, m);
	}

	return m;
}

/*
 * Perform `fast' allocation mbuf clusters from a cache of recently-freed
 * clusters. (If the cache is empty, new clusters are allocated en-masse.)
 */
struct mbuf *
m_getcl(int wait, int type, int flags)
{
	struct mbuf *m = NULL;
	int hdr = (flags & M_PKTHDR);

	m = mz_composite_alloc(MC_MBUF_CL, wait);
	if (m != NULL) {
		u_int16_t flag;
		struct ext_ref *rfa;
		void *cl;

		VERIFY(m->m_type == MT_FREE && m->m_flags == M_EXT);
		cl = m->m_ext.ext_buf;
		rfa = m_get_rfa(m);

		ASSERT(cl != NULL && rfa != NULL);
		VERIFY(MBUF_IS_COMPOSITE(m) && m_get_ext_free(m) == NULL);

		flag = MEXT_FLAGS(m);

		mbuf_init(m, hdr, type);
		MBUF_CL_INIT(m, cl, rfa, 1, flag);

		mtype_stat_inc(type);
		mtype_stat_dec(MT_FREE);
	}
	return m;
}

/* m_mclget() add an mbuf cluster to a normal mbuf */
struct mbuf *
m_mclget(struct mbuf *m, int wait)
{
	struct ext_ref *rfa = NULL;
	char *bytes = NULL;

	if ((rfa = mz_ref_alloc(wait)) == NULL) {
		return m;
	}

	if ((bytes = m_mclalloc(wait)) != NULL) {
		m->m_ext.ext_size = MCLBYTES;
		m->m_ext.ext_buf = bytes;
		MBUF_CL_INIT(m, m->m_ext.ext_buf, rfa, 1, 0);
	} else {
		m->m_ext.ext_size = 0;
		m->m_ext.ext_buf = NULL;
		mz_ref_free(rfa);
	}

	return m;
}

/* Allocate an mbuf cluster */
char *
__sized_by_or_null(MCLBYTES)
m_mclalloc(int wait)
{
	return mz_cl_alloc(ZONE_ID_CLUSTER_2K, wait);
}

/* Free an mbuf cluster */
void
m_mclfree(caddr_t p)
{
	mz_cl_free(ZONE_ID_CLUSTER_2K, p);
}
#endif /* !CONFIG_MBUF_MCACHE */

/*
 * mcl_hasreference() checks if a cluster of an mbuf is referenced by
 * another mbuf; see comments in m_incref() regarding EXTF_READONLY.
 */
int
m_mclhasreference(struct mbuf *m)
{
	if (!(m->m_flags & M_EXT)) {
		return 0;
	}

	ASSERT(m_get_rfa(m) != NULL);

	return (MEXT_FLAGS(m) & EXTF_READONLY) ? 1 : 0;
}

#if !CONFIG_MBUF_MCACHE
__private_extern__ char *
__sized_by_or_null(MBIGCLBYTES)
m_bigalloc(int wait)
{
	return mz_cl_alloc(ZONE_ID_CLUSTER_4K, wait);
}

__private_extern__ void
m_bigfree(caddr_t p, __unused u_int size, __unused caddr_t arg)
{
	mz_cl_free(ZONE_ID_CLUSTER_4K, p);
}

/* m_mbigget() add an 4KB mbuf cluster to a normal mbuf */
__private_extern__ struct mbuf *
m_mbigget(struct mbuf *m, int wait)
{
	struct ext_ref *rfa = NULL;
	void * bytes = NULL;

	if ((rfa = mz_ref_alloc(wait)) == NULL) {
		return m;
	}

	if ((bytes = m_bigalloc(wait)) != NULL) {
		m->m_ext.ext_size = MBIGCLBYTES;
		m->m_ext.ext_buf = bytes;
		MBUF_BIGCL_INIT(m, m->m_ext.ext_buf, rfa, 1, 0);
	} else {
		m->m_ext.ext_size = 0;
		m->m_ext.ext_buf = NULL;
		mz_ref_free(rfa);
	}

	return m;
}

__private_extern__ char *
__sized_by_or_null(M16KCLBYTES)
m_16kalloc(int wait)
{
	return mz_cl_alloc(ZONE_ID_CLUSTER_16K, wait);
}

__private_extern__ void
m_16kfree(caddr_t p, __unused u_int size, __unused caddr_t arg)
{
	mz_cl_free(ZONE_ID_CLUSTER_16K, p);
}

/* m_m16kget() add a 16KB mbuf cluster to a normal mbuf */
__private_extern__ struct mbuf *
m_m16kget(struct mbuf *m, int wait)
{
	struct ext_ref *rfa = NULL;
	void *bytes = NULL;

	if ((rfa = mz_ref_alloc(wait)) == NULL) {
		return m;
	}

	if ((bytes = m_16kalloc(wait)) != NULL) {
		m->m_ext.ext_size = M16KCLBYTES;
		m->m_ext.ext_buf = bytes;
		MBUF_16KCL_INIT(m, m->m_ext.ext_buf, rfa, 1, 0);
	} else {
		m->m_ext.ext_size = 0;
		m->m_ext.ext_buf = NULL;
		mz_ref_free(rfa);
	}

	return m;
}
#endif /* !CONFIG_MBUF_MCACHE */

/*
 * "Move" mbuf pkthdr from "from" to "to".
 * "from" must have M_PKTHDR set, and "to" must be empty.
 */
void
m_copy_pkthdr(struct mbuf *to, struct mbuf *from)
{
	VERIFY(from->m_flags & M_PKTHDR);

	if (to->m_flags & M_PKTHDR) {
		/* We will be taking over the tags of 'to' */
		m_tag_delete_chain(to);
	}
	to->m_pkthdr = from->m_pkthdr;          /* especially tags */
	m_classifier_init(from, 0);             /* purge classifier info */
	m_tag_init(from, 1);                    /* purge all tags from src */
	m_scratch_init(from);                   /* clear src scratch area */
	to->m_flags = (from->m_flags & M_COPYFLAGS) | (to->m_flags & M_EXT);
	if ((to->m_flags & M_EXT) == 0) {
		to->m_data = (uintptr_t)to->m_pktdat;
	}
}

/*
 * Duplicate "from"'s mbuf pkthdr in "to".
 * "from" must have M_PKTHDR set, and "to" must be empty.
 * In particular, this does a deep copy of the packet tags.
 */
int
m_dup_pkthdr(struct mbuf *to, struct mbuf *from, int how)
{
	VERIFY(from->m_flags & M_PKTHDR);

	if (to->m_flags & M_PKTHDR) {
		/* We will be taking over the tags of 'to' */
		m_tag_delete_chain(to);
	}
	to->m_flags = (from->m_flags & M_COPYFLAGS) | (to->m_flags & M_EXT);
	if ((to->m_flags & M_EXT) == 0) {
		to->m_data = (uintptr_t)to->m_pktdat;
	}
	to->m_pkthdr = from->m_pkthdr;
	/* clear TX completion flag so the callback is not called in the copy */
	to->m_pkthdr.pkt_flags &= ~PKTF_TX_COMPL_TS_REQ;
	m_tag_init(to, 0);                      /* preserve dst static tags */
	return m_tag_copy_chain(to, from, how);
}

void
m_copy_pftag(struct mbuf *to, struct mbuf *from)
{
	memcpy(m_pftag(to), m_pftag(from), sizeof(struct pf_mtag));
#if PF_ECN
	m_pftag(to)->pftag_hdr = NULL;
	m_pftag(to)->pftag_flags &= ~(PF_TAG_HDR_INET | PF_TAG_HDR_INET6);
#endif /* PF_ECN */
}

void
m_copy_necptag(struct mbuf *to, struct mbuf *from)
{
	memcpy(m_necptag(to), m_necptag(from), sizeof(struct necp_mtag_));
}

void
m_classifier_init(struct mbuf *m, uint32_t pktf_mask)
{
	VERIFY(m->m_flags & M_PKTHDR);

	m->m_pkthdr.pkt_proto = 0;
	m->m_pkthdr.pkt_flowsrc = 0;
	m->m_pkthdr.pkt_flowid = 0;
	m->m_pkthdr.pkt_ext_flags = 0;
	m->m_pkthdr.pkt_flags &= pktf_mask;     /* caller-defined mask */
	/* preserve service class and interface info for loopback packets */
	if (!(m->m_pkthdr.pkt_flags & PKTF_LOOP)) {
		(void) m_set_service_class(m, MBUF_SC_BE);
	}
	if (!(m->m_pkthdr.pkt_flags & PKTF_IFAINFO)) {
		m->m_pkthdr.pkt_ifainfo = 0;
	}
	/*
	 * Preserve timestamp if requested
	 */
	if (!(m->m_pkthdr.pkt_flags & PKTF_TS_VALID)) {
		m->m_pkthdr.pkt_timestamp = 0;
	}
}

void
m_copy_classifier(struct mbuf *to, struct mbuf *from)
{
	VERIFY(to->m_flags & M_PKTHDR);
	VERIFY(from->m_flags & M_PKTHDR);

	to->m_pkthdr.pkt_proto = from->m_pkthdr.pkt_proto;
	to->m_pkthdr.pkt_flowsrc = from->m_pkthdr.pkt_flowsrc;
	to->m_pkthdr.pkt_flowid = from->m_pkthdr.pkt_flowid;
	to->m_pkthdr.pkt_mpriv_srcid = from->m_pkthdr.pkt_mpriv_srcid;
	to->m_pkthdr.pkt_flags = from->m_pkthdr.pkt_flags;
	to->m_pkthdr.pkt_ext_flags = from->m_pkthdr.pkt_ext_flags;
	(void) m_set_service_class(to, from->m_pkthdr.pkt_svc);
	to->m_pkthdr.pkt_ifainfo  = from->m_pkthdr.pkt_ifainfo;
}

#if !CONFIG_MBUF_MCACHE
/*
 * Return a list of mbuf hdrs that point to clusters.  Try for num_needed;
 * if wantall is not set, return whatever number were available.  Set up the
 * first num_with_pkthdrs with mbuf hdrs configured as packet headers; these
 * are chained on the m_nextpkt field.  Any packets requested beyond this
 * are chained onto the last packet header's m_next field.  The size of
 * the cluster is controlled by the parameter bufsize.
 */
__private_extern__ struct mbuf *
m_getpackets_internal(unsigned int *num_needed, int num_with_pkthdrs,
    int wait, int wantall, size_t bufsize)
{
	mbuf_ref_t m = NULL;
	mbuf_ref_t *np, top;
	unsigned int pnum, needed = *num_needed;
	zstack_t mp_list = {};
	mbuf_class_t class = MC_MBUF_CL;
	u_int16_t flag;
	struct ext_ref *rfa;
	void *cl;

	ASSERT(bufsize == m_maxsize(MC_CL) ||
	    bufsize == m_maxsize(MC_BIGCL) ||
	    bufsize == m_maxsize(MC_16KCL));

	top = NULL;
	np = &top;
	pnum = 0;

	/*
	 * The caller doesn't want all the requested buffers; only some.
	 * Try hard to get what we can, but don't block.  This effectively
	 * overrides MCR_SLEEP, since this thread will not go to sleep
	 * if we can't get all the buffers.
	 */
	if (!wantall || (wait & Z_NOWAIT)) {
		wait &= ~Z_NOWAIT;
		wait |= Z_NOPAGEWAIT;
	}

	/* Allocate the composite mbuf + cluster elements from the cache */
	if (bufsize == m_maxsize(MC_CL)) {
		class = MC_MBUF_CL;
	} else if (bufsize == m_maxsize(MC_BIGCL)) {
		class = MC_MBUF_BIGCL;
	} else {
		class = MC_MBUF_16KCL;
	}
	mp_list = mz_composite_alloc_n(class, needed, wait);
	needed = zstack_count(mp_list);

	for (pnum = 0; pnum < needed; pnum++) {
		m = zstack_pop(&mp_list);

		VERIFY(m->m_type == MT_FREE && m->m_flags == M_EXT);
		cl = m->m_ext.ext_buf;
		rfa = m_get_rfa(m);

		ASSERT(cl != NULL && rfa != NULL);
		VERIFY(MBUF_IS_COMPOSITE(m));

		flag = MEXT_FLAGS(m);

		mbuf_init(m, num_with_pkthdrs, MT_DATA);
		if (bufsize == m_maxsize(MC_16KCL)) {
			MBUF_16KCL_INIT(m, cl, rfa, 1, flag);
		} else if (bufsize == m_maxsize(MC_BIGCL)) {
			MBUF_BIGCL_INIT(m, cl, rfa, 1, flag);
		} else {
			MBUF_CL_INIT(m, cl, rfa, 1, flag);
		}

		if (num_with_pkthdrs > 0) {
			--num_with_pkthdrs;
		}

		*np = m;
		if (num_with_pkthdrs > 0) {
			np = &m->m_nextpkt;
		} else {
			np = &m->m_next;
		}
	}
	ASSERT(pnum != *num_needed || zstack_empty(mp_list));
	if (!zstack_empty(mp_list)) {
		mz_composite_free_n(class, mp_list);
	}
	if (pnum > 0) {
		mtype_stat_add(MT_DATA, pnum);
		mtype_stat_sub(MT_FREE, pnum);
	}

	if (wantall && (pnum != *num_needed)) {
		if (top != NULL) {
			m_freem_list(top);
		}
		return NULL;
	}

	if (pnum > *num_needed) {
		printf("%s: File a radar related to <rdar://10146739>. \
			needed = %u, pnum = %u, num_needed = %u \n",
		    __func__, needed, pnum, *num_needed);
	}
	*num_needed = pnum;

	return top;
}

/*
 * Return list of mbuf linked by m_nextpkt.  Try for numlist, and if
 * wantall is not set, return whatever number were available.  The size of
 * each mbuf in the list is controlled by the parameter packetlen.  Each
 * mbuf of the list may have a chain of mbufs linked by m_next.  Each mbuf
 * in the chain is called a segment.  If maxsegments is not null and the
 * value pointed to is not null, this specify the maximum number of segments
 * for a chain of mbufs.  If maxsegments is zero or the value pointed to
 * is zero the caller does not have any restriction on the number of segments.
 * The actual  number of segments of a mbuf chain is return in the value
 * pointed to by maxsegments.
 */
__private_extern__ struct mbuf *
m_allocpacket_internal(unsigned int *numlist, size_t packetlen,
    unsigned int *maxsegments, int wait, int wantall, size_t wantsize)
{
	mbuf_ref_t *np, top, first = NULL;
	size_t bufsize, r_bufsize;
	unsigned int num = 0;
	unsigned int nsegs = 0;
	unsigned int needed = 0, resid;
	zstack_t mp_list = {}, rmp_list = {};
	mbuf_class_t class = MC_MBUF, rclass = MC_MBUF_CL;

	if (*numlist == 0) {
		os_log(OS_LOG_DEFAULT, "m_allocpacket_internal *numlist is 0");
		return NULL;
	}

	top = NULL;
	np = &top;

	if (wantsize == 0) {
		if (packetlen <= MINCLSIZE) {
			bufsize = packetlen;
		} else if (packetlen > m_maxsize(MC_CL)) {
			/* Use 4KB if jumbo cluster pool isn't available */
			if (packetlen <= m_maxsize(MC_BIGCL)) {
				bufsize = m_maxsize(MC_BIGCL);
			} else {
				bufsize = m_maxsize(MC_16KCL);
			}
		} else {
			bufsize = m_maxsize(MC_CL);
		}
	} else if (wantsize == m_maxsize(MC_CL) ||
	    wantsize == m_maxsize(MC_BIGCL) ||
	    (wantsize == m_maxsize(MC_16KCL))) {
		bufsize = wantsize;
	} else {
		*numlist = 0;
		os_log(OS_LOG_DEFAULT, "m_allocpacket_internal wantsize unsupported");
		return NULL;
	}

	if (bufsize <= MHLEN) {
		nsegs = 1;
	} else if (bufsize <= MINCLSIZE) {
		if (maxsegments != NULL && *maxsegments == 1) {
			bufsize = m_maxsize(MC_CL);
			nsegs = 1;
		} else {
			nsegs = 2;
		}
	} else if (bufsize == m_maxsize(MC_16KCL)) {
		nsegs = ((packetlen - 1) >> M16KCLSHIFT) + 1;
	} else if (bufsize == m_maxsize(MC_BIGCL)) {
		nsegs = ((packetlen - 1) >> MBIGCLSHIFT) + 1;
	} else {
		nsegs = ((packetlen - 1) >> MCLSHIFT) + 1;
	}
	if (maxsegments != NULL) {
		if (*maxsegments && nsegs > *maxsegments) {
			*maxsegments = nsegs;
			*numlist = 0;
			os_log(OS_LOG_DEFAULT, "m_allocpacket_internal nsegs > *maxsegments");
			return NULL;
		}
		*maxsegments = nsegs;
	}

	/*
	 * The caller doesn't want all the requested buffers; only some.
	 * Try hard to get what we can, but don't block.  This effectively
	 * overrides MCR_SLEEP, since this thread will not go to sleep
	 * if we can't get all the buffers.
	 */
	if (!wantall || (wait & Z_NOWAIT)) {
		wait &= ~Z_NOWAIT;
		wait |= Z_NOPAGEWAIT;
	}

	/*
	 * Simple case where all elements in the lists/chains are mbufs.
	 * Unless bufsize is greater than MHLEN, each segment chain is made
	 * up of exactly 1 mbuf.  Otherwise, each segment chain is made up
	 * of 2 mbufs; the second one is used for the residual data, i.e.
	 * the remaining data that cannot fit into the first mbuf.
	 */
	if (bufsize <= MINCLSIZE) {
		/* Allocate the elements in one shot from the mbuf cache */
		ASSERT(bufsize <= MHLEN || nsegs == 2);
		class = MC_MBUF;
		mp_list = mz_alloc_n((*numlist) * nsegs, wait);
		needed = zstack_count(mp_list);

		/*
		 * The number of elements must be even if we are to use an
		 * mbuf (instead of a cluster) to store the residual data.
		 * If we couldn't allocate the requested number of mbufs,
		 * trim the number down (if it's odd) in order to avoid
		 * creating a partial segment chain.
		 */
		if (bufsize > MHLEN && (needed & 0x1)) {
			needed--;
		}

		while (num < needed) {
			mbuf_ref_t m = NULL;

			m = zstack_pop(&mp_list);
			ASSERT(m != NULL);

			mbuf_init(m, 1, MT_DATA);
			num++;
			if (bufsize > MHLEN) {
				/* A second mbuf for this segment chain */
				m->m_next = zstack_pop(&mp_list);

				ASSERT(m->m_next != NULL);

				mbuf_init(m->m_next, 0, MT_DATA);
				num++;
			}
			*np = m;
			np = &m->m_nextpkt;
		}
		ASSERT(num != *numlist || zstack_empty(mp_list));

		if (num > 0) {
			mtype_stat_add(MT_DATA, num);
			mtype_stat_sub(MT_FREE, num);
		}
		num /= nsegs;

		/* We've got them all; return to caller */
		if (num == *numlist) {
			return top;
		}

		goto fail;
	}

	/*
	 * Complex cases where elements are made up of one or more composite
	 * mbufs + cluster, depending on packetlen.  Each N-segment chain can
	 * be illustrated as follows:
	 *
	 * [mbuf + cluster 1] [mbuf + cluster 2] ... [mbuf + cluster N]
	 *
	 * Every composite mbuf + cluster element comes from the intermediate
	 * cache (either MC_MBUF_CL or MC_MBUF_BIGCL).  For space efficiency,
	 * the last composite element will come from the MC_MBUF_CL cache,
	 * unless the residual data is larger than 2KB where we use the
	 * big cluster composite cache (MC_MBUF_BIGCL) instead.  Residual
	 * data is defined as extra data beyond the first element that cannot
	 * fit into the previous element, i.e. there is no residual data if
	 * the chain only has 1 segment.
	 */
	r_bufsize = bufsize;
	resid = packetlen > bufsize ? packetlen % bufsize : 0;
	if (resid > 0) {
		/* There is residual data; figure out the cluster size */
		if (wantsize == 0 && packetlen > MINCLSIZE) {
			/*
			 * Caller didn't request that all of the segments
			 * in the chain use the same cluster size; use the
			 * smaller of the cluster sizes.
			 */
			if (resid > m_maxsize(MC_BIGCL)) {
				r_bufsize = m_maxsize(MC_16KCL);
			} else if (resid > m_maxsize(MC_CL)) {
				r_bufsize = m_maxsize(MC_BIGCL);
			} else {
				r_bufsize = m_maxsize(MC_CL);
			}
		} else {
			/* Use the same cluster size as the other segments */
			resid = 0;
		}
	}

	needed = *numlist;
	if (resid > 0) {
		/*
		 * Attempt to allocate composite mbuf + cluster elements for
		 * the residual data in each chain; record the number of such
		 * elements that can be allocated so that we know how many
		 * segment chains we can afford to create.
		 */
		if (r_bufsize <= m_maxsize(MC_CL)) {
			rclass = MC_MBUF_CL;
		} else if (r_bufsize <= m_maxsize(MC_BIGCL)) {
			rclass = MC_MBUF_BIGCL;
		} else {
			rclass = MC_MBUF_16KCL;
		}
		rmp_list = mz_composite_alloc_n(rclass, *numlist, wait);
		needed = zstack_count(rmp_list);
		if (needed == 0) {
			goto fail;
		}

		/* This is temporarily reduced for calculation */
		ASSERT(nsegs > 1);
		nsegs--;
	}

	/*
	 * Attempt to allocate the rest of the composite mbuf + cluster
	 * elements for the number of segment chains that we need.
	 */
	if (bufsize <= m_maxsize(MC_CL)) {
		class = MC_MBUF_CL;
	} else if (bufsize <= m_maxsize(MC_BIGCL)) {
		class = MC_MBUF_BIGCL;
	} else {
		class = MC_MBUF_16KCL;
	}
	mp_list = mz_composite_alloc_n(class, needed * nsegs, wait);
	needed = zstack_count(mp_list);

	/* Round it down to avoid creating a partial segment chain */
	needed = (needed / nsegs) * nsegs;
	if (needed == 0) {
		goto fail;
	}

	if (resid > 0) {
		/*
		 * We're about to construct the chain(s); take into account
		 * the number of segments we have created above to hold the
		 * residual data for each chain, as well as restore the
		 * original count of segments per chain.
		 */
		ASSERT(nsegs > 0);
		needed += needed / nsegs;
		nsegs++;
	}

	for (;;) {
		mbuf_ref_t m = NULL;
		u_int16_t flag;
		struct ext_ref *rfa;
		void *cl;
		int pkthdr;
		m_ext_free_func_t m_free_func;

		++num;

		if (nsegs == 1 || (num % nsegs) != 0 || resid == 0) {
			m = zstack_pop(&mp_list);
		} else {
			m = zstack_pop(&rmp_list);
		}
		m_free_func = m_get_ext_free(m);
		ASSERT(m != NULL);
		VERIFY(m->m_type == MT_FREE && m->m_flags == M_EXT);
		VERIFY(m_free_func == NULL || m_free_func == m_bigfree ||
		    m_free_func == m_16kfree);

		cl = m->m_ext.ext_buf;
		rfa = m_get_rfa(m);

		ASSERT(cl != NULL && rfa != NULL);
		VERIFY(MBUF_IS_COMPOSITE(m));

		flag = MEXT_FLAGS(m);

		pkthdr = (nsegs == 1 || (num % nsegs) == 1);
		if (pkthdr) {
			first = m;
		}
		mbuf_init(m, pkthdr, MT_DATA);
		if (m_free_func == m_16kfree) {
			MBUF_16KCL_INIT(m, cl, rfa, 1, flag);
		} else if (m_free_func == m_bigfree) {
			MBUF_BIGCL_INIT(m, cl, rfa, 1, flag);
		} else {
			MBUF_CL_INIT(m, cl, rfa, 1, flag);
		}

		*np = m;
		if ((num % nsegs) == 0) {
			np = &first->m_nextpkt;
		} else {
			np = &m->m_next;
		}

		if (num == needed) {
			break;
		}
	}

	if (num > 0) {
		mtype_stat_add(MT_DATA, num);
		mtype_stat_sub(MT_FREE, num);
	}

	num /= nsegs;

	/* We've got them all; return to caller */
	if (num == *numlist) {
		ASSERT(zstack_empty(mp_list) && zstack_empty(rmp_list));
		return top;
	}

fail:
	/* Free up what's left of the above */
	if (!zstack_empty(mp_list)) {
		if (class == MC_MBUF) {
			/* No need to elide, these mbufs came from the cache. */
			mz_free_n(mp_list);
		} else {
			mz_composite_free_n(class, mp_list);
		}
	}
	if (!zstack_empty(rmp_list)) {
		mz_composite_free_n(rclass, rmp_list);
	}
	if (wantall && top != NULL) {
		m_freem_list(top);
		*numlist = 0;
		return NULL;
	}
	*numlist = num;
	return top;
}
#endif /* !CONFIG_MBUF_MCACHE */

/*
 * Best effort to get a mbuf cluster + pkthdr.  Used by drivers to allocated
 * packets on receive ring.
 */
__private_extern__ struct mbuf *
m_getpacket_how(int wait)
{
	unsigned int num_needed = 1;

	return m_getpackets_internal(&num_needed, 1, wait, 1,
	           m_maxsize(MC_CL));
}

/*
 * Best effort to get a mbuf cluster + pkthdr.  Used by drivers to allocated
 * packets on receive ring.
 */
struct mbuf *
m_getpacket(void)
{
	unsigned int num_needed = 1;

	return m_getpackets_internal(&num_needed, 1, M_WAIT, 1,
	           m_maxsize(MC_CL));
}

/*
 * Return a list of mbuf hdrs that point to clusters.  Try for num_needed;
 * if this can't be met, return whatever number were available.  Set up the
 * first num_with_pkthdrs with mbuf hdrs configured as packet headers.  These
 * are chained on the m_nextpkt field.  Any packets requested beyond this are
 * chained onto the last packet header's m_next field.
 */
struct mbuf *
m_getpackets(int num_needed, int num_with_pkthdrs, int how)
{
	unsigned int n = num_needed;

	return m_getpackets_internal(&n, num_with_pkthdrs, how, 0,
	           m_maxsize(MC_CL));
}

/*
 * Return a list of mbuf hdrs set up as packet hdrs chained together
 * on the m_nextpkt field
 */
struct mbuf *
m_getpackethdrs(int num_needed, int how)
{
	mbuf_ref_t m, *np, top;

	top = NULL;
	np = &top;

	while (num_needed--) {
		m = _M_RETRYHDR(how, MT_DATA);
		if (m == NULL) {
			break;
		}

		*np = m;
		np = &m->m_nextpkt;
	}

	return top;
}

#if !CONFIG_MBUF_MCACHE
/*
 * Free an mbuf list (m_nextpkt) while following m_next.  Returns the count
 * for mbufs packets freed.  Used by the drivers.
 */
int
m_freem_list(struct mbuf *m)
{
	struct mbuf *nextpkt;
	zstack_t mp_list = {}, mcl_list = {}, mbc_list = {},
	    m16k_list = {}, m_mcl_list = {},
	    m_mbc_list = {}, m_m16k_list = {}, ref_list = {};
	int pktcount = 0;
	int mt_free = 0, mt_data = 0, mt_header = 0, mt_soname = 0, mt_tag = 0;

	while (m != NULL) {
		pktcount++;

		nextpkt = m->m_nextpkt;
		m->m_nextpkt = NULL;

		while (m != NULL) {
			struct mbuf *next = m->m_next;
			void *cl = NULL;
			if (m->m_type == MT_FREE) {
				panic("m_free: freeing an already freed mbuf");
			}

			if (m->m_flags & M_PKTHDR) {
				/* Free the aux data and tags if there is any */
				m_tag_delete_chain(m);
				m_do_tx_compl_callback(m, NULL);
			}

			if (!(m->m_flags & M_EXT)) {
				mt_free++;
				goto simple_free;
			}

			if (MBUF_IS_PAIRED(m) && m_free_paired(m)) {
				m = next;
				continue;
			}

			mt_free++;

			cl = m->m_ext.ext_buf;
			/*
			 * Make sure that we don't touch any ext_ref
			 * member after we decrement the reference count
			 * since that may lead to use-after-free
			 * when we do not hold the last reference.
			 */
			const bool composite = !!(MEXT_FLAGS(m) & EXTF_COMPOSITE);
			const m_ext_free_func_t m_free_func = m_get_ext_free(m);
			const uint16_t minref = MEXT_MINREF(m);
			const uint16_t refcnt = m_decref(m);
			if (refcnt == minref && !composite) {
				if (m_free_func == NULL) {
					zstack_push(&mcl_list, cl);
				} else if (m_free_func == m_bigfree) {
					zstack_push(&mbc_list, cl);
				} else if (m_free_func == m_16kfree) {
					zstack_push(&m16k_list, cl);
				} else {
					(*(m_free_func))((caddr_t)cl,
					    m->m_ext.ext_size,
					    m_get_ext_arg(m));
				}
				zstack_push(&ref_list, m_get_rfa(m));
				m_set_ext(m, NULL, NULL, NULL);
			} else if (refcnt == minref && composite) {
				VERIFY(!(MEXT_FLAGS(m) & EXTF_PAIRED));
				/*
				 * Amortize the costs of atomic operations
				 * by doing them at the end, if possible.
				 */
				if (m->m_type == MT_DATA) {
					mt_data++;
				} else if (m->m_type == MT_HEADER) {
					mt_header++;
				} else if (m->m_type == MT_SONAME) {
					mt_soname++;
				} else if (m->m_type == MT_TAG) {
					mt_tag++;
				} else {
					mtype_stat_dec(m->m_type);
				}

				m->m_type = MT_FREE;
				m->m_flags = M_EXT;
				m->m_len = 0;
				m->m_next = m->m_nextpkt = NULL;

				/*
				 * MEXT_FLAGS is safe to access here
				 * since we are now sure that we held
				 * the last reference to ext_ref.
				 */
				MEXT_FLAGS(m) &= ~EXTF_READONLY;

				/* "Free" into the intermediate cache */
				if (m_free_func == NULL) {
					zstack_push(&m_mcl_list, m);
				} else if (m_free_func == m_bigfree) {
					zstack_push(&m_mbc_list, m);
				} else {
					VERIFY(m_free_func == m_16kfree);
					zstack_push(&m_m16k_list, m);
				}
				m = next;
				continue;
			}
simple_free:
			/*
			 * Amortize the costs of atomic operations
			 * by doing them at the end, if possible.
			 */
			if (m->m_type == MT_DATA) {
				mt_data++;
			} else if (m->m_type == MT_HEADER) {
				mt_header++;
			} else if (m->m_type == MT_SONAME) {
				mt_soname++;
			} else if (m->m_type == MT_TAG) {
				mt_tag++;
			} else if (m->m_type != MT_FREE) {
				mtype_stat_dec(m->m_type);
			}

			m->m_type = MT_FREE;
			m->m_flags = m->m_len = 0;
			m->m_next = m->m_nextpkt = NULL;

			m_elide(m);
			zstack_push(&mp_list, m);

			m = next;
		}

		m = nextpkt;
	}

	if (mt_free > 0) {
		mtype_stat_add(MT_FREE, mt_free);
	}
	if (mt_data > 0) {
		mtype_stat_sub(MT_DATA, mt_data);
	}
	if (mt_header > 0) {
		mtype_stat_sub(MT_HEADER, mt_header);
	}
	if (mt_soname > 0) {
		mtype_stat_sub(MT_SONAME, mt_soname);
	}
	if (mt_tag > 0) {
		mtype_stat_sub(MT_TAG, mt_tag);
	}
	if (!zstack_empty(mp_list)) {
		/* mbufs elided above. */
		mz_free_n(mp_list);
	}
	if (!zstack_empty(mcl_list)) {
		zfree_nozero_n(ZONE_ID_CLUSTER_2K, mcl_list);
	}
	if (!zstack_empty(mbc_list)) {
		zfree_nozero_n(ZONE_ID_CLUSTER_4K, mbc_list);
	}
	if (!zstack_empty(m16k_list)) {
		zfree_nozero_n(ZONE_ID_CLUSTER_16K, m16k_list);
	}
	if (!zstack_empty(m_mcl_list)) {
		mz_composite_free_n(MC_MBUF_CL, m_mcl_list);
	}
	if (!zstack_empty(m_mbc_list)) {
		mz_composite_free_n(MC_MBUF_BIGCL, m_mbc_list);
	}
	if (!zstack_empty(m_m16k_list)) {
		mz_composite_free_n(MC_MBUF_16KCL, m_m16k_list);
	}
	if (!zstack_empty(ref_list)) {
		zfree_nozero_n(ZONE_ID_MBUF_REF, ref_list);
	}

	return pktcount;
}
#endif /* !CONFIG_MBUF_MCACHE */

/*
 * Wrapper around m_freem_list which captures the packet that's going to be
 * dropped. If funcname is NULL, that means we do not want to store both
 * function name and line number, and only the drop reason will be saved.
 * Make sure to pass the direction flag (DROPTAP_FLAG_DIR_OUT,
 * DROPTAP_FLAG_DIR_IN), or the packet will not be captured.
 */
void
m_drop_list(mbuf_t m_head, struct ifnet *ifp, uint16_t flags, uint32_t reason, const char *funcname,
    uint16_t linenum)
{
	struct mbuf *m = m_head;
	struct mbuf *nextpkt;

	if (m_head == NULL) {
		return;
	}

	if (__probable(droptap_total_tap_count == 0)) {
		m_freem_list(m_head);
		return;
	}

	if (flags & DROPTAP_FLAG_DIR_OUT) {
		while (m != NULL) {
			uint16_t tmp_flags = flags;

			nextpkt = m->m_nextpkt;
			if (m->m_pkthdr.pkt_hdr == NULL) {
				tmp_flags |= DROPTAP_FLAG_L2_MISSING;
			}
			droptap_output_mbuf(m, reason, funcname, linenum, tmp_flags,
			    ifp);
			m = nextpkt;
		}
	} else if (flags & DROPTAP_FLAG_DIR_IN) {
		while (m != NULL) {
			char *frame_header __single;
			uint16_t tmp_flags = flags;

			nextpkt = m->m_nextpkt;

			if ((flags & DROPTAP_FLAG_L2_MISSING) == 0 &&
			    m->m_pkthdr.pkt_hdr != NULL) {
				frame_header = m->m_pkthdr.pkt_hdr;
			} else {
				frame_header = NULL;
				tmp_flags |= DROPTAP_FLAG_L2_MISSING;
			}

			droptap_input_mbuf(m, reason, funcname, linenum, tmp_flags,
			    m->m_pkthdr.rcvif, frame_header);
			m = nextpkt;
		}
	}
	m_freem_list(m_head);
}

void
m_freem(struct mbuf *m)
{
	while (m != NULL) {
		m = m_free(m);
	}
}

/*
 * Wrapper around m_freem which captures the packet that's going to be dropped.
 * If funcname is NULL, that means we do not want to store both function name
 * and line number, and only the drop reason will be saved. Make sure to pass the
 * direction flag (DROPTAP_FLAG_DIR_OUT, DROPTAP_FLAG_DIR_IN), or the packet will
 * not be captured.
 */
static void
m_drop_common(mbuf_t m, struct ifnet *ifp, uint16_t flags, uint32_t reason, const char *funcname,
    uint16_t linenum)
{
	if (flags & DROPTAP_FLAG_DIR_OUT) {
		droptap_output_mbuf(m, reason, funcname, linenum, flags, ifp);
	} else if (flags & DROPTAP_FLAG_DIR_IN) {
		char *frame_header __single;

		if ((flags & DROPTAP_FLAG_L2_MISSING) == 0 &&
		    m->m_pkthdr.pkt_hdr != NULL) {
			frame_header = m->m_pkthdr.pkt_hdr;
		} else {
			frame_header = NULL;
			flags |= DROPTAP_FLAG_L2_MISSING;
		}

		droptap_input_mbuf(m, reason, funcname, linenum, flags, ifp,
		    frame_header);
	}
	m_freem(m);
}

void
m_drop(mbuf_t m, uint16_t flags, uint32_t reason, const char *funcname,
    uint16_t linenum)
{
	if (m == NULL) {
		return;
	}

	if (__probable(droptap_total_tap_count == 0)) {
		m_freem(m);
		return;
	}

	if (flags & DROPTAP_FLAG_DIR_OUT) {
		m_drop_common(m, NULL, flags, reason, funcname, linenum);
	} else if (flags & DROPTAP_FLAG_DIR_IN) {
		m_drop_common(m, m->m_pkthdr.rcvif, flags, reason, funcname, linenum);
	}
}

void
m_drop_if(mbuf_t m, struct ifnet *ifp, uint16_t flags, uint32_t reason, const char *funcname,
    uint16_t linenum)
{
	if (m == NULL) {
		return;
	}

	if (__probable(droptap_total_tap_count == 0)) {
		m_freem(m);
		return;
	}

	m_drop_common(m, ifp, flags, reason, funcname, linenum);
}

void
m_drop_extended(mbuf_t m, struct ifnet *ifp, char *frame_header,
    uint16_t flags, uint32_t reason, const char *funcname, uint16_t linenum)
{
	if (m == NULL) {
		return;
	}

	if (__probable(droptap_total_tap_count == 0)) {
		m_freem(m);
		return;
	}

	if (flags & DROPTAP_FLAG_DIR_OUT) {
		droptap_output_mbuf(m, reason, funcname, linenum, flags,
		    ifp);
	} else if (flags & DROPTAP_FLAG_DIR_IN) {
		droptap_input_mbuf(m, reason, funcname, linenum, flags,
		    m->m_pkthdr.rcvif, frame_header);
	}
	m_freem(m);
}

/*
 * Mbuffer utility routines.
 */
/*
 * Set the m_data pointer of a newly allocated mbuf to place an object of the
 * specified size at the end of the mbuf, longword aligned.
 *
 * NB: Historically, we had M_ALIGN(), MH_ALIGN(), and MEXT_ALIGN() as
 * separate macros, each asserting that it was called at the proper moment.
 * This required callers to themselves test the storage type and call the
 * right one.  Rather than require callers to be aware of those layout
 * decisions, we centralize here.
 */
void
m_align(struct mbuf *m, int len)
{
	int adjust = 0;

	/* At this point data must point to start */
	VERIFY(m->m_data == (uintptr_t)M_START(m));
	VERIFY(len >= 0);
	VERIFY(len <= M_SIZE(m));
	adjust = M_SIZE(m) - len;
	m->m_data += adjust & ~(sizeof(long) - 1);
}

/*
 * Lesser-used path for M_PREPEND: allocate new mbuf to prepend to chain,
 * copy junk along.  Does not adjust packet header length.
 */
struct mbuf *
m_prepend(struct mbuf *m, int len, int how)
{
	struct mbuf *mn;

	_MGET(mn, how, m->m_type);
	if (mn == NULL) {
		m_freem(m);
		return NULL;
	}
	if (m->m_flags & M_PKTHDR) {
		M_COPY_PKTHDR(mn, m);
		m->m_flags &= ~M_PKTHDR;
	}
	mn->m_next = m;
	m = mn;
	if (m->m_flags & M_PKTHDR) {
		VERIFY(len <= MHLEN);
		MH_ALIGN(m, len);
	} else {
		VERIFY(len <= MLEN);
		M_ALIGN(m, len);
	}
	m->m_len = len;
	return m;
}

/*
 * Replacement for old M_PREPEND macro: allocate new mbuf to prepend to
 * chain, copy junk along, and adjust length.
 */
struct mbuf *
m_prepend_2(struct mbuf *m, int len, int how, int align)
{
	if (M_LEADINGSPACE(m) >= len &&
	    (!align || IS_P2ALIGNED((m->m_data - len), sizeof(u_int32_t)))) {
		m->m_data -= len;
		m->m_len += len;
	} else {
		m = m_prepend(m, len, how);
	}
	if ((m) && (m->m_flags & M_PKTHDR)) {
		m->m_pkthdr.len += len;
	}
	return m;
}

/*
 * Make a copy of an mbuf chain starting "off0" bytes from the beginning,
 * continuing for "len" bytes.  If len is M_COPYALL, copy to end of mbuf.
 * The wait parameter is a choice of M_WAIT/M_DONTWAIT from caller.
 *
 * The last mbuf and offset accessed are passed in and adjusted on return to
 * avoid having to iterate over the entire mbuf chain each time.
 */
struct mbuf *
m_copym_mode(struct mbuf *m, int off0, int len0, int wait,
    struct mbuf **m_lastm, int *m_off, uint32_t mode)
{
	mbuf_ref_t n, mhdr = NULL, *np, top;
	int off = off0, len = len0;
	int copyhdr = 0;

	if (off < 0 || len < 0) {
		panic("m_copym: invalid offset %d or len %d", off, len);
	}

	VERIFY((mode != M_COPYM_MUST_COPY_HDR &&
	    mode != M_COPYM_MUST_MOVE_HDR) || (m->m_flags & M_PKTHDR));

	if ((off == 0 && (m->m_flags & M_PKTHDR)) ||
	    mode == M_COPYM_MUST_COPY_HDR || mode == M_COPYM_MUST_MOVE_HDR) {
		mhdr = m;
		copyhdr = 1;
	}

	if (m_lastm != NULL && *m_lastm != NULL) {
		if (off0 >= *m_off) {
			m = *m_lastm;
			off = off0 - *m_off;
		}
	}

	while (off >= m->m_len) {
		off -= m->m_len;
		m = m->m_next;
	}
	np = &top;
	top = NULL;

	while (len > 0) {
		if (m == NULL) {
			if (len != M_COPYALL) {
				panic("m_copym: len != M_COPYALL");
			}
			break;
		}

		if (copyhdr) {
			n = _M_RETRYHDR(wait, m->m_type);
		} else {
			n = _M_RETRY(wait, m->m_type);
		}
		*np = n;

		if (n == NULL) {
			goto nospace;
		}

		if (copyhdr != 0) {
			if ((mode == M_COPYM_MOVE_HDR) ||
			    (mode == M_COPYM_MUST_MOVE_HDR)) {
				M_COPY_PKTHDR(n, mhdr);
			} else if ((mode == M_COPYM_COPY_HDR) ||
			    (mode == M_COPYM_MUST_COPY_HDR)) {
				if (m_dup_pkthdr(n, mhdr, wait) == 0) {
					goto nospace;
				}
			}
			if (len == M_COPYALL) {
				n->m_pkthdr.len -= off0;
			} else {
				n->m_pkthdr.len = len;
			}
			copyhdr = 0;
			/*
			 * There is data to copy from the packet header mbuf
			 * if it is empty or it is before the starting offset
			 */
			if (mhdr != m) {
				np = &n->m_next;
				continue;
			}
		}
		n->m_len = MIN(len, (m->m_len - off));
		if (m->m_flags & M_EXT) {
			n->m_ext = m->m_ext;
			m_incref(m);
			n->m_data = m->m_data + off;
			n->m_flags |= M_EXT;
		} else {
			/*
			 * Limit to the capacity of the destination
			 */
			n->m_len = MIN(n->m_len, M_SIZE(n));

			if (m_mtod_end(n) > m_mtod_upper_bound(n)) {
				panic("%s n %p copy overflow",
				    __func__, n);
			}

			bcopy(mtod(m, caddr_t) + off, mtod(n, caddr_t),
			    (unsigned)n->m_len);
		}
		if (len != M_COPYALL) {
			len -= n->m_len;
		}

		if (len == 0) {
			if (m_lastm != NULL) {
				*m_lastm = m;
				*m_off = off0 + len0 - (off + n->m_len);
			}
		}
		off = 0;
		m = m->m_next;
		np = &n->m_next;
	}

	return top;
nospace:
	m_freem(top);

	return NULL;
}


struct mbuf *
m_copym(struct mbuf *m, int off0, int len, int wait)
{
	return m_copym_mode(m, off0, len, wait, NULL, NULL, M_COPYM_MOVE_HDR);
}

#if !CONFIG_MBUF_MCACHE
/*
 * Equivalent to m_copym except that all necessary mbuf hdrs are allocated
 * within this routine also.
 *
 * The last mbuf and offset accessed are passed in and adjusted on return to
 * avoid having to iterate over the entire mbuf chain each time.
 */
struct mbuf *
m_copym_with_hdrs(struct mbuf *m0, int off0, int len0, int wait,
    struct mbuf **m_lastm, int *m_off, uint32_t mode)
{
	mbuf_ref_t m = m0, n, *np = NULL, top = NULL;
	int off = off0, len = len0;
	zstack_t list = {};
	int copyhdr = 0;
	int type = 0;
	int needed = 0;

	if (off == 0 && (m->m_flags & M_PKTHDR)) {
		copyhdr = 1;
	}

	if (m_lastm != NULL && *m_lastm != NULL) {
		if (off0 >= *m_off) {
			m = *m_lastm;
			off = off0 - *m_off;
		}
	}

	while (off >= m->m_len) {
		off -= m->m_len;
		m = m->m_next;
	}

	n = m;
	while (len > 0) {
		needed++;
		len -= MIN(len, (n->m_len - ((needed == 1) ? off : 0)));
		n = n->m_next;
	}
	needed++;
	len = len0;

	list = mz_alloc_n(needed, wait);
	if (zstack_count(list) != needed) {
		goto nospace;
	}

	needed = 0;
	while (len > 0) {
		n = zstack_pop(&list);
		ASSERT(n != NULL && m != NULL);

		type = (top == NULL) ? MT_HEADER : m->m_type;
		mbuf_init(n, (top == NULL), type);

		if (top == NULL) {
			top = n;
			np = &top->m_next;
			continue;
		} else {
			needed++;
			*np = n;
		}

		if (copyhdr) {
			if ((mode == M_COPYM_MOVE_HDR) ||
			    (mode == M_COPYM_MUST_MOVE_HDR)) {
				M_COPY_PKTHDR(n, m);
			} else if ((mode == M_COPYM_COPY_HDR) ||
			    (mode == M_COPYM_MUST_COPY_HDR)) {
				if (m_dup_pkthdr(n, m, wait) == 0) {
					m_elide(n);
					goto nospace;
				}
			}
			n->m_pkthdr.len = len;
			copyhdr = 0;
		}
		n->m_len = MIN(len, (m->m_len - off));

		if (m->m_flags & M_EXT) {
			n->m_ext = m->m_ext;
			m_incref(m);
			n->m_data = m->m_data + off;
			n->m_flags |= M_EXT;
		} else {
			if (m_mtod_end(n) > m_mtod_upper_bound(n)) {
				panic("%s n %p copy overflow",
				    __func__, n);
			}

			bcopy(mtod(m, caddr_t) + off, mtod(n, caddr_t),
			    (unsigned)n->m_len);
		}
		len -= n->m_len;

		if (len == 0) {
			if (m_lastm != NULL) {
				*m_lastm = m;
				*m_off = off0 + len0 - (off + n->m_len);
			}
			break;
		}
		off = 0;
		m = m->m_next;
		np = &n->m_next;
	}

	mtype_stat_inc(MT_HEADER);
	mtype_stat_add(type, needed);
	mtype_stat_sub(MT_FREE, needed + 1);

	ASSERT(zstack_empty(list));

	return top;

nospace:
	if (!zstack_empty(list)) {
		/* No need to elide, these mbufs came from the cache. */
		mz_free_n(list);
	}
	if (top != NULL) {
		m_freem(top);
	}
	return NULL;
}
#endif /* !CONFIG_MBUF_MCACHE */

/*
 * Copy data from an mbuf chain starting "off" bytes from the beginning,
 * continuing for "len" bytes, into the indicated buffer.
 */
void
m_copydata(struct mbuf *m, int off, int len0, void *vp __sized_by(len0))
{
	int off0 = off, len = len0;
	struct mbuf *m0 = m;
	unsigned count;
	char *cp = vp;

	if (__improbable(off < 0 || len < 0)) {
		panic("%s: invalid offset %d or len %d", __func__, off, len);
		/* NOTREACHED */
	}

	while (off > 0) {
		if (__improbable(m == NULL)) {
			panic("%s: invalid mbuf chain %p [off %d, len %d]",
			    __func__, m0, off0, len0);
			/* NOTREACHED */
		}
		if (off < m->m_len) {
			break;
		}
		off -= m->m_len;
		m = m->m_next;
	}
	while (len > 0) {
		if (__improbable(m == NULL)) {
			panic("%s: invalid mbuf chain %p [off %d, len %d]",
			    __func__, m0, off0, len0);
			/* NOTREACHED */
		}
		count = MIN(m->m_len - off, len);
		bcopy(mtod(m, caddr_t) + off, cp, count);
		len -= count;
		cp += count;
		off = 0;
		m = m->m_next;
	}
}

/*
 * Concatenate mbuf chain n to m.  Both chains must be of the same type
 * (e.g. MT_DATA).  Any m_pkthdr is not updated.
 */
void
m_cat(struct mbuf *m, struct mbuf *n)
{
	while (m->m_next) {
		m = m->m_next;
	}
	while (n) {
		if ((m->m_flags & M_EXT) ||
		    m->m_data + m->m_len + n->m_len >= (uintptr_t)&m->m_dat[MLEN]) {
			/* just join the two chains */
			m->m_next = n;
			return;
		}
		/* splat the data from one into the other */
		bcopy(mtod(n, caddr_t), mtod(m, caddr_t) + m->m_len,
		    (u_int)n->m_len);
		m->m_len += n->m_len;
		n = m_free(n);
	}
}

void
m_adj(struct mbuf *mp, int req_len)
{
	int len = req_len;
	struct mbuf *m;
	int count;

	if ((m = mp) == NULL) {
		return;
	}
	if (len >= 0) {
		/*
		 * Trim from head.
		 */
		while (m != NULL && len > 0) {
			if (m->m_len <= len) {
				len -= m->m_len;
				m->m_len = 0;
				m = m->m_next;
			} else {
				m->m_len -= len;
				m->m_data += len;
				len = 0;
			}
		}
		m = mp;
		if (m->m_flags & M_PKTHDR) {
			m->m_pkthdr.len -= (req_len - len);
		}
	} else {
		/*
		 * Trim from tail.  Scan the mbuf chain,
		 * calculating its length and finding the last mbuf.
		 * If the adjustment only affects this mbuf, then just
		 * adjust and return.  Otherwise, rescan and truncate
		 * after the remaining size.
		 */
		len = -len;
		count = 0;
		for (;;) {
			count += m->m_len;
			if (m->m_next == NULL) {
				break;
			}
			m = m->m_next;
		}
		if (m->m_len >= len) {
			m->m_len -= len;
			m = mp;
			if (m->m_flags & M_PKTHDR) {
				m->m_pkthdr.len -= len;
			}
			return;
		}
		count -= len;
		if (count < 0) {
			count = 0;
		}
		/*
		 * Correct length for chain is "count".
		 * Find the mbuf with last data, adjust its length,
		 * and toss data from remaining mbufs on chain.
		 */
		m = mp;
		if (m->m_flags & M_PKTHDR) {
			m->m_pkthdr.len = count;
		}
		for (; m; m = m->m_next) {
			if (m->m_len >= count) {
				m->m_len = count;
				break;
			}
			count -= m->m_len;
		}
		while ((m = m->m_next)) {
			m->m_len = 0;
		}
	}
}

/*
 * Rearange an mbuf chain so that len bytes are contiguous
 * and in the data area of an mbuf (so that mtod
 * will work for a structure of size len).  Returns the resulting
 * mbuf chain on success, frees it and returns null on failure.
 * If there is room, it will add up to max_protohdr-len extra bytes to the
 * contiguous region in an attempt to avoid being called next time.
 */
struct mbuf *
m_pullup(struct mbuf *n, int len)
{
	struct mbuf *m;
	int count;
	int space;

	/* check invalid arguments */
	if (n == NULL) {
		panic("%s: n == NULL", __func__);
	}
	if (len < 0) {
		os_log_info(OS_LOG_DEFAULT, "%s: failed negative len %d",
		    __func__, len);
		goto bad;
	}
	if (len > MLEN) {
		os_log_info(OS_LOG_DEFAULT, "%s: failed len %d too big",
		    __func__, len);
		goto bad;
	}
	if ((n->m_flags & M_EXT) == 0 &&
	    m_mtod_current(n) >= m_mtod_upper_bound(n)) {
		os_log_info(OS_LOG_DEFAULT, "%s: m_data out of bounds",
		    __func__);
		goto bad;
	}

	/*
	 * If first mbuf has no cluster, and has room for len bytes
	 * without shifting current data, pullup into it,
	 * otherwise allocate a new mbuf to prepend to the chain.
	 */
	if ((n->m_flags & M_EXT) == 0 &&
	    len < m_mtod_upper_bound(n) - m_mtod_current(n) && n->m_next != NULL) {
		if (n->m_len >= len) {
			return n;
		}
		m = n;
		n = n->m_next;
		len -= m->m_len;
	} else {
		if (len > MHLEN) {
			goto bad;
		}
		_MGET(m, M_DONTWAIT, n->m_type);
		if (m == 0) {
			goto bad;
		}
		m->m_len = 0;
		if (n->m_flags & M_PKTHDR) {
			M_COPY_PKTHDR(m, n);
			n->m_flags &= ~M_PKTHDR;
		}
	}
	space = m_mtod_upper_bound(m) - m_mtod_end(m);
	do {
		count = MIN(MIN(MAX(len, max_protohdr), space), n->m_len);
		bcopy(mtod(n, caddr_t), mtod(m, caddr_t) + m->m_len,
		    (unsigned)count);
		len -= count;
		m->m_len += count;
		n->m_len -= count;
		space -= count;
		if (n->m_len != 0) {
			n->m_data += count;
		} else {
			n = m_free(n);
		}
	} while (len > 0 && n != NULL);
	if (len > 0) {
		(void) m_free(m);
		goto bad;
	}
	m->m_next = n;
	return m;
bad:
	m_freem(n);
	return 0;
}

/*
 * Like m_pullup(), except a new mbuf is always allocated, and we allow
 * the amount of empty space before the data in the new mbuf to be specified
 * (in the event that the caller expects to prepend later).
 */
__private_extern__ struct mbuf *
m_copyup(struct mbuf *n, int len, int dstoff)
{
	struct mbuf *m;
	int count, space;

	VERIFY(len >= 0 && dstoff >= 0);

	if (len > (MHLEN - dstoff)) {
		goto bad;
	}
	MGET(m, M_DONTWAIT, n->m_type);
	if (m == NULL) {
		goto bad;
	}
	m->m_len = 0;
	if (n->m_flags & M_PKTHDR) {
		m_copy_pkthdr(m, n);
		n->m_flags &= ~M_PKTHDR;
	}
	m->m_data += dstoff;
	space = m_mtod_upper_bound(m) - m_mtod_end(m);
	do {
		count = min(min(max(len, max_protohdr), space), n->m_len);
		memcpy(mtod(m, caddr_t) + m->m_len, mtod(n, caddr_t),
		    (unsigned)count);
		len -= count;
		m->m_len += count;
		n->m_len -= count;
		space -= count;
		if (n->m_len) {
			n->m_data += count;
		} else {
			n = m_free(n);
		}
	} while (len > 0 && n);
	if (len > 0) {
		(void) m_free(m);
		goto bad;
	}
	m->m_next = n;
	return m;
bad:
	m_freem(n);

	return NULL;
}

/*
 * Partition an mbuf chain in two pieces, returning the tail --
 * all but the first len0 bytes.  In case of failure, it returns NULL and
 * attempts to restore the chain to its original state.
 */
struct mbuf *
m_split(struct mbuf *m0, int len0, int wait)
{
	return m_split0(m0, len0, wait, 1);
}

static struct mbuf *
m_split0(struct mbuf *m0, int len0, int wait, int copyhdr)
{
	struct mbuf *m, *n;
	unsigned len = len0, remain;

	/*
	 * First iterate to the mbuf which contains the first byte of
	 * data at offset len0
	 */
	for (m = m0; m && len > m->m_len; m = m->m_next) {
		len -= m->m_len;
	}
	if (m == NULL) {
		return NULL;
	}
	/*
	 * len effectively is now the offset in the current
	 * mbuf where we have to perform split.
	 *
	 * remain becomes the tail length.
	 * Note that len can also be == m->m_len
	 */
	remain = m->m_len - len;

	/*
	 * If current mbuf len contains the entire remaining offset len,
	 * just make the second mbuf chain pointing to next mbuf onwards
	 * and return after making necessary adjustments
	 */
	if (copyhdr && (m0->m_flags & M_PKTHDR) && remain == 0) {
		_MGETHDR(n, wait, m0->m_type);
		if (n == NULL) {
			return NULL;
		}
		n->m_next = m->m_next;
		m->m_next = NULL;
		n->m_pkthdr.rcvif = m0->m_pkthdr.rcvif;
		n->m_pkthdr.len = m0->m_pkthdr.len - len0;
		m0->m_pkthdr.len = len0;
		return n;
	}
	if (copyhdr && (m0->m_flags & M_PKTHDR)) {
		_MGETHDR(n, wait, m0->m_type);
		if (n == NULL) {
			return NULL;
		}
		n->m_pkthdr.rcvif = m0->m_pkthdr.rcvif;
		n->m_pkthdr.len = m0->m_pkthdr.len - len0;
		m0->m_pkthdr.len = len0;

		/*
		 * If current points to external storage
		 * then it can be shared by making last mbuf
		 * of head chain and first mbuf of current chain
		 * pointing to different data offsets
		 */
		if (m->m_flags & M_EXT) {
			goto extpacket;
		}
		if (remain > MHLEN) {
			/* m can't be the lead packet */
			MH_ALIGN(n, 0);
			n->m_next = m_split(m, len, wait);
			if (n->m_next == NULL) {
				(void) m_free(n);
				return NULL;
			} else {
				return n;
			}
		} else {
			MH_ALIGN(n, remain);
		}
	} else if (remain == 0) {
		n = m->m_next;
		m->m_next = NULL;
		return n;
	} else {
		_MGET(n, wait, m->m_type);
		if (n == NULL) {
			return NULL;
		}

		if ((m->m_flags & M_EXT) == 0) {
			VERIFY(remain <= MLEN);
			M_ALIGN(n, remain);
		}
	}
extpacket:
	if (m->m_flags & M_EXT) {
		n->m_flags |= M_EXT;
		n->m_ext = m->m_ext;
		m_incref(m);
		n->m_data = m->m_data + len;
	} else {
		bcopy(mtod(m, caddr_t) + len, mtod(n, caddr_t), remain);
	}
	n->m_len = remain;
	m->m_len = len;
	n->m_next = m->m_next;
	m->m_next = NULL;
	return n;
}


/*
 * Return the number of bytes in the mbuf chain, m.
 */
unsigned int
m_length(struct mbuf *m)
{
	struct mbuf *m0;
	unsigned int pktlen;

	if (m->m_flags & M_PKTHDR) {
		return m->m_pkthdr.len;
	}

	pktlen = 0;
	for (m0 = m; m0 != NULL; m0 = m0->m_next) {
		pktlen += m0->m_len;
	}
	return pktlen;
}

int
m_chain_capacity(const struct mbuf *m)
{
	int rawlen = 0;
	while (m) {
		rawlen += m_capacity(m);
		m = m->m_next;
	}

	return rawlen;
}


/*
 * Copy data from a buffer back into the indicated mbuf chain,
 * starting "off" bytes from the beginning, extending the mbuf
 * chain if necessary.
 */
void
m_copyback(struct mbuf *m0, int off, int len, const void *cp __sized_by(len))
{
#if DEBUG
	struct mbuf *origm = m0;
	int error;
#endif /* DEBUG */

	if (m0 == NULL) {
		return;
	}

#if DEBUG
	error =
#endif /* DEBUG */
	m_copyback0(&m0, off, len, cp,
	    M_COPYBACK0_COPYBACK | M_COPYBACK0_EXTEND, M_DONTWAIT);

#if DEBUG
	if (error != 0 || (m0 != NULL && origm != m0)) {
		panic("m_copyback");
	}
#endif /* DEBUG */
}

struct mbuf *
m_copyback_cow(struct mbuf *m0, int off, int len, const void *cp __sized_by(len), int how)
{
	int error;

	/* don't support chain expansion */
	VERIFY(off + len <= m_length(m0));

	error = m_copyback0(&m0, off, len, cp,
	    M_COPYBACK0_COPYBACK | M_COPYBACK0_COW, how);
	if (error) {
		/*
		 * no way to recover from partial success.
		 * just free the chain.
		 */
		m_freem(m0);
		return NULL;
	}
	return m0;
}

/*
 * m_makewritable: ensure the specified range writable.
 */
int
m_makewritable(struct mbuf **mp, int off, int len, int how)
{
	int error;
#if DEBUG
	struct mbuf *n;
	int origlen, reslen;

	origlen = m_length(*mp);
#endif /* DEBUG */

	error = m_copyback0(mp, off, len, NULL,
	    M_COPYBACK0_PRESERVE | M_COPYBACK0_COW, how);

#if DEBUG
	reslen = 0;
	for (n = *mp; n; n = n->m_next) {
		reslen += n->m_len;
	}
	if (origlen != reslen) {
		panic("m_makewritable: length changed");
	}
	if (((*mp)->m_flags & M_PKTHDR) && reslen != (*mp)->m_pkthdr.len) {
		panic("m_makewritable: inconsist");
	}
#endif /* DEBUG */

	return error;
}

static int
m_copyback0(struct mbuf **mp0, int off, int len0, const void *vp __sized_by_or_null(len0), int flags,
    int how)
{
	int mlen, len = len0, totlen = 0;
	mbuf_ref_t m, n, *mp;
	const char *cp = vp;

	VERIFY(mp0 != NULL);
	VERIFY(*mp0 != NULL);
	VERIFY((flags & M_COPYBACK0_PRESERVE) == 0 || cp == NULL);
	VERIFY((flags & M_COPYBACK0_COPYBACK) == 0 || cp != NULL);

	/*
	 * we don't bother to update "totlen" in the case of M_COPYBACK0_COW,
	 * assuming that M_COPYBACK0_EXTEND and M_COPYBACK0_COW are exclusive.
	 */

	VERIFY((~flags & (M_COPYBACK0_EXTEND | M_COPYBACK0_COW)) != 0);

	mp = mp0;
	m = *mp;
	while (off > (mlen = m->m_len)) {
		off -= mlen;
		totlen += mlen;
		if (m->m_next == NULL) {
			int tspace;
extend:
			if (!(flags & M_COPYBACK0_EXTEND)) {
				goto out;
			}

			/*
			 * try to make some space at the end of "m".
			 */

			mlen = m->m_len;
			if (off + len >= MINCLSIZE &&
			    !(m->m_flags & M_EXT) && m->m_len == 0) {
				MCLGET(m, how);
			}
			tspace = M_TRAILINGSPACE(m);
			if (tspace > 0) {
				tspace = MIN(tspace, off + len);
				VERIFY(tspace > 0);
				bzero(mtod(m, char *) + m->m_len,
				    MIN(off, tspace));
				m->m_len += tspace;
				off += mlen;
				totlen -= mlen;
				continue;
			}

			/*
			 * need to allocate an mbuf.
			 */

			if (off + len >= MINCLSIZE) {
				n = m_getcl(how, m->m_type, 0);
			} else {
				n = _M_GET(how, m->m_type);
			}
			if (n == NULL) {
				goto out;
			}
			n->m_len = 0;
			n->m_len = MIN(M_TRAILINGSPACE(n), off + len);
			bzero(mtod(n, char *), MIN(n->m_len, off));
			m->m_next = n;
		}
		mp = &m->m_next;
		m = m->m_next;
	}
	while (len > 0) {
		mlen = m->m_len - off;
		if (mlen != 0 && m_mclhasreference(m)) {
			char *datap;
			int eatlen;

			/*
			 * this mbuf is read-only.
			 * allocate a new writable mbuf and try again.
			 */

			/*
			 * if we're going to write into the middle of
			 * a mbuf, split it first.
			 */
			if (off > 0 && len < mlen) {
				n = m_split0(m, off, how, 0);
				if (n == NULL) {
					goto enobufs;
				}
				m->m_next = n;
				mp = &m->m_next;
				m = n;
				off = 0;
				continue;
			}

			/*
			 * XXX TODO coalesce into the trailingspace of
			 * the previous mbuf when possible.
			 */

			/*
			 * allocate a new mbuf.  copy packet header if needed.
			 */
			n = _M_GET(how, m->m_type);
			if (n == NULL) {
				goto enobufs;
			}
			if (off == 0 && (m->m_flags & M_PKTHDR)) {
				M_COPY_PKTHDR(n, m);
				n->m_len = MHLEN;
			} else {
				if (len >= MINCLSIZE) {
					MCLGET(n, M_DONTWAIT);
				}
				n->m_len =
				    (n->m_flags & M_EXT) ? MCLBYTES : MLEN;
			}
			if (n->m_len > len) {
				n->m_len = len;
			}

			/*
			 * free the region which has been overwritten.
			 * copying data from old mbufs if requested.
			 */
			if (flags & M_COPYBACK0_PRESERVE) {
				datap = mtod(n, char *);
			} else {
				datap = NULL;
			}
			eatlen = n->m_len;
			VERIFY(off == 0 || eatlen >= mlen);
			if (off > 0) {
				VERIFY(len >= mlen);
				m->m_len = off;
				m->m_next = n;
				if (datap) {
					m_copydata(m, off, mlen, datap);
					datap += mlen;
				}
				eatlen -= mlen;
				mp = &m->m_next;
				m = m->m_next;
			}
			while (m != NULL && m_mclhasreference(m) &&
			    n->m_type == m->m_type && eatlen > 0) {
				mlen = MIN(eatlen, m->m_len);
				if (datap) {
					m_copydata(m, 0, mlen, datap);
					datap += mlen;
				}
				m->m_data += mlen;
				m->m_len -= mlen;
				eatlen -= mlen;
				if (m->m_len == 0) {
					*mp = m = m_free(m);
				}
			}
			if (eatlen > 0) {
				n->m_len -= eatlen;
			}
			n->m_next = m;
			*mp = m = n;
			continue;
		}
		mlen = MIN(mlen, len);
		if (flags & M_COPYBACK0_COPYBACK) {
			bcopy(cp, mtod(m, caddr_t) + off, (unsigned)mlen);
			cp += mlen;
		}
		len -= mlen;
		mlen += off;
		off = 0;
		totlen += mlen;
		if (len == 0) {
			break;
		}
		if (m->m_next == NULL) {
			goto extend;
		}
		mp = &m->m_next;
		m = m->m_next;
	}
out:
	if (((m = *mp0)->m_flags & M_PKTHDR) && (m->m_pkthdr.len < totlen)) {
		VERIFY(flags & M_COPYBACK0_EXTEND);
		m->m_pkthdr.len = totlen;
	}

	return 0;

enobufs:
	return ENOBUFS;
}

#if !CONFIG_MBUF_MCACHE
uint64_t
mcl_to_paddr(char *addr)
{
	extern addr64_t kvtophys(vm_offset_t va);

	return kvtophys((vm_offset_t)addr);
}
#endif /* !CONFIG_MBUF_MCACHE */

/*
 * Dup the mbuf chain passed in.  The whole thing.  No cute additional cruft.
 * And really copy the thing.  That way, we don't "precompute" checksums
 * for unsuspecting consumers.  Assumption: m->m_nextpkt == 0.  Trick: for
 * small packets, don't dup into a cluster.  That way received  packets
 * don't take up too much room in the sockbuf (cf. sbspace()).
 */
struct mbuf *
m_dup(struct mbuf *m, int how)
{
	mbuf_ref_t n, top, *np;
	int copyhdr = 0;

	np = &top;
	top = NULL;
	if (m->m_flags & M_PKTHDR) {
		copyhdr = 1;
	}

	/*
	 * Quick check: if we have one mbuf and its data fits in an
	 *  mbuf with packet header, just copy and go.
	 */
	if (m->m_next == NULL) {
		/* Then just move the data into an mbuf and be done... */
		if (copyhdr) {
			if (m->m_pkthdr.len <= MHLEN && m->m_len <= MHLEN) {
				if ((n = _M_GETHDR(how, m->m_type)) == NULL) {
					return NULL;
				}
				n->m_len = m->m_len;
				m_dup_pkthdr(n, m, how);
				bcopy(mtod(m, caddr_t), mtod(n, caddr_t), m->m_len);
				return n;
			}
		} else if (m->m_len <= MLEN) {
			if ((n = _M_GET(how, m->m_type)) == NULL) {
				return NULL;
			}
			bcopy(mtod(m, caddr_t), mtod(n, caddr_t), m->m_len);
			n->m_len = m->m_len;
			return n;
		}
	}
	while (m != NULL) {
#if BLUE_DEBUG
		printf("<%x: %x, %x, %x\n", m, m->m_flags, m->m_len,
		    m->m_data);
#endif
		if (copyhdr) {
			n = _M_GETHDR(how, m->m_type);
		} else {
			n = _M_GET(how, m->m_type);
		}
		if (n == NULL) {
			goto nospace;
		}
		if (m->m_flags & M_EXT) {
			if (m->m_len <= m_maxsize(MC_CL)) {
				MCLGET(n, how);
			} else if (m->m_len <= m_maxsize(MC_BIGCL)) {
				n = m_mbigget(n, how);
			} else if (m->m_len <= m_maxsize(MC_16KCL)) {
				n = m_m16kget(n, how);
			}
			if (!(n->m_flags & M_EXT)) {
				(void) m_free(n);
				goto nospace;
			}
		} else {
			VERIFY((copyhdr == 1 && m->m_len <= MHLEN) ||
			    (copyhdr == 0 && m->m_len <= MLEN));
		}
		*np = n;
		if (copyhdr) {
			/* Don't use M_COPY_PKTHDR: preserve m_data */
			m_dup_pkthdr(n, m, how);
			copyhdr = 0;
			if (!(n->m_flags & M_EXT)) {
				n->m_data = (uintptr_t)n->m_pktdat;
			}
		}
		n->m_len = m->m_len;
		/*
		 * Get the dup on the same bdry as the original
		 * Assume that the two mbufs have the same offset to data area
		 * (up to word boundaries)
		 */
		bcopy(mtod(m, caddr_t), mtod(n, caddr_t), (unsigned)n->m_len);
		m = m->m_next;
		np = &n->m_next;
#if BLUE_DEBUG
		printf(">%x: %x, %x, %x\n", n, n->m_flags, n->m_len,
		    n->m_data);
#endif
	}

	return top;

nospace:
	m_freem(top);
	return NULL;
}

#define MBUF_MULTIPAGES(m)                                              \
	(((m)->m_flags & M_EXT) &&                                      \
	((IS_P2ALIGNED((m)->m_data, PAGE_SIZE)                          \
	&& (m)->m_len > PAGE_SIZE) ||                                   \
	(!IS_P2ALIGNED((m)->m_data, PAGE_SIZE) &&                       \
	P2ROUNDUP((m)->m_data, PAGE_SIZE) < ((uintptr_t)(m)->m_data + (m)->m_len))))

static struct mbuf *
m_expand(struct mbuf *m, struct mbuf **last)
{
	mbuf_ref_t top = NULL, *nm = &top;
	uintptr_t data0, data;
	unsigned int len0, len;

	VERIFY(MBUF_MULTIPAGES(m));
	VERIFY(m->m_next == NULL);
	data0 = (uintptr_t)m->m_data;
	len0 = m->m_len;
	*last = top;

	for (;;) {
		struct mbuf *n;

		data = data0;
		if (IS_P2ALIGNED(data, PAGE_SIZE) && len0 > PAGE_SIZE) {
			len = PAGE_SIZE;
		} else if (!IS_P2ALIGNED(data, PAGE_SIZE) &&
		    P2ROUNDUP(data, PAGE_SIZE) < (data + len0)) {
			len = P2ROUNDUP(data, PAGE_SIZE) - data;
		} else {
			len = len0;
		}

		VERIFY(len > 0);
		VERIFY(m->m_flags & M_EXT);
		m->m_data = data;
		m->m_len = len;

		*nm = *last = m;
		nm = &m->m_next;
		m->m_next = NULL;

		data0 += len;
		len0 -= len;
		if (len0 == 0) {
			break;
		}

		n = _M_RETRY(M_DONTWAIT, MT_DATA);
		if (n == NULL) {
			m_freem(top);
			top = *last = NULL;
			break;
		}

		n->m_ext = m->m_ext;
		m_incref(m);
		n->m_flags |= M_EXT;
		m = n;
	}
	return top;
}

struct mbuf *
m_normalize(struct mbuf *m)
{
	mbuf_ref_t top = NULL, *nm = &top;
	boolean_t expanded = FALSE;

	while (m != NULL) {
		mbuf_ref_t n;

		n = m->m_next;
		m->m_next = NULL;

		/* Does the data cross one or more page boundaries? */
		if (MBUF_MULTIPAGES(m)) {
			mbuf_ref_t last;
			if ((m = m_expand(m, &last)) == NULL) {
				m_freem(n);
				m_freem(top);
				top = NULL;
				break;
			}
			*nm = m;
			nm = &last->m_next;
			expanded = TRUE;
		} else {
			*nm = m;
			nm = &m->m_next;
		}
		m = n;
	}
	return top;
}

/*
 * Append the specified data to the indicated mbuf chain,
 * Extend the mbuf chain if the new data does not fit in
 * existing space.
 *
 * Return 1 if able to complete the job; otherwise 0.
 */
int
m_append(struct mbuf *m0, int len0, caddr_t cp0 __sized_by(len0))
{
	struct mbuf *m, *n;
	int remainder, space, len = len0;
	caddr_t cp = cp0;

	for (m = m0; m->m_next != NULL; m = m->m_next) {
		;
	}
	remainder = len;
	space = M_TRAILINGSPACE(m);
	if (space > 0) {
		/*
		 * Copy into available space.
		 */
		if (space > remainder) {
			space = remainder;
		}
		bcopy(cp, mtod(m, caddr_t) + m->m_len, space);
		m->m_len += space;
		cp += space;
		remainder -= space;
	}
	while (remainder > 0) {
		/*
		 * Allocate a new mbuf; could check space
		 * and allocate a cluster instead.
		 */
		n = m_get(M_WAITOK, m->m_type);
		if (n == NULL) {
			break;
		}
		n->m_len = min(MLEN, remainder);
		bcopy(cp, mtod(n, caddr_t), n->m_len);
		cp += n->m_len;
		remainder -= n->m_len;
		m->m_next = n;
		m = n;
	}
	if (m0->m_flags & M_PKTHDR) {
		m0->m_pkthdr.len += len - remainder;
	}
	return remainder == 0;
}

struct mbuf *
m_last(struct mbuf *m)
{
	while (m->m_next != NULL) {
		m = m->m_next;
	}
	return m;
}

unsigned int
m_fixhdr(struct mbuf *m0)
{
	u_int len;

	VERIFY(m0->m_flags & M_PKTHDR);

	len = m_length2(m0, NULL);
	m0->m_pkthdr.len = len;
	return len;
}

unsigned int
m_length2(struct mbuf *m0, struct mbuf **last)
{
	struct mbuf *m;
	u_int len;

	len = 0;
	for (m = m0; m != NULL; m = m->m_next) {
		len += m->m_len;
		if (m->m_next == NULL) {
			break;
		}
	}
	if (last != NULL) {
		*last = m;
	}
	return len;
}

/*
 * Defragment a mbuf chain, returning the shortest possible chain of mbufs
 * and clusters.  If allocation fails and this cannot be completed, NULL will
 * be returned, but the passed in chain will be unchanged.  Upon success,
 * the original chain will be freed, and the new chain will be returned.
 *
 * If a non-packet header is passed in, the original mbuf (chain?) will
 * be returned unharmed.
 *
 * If offset is specfied, the first mbuf in the chain will have a leading
 * space of the amount stated by the "off" parameter.
 *
 * This routine requires that the m_pkthdr.header field of the original
 * mbuf chain is cleared by the caller.
 */
struct mbuf *
m_defrag_offset(struct mbuf *m0, u_int32_t off, int how)
{
	struct mbuf *m_new = NULL, *m_final = NULL;
	int progress = 0, length, pktlen;

	if (!(m0->m_flags & M_PKTHDR)) {
		return m0;
	}

	VERIFY(off < MHLEN);
	m_fixhdr(m0); /* Needed sanity check */

	pktlen = m0->m_pkthdr.len + off;
	if (pktlen > MHLEN) {
		m_final = m_getcl(how, MT_DATA, M_PKTHDR);
	} else {
		m_final = m_gethdr(how, MT_DATA);
	}

	if (m_final == NULL) {
		goto nospace;
	}

	if (off > 0) {
		pktlen -= off;
		m_final->m_data += off;
	}

	/*
	 * Caller must have handled the contents pointed to by this
	 * pointer before coming here, as otherwise it will point to
	 * the original mbuf which will get freed upon success.
	 */
	VERIFY(m0->m_pkthdr.pkt_hdr == NULL);

	if (m_dup_pkthdr(m_final, m0, how) == 0) {
		goto nospace;
	}

	m_new = m_final;

	while (progress < pktlen) {
		length = pktlen - progress;
		if (length > MCLBYTES) {
			length = MCLBYTES;
		}
		length -= ((m_new == m_final) ? off : 0);
		if (length < 0) {
			goto nospace;
		}

		if (m_new == NULL) {
			if (length > MLEN) {
				m_new = m_getcl(how, MT_DATA, 0);
			} else {
				m_new = m_get(how, MT_DATA);
			}
			if (m_new == NULL) {
				goto nospace;
			}
		}

		m_copydata(m0, progress, length, mtod(m_new, caddr_t));
		progress += length;
		m_new->m_len = length;
		if (m_new != m_final) {
			m_cat(m_final, m_new);
		}
		m_new = NULL;
	}
	m_freem(m0);
	m0 = m_final;
	return m0;
nospace:
	if (m_final) {
		m_freem(m_final);
	}
	return NULL;
}

struct mbuf *
m_defrag(struct mbuf *m0, int how)
{
	return m_defrag_offset(m0, 0, how);
}

void
m_mchtype(struct mbuf *m, int t)
{
	mtype_stat_inc(t);
	mtype_stat_dec(m->m_type);
	(m)->m_type = t;
}

void *__unsafe_indexable
m_mtod(struct mbuf *m)
{
	return m_mtod_current(m);
}

/*
 * Return a pointer to mbuf/offset of location in mbuf chain.
 */
struct mbuf *
m_getptr(struct mbuf *m, int loc, int *off)
{
	while (loc >= 0) {
		/* Normal end of search. */
		if (m->m_len > loc) {
			*off = loc;
			return m;
		} else {
			loc -= m->m_len;
			if (m->m_next == NULL) {
				if (loc == 0) {
					/* Point at the end of valid data. */
					*off = m->m_len;
					return m;
				}
				return NULL;
			}
			m = m->m_next;
		}
	}
	return NULL;
}

static uint32_t
mbuf_watchdog_socket_space(struct socket *so)
{
	uint32_t space = 0;

	if (so == NULL) {
		return 0;
	}

	space = so->so_snd.sb_mbcnt + so->so_rcv.sb_mbcnt;

#if INET
	if ((SOCK_DOM(so) == PF_INET || SOCK_DOM(so) == PF_INET6) &&
	    SOCK_PROTO(so) == IPPROTO_TCP) {
		space += tcp_reass_qlen_space(so);
	}
#endif /* INET */

	return space;
}

struct mbuf_watchdog_defunct_args {
	struct proc *top_app;
	uint32_t top_app_space_used;
	bool non_blocking;
};

static bool
proc_fd_trylock(proc_t p)
{
	return lck_mtx_try_lock(&p->p_fd.fd_lock);
}

#if !CONFIG_MBUF_MCACHE
static
#endif
int
mbuf_watchdog_defunct_iterate(proc_t p, void *arg)
{
	struct fileproc *fp = NULL;
	struct mbuf_watchdog_defunct_args *args =
	    (struct mbuf_watchdog_defunct_args *)arg;
	uint32_t space_used = 0;

	/*
	 * Non-blocking is only used when dumping the mbuf usage from the watchdog
	 */
	if (args->non_blocking) {
		if (!proc_fd_trylock(p)) {
			return PROC_RETURNED;
		}
	} else {
		proc_fdlock(p);
	}
	fdt_foreach(fp, p) {
		struct fileglob *fg = fp->fp_glob;
		socket_ref_t so = NULL;

		if (FILEGLOB_DTYPE(fg) != DTYPE_SOCKET) {
			continue;
		}
		so = fg_get_data(fg);
		/*
		 * We calculate the space without the socket
		 * lock because we don't want to be blocked
		 * by another process that called send() and
		 * is stuck waiting for mbufs.
		 *
		 * These variables are 32-bit so we don't have
		 * to worry about incomplete reads.
		 */
		space_used += mbuf_watchdog_socket_space(so);
	}
	proc_fdunlock(p);
	if (space_used > args->top_app_space_used) {
		if (args->top_app != NULL) {
			proc_rele(args->top_app);
		}
		args->top_app = p;
		args->top_app_space_used = space_used;

		return PROC_CLAIMED;
	} else {
		return PROC_RETURNED;
	}
}

extern char *proc_name_address(void *p);

#if !CONFIG_MBUF_MCACHE
static void
mbuf_watchdog_defunct(thread_call_param_t arg0, thread_call_param_t arg1)
{
#pragma unused(arg0, arg1)
	struct mbuf_watchdog_defunct_args args = {};
	struct fileproc *fp = NULL;

	args.non_blocking = false;
	proc_iterate(PROC_ALLPROCLIST,
	    mbuf_watchdog_defunct_iterate, &args, NULL, NULL);

	/*
	 * Defunct all sockets from this app.
	 */
	if (args.top_app != NULL) {
		os_log(OS_LOG_DEFAULT, "%s: defuncting all sockets from %s.%d",
		    __func__,
		    proc_name_address(args.top_app),
		    proc_pid(args.top_app));
		proc_fdlock(args.top_app);
		fdt_foreach(fp, args.top_app) {
			struct fileglob *fg = fp->fp_glob;
			struct socket *so = NULL;

			if (FILEGLOB_DTYPE(fg) != DTYPE_SOCKET) {
				continue;
			}
			so = (struct socket *)fp_get_data(fp);
			if (!socket_try_lock(so)) {
				continue;
			}
			if (sosetdefunct(args.top_app, so,
			    SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL,
			    TRUE) == 0) {
				sodefunct(args.top_app, so,
				    SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL);
			}
			socket_unlock(so, 0);
		}
		proc_fdunlock(args.top_app);
		proc_rele(args.top_app);
		mbstat.m_forcedefunct++;
		zcache_drain(ZONE_ID_MBUF_CLUSTER_2K);
		zcache_drain(ZONE_ID_MBUF_CLUSTER_4K);
		zcache_drain(ZONE_ID_MBUF_CLUSTER_16K);
		zone_drain(zone_by_id(ZONE_ID_MBUF));
		zone_drain(zone_by_id(ZONE_ID_CLUSTER_2K));
		zone_drain(zone_by_id(ZONE_ID_CLUSTER_4K));
		zone_drain(zone_by_id(ZONE_ID_CLUSTER_16K));
		zone_drain(zone_by_id(ZONE_ID_MBUF_REF));
	}
}

static LCK_GRP_DECLARE(mbuf_exhausted_grp, "mbuf-exhausted");
static LCK_TICKET_DECLARE(mbuf_exhausted_lock, &mbuf_exhausted_grp);
static uint32_t mbuf_exhausted_mask;

#define MBUF_EXHAUSTED_DRAIN_MASK  (\
	(1u << MC_MBUF) | \
	(1u << MC_CL) | \
	(1u << MC_BIGCL) | \
	(1u << MC_16KCL))

#define MBUF_EXHAUSTED_DEFUNCT_MASK  (\
	(1u << MC_MBUF) | \
	(1u << MC_MBUF_CL) | \
	(1u << MC_MBUF_BIGCL) | \
	(1u << MC_MBUF_16KCL))

static void
mbuf_watchdog_drain_composite(thread_call_param_t arg0, thread_call_param_t arg1)
{
#pragma unused(arg0, arg1)
	zcache_drain(ZONE_ID_MBUF_CLUSTER_2K);
	zcache_drain(ZONE_ID_MBUF_CLUSTER_4K);
	zcache_drain(ZONE_ID_MBUF_CLUSTER_16K);
}

static void
mbuf_zone_exhausted_start(uint32_t bit)
{
	uint64_t deadline;
	uint32_t mask;

	mask = mbuf_exhausted_mask;
	mbuf_exhausted_mask = mask | bit;

	if ((mask & MBUF_EXHAUSTED_DRAIN_MASK) == 0 &&
	    (bit & MBUF_EXHAUSTED_DRAIN_MASK)) {
		clock_interval_to_deadline(MB_WDT_MAXTIME * 1000 / 10,
		    NSEC_PER_MSEC, &deadline);
		thread_call_enter_delayed(mbuf_drain_tcall, deadline);
	}

	if ((mask & MBUF_EXHAUSTED_DEFUNCT_MASK) == 0 &&
	    (bit & MBUF_EXHAUSTED_DEFUNCT_MASK)) {
		clock_interval_to_deadline(MB_WDT_MAXTIME * 1000 / 2,
		    NSEC_PER_MSEC, &deadline);
		thread_call_enter_delayed(mbuf_defunct_tcall, deadline);
	}
}

static void
mbuf_zone_exhausted_end(uint32_t bit)
{
	uint32_t mask;

	mask = (mbuf_exhausted_mask &= ~bit);

	if ((mask & MBUF_EXHAUSTED_DRAIN_MASK) == 0 &&
	    (bit & MBUF_EXHAUSTED_DRAIN_MASK)) {
		thread_call_cancel(mbuf_drain_tcall);
	}

	if ((mask & MBUF_EXHAUSTED_DEFUNCT_MASK) == 0 &&
	    (bit & MBUF_EXHAUSTED_DEFUNCT_MASK)) {
		thread_call_cancel(mbuf_defunct_tcall);
	}
}

static void
mbuf_zone_exhausted(zone_id_t zid, zone_t zone __unused, bool exhausted)
{
	uint32_t bit;

	if (zid < m_class_to_zid(MBUF_CLASS_MIN) ||
	    zid > m_class_to_zid(MBUF_CLASS_MAX)) {
		return;
	}

	bit = 1u << m_class_from_zid(zid);

	lck_ticket_lock_nopreempt(&mbuf_exhausted_lock, &mbuf_exhausted_grp);

	if (exhausted) {
		mbuf_zone_exhausted_start(bit);
	} else {
		mbuf_zone_exhausted_end(bit);
	}

	lck_ticket_unlock_nopreempt(&mbuf_exhausted_lock);
}
EVENT_REGISTER_HANDLER(ZONE_EXHAUSTED, mbuf_zone_exhausted);
#endif /* !CONFIG_MBUF_MCACHE */

/*
 * Convert between a regular and a packet header mbuf.  Caller is responsible
 * for setting or clearing M_PKTHDR; this routine does the rest of the work.
 */
int
m_reinit(struct mbuf *m, int hdr)
{
	int ret = 0;

	if (hdr) {
		VERIFY(!(m->m_flags & M_PKTHDR));
		if (!(m->m_flags & M_EXT) &&
		    (m->m_data != (uintptr_t)m->m_dat || m->m_len > 0)) {
			/*
			 * If there's no external cluster attached and the
			 * mbuf appears to contain user data, we cannot
			 * safely convert this to a packet header mbuf,
			 * as the packet header structure might overlap
			 * with the data.
			 */
			printf("%s: cannot set M_PKTHDR on altered mbuf %llx, "
			    "m_data %llx (expected %llx), "
			    "m_len %d (expected 0)\n",
			    __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM((uintptr_t)m),
			    (uint64_t)VM_KERNEL_ADDRPERM((uintptr_t)m->m_data),
			    (uint64_t)VM_KERNEL_ADDRPERM((uintptr_t)(m->m_dat)), m->m_len);
			ret = EBUSY;
		} else {
			VERIFY((m->m_flags & M_EXT) || m->m_data == (uintptr_t)m->m_dat);
			m->m_flags |= M_PKTHDR;
			mbuf_init_pkthdr(m);
		}
	} else {
		/* Free the aux data and tags if there is any */
		m_tag_delete_chain(m);
		m_do_tx_compl_callback(m, NULL);
		m->m_flags &= ~M_PKTHDR;
	}

	return ret;
}

int
m_ext_set_prop(struct mbuf *m, uint32_t o, uint32_t n)
{
	ASSERT(m->m_flags & M_EXT);
	return os_atomic_cmpxchg(&MEXT_PRIV(m), o, n, acq_rel);
}

uint32_t
m_ext_get_prop(struct mbuf *m)
{
	ASSERT(m->m_flags & M_EXT);
	return MEXT_PRIV(m);
}

int
m_ext_paired_is_active(struct mbuf *m)
{
	return MBUF_IS_PAIRED(m) ? (MEXT_PREF(m) > MEXT_MINREF(m)) : 1;
}

void
m_ext_paired_activate(struct mbuf *m)
{
	struct ext_ref *rfa;
	int hdr, type;
	caddr_t extbuf;
	m_ext_free_func_t extfree;
	u_int extsize;

	VERIFY(MBUF_IS_PAIRED(m));
	VERIFY(MEXT_REF(m) == MEXT_MINREF(m));
	VERIFY(MEXT_PREF(m) == MEXT_MINREF(m));

	hdr = (m->m_flags & M_PKTHDR);
	type = m->m_type;
	extbuf = m->m_ext.ext_buf;
	extfree = m_get_ext_free(m);
	extsize = m->m_ext.ext_size;
	rfa = m_get_rfa(m);

	VERIFY(extbuf != NULL && rfa != NULL);

	/*
	 * Safe to reinitialize packet header tags, since it's
	 * already taken care of at m_free() time.  Similar to
	 * what's done in m_clattach() for the cluster.  Bump
	 * up MEXT_PREF to indicate activation.
	 */
	mbuf_init(m, hdr, type);
	mext_init(m, extbuf, extsize, extfree, (caddr_t)m, rfa,
	    1, 1, 2, EXTF_PAIRED, MEXT_PRIV(m), m);
}

#if !CONFIG_MBUF_MCACHE
/*
 * This routine is reserved for mbuf_get_driver_scratch(); clients inside
 * xnu that intend on utilizing the module-private area should directly
 * refer to the pkt_mpriv structure in the pkthdr.  They are also expected
 * to set and clear PKTF_PRIV_GUARDED, while owning the packet and prior
 * to handing it off to another module, respectively.
 */
uint32_t
m_scratch_get(struct mbuf *m, uint8_t **p)
{
	struct pkthdr *pkt = &m->m_pkthdr;

	VERIFY(m->m_flags & M_PKTHDR);

	/* See comments in <rdar://problem/14040693> */
	if (pkt->pkt_flags & PKTF_PRIV_GUARDED) {
		panic_plain("Invalid attempt to access guarded module-private "
		    "area: mbuf %p, pkt_flags 0x%x\n", m, pkt->pkt_flags);
		/* NOTREACHED */
	}

	*p = (uint8_t *)&pkt->pkt_mpriv;
	return sizeof(pkt->pkt_mpriv);
}
#endif /* !CONFIG_MBUF_MCACHE */

void
m_add_crumb(struct mbuf *m, uint16_t crumb)
{
	VERIFY(m->m_flags & M_PKTHDR);

	m->m_pkthdr.pkt_crumbs |= crumb;
}

void
m_add_hdr_crumb(struct mbuf *m, uint64_t crumb, uint64_t flag)
{
#if defined(__arm64__)
	while (m != NULL) {
		m->m_mhdrcommon_crumbs &= ~flag;
		m->m_mhdrcommon_crumbs |= (crumb & flag);
		m = m->m_next;
	}
#else
#pragma unused(m, crumb, flag)
#endif /*__arm64__*/
}

void
m_add_hdr_crumb_chain(struct mbuf *head, uint64_t crumb, uint64_t flag)
{
#if defined(__arm64__)
	while (head) {
		/* This assumes that we might have a chain of mbuf chains */
		m_add_hdr_crumb(head, crumb, flag);
		head = head->m_nextpkt;
	}
#else
#pragma unused(head, crumb, flag)
#endif /*__arm64__*/
}

SYSCTL_DECL(_kern_ipc);
SYSCTL_PROC(_kern_ipc, KIPC_MBSTAT, mbstat,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, mbstat_sysctl, "S,mbstat", "");
SYSCTL_PROC(_kern_ipc, OID_AUTO, mb_stat,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, mb_stat_sysctl, "S,mb_stat", "");
SYSCTL_INT(_kern_ipc, OID_AUTO, mb_memory_pressure_percentage,
    CTLFLAG_RW | CTLFLAG_LOCKED, &mb_memory_pressure_percentage, 0,
    "Percentage of when we trigger memory-pressure for an mbuf-class");
