/*
 * Copyright (c) 2018-2021 Apple Inc. All rights reserved.
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

#if (DEVELOPMENT || DEBUG) /* XXX make this whole file a config option? */

#include <skywalk/os_skywalk_private.h>

/*
 * Ignore -Wxnu-typed-allocators for this file, because
 * this is test-only code
 */
__typed_allocators_ignore_push

#define SKMEM_TEST_BUFSIZE      2048

#if XNU_TARGET_OS_OSX && defined(__arm64__)
#define TEST_OPTION_INHIBIT_CACHE    0
#else /* !(XNU_TARGET_OS_OSX && defined(__arm64__)) */
#define TEST_OPTION_INHIBIT_CACHE    KBIF_INHIBIT_CACHE
#endif /* XNU_TARGET_OS_OSX && defined(__arm64__) */

static void skmem_test_start(void *, wait_result_t);
static void skmem_test_stop(void *, wait_result_t);
static void skmem_test_func(void *v, wait_result_t w);
static void skmem_test_mbfreecb(caddr_t cl, uint32_t size, caddr_t arg);
static void skmem_test_alloccb(kern_packet_t, uint32_t, const void *);

extern unsigned int ml_wait_max_cpus(void);
extern kern_return_t thread_terminate(thread_t);

static int skmt_enabled;
static int skmt_busy;
static int skmt_mbcnt;

decl_lck_mtx_data(static, skmt_lock);

struct skmt_alloc_ctx {
	uint32_t        stc_req;        /* # of objects requested */
	uint32_t        stc_idx;        /* expected index */
};

static struct skmt_alloc_ctx skmt_alloccb_ctx;

struct skmt_thread_info {
	kern_packet_t   sti_mph;        /* master packet */
	kern_packet_t   sti_mpc;        /* cloned packet */
	thread_t        sti_thread;     /* thread instance */
	boolean_t       sti_nosleep;    /* non-sleeping allocation */
} __attribute__((aligned(CHANNEL_CACHE_ALIGN_MAX)));

static struct skmt_thread_info *skmth_info;
static uint32_t skmth_info_size;
static int32_t skmth_cnt;
static boolean_t skmth_run;
static kern_pbufpool_t skmth_pp;

void
skmem_test_init(void)
{
	lck_mtx_init(&skmt_lock, &sk_lock_group, &sk_lock_attr);
}

void
skmem_test_fini(void)
{
	lck_mtx_destroy(&skmt_lock, &sk_lock_group);
}

bool
skmem_test_enabled(void)
{
	bool enabled;
	lck_mtx_lock(&skmt_lock);
	enabled = (skmt_busy != 0);
	lck_mtx_unlock(&skmt_lock);
	return enabled;
}

typedef union {
	char c[2];
	uint16_t s;
} short_union_t;

typedef union {
	uint16_t s[2];
	long l;
} long_union_t;

static void
_reduce(int *sum)
{
	long_union_t l_util;

	l_util.l = *sum;
	*sum = l_util.s[0] + l_util.s[1];
	if (*sum > 65535) {
		*sum -= 65535;
	}
}

static uint16_t
skmem_reference_sum(void *buffer, int len, int sum0)
{
	uint16_t *w;
	int sum = sum0;

	w = (uint16_t *)buffer;
	while ((len -= 32) >= 0) {
		sum += w[0]; sum += w[1];
		sum += w[2]; sum += w[3];
		sum += w[4]; sum += w[5];
		sum += w[6]; sum += w[7];
		sum += w[8]; sum += w[9];
		sum += w[10]; sum += w[11];
		sum += w[12]; sum += w[13];
		sum += w[14]; sum += w[15];
		w += 16;
	}
	len += 32;
	while ((len -= 8) >= 0) {
		sum += w[0]; sum += w[1];
		sum += w[2]; sum += w[3];
		w += 4;
	}
	len += 8;
	if (len) {
		_reduce(&sum);
		while ((len -= 2) >= 0) {
			sum += *w++;
		}
	}
	if (len == -1) { /* odd-length packet */
		short_union_t s_util;

		s_util.s = 0;
		s_util.c[0] = *((char *)w);
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	_reduce(&sum);
	return sum & 0xffff;
}

/*
 * At present, the number of objects created in the pool will be
 * higher than the requested amount, if the pool is allowed to use
 * the magazines layer.  Round up a bit to accomodate any rounding
 * ups done by the pool allocator.
 */
#define MAX_PH_ARY      P2ROUNDUP(skmem_cache_magazine_max(1) + 129, 256)

struct skmem_pp_ctx_s {
	os_refcnt_t     skmem_pp_ctx_refcnt;
};

static struct skmem_pp_ctx_s skmem_pp_ctx;

static uint32_t
skmem_pp_ctx_refcnt(void *ctx)
{
	struct skmem_pp_ctx_s *pp_ctx = ctx;
	VERIFY(pp_ctx == &skmem_pp_ctx);
	return os_ref_get_count(&pp_ctx->skmem_pp_ctx_refcnt);
}

static void
skmem_pp_ctx_retain(void *ctx)
{
	struct skmem_pp_ctx_s *pp_ctx = ctx;
	VERIFY(pp_ctx == &skmem_pp_ctx);
	os_ref_retain(&pp_ctx->skmem_pp_ctx_refcnt);
}

static void
skmem_pp_ctx_release(void *ctx)
{
	struct skmem_pp_ctx_s *pp_ctx = ctx;
	VERIFY(pp_ctx == &skmem_pp_ctx);
	(void)os_ref_release(&pp_ctx->skmem_pp_ctx_refcnt);
}

#define BUFLEN 2048

static void
skmem_buflet_tests(uint32_t flags)
{
	struct kern_pbufpool_init pp_init;
	struct kern_pbufpool_memory_info pp_mem_info;
	kern_pbufpool_t pp = NULL;
	struct kern_pbufpool_init pp_init_mb;
	kern_pbufpool_t pp_mb = NULL;
	mach_vm_address_t baddr = 0;
	kern_obj_idx_seg_t sg_idx;
	kern_segment_t sg;
	kern_packet_t *phary = NULL;
	kern_packet_t *phary2 = NULL;
	kern_packet_t *pharyc = NULL;
	struct mbuf **mbary = NULL;
	uint32_t mbcnt = 0;
	uint32_t phcnt = 0, maxphcnt = 0;
	uint32_t phcloned = 0;
	size_t mblen = BUFLEN;
	kern_packet_t ph, ph_mb;
	uint32_t i;
	errno_t err;

	/* packets only */
	VERIFY(!(flags & KBIF_QUANTUM));

	SK_ERR("flags 0x%x", flags);

	phary = (kern_packet_t *) kalloc_data(sizeof(kern_packet_t) * MAX_PH_ARY,
	    Z_WAITOK | Z_ZERO);
	phary2 = (kern_packet_t *) kalloc_data(sizeof(kern_packet_t) * MAX_PH_ARY,
	    Z_WAITOK | Z_ZERO);
	pharyc = (kern_packet_t *) kalloc_data(sizeof(kern_packet_t) * MAX_PH_ARY,
	    Z_WAITOK | Z_ZERO);
	mbary = kalloc_type(struct mbuf *, MAX_PH_ARY, Z_WAITOK | Z_ZERO);

	os_ref_init(&skmem_pp_ctx.skmem_pp_ctx_refcnt, NULL);
	bzero(&pp_init, sizeof(pp_init));
	pp_init.kbi_version = KERN_PBUFPOOL_CURRENT_VERSION;
	pp_init.kbi_buf_seg_size = skmem_usr_buf_seg_size;
	(void) snprintf((char *)pp_init.kbi_name, sizeof(pp_init.kbi_name),
	    "%s", "skmem_buflet_tests");
	pp_init.kbi_flags = flags;
	pp_init.kbi_ctx = &skmem_pp_ctx;
	pp_init.kbi_ctx_retain = skmem_pp_ctx_retain;
	pp_init.kbi_ctx_release = skmem_pp_ctx_release;

	/* must fail if packets is 0 */
	VERIFY(kern_pbufpool_create(&pp_init, &pp, NULL) == EINVAL);
	pp_init.kbi_packets = 64;
	/* must fail if bufsize is 0 */
	VERIFY(kern_pbufpool_create(&pp_init, &pp, NULL) == EINVAL);
	pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
	/* must fail if max_frags is 0 */
	VERIFY(kern_pbufpool_create(&pp_init, &pp, NULL) == EINVAL);

	pp_init.kbi_max_frags = 1;
	VERIFY(kern_pbufpool_create(&pp_init, &pp, NULL) == 0);
	VERIFY(skmem_pp_ctx_refcnt(&skmem_pp_ctx) == 2);
	void *ctx = kern_pbufpool_get_context(pp);
	VERIFY(ctx == &skmem_pp_ctx);
	VERIFY(skmem_pp_ctx_refcnt(&skmem_pp_ctx) == 3);
	skmem_pp_ctx_release(ctx);
	VERIFY(skmem_pp_ctx_refcnt(&skmem_pp_ctx) == 2);
	bzero(&pp_mem_info, sizeof(pp_mem_info));
	VERIFY(kern_pbufpool_get_memory_info(pp, NULL) == EINVAL);
	VERIFY(kern_pbufpool_get_memory_info(pp, &pp_mem_info) == 0);
	VERIFY(pp_mem_info.kpm_flags & KPMF_EXTERNAL);
	VERIFY(pp_mem_info.kpm_buflets >= pp_mem_info.kpm_packets);
	VERIFY(pp_mem_info.kpm_packets >= 64);
	VERIFY(pp_mem_info.kpm_packets <= MAX_PH_ARY);
	VERIFY(pp_mem_info.kpm_max_frags == 1);
	VERIFY(pp_mem_info.kpm_buflets >= 64);
	VERIFY(pp_mem_info.kpm_bufsize == SKMEM_TEST_BUFSIZE);
	VERIFY(kern_pbufpool_alloc(pp, 0, &ph) == EINVAL ||
	    (flags & KBIF_BUFFER_ON_DEMAND));
	if (ph != 0) {
		kern_packet_t phc = 0;
		kern_buflet_t buflet;

		VERIFY(flags & KBIF_BUFFER_ON_DEMAND);
		VERIFY((buflet = kern_packet_get_next_buflet(ph, NULL)) == NULL);
		VERIFY(kern_packet_clone(ph, &phc, KPKT_COPY_LIGHT) == EINVAL);
		VERIFY(kern_packet_clone(ph, &phc, KPKT_COPY_HEAVY) == EINVAL);
		kern_pbufpool_free(pp, ph);
		ph = 0;
	}
	maxphcnt = 32;
	VERIFY(kern_pbufpool_alloc(pp, 5, &ph) == EINVAL);
	if (flags & KBIF_BUFFER_ON_DEMAND) {
		/* allocate and free one at a time (no buflet) */
		for (i = 0, phcnt = 0; i < maxphcnt; i++) {
			boolean_t stop = FALSE;
			/*
			 * This may fail if skmem_region_mtbf is set, or if
			 * the system is short on memory.  Perform retries at
			 * this layer to get at least 32 packets.
			 */
			while ((err = kern_pbufpool_alloc_nosleep(pp, 0, &ph)) != 0) {
				VERIFY(err == ENOMEM);
				if (phcnt < 32) {
					SK_ERR("[a] retrying alloc for packet %u",
					    phcnt);
					delay(250 * NSEC_PER_USEC); /* 1/4 sec */
					continue;
				}
				stop = TRUE;
				break;
			}
			if (stop) {
				break;
			}
			VERIFY(ph != 0);
			VERIFY(kern_packet_get_data_length(ph) == 0);
			VERIFY(kern_packet_get_buflet_count(ph) == 0);
			phary[phcnt++] = ph;
		}
		VERIFY(phcnt >= 32);
		for (i = 0; i < phcnt; i++) {
			kern_pbufpool_free(pp, phary[i]);
			phary[i] = 0;
		}
	}
	/* allocate and free one at a time (1 buflet) */
	for (i = 0, phcnt = 0; i < maxphcnt; i++) {
		boolean_t stop = FALSE;
		/*
		 * This may fail if skmem_region_mtbf is set, or if
		 * the system is short on memory.  Perform retries at
		 * this layer to get at least 32 packets.
		 */
		while ((err = kern_pbufpool_alloc_nosleep(pp, 1, &ph)) != 0) {
			VERIFY(err == ENOMEM);
			if (phcnt < 32) {
				SK_ERR("[a] retrying alloc for packet %u",
				    phcnt);
				delay(250 * NSEC_PER_USEC); /* 1/4 sec */
				continue;
			}
			stop = TRUE;
			break;
		}
		if (stop) {
			break;
		}
		VERIFY(ph != 0);
		VERIFY(kern_packet_get_data_length(ph) == 0);
		VERIFY(kern_packet_get_buflet_count(ph) == 1);
		phary[phcnt++] = ph;
	}
	VERIFY(phcnt >= 32);
	for (i = 0; i < phcnt; i++) {
		kern_pbufpool_free(pp, phary[i]);
		phary[i] = 0;
	}
	/* allocate and free in batch */
	phcnt = maxphcnt;
	for (;;) {
		err = kern_pbufpool_alloc_batch_nosleep(pp, 1, phary, &phcnt);
		VERIFY(err != EINVAL);
		if (err == ENOMEM) {
			phcnt = maxphcnt;
			SK_ERR("retrying batch alloc for %u packets", phcnt);
			delay(250 * NSEC_PER_USEC);     /* 1/4 sec */
		} else if (err == EAGAIN) {
			SK_ERR("batch alloc for %u packets only returned %u",
			    maxphcnt, phcnt);
			break;
		} else {
			VERIFY(err == 0);
			break;
		}
	}
	VERIFY(phcnt > 0);
	for (i = 0; i < phcnt; i++) {
		VERIFY(phary[i] != 0);
		VERIFY(kern_packet_get_data_length(phary[i]) == 0);
		VERIFY(kern_packet_get_buflet_count(phary[i]) == 1);
	}
	kern_pbufpool_free_batch(pp, phary, phcnt);
	/* allocate and free one at a time (blocking) */
	for (i = 0, phcnt = 0; i < maxphcnt; i++) {
		VERIFY(kern_pbufpool_alloc(pp, 1, &ph) == 0);
		VERIFY(ph != 0);
		VERIFY(kern_packet_get_data_length(ph) == 0);
		VERIFY(kern_packet_get_buflet_count(ph) == 1);
		phary[phcnt++] = ph;
	}
	VERIFY(phcnt >= 32);
	for (i = 0; i < phcnt; i++) {
		kern_pbufpool_free(pp, phary[i]);
		phary[i] = 0;
	}
	/* allocate with callback */
	bzero(&skmt_alloccb_ctx, sizeof(skmt_alloccb_ctx));
	skmt_alloccb_ctx.stc_req = phcnt;
	VERIFY(kern_pbufpool_alloc_batch_callback(pp, 1, phary, &phcnt,
	    NULL, &skmt_alloccb_ctx) == EINVAL);
	VERIFY(kern_pbufpool_alloc_batch_callback(pp, 1, phary, &phcnt,
	    skmem_test_alloccb, &skmt_alloccb_ctx) == 0);
	VERIFY(skmt_alloccb_ctx.stc_idx == phcnt);
	kern_pbufpool_free_batch(pp, phary, phcnt);

	/*
	 * Allocate and free test
	 * Case 1: Packet has an mbuf attached
	 */
	mbcnt = phcnt;
	VERIFY(kern_pbufpool_alloc_batch(pp, 1, phary, &phcnt) == 0);
	/* clone packets (lightweight, without mbufs) */
	for (i = 0; i < phcnt; i++) {
		kern_buflet_t buflet, buflet2;
		kern_obj_idx_seg_t buf_idx_seg, buf2_idx_seg;

		VERIFY((buflet = kern_packet_get_next_buflet(phary[i],
		    NULL)) != NULL);
		VERIFY(kern_buflet_set_data_length(buflet, BUFLEN) == 0);
		VERIFY(__packet_finalize(phary[i]) == 0);
		VERIFY(kern_packet_get_data_length(phary[i]) == BUFLEN);
		(void) memset(kern_buflet_get_data_address(buflet), i, BUFLEN);
		kern_packet_set_trace_id(phary[i], i);
		VERIFY(kern_packet_get_trace_id(phary[i]) == i);
		VERIFY(kern_packet_clone(phary[i], &pharyc[i],
		    KPKT_COPY_LIGHT) == 0 || !(flags & KBIF_BUFFER_ON_DEMAND));
		if (pharyc[i] != 0) {
			struct __kern_packet *kpkt2 = SK_PTR_ADDR_KPKT(pharyc[i]);
			/*
			 * Source packet was allocated with 1 buffer, so
			 * validate that the clone packet points to that
			 * same buffer, and that the buffer's usecnt is 2.
			 */
			VERIFY(!(QUM_ADDR(pharyc[i])->qum_qflags & QUM_F_FINALIZED));
			VERIFY(kpkt2->pkt_mbuf == NULL);
			VERIFY(!(kpkt2->pkt_pflags & PKT_F_MBUF_MASK));
			VERIFY((buflet2 = kern_packet_get_next_buflet(pharyc[i],
			    NULL)) != NULL);
			VERIFY(kern_buflet_get_object_address(buflet) ==
			    kern_buflet_get_object_address(buflet2));
			VERIFY(kern_buflet_get_data_address(buflet) ==
			    kern_buflet_get_data_address(buflet2));
			VERIFY(kern_buflet_get_data_limit(buflet) ==
			    kern_buflet_get_data_limit(buflet2));
			VERIFY(kern_buflet_get_data_offset(buflet) ==
			    kern_buflet_get_data_offset(buflet2));
			VERIFY(kern_buflet_get_data_length(buflet) ==
			    kern_buflet_get_data_length(buflet2));
			VERIFY(kern_buflet_set_data_limit(buflet2,
			    (uint16_t)kern_buflet_get_object_limit(buflet2) + 1)
			    == ERANGE);
			VERIFY(kern_buflet_set_data_limit(buflet2,
			    (uint16_t)kern_buflet_get_object_limit(buflet2) - 16)
			    == 0);
			VERIFY(kern_buflet_set_data_address(buflet2,
			    (const void *)((uintptr_t)kern_buflet_get_object_address(buflet2) - 1))
			    == ERANGE);
			VERIFY(kern_buflet_set_data_address(buflet2,
			    (const void *)((uintptr_t)kern_buflet_get_object_address(buflet2) + 16))
			    == 0);
			VERIFY(kern_buflet_set_data_length(buflet2,
			    kern_buflet_get_data_length(buflet2) - 32) == 0);
			VERIFY(kern_buflet_get_object_segment(buflet,
			    &buf_idx_seg) ==
			    kern_buflet_get_object_segment(buflet2,
			    &buf2_idx_seg));
			VERIFY(buf_idx_seg == buf2_idx_seg);
			VERIFY(buflet->buf_ctl == buflet2->buf_ctl);
			VERIFY(buflet->buf_ctl->bc_usecnt == 2);
			++phcloned;
			VERIFY(__packet_finalize(pharyc[i]) == 0);
			/* verify trace id isn't reused */
			VERIFY(kern_packet_get_trace_id(pharyc[i]) == 0);
			kern_packet_set_trace_id(pharyc[i], phcnt - i);
			VERIFY(kern_packet_get_trace_id(pharyc[i]) == (phcnt - i));
			VERIFY(kern_packet_get_trace_id(phary[i]) == i);
		}
	}
	VERIFY(phcloned == phcnt || phcloned == 0);
	if (phcloned != 0) {
		kern_pbufpool_free_batch(pp, pharyc, phcloned);
		phcloned = 0;
	}
	kern_pbufpool_free_batch(pp, phary, phcnt);
	VERIFY(kern_pbufpool_alloc_batch(pp, 1, phary, &phcnt) == 0);
	VERIFY(phcnt == mbcnt);
	VERIFY(skmt_mbcnt == 0);
	for (i = 0; i < mbcnt; i++) {
		struct __kern_packet *kpkt = SK_PTR_ADDR_KPKT(phary[i]);
		kern_buflet_t buflet;

		VERIFY((buflet = kern_packet_get_next_buflet(phary[i],
		    NULL)) != NULL);
		VERIFY(kern_buflet_set_data_length(buflet, BUFLEN) == 0);
		(void) memset(kern_buflet_get_data_address(buflet), i, BUFLEN);
		/* attach mbuf to packets and initialize packets */
		mblen = BUFLEN;
		VERIFY(mbuf_ring_cluster_alloc(MBUF_WAITOK, MBUF_TYPE_HEADER,
		    &mbary[i], skmem_test_mbfreecb, &mblen) == 0);
		VERIFY(mblen == BUFLEN);
		VERIFY(mbary[i] != NULL);
		VERIFY(mbary[i]->m_nextpkt == NULL);
		mbuf_setlen(mbary[i], mblen);
		mbuf_pkthdr_setlen(mbary[i], mblen);
		VERIFY((size_t)m_pktlen(mbary[i]) == mblen);
		(void) memset(mbuf_data(mbary[i]), i, mblen);
		kpkt->pkt_mbuf = mbary[i];
		kpkt->pkt_pflags |= PKT_F_MBUF_DATA;
		VERIFY(__packet_finalize_with_mbuf(kpkt) == 0);
		VERIFY(kern_packet_get_data_length(phary[i]) == BUFLEN);
		VERIFY(mbuf_ring_cluster_activate(kpkt->pkt_mbuf) == 0);
	}
	/* clone packets (heavyweight) */
	for (i = 0; i < phcnt; i++) {
		VERIFY(kern_packet_clone(phary[i], &pharyc[i],
		    KPKT_COPY_HEAVY) == 0);
		struct __kern_packet *kpkt = SK_PTR_ADDR_KPKT(phary[i]);
		struct __kern_packet *kpkt2 = SK_PTR_ADDR_KPKT(pharyc[i]);
		kern_buflet_t buflet, buflet2;
		/*
		 * Source packet was allocated with 1 buffer, so
		 * validate that the clone packet points to different
		 * buffer, and that the clone's attached mbuf is also
		 * different than the source's.
		 */
		VERIFY(!(QUM_ADDR(pharyc[i])->qum_qflags & QUM_F_FINALIZED));
		VERIFY((buflet = kern_packet_get_next_buflet(phary[i],
		    NULL)) != NULL);
		VERIFY((buflet2 = kern_packet_get_next_buflet(pharyc[i],
		    NULL)) != NULL);
		VERIFY(kern_buflet_get_object_address(buflet) !=
		    kern_buflet_get_object_address(buflet2));
		VERIFY(kern_buflet_get_data_address(buflet) !=
		    kern_buflet_get_data_address(buflet2));
		VERIFY(kern_buflet_get_data_limit(buflet) ==
		    kern_buflet_get_data_limit(buflet2));
		VERIFY(kern_buflet_get_data_offset(buflet) ==
		    kern_buflet_get_data_offset(buflet2));
		VERIFY(kern_buflet_get_data_length(buflet) == BUFLEN);
		VERIFY(kern_buflet_get_data_length(buflet) ==
		    kern_buflet_get_data_length(buflet2));
		VERIFY(kpkt->pkt_pflags & PKT_F_MBUF_DATA);
		VERIFY(kpkt2->pkt_pflags & PKT_F_MBUF_DATA);
		VERIFY(m_pktlen(kpkt2->pkt_mbuf) == m_pktlen(kpkt->pkt_mbuf));
		VERIFY(kern_packet_get_data_length(phary[i]) == BUFLEN);
		VERIFY(kern_packet_get_data_length(phary[i]) ==
		    kern_packet_get_data_length(pharyc[i]));
		VERIFY(buflet->buf_ctl != buflet2->buf_ctl);
		VERIFY(buflet->buf_ctl->bc_usecnt == 1);
		VERIFY(buflet2->buf_ctl->bc_usecnt == 1);
		VERIFY(memcmp(kern_buflet_get_data_address(buflet),
		    kern_buflet_get_data_address(buflet2),
		    kern_buflet_get_data_length(buflet)) == 0);
		VERIFY(kpkt->pkt_mbuf != NULL);
		VERIFY(kpkt2->pkt_mbuf != NULL);
		VERIFY(mbuf_data(kpkt->pkt_mbuf) != mbuf_data(kpkt2->pkt_mbuf));
		VERIFY(mbuf_len(kpkt->pkt_mbuf) == mbuf_len(kpkt2->pkt_mbuf));
		/* mbuf contents must have been copied */
		VERIFY(memcmp(mbuf_data(kpkt->pkt_mbuf),
		    mbuf_data(kpkt2->pkt_mbuf), mbuf_len(kpkt->pkt_mbuf)) == 0);
		VERIFY(__packet_finalize(pharyc[i]) == 0);
		++phcloned;
	}
	VERIFY(phcloned == phcnt);
	kern_pbufpool_free_batch(pp, pharyc, phcloned);
	phcloned = 0;
	skmt_mbcnt = mbcnt;
	kern_pbufpool_free_batch(pp, phary, phcnt);
	/* skmem_test_mbfreecb() should have been called for all mbufs by now */
	VERIFY(skmt_mbcnt == 0);
	for (i = 0; i < mbcnt; i++) {
		VERIFY(mbary[i] != NULL);
		m_freem(mbary[i]);
		mbary[i] = NULL;
	}
	mbcnt = 0;

	/*
	 * Allocate and free test
	 * Case 2: Packet has a packet attached
	 */
	VERIFY(pp_mem_info.kpm_packets >= 64);
	phcnt = 32;
	VERIFY(kern_pbufpool_alloc_batch(pp, 1, phary, &phcnt) == 0);
	VERIFY(phcnt == 32);
	VERIFY(kern_pbufpool_alloc_batch(pp, 1, phary2, &phcnt) == 0);
	VERIFY(phcnt == 32);
	/* attach each packet to a packet */
	for (i = 0; i < phcnt; i++) {
		struct __kern_packet *kpkt = SK_PTR_ADDR_KPKT(phary[i]);
		struct __kern_packet *kpkt2 = SK_PTR_ADDR_KPKT(phary2[i]);

		kpkt->pkt_pkt = kpkt2;
		kpkt->pkt_pflags |= PKT_F_PKT_DATA;
	}
	/* free the batch of packets (also free the attached packets) */
	kern_pbufpool_free_batch(pp, phary, phcnt);

	/*
	 * Allocate and free test
	 * Case 3: Packet has a packet attached. The attached packet itself has
	 * an mbuf attached.
	 */
	VERIFY(pp_mem_info.kpm_packets >= 64);
	phcnt = 32;
	mbcnt = 32;
	VERIFY(kern_pbufpool_alloc_batch(pp, 1, phary, &phcnt) == 0);
	VERIFY(phcnt == 32);
	VERIFY(kern_pbufpool_alloc_batch(pp, 1, phary2, &phcnt) == 0);
	VERIFY(phcnt == 32);
	VERIFY(skmt_mbcnt == 0);
	for (i = 0; i < mbcnt; i++) {
		mblen = BUFLEN;
		VERIFY(mbuf_ring_cluster_alloc(MBUF_WAITOK, MBUF_TYPE_HEADER,
		    &mbary[i], skmem_test_mbfreecb, &mblen) == 0);
		VERIFY(mbary[i] != NULL);
		VERIFY(mbary[i]->m_nextpkt == NULL);
	}
	/* attach each packet to a packet */
	for (i = 0; i < phcnt; i++) {
		struct __kern_packet *kpkt = SK_PTR_ADDR_KPKT(phary[i]);
		struct __kern_packet *kpkt2 = SK_PTR_ADDR_KPKT(phary2[i]);

		VERIFY(mbary[i] != NULL);
		VERIFY(__packet_initialize_with_mbuf(kpkt2,
		    mbary[i], 0, 0) == 0);
		VERIFY(mbuf_ring_cluster_activate(kpkt2->pkt_mbuf) == 0);
		kpkt->pkt_pkt = kpkt2;
		kpkt->pkt_pflags |= PKT_F_PKT_DATA;
	}
	skmt_mbcnt = mbcnt;
	/* free the batch of packets (also free the attached packets) */
	kern_pbufpool_free_batch(pp, phary, phcnt);
	/* skmem_test_mbfreecb() should have been called for all mbufs by now */
	VERIFY(skmt_mbcnt == 0);
	for (i = 0; i < mbcnt; i++) {
		VERIFY(mbary[i] != NULL);
		m_freem(mbary[i]);
		mbary[i] = NULL;
	}
	mbcnt = 0;

	kern_pbufpool_destroy(pp);
	pp = NULL;
	/* check that ctx_release has been called */
	VERIFY(skmem_pp_ctx_refcnt(&skmem_pp_ctx) == 1);

	pp_init.kbi_ctx = NULL;
	pp_init.kbi_ctx_retain = NULL;
	pp_init.kbi_ctx_release = NULL;
	pp_init.kbi_buflets = 1;
	/* must fail if buflets is non-zero and less than packets */
	if (!(flags & KBIF_BUFFER_ON_DEMAND)) {
		VERIFY(kern_pbufpool_create(&pp_init, &pp, NULL) == EINVAL);
	} else {
		VERIFY(kern_pbufpool_create(&pp_init, &pp, NULL) == 0);
		kern_pbufpool_destroy(pp);
		pp = NULL;
	}
	pp_init.kbi_buflets = (64 * 2);
	VERIFY(kern_pbufpool_create(&pp_init, &pp, NULL) == 0);
	bzero(&pp_mem_info, sizeof(pp_mem_info));
	VERIFY(kern_pbufpool_get_memory_info(pp, &pp_mem_info) == 0);
	VERIFY(pp_mem_info.kpm_flags & KPMF_EXTERNAL);
	VERIFY(pp_mem_info.kpm_buflets >= pp_mem_info.kpm_packets);
	VERIFY(pp_mem_info.kpm_packets >= 64);
	VERIFY(pp_mem_info.kpm_max_frags == 1);
	VERIFY(pp_mem_info.kpm_buflets >= (64 * 2));
	VERIFY(pp_mem_info.kpm_bufsize == SKMEM_TEST_BUFSIZE);
	VERIFY(kern_pbufpool_alloc(pp, 1, &ph) == 0);
	VERIFY(kern_packet_get_buflet_count(ph) == 1);
	kern_pbufpool_free(pp, ph);
	ph = 0;
	phcnt = 4;
	VERIFY(kern_pbufpool_alloc_batch(pp, 4, phary, &phcnt) == EINVAL);
	VERIFY(kern_pbufpool_alloc_batch(pp, 1, phary, &phcnt) == 0);
	VERIFY(kern_packet_get_buflet_count(phary[0]) == 1);
	VERIFY(kern_packet_get_buflet_count(phary[1]) == 1);
	VERIFY(kern_packet_get_buflet_count(phary[2]) == 1);
	VERIFY(kern_packet_get_buflet_count(phary[3]) == 1);
	kern_pbufpool_free_batch(pp, phary, phcnt);
	kern_pbufpool_destroy(pp);
	pp = NULL;

	/* check multi-buflet KPIs */
	bzero(&pp_init_mb, sizeof(pp_init_mb));
	pp_init_mb.kbi_version = KERN_PBUFPOOL_CURRENT_VERSION;
	pp_init_mb.kbi_buf_seg_size = skmem_usr_buf_seg_size;
	(void) snprintf((char *)pp_init_mb.kbi_name,
	    sizeof(pp_init_mb.kbi_name), "%s", "skmem_buflet_tests_mb");
	pp_init_mb.kbi_flags = flags;
	pp_init_mb.kbi_max_frags = 4;
	pp_init_mb.kbi_packets = 64;
	pp_init_mb.kbi_bufsize = 512;
	pp_init_mb.kbi_buflets =
	    pp_init_mb.kbi_packets * pp_init_mb.kbi_max_frags;

	VERIFY((kern_pbufpool_create(&pp_init_mb, &pp_mb, NULL) == EINVAL) ||
	    (flags & KBIF_BUFFER_ON_DEMAND));

	if (pp_mb != NULL) {
		bzero(&pp_mem_info, sizeof(pp_mem_info));
		VERIFY(kern_pbufpool_get_memory_info(pp_mb, &pp_mem_info) == 0);
		VERIFY(kern_pbufpool_alloc(pp_mb, 0, &ph_mb) == 0 ||
		    !(flags & KBIF_BUFFER_ON_DEMAND));
		if (ph_mb != 0) {
			VERIFY(flags & KBIF_BUFFER_ON_DEMAND);
			kern_pbufpool_free(pp_mb, ph_mb);
			ph_mb = 0;
		}
		VERIFY(kern_pbufpool_alloc_buffer(pp_mb, &baddr, &sg,
		    &sg_idx) == 0 || !(flags & KBIF_BUFFER_ON_DEMAND));
		if (baddr != 0) {
			VERIFY(flags & KBIF_BUFFER_ON_DEMAND);
			kern_pbufpool_free_buffer(pp_mb, baddr);
			baddr = 0;
		}
		kern_pbufpool_destroy(pp_mb);
		pp_mb = NULL;
	}

	kfree_type(struct mbuf *, MAX_PH_ARY, mbary);
	mbary = NULL;

	kfree_data(phary, sizeof(kern_packet_t) * MAX_PH_ARY);
	phary = NULL;

	kfree_data(phary2, sizeof(kern_packet_t) * MAX_PH_ARY);
	phary2 = NULL;

	kfree_data(pharyc, sizeof(kern_packet_t) * MAX_PH_ARY);
	pharyc = NULL;
}

static void
skmem_test_mbfreecb(caddr_t cl, uint32_t size, caddr_t arg)
{
#pragma unused(cl, size)
	struct mbuf *m = (void *)arg;

	VERIFY(!mbuf_ring_cluster_is_active(m));
	VERIFY(skmt_mbcnt > 0);
	os_atomic_dec(&skmt_mbcnt, relaxed);
}

static void
skmem_test_alloccb(kern_packet_t ph, uint32_t idx, const void *ctx)
{
	VERIFY(ph != 0);
	VERIFY(ctx == &skmt_alloccb_ctx);
	VERIFY(idx < skmt_alloccb_ctx.stc_req);
	VERIFY(idx == os_atomic_inc_orig(&skmt_alloccb_ctx.stc_idx, relaxed));
}
static void
skmem_packet_tests(uint32_t flags)
{
	struct kern_pbufpool_memory_info pp_mb_mem_info;
	struct kern_pbufpool_memory_info pp_mem_info;
	struct kern_pbufpool_init pp_init;
	kern_pbufpool_t pp = NULL;
	struct kern_pbufpool_init pp_init_mb;
	kern_pbufpool_t pp_mb = NULL;
	mach_vm_address_t baddr = 0;
	uint8_t *buffer, *ref_buffer;
	kern_obj_idx_seg_t sg_idx;
	kern_buflet_t buflet;
	kern_segment_t sg;
	kern_packet_t ph = 0, ph_mb = 0;
	struct mbuf *m = NULL;
	uint16_t len;
	uint32_t i;
	uint32_t csum_eee_ref, csum_eeo_ref, csum_eoe_ref, csum_eoo_ref;
	uint32_t csum_oee_ref, csum_oeo_ref, csum_ooe_ref, csum_ooo_ref, csum;
	boolean_t test_unaligned;
	kern_buflet_t bft0, bft1;

	SK_ERR("flags 0x%x", flags);

	/*
	 * XXX: Skip packet tests involving unaligned addresses when
	 * KBIF_INHIBIT_CACHE is set, as the copy-and-checksum routine
	 * currently assumes normal memory, rather than device memory.
	 */
	test_unaligned = !(flags & KBIF_INHIBIT_CACHE);

	/* allocate separately in case pool is setup for device memory */
	ref_buffer = (uint8_t *) kalloc_data(SKMEM_TEST_BUFSIZE,
	    Z_WAITOK | Z_ZERO);

	bzero(&pp_init_mb, sizeof(pp_init_mb));
	pp_init_mb.kbi_version = KERN_PBUFPOOL_CURRENT_VERSION;
	pp_init_mb.kbi_buf_seg_size = skmem_usr_buf_seg_size;
	(void) snprintf((char *)pp_init_mb.kbi_name,
	    sizeof(pp_init_mb.kbi_name), "%s", "skmem_packet_tests_mb");
	pp_init_mb.kbi_flags = flags | KBIF_BUFFER_ON_DEMAND;
	pp_init_mb.kbi_max_frags = 4;
	pp_init_mb.kbi_packets = 64;
	pp_init_mb.kbi_bufsize = 512;
	pp_init_mb.kbi_buflets =
	    pp_init_mb.kbi_packets * pp_init_mb.kbi_max_frags;
	pp_init_mb.kbi_ctx = NULL;
	pp_init_mb.kbi_ctx_retain = NULL;
	pp_init_mb.kbi_ctx_release = NULL;

	VERIFY(kern_pbufpool_create(&pp_init_mb, &pp_mb, &pp_mb_mem_info) == 0);
	VERIFY(kern_pbufpool_alloc_buffer(pp_mb, &baddr, NULL, NULL) == 0);
	kern_pbufpool_free_buffer(pp_mb, baddr);
	VERIFY(kern_pbufpool_alloc_buffer(pp_mb, &baddr, &sg, &sg_idx) == 0);
	VERIFY(sg != NULL);
	VERIFY(sg->sg_region != NULL);
	VERIFY(sg->sg_md != NULL);
	VERIFY(sg->sg_start != 0);
	VERIFY(sg->sg_end != 0);
	VERIFY(sg->sg_type == SKSEG_TYPE_ALLOC);
	kern_pbufpool_free_buffer(pp_mb, baddr);
	baddr = 0;

	/* add buflet to a packet with buf count 1 */
	VERIFY(kern_pbufpool_alloc(pp_mb, 1, &ph_mb) == 0);
	VERIFY(kern_pbufpool_alloc_buflet(pp_mb, &bft1) == 0);
	VERIFY(bft1 != NULL);
	VERIFY(kern_buflet_get_data_address(bft1) != NULL);
	VERIFY(kern_buflet_get_object_address(bft1) != NULL);
	VERIFY((bft0 = kern_packet_get_next_buflet(ph_mb, NULL)) != NULL);
	VERIFY(kern_packet_add_buflet(ph_mb, bft0, bft1) == 0);
	VERIFY(kern_packet_get_buflet_count(ph_mb) == 2);
	VERIFY(kern_packet_get_next_buflet(ph_mb, NULL) == bft0);
	VERIFY(kern_packet_get_next_buflet(ph_mb, bft0) == bft1);
	VERIFY(kern_packet_get_next_buflet(ph_mb, bft1) == NULL);
	VERIFY(kern_packet_finalize(ph_mb) == 0);
	kern_pbufpool_free(pp_mb, ph_mb);
	ph_mb = 0;

	/* add buflet to a packet with buf count 0 */
	VERIFY(kern_pbufpool_alloc(pp_mb, 0, &ph_mb) == 0);
	VERIFY(kern_packet_get_buflet_count(ph_mb) == 0);
	VERIFY((bft0 = kern_packet_get_next_buflet(ph_mb, NULL)) == NULL);
	VERIFY(kern_pbufpool_alloc_buflet(pp_mb, &bft1) == 0);
	VERIFY(bft1 != NULL);
	VERIFY(kern_packet_add_buflet(ph_mb, bft0, bft1) == 0);
	VERIFY(kern_packet_get_buflet_count(ph_mb) == 1);
	VERIFY(kern_packet_get_next_buflet(ph_mb, bft0) == bft1);
	VERIFY(kern_packet_get_next_buflet(ph_mb, bft1) == NULL);
	VERIFY(kern_buflet_get_data_address(bft1) != NULL);
	VERIFY(kern_buflet_get_object_address(bft1) != NULL);
	VERIFY(kern_buflet_get_data_limit(bft1) != 0);
	VERIFY(kern_buflet_get_data_length(bft1) == 0);
	VERIFY(kern_packet_finalize(ph_mb) == 0);
	kern_pbufpool_free(pp_mb, ph_mb);
	ph_mb = 0;

	bzero(&pp_init, sizeof(pp_init));
	pp_init.kbi_version = KERN_PBUFPOOL_CURRENT_VERSION;
	pp_init.kbi_buf_seg_size = skmem_usr_buf_seg_size;
	(void) snprintf((char *)pp_init.kbi_name, sizeof(pp_init.kbi_name),
	    "%s", "skmem_packet_tests");
	pp_init.kbi_flags = flags;
	pp_init.kbi_packets = 64;
	pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
	pp_init.kbi_max_frags = 1;
	pp_init.kbi_buflets = (64 * 2);
	pp_init.kbi_ctx = NULL;
	pp_init.kbi_ctx_retain = NULL;
	pp_init.kbi_ctx_release = NULL;

	/* validate multi-buflet packet checksum/copy+checksum routines */
	VERIFY(kern_pbufpool_create(&pp_init, &pp, &pp_mem_info) == 0);
	VERIFY(kern_pbufpool_alloc(pp, 1, &ph) == 0);
	VERIFY(kern_packet_get_buflet_count(ph) == 1);

	VERIFY((buflet = kern_packet_get_next_buflet(ph, NULL)) != NULL);
	VERIFY((buffer = kern_buflet_get_data_address(buflet)) != NULL);
	len = SKMEM_TEST_BUFSIZE;
	for (i = 0; i < len; i++) {
		ref_buffer[i] = (i & 0xff);
	}
	/* enforce load/store byte for device memory case */
	volatile uint8_t *bufp = buffer;
	for (i = 0; i < len; i++) {
		bufp[i] = ref_buffer[i];
	}
	VERIFY(kern_buflet_set_data_length(buflet, len) == 0);
	VERIFY(__packet_finalize(ph) == 0);

	/* calculate and validate reference value */
	csum_eee_ref = __packet_cksum(buffer, len, 0);
	VERIFY(skmem_reference_sum(ref_buffer, len, 0) == csum_eee_ref);
	csum_eoe_ref = __packet_cksum(buffer, len - 2, 0);
	VERIFY(skmem_reference_sum(ref_buffer, len - 2, 0) == csum_eoe_ref);
	csum_eoo_ref = csum_eeo_ref = __packet_cksum(buffer, len - 1, 0);
	VERIFY(skmem_reference_sum(ref_buffer, len - 1, 0) == csum_eoo_ref);
	csum_oeo_ref = csum_ooo_ref = __packet_cksum(buffer + 1, len - 1, 0);
	VERIFY(skmem_reference_sum(ref_buffer + 1, len - 1, 0) == csum_oeo_ref);
	csum_ooe_ref = csum_oee_ref = __packet_cksum(buffer + 1, len - 2, 0);
	VERIFY(skmem_reference_sum(ref_buffer + 1, len - 2, 0) == csum_ooe_ref);

	/* sanity tests */
	VERIFY(skmem_reference_sum(ref_buffer + 2, len - 2, 0) ==
	    __packet_cksum(buffer + 2, len - 2, 0));
	VERIFY(skmem_reference_sum(ref_buffer + 3, len - 3, 0) ==
	    __packet_cksum(buffer + 3, len - 3, 0));
	VERIFY(skmem_reference_sum(ref_buffer + 4, len - 4, 0) ==
	    __packet_cksum(buffer + 4, len - 4, 0));
	VERIFY(skmem_reference_sum(ref_buffer + 5, len - 5, 0) ==
	    __packet_cksum(buffer + 5, len - 5, 0));
	VERIFY(skmem_reference_sum(ref_buffer + 6, len - 6, 0) ==
	    __packet_cksum(buffer + 6, len - 6, 0));
	VERIFY(skmem_reference_sum(ref_buffer + 7, len - 7, 0) ==
	    __packet_cksum(buffer + 7, len - 7, 0));

	VERIFY(mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_HEADER, &m) == 0);
	VERIFY(mbuf_copyback(m, 0, len, buffer, MBUF_WAITOK) == 0);

	/* verify copy-checksum between packets */
	VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
	VERIFY(kern_packet_get_buflet_count(ph_mb) == 4);
	pkt_copypkt_sum(ph, 0, ph_mb, 0, len - 1, &csum, TRUE);
	METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 0);
	VERIFY(__packet_finalize(ph_mb) == 0);
	if (csum_eeo_ref != csum) {
		SK_ERR("pkt_copypkt_sum: csum_eeo_mismatch 0x%x, "
		    "0x%x, 0x%llx", csum_eeo_ref, csum,
		    SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)));
	}
	VERIFY(csum_eeo_ref == csum);
	kern_pbufpool_free(pp_mb, ph_mb);
	ph_mb = 0;

	if (test_unaligned) {
		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		pkt_copypkt_sum(ph, 0, ph_mb, 1, len - 2, &csum, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 1);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 1;
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_eoe_ref != csum) {
			SK_ERR("pkt_copypkt_sum: csum_eoe_mismatch 0x%x, "
			    "0x%x, 0x%llx", csum_eoe_ref, csum,
			    SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)));
		}
		VERIFY(csum_eoe_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;

		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		pkt_copypkt_sum(ph, 0, ph_mb, 1, len - 1, &csum, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 1);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 1;
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_eoo_ref != csum) {
			SK_ERR("pkt_copypkt_sum: csum_eoo_mismatch 0x%x, "
			    "0x%x, 0x%llx", csum_eoo_ref, csum,
			    SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)));
		}
		VERIFY(csum_eoo_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;

		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		pkt_copypkt_sum(ph, 1, ph_mb, 0, len - 1, &csum, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 0);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 0;
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_oeo_ref != csum) {
			SK_ERR("pkt_copypkt_sum: csum_oeo_mismatch 0x%x, "
			    "0x%x, 0x%llx", csum_oeo_ref, csum,
			    SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)));
		}
		VERIFY(csum_oeo_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;

		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		pkt_copypkt_sum(ph, 1, ph_mb, 1, len - 1, &csum, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 1);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 1;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_ooo_ref != csum) {
			SK_ERR("pkt_copypkt_sum: csum_ooo_mismatch 0x%x, "
			    "0x%x, 0x%llx", csum_ooo_ref, csum,
			    SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)));
		}
		VERIFY(csum_ooo_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;

		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		pkt_copypkt_sum(ph, 1, ph_mb, 1, len - 2, &csum, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 1);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 1;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_ooe_ref != csum) {
			SK_ERR("pkt_copypkt_sum: csum_ooe_mismatch 0x%x, "
			    "0x%x, 0x%llx", csum_ooe_ref, csum,
			    SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)));
		}
		VERIFY(csum_ooe_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;

		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		pkt_copypkt_sum(ph, 1, ph_mb, 0, len - 2, &csum, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 0);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 0;
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_ooe_ref != csum) {
			SK_ERR("pkt_copypkt_sum: csum_oee_mismatch 0x%x, "
			    "0x%x, 0x%llx", csum_oee_ref, csum,
			    SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)));
		}
		VERIFY(csum_oee_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;
	}

	VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
	VERIFY(kern_packet_get_buflet_count(ph_mb) == 4);
	pkt_copypkt_sum(ph, 0, ph_mb, 0, len, &csum, TRUE);
	METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 0);
	SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 0;
	SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
	VERIFY(__packet_finalize(ph_mb) == 0);
	if (csum_eee_ref != csum) {
		SK_ERR("pkt_copypkt_sum: csum_eee_mismatch 0x%x, "
		    "0x%x, 0x%llx", csum_eee_ref, csum,
		    SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)));
	}
	VERIFY(csum_eee_ref == csum);

	/* verify copy-checksum from packet to buffer */
	csum = pkt_copyaddr_sum(ph_mb, 0, buffer, len - 1, TRUE, 0, NULL);
	if (csum_eeo_ref != csum) {
		SK_ERR("pkt_copyaddr_sum: csum_eeo_mismatch "
		    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_eeo_ref,
		    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
		    SK_KVA(buffer));
	}
	VERIFY(csum_eeo_ref == csum);

	if (test_unaligned) {
		csum = pkt_copyaddr_sum(ph_mb, 0, buffer + 1, len - 1, TRUE, 0, NULL);
		if (csum_eoo_ref != csum) {
			SK_ERR("pkt_copyaddr_sum: csum_eoo_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_eoo_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(buffer));
		}
		VERIFY(csum_eoo_ref == csum);

		csum = pkt_copyaddr_sum(ph_mb, 0, buffer + 1, len - 2, TRUE, 0, NULL);
		if (csum_eoe_ref != csum) {
			SK_ERR("pkt_copyaddr_sum: csum_eoe_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_eoe_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(buffer));
		}
		VERIFY(csum_eoe_ref == csum);

		csum = pkt_copyaddr_sum(ph_mb, 1, buffer + 1, len - 2, TRUE, 0, NULL);
		if (csum_ooe_ref != csum) {
			SK_ERR("pkt_copyaddr_sum: csum_ooe_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_ooe_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(buffer));
		}
		VERIFY(csum_ooe_ref == csum);

		csum = pkt_copyaddr_sum(ph_mb, 1, buffer, len - 2, TRUE, 0, NULL);
		if (csum_oee_ref != csum) {
			SK_ERR("pkt_copyaddr_sum: csum_oee_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_oee_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(buffer));
		}
		VERIFY(csum_oee_ref == csum);

		csum = pkt_copyaddr_sum(ph_mb, 1, buffer, len - 1, TRUE, 0, NULL);
		if (csum_oeo_ref != csum) {
			SK_ERR("pkt_copyaddr_sum: csum_oeo_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_oeo_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(buffer));
		}
		VERIFY(csum_oeo_ref == csum);

		csum = pkt_copyaddr_sum(ph_mb, 1, buffer + 1, len - 1, TRUE, 0, NULL);
		if (csum_ooo_ref != csum) {
			SK_ERR("pkt_copyaddr_sum: csum_ooo_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_ooo_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(buffer));
		}
		VERIFY(csum_ooo_ref == csum);
	}

	csum = pkt_copyaddr_sum(ph_mb, 0, buffer, len, TRUE, 0, NULL);
	if (csum_eee_ref != csum) {
		SK_ERR("pkt_copyaddr_sum: csum_eee_mismatch "
		    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_eee_ref,
		    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
		    SK_KVA(buffer));
	}
	VERIFY(csum_eee_ref == csum);

	for (i = 0; i < len; i++) {
		VERIFY(buffer[i] == (i & 0xff));
	}
	kern_pbufpool_free(pp_mb, ph_mb);
	ph_mb = 0;

	if (test_unaligned) {
		/* verify copy-checksum from mbuf to packet */
		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		VERIFY(kern_packet_get_buflet_count(ph_mb) == 4);
		csum = pkt_mcopypkt_sum(m, 0, ph_mb, 0, len, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 0);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 0;
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_eee_ref != csum) {
			SK_ERR("pkt_mcopypkt_sum: csum_eee_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_eee_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(m));
		}
		VERIFY(csum_eee_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;

		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		VERIFY(kern_packet_get_buflet_count(ph_mb) == 4);
		csum = pkt_mcopypkt_sum(m, 0, ph_mb, 1, len - 2, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 1);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 1;
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_eoe_ref != csum) {
			SK_ERR("pkt_mcopypkt_sum: csum_eoe_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_eoe_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(m));
		}
		VERIFY(csum_eoe_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;

		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		VERIFY(kern_packet_get_buflet_count(ph_mb) == 4);
		csum = pkt_mcopypkt_sum(m, 0, ph_mb, 1, len - 1, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 1);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 1;
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_eoo_ref != csum) {
			SK_ERR("pkt_mcopypkt_sum: csum_eoo_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_eoo_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(m));
		}
		VERIFY(csum_eoo_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;
	}

	VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
	VERIFY(kern_packet_get_buflet_count(ph_mb) == 4);
	csum = pkt_mcopypkt_sum(m, 0, ph_mb, 0, len - 1, TRUE);
	METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 0);
	SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 0;
	SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
	VERIFY(__packet_finalize(ph_mb) == 0);
	if (csum_eeo_ref != csum) {
		SK_ERR("pkt_mcopypkt_sum: csum_eeo_mismatch "
		    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_eeo_ref,
		    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
		    SK_KVA(m));
	}
	VERIFY(csum_eeo_ref == csum);
	kern_pbufpool_free(pp_mb, ph_mb);
	ph_mb = 0;

	if (test_unaligned) {
		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		VERIFY(kern_packet_get_buflet_count(ph_mb) == 4);
		csum = pkt_mcopypkt_sum(m, 1, ph_mb, 0, len - 1, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 0);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 0;
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_oeo_ref != csum) {
			SK_ERR("pkt_mcopypkt_sum: csum_oeo_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_oeo_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(m));
		}
		VERIFY(csum_oeo_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;

		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		VERIFY(kern_packet_get_buflet_count(ph_mb) == 4);
		csum = pkt_mcopypkt_sum(m, 1, ph_mb, 0, len - 2, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 0);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 0;
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_oee_ref != csum) {
			SK_ERR("pkt_mcopypkt_sum: csum_oee_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_oee_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(m));
		}
		VERIFY(csum_oee_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;

		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		VERIFY(kern_packet_get_buflet_count(ph_mb) == 4);
		csum = pkt_mcopypkt_sum(m, 1, ph_mb, 1, len - 2, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 1);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 1;
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_ooe_ref != csum) {
			SK_ERR("pkt_mcopypkt_sum: csum_ooe_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_ooe_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(m));
		}
		VERIFY(csum_ooe_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;

		VERIFY(kern_pbufpool_alloc(pp_mb, 4, &ph_mb) == 0);
		VERIFY(kern_packet_get_buflet_count(ph_mb) == 4);
		csum = pkt_mcopypkt_sum(m, 1, ph_mb, 1, len - 1, TRUE);
		METADATA_ADJUST_LEN(SK_PTR_ADDR_KQUM(ph_mb), 0, 1);
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_headroom = 1;
		SK_PTR_ADDR_KPKT(ph_mb)->pkt_l2_len = 0;
		VERIFY(__packet_finalize(ph_mb) == 0);
		if (csum_ooo_ref != csum) {
			SK_ERR("pkt_mcopypkt_sum: csum_ooo_mismatch "
			    "0x%x, 0x%x, 0x%llx, 0x%llx", csum_ooo_ref,
			    csum, SK_KVA(SK_PTR_ADDR_KQUM(ph_mb)),
			    SK_KVA(m));
		}
		VERIFY(csum_ooo_ref == csum);
		kern_pbufpool_free(pp_mb, ph_mb);
		ph_mb = 0;
	}

	kern_pbufpool_free(pp, ph);
	ph = 0;
	m_freem(m);
	m = NULL;
	kern_pbufpool_destroy(pp_mb);
	pp_mb = NULL;
	kern_pbufpool_destroy(pp);
	pp = NULL;

	kfree_data(ref_buffer, SKMEM_TEST_BUFSIZE);
	ref_buffer = NULL;
}

static void
skmem_quantum_tests(uint32_t flags)
{
	struct kern_pbufpool_init pp_init;
	struct kern_pbufpool_memory_info pp_mem_info;
	kern_pbufpool_t pp = NULL;
	kern_packet_t *phary = NULL;
	uint32_t phcnt = 0;
	kern_packet_t ph = 0;
	uint32_t i;
	errno_t err;

	flags |= KBIF_QUANTUM;

	SK_ERR("flags 0x%x", flags);

	phary = (kern_packet_t *) kalloc_data(sizeof(kern_packet_t) * MAX_PH_ARY,
	    Z_WAITOK | Z_ZERO);

	bzero(&pp_init, sizeof(pp_init));
	pp_init.kbi_version = KERN_PBUFPOOL_CURRENT_VERSION;
	pp_init.kbi_buf_seg_size = skmem_usr_buf_seg_size;
	(void) snprintf((char *)pp_init.kbi_name, sizeof(pp_init.kbi_name),
	    "%s", "skmem_quantum_tests");
	pp_init.kbi_flags = (KBIF_QUANTUM | flags);
	pp_init.kbi_packets = 64;
	pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
	pp_init.kbi_buflets = (64 * 2);
	pp_init.kbi_ctx = NULL;
	pp_init.kbi_ctx_retain = NULL;
	pp_init.kbi_ctx_release = NULL;

	pp_init.kbi_max_frags = 4;
	/* max_frags must be 1 for quantum type */
	VERIFY(kern_pbufpool_create(&pp_init, &pp, NULL) == EINVAL);
	pp_init.kbi_max_frags = 1;
	if ((flags & KBIF_QUANTUM) && (flags & KBIF_BUFFER_ON_DEMAND)) {
		VERIFY(kern_pbufpool_create(&pp_init, &pp, NULL) == EINVAL);
		goto done;
	}
	VERIFY(kern_pbufpool_create(&pp_init, &pp, NULL) == 0);
	bzero(&pp_mem_info, sizeof(pp_mem_info));
	VERIFY(kern_pbufpool_get_memory_info(pp, &pp_mem_info) == 0);
	VERIFY(pp_mem_info.kpm_flags & KPMF_EXTERNAL);
	VERIFY(pp_mem_info.kpm_buflets >= pp_mem_info.kpm_packets);
	VERIFY(pp_mem_info.kpm_packets >= 64);
	VERIFY(pp_mem_info.kpm_packets <= MAX_PH_ARY);
	VERIFY(pp_mem_info.kpm_max_frags == 1);
	VERIFY(pp_mem_info.kpm_buflets >= 64);
	VERIFY(pp_mem_info.kpm_bufsize == SKMEM_TEST_BUFSIZE);
	VERIFY(kern_pbufpool_alloc(pp, 4, &ph) == EINVAL);
	/* allocate and free one at a time */
	for (i = 0, phcnt = 0; i < pp_mem_info.kpm_packets; i++) {
		boolean_t stop = FALSE;
		/*
		 * This may fail if skmem_region_mtbf is set, or if
		 * the system is short on memory.  Perform retries
		 * at this layer to get at least 64 packets.
		 */
		while ((err = kern_pbufpool_alloc_nosleep(pp, 1, &ph)) != 0) {
			VERIFY(err == ENOMEM);
			if (phcnt < 64) {
				SK_ERR("retrying alloc for quantum %u", phcnt);
				delay(250 * NSEC_PER_USEC); /* 1/4 sec */
				continue;
			}
			stop = TRUE;
			break;
		}
		if (stop) {
			break;
		}
		VERIFY(ph != 0);
		VERIFY(kern_packet_get_data_length(ph) == 0);
		VERIFY(kern_packet_get_buflet_count(ph) == 1);
		phary[phcnt++] = ph;
	}
	VERIFY(phcnt >= 64);
	for (i = 0; i < phcnt; i++) {
		kern_pbufpool_free(pp, phary[i]);
		phary[i] = 0;
	}
	/* allocate and free in batch */
	phcnt = pp_mem_info.kpm_packets;
	for (;;) {
		err = kern_pbufpool_alloc_batch_nosleep(pp, 1, phary, &phcnt);
		VERIFY(err != EINVAL && err != ENOTSUP);
		if (err == ENOMEM) {
			phcnt = pp_mem_info.kpm_packets;
			SK_ERR("retrying batch alloc for %u quantums", phcnt);
			delay(250 * NSEC_PER_USEC);     /* 1/4 sec */
		} else if (err == EAGAIN) {
			SK_ERR("batch alloc for %u quantums only returned %u",
			    pp_mem_info.kpm_packets, phcnt);
			break;
		} else {
			VERIFY(err == 0);
			break;
		}
	}
	VERIFY(phcnt > 0);
	for (i = 0; i < phcnt; i++) {
		VERIFY(phary[i] != 0);
		VERIFY(kern_packet_get_data_length(phary[i]) == 0);
		VERIFY(kern_packet_get_buflet_count(phary[i]) == 1);
	}
	kern_pbufpool_free_batch(pp, phary, phcnt);
	/* allocate and free one at a time (blocking) */
	for (i = 0, phcnt = 0; i < pp_mem_info.kpm_packets; i++) {
		VERIFY(kern_pbufpool_alloc(pp, 1, &ph) == 0);
		VERIFY(ph != 0);
		VERIFY(kern_packet_get_data_length(ph) == 0);
		VERIFY(kern_packet_get_buflet_count(ph) == 1);
		phary[phcnt++] = ph;
	}
	VERIFY(phcnt >= 64);
	for (i = 0; i < phcnt; i++) {
		kern_pbufpool_free(pp, phary[i]);
		phary[i] = 0;
	}
	/* allocate and free in batch (blocking) */
	bzero(&skmt_alloccb_ctx, sizeof(skmt_alloccb_ctx));
	skmt_alloccb_ctx.stc_req = phcnt;
	VERIFY(kern_pbufpool_alloc_batch_callback(pp, 1, phary, &phcnt,
	    skmem_test_alloccb, &skmt_alloccb_ctx) == 0);
	VERIFY(skmt_alloccb_ctx.stc_idx == phcnt);
	kern_pbufpool_free_batch(pp, phary, phcnt);
	kern_pbufpool_destroy(pp);
	pp = NULL;
done:
	kfree_data(phary, sizeof(kern_packet_t) * MAX_PH_ARY);
	phary = NULL;
}

static void
skmem_basic_tests(void)
{
	/* basic sanity (alloc/free) tests on packet buflet KPIs */
	skmem_buflet_tests(0);
	skmem_buflet_tests(KBIF_PERSISTENT);
	skmem_buflet_tests(KBIF_PERSISTENT | KBIF_NO_MAGAZINES);
	skmem_buflet_tests(KBIF_PERSISTENT | KBIF_PHYS_CONTIGUOUS);
	skmem_buflet_tests(KBIF_PERSISTENT | KBIF_PHYS_CONTIGUOUS |
	    KBIF_USER_ACCESS);
	skmem_buflet_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS);
	skmem_buflet_tests(KBIF_PERSISTENT | KBIF_BUFFER_ON_DEMAND);
	skmem_buflet_tests(KBIF_PERSISTENT | TEST_OPTION_INHIBIT_CACHE);
	skmem_buflet_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND);
	skmem_buflet_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS | TEST_OPTION_INHIBIT_CACHE);
	skmem_buflet_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);
	skmem_buflet_tests(KBIF_MONOLITHIC | KBIF_PHYS_CONTIGUOUS);
	skmem_buflet_tests(KBIF_MONOLITHIC | KBIF_USER_ACCESS);
	skmem_buflet_tests(KBIF_MONOLITHIC | KBIF_USER_ACCESS |
	    KBIF_NO_MAGAZINES);
	skmem_buflet_tests(KBIF_MONOLITHIC | KBIF_PHYS_CONTIGUOUS |
	    KBIF_USER_ACCESS);
	skmem_buflet_tests(KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND);
	skmem_buflet_tests(KBIF_MONOLITHIC | KBIF_USER_ACCESS |
	    TEST_OPTION_INHIBIT_CACHE);
	skmem_buflet_tests(KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND |
	    TEST_OPTION_INHIBIT_CACHE);
	skmem_buflet_tests(KBIF_BUFFER_ON_DEMAND | KBIF_NO_MAGAZINES);
	skmem_buflet_tests(KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);

	/* basic sanity (alloc/free) tests on packet buflet KPIs (vdev) */
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_NO_MAGAZINES);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PHYS_CONTIGUOUS);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_PHYS_CONTIGUOUS);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_USER_ACCESS | KBIF_PHYS_CONTIGUOUS);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_USER_ACCESS);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_BUFFER_ON_DEMAND);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    TEST_OPTION_INHIBIT_CACHE);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_USER_ACCESS | TEST_OPTION_INHIBIT_CACHE);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_PHYS_CONTIGUOUS);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS | KBIF_PHYS_CONTIGUOUS);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS | TEST_OPTION_INHIBIT_CACHE);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_BUFFER_ON_DEMAND);
	skmem_buflet_tests(KBIF_VIRTUAL_DEVICE | KBIF_BUFFER_ON_DEMAND |
	    TEST_OPTION_INHIBIT_CACHE);

	/* check packet KPIs (also touches data) */
	skmem_packet_tests(0);
	skmem_packet_tests(KBIF_PHYS_CONTIGUOUS);
	skmem_packet_tests(KBIF_PERSISTENT);
	skmem_packet_tests(KBIF_PERSISTENT | KBIF_NO_MAGAZINES);
	skmem_packet_tests(KBIF_PERSISTENT | KBIF_PHYS_CONTIGUOUS);
	skmem_packet_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_PHYS_CONTIGUOUS | KBIF_USER_ACCESS);
	skmem_packet_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS);
	skmem_packet_tests(KBIF_PERSISTENT | KBIF_BUFFER_ON_DEMAND);
	skmem_packet_tests(KBIF_PERSISTENT | TEST_OPTION_INHIBIT_CACHE);
	skmem_packet_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND);
	skmem_packet_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS | TEST_OPTION_INHIBIT_CACHE);
	skmem_packet_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);
	skmem_packet_tests(KBIF_MONOLITHIC | KBIF_PHYS_CONTIGUOUS);
	skmem_packet_tests(KBIF_MONOLITHIC | KBIF_USER_ACCESS);
	skmem_packet_tests(KBIF_MONOLITHIC | KBIF_USER_ACCESS |
	    KBIF_NO_MAGAZINES);
	skmem_packet_tests(KBIF_MONOLITHIC | KBIF_USER_ACCESS |
	    KBIF_PHYS_CONTIGUOUS);
	skmem_packet_tests(KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND);
#if 0
	/* XXX: commented out failed tests on ARM64e platforms */
	skmem_packet_tests(KBIF_MONOLITHIC | KBIF_USER_ACCESS |
	    TEST_OPTION_INHIBIT_CACHE);
	skmem_packet_tests(KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND |
	    TEST_OPTION_INHIBIT_CACHE);
	skmem_packet_tests(KBIF_BUFFER_ON_DEMAND);
	skmem_packet_tests(KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);
#endif

	/* check packet KPIs (also touches data) (vdev) */
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_NO_MAGAZINES);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PHYS_CONTIGUOUS);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_PHYS_CONTIGUOUS);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_USER_ACCESS);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_BUFFER_ON_DEMAND);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    TEST_OPTION_INHIBIT_CACHE);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_USER_ACCESS | TEST_OPTION_INHIBIT_CACHE);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_PHYS_CONTIGUOUS);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS | KBIF_PHYS_CONTIGUOUS);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND | KBIF_PHYS_CONTIGUOUS);
#if 0
	/* XXX: commented out failed tests on ARM64e platforms */
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS | TEST_OPTION_INHIBIT_CACHE);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_BUFFER_ON_DEMAND);
	skmem_packet_tests(KBIF_VIRTUAL_DEVICE | KBIF_BUFFER_ON_DEMAND |
	    TEST_OPTION_INHIBIT_CACHE);
#endif

	/* check quantum KPIs */
	skmem_quantum_tests(0);
	skmem_quantum_tests(KBIF_PHYS_CONTIGUOUS);
	skmem_quantum_tests(KBIF_PERSISTENT);
	skmem_quantum_tests(KBIF_PERSISTENT | KBIF_NO_MAGAZINES);
	skmem_quantum_tests(KBIF_PERSISTENT | KBIF_PHYS_CONTIGUOUS);
	skmem_quantum_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS);
	skmem_quantum_tests(KBIF_PERSISTENT | KBIF_BUFFER_ON_DEMAND);
	skmem_quantum_tests(KBIF_PERSISTENT | TEST_OPTION_INHIBIT_CACHE);
	skmem_quantum_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND);
	skmem_quantum_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS | TEST_OPTION_INHIBIT_CACHE);
	skmem_quantum_tests(KBIF_PERSISTENT | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);
	skmem_quantum_tests(KBIF_MONOLITHIC | KBIF_PHYS_CONTIGUOUS);
	skmem_quantum_tests(KBIF_MONOLITHIC | KBIF_USER_ACCESS);
	skmem_quantum_tests(KBIF_MONOLITHIC | KBIF_USER_ACCESS |
	    KBIF_PHYS_CONTIGUOUS);
	skmem_quantum_tests(KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND);
	skmem_quantum_tests(KBIF_MONOLITHIC | KBIF_USER_ACCESS |
	    TEST_OPTION_INHIBIT_CACHE);
	skmem_quantum_tests(KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND |
	    TEST_OPTION_INHIBIT_CACHE);
	skmem_quantum_tests(KBIF_BUFFER_ON_DEMAND);
	skmem_quantum_tests(KBIF_BUFFER_ON_DEMAND | KBIF_NO_MAGAZINES);
	skmem_quantum_tests(KBIF_BUFFER_ON_DEMAND | KBIF_PHYS_CONTIGUOUS);
	skmem_quantum_tests(KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);

	/* check quantum KPIs (vdev) */
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_NO_MAGAZINES);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_PHYS_CONTIGUOUS);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_USER_ACCESS);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_BUFFER_ON_DEMAND);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    TEST_OPTION_INHIBIT_CACHE);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_USER_ACCESS | TEST_OPTION_INHIBIT_CACHE);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_PERSISTENT |
	    KBIF_MONOLITHIC | KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_PHYS_CONTIGUOUS);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS | KBIF_PHYS_CONTIGUOUS);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_USER_ACCESS | TEST_OPTION_INHIBIT_CACHE);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_MONOLITHIC |
	    KBIF_BUFFER_ON_DEMAND | TEST_OPTION_INHIBIT_CACHE);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_BUFFER_ON_DEMAND);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_BUFFER_ON_DEMAND |
	    KBIF_PHYS_CONTIGUOUS);
	skmem_quantum_tests(KBIF_VIRTUAL_DEVICE | KBIF_BUFFER_ON_DEMAND |
	    TEST_OPTION_INHIBIT_CACHE);
}

static void
skmem_advanced_tests(int n, int32_t th_max, uint32_t mode, boolean_t nosleep,
    uint32_t flags)
{
	struct kern_pbufpool_init pp_init;
	kern_packet_t mph = 0;
	kern_buflet_t buflet = 0;
	int i;

	VERIFY(skmth_pp == NULL);
	VERIFY(skmth_cnt == 0);

	bzero(&pp_init, sizeof(pp_init));
	pp_init.kbi_version = KERN_PBUFPOOL_CURRENT_VERSION;
	pp_init.kbi_buf_seg_size = skmem_usr_buf_seg_size;
	pp_init.kbi_flags |= flags;
	(void) snprintf((char *)pp_init.kbi_name,
	    sizeof(pp_init.kbi_name), "%s", "skmem_advanced");

	/* prepare */
	switch (mode) {
	case 0:
		pp_init.kbi_packets = th_max;
		pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
		pp_init.kbi_max_frags = 1;
		pp_init.kbi_flags |= KBIF_MONOLITHIC | KBIF_USER_ACCESS;
		VERIFY(kern_pbufpool_create(&pp_init,
		    &skmth_pp, NULL) == 0);
		break;

	case 1:
		pp_init.kbi_packets = th_max;
		pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
		pp_init.kbi_max_frags = 1;
		pp_init.kbi_flags |= KBIF_MONOLITHIC | KBIF_USER_ACCESS |
		    KBIF_VIRTUAL_DEVICE;
		VERIFY(kern_pbufpool_create(&pp_init,
		    &skmth_pp, NULL) == 0);
		break;

	case 2:
		pp_init.kbi_packets = th_max;
		pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
		pp_init.kbi_max_frags = 1;
		pp_init.kbi_flags |= KBIF_MONOLITHIC | KBIF_USER_ACCESS |
		    KBIF_PERSISTENT;
		VERIFY(kern_pbufpool_create(&pp_init,
		    &skmth_pp, NULL) == 0);
		break;

	case 3:
		pp_init.kbi_packets = th_max;
		pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
		pp_init.kbi_max_frags = 1;
		pp_init.kbi_flags |= KBIF_MONOLITHIC | KBIF_USER_ACCESS |
		    KBIF_PERSISTENT | KBIF_VIRTUAL_DEVICE;
		VERIFY(kern_pbufpool_create(&pp_init,
		    &skmth_pp, NULL) == 0);
		break;

	case 4:
		pp_init.kbi_packets = th_max;
		pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
		pp_init.kbi_max_frags = 1;
		pp_init.kbi_flags |= KBIF_PERSISTENT | KBIF_USER_ACCESS;
		VERIFY(kern_pbufpool_create(&pp_init,
		    &skmth_pp, NULL) == 0);
		break;

	case 5:
		pp_init.kbi_packets = th_max;
		pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
		pp_init.kbi_max_frags = 1;
		pp_init.kbi_flags |= KBIF_PERSISTENT | KBIF_VIRTUAL_DEVICE;
		VERIFY(kern_pbufpool_create(&pp_init,
		    &skmth_pp, NULL) == 0);
		break;

	case 6:
		pp_init.kbi_packets = th_max;
		pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
		pp_init.kbi_max_frags = 1;
		pp_init.kbi_flags |= 0;
		VERIFY(kern_pbufpool_create(&pp_init,
		    &skmth_pp, NULL) == 0);
		break;

	case 7:
		pp_init.kbi_packets = th_max;
		pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
		pp_init.kbi_max_frags = 1;
		pp_init.kbi_flags |= KBIF_VIRTUAL_DEVICE;
		VERIFY(kern_pbufpool_create(&pp_init,
		    &skmth_pp, NULL) == 0);
		break;

	case 8:
		pp_init.kbi_packets = (th_max * 2) + 1;
		pp_init.kbi_bufsize = SKMEM_TEST_BUFSIZE;
		pp_init.kbi_max_frags = 1;
		pp_init.kbi_flags |= KBIF_BUFFER_ON_DEMAND;
		VERIFY(kern_pbufpool_create(&pp_init,
		    &skmth_pp, NULL) == 0);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	SK_ERR("%d: th_max %d mode %u nosleep %u nomagazines %u",
	    n, th_max, mode, nosleep, !!(flags & KBIF_NO_MAGAZINES));

	if (pp_init.kbi_flags & KBIF_BUFFER_ON_DEMAND) {
		/* create 1 master packet to clone */
		VERIFY(kern_pbufpool_alloc(skmth_pp, 1, &mph) == 0);
		VERIFY((buflet = kern_packet_get_next_buflet(mph, NULL)) != NULL);
		VERIFY(kern_buflet_set_data_length(buflet, SKMEM_TEST_BUFSIZE) == 0);
		VERIFY(__packet_finalize(mph) == 0);
	}

	bzero(skmth_info, skmth_info_size);

	/* spawn as many threads as there are CPUs */
	for (i = 0; i < th_max; i++) {
		skmth_info[i].sti_mph = mph;
		skmth_info[i].sti_nosleep = nosleep;
		if (kernel_thread_start(skmem_test_func, (void *)(uintptr_t)i,
		    &skmth_info[i].sti_thread) != KERN_SUCCESS) {
			panic("Failed to create skmem test thread");
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}

	lck_mtx_lock(&skmt_lock);
	do {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * USEC_PER_SEC };
		(void) msleep(&skmth_cnt, &skmt_lock, (PZERO - 1),
		    "skmtstartw", &ts);
	} while (skmth_cnt < th_max);
	VERIFY(skmth_cnt == th_max);
	lck_mtx_unlock(&skmt_lock);

	lck_mtx_lock(&skmt_lock);
	VERIFY(!skmth_run);
	skmth_run = TRUE;
	wakeup((caddr_t)&skmth_run);
	lck_mtx_unlock(&skmt_lock);

	/* wait until all threads are done */
	lck_mtx_lock(&skmt_lock);
	do {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * USEC_PER_SEC };
		(void) msleep(&skmth_cnt, &skmt_lock, (PZERO - 1),
		    "skmtstopw", &ts);
	} while (skmth_cnt != 0);
	skmth_run = FALSE;
	lck_mtx_unlock(&skmt_lock);

	if (mph != 0) {
		VERIFY((buflet = kern_packet_get_next_buflet( mph, NULL)) != NULL);
		VERIFY(buflet->buf_ctl->bc_usecnt == 1);
		kern_pbufpool_free(skmth_pp, mph);
		mph = 0;
	}
	kern_pbufpool_destroy(skmth_pp);
	skmth_pp = NULL;
}

__attribute__((noreturn))
static void
skmem_test_func(void *v, wait_result_t w)
{
#pragma unused(w)
	int i = (int)(uintptr_t)v, c;
	kern_packet_t ph = 0;

	/* let skmem_test_start() know we're ready */
	lck_mtx_lock(&skmt_lock);
	os_atomic_inc(&skmth_cnt, relaxed);
	wakeup((caddr_t)&skmth_cnt);
	do {
		(void) msleep(&skmth_run, &skmt_lock, (PZERO - 1),
		    "skmtfuncw", NULL);
	} while (!skmth_run);
	lck_mtx_unlock(&skmt_lock);

	for (c = 0; c < 41; c++) {
		/* run alloc tests */
		VERIFY(skmth_pp != NULL);
		if (skmth_info[i].sti_nosleep) {
			errno_t err = kern_pbufpool_alloc_nosleep(skmth_pp,
			    1, &ph);
			VERIFY(ph != 0 || err != 0);
		} else {
			VERIFY(kern_pbufpool_alloc(skmth_pp, 1, &ph) == 0);
		}

		if (ph != 0) {
			kern_pbufpool_free(skmth_pp, ph);
			ph = 0;
		}

		/* run clone tests */
		if (skmth_info[i].sti_mph != 0) {
			kern_buflet_t buflet, buflet2;
			kern_obj_idx_seg_t buf_idx_seg, buf2_idx_seg;

			if (skmth_info[i].sti_nosleep) {
				errno_t err;
				err = kern_packet_clone_nosleep(skmth_info[i].sti_mph,
				    &skmth_info[i].sti_mpc, KPKT_COPY_LIGHT);
				VERIFY(skmth_info[i].sti_mpc != 0 || err != 0);
			} else {
				VERIFY(kern_packet_clone(skmth_info[i].sti_mph,
				    &skmth_info[i].sti_mpc, KPKT_COPY_LIGHT) == 0);
			}
			if (skmth_info[i].sti_mpc != 0) {
				VERIFY(!(QUM_ADDR(skmth_info[i].sti_mpc)->qum_qflags & QUM_F_FINALIZED));
				VERIFY((buflet = kern_packet_get_next_buflet(
					    skmth_info[i].sti_mph, NULL)) != NULL);
				VERIFY((buflet2 = kern_packet_get_next_buflet(
					    skmth_info[i].sti_mpc, NULL)) != NULL);
				VERIFY(kern_buflet_get_object_address(buflet) ==
				    kern_buflet_get_object_address(buflet2));
				VERIFY(kern_buflet_get_data_address(buflet) ==
				    kern_buflet_get_data_address(buflet2));
				VERIFY(kern_buflet_get_data_limit(buflet) ==
				    kern_buflet_get_data_limit(buflet2));
				VERIFY(kern_buflet_get_data_offset(buflet) ==
				    kern_buflet_get_data_offset(buflet2));
				VERIFY(kern_buflet_get_data_length(buflet) ==
				    kern_buflet_get_data_length(buflet2));
				VERIFY(kern_buflet_get_object_segment(buflet,
				    &buf_idx_seg) ==
				    kern_buflet_get_object_segment(buflet2,
				    &buf2_idx_seg));
				VERIFY(buf_idx_seg == buf2_idx_seg);
				VERIFY(buflet->buf_ctl == buflet2->buf_ctl);
				VERIFY(__packet_finalize(skmth_info[i].sti_mpc) == 0);
				kern_pbufpool_free(skmth_pp, skmth_info[i].sti_mpc);
				skmth_info[i].sti_mpc = 0;
			}
			skmth_info[i].sti_mph = 0;
		}

		/* force cache purges to exercise related code paths */
		if (skmth_pp->pp_kmd_cache != NULL) {
			skmem_cache_reap_now(skmth_pp->pp_kmd_cache, TRUE);
		}
		if (PP_BUF_CACHE_DEF(skmth_pp) != NULL) {
			skmem_cache_reap_now(PP_BUF_CACHE_DEF(skmth_pp), TRUE);
		}
		if (PP_KBFT_CACHE_DEF(skmth_pp) != NULL) {
			skmem_cache_reap_now(PP_KBFT_CACHE_DEF(skmth_pp), TRUE);
		}
	}

	/* let skmem_test_start() know we're finished */
	lck_mtx_lock(&skmt_lock);
	VERIFY(os_atomic_dec_orig(&skmth_cnt, relaxed) != 0);
	wakeup((caddr_t)&skmth_cnt);
	lck_mtx_unlock(&skmt_lock);

	/* for the extra refcnt from kernel_thread_start() */
	thread_deallocate(current_thread());

	thread_terminate(current_thread());
	__builtin_unreachable();
	/* NOTREACHED */
}

static int skmem_test_objs;

struct skmem_test_obj {
	uint64_t        sto_val[2];
};

static int
skmem_test_ctor(struct skmem_obj_info *oi, struct skmem_obj_info *oim,
    void *arg, uint32_t skmflag)
{
#pragma unused(skmflag)
	struct skmem_test_obj *sto = SKMEM_OBJ_ADDR(oi);

	VERIFY(oim == NULL);
	VERIFY(arg == &skmem_test_init);
	VERIFY(SKMEM_OBJ_SIZE(oi) >= sizeof(struct skmem_test_obj));
	sto->sto_val[0] = (uint64_t)(void *)sto ^
	    (uint64_t)(void *)&sto->sto_val[0];
	sto->sto_val[1] = (uint64_t)(void *)sto ^
	    (uint64_t)(void *)&sto->sto_val[1];
	os_atomic_inc(&skmem_test_objs, relaxed);

	return 0;
}

static void
skmem_test_dtor(void *addr, void *arg)
{
	struct skmem_test_obj *sto = addr;

	VERIFY(arg == &skmem_test_init);
	VERIFY((sto->sto_val[0] ^ (uint64_t)(void *)&sto->sto_val[0]) ==
	    (uint64_t)(void *)sto);
	VERIFY((sto->sto_val[1] ^ (uint64_t)(void *)&sto->sto_val[1]) ==
	    (uint64_t)(void *)sto);
	VERIFY(skmem_test_objs > 0);
	os_atomic_dec(&skmem_test_objs, relaxed);
}

static void
skmem_tests(uint32_t align)
{
	struct skmem_cache *skm;
	uint32_t bufsize = sizeof(struct skmem_test_obj);

	uint32_t objary_max = (uint32_t)MAX_PH_ARY;
	void **objary = NULL;
	char name[64];

	VERIFY(align != 0);

	SK_ERR("bufsize %u align %u", bufsize, align);

	objary = kalloc_type(void *, objary_max, Z_WAITOK | Z_ZERO);

	(void) snprintf(name, sizeof(name), "skmem_test.%u.%u", bufsize, align);

	skm = skmem_cache_create(name, bufsize, align, skmem_test_ctor,
	    skmem_test_dtor, NULL, &skmem_test_init, NULL, 0);

	VERIFY(skmem_test_objs == 0);
	for (int i = 0; i < objary_max; i++) {
		objary[i] = skmem_cache_alloc(skm, SKMEM_SLEEP);
		VERIFY(objary[i] != NULL);
		VERIFY(IS_P2ALIGNED(objary[i], align));
	}
	for (int i = 0; i < objary_max; i++) {
		VERIFY(objary[i] != NULL);
		skmem_cache_free(skm, objary[i]);
		objary[i] = NULL;
	}
	skmem_cache_destroy(skm);
	VERIFY(skmem_test_objs == 0);

	kfree_type(void *, objary_max, objary);
	objary = NULL;
}

static void
skmem_test_start(void *v, wait_result_t w)
{
	int32_t ncpus = ml_wait_max_cpus();
	int error = 0, n;
	uint32_t flags;
	uint64_t mtbf_saved;

	lck_mtx_lock(&skmt_lock);
	VERIFY(!skmt_busy);
	skmt_busy = 1;
	skmem_cache_test_start(1);      /* 1 second update interval */
	lck_mtx_unlock(&skmt_lock);

	VERIFY(skmth_info == NULL);
	skmth_info_size = sizeof(struct skmt_thread_info) * ncpus;
	skmth_info = (struct skmt_thread_info *) kalloc_data(skmth_info_size,
	    Z_WAITOK | Z_ZERO);

	/*
	 * Sanity tests.
	 */
	(void) skmem_cache_magazine_max(1);
	(void) skmem_cache_magazine_max(32);
	(void) skmem_cache_magazine_max(64);
	(void) skmem_cache_magazine_max(128);
	(void) skmem_cache_magazine_max(256);
	(void) skmem_cache_magazine_max(512);
	(void) skmem_cache_magazine_max(1024);
	(void) skmem_cache_magazine_max(2048);
	(void) skmem_cache_magazine_max(4096);
	(void) skmem_cache_magazine_max(8192);
	(void) skmem_cache_magazine_max(16384);
	(void) skmem_cache_magazine_max(32768);
	(void) skmem_cache_magazine_max(65536);

	/*
	 * skmem allocator tests
	 */
	skmem_tests(8);
	skmem_tests(16);
	skmem_tests(32);
	skmem_tests(64);
	skmem_tests(128);

	/*
	 * Basic packet buffer pool sanity tests
	 */
	skmem_basic_tests();

	/*
	 * Multi-threaded alloc and free tests (blocking).
	 */
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 0, FALSE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 0, TRUE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 1, FALSE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 1, TRUE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 2, FALSE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 2, TRUE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 3, FALSE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 3, TRUE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 4, FALSE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 5, FALSE, flags);
	}

	/*
	 * Modes 4-5 deal with persistent/mirrored regions, and to
	 * maximize the chance of exercising the allocation failures
	 * handling we lower the MTBF (if set) to the minimum possible,
	 * and restore it to the saved value later.
	 */
	mtbf_saved = skmem_region_get_mtbf();
	if (mtbf_saved != 0) {
		skmem_region_set_mtbf(SKMEM_REGION_MTBF_MIN);
	}

	/*
	 * Multi-threaded alloc and free tests (non-blocking).
	 */

	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 4, TRUE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 5, TRUE, flags);
	}

	/*
	 * Restore MTBF to previous set value.
	 */
	if (mtbf_saved != 0) {
		skmem_region_set_mtbf(mtbf_saved);
	}

	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 6, FALSE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 6, TRUE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 7, FALSE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 7, TRUE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 8, FALSE, flags);
	}
	for (n = 0; n < 7; n++) {
		flags = ((n & 1) ? KBIF_NO_MAGAZINES : 0);
		skmem_advanced_tests(n, ncpus, 8, TRUE, flags);
	}

	lck_mtx_lock(&skmt_lock);
	skmt_enabled = 1;
	wakeup((caddr_t)&skmt_enabled);
	lck_mtx_unlock(&skmt_lock);

	if (error != 0) {
		skmem_test_stop(v, w);
	}
}

static void
skmem_test_stop(void *v, wait_result_t w)
{
#pragma unused(v, w)

	if (skmth_info != NULL) {
		kfree_data(skmth_info, skmth_info_size);
		skmth_info = NULL;
	}

	lck_mtx_lock(&skmt_lock);
	skmem_cache_test_stop();
	VERIFY(skmt_busy);
	skmt_busy = 0;
	skmt_enabled = 0;
	wakeup((caddr_t)&skmt_enabled);
	lck_mtx_unlock(&skmt_lock);
}

static int
sysctl_skmem_test(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error, newvalue, changed;

	lck_mtx_lock(&skmt_lock);
	if ((error = sysctl_io_number(req, skmt_enabled, sizeof(int),
	    &newvalue, &changed)) != 0) {
		goto done;
	}

	if (changed && skmt_enabled != newvalue) {
		thread_t th;
		thread_continue_t func;

		if (newvalue && skmt_busy) {
			SK_ERR("Older skmem test instance is still active");
			error = EBUSY;
			goto done;
		}

		if (newvalue) {
			func = skmem_test_start;
		} else {
			func = skmem_test_stop;
		}

		if (kernel_thread_start(func, NULL, &th) != KERN_SUCCESS) {
			SK_ERR("Failed to create skmem test action thread");
			error = EBUSY;
			goto done;
		}
		do {
			SK_DF(SK_VERB_MEM, "Waiting for %s to complete",
			    newvalue ? "startup" : "shutdown");
			error = msleep(&skmt_enabled, &skmt_lock,
			    PWAIT | PCATCH, "skmtw", NULL);
			/* BEGIN CSTYLED */
			/*
			 * Loop exit conditions:
			 *   - we were interrupted
			 *     OR
			 *   - we are starting up and are enabled
			 *     (Startup complete)
			 *     OR
			 *   - we are starting up and are not busy
			 *     (Failed startup)
			 *     OR
			 *   - we are shutting down and are not busy
			 *     (Shutdown complete)
			 */
			/* END CSTYLED */
		} while (!((error == EINTR) || (newvalue && skmt_enabled) ||
		    (newvalue && !skmt_busy) || (!newvalue && !skmt_busy)));

		thread_deallocate(th);
	}

done:
	lck_mtx_unlock(&skmt_lock);
	return error;
}

SYSCTL_PROC(_kern_skywalk_mem, OID_AUTO, test,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, NULL, 0,
    sysctl_skmem_test, "I", "Start Skywalk memory test");

__typed_allocators_ignore_pop

#endif /* DEVELOPMENT || DEBUG */
