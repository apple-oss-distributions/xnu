/*
 * Copyright (c) 2016-2022 Apple Inc. All rights reserved.
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

#include <skywalk/os_skywalk_private.h>
#include <skywalk/packet/pbufpool_var.h>

static errno_t kern_pbufpool_alloc_common(const kern_pbufpool_t,
    const uint32_t, kern_packet_t *, uint32_t);
static errno_t kern_pbufpool_alloc_batch_common(const kern_pbufpool_t,
    const uint32_t, kern_packet_t *, uint32_t *, alloc_cb_func_t,
    const void *, uint32_t);

#define KBI_INVALID_CB_PAIRS(cb1, cb2)                                  \
	(!(init->kbi_##cb1 == NULL && init->kbi_##cb2 == NULL) &&       \
	((init->kbi_##cb1 == NULL) ^ (init->kbi_##cb2 == NULL)))

errno_t
kern_pbufpool_create(const struct kern_pbufpool_init *init,
    kern_pbufpool_t *ppp, struct kern_pbufpool_memory_info *pp_info)
{
	/* XXX: woodford_s - find a way to get 'srp' off the kernel stack */
	struct skmem_region_params srp[SKMEM_REGIONS];
	struct kern_pbufpool *pp = NULL;
	nexus_meta_type_t md_type;
	nexus_meta_subtype_t md_subtype;
	uint32_t buf_cnt;
	uint16_t max_frags;
	uint32_t ppcreatef = PPCREATEF_EXTERNAL;
	uint32_t pkt_cnt;
	uint32_t pp_region_flags = 0;
	int err = 0;
	bool kernel_only;
	bool tx_pool = true;

	if (ppp == NULL || init == NULL ||
	    init->kbi_version != KERN_PBUFPOOL_CURRENT_VERSION ||
	    init->kbi_packets == 0 || (init->kbi_buflets != 0 &&
	    init->kbi_buflets < init->kbi_packets &&
	    !(init->kbi_flags & KBIF_BUFFER_ON_DEMAND)) ||
	    init->kbi_bufsize == 0 || init->kbi_max_frags == 0 ||
	    ((init->kbi_flags & KBIF_QUANTUM) &&
	    (init->kbi_flags & KBIF_BUFFER_ON_DEMAND)) ||
	    KBI_INVALID_CB_PAIRS(buf_seg_ctor, buf_seg_dtor)) {
		err = EINVAL;
		goto done;
	}

	*ppp = NULL;

	md_type = ((init->kbi_flags & KBIF_QUANTUM) ?
	    NEXUS_META_TYPE_QUANTUM : NEXUS_META_TYPE_PACKET);

	/*
	 * If packet, we assume this is for a driver handling raw frames.
	 * This also implies that at present, we do not create mirrored
	 * regions for user space to conserve memory (since those regions
	 * aren't going to be used anyway.)
	 *
	 * XXX: adi@apple.com - to allow for "direct" channels from
	 * user process to driver, we will need to revisit this.
	 */
	md_subtype = ((md_type == NEXUS_META_TYPE_QUANTUM) ?
	    NEXUS_META_SUBTYPE_PAYLOAD : NEXUS_META_SUBTYPE_RAW);
	kernel_only = (md_type == NEXUS_META_TYPE_PACKET) &&
#if (DEVELOPMENT || DEBUG)
	    !skywalk_netif_direct_enabled() &&
#endif /* (DEVELOPMENT || DEBUG) */
	    ((init->kbi_flags & KBIF_USER_ACCESS) == 0);

	VERIFY((init->kbi_max_frags != 0) &&
	    (init->kbi_max_frags <= UINT16_MAX));
	max_frags = (uint16_t)init->kbi_max_frags;
	if (md_type == NEXUS_META_TYPE_QUANTUM && max_frags > 1) {
		err = EINVAL;
		goto done;
	}
	if ((max_frags > 1) && !(init->kbi_flags & KBIF_BUFFER_ON_DEMAND)) {
		err = EINVAL;
		goto done;
	}

	bzero(&srp, sizeof(srp));
	for (int i = 0; i < SKMEM_REGIONS; i++) {
		srp[i] = *skmem_get_default(i);
	}

	switch (init->kbi_flags & (KBIF_IODIR_IN | KBIF_IODIR_OUT)) {
	case KBIF_IODIR_IN:
		pp_region_flags |= PP_REGION_CONFIG_BUF_IODIR_IN;
		tx_pool = false;
		break;
	case KBIF_IODIR_OUT:
		pp_region_flags |= PP_REGION_CONFIG_BUF_IODIR_OUT;
		break;
	case (KBIF_IODIR_IN | KBIF_IODIR_OUT):
	default:
		pp_region_flags |= PP_REGION_CONFIG_BUF_IODIR_BIDIR;
		break;
	}

	if (init->kbi_flags & KBIF_BUFFER_ON_DEMAND) {
		pp_region_flags |= PP_REGION_CONFIG_BUFLET;
		if (init->kbi_flags & KBIF_RAW_BFLT) {
			pp_region_flags |= PP_REGION_CONFIG_RAW_BUFLET;
		}
	}
	if (kernel_only) {
		pp_region_flags |= PP_REGION_CONFIG_KERNEL_ONLY;
	}
	if (init->kbi_flags & KBIF_KERNEL_READONLY) {
		pp_region_flags |= PP_REGION_CONFIG_BUF_KREADONLY;
	}
	if (init->kbi_flags & KBIF_THREADSAFE) {
		pp_region_flags |= PP_REGION_CONFIG_BUF_THREADSAFE;
	}
	/*
	 * Enable magazine layer for metadata.
	 */
	if (!(init->kbi_flags & KBIF_NO_MAGAZINES)) {
		pp_region_flags |= PP_REGION_CONFIG_MD_MAGAZINE_ENABLE;
	}
	pp_region_flags |= PP_REGION_CONFIG_MD_PERSISTENT;

	pkt_cnt = init->kbi_packets;
	/*
	 * For TCP to be able to send a 4MB window worth of data, packet pool
	 * must have at least 4MB/MTU packets. On devices which are not
	 * memory constrained, we can increase the pool to be atleast
	 * 4K packets.
	 */
	if (tx_pool && !SKMEM_MEM_CONSTRAINED_DEVICE() &&
#if (DEVELOPMENT || DEBUG)
	    !skmem_test_enabled() &&
#endif /* (DEVELOPMENT || DEBUG) */
	    !(init->kbi_flags & KBIF_MONOLITHIC) &&
	    !(init->kbi_flags & KBIF_VIRTUAL_DEVICE) &&
	    !(init->kbi_flags & KBIF_PHYS_CONTIGUOUS) &&
	    !(init->kbi_flags & KBIF_KERNEL_READONLY) &&
	    !(init->kbi_flags & KBIF_QUANTUM)) {
		pkt_cnt = MAX((4 * 1024), pkt_cnt);
	}
#if (DEVELOPMENT || DEBUG)
	if (sk_min_pool_size != 0) {
		pkt_cnt = MAX(pkt_cnt, sk_min_pool_size);
	}
#endif /* (DEVELOPMENT || DEBUG) */
	/* make sure # of buffers is >= # of packets */
	buf_cnt = MAX(pkt_cnt, init->kbi_buflets);

	/*
	 * Apply same logic as in nxprov_create_common().
	 */
	if (init->kbi_flags &
	    (KBIF_PERSISTENT | KBIF_MONOLITHIC | KBIF_INHIBIT_CACHE |
	    KBIF_PHYS_CONTIGUOUS)) {
		if (init->kbi_flags & KBIF_PERSISTENT) {
			pp_region_flags |= PP_REGION_CONFIG_BUF_PERSISTENT;
		}
		if (init->kbi_flags & KBIF_MONOLITHIC) {
			pp_region_flags |= PP_REGION_CONFIG_BUF_MONOLITHIC;
		}
		if (init->kbi_flags & KBIF_INHIBIT_CACHE) {
			pp_region_flags |= PP_REGION_CONFIG_BUF_NOCACHE;
		}
		if (init->kbi_flags & KBIF_PHYS_CONTIGUOUS) {
			pp_region_flags |= PP_REGION_CONFIG_BUF_SEGPHYSCONTIG;
		}
	}

	/* adjust region params */
	pp_regions_params_adjust(srp, md_type, md_subtype, pkt_cnt, max_frags,
	    init->kbi_bufsize, 0, buf_cnt, init->kbi_buf_seg_size,
	    pp_region_flags);

	/*
	 * Create packet pool.
	 */
	ASSERT(ppcreatef & PPCREATEF_EXTERNAL);
	if (kernel_only) {
		ppcreatef |= PPCREATEF_KERNEL_ONLY;
	}
	if (init->kbi_flags & KBIF_BUFFER_ON_DEMAND) {
		ppcreatef |= PPCREATEF_ONDEMAND_BUF;
		if (init->kbi_flags & KBIF_RAW_BFLT) {
			ppcreatef |= PPCREATEF_RAW_BFLT;
		}
	}
	/*
	 * Enable CPU-layer magazine resizing if this is a long-lived
	 * pbufpool, e.g. one that's allocated by a device driver.
	 */
	if (!(init->kbi_flags & KBIF_VIRTUAL_DEVICE)) {
		ppcreatef |= PPCREATEF_DYNAMIC;
	}
	if ((pp = pp_create((const char *)init->kbi_name, srp,
	    init->kbi_buf_seg_ctor, init->kbi_buf_seg_dtor,
	    init->kbi_ctx, init->kbi_ctx_retain, init->kbi_ctx_release,
	    ppcreatef)) == NULL) {
		err = ENOMEM;
		goto done;
	}

	*ppp = pp;

	if (pp_info != NULL) {
		err = kern_pbufpool_get_memory_info(pp, pp_info);
		VERIFY(err == 0);
	}

done:
	if (err != 0 && pp != NULL) {
		/* callee drops reference */
		pp_close(pp);
		pp = NULL;
	}

	return err;
}

void *
kern_pbufpool_get_context(const kern_pbufpool_t pp)
{
	void *ctx = (pp->pp_flags & PPF_EXTERNAL) ? pp->pp_ctx : NULL;
	if (ctx != NULL) {
		pp->pp_ctx_retain(ctx);
	}
	return ctx;
}

errno_t
kern_pbufpool_get_memory_info(const kern_pbufpool_t pp,
    struct kern_pbufpool_memory_info *pp_info)
{
	if (pp_info == NULL) {
		return EINVAL;
	}

	bzero(pp_info, sizeof(*pp_info));
	if (pp->pp_flags & PPF_EXTERNAL) {
		pp_info->kpm_flags |= KPMF_EXTERNAL;
	}
	pp_info->kpm_packets      = pp->pp_kmd_region->skr_c_obj_cnt;
	pp_info->kpm_max_frags    = pp->pp_max_frags;
	pp_info->kpm_buflets      = PP_BUF_REGION_DEF(pp)->skr_c_obj_cnt;
	pp_info->kpm_bufsize      = PP_BUF_SIZE_DEF(pp);
	pp_info->kpm_buf_obj_size = PP_BUF_OBJ_SIZE_DEF(pp);
	pp_info->kpm_bufsegs      = PP_BUF_REGION_DEF(pp)->skr_seg_max_cnt;
	pp_info->kpm_buf_seg_size = PP_BUF_REGION_DEF(pp)->skr_seg_size;

	return 0;
}

kern_segment_idx_t
kern_segment_get_index(const kern_segment_t seg)
{
	return seg->sg_index;
}

static errno_t
kern_pbufpool_alloc_common(const kern_pbufpool_t pp, const uint32_t bufcnt,
    kern_packet_t *pph, uint32_t skmflag)
{
	struct __kern_quantum *kqum;

	*pph = 0;

	if (__improbable(bufcnt > pp->pp_max_frags)) {
		return EINVAL;
	}

	if (__improbable((bufcnt != pp->pp_max_frags) &&
	    !PP_HAS_BUFFER_ON_DEMAND(pp))) {
		return EINVAL;
	}

	kqum = SK_PTR_ADDR_KQUM(pp_alloc_packet(pp, (uint16_t)bufcnt, skmflag));
	if (__probable(kqum != NULL)) {
		*pph = SK_PTR_ENCODE(kqum, METADATA_TYPE(kqum),
		    METADATA_SUBTYPE(kqum));
	}

	return (kqum != NULL) ? 0 : ENOMEM;
}

errno_t
kern_pbufpool_alloc(const kern_pbufpool_t pp, const uint32_t bufcnt,
    kern_packet_t *pph)
{
	return kern_pbufpool_alloc_common(pp, bufcnt, pph, SKMEM_SLEEP);
}

errno_t
kern_pbufpool_alloc_nosleep(const kern_pbufpool_t pp, const uint32_t bufcnt,
    kern_packet_t *pph)
{
	return kern_pbufpool_alloc_common(pp, bufcnt, pph, SKMEM_NOSLEEP);
}

static errno_t
kern_pbufpool_alloc_batch_common(const kern_pbufpool_t pp,
    const uint32_t bufcnt, kern_packet_t *array, uint32_t *size,
    alloc_cb_func_t cb, const void *ctx, uint32_t skmflag)
{
	if (__improbable(array == NULL || size == NULL || *size == 0 ||
	    bufcnt > pp->pp_max_frags || (cb == NULL && ctx != NULL))) {
		return EINVAL;
	}

	if (__improbable((bufcnt != pp->pp_max_frags) &&
	    !PP_HAS_BUFFER_ON_DEMAND(pp))) {
		return EINVAL;
	}

	return pp_alloc_packet_batch(pp, (uint16_t)bufcnt, array, size, TRUE,
	           cb, ctx, skmflag);
}

errno_t
kern_pbufpool_alloc_batch(const kern_pbufpool_t pp, const uint32_t bufcnt,
    kern_packet_t *array, uint32_t *size)
{
	return kern_pbufpool_alloc_batch_common(pp, bufcnt, array,
	           size, NULL, NULL, SKMEM_SLEEP);
}

errno_t
kern_pbufpool_alloc_batch_callback(const kern_pbufpool_t pp,
    const uint32_t bufcnt, kern_packet_t *array, uint32_t *size,
    alloc_cb_func_t cb, const void *ctx)
{
	return kern_pbufpool_alloc_batch_common(pp, bufcnt, array,
	           size, cb, ctx, SKMEM_SLEEP);
}

errno_t
kern_pbufpool_alloc_batch_nosleep(const kern_pbufpool_t pp,
    const uint32_t bufcnt, kern_packet_t *array, uint32_t *size)
{
	return kern_pbufpool_alloc_batch_common(pp, bufcnt, array,
	           size, NULL, NULL, SKMEM_NOSLEEP);
}

errno_t
kern_pbufpool_alloc_batch_nosleep_callback(const kern_pbufpool_t pp,
    const uint32_t bufcnt, kern_packet_t *array, uint32_t *size,
    alloc_cb_func_t cb, const void *ctx)
{
	return kern_pbufpool_alloc_batch_common(pp, bufcnt, array,
	           size, cb, ctx, SKMEM_NOSLEEP);
}

void
kern_pbufpool_free(const kern_pbufpool_t pp, kern_packet_t ph)
{
	pp_free_packet(pp, SK_PTR_ADDR(ph));
}

void
kern_pbufpool_free_batch(const kern_pbufpool_t pp, kern_packet_t *array,
    uint32_t size)
{
	if (__improbable(array == NULL || size == 0)) {
		return;
	}

	pp_free_packet_batch(pp, array, size);
}

void
kern_pbufpool_free_chain(const kern_pbufpool_t pp, kern_packet_t chain)
{
	struct __kern_packet *pkt_chain = SK_PTR_ADDR_KPKT(chain);

	VERIFY(pp == pkt_chain->pkt_qum.qum_pp);
	pp_free_packet_chain(pkt_chain, NULL);
}

errno_t
kern_pbufpool_alloc_buffer(const kern_pbufpool_t pp, mach_vm_address_t *buf,
    kern_segment_t *sg, kern_obj_idx_seg_t *sg_idx)
{
	return pp_alloc_buffer(pp, buf, sg, sg_idx, 0);
}


errno_t
kern_pbufpool_alloc_buffer_nosleep(const kern_pbufpool_t pp,
    mach_vm_address_t *buf, kern_segment_t *sg, kern_obj_idx_seg_t *sg_idx)
{
	return pp_alloc_buffer(pp, buf, sg, sg_idx, SKMEM_NOSLEEP);
}

void
kern_pbufpool_free_buffer(const kern_pbufpool_t pp, mach_vm_address_t baddr)
{
	pp_free_buffer(pp, baddr);
}

void
kern_pbufpool_destroy(kern_pbufpool_t pp)
{
	VERIFY(pp->pp_flags & PPF_EXTERNAL);
	pp_close(pp);
}

errno_t
kern_pbufpool_alloc_buflet(const kern_pbufpool_t pp, kern_buflet_t *pbuf,
    bool attach_buffer)
{
	return pp_alloc_buflet(pp, pbuf, SKMEM_SLEEP,
	           attach_buffer ? PP_ALLOC_BFT_ATTACH_BUFFER : 0);
}

errno_t
kern_pbufpool_alloc_buflet_nosleep(const kern_pbufpool_t pp,
    kern_buflet_t *pbuf, bool attach_buffer)
{
	return pp_alloc_buflet(pp, pbuf, SKMEM_NOSLEEP,
	           attach_buffer ? PP_ALLOC_BFT_ATTACH_BUFFER : 0);
}

errno_t
kern_pbufpool_alloc_batch_buflet(const kern_pbufpool_t pp,
    kern_buflet_t *pbuf_array, uint32_t *size, bool attach_buffer)
{
	return pp_alloc_buflet_batch(pp, (uint64_t *)pbuf_array, size, SKMEM_SLEEP,
	           attach_buffer ? PP_ALLOC_BFT_ATTACH_BUFFER : 0);
}

errno_t
kern_pbufpool_alloc_batch_buflet_nosleep(const kern_pbufpool_t pp,
    kern_buflet_t *pbuf_array, uint32_t *size, bool attach_buffer)
{
	return pp_alloc_buflet_batch(pp, (uint64_t *)pbuf_array, size, SKMEM_NOSLEEP,
	           attach_buffer ? PP_ALLOC_BFT_ATTACH_BUFFER : 0);
}

void
kern_pbufpool_free_buflet(const kern_pbufpool_t pp, kern_buflet_t pbuf)
{
	return pp_free_buflet(pp, pbuf);
}
