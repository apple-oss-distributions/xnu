/*
 * Copyright (c) 2015-2021 Apple Inc. All rights reserved.
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

#if (DEVELOPMENT || DEBUG) // XXX make this whole file a config option?

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/kpipe/nx_kernel_pipe.h>

static int kplo_enabled;
static int kplo_busy;
static int kplo_dump_buf;
static int kplo_inject_error;
static uintptr_t kplo_seed;
static uintptr_t kplo_nx_ctx;
static uint32_t kplo_drv_slots;

static nexus_controller_t kplo_ncd;
static uuid_t kplo_dom_prov_uuid;
static uuid_t kplo_prov_uuid;
static uuid_t kplo_nx_uuid;
static uuid_string_t kplo_nx_uuidstr;

static uint64_t kplo_ntxrings, kplo_nrxrings;
static uint64_t kplo_ntxslots, kplo_nrxslots;
static uint64_t kplo_bufsz, kplo_mdatasz;
static uint64_t kplo_pipes;
static uint64_t kplo_anon = 1;
static kern_channel_ring_t kplo_rxring;
static kern_channel_ring_t kplo_txring;
struct kern_pbufpool_memory_info kplo_tx_pp_info;
static kern_pbufpool_t kplo_tx_pp;
static kern_pbufpool_t kplo_rx_pp;

static LCK_MTX_DECLARE_ATTR(kplo_lock, &sk_lock_group, &sk_lock_attr);

#define KPLO_VERIFY_CTX(addr, ctx)      \
	VERIFY(((uintptr_t)(addr) ^ (uintptr_t)(ctx)) == kplo_seed)
#define KPLO_GENERATE_CTX(addr)         \
	(void *)((uintptr_t)(addr) ^ kplo_seed)
#define KPLO_WHICH_RING(_ring)          \
	((_ring) == kplo_rxring ? "RX" : "TX")

#define KPLO_INJECT_ERROR(_err) do {                                    \
	if (kplo_inject_error == (_err)) {                              \
	        SK_ERR("injecting error %d, returning ENOMEM", (_err)); \
	        error = ENOMEM;                                         \
	        goto done;                                              \
	}                                                               \
} while (0)

static errno_t
kplo_dom_init(kern_nexus_domain_provider_t domprov)
{
#pragma unused(domprov)
	errno_t error = 0;
	lck_mtx_lock(&kplo_lock);
	read_random(&kplo_nx_ctx, sizeof(kplo_nx_ctx));
	read_random(&kplo_seed, sizeof(kplo_seed));
	SK_DF(SK_VERB_KERNEL_PIPE, "seed is 0x%llx", (uint64_t)kplo_seed);
	VERIFY(kplo_drv_slots == 0);
	VERIFY(kplo_ntxrings == 0 && kplo_nrxrings == 0);
	VERIFY(kplo_ntxslots == 0 && kplo_nrxslots == 0);
	VERIFY(kplo_bufsz == 0 && kplo_mdatasz == 0);
	VERIFY(kplo_pipes == 0);
	VERIFY(kplo_rxring == NULL && kplo_txring == NULL);
	VERIFY(kplo_tx_pp == NULL && kplo_rx_pp == NULL);
	lck_mtx_unlock(&kplo_lock);

	KPLO_INJECT_ERROR(1);
done:
	return error;
}

static void
kplo_dom_fini(kern_nexus_domain_provider_t domprov)
{
#pragma unused(domprov)
	lck_mtx_lock(&kplo_lock);
	kplo_nx_ctx = kplo_seed = 0;
	kplo_ntxrings = kplo_nrxrings = kplo_ntxslots = kplo_nrxslots = 0;
	kplo_bufsz = kplo_mdatasz = 0;
	kplo_pipes = 0;
	VERIFY(kplo_busy);
	kplo_busy = 0;
	wakeup(&kplo_enabled); // Allow shutdown to return
	VERIFY(kplo_drv_slots == 0);
	VERIFY(kplo_rxring == NULL && kplo_txring == NULL);
	VERIFY(kplo_tx_pp == NULL && kplo_rx_pp == NULL);
	lck_mtx_unlock(&kplo_lock);

	SK_DF(SK_VERB_KERNEL_PIPE, "called");
}

static errno_t
kplo_pre_connect(kern_nexus_provider_t nxprov,
    proc_t p, kern_nexus_t nexus,
    nexus_port_t nexus_port, kern_channel_t channel, void **ch_ctx)
{
#pragma unused(nxprov, p, nexus_port)
	void *pp_ctx = NULL;
	errno_t error = 0;

	KPLO_VERIFY_CTX(kplo_nx_ctx, kern_nexus_get_context(nexus));
	*ch_ctx = KPLO_GENERATE_CTX(channel);
	SK_DF(SK_VERB_KERNEL_PIPE, "nx_port %u ch 0x%llx ch_ctx 0x%llx",
	    nexus_port, SK_KVA(channel), (uint64_t)(*ch_ctx));

	error = kern_nexus_get_pbufpool(nexus, NULL, NULL);
	VERIFY(error == EINVAL);

	error = kern_nexus_get_pbufpool(nexus, &kplo_tx_pp, &kplo_rx_pp);
	VERIFY(error == 0);
	VERIFY(kplo_tx_pp != NULL);     /* built-in pp */
	VERIFY(kplo_rx_pp != NULL);     /* built-in pp */

	pp_ctx = kern_pbufpool_get_context(kplo_tx_pp);
	VERIFY(pp_ctx == NULL); /* must be NULL for built-in pp */

	error = kern_pbufpool_get_memory_info(kplo_tx_pp, &kplo_tx_pp_info);
	VERIFY(error == 0);
	VERIFY(!(kplo_tx_pp_info.kpm_flags & KPMF_EXTERNAL));
	VERIFY(kplo_tx_pp_info.kpm_packets >=
	    (uint32_t)((kplo_ntxrings * kplo_ntxslots) +
	    (kplo_nrxrings * kplo_nrxslots)));
	VERIFY(kplo_tx_pp_info.kpm_max_frags == 1);
	VERIFY(kplo_tx_pp_info.kpm_buflets >= kplo_tx_pp_info.kpm_packets);
	VERIFY(kplo_tx_pp_info.kpm_bufsize == (uint32_t)kplo_bufsz);

	SK_DF(SK_VERB_KERNEL_PIPE,
	    "kpm_packets %u kpm_max_frags %u kpm_buflets %u kpm_bufsize %u",
	    kplo_tx_pp_info.kpm_packets, kplo_tx_pp_info.kpm_max_frags,
	    kplo_tx_pp_info.kpm_buflets, kplo_tx_pp_info.kpm_bufsize);

	error = 0;

	KPLO_INJECT_ERROR(2);
done:
	if (error != 0) {
		kplo_tx_pp = NULL;
		kplo_rx_pp = NULL;
	}

	return error;
}

static errno_t
kplo_connected(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov)
	errno_t error = 0;
	KPLO_VERIFY_CTX(kplo_nx_ctx, kern_nexus_get_context(nexus));
	KPLO_VERIFY_CTX(channel, kern_channel_get_context(channel));

	SK_DF(SK_VERB_KERNEL_PIPE, "channel 0x%llx", SK_KVA(channel));
	SK_DF(SK_VERB_KERNEL_PIPE, "  RX_ring 0x%llx", SK_KVA(kplo_rxring));
	SK_DF(SK_VERB_KERNEL_PIPE, "  TX_ring 0x%llx", SK_KVA(kplo_txring));

	KPLO_INJECT_ERROR(3);

done:
	return error;
}

static void
kplo_pre_disconnect(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov)
	KPLO_VERIFY_CTX(kplo_nx_ctx, kern_nexus_get_context(nexus));
	KPLO_VERIFY_CTX(channel, kern_channel_get_context(channel));
	SK_DF(SK_VERB_KERNEL_PIPE, "called for channel 0x%llx",
	    SK_KVA(channel));
}

static void
kplo_disconnected(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov)
	KPLO_VERIFY_CTX(kplo_nx_ctx, kern_nexus_get_context(nexus));
	KPLO_VERIFY_CTX(channel, kern_channel_get_context(channel));
	SK_DF(SK_VERB_KERNEL_PIPE, "called for channel 0x%llx",
	    SK_KVA(channel));
	bzero(&kplo_tx_pp_info, sizeof(kplo_tx_pp_info));
	kplo_tx_pp = kplo_rx_pp = NULL;
}

static errno_t
kplo_ring_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel, kern_channel_ring_t ring, boolean_t is_tx_ring,
    void **ring_ctx)
{
#pragma unused(nxprov, is_tx_ring)
	errno_t error = 0;
	KPLO_VERIFY_CTX(kplo_nx_ctx, kern_nexus_get_context(nexus));
	KPLO_VERIFY_CTX(channel, kern_channel_get_context(channel));

	if (is_tx_ring) {
		KPLO_INJECT_ERROR(4);
		VERIFY(kplo_txring == NULL);
		kplo_txring = ring;
	} else {
		KPLO_INJECT_ERROR(5);
		VERIFY(kplo_rxring == NULL);
		kplo_rxring = ring;
	}
	*ring_ctx = KPLO_GENERATE_CTX(ring);

	SK_DF(SK_VERB_KERNEL_PIPE, "%s_ring 0x%llx ring_ctx 0x%llx, err(%d)",
	    KPLO_WHICH_RING(ring), SK_KVA(ring), (uint64_t)(*ring_ctx), error);

done:
	return error;
}

static void
kplo_ring_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring)
{
#pragma unused(nxprov)
	KPLO_VERIFY_CTX(kplo_nx_ctx, kern_nexus_get_context(nexus));
	KPLO_VERIFY_CTX(ring, kern_channel_ring_get_context(ring));
	SK_DF(SK_VERB_KERNEL_PIPE, "%s_ring 0x%llx",
	    KPLO_WHICH_RING(ring), SK_KVA(ring));

	if (ring == kplo_txring) {
		kplo_txring = NULL;
	} else {
		VERIFY(ring == kplo_rxring);
		kplo_rxring = NULL;
	}
}

static errno_t
kplo_slot_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, channel_slot_t slot,
    uint32_t slot_id, struct kern_slot_prop **slot_prop_addr, void **pslot_ctx)
{
#pragma unused(nxprov)
	errno_t error = 0;
	KPLO_VERIFY_CTX(kplo_nx_ctx, kern_nexus_get_context(nexus));
	KPLO_VERIFY_CTX(ring, kern_channel_ring_get_context(ring));

	KPLO_INJECT_ERROR(6);
	if ((slot_id % 5) == 4) {
		KPLO_INJECT_ERROR(7);
	}

	lck_mtx_lock(&kplo_lock);
	*pslot_ctx = KPLO_GENERATE_CTX(slot);
	*slot_prop_addr = NULL;
	SK_DF(SK_VERB_KERNEL_PIPE,
	    "  slot 0x%llx id %u slot_ctx 0x%llx [%u]",
	    SK_KVA(slot), slot_id, SK_KVA(*pslot_ctx), kplo_drv_slots);
	lck_mtx_unlock(&kplo_lock);

done:
	return error;
}

static void
kplo_slot_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, channel_slot_t slot,
    uint32_t slot_id)
{
#pragma unused(nxprov, nexus, slot_id)
	void *ctx;

	KPLO_VERIFY_CTX(kplo_nx_ctx, kern_nexus_get_context(nexus));
	KPLO_VERIFY_CTX(ring, kern_channel_ring_get_context(ring));
	ctx = kern_channel_slot_get_context(ring, slot);

	lck_mtx_lock(&kplo_lock);
	KPLO_VERIFY_CTX(slot, ctx);
	SK_DF(SK_VERB_KERNEL_PIPE, "  slot 0x%llx id %u [%u]",
	    SK_KVA(slot), slot_id, kplo_drv_slots);
	lck_mtx_unlock(&kplo_lock);
}

static errno_t
kplo_sync_tx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, uint32_t flags)
{
#pragma unused(nxprov, nexus)
#pragma unused(ring, flags)
	errno_t error = 0;
	struct kern_channel_ring_stat_increment stats;
	KPLO_VERIFY_CTX(kplo_nx_ctx, kern_nexus_get_context(nexus));
	KPLO_VERIFY_CTX(ring, kern_channel_ring_get_context(ring));
	SK_DF(SK_VERB_KERNEL_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "called with ring \"%s\" krflags 0x%b flags 0x%x",
	    ring->ckr_name, ring->ckr_flags, CKRF_BITS, flags);
	VERIFY(ring == kplo_txring);

	kern_channel_ring_t txkring = kplo_txring;
	kern_channel_ring_t rxkring = kplo_rxring;
	uint32_t avail_rs, avail_ts;
	kern_channel_slot_t rs, ts, prs, pts;
	kern_packet_t ph;       /* packet handle */
	kern_buflet_t buf;      /* buflet handle */
	kern_packet_idx_t pidx;
	kern_packet_t *ary = NULL;
	uint32_t ary_cnt = 0;
	uint16_t rdlen, dlen, doff;
	struct kern_pbufpool *pp;

	KPLO_INJECT_ERROR(8);

	SK_DF(SK_VERB_KERNEL_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "0x%llx: %s %x -> %s", SK_KVA(txkring), txkring->ckr_name,
	    flags, rxkring->ckr_name);
	SK_DF(SK_VERB_KERNEL_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "tx before: kh %3u kt %3u | h %3u t %3u",
	    txkring->ckr_khead, txkring->ckr_ktail,
	    txkring->ckr_rhead, txkring->ckr_rtail);
	SK_DF(SK_VERB_KERNEL_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "rx before: kh %3u kt %3u | h %3u t %3u",
	    rxkring->ckr_khead, rxkring->ckr_ktail,
	    rxkring->ckr_rhead, rxkring->ckr_rtail);

	pp = skmem_arena_nexus(KRNA(ring)->na_arena)->arn_tx_pp;
	VERIFY(pp != NULL);

	/*
	 * We don't actually use prop or avail here,
	 * but get them for test coverage
	 */
	avail_rs = kern_channel_available_slot_count(rxkring);
	avail_ts = kern_channel_available_slot_count(txkring);
	rs = kern_channel_get_next_slot(rxkring, NULL, NULL);
	ts = kern_channel_get_next_slot(txkring, NULL, NULL);
	VERIFY((avail_rs == 0) == (rs == NULL));
	VERIFY((avail_ts == 0) == (ts == NULL));

	if (!rs || !ts) {
		/* either the rxring is full, or nothing to send */
		return 0;
	}

	VERIFY(kern_channel_ring_get_container(txkring, NULL, NULL) == EINVAL);
	VERIFY(kern_channel_ring_get_container(txkring, &ary, &ary_cnt) == 0);
	VERIFY(ary != NULL && ary_cnt >= kplo_ntxslots);
	VERIFY(kplo_bufsz < UINT16_MAX);

	read_random(&rdlen, sizeof(rdlen));
	rdlen %= kplo_bufsz;

	bzero(&stats, sizeof(stats));
	do {
		kern_packet_t tph;
		uint8_t *baddr;

		/* get packet handle */
		ph = kern_channel_slot_get_packet(txkring, ts);
		VERIFY(ph != 0);
		pidx = kern_packet_get_object_index(ph);
		VERIFY(pidx < kplo_tx_pp_info.kpm_packets);

		/* verify buflet and length */
		VERIFY(kern_packet_get_buflet_count(ph) == 1);
		buf = kern_packet_get_next_buflet(ph, NULL);
		VERIFY(buf != NULL);

		baddr = kern_buflet_get_data_address(buf);
		VERIFY(baddr != NULL);
		dlen = kern_buflet_get_data_length(buf);
		VERIFY(dlen == kern_packet_get_data_length(ph));
		VERIFY(kern_buflet_set_data_length(buf, dlen) == 0);
		doff = kern_buflet_get_data_offset(buf);

		if (kplo_dump_buf) {
			SK_DF(SK_VERB_KERNEL_PIPE | SK_VERB_DUMP, "%s",
			    sk_dump("buf", baddr + doff, dlen, 128, NULL, 0));
		}

		VERIFY(kern_buflet_set_data_offset(buf, 0) == 0);
		VERIFY(kern_buflet_set_data_length(buf, 0) == 0);
		VERIFY(kern_buflet_set_data_length(buf,
		    (uint16_t)(kplo_bufsz + 1)) == ERANGE);
		VERIFY(kern_buflet_set_data_length(buf, rdlen) == 0);
		VERIFY(kern_packet_finalize(ph) == 0);
		VERIFY(kern_packet_get_data_length(ph) == rdlen);
		VERIFY(kern_buflet_set_data_length(buf, 0) == 0);
		VERIFY(kern_buflet_set_data_offset(buf,
		    (uint16_t)(kplo_bufsz + 1)) == ERANGE);
		VERIFY(kern_buflet_set_data_length(buf, dlen) == 0);
		VERIFY(kern_buflet_set_data_offset(buf, doff) == 0);
		VERIFY(kern_packet_finalize(ph) == 0);
		VERIFY(kern_packet_get_data_length(ph) == dlen);
		VERIFY(kern_packet_finalize(ph) == 0);
		buf = kern_packet_get_next_buflet(ph, buf);
		VERIFY(buf == NULL);

		/* verify attach and detach */
		VERIFY(kern_channel_slot_detach_packet(txkring, ts, ph) == 0);
		VERIFY(kern_channel_slot_get_packet(txkring, ts) == 0);
		VERIFY(kern_packet_finalize(ph) == 0);
		VERIFY(kern_channel_slot_attach_packet(txkring, ts, ph) == 0);
		VERIFY(kern_channel_slot_get_packet(txkring, ts) == ph);

		stats.kcrsi_slots_transferred++;
		stats.kcrsi_bytes_transferred += dlen;

		tph = kern_channel_slot_get_packet(ring, ts);
		VERIFY(tph != 0);
		VERIFY(kern_channel_slot_detach_packet(txkring, ts, tph) == 0);
		VERIFY(kern_packet_finalize(tph) == 0);
		VERIFY(kern_channel_slot_attach_packet(rxkring, rs, tph) == 0);

		prs = rs;
		pts = ts;
		rs = kern_channel_get_next_slot(rxkring, rs, NULL);
		ts = kern_channel_get_next_slot(txkring, ts, NULL);
		avail_rs--;
		avail_ts--;
		VERIFY((avail_rs == 0) == (rs == NULL));
		VERIFY((avail_ts == 0) == (ts == NULL));
	} while (rs && ts);

	kern_channel_advance_slot(rxkring, prs);
	kern_channel_advance_slot(txkring, pts);
	kern_channel_increment_ring_stats(txkring, &stats);
	kern_channel_increment_ring_stats(rxkring, &stats);

	SK_DF(SK_VERB_KERNEL_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "tx after:  kh %3u kt %3u | h %3u t %3u",
	    txkring->ckr_khead, txkring->ckr_ktail,
	    txkring->ckr_rhead, txkring->ckr_rtail);
	SK_DF(SK_VERB_KERNEL_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "rx after:  kh %3u kt %3u | h %3u t %3u",
	    rxkring->ckr_khead, rxkring->ckr_ktail,
	    rxkring->ckr_rhead, rxkring->ckr_rtail);

	(void) kern_channel_reclaim(txkring);

	kern_channel_notify(rxkring, 0);

	KPLO_INJECT_ERROR(9);
done:
	return error;
}

static errno_t
kplo_sync_rx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, uint32_t flags)
{
	errno_t error;
	struct proc *p = current_proc();
#pragma unused(nxprov, nexus)
#pragma unused(flags)
	KPLO_VERIFY_CTX(kplo_nx_ctx, kern_nexus_get_context(nexus));
	KPLO_VERIFY_CTX(ring, kern_channel_ring_get_context(ring));

	VERIFY(ring = kplo_rxring);
	kern_channel_ring_t txkring = kplo_txring;
	kern_channel_ring_t rxkring = ring;

	SK_DF(SK_VERB_KERNEL_PIPE | SK_VERB_SYNC | SK_VERB_RX,
	    "called with ring \"%s\" krflags 0x%b flags 0x%x",
	    ring->ckr_name, ring->ckr_flags, CKRF_BITS, flags);

	KPLO_INJECT_ERROR(10);

	/* reclaim user-released slots */
	(void) kern_channel_reclaim(rxkring);

	kr_enter(txkring, TRUE);

	if (__improbable(kr_txsync_prologue(NULL, txkring, p) >=
	    txkring->ckr_num_slots)) {
		error = EFAULT;
		goto done;
	}
	error = kplo_sync_tx(nxprov, nexus, txkring, flags);
	kr_txsync_finalize(NULL, txkring, p);

	kr_exit(txkring);

	kern_channel_notify(txkring, 0);

done:
	return error;
}

static void kpipe_loopback_stop(void);

static void
kpipe_loopback_start(void)
{
	nexus_attr_t nxa = NULL;
	uuid_t uuidtmp;
	uuid_string_t uuidstr;
	errno_t error;

	SK_D("Hello loopback pipe!");

	lck_mtx_lock(&kplo_lock);
	/*
	 * This will be cleared when kplo_dom_fini() is called,
	 * or in kpipe_loopback_stop if we failed to register
	 * our domain provider.
	 */
	VERIFY(!kplo_busy);
	kplo_busy = 1;
	lck_mtx_unlock(&kplo_lock);

	struct kern_nexus_domain_provider_init dom_init = {
		.nxdpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxdpi_flags = 0,
		.nxdpi_init = kplo_dom_init,
		.nxdpi_fini = kplo_dom_fini,
	};

	struct kern_nexus_provider_init prov_init = {
		.nxpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxpi_flags = NXPIF_VIRTUAL_DEVICE,
		.nxpi_pre_connect = kplo_pre_connect,
		.nxpi_connected = kplo_connected,
		.nxpi_pre_disconnect = kplo_pre_disconnect,
		.nxpi_disconnected = kplo_disconnected,
		.nxpi_ring_init = kplo_ring_init,
		.nxpi_ring_fini = kplo_ring_fini,
		.nxpi_slot_init = kplo_slot_init,
		.nxpi_slot_fini = kplo_slot_fini,
		.nxpi_sync_tx = kplo_sync_tx,
		.nxpi_sync_rx = kplo_sync_rx,
		.nxpi_tx_doorbell = NULL,
	};

	VERIFY(uuid_is_null(kplo_dom_prov_uuid));
	error = kern_nexus_register_domain_provider(NEXUS_TYPE_KERNEL_PIPE,
	    (const uint8_t *)"kpipe_loopback",
	    &dom_init, sizeof(dom_init), &kplo_dom_prov_uuid);
	if (error != 0) {
		SK_ERR("failed to register kpipe_loopback domain %d", error);
		VERIFY(uuid_is_null(kplo_dom_prov_uuid));
		goto done;
	}

	uuid_unparse_upper(kplo_dom_prov_uuid, uuidstr);
	SK_DF(SK_VERB_KERNEL_PIPE,
	    "Registered kpipe_loopback domain with uuid %s", uuidstr);

	VERIFY(kplo_ncd == NULL);
	error = kern_nexus_controller_create(&kplo_ncd);
	if (error != 0) {
		SK_ERR("Failed to create nexus controller %d", error);
		VERIFY(kplo_ncd == NULL);
		goto done;
	}

	// XXX opaque violation on kplo_ncd
	uuid_unparse_upper(kplo_ncd->ncd_nxctl->nxctl_uuid, uuidstr);
	SK_DF(SK_VERB_KERNEL_PIPE,
	    "Created nexus controller with uuid %s", uuidstr);

	// We don't actually do anything with this.
	uuid_clear(uuidtmp);
	error = kern_nexus_get_default_domain_provider(NEXUS_TYPE_KERNEL_PIPE,
	    &uuidtmp);
	if (error) {
		SK_ERR("Failed to find kernel pipe domain %d", error);
		VERIFY(uuid_is_null(uuidtmp));
		goto done;
	}

	uuid_unparse_upper(uuidtmp, uuidstr);
	SK_DF(SK_VERB_KERNEL_PIPE,
	    "Found kernel pipe domain with uuid %s", uuidstr);

	error = kern_nexus_attr_create(&nxa);
	if (error) {
		SK_ERR("Failed to create nexus_attr %d", error);
		VERIFY(nxa == NULL);
		goto done;
	}

	error = kern_nexus_attr_set(nxa, NEXUS_ATTR_ANONYMOUS, kplo_anon);
	if (error) {
		SK_ERR("Failed to %s anonymous attribute %d",
		    (kplo_anon ? "set" : "clear"), error);
		goto done;
	}

	VERIFY(uuid_is_null(kplo_prov_uuid));
	error = kern_nexus_controller_register_provider(kplo_ncd,
	    kplo_dom_prov_uuid,
	    (const uint8_t *)"com.apple.nexus.kpipe_loopback", &prov_init,
	    sizeof(prov_init), nxa, &kplo_prov_uuid);
	if (error) {
		SK_ERR("Failed to register nexus provider %d", error);
		VERIFY(uuid_is_null(kplo_prov_uuid));
		goto done;
	}

	uuid_unparse_upper(kplo_prov_uuid, uuidstr);
	SK_DF(SK_VERB_KERNEL_PIPE,
	    "Registered nexus controller provider with uuid %s", uuidstr);

	error = kern_nexus_controller_read_provider_attr(kplo_ncd,
	    kplo_prov_uuid, nxa);
	if (error != 0) {
		SK_ERR("Failed to read nexus provider attributes %d", error);
		goto done;
	}

	if ((error = kern_nexus_attr_get(nxa, NEXUS_ATTR_TX_RINGS,
	    &kplo_ntxrings)) != 0) {
		SK_ERR("Failed to retrieve NEXUS_ATTR_TX_RINGS %d", error);
		goto done;
	}
	if ((error = kern_nexus_attr_get(nxa, NEXUS_ATTR_TX_SLOTS,
	    &kplo_ntxslots)) != 0) {
		SK_ERR("Failed to retrieve NEXUS_ATTR_TX_SLOTS %d", error);
		goto done;
	}
	if ((error = kern_nexus_attr_get(nxa, NEXUS_ATTR_RX_RINGS,
	    &kplo_nrxrings)) != 0) {
		SK_ERR("Failed to retrieve NEXUS_ATTR_RX_RINGS %d", error);
		goto done;
	}
	if ((error = kern_nexus_attr_get(nxa, NEXUS_ATTR_RX_SLOTS,
	    &kplo_nrxslots)) != 0) {
		SK_ERR("Failed to retrieve NEXUS_ATTR_RX_SLOTS %d", error);
		goto done;
	}
	if ((error = kern_nexus_attr_get(nxa, NEXUS_ATTR_SLOT_BUF_SIZE,
	    &kplo_bufsz)) != 0) {
		SK_ERR("Failed to retrieve NEXUS_ATTR_BUF_SIZE %d", error);
		goto done;
	}
	if ((error = kern_nexus_attr_get(nxa, NEXUS_ATTR_SLOT_META_SIZE,
	    &kplo_mdatasz)) != 0) {
		SK_ERR("Failed to retrieve NEXUS_ATTR_META_SIZE %d", error);
		goto done;
	}
	if ((error = kern_nexus_attr_get(nxa, NEXUS_ATTR_ANONYMOUS,
	    &kplo_anon)) != 0) {
		SK_ERR("Failed to retrieve NEXUS_ATTR_ANONYMOUS %d", error);
		goto done;
	}
	if ((error = kern_nexus_attr_get(nxa, NEXUS_ATTR_PIPES,
	    &kplo_pipes)) != 0) {
		SK_ERR("Failed to retrieve NEXUS_ATTR_PIPES %d", error);
		goto done;
	}

	SK_DF(SK_VERB_KERNEL_PIPE, "Attributes of %s:", uuidstr);
	SK_DF(SK_VERB_KERNEL_PIPE, "    TX rings:   %llu", kplo_ntxrings);
	SK_DF(SK_VERB_KERNEL_PIPE, "    TX slots:   %llu", kplo_ntxslots);
	SK_DF(SK_VERB_KERNEL_PIPE, "    RX rings:   %llu", kplo_nrxrings);
	SK_DF(SK_VERB_KERNEL_PIPE, "    RX slots:   %llu", kplo_nrxslots);
	SK_DF(SK_VERB_KERNEL_PIPE, "    buffer:     %llu", kplo_bufsz);
	SK_DF(SK_VERB_KERNEL_PIPE, "    metadata:   %llu", kplo_mdatasz);
	SK_DF(SK_VERB_KERNEL_PIPE, "    anonymous:  %llu", kplo_anon);
	SK_DF(SK_VERB_KERNEL_PIPE, "    pipes:      %llu", kplo_pipes);

	struct kern_nexus_init nx_init = {
		.nxi_version = KERN_NEXUS_CURRENT_VERSION,
		.nxi_flags = 0,
		.nxi_tx_pbufpool = NULL,
		.nxi_rx_pbufpool = NULL,
	};

	VERIFY(uuid_is_null(kplo_nx_uuid));
	error = kern_nexus_controller_alloc_provider_instance(kplo_ncd,
	    kplo_prov_uuid, KPLO_GENERATE_CTX(kplo_nx_ctx), NULL, &kplo_nx_uuid,
	    &nx_init);
	if (error) {
		SK_ERR("Failed to alloc provider instance %d", error);
		VERIFY(uuid_is_null(kplo_nx_uuid));
		goto done;
	}

	VERIFY(kplo_nx_uuidstr[0] == '\0');
	uuid_unparse_upper(kplo_nx_uuid, kplo_nx_uuidstr);
	SK_DF(SK_VERB_KERNEL_PIPE,
	    "Allocated provider instance uuid %s", kplo_nx_uuidstr);

	lck_mtx_lock(&kplo_lock);
	kplo_enabled = 1;
	wakeup(&kplo_enabled); // Allow startup to return
	lck_mtx_unlock(&kplo_lock);

done:
	if (nxa != NULL) {
		kern_nexus_attr_destroy(nxa);
		nxa = NULL;
	}
	if (error) {
		kpipe_loopback_stop();
	}
}

static void
kpipe_loopback_stop(void)
{
	uuid_string_t uuidstr;
	errno_t error;

	SK_D("Stopping loopback pipe!");

	if (!uuid_is_null(kplo_nx_uuid)) {
		uuid_unparse_upper(kplo_nx_uuid, uuidstr);
		SK_DF(SK_VERB_KERNEL_PIPE,
		    "Deallocated provider instance uuid %s", uuidstr);
		error = kern_nexus_controller_free_provider_instance(kplo_ncd,
		    kplo_nx_uuid);
		VERIFY(error == 0);
		uuid_clear(kplo_nx_uuid);
		memset(kplo_nx_uuidstr, 0, sizeof(kplo_nx_uuidstr));
	}

	if (!uuid_is_null(kplo_prov_uuid)) {
		uuid_unparse_upper(kplo_prov_uuid, uuidstr);
		SK_DF(SK_VERB_KERNEL_PIPE,
		    "Unregistered nexus controller with uuid %s", uuidstr);
		error = kern_nexus_controller_deregister_provider(kplo_ncd,
		    kplo_prov_uuid);
		VERIFY(error == 0);
		uuid_clear(kplo_prov_uuid);
	}

	if (kplo_ncd) {
		// XXX opaque violation on kplo_ncd
		uuid_unparse_upper(kplo_ncd->ncd_nxctl->nxctl_uuid, uuidstr);
		SK_DF(SK_VERB_KERNEL_PIPE,
		    "Destroying nexus controller with uuid %s", uuidstr);
		kern_nexus_controller_destroy(kplo_ncd);
		kplo_ncd = NULL;
	}

	if (!uuid_is_null(kplo_dom_prov_uuid)) {
		/* mark as not enabled, but defer wakeup to kplo_dom_fini */
		lck_mtx_lock(&kplo_lock);
		VERIFY(kplo_busy);
		kplo_enabled = 0;
		lck_mtx_unlock(&kplo_lock);

		uuid_unparse_upper(kplo_dom_prov_uuid, uuidstr);
		SK_DF(SK_VERB_KERNEL_PIPE,
		    "Unregistered domain provider with uuid %s", uuidstr);
		error = kern_nexus_deregister_domain_provider(
			kplo_dom_prov_uuid);
		VERIFY(error == 0);
		uuid_clear(kplo_dom_prov_uuid);
	} else {
		/* kplo_dom_fini won't be called, so mark unbusy anyway */
		lck_mtx_lock(&kplo_lock);
		VERIFY(kplo_busy);
		kplo_busy = 0;
		kplo_enabled = 0;
		wakeup(&kplo_enabled);
		lck_mtx_unlock(&kplo_lock);
	}

	SK_D("Goodbye loopback pipe!");
}

static int
sysctl_kpipe_loopback_enabled(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error, newvalue, changed;

	lck_mtx_lock(&kplo_lock);
	if ((error = sysctl_io_number(req, kplo_enabled, sizeof(int),
	    &newvalue, &changed)) != 0) {
		goto done;
	}

	if (changed && kplo_enabled != newvalue) {
		thread_t kpth;
		void (*func)(void);

		if (newvalue && kplo_busy) {
			SK_ERR("Older kpipe loopback instance is still active");
			error = EBUSY;
			goto done;
		}

		if (newvalue) {
			func = kpipe_loopback_start;
		} else {
			func = kpipe_loopback_stop;
		}

		if (kernel_thread_start((thread_continue_t)func,
		    NULL, &kpth) != KERN_SUCCESS) {
			SK_ERR("Failed to create kpipe loopback action thread");
			error = EBUSY;
			goto done;
		}
		do {
			SK_DF(SK_VERB_KERNEL_PIPE, "Waiting for %s to complete",
			    newvalue ? "startup" : "shutdown");
			error = msleep(&kplo_enabled, &kplo_lock,
			    PWAIT | PCATCH, "kplow", NULL);
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
		} while (!((error == EINTR) || (newvalue && kplo_enabled) ||
		    (newvalue && !kplo_busy) || (!newvalue && !kplo_busy)));
		thread_deallocate(kpth);
	}

done:
	lck_mtx_unlock(&kplo_lock);
	return error;
}

SYSCTL_NODE(_kern_skywalk_kpipe, OID_AUTO, loopback,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Skywalk kpipe loopback tuning");

SYSCTL_INT(_kern_skywalk_kpipe_loopback, OID_AUTO, dump_buf,
    CTLFLAG_RW | CTLFLAG_LOCKED, &kplo_dump_buf, 0, "Dump buffer");

SYSCTL_INT(_kern_skywalk_kpipe_loopback, OID_AUTO, inject_error,
    CTLFLAG_RW | CTLFLAG_LOCKED, &kplo_inject_error, 0, "Dump metadata");

SYSCTL_PROC(_kern_skywalk_kpipe_loopback, OID_AUTO, enabled,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    NULL, 0, sysctl_kpipe_loopback_enabled,
    "I", "Start the loopback kernel pipe");

SYSCTL_STRING(_kern_skywalk_kpipe_loopback, OID_AUTO, nx_uuid,
    CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED,
    &kplo_nx_uuidstr[0],
    0, "Provider instance of loopback kernel pipe");

#endif /* DEVELOPMENT || DEBUG */
