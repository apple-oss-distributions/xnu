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

#include <skywalk/os_skywalk_private.h>
#include <pexpert/pexpert.h>    /* for PE_parse_boot_argn */
#include <sys/codesign.h>       /* for csproc_get_platform_binary */
#include <sys/signalvar.h>      /* for psignal_with_reason */
#include <sys/reason.h>
#include <sys/kern_memorystatus.h>
#if CONFIG_MACF
#include <security/mac_framework.h>
#endif /* CONFIG_MACF */

#ifndef htole16
#if BYTE_ORDER == LITTLE_ENDIAN
#define htole16(x)      ((uint16_t)(x))
#else /* BYTE_ORDER != LITTLE_ENDIAN */
#define htole16(x)      bswap16((x))
#endif /* BYTE_ORDER == LITTLE_ENDIAN */
#endif /* htole16 */

LCK_GRP_DECLARE(sk_lock_group, "sk_lock");
LCK_ATTR_DECLARE(sk_lock_attr, 0, 0);
LCK_MTX_DECLARE_ATTR(sk_lock, &sk_lock_group, &sk_lock_attr);

static void skywalk_fini(void);
static int sk_priv_chk(proc_t, kauth_cred_t, int);

static int __sk_inited = 0;
#if (DEVELOPMENT || DEBUG)
size_t sk_copy_thres = SK_COPY_THRES;
uint64_t sk_verbose;
#endif /* DEVELOPMENT || DEBUG */
uint32_t sk_debug;
uint64_t sk_features =
#if SKYWALK
    SK_FEATURE_SKYWALK |
#endif
#if DEVELOPMENT
    SK_FEATURE_DEVELOPMENT |
#endif
#if DEBUG
    SK_FEATURE_DEBUG |
#endif
#if CONFIG_NEXUS_FLOWSWITCH
    SK_FEATURE_NEXUS_FLOWSWITCH |
#endif
#if CONFIG_NEXUS_MONITOR
    SK_FEATURE_NEXUS_MONITOR |
#endif
#if CONFIG_NEXUS_NETIF
    SK_FEATURE_NEXUS_NETIF |
#endif
#if CONFIG_NEXUS_USER_PIPE
    SK_FEATURE_NEXUS_USER_PIPE |
#endif
#if CONFIG_NEXUS_KERNEL_PIPE
    SK_FEATURE_NEXUS_KERNEL_PIPE |
#endif
#if CONFIG_NEXUS_KERNEL_PIPE && (DEVELOPMENT || DEBUG)
    SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK |
#endif
#if (DEVELOPMENT || DEBUG)
    SK_FEATURE_DEV_OR_DEBUG |
#endif
    0;

uint32_t sk_opp_defunct = 0;    /* opportunistic defunct */

/* checksum offload is generic to any nexus (not specific to flowswitch) */
uint32_t sk_cksum_tx = 1;       /* advertise outbound offload */
uint32_t sk_cksum_rx = 1;       /* perform inbound checksum offload */

/* guard pages */
uint32_t sk_guard = 0;          /* guard pages (0: disable) */
#define SK_GUARD_MIN    1       /* minimum # of guard pages */
#define SK_GUARD_MAX    4       /* maximum # of guard pages */
uint32_t sk_headguard_sz = SK_GUARD_MIN; /* # of leading guard pages */
uint32_t sk_tailguard_sz = SK_GUARD_MIN; /* # of trailing guard pages */

#if (DEVELOPMENT || DEBUG)
uint32_t sk_txring_sz = 0;      /* flowswitch */
uint32_t sk_rxring_sz = 0;      /* flowswitch */
uint32_t sk_net_txring_sz = 0;  /* netif adapter */
uint32_t sk_net_rxring_sz = 0;  /* netif adapter */
uint32_t sk_min_pool_size = 0;  /* minimum packet pool size */
#endif /* !DEVELOPMENT && !DEBUG */

uint32_t sk_max_flows = NX_FLOWADV_DEFAULT;
uint32_t sk_fadv_nchunks;       /* # of FO_FLOWADV_CHUNK in bitmap */
uint32_t sk_netif_compat_txmodel = NETIF_COMPAT_TXMODEL_DEFAULT;
uint32_t sk_netif_native_txmodel = NETIF_NATIVE_TXMODEL_DEFAULT;
/*
 * Configures the RX aggregation logic for TCP in flowswitch.
 * A non-zero value enables the aggregation logic, with the maximum
 * aggregation length (in bytes) limited to this value.
 */
uint32_t sk_fsw_rx_agg_tcp = 16384;

/*
 * Forces the RX host path to use or not use aggregation, regardless of the
 * existence of filters (see sk_fsw_rx_agg_tcp_host_t for valid values).
 */
uint32_t sk_fsw_rx_agg_tcp_host = SK_FSW_RX_AGG_TCP_HOST_AUTO;

/*
 * Configures the skywalk infrastructure for handling TCP TX aggregation.
 * A non-zero value enables the support.
 */
uint32_t sk_fsw_tx_agg_tcp = 1;
/*
 * Configuration to limit the number of buffers for flowswitch VP channel.
 */
uint32_t sk_fsw_max_bufs = 0;

/* list of interfaces that allow direct open from userspace */
#define SK_NETIF_DIRECT_MAX     8
char sk_netif_direct[SK_NETIF_DIRECT_MAX][IFXNAMSIZ];
uint32_t sk_netif_direct_cnt = 0;

uint16_t sk_tx_delay_qlen = 16;                 /* packets */
uint16_t sk_tx_delay_timeout = (1 * 1000);        /* microseconds */

#define SK_NETIF_COMPAT_AUX_CELL_TX_RING_SZ     64
#define SK_NETIF_COMPAT_AUX_CELL_RX_RING_SZ     64
uint32_t sk_netif_compat_aux_cell_tx_ring_sz =
    SK_NETIF_COMPAT_AUX_CELL_TX_RING_SZ;
uint32_t sk_netif_compat_aux_cell_rx_ring_sz =
    SK_NETIF_COMPAT_AUX_CELL_RX_RING_SZ;

/* Wi-Fi Access Point */
#define SK_NETIF_COMPAT_WAP_TX_RING_SZ  128
#define SK_NETIF_COMPAT_WAP_RX_RING_SZ  128
uint32_t sk_netif_compat_wap_tx_ring_sz = SK_NETIF_COMPAT_WAP_TX_RING_SZ;
uint32_t sk_netif_compat_wap_rx_ring_sz = SK_NETIF_COMPAT_WAP_RX_RING_SZ;

/* AWDL */
#define SK_NETIF_COMPAT_AWDL_TX_RING_SZ 128
#define SK_NETIF_COMPAT_AWDL_RX_RING_SZ 128
uint32_t sk_netif_compat_awdl_tx_ring_sz = SK_NETIF_COMPAT_AWDL_TX_RING_SZ;
uint32_t sk_netif_compat_awdl_rx_ring_sz = SK_NETIF_COMPAT_AWDL_RX_RING_SZ;

/* Wi-Fi Infrastructure */
#define SK_NETIF_COMPAT_WIF_TX_RING_SZ  128
#define SK_NETIF_COMPAT_WIF_RX_RING_SZ  128
uint32_t sk_netif_compat_wif_tx_ring_sz = SK_NETIF_COMPAT_WIF_TX_RING_SZ;
uint32_t sk_netif_compat_wif_rx_ring_sz = SK_NETIF_COMPAT_WIF_RX_RING_SZ;

#define SK_NETIF_COMPAT_USB_ETH_TX_RING_SZ      128
#define SK_NETIF_COMPAT_USB_ETH_RX_RING_SZ      128
uint32_t sk_netif_compat_usb_eth_tx_ring_sz =
    SK_NETIF_COMPAT_USB_ETH_TX_RING_SZ;
uint32_t sk_netif_compat_usb_eth_rx_ring_sz =
    SK_NETIF_COMPAT_USB_ETH_RX_RING_SZ;

#define SK_NETIF_COMPAT_RX_MBQ_LIMIT    8192
int sk_netif_compat_rx_mbq_limit = SK_NETIF_COMPAT_RX_MBQ_LIMIT;

uint32_t sk_netif_tx_mit = SK_NETIF_MIT_AUTO;
uint32_t sk_netif_rx_mit = SK_NETIF_MIT_AUTO;
char sk_ll_prefix[IFNAMSIZ] = "llw";
uint32_t sk_rx_sync_packets = 1;
uint32_t sk_channel_buflet_alloc = 0;

SYSCTL_NODE(_kern, OID_AUTO, skywalk, CTLFLAG_RW | CTLFLAG_LOCKED,
    0, "Skywalk parameters");
SYSCTL_NODE(_kern_skywalk, OID_AUTO, stats, CTLFLAG_RW | CTLFLAG_LOCKED,
    0, "Skywalk statistics");

SYSCTL_OPAQUE(_kern_skywalk, OID_AUTO, features, CTLFLAG_RD | CTLFLAG_LOCKED,
    &sk_features, sizeof(sk_features), "-", "Skywalk features");

#if (DEVELOPMENT || DEBUG)
SYSCTL_QUAD(_kern_skywalk, OID_AUTO, verbose, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sk_verbose, "Skywalk verbose mode");
SYSCTL_UINT(_kern_skywalk, OID_AUTO, debug, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sk_debug, 0, "Skywalk debug mode");
SYSCTL_LONG(_kern_skywalk, OID_AUTO, sk_copy_thres, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sk_copy_thres, "Skywalk copy threshold");
static int __priv_check = 1;
SYSCTL_INT(_kern_skywalk, OID_AUTO, priv_check, CTLFLAG_RW | CTLFLAG_LOCKED,
    &__priv_check, 0, "Skywalk privilege check");
SYSCTL_UINT(_kern_skywalk, OID_AUTO, sk_opp_defunct, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sk_opp_defunct, 0, "Defunct opportunistically");
SYSCTL_UINT(_kern_skywalk, OID_AUTO, sk_cksum_tx, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sk_cksum_tx, 0, "Advertise (and perform) outbound checksum offload");
SYSCTL_UINT(_kern_skywalk, OID_AUTO, sk_cksum_rx, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sk_cksum_rx, 0, "Perform inbound checksum offload");
SYSCTL_UINT(_kern_skywalk, OID_AUTO, sk_rx_sync_packets, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sk_rx_sync_packets, 0, "Enable RX sync packets");
SYSCTL_UINT(_kern_skywalk, OID_AUTO, chan_buf_alloc,
    CTLFLAG_RW | CTLFLAG_LOCKED, &sk_channel_buflet_alloc, 0,
    "channel buflet allocation (enable/disable)");
#endif /* !DEVELOPMENT && !DEBUG */

#if (DEVELOPMENT || DEBUG)
uint32_t sk_inject_error_rmask = 0x3;
SYSCTL_UINT(_kern_skywalk, OID_AUTO, inject_error_rmask,
    CTLFLAG_RW | CTLFLAG_LOCKED, &sk_inject_error_rmask, 0x3, "");
#endif /* !DEVELOPMENT && !DEBUG */

#if (DEVELOPMENT || DEBUG)
static void skywalk_self_tests(void);
#endif /* (DEVELOPMENT || DEBUG) */

#define SKMEM_TAG_SYSCTL_BUF "com.apple.skywalk.sysctl_buf"
kern_allocation_name_t skmem_tag_sysctl_buf;

#define SKMEM_TAG_OID       "com.apple.skywalk.skoid"
kern_allocation_name_t skmem_tag_oid;

#if (SK_LOG || DEVELOPMENT || DEBUG)
#define SKMEM_TAG_DUMP  "com.apple.skywalk.dump"
static kern_allocation_name_t skmem_tag_dump;

static char *sk_dump_buf;
#define SK_DUMP_BUF_SIZE        2048
#define SK_DUMP_BUF_ALIGN       16
#endif /* (SK_LOG || DEVELOPMENT || DEBUG) */

boolean_t
skywalk_netif_direct_enabled(void)
{
	return sk_netif_direct_cnt > 0;
}

boolean_t
skywalk_netif_direct_allowed(const char *ifname)
{
	uint32_t i;

	for (i = 0; i < sk_netif_direct_cnt; i++) {
		if (strncmp(ifname, sk_netif_direct[i], IFXNAMSIZ) == 0) {
			return TRUE;
		}
	}
	return FALSE;
}

#if (DEVELOPMENT || DEBUG)
static void
parse_netif_direct(void)
{
	char buf[(IFXNAMSIZ + 1) * SK_NETIF_DIRECT_MAX];
	size_t i, curr, len, iflen;

	if (!PE_parse_boot_arg_str("sk_netif_direct", buf, sizeof(buf))) {
		return;
	}

	curr = 0;
	len = strlen(buf);
	for (i = 0; i < len + 1 &&
	    sk_netif_direct_cnt < SK_NETIF_DIRECT_MAX; i++) {
		if (buf[i] != ',' && buf[i] != '\0') {
			continue;
		}

		buf[i] = '\0';
		iflen = i - curr;
		if (iflen > 0 && iflen < IFXNAMSIZ) {
			(void) strlcpy(sk_netif_direct[sk_netif_direct_cnt],
			    buf + curr, IFXNAMSIZ);
			sk_netif_direct_cnt++;
		}
		curr = i + 1;
	}
}
#endif /* DEVELOPMENT || DEBUG */

static void
skywalk_fini(void)
{
	SK_LOCK_ASSERT_HELD();

	if (__sk_inited) {
#if (DEVELOPMENT || DEBUG)
		skmem_test_fini();
		cht_test_fini();
#endif /* (DEVELOPMENT || DEBUG) */
		channel_fini();
		nexus_fini();
		skmem_fini();

#if (SK_LOG || DEVELOPMENT || DEBUG)
		if (skmem_tag_dump != NULL) {
			kern_allocation_name_release(skmem_tag_dump);
			skmem_tag_dump = NULL;
		}
		if (sk_dump_buf != NULL) {
			sk_free_data(sk_dump_buf, SK_DUMP_BUF_SIZE);
			sk_dump_buf = NULL;
		}
#endif /* (SK_LOG || DEVELOPMENT || DEBUG) */

		if (skmem_tag_sysctl_buf != NULL) {
			kern_allocation_name_release(skmem_tag_sysctl_buf);
			skmem_tag_sysctl_buf = NULL;
		}

		if (skmem_tag_oid != NULL) {
			kern_allocation_name_release(skmem_tag_oid);
			skmem_tag_oid = NULL;
		}

		__sk_inited = 0;
	}
}

int
skywalk_init(void)
{
	int error;

	VERIFY(!__sk_inited);

	_CASSERT(sizeof(kern_packet_t) == sizeof(uint64_t));
	_CASSERT(sizeof(bitmap_t) == sizeof(uint64_t));

#if (DEVELOPMENT || DEBUG)
	PE_parse_boot_argn("sk_debug", &sk_debug, sizeof(sk_debug));
	PE_parse_boot_argn("sk_verbose", &sk_verbose, sizeof(sk_verbose));
	(void) PE_parse_boot_argn("sk_opp_defunct", &sk_opp_defunct,
	    sizeof(sk_opp_defunct));
	(void) PE_parse_boot_argn("sk_cksum_tx", &sk_cksum_tx,
	    sizeof(sk_cksum_tx));
	(void) PE_parse_boot_argn("sk_cksum_rx", &sk_cksum_rx,
	    sizeof(sk_cksum_rx));
	(void) PE_parse_boot_argn("sk_txring_sz", &sk_txring_sz,
	    sizeof(sk_txring_sz));
	(void) PE_parse_boot_argn("sk_rxring_sz", &sk_rxring_sz,
	    sizeof(sk_rxring_sz));
	(void) PE_parse_boot_argn("sk_net_txring_sz", &sk_net_txring_sz,
	    sizeof(sk_net_txring_sz));
	(void) PE_parse_boot_argn("sk_net_rxring_sz", &sk_net_rxring_sz,
	    sizeof(sk_net_rxring_sz));
	(void) PE_parse_boot_argn("sk_max_flows", &sk_max_flows,
	    sizeof(sk_max_flows));
	(void) PE_parse_boot_argn("sk_native_txmodel", &sk_netif_native_txmodel,
	    sizeof(sk_netif_native_txmodel));
	(void) PE_parse_boot_argn("sk_compat_txmodel", &sk_netif_compat_txmodel,
	    sizeof(sk_netif_compat_txmodel));
	(void) PE_parse_boot_argn("sk_tx_delay_qlen", &sk_tx_delay_qlen,
	    sizeof(sk_tx_delay_qlen));
	(void) PE_parse_boot_argn("sk_ts_delay_timeout", &sk_tx_delay_timeout,
	    sizeof(sk_tx_delay_timeout));
	(void) PE_parse_boot_argn("sk_compat_aux_cell_tx_ring_sz",
	    &sk_netif_compat_aux_cell_tx_ring_sz,
	    sizeof(sk_netif_compat_aux_cell_tx_ring_sz));
	(void) PE_parse_boot_argn("sk_compat_aux_cell_rx_ring_sz",
	    &sk_netif_compat_aux_cell_rx_ring_sz,
	    sizeof(sk_netif_compat_aux_cell_rx_ring_sz));
	(void) PE_parse_boot_argn("sk_compat_wap_tx_ring_sz",
	    &sk_netif_compat_wap_tx_ring_sz,
	    sizeof(sk_netif_compat_wap_tx_ring_sz));
	(void) PE_parse_boot_argn("sk_compat_wap_rx_ring_sz",
	    &sk_netif_compat_wap_rx_ring_sz,
	    sizeof(sk_netif_compat_wap_rx_ring_sz));
	(void) PE_parse_boot_argn("sk_compat_awdl_tx_ring_sz",
	    &sk_netif_compat_awdl_tx_ring_sz,
	    sizeof(sk_netif_compat_awdl_tx_ring_sz));
	(void) PE_parse_boot_argn("sk_compat_awdl_rx_ring_sz",
	    &sk_netif_compat_awdl_rx_ring_sz,
	    sizeof(sk_netif_compat_awdl_rx_ring_sz));
	(void) PE_parse_boot_argn("sk_compat_wif_tx_ring_sz",
	    &sk_netif_compat_wif_tx_ring_sz,
	    sizeof(sk_netif_compat_wif_tx_ring_sz));
	(void) PE_parse_boot_argn("sk_compat_wif_rx_ring_sz",
	    &sk_netif_compat_wif_rx_ring_sz,
	    sizeof(sk_netif_compat_wif_rx_ring_sz));
	(void) PE_parse_boot_argn("sk_compat_usb_eth_tx_ring_sz",
	    &sk_netif_compat_usb_eth_tx_ring_sz,
	    sizeof(sk_netif_compat_usb_eth_tx_ring_sz));
	(void) PE_parse_boot_argn("sk_compat_usb_eth_rx_ring_sz",
	    &sk_netif_compat_usb_eth_rx_ring_sz,
	    sizeof(sk_netif_compat_usb_eth_rx_ring_sz));
	(void) PE_parse_boot_argn("sk_compat_rx_mbq_limit",
	    &sk_netif_compat_rx_mbq_limit, sizeof(sk_netif_compat_rx_mbq_limit));
	(void) PE_parse_boot_argn("sk_netif_tx_mit",
	    &sk_netif_tx_mit, sizeof(sk_netif_tx_mit));
	(void) PE_parse_boot_argn("sk_netif_rx_mit",
	    &sk_netif_rx_mit, sizeof(sk_netif_rx_mit));
	(void) PE_parse_boot_arg_str("sk_ll_prefix", sk_ll_prefix,
	    sizeof(sk_ll_prefix));
	parse_netif_direct();
	(void) PE_parse_boot_argn("sk_fsw_rx_agg_tcp", &sk_fsw_rx_agg_tcp,
	    sizeof(sk_fsw_rx_agg_tcp));
	(void) PE_parse_boot_argn("sk_fsw_tx_agg_tcp", &sk_fsw_tx_agg_tcp,
	    sizeof(sk_fsw_tx_agg_tcp));
	(void) PE_parse_boot_argn("sk_fsw_max_bufs", &sk_fsw_max_bufs,
	    sizeof(sk_fsw_max_bufs));
	(void) PE_parse_boot_argn("sk_rx_sync_packets", &sk_rx_sync_packets,
	    sizeof(sk_rx_sync_packets));
	(void) PE_parse_boot_argn("sk_chan_buf_alloc", &sk_channel_buflet_alloc,
	    sizeof(sk_channel_buflet_alloc));
	(void) PE_parse_boot_argn("sk_guard", &sk_guard, sizeof(sk_guard));
	(void) PE_parse_boot_argn("sk_headguard_sz", &sk_headguard_sz,
	    sizeof(sk_headguard_sz));
	(void) PE_parse_boot_argn("sk_tailguard_sz", &sk_tailguard_sz,
	    sizeof(sk_tailguard_sz));
	(void) PE_parse_boot_argn("sk_min_pool_size", &sk_min_pool_size,
	    sizeof(sk_min_pool_size));
#endif /* DEVELOPMENT || DEBUG */

	if (sk_max_flows == 0) {
		sk_max_flows = NX_FLOWADV_DEFAULT;
	} else if (sk_max_flows > NX_FLOWADV_MAX) {
		sk_max_flows = NX_FLOWADV_MAX;
	}

	if (sk_netif_tx_mit > SK_NETIF_MIT_MAX) {
		sk_netif_tx_mit = SK_NETIF_MIT_MAX;
	}
	if (sk_netif_rx_mit > SK_NETIF_MIT_MAX) {
		sk_netif_rx_mit = SK_NETIF_MIT_MAX;
	}

	sk_fadv_nchunks = (uint32_t)P2ROUNDUP(sk_max_flows, FO_FLOWADV_CHUNK) /
	    FO_FLOWADV_CHUNK;

	if (sk_guard) {
		uint32_t sz;
		/* leading guard page(s) */
		if (sk_headguard_sz == 0) {
			read_frandom(&sz, sizeof(sz));
			sk_headguard_sz = (sz % (SK_GUARD_MAX + 1));
		} else if (sk_headguard_sz > SK_GUARD_MAX) {
			sk_headguard_sz = SK_GUARD_MAX;
		}
		if (sk_headguard_sz < SK_GUARD_MIN) {
			sk_headguard_sz = SK_GUARD_MIN;
		}
		/* trailing guard page(s) */
		if (sk_tailguard_sz == 0) {
			read_frandom(&sz, sizeof(sz));
			sk_tailguard_sz = (sz % (SK_GUARD_MAX + 1));
		} else if (sk_tailguard_sz > SK_GUARD_MAX) {
			sk_tailguard_sz = SK_GUARD_MAX;
		}
		if (sk_tailguard_sz < SK_GUARD_MIN) {
			sk_tailguard_sz = SK_GUARD_MIN;
		}
	} else {
		sk_headguard_sz = sk_tailguard_sz = SK_GUARD_MIN;
	}
	ASSERT(sk_headguard_sz >= SK_GUARD_MIN);
	ASSERT(sk_headguard_sz <= SK_GUARD_MAX);
	ASSERT(sk_tailguard_sz >= SK_GUARD_MIN);
	ASSERT(sk_tailguard_sz <= SK_GUARD_MAX);

	__sk_inited = 1;

	SK_LOCK();
	cuckoo_hashtable_init();
	skmem_init();
	error = nexus_init();
	if (error == 0) {
		error = channel_init();
	}
	if (error != 0) {
		skywalk_fini();
	}
	SK_UNLOCK();

	if (error == 0) {
		ASSERT(skmem_tag_oid == NULL);
		skmem_tag_oid = kern_allocation_name_allocate(SKMEM_TAG_OID, 0);
		ASSERT(skmem_tag_oid != NULL);

		ASSERT(skmem_tag_sysctl_buf == NULL);
		skmem_tag_sysctl_buf =
		    kern_allocation_name_allocate(SKMEM_TAG_SYSCTL_BUF, 0);
		ASSERT(skmem_tag_sysctl_buf != NULL);

#if (SK_LOG || DEVELOPMENT || DEBUG)
		ASSERT(skmem_tag_dump == NULL);
		skmem_tag_dump =
		    kern_allocation_name_allocate(SKMEM_TAG_DUMP, 0);
		ASSERT(skmem_tag_dump != NULL);

		/* allocate space for sk_dump_buf */
		sk_dump_buf = sk_alloc_data(SK_DUMP_BUF_SIZE, Z_WAITOK | Z_NOFAIL,
		    skmem_tag_dump);
#endif /* (SK_LOG || DEVELOPMENT || DEBUG) */

		netns_init();
		protons_init();

#if (DEVELOPMENT || DEBUG)
		skywalk_self_tests();
		skmem_test_init();
		cht_test_init();
#endif /* DEVELOPMENT || DEBUG */
	}

	return error;
}

/*
 * csproc_get_platform_binary() returns non-zero if the process is platform
 * code, which means that it is considered part of the Operating System.
 * On iOS, that means it's contained in the trust cache or a loaded one.
 * On macOS, everything signed by B&I is currently platform code, but the
 * policy in general is subject to change.  Thus this is an approximate.
 */
boolean_t
skywalk_check_platform_binary(proc_t p)
{
	return (csproc_get_platform_binary(p) == 0) ? FALSE : TRUE;
}

static int
sk_priv_chk(proc_t p, kauth_cred_t cred, int priv)
{
#pragma unused(p)
	int ret = priv_check_cred(cred, priv, 0);

#if (DEVELOPMENT || DEBUG)
	if (ret != 0) {
		const char *pstr;

		switch (priv) {
		case PRIV_SKYWALK_REGISTER_USER_PIPE:
			pstr = "com.apple.private.skywalk.register-user-pipe";
			break;

		case PRIV_SKYWALK_REGISTER_KERNEL_PIPE:
			pstr = "com.apple.private.skywalk.register-kernel-pipe";
			break;

		case PRIV_SKYWALK_REGISTER_NET_IF:
			pstr = "com.apple.private.skywalk.register-net-if";
			break;

		case PRIV_SKYWALK_REGISTER_FLOW_SWITCH:
			pstr = "com.apple.private.skywalk.register-flow-switch";
			break;

		case PRIV_SKYWALK_OBSERVE_ALL:
			pstr = "com.apple.private.skywalk.observe-all";
			break;

		case PRIV_SKYWALK_OBSERVE_STATS:
			pstr = "com.apple.private.skywalk.observe-stats";
			break;

		case PRIV_SKYWALK_LOW_LATENCY_CHANNEL:
			pstr = "com.apple.private.skywalk.low-latency-channel";
			break;

		default:
			pstr = "unknown";
			break;
		}

#if SK_LOG
		if (__priv_check) {
			SK_DF(SK_VERB_PRIV, "%s(%d) insufficient privilege %d "
			    "(\"%s\") err %d", sk_proc_name_address(p),
			    sk_proc_pid(p), priv, pstr, ret);
		} else {
			SK_DF(SK_VERB_PRIV, "%s(%d) IGNORING missing privilege "
			    "%d (\"%s\") err %d", sk_proc_name_address(p),
			    sk_proc_pid(p), priv, pstr, ret);
		}
#endif /* SK_LOG */

		/* ignore privilege check failures if requested */
		if (!__priv_check) {
			ret = 0;
		}
	}
#endif /* !DEVELOPMENT && !DEBUG */

	return ret;
}

int
skywalk_priv_check_cred(proc_t p, kauth_cred_t cred, int priv)
{
	return sk_priv_chk(p, cred, priv);
}

int
skywalk_priv_check_proc_cred(proc_t p, int priv)
{
	int ret;
	kauth_cred_t cred = kauth_cred_proc_ref(p);
	ret = sk_priv_chk(p, cred, priv);
	kauth_cred_unref(&cred);

	return ret;
}

#if CONFIG_MACF
int
skywalk_mac_system_check_proc_cred(proc_t p, const char *info_type)
{
	int ret;
	kauth_cred_t cred = kauth_cred_proc_ref(p);
	ret = mac_system_check_info(cred, info_type);
	kauth_cred_unref(&cred);

	return ret;
}
#endif /* CONFIG_MACF */

/*
 * Scan thru the list of privileges needed before we allow someone
 * to open a handle to the Nexus controller.  This should be done
 * at nxctl_create() time, and additional privilege check specific
 * to the operation (e.g. register, etc.) should be done afterwards.
 */
int
skywalk_nxctl_check_privileges(proc_t p, kauth_cred_t cred)
{
	int ret = 0;

	if (p == kernproc) {
		goto done;
	}

	do {
		/*
		 * Check for observe-{stats,all} entitlements first
		 * before the rest, to account for nexus controller
		 * clients that don't need anything but statistics;
		 * it would help quiesce sandbox violation warnings.
		 */
		if ((ret = sk_priv_chk(p, cred,
		    PRIV_SKYWALK_OBSERVE_STATS)) == 0) {
			break;
		}
		if ((ret = sk_priv_chk(p, cred,
		    PRIV_SKYWALK_OBSERVE_ALL)) == 0) {
			break;
		}
		if ((ret = sk_priv_chk(p, cred,
		    PRIV_SKYWALK_REGISTER_USER_PIPE)) == 0) {
			break;
		}
		if ((ret = sk_priv_chk(p, cred,
		    PRIV_SKYWALK_REGISTER_KERNEL_PIPE)) == 0) {
			break;
		}
		if ((ret = sk_priv_chk(p, cred,
		    PRIV_SKYWALK_REGISTER_NET_IF)) == 0) {
			break;
		}
		if ((ret = sk_priv_chk(p, cred,
		    PRIV_SKYWALK_REGISTER_FLOW_SWITCH)) == 0) {
			break;
		}
		/* none set, so too bad */
		ret = EPERM;
	} while (0);

#if (DEVELOPMENT || DEBUG)
	if (ret != 0) {
		SK_ERR("%s(%d) insufficient privilege to open nexus controller "
		    "err %d", sk_proc_name_address(p), sk_proc_pid(p), ret);
	}
#endif /* !DEVELOPMENT && !DEBUG */
done:
	return ret;
}

void
sk_gen_guard_id(boolean_t isch, const uuid_t uuid, guardid_t *guard)
{
#define GUARD_CH_SIG    0x4348  /* 'CH' */
#define GUARD_NX_SIG    0x4e58  /* 'NX' */
	union {
		uint8_t         _u8[8];
		uint16_t        _u16[4];
		uint64_t        _u64;
	} __u;

	read_random(&__u._u16[0], sizeof(uint16_t));
	bcopy(uuid, (void *)&__u._u16[1], sizeof(uint16_t));
	__u._u16[2] = htole16(isch ? GUARD_CH_SIG : GUARD_NX_SIG);
	__u._u16[3] = htole16(0x534b);  /* 'SK' */
	VERIFY(__u._u64 != 0);

	bzero(guard, sizeof(*guard));
	bcopy((void *)&__u._u64, guard, MIN(sizeof(*guard),
	    sizeof(uint64_t)));
}


extern const char *
sk_uuid_unparse(const uuid_t uu, uuid_string_t out)
{
	uuid_unparse_upper(uu, out);
	return (const char *)out;
}

#if SK_LOG
/*
 * packet-dump function, user-supplied or static buffer.
 * The destination buffer must be at least 30+4*len
 *
 * @param p
 *   buffer to be dumped.
 * @param len
 *   buffer's total length.
 * @param dumplen
 *   length to be dumped.
 * @param dst
 *   destination char buffer. sk_dump_buf would be used if dst is NULL.
 * @param lim
 *   destination char buffer max length. Not used if dst is NULL.
 *
 */
const char *
sk_dump(const char *label, const void *obj, int len, int dumplen,
    char *dst, int lim)
{
	int i, j, i0, n = 0;
	static char hex[] = "0123456789abcdef";
	const char *p = obj;    /* dump cursor */
	char *o;        /* output position */

#define P_HI(x) hex[((x) & 0xf0) >> 4]
#define P_LO(x) hex[((x) & 0xf)]
#define P_C(x)  ((x) >= 0x20 && (x) <= 0x7e ? (x) : '.')
	if (lim <= 0 || lim > len) {
		lim = len;
	}
	if (dst == NULL) {
		dst = sk_dump_buf;
		lim = SK_DUMP_BUF_SIZE;
	}
	dumplen = MIN(len, dumplen);
	o = dst;
	n += scnprintf(o, lim, "%s 0x%llx len %d lim %d\n", label,
	    SK_KVA(p), len, lim);
	o += strlen(o);
	/* hexdump routine */
	for (i = 0; i < dumplen;) {
		n += scnprintf(o, lim - n, "%5d: ", i);
		o += strlen(o);
		memset(o, ' ', 48);
		i0 = i;
		for (j = 0; j < 16 && i < dumplen; i++, j++) {
			o[j * 3] = P_HI(p[i]);
			o[j * 3 + 1] = P_LO(p[i]);
		}
		i = i0;
		for (j = 0; j < 16 && i < dumplen; i++, j++) {
			o[j + 48] = P_C(p[i]);
		}
		o[j + 48] = '\n';
		o += j + 49;
	}
	*o = '\0';
#undef P_HI
#undef P_LO
#undef P_C
	return dst;
}

/*
 * "Safe" variant of proc_name_address(), mean to be used only for logging.
 */
const char *
sk_proc_name_address(struct proc *p)
{
	if (p == PROC_NULL) {
		return "proc_null";
	}

	return proc_name_address(p);
}

/*
 * "Safe" variant of proc_pid(), mean to be used only for logging.
 */
int
sk_proc_pid(struct proc *p)
{
	if (p == PROC_NULL) {
		return -1;
	}

	return proc_pid(p);
}

const char *
sk_sa_ntop(struct sockaddr *sa, char *addr_str, size_t addr_strlen)
{
	const char *str = NULL;

	addr_str[0] = '\0';

	switch (sa->sa_family) {
	case AF_INET:
		str = inet_ntop(AF_INET, &SIN(sa)->sin_addr.s_addr,
		    addr_str, (socklen_t)addr_strlen);
		break;

	case AF_INET6:
		str = inet_ntop(AF_INET6, &SIN6(sa)->sin6_addr,
		    addr_str, (socklen_t)addr_strlen);
		break;

	default:
		str = addr_str;
		break;
	}

	return str;
}

const char *
sk_memstatus2str(uint32_t status)
{
	const char *str = NULL;

	switch (status) {
	case kMemorystatusInvalid:
		str = "kMemorystatusInvalid";
		break;

	case kMemorystatusKilled:
		str = "kMemorystatusKilled";
		break;

	case kMemorystatusKilledHiwat:
		str = "kMemorystatusKilledHiwat";
		break;

	case kMemorystatusKilledVnodes:
		str = "kMemorystatusKilledVnodes";
		break;

	case kMemorystatusKilledVMPageShortage:
		str = "kMemorystatusKilledVMPageShortage";
		break;

	case kMemorystatusKilledProcThrashing:
		str = "kMemorystatusKilledProcThrashing";
		break;

	case kMemorystatusKilledVMCompressorThrashing:
		str = "kMemorystatusKilledVMCompressorThrashing";
		break;

	case kMemorystatusKilledVMCompressorSpaceShortage:
		str = "kMemorystatusKilledVMCompressorSpaceShortage";
		break;

	case kMemorystatusKilledFCThrashing:
		str = "kMemorystatusKilledFCThrashing";
		break;

	case kMemorystatusKilledPerProcessLimit:
		str = "kMemorystatusKilledPerProcessLimit";
		break;

	case kMemorystatusKilledDiskSpaceShortage:
		str = "kMemorystatusKilledDiskSpaceShortage";
		break;

	case kMemorystatusKilledIdleExit:
		str = "kMemorystatusKilledIdleExit";
		break;

	case kMemorystatusKilledZoneMapExhaustion:
		str = "kMemorystatusKilledZoneMapExhaustion";
		break;

	default:
		str = "unknown";
		break;
	}

	return str;
}
#endif /* SK_LOG */

bool
sk_sa_has_addr(struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		ASSERT(sa->sa_len == sizeof(struct sockaddr_in));
		return SIN(sa)->sin_addr.s_addr != INADDR_ANY;
	case AF_INET6:
		ASSERT(sa->sa_len == sizeof(struct sockaddr_in6));
		return !IN6_IS_ADDR_UNSPECIFIED(&SIN6(sa)->sin6_addr);
	default:
		return false;
	}
}

bool
sk_sa_has_port(struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		ASSERT(sa->sa_len == sizeof(struct sockaddr_in));
		return SIN(sa)->sin_port != 0;
	case AF_INET6:
		ASSERT(sa->sa_len == sizeof(struct sockaddr_in6));
		return SIN6(sa)->sin6_port != 0;
	default:
		return false;
	}
}

/* returns port number in host byte order */
uint16_t
sk_sa_get_port(struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		ASSERT(sa->sa_len == sizeof(struct sockaddr_in));
		return ntohs(SIN(sa)->sin_port);
	case AF_INET6:
		ASSERT(sa->sa_len == sizeof(struct sockaddr_in6));
		return ntohs(SIN6(sa)->sin6_port);
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

void
skywalk_kill_process(struct proc *p, uint64_t reason_code)
{
	os_reason_t exit_reason = OS_REASON_NULL;

	VERIFY(p != kernproc);

	exit_reason = os_reason_create(OS_REASON_SKYWALK, reason_code);
	if (exit_reason == OS_REASON_NULL) {
		SK_ERR("%s(%d) unable to allocate memory for crash reason "
		    "0x%llX", sk_proc_name_address(p), sk_proc_pid(p),
		    reason_code);
	} else {
		exit_reason->osr_flags |= OS_REASON_FLAG_GENERATE_CRASH_REPORT;
		SK_ERR("%s(%d) aborted for reason 0x%llX",
		    sk_proc_name_address(p), sk_proc_pid(p), reason_code);
	}

	psignal_try_thread_with_reason(p, current_thread(), SIGABRT,
	    exit_reason);
}

#if (DEVELOPMENT || DEBUG)
#define SK_MEMCMP_LEN 256               /* length of each section */
#define SK_MASK_MAXLEN 80               /* maximum mask length */

#define SK_MEMCMP_MASK_VERIFY(t, l, lr) do {                            \
	_CASSERT(sizeof(t##_m) == SK_MASK_MAXLEN);                      \
	if ((sk_memcmp_mask_##l##B(hdr1, hdr2, t##_m) != 0) ^           \
	    (skywalk_memcmp_mask_ref(hdr1, hdr2, t##_m, lr) != 0)) {    \
	        panic_plain("\nbroken: " #t " using "                   \
	            "sk_memcmp_mask_" #l " at i=%d\n", i);              \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
	if ((sk_memcmp_mask_##l##B##_scalar(hdr1, hdr2, t##_m) != 0) ^  \
	    (skywalk_memcmp_mask_ref(hdr1, hdr2, t##_m, lr) != 0)) {    \
	        panic_plain("\nbroken: " #t " using "                   \
	            "sk_memcmp_mask_" #l "_scalar at i=%d\n", i);       \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

#define SK_MEMCMP_MASK_MATCH_VERIFY(t, l) do {                          \
	if (sk_memcmp_mask_##l##B(hdr1, hdr2, t##_m) != 0) {            \
	        panic_plain("\nbroken: " #t " using sk_memcmp_mask_" #l \
	            " mismatch (expected match) at i=%d s1=0x%x"        \
	            " s2=0x%x\n", i, hdr1[i], hdr2[i]);                 \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
	if (sk_memcmp_mask_##l##B##_scalar(hdr1, hdr2, t##_m) != 0) {   \
	        panic_plain("\nbroken: " #t " using sk_memcmp_mask_" #l \
	            "_scalar mismatch (expected match) at i=%d s1=0x%x" \
	            " s2=0x%x\n", i, hdr1[i], hdr2[i]);                 \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

#define SK_MEMCMP_MASK_MISMATCH_VERIFY(t, l) do {                       \
	if (sk_memcmp_mask_##l##B(hdr1, hdr2, t##_m) == 0) {            \
	        panic_plain("\nbroken: " #t " using sk_memcmp_mask_" #l \
	            " match (expected mismatch) at i=%d s1=0x%x"        \
	            " s2=0x%x\n", i, hdr1[i], hdr2[i]);                 \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
	if (sk_memcmp_mask_##l##B##_scalar(hdr1, hdr2, t##_m) == 0) {   \
	        panic_plain("\nbroken: " #t " using sk_memcmp_mask_" #l \
	            "_scalar match (expected mismatch) at i=%d "        \
	            "s1=0x%x s2=0x%x\n", i, hdr1[i], hdr2[i]);          \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

#define SK_MEMCMP_BYTEMASK_VERIFY(t) do {                               \
	if ((sk_memcmp_mask(hdr1, hdr2, t##_m, i) != 0) ^               \
	    (skywalk_memcmp_mask_ref(hdr1, hdr2, t##_m, i) != 0)) {     \
	        panic_plain("\nbroken: " #t " using "                   \
	            "sk_memcmp_mask at i=%d\n", i);                     \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
	if ((sk_memcmp_mask_scalar(hdr1, hdr2, t##_m, i) != 0) ^        \
	    (skywalk_memcmp_mask_ref(hdr1, hdr2, t##_m, i) != 0)) {     \
	        panic_plain("\nbroken: " #t " using "                   \
	            "sk_memcmp_mask_scalar at i=%d\n", i);              \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

static inline int
skywalk_memcmp_mask_ref(const uint8_t *src1, const uint8_t *src2,
    const uint8_t *byte_mask, size_t n)
{
	uint32_t result = 0;
	for (size_t i = 0; i < n; i++) {
		result |= (src1[i] ^ src2[i]) & byte_mask[i];
	}
	return result;
}

static void
skywalk_memcmp_mask_self_tests(void)
{
	static const uint8_t ipv4_m[] = {
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff,
		0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t ipv6_m[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t tcp_m[] = {
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t ipv6_tcp_m[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t udp_m[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t fk_all_m[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t fk_t2_m[] = {
		0x0a, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t fk_t3_m[] = {
		0x0f, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t fk_t4_m[] = {
		0x2f, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t fk_t5_m[] = {
		0x3f, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t fk_i1_m[] = {
		0x02, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t fk_i2_m[] = {
		0x07, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t fk_i3_m[] = {
		0x17, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	/* validate flow entry mask (2-tuple) */
	_CASSERT(FKMASK_2TUPLE == (FKMASK_PROTO | FKMASK_SPORT));
	VERIFY(fk_mask_2tuple.fk_mask == FKMASK_2TUPLE);
	VERIFY(fk_mask_2tuple.fk_ipver == 0);
	VERIFY(fk_mask_2tuple.fk_proto == 0xff);
	VERIFY(fk_mask_2tuple.fk_sport == 0xffff);
	VERIFY(fk_mask_2tuple.fk_dport == 0);
	VERIFY(fk_mask_2tuple.fk_src._addr64[0] == 0);
	VERIFY(fk_mask_2tuple.fk_src._addr64[1] == 0);
	VERIFY(fk_mask_2tuple.fk_dst._addr64[0] == 0);
	VERIFY(fk_mask_2tuple.fk_dst._addr64[1] == 0);
	VERIFY(fk_mask_2tuple.fk_pad[0] == 0);

	_CASSERT(FKMASK_3TUPLE == (FKMASK_2TUPLE | FKMASK_IPVER | FKMASK_SRC));
	VERIFY(fk_mask_3tuple.fk_mask == FKMASK_3TUPLE);
	VERIFY(fk_mask_3tuple.fk_ipver == 0xff);
	VERIFY(fk_mask_3tuple.fk_proto == 0xff);
	VERIFY(fk_mask_3tuple.fk_sport == 0xffff);
	VERIFY(fk_mask_3tuple.fk_dport == 0);
	VERIFY(fk_mask_3tuple.fk_src._addr64[0] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_3tuple.fk_src._addr64[1] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_3tuple.fk_dst._addr64[0] == 0);
	VERIFY(fk_mask_3tuple.fk_dst._addr64[1] == 0);
	VERIFY(fk_mask_3tuple.fk_pad[0] == 0);

	_CASSERT(FKMASK_4TUPLE == (FKMASK_3TUPLE | FKMASK_DPORT));
	VERIFY(fk_mask_4tuple.fk_mask == FKMASK_4TUPLE);
	VERIFY(fk_mask_4tuple.fk_ipver == 0xff);
	VERIFY(fk_mask_4tuple.fk_proto == 0xff);
	VERIFY(fk_mask_4tuple.fk_sport == 0xffff);
	VERIFY(fk_mask_4tuple.fk_dport == 0xffff);
	VERIFY(fk_mask_4tuple.fk_src._addr64[0] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_4tuple.fk_src._addr64[1] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_4tuple.fk_dst._addr64[0] == 0);
	VERIFY(fk_mask_4tuple.fk_dst._addr64[1] == 0);
	VERIFY(fk_mask_4tuple.fk_pad[0] == 0);

	_CASSERT(FKMASK_5TUPLE == (FKMASK_4TUPLE | FKMASK_DST));
	VERIFY(fk_mask_5tuple.fk_mask == FKMASK_5TUPLE);
	VERIFY(fk_mask_5tuple.fk_ipver == 0xff);
	VERIFY(fk_mask_5tuple.fk_proto == 0xff);
	VERIFY(fk_mask_5tuple.fk_sport == 0xffff);
	VERIFY(fk_mask_5tuple.fk_dport == 0xffff);
	VERIFY(fk_mask_5tuple.fk_src._addr64[0] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_5tuple.fk_src._addr64[1] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_5tuple.fk_dst._addr64[0] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_5tuple.fk_dst._addr64[1] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_5tuple.fk_pad[0] == 0);

	_CASSERT(FKMASK_IPFLOW1 == FKMASK_PROTO);
	VERIFY(fk_mask_ipflow1.fk_mask == FKMASK_IPFLOW1);
	VERIFY(fk_mask_ipflow1.fk_ipver == 0);
	VERIFY(fk_mask_ipflow1.fk_proto == 0xff);
	VERIFY(fk_mask_ipflow1.fk_sport == 0);
	VERIFY(fk_mask_ipflow1.fk_dport == 0);
	VERIFY(fk_mask_ipflow1.fk_src._addr64[0] == 0);
	VERIFY(fk_mask_ipflow1.fk_src._addr64[1] == 0);
	VERIFY(fk_mask_ipflow1.fk_dst._addr64[0] == 0);
	VERIFY(fk_mask_ipflow1.fk_dst._addr64[1] == 0);
	VERIFY(fk_mask_ipflow1.fk_pad[0] == 0);

	_CASSERT(FKMASK_IPFLOW2 == (FKMASK_IPFLOW1 | FKMASK_IPVER | FKMASK_SRC));
	VERIFY(fk_mask_ipflow2.fk_mask == FKMASK_IPFLOW2);
	VERIFY(fk_mask_ipflow2.fk_ipver == 0xff);
	VERIFY(fk_mask_ipflow2.fk_proto == 0xff);
	VERIFY(fk_mask_ipflow2.fk_sport == 0);
	VERIFY(fk_mask_ipflow2.fk_dport == 0);
	VERIFY(fk_mask_ipflow2.fk_src._addr64[0] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_ipflow2.fk_src._addr64[1] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_ipflow2.fk_dst._addr64[0] == 0);
	VERIFY(fk_mask_ipflow2.fk_dst._addr64[1] == 0);
	VERIFY(fk_mask_ipflow2.fk_pad[0] == 0);

	_CASSERT(FKMASK_IPFLOW3 == (FKMASK_IPFLOW2 | FKMASK_DST));
	VERIFY(fk_mask_ipflow3.fk_mask == FKMASK_IPFLOW3);
	VERIFY(fk_mask_ipflow3.fk_ipver == 0xff);
	VERIFY(fk_mask_ipflow3.fk_proto == 0xff);
	VERIFY(fk_mask_ipflow3.fk_sport == 0);
	VERIFY(fk_mask_ipflow3.fk_dport == 0);
	VERIFY(fk_mask_ipflow3.fk_src._addr64[0] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_ipflow3.fk_src._addr64[1] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_ipflow3.fk_dst._addr64[0] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_ipflow3.fk_dst._addr64[1] == 0xffffffffffffffffULL);
	VERIFY(fk_mask_ipflow3.fk_pad[0] == 0);

	VERIFY(sk_dump_buf != NULL);

	/* reset sk_dump_buf */
	bzero(sk_dump_buf, SK_DUMP_BUF_SIZE);

	/*
	 * Utilize sk_dump_buf, by splitting it into 3 sections.  Each
	 * section begins on a 128-bit boundary, and is a multiple of
	 * 64-bytes len.  A section is SK_MEMCMP_LEN-bytes long,
	 * which means we need at least 16+(3*SK_MEMCMP_LEN) bytes.
	 *
	 * 1st section is s1 -> (hdr1 aligned to 16-bytes)
	 * 2nd section is s2 -> (hdr2 = hdr1 + SK_MEMCMP_LEN)
	 * 3rd section is s3 -> (mask = hdr2 + SK_MEMCMP_LEN)
	 */
	void *s1, *s2, *s3;

	s1 = sk_dump_buf;
	if (!IS_P2ALIGNED(s1, SK_DUMP_BUF_ALIGN)) {
		s1 = (void *)P2ROUNDUP(s1, SK_DUMP_BUF_ALIGN);
	}
	ASSERT(IS_P2ALIGNED(s1, SK_DUMP_BUF_ALIGN));
	s2 = (void *)((uintptr_t)s1 + SK_MEMCMP_LEN);
	ASSERT(IS_P2ALIGNED(s2, SK_DUMP_BUF_ALIGN));
	s3 = (void *)((uintptr_t)s2 + SK_MEMCMP_LEN);
	ASSERT(IS_P2ALIGNED(s3, SK_DUMP_BUF_ALIGN));

	uint8_t *hdr1 = s1;
	uint8_t *hdr2 = s2;
	uint8_t *byte_m = s3;

	/* fill byte mask with random data */
	read_frandom(byte_m, SK_MEMCMP_LEN);

	kprintf("Skywalk: memcmp mask ... ");

	int i;
	for (i = 0; i < 80; i++) {
		hdr1[i] = 1;
		SK_MEMCMP_MASK_VERIFY(ipv4, 32, 20);
		SK_MEMCMP_MASK_VERIFY(ipv6, 64, 40);
		SK_MEMCMP_MASK_VERIFY(ipv6_tcp, 80, 64);
		SK_MEMCMP_MASK_VERIFY(tcp, 32, 24);
		SK_MEMCMP_MASK_VERIFY(udp, 16, 6);
		SK_MEMCMP_MASK_VERIFY(fk_all, 48, 48);
		SK_MEMCMP_MASK_VERIFY(fk_t2, 48, 48);
		SK_MEMCMP_MASK_VERIFY(fk_t3, 48, 48);
		SK_MEMCMP_MASK_VERIFY(fk_t4, 48, 48);
		SK_MEMCMP_MASK_VERIFY(fk_t5, 48, 48);
		SK_MEMCMP_MASK_VERIFY(fk_i1, 48, 48);
		SK_MEMCMP_MASK_VERIFY(fk_i2, 48, 48);
		SK_MEMCMP_MASK_VERIFY(fk_i3, 48, 48);
		hdr2[i] = 1;
	}

	bzero(hdr1, SK_MEMCMP_LEN);
	bzero(hdr2, SK_MEMCMP_LEN);

	/* re-fill byte mask with random data */
	read_frandom(byte_m, SK_MEMCMP_LEN);

	for (i = 0; i < SK_MEMCMP_LEN; i++) {
		hdr1[i] = 1;
		SK_MEMCMP_BYTEMASK_VERIFY(byte);
		hdr2[i] = 1;
	}

	/* fill hdr1 and hd2 with random data */
	read_frandom(hdr1, SK_MEMCMP_LEN);
	bcopy(hdr1, hdr2, SK_MEMCMP_LEN);
	memset(byte_m, 0xff, SK_MEMCMP_LEN);

	for (i = 0; i < 80; i++) {
		uint8_t val = hdr2[i];
		uint8_t mval = byte_m[i];

		while (hdr2[i] == hdr1[i] || hdr2[i] == 0) {
			uint8_t newval;
			read_frandom(&newval, sizeof(newval));
			hdr2[i] = newval;
		}
		if (i < 16) {
			SK_MEMCMP_MASK_MISMATCH_VERIFY(byte, 16);
		} else if (i < 32) {
			SK_MEMCMP_MASK_MISMATCH_VERIFY(byte, 32);
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 16);
		} else if (i < 48) {
			SK_MEMCMP_MASK_MISMATCH_VERIFY(byte, 48);
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 32);
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 16);
		} else if (i < 64) {
			SK_MEMCMP_MASK_MISMATCH_VERIFY(byte, 64);
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 48);
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 32);
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 16);
		} else if (i < 80) {
			SK_MEMCMP_MASK_MISMATCH_VERIFY(byte, 80);
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 64);
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 48);
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 32);
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 16);
		}
		byte_m[i] = 0;
		if (i < 16) {
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 16);
		} else if (i < 32) {
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 32);
		} else if (i < 48) {
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 48);
		} else if (i < 64) {
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 64);
		} else if (i < 80) {
			SK_MEMCMP_MASK_MATCH_VERIFY(byte, 80);
		}
		hdr2[i] = val;
		byte_m[i] = mval;
	}

	kprintf("PASSED\n");
}

#define SK_COPY_LEN     128             /* length of each section */

#define SK_COPY_PREPARE(t) do {                                         \
	bzero(s2, SK_COPY_LEN);                                         \
	bzero(s3, SK_COPY_LEN);                                         \
	_s1 = s1; _s2 = s2; _s3 = s3;                                   \
	kprintf("Skywalk: " #t " ... ");                                \
} while (0)

#define SK_COPY_VERIFY(t) do {                                          \
	if (_s1 != s1 || _s2 != s2 || _s3 != s3) {                      \
	        panic_plain("\ninput registers clobbered: " #t "\n");   \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
	if (bcmp(s2, s3, SK_COPY_LEN) != 0) {                           \
	        panic_plain("\nbroken: " #t "\n");                      \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	} else {                                                        \
	        kprintf("PASSED\n");                                    \
	}                                                               \
} while (0)

#define SK_ZERO_PREPARE(t) do {                                         \
	bcopy(s1, s2, SK_COPY_LEN);                                     \
	bcopy(s1, s3, SK_COPY_LEN);                                     \
	_s1 = s1; _s2 = s2; _s3 = s3;                                   \
	kprintf("Skywalk: " #t " ... ");                                \
} while (0)

#define SK_ZERO_VERIFY(t)       SK_COPY_VERIFY(t)

static void
skywalk_self_tests(void)
{
	void *s1, *s2, *s3;
	void *_s1, *_s2, *_s3;

	VERIFY(sk_dump_buf != NULL);

	/*
	 * Utilize sk_dump_buf, by splitting it into 3 sections.  Each
	 * section begins on a 128-bit boundary, and is a multiple of
	 * 64-bytes len.  A section is 128-bytes long, which means we
	 * need at least 16+(3*128) bytes.
	 *
	 * 1st section is source buffer full of random data;
	 * 2nd section is reference target based on bcopy;
	 * 3rd section is test target base on our stuff.
	 */
	_CASSERT(SK_COPY_LEN != 0 && (SK_COPY_LEN % 128) == 0);
	_CASSERT((SK_COPY_LEN % 16) == 0);
	_CASSERT((SK_DUMP_BUF_ALIGN % 16) == 0);
	_CASSERT(SK_DUMP_BUF_SIZE >= (SK_DUMP_BUF_ALIGN + (SK_COPY_LEN * 3)));

	s1 = sk_dump_buf;
	if (!IS_P2ALIGNED(s1, SK_DUMP_BUF_ALIGN)) {
		s1 = (void *)P2ROUNDUP(s1, SK_DUMP_BUF_ALIGN);
	}
	ASSERT(IS_P2ALIGNED(s1, SK_DUMP_BUF_ALIGN));
	s2 = (void *)((uintptr_t)s1 + SK_COPY_LEN);
	ASSERT(IS_P2ALIGNED(s2, SK_DUMP_BUF_ALIGN));
	s3 = (void *)((uintptr_t)s2 + SK_COPY_LEN);
	ASSERT(IS_P2ALIGNED(s3, SK_DUMP_BUF_ALIGN));

	/* fill s1 with random data */
	read_frandom(s1, SK_COPY_LEN);

	kprintf("Skywalk: running self-tests\n");

	/* Copy 8-bytes, 64-bit aligned */
	SK_COPY_PREPARE(sk_copy64_8);
	bcopy(s1, s2, 8);
	sk_copy64_8((uint64_t *)s1, (uint64_t *)s3);
	SK_COPY_VERIFY(sk_copy64_8);

	/* Copy 8-bytes, 32-bit aligned */
	SK_COPY_PREPARE(sk_copy32_8);
	bcopy((void *)((uintptr_t)s1 + sizeof(uint32_t)),
	    (void *)((uintptr_t)s2 + sizeof(uint32_t)), 8);
	sk_copy32_8((uint32_t *)((uintptr_t)s1 + sizeof(uint32_t)),
	    (uint32_t *)((uintptr_t)s3 + sizeof(uint32_t)));
	SK_COPY_VERIFY(sk_copy32_8);

	/* Copy 16-bytes, 64-bit aligned */
	SK_COPY_PREPARE(sk_copy64_16);
	bcopy(s1, s2, 16);
	sk_copy64_16((uint64_t *)s1, (uint64_t *)s3);
	SK_COPY_VERIFY(sk_copy64_16);

	/* Copy 16-bytes, 32-bit aligned */
	SK_COPY_PREPARE(sk_copy32_16);
	bcopy((void *)((uintptr_t)s1 + sizeof(uint32_t)),
	    (void *)((uintptr_t)s2 + sizeof(uint32_t)), 16);
	sk_copy32_16((uint32_t *)((uintptr_t)s1 + sizeof(uint32_t)),
	    (uint32_t *)((uintptr_t)s3 + sizeof(uint32_t)));
	SK_COPY_VERIFY(sk_copy32_16);

	/* Copy 20-bytes, 64-bit aligned */
	SK_COPY_PREPARE(sk_copy64_20);
	bcopy(s1, s2, 20);
	sk_copy64_20((uint64_t *)s1, (uint64_t *)s3);
	SK_COPY_VERIFY(sk_copy64_20);

	/* Copy 24-bytes, 64-bit aligned */
	SK_COPY_PREPARE(sk_copy64_24);
	bcopy(s1, s2, 24);
	sk_copy64_24((uint64_t *)s1, (uint64_t *)s3);
	SK_COPY_VERIFY(sk_copy64_24);

	/* Copy 32-bytes, 64-bit aligned */
	SK_COPY_PREPARE(sk_copy64_32);
	bcopy(s1, s2, 32);
	sk_copy64_32((uint64_t *)s1, (uint64_t *)s3);
	SK_COPY_VERIFY(sk_copy64_32);

	/* Copy 32-bytes, 32-bit aligned */
	SK_COPY_PREPARE(sk_copy32_32);
	bcopy((void *)((uintptr_t)s1 + sizeof(uint32_t)),
	    (void *)((uintptr_t)s2 + sizeof(uint32_t)), 32);
	sk_copy32_32((uint32_t *)((uintptr_t)s1 + sizeof(uint32_t)),
	    (uint32_t *)((uintptr_t)s3 + sizeof(uint32_t)));
	SK_COPY_VERIFY(sk_copy32_32);

	/* Copy 40-bytes, 64-bit aligned */
	SK_COPY_PREPARE(sk_copy64_40);
	bcopy(s1, s2, 40);
	sk_copy64_40((uint64_t *)s1, (uint64_t *)s3);
	SK_COPY_VERIFY(sk_copy64_40);

	/* Copy entire section in 64-bytes chunks, 64-bit aligned */
	SK_COPY_PREPARE(sk_copy64_64x);
	bcopy(s1, s2, SK_COPY_LEN);
	sk_copy64_64x((uint64_t *)s1, (uint64_t *)s3, SK_COPY_LEN);
	SK_COPY_VERIFY(sk_copy64_64x);

	/* Copy entire section in 32-bytes chunks, 64-bit aligned */
	SK_COPY_PREPARE(sk_copy64_32x);
	bcopy(s1, s2, SK_COPY_LEN);
	sk_copy64_32x((uint64_t *)s1, (uint64_t *)s3, SK_COPY_LEN);
	SK_COPY_VERIFY(sk_copy64_32x);

	/* Copy entire section in 8-bytes chunks, 64-bit aligned */
	SK_COPY_PREPARE(sk_copy64_8x);
	bcopy(s1, s2, SK_COPY_LEN);
	sk_copy64_8x((uint64_t *)s1, (uint64_t *)s3, SK_COPY_LEN);
	SK_COPY_VERIFY(sk_copy64_8x);

	/* Copy entire section in 4-bytes chunks, 64-bit aligned */
	SK_COPY_PREPARE(sk_copy64_4x);
	bcopy(s1, s2, SK_COPY_LEN);
	sk_copy64_4x((uint32_t *)s1, (uint32_t *)s3, SK_COPY_LEN);
	SK_COPY_VERIFY(sk_copy64_4x);

	/*
	 * Re-use sk_dump_buf for testing sk_zero, same principle as above.
	 *
	 * 1st section is source buffer full of random data;
	 * 2nd section is reference target based on bzero;
	 * 3rd section is test target base on our stuff.
	 */
	SK_ZERO_PREPARE(sk_zero_16);
	bzero(s2, 16);
	sk_zero_16(s3);
	SK_ZERO_VERIFY(sk_zero_16);

	SK_ZERO_PREPARE(sk_zero_32);
	bzero(s2, 32);
	sk_zero_32(s3);
	SK_ZERO_VERIFY(sk_zero_32);

	SK_ZERO_PREPARE(sk_zero_48);
	bzero(s2, 48);
	sk_zero_48(s3);
	SK_ZERO_VERIFY(sk_zero_48);

	SK_ZERO_PREPARE(sk_zero_128);
	bzero(s2, 128);
	sk_zero_128(s3);
	SK_ZERO_VERIFY(sk_zero_128);

	/* Perform memcmp with mask self tests */
	skywalk_memcmp_mask_self_tests();

	/* reset sk_dump_buf */
	bzero(sk_dump_buf, SK_DUMP_BUF_SIZE);

	/* Keep packet trace code in sync with ariadne plist */
	_CASSERT(SK_KTRACE_AON_IF_STATS == 0x8100004);

	_CASSERT(SK_KTRACE_FSW_DEV_RING_FLUSH == 0x8110004);
	_CASSERT(SK_KTRACE_FSW_USER_RING_FLUSH == 0x8110008);
	_CASSERT(SK_KTRACE_FSW_FLOW_TRACK_RTT == 0x8110010);

	_CASSERT(SK_KTRACE_NETIF_RING_TX_REFILL == 0x8120004);
	_CASSERT(SK_KTRACE_NETIF_HOST_ENQUEUE == 0x8120008);
	_CASSERT(SK_KTRACE_NETIF_MIT_RX_INTR == 0x812000c);
	_CASSERT(SK_KTRACE_NETIF_COMMON_INTR == 0x8120010);
	_CASSERT(SK_KTRACE_NETIF_RX_NOTIFY_DEFAULT == 0x8120014);
	_CASSERT(SK_KTRACE_NETIF_RX_NOTIFY_FAST == 0x8120018);

	_CASSERT(SK_KTRACE_CHANNEL_TX_REFILL == 0x8130004);

	_CASSERT(SK_KTRACE_PKT_RX_DRV == 0x8140004);
	_CASSERT(SK_KTRACE_PKT_RX_FSW == 0x8140008);
	_CASSERT(SK_KTRACE_PKT_RX_CHN == 0x814000c);
	_CASSERT(SK_KTRACE_PKT_TX_FSW == 0x8140040);
	_CASSERT(SK_KTRACE_PKT_TX_AQM == 0x8140044);
	_CASSERT(SK_KTRACE_PKT_TX_DRV == 0x8140048);
}
#endif /* DEVELOPMENT || DEBUG */
