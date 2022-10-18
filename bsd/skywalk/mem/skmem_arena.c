/*
 * Copyright (c) 2016-2021 Apple Inc. All rights reserved.
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

/* BEGIN CSTYLED */
/*
 * SKMEM_ARENA_TYPE_NEXUS:
 *
 *   This arena represents the memory subsystem of a nexus adapter.  It consist
 *   of a collection of memory regions that are usable by the nexus, as well
 *   as the various caches for objects in those regions.
 *
 *       (1 per nexus adapter)
 *     +=======================+
 *     |      skmem_arena      |
 *     +-----------------------+              (backing regions)
 *     |     ar_regions[0]     |           +=======================+
 *     :          ...          : ------->> |     skmem_region      |===+
 *     |     ar_regions[n]     |           +=======================+   |===+
 *     +=======================+               +=======================+   |
 *     |     arn_{caches,pp}   | ---+              +=======================+
 *     +-----------------------+    |
 *     |     arn_stats_obj     |    |
 *     |     arn_flowadv_obj   |    |         (cache frontends)
 *     |     arn_nexusadv_obj  |    |      +=======================+
 *     +-----------------------+    +--->> |     skmem_cache       |===+
 *                                         +=======================+   |===+
 *                                             +=======================+   |
 *                                                 +=======================+
 *
 *   Three regions {umd,kmd,buf} are used for the packet buffer pool, which
 *   may be external to the nexus adapter, e.g. created by the driver or an
 *   external entity.  If not supplied, we create these regions along with
 *   the packet buffer pool ourselves.  The rest of the regions (unrelated
 *   to the packet buffer pool) are unique to the arena and are allocated at
 *   arena creation time.
 *
 *   An arena may be mapped to a user task/process for as many times as needed.
 *   The result of each mapping is a contiguous range within the address space
 *   of that task, indicated by [ami_mapaddr, ami_mapaddr + ami_mapsize) span.
 *   This is achieved by leveraging the mapper memory object ar_mapper that
 *   "stitches" the disjoint segments together.  Only user-mappable regions,
 *   i.e. those marked with SKR_MODE_MMAPOK, will be included in this span.
 *
 *   Nexus adapters that are eligible for defunct will trigger the arena to
 *   undergo memory redirection for all regions except those that are marked
 *   with SKR_MODE_NOREDIRECT.  This happens when all of the channels opened
 *   to the adapter are defunct.  Upon completion, those redirected regions
 *   will be torn down in order to reduce their memory footprints.  When this
 *   happens the adapter and its arena are no longer active or in service.
 *
 *   The arena exposes caches for allocating and freeing most region objects.
 *   These slab-allocator based caches act as front-ends to the regions; only
 *   the metadata cache (for kern_packet_t) utilizes the magazines layer.  All
 *   other ones simply utilize skmem_cache for slab-based allocations.
 *
 *   Certain regions contain singleton objects that are simple enough to not
 *   require the slab allocator, such as the ones used for statistics and flow
 *   advisories.  Because of this, we directly allocate from those regions
 *   and store the objects in the arena.
 *
 * SKMEM_ARENA_TYPE_NECP:
 *
 *   This arena represents the memory subsystem of an NECP file descriptor
 *   object.  It consists of a memory region for per-flow statistics, as well
 *   as a cache front-end for that region.
 *
 * SKMEM_ARENA_SYSTEM:
 *
 *   This arena represents general, system-wide objects.  It currently
 *   consists of the sysctls region that's created once at init time.
 */
/* END CSTYLED */

#include <skywalk/os_skywalk_private.h>
#include <net/necp.h>

static void skmem_arena_destroy(struct skmem_arena *);
static void skmem_arena_teardown(struct skmem_arena *, boolean_t);
static int skmem_arena_create_finalize(struct skmem_arena *);
static void skmem_arena_nexus_teardown(struct skmem_arena_nexus *, boolean_t);
static void skmem_arena_necp_teardown(struct skmem_arena_necp *, boolean_t);
static void skmem_arena_system_teardown(struct skmem_arena_system *, boolean_t);
static struct skmem_arena *skmem_arena_alloc(skmem_arena_type_t,
    const char *);
static void skmem_arena_free(struct skmem_arena *);
static void skmem_arena_retain_locked(struct skmem_arena *);
static void skmem_arena_reap_locked(struct skmem_arena *, boolean_t);
static boolean_t skmem_arena_munmap_common(struct skmem_arena *,
    struct skmem_arena_mmap_info *);
#if SK_LOG
static void skmem_arena_create_region_log(struct skmem_arena *);
#endif /* SK_LOG */
static int skmem_arena_mib_get_sysctl SYSCTL_HANDLER_ARGS;

SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, arena,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, skmem_arena_mib_get_sysctl, "S,sk_stats_arena",
    "Skywalk arena statistics");

static LCK_GRP_DECLARE(skmem_arena_lock_grp, "skmem_arena");
static LCK_MTX_DECLARE(skmem_arena_lock, &skmem_arena_lock_grp);

static TAILQ_HEAD(, skmem_arena) skmem_arena_head = TAILQ_HEAD_INITIALIZER(skmem_arena_head);

#define SKMEM_ARENA_LOCK()                      \
	lck_mtx_lock(&skmem_arena_lock)
#define SKMEM_ARENA_LOCK_ASSERT_HELD()          \
	LCK_MTX_ASSERT(&skmem_arena_lock, LCK_MTX_ASSERT_OWNED)
#define SKMEM_ARENA_LOCK_ASSERT_NOTHELD()       \
	LCK_MTX_ASSERT(&skmem_arena_lock, LCK_MTX_ASSERT_NOTOWNED)
#define SKMEM_ARENA_UNLOCK()                    \
	lck_mtx_unlock(&skmem_arena_lock)

#define AR_NEXUS_SIZE           sizeof(struct skmem_arena_nexus)
static ZONE_DEFINE(ar_nexus_zone, SKMEM_ZONE_PREFIX ".mem.arena.nexus",
    AR_NEXUS_SIZE, ZC_ZFREE_CLEARMEM);

#define AR_NECP_SIZE            sizeof(struct skmem_arena_necp)
static ZONE_DEFINE(ar_necp_zone, SKMEM_ZONE_PREFIX ".mem.arena.necp",
    AR_NECP_SIZE, ZC_ZFREE_CLEARMEM);

#define AR_SYSTEM_SIZE          sizeof(struct skmem_arena_system)
static ZONE_DEFINE(ar_system_zone, SKMEM_ZONE_PREFIX ".mem.arena.system",
    AR_SYSTEM_SIZE, ZC_ZFREE_CLEARMEM);

#define SKMEM_TAG_ARENA_MIB     "com.apple.skywalk.arena.mib"
static SKMEM_TAG_DEFINE(skmem_tag_arena_mib, SKMEM_TAG_ARENA_MIB);

static_assert(SKMEM_ARENA_TYPE_NEXUS == SAR_TYPE_NEXUS);
static_assert(SKMEM_ARENA_TYPE_NECP == SAR_TYPE_NECP);
static_assert(SKMEM_ARENA_TYPE_SYSTEM == SAR_TYPE_SYSTEM);

SK_NO_INLINE_ATTRIBUTE
static int
skmem_arena_sd_setup(const struct nexus_adapter *na,
    struct skmem_region_params srp[SKMEM_REGIONS], struct skmem_arena *ar,
    boolean_t kernel_only, boolean_t tx)
{
	struct skmem_arena_nexus *arn = (struct skmem_arena_nexus *)ar;
	struct skmem_cache **cachep;
	struct skmem_region *ksd_skr = NULL, *usd_skr = NULL;
	const char *name = na->na_name;
	char cname[64];
	skmem_region_id_t usd_type, ksd_type;
	int err = 0;

	usd_type = tx ? SKMEM_REGION_TXAUSD : SKMEM_REGION_RXFUSD;
	ksd_type = tx ? SKMEM_REGION_TXAKSD : SKMEM_REGION_RXFKSD;
	if (tx) {
		usd_type = SKMEM_REGION_TXAUSD;
		ksd_type = SKMEM_REGION_TXAKSD;
		cachep = &arn->arn_txaksd_cache;
	} else {
		usd_type = SKMEM_REGION_RXFUSD;
		ksd_type = SKMEM_REGION_RXFKSD;
		cachep = &arn->arn_rxfksd_cache;
	}
	ksd_skr = skmem_region_create(name, &srp[ksd_type], NULL, NULL, NULL);
	if (ksd_skr == NULL) {
		SK_ERR("\"%s\" ar 0x%llx flags %b failed to "
		    "create %s region", ar->ar_name, SK_KVA(ar),
		    ar->ar_flags, ARF_BITS, srp[ksd_type].srp_name);
		err = ENOMEM;
		goto failed;
	}
	ar->ar_regions[ksd_type] = ksd_skr;
	if (!kernel_only) {
		usd_skr = skmem_region_create(name, &srp[usd_type], NULL,
		    NULL, NULL);
		if (usd_skr == NULL) {
			err = ENOMEM;
			goto failed;
		}
		ar->ar_regions[usd_type] = usd_skr;
		skmem_region_mirror(ksd_skr, usd_skr);
	}
	snprintf(cname, sizeof(cname), tx ? "txa_ksd.%s" : "rxf_ksd.%s", name);
	ASSERT(ar->ar_regions[ksd_type] != NULL);
	*cachep = skmem_cache_create(cname,
	    srp[ksd_type].srp_c_obj_size, 0, NULL, NULL, NULL, NULL,
	    ar->ar_regions[ksd_type], SKMEM_CR_NOMAGAZINES);
	if (*cachep == NULL) {
		SK_ERR("\"%s\" ar 0x%llx flags %b failed to create %s",
		    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS, cname);
		err = ENOMEM;
		goto failed;
	}
	return 0;

failed:
	if (ksd_skr != NULL) {
		skmem_region_release(ksd_skr);
		ar->ar_regions[ksd_type] = NULL;
	}
	if (usd_skr != NULL) {
		/*
		 * decrements refcnt incremented by skmem_region_mirror()
		 * this is not needed in case skmem_cache_create() succeeds
		 * because skmem_cache_destroy() does the release.
		 */
		skmem_region_release(usd_skr);

		/* decrements the region's own refcnt */
		skmem_region_release(usd_skr);
		ar->ar_regions[usd_type] = NULL;
	}
	return err;
}

SK_NO_INLINE_ATTRIBUTE
static void
skmem_arena_sd_teardown(struct skmem_arena *ar, boolean_t tx)
{
	struct skmem_arena_nexus *arn = (struct skmem_arena_nexus *)ar;
	struct skmem_cache **cachep;
	struct skmem_region **ksd_rp, **usd_rp;

	if (tx) {
		cachep = &arn->arn_txaksd_cache;
		ksd_rp = &ar->ar_regions[SKMEM_REGION_TXAKSD];
		usd_rp = &ar->ar_regions[SKMEM_REGION_TXAUSD];
	} else {
		cachep = &arn->arn_rxfksd_cache;
		ksd_rp = &ar->ar_regions[SKMEM_REGION_RXFKSD];
		usd_rp = &ar->ar_regions[SKMEM_REGION_RXFUSD];
	}
	if (*cachep != NULL) {
		skmem_cache_destroy(*cachep);
		*cachep = NULL;
	}
	if (*usd_rp != NULL) {
		skmem_region_release(*usd_rp);
		*usd_rp = NULL;
	}
	if (*ksd_rp != NULL) {
		skmem_region_release(*ksd_rp);
		*ksd_rp = NULL;
	}
}

static bool
skmem_arena_pp_setup(struct skmem_arena *ar,
    struct skmem_region_params srp[SKMEM_REGIONS], const char *name,
    struct kern_pbufpool *rx_pp, struct kern_pbufpool *tx_pp,
    uint32_t flags)
{
	struct skmem_arena_nexus *arn = (struct skmem_arena_nexus *)ar;
	boolean_t kernel_only = (flags & SKMEM_PP_FLAG_KERNEL_ONLY) != 0;
	if (rx_pp == NULL && tx_pp == NULL) {
		uint32_t ppcreatef = 0;
		if (flags & SKMEM_PP_FLAG_TRUNCATED_BUF) {
			ppcreatef |= PPCREATEF_TRUNCATED_BUF;
		}
		if (flags & SKMEM_PP_FLAG_KERNEL_ONLY) {
			ppcreatef |= PPCREATEF_KERNEL_ONLY;
		}
		if (srp[SKMEM_REGION_KMD].srp_max_frags > 1) {
			ppcreatef |= PPCREATEF_ONDEMAND_BUF;
		}
		if (flags & SKMEM_PP_FLAG_RAW_BFLT) {
			ppcreatef |= PPCREATEF_RAW_BFLT;
		}
		/* callee retains pp upon success */
		rx_pp = pp_create(name, srp, NULL, NULL, NULL, NULL, NULL,
		    ppcreatef);
		if (rx_pp == NULL) {
			SK_ERR("\"%s\" ar 0x%llx flags %b failed to create pp",
			    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS);
			return false;
		}
		pp_retain(rx_pp);
		tx_pp = rx_pp;
	} else {
		if (rx_pp == NULL) {
			rx_pp = tx_pp;
		} else if (tx_pp == NULL) {
			tx_pp = rx_pp;
		}

		ASSERT(rx_pp->pp_md_type == tx_pp->pp_md_type);
		ASSERT(rx_pp->pp_md_subtype == tx_pp->pp_md_subtype);
		ASSERT(!(!kernel_only &&
		    (PP_KERNEL_ONLY(rx_pp) || (PP_KERNEL_ONLY(tx_pp)))));
		arn->arn_mode |= AR_NEXUS_MODE_EXTERNAL_PPOOL;
		pp_retain(rx_pp);
		pp_retain(tx_pp);
	}

	arn->arn_rx_pp = rx_pp;
	arn->arn_tx_pp = tx_pp;
	if (rx_pp == tx_pp) {
		skmem_region_retain(PP_BUF_REGION_DEF(rx_pp));
		if (PP_BUF_REGION_LARGE(rx_pp) != NULL) {
			skmem_region_retain(PP_BUF_REGION_LARGE(rx_pp));
		}
		ar->ar_regions[SKMEM_REGION_BUF_DEF] = PP_BUF_REGION_DEF(rx_pp);
		ar->ar_regions[SKMEM_REGION_BUF_LARGE] =
		    PP_BUF_REGION_LARGE(rx_pp);
		ar->ar_regions[SKMEM_REGION_RXBUF_DEF] = NULL;
		ar->ar_regions[SKMEM_REGION_RXBUF_LARGE] = NULL;
		ar->ar_regions[SKMEM_REGION_TXBUF_DEF] = NULL;
		ar->ar_regions[SKMEM_REGION_TXBUF_LARGE] = NULL;
		skmem_region_retain(rx_pp->pp_kmd_region);
		ar->ar_regions[SKMEM_REGION_KMD] = rx_pp->pp_kmd_region;
		ar->ar_regions[SKMEM_REGION_RXKMD] = NULL;
		ar->ar_regions[SKMEM_REGION_RXKMD] = NULL;
		if (rx_pp->pp_kbft_region != NULL) {
			skmem_region_retain(rx_pp->pp_kbft_region);
			ar->ar_regions[SKMEM_REGION_KBFT] =
			    rx_pp->pp_kbft_region;
		}
		ar->ar_regions[SKMEM_REGION_RXKBFT] = NULL;
		ar->ar_regions[SKMEM_REGION_TXKBFT] = NULL;
	} else {
		ASSERT(kernel_only); /* split userspace pools not supported */
		ar->ar_regions[SKMEM_REGION_BUF_DEF] = NULL;
		ar->ar_regions[SKMEM_REGION_BUF_LARGE] = NULL;
		skmem_region_retain(PP_BUF_REGION_DEF(rx_pp));
		ar->ar_regions[SKMEM_REGION_RXBUF_DEF] =
		    PP_BUF_REGION_DEF(rx_pp);
		ar->ar_regions[SKMEM_REGION_RXBUF_LARGE] =
		    PP_BUF_REGION_LARGE(rx_pp);
		if (PP_BUF_REGION_LARGE(rx_pp) != NULL) {
			skmem_region_retain(PP_BUF_REGION_LARGE(rx_pp));
		}
		skmem_region_retain(PP_BUF_REGION_DEF(tx_pp));
		ar->ar_regions[SKMEM_REGION_TXBUF_DEF] =
		    PP_BUF_REGION_DEF(tx_pp);
		ar->ar_regions[SKMEM_REGION_TXBUF_LARGE] =
		    PP_BUF_REGION_LARGE(tx_pp);
		if (PP_BUF_REGION_LARGE(tx_pp) != NULL) {
			skmem_region_retain(PP_BUF_REGION_LARGE(tx_pp));
		}
		ar->ar_regions[SKMEM_REGION_KMD] = NULL;
		skmem_region_retain(rx_pp->pp_kmd_region);
		ar->ar_regions[SKMEM_REGION_RXKMD] = rx_pp->pp_kmd_region;
		skmem_region_retain(tx_pp->pp_kmd_region);
		ar->ar_regions[SKMEM_REGION_TXKMD] = tx_pp->pp_kmd_region;
		ar->ar_regions[SKMEM_REGION_KBFT] = NULL;
		if (rx_pp->pp_kbft_region != NULL) {
			ASSERT(PP_HAS_BUFFER_ON_DEMAND(rx_pp));
			skmem_region_retain(rx_pp->pp_kbft_region);
			ar->ar_regions[SKMEM_REGION_RXKBFT] =
			    rx_pp->pp_kbft_region;
		}
		if (tx_pp->pp_kbft_region != NULL) {
			ASSERT(PP_HAS_BUFFER_ON_DEMAND(tx_pp));
			skmem_region_retain(tx_pp->pp_kbft_region);
			ar->ar_regions[SKMEM_REGION_TXKBFT] =
			    tx_pp->pp_kbft_region;
		}
	}

	if (kernel_only) {
		if ((arn->arn_mode & AR_NEXUS_MODE_EXTERNAL_PPOOL) == 0) {
			ASSERT(PP_KERNEL_ONLY(rx_pp));
			ASSERT(PP_KERNEL_ONLY(tx_pp));
			ASSERT(rx_pp->pp_umd_region == NULL);
			ASSERT(tx_pp->pp_umd_region == NULL);
			ASSERT(rx_pp->pp_kmd_region->skr_mirror == NULL);
			ASSERT(tx_pp->pp_kmd_region->skr_mirror == NULL);
			ASSERT(rx_pp->pp_ubft_region == NULL);
			ASSERT(tx_pp->pp_ubft_region == NULL);
			if (rx_pp->pp_kbft_region != NULL) {
				ASSERT(rx_pp->pp_kbft_region->skr_mirror ==
				    NULL);
			}
			if (tx_pp->pp_kbft_region != NULL) {
				ASSERT(tx_pp->pp_kbft_region->skr_mirror ==
				    NULL);
			}
		}
	} else {
		ASSERT(rx_pp == tx_pp);
		ASSERT(!PP_KERNEL_ONLY(rx_pp));
		ASSERT(rx_pp->pp_umd_region->skr_mode & SKR_MODE_MIRRORED);
		ASSERT(rx_pp->pp_kmd_region->skr_mirror != NULL);
		ar->ar_regions[SKMEM_REGION_UMD] = rx_pp->pp_umd_region;
		skmem_region_retain(rx_pp->pp_umd_region);
		if (rx_pp->pp_kbft_region != NULL) {
			ASSERT(rx_pp->pp_kbft_region->skr_mirror != NULL);
			ASSERT(rx_pp->pp_ubft_region != NULL);
			ASSERT(rx_pp->pp_ubft_region->skr_mode &
			    SKR_MODE_MIRRORED);
			ar->ar_regions[SKMEM_REGION_UBFT] =
			    rx_pp->pp_ubft_region;
			skmem_region_retain(rx_pp->pp_ubft_region);
		}
	}

	arn->arn_md_type = rx_pp->pp_md_type;
	arn->arn_md_subtype = rx_pp->pp_md_subtype;
	return true;
}

/*
 * Create a nexus adapter arena.
 */
struct skmem_arena *
skmem_arena_create_for_nexus(const struct nexus_adapter *na,
    struct skmem_region_params srp[SKMEM_REGIONS], struct kern_pbufpool **tx_pp,
    struct kern_pbufpool **rx_pp, uint32_t pp_flags,
    struct kern_nexus_advisory *nxv, int *perr)
{
#define SRP_CFLAGS(_id)         (srp[_id].srp_cflags)
	struct skmem_arena_nexus *arn;
	struct skmem_arena *ar;
	char cname[64];
	uint32_t i;
	const char *name = na->na_name;
	boolean_t kernel_only = (pp_flags & SKMEM_PP_FLAG_KERNEL_ONLY) != 0;

	*perr = 0;

	ar = skmem_arena_alloc(SKMEM_ARENA_TYPE_NEXUS, name);
	ASSERT(ar != NULL && ar->ar_zsize == AR_NEXUS_SIZE);
	arn = (struct skmem_arena_nexus *)ar;

	/* these regions must not be readable/writeable */
	ASSERT(SRP_CFLAGS(SKMEM_REGION_GUARD_HEAD) & SKMEM_REGION_CR_GUARD);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_GUARD_TAIL) & SKMEM_REGION_CR_GUARD);

	/* these regions must be read-only */
	ASSERT(SRP_CFLAGS(SKMEM_REGION_SCHEMA) & SKMEM_REGION_CR_UREADONLY);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_FLOWADV) & SKMEM_REGION_CR_UREADONLY);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_NEXUSADV) & SKMEM_REGION_CR_UREADONLY);
	if ((na->na_flags & NAF_USER_PKT_POOL) == 0) {
		ASSERT(SRP_CFLAGS(SKMEM_REGION_TXAUSD) &
		    SKMEM_REGION_CR_UREADONLY);
		ASSERT(SRP_CFLAGS(SKMEM_REGION_RXFUSD) &
		    SKMEM_REGION_CR_UREADONLY);
	} else {
		ASSERT(!(SRP_CFLAGS(SKMEM_REGION_TXAUSD) &
		    SKMEM_REGION_CR_UREADONLY));
		ASSERT(!(SRP_CFLAGS(SKMEM_REGION_RXFUSD) &
		    SKMEM_REGION_CR_UREADONLY));
	}

	/* these regions must be user-mappable */
	ASSERT(SRP_CFLAGS(SKMEM_REGION_GUARD_HEAD) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_SCHEMA) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_RING) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_BUF_DEF) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_BUF_LARGE) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_UMD) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_UBFT) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_TXAUSD) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_RXFUSD) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_USTATS) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_FLOWADV) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_NEXUSADV) & SKMEM_REGION_CR_MMAPOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_GUARD_TAIL) & SKMEM_REGION_CR_MMAPOK);

	/* these must not be user-mappable */
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_KMD) & SKMEM_REGION_CR_MMAPOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_RXKMD) & SKMEM_REGION_CR_MMAPOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_TXKMD) & SKMEM_REGION_CR_MMAPOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_KBFT) & SKMEM_REGION_CR_MMAPOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_RXKBFT) & SKMEM_REGION_CR_MMAPOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_TXKBFT) & SKMEM_REGION_CR_MMAPOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_TXAKSD) & SKMEM_REGION_CR_MMAPOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_RXFKSD) & SKMEM_REGION_CR_MMAPOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_KSTATS) & SKMEM_REGION_CR_MMAPOK));

	/* these regions must be shareable */
	ASSERT(SRP_CFLAGS(SKMEM_REGION_BUF_DEF) & SKMEM_REGION_CR_SHAREOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_BUF_LARGE) & SKMEM_REGION_CR_SHAREOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_RXBUF_DEF) & SKMEM_REGION_CR_SHAREOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_RXBUF_LARGE) & SKMEM_REGION_CR_SHAREOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_TXBUF_DEF) & SKMEM_REGION_CR_SHAREOK);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_TXBUF_LARGE) & SKMEM_REGION_CR_SHAREOK);

	/* these regions must not be be shareable */
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_GUARD_HEAD) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_SCHEMA) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_RING) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_UMD) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_UBFT) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_TXAUSD) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_RXFUSD) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_USTATS) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_FLOWADV) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_NEXUSADV) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_GUARD_TAIL) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_KMD) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_RXKMD) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_TXKMD) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_KBFT) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_RXKBFT) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_TXKBFT) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_TXAKSD) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_RXFKSD) & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(SRP_CFLAGS(SKMEM_REGION_KSTATS) & SKMEM_REGION_CR_SHAREOK));

	/* these must stay active */
	ASSERT(SRP_CFLAGS(SKMEM_REGION_GUARD_HEAD) & SKMEM_REGION_CR_NOREDIRECT);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_SCHEMA) & SKMEM_REGION_CR_NOREDIRECT);
	ASSERT(SRP_CFLAGS(SKMEM_REGION_GUARD_TAIL) & SKMEM_REGION_CR_NOREDIRECT);

	/* no kstats for nexus */
	ASSERT(srp[SKMEM_REGION_KSTATS].srp_c_obj_cnt == 0);

	AR_LOCK(ar);
	if (!skmem_arena_pp_setup(ar, srp, name, (rx_pp ? *rx_pp : NULL),
	    (tx_pp ? *tx_pp : NULL), pp_flags)) {
		goto failed;
	}

	if (nxv != NULL && nxv->nxv_reg != NULL) {
		struct skmem_region *svr = nxv->nxv_reg;

		ASSERT(svr->skr_cflags & SKMEM_REGION_CR_MONOLITHIC);
		ASSERT(svr->skr_seg_max_cnt == 1);
		ar->ar_regions[SKMEM_REGION_NEXUSADV] = svr;
		skmem_region_retain(svr);

		ASSERT(nxv->nxv_adv != NULL);
		if (nxv->nxv_adv_type == NEXUS_ADVISORY_TYPE_FLOWSWITCH) {
			VERIFY(nxv->flowswitch_nxv_adv->nxadv_ver ==
			    NX_FLOWSWITCH_ADVISORY_CURRENT_VERSION);
		} else if (nxv->nxv_adv_type == NEXUS_ADVISORY_TYPE_NETIF) {
			VERIFY(nxv->netif_nxv_adv->nna_version ==
			    NX_NETIF_ADVISORY_CURRENT_VERSION);
		} else {
			panic_plain("%s: invalid advisory type %d",
			    __func__, nxv->nxv_adv_type);
			/* NOTREACHED */
		}
		arn->arn_nexusadv_obj = nxv->nxv_adv;
	} else {
		ASSERT(ar->ar_regions[SKMEM_REGION_NEXUSADV] == NULL);
		ASSERT(srp[SKMEM_REGION_NEXUSADV].srp_c_obj_cnt == 0);
	}

	if (skmem_arena_sd_setup(na, srp, ar, kernel_only, TRUE) != 0) {
		goto failed;
	}

	if (skmem_arena_sd_setup(na, srp, ar, kernel_only, FALSE) != 0) {
		goto failed;
	}

	for (i = 0; i < SKMEM_REGIONS; i++) {
		/* skip if already created */
		if (ar->ar_regions[i] != NULL) {
			continue;
		}

		/* skip external regions from packet pool */
		if (skmem_region_for_pp(i)) {
			continue;
		}

		/* skip slot descriptor regions */
		if (i == SKMEM_REGION_TXAUSD || i == SKMEM_REGION_RXFUSD ||
		    i == SKMEM_REGION_TXAKSD || i == SKMEM_REGION_RXFKSD) {
			continue;
		}

		/* skip if region is configured to be empty */
		if (srp[i].srp_c_obj_cnt == 0) {
			ASSERT(i == SKMEM_REGION_GUARD_HEAD ||
			    i == SKMEM_REGION_USTATS ||
			    i == SKMEM_REGION_KSTATS ||
			    i == SKMEM_REGION_INTRINSIC ||
			    i == SKMEM_REGION_FLOWADV ||
			    i == SKMEM_REGION_NEXUSADV ||
			    i == SKMEM_REGION_SYSCTLS ||
			    i == SKMEM_REGION_GUARD_TAIL);
			continue;
		}

		ASSERT(srp[i].srp_id == i);

		/*
		 * Skip {SCHEMA, RING, GUARD} for kernel-only arena.  Note
		 * that this is assuming kernel-only arena is always used
		 * for kernel-only nexus adapters (never used directly by
		 * user process.)
		 *
		 * XXX adi@apple.com - see comments in kern_pbufpool_create().
		 * We need to revisit this logic for "direct channel" access,
		 * perhaps via a separate adapter flag.
		 */
		if (kernel_only && (i == SKMEM_REGION_GUARD_HEAD ||
		    i == SKMEM_REGION_SCHEMA || i == SKMEM_REGION_RING ||
		    i == SKMEM_REGION_GUARD_TAIL)) {
			continue;
		}

		/* not for nexus, or for us to create here */
		ASSERT(i != SKMEM_REGION_GUARD_HEAD || sk_guard);
		ASSERT(i != SKMEM_REGION_NEXUSADV);
		ASSERT(i != SKMEM_REGION_SYSCTLS);
		ASSERT(i != SKMEM_REGION_GUARD_TAIL || sk_guard);
		ASSERT(i != SKMEM_REGION_KSTATS);
		ASSERT(i != SKMEM_REGION_INTRINSIC);

		/* otherwise create it */
		if ((ar->ar_regions[i] = skmem_region_create(name, &srp[i],
		    NULL, NULL, NULL)) == NULL) {
			SK_ERR("\"%s\" ar 0x%llx flags %b failed to "
			    "create %s region", ar->ar_name, SK_KVA(ar),
			    ar->ar_flags, ARF_BITS, srp[i].srp_name);
			goto failed;
		}
	}

	/* create skmem_cache for schema (without magazines) */
	ASSERT(ar->ar_regions[SKMEM_REGION_SCHEMA] != NULL || kernel_only);
	if (ar->ar_regions[SKMEM_REGION_SCHEMA] != NULL) {
		(void) snprintf(cname, sizeof(cname), "schema.%s", name);
		if ((arn->arn_schema_cache = skmem_cache_create(cname,
		    srp[SKMEM_REGION_SCHEMA].srp_c_obj_size, 0, NULL, NULL,
		    NULL, NULL, ar->ar_regions[SKMEM_REGION_SCHEMA],
		    SKMEM_CR_NOMAGAZINES)) == NULL) {
			SK_ERR("\"%s\" ar 0x%llx flags %b failed to create %s",
			    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS,
			    cname);
			goto failed;
		}
	}

	/* create skmem_cache for rings (without magazines) */
	(void) snprintf(cname, sizeof(cname), "ring.%s", name);
	ASSERT(ar->ar_regions[SKMEM_REGION_RING] != NULL || kernel_only);
	if ((ar->ar_regions[SKMEM_REGION_RING] != NULL) &&
	    (arn->arn_ring_cache = skmem_cache_create(cname,
	    srp[SKMEM_REGION_RING].srp_c_obj_size, 0, NULL, NULL, NULL, NULL,
	    ar->ar_regions[SKMEM_REGION_RING], SKMEM_CR_NOMAGAZINES)) == NULL) {
		SK_ERR("\"%s\" ar 0x%llx flags %b failed to create %s",
		    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS, cname);
		goto failed;
	}

	/*
	 * If the stats region is present, allocate a single object directly
	 * from the region; we don't need to create an skmem_cache for this,
	 * as the object is allocated (and freed) only once.
	 */
	if (ar->ar_regions[SKMEM_REGION_USTATS] != NULL) {
		struct skmem_region *str = ar->ar_regions[SKMEM_REGION_USTATS];

		/* no kstats for nexus */
		ASSERT(ar->ar_regions[SKMEM_REGION_KSTATS] == NULL);
		ASSERT(str->skr_cflags & SKMEM_REGION_CR_MONOLITHIC);
		ASSERT(str->skr_seg_max_cnt == 1);

		if ((arn->arn_stats_obj = skmem_region_alloc(str, NULL,
		    NULL, NULL, SKMEM_SLEEP)) == NULL) {
			SK_ERR("\"%s\" ar 0x%llx flags %b failed to alloc "
			    "stats", ar->ar_name, SK_KVA(ar), ar->ar_flags,
			    ARF_BITS);
			goto failed;
		}
	}
	ASSERT(ar->ar_regions[SKMEM_REGION_KSTATS] == NULL);

	/*
	 * If the flowadv region is present, allocate a single object directly
	 * from the region; we don't need to create an skmem_cache for this,
	 * as the object is allocated (and freed) only once.
	 */
	if (ar->ar_regions[SKMEM_REGION_FLOWADV] != NULL) {
		struct skmem_region *str =
		    ar->ar_regions[SKMEM_REGION_FLOWADV];

		ASSERT(str->skr_cflags & SKMEM_REGION_CR_MONOLITHIC);
		ASSERT(str->skr_seg_max_cnt == 1);

		if ((arn->arn_flowadv_obj = skmem_region_alloc(str, NULL,
		    NULL, NULL, SKMEM_SLEEP)) == NULL) {
			SK_ERR("\"%s\" ar 0x%llx flags %b failed to alloc "
			    "flowadv", ar->ar_name, SK_KVA(ar), ar->ar_flags,
			    ARF_BITS);
			goto failed;
		}
	}

	if (skmem_arena_create_finalize(ar) != 0) {
		SK_ERR("\"%s\" ar 0x%llx flags %b failed to finalize",
		    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS);
		goto failed;
	}

	++ar->ar_refcnt;        /* for caller */
	AR_UNLOCK(ar);

	SKMEM_ARENA_LOCK();
	TAILQ_INSERT_TAIL(&skmem_arena_head, ar, ar_link);
	SKMEM_ARENA_UNLOCK();

	/* caller didn't give us one, but would like us to return it? */
	if (rx_pp != NULL && *rx_pp == NULL) {
		*rx_pp = arn->arn_rx_pp;
		pp_retain(*rx_pp);
	}
	if (tx_pp != NULL && *tx_pp == NULL) {
		*tx_pp = arn->arn_tx_pp;
		pp_retain(*tx_pp);  /* for caller */
	}

#if SK_LOG
	if (__improbable(sk_verbose != 0)) {
		skmem_arena_create_region_log(ar);
	}
#endif /* SK_LOG */

	return ar;

failed:
	AR_LOCK_ASSERT_HELD(ar);
	skmem_arena_destroy(ar);
	*perr = ENOMEM;

	return NULL;
#undef SRP_CFLAGS
}

void
skmem_arena_nexus_sd_set_noidle(struct skmem_arena_nexus *arn, int cnt)
{
	struct skmem_arena *ar = &arn->arn_cmn;

	AR_LOCK(ar);
	arn->arn_ksd_nodefunct += cnt;
	VERIFY(arn->arn_ksd_nodefunct >= 0);
	AR_UNLOCK(ar);
}

boolean_t
skmem_arena_nexus_sd_idle(struct skmem_arena_nexus *arn)
{
	struct skmem_arena *ar = &arn->arn_cmn;
	boolean_t idle;

	AR_LOCK(ar);
	VERIFY(arn->arn_ksd_nodefunct >= 0);
	idle = (arn->arn_ksd_nodefunct == 0);
	AR_UNLOCK(ar);

	return idle;
}

static void
skmem_arena_nexus_teardown(struct skmem_arena_nexus *arn, boolean_t defunct)
{
	struct skmem_arena *ar = &arn->arn_cmn;
	struct skmem_region *skr;
	int i;

	AR_LOCK_ASSERT_HELD(ar);
	ASSERT(ar->ar_type == SKMEM_ARENA_TYPE_NEXUS);

	/* these should never be set for nexus arena */
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_HEAD] == NULL || sk_guard);
	ASSERT(ar->ar_regions[SKMEM_REGION_SYSCTLS] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_TAIL] == NULL || sk_guard);
	ASSERT(ar->ar_regions[SKMEM_REGION_KSTATS] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_INTRINSIC] == NULL);

	if (arn->arn_stats_obj != NULL) {
		skr = ar->ar_regions[SKMEM_REGION_USTATS];
		ASSERT(skr != NULL && !(skr->skr_mode & SKR_MODE_NOREDIRECT));
		skmem_region_free(skr, arn->arn_stats_obj, NULL);
		arn->arn_stats_obj = NULL;
		skmem_region_release(skr);
		ar->ar_regions[SKMEM_REGION_USTATS] = NULL;
	}
	ASSERT(ar->ar_regions[SKMEM_REGION_USTATS] == NULL);
	ASSERT(arn->arn_stats_obj == NULL);

	if (arn->arn_flowadv_obj != NULL) {
		skr = ar->ar_regions[SKMEM_REGION_FLOWADV];
		ASSERT(skr != NULL && !(skr->skr_mode & SKR_MODE_NOREDIRECT));
		skmem_region_free(skr, arn->arn_flowadv_obj, NULL);
		arn->arn_flowadv_obj = NULL;
		skmem_region_release(skr);
		ar->ar_regions[SKMEM_REGION_FLOWADV] = NULL;
	}
	ASSERT(ar->ar_regions[SKMEM_REGION_FLOWADV] == NULL);
	ASSERT(arn->arn_flowadv_obj == NULL);

	if (arn->arn_nexusadv_obj != NULL) {
		skr = ar->ar_regions[SKMEM_REGION_NEXUSADV];
		ASSERT(skr != NULL && !(skr->skr_mode & SKR_MODE_NOREDIRECT));
		/* we didn't allocate this, so just nullify it */
		arn->arn_nexusadv_obj = NULL;
		skmem_region_release(skr);
		ar->ar_regions[SKMEM_REGION_NEXUSADV] = NULL;
	}
	ASSERT(ar->ar_regions[SKMEM_REGION_NEXUSADV] == NULL);
	ASSERT(arn->arn_nexusadv_obj == NULL);

	ASSERT(!((arn->arn_rx_pp == NULL) ^ (arn->arn_tx_pp == NULL)));
	if (arn->arn_rx_pp != NULL) {
		for (i = 0; i < SKMEM_PP_REGIONS; i++) {
			skmem_region_id_t reg = skmem_pp_region_ids[i];
			skr = ar->ar_regions[reg];
			if (skr != NULL) {
				ASSERT(!(skr->skr_mode & SKR_MODE_NOREDIRECT));
				skmem_region_release(skr);
				ar->ar_regions[reg] = NULL;
			}
		}
		pp_release(arn->arn_rx_pp);
		pp_release(arn->arn_tx_pp);
		arn->arn_rx_pp = NULL;
		arn->arn_tx_pp = NULL;
	}
	for (i = 0; i < SKMEM_PP_REGIONS; i++) {
		ASSERT(ar->ar_regions[skmem_pp_region_ids[i]] == NULL);
	}
	ASSERT(arn->arn_rx_pp == NULL);
	ASSERT(arn->arn_tx_pp == NULL);

	if (arn->arn_ring_cache != NULL) {
		skr = ar->ar_regions[SKMEM_REGION_RING];
		ASSERT(skr != NULL && !(skr->skr_mode & SKR_MODE_NOREDIRECT));
		skmem_cache_destroy(arn->arn_ring_cache);
		arn->arn_ring_cache = NULL;
		skmem_region_release(skr);
		ar->ar_regions[SKMEM_REGION_RING] = NULL;
	}
	ASSERT(ar->ar_regions[SKMEM_REGION_RING] == NULL);
	ASSERT(arn->arn_ring_cache == NULL);

	/*
	 * Stop here if we're in the defunct context, and we're asked
	 * to keep the slot descriptor regions alive as they are still
	 * being referred to by the nexus owner (driver).
	 */
	if (defunct && arn->arn_ksd_nodefunct != 0) {
		ASSERT(arn->arn_ksd_nodefunct > 0);
		return;
	}

	ASSERT(arn->arn_ksd_nodefunct == 0);
	skmem_arena_sd_teardown(ar, TRUE);
	skmem_arena_sd_teardown(ar, FALSE);

	/* stop here if we're in the defunct context */
	if (defunct) {
		return;
	}
	if (arn->arn_schema_cache != NULL) {
		skr = ar->ar_regions[SKMEM_REGION_SCHEMA];
		ASSERT(skr != NULL && (skr->skr_mode & SKR_MODE_NOREDIRECT));
		skmem_cache_destroy(arn->arn_schema_cache);
		arn->arn_schema_cache = NULL;
		skmem_region_release(skr);
		ar->ar_regions[SKMEM_REGION_SCHEMA] = NULL;
	}
	ASSERT(ar->ar_regions[SKMEM_REGION_SCHEMA] == NULL);
	ASSERT(arn->arn_schema_cache == NULL);

	if ((skr = ar->ar_regions[SKMEM_REGION_GUARD_HEAD]) != NULL) {
		ASSERT(skr->skr_mode & SKR_MODE_NOREDIRECT);
		skmem_region_release(skr);
		ar->ar_regions[SKMEM_REGION_GUARD_HEAD] = NULL;
	}
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_HEAD] == NULL);
	if ((skr = ar->ar_regions[SKMEM_REGION_GUARD_TAIL]) != NULL) {
		ASSERT(skr->skr_mode & SKR_MODE_NOREDIRECT);
		skmem_region_release(skr);
		ar->ar_regions[SKMEM_REGION_GUARD_TAIL] = NULL;
	}
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_TAIL] == NULL);
}

/*
 * Create an NECP arena.
 */
struct skmem_arena *
skmem_arena_create_for_necp(const char *name,
    struct skmem_region_params *srp_ustats,
    struct skmem_region_params *srp_kstats, int *perr)
{
	struct skmem_arena_necp *arc;
	struct skmem_arena *ar;
	char cname[64];

	*perr = 0;

	ar = skmem_arena_alloc(SKMEM_ARENA_TYPE_NECP, name);
	ASSERT(ar != NULL && ar->ar_zsize == AR_NECP_SIZE);
	arc = (struct skmem_arena_necp *)ar;

	/*
	 * Must be stats region, and must be user-mappable;
	 * don't assert for SKMEM_REGION_CR_MONOLITHIC here
	 * as the client might want multi-segment mode.
	 */
	ASSERT(srp_ustats->srp_id == SKMEM_REGION_USTATS);
	ASSERT(srp_kstats->srp_id == SKMEM_REGION_KSTATS);
	ASSERT(srp_ustats->srp_cflags & SKMEM_REGION_CR_MMAPOK);
	ASSERT(!(srp_kstats->srp_cflags & SKMEM_REGION_CR_MMAPOK));
	ASSERT(!(srp_ustats->srp_cflags & SKMEM_REGION_CR_SHAREOK));
	ASSERT(!(srp_kstats->srp_cflags & SKMEM_REGION_CR_SHAREOK));
	ASSERT(srp_ustats->srp_c_obj_size != 0);
	ASSERT(srp_kstats->srp_c_obj_size != 0);
	ASSERT(srp_ustats->srp_c_obj_cnt != 0);
	ASSERT(srp_kstats->srp_c_obj_cnt != 0);
	ASSERT(srp_ustats->srp_c_seg_size == srp_kstats->srp_c_seg_size);
	ASSERT(srp_ustats->srp_seg_cnt == srp_kstats->srp_seg_cnt);
	ASSERT(srp_ustats->srp_c_obj_size == srp_kstats->srp_c_obj_size);
	ASSERT(srp_ustats->srp_c_obj_cnt == srp_kstats->srp_c_obj_cnt);

	AR_LOCK(ar);

	if ((ar->ar_regions[SKMEM_REGION_USTATS] = skmem_region_create(name,
	    srp_ustats, NULL, NULL, NULL)) == NULL) {
		SK_ERR("\"%s\" ar 0x%llx flags %b failed to create %s region",
		    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS,
		    srp_ustats->srp_name);
		goto failed;
	}

	if ((ar->ar_regions[SKMEM_REGION_KSTATS] = skmem_region_create(name,
	    srp_kstats, NULL, NULL, NULL)) == NULL) {
		SK_ERR("\"%s\" ar 0x%llx flags %b failed to create %s region",
		    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS,
		    srp_kstats->srp_name);
		goto failed;
	}

	skmem_region_mirror(ar->ar_regions[SKMEM_REGION_KSTATS],
	    ar->ar_regions[SKMEM_REGION_USTATS]);

	/* create skmem_cache for kernel stats (without magazines) */
	(void) snprintf(cname, sizeof(cname), "kstats.%s", name);
	if ((arc->arc_kstats_cache = skmem_cache_create(cname,
	    srp_kstats->srp_c_obj_size, 0, necp_stats_ctor, NULL, NULL, NULL,
	    ar->ar_regions[SKMEM_REGION_KSTATS],
	    SKMEM_CR_NOMAGAZINES)) == NULL) {
		SK_ERR("\"%s\" ar 0x%llx flags %b failed to create %s",
		    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS, cname);
		goto failed;
	}

	if (skmem_arena_create_finalize(ar) != 0) {
		SK_ERR("\"%s\" ar 0x%llx flags %b failed to finalize",
		    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS);
		goto failed;
	}

	/*
	 * These must never be configured for NECP arena.
	 *
	 * XXX: In theory we can add guard pages to this arena,
	 * but for now leave that as an exercise for the future.
	 */
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_HEAD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_SCHEMA] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RING] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_TXAUSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RXFUSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_FLOWADV] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_NEXUSADV] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_SYSCTLS] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_TAIL] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_TXAKSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RXFKSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_INTRINSIC] == NULL);
	for (int i = 0; i < SKMEM_PP_REGIONS; i++) {
		ASSERT(ar->ar_regions[skmem_pp_region_ids[i]] == NULL);
	}

	/* these must be configured for NECP arena */
	ASSERT(ar->ar_regions[SKMEM_REGION_USTATS] != NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_KSTATS] != NULL);

	++ar->ar_refcnt;        /* for caller */
	AR_UNLOCK(ar);

	SKMEM_ARENA_LOCK();
	TAILQ_INSERT_TAIL(&skmem_arena_head, ar, ar_link);
	SKMEM_ARENA_UNLOCK();

#if SK_LOG
	if (__improbable(sk_verbose != 0)) {
		skmem_arena_create_region_log(ar);
	}
#endif /* SK_LOG */

	return ar;

failed:
	AR_LOCK_ASSERT_HELD(ar);
	skmem_arena_destroy(ar);
	*perr = ENOMEM;

	return NULL;
}

static void
skmem_arena_necp_teardown(struct skmem_arena_necp *arc, boolean_t defunct)
{
#pragma unused(defunct)
	struct skmem_arena *ar = &arc->arc_cmn;
	struct skmem_region *skr;

	AR_LOCK_ASSERT_HELD(ar);
	ASSERT(ar->ar_type == SKMEM_ARENA_TYPE_NECP);

	/* these must never be configured for NECP arena */
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_HEAD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_SCHEMA] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RING] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_TXAUSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RXFUSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_FLOWADV] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_NEXUSADV] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_SYSCTLS] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_TAIL] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_TXAKSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RXFKSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_INTRINSIC] == NULL);
	for (int i = 0; i < SKMEM_PP_REGIONS; i++) {
		ASSERT(ar->ar_regions[skmem_pp_region_ids[i]] == NULL);
	}

	if (arc->arc_kstats_cache != NULL) {
		skr = ar->ar_regions[SKMEM_REGION_KSTATS];
		ASSERT(skr != NULL && !(skr->skr_mode & SKR_MODE_NOREDIRECT));
		skmem_cache_destroy(arc->arc_kstats_cache);
		arc->arc_kstats_cache = NULL;
		skmem_region_release(skr);
		ar->ar_regions[SKMEM_REGION_KSTATS] = NULL;

		skr = ar->ar_regions[SKMEM_REGION_USTATS];
		ASSERT(skr != NULL && !(skr->skr_mode & SKR_MODE_NOREDIRECT));
		skmem_region_release(skr);
		ar->ar_regions[SKMEM_REGION_USTATS] = NULL;
	}
	ASSERT(ar->ar_regions[SKMEM_REGION_USTATS] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_KSTATS] == NULL);
	ASSERT(arc->arc_kstats_cache == NULL);
}

/*
 * Given an arena, return its NECP variant (if applicable).
 */
struct skmem_arena_necp *
skmem_arena_necp(struct skmem_arena *ar)
{
	if (__improbable(ar->ar_type != SKMEM_ARENA_TYPE_NECP)) {
		return NULL;
	}

	return (struct skmem_arena_necp *)ar;
}

/*
 * Create a System arena.
 */
struct skmem_arena *
skmem_arena_create_for_system(const char *name, int *perr)
{
	struct skmem_region *skrsys;
	struct skmem_arena_system *ars;
	struct skmem_arena *ar;

	*perr = 0;

	ar = skmem_arena_alloc(SKMEM_ARENA_TYPE_SYSTEM, name);
	ASSERT(ar != NULL && ar->ar_zsize == AR_SYSTEM_SIZE);
	ars = (struct skmem_arena_system *)ar;

	AR_LOCK(ar);
	/* retain system-wide sysctls region */
	skrsys = skmem_get_sysctls_region();
	ASSERT(skrsys != NULL && skrsys->skr_id == SKMEM_REGION_SYSCTLS);
	ASSERT((skrsys->skr_mode & (SKR_MODE_MMAPOK | SKR_MODE_NOMAGAZINES |
	    SKR_MODE_KREADONLY | SKR_MODE_UREADONLY | SKR_MODE_MONOLITHIC |
	    SKR_MODE_SHAREOK)) ==
	    (SKR_MODE_MMAPOK | SKR_MODE_NOMAGAZINES | SKR_MODE_UREADONLY |
	    SKR_MODE_MONOLITHIC));
	ar->ar_regions[SKMEM_REGION_SYSCTLS] = skrsys;
	skmem_region_retain(skrsys);

	/* object is valid as long as the sysctls region is retained */
	ars->ars_sysctls_obj = skmem_get_sysctls_obj(&ars->ars_sysctls_objsize);
	ASSERT(ars->ars_sysctls_obj != NULL);
	ASSERT(ars->ars_sysctls_objsize != 0);

	if (skmem_arena_create_finalize(ar) != 0) {
		SK_ERR("\"%s\" ar 0x%llx flags %b failed to finalize",
		    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS);
		goto failed;
	}

	/*
	 * These must never be configured for system arena.
	 *
	 * XXX: In theory we can add guard pages to this arena,
	 * but for now leave that as an exercise for the future.
	 */
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_HEAD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_SCHEMA] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RING] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_TXAUSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RXFUSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_USTATS] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_FLOWADV] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_NEXUSADV] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_TAIL] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_TXAKSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RXFKSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_KSTATS] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_INTRINSIC] == NULL);
	for (int i = 0; i < SKMEM_PP_REGIONS; i++) {
		ASSERT(ar->ar_regions[skmem_pp_region_ids[i]] == NULL);
	}

	/* these must be configured for system arena */
	ASSERT(ar->ar_regions[SKMEM_REGION_SYSCTLS] != NULL);

	++ar->ar_refcnt;        /* for caller */
	AR_UNLOCK(ar);

	SKMEM_ARENA_LOCK();
	TAILQ_INSERT_TAIL(&skmem_arena_head, ar, ar_link);
	SKMEM_ARENA_UNLOCK();

#if SK_LOG
	if (__improbable(sk_verbose != 0)) {
		skmem_arena_create_region_log(ar);
	}
#endif /* SK_LOG */

	return ar;

failed:
	AR_LOCK_ASSERT_HELD(ar);
	skmem_arena_destroy(ar);
	*perr = ENOMEM;

	return NULL;
}

static void
skmem_arena_system_teardown(struct skmem_arena_system *ars, boolean_t defunct)
{
	struct skmem_arena *ar = &ars->ars_cmn;
	struct skmem_region *skr;

	AR_LOCK_ASSERT_HELD(ar);
	ASSERT(ar->ar_type == SKMEM_ARENA_TYPE_SYSTEM);

	/* these must never be configured for system arena */
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_HEAD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_SCHEMA] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RING] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_TXAUSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RXFUSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_USTATS] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_FLOWADV] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_NEXUSADV] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_GUARD_TAIL] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_TXAKSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_RXFKSD] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_KSTATS] == NULL);
	ASSERT(ar->ar_regions[SKMEM_REGION_INTRINSIC] == NULL);
	for (int i = 0; i < SKMEM_PP_REGIONS; i++) {
		ASSERT(ar->ar_regions[skmem_pp_region_ids[i]] == NULL);
	}

	/* nothing to do here for now during defunct, just return */
	if (defunct) {
		return;
	}

	if (ars->ars_sysctls_obj != NULL) {
		skr = ar->ar_regions[SKMEM_REGION_SYSCTLS];
		ASSERT(skr != NULL && (skr->skr_mode & SKR_MODE_NOREDIRECT));
		/* we didn't allocate this, so don't free it */
		ars->ars_sysctls_obj = NULL;
		ars->ars_sysctls_objsize = 0;
		skmem_region_release(skr);
		ar->ar_regions[SKMEM_REGION_SYSCTLS] = NULL;
	}
	ASSERT(ar->ar_regions[SKMEM_REGION_SYSCTLS] == NULL);
	ASSERT(ars->ars_sysctls_obj == NULL);
	ASSERT(ars->ars_sysctls_objsize == 0);
}

/*
 * Given an arena, return its System variant (if applicable).
 */
struct skmem_arena_system *
skmem_arena_system(struct skmem_arena *ar)
{
	if (__improbable(ar->ar_type != SKMEM_ARENA_TYPE_SYSTEM)) {
		return NULL;
	}

	return (struct skmem_arena_system *)ar;
}

void *
skmem_arena_system_sysctls_obj_addr(struct skmem_arena *ar)
{
	ASSERT(ar->ar_type == SKMEM_ARENA_TYPE_SYSTEM);
	return skmem_arena_system(ar)->ars_sysctls_obj;
}

size_t
skmem_arena_system_sysctls_obj_size(struct skmem_arena *ar)
{
	ASSERT(ar->ar_type == SKMEM_ARENA_TYPE_SYSTEM);
	return skmem_arena_system(ar)->ars_sysctls_objsize;
}

/*
 * Destroy a region.
 */
static void
skmem_arena_destroy(struct skmem_arena *ar)
{
	AR_LOCK_ASSERT_HELD(ar);

	SK_DF(SK_VERB_MEM_ARENA, "\"%s\" ar 0x%llx flags %b",
	    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS);

	ASSERT(ar->ar_refcnt == 0);
	if (ar->ar_link.tqe_next != NULL || ar->ar_link.tqe_prev != NULL) {
		AR_UNLOCK(ar);
		SKMEM_ARENA_LOCK();
		TAILQ_REMOVE(&skmem_arena_head, ar, ar_link);
		SKMEM_ARENA_UNLOCK();
		AR_LOCK(ar);
		ASSERT(ar->ar_refcnt == 0);
	}

	/* teardown all remaining memory regions and associated resources */
	skmem_arena_teardown(ar, FALSE);

	if (ar->ar_ar != NULL) {
		IOSKArenaDestroy(ar->ar_ar);
		ar->ar_ar = NULL;
	}

	if (ar->ar_flags & ARF_ACTIVE) {
		ar->ar_flags &= ~ARF_ACTIVE;
	}

	AR_UNLOCK(ar);

	skmem_arena_free(ar);
}

/*
 * Teardown (or defunct) a region.
 */
static void
skmem_arena_teardown(struct skmem_arena *ar, boolean_t defunct)
{
	uint32_t i;

	switch (ar->ar_type) {
	case SKMEM_ARENA_TYPE_NEXUS:
		skmem_arena_nexus_teardown((struct skmem_arena_nexus *)ar,
		    defunct);
		break;

	case SKMEM_ARENA_TYPE_NECP:
		skmem_arena_necp_teardown((struct skmem_arena_necp *)ar,
		    defunct);
		break;

	case SKMEM_ARENA_TYPE_SYSTEM:
		skmem_arena_system_teardown((struct skmem_arena_system *)ar,
		    defunct);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/* stop here if we're in the defunct context */
	if (defunct) {
		return;
	}

	/* take care of any remaining ones */
	for (i = 0; i < SKMEM_REGIONS; i++) {
		if (ar->ar_regions[i] == NULL) {
			continue;
		}

		skmem_region_release(ar->ar_regions[i]);
		ar->ar_regions[i] = NULL;
	}
}

static int
skmem_arena_create_finalize(struct skmem_arena *ar)
{
	IOSKRegionRef reg[SKMEM_REGIONS];
	uint32_t i, regcnt = 0;
	int err = 0;

	AR_LOCK_ASSERT_HELD(ar);

	ASSERT(ar->ar_regions[SKMEM_REGION_INTRINSIC] == NULL);

	/*
	 * Prepare an array of regions that can be mapped to user task;
	 * exclude regions that aren't eligible for user task mapping.
	 */
	bzero(&reg, sizeof(reg));
	for (i = 0; i < SKMEM_REGIONS; i++) {
		struct skmem_region *skr = ar->ar_regions[i];
		if (skr == NULL || !(skr->skr_mode & SKR_MODE_MMAPOK)) {
			continue;
		}

		ASSERT(skr->skr_reg != NULL);
		reg[regcnt++] = skr->skr_reg;
	}
	ASSERT(regcnt != 0);

	/*
	 * Create backing IOSKArena handle.
	 */
	ar->ar_ar = IOSKArenaCreate(reg, (IOSKCount)regcnt);
	if (ar->ar_ar == NULL) {
		SK_ERR("\"%s\" ar 0x%llx flags %b failed to create "
		    "IOSKArena of %u regions", ar->ar_name, SK_KVA(ar),
		    ar->ar_flags, ARF_BITS, regcnt);
		err = ENOMEM;
		goto failed;
	}

	ar->ar_flags |= ARF_ACTIVE;

failed:
	return err;
}

static struct skmem_arena *
skmem_arena_alloc(skmem_arena_type_t type, const char *name)
{
	const char *ar_str = NULL;
	struct zone *ar_zone = NULL;
	struct skmem_arena *ar;
	size_t ar_zsize = 0;

	switch (type) {
	case SKMEM_ARENA_TYPE_NEXUS:
		ar_zone = ar_nexus_zone;
		ar_zsize = AR_NEXUS_SIZE;
		ar_str = "nexus";
		break;

	case SKMEM_ARENA_TYPE_NECP:
		ar_zone = ar_necp_zone;
		ar_zsize = AR_NECP_SIZE;
		ar_str = "necp";
		break;

	case SKMEM_ARENA_TYPE_SYSTEM:
		ar_zone = ar_system_zone;
		ar_zsize = AR_SYSTEM_SIZE;
		ar_str = "system";
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	ar = zalloc_flags(ar_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	ar->ar_type = type;
	ar->ar_zsize = ar_zsize;
	ar->ar_zone = ar_zone;

	lck_mtx_init(&ar->ar_lock, &skmem_arena_lock_grp,
	    LCK_ATTR_NULL);
	(void) snprintf(ar->ar_name, sizeof(ar->ar_name),
	    "%s.%s.%s", SKMEM_ARENA_PREFIX, ar_str, name);

	return ar;
}

static void
skmem_arena_free(struct skmem_arena *ar)
{
#if DEBUG || DEVELOPMENT
	ASSERT(ar->ar_refcnt == 0);
	ASSERT(!(ar->ar_flags & ARF_ACTIVE));
	ASSERT(ar->ar_ar == NULL);
	ASSERT(ar->ar_mapcnt == 0);
	ASSERT(SLIST_EMPTY(&ar->ar_map_head));
	for (uint32_t i = 0; i < SKMEM_REGIONS; i++) {
		ASSERT(ar->ar_regions[i] == NULL);
	}
#endif /* DEBUG || DEVELOPMENT */

	lck_mtx_destroy(&ar->ar_lock, &skmem_arena_lock_grp);
	zfree(ar->ar_zone, ar);
}

/*
 * Retain an arena.
 */
__attribute__((always_inline))
static inline void
skmem_arena_retain_locked(struct skmem_arena *ar)
{
	AR_LOCK_ASSERT_HELD(ar);
	ar->ar_refcnt++;
	ASSERT(ar->ar_refcnt != 0);
}

void
skmem_arena_retain(struct skmem_arena *ar)
{
	AR_LOCK(ar);
	skmem_arena_retain_locked(ar);
	AR_UNLOCK(ar);
}

/*
 * Release (and potentially destroy) an arena.
 */
__attribute__((always_inline))
static inline boolean_t
skmem_arena_release_locked(struct skmem_arena *ar)
{
	boolean_t lastref = FALSE;

	AR_LOCK_ASSERT_HELD(ar);
	ASSERT(ar->ar_refcnt != 0);
	if (--ar->ar_refcnt == 0) {
		skmem_arena_destroy(ar);
		lastref = TRUE;
	} else {
		lastref = FALSE;
	}

	return lastref;
}

boolean_t
skmem_arena_release(struct skmem_arena *ar)
{
	boolean_t lastref;

	AR_LOCK(ar);
	/* unlock only if this isn't the last reference */
	if (!(lastref = skmem_arena_release_locked(ar))) {
		AR_UNLOCK(ar);
	}

	return lastref;
}

/*
 * Map an arena to the task's address space.
 */
int
skmem_arena_mmap(struct skmem_arena *ar, struct proc *p,
    struct skmem_arena_mmap_info *ami)
{
	task_t task = proc_task(p);
	IOReturn ioerr;
	int err = 0;

	ASSERT(task != kernel_task && task != TASK_NULL);
	ASSERT(ami->ami_arena == NULL);
	ASSERT(ami->ami_mapref == NULL);
	ASSERT(ami->ami_maptask == TASK_NULL);
	ASSERT(!ami->ami_redirect);

	AR_LOCK(ar);
	if ((ar->ar_flags & (ARF_ACTIVE | ARF_DEFUNCT)) != ARF_ACTIVE) {
		err = ENODEV;
		goto failed;
	}

	ASSERT(ar->ar_ar != NULL);
	if ((ami->ami_mapref = IOSKMapperCreate(ar->ar_ar, task)) == NULL) {
		err = ENOMEM;
		goto failed;
	}

	ioerr = IOSKMapperGetAddress(ami->ami_mapref, &ami->ami_mapaddr,
	    &ami->ami_mapsize);
	VERIFY(ioerr == kIOReturnSuccess);

	ami->ami_arena = ar;
	skmem_arena_retain_locked(ar);
	SLIST_INSERT_HEAD(&ar->ar_map_head, ami, ami_link);

	ami->ami_maptask = task;
	ar->ar_mapcnt++;
	if (ar->ar_mapcnt == 1) {
		ar->ar_mapsize = ami->ami_mapsize;
	}

	ASSERT(ami->ami_mapref != NULL);
	ASSERT(ami->ami_arena == ar);
	AR_UNLOCK(ar);

	return 0;

failed:
	AR_UNLOCK(ar);
	skmem_arena_munmap(ar, ami);
	VERIFY(err != 0);

	return err;
}

/*
 * Remove arena's memory mapping from task's address space (common code).
 * Returns true if caller needs to perform a deferred defunct.
 */
static boolean_t
skmem_arena_munmap_common(struct skmem_arena *ar,
    struct skmem_arena_mmap_info *ami)
{
	boolean_t need_defunct = FALSE;

	AR_LOCK(ar);
	if (ami->ami_mapref != NULL) {
		IOSKMapperDestroy(ami->ami_mapref);
		ami->ami_mapref = NULL;

		VERIFY(ar->ar_mapcnt != 0);
		ar->ar_mapcnt--;
		if (ar->ar_mapcnt == 0) {
			ar->ar_mapsize = 0;
		}

		VERIFY(ami->ami_arena == ar);
		SLIST_REMOVE(&ar->ar_map_head, ami, skmem_arena_mmap_info,
		    ami_link);

		/*
		 * We expect that the caller ensures an extra reference
		 * held on the arena, in addition to the one in mmap_info.
		 */
		VERIFY(ar->ar_refcnt > 1);
		(void) skmem_arena_release_locked(ar);
		ami->ami_arena = NULL;

		if (ami->ami_redirect) {
			/*
			 * This mapper has been redirected; decrement
			 * the redirect count associated with it.
			 */
			VERIFY(ar->ar_maprdrcnt != 0);
			ar->ar_maprdrcnt--;
		} else if (ar->ar_maprdrcnt != 0 &&
		    ar->ar_maprdrcnt == ar->ar_mapcnt) {
			/*
			 * The are other mappers for this arena that have
			 * all been redirected, but the arena wasn't marked
			 * inactive by skmem_arena_redirect() last time since
			 * this particular mapper that we just destroyed
			 * was using it.  Now that it's gone, finish the
			 * postponed work below once we return to caller.
			 */
			ASSERT(ar->ar_flags & ARF_ACTIVE);
			ar->ar_flags &= ~ARF_ACTIVE;
			need_defunct = TRUE;
		}
	}
	ASSERT(ami->ami_mapref == NULL);
	ASSERT(ami->ami_arena == NULL);

	ami->ami_maptask = TASK_NULL;
	ami->ami_mapaddr = 0;
	ami->ami_mapsize = 0;
	ami->ami_redirect = FALSE;

	AR_UNLOCK(ar);

	return need_defunct;
}

/*
 * Remove arena's memory mapping from task's address space (channel version).
 * Will perform a deferred defunct if needed.
 */
void
skmem_arena_munmap_channel(struct skmem_arena *ar, struct kern_channel *ch)
{
	SK_LOCK_ASSERT_HELD();
	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

	/*
	 * If this is this is on a channel that was holding the last
	 * active reference count on the arena, and that there are
	 * other defunct channels pointing to that arena, perform the
	 * actual arena defunct now.
	 */
	if (skmem_arena_munmap_common(ar, &ch->ch_mmap)) {
		struct kern_nexus *nx = ch->ch_nexus;
		struct kern_nexus_domain_provider *nxdom_prov = NX_DOM_PROV(nx);

		/*
		 * Similar to kern_channel_defunct(), where we let the
		 * domain provider complete the defunct.  At this point
		 * both sk_lock and the channel locks are held, and so
		 * we indicate that to the callee.
		 */
		nxdom_prov->nxdom_prov_dom->nxdom_defunct_finalize(nxdom_prov,
		    nx, ch, TRUE);
	}
}

/*
 * Remove arena's memory mapping from task's address space (generic).
 * This routine should only be called on non-channel related arenas.
 */
void
skmem_arena_munmap(struct skmem_arena *ar, struct skmem_arena_mmap_info *ami)
{
	(void) skmem_arena_munmap_common(ar, ami);
}

/*
 * Redirect eligible memory regions in the task's memory map so that
 * they get overwritten and backed with anonymous (zero-filled) pages.
 */
int
skmem_arena_mredirect(struct skmem_arena *ar, struct skmem_arena_mmap_info *ami,
    struct proc *p, boolean_t *need_defunct)
{
#pragma unused(p)
	int err = 0;

	*need_defunct = FALSE;

	AR_LOCK(ar);
	ASSERT(ar->ar_ar != NULL);
	if (ami->ami_redirect) {
		err = EALREADY;
	} else if (ami->ami_mapref == NULL) {
		err = ENXIO;
	} else {
		VERIFY(ar->ar_mapcnt != 0);
		ASSERT(ar->ar_flags & ARF_ACTIVE);
		VERIFY(ami->ami_arena == ar);
		/*
		 * This effectively overwrites the mappings for all
		 * redirectable memory regions (i.e. those without the
		 * SKMEM_REGION_CR_NOREDIRECT flag) while preserving their
		 * protection flags.  Accesses to these regions will be
		 * redirected to anonymous, zero-filled pages.
		 */
		IOSKMapperRedirect(ami->ami_mapref);
		ami->ami_redirect = TRUE;

		/*
		 * Mark the arena as inactive if all mapper instances are
		 * redirected; otherwise, we do this later during unmap.
		 * Once inactive, the arena will not allow further mmap,
		 * and it is ready to be defunct later.
		 */
		if (++ar->ar_maprdrcnt == ar->ar_mapcnt) {
			ar->ar_flags &= ~ARF_ACTIVE;
			*need_defunct = TRUE;
		}
	}
	AR_UNLOCK(ar);

	SK_DF(((err != 0) ? SK_VERB_ERROR : SK_VERB_DEFAULT),
	    "%s(%d) \"%s\" ar 0x%llx flags %b inactive %u need_defunct %u "
	    "err %d", sk_proc_name_address(p), sk_proc_pid(p), ar->ar_name,
	    SK_KVA(ar), ar->ar_flags, ARF_BITS, !(ar->ar_flags & ARF_ACTIVE),
	    *need_defunct, err);

	return err;
}

/*
 * Defunct a region.
 */
int
skmem_arena_defunct(struct skmem_arena *ar)
{
	AR_LOCK(ar);

	SK_DF(SK_VERB_MEM_ARENA, "\"%s\" ar 0x%llx flags 0x%b", ar->ar_name,
	    SK_KVA(ar), ar->ar_flags, ARF_BITS);

	if (ar->ar_flags & ARF_DEFUNCT) {
		AR_UNLOCK(ar);
		return EALREADY;
	} else if (ar->ar_flags & ARF_ACTIVE) {
		AR_UNLOCK(ar);
		return EBUSY;
	}

	/* purge the caches now */
	skmem_arena_reap_locked(ar, TRUE);

	/* teardown eligible memory regions and associated resources */
	skmem_arena_teardown(ar, TRUE);

	ar->ar_flags |= ARF_DEFUNCT;

	AR_UNLOCK(ar);

	return 0;
}

/*
 * Retrieve total and in-use memory statistics of regions in the arena.
 */
void
skmem_arena_get_stats(struct skmem_arena *ar, uint64_t *mem_total,
    uint64_t *mem_inuse)
{
	uint32_t i;

	if (mem_total != NULL) {
		*mem_total = 0;
	}
	if (mem_inuse != NULL) {
		*mem_inuse = 0;
	}

	AR_LOCK(ar);
	for (i = 0; i < SKMEM_REGIONS; i++) {
		if (ar->ar_regions[i] == NULL) {
			continue;
		}

		if (mem_total != NULL) {
			*mem_total += AR_MEM_TOTAL(ar, i);
		}
		if (mem_inuse != NULL) {
			*mem_inuse += AR_MEM_INUSE(ar, i);
		}
	}
	AR_UNLOCK(ar);
}

/*
 * Retrieve the offset of a particular region (identified by its ID)
 * from the base of the arena.
 */
mach_vm_offset_t
skmem_arena_get_region_offset(struct skmem_arena *ar, skmem_region_id_t id)
{
	mach_vm_offset_t offset = 0;
	uint32_t i;

	ASSERT(id < SKMEM_REGIONS);

	AR_LOCK(ar);
	for (i = 0; i < id; i++) {
		if (ar->ar_regions[i] == NULL) {
			continue;
		}

		offset += ar->ar_regions[i]->skr_size;
	}
	AR_UNLOCK(ar);

	return offset;
}

static void
skmem_reap_pbufpool_caches(struct kern_pbufpool *pp, boolean_t purge)
{
	if (pp->pp_kmd_cache != NULL) {
		skmem_cache_reap_now(pp->pp_kmd_cache, purge);
	}
	if (PP_BUF_CACHE_DEF(pp) != NULL) {
		skmem_cache_reap_now(PP_BUF_CACHE_DEF(pp), purge);
	}
	if (PP_BUF_CACHE_LARGE(pp) != NULL) {
		skmem_cache_reap_now(PP_BUF_CACHE_LARGE(pp), purge);
	}
	if (PP_KBFT_CACHE_DEF(pp) != NULL) {
		skmem_cache_reap_now(PP_KBFT_CACHE_DEF(pp), purge);
	}
	if (PP_KBFT_CACHE_LARGE(pp) != NULL) {
		skmem_cache_reap_now(PP_KBFT_CACHE_LARGE(pp), purge);
	}
	if (pp->pp_raw_kbft_cache != NULL) {
		skmem_cache_reap_now(pp->pp_raw_kbft_cache, purge);
	}
}

/*
 * Reap all of configured caches in the arena, so that any excess amount
 * outside of their working sets gets released to their respective backing
 * regions.  If purging is specified, we empty the caches' working sets,
 * including everything that's cached at the CPU layer.
 */
static void
skmem_arena_reap_locked(struct skmem_arena *ar, boolean_t purge)
{
	struct skmem_arena_nexus *arn;
	struct skmem_arena_necp *arc;
	struct kern_pbufpool *pp;

	AR_LOCK_ASSERT_HELD(ar);

	switch (ar->ar_type) {
	case SKMEM_ARENA_TYPE_NEXUS:
		arn = (struct skmem_arena_nexus *)ar;
		if (arn->arn_schema_cache != NULL) {
			skmem_cache_reap_now(arn->arn_schema_cache, purge);
		}
		if (arn->arn_ring_cache != NULL) {
			skmem_cache_reap_now(arn->arn_ring_cache, purge);
		}
		if ((pp = arn->arn_rx_pp) != NULL) {
			skmem_reap_pbufpool_caches(pp, purge);
		}
		if ((pp = arn->arn_tx_pp) != NULL && pp != arn->arn_rx_pp) {
			skmem_reap_pbufpool_caches(pp, purge);
		}
		break;

	case SKMEM_ARENA_TYPE_NECP:
		arc = (struct skmem_arena_necp *)ar;
		if (arc->arc_kstats_cache != NULL) {
			skmem_cache_reap_now(arc->arc_kstats_cache, purge);
		}
		break;

	case SKMEM_ARENA_TYPE_SYSTEM:
		break;
	}
}

void
skmem_arena_reap(struct skmem_arena *ar, boolean_t purge)
{
	AR_LOCK(ar);
	skmem_arena_reap_locked(ar, purge);
	AR_UNLOCK(ar);
}

#if SK_LOG
SK_LOG_ATTRIBUTE
static void
skmem_arena_create_region_log(struct skmem_arena *ar)
{
	char label[32];
	int i;

	switch (ar->ar_type) {
	case SKMEM_ARENA_TYPE_NEXUS:
		SK_D("\"%s\" ar 0x%llx flags %b rx_pp 0x%llx tx_pp 0x%llu",
		    ar->ar_name, SK_KVA(ar), ar->ar_flags, ARF_BITS,
		    SK_KVA(skmem_arena_nexus(ar)->arn_rx_pp),
		    SK_KVA(skmem_arena_nexus(ar)->arn_tx_pp));
		break;

	case SKMEM_ARENA_TYPE_NECP:
	case SKMEM_ARENA_TYPE_SYSTEM:
		SK_D("\"%s\" ar 0x%llx flags %b", ar->ar_name,
		    SK_KVA(ar), ar->ar_flags, ARF_BITS);
		break;
	}

	for (i = 0; i < SKMEM_REGIONS; i++) {
		if (ar->ar_regions[i] == NULL) {
			continue;
		}

		(void) snprintf(label, sizeof(label), "REGION_%s:",
		    skmem_region_id2name(i));
		SK_D("  %-16s %6u KB s:[%2u x %6u KB] "
		    "o:[%4u x %6u -> %4u x %6u]", label,
		    (uint32_t)AR_MEM_TOTAL(ar, i) >> 10,
		    (uint32_t)AR_MEM_SEGCNT(ar, i),
		    (uint32_t)AR_MEM_SEGSIZE(ar, i) >> 10,
		    (uint32_t)AR_MEM_OBJCNT_R(ar, i),
		    (uint32_t)AR_MEM_OBJSIZE_R(ar, i),
		    (uint32_t)AR_MEM_OBJCNT_C(ar, i),
		    (uint32_t)AR_MEM_OBJSIZE_C(ar, i));
	}
}
#endif /* SK_LOG */

static size_t
skmem_arena_mib_get_stats(struct skmem_arena *ar, void *out, size_t len)
{
	size_t actual_space = sizeof(struct sk_stats_arena);
	struct sk_stats_arena *sar = out;
	struct skmem_arena_mmap_info *ami = NULL;
	pid_t proc_pid;
	int i;

	if (out == NULL || len < actual_space) {
		goto done;
	}

	AR_LOCK(ar);
	(void) snprintf(sar->sar_name, sizeof(sar->sar_name),
	    "%s", ar->ar_name);
	sar->sar_type = (sk_stats_arena_type_t)ar->ar_type;
	sar->sar_mapsize = (uint64_t)ar->ar_mapsize;
	i = 0;
	SLIST_FOREACH(ami, &ar->ar_map_head, ami_link) {
		if (ami->ami_arena->ar_type == SKMEM_ARENA_TYPE_NEXUS) {
			struct kern_channel *ch;
			ch = container_of(ami, struct kern_channel, ch_mmap);
			proc_pid = ch->ch_pid;
		} else {
			ASSERT((ami->ami_arena->ar_type ==
			    SKMEM_ARENA_TYPE_NECP) ||
			    (ami->ami_arena->ar_type ==
			    SKMEM_ARENA_TYPE_SYSTEM));
			proc_pid =
			    necp_client_get_proc_pid_from_arena_info(ami);
		}
		sar->sar_mapped_pids[i++] = proc_pid;
		if (i >= SK_STATS_ARENA_MAPPED_PID_MAX) {
			break;
		}
	}

	for (i = 0; i < SKMEM_REGIONS; i++) {
		struct skmem_region *skr = ar->ar_regions[i];
		uuid_t *sreg_uuid = &sar->sar_regions_uuid[i];

		if (skr == NULL) {
			uuid_clear(*sreg_uuid);
			continue;
		}

		uuid_copy(*sreg_uuid, skr->skr_uuid);
	}
	AR_UNLOCK(ar);

done:
	return actual_space;
}

static int
skmem_arena_mib_get_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	struct skmem_arena *ar;
	size_t actual_space;
	size_t buffer_space;
	size_t allocated_space;
	caddr_t buffer = NULL;
	caddr_t scan;
	int error = 0;

	if (!kauth_cred_issuser(kauth_cred_get())) {
		return EPERM;
	}

	net_update_uptime();
	buffer_space = req->oldlen;
	if (req->oldptr != USER_ADDR_NULL && buffer_space != 0) {
		if (buffer_space > SK_SYSCTL_ALLOC_MAX) {
			buffer_space = SK_SYSCTL_ALLOC_MAX;
		}
		allocated_space = buffer_space;
		buffer = sk_alloc_data(allocated_space, Z_WAITOK, skmem_tag_arena_mib);
		if (__improbable(buffer == NULL)) {
			return ENOBUFS;
		}
	} else if (req->oldptr == USER_ADDR_NULL) {
		buffer_space = 0;
	}
	actual_space = 0;
	scan = buffer;

	SKMEM_ARENA_LOCK();
	TAILQ_FOREACH(ar, &skmem_arena_head, ar_link) {
		size_t size = skmem_arena_mib_get_stats(ar, scan, buffer_space);
		if (scan != NULL) {
			if (buffer_space < size) {
				/* supplied buffer too small, stop copying */
				error = ENOMEM;
				break;
			}
			scan += size;
			buffer_space -= size;
		}
		actual_space += size;
	}
	SKMEM_ARENA_UNLOCK();

	if (actual_space != 0) {
		int out_error = SYSCTL_OUT(req, buffer, actual_space);
		if (out_error != 0) {
			error = out_error;
		}
	}
	if (buffer != NULL) {
		sk_free_data(buffer, allocated_space);
	}

	return error;
}
