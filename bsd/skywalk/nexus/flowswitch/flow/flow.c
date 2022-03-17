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

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>

#include <dev/random/randomdev.h>

#define SK_FO_ZONE_MAX                  256
#define SK_FO_ZONE_NAME                 "flow.owner"

unsigned int sk_fo_size;                /* size of zone element */
struct skmem_cache *sk_fo_cache;        /* cache for flow_owner */

#define SK_FE_ZONE_NAME                 "flow.entry"

unsigned int sk_fe_size;                /* size of zone element */
struct skmem_cache *sk_fe_cache;        /* cache for flow_entry */

#define SK_FAB_ZONE_NAME                "flow.adv.bmap"

unsigned int sk_fab_size;               /* size of zone element */
struct skmem_cache *sk_fab_cache;       /* cache for flow advisory bitmap */

ZONE_DECLARE(sk_fed_zone, SKMEM_ZONE_PREFIX ".flow.entry.dead",
    sizeof(struct flow_entry_dead), ZC_ZFREE_CLEARMEM);

static int __flow_inited = 0;
uint32_t flow_seed;

int
flow_init(void)
{
	SK_LOCK_ASSERT_HELD();
	ASSERT(!__flow_inited);

	do {
		read_random(&flow_seed, sizeof(flow_seed));
	} while (flow_seed == 0);

	sk_fo_size = sizeof(struct flow_owner);
	if (sk_fo_cache == NULL) {
		sk_fo_cache = skmem_cache_create(SK_FO_ZONE_NAME, sk_fo_size,
		    sizeof(uint64_t), NULL, NULL, NULL, NULL, NULL, 0);
		if (sk_fo_cache == NULL) {
			panic("%s: skmem_cache create failed (%s)", __func__,
			    SK_FO_ZONE_NAME);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}

	sk_fe_size = sizeof(struct flow_entry);
	if (sk_fe_cache == NULL) {
		/* request for 16-bytes alignment (due to fe_key) */
		sk_fe_cache = skmem_cache_create(SK_FE_ZONE_NAME, sk_fe_size,
		    16, NULL, NULL, NULL, NULL, NULL, 0);
		if (sk_fe_cache == NULL) {
			panic("%s: skmem_cache create failed (%s)", __func__,
			    SK_FE_ZONE_NAME);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}

	/* these are initialized in skywalk_init() */
	VERIFY(sk_max_flows > 0 && sk_max_flows <= NX_FLOWADV_MAX);
	VERIFY(sk_fadv_nchunks != 0);
	_CASSERT(sizeof(*((struct flow_owner *)0)->fo_flowadv_bmap) ==
	    sizeof(bitmap_t));

	sk_fab_size = (sk_fadv_nchunks * sizeof(bitmap_t));
	if (sk_fab_cache == NULL) {
		sk_fab_cache = skmem_cache_create(SK_FAB_ZONE_NAME, sk_fab_size,
		    sizeof(uint64_t), NULL, NULL, NULL, NULL, NULL, 0);
		if (sk_fab_cache == NULL) {
			panic("%s: skmem_cache create failed (%s)", __func__,
			    SK_FAB_ZONE_NAME);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}

	flow_route_init();
	flow_stats_init();

	__flow_inited = 1;

	return 0;
}

void
flow_fini(void)
{
	if (__flow_inited) {
		flow_stats_fini();

		flow_route_fini();

		if (sk_fo_cache != NULL) {
			skmem_cache_destroy(sk_fo_cache);
			sk_fo_cache = NULL;
		}
		if (sk_fe_cache != NULL) {
			skmem_cache_destroy(sk_fe_cache);
			sk_fe_cache = NULL;
		}
		if (sk_fab_cache != NULL) {
			skmem_cache_destroy(sk_fab_cache);
			sk_fab_cache = NULL;
		}
		__flow_inited = 0;
	}
}
