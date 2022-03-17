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

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>

#define FS_ZONE_NAME            "flow.stats"

unsigned int flow_stats_size;           /* size of zone element */
struct skmem_cache *flow_stats_cache;   /* cache for flow_stats */

os_refgrp_decl(static, flow_stats_refgrp, "flow_stats", NULL);

static int __flow_stats_inited = 0;

void
flow_stats_init(void)
{
	ASSERT(!__flow_stats_inited);

	flow_stats_size = sizeof(struct flow_stats);
	/* request for 16-bytes alignment (due to fe_key) */
	flow_stats_cache = skmem_cache_create(FS_ZONE_NAME, flow_stats_size,
	    16, NULL, NULL, NULL, NULL, NULL, 0);
	if (flow_stats_cache == NULL) {
		panic("%s: skmem_cache create failed (%s)",
		    __func__, FS_ZONE_NAME);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	__flow_stats_inited = 1;
}

void
flow_stats_fini(void)
{
	if (__flow_stats_inited) {
		skmem_cache_destroy(flow_stats_cache);
		flow_stats_cache = NULL;
		__flow_stats_inited = 0;
	}
}

struct flow_stats *
flow_stats_alloc(boolean_t cansleep)
{
	struct flow_stats *fs;

	_CASSERT((offsetof(struct flow_stats, fs_stats) % 16) == 0);
	_CASSERT((offsetof(struct sk_stats_flow, sf_key) % 16) == 0);

	if ((fs = skmem_cache_alloc(flow_stats_cache,
	    (cansleep ? SKMEM_SLEEP : SKMEM_NOSLEEP))) != NULL) {
		/*
		 * sf_key is 16-bytes aligned which requires fe to begin on
		 * a 16-bytes boundary as well.  This alignment is specified
		 * at flow_stats_cache creation time and we assert here.
		 */
		ASSERT(IS_P2ALIGNED(fs, 16));
		bzero(fs, flow_stats_size);
		os_ref_init(&fs->fs_refcnt, &flow_stats_refgrp);
		SK_DF(SK_VERB_MEM, "allocated fs 0x%llx", SK_KVA(fs));
	}

	return fs;
}

void
flow_stats_free(struct flow_stats *fs)
{
	VERIFY(os_ref_get_count(&fs->fs_refcnt) == 0);

	SK_DF(SK_VERB_MEM, "freeing fs 0x%llx", SK_KVA(fs));
	skmem_cache_free(flow_stats_cache, fs);
}
