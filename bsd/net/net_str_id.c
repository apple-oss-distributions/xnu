/*
 * Copyright (c) 2008-2021 Apple Inc. All rights reserved.
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

#include <sys/types.h>
#include <kern/locks.h>
#include <kern/zalloc.h>
#include <sys/errno.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <libkern/OSAtomic.h>
#include <libkern/libkern.h>
#include <net/if.h>
#include <net/if_mib.h>
#include <string.h>

// TODO: -fbounds-safety increases the alignment and we have
//       no control over the alignment. (rdar://118519573)
#pragma clang diagnostic ignored "-Wcast-align"
#include "net/net_str_id.h"

#define NET_ID_STR_MAX_LEN 2048

#define FIRST_NET_STR_ID                                1000
static SLIST_HEAD(, net_str_id_entry)    net_str_id_list = {NULL};
static LCK_GRP_DECLARE(net_str_id_grp, "mbuf_tag_allocate_id");
static LCK_MTX_DECLARE(net_str_id_lock, &net_str_id_grp);

static u_int32_t nsi_kind_next[NSI_MAX_KIND] = { FIRST_NET_STR_ID, FIRST_NET_STR_ID, FIRST_NET_STR_ID };
static u_int32_t nsi_next_id = FIRST_NET_STR_ID;

__private_extern__ void
net_str_id_first_last(u_int32_t *first, u_int32_t *last, u_int32_t kind)
{
	*first = FIRST_NET_STR_ID;

	switch (kind) {
	case NSI_MBUF_TAG:
	case NSI_VENDOR_CODE:
	case NSI_IF_FAM_ID:
		*last = nsi_kind_next[kind] - 1;
		break;
	default:
		*last = FIRST_NET_STR_ID - 1;
		break;
	}
}

__private_extern__ errno_t
net_str_id_find_internal(const char *string, u_int32_t *out_id,
    u_int32_t kind, int create)
{
	struct net_str_id_entry                 *entry = NULL;


	if (string == NULL || out_id == NULL || kind >= NSI_MAX_KIND) {
		return EINVAL;
	}
	if (strlen(string) > NET_ID_STR_MAX_LEN) {
		return EINVAL;
	}

	*out_id = 0;

	/* Look for an existing entry */
	lck_mtx_lock(&net_str_id_lock);
	SLIST_FOREACH(entry, &net_str_id_list, nsi_next) {
		if (strlcmp(entry->nsi_string, string, entry->nsi_length) == 0) {
			break;
		}
	}

	if (entry == NULL) {
		if (create == 0) {
			lck_mtx_unlock(&net_str_id_lock);
			return ENOENT;
		}

		const uint32_t string_length = (uint32_t)strlen(string) + 1;
		entry = zalloc_permanent(sizeof(*entry) + string_length,
		    ZALIGN_PTR);
		if (entry == NULL) {
			lck_mtx_unlock(&net_str_id_lock);
			return ENOMEM;
		}

		strlcpy(entry->nsi_string, string, string_length);
		entry->nsi_length = string_length;
		entry->nsi_flags = (1 << kind);
		entry->nsi_id = nsi_next_id++;
		nsi_kind_next[kind] = nsi_next_id;
		SLIST_INSERT_HEAD(&net_str_id_list, entry, nsi_next);
	} else if ((entry->nsi_flags & (1 << kind)) == 0) {
		if (create == 0) {
			lck_mtx_unlock(&net_str_id_lock);
			return ENOENT;
		}
		entry->nsi_flags |= (1 << kind);
		if (entry->nsi_id >= nsi_kind_next[kind]) {
			nsi_kind_next[kind] = entry->nsi_id + 1;
		}
	}
	lck_mtx_unlock(&net_str_id_lock);

	*out_id = entry->nsi_id;

	return 0;
}
