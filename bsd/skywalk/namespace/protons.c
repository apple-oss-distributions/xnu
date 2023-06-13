/*
 * Copyright (c) 2019-2021 Apple Inc. All rights reserved.
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

#include <skywalk/os_skywalk.h>
#include <skywalk/os_skywalk_private.h>
#include <skywalk/namespace/protons.h>

#include <kern/bits.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <sys/domain.h>

static int __protons_inited = 0;

decl_lck_mtx_data(static, protons_lock);
static LCK_GRP_DECLARE(protons_lock_group, "protons_lock");
static LCK_MTX_DECLARE(protons_lock, &protons_lock_group);

#define PROTONS_LOCK()                    \
	lck_mtx_lock(&protons_lock)
#define PROTONS_UNLOCK()                  \
	lck_mtx_unlock(&protons_lock)
#define PROTONS_LOCK_ASSERT_HELD()        \
	LCK_MTX_ASSERT(&protons_lock, LCK_MTX_ASSERT_OWNED)
#define PROTONS_LOCK_ASSERT_NOTHELD()     \
	LCK_MTX_ASSERT(&protons_lock, LCK_MTX_ASSERT_NOTOWNED)

os_refgrp_decl(static, protons_token_refgrp, "protons_token", NULL);

struct protons_token {
	RB_ENTRY(protons_token) pt_link;
	os_refcnt_t             pt_refcnt;
	pid_t                   pt_pid;
	pid_t                   pt_epid;
	uint8_t                 pt_protocol;
	uint8_t                 pt_flags;
};

enum {
	PROTONSF_VALID = (((uint8_t)1) << 0),
};

__attribute__((always_inline))
static inline int
pt_cmp(const struct protons_token *pt1, const struct protons_token *pt2)
{
	return (int)pt1->pt_protocol - (int)pt2->pt_protocol;
}
RB_HEAD(protons_token_tree, protons_token);
RB_PROTOTYPE_PREV(protons_token_tree, protons_token, pt_link, pt_cmp);
RB_GENERATE_PREV(protons_token_tree, protons_token, pt_link, pt_cmp);
static struct protons_token_tree protons_tokens;

static SKMEM_TYPE_DEFINE(protons_token_zone, struct protons_token);

static struct protons_token *
protons_token_alloc(bool can_block)
{
	PROTONS_LOCK_ASSERT_HELD();

	struct protons_token *pt = NULL;
	pt = can_block ? zalloc(protons_token_zone) :
	    zalloc_noblock(protons_token_zone);
	if (pt == NULL) {
		return NULL;
	}

	memset(pt, 0, sizeof(*pt));
	os_ref_init(&pt->pt_refcnt, &protons_token_refgrp);

	SK_DF(SK_VERB_NS_PROTO, "token %p alloc", (void *)SK_KVA(pt));

	return pt;
}

static void
protons_token_free(struct protons_token *pt)
{
	PROTONS_LOCK_ASSERT_HELD();

	SK_DF(SK_VERB_NS_PROTO, "token %p free", (void *)SK_KVA(pt));
	ASSERT(os_ref_get_count(&pt->pt_refcnt) == 0);
	zfree(protons_token_zone, pt);
}

bool
protons_token_is_valid(struct protons_token *pt)
{
	if (__improbable(pt == NULL)) {
		return false;
	}
	return pt->pt_flags & PROTONSF_VALID;
}

bool
protons_token_has_matching_pid(struct protons_token *pt, pid_t pid, pid_t epid)
{
	ASSERT(pt != NULL);
	return pt->pt_pid == pid && pt->pt_epid == epid;
}

static struct protons_token *
protons_find_token_with_protocol(uint8_t proto)
{
	struct protons_token find = { .pt_protocol = proto };

	PROTONS_LOCK_ASSERT_HELD();
	struct protons_token *pt = NULL;
	pt = RB_FIND(protons_token_tree, &protons_tokens, &find);
	if (pt) {
		os_ref_retain(&pt->pt_refcnt);
	}
	return pt;
}

int
protons_token_get_use_count(struct protons_token *pt)
{
	/* minus one refcnt in RB tree*/
	return os_ref_get_count(&pt->pt_refcnt) - 1;
}

static void
protons_token_release(struct protons_token *pt)
{
	os_ref_count_t refcnt = os_ref_release(&pt->pt_refcnt);

	SK_DF(SK_VERB_NS_PROTO,
	    "token %p proto %u released by pid %d epid %d, curr use %u",
	    (void *)SK_KVA(pt), pt->pt_protocol, pt->pt_pid, pt->pt_epid,
	    protons_token_get_use_count(pt));

	if (refcnt == 1) {
		RB_REMOVE(protons_token_tree, &protons_tokens, pt);
		(void) os_ref_release(&pt->pt_refcnt);
		pt->pt_flags &= ~PROTONSF_VALID;
		pt->pt_protocol = 0;
		pt->pt_pid = 0;
		pt->pt_epid = 0;
		protons_token_free(pt);
	}
}

static int
protons_reserve_locked(struct protons_token **ptp, pid_t pid, pid_t epid,
    uint8_t proto)
{
	struct protons_token *pt = NULL, *dup = NULL;
	*ptp = NULL;

	pt = protons_find_token_with_protocol(proto);
	if (pt != NULL) {
		/* use previously reserved token with same process */
		ASSERT(pt->pt_flags & PROTONSF_VALID);
		if (pt->pt_pid != pid || pt->pt_epid != epid) {
			SK_ERR("proto %u existed with pid %d epid %d",
			    proto, pt->pt_pid, pt->pt_epid);
			(void) os_ref_release(&pt->pt_refcnt);
			pt = NULL;
			return EEXIST;
		}
	} else {
		/* start with new token */
		pt = protons_token_alloc(true);
		if (pt == NULL) {
			return ENOMEM;
		}

		os_ref_retain(&pt->pt_refcnt);
		pt->pt_flags |= PROTONSF_VALID;
		pt->pt_pid = pid;
		pt->pt_epid = (epid != -1) ? epid : pid;
		pt->pt_protocol = proto;
		dup = RB_INSERT(protons_token_tree, &protons_tokens, pt);
		ASSERT(dup == NULL);
	}

	SK_DF(SK_VERB_NS_PROTO,
	    "token %p proto %u reserved by pid %d epid %d, curr use %u",
	    (void *)SK_KVA(pt), proto, pid, epid, protons_token_get_use_count(pt));
	*ptp = pt;

	return 0;
}

int
protons_reserve(struct protons_token **ptp, pid_t pid, pid_t epid,
    uint8_t proto)
{
	int err = 0;
	PROTONS_LOCK();
	err = protons_reserve_locked(ptp, pid, epid, proto);
	PROTONS_UNLOCK();
	return err;
}

void
protons_release(struct protons_token **ptp)
{
	struct protons_token *pt = *ptp;
	ASSERT(pt != NULL);

	PROTONS_LOCK();
	protons_token_release(pt);
	PROTONS_UNLOCK();
	*ptp = NULL;
}

/* Reserved all protocol used by BSD stack. */
static void
protons_init_netinet_protocol(void)
{
	PROTONS_LOCK();

	uint8_t proto = 0;
	struct protons_token *pt = NULL;
	int error = 0;
	struct protosw *pp = NULL;
	TAILQ_FOREACH(pp, &inetdomain->dom_protosw, pr_entry) {
		pt = NULL;
		proto = (uint8_t)pp->pr_protocol;
		error = protons_reserve_locked(&pt, 0, 0, proto);
		VERIFY(error == 0 || error == EEXIST);
		VERIFY(pt != NULL);
	}

	TAILQ_FOREACH(pp, &inet6domain->dom_protosw, pr_entry) {
		pt = NULL;
		proto = (uint8_t)pp->pr_protocol;
		error = protons_reserve_locked(&pt, 0, 0, proto);
		VERIFY(error == 0 || error == EEXIST);
		VERIFY(pt != NULL);
	}

	PROTONS_UNLOCK();
}

int
protons_init(void)
{
	VERIFY(__protons_inited == 0);

	RB_INIT(&protons_tokens);

	protons_init_netinet_protocol();

	__protons_inited = 1;
	sk_features |= SK_FEATURE_PROTONS;

	SK_D("initialized protons");

	return 0;
}

void
protons_fini(void)
{
	if (__protons_inited == 1) {
		__protons_inited = 0;
		sk_features &= ~SK_FEATURE_PROTONS;
	}
}

static int protons_stats_sysctl SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, protons,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, protons_stats_sysctl, "", "");

static int
protons_stats_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int error = 0;
	size_t actual_space;
	caddr_t buffer = NULL;
	size_t buffer_space;
	size_t allocated_space;
	int out_error;
	caddr_t scan;

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
		buffer = sk_alloc_data(allocated_space, Z_WAITOK, skmem_tag_sysctl_buf);
		if (__improbable(buffer == NULL)) {
			return ENOBUFS;
		}
	} else if (req->oldptr == USER_ADDR_NULL) {
		buffer_space = 0;
	}
	actual_space = 0;
	scan = buffer;

	struct sk_stats_protons_token *spt = (void *)scan;
	size_t spt_size = sizeof(*spt);
	struct protons_token *pt = NULL;
	PROTONS_LOCK();
	RB_FOREACH(pt, protons_token_tree, &protons_tokens) {
		if (scan != NULL) {
			if (buffer_space < spt_size) {
				/* supplied buffer too small, stop copying */
				error = ENOMEM;
				break;
			}
			spt->spt_protocol = pt->pt_protocol;
			spt->spt_refcnt = protons_token_get_use_count(pt);
			spt->spt_pid = pt->pt_pid;
			spt->spt_epid = pt->pt_epid;
			spt++;
			buffer_space -= spt_size;
		}
		actual_space += spt_size;
	}
	PROTONS_UNLOCK();

	if (actual_space != 0) {
		out_error = SYSCTL_OUT(req, buffer, actual_space);
		if (out_error != 0) {
			error = out_error;
		}
	}
	if (buffer != NULL) {
		sk_free_data(buffer, allocated_space);
	}
	return error;
}
