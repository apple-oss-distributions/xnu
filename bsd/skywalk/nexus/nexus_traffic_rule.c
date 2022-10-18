/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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
#include <skywalk/nexus/netif/nx_netif.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/sdt.h>

/*
 * Implementation of nexus traffic rules APIs.
 */

struct nxctl_traffic_rule_type;
struct nxctl_traffic_rule;

/*
 * These callbacks need to be implemented for each rule type.
 */

/* Validate user provided parameters. */
typedef int (nxctl_traffic_rule_validate_cb_t)(
	struct nxctl_traffic_rule_type *type,
	const char *ifname,
	struct ifnet_traffic_descriptor_common *td,
	struct ifnet_traffic_rule_action *ra);
/*
 * Each rule type has its own global structure for storing rules.
 * These callbacks access this global structure.
 */
#define NTR_FIND_FLAG_EXACT 0x0001
typedef int (nxctl_traffic_rule_find_cb_t)(
	struct nxctl_traffic_rule_type *type,
	const char *ifname,
	struct ifnet_traffic_descriptor_common *td,
	uint32_t flags,
	struct nxctl_traffic_rule **ntrp);

typedef int (nxctl_traffic_rule_find_by_uuid_cb_t)(
	struct nxctl_traffic_rule_type *type,
	uuid_t uuid,
	struct nxctl_traffic_rule **ntrp);

typedef void (nxctl_traffic_rule_link_cb_t)(
	struct nxctl_traffic_rule *ntr);

typedef void (nxctl_traffic_rule_unlink_cb_t)(
	struct nxctl_traffic_rule *ntr);

/*
 * Notifies lower layers of the addition/removal of a rule.
 * This is called outside of nxctl_traffic_rule_lock to avoid potential
 * locking issues.
 */
#define NTR_NOTIFY_FLAG_ADD 0x0001
#define NTR_NOTIFY_FLAG_REMOVE 0x0002
typedef int (nxctl_traffic_rule_notify_cb_t)(
	struct nxctl_traffic_rule *ntr,
	uint32_t flags);

/*
 * Create/Destroy callbacks for a rule type.
 */
typedef int (nxctl_traffic_rule_create_cb_t)(
	struct nxctl_traffic_rule_type *type,
	const char *ifname,
	struct ifnet_traffic_descriptor_common *td,
	struct ifnet_traffic_rule_action *ra,
	uint32_t flags,
	struct nxctl_traffic_rule **ntrp);

typedef void (nxctl_traffic_rule_destroy_cb_t)(
	struct nxctl_traffic_rule *ntr);

/*
 * This is used for copying all rules for a type (including generic
 * and type-specific info) to userspace.
 */
typedef int (nxctl_traffic_rule_get_all_cb_t)(
	struct nxctl_traffic_rule_type *type,
	uint32_t size,
	uint32_t *count,
	user_addr_t uaddr);

struct nxctl_traffic_rule_type {
	uint8_t ntrt_type;
	nxctl_traffic_rule_validate_cb_t *ntrt_validate;
	nxctl_traffic_rule_find_cb_t *ntrt_find;
	nxctl_traffic_rule_find_by_uuid_cb_t *ntrt_find_by_uuid;
	nxctl_traffic_rule_link_cb_t *ntrt_link;
	nxctl_traffic_rule_unlink_cb_t *ntrt_unlink;
	nxctl_traffic_rule_notify_cb_t *ntrt_notify;
	nxctl_traffic_rule_create_cb_t *ntrt_create;
	nxctl_traffic_rule_destroy_cb_t *ntrt_destroy;
	nxctl_traffic_rule_get_all_cb_t *ntrt_get_all;
	void *ntrt_storage;
};

static nxctl_traffic_rule_validate_cb_t inet_traffic_rule_validate;
static nxctl_traffic_rule_find_cb_t inet_traffic_rule_find;
static nxctl_traffic_rule_find_by_uuid_cb_t inet_traffic_rule_find_by_uuid;
static nxctl_traffic_rule_link_cb_t inet_traffic_rule_link;
static nxctl_traffic_rule_unlink_cb_t inet_traffic_rule_unlink;
static nxctl_traffic_rule_notify_cb_t inet_traffic_rule_notify;
static nxctl_traffic_rule_create_cb_t inet_traffic_rule_create;
static nxctl_traffic_rule_destroy_cb_t inet_traffic_rule_destroy;
static nxctl_traffic_rule_get_all_cb_t inet_traffic_rule_get_all;

static struct nxctl_traffic_rule_type nxctl_rule_types[] = {
	{
		.ntrt_type = IFNET_TRAFFIC_DESCRIPTOR_TYPE_INET,
		.ntrt_validate = inet_traffic_rule_validate,
		.ntrt_find = inet_traffic_rule_find,
		.ntrt_find_by_uuid = inet_traffic_rule_find_by_uuid,
		.ntrt_link = inet_traffic_rule_link,
		.ntrt_unlink = inet_traffic_rule_unlink,
		.ntrt_notify = inet_traffic_rule_notify,
		.ntrt_create = inet_traffic_rule_create,
		.ntrt_destroy = inet_traffic_rule_destroy,
		.ntrt_get_all = inet_traffic_rule_get_all,
	},
};
#define NRULETYPES \
    (sizeof(nxctl_rule_types)/sizeof(struct nxctl_traffic_rule_type))

/*
 * Generic traffic rule.
 * Contains fields common to all traffic rules.
 */
#define NTR_FLAG_PERSIST 0x0001
#define NTR_FLAG_ON_NXCTL_LIST 0x0002
struct nxctl_traffic_rule {
	struct nxctl_traffic_rule_type *ntr_type;
	uint32_t ntr_flags;
	os_refcnt_t ntr_refcnt;
	uuid_t ntr_uuid;
	char ntr_procname[NTR_PROCNAME_SZ];
	char ntr_ifname[IFNAMSIZ];
	SLIST_ENTRY(nxctl_traffic_rule) ntr_storage_link;
};

/*
 * Inet-specific traffic rule.
 */
struct nxctl_traffic_rule_inet {
	struct nxctl_traffic_rule ntri_common;
	SLIST_ENTRY(nxctl_traffic_rule_inet) ntri_storage_link;
	struct ifnet_traffic_descriptor_inet ntri_td;
	struct ifnet_traffic_rule_action_steer ntri_ra;
};

/*
 * Currently supported tuple types.
 */
static uint8_t nxctl_inet_traffic_rule_masks[] = {
	(IFNET_TRAFFIC_DESCRIPTOR_INET_IPVER |
	IFNET_TRAFFIC_DESCRIPTOR_INET_PROTO |
	IFNET_TRAFFIC_DESCRIPTOR_INET_LADDR |
	IFNET_TRAFFIC_DESCRIPTOR_INET_RADDR |
	IFNET_TRAFFIC_DESCRIPTOR_INET_LPORT |
	IFNET_TRAFFIC_DESCRIPTOR_INET_RPORT),

	(IFNET_TRAFFIC_DESCRIPTOR_INET_IPVER |
	IFNET_TRAFFIC_DESCRIPTOR_INET_PROTO |
	IFNET_TRAFFIC_DESCRIPTOR_INET_RADDR |
	IFNET_TRAFFIC_DESCRIPTOR_INET_RPORT),
};
#define NINETRULEMASKS \
    (sizeof(nxctl_inet_traffic_rule_masks)/sizeof(uint8_t))

/* Per-interface lists of traffic rules */
SLIST_HEAD(nxctl_traffic_rule_inet_head, nxctl_traffic_rule_inet);
struct nxctl_traffic_rule_inet_if {
	char rii_ifname[IFNAMSIZ];
	struct nxctl_traffic_rule_inet_head rii_lists[NINETRULEMASKS];
	uint32_t rii_count;
	SLIST_ENTRY(nxctl_traffic_rule_inet_if) rii_link;
};

/* List of per-interface lists */
SLIST_HEAD(nxctl_traffic_rule_inet_if_head, nxctl_traffic_rule_inet_if);
struct nxctl_traffic_rule_inet_storage {
	struct nxctl_traffic_rule_inet_if_head ris_if_list;
	uint32_t ris_count;
};

/* Per-fd list kept at the nxctl */
SLIST_HEAD(nxctl_traffic_rule_head, nxctl_traffic_rule);
struct nxctl_traffic_rule_storage {
	struct nxctl_traffic_rule_head rs_list;
	uint32_t rs_count;
};

static LCK_RW_DECLARE_ATTR(nxctl_traffic_rule_lock, &sk_lock_group, &sk_lock_attr);
#define NXTR_WLOCK() \
    lck_rw_lock_exclusive(&nxctl_traffic_rule_lock)
#define NXTR_WUNLOCK() \
    lck_rw_unlock_exclusive(&nxctl_traffic_rule_lock)
#define NXTR_RLOCK() \
    lck_rw_lock_shared(&nxctl_traffic_rule_lock)
#define NXTR_RUNLOCK() \
    lck_rw_unlock_shared(&nxctl_traffic_rule_lock)

static struct nxctl_traffic_rule_type *find_traffic_rule_type(uint8_t type);
static void retain_traffic_rule(struct nxctl_traffic_rule *ntr);
static void release_traffic_rule(struct nxctl_traffic_rule *ntr);
static int remove_traffic_rule(struct nxctl *nxctl, uuid_t uuid,
    struct nxctl_traffic_rule **ntrp);
static boolean_t inet_v6addr_cmp(struct ifnet_ip_addr *a1,
    struct ifnet_ip_addr *a2);
static int notify_traffic_rule(struct nxctl_traffic_rule *ntr, uint32_t flags);

#define NXCTL_TRAFFIC_RULE_TAG "com.apple.skywalk.nexus.traffic_rule"
static kern_allocation_name_t nxctl_traffic_rule_tag;
static struct nxctl_traffic_rule_type *inet_traffic_rule_type = NULL;

/*
 * If a interface attaches after rule(s) are added, this function is used
 * retrieve the current rule count for that interface.
 */
int
nxctl_inet_traffic_rule_get_count(const char *ifname, uint32_t *count)
{
	struct nxctl_traffic_rule_inet_storage *rs;
	struct nxctl_traffic_rule_inet_if *rif;
	int err;

	NXTR_RLOCK();
	rs = inet_traffic_rule_type->ntrt_storage;
	if (rs == NULL) {
		err = ENOENT;
		goto fail;
	}
	SLIST_FOREACH(rif, &rs->ris_if_list, rii_link) {
		if (strcmp(rif->rii_ifname, ifname) == 0) {
			break;
		}
	}
	if (rif == NULL) {
		err = ENOENT;
		goto fail;
	}
	*count = rif->rii_count;
	NXTR_RUNLOCK();
	return 0;
fail:
	NXTR_RUNLOCK();
	return err;
}

/*
 * Used for finding the qset id associated with a traffic descriptor.
 */
int
nxctl_inet_traffic_rule_find_qset_id(const char *ifname,
    struct ifnet_traffic_descriptor_inet *td, uint64_t *qset_id)
{
	struct nxctl_traffic_rule_inet *ntri = NULL;
	int err;

	NXTR_RLOCK();
	ASSERT(inet_traffic_rule_type != NULL);
	err = inet_traffic_rule_type->ntrt_find(inet_traffic_rule_type, ifname,
	    (struct ifnet_traffic_descriptor_common *)td, 0,
	    (struct nxctl_traffic_rule **)&ntri);
	if (err != 0) {
		SK_ERR("rule find failed: %d", err);
		goto fail;
	}
	*qset_id = ntri->ntri_ra.ras_qset_id;
	NXTR_RUNLOCK();
	return 0;
fail:
	NXTR_RUNLOCK();
	return err;
}

/*
 * Based on flow_pkt_classify().
 * This function populates struct ifnet_traffic_descriptor_inet instead of struct __flow.
 */
static int
fill_inet_td(struct __kern_packet *pkt, struct ifnet_traffic_descriptor_inet *td)
{
	union {
		volatile struct ip *_iph;
		volatile struct ip6_hdr *_ip6;
	} _l3;
	#define iph _l3._iph
	#define ip6 _l3._ip6
	union {
		volatile struct tcphdr *_tcph;
		volatile struct udphdr *_udph;
	} _l4;
	#define tcph _l4._tcph
	#define udph _l4._udph
	uint8_t *pkt_buf, *l3_hdr;
	uint16_t bdlen, bdlim, bdoff, cls_len;
	size_t pkt_len;
	uint8_t ipv, l3hlen = 0; /* IP header length */
	uint16_t l3tlen = 0;     /* total length of IP packet */
	uint8_t l4hlen = 0;      /* TCP/UDP header length */
	uint16_t ulen = 0;       /* user data length */
	int err;

	ASSERT(pkt->pkt_l2_len <= pkt->pkt_length);
	pkt_len = pkt->pkt_length - pkt->pkt_l2_len;

	MD_BUFLET_ADDR_ABS_DLEN(pkt, pkt_buf, bdlen, bdlim, bdoff);
	cls_len = bdlim - bdoff;
	cls_len -= pkt->pkt_l2_len;
	cls_len = (uint16_t)MIN(cls_len, pkt_len);
	VERIFY(pkt_len >= cls_len);
	if (cls_len == 0) {
		SK_ERR("cls_len == 0");
		err = EINVAL;
		goto fail;
	}
	l3_hdr = pkt_buf + pkt->pkt_headroom + pkt->pkt_l2_len;
	iph = (volatile struct ip *)(void *)l3_hdr;
	ipv = iph->ip_v;

	switch (ipv) {
	case 4:
		if (cls_len < sizeof(struct ip)) {
			SK_ERR("cls_len < sizeof(struct ip) (%d < %d)",
			    cls_len, sizeof(struct ip));
			err = EINVAL;
			goto fail;
		}
		l3hlen = (uint8_t)(iph->ip_hl << 2);
		if (l3hlen < sizeof(struct ip)) {
			SK_ERR("l3hlen < sizeof(struct ip) (%d < %d)",
			    l3hlen, sizeof(struct ip));
			err = EINVAL;
			goto fail;
		}
		if (cls_len < l3hlen) {
			SK_ERR("cls_len < l3hlen (%d < %d)", cls_len, l3hlen);
			err = EINVAL;
			goto fail;
		}
		l3tlen = ntohs(iph->ip_len);
		if (l3tlen < l3hlen) {
			SK_ERR("l3tlen < l3hlen (%d < %d)", l3tlen, l3hlen);
			err = EINVAL;
			goto fail;
		}
		if (pkt_len < l3tlen) {
			SK_ERR("pkt_len < l3tlen (%d < %d)", pkt_len, l3tlen);
			err = EINVAL;
			goto fail;
		}
		td->inet_ipver = IPVERSION;
		td->inet_proto = iph->ip_p;
		bcopy(__DECONST(void *, &iph->ip_src), &td->inet_laddr.iia_v4addr,
		    sizeof(iph->ip_src));
		bcopy(__DECONST(void *, &iph->ip_dst), &td->inet_raddr.iia_v4addr,
		    sizeof(iph->ip_dst));
		break;
	case 6:
		l3hlen = sizeof(struct ip6_hdr);
		if (cls_len < l3hlen) {
			SK_ERR("cls_len < l3hlen (%d < %d)", cls_len, l3hlen);
			err = EINVAL;
			goto fail;
		}
		l3tlen = l3hlen + ntohs(ip6->ip6_plen);
		if (pkt_len < l3tlen) {
			SK_ERR("pkt_len < l3tlen (%d < %d)", pkt_len, l3tlen);
			err = EINVAL;
			goto fail;
		}
		td->inet_ipver = IPV6_VERSION;
		td->inet_proto = ip6->ip6_nxt;
		bcopy(__DECONST(void *, &ip6->ip6_src), &td->inet_laddr,
		    sizeof(ip6->ip6_src));
		bcopy(__DECONST(void *, &ip6->ip6_dst), &td->inet_raddr,
		    sizeof(ip6->ip6_dst));
		break;
	default:
		SK_ERR("ipv == %d", ipv);
		err = EINVAL;
		goto fail;
	}
	tcph = __DECONST(volatile struct tcphdr *, (volatile uint8_t *)iph + l3hlen);
	ulen = (l3tlen - l3hlen);
	if (td->inet_proto == IPPROTO_TCP) {
		if (cls_len < l3hlen + sizeof(*tcph) || ulen < sizeof(*tcph)) {
			SK_ERR("cls_len < l3hlen + sizeof(*tcph) || ulen < sizeof(*tcph) "
			    "(%d < %d + %d || %d < %d)", cls_len, l3hlen, sizeof(*tcph),
			    ulen, sizeof(*tcph));
			err = EINVAL;
			goto fail;
		}
		l4hlen = (uint8_t)(tcph->th_off << 2);
		if (l4hlen < sizeof(*tcph)) {
			SK_ERR("l4hlen < sizeof(*tcph) (%d < %d)", l4hlen, sizeof(*tcph));
			err = EINVAL;
			goto fail;
		}
		if (l4hlen > ulen) {
			SK_ERR("l4hlen > ulen (%d > %d)", l4hlen, ulen);
			err = EINVAL;
			goto fail;
		}
		bcopy(__DECONST(void *, &tcph->th_sport), &td->inet_lport,
		    sizeof(td->inet_lport));
		bcopy(__DECONST(void *, &tcph->th_dport), &td->inet_rport,
		    sizeof(td->inet_rport));
	} else if (td->inet_proto == IPPROTO_UDP) {
		if (cls_len < l3hlen + sizeof(*udph) || ulen < sizeof(*udph)) {
			SK_ERR("cls_len < l3hlen + sizeof(*udph) || ulen < sizeof(*udph) "
			    "(%d < %d + %d || %d < %d)", cls_len, l3hlen, sizeof(*udph),
			    ulen, sizeof(*udph));
			err = EINVAL;
			goto fail;
		}
		l4hlen = sizeof(*udph);
		if (l4hlen > ulen) {
			SK_ERR("l4hlen > ulen (%d > %d)", l4hlen, ulen);
			err = EINVAL;
			goto fail;
		}
		bcopy(__DECONST(void *, &udph->uh_sport), &td->inet_lport,
		    sizeof(td->inet_lport));
		bcopy(__DECONST(void *, &udph->uh_dport), &td->inet_rport,
		    sizeof(td->inet_rport));
	} else {
		err = ENOTSUP;
		goto fail;
	}

	td->inet_common.itd_type = IFNET_TRAFFIC_DESCRIPTOR_TYPE_INET;
	td->inet_common.itd_len = sizeof(*td);
	td->inet_common.itd_flags = IFNET_TRAFFIC_DESCRIPTOR_FLAG_INBOUND |
	    IFNET_TRAFFIC_DESCRIPTOR_FLAG_OUTBOUND;
	td->inet_mask |= (IFNET_TRAFFIC_DESCRIPTOR_INET_IPVER |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_PROTO |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_LADDR |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_RADDR |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_LPORT |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_RPORT);
	return 0;
fail:
	DTRACE_SKYWALK5(classify__failed, struct ip *, iph, size_t, pkt_len,
	    uint8_t, pkt->pkt_l2_len, struct ifnet_traffic_descriptor_inet *, td,
	    int, err);
	bzero(td, sizeof(*td));
	return err;
	#undef iph
	#undef ip6
	#undef tcph
	#undef udph
}

int
nxctl_inet_traffic_rule_find_qset_id_with_pkt(const char *ifname,
    struct __kern_packet *pkt, uint64_t *qset_id)
{
	struct ifnet_traffic_descriptor_inet td;
	int err;

	err = fill_inet_td(pkt, &td);
	if (err != 0) {
		return err;
	}
	return nxctl_inet_traffic_rule_find_qset_id(ifname, &td, qset_id);
}

void
nxctl_traffic_rule_init(void)
{
	ASSERT(nxctl_traffic_rule_tag == NULL);
	nxctl_traffic_rule_tag =
	    kern_allocation_name_allocate(NXCTL_TRAFFIC_RULE_TAG, 0);
	ASSERT(nxctl_traffic_rule_tag != NULL);

	ASSERT(inet_traffic_rule_type == NULL);
	inet_traffic_rule_type =
	    find_traffic_rule_type(IFNET_TRAFFIC_DESCRIPTOR_TYPE_INET);
	ASSERT(inet_traffic_rule_type != NULL);
}

void
nxctl_traffic_rule_fini(void)
{
	if (nxctl_traffic_rule_tag != NULL) {
		kern_allocation_name_release(nxctl_traffic_rule_tag);
		nxctl_traffic_rule_tag = NULL;
	}
	inet_traffic_rule_type = NULL;
}

static struct ifnet_ip_addr v6_zeros_addr = {0};
static boolean_t
inet_v6addr_cmp(struct ifnet_ip_addr *a1, struct ifnet_ip_addr *a2)
{
	return memcmp(a1, a2, sizeof(*a1)) == 0;
}

SK_NO_INLINE_ATTRIBUTE
static struct nxctl_traffic_rule_storage *
nxctl_traffic_rule_storage_create(void)
{
	struct nxctl_traffic_rule_storage *rs;

	rs = sk_alloc_type(struct nxctl_traffic_rule_storage,
	    Z_WAITOK | Z_NOFAIL, nxctl_traffic_rule_tag);
	SLIST_INIT(&rs->rs_list);
	rs->rs_count = 0;
	return rs;
}

SK_NO_INLINE_ATTRIBUTE
static void
nxctl_traffic_rule_storage_destroy(struct nxctl_traffic_rule_storage *rs)
{
	ASSERT(rs->rs_count == 0);
	ASSERT(SLIST_EMPTY(&rs->rs_list));
	sk_free_type(struct nxctl_traffic_rule_storage, rs);
}

/*
 * This is meant to be called during closure of the nxctl's fd.
 * This will cleanup all rules linked to this nxctl. Rules that
 * are marked persistent won't be added to the nxctl list.
 */
void
nxctl_traffic_rule_clean(struct nxctl *nxctl)
{
	struct nxctl_traffic_rule_storage *rs;
	struct nxctl_traffic_rule *ntr, *next;
	int err;

	lck_mtx_lock(&nxctl->nxctl_lock);
	if ((rs = nxctl->nxctl_traffic_rule_storage) == NULL) {
		lck_mtx_unlock(&nxctl->nxctl_lock);
		return;
	}
	ntr = SLIST_FIRST(&rs->rs_list);
	SLIST_INIT(&rs->rs_list);
	rs->rs_count = 0;
	nxctl_traffic_rule_storage_destroy(rs);
	nxctl->nxctl_traffic_rule_storage = NULL;
	lck_mtx_unlock(&nxctl->nxctl_lock);

	while (ntr != NULL) {
		next = SLIST_NEXT(ntr, ntr_storage_link);
		/*
		 * Clearing the flag to tell remove_traffic_rule() not to
		 * remove from the nxctl list again.
		 */
		ntr->ntr_flags &= ~NTR_FLAG_ON_NXCTL_LIST;

		/* Passing NULL because we already hold a reference */
		err = remove_traffic_rule(nxctl, ntr->ntr_uuid, NULL);
		if (err == 0) {
			(void) notify_traffic_rule(ntr, NTR_NOTIFY_FLAG_REMOVE);
		}
		release_traffic_rule(ntr);
		ntr = next;
	}
}

SK_NO_INLINE_ATTRIBUTE
static void
add_traffic_rule_to_nxctl(struct nxctl *nxctl, struct nxctl_traffic_rule *ntr)
{
	struct nxctl_traffic_rule_storage *rs;

	lck_mtx_lock(&nxctl->nxctl_lock);
	if ((rs = nxctl->nxctl_traffic_rule_storage) == NULL) {
		rs = nxctl_traffic_rule_storage_create();
		nxctl->nxctl_traffic_rule_storage = rs;
	}
	ntr->ntr_flags |= NTR_FLAG_ON_NXCTL_LIST;
	retain_traffic_rule(ntr);
	SLIST_INSERT_HEAD(&rs->rs_list, ntr, ntr_storage_link);
	rs->rs_count++;
	lck_mtx_unlock(&nxctl->nxctl_lock);
}

SK_NO_INLINE_ATTRIBUTE
static void
remove_traffic_rule_from_nxctl(struct nxctl *nxctl,
    struct nxctl_traffic_rule *ntr)
{
	struct nxctl_traffic_rule_storage *rs;

	lck_mtx_lock(&nxctl->nxctl_lock);
	if ((ntr->ntr_flags & NTR_FLAG_ON_NXCTL_LIST) == 0) {
		lck_mtx_unlock(&nxctl->nxctl_lock);
		return;
	}
	rs = nxctl->nxctl_traffic_rule_storage;
	SLIST_REMOVE(&rs->rs_list, ntr, nxctl_traffic_rule, ntr_storage_link);
	rs->rs_count--;
	ntr->ntr_flags &= ~NTR_FLAG_ON_NXCTL_LIST;
	release_traffic_rule(ntr);
	if (rs->rs_count == 0) {
		nxctl_traffic_rule_storage_destroy(rs);
		nxctl->nxctl_traffic_rule_storage = NULL;
	}
	lck_mtx_unlock(&nxctl->nxctl_lock);
}

static int
inet_traffic_rule_validate(struct nxctl_traffic_rule_type *type,
    const char *ifname,
    struct ifnet_traffic_descriptor_common *td,
    struct ifnet_traffic_rule_action *ra)
{
#pragma unused(type)
	char buf[IFNAMSIZ];
	int unit, i;
	struct ifnet_traffic_descriptor_inet *tdi;
	uint8_t mask = 0, ipver, proto;

	if (ifunit_extract(ifname, buf, sizeof(buf), &unit) < 0) {
		SK_ERR("invalid ifname: %s", ifname);
		return EINVAL;
	}
	if (td->itd_len != sizeof(*tdi)) {
		SK_ERR("invalid td len: expected %d, actual %d",
		    sizeof(*tdi), td->itd_len);
		return EINVAL;
	}
	if (td->itd_flags == 0 ||
	    (td->itd_flags &
	    ~(IFNET_TRAFFIC_DESCRIPTOR_FLAG_INBOUND |
	    IFNET_TRAFFIC_DESCRIPTOR_FLAG_OUTBOUND)) != 0) {
		SK_ERR("invalid td flags: 0x%x", td->itd_flags);
		return EINVAL;
	}
	tdi = (struct ifnet_traffic_descriptor_inet *)td;
	for (i = 0; i < NINETRULEMASKS; i++) {
		if (tdi->inet_mask == nxctl_inet_traffic_rule_masks[i]) {
			mask = tdi->inet_mask;
			break;
		}
	}
	if (mask == 0) {
		SK_ERR("invalid inet mask: 0x%x", tdi->inet_mask);
		return EINVAL;
	}
	ipver = tdi->inet_ipver;
	if (ipver != IPVERSION && ipver != IPV6_VERSION) {
		SK_ERR("invalid inet ipver: 0x%x", ipver);
		return EINVAL;
	}
	proto = tdi->inet_proto;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		SK_ERR("invalid inet proto: %d", proto);
		return EINVAL;
	}
	if ((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_LADDR) != 0) {
		if (ipver == IPVERSION) {
			if (tdi->inet_laddr.iia_v4addr == INADDR_ANY) {
				SK_ERR("inet laddr v4 cannot be unspecified");
				return EINVAL;
			}
		} else {
			if (inet_v6addr_cmp(&tdi->inet_laddr, &v6_zeros_addr)) {
				SK_ERR("inet laddr v4 cannot be unspecified");
				return EINVAL;
			}
		}
	}
	if ((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_RADDR) != 0) {
		if (ipver == IPVERSION) {
			if (tdi->inet_raddr.iia_v4addr == INADDR_ANY) {
				SK_ERR("inet raddr v6 cannot be unspecified");
				return EINVAL;
			}
		} else {
			if (inet_v6addr_cmp(&tdi->inet_raddr, &v6_zeros_addr)) {
				SK_ERR("inet raddr v6 cannot be unspecified");
				return EINVAL;
			}
		}
	}
	if ((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_LPORT) != 0) {
		if (tdi->inet_lport == 0) {
			SK_ERR("inet lport cannot be unspecified");
			return EINVAL;
		}
	}
	if ((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_RPORT) != 0) {
		if (tdi->inet_rport == 0) {
			SK_ERR("inet rport cannot be unspecified");
			return EINVAL;
		}
	}
	if (ra->ra_len != sizeof(struct ifnet_traffic_rule_action_steer)) {
		SK_ERR("invalid ra len: expected %d, actual %d",
		    sizeof(struct ifnet_traffic_rule_action_steer), ra->ra_len);
		return EINVAL;
	}
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static struct nxctl_traffic_rule_inet_storage *
inet_traffic_rule_storage_create(void)
{
	struct nxctl_traffic_rule_inet_storage *rs;

	rs = sk_alloc_type(struct nxctl_traffic_rule_inet_storage,
	    Z_WAITOK | Z_NOFAIL, nxctl_traffic_rule_tag);
	SLIST_INIT(&rs->ris_if_list);
	rs->ris_count = 0;
	return rs;
}

SK_NO_INLINE_ATTRIBUTE
static void
inet_traffic_rule_storage_destroy(struct nxctl_traffic_rule_inet_storage *rs)
{
	ASSERT(rs->ris_count == 0);
	ASSERT(SLIST_EMPTY(&rs->ris_if_list));
	sk_free_type(struct nxctl_traffic_rule_inet_storage, rs);
}

SK_NO_INLINE_ATTRIBUTE
static struct nxctl_traffic_rule_inet_if *
inet_traffic_rule_if_create(const char *ifname)
{
	struct nxctl_traffic_rule_inet_if *rif;
	int i;

	rif = sk_alloc_type(struct nxctl_traffic_rule_inet_if,
	    Z_WAITOK | Z_NOFAIL, nxctl_traffic_rule_tag);
	for (i = 0; i < NINETRULEMASKS; i++) {
		SLIST_INIT(&rif->rii_lists[i]);
	}
	strlcpy(rif->rii_ifname, ifname, sizeof(rif->rii_ifname));
	rif->rii_count = 0;
	return rif;
}

SK_NO_INLINE_ATTRIBUTE
static void
inet_traffic_rule_if_destroy(struct nxctl_traffic_rule_inet_if *rif)
{
	int i;

	for (i = 0; i < NINETRULEMASKS; i++) {
		ASSERT(SLIST_EMPTY(&rif->rii_lists[i]));
	}
	ASSERT(rif->rii_count == 0);
	sk_free_type(struct nxctl_traffic_rule_inet_if, rif);
}

SK_NO_INLINE_ATTRIBUTE
static boolean_t
inet_traffic_rule_match(struct nxctl_traffic_rule_inet *ntri, const char *ifname,
    uint32_t flags, struct ifnet_traffic_descriptor_inet *tdi)
{
	struct nxctl_traffic_rule *ntr = (struct nxctl_traffic_rule *)ntri;
	struct ifnet_traffic_descriptor_inet *tdi0;
	uint8_t mask;
	boolean_t exact;

	VERIFY(strcmp(ntr->ntr_ifname, ifname) == 0);
	tdi0 = &ntri->ntri_td;

	exact = ((flags & NTR_FIND_FLAG_EXACT) != 0);
	mask = tdi0->inet_mask & tdi->inet_mask;
	if (exact) {
		ASSERT(tdi0->inet_mask == tdi->inet_mask);
	}
	ASSERT((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_IPVER) != 0);
	if (tdi0->inet_ipver != tdi->inet_ipver) {
		DTRACE_SKYWALK2(ipver__mismatch,
		    uint8_t, tdi0->inet_ipver, uint8_t, tdi->inet_ipver);
		return FALSE;
	}
	ASSERT((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_PROTO) != 0);
	if (tdi0->inet_proto != tdi->inet_proto) {
		DTRACE_SKYWALK2(proto__mismatch,
		    uint8_t, tdi0->inet_proto, uint8_t, tdi->inet_proto);
		return FALSE;
	}
	if (tdi0->inet_ipver == IPVERSION) {
		if ((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_LADDR) != 0 &&
		    tdi0->inet_laddr.iia_v4addr != tdi->inet_laddr.iia_v4addr) {
			DTRACE_SKYWALK2(v4laddr__mismatch,
			    in_addr_t, tdi0->inet_laddr.iia_v4addr,
			    in_addr_t, tdi->inet_laddr.iia_v4addr);
			return FALSE;
		}
		if ((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_RADDR) != 0 &&
		    tdi0->inet_raddr.iia_v4addr != tdi->inet_raddr.iia_v4addr) {
			DTRACE_SKYWALK2(v4raddr__mismatch,
			    in_addr_t, tdi0->inet_raddr.iia_v4addr,
			    in_addr_t, tdi->inet_raddr.iia_v4addr);
			return FALSE;
		}
	} else {
		ASSERT(tdi0->inet_ipver == IPV6_VERSION);
		if ((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_LADDR) != 0 &&
		    !inet_v6addr_cmp(&tdi0->inet_laddr, &tdi->inet_laddr)) {
			DTRACE_SKYWALK2(v6laddr__mismatch,
			    struct in6_addr *, &tdi0->inet_laddr,
			    struct in6_addr *, &tdi->inet_laddr);
			return FALSE;
		}
		if ((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_RADDR) != 0 &&
		    !inet_v6addr_cmp(&tdi0->inet_raddr, &tdi->inet_raddr)) {
			DTRACE_SKYWALK2(v6raddr__mismatch,
			    struct in6_addr *, &tdi0->inet_raddr,
			    struct in6_addr *, &tdi->inet_raddr);
			return FALSE;
		}
	}
	if ((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_LPORT) != 0 &&
	    tdi0->inet_lport != tdi->inet_lport) {
		DTRACE_SKYWALK2(lport__mismatch,
		    uint8_t, tdi0->inet_lport, uint8_t, tdi->inet_lport);
		return FALSE;
	}
	if ((mask & IFNET_TRAFFIC_DESCRIPTOR_INET_RPORT) != 0 &&
	    tdi0->inet_rport != tdi->inet_rport) {
		DTRACE_SKYWALK2(rport__mismatch,
		    uint8_t, tdi0->inet_rport, uint8_t, tdi->inet_rport);
		return FALSE;
	}
	return TRUE;
}

static int
inet_traffic_rule_find(struct nxctl_traffic_rule_type *type, const char *ifname,
    struct ifnet_traffic_descriptor_common *td, uint32_t flags,
    struct nxctl_traffic_rule **ntrp)
{
	struct nxctl_traffic_rule_inet *ntri = NULL;
	struct nxctl_traffic_rule_inet_storage *rs = type->ntrt_storage;
	struct nxctl_traffic_rule_inet_if *rif;
	struct ifnet_traffic_descriptor_inet *tdi =
	    (struct ifnet_traffic_descriptor_inet *)td;
	int i;

	if (rs == NULL) {
		return ENOENT;
	}
	SLIST_FOREACH(rif, &rs->ris_if_list, rii_link) {
		if (strcmp(rif->rii_ifname, ifname) != 0) {
			continue;
		}
		for (i = 0; i < NINETRULEMASKS; i++) {
			if ((flags & NTR_FIND_FLAG_EXACT) != 0 &&
			    tdi->inet_mask != nxctl_inet_traffic_rule_masks[i]) {
				continue;
			}
			SLIST_FOREACH(ntri, &rif->rii_lists[i], ntri_storage_link) {
				if (inet_traffic_rule_match(ntri, ifname, flags, tdi)) {
					*ntrp = (struct nxctl_traffic_rule *)ntri;
					return 0;
				}
			}
		}
	}
	return ENOENT;
}

static int
inet_traffic_rule_find_by_uuid(struct nxctl_traffic_rule_type *type,
    uuid_t uuid, struct nxctl_traffic_rule **ntrp)
{
	struct nxctl_traffic_rule_inet *ntri;
	struct nxctl_traffic_rule *ntr;
	struct nxctl_traffic_rule_inet_storage *rs = type->ntrt_storage;
	struct nxctl_traffic_rule_inet_if *rif;
	int i;

	if (rs == NULL) {
		return ENOENT;
	}
	SLIST_FOREACH(rif, &rs->ris_if_list, rii_link) {
		for (i = 0; i < NINETRULEMASKS; i++) {
			SLIST_FOREACH(ntri, &rif->rii_lists[i], ntri_storage_link) {
				ntr = &ntri->ntri_common;
				if (uuid_compare(ntr->ntr_uuid, uuid) == 0) {
					*ntrp = ntr;
					return 0;
				}
			}
		}
	}
	return ENOENT;
}

static void
inet_update_ifnet_traffic_rule_count(const char *ifname, uint32_t count)
{
	struct ifnet *ifp;

	ifp = ifunit_ref(ifname);
	if (ifp == NULL) {
		DTRACE_SKYWALK1(ifname__not__found, char *, ifname);
		return;
	}
	ifnet_update_traffic_rule_count(ifp, count);
	ifnet_decr_iorefcnt(ifp);
}

static void
inet_traffic_rule_link(struct nxctl_traffic_rule *ntr)
{
	struct nxctl_traffic_rule_type *type = ntr->ntr_type;
	struct nxctl_traffic_rule_inet_storage *rs;
	struct nxctl_traffic_rule_inet_if *rif;
	struct nxctl_traffic_rule_inet *ntri =
	    (struct nxctl_traffic_rule_inet *)ntr;
	struct nxctl_traffic_rule_inet_head *list = NULL;
	int i;

	if ((rs = type->ntrt_storage) == NULL) {
		rs = inet_traffic_rule_storage_create();
		type->ntrt_storage = rs;
	}
	SLIST_FOREACH(rif, &rs->ris_if_list, rii_link) {
		if (strcmp(rif->rii_ifname, ntr->ntr_ifname) == 0) {
			break;
		}
	}
	if (rif == NULL) {
		rif = inet_traffic_rule_if_create(ntr->ntr_ifname);
		SLIST_INSERT_HEAD(&rs->ris_if_list, rif, rii_link);
	}
	for (i = 0; i < NINETRULEMASKS; i++) {
		if (ntri->ntri_td.inet_mask ==
		    nxctl_inet_traffic_rule_masks[i]) {
			list = &rif->rii_lists[i];
			break;
		}
	}
	retain_traffic_rule(ntr);
	ASSERT(list != NULL);
	SLIST_INSERT_HEAD(list, ntri, ntri_storage_link);
	/* per-interface count */
	rif->rii_count++;
	inet_update_ifnet_traffic_rule_count(rif->rii_ifname, rif->rii_count);

	/* global count */
	rs->ris_count++;
}

static void
inet_traffic_rule_unlink(struct nxctl_traffic_rule *ntr)
{
	struct nxctl_traffic_rule_inet_storage *rs;
	struct nxctl_traffic_rule_inet_if *rif;
	struct nxctl_traffic_rule_inet *ntri =
	    (struct nxctl_traffic_rule_inet *)ntr;
	struct nxctl_traffic_rule_inet_head *list = NULL;
	struct nxctl_traffic_rule_type *type;
	int i;

	type = ntr->ntr_type;
	rs = type->ntrt_storage;
	ASSERT(rs != NULL);
	SLIST_FOREACH(rif, &rs->ris_if_list, rii_link) {
		if (strcmp(rif->rii_ifname, ntr->ntr_ifname) == 0) {
			break;
		}
	}
	ASSERT(rif != NULL);
	for (i = 0; i < NINETRULEMASKS; i++) {
		if (ntri->ntri_td.inet_mask ==
		    nxctl_inet_traffic_rule_masks[i]) {
			list = &rif->rii_lists[i];
			break;
		}
	}
	ASSERT(list != NULL);
	SLIST_REMOVE(list, ntri, nxctl_traffic_rule_inet, ntri_storage_link);
	rif->rii_count--;
	inet_update_ifnet_traffic_rule_count(rif->rii_ifname, rif->rii_count);

	rs->ris_count--;
	release_traffic_rule(ntr);

	if (rif->rii_count == 0) {
		SLIST_REMOVE(&rs->ris_if_list, rif, nxctl_traffic_rule_inet_if, rii_link);
		inet_traffic_rule_if_destroy(rif);
	}
	if (rs->ris_count == 0) {
		type->ntrt_storage = NULL;
		inet_traffic_rule_storage_destroy(rs);
	}
}

/*
 * XXX
 * This may need additional changes to ensure safety against detach/attach.
 * This is not an issue for the first consumer of llink interfaces, cellular,
 * which does not detach.
 */
static int
inet_traffic_rule_notify(struct nxctl_traffic_rule *ntr, uint32_t flags)
{
	struct ifnet *ifp;
	struct nx_netif *nif;
	struct netif_qset *qset = NULL;
	struct nxctl_traffic_rule_inet *ntri;
	int err = 0;

	ifp = ifunit_ref(ntr->ntr_ifname);
	if (ifp == NULL) {
		DTRACE_SKYWALK1(ifname__not__found, char *, ntr->ntr_ifname);
		err = ENXIO;
		goto done;
	}
	nif = NA(ifp)->nifna_netif;
	if (!NX_LLINK_PROV(nif->nif_nx)) {
		DTRACE_SKYWALK1(llink__not__enabled, struct ifnet *, ifp);
		err = ENOTSUP;
		goto done;
	}
	ntri = (struct nxctl_traffic_rule_inet *)ntr;
	qset = nx_netif_find_qset(nif, ntri->ntri_ra.ras_qset_id);
	err = nx_netif_notify_steering_info(nif, qset,
	    (struct ifnet_traffic_descriptor_common *)&ntri->ntri_td,
	    ((flags & NTR_NOTIFY_FLAG_ADD) != 0));
done:
	if (qset != NULL) {
		nx_netif_qset_release(&qset);
	}
	if (ifp != NULL) {
		ifnet_decr_iorefcnt(ifp);
	}
	return err;
}

static int
inet_traffic_rule_create(struct nxctl_traffic_rule_type *type,
    const char *ifname, struct ifnet_traffic_descriptor_common *td,
    struct ifnet_traffic_rule_action *ra, uint32_t flags,
    struct nxctl_traffic_rule **ntrp)
{
	struct nxctl_traffic_rule_inet *ntri;
	struct nxctl_traffic_rule *ntr;

	ntri = sk_alloc_type(struct nxctl_traffic_rule_inet,
	    Z_WAITOK | Z_NOFAIL, nxctl_traffic_rule_tag);
	ntr = &ntri->ntri_common;

	ntr->ntr_type = type;
	ntr->ntr_flags = flags;
	uuid_generate(ntr->ntr_uuid);
	os_ref_init(&ntr->ntr_refcnt, NULL);

	strlcpy(ntr->ntr_ifname, ifname, sizeof(ntr->ntr_ifname));
	proc_selfname(ntr->ntr_procname, sizeof(ntr->ntr_procname));
	bcopy(td, &ntri->ntri_td, sizeof(ntri->ntri_td));
	bcopy(ra, &ntri->ntri_ra, sizeof(ntri->ntri_ra));

	*ntrp = ntr;
	return 0;
}

static void
inet_traffic_rule_destroy(struct nxctl_traffic_rule *ntr)
{
	struct nxctl_traffic_rule_inet *ntri;

	ASSERT(os_ref_get_count(&ntr->ntr_refcnt) == 0);
	ntri = (struct nxctl_traffic_rule_inet *)ntr;
	sk_free_type(struct nxctl_traffic_rule_inet, ntri);
}

static void
convert_ntri_to_iocinfo(struct nxctl_traffic_rule_inet *ntri,
    struct nxctl_traffic_rule_inet_iocinfo *info)
{
	struct nxctl_traffic_rule *ntr;
	struct nxctl_traffic_rule_generic_iocinfo *ginfo;

	bzero(info, sizeof(*info));
	ntr = &ntri->ntri_common;
	ginfo = &info->tri_common;
	_CASSERT(sizeof(ntr->ntr_procname) == sizeof(ginfo->trg_procname));
	_CASSERT(sizeof(ntr->ntr_ifname) == sizeof(ginfo->trg_ifname));
	uuid_copy(ginfo->trg_uuid, ntr->ntr_uuid);
	strlcpy(ginfo->trg_procname, ntr->ntr_procname,
	    sizeof(ginfo->trg_procname));
	strlcpy(ginfo->trg_ifname, ntr->ntr_ifname,
	    sizeof(ginfo->trg_ifname));
	bcopy(&ntri->ntri_td, &info->tri_td, sizeof(info->tri_td));
	bcopy(&ntri->ntri_ra, &info->tri_ra, sizeof(info->tri_ra));
}

static int
inet_traffic_rule_get_all(struct nxctl_traffic_rule_type *type, uint32_t size,
    uint32_t *count, user_addr_t uaddr)
{
	struct nxctl_traffic_rule_inet *ntri = NULL;
	struct nxctl_traffic_rule_inet_storage *rs = type->ntrt_storage;
	struct nxctl_traffic_rule_inet_if *rif;
	struct nxctl_traffic_rule_inet_iocinfo info;
	int i, err;

	if (size != sizeof(info)) {
		SK_ERR("size: actual %d, expected %d", size, sizeof(info));
		return EINVAL;
	}
	if (rs == NULL) {
		*count = 0;
		return 0;
	}
	if (*count < rs->ris_count) {
		SK_ERR("count: given %d, require: %d", *count, rs->ris_count);
		return ENOBUFS;
	}
	SLIST_FOREACH(rif, &rs->ris_if_list, rii_link) {
		for (i = 0; i < NINETRULEMASKS; i++) {
			SLIST_FOREACH(ntri, &rif->rii_lists[i], ntri_storage_link) {
				convert_ntri_to_iocinfo(ntri, &info);
				err = copyout(&info, uaddr, sizeof(info));
				if (err != 0) {
					SK_ERR("copyout failed: %d", err);
					return err;
				}
				uaddr += sizeof(info);
			}
		}
	}
	*count = rs->ris_count;
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static void
retain_traffic_rule(struct nxctl_traffic_rule *ntr)
{
#if (DEVELOPMENT || DEBUG)
	os_ref_count_t count = os_ref_get_count(&ntr->ntr_refcnt);
	DTRACE_SKYWALK2(ntr__retain, struct nxctl_traffic_rule *, ntr,
	    os_ref_count_t, count);
#endif
	os_ref_retain(&ntr->ntr_refcnt);
}

SK_NO_INLINE_ATTRIBUTE
static void
release_traffic_rule(struct nxctl_traffic_rule *ntr)
{
#if (DEVELOPMENT || DEBUG)
	os_ref_count_t count = os_ref_get_count(&ntr->ntr_refcnt);
	DTRACE_SKYWALK2(ntr__release, struct nxctl_traffic_rule *, ntr,
	    os_ref_count_t, count);
#endif
	if (os_ref_release(&ntr->ntr_refcnt) == 0) {
		ntr->ntr_type->ntrt_destroy(ntr);
	}
}

SK_NO_INLINE_ATTRIBUTE
static int
notify_traffic_rule(struct nxctl_traffic_rule *ntr, uint32_t flags)
{
	return ntr->ntr_type->ntrt_notify(ntr, flags);
}

static void
link_traffic_rule(struct nxctl *nxctl, struct nxctl_traffic_rule *ntr)
{
	/*
	 * The persist flag means: do not clean up rule upon nxctl fd close.
	 * This means we only add the rule to the nxctl list if persist
	 * is not set.
	 */
	if ((ntr->ntr_flags & NTR_FLAG_PERSIST) == 0) {
		add_traffic_rule_to_nxctl(nxctl, ntr);
	}
	ntr->ntr_type->ntrt_link(ntr);
}

static void
unlink_traffic_rule(struct nxctl *nxctl, struct nxctl_traffic_rule *ntr)
{
	if ((ntr->ntr_flags & NTR_FLAG_PERSIST) == 0) {
		remove_traffic_rule_from_nxctl(nxctl, ntr);
	}
	ntr->ntr_type->ntrt_unlink(ntr);
}

static int
find_traffic_rule_by_uuid(uuid_t uuid, struct nxctl_traffic_rule **ntrp)
{
	int i, err;
	struct nxctl_traffic_rule_type *ntrt;
	struct nxctl_traffic_rule *ntr = NULL;

	for (i = 0; i < NRULETYPES; i++) {
		ntrt = &nxctl_rule_types[i];
		err = ntrt->ntrt_find_by_uuid(ntrt, uuid, &ntr);
		if (err == 0) {
			ASSERT(ntr != NULL);
			*ntrp = ntr;
			return 0;
		}
	}
	return ENOENT;
}

static struct nxctl_traffic_rule_type *
find_traffic_rule_type(uint8_t type)
{
	int i;
	struct nxctl_traffic_rule_type *ntrt;

	for (i = 0; i < NRULETYPES; i++) {
		ntrt = &nxctl_rule_types[i];
		if (ntrt->ntrt_type == type) {
			return ntrt;
		}
	}
	return NULL;
}

SK_NO_INLINE_ATTRIBUTE
static int
add_traffic_rule(struct nxctl *nxctl, const char *ifname,
    struct ifnet_traffic_descriptor_common *td,
    struct ifnet_traffic_rule_action *ra,
    uint32_t flags,
    struct nxctl_traffic_rule **ntrp)
{
	struct nxctl_traffic_rule_type *type = NULL;
	struct nxctl_traffic_rule *ntr = NULL;
	int err;

	NXTR_WLOCK();
	type = find_traffic_rule_type(td->itd_type);
	if (type == NULL) {
		SK_ERR("rule type %x not found", td->itd_type);
		err = EINVAL;
		goto fail;
	}
	err = type->ntrt_validate(type, ifname, td, ra);
	if (err != 0) {
		SK_ERR("rule validate failed: %d", err);
		goto fail;
	}
	err = type->ntrt_find(type, ifname, td, NTR_FIND_FLAG_EXACT, &ntr);
	if (err == 0) {
		SK_ERR("rule already exists");
		ASSERT(ntr != NULL);
		err = EEXIST;
		goto fail;
	} else if (err != ENOENT) {
		SK_ERR("rule find failed: %d", err);
		goto fail;
	}
	err = type->ntrt_create(type, ifname, td, ra, flags, &ntr);
	if (err != 0) {
		SK_ERR("rule create failed: %d", err);
		goto fail;
	}
	link_traffic_rule(nxctl, ntr);
	if (ntrp != NULL) {
		retain_traffic_rule(ntr);
		*ntrp = ntr;
	}
	NXTR_WUNLOCK();
	return 0;
fail:
	NXTR_WUNLOCK();
	return err;
}


SK_NO_INLINE_ATTRIBUTE
static int
remove_traffic_rule(struct nxctl *nxctl, uuid_t uuid,
    struct nxctl_traffic_rule **ntrp)
{
	struct nxctl_traffic_rule *ntr;
	int err;

	NXTR_WLOCK();
	err = find_traffic_rule_by_uuid(uuid, &ntr);
	if (err != 0) {
		SK_ERR("traffic rule not found");
		NXTR_WUNLOCK();
		return err;
	}
	if (ntrp != NULL) {
		retain_traffic_rule(ntr);
		*ntrp = ntr;
	}
	unlink_traffic_rule(nxctl, ntr);
	/* release initial reference */
	release_traffic_rule(ntr);
	NXTR_WUNLOCK();
	return 0;
}

static uint32_t
convert_traffic_rule_ioc_flags(uint32_t flags)
{
	uint32_t f = 0;

	if ((flags & NXIOC_ADD_TRAFFIC_RULE_FLAG_PERSIST) != 0) {
		f |= NTR_FLAG_PERSIST;
	}
	return f;
}

SK_NO_INLINE_ATTRIBUTE
static int
add_traffic_rule_generic(struct nxctl *nxctl, const char *ifname,
    struct ifnet_traffic_descriptor_common *td,
    struct ifnet_traffic_rule_action *ra, uint32_t flags, uuid_t *uuid)
{
	struct nxctl_traffic_rule *ntr;
	int err;

	err = add_traffic_rule(nxctl, ifname, td, ra, flags, &ntr);
	if (err != 0) {
		return err;
	}
	(void) notify_traffic_rule(ntr, NTR_NOTIFY_FLAG_ADD);
	uuid_copy(*uuid, ntr->ntr_uuid);
	release_traffic_rule(ntr);
	return 0;
}

int
nxioctl_add_traffic_rule_inet(struct nxctl *nxctl, caddr_t data, proc_t procp)
{
#pragma unused(procp)
	struct nxctl_add_traffic_rule_inet_iocargs *args =
	    (struct nxctl_add_traffic_rule_inet_iocargs *)(void *)data;

	return add_traffic_rule_generic(nxctl, args->atri_ifname,
	           (struct ifnet_traffic_descriptor_common *)&args->atri_td,
	           (struct ifnet_traffic_rule_action *)&args->atri_ra,
	           convert_traffic_rule_ioc_flags(args->atri_flags),
	           &args->atri_uuid);
}

int
nxioctl_remove_traffic_rule(struct nxctl *nxctl, caddr_t data, proc_t procp)
{
#pragma unused(procp)
	struct nxctl_remove_traffic_rule_iocargs *args =
	    (struct nxctl_remove_traffic_rule_iocargs *)(void *)data;
	struct nxctl_traffic_rule *ntr;
	int err;

	err = remove_traffic_rule(nxctl, args->rtr_uuid, &ntr);
	if (err != 0) {
		return err;
	}
	(void) notify_traffic_rule(ntr, NTR_NOTIFY_FLAG_REMOVE);
	release_traffic_rule(ntr);
	return 0;
}

int
nxioctl_get_traffic_rules(struct nxctl *nxctl, caddr_t data, proc_t procp)
{
#pragma unused(nxctl)
	struct nxctl_get_traffic_rules_iocargs *args =
	    (struct nxctl_get_traffic_rules_iocargs *)(void *)data;
	struct nxctl_traffic_rule_type *type;
	user_addr_t uaddr;
	int err;

	NXTR_RLOCK();
	type = find_traffic_rule_type(args->gtr_type);
	if (type == NULL) {
		SK_ERR("rule type %x not found", args->gtr_type);
		err = EINVAL;
		goto fail;
	}
	uaddr = proc_is64bit(procp) ? args->gtr_buf64 :
	    CAST_USER_ADDR_T(args->gtr_buf);
	err = type->ntrt_get_all(type, args->gtr_size, &args->gtr_count, uaddr);
	if (err != 0) {
		goto fail;
	}
	NXTR_RUNLOCK();
	return 0;
fail:
	NXTR_RUNLOCK();
	return err;
}
