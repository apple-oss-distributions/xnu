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

#include <kern/assert.h>
#include <kern/locks.h>
#include <kern/zalloc.h>
#include <libkern/tree.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/bitstring.h>
#include <net/if.h>
#include <net/kpi_interface.h>
#include <net/restricted_in_port.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_var.h>

#include <netinet6/in6_var.h>
#include <string.h>

#include <skywalk/os_skywalk.h>
#include <skywalk/os_skywalk_private.h>
#include <skywalk/os_stats_private.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>

#include <net/if_ports_used.h>

static int __netns_inited = 0;

/*
 * Logging
 */

#define NS_VERB_PROTO(proto)    ((proto == IPPROTO_TCP) ? SK_VERB_NS_TCP : \
	                                    SK_VERB_NS_UDP)
#define NS_VERB_IP(addr_len)    ((addr_len == sizeof (struct in_addr)) ? \
	                                    SK_VERB_NS_IPV4 : SK_VERB_NS_IPV6)
#define PROTO_STR(proto)        ((proto == IPPROTO_TCP) ? "tcp" : "udp")
#define LEN_TO_AF(len)          (((len == sizeof (struct in_addr)) ? \
	                            AF_INET : AF_INET6))
/*
 * Locking
 * Netns is currently protected by a global mutex, NETNS_LOCK. This lock is
 * aquired at the entry of every kernel-facing function, and released at the
 * end. Data within netns_token structures is also protected under this lock.
 */

#define NETNS_LOCK()                    \
	lck_mtx_lock(&netns_lock)
#define NETNS_LOCK_SPIN()               \
	lck_mtx_lock_spin(&netns_lock)
#define NETNS_LOCK_CONVERT() do {       \
	NETNS_LOCK_ASSERT_HELD();       \
	lck_mtx_convert_spin(&netns_lock); \
} while (0)
#define NETNS_UNLOCK()                  \
	lck_mtx_unlock(&netns_lock)
#define NETNS_LOCK_ASSERT_HELD()        \
	LCK_MTX_ASSERT(&netns_lock, LCK_MTX_ASSERT_OWNED)
#define NETNS_LOCK_ASSERT_NOTHELD()     \
	LCK_MTX_ASSERT(&netns_lock, LCK_MTX_ASSERT_NOTOWNED)

static LCK_GRP_DECLARE(netns_lock_group, "netns_lock");
static LCK_MTX_DECLARE(netns_lock, &netns_lock_group);

/*
 * Internal data structures and parameters
 */

/*
 * Local ports are kept track of by reference counts kept in a tree specific to
 * an <IP, protocol> tuple (see struct ns).
 *
 * Note: port numbers are stored in host byte order.
 */
struct ns_reservation {
	RB_ENTRY(ns_reservation) nsr_link;
	in_port_t nsr_port;
	uint32_t nsr_refs[NETNS_OWNER_MAX + 1];
};

#define NETNS_REF_COUNT(nsr, flags)     \
	(nsr)->nsr_refs[((flags) & NETNS_OWNER_MASK)]

static inline int nsr_cmp(const struct ns_reservation *,
    const struct ns_reservation *);

RB_HEAD(ns_reservation_tree, ns_reservation);
RB_PROTOTYPE(ns_reservation_tree, ns_reservation, nsr_link, nsr_cmp);
RB_GENERATE(ns_reservation_tree, ns_reservation, nsr_link, nsr_cmp);

static inline struct ns_reservation *ns_reservation_tree_find(
	struct ns_reservation_tree *, const in_port_t);

/*
 * A namespace keeps track of the local port numbers in use for a given
 * <IP, protocol> tuple. There are also global namespaces for each
 * protocol to accomodate INADDR_ANY behavior and diagnostics.
 */
struct ns {
	RB_ENTRY(ns)    ns_link;

	void            *ns_addr_key;

	union {
		uint32_t        ns_addr[4];
		struct in_addr  ns_inaddr;
		struct in6_addr ns_in6addr;
	};
	uint8_t         ns_addr_len;
	uint8_t         ns_proto;

	in_port_t       ns_last_ephemeral_port_down;
	in_port_t       ns_last_ephemeral_port_up;

	uint8_t         ns_is_freeable;

	uint32_t        ns_n_reservations;
	struct ns_reservation_tree ns_reservations;
};

static uint32_t netns_n_namespaces;

static inline int ns_cmp(const struct ns *, const struct ns *);

RB_HEAD(netns_namespaces_tree, ns) netns_namespaces =
    RB_INITIALIZER(netns_namespaces);
RB_PROTOTYPE_PREV(netns_namespaces_tree, ns, ns_link, ns_cmp);
RB_GENERATE_PREV(netns_namespaces_tree, ns, ns_link, ns_cmp);

/*
 * Declare pointers to global namespaces for each protocol.
 * All non-wildcard reservations will have an entry here.
 */
#define NETNS_N_GLOBAL  4
static struct ns *netns_global_non_wild[NETNS_N_GLOBAL];
static struct ns *netns_global_wild[NETNS_N_GLOBAL];
#define NETNS_NS_TCP    0
#define NETNS_NS_UDP    1
#define NETNS_NS_V4     0
#define NETNS_NS_V6     2
#define NETNS_NS_GLOBAL_IDX(proto, addrlen)     \
	((((proto) == IPPROTO_TCP) ? NETNS_NS_TCP : NETNS_NS_UDP) | \
	(((addrlen) == sizeof (struct in_addr)) ? NETNS_NS_V4 : NETNS_NS_V6))

#define NETNS_NS_UDP_EPHEMERAL_RESERVE  4096

/*
 * Internal token structure
 *
 * Note: port numbers are stored in host byte order.
 */
struct ns_token {
	/* Reservation state */
	ifnet_t                 nt_ifp;
	SLIST_ENTRY(ns_token)   nt_ifp_link;
	SLIST_ENTRY(ns_token)   nt_all_link;
	uint32_t                nt_state;       /* NETNS_STATE_* */

	/* Reservation context */
	union {
		uint32_t        nt_addr[4];
		struct in_addr  nt_inaddr;
		struct in6_addr nt_in6addr;
	};
	uint8_t                 nt_addr_len;
	uint8_t                 nt_proto;
	in_port_t               nt_port;
	uint32_t                nt_flags;

	/* Optional information about the flow */
	struct ns_flow_info     *nt_flow_info;
};

/* Valid values for nt_state */
#define NETNS_STATE_HALFCLOSED  0x1     /* half closed */
#define NETNS_STATE_WITHDRAWN   0x2     /* withdrawn; not offloadable */

#define NETNS_STATE_BITS        "\020\01HALFCLOSED\02WITHDRAWN"

/* List of tokens not bound to an ifnet */
SLIST_HEAD(, ns_token) netns_unbound_tokens = SLIST_HEAD_INITIALIZER(
	netns_unbound_tokens);

/* List of all tokens currently allocated in the system */
SLIST_HEAD(, ns_token) netns_all_tokens = SLIST_HEAD_INITIALIZER(
	netns_all_tokens);

/*
 * Memory management
 */
static ZONE_DEFINE(netns_ns_zone, SKMEM_ZONE_PREFIX ".netns.ns",
    sizeof(struct ns), ZC_ZFREE_CLEARMEM);

#define NETNS_NS_TOKEN_ZONE_NAME        "netns.ns_token"
static unsigned int netns_ns_token_size; /* size of zone element */
static struct skmem_cache *netns_ns_token_cache; /* for ns_token */

#define NETNS_NS_FLOW_INFO_ZONE_NAME    "netns.ns_flow_info"
static unsigned int netns_ns_flow_info_size; /* size of zone element */
static struct skmem_cache *netns_ns_flow_info_cache; /* for ns_flow_info */

#define NETNS_NS_RESERVATION_ZONE_NAME  "netns.ns_reservation"
static unsigned int netns_ns_reservation_size; /* size of zone element */
static struct skmem_cache *netns_ns_reservation_cache; /* for ns_reservation */

static struct ns_reservation *netns_ns_reservation_alloc(boolean_t, in_port_t);
static void netns_ns_reservation_free(struct ns_reservation *);
static struct ns *netns_ns_alloc(zalloc_flags_t);
static void netns_ns_free(struct ns *);
static void netns_ns_cleanup(struct ns *);
static struct ns_token *netns_ns_token_alloc(boolean_t, boolean_t);
static void netns_ns_token_free(struct ns_token *);

/*
 * Utility/internal code
 */
static struct ns *_netns_get_ns(uint32_t *, uint8_t, uint8_t, bool);
static inline boolean_t _netns_is_wildcard_addr(const uint32_t *, uint8_t);
static int _netns_reserve_common(struct ns *, in_port_t, uint32_t);
static void _netns_release_common(struct ns *, in_port_t, uint32_t);
static inline void netns_clear_ifnet(struct ns_token *);
static int _netns_reserve_kpi_common(struct ns *, netns_token *, uint32_t *,
    uint8_t, uint8_t, in_port_t *, uint32_t, struct ns_flow_info *);
static void _netns_set_ifnet_internal(struct ns_token *, struct ifnet *);

static struct ns_reservation *
netns_ns_reservation_alloc(boolean_t can_block, in_port_t port)
{
	struct ns_reservation *res;

	VERIFY(port != 0);

	res = skmem_cache_alloc(netns_ns_reservation_cache,
	    can_block ? SKMEM_SLEEP : SKMEM_NOSLEEP);
	if (res == NULL) {
		return NULL;
	}

	bzero(res, netns_ns_reservation_size);
	res->nsr_port = port;
	return res;
}

static void
netns_ns_reservation_free(struct ns_reservation *res)
{
	skmem_cache_free(netns_ns_reservation_cache, res);
}

static struct ns *
netns_ns_alloc(zalloc_flags_t how)
{
	struct ns *namespace;
	in_port_t first = (in_port_t)ipport_firstauto;
	in_port_t last  = (in_port_t)ipport_lastauto;
	in_port_t rand_port;

	namespace = zalloc_flags(netns_ns_zone, how | Z_ZERO);
	if (namespace == NULL) {
		return NULL;
	}

	namespace->ns_is_freeable = 1;

	RB_INIT(&namespace->ns_reservations);

	/*
	 * Randomize the initial ephemeral port starting point, just in case
	 * this namespace is for an ipv6 address which gets brought up and
	 * down often.
	 */
	if (first == last) {
		rand_port = first;
	} else {
		read_frandom(&rand_port, sizeof(rand_port));

		if (first > last) {
			rand_port = last + (rand_port % (first - last));
		} else {
			rand_port = first + (rand_port % (last - first));
		}
	}
	namespace->ns_last_ephemeral_port_down = rand_port;
	namespace->ns_last_ephemeral_port_up = rand_port;

	return namespace;
}

static void
netns_ns_free(struct ns *namespace)
{
	struct ns_reservation *res;
	struct ns_reservation *tmp_res;
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	SK_DF(NS_VERB_IP(namespace->ns_addr_len) |
	    NS_VERB_PROTO(namespace->ns_proto),
	    "freeing %s ns for IP %s",
	    PROTO_STR(namespace->ns_proto),
	    inet_ntop(LEN_TO_AF(namespace->ns_addr_len),
	    namespace->ns_addr, tmp_ip_str, sizeof(tmp_ip_str)));

	RB_FOREACH_SAFE(res, ns_reservation_tree, &namespace->ns_reservations,
	    tmp_res) {
		netns_ns_reservation_free(res);
		namespace->ns_n_reservations--;
		RB_REMOVE(ns_reservation_tree, &namespace->ns_reservations,
		    res);
	}

	VERIFY(RB_EMPTY(&namespace->ns_reservations));

	if (netns_global_wild[NETNS_NS_GLOBAL_IDX(namespace->ns_proto,
	    namespace->ns_addr_len)] == namespace) {
		netns_global_wild[NETNS_NS_GLOBAL_IDX(namespace->ns_proto,
		namespace->ns_addr_len)] = NULL;
	}
	if (netns_global_non_wild[NETNS_NS_GLOBAL_IDX(namespace->ns_proto,
	    namespace->ns_addr_len)] == namespace) {
		netns_global_non_wild[NETNS_NS_GLOBAL_IDX(namespace->ns_proto,
		namespace->ns_addr_len)] = NULL;
	}

	zfree(netns_ns_zone, namespace);
}

static void
netns_ns_cleanup(struct ns *namespace)
{
	if (namespace->ns_is_freeable &&
	    RB_EMPTY(&namespace->ns_reservations)) {
		RB_REMOVE(netns_namespaces_tree, &netns_namespaces, namespace);
		netns_n_namespaces--;
		netns_ns_free(namespace);
	}
}

static struct ns_token *
netns_ns_token_alloc(boolean_t can_block, boolean_t with_nfi)
{
	struct ns_token *token;

	NETNS_LOCK_ASSERT_HELD();
	NETNS_LOCK_CONVERT();

	token = skmem_cache_alloc(netns_ns_token_cache,
	    can_block ? SKMEM_SLEEP : SKMEM_NOSLEEP);
	if (token == NULL) {
		return NULL;
	}

	bzero(token, netns_ns_token_size);

	if (with_nfi) {
		token->nt_flow_info =  skmem_cache_alloc(netns_ns_flow_info_cache,
		    can_block ? SKMEM_SLEEP : SKMEM_NOSLEEP);
		if (token->nt_flow_info == NULL) {
			skmem_cache_free(netns_ns_token_cache, token);
			return NULL;
		}
	}
	SLIST_INSERT_HEAD(&netns_all_tokens, token, nt_all_link);

	return token;
}

static void
netns_ns_token_free(struct ns_token *token)
{
	NETNS_LOCK_ASSERT_HELD();
	NETNS_LOCK_CONVERT();
	SLIST_REMOVE(&netns_all_tokens, token, ns_token, nt_all_link);

	if (token->nt_flow_info != NULL) {
		skmem_cache_free(netns_ns_flow_info_cache, token->nt_flow_info);
	}
	skmem_cache_free(netns_ns_token_cache, token);
}

__attribute__((always_inline))
static inline int
nsr_cmp(const struct ns_reservation *nsr1, const struct ns_reservation *nsr2)
{
#define NSR_COMPARE(r1, r2)     ((int)(r1)->nsr_port - (int)(r2)->nsr_port)
	return NSR_COMPARE(nsr1, nsr2);
}

__attribute__((always_inline))
static inline int
ns_cmp(const struct ns *a, const struct ns *b)
{
	int d;

	if ((d = (a->ns_addr_len - b->ns_addr_len)) != 0) {
		return d;
	}
	if ((d = (a->ns_proto - b->ns_proto)) != 0) {
		return d;
	}
	if ((d = flow_ip_cmp(a->ns_addr_key, b->ns_addr_key,
	    b->ns_addr_len)) != 0) {
		return d;
	}

	return 0;
}

/*
 * Common routine to look up a reservation.
 *
 * NOTE: Assumes the caller holds the NETNS global lock
 */
__attribute__((always_inline))
static inline struct ns_reservation *
ns_reservation_tree_find(struct ns_reservation_tree *tree, const in_port_t port)
{
	struct ns_reservation res;
	res.nsr_port = port;
	return RB_FIND(ns_reservation_tree, tree, &res);
}

/*
 * Retrieve the namespace for the supplied <address, protocol> tuple.
 * If create is set and such a namespace doesn't already exist, one will be
 * created.
 */
static struct ns *
_netns_get_ns(uint32_t *addr, uint8_t addr_len, uint8_t proto, bool create)
{
	struct ns *namespace = NULL;
	struct ns find = {
		.ns_addr_key = addr,
		.ns_addr_len = addr_len,
		.ns_proto = proto,
	};
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	VERIFY(addr_len == sizeof(struct in_addr) ||
	    addr_len == sizeof(struct in6_addr));

	NETNS_LOCK_ASSERT_HELD();

	namespace = RB_FIND(netns_namespaces_tree, &netns_namespaces, &find);

	if (create && namespace == NULL) {
		SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
		    "allocating %s ns for IP %s",
		    PROTO_STR(proto), inet_ntop(LEN_TO_AF(addr_len), addr,
		    tmp_ip_str, sizeof(tmp_ip_str)));
		NETNS_LOCK_CONVERT();
		namespace = netns_ns_alloc(Z_WAITOK | Z_NOFAIL);
		__builtin_assume(namespace != NULL);
		memcpy(namespace->ns_addr, addr, addr_len);
		namespace->ns_addr_key = &namespace->ns_addr;
		namespace->ns_addr_len = addr_len;
		namespace->ns_proto = proto;
		RB_INSERT(netns_namespaces_tree, &netns_namespaces, namespace);
		netns_n_namespaces++;

		if (_netns_is_wildcard_addr(addr, addr_len) &&
		    netns_global_wild[NETNS_NS_GLOBAL_IDX(proto,
		    addr_len)] == NULL) {
			netns_global_wild[NETNS_NS_GLOBAL_IDX(proto,
			addr_len)] = namespace;
		}
	}

	return namespace;
}

/*
 * Return true if the supplied address is a wildcard (INADDR_ANY)
 */
__attribute__((always_inline))
static boolean_t
_netns_is_wildcard_addr(const uint32_t *addr, uint8_t addr_len)
{
	boolean_t wildcard;

	switch (addr_len) {
	case sizeof(struct in_addr):
		wildcard = (addr[0] == 0);
		break;

	case sizeof(struct in6_addr):
		wildcard = (addr[0] == 0 && addr[1] == 0 &&
		    addr[2] == 0 && addr[3] == 0);
		break;

	default:
		wildcard = FALSE;
		break;
	}

	return wildcard;
}

__attribute__((always_inline))
static boolean_t
_netns_is_port_used(struct ns * gns, struct ns_reservation *curr_res, in_port_t port)
{
	struct ns_reservation *res = NULL;

	if (gns == NULL) {
		return FALSE;
	}

	res = ns_reservation_tree_find(&gns->ns_reservations, port);
	if (res != NULL && res != curr_res) {
		if (NETNS_REF_COUNT(res, NETNS_BSD) > 0 ||
		    NETNS_REF_COUNT(res, NETNS_PF) > 0 ||
		    NETNS_REF_COUNT(res, NETNS_LISTENER) > 0 ||
		    NETNS_REF_COUNT(res, NETNS_SKYWALK) > 0) {
			return TRUE;
		}
	}

	return FALSE;
}

/*
 * Internal shared code to reserve ports within a specific namespace.
 *
 * Note: port numbers are in host byte-order here.
 */
static int
_netns_reserve_common(struct ns *namespace, in_port_t port, uint32_t flags)
{
	struct ns_reservation *res = NULL, *exist = NULL;
	uint8_t proto, addr_len;
	int err = 0;
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	VERIFY(port != 0);
	proto = namespace->ns_proto;
	addr_len = namespace->ns_addr_len;
	NETNS_LOCK_CONVERT();
	res = netns_ns_reservation_alloc(TRUE, port);
	if (res == NULL) {
		SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
		    "ERROR %s:%s:%d // flags 0x%x // OUT OF MEMORY",
		    inet_ntop(LEN_TO_AF(namespace->ns_addr_len),
		    namespace->ns_addr, tmp_ip_str,
		    sizeof(tmp_ip_str)), PROTO_STR(proto), port, flags);
		return ENOMEM;
	}
	exist = RB_INSERT(ns_reservation_tree, &namespace->ns_reservations,
	    res);
	if (__probable(exist == NULL)) {
		namespace->ns_n_reservations++;
	} else {
		netns_ns_reservation_free(res);
		res = exist;
	}

	SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
	    "pre: %s:%s:%d // flags 0x%x // refs %d sky, %d ls, "
	    "%d bsd %d pf", inet_ntop(LEN_TO_AF(namespace->ns_addr_len),
	    namespace->ns_addr, tmp_ip_str, sizeof(tmp_ip_str)),
	    PROTO_STR(proto), port, flags,
	    NETNS_REF_COUNT(res, NETNS_SKYWALK),
	    NETNS_REF_COUNT(res, NETNS_LISTENER),
	    NETNS_REF_COUNT(res, NETNS_BSD),
	    NETNS_REF_COUNT(res, NETNS_PF));

	/* Make reservation */
	/*
	 * Bypass collision detection for reservations in the global non-wild
	 * namespace. We use that namespace for reference counts only.
	 */
	if (namespace !=
	    netns_global_non_wild[NETNS_NS_GLOBAL_IDX(proto, addr_len)]) {
		struct ns_reservation *skres;
		boolean_t is_wild = _netns_is_wildcard_addr(namespace->ns_addr,
		    addr_len);
		struct ns *gns =
		    netns_global_wild[NETNS_NS_GLOBAL_IDX(proto, addr_len)];

		if (NETNS_IS_SKYWALK(flags)) {
			if ((!is_wild || exist != NULL) && gns != NULL &&
			    (skres = ns_reservation_tree_find(
				    &gns->ns_reservations, port)) != NULL &&
			    NETNS_REF_COUNT(skres, NETNS_LISTENER) == 0) {
				/*
				 * The mere existence of any non-skywalk
				 * listener wildcard entry for this
				 * protocol/port number means this must fail.
				 */
				SK_DF(NS_VERB_IP(addr_len) |
				    NS_VERB_PROTO(proto),
				    "ADDRINUSE: Duplicate wildcard");
				err = EADDRINUSE;
				goto done;
			}

			if (is_wild) {
				gns = netns_global_non_wild[
					NETNS_NS_GLOBAL_IDX(proto, addr_len)];
				VERIFY(gns != NULL);

				if (ns_reservation_tree_find(
					    &gns->ns_reservations, port) != NULL) {
					/*
					 * If Skywalk is trying to reserve a
					 * wildcard, then the mere existance of
					 * any entry in the non-wild namespace
					 * for this port means this must fail.
					 */
					SK_DF(NS_VERB_IP(addr_len) |
					    NS_VERB_PROTO(proto), "ADDRINUSE: "
					    "Wildcard with non-wild.");
					err = EADDRINUSE;
					goto done;
				}
			}
		} else {
			/*
			 * Check if Skywalk has reserved a wildcard entry.
			 * Note that the arithmetic OR here is intentional.
			 */
			if ((!is_wild || exist != NULL) && gns != NULL &&
			    (skres = ns_reservation_tree_find(
				    &gns->ns_reservations, port)) != NULL &&
			    (NETNS_REF_COUNT(skres, NETNS_SKYWALK) |
			    NETNS_REF_COUNT(skres, NETNS_LISTENER)) != 0) {
				/*
				 * BSD is trying to reserve a proto/port for
				 * which Skywalk already has a wildcard
				 * reservation.
				 */
				SK_DF(NS_VERB_IP(addr_len) |
				    NS_VERB_PROTO(proto),
				    "ADDRINUSE: BSD requesting Skywalk port");
				err = EADDRINUSE;
				goto done;
			}

			/*
			 * If BSD is trying to reserve a wildcard,
			 * ensure Skywalk has not already reserved
			 * a non-wildcard.
			 */
			if (is_wild) {
				gns = netns_global_non_wild[
					NETNS_NS_GLOBAL_IDX(proto, addr_len)];
				VERIFY(gns != NULL);

				/*
				 * Note that the arithmetic OR here is
				 * intentional.
				 */
				if ((skres = ns_reservation_tree_find(
					    &gns->ns_reservations, port)) != NULL &&
				    (NETNS_REF_COUNT(skres, NETNS_SKYWALK) |
				    NETNS_REF_COUNT(skres,
				    NETNS_LISTENER)) != 0) {
					SK_DF(NS_VERB_IP(addr_len) |
					    NS_VERB_PROTO(proto), "ADDRINUSE: "
					    "BSD wildcard with non-wild.");
					err = EADDRINUSE;
					goto done;
				}
			}
		}

		switch (flags & NETNS_OWNER_MASK) {
		case NETNS_SKYWALK:
			/* check collision w/ BSD */
			if (NETNS_REF_COUNT(res, NETNS_BSD) > 0 ||
			    NETNS_REF_COUNT(res, NETNS_PF) > 0) {
				SK_DF(NS_VERB_IP(addr_len) |
				    NS_VERB_PROTO(proto),
				    "ERROR - Skywalk got ADDRINUSE (w/ BSD)");
				err = EADDRINUSE;
				goto done;
			}

			/* BEGIN CSTYLED */
			/*
			 * Scenarios with new Skywalk connected flow:
			 * 1. With existing Skywalk connected flow,
			 *      NETNS_REF_COUNT(res, NETNS_LISTENER) == 0 &&
			 *      NETNS_REF_COUNT(res, NETNS_SKYWALK) == 1
			 *    reject by failing the wild gns lookup below.
			 * 2. With existing Skywalk 3-tuple listener,
			 *      NETNS_REF_COUNT(res, NETNS_LISTENER) == 1
			 *    bypass the check below.
			 * 3. With existing Skywalk 2-tuple listener,
			 *      NETNS_REF_COUNT(res, NETNS_LISTENER) == 0 &&
			 *      NETNS_REF_COUNT(res, NETNS_SKYWALK) == 0
			 *    pass with successful wild gns lookup.
			 */
			/* END CSTYLED */
			if (NETNS_REF_COUNT(res, NETNS_LISTENER) == 0 &&
			    NETNS_REF_COUNT(res, NETNS_SKYWALK) > 0) {
				/* check if covered by wild Skywalk listener */
				gns = netns_global_wild[
					NETNS_NS_GLOBAL_IDX(proto, addr_len)];
				if (gns != NULL &&
				    (skres = ns_reservation_tree_find(
					    &gns->ns_reservations, port)) != NULL &&
				    NETNS_REF_COUNT(skres, NETNS_LISTENER)
				    != 0) {
					err = 0;
					goto done;
				}
				if (addr_len == sizeof(struct in_addr)) {
					/* If address is IPv4, also check for wild IPv6 registration */
					gns = netns_global_wild[
						NETNS_NS_GLOBAL_IDX(proto, sizeof(struct in6_addr))];
					if (gns != NULL &&
					    (skres = ns_reservation_tree_find(
						    &gns->ns_reservations, port)) != NULL &&
					    NETNS_REF_COUNT(skres, NETNS_LISTENER)
					    != 0) {
						err = 0;
						goto done;
					}
				}
				SK_DF(NS_VERB_IP(addr_len) |
				    NS_VERB_PROTO(proto),
				    "ERROR - Skywalk got ADDRINUSE "
				    "(w/ SK connected flow)");
				err = EADDRINUSE;
			}
			/*
			 * XXX: Duplicate 5-tuple flows under a Skywalk
			 * listener are currently detected by flow manager,
			 * till we implement 5-tuple-aware netns.
			 */
			break;

		case NETNS_LISTENER:
			if (NETNS_REF_COUNT(res, NETNS_BSD) > 0 ||
			    NETNS_REF_COUNT(res, NETNS_PF) > 0 ||
			    NETNS_REF_COUNT(res, NETNS_LISTENER) > 0 ||
			    _netns_is_port_used(netns_global_wild[
				    NETNS_NS_GLOBAL_IDX(proto, sizeof(struct in_addr))], res, port) ||
			    _netns_is_port_used(netns_global_wild[
				    NETNS_NS_GLOBAL_IDX(proto, sizeof(struct in6_addr))], res, port) ||
			    _netns_is_port_used(netns_global_non_wild[
				    NETNS_NS_GLOBAL_IDX(proto, sizeof(struct in_addr))], res, port) ||
			    _netns_is_port_used(netns_global_non_wild[
				    NETNS_NS_GLOBAL_IDX(proto, sizeof(struct in6_addr))], res, port)) {
				SK_DF(NS_VERB_IP(addr_len) |
				    NS_VERB_PROTO(proto),
				    "ERROR - Listener got ADDRINUSE");
				err = EADDRINUSE;
			}
			break;

		case NETNS_BSD:
		case NETNS_PF:
			if (NETNS_REF_COUNT(res, NETNS_SKYWALK) > 0 ||
			    NETNS_REF_COUNT(res, NETNS_LISTENER) > 0) {
				SK_DF(NS_VERB_IP(addr_len) |
				    NS_VERB_PROTO(proto),
				    "ERROR - %s got ADDRINUSE",
				    ((flags & NETNS_OWNER_MASK) == NETNS_PF) ?
				    "PF" : "BSD");
				err = EADDRINUSE;
			}
			break;

		default:
			panic("_netns_reserve_common: invalid owner 0x%x",
			    flags & NETNS_OWNER_MASK);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}

done:
	ASSERT(res != NULL);
	if (__probable(err == 0)) {
		NETNS_REF_COUNT(res, flags)++;
		/* Check for wrap around */
		VERIFY(NETNS_REF_COUNT(res, flags) != 0);
		SK_DF(NS_VERB_IP(namespace->ns_addr_len) |
		    NS_VERB_PROTO(namespace->ns_proto),
		    "post: %s:%s:%d err %d // flags 0x%x // refs %d sky, "
		    "%d ls, %d bsd %d pf",
		    inet_ntop(LEN_TO_AF(namespace->ns_addr_len),
		    namespace->ns_addr, tmp_ip_str, sizeof(tmp_ip_str)),
		    PROTO_STR(namespace->ns_proto), port, err, flags,
		    NETNS_REF_COUNT(res, NETNS_SKYWALK),
		    NETNS_REF_COUNT(res, NETNS_LISTENER),
		    NETNS_REF_COUNT(res, NETNS_BSD),
		    NETNS_REF_COUNT(res, NETNS_PF));
	} else {
		if (exist == NULL) {
			RB_REMOVE(ns_reservation_tree,
			    &namespace->ns_reservations, res);
			namespace->ns_n_reservations--;
			netns_ns_reservation_free(res);
		}
	}
	return err;
}

/*
 * Internal shared code to release ports within a specific namespace.
 */
static void
_netns_release_common(struct ns *namespace, in_port_t port, uint32_t flags)
{
	struct ns_reservation *res;
	uint32_t refs;
	int i;
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	NETNS_LOCK_ASSERT_HELD();

	res = ns_reservation_tree_find(&namespace->ns_reservations, port);
	if (res == NULL) {
		SK_DF(NS_VERB_IP(namespace->ns_addr_len) |
		    NS_VERB_PROTO(namespace->ns_proto),
		    "ERROR %s:%s:%d // flags 0x%x // not found",
		    inet_ntop(LEN_TO_AF(namespace->ns_addr_len),
		    namespace->ns_addr, tmp_ip_str, sizeof(tmp_ip_str)),
		    PROTO_STR(namespace->ns_proto), port, flags);
		VERIFY(res != NULL);
	}

	SK_DF(NS_VERB_IP(namespace->ns_addr_len) |
	    NS_VERB_PROTO(namespace->ns_proto),
	    "%s:%s:%d // flags 0x%x // refs %d sky, %d ls, %d bsd, %d pf",
	    inet_ntop(LEN_TO_AF(namespace->ns_addr_len),
	    namespace->ns_addr, tmp_ip_str, sizeof(tmp_ip_str)),
	    PROTO_STR(namespace->ns_proto), port, flags,
	    NETNS_REF_COUNT(res, NETNS_SKYWALK),
	    NETNS_REF_COUNT(res, NETNS_LISTENER),
	    NETNS_REF_COUNT(res, NETNS_BSD),
	    NETNS_REF_COUNT(res, NETNS_PF));

	/* Release reservation */
	VERIFY(NETNS_REF_COUNT(res, flags) > 0);
	NETNS_REF_COUNT(res, flags) -= 1;

	/* Clean up memory, if appropriate */
	for (i = 0, refs = 0; i <= NETNS_OWNER_MAX && refs == 0; i++) {
		refs |= res->nsr_refs[i];
	}
	if (refs == 0) {
		RB_REMOVE(ns_reservation_tree, &namespace->ns_reservations,
		    res);
		namespace->ns_n_reservations--;
		NETNS_LOCK_CONVERT();
		netns_ns_reservation_free(res);
		netns_ns_cleanup(namespace);
	}
}

__attribute__((always_inline))
static inline void
netns_init_global_ns(struct ns **global_ptr, uint8_t proto, uint8_t addrlen)
{
	struct ns *namespace;

	namespace = *global_ptr = netns_ns_alloc(Z_WAITOK);
	memset(namespace->ns_addr, 0xFF, addrlen);
	namespace->ns_addr_len = addrlen;
	namespace->ns_proto = proto;
	namespace->ns_is_freeable = 0;
}

__attribute__((always_inline))
static inline void
netns_clear_ifnet(struct ns_token *nstoken)
{
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	NETNS_LOCK_ASSERT_HELD();

	if (nstoken->nt_ifp != NULL) {
		SLIST_REMOVE(&nstoken->nt_ifp->if_netns_tokens, nstoken,
		    ns_token, nt_ifp_link);

		SK_DF(NS_VERB_IP(nstoken->nt_addr_len) |
		    NS_VERB_PROTO(nstoken->nt_proto),
		    "%s:%s:%d // removed from ifnet %d",
		    inet_ntop(LEN_TO_AF(nstoken->nt_addr_len),
		    nstoken->nt_addr, tmp_ip_str, sizeof(tmp_ip_str)),
		    PROTO_STR(nstoken->nt_proto), nstoken->nt_port,
		    nstoken->nt_ifp->if_index);

		NETNS_LOCK_CONVERT();
		ifnet_decr_iorefcnt(nstoken->nt_ifp);
		nstoken->nt_ifp = NULL;
	} else {
		SLIST_REMOVE(&netns_unbound_tokens, nstoken, ns_token,
		    nt_ifp_link);
	}
}

/*
 * Internal shared code to perform a port[-range] reservation, along with all
 * the boilerplate and sanity checks expected for a call coming in from the
 * surrounding kernel code.
 */
static int
_netns_reserve_kpi_common(struct ns *ns, netns_token *token, uint32_t *addr,
    uint8_t addr_len, uint8_t proto, in_port_t *port, uint32_t flags,
    struct ns_flow_info *nfi)
{
	boolean_t ns_want_cleanup = (ns == NULL);
	struct ns_token *nt;
	int err = 0;
	in_port_t hport;
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */
	struct ifnet *ifp = (nfi != NULL) ? nfi->nfi_ifp : NULL;

	NETNS_LOCK_ASSERT_HELD();

	hport = ntohs(*port);

	VERIFY((flags & NETNS_OWNER_MASK) <= NETNS_OWNER_MAX);
	VERIFY(addr_len == sizeof(struct in_addr) ||
	    addr_len == sizeof(struct in6_addr));
	VERIFY(proto == IPPROTO_TCP || proto == IPPROTO_UDP);
	VERIFY(hport != 0);

	SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
	    "reserving %s:%s:%d // flags 0x%x // token %svalid",
	    inet_ntop(LEN_TO_AF(addr_len), addr, tmp_ip_str,
	    sizeof(tmp_ip_str)), PROTO_STR(proto), hport, flags,
	    NETNS_TOKEN_VALID(token) ? "" : "in");

	/*
	 * See the documentation for NETNS_PRERESERVED in netns.h for an
	 * explanation of this block.
	 */
	if (NETNS_TOKEN_VALID(token)) {
		if (flags & NETNS_PRERESERVED) {
			nt = *token;
			VERIFY(nt->nt_addr_len == addr_len);
			VERIFY(memcmp(nt->nt_addr, addr, addr_len) == 0);
			VERIFY(nt->nt_proto == proto);
			VERIFY(nt->nt_port == hport);
			VERIFY((nt->nt_flags &
			    NETNS_RESERVATION_FLAGS | NETNS_PRERESERVED) ==
			    (flags & NETNS_RESERVATION_FLAGS));

			if ((nt->nt_flags & NETNS_CONFIGURATION_FLAGS) ==
			    (flags & NETNS_CONFIGURATION_FLAGS)) {
				SK_DF(NS_VERB_IP(nt->nt_addr_len) |
				    NS_VERB_PROTO(nt->nt_proto),
				    "%s:%s:%d // flags 0x%x -> 0x%x",
				    inet_ntop(LEN_TO_AF(nt->nt_addr_len),
				    nt->nt_addr, tmp_ip_str,
				    sizeof(tmp_ip_str)),
				    PROTO_STR(nt->nt_proto),
				    nt->nt_port, nt->nt_flags, flags);
				nt->nt_flags &= ~NETNS_CONFIGURATION_FLAGS;
				nt->nt_flags |=
				    flags & NETNS_CONFIGURATION_FLAGS;
			}
			SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
			    "token was prereserved");
			goto done;
		} else {
			panic("Request to overwrite valid netns token");
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}

	/*
	 * TODO: Check range against bitmap
	 */
	if (hport == 0) {
		/*
		 * Caller request an arbitrary range of ports
		 * TODO: Need to figure out how to allocate
		 * emphemeral ports only.
		 */
		SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
		    "ERROR - wildcard port not yet supported");
		err = ENOMEM;
		goto done;
	}

	/*
	 * Fetch namespace for the specified address/protocol, creating
	 * a new namespace if necessary.
	 */
	if (ns == NULL) {
		ASSERT(ns_want_cleanup);
		ns = _netns_get_ns(addr, addr_len, proto, true);
	}
	if (__improbable(ns == NULL)) {
		SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
		    "ERROR - couldn't create namespace");
		err = ENOMEM;
		goto done;
	}

	/*
	 * Make a reservation in the namespace
	 * This will return an error if an incompatible reservation
	 * already exists.
	 */
	err = _netns_reserve_common(ns, hport, flags);
	if (__improbable(err != 0)) {
		NETNS_LOCK_CONVERT();
		if (ns_want_cleanup) {
			netns_ns_cleanup(ns);
		}
		SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
		    "ERROR - reservation collision");
		goto done;
	}

	if (!_netns_is_wildcard_addr(ns->ns_addr, addr_len)) {
		/* Record the reservation in the non-wild namespace */
		struct ns *nwns;

		nwns = netns_global_non_wild[NETNS_NS_GLOBAL_IDX(proto,
		    addr_len)];
		err = _netns_reserve_common(nwns, hport, flags);
		if (__improbable(err != 0)) {
			/* Need to free the specific namespace entry */
			NETNS_LOCK_CONVERT();
			_netns_release_common(ns, hport, flags);
			if (ns_want_cleanup) {
				netns_ns_cleanup(ns);
			}
			SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
			    "ERROR - reservation collision");
			goto done;
		}
	}

	nt = netns_ns_token_alloc(true, nfi != NULL ? true : false);
	if (nt == NULL) {
		SK_ERR("netns_ns_token_alloc() failed");
		err = ENOMEM;
		goto done;
	}

	ASSERT(nt->nt_ifp == NULL);
	_netns_set_ifnet_internal(nt, ifp);

	memcpy(nt->nt_addr, addr, addr_len);
	nt->nt_addr_len = addr_len;
	nt->nt_proto = proto;
	nt->nt_port = hport;
	nt->nt_flags = flags;

	if (nfi != NULL) {
		VERIFY(nt->nt_flow_info != NULL);

		memcpy(nt->nt_flow_info, nfi, sizeof(struct ns_flow_info));
		/*
		 * The local port is passed as a separate argument
		 */
		if (nfi->nfi_laddr.sa.sa_family == AF_INET) {
			nt->nt_flow_info->nfi_laddr.sin.sin_port = *port;
		} else if (nfi->nfi_laddr.sa.sa_family == AF_INET6) {
			nt->nt_flow_info->nfi_laddr.sin6.sin6_port = *port;
		}
	}
	*token = nt;

done:
	return err;
}

/*
 * Kernel-facing functions
 */

int
netns_init(void)
{
	VERIFY(__netns_inited == 0);

	netns_ns_reservation_size = sizeof(struct ns_reservation);
	netns_ns_reservation_cache = skmem_cache_create(NETNS_NS_RESERVATION_ZONE_NAME,
	    netns_ns_reservation_size, sizeof(uint64_t), NULL, NULL, NULL,
	    NULL, NULL, 0);
	if (netns_ns_reservation_cache == NULL) {
		panic("%s: skmem_cache create failed (%s)", __func__,
		    NETNS_NS_RESERVATION_ZONE_NAME);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	netns_ns_token_size = sizeof(struct ns_token);
	netns_ns_token_cache = skmem_cache_create(NETNS_NS_TOKEN_ZONE_NAME,
	    netns_ns_token_size, sizeof(uint64_t), NULL, NULL, NULL, NULL,
	    NULL, 0);
	if (netns_ns_token_cache == NULL) {
		panic("%s: skmem_cache create failed (%s)", __func__,
		    NETNS_NS_TOKEN_ZONE_NAME);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	netns_ns_flow_info_size = sizeof(struct ns_flow_info);
	netns_ns_flow_info_cache = skmem_cache_create(NETNS_NS_FLOW_INFO_ZONE_NAME,
	    netns_ns_flow_info_size, sizeof(uint64_t), NULL, NULL, NULL,
	    NULL, NULL, 0);
	if (netns_ns_flow_info_cache == NULL) {
		panic("%s: skmem_cache create failed (%s)", __func__,
		    NETNS_NS_FLOW_INFO_ZONE_NAME);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	SLIST_INIT(&netns_unbound_tokens);
	SLIST_INIT(&netns_all_tokens);

	netns_n_namespaces = 0;
	RB_INIT(&netns_namespaces);

	SK_D("initializing global namespaces");

	netns_init_global_ns(
		&netns_global_non_wild[NETNS_NS_GLOBAL_IDX(IPPROTO_TCP,
		sizeof(struct in_addr))], IPPROTO_TCP, sizeof(struct in_addr));

	netns_init_global_ns(
		&netns_global_non_wild[NETNS_NS_GLOBAL_IDX(IPPROTO_UDP,
		sizeof(struct in_addr))], IPPROTO_UDP, sizeof(struct in_addr));

	netns_init_global_ns(
		&netns_global_non_wild[NETNS_NS_GLOBAL_IDX(IPPROTO_TCP,
		sizeof(struct in6_addr))], IPPROTO_TCP, sizeof(struct in6_addr));

	netns_init_global_ns(
		&netns_global_non_wild[NETNS_NS_GLOBAL_IDX(IPPROTO_UDP,
		sizeof(struct in6_addr))], IPPROTO_UDP, sizeof(struct in6_addr));

	/* Done */

	__netns_inited = 1;
	sk_features |= SK_FEATURE_NETNS;

	SK_D("initialized netns");

	return 0;
}

void
netns_uninit(void)
{
	if (__netns_inited == 1) {
		struct ns *namespace;
		struct ns *temp_namespace;
		int i;

		RB_FOREACH_SAFE(namespace, netns_namespaces_tree,
		    &netns_namespaces, temp_namespace) {
			RB_REMOVE(netns_namespaces_tree, &netns_namespaces,
			    namespace);
			netns_n_namespaces--;
			netns_ns_free(namespace);
		}

		for (i = 0; i < NETNS_N_GLOBAL; i++) {
			netns_ns_free(netns_global_non_wild[i]);
		}

		if (netns_ns_flow_info_cache != NULL) {
			skmem_cache_destroy(netns_ns_flow_info_cache);
			netns_ns_flow_info_cache = NULL;
		}
		if (netns_ns_token_cache != NULL) {
			skmem_cache_destroy(netns_ns_token_cache);
			netns_ns_token_cache = NULL;
		}
		if (netns_ns_reservation_cache != NULL) {
			skmem_cache_destroy(netns_ns_reservation_cache);
			netns_ns_reservation_cache = NULL;
		}

		__netns_inited = 0;
		sk_features &= ~SK_FEATURE_NETNS;

		SK_D("uninitialized netns");
	}
}

void
netns_reap_caches(boolean_t purge)
{
	/* these aren't created unless netns is enabled */
	if (netns_ns_token_cache != NULL) {
		skmem_cache_reap_now(netns_ns_token_cache, purge);
	}
	if (netns_ns_reservation_cache != NULL) {
		skmem_cache_reap_now(netns_ns_reservation_cache, purge);
	}
	if (netns_ns_flow_info_cache != NULL) {
		skmem_cache_reap_now(netns_ns_flow_info_cache, purge);
	}
}

boolean_t
netns_is_enabled(void)
{
	return __netns_inited == 1;
}

int
netns_reserve(netns_token *token, uint32_t *addr, uint8_t addr_len,
    uint8_t proto, in_port_t port, uint32_t flags, struct ns_flow_info *nfi)
{
	int err = 0;
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	if (__netns_inited == 0) {
		*token = NULL;
		return err;
	}

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		SK_ERR("netns doesn't support non TCP/UDP protocol");
		return ENOTSUP;
	}

	SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
	    "%s:%s:%d // flags 0x%x", inet_ntop(LEN_TO_AF(addr_len), addr,
	    tmp_ip_str, sizeof(tmp_ip_str)), PROTO_STR(proto), ntohs(port),
	    flags);

	/*
	 * Check wether the process is allowed to bind to a restricted port
	 */
	if (!current_task_can_use_restricted_in_port(port,
	    proto, flags)) {
		*token = NULL;
		return EADDRINUSE;
	}

	NETNS_LOCK_SPIN();
	err = _netns_reserve_kpi_common(NULL, token, addr, addr_len,
	    proto, &port, flags, nfi);
	NETNS_UNLOCK();

	return err;
}

/* Import net.inet.{tcp,udp}.randomize_ports sysctls */
extern int      udp_use_randomport;
extern int      tcp_use_randomport;

int
netns_reserve_ephemeral(netns_token *token, uint32_t *addr, uint8_t addr_len,
    uint8_t proto, in_port_t *port, uint32_t flags, struct ns_flow_info *nfi)
{
	int err = 0;
	in_port_t first = (in_port_t)ipport_firstauto;
	in_port_t last  = (in_port_t)ipport_lastauto;
	in_port_t rand_port;
	in_port_t last_port;
	in_port_t n_last_port;
	struct ns *namespace;
	boolean_t count_up = true;
	boolean_t use_randomport = (proto == IPPROTO_TCP) ?
	    tcp_use_randomport : udp_use_randomport;
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	if (__netns_inited == 0) {
		*token = NULL;
		return err;
	}

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		SK_ERR("netns doesn't support non TCP/UDP protocol");
		return ENOTSUP;
	}

	SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
	    "%s:%s:%d // flags 0x%x", inet_ntop(LEN_TO_AF(addr_len), addr,
	    tmp_ip_str, sizeof(tmp_ip_str)), PROTO_STR(proto), ntohs(*port),
	    flags);

	NETNS_LOCK_SPIN();

	namespace = _netns_get_ns(addr, addr_len, proto, true);
	if (namespace == NULL) {
		err = ENOMEM;
		NETNS_UNLOCK();
		return err;
	}

	if (proto == IPPROTO_UDP) {
		if (UINT16_MAX - namespace->ns_n_reservations <
		    NETNS_NS_UDP_EPHEMERAL_RESERVE) {
			SK_ERR("UDP ephemeral port not available"
			    "(less than 4096 UDP ports left)");
			err = EADDRNOTAVAIL;
			NETNS_UNLOCK();
			return err;
		}
	}

	if (first == last) {
		rand_port = first;
	} else {
		if (use_randomport) {
			NETNS_LOCK_CONVERT();
			read_frandom(&rand_port, sizeof(rand_port));

			if (first > last) {
				rand_port = last + (rand_port %
				    (first - last));
				count_up = false;
			} else {
				rand_port = first + (rand_port %
				    (last - first));
			}
		} else {
			if (first > last) {
				rand_port =
				    namespace->ns_last_ephemeral_port_down - 1;
				if (rand_port < last || rand_port > first) {
					rand_port = last;
				}
				count_up = false;
			} else {
				rand_port =
				    namespace->ns_last_ephemeral_port_up + 1;
				if (rand_port < first || rand_port > last) {
					rand_port = first;
				}
			}
		}
	}
	last_port = rand_port;
	n_last_port = htons(last_port);

	while (true) {
		if (n_last_port == 0) {
			SK_ERR("ephemeral port search range includes 0");
			err = EINVAL;
			break;
		}

		/*
		 * Skip if this is a restricted port as we do not want to
		 * restricted ports as ephemeral
		 */
		if (!IS_RESTRICTED_IN_PORT(n_last_port)) {
			err = _netns_reserve_kpi_common(namespace, token, addr,
			    addr_len, proto, &n_last_port, flags, nfi);
			if (err == 0 || err != EADDRINUSE) {
				break;
			}
		}
		if (count_up) {
			last_port++;
			if (last_port < first || last_port > last) {
				last_port = first;
			}
		} else {
			last_port--;
			if (last_port < last || last_port > first) {
				last_port = last;
			}
		}
		n_last_port = htons(last_port);

		if (last_port == rand_port || first == last) {
			SK_ERR("couldn't find free ephemeral port");
			err = EADDRNOTAVAIL;
			break;
		}
	}

	if (err == 0) {
		*port = n_last_port;
		if (count_up) {
			namespace->ns_last_ephemeral_port_up = last_port;
		} else {
			namespace->ns_last_ephemeral_port_down = last_port;
		}
	} else {
		netns_ns_cleanup(namespace);
	}

	NETNS_UNLOCK();

	return err;
}

void
netns_release(netns_token *token)
{
	struct ns *ns;
	struct ns_token *nt;
	uint8_t proto, addr_len;
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	if (!NETNS_TOKEN_VALID(token)) {
		return;
	}

	if (__netns_inited == 0) {
		*token = NULL;
		return;
	}

	NETNS_LOCK_SPIN();

	nt = *token;
	*token = NULL;

	VERIFY((nt->nt_flags & NETNS_OWNER_MASK) <= NETNS_OWNER_MAX);
	VERIFY(nt->nt_addr_len == sizeof(struct in_addr) ||
	    nt->nt_addr_len == sizeof(struct in6_addr));
	VERIFY(nt->nt_proto == IPPROTO_TCP || nt->nt_proto == IPPROTO_UDP);

	addr_len = nt->nt_addr_len;
	proto = nt->nt_proto;

	SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
	    "releasing %s:%s:%d",
	    inet_ntop(LEN_TO_AF(nt->nt_addr_len), nt->nt_addr,
	    tmp_ip_str, sizeof(tmp_ip_str)), PROTO_STR(proto),
	    nt->nt_port);

	if (!_netns_is_wildcard_addr(nt->nt_addr, addr_len)) {
		/* Remove from global non-wild namespace */

		ns = netns_global_non_wild[NETNS_NS_GLOBAL_IDX(proto,
		    addr_len)];
		VERIFY(ns != NULL);

		_netns_release_common(ns, nt->nt_port, nt->nt_flags);
	}

	ns = _netns_get_ns(nt->nt_addr, addr_len, proto, false);
	VERIFY(ns != NULL);
	_netns_release_common(ns, nt->nt_port, nt->nt_flags);

	netns_clear_ifnet(nt);
	netns_ns_token_free(nt);

	NETNS_UNLOCK();
}

int
netns_change_addr(netns_token *token, uint32_t *addr, uint8_t addr_len)
{
	int err = 0;
	struct ns *old_namespace;
	struct ns *new_namespace;
	struct ns *global_namespace;
	struct ns_token *nt;
	uint8_t proto;
#if SK_LOG
	char tmp_ip_str_1[MAX_IPv6_STR_LEN];
	char tmp_ip_str_2[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	if (__netns_inited == 0) {
		return 0;
	}

	NETNS_LOCK();

	VERIFY(NETNS_TOKEN_VALID(token));

	nt = *token;

	VERIFY((nt->nt_flags & NETNS_OWNER_MASK) == NETNS_BSD);
	VERIFY(nt->nt_addr_len == sizeof(struct in_addr) ||
	    nt->nt_addr_len == sizeof(struct in6_addr));
	VERIFY(nt->nt_proto == IPPROTO_TCP || nt->nt_proto == IPPROTO_UDP);

	proto = nt->nt_proto;

#if SK_LOG
	inet_ntop(LEN_TO_AF(nt->nt_addr_len), nt->nt_addr,
	    tmp_ip_str_1, sizeof(tmp_ip_str_1));
	inet_ntop(LEN_TO_AF(addr_len), addr, tmp_ip_str_2,
	    sizeof(tmp_ip_str_2));
#endif /* SK_LOG */
	SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
	    "changing address for %s:%d from %s to %s",
	    PROTO_STR(proto), nt->nt_port, tmp_ip_str_1,
	    tmp_ip_str_2);

	if (nt->nt_addr_len == addr_len &&
	    memcmp(nt->nt_addr, addr, nt->nt_addr_len) == 0) {
		SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
		    "address didn't change, exiting early");
		goto done;
	}

	old_namespace = _netns_get_ns(nt->nt_addr, nt->nt_addr_len, proto,
	    false);
	VERIFY(old_namespace != NULL);

	new_namespace = _netns_get_ns(addr, addr_len, proto, true);
	if (new_namespace == NULL) {
		err = ENOMEM;
		goto done;
	}

	/* Acquire reservation in new namespace */
	if ((err = _netns_reserve_common(new_namespace, nt->nt_port,
	    nt->nt_flags))) {
		NETNS_LOCK_CONVERT();
		netns_ns_cleanup(new_namespace);
		SK_DF(NS_VERB_IP(addr_len) | NS_VERB_PROTO(proto),
		    "ERROR - reservation collision under new namespace");
		goto done;
	}

	/* Release from old namespace */
	_netns_release_common(old_namespace, nt->nt_port, nt->nt_flags);

	if (!_netns_is_wildcard_addr(nt->nt_addr, nt->nt_addr_len)) {
		/*
		 * Old address is non-wildcard.
		 * Remove old reservation from global non-wild namespace
		 */
		global_namespace = netns_global_non_wild[
			NETNS_NS_GLOBAL_IDX(proto, nt->nt_addr_len)];
		VERIFY(global_namespace != NULL);

		_netns_release_common(global_namespace, nt->nt_port,
		    nt->nt_flags);
	}

	if (!_netns_is_wildcard_addr(addr, addr_len)) {
		/*
		 * New address is non-wildcard.
		 * Record new reservation in global non-wild namespace
		 */
		global_namespace = netns_global_non_wild[
			NETNS_NS_GLOBAL_IDX(proto, addr_len)];
		VERIFY(global_namespace != NULL);

		if ((err = _netns_reserve_common(global_namespace,
		    nt->nt_port, nt->nt_flags)) != 0) {
			SK_DF(NS_VERB_IP(addr_len) |
			    NS_VERB_PROTO(proto),
			    "ERROR - reservation collision under new "
			    "global namespace");
			/* XXX: Should not fail. Maybe assert instead */
			goto done;
		}
	}

	memcpy(nt->nt_addr, addr, addr_len);
	nt->nt_addr_len = addr_len;

done:
	NETNS_UNLOCK();
	return err;
}

static void
_netns_set_ifnet_internal(struct ns_token *nt, struct ifnet *ifp)
{
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	NETNS_LOCK_ASSERT_HELD();

	if (ifp != NULL && ifnet_is_attached(ifp, 1)) {
		nt->nt_ifp = ifp;
		SLIST_INSERT_HEAD(&ifp->if_netns_tokens, nt, nt_ifp_link);

		SK_DF(NS_VERB_IP(nt->nt_addr_len) | NS_VERB_PROTO(nt->nt_proto),
		    "%s:%s:%d // added to ifnet %d",
		    inet_ntop(LEN_TO_AF(nt->nt_addr_len),
		    nt->nt_addr, tmp_ip_str, sizeof(tmp_ip_str)),
		    PROTO_STR(nt->nt_proto), nt->nt_port,
		    ifp->if_index);
	} else {
		SLIST_INSERT_HEAD(&netns_unbound_tokens, nt, nt_ifp_link);
	}
}

void
netns_set_ifnet(netns_token *token, ifnet_t ifp)
{
	struct ns_token *nt;
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	if (__netns_inited == 0) {
		return;
	}

	NETNS_LOCK();

	VERIFY(NETNS_TOKEN_VALID(token));

	nt = *token;

	if (nt->nt_ifp == ifp) {
		SK_DF(NS_VERB_IP(nt->nt_addr_len) | NS_VERB_PROTO(nt->nt_proto),
		    "%s:%s:%d // ifnet already %d, exiting early",
		    inet_ntop(LEN_TO_AF(nt->nt_addr_len),
		    nt->nt_addr, tmp_ip_str, sizeof(tmp_ip_str)),
		    PROTO_STR(nt->nt_proto), nt->nt_port,
		    ifp ? ifp->if_index : -1);
		NETNS_UNLOCK();
		return;
	}

	netns_clear_ifnet(nt);

	_netns_set_ifnet_internal(nt, ifp);

	NETNS_UNLOCK();
}

void
netns_ifnet_detach(ifnet_t ifp)
{
	struct ns_token *token, *tmp_token;

	if (__netns_inited == 0) {
		return;
	}

	NETNS_LOCK();

	SLIST_FOREACH_SAFE(token, &ifp->if_netns_tokens, nt_ifp_link,
	    tmp_token) {
		netns_clear_ifnet(token);
		SLIST_INSERT_HEAD(&netns_unbound_tokens, token, nt_ifp_link);
	}

	NETNS_UNLOCK();
}

static void
_netns_set_state(netns_token *token, uint32_t state)
{
	struct ns_token *nt;
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	if (__netns_inited == 0) {
		return;
	}

	NETNS_LOCK();
	VERIFY(NETNS_TOKEN_VALID(token));

	nt = *token;
	nt->nt_state |= state;

	SK_DF(NS_VERB_IP(nt->nt_addr_len) | NS_VERB_PROTO(nt->nt_proto),
	    "%s:%s:%d // state 0x%b",
	    inet_ntop(LEN_TO_AF(nt->nt_addr_len), nt->nt_addr,
	    tmp_ip_str, sizeof(tmp_ip_str)),
	    PROTO_STR(nt->nt_proto), nt->nt_port, state, NETNS_STATE_BITS);

	NETNS_UNLOCK();
}

void
netns_half_close(netns_token *token)
{
	_netns_set_state(token, NETNS_STATE_HALFCLOSED);
}

void
netns_withdraw(netns_token *token)
{
	_netns_set_state(token, NETNS_STATE_WITHDRAWN);
}

int
netns_get_flow_info(netns_token *token,
    struct ns_flow_info *nfi)
{
	if (__netns_inited == 0) {
		return ENOTSUP;
	}

	NETNS_LOCK();
	if (!NETNS_TOKEN_VALID(token) ||
	    nfi == NULL) {
		NETNS_UNLOCK();
		return EINVAL;
	}

	struct ns_token *nt = *token;
	if (nt->nt_flow_info == NULL) {
		NETNS_UNLOCK();
		return ENOENT;
	}

	memcpy(nfi, nt->nt_flow_info, sizeof(struct ns_flow_info));
	NETNS_UNLOCK();

	return 0;
}

void
netns_change_flags(netns_token *token, uint32_t set_flags,
    uint32_t clear_flags)
{
	struct ns_token *nt;
#if SK_LOG
	char tmp_ip_str[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */

	if (__netns_inited == 0) {
		return;
	}

	NETNS_LOCK();

	VERIFY(NETNS_TOKEN_VALID(token));

	nt = *token;

	VERIFY(!((set_flags | clear_flags) & NETNS_RESERVATION_FLAGS));
	/* TODO: verify set and clear flags don't overlap? */

	SK_DF(NS_VERB_IP(nt->nt_addr_len) | NS_VERB_PROTO(nt->nt_proto),
	    "%s:%s:%d // flags 0x%x -> 0x%x",
	    inet_ntop(LEN_TO_AF(nt->nt_addr_len), nt->nt_addr,
	    tmp_ip_str, sizeof(tmp_ip_str)),
	    PROTO_STR(nt->nt_proto), nt->nt_port, nt->nt_flags,
	    nt->nt_flags | set_flags & ~clear_flags);

	nt->nt_flags |= set_flags;
	nt->nt_flags &= ~clear_flags;

	NETNS_UNLOCK();
}

/*
 * Port offloading KPI
 */
static inline void
netns_local_port_scan_flow_entry(struct flow_entry *fe, protocol_family_t protocol,
    u_int32_t flags, u_int8_t *bitfield)
{
	struct ns_token *token = fe->fe_port_reservation;
	boolean_t iswildcard = false;

	if (fe == NULL || token == NULL) {
		return;
	}

	/*
	 * We are only interested in active flows over skywalk channels
	 */
	if ((token->nt_flags & NETNS_OWNER_MASK) != NETNS_SKYWALK) {
		return;
	}

	if (token->nt_state & NETNS_STATE_WITHDRAWN) {
		return;
	}

	if (!(flags & IFNET_GET_LOCAL_PORTS_ANYTCPSTATEOK) &&
	    (flags & IFNET_GET_LOCAL_PORTS_ACTIVEONLY) &&
	    (token->nt_state & NETNS_STATE_HALFCLOSED)) {
		return;
	}

	VERIFY(token->nt_addr_len == sizeof(struct in_addr) ||
	    token->nt_addr_len == sizeof(struct in6_addr));

	if (token->nt_addr_len == sizeof(struct in_addr)) {
		if (protocol == PF_INET6) {
			return;
		}

		iswildcard = token->nt_inaddr.s_addr == INADDR_ANY;
	} else if (token->nt_addr_len == sizeof(struct in6_addr)) {
		if (protocol == PF_INET) {
			return;
		}

		iswildcard = IN6_IS_ADDR_UNSPECIFIED(
			&token->nt_in6addr);
	}
	if (!(flags & IFNET_GET_LOCAL_PORTS_WILDCARDOK) && iswildcard) {
		return;
	}

	if ((flags & IFNET_GET_LOCAL_PORTS_TCPONLY) &&
	    token->nt_proto == IPPROTO_UDP) {
		return;
	}
	if ((flags & IFNET_GET_LOCAL_PORTS_UDPONLY) &&
	    token->nt_proto == IPPROTO_TCP) {
		return;
	}

	if (!(flags & IFNET_GET_LOCAL_PORTS_NOWAKEUPOK) &&
	    (token->nt_flags & NETNS_NOWAKEFROMSLEEP)) {
		return;
	}

	if ((flags & IFNET_GET_LOCAL_PORTS_RECVANYIFONLY) &&
	    !(token->nt_flags & NETNS_RECVANYIF)) {
		return;
	}

	if ((flags & IFNET_GET_LOCAL_PORTS_EXTBGIDLEONLY) &&
	    !(token->nt_flags & NETNS_EXTBGIDLE)) {
		return;
	}

	if (token->nt_ifp != NULL && token->nt_flow_info != NULL) {
		bitstr_set(bitfield, token->nt_port);
		(void) if_ports_used_add_flow_entry(fe, token->nt_ifp->if_index,
		    token->nt_flow_info, token->nt_flags);
	} else {
		SK_ERR("%s: unknown owner port %u"
		    " nt_flags 0x%x ifindex %u nt_flow_info %p\n",
		    __func__, token->nt_port,
		    token->nt_flags,
		    token->nt_ifp != NULL ? token->nt_ifp->if_index : 0,
		    token->nt_flow_info);
	}
}

static void
netns_get_if_local_ports(ifnet_t ifp, protocol_family_t protocol,
    u_int32_t flags, u_int8_t *bitfield)
{
	struct nx_flowswitch *fsw = NULL;

	if (ifp == NULL || ifp->if_na == NULL) {
		return;
	}
	/* Ensure that the interface is attached and won't detach */
	if (!ifnet_is_attached(ifp, 1)) {
		return;
	}
	fsw = fsw_ifp_to_fsw(ifp);
	if (fsw == NULL) {
		goto done;
	}
	FSW_RLOCK(fsw);
	flow_mgr_foreach_flow(fsw->fsw_flow_mgr, ^(struct flow_entry *_fe) {
		netns_local_port_scan_flow_entry(_fe, protocol, flags,
		bitfield);
	});
	FSW_UNLOCK(fsw);
done:
	ifnet_decr_iorefcnt(ifp);
}

errno_t
netns_get_local_ports(ifnet_t ifp, protocol_family_t protocol,
    u_int32_t flags, u_int8_t *bitfield)
{
	if (__netns_inited == 0) {
		return 0;
	}
	if (ifp != NULL) {
		netns_get_if_local_ports(ifp, protocol, flags, bitfield);
	} else {
		errno_t error;
		ifnet_t *ifp_list;
		uint32_t count, i;

		error = ifnet_list_get_all(IFNET_FAMILY_ANY, &ifp_list, &count);
		if (error != 0) {
			os_log_error(OS_LOG_DEFAULT,
			    "%s: ifnet_list_get_all() failed %d",
			    __func__, error);
			return error;
		}
		for (i = 0; i < count; i++) {
			if (TAILQ_EMPTY(&ifp_list[i]->if_addrhead)) {
				continue;
			}
			netns_get_if_local_ports(ifp_list[i], protocol, flags,
			    bitfield);
		}
		ifnet_list_free(ifp_list);
	}

	return 0;
}

uint32_t
netns_find_anyres_byaddr(struct ifaddr *ifa, uint8_t proto)
{
	int result = 0;
	int ifa_addr_len;
	struct ns_token *token;
	struct ifnet *ifp = ifa->ifa_ifp;
	struct sockaddr *ifa_addr = ifa->ifa_addr;

	if (__netns_inited == 0) {
		return ENOTSUP;
	}

	if ((ifa_addr->sa_family != AF_INET) &&
	    (ifa_addr->sa_family != AF_INET6)) {
		return 0;
	}

	ifa_addr_len = (ifa_addr->sa_family == AF_INET) ?
	    sizeof(struct in_addr) : sizeof(struct in6_addr);

	NETNS_LOCK();

	SLIST_FOREACH(token, &ifp->if_netns_tokens, nt_ifp_link) {
		if ((token->nt_flags & NETNS_OWNER_MASK) == NETNS_PF) {
			continue;
		}
		if (token->nt_addr_len != ifa_addr_len) {
			continue;
		}
		if (token->nt_proto != proto) {
			continue;
		}
		if (ifa_addr->sa_family == AF_INET) {
			if (token->nt_inaddr.s_addr ==
			    (satosin(ifa->ifa_addr))->sin_addr.s_addr) {
				result = 1;
				break;
			}
		} else if (ifa_addr->sa_family == AF_INET6) {
			if (IN6_ARE_ADDR_EQUAL(IFA_IN6(ifa),
			    &token->nt_in6addr)) {
				result = 1;
				break;
			}
		}
	}

	NETNS_UNLOCK();
	return result;
}

static uint32_t
_netns_lookup_ns_n_reservations(uint32_t *addr, uint8_t addr_len, uint8_t proto)
{
	uint32_t ns_n_reservations = 0;
	NETNS_LOCK_SPIN();
	struct ns *namespace = _netns_get_ns(addr, addr_len, proto, true);
	if (namespace != NULL) {
		ns_n_reservations = namespace->ns_n_reservations;
	}
	NETNS_UNLOCK();
	return ns_n_reservations;
}

uint32_t
netns_lookup_reservations_count_in(struct in_addr addr, uint8_t proto)
{
	return _netns_lookup_ns_n_reservations(&addr.s_addr, sizeof(struct in_addr), proto);
}

uint32_t
netns_lookup_reservations_count_in6(struct in6_addr addr, uint8_t proto)
{
	if (IN6_IS_SCOPE_EMBED(&addr)) {
		addr.s6_addr16[1] = 0;
	}
	return _netns_lookup_ns_n_reservations(&addr.s6_addr32[0], sizeof(struct in6_addr), proto);
}

/*
 * Sysctl interface
 */

static int netns_ctl_dump_all SYSCTL_HANDLER_ARGS;

SYSCTL_NODE(_kern_skywalk, OID_AUTO, netns, CTLFLAG_RW | CTLFLAG_LOCKED,
    0, "Netns interface");

SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, netns,
    CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, netns_ctl_dump_all, "-",
    "Namespace contents (struct netns_ctl_dump_header, "
    "skywalk/os_stats_private.h)");

static int
netns_ctl_write_ns(struct sysctl_req *req, struct ns *namespace,
    boolean_t is_global)
{
	struct ns_reservation *res;
	struct netns_ctl_dump_header response_header;
	struct netns_ctl_dump_record response_record;
	int err;

	/* Fill out header */
	memset(&response_header, 0, sizeof(response_header));
	response_header.ncdh_n_records = namespace->ns_n_reservations;
	response_header.ncdh_proto = namespace->ns_proto;

	if (is_global) {
		response_header.ncdh_addr_len = 0;
	} else {
		response_header.ncdh_addr_len = namespace->ns_addr_len;
	}
	memcpy(response_header.ncdh_addr, namespace->ns_addr,
	    namespace->ns_addr_len);

	err = SYSCTL_OUT(req, &response_header, sizeof(response_header));
	if (err) {
		return err;
	}

	/* Fill out records */
	RB_FOREACH(res, ns_reservation_tree, &namespace->ns_reservations) {
		memset(&response_record, 0, sizeof(response_record));
		response_record.ncdr_port = res->nsr_port;
		response_record.ncdr_port_end = 0;
		response_record.ncdr_listener_refs =
		    NETNS_REF_COUNT(res, NETNS_LISTENER);
		response_record.ncdr_skywalk_refs =
		    NETNS_REF_COUNT(res, NETNS_SKYWALK);
		response_record.ncdr_bsd_refs =
		    NETNS_REF_COUNT(res, NETNS_BSD);
		response_record.ncdr_pf_refs =
		    NETNS_REF_COUNT(res, NETNS_PF);
		err = SYSCTL_OUT(req, &response_record,
		    sizeof(response_record));
		if (err) {
			return err;
		}
	}

	return 0;
}

static int
netns_ctl_dump_all SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	struct ns *namespace;
	int i, err = 0;

	if (!kauth_cred_issuser(kauth_cred_get())) {
		return EPERM;
	}

	if (__netns_inited == 0) {
		return ENOTSUP;
	}

	NETNS_LOCK();

	for (i = 0; i < NETNS_N_GLOBAL; i++) {
		err = netns_ctl_write_ns(req, netns_global_non_wild[i], true);
		if (err) {
			goto done;
		}
	}

	RB_FOREACH(namespace, netns_namespaces_tree, &netns_namespaces) {
		err = netns_ctl_write_ns(req, namespace, false);
		if (err) {
			goto done;
		}
	}

	/*
	 * If this is just a request for length, add slop because
	 * this is dynamically changing data
	 */
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx += 20 * sizeof(struct netns_ctl_dump_record);
	}

done:
	NETNS_UNLOCK();
	return err;
}
/* CSTYLED */
